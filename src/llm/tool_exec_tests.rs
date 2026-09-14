use super::*;
use crate::config::EngineConfig;
use crate::engine::DefaultEngine;
use crate::llm::tools;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use tempfile::TempDir;

fn executor_env() -> (TempDir, Arc<dyn Engine>, Arc<FindingCounter>) {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("a.rs"), "fn main() {}\n").unwrap();
    let engine: Arc<dyn Engine> = Arc::new(DefaultEngine::new(EngineConfig::default()));
    (dir, engine, Arc::new(FindingCounter::new()))
}

fn scoped_env() -> (TempDir, Arc<dyn Engine>, Arc<FindingCounter>) {
    let (dir, engine, counter) = executor_env();
    fs::write(dir.path().join("b.rs"), "fn other() {}\n").unwrap();
    (dir, engine, counter)
}

fn executor(
    dir: &TempDir,
    engine: &Arc<dyn Engine>,
    counter: &Arc<FindingCounter>,
) -> ToolExecutor {
    ToolExecutor::new(Arc::clone(engine), dir.path(), Arc::clone(counter))
        .expect("the fixture project is readable")
}

fn changed_lines(spans: &[(&str, &[(u32, u32)])]) -> ChangedLines {
    let hunks: BTreeMap<String, Vec<(u32, u32)>> = spans
        .iter()
        .map(|(path, ranges)| ((*path).to_string(), ranges.to_vec()))
        .collect();
    ChangedLines::try_from(hunks).expect("well-formed hunks")
}

#[test]
fn discover_files_returns_json_list() {
    let (dir, engine, counter) = executor_env();
    let exec = executor(&dir, &engine, &counter);

    let outcome = exec.execute(tools::DISCOVER_FILES, &json!({})).unwrap();

    assert!(outcome.text.contains("a.rs"));
    assert!(outcome.findings.is_empty());
}

#[test]
fn a_cancelled_tool_stops_before_engine_work() {
    let (dir, engine, counter) = executor_env();
    let exec = executor(&dir, &engine, &counter);
    let cancel = CancelToken::default();
    cancel.cancel();

    let error = match exec.execute_with_cancel(tools::DISCOVER_FILES, &json!({}), &cancel) {
        Err(error) => error,
        Ok(_) => panic!("a cancelled tool must fail"),
    };

    assert_eq!(error, "analysis cancelled");
}

#[test]
fn submit_findings_returns_typed_findings() {
    let (dir, engine, counter) = executor_env();
    let exec = executor(&dir, &engine, &counter);

    let outcome = exec
        .execute(
            tools::SUBMIT_FINDINGS,
            &json!({ "findings": [{
                "category": "bug", "severity": "high",
                "title": "boom", "description": "d", "file": "a.rs",
                "confidence": "high"
            }]}),
        )
        .unwrap();

    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(outcome.findings[0].source, FindingSource::Ai);
    assert_eq!(outcome.findings[0].severity, Severity::High);
}

#[test]
fn a_substantial_submission_is_borrowed_without_duplicating_the_input() {
    const SUBSTANTIAL_FINDINGS: usize = 50;

    let (dir, engine, counter) = executor_env();
    let exec = executor(&dir, &engine, &counter);
    let description = "d".repeat(MAX_FINDING_DESCRIPTION_BYTES);
    let findings: Vec<Value> = (0..SUBSTANTIAL_FINDINGS)
        .map(|index| {
            json!({
                "category": "bug", "severity": "high",
                "title": format!("issue {index}"), "description": description,
                "file": "a.rs", "confidence": "high"
            })
        })
        .collect();
    let input = json!({ "findings": findings });
    let last = SUBSTANTIAL_FINDINGS - 1;

    let first = exec.execute(tools::SUBMIT_FINDINGS, &input).unwrap();
    let second = exec.execute(tools::SUBMIT_FINDINGS, &input).unwrap();

    assert_eq!(first.findings.len(), SUBSTANTIAL_FINDINGS);
    assert!(
        first
            .findings
            .iter()
            .all(|finding| finding.description.len() == MAX_FINDING_DESCRIPTION_BYTES)
    );
    assert_eq!(
        second.findings[last].description, first.findings[last].description,
        "a borrowed input must survive execution unchanged"
    );
    assert_eq!(
        input["findings"][last]["description"]
            .as_str()
            .map(str::len),
        Some(MAX_FINDING_DESCRIPTION_BYTES),
        "execute must borrow the caller's input instead of consuming it"
    );
}

#[test]
fn submit_findings_rejects_paths_outside_project() {
    let (dir, engine, counter) = executor_env();
    let outside = TempDir::new().unwrap();
    let outside_file = outside.path().join("outside.rs");
    fs::write(&outside_file, "fn outside() {}\n").unwrap();
    let exec = executor(&dir, &engine, &counter);

    let result = exec.execute(
        tools::SUBMIT_FINDINGS,
        &json!({ "findings": [{
            "category": "bug", "severity": "high",
            "title": "outside", "description": "d",
            "file": outside_file, "confidence": "high"
        }]}),
    );
    let error = result.err().expect("outside path must be rejected");

    assert!(error.contains("path traversal blocked"));
}

#[test]
fn submit_findings_corrects_location_from_exact_snippet() {
    let (dir, engine, counter) = executor_env();
    fs::write(
        dir.path().join("a.rs"),
        "fn first() {}\n\nfn target() {\n    panic!();\n}\n",
    )
    .unwrap();
    let exec = executor(&dir, &engine, &counter);
    let outcome = exec
        .execute(
            tools::SUBMIT_FINDINGS,
            &json!({ "findings": [{
                "category": "bug", "severity": "high",
                "title": "panic", "description": "d", "file": "a.rs",
                "confidence": "high", "line_start": 1, "line_end": 1,
                "code_snippet": "fn target() {\n    panic!();\n}"
            }]}),
        )
        .unwrap();

    assert_eq!(outcome.findings[0].line_start, Some(3));
    assert_eq!(outcome.findings[0].line_end, Some(5));
}

#[test]
fn submit_findings_rejects_invalid_enum_fields() {
    let (dir, engine, counter) = executor_env();
    let exec = executor(&dir, &engine, &counter);
    let accepted = json!({
        "category": "bug",
        "severity": "high",
        "confidence": "medium",
        "title": "title",
        "description": "description",
        "file": "source.rs"
    });

    for (field, invalid_value) in [
        ("category", "not-a-category"),
        ("severity", "not-a-severity"),
        ("confidence", "not-a-confidence"),
    ] {
        let mut finding = accepted.clone();
        finding[field] = json!(invalid_value);
        let result = exec.execute(tools::SUBMIT_FINDINGS, &json!({ "findings": [finding] }));
        let error = match result {
            Ok(_) => panic!("an invalid {field} must be rejected"),
            Err(error) => error,
        };

        assert!(error.contains("finding 1"), "{error}");
        assert!(error.contains(field), "{error}");
    }
}

#[test]
fn submit_findings_rejects_batches_beyond_the_limit() {
    let (dir, engine, counter) = executor_env();
    let exec = executor(&dir, &engine, &counter);
    let findings = vec![json!({}); MAX_FINDINGS_PER_SUBMISSION + 1];

    let error = exec
        .execute(tools::SUBMIT_FINDINGS, &json!({ "findings": findings }))
        .err()
        .expect("oversized finding batches must be rejected");

    assert!(error.contains(&format!("at most {MAX_FINDINGS_PER_SUBMISSION} findings")));
}

#[test]
fn exact_snippet_location_requires_one_match() {
    assert_eq!(
        exact_snippet_line_range("one\ntarget\nthree", "target"),
        LineRange::new(2, 2).ok()
    );
    assert_eq!(exact_snippet_line_range("target\ntarget", "target"), None);
    assert_eq!(exact_snippet_line_range("one", "missing"), None);
    assert_eq!(exact_snippet_line_range("", ""), None);
}

#[test]
fn a_trailing_newline_stays_on_the_snippets_last_content_line() {
    assert_eq!(
        exact_snippet_line_range("danger();\nchanged();\n", "danger();\n"),
        LineRange::new(1, 1).ok()
    );
    assert_eq!(
        exact_snippet_line_range("first\nsecond\nthird\n", "first\nsecond\n"),
        LineRange::new(1, 2).ok()
    );
}

#[test]
fn unscoped_findings_reject_ambiguous_snippets() {
    let (dir, engine, counter) = executor_env();
    fs::write(dir.path().join("a.rs"), "danger();\ndanger();\n").unwrap();
    let exec = executor(&dir, &engine, &counter);

    let error = exec
        .execute(
            tools::SUBMIT_FINDINGS,
            &json!({ "findings": [{
                "category": "bug", "severity": "high", "title": "t", "description": "d",
                "file": "a.rs", "line_start": 1, "line_end": 1,
                "code_snippet": "danger();"
            }]}),
        )
        .err()
        .expect("ambiguous evidence must be rejected outside review mode too");

    assert!(error.contains("does not appear exactly once"), "{error}");
}

#[test]
fn unscoped_findings_reject_ranges_past_end_of_file() {
    let (dir, engine, counter) = executor_env();
    fs::write(dir.path().join("a.rs"), "one\ntwo\n").unwrap();
    let exec = executor(&dir, &engine, &counter);

    let error = exec
        .execute(tools::SUBMIT_FINDINGS, &finding_at("a.rs", 2, 3))
        .err()
        .expect("out-of-file evidence must be rejected outside review mode too");

    assert!(
        error.contains("runs past the end of the file (2 lines)"),
        "{error}"
    );
}

#[test]
fn unknown_tool_is_an_error() {
    let (dir, engine, counter) = executor_env();
    let exec = executor(&dir, &engine, &counter);
    assert!(exec.execute("nope", &json!({})).is_err());
}

#[test]
fn tool_inputs_reject_unknown_fields() {
    let (dir, engine, counter) = executor_env();
    let exec = executor(&dir, &engine, &counter);

    for (tool, input) in [
        (tools::PROJECT_STATS, json!({ "unexpected": true })),
        (
            tools::DISCOVER_FILES,
            json!({ "max_results": 1, "unexpected": true }),
        ),
        (
            tools::SUBMIT_FINDINGS,
            json!({ "findings": [{
                "category": "bug", "severity": "high", "title": "t",
                "description": "d", "file": "a.rs", "unexpected": true
            }] }),
        ),
    ] {
        let error = exec
            .execute(tool, &input)
            .err()
            .expect("unknown fields must be rejected");
        assert!(error.contains("unknown field"), "{error}");
    }
}

#[test]
fn tool_inputs_enforce_declared_resource_limits() {
    let (dir, engine, counter) = executor_env();
    let exec = executor(&dir, &engine, &counter);
    let too_many_filters = vec!["rs"; MAX_FILTERS + 1];

    for (tool, input, field) in [
        (
            tools::DISCOVER_FILES,
            json!({ "extensions": too_many_filters }),
            "extensions",
        ),
        (
            tools::DISCOVER_FILES,
            json!({ "max_depth": MAX_DISCOVERY_DEPTH + 1 }),
            "max_depth",
        ),
        (
            tools::SEARCH_TEXT,
            json!({ "pattern": "x", "context_lines": MAX_CONTEXT_LINES + 1 }),
            "context_lines",
        ),
        (
            tools::SEARCH_TEXT,
            json!({ "pattern": "x", "max_results": MAX_TOOL_RESULTS + 1 }),
            "max_results",
        ),
        (
            tools::READ_FILE,
            json!({ "path": "x".repeat(MAX_PATH_BYTES + 1) }),
            "path",
        ),
        (
            tools::SEARCH_AST,
            json!({
                "path": "a.rs",
                "query": "x".repeat(MAX_AST_QUERY_BYTES + 1),
                "language": "rust"
            }),
            "query",
        ),
        (
            tools::SUBMIT_FINDINGS,
            json!({ "findings": [{
                "category": "bug", "severity": "high",
                "title": "x".repeat(MAX_FINDING_TITLE_BYTES + 1),
                "description": "d", "file": "a.rs"
            }] }),
            "title",
        ),
    ] {
        let error = exec
            .execute(tool, &input)
            .err()
            .expect("inputs beyond declared limits must be rejected");
        assert!(error.contains(field), "{error}");
    }
}

#[test]
fn tool_output_serialization_stops_at_the_byte_limit() {
    assert_eq!(
        serialize_tool_output(&json!({ "ok": true })).unwrap(),
        "{\n  \"ok\": true\n}"
    );

    let error = serialize_tool_output(&"x".repeat(MAX_TOOL_OUTPUT_BYTES))
        .expect_err("oversized tool output must be rejected");

    assert!(error.contains(&MAX_TOOL_OUTPUT_BYTES.to_string()));
}

#[test]
fn read_file_blocks_path_traversal() {
    let (dir, engine, counter) = executor_env();
    let exec = executor(&dir, &engine, &counter);

    let result = exec.execute(tools::READ_FILE, &json!({ "path": "../../../etc/passwd" }));

    assert!(result.is_err());
}

#[test]
fn read_file_normalizes_windows_separators_and_blocks_windows_escapes() {
    let (dir, engine, counter) = executor_env();
    fs::create_dir(dir.path().join("src")).unwrap();
    fs::write(dir.path().join("src").join("main.rs"), "fn portable() {}\n").unwrap();
    let exec = executor(&dir, &engine, &counter);

    let result = exec
        .execute(tools::READ_FILE, &json!({ "path": r"src\main.rs" }))
        .unwrap();
    assert!(result.text.contains("fn portable()"));

    for path in [
        r"..\outside.rs",
        r"C:\Windows\system.ini",
        r"\\server\share\secret",
        "a.rs:alternate-stream",
    ] {
        assert!(
            exec.execute(tools::READ_FILE, &json!({ "path": path }))
                .is_err(),
            "{path} must be rejected"
        );
    }
}

#[cfg(unix)]
#[test]
fn read_file_blocks_symlinks_escaping_the_project() {
    let (dir, engine, counter) = executor_env();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("secret"), "private").unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("secret"),
        dir.path().join("linked-secret"),
    )
    .unwrap();
    let exec = executor(&dir, &engine, &counter);

    let result = exec.execute(tools::READ_FILE, &json!({ "path": "linked-secret" }));

    assert!(result.is_err());
}

#[test]
fn read_file_rejects_incomplete_line_ranges() {
    let (dir, engine, counter) = executor_env();
    let exec = executor(&dir, &engine, &counter);

    for input in [
        json!({ "path": "a.rs", "start_line": 1 }),
        json!({ "path": "a.rs", "end_line": 1 }),
    ] {
        let error = exec
            .execute(tools::READ_FILE, &input)
            .err()
            .expect("an incomplete line range must be rejected");
        assert!(error.contains("start_line and end_line"));
    }
}

#[test]
fn read_file_rejects_invalid_line_ranges() {
    let (dir, engine, counter) = executor_env();
    let exec = executor(&dir, &engine, &counter);

    for input in [
        json!({ "path": "a.rs", "start_line": 0, "end_line": 1 }),
        json!({ "path": "a.rs", "start_line": 2, "end_line": 1 }),
    ] {
        assert!(exec.execute(tools::READ_FILE, &input).is_err());
    }
}

#[test]
fn read_file_rejects_gitignored_files() {
    let (dir, engine, counter) = executor_env();
    fs::write(dir.path().join(".gitignore"), "ignored.rs\n").unwrap();
    fs::write(dir.path().join("ignored.rs"), "fn ignored() {}").unwrap();
    let exec = executor(&dir, &engine, &counter);

    let error = exec
        .execute(tools::READ_FILE, &json!({ "path": "ignored.rs" }))
        .err()
        .expect("gitignored files must not be readable by the model");

    assert!(error.contains("ignored by repository policy"));
}

#[cfg(unix)]
#[test]
fn read_file_rejects_policy_matching_symlink_names() {
    let (dir, engine, counter) = executor_env();
    fs::write(dir.path().join(".gitignore"), "ignored.rs\n").unwrap();
    std::os::unix::fs::symlink("a.rs", dir.path().join(".env")).unwrap();
    std::os::unix::fs::symlink("a.rs", dir.path().join("ignored.rs")).unwrap();
    let exec = executor(&dir, &engine, &counter);

    for path in [".env", "ignored.rs"] {
        assert!(
            exec.execute(tools::READ_FILE, &json!({ "path": path }))
                .is_err(),
            "policy-matching symlink {path} must not expose its target"
        );
    }
}

#[cfg(unix)]
#[test]
fn model_tools_reject_symlinks_whose_targets_are_policy_protected() {
    let (dir, engine, counter) = executor_env();
    fs::write(dir.path().join(".env"), "SECRET=must-not-reach-the-model\n").unwrap();
    fs::write(dir.path().join(".gitignore"), "ignored.rs\n").unwrap();
    fs::write(
        dir.path().join("ignored.rs"),
        "fn must_not_reach_the_model() {}\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(".env", dir.path().join("public.txt")).unwrap();
    std::os::unix::fs::symlink("ignored.rs", dir.path().join("public.rs")).unwrap();
    let exec = executor(&dir, &engine, &counter);

    for path in ["public.txt", "public.rs"] {
        let error = exec
            .execute(tools::READ_FILE, &json!({ "path": path }))
            .err()
            .expect("a policy-protected target must not be readable through a symlink");
        assert!(error.contains("ignored by repository policy"), "{error}");
    }

    let searched = exec
        .execute(
            tools::SEARCH_TEXT,
            &json!({ "pattern": "must-not-reach-the-model|must_not_reach_the_model" }),
        )
        .unwrap();
    assert!(!searched.text.contains("must-not-reach-the-model"));
    assert!(!searched.text.contains("must_not_reach_the_model"));

    let ast_error = exec
        .execute(
            tools::SEARCH_AST,
            &json!({
                "path": "public.rs",
                "language": "rust",
                "query": "(function_item) @function"
            }),
        )
        .err()
        .expect("AST search must not bypass target policy through a symlink");
    assert!(
        ast_error.contains("ignored by repository policy"),
        "{ast_error}"
    );
}

#[cfg(unix)]
#[test]
fn review_scope_applies_to_a_symlinks_canonical_target() {
    let (dir, engine, counter) = scoped_env();
    std::os::unix::fs::symlink("b.rs", dir.path().join("alias.rs")).unwrap();
    let exec = review_executor(&engine, &dir, &counter, &[("alias.rs", &[(1, 1)])]);

    let error = exec
        .execute(tools::READ_FILE, &json!({ "path": "alias.rs" }))
        .err()
        .expect("an allowed alias must not expose an out-of-scope target");

    assert_eq!(error, "'b.rs' is outside the PR review scope");
}

#[test]
fn read_file_allows_gitignore_whitelists() {
    let (dir, engine, counter) = executor_env();
    fs::write(dir.path().join(".gitignore"), "*.rs\n!a.rs\n").unwrap();
    let exec = executor(&dir, &engine, &counter);

    assert!(
        exec.execute(tools::READ_FILE, &json!({ "path": "a.rs" }))
            .is_ok()
    );
}

#[test]
fn search_ast_rejects_gitignored_files() {
    let (dir, engine, counter) = executor_env();
    fs::write(dir.path().join(".gitignore"), "a.rs\n").unwrap();
    let exec = executor(&dir, &engine, &counter);

    let error = exec
        .execute(
            tools::SEARCH_AST,
            &json!({ "path": "a.rs", "language": "rust", "query": "(function_item) @function" }),
        )
        .err()
        .expect("AST search must not bypass repository ignores");

    assert!(error.contains("ignored by repository policy"));
}

#[test]
fn read_file_rejects_sensitive_files() {
    let (dir, engine, counter) = executor_env();
    fs::write(dir.path().join(".env"), "API_TOKEN=secret").unwrap();
    let exec = executor(&dir, &engine, &counter);

    let error = exec
        .execute(tools::READ_FILE, &json!({ "path": ".env" }))
        .err()
        .expect("sensitive files must not be readable by the model");

    assert!(error.contains("ignored by repository policy"));
}

#[test]
fn read_file_records_coverage_when_tracker_is_wired() {
    let (dir, engine, counter) = executor_env();
    let tracker = Arc::new(CoverageTracker::new());
    let exec = executor(&dir, &engine, &counter).with_coverage(Arc::clone(&tracker));

    exec.execute(tools::READ_FILE, &json!({ "path": "a.rs" }))
        .unwrap();

    let read = tracker.read_paths();
    assert!(
        read.contains("a.rs"),
        "expected a.rs to be recorded, got {read:?}"
    );
}

#[test]
fn coverage_is_not_recorded_without_a_tracker() {
    let (dir, engine, counter) = executor_env();
    let exec = executor(&dir, &engine, &counter);
    exec.execute(tools::READ_FILE, &json!({ "path": "a.rs" }))
        .unwrap();
}

#[test]
fn a_read_that_cannot_be_delivered_is_not_recorded_as_inspected() {
    let (dir, engine, counter) = executor_env();
    fs::write(dir.path().join("wide.rs"), "\u{1}".repeat(400_000)).unwrap();
    let tracker = Arc::new(CoverageTracker::new());
    let exec = executor(&dir, &engine, &counter).with_coverage(Arc::clone(&tracker));

    let error = exec
        .execute(tools::READ_FILE, &json!({ "path": "wide.rs" }))
        .err()
        .expect("output past the byte limit must not be delivered");

    assert!(
        error.contains(&MAX_TOOL_OUTPUT_BYTES.to_string()),
        "{error}"
    );
    assert!(
        tracker.read_paths().is_empty(),
        "a file the model never received must not count as inspected"
    );
}

fn review_executor(
    engine: &Arc<dyn Engine>,
    dir: &TempDir,
    counter: &Arc<FindingCounter>,
    spans: &[(&str, &[(u32, u32)])],
) -> ToolExecutor {
    let allowed_files = spans
        .iter()
        .map(|(path, _)| (*path).to_string())
        .collect::<BTreeSet<_>>();
    executor(dir, engine, counter)
        .with_allowed_files(allowed_files)
        .with_finding_scope(changed_lines(spans))
}

fn finding_at(file: &str, line_start: u32, line_end: u32) -> Value {
    json!({ "findings": [{
        "category": "bug", "severity": "high", "title": "t", "description": "d",
        "file": file, "line_start": line_start, "line_end": line_end
    }]})
}

#[test]
fn review_tools_hide_files_outside_the_changed_file_scope() {
    let (dir, engine, counter) = scoped_env();
    let exec = review_executor(&engine, &dir, &counter, &[("a.rs", &[(1, 1)])]);

    let read_error = exec
        .execute(tools::READ_FILE, &json!({ "path": "b.rs" }))
        .err()
        .expect("an unchanged file must not be readable");
    assert_eq!(read_error, "'b.rs' is outside the PR review scope");

    let searched = exec
        .execute(tools::SEARCH_TEXT, &json!({ "pattern": "fn " }))
        .unwrap();
    assert!(searched.text.contains("a.rs"), "{}", searched.text);
    assert!(!searched.text.contains("b.rs"), "{}", searched.text);

    let discovered = exec.execute(tools::DISCOVER_FILES, &json!({})).unwrap();
    assert!(discovered.text.contains("a.rs"), "{}", discovered.text);
    assert!(!discovered.text.contains("b.rs"), "{}", discovered.text);

    let ast_error = exec
        .execute(
            tools::SEARCH_AST,
            &json!({ "path": "b.rs", "language": "rust", "query": "(function_item) @function" }),
        )
        .err()
        .expect("AST search must not bypass review scope");
    assert_eq!(ast_error, "'b.rs' is outside the PR review scope");
}

#[test]
fn review_filters_files_before_applying_result_caps() {
    let (dir, engine, counter) = scoped_env();
    fs::write(dir.path().join("z.rs"), "fn changed() {}\n").unwrap();
    let exec = review_executor(&engine, &dir, &counter, &[("z.rs", &[(1, 1)])]);

    let searched = exec
        .execute(
            tools::SEARCH_TEXT,
            &json!({ "pattern": "fn ", "max_results": 1 }),
        )
        .unwrap();
    assert!(searched.text.contains("z.rs"), "{}", searched.text);
    assert!(!searched.text.contains("a.rs"), "{}", searched.text);

    let discovered = exec
        .execute(tools::DISCOVER_FILES, &json!({ "max_results": 1 }))
        .unwrap();
    assert!(discovered.text.contains("z.rs"), "{}", discovered.text);
    assert!(!discovered.text.contains("a.rs"), "{}", discovered.text);
    assert!(!discovered.text.contains("b.rs"), "{}", discovered.text);
}

#[test]
fn an_unchanged_file_cannot_receive_a_finding() {
    let (dir, engine, counter) = scoped_env();
    let exec = review_executor(&engine, &dir, &counter, &[("a.rs", &[(1, 1)])]);

    let error = exec
        .execute(tools::SUBMIT_FINDINGS, &finding_at("b.rs", 1, 1))
        .err()
        .expect("a finding on an unchanged file must be refused");

    assert_eq!(
        error,
        "finding 1: 'b.rs' is not a file this pull request changed; review only changed files"
    );
}

#[test]
fn unchanged_lines_in_a_changed_file_cannot_receive_a_finding() {
    let (dir, engine, counter) = executor_env();
    fs::write(dir.path().join("a.rs"), "one\ntwo\nthree\nfour\nfive\n").unwrap();
    let exec = review_executor(&engine, &dir, &counter, &[("a.rs", &[(4, 5)])]);

    let accepted = exec
        .execute(tools::SUBMIT_FINDINGS, &finding_at("a.rs", 3, 4))
        .expect("a range reaching into the hunk is in scope");
    let error = exec
        .execute(tools::SUBMIT_FINDINGS, &finding_at("a.rs", 1, 3))
        .err()
        .expect("a range entirely outside the hunk must be refused");

    assert_eq!(accepted.findings.len(), 1);
    assert_eq!(
        error,
        "finding 1: 'a.rs' finding at lines 1-3 touches no line this pull request changed"
    );
}

#[test]
fn a_review_finding_without_a_line_range_is_refused() {
    let (dir, engine, counter) = executor_env();
    let exec = review_executor(&engine, &dir, &counter, &[("a.rs", &[(1, 1)])]);

    let error = exec
        .execute(
            tools::SUBMIT_FINDINGS,
            &json!({ "findings": [{
                "category": "bug", "severity": "high", "title": "t", "description": "d",
                "file": "a.rs"
            }]}),
        )
        .err()
        .expect("a review finding must state the lines it reports");

    assert!(error.contains("must state the changed lines"), "{error}");
}

#[test]
fn snippet_relocation_cannot_move_a_finding_out_of_a_changed_hunk() {
    let (dir, engine, counter) = executor_env();
    fs::write(
        dir.path().join("a.rs"),
        "fn untouched() {\n    danger();\n}\n\nfn changed() {}\n",
    )
    .unwrap();
    let exec = review_executor(&engine, &dir, &counter, &[("a.rs", &[(5, 5)])]);

    let error = exec
        .execute(
            tools::SUBMIT_FINDINGS,
            &json!({ "findings": [{
                "category": "bug", "severity": "high", "title": "t", "description": "d",
                "file": "a.rs", "line_start": 5, "line_end": 5,
                "code_snippet": "    danger();"
            }]}),
        )
        .err()
        .expect("relocation must not smuggle a finding out of the diff");

    assert_eq!(
        error,
        "finding 1: 'a.rs' finding at lines 2-2 touches no line this pull request changed"
    );
}

#[test]
fn a_terminal_newline_cannot_move_unchanged_evidence_into_a_changed_hunk() {
    let (dir, engine, counter) = executor_env();
    fs::write(dir.path().join("a.rs"), "danger();\nchanged();\n").unwrap();
    let exec = review_executor(&engine, &dir, &counter, &[("a.rs", &[(2, 2)])]);

    let error = exec
        .execute(
            tools::SUBMIT_FINDINGS,
            &json!({ "findings": [{
                "category": "bug", "severity": "high", "title": "t", "description": "d",
                "file": "a.rs", "code_snippet": "danger();\n"
            }]}),
        )
        .err()
        .expect("a trailing newline must not extend evidence into the changed line");

    assert_eq!(
        error,
        "finding 1: 'a.rs' finding at lines 1-1 touches no line this pull request changed"
    );
}

#[test]
fn a_review_finding_with_an_unverifiable_snippet_is_refused() {
    let (dir, engine, counter) = executor_env();
    fs::write(dir.path().join("a.rs"), "danger();\ndanger();\n").unwrap();
    let exec = review_executor(&engine, &dir, &counter, &[("a.rs", &[(1, 2)])]);

    let error = exec
        .execute(
            tools::SUBMIT_FINDINGS,
            &json!({ "findings": [{
                "category": "bug", "severity": "high", "title": "t", "description": "d",
                "file": "a.rs", "line_start": 1, "line_end": 1,
                "code_snippet": "danger();"
            }]}),
        )
        .err()
        .expect("an ambiguous snippet leaves the reported lines unverified");

    assert!(error.contains("does not appear exactly once"), "{error}");
}

#[test]
fn a_review_finding_past_the_end_of_the_file_is_refused() {
    let (dir, engine, counter) = executor_env();
    fs::write(dir.path().join("a.rs"), "one\ntwo\n").unwrap();
    let exec = review_executor(&engine, &dir, &counter, &[("a.rs", &[(1, 900)])]);

    let error = exec
        .execute(tools::SUBMIT_FINDINGS, &finding_at("a.rs", 1, 900))
        .err()
        .expect("a range beyond the file must not be reported");

    assert!(
        error.contains("runs past the end of the file (2 lines)"),
        "{error}"
    );
}

#[test]
fn project_stats_ignores_the_review_scope() {
    let (dir, engine, counter) = scoped_env();
    let exec = review_executor(&engine, &dir, &counter, &[("a.rs", &[(1, 1)])]);

    let outcome = exec.execute(tools::PROJECT_STATS, &json!({})).unwrap();
    let stats: Value = serde_json::from_str(&outcome.text).unwrap();

    assert_eq!(stats["total_files"], 2);
}

#[test]
fn an_unscoped_executor_reaches_every_project_file() {
    let (dir, engine, counter) = scoped_env();
    let exec = executor(&dir, &engine, &counter);

    assert!(
        exec.execute(tools::READ_FILE, &json!({ "path": "b.rs" }))
            .is_ok()
    );
    let discovered = exec.execute(tools::DISCOVER_FILES, &json!({})).unwrap();
    assert!(discovered.text.contains("b.rs"));
    let searched = exec
        .execute(tools::SEARCH_TEXT, &json!({ "pattern": "fn " }))
        .unwrap();
    assert!(searched.text.contains("b.rs"));
    assert!(
        exec.execute(
            tools::SUBMIT_FINDINGS,
            &json!({ "findings": [{
                "category": "bug", "severity": "high",
                "title": "t", "description": "d", "file": "b.rs"
            }]}),
        )
        .is_ok(),
        "outside a review, a finding needs no line range"
    );
}

#[test]
fn in_scope_reads_report_the_inspected_path() {
    let (dir, engine, counter) = scoped_env();
    let exec = review_executor(&engine, &dir, &counter, &[("a.rs", &[(1, 1)])]);

    let read = exec
        .execute(tools::READ_FILE, &json!({ "path": "a.rs" }))
        .unwrap();

    assert_eq!(read.inspected_path.as_deref(), Some("a.rs"));
}

#[test]
fn tools_other_than_read_file_report_no_inspected_path() {
    let (dir, engine, counter) = executor_env();
    let exec = executor(&dir, &engine, &counter);

    let discovered = exec.execute(tools::DISCOVER_FILES, &json!({})).unwrap();
    let submitted = exec
        .execute(tools::SUBMIT_FINDINGS, &json!({ "findings": [] }))
        .unwrap();

    assert!(discovered.inspected_path.is_none());
    assert!(submitted.inspected_path.is_none());
}

#[test]
fn discover_files_applies_the_result_cap() {
    let (dir, engine, counter) = scoped_env();
    fs::write(dir.path().join("zz.rs"), "fn last() {}\n").unwrap();
    let exec = executor(&dir, &engine, &counter);

    let outcome = exec
        .execute(tools::DISCOVER_FILES, &json!({ "max_results": 2 }))
        .unwrap();
    let entries: Value = serde_json::from_str(&outcome.text).unwrap();

    assert_eq!(entries.as_array().unwrap().len(), 2);
}

#[test]
fn inventory_executor_reuses_the_same_snapshot_for_discovery_search_and_stats() {
    let (dir, engine, counter) = scoped_env();
    let inventory = ProjectInventory::build(dir.path(), &EngineConfig::default()).unwrap();
    fs::write(dir.path().join("late.rs"), "fn late() {}\n").unwrap();
    let exec = ToolExecutor::from_inventory(
        Arc::clone(&engine),
        Arc::new(inventory),
        Arc::clone(&counter),
    );

    let discovered = exec.execute(tools::DISCOVER_FILES, &json!({})).unwrap();
    let searched = exec
        .execute(tools::SEARCH_TEXT, &json!({ "pattern": "fn " }))
        .unwrap();
    let stats = exec.execute(tools::PROJECT_STATS, &json!({})).unwrap();
    let parsed_stats: Value = serde_json::from_str(&stats.text).unwrap();

    assert!(discovered.text.contains("a.rs"));
    assert!(discovered.text.contains("b.rs"));
    assert!(!discovered.text.contains("late.rs"));
    assert!(searched.text.contains("a.rs"));
    assert!(searched.text.contains("b.rs"));
    assert!(!searched.text.contains("late.rs"));
    assert_eq!(parsed_stats["total_files"], 2);
}

#[test]
fn discover_files_honors_extension_name_and_depth_filters_together() {
    let (dir, engine, counter) = executor_env();
    fs::create_dir(dir.path().join("nested")).unwrap();
    fs::write(dir.path().join("match.rs"), "fn matching() {}\n").unwrap();
    fs::write(dir.path().join("match.py"), "def matching(): pass\n").unwrap();
    fs::write(
        dir.path().join("nested").join("match.rs"),
        "fn nested() {}\n",
    )
    .unwrap();
    let inventory = ProjectInventory::build(dir.path(), &EngineConfig::default()).unwrap();
    let exec = ToolExecutor::from_inventory(
        Arc::clone(&engine),
        Arc::new(inventory),
        Arc::clone(&counter),
    );

    let outcome = exec
        .execute(
            tools::DISCOVER_FILES,
            &json!({
                "extensions": ["rs"],
                "pattern": "match",
                "max_depth": 1
            }),
        )
        .unwrap();
    let entries: Value = serde_json::from_str(&outcome.text).unwrap();

    assert_eq!(
        entries
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["relative_path"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["match.rs"]
    );
}

#[test]
fn submit_findings_rejects_directories_as_evidence_paths() {
    let (dir, engine, counter) = executor_env();
    fs::create_dir(dir.path().join("src")).unwrap();
    let exec = executor(&dir, &engine, &counter);

    let error = match exec.execute(
        tools::SUBMIT_FINDINGS,
        &json!({ "findings": [{
            "category": "bug",
            "severity": "high",
            "title": "directory",
            "description": "not source",
            "file": "src"
        }]}),
    ) {
        Ok(_) => panic!("a directory cannot be accepted as finding evidence"),
        Err(error) => error,
    };

    assert!(error.contains("finding path is not a file: 'src'"));
}

#[test]
fn bounded_json_writer_accepts_the_exact_limit_and_flushes_without_mutation() {
    let mut writer = BoundedJsonWriter {
        bytes: Vec::new(),
        limit: 3,
    };

    assert_eq!(writer.write(b"abc").unwrap(), 3);
    writer.flush().unwrap();

    assert_eq!(writer.bytes, b"abc");
}

#[test]
fn parser_helpers_cover_optional_and_invalid_boundaries() {
    assert!(validate_filters("extensions", None).is_ok());
    assert!(validate_optional_text("pattern", None, 1).is_ok());
    assert!(validate_optional_max("snippet", None, 1).is_ok());
    assert_eq!(parse_line_range(None, None).unwrap(), None);
    assert!(parse_line_range(Some(1), None).is_err());
    assert!(parse_line_range(None, Some(1)).is_err());
    assert!(parse_line_range(Some(2), Some(1)).is_err());
    assert_eq!(parse_severity("critical"), Some(Severity::Critical));
    assert_eq!(parse_severity("medium"), Some(Severity::Medium));
    assert_eq!(parse_severity("low"), Some(Severity::Low));
    assert_eq!(parse_severity("info"), Some(Severity::Info));
    assert_eq!(parse_severity("unknown"), None);
    assert_eq!(parse_confidence("high"), Some(Confidence::High));
    assert_eq!(parse_confidence("medium"), Some(Confidence::Medium));
    assert_eq!(parse_confidence("low"), Some(Confidence::Low));
    assert_eq!(parse_confidence("unknown"), None);
}

#[test]
fn submit_findings_keeps_the_optional_suggestion_and_rule() {
    let (dir, engine, counter) = executor_env();
    let exec = executor(&dir, &engine, &counter);

    let outcome = exec
        .execute(
            tools::SUBMIT_FINDINGS,
            &json!({ "findings": [{
                "category": "bug", "severity": "high",
                "title": "boom", "description": "d", "file": "a.rs",
                "suggestion": "Guard the empty case", "rule": "bug.null-deref"
            }]}),
        )
        .unwrap();

    let finding = &outcome.findings[0];
    assert_eq!(finding.suggestion.as_deref(), Some("Guard the empty case"));
    assert_eq!(finding.rule.as_deref(), Some("bug.null-deref"));
    assert_eq!(finding.confidence, Confidence::Medium);
}

#[test]
fn submit_findings_enforces_every_finding_field_bound() {
    let (dir, engine, counter) = executor_env();
    let exec = executor(&dir, &engine, &counter);
    let accepted = json!({
        "category": "bug", "severity": "high",
        "title": "boom", "description": "d", "file": "a.rs"
    });
    let submission = |field: &str, value: Value| {
        let mut finding = accepted.clone();
        finding[field] = value;
        json!({ "findings": [finding] })
    };

    for (field, value, reason) in [
        (
            "description",
            json!("x".repeat(MAX_FINDING_DESCRIPTION_BYTES + 1)),
            format!("exceeds {MAX_FINDING_DESCRIPTION_BYTES} bytes"),
        ),
        (
            "code_snippet",
            json!("x".repeat(MAX_FINDING_SNIPPET_BYTES + 1)),
            format!("exceeds {MAX_FINDING_SNIPPET_BYTES} bytes"),
        ),
        (
            "suggestion",
            json!("x".repeat(MAX_FINDING_SUGGESTION_BYTES + 1)),
            format!("exceeds {MAX_FINDING_SUGGESTION_BYTES} bytes"),
        ),
        (
            "rule",
            json!("x".repeat(MAX_FINDING_RULE_BYTES + 1)),
            format!("exceeds {MAX_FINDING_RULE_BYTES} bytes"),
        ),
        ("description", json!("   "), "must not be empty".to_string()),
    ] {
        let error = exec
            .execute(tools::SUBMIT_FINDINGS, &submission(field, value))
            .err()
            .unwrap_or_else(|| panic!("{field} beyond its bound must be rejected"));

        assert!(error.starts_with("finding 1: "), "{error}");
        assert!(error.contains(&format!("field '{field}'")), "{error}");
        assert!(error.contains(&reason), "{error}");
    }
}
