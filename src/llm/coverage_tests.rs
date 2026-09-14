use super::*;
use crate::config::EngineConfig;
use crate::config::schema::{AnalysisCategory, LlmConfig, Severity};
use crate::engine::{DefaultEngine, ProjectInventory};
use crate::errors::LlmError;
use crate::llm::tools::{READ_FILE, SUBMIT_FINDINGS};
use crate::llm::types::{
    ContentBlock, LlmOutput, LlmResponse, Message, Role, StopReason, TokenUsage, ToolConfig,
    ToolUseBlock,
};
use async_trait::async_trait;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex as StdMutex};

struct ScriptedBackend {
    responses: StdMutex<Vec<LlmResponse>>,
    calls: StdMutex<Vec<Vec<Message>>>,
}

impl ScriptedBackend {
    fn new(responses: Vec<LlmResponse>) -> Self {
        Self {
            responses: StdMutex::new(responses),
            calls: StdMutex::new(Vec::new()),
        }
    }

    fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }

    fn shard_start_calls(&self) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|messages| messages.len() == 1)
            .count()
    }
}

fn tool_result(backend: &ScriptedBackend, tool_use_id: &str) -> crate::llm::types::ToolResultBlock {
    backend
        .calls
        .lock()
        .unwrap()
        .iter()
        .flat_map(|messages| messages.iter())
        .flat_map(|message| message.content.iter())
        .find_map(|block| match block {
            ContentBlock::ToolResult { tool_result } if tool_result.tool_use_id == tool_use_id => {
                Some(tool_result.clone())
            }
            _ => None,
        })
        .expect("the model must receive the requested tool result")
}

#[async_trait]
impl LlmBackend for ScriptedBackend {
    async fn converse(
        &self,
        messages: &[Message],
        _system_prompt: &str,
        _tool_config: &ToolConfig,
    ) -> Result<LlmResponse, LlmError> {
        self.calls.lock().unwrap().push(messages.to_vec());
        let mut queue = self.responses.lock().unwrap();
        assert!(!queue.is_empty(), "ScriptedBackend exhausted");
        Ok(queue.remove(0))
    }
}

fn submit_response(id: &str, file: &str, title: &str) -> LlmResponse {
    LlmResponse {
        output: LlmOutput {
            message: Message {
                role: Role::Assistant,
                content: vec![ContentBlock::ToolUse {
                    tool_use: ToolUseBlock {
                        tool_use_id: id.into(),
                        name: SUBMIT_FINDINGS.into(),
                        input: json!({ "findings": [{
                            "category": "bug", "severity": "high",
                            "title": title, "description": "d", "file": file,
                            "line_start": 1, "line_end": 5, "confidence": "high"
                        }]}),
                    },
                }],
            },
        },
        stop_reason: StopReason::ToolUse,
        usage: TokenUsage::default(),
    }
}

fn read_response(id: &str, file: &str) -> LlmResponse {
    LlmResponse {
        output: LlmOutput {
            message: Message {
                role: Role::Assistant,
                content: vec![ContentBlock::ToolUse {
                    tool_use: ToolUseBlock {
                        tool_use_id: id.into(),
                        name: READ_FILE.into(),
                        input: json!({ "path": file }),
                    },
                }],
            },
        },
        stop_reason: StopReason::ToolUse,
        usage: TokenUsage::default(),
    }
}

fn end_turn_response() -> LlmResponse {
    LlmResponse {
        output: LlmOutput {
            message: Message {
                role: Role::Assistant,
                content: vec![ContentBlock::Text {
                    text: "done".into(),
                }],
            },
        },
        stop_reason: StopReason::EndTurn,
        usage: TokenUsage::default(),
    }
}

fn three_shard_project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let body = "// filler\n".repeat(5_000);
    for name in ["a", "b", "c"] {
        let sub = dir.path().join(name);
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("f.rs"), format!("fn {name}() {{}}\n{body}")).unwrap();
    }
    dir
}

fn small_window_config() -> Config {
    Config {
        llm: LlmConfig {
            max_context_tokens: MIN_CONTEXT_TOKENS,
            ..LlmConfig::default()
        },
        ..Config::default()
    }
}

#[tokio::test]
async fn runs_once_per_shard_and_aggregates_deduped_findings() {
    let backend = ScriptedBackend::new(vec![
        read_response("r1", "a/f.rs"),
        submit_response("s1", "a/f.rs", "dup"),
        end_turn_response(),
        read_response("r2", "b/f.rs"),
        submit_response("s2", "a/f.rs", "dup"),
        end_turn_response(),
        read_response("r3", "c/f.rs"),
        submit_response("s3", "c/f.rs", "other"),
        end_turn_response(),
    ]);
    let engine: Arc<dyn crate::engine::Engine> =
        Arc::new(DefaultEngine::new(EngineConfig::default()));
    let counter = Arc::new(FindingCounter::new());
    let project = three_shard_project();
    let config = small_window_config();
    let inventory = Arc::new(ProjectInventory::build(project.path(), &config.engine).unwrap());

    let cancel = CancelToken::default();
    let analysis = run_sharded_analysis(ShardedAnalysisRequest {
        backend: &backend,
        engine: Arc::clone(&engine),
        inventory: Arc::clone(&inventory),
        config: &config,
        counter: Arc::clone(&counter),
        system_prompt: "SYS",
        reporter: &Reporter::new(crate::tui::shared_state()),
        review: None,
        cancel: &cancel,
    })
    .await
    .expect("sharded run should succeed");

    assert_eq!(backend.shard_start_calls(), 3, "expected one run per shard");
    assert_eq!(backend.call_count(), 9);
    assert_eq!(
        analysis.findings.len(),
        2,
        "duplicate finding across shards must collapse to one"
    );
    assert_eq!(analysis.status.completeness, ScanCompleteness::Complete);
    assert_eq!(analysis.status.files_inspected, 3);
    assert_eq!(analysis.status.shards_total, 3);
    assert_eq!(analysis.status.shards_completed, 3);
    assert!(analysis.status.failed_shards.is_empty());
    assert_eq!(analysis.status.files_presented, 3);
}

fn finding(counter: &FindingCounter, title: &str, file: &str) -> Finding {
    Finding::new_static(
        counter,
        AnalysisCategory::Bug,
        Severity::High,
        title.into(),
        "d".into(),
        file.into(),
    )
}

#[test]
fn shard_budget_scales_with_window_and_matches_the_minimum_context_window() {
    assert_eq!(shard_content_budget(1_000_000), 400_000);
    assert_eq!(
        shard_content_budget(MIN_CONTEXT_TOKENS),
        MIN_SHARD_BUDGET_TOKENS
    );
}

#[test]
fn retention_overflow_reports_dropped_findings_and_bytes() {
    let mut overflow = RetentionOverflow::default();

    overflow.drop(37);

    let reason = overflow.reason().unwrap();
    assert!(reason.contains("1 findings"));
    assert!(reason.contains("37 bytes"));
}

#[test]
fn shard_success_records_analysis_wide_retention_overflow() {
    let project = two_file_project();
    let config = small_window_config();
    let inventory = Arc::new(ProjectInventory::build(project.path(), &config.engine).unwrap());
    let backend = ResultBackend::new(Vec::new());
    let engine: Arc<dyn crate::engine::Engine> =
        Arc::new(DefaultEngine::new(EngineConfig::default()));
    let counter = Arc::new(FindingCounter::new());
    let reporter = Reporter::new(crate::tui::shared_state());
    let cancel = CancelToken::default();
    let tracker = Arc::new(CoverageTracker::new());
    let executor = ShardExecutor::new(
        ShardedAnalysisRequest {
            backend: &backend,
            engine,
            inventory,
            config: &config,
            counter: Arc::clone(&counter),
            system_prompt: "SYS",
            reporter: &reporter,
            review: None,
            cancel: &cancel,
        },
        tracker,
        config.llm.effective_context_tokens(),
        1,
    );
    let mut outcome = ShardOutcome {
        retained_bytes: MAX_FINDING_BYTES_PER_RUN,
        ..ShardOutcome::default()
    };

    executor.record_shard_success(
        0,
        vec![finding(counter.as_ref(), "overflow", "first.rs")],
        &mut outcome,
    );

    assert!(outcome.aggregate.is_empty());
    assert_eq!(outcome.skipped.entries().len(), 1);
    assert!(outcome.skipped.entries()[0].contains("analysis-wide finding budget exhausted"));
}

#[test]
fn tracker_records_and_reports_read_paths() {
    let tracker = Arc::new(CoverageTracker::new());
    tracker.record("src/a.rs".into());
    tracker.record("src/a.rs".into());
    tracker.record("src/b.rs".into());

    let read = tracker.read_paths();
    assert_eq!(read.len(), 2);
    assert!(read.contains("src/a.rs"));
    assert!(read.contains("src/b.rs"));
}

#[test]
fn dedupe_drops_same_file_title_with_overlapping_lines() {
    let counter = Arc::new(FindingCounter::new());
    let a = finding(&counter, "leak", "src/a.rs").with_lines(10, 20);
    let b = finding(&counter, "leak", "src/a.rs").with_lines(15, 25);

    let deduped = dedupe_findings(vec![a, b]);
    assert_eq!(deduped.len(), 1);
}

#[test]
fn dedupe_keeps_non_overlapping_line_ranges() {
    let counter = Arc::new(FindingCounter::new());
    let a = finding(&counter, "leak", "src/a.rs").with_lines(10, 20);
    let b = finding(&counter, "leak", "src/a.rs").with_lines(40, 50);

    let deduped = dedupe_findings(vec![a, b]);
    assert_eq!(deduped.len(), 2);
}

#[test]
fn dedupe_keeps_same_identity_without_line_ranges() {
    let counter = Arc::new(FindingCounter::new());
    let first = finding(&counter, "leak", "src/a.rs");
    let second = finding(&counter, "leak", "src/a.rs");

    let deduped = dedupe_findings(vec![first, second]);
    assert_eq!(deduped.len(), 2);
}

#[test]
fn dedupe_keeps_findings_in_different_files() {
    let counter = Arc::new(FindingCounter::new());
    let a = finding(&counter, "leak", "src/a.rs").with_lines(10, 20);
    let b = finding(&counter, "leak", "src/b.rs").with_lines(10, 20);

    let deduped = dedupe_findings(vec![a, b]);
    assert_eq!(deduped.len(), 2);
}

#[test]
fn dedupe_distinguishes_by_rule_when_present() {
    let counter = Arc::new(FindingCounter::new());
    let a = finding(&counter, "same", "src/a.rs")
        .with_lines(10, 20)
        .with_rule("bug.one".into());
    let b = finding(&counter, "same", "src/a.rs")
        .with_lines(10, 20)
        .with_rule("bug.two".into());

    let deduped = dedupe_findings(vec![a, b]);
    assert_eq!(deduped.len(), 2, "different rules are different findings");
}

struct ResultBackend {
    results: StdMutex<Vec<Result<LlmResponse, LlmError>>>,
    calls: StdMutex<usize>,
}

impl ResultBackend {
    fn new(results: Vec<Result<LlmResponse, LlmError>>) -> Self {
        Self {
            results: StdMutex::new(results),
            calls: StdMutex::new(0),
        }
    }

    fn call_count(&self) -> usize {
        *self.calls.lock().unwrap()
    }
}

#[async_trait]
impl LlmBackend for ResultBackend {
    async fn converse(
        &self,
        _messages: &[Message],
        _system_prompt: &str,
        _tool_config: &ToolConfig,
    ) -> Result<LlmResponse, LlmError> {
        *self.calls.lock().unwrap() += 1;
        let mut queue = self.results.lock().unwrap();
        assert!(!queue.is_empty(), "ResultBackend exhausted");
        queue.remove(0)
    }
}

fn overloaded() -> Result<LlmResponse, LlmError> {
    Err(LlmError::ApiError {
        status: 429,
        body: "engine overloaded".into(),
    })
}

async fn run_with(backend: &ResultBackend) -> Result<ShardedAnalysis, BugHunterError> {
    run_with_cancel(backend, &CancelToken::default()).await
}

async fn run_with_cancel(
    backend: &ResultBackend,
    cancel: &CancelToken,
) -> Result<ShardedAnalysis, BugHunterError> {
    let engine: Arc<dyn crate::engine::Engine> =
        Arc::new(DefaultEngine::new(EngineConfig::default()));
    let counter = Arc::new(FindingCounter::new());
    let project = three_shard_project();
    let config = small_window_config();
    let inventory = Arc::new(ProjectInventory::build(project.path(), &config.engine).unwrap());
    run_sharded_analysis(ShardedAnalysisRequest {
        backend,
        engine: Arc::clone(&engine),
        inventory: Arc::clone(&inventory),
        config: &config,
        counter: Arc::clone(&counter),
        system_prompt: "SYS",
        reporter: &Reporter::new(crate::tui::shared_state()),
        review: None,
        cancel,
    })
    .await
}

#[tokio::test]
async fn failed_shard_is_skipped_and_later_shards_still_run() {
    let backend = ResultBackend::new(vec![
        overloaded(),
        Ok(submit_response("s2", "b/f.rs", "second")),
        Ok(end_turn_response()),
        Ok(submit_response("s3", "c/f.rs", "third")),
        Ok(end_turn_response()),
    ]);

    let analysis = run_with(&backend)
        .await
        .expect("run must survive one bad shard");

    assert_eq!(
        analysis.findings.len(),
        2,
        "findings from the healthy shards survive"
    );
    assert_eq!(backend.call_count(), 5);
    assert_eq!(
        analysis.status.completeness,
        ScanCompleteness::Partial,
        "a failed shard leaves the scan incomplete"
    );
    assert_eq!(analysis.status.shards_total, 3);
    assert_eq!(analysis.status.shards_completed, 2);
    assert_eq!(analysis.status.failed_shards.len(), 1);
    assert_eq!(analysis.status.failed_shards[0].shard, 1);
    assert!(
        analysis.status.failed_shards[0]
            .error
            .contains("engine overloaded"),
        "the shard error is carried into the report"
    );
}

#[tokio::test]
async fn auth_error_aborts_immediately() {
    let backend = ResultBackend::new(vec![Err(LlmError::AuthError)]);

    let result = run_with(&backend).await;

    assert!(result.is_err());
    assert_eq!(
        backend.call_count(),
        1,
        "a bad token must not retry every shard"
    );
}

#[tokio::test]
async fn every_shard_failing_is_an_error_not_an_empty_report() {
    let backend = ResultBackend::new(vec![overloaded(), overloaded(), overloaded()]);

    let result = run_with(&backend).await;

    assert!(
        result.is_err(),
        "a total failure must not be reported as zero findings"
    );
}

#[tokio::test]
async fn a_cancelled_token_stops_before_the_first_shard() {
    let backend = ResultBackend::new(Vec::new());
    let cancel = CancelToken::default();
    cancel.cancel();

    let result = run_with_cancel(&backend, &cancel).await;

    assert!(matches!(
        result,
        Err(BugHunterError::Llm(LlmError::Cancelled))
    ));
    assert_eq!(
        backend.call_count(),
        0,
        "cancellation must not reach the model"
    );
}

#[test]
fn skipped_files_make_the_scan_partial() {
    let tracker = Arc::new(CoverageTracker::new());
    tracker.record("a/f.rs".into());
    let mut outcome = ShardOutcome {
        presented: BTreeSet::from(["a/f.rs".to_string(), "b/f.rs".to_string()]),
        ..ShardOutcome::default()
    };
    outcome.record_skipped("z/f.rs (shard limit reached)".into());

    let analysis = outcome.into_analysis(&tracker, MAX_SHARDS + 1);

    assert_eq!(analysis.status.completeness, ScanCompleteness::Partial);
    assert_eq!(analysis.status.shards_total, MAX_SHARDS as u32 + 1);
    assert_eq!(analysis.status.shards_completed, MAX_SHARDS as u32);
    assert_eq!(analysis.status.files_presented, 2);
    assert_eq!(analysis.status.files_inspected, 1);
    assert_eq!(
        analysis.status.uninspected_files,
        vec!["b/f.rs (model did not inspect file)".to_string()]
    );
    assert_eq!(
        analysis.status.skipped_files,
        vec!["z/f.rs (shard limit reached)".to_string()]
    );
}

#[test]
fn repo_map_omissions_are_reported_by_path_and_count() {
    let tracker = CoverageTracker::new();
    tracker.record("a/f.rs".into());
    let repo_map = repomap::RepoMap {
        text: String::new(),
        files: vec!["a/f.rs".to_string()],
        estimated_tokens: 1,
        omitted_files: 2,
        omitted_file_reports: vec!["b/f.rs (repo map byte budget exhausted)".to_string()],
        omitted_file_diagnostics: 1,
    };
    let mut outcome = ShardOutcome::default();
    outcome.record_repo_map(&repo_map);

    let analysis = outcome.into_analysis(&tracker, 1);

    assert_eq!(analysis.status.files_presented, 1);
    assert_eq!(analysis.status.files_inspected, 1);
    assert_eq!(
        analysis.status.skipped_files,
        ["b/f.rs (repo map byte budget exhausted)".to_string()]
    );
    assert_eq!(analysis.status.omitted_diagnostics, 1);
    assert_eq!(analysis.status.completeness, ScanCompleteness::Partial);
}

#[test]
fn repo_map_omissions_read_through_tools_count_as_inspected() {
    let tracker = CoverageTracker::new();
    tracker.record("a/f.rs".into());
    tracker.record("b/f.rs".into());
    let repo_map = repomap::RepoMap {
        text: String::new(),
        files: vec!["a/f.rs".to_string()],
        estimated_tokens: 1,
        omitted_files: 1,
        omitted_file_reports: vec!["b/f.rs (repo map byte budget exhausted)".to_string()],
        omitted_file_diagnostics: 0,
    };
    let mut outcome = ShardOutcome::default();
    outcome.record_repo_map(&repo_map);

    let analysis = outcome.into_analysis(&tracker, 1);

    assert_eq!(analysis.status.completeness, ScanCompleteness::Complete);
    assert_eq!(analysis.status.files_presented, 2);
    assert_eq!(analysis.status.files_inspected, 2);
    assert!(analysis.status.skipped_files.is_empty());
    assert_eq!(analysis.status.omitted_diagnostics, 0);
}

#[test]
fn an_incomplete_shard_explains_uninspected_files() {
    let tracker = CoverageTracker::new();
    let mut outcome = ShardOutcome {
        presented: BTreeSet::from(["a/f.rs".to_string()]),
        ..ShardOutcome::default()
    };
    outcome.record_incomplete_shard(2, &["a/f.rs".to_string()]);

    let analysis = outcome.into_analysis(&tracker, 3);

    assert_eq!(
        analysis.status.uninspected_files,
        ["a/f.rs (shard 3 did not complete)".to_string()]
    );
}

#[test]
fn reads_outside_the_presented_set_are_not_counted_as_inspected() {
    let tracker = Arc::new(CoverageTracker::new());
    tracker.record("a/f.rs".into());
    tracker.record("outside/f.rs".into());
    let outcome = ShardOutcome {
        presented: BTreeSet::from(["a/f.rs".to_string()]),
        ..ShardOutcome::default()
    };

    let analysis = outcome.into_analysis(&tracker, 1);

    assert_eq!(analysis.status.completeness, ScanCompleteness::Complete);
    assert_eq!(analysis.status.files_presented, 1);
    assert_eq!(analysis.status.files_inspected, 1);
    assert!(analysis.status.uninspected_files.is_empty());
}

#[test]
fn presented_files_the_model_never_opened_make_the_scan_partial() {
    let tracker = Arc::new(CoverageTracker::new());
    tracker.record("a/f.rs".into());
    let outcome = ShardOutcome {
        presented: BTreeSet::from(["a/f.rs".to_string(), "b/f.rs".to_string()]),
        ..ShardOutcome::default()
    };

    let analysis = outcome.into_analysis(&tracker, 1);

    assert_eq!(analysis.status.completeness, ScanCompleteness::Partial);
    assert!(analysis.status.failed_shards.is_empty());
    assert!(analysis.status.skipped_files.is_empty());
    assert_eq!(
        analysis.status.uninspected_files,
        vec!["b/f.rs (model did not inspect file)".to_string()]
    );
}

#[tokio::test]
async fn a_review_reports_changed_files_it_could_not_present() {
    let project = tempfile::tempdir().unwrap();
    let source = "fn changed() {\n    let x = 1;\n    let y = 2;\n    x + y\n}\n";
    std::fs::write(project.path().join("a.rs"), source).unwrap();
    let config = small_window_config();
    let inventory = Arc::new(ProjectInventory::build(project.path(), &config.engine).unwrap());
    let diff = BTreeMap::from([
        ("a.rs".to_string(), vec![(1, 1)]),
        ("gone.rs".to_string(), vec![(1, 1)]),
    ]);
    let review = ReviewSelection::from_diff(&diff, &inventory, &BTreeMap::new());
    let backend = ScriptedBackend::new(vec![
        read_response("r1", "a.rs"),
        submit_response("s1", "a.rs", "scoped"),
        end_turn_response(),
    ]);
    let engine: Arc<dyn crate::engine::Engine> =
        Arc::new(DefaultEngine::new(EngineConfig::default()));
    let counter = Arc::new(FindingCounter::new());
    let cancel = CancelToken::default();

    let analysis = run_sharded_analysis(ShardedAnalysisRequest {
        backend: &backend,
        engine: Arc::clone(&engine),
        inventory: Arc::clone(&inventory),
        config: &config,
        counter: Arc::clone(&counter),
        system_prompt: "SYS",
        reporter: &Reporter::new(crate::tui::shared_state()),
        review: Some(&review),
        cancel: &cancel,
    })
    .await
    .expect("an unanalyzable changed file must not abort the review");

    assert_eq!(analysis.findings.len(), 1);
    assert_eq!(analysis.status.files_presented, 1);
    assert_eq!(analysis.status.files_inspected, 1);
    assert_eq!(
        analysis.status.skipped_files,
        vec!["gone.rs (absent from the analyzed project)".to_string()]
    );
    assert_eq!(analysis.status.completeness, ScanCompleteness::Partial);
}

#[tokio::test]
async fn a_review_cannot_read_a_file_outside_the_changed_file_scope() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("changed.rs"),
        "fn changed() {\n    let first = 1;\n    let second = 2;\n    let _ = first + second;\n}\n",
    )
    .unwrap();
    std::fs::write(
        project.path().join("private.rs"),
        "const PRIVATE_VALUE: &str = \"must-not-reach-the-model\";\n",
    )
    .unwrap();
    let config = small_window_config();
    let inventory = Arc::new(ProjectInventory::build(project.path(), &config.engine).unwrap());
    let diff = BTreeMap::from([("changed.rs".to_string(), vec![(1, 5)])]);
    let review = ReviewSelection::from_diff(&diff, &inventory, &BTreeMap::new());
    let backend = ScriptedBackend::new(vec![
        read_response("outside-read", "private.rs"),
        read_response("changed-read", "changed.rs"),
        submit_response("submit", "changed.rs", "scoped"),
        end_turn_response(),
    ]);
    let engine: Arc<dyn crate::engine::Engine> =
        Arc::new(DefaultEngine::new(EngineConfig::default()));
    let counter = Arc::new(FindingCounter::new());
    let cancel = CancelToken::default();

    run_sharded_analysis(ShardedAnalysisRequest {
        backend: &backend,
        engine,
        inventory,
        config: &config,
        counter,
        system_prompt: "SYS",
        reporter: &Reporter::new(crate::tui::shared_state()),
        review: Some(&review),
        cancel: &cancel,
    })
    .await
    .expect("the in-scope review must continue after refusing an out-of-scope read");

    let result = tool_result(&backend, "outside-read");
    assert_eq!(
        result.status,
        Some(crate::llm::types::ToolResultStatus::Error)
    );
    assert!(result.content.contains("outside the PR review scope"));
    assert!(!result.content.contains("must-not-reach-the-model"));
}

#[cfg(unix)]
fn project_with_an_unreadable_file() -> Option<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt;

    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("readable.rs"),
        "fn readable() {\n    let first = 1;\n    let second = 2;\n    let _ = first + second;\n}\n",
    )
    .unwrap();
    let locked = project.path().join("locked.rs");
    std::fs::write(&locked, "fn locked() {}\n").unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    std::fs::read(&locked).is_err().then_some(project)
}

#[cfg(unix)]
#[tokio::test]
async fn files_discovery_could_not_read_leave_the_scan_partial() {
    let Some(project) = project_with_an_unreadable_file() else {
        return;
    };
    let config = small_window_config();
    let inventory = Arc::new(ProjectInventory::build(project.path(), &config.engine).unwrap());
    let backend = ScriptedBackend::new(vec![
        read_response("r1", "readable.rs"),
        submit_response("s1", "readable.rs", "found"),
        end_turn_response(),
    ]);
    let engine: Arc<dyn crate::engine::Engine> =
        Arc::new(DefaultEngine::new(EngineConfig::default()));
    let counter = Arc::new(FindingCounter::new());
    let cancel = CancelToken::default();

    let analysis = run_sharded_analysis(ShardedAnalysisRequest {
        backend: &backend,
        engine: Arc::clone(&engine),
        inventory: Arc::clone(&inventory),
        config: &config,
        counter: Arc::clone(&counter),
        system_prompt: "SYS",
        reporter: &Reporter::new(crate::tui::shared_state()),
        review: None,
        cancel: &cancel,
    })
    .await
    .expect("an unreadable file must not abort the run");

    assert_eq!(analysis.status.files_presented, 1);
    assert_eq!(analysis.status.files_inspected, 1);
    assert!(analysis.status.uninspected_files.is_empty());
    assert_eq!(analysis.status.skipped_files.len(), 1);
    assert!(
        analysis.status.skipped_files[0].starts_with("locked.rs ("),
        "the unreadable file must be named with its cause: {:?}",
        analysis.status.skipped_files
    );
    assert_eq!(analysis.status.completeness, ScanCompleteness::Partial);
}

const DEDUPE_SPANS: [Option<(u32, u32)>; 6] = [
    None,
    Some((10, 20)),
    Some((15, 25)),
    Some((20, 30)),
    Some((31, 40)),
    Some((1, 100)),
];
const DEDUPE_SCALE_FINDINGS: usize = 50_000;
const MAX_SPAN_COMPARISONS_PER_FINDING: usize = 2;

fn pairwise_dedupe(findings: Vec<Finding>) -> Vec<Finding> {
    let mut kept: Vec<Finding> = Vec::new();
    for finding in findings {
        if kept
            .iter()
            .any(|existing| pairwise_duplicate(existing, &finding))
        {
            continue;
        }
        kept.push(finding);
    }
    kept
}

fn pairwise_duplicate(a: &Finding, b: &Finding) -> bool {
    let same_identity = match (&a.rule, &b.rule) {
        (Some(rule_a), Some(rule_b)) => rule_a == rule_b,
        _ => a.title == b.title,
    };
    let ranges_overlap = match (a.line_start, a.line_end, b.line_start, b.line_end) {
        (Some(a_start), Some(a_end), Some(b_start), Some(b_end)) => {
            a_start <= b_end && b_start <= a_end
        }
        _ => false,
    };
    a.file == b.file && same_identity && ranges_overlap
}

fn every_identity_and_span_combination(counter: &FindingCounter) -> Vec<Finding> {
    let mut findings = Vec::new();
    for _ in 0..2 {
        for file in ["src/a.rs", "src/b.rs"] {
            for title in ["leak", "race"] {
                for rule in [None, Some("bug.one"), Some("bug.two")] {
                    for span in DEDUPE_SPANS {
                        let mut candidate = finding(counter, title, file);
                        if let Some(rule) = rule {
                            candidate = candidate.with_rule(rule.into());
                        }
                        if let Some((start, end)) = span {
                            candidate = candidate.with_lines(start, end);
                        }
                        findings.push(candidate);
                    }
                }
            }
        }
    }
    findings
}

#[test]
fn dedupe_agrees_with_the_pairwise_definition_on_every_combination() {
    let counter = Arc::new(FindingCounter::new());
    let findings = every_identity_and_span_combination(&counter);
    let submitted = findings.len();

    let expected: Vec<String> = pairwise_dedupe(findings.clone())
        .into_iter()
        .map(|finding| finding.id)
        .collect();
    let deduped: Vec<String> = dedupe_findings(findings)
        .into_iter()
        .map(|finding| finding.id)
        .collect();

    assert_eq!(deduped, expected);
    assert!(
        expected.len() < submitted,
        "the corpus must contain duplicates to be worth comparing"
    );
}

#[test]
fn dedupe_of_one_identity_does_not_compare_findings_pairwise() {
    let counter = Arc::new(FindingCounter::new());
    let findings: Vec<Finding> = (0..DEDUPE_SCALE_FINDINGS)
        .map(|index| {
            let line = index as u32 * 2 + 1;
            finding(&counter, "leak", "src/a.rs").with_lines(line, line)
        })
        .collect();

    SPAN_COMPARISONS.with(|comparisons| comparisons.set(0));
    let deduped = dedupe_findings(findings);
    let comparisons = SPAN_COMPARISONS.with(std::cell::Cell::get);

    assert_eq!(deduped.len(), DEDUPE_SCALE_FINDINGS);
    let ceiling = DEDUPE_SCALE_FINDINGS * MAX_SPAN_COMPARISONS_PER_FINDING;
    assert!(
        comparisons >= DEDUPE_SCALE_FINDINGS - 1,
        "only {comparisons} span comparisons ran for {DEDUPE_SCALE_FINDINGS} findings; the index \
         was bypassed, so this test proves nothing"
    );
    assert!(
        comparisons <= ceiling,
        "deduping {DEDUPE_SCALE_FINDINGS} findings of one identity ran {comparisons} span \
         comparisons against a ceiling of {ceiling}; the cross-shard dedupe is comparing \
         findings pairwise again"
    );
}

#[test]
fn dedupe_treats_touching_spans_of_one_identity_as_one_region() {
    let counter = Arc::new(FindingCounter::new());
    let first = finding(&counter, "leak", "src/a.rs").with_lines(10, 20);
    let second = finding(&counter, "leak", "src/a.rs").with_lines(21, 30);
    let spanning = finding(&counter, "leak", "src/a.rs").with_lines(20, 21);

    let deduped = dedupe_findings(vec![first, second, spanning]);

    assert_eq!(deduped.len(), 2);
}

#[test]
fn dedupe_reads_a_reversed_span_as_the_range_it_denotes() {
    let counter = Arc::new(FindingCounter::new());
    let reversed = finding(&counter, "leak", "src/a.rs").with_lines(20, 10);
    let inside = finding(&counter, "leak", "src/a.rs").with_lines(15, 15);
    let outside = finding(&counter, "leak", "src/a.rs").with_lines(30, 40);

    let deduped = dedupe_findings(vec![reversed, inside, outside]);

    assert_eq!(deduped.len(), 2);
    assert_eq!(deduped[1].line_start, Some(30));
}

fn tiny_source(name: &str) -> String {
    let body = "    let a = 1;\n    let b = 2;\n    let c = a + b;\n    let _ = c;\n";
    format!("fn {name}() {{\n{body}}}\n")
}

fn two_file_project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for name in ["first", "second"] {
        std::fs::write(dir.path().join(format!("{name}.rs")), tiny_source(name)).unwrap();
    }
    dir
}

fn single_turn_config() -> Config {
    Config {
        llm: LlmConfig {
            max_context_tokens: 1_000,
            max_agent_iterations: 1,
            ..LlmConfig::default()
        },
        ..Config::default()
    }
}

fn shards_holding(inventory: &ProjectInventory, path: &str, count: usize) -> Vec<Shard> {
    let entry = inventory
        .files()
        .iter()
        .find(|entry| entry.relative_path == path)
        .expect("the project must contain the sharded file")
        .clone();
    std::iter::repeat_n(entry, count)
        .map(|entry| Shard { files: vec![entry] })
        .collect()
}

#[tokio::test]
async fn shards_past_the_limit_are_reported_as_skipped_without_reaching_the_model() {
    let project = two_file_project();
    let config = single_turn_config();
    let inventory = Arc::new(ProjectInventory::build(project.path(), &config.engine).unwrap());
    let mut shards = shards_holding(&inventory, "first.rs", MAX_SHARDS);
    shards.extend(shards_holding(&inventory, "second.rs", 1));
    let backend = ResultBackend::new(
        std::iter::repeat_with(|| Ok(submit_response("s", "first.rs", "found")))
            .take(MAX_SHARDS)
            .collect(),
    );
    let engine: Arc<dyn crate::engine::Engine> =
        Arc::new(DefaultEngine::new(EngineConfig::default()));
    let counter = Arc::new(FindingCounter::new());
    let cancel = CancelToken::default();
    let tracker = Arc::new(CoverageTracker::new());
    let reporter = Reporter::new(crate::tui::shared_state());
    let executor = ShardExecutor::new(
        ShardedAnalysisRequest {
            backend: &backend,
            engine: Arc::clone(&engine),
            inventory: Arc::clone(&inventory),
            config: &config,
            counter: Arc::clone(&counter),
            system_prompt: "SYS",
            reporter: &reporter,
            review: None,
            cancel: &cancel,
        },
        Arc::clone(&tracker),
        config.llm.effective_context_tokens(),
        shards.len(),
    );

    let outcome = executor
        .run_shards(shards)
        .await
        .expect("the shards within the limit must still produce a report");

    assert_eq!(
        backend.call_count(),
        MAX_SHARDS,
        "no model call may be spent on a shard past the limit"
    );
    assert_eq!(
        outcome.skipped.entries(),
        ["second.rs (shard limit reached)".to_string()],
        "the dropped shard names the files it never analyzed"
    );
    assert_eq!(
        outcome.presented,
        BTreeSet::from(["first.rs".to_string()]),
        "a shard past the limit presents nothing"
    );
    assert_eq!(outcome.aggregate.len(), MAX_SHARDS);
    assert!(outcome.failed_shards.is_empty());
}

#[tokio::test]
async fn a_lost_repository_worker_is_reported_as_an_agent_protocol_failure() {
    let worker = tokio::spawn(std::future::pending::<()>());
    worker.abort();
    let join_error = worker
        .await
        .expect_err("an aborted worker must not report success");
    let join_message = join_error.to_string();

    match repository_worker_failure(join_error) {
        LlmError::AgentProtocol(message) => {
            assert!(
                message.starts_with("repository analysis worker failed: "),
                "the failing stage must be named: {message}"
            );
            assert!(
                message.ends_with(join_message.as_str()),
                "the worker failure must be carried into the message: {message}"
            );
        }
        other => panic!("a lost worker must surface as an agent protocol error, not {other}"),
    }
}

#[tokio::test]
async fn a_repository_map_worker_failure_skips_every_file_in_the_shard() {
    let project = two_file_project();
    let config = single_turn_config();
    let inventory = Arc::new(ProjectInventory::build(project.path(), &config.engine).unwrap());
    let backend = ResultBackend::new(Vec::new());
    let engine: Arc<dyn crate::engine::Engine> =
        Arc::new(DefaultEngine::new(EngineConfig::default()));
    let counter = Arc::new(FindingCounter::new());
    let cancel = CancelToken::default();
    let tracker = Arc::new(CoverageTracker::new());
    let reporter = Reporter::new(crate::tui::shared_state());
    let executor = ShardExecutor::new(
        ShardedAnalysisRequest {
            backend: &backend,
            engine,
            inventory,
            config: &config,
            counter,
            system_prompt: "SYS",
            reporter: &reporter,
            review: None,
            cancel: &cancel,
        },
        tracker,
        config.llm.effective_context_tokens(),
        1,
    );
    let mut outcome = ShardOutcome::default();

    executor
        .complete_shard(
            0,
            2,
            1,
            vec!["first.rs".to_string(), "second.rs".to_string()],
            Err(LlmError::AgentProtocol(
                "repository worker stopped".to_string(),
            )),
            &mut outcome,
        )
        .await
        .unwrap();

    assert_eq!(backend.call_count(), 0);
    assert_eq!(
        outcome.skipped.entries(),
        [
            "first.rs (repository map construction failed)".to_string(),
            "second.rs (repository map construction failed)".to_string(),
        ]
    );
    assert_eq!(outcome.failed_shards.len(), 1);
    assert!(
        outcome.failed_shards[0]
            .error
            .contains("repository worker stopped")
    );
    assert!(matches!(
        outcome.last_error,
        Some(LlmError::AgentProtocol(_))
    ));
}

#[test]
fn a_selection_matching_no_file_cannot_be_sharded() {
    let config = small_window_config();
    let project = two_file_project();
    let inventory = ProjectInventory::build(project.path(), &config.engine).unwrap();

    let error = discover_shards(&inventory, Some(&BTreeSet::new()), MIN_SHARD_BUDGET_TOKENS)
        .expect_err("a selection with no analyzable file cannot be sharded");

    match error {
        BugHunterError::RepoMap(RepoMapError::EmptyProject(path)) => assert_eq!(
            path,
            inventory.filesystem().root().as_path(),
            "the error must name the project root"
        ),
        other => panic!("an empty selection must report an empty project, not {other}"),
    }
    assert_eq!(
        discover_shards(&inventory, None, MIN_SHARD_BUDGET_TOKENS)
            .expect("the unfiltered project has files")
            .len(),
        1,
        "the same project shards fine without a selection"
    );
}

#[tokio::test]
async fn a_review_with_nothing_to_present_fails_before_the_model_is_called() {
    let project = two_file_project();
    let config = small_window_config();
    let inventory = Arc::new(ProjectInventory::build(project.path(), &config.engine).unwrap());
    let diff = BTreeMap::from([("gone.rs".to_string(), vec![(1, 1)])]);
    let review = ReviewSelection::from_diff(&diff, &inventory, &BTreeMap::new());
    let backend = ResultBackend::new(Vec::new());
    let engine: Arc<dyn crate::engine::Engine> =
        Arc::new(DefaultEngine::new(EngineConfig::default()));
    let counter = Arc::new(FindingCounter::new());
    let cancel = CancelToken::default();

    let result = run_sharded_analysis(ShardedAnalysisRequest {
        backend: &backend,
        engine: Arc::clone(&engine),
        inventory: Arc::clone(&inventory),
        config: &config,
        counter: Arc::clone(&counter),
        system_prompt: "SYS",
        reporter: &Reporter::new(crate::tui::shared_state()),
        review: Some(&review),
        cancel: &cancel,
    })
    .await;

    assert!(
        review.presented_files().is_empty(),
        "the changed file is absent from the project"
    );
    assert!(
        matches!(
            result,
            Err(BugHunterError::RepoMap(RepoMapError::EmptyProject(_)))
        ),
        "a review with no presentable file must fail loudly"
    );
    assert_eq!(
        backend.call_count(),
        0,
        "an empty review must not reach the model"
    );
}
