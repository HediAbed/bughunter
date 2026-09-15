use super::*;
use crate::config::schema::Severity;
use crate::report::ScanCompleteness;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;
use tracing_subscriber::layer::SubscriberExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn minimal_config(mode: AnalysisMode) -> ValidatedConfig {
    ValidatedConfig::new(Config::default(), mode).unwrap()
}

fn assert_merged_duplicate(findings: &[Finding]) {
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].file, Path::new("checkout.ts"));
    assert_eq!(findings[0].description, "Hardcoded credential");
    assert_eq!(
        findings[0].suggestion.as_deref(),
        Some("Read the key from the environment")
    );
    assert_eq!(findings[0].source, crate::report::FindingSource::Static);
}

#[test]
fn static_analysis_on_clean_project_returns_no_findings() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("clean.rs"), "fn main() {\n    42\n}\n").unwrap();

    let result = run_static_analysis(dir.path(), &minimal_config(AnalysisMode::Static)).unwrap();

    assert!(result.findings.is_empty());
    assert!(!result.has_findings_above_threshold);
    assert_eq!(result.scan.completeness, ScanCompleteness::Complete);
    assert!(!result.scan.is_partial());
    assert_eq!(result.scan.files_presented, 1, "the clean file was scanned");
    assert_eq!(result.scan.files_inspected, 1);
}

#[test]
fn static_analysis_detects_todo() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("work.rs"),
        "// TODO: fix this\nfn main() {}\n",
    )
    .unwrap();

    let result = run_static_analysis(dir.path(), &minimal_config(AnalysisMode::Static)).unwrap();

    assert!(!result.findings.is_empty());
    assert!(result.findings.iter().any(|f| f.title.contains("TODO")));
}

#[test]
fn static_analysis_outputs_valid_json() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("app.rs"), "fn main() {}\n").unwrap();

    let result = run_static_analysis(dir.path(), &minimal_config(AnalysisMode::Static)).unwrap();

    let parsed: serde_json::Value = serde_json::from_str(&result.output).unwrap();
    assert_eq!(parsed["version"], version::VERSION);
    assert_eq!(parsed["mode"], "static");
}

#[test]
fn detects_hardcoded_secret_and_flags_above_threshold() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("config.py"),
        "password = \"SuperSecret123!\"\n",
    )
    .unwrap();

    let result = run_static_analysis(dir.path(), &minimal_config(AnalysisMode::Static)).unwrap();

    assert!(
        result
            .findings
            .iter()
            .any(|f| f.severity == crate::config::schema::Severity::Critical)
    );
    assert!(result.has_findings_above_threshold);
}

#[test]
fn min_confidence_filters_out_lower_confidence_findings() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("config.py"),
        "password = \"SuperSecret123!\"\n",
    )
    .unwrap();

    let mut raw_config = Config::default();
    raw_config.general.min_confidence = crate::config::schema::Confidence::High;
    let config = ValidatedConfig::new(raw_config, AnalysisMode::Static).unwrap();

    let result = run_static_analysis(dir.path(), &config).unwrap();

    assert!(
        result
            .findings
            .iter()
            .all(|f| f.rule.as_deref() != Some("vulnerability.hardcoded-secret"))
    );
    assert!(!result.has_findings_above_threshold);
}

#[test]
fn markdown_output_format() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("app.rs"), "// TODO: fix\nfn main() {}\n").unwrap();

    let mut raw_config = Config::default();
    raw_config.general.output_format = OutputFormat::Md;
    let config = ValidatedConfig::new(raw_config, AnalysisMode::Static).unwrap();

    let result = run_static_analysis(dir.path(), &config).unwrap();

    assert!(result.output.contains("# BugHunter Analysis Report"));
    assert!(result.output.contains("TODO"));
}

#[test]
fn result_merges_static_and_ai_duplicates_at_the_same_location() {
    use crate::config::schema::{AnalysisCategory, Confidence, Severity};
    use crate::report::FindingSource;

    let project = TempDir::new().unwrap();
    let file = project.path().join("checkout.ts");
    fs::write(&file, "const apiKey = \"secret\";\n").unwrap();
    let counter = FindingCounter::new();
    let deterministic = Finding::new_static(
        &counter,
        AnalysisCategory::Vulnerability,
        Severity::Critical,
        "Possible hardcoded API key detected".into(),
        "Hardcoded credential".into(),
        file,
    )
    .with_lines(1, 1)
    .with_rule("vulnerability.hardcoded-secret".into());
    let mut ai = Finding::new_static(
        &counter,
        AnalysisCategory::Vulnerability,
        Severity::High,
        "Hardcoded API Key".into(),
        "AI duplicate".into(),
        "checkout.ts".into(),
    )
    .with_lines(1, 1)
    .with_snippet("const apiKey = \"secret\";".into())
    .with_suggestion("Read the key from the environment".into())
    .with_rule("Hardcoded Secret".into())
    .with_confidence(Confidence::High);
    ai.source = FindingSource::Ai;
    let reversed = build_result(
        vec![ai.clone(), deterministic.clone()],
        project.path(),
        &minimal_config(AnalysisMode::Static),
        "full",
        ScanStatus::complete(1),
    )
    .unwrap();
    let result = build_result(
        vec![deterministic, ai],
        project.path(),
        &minimal_config(AnalysisMode::Static),
        "full",
        ScanStatus::complete(1),
    )
    .unwrap();

    assert_merged_duplicate(&result.findings);
    assert_merged_duplicate(&reversed.findings);
}

#[test]
fn cross_pipeline_findings_with_different_rules_are_not_duplicates() {
    use crate::config::schema::{AnalysisCategory, Severity};
    use crate::report::FindingSource;

    let counter = FindingCounter::new();
    let deterministic = Finding::new_static(
        &counter,
        AnalysisCategory::Vulnerability,
        Severity::High,
        "Hardcoded secret".into(),
        "deterministic".into(),
        "checkout.ts".into(),
    )
    .with_lines(1, 1)
    .with_rule("vulnerability.hardcoded-secret".into());
    let mut ai = Finding::new_static(
        &counter,
        AnalysisCategory::Vulnerability,
        Severity::High,
        "SQL injection".into(),
        "ai".into(),
        "checkout.ts".into(),
    )
    .with_lines(1, 1)
    .with_rule("sql-injection".into());
    ai.source = FindingSource::Ai;

    assert!(!is_cross_pipeline_duplicate(&deterministic, &ai));
}

#[test]
fn result_keeps_only_enabled_analysis_categories() {
    use crate::config::schema::{AnalysisCategory, Severity};

    let project = TempDir::new().unwrap();
    fs::write(project.path().join("app.rs"), "fn main() {}\n").unwrap();
    let counter = FindingCounter::new();
    let bug = Finding::new_static(
        &counter,
        AnalysisCategory::Bug,
        Severity::Low,
        "bug".into(),
        "bug".into(),
        "app.rs".into(),
    );
    let vulnerability = Finding::new_static(
        &counter,
        AnalysisCategory::Vulnerability,
        Severity::Critical,
        "vulnerability".into(),
        "vulnerability".into(),
        "app.rs".into(),
    );
    let mut config = Config::default();
    config.analysis.categories = vec![AnalysisCategory::Bug];

    let result = build_result(
        vec![vulnerability, bug],
        project.path(),
        &config,
        "ai-only",
        ScanStatus::complete(1),
    )
    .unwrap();

    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].category, AnalysisCategory::Bug);
    assert!(!result.has_findings_above_threshold);
}

#[test]
fn result_order_and_ids_do_not_depend_on_submission_order() {
    use crate::config::schema::{AnalysisCategory, Severity};

    let project = TempDir::new().unwrap();
    let counter = FindingCounter::with_start(80);
    let low_bug = Finding::new_static(
        &counter,
        AnalysisCategory::Bug,
        Severity::Low,
        "low bug".into(),
        "low bug".into(),
        "b.rs".into(),
    );
    let critical_vulnerability = Finding::new_static(
        &counter,
        AnalysisCategory::Vulnerability,
        Severity::Critical,
        "critical vulnerability".into(),
        "critical vulnerability".into(),
        "z.rs".into(),
    );
    let critical_bug = Finding::new_static(
        &counter,
        AnalysisCategory::Bug,
        Severity::Critical,
        "critical bug".into(),
        "critical bug".into(),
        "a.rs".into(),
    );
    let config = Config::default();
    let findings = vec![low_bug, critical_vulnerability, critical_bug];

    let first = build_result(
        findings.clone(),
        project.path(),
        &config,
        "full",
        ScanStatus::complete(0),
    )
    .unwrap();
    let second = build_result(
        findings.into_iter().rev().collect(),
        project.path(),
        &config,
        "full",
        ScanStatus::complete(0),
    )
    .unwrap();
    let report_identity = |result: &AnalysisResult| {
        result
            .findings
            .iter()
            .map(|finding| (finding.id.clone(), finding.title.clone()))
            .collect::<Vec<_>>()
    };

    assert_eq!(report_identity(&first), report_identity(&second));
    assert_eq!(
        report_identity(&first),
        vec![
            ("BUG-001".into(), "critical bug".into()),
            ("VULN-002".into(), "critical vulnerability".into()),
            ("BUG-003".into(), "low bug".into()),
        ]
    );
}
#[test]
fn static_report_carries_the_scan_object() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("a.rs"), "fn main() {}\n").unwrap();
    fs::write(dir.path().join("b.rs"), "fn other() {}\n").unwrap();

    let result = run_static_analysis(dir.path(), &minimal_config(AnalysisMode::Static)).unwrap();

    let parsed: serde_json::Value = serde_json::from_str(&result.output).unwrap();
    assert_eq!(parsed["scan"]["completeness"], "complete");
    assert_eq!(parsed["scan"]["files_presented"], 2);
    assert_eq!(parsed["scan"]["files_inspected"], 2);
    assert_eq!(parsed["scan"]["shards_total"], 0);
    assert!(
        parsed["scan"]["failed_shards"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn markdown_report_neutralizes_untrusted_structure_and_terminal_controls() {
    let counter = FindingCounter::new();
    let finding = Finding::new_static(
        &counter,
        crate::config::schema::AnalysisCategory::Bug,
        crate::config::schema::Severity::High,
        "title\n## injected <script>".into(),
        "<script>\n# injected\n[click](javascript:bad)\u{1b}".into(),
        "bad\n#file.rs".into(),
    )
    .with_suggestion("---\nraw".into());
    let scan = ScanStatus {
        failed_shards: vec![crate::report::FailedShard {
            shard: 1,
            error: "<img>\n## forged".into(),
        }],
        ..ScanStatus::complete(1)
    };

    let markdown = render_markdown_summary(&[finding], &scan).unwrap();

    assert!(!markdown.contains("<script>"));
    assert!(!markdown.contains("<img>"));
    assert!(!markdown.contains("\n# injected"));
    assert!(!markdown.contains("[click]("));
    assert!(!markdown.contains('\u{1b}'));
    assert!(markdown.contains("&lt;script&gt;"));
    assert!(markdown.contains("\\# injected"));
    assert!(markdown.contains("\\[click\\]\\(javascript:bad\\)"));
    assert!(markdown.contains("\\u{1b}"));
}

#[test]
fn markdown_report_preserves_finding_provenance_and_evidence() {
    use crate::config::schema::{AnalysisCategory, Confidence, Severity};
    use crate::report::FindingSource;

    assert_eq!(Confidence::Low.to_string(), "low");
    assert_eq!(Confidence::Medium.to_string(), "medium");
    assert_eq!(Confidence::High.to_string(), "high");
    assert_eq!(FindingSource::Static.to_string(), "static");
    assert_eq!(FindingSource::Ai.to_string(), "ai");

    let counter = FindingCounter::new();
    let mut finding = Finding::new_static(
        &counter,
        AnalysisCategory::Vulnerability,
        Severity::Critical,
        "credential exposure".into(),
        "a credential reaches output".into(),
        "src/secret.rs".into(),
    )
    .with_lines(4, 6)
    .with_snippet("let token = \"value\";\n```\n# forged".into())
    .with_suggestion("keep the value out of output".into())
    .with_rule("vulnerability.credential-exposure".into())
    .with_confidence(Confidence::Medium);
    finding.source = FindingSource::Ai;

    let markdown = render_markdown_summary(&[finding], &ScanStatus::complete(1)).unwrap();

    for expected in [
        "**ID:** VULN\\-001",
        "**Category:** vulnerability",
        "**Confidence:** medium",
        "**Source:** ai",
        "**File:** src/secret\\.rs",
        "**Lines:** 4-6",
        "**Rule:** vulnerability\\.credential\\-exposure",
        "**Code:**",
        "let token = \"value\";",
        "```\n# forged",
        "**Suggestion:** keep the value out of output",
    ] {
        assert!(
            markdown.contains(expected),
            "missing {expected:?}:\n{markdown}"
        );
    }
}

#[test]
fn markdown_code_fences_outgrow_untrusted_delimiter_runs() {
    assert_eq!(markdown_code_fence("~~~~"), "```");
    assert_eq!(markdown_code_fence("```"), "~~~");

    let counter = FindingCounter::new();
    let finding = Finding::new_static(
        &counter,
        crate::config::schema::AnalysisCategory::Bug,
        crate::config::schema::Severity::High,
        "evidence".into(),
        "description".into(),
        "src/lib.rs".into(),
    )
    .with_snippet("#[derive(Debug)]\nlet raw = `value`;\n~~~~\n\u{1b}[2J\n".into());

    let markdown = render_markdown_summary(&[finding], &ScanStatus::complete(1)).unwrap();

    assert!(markdown.contains("```\n#[derive(Debug)]\nlet raw = `value`;\n~~~~\n\\u{1b}[2J\n```"));
    assert!(!markdown.contains('\u{1b}'));
}

#[test]
fn markdown_report_ends_with_a_coverage_section() {
    let scan = ScanStatus {
        completeness: ScanCompleteness::Partial,
        shards_total: 4,
        shards_completed: 3,
        failed_shards: vec![crate::report::FailedShard {
            shard: 2,
            error: "engine overloaded".into(),
        }],
        files_presented: 12,
        files_inspected: 7,
        uninspected_files: vec!["src/untouched.rs".into()],
        skipped_files: vec!["src/capped.rs".into()],
        omitted_diagnostics: 9,
    };

    let markdown = render_markdown_summary(&[], &scan).unwrap();

    assert!(markdown.contains("## Coverage"));
    assert!(markdown.contains("**Completeness:** partial"));
    assert!(markdown.contains("**Shards:** 3/4"));
    assert!(markdown.contains("**Files inspected:** 7/12"));
    assert!(markdown.contains("- shard 2: engine overloaded"));
    assert!(markdown.contains("**Files never presented:** 1"));
    assert!(markdown.contains("- src/capped\\.rs"));
    assert!(markdown.contains("**Files presented but not inspected:** 1"));
    assert!(markdown.contains("- src/untouched\\.rs"));
    assert!(markdown.contains("**Coverage entries omitted:** 9"));
}

#[test]
fn markdown_coverage_section_omits_failures_for_a_complete_scan() {
    let markdown = render_markdown_summary(&[], &ScanStatus::complete(5)).unwrap();

    assert!(markdown.contains("## Coverage"));
    assert!(markdown.contains("**Completeness:** complete"));
    assert!(markdown.contains("**Files inspected:** 5/5"));
    assert!(
        !markdown.contains("**Shards:**"),
        "a static scan has no shards to report"
    );
    assert!(!markdown.contains("Failed shards"));
    assert!(!markdown.contains("never presented"));
    assert!(!markdown.contains("presented but not inspected"));
    assert!(!markdown.contains("omitted"));
}

fn bounded_sample_finding(title: &str, description: &str) -> Finding {
    Finding::new_static(
        &FindingCounter::new(),
        crate::config::schema::AnalysisCategory::Bug,
        Severity::High,
        title.to_string(),
        description.to_string(),
        "src/a.rs".into(),
    )
}

#[test]
fn a_markdown_report_that_exactly_fits_the_byte_ceiling_is_rendered() {
    let findings = [bounded_sample_finding("bounded", "described")];
    let scan = ScanStatus::complete(1);
    let exact = render_markdown_summary(&findings, &scan).unwrap().len();

    let rendered = render_markdown_summary_within(&findings, &scan, exact).unwrap();

    assert_eq!(rendered.len(), exact);
}

#[test]
fn a_markdown_report_one_byte_over_the_ceiling_is_rejected_as_too_large() {
    let findings = [bounded_sample_finding("bounded", "described")];
    let scan = ScanStatus::complete(1);
    let limit = render_markdown_summary(&findings, &scan).unwrap().len() - 1;

    let error = render_markdown_summary_within(&findings, &scan, limit).unwrap_err();

    assert!(matches!(
        error,
        ReportError::TooLarge {
            resource: MARKDOWN_REPORT,
            limit_bytes,
        } if limit_bytes == limit
    ));
}

#[test]
fn every_markdown_prefix_obeys_the_same_hard_byte_ceiling() {
    let finding = bounded_sample_finding("bounded", "described")
        .with_lines(3, 5)
        .with_suggestion("replace it".into());
    let findings = [finding];
    let scan = ScanStatus {
        completeness: ScanCompleteness::Partial,
        shards_total: 2,
        shards_completed: 1,
        failed_shards: vec![crate::report::FailedShard {
            shard: 2,
            error: "failed".into(),
        }],
        files_presented: 3,
        files_inspected: 1,
        uninspected_files: vec!["src/uninspected.rs".into()],
        skipped_files: vec!["src/skipped.rs".into()],
        omitted_diagnostics: 1,
    };
    let exact = render_markdown_summary(&findings, &scan).unwrap().len();

    for limit in 0..exact {
        let error = render_markdown_summary_within(&findings, &scan, limit).unwrap_err();
        assert!(matches!(
            error,
            ReportError::TooLarge {
                resource: MARKDOWN_REPORT,
                limit_bytes,
            } if limit_bytes == limit
        ));
    }

    assert_eq!(
        render_markdown_summary_within(&findings, &scan, exact)
            .unwrap()
            .len(),
        exact
    );
}

struct CancelOnLogMessage {
    needle: &'static str,
    cancel: crate::cancel::CancelToken,
}

impl<S> tracing_subscriber::Layer<S> for CancelOnLogMessage
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut message = LoggedMessage::default();
        event.record(&mut message);
        if message.0.contains(self.needle) {
            self.cancel.cancel();
        }
    }
}

#[derive(Default)]
struct LoggedMessage(String);

impl tracing::field::Visit for LoggedMessage {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0.push_str(value);
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

#[test]
fn repository_map_omissions_emit_the_presented_and_omitted_counts() {
    let state = crate::tui::shared_state();
    let subscriber =
        tracing_subscriber::registry().with(crate::tui::TuiLogLayer::new(state.clone()));
    let repo_map = RepoMap {
        text: String::new(),
        files: vec!["src/presented.rs".into()],
        estimated_tokens: 0,
        omitted_files: 2,
        omitted_file_reports: Vec::new(),
        omitted_file_diagnostics: 0,
    };

    tracing::subscriber::with_default(subscriber, || report_repo_map_omissions(&repo_map));

    let logs: Vec<String> = state
        .lock()
        .logs
        .iter()
        .map(|line| line.text.clone())
        .collect();
    assert!(
        logs.iter().any(|line| {
            line.contains("the repo map byte budget dropped files")
                && line.contains("omitted=2")
                && line.contains("presented=1")
        }),
        "{logs:?}"
    );
}

#[test]
fn markdown_escapes_count_against_the_byte_ceiling() {
    let plain = [bounded_sample_finding("abcd", "described")];
    let escaped = [bounded_sample_finding("[[[[", "described")];
    let scan = ScanStatus::complete(1);
    let plain_bytes = render_markdown_summary(&plain, &scan).unwrap().len();

    let error = render_markdown_summary_within(&escaped, &scan, plain_bytes).unwrap_err();

    assert!(matches!(error, ReportError::TooLarge { .. }));
    assert_eq!(
        render_markdown_summary(&escaped, &scan).unwrap().len(),
        plain_bytes + 4,
        "each escaped bracket must cost its escape byte"
    );
}

#[test]
fn an_oversize_markdown_report_is_rejected_instead_of_returned_truncated() {
    let findings: Vec<Finding> = (0..32)
        .map(|index| bounded_sample_finding(&format!("finding {index}"), &"detail ".repeat(256)))
        .collect();

    let error =
        render_markdown_summary_within(&findings, &ScanStatus::complete(1), 2 * 1024).unwrap_err();

    assert_eq!(
        error.to_string(),
        "the Markdown report exceeds the 2048 byte limit"
    );
}

#[test]
fn a_markdown_coverage_section_reports_omitted_diagnostics_for_a_static_scan() {
    let scan = ScanStatus::static_scan(1, vec!["src/a.rs (unreadable)".into()], 5);

    let markdown = render_markdown_summary(&[], &scan).unwrap();

    assert!(markdown.contains("**Files never presented:** 1"));
    assert!(markdown.contains("- src/a\\.rs \\(unreadable\\)"));
    assert!(markdown.contains("**Coverage entries omitted:** 5"));
}

#[cfg(unix)]
#[test]
fn a_changed_file_discovery_could_not_read_is_skipped_with_its_real_cause() {
    use std::os::unix::fs::PermissionsExt;

    let project = TempDir::new().unwrap();
    let locked = project.path().join("locked.rs");
    fs::write(&locked, "fn locked() {}\n").unwrap();
    fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read(&locked).is_ok() {
        return;
    }
    let config = Config::default();
    let inventory = ProjectInventory::build(project.path(), &config.engine).unwrap();
    let mut scope = crate::review::ReviewScope::new(
        18,
        "main".into(),
        None,
        std::collections::BTreeMap::from([("locked.rs".to_string(), vec![(1, 1)])]),
        String::new(),
    )
    .unwrap();
    scope
        .set_changed_file_coverage(crate::review::ChangedFileCoverage {
            inspectable: std::collections::BTreeSet::new(),
            skipped: vec![crate::review::SkippedChangedFile {
                path: "locked.rs".to_string(),
                reason: crate::review::ChangedFileSkipReason::ExcludedByEngineFilters,
            }],
        })
        .unwrap();

    let selection = review_selection(Some(&scope), &inventory).expect("a review scope selects");

    assert!(selection.presented_files().is_empty());
    assert_eq!(selection.skipped_files().len(), 1);
    assert!(
        selection.skipped_files()[0].starts_with("locked.rs (Permission"),
        "the real read failure must outrank the coarse filter reason: {:?}",
        selection.skipped_files()
    );
}

#[test]
fn claude_status_counts_inspected_map_files() {
    let repo_map = RepoMap {
        text: String::new(),
        files: vec!["src/a.rs".into(), "src/b.rs".into(), "src/c.rs".into()],
        estimated_tokens: 10,
        omitted_files: 0,
        omitted_file_reports: Vec::new(),
        omitted_file_diagnostics: 0,
    };
    let analysis = claude_cli::McpAnalysis {
        findings: Vec::new(),
        inspected_files: ["src/a.rs".to_string(), "outside/z.rs".to_string()]
            .into_iter()
            .collect(),
        tool_calls: 4,
    };

    let scan = claude_scan_status(&analysis, &repo_map, Vec::new());

    assert_eq!(scan.shards_total, 1);
    assert_eq!(scan.shards_completed, 1);
    assert_eq!(scan.files_presented, 3);
    assert_eq!(
        scan.files_inspected, 1,
        "reads outside the map do not count"
    );
    assert_eq!(
        scan.uninspected_files,
        vec![
            "src/b.rs (model did not inspect file)".to_string(),
            "src/c.rs (model did not inspect file)".to_string(),
        ]
    );
    assert_eq!(
        scan.completeness,
        ScanCompleteness::Partial,
        "files presented but never opened leave the scan incomplete"
    );
}

#[test]
fn claude_status_is_complete_only_when_every_presented_file_was_opened() {
    let repo_map = RepoMap {
        text: String::new(),
        files: vec!["src/a.rs".into()],
        estimated_tokens: 10,
        omitted_files: 0,
        omitted_file_reports: Vec::new(),
        omitted_file_diagnostics: 0,
    };
    let analysis = claude_cli::McpAnalysis {
        findings: Vec::new(),
        inspected_files: ["src/a.rs".to_string()].into_iter().collect(),
        tool_calls: 3,
    };

    let scan = claude_scan_status(&analysis, &repo_map, Vec::new());

    assert_eq!(scan.completeness, ScanCompleteness::Complete);
    assert_eq!(scan.shards_completed, 1);
    assert_eq!(scan.files_inspected, 1);
}

#[test]
fn claude_status_accounts_for_files_the_repo_map_budget_dropped() {
    let repo_map = RepoMap {
        text: String::new(),
        files: vec!["src/a.rs".into()],
        estimated_tokens: 10,
        omitted_files: 4,
        omitted_file_reports: vec![
            "src/b.rs (repo map byte budget exhausted)".to_string(),
            "src/c.rs (repo map byte budget exhausted)".to_string(),
        ],
        omitted_file_diagnostics: 2,
    };
    let analysis = claude_cli::McpAnalysis {
        findings: Vec::new(),
        inspected_files: ["src/a.rs".to_string()].into_iter().collect(),
        tool_calls: 3,
    };

    let scan = claude_scan_status(&analysis, &repo_map, Vec::new());

    assert_eq!(
        scan.completeness,
        ScanCompleteness::Partial,
        "files dropped by the byte budget were never presented for analysis"
    );
    assert_eq!(scan.files_presented, 1);
    assert_eq!(scan.files_inspected, 1);
    assert!(scan.uninspected_files.is_empty());
    assert_eq!(
        scan.skipped_files,
        vec![
            "src/b.rs (repo map byte budget exhausted)".to_string(),
            "src/c.rs (repo map byte budget exhausted)".to_string(),
        ]
    );
    assert_eq!(scan.omitted_diagnostics, 2);
}

#[test]
fn claude_status_counts_repo_map_omissions_read_through_tools() {
    let repo_map = RepoMap {
        text: String::new(),
        files: vec!["src/a.rs".into()],
        estimated_tokens: 10,
        omitted_files: 2,
        omitted_file_reports: vec![
            "src/b.rs (repo map byte budget exhausted)".to_string(),
            "src/c.rs (repo map byte budget exhausted)".to_string(),
        ],
        omitted_file_diagnostics: 0,
    };
    let analysis = claude_cli::McpAnalysis {
        findings: Vec::new(),
        inspected_files: ["src/a.rs".to_string(), "src/b.rs".to_string()]
            .into_iter()
            .collect(),
        tool_calls: 3,
    };

    let scan = claude_scan_status(&analysis, &repo_map, Vec::new());

    assert_eq!(scan.files_presented, 2);
    assert_eq!(scan.files_inspected, 2);
    assert_eq!(
        scan.skipped_files,
        vec!["src/c.rs (repo map byte budget exhausted)".to_string()]
    );
    assert_eq!(scan.completeness, ScanCompleteness::Partial);
}

#[test]
fn claude_status_from_project_stats_alone_is_partial() {
    let repo_map = RepoMap {
        text: String::new(),
        files: vec!["src/a.rs".into()],
        estimated_tokens: 10,
        omitted_files: 0,
        omitted_file_reports: Vec::new(),
        omitted_file_diagnostics: 0,
    };
    let analysis = claude_cli::McpAnalysis {
        findings: Vec::new(),
        inspected_files: std::collections::BTreeSet::new(),
        tool_calls: 4,
    };

    let scan = claude_scan_status(&analysis, &repo_map, Vec::new());

    assert_eq!(
        scan.completeness,
        ScanCompleteness::Partial,
        "tool activity without source inspection is not coverage"
    );
    assert_eq!(scan.shards_completed, 0);
    assert_eq!(scan.files_inspected, 0);
}

#[test]
fn claude_status_reports_changed_files_the_review_could_not_analyze() {
    let repo_map = RepoMap {
        text: String::new(),
        files: vec!["src/a.rs".into()],
        estimated_tokens: 10,
        omitted_files: 0,
        omitted_file_reports: Vec::new(),
        omitted_file_diagnostics: 0,
    };
    let analysis = claude_cli::McpAnalysis {
        findings: Vec::new(),
        inspected_files: ["src/a.rs".to_string()].into_iter().collect(),
        tool_calls: 2,
    };

    let scan = claude_scan_status(
        &analysis,
        &repo_map,
        vec!["deps.lock (excluded by engine filters)".to_string()],
    );

    assert_eq!(scan.completeness, ScanCompleteness::Partial);
    assert_eq!(
        scan.skipped_files,
        vec!["deps.lock (excluded by engine filters)".to_string()]
    );
    assert!(scan.uninspected_files.is_empty());
}

#[tokio::test]
async fn already_cancelled_run_aborts_before_reaching_the_model() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("clean.rs"), "fn main() {\n    42\n}\n").unwrap();
    let cancel = crate::cancel::CancelToken::default();
    cancel.cancel();

    let state = crate::tui::shared_state();
    let result = run_analysis(
        dir.path(),
        Some(dir.path()),
        &minimal_config(AnalysisMode::Full),
        state.clone(),
        false,
        None,
        cancel,
    )
    .await;

    let Err(error) = result else {
        panic!("a cancelled run must not produce a report");
    };
    assert!(matches!(error, BugHunterError::Cancelled), "{error}");
    assert_eq!(
        crate::errors::exit_code_for_error(&error),
        crate::errors::EXIT_CANCELLED
    );
    let mut state = state.lock();
    assert_eq!(state.phase, crate::tui::Phase::Cancelled);
    assert!(state.progress() < 1.0);
}

#[tokio::test]
async fn a_run_on_a_missing_project_root_fails_and_marks_the_run_failed() {
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("missing-project");
    let state = crate::tui::shared_state();

    let result = run_analysis(
        &missing,
        None,
        &minimal_config(AnalysisMode::AiOnly),
        state.clone(),
        false,
        None,
        crate::cancel::CancelToken::default(),
    )
    .await;

    let Err(error) = result else {
        panic!("a missing project root must fail the run");
    };
    assert!(
        matches!(
            error,
            BugHunterError::Engine(crate::errors::EngineError::Io { .. })
        ),
        "{error}"
    );
    assert_eq!(state.lock().phase, crate::tui::Phase::Failed);
}

#[tokio::test]
async fn panicked_blocking_analysis_worker_returns_a_typed_error() {
    let panic_on_run = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let worker = {
        let panic_on_run = Arc::clone(&panic_on_run);
        move || -> Result<(), BugHunterError> {
            if panic_on_run.load(std::sync::atomic::Ordering::Relaxed) {
                panic!("worker panic");
            }
            Ok(())
        }
    };
    let cancel = crate::cancel::CancelToken::default();
    run_blocking_analysis("prepare project", &cancel, worker.clone())
        .await
        .unwrap();
    panic_on_run.store(true, std::sync::atomic::Ordering::Relaxed);

    let error = run_blocking_analysis("prepare project", &cancel, worker)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        BugHunterError::Analysis(crate::errors::AnalysisError::WorkerFailed {
            action: "prepare project",
            ..
        })
    ));
}

#[tokio::test]
async fn cancellation_interrupts_a_cooperative_blocking_worker() {
    let cancel = crate::cancel::CancelToken::default();
    let worker_cancel = cancel.clone();
    let runner_cancel = cancel.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();

    let task = tokio::spawn(async move {
        run_blocking_analysis("cooperative work", &runner_cancel, move || {
            let _ = started_tx.send(());
            while !worker_cancel.is_cancelled() {
                std::thread::yield_now();
            }
            Err::<(), BugHunterError>(crate::errors::EngineError::Cancelled.into())
        })
        .await
    });
    started_rx.await.unwrap();
    cancel.cancel();

    let error = tokio::time::timeout(std::time::Duration::from_secs(1), task)
        .await
        .expect("cancellation must promptly release the async caller")
        .expect("worker task must not panic")
        .unwrap_err();
    assert!(matches!(error, BugHunterError::Cancelled));
}

#[test]
fn static_checks_on_a_cancelled_run_abort_with_a_cancellation_error() {
    let project = TempDir::new().unwrap();
    fs::write(project.path().join("source.rs"), "// TODO: static issue\n").unwrap();
    let config = minimal_config(AnalysisMode::Static);
    let context = prepare_context(project.path(), &config).unwrap();
    let cancel = crate::cancel::CancelToken::default();
    cancel.cancel();

    let error = run_static_checks_cancellable(
        &context.engine,
        &context.inventory,
        &config,
        &context.counter,
        &cancel,
    )
    .unwrap_err();

    assert!(matches!(
        error,
        BugHunterError::Engine(crate::errors::EngineError::Cancelled)
    ));
}

#[test]
fn initial_findings_on_a_cancelled_run_abort_before_scanning() {
    let project = TempDir::new().unwrap();
    fs::write(project.path().join("source.rs"), "// TODO: static issue\n").unwrap();
    let config = minimal_config(AnalysisMode::Full);
    let context = prepare_context(project.path(), &config).unwrap();
    let cancel = crate::cancel::CancelToken::default();
    cancel.cancel();

    let error =
        initial_findings_cancellable(&context, &config, AnalysisMode::Full, &cancel).unwrap_err();

    assert!(matches!(
        error,
        BugHunterError::Engine(crate::errors::EngineError::Cancelled)
    ));
}

#[test]
fn repository_map_rejects_an_empty_selected_file_set() {
    let project = TempDir::new().unwrap();
    fs::write(project.path().join("source.rs"), "fn source() {}\n").unwrap();
    let inventory = ProjectInventory::build(project.path(), &EngineConfig::default()).unwrap();
    let selected = std::collections::BTreeSet::new();

    let error = build_repo_map(
        &inventory,
        &EngineConfig::default(),
        10_000,
        Some(&selected),
        &crate::cancel::CancelToken::default(),
    )
    .unwrap_err();

    assert!(matches!(
        error,
        BugHunterError::RepoMap(crate::errors::RepoMapError::EmptyProject(_))
    ));
}

#[test]
fn a_repo_map_build_aborts_as_soon_as_cancellation_is_observed() {
    let project = TempDir::new().unwrap();
    fs::write(project.path().join("kept.rs"), "fn kept() {}\n").unwrap();
    let vanished = project.path().join("vanished.rs");
    fs::write(&vanished, "fn vanished() {}\n").unwrap();
    let inventory = ProjectInventory::build(project.path(), &EngineConfig::default()).unwrap();
    fs::remove_file(&vanished).unwrap();
    let cancel = crate::cancel::CancelToken::default();
    let subscriber = tracing_subscriber::registry().with(CancelOnLogMessage {
        needle: "failed to read file for repo map",
        cancel: cancel.clone(),
    });

    let result = tracing::subscriber::with_default(subscriber, || {
        build_repo_map(&inventory, &EngineConfig::default(), 10_000, None, &cancel)
    });

    assert!(matches!(
        result,
        Err(BugHunterError::Engine(
            crate::errors::EngineError::Cancelled
        ))
    ));
}

#[test]
fn ai_only_mode_starts_without_static_findings() {
    let project = TempDir::new().unwrap();
    fs::write(project.path().join("source.rs"), "// TODO: static issue\n").unwrap();
    let config = minimal_config(AnalysisMode::AiOnly);
    let context = prepare_context(project.path(), &config).unwrap();

    let findings = initial_findings(&context, &config, AnalysisMode::AiOnly).unwrap();

    assert!(findings.is_empty());
}

#[test]
fn finalization_orders_every_category_source_and_line_end() {
    let project = TempDir::new().unwrap();
    let counter = FindingCounter::new();
    let mut findings = Vec::new();
    for (category, title) in [
        (AnalysisCategory::Vulnerability, "vulnerability"),
        (AnalysisCategory::Solid, "solid"),
        (AnalysisCategory::Quality, "quality"),
        (AnalysisCategory::Bug, "bug"),
    ] {
        findings.push(
            Finding::new_static(
                &counter,
                category,
                Severity::Medium,
                title.into(),
                title.into(),
                PathBuf::from("source.rs"),
            )
            .with_lines(1, 3),
        );
    }
    let mut ai = Finding::new_static(
        &counter,
        AnalysisCategory::Bug,
        Severity::Low,
        "source-order".into(),
        "same".into(),
        PathBuf::from("source.rs"),
    )
    .with_lines(10, 12);
    ai.source = FindingSource::Ai;
    let static_finding = Finding::new_static(
        &counter,
        AnalysisCategory::Bug,
        Severity::Low,
        "source-order".into(),
        "same".into(),
        PathBuf::from("source.rs"),
    )
    .with_lines(10, 11);
    findings.extend([ai, static_finding]);

    let finalized = finalize_findings(
        findings,
        project.path(),
        Confidence::Low,
        &[
            AnalysisCategory::Bug,
            AnalysisCategory::Quality,
            AnalysisCategory::Solid,
            AnalysisCategory::Vulnerability,
        ],
    );

    let medium_categories: Vec<_> = finalized
        .iter()
        .filter(|finding| finding.severity == Severity::Medium)
        .map(|finding| finding.category)
        .collect();
    assert_eq!(
        medium_categories,
        vec![
            AnalysisCategory::Bug,
            AnalysisCategory::Quality,
            AnalysisCategory::Solid,
            AnalysisCategory::Vulnerability,
        ]
    );
    let source_order: Vec<_> = finalized
        .iter()
        .filter(|finding| finding.title == "source-order")
        .map(|finding| (finding.source, finding.line_end))
        .collect();
    assert_eq!(
        source_order,
        vec![
            (FindingSource::Static, Some(11)),
            (FindingSource::Ai, Some(12))
        ]
    );
}

#[test]
fn finding_order_uses_suggestion_as_its_final_tie_breaker() {
    let counter = FindingCounter::new();
    let mut left = Finding::new_static(
        &counter,
        AnalysisCategory::Bug,
        Severity::Medium,
        "same".into(),
        "same".into(),
        PathBuf::from("source.rs"),
    )
    .with_lines(3, 4)
    .with_snippet("same".into());
    left.rule = Some("same".into());
    left.suggestion = Some("a".into());
    let mut right = left.clone();
    right.suggestion = Some("b".into());

    assert_eq!(compare_findings(&left, &right), std::cmp::Ordering::Less);
}

#[test]
fn finalization_handles_a_project_removed_before_evidence_validation() {
    let directory = TempDir::new().unwrap();
    let missing_root = directory.path().join("removed");
    let counter = FindingCounter::new();
    let finding = Finding::new_static(
        &counter,
        AnalysisCategory::Bug,
        Severity::Medium,
        "finding".into(),
        "description".into(),
        PathBuf::from("source.rs"),
    );

    let finalized = finalize_findings(
        vec![finding],
        &missing_root,
        Confidence::Low,
        &[AnalysisCategory::Bug],
    );

    assert_eq!(finalized.len(), 1);
}

#[test]
fn findings_without_ranges_do_not_merge_across_pipelines() {
    let counter = FindingCounter::new();
    let static_finding = Finding::new_static(
        &counter,
        AnalysisCategory::Bug,
        Severity::High,
        "same".into(),
        "static".into(),
        PathBuf::from("source.rs"),
    )
    .with_rule("bug.same".into());
    let mut ai_finding = static_finding.clone();
    ai_finding.source = FindingSource::Ai;
    ai_finding.description = "ai".into();

    assert_eq!(
        finalize_findings(
            vec![static_finding, ai_finding],
            Path::new("."),
            Confidence::Low,
            &[AnalysisCategory::Bug],
        )
        .len(),
        2
    );
}

#[test]
fn a_merged_duplicate_never_overwrites_an_existing_snippet_or_suggestion() {
    let counter = FindingCounter::new();
    let kept = Finding::new_static(
        &counter,
        AnalysisCategory::Bug,
        Severity::High,
        "same".into(),
        "kept".into(),
        PathBuf::from("source.rs"),
    )
    .with_rule("bug.same".into())
    .with_lines(10, 20)
    .with_snippet("kept snippet".into())
    .with_suggestion("kept suggestion".into());
    let mut duplicate = kept
        .clone()
        .with_snippet("duplicate snippet".into())
        .with_suggestion("duplicate suggestion".into());
    duplicate.source = FindingSource::Ai;

    let merged = finalize_findings(
        vec![kept, duplicate],
        Path::new("."),
        Confidence::Low,
        &[AnalysisCategory::Bug],
    );

    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].code_snippet.as_deref(), Some("kept snippet"));
    assert_eq!(merged[0].suggestion.as_deref(), Some("kept suggestion"));
}

#[test]
fn a_static_duplicate_replaces_an_ai_duplicate_as_the_primary_finding() {
    let counter = FindingCounter::new();
    let mut ai = Finding::new_static(
        &counter,
        AnalysisCategory::Bug,
        Severity::Medium,
        "same".into(),
        "ai description".into(),
        PathBuf::from("source.rs"),
    )
    .with_lines(4, 4)
    .with_rule("bug.same".into());
    ai.source = FindingSource::Ai;
    let static_finding = Finding::new_static(
        &counter,
        AnalysisCategory::Bug,
        Severity::High,
        "same".into(),
        "static description".into(),
        PathBuf::from("source.rs"),
    )
    .with_lines(4, 4)
    .with_rule("quality.same".into());

    let findings = finalize_findings(
        vec![ai, static_finding],
        Path::new("."),
        Confidence::Low,
        &[AnalysisCategory::Bug],
    );

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].source, FindingSource::Static);
    assert_eq!(findings[0].description, "static description");
}

#[test]
fn normalization_relativizes_missing_absolute_evidence_paths() {
    let project = TempDir::new().unwrap();
    let counter = FindingCounter::new();
    let mut finding = Finding::new_static(
        &counter,
        AnalysisCategory::Bug,
        Severity::Low,
        "missing".into(),
        "missing".into(),
        project.path().join("missing.rs"),
    );
    let canonical_root = project.path().canonicalize().unwrap();

    normalize_finding_path(&mut finding, &canonical_root);

    assert_eq!(finding.file, Path::new("missing.rs"));
}

#[test]
fn full_mode_collects_static_findings_before_the_model_runs() {
    let project = TempDir::new().unwrap();
    fs::write(project.path().join("source.rs"), "// TODO: static issue\n").unwrap();
    let config = minimal_config(AnalysisMode::Full);
    let context = prepare_context(project.path(), &config).unwrap();

    let findings = initial_findings(&context, &config, AnalysisMode::Full).unwrap();

    assert!(
        findings
            .iter()
            .any(|finding| finding.title.contains("TODO")),
        "a mode that requires static analysis seeds the run with its findings: {findings:?}"
    );
}

#[test]
fn cancellation_takes_precedence_over_a_completed_worker_error() {
    let cancel = crate::cancel::CancelToken::default();
    cancel.cancel();
    let worker_error = Err::<(), _>(
        crate::errors::AnalysisError::WorkerFailed {
            action: "prepare project",
            reason: "worker failed too".into(),
        }
        .into(),
    );

    let error = cancellation_precedes(&cancel, worker_error).unwrap_err();

    assert!(matches!(error, BugHunterError::Cancelled));
}

#[test]
fn a_run_is_only_aborted_once_its_token_is_cancelled() {
    let cancel = crate::cancel::CancelToken::default();

    ensure_not_cancelled(&cancel).expect("an active run continues");
    cancel.cancel();
    let error = ensure_not_cancelled(&cancel).unwrap_err();

    assert!(matches!(error, BugHunterError::Cancelled), "{error}");
}

#[test]
fn a_non_interactive_run_never_starts_the_terminal_ui() {
    let started = std::cell::Cell::new(false);

    let mut start_terminal = |_, _| {
        started.set(true);
        Err::<Tui, _>(std::io::Error::other("must not start"))
    };
    let ui = start_tui(
        false,
        &crate::tui::shared_state(),
        &crate::cancel::CancelToken::default(),
        &mut start_terminal,
    )
    .unwrap();

    assert!(ui.is_none());
    assert!(
        !started.get(),
        "a run without the TUI must not touch the terminal"
    );
}

#[test]
fn a_started_terminal_ui_receives_the_run_state_and_cancel_token() {
    let state = crate::tui::shared_state();
    let cancel = crate::cancel::CancelToken::default();
    cancel.cancel();
    let received = std::cell::Cell::new((false, false));
    let mut start_terminal =
        |handed_state: crate::tui::SharedState, handed_cancel: crate::cancel::CancelToken| {
            received.set((
                Arc::ptr_eq(&handed_state, &state),
                handed_cancel.is_cancelled(),
            ));
            Err::<Tui, _>(std::io::Error::other("stop after handoff"))
        };

    let result = start_tui(true, &state, &cancel, &mut start_terminal);
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("the injected terminal failure must stop the run"),
    };

    assert_eq!(received.get(), (true, true));
    assert!(error.to_string().contains("stop after handoff"));
}

#[test]
fn a_terminal_ui_that_cannot_start_fails_the_run_with_its_cause() {
    let mut start_terminal = |_, _| Err::<Tui, _>(std::io::Error::other("no terminal attached"));
    let result = start_tui(
        true,
        &crate::tui::shared_state(),
        &crate::cancel::CancelToken::default(),
        &mut start_terminal,
    );
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("a terminal that cannot start must fail the analysis"),
    };

    let BugHunterError::Analysis(crate::errors::AnalysisError::TerminalFailed { action, source }) =
        error
    else {
        panic!("a terminal that cannot start must fail the analysis");
    };
    assert_eq!(action, "start");
    assert_eq!(source.to_string(), "no terminal attached");
}

#[test]
fn terminal_cleanup_errors_never_replace_an_analysis_error() {
    let analysis_error = BugHunterError::Cancelled;
    let result = preserve_analysis_result::<()>(
        Err(analysis_error),
        Err(std::io::Error::other("restore failed")),
    );
    assert!(matches!(result, Err(BugHunterError::Cancelled)));

    let error =
        preserve_analysis_result(Ok(()), Err(std::io::Error::other("restore failed"))).unwrap_err();
    assert!(matches!(
        error,
        BugHunterError::Analysis(crate::errors::AnalysisError::TerminalFailed {
            action: "restore terminal state",
            ..
        })
    ));
}

#[test]
fn a_successful_run_with_a_clean_terminal_shutdown_keeps_its_result() {
    let result = preserve_analysis_result(Ok(42), Ok(()));

    assert_eq!(result.ok(), Some(42));
}

#[test]
fn a_claude_run_without_a_review_reports_no_skipped_files() {
    let repo_map = RepoMap {
        text: String::new(),
        files: vec!["src/a.rs".into()],
        estimated_tokens: 12,
        omitted_files: 0,
        omitted_file_reports: Vec::new(),
        omitted_file_diagnostics: 0,
    };
    let counter = FindingCounter::new();
    let mut finding = Finding::new_static(
        &counter,
        AnalysisCategory::Bug,
        Severity::High,
        "model finding".into(),
        "model finding".into(),
        PathBuf::from("src/a.rs"),
    );
    finding.source = FindingSource::Ai;
    let analysis = claude_cli::McpAnalysis {
        findings: vec![finding],
        inspected_files: ["src/a.rs".to_string()].into_iter().collect(),
        tool_calls: 2,
    };

    let ai = claude_analysis(analysis, &repo_map, None, &[]);

    assert_eq!(ai.findings.len(), 1);
    assert_eq!(ai.findings[0].title, "model finding");
    assert!(ai.scan.skipped_files.is_empty());
    assert_eq!(ai.scan.completeness, ScanCompleteness::Complete);
    assert_eq!(ai.scan.files_inspected, 1);
}

#[test]
fn a_claude_run_reports_unreadable_inventory_files() {
    let repo_map = RepoMap {
        text: String::new(),
        files: vec!["src/a.rs".into()],
        estimated_tokens: 12,
        omitted_files: 0,
        omitted_file_reports: Vec::new(),
        omitted_file_diagnostics: 0,
    };
    let analysis = claude_cli::McpAnalysis {
        findings: Vec::new(),
        inspected_files: ["src/a.rs".to_string()].into_iter().collect(),
        tool_calls: 1,
    };
    let unreadable = UnreadableFile {
        relative_path: "src/locked.rs".to_string(),
        reason: "permission denied".to_string(),
    };

    let ai = claude_analysis(analysis, &repo_map, None, &[unreadable]);

    assert_eq!(
        ai.scan.skipped_files,
        ["src/locked.rs (permission denied)".to_string()]
    );
    assert_eq!(ai.scan.completeness, ScanCompleteness::Partial);
}

#[test]
fn a_claude_review_run_reports_the_changed_files_it_could_not_present() {
    let project = TempDir::new().unwrap();
    fs::write(project.path().join("app.rs"), "fn app() {}\n").unwrap();
    let inventory = ProjectInventory::build(project.path(), &EngineConfig::default()).unwrap();
    let unpresentable = crate::review::SkippedChangedFile {
        path: "vendor/bundle.min.js".to_string(),
        reason: crate::review::ChangedFileSkipReason::ExcludedByEngineFilters,
    };
    let mut scope = crate::review::ReviewScope::new(
        4,
        "main".into(),
        None,
        std::collections::BTreeMap::from([
            ("app.rs".to_string(), vec![(1, 1)]),
            ("vendor/bundle.min.js".to_string(), vec![(1, 1)]),
        ]),
        String::new(),
    )
    .unwrap();
    scope
        .set_changed_file_coverage(crate::review::ChangedFileCoverage {
            inspectable: std::collections::BTreeSet::from(["app.rs".to_string()]),
            skipped: vec![unpresentable.clone()],
        })
        .unwrap();
    let selection = review_selection(Some(&scope), &inventory).expect("a review scope selects");
    let repo_map = RepoMap {
        text: String::new(),
        files: vec!["app.rs".into()],
        estimated_tokens: 12,
        omitted_files: 0,
        omitted_file_reports: Vec::new(),
        omitted_file_diagnostics: 0,
    };
    let analysis = claude_cli::McpAnalysis {
        findings: Vec::new(),
        inspected_files: ["app.rs".to_string()].into_iter().collect(),
        tool_calls: 1,
    };

    let ai = claude_analysis(analysis, &repo_map, Some(&selection), &[]);

    assert_eq!(ai.scan.skipped_files, vec![unpresentable.report_entry()]);
    assert_eq!(
        ai.scan.completeness,
        ScanCompleteness::Partial,
        "a changed file that never reached the model leaves the scan incomplete"
    );
    assert_eq!(ai.scan.files_inspected, 1);
}

fn openai_config(api_url: String, api_token: Option<String>) -> Config {
    let mut config = Config::default();
    config.llm.backend = BackendConfig::OpenAiCompatible { api_url, api_token };
    config.llm.model = "test-model".into();
    config
}

fn reported_window(tokens: u32) -> ResponseTemplate {
    let body = serde_json::json!({"data": [{"id": "test-model", "context_length": tokens}]});
    ResponseTemplate::new(200).set_body_json(body)
}

async fn models_server(template: ResponseTemplate) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/models"))
        .respond_with(template)
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn a_configured_context_window_is_used_without_asking_the_provider() {
    let server = models_server(reported_window(262_144)).await;
    let mut config = openai_config(server.uri(), Some("token".into()));
    config.llm.max_context_tokens = 12_345;
    let backend = OpenAiBackend::new(config.llm.clone()).unwrap();

    let resolved =
        resolve_context_window(&config, &backend, &crate::cancel::CancelToken::default())
            .await
            .unwrap();

    assert_eq!(resolved.llm.max_context_tokens, 12_345);
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "an explicit context window must not cost a provider round trip"
    );
}

#[tokio::test]
async fn an_automatic_context_window_adopts_the_provider_reported_size() {
    let server = models_server(reported_window(262_144)).await;
    let config = openai_config(server.uri(), Some("token".into()));
    let backend = OpenAiBackend::new(config.llm.clone()).unwrap();

    let resolved =
        resolve_context_window(&config, &backend, &crate::cancel::CancelToken::default())
            .await
            .unwrap();

    assert_eq!(config.llm.max_context_tokens, 0, "the run asked for auto");
    assert_eq!(resolved.llm.max_context_tokens, 262_144);
    assert_eq!(resolved.llm.effective_context_tokens(), 262_144);
}

#[tokio::test]
async fn a_provider_without_a_reported_window_keeps_the_default() {
    let server = models_server(ResponseTemplate::new(500)).await;
    let config = openai_config(server.uri(), Some("token".into()));
    let backend = OpenAiBackend::new(config.llm.clone()).unwrap();

    let resolved =
        resolve_context_window(&config, &backend, &crate::cancel::CancelToken::default())
            .await
            .unwrap();

    assert_eq!(resolved.llm.max_context_tokens, 0);
    assert_eq!(
        resolved.llm.effective_context_tokens(),
        config.llm.effective_context_tokens(),
        "an unreported window leaves the configured fallback untouched"
    );
    assert_eq!(resolved.llm.effective_context_tokens(), 128_000);
}

#[tokio::test]
async fn context_window_detection_stops_when_the_run_is_cancelled() {
    let server =
        models_server(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(30)))
            .await;
    let config = openai_config(server.uri(), Some("token".into()));
    let backend = OpenAiBackend::new(config.llm.clone()).unwrap();
    let cancel = crate::cancel::CancelToken::default();
    let cancellation_signal = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        cancellation_signal.cancel();
    });

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        resolve_context_window(&config, &backend, &cancel),
    )
    .await
    .expect("cancellation must interrupt context-window detection");

    assert!(matches!(result, Err(BugHunterError::Cancelled)));
}

#[tokio::test]
async fn an_openai_backend_without_a_token_fails_before_any_request() {
    let project = TempDir::new().unwrap();
    fs::write(project.path().join("app.rs"), "fn app() {}\n").unwrap();
    let config = openai_config("https://provider.invalid/v1".into(), None);
    let ctx = prepare_context(project.path(), &config).unwrap();
    let reporter = Reporter::new(crate::tui::shared_state());
    let cancel = crate::cancel::CancelToken::default();

    let result = run_ai_analysis(AiRequest {
        config: &config,
        backend_working_directory: Some(project.path()),
        ctx: &ctx,
        project_root: project.path(),
        system_prompt: "system",
        reporter: &reporter,
        review: None,
        cancel: &cancel,
    })
    .await;

    let Err(error) = result else {
        panic!("a backend without credentials must not reach the provider");
    };
    assert!(
        matches!(
            error,
            BugHunterError::Llm(crate::errors::LlmError::AuthError)
        ),
        "{error}"
    );
}

#[cfg(unix)]
#[test]
fn a_finding_path_that_is_not_utf8_fails_the_report_instead_of_panicking() {
    use std::os::unix::ffi::OsStringExt;

    let project = TempDir::new().unwrap();
    let counter = FindingCounter::new();
    let finding = Finding::new_static(
        &counter,
        AnalysisCategory::Bug,
        Severity::High,
        "unnameable evidence".into(),
        "unnameable evidence".into(),
        PathBuf::from(std::ffi::OsString::from_vec(b"src/\xffbroken.rs".to_vec())),
    );

    let error = build_result(
        vec![finding],
        project.path(),
        &Config::default(),
        "static",
        ScanStatus::complete(1),
    )
    .unwrap_err();

    assert!(matches!(
        error,
        BugHunterError::Report(crate::errors::ReportError::SerializationError(_))
    ));
}

#[test]
fn an_ai_duplicate_yields_its_place_to_the_static_finding_it_shadows() {
    let counter = FindingCounter::new();
    let mut ai = Finding::new_static(
        &counter,
        AnalysisCategory::Bug,
        Severity::Critical,
        "same".into(),
        "ai description".into(),
        PathBuf::from("source.rs"),
    )
    .with_lines(4, 6)
    .with_rule("bug.same".into())
    .with_suggestion("read the key from the environment".into());
    ai.source = FindingSource::Ai;
    let static_finding = Finding::new_static(
        &counter,
        AnalysisCategory::Bug,
        Severity::Low,
        "same".into(),
        "static description".into(),
        PathBuf::from("source.rs"),
    )
    .with_lines(5, 5)
    .with_rule("quality.same".into());

    let findings = finalize_findings(
        vec![ai, static_finding],
        Path::new("."),
        Confidence::Low,
        &[AnalysisCategory::Bug],
    );

    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].source,
        FindingSource::Static,
        "the deterministic finding leads even when the model reported it first"
    );
    assert_eq!(findings[0].description, "static description");
    assert_eq!(
        findings[0].severity,
        Severity::Critical,
        "the merged finding keeps the worst severity"
    );
    assert_eq!(
        findings[0].suggestion.as_deref(),
        Some("read the key from the environment"),
        "the surviving finding adopts the suggestion it lacked"
    );
}

#[cfg(unix)]
fn recording_claude_binary(directory: &Path, inspected: &str) -> String {
    use std::os::unix::fs::PermissionsExt;

    let binary = directory.join("claude");
    let script = format!(
        r#"#!/bin/sh
set -eu
workspace=""
while [ $# -gt 0 ]; do
  if [ "$1" = "--mcp-config" ]; then
    workspace=$(dirname "$2")
  fi
  shift
done
cat > /dev/null
printf '%s\n' '{{"tool":"read_file","path":"{inspected}"}}' >> "$workspace/activity.jsonl"
printf '%s\n' '{{"is_error":false,"result":"done"}}'
"#
    );
    fs::write(&binary, script).unwrap();
    let mut permissions = fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&binary, permissions).unwrap();
    binary.to_string_lossy().into_owned()
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_claude_backend_reports_the_files_its_session_inspected() {
    let project = TempDir::new().unwrap();
    fs::write(project.path().join("app.rs"), "fn app() {}\n").unwrap();
    let cli = TempDir::new().unwrap();
    let mut config = Config::default();
    config.llm.backend = BackendConfig::ClaudeCli {
        binary: recording_claude_binary(cli.path(), "app.rs"),
    };
    config.llm.model = "claude-test".into();
    let ctx = prepare_context(project.path(), &config).unwrap();
    let state = crate::tui::shared_state();
    let reporter = Reporter::new(state.clone());
    let cancel = crate::cancel::CancelToken::default();

    let ai = run_ai_analysis(AiRequest {
        config: &config,
        backend_working_directory: Some(project.path()),
        ctx: &ctx,
        project_root: project.path(),
        system_prompt: "system",
        reporter: &reporter,
        review: None,
        cancel: &cancel,
    })
    .await
    .expect("a session that inspected the code completes");

    assert!(ai.findings.is_empty(), "the session submitted no findings");
    assert_eq!(ai.scan.completeness, ScanCompleteness::Complete);
    assert_eq!(ai.scan.shards_total, 1);
    assert_eq!(ai.scan.shards_completed, 1);
    assert_eq!(ai.scan.files_presented, 1);
    assert_eq!(ai.scan.files_inspected, 1);
    assert!(ai.scan.uninspected_files.is_empty());
    assert!(ai.scan.skipped_files.is_empty());
    let state = state.lock();
    assert_eq!(state.model, "claude-test");
    assert_eq!(state.total_shards, 1);
    assert_eq!(state.current_shard, 1);
    assert_eq!(state.completed_shards, 1);
    assert_eq!(state.model_activity.requests, 1);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn successful_full_runs_finish_with_the_authoritative_finding_total() {
    let project = TempDir::new().unwrap();
    fs::write(
        project.path().join("app.rs"),
        "// TODO: deterministic finding\nfn app() {}\n",
    )
    .unwrap();
    let cli = TempDir::new().unwrap();
    let mut raw = Config::default();
    raw.llm.backend = BackendConfig::ClaudeCli {
        binary: recording_claude_binary(cli.path(), "app.rs"),
    };
    raw.llm.model = "claude-test".into();
    let config = ValidatedConfig::new(raw, AnalysisMode::Full).unwrap();
    let state = crate::tui::shared_state();

    let result = run_analysis(
        project.path(),
        Some(project.path()),
        &config,
        state.clone(),
        false,
        None,
        crate::cancel::CancelToken::default(),
    )
    .await
    .unwrap();

    let mut state = state.lock();
    assert_eq!(state.phase, crate::tui::Phase::Finished);
    assert_eq!(state.findings, result.findings.len());
    assert_eq!(state.progress(), 1.0);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_ai_runs_never_render_as_finished() {
    let project = TempDir::new().unwrap();
    fs::write(project.path().join("app.rs"), "fn app() {}\n").unwrap();
    let mut raw = Config::default();
    raw.llm.backend = BackendConfig::ClaudeCli {
        binary: project
            .path()
            .join("missing-claude-binary")
            .to_string_lossy()
            .into_owned(),
    };
    let config = ValidatedConfig::new(raw, AnalysisMode::AiOnly).unwrap();
    let state = crate::tui::shared_state();

    let result = run_analysis(
        project.path(),
        Some(project.path()),
        &config,
        state.clone(),
        false,
        None,
        crate::cancel::CancelToken::default(),
    )
    .await;

    assert!(result.is_err());
    let mut state = state.lock();
    assert_eq!(state.phase, crate::tui::Phase::Failed);
    assert!(state.progress() < 1.0);
}

#[cfg(unix)]
#[tokio::test]
async fn a_run_cancelled_as_the_analysis_completes_reports_cancellation() {
    let project = TempDir::new().unwrap();
    fs::write(project.path().join("app.rs"), "fn app() {}\n").unwrap();
    let cli = TempDir::new().unwrap();
    let mut raw = Config::default();
    raw.llm.backend = BackendConfig::ClaudeCli {
        binary: recording_claude_binary(cli.path(), "app.rs"),
    };
    raw.llm.model = "claude-test".into();
    let config = ValidatedConfig::new(raw, AnalysisMode::AiOnly).unwrap();
    let state = crate::tui::shared_state();
    let cancel = crate::cancel::CancelToken::default();
    let subscriber = tracing_subscriber::registry().with(CancelOnLogMessage {
        needle: "AI analysis complete",
        cancel: cancel.clone(),
    });
    let _guard = tracing::subscriber::set_default(subscriber);

    let result = run_analysis(
        project.path(),
        Some(project.path()),
        &config,
        state.clone(),
        false,
        None,
        cancel,
    )
    .await;

    let Err(error) = result else {
        panic!("a run cancelled after the analysis must not produce a report");
    };
    assert!(matches!(error, BugHunterError::Cancelled), "{error}");
    assert_eq!(state.lock().phase, crate::tui::Phase::Cancelled);
}
