use bughunter::{
    AnalysisError, AnalysisMode, BugHunterError, ChangedFileCoverage, Config, ConfigError,
    EngineError, LlmError, ProjectRoot, RepoMapError, ReportError, ReviewError, ReviewScope,
};

#[tokio::test]
async fn library_runs_static_analysis_without_process_exit() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("app.py"), "value = 1\n").unwrap();

    let root = ProjectRoot::open(project.path()).unwrap();
    let result = bughunter::analyze(&root, Config::default(), AnalysisMode::Static)
        .await
        .unwrap();

    assert!(result.output.contains("\"mode\": \"static\""));
}

#[tokio::test]
async fn library_rejects_unvalidated_configuration() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("app.py"), "value = 1\n").unwrap();
    let mut config = Config::default();
    config.analysis.categories.clear();

    let root = ProjectRoot::open(project.path()).unwrap();
    let result = bughunter::analyze(&root, config, AnalysisMode::Static).await;

    assert!(matches!(result, Err(bughunter::BugHunterError::Config(_))));
}

#[tokio::test]
async fn library_requires_typed_scope_for_review_analysis() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("app.py"), "value = 1\n").unwrap();
    let root = ProjectRoot::open(project.path()).unwrap();

    let result = bughunter::analyze(&root, Config::default(), AnalysisMode::Review).await;

    assert!(matches!(
        result,
        Err(BugHunterError::Config(ConfigError::InvalidValue { field, .. }))
            if field == "mode"
    ));
}

#[tokio::test]
async fn library_review_api_requires_a_validated_config_and_typed_scope() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("app.py"), "value = 1\n").unwrap();
    let root = ProjectRoot::open(project.path()).unwrap();
    let mut config = Config::default();
    config.analysis.categories.clear();
    let review = ReviewScope::new(
        1,
        "main".to_string(),
        Some("0123456789abcdef".to_string()),
        std::collections::BTreeMap::from([("app.py".to_string(), vec![(1, 1)])]),
        String::new(),
    )
    .unwrap();

    let result = bughunter::analyze_review(&root, config, &review).await;

    assert!(matches!(result, Err(BugHunterError::Config(_))));
}

fn sample_review_hunks() -> std::collections::BTreeMap<String, Vec<(u32, u32)>> {
    std::collections::BTreeMap::from([("app.py".to_string(), vec![(1, 2)])])
}

fn review_hunks(
    path: &str,
    spans: Vec<(u32, u32)>,
) -> std::collections::BTreeMap<String, Vec<(u32, u32)>> {
    std::collections::BTreeMap::from([(path.to_string(), spans)])
}

fn assert_invalid_review_scope(scope: Result<ReviewScope, ReviewError>) {
    assert!(matches!(scope, Err(ReviewError::Scope(_))));
}

#[test]
fn review_scope_exposes_pinned_metadata_and_changed_files() {
    let mut scope = ReviewScope::new(
        7,
        "main".to_string(),
        Some("0123456789ABCDEF".to_string()),
        sample_review_hunks(),
        "@@ -1 +1 @@\n-value = 0\n+value = 1\n".to_string(),
    )
    .unwrap();

    assert_eq!(scope.pr(), 7);
    assert_eq!(scope.base_ref(), "main");
    assert_eq!(scope.head_sha(), Some("0123456789ABCDEF"));
    assert_eq!(
        scope.changed_files(),
        std::collections::BTreeSet::from(["app.py".to_string()])
    );
    assert_eq!(scope.hunk_ranges(), sample_review_hunks());
    assert!(scope.prompt_section(1_000).contains("app.py: 1-2"));

    scope
        .set_changed_file_coverage(ChangedFileCoverage {
            inspectable: std::collections::BTreeSet::from(["app.py".to_string()]),
            skipped: Vec::new(),
        })
        .unwrap();
    assert!(scope.skipped_changed_files().is_empty());
}

#[test]
fn review_scope_rejects_inspectable_paths_outside_the_repository() {
    let mut scope = ReviewScope::new(
        7,
        "main".to_string(),
        None,
        sample_review_hunks(),
        String::new(),
    )
    .unwrap();
    let escaping = ChangedFileCoverage {
        inspectable: std::collections::BTreeSet::from(["../escape.py".to_string()]),
        skipped: Vec::new(),
    };

    assert!(matches!(
        scope.set_changed_file_coverage(escaping),
        Err(ReviewError::Scope(_))
    ));
}

#[test]
fn review_scope_rejects_a_zero_pull_request_number() {
    assert_invalid_review_scope(ReviewScope::new(
        0,
        "main".to_string(),
        None,
        sample_review_hunks(),
        String::new(),
    ));
}

#[test]
fn review_scope_rejects_a_non_hexadecimal_head_commit() {
    assert_invalid_review_scope(ReviewScope::new(
        7,
        "main".to_string(),
        Some("ábcdef0123456789".to_string()),
        sample_review_hunks(),
        String::new(),
    ));
}

#[test]
fn review_scope_rejects_a_changed_file_outside_the_repository() {
    assert_invalid_review_scope(ReviewScope::new(
        7,
        "main".to_string(),
        None,
        review_hunks("../escape.py", vec![(1, 1)]),
        String::new(),
    ));
}

#[test]
fn review_scope_rejects_a_zero_line_number() {
    assert_invalid_review_scope(ReviewScope::new(
        7,
        "main".to_string(),
        None,
        review_hunks("app.py", vec![(0, 1)]),
        String::new(),
    ));
}

#[test]
fn review_scope_rejects_a_reversed_line_range() {
    assert_invalid_review_scope(ReviewScope::new(
        7,
        "main".to_string(),
        None,
        review_hunks("app.py", vec![(9, 2)]),
        String::new(),
    ));
}

#[test]
fn review_scope_rejects_an_oversized_diff() {
    assert_invalid_review_scope(ReviewScope::new(
        7,
        "main".to_string(),
        None,
        sample_review_hunks(),
        "x".repeat(32 * 1024 * 1024 + 1),
    ));
}

#[test]
fn concrete_public_error_types_are_nameable() {
    let names = [
        std::any::type_name::<AnalysisError>(),
        std::any::type_name::<ConfigError>(),
        std::any::type_name::<EngineError>(),
        std::any::type_name::<LlmError>(),
        std::any::type_name::<RepoMapError>(),
        std::any::type_name::<ReportError>(),
        std::any::type_name::<ReviewError>(),
    ];

    assert!(names.iter().all(|name| name.starts_with("bughunter::")));
}

#[test]
fn project_root_rejects_invalid_inputs() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("not-a-project");
    std::fs::write(&file, "data").unwrap();

    assert!(ProjectRoot::open(&file).is_err());
    assert!(ProjectRoot::open(&directory.path().join("missing")).is_err());
}

#[cfg(feature = "fuzzing")]
#[test]
fn fuzzing_report_facade_renders_json_and_markdown() {
    let directory = tempfile::tempdir().unwrap();
    let scan = bughunter::ScanStatus::complete(0);

    let json =
        bughunter::fuzzing::render_json_report("1.0.0", directory.path(), &[], "static", &scan)
            .unwrap();
    let markdown = bughunter::fuzzing::render_markdown_report(&[], &scan).unwrap();

    assert!(json.contains("\"mode\": \"static\""));
    assert!(markdown.contains("Coverage"));
}

#[cfg(unix)]
fn write_fake_claude(directory: &std::path::Path, script: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let path = directory.join("claude");
    std::fs::write(&path, script).unwrap();
    let mut permissions = std::fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&path, permissions).unwrap();
    path
}

#[cfg(unix)]
fn claude_config(binary: &std::path::Path) -> Config {
    let mut config = Config::default();
    config.llm.backend = bughunter::BackendConfig::ClaudeCli {
        binary: binary.to_string_lossy().into_owned(),
    };
    config
}

#[cfg(unix)]
#[tokio::test]
async fn library_routes_repository_signatures_through_the_configured_backend() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("app.py"),
        "def routed_function():\n    return 1\n",
    )
    .unwrap();
    let binary = write_fake_claude(
        project.path(),
        "#!/bin/sh\ngrep -Fq 'def routed_function():' || exit 42\nprintf '%s\\n' '{\"is_error\":false,\"result\":\"done\"}'\n",
    );
    let root = ProjectRoot::open(project.path()).unwrap();

    let error = bughunter::analyze(&root, claude_config(&binary), AnalysisMode::AiOnly)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        BugHunterError::Llm(LlmError::AgentProtocol(message))
            if message.contains("made no tool calls")
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn library_review_analysis_includes_files_hidden_by_snapshot_ignore_rules() {
    let project = tempfile::tempdir().unwrap();
    let trusted_tools = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("app.py"),
        "def hidden_signature():\n    return 1\n",
    )
    .unwrap();
    std::fs::write(project.path().join(".ignore"), "app.py\n").unwrap();
    let binary = write_fake_claude(
        trusted_tools.path(),
        "#!/bin/sh\ngrep -Fq 'def hidden_signature():' || exit 42\nprintf '%s\\n' '{\"is_error\":false,\"result\":\"done\"}'\n",
    );
    let root = ProjectRoot::open(project.path()).unwrap();
    let review = ReviewScope::new(
        7,
        "main".to_string(),
        Some("0123456789abcdef".to_string()),
        std::collections::BTreeMap::from([("app.py".to_string(), vec![(2, 2)])]),
        "@@ -2 +2 @@\n-    return 0\n+    return 1\n".to_string(),
    )
    .unwrap();

    let error = bughunter::analyze_review(&root, claude_config(&binary), &review)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        BugHunterError::Llm(LlmError::AgentProtocol(message))
            if message.contains("made no tool calls")
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn library_review_does_not_resolve_a_relative_backend_inside_the_snapshot() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("app.py"), "value = 1\n").unwrap();
    let binary = write_fake_claude(
        project.path(),
        "#!/bin/sh\ntouch \"$(dirname \"$0\")/executed\"\ncat >/dev/null\n",
    );
    let root = ProjectRoot::open(project.path()).unwrap();
    let review = ReviewScope::new(
        8,
        "main".to_string(),
        None,
        std::collections::BTreeMap::from([("app.py".to_string(), vec![(1, 1)])]),
        "@@ -1 +1 @@\n-value = 0\n+value = 1\n".to_string(),
    )
    .unwrap();
    let mut config = claude_config(&binary);
    config.llm.backend = bughunter::BackendConfig::ClaudeCli {
        binary: "./claude".to_string(),
    };

    let error = bughunter::analyze_review(&root, config, &review)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        BugHunterError::Llm(LlmError::ClaudeSpawn { binary, source })
            if binary == "./claude" && source.kind() == std::io::ErrorKind::NotFound
    ));
    assert!(!project.path().join("executed").exists());
}
