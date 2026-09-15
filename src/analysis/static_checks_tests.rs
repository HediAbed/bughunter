use super::*;
use crate::config::EngineConfig;
use crate::config::schema::QualityThresholds;
use crate::engine::DefaultEngine;
use std::fs;
use tempfile::TempDir;

fn default_analysis_config() -> AnalysisConfig {
    AnalysisConfig::default()
}

fn create_engine() -> DefaultEngine {
    DefaultEngine::new(EngineConfig::default())
}

fn counter() -> FindingCounter {
    FindingCounter::new()
}

#[test]
fn detects_long_functions() {
    let dir = TempDir::new().unwrap();
    let lines: Vec<String> = (0..60).map(|i| format!("    let x{i} = {i};")).collect();
    let content = format!("fn long_function() {{\n{}\n}}\n", lines.join("\n"));
    fs::write(dir.path().join("long.rs"), &content).unwrap();

    let engine = create_engine();
    let config = default_analysis_config();
    let findings = run_static_checks(&engine, dir.path(), &config, &counter())
        .unwrap()
        .findings;

    let fn_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule.as_deref() == Some(FUNCTION_LENGTH_RULE))
        .collect();
    assert!(!fn_findings.is_empty());
    assert!(fn_findings[0].title.contains("long_function"));
}

#[test]
fn ignores_short_functions() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("short.rs"), "fn short() {\n    42\n}\n").unwrap();

    let engine = create_engine();
    let config = default_analysis_config();
    let findings = run_static_checks(&engine, dir.path(), &config, &counter())
        .unwrap()
        .findings;

    let fn_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule.as_deref() == Some(FUNCTION_LENGTH_RULE))
        .collect();
    assert!(fn_findings.is_empty());
}

#[test]
fn inventory_scans_report_findings_and_honour_cancellation() {
    let dir = TempDir::new().unwrap();
    let lines: Vec<String> = (0..60).map(|i| format!("    let x{i} = {i};")).collect();
    let content = format!("fn long_function() {{\n{}\n}}\n", lines.join("\n"));
    fs::write(dir.path().join("long.rs"), &content).unwrap();

    let engine = create_engine();
    let config = default_analysis_config();
    let inventory = ProjectInventory::build(dir.path(), &EngineConfig::default()).unwrap();

    let live = run_static_checks_with_inventory_cancellable(
        &engine,
        &inventory,
        &config,
        &counter(),
        &CancelToken::default(),
    )
    .unwrap();

    assert_eq!(live.files_scanned, 1);
    assert!(
        live.findings
            .iter()
            .any(|f| f.rule.as_deref() == Some(FUNCTION_LENGTH_RULE))
    );

    let cancelled = CancelToken::default();
    cancelled.cancel();
    let error = run_static_checks_with_inventory_cancellable(
        &engine,
        &inventory,
        &config,
        &counter(),
        &cancelled,
    )
    .unwrap_err();

    assert!(matches!(error, EngineError::Cancelled));
}

#[test]
fn detects_long_files() {
    let dir = TempDir::new().unwrap();
    let lines: Vec<String> = (0..600).map(|i| format!("let x{i} = {i};")).collect();
    fs::write(dir.path().join("big.rs"), lines.join("\n")).unwrap();

    let engine = create_engine();
    let config = default_analysis_config();
    let findings = run_static_checks(&engine, dir.path(), &config, &counter())
        .unwrap()
        .findings;

    let file_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule.as_deref() == Some(FILE_LENGTH_RULE))
        .collect();
    assert!(!file_findings.is_empty());
}

#[test]
fn detects_hardcoded_api_key() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("config.py"),
        "api_key = \"abcdef1234567890abcdef1234567890\"\n",
    )
    .unwrap();

    let engine = create_engine();
    let config = default_analysis_config();
    let findings = run_static_checks(&engine, dir.path(), &config, &counter())
        .unwrap()
        .findings;

    let secret_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule.as_deref() == Some(HARDCODED_SECRET_RULE))
        .collect();
    assert!(!secret_findings.is_empty());
    assert_eq!(secret_findings[0].severity, Severity::Critical);
}

#[test]
fn detects_hardcoded_password() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("db.py"), "password = \"SuperSecret123!\"\n").unwrap();

    let engine = create_engine();
    let config = default_analysis_config();
    let findings = run_static_checks(&engine, dir.path(), &config, &counter())
        .unwrap()
        .findings;

    let secret_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule.as_deref() == Some(HARDCODED_SECRET_RULE))
        .collect();
    assert!(!secret_findings.is_empty());
}

#[test]
fn detects_secret_assignments_split_across_lines() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("config.py"),
        "api_key\n  =\n  \"abcdef1234567890abcdef1234567890\"\n",
    )
    .unwrap();

    let findings = run_static_checks(
        &create_engine(),
        dir.path(),
        &default_analysis_config(),
        &counter(),
    )
    .unwrap()
    .findings;
    let secret = findings
        .iter()
        .find(|finding| finding.rule.as_deref() == Some(HARDCODED_SECRET_RULE))
        .expect("the multiline secret assignment must be detected");

    assert_eq!(secret.line_start, Some(1));
    assert_eq!(secret.line_end, Some(3));
}

#[test]
fn ignores_known_placeholder_secret_values() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("examples.py"),
        concat!(
            "password = \"password\"\n",
            "api_key = \"your_api_key_here_1234\"\n",
            "token = \"0000000000000000\"\n",
            "password = \"${DATABASE_PASSWORD}\"\n",
            "secret = \"replace-me-please\"\n",
        ),
    )
    .unwrap();

    let findings = run_static_checks(
        &create_engine(),
        dir.path(),
        &default_analysis_config(),
        &counter(),
    )
    .unwrap()
    .findings;

    assert!(
        findings
            .iter()
            .all(|finding| finding.rule.as_deref() != Some(HARDCODED_SECRET_RULE))
    );
}
#[test]
fn detects_todo_comments() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("work.rs"),
        "// TODO: fix this later\nfn hello() {}\n// FIXME: broken\n",
    )
    .unwrap();

    let engine = create_engine();
    let config = default_analysis_config();
    let findings = run_static_checks(&engine, dir.path(), &config, &counter())
        .unwrap()
        .findings;

    let todo_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule.as_deref() == Some(TODO_COMMENT_RULE))
        .collect();
    assert_eq!(todo_findings.len(), 2);
}

#[test]
fn ignores_todo_in_non_comment_code() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("code.rs"),
        "let todo_list = vec![\"item1\"];\n",
    )
    .unwrap();

    let engine = create_engine();
    let config = default_analysis_config();
    let findings = run_static_checks(&engine, dir.path(), &config, &counter())
        .unwrap()
        .findings;

    let todo_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule.as_deref() == Some(TODO_COMMENT_RULE))
        .collect();
    assert!(todo_findings.is_empty());
}

#[test]
fn distinguishes_pointer_expressions_from_block_comments() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("pointers.c"),
        "int *HACK_flag;\n*TODO_pointer = 1;\n/*\n * TODO: real work\n */\n",
    )
    .unwrap();

    let engine = create_engine();
    let config = default_analysis_config();
    let findings = run_static_checks(&engine, dir.path(), &config, &counter())
        .unwrap()
        .findings;
    let todo_findings: Vec<_> = findings
        .iter()
        .filter(|finding| finding.rule.as_deref() == Some(TODO_COMMENT_RULE))
        .collect();

    assert_eq!(todo_findings.len(), 1);
    assert_eq!(todo_findings[0].line_start, Some(4));
}

#[test]
fn respects_custom_thresholds() {
    let dir = TempDir::new().unwrap();
    let lines: Vec<String> = (0..30).map(|i| format!("    let x{i} = {i};")).collect();
    let content = format!("fn medium_function() {{\n{}\n}}\n", lines.join("\n"));
    fs::write(dir.path().join("med.rs"), &content).unwrap();

    let engine = create_engine();
    let mut config = default_analysis_config();
    config.quality = QualityThresholds {
        max_function_lines: 20,
        max_file_lines: 500,
    };
    let findings = run_static_checks(&engine, dir.path(), &config, &counter())
        .unwrap()
        .findings;

    let fn_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule.as_deref() == Some(FUNCTION_LENGTH_RULE))
        .collect();
    assert!(!fn_findings.is_empty());
}

#[test]
fn empty_project_returns_no_findings() {
    let dir = TempDir::new().unwrap();
    let engine = create_engine();
    let config = default_analysis_config();
    let findings = run_static_checks(&engine, dir.path(), &config, &counter())
        .unwrap()
        .findings;
    assert!(findings.is_empty());
}

#[test]
fn vulnerability_only_run_skips_quality_checks() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("app.py"),
        "# TODO: cleanup\npassword = \"SuperSecret123!\"\n",
    )
    .unwrap();

    let engine = create_engine();
    let mut config = default_analysis_config();
    config.categories = vec![AnalysisCategory::Vulnerability];
    let findings = run_static_checks(&engine, dir.path(), &config, &counter())
        .unwrap()
        .findings;

    assert!(
        findings
            .iter()
            .any(|f| f.category == AnalysisCategory::Vulnerability)
    );
    assert!(
        findings
            .iter()
            .all(|f| f.category != AnalysisCategory::Quality)
    );
}

#[test]
fn quality_only_run_skips_secret_checks() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("app.py"),
        "# TODO: cleanup\npassword = \"SuperSecret123!\"\n",
    )
    .unwrap();

    let engine = create_engine();
    let mut config = default_analysis_config();
    config.categories = vec![AnalysisCategory::Quality];
    let findings = run_static_checks(&engine, dir.path(), &config, &counter())
        .unwrap()
        .findings;

    assert!(
        findings
            .iter()
            .any(|f| f.category == AnalysisCategory::Quality)
    );
    assert!(
        findings
            .iter()
            .all(|f| f.category != AnalysisCategory::Vulnerability)
    );
}

#[test]
fn bug_and_solid_only_run_skips_all_static_checks() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("app.py"), "# TODO: cleanup\n").unwrap();

    let engine = create_engine();
    let mut config = default_analysis_config();
    config.categories = vec![AnalysisCategory::Bug, AnalysisCategory::Solid];
    let findings = run_static_checks(&engine, dir.path(), &config, &counter())
        .unwrap()
        .findings;

    assert!(findings.is_empty());
}

#[test]
fn reports_the_number_of_scanned_files() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("a.rs"), "fn a() {}\n").unwrap();
    fs::write(dir.path().join("b.rs"), "fn b() {}\n").unwrap();

    let engine = create_engine();
    let analysis =
        run_static_checks(&engine, dir.path(), &default_analysis_config(), &counter()).unwrap();

    assert_eq!(analysis.files_scanned, 2);
}

#[test]
fn reports_zero_scanned_files_when_no_static_category_is_enabled() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("a.rs"), "// TODO: cleanup\n").unwrap();

    let engine = create_engine();
    let mut config = default_analysis_config();
    config.categories = vec![AnalysisCategory::Bug];
    let analysis = run_static_checks(&engine, dir.path(), &config, &counter()).unwrap();

    assert_eq!(analysis.files_scanned, 0);
    assert!(analysis.findings.is_empty());
}

#[test]
fn rejects_static_finding_sets_beyond_the_global_limit() {
    let directory = TempDir::new().unwrap();
    let source = "api_key = \"abcdef1234567890abcdef1234567890\"\n".repeat(MAX_STATIC_FINDINGS + 1);
    fs::write(directory.path().join("secrets.py"), source).unwrap();

    let engine = create_engine();
    let mut config = default_analysis_config();
    config.categories = vec![AnalysisCategory::Vulnerability];
    let error = match run_static_checks(&engine, directory.path(), &config, &counter()) {
        Ok(_) => panic!("finding limit was not enforced"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        EngineError::FindingLimitExceeded {
            max_findings: MAX_STATIC_FINDINGS
        }
    ));
}

const AST_LANGUAGES: [&str; 13] = [
    "rust",
    "python",
    "javascript",
    "typescript",
    "tsx",
    "go",
    "java",
    "c",
    "cpp",
    "hcl",
    "yaml",
    "bash",
    "json",
];

fn filesystem_for(directory: &TempDir) -> ProjectFilesystem {
    let root = ProjectRoot::open(directory.path()).unwrap();
    ProjectFilesystem::open(root).unwrap()
}

fn discovered_entry(directory: &TempDir, relative_path: &str) -> FileEntry {
    FileEntry {
        path: directory.path().join(relative_path),
        relative_path: relative_path.to_string(),
        size_bytes: 16,
        language: Some("rust".into()),
    }
}

fn scan_entries(directory: &TempDir, files: &[FileEntry]) -> StaticAnalysis {
    scan_sources(directory, files, &[])
}

fn scan_sources(
    directory: &TempDir,
    files: &[FileEntry],
    unreadable: &[UnreadableFile],
) -> StaticAnalysis {
    scan_files(
        &create_engine(),
        DiscoveredSources {
            filesystem: &filesystem_for(directory),
            files,
            unreadable,
        },
        &default_analysis_config(),
        &counter(),
    )
    .unwrap()
}

fn skipped_paths(analysis: &StaticAnalysis) -> Vec<&str> {
    analysis
        .skipped_files
        .iter()
        .map(|entry| {
            entry
                .split_once(' ')
                .map_or(entry.as_str(), |(path, _)| path)
        })
        .collect()
}

#[test]
fn a_file_that_cannot_be_read_is_skipped_instead_of_silently_dropped() {
    let directory = TempDir::new().unwrap();
    fs::write(directory.path().join("present.rs"), "fn a() {}\n").unwrap();
    let files = vec![
        discovered_entry(&directory, "present.rs"),
        discovered_entry(&directory, "vanished.rs"),
    ];

    let analysis = scan_entries(&directory, &files);

    assert_eq!(analysis.files_scanned, 1);
    assert_eq!(skipped_paths(&analysis), vec!["vanished.rs"]);
    assert!(
        analysis.skipped_files[0].contains('('),
        "the skip must carry a reason: {:?}",
        analysis.skipped_files
    );
}

#[test]
fn skipped_static_files_are_reported_in_deterministic_order() {
    let directory = TempDir::new().unwrap();
    let files = vec![
        discovered_entry(&directory, "z_gone.rs"),
        discovered_entry(&directory, "a_gone.rs"),
        discovered_entry(&directory, "m_gone.rs"),
    ];

    let analysis = scan_entries(&directory, &files);

    assert_eq!(analysis.files_scanned, 0);
    assert_eq!(
        skipped_paths(&analysis),
        vec!["a_gone.rs", "m_gone.rs", "z_gone.rs"]
    );
}

#[test]
fn files_discovery_could_not_read_are_reported_as_skipped() {
    let directory = TempDir::new().unwrap();
    fs::write(directory.path().join("readable.rs"), "fn a() {}\n").unwrap();
    let unreadable = vec![UnreadableFile {
        relative_path: "locked.rs".into(),
        reason: "Permission denied (os error 13)".into(),
    }];

    let analysis = scan_sources(
        &directory,
        &[discovered_entry(&directory, "readable.rs")],
        &unreadable,
    );

    assert_eq!(analysis.files_scanned, 1);
    assert_eq!(skipped_paths(&analysis), vec!["locked.rs"]);
    assert!(
        analysis.skipped_files[0].contains("Permission denied"),
        "{:?}",
        analysis.skipped_files
    );
}

#[test]
fn a_fully_readable_project_reports_no_skips() {
    let directory = TempDir::new().unwrap();
    fs::write(directory.path().join("a.rs"), "fn a() {}\n").unwrap();

    let analysis = scan_entries(&directory, &[discovered_entry(&directory, "a.rs")]);

    assert_eq!(analysis.files_scanned, 1);
    assert!(analysis.skipped_files.is_empty());
}

#[test]
fn non_callable_signatures_are_ignored_by_function_length_checks() {
    let signatures = [ast::Signature {
        name: "Configuration".into(),
        kind: ast::SignatureKind::Struct,
        line_start: 1,
        line_end: 100,
    }];
    let mut findings = BoundedFindings::new(10, MAX_STATIC_FINDING_BYTES);

    check_function_lengths(
        Path::new("source.rs"),
        &signatures,
        &default_analysis_config(),
        &counter(),
        &mut findings,
    )
    .unwrap();

    assert!(findings.values.is_empty());
}

#[test]
fn a_file_outside_the_project_root_is_reported_as_skipped() {
    let directory = TempDir::new().unwrap();
    fs::write(directory.path().join("inside.rs"), "fn a() {}\n").unwrap();
    let outside = FileEntry {
        path: std::path::PathBuf::from("/outside/secret.rs"),
        relative_path: "outside/secret.rs".into(),
        size_bytes: 16,
        language: Some("rust".into()),
    };

    let analysis = scan_entries(
        &directory,
        &[discovered_entry(&directory, "inside.rs"), outside],
    );

    assert_eq!(analysis.files_scanned, 1);
    assert_eq!(skipped_paths(&analysis), vec!["outside/secret.rs"]);
    assert!(
        analysis.skipped_files[0].contains("project root"),
        "{:?}",
        analysis.skipped_files
    );
}

#[test]
fn a_parse_failure_is_reported_as_a_skip_with_its_cause() {
    let directory = TempDir::new().unwrap();
    let mut skipped = BoundedDiagnostics::default();
    let file = discovered_entry(&directory, "broken.rs");
    let error = EngineError::ParseFailed {
        path: file.path.clone(),
        reason: "tree-sitter parse returned None".into(),
    };

    record_parse_failure(&mut skipped, &file, &error);

    let (entries, omitted) = skipped.into_sorted_entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(omitted, 0);
    assert!(entries[0].starts_with("broken.rs ("), "{entries:?}");
    assert!(
        entries[0].contains("tree-sitter parse returned None"),
        "{entries:?}"
    );
}

#[test]
fn signature_scan_parses_a_supported_language() {
    let scan = signature_scan(Path::new("a.rs"), "fn a() {}\n", Some("rust"));

    match scan {
        SignatureScan::Parsed(signatures) => assert!(!signatures.is_empty()),
        _ => panic!("rust sources must produce signatures"),
    }
}

#[test]
fn signature_scan_treats_an_unparsable_language_as_a_non_event() {
    assert!(matches!(
        signature_scan(Path::new("a.rb"), "def a; end\n", Some("ruby")),
        SignatureScan::Unsupported
    ));
    assert!(matches!(
        signature_scan(Path::new("data.bin"), "\u{0}", None),
        SignatureScan::Unsupported
    ));
}

#[test]
fn every_ast_language_is_analyzed_instead_of_skipped() {
    for language in AST_LANGUAGES {
        assert!(
            matches!(
                signature_scan(Path::new("sample"), "", Some(language)),
                SignatureScan::Parsed(_)
            ),
            "{language} did not reach signature extraction, so its files would be skipped"
        );
    }
}

fn scan_text_with_limit(
    content: &str,
    config: &AnalysisConfig,
    limit: usize,
    scan_signatures: fn(&Path, &str, Option<&str>) -> SignatureScan,
) -> Result<StaticAnalysis, EngineError> {
    scan_text_with_limits(
        content,
        config,
        ScanLimits {
            max_findings: limit,
            ..ScanLimits::default()
        },
        scan_signatures,
    )
}

fn scan_text_with_limits(
    content: &str,
    config: &AnalysisConfig,
    limits: ScanLimits,
    scan_signatures: fn(&Path, &str, Option<&str>) -> SignatureScan,
) -> Result<StaticAnalysis, EngineError> {
    let directory = TempDir::new().unwrap();
    fs::write(directory.path().join("sample.rs"), content).unwrap();
    let filesystem = filesystem_for(&directory);
    let files = [discovered_entry(&directory, "sample.rs")];
    scan_files_with(
        &create_engine(),
        DiscoveredSources {
            filesystem: &filesystem,
            files: &files,
            unreadable: &[],
        },
        config,
        &counter(),
        limits,
        scan_signatures,
    )
}

fn failing_signature_scan(path: &Path, _: &str, _: Option<&str>) -> SignatureScan {
    SignatureScan::Failed(EngineError::ParseFailed {
        path: path.to_path_buf(),
        reason: "forced parser failure".into(),
    })
}

fn unsupported_signature_scan(_: &Path, _: &str, _: Option<&str>) -> SignatureScan {
    SignatureScan::Unsupported
}
#[test]
fn invalid_secret_detector_patterns_return_typed_errors() {
    let error = match compile_secret_patterns_from(&[("(", "broken")]) {
        Ok(_) => panic!("invalid regex must be rejected"),
        Err(error) => error,
    };

    assert!(matches!(error, EngineError::InvalidPattern { pattern, .. } if pattern == "("));
}

#[test]
fn every_static_detector_propagates_the_finding_limit() {
    let mut quality = default_analysis_config();
    quality.categories = vec![AnalysisCategory::Quality];
    quality.quality.max_file_lines = 0;
    assert!(matches!(
        scan_text_with_limit("value\n", &quality, 0, signature_scan),
        Err(EngineError::FindingLimitExceeded { max_findings: 0 })
    ));

    quality.quality.max_file_lines = usize::MAX;
    quality.quality.max_function_lines = 0;
    assert!(matches!(
        scan_text_with_limit("fn long() {}\n", &quality, 0, signature_scan),
        Err(EngineError::FindingLimitExceeded { max_findings: 0 })
    ));

    quality.quality.max_function_lines = usize::MAX;
    assert!(matches!(
        scan_text_with_limit("// TODO: finish\n", &quality, 0, signature_scan),
        Err(EngineError::FindingLimitExceeded { max_findings: 0 })
    ));

    let mut vulnerability = default_analysis_config();
    vulnerability.categories = vec![AnalysisCategory::Vulnerability];
    assert!(matches!(
        scan_text_with_limit(
            "api_key = \"abcdef1234567890abcdef1234567890\"\n",
            &vulnerability,
            0,
            signature_scan,
        ),
        Err(EngineError::FindingLimitExceeded { max_findings: 0 })
    ));
}

#[test]
fn parser_failures_are_recorded_by_the_scan_pipeline() {
    let mut quality = default_analysis_config();
    quality.categories = vec![AnalysisCategory::Quality];
    quality.quality.max_file_lines = usize::MAX;
    quality.quality.max_function_lines = usize::MAX;

    let analysis =
        scan_text_with_limit("fn source() {}\n", &quality, 1, failing_signature_scan).unwrap();

    assert_eq!(analysis.files_scanned, 0);
    assert_eq!(analysis.skipped_files.len(), 1);
    assert!(analysis.skipped_files[0].contains("forced parser failure"));
}

#[test]
fn unsupported_signature_scans_leave_the_file_analyzed() {
    let mut quality = default_analysis_config();
    quality.categories = vec![AnalysisCategory::Quality];
    quality.quality.max_file_lines = usize::MAX;
    quality.quality.max_function_lines = usize::MAX;

    let analysis =
        scan_text_with_limit("fn source() {}\n", &quality, 1, unsupported_signature_scan).unwrap();

    assert_eq!(analysis.files_scanned, 1);
    assert!(analysis.skipped_files.is_empty());
    assert!(analysis.findings.is_empty());
}

#[test]
fn static_analysis_reports_an_invalid_project_root_as_io() {
    let directory = TempDir::new().unwrap();
    let missing = directory.path().join("missing");

    let error = match run_static_checks(
        &create_engine(),
        &missing,
        &default_analysis_config(),
        &counter(),
    ) {
        Ok(_) => panic!("an invalid project root must fail"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        EngineError::Io { path, .. } if path == missing
    ));
}

#[test]
fn signature_scan_preserves_parser_failures() {
    let path = Path::new("source.rs");
    let scan = signature_scan_with(path, "fn source() {}", Some("rust"), |path, _, _| {
        Err(EngineError::ParseFailed {
            path: path.to_path_buf(),
            reason: "parser failed".into(),
        })
    });

    assert!(matches!(
        scan,
        SignatureScan::Failed(EngineError::ParseFailed { reason, .. })
            if reason == "parser failed"
    ));
}

#[test]
fn the_retained_finding_bytes_are_capped_before_the_finding_is_stored() {
    let mut quality = default_analysis_config();
    quality.categories = vec![AnalysisCategory::Quality];
    quality.quality.max_file_lines = 0;
    quality.quality.max_function_lines = usize::MAX;

    let error = scan_text_with_limits(
        "value\n",
        &quality,
        ScanLimits {
            max_finding_bytes: 8,
            ..ScanLimits::default()
        },
        signature_scan,
    )
    .unwrap_err();

    assert!(matches!(
        error,
        EngineError::FindingBytesExceeded { max_bytes: 8 }
    ));
}

#[test]
fn the_retained_byte_budget_admits_the_exact_fit_and_rejects_one_byte_more() {
    let finding = Finding::new_static(
        &counter(),
        AnalysisCategory::Quality,
        Severity::Low,
        "title".into(),
        "described".into(),
        "src/a.rs".into(),
    );
    let exact = finding.retained_bytes();
    let mut fits = BoundedFindings::new(10, exact);
    let mut one_byte_short = BoundedFindings::new(10, exact - 1);

    fits.push(finding.clone()).unwrap();
    let error = one_byte_short.push(finding).unwrap_err();

    assert_eq!(fits.values.len(), 1);
    assert!(matches!(
        error,
        EngineError::FindingBytesExceeded { max_bytes } if max_bytes == exact - 1
    ));
    assert!(one_byte_short.values.is_empty());
}

#[test]
fn a_huge_todo_comment_is_truncated_on_a_character_boundary_with_a_marker() {
    let mut quality = default_analysis_config();
    quality.categories = vec![AnalysisCategory::Quality];
    quality.quality.max_file_lines = usize::MAX;
    quality.quality.max_function_lines = usize::MAX;
    let comment = format!("// TODO: {}\n", "é".repeat(MAX_TODO_SNIPPET_BYTES));

    let analysis = scan_text_with_limit(&comment, &quality, 10, signature_scan).unwrap();

    let snippet = analysis.findings[0]
        .code_snippet
        .as_deref()
        .expect("the todo finding keeps a snippet");
    assert!(
        snippet.len() <= MAX_TODO_SNIPPET_BYTES,
        "snippet kept {} bytes",
        snippet.len()
    );
    assert!(snippet.ends_with("…[truncated]"), "the cut must be visible");
    assert!(snippet.starts_with("// TODO: é"));
}

#[test]
fn a_todo_comment_within_the_snippet_budget_is_kept_verbatim() {
    let mut quality = default_analysis_config();
    quality.categories = vec![AnalysisCategory::Quality];
    quality.quality.max_file_lines = usize::MAX;
    quality.quality.max_function_lines = usize::MAX;

    let analysis = scan_text_with_limit("// FIXME: small\n", &quality, 10, signature_scan).unwrap();

    assert_eq!(
        analysis.findings[0].code_snippet.as_deref(),
        Some("// FIXME: small")
    );
}

#[test]
fn skipped_diagnostics_are_bounded_sorted_and_counted() {
    let directory = TempDir::new().unwrap();
    fs::write(directory.path().join("present.rs"), "fn a() {}\n").unwrap();
    let unreadable: Vec<UnreadableFile> = ["z.rs", "a.rs", "m.rs"]
        .iter()
        .map(|path| UnreadableFile {
            relative_path: (*path).to_string(),
            reason: "permission denied".to_string(),
        })
        .collect();
    let files = [discovered_entry(&directory, "present.rs")];

    let analysis = scan_files_with(
        &create_engine(),
        DiscoveredSources {
            filesystem: &filesystem_for(&directory),
            files: &files,
            unreadable: &unreadable,
        },
        &default_analysis_config(),
        &counter(),
        ScanLimits {
            max_diagnostics: 2,
            ..ScanLimits::default()
        },
        signature_scan,
    )
    .unwrap();

    assert_eq!(
        analysis.skipped_files,
        vec![
            "a.rs (permission denied)".to_string(),
            "z.rs (permission denied)".to_string()
        ],
        "the retained diagnostics must stay sorted"
    );
    assert_eq!(analysis.omitted_skipped_files, 1);
    assert_eq!(analysis.files_scanned, 1);
}

#[test]
fn skipped_diagnostics_stop_at_the_byte_budget() {
    let directory = TempDir::new().unwrap();
    let unreadable: Vec<UnreadableFile> = ["a.rs", "b.rs", "c.rs"]
        .iter()
        .map(|path| UnreadableFile {
            relative_path: (*path).to_string(),
            reason: "gone".to_string(),
        })
        .collect();
    let entry_bytes = unreadable[0].report_entry().len();

    let analysis = scan_files_with(
        &create_engine(),
        DiscoveredSources {
            filesystem: &filesystem_for(&directory),
            files: &[],
            unreadable: &unreadable,
        },
        &default_analysis_config(),
        &counter(),
        ScanLimits {
            max_diagnostic_bytes: entry_bytes * 2,
            ..ScanLimits::default()
        },
        signature_scan,
    )
    .unwrap();

    assert_eq!(analysis.skipped_files.len(), 2);
    assert_eq!(analysis.omitted_skipped_files, 1);
}

#[test]
fn secret_line_numbers_survive_newline_dense_content() {
    let mut vulnerability = default_analysis_config();
    vulnerability.categories = vec![AnalysisCategory::Vulnerability];
    let content = format!(
        "{}api_key = \"abcdef1234567890abcdef1234567890\"\n\n\napi_key = \"0fedcba9876543210fedcba987654321\"\n",
        "\n".repeat(64)
    );

    let analysis = scan_text_with_limit(&content, &vulnerability, 10, signature_scan).unwrap();

    let lines: Vec<(Option<u32>, Option<u32>)> = analysis
        .findings
        .iter()
        .map(|finding| (finding.line_start, finding.line_end))
        .collect();
    assert_eq!(lines, vec![(Some(65), Some(65)), (Some(68), Some(68))]);
}

#[test]
fn secret_line_numbers_match_a_precomputed_line_index() {
    let content = "a\n\nbc\nd";
    let mut lines = AscendingLines::new(content);

    let observed: Vec<u32> = (0..content.len()).map(|at| lines.line_at(at)).collect();

    assert_eq!(observed, vec![1, 1, 2, 3, 3, 3, 4]);
}

#[test]
fn a_huge_secret_value_is_reported_without_lowercasing_a_copy() {
    let mut vulnerability = default_analysis_config();
    vulnerability.categories = vec![AnalysisCategory::Vulnerability];
    let value: String = std::iter::repeat_n("aBcD9_zY", 32 * 1024).collect();
    let content = format!("password = \"{value}\"\n");

    let analysis = scan_text_with_limit(&content, &vulnerability, 10, signature_scan).unwrap();

    assert_eq!(analysis.findings.len(), 1);
    assert_eq!(analysis.findings[0].line_start, Some(1));
    assert!(
        analysis.findings[0].retained_bytes() < 1024,
        "the secret value must never be retained in the finding"
    );
}

#[test]
fn placeholder_detection_ignores_case_without_allocating_a_copy() {
    assert!(is_placeholder_secret("YOUR_API_KEY_HERE"));
    assert!(is_placeholder_secret("ChangeMe-Please-1234"));
    assert!(is_placeholder_secret("${SECRET_FROM_VAULT}"));
    assert!(is_placeholder_secret("PASSWORD"));
    assert!(is_placeholder_secret("aaaaaaaaaaaaaaaa"));
    assert!(!is_placeholder_secret("aBcD9_zY-qW3rT7pL"));
}

#[test]
fn a_case_insensitive_marker_search_matches_only_real_occurrences() {
    assert!(contains_ignoring_ascii_case("xxDUMMYxx", "dummy"));
    assert!(!contains_ignoring_ascii_case("dumm", "dummy"));
    assert!(!contains_ignoring_ascii_case("", "dummy"));
}
