use std::path::{Path, PathBuf};

use clap::Parser;
use tempfile::TempDir;

use super::analyze::{
    apply_cli_overrides, discovery_source, exit_code_for_result, interactive_progress_enabled,
    write_report_line,
};
use super::commands::{AnalyzeArgs, ConfidenceArg, InitArgs, OutputFormatArg, SeverityArg};
use super::init::{DEFAULT_CONFIG_TEMPLATE, run as run_init};
use super::logging::directive;
use super::{Cli, Command};
use crate::config::schema::{
    AnalysisMode, Confidence, Config, DiscoverySource, LogLevel, OutputFormat, Severity,
};
use crate::errors::{self, BugHunterError};
use crate::orchestrator;
use crate::report::{FailedShard, ScanCompleteness, ScanStatus};

fn analyze_args() -> AnalyzeArgs {
    AnalyzeArgs {
        project: ".".into(),
        format: None,
        output: None,
        fail_severity: None,
        no_fail: false,
        static_only: false,
        ai_only: false,
        with_ai: false,
        categories: None,
        config: None,
        min_confidence: None,
        verbose: false,
        no_progress: false,
        allow_partial: false,
        pr: None,
        repo: None,
    }
}

#[test]
fn with_ai_flag_selects_full_mode() {
    let cli = Cli::try_parse_from(["bughunter", "analyze", "--with-ai"]).unwrap();
    let Command::Analyze(args) = cli.command else {
        panic!("analyze subcommand expected");
    };
    assert_eq!(args.analysis_mode(), AnalysisMode::Full);
}

fn analysis_result(
    has_findings_above_threshold: bool,
    scan: ScanStatus,
) -> orchestrator::AnalysisResult {
    orchestrator::AnalysisResult {
        findings: Vec::new(),
        output: String::new(),
        has_findings_above_threshold,
        scan,
    }
}

fn partial_scan() -> ScanStatus {
    ScanStatus {
        completeness: ScanCompleteness::Partial,
        shards_total: 3,
        shards_completed: 2,
        failed_shards: vec![FailedShard {
            shard: 3,
            error: "engine overloaded".into(),
        }],
        files_presented: 9,
        files_inspected: 4,
        uninspected_files: vec!["src/a.rs".into()],
        skipped_files: Vec::new(),
        omitted_diagnostics: 0,
    }
}

#[test]
fn complete_scan_without_findings_exits_successfully() {
    let result = analysis_result(false, ScanStatus::complete(3));
    assert_eq!(
        exit_code_for_result(&result, &analyze_args()),
        errors::EXIT_SUCCESS
    );
}

#[test]
fn complete_scan_with_findings_exits_with_the_findings_code() {
    let result = analysis_result(true, ScanStatus::complete(3));
    assert_eq!(
        exit_code_for_result(&result, &analyze_args()),
        errors::EXIT_FINDINGS
    );
}

#[test]
fn partial_scan_exits_with_the_partial_code() {
    let result = analysis_result(false, partial_scan());
    assert_eq!(
        exit_code_for_result(&result, &analyze_args()),
        errors::EXIT_PARTIAL
    );
}

#[test]
fn partial_scan_takes_precedence_over_findings() {
    let result = analysis_result(true, partial_scan());
    assert_eq!(
        exit_code_for_result(&result, &analyze_args()),
        errors::EXIT_PARTIAL,
        "an incomplete scan is reported before the findings threshold"
    );
}

#[test]
fn allow_partial_falls_back_to_the_normal_exit_policy() {
    let args = AnalyzeArgs {
        allow_partial: true,
        ..analyze_args()
    };
    assert_eq!(
        exit_code_for_result(&analysis_result(false, partial_scan()), &args),
        errors::EXIT_SUCCESS
    );
    assert_eq!(
        exit_code_for_result(&analysis_result(true, partial_scan()), &args),
        errors::EXIT_FINDINGS
    );
}

#[test]
fn no_fail_suppresses_only_the_findings_code() {
    let args = AnalyzeArgs {
        no_fail: true,
        ..analyze_args()
    };
    let complete = analysis_result(true, ScanStatus::complete(3));
    assert_eq!(exit_code_for_result(&complete, &args), errors::EXIT_SUCCESS);
    assert_eq!(
        exit_code_for_result(&analysis_result(true, partial_scan()), &args),
        errors::EXIT_PARTIAL,
        "--no-fail does not hide an incomplete scan"
    );
}

#[test]
fn init_creates_default_config_file() {
    let directory = TempDir::new().unwrap();
    let args = InitArgs {
        project: Some(directory.path().to_path_buf()),
    };
    let code = run_init(&args).unwrap();
    assert_eq!(code, errors::EXIT_SUCCESS);
    let written = std::fs::read_to_string(directory.path().join(".bughunter.toml")).unwrap();
    assert!(written.contains("[llm]"));
    assert!(written.contains("min_confidence"));
}

#[test]
fn init_refuses_to_overwrite_existing_config() {
    let directory = TempDir::new().unwrap();
    std::fs::write(directory.path().join(".bughunter.toml"), "[llm]\n").unwrap();
    let args = InitArgs {
        project: Some(directory.path().to_path_buf()),
    };
    let result = run_init(&args);
    assert!(matches!(result, Err(BugHunterError::Config(_))));
}

#[test]
fn init_template_is_valid_toml() {
    assert!(toml::from_str::<toml::Value>(DEFAULT_CONFIG_TEMPLATE).is_ok());
}

#[test]
fn unset_flags_leave_config_values_alone() {
    let mut config = Config::default();
    config.general.output_format = OutputFormat::Md;
    config.general.fail_severity = Severity::Critical;
    config.general.min_confidence = Confidence::High;
    apply_cli_overrides(&mut config, &analyze_args());
    assert_eq!(config.general.output_format, OutputFormat::Md);
    assert_eq!(config.general.fail_severity, Severity::Critical);
    assert_eq!(config.general.min_confidence, Confidence::High);
}

#[test]
fn passed_flags_override_config_values() {
    let mut config = Config::default();
    let args = AnalyzeArgs {
        format: Some(OutputFormatArg::Md),
        fail_severity: Some(SeverityArg::Low),
        min_confidence: Some(ConfidenceArg::High),
        ..analyze_args()
    };
    apply_cli_overrides(&mut config, &args);
    assert_eq!(config.general.output_format, OutputFormat::Md);
    assert_eq!(config.general.fail_severity, Severity::Low);
    assert_eq!(config.general.min_confidence, Confidence::High);
}

#[test]
fn interactive_progress_requires_a_human_terminal_session() {
    assert!(interactive_progress_enabled(
        AnalysisMode::Full,
        false,
        false,
        true,
        true,
        true,
        false
    ));
    assert!(interactive_progress_enabled(
        AnalysisMode::AiOnly,
        false,
        false,
        true,
        false,
        true,
        true
    ));
    for disabled in [
        interactive_progress_enabled(AnalysisMode::Static, false, false, true, true, true, false),
        interactive_progress_enabled(AnalysisMode::Full, true, false, true, true, true, false),
        interactive_progress_enabled(AnalysisMode::Full, false, true, true, true, true, false),
        interactive_progress_enabled(AnalysisMode::Full, false, false, false, true, true, false),
        interactive_progress_enabled(AnalysisMode::Full, false, false, true, false, true, false),
        interactive_progress_enabled(AnalysisMode::Full, false, false, true, true, false, false),
    ] {
        assert!(!disabled);
    }
}

#[test]
fn log_directive_scopes_dependencies_to_warn() {
    assert_eq!(directive(false, &LogLevel::Info), "warn,bughunter=info");
    assert_eq!(directive(false, &LogLevel::Error), "warn,bughunter=error");
    assert_eq!(directive(true, &LogLevel::Error), "warn,bughunter=debug");
}

#[test]
fn report_stream_receives_every_byte_and_one_trailing_newline() {
    let mut unterminated = Vec::new();
    write_report_line(&mut unterminated, "{\"findings\":[]}").unwrap();

    let mut terminated = Vec::new();
    write_report_line(&mut terminated, "{\"findings\":[]}\n").unwrap();

    assert_eq!(
        String::from_utf8(unterminated).unwrap(),
        "{\"findings\":[]}\n"
    );
    assert_eq!(
        String::from_utf8(terminated).unwrap(),
        "{\"findings\":[]}\n"
    );
}

#[test]
fn report_stream_write_failures_reach_the_caller() {
    struct ClosedPipe;

    impl std::io::Write for ClosedPipe {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "reader closed",
            ))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let error = write_report_line(&mut ClosedPipe, "report").unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
}

#[test]
fn report_stream_flush_failures_reach_the_caller() {
    struct UnflushableStream {
        written: Vec<u8>,
    }

    impl std::io::Write for UnflushableStream {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("device full"))
        }
    }

    let mut stream = UnflushableStream {
        written: Vec::new(),
    };
    let error = write_report_line(&mut stream, "report").unwrap_err();

    assert_eq!(error.to_string(), "device full");
    assert_eq!(String::from_utf8(stream.written).unwrap(), "report\n");
}

#[test]
fn only_pull_request_runs_treat_the_project_as_an_untrusted_snapshot() {
    let mut args = analyze_args();
    assert_eq!(discovery_source(&args), DiscoverySource::LocalCheckout);

    args.pr = Some(18);

    assert_eq!(discovery_source(&args), DiscoverySource::UntrustedSnapshot);
}

#[test]
fn doctor_defaults_to_the_current_directory_without_a_config_override() {
    let cli = Cli::try_parse_from(["bughunter", "doctor"]).unwrap();
    let Command::Doctor(args) = cli.command else {
        panic!("doctor subcommand expected");
    };

    assert_eq!(args.project, PathBuf::from("."));
    assert!(args.config.is_none());
}

#[test]
fn doctor_accepts_a_project_directory_and_a_config_file() {
    let cli = Cli::try_parse_from([
        "bughunter",
        "doctor",
        "--project",
        "/tmp/project",
        "--config",
        "/tmp/project/custom.toml",
    ])
    .unwrap();
    let Command::Doctor(args) = cli.command else {
        panic!("doctor subcommand expected");
    };

    assert_eq!(args.project, PathBuf::from("/tmp/project"));
    assert_eq!(
        args.config.as_deref(),
        Some(Path::new("/tmp/project/custom.toml"))
    );
}
