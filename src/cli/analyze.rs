use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use super::commands::AnalyzeArgs;
use super::{logging, output, project};
use crate::config;
use crate::config::schema::{AnalysisMode, DiscoverySource};
use crate::domain::ProjectRoot;
use crate::errors::{self, AnalysisError, BugHunterError, ReportError};
use crate::orchestrator;
use crate::review::{ReviewError, ReviewSession};
use crate::tui::{SharedState, replay_logs_to_stderr, shared_state};

const MAX_STATUS_LINE_BYTES: usize = 4 * 1024;
const OMISSION_SUFFIX_BYTES: usize = 32;
const SKIPPED_FILES_PREFIX: &str = "skipped files:";

struct PreparedAnalysis {
    project_root: ProjectRoot,
    backend_working_directory: ProjectRoot,
    config: config::ValidatedConfig,
    review_session: Option<ReviewSession>,
}

pub(super) fn run(args: &AnalyzeArgs) -> Result<i32, BugHunterError> {
    let state = shared_state();
    let mode = args.analysis_mode();
    let (local_checkout, config) = prepare_configuration(args, mode)?;
    let use_tui = interactive_progress_enabled(
        mode,
        args.no_progress,
        std::env::var_os("CI").is_some(),
        std::io::stdin().is_terminal(),
        std::io::stdout().is_terminal(),
        std::io::stderr().is_terminal(),
        config.general.output_path.is_some(),
    );
    logging::init(
        args.verbose,
        use_tui,
        state.clone(),
        &config.general.log_level,
    );

    if args.pr.is_none() && !mode.requires_ai() {
        let prepared = finish_preparation(args, config, local_checkout)?;
        let result = run_with_log_replay(&prepared, &state, use_tui);
        return report_result(args, &prepared, &state, use_tui, result);
    }

    let runtime = map_runtime_result(tokio::runtime::Runtime::new())?;
    let cancel = crate::cancel::CancelToken::default();
    runtime.block_on(async { spawn_cancel_on_signals(cancel.clone()) });

    let prepared =
        match finish_preparation_cancellable(&runtime, args, config, local_checkout, &cancel) {
            Ok(prepared) => prepared,
            Err(error) => {
                replay_buffered_logs(use_tui, &state);
                runtime.shutdown_background();
                return Err(error);
            }
        };
    let result = run_with_log_replay_cancellable(&runtime, &prepared, &state, use_tui, &cancel);
    runtime.shutdown_background();
    report_result(args, &prepared, &state, use_tui, result)
}

fn replay_buffered_logs(use_tui: bool, state: &SharedState) {
    if use_tui {
        let _ = replay_logs_to_stderr(state);
    }
}

fn report_result(
    args: &AnalyzeArgs,
    prepared: &PreparedAnalysis,
    state: &SharedState,
    use_tui: bool,
    result: Result<orchestrator::AnalysisResult, BugHunterError>,
) -> Result<i32, BugHunterError> {
    let result = result?;
    let output_path = prepared.config.general.output_path.as_deref();
    write_output(&result.output, output_path).inspect_err(|_| {
        replay_buffered_logs(use_tui, state);
    })?;
    report_written_findings(output_path, result.findings.len());

    if result.scan.is_partial() {
        report_partial_coverage(&result.scan);
    }

    Ok(exit_code_for_result(&result, args))
}

pub(super) fn interactive_progress_enabled(
    mode: AnalysisMode,
    disabled: bool,
    continuous_integration: bool,
    stdin_is_terminal: bool,
    stdout_is_terminal: bool,
    stderr_is_terminal: bool,
    writes_report_to_file: bool,
) -> bool {
    mode.requires_ai()
        && !disabled
        && !continuous_integration
        && stdin_is_terminal
        && stderr_is_terminal
        && (stdout_is_terminal || writes_report_to_file)
}

pub(super) fn exit_code_for_result(
    result: &orchestrator::AnalysisResult,
    args: &AnalyzeArgs,
) -> i32 {
    if result.scan.is_partial() && !args.allow_partial {
        return errors::EXIT_PARTIAL;
    }
    if result.has_findings_above_threshold && !args.no_fail {
        return errors::EXIT_FINDINGS;
    }
    errors::EXIT_SUCCESS
}

fn report_partial_coverage(scan: &crate::report::ScanStatus) {
    for line in partial_coverage_status(scan) {
        output::print_status(&line);
    }
}

fn partial_coverage_status(scan: &crate::report::ScanStatus) -> Vec<String> {
    let mut lines = vec![format!(
        "partial AI coverage: {}/{} shards completed, {}/{} files inspected",
        scan.shards_completed, scan.shards_total, scan.files_inspected, scan.files_presented
    )];
    if !scan.skipped_files.is_empty() || scan.omitted_diagnostics > 0 {
        lines.push(skipped_files_status(
            &scan.skipped_files,
            scan.omitted_diagnostics,
            MAX_STATUS_LINE_BYTES,
        ));
    }
    lines
}

fn skipped_files_status(skipped_files: &[String], omitted: u32, limit_bytes: usize) -> String {
    let budget = limit_bytes.saturating_sub(OMISSION_SUFFIX_BYTES);
    let mut line = String::from(SKIPPED_FILES_PREFIX);
    let mut listed = 0;
    for entry in skipped_files {
        let separator = if listed == 0 { " " } else { ", " };
        if line.len() + separator.len() + entry.len() > budget {
            break;
        }
        line.push_str(separator);
        line.push_str(entry);
        listed += 1;
    }
    let unlisted = skipped_files
        .len()
        .saturating_sub(listed)
        .saturating_add(omitted as usize);
    if unlisted > 0 {
        line.push_str(&format!(" (+{unlisted} not shown)"));
    }
    line
}

fn run_with_log_replay(
    prepared: &PreparedAnalysis,
    state: &SharedState,
    use_tui: bool,
) -> Result<orchestrator::AnalysisResult, BugHunterError> {
    execute_static(prepared).inspect_err(|_| replay_buffered_logs(use_tui, state))
}

fn run_with_log_replay_cancellable(
    runtime: &tokio::runtime::Runtime,
    prepared: &PreparedAnalysis,
    state: &SharedState,
    use_tui: bool,
    cancel: &crate::cancel::CancelToken,
) -> Result<orchestrator::AnalysisResult, BugHunterError> {
    execute_cancellable(runtime, prepared, state.clone(), use_tui, cancel)
        .inspect_err(|_| replay_buffered_logs(use_tui, state))
}

#[cfg(test)]
fn prepare(args: &AnalyzeArgs, mode: AnalysisMode) -> Result<PreparedAnalysis, BugHunterError> {
    let (local_checkout, config) = prepare_configuration(args, mode)?;
    finish_preparation(args, config, local_checkout)
}

fn prepare_configuration(
    args: &AnalyzeArgs,
    mode: AnalysisMode,
) -> Result<(ProjectRoot, config::ValidatedConfig), BugHunterError> {
    let trusted = project::open(&args.project, args.config.as_deref())?;
    let config = validate_with_cli_overrides(trusted.config, args, mode)?;
    Ok((trusted.root, config))
}

fn finish_preparation(
    args: &AnalyzeArgs,
    config: config::ValidatedConfig,
    local_checkout: ProjectRoot,
) -> Result<PreparedAnalysis, BugHunterError> {
    match args.pr {
        Some(pull_request) => {
            prepare_pull_request_review(args.repo.clone(), config, &local_checkout, pull_request)
        }
        None => Ok(PreparedAnalysis {
            project_root: local_checkout.clone(),
            backend_working_directory: local_checkout,
            config,
            review_session: None,
        }),
    }
}

fn finish_preparation_cancellable(
    runtime: &tokio::runtime::Runtime,
    args: &AnalyzeArgs,
    config: config::ValidatedConfig,
    local_checkout: ProjectRoot,
    cancel: &crate::cancel::CancelToken,
) -> Result<PreparedAnalysis, BugHunterError> {
    let Some(pull_request) = args.pr else {
        return finish_preparation(args, config, local_checkout);
    };
    let repository = args.repo.clone();
    let cancel = cancel.clone();
    runtime.block_on(async move {
        let blocking = tokio::task::spawn_blocking(move || {
            prepare_pull_request_review(repository, config, &local_checkout, pull_request)
        });
        race_worker(cancel, "prepare pull request review", blocking).await
    })
}

async fn race_worker<T>(
    cancel: crate::cancel::CancelToken,
    action: &'static str,
    blocking: tokio::task::JoinHandle<Result<T, BugHunterError>>,
) -> Result<T, BugHunterError> {
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(BugHunterError::Cancelled),
        outcome = blocking => match outcome {
            Ok(result) => result,
            Err(error) => Err(worker_failed(action, error)),
        },
    }
}

fn worker_failed(action: &'static str, error: tokio::task::JoinError) -> BugHunterError {
    AnalysisError::WorkerFailed {
        action,
        reason: error.to_string(),
    }
    .into()
}

fn validate_with_cli_overrides(
    mut config: config::schema::Config,
    args: &AnalyzeArgs,
    mode: AnalysisMode,
) -> Result<config::ValidatedConfig, BugHunterError> {
    apply_cli_overrides(&mut config, args);
    config.engine.discovery_source = discovery_source(args);
    Ok(config::ValidatedConfig::new(config, mode)?)
}

pub(super) fn discovery_source(args: &AnalyzeArgs) -> DiscoverySource {
    match args.pr {
        Some(_) => DiscoverySource::UntrustedSnapshot,
        None => DiscoverySource::LocalCheckout,
    }
}

fn prepare_pull_request_review(
    repository: Option<String>,
    config: config::ValidatedConfig,
    local_checkout: &ProjectRoot,
    pull_request: u64,
) -> Result<PreparedAnalysis, BugHunterError> {
    let mut session = crate::review::prepare_pr_review(
        local_checkout.as_path(),
        pull_request,
        repository.as_deref(),
    )?;
    let project_root = ProjectRoot::open(&session.project_root)?;
    let snapshot_coverage = apply_snapshot_coverage(
        &mut session.scope,
        &project_root,
        &config.engine,
        pull_request,
    );
    snapshot_coverage?;

    Ok(PreparedAnalysis {
        backend_working_directory: local_checkout.clone(),
        project_root,
        config,
        review_session: Some(session),
    })
}

fn apply_snapshot_coverage(
    scope: &mut crate::review::ReviewScope,
    project_root: &ProjectRoot,
    engine: &crate::config::EngineConfig,
    pull_request: u64,
) -> Result<(), BugHunterError> {
    let changed_files = scope.changed_files();
    let coverage =
        crate::review::classify_changed_files(project_root.as_path(), engine, &changed_files);
    apply_changed_file_coverage(scope, pull_request, coverage)
}

fn apply_changed_file_coverage(
    scope: &mut crate::review::ReviewScope,
    pull_request: u64,
    result: Result<crate::review::ChangedFileCoverage, ReviewError>,
) -> Result<(), BugHunterError> {
    let coverage = result?;
    if coverage.inspectable.is_empty() {
        return Err(ReviewError::NoChangedFiles(pull_request).into());
    }
    report_skipped_changed_files(&coverage);
    scope.set_changed_file_coverage(coverage)?;
    Ok(())
}

fn report_skipped_changed_files(coverage: &crate::review::ChangedFileCoverage) {
    if !coverage.is_partial() {
        return;
    }
    output::print_status(&format!(
        "changed files outside the analysable snapshot: {}",
        coverage.skipped_report_entries().join(", ")
    ));
}

fn execute_static(
    prepared: &PreparedAnalysis,
) -> Result<orchestrator::AnalysisResult, BugHunterError> {
    orchestrator::run_static_analysis(prepared.project_root.as_path(), &prepared.config)
}

fn execute_cancellable(
    runtime: &tokio::runtime::Runtime,
    prepared: &PreparedAnalysis,
    state: SharedState,
    use_tui: bool,
    cancel: &crate::cancel::CancelToken,
) -> Result<orchestrator::AnalysisResult, BugHunterError> {
    if prepared.config.mode() == AnalysisMode::Static {
        let project_root = prepared.project_root.as_path().to_path_buf();
        let config = prepared.config.clone();
        let cancel = cancel.clone();
        return runtime.block_on(async move {
            let blocking = tokio::task::spawn_blocking(move || {
                orchestrator::run_static_analysis(&project_root, &config)
            });
            race_worker(cancel, "run static analysis", blocking).await
        });
    }

    runtime.block_on(orchestrator::run_analysis(
        prepared.project_root.as_path(),
        Some(prepared.backend_working_directory.as_path()),
        &prepared.config,
        state,
        use_tui,
        prepared
            .review_session
            .as_ref()
            .map(|session| &session.scope),
        cancel.clone(),
    ))
}

fn map_runtime_result<T>(result: std::io::Result<T>) -> Result<T, BugHunterError> {
    result.map_err(|error| {
        AnalysisError::StaticCheckFailed(format!("failed to start async runtime: {error}")).into()
    })
}

trait CancelTrigger {
    async fn wait(&mut self) -> bool;
}

struct InterruptTrigger;

impl CancelTrigger for InterruptTrigger {
    async fn wait(&mut self) -> bool {
        tokio::signal::ctrl_c().await.is_ok()
    }
}

#[cfg(unix)]
struct UnixSignalTrigger(tokio::signal::unix::Signal);

#[cfg(unix)]
impl CancelTrigger for UnixSignalTrigger {
    async fn wait(&mut self) -> bool {
        self.0.recv().await.is_some()
    }
}

fn spawn_cancel_on_signals(cancel: crate::cancel::CancelToken) {
    tokio::spawn(cancel_while_triggered(InterruptTrigger, cancel.clone()));

    #[cfg(unix)]
    {
        spawn_cancel_on_unix_signal(cancel.clone(), tokio::signal::unix::SignalKind::terminate());
        spawn_cancel_on_unix_signal(cancel, tokio::signal::unix::SignalKind::hangup());
    }
}

async fn cancel_while_triggered(
    mut trigger: impl CancelTrigger,
    cancel: crate::cancel::CancelToken,
) {
    while trigger.wait().await {
        cancel.cancel();
    }
}

#[cfg(unix)]
fn spawn_cancel_on_unix_signal(
    cancel: crate::cancel::CancelToken,
    kind: tokio::signal::unix::SignalKind,
) {
    if let Ok(signals) = tokio::signal::unix::signal(kind) {
        tokio::spawn(cancel_while_triggered(UnixSignalTrigger(signals), cancel));
    }
}

fn report_written_findings(path: Option<&Path>, findings: usize) {
    if let Some(path) = path {
        output::print_status(&format!(
            "{findings} findings written to {}",
            path.display()
        ));
    }
}

pub(super) fn apply_cli_overrides(config: &mut config::schema::Config, args: &AnalyzeArgs) {
    if let Some(format) = &args.format {
        config.general.output_format = format.clone().into();
    }
    if let Some(output_path) = &args.output {
        config.general.output_path = Some(output_path.clone());
    }
    if let Some(fail_severity) = &args.fail_severity {
        config.general.fail_severity = fail_severity.clone().into();
    }
    if let Some(min_confidence) = &args.min_confidence {
        config.general.min_confidence = min_confidence.clone().into();
    }
    if let Some(categories) = &args.categories {
        config.analysis.categories = categories.iter().cloned().map(Into::into).collect();
    }
}

fn write_output(output: &str, path: Option<&Path>) -> Result<(), BugHunterError> {
    match path {
        Some(file_path) => crate::shared::atomic_write(file_path, output.as_bytes())
            .map_err(|source| report_write_error(file_path.to_path_buf(), source)),
        None => {
            let stdout = std::io::stdout();
            let mut stream = stdout.lock();
            write_report_line(&mut stream, output).map_err(stdout_report_error)
        }
    }
}

pub(super) fn write_report_line(
    stream: &mut impl Write,
    output: &str,
) -> Result<(), std::io::Error> {
    stream.write_all(output.as_bytes())?;
    if !output.ends_with('\n') {
        stream.write_all(b"\n")?;
    }
    stream.flush()
}

fn stdout_report_error(source: std::io::Error) -> BugHunterError {
    report_write_error(PathBuf::from("stdout"), source)
}

fn report_write_error(path: PathBuf, source: std::io::Error) -> BugHunterError {
    ReportError::WriteError { path, source }.into()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    use crate::cli::commands::CategoryArg;
    use crate::config::schema::AnalysisCategory;
    use crate::errors::ConfigError;

    fn analyze_args(project: &Path) -> AnalyzeArgs {
        AnalyzeArgs {
            project: project.to_path_buf(),
            format: None,
            output: None,
            fail_severity: None,
            no_fail: false,
            allow_partial: false,
            static_only: false,
            ai_only: false,
            with_ai: false,
            categories: None,
            config: None,
            min_confidence: None,
            verbose: false,
            no_progress: false,
            pr: None,
            repo: None,
        }
    }

    fn static_analysis_of(project: &Path) -> PreparedAnalysis {
        PreparedAnalysis {
            project_root: ProjectRoot::open(project).unwrap(),
            backend_working_directory: ProjectRoot::open(project).unwrap(),
            config: config::ValidatedConfig::new(
                config::schema::Config::default(),
                AnalysisMode::Static,
            )
            .unwrap(),
            review_session: None,
        }
    }

    fn review_scope(hunks: BTreeMap<String, Vec<(u32, u32)>>) -> crate::review::ReviewScope {
        crate::review::ReviewScope::new(
            7,
            "main".to_string(),
            Some("0123456789abcdef".to_string()),
            hunks,
            String::new(),
        )
        .unwrap()
    }

    #[test]
    fn a_cancelled_pull_request_preparation_stops_before_the_network() {
        let project = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let cancel = crate::cancel::CancelToken::default();
        cancel.cancel();
        let mut args = analyze_args(project.path());
        args.pr = Some(7);
        let config =
            config::ValidatedConfig::new(config::schema::Config::default(), AnalysisMode::Static)
                .unwrap();
        let local_checkout = ProjectRoot::open(project.path()).unwrap();

        let error =
            finish_preparation_cancellable(&runtime, &args, config, local_checkout, &cancel)
                .err()
                .expect("a cancelled preparation must not proceed");

        assert!(matches!(error, BugHunterError::Cancelled));
    }

    #[test]
    fn cancellable_preparation_without_a_pull_request_matches_the_plain_path() {
        let project = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let args = analyze_args(project.path());
        let config =
            config::ValidatedConfig::new(config::schema::Config::default(), AnalysisMode::Static)
                .unwrap();
        let local_checkout = ProjectRoot::open(project.path()).unwrap();
        let expected_root = local_checkout.as_path().to_path_buf();

        let prepared = finish_preparation_cancellable(
            &runtime,
            &args,
            config,
            local_checkout,
            &crate::cancel::CancelToken::default(),
        )
        .unwrap();

        assert!(prepared.review_session.is_none());
        assert_eq!(prepared.project_root.as_path(), expected_root);
    }

    #[test]
    fn a_cancelled_static_run_on_the_async_path_is_interrupted() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join("main.py"),
            "def main():\n    return 1\n",
        )
        .unwrap();
        let prepared = static_analysis_of(project.path());
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let cancel = crate::cancel::CancelToken::default();
        cancel.cancel();

        let error =
            execute_cancellable(&runtime, &prepared, shared_state(), false, &cancel).unwrap_err();

        assert!(matches!(error, BugHunterError::Cancelled));
    }

    #[test]
    fn changed_file_coverage_errors_and_empty_sets_are_rejected() {
        let mut scope = review_scope(BTreeMap::new());
        let error = apply_changed_file_coverage(
            &mut scope,
            7,
            Err(ReviewError::Engine("inventory failed".into())),
        )
        .unwrap_err();
        assert!(error.to_string().contains("inventory failed"));

        let error = apply_changed_file_coverage(
            &mut scope,
            7,
            Ok(crate::review::ChangedFileCoverage::default()),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            BugHunterError::Review(ReviewError::NoChangedFiles(7))
        ));
    }

    #[test]
    fn changed_file_coverage_is_attached_to_the_review_scope() {
        let mut scope = review_scope(BTreeMap::new());
        let coverage = crate::review::ChangedFileCoverage {
            inspectable: BTreeSet::from(["src/lib.rs".into()]),
            skipped: Vec::new(),
        };

        apply_changed_file_coverage(&mut scope, 7, Ok(coverage.clone())).unwrap();

        assert_eq!(scope.changed_file_coverage(), &coverage);
    }

    #[test]
    fn runtime_creation_errors_retain_context() {
        let error =
            map_runtime_result::<()>(Err(std::io::Error::other("thread unavailable"))).unwrap_err();

        assert!(error.to_string().contains("failed to start async runtime"));
        assert!(error.to_string().contains("thread unavailable"));
    }

    #[tokio::test]
    async fn every_trigger_cancels_until_the_source_stops() {
        struct ScriptedTrigger {
            remaining: usize,
        }

        impl CancelTrigger for ScriptedTrigger {
            async fn wait(&mut self) -> bool {
                let fired = self.remaining > 0;
                self.remaining = self.remaining.saturating_sub(1);
                fired
            }
        }

        let cancelled = crate::cancel::CancelToken::default();
        cancel_while_triggered(ScriptedTrigger { remaining: 2 }, cancelled.clone()).await;
        assert!(cancelled.is_cancelled());

        let untouched = crate::cancel::CancelToken::default();
        cancel_while_triggered(ScriptedTrigger { remaining: 0 }, untouched.clone()).await;
        assert!(!untouched.is_cancelled());
    }

    #[test]
    fn report_write_errors_retain_the_destination() {
        let file_error = report_write_error(
            PathBuf::from("report.json"),
            std::io::Error::other("disk full"),
        );
        let stdout_error = stdout_report_error(std::io::Error::other("pipe closed"));

        assert!(matches!(
            file_error,
            BugHunterError::Report(ReportError::WriteError { path, .. })
                if path == Path::new("report.json")
        ));
        assert!(matches!(
            stdout_error,
            BugHunterError::Report(ReportError::WriteError { path, .. })
                if path == Path::new("stdout")
        ));
    }

    #[test]
    fn preparation_rejects_a_project_path_that_cannot_be_resolved() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing");

        let outcome = prepare(&analyze_args(&missing), AnalysisMode::Static);

        match outcome {
            Err(BugHunterError::Config(ConfigError::InvalidValue { field, reason })) => {
                assert_eq!(field, "project");
                assert!(reason.contains("cannot resolve"));
            }
            Err(other) => panic!("unexpected preparation error: {other}"),
            Ok(_) => panic!("an unresolvable project must not prepare an analysis"),
        }
    }

    #[test]
    fn static_mode_rejects_categories_no_static_check_can_run() {
        let mut args = analyze_args(Path::new("."));
        args.categories = Some(vec![CategoryArg::Bug]);

        let error = validate_with_cli_overrides(
            config::schema::Config::default(),
            &args,
            AnalysisMode::Static,
        )
        .unwrap_err();

        match error {
            BugHunterError::Config(ConfigError::InvalidValue { field, reason }) => {
                assert_eq!(field, "analysis.categories");
                assert!(reason.contains("static mode requires quality or vulnerability"));
            }
            other => panic!("unexpected validation error: {other}"),
        }
    }

    #[test]
    fn cli_overrides_and_the_discovery_source_reach_the_validated_config() {
        let mut args = analyze_args(Path::new("."));
        args.pr = Some(18);
        args.output = Some(PathBuf::from("report.json"));
        args.categories = Some(vec![CategoryArg::Vulnerability]);

        let validated = validate_with_cli_overrides(
            config::schema::Config::default(),
            &args,
            AnalysisMode::Static,
        )
        .unwrap();

        assert_eq!(validated.mode(), AnalysisMode::Static);
        assert_eq!(
            validated.general.output_path.as_deref(),
            Some(Path::new("report.json"))
        );
        assert_eq!(
            validated.analysis.categories,
            vec![AnalysisCategory::Vulnerability]
        );
        assert_eq!(
            validated.engine.discovery_source,
            DiscoverySource::UntrustedSnapshot
        );
    }

    #[test]
    fn snapshot_coverage_separates_inspectable_from_absent_changed_files() {
        let snapshot = tempfile::tempdir().unwrap();
        std::fs::write(snapshot.path().join("kept.rs"), "fn kept() {}\n").unwrap();
        let project_root = ProjectRoot::open(snapshot.path()).unwrap();
        let mut scope = review_scope(BTreeMap::from([
            ("kept.rs".to_string(), vec![(1, 1)]),
            ("removed.rs".to_string(), vec![(1, 1)]),
        ]));

        apply_snapshot_coverage(
            &mut scope,
            &project_root,
            &crate::config::EngineConfig::default(),
            7,
        )
        .unwrap();

        assert_eq!(
            scope.changed_file_coverage().inspectable,
            BTreeSet::from(["kept.rs".to_string()])
        );
        assert_eq!(
            scope.changed_file_coverage().skipped_report_entries(),
            vec!["removed.rs (absent from the pull request snapshot)".to_string()]
        );
    }

    #[test]
    fn static_mode_analysis_runs_without_an_async_runtime() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join("main.py"),
            "def main():\n    return 1\n",
        )
        .unwrap();
        let prepared = static_analysis_of(project.path());

        let result = execute_static(&prepared).unwrap();

        assert_eq!(result.scan.files_inspected, 1);
        assert!(!result.scan.is_partial());
    }

    #[test]
    fn failed_analyses_flush_interactive_logs_and_propagate_the_error() {
        let project = tempfile::tempdir().unwrap();
        let prepared = static_analysis_of(project.path());
        drop(project);
        let state = shared_state();
        state
            .lock()
            .push_log(tracing::Level::WARN, "buffered before failure".into());

        let flushed = run_with_log_replay(&prepared, &state, true).unwrap_err();
        let plain = run_with_log_replay(&prepared, &state, false).unwrap_err();

        assert!(matches!(flushed, BugHunterError::Engine(_)));
        assert!(matches!(plain, BugHunterError::Engine(_)));
        assert_eq!(
            state.lock().logs.len(),
            1,
            "flushing buffered logs must not consume them"
        );
    }

    #[test]
    fn configured_output_paths_receive_the_report() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("report.json");

        write_output("{\"findings\":[]}", Some(path.as_path())).unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"findings\":[]}");
    }

    #[test]
    fn unreachable_output_paths_report_the_destination() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("absent").join("report.json");

        let error = write_output("{}", Some(path.as_path())).unwrap_err();

        match error {
            BugHunterError::Report(ReportError::WriteError {
                path: destination,
                source,
            }) => {
                assert_eq!(destination, path);
                assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("unexpected write error: {other}"),
        }
    }

    #[test]
    fn omitted_output_paths_send_the_report_to_stdout() {
        assert!(write_output("{}", None).is_ok());
    }

    fn skipped_entries(count: usize) -> Vec<String> {
        (0..count)
            .map(|index| format!("src/file_{index:04}.rs (unreadable)"))
            .collect()
    }

    #[test]
    fn a_short_skip_list_is_reported_in_full() {
        let line = skipped_files_status(
            &["a.rs (gone)".to_string(), "b.rs (gone)".to_string()],
            0,
            MAX_STATUS_LINE_BYTES,
        );

        assert_eq!(line, "skipped files: a.rs (gone), b.rs (gone)");
    }

    #[test]
    fn partial_coverage_reports_a_skip_line_only_when_something_was_skipped() {
        let clean = crate::report::ScanStatus::complete(2);
        let skipped = crate::report::ScanStatus {
            skipped_files: vec!["a.rs (gone)".to_string()],
            ..crate::report::ScanStatus::complete(2)
        };

        let clean_lines = partial_coverage_status(&clean);
        let skipped_lines = partial_coverage_status(&skipped);

        assert_eq!(clean_lines.len(), 1);
        assert!(clean_lines[0].starts_with("partial AI coverage:"));
        assert_eq!(skipped_lines.len(), 2);
        assert_eq!(skipped_lines[1], "skipped files: a.rs (gone)");
    }

    #[test]
    fn a_long_skip_list_stays_under_the_status_ceiling_and_marks_the_omissions() {
        let entries = skipped_entries(5_000);

        let line = skipped_files_status(&entries, 0, MAX_STATUS_LINE_BYTES);

        assert!(
            line.len() <= MAX_STATUS_LINE_BYTES,
            "status line grew to {} bytes",
            line.len()
        );
        assert!(
            line.starts_with("skipped files: src/file_0000.rs (unreadable)"),
            "{line}"
        );
        assert!(line.contains(" not shown)"), "{line}");
        let listed = line.matches("(unreadable)").count();
        assert!(
            listed > 0 && listed < entries.len(),
            "{listed} entries listed"
        );
        assert!(
            line.contains(&format!("(+{} not shown)", entries.len() - listed)),
            "{line}"
        );
    }

    #[test]
    fn diagnostics_dropped_by_the_accumulator_are_added_to_the_unlisted_count() {
        let line = skipped_files_status(&["a.rs (gone)".to_string()], 12, MAX_STATUS_LINE_BYTES);

        assert_eq!(line, "skipped files: a.rs (gone) (+12 not shown)");
    }

    #[test]
    fn an_entry_that_cannot_fit_is_counted_instead_of_split() {
        let line = skipped_files_status(
            &["an-entry-that-does-not-fit.rs (gone)".to_string()],
            0,
            OMISSION_SUFFIX_BYTES + SKIPPED_FILES_PREFIX.len(),
        );

        assert_eq!(line, "skipped files: (+1 not shown)");
    }

    #[test]
    fn an_oversize_report_leaves_the_destination_file_untouched() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("report.md");
        std::fs::write(&destination, "# previous report\n").unwrap();
        let findings = vec![finding_titled("bounded")];
        let scan = crate::report::ScanStatus::complete(1);

        let error = render_then_write(&findings, &scan, 16, &destination).unwrap_err();

        assert!(matches!(
            error,
            BugHunterError::Report(ReportError::TooLarge { .. })
        ));
        assert_eq!(
            std::fs::read_to_string(&destination).unwrap(),
            "# previous report\n",
            "an oversize render must not touch the destination"
        );
    }

    #[test]
    fn a_report_within_the_ceiling_replaces_the_destination_file() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("report.md");
        std::fs::write(&destination, "# previous report\n").unwrap();
        let findings = vec![finding_titled("bounded")];
        let scan = crate::report::ScanStatus::complete(1);

        render_then_write(
            &findings,
            &scan,
            crate::report::limits::MAX_REPORT_BYTES,
            &destination,
        )
        .unwrap();

        let written = std::fs::read_to_string(&destination).unwrap();
        assert!(written.contains("bounded"), "{written}");
    }

    fn finding_titled(title: &str) -> crate::report::Finding {
        crate::report::Finding::new_static(
            &crate::report::FindingCounter::new(),
            AnalysisCategory::Bug,
            crate::config::schema::Severity::High,
            title.to_string(),
            "described".to_string(),
            "src/a.rs".into(),
        )
    }

    fn render_then_write(
        findings: &[crate::report::Finding],
        scan: &crate::report::ScanStatus,
        limit_bytes: usize,
        destination: &Path,
    ) -> Result<(), BugHunterError> {
        let output = orchestrator::render_markdown_summary_within(findings, scan, limit_bytes)
            .map_err(BugHunterError::Report)?;
        write_output(&output, Some(destination))
    }

    #[test]
    fn preparing_an_existing_project_produces_a_local_analysis() {
        let project = tempfile::tempdir().unwrap();

        let prepared = prepare(&analyze_args(project.path()), AnalysisMode::Static).unwrap();

        assert_eq!(prepared.config.mode(), AnalysisMode::Static);
        assert!(prepared.review_session.is_none());
        assert_eq!(
            prepared.project_root.as_path(),
            ProjectRoot::open(project.path()).unwrap().as_path()
        );
    }

    #[test]
    fn a_pull_request_preparation_without_a_git_remote_fails_locally() {
        let project = tempfile::tempdir().unwrap();
        let mut args = analyze_args(project.path());
        args.pr = Some(7);
        let config =
            config::ValidatedConfig::new(config::schema::Config::default(), AnalysisMode::Static)
                .unwrap();
        let local_checkout = ProjectRoot::open(project.path()).unwrap();

        match finish_preparation(&args, config, local_checkout) {
            Err(BugHunterError::Review(_)) => {}
            Err(other) => panic!("unexpected preparation error: {other}"),
            Ok(_) => panic!("a pull request review must not prepare without a git remote"),
        }
    }

    #[test]
    fn a_failed_report_write_flushes_buffered_logs_and_propagates_the_error() {
        let project = tempfile::tempdir().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("absent").join("report.json");
        let mut schema = config::schema::Config::default();
        schema.general.output_path = Some(destination.clone());
        let prepared = PreparedAnalysis {
            project_root: ProjectRoot::open(project.path()).unwrap(),
            backend_working_directory: ProjectRoot::open(project.path()).unwrap(),
            config: config::ValidatedConfig::new(schema, AnalysisMode::Static).unwrap(),
            review_session: None,
        };
        let state = shared_state();
        state
            .lock()
            .push_log(tracing::Level::WARN, "buffered before the failure".into());
        let result = orchestrator::AnalysisResult {
            findings: Vec::new(),
            output: "{}".to_string(),
            has_findings_above_threshold: false,
            scan: crate::report::ScanStatus::complete(0),
        };

        let error = report_result(
            &analyze_args(project.path()),
            &prepared,
            &state,
            true,
            Ok(result),
        )
        .unwrap_err();

        match error {
            BugHunterError::Report(ReportError::WriteError { path, .. }) => {
                assert_eq!(path, destination);
            }
            other => panic!("unexpected report error: {other}"),
        }
        assert_eq!(
            state.lock().logs.len(),
            1,
            "replaying buffered logs must not consume them"
        );
    }

    #[test]
    fn a_panicking_worker_is_mapped_to_a_worker_failure() {
        let runtime = tokio::runtime::Runtime::new().unwrap();

        let error = runtime
            .block_on(async {
                let blocking = tokio::task::spawn_blocking(|| -> Result<(), BugHunterError> {
                    panic!("the static checks blew up");
                });
                race_worker(
                    crate::cancel::CancelToken::default(),
                    "run static analysis",
                    blocking,
                )
                .await
            })
            .unwrap_err();

        match error {
            BugHunterError::Analysis(AnalysisError::WorkerFailed { action, reason }) => {
                assert_eq!(action, "run static analysis");
                assert!(reason.contains("panicked"), "{reason}");
            }
            other => panic!("unexpected worker error: {other}"),
        }
    }

    #[test]
    fn a_finished_worker_returns_its_result_and_a_cancelled_one_does_not_wait() {
        let runtime = tokio::runtime::Runtime::new().unwrap();

        let completed = runtime.block_on(async {
            let blocking = tokio::task::spawn_blocking(|| -> Result<(), BugHunterError> { Ok(()) });
            race_worker(
                crate::cancel::CancelToken::default(),
                "run static analysis",
                blocking,
            )
            .await
        });

        assert!(completed.is_ok());

        let cancelled = runtime.block_on(async {
            let cancel = crate::cancel::CancelToken::default();
            cancel.cancel();
            let blocking = tokio::task::spawn_blocking(|| -> Result<(), BugHunterError> { Ok(()) });
            race_worker(cancel, "run static analysis", blocking).await
        });

        assert!(matches!(cancelled, Err(BugHunterError::Cancelled)));
    }

    #[cfg(unix)]
    const SIGNAL_DELIVERY_ATTEMPTS: usize = 25;

    #[cfg(unix)]
    const SIGNAL_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_millis(40);

    #[cfg(unix)]
    async fn raise_signal_until_cancelled(
        signal: libc::c_int,
        cancel: &crate::cancel::CancelToken,
    ) {
        for _ in 0..SIGNAL_DELIVERY_ATTEMPTS {
            if cancel.is_cancelled() {
                return;
            }
            let delivered = unsafe { libc::kill(libc::getpid(), signal) };
            assert_eq!(delivered, 0, "signal {signal} could not be delivered");
            tokio::time::sleep(SIGNAL_CHECK_INTERVAL).await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn interrupt_and_terminate_signals_cancel_the_token() {
        let mut interrupt_guard =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).unwrap();
        let mut terminate_guard =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();

        let interrupted = crate::cancel::CancelToken::default();
        spawn_cancel_on_signals(interrupted.clone());
        raise_signal_until_cancelled(libc::SIGINT, &interrupted).await;
        assert!(interrupted.is_cancelled(), "SIGINT must cancel the token");

        let terminated = crate::cancel::CancelToken::default();
        spawn_cancel_on_unix_signal(
            terminated.clone(),
            tokio::signal::unix::SignalKind::terminate(),
        );
        raise_signal_until_cancelled(libc::SIGTERM, &terminated).await;
        assert!(terminated.is_cancelled(), "SIGTERM must cancel the token");

        assert!(interrupt_guard.recv().await.is_some());
        assert!(terminate_guard.recv().await.is_some());
    }
}
