#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![cfg_attr(not(test), deny(unsafe_code))]

mod analysis;
mod cancel;
mod cli;
mod config;
mod domain;
mod engine;
mod errors;
#[cfg(feature = "fuzzing")]
pub mod fuzzing;
mod llm;
mod orchestrator;
#[allow(unsafe_code)]
mod process;
mod repomap;
mod report;
mod review;
mod shared;
mod tui;
mod version;

use clap::Parser;

pub use config::ValidatedConfig;
pub use config::schema::{
    AnalysisCategory, AnalysisConfig, AnalysisMode, BackendConfig, Config, EngineConfig,
    GeneralConfig, LlmBackendKind, LlmConfig, LlmSettings, LogLevel, OutputFormat,
    QualityThresholds, Severity, SolidConfig,
};
pub use domain::{LineRange, LineRangeError, ProjectRoot};
pub use errors::{
    AnalysisError, BugHunterError, ConfigError, EngineError, LlmError, RepoMapError, ReportError,
};
pub use orchestrator::AnalysisResult;
pub use report::{Confidence, FailedShard, Finding, FindingSource, ScanCompleteness, ScanStatus};
pub use review::{
    ChangedFileCoverage, ChangedFileSkipReason, DiffResource, ReviewError, ReviewScope,
    SkippedChangedFile,
};

pub async fn analyze(
    project_root: &ProjectRoot,
    config: Config,
    mode: AnalysisMode,
) -> Result<AnalysisResult, BugHunterError> {
    if matches!(mode, AnalysisMode::Review) {
        return Err(ConfigError::InvalidValue {
            field: "mode".into(),
            reason: "review analysis requires analyze_review and a ReviewScope".into(),
        }
        .into());
    }
    let config = ValidatedConfig::new(config, mode)?;
    if config.mode() == AnalysisMode::Static {
        let project_root = project_root.as_path().to_path_buf();
        let worker_result = tokio::task::spawn_blocking(move || {
            orchestrator::run_static_analysis(&project_root, &config)
        })
        .await;
        map_static_worker_result(worker_result)?
    } else {
        orchestrator::run_analysis(
            project_root.as_path(),
            Some(project_root.as_path()),
            &config,
            tui::shared_state(),
            false,
            None,
            cancel::CancelToken::default(),
        )
        .await
    }
}

fn map_static_worker_result<T>(
    result: Result<T, tokio::task::JoinError>,
) -> Result<T, BugHunterError> {
    result.map_err(|error| {
        AnalysisError::StaticCheckFailed(format!("static analysis worker failed: {error}")).into()
    })
}

pub async fn analyze_review(
    project_root: &ProjectRoot,
    mut config: Config,
    review: &ReviewScope,
) -> Result<AnalysisResult, BugHunterError> {
    config.engine.discovery_source = config::schema::DiscoverySource::UntrustedSnapshot;
    let config = ValidatedConfig::new(config, AnalysisMode::Review)?;
    orchestrator::run_analysis(
        project_root.as_path(),
        None,
        &config,
        tui::shared_state(),
        false,
        Some(review),
        cancel::CancelToken::default(),
    )
    .await
}

pub fn run_cli() -> i32 {
    let cli = cli::Cli::parse();
    match cli.run() {
        Ok(code) => code,
        Err(error) => {
            cli::output::print_error(&error.to_string());
            errors::exit_code_for_error(&error)
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn panicked_static_workers_return_a_public_analysis_error() {
        let result = tokio::spawn(async { panic!("worker panic") }).await;

        let error = map_static_worker_result(result).unwrap_err();

        assert!(matches!(
            error,
            BugHunterError::Analysis(AnalysisError::StaticCheckFailed(message))
                if message.contains("static analysis worker failed")
        ));
    }

    #[tokio::test]
    async fn public_static_analysis_returns_the_worker_result() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("source.rs"), "fn short() {}\n").unwrap();
        let project_root = ProjectRoot::open(directory.path()).unwrap();

        let result = analyze(&project_root, Config::default(), AnalysisMode::Static)
            .await
            .unwrap();

        assert!(result.output.contains("\"mode\": \"static\""));
    }
}
