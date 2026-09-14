use std::io::IsTerminal;

use tracing::Dispatch;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::{SubscriberInitExt, TryInitError};
use tracing_subscriber::{EnvFilter, fmt};

use super::log_format::SanitizedFields;
use super::output;
use crate::config::schema::LogLevel;
use crate::tui::{SharedState, TuiLogLayer};

pub(super) fn init(verbose: bool, use_tui: bool, state: SharedState, configured_level: &LogLevel) {
    let filter = build_filter(
        std::env::var(EnvFilter::DEFAULT_ENV),
        verbose,
        configured_level,
    );
    install(filter, use_tui, state);
}

fn install(filter: EnvFilter, use_tui: bool, state: SharedState) {
    report_installation_result(build_dispatch(filter, use_tui, state).try_init());
}

fn build_dispatch(filter: EnvFilter, use_tui: bool, state: SharedState) -> Dispatch {
    if use_tui {
        return Dispatch::new(
            tracing_subscriber::registry()
                .with(filter)
                .with(TuiLogLayer::new(state)),
        );
    }

    let format = fmt::layer()
        .fmt_fields(SanitizedFields)
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_ansi(std::io::stderr().is_terminal())
        .compact();
    Dispatch::new(tracing_subscriber::registry().with(filter).with(format))
}

fn build_filter(
    raw: Result<String, std::env::VarError>,
    verbose: bool,
    configured_level: &LogLevel,
) -> EnvFilter {
    match raw {
        Ok(raw) => EnvFilter::try_new(&raw).unwrap_or_else(|error| {
            output::print_status(&format!(
                "warning: ignoring invalid {}: {error}",
                EnvFilter::DEFAULT_ENV
            ));
            EnvFilter::new(directive(verbose, configured_level))
        }),
        Err(_) => EnvFilter::new(directive(verbose, configured_level)),
    }
}

fn report_installation_result(installation: Result<(), TryInitError>) {
    if let Err(error) = installation {
        output::print_status(&format!("log output is already configured: {error}"));
    }
}

pub(super) fn directive(verbose: bool, configured_level: &LogLevel) -> String {
    let application_level = if verbose {
        "debug"
    } else {
        match configured_level {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    };
    format!("warn,bughunter={application_level}")
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::tui::shared_state;

    fn configured_filter(configured_level: &LogLevel) -> EnvFilter {
        build_filter(Err(std::env::VarError::NotPresent), false, configured_level)
    }

    fn recorded_logs(state: &SharedState) -> Vec<String> {
        state
            .lock()
            .logs
            .iter()
            .map(|line| line.text.clone())
            .collect()
    }

    fn logs_captured_by(filter: EnvFilter, use_tui: bool, emit: impl FnOnce()) -> Vec<String> {
        let state = shared_state();
        tracing::dispatcher::with_default(&build_dispatch(filter, use_tui, state.clone()), emit);
        recorded_logs(&state)
    }

    #[test]
    fn interactive_layers_record_only_events_the_filter_admits() {
        let recorded = logs_captured_by(configured_filter(&LogLevel::Info), true, || {
            tracing::info!("shard finished");
            tracing::trace!("token accounting");
        });

        assert_eq!(recorded, vec!["shard finished".to_string()]);
    }

    #[test]
    fn stderr_layers_keep_events_out_of_the_interactive_buffer() {
        let recorded = logs_captured_by(configured_filter(&LogLevel::Info), false, || {
            tracing::info!("reported on stderr");
        });

        assert!(recorded.is_empty());
    }

    #[test]
    fn valid_environment_filters_replace_the_configured_directive() {
        let filter = build_filter(Ok("bughunter=trace".into()), false, &LogLevel::Error);

        let recorded = logs_captured_by(filter, true, || tracing::trace!("environment override"));

        assert_eq!(recorded, vec!["environment override".to_string()]);
    }

    #[test]
    fn invalid_and_missing_environment_filters_use_the_configured_directive() {
        let invalid = build_filter(Ok("[".into()), false, &LogLevel::Error);
        let missing = configured_filter(&LogLevel::Warn);

        let invalid = invalid.to_string();
        assert!(invalid.contains("warn"));
        assert!(invalid.contains("bughunter=error"));
        let missing = missing.to_string();
        assert!(missing.contains("warn"));
        assert!(missing.contains("bughunter=warn"));
    }

    #[test]
    fn only_the_first_installation_becomes_the_global_subscriber() {
        let installed = shared_state();

        install(configured_filter(&LogLevel::Info), true, installed.clone());
        init(false, false, shared_state(), &LogLevel::Info);
        tracing::info!("recorded by the installed subscriber");

        assert!(
            recorded_logs(&installed).contains(&"recorded by the installed subscriber".to_string()),
            "the first installation must keep receiving events after a rejected duplicate"
        );
    }

    #[test]
    fn trace_and_debug_levels_map_to_matching_directives() {
        assert_eq!(directive(false, &LogLevel::Trace), "warn,bughunter=trace");
        assert_eq!(directive(false, &LogLevel::Debug), "warn,bughunter=debug");
    }
}
