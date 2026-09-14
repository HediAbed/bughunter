use std::path::{Path, PathBuf};

use super::commands::InitArgs;
use crate::errors::{self, BugHunterError, ConfigError};

pub(super) const DEFAULT_CONFIG_TEMPLATE: &str = r#"# BugHunter configuration. All fields are optional; the values shown are the defaults.

[general]
# fail_severity = "high"      # exit code 1 when findings reach this severity
# min_confidence = "low"      # drop findings below this confidence (low | medium | high)
# output_format = "json"      # json | md

[llm]
# backend = "claude-cli"      # local CLI | openai-compatible HTTP
# model = ""                  # model ID required for openai-compatible
# reasoning_effort = "low"    # Claude CLI defaults to low; HTTP support is provider-specific
# api_url = ""                # endpoint URL for openai-compatible
# max_agent_iterations = 50
# max_context_tokens = 0       # 0 auto-detects; explicit windows start at 40000
# max_shard_seconds = 900

[engine]
# max_file_size_bytes = 1048576

[analysis]
# categories = ["bug", "quality", "solid", "vulnerability"]

[analysis.quality]
# max_function_lines = 50
# max_file_lines = 500

[analysis.solid]
# check_srp = true
# check_ocp = true
# check_lsp = true
# check_isp = true
# check_dip = true
"#;

pub(super) fn run(args: &InitArgs) -> Result<i32, BugHunterError> {
    let config_path = config_path(args);

    if config_path.exists() {
        return Err(ConfigError::AlreadyExists { path: config_path }.into());
    }

    crate::shared::atomic_write_new(&config_path, DEFAULT_CONFIG_TEMPLATE.as_bytes()).map_err(
        |source| ConfigError::WriteFailed {
            path: config_path.clone(),
            source,
        },
    )?;

    super::output::print_line(&format!("created {}", config_path.display()))?;
    Ok(errors::EXIT_SUCCESS)
}

fn config_path(args: &InitArgs) -> PathBuf {
    args.project
        .as_deref()
        .unwrap_or_else(|| Path::new("."))
        .join(".bughunter.toml")
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn missing_project_directory_reports_the_config_destination() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing");
        let args = InitArgs {
            project: Some(missing.clone()),
        };

        let error = run(&args).unwrap_err();

        assert!(matches!(
            error,
            BugHunterError::Config(ConfigError::WriteFailed { path, .. })
                if path == missing.join(".bughunter.toml")
        ));
    }

    #[test]
    fn config_destination_follows_the_project_flag() {
        assert_eq!(
            config_path(&InitArgs { project: None }),
            PathBuf::from("./.bughunter.toml")
        );
        assert_eq!(
            config_path(&InitArgs {
                project: Some(PathBuf::from("/tmp/project"))
            }),
            PathBuf::from("/tmp/project/.bughunter.toml")
        );
    }
}
