use std::ffi::OsStr;
use std::fmt::Write as _;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::commands::DoctorArgs;
use super::project::{self, TrustedProject};
use crate::config::ValidatedConfig;
use crate::config::schema::{AnalysisMode, BackendConfig, Config};
use crate::errors::{self, BugHunterError, ConfigError, ReportError};
use crate::llm::claude_cli::{is_bare_cli_name, resolve_cli_binary};

const NO_CONFIG_FILES: &str = "none (built-in defaults)";
const CLAUDE_BINARY_REMEDY: &str =
    "install the Claude CLI or set BUGHUNTER_CLAUDE_CLI_BINARY to its path";

struct Report {
    project: PathBuf,
    config_files: Vec<PathBuf>,
    backend: &'static str,
    readiness: Readiness,
}

enum Readiness {
    Ready(String),
    Misconfigured(ConfigError),
    Unavailable {
        detail: String,
        remedy: &'static str,
    },
}

impl Readiness {
    fn exit_code(&self) -> i32 {
        match self {
            Readiness::Ready(_) => errors::EXIT_SUCCESS,
            Readiness::Misconfigured(_) => errors::EXIT_CONFIG_ERROR,
            Readiness::Unavailable { .. } => errors::EXIT_API_ERROR,
        }
    }
}

pub(super) fn run(args: &DoctorArgs) -> Result<i32, BugHunterError> {
    let project = project::open(&args.project, args.config.as_deref())?;
    let search_path = std::env::var_os("PATH");
    let path_extensions = std::env::var_os("PATHEXT");
    let report = diagnose(project, search_path.as_deref(), path_extensions.as_deref());
    write_report(&mut std::io::stdout().lock(), &report).map_err(stdout_write_error)?;
    Ok(report.readiness.exit_code())
}

fn diagnose(
    project: TrustedProject,
    search_path: Option<&OsStr>,
    path_extensions: Option<&OsStr>,
) -> Report {
    let backend = backend_name(&project.config.llm.backend);
    let config_files = project.source.existing_files();
    let readiness = backend_readiness(
        project.config,
        project.root.as_path(),
        search_path,
        path_extensions,
    );
    Report {
        project: project.root.into_path_buf(),
        config_files,
        backend,
        readiness,
    }
}

fn write_report(stream: &mut dyn Write, report: &Report) -> std::io::Result<()> {
    write_line(stream, &format!("project: {}", report.project.display()))?;
    write_line(
        stream,
        &format!("config: {}", config_sources(&report.config_files)),
    )?;
    write_line(stream, &format!("backend: {}", report.backend))?;
    match &report.readiness {
        Readiness::Ready(detail) => write_line(stream, &format!("ready: {detail}")),
        Readiness::Misconfigured(error) => write_line(stream, &format!("invalid: {error}")),
        Readiness::Unavailable { detail, remedy } => {
            write_line(stream, &format!("missing: {detail}"))?;
            write_line(stream, &format!("remedy: {remedy}"))
        }
    }?;
    stream.flush()
}

fn write_line(stream: &mut dyn Write, message: &str) -> std::io::Result<()> {
    writeln!(stream, "{}", crate::shared::sanitize_terminal_text(message))
}

fn stdout_write_error(source: std::io::Error) -> BugHunterError {
    ReportError::WriteError {
        path: PathBuf::from("stdout"),
        source,
    }
    .into()
}

fn backend_name(backend: &BackendConfig) -> &'static str {
    match backend {
        BackendConfig::ClaudeCli { .. } => "claude-cli",
        BackendConfig::OpenAiCompatible { .. } => "openai-compatible",
    }
}

fn config_sources(files: &[PathBuf]) -> String {
    if files.is_empty() {
        return NO_CONFIG_FILES.to_string();
    }
    let mut sources = String::new();
    for path in files {
        if !sources.is_empty() {
            sources.push_str(", ");
        }
        let _ = write!(sources, "{}", path.display());
    }
    sources
}

fn backend_readiness(
    config: Config,
    working_directory: &Path,
    search_path: Option<&OsStr>,
    path_extensions: Option<&OsStr>,
) -> Readiness {
    let validated = match ValidatedConfig::new(config, AnalysisMode::AiOnly) {
        Ok(validated) => validated,
        Err(error) => return Readiness::Misconfigured(error),
    };
    match &validated.llm.backend {
        BackendConfig::ClaudeCli { binary } => {
            claude_cli_readiness(binary, working_directory, search_path, path_extensions)
        }
        BackendConfig::OpenAiCompatible { api_url, .. } => {
            Readiness::Ready(format!("model {} at {api_url}", validated.llm.model.trim()))
        }
    }
}

fn claude_cli_readiness(
    binary: &str,
    working_directory: &Path,
    search_path: Option<&OsStr>,
    path_extensions: Option<&OsStr>,
) -> Readiness {
    if let Some(path) = resolve_cli_binary(
        binary,
        Some(working_directory),
        search_path,
        path_extensions,
        None,
    ) {
        return Readiness::Ready(format!("executable at {}", path.display()));
    }
    let detail = if is_bare_cli_name(binary) {
        format!("executable {binary:?} not found on PATH")
    } else {
        format!("{binary:?} is not an executable file")
    };
    Readiness::Unavailable {
        detail,
        remedy: CLAUDE_BINARY_REMEDY,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::config::loader::TrustedConfigSource;
    use crate::domain::ProjectRoot;
    use tempfile::TempDir;

    #[cfg(windows)]
    const CLAUDE_SCRIPT: &str = "@exit /b 0\r\n";
    #[cfg(not(windows))]
    const CLAUDE_SCRIPT: &str = "#!/bin/sh\nexit 0\n";

    fn claude_config(binary: &str) -> Config {
        let mut config = Config::default();
        config.llm.backend = BackendConfig::ClaudeCli {
            binary: binary.to_string(),
        };
        config
    }

    fn openai_config(api_token: Option<&str>) -> Config {
        let mut config = Config::default();
        config.llm.backend = BackendConfig::OpenAiCompatible {
            api_url: "https://api.example.com/v1".to_string(),
            api_token: api_token.map(str::to_string),
        };
        config.llm.model = "test-model".to_string();
        config
    }

    fn executable_path(directory: &Path) -> PathBuf {
        directory.join(if cfg!(windows) {
            "claude.cmd"
        } else {
            "claude"
        })
    }

    fn relative_executable_path() -> String {
        Path::new("tools")
            .join(if cfg!(windows) {
                "claude.cmd"
            } else {
                "claude"
            })
            .to_string_lossy()
            .into_owned()
    }

    fn write_executable(path: &Path) {
        std::fs::write(path, CLAUDE_SCRIPT).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = std::fs::metadata(path).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(path, permissions).unwrap();
        }
    }

    fn ready_detail(readiness: &Readiness) -> &str {
        match readiness {
            Readiness::Ready(detail) => detail,
            Readiness::Misconfigured(error) => panic!("expected a ready backend, got {error}"),
            Readiness::Unavailable { detail, .. } => {
                panic!("expected a ready backend, got {detail}")
            }
        }
    }

    fn assert_same_file(actual: &Path, expected: &Path) {
        assert_eq!(
            actual.canonicalize().unwrap(),
            expected.canonicalize().unwrap()
        );
    }

    fn assert_ready_path(readiness: &Readiness, expected: &Path) {
        let path = ready_detail(readiness)
            .strip_prefix("executable at ")
            .map(Path::new)
            .unwrap();
        assert_same_file(path, expected);
    }

    fn rendered(report: &Report) -> String {
        let mut sink = Vec::new();
        write_report(&mut sink, report).unwrap();
        String::from_utf8(sink).unwrap()
    }

    fn report_of(readiness: Readiness) -> Report {
        Report {
            project: PathBuf::from("/project"),
            config_files: vec![PathBuf::from("/project/.bughunter.toml")],
            backend: "claude-cli",
            readiness,
        }
    }

    #[test]
    fn a_configured_claude_executable_is_ready() {
        let directory = TempDir::new().unwrap();
        let binary = executable_path(directory.path());
        write_executable(&binary);

        let readiness = backend_readiness(
            claude_config(binary.to_str().unwrap()),
            directory.path(),
            None,
            None,
        );

        assert_ready_path(&readiness, &binary);
        assert_eq!(readiness.exit_code(), errors::EXIT_SUCCESS);
    }

    #[test]
    fn a_relative_claude_path_resolves_against_the_analysis_working_directory() {
        let project = TempDir::new().unwrap();
        let elsewhere = TempDir::new().unwrap();
        std::fs::create_dir(project.path().join("tools")).unwrap();
        let binary = executable_path(&project.path().join("tools"));
        write_executable(&binary);

        let configured_path = relative_executable_path();
        let inside = backend_readiness(claude_config(&configured_path), project.path(), None, None);
        let outside = backend_readiness(
            claude_config(&configured_path),
            elsewhere.path(),
            None,
            None,
        );

        assert_ready_path(&inside, &binary);
        assert!(matches!(outside, Readiness::Unavailable { .. }));
    }

    #[test]
    fn a_configured_claude_path_that_is_missing_reports_the_remedy() {
        let directory = TempDir::new().unwrap();
        let binary = directory.path().join("absent-claude");

        let readiness = backend_readiness(
            claude_config(binary.to_str().unwrap()),
            directory.path(),
            None,
            None,
        );

        let Readiness::Unavailable { detail, remedy } = &readiness else {
            panic!("expected an unavailable backend");
        };
        assert_eq!(
            *detail,
            format!(
                "{:?} is not an executable file",
                binary.display().to_string()
            )
        );
        assert_eq!(*remedy, CLAUDE_BINARY_REMEDY);
        assert_eq!(readiness.exit_code(), errors::EXIT_API_ERROR);
    }

    #[cfg(unix)]
    #[test]
    fn a_claude_file_without_the_execute_bit_is_not_accepted() {
        let directory = TempDir::new().unwrap();
        let binary = directory.path().join("claude");
        std::fs::write(&binary, CLAUDE_SCRIPT).unwrap();

        assert!(
            resolve_cli_binary(
                binary.to_str().unwrap(),
                Some(directory.path()),
                None,
                None,
                None
            )
            .is_none()
        );
    }

    #[test]
    fn a_claude_name_absent_from_the_search_path_reports_the_remedy() {
        let directory = TempDir::new().unwrap();

        for search_path in [Some(directory.path().as_os_str()), None] {
            let readiness =
                backend_readiness(claude_config("claude"), directory.path(), search_path, None);

            let Readiness::Unavailable { detail, remedy } = &readiness else {
                panic!("expected an unavailable backend for {search_path:?}");
            };
            assert_eq!(*detail, "executable \"claude\" not found on PATH");
            assert_eq!(*remedy, CLAUDE_BINARY_REMEDY);
            assert_eq!(readiness.exit_code(), errors::EXIT_API_ERROR);
        }
    }

    #[test]
    fn a_claude_name_is_resolved_from_the_search_path() {
        let project = TempDir::new().unwrap();
        let empty = TempDir::new().unwrap();
        let installed = TempDir::new().unwrap();
        let binary = executable_path(installed.path());
        write_executable(&binary);
        let search_path =
            std::env::join_paths([empty.path(), installed.path()].iter().copied()).unwrap();

        let readiness = backend_readiness(
            claude_config("claude"),
            project.path(),
            Some(&search_path),
            None,
        );

        assert_ready_path(&readiness, &binary);
    }

    #[test]
    fn an_empty_search_path_entry_resolves_against_the_analysis_working_directory() {
        let project = TempDir::new().unwrap();
        let binary = executable_path(project.path());
        write_executable(&binary);
        let search_path = std::ffi::OsString::from("");

        let resolved = resolve_cli_binary(
            "claude",
            Some(project.path()),
            Some(&search_path),
            None,
            None,
        );

        assert_same_file(resolved.as_deref().unwrap(), &binary);
    }

    #[test]
    fn openai_settings_without_a_token_are_reported_as_invalid() {
        let directory = TempDir::new().unwrap();

        let readiness = backend_readiness(openai_config(None), directory.path(), None, None);

        let Readiness::Misconfigured(error) = &readiness else {
            panic!("expected a misconfigured backend");
        };
        assert!(matches!(
            error,
            ConfigError::MissingRequired { field, .. } if field == "BUGHUNTER_API_TOKEN"
        ));
        assert_eq!(readiness.exit_code(), errors::EXIT_CONFIG_ERROR);
    }

    #[test]
    fn a_configured_openai_backend_is_ready_without_naming_its_token() {
        let directory = TempDir::new().unwrap();

        let readiness = backend_readiness(
            openai_config(Some("secret-token")),
            directory.path(),
            None,
            None,
        );

        assert_eq!(
            ready_detail(&readiness),
            "model test-model at https://api.example.com/v1"
        );
        assert_eq!(readiness.exit_code(), errors::EXIT_SUCCESS);
    }

    #[test]
    fn config_sources_list_every_loaded_file_in_precedence_order() {
        assert_eq!(config_sources(&[]), NO_CONFIG_FILES);
        assert_eq!(
            config_sources(&[
                PathBuf::from("/home/user.toml"),
                PathBuf::from("/p/local.toml")
            ]),
            "/home/user.toml, /p/local.toml"
        );
    }

    #[test]
    fn backend_names_follow_the_configured_backend() {
        assert_eq!(
            backend_name(&BackendConfig::ClaudeCli {
                binary: "claude".to_string()
            }),
            "claude-cli"
        );
        assert_eq!(
            backend_name(&BackendConfig::OpenAiCompatible {
                api_url: String::new(),
                api_token: None
            }),
            "openai-compatible"
        );
    }

    #[test]
    fn the_report_names_the_project_the_config_files_and_the_backend() {
        let directory = TempDir::new().unwrap();
        std::fs::write(directory.path().join(".bughunter.toml"), "[llm]\n").unwrap();
        let binary = executable_path(directory.path());
        write_executable(&binary);
        let root = ProjectRoot::open(directory.path()).unwrap();
        let project = TrustedProject {
            source: TrustedConfigSource::for_local_checkout(root.as_path(), None),
            config: claude_config(binary.to_str().unwrap()),
            root,
        };

        let report = diagnose(project, None, None);

        assert_eq!(
            report.project,
            std::fs::canonicalize(directory.path()).unwrap()
        );
        assert!(
            report
                .config_files
                .contains(&report.project.join(".bughunter.toml"))
        );
        assert_eq!(report.backend, "claude-cli");
        assert_ready_path(&report.readiness, &binary);
    }

    #[test]
    fn a_ready_report_names_the_project_configuration_backend_and_executable() {
        let report = report_of(Readiness::Ready(
            "executable at /usr/bin/claude".to_string(),
        ));

        assert_eq!(
            rendered(&report),
            "project: /project\nconfig: /project/.bughunter.toml\nbackend: claude-cli\nready: executable at /usr/bin/claude\n"
        );
    }

    #[test]
    fn an_invalid_report_names_the_configuration_field_and_its_hint() {
        let report = report_of(Readiness::Misconfigured(ConfigError::MissingRequired {
            field: "BUGHUNTER_API_TOKEN".to_string(),
            hint: "set BUGHUNTER_API_TOKEN in the process environment".to_string(),
        }));

        assert_eq!(
            rendered(&report),
            "project: /project\nconfig: /project/.bughunter.toml\nbackend: claude-cli\ninvalid: missing required config: BUGHUNTER_API_TOKEN (set via set BUGHUNTER_API_TOKEN in the process environment)\n"
        );
    }

    #[test]
    fn an_unavailable_report_names_the_missing_prerequisite_and_its_remedy() {
        let report = report_of(Readiness::Unavailable {
            detail: "executable \"claude\" not found on PATH".to_string(),
            remedy: CLAUDE_BINARY_REMEDY,
        });

        assert_eq!(
            rendered(&report),
            "project: /project\nconfig: /project/.bughunter.toml\nbackend: claude-cli\nmissing: executable \"claude\" not found on PATH\nremedy: install the Claude CLI or set BUGHUNTER_CLAUDE_CLI_BINARY to its path\n"
        );
    }

    #[test]
    fn a_report_line_neutralizes_terminal_control_sequences() {
        let report = report_of(Readiness::Unavailable {
            detail: "executable \"cl\u{1b}[2Jaude\" not found on PATH".to_string(),
            remedy: CLAUDE_BINARY_REMEDY,
        });

        let rendered = rendered(&report);

        assert!(rendered.contains("cl\\u{1b}[2Jaude"));
        assert!(!rendered.contains('\u{1b}'));
    }

    #[test]
    fn a_failed_report_write_reaches_the_caller_from_every_line() {
        struct FailsAfter {
            accepted: usize,
        }

        impl Write for FailsAfter {
            fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
                if self.accepted == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::StorageFull,
                        "device full",
                    ));
                }
                self.accepted -= 1;
                Ok(buffer.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let report = report_of(Readiness::Unavailable {
            detail: "executable \"claude\" not found on PATH".to_string(),
            remedy: CLAUDE_BINARY_REMEDY,
        });

        let mut accepted = 0;
        while let Err(error) = write_report(&mut FailsAfter { accepted }, &report) {
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::StorageFull,
                "the failure after {accepted} accepted writes must reach the caller"
            );
            assert!(matches!(
                stdout_write_error(error),
                BugHunterError::Report(ReportError::WriteError { path, .. })
                    if path == Path::new("stdout")
            ));
            accepted += 1;
        }

        assert!(accepted >= rendered(&report).lines().count());
    }

    #[test]
    fn a_failed_report_flush_reaches_the_caller() {
        struct Unflushable;

        impl Write for Unflushable {
            fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
                Ok(buffer.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("device full"))
            }
        }

        let error = write_report(
            &mut Unflushable,
            &report_of(Readiness::Ready("available".to_string())),
        )
        .unwrap_err();

        assert_eq!(error.to_string(), "device full");
    }

    #[test]
    fn a_project_directory_that_does_not_resolve_stops_the_checks() {
        let directory = TempDir::new().unwrap();
        let args = DoctorArgs {
            project: directory.path().join("absent"),
            config: None,
        };

        let error = run(&args).unwrap_err();

        assert!(matches!(
            error,
            BugHunterError::Config(ConfigError::InvalidValue { field, .. }) if field == "project"
        ));
    }
}
