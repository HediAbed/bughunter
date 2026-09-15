use std::sync::LazyLock;

use assert_cmd::Command;
use predicates::prelude::*;

static TEST_HOME: LazyLock<tempfile::TempDir> =
    LazyLock::new(|| tempfile::tempdir().expect("isolated test home"));

fn isolated_command(home: &std::path::Path) -> std::process::Command {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_bughunter"));
    command
        .env("HOME", home)
        .env_remove("BUGHUNTER_BACKEND")
        .env_remove("BUGHUNTER_CLAUDE_CLI_BINARY")
        .env_remove("BUGHUNTER_API_TOKEN")
        .env_remove("BUGHUNTER_API_URL")
        .env_remove("BUGHUNTER_MODEL")
        .env_remove("BUGHUNTER_MAX_CONTEXT_TOKENS")
        .env_remove("BUGHUNTER_MAX_SHARD_SECONDS")
        .env_remove("BUGHUNTER_CATEGORIES")
        .env_remove("BUGHUNTER_LOG_LEVEL")
        .env_remove("RUST_LOG");
    command
}

fn bughunter() -> Command {
    Command::from_std(isolated_command(TEST_HOME.path()))
}

#[test]
fn invalid_environment_overrides_fail_instead_of_falling_back() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("app.py"), "x = 1\n").unwrap();

    bughunter()
        .args(["analyze", "--static-only", "--project"])
        .arg(project.path())
        .env("BUGHUNTER_BACKEND", "misspelled-provider")
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "invalid config: BUGHUNTER_BACKEND",
        ));
}

#[test]
fn analyze_help_describes_static_default_and_explicit_combined_mode() {
    bughunter()
        .args(["analyze", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Default mode: static"))
        .stdout(predicate::str::contains("--with-ai"))
        .stdout(predicate::str::contains("--no-progress"));
}

#[test]
fn analyze_with_output_file_writes_report_and_stderr_note() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "# TODO: later\n").unwrap();
    let report_path = dir.path().join("report.json");

    bughunter()
        .args(["analyze", "--static-only"])
        .args(["--project", dir.path().to_str().unwrap()])
        .args(["--output", report_path.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("findings written to"));

    let report = std::fs::read_to_string(&report_path).unwrap();
    assert!(serde_json::from_str::<serde_json::Value>(&report).is_ok());
}

#[test]
fn analyze_reports_an_unwritable_destination_instead_of_succeeding() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "# TODO: later\n").unwrap();
    let unreachable = dir.path().join("missing").join("report.json");

    bughunter()
        .args(["analyze", "--static-only"])
        .args(["--project", dir.path().to_str().unwrap()])
        .args(["--output", unreachable.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("report.json"));

    assert!(!unreachable.exists());
}

#[test]
fn analyze_defaults_to_local_static_mode() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "x = 1\n").unwrap();

    bughunter()
        .args(["analyze", "--project", dir.path().to_str().unwrap()])
        .env("BUGHUNTER_CLAUDE_CLI_BINARY", "unavailable-backend")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"mode\": \"static\""));
}

#[test]
fn analyze_report_goes_to_stdout_when_no_output_flag() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "x = 1\n").unwrap();

    bughunter()
        .args(["analyze", "--static-only"])
        .args(["--project", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"mode\": \"static\""));
}

#[test]
fn configured_error_log_level_suppresses_info_messages() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "x = 1\n").unwrap();

    bughunter()
        .args(["analyze", "--static-only"])
        .args(["--project", dir.path().to_str().unwrap()])
        .env("BUGHUNTER_LOG_LEVEL", "error")
        .env_remove("RUST_LOG")
        .assert()
        .success()
        .stderr(predicate::str::is_empty());
}

#[test]
fn explicit_configured_output_path_receives_report() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "x = 1\n").unwrap();
    let report = dir.path().join("configured-report.json");
    let config = write_config(
        dir.path(),
        "trusted.toml",
        &format!("[general]\noutput_path = {:?}\n", report.to_string_lossy()),
    );

    bughunter()
        .args(["analyze", "--static-only"])
        .args(["--project", dir.path().to_str().unwrap()])
        .args(["--config", config.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("findings written to"));

    let value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(report).unwrap()).unwrap();
    assert_eq!(value["mode"], "static");
}

#[test]
fn automatically_discovered_project_output_path_is_ignored() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "x = 1\n").unwrap();
    let report = dir.path().join("project-report.json");
    write_config(
        dir.path(),
        ".bughunter.toml",
        &format!("[general]\noutput_path = {:?}\n", report.to_string_lossy()),
    );

    bughunter()
        .args(["analyze", "--static-only"])
        .args(["--project", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"mode\": \"static\""));

    assert!(!report.exists());
}

#[test]
fn malformed_project_config_fails_with_the_config_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "x = 1\n").unwrap();
    std::fs::write(dir.path().join(".bughunter.toml"), "[general\n").unwrap();

    bughunter()
        .args(["analyze", "--static-only"])
        .args(["--project", dir.path().to_str().unwrap()])
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("failed to parse config file"));
}

#[test]
fn init_then_rerun_fails_with_config_exit_code() {
    let dir = tempfile::tempdir().unwrap();

    bughunter()
        .args(["init", "--project", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("created"));

    bughunter()
        .args(["init", "--project", dir.path().to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn no_fail_flag_forces_exit_zero_despite_critical_finding() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config.py"),
        "password = \"SuperSecret123!\"\n",
    )
    .unwrap();

    let project = ["--project", dir.path().to_str().unwrap()];

    bughunter()
        .args(["analyze", "--static-only", "--fail-severity", "critical"])
        .args(project)
        .assert()
        .code(1);

    bughunter()
        .args([
            "analyze",
            "--static-only",
            "--fail-severity",
            "critical",
            "--no-fail",
        ])
        .args(project)
        .assert()
        .success();
}

#[test]
fn sarif_format_is_rejected_at_argument_parsing() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "x = 1\n").unwrap();

    bughunter()
        .args(["analyze", "--static-only", "--format", "sarif"])
        .args(["--project", dir.path().to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("possible values: json, md"));
}

#[test]
fn json_report_carries_the_scan_status() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "x = 1\n").unwrap();

    let assertion = bughunter()
        .args(["analyze", "--static-only"])
        .args(["--project", dir.path().to_str().unwrap()])
        .assert()
        .success();
    let stdout = String::from_utf8(assertion.get_output().stdout.clone()).unwrap();

    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(value["scan"]["completeness"], "complete");
    assert_eq!(value["scan"]["files_presented"], 1);
    assert_eq!(value["scan"]["files_inspected"], 1);
}

#[test]
fn markdown_report_carries_the_coverage_section() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "x = 1\n").unwrap();

    bughunter()
        .args(["analyze", "--static-only", "--format", "md"])
        .args(["--project", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("## Coverage"))
        .stdout(predicate::str::contains("**Completeness:** complete"));
}

#[test]
fn allow_partial_is_accepted_and_leaves_a_complete_scan_at_exit_zero() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "x = 1\n").unwrap();

    bughunter()
        .args(["analyze", "--static-only", "--allow-partial"])
        .args(["--project", dir.path().to_str().unwrap()])
        .assert()
        .success();
}

#[cfg(unix)]
#[test]
fn hostile_broken_symlink_names_stay_inert_on_stderr_without_progress() {
    const HOSTILE_NAME: &str =
        "evil\u{1b}]0;pwned\u{7}\u{1b}[2J\nWARN forged entry\rreplaced\u{202e}sj.py";
    const ESCAPED_NAME: &str =
        "evil\\u{1b}]0;pwned\\u{7}\\u{1b}[2J\\u{a}WARN forged entry\\u{d}replaced\\u{202e}sj.py";

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "x = 1\n").unwrap();
    std::os::unix::fs::symlink("missing-target", dir.path().join(HOSTILE_NAME)).unwrap();

    let assertion = bughunter()
        .args(["analyze", "--static-only", "--no-progress"])
        .args(["--project", dir.path().to_str().unwrap()])
        .env("BUGHUNTER_LOG_LEVEL", "warn")
        .assert()
        .success();
    let stderr = String::from_utf8(assertion.get_output().stderr.clone()).unwrap();

    let warning = stderr
        .lines()
        .find(|line| line.contains("failed to resolve path against project root"))
        .unwrap_or_else(|| panic!("expected the broken symlink warning in {stderr:?}"));
    assert!(
        warning.contains(ESCAPED_NAME),
        "hostile name was not escaped inside a single line: {warning:?}"
    );
    assert!(
        stderr
            .chars()
            .all(|character| character == '\n'
                || (!character.is_control() && character != '\u{202e}')),
        "raw control character reached stderr: {stderr:?}"
    );
}

fn write_mcp_context(directory: &tempfile::TempDir) -> std::path::PathBuf {
    let context_path = directory.path().join("mcp.json");
    let context = serde_json::json!({
        "project_root": directory.path(),
        "engine_config": bughunter::EngineConfig::default(),
        "findings_path": directory.path().join("findings.jsonl"),
        "activity_path": directory.path().join("activity.jsonl"),
        "finding_id_start": 1,
        "changed_lines": null
    });
    std::fs::write(&context_path, serde_json::to_vec(&context).unwrap()).unwrap();
    context_path
}

#[test]
fn mcp_server_rejects_noise_ignores_notifications_and_answers_ping() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("a.rs"), "fn main() {}\n").unwrap();
    let context_path = write_mcp_context(&directory);
    let input = concat!(
        "\n",
        "not json\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\"}\n"
    );

    let assertion = bughunter()
        .arg("mcp-serve")
        .env("BUGHUNTER_MCP_CONTEXT", context_path)
        .write_stdin(input)
        .assert()
        .success();
    let stdout = String::from_utf8(assertion.get_output().stdout.clone()).unwrap();
    let responses: Vec<serde_json::Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();

    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["id"], serde_json::Value::Null);
    assert_eq!(responses[0]["error"]["code"], -32700);
    assert_eq!(responses[1]["id"], 7);
    assert_eq!(responses[1]["result"], serde_json::json!({}));
}

#[test]
fn mcp_server_executes_ast_searches_against_project_files() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("a.rs"), "fn target() {}\n").unwrap();
    let context_path = write_mcp_context(&directory);
    let input = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 8,
        "method": "tools/call",
        "params": {
            "name": "search_ast",
            "arguments": {
                "path": "a.rs",
                "query": "(function_item) @function",
                "language": "rust"
            }
        }
    })
    .to_string();

    let assertion = bughunter()
        .arg("mcp-serve")
        .env("BUGHUNTER_MCP_CONTEXT", context_path)
        .write_stdin(format!("{input}\n"))
        .assert()
        .success();
    let response: serde_json::Value =
        serde_json::from_slice(&assertion.get_output().stdout).unwrap();
    let matches: serde_json::Value =
        serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap();

    assert_eq!(response["id"], 8);
    assert_eq!(matches[0]["line_start"], 1);
    assert_eq!(matches[0]["line_end"], 1);
    assert_eq!(matches[0]["matched_code"], "fn target() {}");
}

#[test]
fn mcp_server_rejects_an_oversized_line_and_processes_the_next_request() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("a.rs"), "fn main() {}\n").unwrap();
    let context_path = write_mcp_context(&directory);
    let mut input = vec![b'x'; 1024 * 1024 + 1];
    input.extend_from_slice(b"\n{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"ping\"}\n");

    let assertion = bughunter()
        .arg("mcp-serve")
        .env("BUGHUNTER_MCP_CONTEXT", context_path)
        .write_stdin(input)
        .assert()
        .success();
    let stdout = String::from_utf8(assertion.get_output().stdout.clone()).unwrap();
    let responses: Vec<serde_json::Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();

    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["error"]["code"], -32600);
    assert_eq!(responses[1]["id"], 9);
}

#[test]
fn mcp_server_requires_a_valid_context_file() {
    bughunter()
        .arg("mcp-serve")
        .env_remove("BUGHUNTER_MCP_CONTEXT")
        .assert()
        .failure()
        .stderr(predicate::str::contains("BUGHUNTER_MCP_CONTEXT not set"));

    let directory = tempfile::tempdir().unwrap();
    let context_path = directory.path().join("mcp.json");
    std::fs::write(&context_path, b"not json").unwrap();
    bughunter()
        .arg("mcp-serve")
        .env("BUGHUNTER_MCP_CONTEXT", context_path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("mcp server failed"));
}

#[test]
fn mcp_server_enforces_the_session_request_budget() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("a.rs"), "fn main() {}\n").unwrap();
    let context_path = write_mcp_context(&directory);
    let input = (0..=4096)
        .map(|id| format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"ping\"}}\n"))
        .collect::<String>();

    bughunter()
        .arg("mcp-serve")
        .env("BUGHUNTER_MCP_CONTEXT", context_path)
        .write_stdin(input)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "MCP session exceeds 4096 requests",
        ));
}

#[test]
fn documented_category_and_shard_timeout_environment_values_are_loaded() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("app.py"), "# TODO: fix\n").unwrap();

    bughunter()
        .args(["analyze", "--static-only"])
        .args(["--project", directory.path().to_str().unwrap()])
        .env("BUGHUNTER_CATEGORIES", "quality")
        .env("BUGHUNTER_MAX_SHARD_SECONDS", "300")
        .assert()
        .success()
        .stdout(predicate::str::contains("TODO comment found"));
}

#[cfg(unix)]
#[test]
fn interactive_ai_failure_restores_a_pseudo_terminal() {
    use std::os::unix::fs::PermissionsExt;

    if !std::path::Path::new("/usr/bin/script").is_file() {
        return;
    }

    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("app.py"), "value = 1\n").unwrap();
    let claude = directory.path().join("claude");
    std::fs::write(
        &claude,
        "#!/bin/sh\nprintf '%s\\n' '{\"is_error\":false,\"result\":\"done\"}'\n",
    )
    .unwrap();
    std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o755)).unwrap();
    let report = directory.path().join("report.json");
    let command = format!(
        "{} analyze --ai-only --project {} --output {}",
        env!("CARGO_BIN_EXE_bughunter"),
        directory.path().display(),
        report.display()
    );

    let output = std::process::Command::new("/usr/bin/script")
        .args(["-qec", &command, "/dev/null"])
        .env_remove("CI")
        .env("HOME", directory.path())
        .env("BUGHUNTER_CLAUDE_CLI_BINARY", &claude)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let terminal_output = String::from_utf8_lossy(&output.stdout);
    assert!(
        terminal_output.contains("\u{1b}[?1049h"),
        "{terminal_output:?}"
    );
    assert!(
        terminal_output.contains("\u{1b}[?1049l"),
        "{terminal_output:?}"
    );
}

#[test]
fn version_subcommand_prints_the_public_version() {
    bughunter()
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

fn write_claude_stub(path: &std::path::Path) {
    std::fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).unwrap();
    }
}

fn write_config(directory: &std::path::Path, name: &str, contents: &str) -> std::path::PathBuf {
    let path = directory.join(name);
    std::fs::write(&path, contents).unwrap();
    path
}

#[test]
fn doctor_defaults_to_the_working_directory_and_the_built_in_configuration() {
    let project = tempfile::tempdir().unwrap();
    let binary = project.path().join("claude");
    write_claude_stub(&binary);
    let canonical = std::fs::canonicalize(project.path()).unwrap();

    bughunter()
        .arg("doctor")
        .current_dir(project.path())
        .env("BUGHUNTER_CLAUDE_CLI_BINARY", binary.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "project: {}",
            canonical.display()
        )))
        .stdout(predicate::str::contains("config: none (built-in defaults)"))
        .stdout(predicate::str::contains("backend: claude-cli"))
        .stdout(predicate::str::contains(format!(
            "ready: executable at {}",
            binary.display()
        )));
}

#[test]
fn doctor_ignores_llm_fields_from_an_automatically_discovered_project_config() {
    let project = tempfile::tempdir().unwrap();
    let binary = project.path().join("claude");
    write_claude_stub(&binary);
    write_config(
        project.path(),
        ".bughunter.toml",
        "[llm]\nbackend = \"openai-compatible\"\n\
         api_url = \"https://project.example/v1\"\n\
         model = \"project-model\"\n",
    );

    bughunter()
        .args(["doctor", "--project", project.path().to_str().unwrap()])
        .env("BUGHUNTER_CLAUDE_CLI_BINARY", binary.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("backend: claude-cli"))
        .stdout(predicate::str::contains("project.example").not())
        .stdout(predicate::str::contains(format!(
            "ready: executable at {}",
            binary.display()
        )));
}

#[test]
fn doctor_reports_a_ready_claude_backend_for_the_selected_project() {
    let project = tempfile::tempdir().unwrap();
    let binary = project.path().join("claude");
    write_claude_stub(&binary);
    let config = write_config(
        project.path(),
        "trusted.toml",
        &format!(
            "[llm]\nbackend = \"claude-cli\"\nclaude_cli_binary = \"{}\"\n",
            binary.display()
        ),
    );
    let canonical = std::fs::canonicalize(project.path()).unwrap();

    bughunter()
        .args(["doctor", "--project", project.path().to_str().unwrap()])
        .args(["--config", config.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "project: {}",
            canonical.display()
        )))
        .stdout(predicate::str::contains(format!(
            "config: {}",
            canonical.join("trusted.toml").display()
        )))
        .stdout(predicate::str::contains(format!(
            "ready: executable at {}",
            binary.display()
        )));
}

#[test]
fn doctor_reports_a_missing_claude_binary_as_an_unavailable_backend() {
    let project = tempfile::tempdir().unwrap();
    let missing = project.path().join("absent-claude");
    let config = write_config(
        project.path(),
        "trusted.toml",
        &format!(
            "[llm]\nbackend = \"claude-cli\"\nclaude_cli_binary = \"{}\"\n",
            missing.display()
        ),
    );

    bughunter()
        .args(["doctor", "--project", project.path().to_str().unwrap()])
        .args(["--config", config.to_str().unwrap()])
        .assert()
        .code(3)
        .stdout(predicate::str::contains("backend: claude-cli"))
        .stdout(predicate::str::contains(format!(
            "missing: {:?} is not an executable file",
            missing.display().to_string()
        )))
        .stdout(predicate::str::contains(
            "remedy: install the Claude CLI or set BUGHUNTER_CLAUDE_CLI_BINARY to its path",
        ));
}

#[test]
fn doctor_reports_missing_openai_settings_as_a_configuration_error() {
    let project = tempfile::tempdir().unwrap();

    bughunter()
        .args(["doctor", "--project", project.path().to_str().unwrap()])
        .env("BUGHUNTER_BACKEND", "openai-compatible")
        .env("BUGHUNTER_API_URL", "https://api.example.com/v1")
        .env("BUGHUNTER_MODEL", "test-model")
        .assert()
        .code(2)
        .stdout(predicate::str::contains("backend: openai-compatible"))
        .stdout(predicate::str::contains(
            "invalid: missing required config: BUGHUNTER_API_TOKEN",
        ));
}

#[test]
fn doctor_checks_the_openai_backend_without_sending_it_a_request() {
    let backend = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let api_url = format!("http://{}/v1", backend.local_addr().unwrap());
    backend.set_nonblocking(true).unwrap();
    let project = tempfile::tempdir().unwrap();

    bughunter()
        .args(["doctor", "--project", project.path().to_str().unwrap()])
        .env("BUGHUNTER_BACKEND", "openai-compatible")
        .env("BUGHUNTER_API_URL", &api_url)
        .env("BUGHUNTER_API_TOKEN", "secret-token")
        .env("BUGHUNTER_MODEL", "test-model")
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "ready: model test-model at {api_url}"
        )))
        .stdout(predicate::str::contains("secret-token").not());

    let refused = backend.accept().unwrap_err();
    assert_eq!(
        refused.kind(),
        std::io::ErrorKind::WouldBlock,
        "doctor must not open a connection to the configured backend"
    );
}

#[test]
fn doctor_resolves_configuration_through_the_analyze_loader_precedence() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir(home.path().join(".bughunter")).unwrap();
    let user_config = write_config(
        &home.path().join(".bughunter"),
        "config.toml",
        "[llm]\nbackend = \"openai-compatible\"\napi_url = \"https://user.example.com/v1\"\nmodel = \"user-model\"\n",
    );
    write_config(
        project.path(),
        ".bughunter.toml",
        "[llm]\nmodel = \"project-model\"\n",
    );
    let explicit = write_config(
        project.path(),
        "explicit.toml",
        "[llm]\nmodel = \"explicit-model\"\n",
    );
    let canonical = std::fs::canonicalize(project.path()).unwrap();

    bughunter()
        .env("HOME", home.path())
        .env("BUGHUNTER_API_TOKEN", "secret-token")
        .args(["doctor", "--project", project.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "config: {}, {}",
            user_config.display(),
            canonical.join(".bughunter.toml").display()
        )))
        .stdout(predicate::str::contains(
            "ready: model user-model at https://user.example.com/v1",
        ));

    bughunter()
        .env("HOME", home.path())
        .env("BUGHUNTER_API_TOKEN", "secret-token")
        .args(["doctor", "--project", project.path().to_str().unwrap()])
        .args(["--config", explicit.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "config: {}, {}",
            user_config.display(),
            explicit.display()
        )))
        .stdout(predicate::str::contains(
            "ready: model explicit-model at https://user.example.com/v1",
        ));
}

#[test]
fn doctor_rejects_a_project_and_a_config_path_it_cannot_read() {
    let project = tempfile::tempdir().unwrap();

    bughunter()
        .args([
            "doctor",
            "--project",
            project.path().join("absent").to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("cannot resolve"));

    bughunter()
        .args(["doctor", "--project", project.path().to_str().unwrap()])
        .args([
            "--config",
            project.path().join("absent.toml").to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("config file not found"));
}

#[cfg(target_os = "linux")]
#[test]
fn doctor_reports_a_stdout_it_cannot_write() {
    let project = tempfile::tempdir().unwrap();
    let binary = project.path().join("claude");
    write_claude_stub(&binary);
    let unwritable = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();

    let output = isolated_command(project.path())
        .args(["doctor", "--project", project.path().to_str().unwrap()])
        .env("BUGHUNTER_CLAUDE_CLI_BINARY", binary.to_str().unwrap())
        .stdout(std::process::Stdio::from(unwritable))
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap();

    assert_eq!(output.status.code(), Some(4));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("failed to write report to stdout"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn version_reports_a_stdout_it_cannot_flush() {
    let unwritable = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();

    let output = isolated_command(TEST_HOME.path())
        .arg("version")
        .stdout(std::process::Stdio::from(unwritable))
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap();

    assert_eq!(output.status.code(), Some(4));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("failed to write report to stdout"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn init_reports_a_stdout_it_cannot_flush_after_creating_the_configuration() {
    let project = tempfile::tempdir().unwrap();
    let unwritable = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();

    let output = isolated_command(TEST_HOME.path())
        .args(["init", "--project", project.path().to_str().unwrap()])
        .stdout(std::process::Stdio::from(unwritable))
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap();

    assert_eq!(output.status.code(), Some(4));
    assert!(project.path().join(".bughunter.toml").is_file());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("failed to write report to stdout"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
