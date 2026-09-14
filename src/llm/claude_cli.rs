use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, Command};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout_at};
use tracing::{debug, info, warn};

use crate::cancel::CancelToken;
use crate::config::EngineConfig;
use crate::config::schema::{BackendConfig, LlmConfig};
use crate::errors::LlmError;
use crate::report::Finding;
use crate::shared::read_bounded_string;

use super::coverage::dedupe_findings;
use super::mcp_server::McpContext;
use super::review_scope::ChangedLines;
use super::tools::{ToolName, build_tool_config};

const MCP_SERVER_NAME: &str = "bughunter";
const NO_TOOL_CALLS: &str =
    "claude CLI made no tool calls; the scan inspected nothing and cannot be trusted";
const MAX_CLI_STDERR_BYTES: usize = 1024 * 1024;
const MAX_CLI_STDOUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_MCP_ACTIVITY_BYTES: usize = 16 * 1024 * 1024;
const MAX_MCP_FINDINGS_BYTES: usize = 32 * 1024 * 1024;
const NO_BUILTIN_TOOLS: &str = "";
const NO_SETTING_SOURCES: &str = "";
const NON_MUTATING_PERMISSION_MODE: &str = "default";
const REMOVED_CREDENTIAL_ENVIRONMENT_VARIABLES: [&str; 3] =
    ["BUGHUNTER_API_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"];
const CREDENTIAL_ENVIRONMENT_VARIABLE_SUFFIXES: [&str; 6] = [
    "_API_KEY",
    "_CUSTOM_HEADERS",
    "_PASSPHRASE",
    "_PASSWORD",
    "_SECRET",
    "_TOKEN",
];
const CREDENTIAL_ENVIRONMENT_VARIABLE_NAMES: [&str; 4] = [
    "AWS_ACCESS_KEY_ID",
    "AWS_BEARER_TOKEN_BEDROCK",
    "AWS_SECRET_ACCESS_KEY",
    "IDENTITY_HEADER",
];
const PROXY_ENVIRONMENT_VARIABLE_NAMES: [&str; 2] = ["HTTP_PROXY", "HTTPS_PROXY"];
const DEFAULT_CLAUDE_EFFORT: &str = "low";

fn ends_with_ignore_ascii_case(value: &str, suffix: &str) -> bool {
    value
        .len()
        .checked_sub(suffix.len())
        .and_then(|start| value.get(start..))
        .is_some_and(|ending| ending.eq_ignore_ascii_case(suffix))
}

fn is_credential_environment_variable(name: &str) -> bool {
    CREDENTIAL_ENVIRONMENT_VARIABLE_SUFFIXES
        .iter()
        .any(|suffix| ends_with_ignore_ascii_case(name, suffix))
        || CREDENTIAL_ENVIRONMENT_VARIABLE_NAMES
            .iter()
            .any(|credential_name| name.eq_ignore_ascii_case(credential_name))
}

fn is_proxy_environment_variable(name: &str) -> bool {
    PROXY_ENVIRONMENT_VARIABLE_NAMES
        .iter()
        .any(|proxy_name| name.eq_ignore_ascii_case(proxy_name))
}

#[derive(Debug, Default)]
struct CredentialRedactor {
    representations: Vec<String>,
}

impl CredentialRedactor {
    fn from_environment() -> Self {
        Self::from_environment_values(std::env::vars_os().collect())
    }

    fn from_environment_values(environment: Vec<(std::ffi::OsString, std::ffi::OsString)>) -> Self {
        let mut values = Vec::new();
        for (variable, value) in environment {
            let variable = variable.to_string_lossy();
            let is_credential = is_credential_environment_variable(&variable);
            let is_proxy = is_proxy_environment_variable(&variable);
            if !is_credential && !is_proxy {
                continue;
            }
            let value = value.to_string_lossy().into_owned();
            if variable.eq_ignore_ascii_case("ANTHROPIC_CUSTOM_HEADERS") {
                Self::append_custom_header_credentials(&mut values, &value);
                values.push(value);
            } else if is_proxy {
                Self::append_proxy_credentials(&mut values, &value);
            } else {
                values.push(value);
            }
        }
        Self::from_values(values)
    }

    fn append_custom_header_credentials(values: &mut Vec<String>, headers: &str) {
        for header in headers.lines() {
            let (name, value) = header.split_once(':').unwrap_or(("", header));
            let value = value.trim();
            values.push(value.to_owned());
            if name.trim().eq_ignore_ascii_case("authorization")
                && let Some(separator) = value.as_bytes().iter().position(u8::is_ascii_whitespace)
            {
                values.push(value[separator..].trim().to_owned());
            }
        }
    }

    fn append_proxy_credentials(values: &mut Vec<String>, proxy: &str) {
        let Ok(parsed_proxy) = reqwest::Url::parse(proxy) else {
            return;
        };
        let username = parsed_proxy.username();
        let password = parsed_proxy.password();
        if username.is_empty() && password.is_none() {
            return;
        }
        values.push(proxy.to_owned());
        Self::append_percent_encoded_credential(values, username);
        if let Some(password) = password {
            Self::append_percent_encoded_credential(values, password);
        }
    }

    fn append_percent_encoded_credential(values: &mut Vec<String>, credential: &str) {
        values.push(credential.to_owned());
        if let Some(decoded) = percent_decode_if_encoded(credential) {
            values.push(decoded);
        }
    }

    fn from_values(values: Vec<String>) -> Self {
        let mut representations = Vec::new();
        for value in values.into_iter().filter(|value| !value.is_empty()) {
            let json = serde_json::Value::String(value.clone()).to_string();
            representations.push(json[1..json.len() - 1].to_string());
            representations.push(json);
            representations.push(percent_encode(&value, false));
            representations.push(percent_encode(&value, true));
            representations.push(value);
        }
        representations.sort_unstable_by(|left, right| {
            right.len().cmp(&left.len()).then_with(|| left.cmp(right))
        });
        representations.dedup();
        Self { representations }
    }

    fn redact(&self, text: &str) -> String {
        let mut redacted = text.to_string();
        for representation in &self.representations {
            redacted = redacted.replace(representation, "<redacted>");
        }
        redacted
    }
}

fn percent_decode_if_encoded(value: &str) -> Option<String> {
    if !value.as_bytes().contains(&b'%') {
        return None;
    }
    let mut encoded = value.bytes();
    let mut decoded = Vec::with_capacity(value.len());
    while let Some(byte) = encoded.next() {
        if byte == b'%' {
            let high = char::from(encoded.next()?).to_digit(16)? as u8;
            let low = char::from(encoded.next()?).to_digit(16)? as u8;
            decoded.push((high << 4) | low);
        } else {
            decoded.push(byte);
        }
    }
    String::from_utf8(decoded).ok()
}

fn percent_encode(value: &str, lowercase: bool) -> String {
    let hexadecimal = match lowercase {
        true => b"0123456789abcdef",
        false => b"0123456789ABCDEF",
    };
    let mut encoded = String::with_capacity(value.len().saturating_mul(3));
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(hexadecimal[usize::from(byte >> 4)]));
            encoded.push(char::from(hexadecimal[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

#[derive(Debug)]
pub struct McpAnalysis {
    pub findings: Vec<Finding>,
    pub inspected_files: BTreeSet<String>,
    pub tool_calls: u32,
}

pub(crate) struct McpAnalysisRequest<'a> {
    pub(crate) config: &'a LlmConfig,
    pub(crate) engine_config: &'a EngineConfig,
    pub(crate) project_root: &'a Path,
    pub(crate) backend_working_directory: Option<&'a Path>,
    pub(crate) system_prompt: &'a str,
    pub(crate) repo_map: &'a str,
    pub(crate) finding_id_start: u32,
    pub(crate) changed_lines: Option<&'a ChangedLines>,
    pub(crate) cancel: &'a CancelToken,
}

#[derive(Debug, Deserialize)]
struct ActivityEntry {
    tool: String,
    #[serde(default)]
    path: Option<String>,
}

pub(crate) async fn run_mcp_analysis(
    request: McpAnalysisRequest<'_>,
) -> Result<McpAnalysis, LlmError> {
    let forbidden_root = (request.engine_config.discovery_source
        == crate::config::schema::DiscoverySource::UntrustedSnapshot)
        .then_some(request.project_root);
    let binary = resolve_configured_cli_binary(
        request.config,
        request.backend_working_directory,
        forbidden_root,
    )?;
    let (workspace, cli_working_directory) = create_workspaces(&mut tempfile::tempdir)?;
    let context_path = workspace.path().join("context.json");
    let findings_path = workspace.path().join("findings.jsonl");
    let activity_path = workspace.path().join("activity.jsonl");
    let mcp_config_path = workspace.path().join("mcp.json");

    let exe = map_io_result("resolve own binary path", std::env::current_exe())?;

    let context = McpContext {
        project_root: request.project_root.to_path_buf(),
        engine_config: request.engine_config.clone(),
        findings_path: findings_path.clone(),
        activity_path: activity_path.clone(),
        finding_id_start: request.finding_id_start,
        changed_lines: request.changed_lines.cloned(),
    };
    write_serialized_json(&context_path, serde_json::to_string(&context))?;
    let serialized_mcp_config = serde_json::to_string(&mcp_config(&exe, &context_path));
    write_serialized_json(&mcp_config_path, serialized_mcp_config)?;

    let prompt = build_prompt(request.system_prompt, request.repo_map);
    let credential_redactor = CredentialRedactor::from_environment();
    let output = invoke_cli(
        request.config,
        &binary,
        &mcp_config_path,
        cli_working_directory.path(),
        &prompt,
        request.cancel,
    )
    .await?;
    check_cli_error(&output, &credential_redactor)?;

    let activity = read_activity(&activity_path)?;
    reject_uninspected_scan(&activity)?;

    let analysis = McpAnalysis {
        tool_calls: activity.len() as u32,
        findings: dedupe_findings(read_findings(&findings_path)?),
        inspected_files: distinct_read_paths(&activity),
    };
    info!(
        count = analysis.findings.len(),
        tool_calls = analysis.tool_calls,
        inspected = analysis.inspected_files.len(),
        "claude CLI (MCP) analysis complete"
    );
    Ok(analysis)
}

fn mcp_config(exe: &Path, context_path: &Path) -> serde_json::Value {
    serde_json::json!({
        "mcpServers": {
            MCP_SERVER_NAME: {
                "command": exe.to_string_lossy(),
                "args": ["mcp-serve"],
                "env": { "BUGHUNTER_MCP_CONTEXT": context_path.to_string_lossy() }
            }
        }
    })
}

fn build_prompt(system_prompt: &str, repo_map: &str) -> String {
    format!(
        "{system_prompt}\n\n\
         The analysis tools listed above are available to you as MCP tools named \
         `mcp__{MCP_SERVER_NAME}__<tool>` (for example `mcp__{MCP_SERVER_NAME}__read_file` \
         and `mcp__{MCP_SERVER_NAME}__submit_findings`). Use them to explore the code and \
         report every issue via submit_findings. Do not stop until you have inspected the \
         suspicious areas.\n\n\
         Here is the repository map:\n\n{repo_map}"
    )
}

fn allowed_tools() -> String {
    build_tool_config()
        .tools
        .iter()
        .map(|tool| format!("mcp__{MCP_SERVER_NAME}__{}", tool.tool_spec.name))
        .collect::<Vec<_>>()
        .join(",")
}

struct CliInvocation<'a> {
    binary: &'a Path,
    model: &'a str,
    effort: &'a str,
    mcp_config_path: &'a Path,
    working_directory: &'a Path,
    allowed_tools: &'a str,
}

async fn invoke_cli(
    config: &LlmConfig,
    binary: &Path,
    mcp_config_path: &Path,
    working_directory: &Path,
    prompt: &str,
    cancel: &CancelToken,
) -> Result<std::process::Output, LlmError> {
    let allowed_tools = allowed_tools();
    let invocation = CliInvocation {
        binary,
        model: config.model.trim(),
        effort: config
            .reasoning_effort
            .as_deref()
            .unwrap_or(DEFAULT_CLAUDE_EFFORT),
        mcp_config_path,
        working_directory,
        allowed_tools: &allowed_tools,
    };
    debug!(
        prompt_bytes = prompt.len(),
        tools = %allowed_tools,
        "invoking claude CLI with MCP"
    );

    let mut command = cli_command(&invocation);
    let (child, group) = crate::process::spawn_tokio_grouped(&mut command)
        .await
        .map_err(|error| spawn_error(&binary.display().to_string(), error))?;
    let mut session = CliSession::start(child, group, analysis_budget(config));
    session.collect_output(prompt, cancel).await
}

fn analysis_budget(config: &LlmConfig) -> Duration {
    Duration::from_secs(config.max_shard_seconds)
}

fn configured_cli_binary(config: &LlmConfig) -> Result<&str, LlmError> {
    match &config.backend {
        BackendConfig::ClaudeCli { binary } => Ok(binary),
        _ => Err(LlmError::ClaudeProcess {
            code: None,
            stderr: "claude CLI backend is not configured".into(),
        }),
    }
}

#[cfg(windows)]
const DEFAULT_WINDOWS_PATH_EXTENSIONS: &str = ".COM;.EXE;.BAT;.CMD";
#[cfg(any(windows, test))]
const WINDOWS_EXECUTABLE_EXTENSIONS: [(&str, &str); 4] = [
    ("com", ".COM"),
    ("exe", ".EXE"),
    ("bat", ".BAT"),
    ("cmd", ".CMD"),
];

fn resolve_configured_cli_binary(
    config: &LlmConfig,
    working_directory: Option<&Path>,
    forbidden_root: Option<&Path>,
) -> Result<PathBuf, LlmError> {
    let binary = configured_cli_binary(config)?;
    let search_path = std::env::var_os("PATH");
    let path_extensions = std::env::var_os("PATHEXT");
    resolve_cli_binary(
        binary,
        working_directory,
        search_path.as_deref(),
        path_extensions.as_deref(),
        forbidden_root,
    )
    .ok_or_else(|| {
        spawn_error(
            binary,
            std::io::Error::new(std::io::ErrorKind::NotFound, "program not found"),
        )
    })
}

pub(crate) fn resolve_cli_binary(
    binary: &str,
    working_directory: Option<&Path>,
    search_path: Option<&OsStr>,
    path_extensions: Option<&OsStr>,
    forbidden_root: Option<&Path>,
) -> Option<PathBuf> {
    if !is_bare_cli_name(binary) {
        return executable_candidate(
            Path::new(binary),
            working_directory,
            path_extensions,
            forbidden_root,
        );
    }
    std::env::split_paths(search_path?).find_map(|directory| {
        executable_candidate(
            &directory.join(binary),
            working_directory,
            path_extensions,
            forbidden_root,
        )
    })
}

fn executable_candidate(
    candidate: &Path,
    working_directory: Option<&Path>,
    path_extensions: Option<&OsStr>,
    forbidden_root: Option<&Path>,
) -> Option<PathBuf> {
    let path = match candidate.is_absolute() {
        true => candidate.to_path_buf(),
        false => working_directory?.join(candidate),
    };
    let executable = platform_executable_candidate(path, path_extensions)?;
    if forbidden_root.is_some_and(|root| executable_is_within_root(&executable, root)) {
        return None;
    }
    Some(executable)
}

fn executable_is_within_root(candidate: &Path, root: &Path) -> bool {
    candidate.starts_with(root)
        || candidate.canonicalize().ok().is_some_and(|candidate| {
            root.canonicalize()
                .ok()
                .is_some_and(|root| candidate.starts_with(root))
        })
}

#[cfg(not(windows))]
fn platform_executable_candidate(
    path: PathBuf,
    _path_extensions: Option<&OsStr>,
) -> Option<PathBuf> {
    is_executable_file(&path).then_some(path)
}

#[cfg(windows)]
fn platform_executable_candidate(
    path: PathBuf,
    path_extensions: Option<&OsStr>,
) -> Option<PathBuf> {
    if path.extension().is_some() {
        return is_executable_file(&path).then_some(path);
    }
    let extensions = path_extensions
        .and_then(OsStr::to_str)
        .unwrap_or(DEFAULT_WINDOWS_PATH_EXTENSIONS);
    for extension in extensions
        .split(';')
        .filter_map(canonical_windows_path_extension)
    {
        let mut candidate = path.as_os_str().to_os_string();
        candidate.push(extension);
        let candidate = PathBuf::from(candidate);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(any(windows, test))]
fn canonical_windows_path_extension(extension: &str) -> Option<&'static str> {
    let extension = extension.trim();
    WINDOWS_EXECUTABLE_EXTENSIONS
        .iter()
        .find_map(|(_, canonical)| {
            extension
                .eq_ignore_ascii_case(canonical)
                .then_some(*canonical)
        })
}

pub(crate) fn is_bare_cli_name(binary: &str) -> bool {
    Path::new(binary)
        .parent()
        .is_none_or(|parent| parent.as_os_str().is_empty())
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    std::fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(windows)]
fn is_executable_file(path: &Path) -> bool {
    let supported_extension = path
        .extension()
        .and_then(OsStr::to_str)
        .is_some_and(|extension| {
            WINDOWS_EXECUTABLE_EXTENSIONS
                .iter()
                .any(|(supported, _)| extension.eq_ignore_ascii_case(supported))
        });
    supported_extension && std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
}

#[cfg(not(any(unix, windows)))]
fn is_executable_file(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
}

fn cli_command(invocation: &CliInvocation<'_>) -> Command {
    let mut command = Command::new(invocation.binary);
    command
        .arg("-p")
        .arg("--output-format")
        .arg("json")
        .arg("--mcp-config")
        .arg(invocation.mcp_config_path)
        .arg("--strict-mcp-config")
        .arg("--tools")
        .arg(NO_BUILTIN_TOOLS)
        .arg("--allowedTools")
        .arg(invocation.allowed_tools)
        .arg("--permission-mode")
        .arg(NON_MUTATING_PERMISSION_MODE)
        .arg("--setting-sources")
        .arg(NO_SETTING_SOURCES)
        .arg("--effort")
        .arg(invocation.effort)
        .arg("--no-session-persistence");
    if !invocation.model.is_empty() {
        command.arg("--model").arg(invocation.model);
    }
    command
        .current_dir(invocation.working_directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for variable in REMOVED_CREDENTIAL_ENVIRONMENT_VARIABLES {
        command.env_remove(variable);
    }
    command
}

#[derive(Clone, Copy)]
struct LifecycleDeadline {
    expires_at: Instant,
    budget: Duration,
}

impl LifecycleDeadline {
    fn starting_now(budget: Duration) -> Self {
        Self {
            expires_at: Instant::now() + budget,
            budget,
        }
    }

    async fn guard<T>(
        self,
        cancel: &CancelToken,
        work: impl Future<Output = Result<T, LlmError>>,
    ) -> Result<T, LlmError> {
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(LlmError::Cancelled),
            outcome = timeout_at(self.expires_at, work) => outcome.unwrap_or_else(|_| {
                Err(LlmError::Timeout {
                    timeout_seconds: self.budget.as_secs(),
                })
            }),
        }
    }
}

type GroupTerminate = fn(&mut crate::process::ProcessGroup) -> std::io::Result<()>;

struct CliSession {
    child: Child,
    group: Option<crate::process::ProcessGroup>,
    stdin: Option<ChildStdin>,
    stdout: DrainedPipe,
    stderr: DrainedPipe,
    deadline: LifecycleDeadline,
    group_terminate: GroupTerminate,
}

impl CliSession {
    fn start(mut child: Child, group: crate::process::ProcessGroup, budget: Duration) -> Self {
        let stdin = child.stdin.take();
        let stdout = DrainedPipe::start(child.stdout.take(), "stdout", MAX_CLI_STDOUT_BYTES);
        let stderr = DrainedPipe::start(child.stderr.take(), "stderr", MAX_CLI_STDERR_BYTES);
        Self {
            child,
            group: Some(group),
            stdin,
            stdout,
            stderr,
            deadline: LifecycleDeadline::starting_now(budget),
            group_terminate: crate::process::try_terminate_group,
        }
    }

    async fn collect_output(
        &mut self,
        prompt: &str,
        cancel: &CancelToken,
    ) -> Result<std::process::Output, LlmError> {
        let outcome = self.capture_output(prompt, cancel).await;
        if outcome.is_err() {
            self.shutdown().await;
        }
        outcome
    }

    async fn capture_output(
        &mut self,
        prompt: &str,
        cancel: &CancelToken,
    ) -> Result<std::process::Output, LlmError> {
        self.write_prompt(prompt, cancel).await?;
        let status = self.await_exit(cancel).await?;
        self.release_process_group()?;
        let (stdout, stderr) = self.capture_pipes(cancel).await?;
        Ok(std::process::Output {
            status,
            stdout: stdout.bytes,
            stderr: stderr.bytes,
        })
    }

    async fn write_prompt(&mut self, prompt: &str, cancel: &CancelToken) -> Result<(), LlmError> {
        let deadline = self.deadline;
        deadline
            .guard(cancel, send_prompt(self.stdin.take(), prompt))
            .await
    }

    async fn await_exit(&mut self, cancel: &CancelToken) -> Result<ExitStatus, LlmError> {
        let deadline = self.deadline;
        deadline.guard(cancel, self.exit_or_capture_failure()).await
    }

    async fn exit_or_capture_failure(&mut self) -> Result<ExitStatus, LlmError> {
        let Self {
            child,
            stdout,
            stderr,
            ..
        } = self;
        tokio::select! {
            biased;
            failure = stdout.watch_for_failure() => Err(failure),
            failure = stderr.watch_for_failure() => Err(failure),
            status = child.wait() => map_wait_result(status),
        }
    }

    async fn capture_pipes(
        &mut self,
        cancel: &CancelToken,
    ) -> Result<(PipeCapture, PipeCapture), LlmError> {
        let deadline = self.deadline;
        deadline.guard(cancel, self.settle_pipes()).await
    }

    async fn settle_pipes(&mut self) -> Result<(PipeCapture, PipeCapture), LlmError> {
        let stdout = self.stdout.settle().await?;
        let stderr = self.stderr.settle().await?;
        Ok((stdout, stderr))
    }

    fn release_process_group(&mut self) -> Result<(), LlmError> {
        let Some(group) = self.group.as_mut() else {
            return Ok(());
        };
        (self.group_terminate)(group).map_err(|source| LlmError::Io {
            action: "terminate claude CLI subprocess tree".to_string(),
            source,
        })?;
        self.group = None;
        Ok(())
    }

    async fn shutdown(&mut self) {
        self.stdin.take();
        let outcome = match self.group.take() {
            Some(group) => crate::process::terminate_tokio(&mut self.child, group).await,
            None if self.child.id().is_some() => {
                let killed = self.child.kill().await;
                let waited = self.child.wait().await.map(|_| ());
                killed.and(waited)
            }
            None => Ok(()),
        };
        report_termination_failure(outcome);
        self.stdout.release().await;
        self.stderr.release().await;
    }
}

impl Drop for CliSession {
    fn drop(&mut self) {
        if let Some(group) = self.group.take() {
            let _ = crate::process::terminate_group(group);
        }
    }
}

fn report_termination_failure(outcome: std::io::Result<()>) {
    if let Err(error) = outcome {
        warn!(error = %error, "failed to terminate claude CLI subprocess tree");
    }
}

async fn send_prompt(stdin: Option<ChildStdin>, prompt: &str) -> Result<(), LlmError> {
    let mut stdin = stdin.ok_or_else(|| LlmError::ClaudeProcess {
        code: None,
        stderr: "claude CLI subprocess did not expose stdin".into(),
    })?;
    let write_result = stdin.write_all(prompt.as_bytes()).await;
    map_io_result("write prompt to claude CLI", write_result)?;
    map_io_result("close claude CLI stdin", stdin.shutdown().await)
}

fn map_wait_result(result: std::io::Result<ExitStatus>) -> Result<ExitStatus, LlmError> {
    map_io_result("wait for claude CLI", result)
}

#[derive(Debug, Default)]
struct PipeCapture {
    bytes: Vec<u8>,
    truncated: bool,
}

fn drain_pipe<R>(pipe: Option<R>, limit: usize) -> JoinHandle<std::io::Result<PipeCapture>>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut captured = PipeCapture::default();
        if let Some(mut pipe) = pipe {
            let mut chunk = [0u8; 8 * 1024];
            while !captured.truncated {
                let read = pipe.read(&mut chunk).await?;
                if read == 0 {
                    break;
                }
                let copied = read.min(limit.saturating_sub(captured.bytes.len()));
                captured.bytes.extend_from_slice(&chunk[..copied]);
                captured.truncated = copied < read;
            }
        }
        Ok(captured)
    })
}

struct DrainedPipe {
    stream: &'static str,
    limit: usize,
    task: Option<JoinHandle<std::io::Result<PipeCapture>>>,
    settled: Option<PipeCapture>,
}

impl DrainedPipe {
    fn start<R>(pipe: Option<R>, stream: &'static str, limit: usize) -> Self
    where
        R: tokio::io::AsyncRead + Unpin + Send + 'static,
    {
        Self {
            stream,
            limit,
            task: Some(drain_pipe(pipe, limit)),
            settled: None,
        }
    }

    async fn watch_for_failure(&mut self) -> LlmError {
        let Some(task) = self.task.as_mut() else {
            return std::future::pending().await;
        };
        let joined = task.await;
        self.task = None;
        match joined {
            Err(error) => reader_task_failure(self.stream, &error),
            Ok(Err(error)) => pipe_read_failure(self.stream, error),
            Ok(Ok(capture)) => {
                let exceeded_limit = capture.truncated;
                self.settled = Some(capture);
                if exceeded_limit {
                    self.limit_exceeded()
                } else {
                    std::future::pending().await
                }
            }
        }
    }

    async fn settle(&mut self) -> Result<PipeCapture, LlmError> {
        if let Some(task) = self.task.as_mut() {
            let joined = task.await;
            self.task = None;
            let capture = joined.map_err(|error| reader_task_failure(self.stream, &error))?;
            self.settled = Some(capture.map_err(|error| pipe_read_failure(self.stream, error))?);
        }
        let capture = self.settled.take().unwrap_or_default();
        if capture.truncated {
            return Err(self.limit_exceeded());
        }
        Ok(capture)
    }

    async fn release(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
        self.settled = None;
    }

    fn limit_exceeded(&self) -> LlmError {
        LlmError::AgentProtocol(format!(
            "claude CLI {} exceeded the {} byte capture limit",
            self.stream, self.limit
        ))
    }
}

fn reader_task_failure(stream: &str, error: &tokio::task::JoinError) -> LlmError {
    LlmError::AgentProtocol(format!("claude CLI {stream} reader failed: {error}"))
}

fn pipe_read_failure(stream: &str, source: std::io::Error) -> LlmError {
    LlmError::Io {
        action: format!("read claude CLI {stream}"),
        source,
    }
}

fn check_cli_error(
    output: &std::process::Output,
    credential_redactor: &CredentialRedactor,
) -> Result<(), LlmError> {
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return Err(LlmError::ClaudeProcess {
            code: output.status.code(),
            stderr: credential_redactor.redact(&format!("{stderr}\n{stdout}")),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(stdout.trim())
        && value.get("is_error").and_then(|v| v.as_bool()) == Some(true)
    {
        let message = value
            .get("result")
            .and_then(|v| v.as_str())
            .unwrap_or("claude CLI reported an error");
        return Err(LlmError::ClaudeProcess {
            code: None,
            stderr: credential_redactor.redact(message),
        });
    }

    Ok(())
}

fn read_activity(activity_path: &Path) -> Result<Vec<ActivityEntry>, LlmError> {
    let raw = match read_bounded_string(activity_path, MAX_MCP_ACTIVITY_BYTES) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(io_error("read MCP activity log", error)),
    };
    parse_json_lines(&raw, "activity")
}

fn reject_uninspected_scan(activity: &[ActivityEntry]) -> Result<(), LlmError> {
    if activity.iter().any(|entry| is_analysis_tool(&entry.tool)) {
        return Ok(());
    }
    Err(LlmError::AgentProtocol(NO_TOOL_CALLS.to_string()))
}

fn is_analysis_tool(tool: &str) -> bool {
    match ToolName::parse(tool) {
        Some(ToolName::SubmitFindings) | None => false,
        Some(_) => true,
    }
}

fn distinct_read_paths(activity: &[ActivityEntry]) -> BTreeSet<String> {
    activity
        .iter()
        .filter(|entry| entry.tool == ToolName::ReadFile.as_str())
        .filter_map(|entry| entry.path.clone())
        .collect()
}

fn read_findings(findings_path: &Path) -> Result<Vec<Finding>, LlmError> {
    let raw = match read_bounded_string(findings_path, MAX_MCP_FINDINGS_BYTES) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(io_error("read findings file", error)),
    };
    parse_json_lines(&raw, "findings")
}

fn parse_json_lines<T>(raw: &str, resource: &str) -> Result<Vec<T>, LlmError>
where
    T: for<'de> Deserialize<'de>,
{
    raw.lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let line = line.trim();
            (!line.is_empty()).then_some((index, line))
        })
        .map(|(index, line)| {
            serde_json::from_str(line).map_err(|error| {
                LlmError::AgentProtocol(format!(
                    "malformed persisted {resource} line {}: {error}",
                    index + 1
                ))
            })
        })
        .collect()
}

fn write_serialized_json(
    path: &Path,
    serialized: Result<String, serde_json::Error>,
) -> Result<(), LlmError> {
    let json = serialized.map_err(|error| {
        LlmError::Serialization(format!("failed to serialize MCP config: {error}"))
    })?;
    std::fs::write(path, json).map_err(|error| io_error("write MCP config file", error))
}

fn create_workspaces(
    create: &mut dyn FnMut() -> std::io::Result<tempfile::TempDir>,
) -> Result<(tempfile::TempDir, tempfile::TempDir), LlmError> {
    let workspace = map_io_result("create temp workspace", create())?;
    let cli_working_directory =
        map_io_result("create isolated claude CLI working directory", create())?;
    Ok((workspace, cli_working_directory))
}

fn map_io_result<T>(action: &str, result: std::io::Result<T>) -> Result<T, LlmError> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => Err(io_error(action, error)),
    }
}

fn io_error(action: &str, err: std::io::Error) -> LlmError {
    LlmError::Io {
        action: action.to_string(),
        source: err,
    }
}

fn spawn_error(binary: &str, err: std::io::Error) -> LlmError {
    LlmError::ClaudeSpawn {
        binary: binary.to_string(),
        source: err,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::time::Instant;

    #[cfg(unix)]
    const AMPLE_BUDGET: Duration = Duration::from_secs(3600);
    #[cfg(unix)]
    const EXHAUSTED_BUDGET: Duration = Duration::ZERO;
    #[cfg(unix)]
    const PROMPT_LARGER_THAN_ANY_PIPE_BUFFER: usize = 4 * 1024 * 1024;
    #[cfg(unix)]
    const NEVER_READS_STDIN: &str = "exec tail -f /dev/null\n";
    #[cfg(unix)]
    const HOLDS_THE_PIPES_FOREVER: &str =
        "sh -c 'exec tail -f /dev/null' &\nexec tail -f /dev/null\n";
    #[cfg(unix)]
    const INFINITE_OVERSIZED_OUTPUT: &str = "cat > /dev/null\nexec cat /dev/zero\n";
    #[cfg(unix)]
    const SUCCEEDS_WITH_A_PIPE_HOLDING_DESCENDANT: &str =
        "sh -c 'exec tail -f /dev/null' &\nprintf '%s\\n' \"$!\"\ncat > /dev/null\n";
    #[cfg(unix)]
    const PROMPT_FAILURE_DEADLINE: Duration = Duration::from_secs(30);

    #[cfg(unix)]
    const RESOLVE_WORKSPACE: &str = r#"set -eu
workspace=""
while [ $# -gt 0 ]; do
  if [ "$1" = "--mcp-config" ]; then
workspace=$(dirname "$2")
  fi
  shift
done
cat > /dev/null
"#;

    #[cfg(unix)]
    const CLI_SUCCESS: &str = "printf '%s\\n' '{\"is_error\":false,\"result\":\"done\"}'\n";

    fn write_executable(path: &Path, body: &str) {
        std::fs::write(path, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(path).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(path, permissions).unwrap();
        }
    }

    fn resolver_executable(directory: &Path) -> PathBuf {
        let binary = directory.join(if cfg!(windows) {
            "claude.cmd"
        } else {
            "claude"
        });
        let body = if cfg!(windows) {
            "@exit /b 0\r\n"
        } else {
            "#!/bin/sh\nexit 0\n"
        };
        write_executable(&binary, body);
        binary
    }

    #[cfg(unix)]
    fn fake_claude(directory: &Path, body: &str) -> LlmConfig {
        let binary = directory.join("claude");
        write_executable(&binary, &format!("#!/bin/sh\n{body}"));
        LlmConfig {
            backend: BackendConfig::ClaudeCli {
                binary: binary.to_string_lossy().into_owned(),
            },
            model: String::new(),
            ..LlmConfig::default()
        }
    }

    #[cfg(unix)]
    fn append_line(file: &str, line: &str) -> String {
        format!("printf '%s\\n' '{line}' >> \"$workspace/{file}\"\n")
    }

    #[cfg(unix)]
    fn recording_claude(directory: &Path, activity: &[&str]) -> LlmConfig {
        let appends: String = activity
            .iter()
            .map(|line| append_line("activity.jsonl", line))
            .collect();
        fake_claude(
            directory,
            &format!("{RESOLVE_WORKSPACE}{appends}{CLI_SUCCESS}"),
        )
    }

    #[cfg(windows)]
    fn windows_recording_claude(directory: &Path) -> LlmConfig {
        let binary = directory.join("claude.cmd");
        write_executable(
            &binary,
            r#"@echo off
setlocal
set "workspace="
:arguments
if "%~1"=="" goto input
if /I "%~1"=="--mcp-config" set "workspace=%~dp2"
shift
goto arguments
:input
more >nul
> "%workspace%activity.jsonl" echo {"tool":"read_file","path":"src/a.rs"}
echo {"is_error":false,"result":"done"}
"#,
        );
        LlmConfig {
            backend: BackendConfig::ClaudeCli {
                binary: binary.to_string_lossy().into_owned(),
            },
            model: String::new(),
            ..LlmConfig::default()
        }
    }

    #[cfg(unix)]
    fn session_command(script: &str) -> Command {
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg(script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        command
    }

    #[cfg(unix)]
    async fn spawn_session(script: &str, budget: Duration) -> CliSession {
        let mut command = session_command(script);
        let (child, group) = crate::process::spawn_tokio_grouped(&mut command)
            .await
            .unwrap();
        CliSession::start(child, group, budget)
    }

    #[cfg(unix)]
    fn oversized_prompt() -> String {
        "x".repeat(PROMPT_LARGER_THAN_ANY_PIPE_BUFFER)
    }

    #[cfg(unix)]
    fn drains_are_blocked(session: &CliSession) -> bool {
        [&session.stdout, &session.stderr]
            .iter()
            .all(|drain| drain.task.as_ref().is_some_and(|task| !task.is_finished()))
    }

    #[cfg(unix)]
    fn drains_are_released(session: &CliSession) -> bool {
        [&session.stdout, &session.stderr]
            .iter()
            .all(|drain| drain.task.is_none() && drain.settled.is_none())
    }

    #[cfg(unix)]
    fn group_is_alive(group: u32) -> bool {
        let group = i32::try_from(group).unwrap();
        unsafe { libc::kill(-group, 0) == 0 }
    }

    #[cfg(unix)]
    async fn await_group_exit(group: u32) {
        tokio::time::timeout(PROMPT_FAILURE_DEADLINE, async {
            while group_is_alive(group) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the subprocess group remained alive after shutdown");
    }

    fn hardened_invocation<'a>(model: &'a str, working_directory: &'a Path) -> CliInvocation<'a> {
        CliInvocation {
            binary: Path::new("claude"),
            model,
            effort: DEFAULT_CLAUDE_EFFORT,
            mcp_config_path: Path::new("/mcp.json"),
            working_directory,
            allowed_tools: "mcp__bughunter__read_file",
        }
    }

    fn collected_args(command: &Command) -> Vec<String> {
        command
            .as_std()
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect()
    }

    fn flag_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
        let position = args.iter().position(|argument| argument.as_str() == flag)?;
        args.get(position + 1).map(String::as_str)
    }

    fn contains_flag(args: &[String], flag: &str) -> bool {
        args.iter().any(|argument| argument.as_str() == flag)
    }

    async fn analyze(config: &LlmConfig, project: &Path) -> Result<McpAnalysis, LlmError> {
        analyze_with_cancel(config, project, &CancelToken::default()).await
    }

    async fn analyze_with_cancel(
        config: &LlmConfig,
        project: &Path,
        cancel: &CancelToken,
    ) -> Result<McpAnalysis, LlmError> {
        analyze_with_repo_map(config, project, "MAP", cancel).await
    }

    async fn analyze_with_repo_map(
        config: &LlmConfig,
        project: &Path,
        repo_map: &str,
        cancel: &CancelToken,
    ) -> Result<McpAnalysis, LlmError> {
        let engine_config = EngineConfig::default();
        for attempt in 0..32 {
            let result = run_mcp_analysis(McpAnalysisRequest {
                config,
                engine_config: &engine_config,
                project_root: project,
                backend_working_directory: Some(project),
                system_prompt: "SYSTEM",
                repo_map,
                finding_id_start: 1,
                changed_lines: None,
                cancel,
            })
            .await;
            match &result {
                Err(LlmError::ClaudeSpawn { source, .. })
                    if source.kind() == std::io::ErrorKind::ExecutableFileBusy && attempt < 31 =>
                {
                    tokio::task::yield_now().await;
                }
                _ => return result,
            }
        }
        unreachable!()
    }

    fn sample_finding_json() -> String {
        let counter = crate::report::FindingCounter::new();
        let mut finding = crate::report::Finding::new_static(
            &counter,
            crate::config::schema::AnalysisCategory::Bug,
            crate::config::schema::Severity::High,
            "t".into(),
            "d".into(),
            "a.rs".into(),
        );
        finding.line_start = Some(1);
        finding.line_end = Some(1);
        serde_json::to_string(&finding).unwrap()
    }

    #[test]
    fn allowed_tools_lists_all_six_mcp_prefixed() {
        let tools = allowed_tools();
        assert!(tools.contains("mcp__bughunter__discover_files"));
        assert!(tools.contains("mcp__bughunter__submit_findings"));
        assert_eq!(tools.split(',').count(), 6);
    }

    #[test]
    fn mcp_config_points_at_this_binary_and_context() {
        let cfg = mcp_config(Path::new("/opt/bughunter"), Path::new("/tmp/ctx.json"));
        assert_eq!(cfg["mcpServers"]["bughunter"]["command"], "/opt/bughunter");
        assert_eq!(cfg["mcpServers"]["bughunter"]["args"][0], "mcp-serve");
        assert_eq!(
            cfg["mcpServers"]["bughunter"]["env"]["BUGHUNTER_MCP_CONTEXT"],
            "/tmp/ctx.json"
        );
    }

    #[test]
    fn prompt_includes_repo_map_and_tool_naming() {
        let prompt = build_prompt("SYSTEM RULES", "FILE TREE HERE");
        assert!(prompt.contains("SYSTEM RULES"));
        assert!(prompt.contains("FILE TREE HERE"));
        assert!(prompt.contains("mcp__bughunter__submit_findings"));
    }

    #[test]
    fn read_findings_parses_valid_jsonl_and_ignores_blank_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.jsonl");
        let line = sample_finding_json();
        std::fs::write(&path, format!("{line}\n\n{line}\n")).unwrap();

        let findings = read_findings(&path).unwrap();
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn read_findings_rejects_a_malformed_record_without_partial_results() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.jsonl");
        let line = sample_finding_json();
        std::fs::write(&path, format!("{line}\nnot json\n{line}\n")).unwrap();

        let error = read_findings(&path).unwrap_err();

        assert!(matches!(
            error,
            LlmError::AgentProtocol(message)
                if message.contains("findings line 2") && !message.contains(&line)
        ));
    }

    #[test]
    fn read_findings_missing_file_is_empty() {
        let findings = read_findings(Path::new("/nonexistent/findings.jsonl")).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn read_activity_parses_valid_jsonl_and_ignores_blank_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("activity.jsonl");
        std::fs::write(
            &path,
            "{\"tool\":\"read_file\",\"path\":\"src/a.rs\"}\n\
         \n\
         {\"tool\":\"discover_files\",\"path\":null}\n",
        )
        .unwrap();

        let entries = read_activity(&path).unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].tool, "read_file");
        assert_eq!(entries[0].path.as_deref(), Some("src/a.rs"));
        assert_eq!(entries[1].tool, "discover_files");
        assert!(entries[1].path.is_none());
    }

    #[test]
    fn read_activity_rejects_a_malformed_record_without_partial_results() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("activity.jsonl");
        std::fs::write(
            &path,
            "{\"tool\":\"read_file\",\"path\":\"src/a.rs\"}\nnot json\n",
        )
        .unwrap();

        let error = read_activity(&path).unwrap_err();

        assert!(matches!(
            error,
            LlmError::AgentProtocol(message) if message.contains("activity line 2")
        ));
    }

    #[test]
    fn read_activity_missing_file_is_empty() {
        let entries = read_activity(Path::new("/nonexistent/activity.jsonl")).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn submit_findings_alone_does_not_count_as_inspection() {
        let activity = vec![ActivityEntry {
            tool: "submit_findings".to_string(),
            path: None,
        }];

        let error = reject_uninspected_scan(&activity).unwrap_err();
        assert!(matches!(&error, LlmError::AgentProtocol(m) if m == NO_TOOL_CALLS));
    }

    #[test]
    fn every_analysis_tool_counts_as_inspection() {
        for tool in [
            "discover_files",
            "search_text",
            "read_file",
            "project_stats",
            "search_ast",
        ] {
            let activity = vec![ActivityEntry {
                tool: tool.to_string(),
                path: None,
            }];
            assert!(reject_uninspected_scan(&activity).is_ok(), "{tool}");
        }
    }

    #[test]
    fn distinct_read_paths_deduplicates_and_ignores_other_tools() {
        let activity = vec![
            ActivityEntry {
                tool: "read_file".to_string(),
                path: Some("src/b.rs".to_string()),
            },
            ActivityEntry {
                tool: "read_file".to_string(),
                path: Some("src/a.rs".to_string()),
            },
            ActivityEntry {
                tool: "read_file".to_string(),
                path: Some("src/a.rs".to_string()),
            },
            ActivityEntry {
                tool: "search_ast".to_string(),
                path: Some("src/c.rs".to_string()),
            },
        ];

        let paths = distinct_read_paths(&activity);

        let expected = BTreeSet::from(["src/a.rs".to_string(), "src/b.rs".to_string()]);
        assert_eq!(paths, expected);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn analysis_without_any_tool_call_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let config = fake_claude(dir.path(), &format!("{RESOLVE_WORKSPACE}{CLI_SUCCESS}"));

        let error = analyze(&config, dir.path()).await.unwrap_err();

        assert!(matches!(&error, LlmError::AgentProtocol(m) if m == NO_TOOL_CALLS));
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn analysis_that_only_submits_findings_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let config = recording_claude(dir.path(), &[r#"{"tool":"submit_findings","path":null}"#]);

        let error = analyze(&config, dir.path()).await.unwrap_err();

        assert!(matches!(&error, LlmError::AgentProtocol(m) if m == NO_TOOL_CALLS));
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn analysis_reports_tool_calls_and_inspected_files() {
        let dir = tempfile::tempdir().unwrap();
        let config = recording_claude(
            dir.path(),
            &[
                r#"{"tool":"discover_files","path":null}"#,
                r#"{"tool":"read_file","path":"src/a.rs"}"#,
                r#"{"tool":"read_file","path":"src/a.rs"}"#,
                r#"{"tool":"read_file","path":"src/b.rs"}"#,
                r#"{"tool":"submit_findings","path":null}"#,
            ],
        );

        let analysis = analyze(&config, dir.path()).await.unwrap();

        let expected = BTreeSet::from(["src/a.rs".to_string(), "src/b.rs".to_string()]);
        assert_eq!(analysis.tool_calls, 5);
        assert_eq!(analysis.inspected_files, expected);
        assert!(analysis.findings.is_empty());
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn relative_cli_path_is_resolved_before_entering_the_isolated_working_directory() {
        let project = tempfile::tempdir().unwrap();
        let tools = project.path().join("tools");
        std::fs::create_dir(&tools).unwrap();
        let binary = tools.join("claude");
        let script = format!(
            "{RESOLVE_WORKSPACE}{activity}{CLI_SUCCESS}",
            activity = append_line(
                "activity.jsonl",
                r#"{"tool":"read_file","path":"src/a.rs"}"#
            ),
        );
        write_executable(&binary, &format!("#!/bin/sh\n{script}"));
        let config = LlmConfig {
            backend: BackendConfig::ClaudeCli {
                binary: "tools/claude".to_string(),
            },
            ..LlmConfig::default()
        };

        let analysis = analyze(&config, project.path()).await.unwrap();

        assert_eq!(analysis.tool_calls, 1);
        assert_eq!(
            analysis.inspected_files,
            BTreeSet::from(["src/a.rs".to_string()])
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn analysis_returns_findings_persisted_by_the_mcp_server() {
        let dir = tempfile::tempdir().unwrap();
        let script = format!(
            "{RESOLVE_WORKSPACE}{activity}{findings}{CLI_SUCCESS}",
            activity = append_line("activity.jsonl", r#"{"tool":"read_file","path":"a.rs"}"#),
            findings = append_line("findings.jsonl", &sample_finding_json()),
        );
        let config = fake_claude(dir.path(), &script);

        let analysis = analyze(&config, dir.path()).await.unwrap();

        assert_eq!(analysis.tool_calls, 1);
        assert_eq!(analysis.findings.len(), 1);
        assert_eq!(analysis.findings[0].title, "t");
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn analysis_deduplicates_repeated_persisted_findings() {
        let dir = tempfile::tempdir().unwrap();
        let finding = sample_finding_json();
        let script = format!(
            "{RESOLVE_WORKSPACE}{activity}{first}{second}{CLI_SUCCESS}",
            activity = append_line("activity.jsonl", r#"{"tool":"read_file","path":"a.rs"}"#),
            first = append_line("findings.jsonl", &finding),
            second = append_line("findings.jsonl", &finding),
        );
        let config = fake_claude(dir.path(), &script);

        let analysis = analyze(&config, dir.path()).await.unwrap();

        assert_eq!(analysis.findings.len(), 1);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failing_cli_is_reported_before_the_activity_check() {
        let dir = tempfile::tempdir().unwrap();
        let config = fake_claude(dir.path(), "cat > /dev/null\nexit 9\n");

        let error = analyze(&config, dir.path()).await.unwrap_err();

        assert!(matches!(
            error,
            LlmError::ClaudeProcess { code: Some(9), .. }
        ));
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn precancelled_token_aborts_the_run_immediately() {
        let dir = tempfile::tempdir().unwrap();
        let config = fake_claude(dir.path(), "exec tail -f /dev/null\n");
        let cancel = CancelToken::default();
        cancel.cancel();

        let started = Instant::now();
        let error = analyze_with_cancel(&config, dir.path(), &cancel)
            .await
            .unwrap_err();

        assert!(matches!(error, LlmError::Cancelled));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_kills_the_running_subprocess() {
        let dir = tempfile::tempdir().unwrap();
        let readiness_path = make_fifo(dir.path(), "ready");
        let config = fake_claude(
            dir.path(),
            "printf '%s\\n' $$ > \"$(dirname \"$0\")/ready\"\nexec tail -f /dev/null\n",
        );

        let cancel = CancelToken::default();
        let trigger = cancel.clone();
        let readiness = tokio::task::spawn_blocking(move || read_pid(&readiness_path));

        let (result, pid) = tokio::join!(
            analyze_with_cancel(&config, dir.path(), &cancel),
            async move {
                let pid = readiness.await.unwrap();
                trigger.cancel();
                pid
            }
        );
        let error = result.unwrap_err();

        assert!(matches!(error, LlmError::Cancelled));
        assert!(!crate::process::process_is_alive(pid));
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_unblocks_a_prompt_the_cli_stopped_reading() {
        let dir = tempfile::tempdir().unwrap();
        let readiness_path = make_fifo(dir.path(), "prompt-started");
        let config = fake_claude(
            dir.path(),
            "head -c 1 > /dev/null\n\
         printf '%s\\n' $$ > \"$(dirname \"$0\")/prompt-started\"\n\
         exec tail -f /dev/null\n",
        );

        let repo_map = oversized_prompt();
        let cancel = CancelToken::default();
        let trigger = cancel.clone();
        let readiness = tokio::task::spawn_blocking(move || read_pid(&readiness_path));

        let (result, pid) = tokio::join!(
            analyze_with_repo_map(&config, dir.path(), &repo_map, &cancel),
            async move {
                let pid = readiness.await.unwrap();
                trigger.cancel();
                pid
            }
        );

        assert!(matches!(result.unwrap_err(), LlmError::Cancelled));
        assert!(!crate::process::process_is_alive(pid));
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_deadline_times_out_a_prompt_the_child_never_reads() {
        let cancel = CancelToken::default();
        let mut session = spawn_session(NEVER_READS_STDIN, EXHAUSTED_BUDGET).await;

        let error = session
            .write_prompt(&oversized_prompt(), &cancel)
            .await
            .unwrap_err();

        assert!(matches!(error, LlmError::Timeout { timeout_seconds: 0 }));
        session.shutdown().await;
        assert!(session.child.id().is_none());
        assert!(drains_are_released(&session));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shutdown_without_group_ownership_reaps_a_live_child() {
        let mut session = spawn_session(HOLDS_THE_PIPES_FOREVER, AMPLE_BUDGET).await;
        let group = session.group.take().unwrap();
        std::mem::forget(group);
        assert!(session.release_process_group().is_ok());

        session.shutdown().await;

        assert!(session.child.id().is_none());
        assert!(drains_are_released(&session));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shutdown_without_group_ownership_accepts_an_already_reaped_child() {
        let mut session = spawn_session("exit 0", AMPLE_BUDGET).await;
        session.child.wait().await.unwrap();
        crate::process::terminate_group(session.group.take().unwrap()).unwrap();

        session.shutdown().await;

        assert!(session.child.id().is_none());
        assert!(drains_are_released(&session));
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_unblocks_a_capture_the_child_never_finishes() {
        let cancel = CancelToken::default();
        let mut session = spawn_session(HOLDS_THE_PIPES_FOREVER, AMPLE_BUDGET).await;
        let group = session.child.id().unwrap();
        session.write_prompt("prompt", &cancel).await.unwrap();
        assert!(drains_are_blocked(&session));
        cancel.cancel();

        let error = session.await_exit(&cancel).await.unwrap_err();

        assert!(matches!(error, LlmError::Cancelled));
        session.shutdown().await;
        assert!(session.child.id().is_none());
        assert!(drains_are_released(&session));
        await_group_exit(group).await;
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_deadline_times_out_a_capture_the_child_never_finishes() {
        let cancel = CancelToken::default();
        let mut session = spawn_session(HOLDS_THE_PIPES_FOREVER, AMPLE_BUDGET).await;
        session.write_prompt("prompt", &cancel).await.unwrap();
        assert!(drains_are_blocked(&session));
        session.deadline = LifecycleDeadline::starting_now(EXHAUSTED_BUDGET);

        let error = session.await_exit(&cancel).await.unwrap_err();

        assert!(matches!(error, LlmError::Timeout { timeout_seconds: 0 }));
        session.shutdown().await;
        assert!(drains_are_released(&session));
    }

    #[cfg(unix)]
    async fn await_process_exit(process_id: i32) {
        tokio::time::timeout(PROMPT_FAILURE_DEADLINE, async {
            while crate::process::process_is_alive(process_id) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the pipe-holding descendant outlived its process group");
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_successful_child_does_not_wait_for_pipe_holding_descendants() {
        let cancel = CancelToken::default();
        let mut session =
            spawn_session(SUCCEEDS_WITH_A_PIPE_HOLDING_DESCENDANT, AMPLE_BUDGET).await;

        let output = tokio::time::timeout(
            PROMPT_FAILURE_DEADLINE,
            session.collect_output("prompt", &cancel),
        )
        .await
        .unwrap()
        .unwrap();

        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        assert!(session.child.id().is_none(), "the child was not reaped");
        let descendant = String::from_utf8(output.stdout).unwrap();
        let descendant: i32 = descendant.trim().parse().unwrap();
        await_process_exit(descendant).await;
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn infinite_oversized_output_fails_fast_and_kills_the_process_group() {
        let cancel = CancelToken::default();
        let mut session = spawn_session(INFINITE_OVERSIZED_OUTPUT, AMPLE_BUDGET).await;
        let group = session.child.id().unwrap();

        let error = tokio::time::timeout(
            PROMPT_FAILURE_DEADLINE,
            session.collect_output("prompt", &cancel),
        )
        .await
        .unwrap()
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            format!(
                "agent protocol error: claude CLI stdout exceeded the {MAX_CLI_STDOUT_BYTES} byte capture limit"
            )
        );
        assert!(session.child.id().is_none(), "the child was not reaped");
        assert!(drains_are_released(&session));
        await_group_exit(group).await;
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_analysis_whose_cli_floods_stdout_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let config = fake_claude(dir.path(), INFINITE_OVERSIZED_OUTPUT);

        let error = tokio::time::timeout(PROMPT_FAILURE_DEADLINE, analyze(&config, dir.path()))
            .await
            .unwrap()
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            format!(
                "agent protocol error: claude CLI stdout exceeded the {MAX_CLI_STDOUT_BYTES} byte capture limit"
            )
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn output_that_exactly_reaches_both_capture_limits_is_accepted() {
        let cancel = CancelToken::default();
        let script = format!(
            "cat > /dev/null\nhead -c {MAX_CLI_STDOUT_BYTES} /dev/zero\nhead -c {MAX_CLI_STDERR_BYTES} /dev/zero >&2\n"
        );
        let mut session = spawn_session(&script, AMPLE_BUDGET).await;

        let output = session.collect_output("prompt", &cancel).await.unwrap();

        assert!(output.status.success());
        assert_eq!(output.stdout.len(), MAX_CLI_STDOUT_BYTES);
        assert_eq!(output.stderr.len(), MAX_CLI_STDERR_BYTES);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_byte_past_the_stderr_limit_is_rejected() {
        let cancel = CancelToken::default();
        let script = format!(
            "cat > /dev/null\nhead -c {} /dev/zero >&2\n",
            MAX_CLI_STDERR_BYTES + 1
        );
        let mut session = spawn_session(&script, AMPLE_BUDGET).await;

        let error = session.collect_output("prompt", &cancel).await.unwrap_err();

        assert_eq!(
            error.to_string(),
            format!(
                "agent protocol error: claude CLI stderr exceeded the {MAX_CLI_STDERR_BYTES} byte capture limit"
            )
        );
        assert!(drains_are_released(&session));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shutting_down_an_already_reaped_child_releases_the_drains() {
        let mut session = spawn_session("exit 0\n", AMPLE_BUDGET).await;
        let status = session.child.wait().await.unwrap();

        assert!(status.success());
        assert!(session.child.id().is_none());

        session.shutdown().await;

        assert!(drains_are_released(&session));
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn process_group_cleanup_failure_fails_the_analysis_and_runs_final_cleanup() {
        fn refuse_group_cleanup(_: &mut crate::process::ProcessGroup) -> std::io::Result<()> {
            Err(std::io::Error::other("group cleanup refused"))
        }

        let cancel = CancelToken::default();
        let mut session = spawn_session("cat > /dev/null\n", AMPLE_BUDGET).await;
        session.group_terminate = refuse_group_cleanup;

        let error = session.collect_output("prompt", &cancel).await.unwrap_err();

        assert!(matches!(
            &error,
            LlmError::Io { action, source }
                if action == "terminate claude CLI subprocess tree"
                    && source.to_string() == "group cleanup refused"
        ));
        assert!(session.group.is_none());
        assert!(session.child.id().is_none());
        assert!(drains_are_released(&session));
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_an_unfinished_session_kills_the_whole_subprocess_tree() {
        let directory = tempfile::tempdir().unwrap();
        let readiness_path = make_fifo(directory.path(), "descendant");
        let script = format!(
            "sh -c 'exec tail -f /dev/null' &\nprintf '%s\\n' \"$!\" > \"{}\"\nexec tail -f /dev/null\n",
            readiness_path.display()
        );
        let readiness = tokio::task::spawn_blocking(move || read_pid(&readiness_path));
        let session = spawn_session(&script, AMPLE_BUDGET).await;
        let leader = i32::try_from(session.child.id().unwrap()).unwrap();
        let descendant = readiness.await.unwrap();
        assert!(crate::process::process_is_alive(descendant));

        drop(session);

        await_process_exit(leader).await;
        await_process_exit(descendant).await;
    }

    #[tokio::test]
    async fn watching_a_settled_pipe_remains_pending() {
        let mut pipe = DrainedPipe {
            stream: "stdout",
            limit: 1,
            task: None,
            settled: None,
        };
        let mut watch = Box::pin(pipe.watch_for_failure());

        tokio::select! {
            biased;
            _ = &mut watch => panic!("a settled pipe must not invent a failure"),
            () = std::future::ready(()) => {}
        }
    }

    #[tokio::test]
    async fn settling_a_truncated_capture_reports_its_limit() {
        let mut pipe = DrainedPipe {
            stream: "stderr",
            limit: 1,
            task: None,
            settled: Some(PipeCapture {
                bytes: vec![b'x'],
                truncated: true,
            }),
        };

        let error = pipe.settle().await.unwrap_err();

        assert_eq!(
            error.to_string(),
            "agent protocol error: claude CLI stderr exceeded the 1 byte capture limit"
        );
    }

    #[test]
    fn cli_arguments_drop_builtin_tools_project_settings_and_edit_permissions() {
        let working_directory = tempfile::tempdir().unwrap();

        let args = collected_args(&cli_command(&hardened_invocation(
            "opus",
            working_directory.path(),
        )));

        assert_eq!(flag_value(&args, "--tools"), Some(""));
        assert_eq!(flag_value(&args, "--setting-sources"), Some(""));
        assert_eq!(flag_value(&args, "--permission-mode"), Some("default"));
        assert_eq!(flag_value(&args, "--effort"), Some("low"));
        assert_eq!(
            flag_value(&args, "--allowedTools"),
            Some("mcp__bughunter__read_file")
        );
        assert_eq!(flag_value(&args, "--model"), Some("opus"));
        assert!(contains_flag(&args, "--strict-mcp-config"));
        assert!(contains_flag(&args, "--no-session-persistence"));
        assert!(!contains_flag(&args, "acceptEdits"));
    }

    #[test]
    fn cli_arguments_honor_the_configured_reasoning_effort() {
        let working_directory = tempfile::tempdir().unwrap();
        let mut invocation = hardened_invocation("opus", working_directory.path());
        invocation.effort = "high";

        let args = collected_args(&cli_command(&invocation));

        assert_eq!(flag_value(&args, "--effort"), Some("high"));
    }

    #[test]
    fn cli_removes_inherited_credential_environment_variables() {
        let working_directory = tempfile::tempdir().unwrap();
        let command = cli_command(&hardened_invocation("opus", working_directory.path()));

        for variable in REMOVED_CREDENTIAL_ENVIRONMENT_VARIABLES {
            let configured = command
                .as_std()
                .get_envs()
                .find(|(name, _)| *name == std::ffi::OsStr::new(variable))
                .map(|(_, value)| value);
            assert_eq!(configured, Some(None), "{variable} must be removed");
        }

        for variable in [
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_AUTH_TOKEN",
            "CLAUDE_CODE_OAUTH_TOKEN",
        ] {
            let configured = command
                .as_std()
                .get_envs()
                .find(|(name, _)| *name == std::ffi::OsStr::new(variable));
            assert_eq!(configured, None, "{variable} must be inherited");
        }
    }

    #[test]
    fn cli_runs_in_the_isolated_working_directory() {
        let working_directory = tempfile::tempdir().unwrap();

        let command = cli_command(&hardened_invocation("sonnet", working_directory.path()));

        assert_eq!(
            command.as_std().get_current_dir(),
            Some(working_directory.path())
        );
    }

    #[test]
    fn cli_arguments_omit_the_model_when_none_is_configured() {
        let working_directory = tempfile::tempdir().unwrap();

        let command = cli_command(&hardened_invocation("", working_directory.path()));

        assert!(!contains_flag(&collected_args(&command), "--model"));
    }

    #[test]
    fn the_analysis_budget_uses_the_configured_shard_limit() {
        let config = LlmConfig {
            timeout_seconds: 7,
            max_shard_seconds: 19,
            ..LlmConfig::default()
        };

        assert_eq!(analysis_budget(&config), Duration::from_secs(19));
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_cli_starts_in_an_empty_directory_outside_the_project() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lib.rs"), "fn main() {}").unwrap();
        let config = fake_claude(
            dir.path(),
            &format!(
                "{RESOLVE_WORKSPACE}\
             pwd -P > \"$(dirname \"$0\")/cli-cwd\"\n\
             ls -A . | wc -l > \"$(dirname \"$0\")/cli-entries\"\n\
             {activity}{CLI_SUCCESS}",
                activity = append_line("activity.jsonl", r#"{"tool":"read_file","path":"a.rs"}"#),
            ),
        );

        analyze(&config, dir.path()).await.unwrap();

        let recorded_cwd = std::fs::read_to_string(dir.path().join("cli-cwd")).unwrap();
        let recorded_entries = std::fs::read_to_string(dir.path().join("cli-entries")).unwrap();
        let cli_cwd = Path::new(recorded_cwd.trim());

        assert_eq!(recorded_entries.trim(), "0");
        assert!(!cli_cwd.starts_with(dir.path()));
        assert_ne!(cli_cwd, std::env::current_dir().unwrap());
    }

    #[tokio::test]
    async fn pipe_capture_stops_at_the_first_byte_beyond_the_limit() {
        let (mut writer, reader) = tokio::io::duplex(16);
        writer.write_all(b"abcdef").await.unwrap();

        let captured = drain_pipe(Some(reader), 4).await.unwrap().unwrap();

        assert_eq!(captured.bytes, b"abcd");
        assert!(captured.truncated);
        let refused = writer.write_all(b"more").await.unwrap_err();
        assert_eq!(
            refused.kind(),
            std::io::ErrorKind::BrokenPipe,
            "an overflowing capture must release the pipe"
        );
    }

    #[tokio::test]
    async fn pipe_capture_keeps_output_that_exactly_reaches_the_limit() {
        let (mut writer, reader) = tokio::io::duplex(16);
        let write = tokio::spawn(async move {
            writer.write_all(b"abcd").await.unwrap();
        });

        let captured = drain_pipe(Some(reader), 4).await.unwrap().unwrap();
        write.await.unwrap();

        assert_eq!(captured.bytes, b"abcd");
        assert!(!captured.truncated);
    }

    #[tokio::test]
    async fn the_failure_watch_reports_the_exceeded_stream_and_limit() {
        let (mut writer, reader) = tokio::io::duplex(16);
        writer.write_all(b"abcdef").await.unwrap();
        let mut pipe = DrainedPipe::start(Some(reader), "stderr", 4);

        let error = pipe.watch_for_failure().await;

        assert_eq!(
            error.to_string(),
            "agent protocol error: claude CLI stderr exceeded the 4 byte capture limit"
        );
        assert!(pipe.task.is_none());
    }

    #[tokio::test]
    async fn a_settled_clean_capture_stops_the_failure_watch() {
        let (writer, reader) = tokio::io::duplex(16);
        drop(writer);
        let mut pipe = DrainedPipe::start(Some(reader), "stdout", 4);
        while pipe.task.as_ref().is_some_and(|task| !task.is_finished()) {
            tokio::task::yield_now().await;
        }

        let watched = tokio::select! {
            biased;
            error = pipe.watch_for_failure() => Some(error),
            () = std::future::ready(()) => None,
        };

        assert!(
            watched.is_none(),
            "a capture within the limit is not a failure: {watched:?}"
        );
        assert!(pipe.task.is_none());
        let capture = pipe.settle().await.unwrap();
        assert!(capture.bytes.is_empty());
        assert!(!capture.truncated);
    }

    #[tokio::test]
    async fn releasing_a_pipe_stops_a_reader_that_never_sees_eof() {
        let (_writer, reader) = tokio::io::duplex(16);
        let mut pipe = DrainedPipe::start(Some(reader), "stdout", 4);

        pipe.release().await;

        assert!(pipe.task.is_none());
        assert!(pipe.settled.is_none());
    }

    #[cfg(unix)]
    fn make_fifo(directory: &Path, name: &str) -> std::path::PathBuf {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let path = directory.join(name);
        let raw_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(raw_path.as_ptr(), 0o600) }, 0);
        path
    }

    #[cfg(unix)]
    fn read_pid(path: &Path) -> i32 {
        std::fs::read_to_string(path)
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn openai_backend_is_rejected_before_spawning() {
        let directory = tempfile::tempdir().unwrap();
        let config = LlmConfig {
            backend: BackendConfig::OpenAiCompatible {
                api_url: "https://example.invalid/v1".into(),
                api_token: None,
            },
            ..LlmConfig::default()
        };

        let error = analyze(&config, directory.path()).await.unwrap_err();

        assert!(matches!(
            &error,
            LlmError::ClaudeProcess { code: None, stderr }
                if stderr == "claude CLI backend is not configured"
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn missing_cli_binary_reports_the_binary_and_spawn_error() {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("missing-claude");
        let config = LlmConfig {
            backend: BackendConfig::ClaudeCli {
                binary: binary.to_string_lossy().into_owned(),
            },
            model: String::new(),
            ..LlmConfig::default()
        };

        let error = analyze(&config, directory.path()).await.unwrap_err();

        assert!(matches!(
            &error,
            LlmError::ClaudeSpawn { binary, source } if binary.ends_with("missing-claude")
                && source.kind() == std::io::ErrorKind::NotFound
        ));
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn executable_with_a_missing_interpreter_reports_the_spawn_error() {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("claude");
        write_executable(&binary, "#!/definitely/absent/bughunter-interpreter\n");
        let config = LlmConfig {
            backend: BackendConfig::ClaudeCli {
                binary: binary.to_string_lossy().into_owned(),
            },
            model: String::new(),
            ..LlmConfig::default()
        };

        let error = analyze(&config, directory.path()).await.unwrap_err();

        assert!(matches!(
            &error,
            LlmError::ClaudeSpawn {
                binary: reported,
                source
            } if reported == &binary.display().to_string()
                && source.kind() == std::io::ErrorKind::NotFound
        ));
    }

    #[tokio::test]
    async fn missing_child_stdin_is_reported() {
        let error = send_prompt(None, "prompt").await.unwrap_err();

        assert!(matches!(
            &error,
            LlmError::ClaudeProcess { code: None, stderr }
                if stderr == "claude CLI subprocess did not expose stdin"
        ));
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_byte_past_the_stdout_limit_is_rejected() {
        let cancel = CancelToken::default();
        let script = format!(
            "cat > /dev/null\nhead -c {} /dev/zero\n",
            MAX_CLI_STDOUT_BYTES + 1
        );
        let mut session = spawn_session(&script, AMPLE_BUDGET).await;

        let error = session.collect_output("prompt", &cancel).await.unwrap_err();

        assert_eq!(
            error.to_string(),
            format!(
                "agent protocol error: claude CLI stdout exceeded the {MAX_CLI_STDOUT_BYTES} byte capture limit"
            )
        );
        assert!(drains_are_released(&session));
    }

    #[tokio::test]
    async fn an_absent_pipe_settles_empty_and_releases_cleanly() {
        let capture = drain_pipe::<tokio::io::DuplexStream>(None, 4)
            .await
            .unwrap()
            .unwrap();
        assert!(capture.bytes.is_empty());
        assert!(!capture.truncated);

        let mut pipe = DrainedPipe::start::<tokio::io::DuplexStream>(None, "stdout", 4);
        assert!(pipe.settle().await.unwrap().bytes.is_empty());
        assert!(pipe.settle().await.unwrap().bytes.is_empty());
        pipe.release().await;
        assert!(pipe.task.is_none());
    }

    #[tokio::test]
    async fn process_wait_and_pipe_join_failures_retain_context() {
        let wait_error = map_wait_result(Err(std::io::Error::other("wait failed"))).unwrap_err();
        assert!(wait_error.to_string().contains("wait for claude CLI"));

        assert_eq!(
            map_io_result("perform operation", Ok::<u8, std::io::Error>(7)).unwrap(),
            7
        );
        let io_error = map_io_result::<u8>(
            "perform operation",
            Err(std::io::Error::other("operation failed")),
        )
        .unwrap_err();
        assert!(io_error.to_string().contains("perform operation"));

        let first_workspace_error =
            create_workspaces(&mut || Err(std::io::Error::other("first failed"))).unwrap_err();
        assert!(
            first_workspace_error
                .to_string()
                .contains("create temp workspace")
        );

        let mut workspace_results = vec![
            Ok(tempfile::tempdir().unwrap()),
            Err(std::io::Error::other("second failed")),
        ]
        .into_iter();
        let second_workspace_error =
            create_workspaces(&mut || workspace_results.next().unwrap()).unwrap_err();
        assert!(
            second_workspace_error
                .to_string()
                .contains("create isolated claude CLI working directory")
        );

        let mut settling = DrainedPipe {
            stream: "stderr",
            limit: 4,
            task: Some(tokio::spawn(async { panic!("reader failed") })),
            settled: None,
        };
        let join_error = settling.settle().await.unwrap_err();
        assert!(
            join_error
                .to_string()
                .contains("claude CLI stderr reader failed")
        );
        assert!(settling.task.is_none());

        let mut watching = DrainedPipe {
            stream: "stdout",
            limit: 4,
            task: Some(tokio::spawn(async { panic!("reader failed") })),
            settled: None,
        };
        let watch_error = watching.watch_for_failure().await;
        assert!(
            watch_error
                .to_string()
                .contains("claude CLI stdout reader failed")
        );
        assert!(watching.task.is_none());
    }

    #[tokio::test]
    async fn pipe_read_failures_are_reported_for_watch_and_settle_paths() {
        struct FailingReader;

        impl tokio::io::AsyncRead for FailingReader {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _context: &mut std::task::Context<'_>,
                _buffer: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Err(std::io::Error::other("pipe read failed")))
            }
        }

        let mut settling = DrainedPipe::start(Some(FailingReader), "stderr", 4);
        let settle_error = settling.settle().await.unwrap_err();
        assert!(matches!(
            &settle_error,
            LlmError::Io { action, source }
                if action == "read claude CLI stderr"
                    && source.to_string() == "pipe read failed"
        ));
        assert!(settling.task.is_none());

        let mut watching = DrainedPipe::start(Some(FailingReader), "stdout", 4);
        let watch_error = watching.watch_for_failure().await;
        assert!(matches!(
            &watch_error,
            LlmError::Io { action, source }
                if action == "read claude CLI stdout"
                    && source.to_string() == "pipe read failed"
        ));
        assert!(watching.task.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn cli_exit_and_result_errors_preserve_their_messages() {
        use std::os::unix::process::ExitStatusExt;
        let redactor = CredentialRedactor::default();

        let failed = std::process::Output {
            status: ExitStatus::from_raw(3 << 8),
            stdout: b"partial".to_vec(),
            stderr: b"boom".to_vec(),
        };
        let error = check_cli_error(&failed, &redactor).unwrap_err();
        assert!(matches!(
            &error,
            LlmError::ClaudeProcess {
                code: Some(3),
                stderr
            } if stderr == "boom\npartial"
        ));

        for (payload, expected) in [
            (
                r#"{"is_error":true,"result":"credit balance too low"}"#,
                "credit balance too low",
            ),
            (r#"{"is_error":true}"#, "claude CLI reported an error"),
        ] {
            let output = std::process::Output {
                status: ExitStatus::from_raw(0),
                stdout: payload.as_bytes().to_vec(),
                stderr: Vec::new(),
            };
            let error = check_cli_error(&output, &redactor).unwrap_err();
            assert!(matches!(
                &error,
                LlmError::ClaudeProcess { code: None, stderr } if stderr == expected
            ));
        }
    }

    #[test]
    fn environment_redactor_covers_every_inherited_credential() {
        const SUPPORTED_CREDENTIAL_VARIABLES: [&str; 25] = [
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_AUTH_TOKEN",
            "ANTHROPIC_AWS_API_KEY",
            "ANTHROPIC_CUSTOM_HEADERS",
            "ANTHROPIC_FOUNDRY_API_KEY",
            "ANTHROPIC_FOUNDRY_AUTH_TOKEN",
            "ANTHROPIC_IDENTITY_TOKEN",
            "AWS_ACCESS_KEY_ID",
            "AWS_BEARER_TOKEN_BEDROCK",
            "AWS_CONTAINER_AUTHORIZATION_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SECURITY_TOKEN",
            "AWS_SESSION_TOKEN",
            "AZURE_CLIENT_CERTIFICATE_PASSWORD",
            "AZURE_CLIENT_SECRET",
            "BUGHUNTER_API_TOKEN",
            "CLAUDE_CODE_CLIENT_KEY_PASSPHRASE",
            "CLAUDE_CODE_MESSAGING_TOKEN",
            "CLAUDE_CODE_OAUTH_REFRESH_TOKEN",
            "CLAUDE_CODE_OAUTH_TOKEN",
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "GOOGLE_OAUTH_ACCESS_TOKEN",
            "IDENTITY_HEADER",
            "MCP_CLIENT_SECRET",
        ];
        let credentials: Vec<_> = SUPPORTED_CREDENTIAL_VARIABLES
            .into_iter()
            .enumerate()
            .map(|(index, variable)| (variable, format!("provider-credential-{index}")))
            .collect();
        let lowercase_secret = "lowercase-provider-credential";
        let nonsensitive_path = "/tmp/client-key.pem";
        let environment = credentials
            .iter()
            .map(|(variable, secret)| {
                (
                    std::ffi::OsString::from(*variable),
                    std::ffi::OsString::from(secret),
                )
            })
            .chain([
                (
                    std::ffi::OsString::from("anthropic_api_key"),
                    std::ffi::OsString::from(lowercase_secret),
                ),
                (
                    std::ffi::OsString::from("CLAUDE_CODE_CLIENT_KEY"),
                    std::ffi::OsString::from(nonsensitive_path),
                ),
            ]);
        let redactor = CredentialRedactor::from_environment_values(environment.collect());

        for (variable, secret) in credentials {
            assert_eq!(
                redactor.redact(&secret),
                "<redacted>",
                "{variable} must be redacted"
            );
        }
        assert_eq!(redactor.redact(lowercase_secret), "<redacted>");
        assert_eq!(redactor.redact(nonsensitive_path), nonsensitive_path);
    }

    #[test]
    fn custom_header_credentials_are_redacted_without_their_header_names() {
        let authorization = "token\"with\\escapes";
        let api_key = "second-provider-key";
        let malformed = "malformed-provider-secret";
        let headers = format!(
            "Authorization:\tBasic\t{authorization}\nX-Provider-Key: {api_key}\n{malformed}"
        );
        let redactor = CredentialRedactor::from_environment_values(vec![(
            std::ffi::OsString::from("ANTHROPIC_CUSTOM_HEADERS"),
            std::ffi::OsString::from(headers),
        )]);

        let rendered = redactor.redact(&format!(
            "authorization={authorization}; api-key={api_key}; malformed={malformed}; header=Authorization"
        ));

        assert_eq!(
            rendered,
            "authorization=<redacted>; api-key=<redacted>; malformed=<redacted>; header=Authorization"
        );
    }

    #[test]
    fn malformed_percent_encoded_credentials_are_rejected() {
        for credential in ["%", "%G0", "%A", "%AG", "%FF"] {
            assert_eq!(percent_decode_if_encoded(credential), None);
        }
    }

    #[test]
    fn authenticated_proxy_credentials_are_redacted_without_hiding_proxy_hosts() {
        let authenticated = "http://proxy%40user:p%40ss%2fword@proxy.example.com:8080";
        let plain_authenticated =
            "http://plain-user:plain-password@authenticated-proxy.example.com:8080";
        let username_only = "http://solo-user@safe-proxy.example.com:8080";
        let unauthenticated = "http://plain-proxy.example.com:8080";
        let invalid = "not a proxy URL";
        let redactor = CredentialRedactor::from_environment_values(vec![
            (
                std::ffi::OsString::from("https_proxy"),
                std::ffi::OsString::from(authenticated),
            ),
            (
                std::ffi::OsString::from("http_proxy"),
                std::ffi::OsString::from(plain_authenticated),
            ),
            (
                std::ffi::OsString::from("HTTPS_PROXY"),
                std::ffi::OsString::from(username_only),
            ),
            (
                std::ffi::OsString::from("HTTP_PROXY"),
                std::ffi::OsString::from(unauthenticated),
            ),
            (
                std::ffi::OsString::from("HTTPS_PROXY"),
                std::ffi::OsString::from(invalid),
            ),
        ]);

        let rendered = redactor.redact(&format!(
            "url={authenticated}; encoded=p%40ss%2fword; password=p@ss/word; user=proxy@user; plain-url={plain_authenticated}; plain-secret=plain-password; user-url={username_only}; user-info=solo-user; unauthenticated={unauthenticated}; invalid={invalid}"
        ));

        assert_eq!(
            rendered,
            format!(
                "url=<redacted>; encoded=<redacted>; password=<redacted>; user=<redacted>; plain-url=<redacted>; plain-secret=<redacted>; user-url=<redacted>; user-info=<redacted>; unauthenticated={unauthenticated}; invalid={invalid}"
            )
        );
    }

    #[cfg(unix)]
    #[test]
    fn cli_errors_redact_raw_and_escaped_credentials_from_child_output() {
        use std::os::unix::process::ExitStatusExt;

        let secret = "token\"with\\slashes?and=values";
        let json = serde_json::to_string(secret).unwrap();
        let percent_upper = percent_encode(secret, false);
        let percent_lower = percent_encode(secret, true);
        let redactor = CredentialRedactor::from_values(vec![String::new(), secret.to_string()]);
        let environment_redactor = CredentialRedactor::from_environment_values(vec![(
            std::ffi::OsString::from("GH_TOKEN"),
            std::ffi::OsString::from(secret),
        )]);
        assert_eq!(environment_redactor.redact(secret), "<redacted>");
        let output = std::process::Output {
            status: ExitStatus::from_raw(9 << 8),
            stdout: format!("json={json}\nurl={percent_upper}\nlower={percent_lower}").into_bytes(),
            stderr: format!("raw={secret}").into_bytes(),
        };

        let error = check_cli_error(&output, &redactor).unwrap_err();
        let rendered = error.to_string();

        for leaked in [
            secret,
            json.as_str(),
            percent_upper.as_str(),
            percent_lower.as_str(),
        ] {
            assert!(
                !rendered.contains(leaked),
                "credential leaked as {leaked:?}"
            );
        }
        assert!(rendered.matches("<redacted>").count() >= 4, "{rendered}");

        let reported_error = std::process::Output {
            status: ExitStatus::from_raw(0),
            stdout: serde_json::json!({ "is_error": true, "result": secret })
                .to_string()
                .into_bytes(),
            stderr: Vec::new(),
        };
        let reported = check_cli_error(&reported_error, &redactor)
            .unwrap_err()
            .to_string();
        assert!(!reported.contains(secret));
        assert!(reported.contains("<redacted>"));
    }

    #[cfg(unix)]
    #[test]
    fn successful_and_non_boolean_cli_results_are_accepted() {
        use std::os::unix::process::ExitStatusExt;

        for payload in [
            "not json",
            r#"{"result":"done"}"#,
            r#"{"is_error":"true"}"#,
            r#"{"is_error":false}"#,
        ] {
            let output = std::process::Output {
                status: ExitStatus::from_raw(0),
                stdout: payload.as_bytes().to_vec(),
                stderr: Vec::new(),
            };
            assert!(check_cli_error(&output, &CredentialRedactor::default()).is_ok());
        }
    }

    #[test]
    fn activity_and_finding_read_errors_keep_operation_context() {
        let directory = tempfile::tempdir().unwrap();

        let activity_error = read_activity(directory.path()).unwrap_err();
        assert!(matches!(
            &activity_error,
            LlmError::Io { action, .. } if action == "read MCP activity log"
        ));

        let finding_error = read_findings(directory.path()).unwrap_err();
        assert!(matches!(
            &finding_error,
            LlmError::Io { action, .. } if action == "read findings file"
        ));
    }

    #[test]
    fn blank_finding_lines_are_ignored() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("findings.jsonl");
        let finding = sample_finding_json();
        std::fs::write(&path, format!("\n{finding}\n  \n{finding}\n")).unwrap();

        assert_eq!(read_findings(&path).unwrap().len(), 2);
    }

    #[test]
    fn json_write_reports_serialization_and_io_failures() {
        let directory = tempfile::tempdir().unwrap();
        let missing_parent = directory.path().join("missing").join("mcp.json");
        let error = write_serialized_json(
            &missing_parent,
            serde_json::to_string(&serde_json::json!({"a": 1})),
        )
        .unwrap_err();
        assert!(matches!(
            &error,
            LlmError::Io { action, source }
                if action == "write MCP config file"
                    && source.kind() == std::io::ErrorKind::NotFound
        ));

        let invalid = std::collections::BTreeMap::from([((1_u8, 2_u8), 3_u8)]);
        let error = write_serialized_json(
            &directory.path().join("mcp.json"),
            serde_json::to_string(&invalid),
        )
        .unwrap_err();
        assert!(matches!(error, LlmError::Serialization(_)));
    }

    #[test]
    fn only_known_inspection_tools_and_read_paths_count() {
        let unknown = vec![ActivityEntry {
            tool: "read_files".into(),
            path: Some("src/ignored.rs".into()),
        }];
        assert!(reject_uninspected_scan(&unknown).is_err());

        let activity = vec![
            ActivityEntry {
                tool: ToolName::ReadFile.as_str().into(),
                path: None,
            },
            ActivityEntry {
                tool: ToolName::ReadFile.as_str().into(),
                path: Some("src/a.rs".into()),
            },
        ];
        assert_eq!(
            distinct_read_paths(&activity),
            BTreeSet::from(["src/a.rs".into()])
        );
    }

    #[derive(Clone, Default)]
    struct CapturedLogs(std::sync::Arc<parking_lot::Mutex<Vec<u8>>>);

    impl CapturedLogs {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().clone()).expect("the formatter emits utf-8")
        }
    }

    impl std::io::Write for CapturedLogs {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.0.lock().extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn capture_logs() -> (CapturedLogs, tracing::subscriber::DefaultGuard) {
        use tracing_subscriber::layer::SubscriberExt;

        let captured = CapturedLogs::default();
        let sink = captured.clone();
        let layer = tracing_subscriber::fmt::layer()
            .with_writer(move || sink.clone())
            .with_target(false)
            .with_ansi(false)
            .without_time()
            .compact();
        let guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));
        (captured, guard)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_completed_analysis_logs_the_invocation_and_the_result_counts() {
        let dir = tempfile::tempdir().unwrap();
        let script = format!(
            "{RESOLVE_WORKSPACE}{activity}{findings}{CLI_SUCCESS}",
            activity = append_line("activity.jsonl", r#"{"tool":"read_file","path":"a.rs"}"#),
            findings = append_line("findings.jsonl", &sample_finding_json()),
        );
        let config = fake_claude(dir.path(), &script);
        let (logs, _subscriber) = capture_logs();

        let analysis = analyze(&config, dir.path()).await.unwrap();

        assert_eq!(analysis.findings.len(), 1);
        let text = logs.text();
        assert!(
            text.contains("invoking claude CLI with MCP"),
            "the invocation must be logged: {text}"
        );
        assert!(
            text.contains(&format!(
                "prompt_bytes={}",
                build_prompt("SYSTEM", "MAP").len()
            )),
            "the logged prompt size must match the prompt actually sent: {text}"
        );
        assert!(
            text.contains("mcp__bughunter__read_file"),
            "the allowed MCP tools must be logged: {text}"
        );
        assert!(
            text.contains("claude CLI (MCP) analysis complete"),
            "the completed analysis must be logged: {text}"
        );
        assert!(
            text.contains("count=1")
                && text.contains("tool_calls=1")
                && text.contains("inspected=1"),
            "the result counts must be logged: {text}"
        );
    }

    #[test]
    fn a_failed_subprocess_termination_is_logged_with_its_cause() {
        let (logs, _subscriber) = capture_logs();

        report_termination_failure(Ok(()));
        let after_success = logs.text();
        report_termination_failure(Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "operation not permitted",
        )));

        assert!(
            after_success.is_empty(),
            "a clean termination must stay silent: {after_success}"
        );
        let text = logs.text();
        assert!(
            text.contains("failed to terminate claude CLI subprocess tree"),
            "{text}"
        );
        assert!(text.contains("operation not permitted"), "{text}");
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn windows_cmd_backend_exercises_the_analysis_protocol() {
        let directory = tempfile::tempdir().unwrap();
        let config = windows_recording_claude(directory.path());

        let analysis = analyze(&config, directory.path()).await.unwrap();

        assert_eq!(analysis.tool_calls, 1);
        assert_eq!(
            analysis.inspected_files,
            BTreeSet::from(["src/a.rs".to_string()])
        );
    }

    #[test]
    fn review_resolution_rejects_executables_inside_the_untrusted_root() {
        let untrusted = tempfile::tempdir().unwrap();
        let trusted = tempfile::tempdir().unwrap();
        let untrusted_binary = resolver_executable(untrusted.path());
        let trusted_binary = resolver_executable(trusted.path());
        let only_untrusted = std::env::join_paths([untrusted.path()]).unwrap();
        let untrusted_then_trusted =
            std::env::join_paths([untrusted.path(), trusted.path()]).unwrap();
        let forbidden_root = untrusted.path().canonicalize().unwrap();

        assert_eq!(
            resolve_cli_binary(
                "claude",
                None,
                Some(&only_untrusted),
                None,
                Some(&forbidden_root),
            ),
            None
        );
        assert_eq!(
            resolve_cli_binary(
                untrusted_binary.to_str().unwrap(),
                None,
                None,
                None,
                Some(&forbidden_root),
            ),
            None
        );
        assert_resolves_to_same_file(
            resolve_cli_binary(
                "claude",
                None,
                Some(&untrusted_then_trusted),
                None,
                Some(&forbidden_root),
            ),
            &trusted_binary,
        );
    }

    #[cfg(unix)]
    #[test]
    fn review_resolution_rejects_a_symlink_into_the_untrusted_root() {
        let untrusted = tempfile::tempdir().unwrap();
        let search_directory = tempfile::tempdir().unwrap();
        let untrusted_binary = resolver_executable(untrusted.path());
        std::os::unix::fs::symlink(&untrusted_binary, search_directory.path().join("claude"))
            .unwrap();
        let search_path = std::env::join_paths([search_directory.path()]).unwrap();

        assert_eq!(
            resolve_cli_binary(
                "claude",
                None,
                Some(&search_path),
                None,
                Some(untrusted.path()),
            ),
            None
        );
    }

    #[test]
    fn windows_path_extension_policy_accepts_only_supported_extensions() {
        for (raw, expected) in [
            (".COM", Some(".COM")),
            (".exe", Some(".EXE")),
            (" .Bat ", Some(".BAT")),
            (".cMd", Some(".CMD")),
            ("cmd", None),
            (".ps1", None),
            ("C:\\tools\\.EXE", None),
            ("", None),
        ] {
            assert_eq!(canonical_windows_path_extension(raw), expected, "{raw:?}");
        }
    }

    fn assert_resolves_to_same_file(resolved: Option<PathBuf>, expected: &Path) {
        assert_eq!(
            resolved.unwrap().canonicalize().unwrap(),
            expected.canonicalize().unwrap()
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_resolution_accepts_implicit_exe_extensions() {
        let project = tempfile::tempdir().unwrap();
        let tools = project.path().join("tools");
        std::fs::create_dir(&tools).unwrap();
        let executable = tools.join("claude.exe");
        std::fs::write(&executable, b"binary").unwrap();
        let search_path = std::env::join_paths([tools.as_path()]).unwrap();
        let path_extensions = OsStr::new(".EXE");

        assert_resolves_to_same_file(
            resolve_cli_binary(
                "tools/claude",
                Some(project.path()),
                None,
                Some(path_extensions),
                None,
            ),
            &executable,
        );
        assert_resolves_to_same_file(
            resolve_cli_binary(
                "claude",
                Some(project.path()),
                Some(&search_path),
                Some(path_extensions),
                None,
            ),
            &executable,
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_resolution_honors_supported_pathext_order() {
        let project = tempfile::tempdir().unwrap();
        let tools = project.path().join("tools");
        std::fs::create_dir(&tools).unwrap();
        let command = tools.join("claude.cmd");
        let executable = tools.join("claude.exe");
        let unsupported = tools.join("claude.ps1");
        std::fs::write(&command, b"@exit /b 0").unwrap();
        std::fs::write(&executable, b"binary").unwrap();
        std::fs::write(&unsupported, b"exit 0").unwrap();
        let search_path = std::env::join_paths([tools.as_path()]).unwrap();

        assert_resolves_to_same_file(
            resolve_cli_binary(
                "claude",
                Some(project.path()),
                Some(&search_path),
                Some(OsStr::new(".PS1;.CMD;.EXE")),
                None,
            ),
            &command,
        );
    }
}
