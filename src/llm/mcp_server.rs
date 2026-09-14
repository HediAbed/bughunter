use std::fs::OpenOptions;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::config::EngineConfig;
use crate::engine::{DefaultEngine, Engine, ProjectInventory};
use crate::report::{Finding, FindingCounter};
use crate::shared::read_bounded_string;

use super::review_scope::ChangedLines;
use super::tool_exec::ToolExecutor;
use super::tools::build_tool_config;

const MCP_PROTOCOL_VERSION: &str = "2024-11-05";
const JSONRPC_VERSION: &str = "2.0";
const PARSE_ERROR_CODE: i64 = -32700;
const INVALID_REQUEST_CODE: i64 = -32600;
const METHOD_NOT_FOUND_CODE: i64 = -32601;
const INVALID_PARAMS_CODE: i64 = -32602;
const SESSION_LIMIT_CODE: i64 = -32000;
const OVERSIZED_REQUEST: &str = "request exceeds the maximum size";
const CONTEXT_ENV: &str = "BUGHUNTER_MCP_CONTEXT";
const MAX_MCP_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_MCP_CONTEXT_BYTES: usize = 1024 * 1024;
const MAX_MCP_ACTIVITY_BYTES: usize = 16 * 1024 * 1024;
const MAX_MCP_FINDINGS_BYTES: usize = 32 * 1024 * 1024;
const MAX_MCP_REQUESTS: usize = 4096;

#[derive(Debug, Serialize, Deserialize)]
pub struct McpContext {
    pub project_root: PathBuf,
    pub engine_config: EngineConfig,
    pub findings_path: PathBuf,
    pub activity_path: PathBuf,
    pub finding_id_start: u32,
    pub changed_lines: Option<ChangedLines>,
}

pub struct SessionLog {
    findings_path: PathBuf,
    activity_path: PathBuf,
}

impl SessionLog {
    pub fn new(findings_path: PathBuf, activity_path: PathBuf) -> Self {
        Self {
            findings_path,
            activity_path,
        }
    }

    fn record_findings(&self, findings: &[Finding]) -> std::io::Result<()> {
        let lines = findings
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()?;
        append_lines_with_limit(&self.findings_path, &lines, MAX_MCP_FINDINGS_BYTES)
    }

    fn record_call(&self, tool: &str, path: Option<&str>) -> std::io::Result<()> {
        let line = json!({ "tool": tool, "path": path }).to_string();
        append_lines_with_limit(&self.activity_path, &[line], MAX_MCP_ACTIVITY_BYTES)
    }
}

fn append_lines_with_limit(path: &Path, lines: &[String], limit: usize) -> std::io::Result<()> {
    let mut line_lengths = lines.iter().map(String::len);
    let additional_bytes = appended_byte_total(&mut line_lengths)?;
    let current_bytes = match std::fs::metadata(path) {
        Ok(metadata) => usize::try_from(metadata.len()).unwrap_or(usize::MAX),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => return Err(error),
    };
    if current_bytes
        .checked_add(additional_bytes)
        .is_none_or(|total| total > limit)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} exceeds {limit} bytes", path.display()),
        ));
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    for line in lines {
        writeln!(file, "{line}")?;
    }
    Ok(())
}

fn appended_byte_total(line_lengths: &mut dyn Iterator<Item = usize>) -> std::io::Result<usize> {
    let mut total = 0usize;
    for length in line_lengths {
        total = total
            .checked_add(length)
            .and_then(|total| total.checked_add(1))
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "log size overflow")
            })?;
    }
    Ok(total)
}

#[derive(Debug, Eq, PartialEq)]
enum BoundedLine {
    Complete(String),
    TooLong,
    EndOfInput,
}

fn read_bounded_line(reader: &mut dyn BufRead, limit: usize) -> std::io::Result<BoundedLine> {
    let mut bytes = Vec::with_capacity(limit.min(8 * 1024));
    let mut too_long = false;

    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return finish_bounded_line(bytes, too_long, true);
        }

        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let segment_length = newline.unwrap_or(buffer.len());
        let remaining = limit.saturating_sub(bytes.len());
        let copied = segment_length.min(remaining);
        bytes.extend_from_slice(&buffer[..copied]);
        too_long |= segment_length > remaining;
        let consumed = segment_length + usize::from(newline.is_some());
        reader.consume(consumed);

        if newline.is_some() {
            return finish_bounded_line(bytes, too_long, false);
        }
    }
}

fn finish_bounded_line(
    mut bytes: Vec<u8>,
    too_long: bool,
    end_of_input: bool,
) -> std::io::Result<BoundedLine> {
    if too_long {
        return Ok(BoundedLine::TooLong);
    }
    if end_of_input && bytes.is_empty() {
        return Ok(BoundedLine::EndOfInput);
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    String::from_utf8(bytes)
        .map(BoundedLine::Complete)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

struct RequestBudget {
    limit: usize,
    used: usize,
}

impl RequestBudget {
    fn new(limit: usize) -> Self {
        Self { limit, used: 0 }
    }

    fn consume(&mut self) -> std::io::Result<()> {
        if self.used >= self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("MCP session exceeds {} requests", self.limit),
            ));
        }
        self.used += 1;
        Ok(())
    }
}

pub fn serve() -> std::io::Result<()> {
    let context = load_context()?;
    let engine: Arc<dyn Engine> = Arc::new(DefaultEngine::new(context.engine_config.clone()));
    let counter = Arc::new(FindingCounter::with_start(context.finding_id_start));
    let inventory = Arc::new(
        ProjectInventory::build(&context.project_root, &context.engine_config)
            .map_err(std::io::Error::other)?,
    );
    let executor = build_executor(engine, inventory, &context, counter);
    let log = SessionLog::new(context.findings_path.clone(), context.activity_path.clone());

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let budget = RequestBudget::new(MAX_MCP_REQUESTS);
    serve_requests(
        &mut stdin.lock(),
        &mut stdout.lock(),
        &executor,
        &log,
        budget,
    )
}

fn serve_requests(
    input: &mut dyn BufRead,
    out: &mut dyn Write,
    executor: &ToolExecutor,
    log: &SessionLog,
    mut request_budget: RequestBudget,
) -> std::io::Result<()> {
    loop {
        let response = match read_bounded_line(input, MAX_MCP_REQUEST_BYTES)? {
            BoundedLine::EndOfInput => break,
            BoundedLine::TooLong => {
                charge_request_budget(&mut request_budget, out)?;
                Some(error(None, INVALID_REQUEST_CODE, OVERSIZED_REQUEST))
            }
            BoundedLine::Complete(line) => {
                charge_request_budget(&mut request_budget, out)?;
                match line.trim().is_empty() {
                    true => None,
                    false => handle_line(&line, executor, log),
                }
            }
        };
        if let Some(response) = response {
            writeln!(out, "{response}")?;
            out.flush()?;
        }
    }

    Ok(())
}

fn charge_request_budget(budget: &mut RequestBudget, out: &mut dyn Write) -> std::io::Result<()> {
    let Err(limit_error) = budget.consume() else {
        return Ok(());
    };
    writeln!(
        out,
        "{}",
        error(None, SESSION_LIMIT_CODE, &limit_error.to_string())
    )?;
    out.flush()?;
    Err(limit_error)
}

fn build_executor(
    engine: Arc<dyn Engine>,
    inventory: Arc<ProjectInventory>,
    context: &McpContext,
    counter: Arc<FindingCounter>,
) -> ToolExecutor {
    let executor = ToolExecutor::from_inventory(engine, inventory, counter);
    match &context.changed_lines {
        Some(changed_lines) => executor
            .with_allowed_files(changed_lines.files().map(str::to_owned).collect())
            .with_finding_scope(changed_lines.clone()),
        None => executor,
    }
}

fn load_context() -> std::io::Result<McpContext> {
    let path = std::env::var(CONTEXT_ENV).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{CONTEXT_ENV} not set; mcp-serve is invoked by bughunter, not directly"),
        )
    })?;
    let raw = read_bounded_string(Path::new(&path), MAX_MCP_CONTEXT_BYTES)?;
    serde_json::from_str(&raw)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
enum RequestId {
    Number(i64),
    Text(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    #[serde(default)]
    id: Option<RequestId>,
    #[serde(default)]
    params: Option<serde_json::Map<String, Value>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolCallParams {
    name: String,
    #[serde(default)]
    arguments: Option<serde_json::Map<String, Value>>,
}

fn handle_line(line: &str, executor: &ToolExecutor, log: &SessionLog) -> Option<String> {
    match serde_json::from_str::<Value>(line) {
        Ok(request) => handle_request(request, executor, log),
        Err(_) => Some(error(None, PARSE_ERROR_CODE, "request is not valid JSON")),
    }
}

fn handle_request(request: Value, executor: &ToolExecutor, log: &SessionLog) -> Option<String> {
    match parse_envelope(request) {
        Ok(request) => dispatch(request, executor, log),
        Err(reason) => Some(error(None, INVALID_REQUEST_CODE, reason)),
    }
}

fn parse_envelope(request: Value) -> Result<JsonRpcRequest, &'static str> {
    let request: JsonRpcRequest =
        serde_json::from_value(request).map_err(|_| "request is not a JSON-RPC 2.0 object")?;
    if request.jsonrpc != JSONRPC_VERSION {
        return Err("jsonrpc must be exactly \"2.0\"");
    }
    Ok(request)
}

fn dispatch(request: JsonRpcRequest, executor: &ToolExecutor, log: &SessionLog) -> Option<String> {
    let id = request.id?;
    Some(match request.method.as_str() {
        "initialize" => result(&id, initialize_result()),
        "ping" => result(&id, json!({})),
        "tools/list" => result(&id, json!({ "tools": tool_list() })),
        "tools/call" => match parse_tool_call(request.params) {
            Ok(call) => result(&id, call_tool(call, executor, log)),
            Err(reason) => error(Some(&id), INVALID_PARAMS_CODE, &reason),
        },
        _ => error(Some(&id), METHOD_NOT_FOUND_CODE, "method not found"),
    })
}

fn parse_tool_call(
    params: Option<serde_json::Map<String, Value>>,
) -> Result<ToolCallParams, String> {
    let params = params.ok_or_else(|| "tools/call requires params".to_string())?;
    let call: ToolCallParams =
        serde_json::from_value(Value::Object(params)).map_err(|error| error.to_string())?;
    if call.name.trim().is_empty() {
        return Err("tools/call requires a non-empty tool name".to_string());
    }
    Ok(call)
}

#[cfg(feature = "fuzzing")]
pub fn dispatch_mcp_request(
    request: &Value,
    executor: &ToolExecutor,
    log: &SessionLog,
) -> Option<String> {
    handle_request(request.clone(), executor, log)
}

#[cfg(feature = "fuzzing")]
pub fn dispatch_mcp_line(line: &str, executor: &ToolExecutor, log: &SessionLog) -> Option<String> {
    handle_line(line, executor, log)
}

fn initialize_result() -> Value {
    json!({
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": "bughunter", "version": crate::version::VERSION },
    })
}

fn tool_list() -> Vec<Value> {
    build_tool_config()
        .tools
        .into_iter()
        .map(|tool| {
            json!({
                "name": tool.tool_spec.name,
                "description": tool.tool_spec.description,
                "inputSchema": tool.tool_spec.input_schema.json,
            })
        })
        .collect()
}

fn call_tool(call: ToolCallParams, executor: &ToolExecutor, log: &SessionLog) -> Value {
    let arguments = call.arguments.map_or_else(|| json!({}), Value::Object);
    let outcome = match executor.execute(&call.name, &arguments) {
        Ok(outcome) => outcome,
        Err(message) => return tool_error(message),
    };

    if !outcome.findings.is_empty()
        && let Err(error) = log.record_findings(&outcome.findings)
    {
        let count = outcome.findings.len();
        let finding_label = if count == 1 { "finding" } else { "findings" };
        return tool_error(format!("{count} unpersisted {finding_label}: {error}"));
    }

    if let Err(error) = log.record_call(&call.name, outcome.inspected_path.as_deref()) {
        return tool_error(format!("activity log unavailable: {error}"));
    }

    json!({ "content": [{ "type": "text", "text": outcome.text }] })
}

fn tool_error(message: String) -> Value {
    json!({ "content": [{ "type": "text", "text": message }], "isError": true })
}

fn result(id: &RequestId, result: Value) -> String {
    json!({ "jsonrpc": JSONRPC_VERSION, "id": id, "result": result }).to_string()
}

fn error(id: Option<&RequestId>, code: i64, message: &str) -> String {
    let failure = json!({ "code": code, "message": message });
    json!({ "jsonrpc": JSONRPC_VERSION, "id": id, "error": failure }).to_string()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::engine::DefaultEngine;
    use std::collections::BTreeMap;
    use std::fs;
    use tempfile::TempDir;

    fn executor_setup() -> (TempDir, Arc<dyn Engine>, Arc<FindingCounter>) {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("a.rs"), "fn main() {}\n").unwrap();
        let engine: Arc<dyn Engine> = Arc::new(DefaultEngine::new(EngineConfig::default()));
        (dir, engine, Arc::new(FindingCounter::with_start(1)))
    }

    fn tool_executor(
        dir: &TempDir,
        engine: &Arc<dyn Engine>,
        counter: &Arc<FindingCounter>,
    ) -> ToolExecutor {
        ToolExecutor::new(Arc::clone(engine), dir.path(), Arc::clone(counter))
            .expect("the fixture project is readable")
    }

    fn session_log(dir: &TempDir) -> SessionLog {
        SessionLog::new(
            dir.path().join("findings.jsonl"),
            dir.path().join("activity.jsonl"),
        )
    }

    fn activity_lines(dir: &TempDir) -> Vec<Value> {
        let raw = fs::read_to_string(dir.path().join("activity.jsonl")).unwrap_or_default();
        raw.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn call_request(id: u32, name: &str, arguments: Value) -> Value {
        json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": { "name": name, "arguments": arguments }
        })
    }

    #[test]
    fn initialize_advertises_tools_capability() {
        let (dir, engine, counter) = executor_setup();
        let exec = tool_executor(&dir, &engine, &counter);
        let req = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize" });

        let response = handle_request(req, &exec, &session_log(&dir)).unwrap();
        let parsed: Value = serde_json::from_str(&response).unwrap();

        assert_eq!(parsed["id"], 1);
        assert_eq!(parsed["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);
        assert!(parsed["result"]["capabilities"]["tools"].is_object());
    }

    #[test]
    fn initialized_notification_produces_no_response() {
        let (dir, engine, counter) = executor_setup();
        let exec = tool_executor(&dir, &engine, &counter);
        let req = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });

        assert!(handle_request(req, &exec, &session_log(&dir)).is_none());
    }

    #[test]
    fn tools_list_returns_six_tools() {
        let (dir, engine, counter) = executor_setup();
        let exec = tool_executor(&dir, &engine, &counter);
        let req = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" });

        let response = handle_request(req, &exec, &session_log(&dir)).unwrap();
        let parsed: Value = serde_json::from_str(&response).unwrap();

        assert_eq!(parsed["result"]["tools"].as_array().unwrap().len(), 6);
        assert_eq!(parsed["result"]["tools"][0]["name"], "discover_files");
        assert!(parsed["result"]["tools"][0]["inputSchema"].is_object());
    }

    #[test]
    fn tools_call_discover_files_runs() {
        let (dir, engine, counter) = executor_setup();
        let exec = tool_executor(&dir, &engine, &counter);
        let req = call_request(3, "discover_files", json!({}));

        let response = handle_request(req, &exec, &session_log(&dir)).unwrap();
        let parsed: Value = serde_json::from_str(&response).unwrap();

        let text = parsed["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("a.rs"));
    }

    #[test]
    fn tools_call_submit_findings_persists_to_file() {
        let (dir, engine, counter) = executor_setup();
        let exec = tool_executor(&dir, &engine, &counter);
        let req = call_request(
            4,
            "submit_findings",
            json!({ "findings": [{
                "category": "bug", "severity": "high",
                "title": "boom", "description": "d", "file": "a.rs", "confidence": "high"
            }]}),
        );

        let response = handle_request(req, &exec, &session_log(&dir)).unwrap();
        let parsed: Value = serde_json::from_str(&response).unwrap();
        assert!(parsed["result"]["isError"].is_null());

        let written = fs::read_to_string(dir.path().join("findings.jsonl")).unwrap();
        let finding: Value = serde_json::from_str(written.trim()).unwrap();
        assert_eq!(finding["title"], "boom");
        assert_eq!(finding["source"], "ai");
    }

    #[test]
    fn tools_call_reports_unpersisted_finding_count() {
        let (dir, engine, counter) = executor_setup();
        let exec = tool_executor(&dir, &engine, &counter);
        let blocked_path = dir.path().join("blocked");
        fs::create_dir(&blocked_path).unwrap();
        let log = SessionLog::new(blocked_path, dir.path().join("activity.jsonl"));
        let req = call_request(
            5,
            "submit_findings",
            json!({ "findings": [{
                "category": "bug", "severity": "high",
                "title": "boom", "description": "d", "file": "a.rs"
            }]}),
        );

        let response = handle_request(req, &exec, &log).unwrap();
        let parsed: Value = serde_json::from_str(&response).unwrap();
        let text = parsed["result"]["content"][0]["text"].as_str().unwrap();

        assert_eq!(parsed["result"]["isError"], true);
        assert!(text.contains("1 unpersisted finding"));
    }

    #[test]
    fn tools_call_unknown_tool_is_error_result() {
        let (dir, engine, counter) = executor_setup();
        let exec = tool_executor(&dir, &engine, &counter);
        let req = call_request(5, "nope", json!({}));

        let response = handle_request(req, &exec, &session_log(&dir)).unwrap();
        let parsed: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["result"]["isError"], true);
    }

    #[test]
    fn unknown_method_returns_jsonrpc_error() {
        let (dir, engine, counter) = executor_setup();
        let exec = tool_executor(&dir, &engine, &counter);
        let req = json!({ "jsonrpc": "2.0", "id": 9, "method": "does/not/exist" });

        let response = handle_request(req, &exec, &session_log(&dir)).unwrap();
        let parsed: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["error"]["code"], -32601);
    }

    #[test]
    fn successful_call_appends_activity_line_without_path() {
        let (dir, engine, counter) = executor_setup();
        let exec = tool_executor(&dir, &engine, &counter);
        let req = call_request(1, "discover_files", json!({}));

        handle_request(req, &exec, &session_log(&dir)).unwrap();

        let lines = activity_lines(&dir);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["tool"], "discover_files");
        assert!(lines[0]["path"].is_null());
    }

    #[test]
    fn read_file_call_records_project_relative_path() {
        let (dir, engine, counter) = executor_setup();
        let exec = tool_executor(&dir, &engine, &counter);
        let req = call_request(1, "read_file", json!({ "path": "a.rs" }));

        let response = handle_request(req, &exec, &session_log(&dir)).unwrap();
        let parsed: Value = serde_json::from_str(&response).unwrap();
        assert!(parsed["result"]["isError"].is_null());

        let lines = activity_lines(&dir);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["tool"], "read_file");
        assert_eq!(lines[0]["path"], "a.rs");
    }

    #[test]
    fn every_successful_call_appends_one_activity_line() {
        let (dir, engine, counter) = executor_setup();
        let exec = tool_executor(&dir, &engine, &counter);
        let log = session_log(&dir);

        for (id, name, arguments) in [
            (1, "discover_files", json!({})),
            (2, "search_text", json!({ "pattern": "main" })),
            (3, "read_file", json!({ "path": "a.rs" })),
        ] {
            handle_request(call_request(id, name, arguments), &exec, &log).unwrap();
        }

        let lines = activity_lines(&dir);
        let tools: Vec<&str> = lines
            .iter()
            .map(|line| line["tool"].as_str().unwrap())
            .collect();
        assert_eq!(tools, ["discover_files", "search_text", "read_file"]);
        assert!(lines[0]["path"].is_null());
        assert!(lines[1]["path"].is_null());
        assert_eq!(lines[2]["path"], "a.rs");
    }

    #[test]
    fn failed_call_is_not_recorded_as_activity() {
        let (dir, engine, counter) = executor_setup();
        let exec = tool_executor(&dir, &engine, &counter);
        let log = session_log(&dir);

        let unknown = call_request(1, "nope", json!({}));
        let missing = call_request(2, "read_file", json!({ "path": "missing.rs" }));

        handle_request(unknown, &exec, &log).unwrap();
        handle_request(missing, &exec, &log).unwrap();

        assert!(activity_lines(&dir).is_empty());
    }

    #[test]
    fn unwritable_activity_log_surfaces_as_tool_error() {
        let (dir, engine, counter) = executor_setup();
        let exec = tool_executor(&dir, &engine, &counter);
        let blocked_path = dir.path().join("blocked");
        fs::create_dir(&blocked_path).unwrap();
        let log = SessionLog::new(dir.path().join("findings.jsonl"), blocked_path);

        let request = call_request(1, "discover_files", json!({}));
        let response = handle_request(request, &exec, &log).unwrap();
        let parsed: Value = serde_json::from_str(&response).unwrap();

        assert_eq!(parsed["result"]["isError"], true);
        let text = parsed["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("activity log unavailable"));
    }

    #[test]
    fn context_round_trips_activity_path_and_the_finding_scope() {
        let changed_lines =
            ChangedLines::try_from(BTreeMap::from([("src/a.rs".to_string(), vec![(4, 9)])]))
                .unwrap();
        let context = McpContext {
            project_root: PathBuf::from("/project"),
            engine_config: EngineConfig::default(),
            findings_path: PathBuf::from("/tmp/findings.jsonl"),
            activity_path: PathBuf::from("/tmp/activity.jsonl"),
            finding_id_start: 7,
            changed_lines: Some(changed_lines.clone()),
        };

        let raw = serde_json::to_string(&context).unwrap();
        let restored: McpContext = serde_json::from_str(&raw).unwrap();

        assert_eq!(restored.activity_path, PathBuf::from("/tmp/activity.jsonl"));
        assert_eq!(restored.finding_id_start, 7);
        assert_eq!(restored.changed_lines, Some(changed_lines));
    }

    #[test]
    fn build_executor_refuses_reads_beyond_the_changed_files() {
        let (dir, engine, counter) = executor_setup();
        fs::write(dir.path().join("b.rs"), "fn other() {}\n").unwrap();
        let context = McpContext {
            project_root: dir.path().to_path_buf(),
            engine_config: EngineConfig::default(),
            findings_path: dir.path().join("findings.jsonl"),
            activity_path: dir.path().join("activity.jsonl"),
            finding_id_start: 1,
            changed_lines: Some(
                ChangedLines::try_from(BTreeMap::from([("a.rs".to_string(), vec![(1, 1)])]))
                    .unwrap(),
            ),
        };
        let inventory =
            Arc::new(ProjectInventory::build(dir.path(), &context.engine_config).unwrap());
        let exec = build_executor(engine, inventory, &context, counter);
        let log = session_log(&dir);

        let allowed = handle_request(
            call_request(1, "read_file", json!({ "path": "a.rs" })),
            &exec,
            &log,
        )
        .unwrap();
        let refused = handle_request(
            call_request(2, "read_file", json!({ "path": "b.rs" })),
            &exec,
            &log,
        )
        .unwrap();
        let allowed: Value = serde_json::from_str(&allowed).unwrap();
        let refused: Value = serde_json::from_str(&refused).unwrap();

        assert!(allowed["result"]["isError"].is_null(), "{allowed}");
        assert_eq!(refused["result"]["isError"], true, "{refused}");
        assert!(
            refused["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("outside the PR review scope")
        );
        let lines = activity_lines(&dir);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["path"], "a.rs");
    }

    #[test]
    fn build_executor_refuses_findings_outside_the_changed_lines() {
        let (dir, engine, counter) = executor_setup();
        fs::write(dir.path().join("b.rs"), "fn other() {}\n").unwrap();
        let context = McpContext {
            project_root: dir.path().to_path_buf(),
            engine_config: EngineConfig::default(),
            findings_path: dir.path().join("findings.jsonl"),
            activity_path: dir.path().join("activity.jsonl"),
            finding_id_start: 1,
            changed_lines: Some(
                ChangedLines::try_from(BTreeMap::from([("a.rs".to_string(), vec![(1, 1)])]))
                    .unwrap(),
            ),
        };
        let inventory =
            Arc::new(ProjectInventory::build(dir.path(), &context.engine_config).unwrap());
        let exec = build_executor(engine, inventory, &context, counter);
        let log = session_log(&dir);
        let finding = |file: &str| {
            json!({ "findings": [{
                "category": "bug", "severity": "high", "title": "t", "description": "d",
                "file": file, "line_start": 1, "line_end": 1
            }]})
        };

        let accepted = handle_request(
            call_request(1, "submit_findings", finding("a.rs")),
            &exec,
            &log,
        )
        .unwrap();
        let refused = handle_request(
            call_request(2, "submit_findings", finding("b.rs")),
            &exec,
            &log,
        )
        .unwrap();

        let accepted: Value = serde_json::from_str(&accepted).unwrap();
        let refused: Value = serde_json::from_str(&refused).unwrap();
        assert!(accepted["result"]["isError"].is_null(), "{accepted}");
        assert_eq!(refused["result"]["isError"], true);
    }

    #[test]
    fn build_executor_without_a_scope_accepts_project_findings() {
        let (dir, engine, counter) = executor_setup();
        let context = McpContext {
            project_root: dir.path().to_path_buf(),
            engine_config: EngineConfig::default(),
            findings_path: dir.path().join("findings.jsonl"),
            activity_path: dir.path().join("activity.jsonl"),
            finding_id_start: 1,
            changed_lines: None,
        };
        let inventory =
            Arc::new(ProjectInventory::build(dir.path(), &context.engine_config).unwrap());
        let exec = build_executor(engine, inventory, &context, counter);
        let log = session_log(&dir);
        let request = call_request(
            1,
            "submit_findings",
            json!({ "findings": [{
                "category": "bug", "severity": "high", "title": "t", "description": "d",
                "file": "a.rs", "line_start": 1, "line_end": 1
            }]}),
        );

        let response = handle_request(request, &exec, &log).unwrap();
        let response: Value = serde_json::from_str(&response).unwrap();

        assert!(response["result"]["isError"].is_null(), "{response}");
    }

    #[test]
    fn bounded_line_reader_discards_oversized_lines_and_recovers() {
        let mut input = std::io::Cursor::new(b"abcdef\nok\n");

        assert_eq!(
            read_bounded_line(&mut input, 4).unwrap(),
            BoundedLine::TooLong
        );
        assert_eq!(
            read_bounded_line(&mut input, 4).unwrap(),
            BoundedLine::Complete("ok".to_string())
        );
        assert_eq!(
            read_bounded_line(&mut input, 4).unwrap(),
            BoundedLine::EndOfInput
        );
    }
    #[test]
    fn bounded_log_append_rejects_growth_without_partial_writes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("events.jsonl");

        append_lines_with_limit(&path, &["abc".to_string()], 4).unwrap();
        let error = append_lines_with_limit(&path, &["x".to_string()], 4).unwrap_err();

        assert_eq!(std::fs::read_to_string(path).unwrap(), "abc\n");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exceeds 4 bytes"));
    }
    #[test]
    fn request_budget_rejects_calls_beyond_the_limit() {
        let mut budget = RequestBudget::new(2);

        assert!(budget.consume().is_ok());
        assert!(budget.consume().is_ok());
        let error = budget.consume().unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("2 requests"));
    }

    #[test]
    fn bounded_line_reader_accepts_crlf_and_rejects_invalid_utf8() {
        let mut crlf = std::io::Cursor::new(b"ping\r\n");
        assert_eq!(
            read_bounded_line(&mut crlf, 8).unwrap(),
            BoundedLine::Complete("ping".to_string())
        );

        let mut invalid = std::io::Cursor::new(vec![0xff, b'\n']);
        let error = read_bounded_line(&mut invalid, 8).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn notification_for_an_unknown_method_has_no_response() {
        let (dir, engine, counter) = executor_setup();
        let exec = tool_executor(&dir, &engine, &counter);
        let notification = json!({ "jsonrpc": "2.0", "method": "unknown/notification" });

        assert!(handle_request(notification, &exec, &session_log(&dir)).is_none());
    }

    #[test]
    fn tools_call_defaults_missing_arguments_to_an_empty_object() {
        let (dir, engine, counter) = executor_setup();
        let exec = tool_executor(&dir, &engine, &counter);
        let request = json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": { "name": "discover_files" }
        });

        let response = handle_request(request, &exec, &session_log(&dir)).unwrap();
        let response: Value = serde_json::from_str(&response).unwrap();

        assert!(
            response["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("a.rs")
        );
    }

    #[cfg(feature = "fuzzing")]
    #[test]
    fn fuzzing_dispatch_uses_the_same_protocol_handler() {
        let (dir, engine, counter) = executor_setup();
        let exec = tool_executor(&dir, &engine, &counter);
        let request = json!({ "jsonrpc": "2.0", "id": 9, "method": "ping" });

        let response = dispatch_mcp_request(&request, &exec, &session_log(&dir)).unwrap();
        let response: Value = serde_json::from_str(&response).unwrap();

        assert_eq!(response["id"], 9);
        assert_eq!(response["result"], json!({}));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_log_append_propagates_metadata_errors() {
        use std::os::unix::fs::symlink;

        let directory = TempDir::new().unwrap();
        let looped = directory.path().join("loop");
        symlink("loop", &looped).unwrap();

        let error = append_lines_with_limit(&looped, &["entry".into()], 100).unwrap_err();

        assert_ne!(error.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn appended_byte_total_counts_line_feeds_and_rejects_overflow() {
        let mut line_lengths = [2usize, 3].into_iter();
        assert_eq!(appended_byte_total(&mut line_lengths).unwrap(), 7);

        for lengths in [vec![usize::MAX], vec![usize::MAX - 1, 2]] {
            let mut line_lengths = lengths.into_iter();
            let error = appended_byte_total(&mut line_lengths).unwrap_err();

            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
            assert_eq!(error.to_string(), "log size overflow");
        }
    }

    struct BrokenPipeWriter;

    impl Write for BrokenPipeWriter {
        fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "client closed the transport",
            ))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn oversized_request_line() -> Vec<u8> {
        let mut line = vec![b'x'; MAX_MCP_REQUEST_BYTES + 1];
        line.push(b'\n');
        line
    }

    #[test]
    fn serve_requests_rejects_an_oversized_line_then_answers_the_next_request() {
        let (dir, engine, counter) = executor_setup();
        let exec = tool_executor(&dir, &engine, &counter);
        let mut input = oversized_request_line();
        input.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"ping\"}\n");
        let mut output: Vec<u8> = Vec::new();

        serve_requests(
            &mut std::io::Cursor::new(input),
            &mut output,
            &exec,
            &session_log(&dir),
            RequestBudget::new(MAX_MCP_REQUESTS),
        )
        .unwrap();

        let responses: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["error"]["code"], -32600);
        assert_eq!(
            responses[0]["error"]["message"],
            "request exceeds the maximum size"
        );
        assert!(responses[0]["id"].is_null());
        assert_eq!(responses[1]["id"], 11);
        assert_eq!(responses[1]["result"], json!({}));
    }

    #[test]
    fn serve_requests_fails_when_the_oversize_rejection_cannot_be_written() {
        let (dir, engine, counter) = executor_setup();
        let exec = tool_executor(&dir, &engine, &counter);

        let error = serve_requests(
            &mut std::io::Cursor::new(oversized_request_line()),
            &mut BrokenPipeWriter,
            &exec,
            &session_log(&dir),
            RequestBudget::new(MAX_MCP_REQUESTS),
        )
        .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn request_limit_write_failures_preserve_the_transport_error() {
        let error =
            charge_request_budget(&mut RequestBudget::new(0), &mut BrokenPipeWriter).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn an_oversized_line_costs_one_request_from_the_session_budget() {
        let (dir, engine, counter) = executor_setup();
        let exec = tool_executor(&dir, &engine, &counter);
        let mut input = oversized_request_line();
        input.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n");
        let mut output: Vec<u8> = Vec::new();

        let error = serve_requests(
            &mut std::io::Cursor::new(input),
            &mut output,
            &exec,
            &session_log(&dir),
            RequestBudget::new(1),
        )
        .unwrap_err();

        let responses: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(responses.len(), 2, "{responses:?}");
        assert_eq!(responses[0]["error"]["code"], INVALID_REQUEST_CODE);
        assert_eq!(responses[1]["error"]["code"], SESSION_LIMIT_CODE);
        assert!(
            responses[1]["error"]["message"]
                .as_str()
                .unwrap()
                .contains("exceeds 1 requests")
        );
        assert!(activity_lines(&dir).is_empty());
    }

    fn answered(request: Value) -> Value {
        let (dir, engine, counter) = executor_setup();
        let exec = tool_executor(&dir, &engine, &counter);
        let response = handle_request(request, &exec, &session_log(&dir))
            .expect("a request carrying an id must be answered");
        serde_json::from_str(&response).expect("responses are JSON")
    }

    #[test]
    fn requests_outside_the_jsonrpc_envelope_are_invalid_with_a_null_id() {
        for request in [
            json!([{ "jsonrpc": "2.0", "id": 1, "method": "ping" }]),
            json!("ping"),
            json!({ "id": 1, "method": "ping" }),
            json!({ "jsonrpc": "1.0", "id": 1, "method": "ping" }),
            json!({ "jsonrpc": "2.0", "id": 1, "method": "ping", "extra": true }),
            json!({ "jsonrpc": "2.0", "id": 1 }),
            json!({ "jsonrpc": "2.0", "id": true, "method": "ping" }),
            json!({ "jsonrpc": "2.0", "id": 1.5, "method": "ping" }),
            json!({ "jsonrpc": "2.0", "id": 1, "method": 7 }),
            json!({ "jsonrpc": "2.0", "id": 1, "method": "ping", "params": [1, 2] }),
        ] {
            let response = answered(request.clone());

            assert_eq!(response["jsonrpc"], JSONRPC_VERSION, "{request}");
            assert_eq!(response["error"]["code"], INVALID_REQUEST_CODE, "{request}");
            assert!(response["id"].is_null(), "{request}");
            assert!(response["result"].is_null(), "{request}");
        }
    }

    #[test]
    fn malformed_json_is_a_parse_error_and_reaches_no_tool() {
        let (dir, engine, counter) = executor_setup();
        let exec = tool_executor(&dir, &engine, &counter);

        let response = handle_line("{\"jsonrpc\": \"2.0\", ", &exec, &session_log(&dir))
            .expect("malformed JSON must be answered");
        let response: Value = serde_json::from_str(&response).unwrap();

        assert_eq!(response["error"]["code"], PARSE_ERROR_CODE);
        assert!(response["id"].is_null());
        assert!(activity_lines(&dir).is_empty());
    }

    #[test]
    fn malformed_tool_calls_are_refused_before_the_executor_runs() {
        let (dir, engine, counter) = executor_setup();
        let exec = tool_executor(&dir, &engine, &counter);
        let log = session_log(&dir);

        for params in [
            None,
            Some(json!({})),
            Some(json!({ "name": "   " })),
            Some(json!({ "name": 7 })),
            Some(json!({ "name": "read_file", "extra": 1 })),
            Some(json!({ "name": "read_file", "arguments": [] })),
            Some(json!({ "name": "read_file", "arguments": "a.rs" })),
        ] {
            let mut request = json!({ "jsonrpc": "2.0", "id": 4, "method": "tools/call" });
            if let Some(params) = params {
                request["params"] = params;
            }

            let response = handle_request(request.clone(), &exec, &log)
                .expect("a malformed tools/call must be answered");
            let response: Value = serde_json::from_str(&response).unwrap();

            assert_eq!(response["error"]["code"], INVALID_PARAMS_CODE, "{request}");
            assert_eq!(response["id"], 4, "{request}");
            assert!(response["result"].is_null(), "{request}");
        }

        assert!(
            activity_lines(&dir).is_empty(),
            "a malformed call must never reach a tool"
        );
    }

    #[test]
    fn notifications_and_requests_without_an_id_stay_silent_and_run_nothing() {
        let (dir, engine, counter) = executor_setup();
        let exec = tool_executor(&dir, &engine, &counter);
        let log = session_log(&dir);

        for request in [
            json!({ "jsonrpc": "2.0", "method": "notifications/cancelled" }),
            json!({ "jsonrpc": "2.0", "method": "notifications/progress", "params": { "n": 1 } }),
            json!({ "jsonrpc": "2.0", "method": "ping" }),
            json!({ "jsonrpc": "2.0", "method": "tools/call", "params": { "name": "discover_files" } }),
            json!({ "jsonrpc": "2.0", "id": null, "method": "tools/call",
                "params": { "name": "discover_files" } }),
        ] {
            assert!(
                handle_request(request.clone(), &exec, &log).is_none(),
                "{request}"
            );
        }

        assert!(activity_lines(&dir).is_empty());
    }

    #[test]
    fn id_bearing_notification_named_method_receives_method_not_found() {
        let response =
            answered(json!({ "jsonrpc": "2.0", "id": 5, "method": "notifications/initialized" }));

        assert_eq!(response["id"], 5);
        assert_eq!(response["error"]["code"], METHOD_NOT_FOUND_CODE);
    }

    #[test]
    fn a_string_id_is_echoed_with_its_original_type() {
        let response = answered(json!({ "jsonrpc": "2.0", "id": "req-1", "method": "ping" }));

        assert_eq!(response["id"], "req-1");
        assert_eq!(response["result"], json!({}));
    }

    #[cfg(feature = "fuzzing")]
    #[test]
    fn the_fuzzing_line_facade_reports_parse_errors() {
        let (dir, engine, counter) = executor_setup();
        let exec = tool_executor(&dir, &engine, &counter);
        let log = session_log(&dir);

        let malformed = dispatch_mcp_line("{oops", &exec, &log).unwrap();
        let malformed: Value = serde_json::from_str(&malformed).unwrap();
        let ping = dispatch_mcp_line(
            "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}",
            &exec,
            &log,
        )
        .unwrap();
        let ping: Value = serde_json::from_str(&ping).unwrap();

        assert_eq!(malformed["error"]["code"], PARSE_ERROR_CODE);
        assert_eq!(ping["id"], 3);
        assert_eq!(ping["result"], json!({}));
    }
}
