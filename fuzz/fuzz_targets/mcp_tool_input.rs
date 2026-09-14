#![no_main]

use std::path::PathBuf;
use std::sync::{Arc, LazyLock};

use bughunter::Config;
use bughunter::fuzzing::{
    DefaultEngine, FindingCounter, ProjectInventory, SessionLog, ToolExecutor, dispatch_mcp_line,
    dispatch_mcp_request,
};
use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};
use tempfile::TempDir;

const MAX_REQUEST_BYTES: usize = 64 * 1024;
const SAMPLE_SOURCE: &str =
    "fn sample(value: u32) -> u32 {\n    let unused = value;\n    value + 1\n}\n";
const SAMPLE_FILE: &str = "sample.rs";
const FINDINGS_FILE: &str = "findings.jsonl";
const ACTIVITY_FILE: &str = "activity.jsonl";
const JSON_RPC_VERSION: &str = "2.0";
const NOTIFICATION_PREFIX: &str = "notifications/";
const PARSE_ERROR_CODE: i64 = -32700;
const INVALID_REQUEST_CODE: i64 = -32600;
const METHOD_NOT_FOUND_CODE: i64 = -32601;
const INVALID_PARAMS_CODE: i64 = -32602;
const KNOWN_METHODS: [&str; 4] = ["initialize", "ping", "tools/list", "tools/call"];
const METHODS: [&str; 8] = [
    "initialize",
    "notifications/initialized",
    "notifications/cancelled",
    "ping",
    "tools/list",
    "tools/call",
    "tools/unknown",
    "",
];
const TOOL_NAMES: [&str; 8] = [
    "discover_files",
    "search_text",
    "read_file",
    "project_stats",
    "search_ast",
    "submit_findings",
    "unknown_tool",
    "",
];

struct McpFixture {
    _directory: TempDir,
    executor: ToolExecutor,
    log: SessionLog,
    findings_path: PathBuf,
    activity_path: PathBuf,
}

static FIXTURE: LazyLock<McpFixture> = LazyLock::new(|| {
    let directory = tempfile::tempdir().expect("temporary directory");
    std::fs::write(directory.path().join(SAMPLE_FILE), SAMPLE_SOURCE).expect("sample source");
    let engine_config = Config::default().engine;
    let inventory =
        ProjectInventory::build(directory.path(), &engine_config).expect("project inventory");
    let findings_path = directory.path().join(FINDINGS_FILE);
    let activity_path = directory.path().join(ACTIVITY_FILE);
    McpFixture {
        executor: ToolExecutor::from_inventory(
            Arc::new(DefaultEngine::new(engine_config)),
            Arc::new(inventory),
            Arc::new(FindingCounter::new()),
        ),
        log: SessionLog::new(findings_path.clone(), activity_path.clone()),
        findings_path,
        activity_path,
        _directory: directory,
    }
});

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_REQUEST_BYTES {
        return;
    }
    std::fs::write(&FIXTURE.findings_path, []).expect("findings log reset");
    std::fs::write(&FIXTURE.activity_path, []).expect("activity log reset");

    let executor = &FIXTURE.executor;
    let mut cursor = ByteCursor::new(data);

    let shape = cursor.byte() % 3;
    if shape == 0 {
        let line = String::from_utf8_lossy(cursor.rest()).into_owned();
        let response = dispatch_mcp_line(&line, executor, &FIXTURE.log);
        match serde_json::from_str::<Value>(&line) {
            Ok(request) => assert_dispatch_honours_the_protocol(&request, response.as_deref()),
            Err(_) => assert_unparsable_lines_are_reported(&line, response.as_deref()),
        }
        return;
    }

    let request = build_request(shape, &mut cursor);
    let response = dispatch_mcp_request(&request, executor, &FIXTURE.log);
    assert_dispatch_honours_the_protocol(&request, response.as_deref());
});

fn build_request(shape: u8, cursor: &mut ByteCursor) -> Value {
    let identifier = cursor.identifier();
    if shape == 1 {
        return json!({
            "jsonrpc": JSON_RPC_VERSION,
            "id": identifier,
            "method": METHODS[usize::from(cursor.byte()) % METHODS.len()],
        });
    }
    let name = TOOL_NAMES[usize::from(cursor.byte()) % TOOL_NAMES.len()];
    let arguments = serde_json::from_slice(cursor.rest()).unwrap_or_else(|_| json!({}));
    json!({
        "jsonrpc": JSON_RPC_VERSION,
        "id": identifier,
        "method": "tools/call",
        "params": { "name": name, "arguments": arguments },
    })
}

fn assert_unparsable_lines_are_reported(line: &str, response: Option<&str>) {
    let response =
        response.unwrap_or_else(|| panic!("unparsable line {line:?} was answered with silence"));
    let parsed: Value = serde_json::from_str(response)
        .unwrap_or_else(|error| panic!("parse failure produced invalid JSON: {error}"));

    assert_eq!(parsed["jsonrpc"], JSON_RPC_VERSION);
    assert_eq!(
        parsed["error"]["code"], PARSE_ERROR_CODE,
        "unparsable line {line:?} produced {parsed}"
    );
    assert!(
        parsed["id"].is_null(),
        "parse failure invented an identifier: {parsed}"
    );
}

fn assert_dispatch_honours_the_protocol(request: &Value, response: Option<&str>) {
    let method = request.get("method").and_then(Value::as_str);
    let identifier = request.get("id").cloned().unwrap_or(Value::Null);

    let Some(response) = response else {
        let method = method.unwrap_or_else(|| {
            panic!("request {request} without a string method was answered with silence")
        });
        assert_eq!(
            request["jsonrpc"], JSON_RPC_VERSION,
            "request {request} with a foreign protocol version was answered with silence"
        );
        assert!(
            method.starts_with(NOTIFICATION_PREFIX) || identifier.is_null(),
            "request {request} was answered with silence"
        );
        return;
    };

    let parsed: Value = serde_json::from_str(response)
        .unwrap_or_else(|error| panic!("request {request} produced invalid JSON: {error}"));
    assert_eq!(
        parsed["jsonrpc"], JSON_RPC_VERSION,
        "request {request} produced a foreign protocol envelope"
    );
    assert!(
        parsed.get("result").is_some() != parsed.get("error").is_some(),
        "request {request} produced neither or both of result and error"
    );

    if parsed.get("error").is_some() {
        assert_rejection_is_attributable(request, &parsed, method, &identifier);
        return;
    }

    assert_eq!(
        parsed["id"], identifier,
        "request {request} was answered under a different identifier"
    );
    let method = method.unwrap_or_else(|| panic!("request {request} answered without a method"));
    assert!(
        KNOWN_METHODS.contains(&method),
        "unsupported method {method:?} produced a result"
    );
    match method {
        "tools/call" => assert_tool_failures_stay_inside_the_result(&parsed["result"]),
        "tools/list" => assert_advertised_tools_are_callable(&parsed["result"]),
        _ => assert!(
            parsed["result"].is_object(),
            "method {method:?} produced a non-object result: {parsed}"
        ),
    }
}

fn assert_rejection_is_attributable(
    request: &Value,
    parsed: &Value,
    method: Option<&str>,
    identifier: &Value,
) {
    let error = &parsed["error"];
    assert!(
        error["message"]
            .as_str()
            .is_some_and(|message| !message.is_empty()),
        "request {request} was rejected without a reason"
    );
    let code = error["code"]
        .as_i64()
        .unwrap_or_else(|| panic!("request {request} was rejected without a numeric code"));

    match code {
        INVALID_REQUEST_CODE => assert!(
            parsed["id"].is_null(),
            "envelope rejection echoed an unverified identifier: {parsed}"
        ),
        METHOD_NOT_FOUND_CODE => {
            assert_eq!(parsed["id"], *identifier);
            let method =
                method.unwrap_or_else(|| panic!("request {request} lost its method on rejection"));
            assert!(
                !KNOWN_METHODS.contains(&method),
                "callable method {method:?} was reported as not found"
            );
        }
        INVALID_PARAMS_CODE => {
            assert_eq!(parsed["id"], *identifier);
            assert_eq!(
                method,
                Some("tools/call"),
                "request {request} reported invalid params outside a tool call"
            );
        }
        other => panic!("request {request} produced unexpected error code {other}"),
    }
}

fn assert_tool_failures_stay_inside_the_result(result: &Value) {
    let content = result["content"]
        .as_array()
        .unwrap_or_else(|| panic!("tool call answered without a content array: {result}"));
    assert_eq!(
        content.len(),
        1,
        "tool call answered with {} content blocks: {result}",
        content.len()
    );
    assert_eq!(
        content[0]["type"], "text",
        "tool call answered with a non-text block: {result}"
    );
    assert!(
        content[0]["text"].is_string(),
        "tool call answered with a non-string text block: {result}"
    );
    if let Some(is_error) = result.get("isError") {
        assert_eq!(
            is_error,
            &Value::Bool(true),
            "tool call flagged a non-failure: {result}"
        );
    }
}

fn assert_advertised_tools_are_callable(result: &Value) {
    let tools = result["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tool listing answered without an array: {result}"));
    assert!(!tools.is_empty(), "tool listing answered empty: {result}");
    for tool in tools {
        let name = tool["name"]
            .as_str()
            .unwrap_or_else(|| panic!("advertised tool without a name: {tool}"));
        assert!(
            TOOL_NAMES.contains(&name),
            "advertised unknown tool {name:?}"
        );
        assert!(
            tool["description"]
                .as_str()
                .is_some_and(|text| !text.is_empty()),
            "advertised tool {name:?} without a description"
        );
        assert!(
            tool["inputSchema"].is_object(),
            "advertised tool {name:?} without an input schema"
        );
    }
}

struct ByteCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> ByteCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { remaining: data }
    }

    fn byte(&mut self) -> u8 {
        let remaining = self.remaining;
        let Some((value, rest)) = remaining.split_first() else {
            return 0;
        };
        self.remaining = rest;
        *value
    }

    fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.remaining)
    }

    fn identifier(&mut self) -> Value {
        match self.byte() % 3 {
            0 => Value::Null,
            1 => json!(i64::from(self.byte())),
            _ => json!(format!("call-{}", self.byte())),
        }
    }
}
