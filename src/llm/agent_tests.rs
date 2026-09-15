use std::io::Write;
use std::sync::Arc;

use super::*;
use crate::cancel::CancelToken;
use crate::config::EngineConfig;
use crate::config::schema::LlmConfig;
use crate::engine::{
    DefaultEngine, DiscoverOpts, Engine, FileContent, ProjectFilesystem, ProjectInventory,
    ProjectStats, SearchOpts, TextMatch,
};
use crate::llm::coverage::CoverageTracker;
use crate::llm::tool_exec::ToolExecutor;
use crate::llm::types::{
    ContentBlock, LlmOutput, LlmResponse, Role, StopReason, TokenUsage, ToolConfig, ToolUseBlock,
};
use crate::report::FindingCounter;
use async_trait::async_trait;
use parking_lot::Mutex;
use serde_json::json;
use tracing_subscriber::layer::SubscriberExt;

#[derive(Clone, Default)]
struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

impl CapturedLogs {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().clone()).expect("log output is utf-8")
    }
}

impl Write for CapturedLogs {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0.lock().extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn capture_debug_logs() -> (CapturedLogs, tracing::subscriber::DefaultGuard) {
    let captured = CapturedLogs::default();
    let sink = captured.clone();
    let layer = tracing_subscriber::fmt::layer()
        .with_writer(move || sink.clone())
        .with_ansi(false)
        .without_time();
    let guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));
    (captured, guard)
}

struct ScriptedBackend {
    responses: Mutex<Vec<LlmResponse>>,
    calls: Mutex<Vec<Vec<Message>>>,
    tool_names: Mutex<Vec<Vec<String>>>,
}

impl ScriptedBackend {
    fn new(responses: Vec<LlmResponse>) -> Self {
        Self {
            responses: Mutex::new(responses),
            calls: Mutex::new(Vec::new()),
            tool_names: Mutex::new(Vec::new()),
        }
    }

    fn call_count(&self) -> usize {
        self.calls.lock().len()
    }

    fn last_messages(&self) -> Vec<Message> {
        self.calls.lock().last().cloned().unwrap_or_default()
    }

    fn last_tool_names(&self) -> Vec<String> {
        self.tool_names.lock().last().cloned().unwrap_or_default()
    }
}

#[async_trait]
impl LlmBackend for ScriptedBackend {
    async fn converse(
        &self,
        messages: &[Message],
        _system_prompt: &str,
        tool_config: &ToolConfig,
    ) -> Result<LlmResponse, LlmError> {
        self.calls.lock().push(messages.to_vec());
        self.tool_names.lock().push(
            tool_config
                .tools
                .iter()
                .map(|tool| tool.tool_spec.name.clone())
                .collect(),
        );
        let mut queue = self.responses.lock();
        assert!(
            !queue.is_empty(),
            "ScriptedBackend exhausted — test asked for more turns than scripted"
        );
        Ok(queue.remove(0))
    }
}

struct StallingBackend {
    responses: Mutex<Vec<LlmResponse>>,
    stalled: tokio::sync::Notify,
}

impl StallingBackend {
    fn new(responses: Vec<LlmResponse>) -> Self {
        Self {
            responses: Mutex::new(responses),
            stalled: tokio::sync::Notify::new(),
        }
    }

    async fn wait_until_stalled(&self) {
        self.stalled.notified().await;
    }
}

#[async_trait]
impl LlmBackend for StallingBackend {
    async fn converse(
        &self,
        _messages: &[Message],
        _system_prompt: &str,
        _tool_config: &ToolConfig,
    ) -> Result<LlmResponse, LlmError> {
        let next = {
            let mut queue = self.responses.lock();
            (!queue.is_empty()).then(|| queue.remove(0))
        };
        match next {
            Some(response) => Ok(response),
            None => {
                self.stalled.notify_one();
                std::future::pending().await
            }
        }
    }
}

struct CancellingBackend {
    responses: Mutex<Vec<LlmResponse>>,
    cancel: CancelToken,
}

impl CancellingBackend {
    fn new(cancel: CancelToken, responses: Vec<LlmResponse>) -> Self {
        Self {
            responses: Mutex::new(responses),
            cancel,
        }
    }
}

#[async_trait]
impl LlmBackend for CancellingBackend {
    async fn converse(
        &self,
        _messages: &[Message],
        _system_prompt: &str,
        _tool_config: &ToolConfig,
    ) -> Result<LlmResponse, LlmError> {
        let mut queue = self.responses.lock();
        assert!(
            !queue.is_empty(),
            "CancellingBackend exhausted — the loop kept going after cancellation"
        );
        self.cancel.cancel();
        Ok(queue.remove(0))
    }
}

struct CancelOnResponseBackend {
    responses: Mutex<Vec<LlmResponse>>,
    cancel: CancelToken,
    cancel_on_call: usize,
    calls: std::sync::atomic::AtomicUsize,
}

#[async_trait]
impl LlmBackend for CancelOnResponseBackend {
    async fn converse(
        &self,
        _messages: &[Message],
        _system_prompt: &str,
        _tool_config: &ToolConfig,
    ) -> Result<LlmResponse, LlmError> {
        let response = self.responses.lock().remove(0);
        let call = self
            .calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        if call == self.cancel_on_call {
            self.cancel.cancel();
        }
        Ok(response)
    }
}

struct StallingReadEngine {
    delegate: DefaultEngine,
    started: tokio::sync::Notify,
    released: parking_lot::Condvar,
    may_finish: Mutex<bool>,
}

impl StallingReadEngine {
    fn new() -> Self {
        Self {
            delegate: DefaultEngine::new(EngineConfig::default()),
            started: tokio::sync::Notify::new(),
            released: parking_lot::Condvar::new(),
            may_finish: Mutex::new(false),
        }
    }

    async fn wait_until_started(&self) {
        self.started.notified().await;
    }

    fn release(&self) {
        *self.may_finish.lock() = true;
        self.released.notify_all();
    }
}

impl Engine for StallingReadEngine {
    fn discover_files(
        &self,
        root: &std::path::Path,
        opts: &DiscoverOpts,
    ) -> Result<Vec<crate::engine::FileEntry>, crate::errors::EngineError> {
        self.delegate.discover_files(root, opts)
    }

    fn search_project_text(
        &self,
        filesystem: &ProjectFilesystem,
        pattern: &str,
        opts: &SearchOpts,
    ) -> Result<Vec<TextMatch>, crate::errors::EngineError> {
        self.delegate.search_project_text(filesystem, pattern, opts)
    }

    fn search_inventory_text(
        &self,
        inventory: &ProjectInventory,
        pattern: &str,
        opts: &SearchOpts,
    ) -> Result<Vec<TextMatch>, crate::errors::EngineError> {
        self.delegate
            .search_inventory_text(inventory, pattern, opts)
    }

    fn read_project_file(
        &self,
        filesystem: &ProjectFilesystem,
        path: &crate::domain::ProjectPath,
        range: Option<crate::domain::LineRange>,
    ) -> Result<FileContent, crate::errors::EngineError> {
        self.started.notify_one();
        let mut may_finish = self.may_finish.lock();
        while !*may_finish {
            self.released.wait(&mut may_finish);
        }
        self.delegate.read_project_file(filesystem, path, range)
    }

    fn is_path_excluded(&self, path: &std::path::Path) -> bool {
        self.delegate.is_path_excluded(path)
    }

    fn is_path_ignored_by_repository(
        &self,
        project_root: &std::path::Path,
        path: &std::path::Path,
    ) -> bool {
        self.delegate
            .is_path_ignored_by_repository(project_root, path)
    }

    fn project_stats_with_capability(
        &self,
        filesystem: &ProjectFilesystem,
    ) -> Result<ProjectStats, crate::errors::EngineError> {
        self.delegate.project_stats_with_capability(filesystem)
    }

    fn discover_files_cancellable(
        &self,
        root: &std::path::Path,
        opts: &DiscoverOpts,
        cancel: &crate::cancel::CancelToken,
    ) -> Result<Vec<crate::engine::FileEntry>, crate::errors::EngineError> {
        self.delegate.discover_files_cancellable(root, opts, cancel)
    }

    fn search_project_text_cancellable(
        &self,
        filesystem: &ProjectFilesystem,
        pattern: &str,
        opts: &SearchOpts,
        cancel: &crate::cancel::CancelToken,
    ) -> Result<Vec<TextMatch>, crate::errors::EngineError> {
        self.delegate
            .search_project_text_cancellable(filesystem, pattern, opts, cancel)
    }

    fn search_inventory_entries(
        &self,
        inventory: &ProjectInventory,
        entries: &[crate::engine::FileEntry],
        pattern: &str,
        opts: &SearchOpts,
    ) -> Result<Vec<TextMatch>, crate::errors::EngineError> {
        self.delegate
            .search_inventory_entries(inventory, entries, pattern, opts)
    }

    fn search_inventory_entries_cancellable(
        &self,
        inventory: &ProjectInventory,
        entries: &[crate::engine::FileEntry],
        pattern: &str,
        opts: &SearchOpts,
        cancel: &crate::cancel::CancelToken,
    ) -> Result<Vec<TextMatch>, crate::errors::EngineError> {
        self.delegate
            .search_inventory_entries_cancellable(inventory, entries, pattern, opts, cancel)
    }

    fn project_stats_with_capability_cancellable(
        &self,
        filesystem: &ProjectFilesystem,
        cancel: &crate::cancel::CancelToken,
    ) -> Result<ProjectStats, crate::errors::EngineError> {
        self.delegate
            .project_stats_with_capability_cancellable(filesystem, cancel)
    }
}

fn end_turn_response() -> LlmResponse {
    LlmResponse {
        output: LlmOutput {
            message: Message {
                role: Role::Assistant,
                content: vec![ContentBlock::Text {
                    text: "nothing to report".into(),
                }],
            },
        },
        stop_reason: StopReason::EndTurn,
        usage: TokenUsage::default(),
    }
}

fn read_file_response(path: &str, tool_use_id: &str) -> LlmResponse {
    LlmResponse {
        output: LlmOutput {
            message: Message {
                role: Role::Assistant,
                content: vec![ContentBlock::ToolUse {
                    tool_use: ToolUseBlock {
                        tool_use_id: tool_use_id.into(),
                        name: crate::llm::tools::READ_FILE.into(),
                        input: json!({ "path": path }),
                    },
                }],
            },
        },
        stop_reason: StopReason::ToolUse,
        usage: TokenUsage::default(),
    }
}

fn tool_use_response(name: &str, tool_use_id: &str) -> LlmResponse {
    LlmResponse {
        output: LlmOutput {
            message: Message {
                role: Role::Assistant,
                content: vec![ContentBlock::ToolUse {
                    tool_use: ToolUseBlock {
                        tool_use_id: tool_use_id.into(),
                        name: name.into(),
                        input: json!({}),
                    },
                }],
            },
        },
        stop_reason: StopReason::ToolUse,
        usage: TokenUsage::default(),
    }
}

fn empty_submission_response(tool_use_id: &str) -> LlmResponse {
    let mut response = tool_use_response(crate::llm::tools::SUBMIT_FINDINGS, tool_use_id);
    if let ContentBlock::ToolUse { tool_use } = &mut response.output.message.content[0] {
        tool_use.input = json!({ "findings": [] });
    }
    response
}

fn with_usage(mut response: LlmResponse, input_tokens: u32, output_tokens: u32) -> LlmResponse {
    response.usage = TokenUsage {
        input_tokens,
        output_tokens,
    };
    response
}

fn parallel_empty_submission_response() -> LlmResponse {
    let first = empty_submission_response("call-2");
    let second = empty_submission_response("call-3");
    LlmResponse {
        output: LlmOutput {
            message: Message {
                role: Role::Assistant,
                content: vec![
                    first.output.message.content[0].clone(),
                    second.output.message.content[0].clone(),
                ],
            },
        },
        stop_reason: StopReason::ToolUse,
        usage: TokenUsage::default(),
    }
}

fn messages_contain_nudge(messages: &[Message]) -> bool {
    messages.iter().any(|m| {
        m.content.iter().any(|b| match b {
            ContentBlock::Text { text } => {
                text.contains("injecting")
                    || text.contains("You ended the turn without invoking any analysis tool")
            }
            _ => false,
        })
    })
}

fn scripted(responses: Vec<LlmResponse>) -> std::sync::Arc<ScriptedBackend> {
    std::sync::Arc::new(ScriptedBackend::new(responses))
}
fn test_agent_loop<'a>(
    backend: &'a dyn LlmBackend,
    engine: &DefaultEngine,
    inventory: &ProjectInventory,
    counter: &FindingCounter,
    max_context_tokens: u32,
    max_iterations: u32,
) -> AgentLoop<'a> {
    test_agent_loop_with_coverage(
        backend,
        engine,
        inventory,
        counter,
        max_context_tokens,
        max_iterations,
        None,
    )
}

fn test_agent_loop_with_coverage<'a>(
    backend: &'a dyn LlmBackend,
    _engine: &DefaultEngine,
    inventory: &ProjectInventory,
    _counter: &FindingCounter,
    max_context_tokens: u32,
    max_iterations: u32,
    coverage: Option<Arc<CoverageTracker>>,
) -> AgentLoop<'a> {
    let config = EngineConfig::default();
    let engine: Arc<dyn crate::engine::Engine> = Arc::new(DefaultEngine::new(config.clone()));
    let inventory = Arc::new(
        ProjectInventory::build(inventory.filesystem().root().as_path(), &config).unwrap(),
    );
    let counter = Arc::new(FindingCounter::new());
    let mut tools = ToolExecutor::from_inventory(engine, inventory, counter);
    if let Some(coverage) = coverage {
        tools = tools.with_coverage(coverage);
    }
    AgentLoop::new(backend, Arc::new(tools), max_context_tokens, max_iterations)
}

async fn run_scripted(
    responses: Vec<LlmResponse>,
) -> (std::sync::Arc<ScriptedBackend>, Vec<Finding>) {
    run_scripted_with_limit(responses, 10).await
}

async fn run_scripted_with_limit(
    responses: Vec<LlmResponse>,
    max_iterations: u32,
) -> (std::sync::Arc<ScriptedBackend>, Vec<Finding>) {
    let (backend, result) = run_scripted_result(responses, max_iterations).await;
    (
        backend,
        result.expect("agent loop should complete successfully"),
    )
}

async fn run_scripted_result(
    responses: Vec<LlmResponse>,
    max_iterations: u32,
) -> (
    std::sync::Arc<ScriptedBackend>,
    Result<Vec<Finding>, LlmError>,
) {
    let backend = scripted(responses);
    let engine = DefaultEngine::new(EngineConfig::default());
    let tmp = tempfile::tempdir().unwrap();
    let counter = FindingCounter::new();
    let inventory = ProjectInventory::build(tmp.path(), &EngineConfig::default()).unwrap();

    let result = {
        let mut loop_state = test_agent_loop(
            backend.as_ref(),
            &engine,
            &inventory,
            &counter,
            180_000,
            max_iterations,
        );
        loop_state.run("SYS", "REPO MAP").await
    };

    (backend, result)
}

#[tokio::test]
async fn zero_iteration_limit_is_rejected_before_analysis() {
    let (backend, result) = run_scripted_result(Vec::new(), 0).await;

    let error = result.expect_err("zero iterations must reject the analysis");
    assert!(
        error
            .to_string()
            .contains("iteration limit is zero; no analysis was performed"),
        "{error}"
    );
    assert_eq!(backend.call_count(), 0);
}

#[tokio::test]
async fn reserves_the_last_iteration_for_finding_submission() {
    let (backend, findings) = run_scripted_with_limit(
        vec![
            tool_use_response("project_stats", "call-1"),
            empty_submission_response("call-2"),
        ],
        2,
    )
    .await;

    assert_eq!(backend.call_count(), 2);
    assert!(findings.is_empty());
    assert_eq!(
        backend.last_tool_names(),
        vec![crate::llm::tools::SUBMIT_FINDINGS]
    );
    assert!(
        backend
            .last_messages()
            .iter()
            .flat_map(|message| &message.content)
            .filter_map(ContentBlock::as_text)
            .any(|text| text.contains("final agent turn")),
        "last request should tell the model to stop exploring and submit"
    );
}

#[tokio::test]
async fn retries_when_the_final_turn_ends_without_submission() {
    let (backend, findings) = run_scripted_with_limit(
        vec![
            tool_use_response("project_stats", "call-1"),
            end_turn_response(),
            empty_submission_response("call-2"),
        ],
        2,
    )
    .await;

    assert_eq!(backend.call_count(), 3);
    assert!(findings.is_empty());
    assert!(
        backend
            .last_messages()
            .iter()
            .flat_map(|message| &message.content)
            .filter_map(ContentBlock::as_text)
            .any(|text| text.contains("previous final response"))
    );
}

#[tokio::test]
async fn retries_a_malformed_final_submission() {
    let (backend, findings) = run_scripted_with_limit(
        vec![
            tool_use_response("project_stats", "call-1"),
            tool_use_response(crate::llm::tools::SUBMIT_FINDINGS, "call-2"),
            empty_submission_response("call-3"),
        ],
        2,
    )
    .await;

    assert_eq!(backend.call_count(), 3);
    assert!(findings.is_empty());
}

#[tokio::test]
async fn retries_when_finalization_returns_parallel_submissions() {
    let (backend, findings) = run_scripted_with_limit(
        vec![
            tool_use_response("project_stats", "call-1"),
            parallel_empty_submission_response(),
            empty_submission_response("call-4"),
        ],
        2,
    )
    .await;

    assert_eq!(backend.call_count(), 3);
    assert!(findings.is_empty());
}

#[tokio::test]
async fn retries_when_finalization_calls_an_exploration_tool() {
    let (backend, findings) = run_scripted_with_limit(
        vec![
            tool_use_response("project_stats", "call-1"),
            read_file_response("missing.rs", "call-2"),
            empty_submission_response("call-3"),
        ],
        2,
    )
    .await;

    assert_eq!(backend.call_count(), 3);
    assert!(findings.is_empty());
}

#[tokio::test]
async fn errors_after_finalization_retries_are_exhausted() {
    let (backend, result) = run_scripted_result(
        vec![
            tool_use_response("project_stats", "call-1"),
            end_turn_response(),
            end_turn_response(),
            end_turn_response(),
        ],
        2,
    )
    .await;

    assert_eq!(backend.call_count(), 4);
    let error = result.expect_err("missing final submission must fail the scan");
    assert!(error.to_string().contains("finalization attempts"));
}

#[tokio::test]
async fn does_not_mix_exploration_nudge_into_the_final_turn() {
    let (backend, result) = run_scripted_result(
        vec![end_turn_response(), empty_submission_response("call-2")],
        2,
    )
    .await;

    assert!(result.is_err());
    assert_eq!(backend.call_count(), 1);
}

#[tokio::test]
async fn nudges_when_agent_ends_without_any_tool_use() {
    let (backend, findings) = run_scripted(vec![
        end_turn_response(),
        tool_use_response("project_stats", "call-1"),
        end_turn_response(),
        empty_submission_response("call-2"),
    ])
    .await;

    assert_eq!(backend.call_count(), 4, "expected one nudge retry");
    assert!(findings.is_empty());
    assert!(
        messages_contain_nudge(&backend.last_messages()),
        "second call should include the exploration nudge user message",
    );
}

#[tokio::test]
async fn successful_early_submission_completes_without_resubmitting() {
    let (backend, findings) = run_scripted(vec![
        empty_submission_response("call-1"),
        end_turn_response(),
    ])
    .await;

    assert_eq!(backend.call_count(), 2);
    assert!(findings.is_empty());
    assert!(backend.last_tool_names().len() > 1);
}

#[tokio::test]
async fn early_end_after_tool_use_forces_final_submission() {
    let (backend, _findings) = run_scripted(vec![
        tool_use_response("project_stats", "call-1"),
        end_turn_response(),
        empty_submission_response("call-2"),
    ])
    .await;

    assert_eq!(backend.call_count(), 3);
    assert_eq!(
        backend.last_tool_names(),
        vec![crate::llm::tools::SUBMIT_FINDINGS]
    );
    for captured in backend.calls.lock().iter() {
        assert!(
            !messages_contain_nudge(captured),
            "nudge should not appear when the agent already invoked a tool",
        );
    }
}

#[tokio::test]
async fn errors_after_one_nudge_if_model_keeps_bailing() {
    let (backend, result) = run_scripted_result(
        vec![
            end_turn_response(),
            end_turn_response(),
            end_turn_response(),
        ],
        10,
    )
    .await;

    assert!(result.is_err());
    assert_eq!(backend.call_count(), 2, "expected exactly one nudge retry");
}

#[tokio::test]
async fn coverage_tracker_records_files_read_through_the_loop() {
    use crate::llm::coverage::CoverageTracker;

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("x.rs"), "fn x() {}\n").unwrap();

    let backend = scripted(vec![
        read_file_response("x.rs", "call-1"),
        end_turn_response(),
        empty_submission_response("call-2"),
    ]);
    let engine = DefaultEngine::new(EngineConfig::default());
    let counter = FindingCounter::new();
    let inventory = ProjectInventory::build(tmp.path(), &EngineConfig::default()).unwrap();
    let tracker = Arc::new(CoverageTracker::new());

    {
        let mut loop_state = test_agent_loop_with_coverage(
            backend.as_ref(),
            &engine,
            &inventory,
            &counter,
            180_000,
            10,
            Some(Arc::clone(&tracker)),
        );
        loop_state.run("SYS", "MAP").await.unwrap();
    }

    assert!(
        tracker.read_paths().contains("x.rs"),
        "the loop should record files opened via read_file"
    );
}

#[test]
fn count_tool_uses_counts_only_tool_use_blocks() {
    let response = LlmResponse {
        output: LlmOutput {
            message: Message {
                role: Role::Assistant,
                content: vec![
                    ContentBlock::Text {
                        text: "thinking".into(),
                    },
                    ContentBlock::ToolUse {
                        tool_use: ToolUseBlock {
                            tool_use_id: "a".into(),
                            name: "read_file".into(),
                            input: json!({}),
                        },
                    },
                    ContentBlock::ToolUse {
                        tool_use: ToolUseBlock {
                            tool_use_id: "b".into(),
                            name: "search_text".into(),
                            input: json!({}),
                        },
                    },
                ],
            },
        },
        stop_reason: StopReason::ToolUse,
        usage: TokenUsage::default(),
    };
    assert_eq!(count_tool_uses(&response), 2);
}

#[tokio::test]
async fn a_pre_cancelled_token_stops_before_the_first_request() {
    let cancel = CancelToken::default();
    cancel.cancel();

    let backend = scripted(vec![empty_submission_response("call-1")]);
    let engine = DefaultEngine::new(EngineConfig::default());
    let tmp = tempfile::tempdir().unwrap();
    let counter = FindingCounter::new();
    let inventory = ProjectInventory::build(tmp.path(), &EngineConfig::default()).unwrap();

    let result = {
        let mut loop_state =
            test_agent_loop(backend.as_ref(), &engine, &inventory, &counter, 180_000, 10)
                .with_cancel(&cancel);
        loop_state.run("SYS", "MAP").await
    };

    assert!(matches!(result, Err(LlmError::Cancelled)), "{result:?}");
    assert_eq!(
        backend.call_count(),
        0,
        "a cancelled scan must not spend a model turn"
    );
}

#[tokio::test]
async fn cancelling_while_waiting_for_a_model_response_aborts_the_loop() {
    let cancel = CancelToken::default();
    let script = vec![tool_use_response("project_stats", "call-1")];
    let backend = std::sync::Arc::new(StallingBackend::new(script));
    let engine = DefaultEngine::new(EngineConfig::default());
    let tmp = tempfile::tempdir().unwrap();
    let counter = FindingCounter::new();
    let inventory = ProjectInventory::build(tmp.path(), &EngineConfig::default()).unwrap();

    let canceller = tokio::spawn({
        let cancel = cancel.clone();
        let backend = backend.clone();
        async move {
            backend.wait_until_stalled().await;
            cancel.cancel();
        }
    });

    let result = {
        let mut loop_state =
            test_agent_loop(backend.as_ref(), &engine, &inventory, &counter, 180_000, 10)
                .with_cancel(&cancel);
        let run = loop_state.run("SYS", "MAP");
        tokio::time::timeout(std::time::Duration::from_secs(5), run)
            .await
            .expect("cancellation must unblock the pending model request")
    };
    canceller.await.unwrap();

    assert!(matches!(result, Err(LlmError::Cancelled)), "{result:?}");
}

#[tokio::test]
async fn cancellation_wins_when_a_successful_end_turn_becomes_ready_in_the_same_poll() {
    let cancel = CancelToken::default();
    let backend = CancelOnResponseBackend {
        responses: Mutex::new(vec![
            empty_submission_response("submit"),
            end_turn_response(),
        ]),
        cancel: cancel.clone(),
        cancel_on_call: 2,
        calls: std::sync::atomic::AtomicUsize::new(0),
    };
    let engine = DefaultEngine::new(EngineConfig::default());
    let tmp = tempfile::tempdir().unwrap();
    let counter = FindingCounter::new();
    let inventory = ProjectInventory::build(tmp.path(), &EngineConfig::default()).unwrap();

    let result = {
        let mut loop_state = test_agent_loop(&backend, &engine, &inventory, &counter, 180_000, 10)
            .with_cancel(&cancel);
        loop_state.run("SYS", "MAP").await
    };

    assert!(matches!(result, Err(LlmError::Cancelled)), "{result:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_aborts_a_running_tool_worker() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("x.rs"), "fn x() {}\n").unwrap();
    let inventory = ProjectInventory::build(directory.path(), &EngineConfig::default()).unwrap();
    let engine = Arc::new(StallingReadEngine::new());
    let counter = Arc::new(FindingCounter::new());
    let tools = Arc::new(ToolExecutor::from_inventory(
        engine.clone(),
        Arc::new(inventory),
        counter,
    ));
    let backend = scripted(vec![read_file_response("x.rs", "call-1")]);
    let cancel = CancelToken::default();

    let canceller = tokio::spawn({
        let cancel = cancel.clone();
        let engine = Arc::clone(&engine);
        async move {
            engine.wait_until_started().await;
            cancel.cancel();
        }
    });

    let timed_result = {
        let mut loop_state =
            AgentLoop::new(backend.as_ref(), tools, 180_000, 10).with_cancel(&cancel);
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            loop_state.run("SYS", "MAP"),
        )
        .await
    };
    canceller.await.unwrap();
    engine.release();

    let result = timed_result.expect("cancellation must unblock the running tool");
    assert!(matches!(result, Err(LlmError::Cancelled)), "{result:?}");
}

#[tokio::test]
async fn cancelling_during_a_turn_stops_before_the_tool_runs() {
    use crate::llm::coverage::CoverageTracker;

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("x.rs"), "fn x() {}\n").unwrap();

    let cancel = CancelToken::default();
    let script = vec![read_file_response("x.rs", "call-1")];
    let backend = std::sync::Arc::new(CancellingBackend::new(cancel.clone(), script));
    let engine = DefaultEngine::new(EngineConfig::default());
    let counter = FindingCounter::new();
    let inventory = ProjectInventory::build(tmp.path(), &EngineConfig::default()).unwrap();
    let tracker = Arc::new(CoverageTracker::new());

    let result = {
        let mut loop_state = test_agent_loop_with_coverage(
            backend.as_ref(),
            &engine,
            &inventory,
            &counter,
            180_000,
            10,
            Some(Arc::clone(&tracker)),
        )
        .with_cancel(&cancel);
        loop_state.run("SYS", "MAP").await
    };

    assert!(matches!(result, Err(LlmError::Cancelled)), "{result:?}");
    assert!(
        tracker.read_paths().is_empty(),
        "no tool may run once cancellation is observed"
    );
}

struct PendingBackend;

#[async_trait]
impl LlmBackend for PendingBackend {
    async fn converse(
        &self,
        _messages: &[Message],
        _system_prompt: &str,
        _tool_config: &ToolConfig,
    ) -> Result<LlmResponse, LlmError> {
        std::future::pending().await
    }
}

#[tokio::test]
async fn an_expired_budget_interrupts_an_in_flight_model_request() {
    let engine = DefaultEngine::new(EngineConfig::default());
    let tmp = tempfile::tempdir().unwrap();
    let counter = FindingCounter::new();
    let inventory = ProjectInventory::build(tmp.path(), &EngineConfig::default()).unwrap();
    let loop_state = test_agent_loop(&PendingBackend, &engine, &inventory, &counter, 180_000, 10);
    let budget = TimeBudget {
        limit: Some(Duration::ZERO),
        started: Instant::now(),
    };
    let messages = [Message::user_text("MAP")];

    let error = loop_state
        .converse(&messages, "SYS", &build_tool_config(), &budget, 3)
        .await
        .expect_err("an expired budget must interrupt a pending request");

    assert!(
        error
            .to_string()
            .contains("shard exceeded the 0s time budget after 3 iterations"),
        "{error}"
    );
}

#[tokio::test]
async fn an_exhausted_time_budget_fails_the_shard() {
    let config = LlmConfig {
        max_shard_seconds: 0,
        ..LlmConfig::default()
    };
    let backend = scripted(vec![empty_submission_response("call-1")]);
    let engine = DefaultEngine::new(EngineConfig::default());
    let tmp = tempfile::tempdir().unwrap();
    let counter = FindingCounter::new();
    let inventory = ProjectInventory::build(tmp.path(), &EngineConfig::default()).unwrap();

    let result = {
        let mut loop_state =
            test_agent_loop(backend.as_ref(), &engine, &inventory, &counter, 180_000, 10)
                .with_time_budget(config.max_shard_seconds);
        loop_state.run("SYS", "MAP").await
    };

    assert_eq!(
        backend.call_count(),
        0,
        "an exhausted budget must not spend a model turn"
    );
    let error = result.expect_err("an exhausted time budget must fail the shard");
    assert!(matches!(error, LlmError::AgentProtocol(_)), "{error:?}");
    assert!(
        error
            .to_string()
            .contains("shard exceeded the 0s time budget after 0 iterations"),
        "{error}"
    );
}

#[tokio::test]
async fn a_generous_time_budget_does_not_interrupt_the_shard() {
    let backend = scripted(vec![
        tool_use_response("project_stats", "call-1"),
        empty_submission_response("call-2"),
    ]);
    let engine = DefaultEngine::new(EngineConfig::default());
    let tmp = tempfile::tempdir().unwrap();
    let counter = FindingCounter::new();
    let inventory = ProjectInventory::build(tmp.path(), &EngineConfig::default()).unwrap();

    let result = {
        let mut loop_state =
            test_agent_loop(backend.as_ref(), &engine, &inventory, &counter, 180_000, 2)
                .with_time_budget(LlmConfig::default().max_shard_seconds);
        loop_state.run("SYS", "MAP").await
    };

    assert!(result.is_ok(), "{result:?}");
    assert_eq!(backend.call_count(), 2);
}

#[tokio::test]
async fn reports_model_requests_tool_calls_and_finalization() {
    let (logs, _subscriber) = capture_debug_logs();
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("x.rs"), "fn x() {}\n").unwrap();

    let state = crate::tui::shared_state();
    let reporter = Reporter::new(state.clone());
    let backend = scripted(vec![
        with_usage(read_file_response("x.rs", "call-1"), 100, 20),
        with_usage(empty_submission_response("call-2"), 50, 7),
    ]);
    let engine = DefaultEngine::new(EngineConfig::default());
    let counter = FindingCounter::new();
    let inventory = ProjectInventory::build(tmp.path(), &EngineConfig::default()).unwrap();

    {
        let mut loop_state =
            test_agent_loop(backend.as_ref(), &engine, &inventory, &counter, 180_000, 2)
                .with_reporter(&reporter);
        loop_state.run("SYS", "MAP").await.unwrap();
    }

    let observed = state.lock();
    assert_eq!(observed.model_activity.requests, 2);
    assert_eq!(observed.model_activity.input_tokens, 150);
    assert_eq!(observed.model_activity.output_tokens, 27);
    assert_eq!(observed.shard.tool_calls, 2);
    assert_eq!(observed.shard.last_tool, crate::llm::tools::SUBMIT_FINDINGS);
    assert!(
        observed.shard.inspected_tokens > 0,
        "tool results must be accounted against the inspected budget"
    );
    assert!(observed.shard.finalizing);
    assert_eq!(observed.shard.finalization_attempt, 1);
    assert!(logs.text().contains("received response"));
}

#[tokio::test]
async fn reports_every_finalization_attempt() {
    let state = crate::tui::shared_state();
    let reporter = Reporter::new(state.clone());
    let backend = scripted(vec![
        tool_use_response("project_stats", "call-1"),
        end_turn_response(),
        empty_submission_response("call-2"),
    ]);
    let engine = DefaultEngine::new(EngineConfig::default());
    let tmp = tempfile::tempdir().unwrap();
    let counter = FindingCounter::new();
    let inventory = ProjectInventory::build(tmp.path(), &EngineConfig::default()).unwrap();

    {
        let mut loop_state =
            test_agent_loop(backend.as_ref(), &engine, &inventory, &counter, 180_000, 2)
                .with_reporter(&reporter);
        loop_state.run("SYS", "MAP").await.unwrap();
    }

    assert_eq!(state.lock().shard.finalization_attempt, 2);
}

#[tokio::test]
async fn a_rejected_finalization_restates_the_submission_contract() {
    let (backend, _findings) = run_scripted_with_limit(
        vec![
            tool_use_response("project_stats", "call-1"),
            end_turn_response(),
            empty_submission_response("call-2"),
        ],
        2,
    )
    .await;

    let corrections: Vec<String> = backend
        .last_messages()
        .iter()
        .flat_map(|message| message.content.clone())
        .filter_map(|block| block.as_text().map(String::from))
        .filter(|text| text.contains("previous final response"))
        .collect();

    assert_eq!(corrections.len(), 1, "{corrections:?}");
    let correction = &corrections[0];
    assert!(correction.contains("exactly once"), "{correction}");
    assert!(correction.contains("findings array"), "{correction}");
    assert!(correction.contains("may be empty"), "{correction}");
    assert!(correction.contains("Do not send prose"), "{correction}");
}

#[test]
fn rejects_model_responses_with_too_many_tool_calls() {
    let mut response = end_turn_response();
    response.stop_reason = StopReason::ToolUse;
    response.output.message.content = (0..=MAX_TOOL_CALLS_PER_RESPONSE)
        .map(|index| ContentBlock::ToolUse {
            tool_use: ToolUseBlock {
                tool_use_id: format!("call-{index}"),
                name: crate::llm::tools::PROJECT_STATS.to_string(),
                input: json!({}),
            },
        })
        .collect();

    let error = bounded_tool_calls(&response).unwrap_err();

    assert!(matches!(error, LlmError::AgentProtocol(_)));
    assert!(error.to_string().contains(&format!(
        "more than {MAX_TOOL_CALLS_PER_RESPONSE} tool calls"
    )));
}

#[test]
fn estimated_tokens_scales_with_result_length() {
    assert_eq!(estimated_tokens(""), 0);
    assert_eq!(estimated_tokens("abc"), 0);
    assert_eq!(estimated_tokens("abcd"), 1);
    assert_eq!(
        estimated_tokens(&"x".repeat(4 * ESTIMATED_CHARS_PER_TOKEN)),
        4
    );
}

const BOUNDED_CONTEXT_TOKENS: u32 = 4_000;
const OVERSIZED_FILE_LINES: usize = 80_000;

fn maximum_submission_response(tool_use_id: &str, file: &str) -> LlmResponse {
    submission_response(
        tool_use_id,
        file,
        crate::llm::tools::MAX_FINDINGS_PER_SUBMISSION,
    )
}

fn submission_response(tool_use_id: &str, file: &str, count: usize) -> LlmResponse {
    let findings: Vec<serde_json::Value> = (0..count)
        .map(|index| {
            json!({
                "category": "bug",
                "severity": "high",
                "title": format!("issue {tool_use_id} {index}"),
                "description": "d",
                "file": file,
                "confidence": "high"
            })
        })
        .collect();
    let mut response = tool_use_response(crate::llm::tools::SUBMIT_FINDINGS, tool_use_id);
    if let ContentBlock::ToolUse { tool_use } = &mut response.output.message.content[0] {
        tool_use.input = json!({ "findings": findings });
    }
    response
}

fn tool_result_errors(messages: &[Message]) -> Vec<String> {
    messages
        .iter()
        .flat_map(|message| &message.content)
        .filter_map(|block| match block {
            ContentBlock::ToolResult { tool_result }
                if tool_result.status == Some(ToolResultStatus::Error) =>
            {
                Some(tool_result.content.clone())
            }
            _ => None,
        })
        .collect()
}

fn tool_result_contents(messages: &[Message]) -> Vec<String> {
    messages
        .iter()
        .flat_map(|message| &message.content)
        .filter_map(|block| match block {
            ContentBlock::ToolResult { tool_result } => Some(tool_result.content.clone()),
            _ => None,
        })
        .collect()
}

fn request_bytes(messages: &[Message]) -> usize {
    messages
        .iter()
        .flat_map(|message| &message.content)
        .map(|block| match block {
            ContentBlock::Text { text } => text.len(),
            ContentBlock::ToolResult { tool_result } => tool_result.content.len(),
            ContentBlock::ToolUse { tool_use } => tool_use.input.to_string().len(),
        })
        .sum()
}

fn ledger_findings(
    counter: &FindingCounter,
    count: usize,
    description_bytes: usize,
) -> Vec<Finding> {
    (0..count)
        .map(|_| {
            Finding::new_static(
                counter,
                crate::config::schema::AnalysisCategory::Bug,
                crate::config::schema::Severity::High,
                "t".into(),
                "d".repeat(description_bytes),
                "src/a.rs".into(),
            )
        })
        .collect()
}

#[tokio::test]
async fn accepts_one_exploration_submission_and_refuses_the_repeats() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("x.rs"), "fn x() {}\n").unwrap();
    let backend = scripted(vec![
        maximum_submission_response("call-1", "x.rs"),
        maximum_submission_response("call-2", "x.rs"),
        maximum_submission_response("call-3", "x.rs"),
        end_turn_response(),
        empty_submission_response("call-4"),
    ]);
    let engine = DefaultEngine::new(EngineConfig::default());
    let counter = FindingCounter::new();
    let inventory = ProjectInventory::build(tmp.path(), &EngineConfig::default()).unwrap();

    let findings = {
        let mut loop_state =
            test_agent_loop(backend.as_ref(), &engine, &inventory, &counter, 180_000, 10);
        loop_state.run("SYS", "MAP").await.unwrap()
    };

    assert_eq!(backend.call_count(), 5);
    assert_eq!(
        findings.len(),
        crate::llm::tools::MAX_FINDINGS_PER_SUBMISSION,
        "only the first exploration submission may be recorded"
    );
    let refusals = tool_result_errors(&backend.last_messages());
    assert_eq!(refusals.len(), 2, "{refusals:?}");
    assert!(
        refusals
            .iter()
            .all(|refusal| refusal.contains("already submitted") && refusal.contains("final turn")),
        "a refusal must tell the model the final turn accepts the findings: {refusals:?}"
    );
}

#[tokio::test]
async fn a_refused_exploration_submission_is_recovered_in_the_final_turn() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("x.rs"), "fn x() {}\n").unwrap();
    let backend = scripted(vec![
        submission_response("call-1", "x.rs", 2),
        submission_response("call-2", "x.rs", 3),
        end_turn_response(),
        submission_response("call-3", "x.rs", 3),
    ]);
    let engine = DefaultEngine::new(EngineConfig::default());
    let counter = FindingCounter::new();
    let inventory = ProjectInventory::build(tmp.path(), &EngineConfig::default()).unwrap();

    let findings = {
        let mut loop_state =
            test_agent_loop(backend.as_ref(), &engine, &inventory, &counter, 180_000, 10);
        loop_state.run("SYS", "MAP").await.unwrap()
    };

    assert_eq!(backend.call_count(), 4);
    assert_eq!(
        findings.len(),
        5,
        "the refused findings must be recoverable in the final submission"
    );
}

#[tokio::test]
async fn finalization_may_still_submit_after_an_exploration_submission() {
    let (backend, findings) = run_scripted_with_limit(
        vec![
            empty_submission_response("call-1"),
            tool_use_response("project_stats", "call-2"),
            empty_submission_response("call-3"),
        ],
        3,
    )
    .await;

    assert_eq!(backend.call_count(), 3);
    assert!(findings.is_empty());
    assert!(
        tool_result_errors(&backend.last_messages()).is_empty(),
        "the finalization submission must not be refused"
    );
}

#[tokio::test]
async fn bounds_the_next_request_after_an_oversized_tool_result() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("big.rs"),
        "filler line\n".repeat(OVERSIZED_FILE_LINES),
    )
    .unwrap();
    let backend = scripted(vec![
        read_file_response("big.rs", "call-1"),
        empty_submission_response("call-2"),
    ]);
    let engine = DefaultEngine::new(EngineConfig::default());
    let counter = FindingCounter::new();
    let inventory = ProjectInventory::build(tmp.path(), &EngineConfig::default()).unwrap();

    {
        let mut loop_state = test_agent_loop(
            backend.as_ref(),
            &engine,
            &inventory,
            &counter,
            BOUNDED_CONTEXT_TOKENS,
            2,
        );
        loop_state.run("SYS", "MAP").await.unwrap();
    }

    let window_bytes = BOUNDED_CONTEXT_TOKENS as usize * ESTIMATED_CHARS_PER_TOKEN;
    let finalization_request = backend.last_messages();
    assert_eq!(
        backend.calls.lock().len(),
        2,
        "the loop must reach the finalization request"
    );
    let sent = request_bytes(&finalization_request);
    assert!(
        sent <= window_bytes,
        "sent {sent} bytes for a {window_bytes} byte window"
    );
    let results = tool_result_contents(&finalization_request);
    assert_eq!(results.len(), 1, "{results:?}");
    assert!(
        results[0].len() < OVERSIZED_FILE_LINES,
        "the oversized tool result was not truncated: {} bytes",
        results[0].len()
    );
    assert!(results[0].contains("truncated"), "{}", results[0]);
}

#[test]
fn the_ledger_accepts_a_single_exploration_submission() {
    let mut ledger = FindingLedger::default();

    assert!(ledger.refusal(SubmissionPhase::Exploration).is_none());
    ledger.record_submission();

    assert_eq!(
        ledger.refusal(SubmissionPhase::Exploration),
        Some(SUBMISSION_ALREADY_ACCEPTED)
    );
    assert!(
        ledger.refusal(SubmissionPhase::Finalization).is_none(),
        "finalization must still be able to submit"
    );
}

#[test]
fn the_ledger_caps_the_cumulative_finding_count() {
    let counter = FindingCounter::new();
    let mut ledger = FindingLedger::default();

    let first = ledger.admit(ledger_findings(&counter, MAX_FINDINGS_PER_RUN, 8));
    let second = ledger.admit(ledger_findings(&counter, 10, 8));

    assert_eq!((first.recorded, first.dropped), (MAX_FINDINGS_PER_RUN, 0));
    assert_eq!((second.recorded, second.dropped), (0, 10));
    assert_eq!(ledger.take().len(), MAX_FINDINGS_PER_RUN);
}

#[test]
fn the_ledger_rejects_a_whole_submission_that_exceeds_the_byte_budget() {
    let counter = FindingCounter::new();
    let mut ledger = FindingLedger::default();
    let quarter_budget = MAX_FINDING_BYTES_PER_RUN / 4 + 1;

    let rejected = ledger.admit(ledger_findings(&counter, 5, quarter_budget));
    let accepted = ledger.admit(ledger_findings(&counter, 1, quarter_budget));

    assert_eq!((rejected.recorded, rejected.dropped), (0, 5));
    assert_eq!((accepted.recorded, accepted.dropped), (1, 0));
    assert_eq!(ledger.take().len(), 1);
}

#[test]
fn rejected_submissions_explain_that_nothing_was_recorded() {
    let accepted = LedgerAdmission::default();
    let rejected = LedgerAdmission {
        recorded: 0,
        dropped: 3,
    };

    assert_eq!(accepted.rejection(), None);
    let report = rejected.rejection().unwrap();
    assert!(report.contains("Rejected all 3 findings"), "{report}");
    assert!(
        report.contains("none from this call were recorded"),
        "{report}"
    );
}

#[tokio::test]
async fn cancellation_and_timeout_are_both_enforced_when_configured_together() {
    let engine = DefaultEngine::new(EngineConfig::default());
    let directory = tempfile::tempdir().unwrap();
    let inventory = ProjectInventory::build(directory.path(), &EngineConfig::default()).unwrap();
    let counter = FindingCounter::new();
    let messages = [Message::user_text("MAP")];
    let tools = build_tool_config();

    let cancelled = CancelToken::default();
    cancelled.cancel();
    let cancelled_loop =
        test_agent_loop(&PendingBackend, &engine, &inventory, &counter, 180_000, 10)
            .with_cancel(&cancelled);
    let generous_budget = TimeBudget {
        limit: Some(Duration::from_secs(60)),
        started: Instant::now(),
    };
    assert!(matches!(
        cancelled_loop
            .converse(&messages, "SYS", &tools, &generous_budget, 2)
            .await,
        Err(LlmError::Cancelled)
    ));

    let active = CancelToken::default();
    let timed_loop = test_agent_loop(&PendingBackend, &engine, &inventory, &counter, 180_000, 10)
        .with_cancel(&active);
    let expired_budget = TimeBudget {
        limit: Some(Duration::ZERO),
        started: Instant::now(),
    };
    let error = timed_loop
        .converse(&messages, "SYS", &tools, &expired_budget, 4)
        .await
        .expect_err("the timeout must interrupt a pending request");
    assert!(error.to_string().contains("after 4 iterations"), "{error}");
}

#[tokio::test]
async fn max_token_responses_and_unknown_tools_are_handled_without_panics() {
    let engine = DefaultEngine::new(EngineConfig::default());
    let directory = tempfile::tempdir().unwrap();
    let inventory = ProjectInventory::build(directory.path(), &EngineConfig::default()).unwrap();
    let counter = FindingCounter::new();
    let backend = scripted(Vec::new());
    let mut loop_state =
        test_agent_loop(backend.as_ref(), &engine, &inventory, &counter, 180_000, 10);

    let mut max_tokens = end_turn_response();
    max_tokens.stop_reason = StopReason::MaxTokens;
    let mut messages = Vec::new();
    let budget = TimeBudget {
        limit: None,
        started: Instant::now(),
    };
    loop_state
        .handle_response_actions(&max_tokens, &mut messages, &budget, 0)
        .await
        .unwrap();
    assert!(messages.is_empty());

    let unknown = ToolUseBlock {
        tool_use_id: "unknown-1".into(),
        name: "unknown_tool".into(),
        input: json!({}),
    };
    let result = loop_state
        .dispatch_single_tool(&unknown, SubmissionPhase::Exploration, &budget, 0)
        .await
        .unwrap();
    assert_eq!(result.status, Some(ToolResultStatus::Error));
}

#[tokio::test]
async fn reporter_counts_findings_admitted_by_the_agent() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("x.rs"), "fn x() {}\n").unwrap();
    let state = crate::tui::shared_state();
    let reporter = Reporter::new(state.clone());
    let backend = scripted(vec![
        submission_response("submit-1", "x.rs", 1),
        end_turn_response(),
    ]);
    let engine = DefaultEngine::new(EngineConfig::default());
    let inventory = ProjectInventory::build(directory.path(), &EngineConfig::default()).unwrap();
    let counter = FindingCounter::new();

    let findings = {
        let mut loop_state =
            test_agent_loop(backend.as_ref(), &engine, &inventory, &counter, 180_000, 10)
                .with_reporter(&reporter);
        loop_state.run("SYS", "MAP").await.unwrap()
    };

    assert_eq!(findings.len(), 1);
    assert_eq!(state.lock().findings, 1);
}
#[tokio::test]
async fn tool_worker_panics_become_protocol_errors() {
    let worker = tokio::spawn(async { panic!("worker failed") });
    let join_error = worker.await.unwrap_err();

    let error = tool_worker_failure(join_error);

    assert!(matches!(
        error,
        LlmError::AgentProtocol(message) if message.contains("tool worker failed")
    ));
}

#[test]
fn unknown_tool_activity_uses_the_querying_phase() {
    let state = crate::tui::shared_state();
    let reporter = Reporter::new(state.clone());
    let call = ToolUseBlock {
        tool_use_id: "unknown-activity".into(),
        name: "unknown_tool".into(),
        input: json!({}),
    };

    report_activity(&reporter, &call);

    let observed = state.lock();
    assert_eq!(observed.phase, Phase::Querying);
    assert!(observed.detail.is_empty());
}

const RESULT_BUDGET_CALLS: usize = 12;

fn read_file_calls(paths: &[String]) -> LlmResponse {
    LlmResponse {
        output: LlmOutput {
            message: Message {
                role: Role::Assistant,
                content: paths
                    .iter()
                    .enumerate()
                    .map(|(index, path)| ContentBlock::ToolUse {
                        tool_use: ToolUseBlock {
                            tool_use_id: format!("call-{index}"),
                            name: crate::llm::tools::READ_FILE.into(),
                            input: json!({ "path": path }),
                        },
                    })
                    .collect(),
            },
        },
        stop_reason: StopReason::ToolUse,
        usage: TokenUsage::default(),
    }
}

fn repeated_tool_calls(call: &ContentBlock, count: usize) -> LlmResponse {
    LlmResponse {
        output: LlmOutput {
            message: Message {
                role: Role::Assistant,
                content: vec![call.clone(); count],
            },
        },
        stop_reason: StopReason::ToolUse,
        usage: TokenUsage::default(),
    }
}

fn successful_tool_results(messages: &[Message]) -> (usize, usize) {
    messages
        .iter()
        .flat_map(|message| &message.content)
        .filter_map(|block| match block {
            ContentBlock::ToolResult { tool_result }
                if tool_result.status == Some(ToolResultStatus::Success) =>
            {
                Some(tool_result.content.len())
            }
            _ => None,
        })
        .fold((0, 0), |(count, bytes), length| (count + 1, bytes + length))
}

fn unbounded_budget() -> TimeBudget {
    TimeBudget {
        limit: None,
        started: Instant::now(),
    }
}

#[tokio::test]
async fn a_response_past_the_tool_call_limit_executes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("x.rs"), "fn x() {}\n").unwrap();
    let backend = scripted(Vec::new());
    let engine = DefaultEngine::new(EngineConfig::default());
    let counter = FindingCounter::new();
    let inventory = ProjectInventory::build(tmp.path(), &EngineConfig::default()).unwrap();
    let mut loop_state =
        test_agent_loop(backend.as_ref(), &engine, &inventory, &counter, 180_000, 10);
    let submission = submission_response("call-0", "x.rs", 1)
        .output
        .message
        .content[0]
        .clone();
    let response = repeated_tool_calls(&submission, MAX_TOOL_CALLS_PER_RESPONSE + 1);
    let mut messages = Vec::new();

    let error = loop_state
        .handle_response_actions(&response, &mut messages, &unbounded_budget(), 0)
        .await
        .expect_err("one call past the limit must reject the whole response");

    assert!(error.to_string().contains(&format!(
        "more than {MAX_TOOL_CALLS_PER_RESPONSE} tool calls"
    )));
    assert!(
        messages.is_empty(),
        "a rejected response produces no results"
    );
    assert!(
        loop_state.ledger.recorded.is_empty(),
        "a rejected response must not execute a single call"
    );
}

#[test]
fn the_response_result_budget_admits_exactly_its_byte_limit() {
    let mut budget = ToolResultBudget::default();

    let admitted = budget.admit(ToolResultBlock::success(
        "call-1",
        &"x".repeat(MAX_TOOL_RESULT_BYTES_PER_RESPONSE),
    ));

    assert_eq!(admitted.status, Some(ToolResultStatus::Success));
    assert_eq!(admitted.content.len(), MAX_TOOL_RESULT_BYTES_PER_RESPONSE);
    assert!(budget.is_exhausted());
}

#[test]
fn the_response_result_budget_replaces_a_result_that_would_overflow_it() {
    let mut budget = ToolResultBudget::default();
    let filler = "x".repeat(MAX_TOOL_RESULT_BYTES_PER_RESPONSE - 1);

    let admitted = budget.admit(ToolResultBlock::success("call-1", &filler));

    assert_eq!(admitted.content.len(), filler.len());
    assert!(!budget.is_exhausted());

    let refused = budget.admit(ToolResultBlock::success("call-2", "xx"));

    assert_eq!(refused.status, Some(ToolResultStatus::Error));
    assert_eq!(refused.tool_use_id, "call-2");
    assert!(
        refused
            .content
            .contains(&MAX_TOOL_RESULT_BYTES_PER_RESPONSE.to_string()),
        "{}",
        refused.content
    );
    assert!(budget.is_exhausted());
}

#[tokio::test]
async fn an_exhausted_result_budget_stops_executing_further_calls() {
    let (logs, _subscriber) = capture_debug_logs();
    let tmp = tempfile::tempdir().unwrap();
    let readable_bytes = EngineConfig::default().max_file_size_bytes as usize;
    let paths: Vec<String> = (0..RESULT_BUDGET_CALLS)
        .map(|index| format!("big-{index}.rs"))
        .collect();
    for path in &paths {
        std::fs::write(tmp.path().join(path), "x".repeat(readable_bytes)).unwrap();
    }
    let backend = scripted(Vec::new());
    let engine = DefaultEngine::new(EngineConfig::default());
    let counter = FindingCounter::new();
    let inventory = ProjectInventory::build(tmp.path(), &EngineConfig::default()).unwrap();
    let tracker = Arc::new(CoverageTracker::new());
    let mut loop_state = test_agent_loop_with_coverage(
        backend.as_ref(),
        &engine,
        &inventory,
        &counter,
        180_000,
        10,
        Some(Arc::clone(&tracker)),
    );
    let mut messages = Vec::new();

    loop_state
        .handle_response_actions(
            &read_file_calls(&paths),
            &mut messages,
            &unbounded_budget(),
            0,
        )
        .await
        .unwrap();

    let (admitted, admitted_bytes) = successful_tool_results(&messages);
    let refused = tool_result_errors(&messages);
    let executed = tracker.read_paths().len();

    assert_eq!(
        admitted + refused.len(),
        RESULT_BUDGET_CALLS,
        "every call owes the model exactly one result"
    );
    assert!(
        admitted_bytes <= MAX_TOOL_RESULT_BYTES_PER_RESPONSE,
        "admitted {admitted_bytes} bytes of tool results"
    );
    assert!(
        refused.len() >= 2,
        "the budget must refuse the calls that follow it"
    );
    assert!(
        executed <= admitted + 1,
        "executed {executed} calls for {admitted} admitted results"
    );
    assert!(
        executed < RESULT_BUDGET_CALLS,
        "an exhausted budget still executed every call"
    );
    assert!(
        refused
            .iter()
            .all(|text| text.contains(&MAX_TOOL_RESULT_BYTES_PER_RESPONSE.to_string())),
        "{refused:?}"
    );
    assert!(
        logs.text()
            .contains("skipping a tool call: the per-response result budget is exhausted")
    );
}
