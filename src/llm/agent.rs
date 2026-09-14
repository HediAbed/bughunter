use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use crate::cancel::CancelToken;
use crate::errors::LlmError;
use crate::report::Finding;
use crate::shared::ESTIMATED_CHARS_PER_TOKEN;
use crate::tui::{Phase, Reporter};

use super::client::LlmBackend;
use super::context::ContextManager;
use super::tool_exec::{ToolExecutor, ToolOutcome};
use super::tools::{self, build_finalization_tool_config, build_tool_config};
use super::types::{
    ContentBlock, LlmResponse, Message, StopReason, ToolResultBlock, ToolResultStatus, ToolUseBlock,
};

pub struct AgentLoop<'a> {
    backend: &'a dyn LlmBackend,
    tools: Arc<ToolExecutor>,
    context_manager: ContextManager,
    ledger: FindingLedger,
    max_iterations: u32,
    reporter: Option<&'a Reporter>,
    cancel: Option<&'a CancelToken>,
    time_budget_seconds: Option<u64>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IterationOutcome {
    Continue,
    Complete,
    Finalize,
}
#[derive(Default)]
struct ExplorationProgress {
    tool_calls_made: u32,
    nudged: bool,
}

impl<'a> AgentLoop<'a> {
    pub fn new(
        backend: &'a dyn LlmBackend,
        tools: Arc<ToolExecutor>,
        max_context_tokens: u32,
        max_iterations: u32,
    ) -> Self {
        Self {
            backend,
            tools,
            context_manager: ContextManager::new(max_context_tokens),
            ledger: FindingLedger::default(),
            max_iterations,
            reporter: None,
            cancel: None,
            time_budget_seconds: None,
        }
    }

    pub fn with_reporter(mut self, reporter: &'a Reporter) -> Self {
        self.reporter = Some(reporter);
        self
    }

    pub fn with_cancel(mut self, cancel: &'a CancelToken) -> Self {
        self.cancel = Some(cancel);
        self
    }

    pub fn with_time_budget(mut self, seconds: u64) -> Self {
        self.time_budget_seconds = Some(seconds);
        self
    }

    pub async fn run(
        &mut self,
        system_prompt: &str,
        repo_map: &str,
    ) -> Result<Vec<Finding>, LlmError> {
        let analysis_tools = build_tool_config();
        let submission_tool = build_finalization_tool_config();
        let mut messages = vec![Message::user_text(repo_map)];
        let mut progress = ExplorationProgress::default();
        let budget = TimeBudget::start(self.time_budget_seconds);

        for iteration in 0..self.max_iterations {
            self.ensure_not_cancelled()?;
            budget.ensure_remaining(iteration)?;

            let final_iteration = iteration + 1 == self.max_iterations;
            debug!(iteration, final_iteration, "agent loop iteration");

            if final_iteration {
                return self
                    .finalize_analysis(
                        &mut messages,
                        system_prompt,
                        &submission_tool,
                        iteration,
                        &budget,
                    )
                    .await;
            }
            let outcome = self
                .run_exploration_iteration(
                    &mut messages,
                    system_prompt,
                    &analysis_tools,
                    iteration,
                    &mut progress,
                    &budget,
                )
                .await?;
            if outcome == IterationOutcome::Finalize {
                return self
                    .finalize_analysis(
                        &mut messages,
                        system_prompt,
                        &submission_tool,
                        iteration + 1,
                        &budget,
                    )
                    .await;
            }
            if outcome == IterationOutcome::Complete {
                self.ensure_not_cancelled()?;
                return Ok(self.complete_analysis(iteration + 1));
            }
        }

        Err(LlmError::AgentProtocol(
            "agent iteration limit is zero; no analysis was performed".into(),
        ))
    }

    async fn run_exploration_iteration(
        &mut self,
        messages: &mut Vec<Message>,
        system_prompt: &str,
        tool_config: &super::types::ToolConfig,
        iteration: u32,
        progress: &mut ExplorationProgress,
        budget: &TimeBudget,
    ) -> Result<IterationOutcome, LlmError> {
        if let Some(reporter) = self.reporter {
            reporter.phase(Phase::Querying, "");
        }
        let response = self
            .send_request(messages, system_prompt, tool_config, budget, iteration)
            .await?;
        messages.push(response.output.message.clone());

        if response.stop_reason == StopReason::EndTurn {
            if self.ledger.has_accepted_submission() && !self.ledger.has_refused_submission() {
                return Ok(IterationOutcome::Complete);
            }
            if progress.tool_calls_made > 0 {
                return Ok(IterationOutcome::Finalize);
            }
            if progress.nudged {
                return Err(LlmError::AgentProtocol(
                    "agent ended twice without inspecting source code".into(),
                ));
            }
            if iteration + 2 >= self.max_iterations {
                return Err(LlmError::AgentProtocol(
                    "agent ended before inspecting source code and no exploration turn remains"
                        .into(),
                ));
            }
            warn!("agent ended turn with zero tool calls; injecting exploration nudge");
            messages.push(Message::user_text(EXPLORATION_NUDGE));
            progress.nudged = true;
            return Ok(IterationOutcome::Continue);
        }

        progress.tool_calls_made += count_tool_uses(&response);
        self.handle_response_actions(&response, messages, budget, iteration)
            .await?;
        if self.context_manager.should_compact(messages) {
            info!("compacting context to free token budget");
            self.context_manager.compact_messages(messages);
        }
        Ok(IterationOutcome::Continue)
    }

    async fn finalize_analysis(
        &mut self,
        messages: &mut Vec<Message>,
        system_prompt: &str,
        tool_config: &super::types::ToolConfig,
        requests_before_finalization: u32,
        budget: &TimeBudget,
    ) -> Result<Vec<Finding>, LlmError> {
        info!("reserving final agent turn for finding submission");
        messages.push(Message::user_text(FINALIZATION_NUDGE));

        for attempt in 0..MAX_FINALIZATION_ATTEMPTS {
            self.ensure_not_cancelled()?;
            if let Some(reporter) = self.reporter {
                reporter.phase(Phase::Submitting, "");
                reporter.finalization_started(attempt + 1);
            }
            let response = self
                .send_request(
                    messages,
                    system_prompt,
                    tool_config,
                    budget,
                    requests_before_finalization + attempt,
                )
                .await?;
            messages.push(response.output.message.clone());

            if self
                .handle_finalization_response(
                    &response,
                    messages,
                    budget,
                    requests_before_finalization + attempt,
                )
                .await?
            {
                self.ensure_not_cancelled()?;
                return Ok(self.complete_analysis(requests_before_finalization + attempt + 1));
            }
            if attempt + 1 < MAX_FINALIZATION_ATTEMPTS {
                warn!(
                    attempt = attempt + 1,
                    max = MAX_FINALIZATION_ATTEMPTS,
                    "finalization response rejected; retrying"
                );
                messages.push(Message::user_text(FINALIZATION_RETRY_NUDGE));
            }
        }

        Err(LlmError::AgentProtocol(format!(
            "agent did not call submit_findings successfully after {MAX_FINALIZATION_ATTEMPTS} finalization attempts"
        )))
    }

    async fn handle_finalization_response(
        &mut self,
        response: &LlmResponse,
        messages: &mut Vec<Message>,
        budget: &TimeBudget,
        iteration: u32,
    ) -> Result<bool, LlmError> {
        let tool_calls = bounded_tool_calls(response)?;
        if tool_calls.is_empty() {
            return Ok(false);
        }

        if tool_calls.len() != 1 {
            let results = tool_calls
                .iter()
                .map(|call| {
                    ToolResultBlock::error(
                        &call.tool_use_id,
                        "finalization requires exactly one submit_findings call",
                    )
                })
                .collect();
            messages.push(Message::user_tool_results(results));
            return Ok(false);
        }

        let call = &tool_calls[0];
        let result = if call.name == tools::SUBMIT_FINDINGS {
            self.dispatch_single_tool(call, SubmissionPhase::Finalization, budget, iteration)
                .await?
        } else {
            ToolResultBlock::error(
                &call.tool_use_id,
                "finalization accepts only submit_findings",
            )
        };
        let submitted = result.status == Some(ToolResultStatus::Success);
        messages.push(Message::user_tool_results(vec![result]));
        Ok(submitted)
    }

    fn complete_analysis(&mut self, iterations: u32) -> Vec<Finding> {
        let findings = self.ledger.take();
        info!(
            findings = findings.len(),
            iterations, "agent completed analysis"
        );
        findings
    }

    async fn converse(
        &self,
        messages: &[Message],
        system_prompt: &str,
        tool_config: &super::types::ToolConfig,
        budget: &TimeBudget,
        iteration: u32,
    ) -> Result<LlmResponse, LlmError> {
        let request = self.backend.converse(messages, system_prompt, tool_config);
        self.guarded(request, budget, iteration).await
    }

    async fn guarded<T>(
        &self,
        work: impl Future<Output = Result<T, LlmError>>,
        budget: &TimeBudget,
        iteration: u32,
    ) -> Result<T, LlmError> {
        let result = match (self.cancel, budget.remaining()) {
            (Some(cancel), Some(remaining)) => {
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => Err(LlmError::Cancelled),
                    () = tokio::time::sleep(remaining) => budget.exceeded(iteration),
                    result = work => result,
                }
            }
            (Some(cancel), None) => {
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => Err(LlmError::Cancelled),
                    result = work => result,
                }
            }
            (None, Some(remaining)) => {
                tokio::select! {
                    biased;
                    () = tokio::time::sleep(remaining) => budget.exceeded(iteration),
                    result = work => result,
                }
            }
            (None, None) => work.await,
        };
        self.ensure_not_cancelled()?;
        result
    }

    async fn send_request(
        &mut self,
        messages: &mut [Message],
        system_prompt: &str,
        tool_config: &super::types::ToolConfig,
        budget: &TimeBudget,
        iteration: u32,
    ) -> Result<LlmResponse, LlmError> {
        self.context_manager
            .bound_complete_request(messages, system_prompt, tool_config)?;
        if let Some(reporter) = self.reporter {
            reporter.model_request_started();
        }
        let response = self
            .converse(messages, system_prompt, tool_config, budget, iteration)
            .await?;
        self.context_manager
            .update_usage(response.usage.input_tokens, response.usage.output_tokens);
        if let Some(reporter) = self.reporter {
            reporter.model_response(
                u64::from(response.usage.input_tokens),
                u64::from(response.usage.output_tokens),
            );
        }

        debug!(
            stop_reason = ?response.stop_reason,
            input_tokens = response.usage.input_tokens,
            output_tokens = response.usage.output_tokens,
            "received response"
        );

        Ok(response)
    }

    async fn handle_response_actions(
        &mut self,
        response: &LlmResponse,
        messages: &mut Vec<Message>,
        budget: &TimeBudget,
        iteration: u32,
    ) -> Result<(), LlmError> {
        if response.stop_reason == StopReason::ToolUse {
            let tool_calls = bounded_tool_calls(response)?;

            let results = self
                .dispatch_tool_calls(&tool_calls, budget, iteration)
                .await?;
            messages.push(Message::user_tool_results(results));
        }

        if response.stop_reason == StopReason::MaxTokens {
            warn!("response hit max_tokens, continuing");
        }
        Ok(())
    }

    async fn dispatch_tool_calls(
        &mut self,
        tool_calls: &[ToolUseBlock],
        budget: &TimeBudget,
        iteration: u32,
    ) -> Result<Vec<ToolResultBlock>, LlmError> {
        let mut results = Vec::with_capacity(tool_calls.len());
        let mut content_budget = ToolResultBudget::default();
        for call in tool_calls {
            if content_budget.is_exhausted() {
                debug!(
                    tool = &call.name,
                    "skipping a tool call: the per-response result budget is exhausted"
                );
                results.push(ToolResultBlock::error(
                    &call.tool_use_id,
                    &ToolResultBudget::exhausted_message(),
                ));
                continue;
            }
            let result = self
                .dispatch_single_tool(call, SubmissionPhase::Exploration, budget, iteration)
                .await?;
            results.push(content_budget.admit(result));
        }
        Ok(results)
    }

    async fn dispatch_single_tool(
        &mut self,
        call: &ToolUseBlock,
        phase: SubmissionPhase,
        budget: &TimeBudget,
        iteration: u32,
    ) -> Result<ToolResultBlock, LlmError> {
        self.ensure_not_cancelled()?;
        debug!(tool = &call.name, "dispatching tool call");
        if let Some(reporter) = self.reporter {
            report_activity(reporter, call);
        }

        let result = self.execute_tool(call, phase, budget, iteration).await?;
        if let Some(reporter) = self.reporter {
            reporter.tool_executed(&call.name, estimated_tokens(&result.content));
        }
        Ok(result)
    }

    async fn execute_tool(
        &mut self,
        call: &ToolUseBlock,
        phase: SubmissionPhase,
        budget: &TimeBudget,
        iteration: u32,
    ) -> Result<ToolResultBlock, LlmError> {
        let submission = call.name == tools::SUBMIT_FINDINGS;
        if submission && let Some(refusal) = self.ledger.refusal(phase) {
            warn!(refusal, "refusing a finding submission");
            self.ledger.record_refusal();
            return Ok(ToolResultBlock::error(&call.tool_use_id, refusal));
        }

        let executed = self.execute_off_thread(call, budget, iteration).await?;
        let outcome = match executed {
            Ok(outcome) => outcome,
            Err(err) => return Ok(ToolResultBlock::error(&call.tool_use_id, &err)),
        };
        let admission = self.ledger.admit(outcome.findings);
        if let Some(reason) = admission.rejection() {
            return Ok(ToolResultBlock::error(&call.tool_use_id, &reason));
        }
        if submission {
            self.ledger.record_submission();
        }
        if admission.recorded > 0
            && let Some(reporter) = self.reporter
        {
            reporter.add_findings(admission.recorded);
        }
        Ok(ToolResultBlock::success(&call.tool_use_id, &outcome.text))
    }

    async fn execute_off_thread(
        &self,
        call: &ToolUseBlock,
        budget: &TimeBudget,
        iteration: u32,
    ) -> Result<Result<ToolOutcome, String>, LlmError> {
        let tools = Arc::clone(&self.tools);
        let name = call.name.clone();
        let input = call.input.clone();
        let cancel = self.cancel.cloned();
        let mut worker = tokio::task::spawn_blocking(move || match cancel {
            Some(cancel) => tools.execute_with_cancel(&name, &input, &cancel),
            None => tools.execute(&name, &input),
        });
        let joined = self
            .guarded(
                async { (&mut worker).await.map_err(tool_worker_failure) },
                budget,
                iteration,
            )
            .await;
        if joined.is_err() {
            worker.abort();
        }
        joined
    }

    fn ensure_not_cancelled(&self) -> Result<(), LlmError> {
        match self.cancel {
            Some(cancel) if cancel.is_cancelled() => Err(LlmError::Cancelled),
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SubmissionPhase {
    Exploration,
    Finalization,
}

#[derive(Default)]
struct FindingLedger {
    recorded: Vec<Finding>,
    recorded_bytes: usize,
    accepted_submissions: u32,
    refused_submissions: u32,
}

#[derive(Default)]
struct LedgerAdmission {
    recorded: usize,
    dropped: usize,
}

impl FindingLedger {
    fn has_accepted_submission(&self) -> bool {
        self.accepted_submissions > 0
    }

    fn has_refused_submission(&self) -> bool {
        self.refused_submissions > 0
    }

    fn refusal(&self, phase: SubmissionPhase) -> Option<&'static str> {
        match phase {
            SubmissionPhase::Exploration if self.has_accepted_submission() => {
                Some(SUBMISSION_ALREADY_ACCEPTED)
            }
            _ => None,
        }
    }

    fn record_submission(&mut self) {
        self.accepted_submissions += 1;
    }

    fn record_refusal(&mut self) {
        self.refused_submissions += 1;
    }

    fn admit(&mut self, findings: Vec<Finding>) -> LedgerAdmission {
        let finding_count = findings.len();
        let required_bytes = findings.iter().try_fold(0usize, |total, finding| {
            total.checked_add(finding.retained_bytes())
        });
        if finding_count > self.remaining_findings()
            || required_bytes.is_none_or(|bytes| bytes > self.remaining_bytes())
        {
            warn!(
                rejected = finding_count,
                recorded = self.recorded.len(),
                bytes = self.recorded_bytes,
                "run-wide finding budget exhausted; rejecting the whole submission"
            );
            return LedgerAdmission {
                recorded: 0,
                dropped: finding_count,
            };
        }
        self.recorded_bytes += required_bytes.unwrap_or(0);
        self.recorded.extend(findings);
        LedgerAdmission {
            recorded: finding_count,
            dropped: 0,
        }
    }

    fn take(&mut self) -> Vec<Finding> {
        std::mem::take(self).recorded
    }

    fn remaining_findings(&self) -> usize {
        MAX_FINDINGS_PER_RUN.saturating_sub(self.recorded.len())
    }

    fn remaining_bytes(&self) -> usize {
        MAX_FINDING_BYTES_PER_RUN.saturating_sub(self.recorded_bytes)
    }
}

impl LedgerAdmission {
    fn rejection(&self) -> Option<String> {
        if self.dropped == 0 {
            return None;
        }
        Some(format!(
            "Rejected all {} findings: this submission would exceed the run-wide budget of \
             {MAX_FINDINGS_PER_RUN} findings and {MAX_FINDING_BYTES_PER_RUN} bytes. Submit fewer \
             or smaller findings; none from this call were recorded.",
            self.dropped
        ))
    }
}

struct ToolResultBudget {
    remaining: usize,
}

impl Default for ToolResultBudget {
    fn default() -> Self {
        Self {
            remaining: MAX_TOOL_RESULT_BYTES_PER_RESPONSE,
        }
    }
}

impl ToolResultBudget {
    fn is_exhausted(&self) -> bool {
        self.remaining == 0
    }

    fn admit(&mut self, result: ToolResultBlock) -> ToolResultBlock {
        match self.remaining.checked_sub(result.content.len()) {
            Some(remaining) => {
                self.remaining = remaining;
                result
            }
            None => {
                self.remaining = 0;
                warn!(
                    bytes = result.content.len(),
                    "dropping a tool result: the per-response result budget is exhausted"
                );
                ToolResultBlock::error(&result.tool_use_id, &Self::exhausted_message())
            }
        }
    }

    fn exhausted_message() -> String {
        format!(
            "the {MAX_TOOL_RESULT_BYTES_PER_RESPONSE} byte tool result budget for one response is \
             exhausted, so this call produced no result; end the turn and request fewer or smaller \
             tool results"
        )
    }
}

fn tool_use_blocks(response: &LlmResponse) -> impl Iterator<Item = &ToolUseBlock> {
    response
        .output
        .message
        .content
        .iter()
        .filter_map(ContentBlock::as_tool_use)
}

fn bounded_tool_calls(response: &LlmResponse) -> Result<Vec<ToolUseBlock>, LlmError> {
    if tool_use_blocks(response)
        .nth(MAX_TOOL_CALLS_PER_RESPONSE)
        .is_some()
    {
        return Err(LlmError::AgentProtocol(format!(
            "model returned more than {MAX_TOOL_CALLS_PER_RESPONSE} tool calls in one response"
        )));
    }
    Ok(tool_use_blocks(response).cloned().collect())
}

fn tool_worker_failure(error: tokio::task::JoinError) -> LlmError {
    LlmError::AgentProtocol(format!("tool worker failed: {error}"))
}

struct TimeBudget {
    limit: Option<Duration>,
    started: Instant,
}

impl TimeBudget {
    fn start(seconds: Option<u64>) -> Self {
        Self {
            limit: seconds.map(Duration::from_secs),
            started: Instant::now(),
        }
    }

    fn remaining(&self) -> Option<Duration> {
        self.limit
            .map(|limit| limit.saturating_sub(self.started.elapsed()))
    }

    fn ensure_remaining(&self, iteration: u32) -> Result<(), LlmError> {
        let Some(limit) = self.limit else {
            return Ok(());
        };
        if self.started.elapsed() < limit {
            return Ok(());
        }
        self.exceeded(iteration)
    }

    fn exceeded<T>(&self, iteration: u32) -> Result<T, LlmError> {
        let budget = self.limit.map_or(0, |limit| limit.as_secs());
        warn!(budget, iteration, "shard exceeded its wall-clock budget");
        Err(LlmError::AgentProtocol(format!(
            "shard exceeded the {budget}s time budget after {iteration} iterations"
        )))
    }
}

fn estimated_tokens(text: &str) -> u64 {
    (text.len() / ESTIMATED_CHARS_PER_TOKEN) as u64
}

const MAX_FINALIZATION_ATTEMPTS: u32 = 3;
const MAX_TOOL_CALLS_PER_RESPONSE: usize = 128;
const MAX_TOOL_RESULT_BYTES_PER_RESPONSE: usize = 8 * 1024 * 1024;
pub(crate) const MAX_FINDINGS_PER_RUN: usize = 2_000;
pub(crate) const MAX_FINDING_BYTES_PER_RUN: usize = 8 * 1024 * 1024;

const SUBMISSION_ALREADY_ACCEPTED: &str = "findings were already submitted in this run and \
submit_findings accepts one successful call during exploration, so this submission was not \
recorded. Keep the findings; you will be asked for every unsubmitted finding in the final turn, \
and that submission will be accepted.";

const EXPLORATION_NUDGE: &str = "You ended the turn without invoking any analysis tool, \
so no source code has been inspected and no finding can be trusted. You must call at \
least one tool before ending the turn. Start with project_stats or discover_files to \
locate source files, then read_file to inspect specific ones, and submit_findings if \
you discover issues. Do not emit <end_turn/> again until you have actually read source.";

const FINALIZATION_NUDGE: &str = "This is the final agent turn. Stop exploring and review \
the evidence already collected. You MUST call submit_findings now with every verified \
finding that has not already been submitted. Use an empty findings array when there are \
no unsubmitted verified issues. Do not repeat prior findings or call another tool.";

const FINALIZATION_RETRY_NUDGE: &str = "Your previous final response was rejected because \
it did not successfully call submit_findings. No more exploration is allowed. Call the \
submit_findings tool exactly once, in this turn, passing the findings array — that array \
may be empty when nothing remains to report. Do not send prose, do not explain yourself, \
do not call any other tool, and do not emit more than one submit_findings call.";

fn count_tool_uses(response: &LlmResponse) -> u32 {
    tool_use_blocks(response).count() as u32
}

fn report_activity(reporter: &Reporter, call: &ToolUseBlock) {
    let detail = |key: &str| {
        call.input
            .get(key)
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string()
    };
    let (phase, text) = match call.name.as_str() {
        tools::READ_FILE | tools::SEARCH_AST => (Phase::Reading, detail("path")),
        tools::SEARCH_TEXT => (Phase::Searching, detail("pattern")),
        tools::DISCOVER_FILES => (Phase::Discovering, String::new()),
        tools::PROJECT_STATS => (Phase::Discovering, "project stats".to_string()),
        tools::SUBMIT_FINDINGS => (Phase::Submitting, String::new()),
        _ => (Phase::Querying, String::new()),
    };
    reporter.phase(phase, text);
}

#[cfg(test)]
#[path = "agent_tests.rs"]
mod tests;
