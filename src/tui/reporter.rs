use std::sync::Arc;

use parking_lot::Mutex;

use super::state::{Phase, ScanState, ShardProgress};

const MAX_REPORTER_TEXT_BYTES: usize = 4 * 1024;

#[derive(Clone)]
pub struct Reporter {
    state: Arc<Mutex<ScanState>>,
}

impl Reporter {
    pub fn new(state: Arc<Mutex<ScanState>>) -> Self {
        Self { state }
    }

    pub fn set_model(&self, model: &str, context_window: u32) {
        let model = bounded_reporter_text(model);
        let mut s = self.state.lock();
        s.model = model;
        s.context_window = context_window;
    }

    pub fn set_total_shards(&self, total: usize) {
        self.state.lock().total_shards = total;
    }

    pub fn shard_started(&self, index: usize, files: usize, eligible_tokens: u64) {
        let mut s = self.state.lock();
        s.current_shard = index;
        s.shard = ShardProgress {
            files,
            eligible_tokens,
            ..ShardProgress::default()
        };
    }

    pub fn shard_completed(&self) {
        self.state.lock().completed_shards += 1;
    }

    pub fn model_request_started(&self) {
        self.state.lock().model_activity.requests += 1;
    }

    pub fn model_response(&self, input_tokens: u64, output_tokens: u64) {
        let mut s = self.state.lock();
        s.model_activity.input_tokens += input_tokens;
        s.model_activity.output_tokens += output_tokens;
    }

    pub fn tool_executed(&self, tool: &str, inspected_tokens: u64) {
        let tool = bounded_reporter_text(tool);
        let mut s = self.state.lock();
        s.shard.tool_calls += 1;
        s.shard.last_tool = tool;
        s.shard.inspected_tokens += inspected_tokens;
    }

    pub fn finalization_started(&self, attempt: u32) {
        let mut s = self.state.lock();
        s.shard.finalizing = true;
        s.shard.finalization_attempt = attempt;
    }

    pub fn phase(&self, phase: Phase, detail: impl AsRef<str>) {
        let detail = bounded_reporter_text(detail.as_ref());
        let mut state = self.state.lock();
        state.phase = phase;
        state.detail = detail;
    }

    pub fn add_findings(&self, delta: usize) {
        self.state.lock().findings += delta;
    }

    pub fn set_findings(&self, total: usize) {
        self.state.lock().findings = total;
    }
}

fn bounded_reporter_text(value: &str) -> String {
    crate::shared::sanitize_terminal_text_bounded(value, MAX_REPORTER_TEXT_BYTES)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{MAX_REPORTER_TEXT_BYTES, Reporter};
    use crate::shared::TERMINAL_TEXT_TRUNCATION_MARKER;
    use crate::tui::state::{Phase, shared_state};

    #[test]
    fn shard_started_records_index_files_and_budget() {
        let state = shared_state();
        Reporter::new(state.clone()).shard_started(3, 12, 40_000);
        let s = state.lock();
        assert_eq!(s.current_shard, 3);
        assert_eq!(s.shard.files, 12);
        assert_eq!(s.shard.eligible_tokens, 40_000);
    }

    #[test]
    fn shard_started_resets_the_previous_shard_activity() {
        let state = shared_state();
        let reporter = Reporter::new(state.clone());
        reporter.shard_started(1, 5, 1_000);
        reporter.tool_executed("read_file", 400);
        reporter.finalization_started(2);
        reporter.shard_started(2, 6, 2_000);
        let s = state.lock();
        assert_eq!(s.shard.inspected_tokens, 0);
        assert_eq!(s.shard.tool_calls, 0);
        assert_eq!(s.shard.last_tool, "");
        assert!(!s.shard.finalizing);
        assert_eq!(s.shard.finalization_attempt, 0);
        assert_eq!(s.shard.eligible_tokens, 2_000);
    }

    #[test]
    fn model_request_started_counts_requests() {
        let state = shared_state();
        let reporter = Reporter::new(state.clone());
        reporter.model_request_started();
        reporter.model_request_started();
        assert_eq!(state.lock().model_activity.requests, 2);
    }

    #[test]
    fn model_response_accumulates_token_usage() {
        let state = shared_state();
        let reporter = Reporter::new(state.clone());
        reporter.model_response(1_200, 340);
        reporter.model_response(800, 60);
        let s = state.lock();
        assert_eq!(s.model_activity.input_tokens, 2_000);
        assert_eq!(s.model_activity.output_tokens, 400);
    }

    #[test]
    fn model_response_survives_a_shard_boundary() {
        let state = shared_state();
        let reporter = Reporter::new(state.clone());
        reporter.model_response(1_000, 100);
        reporter.shard_started(2, 3, 500);
        let s = state.lock();
        assert_eq!(s.model_activity.input_tokens, 1_000);
        assert_eq!(s.model_activity.output_tokens, 100);
    }

    #[test]
    fn tool_executed_tracks_calls_name_and_inspected_tokens() {
        let state = shared_state();
        let reporter = Reporter::new(state.clone());
        reporter.shard_started(1, 4, 10_000);
        reporter.tool_executed("read_file", 1_500);
        reporter.tool_executed("search", 900);
        let s = state.lock();
        assert_eq!(s.shard.tool_calls, 2);
        assert_eq!(s.shard.last_tool, "search");
        assert_eq!(s.shard.inspected_tokens, 2_400);
    }

    #[test]
    fn tool_executed_advances_progress() {
        let state = shared_state();
        let reporter = Reporter::new(state.clone());
        reporter.set_total_shards(1);
        reporter.shard_started(1, 4, 10_000);
        reporter.phase(Phase::Reading, "");
        let before = state.lock().progress();
        reporter.tool_executed("read_file", 4_000);
        let after = state.lock().progress();
        assert!(after > before, "{after} must exceed {before}");
    }

    #[test]
    fn finalization_started_marks_the_attempt() {
        let state = shared_state();
        Reporter::new(state.clone()).finalization_started(3);
        let s = state.lock();
        assert!(s.shard.finalizing);
        assert_eq!(s.shard.finalization_attempt, 3);
    }

    #[test]
    fn finalization_started_advances_progress() {
        let state = shared_state();
        let reporter = Reporter::new(state.clone());
        reporter.set_total_shards(1);
        reporter.shard_started(1, 4, 10_000);
        reporter.phase(Phase::Submitting, "");
        let before = state.lock().progress();
        reporter.finalization_started(1);
        let after = state.lock().progress();
        assert!(after > before, "{after} must exceed {before}");
    }

    #[test]
    fn shard_completed_counts_finished_shards() {
        let state = shared_state();
        let reporter = Reporter::new(state.clone());
        reporter.shard_completed();
        reporter.shard_completed();
        assert_eq!(state.lock().completed_shards, 2);
    }

    #[test]
    fn phase_sets_label_and_detail() {
        let state = shared_state();
        Reporter::new(state.clone()).phase(Phase::Reading, "src/main.rs");
        let s = state.lock();
        assert_eq!(s.phase, Phase::Reading);
        assert_eq!(s.detail, "src/main.rs");
    }

    #[test]
    fn display_text_is_sanitized_before_entering_tui_state() {
        let state = shared_state();
        let reporter = Reporter::new(state.clone());
        reporter.set_model("model\u{1b}[2J", 1000);
        reporter.shard_started(1, 1, 1);
        reporter.tool_executed("read\nfile", 0);
        reporter.phase(Phase::Reading, "a\u{202e}b");

        let state = state.lock();
        assert_eq!(state.model, "model\\u{1b}[2J");
        assert_eq!(state.shard.last_tool, "read\\u{a}file");
        assert_eq!(state.detail, "a\\u{202e}b");
    }

    #[test]
    fn display_text_that_ends_on_the_cap_is_kept_verbatim() {
        let exact = "m".repeat(MAX_REPORTER_TEXT_BYTES);
        let state = shared_state();
        let reporter = Reporter::new(state.clone());

        reporter.set_model(&exact, 1);
        reporter.shard_started(1, 1, 1);
        reporter.tool_executed(&exact, 0);
        reporter.phase(Phase::Reading, &exact);

        let state = state.lock();
        assert_eq!(state.model, exact);
        assert_eq!(state.shard.last_tool, exact);
        assert_eq!(state.detail, exact);
    }

    #[test]
    fn display_text_one_byte_past_the_cap_is_marked_as_truncated() {
        let flood = "m".repeat(MAX_REPORTER_TEXT_BYTES + 1);
        let state = shared_state();
        let reporter = Reporter::new(state.clone());

        reporter.set_model(&flood, 1);
        reporter.shard_started(1, 1, 1);
        reporter.tool_executed(&flood, 0);
        reporter.phase(Phase::Reading, flood.clone());

        let state = state.lock();
        for text in [&state.model, &state.shard.last_tool, &state.detail] {
            assert_eq!(text.len(), MAX_REPORTER_TEXT_BYTES);
            assert!(text.ends_with(TERMINAL_TEXT_TRUNCATION_MARKER));
        }
    }

    #[test]
    fn hostile_multibyte_display_text_is_escaped_and_capped() {
        let flood = "é\u{1b}".repeat(MAX_REPORTER_TEXT_BYTES);
        let state = shared_state();
        let reporter = Reporter::new(state.clone());

        reporter.phase(Phase::Reading, &flood);

        let state = state.lock();
        assert!(state.detail.len() <= MAX_REPORTER_TEXT_BYTES);
        assert!(state.detail.starts_with("é\\u{1b}é"));
        assert!(state.detail.ends_with(TERMINAL_TEXT_TRUNCATION_MARKER));
        assert!(!state.detail.contains('\u{1b}'));
    }

    #[test]
    fn snapshot_text_stays_within_the_reporter_cap() {
        let flood = "m".repeat(MAX_REPORTER_TEXT_BYTES * 3);
        let state = shared_state();
        let reporter = Reporter::new(state.clone());
        reporter.set_model(&flood, 1);
        reporter.shard_started(1, 1, 1);
        reporter.tool_executed(&flood, 0);
        reporter.phase(Phase::Reading, &flood);

        let snapshot = state.lock().snapshot();

        let cloned = snapshot.model.len() + snapshot.detail.len() + snapshot.shard.last_tool.len();
        assert_eq!(cloned, 3 * MAX_REPORTER_TEXT_BYTES);
    }

    #[test]
    fn findings_accumulate_and_can_be_replaced() {
        let state = shared_state();
        let reporter = Reporter::new(state.clone());
        reporter.add_findings(2);
        reporter.add_findings(3);
        assert_eq!(state.lock().findings, 5);
        reporter.set_findings(4);
        assert_eq!(state.lock().findings, 4);
    }

    #[test]
    fn set_model_records_model_and_context_window() {
        let state = shared_state();
        Reporter::new(state.clone()).set_model("test-model", 128_000);
        let state = state.lock();
        assert_eq!(state.model, "test-model");
        assert_eq!(state.context_window, 128_000);
    }
}
