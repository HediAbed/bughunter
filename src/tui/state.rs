use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use ratatui::style::Color;
use tracing::Level;

const MAX_LOG_LINES: usize = 1000;
pub(crate) const MAX_LOG_LINE_BYTES: usize = 8 * 1024;
pub(crate) const RENDER_LOG_LINES: usize = 256;

const PROGRESS_FLOOR: f64 = 0.03;
const PROGRESS_CEILING: f64 = 0.97;
const SHARD_INSPECTION_WEIGHT: f64 = 0.9;
const SHARD_FINALIZATION_WEIGHT: f64 = 0.1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Preparing,
    Discovering,
    Reading,
    Searching,
    Querying,
    Submitting,
    Failed,
    Cancelled,
    Finished,
}

impl Phase {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Phase::Preparing => "preparing",
            Phase::Discovering => "discovering files",
            Phase::Reading => "reading",
            Phase::Searching => "searching",
            Phase::Querying => "querying model",
            Phase::Submitting => "recording findings",
            Phase::Failed => "failed",
            Phase::Cancelled => "cancelled",
            Phase::Finished => "finished",
        }
    }

    pub(crate) fn color(self) -> Color {
        match self {
            Phase::Preparing => Color::Gray,
            Phase::Discovering => Color::Magenta,
            Phase::Reading => Color::Green,
            Phase::Searching => Color::Blue,
            Phase::Querying => Color::Yellow,
            Phase::Submitting => Color::Cyan,
            Phase::Failed => Color::Red,
            Phase::Cancelled => Color::Yellow,
            Phase::Finished => Color::Green,
        }
    }
}

#[derive(Clone)]
pub(crate) struct LogLine {
    pub(crate) time: String,
    pub(crate) level: Level,
    pub(crate) text: String,
}

#[derive(Clone, Default)]
pub(crate) struct ShardProgress {
    pub(crate) files: usize,
    pub(crate) eligible_tokens: u64,
    pub(crate) inspected_tokens: u64,
    pub(crate) tool_calls: u32,
    pub(crate) last_tool: String,
    pub(crate) finalizing: bool,
    pub(crate) finalization_attempt: u32,
}

impl ShardProgress {
    fn fraction(&self) -> f64 {
        let inspected = self.inspected_tokens as f64;
        let eligible = self.eligible_tokens.max(1) as f64;
        let inspection = (inspected / eligible).min(1.0);
        SHARD_INSPECTION_WEIGHT * inspection
            + SHARD_FINALIZATION_WEIGHT * f64::from(self.finalizing)
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct ModelActivity {
    pub(crate) requests: u64,
    pub(crate) input_tokens: u64,
    pub(crate) output_tokens: u64,
}

pub struct ScanState {
    pub(crate) model: String,
    pub(crate) context_window: u32,
    pub(crate) total_shards: usize,
    pub(crate) current_shard: usize,
    pub(crate) completed_shards: usize,
    pub(crate) shard: ShardProgress,
    pub(crate) model_activity: ModelActivity,
    pub(crate) phase: Phase,
    pub(crate) detail: String,
    pub(crate) findings: usize,
    started: Instant,
    displayed_progress: f64,
    pub(crate) logs: VecDeque<LogLine>,
}

impl ScanState {
    pub(crate) fn new() -> Self {
        Self {
            model: String::new(),
            context_window: 0,
            total_shards: 0,
            current_shard: 0,
            completed_shards: 0,
            shard: ShardProgress::default(),
            model_activity: ModelActivity::default(),
            phase: Phase::Preparing,
            detail: String::new(),
            findings: 0,
            started: Instant::now(),
            displayed_progress: 0.0,
            logs: VecDeque::new(),
        }
    }

    pub(crate) fn push_log(&mut self, level: Level, text: String) {
        while self.logs.len() >= MAX_LOG_LINES {
            self.logs.pop_front();
        }
        self.logs.push_back(LogLine {
            time: chrono::Local::now().format("%H:%M:%S").to_string(),
            level,
            text: bounded_log_line(text),
        });
    }

    fn raw_progress(&self) -> f64 {
        if self.phase == Phase::Finished {
            return 1.0;
        }
        if !self.has_started() {
            return 0.0;
        }
        let total = self.total_shards.max(1) as f64;
        let completed = self.completed_shards.min(self.total_shards.max(1)) as f64;
        let done = ((completed + self.active_shard_fraction()) / total).clamp(0.0, 1.0);
        PROGRESS_FLOOR + (PROGRESS_CEILING - PROGRESS_FLOOR) * done
    }

    pub(crate) fn progress(&mut self) -> f64 {
        self.displayed_progress = self.displayed_progress.max(self.raw_progress());
        self.displayed_progress
    }

    fn has_started(&self) -> bool {
        self.phase != Phase::Preparing || self.total_shards > 0
    }

    fn active_shard_fraction(&self) -> f64 {
        if self.current_shard <= self.completed_shards {
            return 0.0;
        }
        self.shard.fraction()
    }

    pub(crate) fn snapshot(&mut self) -> Snapshot {
        let progress = self.progress();
        let start = self.logs.len().saturating_sub(RENDER_LOG_LINES);
        Snapshot {
            model: self.model.clone(),
            context_window: self.context_window,
            total_shards: self.total_shards,
            current_shard: self.current_shard,
            shard: self.shard.clone(),
            model_activity: self.model_activity,
            phase: self.phase,
            detail: self.detail.clone(),
            findings: self.findings,
            progress,
            elapsed: self.started.elapsed(),
            logs: self.logs.iter().skip(start).cloned().collect(),
        }
    }
}

fn bounded_log_line(text: String) -> String {
    if text.len() <= MAX_LOG_LINE_BYTES && crate::shared::is_terminal_text_safe(&text) {
        return text;
    }
    crate::shared::sanitize_terminal_text_bounded(&text, MAX_LOG_LINE_BYTES)
}

pub(crate) struct Snapshot {
    pub(crate) model: String,
    pub(crate) context_window: u32,
    pub(crate) total_shards: usize,
    pub(crate) current_shard: usize,
    pub(crate) shard: ShardProgress,
    pub(crate) model_activity: ModelActivity,
    pub(crate) phase: Phase,
    pub(crate) detail: String,
    pub(crate) findings: usize,
    pub(crate) progress: f64,
    pub(crate) elapsed: Duration,
    pub(crate) logs: Vec<LogLine>,
}

pub type SharedState = Arc<Mutex<ScanState>>;

pub fn shared_state() -> SharedState {
    Arc::new(Mutex::new(ScanState::new()))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        MAX_LOG_LINE_BYTES, MAX_LOG_LINES, PROGRESS_CEILING, PROGRESS_FLOOR, Phase,
        RENDER_LOG_LINES, ScanState, ShardProgress,
    };
    use std::collections::HashSet;

    use ratatui::style::Color;
    use tracing::Level;

    use crate::shared::TERMINAL_TEXT_TRUNCATION_MARKER;

    fn single_shard_state(eligible_tokens: u64) -> ScanState {
        let mut state = ScanState::new();
        state.total_shards = 1;
        state.current_shard = 1;
        state.phase = Phase::Querying;
        state.shard.files = 4;
        state.shard.eligible_tokens = eligible_tokens;
        state
    }

    #[test]
    fn log_ring_buffer_is_bounded() {
        let mut state = ScanState::new();
        for i in 0..(MAX_LOG_LINES + 50) {
            state.push_log(Level::INFO, format!("line {i}"));
        }
        assert_eq!(state.logs.len(), MAX_LOG_LINES);
        assert_eq!(state.logs.back().unwrap().text, "line 1049");
    }

    #[test]
    fn a_log_line_that_ends_on_the_byte_cap_is_kept_verbatim() {
        let mut state = ScanState::new();
        let exact = "x".repeat(MAX_LOG_LINE_BYTES);

        state.push_log(Level::INFO, exact.clone());

        assert_eq!(state.logs.back().unwrap().text, exact);
    }

    #[test]
    fn a_log_line_one_byte_past_the_byte_cap_is_marked_as_truncated() {
        let mut state = ScanState::new();

        state.push_log(Level::INFO, "x".repeat(MAX_LOG_LINE_BYTES + 1));

        let line = &state.logs.back().unwrap().text;
        assert_eq!(line.len(), MAX_LOG_LINE_BYTES);
        assert!(line.ends_with(TERMINAL_TEXT_TRUNCATION_MARKER));
    }

    #[test]
    fn log_lines_escape_control_and_bidi_characters_before_capping() {
        let mut state = ScanState::new();

        state.push_log(Level::INFO, "safe\u{1b}[2J\u{202e}txt".into());

        assert_eq!(
            state.logs.back().unwrap().text,
            "safe\\u{1b}[2J\\u{202e}txt"
        );
    }

    #[test]
    fn the_log_ring_bounds_its_aggregate_bytes() {
        let mut state = ScanState::new();
        let oversized = "x".repeat(MAX_LOG_LINE_BYTES * 2);

        for _ in 0..(MAX_LOG_LINES + 10) {
            state.push_log(Level::INFO, oversized.clone());
        }

        let retained: usize = state.logs.iter().map(|line| line.text.len()).sum();
        assert_eq!(state.logs.len(), MAX_LOG_LINES);
        assert_eq!(retained, MAX_LOG_LINES * MAX_LOG_LINE_BYTES);
    }

    #[test]
    fn snapshots_clone_only_bounded_log_bytes() {
        let mut state = ScanState::new();
        let oversized = "x".repeat(MAX_LOG_LINE_BYTES * 2);

        for _ in 0..(RENDER_LOG_LINES + 20) {
            state.push_log(Level::INFO, oversized.clone());
        }

        let snapshot = state.snapshot();
        let cloned: usize = snapshot.logs.iter().map(|line| line.text.len()).sum();
        assert_eq!(snapshot.logs.len(), RENDER_LOG_LINES);
        assert_eq!(cloned, RENDER_LOG_LINES * MAX_LOG_LINE_BYTES);
    }

    #[test]
    fn progress_is_zero_while_preparing() {
        let mut state = ScanState::new();
        assert_eq!(state.progress(), 0.0);
    }

    #[test]
    fn progress_baseline_is_three_percent_once_running() {
        let mut state = ScanState::new();
        state.phase = Phase::Querying;
        assert_eq!(state.progress(), PROGRESS_FLOOR);
    }

    #[test]
    fn knowing_the_shard_count_also_starts_progress() {
        let mut state = ScanState::new();
        state.total_shards = 12;
        assert_eq!(state.progress(), PROGRESS_FLOOR);
    }

    #[test]
    fn progress_rises_with_inspected_tokens() {
        let mut state = single_shard_state(10_000);
        let baseline = state.progress();
        state.shard.inspected_tokens = 2_500;
        let quarter = state.progress();
        state.shard.inspected_tokens = 7_500;
        let three_quarters = state.progress();
        assert!(quarter > baseline);
        assert!(three_quarters > quarter);
    }

    #[test]
    fn single_shard_progress_stays_strictly_inside_the_band_mid_flight() {
        let mut state = single_shard_state(10_000);
        state.shard.inspected_tokens = 5_000;
        let progress = state.progress();
        assert!(progress > PROGRESS_FLOOR, "{progress} must exceed 0.03");
        assert!(
            progress < PROGRESS_CEILING,
            "{progress} must stay under 0.97"
        );
    }

    #[test]
    fn saturated_single_shard_never_exceeds_the_ceiling() {
        let mut state = single_shard_state(1_000);
        state.shard.inspected_tokens = 50_000;
        state.shard.finalizing = true;
        assert_eq!(state.progress(), PROGRESS_CEILING);
    }

    #[test]
    fn finalization_contributes_the_last_tenth_of_a_shard() {
        let mut state = single_shard_state(1_000);
        state.shard.inspected_tokens = 1_000;
        let inspected_only = state.progress();
        state.shard.finalizing = true;
        let with_finalization = state.progress();
        assert!(with_finalization > inspected_only);
        assert_eq!(with_finalization, PROGRESS_CEILING);
    }

    #[test]
    fn completed_shards_count_fully() {
        let mut state = ScanState::new();
        state.phase = Phase::Querying;
        state.total_shards = 4;
        state.completed_shards = 2;
        state.current_shard = 2;
        let expected = PROGRESS_FLOOR + (PROGRESS_CEILING - PROGRESS_FLOOR) * 0.5;
        assert!((state.progress() - expected).abs() < 1e-9);
    }

    #[test]
    fn starting_the_next_shard_does_not_regress_progress() {
        let mut state = ScanState::new();
        state.phase = Phase::Querying;
        state.total_shards = 2;
        state.current_shard = 1;
        state.shard.eligible_tokens = 1_000;
        state.shard.inspected_tokens = 1_000;
        state.shard.finalizing = true;
        let end_of_first = state.progress();

        state.completed_shards = 1;
        state.current_shard = 2;
        state.shard.eligible_tokens = 1_000;
        state.shard.inspected_tokens = 0;
        state.shard.finalizing = false;
        assert!(state.progress() >= end_of_first);
    }

    #[test]
    fn progress_never_decreases_over_a_scripted_run() {
        let mut state = ScanState::new();
        let mut previous = state.progress();
        let assert_monotonic = |state: &mut ScanState, previous: &mut f64| {
            let current = state.progress();
            assert!(
                current >= *previous,
                "progress regressed from {previous} to {current}"
            );
            *previous = current;
        };

        state.total_shards = 3;
        assert_monotonic(&mut state, &mut previous);

        for shard in 1..=3usize {
            state.current_shard = shard;
            state.shard = ShardProgress {
                files: 3,
                eligible_tokens: 4_000,
                ..ShardProgress::default()
            };
            state.phase = Phase::Querying;
            assert_monotonic(&mut state, &mut previous);

            for chunk in [900u64, 1_400, 300, 5_000] {
                state.phase = Phase::Reading;
                state.shard.inspected_tokens += chunk;
                state.shard.tool_calls += 1;
                assert_monotonic(&mut state, &mut previous);
            }

            state.phase = Phase::Submitting;
            state.shard.finalizing = true;
            assert_monotonic(&mut state, &mut previous);

            state.completed_shards = shard;
            assert_monotonic(&mut state, &mut previous);
        }

        state.phase = Phase::Finished;
        assert_monotonic(&mut state, &mut previous);
        assert_eq!(previous, 1.0);
    }

    #[test]
    fn progress_reaches_one_only_when_finished() {
        let mut state = single_shard_state(100);
        state.shard.inspected_tokens = u64::MAX / 2;
        state.shard.finalizing = true;
        state.completed_shards = 1;
        assert!(state.progress() < 1.0);
        state.phase = Phase::Finished;
        assert_eq!(state.progress(), 1.0);
    }

    #[test]
    fn failed_and_cancelled_progress_never_claims_completion() {
        for phase in [Phase::Failed, Phase::Cancelled] {
            let mut state = single_shard_state(100);
            state.shard.inspected_tokens = u64::MAX / 2;
            state.shard.finalizing = true;
            state.completed_shards = 1;
            state.phase = phase;
            assert!(state.progress() < 1.0, "{phase:?} claimed completion");
        }
    }

    #[test]
    fn finished_progress_stays_at_one() {
        let mut state = single_shard_state(100);
        state.phase = Phase::Finished;
        assert_eq!(state.progress(), 1.0);
        state.phase = Phase::Querying;
        assert_eq!(state.progress(), 1.0);
    }

    #[test]
    fn snapshot_carries_progress_and_shard_detail() {
        let mut state = single_shard_state(2_000);
        state.shard.inspected_tokens = 1_000;
        state.shard.tool_calls = 7;
        state.shard.last_tool = "read_file".into();
        state.model_activity.requests = 3;
        let snapshot = state.snapshot();
        assert_eq!(snapshot.shard.tool_calls, 7);
        assert_eq!(snapshot.shard.last_tool, "read_file");
        assert_eq!(snapshot.model_activity.requests, 3);
        assert!(snapshot.progress > PROGRESS_FLOOR);
        assert!(snapshot.progress < PROGRESS_CEILING);
    }

    #[test]
    fn zero_eligible_tokens_keeps_progress_at_the_baseline_until_work_lands() {
        let mut state = ScanState::new();
        state.phase = Phase::Querying;
        state.current_shard = 1;
        assert_eq!(state.progress(), PROGRESS_FLOOR);
    }

    #[test]
    fn every_phase_has_a_distinct_label_and_expected_color() {
        let phases = [
            (Phase::Preparing, "preparing", Color::Gray),
            (Phase::Discovering, "discovering files", Color::Magenta),
            (Phase::Reading, "reading", Color::Green),
            (Phase::Searching, "searching", Color::Blue),
            (Phase::Querying, "querying model", Color::Yellow),
            (Phase::Submitting, "recording findings", Color::Cyan),
            (Phase::Failed, "failed", Color::Red),
            (Phase::Cancelled, "cancelled", Color::Yellow),
            (Phase::Finished, "finished", Color::Green),
        ];

        for (phase, label, color) in phases {
            assert_eq!(phase.label(), label);
            assert_eq!(phase.color(), color);
        }

        let labels = phases
            .iter()
            .map(|(_, label, _)| *label)
            .collect::<HashSet<_>>();
        assert_eq!(labels.len(), phases.len());
    }
}
