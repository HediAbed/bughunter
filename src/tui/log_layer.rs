use std::fmt::Write as _;
use std::io::{self, Write};
use std::sync::Arc;

use parking_lot::Mutex;
use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

use crate::shared::BoundedTerminalText;

use super::state::{MAX_LOG_LINE_BYTES, ScanState, SharedState};
use super::view::level_label;

pub struct TuiLogLayer {
    state: Arc<Mutex<ScanState>>,
}

impl TuiLogLayer {
    pub fn new(state: Arc<Mutex<ScanState>>) -> Self {
        Self { state }
    }
}

impl<S> Layer<S> for TuiLogLayer
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = EventVisitor::new(MAX_LOG_LINE_BYTES);
        event.record(&mut visitor);
        let text = visitor.finish();
        let mut state = self.state.lock();
        state.push_log(*event.metadata().level(), text);
    }
}

struct EventVisitor {
    message: BoundedTerminalText,
    fields: BoundedTerminalText,
}

impl EventVisitor {
    fn new(max_bytes: usize) -> Self {
        Self {
            message: BoundedTerminalText::new(max_bytes),
            fields: BoundedTerminalText::new(max_bytes),
        }
    }

    fn finish(self) -> String {
        let mut line = self.message.finish();
        line.push_str(&self.fields.finish());
        line
    }
}

impl Visit for EventVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_text(value);
        } else {
            let _ = write!(self.fields, " {}={}", field.name(), value);
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.fields, " {}={:?}", field.name(), value);
        }
    }
}

pub fn replay_logs_to_stderr(state: &SharedState) -> io::Result<()> {
    let stderr = io::stderr();
    let mut stream = stderr.lock();
    replay_logs(state, &mut stream)
}

fn replay_logs(state: &SharedState, stream: &mut impl Write) -> io::Result<()> {
    let logs: Vec<_> = state.lock().logs.iter().cloned().collect();
    for line in logs {
        writeln!(
            stream,
            "{} {:<5} {}",
            line.time,
            level_label(line.level),
            line.text
        )?;
    }
    stream.flush()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt;

    use crate::shared::TERMINAL_TEXT_TRUNCATION_MARKER;

    fn capture(emit: impl FnOnce()) -> Vec<(tracing::Level, String)> {
        let state: SharedState = Arc::new(Mutex::new(ScanState::new()));
        let subscriber = tracing_subscriber::registry().with(TuiLogLayer::new(state.clone()));
        tracing::subscriber::with_default(subscriber, emit);
        let state = state.lock();
        state
            .logs
            .iter()
            .map(|line| (line.level, line.text.clone()))
            .collect()
    }

    struct ScriptedStream {
        written: Vec<u8>,
        failure: Option<io::ErrorKind>,
    }

    impl ScriptedStream {
        fn accepting() -> Self {
            Self {
                written: Vec::new(),
                failure: None,
            }
        }

        fn refusing(failure: io::ErrorKind) -> Self {
            Self {
                written: Vec::new(),
                failure: Some(failure),
            }
        }
    }

    impl Write for ScriptedStream {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if let Some(failure) = self.failure {
                return Err(io::Error::from(failure));
            }
            self.written.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn replay_copies_sanitized_logs_without_holding_the_state_lock() {
        let state: SharedState = Arc::new(Mutex::new(ScanState::new()));
        state
            .lock()
            .push_log(tracing::Level::WARN, "line\nwith-control".into());
        let mut stream = ScriptedStream::accepting();

        replay_logs(&state, &mut stream).unwrap();

        let output = String::from_utf8(stream.written).unwrap();
        assert!(output.contains("WARN"));
        assert!(output.contains("line\\u{a}with-control"));
        assert!(!output.contains("line\nwith-control"));
    }

    #[test]
    fn a_replay_to_a_failing_stream_surfaces_the_write_error() {
        let state: SharedState = Arc::new(Mutex::new(ScanState::new()));
        state
            .lock()
            .push_log(tracing::Level::INFO, "unreachable reader".into());
        let mut stream = ScriptedStream::refusing(io::ErrorKind::BrokenPipe);

        let error = replay_logs(&state, &mut stream)
            .expect_err("a broken stream must surface its write error");

        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert!(stream.written.is_empty());
    }

    #[test]
    fn events_record_the_message_and_level() {
        let logs = capture(|| tracing::info!("analyzing shard"));

        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].0, tracing::Level::INFO);
        assert_eq!(logs[0].1, "analyzing shard");
    }

    #[test]
    fn string_fields_are_appended_after_the_message() {
        let logs = capture(|| tracing::warn!(file = "a.rs", "skipped"));

        assert_eq!(logs[0].0, tracing::Level::WARN);
        assert_eq!(logs[0].1, "skipped file=a.rs");
    }

    #[test]
    fn non_string_fields_use_their_debug_form() {
        let logs = capture(|| tracing::info!(count = 3, "done"));

        assert_eq!(logs[0].1, "done count=3");
    }

    #[test]
    fn explicit_message_field_is_used_without_debug_quotes() {
        let logs = capture(|| tracing::info!(message = "explicit message field"));

        assert_eq!(logs[0].1, "explicit message field");
    }

    #[test]
    fn a_message_that_ends_on_the_line_cap_is_kept_verbatim() {
        let exact = "m".repeat(MAX_LOG_LINE_BYTES);

        let logs = capture(|| tracing::info!("{}", exact));

        assert_eq!(logs[0].1, exact);
    }

    #[test]
    fn a_message_one_byte_past_the_line_cap_is_marked_as_truncated() {
        let over = "m".repeat(MAX_LOG_LINE_BYTES + 1);

        let logs = capture(|| tracing::info!("{}", over));

        let line = &logs[0].1;
        assert_eq!(line.len(), MAX_LOG_LINE_BYTES);
        assert!(line.starts_with("mmmm"));
        assert!(line.ends_with(TERMINAL_TEXT_TRUNCATION_MARKER));
    }

    #[test]
    fn multibyte_messages_are_truncated_on_character_boundaries() {
        let logs = capture(|| tracing::info!("{}", "é".repeat(MAX_LOG_LINE_BYTES)));

        let kept = (MAX_LOG_LINE_BYTES - TERMINAL_TEXT_TRUNCATION_MARKER.len()) / 2;
        assert_eq!(
            logs[0].1,
            "é".repeat(kept) + TERMINAL_TEXT_TRUNCATION_MARKER
        );
    }

    #[test]
    fn control_sequences_stay_escaped_when_the_line_is_capped() {
        let logs = capture(|| tracing::info!("{}", "\u{1b}[2J".repeat(MAX_LOG_LINE_BYTES)));

        let line = &logs[0].1;
        assert!(line.len() <= MAX_LOG_LINE_BYTES, "{} bytes", line.len());
        assert!(line.starts_with("\\u{1b}[2J"));
        assert!(line.ends_with(TERMINAL_TEXT_TRUNCATION_MARKER));
        assert!(!line.contains('\u{1b}'));
    }

    #[test]
    fn many_oversized_fields_stay_within_the_line_cap() {
        let owned = "v".repeat(1024);
        let value = owned.as_str();

        let logs = capture(|| {
            tracing::info!(
                a = value,
                b = value,
                c = value,
                d = value,
                e = value,
                f = value,
                g = value,
                h = value,
                i = value,
                j = value,
                k = value,
                l = value,
                "flooded"
            )
        });

        let line = &logs[0].1;
        assert_eq!(line.len(), MAX_LOG_LINE_BYTES);
        assert!(line.starts_with("flooded a=vvvv"));
        assert!(line.ends_with(TERMINAL_TEXT_TRUNCATION_MARKER));
    }

    #[test]
    fn replay_prints_buffered_lines_without_consuming_them() {
        let state: SharedState = Arc::new(Mutex::new(ScanState::new()));
        state.lock().push_log(tracing::Level::INFO, "kept".into());
        let mut output = Vec::new();

        replay_logs(&state, &mut output).unwrap();

        assert!(String::from_utf8(output).unwrap().contains("kept"));
        assert_eq!(state.lock().logs.len(), 1);
    }
}
