use std::fmt::{self, Write};

use tracing::field::{Field, Visit};
use tracing_subscriber::field::RecordFields;
use tracing_subscriber::fmt::FormatFields;
use tracing_subscriber::fmt::format::Writer;

use crate::shared::sanitize_terminal_text;

const MESSAGE_FIELD: &str = "message";
const LOG_CRATE_FIELD_PREFIX: &str = "log.";

pub(super) struct SanitizedFields;

impl<'writer> FormatFields<'writer> for SanitizedFields {
    fn format_fields<R: RecordFields>(&self, writer: Writer<'writer>, fields: R) -> fmt::Result {
        let mut visitor = SanitizedVisitor::new(writer);
        fields.record(&mut visitor);
        visitor.result
    }
}

struct SanitizedVisitor<'writer> {
    writer: Writer<'writer>,
    result: fmt::Result,
    has_written_field: bool,
}

impl<'writer> SanitizedVisitor<'writer> {
    fn new(writer: Writer<'writer>) -> Self {
        Self {
            writer,
            result: Ok(()),
            has_written_field: false,
        }
    }

    fn append_field(&mut self, name: &str, value: fmt::Arguments<'_>) {
        if self.result.is_err() || name.starts_with(LOG_CRATE_FIELD_PREFIX) {
            return;
        }
        self.result = self.write_field(name, value);
    }

    fn write_field(&mut self, name: &str, value: fmt::Arguments<'_>) -> fmt::Result {
        if std::mem::replace(&mut self.has_written_field, true) {
            self.writer.write_char(' ')?;
        }
        if name != MESSAGE_FIELD {
            write!(self.writer, "{}=", sanitize_terminal_text(name))?;
        }
        let mut inert = InertWriter {
            inner: &mut self.writer,
        };
        inert.write_fmt(value)
    }
}

impl Visit for SanitizedVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.append_field(field.name(), format_args!("{value}"));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.append_field(field.name(), format_args!("{value:?}"));
    }
}

struct InertWriter<'borrow, 'writer> {
    inner: &'borrow mut Writer<'writer>,
}

impl Write for InertWriter<'_, '_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.inner.write_str(&sanitize_terminal_text(text))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::sync::Arc;

    use parking_lot::Mutex;
    use tracing_subscriber::layer::SubscriberExt;

    use super::SanitizedFields;
    use crate::errors::LlmError;

    const OSC_TITLE_INJECTION: &str = "\u{1b}]0;pwned\u{7}";
    const CSI_CLEAR_SCREEN: &str = "\u{1b}[2J";
    const RIGHT_TO_LEFT_OVERRIDE: char = '\u{202e}';

    #[derive(Clone, Default)]
    struct CapturedOutput(Arc<Mutex<Vec<u8>>>);

    impl CapturedOutput {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().clone()).expect("formatter emits utf-8")
        }
    }

    impl std::io::Write for CapturedOutput {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.0.lock().extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn emit_to_stderr_sink(emit: impl FnOnce()) -> String {
        let captured = CapturedOutput::default();
        let sink = captured.clone();
        let layer = tracing_subscriber::fmt::layer()
            .fmt_fields(SanitizedFields)
            .with_writer(move || sink.clone())
            .with_target(false)
            .with_ansi(false)
            .without_time()
            .compact();
        tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), emit);
        captured.text()
    }

    fn assert_free_of_raw_control_characters(output: &str) {
        let offender = output
            .trim_end_matches('\n')
            .chars()
            .find(|character| character.is_control() || *character == RIGHT_TO_LEFT_OVERRIDE);
        assert_eq!(
            offender, None,
            "raw control character survived in {output:?}"
        );
    }

    #[test]
    fn display_valued_fields_are_escaped_into_inert_text() {
        let hostile_path = format!("src/{OSC_TITLE_INJECTION}{CSI_CLEAR_SCREEN}a.rs");

        let output = emit_to_stderr_sink(|| {
            tracing::warn!(path = %hostile_path, "failed to resolve path");
        });

        assert_free_of_raw_control_characters(&output);
        assert!(
            output.contains("path=src/\\u{1b}]0;pwned\\u{7}\\u{1b}[2Ja.rs"),
            "unexpected output {output:?}"
        );
    }

    #[test]
    fn remote_api_error_bodies_are_escaped_into_inert_text() {
        let hostile_error = LlmError::ApiError {
            status: 500,
            body: format!("backend said {CSI_CLEAR_SCREEN}{OSC_TITLE_INJECTION}"),
        };

        let output = emit_to_stderr_sink(|| {
            tracing::warn!(attempt = 1, error = %hostile_error, "request failed, will retry");
        });

        assert_free_of_raw_control_characters(&output);
        assert!(
            output.contains(
                "error=API request failed: HTTP 500: backend said \\u{1b}[2J\\u{1b}]0;pwned\\u{7}"
            ),
            "unexpected output {output:?}"
        );
    }

    #[test]
    fn model_supplied_string_fields_are_escaped_into_inert_text() {
        let hostile_tool = format!("read_file{OSC_TITLE_INJECTION}");

        let output = emit_to_stderr_sink(|| {
            tracing::warn!(tool = hostile_tool.as_str(), "dispatching tool call");
        });

        assert_free_of_raw_control_characters(&output);
        assert!(
            output.contains("tool=read_file\\u{1b}]0;pwned\\u{7}"),
            "unexpected output {output:?}"
        );
    }

    #[test]
    fn debug_valued_fields_are_escaped_into_inert_text() {
        let hostile_files = vec![format!("{RIGHT_TO_LEFT_OVERRIDE}gnp.js")];

        let output = emit_to_stderr_sink(|| {
            tracing::warn!(files = ?hostile_files, "files skipped");
        });

        assert_free_of_raw_control_characters(&output);
        assert!(
            output.contains("files=[\"\\u{202e}gnp.js\"]"),
            "unexpected output {output:?}"
        );
    }

    #[test]
    fn hostile_messages_cannot_forge_additional_log_lines() {
        let output = emit_to_stderr_sink(|| {
            tracing::warn!("truncated\n ERROR forged entry\rreplaced");
        });

        assert_free_of_raw_control_characters(&output);
        assert_eq!(output.lines().count(), 1, "unexpected output {output:?}");
        assert!(
            output.contains("truncated\\u{a} ERROR forged entry\\u{d}replaced"),
            "unexpected output {output:?}"
        );
    }

    #[test]
    fn field_names_and_pair_structure_survive_sanitization() {
        let output = emit_to_stderr_sink(|| {
            tracing::warn!(shard = 3, total = 7, error = "overloaded", "shard failed");
        });

        assert_eq!(
            output.trim_end(),
            " WARN shard failed shard=3 total=7 error=overloaded"
        );
    }

    #[test]
    fn safe_unicode_is_preserved_verbatim() {
        let output = emit_to_stderr_sink(|| {
            tracing::info!(path = %"säume/日本語/λ.rs", "building repo map");
        });

        assert!(
            output.contains("path=säume/日本語/λ.rs"),
            "unexpected output {output:?}"
        );
    }

    #[test]
    fn log_crate_metadata_fields_stay_out_of_the_rendered_line() {
        let output = emit_to_stderr_sink(|| {
            tracing::warn!(log.target = "ignore::walk", path = "a.rs", "skipped");
        });

        assert_eq!(output.trim_end(), " WARN skipped path=a.rs");
    }
}
