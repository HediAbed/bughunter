use std::borrow::Cow;
use std::fmt::Write as FormatWrite;
use std::io::Write as ByteWrite;

use crate::errors::ReportError;

pub const MAX_REPORT_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_DIAGNOSTIC_ENTRIES: usize = 10_000;
pub const MAX_DIAGNOSTIC_BYTES: usize = 16 * 1024 * 1024;
pub const TRUNCATION_MARKER: &str = "…[truncated]";

pub const JSON_REPORT: &str = "the JSON report";
pub const MARKDOWN_REPORT: &str = "the Markdown report";

pub fn truncate_on_char_boundary(text: &str, max_bytes: usize) -> &str {
    if text.len() <= max_bytes {
        return text;
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

pub fn truncate_with_marker(text: &str, max_bytes: usize) -> Cow<'_, str> {
    if text.len() <= max_bytes {
        return Cow::Borrowed(text);
    }
    let kept = truncate_on_char_boundary(text, max_bytes.saturating_sub(TRUNCATION_MARKER.len()));
    let mut marked = String::with_capacity(kept.len() + TRUNCATION_MARKER.len());
    marked.push_str(kept);
    marked.push_str(TRUNCATION_MARKER);
    Cow::Owned(marked)
}

pub struct BoundedText {
    text: String,
    resource: &'static str,
    limit: usize,
}

impl BoundedText {
    pub fn new(resource: &'static str, limit: usize) -> Self {
        Self {
            text: String::new(),
            resource,
            limit,
        }
    }

    pub fn push(&mut self, fragment: &str) -> Result<(), ReportError> {
        if self.text.len() + fragment.len() > self.limit {
            return Err(self.exhausted());
        }
        self.text.push_str(fragment);
        Ok(())
    }

    pub fn push_fmt(&mut self, fragment: std::fmt::Arguments<'_>) -> Result<(), ReportError> {
        let written = self.write_fmt(fragment);
        match written {
            Ok(()) => Ok(()),
            Err(_) => Err(self.exhausted()),
        }
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    pub fn into_string(self) -> String {
        self.text
    }

    fn exhausted(&self) -> ReportError {
        ReportError::TooLarge {
            resource: self.resource,
            limit_bytes: self.limit,
        }
    }
}

impl FormatWrite for BoundedText {
    fn write_str(&mut self, fragment: &str) -> std::fmt::Result {
        if self.text.len() + fragment.len() > self.limit {
            return Err(std::fmt::Error);
        }
        self.text.push_str(fragment);
        Ok(())
    }
}

pub struct BoundedBytes {
    bytes: Vec<u8>,
    limit: usize,
    exhausted: bool,
}

impl BoundedBytes {
    pub fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            exhausted: false,
        }
    }

    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl ByteWrite for BoundedBytes {
    fn write(&mut self, chunk: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len() + chunk.len() > self.limit {
            self.exhausted = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "report byte limit exhausted",
            ));
        }
        self.bytes.extend_from_slice(chunk);
        Ok(chunk.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn path_diagnostic(path: &str, reason: &str) -> String {
    format!("{path} ({reason})")
}

pub struct BoundedDiagnostics {
    entries: Vec<String>,
    retained_bytes: usize,
    omitted: u32,
    max_entries: usize,
    max_bytes: usize,
}

impl Default for BoundedDiagnostics {
    fn default() -> Self {
        Self::with_limits(MAX_DIAGNOSTIC_ENTRIES, MAX_DIAGNOSTIC_BYTES)
    }
}

impl BoundedDiagnostics {
    pub fn with_limits(max_entries: usize, max_bytes: usize) -> Self {
        Self {
            entries: Vec::new(),
            retained_bytes: 0,
            omitted: 0,
            max_entries,
            max_bytes,
        }
    }

    pub fn record(&mut self, entry: String) {
        if self.count_allows_entry() {
            self.record_within_byte_limit(entry);
        }
    }

    pub fn record_with(&mut self, entry: &mut dyn FnMut() -> String) {
        if self.count_allows_entry() {
            self.record_within_byte_limit(entry());
        }
    }

    fn count_allows_entry(&mut self) -> bool {
        if self.entries.len() < self.max_entries {
            return true;
        }
        self.omit(1);
        false
    }

    fn record_within_byte_limit(&mut self, entry: String) {
        let Some(retained_bytes) = self.retained_bytes.checked_add(entry.len()) else {
            self.omit(1);
            return;
        };
        if retained_bytes > self.max_bytes {
            self.omit(1);
            return;
        }
        self.retained_bytes = retained_bytes;
        self.entries.push(entry);
    }

    pub fn omit(&mut self, count: u32) {
        self.omitted = self.omitted.saturating_add(count);
    }

    #[cfg(test)]
    pub fn entries(&self) -> &[String] {
        &self.entries
    }

    #[cfg(test)]
    pub fn retained(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub fn omitted(&self) -> u32 {
        self.omitted
    }

    pub fn observed(&self) -> usize {
        self.entries.len().saturating_add(self.omitted as usize)
    }

    pub fn into_sorted_entries(mut self) -> (Vec<String>, u32) {
        self.entries.sort_unstable();
        (self.entries, self.omitted)
    }

    pub fn into_entries(self) -> (Vec<String>, u32) {
        (self.entries, self.omitted)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn bounded_text_accepts_exactly_the_limit() {
        let mut text = BoundedText::new(MARKDOWN_REPORT, 5);

        text.push("abc").unwrap();
        text.push_fmt(format_args!("{}{}", "d", "e")).unwrap();

        assert_eq!(text.into_string(), "abcde");
    }

    #[test]
    fn bounded_text_rejects_the_byte_after_the_limit() {
        let mut text = BoundedText::new(MARKDOWN_REPORT, 5);
        text.push("abcde").unwrap();

        let error = text.push("f").unwrap_err();

        assert!(matches!(
            error,
            ReportError::TooLarge {
                resource: MARKDOWN_REPORT,
                limit_bytes: 5
            }
        ));
        assert_eq!(text.into_string(), "abcde");
    }

    #[test]
    fn bounded_text_starts_empty_and_reports_the_named_resource() {
        let mut text = BoundedText::new(JSON_REPORT, 1);
        assert!(text.is_empty());

        let error = text.push_fmt(format_args!("{}", "too long")).unwrap_err();

        assert_eq!(
            error.to_string(),
            "the JSON report exceeds the 1 byte limit"
        );
    }

    #[test]
    fn bounded_bytes_accepts_exactly_the_limit_and_rejects_the_next_byte() {
        let mut sink = BoundedBytes::new(4);

        sink.write_all(b"abcd").unwrap();
        assert!(!sink.is_exhausted());
        sink.flush().unwrap();

        assert!(sink.write_all(b"e").is_err());
        assert!(sink.is_exhausted());
        assert_eq!(sink.into_bytes(), b"abcd".to_vec());
    }

    #[test]
    fn diagnostics_omit_the_entry_after_the_count_limit() {
        let mut diagnostics = BoundedDiagnostics::with_limits(2, MAX_DIAGNOSTIC_BYTES);

        for entry in ["b", "a", "c"] {
            diagnostics.record(entry.to_string());
        }

        assert_eq!(diagnostics.retained(), 2);
        assert_eq!(diagnostics.omitted(), 1);
        assert_eq!(diagnostics.observed(), 3);
        assert_eq!(
            diagnostics.into_sorted_entries(),
            (vec!["a".to_string(), "b".to_string()], 1)
        );
    }

    #[test]
    fn diagnostics_never_build_an_entry_once_the_count_is_exhausted() {
        let mut diagnostics = BoundedDiagnostics::with_limits(1, MAX_DIAGNOSTIC_BYTES);
        let mut built = 0;

        for _ in 0..4 {
            diagnostics.record_with(&mut || {
                built += 1;
                "entry".to_string()
            });
        }

        assert_eq!(built, 1, "an omitted entry must not be formatted");
        assert_eq!(diagnostics.omitted(), 3);
    }

    #[test]
    fn diagnostics_omit_the_entry_that_would_cross_the_byte_limit() {
        let mut diagnostics = BoundedDiagnostics::with_limits(MAX_DIAGNOSTIC_ENTRIES, 6);

        diagnostics.record("abc".to_string());
        diagnostics.record("def".to_string());
        diagnostics.record("g".to_string());
        diagnostics.record(String::new());

        let (entries, omitted) = diagnostics.into_entries();
        assert_eq!(
            entries,
            vec!["abc".to_string(), "def".to_string(), String::new()]
        );
        assert_eq!(omitted, 1);
    }

    #[test]
    fn diagnostics_treat_retained_byte_overflow_as_an_omission() {
        let mut diagnostics = BoundedDiagnostics::with_limits(MAX_DIAGNOSTIC_ENTRIES, usize::MAX);
        diagnostics.retained_bytes = usize::MAX;

        diagnostics.record("x".to_string());

        assert!(diagnostics.entries().is_empty());
        assert_eq!(diagnostics.omitted(), 1);
    }

    #[test]
    fn explicit_diagnostic_omissions_saturate() {
        let mut diagnostics = BoundedDiagnostics::default();

        diagnostics.omit(u32::MAX);
        diagnostics.omit(1);

        assert_eq!(diagnostics.omitted(), u32::MAX);
    }

    #[test]
    fn path_diagnostics_keep_the_reason_attached_to_the_path() {
        assert_eq!(
            path_diagnostic("src/main.rs", "model did not inspect file"),
            "src/main.rs (model did not inspect file)"
        );
    }

    #[test]
    fn diagnostics_default_to_the_named_limits() {
        let diagnostics = BoundedDiagnostics::default();

        assert_eq!(diagnostics.max_entries, MAX_DIAGNOSTIC_ENTRIES);
        assert_eq!(diagnostics.max_bytes, MAX_DIAGNOSTIC_BYTES);
        assert_eq!(diagnostics.observed(), 0);
    }

    #[test]
    fn truncation_stops_on_a_character_boundary() {
        assert_eq!(truncate_on_char_boundary("héllo", 2), "h");
        assert_eq!(truncate_on_char_boundary("héllo", 3), "hé");
        assert_eq!(truncate_on_char_boundary("héllo", 99), "héllo");
        assert_eq!(truncate_on_char_boundary("é", 1), "");
    }

    #[test]
    fn marked_truncation_keeps_short_text_borrowed() {
        let text = truncate_with_marker("short", 5);

        assert!(matches!(text, Cow::Borrowed("short")));
    }

    #[test]
    fn marked_truncation_marks_the_cut_and_respects_the_limit() {
        let source = "é".repeat(64);
        let limit = 32;

        let text = truncate_with_marker(&source, limit);

        assert!(text.ends_with(TRUNCATION_MARKER), "{text}");
        assert!(text.len() <= limit, "{} bytes", text.len());
        assert!(
            text.strip_suffix(TRUNCATION_MARKER)
                .is_some_and(|kept| kept.chars().all(|character| character == 'é')),
            "{text}"
        );
    }
}
