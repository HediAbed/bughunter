use std::borrow::Cow;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const ESTIMATED_CHARS_PER_TOKEN: usize = 4;

pub fn canonicalize_path_with_missing_leaf(path: &Path) -> std::io::Result<PathBuf> {
    match path.canonicalize() {
        Ok(canonical_path) => Ok(canonical_path),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            let file_name = path.file_name().ok_or(source)?;
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            Ok(parent.canonicalize()?.join(file_name))
        }
        Err(source) => Err(source),
    }
}

pub fn read_bounded_string(path: &Path, max_bytes: usize) -> std::io::Result<String> {
    let read_limit = max_bytes.checked_add(1).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "file size limit is too large",
        )
    })?;
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::with_capacity(read_limit.min(8 * 1024));
    file.take(read_limit as u64).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} exceeds {max_bytes} bytes", path.display()),
        ));
    }
    String::from_utf8(bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

pub fn atomic_write(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let temporary = prepare_atomic_write(path, contents)?;
    temporary.persist(path).map_err(|error| error.error)?;
    sync_parent_directory(path)
}

pub fn atomic_write_new(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let temporary = prepare_atomic_write(path, contents)?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error)?;
    sync_parent_directory(path)
}

fn prepare_atomic_write(path: &Path, contents: &[u8]) -> std::io::Result<tempfile::NamedTempFile> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(contents)?;
    temporary.as_file().sync_all()?;
    Ok(temporary)
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

pub fn root_cause_message(error: &dyn std::error::Error) -> String {
    let mut deepest = error;
    while let Some(source) = deepest.source() {
        deepest = source;
    }
    deepest.to_string()
}

pub const TERMINAL_TEXT_TRUNCATION_MARKER: &str = "…[truncated]";

pub fn sanitize_terminal_text(value: &str) -> Cow<'_, str> {
    if is_terminal_text_safe(value) {
        return Cow::Borrowed(value);
    }
    let mut sanitized = String::with_capacity(value.len());
    for character in value.chars() {
        if is_terminal_safe(character) {
            sanitized.push(character);
        } else {
            sanitized.extend(character.escape_unicode());
        }
    }
    Cow::Owned(sanitized)
}

pub fn is_terminal_text_safe(value: &str) -> bool {
    value.chars().all(is_terminal_safe)
}

pub fn sanitize_terminal_text_bounded(value: &str, max_bytes: usize) -> String {
    let mut bounded = BoundedTerminalText::new(max_bytes);
    bounded.push_text(value);
    bounded.finish()
}

pub struct BoundedTerminalText {
    text: String,
    max_bytes: usize,
    marker_fit_bytes: usize,
    truncated: bool,
}

impl BoundedTerminalText {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            text: String::new(),
            max_bytes,
            marker_fit_bytes: 0,
            truncated: false,
        }
    }

    pub fn push_text(&mut self, chunk: &str) {
        if self.truncated {
            return;
        }
        for character in chunk.chars() {
            if !self.push_sanitized(character) {
                self.truncated = true;
                return;
            }
        }
    }

    pub fn finish(mut self) -> String {
        if !self.truncated {
            return self.text;
        }
        if self.max_bytes < TERMINAL_TEXT_TRUNCATION_MARKER.len() {
            self.text.clear();
            self.text.push_str(truncation_marker_prefix(self.max_bytes));
            return self.text;
        }
        self.text.truncate(self.marker_fit_bytes);
        self.text.push_str(TERMINAL_TEXT_TRUNCATION_MARKER);
        self.text
    }

    fn push_sanitized(&mut self, character: char) -> bool {
        let start = self.text.len();
        if is_terminal_safe(character) {
            if start + character.len_utf8() > self.max_bytes {
                return false;
            }
            self.text.push(character);
        } else {
            for escaped in character.escape_unicode() {
                if self.text.len() + escaped.len_utf8() > self.max_bytes {
                    self.text.truncate(start);
                    return false;
                }
                self.text.push(escaped);
            }
        }
        if self.text.len() + TERMINAL_TEXT_TRUNCATION_MARKER.len() <= self.max_bytes {
            self.marker_fit_bytes = self.text.len();
        }
        true
    }
}

impl std::fmt::Write for BoundedTerminalText {
    fn write_str(&mut self, chunk: &str) -> std::fmt::Result {
        self.push_text(chunk);
        Ok(())
    }
}

fn truncation_marker_prefix(max_bytes: usize) -> &'static str {
    let mut end = max_bytes.min(TERMINAL_TEXT_TRUNCATION_MARKER.len());
    while end > 0 && !TERMINAL_TEXT_TRUNCATION_MARKER.is_char_boundary(end) {
        end -= 1;
    }
    &TERMINAL_TEXT_TRUNCATION_MARKER[..end]
}

pub fn sanitize_markdown_inline(value: &str) -> String {
    sanitize_markdown(value, false)
}

pub fn sanitize_markdown_block(value: &str) -> String {
    sanitize_markdown(value, true)
}

pub fn sanitize_markdown_code(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len());
    for character in value.chars() {
        if character == '\n' || is_terminal_safe(character) {
            sanitized.push(character);
        } else {
            sanitized.extend(character.escape_unicode());
        }
    }
    sanitized
}

fn sanitize_markdown(value: &str, preserve_newlines: bool) -> String {
    let mut sanitized = String::with_capacity(value.len());
    for character in value.chars() {
        if character == '\n' && preserve_newlines {
            sanitized.push('\n');
        } else if !is_terminal_safe(character) {
            sanitized.extend(character.escape_unicode());
        } else {
            match character {
                '&' => sanitized.push_str("&amp;"),
                '<' => sanitized.push_str("&lt;"),
                '>' => sanitized.push_str("&gt;"),
                '\\' | '`' | '*' | '_' | '{' | '}' | '[' | ']' | '(' | ')' | '#' | '+' | '-'
                | '.' | '!' | '|' | '=' | '~' => {
                    sanitized.push('\\');
                    sanitized.push(character);
                }
                _ => sanitized.push(character),
            }
        }
    }
    sanitized
}

fn is_terminal_safe(character: char) -> bool {
    !character.is_control()
        && !matches!(
            character,
            '\u{061c}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{feff}'
        )
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn root_cause_message_unwraps_to_the_deepest_source() {
        let wrapped = crate::errors::EngineError::Io {
            path: std::path::PathBuf::from("/tmp/locked.rs"),
            source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        };

        let message = root_cause_message(&wrapped);

        assert_eq!(message, std::io::ErrorKind::PermissionDenied.to_string());
        assert!(!message.contains("/tmp/locked.rs"));
    }

    #[test]
    fn root_cause_message_falls_back_to_the_error_itself() {
        let standalone = std::io::Error::other("no source here");

        assert_eq!(root_cause_message(&standalone), "no source here");
    }

    #[test]
    fn path_canonicalization_preserves_a_missing_leaf() {
        let directory = tempfile::tempdir().unwrap();
        let existing = directory.path().join("existing");
        std::fs::write(&existing, "").unwrap();
        let canonical_root = directory.path().canonicalize().unwrap();

        assert_eq!(
            canonicalize_path_with_missing_leaf(&existing).unwrap(),
            existing.canonicalize().unwrap()
        );
        assert_eq!(
            canonicalize_path_with_missing_leaf(&directory.path().join("missing")).unwrap(),
            canonical_root.join("missing")
        );
        assert_eq!(
            canonicalize_path_with_missing_leaf(
                &directory.path().join("missing-parent").join("missing")
            )
            .unwrap_err()
            .kind(),
            std::io::ErrorKind::NotFound
        );
        let relative_missing = Path::new("__bughunter_missing_canonicalization_test_leaf__");
        assert!(!relative_missing.exists());
        assert_eq!(
            canonicalize_path_with_missing_leaf(relative_missing).unwrap(),
            std::env::current_dir()
                .unwrap()
                .canonicalize()
                .unwrap()
                .join(relative_missing)
        );
        #[cfg(unix)]
        assert_eq!(
            canonicalize_path_with_missing_leaf(
                &directory.path().join("missing-parent").join("..")
            )
            .unwrap_err()
            .kind(),
            std::io::ErrorKind::NotFound
        );
    }

    #[test]
    fn bounded_text_reader_accepts_exact_limit_and_rejects_larger_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("input.txt");
        std::fs::write(&path, "abcd").unwrap();

        assert_eq!(read_bounded_string(&path, 4).unwrap(), "abcd");

        let error = read_bounded_string(&path, 3).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exceeds 3 bytes"));
    }

    #[test]
    fn atomic_write_replaces_the_destination() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("report.json");
        std::fs::write(&path, "old").unwrap();

        atomic_write(&path, b"complete").unwrap();

        assert_eq!(std::fs::read_to_string(path).unwrap(), "complete");
    }

    #[test]
    fn atomic_new_write_does_not_replace_an_existing_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".bughunter.toml");
        std::fs::write(&path, "existing").unwrap();

        let error = atomic_write_new(&path, b"replacement").unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read_to_string(path).unwrap(), "existing");
    }

    #[test]
    fn terminal_text_escapes_control_and_directional_characters() {
        let sanitized = sanitize_terminal_text("safe\u{1b}[2J\n\u{202e}txt");

        assert_eq!(sanitized, "safe\\u{1b}[2J\\u{a}\\u{202e}txt");
        assert!(matches!(
            sanitize_terminal_text("safe"),
            Cow::Borrowed("safe")
        ));
    }

    #[test]
    fn markdown_text_escapes_structure_html_and_controls() {
        assert_eq!(
            sanitize_markdown_inline("# [x](javascript:bad)<script>\n"),
            "\\# \\[x\\]\\(javascript:bad\\)&lt;script&gt;\\u{a}"
        );
        assert_eq!(
            sanitize_markdown_block("line\n---\n&"),
            "line\n\\-\\-\\-\n&amp;"
        );
    }

    #[test]
    fn markdown_code_preserves_evidence_and_escapes_terminal_controls() {
        assert_eq!(
            sanitize_markdown_code("#[derive(Debug)]\n\tlet value = `raw`;\u{202e}\u{1b}"),
            "#[derive(Debug)]\n\\u{9}let value = `raw`;\\u{202e}\\u{1b}"
        );
    }

    #[test]
    fn bounded_text_reader_rejects_an_unrepresentable_limit() {
        let error = read_bounded_string(Path::new("unused"), usize::MAX).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("limit is too large"));
    }

    #[test]
    fn bounded_text_reader_rejects_invalid_utf8() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("invalid.txt");
        std::fs::write(&path, [0xff]).unwrap();

        let error = read_bounded_string(&path, 1).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn atomic_helpers_accept_a_bare_filename_parent() {
        let temporary = prepare_atomic_write(Path::new("report.tmp"), b"contents").unwrap();

        assert_eq!(std::fs::read(temporary.path()).unwrap(), b"contents");
        sync_parent_directory(Path::new("report.tmp")).unwrap();
    }

    #[test]
    fn terminal_text_neutralizes_ansi_csi_and_osc_sequences() {
        let sanitized = sanitize_terminal_text("a\u{1b}[31mred\u{1b}]0;title\u{7}\r\u{0}b");

        assert_eq!(
            sanitized,
            "a\\u{1b}[31mred\\u{1b}]0;title\\u{7}\\u{d}\\u{0}b"
        );
        assert!(!sanitized.chars().any(char::is_control));
    }

    #[test]
    fn terminal_text_neutralizes_bidi_and_invisible_characters() {
        let hostile =
            "start\u{202e}dne\u{202c}\u{200b}\u{200f}\u{61c}\u{feff}\u{2066}\u{2069}\u{2060}end";

        assert_eq!(
            sanitize_terminal_text(hostile),
            "start\\u{202e}dne\\u{202c}\\u{200b}\\u{200f}\\u{61c}\\u{feff}\\u{2066}\\u{2069}\\u{2060}end"
        );
    }

    #[test]
    fn terminal_text_escapes_nul_and_c1_control_characters() {
        assert_eq!(
            sanitize_terminal_text("a\u{0}b\u{85}c\u{9b}d"),
            "a\\u{0}b\\u{85}c\\u{9b}d"
        );
        assert_eq!(sanitize_markdown_block("a\u{0}b"), "a\\u{0}b");
    }

    #[test]
    fn terminal_text_escaping_is_chunk_independent() {
        let streamed = "log\u{1b}[2Jline\u{202e}tail\u{0}";
        let whole = sanitize_terminal_text(streamed);

        for (split, _) in streamed.char_indices() {
            let (head, tail) = streamed.split_at(split);
            let joined = format!(
                "{}{}",
                sanitize_terminal_text(head),
                sanitize_terminal_text(tail)
            );

            assert_eq!(joined, whole, "chunk boundary at byte {split}");
        }
    }

    #[test]
    fn terminal_text_sanitization_is_idempotent_and_borrows_safe_input() {
        let sanitized = sanitize_terminal_text("x\u{1b}y\u{202e}z").into_owned();

        assert!(matches!(
            sanitize_terminal_text(&sanitized),
            Cow::Borrowed(_)
        ));
        assert_eq!(sanitize_terminal_text(&sanitized), sanitized);
    }

    #[test]
    fn bounded_terminal_text_keeps_input_that_ends_on_the_limit() {
        assert_eq!(sanitize_terminal_text_bounded("abcd", 4), "abcd");
        assert_eq!(sanitize_terminal_text_bounded("", 0), "");
        assert_eq!(
            sanitize_terminal_text_bounded("safe\u{1b}[2J\n\u{202e}txt", 29),
            "safe\\u{1b}[2J\\u{a}\\u{202e}txt"
        );
    }

    #[test]
    fn bounded_terminal_text_marks_truncation_within_the_limit() {
        let limit = TERMINAL_TEXT_TRUNCATION_MARKER.len() + 6;

        let bounded = sanitize_terminal_text_bounded(&"a".repeat(100), limit);

        assert_eq!(bounded, format!("aaaaaa{TERMINAL_TEXT_TRUNCATION_MARKER}"));
        assert_eq!(bounded.len(), limit);
    }

    #[test]
    fn bounded_terminal_text_truncates_multibyte_input_on_character_boundaries() {
        let limit = TERMINAL_TEXT_TRUNCATION_MARKER.len() + 6;

        let bounded = sanitize_terminal_text_bounded(&"é".repeat(11), limit);

        assert_eq!(bounded, format!("ééé{TERMINAL_TEXT_TRUNCATION_MARKER}"));
        assert_eq!(bounded.len(), limit);
    }

    #[test]
    fn bounded_terminal_text_never_emits_half_of_an_escape_sequence() {
        let limit = TERMINAL_TEXT_TRUNCATION_MARKER.len() + 6;

        let bounded = sanitize_terminal_text_bounded(&"\u{1b}".repeat(4), limit);

        assert_eq!(
            bounded,
            format!("\\u{{1b}}{TERMINAL_TEXT_TRUNCATION_MARKER}")
        );
        assert_eq!(bounded.len(), limit);
    }

    #[test]
    fn bounded_terminal_text_keeps_the_marker_when_the_limit_cannot_hold_it() {
        assert_eq!(sanitize_terminal_text_bounded("\u{1b}", 3), "…");
        assert_eq!(sanitize_terminal_text_bounded("aaaaaaaa", 5), "…[t");
        assert_eq!(sanitize_terminal_text_bounded("aaaaaaaa", 2), "");
        assert_eq!(sanitize_terminal_text_bounded("aaaaaaaa", 0), "");
    }

    #[test]
    fn bounded_terminal_text_sink_is_chunk_independent() {
        let streamed = "log\u{1b}[2Jline\u{202e}tail\u{0}";
        let tight = TERMINAL_TEXT_TRUNCATION_MARKER.len() + 6;

        for limit in [tight, 4 * 1024] {
            let mut sink = BoundedTerminalText::new(limit);
            for character in streamed.chars() {
                let mut encoded = [0u8; 4];
                sink.push_text(character.encode_utf8(&mut encoded));
            }

            assert_eq!(
                sink.finish(),
                sanitize_terminal_text_bounded(streamed, limit)
            );
        }
    }

    #[test]
    fn markdown_inline_defuses_link_and_image_injection() {
        let sanitized =
            sanitize_markdown_inline("[click](javascript:alert(1)) ![i](http://e/x.png)");

        assert_eq!(
            sanitized,
            "\\[click\\]\\(javascript:alert\\(1\\)\\) \\!\\[i\\]\\(http://e/x\\.png\\)"
        );
        assert!(!sanitized.contains("]("));
        assert!(!sanitized.contains("!["));
    }

    #[test]
    fn markdown_inline_defuses_html_tags_and_code_fences() {
        let sanitized = sanitize_markdown_inline("<script>a&b</script> ```rust");

        assert_eq!(
            sanitized,
            "&lt;script&gt;a&amp;b&lt;/script&gt; \\`\\`\\`rust"
        );
        assert!(!sanitized.contains('<'));
        assert!(!sanitized.contains('>'));
        assert!(!sanitized.contains("```"));
    }

    #[test]
    fn markdown_block_defuses_tilde_fences_and_setext_headings() {
        let sanitized = sanitize_markdown_block("title\n===\n~~~rust\npayload\n~~~");

        assert_eq!(
            sanitized,
            "title\n\\=\\=\\=\n\\~\\~\\~rust\npayload\n\\~\\~\\~"
        );
        assert!(!sanitized.contains("==="));
        assert!(!sanitized.contains("~~~"));
    }

    #[test]
    fn markdown_inline_collapses_newlines_that_block_preserves() {
        assert_eq!(
            sanitize_markdown_inline("first\nsecond"),
            "first\\u{a}second"
        );
        assert_eq!(sanitize_markdown_block("first\nsecond"), "first\nsecond");
    }

    #[test]
    fn markdown_block_defuses_report_structure_forgery() {
        let forgery = "## [critical] Fake\n\n**File:** /etc/passwd\n\n---\n\nNo issues found.";

        let sanitized = sanitize_markdown_block(forgery);

        assert_eq!(
            sanitized.matches('\n').count(),
            forgery.matches('\n').count()
        );
        assert!(sanitized.starts_with("\\#\\# \\[critical\\] Fake"));
        assert!(!sanitized.contains("## ["));
        assert!(!sanitized.contains("**File:**"));
        assert!(!sanitized.contains("---"));
        assert!(!sanitized.contains("No issues found."));
    }

    #[test]
    fn markdown_sanitization_stays_injection_free_when_applied_twice() {
        let hostile = "<a>](`\\!*_|{}[]()#+-.";

        for sanitize in [
            sanitize_markdown_inline as fn(&str) -> String,
            sanitize_markdown_block,
        ] {
            let once = sanitize(hostile);
            let twice = sanitize(&once);

            for primitive in ["<", ">", "](", "![", "```"] {
                assert!(!once.contains(primitive), "{primitive} survived one pass");
                assert!(
                    !twice.contains(primitive),
                    "{primitive} survived two passes"
                );
            }
        }
    }
}
