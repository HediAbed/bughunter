use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use regex::Regex;

use super::filesystem::ProjectFilesystem;
use super::reader;
use super::walker::{self, DiscoverOpts, FileEntry};
use crate::cancel::CancelToken;
use crate::config::EngineConfig;
use crate::errors::EngineError;

pub const MAX_SEARCH_PATTERN_BYTES: usize = 4 * 1024;
pub const MAX_SEARCH_RESULTS: u32 = 1_000;
pub const MAX_SEARCH_CONTEXT_LINES: u32 = 20;

const DEFAULT_MAX_SEARCH_RESULTS: u32 = 500;
const MAX_INDEXED_LINES_PER_FILE: u32 = 1_000_000;
const MAX_RETAINED_LINE_BYTES: usize = 64 * 1024;
const MAX_AGGREGATE_MATCH_BYTES: usize = 2 * 1024 * 1024;
const MATERIALIZATION_PREALLOCATION: usize = 64;
const TRUNCATION_MARKER: &str = "…[truncated]";

const PATTERN_RESOURCE: &str = "pattern byte";
const RESULT_RESOURCE: &str = "result";
const CONTEXT_RESOURCE: &str = "context line";
const INDEXED_LINE_RESOURCE: &str = "indexed file line";
const AGGREGATE_TEXT_RESOURCE: &str = "aggregate match text byte";

#[derive(Debug, Clone, serde::Serialize)]
pub struct TextMatch {
    pub path: PathBuf,
    pub line_number: u32,
    pub line_content: String,
    pub context_before: Vec<String>,
    pub context_after: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SearchOpts {
    pub case_sensitive: bool,
    pub file_extensions: Option<Vec<String>>,
    pub max_results: Option<u32>,
    pub context_lines: u32,
}

pub fn search_project_text(
    filesystem: &ProjectFilesystem,
    pattern: &str,
    opts: &SearchOpts,
    config: &EngineConfig,
) -> Result<Vec<TextMatch>, EngineError> {
    let search = TextSearch::new(pattern, opts)?;
    let discovery = DiscoverOpts {
        extensions: opts.file_extensions.clone(),
        ..DiscoverOpts::default()
    };
    let walk = walker::walk_project_with_capability(filesystem, config, &discovery)?;
    search.search_entries(filesystem, &walk.files, config, None)
}

pub fn search_project_text_cancellable(
    filesystem: &ProjectFilesystem,
    pattern: &str,
    opts: &SearchOpts,
    config: &EngineConfig,
    cancel: &CancelToken,
) -> Result<Vec<TextMatch>, EngineError> {
    let search = TextSearch::new(pattern, opts)?;
    let discovery = DiscoverOpts {
        extensions: opts.file_extensions.clone(),
        ..DiscoverOpts::default()
    };
    let walk =
        walker::walk_project_with_capability_cancellable(filesystem, config, &discovery, cancel)?;
    search.search_entries(filesystem, &walk.files, config, Some(cancel))
}

pub fn search_project_entries(
    filesystem: &ProjectFilesystem,
    entries: &[FileEntry],
    pattern: &str,
    opts: &SearchOpts,
    config: &EngineConfig,
) -> Result<Vec<TextMatch>, EngineError> {
    TextSearch::new(pattern, opts)?.search_entries(filesystem, entries, config, None)
}

pub fn search_project_entries_cancellable(
    filesystem: &ProjectFilesystem,
    entries: &[FileEntry],
    pattern: &str,
    opts: &SearchOpts,
    config: &EngineConfig,
    cancel: &CancelToken,
) -> Result<Vec<TextMatch>, EngineError> {
    TextSearch::new(pattern, opts)?.search_entries(filesystem, entries, config, Some(cancel))
}

#[derive(Clone, Copy)]
struct SearchLimits {
    max_results: usize,
    context_lines: u32,
    max_indexed_lines: u32,
    max_retained_line_bytes: usize,
    max_aggregate_bytes: usize,
}

impl SearchLimits {
    fn resolve(pattern: &str, opts: &SearchOpts) -> Result<Self, EngineError> {
        if pattern.len() > MAX_SEARCH_PATTERN_BYTES {
            return Err(search_limit_exceeded(
                PATTERN_RESOURCE,
                MAX_SEARCH_PATTERN_BYTES,
            ));
        }
        if opts.context_lines > MAX_SEARCH_CONTEXT_LINES {
            return Err(search_limit_exceeded(
                CONTEXT_RESOURCE,
                MAX_SEARCH_CONTEXT_LINES as usize,
            ));
        }
        let requested_results = opts.max_results.unwrap_or(DEFAULT_MAX_SEARCH_RESULTS);
        if requested_results > MAX_SEARCH_RESULTS {
            return Err(search_limit_exceeded(
                RESULT_RESOURCE,
                MAX_SEARCH_RESULTS as usize,
            ));
        }

        Ok(Self {
            max_results: usize::try_from(requested_results).unwrap_or(usize::MAX),
            context_lines: opts.context_lines,
            max_indexed_lines: MAX_INDEXED_LINES_PER_FILE,
            max_retained_line_bytes: MAX_RETAINED_LINE_BYTES,
            max_aggregate_bytes: MAX_AGGREGATE_MATCH_BYTES,
        })
    }
}

struct TextSearch<'a> {
    regex: Regex,
    limits: SearchLimits,
    file_extensions: Option<&'a [String]>,
}

impl<'a> TextSearch<'a> {
    fn new(pattern: &str, opts: &'a SearchOpts) -> Result<Self, EngineError> {
        let limits = SearchLimits::resolve(pattern, opts)?;
        Ok(Self {
            regex: build_regex(pattern, opts.case_sensitive)?,
            limits,
            file_extensions: opts.file_extensions.as_deref(),
        })
    }

    fn search_entries(
        &self,
        filesystem: &ProjectFilesystem,
        entries: &[FileEntry],
        config: &EngineConfig,
        cancel: Option<&CancelToken>,
    ) -> Result<Vec<TextMatch>, EngineError> {
        ensure_not_cancelled(cancel)?;
        let mut matches = BoundedTextMatches::new(self.limits);
        for entry in entries {
            ensure_not_cancelled(cancel)?;
            if matches.is_full() {
                break;
            }
            if !matches_extension_filter(&entry.path, self.file_extensions) {
                continue;
            }
            let Ok(project_path) = filesystem.project_path(&entry.path) else {
                continue;
            };
            let Ok(file) = reader::read_project_file(filesystem, &project_path, None, config)
            else {
                continue;
            };
            self.scan_file(&file.path, &file.content, &mut matches, cancel)?;
        }
        ensure_not_cancelled(cancel)?;
        Ok(matches.into_vec())
    }

    fn scan_file(
        &self,
        path: &Path,
        content: &str,
        matches: &mut BoundedTextMatches,
        cancel: Option<&CancelToken>,
    ) -> Result<(), EngineError> {
        let mut window = LineWindow::new(self.limits.context_lines);
        let mut indexed_lines = 0;
        for line in content.lines() {
            ensure_not_cancelled(cancel)?;
            indexed_lines = self.count_indexed_line(indexed_lines)?;
            window.push(line);
            let Some(decided) = self.decided_line_number(indexed_lines) else {
                continue;
            };
            self.emit_match_at(path, &window, decided, matches)?;
            if matches.is_full() {
                return Ok(());
            }
        }
        self.flush_trailing_matches(path, &window, indexed_lines, matches)
    }

    fn count_indexed_line(&self, indexed_lines: u32) -> Result<u32, EngineError> {
        indexed_lines
            .checked_add(1)
            .filter(|count| *count <= self.limits.max_indexed_lines)
            .ok_or_else(|| {
                search_limit_exceeded(
                    INDEXED_LINE_RESOURCE,
                    self.limits.max_indexed_lines as usize,
                )
            })
    }

    fn decided_line_number(&self, indexed_lines: u32) -> Option<u32> {
        indexed_lines
            .checked_sub(self.limits.context_lines)
            .filter(|line_number| *line_number > 0)
    }

    fn flush_trailing_matches(
        &self,
        path: &Path,
        window: &LineWindow<'_>,
        total_lines: u32,
        matches: &mut BoundedTextMatches,
    ) -> Result<(), EngineError> {
        let first_pending = total_lines
            .saturating_sub(self.limits.context_lines)
            .saturating_add(1);
        for line_number in first_pending..=total_lines {
            if matches.is_full() {
                break;
            }
            self.emit_match_at(path, window, line_number, matches)?;
        }
        Ok(())
    }

    fn emit_match_at(
        &self,
        path: &Path,
        window: &LineWindow<'_>,
        line_number: u32,
        matches: &mut BoundedTextMatches,
    ) -> Result<(), EngineError> {
        let Some(candidate) = MatchCandidate::at(window, line_number) else {
            return Ok(());
        };
        if !self.regex.is_match(candidate.line) {
            return Ok(());
        }
        matches.push(path, &candidate)
    }
}

struct LineWindow<'a> {
    lines: VecDeque<&'a str>,
    context_span: usize,
    capacity: usize,
    first_line_number: u32,
}

impl<'a> LineWindow<'a> {
    fn new(context_lines: u32) -> Self {
        let context_span = usize::try_from(context_lines).unwrap_or(usize::MAX);
        let capacity = context_span.saturating_mul(2).saturating_add(1);
        Self {
            lines: VecDeque::with_capacity(capacity),
            context_span,
            capacity,
            first_line_number: 1,
        }
    }

    fn push(&mut self, line: &'a str) {
        if self.lines.len() == self.capacity {
            self.lines.pop_front();
            self.first_line_number = self.first_line_number.saturating_add(1);
        }
        self.lines.push_back(line);
    }

    fn offset_of(&self, line_number: u32) -> Option<usize> {
        let offset = usize::try_from(line_number.checked_sub(self.first_line_number)?).ok()?;
        (offset < self.lines.len()).then_some(offset)
    }

    fn span(&self, start: usize, end: usize) -> impl ExactSizeIterator<Item = &'a str> + '_ {
        self.lines.iter().take(end).skip(start).copied()
    }
}

struct MatchCandidate<'a, 'w> {
    window: &'w LineWindow<'a>,
    line_number: u32,
    offset: usize,
    line: &'a str,
}

impl<'a, 'w> MatchCandidate<'a, 'w> {
    fn at(window: &'w LineWindow<'a>, line_number: u32) -> Option<Self> {
        let offset = window.offset_of(line_number)?;
        let line = window.lines.get(offset).copied()?;
        Some(Self {
            window,
            line_number,
            offset,
            line,
        })
    }

    fn context_before(&self) -> impl ExactSizeIterator<Item = &'a str> + '_ {
        let start = self.offset.saturating_sub(self.window.context_span);
        self.window.span(start, self.offset)
    }

    fn context_after(&self) -> impl ExactSizeIterator<Item = &'a str> + '_ {
        let start = self.offset.saturating_add(1);
        self.window
            .span(start, start.saturating_add(self.window.context_span))
    }

    fn retained_lines(&self) -> impl Iterator<Item = &'a str> + '_ {
        self.context_before()
            .chain(std::iter::once(self.line))
            .chain(self.context_after())
    }
}

struct BoundedTextMatches {
    values: Vec<TextMatch>,
    limits: SearchLimits,
    retained_bytes: usize,
}

impl BoundedTextMatches {
    fn new(limits: SearchLimits) -> Self {
        Self {
            values: Vec::with_capacity(limits.max_results.min(MATERIALIZATION_PREALLOCATION)),
            limits,
            retained_bytes: 0,
        }
    }

    fn is_full(&self) -> bool {
        self.values.len() >= self.limits.max_results
    }

    fn push(&mut self, path: &Path, candidate: &MatchCandidate<'_, '_>) -> Result<(), EngineError> {
        let projected = self
            .retained_bytes
            .saturating_add(self.candidate_bytes(candidate));
        if projected > self.limits.max_aggregate_bytes {
            return Err(search_limit_exceeded(
                AGGREGATE_TEXT_RESOURCE,
                self.limits.max_aggregate_bytes,
            ));
        }

        let materialized = self.materialize(path, candidate);
        self.retained_bytes = projected;
        self.values.push(materialized);
        Ok(())
    }

    fn candidate_bytes(&self, candidate: &MatchCandidate<'_, '_>) -> usize {
        candidate.retained_lines().fold(0, |total, line| {
            total.saturating_add(retained_len(line, self.limits.max_retained_line_bytes))
        })
    }

    fn materialize(&self, path: &Path, candidate: &MatchCandidate<'_, '_>) -> TextMatch {
        #[cfg(test)]
        record_constructed_match();
        let max_bytes = self.limits.max_retained_line_bytes;
        TextMatch {
            path: path.to_path_buf(),
            line_number: candidate.line_number,
            line_content: retained_line(candidate.line, max_bytes),
            context_before: candidate
                .context_before()
                .map(|line| retained_line(line, max_bytes))
                .collect(),
            context_after: candidate
                .context_after()
                .map(|line| retained_line(line, max_bytes))
                .collect(),
        }
    }

    fn into_vec(self) -> Vec<TextMatch> {
        self.values
    }
}

fn search_limit_exceeded(resource: &'static str, limit: usize) -> EngineError {
    EngineError::SearchLimitExceeded { resource, limit }
}

fn ensure_not_cancelled(cancel: Option<&CancelToken>) -> Result<(), EngineError> {
    if cancel.is_some_and(CancelToken::is_cancelled) {
        return Err(EngineError::Cancelled);
    }
    Ok(())
}

fn build_regex(pattern: &str, case_sensitive: bool) -> Result<Regex, EngineError> {
    let builder = regex::RegexBuilder::new(pattern)
        .case_insensitive(!case_sensitive)
        .build();

    builder.map_err(|source| EngineError::InvalidPattern {
        pattern: pattern.to_string(),
        source,
    })
}

fn matches_extension_filter(path: &Path, filter: Option<&[String]>) -> bool {
    let Some(extensions) = filter else {
        return true;
    };

    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extensions.iter().any(|allowed| allowed == extension))
}

fn retained_len(line: &str, max_bytes: usize) -> usize {
    match truncation_end(line, max_bytes) {
        Some(end) => end.saturating_add(TRUNCATION_MARKER.len()),
        None => line.len(),
    }
}

fn retained_line(line: &str, max_bytes: usize) -> String {
    let Some(end) = truncation_end(line, max_bytes) else {
        return line.to_string();
    };

    let mut retained = String::with_capacity(end.saturating_add(TRUNCATION_MARKER.len()));
    retained.push_str(&line[..end]);
    retained.push_str(TRUNCATION_MARKER);
    retained
}

fn truncation_end(line: &str, max_bytes: usize) -> Option<usize> {
    if line.len() <= max_bytes {
        return None;
    }

    let mut end = max_bytes.saturating_sub(TRUNCATION_MARKER.len());
    while end > 0 && !line.is_char_boundary(end) {
        end -= 1;
    }
    Some(end)
}

#[cfg(test)]
thread_local! {
    static CONSTRUCTED_MATCHES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn record_constructed_match() {
    CONSTRUCTED_MATCHES.with(|constructed| constructed.set(constructed.get() + 1));
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::domain::ProjectRoot;
    use std::fs;
    use tempfile::TempDir;

    fn default_config() -> EngineConfig {
        EngineConfig::default()
    }

    fn snapshot_config() -> EngineConfig {
        EngineConfig {
            discovery_source: crate::config::schema::DiscoverySource::UntrustedSnapshot,
            ..EngineConfig::default()
        }
    }

    fn open_filesystem(root: &Path) -> ProjectFilesystem {
        ProjectFilesystem::open(ProjectRoot::open(root).unwrap()).unwrap()
    }

    fn entry(path: &Path) -> FileEntry {
        FileEntry {
            relative_path: path.file_name().unwrap().to_string_lossy().into_owned(),
            size_bytes: fs::metadata(path)
                .map(|metadata| metadata.len())
                .unwrap_or_default(),
            path: path.to_path_buf(),
            language: None,
        }
    }

    fn search_text(
        root: &Path,
        pattern: &str,
        options: &SearchOpts,
        config: &EngineConfig,
    ) -> Result<Vec<TextMatch>, EngineError> {
        search_project_text(&open_filesystem(root), pattern, options, config)
    }

    #[test]
    fn finds_simple_pattern() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("test.rs"), "fn hello() {}\nfn world() {}").unwrap();

        let results = search_text(
            dir.path(),
            "hello",
            &SearchOpts::default(),
            &default_config(),
        )
        .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].line_number, 1);
        assert!(results[0].line_content.contains("hello"));
    }

    #[test]
    fn finds_regex_pattern() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("test.rs"),
            "fn hello() {}\nfn world() {}\nfn help() {}",
        )
        .unwrap();

        let results = search_text(
            dir.path(),
            r"fn hel\w+",
            &SearchOpts::default(),
            &default_config(),
        )
        .unwrap();

        assert_eq!(results.len(), 2);
    }

    #[test]
    fn returns_context_lines() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("test.rs"),
            "line 1\nline 2\nTARGET\nline 4\nline 5",
        )
        .unwrap();

        let opts = SearchOpts {
            context_lines: 1,
            ..Default::default()
        };
        let results = search_text(dir.path(), "TARGET", &opts, &default_config()).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].context_before, vec!["line 2"]);
        assert_eq!(results[0].context_after, vec!["line 4"]);
    }

    #[test]
    fn case_insensitive_by_default() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("test.rs"), "Hello World").unwrap();

        let results = search_text(
            dir.path(),
            "hello",
            &SearchOpts::default(),
            &default_config(),
        )
        .unwrap();

        assert_eq!(results.len(), 1);
    }

    #[test]
    fn case_sensitive_when_specified() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("test.rs"), "Hello World").unwrap();

        let opts = SearchOpts {
            case_sensitive: true,
            ..Default::default()
        };
        let results = search_text(dir.path(), "hello", &opts, &default_config()).unwrap();

        assert_eq!(results.len(), 0);
    }

    #[test]
    fn filters_by_extension() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("test.rs"), "match me").unwrap();
        fs::write(dir.path().join("test.py"), "match me").unwrap();

        let opts = SearchOpts {
            file_extensions: Some(vec!["rs".into()]),
            ..Default::default()
        };
        let results = search_text(dir.path(), "match", &opts, &default_config()).unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].path.to_string_lossy().ends_with(".rs"));
    }

    #[test]
    fn respects_max_results() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("test.rs"),
            "match\nmatch\nmatch\nmatch\nmatch",
        )
        .unwrap();

        let opts = SearchOpts {
            max_results: Some(2),
            ..Default::default()
        };
        let results = search_text(dir.path(), "match", &opts, &default_config()).unwrap();

        assert!(results.len() <= 2);
    }

    #[test]
    fn returns_error_for_invalid_regex() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("test.rs"), "content").unwrap();

        let result = search_text(
            dir.path(),
            "[invalid",
            &SearchOpts::default(),
            &default_config(),
        );

        assert!(matches!(result, Err(EngineError::InvalidPattern { .. })));
    }

    #[test]
    fn skips_unignored_environment_files() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".env"), "API_TOKEN=needle").unwrap();
        fs::write(dir.path().join("included.txt"), "needle").unwrap();

        let results = search_text(
            dir.path(),
            "needle",
            &SearchOpts::default(),
            &default_config(),
        )
        .unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].path.ends_with("included.txt"));
    }

    #[test]
    fn honors_repository_exclude_file() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join(".git/info")).unwrap();
        fs::write(dir.path().join(".git/info/exclude"), "ignored.txt\n").unwrap();
        fs::write(dir.path().join("ignored.txt"), "needle").unwrap();
        fs::write(dir.path().join("included.txt"), "needle").unwrap();

        let results = search_text(
            dir.path(),
            "needle",
            &SearchOpts::default(),
            &default_config(),
        )
        .unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].path.ends_with("included.txt"));
    }

    #[test]
    fn non_utf8_file_does_not_abort_the_search() {
        let dir = TempDir::new().unwrap();
        let mut weird = b"prefix ".to_vec();
        weird.extend_from_slice(&[0xFF, 0xFE]);
        weird.extend_from_slice(b" needle suffix");
        fs::write(dir.path().join("weird.txt"), &weird).unwrap();
        fs::write(dir.path().join("clean.txt"), "a needle here").unwrap();

        let results = search_text(
            dir.path(),
            "needle",
            &SearchOpts::default(),
            &default_config(),
        )
        .unwrap();

        assert_eq!(results.len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn skips_symlinks_leaving_the_project() {
        let outside = TempDir::new().unwrap();
        let secret = outside.path().join("secret.txt");
        fs::write(&secret, "needle outside the project").unwrap();

        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("inside.txt"), "needle inside").unwrap();
        std::os::unix::fs::symlink(&secret, dir.path().join("linked.txt")).unwrap();

        let results = search_text(
            dir.path(),
            "needle",
            &SearchOpts::default(),
            &default_config(),
        )
        .unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].path.ends_with("inside.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn searches_symlinks_resolving_inside_the_project() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("target.txt"), "needle").unwrap();
        std::os::unix::fs::symlink(dir.path().join("target.txt"), dir.path().join("alias.txt"))
            .unwrap();

        let results = search_text(
            dir.path(),
            "needle",
            &SearchOpts::default(),
            &default_config(),
        )
        .unwrap();

        assert_eq!(results.len(), 2);
    }

    const REPETITIVE_MATCH_LINES: usize = 50_000;
    const WIDE_CONTEXT_LINES: u32 = 20;
    const BOUNDED_RESULT_LIMIT: u32 = 4;

    fn repetitive_project() -> TempDir {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("repetitive.txt"),
            "needle\n".repeat(REPETITIVE_MATCH_LINES),
        )
        .unwrap();
        dir
    }

    fn constructed_matches_while<T>(search: impl FnOnce() -> T) -> (T, usize) {
        CONSTRUCTED_MATCHES.with(|constructed| constructed.set(0));
        let results = search();
        (results, CONSTRUCTED_MATCHES.with(std::cell::Cell::get))
    }

    #[test]
    fn applies_the_result_limit_before_building_matches() {
        let dir = repetitive_project();
        let opts = SearchOpts {
            max_results: Some(BOUNDED_RESULT_LIMIT),
            context_lines: WIDE_CONTEXT_LINES,
            ..Default::default()
        };

        let (results, constructed) = constructed_matches_while(|| {
            search_text(dir.path(), "needle", &opts, &default_config()).unwrap()
        });

        assert_eq!(results.len(), BOUNDED_RESULT_LIMIT as usize);
        assert_eq!(
            constructed, BOUNDED_RESULT_LIMIT as usize,
            "{REPETITIVE_MATCH_LINES} matching lines built {constructed} matches for a limit of \
         {BOUNDED_RESULT_LIMIT}; the limit is applied after the matches are built"
        );
        let cloned_lines: usize = results
            .iter()
            .map(|text_match| text_match.context_before.len() + text_match.context_after.len() + 1)
            .sum();
        let window = 2 * WIDE_CONTEXT_LINES as usize + 1;
        assert!(
            cloned_lines <= results.len() * window,
            "cloned {cloned_lines} lines for {} matches",
            results.len()
        );
    }

    #[test]
    fn builds_every_match_that_fits_the_result_limit() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("small.txt"), "needle\nneedle\nother\n").unwrap();

        let (results, constructed) = constructed_matches_while(|| {
            search_text(
                dir.path(),
                "needle",
                &SearchOpts::default(),
                &default_config(),
            )
            .unwrap()
        });

        assert_eq!(results.len(), 2);
        assert_eq!(constructed, 2);
    }

    #[test]
    fn inventory_search_does_not_rewalk_new_files() {
        let directory = TempDir::new().unwrap();
        fs::write(directory.path().join("indexed.rs"), "needle\n").unwrap();
        let config = default_config();
        let inventory = crate::engine::ProjectInventory::build(directory.path(), &config).unwrap();
        fs::write(directory.path().join("late.rs"), "needle\n").unwrap();

        let results = search_project_entries(
            inventory.filesystem(),
            inventory.files(),
            "needle",
            &SearchOpts::default(),
            &config,
        )
        .unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].path.ends_with("indexed.rs"));
    }

    #[test]
    fn an_untrusted_snapshot_searches_files_its_own_ignore_files_name() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("hidden.rs"), "needle\n").unwrap();
        fs::write(dir.path().join(".ignore"), "hidden.rs\n").unwrap();

        let local = search_text(
            dir.path(),
            "needle",
            &SearchOpts::default(),
            &default_config(),
        )
        .unwrap();
        let snapshot = search_text(
            dir.path(),
            "needle",
            &SearchOpts::default(),
            &snapshot_config(),
        )
        .unwrap();

        assert!(
            local.is_empty(),
            "a local scan still honors repository ignore files"
        );
        assert_eq!(
            snapshot.len(),
            1,
            "search must reach files an untrusted snapshot tried to hide"
        );
    }

    #[test]
    fn stops_walking_once_the_result_limit_is_reached() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("a.txt"), "needle\n").unwrap();
        fs::write(dir.path().join("b.txt"), "needle\n").unwrap();
        let opts = SearchOpts {
            max_results: Some(1),
            ..Default::default()
        };

        let (results, constructed) = constructed_matches_while(|| {
            search_text(dir.path(), "needle", &opts, &default_config()).unwrap()
        });

        assert_eq!(results.len(), 1);
        assert_eq!(
            constructed, 1,
            "the walk must stop at the limit instead of reading the remaining files"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_file_named_outside_the_project_path_grammar_is_skipped() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("plain.txt"), "needle\n").unwrap();
        fs::write(dir.path().join("odd:name.txt"), "needle\n").unwrap();

        let results = search_text(
            dir.path(),
            "needle",
            &SearchOpts::default(),
            &default_config(),
        )
        .unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].path.ends_with("plain.txt"));
    }

    #[test]
    fn a_file_that_cannot_be_read_is_skipped() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("small.txt"), "needle\n").unwrap();
        fs::write(dir.path().join("large.txt"), "needle\n".repeat(20)).unwrap();
        let config = EngineConfig {
            max_file_size_bytes: 32,
            ..EngineConfig::default()
        };

        let results = search_text(dir.path(), "needle", &SearchOpts::default(), &config).unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].path.ends_with("small.txt"));
    }

    #[test]
    fn entry_search_stops_at_the_result_limit() {
        let dir = TempDir::new().unwrap();
        let first = dir.path().join("first.txt");
        let second = dir.path().join("second.txt");
        fs::write(&first, "needle\n").unwrap();
        fs::write(&second, "needle\n").unwrap();
        let filesystem = open_filesystem(dir.path());
        let entries = [entry(&first), entry(&second)];
        let opts = SearchOpts {
            max_results: Some(1),
            ..Default::default()
        };

        let (results, constructed) = constructed_matches_while(|| {
            search_project_entries(&filesystem, &entries, "needle", &opts, &default_config())
                .unwrap()
        });

        assert_eq!(results.len(), 1);
        assert_eq!(
            constructed, 1,
            "the entry search must stop at the limit instead of reading the remaining entries"
        );
    }

    #[test]
    fn entry_search_filters_by_extension() {
        let dir = TempDir::new().unwrap();
        let notes = dir.path().join("notes.md");
        let source = dir.path().join("app.rs");
        fs::write(&notes, "needle\n").unwrap();
        fs::write(&source, "needle\n").unwrap();
        let filesystem = open_filesystem(dir.path());
        let entries = [entry(&notes), entry(&source)];
        let opts = SearchOpts {
            file_extensions: Some(vec!["rs".to_string()]),
            ..Default::default()
        };

        let results =
            search_project_entries(&filesystem, &entries, "needle", &opts, &default_config())
                .unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].path.ends_with("app.rs"));
    }

    #[test]
    fn emitting_a_line_outside_the_window_is_a_no_op() {
        let opts = SearchOpts::default();
        let search = TextSearch::new("needle", &opts).unwrap();
        let mut window = LineWindow::new(0);
        window.push("needle");
        let mut matches = BoundedTextMatches::new(search.limits);

        search
            .emit_match_at(Path::new("source.rs"), &window, 2, &mut matches)
            .unwrap();

        assert!(matches.into_vec().is_empty());
    }

    #[test]
    fn entry_search_skips_entries_outside_the_project() {
        let outside = TempDir::new().unwrap();
        let secret = outside.path().join("secret.txt");
        fs::write(&secret, "needle\n").unwrap();
        let dir = TempDir::new().unwrap();
        let inside = dir.path().join("inside.txt");
        fs::write(&inside, "needle\n").unwrap();
        let filesystem = open_filesystem(dir.path());
        let entries = [entry(&secret), entry(&inside)];

        let results = search_project_entries(
            &filesystem,
            &entries,
            "needle",
            &SearchOpts::default(),
            &default_config(),
        )
        .unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].path.ends_with("inside.txt"));
    }

    #[test]
    fn entry_search_skips_entries_whose_file_disappeared() {
        let dir = TempDir::new().unwrap();
        let kept = dir.path().join("kept.txt");
        let removed = dir.path().join("removed.txt");
        fs::write(&kept, "needle\n").unwrap();
        fs::write(&removed, "needle\n").unwrap();
        let filesystem = open_filesystem(dir.path());
        let entries = [entry(&removed), entry(&kept)];
        fs::remove_file(&removed).unwrap();

        let results = search_project_entries(
            &filesystem,
            &entries,
            "needle",
            &SearchOpts::default(),
            &default_config(),
        )
        .unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].path.ends_with("kept.txt"));
    }

    const SNOWMAN: char = '☃';

    fn config_with_file_size(max_file_size_bytes: u64) -> EngineConfig {
        EngineConfig {
            max_file_size_bytes,
            ..EngineConfig::default()
        }
    }

    fn limit_error(result: Result<Vec<TextMatch>, EngineError>) -> (&'static str, usize) {
        match result {
            Err(EngineError::SearchLimitExceeded { resource, limit }) => (resource, limit),
            other => panic!("expected a search limit error, got {other:?}"),
        }
    }

    fn line_dense_content(lines: u32) -> String {
        let mut content = String::from("needle\n");
        content.push_str(&"\n".repeat(lines.saturating_sub(1) as usize));
        content
    }

    fn matching_line(bytes: usize) -> String {
        let mut line = String::from("needle");
        line.push_str(&"x".repeat(bytes.saturating_sub(line.len())));
        line.push('\n');
        line
    }

    fn write_wide_lines(root: &Path, name: &str, lines: usize) {
        fs::write(
            root.join(name),
            matching_line(MAX_RETAINED_LINE_BYTES).repeat(lines),
        )
        .unwrap();
    }

    fn located(results: &[TextMatch]) -> Vec<(String, u32)> {
        results
            .iter()
            .map(|text_match| {
                let name = text_match
                    .path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_default();
                (name, text_match.line_number)
            })
            .collect()
    }

    #[test]
    fn a_file_denser_than_the_indexed_line_limit_is_rejected() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("dense.txt"),
            line_dense_content(MAX_INDEXED_LINES_PER_FILE + 1),
        )
        .unwrap();

        let result = search_text(
            dir.path(),
            "needle",
            &SearchOpts::default(),
            &default_config(),
        );

        assert_eq!(
            limit_error(result),
            (INDEXED_LINE_RESOURCE, MAX_INDEXED_LINES_PER_FILE as usize)
        );
    }

    #[test]
    fn a_file_at_the_indexed_line_limit_is_searched() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("dense.txt"),
            line_dense_content(MAX_INDEXED_LINES_PER_FILE),
        )
        .unwrap();

        let results = search_text(
            dir.path(),
            "needle",
            &SearchOpts::default(),
            &default_config(),
        )
        .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].line_number, 1);
    }

    #[test]
    fn a_rejected_file_leaves_no_partial_results() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("a.txt"), "needle\n").unwrap();
        fs::write(
            dir.path().join("b.txt"),
            line_dense_content(MAX_INDEXED_LINES_PER_FILE + 1),
        )
        .unwrap();

        let result = search_text(
            dir.path(),
            "needle",
            &SearchOpts::default(),
            &default_config(),
        );

        assert_eq!(
            limit_error(result),
            (INDEXED_LINE_RESOURCE, MAX_INDEXED_LINES_PER_FILE as usize),
            "the match found before the dense file must not survive as a partial result"
        );
    }

    #[test]
    fn a_line_at_the_retention_limit_is_kept_whole() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("wide.txt"),
            matching_line(MAX_RETAINED_LINE_BYTES),
        )
        .unwrap();

        let results = search_text(
            dir.path(),
            "needle",
            &SearchOpts::default(),
            &default_config(),
        )
        .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].line_content.len(), MAX_RETAINED_LINE_BYTES);
        assert!(!results[0].line_content.ends_with(TRUNCATION_MARKER));
    }

    #[test]
    fn a_line_over_the_retention_limit_is_truncated_with_a_visible_marker() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("wide.txt"),
            matching_line(MAX_RETAINED_LINE_BYTES + 1),
        )
        .unwrap();

        let results = search_text(
            dir.path(),
            "needle",
            &SearchOpts::default(),
            &default_config(),
        )
        .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].line_content.len(), MAX_RETAINED_LINE_BYTES);
        assert!(results[0].line_content.starts_with("needle"));
        assert!(results[0].line_content.ends_with(TRUNCATION_MARKER));
    }

    #[test]
    fn context_lines_over_the_retention_limit_are_truncated() {
        let dir = TempDir::new().unwrap();
        let mut content = "x".repeat(MAX_RETAINED_LINE_BYTES + 1);
        content.push_str("\nneedle\n");
        fs::write(dir.path().join("wide.txt"), content).unwrap();
        let opts = SearchOpts {
            context_lines: 1,
            ..Default::default()
        };

        let results = search_text(dir.path(), "needle", &opts, &default_config()).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].context_before.len(), 1);
        assert_eq!(results[0].context_before[0].len(), MAX_RETAINED_LINE_BYTES);
        assert!(results[0].context_before[0].ends_with(TRUNCATION_MARKER));
    }

    #[test]
    fn truncation_keeps_utf8_characters_whole() {
        let dir = TempDir::new().unwrap();
        let snowmen = MAX_RETAINED_LINE_BYTES / SNOWMAN.len_utf8() + 100;
        fs::write(
            dir.path().join("utf8.txt"),
            format!("{}\n", SNOWMAN.to_string().repeat(snowmen)),
        )
        .unwrap();

        let results = search_text(
            dir.path(),
            &SNOWMAN.to_string(),
            &SearchOpts::default(),
            &default_config(),
        )
        .unwrap();

        assert_eq!(results.len(), 1);
        let content = &results[0].line_content;
        let kept = content.strip_suffix(TRUNCATION_MARKER).unwrap();
        let budget = MAX_RETAINED_LINE_BYTES - TRUNCATION_MARKER.len();
        assert!(content.len() <= MAX_RETAINED_LINE_BYTES);
        assert!(kept.chars().all(|character| character == SNOWMAN));
        assert_eq!(kept.len(), budget - budget % SNOWMAN.len_utf8());
    }

    #[test]
    fn a_result_set_at_the_aggregate_text_budget_is_returned() {
        let dir = TempDir::new().unwrap();
        let lines_per_file = MAX_AGGREGATE_MATCH_BYTES / MAX_RETAINED_LINE_BYTES / 2;
        write_wide_lines(dir.path(), "a.txt", lines_per_file);
        write_wide_lines(dir.path(), "b.txt", lines_per_file);

        let results = search_text(
            dir.path(),
            "needle",
            &SearchOpts::default(),
            &config_with_file_size(4 * 1024 * 1024),
        )
        .unwrap();

        assert_eq!(results.len(), lines_per_file * 2);
        assert_eq!(
            results
                .iter()
                .map(|text_match| text_match.line_content.len())
                .sum::<usize>(),
            MAX_AGGREGATE_MATCH_BYTES
        );
    }

    #[test]
    fn a_result_set_over_the_aggregate_text_budget_is_rejected() {
        let dir = TempDir::new().unwrap();
        let lines_per_file = MAX_AGGREGATE_MATCH_BYTES / MAX_RETAINED_LINE_BYTES / 2 + 1;
        write_wide_lines(dir.path(), "a.txt", lines_per_file);
        write_wide_lines(dir.path(), "b.txt", lines_per_file);

        let result = search_text(
            dir.path(),
            "needle",
            &SearchOpts::default(),
            &config_with_file_size(4 * 1024 * 1024),
        );

        assert_eq!(
            limit_error(result),
            (AGGREGATE_TEXT_RESOURCE, MAX_AGGREGATE_MATCH_BYTES)
        );
    }

    #[test]
    fn a_context_request_over_the_limit_is_rejected() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("a.txt"), "needle\n").unwrap();
        let opts = SearchOpts {
            context_lines: MAX_SEARCH_CONTEXT_LINES + 1,
            ..Default::default()
        };

        let result = search_text(dir.path(), "needle", &opts, &default_config());

        assert_eq!(
            limit_error(result),
            (CONTEXT_RESOURCE, MAX_SEARCH_CONTEXT_LINES as usize)
        );
    }

    #[test]
    fn the_widest_allowed_context_is_returned_in_full() {
        let dir = TempDir::new().unwrap();
        let padding = MAX_SEARCH_CONTEXT_LINES as usize + 10;
        fs::write(
            dir.path().join("a.txt"),
            format!(
                "{}needle\n{}",
                "before\n".repeat(padding),
                "after\n".repeat(padding)
            ),
        )
        .unwrap();
        let opts = SearchOpts {
            context_lines: MAX_SEARCH_CONTEXT_LINES,
            ..Default::default()
        };

        let results = search_text(dir.path(), "needle", &opts, &default_config()).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].line_number, padding as u32 + 1);
        assert_eq!(
            results[0].context_before.len(),
            MAX_SEARCH_CONTEXT_LINES as usize
        );
        assert_eq!(
            results[0].context_after.len(),
            MAX_SEARCH_CONTEXT_LINES as usize
        );
        assert!(
            results[0]
                .context_before
                .iter()
                .all(|line| line == "before")
        );
        assert!(results[0].context_after.iter().all(|line| line == "after"));
    }

    #[test]
    fn a_result_request_over_the_limit_is_rejected() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("a.txt"), "needle\n").unwrap();
        let opts = SearchOpts {
            max_results: Some(MAX_SEARCH_RESULTS + 1),
            ..Default::default()
        };

        let result = search_text(dir.path(), "needle", &opts, &default_config());

        assert_eq!(
            limit_error(result),
            (RESULT_RESOURCE, MAX_SEARCH_RESULTS as usize)
        );
    }

    #[test]
    fn the_largest_allowed_result_request_is_accepted() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("a.txt"), "needle\n".repeat(3)).unwrap();
        let opts = SearchOpts {
            max_results: Some(MAX_SEARCH_RESULTS),
            ..Default::default()
        };

        let results = search_text(dir.path(), "needle", &opts, &default_config()).unwrap();

        assert_eq!(results.len(), 3);
    }

    #[test]
    fn an_oversized_pattern_is_rejected_without_echoing_it() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("a.txt"), "needle\n").unwrap();
        let pattern = "a".repeat(MAX_SEARCH_PATTERN_BYTES + 1);

        let error = search_text(
            dir.path(),
            &pattern,
            &SearchOpts::default(),
            &default_config(),
        )
        .unwrap_err();
        let message = error.to_string();

        assert_eq!(
            limit_error(Err(error)),
            (PATTERN_RESOURCE, MAX_SEARCH_PATTERN_BYTES)
        );
        assert!(!message.contains(&pattern));
    }

    #[test]
    fn a_pattern_at_the_size_limit_is_compiled() {
        let dir = TempDir::new().unwrap();
        let pattern = "a".repeat(MAX_SEARCH_PATTERN_BYTES);
        fs::write(dir.path().join("a.txt"), format!("{pattern}\n")).unwrap();

        let results = search_text(
            dir.path(),
            &pattern,
            &SearchOpts::default(),
            &default_config(),
        )
        .unwrap();

        assert_eq!(results.len(), 1);
    }

    #[test]
    fn matches_are_ordered_by_path_then_line() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("c.txt"), "needle\n").unwrap();
        fs::write(dir.path().join("a.txt"), "needle\nfiller\nneedle\n").unwrap();
        fs::write(dir.path().join("b.txt"), "needle\n").unwrap();

        let first = search_text(
            dir.path(),
            "needle",
            &SearchOpts::default(),
            &default_config(),
        )
        .unwrap();
        let second = search_text(
            dir.path(),
            "needle",
            &SearchOpts::default(),
            &default_config(),
        )
        .unwrap();

        assert_eq!(
            located(&first),
            vec![
                ("a.txt".to_string(), 1),
                ("a.txt".to_string(), 3),
                ("b.txt".to_string(), 1),
                ("c.txt".to_string(), 1),
            ]
        );
        assert_eq!(located(&first), located(&second));
    }

    #[test]
    fn binary_files_are_left_out_of_the_bounded_walk() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("data.bin"), b"needle\0binary").unwrap();
        fs::write(dir.path().join("text.txt"), "needle\n").unwrap();

        let results = search_text(
            dir.path(),
            "needle",
            &SearchOpts::default(),
            &default_config(),
        )
        .unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].path.ends_with("text.txt"));
    }

    #[test]
    fn files_without_any_matchable_line_produce_no_matches() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("empty.txt"), "").unwrap();
        fs::write(dir.path().join("blank.txt"), "\n").unwrap();
        let opts = SearchOpts {
            context_lines: 3,
            ..Default::default()
        };

        let results = search_text(dir.path(), "needle", &opts, &default_config()).unwrap();

        assert!(results.is_empty());
    }

    #[test]
    fn context_wider_than_the_file_returns_every_neighbouring_line() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("small.txt"), "first\nneedle\nlast\n").unwrap();
        let opts = SearchOpts {
            context_lines: MAX_SEARCH_CONTEXT_LINES,
            ..Default::default()
        };

        let results = search_text(dir.path(), "needle", &opts, &default_config()).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].line_number, 2);
        assert_eq!(results[0].context_before, vec!["first".to_string()]);
        assert_eq!(results[0].context_after, vec!["last".to_string()]);
    }

    #[test]
    fn a_final_line_without_a_newline_keeps_its_context() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("tail.txt"), "one\ntwo\nthree\nneedle").unwrap();
        let opts = SearchOpts {
            context_lines: 2,
            ..Default::default()
        };

        let results = search_text(dir.path(), "needle", &opts, &default_config()).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].line_number, 4);
        assert_eq!(
            results[0].context_before,
            vec!["two".to_string(), "three".to_string()]
        );
        assert!(results[0].context_after.is_empty());
    }

    #[test]
    fn the_result_limit_stops_the_trailing_flush() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("tail.txt"),
            "pad\npad\npad\nneedle\nneedle\n",
        )
        .unwrap();
        let opts = SearchOpts {
            max_results: Some(1),
            context_lines: 2,
            ..Default::default()
        };

        let (results, constructed) = constructed_matches_while(|| {
            search_text(dir.path(), "needle", &opts, &default_config()).unwrap()
        });

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].line_number, 4);
        assert_eq!(
            constructed, 1,
            "the trailing flush must stop at the result limit"
        );
    }

    #[test]
    fn the_aggregate_text_budget_counts_retained_context() {
        let dir = TempDir::new().unwrap();
        let filler = "f".repeat(60 * 1024);
        let mut content = String::new();
        for _ in 0..20 {
            content.push_str(&filler);
            content.push_str("\nneedle\n");
        }
        content.push_str(&filler);
        content.push('\n');
        fs::write(dir.path().join("padded.txt"), content).unwrap();
        let config = config_with_file_size(4 * 1024 * 1024);
        let opts = SearchOpts {
            context_lines: 1,
            ..Default::default()
        };

        let matched_lines_only =
            search_text(dir.path(), "needle", &SearchOpts::default(), &config).unwrap();
        let with_context = search_text(dir.path(), "needle", &opts, &config);

        assert_eq!(matched_lines_only.len(), 20);
        assert_eq!(
            limit_error(with_context),
            (AGGREGATE_TEXT_RESOURCE, MAX_AGGREGATE_MATCH_BYTES),
            "context lines must be charged against the aggregate budget"
        );
    }

    #[test]
    fn the_match_that_breaks_the_aggregate_budget_is_never_materialized() {
        let dir = TempDir::new().unwrap();
        let affordable_matches = MAX_AGGREGATE_MATCH_BYTES / MAX_RETAINED_LINE_BYTES;
        write_wide_lines(dir.path(), "a.txt", affordable_matches / 2 + 1);
        write_wide_lines(dir.path(), "b.txt", affordable_matches / 2 + 1);

        let (result, constructed) = constructed_matches_while(|| {
            search_text(
                dir.path(),
                "needle",
                &SearchOpts::default(),
                &config_with_file_size(4 * 1024 * 1024),
            )
        });

        assert_eq!(
            limit_error(result),
            (AGGREGATE_TEXT_RESOURCE, MAX_AGGREGATE_MATCH_BYTES)
        );
        assert_eq!(
            constructed, affordable_matches,
            "the rejected match must be refused before its text is cloned"
        );
    }
}
