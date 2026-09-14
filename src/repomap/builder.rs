use std::collections::BTreeMap;
#[cfg(test)]
use std::collections::BTreeSet;
use std::path::Path;

use tracing::warn;

use crate::cancel::CancelToken;
use crate::config::EngineConfig;
#[cfg(test)]
use crate::domain::ProjectRoot;
use crate::engine::ast::{self, SignatureKind};
use crate::engine::filesystem::ProjectFilesystem;
use crate::engine::reader;
#[cfg(test)]
use crate::engine::stats;
use crate::engine::stats::ProjectStats;
use crate::engine::walker::FileEntry;
#[cfg(test)]
use crate::engine::walker::{self, DiscoverOpts};
use crate::errors::EngineError;
#[cfg(test)]
use crate::errors::RepoMapError;
use crate::report::limits::BoundedDiagnostics;
use crate::shared::ESTIMATED_CHARS_PER_TOKEN;

use super::{RepoMap, parent_dir};

const ESTIMATED_BYTES_PER_LINE: u64 = 30;
const MAX_HEADER_LANGUAGES: usize = 5;
const NESTED_INDENT: &str = "  ";
const SIGNATURE_INDENT: &str = "  ";
const SIGNATURE_SEPARATOR: &str = " ";
const LINE_BREAK: &str = "\n";
const DIRECTORY_SUFFIX: &str = "/\n";
const FILE_LINE_PREFIX: &str = " (~";
const FILE_LINE_SUFFIX: &str = " lines)\n";
const SIGNATURE_TRUNCATION_MARKER: &str = " ...(truncated)";
const MIN_TRUNCATED_SIGNATURE_BYTES: usize = 8;
const TRUNCATION_NOTICE_RESERVE_BYTES: usize = 192;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn build_repo_map(
    root: &Path,
    engine_config: &EngineConfig,
    token_budget: u32,
    only_paths: Option<&BTreeSet<String>>,
) -> Result<RepoMap, RepoMapError> {
    let canonical_root = root
        .canonicalize()
        .map_err(|e| RepoMapError::BuildFailed(format!("cannot resolve project root: {e}")))?;
    let project_root = ProjectRoot::open(&canonical_root)
        .map_err(|error| RepoMapError::BuildFailed(error.to_string()))?;
    let filesystem = ProjectFilesystem::open(project_root)
        .map_err(|error| RepoMapError::BuildFailed(error.to_string()))?;

    let mut files = walker::walk_project(&canonical_root, engine_config, &DiscoverOpts::default())
        .map_err(|e| RepoMapError::BuildFailed(format!("file discovery failed: {e}")))?;

    if let Some(allow) = only_paths {
        files.retain(|entry| allow.contains(&entry.relative_path));
    }

    if files.is_empty() {
        return Err(RepoMapError::EmptyProject(canonical_root));
    }

    let project_stats = stats::project_stats_with_capability(&filesystem, engine_config)
        .map_err(|e| RepoMapError::BuildFailed(format!("stats failed: {e}")))?;

    Ok(build_repo_map_for_entries(
        &filesystem,
        engine_config,
        token_budget,
        &files,
        &project_stats,
    ))
}

#[cfg(test)]
pub fn build_repo_map_for_entries(
    filesystem: &ProjectFilesystem,
    engine_config: &EngineConfig,
    token_budget: u32,
    files: &[FileEntry],
    stats: &ProjectStats,
) -> RepoMap {
    let project_name = extract_project_name(filesystem.root().as_path());
    render_repo_map(
        &project_name,
        stats,
        files,
        token_budget,
        &mut |file, remaining_bytes| {
            signatures_for_file(filesystem, file, engine_config, remaining_bytes)
        },
    )
}

pub fn build_repo_map_for_entries_cancellable(
    filesystem: &ProjectFilesystem,
    engine_config: &EngineConfig,
    token_budget: u32,
    files: &[FileEntry],
    stats: &ProjectStats,
    cancel: &CancelToken,
) -> Result<RepoMap, EngineError> {
    let project_name = extract_project_name(filesystem.root().as_path());
    render_repo_map_with_cancel(
        &project_name,
        stats,
        files,
        token_budget,
        &mut |file, remaining_bytes| {
            signatures_for_file(filesystem, file, engine_config, remaining_bytes)
        },
        Some(cancel),
    )
}

fn signatures_for_file(
    filesystem: &ProjectFilesystem,
    file: &FileEntry,
    engine_config: &EngineConfig,
    max_retained_bytes: usize,
) -> ast::SignatureBatch {
    let Some(language) = file
        .language
        .as_deref()
        .filter(|language| ast::language_for_name(language).is_some())
    else {
        return ast::SignatureBatch::empty();
    };
    read_and_extract_signatures(
        filesystem,
        &file.path,
        language,
        engine_config,
        max_retained_bytes,
    )
    .unwrap_or_else(ast::SignatureBatch::empty)
}

fn read_and_extract_signatures(
    filesystem: &ProjectFilesystem,
    path: &Path,
    lang: &str,
    engine_config: &EngineConfig,
    max_retained_bytes: usize,
) -> Option<ast::SignatureBatch> {
    let project_path = filesystem.project_path(path).ok()?;
    let content = match reader::read_project_file(filesystem, &project_path, None, engine_config) {
        Ok(fc) => fc.content,
        Err(err) => {
            warn!(path = %path.display(), error = %err, "failed to read file for repo map");
            return None;
        }
    };

    match ast::extract_signatures_with_budget(path, &content, lang, max_retained_bytes) {
        Ok(signatures) => Some(signatures),
        Err(err) => {
            warn!(path = %path.display(), error = %err, "AST signature extraction failed");
            None
        }
    }
}

fn extract_project_name(canonical_root: &Path) -> String {
    canonical_root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("project")
        .to_string()
}

#[cfg(test)]
fn render_repo_map(
    project_name: &str,
    stats: &ProjectStats,
    files: &[FileEntry],
    token_budget: u32,
    signatures_for: &mut dyn FnMut(&FileEntry, usize) -> ast::SignatureBatch,
) -> RepoMap {
    render_repo_map_with_cancel(
        project_name,
        stats,
        files,
        token_budget,
        signatures_for,
        None,
    )
    .expect("an uncancelled repository-map render cannot be cancelled")
}

fn render_repo_map_with_cancel(
    project_name: &str,
    stats: &ProjectStats,
    files: &[FileEntry],
    token_budget: u32,
    signatures_for: &mut dyn FnMut(&FileEntry, usize) -> ast::SignatureBatch,
    cancel: Option<&CancelToken>,
) -> Result<RepoMap, EngineError> {
    ensure_not_cancelled(cancel)?;
    let ceiling = budget_bytes(token_budget);
    let header = format_header(project_name, stats);
    let reserved = header
        .len()
        .saturating_add(rendered_listing_bytes(files))
        .saturating_add(TRUNCATION_NOTICE_RESERVE_BYTES);
    let signature_ceiling = ceiling.saturating_sub(reserved);
    let signatures =
        extract_all_signatures_with_cancel(files, signature_ceiling, signatures_for, cancel)?;

    let mut render = RepoMapRender::new(ceiling, signatures.detail);
    render.append_header(&header);
    for file in files {
        ensure_not_cancelled(cancel)?;
        let file_signatures = signatures
            .by_path
            .get(file.relative_path.as_str())
            .map(Vec::as_slice);
        render.append_file(file, file_signatures);
    }

    ensure_not_cancelled(cancel)?;
    Ok(render.finish(files.len()))
}

fn format_header(project_name: &str, stats: &ProjectStats) -> String {
    let lang_summary: Vec<String> = stats
        .languages
        .iter()
        .take(MAX_HEADER_LANGUAGES)
        .map(|l| format!("{} {}%", l.name, percentage(l.code, stats.total_code_lines)))
        .collect();

    format!(
        "Project: {project_name} ({})\nFiles: {} | Code: {} lines | Comments: {} lines\n\n",
        lang_summary.join(", "),
        stats.total_files,
        stats.total_code_lines,
        stats.total_comment_lines,
    )
}

struct MappedSignature {
    kind_label: &'static str,
    text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignatureDetail {
    Complete,
    Truncated,
    Unbudgeted,
}

impl SignatureDetail {
    fn label(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Truncated => "truncated",
            Self::Unbudgeted => "unbudgeted",
        }
    }
}

struct SignatureIndex<'a> {
    by_path: BTreeMap<&'a str, Vec<MappedSignature>>,
    detail: SignatureDetail,
}

#[cfg(test)]
fn extract_all_signatures<'a>(
    files: &'a [FileEntry],
    ceiling_bytes: usize,
    signatures_for: &mut dyn FnMut(&FileEntry, usize) -> ast::SignatureBatch,
) -> SignatureIndex<'a> {
    extract_all_signatures_with_cancel(files, ceiling_bytes, signatures_for, None)
        .expect("an uncancelled signature pass cannot be cancelled")
}

fn extract_all_signatures_with_cancel<'a>(
    files: &'a [FileEntry],
    ceiling_bytes: usize,
    signatures_for: &mut dyn FnMut(&FileEntry, usize) -> ast::SignatureBatch,
    cancel: Option<&CancelToken>,
) -> Result<SignatureIndex<'a>, EngineError> {
    ensure_not_cancelled(cancel)?;
    let mut index = SignatureIndex {
        by_path: BTreeMap::new(),
        detail: SignatureDetail::Complete,
    };
    if ceiling_bytes == 0 {
        if !files.is_empty() {
            index.detail = SignatureDetail::Unbudgeted;
        }
        return Ok(index);
    }

    let mut budget = SignatureBudget::new(ceiling_bytes);
    for file in files {
        ensure_not_cancelled(cancel)?;
        let indent_bytes = indent_for(&file.relative_path).len();
        let batch = signatures_for(file, budget.remaining());
        let complete = batch.complete;
        let (kept, truncated) = budget.retain(indent_bytes, batch.signatures);
        if !kept.is_empty() {
            index.by_path.insert(file.relative_path.as_str(), kept);
        }
        if truncated || !complete {
            index.detail = SignatureDetail::Truncated;
            break;
        }
    }

    ensure_not_cancelled(cancel)?;
    Ok(index)
}

fn ensure_not_cancelled(cancel: Option<&CancelToken>) -> Result<(), EngineError> {
    if cancel.is_some_and(CancelToken::is_cancelled) {
        return Err(EngineError::Cancelled);
    }
    Ok(())
}

struct SignatureBudget {
    ceiling_bytes: usize,
    retained_bytes: usize,
}

impl SignatureBudget {
    fn new(ceiling_bytes: usize) -> Self {
        Self {
            ceiling_bytes,
            retained_bytes: 0,
        }
    }

    fn remaining(&self) -> usize {
        self.ceiling_bytes.saturating_sub(self.retained_bytes)
    }

    fn retain(
        &mut self,
        indent_bytes: usize,
        signatures: Vec<ast::RepoMapSignature>,
    ) -> (Vec<MappedSignature>, bool) {
        let mut kept = Vec::new();

        for signature in signatures {
            let kind_label = format_kind(&signature.kind);
            let cost = signature_line_bytes(indent_bytes, kind_label, signature.text.len());
            let projected = self.retained_bytes.saturating_add(cost);
            if projected > self.ceiling_bytes {
                let available = self.ceiling_bytes.saturating_sub(self.retained_bytes);
                if let Some(truncated) =
                    truncated_signature(kind_label, signature.text, indent_bytes, available)
                {
                    self.retained_bytes = self.retained_bytes.saturating_add(signature_line_bytes(
                        indent_bytes,
                        kind_label,
                        truncated.text.len(),
                    ));
                    kept.push(truncated);
                }
                return (kept, true);
            }
            self.retained_bytes = projected;
            kept.push(MappedSignature {
                kind_label,
                text: signature.text,
            });
        }

        (kept, false)
    }
}

fn truncated_signature(
    kind_label: &'static str,
    text: String,
    indent_bytes: usize,
    available: usize,
) -> Option<MappedSignature> {
    let framing = signature_line_bytes(indent_bytes, kind_label, SIGNATURE_TRUNCATION_MARKER.len());
    let prefix = char_boundary_prefix(&text, available.saturating_sub(framing));
    if prefix.len() < MIN_TRUNCATED_SIGNATURE_BYTES {
        return None;
    }

    let mut truncated = String::with_capacity(
        prefix
            .len()
            .saturating_add(SIGNATURE_TRUNCATION_MARKER.len()),
    );
    truncated.push_str(prefix);
    truncated.push_str(SIGNATURE_TRUNCATION_MARKER);

    Some(MappedSignature {
        kind_label,
        text: truncated,
    })
}

struct RepoMapWriter {
    text: String,
    body_ceiling: usize,
    ceiling: usize,
}

impl RepoMapWriter {
    fn new(ceiling: usize) -> Self {
        Self {
            text: String::new(),
            body_ceiling: ceiling.saturating_sub(TRUNCATION_NOTICE_RESERVE_BYTES),
            ceiling,
        }
    }

    fn remaining(&self) -> usize {
        self.body_ceiling.saturating_sub(self.text.len())
    }

    fn fits(&self, needed: usize) -> bool {
        needed <= self.remaining()
    }

    fn try_append(&mut self, segments: &[&str]) -> bool {
        if !self.fits(total_len(segments)) {
            return false;
        }
        self.push_segments(segments);
        true
    }

    fn push_segments(&mut self, segments: &[&str]) {
        self.text.reserve(total_len(segments));
        for segment in segments {
            self.text.push_str(segment);
        }
        debug_assert!(self.text.len() <= self.body_ceiling);
    }

    fn append_notice(&mut self, notice: &str) {
        if self.text.len().saturating_add(notice.len()) <= self.ceiling {
            self.text.push_str(notice);
        }
    }
}

struct RepoMapRender<'a> {
    writer: RepoMapWriter,
    presented: Vec<String>,
    current_dir: &'a str,
    omitted_files: BoundedDiagnostics,
    signature_detail: SignatureDetail,
    signature_budget_exhausted: bool,
}

impl<'a> RepoMapRender<'a> {
    fn new(ceiling: usize, signature_detail: SignatureDetail) -> Self {
        Self {
            writer: RepoMapWriter::new(ceiling),
            presented: Vec::new(),
            current_dir: "",
            omitted_files: BoundedDiagnostics::default(),
            signature_detail,
            signature_budget_exhausted: false,
        }
    }

    fn append_header(&mut self, header: &str) {
        self.writer.try_append(&[header]);
    }

    fn append_file(&mut self, file: &'a FileEntry, signatures: Option<&[MappedSignature]>) {
        let directory = parent_dir(&file.relative_path);
        let changed = directory != self.current_dir;
        let blank = if changed && !self.current_dir.is_empty() {
            LINE_BREAK
        } else {
            ""
        };
        let label = if changed { directory } else { "" };
        let suffix = if label.is_empty() {
            ""
        } else {
            DIRECTORY_SUFFIX
        };
        let needed = blank
            .len()
            .saturating_add(label.len())
            .saturating_add(suffix.len())
            .saturating_add(rendered_file_line_bytes(
                &file.relative_path,
                file.size_bytes,
            ));

        if !self.writer.fits(needed) {
            self.omitted_files
                .record_with(&mut || super::omitted_file_report(&file.relative_path));
            return;
        }

        let indent = indent_for(&file.relative_path);
        let name = file_name(&file.relative_path);
        let line_count = file.size_bytes / ESTIMATED_BYTES_PER_LINE;
        let line = format!("{indent}{name}{FILE_LINE_PREFIX}{line_count}{FILE_LINE_SUFFIX}");
        self.writer
            .push_segments(&[blank, label, suffix, line.as_str()]);
        self.current_dir = directory;
        self.presented.push(file.relative_path.clone());

        if self.signature_budget_exhausted {
            return;
        }
        if let Some(signatures) = signatures {
            self.append_signatures(indent, signatures);
        }
    }

    fn append_signatures(&mut self, indent: &str, signatures: &[MappedSignature]) {
        for signature in signatures {
            let appended = self.writer.try_append(&[
                indent,
                SIGNATURE_INDENT,
                signature.kind_label,
                SIGNATURE_SEPARATOR,
                signature.text.as_str(),
                LINE_BREAK,
            ]);
            if !appended {
                self.signature_detail = SignatureDetail::Truncated;
                self.signature_budget_exhausted = true;
                return;
            }
        }
    }

    fn finish(mut self, total_files: usize) -> RepoMap {
        let omitted_files = u32::try_from(self.omitted_files.observed()).unwrap_or(u32::MAX);
        if omitted_files > 0 || self.signature_detail != SignatureDetail::Complete {
            let notice = truncation_notice(
                self.writer.ceiling,
                omitted_files,
                total_files,
                self.signature_detail,
            );
            self.writer.append_notice(&notice);
        }

        let text = self.writer.text;
        let estimated_tokens = estimate_tokens(&text);
        let (omitted_file_reports, omitted_file_diagnostics) =
            self.omitted_files.into_sorted_entries();

        RepoMap {
            text,
            files: self.presented,
            estimated_tokens,
            omitted_files,
            omitted_file_reports,
            omitted_file_diagnostics,
        }
    }
}

fn truncation_notice(
    ceiling_bytes: usize,
    omitted_files: u32,
    total_files: usize,
    signature_detail: SignatureDetail,
) -> String {
    let detail = signature_detail.label();
    format!(
        "\n... (repo map truncated: byte budget {ceiling_bytes} exhausted; files omitted: {omitted_files}/{total_files}; signature detail: {detail}) ...\n"
    )
}

pub(crate) fn rendered_listing_bytes(files: &[FileEntry]) -> usize {
    let mut total = 0usize;
    let mut current_dir = "";

    for file in files {
        let directory = parent_dir(&file.relative_path);
        if directory != current_dir {
            if !current_dir.is_empty() {
                total = total.saturating_add(LINE_BREAK.len());
            }
            total = total.saturating_add(directory_label_bytes(directory));
            current_dir = directory;
        }
        total = total.saturating_add(rendered_file_line_bytes(
            &file.relative_path,
            file.size_bytes,
        ));
    }

    total
}

pub(crate) fn rendered_file_line_bytes(relative_path: &str, size_bytes: u64) -> usize {
    indent_for(relative_path)
        .len()
        .saturating_add(file_name(relative_path).len())
        .saturating_add(FILE_LINE_PREFIX.len())
        .saturating_add(decimal_digits(size_bytes / ESTIMATED_BYTES_PER_LINE))
        .saturating_add(FILE_LINE_SUFFIX.len())
}

fn directory_label_bytes(directory: &str) -> usize {
    if directory.is_empty() {
        return 0;
    }
    directory.len().saturating_add(DIRECTORY_SUFFIX.len())
}

fn signature_line_bytes(indent_bytes: usize, kind_label: &str, text_bytes: usize) -> usize {
    indent_bytes
        .saturating_add(SIGNATURE_INDENT.len())
        .saturating_add(kind_label.len())
        .saturating_add(SIGNATURE_SEPARATOR.len())
        .saturating_add(text_bytes)
        .saturating_add(LINE_BREAK.len())
}

fn indent_for(relative_path: &str) -> &'static str {
    if parent_dir(relative_path).is_empty() {
        return "";
    }
    NESTED_INDENT
}

fn file_name(relative_path: &str) -> &str {
    match relative_path.rfind('/') {
        Some(pos) => &relative_path[pos + 1..],
        None => relative_path,
    }
}

fn format_kind(kind: &SignatureKind) -> &'static str {
    match kind {
        SignatureKind::Function => "fn",
        SignatureKind::Method => "method",
        SignatureKind::Struct => "struct",
        SignatureKind::Enum => "enum",
        SignatureKind::Trait => "trait",
        SignatureKind::Interface => "interface",
        SignatureKind::Class => "class",
        SignatureKind::Impl => "impl",
    }
}

fn char_boundary_prefix(text: &str, max_bytes: usize) -> &str {
    if max_bytes >= text.len() {
        return text;
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn total_len(segments: &[&str]) -> usize {
    segments
        .iter()
        .fold(0usize, |total, segment| total.saturating_add(segment.len()))
}

fn decimal_digits(value: u64) -> usize {
    match value {
        0 => 1,
        _ => value.ilog10() as usize + 1,
    }
}

fn percentage(part: u64, total: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    let scaled = u128::from(part) * 100;
    u64::try_from(scaled / u128::from(total)).unwrap_or(u64::MAX)
}

fn budget_bytes(token_budget: u32) -> usize {
    let bytes = u64::from(token_budget).saturating_mul(ESTIMATED_CHARS_PER_TOKEN as u64);
    usize::try_from(bytes).unwrap_or(usize::MAX)
}

fn estimate_tokens(text: &str) -> u32 {
    u32::try_from(text.len() / ESTIMATED_CHARS_PER_TOKEN).unwrap_or(u32::MAX)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn default_config() -> EngineConfig {
        EngineConfig::default()
    }

    fn open_filesystem(root: &Path) -> ProjectFilesystem {
        let canonical_root = root.canonicalize().unwrap();
        ProjectFilesystem::open(ProjectRoot::open(&canonical_root).unwrap()).unwrap()
    }

    fn single_file_stats() -> ProjectStats {
        ProjectStats {
            total_files: 1,
            total_lines: 1,
            total_code_lines: 1,
            total_comment_lines: 0,
            total_blank_lines: 0,
            languages: Vec::new(),
        }
    }

    fn rust_project_stats() -> ProjectStats {
        ProjectStats {
            total_files: 2,
            total_lines: 3,
            total_code_lines: 3,
            total_comment_lines: 0,
            total_blank_lines: 0,
            languages: vec![stats::LanguageStats {
                name: "Rust".into(),
                files: 2,
                code: 3,
                comments: 0,
                blanks: 0,
            }],
        }
    }

    fn entry(relative_path: &str, size_bytes: u64) -> FileEntry {
        FileEntry {
            path: PathBuf::from(relative_path),
            relative_path: relative_path.to_string(),
            size_bytes,
            language: Some("rust".to_string()),
        }
    }

    fn rust_entries(count: usize) -> Vec<FileEntry> {
        (0..count)
            .map(|index| entry(&format!("src/module_{index}.rs"), 60))
            .collect()
    }

    fn long_path_entries(count: usize) -> Vec<FileEntry> {
        let directory = "deeply_nested_directory".repeat(8);
        (0..count)
            .map(|index| entry(&format!("{directory}/file_{index}.rs"), 0))
            .collect()
    }

    fn one_signature(text: &str) -> ast::SignatureBatch {
        ast::SignatureBatch {
            signatures: vec![ast::RepoMapSignature {
                kind: SignatureKind::Function,
                text: text.to_string(),
            }],
            complete: true,
        }
    }

    fn body_ceiling(token_budget: u32) -> usize {
        budget_bytes(token_budget).saturating_sub(TRUNCATION_NOTICE_RESERVE_BYTES)
    }

    #[test]
    fn every_signature_detail_has_a_stable_report_label() {
        assert_eq!(SignatureDetail::Complete.label(), "complete");
        assert_eq!(SignatureDetail::Truncated.label(), "truncated");
        assert_eq!(SignatureDetail::Unbudgeted.label(), "unbudgeted");
    }

    #[test]
    fn an_exhausted_signature_budget_still_lists_later_files_without_signatures() {
        let file = entry("src/later.rs", 30);
        let signature = MappedSignature {
            kind_label: "fn",
            text: "fn later()".into(),
        };
        let mut render = RepoMapRender::new(1_024, SignatureDetail::Truncated);
        render.signature_budget_exhausted = true;

        render.append_file(&file, Some(&[signature]));

        assert_eq!(render.presented, vec!["src/later.rs"]);
        assert!(render.writer.text.contains("later.rs"));
        assert!(!render.writer.text.contains("fn later()"));
    }

    #[test]
    fn a_character_prefix_larger_than_the_text_returns_the_whole_text() {
        assert_eq!(char_boundary_prefix("éclair", usize::MAX), "éclair");
        assert_eq!(char_boundary_prefix("éclair", "éclair".len()), "éclair");
    }

    #[test]
    fn builds_map_for_rust_project() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(
        src.join("main.rs"),
        "fn main() {\n    println!(\"hello\");\n}\n\nfn helper(x: i32) -> i32 {\n    x + 1\n}\n",
    )
    .unwrap();
        fs::write(
        src.join("lib.rs"),
        "pub struct Config {\n    pub name: String,\n}\n\npub fn create() -> Config {\n    Config { name: String::new() }\n}\n",
    )
    .unwrap();

        let map = build_repo_map(dir.path(), &default_config(), 30_000, None).unwrap();

        assert!(map.files.len() >= 2);
        assert!(map.files.contains(&"src/main.rs".to_string()));
        assert!(map.files.contains(&"src/lib.rs".to_string()));
        assert!(map.text.contains("main"));
        assert!(map.text.contains("helper"));
        assert!(map.text.contains("Config"));
        assert!(map.estimated_tokens > 0);
        assert_eq!(map.omitted_files, 0);
    }

    #[test]
    fn returns_error_for_empty_project() {
        let dir = TempDir::new().unwrap();
        let result = build_repo_map(dir.path(), &default_config(), 30_000, None);
        assert!(matches!(result, Err(RepoMapError::EmptyProject(_))));
    }

    #[test]
    fn includes_language_stats() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("app.rs"), "fn main() {}\n").unwrap();

        let map = build_repo_map(dir.path(), &default_config(), 30_000, None).unwrap();

        assert!(map.text.contains("Rust"));
    }

    #[test]
    fn truncates_when_exceeding_budget() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("src");
        fs::create_dir_all(&src).unwrap();

        let mut large_code = String::new();
        for i in 0..200 {
            large_code.push_str(&format!(
                "pub fn function_{i}(x: i32) -> i32 {{ x + {i} }}\n\n"
            ));
        }
        fs::write(src.join("big.rs"), &large_code).unwrap();

        let tiny_budget = 100;
        let map = build_repo_map(dir.path(), &default_config(), tiny_budget, None).unwrap();

        assert!(map.text.contains("truncated"));
        assert!(map.text.len() <= budget_bytes(tiny_budget));
    }

    #[test]
    fn every_path_survives_signature_truncation_when_the_listing_fits() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("src");
        fs::create_dir_all(&src).unwrap();

        for i in 0..50 {
            fs::write(
                src.join(format!("module_{i}.rs")),
                format!("pub fn handler_{i}(x: i32) -> i32 {{ x + {i} }}\n"),
            )
            .unwrap();
        }

        let budget = 500;
        let map = build_repo_map(dir.path(), &default_config(), budget, None).unwrap();

        assert_eq!(
            map.omitted_files, 0,
            "the listing fits, so nothing is omitted"
        );
        assert_eq!(map.files.len(), 50);
        assert!(map.text.contains("files omitted: 0/50"));
        assert!(map.text.contains("signature detail: truncated"));
        assert!(map.text.len() <= budget_bytes(budget));
        for i in 0..50 {
            assert!(
                map.text.contains(&format!("module_{i}.rs")),
                "file module_{i}.rs must still be listed by path despite truncation"
            );
        }
    }

    #[test]
    fn handles_mixed_language_project() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("main.rs"), "fn rust_fn() {}\n").unwrap();
        fs::write(dir.path().join("app.py"), "def python_fn():\n    pass\n").unwrap();

        let map = build_repo_map(dir.path(), &default_config(), 30_000, None).unwrap();

        assert!(map.text.contains("rust_fn"));
        assert!(map.text.contains("python_fn"));
    }

    #[test]
    fn files_are_grouped_by_directory() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("src");
        let lib = dir.path().join("lib");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&lib).unwrap();
        fs::write(src.join("a.rs"), "fn a() {}\n").unwrap();
        fs::write(lib.join("b.rs"), "fn b() {}\n").unwrap();

        let map = build_repo_map(dir.path(), &default_config(), 30_000, None).unwrap();

        let src_pos = map.text.find("src/");
        let lib_pos = map.text.find("lib/");
        assert!(src_pos.is_some());
        assert!(lib_pos.is_some());
    }

    #[test]
    fn only_the_selected_paths_are_mapped() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("kept.rs"), "fn kept_helper() {}\n").unwrap();
        fs::write(src.join("dropped.rs"), "fn dropped_helper() {}\n").unwrap();
        let selected = BTreeSet::from(["src/kept.rs".to_string()]);

        let map = build_repo_map(dir.path(), &default_config(), 30_000, Some(&selected)).unwrap();

        assert_eq!(map.files, vec!["src/kept.rs".to_string()]);
        assert!(map.text.contains("kept_helper"));
        assert!(
            !map.text.contains("dropped"),
            "an unselected file must not reach the map: {}",
            map.text
        );
    }

    #[test]
    fn a_selection_matching_no_discovered_file_is_an_empty_project() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("app.rs"), "fn app() {}\n").unwrap();
        let selected = BTreeSet::from(["other/app.rs".to_string()]);

        let result = build_repo_map(dir.path(), &default_config(), 30_000, Some(&selected));

        assert!(matches!(result, Err(RepoMapError::EmptyProject(_))));
    }

    #[test]
    fn a_file_the_reader_rejects_is_still_listed_without_signatures() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("big.rs"), "fn oversized() {}\n").unwrap();
        let filesystem = open_filesystem(dir.path());
        let files = vec![FileEntry {
            path: filesystem.root().as_path().join("big.rs"),
            relative_path: "big.rs".to_string(),
            size_bytes: 18,
            language: Some("rust".to_string()),
        }];
        let mut capped = default_config();
        capped.max_file_size_bytes = 4;

        let readable = build_repo_map_for_entries(
            &filesystem,
            &default_config(),
            30_000,
            &files,
            &single_file_stats(),
        );
        let rejected =
            build_repo_map_for_entries(&filesystem, &capped, 30_000, &files, &single_file_stats());

        assert!(readable.text.contains("oversized"));
        assert_eq!(rejected.files, vec!["big.rs".to_string()]);
        assert!(
            !rejected.text.contains("oversized"),
            "a file the reader rejects contributes no signatures: {}",
            rejected.text
        );
    }

    #[test]
    fn a_file_without_a_supported_language_is_listed_without_signatures() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("notes.txt"), "just prose\n").unwrap();
        let filesystem = open_filesystem(dir.path());
        let files = vec![FileEntry {
            path: filesystem.root().as_path().join("notes.txt"),
            relative_path: "notes.txt".to_string(),
            size_bytes: 11,
            language: None,
        }];

        let map = build_repo_map_for_entries(
            &filesystem,
            &default_config(),
            30_000,
            &files,
            &single_file_stats(),
        );

        assert_eq!(map.files, vec!["notes.txt".to_string()]);
        assert!(
            map.text.contains("notes.txt (~0 lines)"),
            "a file with no supported language is still presented by path: {}",
            map.text
        );
    }

    #[test]
    fn a_language_without_ast_support_yields_no_signatures() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("legacy.cbl"), "PROGRAM-ID. LEGACY.\n").unwrap();
        let filesystem = open_filesystem(dir.path());
        let legacy = filesystem.root().as_path().join("legacy.cbl");

        assert!(
            read_and_extract_signatures(
                &filesystem,
                &legacy,
                "cobol",
                &default_config(),
                usize::MAX,
            )
            .is_none(),
            "an unsupported language cannot produce signatures"
        );
        assert!(
            read_and_extract_signatures(
                &filesystem,
                &legacy,
                "rust",
                &default_config(),
                usize::MAX,
            )
            .is_some(),
            "the same file is readable, so only the language stopped extraction"
        );
    }

    #[test]
    fn an_ordinary_project_renders_paths_and_signatures_in_input_order() {
        let files = vec![entry("main.rs", 30), entry("src/lib.rs", 60)];

        let map = render_repo_map(
            "api",
            &rust_project_stats(),
            &files,
            30_000,
            &mut |file, _| one_signature(file_name(&file.relative_path)),
        );

        assert_eq!(
            map.text,
            concat!(
                "Project: api (Rust 100%)\n",
                "Files: 2 | Code: 3 lines | Comments: 0 lines\n",
                "\n",
                "main.rs (~1 lines)\n",
                "  fn main.rs\n",
                "src/\n",
                "  lib.rs (~2 lines)\n",
                "    fn lib.rs\n",
            )
        );
        assert_eq!(
            map.files,
            vec!["main.rs".to_string(), "src/lib.rs".to_string()]
        );
        assert_eq!(map.omitted_files, 0);
        assert_eq!(
            usize::try_from(map.estimated_tokens).unwrap(),
            map.text.len() / ESTIMATED_CHARS_PER_TOKEN
        );
    }

    #[test]
    fn every_file_is_read_while_the_signature_budget_lasts() {
        let files = rust_entries(4);
        let mut read_order = Vec::new();

        let map = render_repo_map(
            "api",
            &single_file_stats(),
            &files,
            30_000,
            &mut |file, _| {
                read_order.push(file.relative_path.clone());
                one_signature(&file.relative_path)
            },
        );

        assert_eq!(read_order.len(), 4);
        assert!(!map.text.contains("repo map truncated"));
        assert_eq!(map.files.len(), 4);
        assert_eq!(map.omitted_files, 0);
    }

    #[test]
    fn no_file_is_read_when_the_listing_leaves_no_signature_budget() {
        let files = rust_entries(4);
        let mut read_order = Vec::new();

        let map = render_repo_map("api", &single_file_stats(), &files, 0, &mut |file, _| {
            read_order.push(file.relative_path.clone());
            one_signature(&file.relative_path)
        });

        assert!(
            read_order.is_empty(),
            "a zero budget must not parse a single file"
        );
        assert!(map.text.is_empty());
        assert!(map.files.is_empty());
        assert_eq!(map.omitted_files, 4);
        assert_eq!(map.omitted_file_reports.len(), 4);
        assert_eq!(map.omitted_file_diagnostics, 0);
        assert!(
            map.omitted_file_reports
                .iter()
                .all(|entry| entry.ends_with(" (repo map byte budget exhausted)"))
        );
    }

    #[test]
    fn no_file_is_read_after_the_signature_ceiling_is_exhausted() {
        let files = rust_entries(4);
        let mut read_order = Vec::new();

        let index = extract_all_signatures(&files, 100, &mut |file, _| {
            read_order.push(file.relative_path.clone());
            one_signature(&"s".repeat(100))
        });

        assert_eq!(read_order, vec!["src/module_0.rs".to_string()]);
        assert_eq!(index.detail, SignatureDetail::Truncated);
        assert_eq!(index.by_path.len(), 1);
    }

    #[test]
    fn signature_accumulation_across_files_stops_at_the_shared_ceiling() {
        let files = rust_entries(500);
        let ceiling = 1_000;
        let mut reads = 0usize;

        let index = extract_all_signatures(&files, ceiling, &mut |_, _| {
            reads += 1;
            one_signature(&"s".repeat(100))
        });

        let retained: usize = index
            .by_path
            .values()
            .flatten()
            .map(|signature| {
                signature_line_bytes(
                    NESTED_INDENT.len(),
                    signature.kind_label,
                    signature.text.len(),
                )
            })
            .sum();

        assert!(
            retained <= ceiling,
            "retained {retained} bytes against a {ceiling} byte ceiling"
        );
        assert_eq!(index.detail, SignatureDetail::Truncated);
        assert_eq!(index.by_path.len(), 9);
        assert_eq!(
            reads, 10,
            "extraction must stop at the file that exhausts the ceiling"
        );
    }

    #[test]
    fn signature_extraction_receives_only_the_remaining_byte_budget() {
        let files = rust_entries(2);
        let mut budgets = Vec::new();

        let index = extract_all_signatures(&files, 100, &mut |_, remaining| {
            budgets.push(remaining);
            one_signature("small")
        });

        assert_eq!(budgets.len(), 2);
        assert_eq!(budgets[0], 100);
        assert!(budgets[1] < budgets[0]);
        assert_eq!(index.detail, SignatureDetail::Complete);
    }

    #[test]
    fn the_real_signature_provider_does_not_charge_names_the_map_discards() {
        let directory = TempDir::new().unwrap();
        let name = "n".repeat(40);
        let source = format!("fn {name}() {{}}\n");
        fs::write(directory.path().join("tight.rs"), &source).unwrap();
        let filesystem = open_filesystem(directory.path());
        let file = FileEntry {
            path: filesystem.root().as_path().join("tight.rs"),
            relative_path: "tight.rs".to_string(),
            size_bytes: source.len() as u64,
            language: Some("rust".to_string()),
        };

        let batch = signatures_for_file(&filesystem, &file, &default_config(), 64);
        let mut budget = SignatureBudget::new(64);
        let (kept, truncated) = budget.retain(0, batch.signatures);

        assert_eq!(kept.len(), 1);
        assert!(!truncated);
        assert!(budget.retained_bytes <= 64);
    }
    #[test]
    fn an_oversized_signature_is_truncated_on_a_char_boundary_and_marked() {
        let files = rust_entries(1);
        let framing =
            signature_line_bytes(NESTED_INDENT.len(), "fn", SIGNATURE_TRUNCATION_MARKER.len());
        let odd_room = 21;
        let ceiling = framing + odd_room;

        let index =
            extract_all_signatures(&files, ceiling, &mut |_, _| one_signature(&"é".repeat(50)));

        let kept: Vec<&MappedSignature> = index.by_path.values().flatten().collect();
        assert_eq!(kept.len(), 1);
        let prefix = kept[0]
            .text
            .strip_suffix(SIGNATURE_TRUNCATION_MARKER)
            .expect("a shortened signature must carry the marker");
        assert_eq!(
            prefix.len(),
            odd_room - 1,
            "an odd cut must fall back to the previous char boundary"
        );
        assert!(prefix.chars().all(|character| character == 'é'));
        assert_eq!(index.detail, SignatureDetail::Truncated);
        assert!(
            signature_line_bytes(NESTED_INDENT.len(), kept[0].kind_label, kept[0].text.len())
                <= ceiling
        );
    }

    #[test]
    fn an_oversized_signature_is_marked_inside_the_map() {
        let files = rust_entries(1);
        let token_budget = 100;
        let header = format_header("api", &single_file_stats());
        let signature_room =
            body_ceiling(token_budget) - header.len() - rendered_listing_bytes(&files);
        let framing =
            signature_line_bytes(NESTED_INDENT.len(), "fn", SIGNATURE_TRUNCATION_MARKER.len());

        let map = render_repo_map(
            "api",
            &single_file_stats(),
            &files,
            token_budget,
            &mut |_, _| one_signature(&"x".repeat(400)),
        );

        assert!(map.text.len() <= budget_bytes(token_budget));
        assert!(
            map.text.contains(&format!(
                "fn {}{}",
                "x".repeat(signature_room - framing),
                SIGNATURE_TRUNCATION_MARKER
            )),
            "the map must show a marked, in-budget signature: {}",
            map.text
        );
        assert!(map.text.contains("signature detail: truncated"));
    }

    #[test]
    fn a_repeated_path_cannot_render_its_signature_twice_past_the_ceiling() {
        let duplicated = entry("src/module_0.rs", 60);
        let files = vec![duplicated.clone(), duplicated];
        let signature_text = "dup_helper";
        let needed = format_header("api", &single_file_stats()).len()
            + rendered_listing_bytes(&files)
            + signature_line_bytes(NESTED_INDENT.len(), "fn", signature_text.len())
            + TRUNCATION_NOTICE_RESERVE_BYTES;
        let token_budget = u32::try_from(needed.div_ceil(ESTIMATED_CHARS_PER_TOKEN)).unwrap();

        let map = render_repo_map(
            "api",
            &single_file_stats(),
            &files,
            token_budget,
            &mut |_, _| one_signature(signature_text),
        );

        assert!(map.text.len() <= budget_bytes(token_budget));
        assert_eq!(
            map.text.matches(&format!("fn {signature_text}")).count(),
            1,
            "the repeated signature must not be rendered past the ceiling: {}",
            map.text
        );
        assert_eq!(map.omitted_files, 0);
        assert!(map.text.contains("signature detail: truncated"));
    }

    #[test]
    fn thousands_of_long_paths_cannot_exceed_a_tiny_budget() {
        let files = long_path_entries(3_000);
        let token_budget = 10;
        let mut reads = 0usize;

        let map = render_repo_map(
            "api",
            &single_file_stats(),
            &files,
            token_budget,
            &mut |_, _| {
                reads += 1;
                one_signature("tiny")
            },
        );

        assert!(
            map.text.is_empty(),
            "a forty byte ceiling leaves room for nothing: {}",
            map.text
        );
        assert!(map.text.len() <= budget_bytes(token_budget));
        assert_eq!(
            reads, 0,
            "no file may be parsed when no signature byte is budgeted"
        );
        assert!(
            map.files.is_empty(),
            "an unrepresentable path must not be retained"
        );
        assert_eq!(map.omitted_files, 3_000);
        assert_eq!(map.omitted_file_reports.len(), 3_000);
        assert_eq!(map.omitted_file_diagnostics, 0);
        assert!(
            map.omitted_file_reports
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
    }

    #[test]
    fn a_budget_that_holds_only_some_paths_reports_the_rest() {
        let files = long_path_entries(3_000);
        let token_budget = 200;
        let mut reads = 0usize;

        let map = render_repo_map(
            "api",
            &single_file_stats(),
            &files,
            token_budget,
            &mut |_, _| {
                reads += 1;
                one_signature("tiny")
            },
        );

        assert!(map.text.len() <= budget_bytes(token_budget));
        assert_eq!(reads, 0);
        assert!(
            !map.files.is_empty(),
            "the paths that fit must be presented"
        );
        assert_eq!(map.files.len() as u32 + map.omitted_files, 3_000);
        assert!(
            map.text
                .contains(&format!("files omitted: {}/3000", map.omitted_files))
        );
        assert!(map.text.contains("signature detail: unbudgeted"));
        for path in &map.files {
            assert!(
                map.text.contains(file_name(path)),
                "a presented path must appear in the map: {path}"
            );
        }
    }

    #[test]
    fn no_budget_produces_text_beyond_its_ceiling() {
        let files = rust_entries(30);

        for token_budget in 0..=120u32 {
            let map = render_repo_map(
                "api",
                &single_file_stats(),
                &files,
                token_budget,
                &mut |file, _| one_signature(&file.relative_path),
            );

            assert!(
                map.text.len() <= budget_bytes(token_budget),
                "budget {token_budget} produced {} bytes",
                map.text.len()
            );
            assert_eq!(
                map.files.len() as u32 + map.omitted_files,
                30,
                "every file is either presented or counted as omitted"
            );
        }
    }

    #[test]
    fn the_writer_accepts_exactly_the_remaining_bytes_and_rejects_one_more() {
        let mut writer = RepoMapWriter::new(TRUNCATION_NOTICE_RESERVE_BYTES + 10);

        assert_eq!(writer.remaining(), 10);
        assert!(
            !writer.try_append(&["12345", "678901"]),
            "eleven bytes must not fit"
        );
        assert!(
            writer.text.is_empty(),
            "a rejected segment must leave no partial write"
        );
        assert!(
            writer.try_append(&["12345", "67890"]),
            "ten bytes fill the body exactly"
        );
        assert_eq!(writer.remaining(), 0);
        assert!(!writer.try_append(&["x"]));
        assert_eq!(writer.text.len(), 10);

        writer.append_notice("0123456789");
        assert_eq!(
            writer.text.len(),
            20,
            "the reserve keeps room for the notice"
        );
    }

    #[test]
    fn the_last_file_line_that_exactly_fits_is_presented() {
        let files = vec![entry("a.rs", 0)];
        let header = format_header("p", &single_file_stats());
        let needed = header.len()
            + rendered_file_line_bytes("a.rs", 0)
            + TRUNCATION_NOTICE_RESERVE_BYTES
            + 1;
        let fitting = u32::try_from(needed.div_ceil(ESTIMATED_CHARS_PER_TOKEN)).unwrap();
        let tight = u32::try_from((needed - 2) / ESTIMATED_CHARS_PER_TOKEN).unwrap();

        let fits = render_repo_map("p", &single_file_stats(), &files, fitting, &mut |_, _| {
            ast::SignatureBatch::empty()
        });
        let misses = render_repo_map("p", &single_file_stats(), &files, tight, &mut |_, _| {
            ast::SignatureBatch::empty()
        });

        assert_eq!(fits.text, format!("{header}a.rs (~0 lines)\n"));
        assert_eq!(fits.files, vec!["a.rs".to_string()]);
        assert_eq!(fits.omitted_files, 0);

        assert!(
            !misses.text.contains("a.rs (~0 lines)"),
            "one byte short must drop the line entirely: {}",
            misses.text
        );
        assert_eq!(misses.omitted_files, 1);
        assert!(misses.text.contains("files omitted: 1/1"));
        assert!(misses.text.len() <= budget_bytes(tight));
    }

    #[test]
    fn every_shard_map_stays_within_the_repo_map_ceiling() {
        let files: Vec<FileEntry> = (0..80u32)
            .map(|index| {
                entry(
                    &format!("crates/pkg_{}/src/file_{index}.rs", index % 5),
                    u64::from(index % 7) * 120,
                )
            })
            .collect();
        let token_budget = 300;

        let shards = crate::repomap::shard::partition_into_shards(files, 400);

        assert!(shards.len() > 1, "expected the fixture to need sharding");
        for shard in &shards {
            let map = render_repo_map(
                "api",
                &single_file_stats(),
                &shard.files,
                token_budget,
                &mut |file, _| one_signature(&file.relative_path),
            );

            assert!(
                map.text.len() <= budget_bytes(token_budget),
                "a shard map rendered {} bytes above its ceiling",
                map.text.len()
            );
            assert_eq!(
                map.files.len() as u32 + map.omitted_files,
                shard.files.len() as u32
            );
        }
    }

    #[test]
    fn the_map_is_byte_identical_across_runs() {
        let files = rust_entries(20);
        let render = || {
            render_repo_map("api", &single_file_stats(), &files, 400, &mut |file, _| {
                one_signature(&file.relative_path)
            })
        };

        let first = render();
        let second = render();

        assert_eq!(first.text, second.text);
        assert_eq!(first.files, second.files);
        assert_eq!(first.omitted_files, second.omitted_files);
        let earlier = first.text.find("module_1.rs").unwrap();
        let later = first.text.find("module_2.rs").unwrap();
        assert!(
            earlier < later,
            "files keep their input order: {}",
            first.text
        );
    }

    #[test]
    fn the_predicted_file_line_length_matches_the_rendered_line() {
        for (path, size) in [
            ("a.rs", 0u64),
            ("b.rs", 270),
            ("src/c.rs", 300),
            ("src/deep/nested/d.rs", 29),
            ("e.rs", u64::MAX),
        ] {
            let files = vec![entry(path, size)];
            let stats = single_file_stats();
            let header = format_header("p", &stats);

            let map = render_repo_map("p", &stats, &files, u32::MAX, &mut |_, _| {
                ast::SignatureBatch::empty()
            });
            let listing = &map.text[header.len()..];

            assert_eq!(
                listing.len(),
                rendered_listing_bytes(&files),
                "listing prediction drifted for {path}"
            );
            assert_eq!(
                listing.len() - directory_label_bytes(parent_dir(path)),
                rendered_file_line_bytes(path, size),
                "file line prediction drifted for {path}"
            );
        }
    }

    #[test]
    fn the_truncation_notice_always_fits_its_reserve() {
        let worst = truncation_notice(
            usize::MAX,
            u32::MAX,
            usize::MAX,
            SignatureDetail::Unbudgeted,
        );

        assert!(
            worst.len() <= TRUNCATION_NOTICE_RESERVE_BYTES,
            "the notice needs {} bytes but only {TRUNCATION_NOTICE_RESERVE_BYTES} are reserved",
            worst.len()
        );
        assert!(worst.contains("byte budget"));
        assert!(worst.contains("files omitted"));
    }

    #[test]
    fn byte_arithmetic_saturates_instead_of_overflowing() {
        assert_eq!(budget_bytes(0), 0);
        assert_eq!(
            budget_bytes(u32::MAX),
            u32::MAX as usize * ESTIMATED_CHARS_PER_TOKEN
        );
        assert_eq!(
            estimate_tokens(&"x".repeat(4 * ESTIMATED_CHARS_PER_TOKEN)),
            4
        );
        assert_eq!(decimal_digits(0), 1);
        assert_eq!(decimal_digits(9), 1);
        assert_eq!(decimal_digits(10), 2);
        assert_eq!(decimal_digits(u64::MAX), 20);
        assert_eq!(total_len(&["ab", "c"]), 3);
        assert_eq!(
            signature_line_bytes(usize::MAX, "fn", usize::MAX),
            usize::MAX
        );
        assert_eq!(
            rendered_file_line_bytes("a.rs", u64::MAX),
            "a.rs".len() + FILE_LINE_PREFIX.len() + 18 + FILE_LINE_SUFFIX.len()
        );
        assert_eq!(
            rendered_listing_bytes(&[entry("a.rs", u64::MAX), entry("b.rs", u64::MAX)]),
            2 * rendered_file_line_bytes("a.rs", u64::MAX)
        );
    }

    #[test]
    fn percentage_saturates_and_survives_zero_totals() {
        assert_eq!(percentage(3u64, 4u64), 75);
        assert_eq!(percentage(0u64, 0u64), 0);
        assert_eq!(percentage(u64::MAX, 1u64), u64::MAX);
        assert_eq!(percentage(1u64, u64::MAX), 0);
    }

    #[test]
    fn the_map_labels_every_signature_kind() {
        let kinds = [
            (SignatureKind::Function, "fn"),
            (SignatureKind::Method, "method"),
            (SignatureKind::Struct, "struct"),
            (SignatureKind::Enum, "enum"),
            (SignatureKind::Trait, "trait"),
            (SignatureKind::Interface, "interface"),
            (SignatureKind::Class, "class"),
            (SignatureKind::Impl, "impl"),
        ];
        let signatures = || ast::SignatureBatch {
            signatures: kinds
                .iter()
                .enumerate()
                .map(|(index, (kind, _))| ast::RepoMapSignature {
                    kind: kind.clone(),
                    text: format!("item_{index}"),
                })
                .collect(),
            complete: true,
        };
        let files = vec![entry("api.rs", 30)];

        let map = render_repo_map("api", &single_file_stats(), &files, 30_000, &mut |_, _| {
            signatures()
        });

        for (index, (_, label)) in kinds.iter().enumerate() {
            assert!(
                map.text.contains(&format!("{label} item_{index}")),
                "the map must label {label} signatures: {}",
                map.text
            );
        }
    }

    #[test]
    fn a_project_without_counted_code_lines_reports_zero_percent() {
        let stats = ProjectStats {
            total_files: 1,
            total_lines: 4,
            total_code_lines: 0,
            total_comment_lines: 0,
            total_blank_lines: 4,
            languages: vec![stats::LanguageStats {
                name: "Rust".into(),
                files: 1,
                code: 0,
                comments: 0,
                blanks: 4,
            }],
        };

        let header = format_header("blank", &stats);

        assert!(
            header.contains("Rust 0%"),
            "a project with no counted code lines must not divide by zero: {header}"
        );
    }

    #[test]
    fn a_language_share_stays_exact_for_line_counts_beyond_u32() {
        let code = u64::from(u32::MAX) + 1;
        let total_code = code * 4;
        let stats = ProjectStats {
            total_files: 2,
            total_lines: total_code,
            total_code_lines: total_code,
            total_comment_lines: 0,
            total_blank_lines: 0,
            languages: vec![stats::LanguageStats {
                name: "Rust".into(),
                files: 1,
                code,
                comments: 0,
                blanks: 0,
            }],
        };

        let header = format_header("wide", &stats);

        assert!(
            header.contains("Rust 25%"),
            "a language share must stay exact past u32::MAX: {header}"
        );
        assert!(
            header.contains(&total_code.to_string()),
            "the header must print the whole u64 code line total: {header}"
        );
    }

    #[test]
    fn a_language_share_at_the_u64_ceiling_neither_wraps_nor_panics() {
        assert_eq!(percentage(u64::MAX, u64::MAX), 100);
        assert_eq!(percentage(u64::MAX / 2, u64::MAX), 49);
        assert_eq!(percentage(u64::MAX, 1), u64::MAX);
        assert_eq!(percentage(0, u64::MAX), 0);
    }
}
