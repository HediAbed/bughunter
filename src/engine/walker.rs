use std::path::{Path, PathBuf};
use std::sync::Arc;

use ignore::WalkBuilder;
use tracing::warn;

use crate::cancel::CancelToken;
use crate::config::EngineConfig;
use crate::domain::ProjectRoot;
use crate::errors::EngineError;
use crate::shared::root_cause_message;

use super::exclusions::{self, IgnoreLimits, RepositoryIgnoreRules};
use super::filesystem::ProjectFilesystem;
use super::language;

const BINARY_DETECTION_BUFFER_SIZE: usize = 8192;
const PROJECT_ROOT_KEY: &str = ".";
const NON_UNICODE_PATH_REASON: &str = "path is not valid UTF-8";

pub const MAX_VISITED_ENTRIES: usize = 1_000_000;
pub const MAX_DISCOVERED_FILES: usize = 100_000;
pub const MAX_UNREADABLE_DIAGNOSTICS: usize = 10_000;
pub const MAX_UNREADABLE_DIAGNOSTIC_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_RETAINED_PATH_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_INCLUDED_SOURCE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

const VISITED_ENTRIES: &str = "visited entries";
const DISCOVERED_FILES: &str = "discovered files";
const UNREADABLE_DIAGNOSTICS: &str = "unreadable diagnostics";
const UNREADABLE_DIAGNOSTIC_BYTES: &str = "unreadable diagnostic bytes";
const RETAINED_PATH_BYTES: &str = "retained path bytes";
const INCLUDED_SOURCE_BYTES: &str = "included source bytes";

#[derive(Debug, Clone, serde::Serialize)]
pub struct FileEntry {
    pub path: PathBuf,
    pub relative_path: String,
    pub size_bytes: u64,
    pub language: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DiscoverOpts {
    pub extensions: Option<Vec<String>>,
    pub pattern: Option<String>,
    pub max_depth: Option<u32>,
    pub max_results: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct UnreadableFile {
    pub relative_path: String,
    pub reason: String,
}

impl UnreadableFile {
    pub fn report_entry(&self) -> String {
        format!("{} ({})", self.relative_path, self.reason)
    }
}

#[derive(Debug, Default)]
pub struct ProjectWalk {
    pub files: Vec<FileEntry>,
    pub unreadable: Vec<UnreadableFile>,
}

enum WalkedEntry {
    Included(FileEntry),
    Unreadable(UnreadableFile),
    Excluded,
}

pub fn walk_project(
    root: &Path,
    config: &EngineConfig,
    opts: &DiscoverOpts,
) -> Result<Vec<FileEntry>, EngineError> {
    let project_root = ProjectRoot::open(root).map_err(|error| EngineError::Io {
        path: root.to_path_buf(),
        source: std::io::Error::other(error),
    })?;
    let filesystem = ProjectFilesystem::open(project_root)?;
    Ok(walk_project_with_capability(&filesystem, config, opts)?.files)
}

pub fn walk_project_with_capability(
    filesystem: &ProjectFilesystem,
    config: &EngineConfig,
    opts: &DiscoverOpts,
) -> Result<ProjectWalk, EngineError> {
    walk_project_within_limits_and_cancel(filesystem, config, opts, WalkLimits::default(), None)
}

pub fn walk_project_with_capability_cancellable(
    filesystem: &ProjectFilesystem,
    config: &EngineConfig,
    opts: &DiscoverOpts,
    cancel: &CancelToken,
) -> Result<ProjectWalk, EngineError> {
    walk_project_within_limits_and_cancel(
        filesystem,
        config,
        opts,
        WalkLimits::default(),
        Some(cancel),
    )
}

#[cfg(test)]
fn walk_project_within_limits(
    filesystem: &ProjectFilesystem,
    config: &EngineConfig,
    opts: &DiscoverOpts,
    limits: WalkLimits,
) -> Result<ProjectWalk, EngineError> {
    walk_project_within_limits_and_cancel(filesystem, config, opts, limits, None)
}

fn walk_project_within_limits_and_cancel(
    filesystem: &ProjectFilesystem,
    config: &EngineConfig,
    opts: &DiscoverOpts,
    limits: WalkLimits,
    cancel: Option<&CancelToken>,
) -> Result<ProjectWalk, EngineError> {
    ensure_not_cancelled(cancel)?;
    let root = filesystem.root().as_path();
    let rules = RepositoryIgnoreRules::for_walk(root, config, limits.ignore);
    let mut bounded = BoundedWalk::new(limits);
    for result in project_walker(root, config, opts, &rules) {
        ensure_not_cancelled(cancel)?;
        bounded.visit()?;
        check_ignore_rule_budget(&rules)?;
        report_ignore_rule_failures(&rules, root, &mut bounded)?;
        match process_entry(result, root, filesystem, config, opts) {
            WalkedEntry::Included(entry) => bounded.include(entry)?,
            WalkedEntry::Unreadable(unreadable) => bounded.report_unreadable(unreadable)?,
            WalkedEntry::Excluded => {}
        }
    }
    ensure_not_cancelled(cancel)?;
    check_ignore_rule_budget(&rules)?;
    report_ignore_rule_failures(&rules, root, &mut bounded)?;
    Ok(bounded.finish(opts.max_results.unwrap_or(u32::MAX) as usize))
}

fn ensure_not_cancelled(cancel: Option<&CancelToken>) -> Result<(), EngineError> {
    if cancel.is_some_and(CancelToken::is_cancelled) {
        return Err(EngineError::Cancelled);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub struct WalkLimits {
    pub visited_entries: usize,
    pub files: usize,
    pub unreadable_diagnostics: usize,
    pub unreadable_diagnostic_bytes: usize,
    pub retained_path_bytes: usize,
    pub included_source_bytes: u64,
    pub ignore: IgnoreLimits,
}

impl Default for WalkLimits {
    fn default() -> Self {
        Self {
            visited_entries: MAX_VISITED_ENTRIES,
            files: MAX_DISCOVERED_FILES,
            unreadable_diagnostics: MAX_UNREADABLE_DIAGNOSTICS,
            unreadable_diagnostic_bytes: MAX_UNREADABLE_DIAGNOSTIC_BYTES,
            retained_path_bytes: MAX_RETAINED_PATH_BYTES,
            included_source_bytes: MAX_INCLUDED_SOURCE_BYTES,
            ignore: IgnoreLimits::default(),
        }
    }
}

struct BoundedWalk {
    limits: WalkLimits,
    files: Vec<FileEntry>,
    unreadable: Vec<UnreadableFile>,
    visited_entries: usize,
    unreadable_diagnostic_bytes: usize,
    retained_path_bytes: usize,
    included_source_bytes: u64,
}

impl BoundedWalk {
    fn new(limits: WalkLimits) -> Self {
        Self {
            limits,
            files: Vec::new(),
            unreadable: Vec::new(),
            visited_entries: 0,
            unreadable_diagnostic_bytes: 0,
            retained_path_bytes: 0,
            included_source_bytes: 0,
        }
    }

    fn visit(&mut self) -> Result<(), EngineError> {
        if self.visited_entries == self.limits.visited_entries {
            return Err(discovery_limit(
                VISITED_ENTRIES,
                self.limits.visited_entries as u64,
            ));
        }
        self.visited_entries += 1;
        Ok(())
    }

    fn include(&mut self, entry: FileEntry) -> Result<(), EngineError> {
        if self.files.len() == self.limits.files {
            return Err(discovery_limit(DISCOVERED_FILES, self.limits.files as u64));
        }
        let retained_path_bytes =
            self.retained_path_bytes + entry.path.as_os_str().len() + entry.relative_path.len();
        if retained_path_bytes > self.limits.retained_path_bytes {
            return Err(discovery_limit(
                RETAINED_PATH_BYTES,
                self.limits.retained_path_bytes as u64,
            ));
        }
        let included_source_bytes = self.included_source_bytes.saturating_add(entry.size_bytes);
        if included_source_bytes > self.limits.included_source_bytes {
            return Err(discovery_limit(
                INCLUDED_SOURCE_BYTES,
                self.limits.included_source_bytes,
            ));
        }
        self.retained_path_bytes = retained_path_bytes;
        self.included_source_bytes = included_source_bytes;
        self.files.push(entry);
        Ok(())
    }

    fn report_unreadable(&mut self, unreadable: UnreadableFile) -> Result<(), EngineError> {
        if self.unreadable.len() == self.limits.unreadable_diagnostics {
            return Err(discovery_limit(
                UNREADABLE_DIAGNOSTICS,
                self.limits.unreadable_diagnostics as u64,
            ));
        }
        let diagnostic_bytes = self.unreadable_diagnostic_bytes
            + unreadable.relative_path.len()
            + unreadable.reason.len();
        if diagnostic_bytes > self.limits.unreadable_diagnostic_bytes {
            return Err(discovery_limit(
                UNREADABLE_DIAGNOSTIC_BYTES,
                self.limits.unreadable_diagnostic_bytes as u64,
            ));
        }
        self.unreadable_diagnostic_bytes = diagnostic_bytes;
        self.unreadable.push(unreadable);
        Ok(())
    }

    fn finish(mut self, max_results: usize) -> ProjectWalk {
        self.files
            .sort_unstable_by(|left, right| left.relative_path.cmp(&right.relative_path));
        self.files.truncate(max_results);
        self.unreadable.sort_unstable_by(|left, right| {
            (&left.relative_path, &left.reason).cmp(&(&right.relative_path, &right.reason))
        });
        ProjectWalk {
            files: self.files,
            unreadable: self.unreadable,
        }
    }
}

fn discovery_limit(resource: &'static str, limit: u64) -> EngineError {
    EngineError::DiscoveryLimitExceeded { resource, limit }
}

fn check_ignore_rule_budget(rules: &RepositoryIgnoreRules) -> Result<(), EngineError> {
    match rules.exhausted() {
        Some(exhausted) => Err(discovery_limit(exhausted.resource, exhausted.limit as u64)),
        None => Ok(()),
    }
}

fn report_ignore_rule_failures(
    rules: &RepositoryIgnoreRules,
    canonical_root: &Path,
    bounded: &mut BoundedWalk,
) -> Result<(), EngineError> {
    for failure in rules.take_failures() {
        let unreadable = UnreadableFile {
            relative_path: relative_key(&failure.source, canonical_root),
            reason: walk_error_reason(&failure.error),
        };
        warn!(
            path = %unreadable.relative_path,
            reason = %unreadable.reason,
            "failed to load the ignore rules for a directory"
        );
        bounded.report_unreadable(unreadable)?;
    }
    Ok(())
}

fn project_walker(
    root: &Path,
    config: &EngineConfig,
    opts: &DiscoverOpts,
    rules: &Arc<RepositoryIgnoreRules>,
) -> ignore::Walk {
    let mut builder = walk_builder(root, rules);
    let depth = opts
        .max_depth
        .map(|depth| depth as usize)
        .or(config.max_depth);
    if let Some(depth) = depth {
        builder.max_depth(Some(depth));
    }
    builder.build()
}

fn walk_builder(root: &Path, rules: &Arc<RepositoryIgnoreRules>) -> WalkBuilder {
    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(false)
        .ignore(false)
        .parents(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false);
    if rules.honors_ignore_files() {
        let rules = Arc::clone(rules);
        builder.filter_entry(move |entry| {
            let is_directory = entry
                .file_type()
                .is_some_and(|file_type| file_type.is_dir());
            let admitted = rules.admits(entry.path(), is_directory);
            if admitted && is_directory {
                rules.load_directory(entry.path());
            }
            admitted
        });
    }
    builder
}

fn process_entry(
    result: Result<ignore::DirEntry, ignore::Error>,
    canonical_root: &Path,
    filesystem: &ProjectFilesystem,
    config: &EngineConfig,
    opts: &DiscoverOpts,
) -> WalkedEntry {
    let dir_entry = match result {
        Ok(entry) => entry,
        Err(error) => return unreadable_walk_error(&error, canonical_root),
    };

    classify_entry(
        dir_entry.path(),
        canonical_root,
        filesystem,
        config,
        opts,
        &|| dir_entry.metadata().map(|metadata| metadata.len()),
    )
}

fn classify_entry(
    path: &Path,
    canonical_root: &Path,
    filesystem: &ProjectFilesystem,
    config: &EngineConfig,
    opts: &DiscoverOpts,
    read_size_bytes: &dyn Fn() -> Result<u64, ignore::Error>,
) -> WalkedEntry {
    if path.is_dir() || !is_eligible_file(path, config) {
        return WalkedEntry::Excluded;
    }

    if exclusions::escapes_project_root(path, canonical_root) {
        return WalkedEntry::Excluded;
    }

    let size_bytes = match read_size_bytes() {
        Ok(size_bytes) => size_bytes,
        Err(error) => {
            warn!(path = %path.display(), %error, "failed to read file metadata");
            return unreadable(path, canonical_root, &error);
        }
    };
    if size_bytes > config.max_file_size_bytes {
        return WalkedEntry::Excluded;
    }

    if !matches_filters(path, opts) {
        return WalkedEntry::Excluded;
    }
    let Some(relative_path) = unicode_relative_key(path, canonical_root) else {
        return WalkedEntry::Unreadable(UnreadableFile {
            relative_path: relative_key(path, canonical_root),
            reason: NON_UNICODE_PATH_REASON.to_string(),
        });
    };
    match is_binary_file(filesystem, path) {
        Ok(false) => WalkedEntry::Included(build_file_entry(path, relative_path, size_bytes)),
        Ok(true) => WalkedEntry::Excluded,
        Err(error) => {
            warn!(path = %path.display(), %error, "failed to read file for binary detection, skipping");
            unreadable(path, canonical_root, &error)
        }
    }
}

fn unreadable_walk_error(error: &ignore::Error, canonical_root: &Path) -> WalkedEntry {
    let file = unreadable_walk_file(error, canonical_root);
    warn!(path = %file.relative_path, %error, "failed to read directory entry");
    WalkedEntry::Unreadable(file)
}

fn unreadable_walk_file(error: &ignore::Error, canonical_root: &Path) -> UnreadableFile {
    UnreadableFile {
        relative_path: walk_error_key(error, canonical_root),
        reason: walk_error_reason(error),
    }
}

fn walk_error_key(error: &ignore::Error, canonical_root: &Path) -> String {
    let key = failed_path(error)
        .map(|path| relative_key(path, canonical_root))
        .unwrap_or_default();
    if key.is_empty() {
        return PROJECT_ROOT_KEY.to_string();
    }
    key
}

fn failed_path(error: &ignore::Error) -> Option<&Path> {
    match error {
        ignore::Error::WithPath { path, .. } => Some(path.as_path()),
        ignore::Error::WithLineNumber { err, .. } | ignore::Error::WithDepth { err, .. } => {
            failed_path(err)
        }
        ignore::Error::Partial(errors) => errors.iter().find_map(failed_path),
        _ => None,
    }
}

fn walk_error_reason(error: &ignore::Error) -> String {
    match error {
        ignore::Error::WithPath { err, .. } | ignore::Error::WithDepth { err, .. } => {
            walk_error_reason(err)
        }
        ignore::Error::Partial(errors) => errors
            .iter()
            .map(walk_error_reason)
            .collect::<Vec<String>>()
            .join("; "),
        ignore::Error::Io(source) => root_cause_message(source),
        sanitized => sanitized.to_string(),
    }
}

fn unreadable(path: &Path, canonical_root: &Path, error: &dyn std::error::Error) -> WalkedEntry {
    WalkedEntry::Unreadable(UnreadableFile {
        relative_path: relative_key(path, canonical_root),
        reason: root_cause_message(error),
    })
}

fn is_eligible_file(path: &Path, config: &EngineConfig) -> bool {
    !exclusions::is_excluded(path, config)
}

pub fn relative_key(path: &Path, canonical_root: &Path) -> String {
    let relative = path.strip_prefix(canonical_root).unwrap_or(path);
    unicode_path_key(relative).unwrap_or_else(|| non_unicode_path_key(relative))
}

fn unicode_relative_key(path: &Path, canonical_root: &Path) -> Option<String> {
    let relative = path.strip_prefix(canonical_root).unwrap_or(path);
    unicode_path_key(relative)
}

fn unicode_path_key(path: &Path) -> Option<String> {
    path.to_str().map(|value| value.replace('\\', "/"))
}

#[cfg(unix)]
fn non_unicode_path_key(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;

    let mut encoded = String::from("<bytes>:");
    for byte in path.as_os_str().as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'/' | b'.' | b'_' | b'-') {
            encoded.push(char::from(*byte));
        } else {
            push_hex_byte(&mut encoded, *byte);
        }
    }
    encoded
}

#[cfg(windows)]
fn non_unicode_path_key(path: &Path) -> String {
    use std::os::windows::ffi::OsStrExt;

    let mut encoded = String::from("<utf16>:");
    for unit in path.as_os_str().encode_wide() {
        if unit == u16::from(b'\\') {
            encoded.push('/');
        } else if unit <= 0x7f
            && (u8::try_from(unit).unwrap().is_ascii_alphanumeric()
                || matches!(unit as u8, b'/' | b'.' | b'_' | b'-'))
        {
            encoded.push(char::from(unit as u8));
        } else {
            encoded.push('%');
            encoded.push('u');
            for shift in [12, 8, 4, 0] {
                encoded.push(hex_digit(((unit >> shift) & 0x0f) as u8));
            }
        }
    }
    encoded
}

#[cfg(not(any(unix, windows)))]
fn non_unicode_path_key(_path: &Path) -> String {
    "<non-unicode-path>".to_string()
}

#[cfg(unix)]
fn push_hex_byte(output: &mut String, byte: u8) {
    output.push('%');
    output.push(hex_digit(byte >> 4));
    output.push(hex_digit(byte & 0x0f));
}

#[cfg(any(unix, windows))]
fn hex_digit(value: u8) -> char {
    char::from(if value < 10 {
        b'0' + value
    } else {
        b'A' + value - 10
    })
}

fn build_file_entry(path: &Path, relative_path: String, size_bytes: u64) -> FileEntry {
    FileEntry {
        path: path.to_path_buf(),
        relative_path,
        size_bytes,
        language: language::detect(path, None).map(String::from),
    }
}

fn matches_filters(path: &Path, opts: &DiscoverOpts) -> bool {
    if let Some(extensions) = &opts.extensions {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !extensions.iter().any(|e| e == ext) {
            return false;
        }
    }

    if let Some(pattern) = &opts.pattern {
        let filename = path.file_name().and_then(|f| f.to_str()).unwrap_or("");
        if !filename.contains(pattern.as_str()) {
            return false;
        }
    }

    true
}

fn is_binary_file(filesystem: &ProjectFilesystem, path: &Path) -> Result<bool, EngineError> {
    use std::io::Read;

    let project_path = filesystem.project_path(path)?;
    let mut file = filesystem.open_file(&project_path)?;
    let mut buffer = [0u8; BINARY_DETECTION_BUFFER_SIZE];
    let bytes_read = file.read(&mut buffer).map_err(|source| EngineError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(buffer[..bytes_read].contains(&0))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::config::schema::DiscoverySource;
    use std::fs;
    use tempfile::TempDir;

    fn default_config() -> EngineConfig {
        EngineConfig::default()
    }

    fn snapshot_config() -> EngineConfig {
        EngineConfig {
            discovery_source: DiscoverySource::UntrustedSnapshot,
            ..EngineConfig::default()
        }
    }

    fn project_with_ignore_file(dir: &TempDir) {
        fs::write(dir.path().join("visible.rs"), "fn visible() {}\n").unwrap();
        fs::write(dir.path().join("hidden.rs"), "fn hidden() {}\n").unwrap();
        fs::write(dir.path().join(".ignore"), "hidden.rs\n").unwrap();
    }

    #[test]
    fn a_local_scan_honors_repository_ignore_files() {
        let dir = TempDir::new().unwrap();
        project_with_ignore_file(&dir);

        let entries =
            walk_project(dir.path(), &default_config(), &DiscoverOpts::default()).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.relative_path.as_str()).collect();

        assert!(paths.contains(&"visible.rs"));
        assert!(!paths.contains(&"hidden.rs"));
    }

    #[test]
    fn an_untrusted_snapshot_discovers_files_its_own_ignore_files_name() {
        let dir = TempDir::new().unwrap();
        project_with_ignore_file(&dir);

        let entries =
            walk_project(dir.path(), &snapshot_config(), &DiscoverOpts::default()).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.relative_path.as_str()).collect();

        assert!(
            paths.contains(&"hidden.rs"),
            "an ignore file inside an untrusted snapshot must not hide files: {paths:?}"
        );
        assert!(paths.contains(&"visible.rs"));
    }

    fn create_test_project(dir: &TempDir) {
        let src = dir.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("main.rs"), "fn main() {}").unwrap();
        fs::write(src.join("lib.rs"), "pub fn hello() {}").unwrap();
        fs::write(dir.path().join("Cargo.toml"), "[package]").unwrap();
    }

    #[test]
    fn discovers_files_in_project() {
        let dir = TempDir::new().unwrap();
        create_test_project(&dir);

        let entries =
            walk_project(dir.path(), &default_config(), &DiscoverOpts::default()).unwrap();

        assert!(entries.len() >= 3);
        let paths: Vec<&str> = entries.iter().map(|e| e.relative_path.as_str()).collect();
        assert!(paths.contains(&"src/main.rs"));
        assert!(paths.contains(&"src/lib.rs"));
    }

    #[test]
    fn detects_language_for_entries() {
        let dir = TempDir::new().unwrap();
        create_test_project(&dir);

        let entries =
            walk_project(dir.path(), &default_config(), &DiscoverOpts::default()).unwrap();
        let rust_file = entries
            .iter()
            .find(|e| e.relative_path == "src/main.rs")
            .unwrap();

        assert_eq!(rust_file.language.as_deref(), Some("rust"));
    }

    #[test]
    fn filters_by_extension() {
        let dir = TempDir::new().unwrap();
        create_test_project(&dir);

        let opts = DiscoverOpts {
            extensions: Some(vec!["rs".into()]),
            ..Default::default()
        };
        let entries = walk_project(dir.path(), &default_config(), &opts).unwrap();

        assert!(entries.iter().all(|e| e.relative_path.ends_with(".rs")));
    }

    #[test]
    fn respects_max_results() {
        let dir = TempDir::new().unwrap();
        create_test_project(&dir);

        let opts = DiscoverOpts {
            max_results: Some(1),
            ..Default::default()
        };
        let entries = walk_project(dir.path(), &default_config(), &opts).unwrap();

        assert!(entries.len() <= 1);
    }

    #[test]
    fn max_results_returns_alphabetically_first_files() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("z.txt"), "z").unwrap();
        fs::write(dir.path().join("a.txt"), "a").unwrap();
        fs::write(dir.path().join("m.txt"), "m").unwrap();

        let opts = DiscoverOpts {
            max_results: Some(2),
            ..Default::default()
        };
        let entries = walk_project(dir.path(), &default_config(), &opts).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.relative_path.as_str()).collect();

        assert_eq!(paths, vec!["a.txt", "m.txt"]);
    }

    #[test]
    fn skips_unignored_environment_files() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".env"), "API_TOKEN=secret").unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

        let entries =
            walk_project(dir.path(), &default_config(), &DiscoverOpts::default()).unwrap();
        let paths: Vec<&str> = entries
            .iter()
            .map(|entry| entry.relative_path.as_str())
            .collect();

        assert!(!paths.contains(&".env"));
        assert!(paths.contains(&"main.rs"));
    }

    #[test]
    fn skips_binary_files() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("binary.bin"), [0u8, 1, 2, 0, 3]).unwrap();
        fs::write(dir.path().join("text.txt"), "hello world").unwrap();

        let entries =
            walk_project(dir.path(), &default_config(), &DiscoverOpts::default()).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.relative_path.as_str()).collect();

        assert!(!paths.contains(&"binary.bin"));
        assert!(paths.contains(&"text.txt"));
    }

    #[test]
    fn binary_detection_reports_file_open_errors() {
        let dir = TempDir::new().unwrap();
        let filesystem = open_filesystem(&dir);

        let error = is_binary_file(&filesystem, &dir.path().join("missing.rs"))
            .expect_err("missing files must produce an I/O error");

        assert!(matches!(error, EngineError::FileNotFound(_)));
    }

    #[cfg(unix)]
    #[test]
    fn binary_detection_reports_read_errors() {
        let dir = TempDir::new().unwrap();
        let filesystem = open_filesystem(&dir);
        let nested = filesystem.root().as_path().join("nested");
        fs::create_dir(&nested).unwrap();

        let error = is_binary_file(&filesystem, &nested)
            .expect_err("a directory cannot be streamed as a file");

        match error {
            EngineError::NotRegularFile(path) => {
                assert_eq!(path, nested);
            }
            other => panic!("expected a not-a-regular-file error, got {other:?}"),
        }
    }

    #[test]
    fn results_are_sorted_alphabetically() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("z.txt"), "z").unwrap();
        fs::write(dir.path().join("a.txt"), "a").unwrap();
        fs::write(dir.path().join("m.txt"), "m").unwrap();

        let entries =
            walk_project(dir.path(), &default_config(), &DiscoverOpts::default()).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.relative_path.as_str()).collect();

        assert_eq!(paths, vec!["a.txt", "m.txt", "z.txt"]);
    }

    #[test]
    fn preserves_path_case_and_matches_extensions_exactly() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("Source.RS"), "fn upper() {}").unwrap();
        let lowercase_file = if cfg!(windows) {
            "lower.rs"
        } else {
            "source.rs"
        };
        fs::write(dir.path().join(lowercase_file), "fn lower() {}").unwrap();
        let all_entries =
            walk_project(dir.path(), &default_config(), &DiscoverOpts::default()).unwrap();
        let all_paths: Vec<&str> = all_entries
            .iter()
            .map(|entry| entry.relative_path.as_str())
            .collect();
        let options = DiscoverOpts {
            extensions: Some(vec!["rs".to_string()]),
            ..DiscoverOpts::default()
        };

        let filtered_entries = walk_project(dir.path(), &default_config(), &options).unwrap();
        let filtered_paths: Vec<&str> = filtered_entries
            .iter()
            .map(|entry| entry.relative_path.as_str())
            .collect();

        assert_eq!(all_paths, vec!["Source.RS", lowercase_file]);
        assert_eq!(filtered_paths, vec![lowercase_file]);
    }

    #[test]
    fn skips_files_exceeding_max_size() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("small.txt"), "hello").unwrap();
        fs::write(dir.path().join("large.txt"), "x".repeat(2_000_000)).unwrap();

        let entries =
            walk_project(dir.path(), &default_config(), &DiscoverOpts::default()).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.relative_path.as_str()).collect();

        assert!(paths.contains(&"small.txt"));
        assert!(!paths.contains(&"large.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn skips_symlinks_leaving_the_project() {
        let outside = TempDir::new().unwrap();
        let secret = outside.path().join("secret.rs");
        fs::write(&secret, "fn secret() {}").unwrap();

        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();
        std::os::unix::fs::symlink(&secret, dir.path().join("linked.rs")).unwrap();

        let entries =
            walk_project(dir.path(), &default_config(), &DiscoverOpts::default()).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.relative_path.as_str()).collect();

        assert_eq!(paths, vec!["main.rs"]);
    }

    #[cfg(unix)]
    #[test]
    fn keeps_symlinks_resolving_inside_the_project() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();
        std::os::unix::fs::symlink(dir.path().join("main.rs"), dir.path().join("alias.rs"))
            .unwrap();

        let entries =
            walk_project(dir.path(), &default_config(), &DiscoverOpts::default()).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.relative_path.as_str()).collect();

        assert_eq!(paths, vec!["alias.rs", "main.rs"]);
    }

    #[cfg(unix)]
    #[test]
    fn skips_broken_symlinks() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();
        std::os::unix::fs::symlink(dir.path().join("gone.rs"), dir.path().join("dangling.rs"))
            .unwrap();

        let entries =
            walk_project(dir.path(), &default_config(), &DiscoverOpts::default()).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.relative_path.as_str()).collect();

        assert_eq!(paths, vec!["main.rs"]);
    }

    fn open_filesystem(dir: &TempDir) -> ProjectFilesystem {
        ProjectFilesystem::open(ProjectRoot::open(dir.path()).unwrap()).unwrap()
    }

    fn walk(dir: &TempDir) -> ProjectWalk {
        walk_project_with_capability(
            &open_filesystem(dir),
            &default_config(),
            &DiscoverOpts::default(),
        )
        .unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn reports_a_file_it_could_not_read_instead_of_dropping_it() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("open.rs"), "fn open() {}").unwrap();
        let locked = dir.path().join("locked.rs");
        fs::write(&locked, "fn locked() {}").unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();

        let walk = walk(&dir);

        let paths: Vec<&str> = walk
            .files
            .iter()
            .map(|e| e.relative_path.as_str())
            .collect();
        assert_eq!(paths, vec!["open.rs"]);
        let unreadable: Vec<&str> = walk
            .unreadable
            .iter()
            .map(|file| file.relative_path.as_str())
            .collect();
        assert_eq!(unreadable, vec!["locked.rs"]);
        assert!(!walk.unreadable[0].reason.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_broken_symlink_is_excluded_without_being_reported_as_unreadable() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();
        std::os::unix::fs::symlink("missing-target", dir.path().join("dangling.rs")).unwrap();

        let walk = walk(&dir);

        assert_eq!(walk.files.len(), 1);
        assert!(
            walk.unreadable.is_empty(),
            "a broken symlink must not make a scan partial: {:?}",
            walk.unreadable
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_source_paths_are_reported_as_unreadable() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let dir = TempDir::new().unwrap();
        let filename = OsString::from_vec(b"invalid-\xff.rs".to_vec());
        fs::write(dir.path().join(filename), "fn invalid() {}").unwrap();

        let walk = walk(&dir);

        assert!(walk.files.is_empty());
        assert_eq!(walk.unreadable.len(), 1);
        assert_eq!(walk.unreadable[0].relative_path, "<bytes>:invalid-%FF.rs");
        assert_eq!(walk.unreadable[0].reason, "path is not valid UTF-8");
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_path_bytes_are_escaped_as_two_uppercase_hex_digits() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let dir = TempDir::new().unwrap();
        let filename = OsString::from_vec(b"legacy\x0E\xA0.rs".to_vec());
        fs::write(dir.path().join(filename), "fn legacy() {}").unwrap();

        let walk = walk(&dir);

        assert!(walk.files.is_empty());
        let keys: Vec<&str> = walk
            .unreadable
            .iter()
            .map(|file| file.relative_path.as_str())
            .collect();
        assert_eq!(keys, vec!["<bytes>:legacy%0E%A0.rs"]);
    }

    #[test]
    fn an_excluded_or_oversized_file_is_not_reported_as_unreadable() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();
        fs::write(dir.path().join("big.rs"), "x".repeat(2048)).unwrap();
        fs::write(dir.path().join(".env"), "TOKEN=value").unwrap();
        let config = EngineConfig {
            max_file_size_bytes: 1024,
            ..EngineConfig::default()
        };
        let filesystem = open_filesystem(&dir);

        let walk =
            walk_project_with_capability(&filesystem, &config, &DiscoverOpts::default()).unwrap();

        let paths: Vec<&str> = walk
            .files
            .iter()
            .map(|e| e.relative_path.as_str())
            .collect();
        assert_eq!(paths, vec!["main.rs"]);
        assert!(walk.unreadable.is_empty(), "{:?}", walk.unreadable);
    }

    #[test]
    fn a_root_that_cannot_be_resolved_reports_the_requested_path() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("missing");

        let error = walk_project(&missing, &default_config(), &DiscoverOpts::default())
            .expect_err("a root that cannot be resolved must not be walked");

        match error {
            EngineError::Io { path, source } => {
                assert_eq!(path, missing);
                assert!(
                    source.to_string().contains(&missing.display().to_string()),
                    "the failure must name the root that could not be resolved: {source}"
                );
            }
            other => panic!("expected an I/O error, got {other:?}"),
        }
    }

    #[test]
    fn max_depth_stops_the_walk_at_the_requested_level() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("top.rs"), "fn top() {}").unwrap();
        let nested = dir.path().join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("deep.rs"), "fn deep() {}").unwrap();
        let shallow = DiscoverOpts {
            max_depth: Some(1),
            ..DiscoverOpts::default()
        };

        let full = walk_project(dir.path(), &default_config(), &DiscoverOpts::default()).unwrap();
        let limited = walk_project(dir.path(), &default_config(), &shallow).unwrap();

        let full_paths: Vec<&str> = full.iter().map(|e| e.relative_path.as_str()).collect();
        let limited_paths: Vec<&str> = limited.iter().map(|e| e.relative_path.as_str()).collect();
        assert_eq!(full_paths, vec!["nested/deep.rs", "top.rs"]);
        assert_eq!(limited_paths, vec!["top.rs"]);
    }

    #[test]
    fn filters_by_filename_pattern() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("service_test.rs"), "fn matched() {}").unwrap();
        fs::write(dir.path().join("service.rs"), "fn skipped() {}").unwrap();
        let opts = DiscoverOpts {
            pattern: Some("_test".to_string()),
            ..DiscoverOpts::default()
        };

        let entries = walk_project(dir.path(), &default_config(), &opts).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.relative_path.as_str()).collect();

        assert_eq!(paths, vec!["service_test.rs"]);
    }

    #[test]
    fn a_walk_error_that_names_a_path_is_reported_as_unreadable() {
        let dir = TempDir::new().unwrap();
        let filesystem = open_filesystem(&dir);

        let entry = process_entry(
            Err(ignore::Error::WithPath {
                path: filesystem.root().as_path().join("locked"),
                err: Box::new(ignore::Error::WithDepth {
                    depth: 1,
                    err: Box::new(ignore::Error::Io(std::io::Error::from(
                        std::io::ErrorKind::PermissionDenied,
                    ))),
                }),
            }),
            filesystem.root().as_path(),
            &filesystem,
            &default_config(),
            &DiscoverOpts::default(),
        );

        match entry {
            WalkedEntry::Unreadable(file) => {
                assert_eq!(file.report_entry(), "locked (permission denied)");
            }
            _ => panic!("a walk error that names a path must be reported as unreadable"),
        }
    }

    #[test]
    fn a_walk_error_without_a_path_is_reported_against_the_project_root() {
        let dir = TempDir::new().unwrap();
        let filesystem = open_filesystem(&dir);

        let entry = process_entry(
            Err(ignore::Error::WithDepth {
                depth: 0,
                err: Box::new(ignore::Error::Io(std::io::Error::from(
                    std::io::ErrorKind::PermissionDenied,
                ))),
            }),
            filesystem.root().as_path(),
            &filesystem,
            &default_config(),
            &DiscoverOpts::default(),
        );

        match entry {
            WalkedEntry::Unreadable(file) => {
                assert_eq!(file.report_entry(), ". (permission denied)");
            }
            _ => panic!("a walk error without a path must still be reported as unreadable"),
        }
    }

    #[test]
    fn an_unparsable_ignore_file_is_reported_against_that_file() {
        let dir = TempDir::new().unwrap();
        let filesystem = open_filesystem(&dir);

        let entry = process_entry(
            Err(ignore::Error::Partial(vec![ignore::Error::WithPath {
                path: filesystem.root().as_path().join(".gitignore"),
                err: Box::new(ignore::Error::Glob {
                    glob: Some("[".to_string()),
                    err: "unclosed character class".to_string(),
                }),
            }])),
            filesystem.root().as_path(),
            &filesystem,
            &default_config(),
            &DiscoverOpts::default(),
        );

        match entry {
            WalkedEntry::Unreadable(file) => {
                assert_eq!(
                    file.report_entry(),
                    ".gitignore (error parsing glob '[': unclosed character class)",
                    "the report must stay project-relative and carry the glob failure"
                );
            }
            _ => panic!("an unparsable ignore file must be reported as unreadable"),
        }
    }

    #[test]
    fn an_unparsable_nested_ignore_file_makes_the_scan_partial() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join(".gitignore"), "\\\n").unwrap();
        fs::write(nested.join("app.rs"), "fn app() {}").unwrap();

        let walk = walk(&dir);

        let paths: Vec<&str> = walk
            .files
            .iter()
            .map(|e| e.relative_path.as_str())
            .collect();
        let unreadable: Vec<&str> = walk
            .unreadable
            .iter()
            .map(|file| file.relative_path.as_str())
            .collect();
        assert!(paths.contains(&"nested/app.rs"), "{paths:?}");
        assert_eq!(
            unreadable,
            vec!["nested/.gitignore"],
            "ignore rules that failed to load must make the scan partial"
        );
        assert!(!walk.unreadable[0].reason.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_directory_is_reported_instead_of_vanishing_from_the_scan() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("open.rs"), "fn open() {}").unwrap();
        let locked = dir.path().join("locked");
        fs::create_dir(&locked).unwrap();
        fs::write(locked.join("hidden.rs"), "fn hidden() {}").unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();

        let walk = walk(&dir);
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();

        let paths: Vec<&str> = walk
            .files
            .iter()
            .map(|e| e.relative_path.as_str())
            .collect();
        let unreadable: Vec<&str> = walk
            .unreadable
            .iter()
            .map(|file| file.relative_path.as_str())
            .collect();
        assert_eq!(paths, vec!["open.rs"]);
        assert_eq!(
            unreadable,
            vec!["locked"],
            "an unreadable subtree must make the scan partial instead of disappearing"
        );
    }

    #[test]
    fn a_file_whose_size_cannot_be_read_is_reported_as_unreadable() {
        let dir = TempDir::new().unwrap();
        let filesystem = open_filesystem(&dir);
        let path = filesystem.root().as_path().join("locked.rs");
        fs::write(&path, "fn locked() {}").unwrap();

        let entry = classify_entry(
            &path,
            filesystem.root().as_path(),
            &filesystem,
            &default_config(),
            &DiscoverOpts::default(),
            &|| {
                Err(ignore::Error::Io(std::io::Error::from(
                    std::io::ErrorKind::PermissionDenied,
                )))
            },
        );

        match entry {
            WalkedEntry::Unreadable(file) => {
                assert_eq!(file.relative_path, "locked.rs");
                assert_eq!(file.reason, "permission denied");
            }
            _ => panic!("a file whose size cannot be read must be reported as unreadable"),
        }
    }

    fn walk_within(dir: &TempDir, limits: WalkLimits) -> Result<ProjectWalk, EngineError> {
        walk_project_within_limits(
            &open_filesystem(dir),
            &default_config(),
            &DiscoverOpts::default(),
            limits,
        )
    }

    fn exhausted_resource(error: EngineError) -> (&'static str, u64) {
        match error {
            EngineError::DiscoveryLimitExceeded { resource, limit } => (resource, limit),
            other => panic!("expected a discovery limit failure, got {other:?}"),
        }
    }

    fn project_with_three_files() -> TempDir {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("a.rs"), "fn a() {}").unwrap();
        fs::write(dir.path().join("b.rs"), "fn b() {}").unwrap();
        fs::write(dir.path().join("c.rs"), "fn c() {}").unwrap();
        dir
    }

    #[test]
    fn visiting_stops_at_the_entry_past_the_visited_entry_limit() {
        let dir = project_with_three_files();

        let accepted = walk_within(
            &dir,
            WalkLimits {
                visited_entries: 4,
                ..WalkLimits::default()
            },
        )
        .expect("the root plus three files must fit a limit of four visits");
        let rejected = walk_within(
            &dir,
            WalkLimits {
                visited_entries: 3,
                ..WalkLimits::default()
            },
        )
        .expect_err("the fourth visited entry must be rejected");

        assert_eq!(accepted.files.len(), 3);
        assert_eq!(exhausted_resource(rejected), (VISITED_ENTRIES, 3));
    }

    #[test]
    fn retaining_stops_at_the_file_past_the_file_limit() {
        let dir = project_with_three_files();

        let accepted = walk_within(
            &dir,
            WalkLimits {
                files: 3,
                ..WalkLimits::default()
            },
        )
        .expect("three files must fit a limit of three");
        let rejected = walk_within(
            &dir,
            WalkLimits {
                files: 2,
                ..WalkLimits::default()
            },
        )
        .expect_err("the third retained file must be rejected");

        assert_eq!(accepted.files.len(), 3);
        assert_eq!(exhausted_resource(rejected), (DISCOVERED_FILES, 2));
    }

    #[test]
    fn retained_path_bytes_count_the_absolute_and_the_relative_form() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("only.rs"), "fn only() {}").unwrap();
        let filesystem = open_filesystem(&dir);
        let absolute = filesystem.root().as_path().join("only.rs");
        let exact = absolute.as_os_str().len() + "only.rs".len();

        let accepted = walk_within(
            &dir,
            WalkLimits {
                retained_path_bytes: exact,
                ..WalkLimits::default()
            },
        )
        .expect("the exact retained path byte cost must be accepted");
        let rejected = walk_within(
            &dir,
            WalkLimits {
                retained_path_bytes: exact - 1,
                ..WalkLimits::default()
            },
        )
        .expect_err("one byte below the retained path cost must be rejected");

        assert_eq!(accepted.files.len(), 1);
        assert_eq!(
            exhausted_resource(rejected),
            (RETAINED_PATH_BYTES, exact as u64 - 1)
        );
    }

    #[test]
    fn included_source_bytes_are_capped_across_every_retained_file() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("a.rs"), "ab").unwrap();
        fs::write(dir.path().join("b.rs"), "cde").unwrap();

        let accepted = walk_within(
            &dir,
            WalkLimits {
                included_source_bytes: 5,
                ..WalkLimits::default()
            },
        )
        .expect("five bytes of source must fit a limit of five");
        let rejected = walk_within(
            &dir,
            WalkLimits {
                included_source_bytes: 4,
                ..WalkLimits::default()
            },
        )
        .expect_err("the byte past the limit must be rejected");

        assert_eq!(accepted.files.len(), 2);
        assert_eq!(exhausted_resource(rejected), (INCLUDED_SOURCE_BYTES, 4));
    }

    fn project_with_two_broken_ignore_files() -> TempDir {
        let dir = TempDir::new().unwrap();
        for name in ["one", "two"] {
            let nested = dir.path().join(name);
            fs::create_dir(&nested).unwrap();
            fs::write(nested.join(".gitignore"), "\\\n").unwrap();
            fs::write(nested.join("app.rs"), "fn app() {}").unwrap();
        }
        dir
    }

    #[test]
    fn retaining_stops_at_the_diagnostic_past_the_diagnostic_limit() {
        let dir = project_with_two_broken_ignore_files();

        let accepted = walk_within(
            &dir,
            WalkLimits {
                unreadable_diagnostics: 2,
                ..WalkLimits::default()
            },
        )
        .expect("two broken ignore files must fit a limit of two diagnostics");
        let rejected = walk_within(
            &dir,
            WalkLimits {
                unreadable_diagnostics: 1,
                ..WalkLimits::default()
            },
        )
        .expect_err("the second diagnostic must be rejected");

        let reported: Vec<&str> = accepted
            .unreadable
            .iter()
            .map(|file| file.relative_path.as_str())
            .collect();
        assert_eq!(reported, vec!["one/.gitignore", "two/.gitignore"]);
        assert_eq!(exhausted_resource(rejected), (UNREADABLE_DIAGNOSTICS, 1));
    }

    #[test]
    fn retaining_stops_at_the_diagnostic_byte_past_the_byte_limit() {
        let dir = project_with_two_broken_ignore_files();
        let unbounded = walk_within(&dir, WalkLimits::default()).unwrap();
        let exact: usize = unbounded
            .unreadable
            .iter()
            .map(|file| file.relative_path.len() + file.reason.len())
            .sum();

        let accepted = walk_within(
            &dir,
            WalkLimits {
                unreadable_diagnostic_bytes: exact,
                ..WalkLimits::default()
            },
        )
        .expect("the exact diagnostic byte cost must be accepted");
        let rejected = walk_within(
            &dir,
            WalkLimits {
                unreadable_diagnostic_bytes: exact - 1,
                ..WalkLimits::default()
            },
        )
        .expect_err("one byte below the diagnostic cost must be rejected");

        assert_eq!(accepted.unreadable.len(), 2);
        assert_eq!(
            exhausted_resource(rejected),
            (UNREADABLE_DIAGNOSTIC_BYTES, exact as u64 - 1)
        );
    }

    #[test]
    fn an_exhausted_ignore_pattern_budget_fails_the_walk() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".ignore"), "hidden.rs\n").unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

        let rejected = walk_within(
            &dir,
            WalkLimits {
                ignore: IgnoreLimits {
                    patterns: 0,
                    ..IgnoreLimits::default()
                },
                ..WalkLimits::default()
            },
        )
        .expect_err("an ignore rule past the pattern budget must fail the walk");

        assert_eq!(
            exhausted_resource(rejected),
            (exclusions::IGNORE_PATTERNS, 0)
        );
    }

    #[test]
    fn an_oversized_ignore_line_fails_the_walk() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".ignore"), format!("{}\n", "a".repeat(17))).unwrap();

        let rejected = walk_within(
            &dir,
            WalkLimits {
                ignore: IgnoreLimits {
                    line_bytes: 16,
                    ..IgnoreLimits::default()
                },
                ..WalkLimits::default()
            },
        )
        .expect_err("an ignore line past the physical line budget must fail the walk");

        assert_eq!(
            exhausted_resource(rejected),
            (exclusions::IGNORE_LINE_BYTES, 16)
        );
    }

    #[test]
    fn a_nested_negation_reinstates_a_file_the_root_ignored() {
        let dir = TempDir::new().unwrap();
        fs::create_dir(dir.path().join("src")).unwrap();
        fs::write(dir.path().join(".ignore"), "*.txt\n").unwrap();
        fs::write(dir.path().join("src/.ignore"), "!allowed.txt\n").unwrap();
        fs::write(dir.path().join("blocked.txt"), "blocked").unwrap();
        fs::write(dir.path().join("src/allowed.txt"), "allowed").unwrap();
        let text_files = DiscoverOpts {
            extensions: Some(vec!["txt".to_string()]),
            ..DiscoverOpts::default()
        };

        let entries = walk_project(dir.path(), &default_config(), &text_files).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.relative_path.as_str()).collect();

        assert_eq!(paths, vec!["src/allowed.txt"]);
    }

    #[test]
    fn a_parent_ignore_file_above_the_project_root_still_applies() {
        let outer = TempDir::new().unwrap();
        fs::write(outer.path().join(".ignore"), "hidden.rs\n").unwrap();
        let project = outer.path().join("project");
        fs::create_dir(&project).unwrap();
        fs::write(project.join("hidden.rs"), "fn hidden() {}").unwrap();
        fs::write(project.join("visible.rs"), "fn visible() {}").unwrap();

        let entries = walk_project(&project, &default_config(), &DiscoverOpts::default()).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.relative_path.as_str()).collect();

        assert_eq!(paths, vec!["visible.rs"]);
    }

    #[test]
    fn max_results_keeps_the_alphabetically_first_files_across_directories() {
        let dir = TempDir::new().unwrap();
        fs::create_dir(dir.path().join("zeta")).unwrap();
        fs::create_dir(dir.path().join("alpha")).unwrap();
        fs::write(dir.path().join("zeta/one.rs"), "fn one() {}").unwrap();
        fs::write(dir.path().join("alpha/two.rs"), "fn two() {}").unwrap();
        fs::write(dir.path().join("middle.rs"), "fn middle() {}").unwrap();
        let opts = DiscoverOpts {
            max_results: Some(2),
            ..DiscoverOpts::default()
        };

        let entries = walk_project(dir.path(), &default_config(), &opts).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.relative_path.as_str()).collect();

        assert_eq!(paths, vec!["alpha/two.rs", "middle.rs"]);
    }

    #[test]
    fn unreadable_diagnostics_are_reported_in_a_deterministic_order() {
        let dir = project_with_two_broken_ignore_files();

        let first = walk_within(&dir, WalkLimits::default()).unwrap();
        let second = walk_within(&dir, WalkLimits::default()).unwrap();

        let order: Vec<&str> = first
            .unreadable
            .iter()
            .map(|file| file.relative_path.as_str())
            .collect();
        assert_eq!(order, vec!["one/.gitignore", "two/.gitignore"]);
        assert_eq!(
            order,
            second
                .unreadable
                .iter()
                .map(|file| file.relative_path.as_str())
                .collect::<Vec<&str>>()
        );
    }
}
