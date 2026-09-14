use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use ignore::Match;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use tracing::warn;

use crate::config::EngineConfig;

const SENSITIVE_FILENAMES: &[&str] = &[
    ".env",
    ".envrc",
    ".git-credentials",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
];

const PROTECTED_DIRS: &[&str] = &[".git", ".aws", ".ssh", ".gnupg"];

pub fn is_excluded(path: &Path, config: &EngineConfig) -> bool {
    has_protected_component(path)
        || has_excluded_ancestor(path, config)
        || has_excluded_extension(path, config)
        || has_sensitive_filename(path)
}

pub fn escapes_project_root(path: &Path, canonical_root: &Path) -> bool {
    match std::fs::canonicalize(path) {
        Ok(resolved) => !resolved.starts_with(canonical_root),
        Err(error) => {
            warn!(path = %path.display(), %error, "failed to resolve path against project root, skipping");
            true
        }
    }
}

pub const MAX_IGNORE_SOURCE_BYTES: usize = 1024 * 1024;
pub const MAX_IGNORE_LINE_BYTES: usize = 16 * 1024;
pub const MAX_IGNORE_PATTERNS: usize = 100_000;
pub const MAX_IGNORE_PATTERN_BYTES: usize = 16 * 1024 * 1024;

pub const IGNORE_SOURCE_BYTES: &str = "ignore source bytes";
pub const IGNORE_LINE_BYTES: &str = "ignore line bytes";
pub const IGNORE_PATTERNS: &str = "ignore patterns";
pub const IGNORE_PATTERN_BYTES: &str = "ignore pattern bytes";
pub const GLOBAL_GIT_CONFIG_BYTES: &str = "global git configuration bytes";
pub const GLOBAL_GIT_CONFIG_LINE_BYTES: &str = "global git configuration line bytes";
pub const GLOBAL_EXCLUDES_PATH_BYTES: &str = "global excludes path bytes";

const IGNORE_FILENAME: &str = ".ignore";
const GITIGNORE_FILENAME: &str = ".gitignore";
const GIT_MARKER: &str = ".git";
const JUJUTSU_MARKER: &str = ".jj";
const GIT_INFO_EXCLUDE: &str = "info/exclude";
const GIT_COMMON_DIR_FILE: &str = "commondir";
const GIT_DIR_REDIRECT_PREFIX: &str = "gitdir: ";
const EXCLUDES_FILE_KEY: &str = "excludesfile";
const UTF8_BOM: &str = "\u{feff}";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IgnoreLimits {
    pub source_bytes: usize,
    pub line_bytes: usize,
    pub patterns: usize,
    pub pattern_bytes: usize,
}

impl Default for IgnoreLimits {
    fn default() -> Self {
        Self {
            source_bytes: MAX_IGNORE_SOURCE_BYTES,
            line_bytes: MAX_IGNORE_LINE_BYTES,
            patterns: MAX_IGNORE_PATTERNS,
            pattern_bytes: MAX_IGNORE_PATTERN_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExhaustedIgnoreLimit {
    pub resource: &'static str,
    pub limit: usize,
}

impl ExhaustedIgnoreLimit {
    fn new(resource: &'static str, limit: usize) -> Self {
        Self { resource, limit }
    }
}

pub struct IgnoreRuleFailure {
    pub source: PathBuf,
    pub error: ignore::Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IgnoreRuleModel {
    ProjectWalk,
    PathQuery,
}

impl IgnoreRuleModel {
    fn starts_inside_checkout(self) -> bool {
        self == Self::PathQuery
    }

    fn spans_directories_above_root(self) -> bool {
        self == Self::ProjectWalk
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IgnoreVerdict {
    Undecided,
    Ignore,
    Whitelist,
}

impl IgnoreVerdict {
    fn of<T>(matched: Match<T>) -> Self {
        match matched {
            Match::None => Self::Undecided,
            Match::Ignore(_) => Self::Ignore,
            Match::Whitelist(_) => Self::Whitelist,
        }
    }

    fn is_undecided(self) -> bool {
        self == Self::Undecided
    }

    fn or(self, fallback: Self) -> Self {
        if self.is_undecided() { fallback } else { self }
    }
}

struct DirectoryIgnoreRules {
    ignore: Gitignore,
    git_ignore: Gitignore,
    git_exclude: Gitignore,
    has_checkout_marker: bool,
}

#[derive(Default)]
struct IgnoreRuleState {
    accepted_patterns: usize,
    accepted_pattern_bytes: usize,
    directories: HashMap<PathBuf, Arc<DirectoryIgnoreRules>>,
    global: Option<Arc<Gitignore>>,
    failures: Vec<IgnoreRuleFailure>,
    exhausted: Option<ExhaustedIgnoreLimit>,
}

pub struct RepositoryIgnoreRules {
    root: PathBuf,
    limits: IgnoreLimits,
    model: IgnoreRuleModel,
    honors_ignore_files: bool,
    state: Mutex<IgnoreRuleState>,
}

impl RepositoryIgnoreRules {
    pub fn for_walk(root: &Path, config: &EngineConfig, limits: IgnoreLimits) -> Arc<Self> {
        let rules = Arc::new(Self::new(
            root,
            config,
            limits,
            IgnoreRuleModel::ProjectWalk,
        ));
        rules.load_root_chain();
        rules
    }

    pub fn for_path_query(root: &Path, config: &EngineConfig, limits: IgnoreLimits) -> Self {
        let rules = Self::new(root, config, limits, IgnoreRuleModel::PathQuery);
        rules.load_root_chain();
        rules
    }

    fn new(
        root: &Path,
        config: &EngineConfig,
        limits: IgnoreLimits,
        model: IgnoreRuleModel,
    ) -> Self {
        Self {
            root: root.to_path_buf(),
            limits,
            model,
            honors_ignore_files: config.discovery_source.honors_repository_ignore_files(),
            state: Mutex::new(IgnoreRuleState::default()),
        }
    }

    pub fn honors_ignore_files(&self) -> bool {
        self.honors_ignore_files
    }

    pub fn exhausted(&self) -> Option<ExhaustedIgnoreLimit> {
        self.state().exhausted
    }

    pub fn take_failures(&self) -> Vec<IgnoreRuleFailure> {
        std::mem::take(&mut self.state().failures)
    }

    pub fn admits(&self, path: &Path, is_dir: bool) -> bool {
        self.verdict(path, is_dir) != IgnoreVerdict::Ignore
    }

    pub fn load_directory(&self, directory: &Path) {
        if !self.honors_ignore_files {
            return;
        }
        let mut state = self.state();
        self.directory_rules(&mut state, directory);
    }

    pub fn ignores_path_or_ancestor(&self, path: &Path) -> bool {
        if !self.honors_ignore_files {
            return false;
        }
        let Some(parent) = path.parent() else {
            return !self.admits(path, false);
        };
        let Ok(relative_parent) = parent.strip_prefix(&self.root) else {
            return true;
        };
        let mut directory = self.root.clone();
        for component in relative_parent.components() {
            directory.push(component);
            if !self.admits(&directory, true) {
                return true;
            }
        }
        !self.admits(path, false)
    }

    fn state(&self) -> MutexGuard<'_, IgnoreRuleState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn load_root_chain(&self) {
        if !self.honors_ignore_files {
            return;
        }
        let mut state = self.state();
        for directory in self.rule_directories_from(&self.root) {
            if self.directory_rules(&mut state, directory).is_none() {
                return;
            }
        }
    }

    fn rule_directories_from<'a>(&self, directory: &'a Path) -> impl Iterator<Item = &'a Path> {
        let spans_above_root = self.model.spans_directories_above_root();
        let root = self.root.as_path();
        directory
            .ancestors()
            .take_while(move |candidate| spans_above_root || candidate.starts_with(root))
    }

    fn verdict(&self, path: &Path, is_dir: bool) -> IgnoreVerdict {
        if !self.honors_ignore_files {
            return IgnoreVerdict::Undecided;
        }
        let Some(parent) = path.parent() else {
            return IgnoreVerdict::Undecided;
        };
        let mut state = self.state();
        if state.exhausted.is_some() {
            return IgnoreVerdict::Undecided;
        }
        let mut inside_checkout = self.model.starts_inside_checkout();
        let mut rules_by_directory = Vec::new();
        for directory in self.rule_directories_from(parent) {
            let Some(rules) = self.directory_rules(&mut state, directory) else {
                return IgnoreVerdict::Undecided;
            };
            inside_checkout = inside_checkout || rules.has_checkout_marker;
            rules_by_directory.push(rules);
        }
        let mut ignore = IgnoreVerdict::Undecided;
        let mut git_ignore = IgnoreVerdict::Undecided;
        let mut git_exclude = IgnoreVerdict::Undecided;
        let mut passed_checkout_root = false;
        for rules in rules_by_directory {
            if ignore.is_undecided() {
                ignore = IgnoreVerdict::of(rules.ignore.matched(path, is_dir));
            }
            if inside_checkout && !passed_checkout_root {
                if git_ignore.is_undecided() {
                    git_ignore = IgnoreVerdict::of(rules.git_ignore.matched(path, is_dir));
                }
                if git_exclude.is_undecided() {
                    git_exclude = IgnoreVerdict::of(rules.git_exclude.matched(path, is_dir));
                }
            }
            passed_checkout_root = passed_checkout_root || rules.has_checkout_marker;
        }
        let global = if inside_checkout {
            self.global_rules(&mut state)
                .map(|global| IgnoreVerdict::of(global.matched(path, is_dir)))
        } else {
            Some(IgnoreVerdict::Undecided)
        };
        combine_ignore_verdicts(ignore, git_ignore, git_exclude, global)
    }

    fn directory_rules(
        &self,
        state: &mut IgnoreRuleState,
        directory: &Path,
    ) -> Option<Arc<DirectoryIgnoreRules>> {
        if let Some(rules) = state.directories.get(directory) {
            return Some(Arc::clone(rules));
        }
        match self.load_directory_rules(state, directory) {
            Ok(rules) => {
                let rules = Arc::new(rules);
                state
                    .directories
                    .insert(directory.to_path_buf(), Arc::clone(&rules));
                Some(rules)
            }
            Err(exhausted) => {
                state.exhausted = Some(exhausted);
                None
            }
        }
    }

    fn load_directory_rules(
        &self,
        state: &mut IgnoreRuleState,
        directory: &Path,
    ) -> Result<DirectoryIgnoreRules, ExhaustedIgnoreLimit> {
        let ignore = self.load_matcher(state, directory, &directory.join(IGNORE_FILENAME))?;
        let git_ignore =
            self.load_matcher(state, directory, &directory.join(GITIGNORE_FILENAME))?;
        let git_marker = directory.join(GIT_MARKER);
        let has_git_marker = git_marker.exists();
        let git_exclude = match has_git_marker {
            true => match resolve_git_common_directory(&git_marker, self.limits)? {
                Some(common_directory) => {
                    self.load_matcher(state, directory, &common_directory.join(GIT_INFO_EXCLUDE))?
                }
                None => Gitignore::empty(),
            },
            false => Gitignore::empty(),
        };
        Ok(DirectoryIgnoreRules {
            ignore,
            git_ignore,
            git_exclude,
            has_checkout_marker: has_git_marker || directory.join(JUJUTSU_MARKER).exists(),
        })
    }

    fn global_rules(&self, state: &mut IgnoreRuleState) -> Option<Arc<Gitignore>> {
        if let Some(global) = &state.global {
            return Some(Arc::clone(global));
        }
        self.global_rules_from(state, global_excludes_path(self.limits))
    }

    fn global_rules_from(
        &self,
        state: &mut IgnoreRuleState,
        source: Result<Option<PathBuf>, ExhaustedIgnoreLimit>,
    ) -> Option<Arc<Gitignore>> {
        match source.and_then(|source| self.load_global_rules(state, source.as_deref())) {
            Ok(global) => {
                let global = Arc::new(global);
                state.global = Some(Arc::clone(&global));
                Some(global)
            }
            Err(exhausted) => {
                state.exhausted = Some(exhausted);
                None
            }
        }
    }

    fn load_global_rules(
        &self,
        state: &mut IgnoreRuleState,
        source: Option<&Path>,
    ) -> Result<Gitignore, ExhaustedIgnoreLimit> {
        let Some(source) = source else {
            return Ok(Gitignore::empty());
        };
        if !source.is_file() {
            return Ok(Gitignore::empty());
        }
        self.load_matcher(state, &self.root, source)
    }

    fn load_matcher(
        &self,
        state: &mut IgnoreRuleState,
        matcher_root: &Path,
        source: &Path,
    ) -> Result<Gitignore, ExhaustedIgnoreLimit> {
        let Some(contents) = read_bounded(source, self.limits.source_bytes, IGNORE_SOURCE_BYTES)?
        else {
            return Ok(Gitignore::empty());
        };
        let mut builder = GitignoreBuilder::new(matcher_root);
        let line_failure = self.add_bounded_patterns(state, &mut builder, source, &contents)?;
        let (matcher, failure) = resolve_matcher_build(builder.build(), line_failure);
        if let Some(error) = failure {
            state.failures.push(IgnoreRuleFailure {
                source: source.to_path_buf(),
                error,
            });
        }
        Ok(matcher)
    }

    fn add_bounded_patterns(
        &self,
        state: &mut IgnoreRuleState,
        builder: &mut GitignoreBuilder,
        source: &Path,
        contents: &[u8],
    ) -> Result<Option<ignore::Error>, ExhaustedIgnoreLimit> {
        let mut failure = None;
        for (index, physical_line) in physical_lines(contents).enumerate() {
            if physical_line.len() > self.limits.line_bytes {
                return Err(ExhaustedIgnoreLimit::new(
                    IGNORE_LINE_BYTES,
                    self.limits.line_bytes,
                ));
            }
            let Ok(text) = std::str::from_utf8(strip_carriage_return(physical_line)) else {
                return Ok(Some(undecodable_line_error(index + 1)));
            };
            let text = match index {
                0 => text.trim_start_matches(UTF8_BOM),
                _ => text,
            };
            let Some(pattern) = retained_pattern(text) else {
                continue;
            };
            if state.accepted_patterns + 1 > self.limits.patterns {
                return Err(ExhaustedIgnoreLimit::new(
                    IGNORE_PATTERNS,
                    self.limits.patterns,
                ));
            }
            let accepted_pattern_bytes = state.accepted_pattern_bytes + pattern.len();
            if accepted_pattern_bytes > self.limits.pattern_bytes {
                return Err(ExhaustedIgnoreLimit::new(
                    IGNORE_PATTERN_BYTES,
                    self.limits.pattern_bytes,
                ));
            }
            if let Err(error) = builder.add_line(Some(source.to_path_buf()), text) {
                failure = failure.or(Some(error));
                continue;
            }
            state.accepted_patterns += 1;
            state.accepted_pattern_bytes = accepted_pattern_bytes;
        }
        Ok(failure)
    }
}

fn resolve_matcher_build(
    result: Result<Gitignore, ignore::Error>,
    line_failure: Option<ignore::Error>,
) -> (Gitignore, Option<ignore::Error>) {
    match result {
        Ok(matcher) => (matcher, line_failure),
        Err(error) => (Gitignore::empty(), line_failure.or(Some(error))),
    }
}

fn combine_ignore_verdicts(
    ignore: IgnoreVerdict,
    git_ignore: IgnoreVerdict,
    git_exclude: IgnoreVerdict,
    global: Option<IgnoreVerdict>,
) -> IgnoreVerdict {
    let Some(global) = global else {
        return IgnoreVerdict::Undecided;
    };
    ignore.or(git_ignore).or(git_exclude).or(global)
}

fn physical_lines(contents: &[u8]) -> impl Iterator<Item = &[u8]> {
    (!contents.is_empty())
        .then(|| contents.strip_suffix(b"\n").unwrap_or(contents))
        .into_iter()
        .flat_map(|body| body.split(|byte| *byte == b'\n'))
}

fn strip_carriage_return(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn retained_pattern(line: &str) -> Option<&str> {
    if line.starts_with('#') {
        return None;
    }
    let pattern = match line.ends_with("\\ ") {
        true => line,
        false => line.trim_end(),
    };
    (!pattern.is_empty()).then_some(pattern)
}

fn undecodable_line_error(line_number: usize) -> ignore::Error {
    ignore::Error::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("ignore rule on line {line_number} is not valid UTF-8"),
    ))
}

fn read_bounded(
    path: &Path,
    limit: usize,
    resource: &'static str,
) -> Result<Option<Vec<u8>>, ExhaustedIgnoreLimit> {
    let Ok(file) = std::fs::File::open(path) else {
        return Ok(None);
    };
    let mut contents = Vec::new();
    if file
        .take(limit as u64 + 1)
        .read_to_end(&mut contents)
        .is_err()
    {
        return Ok(None);
    }
    if contents.len() > limit {
        return Err(ExhaustedIgnoreLimit::new(resource, limit));
    }
    Ok(Some(contents))
}

fn bounded_first_line<'a>(
    contents: &'a [u8],
    limit: usize,
    resource: &'static str,
) -> Result<Option<&'a str>, ExhaustedIgnoreLimit> {
    let Some(line) = physical_lines(contents).next() else {
        return Ok(None);
    };
    if line.len() > limit {
        return Err(ExhaustedIgnoreLimit::new(resource, limit));
    }
    Ok(std::str::from_utf8(strip_carriage_return(line)).ok())
}

fn resolve_git_common_directory(
    git_marker: &Path,
    limits: IgnoreLimits,
) -> Result<Option<PathBuf>, ExhaustedIgnoreLimit> {
    if git_marker.is_dir() {
        return Ok(Some(git_marker.to_path_buf()));
    }
    let Some(contents) = read_bounded(git_marker, limits.source_bytes, IGNORE_SOURCE_BYTES)? else {
        return Ok(None);
    };
    let Some(redirect) = bounded_first_line(&contents, limits.line_bytes, IGNORE_LINE_BYTES)?
        .and_then(|line| line.strip_prefix(GIT_DIR_REDIRECT_PREFIX))
    else {
        return Ok(None);
    };
    let git_directory = PathBuf::from(redirect);
    let common_directory_file = git_directory.join(GIT_COMMON_DIR_FILE);
    let Some(contents) = read_bounded(
        &common_directory_file,
        limits.source_bytes,
        IGNORE_SOURCE_BYTES,
    )?
    else {
        return Ok(None);
    };
    let Some(common_directory) =
        bounded_first_line(&contents, limits.line_bytes, IGNORE_LINE_BYTES)?
    else {
        return Ok(None);
    };
    Ok(Some(match common_directory.starts_with('.') {
        true => git_directory.join(common_directory),
        false => PathBuf::from(common_directory),
    }))
}

fn global_excludes_path(limits: IgnoreLimits) -> Result<Option<PathBuf>, ExhaustedIgnoreLimit> {
    let home = home_directory();
    let candidates = global_git_config_paths(home.as_deref());
    Ok(
        configured_excludes_path(&candidates, home.as_deref(), limits)?
            .or_else(|| default_excludes_path(home.as_deref())),
    )
}

fn configured_excludes_path(
    candidates: &[PathBuf],
    home: Option<&Path>,
    limits: IgnoreLimits,
) -> Result<Option<PathBuf>, ExhaustedIgnoreLimit> {
    for candidate in candidates {
        let Some(contents) = read_bounded(candidate, limits.source_bytes, GLOBAL_GIT_CONFIG_BYTES)?
        else {
            continue;
        };
        if let Some(configured) = excludes_path_from_config(&contents, home, limits)? {
            return Ok(Some(configured));
        }
    }
    Ok(None)
}

fn global_git_config_paths(home: Option<&Path>) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    candidates.extend(non_empty_environment_path("GIT_CONFIG_GLOBAL"));
    candidates.extend(home.map(|home| home.join(".gitconfig")));
    candidates.extend(git_config_home(home).map(|directory| directory.join("git/config")));
    candidates.push(
        non_empty_environment_path("GIT_CONFIG_SYSTEM")
            .unwrap_or_else(|| PathBuf::from("/etc/gitconfig")),
    );
    candidates
}

fn default_excludes_path(home: Option<&Path>) -> Option<PathBuf> {
    git_config_home(home).map(|directory| directory.join("git/ignore"))
}

fn git_config_home(home: Option<&Path>) -> Option<PathBuf> {
    non_empty_environment_path("XDG_CONFIG_HOME").or_else(|| home.map(|home| home.join(".config")))
}

fn non_empty_environment_path(key: &str) -> Option<PathBuf> {
    non_empty_path(std::env::var_os(key))
}

fn non_empty_path(value: Option<std::ffi::OsString>) -> Option<PathBuf> {
    match value {
        Some(value) if !value.is_empty() => Some(PathBuf::from(value)),
        _ => None,
    }
}

fn home_directory() -> Option<PathBuf> {
    directories::BaseDirs::new().map(|directories| directories.home_dir().to_path_buf())
}

fn excludes_path_from_config(
    contents: &[u8],
    home: Option<&Path>,
    limits: IgnoreLimits,
) -> Result<Option<PathBuf>, ExhaustedIgnoreLimit> {
    for line in physical_lines(contents) {
        if line.len() > limits.line_bytes {
            return Err(ExhaustedIgnoreLimit::new(
                GLOBAL_GIT_CONFIG_LINE_BYTES,
                limits.line_bytes,
            ));
        }
        let Ok(text) = std::str::from_utf8(strip_carriage_return(line)) else {
            continue;
        };
        let Some(value) = excludes_file_value(text) else {
            continue;
        };
        let expanded = expand_home(value, home);
        if expanded.len() > limits.line_bytes {
            return Err(ExhaustedIgnoreLimit::new(
                GLOBAL_EXCLUDES_PATH_BYTES,
                limits.line_bytes,
            ));
        }
        return Ok(Some(PathBuf::from(expanded)));
    }
    Ok(None)
}

fn excludes_file_value(line: &str) -> Option<&str> {
    let assignment = strip_prefix_ignoring_ascii_case(line.trim_start(), EXCLUDES_FILE_KEY)?;
    let value = assignment.trim_start().strip_prefix('=')?.trim();
    let value = value.strip_prefix('"').unwrap_or(value).trim_start();
    let value = value.strip_suffix('"').unwrap_or(value).trim_end();
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return None;
    }
    Some(value)
}

fn strip_prefix_ignoring_ascii_case<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let (head, rest) = text.split_at_checked(prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then_some(rest)
}

fn expand_home(value: &str, home: Option<&Path>) -> String {
    match home {
        Some(home) => value.replace('~', &home.to_string_lossy()),
        None => value.to_string(),
    }
}

pub fn is_git_ignored(project_root: &Path, path: &Path, config: &EngineConfig) -> bool {
    RepositoryIgnoreRules::for_path_query(project_root, config, IgnoreLimits::default())
        .ignores_path_or_ancestor(path)
}

pub fn has_excluded_ancestor(path: &Path, config: &EngineConfig) -> bool {
    has_matching_component(path, |name| {
        config.exclude_dirs.iter().any(|excluded| excluded == name)
    })
}

fn has_protected_component(path: &Path) -> bool {
    has_matching_component(path, |name| {
        PROTECTED_DIRS
            .iter()
            .any(|protected| name.eq_ignore_ascii_case(protected))
    })
}

fn has_matching_component(path: &Path, matches: impl Fn(&str) -> bool) -> bool {
    path.components().any(|component| match component {
        std::path::Component::Normal(name) => matches(name.to_string_lossy().as_ref()),
        _ => false,
    })
}

fn has_sensitive_filename(path: &Path) -> bool {
    let Some(filename) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    SENSITIVE_FILENAMES.contains(&filename) || filename.starts_with(".env.")
}

const EXCLUDED_FILENAME_SUFFIXES: &[&str] = &[".min.js", ".min.css", ".bundle.js"];

pub fn has_excluded_extension(path: &Path, config: &EngineConfig) -> bool {
    if let Some(filename) = path.file_name().and_then(|f| f.to_str()) {
        let filename_lower = filename.to_lowercase();
        if EXCLUDED_FILENAME_SUFFIXES
            .iter()
            .any(|suffix| filename_lower.ends_with(suffix))
        {
            return true;
        }
    }

    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };

    let ext_lower = ext.to_lowercase();
    config
        .exclude_extensions
        .iter()
        .any(|excluded| excluded == &ext_lower)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::config::schema::DiscoverySource;
    use std::path::Path;

    fn default_config() -> EngineConfig {
        EngineConfig::default()
    }

    #[test]
    fn detects_git_ancestor() {
        let path = Path::new("/project/.git/hooks/pre-commit");
        assert!(has_excluded_ancestor(path, &default_config()));
    }

    #[test]
    fn detects_node_modules_ancestor() {
        let path = Path::new("/project/node_modules/pkg/index.js");
        assert!(has_excluded_ancestor(path, &default_config()));
    }

    #[test]
    fn default_config_allows_rust_binary_sources() {
        let path = Path::new("/project/src/bin/server.rs");
        assert!(!has_excluded_ancestor(path, &default_config()));
    }

    #[test]
    fn allows_normal_paths() {
        let path = Path::new("/project/src/main.rs");
        assert!(!has_excluded_ancestor(path, &default_config()));
    }

    #[test]
    fn excludes_sensitive_paths() {
        let config = default_config();

        assert!(is_excluded(Path::new("/project/.env.production"), &config));
        assert!(is_excluded(Path::new("/project/id_ed25519"), &config));
        assert!(is_excluded(Path::new("/project/.aws/credentials"), &config));
    }

    #[test]
    fn applies_repository_ignore_precedence() {
        let dir = repository_with_ignore_files();
        let root = dir.path();
        let config = default_config();

        assert!(is_git_ignored(root, &root.join("blocked.txt"), &config));
        assert!(is_git_ignored(root, &root.join("info.rs"), &config));
        assert!(!is_git_ignored(
            root,
            &root.join("src/allowed.txt"),
            &config
        ));
        assert!(is_git_ignored(
            root,
            &root.join("private/secret.txt"),
            &config
        ));
        assert!(!is_git_ignored(root, &root.join("main.rs"), &config));
    }

    #[test]
    fn an_untrusted_snapshot_never_honors_its_own_ignore_files() {
        let dir = repository_with_ignore_files();
        let root = dir.path();
        let config = EngineConfig {
            discovery_source: DiscoverySource::UntrustedSnapshot,
            ..EngineConfig::default()
        };

        assert!(!is_git_ignored(root, &root.join("blocked.txt"), &config));
        assert!(!is_git_ignored(root, &root.join("info.rs"), &config));
        assert!(!is_git_ignored(
            root,
            &root.join("private/secret.txt"),
            &config
        ));
    }

    fn repository_with_ignore_files() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join(".git/info")).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("private")).unwrap();
        std::fs::write(root.join(".gitignore"), "*.txt\nprivate/\n").unwrap();
        std::fs::write(root.join(".git/info/exclude"), "info.rs\n").unwrap();
        std::fs::write(root.join("src/.gitignore"), "!allowed.txt\n").unwrap();
        std::fs::write(root.join("private/.gitignore"), "!secret.txt\n").unwrap();
        dir
    }

    #[test]
    fn detects_excluded_extension() {
        let path = Path::new("app.pyc");
        assert!(has_excluded_extension(path, &default_config()));
    }

    #[test]
    fn case_insensitive_extension_check() {
        let path = Path::new("image.PNG");
        assert!(has_excluded_extension(path, &default_config()));
    }

    #[test]
    fn allows_source_extensions() {
        let path = Path::new("main.rs");
        assert!(!has_excluded_extension(path, &default_config()));
    }

    fn config_without_exclusions() -> EngineConfig {
        EngineConfig {
            exclude_dirs: Vec::new(),
            exclude_extensions: Vec::new(),
            ..EngineConfig::default()
        }
    }

    #[test]
    fn protected_directories_survive_cleared_exclusions() {
        let config = config_without_exclusions();

        assert!(is_excluded(Path::new("/project/.aws/credentials"), &config));
        assert!(is_excluded(Path::new("/project/.git/config"), &config));
        assert!(is_excluded(
            Path::new("/project/.ssh/id_ed25519.pub"),
            &config
        ));
        assert!(is_excluded(
            Path::new("/project/.gnupg/pubring.kbx"),
            &config
        ));
        assert!(!is_excluded(Path::new("/project/src/main.rs"), &config));
    }

    #[test]
    fn protected_directory_match_ignores_case() {
        let config = config_without_exclusions();

        assert!(is_excluded(Path::new("/project/.SSH/config"), &config));
    }

    #[test]
    fn path_inside_root_does_not_escape() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let file = root.join("main.rs");
        std::fs::write(&file, "fn main() {}").unwrap();

        assert!(!escapes_project_root(&file, &root));
    }

    #[test]
    fn unresolvable_path_escapes_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();

        assert!(escapes_project_root(&root.join("missing.rs"), &root));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_leaving_root_escapes_root() {
        let outside = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let root = project.path().canonicalize().unwrap();
        let secret = outside.path().canonicalize().unwrap().join("secret.rs");
        std::fs::write(&secret, "fn secret() {}").unwrap();
        let link = root.join("linked.rs");
        std::os::unix::fs::symlink(&secret, &link).unwrap();

        assert!(escapes_project_root(&link, &root));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_staying_inside_root_does_not_escape() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let target = root.join("target.rs");
        std::fs::write(&target, "fn target() {}").unwrap();
        let link = root.join("linked.rs");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(!escapes_project_root(&link, &root));
    }

    #[test]
    fn git_ignore_handles_parentless_and_outside_paths() {
        let directory = tempfile::tempdir().unwrap();
        let config = EngineConfig::default();

        assert!(!is_git_ignored(directory.path(), Path::new(""), &config));
        assert!(is_git_ignored(
            directory.path(),
            directory.path().parent().unwrap(),
            &config,
        ));
    }

    #[test]
    fn excluded_suffixes_are_detected_before_extensions() {
        assert!(has_excluded_extension(
            Path::new("bundle.min.js"),
            &EngineConfig::default(),
        ));
    }

    #[test]
    fn excluded_extensions_match_case_insensitively() {
        let config = EngineConfig {
            exclude_extensions: vec!["rs".into()],
            ..EngineConfig::default()
        };

        assert!(has_excluded_extension(Path::new("SOURCE.RS"), &config));
        assert!(!has_excluded_extension(Path::new("README"), &config));
        assert!(!has_excluded_extension(Path::new("/"), &config));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_filenames_are_not_treated_as_sensitive() {
        use std::os::unix::ffi::OsStringExt;

        let filename = std::ffi::OsString::from_vec(vec![0xff]);

        assert!(!has_sensitive_filename(Path::new(&filename)));
    }

    fn tiny_limits() -> IgnoreLimits {
        IgnoreLimits {
            source_bytes: 64,
            line_bytes: 16,
            patterns: 3,
            pattern_bytes: 12,
        }
    }

    fn rules_for(root: &Path, limits: IgnoreLimits) -> RepositoryIgnoreRules {
        RepositoryIgnoreRules::for_path_query(root, &EngineConfig::default(), limits)
    }

    #[test]
    fn physical_lines_keeps_an_unterminated_final_line() {
        let terminated: Vec<&[u8]> = physical_lines(b"a\nb\n").collect();
        let unterminated: Vec<&[u8]> = physical_lines(b"a\nb").collect();

        assert_eq!(terminated, vec![b"a".as_slice(), b"b".as_slice()]);
        assert_eq!(unterminated, vec![b"a".as_slice(), b"b".as_slice()]);
        assert_eq!(physical_lines(b"").count(), 0);
        assert_eq!(
            physical_lines(b"\n").collect::<Vec<&[u8]>>(),
            vec![b"".as_slice()]
        );
    }

    #[test]
    fn a_source_is_accepted_at_its_exact_byte_limit_and_rejected_one_byte_later() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join(".ignore");
        std::fs::write(&source, "x".repeat(64)).unwrap();

        let accepted = read_bounded(&source, 64, IGNORE_SOURCE_BYTES);
        let rejected = read_bounded(&source, 63, IGNORE_SOURCE_BYTES);

        assert_eq!(
            accepted.map(|contents| contents.map(|bytes| bytes.len())),
            Ok(Some(64))
        );
        assert_eq!(
            rejected,
            Err(ExhaustedIgnoreLimit::new(IGNORE_SOURCE_BYTES, 63))
        );
    }

    #[test]
    fn a_missing_source_is_not_a_limit_failure() {
        let directory = tempfile::tempdir().unwrap();

        let contents = read_bounded(&directory.path().join(".ignore"), 64, IGNORE_SOURCE_BYTES);

        assert_eq!(contents, Ok(None));
    }

    #[test]
    fn an_oversized_ignore_line_is_rejected_before_the_matcher_is_built() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join(".ignore"),
            format!("{}\n", "a".repeat(17)),
        )
        .unwrap();

        let rules = rules_for(directory.path(), tiny_limits());

        assert_eq!(
            rules.exhausted(),
            Some(ExhaustedIgnoreLimit::new(IGNORE_LINE_BYTES, 16))
        );
    }

    #[test]
    fn an_ignore_line_at_the_exact_limit_is_accepted() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join(".ignore"),
            format!("{}\n", "a".repeat(16)),
        )
        .unwrap();

        let rules = rules_for(
            directory.path(),
            IgnoreLimits {
                pattern_bytes: 16,
                ..tiny_limits()
            },
        );

        assert_eq!(rules.exhausted(), None);
    }

    #[test]
    fn an_unterminated_oversized_ignore_line_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join(".ignore"), "a".repeat(17)).unwrap();

        let rules = rules_for(directory.path(), tiny_limits());

        assert_eq!(
            rules.exhausted(),
            Some(ExhaustedIgnoreLimit::new(IGNORE_LINE_BYTES, 16))
        );
    }

    #[test]
    fn the_pattern_budget_is_shared_across_ignore_sources() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("nested")).unwrap();
        std::fs::write(directory.path().join(".ignore"), "a\nb\n").unwrap();
        std::fs::write(directory.path().join("nested/.ignore"), "c\nd\n").unwrap();
        let limits = IgnoreLimits {
            patterns: 3,
            ..IgnoreLimits::default()
        };

        let rules = rules_for(directory.path(), limits);
        rules.load_directory(&directory.path().join("nested"));

        assert_eq!(
            rules.exhausted(),
            Some(ExhaustedIgnoreLimit::new(IGNORE_PATTERNS, 3))
        );
    }

    #[test]
    fn the_pattern_byte_budget_is_shared_across_ignore_sources() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("nested")).unwrap();
        std::fs::write(directory.path().join(".ignore"), "aa\nbb\n").unwrap();
        std::fs::write(directory.path().join("nested/.ignore"), "cc\ndd\n").unwrap();
        let limits = IgnoreLimits {
            pattern_bytes: 7,
            ..IgnoreLimits::default()
        };

        let rules = rules_for(directory.path(), limits);
        rules.load_directory(&directory.path().join("nested"));

        assert_eq!(
            rules.exhausted(),
            Some(ExhaustedIgnoreLimit::new(IGNORE_PATTERN_BYTES, 7))
        );
    }

    #[test]
    fn comments_and_blank_lines_do_not_consume_the_pattern_budget() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join(".ignore"), "# comment\n\n   \nkept\n").unwrap();
        let exact = IgnoreLimits {
            patterns: 1,
            pattern_bytes: 4,
            ..IgnoreLimits::default()
        };
        let one_byte_short = IgnoreLimits {
            pattern_bytes: 3,
            ..exact
        };

        assert_eq!(rules_for(directory.path(), exact).exhausted(), None);
        assert_eq!(
            rules_for(directory.path(), one_byte_short).exhausted(),
            Some(ExhaustedIgnoreLimit::new(IGNORE_PATTERN_BYTES, 3))
        );
    }

    #[test]
    fn an_exhausted_ignore_budget_stops_matching_instead_of_guessing() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join(".ignore"), "blocked\n").unwrap();
        let limits = IgnoreLimits {
            patterns: 0,
            ..IgnoreLimits::default()
        };

        let rules = rules_for(directory.path(), limits);

        assert_eq!(
            rules.exhausted(),
            Some(ExhaustedIgnoreLimit::new(IGNORE_PATTERNS, 0))
        );
        assert!(rules.admits(&directory.path().join("blocked"), false));
    }

    #[test]
    fn a_broken_ignore_pattern_is_reported_against_its_source() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join(".ignore");
        std::fs::write(&source, "\\\n").unwrap();

        let rules = rules_for(directory.path(), IgnoreLimits::default());
        let failures = rules.take_failures();

        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].source, source);
        assert!(!failures[0].error.to_string().is_empty());
        assert!(rules.take_failures().is_empty());
    }

    #[test]
    fn an_ignore_rule_that_is_not_utf8_is_reported_with_its_line_number() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join(".ignore"), b"good\n\xff\n").unwrap();

        let rules = rules_for(directory.path(), IgnoreLimits::default());
        let failures = rules.take_failures();

        assert_eq!(failures.len(), 1);
        assert!(
            failures[0].error.to_string().contains("line 2"),
            "the diagnostic must name the offending line: {}",
            failures[0].error
        );
    }

    #[test]
    fn nested_negation_reinstates_a_file_the_root_ignored() {
        let directory = repository_with_ignore_files();
        let root = directory.path();
        let rules = rules_for(root, IgnoreLimits::default());

        assert!(!rules.admits(&root.join("blocked.txt"), false));
        assert!(rules.admits(&root.join("src/allowed.txt"), false));
    }

    #[test]
    fn a_global_excludes_setting_is_parsed_from_a_git_configuration() {
        let limits = IgnoreLimits::default();

        let parsed =
            excludes_path_from_config(b"[core]\nexcludesFile = /tmp/ignore\n", None, limits);
        let quoted =
            excludes_path_from_config(b"[core]\nexcludesFile = \"/tmp/ignore\"\n", None, limits);
        let unrelated =
            excludes_path_from_config(b"[core]\nexcludeFile = /tmp/ignore\n", None, limits);
        let spaced =
            excludes_path_from_config(b"excludesFile = \" \"/tmp/ignore \" \"\n", None, limits);

        assert_eq!(parsed, Ok(Some(PathBuf::from("/tmp/ignore"))));
        assert_eq!(quoted, Ok(Some(PathBuf::from("/tmp/ignore"))));
        assert_eq!(unrelated, Ok(None));
        assert_eq!(spaced, Ok(None));
    }

    #[test]
    fn an_oversized_git_configuration_line_is_rejected() {
        let limits = IgnoreLimits {
            line_bytes: 16,
            ..IgnoreLimits::default()
        };

        let parsed =
            excludes_path_from_config(b"excludesFile = /tmp/a/long/ignore\n", None, limits);

        assert_eq!(
            parsed,
            Err(ExhaustedIgnoreLimit::new(GLOBAL_GIT_CONFIG_LINE_BYTES, 16))
        );
    }

    #[test]
    fn a_home_expanded_excludes_path_is_bounded() {
        let limits = IgnoreLimits {
            line_bytes: 32,
            ..IgnoreLimits::default()
        };
        let home = PathBuf::from(format!("/{}", "h".repeat(40)));

        let parsed = excludes_path_from_config(b"excludesFile = ~/ignore\n", Some(&home), limits);

        assert_eq!(
            parsed,
            Err(ExhaustedIgnoreLimit::new(GLOBAL_EXCLUDES_PATH_BYTES, 32))
        );
    }

    #[test]
    fn a_home_expanded_excludes_path_at_the_limit_is_accepted() {
        let limits = IgnoreLimits {
            line_bytes: 32,
            ..IgnoreLimits::default()
        };
        let home = PathBuf::from("/home/short");

        let parsed = excludes_path_from_config(b"excludesFile = ~/ignore\n", Some(&home), limits);

        assert_eq!(parsed, Ok(Some(PathBuf::from("/home/short/ignore"))));
    }

    #[test]
    fn git_configuration_candidates_follow_git_precedence() {
        let home = PathBuf::from("/home/example");

        let candidates = global_git_config_paths(Some(&home));

        assert!(candidates.contains(&home.join(".gitconfig")));
        assert_eq!(candidates.last(), Some(&PathBuf::from("/etc/gitconfig")));
    }

    #[test]
    fn an_oversized_global_git_configuration_is_rejected_at_the_byte_past_the_limit() {
        let directory = tempfile::tempdir().unwrap();
        let configuration = directory.path().join("gitconfig");
        let limits = IgnoreLimits {
            source_bytes: 64,
            ..IgnoreLimits::default()
        };
        let candidates = vec![configuration.clone()];

        std::fs::write(&configuration, "x".repeat(64)).unwrap();
        let accepted = configured_excludes_path(&candidates, None, limits);
        std::fs::write(&configuration, "x".repeat(65)).unwrap();
        let rejected = configured_excludes_path(&candidates, None, limits);

        assert_eq!(accepted, Ok(None));
        assert_eq!(
            rejected,
            Err(ExhaustedIgnoreLimit::new(GLOBAL_GIT_CONFIG_BYTES, 64))
        );
    }

    #[test]
    fn the_first_git_configuration_naming_an_excludes_file_wins() {
        let directory = tempfile::tempdir().unwrap();
        let silent = directory.path().join("silent");
        let naming = directory.path().join("naming");
        std::fs::write(&silent, "[core]\nautocrlf = true\n").unwrap();
        std::fs::write(&naming, "[core]\nexcludesFile = /tmp/chosen\n").unwrap();
        let missing = directory.path().join("absent");

        let configured =
            configured_excludes_path(&[missing, silent, naming], None, IgnoreLimits::default());

        assert_eq!(configured, Ok(Some(PathBuf::from("/tmp/chosen"))));
    }
    #[test]
    fn untrusted_rules_skip_explicit_directory_loads_and_direct_matches() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join(".ignore"), "blocked\n").unwrap();
        let config = EngineConfig {
            discovery_source: DiscoverySource::UntrustedSnapshot,
            ..EngineConfig::default()
        };
        let rules = RepositoryIgnoreRules::for_path_query(
            directory.path(),
            &config,
            IgnoreLimits::default(),
        );

        rules.load_directory(directory.path());

        assert!(rules.admits(&directory.path().join("blocked"), false));
        assert_eq!(rules.exhausted(), None);
    }

    #[test]
    fn a_nested_rule_budget_failure_is_fail_open() {
        let directory = tempfile::tempdir().unwrap();
        let nested = directory.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        std::fs::write(nested.join(".ignore"), "blocked\n").unwrap();
        let limits = IgnoreLimits {
            patterns: 0,
            ..IgnoreLimits::default()
        };
        let rules = rules_for(directory.path(), limits);

        assert!(rules.admits(&nested.join("blocked"), false));
        assert_eq!(
            rules.exhausted(),
            Some(ExhaustedIgnoreLimit::new(IGNORE_PATTERNS, 0))
        );
    }

    #[test]
    fn global_rule_resolution_records_a_terminal_state() {
        let directory = tempfile::tempdir().unwrap();
        let rules = rules_for(directory.path(), IgnoreLimits::default());
        let mut state = IgnoreRuleState::default();

        let loaded = rules.global_rules(&mut state);

        assert!(loaded.is_some() || state.exhausted.is_some());
    }

    #[test]
    fn a_global_rule_resolution_limit_is_fail_open() {
        let directory = tempfile::tempdir().unwrap();
        let rules = rules_for(directory.path(), IgnoreLimits::default());
        let mut state = IgnoreRuleState::default();
        let exhausted = ExhaustedIgnoreLimit::new(GLOBAL_GIT_CONFIG_BYTES, 4);

        let loaded = rules.global_rules_from(&mut state, Err(exhausted));

        assert!(loaded.is_none());
        assert_eq!(state.exhausted, Some(exhausted));
    }

    #[test]
    fn an_unavailable_global_matcher_discards_partial_ignore_decisions() {
        assert!(
            combine_ignore_verdicts(
                IgnoreVerdict::Ignore,
                IgnoreVerdict::Ignore,
                IgnoreVerdict::Ignore,
                None,
            ) == IgnoreVerdict::Undecided
        );
        assert!(
            combine_ignore_verdicts(
                IgnoreVerdict::Ignore,
                IgnoreVerdict::Undecided,
                IgnoreVerdict::Undecided,
                Some(IgnoreVerdict::Undecided),
            ) == IgnoreVerdict::Ignore
        );
    }

    #[test]
    fn absent_and_non_file_global_excludes_sources_are_empty() {
        let directory = tempfile::tempdir().unwrap();
        let rules = rules_for(directory.path(), IgnoreLimits::default());
        let mut state = IgnoreRuleState::default();

        let absent = rules.load_global_rules(&mut state, None).unwrap();
        let non_file = rules
            .load_global_rules(&mut state, Some(directory.path()))
            .unwrap();

        assert!(
            absent
                .matched(directory.path().join("file"), false)
                .is_none()
        );
        assert!(
            non_file
                .matched(directory.path().join("file"), false)
                .is_none()
        );
    }

    #[test]
    fn bounded_pattern_loading_builds_an_effective_matcher() {
        let directory = tempfile::tempdir().unwrap();
        let rules = rules_for(directory.path(), IgnoreLimits::default());
        let source = directory.path().join(".ignore");
        let mut state = IgnoreRuleState::default();
        let mut builder = GitignoreBuilder::new(directory.path());

        let failure = rules
            .add_bounded_patterns(&mut state, &mut builder, &source, b"blocked\n")
            .unwrap();
        let matcher = builder.build().unwrap();

        assert!(failure.is_none());
        assert!(
            matcher
                .matched(directory.path().join("blocked"), false)
                .is_ignore()
        );
        assert_eq!(state.accepted_patterns, 1);
    }

    #[test]
    fn matcher_build_failures_preserve_the_first_pattern_error() {
        let first = undecodable_line_error(1);
        let build = Err(undecodable_line_error(2));

        let (matcher, failure) = resolve_matcher_build(build, Some(first));

        assert!(matcher.matched(Path::new("anything"), false).is_none());
        assert!(failure.unwrap().to_string().contains("line 1"));
    }

    #[test]
    fn bounded_first_lines_handle_empty_invalid_exact_and_oversized_inputs() {
        assert_eq!(bounded_first_line(b"", 3, IGNORE_LINE_BYTES), Ok(None));
        assert_eq!(
            bounded_first_line(b"abc\nrest", 3, IGNORE_LINE_BYTES),
            Ok(Some("abc"))
        );
        assert_eq!(
            bounded_first_line(b"abc\r\nrest", 4, IGNORE_LINE_BYTES),
            Ok(Some("abc"))
        );
        assert_eq!(
            bounded_first_line(b"\xff\n", 3, IGNORE_LINE_BYTES),
            Ok(None)
        );
        assert_eq!(
            bounded_first_line(b"abcd\n", 3, IGNORE_LINE_BYTES),
            Err(ExhaustedIgnoreLimit::new(IGNORE_LINE_BYTES, 3))
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_that_cannot_be_read_as_a_file_is_treated_as_absent() {
        let directory = tempfile::tempdir().unwrap();

        assert_eq!(
            read_bounded(directory.path(), 64, IGNORE_SOURCE_BYTES),
            Ok(None)
        );
    }

    #[test]
    fn a_trailing_escaped_space_is_retained_in_an_ignore_pattern() {
        assert_eq!(retained_pattern("kept\\ "), Some("kept\\ "));
    }

    #[test]
    fn invalid_git_configuration_lines_do_not_hide_a_later_valid_setting() {
        let parsed = excludes_path_from_config(
            b"\xff\nexcludesFile = /tmp/ignore\n",
            None,
            IgnoreLimits::default(),
        );

        assert_eq!(parsed, Ok(Some(PathBuf::from("/tmp/ignore"))));
    }

    #[test]
    fn git_directory_redirects_cover_missing_invalid_relative_and_absolute_targets() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join(".git");
        assert_eq!(
            resolve_git_common_directory(&marker, IgnoreLimits::default()),
            Ok(None)
        );

        std::fs::write(&marker, "not a redirect\n").unwrap();
        assert_eq!(
            resolve_git_common_directory(&marker, IgnoreLimits::default()),
            Ok(None)
        );

        let git_directory = directory.path().join("metadata");
        std::fs::create_dir(&git_directory).unwrap();
        std::fs::write(&marker, format!("gitdir: {}\n", git_directory.display())).unwrap();
        assert_eq!(
            resolve_git_common_directory(&marker, IgnoreLimits::default()),
            Ok(None)
        );

        let marker_bytes = std::fs::metadata(&marker).unwrap().len() as usize;
        std::fs::write(
            git_directory.join("commondir"),
            "x".repeat(marker_bytes + 1),
        )
        .unwrap();
        let limits = IgnoreLimits {
            source_bytes: marker_bytes,
            ..IgnoreLimits::default()
        };
        assert_eq!(
            resolve_git_common_directory(&marker, limits),
            Err(ExhaustedIgnoreLimit::new(IGNORE_SOURCE_BYTES, marker_bytes))
        );

        std::fs::write(git_directory.join("commondir"), "").unwrap();
        assert_eq!(
            resolve_git_common_directory(&marker, IgnoreLimits::default()),
            Ok(None)
        );

        std::fs::write(git_directory.join("commondir"), ".\n").unwrap();
        assert_eq!(
            resolve_git_common_directory(&marker, IgnoreLimits::default()),
            Ok(Some(git_directory.join(".")))
        );

        let absolute = directory.path().join("common");
        std::fs::write(
            git_directory.join("commondir"),
            format!("{}\n", absolute.display()),
        )
        .unwrap();
        assert_eq!(
            resolve_git_common_directory(&marker, IgnoreLimits::default()),
            Ok(Some(absolute))
        );
    }

    #[test]
    fn an_invalid_git_directory_redirect_leaves_repository_rules_empty() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join(".git"), "not a redirect\n").unwrap();

        let rules = rules_for(directory.path(), IgnoreLimits::default());

        assert!(rules.admits(&directory.path().join("main.rs"), false));
        assert_eq!(rules.exhausted(), None);
    }
    #[test]
    fn poisoned_ignore_state_recovers_without_discarding_the_rules() {
        let directory = tempfile::tempdir().unwrap();
        let rules = rules_for(directory.path(), IgnoreLimits::default());
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _state = rules.state.lock().unwrap();
            panic!("poison ignore state");
        }));

        assert!(panic.is_err());
        assert!(rules.admits(&directory.path().join("main.rs"), false));
    }

    #[test]
    fn environment_paths_ignore_missing_and_empty_values() {
        assert_eq!(non_empty_path(None), None);
        assert_eq!(non_empty_path(Some(std::ffi::OsString::new())), None);
        assert_eq!(
            non_empty_path(Some(std::ffi::OsString::from("/tmp/gitconfig"))),
            Some(PathBuf::from("/tmp/gitconfig"))
        );
    }
}
