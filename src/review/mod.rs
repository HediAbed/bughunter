pub(crate) mod archive;
mod github;

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use wait_timeout::ChildExt;

use crate::domain::{LineRange, ProjectPath};
use archive::{ArchiveLimits, extract_zip_archive};
use github::{GitHubClient, GitHubHostPolicy, RepositorySlug};
use tracing::info;

#[derive(Debug, thiserror::Error)]
pub enum ReviewError {
    #[error("GitHub request failed: {0}")]
    GitHub(String),

    #[error("git failed: {0}")]
    Git(String),

    #[error("PR #{0} changed no reviewable files")]
    NoChangedFiles(u64),

    #[error("failed to inspect pull request snapshot: {0}")]
    Engine(String),

    #[error("{action}: {source}")]
    Io {
        action: String,
        #[source]
        source: std::io::Error,
    },
    #[error("pull request archive failed validation: {0}")]
    Archive(String),

    #[error("invalid review scope: {0}")]
    Scope(String),

    #[error("review diff exceeds the {resource} limit of {limit}")]
    DiffLimit {
        resource: DiffResource,
        limit: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiffResource {
    ChangedFiles,
    RangesPerFile,
    TotalRanges,
    PathBytes,
}

impl std::fmt::Display for DiffResource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ChangedFiles => "changed files",
            Self::RangesPerFile => "changed line ranges per file",
            Self::TotalRanges => "total changed line ranges",
            Self::PathBytes => "changed file path bytes",
        })
    }
}

const MAX_BASE_REF_BYTES: usize = 255;
const MAX_HEAD_SHA_BYTES: usize = 64;
const MAX_DIFF_BYTES: usize = 32 * 1024 * 1024;
const MAX_CHANGED_FILES: usize = 10_000;
const MAX_RANGES_PER_FILE: usize = 10_000;
const MAX_TOTAL_RANGES: usize = 100_000;
const MAX_REPORTED_PATH_BYTES: usize = 4096;

#[derive(Clone, Copy)]
pub struct DiffLimits {
    pub max_changed_files: usize,
    pub max_ranges_per_file: usize,
    pub max_total_ranges: usize,
    pub max_path_bytes: usize,
}

impl Default for DiffLimits {
    fn default() -> Self {
        Self {
            max_changed_files: MAX_CHANGED_FILES,
            max_ranges_per_file: MAX_RANGES_PER_FILE,
            max_total_ranges: MAX_TOTAL_RANGES,
            max_path_bytes: MAX_REPORTED_PATH_BYTES,
        }
    }
}

fn exhausted(resource: DiffResource, limit: usize) -> ReviewError {
    ReviewError::DiffLimit { resource, limit }
}

pub struct ReviewScope {
    pr: u64,
    base_ref: String,
    head_sha: Option<String>,
    hunks: BTreeMap<String, Vec<LineRange>>,
    diff_text: String,
    changed_file_coverage: ChangedFileCoverage,
}

impl ReviewScope {
    pub fn new(
        pr: u64,
        base_ref: String,
        head_sha: Option<String>,
        hunks: BTreeMap<String, Vec<(u32, u32)>>,
        diff_text: String,
    ) -> Result<Self, ReviewError> {
        if pr == 0 {
            return Err(ReviewError::Scope(
                "pull request number must be greater than zero".to_string(),
            ));
        }
        if base_ref.len() > MAX_BASE_REF_BYTES {
            return Err(ReviewError::Scope(format!(
                "base reference exceeds {MAX_BASE_REF_BYTES} bytes"
            )));
        }
        if diff_text.len() > MAX_DIFF_BYTES {
            return Err(ReviewError::Scope(format!(
                "unified diff exceeds {MAX_DIFF_BYTES} bytes"
            )));
        }
        Ok(Self {
            pr,
            base_ref,
            head_sha: validated_head_sha(head_sha)?,
            hunks: validated_hunks(hunks, DiffLimits::default())?,
            diff_text,
            changed_file_coverage: ChangedFileCoverage::default(),
        })
    }

    pub fn pr(&self) -> u64 {
        self.pr
    }

    pub fn base_ref(&self) -> &str {
        &self.base_ref
    }

    pub fn head_sha(&self) -> Option<&str> {
        self.head_sha.as_deref()
    }

    pub fn changed_files(&self) -> BTreeSet<String> {
        self.hunks.keys().cloned().collect()
    }

    pub fn hunk_ranges(&self) -> BTreeMap<String, Vec<(u32, u32)>> {
        self.hunks
            .iter()
            .map(|(path, ranges)| {
                let spans = ranges
                    .iter()
                    .map(|range| (range.start(), range.end()))
                    .collect();
                (path.clone(), spans)
            })
            .collect()
    }

    pub fn changed_file_coverage(&self) -> &ChangedFileCoverage {
        &self.changed_file_coverage
    }

    pub fn set_changed_file_coverage(
        &mut self,
        coverage: ChangedFileCoverage,
    ) -> Result<(), ReviewError> {
        if coverage.inspectable.len() > MAX_CHANGED_FILES
            || coverage.skipped.len() > MAX_CHANGED_FILES
        {
            return Err(ReviewError::Scope(format!(
                "changed file coverage exceeds {MAX_CHANGED_FILES} paths"
            )));
        }
        for path in &coverage.inspectable {
            scope_path(path)?;
        }
        for skipped in &coverage.skipped {
            if skipped.path.len() > MAX_REPORTED_PATH_BYTES {
                return Err(ReviewError::Scope(format!(
                    "a skipped changed file path exceeds {MAX_REPORTED_PATH_BYTES} bytes"
                )));
            }
        }
        self.changed_file_coverage = coverage;
        Ok(())
    }

    pub fn skipped_changed_files(&self) -> &[SkippedChangedFile] {
        &self.changed_file_coverage.skipped
    }

    pub fn prompt_section(&self, diff_char_cap: usize) -> String {
        let mut section = format!(
            "## PR Review Scope\n\
             You are reviewing GitHub pull request #{} (base branch: {}{}).\n\
             Only the files listed below changed in this PR. Review each one and scrutinise \
             the changed lines and how they interact with the surrounding and unchanged code. \
             Report only defects introduced or exposed by these changes; do not report \
             pre-existing issues in unrelated files.\n\n\
             Changed files (new-side line ranges):\n",
            self.pr,
            self.display_base_ref(),
            self.head_description()
        );
        self.append_changed_files(&mut section);
        self.append_diff(&mut section, diff_char_cap);
        section
    }

    fn display_base_ref(&self) -> &str {
        if self.base_ref.is_empty() {
            "unknown"
        } else {
            &self.base_ref
        }
    }

    fn head_description(&self) -> String {
        match &self.head_sha {
            Some(head_sha) => format!(", head commit: {}", safe_truncate(head_sha, 12)),
            None => String::new(),
        }
    }

    fn append_changed_files(&self, section: &mut String) {
        for (file, ranges) in &self.hunks {
            let rendered_ranges = render_line_ranges(ranges);
            if rendered_ranges.is_empty() {
                section.push_str(&format!("- {file}\n"));
            } else {
                section.push_str(&format!("- {file}: {rendered_ranges}\n"));
            }
        }
    }

    fn append_diff(&self, section: &mut String, diff_char_cap: usize) {
        let truncated = self.diff_text.len() > diff_char_cap;
        section.push_str(if truncated {
            "\nUnified diff (truncated):\n```diff\n"
        } else {
            "\nUnified diff:\n```diff\n"
        });
        section.push_str(safe_truncate(&self.diff_text, diff_char_cap));
        if truncated {
            section.push_str("\n... (diff truncated) ...");
        }
        section.push_str("\n```\n");
    }
}

fn validated_head_sha(head_sha: Option<String>) -> Result<Option<String>, ReviewError> {
    let Some(head_sha) = head_sha else {
        return Ok(None);
    };
    let hexadecimal = !head_sha.is_empty()
        && head_sha.len() <= MAX_HEAD_SHA_BYTES
        && head_sha.bytes().all(|byte| byte.is_ascii_hexdigit());
    if !hexadecimal {
        return Err(ReviewError::Scope(format!(
            "head commit must be 1 to {MAX_HEAD_SHA_BYTES} hexadecimal characters"
        )));
    }
    Ok(Some(head_sha))
}

fn validated_hunks(
    hunks: BTreeMap<String, Vec<(u32, u32)>>,
    limits: DiffLimits,
) -> Result<BTreeMap<String, Vec<LineRange>>, ReviewError> {
    if hunks.len() > limits.max_changed_files {
        return Err(exhausted(
            DiffResource::ChangedFiles,
            limits.max_changed_files,
        ));
    }
    let mut validated: BTreeMap<String, Vec<LineRange>> = BTreeMap::new();
    let mut retained_ranges = 0usize;
    for (path, spans) in hunks {
        if path.len() > limits.max_path_bytes {
            return Err(exhausted(DiffResource::PathBytes, limits.max_path_bytes));
        }
        if spans.len() > limits.max_ranges_per_file {
            return Err(exhausted(
                DiffResource::RangesPerFile,
                limits.max_ranges_per_file,
            ));
        }
        if spans.len() > limits.max_total_ranges.saturating_sub(retained_ranges) {
            return Err(exhausted(
                DiffResource::TotalRanges,
                limits.max_total_ranges,
            ));
        }
        retained_ranges += spans.len();
        let path = scope_path(&path)?.key();
        let ranges = spans
            .into_iter()
            .map(|(start, end)| {
                LineRange::new(start, end)
                    .map_err(|error| ReviewError::Scope(format!("{path}: {error}")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        match validated.entry(path) {
            Entry::Occupied(occupied) => {
                return Err(ReviewError::Scope(format!(
                    "changed files contain the duplicate path {}",
                    occupied.key()
                )));
            }
            Entry::Vacant(vacant) => {
                vacant.insert(ranges);
            }
        }
    }
    Ok(validated)
}

fn scope_path(path: &str) -> Result<ProjectPath, ReviewError> {
    ProjectPath::parse(Path::new(path))
        .map_err(|error| ReviewError::Scope(format!("changed file '{path}': {error}")))
}

fn render_line_ranges(ranges: &[LineRange]) -> String {
    ranges
        .iter()
        .map(|range| {
            if range.start() == range.end() {
                range.start().to_string()
            } else {
                format!("{}-{}", range.start(), range.end())
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangedFileSkipReason {
    UnsafePath,
    AbsentFromSnapshot,
    ExcludedByEngineFilters,
}

impl std::fmt::Display for ChangedFileSkipReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::UnsafePath => "not a repository-relative path",
            Self::AbsentFromSnapshot => "absent from the pull request snapshot",
            Self::ExcludedByEngineFilters => "excluded by engine filters",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkippedChangedFile {
    pub path: String,
    pub reason: ChangedFileSkipReason,
}

impl SkippedChangedFile {
    pub fn report_entry(&self) -> String {
        format!("{} ({})", self.path, self.reason)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ChangedFileCoverage {
    pub inspectable: BTreeSet<String>,
    pub skipped: Vec<SkippedChangedFile>,
}

impl ChangedFileCoverage {
    pub fn is_partial(&self) -> bool {
        !self.skipped.is_empty()
    }

    pub fn skipped_report_entries(&self) -> Vec<String> {
        self.skipped
            .iter()
            .map(SkippedChangedFile::report_entry)
            .collect()
    }
}

pub struct ReviewSession {
    pub scope: ReviewScope,
    pub project_root: PathBuf,
    _temporary_directory: tempfile::TempDir,
}

pub fn prepare_pr_review(
    repo_dir: &Path,
    pr: u64,
    repo_slug: Option<&str>,
) -> Result<ReviewSession, ReviewError> {
    let client = GitHubClient::github(github_token_from_environment())?;
    prepare_review_session(&client, repo_dir, pr, repo_slug)
}

fn prepare_review_session(
    client: &GitHubClient,
    repo_dir: &Path,
    pr: u64,
    repo_slug: Option<&str>,
) -> Result<ReviewSession, ReviewError> {
    let repository = resolve_repository_slug(repo_dir, repo_slug, &client.host_policy())?;
    let metadata = client.pull_request(&repository, pr)?;
    let diff_text = client.compare_diff(&repository, &metadata.revisions)?;
    let hunks = parse_unified_diff(&diff_text, DiffLimits::default())?;
    if hunks.is_empty() {
        return Err(ReviewError::NoChangedFiles(pr));
    }

    let archive = client.download_archive(&repository, &metadata.revisions)?;
    let snapshot = extract_pull_request_snapshot(archive.path())?;

    info!(
        pr,
        repository = %repository.as_str(),
        base = %metadata.base_ref,
        head = %metadata.revisions.head_sha(),
        files = hunks.len(),
        project_root = %snapshot.project_root.display(),
        "prepared pull request archive"
    );

    let scope = ReviewScope::new(
        pr,
        metadata.base_ref,
        Some(metadata.revisions.head_sha().to_string()),
        hunks,
        diff_text,
    )?;
    Ok(ReviewSession {
        scope,
        project_root: snapshot.project_root,
        _temporary_directory: snapshot.directory,
    })
}

const GITHUB_TOKEN_VARIABLES: [&str; 2] = ["GH_TOKEN", "GITHUB_TOKEN"];

fn github_token_from_environment() -> Option<String> {
    first_usable_token(
        GITHUB_TOKEN_VARIABLES
            .into_iter()
            .filter_map(|variable| std::env::var(variable).ok()),
    )
}

fn first_usable_token(mut candidates: impl Iterator<Item = String>) -> Option<String> {
    candidates.find(|token| !token.is_empty())
}

struct PullRequestSnapshot {
    directory: tempfile::TempDir,
    project_root: PathBuf,
}

fn extract_pull_request_snapshot(archive: &Path) -> Result<PullRequestSnapshot, ReviewError> {
    let directory = create_extraction_directory(&std::env::temp_dir())?;
    let extracted = extract_zip_archive(archive, directory.path(), ArchiveLimits::default())?;
    let project_root = canonical_project_root(&extracted)?;
    Ok(PullRequestSnapshot {
        directory,
        project_root,
    })
}

fn create_extraction_directory(parent: &Path) -> Result<tempfile::TempDir, ReviewError> {
    tempfile::Builder::new()
        .prefix("bughunter-pr-")
        .tempdir_in(parent)
        .map_err(|source| ReviewError::Io {
            action: "create pull request extraction directory".to_string(),
            source,
        })
}

fn canonical_project_root(extracted_root: &Path) -> Result<PathBuf, ReviewError> {
    extracted_root
        .canonicalize()
        .map_err(|source| ReviewError::Io {
            action: "resolve pull request project root".to_string(),
            source,
        })
}

pub fn classify_changed_files(
    project_root: &Path,
    engine_config: &crate::config::EngineConfig,
    changed_files: &BTreeSet<String>,
) -> Result<ChangedFileCoverage, ReviewError> {
    let inventory = inspectable_inventory(project_root, engine_config)?;
    let mut coverage = ChangedFileCoverage::default();
    for path in changed_files {
        if inventory.contains(path) {
            coverage.inspectable.insert(path.clone());
        } else {
            coverage.skipped.push(SkippedChangedFile {
                path: path.clone(),
                reason: skip_reason(project_root, path),
            });
        }
    }
    Ok(coverage)
}

fn inspectable_inventory(
    project_root: &Path,
    engine_config: &crate::config::EngineConfig,
) -> Result<BTreeSet<String>, ReviewError> {
    let entries = match crate::engine::walker::walk_project(
        project_root,
        engine_config,
        &crate::engine::walker::DiscoverOpts::default(),
    ) {
        Ok(entries) => entries,
        Err(error) => return Err(ReviewError::Engine(error.to_string())),
    };
    Ok(entries
        .into_iter()
        .map(|entry| entry.relative_path)
        .collect())
}

fn skip_reason(project_root: &Path, relative_path: &str) -> ChangedFileSkipReason {
    let Ok(project_path) = ProjectPath::parse(Path::new(relative_path)) else {
        return ChangedFileSkipReason::UnsafePath;
    };
    let present_in_snapshot = std::fs::symlink_metadata(project_root.join(project_path.as_path()))
        .is_ok_and(|metadata| metadata.is_file());
    if present_in_snapshot {
        ChangedFileSkipReason::ExcludedByEngineFilters
    } else {
        ChangedFileSkipReason::AbsentFromSnapshot
    }
}

fn resolve_repository_slug(
    repo_dir: &Path,
    explicit: Option<&str>,
    hosts: &GitHubHostPolicy,
) -> Result<RepositorySlug, ReviewError> {
    match explicit {
        Some(slug) => RepositorySlug::parse(slug),
        None => {
            let remote = run_git_metadata(repo_dir, &["remote", "get-url", "origin"])?;
            repository_slug_from_remote(remote.trim(), hosts)
        }
    }
}

struct RemoteLocation {
    host: String,
    repository_path: String,
}

impl RemoteLocation {
    fn parse(remote: &str) -> Option<Self> {
        let (host, path) = match reqwest::Url::parse(remote) {
            Ok(url) => (url.host_str()?.to_string(), url.path().to_string()),
            Err(_) => {
                let (authority, path) = remote.split_once(':')?;
                let (_, host) = authority.rsplit_once('@')?;
                (host.to_string(), path.to_string())
            }
        };
        let path = path.trim_matches('/');
        Some(Self {
            host,
            repository_path: path.strip_suffix(".git").unwrap_or(path).to_string(),
        })
    }
}

fn repository_slug_from_remote(
    remote: &str,
    hosts: &GitHubHostPolicy,
) -> Result<RepositorySlug, ReviewError> {
    let Some(location) = RemoteLocation::parse(remote) else {
        return Err(unreadable_remote());
    };
    if !hosts.accepts(&location.host) {
        return Err(non_github_remote(&location.host));
    }
    RepositorySlug::parse(&location.repository_path)
        .map_err(|_| unreadable_remote_path(&location.host))
}

fn unreadable_remote() -> ReviewError {
    ReviewError::Git(
        "cannot derive a GitHub repository from the origin URL; pass --repo owner/repository"
            .to_string(),
    )
}

fn unreadable_remote_path(host: &str) -> ReviewError {
    ReviewError::Git(format!(
        "cannot derive a GitHub repository from the origin path on '{host}'; \
         pass --repo owner/repository"
    ))
}

fn non_github_remote(host: &str) -> ReviewError {
    ReviewError::Git(format!(
        "origin host '{host}' is not a GitHub host; pass --repo owner/repository"
    ))
}

const MAX_GIT_METADATA_BYTES: usize = 16 * 1024;
const GIT_METADATA_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
struct ProcessCapture {
    bytes: Vec<u8>,
    truncated: bool,
}

type ProcessWait = fn(&mut Child, Duration) -> std::io::Result<Option<ExitStatus>>;
type ProcessSpawn = fn(&mut Command) -> std::io::Result<(Child, crate::process::ProcessGroup)>;
type ProcessTerminate = fn(&mut Child, crate::process::ProcessGroup) -> std::io::Result<()>;
type GroupTerminate = fn(crate::process::ProcessGroup) -> std::io::Result<()>;

struct ProcessControl {
    spawn: ProcessSpawn,
    wait: ProcessWait,
    terminate: ProcessTerminate,
    terminate_group: GroupTerminate,
}

impl Default for ProcessControl {
    fn default() -> Self {
        Self {
            spawn: crate::process::spawn_std_grouped,
            wait: |child, timeout| child.wait_timeout(timeout),
            terminate: crate::process::terminate_std,
            terminate_group: crate::process::terminate_group,
        }
    }
}

#[derive(Clone, Copy)]
struct MetadataDeadline {
    expires_at: Instant,
    budget: Duration,
}

impl MetadataDeadline {
    fn starting_now(budget: Duration) -> Self {
        Self {
            expires_at: Instant::now() + budget,
            budget,
        }
    }

    fn remaining(self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }

    fn exceeded(self) -> ReviewError {
        ReviewError::Git(format!(
            "git metadata command exceeded {} seconds",
            self.budget.as_secs_f64()
        ))
    }
}

struct PipeReader {
    stream: &'static str,
    captures: std::sync::mpsc::Receiver<std::io::Result<ProcessCapture>>,
}

impl PipeReader {
    fn spawn(stream: &'static str, pipe: impl Read + Send + 'static) -> Self {
        let (sender, captures) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(read_process_pipe(pipe, MAX_GIT_METADATA_BYTES));
        });
        Self { stream, captures }
    }

    fn collect(&self, deadline: MetadataDeadline) -> Result<ProcessCapture, ReviewError> {
        match self.captures.recv_timeout(deadline.remaining()) {
            Ok(Ok(capture)) if capture.truncated => Err(ReviewError::Git(format!(
                "git metadata {} exceeds {MAX_GIT_METADATA_BYTES} bytes",
                self.stream
            ))),
            Ok(Ok(capture)) => Ok(capture),
            Ok(Err(source)) => Err(ReviewError::Io {
                action: format!("read git {}", self.stream),
                source,
            }),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(deadline.exceeded()),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(ReviewError::Git(format!(
                "git {} reader panicked",
                self.stream
            ))),
        }
    }
}

struct MetadataReaders {
    stdout: PipeReader,
    stderr: PipeReader,
}

impl MetadataReaders {
    fn spawn(stdout: ChildStdout, stderr: ChildStderr) -> Self {
        Self {
            stdout: PipeReader::spawn("stdout", stdout),
            stderr: PipeReader::spawn("stderr", stderr),
        }
    }

    fn collect(
        &self,
        deadline: MetadataDeadline,
    ) -> Result<(ProcessCapture, ProcessCapture), ReviewError> {
        let stdout = self.stdout.collect(deadline)?;
        let stderr = self.stderr.collect(deadline)?;
        Ok((stdout, stderr))
    }

    fn release(&self, deadline: MetadataDeadline) {
        let _ = self.stdout.collect(deadline);
        let _ = self.stderr.collect(deadline);
    }
}

fn run_git_metadata(repo_dir: &Path, args: &[&str]) -> Result<String, ReviewError> {
    run_git_metadata_command(
        Path::new("git"),
        repo_dir,
        args,
        GIT_METADATA_TIMEOUT,
        ProcessControl::default(),
    )
}

fn run_git_metadata_command(
    binary: &Path,
    repo_dir: &Path,
    args: &[&str],
    timeout: Duration,
    control: ProcessControl,
) -> Result<String, ReviewError> {
    let mut command = git_metadata_command(binary, repo_dir, args);
    let (mut child, group, stdout, stderr) = spawn_with_pipes(&mut command, control.spawn)?;
    let deadline = MetadataDeadline::starting_now(timeout);
    let readers = MetadataReaders::spawn(stdout, stderr);
    let status = match (control.wait)(&mut child, deadline.remaining()) {
        Ok(Some(status)) => status,
        Ok(None) => {
            terminate_and_release(&mut child, group, control.terminate, &readers, deadline)?;
            return Err(deadline.exceeded());
        }
        Err(source) => {
            terminate_and_release(&mut child, group, control.terminate, &readers, deadline)?;
            return Err(ReviewError::Io {
                action: "wait for git metadata command".to_string(),
                source,
            });
        }
    };
    release_process_group(group, control.terminate_group)?;
    let (stdout, stderr) = readers.collect(deadline)?;
    if !status.success() {
        return Err(ReviewError::Git(format!(
            "git {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&stderr.bytes).trim()
        )));
    }
    String::from_utf8(stdout.bytes)
        .map_err(|error| ReviewError::Git(format!("git metadata is not UTF-8: {error}")))
}

fn git_metadata_command(binary: &Path, repo_dir: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(binary);
    command
        .args(args)
        .current_dir(repo_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn spawn_with_pipes(
    command: &mut Command,
    spawn: ProcessSpawn,
) -> Result<
    (
        Child,
        crate::process::ProcessGroup,
        ChildStdout,
        ChildStderr,
    ),
    ReviewError,
> {
    let (mut child, group) = spawn(command).map_err(|source| ReviewError::Io {
        action: "run git metadata command".to_string(),
        source,
    })?;
    let Some(stdout) = child.stdout.take() else {
        let _ = crate::process::terminate_std(&mut child, group);
        return Err(ReviewError::Git(
            "git metadata command has no stdout pipe".to_string(),
        ));
    };
    let Some(stderr) = child.stderr.take() else {
        let _ = crate::process::terminate_std(&mut child, group);
        return Err(ReviewError::Git(
            "git metadata command has no stderr pipe".to_string(),
        ));
    };
    Ok((child, group, stdout, stderr))
}

fn terminate_and_release(
    child: &mut Child,
    group: crate::process::ProcessGroup,
    terminate: ProcessTerminate,
    readers: &MetadataReaders,
    deadline: MetadataDeadline,
) -> Result<(), ReviewError> {
    let termination = terminate(child, group).map_err(|source| ReviewError::Io {
        action: "terminate git metadata command".to_string(),
        source,
    });
    readers.release(deadline);
    termination
}

fn release_process_group(
    group: crate::process::ProcessGroup,
    terminate_group: GroupTerminate,
) -> Result<(), ReviewError> {
    terminate_group(group).map_err(|source| ReviewError::Io {
        action: "terminate git metadata process group".to_string(),
        source,
    })
}

fn read_process_pipe(mut pipe: impl Read, limit: usize) -> std::io::Result<ProcessCapture> {
    let mut bytes = Vec::with_capacity(limit.min(8 * 1024));
    let mut truncated = false;
    let mut buffer = [0u8; 8 * 1024];
    while !truncated {
        let read = pipe.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let copied = read.min(limit.saturating_sub(bytes.len()));
        bytes.extend_from_slice(&buffer[..copied]);
        truncated = copied < read;
    }
    Ok(ProcessCapture { bytes, truncated })
}

pub fn parse_unified_diff(
    diff: &str,
    limits: DiffLimits,
) -> Result<BTreeMap<String, Vec<(u32, u32)>>, ReviewError> {
    let mut ranges: BTreeMap<String, Vec<(u32, u32)>> = BTreeMap::new();
    let mut current: Option<ChangedFileRanges> = None;
    let mut retained_ranges = 0usize;
    let mut previous = "";
    let mut in_hunk_body = false;

    for line in diff.lines() {
        if line.starts_with("diff --git ") {
            in_hunk_body = false;
        } else if !in_hunk_body && previous.starts_with("--- ") && line.starts_with("+++ ") {
            retain_changed_file(&mut ranges, current.take(), limits)?;
            current = opened_changed_file(&previous[4..], &line[4..], limits)?;
        } else if line.starts_with("@@") {
            in_hunk_body = true;
            if let Some(file) = &mut current
                && let Some(range) = parse_new_range(line)
            {
                if file.spans.len() == limits.max_ranges_per_file {
                    return Err(exhausted(
                        DiffResource::RangesPerFile,
                        limits.max_ranges_per_file,
                    ));
                }
                if retained_ranges == limits.max_total_ranges {
                    return Err(exhausted(
                        DiffResource::TotalRanges,
                        limits.max_total_ranges,
                    ));
                }
                file.spans.push(range);
                retained_ranges += 1;
            }
        }
        previous = line;
    }
    retain_changed_file(&mut ranges, current.take(), limits)?;

    Ok(ranges)
}

struct ChangedFileRanges {
    path: String,
    spans: Vec<(u32, u32)>,
}

fn opened_changed_file(
    old_header: &str,
    new_header: &str,
    limits: DiffLimits,
) -> Result<Option<ChangedFileRanges>, ReviewError> {
    let path = match new_side_path(new_header)? {
        Some(path) => path,
        None if git_header_path(new_header)? == "/dev/null" => {
            let Some(path) = old_side_path(old_header)? else {
                return Ok(None);
            };
            path
        }
        None => return Ok(None),
    };
    if path.len() > limits.max_path_bytes {
        return Err(exhausted(DiffResource::PathBytes, limits.max_path_bytes));
    }
    Ok(Some(ChangedFileRanges {
        path,
        spans: Vec::new(),
    }))
}

fn retain_changed_file(
    ranges: &mut BTreeMap<String, Vec<(u32, u32)>>,
    changed_file: Option<ChangedFileRanges>,
    limits: DiffLimits,
) -> Result<(), ReviewError> {
    let Some(changed_file) = changed_file else {
        return Ok(());
    };
    let at_file_capacity = ranges.len() == limits.max_changed_files;
    match ranges.entry(changed_file.path) {
        Entry::Occupied(mut occupied) => {
            let retained = occupied.get_mut();
            let remaining = limits.max_ranges_per_file.saturating_sub(retained.len());
            if changed_file.spans.len() > remaining {
                return Err(exhausted(
                    DiffResource::RangesPerFile,
                    limits.max_ranges_per_file,
                ));
            }
            retained.extend(changed_file.spans);
        }
        Entry::Vacant(vacant) => {
            if at_file_capacity {
                return Err(exhausted(
                    DiffResource::ChangedFiles,
                    limits.max_changed_files,
                ));
            }
            vacant.insert(changed_file.spans);
        }
    }
    Ok(())
}

fn new_side_path(header: &str) -> Result<Option<String>, ReviewError> {
    normalized_side_path(header, "b/")
}

fn old_side_path(header: &str) -> Result<Option<String>, ReviewError> {
    normalized_side_path(header, "a/")
}

fn normalized_side_path(
    header: &str,
    expected_prefix: &str,
) -> Result<Option<String>, ReviewError> {
    let mut path = git_header_path(header)?;
    if path == "/dev/null" {
        return Ok(None);
    }
    if path.starts_with(expected_prefix) {
        path.drain(..expected_prefix.len());
    }
    Ok((!path.is_empty()).then_some(path))
}

fn git_header_path(header: &str) -> Result<String, ReviewError> {
    if header.starts_with('"') {
        decode_git_quoted_path(header)
    } else {
        Ok(header.split('\t').next().unwrap_or(header).to_string())
    }
}

fn decode_git_quoted_path(header: &str) -> Result<String, ReviewError> {
    let bytes = header.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut cursor = 1;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'"' => return finish_git_quoted_path(bytes, cursor, decoded),
            b'\\' => {
                cursor += 1;
                push_git_escaped_byte(bytes, &mut cursor, &mut decoded)?;
            }
            byte => {
                decoded.push(byte);
                cursor += 1;
            }
        }
    }
    Err(invalid_diff_path("has an unterminated quote"))
}

fn finish_git_quoted_path(
    bytes: &[u8],
    closing_quote: usize,
    decoded: Vec<u8>,
) -> Result<String, ReviewError> {
    let suffix = &bytes[closing_quote + 1..];
    if !suffix.is_empty() && !suffix.starts_with(b"\t") {
        return Err(invalid_diff_path("has data after its closing quote"));
    }
    if decoded.contains(&0) {
        return Err(invalid_diff_path("contains a null byte"));
    }
    String::from_utf8(decoded).map_err(|_| invalid_diff_path("is not UTF-8"))
}

fn push_git_escaped_byte(
    bytes: &[u8],
    cursor: &mut usize,
    decoded: &mut Vec<u8>,
) -> Result<(), ReviewError> {
    let Some(&escaped) = bytes.get(*cursor) else {
        return Err(invalid_diff_path("ends with an incomplete escape"));
    };
    if escaped.is_ascii_digit() && escaped <= b'7' {
        let (value, width) = decode_git_octal_byte(bytes, *cursor)?;
        decoded.push(value);
        *cursor += width;
        return Ok(());
    }
    let value = match escaped {
        b'a' => 0x07,
        b'b' => 0x08,
        b't' => b'\t',
        b'n' => b'\n',
        b'v' => 0x0b,
        b'f' => 0x0c,
        b'r' => b'\r',
        b'\\' => b'\\',
        b'"' => b'"',
        _ => return Err(invalid_diff_path("contains an unsupported escape")),
    };
    decoded.push(value);
    *cursor += 1;
    Ok(())
}

fn decode_git_octal_byte(bytes: &[u8], start: usize) -> Result<(u8, usize), ReviewError> {
    let mut value = 0u16;
    let mut width = 0;
    for byte in bytes.iter().skip(start).take(3) {
        if !(b'0'..=b'7').contains(byte) {
            break;
        }
        value = value * 8 + u16::from(*byte - b'0');
        width += 1;
    }
    let value =
        u8::try_from(value).map_err(|_| invalid_diff_path("contains an oversized octal escape"))?;
    Ok((value, width))
}

fn invalid_diff_path(reason: &'static str) -> ReviewError {
    ReviewError::Scope(format!("changed file path {reason}"))
}

fn parse_new_range(hunk: &str) -> Option<(u32, u32)> {
    let new_side = hunk
        .split_whitespace()
        .find(|token| token.starts_with('+'))?;
    let mut parts = new_side[1..].split(',');
    let start: u32 = parts.next()?.parse().ok()?;
    let count: u32 = match parts.next() {
        Some(raw) => raw.parse().ok()?,
        None => 1,
    };
    if start == 0 || count == 0 {
        return None;
    }
    let end = start.checked_add(count - 1)?;
    Some((start, end))
}

fn safe_truncate(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    #[cfg(unix)]
    use crate::process::spawn_std_grouped;
    use std::io::Write;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn github_hosts() -> GitHubHostPolicy {
        GitHubHostPolicy::with_api_host("api.github.com")
    }

    const SAMPLE_DIFF: &str = "diff --git a/src/foo.rs b/src/foo.rs\n\
index 1111111..2222222 100644\n\
--- a/src/foo.rs\n\
+++ b/src/foo.rs\n\
@@ -10,3 +10,4 @@ fn foo() {\n\
 ctx\n\
-old\n\
+new1\n\
+new2\n\
@@ -40,2 +41,2 @@\n\
 a\n\
-b\n\
+c\n\
diff --git a/new.txt b/new.txt\n\
new file mode 100644\n\
--- /dev/null\n\
+++ b/new.txt\n\
@@ -0,0 +1,2 @@\n\
+hello\n\
+world\n\
diff --git a/gone.txt b/gone.txt\n\
deleted file mode 100644\n\
--- a/gone.txt\n\
+++ /dev/null\n\
@@ -1,2 +0,0 @@\n\
-x\n\
-y\n";

    fn parsed_diff(diff: &str) -> BTreeMap<String, Vec<(u32, u32)>> {
        match parse_unified_diff(diff, DiffLimits::default()) {
            Ok(hunks) => hunks,
            Err(error) => panic!("the sample diff must parse within the default limits: {error}"),
        }
    }

    fn small_limits() -> DiffLimits {
        DiffLimits {
            max_changed_files: 2,
            max_ranges_per_file: 2,
            max_total_ranges: 3,
            max_path_bytes: 8,
        }
    }

    fn exhausted_resource(error: ReviewError) -> (DiffResource, usize) {
        match error {
            ReviewError::DiffLimit { resource, limit } => (resource, limit),
            other => panic!("expected an exhausted diff limit, got {other}"),
        }
    }

    fn rejected_parse(diff: &str, limits: DiffLimits) -> (DiffResource, usize) {
        match parse_unified_diff(diff, limits) {
            Ok(hunks) => panic!("the diff must be rejected, parsed {} files", hunks.len()),
            Err(error) => exhausted_resource(error),
        }
    }

    fn changed_file_block(path: &str, hunks: usize) -> String {
        let mut block = format!("diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n");
        for index in 0..hunks {
            let start = index + 1;
            block.push_str(&format!("@@ -{start},1 +{start},1 @@\n+line\n"));
        }
        block
    }

    #[test]
    fn parses_new_side_ranges_per_file() {
        let parsed = parsed_diff(SAMPLE_DIFF);
        assert_eq!(parsed.get("src/foo.rs"), Some(&vec![(10, 13), (41, 42)]));
        assert_eq!(parsed.get("new.txt"), Some(&vec![(1, 2)]));
    }

    #[test]
    fn retains_deleted_files_without_new_side_ranges() {
        let parsed = parsed_diff(SAMPLE_DIFF);
        assert_eq!(parsed.get("gone.txt"), Some(&Vec::new()));
    }

    #[test]
    fn side_headers_without_a_source_or_destination_do_not_create_a_changed_file() {
        let parsed = parsed_diff("--- /dev/null\n+++ /dev/null\n@@ -0,0 +0,0 @@\n");
        assert!(parsed.is_empty());
    }

    #[test]
    fn single_line_hunk_without_count_is_one_line() {
        let diff = "--- a/x\n+++ b/x\n@@ -5 +7 @@\n-a\n+b\n";
        let parsed = parsed_diff(diff);
        assert_eq!(parsed.get("x"), Some(&vec![(7, 7)]));
    }

    #[test]
    fn hunk_ranges_always_start_at_one_or_later_and_never_invert() {
        for header in [
            "@@ -1,1 +0,3 @@",
            "@@ -1,1 +4294967295,2 @@",
            "@@ -1,1 +0 @@",
            "@@ -1,1 +1,0 @@",
        ] {
            let diff = format!("--- a/x\n+++ b/x\n{header}\n+a\n");
            let parsed = parsed_diff(&diff);

            assert_eq!(
                parsed.get("x").map(Vec::len),
                Some(0),
                "{header} cannot describe reviewable new-side lines"
            );
        }

        let parsed = parsed_diff("--- a/x\n+++ b/x\n@@ -1,1 +4294967295,1 @@\n+a\n");
        assert_eq!(parsed.get("x"), Some(&vec![(u32::MAX, u32::MAX)]));
    }

    #[test]
    fn a_hunk_whose_end_overflows_is_dropped_without_exhausting_a_limit() {
        let overflowing = "--- a/x\n+++ b/x\n@@ -1,1 +4294967295,2 @@\n+a\n\
                           @@ -1,1 +4294967294,2 @@\n+b\n";

        let parsed = parse_unified_diff(overflowing, small_limits())
            .expect("an overflowing endpoint is not a limit failure");

        assert_eq!(parsed.get("x"), Some(&vec![(u32::MAX - 1, u32::MAX)]));
    }

    #[test]
    fn headers_without_a_new_side_path_are_ignored() {
        for header in ["+++ b/", "+++ ", "+++ b/\t2026-01-01"] {
            let diff = format!("--- a/x\n{header}\n@@ -1,1 +1,2 @@\n+a\n");

            assert!(
                parsed_diff(&diff).is_empty(),
                "{header} must not introduce an empty changed-file key"
            );
        }
    }

    #[test]
    fn added_content_line_starting_with_plusplus_is_not_a_header() {
        let diff = "--- a/x\n+++ b/x\n@@ -1,0 +1,1 @@\n+++ not a header\n";
        let parsed = parsed_diff(diff);
        assert_eq!(parsed.keys().collect::<Vec<_>>(), vec!["x"]);
    }

    #[test]
    fn removed_and_added_marker_lines_are_not_headers() {
        let diff = "--- a/x\n+++ b/x\n@@ -1,2 +1,2 @@\n--- old\n+++ new\n";
        let parsed = parsed_diff(diff);
        assert_eq!(parsed.keys().collect::<Vec<_>>(), vec!["x"]);
        assert_eq!(parsed.get("x"), Some(&vec![(1, 2)]));
    }

    #[test]
    fn the_parser_accepts_a_diff_that_exactly_meets_every_limit() {
        let limits = small_limits();
        let mut diff = changed_file_block("a.rs", limits.max_ranges_per_file);
        diff.push_str(&changed_file_block("b.rs", 1));

        let parsed = parse_unified_diff(&diff, limits).expect("the exact boundary is reviewable");

        assert_eq!(parsed.len(), limits.max_changed_files);
        assert_eq!(parsed.get("a.rs"), Some(&vec![(1, 1), (2, 2)]));
        assert_eq!(parsed.get("b.rs"), Some(&vec![(1, 1)]));
    }

    #[test]
    fn the_parser_rejects_one_changed_file_past_the_limit() {
        let limits = small_limits();
        let mut diff = String::new();
        for index in 0..=limits.max_changed_files {
            diff.push_str(&changed_file_block(&format!("f{index}.rs"), 1));
        }

        assert_eq!(
            rejected_parse(&diff, limits),
            (DiffResource::ChangedFiles, limits.max_changed_files)
        );
    }

    #[test]
    fn the_parser_rejects_one_range_past_the_per_file_limit() {
        let limits = small_limits();
        let diff = changed_file_block("a.rs", limits.max_ranges_per_file + 1);

        assert_eq!(
            rejected_parse(&diff, limits),
            (DiffResource::RangesPerFile, limits.max_ranges_per_file)
        );
    }

    #[test]
    fn the_parser_rejects_ranges_that_reopen_a_changed_file_past_its_limit() {
        let limits = small_limits();
        let mut diff = changed_file_block("a.rs", limits.max_ranges_per_file);
        diff.push_str(&changed_file_block("a.rs", 1));

        assert_eq!(
            rejected_parse(&diff, limits),
            (DiffResource::RangesPerFile, limits.max_ranges_per_file)
        );
    }

    #[test]
    fn the_parser_rejects_one_range_past_the_total_across_changed_files() {
        let limits = DiffLimits {
            max_ranges_per_file: 2,
            max_total_ranges: 3,
            ..small_limits()
        };
        let mut diff = changed_file_block("a.rs", 2);
        diff.push_str(&changed_file_block("b.rs", 2));

        assert_eq!(
            rejected_parse(&diff, limits),
            (DiffResource::TotalRanges, limits.max_total_ranges)
        );
    }

    #[test]
    fn the_parser_accepts_a_path_of_exactly_the_limit_and_rejects_one_byte_more() {
        let limits = DiffLimits {
            max_path_bytes: 16,
            ..small_limits()
        };
        let exact = "p".repeat(limits.max_path_bytes);
        let parsed = parse_unified_diff(
            &format!("--- a/{exact}\n+++ b/{exact}\n@@ -1,1 +1,1 @@\n+a\n"),
            limits,
        )
        .expect("a path of exactly the limit is reviewable");
        assert_eq!(parsed.get(exact.as_str()), Some(&vec![(1, 1)]));

        let huge = "p".repeat(limits.max_path_bytes + 1);
        assert_eq!(
            rejected_parse(
                &format!("--- a/{huge}\n+++ b/{huge}\n@@ -1,1 +1,1 @@\n+a\n"),
                limits
            ),
            (DiffResource::PathBytes, limits.max_path_bytes)
        );
    }

    #[test]
    fn a_rejected_diff_yields_no_partial_changed_files() {
        let limits = small_limits();
        let mut diff = changed_file_block("a.rs", 1);
        diff.push_str(&changed_file_block("b.rs", 1));
        diff.push_str(&changed_file_block("c.rs", 1));

        let rejection = parse_unified_diff(&diff, limits);

        assert!(
            rejection.is_err(),
            "a third changed file must exhaust the limit"
        );
        assert_eq!(
            exhausted_resource(rejection.unwrap_err()),
            (DiffResource::ChangedFiles, limits.max_changed_files)
        );
    }

    #[test]
    fn a_limit_rejection_names_the_resource_without_echoing_the_path() {
        let limits = DiffLimits {
            max_path_bytes: 8,
            ..small_limits()
        };
        let secret = "s3cr3t-token-in-a-path";
        let diff = format!("--- a/{secret}\n+++ b/{secret}\n@@ -1,1 +1,1 @@\n+a\n");

        let message = match parse_unified_diff(&diff, limits) {
            Ok(_) => panic!("an oversized path must be rejected"),
            Err(error) => error.to_string(),
        };

        assert_eq!(
            message,
            "review diff exceeds the changed file path bytes limit of 8"
        );
        assert!(!message.contains(secret));
    }

    #[test]
    fn every_diff_limit_resource_has_a_stable_display_name() {
        assert_eq!(DiffResource::ChangedFiles.to_string(), "changed files");
        assert_eq!(
            DiffResource::RangesPerFile.to_string(),
            "changed line ranges per file"
        );
        assert_eq!(
            DiffResource::TotalRanges.to_string(),
            "total changed line ranges"
        );
        assert_eq!(
            DiffResource::PathBytes.to_string(),
            "changed file path bytes"
        );
    }

    #[test]
    fn quoted_timestamped_and_renamed_headers_resolve_new_side_paths() {
        let quoted = "--- \"a/odd name.rs\"\n+++ \"b/odd name.rs\"\n@@ -1,1 +1,2 @@\n+a\n";
        assert_eq!(
            parsed_diff(quoted).keys().collect::<Vec<_>>(),
            vec!["odd name.rs"]
        );

        let escaped = r#"--- "a/odd\040name\011part.rs"
+++ "b/odd\040name\011part.rs"
@@ -1,1 +3,2 @@
+a
"#;
        assert_eq!(
            parsed_diff(escaped).get("odd name\tpart.rs"),
            Some(&vec![(3, 4)])
        );

        let timestamped = "--- a/old.rs\t2026-01-01\n+++ b/new.rs\t2026-01-02\n@@ -1 +2 @@\n+a\n";
        assert_eq!(parsed_diff(timestamped).get("new.rs"), Some(&vec![(2, 2)]));

        let renamed = "diff --git a/old.rs b/new.rs\n\
                       similarity index 100%\n\
                       rename from old.rs\n\
                       rename to new.rs\n";
        assert!(parsed_diff(renamed).is_empty());

        let renamed_with_hunks = "diff --git a/old.rs b/new.rs\n\
                                  similarity index 84%\n\
                                  rename from old.rs\n\
                                  rename to new.rs\n\
                                  --- a/old.rs\n\
                                  +++ b/new.rs\n\
                                  @@ -1,1 +1,2 @@\n\
                                  +a\n";
        assert_eq!(
            parsed_diff(renamed_with_hunks).get("new.rs"),
            Some(&vec![(1, 2)])
        );
    }

    #[test]
    fn git_quoted_path_decoder_supports_c_escapes_and_timestamp_suffixes() {
        let encoded = concat!(r#""b/\a\b\t\n\v\f\r\\\".rs""#, "\t2026-01-01");

        assert_eq!(
            decode_git_quoted_path(encoded).unwrap(),
            "b/\x07\x08\t\n\x0b\x0c\r\\\".rs"
        );
        assert_eq!(new_side_path("").unwrap(), None);
    }

    #[test]
    fn a_short_octal_escape_ends_at_the_first_non_octal_byte() {
        assert_eq!(
            decode_git_quoted_path(r#""b/a\77z\101\1.rs""#).unwrap(),
            "b/a?zA\x01.rs"
        );

        let diff = concat!(
            "--- a/old.rs\n",
            r#"+++ "b/dir/a\77z.rs""#,
            "\n@@ -1 +1,2 @@\n+a\n"
        );

        assert_eq!(parsed_diff(diff).get("dir/a?z.rs"), Some(&vec![(1, 2)]));
    }

    #[test]
    fn malformed_quoted_diff_paths_are_rejected() {
        for path in [
            r#""b/unterminated.rs"#,
            r#""b/incomplete\"#,
            r#""b/bad\q.rs""#,
            r#""b/bad\400.rs""#,
            r#""b/bad\000.rs""#,
            r#""b/bad\377.rs""#,
            r#""b/file.rs"suffix"#,
        ] {
            let diff = format!("--- a/old.rs\n+++ {path}\n@@ -1 +1 @@\n+a\n");

            assert!(matches!(
                parse_unified_diff(&diff, DiffLimits::default()),
                Err(ReviewError::Scope(_))
            ));
        }
    }

    #[test]
    fn validated_hunks_rejects_one_range_past_the_total_across_changed_files() {
        let limits = small_limits();
        let hunks = BTreeMap::from([
            ("a.rs".to_string(), vec![(1, 1), (2, 2)]),
            ("b.rs".to_string(), vec![(3, 3), (4, 4)]),
        ]);

        let rejection = validated_hunks(hunks, limits);

        assert!(rejection.is_err(), "four ranges exceed the total of 3");
        assert_eq!(
            exhausted_resource(rejection.unwrap_err()),
            (DiffResource::TotalRanges, limits.max_total_ranges)
        );
    }

    #[test]
    fn validated_hunks_accepts_a_scope_that_exactly_meets_every_limit() {
        let limits = small_limits();
        let hunks = BTreeMap::from([
            ("a.rs".to_string(), vec![(1, 1), (2, 2)]),
            ("b.rs".to_string(), vec![(3, 3)]),
        ]);

        let validated = validated_hunks(hunks, limits).expect("the exact boundary is reviewable");

        assert_eq!(validated.len(), limits.max_changed_files);
        assert_eq!(
            validated.get("a.rs").map(Vec::len),
            Some(limits.max_ranges_per_file)
        );
    }

    #[test]
    fn validated_hunks_rejects_an_oversized_path_before_normalizing_it() {
        let limits = small_limits();
        let huge = "p".repeat(limits.max_path_bytes + 1);
        let hunks = BTreeMap::from([(huge.clone(), vec![(1, 1)])]);

        let rejection = validated_hunks(hunks, limits);

        assert!(rejection.is_err(), "an oversized path must be rejected");
        let error = rejection.unwrap_err();
        assert!(!error.to_string().contains(huge.as_str()));
        assert_eq!(
            exhausted_resource(error),
            (DiffResource::PathBytes, limits.max_path_bytes)
        );
    }

    #[test]
    fn a_review_scope_rejects_a_changed_path_beyond_four_kibibytes() {
        let huge = "p".repeat(MAX_REPORTED_PATH_BYTES + 1);
        let rejection = ReviewScope::new(
            1,
            "main".to_string(),
            None,
            BTreeMap::from([(huge.clone(), vec![(1, 1)])]),
            String::new(),
        );

        let message = match rejection {
            Ok(_) => panic!("a 4 KiB changed path must be rejected"),
            Err(error) => error.to_string(),
        };
        assert_eq!(
            message,
            "review diff exceeds the changed file path bytes limit of 4096"
        );
        assert!(!message.contains(huge.as_str()));

        let exact = "p".repeat(MAX_REPORTED_PATH_BYTES);
        assert!(
            ReviewScope::new(
                1,
                "main".to_string(),
                None,
                BTreeMap::from([(exact, vec![(1, 1)])]),
                String::new(),
            )
            .is_ok(),
            "a path of exactly 4096 bytes stays reviewable"
        );
    }

    #[test]
    fn prompt_section_lists_files_and_ranges() {
        let parsed = parsed_diff(SAMPLE_DIFF);
        let scope = ReviewScope::new(
            18,
            "main".to_string(),
            Some("abc".to_string()),
            parsed,
            SAMPLE_DIFF.to_string(),
        )
        .unwrap();
        let section = scope.prompt_section(10_000);
        assert!(section.contains("pull request #18"));
        assert!(section.contains("src/foo.rs: 10-13, 41-42"));
        assert!(section.contains("new.txt: 1-2"));
    }

    #[test]
    fn prompt_section_truncates_large_diff() {
        let big = "x".repeat(50_000);
        let scope = ReviewScope::new(1, String::new(), None, BTreeMap::new(), big).unwrap();
        let section = scope.prompt_section(1_000);
        assert!(section.contains("(truncated)"));
        assert!(section.contains("diff truncated"));
    }

    fn rejected_scope(result: Result<ReviewScope, ReviewError>) -> String {
        match result {
            Ok(_) => panic!("the review scope must be rejected"),
            Err(error) => error.to_string(),
        }
    }

    fn rejected_coverage(result: Result<(), ReviewError>) -> String {
        match result {
            Ok(()) => panic!("the changed file coverage must be rejected"),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn a_review_scope_normalizes_its_changed_paths() {
        let scope = ReviewScope::new(
            3,
            "main".to_string(),
            Some("ABCDEF0123456789".to_string()),
            BTreeMap::from([("./src/app.rs".to_string(), vec![(4, 9)])]),
            String::new(),
        )
        .unwrap();

        assert_eq!(
            scope.changed_files(),
            BTreeSet::from(["src/app.rs".to_string()])
        );
        assert_eq!(
            scope.hunk_ranges(),
            BTreeMap::from([("src/app.rs".to_string(), vec![(4, 9)])])
        );
        assert!(
            scope
                .prompt_section(64)
                .contains(", head commit: ABCDEF012345)"),
            "the head commit is rendered on a character boundary"
        );
    }

    #[test]
    fn a_review_scope_rejects_unusable_pull_request_metadata() {
        let hunks = || BTreeMap::from([("src/app.rs".to_string(), vec![(1, 2)])]);

        assert_eq!(
            rejected_scope(ReviewScope::new(
                0,
                "main".to_string(),
                None,
                hunks(),
                String::new()
            )),
            "invalid review scope: pull request number must be greater than zero"
        );
        assert!(
            rejected_scope(ReviewScope::new(
                1,
                "b".repeat(MAX_BASE_REF_BYTES + 1),
                None,
                hunks(),
                String::new()
            ))
            .contains("base reference exceeds")
        );
        assert!(
            rejected_scope(ReviewScope::new(
                1,
                "main".to_string(),
                None,
                hunks(),
                "x".repeat(MAX_DIFF_BYTES + 1)
            ))
            .contains("unified diff exceeds")
        );

        for head_sha in [String::new(), "ábcdef".to_string(), "a".repeat(65)] {
            assert!(
                rejected_scope(ReviewScope::new(
                    1,
                    "main".to_string(),
                    Some(head_sha.clone()),
                    hunks(),
                    String::new()
                ))
                .contains("head commit must be 1 to 64 hexadecimal characters"),
                "{head_sha:?} is not a commit identifier"
            );
        }
    }

    #[test]
    fn a_review_scope_rejects_unusable_changed_files() {
        let with_hunks = |path: &str, spans: Vec<(u32, u32)>| {
            ReviewScope::new(
                1,
                "main".to_string(),
                None,
                BTreeMap::from([(path.to_string(), spans)]),
                String::new(),
            )
        };

        assert!(
            rejected_scope(with_hunks("../escape.rs", vec![(1, 1)]))
                .contains("changed file '../escape.rs'")
        );
        assert!(rejected_scope(with_hunks("/etc/passwd", vec![(1, 1)])).contains("relative"));
        assert!(
            rejected_scope(with_hunks("src/app.rs", vec![(0, 1)]))
                .contains("src/app.rs: line range start must be greater than zero")
        );
        assert!(
            rejected_scope(with_hunks("src/app.rs", vec![(1, 0)]))
                .contains("line range end must be greater than zero")
        );
        assert!(
            rejected_scope(with_hunks("src/app.rs", vec![(9, 2)]))
                .contains("line range end 2 precedes start 9")
        );
        assert!(
            rejected_scope(with_hunks(
                "src/app.rs",
                vec![(1, 1); MAX_RANGES_PER_FILE + 1]
            ))
            .contains("review diff exceeds the changed line ranges per file limit of 10000")
        );

        let duplicated = BTreeMap::from([
            ("src/app.rs".to_string(), vec![(1, 1)]),
            ("./src/app.rs".to_string(), vec![(2, 2)]),
        ]);
        assert!(
            rejected_scope(ReviewScope::new(
                1,
                "main".to_string(),
                None,
                duplicated,
                String::new()
            ))
            .contains("duplicate path src/app.rs")
        );

        let flooded = (0..=MAX_CHANGED_FILES)
            .map(|index| (format!("file{index}.rs"), vec![(1, 1)]))
            .collect();
        assert!(
            rejected_scope(ReviewScope::new(
                1,
                "main".to_string(),
                None,
                flooded,
                String::new()
            ))
            .contains("review diff exceeds the changed files limit of 10000")
        );
    }

    #[test]
    fn changed_file_coverage_must_name_repository_relative_inspectable_paths() {
        let mut scope = ReviewScope::new(
            1,
            "main".to_string(),
            None,
            BTreeMap::from([("a.rs".to_string(), vec![(1, 1)])]),
            String::new(),
        )
        .unwrap();

        scope
            .set_changed_file_coverage(ChangedFileCoverage {
                inspectable: BTreeSet::from(["a.rs".to_string()]),
                skipped: vec![SkippedChangedFile {
                    path: "../escape.rs".to_string(),
                    reason: ChangedFileSkipReason::UnsafePath,
                }],
            })
            .unwrap();
        assert_eq!(
            scope.skipped_changed_files().len(),
            1,
            "an unsafe changed file is reported as skipped, never analyzed"
        );

        assert!(
            rejected_coverage(scope.set_changed_file_coverage(ChangedFileCoverage {
                inspectable: BTreeSet::from(["/etc/passwd".to_string()]),
                skipped: Vec::new(),
            }))
            .contains("changed file '/etc/passwd'")
        );
        assert!(
            rejected_coverage(scope.set_changed_file_coverage(ChangedFileCoverage {
                inspectable: BTreeSet::new(),
                skipped: vec![SkippedChangedFile {
                    path: "x".repeat(MAX_REPORTED_PATH_BYTES + 1),
                    reason: ChangedFileSkipReason::AbsentFromSnapshot,
                }],
            }))
            .contains("skipped changed file path exceeds")
        );
        assert!(
            rejected_coverage(
                scope.set_changed_file_coverage(ChangedFileCoverage {
                    inspectable: (0..=MAX_CHANGED_FILES)
                        .map(|index| format!("file{index}.rs"))
                        .collect(),
                    skipped: Vec::new(),
                })
            )
            .contains("coverage exceeds 10000 paths")
        );
        assert_eq!(
            scope.skipped_changed_files().len(),
            1,
            "a rejected coverage update leaves the previous coverage in place"
        );
    }

    #[test]
    fn changed_file_coverage_separates_inspectable_from_skipped_paths() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.rs"), "fn a() {}\n").unwrap();
        std::fs::write(dir.path().join("deps.lock"), "x\n").unwrap();
        let engine = crate::config::EngineConfig::default();
        let changed: BTreeSet<String> = [
            "a.rs".to_string(),
            "deps.lock".to_string(),
            "gone.txt".to_string(),
            "../escape.rs".to_string(),
        ]
        .into_iter()
        .collect();

        let coverage = classify_changed_files(dir.path(), &engine, &changed).unwrap();

        assert_eq!(
            coverage.inspectable,
            ["a.rs".to_string()].into_iter().collect::<BTreeSet<_>>()
        );
        assert!(coverage.is_partial());
        assert_eq!(
            coverage.skipped_report_entries(),
            vec![
                "../escape.rs (not a repository-relative path)".to_string(),
                "deps.lock (excluded by engine filters)".to_string(),
                "gone.txt (absent from the pull request snapshot)".to_string(),
            ],
            "every skipped changed file must survive with its reason"
        );
    }

    #[test]
    fn changed_file_coverage_is_empty_when_every_changed_file_is_filtered() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("deps.lock"), "x\n").unwrap();
        let engine = crate::config::EngineConfig::default();
        let changed: BTreeSet<String> = ["deps.lock".to_string()].into_iter().collect();

        let coverage = classify_changed_files(dir.path(), &engine, &changed).unwrap();

        assert!(coverage.inspectable.is_empty());
        assert_eq!(
            coverage.skipped,
            vec![SkippedChangedFile {
                path: "deps.lock".to_string(),
                reason: ChangedFileSkipReason::ExcludedByEngineFilters,
            }]
        );
    }

    #[test]
    fn changed_file_classification_reports_inventory_failures() {
        let directory = tempfile::tempdir().unwrap();
        let removed_root = directory.path().to_path_buf();
        directory.close().unwrap();

        let result = classify_changed_files(
            &removed_root,
            &crate::config::EngineConfig::default(),
            &BTreeSet::new(),
        );
        let error = match result {
            Ok(_) => panic!("a removed project root must be rejected"),
            Err(error) => error,
        };

        assert!(matches!(error, ReviewError::Engine(_)));
    }

    #[test]
    fn snapshot_ignore_files_cannot_hide_a_changed_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("changed.rs"), "fn changed() {}\n").unwrap();
        std::fs::write(dir.path().join(".ignore"), "changed.rs\n").unwrap();
        let changed: BTreeSet<String> = ["changed.rs".to_string()].into_iter().collect();
        let snapshot_engine = crate::config::EngineConfig {
            discovery_source: crate::config::schema::DiscoverySource::UntrustedSnapshot,
            ..crate::config::EngineConfig::default()
        };

        let local = classify_changed_files(
            dir.path(),
            &crate::config::EngineConfig::default(),
            &changed,
        )
        .unwrap();
        let snapshot = classify_changed_files(dir.path(), &snapshot_engine, &changed).unwrap();

        assert!(
            local.inspectable.is_empty(),
            "a local scan still honors repository ignore files"
        );
        assert_eq!(
            snapshot.inspectable, changed,
            "an ignore file authored in the pull request head must not shrink review scope"
        );
        assert!(snapshot.skipped.is_empty());
    }

    #[test]
    fn accepts_github_https_and_ssh_origins() {
        let hosts = github_hosts();

        for remote in [
            "https://github.com/owner/project.git",
            "https://github.com/owner/project",
            "git@github.com:owner/project.git",
            "ssh://git@ssh.github.com:443/owner/project.git",
            "https://token@www.github.com/owner/project.git",
        ] {
            assert_eq!(
                repository_slug_from_remote(remote, &hosts)
                    .unwrap_or_else(|error| panic!("{remote} must resolve: {error}"))
                    .as_str(),
                "owner/project"
            );
        }
    }

    #[test]
    fn rejects_origins_hosted_outside_github() {
        let hosts = github_hosts();

        for remote in [
            "git@gitlab.com:owner/project.git",
            "https://gitlab.com/owner/project.git",
            "https://bitbucket.org/owner/project.git",
            "https://github.com.evil.example/owner/project.git",
            "ssh://git@evil.example/owner/project.git",
        ] {
            let error = repository_slug_from_remote(remote, &hosts)
                .expect_err("a non-GitHub origin must be rejected");
            assert!(
                error.to_string().contains("is not a GitHub host"),
                "unexpected error for {remote}: {error}"
            );
        }
    }

    #[test]
    fn rejects_origins_without_a_resolvable_host() {
        let hosts = github_hosts();

        for remote in ["/srv/git/project.git", "github.com:owner/project.git", ""] {
            let error = repository_slug_from_remote(remote, &hosts)
                .expect_err("an origin without a host must be rejected");
            assert!(
                error
                    .to_string()
                    .contains("cannot derive a GitHub repository"),
                "unexpected error for {remote}: {error}"
            );
        }
    }

    #[test]
    fn enterprise_api_host_resolves_its_own_origins() {
        let hosts = GitHubHostPolicy::with_api_host("ghe.example.com");

        assert_eq!(
            repository_slug_from_remote("https://ghe.example.com/owner/project.git", &hosts)
                .unwrap()
                .as_str(),
            "owner/project"
        );
    }

    #[test]
    fn rejected_origins_never_echo_their_credentials() {
        let hosts = github_hosts();
        let secret = "ghp-super-secret";

        for remote in [
            format!("https://oauth2:{secret}@gitlab.com/owner/project.git"),
            format!("https://{secret}@gitlab.com/owner/project.git"),
            format!("https://oauth2:{secret}@github.com/owner/project/extra.git"),
            format!("{secret}:pass@github.com:owner/project.git"),
            format!("https://gitlab.com/owner/project.git?token={secret}"),
            format!("git@gitlab.com:owner/project.git#{secret}"),
        ] {
            let error = repository_slug_from_remote(&remote, &hosts)
                .expect_err("the origin must be rejected");

            assert!(
                !error.to_string().contains(secret),
                "credentials leaked for {remote}: {error}"
            );
        }
    }

    #[test]
    fn rejected_origins_name_only_their_host() {
        let hosts = github_hosts();

        assert_eq!(
            repository_slug_from_remote("https://gitlab.com/owner/project.git", &hosts)
                .unwrap_err()
                .to_string(),
            "git failed: origin host 'gitlab.com' is not a GitHub host; \
         pass --repo owner/repository"
        );
        assert_eq!(
            repository_slug_from_remote("https://github.com/owner/project/extra", &hosts)
                .unwrap_err()
                .to_string(),
            "git failed: cannot derive a GitHub repository from the origin path on 'github.com'; \
         pass --repo owner/repository"
        );
    }

    #[test]
    fn the_first_non_empty_token_variable_wins() {
        assert_eq!(
            first_usable_token(["".to_string(), "second".to_string()].into_iter()),
            Some("second".to_string())
        );
        assert_eq!(
            first_usable_token(["first".to_string(), "second".to_string()].into_iter()),
            Some("first".to_string())
        );
        assert_eq!(
            first_usable_token(["".to_string()].into_iter()),
            None,
            "an empty token must not authenticate the request"
        );
    }

    struct EndlessPipe {
        remaining_reads: usize,
    }

    impl Read for EndlessPipe {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let Some(remaining) = self.remaining_reads.checked_sub(1) else {
                return Err(std::io::Error::other(
                    "the reader kept draining past the limit",
                ));
            };
            self.remaining_reads = remaining;
            let written = buffer.len().min(8);
            buffer[..written].fill(b'x');
            Ok(written)
        }
    }

    #[test]
    fn bounded_process_reader_stops_at_the_first_byte_beyond_the_limit() {
        let captured = read_process_pipe(EndlessPipe { remaining_reads: 3 }, 16).unwrap();

        assert_eq!(captured.bytes, b"x".repeat(16));
        assert!(captured.truncated);
    }

    #[test]
    fn bounded_process_reader_keeps_output_that_exactly_reaches_the_limit() {
        let captured = read_process_pipe(std::io::Cursor::new(b"abcd"), 4).unwrap();

        assert_eq!(captured.bytes, b"abcd");
        assert!(!captured.truncated);
    }

    #[cfg(unix)]
    fn await_process_exit(process_id: i32) {
        let deadline = std::time::Instant::now() + GIT_METADATA_TIMEOUT;
        while crate::process::process_is_alive(process_id) {
            assert!(
                std::time::Instant::now() < deadline,
                "a pipe-holding descendant outlived its process group"
            );
            std::thread::yield_now();
        }
    }

    #[cfg(unix)]
    const DESCENDANT_PID_FILE: &str = "descendant.pid";

    #[cfg(unix)]
    const RECORDS_A_DESCENDANT_AND_WAITS: &str = "tail -f /dev/null &\n\
         printf '%s\\n' \"$!\" > descendant.partial\n\
         mv descendant.partial descendant.pid\n\
         wait\n";

    #[cfg(unix)]
    fn report_timeout_once_the_descendant_is_recorded(
        child: &mut Child,
        _timeout: Duration,
    ) -> std::io::Result<Option<ExitStatus>> {
        let working_directory = std::fs::read_link(format!("/proc/{}/cwd", child.id()))?;
        let recorded = working_directory.join(DESCENDANT_PID_FILE);
        let deadline = std::time::Instant::now() + GIT_METADATA_TIMEOUT;
        while !recorded.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "the command never recorded its descendant"
            );
            std::thread::yield_now();
        }
        Ok(None)
    }

    #[cfg(unix)]
    #[test]
    fn git_metadata_timeout_terminates_the_subprocess_tree() {
        let directory = tempfile::tempdir().unwrap();

        let error = run_git_metadata_command(
            Path::new("/bin/sh"),
            directory.path(),
            &["-c", RECORDS_A_DESCENDANT_AND_WAITS],
            GIT_METADATA_TIMEOUT,
            ProcessControl {
                wait: report_timeout_once_the_descendant_is_recorded,
                ..ProcessControl::default()
            },
        )
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            format!(
                "git failed: git metadata command exceeded {} seconds",
                GIT_METADATA_TIMEOUT.as_secs_f64()
            )
        );
        let descendant: i32 = std::fs::read_to_string(directory.path().join(DESCENDANT_PID_FILE))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        await_process_exit(descendant);
    }

    #[test]
    fn prompt_lists_changed_files_without_line_ranges() {
        let scope = ReviewScope::new(
            1,
            String::new(),
            None,
            BTreeMap::from([("deleted.rs".to_string(), Vec::new())]),
            String::new(),
        )
        .unwrap();

        let prompt = scope.prompt_section(100);

        assert!(prompt.contains("base branch: unknown"));
        assert!(prompt.contains("- deleted.rs\n"));
        assert!(!prompt.contains("head commit:"));
    }

    #[test]
    fn git_metadata_reports_spawn_failure() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing-git");

        let error = run_git_metadata_command(
            &missing,
            directory.path(),
            &[],
            Duration::from_secs(1),
            ProcessControl::default(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("run git metadata command"));
    }

    #[cfg(unix)]
    #[test]
    fn git_metadata_reports_nonzero_status_and_invalid_utf8() {
        let directory = tempfile::tempdir().unwrap();
        let error = run_git_metadata_command(
            Path::new("/bin/sh"),
            directory.path(),
            &["-c", "printf failed >&2; exit 7"],
            Duration::from_secs(1),
            ProcessControl::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("failed"));

        let error = run_git_metadata_command(
            Path::new("/bin/sh"),
            directory.path(),
            &["-c", "printf '\\377'"],
            Duration::from_secs(1),
            ProcessControl::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("not UTF-8"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_git_metadata_commands_capture_success_and_nonzero_status() {
        let directory = tempfile::tempdir().unwrap();
        let output = run_git_metadata_command(
            Path::new("cmd.exe"),
            directory.path(),
            &["/D", "/S", "/C", "echo ok"],
            Duration::from_secs(5),
            ProcessControl::default(),
        )
        .unwrap();
        assert_eq!(output.trim(), "ok");

        let error = run_git_metadata_command(
            Path::new("cmd.exe"),
            directory.path(),
            &["/D", "/S", "/C", "echo failed 1>&2 & exit /b 7"],
            Duration::from_secs(5),
            ProcessControl::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("failed"));
    }

    #[test]
    fn process_reader_failures_retain_the_stream_name() {
        let (sender, captures) = std::sync::mpsc::channel();
        sender
            .send(Err(std::io::Error::other("broken reader")))
            .unwrap();
        let reader = PipeReader {
            stream: "stdout",
            captures,
        };

        let error = reader
            .collect(MetadataDeadline::starting_now(GIT_METADATA_TIMEOUT))
            .unwrap_err();

        assert!(error.to_string().contains("read git stdout"));
        assert!(error.to_string().contains("broken reader"));
    }

    #[test]
    fn process_reader_panics_retain_the_stream_name() {
        let (sender, captures) = std::sync::mpsc::channel::<std::io::Result<ProcessCapture>>();
        std::thread::spawn(move || {
            let _sender = sender;
            panic!("reader panic");
        });
        let reader = PipeReader {
            stream: "stderr",
            captures,
        };

        let error = reader
            .collect(MetadataDeadline::starting_now(GIT_METADATA_TIMEOUT))
            .unwrap_err();

        assert!(error.to_string().contains("git stderr reader panicked"));
    }

    #[test]
    fn unicode_truncation_stops_on_a_character_boundary() {
        assert_eq!(safe_truncate("é", 1), "");
        assert_eq!(safe_truncate("é", 2), "é");
    }

    fn read_seed_corpus(target: &str) -> BTreeMap<String, String> {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fuzz/seeds")
            .join(target);
        let mut seeds = BTreeMap::new();
        for entry in std::fs::read_dir(&directory).expect("committed fuzz seed corpus") {
            let path = entry.expect("seed directory entry").path();
            let name = path
                .file_name()
                .expect("seed file name")
                .to_string_lossy()
                .into_owned();
            let bytes = std::fs::read(&path).expect("seed contents");
            seeds.insert(name, String::from_utf8_lossy(&bytes).into_owned());
        }
        assert!(
            !seeds.is_empty(),
            "the committed {target} seed corpus is empty"
        );
        seeds
    }

    #[test]
    fn unified_diff_seed_corpus_is_deterministic_for_accepted_and_rejected_inputs() {
        let seeds = read_seed_corpus("unified_diff");
        for required in [
            "single-file-two-hunks",
            "crlf-line-endings",
            "zero-start-hunk-header",
            "saturating-start-hunk-header",
            "max-start-single-line-hunk",
            "truncated-hunk-header",
            "header-without-path",
            "header-inside-hunk-body",
            "control-bytes-in-path",
            "trailing-carriage-return-header",
            "unterminated-quoted-path",
        ] {
            assert!(
                seeds.contains_key(required),
                "the committed unified_diff corpus lost the {required} seed"
            );
        }

        let parse_outcome = |diff: &str| {
            parse_unified_diff(diff, DiffLimits::default()).map_err(|error| error.to_string())
        };
        let mut accepted = 0usize;
        let mut rejected = 0usize;

        for (name, diff) in &seeds {
            let outcome = parse_outcome(diff);
            assert_eq!(
                &outcome,
                &parse_outcome(diff),
                "{name} parses nondeterministically"
            );

            let without_carriage_returns = diff.replace('\r', "");
            let normalized = parse_outcome(&without_carriage_returns);
            assert_eq!(
                normalized,
                parse_outcome(&format!("{without_carriage_returns}\n")),
                "{name} parses differently with a trailing newline"
            );
            assert_eq!(
                normalized,
                parse_outcome(&without_carriage_returns.replace('\n', "\r\n")),
                "{name} parses differently with CRLF line endings"
            );

            let Ok(hunks) = outcome else {
                rejected += 1;
                continue;
            };
            accepted += 1;

            let header_lines = diff.lines().filter(|line| line.starts_with("+++ ")).count();
            let hunk_lines = diff.lines().filter(|line| line.starts_with("@@")).count();
            assert!(
                hunks.len() <= header_lines,
                "{name} produced more files than new-side headers"
            );

            let mut parsed_ranges = 0;
            for (path, spans) in &hunks {
                assert!(!path.is_empty(), "{name} produced an empty file path");
                assert!(
                    !path.contains('\t'),
                    "{name} produced the tab-bearing path {path:?}"
                );
                assert!(
                    diff.contains(path.as_str()),
                    "{name} produced the path {path:?} which is absent from the diff"
                );
                for &(start, end) in spans {
                    assert!(
                        start >= 1 && start <= end,
                        "{name} produced the invalid range ({start}, {end}) for {path:?}"
                    );
                }
                parsed_ranges += spans.len();
            }
            assert!(
                parsed_ranges <= hunk_lines,
                "{name} produced more ranges than hunk headers"
            );
        }

        assert!(
            accepted > 0,
            "the committed seed corpus has no accepted diff"
        );
        assert!(
            rejected > 0,
            "the committed seed corpus has no rejected diff"
        );
    }

    #[test]
    fn unified_diff_seeds_stay_within_injected_limits_or_are_rejected() {
        let limits = DiffLimits {
            max_changed_files: 2,
            max_ranges_per_file: 2,
            max_total_ranges: 3,
            max_path_bytes: 16,
        };
        let mut accepted = 0usize;

        for (name, diff) in read_seed_corpus("unified_diff") {
            let Ok(hunks) = parse_unified_diff(&diff, limits) else {
                continue;
            };
            accepted += 1;
            assert!(
                hunks.len() <= limits.max_changed_files,
                "{name} retained {} changed files",
                hunks.len()
            );
            let mut retained_ranges = 0usize;
            for (path, spans) in &hunks {
                assert!(
                    path.len() <= limits.max_path_bytes,
                    "{name} retained the {} byte path {path:?}",
                    path.len()
                );
                assert!(
                    spans.len() <= limits.max_ranges_per_file,
                    "{name} retained {} ranges for {path:?}",
                    spans.len()
                );
                retained_ranges += spans.len();
            }
            assert!(
                retained_ranges <= limits.max_total_ranges,
                "{name} retained {retained_ranges} ranges in total"
            );
        }

        assert!(
            accepted > 0,
            "no committed seed parses within the injected limits"
        );
    }

    #[test]
    fn unified_diff_seed_adversarial_headers_have_pinned_hunks() {
        let seeds = read_seed_corpus("unified_diff");
        let hunks_for = |name: &str| parsed_diff(&seeds[name]);
        let pinned =
            |path: &str, spans: Vec<(u32, u32)>| BTreeMap::from([(path.to_string(), spans)]);

        assert_eq!(
            hunks_for("single-file-two-hunks"),
            pinned("src/main.rs", vec![(1, 4), (22, 26)])
        );
        assert_eq!(
            hunks_for("crlf-line-endings"),
            pinned("src/lib.rs", vec![(1, 3)])
        );
        assert_eq!(
            hunks_for("max-start-single-line-hunk"),
            pinned("max.rs", vec![(u32::MAX, u32::MAX)])
        );
        assert_eq!(
            hunks_for("header-inside-hunk-body"),
            pinned("body.rs", vec![(1, 6), (9, 17)])
        );
        assert_eq!(
            hunks_for("zero-count-hunks"),
            pinned("counts.rs", vec![(7, 7)])
        );
        assert_eq!(
            hunks_for("zero-start-hunk-header"),
            pinned("zero.rs", Vec::new())
        );
        assert_eq!(
            hunks_for("saturating-start-hunk-header"),
            pinned("sat.rs", Vec::new())
        );
        assert_eq!(
            hunks_for("truncated-hunk-header"),
            pinned("trunc.rs", Vec::new())
        );
        assert_eq!(
            hunks_for("deleted-file-dev-null"),
            pinned("gone.rs", Vec::new())
        );

        for empty in [
            "header-without-path",
            "rename-and-mode-only",
            "binary-file",
            "hunk-before-any-header",
        ] {
            assert!(
                hunks_for(empty).is_empty(),
                "{empty} must produce no reviewable files"
            );
        }
    }

    #[test]
    fn unified_diff_seed_trailing_carriage_return_stays_in_the_path_until_terminated() {
        let seeds = read_seed_corpus("unified_diff");
        let diff = &seeds["trailing-carriage-return-header"];

        assert_eq!(
            parsed_diff(diff),
            BTreeMap::from([
                ("x.rs".to_string(), Vec::new()),
                ("x.rs\r".to_string(), Vec::new()),
            ])
        );
        assert_eq!(
            parsed_diff(&format!("{diff}\n")),
            BTreeMap::from([("x.rs".to_string(), Vec::<(u32, u32)>::new())])
        );
    }

    const PR_BASE_SHA: &str = "1111111111111111111111111111111111111111";
    const PR_HEAD_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
    const PR_DIFF: &str = "--- a/src/foo.rs\n+++ b/src/foo.rs\n@@ -1,1 +1,2 @@\n+// added\n";

    #[derive(Clone, Default)]
    struct CapturedLogs(std::sync::Arc<parking_lot::Mutex<Vec<u8>>>);

    impl CapturedLogs {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().clone()).expect("log output is utf-8")
        }
    }

    impl Write for CapturedLogs {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.0.lock().extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn capture_logs(emit: impl FnOnce()) -> String {
        use tracing_subscriber::layer::SubscriberExt;

        let captured = CapturedLogs::default();
        let sink = captured.clone();
        let layer = tracing_subscriber::fmt::layer()
            .with_writer(move || sink.clone())
            .with_ansi(false)
            .without_time();
        tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), emit);
        captured.text()
    }

    fn pull_request_archive() -> Vec<u8> {
        let mut archive = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        archive
            .start_file(
                "owner-project-head/src/foo.rs",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        archive.write_all(b"fn foo() {}\n").unwrap();
        archive.finish().unwrap().into_inner()
    }

    fn test_github_client(api_base: &str) -> GitHubClient {
        GitHubClient::new(
            reqwest::Url::parse(&format!("{api_base}/")).unwrap(),
            None,
            github::GitHubLimits::default(),
        )
        .unwrap()
    }

    async fn mount_pull_request(
        server: &MockServer,
        base_ref: &str,
        diff: &str,
        archive: Option<Vec<u8>>,
    ) {
        Mock::given(method("GET"))
            .and(path("/repos/owner/project/pulls/7"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "base": { "ref": base_ref, "sha": PR_BASE_SHA },
                "head": { "sha": PR_HEAD_SHA }
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/repos/owner/project/compare/{PR_BASE_SHA}...{PR_HEAD_SHA}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_string(diff))
            .mount(server)
            .await;
        if let Some(archive) = archive {
            Mock::given(method("GET"))
                .and(path(format!("/repos/owner/project/zipball/{PR_HEAD_SHA}")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(archive))
                .mount(server)
                .await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pull_request_without_reviewable_hunks_is_rejected() {
        let server = MockServer::start().await;
        mount_pull_request(&server, "main", "", None).await;
        let api_base = server.uri();

        let outcome = tokio::task::spawn_blocking(move || {
            prepare_review_session(
                &test_github_client(&api_base),
                Path::new("."),
                7,
                Some("owner/project"),
            )
        })
        .await
        .unwrap();

        let Err(error) = outcome else {
            panic!("an empty diff must not produce a review session");
        };
        assert_eq!(error.to_string(), "PR #7 changed no reviewable files");
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            2,
            "an empty diff must not download the head archive"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_deletion_only_pull_request_is_reported_as_partial_coverage() {
        let server = MockServer::start().await;
        let deleted = "diff --git a/gone.rs b/gone.rs\n\
                       deleted file mode 100644\n\
                       --- a/gone.rs\n\
                       +++ /dev/null\n\
                       @@ -1 +0,0 @@\n\
                       -removed\n";
        mount_pull_request(&server, "main", deleted, Some(pull_request_archive())).await;
        let api_base = server.uri();

        let session = tokio::task::spawn_blocking(move || {
            prepare_review_session(
                &test_github_client(&api_base),
                Path::new("."),
                7,
                Some("owner/project"),
            )
        })
        .await
        .unwrap()
        .expect("a deletion is a changed file even without new-side lines");
        let coverage = classify_changed_files(
            &session.project_root,
            &crate::config::EngineConfig::default(),
            &session.scope.changed_files(),
        )
        .unwrap();

        assert!(coverage.inspectable.is_empty());
        assert_eq!(
            coverage.skipped,
            vec![SkippedChangedFile {
                path: "gone.rs".to_string(),
                reason: ChangedFileSkipReason::AbsentFromSnapshot,
            }]
        );
        assert!(coverage.is_partial());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn invalid_remote_diff_paths_are_rejected_after_snapshot_preparation() {
        let server = MockServer::start().await;
        let invalid_path_diff =
            "--- a/src:unsafe.rs\n+++ b/src:unsafe.rs\n@@ -1 +1 @@\n-old\n+new\n";
        mount_pull_request(
            &server,
            "main",
            invalid_path_diff,
            Some(pull_request_archive()),
        )
        .await;
        let api_base = server.uri();

        let outcome = tokio::task::spawn_blocking(move || {
            prepare_review_session(
                &test_github_client(&api_base),
                Path::new("."),
                7,
                Some("owner/project"),
            )
        })
        .await
        .unwrap();

        let error = match outcome {
            Ok(_) => panic!("invalid remote metadata must be rejected"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("Windows drive and alternate-stream paths are not allowed"),
            "{error}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_prepared_session_exposes_the_snapshot_and_logs_the_pinned_revision() {
        let server = MockServer::start().await;
        mount_pull_request(&server, "main", PR_DIFF, Some(pull_request_archive())).await;
        let api_base = server.uri();

        let (session, logs) = tokio::task::spawn_blocking(move || {
            let client = test_github_client(&api_base);
            let mut prepared = None;
            let logs = capture_logs(|| {
                prepared = Some(prepare_review_session(
                    &client,
                    Path::new("."),
                    7,
                    Some("owner/project"),
                ));
            });
            (prepared.unwrap().unwrap(), logs)
        })
        .await
        .unwrap();

        assert_eq!(session.scope.pr(), 7);
        assert_eq!(session.scope.base_ref(), "main");
        assert_eq!(session.scope.head_sha(), Some(PR_HEAD_SHA));
        assert_eq!(
            session.scope.changed_files(),
            BTreeSet::from(["src/foo.rs".to_string()])
        );
        assert_eq!(
            std::fs::read_to_string(session.project_root.join("src/foo.rs")).unwrap(),
            "fn foo() {}\n",
            "the reviewed files come from the extracted head archive"
        );
        assert!(logs.contains("prepared pull request archive"), "{logs}");
        assert!(logs.contains("repository=owner/project"), "{logs}");
        assert!(logs.contains("base=main"), "{logs}");
        assert!(logs.contains(&format!("head={PR_HEAD_SHA}")), "{logs}");
        assert!(logs.contains("files=1"), "{logs}");
        assert!(
            logs.contains(&format!("project_root={}", session.project_root.display())),
            "{logs}"
        );
    }

    #[test]
    fn snapshot_extraction_reports_unusable_directories() {
        let directory = tempfile::tempdir().unwrap();
        let absent = directory.path().join("absent");

        let error = create_extraction_directory(&absent).unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("create pull request extraction directory:"),
            "{error}"
        );

        let error = canonical_project_root(&absent).unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("resolve pull request project root:"),
            "{error}"
        );

        let extraction = create_extraction_directory(directory.path()).unwrap();
        assert_eq!(
            canonical_project_root(extraction.path()).unwrap(),
            extraction.path().canonicalize().unwrap()
        );
        assert!(
            extraction
                .path()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("bughunter-pr-")
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_command_without_pipes_is_rejected_and_terminated() {
        let directory = tempfile::tempdir().unwrap();
        let started = std::time::Instant::now();

        let mut command =
            git_metadata_command(Path::new("/bin/sh"), directory.path(), &["-c", "sleep 30"]);
        command.stdout(Stdio::null());
        let Err(error) = spawn_with_pipes(&mut command, spawn_std_grouped) else {
            panic!("a command without stdout must fail");
        };
        assert_eq!(
            error.to_string(),
            "git failed: git metadata command has no stdout pipe"
        );

        let mut command =
            git_metadata_command(Path::new("/bin/sh"), directory.path(), &["-c", "sleep 30"]);
        command.stderr(Stdio::null());
        let Err(error) = spawn_with_pipes(&mut command, spawn_std_grouped) else {
            panic!("a command without stderr must fail");
        };
        assert_eq!(
            error.to_string(),
            "git failed: git metadata command has no stderr pipe"
        );

        assert!(
            started.elapsed() < Duration::from_secs(10),
            "a missing pipe must terminate the child instead of waiting for it"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_grouped_spawn_is_reported_after_its_child_is_reaped() {
        static SPAWNED_CHILD: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

        fn refuse_spawn(
            command: &mut Command,
        ) -> std::io::Result<(Child, crate::process::ProcessGroup)> {
            let (mut child, group) = spawn_std_grouped(command)?;
            SPAWNED_CHILD.store(child.id(), std::sync::atomic::Ordering::SeqCst);
            crate::process::terminate_std(&mut child, group)?;
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "the isolated spawn was refused",
            ))
        }

        let directory = tempfile::tempdir().unwrap();
        let mut command = git_metadata_command(
            Path::new("/bin/sh"),
            directory.path(),
            &["-c", "exec sleep 30"],
        );
        let started = std::time::Instant::now();

        let Err(error) = spawn_with_pipes(&mut command, refuse_spawn) else {
            panic!("a refused grouped spawn must fail");
        };

        assert_eq!(
            error.to_string(),
            "run git metadata command: the isolated spawn was refused"
        );
        let ReviewError::Io { source, .. } = &error else {
            panic!("expected an I/O failure, got {error}");
        };
        assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "a refused spawn must kill the child instead of waiting for it"
        );
        let refused = i32::try_from(SPAWNED_CHILD.load(std::sync::atomic::Ordering::SeqCst))
            .expect("a spawned child reports a positive process id");
        assert!(
            unsafe { libc::kill(refused, 0) } != 0,
            "process {refused} must be reaped instead of left as a zombie"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_wait_terminates_the_command_and_reports_the_wait_error() {
        let directory = tempfile::tempdir().unwrap();
        let started = std::time::Instant::now();

        let error = run_git_metadata_command(
            Path::new("/bin/sh"),
            directory.path(),
            &["-c", "sleep 30"],
            Duration::from_secs(30),
            ProcessControl {
                wait: |_, _| Err(std::io::Error::other("waitpid failed")),
                ..ProcessControl::default()
            },
        )
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            "wait for git metadata command: waitpid failed"
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "a failed wait must still terminate the child"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_termination_is_reported_after_the_readers_are_released() {
        let directory = tempfile::tempdir().unwrap();

        let error = run_git_metadata_command(
            Path::new("/bin/sh"),
            directory.path(),
            &["-c", "sleep 30"],
            Duration::from_millis(50),
            ProcessControl {
                wait: |_, _| Ok(None),
                terminate: |child, group| {
                    crate::process::terminate_std(child, group)?;
                    Err(std::io::Error::other("kill refused"))
                },
                ..ProcessControl::default()
            },
        )
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            "terminate git metadata command: kill refused"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_process_group_cleanup_is_reported() {
        let directory = tempfile::tempdir().unwrap();

        let error = run_git_metadata_command(
            Path::new("/bin/sh"),
            directory.path(),
            &["-c", "printf 'ok\\n'"],
            GIT_METADATA_TIMEOUT,
            ProcessControl {
                terminate_group: |_| Err(std::io::Error::other("group kill refused")),
                ..ProcessControl::default()
            },
        )
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            "terminate git metadata process group: group kill refused"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_successful_command_does_not_wait_for_pipe_holding_descendants() {
        let directory = tempfile::tempdir().unwrap();

        let output = run_git_metadata_command(
            Path::new("/bin/sh"),
            directory.path(),
            &[
                "-c",
                "sh -c 'exec tail -f /dev/null' &\nprintf '%s\\n' \"$!\"\n",
            ],
            GIT_METADATA_TIMEOUT,
            ProcessControl::default(),
        )
        .unwrap();

        let descendant: i32 = output.trim().parse().unwrap();
        await_process_exit(descendant);
    }

    #[cfg(unix)]
    #[test]
    fn infinite_oversized_metadata_output_fails_fast() {
        let directory = tempfile::tempdir().unwrap();

        let error = run_git_metadata_command(
            Path::new("/bin/sh"),
            directory.path(),
            &["-c", "exec cat /dev/zero"],
            GIT_METADATA_TIMEOUT,
            ProcessControl::default(),
        )
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            format!("git failed: git metadata stdout exceeds {MAX_GIT_METADATA_BYTES} bytes"),
            "an endless writer must be rejected instead of exhausting the deadline"
        );
    }

    #[cfg(unix)]
    #[test]
    fn one_byte_past_the_metadata_limit_is_rejected_per_stream() {
        let directory = tempfile::tempdir().unwrap();
        let beyond_limit = MAX_GIT_METADATA_BYTES + 1;

        let stdout_error = run_git_metadata_command(
            Path::new("/bin/sh"),
            directory.path(),
            &["-c", &format!("head -c {beyond_limit} /dev/zero")],
            GIT_METADATA_TIMEOUT,
            ProcessControl::default(),
        )
        .unwrap_err();
        assert_eq!(
            stdout_error.to_string(),
            format!("git failed: git metadata stdout exceeds {MAX_GIT_METADATA_BYTES} bytes")
        );

        let stderr_error = run_git_metadata_command(
            Path::new("/bin/sh"),
            directory.path(),
            &["-c", &format!("head -c {beyond_limit} /dev/zero >&2")],
            GIT_METADATA_TIMEOUT,
            ProcessControl::default(),
        )
        .unwrap_err();
        assert_eq!(
            stderr_error.to_string(),
            format!("git failed: git metadata stderr exceeds {MAX_GIT_METADATA_BYTES} bytes")
        );
    }

    #[cfg(unix)]
    #[test]
    fn metadata_output_that_exactly_reaches_the_limit_is_accepted() {
        let directory = tempfile::tempdir().unwrap();

        let output = run_git_metadata_command(
            Path::new("/bin/sh"),
            directory.path(),
            &[
                "-c",
                &format!(
                    "head -c {MAX_GIT_METADATA_BYTES} /dev/zero\nhead -c {MAX_GIT_METADATA_BYTES} /dev/zero >&2\n"
                ),
            ],
            GIT_METADATA_TIMEOUT,
            ProcessControl::default(),
        )
        .unwrap();

        assert_eq!(output.len(), MAX_GIT_METADATA_BYTES);
    }

    #[cfg(unix)]
    #[test]
    fn a_reader_that_never_finishes_is_bounded_by_the_absolute_deadline() {
        let (writer, pipe) = std::os::unix::net::UnixStream::pair().unwrap();
        let reader = PipeReader::spawn("stdout", pipe);

        let error = reader
            .collect(MetadataDeadline::starting_now(Duration::ZERO))
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "git failed: git metadata command exceeded 0 seconds"
        );
        drop(writer);
    }
}
