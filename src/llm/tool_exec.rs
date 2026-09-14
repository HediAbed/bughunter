use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cancel::CancelToken;
use crate::config::schema::{AnalysisCategory, Severity};
use crate::domain::ProjectPath;
#[cfg(test)]
use crate::domain::ProjectRoot;
use crate::engine::{
    DiscoverOpts, Engine, FileContent, FileEntry, LineRange, ProjectFilesystem, ProjectInventory,
    SearchOpts,
};
use crate::report::{Confidence, Finding, FindingCounter, FindingSource};

use super::coverage::CoverageTracker;
use super::review_scope::ChangedLines;
use super::tools::{
    MAX_AST_QUERY_BYTES, MAX_CONTEXT_LINES, MAX_DISCOVERY_DEPTH, MAX_EXTENSION_BYTES,
    MAX_FILE_PATTERN_BYTES, MAX_FILTERS, MAX_FINDING_DESCRIPTION_BYTES, MAX_FINDING_RULE_BYTES,
    MAX_FINDING_SNIPPET_BYTES, MAX_FINDING_SUGGESTION_BYTES, MAX_FINDING_TITLE_BYTES,
    MAX_FINDINGS_PER_SUBMISSION, MAX_LANGUAGE_BYTES, MAX_PATH_BYTES, MAX_SEARCH_PATTERN_BYTES,
    MAX_TOOL_RESULTS, ToolName,
};

const DEFAULT_SEARCH_CONTEXT_LINES: u32 = 3;
const MAX_TOOL_OUTPUT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyArgs {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiscoverArgs {
    extensions: Option<Vec<String>>,
    pattern: Option<String>,
    max_depth: Option<u32>,
    max_results: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchArgs {
    pattern: String,
    #[serde(default)]
    case_sensitive: bool,
    file_extensions: Option<Vec<String>>,
    max_results: Option<u32>,
    context_lines: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadArgs {
    path: String,
    start_line: Option<u32>,
    end_line: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AstArgs {
    path: String,
    query: String,
    language: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitArgs {
    findings: Vec<serde::de::IgnoredAny>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AiFindingInput {
    category: String,
    severity: String,
    title: String,
    description: String,
    file: String,
    confidence: Option<String>,
    line_start: Option<u32>,
    line_end: Option<u32>,
    code_snippet: Option<String>,
    suggestion: Option<String>,
    rule: Option<String>,
}

pub struct ToolOutcome {
    pub text: String,
    pub findings: Vec<Finding>,
    pub inspected_path: Option<String>,
}

impl ToolOutcome {
    fn text(text: String) -> Self {
        Self {
            text,
            findings: Vec::new(),
            inspected_path: None,
        }
    }
}

struct BoundedJsonWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let remaining = self.limit.saturating_sub(self.bytes.len());
        if buffer.len() > remaining {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("tool output exceeds {} bytes", self.limit),
            ));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn serialize_tool_output<T: Serialize>(value: &T) -> Result<String, String> {
    let mut output = BoundedJsonWriter {
        bytes: Vec::new(),
        limit: MAX_TOOL_OUTPUT_BYTES,
    };
    stringify_error(serde_json::to_writer_pretty(&mut output, value))?;
    stringify_error(String::from_utf8(output.bytes))
}

fn stringify_error<T, E: std::fmt::Display>(result: Result<T, E>) -> Result<T, String> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => Err(error.to_string()),
    }
}

fn ensure_not_cancelled(cancel: Option<&CancelToken>) -> Result<(), String> {
    if cancel.is_some_and(CancelToken::is_cancelled) {
        return Err("analysis cancelled".to_string());
    }
    Ok(())
}

fn deserialize_args<'de, T: Deserialize<'de>>(input: &'de Value) -> Result<T, String> {
    stringify_error(T::deserialize(input))
}

#[derive(Clone)]
enum ProjectAccess {
    Inventory(Arc<ProjectInventory>),
    #[cfg(test)]
    Filesystem(Arc<ProjectFilesystem>),
}

impl ProjectAccess {
    fn filesystem(&self) -> &ProjectFilesystem {
        match self {
            Self::Inventory(inventory) => inventory.filesystem(),
            #[cfg(test)]
            Self::Filesystem(filesystem) => filesystem.as_ref(),
        }
    }

    fn inventory(&self) -> Option<&ProjectInventory> {
        match self {
            Self::Inventory(inventory) => Some(inventory.as_ref()),
            #[cfg(test)]
            Self::Filesystem(_) => None,
        }
    }
}

#[derive(Clone)]
pub struct ToolExecutor {
    engine: Arc<dyn Engine>,
    access: ProjectAccess,
    counter: Arc<FindingCounter>,
    coverage: Option<Arc<CoverageTracker>>,
    allowed_files: Option<Arc<BTreeSet<String>>>,
    finding_scope: Option<ChangedLines>,
}

impl ToolExecutor {
    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn new(
        engine: Arc<dyn Engine>,
        project_root: &Path,
        counter: Arc<FindingCounter>,
    ) -> Result<Self, String> {
        let root = stringify_error(ProjectRoot::open(project_root))?;
        let filesystem = stringify_error(ProjectFilesystem::open(root))?;
        Ok(Self {
            engine,
            access: ProjectAccess::Filesystem(Arc::new(filesystem)),
            counter,
            coverage: None,
            allowed_files: None,
            finding_scope: None,
        })
    }

    pub fn from_inventory(
        engine: Arc<dyn Engine>,
        inventory: Arc<ProjectInventory>,
        counter: Arc<FindingCounter>,
    ) -> Self {
        Self {
            engine,
            access: ProjectAccess::Inventory(inventory),
            counter,
            coverage: None,
            allowed_files: None,
            finding_scope: None,
        }
    }

    fn filesystem(&self) -> &ProjectFilesystem {
        self.access.filesystem()
    }

    pub fn with_coverage(mut self, coverage: Arc<CoverageTracker>) -> Self {
        self.coverage = Some(coverage);
        self
    }

    pub fn with_allowed_files(mut self, files: BTreeSet<String>) -> Self {
        self.allowed_files = Some(Arc::new(files));
        self
    }

    pub fn with_finding_scope(mut self, changed_lines: ChangedLines) -> Self {
        self.finding_scope = Some(changed_lines);
        self
    }

    pub fn execute(&self, name: &str, input: &Value) -> Result<ToolOutcome, String> {
        self.execute_inner(name, input, None)
    }

    pub fn execute_with_cancel(
        &self,
        name: &str,
        input: &Value,
        cancel: &CancelToken,
    ) -> Result<ToolOutcome, String> {
        self.execute_inner(name, input, Some(cancel))
    }

    fn execute_inner(
        &self,
        name: &str,
        input: &Value,
        cancel: Option<&CancelToken>,
    ) -> Result<ToolOutcome, String> {
        ensure_not_cancelled(cancel)?;
        let tool = ToolName::parse(name).ok_or_else(|| format!("unknown tool: {name}"))?;
        let outcome = match tool {
            ToolName::DiscoverFiles => self.discover_files(input, cancel).map(ToolOutcome::text),
            ToolName::SearchText => self.search_text(input, cancel).map(ToolOutcome::text),
            ToolName::ReadFile => self.read_file(input),
            ToolName::ProjectStats => self.project_stats(input, cancel).map(ToolOutcome::text),
            ToolName::SearchAst => self.search_ast(input, cancel).map(ToolOutcome::text),
            ToolName::SubmitFindings => self.submit_findings(input, cancel),
        }?;
        ensure_not_cancelled(cancel)?;
        Ok(outcome)
    }

    fn discover_files(
        &self,
        input: &Value,
        cancel: Option<&CancelToken>,
    ) -> Result<String, String> {
        let args: DiscoverArgs = deserialize_args(input)?;
        validate_filters("extensions", args.extensions.as_deref())?;
        validate_optional_text("pattern", args.pattern.as_deref(), MAX_FILE_PATTERN_BYTES)?;
        validate_optional_integer("max_depth", args.max_depth, 1, MAX_DISCOVERY_DEPTH)?;
        validate_optional_integer("max_results", args.max_results, 1, MAX_TOOL_RESULTS)?;

        let result_limit = args.max_results.unwrap_or(MAX_TOOL_RESULTS);
        let opts = DiscoverOpts {
            extensions: args.extensions,
            pattern: args.pattern,
            max_depth: args.max_depth,
            max_results: self.allowed_files.is_none().then_some(result_limit),
        };

        let files = match self.access.inventory() {
            Some(inventory) => {
                let selected = match cancel {
                    Some(cancel) => stringify_error(
                        inventory.select_files_cancellable(self.allowed_files.as_deref(), cancel),
                    )?,
                    None => inventory.select_files(self.allowed_files.as_deref()),
                };
                selected
                    .iter()
                    .filter(|entry| matches_discovery_options(entry, &opts))
                    .take(result_limit as usize)
                    .cloned()
                    .collect()
            }
            None => {
                let discovered = match cancel {
                    Some(cancel) => self.engine.discover_files_cancellable(
                        self.filesystem().root().as_path(),
                        &opts,
                        cancel,
                    ),
                    None => self
                        .engine
                        .discover_files(self.filesystem().root().as_path(), &opts),
                };
                let mut files = stringify_error(discovered)?;
                self.retain_allowed_files(&mut files);
                files.truncate(result_limit as usize);
                files
            }
        };

        serialize_tool_output(&files)
    }

    fn search_text(&self, input: &Value, cancel: Option<&CancelToken>) -> Result<String, String> {
        let args: SearchArgs = deserialize_args(input)?;
        validate_required_text("pattern", &args.pattern, MAX_SEARCH_PATTERN_BYTES)?;
        validate_filters("file_extensions", args.file_extensions.as_deref())?;
        validate_optional_integer("context_lines", args.context_lines, 0, MAX_CONTEXT_LINES)?;
        validate_optional_integer("max_results", args.max_results, 1, MAX_TOOL_RESULTS)?;
        let result_limit = args.max_results.unwrap_or(MAX_TOOL_RESULTS);
        let opts = SearchOpts {
            case_sensitive: args.case_sensitive,
            file_extensions: args.file_extensions,
            max_results: self.allowed_files.is_none().then_some(result_limit),
            context_lines: args.context_lines.unwrap_or(DEFAULT_SEARCH_CONTEXT_LINES),
        };

        let search_result = match self.access.inventory() {
            Some(inventory) => {
                let entries = match cancel {
                    Some(cancel) => stringify_error(
                        inventory.select_files_cancellable(self.allowed_files.as_deref(), cancel),
                    )?,
                    None => inventory.select_files(self.allowed_files.as_deref()),
                };
                match cancel {
                    Some(cancel) => self.engine.search_inventory_entries_cancellable(
                        inventory,
                        &entries,
                        &args.pattern,
                        &opts,
                        cancel,
                    ),
                    None => self.engine.search_inventory_entries(
                        inventory,
                        &entries,
                        &args.pattern,
                        &opts,
                    ),
                }
            }
            None => match cancel {
                Some(cancel) => self.engine.search_project_text_cancellable(
                    self.filesystem(),
                    &args.pattern,
                    &opts,
                    cancel,
                ),
                None => self
                    .engine
                    .search_project_text(self.filesystem(), &args.pattern, &opts),
            },
        };
        let mut matches = stringify_error(search_result)?;
        self.retain_allowed_matches(&mut matches);
        matches.truncate(result_limit as usize);

        serialize_tool_output(&matches)
    }

    fn read_file(&self, input: &Value) -> Result<ToolOutcome, String> {
        let args: ReadArgs = deserialize_args(input)?;
        validate_required_text("path", &args.path, MAX_PATH_BYTES)?;
        let resolved = self.resolve_readable_path(&args.path)?;

        let range = parse_line_range(args.start_line, args.end_line)?;

        let content = stringify_error(self.engine.read_project_file(
            self.filesystem(),
            &resolved.project_path,
            range,
        ))?;

        let text = serialize_tool_output(&content)?;
        self.record_coverage(&resolved.relative_key);

        Ok(ToolOutcome {
            text,
            findings: Vec::new(),
            inspected_path: Some(resolved.relative_key),
        })
    }

    fn resolve_readable_path(&self, relative_path: &str) -> Result<ResolvedPath, String> {
        let project_path = parse_project_path(relative_path)?;
        let relative_key = project_path.key();
        self.ensure_allowed_file(&relative_key)?;
        self.resolve_project_path(relative_path, project_path)
    }

    fn resolve_project_path(
        &self,
        relative_path: &str,
        project_path: ProjectPath,
    ) -> Result<ResolvedPath, String> {
        let requested_path = self.filesystem().absolute_path(&project_path);
        self.ensure_policy_allows(relative_path, &requested_path)?;

        let project_path = stringify_error(self.filesystem().project_path(&requested_path))?;
        let relative_key = project_path.key();
        self.ensure_allowed_file(&relative_key)?;
        let absolute_path = self.filesystem().absolute_path(&project_path);
        self.ensure_policy_allows(relative_path, &absolute_path)?;

        Ok(ResolvedPath {
            relative_key,
            project_path,
            absolute_path,
        })
    }

    fn ensure_policy_allows(
        &self,
        relative_path: &str,
        absolute_path: &Path,
    ) -> Result<(), String> {
        let excluded = self.engine.is_path_excluded(absolute_path)
            || self
                .engine
                .is_path_ignored_by_repository(self.filesystem().root().as_path(), absolute_path);
        if excluded {
            return Err(format!(
                "path ignored by repository policy: '{relative_path}'"
            ));
        }
        Ok(())
    }

    fn ensure_allowed_file(&self, relative_key: &str) -> Result<(), String> {
        if self
            .allowed_files
            .as_ref()
            .is_none_or(|allowed| allowed.contains(relative_key))
        {
            return Ok(());
        }
        Err(format!("'{relative_key}' is outside the PR review scope"))
    }

    fn retain_allowed_files(&self, files: &mut Vec<FileEntry>) {
        if let Some(allowed) = &self.allowed_files {
            files.retain(|entry| allowed.contains(&entry.relative_path));
        }
    }

    fn retain_allowed_matches(&self, matches: &mut Vec<crate::engine::TextMatch>) {
        let Some(allowed) = &self.allowed_files else {
            return;
        };
        matches.retain(|found| {
            self.filesystem()
                .project_path(&found.path)
                .is_ok_and(|path| allowed.contains(&path.key()))
        });
    }

    fn record_coverage(&self, relative_path: &str) {
        if let Some(tracker) = &self.coverage {
            tracker.record(relative_path.to_string());
        }
    }

    fn project_stats(&self, input: &Value, cancel: Option<&CancelToken>) -> Result<String, String> {
        let _: EmptyArgs = deserialize_args(input)?;
        if let Some(inventory) = self.access.inventory() {
            return serialize_tool_output(inventory.stats());
        }
        let stats = stringify_error(match cancel {
            Some(cancel) => self
                .engine
                .project_stats_with_capability_cancellable(self.filesystem(), cancel),
            None => self.engine.project_stats_with_capability(self.filesystem()),
        })?;
        serialize_tool_output(&stats)
    }

    fn search_ast(&self, input: &Value, cancel: Option<&CancelToken>) -> Result<String, String> {
        let args: AstArgs = deserialize_args(input)?;
        validate_required_text("path", &args.path, MAX_PATH_BYTES)?;
        validate_required_text("query", &args.query, MAX_AST_QUERY_BYTES)?;
        validate_required_text("language", &args.language, MAX_LANGUAGE_BYTES)?;

        let resolved = self.resolve_readable_path(&args.path)?;
        let file_content = stringify_error(self.engine.read_project_file(
            self.filesystem(),
            &resolved.project_path,
            None,
        ))?;

        let search_result = match cancel {
            Some(cancel) => crate::engine::ast::search_ast_cancellable(
                &resolved.absolute_path,
                &file_content.content,
                &args.language,
                &args.query,
                MAX_TOOL_RESULTS as usize,
                cancel,
            ),
            None => crate::engine::ast::search_ast(
                &resolved.absolute_path,
                &file_content.content,
                &args.language,
                &args.query,
                MAX_TOOL_RESULTS as usize,
            ),
        };
        let matches = stringify_error(search_result)?;

        serialize_tool_output(&matches)
    }

    fn submit_findings(
        &self,
        input: &Value,
        cancel: Option<&CancelToken>,
    ) -> Result<ToolOutcome, String> {
        let submitted = submitted_findings(input)?;
        let findings: Vec<Finding> = submitted
            .iter()
            .enumerate()
            .map(|(index, value)| {
                ensure_not_cancelled(cancel)?;
                parse_ai_finding(&self.counter, value)
                    .and_then(|finding| self.prepare_finding(finding))
                    .map_err(|error| format!("finding {}: {error}", index + 1))
            })
            .collect::<Result<_, _>>()?;

        let text = format!("Accepted {} findings.", findings.len());
        Ok(ToolOutcome {
            text,
            findings,
            inspected_path: None,
        })
    }

    fn prepare_finding(&self, mut finding: Finding) -> Result<Finding, String> {
        let submitted_path = finding.file.to_string_lossy();
        let project_path = parse_project_path(&submitted_path)?;
        let relative_key = project_path.key();
        if let Some(changed_lines) = &self.finding_scope {
            ensure_finding_file_is_changed(&relative_key, changed_lines)?;
        }
        self.ensure_allowed_file(&relative_key)?;
        let resolved = self.resolve_project_path(&submitted_path, project_path)?;
        if !stringify_error(self.filesystem().metadata(&resolved.project_path))?.is_file() {
            return Err(format!(
                "finding path is not a file: '{}'",
                finding.file.display()
            ));
        }
        finding.file = PathBuf::from(&resolved.relative_key);
        let Some(source) = self.verification_source(&finding, &resolved)? else {
            return Ok(finding);
        };
        let snippet = SnippetLocation::locate(&source.content, finding.code_snippet.as_deref());
        verify_finding_evidence(
            &mut finding,
            &resolved.relative_key,
            &snippet,
            source.total_lines,
        )?;
        if let Some(changed_lines) = &self.finding_scope {
            ensure_finding_reviews_changed_lines(&finding, &resolved.relative_key, changed_lines)?;
        }
        Ok(finding)
    }

    fn verification_source(
        &self,
        finding: &Finding,
        resolved: &ResolvedPath,
    ) -> Result<Option<FileContent>, String> {
        if finding.code_snippet.is_none()
            && self.finding_scope.is_none()
            && finding.line_start.is_none()
            && finding.line_end.is_none()
        {
            return Ok(None);
        }
        stringify_error(self.engine.read_project_file(
            self.filesystem(),
            &resolved.project_path,
            None,
        ))
        .map(Some)
    }
}

enum SnippetLocation {
    Absent,
    Located(LineRange),
    Unresolved,
}

impl SnippetLocation {
    fn locate(content: &str, snippet: Option<&str>) -> Self {
        let Some(snippet) = snippet else {
            return Self::Absent;
        };
        match exact_snippet_line_range(content, snippet) {
            Some(range) => Self::Located(range),
            None => Self::Unresolved,
        }
    }

    fn apply(&self, finding: &mut Finding) {
        if let Self::Located(range) = self {
            finding.line_start = Some(range.start());
            finding.line_end = Some(range.end());
        }
    }
}

fn verify_finding_evidence(
    finding: &mut Finding,
    path: &str,
    snippet: &SnippetLocation,
    total_lines: u32,
) -> Result<(), String> {
    if matches!(snippet, SnippetLocation::Unresolved) {
        return Err(format!(
            "'{path}' code_snippet does not appear exactly once in the file, so the reported \
             lines cannot be verified"
        ));
    }
    snippet.apply(finding);
    if let Some(range) = reviewed_range(finding)
        && range.end() > total_lines
    {
        return Err(format!(
            "'{path}' finding at lines {}-{} runs past the end of the file ({total_lines} lines)",
            range.start(),
            range.end()
        ));
    }
    Ok(())
}

fn ensure_finding_file_is_changed(path: &str, changed_lines: &ChangedLines) -> Result<(), String> {
    if changed_lines.covers(path) {
        return Ok(());
    }
    Err(format!(
        "'{path}' is not a file this pull request changed; review only changed files"
    ))
}

fn ensure_finding_reviews_changed_lines(
    finding: &Finding,
    path: &str,
    changed_lines: &ChangedLines,
) -> Result<(), String> {
    ensure_finding_file_is_changed(path, changed_lines)?;
    let Some(range) = reviewed_range(finding) else {
        return Err(format!(
            "'{path}' finding must state the changed lines it reports: set line_start and \
             line_end, or quote an exact code_snippet"
        ));
    };
    if !changed_lines.overlaps(path, range) {
        return Err(format!(
            "'{path}' finding at lines {}-{} touches no line this pull request changed",
            range.start(),
            range.end()
        ));
    }
    Ok(())
}

fn reviewed_range(finding: &Finding) -> Option<LineRange> {
    LineRange::new(finding.line_start?, finding.line_end?).ok()
}

fn matches_discovery_options(entry: &FileEntry, options: &DiscoverOpts) -> bool {
    let matches_extension = options.extensions.as_ref().is_none_or(|extensions| {
        entry
            .path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extensions.iter().any(|item| item == extension))
    });
    let matches_pattern = options.pattern.as_ref().is_none_or(|pattern| {
        entry
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.contains(pattern))
    });
    let matches_depth = options.max_depth.is_none_or(|max_depth| {
        Path::new(&entry.relative_path).components().count() <= max_depth as usize
    });
    matches_extension && matches_pattern && matches_depth
}

fn exact_snippet_line_range(content: &str, snippet: &str) -> Option<LineRange> {
    if snippet.is_empty() {
        return None;
    }
    let mut matches = content.match_indices(snippet).map(|(offset, _)| offset);
    let offset = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    let start = content[..offset]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count() as u32
        + 1;
    let occupied = snippet.strip_suffix('\n').unwrap_or(snippet);
    let end = start + occupied.bytes().filter(|byte| *byte == b'\n').count() as u32;
    LineRange::new(start, end).ok()
}

struct ResolvedPath {
    project_path: ProjectPath,
    absolute_path: PathBuf,
    relative_key: String,
}

fn parse_project_path(relative_path: &str) -> Result<ProjectPath, String> {
    ProjectPath::parse(Path::new(relative_path))
        .map_err(|error| format!("path traversal blocked: '{relative_path}': {error}"))
}

fn submitted_findings(input: &Value) -> Result<&[Value], String> {
    let shape: SubmitArgs = deserialize_args(input)?;
    if shape.findings.len() > MAX_FINDINGS_PER_SUBMISSION {
        return Err(format!(
            "submit_findings accepts at most {MAX_FINDINGS_PER_SUBMISSION} findings"
        ));
    }
    Ok(input
        .get("findings")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice))
}

fn parse_ai_finding(counter: &FindingCounter, value: &Value) -> Result<Finding, String> {
    let input: AiFindingInput = deserialize_args(value)?;
    let category = match parse_category(&input.category) {
        Some(category) => category,
        None => return Err(format!("invalid category '{}'", input.category)),
    };
    let severity = match parse_severity(&input.severity) {
        Some(severity) => severity,
        None => return Err(format!("invalid severity '{}'", input.severity)),
    };
    let confidence = match &input.confidence {
        Some(raw) => match parse_confidence(raw) {
            Some(confidence) => confidence,
            None => return Err(format!("invalid confidence '{raw}'")),
        },
        None => Confidence::Medium,
    };
    validate_required_text("title", &input.title, MAX_FINDING_TITLE_BYTES)?;
    validate_required_text(
        "description",
        &input.description,
        MAX_FINDING_DESCRIPTION_BYTES,
    )?;
    validate_required_text("file", &input.file, MAX_PATH_BYTES)?;
    validate_optional_max(
        "code_snippet",
        input.code_snippet.as_deref(),
        MAX_FINDING_SNIPPET_BYTES,
    )?;
    validate_optional_max(
        "suggestion",
        input.suggestion.as_deref(),
        MAX_FINDING_SUGGESTION_BYTES,
    )?;
    validate_optional_max("rule", input.rule.as_deref(), MAX_FINDING_RULE_BYTES)?;
    let range = parse_line_range(input.line_start, input.line_end)?;

    let mut finding = Finding::new_static(
        counter,
        category,
        severity,
        input.title,
        input.description,
        input.file.into(),
    );
    finding.source = FindingSource::Ai;
    finding.confidence = confidence;
    if let Some(range) = range {
        finding = finding.with_lines(range.start(), range.end());
    }
    if let Some(snippet) = input.code_snippet {
        finding = finding.with_snippet(snippet);
    }
    if let Some(suggestion) = input.suggestion {
        finding = finding.with_suggestion(suggestion);
    }
    if let Some(rule) = input.rule {
        finding = finding.with_rule(rule);
    }
    Ok(finding)
}

fn validate_filters(field: &str, filters: Option<&[String]>) -> Result<(), String> {
    let Some(filters) = filters else {
        return Ok(());
    };
    if filters.len() > MAX_FILTERS {
        return Err(format!("{field} accepts at most {MAX_FILTERS} values"));
    }
    for filter in filters {
        validate_required_text(field, filter, MAX_EXTENSION_BYTES)?;
    }
    Ok(())
}

fn validate_required_text(field: &str, value: &str, max_bytes: usize) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("field '{field}' must not be empty"));
    }
    validate_text_limit(field, value, max_bytes)
}

fn validate_optional_text(
    field: &str,
    value: Option<&str>,
    max_bytes: usize,
) -> Result<(), String> {
    match value {
        Some(value) => validate_required_text(field, value, max_bytes),
        None => Ok(()),
    }
}

fn validate_optional_max(field: &str, value: Option<&str>, max_bytes: usize) -> Result<(), String> {
    match value {
        Some(value) => validate_text_limit(field, value, max_bytes),
        None => Ok(()),
    }
}

fn validate_text_limit(field: &str, value: &str, max_bytes: usize) -> Result<(), String> {
    if value.len() > max_bytes {
        return Err(format!("field '{field}' exceeds {max_bytes} bytes"));
    }
    Ok(())
}

fn validate_optional_integer(
    field: &str,
    value: Option<u32>,
    minimum: u32,
    maximum: u32,
) -> Result<(), String> {
    if value.is_some_and(|value| !(minimum..=maximum).contains(&value)) {
        return Err(format!(
            "field '{field}' must be between {minimum} and {maximum}"
        ));
    }
    Ok(())
}

fn parse_category(raw: &str) -> Option<AnalysisCategory> {
    match raw {
        "bug" => Some(AnalysisCategory::Bug),
        "quality" => Some(AnalysisCategory::Quality),
        "solid" => Some(AnalysisCategory::Solid),
        "vulnerability" => Some(AnalysisCategory::Vulnerability),
        _ => None,
    }
}

fn parse_line_range(
    start_line: Option<u32>,
    end_line: Option<u32>,
) -> Result<Option<LineRange>, String> {
    match (start_line, end_line) {
        (None, None) => Ok(None),
        (Some(start), Some(end)) => stringify_error(LineRange::new(start, end)).map(Some),
        _ => Err("start_line and end_line must be provided together".into()),
    }
}

fn parse_severity(raw: &str) -> Option<Severity> {
    match raw {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        "info" => Some(Severity::Info),
        _ => None,
    }
}

fn parse_confidence(raw: &str) -> Option<Confidence> {
    match raw {
        "high" => Some(Confidence::High),
        "medium" => Some(Confidence::Medium),
        "low" => Some(Confidence::Low),
        _ => None,
    }
}

#[cfg(test)]
#[path = "tool_exec_tests.rs"]
mod tests;
