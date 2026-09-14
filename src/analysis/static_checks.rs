use std::path::Path;

use regex::{Captures, Regex};
use tracing::warn;

use crate::cancel::CancelToken;
use crate::config::schema::{AnalysisCategory, AnalysisConfig, Severity};
#[cfg(test)]
use crate::domain::ProjectRoot;
use crate::engine::ast;
use crate::engine::walker::UnreadableFile;
use crate::engine::{Engine, FileEntry, ProjectFilesystem, ProjectInventory};
use crate::errors::EngineError;
use crate::report::limits::{
    BoundedDiagnostics, MAX_DIAGNOSTIC_BYTES, MAX_DIAGNOSTIC_ENTRIES, path_diagnostic,
    truncate_with_marker,
};
use crate::report::{Confidence, Finding, FindingCounter};
use crate::shared::root_cause_message;

const FUNCTION_LENGTH_RULE: &str = "quality.function-length";
const FILE_LENGTH_RULE: &str = "quality.file-length";
const HARDCODED_SECRET_RULE: &str = "vulnerability.hardcoded-secret";
const TODO_COMMENT_RULE: &str = "quality.todo-comment";
const MAX_STATIC_FINDINGS: usize = 10_000;
const MAX_STATIC_FINDING_BYTES: usize = 8 * 1024 * 1024;
const MAX_TODO_SNIPPET_BYTES: usize = 16 * 1024;
const MIN_DISTINCT_SECRET_CHARACTERS: usize = 4;
const PLACEHOLDER_VALUES: [&str; 4] = ["password", "password123", "secret", "secret123"];
const PLACEHOLDER_MARKERS: [&str; 14] = [
    "example",
    "sample",
    "placeholder",
    "changeme",
    "change_me",
    "change-me",
    "replace",
    "dummy",
    "redacted",
    "notasecret",
    "not_a_secret",
    "not-a-secret",
    "your_",
    "your-",
];
const SECRET_PATTERN_SOURCES: [(&str, &str); 5] = [
    (
        r#"(?i)\b(?:api[_-]?key|apikey)\b\s*[:=]\s*["'](?P<value>[a-z0-9_-]{16,})["']"#,
        "API key",
    ),
    (
        r#"(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*["'](?P<value>[^\s"']{8,})["']"#,
        "password",
    ),
    (
        r#"(?i)\b(?:secret|token)\b\s*[:=]\s*["'](?P<value>[a-z0-9_-]{16,})["']"#,
        "secret/token",
    ),
    (
        r#"(?i:\baws_access_key_id\b)\s*[:=]\s*["'](?P<value>AKIA[A-Z0-9]{16})["']"#,
        "AWS access key",
    ),
    (
        r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        "private key",
    ),
];

struct SecretPattern {
    regex: Regex,
    secret_type: &'static str,
}

#[derive(Debug)]
pub struct StaticAnalysis {
    pub findings: Vec<Finding>,
    pub files_scanned: u32,
    pub skipped_files: Vec<String>,
    pub omitted_skipped_files: u32,
}

enum SignatureScan {
    Parsed(Vec<ast::Signature>),
    Unsupported,
    Failed(EngineError),
}

struct BoundedFindings {
    values: Vec<Finding>,
    retained_bytes: usize,
    max_findings: usize,
    max_bytes: usize,
}

impl BoundedFindings {
    fn new(max_findings: usize, max_bytes: usize) -> Self {
        Self {
            values: Vec::new(),
            retained_bytes: 0,
            max_findings,
            max_bytes,
        }
    }

    fn push(&mut self, finding: Finding) -> Result<(), EngineError> {
        if self.values.len() >= self.max_findings {
            return Err(EngineError::FindingLimitExceeded {
                max_findings: self.max_findings,
            });
        }
        let bytes = finding.retained_bytes();
        if self.retained_bytes + bytes > self.max_bytes {
            return Err(EngineError::FindingBytesExceeded {
                max_bytes: self.max_bytes,
            });
        }
        self.retained_bytes += bytes;
        self.values.push(finding);
        Ok(())
    }

    fn into_vec(self) -> Vec<Finding> {
        self.values
    }
}

fn record_skipped_path(skipped: &mut BoundedDiagnostics, relative_path: &str, reason: String) {
    skipped.record_with(&mut || path_diagnostic(relative_path, &reason));
}

#[cfg(test)]
pub fn run_static_checks(
    engine: &dyn Engine,
    root: &Path,
    config: &AnalysisConfig,
    counter: &FindingCounter,
) -> Result<StaticAnalysis, EngineError> {
    let project_root = ProjectRoot::open(root).map_err(|error| EngineError::Io {
        path: root.to_path_buf(),
        source: std::io::Error::other(error),
    })?;
    let filesystem = ProjectFilesystem::open(project_root)?;
    let files = engine.discover_files(root, &Default::default())?;
    scan_files(
        engine,
        DiscoveredSources {
            filesystem: &filesystem,
            files: &files,
            unreadable: &[],
        },
        config,
        counter,
    )
}

pub fn run_static_checks_with_inventory(
    engine: &dyn Engine,
    inventory: &ProjectInventory,
    config: &AnalysisConfig,
    counter: &FindingCounter,
) -> Result<StaticAnalysis, EngineError> {
    scan_files(
        engine,
        DiscoveredSources {
            filesystem: inventory.filesystem(),
            files: inventory.files(),
            unreadable: inventory.unreadable_files(),
        },
        config,
        counter,
    )
}

pub fn run_static_checks_with_inventory_cancellable(
    engine: &dyn Engine,
    inventory: &ProjectInventory,
    config: &AnalysisConfig,
    counter: &FindingCounter,
    cancel: &CancelToken,
) -> Result<StaticAnalysis, EngineError> {
    scan_files_with_cancel(
        engine,
        DiscoveredSources {
            filesystem: inventory.filesystem(),
            files: inventory.files(),
            unreadable: inventory.unreadable_files(),
        },
        config,
        counter,
        ScanLimits::default(),
        signature_scan,
        Some(cancel),
    )
}

struct DiscoveredSources<'a> {
    filesystem: &'a ProjectFilesystem,
    files: &'a [FileEntry],
    unreadable: &'a [UnreadableFile],
}

fn scan_files(
    engine: &dyn Engine,
    sources: DiscoveredSources<'_>,
    config: &AnalysisConfig,
    counter: &FindingCounter,
) -> Result<StaticAnalysis, EngineError> {
    scan_files_with(
        engine,
        sources,
        config,
        counter,
        ScanLimits::default(),
        signature_scan,
    )
}

struct ScanLimits {
    max_findings: usize,
    max_finding_bytes: usize,
    max_diagnostics: usize,
    max_diagnostic_bytes: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_findings: MAX_STATIC_FINDINGS,
            max_finding_bytes: MAX_STATIC_FINDING_BYTES,
            max_diagnostics: MAX_DIAGNOSTIC_ENTRIES,
            max_diagnostic_bytes: MAX_DIAGNOSTIC_BYTES,
        }
    }
}

fn scan_files_with(
    engine: &dyn Engine,
    sources: DiscoveredSources<'_>,
    config: &AnalysisConfig,
    counter: &FindingCounter,
    limits: ScanLimits,
    scan_signatures: fn(&Path, &str, Option<&str>) -> SignatureScan,
) -> Result<StaticAnalysis, EngineError> {
    scan_files_with_cancel(
        engine,
        sources,
        config,
        counter,
        limits,
        scan_signatures,
        None,
    )
}

fn scan_files_with_cancel(
    engine: &dyn Engine,
    sources: DiscoveredSources<'_>,
    config: &AnalysisConfig,
    counter: &FindingCounter,
    limits: ScanLimits,
    scan_signatures: fn(&Path, &str, Option<&str>) -> SignatureScan,
    cancel: Option<&CancelToken>,
) -> Result<StaticAnalysis, EngineError> {
    ensure_not_cancelled(cancel)?;
    let quality_enabled = config.categories.contains(&AnalysisCategory::Quality);
    let vulnerability_enabled = config.categories.contains(&AnalysisCategory::Vulnerability);
    if !quality_enabled && !vulnerability_enabled {
        return Ok(StaticAnalysis {
            findings: Vec::new(),
            files_scanned: 0,
            skipped_files: Vec::new(),
            omitted_skipped_files: 0,
        });
    }
    let secret_patterns = vulnerability_enabled
        .then(compile_secret_patterns)
        .transpose()?;
    let mut findings = BoundedFindings::new(limits.max_findings, limits.max_finding_bytes);
    let mut skipped =
        BoundedDiagnostics::with_limits(limits.max_diagnostics, limits.max_diagnostic_bytes);
    for file in sources.files {
        ensure_not_cancelled(cancel)?;
        let Ok(project_path) = sources.filesystem.project_path(&file.path) else {
            warn!(path = %file.path.display(), "failed to resolve a discovered file inside the project root");
            record_skipped_path(
                &mut skipped,
                &file.relative_path,
                "path is not inside the project root".to_string(),
            );
            continue;
        };
        let content = match engine.read_project_file(sources.filesystem, &project_path, None) {
            Ok(content) => content,
            Err(error) => {
                warn!(path = %file.path.display(), %error, "failed to read file for static analysis");
                record_skipped_path(
                    &mut skipped,
                    &file.relative_path,
                    root_cause_message(&error),
                );
                continue;
            }
        };
        if quality_enabled {
            check_file_length(
                &content.path,
                content.total_lines,
                config,
                counter,
                &mut findings,
            )?;
            match scan_signatures(&content.path, &content.content, file.language.as_deref()) {
                SignatureScan::Parsed(signatures) => check_function_lengths(
                    &content.path,
                    &signatures,
                    config,
                    counter,
                    &mut findings,
                )?,
                SignatureScan::Unsupported => {}
                SignatureScan::Failed(error) => record_parse_failure(&mut skipped, file, &error),
            }
            check_todo_comments(&content.path, &content.content, counter, &mut findings)?;
        }
        ensure_not_cancelled(cancel)?;
        if let Some(secret_patterns) = &secret_patterns {
            check_hardcoded_secrets(
                &content.path,
                &content.content,
                secret_patterns,
                counter,
                &mut findings,
            )?;
        }
    }
    ensure_not_cancelled(cancel)?;
    let files_scanned = sources.files.len().saturating_sub(skipped.observed()) as u32;
    for unreadable in sources.unreadable {
        skipped.record_with(&mut || unreadable.report_entry());
    }
    let (skipped_files, omitted_skipped_files) = skipped.into_sorted_entries();
    Ok(StaticAnalysis {
        findings: findings.into_vec(),
        files_scanned,
        skipped_files,
        omitted_skipped_files,
    })
}

fn ensure_not_cancelled(cancel: Option<&CancelToken>) -> Result<(), EngineError> {
    if cancel.is_some_and(CancelToken::is_cancelled) {
        return Err(EngineError::Cancelled);
    }
    Ok(())
}

fn check_file_length(
    path: &Path,
    total_lines: u32,
    config: &AnalysisConfig,
    counter: &FindingCounter,
    findings: &mut BoundedFindings,
) -> Result<(), EngineError> {
    let threshold = config.quality.max_file_lines as u32;
    if total_lines > threshold {
        findings.push(
            Finding::new_static(
                counter,
                AnalysisCategory::Quality,
                Severity::Medium,
                format!("File exceeds {threshold} lines ({total_lines} lines)"),
                "Large files are harder to navigate and maintain. Consider splitting into smaller, focused modules.".into(),
                path.to_path_buf(),
            )
            .with_rule(FILE_LENGTH_RULE.into()),
        )?;
    }
    Ok(())
}

fn record_parse_failure(skipped: &mut BoundedDiagnostics, file: &FileEntry, error: &EngineError) {
    warn!(path = %file.path.display(), %error, "failed to parse file for static analysis");
    record_skipped_path(skipped, &file.relative_path, root_cause_message(error));
}

fn signature_scan(path: &Path, content: &str, language: Option<&str>) -> SignatureScan {
    signature_scan_with(path, content, language, ast::extract_signatures)
}

fn signature_scan_with(
    path: &Path,
    content: &str,
    language: Option<&str>,
    extract: fn(&Path, &str, &str) -> Result<Vec<ast::Signature>, EngineError>,
) -> SignatureScan {
    let Some(language) = language else {
        return SignatureScan::Unsupported;
    };
    match extract(path, content, language) {
        Ok(signatures) => SignatureScan::Parsed(signatures),
        Err(EngineError::UnsupportedLanguage { .. }) => SignatureScan::Unsupported,
        Err(error) => SignatureScan::Failed(error),
    }
}

fn check_function_lengths(
    path: &Path,
    signatures: &[ast::Signature],
    config: &AnalysisConfig,
    counter: &FindingCounter,
    findings: &mut BoundedFindings,
) -> Result<(), EngineError> {
    let threshold = config.quality.max_function_lines;

    for signature in signatures {
        if signature.kind != ast::SignatureKind::Function
            && signature.kind != ast::SignatureKind::Method
        {
            continue;
        }
        let length = (signature.line_end - signature.line_start + 1) as usize;
        if length > threshold {
            let severity = if length > threshold * 2 {
                Severity::High
            } else {
                Severity::Medium
            };
            findings.push(
                Finding::new_static(
                    counter,
                    AnalysisCategory::Quality,
                    severity,
                    format!(
                        "Function '{}' is {length} lines (max: {threshold})",
                        signature.name
                    ),
                    "Long functions are hard to understand and test. Extract smaller, focused helper functions.".into(),
                    path.to_path_buf(),
                )
                .with_lines(signature.line_start, signature.line_end)
                .with_rule(FUNCTION_LENGTH_RULE.into()),
            )?;
        }
    }
    Ok(())
}

fn compile_secret_patterns() -> Result<Vec<SecretPattern>, EngineError> {
    compile_secret_patterns_from(&SECRET_PATTERN_SOURCES)
}

fn compile_secret_patterns_from(
    sources: &[(&str, &'static str)],
) -> Result<Vec<SecretPattern>, EngineError> {
    sources
        .iter()
        .map(|(pattern, secret_type)| {
            Regex::new(pattern)
                .map(|regex| SecretPattern { regex, secret_type })
                .map_err(|source| EngineError::InvalidPattern {
                    pattern: (*pattern).to_string(),
                    source,
                })
        })
        .collect()
}

fn check_hardcoded_secrets(
    path: &Path,
    content: &str,
    patterns: &[SecretPattern],
    counter: &FindingCounter,
    findings: &mut BoundedFindings,
) -> Result<(), EngineError> {
    for pattern in patterns {
        let mut lines = AscendingLines::new(content);
        for matched in pattern
            .regex
            .captures_iter(content)
            .filter(|captures| !value_group_is_a_placeholder(captures))
            .filter_map(|captures| captures.get(0))
        {
            let line_start = lines.line_at(matched.start());
            let line_end = lines.line_at(matched.end().saturating_sub(1));
            findings.push(
                Finding::new_static(
                    counter,
                    AnalysisCategory::Vulnerability,
                    Severity::Critical,
                    format!("Possible hardcoded {} detected", pattern.secret_type),
                    "Hardcoded credentials are a security risk. Use environment variables or a secrets manager.".into(),
                    path.to_path_buf(),
                )
                .with_lines(line_start, line_end)
                .with_rule(HARDCODED_SECRET_RULE.into())
                .with_confidence(Confidence::Medium),
            )?;
        }
    }
    Ok(())
}

fn value_group_is_a_placeholder(captures: &Captures<'_>) -> bool {
    captures
        .name("value")
        .is_some_and(|value| is_placeholder_secret(value.as_str()))
}

struct AscendingLines<'a> {
    content: &'a str,
    next_newline: Option<usize>,
    line: u32,
}

impl<'a> AscendingLines<'a> {
    fn new(content: &'a str) -> Self {
        Self {
            content,
            next_newline: content.find('\n'),
            line: 1,
        }
    }

    fn line_at(&mut self, byte_offset: usize) -> u32 {
        while let Some(newline) = self.next_newline {
            if newline >= byte_offset {
                break;
            }
            self.line = self.line.saturating_add(1);
            self.next_newline = self.content[newline + 1..]
                .find('\n')
                .map(|index| newline + 1 + index);
        }
        self.line
    }
}

fn is_placeholder_secret(value: &str) -> bool {
    if value.starts_with("${") || value.starts_with("{{") || value.starts_with('<') {
        return true;
    }
    if PLACEHOLDER_VALUES
        .iter()
        .any(|placeholder| value.eq_ignore_ascii_case(placeholder))
    {
        return true;
    }
    if PLACEHOLDER_MARKERS
        .iter()
        .any(|marker| contains_ignoring_ascii_case(value, marker))
    {
        return true;
    }
    has_too_few_distinct_characters(value)
}

fn contains_ignoring_ascii_case(haystack: &str, needle: &str) -> bool {
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn has_too_few_distinct_characters(value: &str) -> bool {
    let mut observed_bytes = [false; 256];
    let mut distinct_characters = 0;
    for byte in value.bytes() {
        let index = usize::from(byte.to_ascii_lowercase());
        if observed_bytes[index] {
            continue;
        }
        observed_bytes[index] = true;
        distinct_characters += 1;
        if distinct_characters >= MIN_DISTINCT_SECRET_CHARACTERS {
            return false;
        }
    }
    true
}

fn check_todo_comments(
    path: &Path,
    content: &str,
    counter: &FindingCounter,
    findings: &mut BoundedFindings,
) -> Result<(), EngineError> {
    let markers = ["TODO", "FIXME", "HACK", "XXX"];
    let mut inside_block_comment = false;

    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        let starts_block_comment = trimmed.starts_with("/*");
        let is_comment = inside_block_comment
            || starts_block_comment
            || trimmed.starts_with("//")
            || trimmed.starts_with('#');

        if is_comment {
            for marker in markers {
                if line.contains(marker) {
                    let line_number = (index + 1) as u32;
                    findings.push(
                        Finding::new_static(
                            counter,
                            AnalysisCategory::Quality,
                            Severity::Low,
                            format!("{marker} comment found"),
                            format!("{marker} comments indicate unfinished work. Resolve or track in an issue tracker."),
                            path.to_path_buf(),
                        )
                        .with_lines(line_number, line_number)
                        .with_snippet(
                            truncate_with_marker(trimmed, MAX_TODO_SNIPPET_BYTES).into_owned(),
                        )
                        .with_rule(TODO_COMMENT_RULE.into()),
                    )?;
                    break;
                }
            }
        }

        if inside_block_comment {
            inside_block_comment = !trimmed.contains("*/");
        } else if starts_block_comment {
            inside_block_comment = !trimmed[2..].contains("*/");
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "static_checks_tests.rs"]
mod tests;
