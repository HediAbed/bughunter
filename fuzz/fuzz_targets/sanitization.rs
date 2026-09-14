#![no_main]

use std::borrow::Cow;
use std::path::{Path, PathBuf};

use bughunter::fuzzing::{
    FindingCounter, render_json_report, render_markdown_report, sanitize_markdown_block,
    sanitize_markdown_inline, sanitize_terminal_text,
};
use bughunter::{
    AnalysisCategory, Confidence, FailedShard, Finding, FindingSource, ScanCompleteness,
    ScanStatus, Severity,
};
use libfuzzer_sys::fuzz_target;

const FIELD_SEPARATOR: u8 = 0x1f;
const MAX_FIELDS: usize = 64;
const MAX_CHUNK_SPLITS: usize = 16;
const FIELDS_PER_FINDING: usize = 6;
const MAX_FINDINGS: usize = 8;
const FIRST_FINDING_ID: u32 = 1;
const SCAN_FIELD_STRIDE: usize = 7;
const FUZZ_VERSION: &str = "0.0.0-fuzz";
const MARKDOWN_REPORT_HEADER: &str = "# BugHunter Analysis Report\n";
const EMPTY_REPORT_SENTINEL: &str = "No issues found.";
const FINDING_SECTION_MARKER: &str = "\n## [";
const MARKDOWN_INJECTION_PRIMITIVES: [&str; 5] = ["<", ">", "](", "![", "```"];
const MARKDOWN_CODE_MARKER: &str = "**Code:**\n\n";

fuzz_target!(|data: &[u8]| {
    let fields = decode_fields(data);

    for field in &fields {
        assert_terminal_sanitization_invariants(field);
        assert_terminal_sanitization_is_chunk_independent(field);
        assert_markdown_inline_invariants(field);
        assert_markdown_block_invariants(field);
    }

    let mode = fields[0].as_str();
    let project_root = PathBuf::from(fields.get(1).cloned().unwrap_or_default());
    let finding_fields = fields.get(2..).unwrap_or_default();
    let findings = build_findings(finding_fields);
    let scan = build_scan_status(finding_fields);

    assert_finding_ids_are_unique(&findings);
    assert_markdown_report_invariants(&findings, &scan);
    assert_json_report_invariants(&findings, &scan, &project_root, mode);
});

fn decode_fields(data: &[u8]) -> Vec<String> {
    data.split(|byte| *byte == FIELD_SEPARATOR)
        .take(MAX_FIELDS)
        .map(|field| String::from_utf8_lossy(field).into_owned())
        .collect()
}

fn assert_terminal_sanitization_invariants(input: &str) {
    let sanitized = sanitize_terminal_text(input);
    assert_single_line_display_safe(sanitized.as_ref(), "terminal text");

    let repeated = sanitize_terminal_text(input);
    assert_eq!(
        repeated.as_ref(),
        sanitized.as_ref(),
        "terminal sanitization is not deterministic"
    );

    let twice = sanitize_terminal_text(sanitized.as_ref());
    assert_eq!(
        twice.as_ref(),
        sanitized.as_ref(),
        "terminal sanitization is not idempotent"
    );
    assert!(
        matches!(twice, Cow::Borrowed(_)),
        "already safe terminal text was reallocated"
    );

    assert!(
        sanitized.len() >= input.len(),
        "terminal sanitization dropped bytes"
    );
    assert_eq!(
        matches!(sanitized, Cow::Borrowed(_)),
        sanitized.len() == input.len(),
        "terminal sanitization borrowed a rewritten string"
    );
}

fn assert_terminal_sanitization_is_chunk_independent(input: &str) {
    let characters = input.chars().count();
    if characters == 0 {
        return;
    }

    let whole = sanitize_terminal_text(input);
    let stride = characters.div_ceil(MAX_CHUNK_SPLITS);
    for (split, _) in input.char_indices().step_by(stride) {
        let (head, tail) = input.split_at(split);
        let mut streamed = sanitize_terminal_text(head).into_owned();
        streamed.push_str(sanitize_terminal_text(tail).as_ref());
        assert_eq!(
            streamed,
            whole.as_ref(),
            "terminal sanitization is not chunk independent at byte {split}"
        );
    }
}

fn assert_markdown_inline_invariants(input: &str) {
    let sanitized = sanitize_markdown_inline(input);
    assert_single_line_display_safe(&sanitized, "markdown inline");
    assert_markdown_injection_free(&sanitized, "markdown inline");
    assert_eq!(
        sanitize_markdown_inline(input),
        sanitized,
        "inline markdown sanitization is not deterministic"
    );

    let resanitized = sanitize_markdown_inline(&sanitized);
    assert_single_line_display_safe(&resanitized, "re-sanitized markdown inline");
    assert_markdown_injection_free(&resanitized, "re-sanitized markdown inline");
}

fn assert_markdown_block_invariants(input: &str) {
    let sanitized = sanitize_markdown_block(input);
    assert_multi_line_display_safe(&sanitized, "markdown block");
    assert_markdown_injection_free(&sanitized, "markdown block");
    assert_eq!(
        sanitized.matches('\n').count(),
        input.matches('\n').count(),
        "block markdown sanitization changed the line count"
    );
    assert_eq!(
        sanitize_markdown_block(input),
        sanitized,
        "block markdown sanitization is not deterministic"
    );

    let resanitized = sanitize_markdown_block(&sanitized);
    assert_multi_line_display_safe(&resanitized, "re-sanitized markdown block");
    assert_markdown_injection_free(&resanitized, "re-sanitized markdown block");

    if !input.contains('\n') {
        assert_eq!(
            sanitize_markdown_inline(input),
            sanitized,
            "inline and block markdown disagree on single-line input"
        );
    }
}

fn assert_single_line_display_safe(text: &str, context: &str) {
    for character in text.chars() {
        assert!(
            !character.is_control(),
            "{context} leaked control character {character:?}"
        );
        assert!(
            !is_hostile_format_character(character),
            "{context} leaked format character {character:?}"
        );
    }
}

fn assert_multi_line_display_safe(text: &str, context: &str) {
    for character in text.chars() {
        assert!(
            !character.is_control() || character == '\n',
            "{context} leaked control character {character:?}"
        );
        assert!(
            !is_hostile_format_character(character),
            "{context} leaked format character {character:?}"
        );
    }
}

fn assert_markdown_injection_free(text: &str, context: &str) {
    for primitive in MARKDOWN_INJECTION_PRIMITIVES {
        assert!(
            !text.contains(primitive),
            "{context} leaked markdown primitive {primitive:?}"
        );
    }
}

fn is_hostile_format_character(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{feff}'
    )
}

fn build_findings(fields: &[String]) -> Vec<Finding> {
    let counter = FindingCounter::with_start(FIRST_FINDING_ID);
    let findings: Vec<Finding> = fields
        .chunks(FIELDS_PER_FINDING)
        .take(MAX_FINDINGS)
        .enumerate()
        .map(|(index, chunk)| build_finding(&counter, index, chunk))
        .collect();

    assert_eq!(
        counter.peek(),
        FIRST_FINDING_ID + findings.len() as u32,
        "finding counter did not advance once per finding"
    );
    findings
}

fn build_finding(counter: &FindingCounter, index: usize, chunk: &[String]) -> Finding {
    let title = field_at(chunk, 0);
    let description = field_at(chunk, 1);
    let shape = index + title.len() + description.len();

    let mut finding = Finding::new_static(
        counter,
        category_from(shape),
        severity_from(shape),
        title,
        description,
        PathBuf::from(field_at(chunk, 5)),
    )
    .with_confidence(confidence_from(shape));

    if let Some(suggestion) = optional_field_at(chunk, 2) {
        finding = finding.with_suggestion(suggestion);
    }
    if let Some(snippet) = optional_field_at(chunk, 3) {
        finding = finding.with_snippet(snippet);
    }
    if let Some(rule) = optional_field_at(chunk, 4) {
        finding = finding.with_rule(rule);
    }
    if shape.is_multiple_of(2) {
        finding = finding.with_lines(shape as u32, shape.saturating_add(1) as u32);
    }
    finding.source = source_from(shape);
    finding
}

fn field_at(chunk: &[String], position: usize) -> String {
    chunk.get(position).cloned().unwrap_or_default()
}

fn optional_field_at(chunk: &[String], position: usize) -> Option<String> {
    chunk
        .get(position)
        .filter(|field| !field.is_empty())
        .cloned()
}

fn severity_from(shape: usize) -> Severity {
    match shape % 5 {
        0 => Severity::Info,
        1 => Severity::Low,
        2 => Severity::Medium,
        3 => Severity::High,
        _ => Severity::Critical,
    }
}

fn category_from(shape: usize) -> AnalysisCategory {
    match shape % 4 {
        0 => AnalysisCategory::Bug,
        1 => AnalysisCategory::Quality,
        2 => AnalysisCategory::Solid,
        _ => AnalysisCategory::Vulnerability,
    }
}

fn confidence_from(shape: usize) -> Confidence {
    match shape % 3 {
        0 => Confidence::Low,
        1 => Confidence::Medium,
        _ => Confidence::High,
    }
}

fn source_from(shape: usize) -> FindingSource {
    if shape.is_multiple_of(2) {
        FindingSource::Static
    } else {
        FindingSource::Ai
    }
}

fn build_scan_status(fields: &[String]) -> ScanStatus {
    let failed_shards: Vec<FailedShard> = select_fields(fields, 0)
        .map(|(index, error)| FailedShard {
            shard: index as u32,
            error: error.to_owned(),
        })
        .collect();
    let skipped_files: Vec<String> = select_fields(fields, 1)
        .map(|(_, name)| name.to_owned())
        .collect();
    let uninspected_files: Vec<String> = select_fields(fields, 2)
        .map(|(_, name)| name.to_owned())
        .collect();
    let omitted_diagnostics = select_fields(fields, 3).count() as u32;

    let shards_total = failed_shards.len().saturating_add(1) as u32;
    let files_presented = fields.len() as u32;
    ScanStatus {
        completeness: ScanCompleteness::of(&failed_shards, &skipped_files, &uninspected_files)
            .with_omissions(omitted_diagnostics),
        shards_total,
        shards_completed: shards_total - failed_shards.len() as u32,
        failed_shards,
        files_presented,
        files_inspected: files_presented.saturating_sub(uninspected_files.len() as u32),
        uninspected_files,
        skipped_files,
        omitted_diagnostics,
    }
}

fn select_fields(fields: &[String], remainder: usize) -> impl Iterator<Item = (usize, &str)> {
    fields
        .iter()
        .enumerate()
        .filter(move |(index, field)| !field.is_empty() && index % SCAN_FIELD_STRIDE == remainder)
        .map(|(index, field)| (index, field.as_str()))
}

fn assert_finding_ids_are_unique(findings: &[Finding]) {
    let mut identifiers: Vec<&str> = findings.iter().map(|finding| finding.id.as_str()).collect();
    let total = identifiers.len();
    identifiers.sort_unstable();
    identifiers.dedup();
    assert_eq!(identifiers.len(), total, "duplicate finding identifier");
}

fn markdown_without_code_snippets(rendered: &str) -> (String, usize) {
    let mut outside = String::with_capacity(rendered.len());
    let mut remaining = rendered;
    let mut snippets = 0usize;
    while let Some(marker_start) = remaining.find(MARKDOWN_CODE_MARKER) {
        let opening_start = marker_start + MARKDOWN_CODE_MARKER.len();
        outside.push_str(&remaining[..opening_start]);
        let fenced = &remaining[opening_start..];
        let (fence, content) = fenced
            .split_once('\n')
            .expect("code fence has an opening line");
        let delimiter = fence.as_bytes().first().copied();
        assert!(
            fence.len() >= 3
                && delimiter.is_some_and(|delimiter| matches!(delimiter, b'`' | b'~'))
                && fence.bytes().all(|byte| Some(byte) == delimiter),
            "markdown report emitted an invalid code fence"
        );
        let closing = format!("\n{fence}\n");
        let closing_start = content
            .find(&closing)
            .expect("code fence has a matching closing line");
        remaining = &content[closing_start + closing.len()..];
        snippets += 1;
    }
    outside.push_str(remaining);
    (outside, snippets)
}

fn assert_markdown_report_invariants(findings: &[Finding], scan: &ScanStatus) {
    let rendered = render_markdown_report(findings, scan).expect("markdown report renders");

    assert_multi_line_display_safe(&rendered, "markdown report");
    let expected_snippets = findings
        .iter()
        .filter(|finding| finding.code_snippet.is_some())
        .count();
    let (outside_code_snippets, rendered_snippets) = markdown_without_code_snippets(&rendered);
    assert_eq!(
        rendered_snippets, expected_snippets,
        "markdown report lost or forged a code snippet"
    );
    assert_markdown_injection_free(
        &outside_code_snippets,
        "markdown report outside structural code fences",
    );
    assert!(
        rendered.starts_with(MARKDOWN_REPORT_HEADER),
        "markdown report lost its header"
    );
    assert_eq!(
        outside_code_snippets
            .matches(FINDING_SECTION_MARKER)
            .count(),
        findings.len(),
        "finding sections in the markdown report are forgeable"
    );
    assert!(
        outside_code_snippets.contains(&format!("**Findings:** {}\n", findings.len())),
        "markdown report finding count is forgeable"
    );
    assert!(
        outside_code_snippets.contains(&format!("**Completeness:** {}\n", scan.completeness)),
        "markdown report lost the coverage section"
    );
    assert_eq!(
        findings.is_empty(),
        outside_code_snippets.contains(EMPTY_REPORT_SENTINEL),
        "markdown report empty-result sentinel is forgeable"
    );
    assert_eq!(
        render_markdown_report(findings, scan).expect("markdown report re-renders"),
        rendered,
        "markdown report rendering is not deterministic"
    );
}

fn assert_json_report_invariants(
    findings: &[Finding],
    scan: &ScanStatus,
    project_root: &Path,
    mode: &str,
) {
    let rendered = render_json_report(FUZZ_VERSION, project_root, findings, mode, scan)
        .expect("json report renders");

    for character in rendered.chars().filter(|character| *character < ' ') {
        assert_eq!(
            character, '\n',
            "json report leaked unescaped C0 control character {character:?}"
        );
    }

    let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("json report parses");
    assert_eq!(parsed["version"], FUZZ_VERSION);
    assert_eq!(parsed["mode"], mode);
    assert_eq!(
        parsed["summary"]["total"].as_u64(),
        Some(findings.len() as u64),
        "json summary total disagrees with the finding count"
    );
    assert_eq!(
        parsed["findings"]
            .as_array()
            .expect("json findings array")
            .len(),
        findings.len(),
        "json findings array disagrees with the finding count"
    );
    assert!(
        parsed["analyzed_at"]
            .as_str()
            .is_some_and(|stamp| !stamp.is_empty()),
        "json report lost its timestamp"
    );

    let restored: Vec<Finding> =
        serde_json::from_value(parsed["findings"].clone()).expect("findings deserialize");
    let restored_scan: ScanStatus =
        serde_json::from_value(parsed["scan"].clone()).expect("scan status deserializes");
    let rerendered =
        render_json_report(FUZZ_VERSION, project_root, &restored, mode, &restored_scan)
            .expect("json report re-renders");
    let reparsed: serde_json::Value =
        serde_json::from_str(&rerendered).expect("re-rendered json report parses");

    assert_eq!(
        without_timestamp(&reparsed),
        without_timestamp(&parsed),
        "json report is not stable across a serialization round trip"
    );
}

fn without_timestamp(report: &serde_json::Value) -> serde_json::Value {
    let mut stripped = report.clone();
    stripped
        .as_object_mut()
        .expect("json report object")
        .remove("analyzed_at");
    stripped
}
