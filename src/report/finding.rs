use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use serde::{Deserialize, Serialize};

pub use crate::config::schema::Confidence;
use crate::config::schema::{AnalysisCategory, Severity};

#[derive(Debug)]
pub struct FindingCounter(AtomicU32);

impl FindingCounter {
    pub fn new() -> Self {
        Self(AtomicU32::new(1))
    }

    pub fn with_start(start: u32) -> Self {
        Self(AtomicU32::new(start.max(1)))
    }

    pub fn next_id(&self, category: AnalysisCategory) -> String {
        let counter = self.0.fetch_add(1, Ordering::Relaxed);
        let prefix = category_prefix(category);
        format!("{prefix}-{counter:03}")
    }

    pub fn peek(&self) -> u32 {
        self.0.load(Ordering::Relaxed)
    }
}

impl Default for FindingCounter {
    fn default() -> Self {
        Self::new()
    }
}

fn category_prefix(category: AnalysisCategory) -> &'static str {
    match category {
        AnalysisCategory::Bug => "BUG",
        AnalysisCategory::Quality => "QUAL",
        AnalysisCategory::Solid => "SOLID",
        AnalysisCategory::Vulnerability => "VULN",
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub category: AnalysisCategory,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub file: PathBuf,
    pub line_start: Option<u32>,
    pub line_end: Option<u32>,
    pub code_snippet: Option<String>,
    pub suggestion: Option<String>,
    pub rule: Option<String>,
    pub confidence: Confidence,
    pub source: FindingSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSource {
    Static,
    Ai,
}

impl std::fmt::Display for FindingSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingSource::Static => write!(f, "static"),
            FindingSource::Ai => write!(f, "ai"),
        }
    }
}

impl Finding {
    pub fn new_static(
        counter: &FindingCounter,
        category: AnalysisCategory,
        severity: Severity,
        title: String,
        description: String,
        file: PathBuf,
    ) -> Self {
        Self {
            id: counter.next_id(category),
            category,
            severity,
            title,
            description,
            file,
            line_start: None,
            line_end: None,
            code_snippet: None,
            suggestion: None,
            rule: None,
            confidence: Confidence::High,
            source: FindingSource::Static,
        }
    }

    pub fn with_lines(mut self, start: u32, end: u32) -> Self {
        self.line_start = Some(start);
        self.line_end = Some(end);
        self
    }

    pub fn with_snippet(mut self, snippet: String) -> Self {
        self.code_snippet = Some(snippet);
        self
    }

    pub fn with_suggestion(mut self, suggestion: String) -> Self {
        self.suggestion = Some(suggestion);
        self
    }

    pub fn with_rule(mut self, rule: String) -> Self {
        self.rule = Some(rule);
        self
    }

    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn retained_bytes(&self) -> usize {
        let optional = |value: &Option<String>| value.as_ref().map_or(0, String::len);
        self.id.len()
            + self.title.len()
            + self.description.len()
            + self.file.as_os_str().len()
            + optional(&self.code_snippet)
            + optional(&self.suggestion)
            + optional(&self.rule)
    }

    pub(crate) fn assign_report_sequence(&mut self, sequence: usize) {
        self.id = format!("{}-{sequence:03}", category_prefix(self.category));
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub total: usize,
    pub by_severity: std::collections::HashMap<Severity, usize>,
    pub by_category: std::collections::HashMap<AnalysisCategory, usize>,
}

impl Summary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut by_severity = std::collections::HashMap::new();
        let mut by_category = std::collections::HashMap::new();

        for finding in findings {
            *by_severity.entry(finding.severity).or_insert(0) += 1;
            *by_category.entry(finding.category).or_insert(0) += 1;
        }

        Self {
            total: findings.len(),
            by_severity,
            by_category,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ScanCompleteness {
    Complete,
    Partial,
}

impl std::fmt::Display for ScanCompleteness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanCompleteness::Complete => write!(f, "complete"),
            ScanCompleteness::Partial => write!(f, "partial"),
        }
    }
}

impl ScanCompleteness {
    pub fn of(failed_shards: &[FailedShard], skipped: &[String], uninspected: &[String]) -> Self {
        if failed_shards.is_empty() && skipped.is_empty() && uninspected.is_empty() {
            Self::Complete
        } else {
            Self::Partial
        }
    }

    pub fn with_omissions(self, omitted_diagnostics: u32) -> Self {
        if omitted_diagnostics > 0 {
            return Self::Partial;
        }
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedShard {
    pub shard: u32,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatus {
    pub completeness: ScanCompleteness,
    pub shards_total: u32,
    pub shards_completed: u32,
    pub failed_shards: Vec<FailedShard>,
    pub files_presented: u32,
    pub files_inspected: u32,
    pub uninspected_files: Vec<String>,
    pub skipped_files: Vec<String>,
    #[serde(default)]
    pub omitted_diagnostics: u32,
}

impl ScanStatus {
    pub fn complete(files: u32) -> Self {
        Self::static_scan(files, Vec::new(), 0)
    }

    pub fn static_scan(
        files_inspected: u32,
        skipped_files: Vec<String>,
        omitted_diagnostics: u32,
    ) -> Self {
        let unscanned = (skipped_files.len() as u64).saturating_add(u64::from(omitted_diagnostics));
        Self {
            completeness: ScanCompleteness::of(&[], &skipped_files, &[])
                .with_omissions(omitted_diagnostics),
            shards_total: 0,
            shards_completed: 0,
            failed_shards: Vec::new(),
            files_presented: files_inspected
                .saturating_add(u32::try_from(unscanned).unwrap_or(u32::MAX)),
            files_inspected,
            uninspected_files: Vec::new(),
            skipped_files,
            omitted_diagnostics,
        }
    }

    pub fn is_partial(&self) -> bool {
        self.completeness == ScanCompleteness::Partial
    }
}

pub fn findings_above_threshold(findings: &[Finding], threshold: Severity) -> bool {
    findings.iter().any(|f| f.severity >= threshold)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn counter() -> FindingCounter {
        FindingCounter::new()
    }

    fn sample_finding(c: &FindingCounter) -> Finding {
        Finding::new_static(
            c,
            AnalysisCategory::Bug,
            Severity::High,
            "Null dereference".into(),
            "Possible null pointer dereference".into(),
            "src/main.rs".into(),
        )
    }

    #[test]
    fn creates_finding_with_auto_id() {
        let c = counter();
        let finding = sample_finding(&c);
        assert!(finding.id.starts_with("BUG-"));
        assert_eq!(finding.source, FindingSource::Static);
        assert_eq!(finding.confidence, Confidence::High);
    }

    #[test]
    fn increments_finding_ids() {
        let c = counter();
        let f1 = sample_finding(&c);
        let f2 = sample_finding(&c);
        assert_ne!(f1.id, f2.id);
    }

    #[test]
    fn builder_methods_set_fields() {
        let c = counter();
        let finding = sample_finding(&c)
            .with_lines(10, 20)
            .with_snippet("let x = None;".into())
            .with_suggestion("Add None check".into())
            .with_rule("bug.null-deref".into())
            .with_confidence(Confidence::Medium);

        assert_eq!(finding.line_start, Some(10));
        assert_eq!(finding.line_end, Some(20));
        assert_eq!(finding.code_snippet.as_deref(), Some("let x = None;"));
        assert_eq!(finding.suggestion.as_deref(), Some("Add None check"));
        assert_eq!(finding.rule.as_deref(), Some("bug.null-deref"));
        assert_eq!(finding.confidence, Confidence::Medium);
    }

    #[test]
    fn summary_counts_correctly() {
        let c = counter();
        let findings = vec![
            Finding::new_static(
                &c,
                AnalysisCategory::Bug,
                Severity::High,
                "bug1".into(),
                "d".into(),
                "f.rs".into(),
            ),
            Finding::new_static(
                &c,
                AnalysisCategory::Bug,
                Severity::Critical,
                "bug2".into(),
                "d".into(),
                "f.rs".into(),
            ),
            Finding::new_static(
                &c,
                AnalysisCategory::Quality,
                Severity::Medium,
                "q1".into(),
                "d".into(),
                "f.rs".into(),
            ),
        ];

        let summary = Summary::from_findings(&findings);

        assert_eq!(summary.total, 3);
        assert_eq!(summary.by_category[&AnalysisCategory::Bug], 2);
        assert_eq!(summary.by_category[&AnalysisCategory::Quality], 1);
        assert_eq!(summary.by_severity[&Severity::High], 1);
        assert_eq!(summary.by_severity[&Severity::Critical], 1);
        assert_eq!(summary.by_severity[&Severity::Medium], 1);
        assert!(
            !summary.by_severity.contains_key(&Severity::Low),
            "a severity nobody reported must not appear in the summary"
        );
    }

    #[test]
    fn findings_above_threshold_detects_high() {
        let c = counter();
        let findings = vec![sample_finding(&c)];
        assert!(findings_above_threshold(&findings, Severity::High));
        assert!(!findings_above_threshold(&findings, Severity::Critical));
    }

    #[test]
    fn empty_findings_below_any_threshold() {
        assert!(!findings_above_threshold(&[], Severity::Low));
    }

    #[test]
    fn finding_serializes_to_json() {
        let c = counter();
        let finding = sample_finding(&c).with_lines(5, 10);
        let json = serde_json::to_string(&finding).unwrap();
        assert!(json.contains("\"category\":\"bug\""));
        assert!(json.contains("\"severity\":\"high\""));
        assert!(json.contains("\"line_start\":5"));
    }

    #[test]
    fn category_prefixes_are_correct() {
        let c = counter();
        let bug = Finding::new_static(
            &c,
            AnalysisCategory::Bug,
            Severity::Low,
            "t".into(),
            "d".into(),
            "f".into(),
        );
        let qual = Finding::new_static(
            &c,
            AnalysisCategory::Quality,
            Severity::Low,
            "t".into(),
            "d".into(),
            "f".into(),
        );
        let solid = Finding::new_static(
            &c,
            AnalysisCategory::Solid,
            Severity::Low,
            "t".into(),
            "d".into(),
            "f".into(),
        );
        let vuln = Finding::new_static(
            &c,
            AnalysisCategory::Vulnerability,
            Severity::Low,
            "t".into(),
            "d".into(),
            "f".into(),
        );

        assert!(bug.id.starts_with("BUG-"));
        assert!(qual.id.starts_with("QUAL-"));
        assert!(solid.id.starts_with("SOLID-"));
        assert!(vuln.id.starts_with("VULN-"));
    }

    #[test]
    fn separate_counters_are_independent() {
        let c1 = counter();
        let c2 = counter();
        let f1 = sample_finding(&c1);
        let f2 = sample_finding(&c2);
        assert_eq!(f1.id, f2.id);
    }

    #[test]
    fn complete_status_marks_every_file_inspected() {
        let status = ScanStatus::complete(12);

        assert_eq!(status.completeness, ScanCompleteness::Complete);
        assert!(!status.is_partial());
        assert_eq!(status.files_presented, 12);
        assert_eq!(status.files_inspected, 12);
        assert_eq!(status.shards_total, 0);
        assert_eq!(status.shards_completed, 0);
        assert!(status.failed_shards.is_empty());
        assert!(status.uninspected_files.is_empty());
        assert!(status.skipped_files.is_empty());
    }

    #[test]
    fn a_static_scan_with_skipped_files_is_partial() {
        let status = ScanStatus::static_scan(
            3,
            vec![
                "src/a.rs (unreadable)".into(),
                "src/b.rs (unreadable)".into(),
            ],
            0,
        );

        assert_eq!(status.completeness, ScanCompleteness::Partial);
        assert!(status.is_partial());
        assert_eq!(status.files_inspected, 3);
        assert_eq!(status.files_presented, 5);
        assert_eq!(status.skipped_files.len(), 2);
        assert_eq!(status.omitted_diagnostics, 0);
    }

    #[test]
    fn omitted_diagnostics_count_towards_the_presented_files_and_partial_completeness() {
        let status = ScanStatus::static_scan(3, vec!["src/a.rs (unreadable)".into()], 7);

        assert!(status.is_partial());
        assert_eq!(status.omitted_diagnostics, 7);
        assert_eq!(status.files_presented, 11);
        assert_eq!(status.skipped_files.len(), 1);
    }

    #[test]
    fn omissions_alone_make_a_scan_partial() {
        assert_eq!(
            ScanCompleteness::Complete.with_omissions(0),
            ScanCompleteness::Complete
        );
        assert_eq!(
            ScanCompleteness::Complete.with_omissions(1),
            ScanCompleteness::Partial
        );
        assert!(ScanStatus::static_scan(2, Vec::new(), 1).is_partial());
    }

    #[test]
    fn retained_bytes_sum_every_stored_finding_field() {
        let finding = Finding::new_static(
            &counter(),
            AnalysisCategory::Bug,
            Severity::High,
            "title".into(),
            "description".into(),
            "src/a.rs".into(),
        )
        .with_snippet("snip".into())
        .with_suggestion("fix".into())
        .with_rule("rule".into());

        let expected = finding.id.len()
            + "title".len()
            + "description".len()
            + "src/a.rs".len()
            + "snip".len()
            + "fix".len()
            + "rule".len();

        assert_eq!(finding.retained_bytes(), expected);
    }

    #[test]
    fn completeness_is_partial_for_any_kind_of_gap() {
        let failed = vec![FailedShard {
            shard: 1,
            error: "boom".into(),
        }];
        let paths = vec!["src/a.rs".to_string()];

        assert_eq!(
            ScanCompleteness::of(&[], &[], &[]),
            ScanCompleteness::Complete
        );
        assert_eq!(
            ScanCompleteness::of(&failed, &[], &[]),
            ScanCompleteness::Partial
        );
        assert_eq!(
            ScanCompleteness::of(&[], &paths, &[]),
            ScanCompleteness::Partial
        );
        assert_eq!(
            ScanCompleteness::of(&[], &[], &paths),
            ScanCompleteness::Partial
        );
    }

    #[test]
    fn completeness_serializes_lowercase() {
        let complete = serde_json::to_string(&ScanCompleteness::Complete).unwrap();
        let partial = serde_json::to_string(&ScanCompleteness::Partial).unwrap();

        assert_eq!(complete, "\"complete\"");
        assert_eq!(partial, "\"partial\"");
    }

    #[test]
    fn partial_status_round_trips_through_json() {
        let status = ScanStatus {
            completeness: ScanCompleteness::Partial,
            shards_total: 4,
            shards_completed: 2,
            failed_shards: vec![FailedShard {
                shard: 3,
                error: "engine overloaded".into(),
            }],
            files_presented: 10,
            files_inspected: 6,
            uninspected_files: vec!["src/a.rs".into()],
            skipped_files: vec!["src/b.rs".into()],
            omitted_diagnostics: 3,
        };

        let json = serde_json::to_string(&status).unwrap();
        let restored: ScanStatus = serde_json::from_str(&json).unwrap();

        assert!(restored.is_partial());
        assert_eq!(restored.shards_total, 4);
        assert_eq!(restored.shards_completed, 2);
        assert_eq!(restored.failed_shards.len(), 1);
        assert_eq!(restored.failed_shards[0].shard, 3);
        assert_eq!(restored.failed_shards[0].error, "engine overloaded");
        assert_eq!(restored.files_inspected, 6);
        assert_eq!(restored.uninspected_files, vec!["src/a.rs".to_string()]);
        assert_eq!(restored.skipped_files, vec!["src/b.rs".to_string()]);
        assert_eq!(restored.omitted_diagnostics, 3);
    }

    #[test]
    fn a_status_without_an_omission_count_deserializes_as_nothing_omitted() {
        let legacy = r#"{
            "completeness": "complete",
            "shards_total": 0,
            "shards_completed": 0,
            "failed_shards": [],
            "files_presented": 2,
            "files_inspected": 2,
            "uninspected_files": [],
            "skipped_files": []
        }"#;

        let restored: ScanStatus = serde_json::from_str(legacy).unwrap();

        assert_eq!(restored.omitted_diagnostics, 0);
        assert!(!restored.is_partial());
    }

    #[test]
    fn counter_default_and_peek_expose_the_next_identifier_without_consuming_it() {
        let counter = FindingCounter::default();

        assert_eq!(counter.peek(), 1);
        assert_eq!(counter.next_id(AnalysisCategory::Bug), "BUG-001");
        assert_eq!(counter.peek(), 2);
    }

    #[test]
    fn a_counter_started_below_the_first_identifier_still_numbers_from_one() {
        let counter = FindingCounter::with_start(0);

        assert_eq!(counter.peek(), 1);
        assert_eq!(counter.next_id(AnalysisCategory::Bug), "BUG-001");
    }

    #[test]
    fn a_counter_resumes_at_the_identifier_the_caller_reserved() {
        let counter = FindingCounter::with_start(42);

        assert_eq!(counter.peek(), 42);
        assert_eq!(counter.next_id(AnalysisCategory::Vulnerability), "VULN-042");
        assert_eq!(counter.next_id(AnalysisCategory::Vulnerability), "VULN-043");
        assert_eq!(counter.peek(), 44);
    }

    #[test]
    fn report_sequences_are_padded_and_prefixed_by_the_finding_category() {
        let counter = FindingCounter::with_start(900);
        let cases = [
            (AnalysisCategory::Bug, 1_usize, "BUG-001"),
            (AnalysisCategory::Quality, 12, "QUAL-012"),
            (AnalysisCategory::Solid, 123, "SOLID-123"),
            (AnalysisCategory::Vulnerability, 1234, "VULN-1234"),
        ];

        for (category, sequence, expected) in cases {
            let mut finding = Finding::new_static(
                &counter,
                category,
                Severity::Low,
                "t".into(),
                "d".into(),
                "f.rs".into(),
            );

            finding.assign_report_sequence(sequence);

            assert_eq!(finding.id, expected);
        }
    }

    #[test]
    fn completeness_displays_the_lowercase_word_the_markdown_report_prints() {
        assert_eq!(ScanCompleteness::Complete.to_string(), "complete");
        assert_eq!(ScanCompleteness::Partial.to_string(), "partial");
    }

    #[test]
    fn a_static_scan_saturates_the_presented_count_instead_of_overflowing() {
        let status = ScanStatus::static_scan(u32::MAX, vec!["src/a.rs (unreadable)".into()], 0);

        assert_eq!(status.files_inspected, u32::MAX);
        assert_eq!(status.files_presented, u32::MAX);
        assert!(status.is_partial());
    }

    #[test]
    fn a_static_scan_saturates_the_presented_count_across_omitted_diagnostics() {
        let status = ScanStatus::static_scan(u32::MAX - 1, Vec::new(), u32::MAX);

        assert_eq!(status.files_inspected, u32::MAX - 1);
        assert_eq!(status.files_presented, u32::MAX);
        assert_eq!(status.omitted_diagnostics, u32::MAX);
    }

    #[test]
    fn findings_round_trip_through_the_report_format_with_their_source() {
        for (source, serialized) in [
            (FindingSource::Static, "\"source\":\"static\""),
            (FindingSource::Ai, "\"source\":\"ai\""),
        ] {
            let c = counter();
            let mut finding = sample_finding(&c)
                .with_lines(5, 9)
                .with_rule("bug.null-deref".into())
                .with_confidence(Confidence::Medium);
            finding.source = source;

            let json = serde_json::to_string(&finding).unwrap();
            let restored: Finding = serde_json::from_str(&json).unwrap();

            assert!(json.contains(serialized), "{json}");
            assert_eq!(restored.source, source);
            assert_eq!(restored.id, finding.id);
            assert_eq!(restored.file, finding.file);
            assert_eq!(restored.line_start, Some(5));
            assert_eq!(restored.line_end, Some(9));
            assert_eq!(restored.rule.as_deref(), Some("bug.null-deref"));
            assert_eq!(restored.confidence, Confidence::Medium);
        }
    }
}
