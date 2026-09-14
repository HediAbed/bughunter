use std::path::Path;

use serde::Serialize;

use crate::errors::ReportError;

use super::limits::{BoundedBytes, JSON_REPORT, MAX_REPORT_BYTES};
use super::{Finding, ScanStatus, Summary};

#[derive(Debug, Serialize)]
pub struct JsonReport<'a> {
    pub version: &'a str,
    pub project: &'a str,
    pub analyzed_at: String,
    pub mode: &'a str,
    pub summary: Summary,
    pub scan: &'a ScanStatus,
    pub findings: &'a [Finding],
}

pub fn render(
    version: &str,
    project_root: &Path,
    findings: &[Finding],
    mode: &str,
    scan: &ScanStatus,
) -> Result<String, ReportError> {
    render_within(
        version,
        project_root,
        findings,
        mode,
        scan,
        MAX_REPORT_BYTES,
    )
}

pub fn render_within(
    version: &str,
    project_root: &Path,
    findings: &[Finding],
    mode: &str,
    scan: &ScanStatus,
    limit_bytes: usize,
) -> Result<String, ReportError> {
    let project = project_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown");

    let report = JsonReport {
        version,
        project,
        analyzed_at: chrono::Utc::now().to_rfc3339(),
        mode,
        summary: Summary::from_findings(findings),
        scan,
        findings,
    };

    serialize_pretty_within(&report, limit_bytes)
}

fn serialize_pretty_within(
    value: &impl Serialize,
    limit_bytes: usize,
) -> Result<String, ReportError> {
    let mut sink = BoundedBytes::new(limit_bytes);
    let serialized = serde_json::to_writer_pretty(&mut sink, value);
    match serialized {
        Ok(()) => json_bytes_to_string(sink.into_bytes()),
        Err(_) if sink.is_exhausted() => Err(ReportError::TooLarge {
            resource: JSON_REPORT,
            limit_bytes,
        }),
        Err(error) => Err(ReportError::SerializationError(error.to_string())),
    }
}

fn json_bytes_to_string(bytes: Vec<u8>) -> Result<String, ReportError> {
    match String::from_utf8(bytes) {
        Ok(json) => Ok(json),
        Err(_) => Err(ReportError::SerializationError(
            "report is not valid UTF-8".to_string(),
        )),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::config::schema::{AnalysisCategory, Severity};
    use crate::report::finding::{FailedShard, FindingCounter, ScanCompleteness};

    fn partial_scan() -> ScanStatus {
        ScanStatus {
            completeness: ScanCompleteness::Partial,
            shards_total: 3,
            shards_completed: 2,
            failed_shards: vec![FailedShard {
                shard: 2,
                error: "engine overloaded".into(),
            }],
            files_presented: 9,
            files_inspected: 5,
            uninspected_files: vec!["src/skipped.rs".into()],
            skipped_files: vec!["src/capped.rs".into()],
            omitted_diagnostics: 4,
        }
    }

    #[test]
    fn renders_empty_report() {
        let json = render(
            "0.1.0",
            Path::new("/tmp/myapp"),
            &[],
            "static",
            &ScanStatus::complete(7),
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["version"], "0.1.0");
        assert_eq!(parsed["project"], "myapp");
        assert_eq!(parsed["mode"], "static");
        assert_eq!(parsed["summary"]["total"], 0);
        assert!(parsed["findings"].as_array().unwrap().is_empty());
        assert_eq!(parsed["scan"]["completeness"], "complete");
        assert_eq!(parsed["scan"]["files_presented"], 7);
        assert_eq!(parsed["scan"]["files_inspected"], 7);
    }

    #[test]
    fn renders_report_with_findings() {
        let c = FindingCounter::new();
        let findings = vec![
            Finding::new_static(
                &c,
                AnalysisCategory::Bug,
                Severity::High,
                "test bug".into(),
                "description".into(),
                "src/main.rs".into(),
            )
            .with_lines(10, 20),
        ];

        let json = render(
            "0.1.0",
            Path::new("/tmp/proj"),
            &findings,
            "static",
            &ScanStatus::complete(1),
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["summary"]["total"], 1);
        assert_eq!(parsed["findings"][0]["severity"], "high");
        assert_eq!(parsed["findings"][0]["line_start"], 10);
    }

    #[test]
    fn output_is_valid_json() {
        let c = FindingCounter::new();
        let findings = vec![
            Finding::new_static(
                &c,
                AnalysisCategory::Vulnerability,
                Severity::Critical,
                "secret found".into(),
                "hardcoded password".into(),
                "config.py".into(),
            ),
            Finding::new_static(
                &c,
                AnalysisCategory::Quality,
                Severity::Low,
                "TODO comment".into(),
                "unfinished work".into(),
                "lib.rs".into(),
            ),
        ];

        let json = render(
            "0.1.0",
            Path::new("/app"),
            &findings,
            "full",
            &ScanStatus::complete(2),
        )
        .unwrap();
        assert!(serde_json::from_str::<serde_json::Value>(&json).is_ok());
    }

    #[test]
    fn partial_scan_status_is_serialized_in_full() {
        let json = render("0.1.0", Path::new("/app"), &[], "ai", &partial_scan()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["scan"]["completeness"], "partial");
        assert_eq!(parsed["scan"]["shards_total"], 3);
        assert_eq!(parsed["scan"]["shards_completed"], 2);
        assert_eq!(parsed["scan"]["failed_shards"][0]["shard"], 2);
        assert_eq!(
            parsed["scan"]["failed_shards"][0]["error"],
            "engine overloaded"
        );
        assert_eq!(parsed["scan"]["files_presented"], 9);
        assert_eq!(parsed["scan"]["files_inspected"], 5);
        assert_eq!(parsed["scan"]["uninspected_files"][0], "src/skipped.rs");
        assert_eq!(parsed["scan"]["skipped_files"][0], "src/capped.rs");
        assert_eq!(parsed["scan"]["omitted_diagnostics"], 4);
    }

    #[test]
    fn root_project_path_uses_the_unknown_project_name() {
        let json = render(
            "0.1.0",
            Path::new("/"),
            &[],
            "static",
            &ScanStatus::complete(0),
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["project"], "unknown");
    }

    #[test]
    fn serialization_failures_are_reported_as_report_errors() {
        struct FailingSerialization;

        impl Serialize for FailingSerialization {
            fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                Err(serde::ser::Error::custom("cannot serialize"))
            }
        }

        let error = serialize_pretty_within(&FailingSerialization, MAX_REPORT_BYTES).unwrap_err();

        assert!(matches!(
            error,
            ReportError::SerializationError(message) if message.contains("cannot serialize")
        ));
    }

    fn stamped_report<'a>(scan: &'a ScanStatus, findings: &'a [Finding]) -> JsonReport<'a> {
        JsonReport {
            version: "1.2.3",
            project: "app",
            analyzed_at: "2026-08-30T00:00:00+00:00".to_string(),
            mode: "static",
            summary: Summary::from_findings(findings),
            scan,
            findings,
        }
    }

    fn stamped_bytes(scan: &ScanStatus, findings: &[Finding]) -> usize {
        serialize_pretty_within(&stamped_report(scan, findings), MAX_REPORT_BYTES)
            .unwrap()
            .len()
    }

    fn titled_finding(counter: &FindingCounter, title: &str) -> Finding {
        Finding::new_static(
            counter,
            AnalysisCategory::Bug,
            Severity::High,
            title.to_string(),
            "d".into(),
            "src/a.rs".into(),
        )
    }

    #[test]
    fn a_report_that_exactly_fits_the_byte_ceiling_is_rendered() {
        let scan = ScanStatus::complete(0);
        let exact = stamped_bytes(&scan, &[]);

        let rendered = serialize_pretty_within(&stamped_report(&scan, &[]), exact).unwrap();

        assert_eq!(rendered.len(), exact);
    }

    #[test]
    fn a_report_one_byte_over_the_ceiling_is_rejected_as_too_large() {
        let scan = ScanStatus::complete(0);
        let limit = stamped_bytes(&scan, &[]) - 1;

        let error = serialize_pretty_within(&stamped_report(&scan, &[]), limit).unwrap_err();

        assert!(matches!(
            error,
            ReportError::TooLarge {
                resource: JSON_REPORT,
                limit_bytes,
            } if limit_bytes == limit
        ));
    }

    #[test]
    fn json_escapes_count_against_the_byte_ceiling() {
        let counter = FindingCounter::new();
        let plain = [titled_finding(&counter, "abcdefgh")];
        let quoted = [titled_finding(&counter, "\"\"\"\"\"\"\"\"")];
        let scan = ScanStatus::complete(1);
        let plain_bytes = stamped_bytes(&scan, &plain);

        let error =
            serialize_pretty_within(&stamped_report(&scan, &quoted), plain_bytes).unwrap_err();

        assert!(matches!(error, ReportError::TooLarge { .. }));
        assert_eq!(
            stamped_bytes(&scan, &quoted),
            plain_bytes + quoted[0].title.len(),
            "each escaped quote must cost its escape byte"
        );
    }

    #[test]
    fn an_oversize_finding_set_never_yields_a_partial_report() {
        let counter = FindingCounter::new();
        let findings: Vec<Finding> = (0..64)
            .map(|index| {
                Finding::new_static(
                    &counter,
                    AnalysisCategory::Quality,
                    Severity::Low,
                    format!("title {index}"),
                    "x".repeat(1024),
                    "src/a.rs".into(),
                )
            })
            .collect();

        let error = render_within(
            "0.1.0",
            Path::new("/tmp/app"),
            &findings,
            "static",
            &ScanStatus::complete(1),
            4 * 1024,
        )
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            "the JSON report exceeds the 4096 byte limit"
        );
    }

    #[test]
    fn a_generous_ceiling_renders_the_whole_report() {
        let counter = FindingCounter::new();
        let findings = [titled_finding(&counter, "kept")];

        let rendered = render_within(
            "0.1.0",
            Path::new("/tmp/app"),
            &findings,
            "static",
            &ScanStatus::complete(1),
            MAX_REPORT_BYTES,
        )
        .unwrap();

        assert!(rendered.contains("\"kept\""), "{rendered}");
    }

    #[test]
    fn the_summary_buckets_the_findings_by_severity_and_category() {
        let c = FindingCounter::new();
        let findings = vec![
            Finding::new_static(
                &c,
                AnalysisCategory::Bug,
                Severity::High,
                "bug".into(),
                "d".into(),
                "src/a.rs".into(),
            ),
            Finding::new_static(
                &c,
                AnalysisCategory::Bug,
                Severity::Low,
                "bug".into(),
                "d".into(),
                "src/b.rs".into(),
            ),
            Finding::new_static(
                &c,
                AnalysisCategory::Vulnerability,
                Severity::Critical,
                "vuln".into(),
                "d".into(),
                "src/c.rs".into(),
            ),
        ];

        let json = render(
            "0.1.0",
            Path::new("/tmp/proj"),
            &findings,
            "full",
            &ScanStatus::complete(3),
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["summary"]["total"], 3);
        assert_eq!(parsed["summary"]["by_category"]["bug"], 2);
        assert_eq!(parsed["summary"]["by_category"]["vulnerability"], 1);
        assert_eq!(parsed["summary"]["by_severity"]["high"], 1);
        assert_eq!(parsed["summary"]["by_severity"]["low"], 1);
        assert_eq!(parsed["summary"]["by_severity"]["critical"], 1);
        assert!(parsed["summary"]["by_severity"]["medium"].is_null());
        assert_eq!(parsed["findings"][0]["source"], "static");
    }

    #[test]
    fn every_report_is_stamped_with_an_rfc3339_analysis_time() {
        let json = render(
            "0.1.0",
            Path::new("/tmp/proj"),
            &[],
            "static",
            &ScanStatus::complete(0),
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let stamped = parsed["analyzed_at"].as_str().expect("a timestamp string");
        let parsed_time = chrono::DateTime::<chrono::FixedOffset>::parse_from_rfc3339(stamped);

        assert!(parsed_time.is_ok(), "{stamped}");
    }

    #[cfg(unix)]
    #[test]
    fn a_project_directory_name_that_is_not_utf8_is_reported_as_unknown() {
        use std::os::unix::ffi::OsStrExt;

        let root = Path::new(std::ffi::OsStr::from_bytes(b"/tmp/\xffproject"));

        let json = render("0.1.0", root, &[], "static", &ScanStatus::complete(0)).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["project"], "unknown");
    }

    #[cfg(unix)]
    #[test]
    fn a_finding_path_that_is_not_utf8_fails_the_render_instead_of_being_dropped() {
        use std::os::unix::ffi::OsStringExt;

        let c = FindingCounter::new();
        let finding = Finding::new_static(
            &c,
            AnalysisCategory::Bug,
            Severity::High,
            "unnameable evidence".into(),
            "unnameable evidence".into(),
            std::ffi::OsString::from_vec(b"src/\xffbroken.rs".to_vec()).into(),
        );

        let error = render(
            "0.1.0",
            Path::new("/tmp/proj"),
            &[finding],
            "static",
            &ScanStatus::complete(1),
        )
        .unwrap_err();

        let ReportError::SerializationError(message) = error else {
            panic!("an unserializable report must fail as a serialization error");
        };
        assert!(message.contains("invalid UTF-8"), "{message}");
    }

    #[test]
    fn a_report_borrowing_its_inputs_serializes_the_documented_schema_in_order() {
        let findings: Vec<Finding> = Vec::new();
        let scan = ScanStatus::complete(0);
        let expected = r#"{
  "version": "1.2.3",
  "project": "app",
  "analyzed_at": "2026-08-30T00:00:00+00:00",
  "mode": "static",
  "summary": {
    "total": 0,
    "by_severity": {},
    "by_category": {}
  },
  "scan": {
    "completeness": "complete",
    "shards_total": 0,
    "shards_completed": 0,
    "failed_shards": [],
    "files_presented": 0,
    "files_inspected": 0,
    "uninspected_files": [],
    "skipped_files": [],
    "omitted_diagnostics": 0
  },
  "findings": []
}"#;

        let json =
            serialize_pretty_within(&stamped_report(&scan, &findings), MAX_REPORT_BYTES).unwrap();

        assert_eq!(json, expected);
    }

    #[test]
    fn rendering_borrows_its_inputs_and_repeats_the_same_report() {
        let c = FindingCounter::new();
        let findings = vec![
            Finding::new_static(
                &c,
                AnalysisCategory::Bug,
                Severity::High,
                "borrowed".into(),
                "d".into(),
                "src/a.rs".into(),
            )
            .with_lines(3, 4),
        ];
        let scan = partial_scan();

        let first = render("0.1.0", Path::new("/tmp/proj"), &findings, "full", &scan).unwrap();
        let second = render("0.1.0", Path::new("/tmp/proj"), &findings, "full", &scan).unwrap();

        let first_report: serde_json::Value = serde_json::from_str(&first).unwrap();
        let second_report: serde_json::Value = serde_json::from_str(&second).unwrap();
        assert_eq!(first_report["findings"], second_report["findings"]);
        assert_eq!(first_report["scan"], second_report["scan"]);
        assert_eq!(first_report["summary"], second_report["summary"]);
        assert_eq!(first_report["findings"][0]["title"], "borrowed");
        assert_eq!(first_report["findings"][0]["line_start"], 3);
        assert_eq!(first_report["scan"]["completeness"], "partial");
        assert_eq!(findings.len(), 1, "the caller still owns its findings");
        assert_eq!(findings[0].line_start, Some(3));
        assert!(scan.is_partial(), "the caller still owns its scan status");
    }
    #[test]
    fn json_byte_conversion_rejects_invalid_utf8() {
        assert_eq!(json_bytes_to_string(b"{}".to_vec()).unwrap(), "{}");

        let error = json_bytes_to_string(vec![0xff]).unwrap_err();

        assert!(matches!(
            error,
            ReportError::SerializationError(message) if message == "report is not valid UTF-8"
        ));
    }
}
