use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::thread;

use bughunter::{AnalysisMode, AnalysisResult, Config, Finding, ProjectRoot};

const CONCURRENT_ANALYSES: usize = 4;
const REPEATED_ANALYSES: usize = 3;
const MAX_FUNCTION_LINES: usize = 5;
const MAX_FILE_LINES: usize = 20;
const PADDING_STATEMENTS: usize = 24;
const LONG_LINE_TERMS: usize = 256;
const NESTED_DEPTH: usize = 16;
const UNICODE_TEXT: &str = "ünïcødé ✓ 変数";

const MULTI_LANGUAGE_FILES: [&str; 4] = ["service.go", "service.js", "service.py", "service.rs"];
const PATHOLOGICAL_FILES: [&str; 2] = ["deep.py", "deep.rs"];
const SINGLE_LANGUAGE_FILE: &str = "helper.py";

const PYTHON_FUNCTION: &str = r#"def accumulate(values):
    total = 0
    for value in values:
        total += value
        total += 1
        total += 2
        total += 3
    return total
"#;

const RUST_FUNCTION: &str = r#"pub fn accumulate(values: &[i64]) -> i64 {
    let mut total = 0;
    for value in values {
        total += value;
        total += 1;
        total += 2;
        total += 3;
    }
    total
}
"#;

const JAVASCRIPT_FUNCTION: &str = r#"function accumulate(values) {
    let total = 0;
    for (const value of values) {
        total += value;
        total += 1;
        total += 2;
        total += 3;
    }
    return total;
}
"#;

const GO_FUNCTION: &str = r#"package main

func accumulate(values []int) int {
    total := 0
    for _, value := range values {
        total += value
        total += 1
        total += 2
        total += 3
    }
    return total
}
"#;

const PYTHON_PADDING: &str = "filler_INDEX = INDEX\n";
const RUST_PADDING: &str = "pub const FILLER_INDEX: i64 = INDEX;\n";
const JAVASCRIPT_PADDING: &str = "const fillerINDEX = INDEX;\n";
const GO_PADDING: &str = "var fillerINDEX int = INDEX\n";

struct AnalysisOutcome {
    fingerprints: Vec<String>,
    identifiers: BTreeSet<String>,
    files: BTreeSet<String>,
    files_presented: u32,
    files_inspected: u32,
}

fn sanitizer_config() -> Config {
    let mut config = Config::default();
    config.analysis.quality.max_function_lines = MAX_FUNCTION_LINES;
    config.analysis.quality.max_file_lines = MAX_FILE_LINES;
    config
}

fn padding(statement: &str) -> String {
    (0..PADDING_STATEMENTS)
        .map(|index| statement.replace("INDEX", &index.to_string()))
        .collect()
}

fn long_sum() -> String {
    (0..LONG_LINE_TERMS)
        .map(|term| format!(" + {term}"))
        .collect()
}

fn nested(open: char, close: char) -> String {
    format!(
        "{}1{}",
        open.to_string().repeat(NESTED_DEPTH),
        close.to_string().repeat(NESTED_DEPTH)
    )
}

fn write_multi_language_project(root: &Path) {
    write_source(root, "service.py", PYTHON_FUNCTION, PYTHON_PADDING);
    write_source(root, "service.rs", RUST_FUNCTION, RUST_PADDING);
    write_source(root, "service.js", JAVASCRIPT_FUNCTION, JAVASCRIPT_PADDING);
    write_source(root, "service.go", GO_FUNCTION, GO_PADDING);
}

fn write_single_language_project(root: &Path) {
    write_source(root, SINGLE_LANGUAGE_FILE, PYTHON_FUNCTION, PYTHON_PADDING);
}

fn write_pathological_project(root: &Path) {
    let python = format!(
        "{PYTHON_FUNCTION}nested = {}\ntotal = 0{}\nlabel = \"{UNICODE_TEXT}\"\n{}",
        nested('[', ']'),
        long_sum(),
        padding(PYTHON_PADDING)
    );
    let rust = format!(
        "{RUST_FUNCTION}pub static NESTED: i64 = {};\npub static TOTAL: i64 = 0{};\npub static LABEL: &str = \"{UNICODE_TEXT}\";\n{}",
        nested('(', ')'),
        long_sum(),
        padding(RUST_PADDING)
    );
    fs::write(root.join("deep.py"), python).unwrap();
    fs::write(root.join("deep.rs"), rust).unwrap();
}

fn write_source(root: &Path, name: &str, function: &str, statement: &str) {
    let source = format!("{function}{}", padding(statement));
    fs::write(root.join(name), source).unwrap();
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_owned()
}

fn fingerprint(finding: &Finding) -> String {
    format!(
        "{}|{:?}|{:?}|{}|{}|{}",
        file_name(&finding.file),
        finding.category,
        finding.severity,
        finding.rule.as_deref().unwrap_or_default(),
        finding.line_start.unwrap_or_default(),
        finding.title
    )
}

fn outcome(result: &AnalysisResult) -> AnalysisOutcome {
    let mut fingerprints: Vec<String> = result.findings.iter().map(fingerprint).collect();
    fingerprints.sort();
    AnalysisOutcome {
        fingerprints,
        identifiers: result
            .findings
            .iter()
            .map(|finding| finding.id.clone())
            .collect(),
        files: result
            .findings
            .iter()
            .map(|finding| file_name(&finding.file))
            .collect(),
        files_presented: result.scan.files_presented,
        files_inspected: result.scan.files_inspected,
    }
}

fn analyze_static(path: &Path) -> AnalysisOutcome {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let root = ProjectRoot::open(path).unwrap();
    let analysis = runtime
        .block_on(bughunter::analyze(
            &root,
            sanitizer_config(),
            AnalysisMode::Static,
        ))
        .unwrap();
    outcome(&analysis)
}

fn reported_files_are_limited_to(files: &BTreeSet<String>, expected: &[&str]) -> bool {
    files.iter().all(|name| expected.contains(&name.as_str()))
}

#[test]
fn concurrent_static_analyses_report_identical_findings() {
    let project = tempfile::tempdir().unwrap();
    write_multi_language_project(project.path());

    let baseline = analyze_static(project.path());

    assert!(!baseline.fingerprints.is_empty());
    assert_eq!(baseline.identifiers.len(), baseline.fingerprints.len());
    assert_eq!(baseline.files_inspected, MULTI_LANGUAGE_FILES.len() as u32);
    assert_eq!(baseline.files_presented, baseline.files_inspected);
    assert!(reported_files_are_limited_to(
        &baseline.files,
        &MULTI_LANGUAGE_FILES
    ));

    let project_path = project.path().to_path_buf();
    let workers: Vec<_> = (0..CONCURRENT_ANALYSES)
        .map(|_| {
            let path = project_path.clone();
            thread::spawn(move || analyze_static(&path))
        })
        .collect();

    for worker in workers {
        let concurrent = worker.join().unwrap();
        assert_eq!(concurrent.fingerprints, baseline.fingerprints);
        assert_eq!(concurrent.identifiers, baseline.identifiers);
        assert_eq!(concurrent.files_inspected, baseline.files_inspected);
        assert_eq!(concurrent.files_presented, baseline.files_presented);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interleaved_analyses_keep_project_results_isolated() {
    let multi_language = tempfile::tempdir().unwrap();
    write_multi_language_project(multi_language.path());
    let single_language = tempfile::tempdir().unwrap();
    write_single_language_project(single_language.path());

    let multi_root = ProjectRoot::open(multi_language.path()).unwrap();
    let single_root = ProjectRoot::open(single_language.path()).unwrap();

    let (first_multi, first_single, second_multi, second_single) = tokio::join!(
        bughunter::analyze(&multi_root, sanitizer_config(), AnalysisMode::Static),
        bughunter::analyze(&single_root, sanitizer_config(), AnalysisMode::Static),
        bughunter::analyze(&multi_root, sanitizer_config(), AnalysisMode::Static),
        bughunter::analyze(&single_root, sanitizer_config(), AnalysisMode::Static),
    );

    let first_multi = outcome(&first_multi.unwrap());
    let second_multi = outcome(&second_multi.unwrap());
    let first_single = outcome(&first_single.unwrap());
    let second_single = outcome(&second_single.unwrap());

    assert!(!first_multi.fingerprints.is_empty());
    assert!(!first_single.fingerprints.is_empty());
    assert_eq!(first_multi.fingerprints, second_multi.fingerprints);
    assert_eq!(first_single.fingerprints, second_single.fingerprints);
    assert_ne!(first_multi.fingerprints, first_single.fingerprints);
    assert_eq!(
        first_multi.files_inspected,
        MULTI_LANGUAGE_FILES.len() as u32
    );
    assert_eq!(first_single.files_inspected, 1);
    assert!(reported_files_are_limited_to(
        &first_multi.files,
        &MULTI_LANGUAGE_FILES
    ));
    assert_eq!(
        first_single.files,
        BTreeSet::from([SINGLE_LANGUAGE_FILE.to_owned()])
    );
}

#[test]
fn repeated_analyses_of_pathological_sources_stay_stable() {
    let project = tempfile::tempdir().unwrap();
    write_pathological_project(project.path());

    let baseline = analyze_static(project.path());

    assert!(!baseline.fingerprints.is_empty());
    assert_eq!(baseline.files_inspected, PATHOLOGICAL_FILES.len() as u32);
    assert_eq!(baseline.files_presented, baseline.files_inspected);
    assert!(reported_files_are_limited_to(
        &baseline.files,
        &PATHOLOGICAL_FILES
    ));

    for _ in 1..REPEATED_ANALYSES {
        let repeated = analyze_static(project.path());
        assert_eq!(repeated.fingerprints, baseline.fingerprints);
        assert_eq!(repeated.identifiers, baseline.identifiers);
        assert_eq!(repeated.files_inspected, baseline.files_inspected);
        assert_eq!(repeated.files_presented, baseline.files_presented);
    }
}
