#![no_main]

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use bughunter::{AnalysisMode, Config, ProjectRoot, analyze};
use libfuzzer_sys::fuzz_target;
use tempfile::TempDir;
use tokio::runtime::{Builder, Runtime};

const MAX_SOURCE_BYTES: usize = 4096;
const AST_EXTENSIONS: [&str; 13] = [
    "rs", "py", "js", "ts", "tsx", "go", "java", "c", "cpp", "sh", "hcl", "yaml", "json",
];

struct StaticAnalysisFixture {
    _directory: TempDir,
    project_root: ProjectRoot,
    source_paths: [PathBuf; AST_EXTENSIONS.len()],
}

static FIXTURE: LazyLock<StaticAnalysisFixture> = LazyLock::new(|| {
    let directory = tempfile::tempdir().expect("temporary directory");
    let source_paths =
        AST_EXTENSIONS.map(|extension| directory.path().join(format!("input.{extension}")));
    let project_root = ProjectRoot::open(directory.path()).expect("project root");
    StaticAnalysisFixture {
        _directory: directory,
        project_root,
        source_paths,
    }
});

static RUNTIME: LazyLock<Runtime> =
    LazyLock::new(|| Builder::new_current_thread().build().expect("runtime"));

fuzz_target!(|data: &[u8]| {
    let Some((selector, source)) = data.split_first() else {
        return;
    };
    if source.len() > MAX_SOURCE_BYTES {
        return;
    }
    let selected = usize::from(*selector) % AST_EXTENSIONS.len();

    for (index, path) in FIXTURE.source_paths.iter().enumerate() {
        if index == selected {
            std::fs::write(path, source).expect("source write");
        } else {
            remove_stale_source(path);
        }
    }

    let analysis = RUNTIME
        .block_on(analyze(
            &FIXTURE.project_root,
            Config::default(),
            AnalysisMode::Static,
        ))
        .expect("static analysis of a bounded source file must succeed");

    let parsed: serde_json::Value = serde_json::from_str(&analysis.output).expect("JSON report");
    assert_eq!(parsed["mode"], "static");
    assert_eq!(
        analysis.scan.files_presented, analysis.scan.files_inspected,
        "a bounded {} source file was presented without being inspected",
        AST_EXTENSIONS[selected]
    );
    assert!(
        analysis.scan.files_inspected <= 1,
        "static analysis inspected more files than the fixture contains"
    );
});

fn remove_stale_source(path: &Path) {
    if let Err(error) = std::fs::remove_file(path) {
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::NotFound,
            "stale source file {} could not be removed",
            path.display()
        );
    }
}
