use std::fs;
use std::ops::Range;
use std::sync::LazyLock;
use std::time::Duration;

use bughunter::{AnalysisMode, AnalysisResult, Config, ProjectRoot};
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tempfile::TempDir;
use tokio::runtime::{Builder, Runtime};

const LARGE_FILE_FUNCTION_COUNT: usize = 90;
const PROJECT_MODULE_COUNT: usize = 12;
const FILES_PER_MODULE: usize = 16;
const FUNCTIONS_PER_PROJECT_FILE: usize = 2;
const MINIMUM_BODY_STATEMENTS: usize = 18;
const BODY_LENGTH_VARIANTS: usize = 6;
const BODY_LENGTH_STEP: usize = 14;
const TODO_FUNCTION_INTERVAL: usize = 4;
const SECRET_FUNCTION_INTERVAL: usize = 7;
const ESTIMATED_BYTES_PER_FUNCTION: usize = 4096;
const SAMPLE_SIZE: usize = 10;
const WARM_UP_TIME: Duration = Duration::from_secs(2);
const SINGLE_FILE_MEASUREMENT_TIME: Duration = Duration::from_secs(6);
const PROJECT_MEASUREMENT_TIME: Duration = Duration::from_secs(12);

static BENCH_RUNTIME: LazyLock<Runtime> = LazyLock::new(|| {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime for benchmark analysis calls")
});

fn static_scan_of_large_single_file(criterion: &mut Criterion) {
    let fixture = ProjectFixture::single_large_file();
    fixture.verify_scan_covers_every_file();

    let mut group = criterion.benchmark_group("static_scan_single_large_file");
    group.warm_up_time(WARM_UP_TIME);
    group.measurement_time(SINGLE_FILE_MEASUREMENT_TIME);
    group.throughput(Throughput::Bytes(fixture.byte_count));
    let parameter = format!("{}_lines", fixture.line_count);
    let id = BenchmarkId::new("typescript_module", parameter);
    group.bench_function(id, |bencher| {
        bencher.iter_batched(
            || fixture.config.clone(),
            |config| fixture.analyze(config),
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn static_scan_of_multi_language_project(criterion: &mut Criterion) {
    let fixture = ProjectFixture::multi_language_project();
    fixture.verify_scan_covers_every_file();

    let mut group = criterion.benchmark_group("static_scan_multi_language_project");
    group.warm_up_time(WARM_UP_TIME);
    group.measurement_time(PROJECT_MEASUREMENT_TIME);
    group.throughput(Throughput::ElementsAndBytes {
        elements: fixture.file_count,
        bytes: fixture.byte_count,
    });
    let parameter = format!("{}_files", fixture.file_count);
    let id = BenchmarkId::new("mixed_language_modules", parameter);
    group.bench_function(id, |bencher| {
        bencher.iter_batched(
            || fixture.config.clone(),
            |config| fixture.analyze(config),
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

struct ProjectFixture {
    _directory: TempDir,
    root: ProjectRoot,
    config: Config,
    file_count: u64,
    line_count: u64,
    byte_count: u64,
}

impl ProjectFixture {
    fn single_large_file() -> Self {
        let file = GeneratedFile {
            relative_path: "src/analytics_pipeline.ts".to_string(),
            contents: generate_source(&TYPESCRIPT_TEMPLATE, 0..LARGE_FILE_FUNCTION_COUNT),
        };
        Self::write_to_temp_dir(vec![file])
    }

    fn multi_language_project() -> Self {
        let mut files = Vec::with_capacity(PROJECT_MODULE_COUNT * FILES_PER_MODULE);
        for module in 0..PROJECT_MODULE_COUNT {
            for file in 0..FILES_PER_MODULE {
                let ordinal = module * FILES_PER_MODULE + file;
                let template = &PROJECT_TEMPLATES[ordinal % PROJECT_TEMPLATES.len()];
                let first_function = ordinal * FUNCTIONS_PER_PROJECT_FILE;
                let functions = first_function..first_function + FUNCTIONS_PER_PROJECT_FILE;
                let generated = GeneratedFile {
                    relative_path: project_file_path(module, file, template.extension),
                    contents: generate_source(template, functions),
                };
                files.push(generated);
            }
        }
        Self::write_to_temp_dir(files)
    }

    fn write_to_temp_dir(files: Vec<GeneratedFile>) -> Self {
        let directory = TempDir::new().expect("temporary directory for the benchmark fixture");
        let mut line_count: u64 = 0;
        let mut byte_count: u64 = 0;
        for file in &files {
            let path = directory.path().join(&file.relative_path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("benchmark fixture module directory");
            }
            fs::write(&path, &file.contents).expect("benchmark fixture source file");
            line_count += file.contents.lines().count() as u64;
            byte_count += file.contents.len() as u64;
        }
        let root = ProjectRoot::open(directory.path()).expect("benchmark fixture project root");
        Self {
            _directory: directory,
            root,
            config: Config::default(),
            file_count: files.len() as u64,
            line_count,
            byte_count,
        }
    }

    fn analyze(&self, config: Config) -> AnalysisResult {
        let analysis = bughunter::analyze(&self.root, config, AnalysisMode::Static);
        BENCH_RUNTIME
            .block_on(analysis)
            .expect("static analysis of the benchmark fixture must succeed")
    }

    fn verify_scan_covers_every_file(&self) {
        let result = self.analyze(self.config.clone());
        let inspected = u64::from(result.scan.files_inspected);
        assert_eq!(
            inspected, self.file_count,
            "static analysis must inspect every generated fixture file"
        );
        assert!(
            !result.findings.is_empty(),
            "generated fixture must produce static findings"
        );
    }
}

struct GeneratedFile {
    relative_path: String,
    contents: String,
}

fn project_file_path(module: usize, file: usize, extension: &str) -> String {
    format!("module_{module:02}/reducer_{file:02}.{extension}")
}

fn generate_source(template: &SourceTemplate, functions: Range<usize>) -> String {
    let mut source = String::with_capacity(functions.len() * ESTIMATED_BYTES_PER_FUNCTION);
    source.push_str(template.header);
    for index in functions {
        append_function(&mut source, template, index);
    }
    source.push_str(template.footer);
    source
}

fn append_function(source: &mut String, template: &SourceTemplate, index: usize) {
    source.push_str(&format!(
        "{}{index}{}\n",
        template.signature_prefix, template.signature_suffix
    ));
    append_line(source, template.body_prologue);
    if index % TODO_FUNCTION_INTERVAL == 0 {
        append_line(source, template.todo_comment);
    }
    if index % SECRET_FUNCTION_INTERVAL == 0 {
        append_line(source, template.secret_statement);
    }
    let statements = template.statements;
    for position in 0..body_statement_count(index) {
        append_line(source, statements[position % statements.len()]);
    }
    append_line(source, template.body_epilogue);
    if !template.closer.is_empty() {
        append_line(source, template.closer);
    }
    source.push('\n');
}

fn body_statement_count(index: usize) -> usize {
    MINIMUM_BODY_STATEMENTS + (index % BODY_LENGTH_VARIANTS) * BODY_LENGTH_STEP
}

fn append_line(source: &mut String, line: &str) {
    source.push_str(line);
    source.push('\n');
}

struct SourceTemplate {
    extension: &'static str,
    header: &'static str,
    footer: &'static str,
    signature_prefix: &'static str,
    signature_suffix: &'static str,
    body_prologue: &'static str,
    body_epilogue: &'static str,
    closer: &'static str,
    todo_comment: &'static str,
    secret_statement: &'static str,
    statements: &'static [&'static str],
}

const RUST_HEADER: &str = "pub struct Record {
    pub id: u64,
    pub label: String,
}

";

const RUST_STATEMENTS: &[&str] = &[
    "    total = total.wrapping_add(records.len() as u64);",
    "    for record in records {\n        total = total.wrapping_add(record.id);\n    }",
    "    let label_bytes: usize = records.iter().map(|item| item.label.len()).sum();",
    "    total = total.wrapping_add(label_bytes as u64);",
    "    if total % 3 == 0 {\n        total = total.wrapping_mul(2);\n    }",
    "    total = total.rotate_left(1);",
];

const RUST_TEMPLATE: SourceTemplate = SourceTemplate {
    extension: "rs",
    header: RUST_HEADER,
    footer: "",
    signature_prefix: "pub fn reduce_records_",
    signature_suffix: "(records: &[Record]) -> u64 {",
    body_prologue: "    let mut total: u64 = 0;",
    body_epilogue: "    total",
    closer: "}",
    todo_comment: "    // TODO: extract the accumulation loop into a helper",
    secret_statement: "    let fixture_token = \"bench_fixture_token_0001\";",
    statements: RUST_STATEMENTS,
};

const PYTHON_HEADER: &str = "class Record:
    id = 0
    label = \"\"


";

const PYTHON_STATEMENTS: &[&str] = &[
    "    total += len(records)",
    "    for record in records:\n        total += record.id",
    "    label_bytes = [len(record.label) for record in records]",
    "    total += sum(label_bytes)",
    "    if total % 3 == 0:\n        total *= 2",
    "    total %= 1000003",
];

const PYTHON_TEMPLATE: SourceTemplate = SourceTemplate {
    extension: "py",
    header: PYTHON_HEADER,
    footer: "",
    signature_prefix: "def reduce_records_",
    signature_suffix: "(records):",
    body_prologue: "    total = 0",
    body_epilogue: "    return total",
    closer: "",
    todo_comment: "    # TODO: extract the accumulation loop into a helper",
    secret_statement: "    fixture_token = \"bench_fixture_token_0001\"",
    statements: PYTHON_STATEMENTS,
};

const TYPESCRIPT_HEADER: &str = "export interface Record {
    id: number;
    label: string;
}

";

const TYPESCRIPT_STATEMENTS: &[&str] = &[
    "    total += records.length;",
    "    for (const record of records) {\n        total += record.id;\n    }",
    "    const labelBytes = records.map((record) => record.label.length);",
    "    total += labelBytes.reduce((left, right) => left + right, 0);",
    "    if (total % 3 === 0) {\n        total *= 2;\n    }",
    "    total = total % 1000003;",
];

const TYPESCRIPT_TEMPLATE: SourceTemplate = SourceTemplate {
    extension: "ts",
    header: TYPESCRIPT_HEADER,
    footer: "",
    signature_prefix: "export function reduceRecords",
    signature_suffix: "(records: Record[]): number {",
    body_prologue: "    let total = 0;",
    body_epilogue: "    return total;",
    closer: "}",
    todo_comment: "    // TODO: extract the accumulation loop into a helper",
    secret_statement: "    const fixtureToken = \"bench_fixture_token_0001\";",
    statements: TYPESCRIPT_STATEMENTS,
};

const GO_HEADER: &str = "package benchfixture

type Record struct {
    ID uint64
    Label string
}

";

const GO_STATEMENTS: &[&str] = &[
    "    total += uint64(len(records))",
    "    for _, record := range records {\n        total += record.ID\n    }",
    "    labelBytes := len(records) * 2",
    "    total += uint64(labelBytes)",
    "    if total%3 == 0 {\n        total *= 2\n    }",
    "    total = total % 1000003",
];

const GO_TEMPLATE: SourceTemplate = SourceTemplate {
    extension: "go",
    header: GO_HEADER,
    footer: "",
    signature_prefix: "func ReduceRecords",
    signature_suffix: "(records []Record) uint64 {",
    body_prologue: "    var total uint64",
    body_epilogue: "    return total",
    closer: "}",
    todo_comment: "    // TODO: extract the accumulation loop into a helper",
    secret_statement: "    var fixtureToken = \"bench_fixture_token_0001\"",
    statements: GO_STATEMENTS,
};

const JAVA_HEADER: &str = "package benchfixture;

import java.util.List;

public final class RecordReducer {

    public static final class Record {
        public long id;
        public String label;
    }

";

const JAVA_STATEMENTS: &[&str] = &[
    "        total += records.size();",
    "        for (Record record : records) {\n            total += record.id;\n        }",
    "        total += records.isEmpty() ? 0 : records.get(0).label.length();",
    "        if (total % 3 == 0) {\n            total *= 2;\n        }",
    "        total = total % 1000003;",
];

const JAVA_TEMPLATE: SourceTemplate = SourceTemplate {
    extension: "java",
    header: JAVA_HEADER,
    footer: "}\n",
    signature_prefix: "    public static long reduceRecords",
    signature_suffix: "(List<Record> records) {",
    body_prologue: "        long total = 0;",
    body_epilogue: "        return total;",
    closer: "    }",
    todo_comment: "        // TODO: extract the accumulation loop into a helper",
    secret_statement: "        String fixtureToken = \"bench_fixture_token_0001\";",
    statements: JAVA_STATEMENTS,
};

const PROJECT_TEMPLATES: &[SourceTemplate] = &[
    RUST_TEMPLATE,
    PYTHON_TEMPLATE,
    TYPESCRIPT_TEMPLATE,
    GO_TEMPLATE,
    JAVA_TEMPLATE,
];

criterion_group! {
    name = large_inputs;
    config = Criterion::default().sample_size(SAMPLE_SIZE);
    targets = static_scan_of_large_single_file, static_scan_of_multi_language_project
}
criterion_main!(large_inputs);
