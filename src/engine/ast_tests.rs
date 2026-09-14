use super::*;

const RUST_CODE: &str = r#"
use std::io;

pub struct Config {
pub name: String,
pub value: i32,
}

pub enum Status {
Active,
Inactive,
}

pub trait Processor {
fn process(&self) -> Result<(), io::Error>;
}

impl Config {
pub fn new(name: String) -> Self {
    Self { name, value: 0 }
}
}

fn helper_function(x: i32) -> i32 {
x + 1
}
"#;

const TYPESCRIPT_CODE: &str = r#"
interface QuoteProvider {
fetchQuote(amount: number): Promise<number>;
}

class ApiServer {
handleRequest(req: string): void {
    console.log(req);
}
}

function standaloneHelper(x: number): number {
return x + 1;
}
"#;

const JAVASCRIPT_CODE: &str = r#"
class Dashboard {
render() {
    return "ok";
}
}

function formatLabel(value) {
return String(value);
}
"#;

const PYTHON_CODE: &str = r#"
class MyClass:
def __init__(self, name):
    self.name = name

def greet(self):
    return f"Hello, {self.name}"

def standalone_function(x):
return x + 1
"#;

const GO_CODE: &str = r#"
package main

func main() {
fmt.Println("hello")
}

func helper(x int) int {
return x + 1
}

type Config struct {
Name string
Value int
}
"#;

const JAVA_CODE: &str = r#"
interface Processor {
void process();
}

class Service implements Processor {
public void process() {
System.out.println("ok");
}
}
"#;

const C_CODE: &str = r#"
struct Request {
int value;
};

int calculate(int value) {
return value + 1;
}
"#;

const CPP_CODE: &str = r#"
struct Worker {
int value;
};

int execute(int value) {
return value * 2;
}
"#;

#[test]
fn extracts_rust_signatures() {
    let sigs = extract_signatures(Path::new("test.rs"), RUST_CODE, "rust").unwrap();
    let names: Vec<&str> = sigs.iter().map(|s| s.name.as_str()).collect();

    assert!(names.contains(&"Config"));
    assert!(names.contains(&"Status"));
    assert!(names.contains(&"Processor"));
    assert!(names.contains(&"helper_function"));
}

#[test]
fn classifies_rust_node_kinds() {
    let sigs = extract_signatures(Path::new("test.rs"), RUST_CODE, "rust").unwrap();

    let config = sigs
        .iter()
        .find(|s| s.name == "Config" && s.kind == SignatureKind::Struct);
    assert!(config.is_some());

    let status = sigs
        .iter()
        .find(|s| s.name == "Status" && s.kind == SignatureKind::Enum);
    assert!(status.is_some());

    let processor = sigs
        .iter()
        .find(|s| s.name == "Processor" && s.kind == SignatureKind::Trait);
    assert!(processor.is_some());

    let implementation = sigs
        .iter()
        .find(|s| s.name == "Config" && s.kind == SignatureKind::Impl);
    assert!(implementation.is_some());
}

const SUPPORTED_LANGUAGES: &[(&str, bool)] = &[
    ("rust", true),
    ("python", true),
    ("javascript", true),
    ("typescript", true),
    ("tsx", true),
    ("go", true),
    ("java", true),
    ("c", true),
    ("cpp", true),
    ("bash", true),
    ("hcl", true),
    ("yaml", false),
    ("json", false),
];

#[test]
fn every_supported_language_resolves_a_grammar_and_a_compiling_query() {
    for (name, extracts_signatures) in SUPPORTED_LANGUAGES {
        let grammar = language_for_name(name).unwrap_or_else(|| panic!("no grammar for {name}"));
        let query_source = signature_query_for_language(name);

        assert_eq!(
            !query_source.is_empty(),
            *extracts_signatures,
            "unexpected query presence for {name}"
        );
        if *extracts_signatures {
            assert!(
                Query::new(&grammar, query_source).is_ok(),
                "signature query does not compile for {name}"
            );
        }
    }
}

#[test]
fn languages_without_a_signature_query_parse_into_an_empty_list() {
    let yaml = extract_signatures(Path::new("ci.yaml"), YAML_CODE, "yaml").unwrap();
    let json = extract_signatures(Path::new("package.json"), JSON_CODE, "json").unwrap();

    assert!(yaml.is_empty());
    assert!(json.is_empty());
}

#[test]
fn extracts_typescript_signatures() {
    let sigs = extract_signatures(Path::new("test.ts"), TYPESCRIPT_CODE, "typescript").unwrap();
    let names: Vec<&str> = sigs.iter().map(|s| s.name.as_str()).collect();

    assert!(names.contains(&"ApiServer"));
    assert!(names.contains(&"QuoteProvider"));
    assert!(names.contains(&"handleRequest"));
    assert!(names.contains(&"standaloneHelper"));

    let class = sigs.iter().find(|s| s.name == "ApiServer").unwrap();
    assert_eq!(class.kind, SignatureKind::Class);
    let interface = sigs.iter().find(|s| s.name == "QuoteProvider").unwrap();
    assert_eq!(interface.kind, SignatureKind::Interface);
    let method = sigs.iter().find(|s| s.name == "handleRequest").unwrap();
    assert_eq!(method.kind, SignatureKind::Method);
}

#[test]
fn extracts_tsx_signatures_with_typescript_grammar_shapes() {
    let sigs = extract_signatures(Path::new("test.tsx"), TYPESCRIPT_CODE, "tsx").unwrap();
    assert!(sigs.iter().any(|s| s.name == "ApiServer"));
}

#[test]
fn extracts_javascript_signatures() {
    let sigs = extract_signatures(Path::new("test.js"), JAVASCRIPT_CODE, "javascript").unwrap();
    let names: Vec<&str> = sigs.iter().map(|s| s.name.as_str()).collect();

    assert!(names.contains(&"Dashboard"));
    assert!(names.contains(&"render"));
    assert!(names.contains(&"formatLabel"));
}

#[test]
fn extracts_python_signatures() {
    let sigs = extract_signatures(Path::new("test.py"), PYTHON_CODE, "python").unwrap();
    let names: Vec<&str> = sigs.iter().map(|s| s.name.as_str()).collect();

    assert!(names.contains(&"MyClass"));
    assert!(names.contains(&"standalone_function"));
}

#[test]
fn extracts_go_signatures() {
    let sigs = extract_signatures(Path::new("test.go"), GO_CODE, "go").unwrap();
    let names: Vec<&str> = sigs.iter().map(|s| s.name.as_str()).collect();

    assert!(names.contains(&"main"));
    assert!(names.contains(&"helper"));

    let config = sigs
        .iter()
        .find(|s| s.name == "Config" && s.kind == SignatureKind::Struct);
    assert!(config.is_some());
}

#[test]
fn extracts_java_signatures() {
    let signatures = extract_signatures(Path::new("Service.java"), JAVA_CODE, "java").unwrap();

    assert!(signatures.iter().any(|signature| {
        signature.name == "Processor" && signature.kind == SignatureKind::Interface
    }));
    assert!(signatures.iter().any(|signature| {
        signature.name == "Service" && signature.kind == SignatureKind::Class
    }));
    assert!(signatures.iter().any(|signature| {
        signature.name == "process" && signature.kind == SignatureKind::Method
    }));
}

#[test]
fn extracts_c_signatures() {
    let signatures = extract_signatures(Path::new("request.c"), C_CODE, "c").unwrap();

    assert!(signatures.iter().any(|signature| {
        signature.name == "Request" && signature.kind == SignatureKind::Struct
    }));
    assert!(signatures.iter().any(|signature| {
        signature.name == "calculate" && signature.kind == SignatureKind::Function
    }));
}

#[test]
fn extracts_cpp_signatures() {
    let signatures = extract_signatures(Path::new("worker.cpp"), CPP_CODE, "cpp").unwrap();

    assert!(signatures.iter().any(|signature| {
        signature.name == "Worker" && signature.kind == SignatureKind::Struct
    }));
    assert!(signatures.iter().any(|signature| {
        signature.name == "execute" && signature.kind == SignatureKind::Function
    }));
}

#[test]
fn returns_error_for_unsupported_language() {
    let result = extract_signatures(Path::new("test.xyz"), "code", "unknown_lang");
    assert!(matches!(
        result,
        Err(EngineError::UnsupportedLanguage { .. })
    ));
}

#[test]
fn signatures_have_line_numbers() {
    let sigs = extract_signatures(Path::new("test.rs"), RUST_CODE, "rust").unwrap();
    for sig in &sigs {
        assert!(sig.line_start > 0);
        assert!(sig.line_end >= sig.line_start);
    }
}

#[test]
fn ast_search_finds_rust_functions() {
    let query = "(function_item name: (identifier) @name) @def";
    let matches = search_ast(Path::new("test.rs"), RUST_CODE, "rust", query, usize::MAX).unwrap();

    assert!(!matches.is_empty());
    assert!(
        matches
            .iter()
            .any(|m| m.matched_code.contains("helper_function"))
    );
}

#[test]
fn ast_search_stops_at_the_requested_result_limit() {
    let query = "(function_item name: (identifier) @name) @def";
    let matches = search_ast(Path::new("test.rs"), RUST_CODE, "rust", query, 1).unwrap();

    assert_eq!(matches.len(), 1);
}

#[test]
fn ast_search_returns_error_for_bad_query() {
    let result = search_ast(
        Path::new("test.rs"),
        RUST_CODE,
        "rust",
        "(not_a_real_node)",
        usize::MAX,
    );
    assert!(matches!(result, Err(EngineError::ParseFailed { .. })));
}

#[test]
fn handles_empty_file() {
    let sigs = extract_signatures(Path::new("empty.rs"), "", "rust").unwrap();
    assert!(sigs.is_empty());
}

#[test]
fn an_unsupported_language_has_neither_grammar_nor_query() {
    assert!(language_for_name("brainfuck").is_none());
    assert!(signature_query_for_language("brainfuck").is_empty());
    assert!(matches!(
        extract_signatures(Path::new("prog.bf"), "++>", "brainfuck"),
        Err(EngineError::UnsupportedLanguage { .. })
    ));
}

const BASH_CODE: &str = r#"#!/usr/bin/env bash

foo() {
  echo "hello"
}

function bar {
  echo "world"
}
"#;

const HCL_CODE: &str = r#"
resource "aws_s3_bucket" "assets" {
  bucket = "my-assets"
}

variable "region" {
  default = "eu-west-1"
}
"#;

const YAML_CODE: &str = r#"
name: build
steps:
  - run: cargo test
  - run: cargo clippy
"#;

const JSON_CODE: &str = r#"{
  "name": "bughunter",
  "version": "0.1.0"
}
"#;

#[test]
fn extracts_bash_function_signatures() {
    let sigs = extract_signatures(Path::new("run.sh"), BASH_CODE, "bash").unwrap();
    let foo = sigs.iter().find(|s| s.name == "foo").unwrap();
    assert_eq!(foo.kind, SignatureKind::Function);
    assert!(sigs.iter().any(|s| s.name == "bar"));
}

#[test]
fn extracts_hcl_block_signatures() {
    let sigs = extract_signatures(Path::new("main.tf"), HCL_CODE, "hcl").unwrap();
    assert!(!sigs.is_empty());
    let resource = sigs.iter().find(|s| s.name == "resource").unwrap();
    assert_eq!(resource.kind, SignatureKind::Struct);
    assert!(sigs.iter().any(|s| s.name == "variable"));
}

#[test]
fn parser_setup_and_missing_tree_errors_retain_the_source_path() {
    let path = Path::new("source.rs");
    let setup = map_parser_setup(path, "rust", false, usize::MAX).unwrap_err();
    assert!(matches!(
        setup,
        EngineError::ParseFailed { path: error_path, reason }
            if error_path == path && reason.contains("incompatible grammar")
    ));

    let missing = require_parse_tree(path, None).unwrap_err();
    assert!(matches!(
        missing,
        EngineError::ParseFailed { path: error_path, reason }
            if error_path == path && reason.contains("returned None")
    ));
}

#[test]
fn capture_names_must_be_present_and_non_empty() {
    assert_eq!(non_empty_capture_text(None), None);
    assert_eq!(non_empty_capture_text(Some("")), None);
    assert_eq!(non_empty_capture_text(Some("name")), Some("name"));
}

#[test]
fn signature_matches_without_the_requested_name_are_skipped() {
    let source = "fn present() {}\n";
    let language: tree_sitter::Language = tree_sitter_rust::LANGUAGE.into();
    let (_, tree) = parse_source(Path::new("source.rs"), source, "rust").unwrap();
    let query = Query::new(&language, "(function_item) @def").unwrap();
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), source.as_bytes());
    let query_match = matches.next().unwrap();

    assert!(
        signature_candidate(query_match, usize::MAX, source.as_bytes(), source, "rust").is_none()
    );
}

struct CountingSignatureSink {
    accepted: usize,
}

impl SignatureCandidateSink for CountingSignatureSink {
    fn accept(&mut self, _candidate: SignatureCandidate<'_>) -> Result<bool, EngineError> {
        self.accepted += 1;
        Ok(true)
    }
}

#[test]
fn signature_collection_skips_matches_without_a_name_capture() {
    let source = "fn present() {}\n";
    let language: tree_sitter::Language = tree_sitter_rust::LANGUAGE.into();
    let (_, tree) = parse_source(Path::new("source.rs"), source, "rust").unwrap();
    let query = Query::new(
        &language,
        "(function_item name: (identifier) @name) @def\n(function_item) @def",
    )
    .unwrap();
    let mut sink = CountingSignatureSink { accepted: 0 };

    let complete = visit_signature_candidates(source, "rust", &tree, &query, &mut sink).unwrap();

    assert!(complete);
    assert_eq!(sink.accepted, 1);
}

#[test]
fn ast_collection_skips_query_matches_without_captures() {
    let source = "fn present() {}\n";
    let path = Path::new("source.rs");
    let language: tree_sitter::Language = tree_sitter_rust::LANGUAGE.into();
    let (_, tree) = parse_source(path, source, "rust").unwrap();
    let query = Query::new(&language, "(function_item)").unwrap();

    let matches =
        collect_ast_matches(path, source, "rust", &tree, &query, generous_match_limits()).unwrap();

    assert!(matches.is_empty());
}

#[test]
fn unknown_signature_nodes_use_the_function_fallback() {
    assert_eq!(
        classify_node("unknown_node", "unknown_language"),
        SignatureKind::Function
    );
}

const ANY_FUNCTION_QUERY: &str = "(function_item) @def";

fn signature_limits(max_count: usize, max_retained_bytes: usize) -> SignatureLimits {
    SignatureLimits {
        max_count,
        max_retained_bytes,
    }
}

fn match_limits(
    max_results: usize,
    max_result_bytes: usize,
    max_total_bytes: usize,
) -> MatchLimits {
    MatchLimits {
        max_results,
        max_result_bytes,
        max_total_bytes,
    }
}

fn generous_match_limits() -> MatchLimits {
    match_limits(
        usize::MAX,
        MAX_MATCHED_CODE_BYTES,
        MAX_MATCHED_CODE_TOTAL_BYTES,
    )
}

fn collect_rust_signatures(
    content: &str,
    limits: SignatureLimits,
) -> Result<Vec<Signature>, EngineError> {
    let path = Path::new("bounded.rs");
    let (language, tree) = parse_source(path, content, "rust").unwrap();
    let query = build_query(path, &language, signature_query_for_language("rust")).unwrap();
    collect_signatures(content, "rust", &tree, &query, limits)
}

fn collect_rust_matches(content: &str, limits: MatchLimits) -> Result<Vec<AstMatch>, EngineError> {
    let path = Path::new("bounded.rs");
    let (language, tree) = parse_source(path, content, "rust").unwrap();
    let query = build_query(path, &language, ANY_FUNCTION_QUERY).unwrap();
    collect_ast_matches(path, content, "rust", &tree, &query, limits)
}

fn rust_functions(count: usize) -> String {
    (0..count)
        .map(|index| format!("fn f{index}() {{}}\n"))
        .collect()
}

fn rust_function_with_first_line_bytes(bytes: usize) -> String {
    let prefix = "fn padded(unused_";
    let suffix = ": i32) {}";
    let padding = bytes - prefix.len() - suffix.len();
    format!("{prefix}{}{suffix}\n", "x".repeat(padding))
}

fn rust_function_of_bytes(name: &str, bytes: usize) -> String {
    let head = format!("fn {name}() {{\n    let _padding = \"");
    let tail = "\";\n}";
    let padding = bytes - head.len() - tail.len();
    format!("{head}{}{tail}", "x".repeat(padding))
}

#[test]
fn the_ast_limits_are_the_named_hard_limits_of_the_tool_contract() {
    assert_eq!(MAX_AST_QUERY_BYTES, 16 * 1024);
    assert_eq!(MAX_SIGNATURES, 10_000);
    assert_eq!(MAX_SIGNATURE_RETAINED_BYTES, 8 * 1024 * 1024);
    assert_eq!(MAX_SIGNATURE_TEXT_BYTES, 4 * 1024);
    assert_eq!(MAX_MATCHED_CODE_BYTES, 64 * 1024);
    assert_eq!(MAX_MATCHED_CODE_TOTAL_BYTES, 2 * 1024 * 1024);

    assert_eq!(DEFAULT_SIGNATURE_LIMITS.max_count, MAX_SIGNATURES);
    assert_eq!(
        DEFAULT_SIGNATURE_LIMITS.max_retained_bytes,
        MAX_SIGNATURE_RETAINED_BYTES
    );

    let limits = MatchLimits::for_results(7);
    assert_eq!(limits.max_results, 7);
    assert_eq!(limits.max_result_bytes, MAX_MATCHED_CODE_BYTES);
    assert_eq!(limits.max_total_bytes, MAX_MATCHED_CODE_TOTAL_BYTES);
}

#[test]
fn accumulator_preallocation_stays_bounded_for_unbounded_requests() {
    let signatures = BoundedSignatures::new(signature_limits(usize::MAX, usize::MAX));
    assert!(signatures.values.capacity() <= MATERIALIZATION_PREALLOCATION);

    let path = Path::new("prealloc.rs");
    let unbounded = BoundedAstMatches::new(MatchLimits::for_results(usize::MAX), path, "rust");
    assert!(unbounded.values.capacity() <= MATERIALIZATION_PREALLOCATION);

    let small = BoundedAstMatches::new(MatchLimits::for_results(2), path, "rust");
    assert!(small.values.capacity() <= 2);
}

#[test]
fn line_numbers_are_one_based_and_saturate_at_the_u32_ceiling() {
    assert_eq!(line_number(0), 1);
    assert_eq!(line_number(41), 42);
    assert_eq!(line_number(usize::from(u16::MAX)), 65_536);
    assert_eq!(line_number(u32::MAX as usize - 1), MAX_LINE_NUMBER);
    assert_eq!(line_number(u32::MAX as usize), MAX_LINE_NUMBER);
    assert_eq!(line_number(usize::MAX), MAX_LINE_NUMBER);
}

#[test]
fn char_boundary_flooring_never_splits_a_multibyte_character() {
    let text = "aé✓";
    assert_eq!(text.len(), 6);

    assert_eq!(floor_char_boundary(text, 0), 0);
    assert_eq!(floor_char_boundary(text, 1), 1);
    assert_eq!(floor_char_boundary(text, 2), 1);
    assert_eq!(floor_char_boundary(text, 3), 3);
    assert_eq!(floor_char_boundary(text, 4), 3);
    assert_eq!(floor_char_boundary(text, 5), 3);
    assert_eq!(floor_char_boundary(text, 6), 6);
    assert_eq!(floor_char_boundary(text, usize::MAX), 6);
    assert_eq!(floor_char_boundary("", usize::MAX), 0);
}

#[test]
fn first_line_slicing_is_utf8_safe_and_clamped() {
    let content = "// héllo wörld\nfn ünicode() {}\n";
    let inside_multibyte = content.find('é').unwrap() + 1;
    assert!(!content.is_char_boundary(inside_multibyte));

    assert_eq!(first_line_at(content, 0), "// héllo wörld");
    assert_eq!(first_line_at(content, 3), "// héllo wörld");
    assert_eq!(first_line_at(content, inside_multibyte), "// héllo wörld");
    assert_eq!(
        first_line_at(content, content.find("fn ünicode").unwrap()),
        "fn ünicode() {}"
    );
    assert!(first_line_at(content, content.len()).is_empty());
    assert!(first_line_at(content, usize::MAX).is_empty());
    assert!(first_line_at("", 0).is_empty());
    assert_eq!(first_line_at("fn crlf() {}\r\nnext\r\n", 0), "fn crlf() {}");
}

#[test]
fn each_repository_signature_text_is_sliced_from_its_own_start_byte() {
    let source = "fn first() {\n    let value = 1;\n}\n\nstruct Second {\n    field: i32,\n}\n";
    let batch = extract_signatures_with_budget(
        Path::new("multi.rs"),
        source,
        "rust",
        MAX_SIGNATURE_RETAINED_BYTES,
    )
    .unwrap();
    let texts: Vec<&str> = batch
        .signatures
        .iter()
        .map(|signature| signature.text.as_str())
        .collect();
    assert_eq!(texts, ["fn first() {", "struct Second {"]);

    let signatures = extract_signatures(Path::new("multi.rs"), source, "rust").unwrap();
    let first = signatures
        .iter()
        .find(|signature| signature.name == "first")
        .unwrap();
    let second = signatures
        .iter()
        .find(|signature| signature.name == "Second")
        .unwrap();
    assert_eq!((first.line_start, first.line_end), (1, 3));
    assert_eq!((second.line_start, second.line_end), (5, 7));
}

#[test]
fn multibyte_content_before_a_node_keeps_repository_text_and_line_span_intact() {
    let source = "// wörld ✓\nfn after_multibyte() {\n    let value = \"héllo\";\n}\n";
    let batch = extract_signatures_with_budget(
        Path::new("utf8.rs"),
        source,
        "rust",
        MAX_SIGNATURE_RETAINED_BYTES,
    )
    .unwrap();
    assert_eq!(batch.signatures[0].text, "fn after_multibyte() {");

    let signatures = extract_signatures(Path::new("utf8.rs"), source, "rust").unwrap();
    let signature = signatures
        .iter()
        .find(|signature| signature.name == "after_multibyte")
        .unwrap();
    assert_eq!((signature.line_start, signature.line_end), (2, 4));
}

#[test]
fn a_repository_signature_line_at_the_byte_limit_is_retained_whole() {
    let source = rust_function_with_first_line_bytes(MAX_SIGNATURE_TEXT_BYTES);
    let batch = extract_signatures_with_budget(
        Path::new("exact.rs"),
        &source,
        "rust",
        MAX_SIGNATURE_RETAINED_BYTES,
    )
    .unwrap();
    let padded = &batch.signatures[0].text;

    assert_eq!(padded.len(), MAX_SIGNATURE_TEXT_BYTES);
    assert!(!padded.contains(SIGNATURE_TEXT_TRUNCATION_MARKER));
}

#[test]
fn a_repository_signature_past_the_byte_limit_is_truncated_on_a_char_boundary() {
    let source = format!(
        "fn wide() {{ let _padding = \"{}\"; }}\n",
        "✓".repeat(MAX_SIGNATURE_TEXT_BYTES)
    );
    let batch = extract_signatures_with_budget(
        Path::new("wide.rs"),
        &source,
        "rust",
        MAX_SIGNATURE_RETAINED_BYTES,
    )
    .unwrap();
    let wide = &batch.signatures[0].text;
    assert!(wide.len() <= MAX_SIGNATURE_TEXT_BYTES);
    assert!(wide.ends_with(SIGNATURE_TEXT_TRUNCATION_MARKER));

    let head = wide.strip_suffix(SIGNATURE_TEXT_TRUNCATION_MARKER).unwrap();
    assert!(head.len() >= MAX_SIGNATURE_TEXT_HEAD_BYTES - 2);
    assert!(source.starts_with(head));
}

#[test]
fn static_signature_budget_counts_only_materialized_names() {
    let source = format!(
        "fn wide() {{ let _padding = \"{}\"; }}\n",
        "✓".repeat(MAX_SIGNATURE_TEXT_BYTES)
    );
    let retained_name_bytes = "wide".len();

    let signatures = collect_rust_signatures(
        &source,
        signature_limits(MAX_SIGNATURES, retained_name_bytes),
    )
    .unwrap();
    assert_eq!(signatures.len(), 1);

    let rejected = collect_rust_signatures(
        &source,
        signature_limits(MAX_SIGNATURES, retained_name_bytes - 1),
    )
    .unwrap_err();
    assert!(matches!(
        rejected,
        EngineError::AstLimitExceeded { resource, limit }
            if resource == SIGNATURE_BYTES_RESOURCE && limit == retained_name_bytes - 1
    ));
}

#[test]
fn the_signature_count_limit_admits_the_limit_and_rejects_one_more() {
    let source = rust_functions(8);

    let exact = collect_rust_signatures(&source, signature_limits(8, MAX_SIGNATURE_RETAINED_BYTES))
        .unwrap();
    assert_eq!(exact.len(), 8);

    let rejected =
        collect_rust_signatures(&source, signature_limits(7, MAX_SIGNATURE_RETAINED_BYTES))
            .unwrap_err();
    assert!(matches!(
        rejected,
        EngineError::AstLimitExceeded { resource, limit }
            if resource == SIGNATURE_COUNT_RESOURCE && limit == 7
    ));
    assert_eq!(
        rejected.to_string(),
        "AST signature count limit of 7 exceeded"
    );
}

#[test]
fn the_signature_byte_limit_admits_the_limit_and_rejects_one_more() {
    let source = rust_functions(4);
    let signatures = collect_rust_signatures(
        &source,
        signature_limits(MAX_SIGNATURES, MAX_SIGNATURE_RETAINED_BYTES),
    )
    .unwrap();
    let charged: usize = signatures
        .iter()
        .map(|signature| signature.name.len())
        .sum();

    assert_eq!(
        collect_rust_signatures(&source, signature_limits(MAX_SIGNATURES, charged))
            .unwrap()
            .len(),
        4
    );

    let rejected = collect_rust_signatures(&source, signature_limits(MAX_SIGNATURES, charged - 1))
        .unwrap_err();
    assert!(matches!(
        rejected,
        EngineError::AstLimitExceeded { resource, limit }
            if resource == SIGNATURE_BYTES_RESOURCE && limit == charged - 1
    ));
}

#[test]
fn budgeted_signature_extraction_stops_before_materializing_the_next_signature() {
    let source = rust_functions(100);
    let unbounded = extract_signatures_with_budget(
        Path::new("bounded.rs"),
        &source,
        "rust",
        MAX_SIGNATURE_RETAINED_BYTES,
    )
    .unwrap();
    let budget = unbounded.signatures[0].text.len();

    let batch =
        extract_signatures_with_budget(Path::new("bounded.rs"), &source, "rust", budget).unwrap();
    let retained_bytes: usize = batch
        .signatures
        .iter()
        .map(|signature| signature.text.len())
        .sum();

    assert_eq!(batch.signatures.len(), 1);
    assert!(retained_bytes <= budget);
    assert!(!batch.complete);
}

#[test]
fn budgeted_signature_extraction_enforces_the_count_before_materializing_another_signature() {
    let source = rust_functions(2);
    let (language, tree) = parse_source(Path::new("bounded.rs"), &source, "rust").unwrap();
    let query = build_query(
        Path::new("bounded.rs"),
        &language,
        signature_query_for_language("rust"),
    )
    .unwrap();

    let batch = collect_signature_batch(
        &source,
        "rust",
        &tree,
        &query,
        SignatureLimits {
            max_count: 1,
            max_retained_bytes: usize::MAX,
        },
    )
    .unwrap();

    assert_eq!(batch.signatures.len(), 1);
    assert!(!batch.complete);
}

#[test]
fn budgeted_signature_extraction_accepts_languages_without_signature_queries() {
    for (path, source, language) in [
        ("config.yaml", "enabled: true\n", "yaml"),
        ("package.json", r#"{"enabled":true}"#, "json"),
    ] {
        let batch = extract_signatures_with_budget(Path::new(path), source, language, 64).unwrap();

        assert!(batch.signatures.is_empty());
        assert!(batch.complete);
    }
}
#[test]
fn the_query_source_limit_admits_the_limit_and_rejects_one_more() {
    let pattern = "(function_item name: (identifier) @name) @def";
    let exact = format!(
        "{}{pattern}",
        "\n".repeat(MAX_AST_QUERY_BYTES - pattern.len())
    );
    assert_eq!(exact.len(), MAX_AST_QUERY_BYTES);

    let matches = search_ast(Path::new("test.rs"), RUST_CODE, "rust", &exact, usize::MAX).unwrap();
    assert!(!matches.is_empty());

    let over = format!("{exact}\n");
    let rejected =
        search_ast(Path::new("test.rs"), RUST_CODE, "rust", &over, usize::MAX).unwrap_err();
    assert!(matches!(
        rejected,
        EngineError::AstLimitExceeded { resource, limit }
            if resource == QUERY_SOURCE_RESOURCE && limit == MAX_AST_QUERY_BYTES
    ));
}

#[test]
fn an_oversized_query_is_rejected_before_it_is_compiled() {
    let invalid_and_oversized = "(not_a_real_node)\n".repeat(2_000);
    assert!(invalid_and_oversized.len() > MAX_AST_QUERY_BYTES);

    let rejected = search_ast(
        Path::new("test.rs"),
        RUST_CODE,
        "rust",
        &invalid_and_oversized,
        usize::MAX,
    )
    .unwrap_err();

    assert!(
        matches!(
            rejected,
            EngineError::AstLimitExceeded { resource, .. } if resource == QUERY_SOURCE_RESOURCE
        ),
        "the byte limit must win over query compilation: {rejected}"
    );
}

#[test]
fn a_match_at_the_byte_limit_is_kept_and_one_byte_more_is_rejected() {
    let exact = rust_function_of_bytes("exact", MAX_MATCHED_CODE_BYTES);
    let matches = search_ast(
        Path::new("exact.rs"),
        &exact,
        "rust",
        ANY_FUNCTION_QUERY,
        usize::MAX,
    )
    .unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].matched_code.len(), MAX_MATCHED_CODE_BYTES);

    let over = rust_function_of_bytes("over", MAX_MATCHED_CODE_BYTES + 1);
    let rejected = search_ast(
        Path::new("over.rs"),
        &over,
        "rust",
        ANY_FUNCTION_QUERY,
        usize::MAX,
    )
    .unwrap_err();
    assert!(matches!(
        rejected,
        EngineError::AstLimitExceeded { resource, limit }
            if resource == MATCHED_CODE_RESOURCE && limit == MAX_MATCHED_CODE_BYTES
    ));
}

#[test]
fn overlapping_matches_are_charged_once_per_match() {
    let source = "fn outer() {\n    fn inner() {}\n}\n";
    let matches = collect_rust_matches(source, generous_match_limits()).unwrap();
    assert_eq!(matches.len(), 2);

    let charged: usize = matches.iter().map(|m| m.matched_code.len()).sum();
    assert!(
        charged > source.len(),
        "a nested match must be charged on top of its enclosing match"
    );

    assert!(
        collect_rust_matches(
            source,
            match_limits(usize::MAX, MAX_MATCHED_CODE_BYTES, charged)
        )
        .is_ok()
    );

    let rejected = collect_rust_matches(
        source,
        match_limits(usize::MAX, MAX_MATCHED_CODE_BYTES, charged - 1),
    )
    .unwrap_err();
    assert!(matches!(
        rejected,
        EngineError::AstLimitExceeded { resource, limit }
            if resource == MATCHED_CODE_TOTAL_RESOURCE && limit == charged - 1
    ));
}

#[test]
fn matched_code_is_charged_in_bytes_not_characters() {
    let source = "fn unicode_body() {\n    let value = \"héllo wörld ✓\";\n}\n";
    let matches = collect_rust_matches(source, generous_match_limits()).unwrap();
    let matched = &matches[0].matched_code;

    assert!(matched.contains("héllo wörld ✓"));
    assert!(matched.len() > matched.chars().count());

    assert!(
        collect_rust_matches(
            source,
            match_limits(usize::MAX, matched.len(), MAX_MATCHED_CODE_TOTAL_BYTES)
        )
        .is_ok()
    );

    let rejected = collect_rust_matches(
        source,
        match_limits(usize::MAX, matched.len() - 1, MAX_MATCHED_CODE_TOTAL_BYTES),
    )
    .unwrap_err();
    assert!(matches!(
        rejected,
        EngineError::AstLimitExceeded { resource, .. } if resource == MATCHED_CODE_RESOURCE
    ));
}

#[test]
fn the_aggregate_match_budget_admits_the_limit_and_rejects_one_more() {
    let unit = rust_function_of_bytes("padded", MAX_MATCHED_CODE_BYTES);
    let within_budget = MAX_MATCHED_CODE_TOTAL_BYTES / MAX_MATCHED_CODE_BYTES;
    let source: String = (0..=within_budget).map(|_| format!("{unit}\n")).collect();

    let matches = search_ast(
        Path::new("flood.rs"),
        &source,
        "rust",
        ANY_FUNCTION_QUERY,
        within_budget,
    )
    .unwrap();
    assert_eq!(matches.len(), within_budget);
    let charged: usize = matches.iter().map(|m| m.matched_code.len()).sum();
    assert_eq!(charged, MAX_MATCHED_CODE_TOTAL_BYTES);

    let rejected = search_ast(
        Path::new("flood.rs"),
        &source,
        "rust",
        ANY_FUNCTION_QUERY,
        usize::MAX,
    )
    .unwrap_err();
    assert!(matches!(
        rejected,
        EngineError::AstLimitExceeded { resource, limit }
            if resource == MATCHED_CODE_TOTAL_RESOURCE && limit == MAX_MATCHED_CODE_TOTAL_BYTES
    ));
}

#[test]
fn an_oversized_match_after_valid_ones_yields_no_partial_success() {
    let mut source = String::from("fn small_one() {}\nfn small_two() {}\n");
    source.push_str(&rust_function_of_bytes("huge", MAX_MATCHED_CODE_BYTES + 1));

    let rejected = search_ast(
        Path::new("mixed.rs"),
        &source,
        "rust",
        ANY_FUNCTION_QUERY,
        usize::MAX,
    )
    .unwrap_err();
    assert!(matches!(
        rejected,
        EngineError::AstLimitExceeded { resource, .. } if resource == MATCHED_CODE_RESOURCE
    ));

    let capped = search_ast(
        Path::new("mixed.rs"),
        &source,
        "rust",
        ANY_FUNCTION_QUERY,
        2,
    )
    .unwrap();
    assert_eq!(capped.len(), 2);
    assert_eq!(capped[0].matched_code, "fn small_one() {}");
    assert_eq!(capped[1].matched_code, "fn small_two() {}");

    let none = search_ast(
        Path::new("mixed.rs"),
        &source,
        "rust",
        ANY_FUNCTION_QUERY,
        0,
    )
    .unwrap();
    assert!(none.is_empty());
}

#[test]
fn ordinary_extraction_and_search_stay_within_the_default_limits() {
    let signatures = extract_signatures(Path::new("test.rs"), RUST_CODE, "rust").unwrap();
    assert!(signatures.len() < MAX_SIGNATURES);
    let charged: usize = signatures
        .iter()
        .map(|signature| signature.name.len())
        .sum();
    assert!(charged < MAX_SIGNATURE_RETAINED_BYTES);

    let batch = extract_signatures_with_budget(
        Path::new("test.rs"),
        RUST_CODE,
        "rust",
        MAX_SIGNATURE_RETAINED_BYTES,
    )
    .unwrap();
    assert!(
        batch
            .signatures
            .iter()
            .all(|signature| !signature.text.contains(SIGNATURE_TEXT_TRUNCATION_MARKER))
    );

    let matches = search_ast(
        Path::new("test.rs"),
        RUST_CODE,
        "rust",
        ANY_FUNCTION_QUERY,
        usize::MAX,
    )
    .unwrap();
    assert_eq!(matches.len(), 2);
    assert!(
        matches
            .iter()
            .all(|matched| matched.matched_code.len() < MAX_MATCHED_CODE_BYTES)
    );
    assert!(matches.iter().all(|matched| matched.language == "rust"));
    assert!(
        matches
            .iter()
            .all(|matched| matched.path == Path::new("test.rs")
                && matched.line_end >= matched.line_start)
    );
}
