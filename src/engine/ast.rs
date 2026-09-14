use std::path::{Path, PathBuf};

use streaming_iterator::StreamingIterator;
use tree_sitter::{Language, Parser, Query, QueryCursor};

use crate::cancel::CancelToken;
use crate::errors::EngineError;

pub const MAX_AST_QUERY_BYTES: usize = 16 * 1024;

const MAX_SIGNATURES: usize = 10_000;
const MAX_SIGNATURE_RETAINED_BYTES: usize = 8 * 1024 * 1024;
const MAX_SIGNATURE_TEXT_BYTES: usize = 4 * 1024;
const MAX_MATCHED_CODE_BYTES: usize = 64 * 1024;
const MAX_MATCHED_CODE_TOTAL_BYTES: usize = 2 * 1024 * 1024;
const MATERIALIZATION_PREALLOCATION: usize = 64;
const MAX_LINE_NUMBER: u32 = u32::MAX;

const SIGNATURE_TEXT_TRUNCATION_MARKER: &str = " ... (truncated)";
const MAX_SIGNATURE_TEXT_HEAD_BYTES: usize =
    MAX_SIGNATURE_TEXT_BYTES - SIGNATURE_TEXT_TRUNCATION_MARKER.len();

const QUERY_SOURCE_RESOURCE: &str = "query source byte";
const SIGNATURE_COUNT_RESOURCE: &str = "signature count";
const SIGNATURE_BYTES_RESOURCE: &str = "signature byte";
const MATCHED_CODE_RESOURCE: &str = "matched code byte";
const MATCHED_CODE_TOTAL_RESOURCE: &str = "aggregate matched code byte";

#[derive(Debug, Clone, serde::Serialize)]
pub struct AstMatch {
    pub path: PathBuf,
    pub line_start: u32,
    pub line_end: u32,
    pub matched_code: String,
    pub language: String,
}

#[derive(Debug, Clone)]
pub struct Signature {
    pub name: String,
    pub kind: SignatureKind,
    pub line_start: u32,
    pub line_end: u32,
}

pub(crate) struct RepoMapSignature {
    pub(crate) kind: SignatureKind,
    pub(crate) text: String,
}

pub(crate) struct SignatureBatch {
    pub(crate) signatures: Vec<RepoMapSignature>,
    pub(crate) complete: bool,
}

impl SignatureBatch {
    pub(crate) fn empty() -> Self {
        Self {
            signatures: Vec::new(),
            complete: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureKind {
    Function,
    Struct,
    Enum,
    Trait,
    Interface,
    Class,
    Method,
    Impl,
}

pub fn language_for_name(name: &str) -> Option<Language> {
    let lang_fn = match name {
        "rust" => Some(tree_sitter_rust::LANGUAGE),
        "python" => Some(tree_sitter_python::LANGUAGE),
        "javascript" => Some(tree_sitter_javascript::LANGUAGE),
        "typescript" => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT),
        "tsx" => Some(tree_sitter_typescript::LANGUAGE_TSX),
        "go" => Some(tree_sitter_go::LANGUAGE),
        "java" => Some(tree_sitter_java::LANGUAGE),
        "c" => Some(tree_sitter_c::LANGUAGE),
        "cpp" => Some(tree_sitter_cpp::LANGUAGE),
        "hcl" => Some(tree_sitter_hcl::LANGUAGE),
        "yaml" => Some(tree_sitter_yaml::LANGUAGE),
        "bash" => Some(tree_sitter_bash::LANGUAGE),
        "json" => Some(tree_sitter_json::LANGUAGE),
        _ => None,
    };
    lang_fn.map(|f| f.into())
}

pub fn extract_signatures(
    path: &Path,
    content: &str,
    language_name: &str,
) -> Result<Vec<Signature>, EngineError> {
    let (ts_language, tree) = parse_source(path, content, language_name)?;

    let query_source = signature_query_for_language(language_name);
    if query_source.is_empty() {
        return Ok(Vec::new());
    }

    let query = build_query(path, &ts_language, query_source)?;
    collect_signatures(
        content,
        language_name,
        &tree,
        &query,
        DEFAULT_SIGNATURE_LIMITS,
    )
}

pub(crate) fn extract_signatures_with_budget(
    path: &Path,
    content: &str,
    language_name: &str,
    max_retained_bytes: usize,
) -> Result<SignatureBatch, EngineError> {
    let (ts_language, tree) = parse_source(path, content, language_name)?;
    let query_source = signature_query_for_language(language_name);
    if query_source.is_empty() {
        return Ok(SignatureBatch::empty());
    }

    let query = build_query(path, &ts_language, query_source)?;
    collect_signature_batch(
        content,
        language_name,
        &tree,
        &query,
        SignatureLimits {
            max_count: MAX_SIGNATURES,
            max_retained_bytes: max_retained_bytes.min(MAX_SIGNATURE_RETAINED_BYTES),
        },
    )
}

fn parse_source(
    path: &Path,
    content: &str,
    language_name: &str,
) -> Result<(Language, tree_sitter::Tree), EngineError> {
    let ts_language =
        language_for_name(language_name).ok_or_else(|| EngineError::UnsupportedLanguage {
            language: language_name.into(),
        })?;

    let mut parser = Parser::new();
    let language_abi_version = ts_language.abi_version();
    let parser_ready = parser.set_language(&ts_language).is_ok();
    map_parser_setup(path, language_name, parser_ready, language_abi_version)?;

    let tree = require_parse_tree(path, parser.parse(content, None))?;

    Ok((ts_language, tree))
}

fn map_parser_setup(
    path: &Path,
    language_name: &str,
    parser_ready: bool,
    language_abi_version: usize,
) -> Result<(), EngineError> {
    if parser_ready {
        return Ok(());
    }
    Err(EngineError::ParseFailed {
        path: path.to_path_buf(),
        reason: format!(
            "failed to set language {language_name}: incompatible grammar ABI version {language_abi_version}"
        ),
    })
}

fn require_parse_tree(
    path: &Path,
    tree: Option<tree_sitter::Tree>,
) -> Result<tree_sitter::Tree, EngineError> {
    match tree {
        Some(tree) => Ok(tree),
        None => Err(EngineError::ParseFailed {
            path: path.to_path_buf(),
            reason: "tree-sitter parse returned None".into(),
        }),
    }
}

fn build_query(
    path: &Path,
    ts_language: &Language,
    query_source: &str,
) -> Result<Query, EngineError> {
    if query_source.len() > MAX_AST_QUERY_BYTES {
        return Err(EngineError::AstLimitExceeded {
            resource: QUERY_SOURCE_RESOURCE,
            limit: MAX_AST_QUERY_BYTES,
        });
    }

    match Query::new(ts_language, query_source) {
        Ok(query) => Ok(query),
        Err(error) => Err(EngineError::ParseFailed {
            path: path.to_path_buf(),
            reason: format!("invalid tree-sitter query: {error}"),
        }),
    }
}

fn line_number(row: usize) -> u32 {
    u32::try_from(row.saturating_add(1)).unwrap_or(MAX_LINE_NUMBER)
}

fn line_span(node: tree_sitter::Node<'_>) -> (u32, u32) {
    (
        line_number(node.start_position().row),
        line_number(node.end_position().row),
    )
}

fn floor_char_boundary(text: &str, index: usize) -> usize {
    let mut boundary = index.min(text.len());
    while boundary > 0 && !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    boundary
}

fn first_line_at(content: &str, start_byte: usize) -> &str {
    let scanned = &content[..floor_char_boundary(content, start_byte)];
    let line_start = scanned.rfind('\n').map_or(0, |index| index + 1);
    let remainder = &content[line_start..];
    let line_end = remainder.find('\n').unwrap_or(remainder.len());
    remainder[..line_end].trim()
}

struct SignatureText<'a> {
    head: &'a str,
    truncated: bool,
}

impl<'a> SignatureText<'a> {
    fn bounded_first_line(content: &'a str, start_byte: usize) -> Self {
        let line = first_line_at(content, start_byte);
        if line.len() <= MAX_SIGNATURE_TEXT_BYTES {
            return Self {
                head: line,
                truncated: false,
            };
        }

        Self {
            head: &line[..floor_char_boundary(line, MAX_SIGNATURE_TEXT_HEAD_BYTES)],
            truncated: true,
        }
    }

    fn retained_bytes(&self) -> usize {
        if self.truncated {
            self.head
                .len()
                .saturating_add(SIGNATURE_TEXT_TRUNCATION_MARKER.len())
        } else {
            self.head.len()
        }
    }

    fn materialize(&self) -> String {
        let mut text = String::with_capacity(self.retained_bytes());
        text.push_str(self.head);
        if self.truncated {
            text.push_str(SIGNATURE_TEXT_TRUNCATION_MARKER);
        }
        text
    }

    fn materialize_within(&self, max_bytes: usize) -> (String, bool) {
        if self.retained_bytes() <= max_bytes {
            return (self.materialize(), true);
        }

        let marker = if max_bytes >= SIGNATURE_TEXT_TRUNCATION_MARKER.len() {
            SIGNATURE_TEXT_TRUNCATION_MARKER
        } else {
            ""
        };
        let head_limit = max_bytes.saturating_sub(marker.len());
        let head = &self.head[..floor_char_boundary(self.head, head_limit)];
        let mut text = String::with_capacity(head.len().saturating_add(marker.len()));
        text.push_str(head);
        text.push_str(marker);
        (text, false)
    }
}

#[derive(Clone, Copy)]
struct SignatureLimits {
    max_count: usize,
    max_retained_bytes: usize,
}

const DEFAULT_SIGNATURE_LIMITS: SignatureLimits = SignatureLimits {
    max_count: MAX_SIGNATURES,
    max_retained_bytes: MAX_SIGNATURE_RETAINED_BYTES,
};

struct SignatureCandidate<'a> {
    name: &'a str,
    kind: SignatureKind,
    line_start: u32,
    line_end: u32,
    text: SignatureText<'a>,
}

impl SignatureCandidate<'_> {
    fn retained_signature_bytes(&self) -> usize {
        self.name.len()
    }

    fn materialize_signature(self) -> Signature {
        Signature {
            name: self.name.to_string(),
            kind: self.kind,
            line_start: self.line_start,
            line_end: self.line_end,
        }
    }
}

trait SignatureCandidateSink {
    fn accept(&mut self, candidate: SignatureCandidate<'_>) -> Result<bool, EngineError>;
}

struct BoundedSignatures {
    values: Vec<Signature>,
    limits: SignatureLimits,
    retained_bytes: usize,
}

impl BoundedSignatures {
    fn new(limits: SignatureLimits) -> Self {
        Self {
            values: Vec::with_capacity(limits.max_count.min(MATERIALIZATION_PREALLOCATION)),
            limits,
            retained_bytes: 0,
        }
    }

    fn push(&mut self, candidate: SignatureCandidate<'_>) -> Result<(), EngineError> {
        if self.values.len() >= self.limits.max_count {
            return Err(EngineError::AstLimitExceeded {
                resource: SIGNATURE_COUNT_RESOURCE,
                limit: self.limits.max_count,
            });
        }

        let projected = self
            .retained_bytes
            .saturating_add(candidate.retained_signature_bytes());
        if projected > self.limits.max_retained_bytes {
            return Err(EngineError::AstLimitExceeded {
                resource: SIGNATURE_BYTES_RESOURCE,
                limit: self.limits.max_retained_bytes,
            });
        }

        self.retained_bytes = projected;
        self.values.push(candidate.materialize_signature());
        Ok(())
    }

    fn into_vec(self) -> Vec<Signature> {
        self.values
    }
}

impl SignatureCandidateSink for BoundedSignatures {
    fn accept(&mut self, candidate: SignatureCandidate<'_>) -> Result<bool, EngineError> {
        self.push(candidate)?;
        Ok(true)
    }
}

enum RepoMapSignatureRetention {
    Retained,
    Truncated,
    Full,
}

struct BoundedRepoMapSignatures {
    values: Vec<RepoMapSignature>,
    limits: SignatureLimits,
    retained_bytes: usize,
}

impl BoundedRepoMapSignatures {
    fn new(limits: SignatureLimits) -> Self {
        Self {
            values: Vec::with_capacity(limits.max_count.min(MATERIALIZATION_PREALLOCATION)),
            limits,
            retained_bytes: 0,
        }
    }

    fn push(&mut self, candidate: SignatureCandidate<'_>) -> RepoMapSignatureRetention {
        if self.values.len() >= self.limits.max_count {
            return RepoMapSignatureRetention::Full;
        }

        let available = self
            .limits
            .max_retained_bytes
            .saturating_sub(self.retained_bytes);
        let (text, complete) = candidate.text.materialize_within(available);
        if !complete && text.is_empty() {
            return RepoMapSignatureRetention::Full;
        }

        self.retained_bytes = self.retained_bytes.saturating_add(text.len());
        self.values.push(RepoMapSignature {
            kind: candidate.kind,
            text,
        });
        if complete {
            RepoMapSignatureRetention::Retained
        } else {
            RepoMapSignatureRetention::Truncated
        }
    }

    fn into_vec(self) -> Vec<RepoMapSignature> {
        self.values
    }
}

impl SignatureCandidateSink for BoundedRepoMapSignatures {
    fn accept(&mut self, candidate: SignatureCandidate<'_>) -> Result<bool, EngineError> {
        Ok(matches!(
            self.push(candidate),
            RepoMapSignatureRetention::Retained
        ))
    }
}

fn name_capture_index(query: &Query) -> usize {
    query
        .capture_names()
        .iter()
        .position(|name| *name == "name")
        .unwrap_or(0)
}

fn collect_signatures(
    content: &str,
    language_name: &str,
    tree: &tree_sitter::Tree,
    query: &Query,
    limits: SignatureLimits,
) -> Result<Vec<Signature>, EngineError> {
    let mut signatures = BoundedSignatures::new(limits);
    visit_signature_candidates(content, language_name, tree, query, &mut signatures)?;
    Ok(signatures.into_vec())
}

fn collect_signature_batch(
    content: &str,
    language_name: &str,
    tree: &tree_sitter::Tree,
    query: &Query,
    limits: SignatureLimits,
) -> Result<SignatureBatch, EngineError> {
    let mut signatures = BoundedRepoMapSignatures::new(limits);
    let complete =
        visit_signature_candidates(content, language_name, tree, query, &mut signatures)?;

    Ok(SignatureBatch {
        signatures: signatures.into_vec(),
        complete,
    })
}

fn visit_signature_candidates(
    content: &str,
    language_name: &str,
    tree: &tree_sitter::Tree,
    query: &Query,
    sink: &mut dyn SignatureCandidateSink,
) -> Result<bool, EngineError> {
    let source_bytes = content.as_bytes();
    let mut cursor = QueryCursor::new();
    let name_index = name_capture_index(query);
    let mut query_matches = cursor.matches(query, tree.root_node(), source_bytes);

    while let Some(query_match) = query_matches.next() {
        let Some(candidate) = signature_candidate(
            query_match,
            name_index,
            source_bytes,
            content,
            language_name,
        ) else {
            continue;
        };
        if !sink.accept(candidate)? {
            return Ok(false);
        }
    }

    Ok(true)
}

fn signature_candidate<'a>(
    m: &tree_sitter::QueryMatch,
    name_index: usize,
    source_bytes: &'a [u8],
    content: &'a str,
    language_name: &str,
) -> Option<SignatureCandidate<'a>> {
    let full_capture = m.captures.first()?;
    let name_capture = m.captures.iter().find(|c| c.index as usize == name_index)?;

    let node = full_capture.node;
    let name = non_empty_capture_text(name_capture.node.utf8_text(source_bytes).ok())?;
    let (line_start, line_end) = line_span(node);

    Some(SignatureCandidate {
        name,
        kind: classify_node(node.kind(), language_name),
        line_start,
        line_end,
        text: SignatureText::bounded_first_line(content, node.start_byte()),
    })
}

fn non_empty_capture_text(text: Option<&str>) -> Option<&str> {
    text.filter(|text| !text.is_empty())
}

const RUST_SIGNATURE_QUERY: &str = r#"
    (function_item name: (identifier) @name) @def
    (struct_item name: (type_identifier) @name) @def
    (enum_item name: (type_identifier) @name) @def
    (trait_item name: (type_identifier) @name) @def
    (impl_item type: (type_identifier) @name) @def
"#;
const PYTHON_SIGNATURE_QUERY: &str = r#"
    (function_definition name: (identifier) @name) @def
    (class_definition name: (identifier) @name) @def
"#;
const JAVASCRIPT_SIGNATURE_QUERY: &str = r#"
    (function_declaration name: (identifier) @name) @def
    (class_declaration name: (identifier) @name) @def
    (method_definition name: (property_identifier) @name) @def
"#;
const TYPESCRIPT_SIGNATURE_QUERY: &str = r#"
    (function_declaration name: (identifier) @name) @def
    (class_declaration name: (type_identifier) @name) @def
    (interface_declaration name: (type_identifier) @name) @def
    (method_definition name: (property_identifier) @name) @def
"#;
const GO_SIGNATURE_QUERY: &str = r#"
    (function_declaration name: (identifier) @name) @def
    (method_declaration name: (field_identifier) @name) @def
    (type_declaration (type_spec name: (type_identifier) @name)) @def
"#;
const JAVA_SIGNATURE_QUERY: &str = r#"
    (class_declaration name: (identifier) @name) @def
    (interface_declaration name: (identifier) @name) @def
    (method_declaration name: (identifier) @name) @def
"#;
const C_SIGNATURE_QUERY: &str = r#"
    (function_definition declarator: (function_declarator declarator: (identifier) @name)) @def
    (struct_specifier name: (type_identifier) @name) @def
"#;

fn signature_query_for_language(language: &str) -> &'static str {
    match language {
        "rust" => RUST_SIGNATURE_QUERY,
        "python" => PYTHON_SIGNATURE_QUERY,
        "javascript" => JAVASCRIPT_SIGNATURE_QUERY,
        "typescript" | "tsx" => TYPESCRIPT_SIGNATURE_QUERY,
        "go" => GO_SIGNATURE_QUERY,
        "java" => JAVA_SIGNATURE_QUERY,
        "c" | "cpp" => C_SIGNATURE_QUERY,
        "bash" => "(function_definition name: (word) @name) @def",
        "hcl" => "(block (identifier) @name) @def",
        _ => "",
    }
}

fn classify_node(node_kind: &str, language: &str) -> SignatureKind {
    match (node_kind, language) {
        ("function_item", "rust") | ("function_definition", _) | ("function_declaration", _) => {
            SignatureKind::Function
        }
        ("method_declaration", _) | ("method_definition", _) => SignatureKind::Method,
        ("struct_item", "rust") | ("struct_specifier", _) => SignatureKind::Struct,
        ("enum_item", _) => SignatureKind::Enum,
        ("trait_item", _) => SignatureKind::Trait,
        ("interface_declaration", _) => SignatureKind::Interface,
        ("class_declaration", _) | ("class_definition", _) => SignatureKind::Class,
        ("impl_item", _) => SignatureKind::Impl,
        ("type_declaration", _) | ("type_spec", _) => SignatureKind::Struct,
        ("block", "hcl") => SignatureKind::Struct,
        _ => SignatureKind::Function,
    }
}

pub fn search_ast(
    path: &Path,
    content: &str,
    language_name: &str,
    query_source: &str,
    max_results: usize,
) -> Result<Vec<AstMatch>, EngineError> {
    search_ast_inner(
        path,
        content,
        language_name,
        query_source,
        max_results,
        None,
    )
}

pub fn search_ast_cancellable(
    path: &Path,
    content: &str,
    language_name: &str,
    query_source: &str,
    max_results: usize,
    cancel: &CancelToken,
) -> Result<Vec<AstMatch>, EngineError> {
    search_ast_inner(
        path,
        content,
        language_name,
        query_source,
        max_results,
        Some(cancel),
    )
}

fn search_ast_inner(
    path: &Path,
    content: &str,
    language_name: &str,
    query_source: &str,
    max_results: usize,
    cancel: Option<&CancelToken>,
) -> Result<Vec<AstMatch>, EngineError> {
    ensure_not_cancelled(cancel)?;
    let (ts_language, tree) = parse_source(path, content, language_name)?;
    ensure_not_cancelled(cancel)?;
    let query = build_query(path, &ts_language, query_source)?;

    collect_ast_matches_with_cancel(
        path,
        content,
        language_name,
        &tree,
        &query,
        MatchLimits::for_results(max_results),
        cancel,
    )
}

#[derive(Clone, Copy)]
struct MatchLimits {
    max_results: usize,
    max_result_bytes: usize,
    max_total_bytes: usize,
}

impl MatchLimits {
    fn for_results(max_results: usize) -> Self {
        Self {
            max_results,
            max_result_bytes: MAX_MATCHED_CODE_BYTES,
            max_total_bytes: MAX_MATCHED_CODE_TOTAL_BYTES,
        }
    }
}

struct MatchCandidate<'a> {
    line_start: u32,
    line_end: u32,
    matched_code: &'a str,
}

struct BoundedAstMatches<'a> {
    values: Vec<AstMatch>,
    limits: MatchLimits,
    matched_code_bytes: usize,
    path: &'a Path,
    language_name: &'a str,
}

impl<'a> BoundedAstMatches<'a> {
    fn new(limits: MatchLimits, path: &'a Path, language_name: &'a str) -> Self {
        Self {
            values: Vec::with_capacity(limits.max_results.min(MATERIALIZATION_PREALLOCATION)),
            limits,
            matched_code_bytes: 0,
            path,
            language_name,
        }
    }

    fn is_full(&self) -> bool {
        self.values.len() >= self.limits.max_results
    }

    fn push(&mut self, candidate: MatchCandidate<'_>) -> Result<(), EngineError> {
        let matched_bytes = candidate.matched_code.len();
        if matched_bytes > self.limits.max_result_bytes {
            return Err(EngineError::AstLimitExceeded {
                resource: MATCHED_CODE_RESOURCE,
                limit: self.limits.max_result_bytes,
            });
        }

        let projected = self.matched_code_bytes.saturating_add(matched_bytes);
        if projected > self.limits.max_total_bytes {
            return Err(EngineError::AstLimitExceeded {
                resource: MATCHED_CODE_TOTAL_RESOURCE,
                limit: self.limits.max_total_bytes,
            });
        }

        self.matched_code_bytes = projected;
        self.values.push(AstMatch {
            path: self.path.to_path_buf(),
            line_start: candidate.line_start,
            line_end: candidate.line_end,
            matched_code: candidate.matched_code.to_string(),
            language: self.language_name.to_string(),
        });
        Ok(())
    }

    fn into_vec(self) -> Vec<AstMatch> {
        self.values
    }
}

#[cfg(test)]
fn collect_ast_matches(
    path: &Path,
    content: &str,
    language_name: &str,
    tree: &tree_sitter::Tree,
    query: &Query,
    limits: MatchLimits,
) -> Result<Vec<AstMatch>, EngineError> {
    collect_ast_matches_with_cancel(path, content, language_name, tree, query, limits, None)
}

fn collect_ast_matches_with_cancel(
    path: &Path,
    content: &str,
    language_name: &str,
    tree: &tree_sitter::Tree,
    query: &Query,
    limits: MatchLimits,
    cancel: Option<&CancelToken>,
) -> Result<Vec<AstMatch>, EngineError> {
    let source_bytes = content.as_bytes();
    let mut cursor = QueryCursor::new();
    let mut matches = BoundedAstMatches::new(limits, path, language_name);

    let mut query_matches = cursor.matches(query, tree.root_node(), source_bytes);
    while let Some(m) = query_matches.next() {
        ensure_not_cancelled(cancel)?;
        if matches.is_full() {
            break;
        }
        let Some(candidate) = match_candidate(m, source_bytes) else {
            continue;
        };
        matches.push(candidate)?;
    }

    Ok(matches.into_vec())
}

fn ensure_not_cancelled(cancel: Option<&CancelToken>) -> Result<(), EngineError> {
    if cancel.is_some_and(CancelToken::is_cancelled) {
        return Err(EngineError::Cancelled);
    }
    Ok(())
}

fn match_candidate<'a>(
    m: &tree_sitter::QueryMatch,
    source_bytes: &'a [u8],
) -> Option<MatchCandidate<'a>> {
    let node = m.captures.first()?.node;
    let matched_code = node.utf8_text(source_bytes).ok()?;
    let (line_start, line_end) = line_span(node);

    Some(MatchCandidate {
        line_start,
        line_end,
        matched_code,
    })
}

#[cfg(test)]
#[path = "ast_tests.rs"]
mod tests;
