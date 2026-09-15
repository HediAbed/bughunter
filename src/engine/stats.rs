use std::collections::BTreeMap;

use crate::cancel::CancelToken;
use crate::config::EngineConfig;
use crate::errors::EngineError;

use super::filesystem::ProjectFilesystem;
use super::reader;
use super::walker::{self, DiscoverOpts, FileEntry};

pub const STATS_COUNTER_LIMIT: u64 = u64::MAX;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProjectStats {
    pub total_files: u64,
    pub total_lines: u64,
    pub total_code_lines: u64,
    pub total_comment_lines: u64,
    pub total_blank_lines: u64,
    pub languages: Vec<LanguageStats>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct LanguageStats {
    pub name: String,
    pub files: u64,
    pub code: u64,
    pub comments: u64,
    pub blanks: u64,
}

pub fn project_stats_with_capability(
    filesystem: &ProjectFilesystem,
    engine_config: &EngineConfig,
) -> Result<ProjectStats, EngineError> {
    let walk =
        walker::walk_project_with_capability(filesystem, engine_config, &DiscoverOpts::default())?;
    Ok(project_stats_for_entries(
        filesystem,
        engine_config,
        &walk.files,
    ))
}

pub fn project_stats_with_capability_cancellable(
    filesystem: &ProjectFilesystem,
    engine_config: &EngineConfig,
    cancel: &CancelToken,
) -> Result<ProjectStats, EngineError> {
    let walk = walker::walk_project_with_capability_cancellable(
        filesystem,
        engine_config,
        &DiscoverOpts::default(),
        cancel,
    )?;
    project_stats_for_entries_cancellable(filesystem, engine_config, &walk.files, cancel)
}

pub fn project_stats_for_entries(
    filesystem: &ProjectFilesystem,
    engine_config: &EngineConfig,
    files: &[FileEntry],
) -> ProjectStats {
    aggregate_stats(count_capability_lines_per_language(
        filesystem,
        engine_config,
        files,
    ))
}

pub fn project_stats_for_entries_cancellable(
    filesystem: &ProjectFilesystem,
    engine_config: &EngineConfig,
    files: &[FileEntry],
    cancel: &CancelToken,
) -> Result<ProjectStats, EngineError> {
    Ok(aggregate_stats(count_capability_lines_per_language_inner(
        filesystem,
        engine_config,
        files,
        Some(cancel),
    )?))
}

#[derive(Default)]
struct LineCounts {
    files: u64,
    code: u64,
    comments: u64,
    blanks: u64,
}

impl LineCounts {
    fn absorb_language(&mut self, language: &LanguageStats) {
        self.files = bounded_sum(self.files, language.files);
        self.code = bounded_sum(self.code, language.code);
        self.comments = bounded_sum(self.comments, language.comments);
        self.blanks = bounded_sum(self.blanks, language.blanks);
    }

    fn line_total(&self) -> u64 {
        bounded_sum(bounded_sum(self.code, self.comments), self.blanks)
    }
}

fn bounded_sum(left: u64, right: u64) -> u64 {
    left.checked_add(right).unwrap_or(STATS_COUNTER_LIMIT)
}

fn bounded_increment(counter: &mut u64) {
    *counter = bounded_sum(*counter, 1);
}

fn count_capability_lines_per_language<'a>(
    filesystem: &ProjectFilesystem,
    engine_config: &EngineConfig,
    files: &'a [FileEntry],
) -> BTreeMap<&'a str, LineCounts> {
    count_capability_lines_per_language_inner(filesystem, engine_config, files, None)
        .expect("an uncancelled statistics pass cannot be cancelled")
}

fn count_capability_lines_per_language_inner<'a>(
    filesystem: &ProjectFilesystem,
    engine_config: &EngineConfig,
    files: &'a [FileEntry],
    cancel: Option<&CancelToken>,
) -> Result<BTreeMap<&'a str, LineCounts>, EngineError> {
    let mut per_language: BTreeMap<&'a str, LineCounts> = BTreeMap::new();
    for entry in files {
        ensure_not_cancelled(cancel)?;
        let Some(language) = entry.language.as_deref() else {
            continue;
        };
        let Ok(project_path) = filesystem.project_path(&entry.path) else {
            continue;
        };
        let Ok(file) = reader::read_project_file(filesystem, &project_path, None, engine_config)
        else {
            continue;
        };
        let counts = per_language.entry(language).or_default();
        bounded_increment(&mut counts.files);
        add_line_counts_inner(&file.content, &comment_syntax(language), counts, cancel)?;
    }
    ensure_not_cancelled(cancel)?;
    Ok(per_language)
}

#[cfg(test)]
fn add_line_counts(content: &str, syntax: &CommentSyntax, counts: &mut LineCounts) {
    add_line_counts_inner(content, syntax, counts, None)
        .expect("an uncancelled line count cannot be cancelled");
}

fn add_line_counts_inner(
    content: &str,
    syntax: &CommentSyntax,
    counts: &mut LineCounts,
    cancel: Option<&CancelToken>,
) -> Result<(), EngineError> {
    let mut open_block: Option<BlockDelimiters> = None;

    for line in content.lines() {
        ensure_not_cancelled(cancel)?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            bounded_increment(&mut counts.blanks);
        } else if is_comment_line(trimmed, syntax, &mut open_block) {
            bounded_increment(&mut counts.comments);
        } else {
            bounded_increment(&mut counts.code);
        }
    }
    Ok(())
}

fn ensure_not_cancelled(cancel: Option<&CancelToken>) -> Result<(), EngineError> {
    if cancel.is_some_and(CancelToken::is_cancelled) {
        return Err(EngineError::Cancelled);
    }
    Ok(())
}

fn is_comment_line(
    line: &str,
    syntax: &CommentSyntax,
    open_block: &mut Option<BlockDelimiters>,
) -> bool {
    let mut rest = line;
    let mut has_code = false;

    while !rest.is_empty() {
        if let Some(block) = *open_block {
            match rest.find(block.close) {
                Some(index) => {
                    *open_block = None;
                    rest = rest[index + block.close.len()..].trim_start();
                }
                None => return !has_code,
            }
            continue;
        }

        if let Some(block) = syntax.block_at_start(rest) {
            *open_block = Some(block);
            rest = &rest[block.open.len()..];
            continue;
        }

        if syntax.starts_line_comment(rest) {
            return !has_code;
        }

        match syntax.next_marker_index(rest).filter(|index| *index > 0) {
            Some(index) => {
                has_code = true;
                rest = &rest[index..];
            }
            None => return false,
        }
    }

    !has_code
}

#[derive(Clone, Copy)]
struct BlockDelimiters {
    open: &'static str,
    close: &'static str,
}

impl BlockDelimiters {
    const fn new(open: &'static str, close: &'static str) -> Self {
        Self { open, close }
    }
}

#[derive(Clone, Copy)]
struct CommentSyntax {
    line_markers: &'static [&'static str],
    block_markers: &'static [BlockDelimiters],
}

impl CommentSyntax {
    const fn new(
        line_markers: &'static [&'static str],
        block_markers: &'static [BlockDelimiters],
    ) -> Self {
        Self {
            line_markers,
            block_markers,
        }
    }

    fn block_at_start(&self, text: &str) -> Option<BlockDelimiters> {
        self.block_markers
            .iter()
            .find(|block| text.starts_with(block.open))
            .copied()
    }

    fn starts_line_comment(&self, text: &str) -> bool {
        self.line_markers
            .iter()
            .any(|marker| text.starts_with(marker))
    }

    fn next_marker_index(&self, text: &str) -> Option<usize> {
        self.line_markers
            .iter()
            .copied()
            .chain(self.block_markers.iter().map(|block| block.open))
            .filter_map(|marker| text.find(marker))
            .min()
    }
}

const NO_BLOCKS: &[BlockDelimiters] = &[];
const SLASH_STAR_BLOCKS: &[BlockDelimiters] = &[BlockDelimiters::new("/*", "*/")];
const MARKUP_BLOCKS: &[BlockDelimiters] = &[BlockDelimiters::new("<!--", "-->")];
const PYTHON_BLOCKS: &[BlockDelimiters] = &[
    BlockDelimiters::new("\"\"\"", "\"\"\""),
    BlockDelimiters::new("'''", "'''"),
];
const RUBY_BLOCKS: &[BlockDelimiters] = &[BlockDelimiters::new("=begin", "=end")];
const LUA_BLOCKS: &[BlockDelimiters] = &[BlockDelimiters::new("--[[", "]]")];
const HASKELL_BLOCKS: &[BlockDelimiters] = &[BlockDelimiters::new("{-", "-}")];
const OCAML_BLOCKS: &[BlockDelimiters] = &[BlockDelimiters::new("(*", "*)")];
const WEB_COMPONENT_BLOCKS: &[BlockDelimiters] = &[
    BlockDelimiters::new("/*", "*/"),
    BlockDelimiters::new("<!--", "-->"),
];

const SLASH_MARKERS: &[&str] = &["//"];
const HASH_MARKERS: &[&str] = &["#"];
const HASH_SLASH_MARKERS: &[&str] = &["#", "//"];
const DASH_MARKERS: &[&str] = &["--"];
const PERCENT_MARKERS: &[&str] = &["%"];
const NO_MARKERS: &[&str] = &[];

const C_STYLE: CommentSyntax = CommentSyntax::new(SLASH_MARKERS, SLASH_STAR_BLOCKS);
const HASH_STYLE: CommentSyntax = CommentSyntax::new(HASH_MARKERS, NO_BLOCKS);
const HCL_STYLE: CommentSyntax = CommentSyntax::new(HASH_SLASH_MARKERS, SLASH_STAR_BLOCKS);
const PYTHON_STYLE: CommentSyntax = CommentSyntax::new(HASH_MARKERS, PYTHON_BLOCKS);
const RUBY_STYLE: CommentSyntax = CommentSyntax::new(HASH_MARKERS, RUBY_BLOCKS);
const SQL_STYLE: CommentSyntax = CommentSyntax::new(DASH_MARKERS, SLASH_STAR_BLOCKS);
const LUA_STYLE: CommentSyntax = CommentSyntax::new(DASH_MARKERS, LUA_BLOCKS);
const HASKELL_STYLE: CommentSyntax = CommentSyntax::new(DASH_MARKERS, HASKELL_BLOCKS);
const OCAML_STYLE: CommentSyntax = CommentSyntax::new(NO_MARKERS, OCAML_BLOCKS);
const ERLANG_STYLE: CommentSyntax = CommentSyntax::new(PERCENT_MARKERS, NO_BLOCKS);
const MARKUP_STYLE: CommentSyntax = CommentSyntax::new(NO_MARKERS, MARKUP_BLOCKS);
const WEB_STYLE: CommentSyntax = CommentSyntax::new(SLASH_MARKERS, WEB_COMPONENT_BLOCKS);
const NO_COMMENTS: CommentSyntax = CommentSyntax::new(NO_MARKERS, NO_BLOCKS);

struct LanguageProfile {
    id: &'static str,
    display_name: &'static str,
    syntax: CommentSyntax,
}

impl LanguageProfile {
    const fn new(id: &'static str, display_name: &'static str, syntax: CommentSyntax) -> Self {
        Self {
            id,
            display_name,
            syntax,
        }
    }
}

const LANGUAGE_PROFILES: &[LanguageProfile] = &[
    LanguageProfile::new("bash", "Shell", HASH_STYLE),
    LanguageProfile::new("c", "C", C_STYLE),
    LanguageProfile::new("cmake", "CMake", HASH_STYLE),
    LanguageProfile::new("cpp", "C++", C_STYLE),
    LanguageProfile::new("csharp", "C#", C_STYLE),
    LanguageProfile::new("css", "CSS", C_STYLE),
    LanguageProfile::new("dart", "Dart", C_STYLE),
    LanguageProfile::new("dockerfile", "Dockerfile", HASH_STYLE),
    LanguageProfile::new("elixir", "Elixir", HASH_STYLE),
    LanguageProfile::new("erlang", "Erlang", ERLANG_STYLE),
    LanguageProfile::new("go", "Go", C_STYLE),
    LanguageProfile::new("graphql", "GraphQL", HASH_STYLE),
    LanguageProfile::new("groovy", "Groovy", C_STYLE),
    LanguageProfile::new("haskell", "Haskell", HASKELL_STYLE),
    LanguageProfile::new("hcl", "HCL", HCL_STYLE),
    LanguageProfile::new("html", "HTML", MARKUP_STYLE),
    LanguageProfile::new("java", "Java", C_STYLE),
    LanguageProfile::new("javascript", "JavaScript", C_STYLE),
    LanguageProfile::new("json", "JSON", NO_COMMENTS),
    LanguageProfile::new("kotlin", "Kotlin", C_STYLE),
    LanguageProfile::new("lua", "Lua", LUA_STYLE),
    LanguageProfile::new("makefile", "Makefile", HASH_STYLE),
    LanguageProfile::new("markdown", "Markdown", MARKUP_STYLE),
    LanguageProfile::new("nim", "Nim", HASH_STYLE),
    LanguageProfile::new("ocaml", "OCaml", OCAML_STYLE),
    LanguageProfile::new("perl", "Perl", HASH_STYLE),
    LanguageProfile::new("php", "PHP", C_STYLE),
    LanguageProfile::new("protobuf", "Protocol Buffers", C_STYLE),
    LanguageProfile::new("python", "Python", PYTHON_STYLE),
    LanguageProfile::new("r", "R", HASH_STYLE),
    LanguageProfile::new("ruby", "Ruby", RUBY_STYLE),
    LanguageProfile::new("rust", "Rust", C_STYLE),
    LanguageProfile::new("scala", "Scala", C_STYLE),
    LanguageProfile::new("sql", "SQL", SQL_STYLE),
    LanguageProfile::new("svelte", "Svelte", WEB_STYLE),
    LanguageProfile::new("swift", "Swift", C_STYLE),
    LanguageProfile::new("toml", "TOML", HASH_STYLE),
    LanguageProfile::new("tsx", "TSX", C_STYLE),
    LanguageProfile::new("typescript", "TypeScript", C_STYLE),
    LanguageProfile::new("vue", "Vue", WEB_STYLE),
    LanguageProfile::new("xml", "XML", MARKUP_STYLE),
    LanguageProfile::new("yaml", "YAML", HASH_STYLE),
    LanguageProfile::new("zig", "Zig", C_STYLE),
];

fn profile_for(language: &str) -> Option<&'static LanguageProfile> {
    LANGUAGE_PROFILES
        .iter()
        .find(|profile| profile.id == language)
}

fn comment_syntax(language: &str) -> CommentSyntax {
    match profile_for(language) {
        Some(profile) => profile.syntax,
        None => NO_COMMENTS,
    }
}

fn display_name(language: &str) -> &str {
    match profile_for(language) {
        Some(profile) => profile.display_name,
        None => language,
    }
}

fn aggregate_stats(per_language: BTreeMap<&str, LineCounts>) -> ProjectStats {
    let mut languages: Vec<LanguageStats> = per_language
        .into_iter()
        .map(|(language, counts)| LanguageStats {
            name: display_name(language).to_string(),
            files: counts.files,
            code: counts.code,
            comments: counts.comments,
            blanks: counts.blanks,
        })
        .collect();

    languages.sort_by_key(|language| std::cmp::Reverse(language.code));

    let mut totals = LineCounts::default();
    for language in &languages {
        totals.absorb_language(language);
    }

    ProjectStats {
        total_files: totals.files,
        total_lines: totals.line_total(),
        total_code_lines: totals.code,
        total_comment_lines: totals.comments,
        total_blank_lines: totals.blanks,
        languages,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::domain::ProjectRoot;
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    fn project_stats(
        root: &Path,
        engine_config: &EngineConfig,
    ) -> Result<ProjectStats, EngineError> {
        let project_root = ProjectRoot::open(root).map_err(|error| EngineError::Io {
            path: root.to_path_buf(),
            source: std::io::Error::other(error),
        })?;
        let filesystem = ProjectFilesystem::open(project_root)?;
        project_stats_with_capability(&filesystem, engine_config)
    }

    fn default_config() -> EngineConfig {
        EngineConfig::default()
    }

    fn open_filesystem(root: &Path) -> ProjectFilesystem {
        ProjectFilesystem::open(ProjectRoot::open(root).unwrap()).unwrap()
    }

    fn entry(path: &Path, language: &str) -> FileEntry {
        FileEntry {
            relative_path: path.file_name().unwrap().to_string_lossy().into_owned(),
            size_bytes: fs::metadata(path)
                .map(|metadata| metadata.len())
                .unwrap_or_default(),
            path: path.to_path_buf(),
            language: Some(language.to_string()),
        }
    }

    #[test]
    fn counts_rust_project() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(
            src.join("main.rs"),
            "// A comment\nfn main() {\n    println!(\"hello\");\n}\n",
        )
        .unwrap();

        let stats = project_stats(dir.path(), &default_config()).unwrap();

        assert!(stats.total_files > 0);
        assert!(stats.total_code_lines > 0);
        assert!(stats.total_comment_lines > 0);
        assert!(!stats.languages.is_empty());
    }

    #[test]
    fn languages_sorted_by_code_lines_descending() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("small.py"), "x = 1\n").unwrap();
        fs::write(
            dir.path().join("big.rs"),
            "fn a() {}\nfn b() {}\nfn c() {}\nfn d() {}\nfn e() {}\n",
        )
        .unwrap();

        let stats = project_stats(dir.path(), &default_config()).unwrap();

        assert_eq!(stats.languages.len(), 2);
        assert_eq!(stats.languages[0].name, "Rust");
        assert_eq!(stats.languages[1].name, "Python");
    }

    #[test]
    fn handles_empty_directory() {
        let dir = TempDir::new().unwrap();

        let stats = project_stats(dir.path(), &default_config()).unwrap();

        assert_eq!(stats.total_files, 0);
        assert_eq!(stats.total_lines, 0);
    }

    #[test]
    fn entry_stats_match_the_plain_count_and_honour_cancellation() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("app.rs");
        fs::write(&file, "// note\nfn main() {}\n").unwrap();
        let filesystem = open_filesystem(dir.path());
        let config = default_config();
        let files = vec![entry(&file, "rust")];

        let plain = project_stats_for_entries(&filesystem, &config, &files);
        let live = project_stats_for_entries_cancellable(
            &filesystem,
            &config,
            &files,
            &CancelToken::default(),
        )
        .unwrap();

        assert_eq!(live.total_code_lines, plain.total_code_lines);
        assert_eq!(live.total_comment_lines, plain.total_comment_lines);
        assert_eq!(live.total_lines, plain.total_lines);

        let cancelled = CancelToken::default();
        cancelled.cancel();
        let error = project_stats_for_entries_cancellable(&filesystem, &config, &files, &cancelled)
            .unwrap_err();

        assert!(matches!(error, EngineError::Cancelled));
    }

    #[test]
    fn counts_code_comment_and_blank_lines() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("first.rs"),
            "// header\nfn main() {}\n\n/* block\n   still block */\nfn second() {}\n",
        )
        .unwrap();
        fs::write(dir.path().join("second.rs"), "fn third() {}\n\n// tail\n").unwrap();

        let stats = project_stats(dir.path(), &default_config()).unwrap();

        assert_eq!(stats.languages.len(), 1);
        assert_eq!(stats.languages[0].name, "Rust");
        assert_eq!(stats.languages[0].files, 2);
        assert_eq!(stats.languages[0].code, 3);
        assert_eq!(stats.languages[0].comments, 4);
        assert_eq!(stats.languages[0].blanks, 2);
        assert_eq!(stats.total_files, 2);
        assert_eq!(stats.total_code_lines, 3);
        assert_eq!(stats.total_comment_lines, 4);
        assert_eq!(stats.total_blank_lines, 2);
        assert_eq!(stats.total_lines, 9);
    }

    #[test]
    fn code_followed_by_a_comment_counts_as_code() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("app.rs"), "let x = 1; // note\n").unwrap();

        let stats = project_stats(dir.path(), &default_config()).unwrap();

        assert_eq!(stats.total_code_lines, 1);
        assert_eq!(stats.total_comment_lines, 0);
    }

    #[test]
    fn unterminated_block_keeps_following_lines_as_comments() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("app.rs"),
            "let x = 1; /* start\nstill inside\n*/ let y = 2;\n",
        )
        .unwrap();

        let stats = project_stats(dir.path(), &default_config()).unwrap();

        assert_eq!(stats.total_code_lines, 2);
        assert_eq!(stats.total_comment_lines, 1);
    }

    #[test]
    fn counts_python_docstrings_as_comments() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("app.py"),
            "\"\"\"module docs\nsecond line\n\"\"\"\nvalue = 1\n# note\n",
        )
        .unwrap();

        let stats = project_stats(dir.path(), &default_config()).unwrap();

        assert_eq!(stats.total_comment_lines, 4);
        assert_eq!(stats.total_code_lines, 1);
    }

    #[test]
    fn counts_every_non_blank_line_as_code_without_comment_syntax() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("data.json"), "{\n  \"a\": 1\n}\n").unwrap();

        let stats = project_stats(dir.path(), &default_config()).unwrap();

        assert_eq!(stats.languages[0].name, "JSON");
        assert_eq!(stats.total_code_lines, 3);
        assert_eq!(stats.total_comment_lines, 0);
    }

    #[test]
    fn skips_excluded_directories() {
        let dir = TempDir::new().unwrap();
        let vendored = dir.path().join("node_modules");
        fs::create_dir_all(&vendored).unwrap();
        fs::write(vendored.join("lib.js"), "const a = 1;\n").unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();

        let stats = project_stats(dir.path(), &default_config()).unwrap();

        assert_eq!(stats.total_files, 1);
        assert_eq!(stats.languages.len(), 1);
        assert_eq!(stats.languages[0].name, "Rust");
    }

    #[test]
    fn ignores_files_without_a_detected_language() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("notes.unknownext"), "plain text\n").unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();

        let stats = project_stats(dir.path(), &default_config()).unwrap();

        assert_eq!(stats.total_files, 1);
        assert_eq!(stats.languages.len(), 1);
    }

    #[test]
    fn skips_files_above_the_configured_size_limit() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("small.rs"), "fn main() {}\n").unwrap();
        fs::write(dir.path().join("big.rs"), "fn big() {}\n".repeat(100)).unwrap();
        let config = EngineConfig {
            max_file_size_bytes: 64,
            ..EngineConfig::default()
        };

        let stats = project_stats(dir.path(), &config).unwrap();

        assert_eq!(stats.total_files, 1);
        assert_eq!(stats.total_code_lines, 1);
    }

    #[cfg(unix)]
    #[test]
    fn ignores_symlinks_leaving_the_project() {
        let outside = TempDir::new().unwrap();
        let secret = outside.path().join("secret.rs");
        fs::write(&secret, "fn a() {}\nfn b() {}\n").unwrap();

        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();
        std::os::unix::fs::symlink(&secret, dir.path().join("linked.rs")).unwrap();

        let stats = project_stats(dir.path(), &default_config()).unwrap();

        assert_eq!(stats.total_files, 1);
        assert_eq!(stats.total_code_lines, 1);
    }

    #[test]
    fn reports_display_names_for_detected_languages() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("app.ts"), "const a = 1;\n").unwrap();
        fs::write(dir.path().join("style.css"), "a { color: red; }\n").unwrap();

        let stats = project_stats(dir.path(), &default_config()).unwrap();
        let names: Vec<&str> = stats
            .languages
            .iter()
            .map(|language| language.name.as_str())
            .collect();

        assert!(names.contains(&"TypeScript"));
        assert!(names.contains(&"CSS"));
    }

    #[test]
    fn detected_languages_have_profiles() {
        let extensions = [
            "rs", "py", "ts", "sh", "sql", "lua", "hs", "ml", "erl", "vue",
        ];

        for extension in extensions {
            let path = std::path::PathBuf::from(format!("sample.{extension}"));
            let language = crate::engine::language::detect(&path, None).unwrap();
            assert!(profile_for(language).is_some(), "missing {language}");
        }
    }

    #[test]
    fn missing_root_reports_io_error() {
        let dir = TempDir::new().unwrap();

        let result = project_stats(&dir.path().join("missing"), &default_config());

        assert!(matches!(result, Err(EngineError::Io { .. })));
    }

    #[test]
    fn an_entry_outside_the_project_is_skipped() {
        let outside = TempDir::new().unwrap();
        let secret = outside.path().join("secret.rs");
        fs::write(&secret, "fn secret() {}\n").unwrap();
        let dir = TempDir::new().unwrap();
        let main = dir.path().join("main.rs");
        fs::write(&main, "fn main() {}\n").unwrap();
        let filesystem = open_filesystem(dir.path());
        let entries = [entry(&secret, "rust"), entry(&main, "rust")];

        let stats = project_stats_for_entries(&filesystem, &default_config(), &entries);

        assert_eq!(stats.total_files, 1);
        assert_eq!(stats.total_code_lines, 1);
    }

    #[test]
    fn an_entry_whose_file_disappeared_is_skipped() {
        let dir = TempDir::new().unwrap();
        let kept = dir.path().join("kept.rs");
        let removed = dir.path().join("removed.rs");
        fs::write(&kept, "fn kept() {}\n").unwrap();
        fs::write(&removed, "fn removed() {}\n").unwrap();
        let filesystem = open_filesystem(dir.path());
        let entries = [entry(&removed, "rust"), entry(&kept, "rust")];
        fs::remove_file(&removed).unwrap();

        let stats = project_stats_for_entries(&filesystem, &default_config(), &entries);

        assert_eq!(stats.total_files, 1);
        assert_eq!(stats.total_code_lines, 1);
    }

    #[test]
    fn an_unrecognized_language_keeps_its_own_name_and_has_no_comment_syntax() {
        let dir = TempDir::new().unwrap();
        let source = dir.path().join("app.cbl");
        fs::write(&source, "// not a comment\nMOVE 1 TO X\n").unwrap();
        let filesystem = open_filesystem(dir.path());
        let entries = [entry(&source, "cobol")];

        let stats = project_stats_for_entries(&filesystem, &default_config(), &entries);

        assert_eq!(stats.languages.len(), 1);
        assert_eq!(stats.languages[0].name, "cobol");
        assert_eq!(stats.total_code_lines, 2);
        assert_eq!(stats.total_comment_lines, 0);
    }

    #[test]
    fn comment_counting_follows_the_markers_it_is_given() {
        let syntax = CommentSyntax::new(&["@@"], SLASH_STAR_BLOCKS);
        let mut counts = LineCounts::default();

        add_line_counts(
            "@@ note\n/* opened\nstill inside */\nvalue = 1\n\n",
            &syntax,
            &mut counts,
        );

        assert_eq!(counts.comments, 3);
        assert_eq!(counts.code, 1);
        assert_eq!(counts.blanks, 1);
    }

    #[test]
    fn an_open_block_closes_on_the_delimiter_it_was_opened_with() {
        let syntax = comment_syntax("rust");
        let mut open_block = Some(BlockDelimiters::new("<%#", "#%>"));

        let inside = is_comment_line("still inside", &syntax, &mut open_block);
        let closing = is_comment_line("done #%> let x = 1;", &syntax, &mut open_block);

        assert!(inside);
        assert!(!closing);
        assert!(open_block.is_none());
    }

    #[test]
    fn a_language_profile_pairs_its_identity_with_its_syntax() {
        let profile = LanguageProfile::new("crystal", "Crystal", HASH_STYLE);
        let mut counts = LineCounts::default();

        add_line_counts("# note\nputs 1\n", &profile.syntax, &mut counts);

        assert_eq!(profile.id, "crystal");
        assert_eq!(profile.display_name, "Crystal");
        assert_eq!(counts.comments, 1);
        assert_eq!(counts.code, 1);
    }

    fn beyond_u32() -> u64 {
        u64::from(u32::MAX) + 1
    }

    #[test]
    fn ordinary_counts_aggregate_to_their_exact_totals() {
        let per_language = BTreeMap::from([
            (
                "rust",
                LineCounts {
                    files: 2,
                    code: 7,
                    comments: 3,
                    blanks: 1,
                },
            ),
            (
                "python",
                LineCounts {
                    files: 1,
                    code: 4,
                    comments: 0,
                    blanks: 2,
                },
            ),
        ]);

        let stats = aggregate_stats(per_language);

        assert_eq!(stats.total_files, 3);
        assert_eq!(stats.total_code_lines, 11);
        assert_eq!(stats.total_comment_lines, 3);
        assert_eq!(stats.total_blank_lines, 3);
        assert_eq!(stats.total_lines, 17);
        assert_eq!(stats.languages[0].name, "Rust");
        assert_eq!(stats.languages[1].name, "Python");
    }

    #[test]
    fn counters_wider_than_u32_aggregate_without_truncation() {
        let wide = beyond_u32();
        let per_language = BTreeMap::from([(
            "rust",
            LineCounts {
                files: wide,
                code: wide,
                comments: wide + 1,
                blanks: wide + 2,
            },
        )]);

        let stats = aggregate_stats(per_language);

        assert_eq!(stats.languages[0].files, wide);
        assert_eq!(stats.languages[0].code, wide);
        assert_eq!(stats.languages[0].comments, wide + 1);
        assert_eq!(stats.languages[0].blanks, wide + 2);
        assert_eq!(stats.total_files, wide);
        assert_eq!(stats.total_code_lines, wide);
        assert_eq!(stats.total_comment_lines, wide + 1);
        assert_eq!(stats.total_blank_lines, wide + 2);
        assert_eq!(stats.total_lines, wide * 3 + 3);
    }

    #[test]
    fn languages_beyond_u32_keep_descending_code_order() {
        let wide = beyond_u32();
        let per_language = BTreeMap::from([
            (
                "python",
                LineCounts {
                    files: 1,
                    code: wide + 1,
                    ..LineCounts::default()
                },
            ),
            (
                "rust",
                LineCounts {
                    files: 1,
                    code: wide,
                    ..LineCounts::default()
                },
            ),
        ]);

        let stats = aggregate_stats(per_language);

        assert_eq!(stats.languages[0].name, "Python");
        assert_eq!(stats.languages[1].name, "Rust");
        assert_eq!(stats.total_code_lines, wide * 2 + 1);
    }

    #[test]
    fn a_counter_reaches_the_limit_exactly_and_then_stops() {
        let mut counter = STATS_COUNTER_LIMIT - 1;

        bounded_increment(&mut counter);
        assert_eq!(counter, STATS_COUNTER_LIMIT);

        bounded_increment(&mut counter);
        assert_eq!(counter, STATS_COUNTER_LIMIT);
    }

    #[test]
    fn a_sum_one_past_the_limit_clamps_to_the_limit() {
        assert_eq!(bounded_sum(0, 0), 0);
        assert_eq!(bounded_sum(STATS_COUNTER_LIMIT - 2, 2), STATS_COUNTER_LIMIT);
        assert_eq!(bounded_sum(STATS_COUNTER_LIMIT - 2, 3), STATS_COUNTER_LIMIT);
        assert_eq!(
            bounded_sum(STATS_COUNTER_LIMIT, STATS_COUNTER_LIMIT),
            STATS_COUNTER_LIMIT
        );
    }

    #[test]
    fn counting_lines_into_counters_at_the_limit_does_not_wrap() {
        let mut counts = LineCounts {
            files: STATS_COUNTER_LIMIT,
            code: STATS_COUNTER_LIMIT,
            comments: STATS_COUNTER_LIMIT - 1,
            blanks: STATS_COUNTER_LIMIT,
        };

        add_line_counts(
            "// note\nlet x = 1;\n\n",
            &comment_syntax("rust"),
            &mut counts,
        );

        assert_eq!(counts.comments, STATS_COUNTER_LIMIT);
        assert_eq!(counts.code, STATS_COUNTER_LIMIT);
        assert_eq!(counts.blanks, STATS_COUNTER_LIMIT);
    }

    #[test]
    fn totals_clamp_at_the_limit_instead_of_wrapping() {
        let two_thirds = STATS_COUNTER_LIMIT / 3 * 2;
        let counts = || LineCounts {
            files: two_thirds,
            code: two_thirds,
            comments: two_thirds,
            blanks: two_thirds,
        };
        let per_language = BTreeMap::from([("rust", counts()), ("python", counts())]);

        let stats = aggregate_stats(per_language);

        assert_eq!(stats.total_files, STATS_COUNTER_LIMIT);
        assert_eq!(stats.total_code_lines, STATS_COUNTER_LIMIT);
        assert_eq!(stats.total_comment_lines, STATS_COUNTER_LIMIT);
        assert_eq!(stats.total_blank_lines, STATS_COUNTER_LIMIT);
        assert_eq!(stats.total_lines, STATS_COUNTER_LIMIT);
    }

    #[test]
    fn a_single_language_at_the_limit_clamps_only_the_line_total() {
        let per_language = BTreeMap::from([(
            "rust",
            LineCounts {
                files: 1,
                code: STATS_COUNTER_LIMIT,
                comments: 1,
                blanks: 0,
            },
        )]);

        let stats = aggregate_stats(per_language);

        assert_eq!(stats.total_code_lines, STATS_COUNTER_LIMIT);
        assert_eq!(stats.total_comment_lines, 1);
        assert_eq!(stats.total_lines, STATS_COUNTER_LIMIT);
    }

    #[test]
    fn serialized_stats_keep_their_field_names_and_wide_values() {
        let wide = beyond_u32();
        let per_language = BTreeMap::from([(
            "rust",
            LineCounts {
                files: 1,
                code: wide,
                comments: 0,
                blanks: 0,
            },
        )]);

        let json = serde_json::to_value(aggregate_stats(per_language)).unwrap();

        assert_eq!(json["total_files"], 1);
        assert_eq!(json["total_lines"], wide);
        assert_eq!(json["total_code_lines"], wide);
        assert_eq!(json["total_comment_lines"], 0);
        assert_eq!(json["total_blank_lines"], 0);
        assert_eq!(json["languages"][0]["name"], "Rust");
        assert_eq!(json["languages"][0]["files"], 1);
        assert_eq!(json["languages"][0]["code"], wide);
        assert_eq!(json["languages"][0]["comments"], 0);
        assert_eq!(json["languages"][0]["blanks"], 0);
    }
}
