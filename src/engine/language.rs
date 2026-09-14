use std::path::Path;

pub fn detect_by_extension(path: &Path) -> Option<&'static str> {
    let ext = path.extension()?.to_str()?;
    match ext.to_lowercase().as_str() {
        "rs" => Some("rust"),
        "go" => Some("go"),
        "ts" => Some("typescript"),
        "tsx" => Some("tsx"),
        "js" | "jsx" | "mjs" | "cjs" => Some("javascript"),
        "py" | "pyi" => Some("python"),
        "java" => Some("java"),
        "rb" => Some("ruby"),
        "c" | "h" => Some("c"),
        "cpp" | "cc" | "cxx" | "hpp" | "hxx" => Some("cpp"),
        "cs" => Some("csharp"),
        "kt" | "kts" => Some("kotlin"),
        "swift" => Some("swift"),
        "scala" => Some("scala"),
        "php" => Some("php"),
        "lua" => Some("lua"),
        "sh" | "bash" | "zsh" => Some("bash"),
        "tf" | "tofu" | "hcl" => Some("hcl"),
        "yaml" | "yml" => Some("yaml"),
        "toml" => Some("toml"),
        "json" => Some("json"),
        "md" | "markdown" => Some("markdown"),
        "sql" => Some("sql"),
        "html" | "htm" => Some("html"),
        "css" | "scss" | "sass" | "less" => Some("css"),
        "xml" | "xsl" | "xslt" => Some("xml"),
        "proto" => Some("protobuf"),
        "graphql" | "gql" => Some("graphql"),
        "zig" => Some("zig"),
        "nim" => Some("nim"),
        "ex" | "exs" => Some("elixir"),
        "erl" | "hrl" => Some("erlang"),
        "hs" | "lhs" => Some("haskell"),
        "ml" | "mli" => Some("ocaml"),
        "r" => Some("r"),
        "dart" => Some("dart"),
        "vue" => Some("vue"),
        "svelte" => Some("svelte"),
        _ => None,
    }
}

pub fn detect_by_filename(path: &Path) -> Option<&'static str> {
    let filename = path.file_name()?.to_str()?;
    match filename {
        "Dockerfile" | "Containerfile" => Some("dockerfile"),
        "Makefile" | "GNUmakefile" => Some("makefile"),
        "CMakeLists.txt" => Some("cmake"),
        "Cargo.toml" | "Cargo.lock" => Some("toml"),
        "Gemfile" | "Rakefile" => Some("ruby"),
        "Jenkinsfile" => Some("groovy"),
        _ => None,
    }
}

pub fn detect_by_shebang(first_line: &str) -> Option<&'static str> {
    if !first_line.starts_with("#!") {
        return None;
    }
    let line = first_line.to_lowercase();
    if line.contains("python") {
        return Some("python");
    }
    if line.contains("node") {
        return Some("javascript");
    }
    if line.contains("bash") || line.ends_with("/sh") {
        return Some("bash");
    }
    if line.contains("ruby") {
        return Some("ruby");
    }
    if line.contains("perl") {
        return Some("perl");
    }
    None
}

pub fn detect(path: &Path, first_line: Option<&str>) -> Option<&'static str> {
    detect_by_extension(path)
        .or_else(|| detect_by_filename(path))
        .or_else(|| first_line.and_then(detect_by_shebang))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::path::Path;

    const EXTENSION_LANGUAGES: &[(&str, &str)] = &[
        ("rs", "rust"),
        ("go", "go"),
        ("ts", "typescript"),
        ("tsx", "tsx"),
        ("js", "javascript"),
        ("jsx", "javascript"),
        ("mjs", "javascript"),
        ("cjs", "javascript"),
        ("py", "python"),
        ("pyi", "python"),
        ("java", "java"),
        ("rb", "ruby"),
        ("c", "c"),
        ("h", "c"),
        ("cpp", "cpp"),
        ("cc", "cpp"),
        ("cxx", "cpp"),
        ("hpp", "cpp"),
        ("hxx", "cpp"),
        ("cs", "csharp"),
        ("kt", "kotlin"),
        ("kts", "kotlin"),
        ("swift", "swift"),
        ("scala", "scala"),
        ("php", "php"),
        ("lua", "lua"),
        ("sh", "bash"),
        ("bash", "bash"),
        ("zsh", "bash"),
        ("tf", "hcl"),
        ("tofu", "hcl"),
        ("hcl", "hcl"),
        ("yaml", "yaml"),
        ("yml", "yaml"),
        ("toml", "toml"),
        ("json", "json"),
        ("md", "markdown"),
        ("markdown", "markdown"),
        ("sql", "sql"),
        ("html", "html"),
        ("htm", "html"),
        ("css", "css"),
        ("scss", "css"),
        ("sass", "css"),
        ("less", "css"),
        ("xml", "xml"),
        ("xsl", "xml"),
        ("xslt", "xml"),
        ("proto", "protobuf"),
        ("graphql", "graphql"),
        ("gql", "graphql"),
        ("zig", "zig"),
        ("nim", "nim"),
        ("ex", "elixir"),
        ("exs", "elixir"),
        ("erl", "erlang"),
        ("hrl", "erlang"),
        ("hs", "haskell"),
        ("lhs", "haskell"),
        ("ml", "ocaml"),
        ("mli", "ocaml"),
        ("r", "r"),
        ("dart", "dart"),
        ("vue", "vue"),
        ("svelte", "svelte"),
    ];

    const FILENAME_LANGUAGES: &[(&str, &str)] = &[
        ("Dockerfile", "dockerfile"),
        ("Containerfile", "dockerfile"),
        ("Makefile", "makefile"),
        ("GNUmakefile", "makefile"),
        ("CMakeLists.txt", "cmake"),
        ("Cargo.toml", "toml"),
        ("Cargo.lock", "toml"),
        ("Gemfile", "ruby"),
        ("Rakefile", "ruby"),
        ("Jenkinsfile", "groovy"),
    ];

    const SHEBANG_LANGUAGES: &[(&str, Option<&str>)] = &[
        ("#!/usr/bin/env python3", Some("python")),
        ("#!/usr/bin/python", Some("python")),
        ("#!/usr/bin/env node", Some("javascript")),
        ("#!/bin/bash", Some("bash")),
        ("#!/usr/bin/env bash", Some("bash")),
        ("#!/bin/sh", Some("bash")),
        ("#!/usr/bin/env ruby", Some("ruby")),
        ("#!/usr/bin/perl", Some("perl")),
        ("#!/USR/BIN/ENV PYTHON3", Some("python")),
        ("#!/usr/bin/env fish", None),
        ("#!", None),
        ("# not a shebang", None),
        ("", None),
    ];

    #[test]
    fn every_known_extension_maps_to_its_language_case_insensitively() {
        for (extension, expected) in EXTENSION_LANGUAGES {
            let lowercase = format!("sample.{extension}");
            let uppercase = format!("sample.{}", extension.to_uppercase());

            assert_eq!(
                detect(Path::new(&lowercase), None),
                Some(*expected),
                "{lowercase}"
            );
            assert_eq!(
                detect(Path::new(&uppercase), None),
                Some(*expected),
                "{uppercase}"
            );
        }
    }

    #[test]
    fn an_unknown_extension_is_not_detected() {
        assert_eq!(detect_by_extension(Path::new("data.xyz")), None);
        assert_eq!(detect(Path::new("data.xyz"), None), None);
        assert_eq!(
            detect(Path::new("data.xyz"), Some("#!/usr/bin/env fish")),
            None
        );
    }

    #[test]
    fn a_path_without_an_extension_falls_through_extension_detection() {
        assert_eq!(detect_by_extension(Path::new("README")), None);
        assert_eq!(detect_by_extension(Path::new("/")), None);
    }

    #[test]
    fn every_known_filename_maps_to_its_language() {
        for (filename, expected) in FILENAME_LANGUAGES {
            assert_eq!(
                detect_by_filename(Path::new(filename)),
                Some(*expected),
                "{filename}"
            );
            assert_eq!(
                detect_by_filename(&Path::new("nested/dir").join(filename)),
                Some(*expected),
                "nested {filename}"
            );
        }
    }

    #[test]
    fn filename_detection_requires_an_exact_match() {
        assert_eq!(detect_by_filename(Path::new("Makefile.old")), None);
        assert_eq!(detect_by_filename(Path::new("dockerfile")), None);
    }

    #[test]
    fn a_path_with_no_final_component_is_not_detected() {
        assert_eq!(detect_by_filename(Path::new("/")), None);
        assert_eq!(detect_by_filename(Path::new("..")), None);
        assert_eq!(detect(Path::new(".."), None), None);
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_path_components_are_not_detected() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let non_utf8_extension = Path::new(OsStr::from_bytes(b"sample.r\xff"));
        let non_utf8_filename = Path::new(OsStr::from_bytes(b"Makefile\xff"));

        assert_eq!(detect_by_extension(non_utf8_extension), None);
        assert_eq!(detect_by_filename(non_utf8_filename), None);
        assert_eq!(detect(non_utf8_extension, None), None);
    }

    #[test]
    fn every_known_shebang_maps_to_its_language() {
        for (first_line, expected) in SHEBANG_LANGUAGES {
            assert_eq!(detect_by_shebang(first_line), *expected, "{first_line}");
            assert_eq!(
                detect(Path::new("script"), Some(first_line)),
                *expected,
                "{first_line}"
            );
        }
    }

    #[test]
    fn a_missing_first_line_skips_shebang_detection() {
        assert_eq!(detect(Path::new("script"), None), None);
    }

    #[test]
    fn extension_detection_wins_over_filename_and_shebang() {
        assert_eq!(
            detect(Path::new("Cargo.toml"), Some("#!/usr/bin/env python3")),
            Some("toml")
        );
        assert_eq!(
            detect(Path::new("app.rs"), Some("#!/usr/bin/env python3")),
            Some("rust")
        );
    }

    #[test]
    fn filename_detection_wins_over_shebang() {
        assert_eq!(
            detect(Path::new("Makefile"), Some("#!/usr/bin/env python3")),
            Some("makefile")
        );
        assert_eq!(
            detect(Path::new("Cargo.lock"), Some("#!/usr/bin/env python3")),
            Some("toml")
        );
    }
}
