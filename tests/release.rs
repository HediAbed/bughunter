#![cfg(unix)]

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;

const REQUIRED_ARCHIVE_DOCUMENTS: [&str; 3] = ["LICENSE", "README.md", "THIRD_PARTY_LICENSES.txt"];

const GENERATED_NOTICE: &str = "THIRD_PARTY_LICENSES.txt";

fn project_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn make_value(target: &str) -> String {
    let output = Command::new("make")
        .arg("--no-print-directory")
        .arg(target)
        .current_dir(project_root())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "make {target} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn release_workflow() -> String {
    fs::read_to_string(project_root().join(".github/workflows/release.yml")).unwrap()
}

fn ci_workflow() -> String {
    fs::read_to_string(project_root().join(".github/workflows/ci.yml")).unwrap()
}

fn parsed_toml(name: &str) -> toml::Table {
    fs::read_to_string(project_root().join(name))
        .unwrap()
        .parse()
        .unwrap()
}

fn string_set(values: &toml::Value) -> BTreeSet<&str> {
    values
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect()
}

fn assert_contains(workflow: &str, fragment: &str) {
    assert!(
        workflow.contains(fragment),
        "release workflow is missing:\n{fragment}"
    );
}

fn step_offset(workflow: &str, name: &str) -> usize {
    workflow
        .find(&format!("- name: {name}"))
        .unwrap_or_else(|| panic!("release workflow has no step named {name:?}"))
}

fn double_stash_value_tags(template: &str) -> Vec<&str> {
    let mut tags = Vec::new();
    let mut index = 0;

    while let Some(offset) = template[index..].find("{{") {
        let start = index + offset;
        let braces = template[start..]
            .bytes()
            .take_while(|brace| *brace == b'{')
            .count();
        let body_start = start + braces;
        let body_end = template[body_start..]
            .find('}')
            .map_or(template.len(), |end| body_start + end);
        let body = &template[body_start..body_end];

        if braces == 2 && !body.starts_with('#') && !body.starts_with('/') {
            tags.push(body);
        }

        index = body_end.max(body_start);
    }

    tags
}

#[test]
fn release_documents_match_the_published_set() {
    let documents: Vec<String> = make_value("print-release-documents")
        .split_whitespace()
        .map(str::to_owned)
        .collect();

    assert_eq!(
        documents
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(REQUIRED_ARCHIVE_DOCUMENTS),
        "the release archive document set changed"
    );
    assert_eq!(
        documents.len(),
        REQUIRED_ARCHIVE_DOCUMENTS.len(),
        "make print-release-documents repeats a document: {documents:?}"
    );

    for document in documents.iter().filter(|name| *name != GENERATED_NOTICE) {
        assert!(
            project_root().join(document).is_file(),
            "release document {document} is missing from the repository"
        );
    }
}

#[test]
fn the_generated_notice_stays_a_release_artifact() {
    let ignored = fs::read_to_string(project_root().join(".gitignore")).unwrap();

    assert!(
        ignored
            .lines()
            .any(|line| line.trim() == format!("/{GENERATED_NOTICE}")),
        "a machine-generated notice must not be committed"
    );
}

#[test]
fn the_release_gate_only_trusts_push_runs_of_the_tagged_commit() {
    let workflow = release_workflow();

    assert_contains(&workflow, "for workflow in ci sanitizers; do");
    assert_contains(
        &workflow,
        r#"runs?event=push&head_sha=${COMMIT}&per_page=1"#,
    );
    assert_contains(&workflow, r#"if [ "$conclusion" != "success" ]; then"#);
    assert!(
        !workflow.contains(r#"runs?head_sha="#),
        "a pull request run tests the merge commit, so the gate must filter on push runs"
    );
}

#[test]
fn the_archive_stages_the_binary_and_every_release_document() {
    let workflow = release_workflow();

    assert_contains(
        &workflow,
        r#"documents="$(make --no-print-directory print-release-documents | tr ' ' '\n' | sed '/^$/d')""#,
    );
    assert_contains(
        &workflow,
        r#"install -Dm755 target/release/bughunter "$staging/bughunter""#,
    );
    assert_contains(
        &workflow,
        r#"printf '%s\n' "$documents" | while IFS= read -r document; do"#,
    );
    assert_contains(
        &workflow,
        r#"install -Dm644 "$document" "$staging/$document""#,
    );
    assert_contains(
        &workflow,
        r#"{ printf '%s\n' bughunter; printf '%s\n' "$documents"; } | LC_ALL=C sort > "$RUNNER_TEMP/archive-expected.txt""#,
    );
    assert_contains(
        &workflow,
        r#"diff -u "$RUNNER_TEMP/archive-expected.txt" "$RUNNER_TEMP/archive-actual.txt""#,
    );
}

#[test]
fn the_archive_is_built_deterministically() {
    let workflow = release_workflow();

    for flag in [
        "--sort=name",
        r#"--mtime="@$SOURCE_DATE_EPOCH""#,
        "--owner=0",
        "--group=0",
        "--numeric-owner",
        "gzip -n -9",
    ] {
        assert_contains(&workflow, flag);
    }
}

#[test]
fn the_archive_name_uses_the_pinned_release_target() {
    let workflow = release_workflow();
    let target = make_value("print-release-target");

    assert_eq!(target, "x86_64-unknown-linux-gnu");
    assert_contains(
        &workflow,
        r#"archive="bughunter-${version}-$(make --no-print-directory print-release-target).tar.gz""#,
    );
    assert_contains(&workflow, &format!("bughunter-*-{target}.tar.gz"));
}

#[test]
fn reproducibility_variables_are_exported_before_the_release_build() {
    let workflow = release_workflow();
    let checkout = workflow
        .find("actions/checkout@")
        .expect("the release workflow must check the repository out");
    let export = step_offset(&workflow, "Export reproducibility variables");

    assert!(
        export < step_offset(&workflow, "Build"),
        "the release build must observe SOURCE_DATE_EPOCH, TZ, and LC_ALL"
    );
    assert!(
        checkout < export,
        "SOURCE_DATE_EPOCH is read from git log, so the checkout has to come first"
    );

    for variable in [
        "SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)",
        "TZ=UTC",
        "LC_ALL=C",
    ] {
        assert_contains(&workflow, variable);
    }
}

#[test]
fn release_tooling_is_installed_from_the_makefile_pins() {
    let workflow = release_workflow();

    assert_contains(
        &workflow,
        r#"cargo install cargo-about --version "$(make --no-print-directory print-cargo-about-version)" --locked --features cli"#,
    );
    assert_contains(
        &workflow,
        r#"cargo install cargo-cyclonedx --version "$(make --no-print-directory print-cargo-cyclonedx-version)" --locked"#,
    );
    assert_eq!(make_value("print-cargo-about-version"), "0.9.2");
    assert_eq!(make_value("print-cargo-cyclonedx-version"), "0.5.9");
}

#[test]
fn the_notice_is_generated_and_verified_through_make() {
    assert_contains(&release_workflow(), "run: make license-notice");
}

#[test]
fn the_sbom_describes_the_released_graph() {
    let workflow = release_workflow();

    assert_contains(
        &workflow,
        r#"cargo cyclonedx --format json --spec-version 1.5 --target "$(make --no-print-directory print-release-target)" --no-build-deps --override-filename bughunter-unsanitized.cdx"#,
    );
    assert!(
        !workflow.contains("--license-strict"),
        "--license-strict downgrades components to unparsed license names without failing the run"
    );
    assert!(
        !workflow.contains("--describe binaries"),
        "cargo-cyclonedx 0.5.9 rejects --override-filename together with --describe binaries"
    );
}

#[test]
fn the_sbom_is_sanitized_and_regenerated_for_comparison() {
    let workflow = release_workflow();

    assert_contains(&workflow, "git diff --exit-code -- Cargo.lock");
    assert_contains(&workflow, r#"jq -r '.metadata.component["bom-ref"]'"#);
    assert_contains(
        &workflow,
        r#"--arg stable "pkg:cargo/bughunter@${version}""#,
    );
    assert_contains(&workflow, "jq -S --arg root");
    assert_contains(&workflow, "del(.metadata.timestamp, .serialNumber)");
    assert_contains(
        &workflow,
        "if grep -q 'path+file:' bughunter.cdx.json; then",
    );
    assert_contains(
        &workflow,
        r#"if grep -qF "$GITHUB_WORKSPACE" bughunter.cdx.json; then"#,
    );
    assert_contains(
        &workflow,
        r#"cmp bughunter.cdx.json "$RUNNER_TEMP/bughunter.cdx.json""#,
    );
}

#[test]
fn the_sbom_covers_the_release_graph_and_stays_inside_the_lockfile() {
    let workflow = release_workflow();

    assert_contains(
        &workflow,
        r#"comm -23 "$(make --no-print-directory print-license-graph)" "$RUNNER_TEMP/sbom-packages.txt" > "$RUNNER_TEMP/sbom-missing.txt""#,
    );
    assert_contains(
        &workflow,
        r#"comm -13 "$RUNNER_TEMP/locked-packages.txt" "$RUNNER_TEMP/sbom-packages.txt" > "$RUNNER_TEMP/sbom-unlocked.txt""#,
    );
    assert_contains(
        &workflow,
        r#"if [ -s "$RUNNER_TEMP/sbom-missing.txt" ]; then"#,
    );
    assert_contains(
        &workflow,
        r#"if [ -s "$RUNNER_TEMP/sbom-unlocked.txt" ]; then"#,
    );
    assert_eq!(
        make_value("print-license-graph"),
        "target/license/dependency-graph.txt"
    );
}

#[test]
fn the_license_policy_targets_the_release_triple() {
    let config = parsed_toml("about.toml");
    let target = make_value("print-release-target");

    assert_eq!(
        string_set(config.get("targets").unwrap()),
        BTreeSet::from([target.as_str()]),
        "about.toml must resolve licenses for exactly the released target"
    );
}

#[test]
fn the_license_policy_accepts_exactly_the_audited_licenses() {
    let about = parsed_toml("about.toml");
    let deny = parsed_toml("deny.toml");
    let allowed = deny
        .get("licenses")
        .unwrap()
        .as_table()
        .unwrap()
        .get("allow")
        .unwrap()
        .clone();

    assert_eq!(
        string_set(about.get("accepted").unwrap()),
        string_set(&allowed),
        "about.toml and deny.toml must agree on the accepted licenses"
    );
}

#[test]
fn the_license_policy_excludes_build_and_development_dependencies() {
    let config = parsed_toml("about.toml");
    let flag = |key: &str| config.get(key).unwrap().as_bool();

    assert_eq!(flag("ignore-build-dependencies"), Some(true));
    assert_eq!(flag("ignore-dev-dependencies"), Some(true));
    assert_eq!(
        flag("ignore-transitive-dependencies"),
        Some(false),
        "the notice must cover the whole transitive release graph"
    );
    assert_eq!(
        config
            .get("private")
            .unwrap()
            .as_table()
            .unwrap()
            .get("ignore")
            .unwrap()
            .as_bool(),
        Some(true),
        "bughunter ships its own LICENSE and is not one of its third parties"
    );
}

#[test]
fn every_license_clarification_is_checksum_bound() {
    let config = parsed_toml("about.toml");
    let clarified: Vec<(&String, &toml::Table)> = config
        .iter()
        .filter_map(|(name, value)| {
            let clarify = value.as_table()?.get("clarify")?.as_table()?;
            Some((name, clarify))
        })
        .collect();

    assert!(
        !clarified.is_empty(),
        "crates that ship no usable license text still need reviewed clarifications"
    );

    for (crate_name, clarify) in clarified {
        assert!(
            clarify
                .get("license")
                .and_then(toml::Value::as_str)
                .is_some(),
            "{crate_name} clarification has no license expression"
        );

        let mut sources = ["files", "git"]
            .iter()
            .filter_map(|key| clarify.get(*key))
            .peekable();
        assert!(
            sources.peek().is_some(),
            "{crate_name} clarification has neither files nor git as a source of truth"
        );

        for entry in sources.flat_map(|source| source.as_array().unwrap()) {
            let entry = entry.as_table().unwrap();
            assert!(
                !entry.get("path").unwrap().as_str().unwrap().is_empty(),
                "{crate_name} clarification has an empty path"
            );

            let checksum = entry.get("checksum").unwrap().as_str().unwrap();
            assert_eq!(
                checksum.len(),
                64,
                "{crate_name} checksum {checksum} is not a sha256 digest"
            );
            assert!(
                checksum
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "{crate_name} checksum {checksum} is not lowercase hex"
            );
        }
    }
}

#[test]
fn the_notice_template_emits_raw_text_without_host_paths() {
    let template = fs::read_to_string(project_root().join("about.hbs")).unwrap();

    for tag in ["{{{text}}}", "{{{name}}}", "{{{id}}}"] {
        assert!(
            template.contains(tag),
            "the plain-text notice must render {tag} unescaped"
        );
    }
    assert_eq!(
        double_stash_value_tags(&template),
        Vec::<&str>::new(),
        "handlebars html-escapes double-stash values, which corrupts license text"
    );
    assert!(
        !template.contains("source_path"),
        "source_path leaks registry paths from the machine that built the release"
    );
}

const ICU_NOTICE_HEADER: &str = "COPYRIGHT AND PERMISSION NOTICE (ICU 58 and later)";

fn bundled_notice() -> std::path::PathBuf {
    project_root().join(make_value("print-bundled-notice"))
}

fn packaged_bundled_notice() -> std::path::PathBuf {
    let output = Command::new("cargo")
        .args(["metadata", "--locked", "--format-version", "1"])
        .current_dir(project_root())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "cargo metadata failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let manifest = metadata["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|package| package["name"] == "tree-sitter")
        .expect("tree-sitter must stay in the locked dependency graph")["manifest_path"]
        .as_str()
        .unwrap()
        .to_owned();

    Path::new(&manifest)
        .parent()
        .unwrap()
        .join("src/unicode/LICENSE")
}

fn sha256(path: &Path) -> String {
    let output = Command::new("sha256sum").arg(path).output().unwrap();

    assert!(
        output.status.success(),
        "sha256sum {} failed",
        path.display()
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned()
}

#[test]
fn the_bundled_unicode_notice_is_committed_with_the_icu_header() {
    let notice = bundled_notice();

    assert!(
        notice.is_file(),
        "the reviewed bundled notice {} must be committed",
        notice.display()
    );
    assert!(
        fs::read_to_string(&notice)
            .unwrap()
            .starts_with(ICU_NOTICE_HEADER),
        "the bundled notice must be the verbatim ICU notice"
    );
}

#[test]
fn the_bundled_unicode_notice_matches_the_reviewed_checksum() {
    assert_eq!(
        sha256(&bundled_notice()),
        make_value("print-bundled-notice-sha256"),
        "the committed notice and the reviewed checksum disagree"
    );
}

#[test]
fn the_bundled_unicode_notice_matches_the_packaged_crate_file() {
    let packaged = packaged_bundled_notice();

    assert!(
        packaged.is_file(),
        "tree-sitter no longer ships {}; review the upgrade",
        packaged.display()
    );
    assert_eq!(
        fs::read(bundled_notice()).unwrap(),
        fs::read(&packaged).unwrap(),
        "the committed notice drifted from the packaged tree-sitter notice"
    );
}

#[test]
fn the_bundled_notice_is_a_generation_input_not_an_archive_member() {
    let documents = make_value("print-release-documents");
    let input = make_value("print-bundled-notice");

    assert!(
        !documents
            .split_whitespace()
            .any(|document| document == input),
        "the bundled notice is folded into {GENERATED_NOTICE}, so it must not be staged separately"
    );
}

#[test]
fn the_tree_sitter_clarification_keeps_its_declared_mit_license() {
    let config = parsed_toml("about.toml");

    assert_eq!(
        config["tree-sitter"]["clarify"]["license"].as_str(),
        Some("MIT"),
        "carrying the bundled notice must not restate the license tree-sitter declares"
    );
}

#[test]
fn the_bundled_unicode_notice_is_protected_from_line_ending_rewrites() {
    let notice = make_value("print-bundled-notice");
    let output = Command::new("git")
        .args(["check-attr", "text", "--"])
        .arg(&notice)
        .current_dir(project_root())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "git check-attr failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let reported = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        reported.trim_end(),
        format!("{notice}: text: unset"),
        "core.autocrlf must not be able to rewrite the checksum-pinned notice"
    );
}

#[test]
fn continuous_integration_lints_workflows_with_a_checksum_pinned_binary() {
    let workflow = ci_workflow();
    let install = step_offset(&workflow, "Install actionlint");
    let lint = step_offset(&workflow, "Lint workflows");
    let check = step_offset(&workflow, "Format, lint, and test both Cargo manifests");

    assert!(install < lint);
    assert!(lint < check);
    assert_contains(&workflow, "ACTIONLINT_VERSION: 1.7.12");
    assert_contains(
        &workflow,
        "ACTIONLINT_LINUX_AMD64_SHA256: 8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8",
    );
    assert_contains(
        &workflow,
        r#"https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz"#,
    );
    assert_contains(&workflow, r#""${RUNNER_TEMP}/actionlint""#);
}
