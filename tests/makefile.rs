#![cfg(unix)]

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

fn project_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

fn prepend_to_path(directory: &Path) -> OsString {
    std::env::join_paths(
        std::iter::once(directory.to_path_buf()).chain(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        )),
    )
    .unwrap()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn setup_installs_binary_and_prints_next_steps() {
    let environment = tempfile::tempdir().unwrap();
    let cargo_home = environment.path().join("cargo home");
    fs::create_dir_all(&cargo_home).unwrap();
    let cargo = environment.path().join("cargo");
    write_executable(
        &cargo,
        r#"#!/bin/sh
set -eu
printf '%s\n' "$*" > "$CARGO_HOME/invocation"
test "$1" = install
test "$#" -eq 7
test "$6" = --root
test "$7" = "$CARGO_HOME"
mkdir -p "$CARGO_HOME/bin"
cat > "$CARGO_HOME/bin/bughunter" <<'SCRIPT'
#!/bin/sh
printf '%s\n' 'bughunter 0.1.0'
SCRIPT
chmod +x "$CARGO_HOME/bin/bughunter"
"#,
    );

    let output = Command::new("make")
        .arg("setup")
        .arg(format!("CARGO={}", cargo.display()))
        .arg(format!("INSTALL_ROOT={}", cargo_home.display()))
        .current_dir(project_root())
        .env("CARGO_HOME", &cargo_home)
        .env("PATH", prepend_to_path(&cargo_home.join("bin")))
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(
        fs::read_to_string(cargo_home.join("invocation")).unwrap(),
        format!(
            "install --path . --locked --force --root {}\n",
            cargo_home.display()
        )
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("bughunter 0.1.0"));
    assert!(stdout.contains("make doctor"));
    assert!(stdout.contains("make config PROJECT=/path/to/project"));
    assert!(stdout.contains("bughunter analyze --project /path/to/project"));
}

#[test]
fn setup_runs_the_new_binary_when_path_contains_a_stale_copy() {
    let environment = tempfile::tempdir().unwrap();
    let selected_root = environment.path().join("selected-root");
    let selected_bin = selected_root.join("bin");
    let stale_bin = environment.path().join("stale-bin");
    fs::create_dir_all(&selected_bin).unwrap();
    fs::create_dir_all(&stale_bin).unwrap();
    let cargo = environment.path().join("cargo");
    write_executable(
        &cargo,
        r#"#!/bin/sh
set -eu
test "$1" = install
cat > "$CUSTOM_INSTALL_BIN/bughunter" <<'SCRIPT'
#!/bin/sh
printf '%s\n' 'bughunter selected-root'
SCRIPT
chmod +x "$CUSTOM_INSTALL_BIN/bughunter"
"#,
    );
    write_executable(
        &stale_bin.join("bughunter"),
        "#!/bin/sh\nprintf '%s\\n' 'bughunter stale-path-copy'\n",
    );
    let output = Command::new("make")
        .arg("setup")
        .arg(format!("CARGO={}", cargo.display()))
        .arg(format!("INSTALL_ROOT={}", selected_root.display()))
        .current_dir(project_root())
        .env("CUSTOM_INSTALL_BIN", &selected_bin)
        .env("PATH", prepend_to_path(&stale_bin))
        .output()
        .unwrap();

    assert_success(&output);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("bughunter selected-root"));
    assert!(!stdout.contains("bughunter stale-path-copy"));
}

#[test]
fn setup_reports_when_installed_binary_is_missing() {
    let environment = tempfile::tempdir().unwrap();
    let install_root = environment.path().join("install-root");
    let cargo = environment.path().join("cargo");
    write_executable(&cargo, "#!/bin/sh\nexit 0\n");

    let output = Command::new("make")
        .arg("setup")
        .arg(format!("CARGO={}", cargo.display()))
        .arg(format!("INSTALL_ROOT={}", install_root.display()))
        .current_dir(project_root())
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8(output.stdout).unwrap().contains(&format!(
        "Cargo reported success, but {} is not executable",
        install_root.join("bin/bughunter").display()
    )));
}

#[test]
fn config_initializes_the_selected_project() {
    let project = tempfile::tempdir().unwrap();
    let binary = Path::new(env!("CARGO_BIN_EXE_bughunter"));

    let output = Command::new("make")
        .arg("config")
        .arg(format!("PROJECT={}", project.path().display()))
        .arg(format!("BUGHUNTER={}", binary.display()))
        .arg("CARGO=/bin/true")
        .current_dir(project_root())
        .output()
        .unwrap();

    assert_success(&output);
    assert!(project.path().join(".bughunter.toml").is_file());
}

#[test]
fn help_describes_the_user_workflow_without_demo_targets() {
    let output = Command::new("make")
        .arg("help")
        .current_dir(project_root())
        .output()
        .unwrap();

    assert_success(&output);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("make setup                 Install bughunter"));
    assert!(stdout.contains("make config PROJECT=path"));
    assert!(stdout.contains("make run PROJECT=path"));
    assert!(!stdout.contains("make demo"));
}

const DOCTOR_STUB: &str = r#"#!/bin/sh
printf '%s\n' "$*" >> "$CAPTURE_FILE"
case "$1" in
--version) printf '%s\n' 'bughunter 0.1.0' ;;
doctor)
  [ "$2" = "--project" ] || { printf '%s\n' "expected --project, got: $*"; exit 64; }
  [ -n "$3" ] || { printf '%s\n' "expected a project path"; exit 64; }
  [ "$#" -eq 3 ] || { printf '%s\n' "unexpected extra arguments: $*"; exit 64; }
  printf '%s\n' "checked project $3" ;;
*) printf '%s\n' "unexpected invocation: $*"; exit 64 ;;
esac
"#;

fn make_doctor(binary: &Path, capture: &Path) -> Command {
    let mut command = Command::new("make");
    command
        .arg("doctor")
        .arg(format!("BUGHUNTER={}", binary.display()))
        .arg("CARGO=/missing/cargo")
        .current_dir(project_root())
        .env("CAPTURE_FILE", capture);
    command
}

#[test]
fn doctor_uses_the_default_install_root_without_path_lookup() {
    let environment = tempfile::tempdir().unwrap();
    let install_root = environment.path().join("install root");
    let binary = install_root.join("bin/bughunter");
    let invocation = environment.path().join("invocation");
    fs::create_dir_all(binary.parent().unwrap()).unwrap();
    write_executable(&binary, DOCTOR_STUB);

    let output = Command::new("make")
        .arg("doctor")
        .arg(format!("INSTALL_ROOT={}", install_root.display()))
        .arg("CARGO=/missing/cargo")
        .arg("PROJECT=/tmp/default-install")
        .current_dir(project_root())
        .env("CAPTURE_FILE", &invocation)
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(
        fs::read_to_string(&invocation).unwrap(),
        "--version\ndoctor --project /tmp/default-install\n"
    );
}

#[test]
fn doctor_runs_the_installed_binary_and_forwards_the_selected_project() {
    let environment = tempfile::tempdir().unwrap();
    let binary = environment.path().join("bughunter");
    let invocation = environment.path().join("invocation");
    write_executable(&binary, DOCTOR_STUB);

    let output = make_doctor(&binary, &invocation)
        .arg("PROJECT=/tmp/example-project")
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(
        fs::read_to_string(&invocation).unwrap(),
        "--version\ndoctor --project /tmp/example-project\n"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("bughunter 0.1.0"));
    assert!(stdout.contains("checked project /tmp/example-project"));
}

#[test]
fn doctor_checks_the_current_project_by_default() {
    let environment = tempfile::tempdir().unwrap();
    let binary = environment.path().join("bughunter");
    let invocation = environment.path().join("invocation");
    write_executable(&binary, DOCTOR_STUB);

    let output = make_doctor(&binary, &invocation).output().unwrap();

    assert_success(&output);
    assert_eq!(
        fs::read_to_string(&invocation).unwrap(),
        "--version\ndoctor --project .\n"
    );
}

#[test]
fn doctor_reports_a_missing_installation_without_running_checks() {
    let environment = tempfile::tempdir().unwrap();
    let missing = environment.path().join("bughunter");
    let invocation = environment.path().join("invocation");

    let output = make_doctor(&missing, &invocation).output().unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("bughunter is not installed; run make setup")
    );
    assert!(!invocation.exists());
}

#[test]
fn run_uses_the_installed_binary_and_forwards_scan_options() {
    let environment = tempfile::tempdir().unwrap();
    let binary = environment.path().join("bughunter");
    let invocation = environment.path().join("invocation");
    write_executable(
        &binary,
        "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$CAPTURE_FILE\"\n",
    );

    let output = Command::new("make")
        .arg("run")
        .arg(format!("BUGHUNTER={}", binary.display()))
        .arg("CARGO=/missing/cargo")
        .arg("PROJECT=/tmp/example-project")
        .arg("ARGS=--static-only --no-fail")
        .current_dir(project_root())
        .env("CAPTURE_FILE", &invocation)
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(
        fs::read_to_string(invocation).unwrap(),
        "analyze --project /tmp/example-project --static-only --no-fail\n"
    );
}

fn pinned_value(target: &str) -> String {
    let output = Command::new("make")
        .arg("--no-print-directory")
        .arg(target)
        .current_dir(project_root())
        .output()
        .unwrap();

    assert_success(&output);
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

struct CoverageToolStubs {
    _environment: tempfile::TempDir,
    binaries: std::path::PathBuf,
    cargo: std::path::PathBuf,
    coverage_dir: std::path::PathBuf,
    invocation_log: std::path::PathBuf,
}

impl CoverageToolStubs {
    fn new(reported_version: &str, rustup_run_succeeds: bool) -> Self {
        let environment = tempfile::tempdir().unwrap();
        let binaries = environment.path().join("bin");
        fs::create_dir_all(&binaries).unwrap();

        write_executable(
            &binaries.join("rustup"),
            &format!(
                r#"#!/bin/sh
if [ "$1" = 'run' ]; then
    exit {run_status}
fi
exit 0
"#,
                run_status = u8::from(!rustup_run_succeeds)
            ),
        );
        write_executable(&binaries.join("cargo-llvm-cov"), "#!/bin/sh\nexit 0\n");

        let cargo = environment.path().join("cargo");
        write_executable(
            &cargo,
            &format!(
                r#"#!/bin/sh
if [ "$1" = 'llvm-cov' ] && [ "$2" = '--version' ]; then
    printf 'cargo-llvm-cov %s\n' '{reported_version}'
    exit 0
fi
printf '%s\n' "$*" >> "$INVOCATION_LOG"
exit 0
"#
            ),
        );

        Self {
            binaries,
            cargo,
            coverage_dir: environment.path().join("coverage"),
            invocation_log: environment.path().join("invocations"),
            _environment: environment,
        }
    }

    fn run(&self, target: &str) -> Output {
        Command::new("make")
            .arg(target)
            .arg(format!("CARGO={}", self.cargo.display()))
            .arg(format!("COVERAGE_DIR={}", self.coverage_dir.display()))
            .current_dir(project_root())
            .env("PATH", prepend_to_path(&self.binaries))
            .env("INVOCATION_LOG", &self.invocation_log)
            .output()
            .unwrap()
    }

    fn ran_cargo(&self) -> bool {
        self.invocation_log.exists()
    }
}

#[test]
fn coverage_rejects_a_cargo_llvm_cov_version_other_than_the_pin() {
    let pinned = pinned_value("print-llvm-cov-version");
    let stubs = CoverageToolStubs::new("0.0.1", true);

    let output = stubs.run("coverage");

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("found 0.0.1"), "stdout:\n{stdout}");
    assert!(
        stdout.contains(&format!(
            "cargo install cargo-llvm-cov --version {pinned} --locked --force"
        )),
        "stdout:\n{stdout}"
    );
    assert!(
        !stubs.ran_cargo(),
        "coverage invoked cargo despite an unpinned cargo-llvm-cov version"
    );
}

#[test]
fn coverage_accepts_the_pinned_cargo_llvm_cov_version() {
    let pinned = pinned_value("print-llvm-cov-version");
    let stubs = CoverageToolStubs::new(&pinned, true);

    assert_success(&stubs.run("require-cargo-llvm-cov"));
}

#[test]
fn coverage_requires_the_pinned_nightly_toolchain() {
    let nightly = pinned_value("print-nightly");
    let pinned = pinned_value("print-llvm-cov-version");
    let stubs = CoverageToolStubs::new(&pinned, false);

    let output = stubs.run("coverage");

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains(&format!("toolchain {nightly} is missing")),
        "stdout:\n{stdout}"
    );
    assert!(
        !stubs.ran_cargo(),
        "coverage invoked cargo without the pinned nightly toolchain"
    );
}

struct SanitizerToolStubs {
    _environment: tempfile::TempDir,
    binaries: std::path::PathBuf,
    cargo: std::path::PathBuf,
    invocation_log: std::path::PathBuf,
}

impl SanitizerToolStubs {
    fn new() -> Self {
        let environment = tempfile::tempdir().unwrap();
        let binaries = environment.path().join("bin");
        fs::create_dir_all(&binaries).unwrap();
        write_executable(
            &binaries.join("rustup"),
            r#"#!/bin/sh
if [ "$1" = 'run' ]; then
    exit 0
fi
if [ "$1" = 'component' ]; then
    printf '%s\n' 'rust-src-x86_64-unknown-linux-gnu'
    exit 0
fi
exit 1
"#,
        );
        let cargo = environment.path().join("cargo");
        write_executable(
            &cargo,
            "#!/bin/sh\nprintf '%s\n' \"$*\" > \"$INVOCATION_LOG\"\n",
        );
        let invocation_log = environment.path().join("invocation");
        Self {
            binaries,
            cargo,
            invocation_log,
            _environment: environment,
        }
    }

    fn invocation_for(&self, target: &str) -> String {
        let output = Command::new("make")
            .arg(target)
            .arg(format!("CARGO={}", self.cargo.display()))
            .current_dir(project_root())
            .env("PATH", prepend_to_path(&self.binaries))
            .env("INVOCATION_LOG", &self.invocation_log)
            .output()
            .unwrap();
        assert_success(&output);
        fs::read_to_string(&self.invocation_log)
            .unwrap()
            .trim()
            .to_owned()
    }
}

#[test]
fn address_sanitizer_runs_the_complete_test_suite() {
    let stubs = SanitizerToolStubs::new();

    assert_eq!(
        stubs.invocation_for("sanitize-asan"),
        "+nightly-2025-06-26 test --locked --all-features --lib --bins --tests --target x86_64-unknown-linux-gnu -Zbuild-std -- --test-threads=1"
    );
}

#[test]
fn thread_sanitizer_runs_the_dedicated_race_scenarios() {
    let stubs = SanitizerToolStubs::new();

    assert_eq!(
        stubs.invocation_for("sanitize-tsan"),
        "+nightly-2025-06-26 test --locked --all-features --test sanitizer_scenarios --target x86_64-unknown-linux-gnu -Zbuild-std -- --test-threads=1"
    );
}

struct MaintainerToolStubs {
    _environment: tempfile::TempDir,
    binaries: std::path::PathBuf,
    cargo: std::path::PathBuf,
    corpus: std::path::PathBuf,
    invocation_log: std::path::PathBuf,
}

impl MaintainerToolStubs {
    fn new(reported_cargo_deny_version: Option<&str>) -> Self {
        let environment = tempfile::tempdir().unwrap();
        let binaries = environment.path().join("bin");
        fs::create_dir_all(&binaries).unwrap();
        write_executable(&binaries.join("rustup"), "#!/bin/sh\nexit 0\n");
        write_executable(&binaries.join("cargo-fuzz"), "#!/bin/sh\nexit 0\n");
        if reported_cargo_deny_version.is_some() {
            write_executable(&binaries.join("cargo-deny"), "#!/bin/sh\nexit 0\n");
        }

        let cargo = binaries.join("cargo");
        write_executable(
            &cargo,
            &format!(
                r#"#!/bin/sh
if [ "$1" = 'fuzz' ] && [ "$2" = '--version' ]; then
    printf 'cargo-fuzz %s\n' '{fuzz_version}'
    exit 0
fi
if [ "$1" = 'deny' ] && [ "$2" = '--version' ]; then
    printf 'cargo-deny %s\n' '{deny_version}'
    exit 0
fi
printf '%s\n' "$*" >> "$INVOCATION_LOG"
exit 0
"#,
                fuzz_version = pinned_value("print-cargo-fuzz-version"),
                deny_version = reported_cargo_deny_version.unwrap_or_default()
            ),
        );

        Self {
            binaries,
            cargo,
            corpus: environment.path().join("smoke-corpus"),
            invocation_log: environment.path().join("invocations"),
            _environment: environment,
        }
    }

    fn make(&self, target: &str) -> Command {
        let mut command = Command::new("make");
        command
            .arg(target)
            .arg(format!("CARGO={}", self.cargo.display()))
            .arg(format!("FUZZ_SMOKE_CORPUS={}", self.corpus.display()))
            .current_dir(project_root())
            .env("INVOCATION_LOG", &self.invocation_log);
        command
    }

    fn run(&self, target: &str) -> Output {
        self.make(target)
            .env("PATH", prepend_to_path(&self.binaries))
            .output()
            .unwrap()
    }

    fn run_without_cargo_deny(&self, target: &str) -> Output {
        let inherited = std::env::var_os("PATH").unwrap_or_default();
        let without_tool = std::env::split_paths(&inherited)
            .filter(|directory| !directory.join("cargo-deny").exists());
        let stubs_first = std::iter::once(self.binaries.clone()).chain(without_tool);
        let path = std::env::join_paths(stubs_first).unwrap();
        self.make(target).env("PATH", path).output().unwrap()
    }

    fn invocations(&self) -> Vec<String> {
        fs::read_to_string(&self.invocation_log)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

fn sorted_file_names(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn check_formats_and_lints_both_manifests_with_locked_dependencies() {
    let stubs = MaintainerToolStubs::new(None);

    assert_success(&stubs.run("check"));

    assert_eq!(
        stubs.invocations(),
        [
            "fmt --check",
            "fmt --manifest-path fuzz/Cargo.toml --check",
            "clippy --locked --all-targets --all-features -- -D warnings",
            "clippy --manifest-path fuzz/Cargo.toml --locked --all-targets -- -D warnings",
            "test --locked",
        ]
    );
}

#[test]
fn clean_removes_the_workspace_and_the_fuzz_build_output() {
    let stubs = MaintainerToolStubs::new(None);

    assert_success(&stubs.run("clean"));

    assert_eq!(
        stubs.invocations(),
        ["clean", "clean --manifest-path fuzz/Cargo.toml"]
    );
}

#[test]
fn audit_checks_both_manifests_with_the_pinned_cargo_deny() {
    let pinned = pinned_value("print-cargo-deny-version");
    let stubs = MaintainerToolStubs::new(Some(pinned.as_str()));

    assert_success(&stubs.run("audit"));

    assert_eq!(
        stubs.invocations(),
        ["deny check", "deny --manifest-path fuzz/Cargo.toml check"]
    );
}

#[test]
fn audit_rejects_a_cargo_deny_version_other_than_the_pin() {
    let pinned = pinned_value("print-cargo-deny-version");
    let stubs = MaintainerToolStubs::new(Some("0.0.1"));

    let output = stubs.run("audit");

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("found 0.0.1"), "stdout:\n{stdout}");
    assert!(
        stdout.contains(&format!(
            "cargo install cargo-deny --version {pinned} --locked --force"
        )),
        "stdout:\n{stdout}"
    );
    assert!(
        stubs.invocations().is_empty(),
        "audit ran cargo-deny despite an unpinned version"
    );
}

#[test]
fn audit_reports_a_missing_cargo_deny_with_the_pinned_install_command() {
    let pinned = pinned_value("print-cargo-deny-version");
    let stubs = MaintainerToolStubs::new(None);

    let output = stubs.run_without_cargo_deny("audit");

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains(&format!(
            "cargo-deny {pinned} is required: cargo install cargo-deny --version {pinned} --locked"
        )),
        "stdout:\n{stdout}"
    );
    assert!(
        stubs.invocations().is_empty(),
        "audit ran cargo-deny before checking that it is installed"
    );
}

#[test]
fn fuzz_smoke_runs_from_a_fresh_copy_of_the_committed_seeds() {
    let nightly = pinned_value("print-nightly");
    let stubs = MaintainerToolStubs::new(None);
    let corpus = stubs.corpus.join("static_analysis");
    fs::create_dir_all(&corpus).unwrap();
    fs::write(corpus.join("input-from-a-previous-run"), b"stale").unwrap();

    assert_success(&stubs.run("fuzz-static_analysis"));

    assert_eq!(
        stubs.invocations(),
        [format!(
            "+{nightly} fuzz run static_analysis {} -- -runs=1000 -seed=1 -max_len=4096 -rss_limit_mb=1024 -timeout=25",
            corpus.display()
        )]
    );
    assert_eq!(
        sorted_file_names(&corpus),
        sorted_file_names(&project_root().join("fuzz/seeds/static_analysis"))
    );
}

#[test]
fn fuzz_smoke_applies_the_per_target_resource_bounds() {
    let nightly = pinned_value("print-nightly");
    let stubs = MaintainerToolStubs::new(None);

    assert_success(&stubs.run("fuzz-archive_extraction"));

    let corpus = stubs.corpus.join("archive_extraction");
    assert_eq!(
        stubs.invocations(),
        [format!(
            "+{nightly} fuzz run archive_extraction {} -- -runs=1000 -seed=1 -max_len=8192 -rss_limit_mb=2048 -timeout=25",
            corpus.display()
        )]
    );
    assert_eq!(
        sorted_file_names(&corpus),
        sorted_file_names(&project_root().join("fuzz/seeds/archive_extraction"))
    );
}

const STUB_LICENSE_TREE: &str =
    "bughunter v0.1.0 (/stub/root)\ndemo v1.0.0\nother v2.3.4 (proc-macro)\n";

const STUB_LICENSE_JSON: &str = r#"{
  "overview": [],
  "licenses": [
    {
      "name": "MIT License",
      "id": "MIT",
      "first_of_kind": true,
      "text": "MIT license text",
      "source_path": null,
      "used_by": [
        { "crate": { "name": "demo", "version": "1.0.0" }, "path": null },
        { "crate": { "name": "other", "version": "2.3.4" }, "path": null }
      ]
    }
  ],
  "crates": [
    { "package": { "name": "demo", "version": "1.0.0" }, "license": "MIT" },
    { "package": { "name": "other", "version": "2.3.4" }, "license": "MIT" }
  ]
}
"#;

const CANONICAL_FALLBACK_DIAGNOSTIC: &str =
    "unable to find text for license 'MIT' for crate 'demo 1.0.0', falling back to canonical text";

const BUNDLED_NOTICE_HEADING: &str =
    "Supplemental notice: Unicode character data bundled in tree-sitter";

const ICU_NOTICE_HEADER: &str = "COPYRIGHT AND PERMISSION NOTICE (ICU 58 and later)";

struct LicenseNoticeStubs {
    _environment: tempfile::TempDir,
    binaries: std::path::PathBuf,
    cargo: std::path::PathBuf,
    work_dir: std::path::PathBuf,
    notice: std::path::PathBuf,
    invocation_log: std::path::PathBuf,
    diagnostic: String,
    unstable_regeneration: bool,
    licenses_json: String,
    dependency_tree: String,
    notice_input: std::path::PathBuf,
    packaged_notice: std::path::PathBuf,
}

impl LicenseNoticeStubs {
    fn new(reported_version: &str) -> Self {
        let environment = tempfile::tempdir().unwrap();
        let binaries = environment.path().join("bin");
        fs::create_dir_all(&binaries).unwrap();
        write_executable(&binaries.join("cargo-about"), "#!/bin/sh\nexit 0\n");

        let cargo = binaries.join("cargo");
        write_executable(
            &cargo,
            &format!(
                r#"#!/bin/sh
if [ "$1" = 'about' ] && [ "$2" = '--version' ]; then
    printf 'cargo-about %s\n' '{reported_version}'
    exit 0
fi
if [ "$1" = 'metadata' ]; then
    printf '%s' "$STUB_METADATA"
    exit 0
fi
printf '%s\n' "$*" >> "$INVOCATION_LOG"
if [ "$1" = 'about' ]; then
    output=''
    format='handlebars'
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --output-file) output="$2"; shift ;;
            --format) format="$2"; shift ;;
        esac
        shift
    done
    if [ "$format" = 'json' ]; then
        printf '%s' "$STUB_LICENSE_JSON" > "$output"
    elif [ -n "$STUB_UNSTABLE" ] && [ -f "$STUB_FIRST_NOTICE" ]; then
        printf 'a different notice\n' > "$output"
    else
        printf 'the notice\n' > "$output"
        : > "$STUB_FIRST_NOTICE"
    fi
    if [ -n "$STUB_DIAGNOSTIC" ]; then
        printf '%s\n' "$STUB_DIAGNOSTIC" >&2
    fi
    exit 0
fi
if [ "$1" = 'tree' ]; then
    printf '%s' "$STUB_LICENSE_TREE"
    exit 0
fi
exit 0
"#
            ),
        );

        let notice_input = environment.path().join("bundled-notice.txt");
        let packaged_root = environment.path().join("packaged/tree-sitter-0.25.10");
        let packaged_notice = packaged_root.join("src/unicode/LICENSE");
        let reviewed = project_root().join(pinned_value("print-bundled-notice"));
        fs::create_dir_all(packaged_notice.parent().unwrap()).unwrap();
        fs::copy(&reviewed, &notice_input).unwrap();
        fs::copy(&reviewed, &packaged_notice).unwrap();

        Self {
            binaries,
            cargo,
            work_dir: environment.path().join("license-work"),
            notice: environment.path().join("NOTICE.txt"),
            invocation_log: environment.path().join("invocations"),
            diagnostic: String::new(),
            unstable_regeneration: false,
            licenses_json: STUB_LICENSE_JSON.to_owned(),
            dependency_tree: STUB_LICENSE_TREE.to_owned(),
            notice_input,
            packaged_notice,
            _environment: environment,
        }
    }

    fn reporting(mut self, diagnostic: &str) -> Self {
        self.diagnostic = diagnostic.to_owned();
        self
    }

    fn with_unstable_regeneration(mut self) -> Self {
        self.unstable_regeneration = true;
        self
    }

    fn reporting_licenses(mut self, licenses_json: &str) -> Self {
        self.licenses_json = licenses_json.to_owned();
        self
    }

    fn reporting_dependencies(mut self, dependency_tree: &str) -> Self {
        self.dependency_tree = dependency_tree.to_owned();
        self
    }

    fn with_tampered_notice_input(self) -> Self {
        let mut tampered = fs::read(&self.notice_input).unwrap();
        tampered.extend_from_slice(b"tampered\n");
        fs::write(&self.notice_input, tampered).unwrap();
        self
    }

    fn with_upgraded_packaged_notice(self) -> Self {
        fs::write(&self.packaged_notice, "a revised upstream notice\n").unwrap();
        self
    }

    fn without_packaged_notice(self) -> Self {
        fs::remove_file(&self.packaged_notice).unwrap();
        self
    }

    fn regenerated_notice(&self) -> String {
        fs::read_to_string(self.work_dir.join("regenerated-notice.txt")).unwrap()
    }

    fn make(&self) -> Command {
        let mut command = Command::new("make");
        command
            .arg("license-notice")
            .arg(format!("CARGO={}", self.cargo.display()))
            .arg(format!("LICENSE_WORK_DIR={}", self.work_dir.display()))
            .arg(format!("LICENSE_NOTICE={}", self.notice.display()))
            .arg(format!("BUNDLED_NOTICE={}", self.notice_input.display()))
            .current_dir(project_root())
            .env("INVOCATION_LOG", &self.invocation_log)
            .env("STUB_LICENSE_JSON", &self.licenses_json)
            .env("STUB_LICENSE_TREE", &self.dependency_tree)
            .env("STUB_DIAGNOSTIC", &self.diagnostic)
            .env(
                "STUB_METADATA",
                format!(
                    r#"{{"packages":[{{"name":"tree-sitter","manifest_path":"{}/Cargo.toml"}}]}}"#,
                    self.packaged_notice
                        .parent()
                        .unwrap()
                        .parent()
                        .unwrap()
                        .parent()
                        .unwrap()
                        .display()
                ),
            )
            .env(
                "STUB_FIRST_NOTICE",
                self._environment.path().join("first-notice"),
            )
            .env(
                "STUB_UNSTABLE",
                if self.unstable_regeneration { "1" } else { "" },
            );
        command
    }

    fn run(&self) -> Output {
        self.make()
            .env("PATH", prepend_to_path(&self.binaries))
            .output()
            .unwrap()
    }

    fn run_without_cargo_about(&self) -> Output {
        let inherited = std::env::var_os("PATH").unwrap_or_default();
        let without_tool = std::env::split_paths(&inherited)
            .filter(|directory| !directory.join("cargo-about").exists());
        let path = std::env::join_paths(std::iter::once(self.binaries.clone()).chain(without_tool))
            .unwrap();
        let stubs_only = self.binaries.join("cargo-about");
        fs::remove_file(stubs_only).unwrap();
        self.make().env("PATH", path).output().unwrap()
    }

    fn invocations(&self) -> Vec<String> {
        fs::read_to_string(&self.invocation_log)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

#[test]
fn license_notice_generates_from_the_locked_release_graph() {
    let stubs = LicenseNoticeStubs::new(&pinned_value("print-cargo-about-version"));

    let output = stubs.run();

    assert_success(&output);
    let invocations = stubs.invocations();
    let target = pinned_value("print-release-target");

    let notices: Vec<&String> = invocations
        .iter()
        .filter(|invocation| {
            invocation.starts_with("about") && !invocation.contains("--format json")
        })
        .collect();
    assert_eq!(
        notices.len(),
        2,
        "the notice must be generated twice for a byte comparison: {invocations:?}"
    );

    for invocation in &invocations {
        if invocation.starts_with("about") {
            for flag in [
                "--config about.toml",
                "--manifest-path Cargo.toml",
                "--locked",
                "--fail",
            ] {
                assert!(
                    invocation.contains(flag),
                    "cargo about was called without {flag}: {invocation}"
                );
            }
            assert!(
                invocation.contains(&format!("--target {target}")),
                "cargo about resolved a target other than {target}: {invocation}"
            );
        }
    }

    let tree = invocations
        .iter()
        .find(|invocation| invocation.starts_with("tree"))
        .expect("the notice must be compared against the cargo dependency graph");
    for flag in ["--locked", "--edges normal", "--no-dedupe"] {
        assert!(
            tree.contains(flag),
            "cargo tree was called without {flag}: {tree}"
        );
    }
    assert!(tree.contains(&format!("--target {target}")), "tree: {tree}");

    assert!(
        fs::read_to_string(&stubs.notice)
            .unwrap()
            .starts_with("the notice\n"),
        "the generated notice must lead with the cargo-about output"
    );
}

#[test]
fn license_notice_rejects_a_cargo_about_version_other_than_the_pin() {
    let pinned = pinned_value("print-cargo-about-version");
    let stubs = LicenseNoticeStubs::new("0.0.1");

    let output = stubs.run();

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("found 0.0.1"), "stdout:\n{stdout}");
    assert!(
        stdout.contains(&format!(
            "cargo install cargo-about --version {pinned} --locked --features cli --force"
        )),
        "stdout:\n{stdout}"
    );
    assert!(
        stubs.invocations().is_empty(),
        "an unpinned cargo-about still generated a notice"
    );
}

#[test]
fn license_notice_reports_a_missing_cargo_about_with_the_pinned_install_command() {
    let pinned = pinned_value("print-cargo-about-version");
    let stubs = LicenseNoticeStubs::new(&pinned);

    let output = stubs.run_without_cargo_about();

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains(&format!(
            "cargo install cargo-about --version {pinned} --locked --features cli"
        )),
        "stdout:\n{stdout}"
    );
}

#[test]
fn license_notice_rejects_a_canonical_license_text_fallback() {
    let stubs = LicenseNoticeStubs::new(&pinned_value("print-cargo-about-version"))
        .reporting(CANONICAL_FALLBACK_DIAGNOSTIC);

    let output = stubs.run();

    assert!(
        !output.status.success(),
        "a canonical text fallback must fail the release even though cargo-about exits zero"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("falling back to canonical text"),
        "the offending diagnostic must be reported:\n{stdout}"
    );
    assert!(
        stdout.contains("checksum-bound clarification in about.toml"),
        "stdout:\n{stdout}"
    );
}

#[test]
fn license_notice_rejects_a_stale_clarification_checksum() {
    let stubs = LicenseNoticeStubs::new(&pinned_value("print-cargo-about-version")).reporting(
        "failed to validate all files specified in clarification for crate demo 1.0.0: checksum mismatch",
    );

    let output = stubs.run();

    assert!(
        !output.status.success(),
        "a clarification that no longer validates must fail the release"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("failed to validate all files specified in clarification"),
        "the offending diagnostic must be reported:\n{stdout}"
    );
}

#[test]
fn license_notice_rejects_an_unstable_regeneration() {
    let stubs = LicenseNoticeStubs::new(&pinned_value("print-cargo-about-version"))
        .with_unstable_regeneration();

    let output = stubs.run();

    assert!(
        !output.status.success(),
        "a notice that changes between runs is not reproducible"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stdout.contains("differ"),
        "the byte comparison, not an earlier gate, must reject the unstable notice\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
fn license_notice_rejects_an_unattributed_package() {
    let stubs = LicenseNoticeStubs::new(&pinned_value("print-cargo-about-version"))
        .reporting_licenses(
            r#"{
  "overview": [],
  "licenses": [
    {
      "name": "MIT License",
      "id": "MIT",
      "first_of_kind": true,
      "text": "MIT license text",
      "source_path": null,
      "used_by": [{ "crate": { "name": "demo", "version": "1.0.0" }, "path": null }]
    }
  ],
  "crates": [
    { "package": { "name": "demo", "version": "1.0.0" }, "license": "MIT" },
    { "package": { "name": "other", "version": "2.3.4" }, "license": "MIT" }
  ]
}
"#,
        );

    let output = stubs.run();

    assert!(
        !output.status.success(),
        "a package with no attributed license text must fail the release"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("leaves a package unattributed"),
        "stdout:\n{stdout}"
    );
}

#[test]
fn license_notice_rejects_a_notice_that_misses_a_release_dependency() {
    let stubs = LicenseNoticeStubs::new(&pinned_value("print-cargo-about-version"))
        .reporting_dependencies(
            "bughunter v0.1.0 (/stub/root)\ndemo v1.0.0\nother v2.3.4\nthird v3.0.0\n",
        );

    let output = stubs.run();

    assert!(
        !output.status.success(),
        "a locked dependency absent from the notice must fail the release"
    );
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("third v3.0.0"),
        "the missing dependency must be named in the diff"
    );
}

#[test]
fn license_notice_appends_the_bundled_notice_to_both_generated_copies() {
    let stubs = LicenseNoticeStubs::new(&pinned_value("print-cargo-about-version"));

    let output = stubs.run();

    assert_success(&output);
    let shipped = fs::read_to_string(&stubs.notice).unwrap();
    let regenerated = stubs.regenerated_notice();

    for (label, notice) in [("shipped", &shipped), ("regenerated", &regenerated)] {
        assert!(
            notice.contains(BUNDLED_NOTICE_HEADING),
            "the {label} notice is missing the supplemental heading"
        );
        assert!(
            notice.contains(ICU_NOTICE_HEADER),
            "the {label} notice is missing the bundled Unicode notice"
        );
    }
    assert_eq!(
        shipped, regenerated,
        "both notices must carry the supplement so the byte comparison covers what ships"
    );
    assert!(
        shipped.starts_with("the notice\n"),
        "the supplement must be appended, not prepended"
    );
}

#[test]
fn license_notice_rejects_a_bundled_notice_that_fails_its_checksum() {
    let stubs = LicenseNoticeStubs::new(&pinned_value("print-cargo-about-version"))
        .with_tampered_notice_input();

    let output = stubs.run();

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("does not match the reviewed checksum"),
        "stdout:\n{stdout}"
    );
    assert!(
        stubs.invocations().is_empty(),
        "the bundled notice must be checked before the notice is generated"
    );
}

#[test]
fn license_notice_rejects_a_bundled_notice_that_drifts_from_the_package() {
    let stubs = LicenseNoticeStubs::new(&pinned_value("print-cargo-about-version"))
        .with_upgraded_packaged_notice();

    let output = stubs.run();

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("no longer matches the packaged notice"),
        "stdout:\n{stdout}"
    );
    assert!(
        stubs.invocations().is_empty(),
        "package drift must be caught before the notice is generated"
    );
}

#[test]
fn license_notice_rejects_a_crate_that_stopped_shipping_the_bundled_notice() {
    let stubs = LicenseNoticeStubs::new(&pinned_value("print-cargo-about-version"))
        .without_packaged_notice();

    let output = stubs.run();

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("no longer ships src/unicode/LICENSE"),
        "stdout:\n{stdout}"
    );
    assert!(stubs.invocations().is_empty());
}

#[test]
fn install_and_uninstall_honor_staging_prefix_and_build_configuration() {
    let project = tempfile::tempdir().unwrap();
    fs::copy(
        project_root().join("Makefile"),
        project.path().join("Makefile"),
    )
    .unwrap();
    let binary = project.path().join("target/debug/bughunter");
    fs::create_dir_all(binary.parent().unwrap()).unwrap();
    write_executable(&binary, "#!/bin/sh\nexit 0\n");
    let stage = project.path().join("stage");
    let prefix = "/opt/bughunter";

    let installed = Command::new("make")
        .arg("install")
        .arg("CARGO=/bin/true")
        .arg("CONFIG=debug")
        .arg(format!("DESTDIR={}", stage.display()))
        .arg(format!("PREFIX={prefix}"))
        .current_dir(project.path())
        .output()
        .unwrap();

    assert_success(&installed);
    let installed_binary = stage.join("opt/bughunter/bin/bughunter");
    assert_eq!(
        fs::read_to_string(&installed_binary).unwrap(),
        "#!/bin/sh\nexit 0\n"
    );
    assert_ne!(
        fs::metadata(&installed_binary)
            .unwrap()
            .permissions()
            .mode()
            & 0o111,
        0
    );

    let uninstalled = Command::new("make")
        .arg("uninstall")
        .arg(format!("DESTDIR={}", stage.display()))
        .arg(format!("PREFIX={prefix}"))
        .current_dir(project.path())
        .output()
        .unwrap();

    assert_success(&uninstalled);
    assert!(!installed_binary.exists());
}
