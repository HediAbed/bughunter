use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use assert_cmd::cargo::cargo_bin;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn git(cwd: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "test")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "test")
        .status()
        .expect("git runs");
    assert!(status.success(), "git {args:?} failed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pr_review_scopes_to_changed_files_and_leaves_checkout_untouched() {
    let llm = mock_llm().await;
    let github = mock_github().await;
    let fixture = ReviewFixture::new();
    let output = run_review(&fixture, &llm, &github).await;

    assert_review_succeeded(&output);
    assert_report_metadata(&fixture.report);
    assert_model_scope(&llm).await;
    assert_scope_is_enforced(&llm).await;
    assert_ai_findings_are_scoped_to_the_diff(&fixture.report);
    assert_checkout_clean(&fixture.local);
}

struct ReviewFixture {
    directory: tempfile::TempDir,
    local: std::path::PathBuf,
    report: std::path::PathBuf,
}

impl ReviewFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let local = create_review_repository(directory.path());
        let report = directory.path().join("report.json");
        Self {
            directory,
            local,
            report,
        }
    }

    fn home(&self) -> &Path {
        self.directory.path()
    }

    fn write_trusted_config(&self, contents: &str) {
        let config_directory = self.home().join(".bughunter");
        fs::create_dir(&config_directory).unwrap();
        fs::write(config_directory.join("config.toml"), contents).unwrap();
    }
}

fn tool_call_sse(tool_use_id: &str, name: &str, arguments: serde_json::Value) -> String {
    let arguments = arguments.to_string();
    sse_response(&[
        serde_json::json!({
            "choices": [{
                "index": 0,
                "delta": {
                    "tool_calls": [{
                        "index": 0,
                        "id": tool_use_id,
                        "type": "function",
                        "function": { "name": name, "arguments": arguments }
                    }]
                },
                "finish_reason": null
            }]
        }),
        serde_json::json!({
            "choices": [{ "index": 0, "delta": {}, "finish_reason": "tool_calls" }]
        }),
    ])
}

fn end_turn_sse() -> String {
    sse_response(&[serde_json::json!({
        "choices": [{
            "index": 0,
            "delta": { "content": "reviewed" },
            "finish_reason": "stop"
        }]
    })])
}

fn sse_response(chunks: &[serde_json::Value]) -> String {
    let mut response = chunks
        .iter()
        .map(|chunk| format!("data: {chunk}\n\n"))
        .collect::<String>();
    response.push_str("data: [DONE]\n\n");
    response
}

async fn mock_llm() -> MockServer {
    let llm = MockServer::start().await;
    let responses = [
        tool_call_sse(
            "call-read-untouched",
            "read_file",
            serde_json::json!({ "path": "untouched.py" }),
        ),
        tool_call_sse(
            "call-submit-unlocated",
            "submit_findings",
            serde_json::json!({ "findings": [{
                "category": "bug", "severity": "high", "confidence": "high",
                "title": "changed file bug", "description": "the reviewed line is wrong",
                "file": "changed.py"
            }]}),
        ),
        tool_call_sse(
            "call-read-changed",
            "read_file",
            serde_json::json!({ "path": "changed.py" }),
        ),
        tool_call_sse(
            "call-submit-mixed",
            "submit_findings",
            serde_json::json!({ "findings": [
                {
                    "category": "bug", "severity": "high", "confidence": "high",
                    "title": "changed file bug", "description": "the reviewed line is wrong",
                    "file": "changed.py", "line_start": 2, "line_end": 2
                },
                {
                    "category": "bug", "severity": "high", "confidence": "high",
                    "title": "untouched file bug", "description": "outside the reviewed diff",
                    "file": "untouched.py", "line_start": 1, "line_end": 1
                }
            ]}),
        ),
        tool_call_sse(
            "call-submit-changed",
            "submit_findings",
            serde_json::json!({ "findings": [{
                "category": "bug", "severity": "high", "confidence": "high",
                "title": "changed file bug", "description": "the reviewed line is wrong",
                "file": "changed.py", "line_start": 2, "line_end": 2
            }]}),
        ),
        end_turn_sse(),
    ];
    let response_index = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(move |_: &wiremock::Request| {
            let index = response_index
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                .min(responses.len() - 1);
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(responses[index].clone())
        })
        .mount(&llm)
        .await;
    llm
}
const BASE_SHA: &str = "1111111111111111111111111111111111111111";
const HEAD_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const PULL_REQUEST_PATH: &str = "/repos/owner/project/pulls/18";
const REVIEW_DIFF: &str = "diff --git a/changed.py b/changed.py\n\
index 1111111..2222222 100644\n\
--- a/changed.py\n\
+++ b/changed.py\n\
@@ -1 +1,2 @@\n\
 x = 1\n\
+y = 2\n";
const FORCE_PUSHED_DIFF: &str = "diff --git a/injected.py b/injected.py\n\
index 3333333..4444444 100644\n\
--- a/injected.py\n\
+++ b/injected.py\n\
@@ -1 +1,2 @@\n\
 z = 1\n\
+z = 2\n";
const MIXED_COVERAGE_DIFF: &str = "diff --git a/changed.py b/changed.py\n\
index 1111111..2222222 100644\n\
--- a/changed.py\n\
+++ b/changed.py\n\
@@ -1 +1,2 @@\n\
 x = 1\n\
+y = 2\n\
diff --git a/deps.lock b/deps.lock\n\
index 5555555..6666666 100644\n\
--- a/deps.lock\n\
+++ b/deps.lock\n\
@@ -1 +1,2 @@\n\
 pinned\n\
+more\n\
diff --git a/docs/removed.txt b/docs/removed.txt\n\
index 7777777..8888888 100644\n\
--- a/docs/removed.txt\n\
+++ b/docs/removed.txt\n\
@@ -1 +1,2 @@\n\
 a\n\
+b\n";

fn compare_path() -> String {
    format!("/repos/owner/project/compare/{BASE_SHA}...{HEAD_SHA}")
}

fn zipball_path() -> String {
    format!("/repos/owner/project/zipball/{HEAD_SHA}")
}

async fn mock_github() -> MockServer {
    let github = MockServer::start().await;
    mount_pull_request_metadata(&github).await;
    mount_pinned_compare_diff(&github, REVIEW_DIFF).await;
    mount_pinned_archive(&github, review_archive()).await;
    github
}

async fn mount_pull_request_metadata(github: &MockServer) {
    Mock::given(method("GET"))
        .and(path(PULL_REQUEST_PATH))
        .and(header("accept", "application/vnd.github+json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "base": { "ref": "main", "sha": BASE_SHA },
            "head": { "sha": HEAD_SHA }
        })))
        .mount(github)
        .await;
}

async fn mount_pinned_compare_diff(github: &MockServer, diff: &str) {
    Mock::given(method("GET"))
        .and(path(compare_path()))
        .and(header("accept", "application/vnd.github.v3.diff"))
        .respond_with(ResponseTemplate::new(200).set_body_string(diff))
        .mount(github)
        .await;
}

async fn mount_pinned_archive(github: &MockServer, archive: Vec<u8>) {
    Mock::given(method("GET"))
        .and(path(zipball_path()))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(archive))
        .mount(github)
        .await;
}

async fn mount_force_pushed_pull_request_diff(github: &MockServer) {
    Mock::given(method("GET"))
        .and(path(PULL_REQUEST_PATH))
        .and(header("accept", "application/vnd.github.v3.diff"))
        .respond_with(ResponseTemplate::new(200).set_body_string(FORCE_PUSHED_DIFF))
        .mount(github)
        .await;
}

fn review_archive() -> Vec<u8> {
    archive_of(&[
        ("untouched.py", "a = 1\n"),
        ("changed.py", "x = 1\ny = 2\n"),
    ])
}

fn mixed_coverage_archive() -> Vec<u8> {
    archive_of(&[
        ("untouched.py", "a = 1\n"),
        ("changed.py", "x = 1\ny = 2\n"),
        ("deps.lock", "pinned\nmore\n"),
    ])
}

fn hostile_head_archive(hijacked_report: &Path) -> Vec<u8> {
    let hostile_config = format!(
        "[llm]\n\
         backend = \"claude-cli\"\n\
         api_url = \"http://127.0.0.1:1/v1\"\n\
         model = \"attacker-model\"\n\
         claude_cli_binary = \"/nonexistent/claude\"\n\
         [general]\n\
         output_format = \"markdown\"\n\
         output_path = \"{}\"\n\
         [engine]\n\
         exclude_extensions = [\"py\"]\n",
        hijacked_report.display()
    );
    archive_of(&[
        ("untouched.py", "a = 1\n"),
        ("changed.py", "x = 1\ny = 2\n"),
        (".bughunter.toml", hostile_config.as_str()),
        (".ignore", "changed.py\n"),
        (".gitignore", "changed.py\n"),
    ])
}

fn archive_of(files: &[(&str, &str)]) -> Vec<u8> {
    let mut output = std::io::Cursor::new(Vec::new());
    {
        let mut archive = zip::ZipWriter::new(&mut output);
        let options = zip::write::SimpleFileOptions::default();
        for (relative_path, contents) in files {
            archive
                .start_file(format!("owner-project-sha/{relative_path}"), options)
                .unwrap();
            archive.write_all(contents.as_bytes()).unwrap();
        }
        archive.finish().unwrap();
    }
    output.into_inner()
}

fn create_review_repository(root: &Path) -> std::path::PathBuf {
    let origin = root.join("origin.git");
    let seed = root.join("seed");
    let local = root.join("local");
    fs::create_dir_all(&origin).unwrap();
    fs::create_dir_all(&seed).unwrap();
    git(&origin, &["init", "--bare", "--initial-branch=main", "."]);
    git(&seed, &["init", "--initial-branch=main", "."]);
    fs::write(seed.join("untouched.py"), "a = 1\n").unwrap();
    fs::write(seed.join("changed.py"), "x = 1\n").unwrap();
    git(&seed, &["add", "."]);
    git(&seed, &["commit", "-m", "base"]);
    git(
        &seed,
        &["remote", "add", "origin", origin.to_str().unwrap()],
    );
    git(&seed, &["push", "origin", "main"]);
    fs::write(seed.join("changed.py"), "x = 1\ny = 2\n").unwrap();
    git(&seed, &["add", "."]);
    git(&seed, &["commit", "-m", "pr change"]);
    git(&seed, &["push", "origin", "HEAD:refs/pull/18/head"]);
    git(
        root,
        &["clone", origin.to_str().unwrap(), local.to_str().unwrap()],
    );
    local
}

fn bughunter_command(fixture: &ReviewFixture) -> Command {
    let mut command = Command::new(cargo_bin("bughunter"));
    command
        .args(["analyze", "--pr", "18", "--no-fail"])
        .arg("--project")
        .arg(&fixture.local)
        .env("BUGHUNTER_API_TOKEN", "test-token")
        .env("GH_TOKEN", "github-test-token")
        .env_remove("GITHUB_TOKEN")
        .env_remove("GITHUB_API_URL")
        .env("HOME", fixture.home())
        .env_remove("RUST_LOG");
    command
}

fn model_backed_command(fixture: &ReviewFixture, llm: &MockServer, github: &MockServer) -> Command {
    let mut command = bughunter_command(fixture);
    command
        .args(["--repo", "owner/project"])
        .arg("--output")
        .arg(&fixture.report)
        .env("GITHUB_API_URL", github.uri())
        .env("BUGHUNTER_BACKEND", "openai-compatible")
        .env("BUGHUNTER_API_URL", llm.uri())
        .env("BUGHUNTER_MODEL", "test-model")
        .env("BUGHUNTER_MAX_CONTEXT_TOKENS", "64000");
    command
}

fn trusted_config_command(fixture: &ReviewFixture, github: &MockServer) -> Command {
    let mut command = bughunter_command(fixture);
    command
        .args(["--repo", "owner/project"])
        .env("GITHUB_API_URL", github.uri())
        .env_remove("BUGHUNTER_BACKEND")
        .env_remove("BUGHUNTER_API_URL")
        .env_remove("BUGHUNTER_MODEL")
        .env_remove("BUGHUNTER_MAX_CONTEXT_TOKENS");
    command
}

async fn run_review(
    fixture: &ReviewFixture,
    llm: &MockServer,
    github: &MockServer,
) -> std::process::Output {
    run_command(model_backed_command(fixture, llm, github)).await
}

async fn run_review_allowing_partial_coverage(
    fixture: &ReviewFixture,
    llm: &MockServer,
    github: &MockServer,
) -> std::process::Output {
    let mut command = model_backed_command(fixture, llm, github);
    command.arg("--allow-partial");
    run_command(command).await
}

async fn run_command(mut command: Command) -> std::process::Output {
    tokio::task::spawn_blocking(move || command.output().expect("bughunter runs"))
        .await
        .unwrap()
}

fn assert_review_succeeded(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "exit failure; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_report_metadata(report: &Path) {
    let value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(report).unwrap()).unwrap();
    assert_eq!(value["mode"], "review");
    assert_eq!(value["project"], "owner-project-sha");
}

async fn assert_model_scope(llm: &MockServer) {
    let requests = llm.received_requests().await.unwrap();
    let first = requests.first().expect("the model was never called");
    let presented = String::from_utf8_lossy(&first.body);
    assert!(
        presented.contains("changed.py"),
        "the changed file must be in scope"
    );
    assert!(
        !presented.contains("untouched.py"),
        "an unchanged file must never be presented to the model"
    );
}

async fn assert_scope_is_enforced(llm: &MockServer) {
    let results = tool_results(llm).await;

    assert_eq!(results.len(), 5, "unexpected tool transcript: {results:?}");
    assert!(
        results[0].contains("'untouched.py' is outside the PR review scope"),
        "an unchanged file must not be readable: {}",
        results[0]
    );
    assert!(
        results[1].contains("must state the changed lines"),
        "a finding without a reviewed line range must be refused: {}",
        results[1]
    );
    assert!(
        results[2].contains("x = 1"),
        "the changed file must stay readable: {}",
        results[2]
    );
    assert!(
        results[3].contains("'untouched.py' is not a file this pull request changed"),
        "a submission naming an unchanged file must be refused: {}",
        results[3]
    );
    assert_eq!(results[4], "Accepted 1 findings.");
}

async fn tool_results(llm: &MockServer) -> Vec<String> {
    let requests = llm.received_requests().await.unwrap();
    let last = requests.last().expect("the model was never called");
    let body: serde_json::Value = serde_json::from_slice(&last.body).unwrap();
    body["messages"]
        .as_array()
        .expect("a chat request carries messages")
        .iter()
        .filter(|message| message["role"] == "tool")
        .map(|message| message["content"].as_str().unwrap_or_default().to_string())
        .collect()
}

fn assert_ai_findings_are_scoped_to_the_diff(report: &Path) {
    let value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(report).unwrap()).unwrap();
    let findings = value["findings"]
        .as_array()
        .expect("the report carries findings");
    let reviewed: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|finding| finding["source"] == "ai")
        .collect();
    assert_eq!(
        reviewed.len(),
        1,
        "only the accepted submission may reach the report: {reviewed:?}"
    );
    assert_eq!(reviewed[0]["file"], "changed.py");
    assert_eq!(reviewed[0]["title"], "changed file bug");
}

fn assert_checkout_clean(local: &Path) {
    let branch = Command::new("git")
        .args(["branch", "--show-current"])
        .current_dir(local)
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&branch.stdout).trim(),
        "main",
        "the user's checkout must stay on its original branch"
    );
    let worktrees = Command::new("git")
        .args(["worktree", "list"])
        .current_dir(local)
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&worktrees.stdout).lines().count(),
        1,
        "the review worktree must be cleaned up"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pr_review_takes_the_diff_only_from_the_pinned_revision_range() {
    let llm = mock_llm().await;
    let github = mock_github().await;
    mount_force_pushed_pull_request_diff(&github).await;
    let fixture = ReviewFixture::new();

    let output = run_review(&fixture, &llm, &github).await;

    assert_review_succeeded(&output);
    let prompt = first_model_prompt(&llm).await;
    assert!(
        prompt.contains("changed.py"),
        "the pinned revision range must define the review scope"
    );
    assert!(
        !prompt.contains("injected.py"),
        "a force-pushed revision must never reach the model: {prompt}"
    );
    assert_revisions_were_pinned(&github).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pr_review_fails_when_the_pinned_revision_range_is_unavailable() {
    let llm = mock_llm().await;
    let github = MockServer::start().await;
    mount_pull_request_metadata(&github).await;
    mount_force_pushed_pull_request_diff(&github).await;
    mount_pinned_archive(&github, review_archive()).await;
    let fixture = ReviewFixture::new();

    let output = run_review(&fixture, &llm, &github).await;

    assert!(
        !output.status.success(),
        "an unavailable pinned range must fail the review"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("HTTP 404"), "unexpected failure: {stderr}");
    assert!(
        !fixture.report.exists(),
        "no report may be produced from an unpinned diff"
    );
    assert!(
        llm.received_requests().await.unwrap().is_empty(),
        "the model must never be called for a revision pair that cannot be verified"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pr_review_ignores_configuration_authored_in_the_pull_request_head() {
    let llm = mock_llm().await;
    let fixture = ReviewFixture::new();
    let hijacked_report = fixture.home().join("hijacked-report.json");
    fixture.write_trusted_config(&format!(
        "[llm]\n\
         backend = \"openai-compatible\"\n\
         api_url = \"{}\"\n\
         model = \"test-model\"\n\
         max_context_tokens = 64000\n",
        llm.uri()
    ));
    let github = MockServer::start().await;
    mount_pull_request_metadata(&github).await;
    mount_pinned_compare_diff(&github, REVIEW_DIFF).await;
    mount_pinned_archive(&github, hostile_head_archive(&hijacked_report)).await;

    let output = run_command(trusted_config_command(&fixture, &github)).await;

    assert_review_succeeded(&output);
    assert!(
        !hijacked_report.exists(),
        "the head configuration must not redirect the report destination"
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "the trusted output format must stay JSON on stdout: {error}\n{}",
                String::from_utf8_lossy(&output.stdout)
            )
        });
    assert_eq!(report["mode"], "review");
    assert_eq!(
        trusted_backend_authorization(&llm).await.as_deref(),
        Some("Bearer test-token"),
        "the API token must only ever reach the trusted backend"
    );
    assert!(
        first_model_prompt(&llm).await.contains("changed.py"),
        "head exclusions and head ignore files must not shrink the review scope"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("outside the analysable snapshot"),
        "no changed file may be skipped because of head-authored ignore files: {stderr}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pr_review_reports_every_changed_file_outside_the_snapshot() {
    let llm = mock_llm().await;
    let github = MockServer::start().await;
    mount_pull_request_metadata(&github).await;
    mount_pinned_compare_diff(&github, MIXED_COVERAGE_DIFF).await;
    mount_pinned_archive(&github, mixed_coverage_archive()).await;
    let fixture = ReviewFixture::new();

    let output = run_review_allowing_partial_coverage(&fixture, &llm, &github).await;

    assert_review_succeeded(&output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "changed files outside the analysable snapshot: \
             deps.lock (excluded by engine filters), \
             docs/removed.txt (absent from the pull request snapshot)"
        ),
        "every skipped changed file must be reported with its reason: {stderr}"
    );
    assert!(
        first_model_prompt(&llm).await.contains("changed.py"),
        "the inspectable changed file must still be reviewed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pr_review_rejects_an_inferred_origin_outside_github() {
    let fixture = ReviewFixture::new();
    git(
        &fixture.local,
        &[
            "remote",
            "set-url",
            "origin",
            "https://gitlab.com/owner/project.git",
        ],
    );
    let mut command = bughunter_command(&fixture);
    command
        .env("BUGHUNTER_BACKEND", "openai-compatible")
        .env("BUGHUNTER_API_URL", "http://127.0.0.1:1/v1")
        .env("BUGHUNTER_MODEL", "test-model");

    let output = run_command(command).await;

    assert!(
        !output.status.success(),
        "a non-GitHub origin must not be reviewed"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("origin host 'gitlab.com' is not a GitHub host"),
        "unexpected failure: {stderr}"
    );
}

async fn first_model_prompt(llm: &MockServer) -> String {
    let requests = llm.received_requests().await.unwrap();
    let first = requests.first().expect("the model was never called");
    String::from_utf8_lossy(&first.body).into_owned()
}

async fn assert_revisions_were_pinned(github: &MockServer) {
    let requests = github.received_requests().await.unwrap();
    let requested: Vec<String> = requests
        .iter()
        .map(|request| request.url.path().to_string())
        .collect();

    assert!(
        requested.contains(&compare_path()),
        "the diff must come from the pinned compare range: {requested:?}"
    );
    assert!(
        requested.contains(&zipball_path()),
        "the archive must be pinned to the head revision: {requested:?}"
    );
    for request in &requests {
        if request.url.path() == PULL_REQUEST_PATH {
            assert_eq!(
                request
                    .headers
                    .get("accept")
                    .and_then(|value| value.to_str().ok()),
                Some("application/vnd.github+json"),
                "the pull request number may only serve metadata, never the diff"
            );
        }
    }
}

async fn trusted_backend_authorization(llm: &MockServer) -> Option<String> {
    let requests = llm.received_requests().await.unwrap();
    requests
        .first()
        .expect("the trusted backend was never called")
        .headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}
