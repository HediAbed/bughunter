use std::io::{Read, Write};
use std::path::Path;

use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::header::ACCEPT;
use reqwest::{StatusCode, Url, redirect};
use serde::Deserialize;

use super::ReviewError;

const GITHUB_API_BASE: &str = "https://api.github.com/";
const GITHUB_DIFF_MEDIA_TYPE: &str = "application/vnd.github.v3.diff";
const GITHUB_JSON_MEDIA_TYPE: &str = "application/vnd.github+json";
const MAX_REDIRECTS: usize = 5;
const GITHUB_REMOTE_HOSTS: [&str; 3] = ["github.com", "www.github.com", "ssh.github.com"];

#[derive(Clone, Copy)]
pub(super) struct GitHubLimits {
    pub(super) max_metadata_bytes: usize,
    pub(super) max_diff_bytes: usize,
    pub(super) max_archive_bytes: usize,
    pub(super) max_error_bytes: usize,
}

impl Default for GitHubLimits {
    fn default() -> Self {
        Self {
            max_metadata_bytes: 1024 * 1024,
            max_diff_bytes: 32 * 1024 * 1024,
            max_archive_bytes: 256 * 1024 * 1024,
            max_error_bytes: 64 * 1024,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RepositorySlug(String);

impl RepositorySlug {
    pub(super) fn parse(raw: &str) -> Result<Self, ReviewError> {
        let mut parts = raw.split('/');
        let owner = parts.next().unwrap_or_default();
        let repository = parts.next().unwrap_or_default();
        if parts.next().is_some()
            || !valid_slug_component(owner, 39)
            || !valid_slug_component(repository, 100)
        {
            return Err(ReviewError::GitHub(format!(
                "invalid GitHub repository slug '{raw}'; expected owner/repository"
            )));
        }
        Ok(Self(format!("{owner}/{repository}")))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

fn valid_slug_component(component: &str, max_length: usize) -> bool {
    !component.is_empty()
        && component.len() <= max_length
        && component != "."
        && component != ".."
        && component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[derive(Debug)]
pub(super) struct PullRequestMetadata {
    pub(super) base_ref: String,
    pub(super) revisions: PinnedRevisions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PinnedRevisions {
    base_sha: String,
    head_sha: String,
}

impl PinnedRevisions {
    pub(super) fn parse(base_sha: &str, head_sha: &str) -> Result<Self, ReviewError> {
        Ok(Self {
            base_sha: commit_sha(base_sha, "base")?,
            head_sha: commit_sha(head_sha, "head")?,
        })
    }

    pub(super) fn head_sha(&self) -> &str {
        &self.head_sha
    }

    fn compare_range(&self) -> String {
        format!("{}...{}", self.base_sha, self.head_sha)
    }
}

fn commit_sha(value: &str, label: &str) -> Result<String, ReviewError> {
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ReviewError::GitHub(format!(
            "pull request {label} commit is invalid"
        )));
    }
    Ok(value.to_ascii_lowercase())
}

#[derive(Clone, Debug)]
pub(super) struct GitHubHostPolicy {
    api_host: String,
}

impl GitHubHostPolicy {
    pub(super) fn with_api_host(api_host: &str) -> Self {
        Self {
            api_host: normalized_host(api_host),
        }
    }

    pub(super) fn accepts(&self, host: &str) -> bool {
        let host = normalized_host(host);
        if host.is_empty() {
            return false;
        }
        GITHUB_REMOTE_HOSTS.contains(&host.as_str()) || host == self.api_host
    }
}

fn normalized_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

struct AuthToken(String);

pub(super) struct GitHubClient {
    http: Client,
    api_base: Url,
    token: Option<AuthToken>,
    limits: GitHubLimits,
}

impl GitHubClient {
    pub(super) fn github(token: Option<String>) -> Result<Self, ReviewError> {
        let raw_api_base =
            std::env::var("GITHUB_API_URL").unwrap_or_else(|_| GITHUB_API_BASE.to_string());
        Self::new(
            parse_api_base(raw_api_base)?,
            token,
            GitHubLimits::default(),
        )
    }

    pub(super) fn new(
        api_base: Url,
        token: Option<String>,
        limits: GitHubLimits,
    ) -> Result<Self, ReviewError> {
        validate_api_base(&api_base)?;
        let redirect_policy = redirect_policy(&api_base)?;
        let http = Client::builder()
            .user_agent(crate::version::USER_AGENT)
            .redirect(redirect_policy)
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .map_err(network_error)?;
        Ok(Self {
            http,
            api_base,
            token: token.filter(|value| !value.is_empty()).map(AuthToken),
            limits,
        })
    }

    pub(super) fn pull_request(
        &self,
        slug: &RepositorySlug,
        number: u64,
    ) -> Result<PullRequestMetadata, ReviewError> {
        let response = self
            .request(slug, &format!("pulls/{number}"))
            .header(ACCEPT, GITHUB_JSON_MEDIA_TYPE)
            .send()
            .map_err(network_error)?;
        let body = self.success_body(response, self.limits.max_metadata_bytes, "metadata")?;
        let metadata: ApiPullRequest = serde_json::from_slice(&body).map_err(|error| {
            ReviewError::GitHub(format!("invalid pull request metadata: {error}"))
        })?;
        validate_metadata(metadata)
    }

    pub(super) fn host_policy(&self) -> GitHubHostPolicy {
        GitHubHostPolicy::with_api_host(self.api_base.host_str().unwrap_or_default())
    }

    pub(super) fn compare_diff(
        &self,
        slug: &RepositorySlug,
        revisions: &PinnedRevisions,
    ) -> Result<String, ReviewError> {
        let response = self
            .request(slug, &format!("compare/{}", revisions.compare_range()))
            .header(ACCEPT, GITHUB_DIFF_MEDIA_TYPE)
            .send()
            .map_err(network_error)?;
        let body = self.success_body(response, self.limits.max_diff_bytes, "diff")?;
        String::from_utf8(body).map_err(|error| {
            ReviewError::GitHub(format!("pull request diff is not UTF-8: {error}"))
        })
    }

    pub(super) fn download_archive(
        &self,
        slug: &RepositorySlug,
        revisions: &PinnedRevisions,
    ) -> Result<tempfile::NamedTempFile, ReviewError> {
        let response = self
            .request(slug, &format!("zipball/{}", revisions.head_sha()))
            .header(ACCEPT, GITHUB_JSON_MEDIA_TYPE)
            .send()
            .map_err(network_error)?;
        self.download_success_body(response, self.limits.max_archive_bytes)
    }

    fn request(&self, slug: &RepositorySlug, endpoint: &str) -> RequestBuilder {
        let request = self.http.get(self.endpoint_url(slug, endpoint));
        match &self.token {
            Some(token) => request.bearer_auth(&token.0),
            None => request,
        }
    }

    fn endpoint_url(&self, slug: &RepositorySlug, endpoint: &str) -> Url {
        let mut url = self.api_base.clone();
        let base_path = self.api_base.path().trim_end_matches('/');
        url.set_path(&format!("{base_path}/repos/{}/{endpoint}", slug.as_str()));
        url
    }

    fn success_body(
        &self,
        response: Response,
        limit: usize,
        label: &str,
    ) -> Result<Vec<u8>, ReviewError> {
        let status = response.status();
        if !status.is_success() {
            return Err(self.http_status_error(response, status));
        }
        let body = read_body_prefix(response, limit).map_err(body_read_error)?;
        if body.truncated {
            return Err(ReviewError::GitHub(format!(
                "GitHub pull request {label} exceeds {limit} bytes"
            )));
        }
        Ok(body.bytes)
    }

    fn download_success_body(
        &self,
        mut response: Response,
        limit: usize,
    ) -> Result<tempfile::NamedTempFile, ReviewError> {
        let status = response.status();
        if !status.is_success() {
            return Err(self.http_status_error(response, status));
        }
        if response
            .content_length()
            .is_some_and(|length| length > limit as u64)
        {
            return Err(archive_limit_error(limit));
        }
        let mut archive = create_archive_file(&std::env::temp_dir())?;
        write_archive_body(&mut response, &mut archive, limit)?;
        Ok(archive)
    }

    fn http_status_error(&self, response: Response, status: StatusCode) -> ReviewError {
        let detail = match &self.token {
            Some(_) => "<response body withheld from an authenticated request>".to_string(),
            None => unauthenticated_error_detail(read_body_prefix(
                response,
                self.limits.max_error_bytes,
            )),
        };
        ReviewError::GitHub(format!("GitHub API returned HTTP {status}: {detail}"))
    }
}

fn unauthenticated_error_detail(body: std::io::Result<BodyPrefix>) -> String {
    match body {
        Ok(body) => String::from_utf8_lossy(&body.bytes).into_owned(),
        Err(_) => "<failed to read response body>".to_string(),
    }
}

#[derive(Deserialize)]
struct ApiPullRequest {
    base: ApiReference,
    head: ApiHead,
}

#[derive(Deserialize)]
struct ApiReference {
    r#ref: String,
    sha: String,
}

#[derive(Deserialize)]
struct ApiHead {
    sha: String,
}

fn validate_metadata(metadata: ApiPullRequest) -> Result<PullRequestMetadata, ReviewError> {
    if metadata.base.r#ref.is_empty() || metadata.base.r#ref.len() > 255 {
        return Err(ReviewError::GitHub(
            "pull request base reference is invalid".to_string(),
        ));
    }
    let revisions = PinnedRevisions::parse(&metadata.base.sha, &metadata.head.sha)?;
    Ok(PullRequestMetadata {
        base_ref: metadata.base.r#ref,
        revisions,
    })
}

fn parse_api_base(raw_api_base: String) -> Result<Url, ReviewError> {
    if raw_api_base.len() > 2048 {
        return Err(ReviewError::GitHub(
            "GitHub API base URL exceeds 2048 bytes".to_string(),
        ));
    }
    let normalized = if raw_api_base.ends_with('/') {
        raw_api_base
    } else {
        format!("{raw_api_base}/")
    };
    Url::parse(&normalized)
        .map_err(|error| ReviewError::GitHub(format!("invalid GitHub API URL: {error}")))
}

fn validate_api_base(api_base: &Url) -> Result<(), ReviewError> {
    let host = api_base.host_str();
    let secure = api_base.scheme() == "https";
    let loopback_http = api_base.scheme() == "http"
        && host.is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1"));
    if host.is_none()
        || (!secure && !loopback_http)
        || !api_base.username().is_empty()
        || api_base.password().is_some()
        || api_base.query().is_some()
        || api_base.fragment().is_some()
        || api_base.path().len() > 1024
    {
        return Err(ReviewError::GitHub(
            "invalid GitHub API base URL".to_string(),
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct RedirectTrust {
    host: String,
    scheme: String,
    port: Option<u16>,
    production: bool,
    allows_codeload: bool,
}

impl RedirectTrust {
    fn from_api_base(api_base: &Url) -> Result<Self, ReviewError> {
        let host = api_base
            .host_str()
            .ok_or_else(|| ReviewError::GitHub("GitHub API URL has no host".to_string()))?
            .to_string();
        let scheme = api_base.scheme().to_string();
        Ok(Self {
            production: scheme == "https",
            allows_codeload: host == "api.github.com",
            port: api_base.port_or_known_default(),
            host,
            scheme,
        })
    }

    fn accepts(&self, target: &Url) -> bool {
        if !target.username().is_empty() || target.password().is_some() {
            return false;
        }
        if self.production {
            return target.scheme() == "https"
                && target.port_or_known_default() == self.port
                && target.host_str().is_some_and(|host| {
                    host == self.host || self.allows_codeload && host == "codeload.github.com"
                });
        }
        target.scheme() == self.scheme
            && target.host_str() == Some(self.host.as_str())
            && target.port_or_known_default() == self.port
    }
}

fn redirect_policy(api_base: &Url) -> Result<redirect::Policy, ReviewError> {
    let trust = RedirectTrust::from_api_base(api_base)?;
    Ok(redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.error("redirect limit exceeded");
        }
        if trust.accepts(attempt.url()) {
            attempt.follow()
        } else {
            attempt.error("redirect target is not trusted")
        }
    }))
}

struct BodyPrefix {
    bytes: Vec<u8>,
    truncated: bool,
}

fn read_body_prefix(mut response: Response, limit: usize) -> std::io::Result<BodyPrefix> {
    let mut bytes = Vec::with_capacity(
        response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or_default()
            .min(limit),
    );
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = response.read(&mut buffer)?;
        if read == 0 {
            return Ok(BodyPrefix {
                bytes,
                truncated: false,
            });
        }
        let remaining = limit.saturating_sub(bytes.len());
        let copied = read.min(remaining);
        bytes.extend_from_slice(&buffer[..copied]);
        if read > copied {
            return Ok(BodyPrefix {
                bytes,
                truncated: true,
            });
        }
    }
}

fn create_archive_file(directory: &Path) -> Result<tempfile::NamedTempFile, ReviewError> {
    tempfile::NamedTempFile::new_in(directory).map_err(|source| ReviewError::Io {
        action: "create pull request archive".to_string(),
        source,
    })
}

fn write_archive_body(
    body: &mut dyn Read,
    sink: &mut dyn Write,
    limit: usize,
) -> Result<(), ReviewError> {
    let mut buffer = [0u8; 32 * 1024];
    let mut written = 0u64;
    loop {
        let read = body.read(&mut buffer).map_err(body_read_error)?;
        if read == 0 {
            break;
        }
        written += read as u64;
        if written > limit as u64 {
            return Err(archive_limit_error(limit));
        }
        sink.write_all(&buffer[..read])
            .map_err(|source| ReviewError::Io {
                action: "write pull request archive".to_string(),
                source,
            })?;
    }
    sink.flush().map_err(|source| ReviewError::Io {
        action: "flush pull request archive".to_string(),
        source,
    })
}

fn archive_limit_error(limit: usize) -> ReviewError {
    ReviewError::GitHub(format!("GitHub pull request archive exceeds {limit} bytes"))
}

fn body_read_error(error: std::io::Error) -> ReviewError {
    ReviewError::GitHub(format!("failed to read GitHub response: {error}"))
}

fn network_error(error: reqwest::Error) -> ReviewError {
    ReviewError::GitHub(format!("GitHub request failed: {error}"))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const BASE_SHA: &str = "1111111111111111111111111111111111111111";
    const HEAD_SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    fn test_client(api_base: &str, limits: GitHubLimits) -> GitHubClient {
        GitHubClient::new(
            reqwest::Url::parse(&format!("{api_base}/")).unwrap(),
            Some("secret-token".to_string()),
            limits,
        )
        .unwrap()
    }

    fn pinned_revisions() -> PinnedRevisions {
        PinnedRevisions::parse(BASE_SHA, HEAD_SHA).unwrap()
    }

    fn compare_path() -> String {
        format!("/repos/owner/project/compare/{BASE_SHA}...{HEAD_SHA}")
    }

    #[test]
    fn repository_slug_accepts_owner_and_name_only() {
        assert_eq!(
            RepositorySlug::parse("owner/project").unwrap().as_str(),
            "owner/project"
        );
        assert!(RepositorySlug::parse("owner").is_err());
        assert!(RepositorySlug::parse("owner/project/extra").is_err());
        assert!(RepositorySlug::parse("../project").is_err());
    }

    #[test]
    fn revisions_require_full_commit_shas() {
        assert!(PinnedRevisions::parse(BASE_SHA, HEAD_SHA).is_ok());
        assert!(
            PinnedRevisions::parse("main", HEAD_SHA)
                .unwrap_err()
                .to_string()
                .contains("base commit is invalid")
        );
        assert!(
            PinnedRevisions::parse(BASE_SHA, &HEAD_SHA[..7])
                .unwrap_err()
                .to_string()
                .contains("head commit is invalid")
        );
        assert!(PinnedRevisions::parse(BASE_SHA, &"z".repeat(40)).is_err());
    }

    #[test]
    fn host_policy_accepts_github_and_the_configured_api_host() {
        let policy = GitHubHostPolicy::with_api_host("api.github.com");

        assert!(policy.accepts("github.com"));
        assert!(policy.accepts("GitHub.com."));
        assert!(policy.accepts("www.github.com"));
        assert!(policy.accepts("ssh.github.com"));
        assert!(policy.accepts("api.github.com"));
        assert!(!policy.accepts("gitlab.com"));
        assert!(!policy.accepts("github.com.evil.example"));
        assert!(!policy.accepts("evil-github.com"));
        assert!(!policy.accepts(""));
    }

    #[test]
    fn host_policy_accepts_an_enterprise_api_host() {
        let policy = GitHubHostPolicy::with_api_host("ghe.example.com");

        assert!(policy.accepts("ghe.example.com"));
        assert!(policy.accepts("github.com"));
        assert!(!policy.accepts("other.example.com"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fetches_pull_request_metadata_with_authentication() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/project/pulls/7"))
            .and(header("authorization", "Bearer secret-token"))
            .and(header("user-agent", crate::version::USER_AGENT))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "base": { "ref": "main", "sha": BASE_SHA },
                "head": { "sha": HEAD_SHA }
            })))
            .mount(&server)
            .await;
        let api_base = server.uri();

        let metadata = tokio::task::spawn_blocking(move || {
            let client = test_client(&api_base, GitHubLimits::default());
            let slug = RepositorySlug::parse("owner/project").unwrap();
            client.pull_request(&slug, 7)
        })
        .await
        .unwrap()
        .unwrap();

        assert_eq!(metadata.base_ref, "main");
        assert_eq!(metadata.revisions, pinned_revisions());
        assert_eq!(metadata.revisions.head_sha(), HEAD_SHA);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejects_metadata_whose_base_revision_is_not_pinned() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/project/pulls/7"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "base": { "ref": "main", "sha": "main" },
                "head": { "sha": HEAD_SHA }
            })))
            .mount(&server)
            .await;
        let api_base = server.uri();

        let error = tokio::task::spawn_blocking(move || {
            let client = test_client(&api_base, GitHubLimits::default());
            let slug = RepositorySlug::parse("owner/project").unwrap();
            client.pull_request(&slug, 7)
        })
        .await
        .unwrap()
        .unwrap_err();

        assert!(error.to_string().contains("base commit is invalid"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn compare_diff_reads_only_the_sha_pinned_range() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(compare_path()))
            .and(header("accept", GITHUB_DIFF_MEDIA_TYPE))
            .respond_with(ResponseTemplate::new(200).set_body_string("diff --git a/x b/x\n"))
            .mount(&server)
            .await;
        let api_base = server.uri();

        let diff = tokio::task::spawn_blocking(move || {
            let client = test_client(&api_base, GitHubLimits::default());
            let slug = RepositorySlug::parse("owner/project").unwrap();
            client.compare_diff(&slug, &pinned_revisions())
        })
        .await
        .unwrap()
        .unwrap();

        assert_eq!(diff, "diff --git a/x b/x\n");
        let requested: Vec<String> = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|request| request.url.path().to_string())
            .collect();
        assert_eq!(
            requested,
            vec![compare_path()],
            "the diff must come from the pinned compare endpoint, never the pull request number"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejects_diff_responses_beyond_the_limit() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(compare_path()))
            .respond_with(ResponseTemplate::new(200).set_body_string("12345"))
            .mount(&server)
            .await;
        let limits = GitHubLimits {
            max_diff_bytes: 4,
            ..GitHubLimits::default()
        };
        let api_base = server.uri();

        let error = tokio::task::spawn_blocking(move || {
            let client = test_client(&api_base, limits);
            let slug = RepositorySlug::parse("owner/project").unwrap();
            client.compare_diff(&slug, &pinned_revisions())
        })
        .await
        .unwrap()
        .unwrap_err();

        assert!(error.to_string().contains("diff exceeds 4 bytes"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejects_archive_downloads_beyond_the_limit() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/repos/owner/project/zipball/{HEAD_SHA}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"12345"))
            .mount(&server)
            .await;
        let limits = GitHubLimits {
            max_archive_bytes: 4,
            ..GitHubLimits::default()
        };
        let api_base = server.uri();

        let error = tokio::task::spawn_blocking(move || {
            let client = test_client(&api_base, limits);
            let slug = RepositorySlug::parse("owner/project").unwrap();
            client.download_archive(&slug, &pinned_revisions())
        })
        .await
        .unwrap()
        .unwrap_err();

        assert!(error.to_string().contains("archive exceeds 4 bytes"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejects_redirects_to_untrusted_hosts() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/project/pulls/7"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", "https://example.invalid/stolen"),
            )
            .mount(&server)
            .await;
        let api_base = server.uri();

        let error = tokio::task::spawn_blocking(move || {
            let client = test_client(&api_base, GitHubLimits::default());
            let slug = RepositorySlug::parse("owner/project").unwrap();
            client.pull_request(&slug, 7)
        })
        .await
        .unwrap()
        .unwrap_err();

        assert!(error.to_string().contains("redirect"));
    }

    fn unauthenticated_test_client(api_base: &str, limits: GitHubLimits) -> GitHubClient {
        GitHubClient::new(
            reqwest::Url::parse(&format!("{api_base}/")).unwrap(),
            None,
            limits,
        )
        .unwrap()
    }

    fn raw_http_server(response: Vec<u8>) -> (String, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request);
            stream.write_all(&response).unwrap();
        });
        (format!("http://{address}"), handle)
    }

    #[test]
    fn api_base_validation_rejects_credentials_queries_fragments_and_insecure_hosts() {
        for value in [
            "http://example.com/",
            "https://user@example.com/",
            "https://example.com/?query=1",
            "https://example.com/#fragment",
            &format!("https://example.com/{}", "x".repeat(1025)),
        ] {
            let url = Url::parse(value).unwrap();
            assert!(validate_api_base(&url).is_err(), "{value}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejects_malformed_metadata_and_invalid_base_references() {
        let malformed_server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{"))
            .mount(&malformed_server)
            .await;
        let api_base = malformed_server.uri();
        let error = tokio::task::spawn_blocking(move || {
            let client = test_client(&api_base, GitHubLimits::default());
            client.pull_request(&RepositorySlug::parse("owner/project").unwrap(), 7)
        })
        .await
        .unwrap()
        .unwrap_err();
        assert!(error.to_string().contains("invalid pull request metadata"));

        let invalid_ref_server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "base": { "ref": "", "sha": BASE_SHA },
                "head": { "sha": HEAD_SHA }
            })))
            .mount(&invalid_ref_server)
            .await;
        let api_base = invalid_ref_server.uri();
        let error = tokio::task::spawn_blocking(move || {
            let client = test_client(&api_base, GitHubLimits::default());
            client.pull_request(&RepositorySlug::parse("owner/project").unwrap(), 7)
        })
        .await
        .unwrap()
        .unwrap_err();
        assert!(error.to_string().contains("base reference is invalid"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejects_non_utf8_diffs_and_reports_unauthenticated_http_errors() {
        let diff_server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0xff]))
            .mount(&diff_server)
            .await;
        let api_base = diff_server.uri();
        let error = tokio::task::spawn_blocking(move || {
            let client = test_client(&api_base, GitHubLimits::default());
            client.compare_diff(
                &RepositorySlug::parse("owner/project").unwrap(),
                &pinned_revisions(),
            )
        })
        .await
        .unwrap()
        .unwrap_err();
        assert!(error.to_string().contains("diff is not UTF-8"));

        let error_server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
            .mount(&error_server)
            .await;
        let api_base = error_server.uri();
        let error = tokio::task::spawn_blocking(move || {
            let client = unauthenticated_test_client(&api_base, GitHubLimits::default());
            client.pull_request(&RepositorySlug::parse("owner/project").unwrap(), 7)
        })
        .await
        .unwrap()
        .unwrap_err();
        assert!(error.to_string().contains("HTTP 503"));
        assert!(error.to_string().contains("unavailable"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn archive_download_handles_success_status_errors_and_chunked_limits() {
        let success_server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"archive"))
            .mount(&success_server)
            .await;
        let api_base = success_server.uri();
        let archive = tokio::task::spawn_blocking(move || {
            let client = test_client(&api_base, GitHubLimits::default());
            client.download_archive(
                &RepositorySlug::parse("owner/project").unwrap(),
                &pinned_revisions(),
            )
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(std::fs::read(archive.path()).unwrap(), b"archive");

        let error_server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404).set_body_string("missing"))
            .mount(&error_server)
            .await;
        let api_base = error_server.uri();
        let error = tokio::task::spawn_blocking(move || {
            let client = test_client(&api_base, GitHubLimits::default());
            client.download_archive(
                &RepositorySlug::parse("owner/project").unwrap(),
                &pinned_revisions(),
            )
        })
        .await
        .unwrap()
        .unwrap_err();
        assert!(error.to_string().contains("HTTP 404"));

        let response =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\n12345\r\n0\r\n\r\n"
            .to_vec();
        let (api_base, server) = raw_http_server(response);
        let limits = GitHubLimits {
            max_archive_bytes: 4,
            ..GitHubLimits::default()
        };
        let error = tokio::task::spawn_blocking(move || {
            let client = test_client(&api_base, limits);
            client.download_archive(
                &RepositorySlug::parse("owner/project").unwrap(),
                &pinned_revisions(),
            )
        })
        .await
        .unwrap()
        .unwrap_err();
        server.join().unwrap();
        assert!(error.to_string().contains("archive exceeds 4 bytes"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn truncated_http_bodies_are_reported_as_read_failures() {
        let response =
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nabc".to_vec();
        let (api_base, server) = raw_http_server(response);

        let error = tokio::task::spawn_blocking(move || {
            let client = test_client(&api_base, GitHubLimits::default());
            client.compare_diff(
                &RepositorySlug::parse("owner/project").unwrap(),
                &pinned_revisions(),
            )
        })
        .await
        .unwrap()
        .unwrap_err();

        server.join().unwrap();
        assert!(error.to_string().contains("failed to read GitHub response"));
    }

    fn url(value: &str) -> Url {
        Url::parse(value).unwrap()
    }

    struct BrokenSink {
        fail_on_write: bool,
    }

    impl Write for BrokenSink {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            if self.fail_on_write {
                return Err(std::io::Error::other("no space left on device"));
            }
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("flush rejected"))
        }
    }

    struct BrokenSource;

    impl Read for BrokenSource {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("connection reset"))
        }
    }

    async fn mount_redirect(server: &MockServer, from: String, to: String) {
        Mock::given(method("GET"))
            .and(path(from))
            .respond_with(ResponseTemplate::new(302).insert_header("location", to.as_str()))
            .mount(server)
            .await;
    }

    #[test]
    fn the_api_base_is_normalized_and_bounded() {
        assert_eq!(
            parse_api_base("https://ghe.example.com/api/v3".to_string())
                .unwrap()
                .as_str(),
            "https://ghe.example.com/api/v3/",
            "a base URL without a trailing slash must gain one so joins stay under it"
        );
        assert_eq!(
            parse_api_base("https://ghe.example.com/api/v3/".to_string())
                .unwrap()
                .as_str(),
            "https://ghe.example.com/api/v3/"
        );
        assert!(
            parse_api_base(format!("https://example.com/{}", "x".repeat(2028))).is_ok(),
            "a 2048 byte base URL is within the limit"
        );

        let error =
            parse_api_base(format!("https://example.com/{}", "x".repeat(2029))).unwrap_err();
        assert_eq!(
            error.to_string(),
            "GitHub request failed: GitHub API base URL exceeds 2048 bytes"
        );

        let error = parse_api_base("not a url".to_string()).unwrap_err();
        assert!(
            error.to_string().contains("invalid GitHub API URL"),
            "{error}"
        );
    }

    #[test]
    fn endpoint_urls_keep_the_enterprise_api_path_prefix() {
        let client = GitHubClient::new(
            url("https://ghe.example.com/api/v3/"),
            None,
            GitHubLimits::default(),
        )
        .unwrap();
        let slug = RepositorySlug::parse("owner/project").unwrap();

        assert_eq!(
            client.endpoint_url(&slug, "pulls/7").as_str(),
            "https://ghe.example.com/api/v3/repos/owner/project/pulls/7"
        );
        let compare = client.endpoint_url(&slug, &format!("compare/{BASE_SHA}...{HEAD_SHA}"));
        assert_eq!(
            compare.as_str(),
            format!(
                "https://ghe.example.com/api/v3/repos/owner/project/compare/{BASE_SHA}...{HEAD_SHA}"
            )
        );
    }

    #[test]
    fn the_archive_temporary_file_reports_a_missing_directory() {
        let directory = tempfile::tempdir().unwrap();

        let error = create_archive_file(&directory.path().join("absent")).unwrap_err();

        assert!(
            error
                .to_string()
                .starts_with("create pull request archive:"),
            "{error}"
        );
        assert!(create_archive_file(directory.path()).is_ok());
    }

    #[test]
    fn archive_bodies_stream_to_the_sink_and_report_transfer_failures() {
        let mut sink = Vec::new();
        write_archive_body(&mut std::io::Cursor::new(b"archive".to_vec()), &mut sink, 7).unwrap();
        assert_eq!(
            sink, b"archive",
            "a body at exactly the limit is kept whole"
        );

        let error = write_archive_body(
            &mut std::io::Cursor::new(b"archive".to_vec()),
            &mut Vec::new(),
            6,
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "GitHub request failed: GitHub pull request archive exceeds 6 bytes"
        );

        let error = write_archive_body(&mut BrokenSource, &mut Vec::new(), 64).unwrap_err();
        assert!(
            error.to_string().contains("failed to read GitHub response"),
            "{error}"
        );
        assert!(error.to_string().contains("connection reset"), "{error}");

        let error = write_archive_body(
            &mut std::io::Cursor::new(b"archive".to_vec()),
            &mut BrokenSink {
                fail_on_write: true,
            },
            64,
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "write pull request archive: no space left on device"
        );

        let error = write_archive_body(
            &mut std::io::Cursor::new(b"archive".to_vec()),
            &mut BrokenSink {
                fail_on_write: false,
            },
            64,
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "flush pull request archive: flush rejected"
        );
    }

    #[test]
    fn production_redirects_stay_on_github_hosts() {
        let github = RedirectTrust::from_api_base(&url("https://api.github.com/")).unwrap();

        assert!(github.accepts(&url("https://api.github.com/repos/owner/project")));
        assert!(github.accepts(&url("https://codeload.github.com/owner/project/zip")));
        assert!(
            !github.accepts(&url("http://api.github.com/repos/owner/project")),
            "a redirect must never downgrade to plaintext"
        );
        assert!(!github.accepts(&url("https://api.github.com.evil.example/repos")));
        assert!(!github.accepts(&url("https://api.github.com:444/repos/owner/project")));
        assert!(!github.accepts(&url("https://token@api.github.com/repos/owner/project")));

        let enterprise =
            RedirectTrust::from_api_base(&url("https://ghe.example.com/api/v3/")).unwrap();

        assert!(enterprise.accepts(&url("https://ghe.example.com/api/v3/repos")));
        assert!(
            !enterprise.accepts(&url("https://codeload.github.com/owner/project/zip")),
            "codeload is trusted only for the github.com API base"
        );
        assert!(!enterprise.accepts(&url("https://ghe.example.com:8443/api/v3/repos")));

        let enterprise_with_port =
            RedirectTrust::from_api_base(&url("https://ghe.example.com:8443/api/v3/")).unwrap();
        assert!(enterprise_with_port.accepts(&url("https://ghe.example.com:8443/api/v3/repos")));
        assert!(!enterprise_with_port.accepts(&url("https://ghe.example.com/api/v3/repos")));
    }

    #[test]
    fn loopback_redirects_require_the_same_scheme_host_and_port() {
        let trust = RedirectTrust::from_api_base(&url("http://127.0.0.1:8080/")).unwrap();

        assert!(trust.accepts(&url("http://127.0.0.1:8080/repos")));
        assert!(!trust.accepts(&url("http://127.0.0.1:9090/repos")));
        assert!(!trust.accepts(&url("http://localhost:8080/repos")));
        assert!(!trust.accepts(&url("https://127.0.0.1:8080/repos")));
        assert_eq!(
            RedirectTrust::from_api_base(&url("data:text/plain,body"))
                .unwrap_err()
                .to_string(),
            "GitHub request failed: GitHub API URL has no host"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn trusted_redirects_are_followed_within_the_limit() {
        let server = MockServer::start().await;
        let base = server.uri();
        mount_redirect(
            &server,
            "/repos/owner/project/pulls/7".to_string(),
            format!("{base}/hop/1"),
        )
        .await;
        for hop in 1..MAX_REDIRECTS - 1 {
            mount_redirect(
                &server,
                format!("/hop/{hop}"),
                format!("{base}/hop/{}", hop + 1),
            )
            .await;
        }
        Mock::given(method("GET"))
            .and(path(format!("/hop/{}", MAX_REDIRECTS - 1)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "base": { "ref": "main", "sha": BASE_SHA },
                "head": { "sha": HEAD_SHA }
            })))
            .mount(&server)
            .await;
        let api_base = server.uri();

        let metadata = tokio::task::spawn_blocking(move || {
            let client = test_client(&api_base, GitHubLimits::default());
            client.pull_request(&RepositorySlug::parse("owner/project").unwrap(), 7)
        })
        .await
        .unwrap()
        .unwrap();

        assert_eq!(metadata.revisions, pinned_revisions());
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests.len(),
            MAX_REDIRECTS,
            "four redirects are followed before the pinned metadata arrives"
        );
        assert!(
            requests
                .iter()
                .all(|request| request.headers.contains_key("authorization")),
            "a same-host redirect must keep the bearer token"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_redirect_chain_beyond_the_limit_is_refused() {
        let server = MockServer::start().await;
        let base = server.uri();
        mount_redirect(
            &server,
            "/repos/owner/project/pulls/7".to_string(),
            format!("{base}/hop/1"),
        )
        .await;
        for hop in 1..=MAX_REDIRECTS {
            mount_redirect(
                &server,
                format!("/hop/{hop}"),
                format!("{base}/hop/{}", hop + 1),
            )
            .await;
        }
        let api_base = server.uri();

        let error = tokio::task::spawn_blocking(move || {
            let client = test_client(&api_base, GitHubLimits::default());
            client.pull_request(&RepositorySlug::parse("owner/project").unwrap(), 7)
        })
        .await
        .unwrap()
        .unwrap_err();

        assert!(error.to_string().contains("redirect"), "{error}");
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            MAX_REDIRECTS,
            "the fifth redirect is refused instead of followed"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authenticated_error_bodies_never_reach_the_error() {
        let token = "secret-token";
        let leaky = format!(
            "{{\"message\":\"bad credentials {token}\",\"quoted\":\"\\\"{token}\\\"\",\
         \"escaped\":\"secret\\u002dtoken\"}}"
        );
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(403).set_body_string(leaky))
            .mount(&server)
            .await;
        let api_base = server.uri();

        let error = tokio::task::spawn_blocking(move || {
            let client = test_client(&api_base, GitHubLimits::default());
            client.pull_request(&RepositorySlug::parse("owner/project").unwrap(), 7)
        })
        .await
        .unwrap()
        .unwrap_err();

        let rendered = error.to_string();
        assert_eq!(
            rendered,
            "GitHub request failed: GitHub API returned HTTP 403 Forbidden: \
         <response body withheld from an authenticated request>"
        );
        assert!(
            !rendered.contains(token),
            "no escaping of the token can survive a withheld body: {rendered}"
        );
        assert!(!rendered.contains("bad credentials"), "{rendered}");
    }

    #[test]
    fn unreadable_unauthenticated_error_bodies_have_a_safe_fallback() {
        let detail = unauthenticated_error_detail(Err(std::io::Error::other("read failed")));

        assert_eq!(detail, "<failed to read response body>");
    }
}
