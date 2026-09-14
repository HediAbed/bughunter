use std::time::Duration;

use async_trait::async_trait;
use reqwest::StatusCode;
use serde_json::Value;
use tracing::{info, warn};

use crate::config::schema::{BackendConfig, LlmConfig, MAX_CONTEXT_TOKENS, MIN_CONTEXT_TOKENS};
use crate::errors::LlmError;

use super::types::{ChatCompletionRequest, LlmResponse, Message, StreamAccumulator, ToolConfig};

const BACKOFF_BASE_MS: u64 = 1000;
const MAX_BACKOFF_EXPONENT: u32 = 6;
const MAX_RETRY_AFTER_SECONDS: u64 = 60;
const AUTHENTICATED_ERROR_BODY: &str = "<authenticated response body withheld>";
const MAX_MODEL_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_STREAM_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

#[async_trait]
pub trait LlmBackend: Send + Sync {
    async fn converse(
        &self,
        messages: &[Message],
        system_prompt: &str,
        tool_config: &ToolConfig,
    ) -> Result<LlmResponse, LlmError>;
}

pub struct OpenAiBackend {
    http: reqwest::Client,
    config: LlmConfig,
    api_url: String,
    api_token: String,
}

impl OpenAiBackend {
    pub fn new(config: LlmConfig) -> Result<Self, LlmError> {
        let BackendConfig::OpenAiCompatible { api_url, api_token } = &config.backend else {
            return Err(LlmError::AuthError);
        };
        let token = api_token.as_deref().ok_or(LlmError::AuthError)?;
        if token.is_empty() {
            return Err(LlmError::AuthError);
        }
        let api_url = api_url.clone();
        let api_token = token.to_string();

        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(config.timeout_seconds))
            .user_agent(crate::version::USER_AGENT)
            .build()?;

        Ok(Self {
            http,
            config,
            api_url,
            api_token,
        })
    }

    pub async fn detect_context_window(&self) -> Option<u32> {
        let url = format!("{}/models", self.api_url);
        let token = self.api_token.as_str();
        let mut response = self.http.get(&url).bearer_auth(token).send().await.ok()?;
        if !response.status().is_success() {
            return None;
        }
        let body = read_response_body(&mut response, MAX_MODEL_RESPONSE_BYTES)
            .await
            .ok()?;
        if body.truncated {
            return None;
        }
        let body: Value = serde_json::from_slice(&body.bytes).ok()?;
        context_window_from_models(&body, &self.config.model)
    }

    async fn converse_with_retry(
        &self,
        request: &ChatCompletionRequest,
    ) -> Result<LlmResponse, LlmError> {
        let url = format!("{}/chat/completions", self.api_url);
        let token = self.api_token.as_str();

        let mut last_error = None;
        let max_attempts = self.config.max_retries + 1;

        for attempt in 0..max_attempts {
            if attempt > 0 {
                let backoff = backoff_duration(&last_error, attempt);
                info!(
                    attempt,
                    backoff_ms = backoff.as_millis(),
                    "retrying after backoff"
                );
                tokio::time::sleep(backoff).await;
            }

            match self.send_once(&url, token, request).await {
                Ok(response) => return Ok(response),
                Err(err) => {
                    if !is_retryable(&err) {
                        return Err(err);
                    }
                    warn!(attempt, error = %err, "request failed, will retry");
                    last_error = Some(err);
                }
            }
        }

        Err(last_error.unwrap_or(LlmError::Timeout {
            timeout_seconds: self.config.timeout_seconds,
        }))
    }

    async fn send_once(
        &self,
        url: &str,
        token: &str,
        request: &ChatCompletionRequest,
    ) -> Result<LlmResponse, LlmError> {
        let mut response = self
            .http
            .post(url)
            .bearer_auth(token)
            .json(request)
            .send()
            .await
            .map_err(|error| {
                normalize_timeout(LlmError::Network(error), self.config.timeout_seconds)
            })?;

        let status = response.status();
        if status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED {
            return Err(LlmError::AuthError);
        }

        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .map(|seconds| seconds.min(MAX_RETRY_AFTER_SECONDS));
            if let Some(retry_after_seconds) = retry_after {
                return Err(LlmError::RateLimited {
                    retry_after_seconds,
                });
            }
            return Err(LlmError::ApiError {
                status: 429,
                body: AUTHENTICATED_ERROR_BODY.to_string(),
            });
        }

        if !status.is_success() {
            return Err(LlmError::ApiError {
                status: status.as_u16(),
                body: AUTHENTICATED_ERROR_BODY.to_string(),
            });
        }

        read_sse_response(&mut response)
            .await
            .map_err(|error| normalize_timeout(error, self.config.timeout_seconds))
    }

    fn build_request(
        &self,
        messages: &[Message],
        system_prompt: &str,
        tool_config: &ToolConfig,
    ) -> ChatCompletionRequest {
        ChatCompletionRequest::build(
            &self.config.model,
            self.config.max_tokens,
            self.config.temperature,
            self.config.reasoning_effort.clone(),
            system_prompt,
            messages,
            tool_config,
        )
    }
}

#[async_trait]
impl LlmBackend for OpenAiBackend {
    async fn converse(
        &self,
        messages: &[Message],
        system_prompt: &str,
        tool_config: &ToolConfig,
    ) -> Result<LlmResponse, LlmError> {
        let request = self.build_request(messages, system_prompt, tool_config);
        self.converse_with_retry(&request).await
    }
}

struct ResponseBody {
    bytes: Vec<u8>,
    truncated: bool,
}

async fn read_response_body(
    response: &mut reqwest::Response,
    limit: usize,
) -> Result<ResponseBody, reqwest::Error> {
    let mut bytes = Vec::with_capacity(
        response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or_default()
            .min(limit),
    );
    while let Some(chunk) = response.chunk().await? {
        let remaining = limit.saturating_sub(bytes.len());
        if chunk.len() > remaining {
            bytes.extend_from_slice(&chunk[..remaining]);
            return Ok(ResponseBody {
                bytes,
                truncated: true,
            });
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(ResponseBody {
        bytes,
        truncated: false,
    })
}

async fn read_sse_response(response: &mut reqwest::Response) -> Result<LlmResponse, LlmError> {
    read_sse_response_with_limit(response, MAX_STREAM_RESPONSE_BYTES).await
}

async fn read_sse_response_with_limit(
    response: &mut reqwest::Response,
    limit: usize,
) -> Result<LlmResponse, LlmError> {
    let mut accumulator = StreamAccumulator::default();
    let mut received_bytes = 0usize;

    while let Some(chunk) = response.chunk().await? {
        received_bytes = received_bytes
            .checked_add(chunk.len())
            .filter(|total| *total <= limit)
            .ok_or_else(|| {
                LlmError::AgentProtocol(format!("model response exceeded {limit} bytes"))
            })?;
        if accumulator.ingest_bytes(&chunk) {
            break;
        }
    }
    accumulator.finish();

    if let Some(limit) = accumulator.exhausted_limit() {
        return Err(LlmError::AgentProtocol(format!(
            "model response exceeded {} bytes ({} limit)",
            limit.bytes(),
            limit.resource()
        )));
    }

    if accumulator.has_malformed_data() {
        return Err(LlmError::IncompleteStream {
            reason: "malformed data event",
        });
    }
    if !accumulator.is_complete() {
        return Err(LlmError::IncompleteStream {
            reason: "stream ended before a completion signal",
        });
    }

    accumulator
        .into_response()
        .ok_or_else(|| LlmError::ApiError {
            status: 200,
            body: "stream closed without producing a response".to_string(),
        })
}

fn normalize_timeout(error: LlmError, timeout_seconds: u64) -> LlmError {
    match error {
        LlmError::Network(source) if source.is_timeout() => LlmError::Timeout { timeout_seconds },
        other => other,
    }
}

fn backoff_duration(last_error: &Option<LlmError>, attempt: u32) -> Duration {
    if let Some(LlmError::RateLimited {
        retry_after_seconds,
    }) = last_error
    {
        return Duration::from_secs((*retry_after_seconds).min(MAX_RETRY_AFTER_SECONDS));
    }
    let exponent = (attempt - 1).min(MAX_BACKOFF_EXPONENT);
    Duration::from_millis(BACKOFF_BASE_MS * 2u64.saturating_pow(exponent))
}

fn is_retryable(error: &LlmError) -> bool {
    matches!(
        error,
        LlmError::RateLimited { .. }
            | LlmError::Timeout { .. }
            | LlmError::Network(_)
            | LlmError::IncompleteStream { .. }
            | LlmError::ApiError {
                status: 429 | 500..=599,
                ..
            }
    )
}

fn context_window_from_models(body: &Value, model: &str) -> Option<u32> {
    const WINDOW_FIELDS: [&str; 4] = [
        "context_length",
        "max_model_len",
        "max_context_tokens",
        "context_window",
    ];
    let entry = body
        .get("data")?
        .as_array()?
        .iter()
        .find(|m| m.get("id").and_then(Value::as_str) == Some(model))?;
    WINDOW_FIELDS
        .iter()
        .find_map(|field| entry.get(field).and_then(Value::as_u64))
        .and_then(|tokens| u32::try_from(tokens).ok())
        .filter(|tokens| (MIN_CONTEXT_TOKENS..=MAX_CONTEXT_TOKENS).contains(tokens))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::super::tools::build_tool_config;
    use super::super::types::MAX_TOOL_ARGUMENT_BYTES;
    use super::*;
    use std::io::Write;

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_config() -> LlmConfig {
        LlmConfig {
            backend: BackendConfig::OpenAiCompatible {
                api_url: "https://example.com/v1".into(),
                api_token: Some("test-token".into()),
            },
            model: "test-model".into(),
            ..LlmConfig::default()
        }
    }

    fn openai_config(api_url: String, max_retries: u32) -> LlmConfig {
        LlmConfig {
            backend: BackendConfig::OpenAiCompatible {
                api_url,
                api_token: Some("test-token".into()),
            },
            model: "test-model".into(),
            max_retries,
            ..LlmConfig::default()
        }
    }

    fn no_tools() -> ToolConfig {
        ToolConfig {
            tools: Vec::new(),
            required_tool: None,
        }
    }

    fn successful_streaming_template() -> ResponseTemplate {
        let body = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"all\"}}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\" clear\"},\"finish_reason\":\"stop\"}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":3}}\n\n",
            "data: [DONE]\n\n",
        );
        ResponseTemplate::new(200)
            .insert_header("content-type", "text/event-stream")
            .set_body_string(body)
    }

    async fn completions_server(template: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(template)
            .mount(&server)
            .await;
        server
    }

    async fn completions_server_failing_once(template: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(template)
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(successful_streaming_template())
            .with_priority(2)
            .mount(&server)
            .await;
        server
    }

    async fn models_server(template: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/models"))
            .respond_with(template)
            .mount(&server)
            .await;
        server
    }

    fn backend_for(server: &MockServer, max_retries: u32) -> OpenAiBackend {
        OpenAiBackend::new(openai_config(server.uri(), max_retries)).unwrap()
    }

    async fn converse_once(backend: &OpenAiBackend) -> Result<LlmResponse, LlmError> {
        backend
            .converse(&[Message::user_text("status?")], "system", &no_tools())
            .await
    }

    async fn request_count(server: &MockServer) -> usize {
        server.received_requests().await.unwrap().len()
    }

    fn closing_http_server() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            drop(stream);
        });
        format!("http://{address}")
    }

    fn truncated_http_server(status: u16, body: &'static [u8]) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            let _ = std::io::Read::read(&mut stream, &mut request);
            write!(
                stream,
                "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len() + 10
            )
            .unwrap();
            stream.write_all(body).unwrap();
        });
        format!("http://{address}")
    }

    fn stalling_http_server(send_headers: bool) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            let _ = std::io::Read::read(&mut stream, &mut request);
            if send_headers {
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 64\r\nConnection: close\r\n\r\n",
                );
                let _ = stream.flush();
            }
            std::thread::sleep(Duration::from_secs(2));
        });
        format!("http://{address}")
    }

    async fn timeout_from(api_url: String) -> LlmError {
        let config = LlmConfig {
            backend: BackendConfig::OpenAiCompatible {
                api_url,
                api_token: Some("test-token".into()),
            },
            timeout_seconds: 1,
            max_retries: 0,
            ..test_config()
        };
        let backend = OpenAiBackend::new(config).unwrap();
        converse_once(&backend).await.unwrap_err()
    }

    #[test]
    fn creates_backend_with_valid_token() {
        let client = OpenAiBackend::new(test_config());
        assert!(client.is_ok());
    }

    #[test]
    fn rejects_missing_token() {
        let mut config = test_config();
        config.backend = BackendConfig::OpenAiCompatible {
            api_url: "https://example.com/v1".into(),
            api_token: None,
        };
        let result = OpenAiBackend::new(config);
        assert!(matches!(result, Err(LlmError::AuthError)));
    }

    #[test]
    fn rejects_empty_token() {
        let mut config = test_config();
        config.backend = BackendConfig::OpenAiCompatible {
            api_url: "https://example.com/v1".into(),
            api_token: Some(String::new()),
        };
        let result = OpenAiBackend::new(config);
        assert!(matches!(result, Err(LlmError::AuthError)));
    }

    #[test]
    fn retryable_errors() {
        assert!(is_retryable(&LlmError::RateLimited {
            retry_after_seconds: 5
        }));
        assert!(is_retryable(&LlmError::Timeout {
            timeout_seconds: 30
        }));
        assert!(is_retryable(&LlmError::ApiError {
            status: 500,
            body: "internal".into()
        }));
        assert!(is_retryable(&LlmError::ApiError {
            status: 503,
            body: "unavailable".into()
        }));
        assert!(is_retryable(&LlmError::ApiError {
            status: 429,
            body: "engine overloaded".into()
        }));
    }

    #[test]
    fn non_retryable_errors() {
        assert!(!is_retryable(&LlmError::AuthError));
        assert!(!is_retryable(&LlmError::ApiError {
            status: 400,
            body: "bad request".into()
        }));
        assert!(!is_retryable(&LlmError::ApiError {
            status: 404,
            body: "not found".into()
        }));
    }

    #[test]
    fn retryable_status_boundaries() {
        let api_error = |status: u16| LlmError::ApiError {
            status,
            body: String::new(),
        };
        assert!(!is_retryable(&api_error(428)));
        assert!(is_retryable(&api_error(429)));
        assert!(!is_retryable(&api_error(430)));
        assert!(!is_retryable(&api_error(499)));
        assert!(is_retryable(&api_error(500)));
        assert!(is_retryable(&api_error(599)));
        assert!(!is_retryable(&api_error(600)));
    }

    #[test]
    fn cancellation_is_never_retried() {
        assert!(!is_retryable(&LlmError::Cancelled));
    }

    #[test]
    fn backoff_doubles_until_the_exponent_cap() {
        let capped_attempt = MAX_BACKOFF_EXPONENT + 1;
        assert_eq!(
            backoff_duration(&None, 1),
            Duration::from_millis(BACKOFF_BASE_MS)
        );
        assert_eq!(
            backoff_duration(&None, 2),
            Duration::from_millis(BACKOFF_BASE_MS * 2)
        );
        assert_eq!(
            backoff_duration(&None, capped_attempt),
            Duration::from_millis(BACKOFF_BASE_MS * 64)
        );
        assert_eq!(
            backoff_duration(&None, capped_attempt + 100),
            backoff_duration(&None, capped_attempt),
            "the exponent must saturate instead of overflowing"
        );
    }

    #[test]
    fn retry_after_header_overrides_exponential_backoff() {
        let rate_limited = Some(LlmError::RateLimited {
            retry_after_seconds: 7,
        });
        assert_eq!(backoff_duration(&rate_limited, 1), Duration::from_secs(7));
        assert_eq!(backoff_duration(&rate_limited, 5), Duration::from_secs(7));
    }

    #[test]
    fn model_context_window_accepts_only_the_supported_range() {
        let model = |context_length: u64| {
            serde_json::json!({
                "data": [{
                    "id": "test-model",
                    "context_length": context_length
                }]
            })
        };
        let minimum = u64::from(crate::config::schema::MIN_CONTEXT_TOKENS);

        assert_eq!(
            context_window_from_models(&model(minimum - 1), "test-model"),
            None
        );
        assert_eq!(
            context_window_from_models(&model(minimum), "test-model"),
            Some(minimum as u32)
        );
        assert_eq!(
            context_window_from_models(&model(u64::from(MAX_CONTEXT_TOKENS)), "test-model"),
            Some(MAX_CONTEXT_TOKENS)
        );
        assert_eq!(
            context_window_from_models(&model(u64::from(MAX_CONTEXT_TOKENS) + 1), "test-model"),
            None
        );
        assert_eq!(context_window_from_models(&model(0), "test-model"), None);
    }
    #[test]
    fn builds_request_with_tools_and_inference_params() {
        let client = OpenAiBackend::new(test_config()).unwrap();
        let messages = vec![Message::user_text("hello")];
        let tools = build_tool_config();

        let request = client.build_request(&messages, "system prompt", &tools);

        assert_eq!(request.model, "test-model");
        assert_eq!(request.messages.len(), 2);
        assert_eq!(request.messages[0].role, "system");
        assert_eq!(request.tools.len(), tools.tools.len());
        assert_eq!(request.max_tokens, LlmConfig::default().max_tokens);
    }

    async fn mock_streaming_backend() -> (wiremock::MockServer, OpenAiBackend) {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let sse = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"all\"}}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\" clear\"},\"finish_reason\":\"stop\"}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":3}}\n\n",
            "data: [DONE]\n\n",
        );
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(header("user-agent", crate::version::USER_AGENT))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(sse),
            )
            .mount(&server)
            .await;
        let config = LlmConfig {
            backend: BackendConfig::OpenAiCompatible {
                api_url: server.uri(),
                api_token: Some("test-token".into()),
            },
            model: "test-model".into(),
            ..LlmConfig::default()
        };

        (server, OpenAiBackend::new(config).unwrap())
    }

    #[tokio::test]
    async fn streams_and_reassembles_response_over_http() {
        let (_server, backend) = mock_streaming_backend().await;
        let response = backend
            .converse(
                &[Message::user_text("status?")],
                "system",
                &ToolConfig {
                    tools: vec![],
                    required_tool: None,
                },
            )
            .await
            .unwrap();

        assert_eq!(
            response.stop_reason,
            super::super::types::StopReason::EndTurn
        );
        assert_eq!(
            response.output.message.content[0].as_text(),
            Some("all clear")
        );
        assert_eq!(response.usage.input_tokens, 11);
        assert_eq!(response.usage.output_tokens, 3);
    }

    #[tokio::test]
    async fn authenticated_http_errors_withhold_untrusted_response_bodies() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let api_token = r#"test"token\with\slashes"#;
        let escaped_token = serde_json::to_string(api_token).unwrap();
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_string(format!("public-body-marker {escaped_token}")),
            )
            .mount(&server)
            .await;

        let config = LlmConfig {
            backend: BackendConfig::OpenAiCompatible {
                api_url: server.uri(),
                api_token: Some(api_token.into()),
            },
            ..test_config()
        };
        let backend = OpenAiBackend::new(config).unwrap();

        let error = backend
            .converse(&[], "system", &build_tool_config())
            .await
            .unwrap_err();
        let rendered = error.to_string();

        assert!(rendered.contains("authenticated response body withheld"));
        assert!(!rendered.contains(api_token));
        assert!(!rendered.contains(&escaped_token));
        assert!(!rendered.contains("public-body-marker"));
    }
    #[tokio::test]
    async fn refuses_http_redirects_before_credentials_can_cross_origins() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let target = MockServer::start().await;
        let source = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("location", format!("{}/stolen", target.uri())),
            )
            .mount(&source)
            .await;
        Mock::given(method("POST"))
            .and(path("/stolen"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&target)
            .await;
        let config = LlmConfig {
            backend: BackendConfig::OpenAiCompatible {
                api_url: source.uri(),
                api_token: Some("test-token".into()),
            },
            max_retries: 0,
            ..test_config()
        };
        let backend = OpenAiBackend::new(config).unwrap();

        let error = backend
            .converse(&[], "system", &build_tool_config())
            .await
            .unwrap_err();

        assert!(matches!(error, LlmError::ApiError { status: 307, .. }));
        assert!(target.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn response_header_deadlines_are_typed_as_timeouts() {
        let error = timeout_from(stalling_http_server(false)).await;

        assert!(matches!(error, LlmError::Timeout { timeout_seconds: 1 }));
    }

    #[tokio::test]
    async fn streaming_body_deadlines_are_typed_as_timeouts() {
        let error = timeout_from(stalling_http_server(true)).await;

        assert!(matches!(error, LlmError::Timeout { timeout_seconds: 1 }));
    }

    #[tokio::test]
    async fn streaming_response_rejects_payloads_beyond_the_limit() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"data: over-limit\n"))
            .mount(&server)
            .await;
        let mut response = reqwest::get(server.uri()).await.unwrap();

        let error = read_sse_response_with_limit(&mut response, 8)
            .await
            .unwrap_err();

        assert!(matches!(error, LlmError::AgentProtocol(_)));
        assert!(error.to_string().contains("exceeded 8 bytes"));
    }

    async fn streaming_response(body: &'static [u8]) -> (wiremock::MockServer, reqwest::Response) {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(&server)
            .await;
        let response = reqwest::get(server.uri()).await.unwrap();
        (server, response)
    }

    #[tokio::test]
    async fn rejects_malformed_stream_data_events() {
        let (_server, mut response) =
            streaming_response(b"data: {not-json}\n\ndata: [DONE]\n").await;

        let error = read_sse_response(&mut response).await.unwrap_err();

        assert!(matches!(error, LlmError::IncompleteStream { .. }));
        assert!(error.to_string().contains("malformed data event"));
        assert!(is_retryable(&error));
    }

    #[tokio::test]
    async fn rejects_stream_eof_without_a_completion_signal() {
        let (_server, mut response) =
            streaming_response(b"data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n")
                .await;

        let error = read_sse_response(&mut response).await.unwrap_err();

        assert!(matches!(error, LlmError::IncompleteStream { .. }));
        assert!(error.to_string().contains("completion signal"));
        assert!(is_retryable(&error));
    }

    #[tokio::test]
    async fn accepts_finish_reason_when_done_marker_is_omitted() {
        let (_server, mut response) = streaming_response(
        b"data: {\"choices\":[{\"delta\":{\"content\":\"complete\"},\"finish_reason\":\"stop\"}]}\n",
    )
    .await;

        let result = read_sse_response(&mut response).await.unwrap();

        assert_eq!(result.output.message.content[0].as_text(), Some("complete"));
    }

    #[tokio::test]
    async fn bounded_response_body_preserves_only_the_allowed_prefix() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"abcdef"))
            .mount(&server)
            .await;
        let mut response = reqwest::get(server.uri()).await.unwrap();

        let body = read_response_body(&mut response, 4).await.unwrap();

        assert_eq!(body.bytes, b"abcd");
        assert!(body.truncated);
    }

    #[tokio::test]
    async fn bounded_response_body_accepts_the_exact_limit() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"abcd"))
            .mount(&server)
            .await;
        let mut response = reqwest::get(server.uri()).await.unwrap();

        let body = read_response_body(&mut response, 4).await.unwrap();

        assert_eq!(body.bytes, b"abcd");
        assert!(!body.truncated);
    }

    #[test]
    fn detects_context_window_across_provider_field_names() {
        let body = serde_json::json!({
            "data": [
                { "id": "vllm-model", "max_model_len": 65536 },
                { "id": "gateway-model", "context_length": 128000 }
            ]
        });
        assert_eq!(context_window_from_models(&body, "vllm-model"), Some(65536));
        assert_eq!(
            context_window_from_models(&body, "gateway-model"),
            Some(128000)
        );
    }

    #[test]
    fn returns_none_when_model_or_window_missing() {
        let body = serde_json::json!({
            "data": [{ "id": "model-without-window", "object": "model" }]
        });
        assert_eq!(
            context_window_from_models(&body, "model-without-window"),
            None
        );
        assert_eq!(context_window_from_models(&body, "absent"), None);
    }

    #[test]
    fn rejects_claude_cli_backend() {
        let config = LlmConfig {
            backend: BackendConfig::ClaudeCli {
                binary: "claude".into(),
            },
            ..test_config()
        };

        assert!(matches!(
            OpenAiBackend::new(config),
            Err(LlmError::AuthError)
        ));
    }

    #[tokio::test]
    async fn detects_context_window_from_models_endpoint() {
        let body = serde_json::json!({
            "data": [{ "id": "test-model", "context_window": 65_536 }]
        });
        let server = models_server(ResponseTemplate::new(200).set_body_json(body)).await;
        let backend = backend_for(&server, 0);

        assert_eq!(backend.detect_context_window().await, Some(65_536));
    }

    #[tokio::test]
    async fn context_window_detection_rejects_bad_status_body_and_transport() {
        let failure = models_server(ResponseTemplate::new(500)).await;
        assert_eq!(backend_for(&failure, 0).detect_context_window().await, None);

        let invalid =
            models_server(ResponseTemplate::new(200).set_body_string("<html>gateway</html>")).await;
        assert_eq!(backend_for(&invalid, 0).detect_context_window().await, None);

        let oversized = models_server(ResponseTemplate::new(200).set_body_bytes(vec![
            b' ';
            MAX_MODEL_RESPONSE_BYTES
                + 1
        ]))
        .await;
        assert_eq!(
            backend_for(&oversized, 0).detect_context_window().await,
            None
        );

        let transport = OpenAiBackend::new(openai_config(closing_http_server(), 0)).unwrap();
        assert_eq!(transport.detect_context_window().await, None);
    }

    #[tokio::test]
    async fn authentication_failures_are_not_retried() {
        for status in [401u16, 403] {
            let server = completions_server(ResponseTemplate::new(status)).await;
            let error = converse_once(&backend_for(&server, 3)).await.unwrap_err();

            assert!(matches!(error, LlmError::AuthError));
            assert_eq!(request_count(&server).await, 1);
        }
    }

    #[tokio::test]
    async fn client_error_preserves_status_and_withholds_body() {
        let server =
            completions_server(ResponseTemplate::new(400).set_body_string("unknown model")).await;
        let error = converse_once(&backend_for(&server, 3)).await.unwrap_err();

        assert!(matches!(
            error,
            LlmError::ApiError { status: 400, ref body }
                if body == AUTHENTICATED_ERROR_BODY
        ));
        assert_eq!(request_count(&server).await, 1);
    }

    #[tokio::test]
    async fn client_error_does_not_read_a_partial_body() {
        let backend =
            OpenAiBackend::new(openai_config(truncated_http_server(400, b"short"), 0)).unwrap();
        let error = converse_once(&backend).await.unwrap_err();

        assert!(matches!(
            error,
            LlmError::ApiError { status: 400, ref body }
                if body == AUTHENTICATED_ERROR_BODY
        ));
    }

    #[tokio::test]
    async fn rate_limit_parses_retry_after_and_withholds_fallback_body() {
        let server =
            completions_server(ResponseTemplate::new(429).insert_header("retry-after", "3")).await;
        let error = converse_once(&backend_for(&server, 0)).await.unwrap_err();
        assert!(matches!(
            error,
            LlmError::RateLimited {
                retry_after_seconds: 3
            }
        ));

        for header in [None, Some("not-seconds")] {
            let mut template = ResponseTemplate::new(429).set_body_string("slow down");
            if let Some(value) = header {
                template = template.insert_header("retry-after", value);
            }
            let server = completions_server(template).await;
            let error = converse_once(&backend_for(&server, 0)).await.unwrap_err();
            assert!(matches!(
                error,
                LlmError::ApiError { status: 429, ref body }
                    if body == AUTHENTICATED_ERROR_BODY
            ));
        }
    }

    #[tokio::test]
    async fn zero_retry_after_retries_without_a_fixed_delay() {
        let first = ResponseTemplate::new(429).insert_header("retry-after", "0");
        let server = completions_server_failing_once(first).await;

        let response = converse_once(&backend_for(&server, 1)).await.unwrap();

        assert_eq!(
            response.output.message.content[0].as_text(),
            Some("all clear")
        );
        assert_eq!(request_count(&server).await, 2);
    }

    #[tokio::test]
    async fn an_absurd_retry_after_header_is_bounded_before_any_timer() {
        let header = u64::MAX.to_string();
        let server = completions_server(
            ResponseTemplate::new(429).insert_header("retry-after", header.as_str()),
        )
        .await;

        let error = converse_once(&backend_for(&server, 0)).await.unwrap_err();

        assert!(matches!(
            error,
            LlmError::RateLimited {
                retry_after_seconds: MAX_RETRY_AFTER_SECONDS
            }
        ));
        assert_eq!(
            backoff_duration(&Some(error), 1),
            Duration::from_secs(MAX_RETRY_AFTER_SECONDS)
        );
        assert_eq!(
            backoff_duration(
                &Some(LlmError::RateLimited {
                    retry_after_seconds: u64::MAX
                }),
                1
            ),
            Duration::from_secs(MAX_RETRY_AFTER_SECONDS),
            "an unbounded rate limit must never reach the timer"
        );
    }

    #[tokio::test]
    async fn tool_call_arguments_beyond_the_limit_fail_the_response() {
        let chunk = serde_json::json!({
            "choices": [{
                "delta": {
                    "tool_calls": [{
                        "index": 0,
                        "id": "call-1",
                        "function": {
                            "name": "read_file",
                            "arguments": "a".repeat(MAX_TOOL_ARGUMENT_BYTES + 1)
                        }
                    }]
                }
            }]
        });
        let server = completions_server(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(format!("data: {chunk}\ndata: [DONE]\n")),
        )
        .await;

        let error = converse_once(&backend_for(&server, 0)).await.unwrap_err();

        let rendered = error.to_string();
        assert!(matches!(error, LlmError::AgentProtocol(_)), "{rendered}");
        assert!(
            rendered.contains(&MAX_TOOL_ARGUMENT_BYTES.to_string()),
            "{rendered}"
        );
        assert!(rendered.contains("tool call arguments"), "{rendered}");
    }

    #[tokio::test]
    async fn closed_connection_maps_to_network_error() {
        let backend = OpenAiBackend::new(openai_config(closing_http_server(), 0)).unwrap();

        let error = converse_once(&backend).await.unwrap_err();

        assert!(matches!(error, LlmError::Network(_)));
    }

    #[tokio::test]
    async fn completed_stream_without_payload_is_rejected() {
        let server = completions_server(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string("data: [DONE]\n\n"),
        )
        .await;

        let error = converse_once(&backend_for(&server, 0)).await.unwrap_err();

        assert!(matches!(
            error,
            LlmError::ApiError { status: 200, ref body }
                if body == "stream closed without producing a response"
        ));
    }
}
