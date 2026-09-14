use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum BugHunterError {
    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("engine error: {0}")]
    Engine(#[from] EngineError),

    #[error("LLM error: {0}")]
    Llm(#[from] LlmError),

    #[error("analysis error: {0}")]
    Analysis(#[from] AnalysisError),

    #[error("report error: {0}")]
    Report(#[from] ReportError),

    #[error("repo map error: {0}")]
    RepoMap(#[from] RepoMapError),

    #[error("PR review error: {0}")]
    Review(#[from] crate::review::ReviewError),

    #[error("analysis cancelled")]
    Cancelled,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("config file not found: {path}")]
    FileNotFound { path: PathBuf },

    #[error("invalid config: {field}: {reason}")]
    InvalidValue { field: String, reason: String },

    #[error("missing required config: {field} (set via {hint})")]
    MissingRequired { field: String, hint: String },

    #[error("failed to parse config file {path}: {message}")]
    ParseError { path: PathBuf, message: String },

    #[error("failed to read config file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write config file {path}: {source}")]
    WriteFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("config file already exists: {path}")]
    AlreadyExists { path: PathBuf },
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("analysis cancelled")]
    Cancelled,

    #[error("file not found: {0}")]
    FileNotFound(PathBuf),

    #[error("path excluded from analysis: {0}")]
    ExcludedPath(PathBuf),

    #[error("not a regular file: {0}")]
    NotRegularFile(PathBuf),

    #[error("file too large: {path} ({size_bytes} bytes, max {max_bytes})")]
    FileTooLarge {
        path: PathBuf,
        size_bytes: u64,
        max_bytes: u64,
    },

    #[error("static analysis exceeded the limit of {max_findings} findings")]
    FindingLimitExceeded { max_findings: usize },

    #[error("static analysis retained finding data exceeds the {max_bytes} byte limit")]
    FindingBytesExceeded { max_bytes: usize },

    #[error("AST {resource} limit of {limit} exceeded")]
    AstLimitExceeded {
        resource: &'static str,
        limit: usize,
    },

    #[error("project discovery {resource} limit of {limit} exceeded")]
    DiscoveryLimitExceeded { resource: &'static str, limit: u64 },
    #[error("search {resource} limit of {limit} exceeded")]
    SearchLimitExceeded {
        resource: &'static str,
        limit: usize,
    },

    #[error("invalid regex pattern '{pattern}': {source}")]
    InvalidPattern {
        pattern: String,
        #[source]
        source: regex::Error,
    },

    #[error("tree-sitter parse failed for {path}: {reason}")]
    ParseFailed { path: PathBuf, reason: String },

    #[error("unsupported language for AST operations: {language}")]
    UnsupportedLanguage { language: String },

    #[error("IO error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    #[error("API request failed: HTTP {status}: {body}")]
    ApiError { status: u16, body: String },

    #[error("authentication failed: check BUGHUNTER_API_TOKEN")]
    AuthError,

    #[error("rate limited, retry after {retry_after_seconds}s")]
    RateLimited { retry_after_seconds: u64 },

    #[error("request timed out after {timeout_seconds}s")]
    Timeout { timeout_seconds: u64 },

    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("incomplete model response stream: {reason}")]
    IncompleteStream { reason: &'static str },

    #[error(
        "failed to spawn claude CLI at {binary}: {source}. Ensure the binary is installed and on PATH, or set llm.claude_cli_binary"
    )]
    ClaudeSpawn {
        binary: String,
        #[source]
        source: std::io::Error,
    },

    #[error("claude CLI failed (exit {code:?}): {stderr}")]
    ClaudeProcess { code: Option<i32>, stderr: String },

    #[error("failed to {action}: {source}")]
    Io {
        action: String,
        #[source]
        source: std::io::Error,
    },

    #[error("serialization failed: {0}")]
    Serialization(String),

    #[error("agent protocol error: {0}")]
    AgentProtocol(String),

    #[error("cancelled")]
    Cancelled,
}

#[derive(Debug, thiserror::Error)]
pub enum AnalysisError {
    #[error("static analysis failed: {0}")]
    StaticCheckFailed(String),

    #[error("{action} worker failed: {reason}")]
    WorkerFailed {
        action: &'static str,
        reason: String,
    },

    #[error("terminal UI failed to {action}: {source}")]
    TerminalFailed {
        action: &'static str,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("failed to write report to {path}: {source}")]
    WriteError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("serialization failed: {0}")]
    SerializationError(String),

    #[error("{resource} exceeds the {limit_bytes} byte limit")]
    TooLarge {
        resource: &'static str,
        limit_bytes: usize,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum RepoMapError {
    #[error("failed to build repo map: {0}")]
    BuildFailed(String),

    #[error("no source files found in {0}")]
    EmptyProject(PathBuf),
}

pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_FINDINGS: i32 = 1;
pub const EXIT_CONFIG_ERROR: i32 = 2;
pub const EXIT_API_ERROR: i32 = 3;
pub const EXIT_PROJECT_ERROR: i32 = 4;
pub const EXIT_PARTIAL: i32 = 5;
pub const EXIT_CANCELLED: i32 = 130;

pub fn exit_code_for_error(error: &BugHunterError) -> i32 {
    match error {
        BugHunterError::Cancelled | BugHunterError::Llm(LlmError::Cancelled) => EXIT_CANCELLED,
        BugHunterError::Config(_) => EXIT_CONFIG_ERROR,
        BugHunterError::Llm(_) => EXIT_API_ERROR,
        BugHunterError::Engine(_)
        | BugHunterError::RepoMap(_)
        | BugHunterError::Analysis(_)
        | BugHunterError::Review(_)
        | BugHunterError::Report(_) => EXIT_PROJECT_ERROR,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn config_error_returns_exit_code_2() {
        let err = BugHunterError::Config(ConfigError::MissingRequired {
            field: "token".into(),
            hint: "set BUGHUNTER_API_TOKEN".into(),
        });
        assert_eq!(exit_code_for_error(&err), EXIT_CONFIG_ERROR);
    }

    #[test]
    fn llm_error_returns_exit_code_3() {
        let err = BugHunterError::Llm(LlmError::AuthError);
        assert_eq!(exit_code_for_error(&err), EXIT_API_ERROR);
    }

    #[test]
    fn engine_error_returns_exit_code_4() {
        let err = BugHunterError::Engine(EngineError::FileNotFound("/test".into()));
        assert_eq!(exit_code_for_error(&err), EXIT_PROJECT_ERROR);
    }

    #[test]
    fn report_error_returns_exit_code_4() {
        let err = BugHunterError::Report(ReportError::SerializationError("bad".into()));
        assert_eq!(exit_code_for_error(&err), EXIT_PROJECT_ERROR);
    }

    #[test]
    fn analysis_error_returns_exit_code_4() {
        let err = BugHunterError::Analysis(AnalysisError::StaticCheckFailed("boom".into()));
        assert_eq!(exit_code_for_error(&err), EXIT_PROJECT_ERROR);
    }

    #[test]
    fn repomap_error_returns_exit_code_4() {
        let err = BugHunterError::RepoMap(RepoMapError::EmptyProject("/test".into()));
        assert_eq!(exit_code_for_error(&err), EXIT_PROJECT_ERROR);
    }

    #[test]
    fn config_error_from_conversion() {
        let config_err = ConfigError::MissingRequired {
            field: "f".into(),
            hint: "h".into(),
        };
        let err: BugHunterError = config_err.into();
        assert!(matches!(err, BugHunterError::Config(_)));
    }

    #[test]
    fn error_messages_contain_context() {
        let err = ConfigError::InvalidValue {
            field: "temperature".into(),
            reason: "must be between 0 and 1".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("temperature"));
        assert!(msg.contains("must be between 0 and 1"));
    }

    #[test]
    fn engine_error_file_too_large_message() {
        let err = EngineError::FileTooLarge {
            path: "/big.rs".into(),
            size_bytes: 2_000_000,
            max_bytes: 1_000_000,
        };
        let msg = err.to_string();
        assert!(msg.contains("2000000"));
        assert!(msg.contains("1000000"));
    }

    #[test]
    fn cancelled_error_returns_exit_code_130() {
        assert_eq!(exit_code_for_error(&BugHunterError::Cancelled), 130);
        assert_eq!(
            exit_code_for_error(&BugHunterError::Cancelled),
            EXIT_CANCELLED
        );
    }

    #[test]
    fn cancelled_llm_error_returns_exit_code_130() {
        let err = BugHunterError::Llm(LlmError::Cancelled);
        assert_eq!(exit_code_for_error(&err), EXIT_CANCELLED);
    }

    #[test]
    fn cancelled_llm_error_does_not_map_to_api_error() {
        let err = BugHunterError::Llm(LlmError::Cancelled);
        assert_ne!(exit_code_for_error(&err), EXIT_API_ERROR);
    }

    #[test]
    fn partial_exit_code_is_five() {
        assert_eq!(EXIT_PARTIAL, 5);
    }

    #[test]
    fn cancellation_messages_are_stable() {
        assert_eq!(BugHunterError::Cancelled.to_string(), "analysis cancelled");
        assert_eq!(LlmError::Cancelled.to_string(), "cancelled");
    }

    #[test]
    fn cancelled_llm_error_converts_into_cancelled_variant() {
        let err: BugHunterError = LlmError::Cancelled.into();
        assert!(matches!(err, BugHunterError::Llm(LlmError::Cancelled)));
        assert_eq!(exit_code_for_error(&err), EXIT_CANCELLED);
    }
}
