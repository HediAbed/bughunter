use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const OPENAI_DEFAULT_API_URL: &str = "";
const OPENAI_DEFAULT_MODEL: &str = "";
const DEFAULT_MAX_TOKENS: u32 = 8192;
const DEFAULT_TIMEOUT_SECONDS: u64 = 180;
const DEFAULT_MAX_RETRIES: u32 = 3;
const DEFAULT_MAX_AGENT_ITERATIONS: u32 = 50;
const DEFAULT_MAX_SHARD_SECONDS: u64 = 900;
const AUTO_CONTEXT_TOKENS: u32 = 0;
const DEFAULT_CONTEXT_TOKENS: u32 = 128_000;
pub(crate) const MIN_CONTEXT_TOKENS: u32 = 40_000;
pub(crate) const MAX_CONTEXT_TOKENS: u32 = 2_000_000;
const DEFAULT_CLAUDE_CLI_BINARY: &str = "claude";
const DEFAULT_MAX_FILE_SIZE_BYTES: u64 = 1_048_576;
const DEFAULT_MAX_FUNCTION_LINES: usize = 50;
const DEFAULT_MAX_FILE_LINES: usize = 500;

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub general: GeneralConfig,
    pub engine: EngineConfig,
    pub llm: LlmConfig,
    pub analysis: AnalysisConfig,
}

#[derive(Debug, Clone)]
pub struct GeneralConfig {
    pub log_level: LogLevel,
    pub fail_severity: Severity,
    pub min_confidence: Confidence,
    pub output_format: OutputFormat,
    pub output_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiscoverySource {
    #[default]
    LocalCheckout,
    UntrustedSnapshot,
}

impl DiscoverySource {
    pub fn honors_repository_ignore_files(self) -> bool {
        matches!(self, Self::LocalCheckout)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    pub max_file_size_bytes: u64,
    pub exclude_dirs: Vec<String>,
    pub exclude_extensions: Vec<String>,
    pub max_depth: Option<usize>,
    pub discovery_source: DiscoverySource,
}

#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub backend: BackendConfig,
    pub model: String,
    pub max_tokens: u32,
    pub temperature: f32,
    pub reasoning_effort: Option<String>,
    pub timeout_seconds: u64,
    pub max_retries: u32,
    pub max_agent_iterations: u32,
    pub max_context_tokens: u32,
    pub max_shard_seconds: u64,
}

#[derive(Clone)]
pub enum BackendConfig {
    OpenAiCompatible {
        api_url: String,
        api_token: Option<String>,
    },
    ClaudeCli {
        binary: String,
    },
}

impl std::fmt::Debug for BackendConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendConfig::OpenAiCompatible { api_url, api_token } => f
                .debug_struct("OpenAiCompatible")
                .field("api_url", api_url)
                .field("api_token", &api_token.as_ref().map(|_| "<redacted>"))
                .finish(),
            BackendConfig::ClaudeCli { binary } => {
                f.debug_struct("ClaudeCli").field("binary", binary).finish()
            }
        }
    }
}

#[derive(Clone)]
pub struct LlmSettings {
    pub backend: LlmBackendKind,
    pub api_url: String,
    pub api_token: Option<String>,
    pub model: String,
    pub max_tokens: u32,
    pub temperature: f32,
    pub reasoning_effort: Option<String>,
    pub timeout_seconds: u64,
    pub max_retries: u32,
    pub max_agent_iterations: u32,
    pub max_context_tokens: u32,
    pub max_shard_seconds: u64,
    pub claude_cli_binary: String,
}

impl LlmSettings {
    pub fn build(self) -> LlmConfig {
        let backend = match self.backend {
            LlmBackendKind::OpenAiCompatible => BackendConfig::OpenAiCompatible {
                api_url: self.api_url,
                api_token: self.api_token,
            },
            LlmBackendKind::ClaudeCli => BackendConfig::ClaudeCli {
                binary: self.claude_cli_binary,
            },
        };
        LlmConfig {
            backend,
            model: self.model,
            max_tokens: self.max_tokens,
            temperature: self.temperature,
            reasoning_effort: self.reasoning_effort,
            timeout_seconds: self.timeout_seconds,
            max_retries: self.max_retries,
            max_agent_iterations: self.max_agent_iterations,
            max_context_tokens: self.max_context_tokens,
            max_shard_seconds: self.max_shard_seconds,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LlmBackendKind {
    #[serde(rename = "openai-compatible")]
    OpenAiCompatible,
    ClaudeCli,
}

#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    pub categories: Vec<AnalysisCategory>,
    pub quality: QualityThresholds,
    pub solid: SolidConfig,
}

#[derive(Debug, Clone)]
pub struct QualityThresholds {
    pub max_function_lines: usize,
    pub max_file_lines: usize,
}

#[derive(Debug, Clone)]
pub struct SolidConfig {
    pub check_srp: bool,
    pub check_ocp: bool,
    pub check_lsp: bool,
    pub check_isp: bool,
    pub check_dip: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, serde::Serialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, serde::Serialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Json,
    Md,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AnalysisCategory {
    Bug,
    Quality,
    Solid,
    Vulnerability,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            log_level: LogLevel::Info,
            fail_severity: Severity::High,
            min_confidence: Confidence::Low,
            output_format: OutputFormat::Json,
            output_path: None,
        }
    }
}

const DEFAULT_EXCLUDE_DIRS: &[&str] = &[
    ".git",
    ".svn",
    ".hg",
    ".aws",
    ".ssh",
    ".gnupg",
    "node_modules",
    ".next",
    ".nuxt",
    ".output",
    "bower_components",
    "target",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "site-packages",
    ".eggs",
    "vendor",
    ".gradle",
    ".m2",
    "obj",
    "packages",
    "dist",
    "build",
    "out",
    ".cache",
    "coverage",
    ".nyc_output",
    ".idea",
    ".vscode",
    ".vs",
    ".eclipse",
    ".docker",
    ".terraform",
];

const DEFAULT_EXCLUDE_EXTENSIONS: &[&str] = &[
    "lock", "map", "wasm", "pyc", "pyo", "class", "o", "so", "dylib", "dll", "exe", "a", "lib",
    "jar", "war", "ear", "zip", "tar", "gz", "png", "jpg", "jpeg", "gif", "ico", "svg", "woff",
    "woff2", "ttf", "eot", "mp3", "mp4", "pdf", "db", "sqlite", "sqlite3",
];

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            max_file_size_bytes: DEFAULT_MAX_FILE_SIZE_BYTES,
            exclude_dirs: DEFAULT_EXCLUDE_DIRS.iter().map(|s| (*s).into()).collect(),
            exclude_extensions: DEFAULT_EXCLUDE_EXTENSIONS
                .iter()
                .map(|s| (*s).into())
                .collect(),
            max_depth: None,
            discovery_source: DiscoverySource::default(),
        }
    }
}

impl Default for LlmConfig {
    fn default() -> Self {
        LlmSettings::default().build()
    }
}

impl Default for LlmSettings {
    fn default() -> Self {
        Self {
            backend: LlmBackendKind::ClaudeCli,
            api_url: OPENAI_DEFAULT_API_URL.into(),
            api_token: None,
            model: OPENAI_DEFAULT_MODEL.into(),
            max_tokens: DEFAULT_MAX_TOKENS,
            temperature: 0.0,
            reasoning_effort: None,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            max_retries: DEFAULT_MAX_RETRIES,
            max_agent_iterations: DEFAULT_MAX_AGENT_ITERATIONS,
            max_context_tokens: AUTO_CONTEXT_TOKENS,
            max_shard_seconds: DEFAULT_MAX_SHARD_SECONDS,
            claude_cli_binary: DEFAULT_CLAUDE_CLI_BINARY.into(),
        }
    }
}

impl LlmConfig {
    pub fn effective_context_tokens(&self) -> u32 {
        if self.max_context_tokens == AUTO_CONTEXT_TOKENS {
            DEFAULT_CONTEXT_TOKENS
        } else {
            self.max_context_tokens
        }
    }
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            categories: vec![
                AnalysisCategory::Bug,
                AnalysisCategory::Quality,
                AnalysisCategory::Solid,
                AnalysisCategory::Vulnerability,
            ],
            quality: QualityThresholds::default(),
            solid: SolidConfig::default(),
        }
    }
}

impl Default for QualityThresholds {
    fn default() -> Self {
        Self {
            max_function_lines: DEFAULT_MAX_FUNCTION_LINES,
            max_file_lines: DEFAULT_MAX_FILE_LINES,
        }
    }
}

impl Default for SolidConfig {
    fn default() -> Self {
        Self {
            check_srp: true,
            check_ocp: true,
            check_lsp: true,
            check_isp: true,
            check_dip: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisMode {
    Static,
    AiOnly,
    Full,
    Review,
}

impl AnalysisMode {
    pub fn requires_ai(&self) -> bool {
        matches!(
            self,
            AnalysisMode::AiOnly | AnalysisMode::Full | AnalysisMode::Review
        )
    }

    pub fn requires_static(&self) -> bool {
        matches!(self, AnalysisMode::Static | AnalysisMode::Full)
    }
}

impl std::fmt::Display for AnalysisMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnalysisMode::Static => write!(f, "static"),
            AnalysisMode::AiOnly => write!(f, "ai"),
            AnalysisMode::Full => write!(f, "full"),
            AnalysisMode::Review => write!(f, "review"),
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}
impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::Low => write!(f, "low"),
            Confidence::Medium => write!(f, "medium"),
            Confidence::High => write!(f, "high"),
        }
    }
}

impl std::fmt::Display for AnalysisCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnalysisCategory::Bug => write!(f, "bug"),
            AnalysisCategory::Quality => write!(f, "quality"),
            AnalysisCategory::Solid => write!(f, "solid"),
            AnalysisCategory::Vulnerability => write!(f, "vulnerability"),
        }
    }
}

#[cfg(test)]
#[path = "schema_tests.rs"]
mod tests;
