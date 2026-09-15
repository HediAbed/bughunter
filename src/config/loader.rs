use std::path::{Path, PathBuf};

use crate::errors::ConfigError;
use crate::shared::read_bounded_string;
use serde::Deserialize;

const MAX_CONFIG_BYTES: usize = 1024 * 1024;

use super::schema::{
    AnalysisCategory, AnalysisConfig, Confidence, Config, EngineConfig, GeneralConfig,
    LlmBackendKind, LlmSettings, LogLevel, OutputFormat, QualityThresholds, Severity, SolidConfig,
};

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct TomlConfig {
    general: Option<TomlGeneral>,
    engine: Option<TomlEngine>,
    llm: Option<TomlLlm>,
    analysis: Option<TomlAnalysis>,
    api_token: Option<serde::de::IgnoredAny>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct TomlGeneral {
    log_level: Option<LogLevel>,
    fail_severity: Option<Severity>,
    min_confidence: Option<Confidence>,
    output_format: Option<OutputFormat>,
    output_path: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct TomlEngine {
    max_file_size_bytes: Option<u64>,
    exclude_dirs: Option<Vec<String>>,
    exclude_extensions: Option<Vec<String>>,
    max_depth: Option<usize>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct TomlLlm {
    backend: Option<LlmBackendKind>,
    api_url: Option<String>,
    model: Option<String>,
    max_tokens: Option<u32>,
    temperature: Option<f32>,
    reasoning_effort: Option<String>,
    timeout_seconds: Option<u64>,
    max_retries: Option<u32>,
    max_agent_iterations: Option<u32>,
    max_context_tokens: Option<u32>,
    max_shard_seconds: Option<u64>,
    claude_cli_binary: Option<String>,
    api_token: Option<serde::de::IgnoredAny>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct TomlAnalysis {
    categories: Option<Vec<AnalysisCategory>>,
    quality: Option<TomlQuality>,
    solid: Option<TomlSolid>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct TomlQuality {
    max_function_lines: Option<usize>,
    max_file_lines: Option<usize>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct TomlSolid {
    check_srp: Option<bool>,
    check_ocp: Option<bool>,
    check_lsp: Option<bool>,
    check_isp: Option<bool>,
    check_dip: Option<bool>,
}

pub struct TrustedConfigSource {
    project_root: PathBuf,
    explicit_file: Option<PathBuf>,
    user_file: Option<PathBuf>,
}

impl TrustedConfigSource {
    pub fn for_local_checkout(project_root: &Path, explicit_file: Option<&Path>) -> Self {
        Self {
            project_root: project_root.to_path_buf(),
            explicit_file: explicit_file.map(Path::to_path_buf),
            user_file: user_config_path(),
        }
    }

    fn project_file(&self) -> PathBuf {
        match &self.explicit_file {
            Some(path) => path.clone(),
            None => self.project_root.join(".bughunter.toml"),
        }
    }

    fn existing_user_file(&self) -> Option<&Path> {
        self.user_file.as_deref().filter(|path| path.exists())
    }

    fn existing_project_file(&self) -> Option<PathBuf> {
        let path = self.project_file();
        path.exists().then_some(path)
    }

    pub fn existing_files(&self) -> Vec<PathBuf> {
        let mut files = Vec::with_capacity(2);
        files.extend(self.existing_user_file().map(Path::to_path_buf));
        files.extend(self.existing_project_file());
        files
    }
}

pub fn load_config(source: &TrustedConfigSource) -> Result<Config, ConfigError> {
    let mut config = Config::default();
    let mut llm = LlmSettings::default();

    if let Some(path) = source.existing_user_file() {
        merge_toml(&mut config, &mut llm, &parse_toml_file(path)?);
    }

    if let Some(path) = &source.explicit_file
        && !path.exists()
    {
        return Err(ConfigError::FileNotFound { path: path.clone() });
    }

    if let Some(path) = source.existing_project_file() {
        let toml = parse_toml_file(&path)?;
        if source.explicit_file.is_some() {
            merge_toml(&mut config, &mut llm, &toml);
        } else {
            merge_discovered_project_toml(&mut config, &toml);
        }
    }

    merge_env(&mut config, &mut llm)?;

    llm.api_url = normalize_api_url(&llm.api_url);
    config.llm = llm.build();
    Ok(config)
}

fn user_config_path() -> Option<PathBuf> {
    directories::BaseDirs::new().map(|dirs| dirs.home_dir().join(".bughunter").join("config.toml"))
}

fn parse_toml_file(path: &Path) -> Result<TomlConfig, ConfigError> {
    let content = read_bounded_string(path, MAX_CONFIG_BYTES).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            ConfigError::FileNotFound {
                path: path.to_path_buf(),
            }
        } else {
            ConfigError::Io {
                path: path.to_path_buf(),
                source,
            }
        }
    })?;

    parse_toml_text(&content, path)
}

fn parse_toml_text(content: &str, path: &Path) -> Result<TomlConfig, ConfigError> {
    let toml: TomlConfig = toml::from_str(content).map_err(|error| ConfigError::ParseError {
        path: path.to_path_buf(),
        message: error.message().to_string(),
    })?;
    if persists_an_api_token(&toml) {
        return Err(ConfigError::InvalidValue {
            field: "llm.api_token".to_string(),
            reason: "API tokens must be supplied through BUGHUNTER_API_TOKEN".to_string(),
        });
    }
    Ok(toml)
}

fn persists_an_api_token(toml: &TomlConfig) -> bool {
    toml.api_token.is_some() || toml.llm.as_ref().is_some_and(|llm| llm.api_token.is_some())
}

fn merge_toml(config: &mut Config, llm: &mut LlmSettings, toml: &TomlConfig) {
    if let Some(general) = &toml.general {
        merge_general(&mut config.general, general);
    }
    if let Some(engine) = &toml.engine {
        merge_engine(&mut config.engine, engine);
    }
    if let Some(toml_llm) = &toml.llm {
        merge_llm(llm, toml_llm);
    }
    if let Some(analysis) = &toml.analysis {
        merge_analysis(&mut config.analysis, analysis);
    }
}

fn merge_discovered_project_toml(config: &mut Config, toml: &TomlConfig) {
    if let Some(general) = &toml.general {
        merge_general_without_output_path(&mut config.general, general);
    }
    if let Some(engine) = &toml.engine {
        merge_engine(&mut config.engine, engine);
    }
    if let Some(analysis) = &toml.analysis {
        merge_analysis(&mut config.analysis, analysis);
    }
}

fn merge_general(config: &mut GeneralConfig, toml: &TomlGeneral) {
    merge_general_without_output_path(config, toml);
    if let Some(v) = &toml.output_path {
        config.output_path = Some(v.clone());
    }
}

fn merge_general_without_output_path(config: &mut GeneralConfig, toml: &TomlGeneral) {
    if let Some(v) = &toml.log_level {
        config.log_level = v.clone();
    }
    if let Some(v) = toml.fail_severity {
        config.fail_severity = v;
    }
    if let Some(v) = toml.min_confidence {
        config.min_confidence = v;
    }
    if let Some(v) = &toml.output_format {
        config.output_format = v.clone();
    }
}

fn merge_engine(config: &mut EngineConfig, toml: &TomlEngine) {
    if let Some(v) = toml.max_file_size_bytes {
        config.max_file_size_bytes = v;
    }
    if let Some(v) = &toml.exclude_dirs {
        extend_exclusions(&mut config.exclude_dirs, v);
    }
    if let Some(v) = &toml.exclude_extensions {
        extend_exclusions(&mut config.exclude_extensions, v);
    }
    if toml.max_depth.is_some() {
        config.max_depth = toml.max_depth;
    }
}

fn extend_exclusions(current: &mut Vec<String>, additional: &[String]) {
    current.extend_from_slice(additional);
    current.sort();
    current.dedup();
}

fn merge_llm(config: &mut LlmSettings, toml: &TomlLlm) {
    if let Some(v) = toml.backend {
        config.backend = v;
    }
    if let Some(v) = &toml.api_url {
        config.api_url = v.clone();
    }
    if let Some(v) = &toml.model {
        config.model = v.clone();
    }
    if let Some(v) = toml.max_tokens {
        config.max_tokens = v;
    }
    if let Some(v) = toml.temperature {
        config.temperature = v;
    }
    if let Some(v) = &toml.reasoning_effort {
        config.reasoning_effort = Some(v.clone());
    }
    if let Some(v) = toml.timeout_seconds {
        config.timeout_seconds = v;
    }
    if let Some(v) = toml.max_retries {
        config.max_retries = v;
    }
    if let Some(v) = toml.max_agent_iterations {
        config.max_agent_iterations = v;
    }
    if let Some(v) = toml.max_context_tokens {
        config.max_context_tokens = v;
    }
    if let Some(v) = toml.max_shard_seconds {
        config.max_shard_seconds = v;
    }
    if let Some(v) = &toml.claude_cli_binary {
        config.claude_cli_binary = v.clone();
    }
}

fn normalize_api_url(api_url: &str) -> String {
    api_url.trim().trim_end_matches('/').to_string()
}

fn merge_analysis(config: &mut AnalysisConfig, toml: &TomlAnalysis) {
    if let Some(v) = &toml.categories {
        config.categories = v.clone();
    }
    if let Some(quality) = &toml.quality {
        merge_quality(&mut config.quality, quality);
    }
    if let Some(solid) = &toml.solid {
        merge_solid(&mut config.solid, solid);
    }
}

fn merge_quality(config: &mut QualityThresholds, toml: &TomlQuality) {
    if let Some(v) = toml.max_function_lines {
        config.max_function_lines = v;
    }
    if let Some(v) = toml.max_file_lines {
        config.max_file_lines = v;
    }
}

fn merge_solid(config: &mut SolidConfig, toml: &TomlSolid) {
    if let Some(v) = toml.check_srp {
        config.check_srp = v;
    }
    if let Some(v) = toml.check_ocp {
        config.check_ocp = v;
    }
    if let Some(v) = toml.check_lsp {
        config.check_lsp = v;
    }
    if let Some(v) = toml.check_isp {
        config.check_isp = v;
    }
    if let Some(v) = toml.check_dip {
        config.check_dip = v;
    }
}

fn merge_env(config: &mut Config, llm: &mut LlmSettings) -> Result<(), ConfigError> {
    if let Some(value) = env_value("BUGHUNTER_BACKEND")? {
        llm.backend = parse_backend(&value)?;
    }
    if let Some(value) = env_value("BUGHUNTER_CLAUDE_CLI_BINARY")? {
        llm.claude_cli_binary = value;
    }
    if let Some(value) = env_value("BUGHUNTER_API_TOKEN")? {
        llm.api_token = Some(value);
    }
    if let Some(value) = env_value("BUGHUNTER_API_URL")? {
        llm.api_url = value;
    }
    if let Some(value) = env_value("BUGHUNTER_MODEL")? {
        llm.model = value;
    }
    if let Some(tokens) = env_number("BUGHUNTER_MAX_CONTEXT_TOKENS", "a non-negative integer")? {
        llm.max_context_tokens = tokens;
    }
    if let Some(seconds) = env_number("BUGHUNTER_MAX_SHARD_SECONDS", "a positive integer")? {
        llm.max_shard_seconds = seconds;
    }
    if let Some(value) = env_value("BUGHUNTER_LOG_LEVEL")? {
        config.general.log_level = parse_log_level(&value)?;
    }
    if let Some(value) = env_value("BUGHUNTER_CATEGORIES")? {
        config.analysis.categories = parse_categories(&value)?;
    }
    Ok(())
}

fn env_value(key: &str) -> Result<Option<String>, ConfigError> {
    match std::env::var(key) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(invalid_env(
            key,
            "must contain valid Unicode text".to_string(),
        )),
    }
}

fn parse_backend(value: &str) -> Result<LlmBackendKind, ConfigError> {
    match value.to_lowercase().as_str() {
        "openai-compatible" => Ok(LlmBackendKind::OpenAiCompatible),
        "claude-cli" => Ok(LlmBackendKind::ClaudeCli),
        _ => Err(invalid_env(
            "BUGHUNTER_BACKEND",
            "expected openai-compatible or claude-cli".to_string(),
        )),
    }
}

fn env_number<T: std::str::FromStr>(key: &str, expected: &str) -> Result<Option<T>, ConfigError> {
    let Some(value) = env_value(key)? else {
        return Ok(None);
    };
    parse_env_number(key, &value, expected).map(Some)
}

fn parse_env_number<T: std::str::FromStr>(
    key: &str,
    value: &str,
    expected: &str,
) -> Result<T, ConfigError> {
    value
        .trim()
        .parse::<T>()
        .map_err(|_| invalid_env(key, format!("expected {expected}")))
}

fn parse_categories(value: &str) -> Result<Vec<AnalysisCategory>, ConfigError> {
    let mut categories = Vec::new();
    for item in value.split(',') {
        let item = item.trim();
        let category = if item.eq_ignore_ascii_case("bug") {
            AnalysisCategory::Bug
        } else if item.eq_ignore_ascii_case("quality") {
            AnalysisCategory::Quality
        } else if item.eq_ignore_ascii_case("solid") {
            AnalysisCategory::Solid
        } else if item.eq_ignore_ascii_case("vulnerability") {
            AnalysisCategory::Vulnerability
        } else {
            return Err(invalid_env(
                "BUGHUNTER_CATEGORIES",
                "expected a comma-delimited list of bug, quality, solid, or vulnerability"
                    .to_string(),
            ));
        };
        if !categories.contains(&category) {
            categories.push(category);
        }
    }
    Ok(categories)
}

fn parse_log_level(value: &str) -> Result<LogLevel, ConfigError> {
    match value.to_lowercase().as_str() {
        "trace" => Ok(LogLevel::Trace),
        "debug" => Ok(LogLevel::Debug),
        "info" => Ok(LogLevel::Info),
        "warn" => Ok(LogLevel::Warn),
        "error" => Ok(LogLevel::Error),
        _ => Err(invalid_env(
            "BUGHUNTER_LOG_LEVEL",
            "expected trace, debug, info, warn, or error".to_string(),
        )),
    }
}

fn invalid_env(field: &str, reason: String) -> ConfigError {
    ConfigError::InvalidValue {
        field: field.to_string(),
        reason,
    }
}

#[cfg(feature = "fuzzing")]
pub fn config_from_toml_text(content: &str) -> Result<Config, ConfigError> {
    let toml = parse_toml_text(content, Path::new("fuzz.bughunter.toml"))?;
    let mut config = Config::default();
    let mut llm = LlmSettings::default();
    merge_toml(&mut config, &mut llm, &toml);
    llm.api_url = normalize_api_url(&llm.api_url);
    config.llm = llm.build();
    Ok(config)
}

#[cfg(test)]
#[path = "loader_tests.rs"]
mod tests;
