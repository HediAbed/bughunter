use std::net::IpAddr;

use reqwest::Url;

use crate::errors::ConfigError;

use super::schema::{
    AnalysisCategory, AnalysisMode, BackendConfig, Config, MAX_CONTEXT_TOKENS, MIN_CONTEXT_TOKENS,
};
const MAX_API_URL_BYTES: usize = 2048;
const MAX_API_TOKEN_BYTES: usize = 16 * 1024;
const MAX_MODEL_BYTES: usize = 256;
const MAX_REASONING_EFFORT_BYTES: usize = 64;
const MAX_CLAUDE_BINARY_BYTES: usize = 4096;
const MAX_FILE_SIZE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ENGINE_DEPTH: usize = 1024;
const MAX_EXCLUSIONS: usize = 4096;
const MAX_EXCLUSION_BYTES: usize = 256;
const MAX_QUALITY_LINES: usize = 1_000_000;

#[derive(Debug, Clone)]
pub struct ValidatedConfig {
    config: Config,
    mode: AnalysisMode,
}

impl ValidatedConfig {
    pub fn new(config: Config, mode: AnalysisMode) -> Result<Self, ConfigError> {
        validate(&config, mode)?;
        Ok(Self { config, mode })
    }

    pub fn mode(&self) -> AnalysisMode {
        self.mode
    }

    pub fn into_inner(self) -> Config {
        self.config
    }
}

impl std::ops::Deref for ValidatedConfig {
    type Target = Config;

    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

fn validate(config: &Config, mode: AnalysisMode) -> Result<(), ConfigError> {
    if mode.requires_ai() {
        match &config.llm.backend {
            BackendConfig::OpenAiCompatible { api_url, api_token } => {
                validate_openai_backend(api_url, api_token.as_deref(), &config.llm.model)?;
                validate_agent_iterations(config)?;
            }
            BackendConfig::ClaudeCli { binary } => validate_claude_cli_backend(binary)?,
        }
    }

    if config.analysis.categories.is_empty() {
        return Err(ConfigError::InvalidValue {
            field: "analysis.categories".into(),
            reason: "at least one analysis category must be enabled".into(),
        });
    }

    if matches!(mode, AnalysisMode::Static)
        && config.analysis.categories.iter().all(|category| {
            !matches!(
                category,
                AnalysisCategory::Quality | AnalysisCategory::Vulnerability
            )
        })
    {
        return Err(ConfigError::InvalidValue {
            field: "analysis.categories".into(),
            reason: "static mode requires quality or vulnerability".into(),
        });
    }

    if !(0.0..=1.0).contains(&config.llm.temperature) {
        return Err(ConfigError::InvalidValue {
            field: "llm.temperature".into(),
            reason: format!(
                "must be between 0.0 and 1.0, got {}",
                config.llm.temperature
            ),
        });
    }

    validate_engine_config(config)?;
    validate_llm_limits(config)?;
    validate_analysis_config(config)?;

    Ok(())
}

fn validate_engine_config(config: &Config) -> Result<(), ConfigError> {
    validate_range(
        "engine.max_file_size_bytes",
        config.engine.max_file_size_bytes,
        1..=MAX_FILE_SIZE_BYTES,
    )?;
    if let Some(max_depth) = config.engine.max_depth {
        validate_range("engine.max_depth", max_depth, 1..=MAX_ENGINE_DEPTH)?;
    }
    validate_string_list("engine.exclude_dirs", &config.engine.exclude_dirs)?;
    validate_string_list(
        "engine.exclude_extensions",
        &config.engine.exclude_extensions,
    )
}

fn validate_string_list(field: &str, values: &[String]) -> Result<(), ConfigError> {
    if values.len() > MAX_EXCLUSIONS {
        return invalid_value(field, format!("accepts at most {MAX_EXCLUSIONS} values"));
    }
    if let Some(value) = values
        .iter()
        .find(|value| value.trim().is_empty() || value.len() > MAX_EXCLUSION_BYTES)
    {
        return invalid_value(
            field,
            format!(
                "values must contain 1 to {MAX_EXCLUSION_BYTES} bytes, got {}",
                value.len()
            ),
        );
    }
    Ok(())
}

fn validate_analysis_config(config: &Config) -> Result<(), ConfigError> {
    validate_range(
        "analysis.quality.max_function_lines",
        config.analysis.quality.max_function_lines,
        1..=MAX_QUALITY_LINES,
    )?;
    validate_range(
        "analysis.quality.max_file_lines",
        config.analysis.quality.max_file_lines,
        1..=MAX_QUALITY_LINES,
    )
}

fn validate_agent_iterations(config: &Config) -> Result<(), ConfigError> {
    let iterations = config.llm.max_agent_iterations;
    if iterations < 2 {
        return Err(ConfigError::InvalidValue {
            field: "llm.max_agent_iterations".into(),
            reason: "must be at least 2 to allow exploration and final submission".into(),
        });
    }
    validate_range("llm.max_agent_iterations", iterations, 2..=500)
}

fn validate_llm_limits(config: &Config) -> Result<(), ConfigError> {
    validate_range("llm.max_tokens", config.llm.max_tokens, 256..=1_000_000)?;
    validate_range("llm.timeout_seconds", config.llm.timeout_seconds, 1..=3600)?;
    validate_range("llm.max_retries", config.llm.max_retries, 0..=10)?;
    validate_range(
        "llm.max_shard_seconds",
        config.llm.max_shard_seconds,
        60..=7200,
    )?;
    if config.llm.max_context_tokens != 0 {
        validate_range(
            "llm.max_context_tokens",
            config.llm.max_context_tokens,
            MIN_CONTEXT_TOKENS..=MAX_CONTEXT_TOKENS,
        )?;
    }
    if let Some(reasoning_effort) = &config.llm.reasoning_effort {
        validate_nonempty_string(
            "llm.reasoning_effort",
            reasoning_effort,
            MAX_REASONING_EFFORT_BYTES,
        )?;
    }
    Ok(())
}

fn validate_nonempty_string(field: &str, value: &str, max_bytes: usize) -> Result<(), ConfigError> {
    if value.trim().is_empty() || value.len() > max_bytes {
        return invalid_value(
            field,
            format!("must contain 1 to {max_bytes} bytes, got {}", value.len()),
        );
    }
    Ok(())
}

fn invalid_value<T>(field: &str, reason: String) -> Result<T, ConfigError> {
    Err(ConfigError::InvalidValue {
        field: field.into(),
        reason,
    })
}

fn validate_range<T>(
    field: &str,
    value: T,
    allowed: std::ops::RangeInclusive<T>,
) -> Result<(), ConfigError>
where
    T: PartialOrd + std::fmt::Display,
{
    if allowed.contains(&value) {
        return Ok(());
    }

    Err(ConfigError::InvalidValue {
        field: field.into(),
        reason: format!(
            "must be between {} and {}, got {value}",
            allowed.start(),
            allowed.end()
        ),
    })
}

fn validate_openai_backend(
    api_url: &str,
    api_token: Option<&str>,
    model: &str,
) -> Result<(), ConfigError> {
    let Some(api_token) = api_token else {
        return Err(ConfigError::MissingRequired {
            field: "BUGHUNTER_API_TOKEN".into(),
            hint: "set BUGHUNTER_API_TOKEN in the process environment".into(),
        });
    };
    validate_nonempty_string("BUGHUNTER_API_TOKEN", api_token, MAX_API_TOKEN_BYTES)?;
    validate_api_url(api_url)?;
    validate_nonempty_string("llm.model", model, MAX_MODEL_BYTES)
}

fn validate_api_url(api_url: &str) -> Result<(), ConfigError> {
    if api_url.len() > MAX_API_URL_BYTES {
        return invalid_value(
            "llm.api_url",
            format!("must not exceed {MAX_API_URL_BYTES} bytes"),
        );
    }
    let parsed = Url::parse(api_url).map_err(|error| ConfigError::InvalidValue {
        field: "llm.api_url".into(),
        reason: format!("must be a valid URL: {error}"),
    })?;
    let host = parsed.host_str();
    let loopback_http = parsed.scheme() == "http"
        && host.is_some_and(|host| {
            host == "localhost"
                || host
                    .trim_matches(['[', ']'])
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
    if host.is_none()
        || (parsed.scheme() != "https" && !loopback_http)
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return invalid_value(
            "llm.api_url",
            "must use HTTPS, except for loopback HTTP, without credentials, query, or fragment"
                .into(),
        );
    }
    Ok(())
}

fn validate_claude_cli_backend(binary: &str) -> Result<(), ConfigError> {
    validate_nonempty_string("llm.claude_cli_binary", binary, MAX_CLAUDE_BINARY_BYTES)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn valid_config() -> Config {
        let mut config = Config::default();
        config.llm.backend = BackendConfig::OpenAiCompatible {
            api_url: "https://example.com".into(),
            api_token: Some("test-token".into()),
        };
        config.llm.model = "test-model".into();
        config
    }

    fn valid_claude_cli_config() -> Config {
        let mut config = Config::default();
        config.llm.backend = BackendConfig::ClaudeCli {
            binary: "claude".into(),
        };
        config
    }

    #[test]
    fn accepts_valid_config_in_full_mode() {
        assert!(validate(&valid_config(), AnalysisMode::Full).is_ok());
    }

    #[test]
    fn accepts_valid_config_in_ai_only_mode() {
        assert!(validate(&valid_config(), AnalysisMode::AiOnly).is_ok());
    }

    #[test]
    fn accepts_missing_token_in_static_mode() {
        let config = Config::default();
        assert!(validate(&config, AnalysisMode::Static).is_ok());
    }

    #[test]
    fn rejects_missing_token_in_full_mode() {
        let mut config = Config::default();
        config.llm.backend = BackendConfig::OpenAiCompatible {
            api_url: String::new(),
            api_token: None,
        };
        let result = validate(&config, AnalysisMode::Full);
        assert!(matches!(result, Err(ConfigError::MissingRequired { .. })));
    }

    #[test]
    fn rejects_missing_token_in_ai_only_mode() {
        let mut config = Config::default();
        config.llm.backend = BackendConfig::OpenAiCompatible {
            api_url: String::new(),
            api_token: None,
        };
        let result = validate(&config, AnalysisMode::AiOnly);
        assert!(matches!(result, Err(ConfigError::MissingRequired { .. })));
    }

    #[test]
    fn rejects_empty_categories() {
        let mut config = valid_config();
        config.analysis.categories = vec![];
        let result = validate(&config, AnalysisMode::Full);
        assert!(matches!(result, Err(ConfigError::InvalidValue { .. })));
    }

    #[test]
    fn rejects_temperature_out_of_range() {
        let mut config = valid_config();
        config.llm.temperature = 1.5;
        let result = validate(&config, AnalysisMode::Full);
        assert!(matches!(result, Err(ConfigError::InvalidValue { .. })));
    }

    #[test]
    fn rejects_negative_temperature() {
        let mut config = valid_config();
        config.llm.temperature = -0.1;
        let result = validate(&config, AnalysisMode::Full);
        assert!(matches!(result, Err(ConfigError::InvalidValue { .. })));
    }

    #[test]
    fn rejects_not_a_number_temperature() {
        let mut config = valid_config();
        config.llm.temperature = f32::NAN;
        let result = validate(&config, AnalysisMode::Full);
        assert!(matches!(result, Err(ConfigError::InvalidValue { .. })));
    }

    #[test]
    fn rejects_agent_limit_without_exploration_and_submission_turns() {
        let mut config = valid_config();
        config.llm.max_agent_iterations = 1;
        let result = validate(&config, AnalysisMode::AiOnly);
        assert!(matches!(
            result,
            Err(ConfigError::InvalidValue { field, .. })
                if field == "llm.max_agent_iterations"
        ));
    }

    #[test]
    fn static_mode_ignores_agent_iteration_limit() {
        let mut config = Config::default();
        config.llm.max_agent_iterations = 0;
        assert!(validate(&config, AnalysisMode::Static).is_ok());
    }

    #[test]
    fn static_mode_rejects_categories_without_static_implementations() {
        for category in [AnalysisCategory::Bug, AnalysisCategory::Solid] {
            let mut config = Config::default();
            config.analysis.categories = vec![category];

            let result = validate(&config, AnalysisMode::Static);

            assert!(matches!(
                result,
                Err(ConfigError::InvalidValue { field, .. })
                    if field == "analysis.categories"
            ));
        }
    }

    #[test]
    fn static_mode_accepts_every_implemented_category() {
        let mut config = Config::default();
        config.analysis.categories =
            vec![AnalysisCategory::Quality, AnalysisCategory::Vulnerability];

        assert!(validate(&config, AnalysisMode::Static).is_ok());
    }

    #[test]
    fn ai_modes_accept_categories_without_static_implementations() {
        for mode in [AnalysisMode::AiOnly, AnalysisMode::Full] {
            let mut config = valid_config();
            config.analysis.categories = vec![AnalysisCategory::Bug, AnalysisCategory::Solid];

            assert!(validate(&config, mode).is_ok());
        }
    }

    #[test]
    fn rejects_zero_max_depth() {
        let mut config = valid_config();
        config.engine.max_depth = Some(0);
        let result = validate(&config, AnalysisMode::Full);

        assert!(matches!(
            result,
            Err(ConfigError::InvalidValue { field, .. }) if field == "engine.max_depth"
        ));
    }

    #[test]
    fn rejects_zero_max_file_size() {
        let mut config = valid_config();
        config.engine.max_file_size_bytes = 0;
        let result = validate(&config, AnalysisMode::Full);
        assert!(matches!(result, Err(ConfigError::InvalidValue { .. })));
    }

    #[test]
    fn claude_cli_backend_accepts_missing_api_token() {
        let config = valid_claude_cli_config();
        assert!(validate(&config, AnalysisMode::AiOnly).is_ok());
        assert!(validate(&config, AnalysisMode::Full).is_ok());
    }

    #[test]
    fn rejects_engine_resource_limits() {
        let mut config = valid_config();
        config.engine.max_file_size_bytes = MAX_FILE_SIZE_BYTES + 1;
        assert_eq!(rejected_field(&config), "engine.max_file_size_bytes");

        config.engine.max_file_size_bytes = 1;
        config.engine.max_depth = Some(MAX_ENGINE_DEPTH + 1);
        assert_eq!(rejected_field(&config), "engine.max_depth");

        config.engine.max_depth = None;
        config.engine.exclude_dirs = vec!["x".into(); MAX_EXCLUSIONS + 1];
        assert_eq!(rejected_field(&config), "engine.exclude_dirs");

        config.engine.exclude_dirs = vec!["x".repeat(MAX_EXCLUSION_BYTES + 1)];
        assert_eq!(rejected_field(&config), "engine.exclude_dirs");

        config.engine.exclude_dirs = vec![" ".into()];
        assert_eq!(rejected_field(&config), "engine.exclude_dirs");
    }

    #[test]
    fn rejects_context_and_analysis_limits() {
        let mut config = valid_config();
        config.llm.max_context_tokens = MIN_CONTEXT_TOKENS - 1;
        assert_eq!(rejected_field(&config), "llm.max_context_tokens");

        config.llm.max_context_tokens = MAX_CONTEXT_TOKENS + 1;
        assert_eq!(rejected_field(&config), "llm.max_context_tokens");

        config.llm.max_context_tokens = 0;
        config.analysis.quality.max_function_lines = 0;
        assert_eq!(
            rejected_field(&config),
            "analysis.quality.max_function_lines"
        );

        config.analysis.quality.max_function_lines = 1;
        config.analysis.quality.max_file_lines = MAX_QUALITY_LINES + 1;
        assert_eq!(rejected_field(&config), "analysis.quality.max_file_lines");
    }

    #[test]
    fn accepts_auto_and_bounded_context_limits() {
        let mut config = valid_config();
        for max_context_tokens in [0, MIN_CONTEXT_TOKENS, MAX_CONTEXT_TOKENS] {
            config.llm.max_context_tokens = max_context_tokens;
            assert!(validate(&config, AnalysisMode::Full).is_ok());
        }
    }

    #[test]
    fn rejects_unsafe_api_urls() {
        for api_url in [
            "http://example.com/v1",
            "https://user:password@example.com/v1",
            "https://example.com/v1?token=secret",
            "https://example.com/v1#fragment",
            "not-a-url",
        ] {
            let mut config = valid_config();
            config.llm.backend = BackendConfig::OpenAiCompatible {
                api_url: api_url.into(),
                api_token: Some("test-token".into()),
            };
            assert_eq!(rejected_field(&config), "llm.api_url");
        }
    }

    #[test]
    fn accepts_https_and_loopback_http_api_urls() {
        for api_url in [
            "https://example.com/v1",
            "http://localhost:8080/v1",
            "http://127.0.0.1:8080/v1",
            "http://[::1]:8080/v1",
        ] {
            let mut config = valid_config();
            config.llm.backend = BackendConfig::OpenAiCompatible {
                api_url: api_url.into(),
                api_token: Some("test-token".into()),
            };
            assert!(validate(&config, AnalysisMode::Full).is_ok(), "{api_url}");
        }
    }

    #[test]
    fn rejects_oversized_backend_strings() {
        let mut config = valid_config();
        config.llm.backend = BackendConfig::OpenAiCompatible {
            api_url: format!("https://example.com/{}", "x".repeat(MAX_API_URL_BYTES)),
            api_token: Some("test-token".into()),
        };
        assert_eq!(rejected_field(&config), "llm.api_url");

        config = valid_config();
        config.llm.backend = BackendConfig::OpenAiCompatible {
            api_url: "https://example.com/v1".into(),
            api_token: Some("x".repeat(MAX_API_TOKEN_BYTES + 1)),
        };
        assert_eq!(rejected_field(&config), "BUGHUNTER_API_TOKEN");

        config = valid_config();
        config.llm.model = "x".repeat(MAX_MODEL_BYTES + 1);
        assert_eq!(rejected_field(&config), "llm.model");

        config = valid_config();
        config.llm.reasoning_effort = Some("x".repeat(MAX_REASONING_EFFORT_BYTES + 1));
        assert_eq!(rejected_field(&config), "llm.reasoning_effort");

        config = valid_claude_cli_config();
        config.llm.backend = BackendConfig::ClaudeCli {
            binary: "x".repeat(MAX_CLAUDE_BINARY_BYTES + 1),
        };
        assert_eq!(rejected_field(&config), "llm.claude_cli_binary");
    }
    #[test]
    fn claude_cli_ignores_openai_agent_iteration_limit() {
        let mut config = valid_claude_cli_config();
        config.llm.max_agent_iterations = 0;
        assert!(validate(&config, AnalysisMode::AiOnly).is_ok());
    }

    #[test]
    fn claude_cli_backend_rejects_empty_binary() {
        let mut config = valid_claude_cli_config();
        config.llm.backend = BackendConfig::ClaudeCli {
            binary: "   ".into(),
        };
        let result = validate(&config, AnalysisMode::Full);
        assert!(matches!(result, Err(ConfigError::InvalidValue { .. })));
    }

    fn rejected_field(config: &Config) -> String {
        match validate(config, AnalysisMode::Full) {
            Err(ConfigError::InvalidValue { field, .. }) => field,
            other => panic!("expected an invalid value error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_agent_iterations_above_maximum() {
        let mut config = valid_config();
        config.llm.max_agent_iterations = 501;

        assert_eq!(rejected_field(&config), "llm.max_agent_iterations");
    }

    #[test]
    fn accepts_agent_iterations_at_maximum() {
        let mut config = valid_config();
        config.llm.max_agent_iterations = 500;

        assert!(validate(&config, AnalysisMode::Full).is_ok());
    }

    #[test]
    fn rejects_max_tokens_outside_bounds() {
        let mut config = valid_config();
        config.llm.max_tokens = 255;
        assert_eq!(rejected_field(&config), "llm.max_tokens");

        config.llm.max_tokens = 1_000_001;
        assert_eq!(rejected_field(&config), "llm.max_tokens");
    }

    #[test]
    fn rejects_timeout_outside_bounds() {
        let mut config = valid_config();
        config.llm.timeout_seconds = 0;
        assert_eq!(rejected_field(&config), "llm.timeout_seconds");

        config.llm.timeout_seconds = 3601;
        assert_eq!(rejected_field(&config), "llm.timeout_seconds");
    }

    #[test]
    fn rejects_excessive_max_retries() {
        let mut config = valid_config();
        config.llm.max_retries = 11;

        assert_eq!(rejected_field(&config), "llm.max_retries");
    }

    #[test]
    fn rejects_max_shard_seconds_outside_bounds() {
        let mut config = valid_config();
        config.llm.max_shard_seconds = 59;
        assert_eq!(rejected_field(&config), "llm.max_shard_seconds");

        config.llm.max_shard_seconds = 7201;
        assert_eq!(rejected_field(&config), "llm.max_shard_seconds");
    }

    #[test]
    fn accepts_max_shard_seconds_at_bounds() {
        let mut config = valid_config();

        config.llm.max_shard_seconds = 60;
        assert!(validate(&config, AnalysisMode::Full).is_ok());

        config.llm.max_shard_seconds = 7200;
        assert!(validate(&config, AnalysisMode::Full).is_ok());
    }

    #[test]
    fn llm_limits_apply_to_the_claude_cli_backend() {
        let mut config = valid_claude_cli_config();
        config.llm.max_shard_seconds = 10;

        assert_eq!(rejected_field(&config), "llm.max_shard_seconds");
    }

    #[test]
    fn validated_config_can_return_its_owned_configuration() {
        let config = valid_config();
        let expected_model = config.llm.model.clone();

        let restored = ValidatedConfig::new(config, AnalysisMode::Full)
            .unwrap()
            .into_inner();

        assert_eq!(restored.llm.model, expected_model);
    }
}
