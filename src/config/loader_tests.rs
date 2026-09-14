use super::*;
#[cfg(feature = "fuzzing")]
use crate::config::ValidatedConfig;
#[cfg(feature = "fuzzing")]
use crate::config::schema::AnalysisMode;
use crate::config::schema::BackendConfig;
use std::fs;
use tempfile::TempDir;

fn load(project_root: &Path, config_override: Option<&Path>) -> Result<Config, ConfigError> {
    load_config(&TrustedConfigSource {
        project_root: project_root.to_path_buf(),
        explicit_file: config_override.map(Path::to_path_buf),
        user_file: None,
    })
}

#[test]
fn loads_default_config_when_no_files_exist() {
    let dir = TempDir::new().unwrap();
    let config = load(dir.path(), None).unwrap();

    assert_eq!(config.llm.max_tokens, 8192);
    assert!(matches!(
        config.llm.backend,
        BackendConfig::ClaudeCli { .. }
    ));
    assert_eq!(config.analysis.categories.len(), 4);
    assert_eq!(config.llm.max_shard_seconds, 900);
}

#[test]
fn automatically_discovered_project_config_ignores_llm_fields() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join(".bughunter.toml"),
        "[llm]\nmax_tokens = 4096\n",
    )
    .unwrap();

    let config = load(dir.path(), None).unwrap();

    assert_eq!(config.llm.max_tokens, 8192);
}

#[test]
fn merges_engine_config() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join(".bughunter.toml"),
        "[engine]\nmax_file_size_bytes = 500000\n",
    )
    .unwrap();

    let config = load(dir.path(), None).unwrap();

    assert_eq!(config.engine.max_file_size_bytes, 500_000);
}

#[test]
fn returns_error_for_invalid_toml() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join(".bughunter.toml"), "not valid toml {{{").unwrap();

    let result = load(dir.path(), None);
    assert!(matches!(result, Err(ConfigError::ParseError { .. })));
}

#[test]
fn rejects_configuration_files_beyond_the_size_limit() {
    let directory = TempDir::new().unwrap();
    fs::write(
        directory.path().join(".bughunter.toml"),
        vec![b' '; MAX_CONFIG_BYTES + 1],
    )
    .unwrap();

    let error = load(directory.path(), None).unwrap_err();

    assert!(matches!(
        error,
        ConfigError::Io { source, .. }
            if source.kind() == std::io::ErrorKind::InvalidData
    ));
}

#[test]
fn respects_config_override_path() {
    let dir = TempDir::new().unwrap();
    let custom = dir.path().join("custom.toml");
    fs::write(&custom, "[llm]\nmax_tokens = 2048\n").unwrap();

    let config = load(dir.path(), Some(&custom)).unwrap();

    assert_eq!(config.llm.max_tokens, 2048);
}

#[test]
fn missing_config_override_path_is_an_error() {
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("nope.toml");

    let result = load(dir.path(), Some(&missing));

    assert!(matches!(result, Err(ConfigError::FileNotFound { .. })));
}

#[cfg(unix)]
#[test]
fn unreadable_config_file_reports_io_error_not_file_not_found() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join(".bughunter.toml");
    fs::write(&config_path, "[llm]\n").unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o000)).unwrap();

    if fs::read_to_string(&config_path).is_ok() {
        return;
    }

    let result = load(dir.path(), None);

    assert!(matches!(result, Err(ConfigError::Io { .. })));
}

#[test]
fn merges_min_confidence() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join(".bughunter.toml"),
        "[general]\nmin_confidence = \"high\"\n",
    )
    .unwrap();

    let config = load(dir.path(), None).unwrap();

    assert_eq!(config.general.min_confidence, Confidence::High);
}

#[test]
fn merge_env_preserves_existing_values_when_env_not_set() {
    let mut config = Config::default();
    let mut llm = LlmSettings {
        backend: LlmBackendKind::OpenAiCompatible,
        api_token: Some("original".into()),
        api_url: "https://custom.example.com".into(),
        ..LlmSettings::default()
    };
    merge_env(&mut config, &mut llm).unwrap();
    assert_eq!(llm.api_url, "https://custom.example.com");
}

#[test]
fn merges_analysis_quality_thresholds() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join(".bughunter.toml"),
        "[analysis.quality]\nmax_function_lines = 30\n",
    )
    .unwrap();

    let config = load(dir.path(), None).unwrap();

    assert_eq!(config.analysis.quality.max_function_lines, 30);
}

#[test]
fn merges_solid_config() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join(".bughunter.toml"),
        "[analysis.solid]\ncheck_srp = false\n",
    )
    .unwrap();

    let config = load(dir.path(), None).unwrap();

    assert!(!config.analysis.solid.check_srp);
}

#[test]
fn default_backend_is_claude_cli() {
    let dir = TempDir::new().unwrap();
    let config = load(dir.path(), None).unwrap();
    assert!(
        matches!(&config.llm.backend, BackendConfig::ClaudeCli { binary } if binary == "claude")
    );
}

#[test]
fn merges_backend_selection_from_toml() {
    let dir = TempDir::new().unwrap();
    let explicit = dir.path().join("trusted.toml");
    fs::write(&explicit, "[llm]\nbackend = \"openai-compatible\"\n").unwrap();

    let config = load(dir.path(), Some(&explicit)).unwrap();

    assert!(matches!(
        config.llm.backend,
        BackendConfig::OpenAiCompatible { .. }
    ));
}

#[test]
fn merges_claude_cli_binary_from_toml() {
    let dir = TempDir::new().unwrap();
    let explicit = dir.path().join("trusted.toml");
    fs::write(
        &explicit,
        "[llm]\nclaude_cli_binary = \"/opt/bin/claude\"\n",
    )
    .unwrap();

    let config = load(dir.path(), Some(&explicit)).unwrap();

    assert!(
        matches!(&config.llm.backend, BackendConfig::ClaudeCli { binary } if binary == "/opt/bin/claude")
    );
}

#[test]
fn toml_exclude_dirs_extend_the_defaults() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join(".bughunter.toml"),
        "[engine]\nexclude_dirs = [\"fixtures\"]\n",
    )
    .unwrap();

    let config = load(dir.path(), None).unwrap();
    let excluded = config.engine.exclude_dirs;

    assert!(excluded.contains(&"fixtures".to_string()));
    assert!(excluded.contains(&"node_modules".to_string()));
    assert!(excluded.contains(&".git".to_string()));
    assert!(excluded.is_sorted());
}

#[test]
fn toml_exclude_extensions_extend_the_defaults() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join(".bughunter.toml"),
        "[engine]\nexclude_extensions = [\"snap\"]\n",
    )
    .unwrap();

    let config = load(dir.path(), None).unwrap();
    let excluded = config.engine.exclude_extensions;

    assert!(excluded.contains(&"snap".to_string()));
    assert!(excluded.contains(&"png".to_string()));
    assert!(excluded.is_sorted());
}

#[test]
fn repeated_exclusions_are_deduplicated() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join(".bughunter.toml"),
        "[engine]\nexclude_dirs = [\"target\", \"fixtures\", \"fixtures\"]\n",
    )
    .unwrap();

    let config = load(dir.path(), None).unwrap();
    let excluded = config.engine.exclude_dirs;
    let unique: std::collections::BTreeSet<&String> = excluded.iter().collect();

    assert_eq!(unique.len(), excluded.len());
    assert!(excluded.contains(&"fixtures".to_string()));
    assert!(excluded.contains(&"target".to_string()));
}

#[test]
fn credential_directories_stay_excluded_when_exclusions_are_overridden() {
    use crate::engine::exclusions::is_excluded;

    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join(".bughunter.toml"),
        "[engine]\nexclude_dirs = [\"fixtures\"]\n",
    )
    .unwrap();

    let config = load(dir.path(), None).unwrap();
    let engine = &config.engine;

    assert!(is_excluded(Path::new("/project/.aws/credentials"), engine));
    assert!(is_excluded(Path::new("/project/.ssh/id_rsa"), engine));
    assert!(is_excluded(Path::new("/project/node_modules/a.js"), engine));
    assert!(!is_excluded(Path::new("/project/src/main.rs"), engine));
}

#[test]
fn unknown_toml_key_is_rejected() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join(".bughunter.toml"),
        "[llm]\nmax_tokns = 4096\n",
    )
    .unwrap();

    let result = load(dir.path(), None);

    assert!(matches!(result, Err(ConfigError::ParseError { .. })));
}

#[test]
fn unknown_toml_section_is_rejected() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join(".bughunter.toml"),
        "[engnie]\nmax_file_size_bytes = 1024\n",
    )
    .unwrap();

    let result = load(dir.path(), None);

    assert!(matches!(result, Err(ConfigError::ParseError { .. })));
}

#[test]
fn trailing_slashes_are_trimmed_from_api_url() {
    let dir = TempDir::new().unwrap();
    let explicit = dir.path().join("trusted.toml");
    fs::write(
        &explicit,
        "[llm]\nbackend = \"openai-compatible\"\napi_url = \"https://api.example.com/v1//\"\n",
    )
    .unwrap();

    let config = load(dir.path(), Some(&explicit)).unwrap();
    let BackendConfig::OpenAiCompatible { api_url, .. } = &config.llm.backend else {
        panic!("expected the openai-compatible backend");
    };

    assert_eq!(api_url, "https://api.example.com/v1");
}

#[test]
fn merges_max_shard_seconds_from_toml() {
    let dir = TempDir::new().unwrap();
    let explicit = dir.path().join("trusted.toml");
    fs::write(&explicit, "[llm]\nmax_shard_seconds = 1200\n").unwrap();

    let config = load(dir.path(), Some(&explicit)).unwrap();

    assert_eq!(config.llm.max_shard_seconds, 1200);
}

#[test]
fn api_url_normalization_trims_whitespace_and_trailing_slashes() {
    assert_eq!(
        normalize_api_url("https://x.example/v1"),
        "https://x.example/v1"
    );
    assert_eq!(
        normalize_api_url("  https://x.example/v1/  "),
        "https://x.example/v1"
    );
    assert_eq!(
        normalize_api_url("https://x.example///"),
        "https://x.example"
    );
    assert_eq!(normalize_api_url(""), "");
}

#[test]
fn backend_env_values_require_documented_names() {
    assert!(matches!(
        parse_backend("OPENAI-COMPATIBLE"),
        Ok(LlmBackendKind::OpenAiCompatible)
    ));
    assert!(matches!(
        parse_backend("Claude-CLI"),
        Ok(LlmBackendKind::ClaudeCli)
    ));
    for alias in ["provider", "custom", "cli", "claude_cli"] {
        assert!(parse_backend(alias).is_err(), "{alias}");
    }
}

#[test]
fn category_env_values_accept_comma_delimited_lists() {
    assert_eq!(
        parse_categories(" BUG, quality,solid,vulnerability ").unwrap(),
        vec![
            AnalysisCategory::Bug,
            AnalysisCategory::Quality,
            AnalysisCategory::Solid,
            AnalysisCategory::Vulnerability,
        ]
    );
    assert!(parse_categories("").is_err());
    assert!(parse_categories("quality,unknown").is_err());
}

#[test]
fn log_level_env_values_parse_case_insensitively() {
    assert!(matches!(parse_log_level("TRACE"), Ok(LogLevel::Trace)));
    assert!(matches!(parse_log_level("debug"), Ok(LogLevel::Debug)));
    assert!(matches!(parse_log_level("info"), Ok(LogLevel::Info)));
    assert!(matches!(parse_log_level("Warn"), Ok(LogLevel::Warn)));
    assert!(matches!(parse_log_level("error"), Ok(LogLevel::Error)));
    assert!(parse_log_level("verbose").is_err());
}

#[test]
fn numeric_env_values_accept_padding_and_reject_garbage() {
    assert_eq!(
        parse_env_number::<u64>(
            "BUGHUNTER_MAX_SHARD_SECONDS",
            " 1200 ",
            "a positive integer"
        )
        .unwrap(),
        1200
    );
    assert!(matches!(
        parse_env_number::<u64>(
            "BUGHUNTER_MAX_SHARD_SECONDS",
            "ninety",
            "a positive integer"
        ),
        Err(ConfigError::InvalidValue { .. })
    ));
    assert!(matches!(
        parse_env_number::<u32>(
            "BUGHUNTER_MAX_CONTEXT_TOKENS",
            "-5",
            "a non-negative integer"
        ),
        Err(ConfigError::InvalidValue { .. })
    ));
}

#[test]
fn rejects_api_tokens_in_configuration_files() {
    let secret = "must-stay-in-the-environment";

    for contents in [
        format!("[llm]\napi_token = \"{secret}\"\n"),
        format!("llm.api_token = \"{secret}\"\n"),
        format!("llm = {{ api_token = \"{secret}\" }}\n"),
        format!("api_token = \"{secret}\"\n"),
        format!("[llm]\nmodel = \"m\"\napi_token = \"{secret}\"\n"),
    ] {
        let directory = TempDir::new().unwrap();
        fs::write(directory.path().join(".bughunter.toml"), &contents).unwrap();

        let error = load(directory.path(), None).unwrap_err();

        assert!(
            matches!(&error, ConfigError::InvalidValue { field, .. } if field == "llm.api_token"),
            "unexpected error for {contents:?}: {error}"
        );
        assert!(
            !error.to_string().contains(secret),
            "the token must never reach the error message for {contents:?}"
        );
    }
}

#[test]
fn trusted_source_resolves_the_local_checkout_config_file() {
    let local_checkout = TempDir::new().unwrap();
    let explicit = local_checkout.path().join("explicit.toml");

    let inferred = TrustedConfigSource::for_local_checkout(local_checkout.path(), None);
    let overridden =
        TrustedConfigSource::for_local_checkout(local_checkout.path(), Some(&explicit));

    assert_eq!(
        inferred.project_file(),
        local_checkout.path().join(".bughunter.toml")
    );
    assert_eq!(overridden.project_file(), explicit);
}

#[test]
fn automatically_discovered_project_configuration_cannot_override_user_llm_configuration() {
    let home = TempDir::new().unwrap();
    let project = TempDir::new().unwrap();
    let user_file = home.path().join("config.toml");
    fs::write(
        &user_file,
        "[llm]\nmax_tokens = 1024\nmax_agent_iterations = 3\n",
    )
    .unwrap();
    fs::write(
        project.path().join(".bughunter.toml"),
        "[llm]\nmax_tokens = 4096\n",
    )
    .unwrap();

    let config = load_config(&TrustedConfigSource {
        project_root: project.path().to_path_buf(),
        explicit_file: None,
        user_file: Some(user_file),
    })
    .unwrap();

    assert_eq!(config.llm.max_tokens, 1024);
    assert_eq!(config.llm.max_agent_iterations, 3);
}

#[test]
fn automatically_discovered_project_configuration_cannot_override_trusted_fields() {
    let home = TempDir::new().unwrap();
    let project = TempDir::new().unwrap();
    let user_file = home.path().join("config.toml");
    fs::write(
        &user_file,
        "[general]\noutput_path = \"trusted.json\"\n\
         [llm]\nbackend = \"openai-compatible\"\n\
         api_url = \"https://trusted.example/v1\"\n\
         model = \"trusted-model\"\n\
         max_tokens = 2048\n",
    )
    .unwrap();
    fs::write(
        project.path().join(".bughunter.toml"),
        "[general]\noutput_path = \"project.json\"\n\
         [llm]\nbackend = \"claude-cli\"\n\
         claude_cli_binary = \"/tmp/project-claude\"\n\
         model = \"project-model\"\n\
         max_tokens = 4096\n",
    )
    .unwrap();

    let config = load_config(&TrustedConfigSource {
        project_root: project.path().to_path_buf(),
        explicit_file: None,
        user_file: Some(user_file),
    })
    .unwrap();

    assert_eq!(config.general.output_path, Some("trusted.json".into()));
    assert_eq!(config.llm.model, "trusted-model");
    assert_eq!(config.llm.max_tokens, 2048);
    assert!(matches!(
        config.llm.backend,
        BackendConfig::OpenAiCompatible {
            ref api_url,
            api_token: None
        } if api_url == "https://trusted.example/v1"
    ));
}

#[test]
fn configuration_files_cannot_choose_the_discovery_source() {
    let directory = TempDir::new().unwrap();
    fs::write(
        directory.path().join(".bughunter.toml"),
        "[engine]\ndiscovery_source = \"local-checkout\"\n",
    )
    .unwrap();

    let error = load(directory.path(), None).unwrap_err();

    assert!(
        matches!(error, ConfigError::ParseError { .. }),
        "discovery source must never be configurable: {error}"
    );
}

#[test]
fn missing_config_file_is_reported_by_path() {
    let directory = TempDir::new().unwrap();
    let missing = directory.path().join("missing.toml");

    let error = parse_toml_file(&missing).unwrap_err();

    assert!(matches!(error, ConfigError::FileNotFound { path } if path == missing));
}

#[test]
fn every_persistable_configuration_field_overrides_its_default() {
    let directory = TempDir::new().unwrap();
    let explicit = directory.path().join("trusted.toml");
    fs::write(
        &explicit,
        r#"
[general]
log_level = "trace"
fail_severity = "low"
min_confidence = "medium"
output_format = "md"
output_path = "report.md"

[engine]
max_file_size_bytes = 4096
exclude_dirs = ["private-cache"]
exclude_extensions = ["secret"]
max_depth = 3

[llm]
backend = "openai-compatible"
api_url = "https://api.example.com/v1/"
model = "test-model"
max_tokens = 512
temperature = 0.7
reasoning_effort = "high"
timeout_seconds = 90
max_retries = 1
max_agent_iterations = 7
max_context_tokens = 4321
max_shard_seconds = 120
claude_cli_binary = "/opt/claude"

[analysis]
categories = ["bug"]

[analysis.quality]
max_function_lines = 11
max_file_lines = 22

[analysis.solid]
check_srp = false
check_ocp = false
check_lsp = false
check_isp = false
check_dip = false
"#,
    )
    .unwrap();

    let config = load(directory.path(), Some(&explicit)).unwrap();

    assert_eq!(config.general.log_level, LogLevel::Trace);
    assert_eq!(config.general.fail_severity, Severity::Low);
    assert_eq!(config.general.min_confidence, Confidence::Medium);
    assert_eq!(config.general.output_format, OutputFormat::Md);
    assert_eq!(config.general.output_path, Some("report.md".into()));
    assert_eq!(config.engine.max_file_size_bytes, 4096);
    assert!(config.engine.exclude_dirs.contains(&"private-cache".into()));
    assert!(config.engine.exclude_extensions.contains(&"secret".into()));
    assert_eq!(config.engine.max_depth, Some(3));
    assert_eq!(config.llm.model, "test-model");
    assert_eq!(config.llm.max_tokens, 512);
    assert_eq!(config.llm.temperature, 0.7);
    assert_eq!(config.llm.reasoning_effort.as_deref(), Some("high"));
    assert_eq!(config.llm.timeout_seconds, 90);
    assert_eq!(config.llm.max_retries, 1);
    assert_eq!(config.llm.max_agent_iterations, 7);
    assert_eq!(config.llm.max_context_tokens, 4321);
    assert_eq!(config.llm.max_shard_seconds, 120);
    assert_eq!(config.analysis.categories, vec![AnalysisCategory::Bug]);
    assert_eq!(config.analysis.quality.max_function_lines, 11);
    assert_eq!(config.analysis.quality.max_file_lines, 22);
    assert!(!config.analysis.solid.check_srp);
    assert!(!config.analysis.solid.check_ocp);
    assert!(!config.analysis.solid.check_lsp);
    assert!(!config.analysis.solid.check_isp);
    assert!(!config.analysis.solid.check_dip);
    let BackendConfig::OpenAiCompatible { api_url, api_token } = config.llm.backend else {
        panic!("expected openai-compatible backend");
    };
    assert_eq!(api_url, "https://api.example.com/v1");
    assert_eq!(api_token, None);
}

#[test]
fn parse_errors_never_echo_the_offending_source_line() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join(".bughunter.toml"),
        "[llm]\napi_token = \"sk-super-secret-value\n",
    )
    .unwrap();

    let error = load(dir.path(), None).unwrap_err();
    let rendered = format!("{error}");

    assert!(matches!(error, ConfigError::ParseError { .. }));
    assert!(
        !rendered.contains("sk-super-secret-value"),
        "parse error leaked the secret: {rendered}"
    );
    assert!(
        !rendered.contains("api_token"),
        "parse error leaked the offending source line: {rendered}"
    );
}

#[cfg(feature = "fuzzing")]
#[test]
fn fuzz_configuration_entrypoint_builds_the_same_typed_config() {
    let config = config_from_toml_text(
        "[llm]\nmodel = \"fuzz-model\"\nmax_tokens = 512\n[analysis]\ncategories = [\"bug\"]\n",
    )
    .unwrap();

    assert_eq!(config.llm.model, "fuzz-model");
    assert_eq!(config.llm.max_tokens, 512);
    assert_eq!(config.analysis.categories, vec![AnalysisCategory::Bug]);
}

#[cfg(feature = "fuzzing")]
#[test]
fn fuzz_configuration_entrypoint_rejects_persisted_tokens_and_unknown_keys() {
    let persisted = config_from_toml_text("api_token = \"leaked\"\n").unwrap_err();
    assert!(matches!(
        persisted,
        ConfigError::InvalidValue { ref field, .. } if field == "llm.api_token"
    ));

    let nested = config_from_toml_text("[llm]\napi_token = \"leaked\"\n").unwrap_err();
    assert!(matches!(
        nested,
        ConfigError::InvalidValue { ref field, .. } if field == "llm.api_token"
    ));

    let unknown = config_from_toml_text("[llm]\nmax_tokens = 512\nzz_unknown = 1\n").unwrap_err();
    assert!(matches!(unknown, ConfigError::ParseError { .. }));
}

#[cfg(feature = "fuzzing")]
#[test]
fn fuzz_configuration_entrypoint_normalises_urls_and_preserves_default_exclusions() {
    let defaults = Config::default();
    let config = config_from_toml_text(
        "[llm]\nbackend = \"openai-compatible\"\napi_url = \"https://api.example.com/v1///\"\n",
    )
    .unwrap();

    let BackendConfig::OpenAiCompatible { api_url, api_token } = &config.llm.backend else {
        panic!("expected openai-compatible backend");
    };
    assert_eq!(api_url, "https://api.example.com/v1");
    assert_eq!(api_token.as_deref(), None);
    assert_eq!(config.engine.exclude_dirs, defaults.engine.exclude_dirs);
    assert_eq!(
        config.engine.exclude_extensions,
        defaults.engine.exclude_extensions
    );
}

#[cfg(feature = "fuzzing")]
#[test]
fn fuzz_configuration_entrypoint_sorts_and_deduplicates_merged_exclusions() {
    let config = config_from_toml_text(
        "[engine]\nexclude_dirs = [\"zzz\", \"aaa\", \"aaa\"]\nexclude_extensions = [\"zz\", \"zz\"]\n",
    )
    .unwrap();

    for list in [
        &config.engine.exclude_dirs,
        &config.engine.exclude_extensions,
    ] {
        assert!(
            list.windows(2).all(|pair| pair[0] < pair[1]),
            "merged exclusions are not sorted and deduplicated: {list:?}"
        );
    }
    assert!(config.engine.exclude_dirs.contains(&"aaa".to_string()));
    assert!(config.engine.exclude_dirs.contains(&"zzz".to_string()));
}

#[cfg(feature = "fuzzing")]
#[test]
fn fuzz_configuration_entrypoint_rejects_a_not_a_number_temperature() {
    let config = config_from_toml_text("[llm]\ntemperature = nan\n").unwrap();

    assert!(config.llm.temperature.is_nan());
    assert!(matches!(
        ValidatedConfig::new(config, AnalysisMode::Static),
        Err(ConfigError::InvalidValue { ref field, .. }) if field == "llm.temperature"
    ));
}
