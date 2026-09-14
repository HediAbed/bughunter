#![no_main]

use bughunter::fuzzing::config_from_toml_text;
use bughunter::{
    AnalysisCategory, AnalysisMode, BackendConfig, Config, ConfigError, ValidatedConfig,
};
use libfuzzer_sys::fuzz_target;

const MAX_TOML_BYTES: usize = 64 * 1024;
const BYTE_ORDER_MARK: char = '\u{feff}';
const UNKNOWN_KEY_SUFFIX: &str = "\nzz_unknown_fuzz_key = 1\n";
const API_TOKEN_PREFIX: &str = "api_token = \"leaked\"\n";
const API_TOKEN_FIELD: &str = "llm.api_token";
const VALIDATED_MAX_FILE_SIZE_BYTES: u64 = 64 * 1024 * 1024;
const VALIDATED_MAX_ENGINE_DEPTH: usize = 1024;
const VALIDATED_MAX_EXCLUSIONS: usize = 4096;
const VALIDATED_MAX_EXCLUSION_BYTES: usize = 256;
const VALIDATED_MAX_QUALITY_LINES: usize = 1_000_000;
const ALL_MODES: [AnalysisMode; 4] = [
    AnalysisMode::Static,
    AnalysisMode::AiOnly,
    AnalysisMode::Full,
    AnalysisMode::Review,
];

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_TOML_BYTES {
        return;
    }
    let text = String::from_utf8_lossy(data);

    let config = match config_from_toml_text(&text) {
        Ok(config) => config,
        Err(error) => {
            assert_text_only_error(&error, &text);
            return;
        }
    };

    assert_eq!(
        format!("{config:?}"),
        format!(
            "{:?}",
            config_from_toml_text(&text).expect("second load of an accepted document")
        ),
        "loading {text:?} twice produced different configurations"
    );
    assert_exclusions_stay_unique(&config);
    assert_no_credential_survives_text_loading(&config, &text);

    let mutable = text.strip_prefix(BYTE_ORDER_MARK).unwrap_or(&text);
    assert_unknown_keys_are_rejected(mutable);
    assert_persisted_api_tokens_are_rejected(mutable);

    for mode in ALL_MODES {
        assert_validation_agrees_with_its_limits(&config, mode);
    }
});

fn assert_text_only_error(error: &ConfigError, text: &str) {
    match error {
        ConfigError::ParseError { .. } | ConfigError::InvalidValue { .. } => {}
        other => panic!("text-only loading reported a filesystem error {other:?} for {text:?}"),
    }
}

fn assert_exclusions_stay_unique(config: &Config) {
    let defaults = Config::default();
    for (loaded, default) in [
        (&config.engine.exclude_dirs, &defaults.engine.exclude_dirs),
        (
            &config.engine.exclude_extensions,
            &defaults.engine.exclude_extensions,
        ),
    ] {
        let mut deduplicated = loaded.clone();
        deduplicated.sort();
        deduplicated.dedup();
        assert_eq!(
            deduplicated.len(),
            loaded.len(),
            "exclusion list repeats an entry: {loaded:?}"
        );
        if loaded != default {
            assert!(
                loaded.windows(2).all(|pair| pair[0] < pair[1]),
                "merged exclusion list is not sorted: {loaded:?}"
            );
        }
    }
}

fn assert_no_credential_survives_text_loading(config: &Config, text: &str) {
    let BackendConfig::OpenAiCompatible { api_url, api_token } = &config.llm.backend else {
        return;
    };
    assert!(
        api_token.is_none(),
        "document {text:?} loaded an API token from disk"
    );
    assert!(
        !api_url.ends_with('/'),
        "document {text:?} kept a trailing slash in {api_url:?}"
    );
}

fn assert_unknown_keys_are_rejected(text: &str) {
    let extended = format!("{text}{UNKNOWN_KEY_SUFFIX}");
    let error = config_from_toml_text(&extended)
        .err()
        .unwrap_or_else(|| panic!("unknown key accepted in {extended:?}"));
    assert!(
        matches!(error, ConfigError::ParseError { .. }),
        "unknown key produced {error:?} instead of a parse error"
    );
}

fn assert_persisted_api_tokens_are_rejected(text: &str) {
    let with_token = format!("{API_TOKEN_PREFIX}{text}");
    let error = config_from_toml_text(&with_token)
        .err()
        .unwrap_or_else(|| panic!("persisted api_token accepted in {with_token:?}"));
    match error {
        ConfigError::InvalidValue { field, .. } => assert_eq!(field, API_TOKEN_FIELD),
        other => panic!("persisted api_token produced {other:?}"),
    }
}

fn assert_validation_agrees_with_its_limits(config: &Config, mode: AnalysisMode) {
    let Ok(validated) = ValidatedConfig::new(config.clone(), mode) else {
        return;
    };
    assert_eq!(validated.mode(), mode);
    assert!(
        (1..=VALIDATED_MAX_FILE_SIZE_BYTES).contains(&validated.engine.max_file_size_bytes),
        "accepted engine.max_file_size_bytes {}",
        validated.engine.max_file_size_bytes
    );
    if let Some(depth) = validated.engine.max_depth {
        assert!(
            (1..=VALIDATED_MAX_ENGINE_DEPTH).contains(&depth),
            "accepted engine.max_depth {depth}"
        );
    }
    assert!(
        (0.0..=1.0).contains(&validated.llm.temperature),
        "accepted llm.temperature {}",
        validated.llm.temperature
    );
    assert!(!validated.analysis.categories.is_empty());
    assert!(
        (1..=VALIDATED_MAX_QUALITY_LINES).contains(&validated.analysis.quality.max_function_lines),
        "accepted analysis.quality.max_function_lines {}",
        validated.analysis.quality.max_function_lines
    );
    assert!(
        (1..=VALIDATED_MAX_QUALITY_LINES).contains(&validated.analysis.quality.max_file_lines),
        "accepted analysis.quality.max_file_lines {}",
        validated.analysis.quality.max_file_lines
    );
    for list in [
        &validated.engine.exclude_dirs,
        &validated.engine.exclude_extensions,
    ] {
        assert!(list.len() <= VALIDATED_MAX_EXCLUSIONS);
        for value in list {
            assert!(!value.trim().is_empty());
            assert!(value.len() <= VALIDATED_MAX_EXCLUSION_BYTES);
        }
    }
    if matches!(mode, AnalysisMode::Static) {
        assert!(
            validated
                .analysis
                .categories
                .iter()
                .any(|category| matches!(
                    category,
                    AnalysisCategory::Quality | AnalysisCategory::Vulnerability
                )),
            "static mode accepted categories {:?}",
            validated.analysis.categories
        );
    }
}
