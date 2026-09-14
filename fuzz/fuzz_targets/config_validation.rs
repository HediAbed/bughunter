#![no_main]

use bughunter::{
    AnalysisCategory, AnalysisMode, BackendConfig, Config, ConfigError, LineRange, LineRangeError,
    ValidatedConfig,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 4 * 1024;
const MAX_GENERATED_LIST: usize = 8;
const MAX_FILE_SIZE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ENGINE_DEPTH: usize = 1024;
const MAX_EXCLUSIONS: usize = 4096;
const MAX_EXCLUSION_BYTES: usize = 256;
const MAX_API_URL_BYTES: usize = 2048;
const MAX_API_TOKEN_BYTES: usize = 16 * 1024;
const MAX_MODEL_BYTES: usize = 256;
const MAX_REASONING_EFFORT_BYTES: usize = 64;
const MAX_CLAUDE_BINARY_BYTES: usize = 4096;
const MAX_CONTEXT_TOKENS: u32 = 2_000_000;
const MAX_QUALITY_LINES: usize = 1_000_000;
const ALL_CATEGORIES: [AnalysisCategory; 4] = [
    AnalysisCategory::Bug,
    AnalysisCategory::Quality,
    AnalysisCategory::Solid,
    AnalysisCategory::Vulnerability,
];
const ALL_MODES: [AnalysisMode; 4] = [
    AnalysisMode::Static,
    AnalysisMode::AiOnly,
    AnalysisMode::Full,
    AnalysisMode::Review,
];
const CANDIDATE_API_URLS: [&str; 8] = [
    "https://api.example.com/v1",
    "http://127.0.0.1:8080",
    "http://localhost:11434",
    "http://example.com",
    "https://user:secret@api.example.com",
    "https://api.example.com/v1?key=value",
    "https://api.example.com/v1#fragment",
    "not-a-url",
];
const CANDIDATE_TEMPERATURES: [f32; 8] = [
    0.0,
    0.5,
    1.0,
    -0.0,
    1.000_001,
    -0.000_001,
    f32::NAN,
    f32::INFINITY,
];

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let mut cursor = ByteCursor::new(data);
    let config = generate_config(&mut cursor);
    let mode = ALL_MODES[usize::from(cursor.byte()) % ALL_MODES.len()];

    let outcome = ValidatedConfig::new(config.clone(), mode);
    assert_eq!(
        outcome.is_ok(),
        ValidatedConfig::new(config.clone(), mode).is_ok(),
        "validating {config:?} in {mode:?} twice disagreed with itself"
    );

    match outcome {
        Ok(validated) => assert_accepted_config_is_within_every_limit(&validated, mode),
        Err(error) => assert_rejection_names_a_field(&error, &config, mode),
    }

    assert_line_range_contract(cursor.u32(), cursor.u32());
});

fn generate_config(cursor: &mut ByteCursor) -> Config {
    let mut config = Config::default();

    config.engine.max_file_size_bytes = cursor.u64();
    config.engine.max_depth = cursor.boolean().then(|| cursor.usize());
    config.engine.exclude_dirs = cursor.text_list();
    config.engine.exclude_extensions = cursor.text_list();

    config.llm.max_tokens = cursor.u32();
    config.llm.timeout_seconds = cursor.u64();
    config.llm.max_retries = cursor.u32();
    config.llm.max_agent_iterations = cursor.u32();
    config.llm.max_context_tokens = cursor.u32();
    config.llm.max_shard_seconds = cursor.u64();
    config.llm.temperature = cursor.temperature();
    config.llm.model = cursor.text();
    config.llm.reasoning_effort = cursor.boolean().then(|| cursor.text());
    config.llm.backend = if cursor.boolean() {
        BackendConfig::OpenAiCompatible {
            api_url: cursor.api_url(),
            api_token: cursor.boolean().then(|| cursor.text()),
        }
    } else {
        BackendConfig::ClaudeCli {
            binary: cursor.text(),
        }
    };

    config.analysis.categories = ALL_CATEGORIES
        .into_iter()
        .filter(|_| cursor.boolean())
        .collect();
    config.analysis.quality.max_function_lines = cursor.usize();
    config.analysis.quality.max_file_lines = cursor.usize();

    config
}

fn assert_accepted_config_is_within_every_limit(validated: &ValidatedConfig, mode: AnalysisMode) {
    assert_eq!(validated.mode(), mode, "validation forgot the mode");

    assert!(
        (1..=MAX_FILE_SIZE_BYTES).contains(&validated.engine.max_file_size_bytes),
        "accepted engine.max_file_size_bytes {}",
        validated.engine.max_file_size_bytes
    );
    if let Some(depth) = validated.engine.max_depth {
        assert!(
            (1..=MAX_ENGINE_DEPTH).contains(&depth),
            "accepted engine.max_depth {depth}"
        );
    }
    for list in [
        &validated.engine.exclude_dirs,
        &validated.engine.exclude_extensions,
    ] {
        assert!(
            list.len() <= MAX_EXCLUSIONS,
            "accepted {} exclusions",
            list.len()
        );
        for value in list {
            assert_bounded_text("exclusion", value, MAX_EXCLUSION_BYTES);
        }
    }

    assert!(
        (0.0..=1.0).contains(&validated.llm.temperature),
        "accepted llm.temperature {}",
        validated.llm.temperature
    );
    assert!(
        (256..=1_000_000).contains(&validated.llm.max_tokens),
        "accepted llm.max_tokens {}",
        validated.llm.max_tokens
    );
    assert!(
        (1..=3600).contains(&validated.llm.timeout_seconds),
        "accepted llm.timeout_seconds {}",
        validated.llm.timeout_seconds
    );
    assert!(
        validated.llm.max_retries <= 10,
        "accepted llm.max_retries {}",
        validated.llm.max_retries
    );
    assert!(
        (60..=7200).contains(&validated.llm.max_shard_seconds),
        "accepted llm.max_shard_seconds {}",
        validated.llm.max_shard_seconds
    );
    assert!(
        validated.llm.max_context_tokens == 0
            || (1024..=MAX_CONTEXT_TOKENS).contains(&validated.llm.max_context_tokens),
        "accepted llm.max_context_tokens {}",
        validated.llm.max_context_tokens
    );
    if let Some(effort) = &validated.llm.reasoning_effort {
        assert_bounded_text("llm.reasoning_effort", effort, MAX_REASONING_EFFORT_BYTES);
    }

    assert!(
        !validated.analysis.categories.is_empty(),
        "accepted an empty category set"
    );
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
    assert!(
        (1..=MAX_QUALITY_LINES).contains(&validated.analysis.quality.max_function_lines),
        "accepted analysis.quality.max_function_lines {}",
        validated.analysis.quality.max_function_lines
    );
    assert!(
        (1..=MAX_QUALITY_LINES).contains(&validated.analysis.quality.max_file_lines),
        "accepted analysis.quality.max_file_lines {}",
        validated.analysis.quality.max_file_lines
    );

    if mode.requires_ai() {
        assert_backend_is_usable(&validated.llm.backend, &validated.llm.model);
        if matches!(
            validated.llm.backend,
            BackendConfig::OpenAiCompatible { .. }
        ) {
            assert!(
                (2..=500).contains(&validated.llm.max_agent_iterations),
                "accepted llm.max_agent_iterations {}",
                validated.llm.max_agent_iterations
            );
        }
    }
}

fn assert_backend_is_usable(backend: &BackendConfig, model: &str) {
    match backend {
        BackendConfig::OpenAiCompatible { api_url, api_token } => {
            assert!(
                !api_url.is_empty() && api_url.len() <= MAX_API_URL_BYTES,
                "accepted a {} byte llm.api_url for an AI mode",
                api_url.len()
            );
            let token = api_token
                .as_deref()
                .unwrap_or_else(|| panic!("accepted a tokenless OpenAI backend for an AI mode"));
            assert_bounded_text("BUGHUNTER_API_TOKEN", token, MAX_API_TOKEN_BYTES);
            assert_bounded_text("llm.model", model, MAX_MODEL_BYTES);
        }
        BackendConfig::ClaudeCli { binary } => {
            assert_bounded_text("llm.claude_cli_binary", binary, MAX_CLAUDE_BINARY_BYTES);
        }
    }
}

fn assert_bounded_text(field: &str, value: &str, max_bytes: usize) {
    assert!(!value.trim().is_empty(), "accepted a blank {field}");
    assert!(
        value.len() <= max_bytes,
        "accepted a {} byte {field}",
        value.len()
    );
}

fn assert_rejection_names_a_field(error: &ConfigError, config: &Config, mode: AnalysisMode) {
    match error {
        ConfigError::InvalidValue { field, reason } => {
            assert!(!field.is_empty(), "rejected {config:?} without a field");
            assert!(!reason.is_empty(), "rejected {config:?} without a reason");
        }
        ConfigError::MissingRequired { field, .. } => {
            assert!(!field.is_empty(), "rejected {config:?} without a field");
            assert!(
                mode.requires_ai(),
                "reported a missing credential for {mode:?}"
            );
        }
        other => panic!("in-memory validation reported {other:?} for {config:?}"),
    }
}

fn assert_line_range_contract(start: u32, end: u32) {
    match LineRange::new(start, end) {
        Ok(range) => {
            assert!(start >= 1 && end >= start, "accepted lines {start}..{end}");
            assert_eq!(range.start(), start, "line range moved its start");
            assert_eq!(range.end(), end, "line range moved its end");
        }
        Err(LineRangeError::ZeroStart) => assert_eq!(start, 0, "rejected a non-zero start"),
        Err(LineRangeError::ZeroEnd) => {
            assert!(start >= 1 && end == 0, "rejected a non-zero end");
        }
        Err(LineRangeError::Reversed {
            start: reported_start,
            end: reported_end,
        }) => {
            assert_eq!((reported_start, reported_end), (start, end));
            assert!(end >= 1 && end < start, "rejected an ordered range");
        }
    }
}

struct ByteCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> ByteCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { remaining: data }
    }

    fn byte(&mut self) -> u8 {
        self.take::<1>()[0]
    }

    fn boolean(&mut self) -> bool {
        self.byte() & 1 == 1
    }

    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take())
    }

    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.take())
    }

    fn usize(&mut self) -> usize {
        usize::try_from(self.u64()).unwrap_or(usize::MAX)
    }

    fn text(&mut self) -> String {
        let remaining = self.remaining;
        let length = usize::from(self.byte()).min(remaining.len());
        let (value, rest) = remaining.split_at(length);
        self.remaining = rest;
        String::from_utf8_lossy(value).into_owned()
    }

    fn text_list(&mut self) -> Vec<String> {
        let count = usize::from(self.byte()) % (MAX_GENERATED_LIST + 1);
        (0..count).map(|_| self.text()).collect()
    }

    fn temperature(&mut self) -> f32 {
        if self.boolean() {
            return CANDIDATE_TEMPERATURES[usize::from(self.byte()) % CANDIDATE_TEMPERATURES.len()];
        }
        f32::from_bits(self.u32())
    }

    fn api_url(&mut self) -> String {
        if self.boolean() {
            return CANDIDATE_API_URLS[usize::from(self.byte()) % CANDIDATE_API_URLS.len()]
                .to_string();
        }
        self.text()
    }

    fn take<const N: usize>(&mut self) -> [u8; N] {
        let remaining = self.remaining;
        let mut output = [0; N];
        let length = N.min(remaining.len());
        output[..length].copy_from_slice(&remaining[..length]);
        self.remaining = &remaining[length..];
        output
    }
}
