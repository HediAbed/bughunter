use super::*;

#[test]
fn backend_debug_redacts_api_token() {
    let backend = BackendConfig::OpenAiCompatible {
        api_url: "https://api.example.com".into(),
        api_token: Some("sk-super-secret-value".into()),
    };
    let rendered = format!("{backend:?}");
    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains("sk-super-secret-value"));
    assert!(rendered.contains("https://api.example.com"));
}

#[test]
fn effective_context_tokens_uses_the_default_until_explicitly_overridden() {
    let mut config = LlmConfig::default();
    assert_eq!(config.effective_context_tokens(), 128_000);

    config.max_context_tokens = 64_000;
    assert_eq!(config.effective_context_tokens(), 64_000);
}

#[test]
fn static_mode_requires_static_not_ai() {
    assert!(AnalysisMode::Static.requires_static());
    assert!(!AnalysisMode::Static.requires_ai());
}

#[test]
fn ai_only_mode_requires_ai_not_static() {
    assert!(AnalysisMode::AiOnly.requires_ai());
    assert!(!AnalysisMode::AiOnly.requires_static());
}

#[test]
fn full_mode_requires_both() {
    assert!(AnalysisMode::Full.requires_ai());
    assert!(AnalysisMode::Full.requires_static());
}

#[test]
fn review_mode_requires_ai_not_static() {
    assert!(AnalysisMode::Review.requires_ai());
    assert!(!AnalysisMode::Review.requires_static());
}

#[test]
fn analysis_mode_display() {
    assert_eq!(AnalysisMode::Static.to_string(), "static");
    assert_eq!(AnalysisMode::AiOnly.to_string(), "ai");
    assert_eq!(AnalysisMode::Full.to_string(), "full");
    assert_eq!(AnalysisMode::Review.to_string(), "review");
}

#[test]
fn confidence_orders_low_to_high() {
    assert!(Confidence::Low < Confidence::Medium);
    assert!(Confidence::Medium < Confidence::High);
}

#[test]
fn severity_orders_info_to_critical() {
    assert!(Severity::Info < Severity::Low);
    assert!(Severity::High < Severity::Critical);
}

#[test]
fn claude_cli_backend_debug_includes_only_its_binary() {
    let backend = BackendConfig::ClaudeCli {
        binary: "/opt/bin/claude".into(),
    };

    let rendered = format!("{backend:?}");

    assert_eq!(rendered, "ClaudeCli { binary: \"/opt/bin/claude\" }");
}

#[test]
fn severity_display_matches_serialized_values() {
    for severity in [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ] {
        assert_eq!(
            format!("\"{severity}\""),
            serde_json::to_string(&severity).unwrap()
        );
    }
}

#[test]
fn category_display_matches_serialized_values() {
    for category in [
        AnalysisCategory::Bug,
        AnalysisCategory::Quality,
        AnalysisCategory::Solid,
        AnalysisCategory::Vulnerability,
    ] {
        assert_eq!(
            format!("\"{category}\""),
            serde_json::to_string(&category).unwrap()
        );
    }
}
