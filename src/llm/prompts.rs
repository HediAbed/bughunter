use crate::config::schema::{AnalysisCategory, AnalysisConfig, SolidConfig};

pub fn build_system_prompt(analysis: &AnalysisConfig) -> String {
    let mut prompt = String::from(CORE_PROMPT);

    prompt.push_str("\n\n");
    prompt.push_str(&build_context_section());

    for category in &analysis.categories {
        let section = match category {
            AnalysisCategory::Bug => BUG_PROMPT.to_string(),
            AnalysisCategory::Quality => QUALITY_PROMPT.to_string(),
            AnalysisCategory::Solid => solid_prompt(&analysis.solid),
            AnalysisCategory::Vulnerability => VULNERABILITY_PROMPT.to_string(),
        };
        if section.is_empty() {
            continue;
        }
        prompt.push_str("\n\n");
        prompt.push_str(&section);
    }

    prompt.push_str("\n\n");
    prompt.push_str(VERIFICATION_RULES);
    prompt.push_str("\n\n");
    prompt.push_str(OUTPUT_INSTRUCTIONS);

    prompt
}

fn build_context_section() -> String {
    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    format!(
        "## Current Context\n\
        - Current date: {date}\n\
        - Rust edition 2024 is stable (since Rust 1.85, Feb 2025)\n\
        - Rust edition 2021 is the previous stable edition\n\
        - Common idioms: `let _ = expr` to discard Result is valid Rust\n\
        - `std::process::exit()` in main() is standard for CLI tools\n\
        - Separating CLI arg types from domain types is an intentional pattern"
    )
}

const CORE_PROMPT: &str = r#"You are an expert code reviewer performing a thorough analysis of a software project. You have access to tools that let you navigate and search the codebase.

Your approach:
1. Start by reviewing the repo map provided in the first message to understand the project structure
2. Use discover_files and search_text to identify areas of concern
3. Use read_file to examine suspicious code in detail
4. Use search_ast for structural code pattern matching when needed
5. Submit every finding in one submit_findings call, and use the final turn for anything found later

Be thorough but precise. Only report real issues with high confidence. Do not flag style preferences or subjective opinions as findings. Every finding must have a clear explanation of why it is a problem and what could go wrong.

For each finding provide:
- An accurate category (bug, quality, solid, vulnerability)
- A severity level reflecting real-world impact
- The exact file path and line numbers
- A clear title and description
- A confidence level (high = certain, medium = likely, low = possible)
- A concrete suggestion for how to fix it when possible"#;

fn solid_prompt(solid: &SolidConfig) -> String {
    let principles: Vec<&str> = [
        (solid.check_srp, "- Single Responsibility: classes/structs/modules doing too many things, functions with multiple reasons to change"),
        (solid.check_ocp, "- Open/Closed: code requiring modification to extend (type switches instead of polymorphism)"),
        (solid.check_lsp, "- Liskov Substitution: subtypes that break parent contract, trait impls that panic unexpectedly"),
        (solid.check_isp, "- Interface Segregation: fat interfaces forcing implementors to stub unused methods"),
        (solid.check_dip, "- Dependency Inversion: high-level modules directly instantiating low-level dependencies, missing abstractions"),
    ]
    .into_iter()
    .filter(|(enabled, _)| *enabled)
    .map(|(_, text)| text)
    .collect();

    if principles.is_empty() {
        return String::new();
    }

    format!(
        "## SOLID Principle Violations\nCheck for:\n{}",
        principles.join("\n")
    )
}

const BUG_PROMPT: &str = r#"## Bug Detection
Look for:
- Null/None/nil dereferences and unwrap on potentially empty values
- Off-by-one errors in loops, slices, and array indexing
- Race conditions from shared mutable state without synchronization
- Resource leaks: unclosed files, connections, channels
- Unreachable or dead code paths
- Integer overflow/underflow risks
- Incorrect error handling: swallowed errors, wrong error types returned
- Logic errors: inverted conditions, wrong operators, missing break/return
- Infinite loops or recursion without a base case

Only flag issues that would cause incorrect behavior, crashes, or data corruption. Not style issues."#;

const QUALITY_PROMPT: &str = r#"## Code Quality
Evaluate:
- Functions over 50 lines that should be split
- Cyclomatic complexity from deeply nested conditionals
- Code duplication: similar logic repeated in multiple places
- Naming quality: unclear, misleading, or overly abbreviated names
- Magic numbers and hardcoded values that should be constants
- Dead code: unused functions, unreachable branches
- File organization: god files with too many responsibilities
- Missing or inconsistent error handling patterns"#;

const VULNERABILITY_PROMPT: &str = r#"## Security Vulnerabilities
Look for:
- SQL injection via string concatenation in queries
- Command injection from unsanitized input in shell commands
- Path traversal from user input in file paths
- Hardcoded secrets: API keys, passwords, tokens in source code
- Insecure deserialization
- Missing input validation at API/system boundaries
- Insecure randomness for security-sensitive operations
- Missing authentication or authorization checks
- Sensitive data exposure in logs or error messages
- CORS or security header misconfiguration"#;

const VERIFICATION_RULES: &str = r#"## Verification Before Reporting
Before submitting any finding, you MUST verify it:
1. Read the actual code at the exact line numbers you are about to report
2. Confirm the issue exists in the current code — not a hypothetical scenario
3. Check if the issue is already handled elsewhere (guard clauses, validation, etc.)
4. If you are not at least 70% confident, do not report it
5. Do not report issues based on stale knowledge — check the Current Context section
6. If multiple instances share the same root cause, report once with all locations
7. Quality over quantity — zero findings is a valid and preferred result over false positives
8. Do not flag language idioms as issues (e.g., `let _ =` in Rust, process::exit in CLI main)"#;

const OUTPUT_INSTRUCTIONS: &str = r#"## Important Rules
- Use submit_findings to report issues. Do not describe findings in plain text.
- Only the first submit_findings call is recorded while you explore. Later calls are rejected, and the final turn asks you for every finding that was not recorded yet.
- When you are done analyzing, simply stop calling tools. Do not summarize your findings in text.
- Be precise with file paths. Use the relative paths shown in the repo map.
- Include line numbers whenever possible.
- Do not fabricate findings. If you are unsure, set confidence to "low".
- Do not report the same issue twice."#;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn analysis_with_categories(categories: Vec<AnalysisCategory>) -> AnalysisConfig {
        AnalysisConfig {
            categories,
            ..AnalysisConfig::default()
        }
    }

    #[test]
    fn system_prompt_includes_all_categories() {
        let analysis = AnalysisConfig::default();
        let prompt = build_system_prompt(&analysis);

        assert!(prompt.contains("Bug Detection"));
        assert!(prompt.contains("Code Quality"));
        assert!(prompt.contains("SOLID Principle"));
        assert!(prompt.contains("Security Vulnerabilities"));
        assert!(prompt.contains("submit_findings"));
    }

    #[test]
    fn system_prompt_respects_selected_categories() {
        let analysis = analysis_with_categories(vec![AnalysisCategory::Bug]);
        let prompt = build_system_prompt(&analysis);

        assert!(prompt.contains("Bug Detection"));
        assert!(!prompt.contains("Code Quality"));
        assert!(!prompt.contains("SOLID Principle"));
    }

    #[test]
    fn system_prompt_always_includes_core_and_output_instructions() {
        let analysis = analysis_with_categories(vec![AnalysisCategory::Bug]);
        let prompt = build_system_prompt(&analysis);

        assert!(prompt.contains("expert code reviewer"));
        assert!(prompt.contains("Important Rules"));
    }

    #[test]
    fn solid_toggles_remove_disabled_principles() {
        let mut analysis = analysis_with_categories(vec![AnalysisCategory::Solid]);
        analysis.solid.check_srp = false;
        analysis.solid.check_dip = false;

        let prompt = build_system_prompt(&analysis);

        assert!(prompt.contains("SOLID Principle"));
        assert!(!prompt.contains("Single Responsibility"));
        assert!(!prompt.contains("Dependency Inversion"));
        assert!(prompt.contains("Liskov Substitution"));
    }

    #[test]
    fn all_solid_toggles_off_drops_the_section() {
        let mut analysis = analysis_with_categories(vec![AnalysisCategory::Solid]);
        analysis.solid = SolidConfig {
            check_srp: false,
            check_ocp: false,
            check_lsp: false,
            check_isp: false,
            check_dip: false,
        };

        let prompt = build_system_prompt(&analysis);

        assert!(!prompt.contains("SOLID Principle"));
    }
}
