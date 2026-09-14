use std::path::PathBuf;

use clap::{Args, ValueEnum};

use crate::config::schema::{AnalysisCategory, AnalysisMode, Confidence, OutputFormat, Severity};

#[derive(Args, Debug)]
pub struct AnalyzeArgs {
    #[arg(long, default_value = ".", help = "Path to project root")]
    pub project: PathBuf,

    #[arg(long, help = "Output format [default: json]")]
    pub format: Option<OutputFormatArg>,

    #[arg(long, help = "Write report to file instead of stdout")]
    pub output: Option<PathBuf>,

    #[arg(long, help = "Minimum severity to fail (exit code 1) [default: high]")]
    pub fail_severity: Option<SeverityArg>,

    #[arg(
        long,
        help = "Always exit 0, even when findings meet the fail threshold"
    )]
    pub no_fail: bool,

    #[arg(long, help = "Exit normally even when AI coverage is partial")]
    pub allow_partial: bool,

    #[arg(long, help = "Run static checks only, no LLM call (fastest mode)")]
    pub static_only: bool,

    #[arg(
        long,
        conflicts_with = "static_only",
        help = "Run AI analysis only, skip static checks"
    )]
    pub ai_only: bool,

    #[arg(
        long,
        conflicts_with_all = ["static_only", "ai_only", "pr"],
        help = "Run static checks and AI analysis"
    )]
    pub with_ai: bool,

    #[arg(
        long,
        value_delimiter = ',',
        help = "Analysis categories to run (comma-separated)"
    )]
    pub categories: Option<Vec<CategoryArg>>,

    #[arg(long, help = "Path to .bughunter.toml config file")]
    pub config: Option<PathBuf>,

    #[arg(long, help = "Minimum confidence to include in report [default: low]")]
    pub min_confidence: Option<ConfidenceArg>,

    #[arg(long, help = "Enable debug logging")]
    pub verbose: bool,

    #[arg(long, help = "Disable the interactive progress display")]
    pub no_progress: bool,

    #[arg(
        long,
        value_name = "NUMBER",
        conflicts_with = "static_only",
        help = "Review only the files changed in a GitHub PR (fetches the pinned base and head revisions from the GitHub API)"
    )]
    pub pr: Option<u64>,

    #[arg(
        long,
        value_name = "OWNER/REPO",
        requires = "pr",
        help = "GitHub repo for --pr; defaults to the project's git origin"
    )]
    pub repo: Option<String>,
}

#[derive(Args, Debug)]
pub struct InitArgs {
    #[arg(long, help = "Project directory to create config in")]
    pub project: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct DoctorArgs {
    #[arg(long, default_value = ".", help = "Path to project root")]
    pub project: PathBuf,

    #[arg(long, help = "Path to .bughunter.toml config file")]
    pub config: Option<PathBuf>,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormatArg {
    Json,
    Md,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum SeverityArg {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum CategoryArg {
    Bug,
    Quality,
    Solid,
    Vulnerability,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum ConfidenceArg {
    High,
    Medium,
    Low,
}

impl From<OutputFormatArg> for OutputFormat {
    fn from(arg: OutputFormatArg) -> Self {
        match arg {
            OutputFormatArg::Json => OutputFormat::Json,
            OutputFormatArg::Md => OutputFormat::Md,
        }
    }
}

impl From<SeverityArg> for Severity {
    fn from(arg: SeverityArg) -> Self {
        match arg {
            SeverityArg::Critical => Severity::Critical,
            SeverityArg::High => Severity::High,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::Low => Severity::Low,
            SeverityArg::Info => Severity::Info,
        }
    }
}

impl AnalyzeArgs {
    pub fn analysis_mode(&self) -> AnalysisMode {
        if self.pr.is_some() {
            AnalysisMode::Review
        } else if self.static_only {
            AnalysisMode::Static
        } else if self.ai_only {
            AnalysisMode::AiOnly
        } else if self.with_ai {
            AnalysisMode::Full
        } else {
            AnalysisMode::Static
        }
    }
}

impl From<CategoryArg> for AnalysisCategory {
    fn from(arg: CategoryArg) -> Self {
        match arg {
            CategoryArg::Bug => AnalysisCategory::Bug,
            CategoryArg::Quality => AnalysisCategory::Quality,
            CategoryArg::Solid => AnalysisCategory::Solid,
            CategoryArg::Vulnerability => AnalysisCategory::Vulnerability,
        }
    }
}

impl From<ConfidenceArg> for Confidence {
    fn from(arg: ConfidenceArg) -> Self {
        match arg {
            ConfidenceArg::High => Confidence::High,
            ConfidenceArg::Medium => Confidence::Medium,
            ConfidenceArg::Low => Confidence::Low,
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn default_args() -> AnalyzeArgs {
        AnalyzeArgs {
            project: ".".into(),
            format: None,
            output: None,
            fail_severity: None,
            no_fail: false,
            static_only: false,
            ai_only: false,
            with_ai: false,
            categories: None,
            config: None,
            min_confidence: None,
            verbose: false,
            no_progress: false,
            allow_partial: false,
            pr: None,
            repo: None,
        }
    }

    #[test]
    fn defaults_to_static_mode() {
        let args = default_args();
        assert_eq!(args.analysis_mode(), AnalysisMode::Static);
    }

    #[test]
    fn static_only_flag_selects_static_mode() {
        let args = AnalyzeArgs {
            static_only: true,
            ..default_args()
        };
        assert_eq!(args.analysis_mode(), AnalysisMode::Static);
    }

    #[test]
    fn ai_only_flag_selects_ai_only_mode() {
        let args = AnalyzeArgs {
            ai_only: true,
            ..default_args()
        };
        assert_eq!(args.analysis_mode(), AnalysisMode::AiOnly);
    }

    #[test]
    fn confidence_arg_converts_to_domain_type() {
        assert_eq!(Confidence::from(ConfidenceArg::Low), Confidence::Low);
        assert_eq!(Confidence::from(ConfidenceArg::Medium), Confidence::Medium);
        assert_eq!(Confidence::from(ConfidenceArg::High), Confidence::High);
    }

    #[test]
    fn pr_flag_selects_review_mode_over_other_flags() {
        let args = AnalyzeArgs {
            pr: Some(42),
            static_only: true,
            ai_only: true,
            ..default_args()
        };

        assert_eq!(args.analysis_mode(), AnalysisMode::Review);
    }

    #[test]
    fn output_format_arg_converts_to_domain_type() {
        assert_eq!(
            OutputFormat::from(OutputFormatArg::Json),
            OutputFormat::Json
        );
        assert_eq!(OutputFormat::from(OutputFormatArg::Md), OutputFormat::Md);
    }

    #[test]
    fn severity_arg_converts_to_domain_type() {
        let pairs = [
            (SeverityArg::Info, Severity::Info),
            (SeverityArg::Low, Severity::Low),
            (SeverityArg::Medium, Severity::Medium),
            (SeverityArg::High, Severity::High),
            (SeverityArg::Critical, Severity::Critical),
        ];

        for (argument, expected) in pairs {
            assert_eq!(Severity::from(argument), expected);
        }
    }

    #[test]
    fn category_arg_converts_to_domain_type() {
        let pairs = [
            (CategoryArg::Bug, AnalysisCategory::Bug),
            (CategoryArg::Quality, AnalysisCategory::Quality),
            (CategoryArg::Solid, AnalysisCategory::Solid),
            (CategoryArg::Vulnerability, AnalysisCategory::Vulnerability),
        ];

        for (argument, expected) in pairs {
            assert_eq!(AnalysisCategory::from(argument), expected);
        }
    }
}
