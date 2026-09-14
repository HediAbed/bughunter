mod analyze;
mod commands;
mod doctor;
mod init;
mod log_format;
mod logging;
pub mod output;
mod project;

#[cfg(test)]
mod tests;

use clap::{Parser, Subcommand};

use crate::errors::{BugHunterError, LlmError};
use commands::{AnalyzeArgs, DoctorArgs, InitArgs};

#[derive(Parser, Debug)]
#[command(
    name = "bughunter",
    version = crate::version::VERSION,
    about = "Local static code analysis with optional external analysis",
    long_about = "BugHunter analyzes codebases for bugs, quality issues, SOLID violations, and security vulnerabilities.\n\n\
                  The default analyze mode runs local static checks only. External analysis runs only when explicitly selected with --with-ai or --ai-only.",
    after_help = "ENVIRONMENT VARIABLES:\n  \
                  BUGHUNTER_BACKEND            claude-cli | openai-compatible\n  \
                  BUGHUNTER_CLAUDE_CLI_BINARY  Executable path for the CLI backend\n  \
                  BUGHUNTER_MODEL              Model identifier\n  \
                  BUGHUNTER_API_TOKEN          Bearer token for the HTTP backend\n  \
                  BUGHUNTER_API_URL            HTTP backend base URL\n  \
                  BUGHUNTER_LOG_LEVEL          trace | debug | info | warn | error\n\n\
                  EXAMPLES:\n  \
                  bughunter analyze --project .\n  \
                  bughunter analyze --project . --with-ai --output report.json\n  \
                  bughunter doctor --project .\n  \
                  bughunter help analyze"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    #[command(
        about = "Analyze a project for bugs, quality issues, SOLID violations, and vulnerabilities",
        long_about = "Analyze a project for bugs, code quality issues, SOLID violations, and security vulnerabilities.\n\n\
                      Default mode: static. It runs local regex and syntax-tree checks without an external request.\n\
                      Pass --with-ai for static and AI analysis, or --ai-only to skip static checks.",
        after_help = "EXAMPLES:\n  \
                      bughunter analyze --project .\n  \
                      bughunter analyze --project . --with-ai --output report.json\n  \
                      bughunter analyze --project . --ai-only --format md\n\n\
                      EXIT CODES:\n  \
                      0    Analysis completed below the finding threshold\n  \
                      1    Findings met the configured threshold\n  \
                      2    Configuration error\n  \
                      3    Analysis backend error\n  \
                      4    Project or engine error\n  \
                      5    Analysis coverage was partial\n  \
                      130  Analysis was cancelled"
    )]
    Analyze(AnalyzeArgs),
    #[command(
        about = "Check the local prerequisites of the configured analysis backend",
        long_about = "Resolve configuration through the same loader and precedence as analyze, then report the selected backend and whether its local prerequisites are present.\n\n\
                      Every check is local: no provider request is made.",
        after_help = "EXAMPLES:\n  \
                      bughunter doctor --project .\n  \
                      bughunter doctor --project . --config ./.bughunter.toml\n\n\
                      EXIT CODES:\n  \
                      0    The selected backend is ready\n  \
                      2    Configuration error\n  \
                      3    The selected backend is unavailable locally"
    )]
    Doctor(DoctorArgs),
    #[command(about = "Create a default .bughunter.toml config file")]
    Init(InitArgs),
    #[command(about = "Print version information")]
    Version,
    #[command(name = "mcp-serve", hide = true)]
    McpServe,
}

impl Cli {
    pub(crate) fn run(&self) -> Result<i32, BugHunterError> {
        match &self.command {
            Command::Analyze(args) => analyze::run(args),
            Command::Doctor(args) => doctor::run(args),
            Command::Init(args) => init::run(args),
            Command::Version => {
                output::print_version()?;
                Ok(0)
            }
            Command::McpServe => {
                crate::llm::mcp_server::serve().map_err(|error| {
                    BugHunterError::Llm(LlmError::ApiError {
                        status: 0,
                        body: format!("mcp server failed: {error}"),
                    })
                })?;
                Ok(0)
            }
        }
    }
}
