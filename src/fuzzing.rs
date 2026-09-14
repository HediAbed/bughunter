use std::path::Path;

use crate::errors::ReportError;
use crate::report::{Finding, ScanStatus};

pub use crate::config::loader::config_from_toml_text;
pub use crate::domain::{ProjectPath, ProjectPathError};
pub use crate::engine::{DefaultEngine, ProjectInventory};
pub use crate::llm::mcp_server::{SessionLog, dispatch_mcp_line, dispatch_mcp_request};
pub use crate::llm::tool_exec::{ToolExecutor, ToolOutcome};
pub use crate::llm::types::{
    ContentBlock, LlmResponse, Role, StopReason, StreamAccumulator, StreamLimit,
};
pub use crate::report::FindingCounter;
pub use crate::review::archive::{ArchiveLimits, extract_zip_archive};
pub use crate::review::{DiffLimits, parse_unified_diff};
pub use crate::shared::{
    sanitize_markdown_block, sanitize_markdown_inline, sanitize_terminal_text,
};

pub fn render_json_report(
    version: &str,
    project_root: &Path,
    findings: &[Finding],
    mode: &str,
    scan: &ScanStatus,
) -> Result<String, ReportError> {
    crate::report::json::render(version, project_root, findings, mode, scan)
}

pub fn render_markdown_report(
    findings: &[Finding],
    scan: &ScanStatus,
) -> Result<String, ReportError> {
    crate::orchestrator::render_markdown_summary(findings, scan)
}
