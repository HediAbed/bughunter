use serde_json::json;

use super::types::{InputSchema, ToolConfig, ToolDefinition, ToolSpec};
pub(super) const MAX_PATH_BYTES: usize = 4096;
pub(super) const MAX_FILTERS: usize = 32;
pub(super) const MAX_EXTENSION_BYTES: usize = 32;
pub(super) const MAX_FILE_PATTERN_BYTES: usize = 256;
pub(super) const MAX_SEARCH_PATTERN_BYTES: usize = 4096;
pub(super) const MAX_AST_QUERY_BYTES: usize = crate::engine::ast::MAX_AST_QUERY_BYTES;
pub(super) const MAX_LANGUAGE_BYTES: usize = 32;
pub(super) const MAX_DISCOVERY_DEPTH: u32 = 256;
pub(super) const MAX_TOOL_RESULTS: u32 = 1000;
pub(super) const MAX_CONTEXT_LINES: u32 = 20;
pub(super) const MAX_FINDINGS_PER_SUBMISSION: usize = 1000;
pub(super) const MAX_FINDING_TITLE_BYTES: usize = 512;
pub(super) const MAX_FINDING_DESCRIPTION_BYTES: usize = 16 * 1024;
pub(super) const MAX_FINDING_SNIPPET_BYTES: usize = 64 * 1024;
pub(super) const MAX_FINDING_SUGGESTION_BYTES: usize = 16 * 1024;
pub(super) const MAX_FINDING_RULE_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolName {
    DiscoverFiles,
    SearchText,
    ReadFile,
    ProjectStats,
    SearchAst,
    SubmitFindings,
}

impl ToolName {
    const ALL: [ToolName; 6] = [
        ToolName::DiscoverFiles,
        ToolName::SearchText,
        ToolName::ReadFile,
        ToolName::ProjectStats,
        ToolName::SearchAst,
        ToolName::SubmitFindings,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            ToolName::DiscoverFiles => "discover_files",
            ToolName::SearchText => "search_text",
            ToolName::ReadFile => "read_file",
            ToolName::ProjectStats => "project_stats",
            ToolName::SearchAst => "search_ast",
            ToolName::SubmitFindings => "submit_findings",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tool| tool.as_str() == name)
    }
}

pub const DISCOVER_FILES: &str = ToolName::DiscoverFiles.as_str();
pub const SEARCH_TEXT: &str = ToolName::SearchText.as_str();
pub const READ_FILE: &str = ToolName::ReadFile.as_str();
pub const PROJECT_STATS: &str = ToolName::ProjectStats.as_str();
pub const SEARCH_AST: &str = ToolName::SearchAst.as_str();
pub const SUBMIT_FINDINGS: &str = ToolName::SubmitFindings.as_str();

pub fn build_tool_config() -> ToolConfig {
    ToolConfig {
        tools: vec![
            discover_files_tool(),
            search_text_tool(),
            read_file_tool(),
            project_stats_tool(),
            search_ast_tool(),
            submit_findings_tool(),
        ],
        required_tool: None,
    }
}

pub fn build_finalization_tool_config() -> ToolConfig {
    ToolConfig {
        tools: vec![submit_findings_tool()],
        required_tool: Some(SUBMIT_FINDINGS.into()),
    }
}

fn discover_files_tool() -> ToolDefinition {
    ToolDefinition {
        tool_spec: ToolSpec {
            name: DISCOVER_FILES.into(),
            description: "Find files in the project matching criteria. Use to explore project structure or locate files by extension or name pattern.".into(),
            input_schema: InputSchema {
                json: json!({
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "extensions": {
                            "type": "array",
                            "maxItems": MAX_FILTERS,
                            "items": {"type": "string", "minLength": 1, "maxLength": MAX_EXTENSION_BYTES},
                            "description": "Filter by file extensions, e.g. [\"rs\", \"py\", \"ts\"]"
                        },
                        "pattern": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": MAX_FILE_PATTERN_BYTES,
                            "description": "Filename substring pattern to match"
                        },
                        "max_depth": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": MAX_DISCOVERY_DEPTH,
                            "description": "Max directory depth to search"
                        },
                        "max_results": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": MAX_TOOL_RESULTS,
                            "description": "Max number of files to return"
                        }
                    }
                }),
            },
        },
    }
}

fn search_text_tool() -> ToolDefinition {
    ToolDefinition {
        tool_spec: ToolSpec {
            name: SEARCH_TEXT.into(),
            description: "Search code by text/regex pattern across the project. Returns matching lines with surrounding context.".into(),
            input_schema: InputSchema {
                json: json!({
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "pattern": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": MAX_SEARCH_PATTERN_BYTES,
                            "description": "Search pattern (regex supported)"
                        },
                        "file_extensions": {
                            "type": "array",
                            "maxItems": MAX_FILTERS,
                            "items": {"type": "string", "minLength": 1, "maxLength": MAX_EXTENSION_BYTES},
                            "description": "Only search files with these extensions"
                        },
                        "case_sensitive": {
                            "type": "boolean",
                            "description": "Case sensitive search (default: false)"
                        },
                        "context_lines": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": MAX_CONTEXT_LINES,
                            "description": "Lines of context around each match (default: 3)"
                        },
                        "max_results": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": MAX_TOOL_RESULTS,
                            "description": "Max matches to return"
                        }
                    },
                    "required": ["pattern"]
                }),
            },
        },
    }
}

fn read_file_tool() -> ToolDefinition {
    ToolDefinition {
        tool_spec: ToolSpec {
            name: READ_FILE.into(),
            description: "Read the content of a file, optionally a specific line range. Use this to examine code in detail.".into(),
            input_schema: InputSchema {
                json: json!({
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "path": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": MAX_PATH_BYTES,
                            "description": "Relative path to the file from project root"
                        },
                        "start_line": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "First line to read (1-indexed)"
                        },
                        "end_line": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Last line to read (inclusive)"
                        }
                    },
                    "required": ["path"]
                }),
            },
        },
    }
}

fn project_stats_tool() -> ToolDefinition {
    ToolDefinition {
        tool_spec: ToolSpec {
            name: PROJECT_STATS.into(),
            description: "Get project statistics: total files, lines of code, language breakdown. Gives a high-level overview of project scale and composition.".into(),
            input_schema: InputSchema {
                json: json!({
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {}
                }),
            },
        },
    }
}

fn search_ast_tool() -> ToolDefinition {
    ToolDefinition {
        tool_spec: ToolSpec {
            name: SEARCH_AST.into(),
            description: "Search code by AST structure pattern using tree-sitter queries. More precise than text search for finding code patterns regardless of formatting.".into(),
            input_schema: InputSchema {
                json: json!({
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "path": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": MAX_PATH_BYTES,
                            "description": "File to search in (relative path)"
                        },
                        "query": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": MAX_AST_QUERY_BYTES,
                            "description": "Tree-sitter S-expression query pattern"
                        },
                        "language": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": MAX_LANGUAGE_BYTES,
                            "description": "Language: rust, python, javascript, typescript, go, java, c, cpp"
                        }
                    },
                    "required": ["path", "query", "language"]
                }),
            },
        },
    }
}

fn submit_findings_tool() -> ToolDefinition {
    ToolDefinition {
        tool_spec: ToolSpec {
            name: SUBMIT_FINDINGS.into(),
            description: "Submit analysis findings. Call this to report bugs, quality issues, SOLID violations, or vulnerabilities you found. Only the first call is recorded while you explore; the final turn asks you again for every finding that was not recorded yet.".into(),
            input_schema: InputSchema {
                json: json!({
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "findings": {
                            "type": "array",
                            "maxItems": MAX_FINDINGS_PER_SUBMISSION,
                            "items": {
                                "type": "object",
                                "additionalProperties": false,
                                "properties": {
                                    "category": {
                                        "type": "string",
                                        "enum": ["bug", "quality", "solid", "vulnerability"]
                                    },
                                    "severity": {
                                        "type": "string",
                                        "enum": ["critical", "high", "medium", "low", "info"]
                                    },
                                    "title": {"type": "string", "minLength": 1, "maxLength": MAX_FINDING_TITLE_BYTES},
                                    "description": {"type": "string", "minLength": 1, "maxLength": MAX_FINDING_DESCRIPTION_BYTES},
                                    "file": {"type": "string", "minLength": 1, "maxLength": MAX_PATH_BYTES},
                                    "line_start": {"type": "integer", "minimum": 1},
                                    "line_end": {"type": "integer", "minimum": 1},
                                    "code_snippet": {"type": "string", "maxLength": MAX_FINDING_SNIPPET_BYTES},
                                    "suggestion": {"type": "string", "maxLength": MAX_FINDING_SUGGESTION_BYTES},
                                    "rule": {"type": "string", "maxLength": MAX_FINDING_RULE_BYTES},
                                    "confidence": {
                                        "type": "string",
                                        "enum": ["high", "medium", "low"]
                                    }
                                },
                                "required": ["category", "severity", "title", "description", "file"]
                            }
                        }
                    },
                    "required": ["findings"]
                }),
            },
        },
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn tool_config_has_six_tools() {
        let config = build_tool_config();
        assert_eq!(config.tools.len(), 6);
    }

    #[test]
    fn finalization_only_exposes_finding_submission() {
        let config = build_finalization_tool_config();
        assert_eq!(config.tools.len(), 1);
        assert_eq!(config.tools[0].tool_spec.name, SUBMIT_FINDINGS);
    }

    #[test]
    fn all_tools_have_names_and_descriptions() {
        let config = build_tool_config();
        for tool in &config.tools {
            assert!(!tool.tool_spec.name.is_empty());
            assert!(!tool.tool_spec.description.is_empty());
        }
    }

    #[test]
    fn every_tool_schema_is_a_json_object() {
        let config = build_tool_config();
        for tool in &config.tools {
            assert!(
                tool.tool_spec.input_schema.json.is_object(),
                "{} schema must be a JSON object",
                tool.tool_spec.name
            );
        }
    }

    #[test]
    fn every_object_schema_rejects_unknown_properties() {
        for tool in build_tool_config().tools {
            assert_closed_objects(&tool.tool_spec.input_schema.json, &tool.tool_spec.name);
        }
    }

    fn assert_closed_objects(schema: &serde_json::Value, tool_name: &str) {
        if schema["type"] == "object" {
            assert_eq!(
                schema["additionalProperties"], false,
                "{tool_name} contains an open object schema: {schema}"
            );
        }
        if let Some(properties) = schema
            .get("properties")
            .and_then(serde_json::Value::as_object)
        {
            for property in properties.values() {
                assert_closed_objects(property, tool_name);
            }
        }
        if let Some(items) = schema.get("items") {
            assert_closed_objects(items, tool_name);
        }
    }

    #[test]
    fn submit_findings_has_required_fields() {
        let config = build_tool_config();
        let submit = config
            .tools
            .iter()
            .find(|t| t.tool_spec.name == "submit_findings")
            .unwrap();
        let schema = &submit.tool_spec.input_schema.json;
        let required: Vec<&str> = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(required.contains(&"findings"));
    }

    #[test]
    fn tool_names_are_unique() {
        let config = build_tool_config();
        let names: Vec<&str> = config
            .tools
            .iter()
            .map(|t| t.tool_spec.name.as_str())
            .collect();
        let mut unique = names.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(names.len(), unique.len());
    }
}
