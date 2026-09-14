mod openai;
mod sse;

pub use openai::*;
pub use sse::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub role: Role,
    pub content: Vec<ContentBlock>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    User,
    Assistant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentBlock {
    Text { text: String },
    ToolUse { tool_use: ToolUseBlock },
    ToolResult { tool_result: ToolResultBlock },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolUseBlock {
    pub tool_use_id: String,
    pub name: String,
    pub input: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolResultBlock {
    pub tool_use_id: String,
    pub content: String,
    pub status: Option<ToolResultStatus>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolResultStatus {
    Success,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    EndTurn,
    ToolUse,
    MaxTokens,
}

#[derive(Debug, Clone)]
pub struct LlmResponse {
    pub output: LlmOutput,
    pub stop_reason: StopReason,
    pub usage: TokenUsage,
}

#[derive(Debug, Clone)]
pub struct LlmOutput {
    pub message: Message,
}

#[derive(Debug, Clone, Default)]
pub struct TokenUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
}

#[derive(Debug, Clone)]
pub struct ToolConfig {
    pub tools: Vec<ToolDefinition>,
    pub required_tool: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ToolDefinition {
    pub tool_spec: ToolSpec,
}

#[derive(Debug, Clone)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub input_schema: InputSchema,
}

#[derive(Debug, Clone)]
pub struct InputSchema {
    pub json: serde_json::Value,
}

impl Message {
    pub fn user_text(text: &str) -> Self {
        Self {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: text.to_string(),
            }],
        }
    }

    pub fn user_tool_results(results: Vec<ToolResultBlock>) -> Self {
        Self {
            role: Role::User,
            content: results
                .into_iter()
                .map(|r| ContentBlock::ToolResult { tool_result: r })
                .collect(),
        }
    }
}

impl ContentBlock {
    #[cfg(test)]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            ContentBlock::Text { text } => Some(text),
            _ => None,
        }
    }

    pub fn as_tool_use(&self) -> Option<&ToolUseBlock> {
        match self {
            ContentBlock::ToolUse { tool_use } => Some(tool_use),
            _ => None,
        }
    }
}

impl ToolResultBlock {
    pub fn success(tool_use_id: &str, content: &str) -> Self {
        Self {
            tool_use_id: tool_use_id.to_string(),
            content: content.to_string(),
            status: Some(ToolResultStatus::Success),
        }
    }

    pub fn error(tool_use_id: &str, message: &str) -> Self {
        Self {
            tool_use_id: tool_use_id.to_string(),
            content: message.to_string(),
            status: Some(ToolResultStatus::Error),
        }
    }
}
