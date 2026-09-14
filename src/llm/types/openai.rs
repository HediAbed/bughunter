use serde::{Deserialize, Serialize};

use super::{ContentBlock, Message, Role, ToolConfig};

#[derive(Debug, Serialize)]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ChatTool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<ChatToolChoice>,
    pub max_tokens: u32,
    pub temperature: f32,
    pub stream: bool,
    pub stream_options: StreamOptions,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct StreamOptions {
    pub include_usage: bool,
}

#[derive(Debug, Serialize)]
pub struct ChatTool {
    #[serde(rename = "type")]
    pub kind: String,
    pub function: ChatFunctionDef,
}

#[derive(Debug, Serialize)]
pub struct ChatToolChoice {
    #[serde(rename = "type")]
    kind: String,
    function: ChatFunctionChoice,
}

impl ChatToolChoice {
    fn required(function_name: &str) -> Self {
        Self {
            kind: function_call_type(),
            function: ChatFunctionChoice {
                name: function_name.to_string(),
            },
        }
    }
}

#[derive(Debug, Serialize)]
struct ChatFunctionChoice {
    name: String,
}

#[derive(Debug, Serialize)]
pub struct ChatFunctionDef {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct ChatMessage {
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ChatToolCall>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChatToolCall {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub function: ChatFunctionCall,
}

fn function_call_type() -> String {
    "function".to_string()
}

#[derive(Debug, Clone, Serialize)]
pub struct ChatFunctionCall {
    pub name: String,
    pub arguments: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct ChatUsage {
    #[serde(default)]
    pub prompt_tokens: u32,
    #[serde(default)]
    pub completion_tokens: u32,
}

impl ChatCompletionRequest {
    pub fn build(
        model: &str,
        max_tokens: u32,
        temperature: f32,
        reasoning_effort: Option<String>,
        system_prompt: &str,
        messages: &[Message],
        tool_config: &ToolConfig,
    ) -> Self {
        Self {
            model: model.to_string(),
            messages: to_chat_messages(system_prompt, messages),
            tools: to_chat_tools(tool_config),
            tool_choice: tool_config
                .required_tool
                .as_deref()
                .map(ChatToolChoice::required),
            max_tokens,
            temperature,
            stream: true,
            stream_options: StreamOptions {
                include_usage: true,
            },
            reasoning_effort,
        }
    }
}

fn to_chat_tools(tool_config: &ToolConfig) -> Vec<ChatTool> {
    tool_config
        .tools
        .iter()
        .map(|t| ChatTool {
            kind: function_call_type(),
            function: ChatFunctionDef {
                name: t.tool_spec.name.clone(),
                description: t.tool_spec.description.clone(),
                parameters: t.tool_spec.input_schema.json.clone(),
            },
        })
        .collect()
}

fn to_chat_messages(system_prompt: &str, messages: &[Message]) -> Vec<ChatMessage> {
    let mut wire = Vec::with_capacity(messages.len() + 1);
    wire.push(ChatMessage {
        role: "system".to_string(),
        content: Some(system_prompt.to_string()),
        tool_calls: Vec::new(),
        tool_call_id: None,
    });

    for message in messages {
        match message.role {
            Role::User => append_user_message(&mut wire, message),
            Role::Assistant => wire.push(assistant_message(message)),
        }
    }

    wire
}

fn append_user_message(wire: &mut Vec<ChatMessage>, message: &Message) {
    let mut text = String::new();
    for block in &message.content {
        match block {
            ContentBlock::Text { text: t } => {
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(t);
            }
            ContentBlock::ToolResult { tool_result } => {
                wire.push(ChatMessage {
                    role: "tool".to_string(),
                    content: Some(tool_result.content.clone()),
                    tool_calls: Vec::new(),
                    tool_call_id: Some(tool_result.tool_use_id.clone()),
                });
            }
            ContentBlock::ToolUse { .. } => {}
        }
    }

    if !text.is_empty() {
        wire.push(ChatMessage {
            role: "user".to_string(),
            content: Some(text),
            tool_calls: Vec::new(),
            tool_call_id: None,
        });
    }
}

fn assistant_message(message: &Message) -> ChatMessage {
    let mut text = String::new();
    let mut tool_calls = Vec::new();

    for block in &message.content {
        match block {
            ContentBlock::Text { text: t } => {
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(t);
            }
            ContentBlock::ToolUse { tool_use } => tool_calls.push(ChatToolCall {
                id: tool_use.tool_use_id.clone(),
                kind: function_call_type(),
                function: ChatFunctionCall {
                    name: tool_use.name.clone(),
                    arguments: tool_use.input.to_string(),
                },
            }),
            ContentBlock::ToolResult { .. } => {}
        }
    }

    ChatMessage {
        role: "assistant".to_string(),
        content: (!text.is_empty()).then_some(text),
        tool_calls,
        tool_call_id: None,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::llm::types::{InputSchema, ToolDefinition, ToolResultBlock, ToolSpec, ToolUseBlock};
    use serde_json::json;

    #[test]
    fn request_serializes_system_and_user_messages() {
        let request = ChatCompletionRequest::build(
            "test-model",
            8192,
            0.0,
            None,
            "You are a reviewer",
            &[Message::user_text("analyze this")],
            &ToolConfig {
                tools: vec![],
                required_tool: None,
            },
        );
        let value = serde_json::to_value(&request).unwrap();

        assert_eq!(value["model"], "test-model");
        assert_eq!(value["messages"][0]["role"], "system");
        assert_eq!(value["messages"][0]["content"], "You are a reviewer");
        assert_eq!(value["messages"][1]["role"], "user");
        assert_eq!(value["messages"][1]["content"], "analyze this");
        assert_eq!(value["max_tokens"], 8192);
        assert!(value.get("tools").is_none());
        assert!(value.get("reasoning_effort").is_none());
    }

    #[test]
    fn request_includes_reasoning_effort_when_set() {
        let request = ChatCompletionRequest::build(
            "test-model",
            8192,
            0.0,
            Some("high".to_string()),
            "sys",
            &[Message::user_text("hi")],
            &ToolConfig {
                tools: vec![],
                required_tool: None,
            },
        );
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["reasoning_effort"], "high");
    }

    #[test]
    fn finalization_request_requires_tool_use() {
        let config = crate::llm::tools::build_finalization_tool_config();
        let request = ChatCompletionRequest::build(
            "test-model",
            8192,
            0.0,
            None,
            "sys",
            &[Message::user_text("finalize")],
            &config,
        );
        let value = serde_json::to_value(&request).unwrap();

        assert_eq!(value["tool_choice"]["type"], "function");
        assert_eq!(value["tool_choice"]["function"]["name"], "submit_findings");
        assert_eq!(value["tools"].as_array().unwrap().len(), 1);
        assert_eq!(value["tools"][0]["function"]["name"], "submit_findings");
    }

    #[test]
    fn tool_definitions_map_to_function_wire_shape() {
        let config = ToolConfig {
            tools: vec![ToolDefinition {
                tool_spec: ToolSpec {
                    name: "read_file".into(),
                    description: "reads a file".into(),
                    input_schema: InputSchema {
                        json: json!({"type": "object"}),
                    },
                },
            }],
            required_tool: None,
        };
        let tools = to_chat_tools(&config);
        let value = serde_json::to_value(&tools[0]).unwrap();

        assert_eq!(value["type"], "function");
        assert_eq!(value["function"]["name"], "read_file");
        assert_eq!(value["function"]["description"], "reads a file");
        assert_eq!(value["function"]["parameters"]["type"], "object");
    }

    #[test]
    fn assistant_tool_use_and_tool_results_round_trip_to_wire() {
        let messages = vec![
            Message {
                role: Role::Assistant,
                content: vec![ContentBlock::ToolUse {
                    tool_use: ToolUseBlock {
                        tool_use_id: "call_1".into(),
                        name: "read_file".into(),
                        input: json!({"path": "src/main.rs"}),
                    },
                }],
            },
            Message::user_tool_results(vec![ToolResultBlock::success("call_1", "fn main() {}")]),
        ];
        let wire = to_chat_messages("sys", &messages);

        assert_eq!(wire[0].role, "system");
        assert_eq!(wire[1].role, "assistant");
        assert_eq!(wire[1].tool_calls[0].id, "call_1");
        assert_eq!(wire[1].tool_calls[0].function.name, "read_file");
        assert_eq!(
            wire[1].tool_calls[0].function.arguments,
            json!({"path": "src/main.rs"}).to_string()
        );
        assert_eq!(wire[2].role, "tool");
        assert_eq!(wire[2].tool_call_id.as_deref(), Some("call_1"));
        assert_eq!(wire[2].content.as_deref(), Some("fn main() {}"));
    }

    #[test]
    fn request_includes_configured_temperature() {
        let request = ChatCompletionRequest::build(
            "test-model",
            8192,
            0.5,
            None,
            "sys",
            &[Message::user_text("hi")],
            &ToolConfig {
                tools: vec![],
                required_tool: None,
            },
        );
        let value = serde_json::to_value(&request).unwrap();

        assert_eq!(value["temperature"], 0.5);
        assert_eq!(value["stream"], true);
        assert_eq!(value["stream_options"]["include_usage"], true);
    }

    #[test]
    fn wire_mapping_joins_text_and_ignores_blocks_invalid_for_the_message_role() {
        let user = Message {
            role: Role::User,
            content: vec![
                ContentBlock::Text { text: "one".into() },
                ContentBlock::Text { text: "two".into() },
                ContentBlock::ToolUse {
                    tool_use: ToolUseBlock {
                        tool_use_id: "ignored".into(),
                        name: "ignored".into(),
                        input: json!({}),
                    },
                },
            ],
        };
        let assistant = Message {
            role: Role::Assistant,
            content: vec![
                ContentBlock::Text {
                    text: "three".into(),
                },
                ContentBlock::Text {
                    text: "four".into(),
                },
                ContentBlock::ToolResult {
                    tool_result: ToolResultBlock::success("ignored", "ignored"),
                },
            ],
        };

        let wire = to_chat_messages("system", &[user, assistant]);

        assert_eq!(wire[1].content.as_deref(), Some("one\ntwo"));
        assert_eq!(wire[2].content.as_deref(), Some("three\nfour"));
        assert!(wire[2].tool_calls.is_empty());
    }
}
