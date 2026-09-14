use super::types::{ContentBlock, Message, ToolConfig};
use crate::errors::LlmError;
use crate::shared::ESTIMATED_CHARS_PER_TOKEN;

const COMPACTION_THRESHOLD_PERCENT: u64 = 80;
const MIN_TOOL_RESULT_SIZE_FOR_COMPACTION: usize = 500;
const MAX_TEXT_SIZE_BEFORE_TRUNCATION: usize = 2000;
const TRUNCATED_TEXT_PREVIEW_SIZE: usize = 500;
const PROTECTED_TAIL_MESSAGE_COUNT: usize = 4;
const REQUEST_BUDGET_PERCENT: usize = 75;
const REPO_MAP_BUDGET_PERCENT: usize = 25;
const MIN_USEFUL_CONTENT_BYTES: usize = 512;
const REQUEST_ENVELOPE_BYTES: usize = 512;
const MESSAGE_ENVELOPE_BYTES: usize = 64;
const BLOCK_ENVELOPE_BYTES: usize = 64;
const TOOL_DEFINITION_ENVELOPE_BYTES: usize = 96;
const TRUNCATION_NOTICE: &str = "\n[... truncated to save context ...]";
const COMPACTION_NOTICE: &str =
    "[Content compacted to save context. Call the tool again if needed.]";

pub struct ContextManager {
    max_tokens: u32,
    current_tokens: u32,
}

impl ContextManager {
    pub fn new(max_tokens: u32) -> Self {
        Self {
            max_tokens,
            current_tokens: 0,
        }
    }

    pub fn update_usage(&mut self, input_tokens: u32, output_tokens: u32) {
        self.current_tokens = input_tokens.saturating_add(output_tokens);
    }

    pub fn should_compact(&self, messages: &[Message]) -> bool {
        let threshold = u64::from(self.max_tokens) * COMPACTION_THRESHOLD_PERCENT / 100;
        let local_tokens =
            estimated_message_bytes(messages).div_ceil(ESTIMATED_CHARS_PER_TOKEN) as u64;
        u64::from(self.current_tokens) > threshold || local_tokens > threshold
    }

    pub fn compact_messages(&self, messages: &mut [Message]) {
        if messages.len() <= PROTECTED_TAIL_MESSAGE_COUNT + 1 {
            return;
        }

        let protected_start = 1;
        let protected_end = messages.len().saturating_sub(PROTECTED_TAIL_MESSAGE_COUNT);

        for message in &mut messages[protected_start..protected_end] {
            compact_message(message);
        }
    }

    pub fn bound_complete_request(
        &self,
        messages: &mut [Message],
        system_prompt: &str,
        tool_config: &ToolConfig,
    ) -> Result<(), LlmError> {
        let budget = self.request_budget_bytes();
        let metadata = estimated_request_metadata_bytes(system_prompt, tool_config);
        if metadata > budget {
            return Err(request_budget_error(metadata, budget));
        }
        self.bound_messages(messages, budget - metadata);
        let estimated = estimated_complete_request_bytes(messages, system_prompt, tool_config);
        if estimated > budget {
            return Err(request_budget_error(estimated, budget));
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn bound_next_request(&self, messages: &mut [Message]) {
        self.bound_messages(messages, self.request_budget_bytes());
    }

    fn bound_messages(&self, messages: &mut [Message], budget: usize) {
        let Some((repo_map, exchanges)) = messages.split_first_mut() else {
            return;
        };
        let repo_map_reserve = percent_of(budget, REPO_MAP_BUDGET_PERCENT);
        let mut remaining = budget.saturating_sub(repo_map_reserve);
        for message in exchanges.iter_mut().rev() {
            remaining = remaining.saturating_sub(bound_message(message, remaining));
        }
        bound_message(repo_map, repo_map_reserve.saturating_add(remaining));
    }

    fn request_budget_bytes(&self) -> usize {
        percent_of(
            (self.max_tokens as usize).saturating_mul(ESTIMATED_CHARS_PER_TOKEN),
            REQUEST_BUDGET_PERCENT,
        )
    }
}

fn percent_of(value: usize, percent: usize) -> usize {
    value / 100 * percent
}

fn bound_message(message: &mut Message, limit: usize) -> usize {
    let mut used = MESSAGE_ENVELOPE_BYTES;
    for block in &mut message.content {
        used = used.saturating_add(bound_block(block, limit.saturating_sub(used)));
    }
    used
}

fn bound_block(block: &mut ContentBlock, limit: usize) -> usize {
    let payload_limit = limit.saturating_sub(BLOCK_ENVELOPE_BYTES);
    match block {
        ContentBlock::Text { text } => fit_content(text, payload_limit),
        ContentBlock::ToolResult { tool_result } => {
            let identifier_bytes = serialized_json_string_bytes(&tool_result.tool_use_id);
            fit_content(
                &mut tool_result.content,
                payload_limit.saturating_sub(identifier_bytes),
            );
        }
        ContentBlock::ToolUse { tool_use } => {
            let identity = serialized_json_string_bytes(&tool_use.tool_use_id)
                .saturating_add(serialized_json_string_bytes(&tool_use.name));
            if estimated_tool_input_bytes(&tool_use.input) > payload_limit.saturating_sub(identity)
            {
                tool_use.input = serde_json::Value::Object(serde_json::Map::new());
            }
        }
    }
    BLOCK_ENVELOPE_BYTES.saturating_add(estimated_block_payload_bytes(block))
}

fn fit_content(content: &mut String, limit: usize) {
    if serialized_json_string_bytes(content) <= limit {
        return;
    }
    let notice_bytes = serialized_json_string_bytes(TRUNCATION_NOTICE).saturating_sub(2);
    let useful_limit = MIN_USEFUL_CONTENT_BYTES
        .saturating_add(notice_bytes)
        .saturating_add(2);
    if limit >= useful_limit {
        let prefix_budget = limit.saturating_sub(notice_bytes).saturating_sub(2);
        let keep = find_serialized_prefix(content, prefix_budget);
        content.truncate(keep);
        content.push_str(TRUNCATION_NOTICE);
        return;
    }
    content.clear();
    if serialized_json_string_bytes(COMPACTION_NOTICE) <= limit {
        content.push_str(COMPACTION_NOTICE);
    }
}

fn estimated_message_bytes(messages: &[Message]) -> usize {
    messages.iter().fold(0usize, |total, message| {
        total
            .saturating_add(MESSAGE_ENVELOPE_BYTES)
            .saturating_add(message.content.iter().fold(0usize, |message_total, block| {
                message_total
                    .saturating_add(BLOCK_ENVELOPE_BYTES)
                    .saturating_add(estimated_block_payload_bytes(block))
            }))
    })
}

fn estimated_block_payload_bytes(block: &ContentBlock) -> usize {
    match block {
        ContentBlock::Text { text } => serialized_json_string_bytes(text),
        ContentBlock::ToolResult { tool_result } => {
            serialized_json_string_bytes(&tool_result.tool_use_id)
                .saturating_add(serialized_json_string_bytes(&tool_result.content))
        }
        ContentBlock::ToolUse { tool_use } => serialized_json_string_bytes(&tool_use.tool_use_id)
            .saturating_add(serialized_json_string_bytes(&tool_use.name))
            .saturating_add(estimated_tool_input_bytes(&tool_use.input)),
    }
}

fn estimated_complete_request_bytes(
    messages: &[Message],
    system_prompt: &str,
    tool_config: &ToolConfig,
) -> usize {
    estimated_request_metadata_bytes(system_prompt, tool_config)
        .saturating_add(estimated_message_bytes(messages))
}

fn estimated_request_metadata_bytes(system_prompt: &str, tool_config: &ToolConfig) -> usize {
    let tools = tool_config.tools.iter().fold(0usize, |total, tool| {
        total
            .saturating_add(TOOL_DEFINITION_ENVELOPE_BYTES)
            .saturating_add(serialized_json_string_bytes(&tool.tool_spec.name))
            .saturating_add(serialized_json_string_bytes(&tool.tool_spec.description))
            .saturating_add(estimated_json_bytes(&tool.tool_spec.input_schema.json))
    });
    REQUEST_ENVELOPE_BYTES
        .saturating_add(serialized_json_string_bytes(system_prompt))
        .saturating_add(tools)
        .saturating_add(
            tool_config
                .required_tool
                .as_deref()
                .map_or(0, serialized_json_string_bytes),
        )
}

fn estimated_tool_input_bytes(value: &serde_json::Value) -> usize {
    estimated_json_bytes(value)
        .saturating_mul(2)
        .saturating_add(2)
}

fn estimated_json_bytes(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Null => 4,
        serde_json::Value::Bool(_) => 5,
        serde_json::Value::Number(_) => 24,
        serde_json::Value::String(value) => serialized_json_string_bytes(value),
        serde_json::Value::Array(values) => values.iter().fold(2usize, |total, value| {
            total
                .saturating_add(1)
                .saturating_add(estimated_json_bytes(value))
        }),
        serde_json::Value::Object(values) => values.iter().fold(2usize, |total, (key, value)| {
            total
                .saturating_add(serialized_json_string_bytes(key))
                .saturating_add(1)
                .saturating_add(estimated_json_bytes(value))
        }),
    }
}

fn serialized_json_string_bytes(value: &str) -> usize {
    value.chars().fold(2usize, |total, character| {
        total.saturating_add(serialized_json_character_bytes(character))
    })
}

fn serialized_json_character_bytes(character: char) -> usize {
    match character {
        '"' | '\\' | '\u{8}' | '\t' | '\n' | '\u{c}' | '\r' => 2,
        '\0'..='\u{1f}' => 6,
        _ => character.len_utf8(),
    }
}

fn find_serialized_prefix(value: &str, limit: usize) -> usize {
    let mut used = 0usize;
    let mut end = 0usize;
    for (index, character) in value.char_indices() {
        let next = used.saturating_add(serialized_json_character_bytes(character));
        if next > limit {
            break;
        }
        used = next;
        end = index + character.len_utf8();
    }
    end
}

fn request_budget_error(estimated_bytes: usize, budget_bytes: usize) -> LlmError {
    LlmError::AgentProtocol(format!(
        "model request requires {estimated_bytes} estimated bytes, exceeding the context request budget of {budget_bytes} bytes"
    ))
}

fn compact_message(message: &mut Message) {
    for block in &mut message.content {
        match block {
            ContentBlock::ToolResult { tool_result }
                if tool_result.content.len() > MIN_TOOL_RESULT_SIZE_FOR_COMPACTION =>
            {
                tool_result.content = COMPACTION_NOTICE.into();
            }
            ContentBlock::Text { text } if text.len() > MAX_TEXT_SIZE_BEFORE_TRUNCATION => {
                let truncate_at = find_char_boundary(text, TRUNCATED_TEXT_PREVIEW_SIZE);
                text.truncate(truncate_at);
                text.push_str(TRUNCATION_NOTICE);
            }
            _ => {}
        }
    }
}

fn find_char_boundary(text: &str, target: usize) -> usize {
    if target >= text.len() {
        return text.len();
    }
    let mut boundary = target;
    while boundary > 0 && !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    boundary
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::llm::types::ToolResultBlock;

    #[test]
    fn should_compact_at_80_percent() {
        let mut mgr = ContextManager::new(100_000);
        mgr.update_usage(70_000, 5_000);
        assert!(!mgr.should_compact(&[]));

        mgr.update_usage(75_000, 6_000);
        assert!(mgr.should_compact(&[]));
    }

    #[test]
    fn should_compact_when_local_messages_exceed_the_threshold() {
        let mgr = ContextManager::new(100);
        let messages = vec![Message::user_text(&"x".repeat(321))];

        assert!(mgr.should_compact(&messages));
    }

    #[test]
    fn compact_preserves_first_and_last_messages() {
        let mgr = ContextManager::new(100_000);
        let mut messages = vec![
            Message::user_text("repo map (keep this)"),
            Message::user_text(&"x".repeat(3000)),
            Message::user_text(&"y".repeat(3000)),
            Message::user_text("recent 1"),
            Message::user_text("recent 2"),
            Message::user_text("recent 3"),
            Message::user_text("recent 4"),
        ];

        mgr.compact_messages(&mut messages);

        let first_text = messages[0].content[0].as_text().unwrap();
        assert_eq!(first_text, "repo map (keep this)");

        let compacted = messages[1].content[0].as_text().unwrap();
        assert!(compacted.contains("truncated"));
    }

    #[test]
    fn compact_does_nothing_with_few_messages() {
        let mgr = ContextManager::new(100_000);
        let mut messages = vec![
            Message::user_text("msg1"),
            Message::user_text("msg2"),
            Message::user_text("msg3"),
        ];
        let original_len = messages.len();
        mgr.compact_messages(&mut messages);
        assert_eq!(messages.len(), original_len);
    }

    fn tool_result_message(tool_use_id: &str, content: &str) -> Message {
        Message::user_tool_results(vec![crate::llm::types::ToolResultBlock::success(
            tool_use_id,
            content,
        )])
    }

    fn tool_result_content(message: &Message) -> &str {
        match &message.content[0] {
            ContentBlock::ToolResult { tool_result } => &tool_result.content,
            other => panic!("expected a tool result block, got {other:?}"),
        }
    }

    fn identifier_bytes(messages: &[Message]) -> usize {
        messages
            .iter()
            .flat_map(|message| &message.content)
            .filter_map(|block| match block {
                ContentBlock::ToolResult { tool_result } => Some(tool_result.tool_use_id.len()),
                _ => None,
            })
            .sum()
    }

    #[test]
    fn bounds_an_oversized_recent_tool_result_to_the_request_budget() {
        let manager = ContextManager::new(8_000);
        let mut messages = vec![
            Message::user_text("repo map"),
            tool_result_message("call-1", &"x".repeat(4 * 1024 * 1024)),
        ];

        manager.bound_next_request(&mut messages);

        let bounded = estimated_message_bytes(&messages);
        assert!(
            bounded <= manager.request_budget_bytes(),
            "next request is {bounded} bytes against a {} byte budget",
            manager.request_budget_bytes()
        );
        assert!(tool_result_content(&messages[1]).ends_with(TRUNCATION_NOTICE));
        assert_eq!(messages[0].content[0].as_text().unwrap(), "repo map");
    }

    fn assistant_tool_call(name: &str, input: serde_json::Value) -> Message {
        Message {
            role: crate::llm::types::Role::Assistant,
            content: vec![ContentBlock::ToolUse {
                tool_use: crate::llm::types::ToolUseBlock {
                    tool_use_id: "call-1".into(),
                    name: name.to_string(),
                    input,
                },
            }],
        }
    }

    fn tool_call_input(message: &Message) -> &serde_json::Value {
        match &message.content[0] {
            ContentBlock::ToolUse { tool_use } => &tool_use.input,
            other => panic!("expected a tool use block, got {other:?}"),
        }
    }

    #[test]
    fn compacts_a_tool_call_input_that_cannot_be_truncated() {
        let manager = ContextManager::new(1_000);
        let bloated = serde_json::json!({ "findings": "z".repeat(64 * 1024) });
        let mut messages = vec![
            Message::user_text("repo map"),
            assistant_tool_call("submit_findings", bloated),
        ];

        manager.bound_next_request(&mut messages);

        assert_eq!(tool_call_input(&messages[1]), &serde_json::json!({}));
        let bounded = estimated_message_bytes(&messages);
        assert!(bounded <= manager.request_budget_bytes(), "{bounded} bytes");
    }

    #[test]
    fn keeps_a_tool_call_input_that_fits_the_remaining_budget() {
        let manager = ContextManager::new(8_000);
        let input = serde_json::json!({ "path": "src/main.rs" });
        let mut messages = vec![
            Message::user_text("repo map"),
            assistant_tool_call("read_file", input.clone()),
        ];

        manager.bound_next_request(&mut messages);

        assert_eq!(tool_call_input(&messages[1]), &input);
    }

    #[test]
    fn the_first_request_keeps_the_whole_repo_map() {
        let manager = ContextManager::new(4_000);
        let map = "src/main.rs\n".repeat(400);
        let mut messages = vec![Message::user_text(&map)];

        manager.bound_next_request(&mut messages);

        assert_eq!(messages[0].content[0].as_text().unwrap(), map);
    }

    #[test]
    fn bounds_every_recent_result_against_what_the_window_leaves() {
        let manager = ContextManager::new(4_000);
        let oversized = "y".repeat(64 * 1024);
        let mut messages = vec![
            Message::user_text("repo map"),
            tool_result_message("call-1", &oversized),
            tool_result_message("call-2", &oversized),
            tool_result_message("call-3", &oversized),
        ];

        manager.bound_next_request(&mut messages);

        let bounded = estimated_message_bytes(&messages);
        assert!(
            bounded <= manager.request_budget_bytes() + identifier_bytes(&messages),
            "next request is {bounded} bytes against a {} byte budget",
            manager.request_budget_bytes()
        );
        assert!(
            tool_result_content(&messages[3]).len() > tool_result_content(&messages[1]).len(),
            "the newest result must keep the most context"
        );
        assert!(tool_result_content(&messages[1]).len() <= COMPACTION_NOTICE.len());
    }

    #[test]
    fn replaces_a_result_that_no_longer_fits_with_the_compaction_notice() {
        let manager = ContextManager::new(200);
        let mut messages = vec![
            Message::user_text("repo map"),
            tool_result_message("call-1", &"y".repeat(8 * 1024)),
            tool_result_message("call-2", &"z".repeat(100)),
        ];

        manager.bound_next_request(&mut messages);

        assert_eq!(tool_result_content(&messages[2]).len(), 100);
        assert_eq!(tool_result_content(&messages[1]), COMPACTION_NOTICE);
    }

    #[test]
    fn bounding_the_request_twice_changes_nothing_more() {
        let manager = ContextManager::new(8_000);
        let mut messages = vec![
            Message::user_text("repo map"),
            tool_result_message("call-1", &"x".repeat(1024 * 1024)),
            Message::user_text(&"prose ".repeat(4_000)),
        ];

        manager.bound_next_request(&mut messages);
        let after_first_pass = messages.clone();
        manager.bound_next_request(&mut messages);

        assert_eq!(messages, after_first_pass);
    }

    #[test]
    fn bounding_an_empty_conversation_does_nothing() {
        let manager = ContextManager::new(8_000);
        let mut messages: Vec<Message> = Vec::new();

        manager.bound_next_request(&mut messages);

        assert!(messages.is_empty());
    }

    #[test]
    fn system_prompt_bytes_reduce_the_available_conversation_budget() {
        let manager = ContextManager::new(2_000);
        let system_prompt = "s".repeat(4_000);
        let tools = crate::llm::types::ToolConfig {
            tools: Vec::new(),
            required_tool: None,
        };
        let mut messages = vec![
            Message::user_text("repo map"),
            Message::user_text(&"x".repeat(16 * 1024)),
        ];

        manager
            .bound_complete_request(&mut messages, &system_prompt, &tools)
            .unwrap();

        let estimated = estimated_complete_request_bytes(&messages, &system_prompt, &tools);
        assert!(estimated <= manager.request_budget_bytes());
        assert!(messages[1].content[0].as_text().unwrap().len() < 16 * 1024);
    }

    #[test]
    fn oversized_tool_definitions_are_rejected_before_a_model_request() {
        let manager = ContextManager::new(100);
        let tools = crate::llm::types::ToolConfig {
            tools: vec![crate::llm::types::ToolDefinition {
                tool_spec: crate::llm::types::ToolSpec {
                    name: "oversized".to_string(),
                    description: "x".repeat(1_000),
                    input_schema: crate::llm::types::InputSchema {
                        json: serde_json::json!({"type": "object"}),
                    },
                },
            }],
            required_tool: Some("oversized".to_string()),
        };
        let mut messages = vec![Message::user_text("repo map")];

        let error = manager
            .bound_complete_request(&mut messages, "", &tools)
            .unwrap_err();

        assert!(error.to_string().contains("context request budget"));
    }

    #[test]
    fn a_conversation_of_irreducible_turns_is_rejected_after_bounding() {
        let manager = ContextManager::new(1_000);
        let tools = crate::llm::types::ToolConfig {
            tools: Vec::new(),
            required_tool: None,
        };
        let budget = manager.request_budget_bytes();
        let metadata = estimated_request_metadata_bytes("", &tools);
        let irreducible_bytes_per_turn =
            MESSAGE_ENVELOPE_BYTES + BLOCK_ENVELOPE_BYTES + serialized_json_string_bytes("");
        let turns = (budget - metadata) / irreducible_bytes_per_turn + 2;
        let mut messages: Vec<Message> = (0..turns).map(|_| Message::user_text("hi")).collect();
        assert!(
            metadata <= budget,
            "the metadata guard must let this request through to bounding"
        );

        let error = manager
            .bound_complete_request(&mut messages, "", &tools)
            .unwrap_err();

        assert_eq!(
            messages.len(),
            turns,
            "bounding shrinks payloads but never drops a turn"
        );
        assert!(
            messages
                .iter()
                .any(|message| message.content[0].as_text().unwrap().is_empty()),
            "bounding must strip every payload it can before rejecting"
        );
        let estimated = estimated_complete_request_bytes(&messages, "", &tools);
        assert!(
            estimated >= metadata + turns * irreducible_bytes_per_turn,
            "{estimated} bytes cannot drop below the envelope floor of {turns} turns"
        );
        assert!(
            estimated > budget,
            "{estimated} bytes against a {budget} byte budget"
        );
        assert_eq!(
            error.to_string(),
            request_budget_error(estimated, budget).to_string(),
            "the rejection must report the bounded request size, not the metadata size"
        );
    }

    #[test]
    fn json_estimation_covers_every_value_shape() {
        let value = serde_json::json!({
            "null": null,
            "boolean": true,
            "number": 42,
            "string": "value",
            "array": [false, 7]
        });

        assert!(estimated_json_bytes(&value) > 0);
    }

    #[test]
    fn compaction_replaces_large_tool_results_and_preserves_small_blocks() {
        let mut message = Message::user_tool_results(vec![
            ToolResultBlock::success(
                "large",
                &"x".repeat(MIN_TOOL_RESULT_SIZE_FOR_COMPACTION + 1),
            ),
            ToolResultBlock::success("small", "kept"),
        ]);

        compact_message(&mut message);

        let contents: Vec<_> = message
            .content
            .iter()
            .filter_map(|block| match block {
                ContentBlock::ToolResult { tool_result } => Some(tool_result.content.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(contents, vec![COMPACTION_NOTICE, "kept"]);
    }

    #[test]
    fn character_boundary_search_handles_short_and_multibyte_text() {
        assert_eq!(find_char_boundary("short", 10), 5);
        assert_eq!(find_char_boundary("aé", 2), 1);
    }
}
