use serde::Deserialize;
use tracing::warn;

use super::openai::ChatUsage;
use super::{
    ContentBlock, LlmOutput, LlmResponse, Message, Role, StopReason, TokenUsage, ToolUseBlock,
};

const SSE_DATA_PREFIX: &str = "data:";
const SSE_DONE_MARKER: &str = "[DONE]";
const SSE_LINE_FEED: u8 = b'\n';

pub const MAX_STREAM_AGGREGATE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_TOOL_ARGUMENT_BYTES: usize = 1024 * 1024;
pub const MAX_TOOL_ARGUMENT_AGGREGATE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamLimit {
    Stream,
    ToolArguments,
    ToolArgumentAggregate,
}

impl StreamLimit {
    pub const fn bytes(self) -> usize {
        match self {
            Self::Stream => MAX_STREAM_AGGREGATE_BYTES,
            Self::ToolArguments => MAX_TOOL_ARGUMENT_BYTES,
            Self::ToolArgumentAggregate => MAX_TOOL_ARGUMENT_AGGREGATE_BYTES,
        }
    }

    pub const fn resource(self) -> &'static str {
        match self {
            Self::Stream => "streamed response",
            Self::ToolArguments => "single tool call arguments",
            Self::ToolArgumentAggregate => "combined tool call arguments",
        }
    }
}

#[derive(Debug, Deserialize)]
struct ChatCompletionChunk {
    #[serde(default)]
    choices: Vec<ChatChunkChoice>,
    #[serde(default)]
    usage: Option<ChatUsage>,
}

#[derive(Debug, Deserialize)]
struct ChatChunkChoice {
    #[serde(default)]
    delta: ChatDelta,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ChatDelta {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Vec<ChatToolCallDelta>,
}

#[derive(Debug, Deserialize)]
struct ChatToolCallDelta {
    #[serde(default)]
    index: Option<usize>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    function: Option<ChatFunctionCallDelta>,
}

#[derive(Debug, Default, Deserialize)]
struct ChatFunctionCallDelta {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    arguments: Option<String>,
}

#[derive(Default)]
struct PartialToolCall {
    id: String,
    name: String,
    arguments: String,
}

#[derive(Default)]
pub struct StreamAccumulator {
    pending: Vec<u8>,
    content: String,
    tool_calls: std::collections::BTreeMap<usize, PartialToolCall>,
    last_tool_index: Option<usize>,
    finish_reason: Option<String>,
    saw_done_marker: bool,
    malformed_data: bool,
    exhausted: Option<StreamLimit>,
    stream_bytes: usize,
    argument_bytes: usize,
    usage: TokenUsage,
}

impl StreamAccumulator {
    pub fn ingest_bytes(&mut self, bytes: &[u8]) -> bool {
        if !self.admit_stream_bytes(bytes.len()) {
            self.pending.clear();
            return true;
        }
        let mut buffer = std::mem::take(&mut self.pending);
        buffer.extend_from_slice(bytes);
        let mut consumed = 0;
        let mut stop = false;
        while let Some(offset) = buffer[consumed..]
            .iter()
            .position(|byte| *byte == SSE_LINE_FEED)
        {
            let line_end = consumed + offset + 1;
            stop = self.consume_frame_line(&buffer[consumed..line_end]);
            consumed = line_end;
            if stop {
                break;
            }
        }
        if stop {
            buffer.clear();
        } else {
            buffer.drain(..consumed);
        }
        self.pending = buffer;
        stop
    }

    pub fn finish(&mut self) {
        if self.exhausted.is_some() || self.pending.is_empty() {
            return;
        }
        let line = std::mem::take(&mut self.pending);
        self.consume_frame_line(&line);
    }
    fn consume_frame_line(&mut self, line: &[u8]) -> bool {
        let Ok(line) = std::str::from_utf8(line) else {
            self.malformed_data = true;
            return false;
        };
        self.consume_line(line)
    }

    pub fn is_complete(&self) -> bool {
        self.saw_done_marker || self.finish_reason.is_some()
    }

    pub fn has_malformed_data(&self) -> bool {
        self.malformed_data
    }

    pub fn exhausted_limit(&self) -> Option<StreamLimit> {
        self.exhausted
    }

    fn admit_stream_bytes(&mut self, bytes: usize) -> bool {
        let total = self.stream_bytes.saturating_add(bytes);
        if total > MAX_STREAM_AGGREGATE_BYTES {
            self.exhaust(StreamLimit::Stream);
            return false;
        }
        self.stream_bytes = total;
        true
    }

    fn admit_argument_bytes(&mut self, index: usize, bytes: usize) -> bool {
        let retained = self
            .tool_calls
            .get(&index)
            .map_or(0, |slot| slot.arguments.len());
        if retained.saturating_add(bytes) > MAX_TOOL_ARGUMENT_BYTES {
            self.exhaust(StreamLimit::ToolArguments);
            return false;
        }
        let total = self.argument_bytes.saturating_add(bytes);
        if total > MAX_TOOL_ARGUMENT_AGGREGATE_BYTES {
            self.exhaust(StreamLimit::ToolArgumentAggregate);
            return false;
        }
        self.argument_bytes = total;
        true
    }

    fn exhaust(&mut self, limit: StreamLimit) {
        if self.exhausted.is_some() {
            return;
        }
        warn!(
            resource = limit.resource(),
            limit_bytes = limit.bytes(),
            "streamed model response exhausted a hard limit"
        );
        self.exhausted = Some(limit);
    }

    fn consume_line(&mut self, line: &str) -> bool {
        let Some(payload) = line.trim().strip_prefix(SSE_DATA_PREFIX) else {
            return false;
        };
        let payload = payload.trim();
        if payload == SSE_DONE_MARKER {
            self.saw_done_marker = true;
            return true;
        }
        if payload.is_empty() {
            return false;
        }
        match serde_json::from_str::<ChatCompletionChunk>(payload) {
            Ok(chunk) => self.ingest(chunk),
            Err(_) => self.malformed_data = true,
        }
        self.exhausted.is_some()
    }

    fn ingest(&mut self, chunk: ChatCompletionChunk) {
        if let Some(usage) = chunk.usage {
            self.usage = TokenUsage {
                input_tokens: usage.prompt_tokens,
                output_tokens: usage.completion_tokens,
            };
        }
        for choice in chunk.choices {
            if let Some(reason) = choice.finish_reason {
                self.finish_reason = Some(reason);
            }
            if let Some(text) = choice.delta.content {
                self.content.push_str(&text);
            }
            for fragment in choice.delta.tool_calls {
                self.merge_tool_call(fragment);
            }
        }
    }

    fn merge_tool_call(&mut self, fragment: ChatToolCallDelta) {
        let index = self.slot_for(&fragment);
        self.last_tool_index = Some(index);
        let function = fragment.function.unwrap_or_default();
        let arguments = function.arguments.unwrap_or_default();
        if !self.admit_argument_bytes(index, arguments.len()) {
            return;
        }
        let slot = self.tool_calls.entry(index).or_default();
        if let Some(id) = fragment.id.filter(|id| !id.is_empty()) {
            slot.id = id;
        }
        if let Some(name) = function.name.filter(|name| !name.is_empty()) {
            slot.name = name;
        }
        slot.arguments.push_str(&arguments);
    }

    fn slot_for(&self, fragment: &ChatToolCallDelta) -> usize {
        if let Some(index) = fragment.index {
            return index;
        }
        let starts_new_call = fragment
            .function
            .as_ref()
            .and_then(|f| f.name.as_deref())
            .is_some_and(|name| !name.is_empty());
        match self.last_tool_index {
            Some(last) if !starts_new_call => last,
            _ => self.tool_calls.keys().next_back().map_or(0, |max| max + 1),
        }
    }

    pub fn into_response(self) -> Option<LlmResponse> {
        let has_tool_calls = !self.tool_calls.is_empty();
        if self.content.is_empty() && !has_tool_calls && self.finish_reason.is_none() {
            return None;
        }

        let mut content = Vec::new();
        if !self.content.is_empty() {
            content.push(ContentBlock::Text { text: self.content });
        }
        for call in self.tool_calls.into_values() {
            content.push(ContentBlock::ToolUse {
                tool_use: ToolUseBlock {
                    tool_use_id: call.id,
                    name: call.name,
                    input: parse_arguments(&call.arguments),
                },
            });
        }

        let stop_reason = map_finish_reason(&self.finish_reason, !has_tool_calls);
        Some(LlmResponse {
            output: LlmOutput {
                message: Message {
                    role: Role::Assistant,
                    content,
                },
            },
            stop_reason,
            usage: self.usage,
        })
    }
}

fn parse_arguments(arguments: &str) -> serde_json::Value {
    if arguments.trim().is_empty() {
        return serde_json::json!({});
    }
    serde_json::from_str(arguments).unwrap_or_else(|_| serde_json::json!({}))
}

fn map_finish_reason(finish_reason: &Option<String>, no_tool_calls: bool) -> StopReason {
    if !no_tool_calls {
        return StopReason::ToolUse;
    }
    match finish_reason.as_deref() {
        Some("tool_calls") => StopReason::ToolUse,
        Some("length") => StopReason::MaxTokens,
        _ => StopReason::EndTurn,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use serde_json::json;

    fn reassemble(sse: &str) -> LlmResponse {
        let mut accumulator = StreamAccumulator::default();
        for byte in sse.as_bytes() {
            if accumulator.ingest_bytes(&[*byte]) {
                break;
            }
        }
        accumulator.finish();
        accumulator
            .into_response()
            .expect("stream produced a response")
    }

    #[test]
    fn stream_reassembles_content_tool_call_and_usage() {
        let sse = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Let me \"},\"finish_reason\":null}]}\n",
            "\n",
            "data:{\"choices\":[{\"index\":0,\"delta\":{\"content\":\"check.\"},\"finish_reason\":null}]}\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_xyz\",\"type\":\"function\",\"function\":{\"name\":\"read_file\",\"arguments\":\"\"}}]},\"finish_reason\":null}]}\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"path\\\": \\\"\"}}]},\"finish_reason\":null}]}\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"src/main.rs\\\"}\"}}]},\"finish_reason\":null}]}\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":42,\"completion_tokens\":18}}\n",
            "data: [DONE]\n",
        );

        let response = reassemble(sse);

        assert_eq!(response.stop_reason, StopReason::ToolUse);
        assert_eq!(response.usage.input_tokens, 42);
        assert_eq!(response.usage.output_tokens, 18);
        assert_eq!(
            response.output.message.content[0].as_text(),
            Some("Let me check.")
        );
        let tool = response.output.message.content[1].as_tool_use().unwrap();
        assert_eq!(tool.name, "read_file");
        assert_eq!(tool.tool_use_id, "call_xyz");
        assert_eq!(tool.input["path"], "src/main.rs");
    }

    #[test]
    fn stream_plain_text_maps_to_end_turn() {
        let sse = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"nothing to report\"},\"finish_reason\":null}]}\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n",
            "data: [DONE]\n",
        );

        let response = reassemble(sse);

        assert_eq!(response.stop_reason, StopReason::EndTurn);
        assert_eq!(
            response.output.message.content[0].as_text(),
            Some("nothing to report")
        );
    }

    #[test]
    fn stream_stops_reading_after_done_marker() {
        let mut accumulator = StreamAccumulator::default();
        assert!(
            !accumulator.ingest_bytes(
                b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n"
            )
        );
        assert!(accumulator.ingest_bytes(b"data: [DONE]\n"));
    }

    #[test]
    fn stream_without_output_yields_no_response() {
        let mut accumulator = StreamAccumulator::default();
        assert!(!accumulator.ingest_bytes(b"\n"));
        assert!(!accumulator.ingest_bytes(b": keep-alive comment\n"));
        assert!(!accumulator.ingest_bytes(b"event: message\n"));
        assert!(accumulator.into_response().is_none());
    }

    #[test]
    fn stream_reassembles_line_and_multibyte_char_split_across_chunks() {
        let line = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"café\"},\"finish_reason\":\"stop\"}]}\n";
        let bytes = line.as_bytes();
        let accent_start = line.find('é').unwrap();

        let mut accumulator = StreamAccumulator::default();
        accumulator.ingest_bytes(&bytes[..accent_start + 1]);
        accumulator.ingest_bytes(&bytes[accent_start + 1..]);
        accumulator.finish();

        let response = accumulator.into_response().unwrap();
        assert_eq!(response.output.message.content[0].as_text(), Some("café"));
    }

    #[test]
    fn stream_reassembles_two_parallel_tool_calls_by_index() {
        let sse = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_a\",\"function\":{\"name\":\"read_file\",\"arguments\":\"{\\\"p\\\":1}\"}}]}}]}\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":1,\"id\":\"call_b\",\"function\":{\"name\":\"list_dir\",\"arguments\":\"{\\\"p\\\":2}\"}}]}}]}\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n",
            "data: [DONE]\n",
        );

        let response = reassemble(sse);

        let first = response.output.message.content[0].as_tool_use().unwrap();
        let second = response.output.message.content[1].as_tool_use().unwrap();
        assert_eq!(first.tool_use_id, "call_a");
        assert_eq!(first.name, "read_file");
        assert_eq!(first.input["p"], 1);
        assert_eq!(second.tool_use_id, "call_b");
        assert_eq!(second.name, "list_dir");
        assert_eq!(second.input["p"], 2);
    }

    #[test]
    fn stream_allocates_new_slot_when_index_omitted() {
        let sse = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"id\":\"call_a\",\"function\":{\"name\":\"read_file\",\"arguments\":\"{}\"}}]}}]}\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"id\":\"call_b\",\"function\":{\"name\":\"list_dir\",\"arguments\":\"{}\"}}]}}]}\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n",
            "data: [DONE]\n",
        );

        let response = reassemble(sse);

        assert_eq!(response.output.message.content.len(), 2);
        assert_eq!(
            response.output.message.content[0]
                .as_tool_use()
                .unwrap()
                .name,
            "read_file"
        );
        assert_eq!(
            response.output.message.content[1]
                .as_tool_use()
                .unwrap()
                .name,
            "list_dir"
        );
    }

    #[test]
    fn length_finish_reason_maps_to_max_tokens() {
        assert_eq!(
            map_finish_reason(&Some("length".into()), true),
            StopReason::MaxTokens
        );
    }

    #[test]
    fn tool_calls_force_tool_use_even_without_matching_finish_reason() {
        assert_eq!(
            map_finish_reason(&Some("stop".into()), false),
            StopReason::ToolUse
        );
    }

    #[test]
    fn empty_arguments_parse_to_empty_object() {
        assert_eq!(parse_arguments(""), json!({}));
        assert_eq!(parse_arguments("  "), json!({}));
        assert_eq!(parse_arguments("{\"a\":1}"), json!({"a": 1}));
    }

    #[test]
    fn finish_consumes_a_final_line_without_a_line_feed() {
        let mut accumulator = StreamAccumulator::default();
        assert!(
            !accumulator.ingest_bytes(
                b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"tail\"}}]}"
            )
        );

        accumulator.finish();

        let response = accumulator.into_response().unwrap();
        assert_eq!(response.output.message.content[0].as_text(), Some("tail"));

        let mut empty = StreamAccumulator::default();
        empty.ingest_bytes(b"data: ");
        empty.finish();
        assert!(empty.into_response().is_none());
    }

    #[test]
    fn omitted_tool_index_continues_the_last_unnamed_fragment() {
        let sse = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"function\":{\"name\":\"read_file\",\"arguments\":\"{\\\"pa\"}}]}}]}\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"function\":{\"arguments\":\"th\\\":\\\"x\\\"}\"}}]}}]}\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n",
        );

        let response = reassemble(sse);
        let call = response.output.message.content[0].as_tool_use().unwrap();

        assert_eq!(call.name, "read_file");
        assert_eq!(call.input, json!({"path": "x"}));
    }

    #[test]
    fn id_only_fragment_and_empty_continuations_merge_into_one_tool_call() {
        let sse = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_a\"}]}}]}\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"read_file\",\"arguments\":\"{\\\"path\\\":\\\"\"}}]}}]}\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"\",\"function\":{\"name\":\"\",\"arguments\":\"a.rs\\\"}\"}}]}}]}\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n",
            "data: [DONE]\n",
        );

        let response = reassemble(sse);

        assert_eq!(response.stop_reason, StopReason::ToolUse);
        assert_eq!(response.output.message.content.len(), 1);
        let call = response.output.message.content[0].as_tool_use().unwrap();
        assert_eq!(call.tool_use_id, "call_a");
        assert_eq!(call.name, "read_file");
        assert_eq!(call.input, json!({"path": "a.rs"}));
    }

    fn accumulate_in_chunks(stream: &[u8], boundaries: &[usize]) -> (bool, bool, String) {
        let mut accumulator = StreamAccumulator::default();
        let mut start = 0;
        for boundary in boundaries.iter().chain(std::iter::once(&stream.len())) {
            if accumulator.ingest_bytes(&stream[start..*boundary]) {
                break;
            }
            start = *boundary;
        }
        accumulator.finish();
        (
            accumulator.is_complete(),
            accumulator.has_malformed_data(),
            format!("{:?}", accumulator.into_response()),
        )
    }

    #[test]
    fn chunk_boundaries_never_change_the_reassembled_stream() {
        let stream = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ab\"}}]}\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",\"function\":{\"name\":\"read_file\",\"arguments\":\"{\\\"path\\\":\\\"a.rs\\\"}\"}}]}}]}\n",
        "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":2}}\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n",
        "data: [DONE]\n",
    )
    .as_bytes();
        let whole = accumulate_in_chunks(stream, &[]);

        for boundaries in [
            vec![1],
            vec![stream.len() / 2],
            vec![13, 40, 41, 200],
            (0..stream.len()).collect::<Vec<_>>(),
        ] {
            assert_eq!(
                accumulate_in_chunks(stream, &boundaries),
                whole,
                "chunking at {boundaries:?} changed the reassembled stream"
            );
        }
    }

    #[test]
    fn a_completion_marker_split_across_chunks_still_discards_the_remainder() {
        let stream = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"kept\"}}]}\n",
            "data: [DONE]\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"dropped\"}}]}\n",
        )
        .as_bytes();
        let split_inside_the_marker = stream.len() - 40;

        let (complete, malformed, response) =
            accumulate_in_chunks(stream, &[split_inside_the_marker]);

        assert!(complete);
        assert!(!malformed);
        assert!(response.contains("kept"));
        assert!(!response.contains("dropped"));
        assert_eq!(
            (complete, malformed, response),
            accumulate_in_chunks(stream, &[])
        );
    }

    #[test]
    fn malformed_payloads_are_reported_independently_of_chunking() {
        let stream = b"data: {not json\ndata: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"}}]}\n";

        let whole = accumulate_in_chunks(stream, &[]);

        assert!(whole.1, "malformed payload was not reported");
        assert!(whole.2.contains("ok"), "malformed payload dropped the rest");
        assert_eq!(accumulate_in_chunks(stream, &[7, 8, 30]), whole);
    }
    #[test]
    fn invalid_utf8_frames_are_rejected_without_accepting_replacement_text() {
        let mut stream = b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"".to_vec();
        stream.push(0xff);
        stream.extend_from_slice(b"trusted\"}}]}\ndata: [DONE]\n");

        let whole = accumulate_in_chunks(&stream, &[]);

        assert!(whole.1);
        assert!(!whole.2.contains("trusted"));
        assert_eq!(accumulate_in_chunks(&stream, &[12, 57]), whole);
    }

    fn argument_fragment(index: usize, arguments: &str) -> String {
        let chunk = json!({
            "choices": [{
                "delta": {
                    "tool_calls": [{
                        "index": index,
                        "function": { "arguments": arguments }
                    }]
                }
            }]
        });
        format!("data: {chunk}\n")
    }

    fn content_fragment(text: &str) -> String {
        let chunk = json!({ "choices": [{ "delta": { "content": text } }] });
        format!("data: {chunk}\n")
    }

    #[test]
    fn the_stream_aggregate_admits_its_exact_limit_and_rejects_the_next_byte() {
        const CHUNK_BYTES: usize = 1024 * 1024;
        let mut chunk = vec![b'x'; CHUNK_BYTES - 1];
        chunk.push(SSE_LINE_FEED);
        let mut accumulator = StreamAccumulator::default();

        for _ in 0..MAX_STREAM_AGGREGATE_BYTES / CHUNK_BYTES {
            assert!(!accumulator.ingest_bytes(&chunk));
        }

        assert_eq!(accumulator.stream_bytes, MAX_STREAM_AGGREGATE_BYTES);
        assert!(accumulator.exhausted_limit().is_none());

        let stopped = accumulator.ingest_bytes(b"x");

        assert!(
            stopped,
            "the accumulator must stop once its aggregate is full"
        );
        assert_eq!(accumulator.exhausted_limit(), Some(StreamLimit::Stream));
        assert_eq!(accumulator.stream_bytes, MAX_STREAM_AGGREGATE_BYTES);
        assert!(accumulator.pending.is_empty());
    }

    #[test]
    fn fragmented_tool_arguments_fill_the_per_call_limit_and_reject_the_next_byte() {
        let half = MAX_TOOL_ARGUMENT_BYTES / 2;
        let mut accumulator = StreamAccumulator::default();

        for _ in 0..2 {
            assert!(!accumulator.ingest_bytes(argument_fragment(0, &"a".repeat(half)).as_bytes()));
        }

        assert!(accumulator.exhausted_limit().is_none());
        assert_eq!(
            accumulator.tool_calls[&0].arguments.len(),
            MAX_TOOL_ARGUMENT_BYTES
        );

        let stopped = accumulator.ingest_bytes(argument_fragment(0, "a").as_bytes());

        assert!(stopped);
        assert_eq!(
            accumulator.exhausted_limit(),
            Some(StreamLimit::ToolArguments)
        );
        assert_eq!(
            accumulator.tool_calls[&0].arguments.len(),
            MAX_TOOL_ARGUMENT_BYTES,
            "the rejected fragment must not be retained"
        );
    }

    #[test]
    fn fragmented_tool_arguments_fill_the_aggregate_limit_and_reject_the_next_call() {
        let calls = MAX_TOOL_ARGUMENT_AGGREGATE_BYTES / MAX_TOOL_ARGUMENT_BYTES;
        let arguments = "a".repeat(MAX_TOOL_ARGUMENT_BYTES);
        let mut accumulator = StreamAccumulator::default();

        for index in 0..calls {
            assert!(!accumulator.ingest_bytes(argument_fragment(index, &arguments).as_bytes()));
        }

        assert!(accumulator.exhausted_limit().is_none());
        assert_eq!(
            accumulator.argument_bytes,
            MAX_TOOL_ARGUMENT_AGGREGATE_BYTES
        );

        let stopped = accumulator.ingest_bytes(argument_fragment(calls, "a").as_bytes());

        assert!(stopped);
        assert_eq!(
            accumulator.exhausted_limit(),
            Some(StreamLimit::ToolArgumentAggregate)
        );
        assert_eq!(
            accumulator.argument_bytes,
            MAX_TOOL_ARGUMENT_AGGREGATE_BYTES
        );
        assert!(
            !accumulator.tool_calls.contains_key(&calls),
            "the rejected call must retain nothing at all"
        );
    }

    #[test]
    fn the_first_stream_limit_remains_the_reported_limit() {
        let mut accumulator = StreamAccumulator::default();

        accumulator.exhaust(StreamLimit::Stream);
        accumulator.exhaust(StreamLimit::ToolArguments);

        assert_eq!(accumulator.exhausted_limit(), Some(StreamLimit::Stream));
    }

    #[test]
    fn one_chunk_with_many_lines_matches_line_by_line_ingestion() {
        let mut stream = String::new();
        for index in 0..500 {
            stream.push_str(&content_fragment(&format!("piece-{index} ")));
        }
        stream.push_str("data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n");
        stream.push_str("data: [DONE]\n");
        let stream = stream.as_bytes();
        let line_starts: Vec<usize> = stream
            .iter()
            .enumerate()
            .filter(|(_, byte)| **byte == SSE_LINE_FEED)
            .map(|(index, _)| index + 1)
            .collect();

        let whole = accumulate_in_chunks(stream, &[]);

        assert!(whole.0, "the completion marker must be honoured");
        assert!(!whole.1);
        assert!(whole.2.contains("piece-499"), "{}", whole.2);
        assert_eq!(
            accumulate_in_chunks(stream, &line_starts),
            whole,
            "one chunk with many lines must match line-by-line ingestion"
        );
    }
}
