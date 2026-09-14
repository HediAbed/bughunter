#![no_main]

use bughunter::fuzzing::{
    ContentBlock, LlmResponse, Role, StopReason, StreamAccumulator, StreamLimit,
};
use libfuzzer_sys::fuzz_target;

const MAX_STREAM_BYTES: usize = 64 * 1024;
const MAX_CHUNK_BOUNDARIES: usize = 8;
const BOUNDARY_SCALE: usize = 256;
const SSE_DATA_PREFIX: &str = "data:";
const SSE_DONE_MARKER: &str = "[DONE]";

struct AccumulatedStream {
    complete: bool,
    malformed: bool,
    exhausted: Option<StreamLimit>,
    response: Option<LlmResponse>,
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_STREAM_BYTES {
        return;
    }
    let Some((boundaries, stream)) = split_plan(data) else {
        return;
    };

    let whole = accumulate(&[stream]);
    let chunked = accumulate(&chunks(stream, &boundaries));

    assert_eq!(
        whole.complete, chunked.complete,
        "chunking at {boundaries:?} changed completion of {stream:?}"
    );
    assert_eq!(
        whole.malformed, chunked.malformed,
        "chunking at {boundaries:?} changed the malformed flag of {stream:?}"
    );
    assert_eq!(
        whole.exhausted, chunked.exhausted,
        "chunking at {boundaries:?} changed the exhausted limit of {stream:?}"
    );
    assert!(
        whole.exhausted.is_none(),
        "a stream of at most {MAX_STREAM_BYTES} bytes exhausted {:?}",
        whole.exhausted
    );
    assert_eq!(
        format!("{:?}", whole.response),
        format!("{:?}", chunked.response),
        "chunking at {boundaries:?} changed the response for {stream:?}"
    );

    let text = String::from_utf8_lossy(stream);
    if whole.malformed {
        assert!(
            std::str::from_utf8(stream).is_err() || text.contains(SSE_DATA_PREFIX),
            "reported malformed data for a UTF-8 stream without any data line: {text:?}"
        );
    }
    if carries_a_completion_marker(&text) {
        assert!(whole.complete, "ignored the completion marker in {text:?}");
    }
    if let Some(response) = &whole.response {
        assert_response_is_a_single_assistant_turn(response, &text);
    }
});

fn carries_a_completion_marker(text: &str) -> bool {
    text.lines().any(|line| {
        line.trim()
            .strip_prefix(SSE_DATA_PREFIX)
            .is_some_and(|payload| payload.trim() == SSE_DONE_MARKER)
    })
}

fn split_plan(data: &[u8]) -> Option<(Vec<usize>, &[u8])> {
    let (requested_boundaries, rest) = data.split_first()?;
    let boundary_count = usize::from(*requested_boundaries) % (MAX_CHUNK_BOUNDARIES + 1);
    if rest.len() < boundary_count {
        return None;
    }
    let (fractions, stream) = rest.split_at(boundary_count);
    let mut boundaries: Vec<usize> = fractions
        .iter()
        .map(|fraction| usize::from(*fraction) * stream.len() / BOUNDARY_SCALE)
        .collect();
    boundaries.sort_unstable();
    Some((boundaries, stream))
}

fn chunks<'a>(stream: &'a [u8], boundaries: &[usize]) -> Vec<&'a [u8]> {
    let mut chunks = Vec::with_capacity(boundaries.len() + 1);
    let mut start = 0;
    for boundary in boundaries {
        chunks.push(&stream[start..*boundary]);
        start = *boundary;
    }
    chunks.push(&stream[start..]);
    chunks
}

fn accumulate(chunks: &[&[u8]]) -> AccumulatedStream {
    let mut accumulator = StreamAccumulator::default();
    for chunk in chunks {
        if accumulator.ingest_bytes(chunk) {
            break;
        }
    }
    accumulator.finish();
    AccumulatedStream {
        complete: accumulator.is_complete(),
        malformed: accumulator.has_malformed_data(),
        exhausted: accumulator.exhausted_limit(),
        response: accumulator.into_response(),
    }
}

fn assert_response_is_a_single_assistant_turn(response: &LlmResponse, text: &str) {
    let message = &response.output.message;
    assert_eq!(
        message.role,
        Role::Assistant,
        "stream {text:?} produced a non-assistant turn"
    );

    let text_blocks = message
        .content
        .iter()
        .enumerate()
        .filter(|(_, block)| matches!(block, ContentBlock::Text { .. }))
        .map(|(position, _)| position)
        .collect::<Vec<_>>();
    assert!(
        text_blocks.len() <= 1,
        "stream {text:?} produced {} text blocks instead of a merged one",
        text_blocks.len()
    );
    assert!(
        text_blocks.first().is_none_or(|position| *position == 0),
        "stream {text:?} placed the merged text block after a tool call"
    );

    let has_tool_calls = message
        .content
        .iter()
        .any(|block| matches!(block, ContentBlock::ToolUse { .. }));
    if has_tool_calls {
        assert_eq!(
            response.stop_reason,
            StopReason::ToolUse,
            "stream {text:?} produced tool calls with a non-tool stop reason"
        );
    }
}
