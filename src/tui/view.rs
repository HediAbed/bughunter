use std::time::Duration;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, List, ListItem, Paragraph};
use tracing::Level;
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

use super::state::Snapshot;

pub(crate) fn render(frame: &mut ratatui::Frame, snapshot: &Snapshot) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(6), Constraint::Min(0)])
        .split(frame.area());

    render_header(frame, chunks[0], snapshot);
    render_log(frame, chunks[1], snapshot);
}

fn render_header(frame: &mut ratatui::Frame, area: Rect, snapshot: &Snapshot) {
    let block = header_block();
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(inner);

    frame.render_widget(Paragraph::new(summary_line(snapshot)), rows[0]);
    frame.render_widget(Paragraph::new(status_line(snapshot)), rows[1]);
    frame.render_widget(Paragraph::new(detail_line(snapshot, inner)), rows[2]);

    render_progress(frame, rows[3], snapshot);
}

fn header_block() -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(
            " bughunter ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .title(Line::from(Span::styled(
            " Ctrl-C to stop ",
            Style::default().fg(Color::DarkGray),
        )))
}

fn summary_line(snapshot: &Snapshot) -> Line<'static> {
    let ctx = if snapshot.context_window > 0 {
        format_thousands(snapshot.context_window)
    } else {
        "-".to_string()
    };
    let mut spans = vec![
        Span::styled("model ", Style::default().fg(Color::DarkGray)),
        Span::raw(snapshot.model.clone()),
        Span::styled("   context ", Style::default().fg(Color::DarkGray)),
        Span::raw(ctx),
        Span::styled("   elapsed ", Style::default().fg(Color::DarkGray)),
        Span::raw(format_elapsed(snapshot.elapsed)),
    ];
    if let Some(activity) = model_activity_text(snapshot) {
        spans.push(Span::styled(
            "   llm ",
            Style::default().fg(Color::DarkGray),
        ));
        spans.push(Span::raw(activity));
    }
    Line::from(spans)
}

fn model_activity_text(snapshot: &Snapshot) -> Option<String> {
    let activity = &snapshot.model_activity;
    if activity.requests == 0 {
        return None;
    }
    Some(format!(
        "{} req · {} in · {} out",
        activity.requests,
        format_compact_tokens(activity.input_tokens),
        format_compact_tokens(activity.output_tokens)
    ))
}

fn status_line(snapshot: &Snapshot) -> Line<'static> {
    let shard = if snapshot.shard.files > 0 {
        format!(
            "{}/{} ({} files)",
            snapshot.current_shard, snapshot.total_shards, snapshot.shard.files
        )
    } else {
        format!("{}/{}", snapshot.current_shard, snapshot.total_shards)
    };
    let mut spans = vec![
        Span::styled("phase ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            snapshot.phase.label(),
            Style::default()
                .fg(snapshot.phase.color())
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("   shard ", Style::default().fg(Color::DarkGray)),
        Span::raw(shard),
        Span::styled("   findings ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            snapshot.findings.to_string(),
            Style::default().fg(Color::Yellow),
        ),
    ];
    if snapshot.shard.finalizing {
        spans.push(Span::styled(
            "   finalizing ",
            Style::default().fg(Color::DarkGray),
        ));
        spans.push(Span::styled(
            format!("attempt {}", snapshot.shard.finalization_attempt),
            Style::default().fg(Color::Cyan),
        ));
    }
    Line::from(spans)
}

fn detail_line(snapshot: &Snapshot, inner: Rect) -> Line<'static> {
    let width = inner.width.saturating_sub(2) as usize;
    let activity = tool_activity_text(snapshot);
    let activity_width = display_width(&activity);
    let activity_fits = activity_width > 0 && activity_width < width;
    let detail_width = if activity_fits {
        width - activity_width
    } else {
        width
    };

    let mut spans = vec![
        Span::styled("→ ", Style::default().fg(snapshot.phase.color())),
        Span::raw(truncate(&snapshot.detail, detail_width)),
    ];
    if activity_fits {
        spans.push(Span::styled(activity, Style::default().fg(Color::DarkGray)));
    }
    Line::from(spans)
}

fn tool_activity_text(snapshot: &Snapshot) -> String {
    if snapshot.shard.tool_calls == 0 {
        return String::new();
    }
    format!(
        "   tool {} · {} calls · {} tokens",
        snapshot.shard.last_tool,
        snapshot.shard.tool_calls,
        format_compact_tokens(snapshot.shard.inspected_tokens)
    )
}

fn render_progress(frame: &mut ratatui::Frame, area: Rect, snapshot: &Snapshot) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let ratio = snapshot.progress.clamp(0.0, 1.0);
    let gauge = Gauge::default()
        .gauge_style(Style::default().fg(Color::Green).bg(Color::Black))
        .ratio(ratio)
        .label(format!("{:.0}%", ratio * 100.0));
    frame.render_widget(gauge, area);
}

fn render_log(frame: &mut ratatui::Frame, area: Rect, snapshot: &Snapshot) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(" activity ", Style::default().fg(Color::Cyan)));
    let inner_height = block.inner(area).height as usize;

    let items: Vec<ListItem> = snapshot
        .logs
        .iter()
        .rev()
        .take(inner_height)
        .rev()
        .map(|line| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{} ", line.time),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    format!("{:<5} ", level_label(line.level)),
                    Style::default().fg(level_color(line.level)),
                ),
                Span::raw(line.text.clone()),
            ]))
        })
        .collect();

    frame.render_widget(List::new(items).block(block), area);
}

pub(crate) fn level_label(level: Level) -> &'static str {
    match level {
        Level::ERROR => "ERROR",
        Level::WARN => "WARN",
        Level::INFO => "INFO",
        Level::DEBUG => "DEBUG",
        Level::TRACE => "TRACE",
    }
}

fn level_color(level: Level) -> Color {
    match level {
        Level::ERROR => Color::Red,
        Level::WARN => Color::Yellow,
        Level::INFO => Color::Green,
        Level::DEBUG => Color::DarkGray,
        Level::TRACE => Color::DarkGray,
    }
}

fn display_width(text: &str) -> usize {
    UnicodeWidthStr::width(text)
}

fn truncate(text: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    if display_width(text) <= max {
        return text.to_string();
    }

    const ELLIPSIS: &str = "…";
    let content_width = max.saturating_sub(display_width(ELLIPSIS));
    let mut kept = String::new();
    let mut kept_width: usize = 0;
    for grapheme in text.graphemes(true) {
        let width = display_width(grapheme);
        if kept_width.saturating_add(width) > content_width {
            break;
        }
        kept.push_str(grapheme);
        kept_width += width;
    }
    kept.push_str(ELLIPSIS);
    kept
}

fn format_elapsed(elapsed: Duration) -> String {
    let secs = elapsed.as_secs();
    let (m, s) = (secs / 60, secs % 60);
    if m > 0 {
        format!("{m}m{s:02}s")
    } else {
        format!("{s}s")
    }
}

fn format_thousands(value: u32) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

fn format_compact_tokens(value: u64) -> String {
    if value < 1_000 {
        return value.to_string();
    }
    if value < 1_000_000 {
        return format!("{:.1}k", value as f64 / 1_000.0);
    }
    format!("{:.1}M", value as f64 / 1_000_000.0)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        display_width, format_compact_tokens, format_elapsed, format_thousands, level_color,
        level_label, render, truncate,
    };
    use crate::tui::state::{Phase, ScanState};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use ratatui::style::Color;
    use std::time::Duration;
    use tracing::Level;

    fn render_buffer(width: u16, height: u16, state: &mut ScanState) -> Buffer {
        let snapshot = state.snapshot();
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| render(frame, &snapshot)).unwrap();
        terminal.backend().buffer().clone()
    }

    fn render_at(width: u16, height: u16, state: &mut ScanState) -> String {
        render_buffer(width, height, state)
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>()
    }

    fn rendered_level_color(level: Level, label: &str) -> Color {
        let mut state = ScanState::new();
        state.push_log(level, "entry".into());
        let buffer = render_buffer(80, 10, &mut state);
        let symbols = buffer
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<Vec<_>>();
        let start = (0..=symbols.len() - label.len())
            .find(|&index| symbols[index..index + label.len()].concat() == label)
            .unwrap();
        buffer.content()[start].fg
    }

    fn sample_state() -> ScanState {
        let mut state = ScanState::new();
        state.model = "test-model".into();
        state.context_window = 128_000;
        state.total_shards = 45;
        state.current_shard = 2;
        state.phase = Phase::Reading;
        state.detail = "apps/backend-api/src/server/auth.ts".into();
        state.findings = 3;
        state.push_log(Level::INFO, "analyzing shard".into());
        state
    }

    #[test]
    fn renders_without_panic_across_sizes() {
        let mut state = sample_state();
        for (w, h) in [(40, 10), (80, 24), (200, 60), (30, 6)] {
            let rendered = render_at(w, h, &mut state);
            assert!(rendered.contains("bughunter"));
        }
    }

    #[test]
    fn shows_current_activity_and_findings() {
        let rendered = render_at(120, 20, &mut sample_state());
        assert!(rendered.contains("reading"));
        assert!(rendered.contains("auth.ts"));
        assert!(rendered.contains("test-model"));
    }

    #[test]
    fn shows_tool_activity_counter() {
        let mut state = sample_state();
        state.shard.last_tool = "read_file".into();
        state.shard.tool_calls = 12;
        state.shard.inspected_tokens = 8_400;
        let rendered = render_at(160, 20, &mut state);
        assert!(rendered.contains("tool read_file"));
        assert!(rendered.contains("12 calls"));
        assert!(rendered.contains("8.4k tokens"));
    }

    #[test]
    fn hides_tool_activity_before_the_first_tool_call() {
        let rendered = render_at(160, 20, &mut sample_state());
        assert!(!rendered.contains("calls"));
    }

    #[test]
    fn shows_model_activity_once_a_request_is_made() {
        let mut state = sample_state();
        state.model_activity.requests = 3;
        state.model_activity.input_tokens = 12_400;
        state.model_activity.output_tokens = 900;
        let rendered = render_at(200, 20, &mut state);
        assert!(rendered.contains("3 req"));
        assert!(rendered.contains("12.4k in"));
        assert!(rendered.contains("900 out"));
    }

    #[test]
    fn shows_finalization_attempt() {
        let mut state = sample_state();
        state.shard.finalizing = true;
        state.shard.finalization_attempt = 2;
        let rendered = render_at(160, 20, &mut state);
        assert!(rendered.contains("attempt 2"));
    }

    #[test]
    fn renders_the_progress_percentage_from_state() {
        let mut state = ScanState::new();
        state.total_shards = 1;
        state.current_shard = 1;
        state.phase = Phase::Reading;
        state.shard.eligible_tokens = 10_000;
        state.shard.inspected_tokens = 5_000;
        let rendered = render_at(120, 20, &mut state);
        assert!(rendered.contains("45%"), "{rendered}");
    }

    #[test]
    fn renders_zero_percent_before_the_run_starts() {
        let mut state = ScanState::new();
        let rendered = render_at(120, 20, &mut state);
        assert!(rendered.contains("0%"));
    }

    #[test]
    fn renders_full_progress_when_finished() {
        let mut state = sample_state();
        state.phase = Phase::Finished;
        let rendered = render_at(120, 20, &mut state);
        assert!(rendered.contains("100%"));
    }

    #[test]
    fn a_header_too_short_for_the_gauge_renders_without_it() {
        let mut state = ScanState::new();
        state.total_shards = 1;
        state.current_shard = 1;
        state.phase = Phase::Reading;
        state.shard.eligible_tokens = 10_000;
        state.shard.inspected_tokens = 5_000;

        let roomy = render_at(120, 20, &mut state);
        let cramped = render_at(120, 4, &mut state);

        assert!(roomy.contains("45%"), "{roomy}");
        assert!(!cramped.contains("45%"), "{cramped}");
    }

    #[test]
    fn thousands_separator() {
        assert_eq!(format_thousands(204_800), "204,800");
        assert_eq!(format_thousands(1_000_000), "1,000,000");
        assert_eq!(format_thousands(512), "512");
    }

    #[test]
    fn compact_tokens() {
        assert_eq!(format_compact_tokens(0), "0");
        assert_eq!(format_compact_tokens(999), "999");
        assert_eq!(format_compact_tokens(8_400), "8.4k");
        assert_eq!(format_compact_tokens(204_800), "204.8k");
        assert_eq!(format_compact_tokens(2_500_000), "2.5M");
    }

    #[test]
    fn truncate_respects_terminal_cell_width_and_graphemes() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 5), "hell…");
        assert_eq!(truncate("hello", 1), "…");
        assert_eq!(truncate("hello", 0), "");
        assert_eq!(truncate("界界", 3), "界…");
        assert_eq!(truncate("ae\u{301}x", 2), "a…");
        assert!(display_width(&truncate("界界界", 4)) <= 4);
    }

    #[test]
    fn shard_counter_includes_file_count_after_sizing() {
        let mut state = sample_state();
        let without_file_count = render_at(160, 20, &mut state);
        assert!(without_file_count.contains("2/45"));
        assert!(!without_file_count.contains("files"));

        state.shard.files = 7;
        let sized = render_at(160, 20, &mut state);
        assert!(sized.contains("2/45 (7 files)"));
    }

    #[test]
    fn narrow_rows_drop_tool_activity() {
        let mut state = sample_state();
        state.shard.last_tool = "read_file".into();
        state.shard.tool_calls = 12;
        state.shard.inspected_tokens = 8_400;

        let wide = render_at(160, 20, &mut state);
        let narrow = render_at(30, 12, &mut state);

        assert!(wide.contains("tool read_file"));
        assert!(!narrow.contains("read_file"));
        assert!(narrow.contains('…'));
    }

    #[test]
    fn every_log_level_uses_its_label_and_color() {
        for (level, label, color) in [
            (Level::ERROR, "ERROR", Color::Red),
            (Level::WARN, "WARN", Color::Yellow),
            (Level::INFO, "INFO", Color::Green),
            (Level::DEBUG, "DEBUG", Color::DarkGray),
            (Level::TRACE, "TRACE", Color::DarkGray),
        ] {
            assert_eq!(level_label(level), label);
            assert_eq!(level_color(level), color);
            assert_eq!(rendered_level_color(level, label), color);
        }
    }

    #[test]
    fn elapsed_switches_from_seconds_to_minutes() {
        assert_eq!(format_elapsed(Duration::from_secs(0)), "0s");
        assert_eq!(format_elapsed(Duration::from_secs(59)), "59s");
        assert_eq!(format_elapsed(Duration::from_secs(60)), "1m00s");
        assert_eq!(format_elapsed(Duration::from_secs(3_605)), "60m05s");
    }
}
