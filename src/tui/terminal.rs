use std::io::{self, Stderr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::cursor::{Hide, Show};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};

use crate::cancel::CancelToken;

use super::state::SharedState;
use super::view::render;

const RENDER_INTERVAL: Duration = Duration::from_millis(120);
const INPUT_POLL_INTERVAL: Duration = Duration::from_millis(100);

type TuiTerminal = Terminal<CrosstermBackend<Stderr>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Cancel,
    Ignore,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct TerminalState {
    raw_mode: bool,
    alternate_screen: bool,
    cursor_hidden: bool,
}

impl TerminalState {
    const fn new(raw_mode: bool, alternate_screen: bool, cursor_hidden: bool) -> Self {
        Self {
            raw_mode,
            alternate_screen,
            cursor_hidden,
        }
    }
}

struct TerminalSession {
    state: TerminalState,
}

impl TerminalSession {
    fn restore(&mut self) -> io::Result<()> {
        let mut disable = disable_raw_mode;
        let mut leave_screen = || execute!(io::stderr(), LeaveAlternateScreen);
        let mut show_cursor = || execute!(io::stderr(), Show);
        restore_state_with(
            &mut self.state,
            &mut disable,
            &mut leave_screen,
            &mut show_cursor,
        )
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

pub struct Tui {
    stop: Arc<AtomicBool>,
    render_loop: Option<tokio::task::JoinHandle<io::Result<()>>>,
    input_loop: Option<tokio::task::JoinHandle<()>>,
    session: Option<TerminalSession>,
}

impl Tui {
    pub fn start(state: SharedState, cancel: CancelToken) -> io::Result<Self> {
        let (terminal, session) = setup_terminal()?;
        let stop = Arc::new(AtomicBool::new(false));
        let render_loop = spawn_render_loop(terminal, state, stop.clone(), cancel.clone());
        let input_loop = spawn_input_loop(cancel, stop.clone());

        Ok(Self {
            stop,
            render_loop: Some(render_loop),
            input_loop: Some(input_loop),
            session: Some(session),
        })
    }

    pub async fn stop(mut self) -> io::Result<()> {
        self.stop.store(true, Ordering::Release);
        let mut first_error = None;

        if let Some(input_loop) = self.input_loop.take() {
            retain_first_error(
                &mut first_error,
                input_loop
                    .await
                    .map_err(|error| io::Error::other(format!("TUI input task failed: {error}"))),
            );
        }
        if let Some(render_loop) = self.render_loop.take() {
            match render_loop.await {
                Ok(result) => retain_first_error(&mut first_error, result),
                Err(error) => retain_first_error(
                    &mut first_error,
                    Err(io::Error::other(format!("TUI render task failed: {error}"))),
                ),
            }
        }
        if let Some(session) = self.session.as_mut() {
            retain_first_error(&mut first_error, session.restore());
        }

        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(render_loop) = self.render_loop.take() {
            render_loop.abort();
        }
        if let Some(input_loop) = self.input_loop.take() {
            input_loop.abort();
        }
        if let Some(session) = self.session.as_mut() {
            let _ = session.restore();
        }
    }
}

async fn run_render_loop(
    draw_frame: &mut (dyn FnMut() -> io::Result<()> + Send),
    stop: &AtomicBool,
    cancel: &CancelToken,
) -> io::Result<()> {
    let mut ticker = tokio::time::interval(RENDER_INTERVAL);
    while !stop.load(Ordering::Acquire) {
        ticker.tick().await;
        if let Err(error) = draw_frame() {
            cancel.cancel();
            return Err(error);
        }
    }
    draw_frame()
}

fn spawn_render_loop(
    mut terminal: TuiTerminal,
    state: SharedState,
    stop: Arc<AtomicBool>,
    cancel: CancelToken,
) -> tokio::task::JoinHandle<io::Result<()>> {
    tokio::spawn(async move {
        let mut draw_frame = || draw(&mut terminal, &state);
        run_render_loop(&mut draw_frame, &stop, &cancel).await
    })
}

fn spawn_input_loop(cancel: CancelToken, stop: Arc<AtomicBool>) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        let mut poll = poll_action;
        let mut wait_after_error = std::thread::sleep;
        run_input_loop(&cancel, &stop, &mut poll, &mut wait_after_error);
    })
}

fn run_input_loop(
    cancel: &CancelToken,
    stop: &AtomicBool,
    poll: &mut dyn FnMut(Duration) -> io::Result<Action>,
    wait_after_error: &mut dyn FnMut(Duration),
) {
    while !stop.load(Ordering::Acquire) {
        match poll(INPUT_POLL_INTERVAL) {
            Ok(Action::Cancel) => cancel.cancel(),
            Ok(Action::Ignore) => {}
            Err(_) => wait_after_error(INPUT_POLL_INTERVAL),
        }
    }
}

fn poll_action(timeout: Duration) -> io::Result<Action> {
    poll_action_with(timeout, &mut event::poll, &mut event::read)
}

fn poll_action_with(
    timeout: Duration,
    poll: &mut dyn FnMut(Duration) -> io::Result<bool>,
    read: &mut dyn FnMut() -> io::Result<Event>,
) -> io::Result<Action> {
    if !poll(timeout)? {
        return Ok(Action::Ignore);
    }
    Ok(action_for(&read()?))
}

fn action_for(event: &Event) -> Action {
    match event {
        Event::Key(key) if is_cancel_key(key) => Action::Cancel,
        _ => Action::Ignore,
    }
}

fn is_cancel_key(key: &KeyEvent) -> bool {
    if key.kind == KeyEventKind::Release {
        return false;
    }
    match key.code {
        KeyCode::Char('c') | KeyCode::Char('C') => key.modifiers.contains(KeyModifiers::CONTROL),
        KeyCode::Char('q') | KeyCode::Char('Q') => true,
        _ => false,
    }
}

fn setup_terminal() -> io::Result<(TuiTerminal, TerminalSession)> {
    let mut enable = enable_raw_mode;
    let mut enter_screen = || execute!(io::stderr(), EnterAlternateScreen);
    let mut hide_cursor = || execute!(io::stderr(), Hide);
    let mut create_terminal = || Terminal::new(CrosstermBackend::new(io::stderr()));
    setup_terminal_with_backend(
        &mut enable,
        &mut enter_screen,
        &mut hide_cursor,
        &mut create_terminal,
    )
}

fn setup_terminal_with_backend(
    enable: &mut dyn FnMut() -> io::Result<()>,
    enter_screen: &mut dyn FnMut() -> io::Result<()>,
    hide_cursor: &mut dyn FnMut() -> io::Result<()>,
    create_terminal: &mut dyn FnMut() -> io::Result<TuiTerminal>,
) -> io::Result<(TuiTerminal, TerminalSession)> {
    let mut rollback = |state| {
        let mut session = TerminalSession { state };
        let _ = session.restore();
    };
    let (terminal, state) = setup_terminal_with(
        enable,
        enter_screen,
        hide_cursor,
        create_terminal,
        &mut rollback,
    )?;
    Ok((terminal, TerminalSession { state }))
}

fn setup_terminal_with<T>(
    enable: &mut dyn FnMut() -> io::Result<()>,
    enter_screen: &mut dyn FnMut() -> io::Result<()>,
    hide_cursor: &mut dyn FnMut() -> io::Result<()>,
    create_terminal: &mut dyn FnMut() -> io::Result<T>,
    rollback: &mut dyn FnMut(TerminalState),
) -> io::Result<(T, TerminalState)> {
    let mut state = TerminalState::new(false, false, false);
    state.raw_mode = true;
    if let Err(error) = enable() {
        rollback(state);
        return Err(error);
    }
    state.alternate_screen = true;
    if let Err(error) = enter_screen() {
        rollback(state);
        return Err(error);
    }
    state.cursor_hidden = true;
    if let Err(error) = hide_cursor() {
        rollback(state);
        return Err(error);
    }
    match create_terminal() {
        Ok(terminal) => Ok((terminal, state)),
        Err(error) => {
            rollback(state);
            Err(error)
        }
    }
}

fn restore_state_with(
    state: &mut TerminalState,
    disable: &mut dyn FnMut() -> io::Result<()>,
    leave_screen: &mut dyn FnMut() -> io::Result<()>,
    show_cursor: &mut dyn FnMut() -> io::Result<()>,
) -> io::Result<()> {
    let mut first_error = None;
    if state.raw_mode {
        let result = disable();
        if result.is_ok() {
            state.raw_mode = false;
        }
        retain_first_error(&mut first_error, result);
    }
    if state.alternate_screen {
        let result = leave_screen();
        if result.is_ok() {
            state.alternate_screen = false;
        }
        retain_first_error(&mut first_error, result);
    }
    if state.cursor_hidden {
        let result = show_cursor();
        if result.is_ok() {
            state.cursor_hidden = false;
        }
        retain_first_error(&mut first_error, result);
    }
    first_error.map_or(Ok(()), Err)
}

fn retain_first_error(first_error: &mut Option<io::Error>, result: io::Result<()>) {
    if first_error.is_none()
        && let Err(error) = result
    {
        *first_error = Some(error);
    }
}

fn draw(terminal: &mut TuiTerminal, state: &SharedState) -> io::Result<()> {
    let snapshot = {
        let mut state = state.lock();
        state.snapshot()
    };
    terminal.draw(|frame| render(frame, &snapshot)).map(|_| ())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        Action, INPUT_POLL_INTERVAL, TerminalSession, TerminalState, Tui, action_for, poll_action,
        poll_action_with, restore_state_with, run_input_loop, run_render_loop, setup_terminal,
        setup_terminal_with, setup_terminal_with_backend, spawn_input_loop, spawn_render_loop,
    };
    use ratatui::backend::CrosstermBackend;
    use ratatui::crossterm::event::{
        Event, KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers, MouseButton,
        MouseEvent, MouseEventKind,
    };
    use ratatui::layout::Rect;
    use ratatui::{Terminal, TerminalOptions, Viewport};
    use std::io;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    const FIXTURE_TERMINAL_WIDTH: u16 = 80;
    const FIXTURE_TERMINAL_HEIGHT: u16 = 24;

    fn fixture_terminal() -> io::Result<super::TuiTerminal> {
        Terminal::with_options(
            CrosstermBackend::new(io::stderr()),
            TerminalOptions {
                viewport: Viewport::Fixed(Rect::new(
                    0,
                    0,
                    FIXTURE_TERMINAL_WIDTH,
                    FIXTURE_TERMINAL_HEIGHT,
                )),
            },
        )
    }

    fn key(code: KeyCode, modifiers: KeyModifiers) -> Event {
        Event::Key(KeyEvent {
            code,
            modifiers,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        })
    }

    #[test]
    fn ctrl_c_cancels() {
        assert_eq!(
            action_for(&key(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Action::Cancel
        );
    }

    #[test]
    fn ctrl_uppercase_c_cancels() {
        assert_eq!(
            action_for(&key(
                KeyCode::Char('C'),
                KeyModifiers::CONTROL | KeyModifiers::SHIFT
            )),
            Action::Cancel
        );
    }

    #[test]
    fn q_cancels() {
        assert_eq!(
            action_for(&key(KeyCode::Char('q'), KeyModifiers::NONE)),
            Action::Cancel
        );
        assert_eq!(
            action_for(&key(KeyCode::Char('Q'), KeyModifiers::SHIFT)),
            Action::Cancel
        );
    }

    #[test]
    fn plain_c_is_ignored() {
        assert_eq!(
            action_for(&key(KeyCode::Char('c'), KeyModifiers::NONE)),
            Action::Ignore
        );
    }

    #[test]
    fn unrelated_keys_are_ignored() {
        for code in [
            KeyCode::Char('a'),
            KeyCode::Enter,
            KeyCode::Esc,
            KeyCode::Up,
            KeyCode::Tab,
        ] {
            assert_eq!(action_for(&key(code, KeyModifiers::NONE)), Action::Ignore);
        }
    }

    #[test]
    fn key_release_never_cancels() {
        let release = Event::Key(KeyEvent {
            code: KeyCode::Char('q'),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Release,
            state: KeyEventState::NONE,
        });
        assert_eq!(action_for(&release), Action::Ignore);
    }

    #[test]
    fn key_repeat_still_cancels() {
        let repeat = Event::Key(KeyEvent {
            code: KeyCode::Char('c'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Repeat,
            state: KeyEventState::NONE,
        });
        assert_eq!(action_for(&repeat), Action::Cancel);
    }

    #[test]
    fn non_key_events_are_ignored() {
        let resize = Event::Resize(80, 24);
        assert_eq!(action_for(&resize), Action::Ignore);
        let mouse = Event::Mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 1,
            row: 1,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(action_for(&mouse), Action::Ignore);
    }

    #[test]
    fn input_loop_handles_cancel_ignore_and_poll_errors() {
        for action in [Action::Cancel, Action::Ignore] {
            let cancel = crate::cancel::CancelToken::default();
            let stop = AtomicBool::new(false);
            run_input_loop(
                &cancel,
                &stop,
                &mut |_| {
                    stop.store(true, Ordering::Relaxed);
                    Ok(action)
                },
                &mut |_| panic!("successful input must not back off"),
            );
            assert_eq!(cancel.is_cancelled(), action == Action::Cancel);
        }

        let cancel = crate::cancel::CancelToken::default();
        let stop = AtomicBool::new(false);
        let mut waited = false;
        run_input_loop(
            &cancel,
            &stop,
            &mut |_| {
                stop.store(true, Ordering::Relaxed);
                Err(std::io::Error::other("terminal unavailable"))
            },
            &mut |duration| {
                assert_eq!(duration, INPUT_POLL_INTERVAL);
                waited = true;
            },
        );
        assert!(waited);
        assert!(!cancel.is_cancelled());
    }

    #[test]
    fn terminal_setup_rolls_back_every_transition_that_may_have_started() {
        let cases = [
            (0, TerminalState::new(true, false, false), "raw failed"),
            (1, TerminalState::new(true, true, false), "enter failed"),
            (2, TerminalState::new(true, true, true), "hide failed"),
            (3, TerminalState::new(true, true, true), "create failed"),
        ];

        for (failure, expected_state, message) in cases {
            let rolled_back = std::cell::Cell::new(None);
            let result = setup_terminal_with(
                &mut || {
                    (failure != 0)
                        .then_some(())
                        .ok_or_else(|| std::io::Error::other(message))
                },
                &mut || {
                    (failure != 1)
                        .then_some(())
                        .ok_or_else(|| std::io::Error::other(message))
                },
                &mut || {
                    (failure != 2)
                        .then_some(())
                        .ok_or_else(|| std::io::Error::other(message))
                },
                &mut || {
                    (failure != 3)
                        .then_some(7u8)
                        .ok_or_else(|| std::io::Error::other(message))
                },
                &mut |state| rolled_back.set(Some(state)),
            );

            assert_eq!(result.unwrap_err().to_string(), message);
            assert_eq!(rolled_back.get(), Some(expected_state));
        }

        let (terminal, state) = setup_terminal_with(
            &mut || Ok(()),
            &mut || Ok(()),
            &mut || Ok(()),
            &mut || Ok(7u8),
            &mut |_| panic!("successful setup must not roll back"),
        )
        .unwrap();
        assert_eq!(terminal, 7);
        assert_eq!(state, TerminalState::new(true, true, true));
    }

    #[test]
    fn restoration_attempts_active_steps_in_order_keeps_failures_and_reports_the_first_error() {
        let names = ["raw", "screen", "cursor"];

        for state_bits in 0..8u8 {
            for failure_mask in 0..8u8 {
                let active = [
                    state_bits & 1 != 0,
                    state_bits & 2 != 0,
                    state_bits & 4 != 0,
                ];
                let failed = [
                    failure_mask & 1 != 0,
                    failure_mask & 2 != 0,
                    failure_mask & 4 != 0,
                ];
                let mut state = TerminalState::new(active[0], active[1], active[2]);
                let attempts = std::cell::RefCell::new(Vec::new());

                let result = restore_state_with(
                    &mut state,
                    &mut || {
                        attempts.borrow_mut().push("raw");
                        (!failed[0])
                            .then_some(())
                            .ok_or_else(|| std::io::Error::other("raw restore failed"))
                    },
                    &mut || {
                        attempts.borrow_mut().push("screen");
                        (!failed[1])
                            .then_some(())
                            .ok_or_else(|| std::io::Error::other("screen restore failed"))
                    },
                    &mut || {
                        attempts.borrow_mut().push("cursor");
                        (!failed[2])
                            .then_some(())
                            .ok_or_else(|| std::io::Error::other("cursor restore failed"))
                    },
                );

                let expected_attempts: Vec<&str> = names
                    .into_iter()
                    .zip(active)
                    .filter_map(|(name, active)| active.then_some(name))
                    .collect();
                assert_eq!(
                    attempts.borrow().as_slice(),
                    expected_attempts.as_slice(),
                    "only active steps are attempted, in order: state {state_bits:03b} mask {failure_mask:03b}"
                );
                assert_eq!(
                    state,
                    TerminalState::new(
                        active[0] && failed[0],
                        active[1] && failed[1],
                        active[2] && failed[2],
                    ),
                    "failed steps stay active for a later retry: state {state_bits:03b} mask {failure_mask:03b}"
                );
                match (0..3).find(|&index| active[index] && failed[index]) {
                    Some(index) => assert_eq!(
                        result.unwrap_err().to_string(),
                        format!("{} restore failed", names[index]),
                        "the first failure wins: state {state_bits:03b} mask {failure_mask:03b}"
                    ),
                    None => assert!(
                        result.is_ok(),
                        "nothing failed: state {state_bits:03b} mask {failure_mask:03b}"
                    ),
                }
            }
        }
    }

    #[test]
    fn a_poll_without_an_event_is_ignored_without_reading() {
        let action = poll_action_with(Duration::ZERO, &mut |_| Ok(false), &mut || {
            panic!("no event is read when polling reports none")
        })
        .unwrap();

        assert_eq!(action, Action::Ignore);
    }

    #[test]
    fn poll_and_read_failures_are_propagated() {
        let error = poll_action_with(
            Duration::ZERO,
            &mut |_| Err(std::io::Error::other("terminal lost")),
            &mut || panic!("a failed poll must not read"),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "terminal lost");

        let error = poll_action_with(Duration::ZERO, &mut |_| Ok(true), &mut || {
            Err(std::io::Error::other("event stream closed"))
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "event stream closed");
    }

    #[test]
    fn a_polled_cancel_key_cancels() {
        let action = poll_action_with(Duration::ZERO, &mut |_| Ok(true), &mut || {
            Ok(key(KeyCode::Char('q'), KeyModifiers::NONE))
        })
        .unwrap();

        assert_eq!(action, Action::Cancel);
    }

    #[test]
    fn polling_the_real_terminal_never_invents_a_cancel() {
        let action = poll_action(Duration::ZERO);

        assert!(!matches!(action, Ok(Action::Cancel)), "{action:?}");
    }

    #[tokio::test]
    async fn a_render_loop_draw_failure_cancels_the_scan() {
        let cancel = crate::cancel::CancelToken::default();
        let stop = AtomicBool::new(false);

        let error = run_render_loop(
            &mut || Err(std::io::Error::other("frame write failed")),
            &stop,
            &cancel,
        )
        .await
        .unwrap_err();

        assert_eq!(error.to_string(), "frame write failed");
        assert!(cancel.is_cancelled());
    }

    #[tokio::test]
    async fn a_stopped_render_loop_draws_one_final_frame_without_cancelling() {
        let cancel = crate::cancel::CancelToken::default();
        let stop = AtomicBool::new(true);
        let draws = AtomicBool::new(false);

        run_render_loop(
            &mut || {
                draws.store(true, Ordering::Relaxed);
                Ok(())
            },
            &stop,
            &cancel,
        )
        .await
        .unwrap();

        assert!(draws.load(Ordering::Relaxed));
        assert!(!cancel.is_cancelled());
    }

    #[tokio::test]
    async fn a_render_loop_draws_until_it_is_stopped() {
        let cancel = crate::cancel::CancelToken::default();
        let stop = AtomicBool::new(false);
        let draws = std::sync::atomic::AtomicUsize::new(0);

        run_render_loop(
            &mut || {
                draws.fetch_add(1, Ordering::Relaxed);
                stop.store(true, Ordering::Relaxed);
                Ok(())
            },
            &stop,
            &cancel,
        )
        .await
        .unwrap();

        assert_eq!(draws.load(Ordering::Relaxed), 2);
        assert!(!cancel.is_cancelled());
    }

    #[tokio::test]
    async fn a_spawned_render_loop_stopped_up_front_draws_once_without_cancelling() {
        let terminal = fixture_terminal().expect("a fixed viewport needs no host terminal");
        let stop = Arc::new(AtomicBool::new(true));
        let cancel = crate::cancel::CancelToken::default();

        let render_loop =
            spawn_render_loop(terminal, crate::tui::shared_state(), stop, cancel.clone());
        let outcome = render_loop
            .await
            .expect("the render task must finish instead of hanging");

        drop(outcome);
        assert!(
            !cancel.is_cancelled(),
            "a loop stopped before its first tick never cancels the scan"
        );
    }

    #[tokio::test]
    async fn a_spawned_input_loop_stopped_up_front_exits_without_cancelling() {
        let cancel = crate::cancel::CancelToken::default();
        let stop = Arc::new(AtomicBool::new(true));

        let input_loop = spawn_input_loop(cancel.clone(), stop);
        input_loop
            .await
            .expect("the input task must finish instead of hanging");

        assert!(!cancel.is_cancelled());
    }

    #[test]
    fn restoring_an_idle_session_attempts_nothing() {
        let mut session = TerminalSession {
            state: TerminalState::default(),
        };

        session.restore().unwrap();

        assert_eq!(session.state, TerminalState::default());
    }

    #[test]
    fn restoring_a_session_leaves_the_alternate_screen_and_shows_the_cursor() {
        let mut session = TerminalSession {
            state: TerminalState::new(false, true, true),
        };

        session.restore().unwrap();

        assert_eq!(session.state, TerminalState::default());
    }

    #[test]
    fn restoring_a_session_disables_raw_mode() {
        let mut session = TerminalSession {
            state: TerminalState::new(true, false, false),
        };

        session.restore().unwrap();

        assert_eq!(session.state, TerminalState::default());
    }

    fn tui_with_loops(
        render_loop: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
        input_loop: Option<tokio::task::JoinHandle<()>>,
    ) -> Tui {
        Tui {
            stop: Arc::new(AtomicBool::new(false)),
            render_loop,
            input_loop,
            session: Some(TerminalSession {
                state: TerminalState::default(),
            }),
        }
    }

    #[tokio::test]
    async fn stop_signals_the_loops_and_restores_the_session() {
        let tui = tui_with_loops(
            Some(tokio::spawn(async { Ok(()) })),
            Some(tokio::spawn(async {})),
        );
        let stop = tui.stop.clone();

        tui.stop().await.unwrap();

        assert!(stop.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn stopping_a_tui_without_loops_only_sets_the_stop_flag() {
        let mut tui = tui_with_loops(None, None);
        tui.session = None;
        let stop = tui.stop.clone();

        tui.stop().await.unwrap();

        assert!(stop.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn stop_reports_an_input_loop_that_died() {
        let input_loop = tokio::spawn(std::future::pending::<()>());
        input_loop.abort();
        let tui = tui_with_loops(Some(tokio::spawn(async { Ok(()) })), Some(input_loop));

        let error = tui.stop().await.unwrap_err();

        assert!(
            error.to_string().starts_with("TUI input task failed: "),
            "{error}"
        );
    }

    #[tokio::test]
    async fn stop_reports_a_render_loop_that_died() {
        let render_loop = tokio::spawn(std::future::pending::<std::io::Result<()>>());
        render_loop.abort();
        let tui = tui_with_loops(Some(render_loop), Some(tokio::spawn(async {})));

        let error = tui.stop().await.unwrap_err();

        assert!(
            error.to_string().starts_with("TUI render task failed: "),
            "{error}"
        );
    }

    #[tokio::test]
    async fn stop_propagates_a_draw_failure_from_the_render_loop() {
        let tui = tui_with_loops(
            Some(tokio::spawn(async {
                Err(std::io::Error::other("frame write failed"))
            })),
            Some(tokio::spawn(async {})),
        );

        let error = tui.stop().await.unwrap_err();

        assert_eq!(error.to_string(), "frame write failed");
    }

    #[tokio::test]
    async fn stop_reports_the_earliest_failure_when_several_steps_fail() {
        let input_loop = tokio::spawn(std::future::pending::<()>());
        input_loop.abort();
        let tui = tui_with_loops(
            Some(tokio::spawn(async {
                Err(std::io::Error::other("frame write failed"))
            })),
            Some(input_loop),
        );

        let error = tui.stop().await.unwrap_err();

        assert!(
            error.to_string().starts_with("TUI input task failed: "),
            "the input loop fails first: {error}"
        );
    }

    #[tokio::test]
    async fn dropping_a_tui_stops_and_aborts_its_loops() {
        let tui = tui_with_loops(
            Some(tokio::spawn(std::future::pending::<std::io::Result<()>>())),
            Some(tokio::spawn(std::future::pending::<()>())),
        );
        let stop = tui.stop.clone();

        drop(tui);

        assert!(stop.load(Ordering::Acquire));
    }

    #[test]
    fn setup_either_fails_before_creating_a_terminal_or_yields_an_active_session() {
        match setup_terminal() {
            Ok((_terminal, session)) => {
                assert_eq!(session.state, TerminalState::new(true, true, true));
            }
            Err(error) => {
                assert!(!error.to_string().is_empty());
            }
        }
    }

    #[test]
    fn setup_with_backend_propagates_a_stage_failure_and_returns_active_state_on_success() {
        let mut create_terminal = fixture_terminal;

        let outcome = setup_terminal_with_backend(
            &mut || Err(std::io::Error::other("raw mode unavailable")),
            &mut || Ok(()),
            &mut || Ok(()),
            &mut create_terminal,
        );
        let error = match outcome {
            Ok(_) => panic!("a failed stage must not produce a terminal"),
            Err(error) => error,
        };
        assert_eq!(error.to_string(), "raw mode unavailable");

        let (_terminal, session) = setup_terminal_with_backend(
            &mut || Ok(()),
            &mut || Ok(()),
            &mut || Ok(()),
            &mut create_terminal,
        )
        .unwrap();
        assert_eq!(session.state, TerminalState::new(true, true, true));
    }

    #[tokio::test]
    async fn starting_a_tui_either_fails_before_spawning_loops_or_stops_cleanly() {
        match Tui::start(
            crate::tui::shared_state(),
            crate::cancel::CancelToken::default(),
        ) {
            Ok(tui) => tui.stop().await.unwrap(),
            Err(error) => assert!(!error.to_string().is_empty()),
        }
    }
}
