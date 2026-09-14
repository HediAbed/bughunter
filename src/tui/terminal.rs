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

fn spawn_render_loop(
    mut terminal: TuiTerminal,
    state: SharedState,
    stop: Arc<AtomicBool>,
    cancel: CancelToken,
) -> tokio::task::JoinHandle<io::Result<()>> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(RENDER_INTERVAL);
        while !stop.load(Ordering::Acquire) {
            ticker.tick().await;
            if let Err(error) = draw(&mut terminal, &state) {
                cancel.cancel();
                return Err(error);
            }
        }
        draw(&mut terminal, &state)
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
    if !event::poll(timeout)? {
        return Ok(Action::Ignore);
    }
    Ok(action_for(&event::read()?))
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
    let mut rollback = |state| {
        let mut session = TerminalSession { state };
        let _ = session.restore();
    };
    let (terminal, state) = setup_terminal_with(
        &mut enable,
        &mut enter_screen,
        &mut hide_cursor,
        &mut create_terminal,
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
        Action, INPUT_POLL_INTERVAL, TerminalState, action_for, restore_state_with, run_input_loop,
        setup_terminal_with,
    };
    use ratatui::crossterm::event::{
        Event, KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers, MouseButton,
        MouseEvent, MouseEventKind,
    };
    use std::sync::atomic::{AtomicBool, Ordering};

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
    fn restoration_attempts_every_active_transition_and_keeps_failed_ones_active() {
        let mut state = TerminalState::new(true, true, true);
        let events = std::cell::RefCell::new(Vec::new());

        let error = restore_state_with(
            &mut state,
            &mut || {
                events.borrow_mut().push("raw");
                Err(std::io::Error::other("raw restore failed"))
            },
            &mut || {
                events.borrow_mut().push("screen");
                Ok(())
            },
            &mut || {
                events.borrow_mut().push("cursor");
                Err(std::io::Error::other("cursor restore failed"))
            },
        )
        .unwrap_err();

        assert_eq!(error.to_string(), "raw restore failed");
        assert_eq!(*events.borrow(), ["raw", "screen", "cursor"]);
        assert_eq!(state, TerminalState::new(true, false, true));
    }
}
