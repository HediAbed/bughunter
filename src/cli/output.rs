use std::io::{self, Write};
use std::path::PathBuf;

use crate::errors::{BugHunterError, ReportError};

pub fn print_version() -> Result<(), BugHunterError> {
    print_line(&format!(
        "{} {}",
        crate::version::NAME,
        crate::version::VERSION
    ))
}

pub fn print_line(message: &str) -> Result<(), BugHunterError> {
    let stdout = io::stdout();
    let mut stream = stdout.lock();
    let sanitized = crate::shared::sanitize_terminal_text(message);
    write_line(&mut stream, &sanitized).map_err(stdout_write_error)
}

fn write_line(stream: &mut impl Write, message: &str) -> std::io::Result<()> {
    writeln!(stream, "{message}")?;
    stream.flush()
}

fn stdout_write_error(source: std::io::Error) -> BugHunterError {
    ReportError::WriteError {
        path: PathBuf::from("stdout"),
        source,
    }
    .into()
}

pub fn print_error(message: &str) {
    let _ = writeln!(
        io::stderr(),
        "error: {}",
        crate::shared::sanitize_terminal_text(message)
    );
}

pub fn print_status(message: &str) {
    let _ = writeln!(
        io::stderr(),
        "{}",
        crate::shared::sanitize_terminal_text(message)
    );
}
