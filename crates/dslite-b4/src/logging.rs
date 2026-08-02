//! A per-event stderr writer that enforces one physical line per event.
//!
//! `tracing-subscriber` sanitizes ANSI terminal controls, but intentionally
//! leaves line breaks and some other control characters unchanged. This
//! writer escapes every embedded control character and preserves only the
//! formatter's final newline.

use std::io::{self, Write};

use dslite_b4::config::LogLevel;
use tracing_subscriber::fmt::MakeWriter;

pub(crate) fn init(level: LogLevel) {
    let default_filter = format!("dslite_b4={}", level.as_str());
    tracing_subscriber::fmt()
        .compact()
        .with_ansi(false)
        .with_writer(SanitizedStderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| default_filter.parse().unwrap()),
        )
        .init();
}

#[derive(Clone, Copy)]
pub(crate) struct SanitizedStderr;

pub(crate) struct SanitizedEvent {
    bytes: Vec<u8>,
}

impl<'a> MakeWriter<'a> for SanitizedStderr {
    type Writer = SanitizedEvent;

    fn make_writer(&'a self) -> Self::Writer {
        SanitizedEvent { bytes: Vec::new() }
    }
}

impl Write for SanitizedEvent {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for SanitizedEvent {
    fn drop(&mut self) {
        let clean = sanitize(&self.bytes);
        let _ = io::stderr().lock().write_all(clean.as_bytes());
    }
}

fn sanitize(bytes: &[u8]) -> String {
    let terminal_newline = bytes.last() == Some(&b'\n');
    let content = if terminal_newline {
        &bytes[..bytes.len() - 1]
    } else {
        bytes
    };
    let text = String::from_utf8_lossy(content);
    let mut clean = String::with_capacity(text.len() + 1);
    for character in text.chars() {
        match character {
            '\n' => clean.push_str("\\n"),
            '\r' => clean.push_str("\\r"),
            '\t' => clean.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(clean, "\\u{{{:x}}}", character as u32);
            }
            character => clean.push(character),
        }
    }
    clean.push('\n');
    clean
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_one_physical_line_and_escapes_controls() {
        assert_eq!(
            sanitize(b"first\nsecond\r\x1b[31m\n"),
            "first\\nsecond\\r\\u{1b}[31m\n"
        );
    }
}
