//! The log facade (spec/04 §8, spec/01 §5.4, D28).
//!
//! One line per event: `<UTC time> <LEVEL> <area> <event> key=value…`, ≤ 1,024 bytes, values
//! limited to 0x21–0x7E (others become `?`). The API takes only static event names and typed
//! fields, so secrets (which have no `Display`), URLs, hosts, origins and labels cannot be passed.
//!
//! (2026-11-17, spec/15 §11.4 S2: the facade is split from the file writer. This module formats
//! and filters; a platform [`LogSink`], installed once with [`install`], only stores lines that
//! [`format_line`] already sanitized. On Windows the sink is the rotating `logs\yw-app.log`
//! writer of `log_file`. Before that, `LogWriter` and `init` lived here.)

use std::panic::Location;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use crate::errors::ErrorCode;
use crate::network::NetworkId;

/// Longest line (bytes, including LF).
pub const LOG_LINE_MAX_BYTES: usize = 1_024;

/// `logLevel` (the setting, spec/04 §6; `settings` re-exports it).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    /// `error`.
    Error,
    /// `warn`.
    Warn,
    /// `info`.
    Info,
    /// `debug`.
    Debug,
}

impl LogLevel {
    /// Settings string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }

    /// Parses the settings string.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "error" => Some(Self::Error),
            "warn" => Some(Self::Warn),
            "info" => Some(Self::Info),
            "debug" => Some(Self::Debug),
            _ => None,
        }
    }
}

/// Whether `text` is a commit id this app shows: 7–40 lowercase hex digits ([`Field::Commit`],
/// and the installation record of `build_info`).
#[must_use]
pub fn is_commit(text: &str) -> bool {
    (7..=40).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A typed log field value.
#[derive(Clone, Copy, Debug)]
pub enum Field<'a> {
    /// A static word (enum name, reason, state).
    Word(&'static str),
    /// A network identifier.
    Net(NetworkId),
    /// An error code.
    Code(ErrorCode),
    /// A number.
    Num(u64),
    /// A signed number (JSON-RPC error codes).
    Int(i64),
    /// An EVM address (allowed by D28): 20 raw bytes, written as lowercase hex.
    Address(&'a [u8; 20]),
    /// A transaction hash (allowed by D28): written as `0x` + lowercase hex.
    Hash(&'a [u8; 32]),
    /// A Bitcoin txid (allowed by D28): display-order lowercase hex without prefix.
    BtcTxid(yw_core::btc::Txid),
    /// The LLM endpoint `host[:port]` (spec/01 §5.4, spec/06 §8): never an RPC host, never a
    /// path or query.
    LlmHost(&'a str),
    /// A source location, written `file:line` (the panic hook, [`panic_line`]): where in the code,
    /// never a value.
    Source(&'a Location<'a>),
    /// The installed commit (`build_info`): written only when it is 7–40 lowercase hex digits
    /// ([`is_commit`]), else `?`.
    Commit(&'a str),
}

/// UTC `YYYY-MM-DDTHH:MM:SS.mmmZ` from Unix milliseconds.
#[must_use]
pub fn format_utc(unix_ms: u64) -> String {
    let millis = unix_ms % 1_000;
    let seconds = unix_ms / 1_000;
    let days = seconds / 86_400;
    let rem = seconds % 86_400;
    let (hour, minute, second) = (rem / 3_600, (rem % 3_600) / 60, rem % 60);
    // Civil-from-days (H. Hinnant), valid for the Unix era.
    let z = days.saturating_add(719_468);
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// One sanitized line stamped with the current time, for a sink's own lines (a failed rotation).
///
/// (2026-11-17 E1 review: before this, the line clock itself was public as `now_unix_ms`, which
/// any engine module could have used as an unrestricted wall clock. Now only log lines read it.)
#[must_use]
pub fn format_line_now(
    level: LogLevel,
    area: &'static str,
    event: &'static str,
    fields: &[(&'static str, Field<'_>)],
) -> String {
    format_line(log_line_unix_ms(), level, area, event, fields)
}

/// The wall clock of the line timestamps (Unix milliseconds; 0 before 1970). Private: the
/// engine's other time comes from `yw_platform::Clock`.
#[expect(
    clippy::disallowed_types,
    reason = "log line timestamps only (spec/01 §5.1): never compared with a deadline"
)]
fn log_line_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

const fn level_word(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Error => "ERROR",
        LogLevel::Warn => "WARN",
        LogLevel::Info => "INFO",
        LogLevel::Debug => "DEBUG",
    }
}

fn push_sanitized(line: &mut String, text: &str) {
    for character in text.chars() {
        line.push(if ('\u{21}'..='\u{7E}').contains(&character) {
            character
        } else {
            '?'
        });
    }
}

/// Formats one line (without timestamp source dependency) — pure, for tests.
#[must_use]
pub fn format_line(
    unix_ms: u64,
    level: LogLevel,
    area: &'static str,
    event: &'static str,
    fields: &[(&'static str, Field<'_>)],
) -> String {
    let mut line = String::with_capacity(128);
    line.push_str(&format_utc(unix_ms));
    line.push(' ');
    line.push_str(level_word(level));
    line.push(' ');
    push_sanitized(&mut line, area);
    line.push(' ');
    push_sanitized(&mut line, event);
    for (key, value) in fields {
        line.push(' ');
        push_sanitized(&mut line, key);
        line.push('=');
        match value {
            Field::Word(word) => push_sanitized(&mut line, word),
            Field::Net(network) => push_sanitized(&mut line, &network.to_string()),
            Field::Code(code) => push_sanitized(&mut line, code.code()),
            Field::Num(number) => line.push_str(&number.to_string()),
            Field::Int(number) => line.push_str(&number.to_string()),
            Field::Address(bytes) => {
                line.push_str("0x");
                line.push_str(&yw_core::hex::encode(bytes.as_slice()));
            }
            Field::Hash(bytes) => {
                line.push_str("0x");
                line.push_str(&yw_core::hex::encode(bytes.as_slice()));
            }
            Field::BtcTxid(txid) => line.push_str(&txid.to_display_hex()),
            Field::LlmHost(host) => {
                let authority = host.split(['/', '?', '#']).next().unwrap_or("");
                push_sanitized(&mut line, authority);
            }
            Field::Source(location) => {
                push_sanitized(&mut line, location.file());
                line.push(':');
                line.push_str(&location.line().to_string());
            }
            Field::Commit(commit) => {
                if is_commit(commit) {
                    line.push_str(commit);
                } else {
                    line.push('?');
                }
            }
        }
    }
    if line.len() > LOG_LINE_MAX_BYTES - 1 {
        let mut cut = LOG_LINE_MAX_BYTES - 1;
        while !line.is_char_boundary(cut) {
            cut -= 1;
        }
        line.truncate(cut);
    }
    line.push('\n');
    line
}

/// Where finished lines go (the platform's log store; Windows: `log_file::LogWriter`). It only
/// receives lines that [`format_line`] built and sanitized, never raw text (D28).
pub trait LogSink: Send {
    /// Stores one finished line (ending in LF). `flush_now` is set for `warn` and above.
    fn write_line(&mut self, line: &str, flush_now: bool);
    /// Writes buffered lines (every 2 s and at exit).
    fn flush(&mut self);
}

/// The process logger.
struct Logger {
    sink: Mutex<Box<dyn LogSink>>,
    level: AtomicU8,
}

static LOGGER: OnceLock<Logger> = OnceLock::new();

const fn level_rank(level: LogLevel) -> u8 {
    match level {
        LogLevel::Error => 0,
        LogLevel::Warn => 1,
        LogLevel::Info => 2,
        LogLevel::Debug => 3,
    }
}

/// Installs the process logger's sink (first call wins). Lines logged before it are dropped.
pub fn install(sink: Box<dyn LogSink>, level: LogLevel) {
    let _ = LOGGER.set(Logger {
        sink: Mutex::new(sink),
        level: AtomicU8::new(level_rank(level)),
    });
}

/// Changes the minimum level (applies from the next line).
pub fn set_level(level: LogLevel) {
    if let Some(logger) = LOGGER.get() {
        logger.level.store(level_rank(level), Ordering::Relaxed);
    }
}

/// Logs one event. `warn` and above are flushed immediately.
pub fn log(
    level: LogLevel,
    area: &'static str,
    event: &'static str,
    fields: &[(&'static str, Field<'_>)],
) {
    let Some(logger) = LOGGER.get() else {
        return;
    };
    if level_rank(level) > logger.level.load(Ordering::Relaxed) {
        return;
    }
    let line = format_line(log_line_unix_ms(), level, area, event, fields);
    if let Ok(mut sink) = logger.sink.lock() {
        sink.write_line(&line, level <= LogLevel::Warn);
    }
}

/// Flushes buffered lines (every 2 s and at exit).
pub fn flush() {
    if let Some(logger) = LOGGER.get()
        && let Ok(mut sink) = logger.sink.lock()
    {
        sink.flush();
    }
}

/// `info` shorthand.
pub fn info(area: &'static str, event: &'static str, fields: &[(&'static str, Field<'_>)]) {
    log(LogLevel::Info, area, event, fields);
}

/// `warn` shorthand.
pub fn warn(area: &'static str, event: &'static str, fields: &[(&'static str, Field<'_>)]) {
    log(LogLevel::Warn, area, event, fields);
}

/// How often [`panic_line`] tries the logger, 1 ms apart.
const PANIC_LOCK_TRIES: u32 = 10;

/// The panic hook's line (spec/04 §1.5, §8): `ERROR app app.panic at=<file>:<line>`, never the
/// message (it may carry values), written at once with the lines buffered before it (they would
/// be lost: the process aborts right after). The logger is only tried, briefly: this thread may
/// have panicked while holding it.
pub fn panic_line(location: Option<&Location<'_>>) {
    let Some(logger) = LOGGER.get() else {
        return;
    };
    let at = location.map(|location| ("at", Field::Source(location)));
    let line = format_line(
        log_line_unix_ms(),
        LogLevel::Error,
        "app",
        "app.panic",
        at.as_slice(),
    );
    for _ in 0..PANIC_LOCK_TRIES {
        if let Ok(mut sink) = logger.sink.try_lock() {
            sink.write_line(&line, true);
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(test)]
mod tests {
    use super::{Field, LogLevel, format_line, format_utc, is_commit};
    use crate::errors::ErrorCode;
    use crate::network::NetworkId;

    #[test]
    fn utc_formatting() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(format_utc(1_793_017_696_789), "2026-10-26T12:28:16.789Z");
        assert_eq!(format_utc(951_782_400_000), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn line_format_matches_spec_example_shape() {
        let line = format_line(
            1_793_018_096_789,
            LogLevel::Warn,
            "rpc",
            "E-RPC-002",
            &[
                ("method", Field::Word("eth_simulateV1")),
                ("net", Field::Net(NetworkId::Eip155(11_155_111))),
                ("ms", Field::Num(12_000)),
                ("code", Field::Code(ErrorCode::Rpc002)),
            ],
        );
        assert_eq!(
            line,
            "2026-10-26T12:34:56.789Z WARN rpc E-RPC-002 method=eth_simulateV1 net=eip155:11155111 ms=12000 code=E-RPC-002\n"
        );
        let sanitized = format_line(
            0,
            LogLevel::Info,
            "a",
            "b",
            &[("k", Field::Word("x y\u{e9}"))],
        );
        assert!(sanitized.ends_with("k=x?y?\n"));
        let long = [(
            "k",
            Field::Word("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ); 40];
        assert_eq!(format_line(0, LogLevel::Info, "a", "b", &long).len(), 1_024);
    }

    /// A commit field is written only when it is 7–40 lowercase hex digits.
    #[test]
    fn commit_field_is_checked() {
        assert!(is_commit("75c3136"));
        assert!(!is_commit("75C3136"));
        assert!(!is_commit("75c313"));
        let line =
            |commit| format_line(0, LogLevel::Info, "a", "b", &[("c", Field::Commit(commit))]);
        assert!(line("75c3136a1b2c").ends_with(" c=75c3136a1b2c\n"));
        assert!(line("75c3136 x").ends_with(" c=?\n"));
    }

    #[test]
    fn level_strings_round_trip() {
        for level in [
            LogLevel::Error,
            LogLevel::Warn,
            LogLevel::Info,
            LogLevel::Debug,
        ] {
            assert_eq!(LogLevel::parse(level.as_str()), Some(level));
        }
        assert_eq!(LogLevel::parse("trace"), None);
    }
}
