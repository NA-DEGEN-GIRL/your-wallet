//! Local log file (spec/04 §8, spec/01 §5.4, D28).
//!
//! `logs\yw-app.log` rotated through `yw-app.1.log` … `yw-app.4.log` at 1 MiB. One line per
//! event: `<UTC time> <LEVEL> <area> <event> key=value…`, ≤ 1,024 bytes, values limited to
//! 0x21–0x7E (others become `?`). The API takes only static event names and typed fields, so
//! secrets (which have no `Display`), URLs, hosts, origins and labels cannot be passed.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::errors::ErrorCode;
use crate::network::NetworkId;
use crate::settings::LogLevel;

/// Rotation threshold.
pub const LOG_FILE_MAX_BYTES: u64 = 1_048_576;
/// Longest line (bytes, including LF).
pub const LOG_LINE_MAX_BYTES: usize = 1_024;
const ROTATIONS: u8 = 4;

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

fn now_unix_ms() -> u64 {
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

/// The rotating file writer.
#[derive(Debug)]
pub struct LogWriter {
    dir: PathBuf,
    file: Option<File>,
    size: u64,
    buffer: Vec<u8>,
}

fn numbered(dir: &Path, index: u8) -> PathBuf {
    if index == 0 {
        dir.join("yw-app.log")
    } else {
        dir.join(format!("yw-app.{index}.log"))
    }
}

impl LogWriter {
    /// Opens (appends to) `dir\yw-app.log`.
    #[must_use]
    pub fn open(dir: &Path) -> Self {
        let path = numbered(dir, 0);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .ok();
        let size = file
            .as_ref()
            .and_then(|file| file.metadata().ok())
            .map_or(0, |metadata| metadata.len());
        Self {
            dir: dir.to_path_buf(),
            file,
            size,
            buffer: Vec::new(),
        }
    }

    /// Rotates the files. If the current file could not be renamed away (another program holds
    /// it, a `.1` that cannot be replaced), it is truncated instead so it never grows past the
    /// bound, and a `rotate.failed` line says so; if even that fails, file logging stops for this
    /// run (spec/04 §8).
    fn rotate(&mut self) {
        self.flush();
        self.file = None;
        let _ = fs::remove_file(numbered(&self.dir, ROTATIONS));
        for index in (0..ROTATIONS).rev() {
            let _ = fs::rename(numbered(&self.dir, index), numbered(&self.dir, index + 1));
        }
        let current = numbered(&self.dir, 0);
        let renamed = fs::metadata(&current)
            .ok()
            .is_none_or(|metadata| metadata.len() == 0);
        self.file = if renamed {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&current)
                .ok()
        } else {
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&current)
                .ok()
        };
        self.size = 0;
        if !renamed && self.file.is_some() {
            let line = format_line(now_unix_ms(), LogLevel::Warn, "log", "rotate.failed", &[]);
            self.buffer.extend_from_slice(line.as_bytes());
        }
    }

    /// Appends one line, rotating first if it would exceed the bound. A failed rotation truncates
    /// the current file (or stops file logging) instead of letting it grow (spec/04 §8).
    pub fn write_line(&mut self, line: &str, flush_now: bool) {
        let len = u64::try_from(line.len()).unwrap_or(u64::MAX);
        let pending = u64::try_from(self.buffer.len()).unwrap_or(u64::MAX);
        if self.size.saturating_add(pending).saturating_add(len) > LOG_FILE_MAX_BYTES {
            self.rotate();
        }
        self.buffer.extend_from_slice(line.as_bytes());
        if flush_now {
            self.flush();
        }
    }

    /// Writes buffered lines.
    pub fn flush(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        if let Some(file) = self.file.as_mut()
            && file.write_all(&self.buffer).is_ok()
        {
            let _ = file.flush();
            self.size = self
                .size
                .saturating_add(u64::try_from(self.buffer.len()).unwrap_or(0));
        }
        self.buffer.clear();
    }
}

/// The process logger.
#[derive(Debug)]
pub struct Logger {
    writer: Mutex<LogWriter>,
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

/// Installs the process logger writing under `dir` (first call wins).
pub fn init(dir: &Path, level: LogLevel) {
    let _ = LOGGER.set(Logger {
        writer: Mutex::new(LogWriter::open(dir)),
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
    let line = format_line(now_unix_ms(), level, area, event, fields);
    if let Ok(mut writer) = logger.writer.lock() {
        writer.write_line(&line, level <= LogLevel::Warn);
    }
}

/// Flushes buffered lines (every 2 s and at exit).
pub fn flush() {
    if let Some(logger) = LOGGER.get()
        && let Ok(mut writer) = logger.writer.lock()
    {
        writer.flush();
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

#[cfg(test)]
mod tests {
    use super::{Field, LOG_FILE_MAX_BYTES, LogWriter, format_line, format_utc};
    use crate::errors::ErrorCode;
    use crate::network::NetworkId;
    use crate::settings::LogLevel;

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

    #[test]
    fn rotation_keeps_five_files() {
        let dir = std::env::temp_dir().join(format!(
            "yw-app-log-test-{}-{}",
            std::process::id(),
            yw_win::time::monotonic_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut writer = LogWriter::open(&dir);
        let line = format!("{}\n", "x".repeat(1_000));
        let lines_per_file = usize::try_from(LOG_FILE_MAX_BYTES).unwrap() / line.len() + 1;
        for _ in 0..lines_per_file * 6 {
            writer.write_line(&line, true);
        }
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "yw-app.1.log",
                "yw-app.2.log",
                "yw-app.3.log",
                "yw-app.4.log",
                "yw-app.log"
            ]
        );
        for name in &names {
            assert!(std::fs::metadata(dir.join(name)).unwrap().len() <= LOG_FILE_MAX_BYTES);
        }
        drop(writer);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn failed_rotation_truncates_instead_of_growing() {
        let dir = std::env::temp_dir().join(format!(
            "yw-app-log-stuck-{}-{}",
            std::process::id(),
            yw_win::time::monotonic_ms()
        ));
        // `.1`–`.4` are non-empty directories: no rename in the chain can succeed, so the current
        // file stays where it is.
        for index in 1..=4 {
            let blocker = dir.join(format!("yw-app.{index}.log"));
            std::fs::create_dir_all(&blocker).unwrap();
            std::fs::write(blocker.join("keep"), b"x").unwrap();
        }
        let mut writer = LogWriter::open(&dir);
        let line = format!("{}\n", "y".repeat(1_000));
        let lines_per_file = usize::try_from(LOG_FILE_MAX_BYTES).unwrap() / line.len() + 1;
        for _ in 0..lines_per_file * 3 {
            writer.write_line(&line, true);
        }
        let current = dir.join("yw-app.log");
        let size = std::fs::metadata(&current).unwrap().len();
        assert!(size <= LOG_FILE_MAX_BYTES, "{size}");
        let text = std::fs::read_to_string(&current).unwrap();
        assert!(text.contains(" WARN log rotate.failed\n"));
        assert!(text.ends_with(&line));
        drop(writer);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
