//! The Windows log file (spec/04 §8, D28): the [`LogSink`] behind the `logging` facade.
//!
//! `logs\yw-app.log` rotated through `yw-app.1.log` … `yw-app.4.log` at 1 MiB. It stores only the
//! finished, sanitized lines of `logging::format_line`.
//!
//! (2026-11-17, spec/15 §11.4 S2: moved unchanged out of `logging`, which keeps the formatting,
//! the level filter and the process logger.)

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::logging::{self, LogLevel, LogSink, format_line_now};

/// Rotation threshold.
pub const LOG_FILE_MAX_BYTES: u64 = 1_048_576;
const ROTATIONS: u8 = 4;

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
            let line = format_line_now(LogLevel::Warn, "log", "rotate.failed", &[]);
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

impl LogSink for LogWriter {
    fn write_line(&mut self, line: &str, flush_now: bool) {
        Self::write_line(self, line, flush_now);
    }

    fn flush(&mut self) {
        Self::flush(self);
    }
}

/// Installs the process logger writing under `dir` (first call wins).
pub fn init(dir: &Path, level: LogLevel) {
    logging::install(Box::new(LogWriter::open(dir)), level);
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::{LOG_FILE_MAX_BYTES, LogWriter};

    /// A fresh temp folder name: process id + a counter (2026-11-17; before, `monotonic_ms`).
    fn temp_dir(tag: &str) -> std::path::PathBuf {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        std::env::temp_dir().join(format!(
            "yw-app-log-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn rotation_keeps_five_files() {
        let dir = temp_dir("test");
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
        let dir = temp_dir("stuck");
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
