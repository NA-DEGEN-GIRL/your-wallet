//! The Android log file (spec/15 §3.3, spec/04 §8, D28; 2026-11-25 A2-4b): the [`LogSink`] behind
//! the `yw_engine::logging` facade, `noBackupFilesDir/v3/logs/yw.log` rotated through `yw.1.log` …
//! `yw.4.log` at 1 MiB, as the Windows `log_file::LogWriter` (yw-app). It stores only the finished,
//! sanitized lines of `logging::format_line`; nothing goes to logcat (the app has no logcat writer
//! at all: libyw.so does not link `liblog`).
//!
//! A failed rotation truncates the current file (and says so with `rotate.failed`) instead of
//! letting it grow; if even that fails, file logging stops for the run. Files are created `0600`
//! in a `0700` folder inside the app's own data. Platform-neutral std code (the gate tests it in a
//! temporary folder).
#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use yw_engine::logging::{LogLevel, LogSink, format_line_now};

/// Rotation threshold.
pub const LOG_FILE_MAX_BYTES: u64 = 1_048_576;
/// Older files kept.
const ROTATIONS: u8 = 4;

fn numbered(dir: &Path, index: u8) -> PathBuf {
    if index == 0 {
        dir.join("yw.log")
    } else {
        dir.join(format!("yw.{index}.log"))
    }
}

/// Opens for appending (or truncating), owner-only on unix.
fn open(path: &Path, truncate: bool) -> Option<File> {
    let mut options = OpenOptions::new();
    options.create(true);
    if truncate {
        options.write(true).truncate(true);
    } else {
        options.append(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).ok()
}

/// The rotating log file.
#[derive(Debug)]
pub struct LogFile {
    dir: PathBuf,
    file: Option<File>,
    size: u64,
    buffer: Vec<u8>,
}

impl LogFile {
    /// Opens (appends to) `dir/yw.log`, creating `dir` (owner-only on unix).
    #[must_use]
    pub fn open(dir: &Path) -> Self {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        let file = builder
            .create(dir)
            .ok()
            .and_then(|()| open(&numbered(dir, 0), false));
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

    fn rotate(&mut self) {
        self.flush_buffer();
        self.file = None;
        let _ = fs::remove_file(numbered(&self.dir, ROTATIONS));
        for index in (0..ROTATIONS).rev() {
            let _ = fs::rename(numbered(&self.dir, index), numbered(&self.dir, index + 1));
        }
        let current = numbered(&self.dir, 0);
        let renamed = fs::metadata(&current)
            .ok()
            .is_none_or(|metadata| metadata.len() == 0);
        self.file = open(&current, !renamed);
        self.size = 0;
        if !renamed && self.file.is_some() {
            let line = format_line_now(LogLevel::Warn, "log", "rotate.failed", &[]);
            self.buffer.extend_from_slice(line.as_bytes());
        }
    }

    fn flush_buffer(&mut self) {
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

impl LogSink for LogFile {
    fn write_line(&mut self, line: &str, flush_now: bool) {
        let len = u64::try_from(line.len()).unwrap_or(u64::MAX);
        let pending = u64::try_from(self.buffer.len()).unwrap_or(u64::MAX);
        if self.size.saturating_add(pending).saturating_add(len) > LOG_FILE_MAX_BYTES {
            self.rotate();
        }
        self.buffer.extend_from_slice(line.as_bytes());
        if flush_now {
            self.flush_buffer();
        }
    }

    fn flush(&mut self) {
        self.flush_buffer();
    }
}

#[cfg(test)]
mod tests {
    use yw_engine::logging::{LogLevel, LogSink, format_line};

    use super::{LOG_FILE_MAX_BYTES, LogFile};

    #[test]
    fn lines_rotate_at_the_bound() {
        let dir = std::env::temp_dir().join(format!("yw-android-log-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut log = LogFile::open(&dir);
        let line = format_line(0, LogLevel::Info, "app", "app.start", &[]);
        log.write_line(&line, true);
        assert_eq!(std::fs::read_to_string(dir.join("yw.log")).unwrap(), line);
        let lines = usize::try_from(LOG_FILE_MAX_BYTES).unwrap() / line.len() + 2;
        for _ in 0..lines {
            log.write_line(&line, false);
        }
        log.flush();
        assert!(dir.join("yw.1.log").is_file());
        let current = std::fs::metadata(dir.join("yw.log")).unwrap().len();
        assert!(current < LOG_FILE_MAX_BYTES);
        drop(log);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
