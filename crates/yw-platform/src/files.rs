//! The file seam of the wallet data folder (spec/02 §6.2, spec/15 §5.1, §11.2).
//!
//! 2026-11-25 (spec/15 §17 A2-4a): the few file operations yw-engine's
//! `file_storage::FileStorage` (the atomic commit temp → flush → replace → folder flush, the
//! `.prev` rotation, the set-aside copies, the link refusal) needs, so the same storage logic runs
//! on every platform. Windows implements it for `yw_win::file::WinFiles` over the unchanged
//! `yw_win::file` functions; Android implements it in yw-android (A2-4b). Before, the logic was
//! yw-app `store::FileStorage` calling `yw_win::file` directly.
//!
//! Nothing here touches a file: the trait only names the operations (the crate's `clippy.toml`
//! bans file access). Errors carry no path.

use core::fmt;
use std::ffi::OsString;
use std::io;
use std::path::Path;

/// A file operation's failure. Carries no path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsError {
    /// The file or folder does not exist.
    NotFound,
    /// The path (or the folder) is a link the storage never follows (Windows: a reparse point,
    /// a symlink or a junction).
    Link,
    /// The file is larger than the limit.
    TooLarge,
    /// An OS call failed with this code (Windows: the Win32 error code).
    Os(u32),
    /// A std I/O call failed.
    Io(io::ErrorKind),
}

impl fmt::Display for FsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => formatter.write_str("file not found"),
            Self::Link => formatter.write_str("link rejected"),
            Self::TooLarge => formatter.write_str("file too large"),
            Self::Os(code) => write!(formatter, "OS error {code}"),
            Self::Io(kind) => write!(formatter, "I/O error: {kind:?}"),
        }
    }
}

impl std::error::Error for FsError {}

/// The file operations of the wallet data folder. Every path is inside the one folder the
/// storage was opened on (or is that folder).
pub trait Files: Send {
    /// Creates `dir` and its parents when missing, and refuses a final component that is a link.
    ///
    /// # Errors
    ///
    /// [`FsError::Link`] or the failing I/O error.
    fn ensure_dir(&self, dir: &Path) -> Result<(), FsError>;

    /// `Err(Link)` when `path` exists and is a link; `Ok` when it is absent or ordinary.
    ///
    /// # Errors
    ///
    /// [`FsError::Link`] or an I/O error other than "not found".
    fn reject_link(&self, path: &Path) -> Result<(), FsError>;

    /// Reads `path` (at most `max` bytes) without following a link at `path` itself.
    ///
    /// # Errors
    ///
    /// [`FsError::NotFound`], [`FsError::Link`], [`FsError::TooLarge`] or an I/O error.
    fn read_limited_no_follow(&self, path: &Path, max: u64) -> Result<Vec<u8>, FsError>;

    /// Writes `bytes` to `path`, which must not exist (create-new), makes them durable and
    /// closes the file. A failed write removes the partial file.
    ///
    /// # Errors
    ///
    /// `Io(AlreadyExists)` when `path` exists, or the failing I/O error.
    fn write_new_synced(&self, path: &Path, bytes: &[u8]) -> Result<(), FsError>;

    /// Atomically renames `from` over `to` (replacing it), written through.
    ///
    /// # Errors
    ///
    /// [`FsError::NotFound`] or the failing OS error.
    fn replace(&self, from: &Path, to: &Path) -> Result<(), FsError>;

    /// Renames `from` to `to`, written through; fails when `to` exists (never overwrites).
    ///
    /// # Errors
    ///
    /// [`FsError::NotFound`] or the failing OS error.
    fn rename_no_replace(&self, from: &Path, to: &Path) -> Result<(), FsError>;

    /// Makes the renames inside `dir` durable (flushes the folder itself), refusing a folder that
    /// is a link.
    ///
    /// # Errors
    ///
    /// [`FsError::Link`] or the failing I/O error.
    fn flush_dir(&self, dir: &Path) -> Result<(), FsError>;

    /// Deletes the file `path`.
    ///
    /// # Errors
    ///
    /// [`FsError::NotFound`] when it is absent, or the failing I/O error.
    fn remove_file(&self, path: &Path) -> Result<(), FsError>;

    /// Whether `path` exists (a metadata check that follows a link, like `Path::exists`).
    fn exists(&self, path: &Path) -> bool;

    /// Whether `path` is a regular file (following a link, like `Path::is_file`).
    fn is_file(&self, path: &Path) -> bool;

    /// The names of the entries directly in `dir`, in the order the OS lists them.
    ///
    /// # Errors
    ///
    /// The failing I/O error of the listing or of an entry.
    fn list_dir(&self, dir: &Path) -> Result<Vec<OsString>, FsError>;
}
