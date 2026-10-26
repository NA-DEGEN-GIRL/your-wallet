#![allow(unsafe_code)]
//! Durable file writes (spec.md §4.3, spec/01 §7.2).
//!
//! Pattern ported from `archive/spec-v2.4:demo/sepolia-wallet/src/backend.rs:6148-6403`
//! (`write_new_file`, `DurableParentDirectory`): create-new → write → `FlushFileBuffers` → close →
//! `MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)` → flush the parent directory. The building
//! blocks are public so yw-app's `VaultStorage` can stop between steps (spec/02 §6.2, V-FS).

use core::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_READ, FILE_SHARE_WRITE,
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};

use crate::error::WinError;
use crate::wide::path_wide;

/// Largest payload accepted by [`atomic_write`] (64 MiB).
pub const ATOMIC_WRITE_MAX: usize = 64 * 1_024 * 1_024;

/// File operation failure. Carries no path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileError {
    /// The file or directory does not exist.
    NotFound,
    /// The target or its parent is a reparse point (symlink, junction).
    ReparsePoint,
    /// The data exceeds the limit.
    TooLarge,
    /// A Win32 call failed.
    Os(WinError),
    /// A std I/O call failed.
    Io(io::ErrorKind),
}

impl fmt::Display for FileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => formatter.write_str("file not found"),
            Self::ReparsePoint => formatter.write_str("reparse point rejected"),
            Self::TooLarge => formatter.write_str("file too large"),
            Self::Os(error) => write!(formatter, "{error}"),
            Self::Io(kind) => write!(formatter, "I/O error: {kind:?}"),
        }
    }
}

impl std::error::Error for FileError {}

impl From<io::Error> for FileError {
    fn from(error: io::Error) -> Self {
        if error.kind() == io::ErrorKind::NotFound {
            Self::NotFound
        } else {
            Self::Io(error.kind())
        }
    }
}

/// `<path>.tmp` (the temporary file always lives in the same directory).
#[must_use]
pub fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".tmp");
    PathBuf::from(name)
}

/// `Err(ReparsePoint)` when `path` exists and is a reparse point; `Ok` when absent or ordinary.
///
/// # Errors
///
/// [`FileError::ReparsePoint`] or an I/O error other than "not found".
pub fn reject_reparse_point(path: &Path) -> Result<(), FileError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 => {
            Err(FileError::ReparsePoint)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Writes `bytes` to `path`, which must not exist (`CREATE_NEW`, share mode 0), then
/// `FlushFileBuffers` and closes. A failed write removes the partial file.
///
/// # Errors
///
/// `Io(AlreadyExists)` when `path` exists, or the failing I/O error.
pub fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<(), FileError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .open(path)?;
    let result = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(path);
        return Err(error.into());
    }
    Ok(())
}

fn move_file(from: &Path, to: &Path, flags: u32) -> Result<(), FileError> {
    let from_wide = path_wide(from, "MoveFileExW").map_err(FileError::Os)?;
    let to_wide = path_wide(to, "MoveFileExW").map_err(FileError::Os)?;
    // SAFETY: Both paths are NUL-terminated UTF-16 buffers that live across the call.
    let ok = unsafe { MoveFileExW(from_wide.as_ptr(), to_wide.as_ptr(), flags) };
    if ok == 0 {
        let error = WinError::last("MoveFileExW");
        return Err(match error.code {
            2 | 3 => FileError::NotFound,
            _ => FileError::Os(error),
        });
    }
    Ok(())
}

/// `MoveFileExW(from, to, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`.
///
/// # Errors
///
/// [`FileError::NotFound`] or [`FileError::Os`].
pub fn replace_file(from: &Path, to: &Path) -> Result<(), FileError> {
    move_file(from, to, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)
}

/// `MoveFileExW(from, to, MOVEFILE_WRITE_THROUGH)`: fails when `to` exists (never overwrites).
///
/// # Errors
///
/// [`FileError::NotFound`] or [`FileError::Os`] (e.g. `ERROR_ALREADY_EXISTS`).
pub fn rename_no_replace(from: &Path, to: &Path) -> Result<(), FileError> {
    move_file(from, to, MOVEFILE_WRITE_THROUGH)
}

/// Opens `dir` with `FILE_FLAG_BACKUP_SEMANTICS` and `GENERIC_WRITE` and calls `FlushFileBuffers`
/// so a rename inside it is durable (NTFS).
///
/// # Errors
///
/// [`FileError::ReparsePoint`] or the failing I/O error.
pub fn flush_dir(dir: &Path) -> Result<(), FileError> {
    let directory = OpenOptions::new()
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(dir)?;
    if directory.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(FileError::ReparsePoint);
    }
    directory.sync_all()?;
    Ok(())
}

/// Atomically replaces `path` with `bytes` (≤ 64 MiB): reject reparse points → delete a leftover
/// `<path>.tmp` → create-new/write/flush/close the temporary → `MoveFileExW(REPLACE_EXISTING |
/// WRITE_THROUGH)` → flush the parent. On a failure in the write or move the temporary is removed
/// and the original error returned.
///
/// # Errors
///
/// [`FileError`].
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), FileError> {
    if bytes.len() > ATOMIC_WRITE_MAX {
        return Err(FileError::TooLarge);
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(FileError::Io(io::ErrorKind::InvalidInput))?;
    reject_reparse_point(parent)?;
    reject_reparse_point(path)?;
    let tmp = tmp_path(path);
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    write_new_synced(&tmp, bytes)?;
    if let Err(error) = replace_file(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    flush_dir(parent)
}

/// Reads `path` if it is at most `max` bytes.
///
/// # Errors
///
/// [`FileError::NotFound`], [`FileError::TooLarge`] or an I/O error.
pub fn read_limited(path: &Path, max: u64) -> Result<Vec<u8>, FileError> {
    let file = File::open(path)?;
    if file.metadata()?.len() > max {
        return Err(FileError::TooLarge);
    }
    let mut bytes = Vec::new();
    file.take(max.saturating_add(1)).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_or(true, |len| len > max) {
        return Err(FileError::TooLarge);
    }
    Ok(bytes)
}

/// `create_dir_all(path)`, rejecting a final component that is a reparse point.
///
/// # Errors
///
/// [`FileError::ReparsePoint`] or an I/O error.
pub fn ensure_dir(path: &Path) -> Result<(), FileError> {
    fs::create_dir_all(path)?;
    reject_reparse_point(path)
}

#[cfg(test)]
mod tests {
    use super::tmp_path;
    use std::path::Path;

    #[test]
    fn tmp_path_appends_suffix_in_same_directory() {
        assert_eq!(
            tmp_path(Path::new(r"C:\a\vault.ywv")),
            Path::new(r"C:\a\vault.ywv.tmp")
        );
    }
}
