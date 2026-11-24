//! The Android [`Files`] of the wallet data folder (spec/15 §5.1, spec/02 §6.2; 2026-11-25 A2-4b):
//! std file calls with `libc` flags, no `unsafe`.
//!
//! - Reads open the file itself with `O_NOFOLLOW` (a link fails with `ELOOP` → [`FsError::Link`])
//!   and `O_NONBLOCK` (a FIFO planted under a wallet name cannot block the read), then refuse
//!   anything that is not a regular file, and read at most the limit.
//! - New files are `O_CREAT | O_EXCL | O_NOFOLLOW`, mode `0600`, written, `fsync`ed and closed; a
//!   failed write removes the partial file. Folders are made `0700`.
//! - `replace` is `rename(2)` (atomic, replaces); durability comes from [`Files::flush_dir`], an
//!   `fsync` of the folder opened `O_DIRECTORY | O_NOFOLLOW`.
//! - `rename_no_replace` checks that the target is absent (`lstat`, a link counts as present) and
//!   then `rename(2)`s. Only quarantine and the `.prev` set-aside use it, with a fresh
//!   `.corrupt-<t>` name, and the one writer of the folder is the key worker, so nothing races the
//!   check. The atomic ways are not open to the app: `renameat2(RENAME_NOREPLACE)` has no bionic
//!   wrapper before API 30 (the app's seccomp filter on API 29 is not known to allow the raw
//!   call), and `link(2)` + `unlink(2)` was refused on the test device with `EPERM`/`EACCES`
//!   (2026-11-25, spec/09 §2.6; most likely the platform policy against app hard links), so it
//!   is not tried.
//! - Errors keep the errno (`FsError::Os`), never a path (D28).
#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

use yw_platform::files::{Files, FsError};

/// The data folder's files on Android.
#[derive(Clone, Copy, Debug, Default)]
pub struct AndroidFiles;

fn fs_error(error: &io::Error) -> FsError {
    match error.kind() {
        io::ErrorKind::NotFound => FsError::NotFound,
        _ => match error.raw_os_error() {
            Some(libc::ELOOP) => FsError::Link,
            Some(code) => FsError::Os(u32::try_from(code).unwrap_or(u32::MAX)),
            None => FsError::Io(error.kind()),
        },
    }
}

impl Files for AndroidFiles {
    fn ensure_dir(&self, dir: &Path) -> Result<(), FsError> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|error| fs_error(&error))?;
        let metadata = fs::symlink_metadata(dir).map_err(|error| fs_error(&error))?;
        if metadata.file_type().is_symlink() {
            return Err(FsError::Link);
        }
        if !metadata.is_dir() {
            return Err(FsError::Os(
                u32::try_from(libc::ENOTDIR).unwrap_or(u32::MAX),
            ));
        }
        Ok(())
    }

    fn reject_link(&self, path: &Path) -> Result<(), FsError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => Err(FsError::Link),
            Ok(_) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(fs_error(&error)),
        }
    }

    fn read_limited_no_follow(&self, path: &Path, max: u64) -> Result<Vec<u8>, FsError> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .map_err(|error| fs_error(&error))?;
        let metadata = file.metadata().map_err(|error| fs_error(&error))?;
        if !metadata.is_file() {
            return Err(FsError::Os(u32::try_from(libc::EINVAL).unwrap_or(u32::MAX)));
        }
        if metadata.len() > max {
            return Err(FsError::TooLarge);
        }
        let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
        file.take(max.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| fs_error(&error))?;
        if u64::try_from(bytes.len()).map_or(true, |len| len > max) {
            return Err(FsError::TooLarge);
        }
        Ok(bytes)
    }

    fn write_new_synced(&self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        let mut file: File = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|error| match error.kind() {
                io::ErrorKind::AlreadyExists => FsError::Io(io::ErrorKind::AlreadyExists),
                _ => fs_error(&error),
            })?;
        let written = file.write_all(bytes).and_then(|()| file.sync_all());
        drop(file);
        if let Err(error) = written {
            let _ = fs::remove_file(path);
            return Err(fs_error(&error));
        }
        Ok(())
    }

    fn replace(&self, from: &Path, to: &Path) -> Result<(), FsError> {
        fs::rename(from, to).map_err(|error| fs_error(&error))
    }

    fn rename_no_replace(&self, from: &Path, to: &Path) -> Result<(), FsError> {
        match fs::symlink_metadata(to) {
            Ok(_) => Err(FsError::Os(u32::try_from(libc::EEXIST).unwrap_or(u32::MAX))),
            Err(missing) if missing.kind() == io::ErrorKind::NotFound => {
                fs::rename(from, to).map_err(|error| fs_error(&error))
            }
            Err(other) => Err(fs_error(&other)),
        }
    }

    fn flush_dir(&self, dir: &Path) -> Result<(), FsError> {
        let folder = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(dir)
            .map_err(|error| fs_error(&error))?;
        folder.sync_all().map_err(|error| fs_error(&error))
    }

    fn remove_file(&self, path: &Path) -> Result<(), FsError> {
        fs::remove_file(path).map_err(|error| fs_error(&error))
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn is_file(&self, path: &Path) -> bool {
        path.is_file()
    }

    fn list_dir(&self, dir: &Path) -> Result<Vec<OsString>, FsError> {
        let mut names = Vec::new();
        for entry in fs::read_dir(dir).map_err(|error| fs_error(&error))? {
            names.push(entry.map_err(|error| fs_error(&error))?.file_name());
        }
        Ok(names)
    }
}
