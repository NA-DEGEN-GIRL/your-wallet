//! `VaultStorage` over yw-win file functions (spec/02 §6.2) and the `LockedSlot` adapter over
//! `yw_win::mem::LockedBox<320>` (spec/02 §7.3, D10).
//!
//! Commit sequence (spec/02 §6.2, pattern from
//! `archive/spec-v2.4:demo/sepolia-wallet/src/backend.rs:6148-6403`): (1) read and CAS-check the
//! main file, (2) previous bytes → `<name>.prev.tmp` → flush → `MoveFileExW` to `<name>.prev`,
//! (3) new bytes → `<name>.tmp` (`CREATE_NEW`) → flush → close, (4) `MoveFileExW` over the main
//! file, (5) flush the folder, (6) read back and compare. Orphan `*.tmp` files are removed when the
//! storage is opened.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use yw_core::error::StorageError;
use yw_core::vault::{FileKind, LockedSlot, SLOT_LEN, VaultStorage, peek_generation};
use yw_win::WinError;
use yw_win::file::{
    FileError, ensure_dir, flush_dir, read_limited, rename_no_replace, replace_file,
    write_new_synced,
};
use yw_win::mem::LockedBox;

const VAULT_MAX: u64 = 65_536;
const META_MAX: u64 = 8 * 1_048_576 + 80;
const JOURNAL_MAX: u64 = 16 * 1_048_576 + 80;

/// File name of a kind.
#[must_use]
pub const fn file_name(kind: FileKind) -> &'static str {
    match kind {
        FileKind::Vault => "vault.ywv",
        FileKind::Meta => "meta.ywm",
        FileKind::Journal => "journal.ywj",
    }
}

const fn max_size(kind: FileKind) -> u64 {
    match kind {
        FileKind::Vault => VAULT_MAX,
        FileKind::Meta => META_MAX,
        FileKind::Journal => JOURNAL_MAX,
    }
}

fn with_suffix(dir: &Path, kind: FileKind, suffix: &str) -> PathBuf {
    dir.join(format!("{}{suffix}", file_name(kind)))
}

fn storage_error(error: FileError) -> StorageError {
    match error {
        FileError::NotFound => StorageError::NotFound,
        FileError::TooLarge => StorageError::TooLarge,
        FileError::ReparsePoint => StorageError::Io(0x0000_1126),
        FileError::Os(WinError { code, .. }) => StorageError::Io(code),
        FileError::Io(kind) => StorageError::Io(match kind {
            io::ErrorKind::AlreadyExists => 183,
            io::ErrorKind::PermissionDenied => 5,
            _ => 0xFFFF_FFFF,
        }),
    }
}

fn remove_if_present(path: &Path) -> Result<(), StorageError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(storage_error(error.into())),
    }
}

/// The wallet data folder storage.
#[derive(Debug)]
pub struct FileStorage {
    dir: PathBuf,
    #[cfg(test)]
    stop_after: Option<u8>,
}

impl FileStorage {
    /// Opens the folder (creating it) and removes orphan temporary files (spec/02 §6.2).
    ///
    /// # Errors
    ///
    /// [`StorageError`] if the folder cannot be created or a temporary file cannot be removed.
    pub fn open(dir: &Path) -> Result<Self, StorageError> {
        ensure_dir(dir).map_err(storage_error)?;
        for kind in [FileKind::Vault, FileKind::Meta, FileKind::Journal] {
            remove_if_present(&with_suffix(dir, kind, ".tmp"))?;
            remove_if_present(&with_suffix(dir, kind, ".prev.tmp"))?;
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            #[cfg(test)]
            stop_after: None,
        })
    }

    /// Path of the main file.
    #[must_use]
    pub fn path(&self, kind: FileKind) -> PathBuf {
        with_suffix(&self.dir, kind, "")
    }

    /// Whether `<name>` or `<name>.prev` exists (leftover sidecar detection, spec/04 §2.2).
    #[must_use]
    pub fn any_present(&self, kind: FileKind) -> bool {
        self.path(kind).exists() || with_suffix(&self.dir, kind, ".prev").exists()
    }

    fn read(path: &Path, kind: FileKind) -> Result<Option<Vec<u8>>, StorageError> {
        match read_limited(path, max_size(kind)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(FileError::NotFound) => Ok(None),
            Err(error) => Err(storage_error(error)),
        }
    }

    /// Replaces `<name>` with the bytes of `<name>.prev` after quarantining the main file
    /// (E-VLT-006 "이전 사본 사용" for sidecars).
    ///
    /// # Errors
    ///
    /// [`StorageError`].
    pub fn restore_prev(&mut self, kind: FileKind, now_unix: u64) -> Result<(), StorageError> {
        let prev = Self::read(&with_suffix(&self.dir, kind, ".prev"), kind)?
            .ok_or(StorageError::NotFound)?;
        if self.path(kind).exists() {
            self.quarantine(kind, now_unix)?;
        }
        let tmp = with_suffix(&self.dir, kind, ".tmp");
        remove_if_present(&tmp)?;
        write_new_synced(&tmp, &prev).map_err(storage_error)?;
        replace_file(&tmp, &self.path(kind)).map_err(storage_error)?;
        let _ = flush_dir(&self.dir);
        Ok(())
    }

    /// Stops `commit` with `Io(0)` right after step `step` (1–6) — V-FS fault injection.
    #[cfg(test)]
    pub fn commit_until(&mut self, step: u8) {
        self.stop_after = Some(step);
    }

    #[cfg(test)]
    fn stop(&self, step: u8) -> Result<(), StorageError> {
        if self.stop_after == Some(step) {
            return Err(StorageError::Io(0));
        }
        Ok(())
    }

    #[cfg(not(test))]
    #[expect(
        clippy::unused_self,
        clippy::unnecessary_wraps,
        reason = "test-only fault hook"
    )]
    const fn stop(&self, _step: u8) -> Result<(), StorageError> {
        Ok(())
    }
}

impl VaultStorage for FileStorage {
    fn load(&self, kind: FileKind) -> Result<Option<Vec<u8>>, StorageError> {
        Self::read(&self.path(kind), kind)
    }

    fn load_prev(&self, kind: FileKind) -> Result<Option<Vec<u8>>, StorageError> {
        Self::read(&with_suffix(&self.dir, kind, ".prev"), kind)
    }

    fn commit(
        &mut self,
        kind: FileKind,
        expected_generation: Option<u64>,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        if u64::try_from(bytes.len()).map_or(true, |len| len > max_size(kind)) {
            return Err(StorageError::TooLarge);
        }
        // 1. Read the main file and check the precondition; nothing is written on failure.
        let current = self.load(kind)?;
        match (expected_generation, &current) {
            (None, None) => {}
            (None, Some(_)) => return Err(StorageError::AlreadyExists),
            (Some(_), None) => return Err(StorageError::GenerationConflict),
            (Some(expected), Some(existing)) => match peek_generation(kind, existing) {
                None => return Err(StorageError::Corrupt),
                Some(found) if found != expected => return Err(StorageError::GenerationConflict),
                Some(_) => {}
            },
        }
        self.stop(1)?;
        // 2. The previous bytes become `<name>.prev`.
        if let Some(existing) = &current {
            let prev_tmp = with_suffix(&self.dir, kind, ".prev.tmp");
            remove_if_present(&prev_tmp)?;
            write_new_synced(&prev_tmp, existing).map_err(storage_error)?;
            replace_file(&prev_tmp, &with_suffix(&self.dir, kind, ".prev"))
                .map_err(storage_error)?;
        }
        self.stop(2)?;
        // 3. The new bytes go to `<name>.tmp` (CREATE_NEW).
        let tmp = with_suffix(&self.dir, kind, ".tmp");
        remove_if_present(&tmp)?;
        write_new_synced(&tmp, bytes).map_err(storage_error)?;
        self.stop(3)?;
        // 4. Atomic replace.
        if let Err(error) = replace_file(&tmp, &self.path(kind)) {
            let _ = fs::remove_file(&tmp);
            return Err(storage_error(error));
        }
        self.stop(4)?;
        // 5. Folder flush (recommended).
        let _ = flush_dir(&self.dir);
        self.stop(5)?;
        // 6. Read back.
        if self.load(kind)?.as_deref() != Some(bytes) {
            return Err(StorageError::Io(0xFFFF_FFFE));
        }
        self.stop(6)?;
        Ok(())
    }

    fn quarantine(&mut self, kind: FileKind, now_unix: u64) -> Result<(), StorageError> {
        let target = with_suffix(&self.dir, kind, &format!(".corrupt-{now_unix}"));
        rename_no_replace(&self.path(kind), &target).map_err(storage_error)
    }
}

/// The resident slot on a `VirtualLock` page (spec/01 §5.3: `LockedBox<320>`).
#[derive(Debug)]
pub struct LockedSlotBox(LockedBox<SLOT_LEN>);

impl LockedSlotBox {
    /// Allocates and locks the slot.
    ///
    /// # Errors
    ///
    /// The `VirtualAlloc`/`VirtualLock` failure (E-VLT-007).
    pub fn new() -> Result<Self, WinError> {
        LockedBox::new_zeroed().map(Self)
    }
}

impl LockedSlot for LockedSlotBox {
    fn bytes(&self) -> &[u8; SLOT_LEN] {
        self.0.expose()
    }

    fn bytes_mut(&mut self) -> &mut [u8; SLOT_LEN] {
        self.0.expose_mut()
    }
}

#[cfg(test)]
mod tests;
