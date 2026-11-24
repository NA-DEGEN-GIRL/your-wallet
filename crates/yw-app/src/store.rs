//! `VaultStorage` of the wallet data folder on Windows (spec/02 §6.2) and the `LockedSlot`
//! adapter over `yw_win::mem::LockedBox<320>` (spec/02 §7.3, D10); together with the reset moves
//! they are the key worker's Windows platform [`WinKeyPlatform`] (2026-11-17).
//!
//! 2026-11-25 (spec/15 §17 A2-4a): the storage logic (the commit sequence of spec/02 §6.2, the
//! `.prev` rotation, quarantine, the set-aside copies, the link refusal of review L8) moved
//! unchanged into yw-engine's `file_storage::FileStorage`, which makes its file calls through the
//! yw-platform `Files` seam; on Windows that is `yw_win::file::WinFiles`, the same `yw_win::file`
//! functions and std calls in the same order as before. [`FileStorage`] here is that storage over
//! `WinFiles` plus the V-FS fault point of the tests below (`commit_until`, spec/09 §4.1), which
//! stays `#[cfg(test)]` in this crate. Before, this file held the logic itself.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use yw_core::error::{StorageError, VaultError};
use yw_core::lang::Lang;
use yw_core::vault::{FileKind, LockedSlot, SLOT_LEN, VaultStorage};
use yw_platform::Clock;
use yw_win::WinError;
use yw_win::file::WinFiles;
use yw_win::mem::LockedBox;

pub use yw_engine::wallet_files::file_name;
use yw_engine::wallet_files::{ResetError, ResetReport, with_suffix};
use yw_engine::workers::key::platform::{KeyDeps, KeyPlatform, WalletStore};
use yw_engine::yubikey::CardSource;

/// Whether `<name>.prev` exists in `dir` (a metadata check only, no read; the UI uses it to offer
/// `.prev` recovery, spec/04 §2.5 S07/S09).
#[must_use]
pub fn prev_exists(dir: &Path, kind: FileKind) -> bool {
    with_suffix(dir, kind, ".prev").is_file()
}

/// The wallet data folder storage: yw-engine's `FileStorage` over [`WinFiles`].
#[derive(Debug)]
pub struct FileStorage {
    inner: yw_engine::file_storage::FileStorage<WinFiles>,
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
        Ok(Self {
            inner: yw_engine::file_storage::FileStorage::open(WinFiles, dir)?,
            #[cfg(test)]
            stop_after: None,
        })
    }

    /// Path of the main file.
    #[must_use]
    pub fn path(&self, kind: FileKind) -> PathBuf {
        self.inner.path(kind)
    }

    /// Whether `<name>` or `<name>.prev` exists (leftover sidecar detection, spec/04 §2.2).
    #[must_use]
    pub fn any_present(&self, kind: FileKind) -> bool {
        self.inner.any_present(kind)
    }

    /// Replaces `<name>` with the bytes of `<name>.prev` after quarantining the main file
    /// (E-VLT-006 "이전 사본 사용" for sidecars; the key worker has opened and decoded `.prev`
    /// first). Returns the name the main file was moved to (`None`: there was none).
    ///
    /// # Errors
    ///
    /// [`StorageError`].
    pub fn restore_prev(
        &mut self,
        kind: FileKind,
        now_unix: u64,
    ) -> Result<Option<String>, StorageError> {
        self.inner.restore_prev(kind, now_unix)
    }

    /// Moves the main file, when there is one, aside as `<name>.corrupt-<now_unix>` (never
    /// overwriting) and returns that name.
    ///
    /// # Errors
    ///
    /// [`StorageError`].
    pub fn quarantine_main(
        &mut self,
        kind: FileKind,
        now_unix: u64,
    ) -> Result<Option<String>, StorageError> {
        self.inner.quarantine_main(kind, now_unix)
    }

    /// `격리하고 새로 시작` of a sidecar: moves `<name>.prev`, when there is one, aside as
    /// `<name>.prev.corrupt-<now_unix>` (never overwriting) and returns that name. Otherwise the
    /// fresh file's second save would rotate over it, and it may be the last readable copy.
    ///
    /// # Errors
    ///
    /// [`StorageError`].
    pub fn set_prev_aside(
        &mut self,
        kind: FileKind,
        now_unix: u64,
    ) -> Result<Option<String>, StorageError> {
        self.inner.set_prev_aside(kind, now_unix)
    }

    /// Stops `commit` with `Io(0)` right after step `step` (1–6) — V-FS fault injection.
    #[cfg(test)]
    pub fn commit_until(&mut self, step: u8) {
        self.stop_after = Some(step);
    }

    /// The step hook of `commit`: the V-FS fault point in test builds, nothing otherwise.
    #[cfg(test)]
    fn stop_hook(&self) -> impl FnMut(u8) -> Result<(), StorageError> + use<> {
        let stop_after = self.stop_after;
        move |step| {
            if stop_after == Some(step) {
                return Err(StorageError::Io(0));
            }
            Ok(())
        }
    }

    #[cfg(not(test))]
    #[expect(clippy::unused_self, reason = "test-only fault hook")]
    fn stop_hook(&self) -> impl FnMut(u8) -> Result<(), StorageError> + use<> {
        |_| Ok(())
    }
}

impl VaultStorage for FileStorage {
    fn load(&self, kind: FileKind) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.load(kind)
    }

    fn load_prev(&self, kind: FileKind) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.load_prev(kind)
    }

    fn commit(
        &mut self,
        kind: FileKind,
        expected_generation: Option<u64>,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        let stop = self.stop_hook();
        self.inner
            .commit_with_steps(kind, expected_generation, bytes, stop)
    }

    fn quarantine(&mut self, kind: FileKind, now_unix: u64) -> Result<(), StorageError> {
        self.inner.quarantine(kind, now_unix)
    }

    fn copies(&self, kind: FileKind) -> Result<Vec<String>, StorageError> {
        self.inner.copies(kind)
    }

    fn load_copy(&self, kind: FileKind, name: &str) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.load_copy(kind, name)
    }

    fn replace_copy(
        &mut self,
        kind: FileKind,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        self.inner.replace_copy(kind, name, bytes)
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

impl WalletStore for FileStorage {
    fn any_present(&self, kind: FileKind) -> bool {
        Self::any_present(self, kind)
    }

    fn restore_prev(
        &mut self,
        kind: FileKind,
        now_unix: u64,
    ) -> Result<Option<String>, StorageError> {
        Self::restore_prev(self, kind, now_unix)
    }

    fn quarantine_main(
        &mut self,
        kind: FileKind,
        now_unix: u64,
    ) -> Result<Option<String>, StorageError> {
        Self::quarantine_main(self, kind, now_unix)
    }

    fn set_prev_aside(
        &mut self,
        kind: FileKind,
        now_unix: u64,
    ) -> Result<Option<String>, StorageError> {
        Self::set_prev_aside(self, kind, now_unix)
    }
}

/// The key worker's Windows platform (2026-11-17, spec/15 §11.4 S2): [`FileStorage`], the
/// `VirtualLock` slot [`LockedSlotBox`] and [`reset::move_wallet_files`] — the same calls the
/// worker made itself before.
#[derive(Clone, Copy, Debug, Default)]
pub struct WinKeyPlatform;

impl WinKeyPlatform {
    /// The production set: this platform, the App's `clock` and the PC/SC readers. Only
    /// `main.rs` calls it (the source scan `card_pcsc::tests::pcsc_readers_only_from_main`).
    /// 2026-11-19 (S4 B1a, spec/15 §11.4 S4 critique B-19): `main.rs` passes the App's clock,
    /// which the worker reads through [`ArcClock`](crate::system_clock::ArcClock); before, its
    /// own `SystemClock` (`GetTickCount64`, the same base).
    #[must_use]
    pub fn deps(clock: Arc<dyn Clock>) -> KeyDeps {
        KeyDeps {
            platform: Box::new(Self),
            clock: Box::new(crate::system_clock::ArcClock(clock)),
            cards: Box::new(crate::card_pcsc::PcscSource),
        }
    }

    /// This platform and `SystemClock` with another card source: tests on real wallet files pass
    /// `yubikey::NoReaders` or the emulator, never the machine's readers (2026-11-17 S2 review,
    /// AGENTS rule 3).
    #[must_use]
    pub fn deps_with_cards(cards: Box<dyn CardSource>) -> KeyDeps {
        KeyDeps {
            platform: Box::new(Self),
            clock: Box::new(crate::system_clock::SystemClock),
            cards,
        }
    }

    /// A slot on a locked page (E-VLT-007 when it cannot be allocated or locked).
    ///
    /// # Errors
    ///
    /// [`VaultError::OutOfMemory`].
    pub fn locked_slot() -> Result<LockedSlotBox, VaultError> {
        LockedSlotBox::new().map_err(|_| VaultError::OutOfMemory)
    }
}

impl KeyPlatform for WinKeyPlatform {
    fn open_storage(&self, dir: &Path) -> Result<Box<dyn WalletStore>, StorageError> {
        FileStorage::open(dir).map(|storage| Box::new(storage) as Box<dyn WalletStore>)
    }

    fn new_slot(&self) -> Result<Box<dyn LockedSlot>, VaultError> {
        Self::locked_slot().map(|slot| Box::new(slot) as Box<dyn LockedSlot>)
    }

    fn move_wallet_files(
        &self,
        dir: &Path,
        stamp: &str,
        include_settings: bool,
        lang: Lang,
    ) -> Result<ResetReport, ResetError> {
        reset::move_wallet_files(dir, stamp, include_settings, lang)
    }
}

pub mod reset;
#[cfg(test)]
mod tests;
