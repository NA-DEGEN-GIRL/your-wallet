//! What the key worker gets from its platform (2026-11-17, spec/15 §11.2, §11.4 S2): the wallet
//! file storage, the resident key slot, the reset file moves, the clock and the `YubiKey`
//! readers. Before, the worker named yw-app's `store` (`FileStorage`, `LockedSlotBox`,
//! `reset::move_wallet_files`), the PC/SC source and `SystemTime` itself.
//!
//! On Windows `store::WinKeyPlatform` passes the same `FileStorage` (atomic writes, reparse
//! refusal, `.prev`) and the `VirtualLock` slot `LockedSlotBox` as before (spec/02 §6.2, §7.3),
//! `system_clock::SystemClock` and `card_pcsc::PcscSource`.

use std::path::Path;

use yw_core::error::{StorageError, VaultError};
use yw_core::lang::Lang;
use yw_core::vault::{FileKind, LockedSlot, VaultStorage};
use yw_platform::Clock;

use crate::wallet_files::{ResetError, ResetReport};
use crate::yubikey::CardSource;

/// The wallet data folder storage: the vault's [`VaultStorage`] plus the sidecar recovery moves
/// of E-VLT-006 (spec/02 §6.3) and the leftover check (spec/04 §2.2).
pub trait WalletStore: VaultStorage {
    /// Whether `<name>` or `<name>.prev` exists (leftover sidecar detection).
    fn any_present(&self, kind: FileKind) -> bool;

    /// Replaces `<name>` with the bytes of `<name>.prev` after quarantining the main file
    /// ("이전 사본 사용"). Returns the name the main file was moved to (`None`: there was none).
    ///
    /// # Errors
    ///
    /// [`StorageError`].
    fn restore_prev(
        &mut self,
        kind: FileKind,
        now_unix: u64,
    ) -> Result<Option<String>, StorageError>;

    /// Moves the main file, when there is one, aside as `<name>.corrupt-<now_unix>` (never
    /// overwriting) and returns that name.
    ///
    /// # Errors
    ///
    /// [`StorageError`].
    fn quarantine_main(
        &mut self,
        kind: FileKind,
        now_unix: u64,
    ) -> Result<Option<String>, StorageError>;

    /// Moves `<name>.prev`, when there is one, aside as `<name>.prev.corrupt-<now_unix>` (never
    /// overwriting) and returns that name ("격리하고 새로 시작").
    ///
    /// # Errors
    ///
    /// [`StorageError`].
    fn set_prev_aside(
        &mut self,
        kind: FileKind,
        now_unix: u64,
    ) -> Result<Option<String>, StorageError>;
}

/// How many Argon2id derivations one vault call runs (2026-11-25 A2-8, spec/15 §5.3): most run
/// one; a password change runs two in one call (the old password's check and the new KEK,
/// yw-core `Session::change_password`, spec/02 §4.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KdfRuns {
    /// One derivation (create, import, unlock, every password check).
    One,
    /// Two derivations in one call (the password change).
    Two,
}

/// The platform's leave for one Argon2-bound vault call (2026-11-25 A2-8, spec/15 §5.3): while
/// it lives the call runs; when it is dropped — right after the call, whatever its result — the
/// platform releases the working memory (Android: `mallopt(M_PURGE)`). Windows gives one that
/// does nothing.
#[derive(Debug)]
pub struct KdfPass {
    done: Option<fn()>,
}

impl KdfPass {
    /// A leave with nothing to do afterwards (Windows, tests).
    #[must_use]
    pub const fn none() -> Self {
        Self { done: None }
    }

    /// A leave that runs `done` when it is dropped.
    #[must_use]
    pub const fn then(done: fn()) -> Self {
        Self { done: Some(done) }
    }
}

impl Drop for KdfPass {
    fn drop(&mut self) {
        if let Some(done) = self.done.take() {
            done();
        }
    }
}

/// The key worker's platform services.
pub trait KeyPlatform: Send {
    /// Asks to run one vault call that derives the KEK with Argon2id `runs` times (2026-11-25
    /// A2-8, spec/15 §5.3). Android checks the device's memory first and refuses with
    /// [`VaultError::OutOfMemory`] (E-VLT-007) when the run could get the app killed, so the call
    /// is not made and the job ends with that error; the leave it gives purges the allocator's
    /// free memory when dropped. The default (Windows) lets every call run and does nothing
    /// after: Windows behaviour is unchanged.
    ///
    /// # Errors
    ///
    /// [`VaultError::OutOfMemory`] when the platform refuses the run.
    fn kdf_begin(&self, runs: KdfRuns) -> Result<KdfPass, VaultError> {
        let _ = runs;
        Ok(KdfPass::none())
    }

    /// Opens the wallet data folder `dir` (creating it, removing orphan temporary files).
    ///
    /// # Errors
    ///
    /// [`StorageError`].
    fn open_storage(&self, dir: &Path) -> Result<Box<dyn WalletStore>, StorageError>;

    /// A new resident slot for the DEK (Windows: a `VirtualLock` page, spec/02 §7.3, D10).
    ///
    /// # Errors
    ///
    /// [`VaultError::OutOfMemory`] when the slot cannot be allocated or locked (E-VLT-007).
    fn new_slot(&self) -> Result<Box<dyn LockedSlot>, VaultError>;

    /// `지갑 초기화` (spec/04 §2.20): moves the wallet files of `dir` into a new `reset-<stamp>`
    /// folder.
    ///
    /// # Errors
    ///
    /// [`ResetError`].
    fn move_wallet_files(
        &self,
        dir: &Path,
        stamp: &str,
        include_settings: bool,
        lang: Lang,
    ) -> Result<ResetReport, ResetError>;
}

/// What `KeyWorker::new` takes from the platform.
pub struct KeyDeps {
    /// Storage, slot and reset moves.
    pub platform: Box<dyn KeyPlatform>,
    /// The clock: wall time for vault records, monotonic time for the Solana sign-time check
    /// (the same base the App uses, spec/07 §13.1; Windows: `GetTickCount64`).
    pub clock: Box<dyn Clock>,
    /// The inserted `YubiKey`s (PC/SC on Windows; the emulator in tests, spec/10 §12.1).
    pub cards: Box<dyn CardSource>,
}

impl core::fmt::Debug for KeyDeps {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("KeyDeps").finish_non_exhaustive()
    }
}

/// In-memory platform for the key worker's unit tests (modelled on yw-core's `MemStorage` and
/// `HeapSlot`): real-file coverage stays with the yw-app tests on `store::WinKeyPlatform`.
#[cfg(test)]
pub(crate) mod testing {
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    use yw_core::error::{StorageError, VaultError};
    use yw_core::lang::Lang;
    use yw_core::vault::{FileKind, LockedSlot, SLOT_LEN, VaultStorage, peek_generation};
    use yw_platform::Clock;

    use super::{KeyDeps, KeyPlatform, WalletStore};
    use crate::wallet_files::{ResetError, ResetReport, file_name};

    /// The monotonic time of [`FixedClock`]; card and software sign jobs pass it as
    /// `consumed_at_ms`.
    pub(crate) const MONO_MS: u64 = 86_400_000;

    /// The wall time of [`FixedClock`] (2026-11-17T00:00:00Z).
    pub(crate) const WALL_MS: u64 = 1_794_873_600_000;

    /// Both times stand still: monotonic at [`MONO_MS`], wall at [`WALL_MS`]. (2026-11-17 S2
    /// review: the wall time was `SystemTime::now()`, which the yw-engine clippy policy forbids
    /// once the worker moves there; no test reads the real date.)
    pub(crate) struct FixedClock;

    impl Clock for FixedClock {
        fn now_ms(&self) -> u64 {
            MONO_MS
        }

        fn now_unix_ms(&self) -> u64 {
            WALL_MS
        }

        fn sleep_ms(&self, _ms: u64) {}
    }

    #[derive(Default)]
    struct Files {
        main: BTreeMap<&'static str, Vec<u8>>,
        prev: BTreeMap<&'static str, Vec<u8>>,
        aside: Vec<String>,
    }

    /// One shared in-memory data folder (every `open_storage` sees the same files).
    #[derive(Clone, Default)]
    pub(crate) struct MemStore(Arc<Mutex<Files>>);

    impl MemStore {
        fn with<T>(&self, f: impl FnOnce(&mut Files) -> T) -> Result<T, StorageError> {
            let mut files = self.0.lock().map_err(|_| StorageError::Io(0))?;
            Ok(f(&mut files))
        }
    }

    impl VaultStorage for MemStore {
        fn load(&self, kind: FileKind) -> Result<Option<Vec<u8>>, StorageError> {
            self.with(|files| files.main.get(file_name(kind)).cloned())
        }

        fn load_prev(&self, kind: FileKind) -> Result<Option<Vec<u8>>, StorageError> {
            self.with(|files| files.prev.get(file_name(kind)).cloned())
        }

        fn commit(
            &mut self,
            kind: FileKind,
            expected: Option<u64>,
            bytes: &[u8],
        ) -> Result<(), StorageError> {
            self.with(|files| {
                let name = file_name(kind);
                match (expected, files.main.get(name)) {
                    (None, None) => {}
                    (None, Some(_)) => return Err(StorageError::AlreadyExists),
                    (Some(_), None) => return Err(StorageError::GenerationConflict),
                    (Some(expected), Some(existing)) => match peek_generation(kind, existing) {
                        None => return Err(StorageError::Corrupt),
                        Some(found) if found != expected => {
                            return Err(StorageError::GenerationConflict);
                        }
                        Some(_) => {}
                    },
                }
                if let Some(old) = files.main.insert(name, bytes.to_vec()) {
                    files.prev.insert(name, old);
                }
                Ok(())
            })?
        }

        fn quarantine(&mut self, kind: FileKind, now_unix: u64) -> Result<(), StorageError> {
            self.with(|files| {
                let name = file_name(kind);
                files.main.remove(name).ok_or(StorageError::NotFound)?;
                files.aside.push(format!("{name}.corrupt-{now_unix}"));
                Ok(())
            })?
        }
    }

    impl WalletStore for MemStore {
        fn any_present(&self, kind: FileKind) -> bool {
            self.with(|files| {
                files.main.contains_key(file_name(kind)) || files.prev.contains_key(file_name(kind))
            })
            .unwrap_or(false)
        }

        fn restore_prev(
            &mut self,
            kind: FileKind,
            now_unix: u64,
        ) -> Result<Option<String>, StorageError> {
            let prev = self.load_prev(kind)?.ok_or(StorageError::NotFound)?;
            let quarantined = self.quarantine_main(kind, now_unix)?;
            self.with(|files| files.main.insert(file_name(kind), prev))?;
            Ok(quarantined)
        }

        fn quarantine_main(
            &mut self,
            kind: FileKind,
            now_unix: u64,
        ) -> Result<Option<String>, StorageError> {
            if self.load(kind)?.is_none() {
                return Ok(None);
            }
            self.quarantine(kind, now_unix)?;
            Ok(Some(format!("{}.corrupt-{now_unix}", file_name(kind))))
        }

        fn set_prev_aside(
            &mut self,
            kind: FileKind,
            now_unix: u64,
        ) -> Result<Option<String>, StorageError> {
            self.with(|files| {
                files.prev.remove(file_name(kind)).map(|_| {
                    let name = format!("{}.prev.corrupt-{now_unix}", file_name(kind));
                    files.aside.push(name.clone());
                    name
                })
            })
        }
    }

    /// A heap slot (tests only; production slots are locked pages).
    struct HeapSlot(Box<[u8; SLOT_LEN]>);

    impl LockedSlot for HeapSlot {
        fn bytes(&self) -> &[u8; SLOT_LEN] {
            &self.0
        }

        fn bytes_mut(&mut self) -> &mut [u8; SLOT_LEN] {
            &mut self.0
        }
    }

    /// The in-memory platform: one [`MemStore`], heap slots, resets that move nothing.
    #[derive(Clone, Default)]
    pub(crate) struct MemPlatform(pub(crate) MemStore);

    impl KeyPlatform for MemPlatform {
        fn open_storage(&self, _dir: &Path) -> Result<Box<dyn WalletStore>, StorageError> {
            Ok(Box::new(self.0.clone()))
        }

        fn new_slot(&self) -> Result<Box<dyn LockedSlot>, VaultError> {
            Ok(Box::new(HeapSlot(Box::new([0; SLOT_LEN]))))
        }

        fn move_wallet_files(
            &self,
            _dir: &Path,
            _stamp: &str,
            _include_settings: bool,
            _lang: Lang,
        ) -> Result<ResetReport, ResetError> {
            Ok(ResetReport {
                folder: None,
                moved: Vec::new(),
                settings_moved: false,
            })
        }
    }

    /// A fresh in-memory folder, the fixed clock and no readers.
    pub(crate) fn deps() -> KeyDeps {
        KeyDeps {
            platform: Box::new(MemPlatform::default()),
            clock: Box::new(FixedClock),
            cards: Box::new(crate::yubikey::NoReaders),
        }
    }

    /// A folder name for a test (process id + counter; nothing is created, and the in-memory
    /// platform ignores it). (2026-11-17, spec/15 §11.4 S2 E3: a relative name; before, it was
    /// under `std::env::temp_dir()`, which the yw-engine clippy policy forbids, spec/01 §5.1.)
    pub(crate) fn temp_name(tag: &str) -> std::path::PathBuf {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        std::path::PathBuf::from(format!(
            "yw-engine-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }
}
