//! The Android key-worker platform and app store over the sealed files (spec/15 §5.1–§5.3, §11.2;
//! 2026-11-25 A2-4b).
//!
//! - [`DataPlatform`] is the engine's [`KeyPlatform`]: [`KeyPlatform::open_storage`] gives yw-engine's
//!   `FileStorage` over [`SealedFiles`] (the commit sequence of spec/02 §6.2 unchanged, every file a
//!   `YWK2` envelope), [`KeyPlatform::new_slot`] the platform's locked slot (Android:
//!   `slot::AndroidSlot`, `mmap` + `mlock` + `madvise(MADV_DONTDUMP)`, fail closed).
//!   `move_wallet_files` (the wallet reset, spec/04 §2.20) is not on Android before its settings
//!   screen: it refuses and moves nothing. 2026-11-25 A2-8 (spec/15 §5.3): its
//!   [`KeyPlatform::kdf_begin`] asks [`KdfHooks::gate`] before every Argon2-bound vault call and
//!   the leave it gives runs [`KdfHooks::done`] right after it (Android: the memory check and
//!   `mallopt(M_PURGE)`, `crate::shell`).
//! - [`DataStore`] is the engine's [`AppStore`]: `settings.json` plain and atomic (temp → sync →
//!   rename → folder sync), `apikeys.ks` sealed ([`SealKind::ApiKeys`]; a damaged file is
//!   "unreadable", never its raw bytes), the `vault.ywv` facts (the generation needs the device key:
//!   the inner header is inside the envelope), `.prev` checks; no reset candidates (as above).
//!   Its names (`settings.json`, `apikeys.ks` and their `.tmp`) never start with `vault.ywv`,
//!   `meta.ywm` or `journal.ywj`, so they never meet a quarantine or set-aside name of the key
//!   worker's `rename_no_replace` (spec/15 §5.1; test `the_app_store_names_are_not_the_vault_files`).
//! - (2026-11-25 A2-4b review) [`AppStore::vault_file_info`] is not a plain file read here as on
//!   Windows: it unwraps `vault.ywv` through the Keystore (one I/O request, up to
//!   [`crate::device_key::KEY_TIMEOUT`]) and holds that file's key in the calling thread. The
//!   engine calls it on the wallet thread (lock screen, settings, the meta write's rollback
//!   check). Before A2-6/A2-8 wire [`DataStore`] into the wallet, the generation must come from
//!   the key worker (which reads the vault anyway), or this call must run off the wallet thread
//!   with a short deadline that gives `None` (spec/15 §5.2). (2026-11-25 A2-8: the second, on
//!   the wallet thread: `crate::shell::app_store` gives this store a device key whose requests
//!   end after `crate::shell::STORE_TIMEOUT` (3 s, under Android's 5 s input deadline), so a slow
//!   Keystore makes the read `None` — no generation, so no rollback note that time, as when
//!   Windows cannot read the file — and a slow `apikeys.ks` write fails as a failed write.)
//!
//! Platform-neutral over any [`Files`] (the Windows gate tests it in memory); Android passes
//! `android_files::AndroidFiles` and the broker's device key.

use core::fmt;
use std::path::{Path, PathBuf};

use yw_core::error::{StorageError, VaultError};
use yw_core::lang::Lang;
use yw_core::vault::envelope::SealKind;
use yw_core::vault::{FileKind, LockedSlot, peek_generation};
use yw_engine::app_store::{AppStore, SealedRead};
use yw_engine::file_storage::FileStorage;
use yw_engine::wallet_files::{ResetError, ResetReport, file_name, with_suffix};
use yw_engine::workers::key::platform::{KdfPass, KdfRuns, KeyPlatform, WalletStore};
use yw_platform::files::{Files, FsError};

use crate::device_key::MakeKey;
use crate::sealed_files::SealedFiles;

/// The data folder under `Context.getNoBackupFilesDir()` (spec/15 §5.1).
pub const DATA_FOLDER: &str = "v3";
/// `settings.json`.
pub const SETTINGS_NAME: &str = "settings.json";
/// The sealed API keys (spec/15 §5.1; Windows `apikeys.dpapi`).
pub const APIKEYS_NAME: &str = "apikeys.ks";
/// Largest `apikeys.ks` (inner bytes), as Windows' `apikeys.dpapi`.
const APIKEYS_MAX_BYTES: u64 = 1_048_576;
/// Largest `vault.ywv` read for its facts (inner bytes), as Windows.
const VAULT_PEEK_BYTES: u64 = 65_536;
/// The storage error of the refused reset.
pub const RESET_REFUSED: u32 = crate::device_key::DeviceCode::BASE + 0x120;

/// Makes the platform's locked slot.
pub type SlotMaker = fn() -> Result<Box<dyn LockedSlot>, VaultError>;

/// What runs around every Argon2-bound vault call (2026-11-25 A2-8, spec/15 §5.3).
#[derive(Clone, Copy, Debug)]
pub struct KdfHooks {
    /// Before the call: `Err` refuses it (the job ends with that error, the call is not made).
    pub gate: fn(KdfRuns) -> Result<(), VaultError>,
    /// Right after the call, whatever its result.
    pub done: fn(),
}

impl KdfHooks {
    /// No check and nothing after (the gate's in-memory tests; never the Android build, whose
    /// platform is `crate::shell::platform`).
    pub const UNCHECKED: Self = Self {
        gate: unchecked_gate,
        done: nothing,
    };
}

#[expect(clippy::unnecessary_wraps, reason = "the `KdfHooks::gate` signature")]
const fn unchecked_gate(_runs: KdfRuns) -> Result<(), VaultError> {
    Ok(())
}

const fn nothing() {}

/// The key worker's platform on Android (module doc).
pub struct DataPlatform<F, D> {
    files: F,
    device: D,
    slot: SlotMaker,
    kdf: KdfHooks,
}

impl<F, D> fmt::Debug for DataPlatform<F, D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DataPlatform")
    }
}

impl<F, D> DataPlatform<F, D> {
    /// The platform over `files` and `device`, making slots with `slot`, with `kdf` around every
    /// Argon2-bound vault call.
    pub const fn new(files: F, device: D, slot: SlotMaker, kdf: KdfHooks) -> Self {
        Self {
            files,
            device,
            slot,
            kdf,
        }
    }
}

impl<F, D> KeyPlatform for DataPlatform<F, D>
where
    F: Files + Clone + 'static,
    D: MakeKey + Send + Clone + 'static,
{
    fn open_storage(&self, dir: &Path) -> Result<Box<dyn WalletStore>, StorageError> {
        let sealed = SealedFiles::new(self.files.clone(), self.device.clone());
        Ok(Box::new(FileStorage::open(sealed, dir)?))
    }

    fn new_slot(&self) -> Result<Box<dyn LockedSlot>, VaultError> {
        (self.slot)()
    }

    fn kdf_begin(&self, runs: KdfRuns) -> Result<KdfPass, VaultError> {
        (self.kdf.gate)(runs)?;
        Ok(KdfPass::then(self.kdf.done))
    }

    fn move_wallet_files(
        &self,
        _dir: &Path,
        _stamp: &str,
        _include_settings: bool,
        _lang: Lang,
    ) -> Result<ResetReport, ResetError> {
        Err(ResetError::Folder(StorageError::Io(RESET_REFUSED)))
    }
}

/// The app's data-folder store on Android (module doc).
pub struct DataStore<F, D> {
    sealed: SealedFiles<F, D>,
    data: PathBuf,
}

impl<F, D> fmt::Debug for DataStore<F, D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DataStore")
    }
}

impl<F: Files, D: MakeKey + Send> DataStore<F, D> {
    /// The store of the data folder `data`.
    pub fn new(files: F, device: D, data: &Path) -> Self {
        Self {
            sealed: SealedFiles::new(files, device),
            data: data.to_path_buf(),
        }
    }

    /// Writes `bytes` to `name` atomically through `write` (temp → sync → rename → folder sync).
    fn atomic(
        &self,
        name: &str,
        write: impl FnOnce(&Path) -> Result<(), FsError>,
    ) -> Result<(), FsError> {
        let files = self.sealed.plain();
        files.ensure_dir(&self.data)?;
        let target = self.data.join(name);
        let tmp = self.data.join(format!("{name}.tmp"));
        files.reject_link(&target)?;
        match files.remove_file(&tmp) {
            Ok(()) | Err(FsError::NotFound) => {}
            Err(error) => return Err(error),
        }
        write(&tmp)?;
        if let Err(error) = files.replace(&tmp, &target) {
            let _ = files.remove_file(&tmp);
            return Err(error);
        }
        files.flush_dir(&self.data)
    }
}

impl<F: Files, D: MakeKey + Send> AppStore for DataStore<F, D> {
    fn write_settings(&self, json: &[u8]) -> bool {
        self.atomic(SETTINGS_NAME, |tmp| {
            self.sealed.plain().write_new_synced(tmp, json)
        })
        .is_ok()
    }

    fn read_sealed_keys(&self) -> SealedRead {
        match self.sealed.read_sealed(
            &self.data.join(APIKEYS_NAME),
            SealKind::ApiKeys,
            APIKEYS_MAX_BYTES,
        ) {
            Ok(Some(plain)) => SealedRead::Plain(plain),
            Err(FsError::NotFound) => SealedRead::NotFound,
            Ok(None) | Err(_) => SealedRead::Unreadable,
        }
    }

    fn write_sealed_keys(&self, plain: &[u8]) -> bool {
        self.atomic(APIKEYS_NAME, |tmp| {
            self.sealed.write_sealed(tmp, SealKind::ApiKeys, plain)
        })
        .is_ok()
    }

    fn vault_file_info(&self) -> Option<(u64, u64)> {
        let path = self.data.join(file_name(FileKind::Vault));
        let inner = self
            .sealed
            .read_sealed(&path, SealKind::Vault, VAULT_PEEK_BYTES)
            .ok()??;
        let generation = peek_generation(FileKind::Vault, &inner)?;
        let written = std::fs::symlink_metadata(&path)
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |since| {
                u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
            });
        Some((generation, written))
    }

    fn prev_exists(&self, kind: FileKind) -> bool {
        self.sealed
            .plain()
            .is_file(&with_suffix(&self.data, kind, ".prev"))
    }

    fn reset_candidates(&self, _include_settings: bool) -> Vec<String> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use yw_core::bip32::path::AccountIndex;
    use yw_core::error::{StorageError, VaultError};
    use yw_core::password::VaultPassword;
    use yw_core::vault::envelope::{MAGIC, SealKind};
    use yw_core::vault::{
        EvmKeySource, FileKind, JOURNAL_MAGIC, LockedSlot, META_MAGIC, SLOT_LEN, Vault,
        VaultStatus, VaultStorage, check_vault_header, peek_generation,
    };
    use yw_engine::app_store::{AppStore, SealedRead};
    use yw_engine::file_storage::FileStorage;
    use yw_engine::workers::key::platform::KeyPlatform;

    use super::{DataPlatform, DataStore};
    use crate::device_key::{DeviceCode, MakeKey};
    use crate::sealed_files::SealedFiles;
    use crate::sealed_files::testing::{FakeKey, MemFiles};

    /// The state of a [`SharedKey`]: [`FakeKey`]'s `refuse`, `missing` and `made`.
    #[derive(Debug, Default)]
    struct KeyState {
        refuse: Option<u32>,
        missing: bool,
        made: u32,
    }

    /// A shareable stand-in device key (the platform clones it per storage).
    #[derive(Clone, Debug, Default)]
    struct SharedKey(std::sync::Arc<std::sync::Mutex<KeyState>>);

    impl SharedKey {
        fn refuse(&self, code: Option<u32>) {
            self.0.lock().unwrap().refuse = code;
        }

        fn lose(&self) {
            self.0.lock().unwrap().missing = true;
        }

        fn made(&self) -> u32 {
            self.0.lock().unwrap().made
        }

        /// Runs `call` on a [`FakeKey`] with this state and keeps what it changed.
        fn with<T>(&self, call: impl FnOnce(&FakeKey) -> T) -> T {
            let mut state = self.0.lock().unwrap();
            let fake = FakeKey::default();
            fake.refuse.set(state.refuse);
            fake.missing.set(state.missing);
            let out = call(&fake);
            state.missing = fake.missing.get();
            state.made += fake.made.get();
            out
        }
    }

    impl yw_core::vault::envelope::DeviceKey for SharedKey {
        fn wrap(
            &self,
            kind: SealKind,
            file_key: &[u8; 32],
        ) -> Result<[u8; 60], yw_core::vault::envelope::EnvelopeError> {
            self.with(|fake| fake.wrap(kind, file_key))
        }

        fn unwrap(
            &self,
            kind: SealKind,
            wrapped: &[u8; 60],
        ) -> Result<yw_core::secret::Zeroizing<[u8; 32]>, yw_core::vault::envelope::EnvelopeError>
        {
            self.with(|fake| fake.unwrap(kind, wrapped))
        }
    }

    impl MakeKey for SharedKey {
        fn make_key(&self) -> Result<(), yw_core::vault::envelope::EnvelopeError> {
            self.with(MakeKey::make_key)
        }
    }

    struct HeapSlot(Box<[u8; SLOT_LEN]>);

    impl LockedSlot for HeapSlot {
        fn bytes(&self) -> &[u8; SLOT_LEN] {
            &self.0
        }

        fn bytes_mut(&mut self) -> &mut [u8; SLOT_LEN] {
            &mut self.0
        }
    }

    #[expect(clippy::unnecessary_wraps, reason = "the `SlotMaker` signature")]
    fn heap_slot() -> Result<Box<dyn LockedSlot>, VaultError> {
        Ok(Box::new(HeapSlot(Box::new([0; SLOT_LEN]))))
    }

    const DIR: &str = "data/v3";
    /// The public test vector (spec/02 §11.4), never a real phrase.
    fn phrase() -> String {
        let mut phrase = "abandon ".repeat(11);
        phrase.push_str("about");
        phrase
    }
    /// spec/02 §11.4: `m/44'/60'/0'/0/0` of [`phrase`].
    const ACCOUNT_0: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";

    fn sealed_storage(
        files: &MemFiles,
        key: &SharedKey,
    ) -> FileStorage<SealedFiles<MemFiles, SharedKey>> {
        FileStorage::open(SealedFiles::new(files.clone(), key.clone()), Path::new(DIR)).unwrap()
    }

    /// A structurally valid sidecar of `generation` (spec/02 §5.2; the engine's test helper).
    fn sidecar(magic: [u8; 8], kind: FileKind, generation: u64) -> Vec<u8> {
        let mut bytes = magic.to_vec();
        bytes.extend_from_slice(&3_u16.to_be_bytes());
        bytes.extend_from_slice(&64_u16.to_be_bytes());
        bytes.extend_from_slice(&[7; 16]);
        bytes.extend_from_slice(&generation.to_be_bytes());
        bytes.extend_from_slice(&[0; 24]);
        bytes.extend_from_slice(&16_u32.to_be_bytes());
        bytes.extend_from_slice(&[generation.to_le_bytes()[0]; 16]);
        assert_eq!(peek_generation(kind, &bytes), Some(generation));
        bytes
    }

    #[test]
    fn commits_are_sealed_on_disk_and_inner_above() {
        let files = MemFiles::default();
        let key = SharedKey::default();
        let mut storage = sealed_storage(&files, &key);
        let first = sidecar(META_MAGIC, FileKind::Meta, 1);
        storage.commit(FileKind::Meta, None, &first).unwrap();
        let second = sidecar(META_MAGIC, FileKind::Meta, 2);
        storage.commit(FileKind::Meta, Some(1), &second).unwrap();
        // On disk: two envelopes (main and `.prev`), no inner run in either.
        for name in ["meta.ywm", "meta.ywm.prev"] {
            let raw = files.raw(&Path::new(DIR).join(name)).unwrap();
            assert_eq!(&raw[..4], &MAGIC, "{name}");
            assert_eq!(raw[5], SealKind::Meta.number());
            assert!(
                !raw.windows(8).any(|window| window == b"YWMETA03"),
                "{name}"
            );
        }
        assert_eq!(storage.load(FileKind::Meta).unwrap().unwrap(), second);
        assert_eq!(storage.load_prev(FileKind::Meta).unwrap().unwrap(), first);
        assert_eq!(peek_generation(FileKind::Meta, &second), Some(2));
        // Only the expected names exist (no leftover temporary file).
        assert_eq!(files.names(), ["meta.ywm", "meta.ywm.prev"]);
        // A quarantined copy keeps its kind (the name starts with meta.ywm).
        storage.quarantine(FileKind::Meta, 17).unwrap();
        assert_eq!(
            storage
                .load_copy(FileKind::Meta, "meta.ywm.corrupt-17")
                .unwrap(),
            Some(second)
        );
    }

    #[test]
    fn a_damaged_envelope_reads_as_nothing_parsable_and_blocks_the_commit() {
        let files = MemFiles::default();
        let key = SharedKey::default();
        let mut storage = sealed_storage(&files, &key);
        let inner = sidecar(JOURNAL_MAGIC, FileKind::Journal, 1);
        storage.commit(FileKind::Journal, None, &inner).unwrap();
        let path = Path::new(DIR).join("journal.ywj");
        let mut raw = files.raw(&path).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        files.put(&path, &raw);
        let read = storage.load(FileKind::Journal).unwrap().unwrap();
        assert!(read.is_empty(), "a damaged envelope reads as zero bytes");
        assert_eq!(peek_generation(FileKind::Journal, &read), None);
        assert!(
            check_vault_header(&[]).is_err(),
            "no inner format parses an empty file"
        );
        assert_eq!(
            storage.commit(FileKind::Journal, Some(1), &inner),
            Err(StorageError::Corrupt)
        );
        assert_eq!(files.raw(&path).unwrap(), raw, "nothing written");
        // A plain (unsealed) inner file is no envelope: it never reads as its inner bytes.
        files.put(&path, &inner);
        assert!(storage.load(FileKind::Journal).unwrap().unwrap().is_empty());
    }

    #[test]
    fn a_device_key_failure_is_an_error_not_damage() {
        let files = MemFiles::default();
        let key = SharedKey::default();
        let mut storage = sealed_storage(&files, &key);
        let inner = vec![3_u8; 80];
        storage.commit(FileKind::Meta, None, &inner).unwrap();
        let before = files.raw(&Path::new(DIR).join("meta.ywm")).unwrap();
        key.refuse(Some(0x7977_0004));
        assert_eq!(
            storage.load(FileKind::Meta),
            Err(StorageError::Io(0x7977_0004))
        );
        assert_eq!(
            storage.commit(FileKind::Meta, None, &inner),
            Err(StorageError::Io(0x7977_0004))
        );
        assert_eq!(
            files.raw(&Path::new(DIR).join("meta.ywm")).unwrap(),
            before,
            "nothing moved"
        );
        assert_eq!(files.names(), ["meta.ywm"]);
    }

    /// spec/15 §5.2 (2026-11-25 A2-4b review): the device key is made only by a write into a
    /// folder with no sealed file; with sealed files there a missing key is "key missing"
    /// (`StorageError::Io(0x7977_0001)`), nothing is written and no key is made.
    #[test]
    fn a_lost_device_key_is_never_replaced() {
        use yw_platform::files::FsError;
        let files = MemFiles::default();
        let key = SharedKey::default();
        key.lose();
        // A new folder (settings and logs are no sealed files): the first write makes the key.
        files.put(&Path::new(DIR).join("settings.json"), b"{}");
        files.put(&Path::new(DIR).join("logs").join("yw.log"), b"x");
        let mut storage = sealed_storage(&files, &key);
        let inner = sidecar(META_MAGIC, FileKind::Meta, 1);
        storage.commit(FileKind::Meta, None, &inner).unwrap();
        assert_eq!(key.made(), 1);
        assert_eq!(storage.load(FileKind::Meta).unwrap().unwrap(), inner);
        // The key is lost while sealed files exist: reads and every write say "key missing".
        key.lose();
        let missing = StorageError::Io(DeviceCode::KEY_MISSING);
        assert_eq!(missing, StorageError::Io(0x7977_0001));
        let before = files.names();
        assert_eq!(storage.load(FileKind::Meta), Err(missing));
        let journal = sidecar(JOURNAL_MAGIC, FileKind::Journal, 1);
        assert_eq!(
            storage.commit(FileKind::Journal, None, &journal),
            Err(missing)
        );
        let store = DataStore::new(files.clone(), key.clone(), Path::new(DIR));
        assert!(
            !store.write_sealed_keys(b"rpc:keys"),
            "a write with no read first"
        );
        let sealed = SealedFiles::new(files.clone(), key.clone());
        assert_eq!(
            sealed.write_sealed(&Path::new(DIR).join("vault.ywv.tmp"), SealKind::Vault, b"v"),
            Err(FsError::Os(DeviceCode::KEY_MISSING))
        );
        assert_eq!(files.names(), before, "nothing written");
        assert_eq!(key.made(), 1, "no new key");
        // A quarantined copy alone still counts: it was sealed with the lost key.
        files.0.lock().unwrap().clear();
        files.put(&Path::new(DIR).join("meta.ywm.corrupt-9"), b"old");
        assert_eq!(
            sealed.write_sealed(&Path::new(DIR).join("meta.ywm.tmp"), SealKind::Meta, b"m"),
            Err(FsError::Os(DeviceCode::KEY_MISSING))
        );
        assert_eq!(files.names(), ["meta.ywm.corrupt-9"]);
        assert_eq!(key.made(), 1);
        // Once the old files are moved away, the next write makes a new key.
        files.0.lock().unwrap().clear();
        assert!(store.write_sealed_keys(b"rpc:keys"));
        assert_eq!(key.made(), 2);
        // A key that cannot be made: no file (fail closed).
        files.0.lock().unwrap().clear();
        key.lose();
        key.refuse(Some(DeviceCode::BASE + 2));
        assert!(!store.write_sealed_keys(b"x"));
        assert!(files.names().is_empty());
        assert_eq!(key.made(), 2);
    }

    /// A folder that cannot be listed counts as holding sealed files: no key is made.
    #[test]
    fn an_unlistable_folder_makes_no_key() {
        use yw_platform::files::{Files, FsError};

        #[derive(Debug)]
        struct NoList(MemFiles);

        impl Files for NoList {
            fn ensure_dir(&self, dir: &Path) -> Result<(), FsError> {
                self.0.ensure_dir(dir)
            }
            fn reject_link(&self, path: &Path) -> Result<(), FsError> {
                self.0.reject_link(path)
            }
            fn read_limited_no_follow(&self, path: &Path, max: u64) -> Result<Vec<u8>, FsError> {
                self.0.read_limited_no_follow(path, max)
            }
            fn write_new_synced(&self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
                self.0.write_new_synced(path, bytes)
            }
            fn replace(&self, from: &Path, to: &Path) -> Result<(), FsError> {
                self.0.replace(from, to)
            }
            fn rename_no_replace(&self, from: &Path, to: &Path) -> Result<(), FsError> {
                self.0.rename_no_replace(from, to)
            }
            fn flush_dir(&self, dir: &Path) -> Result<(), FsError> {
                self.0.flush_dir(dir)
            }
            fn remove_file(&self, path: &Path) -> Result<(), FsError> {
                self.0.remove_file(path)
            }
            fn exists(&self, path: &Path) -> bool {
                self.0.exists(path)
            }
            fn is_file(&self, path: &Path) -> bool {
                self.0.is_file(path)
            }
            fn list_dir(&self, _dir: &Path) -> Result<Vec<std::ffi::OsString>, FsError> {
                Err(FsError::Os(13))
            }
        }

        let files = MemFiles::default();
        let key = FakeKey::default();
        key.missing.set(true);
        let sealed = SealedFiles::new(NoList(files.clone()), key);
        assert_eq!(
            sealed.write_new_synced(&Path::new(DIR).join("vault.ywv.tmp"), b"v"),
            Err(FsError::Os(DeviceCode::KEY_MISSING))
        );
        assert!(files.names().is_empty());
    }

    /// spec/15 §5.1 (2026-11-25 A2-4b review): the app store's names never start with a vault,
    /// meta or journal name, so they never meet a `rename_no_replace` target of the key worker
    /// (`<name>.corrupt-<t>`, `<name>.prev.corrupt-<t>`).
    #[test]
    fn the_app_store_names_are_not_the_vault_files() {
        for name in [
            super::SETTINGS_NAME,
            "settings.json.tmp",
            super::APIKEYS_NAME,
            "apikeys.ks.tmp",
        ] {
            for base in ["vault.ywv", "meta.ywm", "journal.ywj"] {
                assert!(!name.starts_with(base), "{name}");
            }
            assert!(matches!(
                crate::sealed_files::kind_of(Path::new(name)),
                None | Some(SealKind::ApiKeys)
            ));
        }
    }

    #[test]
    fn other_names_never_pass_unsealed() {
        use yw_platform::files::{Files, FsError};
        let sealed = SealedFiles::new(MemFiles::default(), FakeKey::default());
        let path = Path::new(DIR).join("settings.json");
        assert_eq!(
            sealed.write_new_synced(&path, b"{}"),
            Err(FsError::Os(crate::sealed_files::NOT_SEALED))
        );
        assert_eq!(
            sealed.read_limited_no_follow(&path, 10),
            Err(FsError::Os(crate::sealed_files::NOT_SEALED))
        );
        for (name, kind) in [
            ("vault.ywv", Some(SealKind::Vault)),
            ("vault.ywv.prev.tmp", Some(SealKind::Vault)),
            ("meta.ywm.corrupt-5", Some(SealKind::Meta)),
            ("journal.ywj.copy.tmp", Some(SealKind::Journal)),
            ("apikeys.ks", Some(SealKind::ApiKeys)),
            ("apikeys.ks.tmp", Some(SealKind::ApiKeys)),
            ("vault.ywvx", None),
            ("meta.ywm2", None),
            ("settings.json", None),
            ("yw.log", None),
            ("", None),
        ] {
            assert_eq!(
                crate::sealed_files::kind_of(Path::new(name)),
                kind,
                "{name}"
            );
        }
    }

    /// The whole vault over the sealed storage with the real KDF (spec/15 §5.2): create from the
    /// public test vector, write meta, drop everything, reopen, unlock, same account 0 (spec/02
    /// §11.4) and same meta; then a damaged meta envelope is `SidecarCorrupt` (spec/02's
    /// handling), and a refusing device key fails the unlock without touching a file.
    #[test]
    fn create_reopen_unlock_over_sealed_files() {
        let files = MemFiles::default();
        let key = SharedKey::default();
        let platform = DataPlatform::new(
            files.clone(),
            key.clone(),
            heap_slot,
            super::KdfHooks::UNCHECKED,
        );
        let password = VaultPassword::new(b"synthetic test password 1").unwrap();
        {
            let storage = platform.open_storage(Path::new(DIR)).unwrap();
            let mut vault = Vault::load(storage).unwrap();
            assert_eq!(vault.status(), VaultStatus::NoVault);
            vault
                .import_mnemonic(&password, &phrase(), None, platform.new_slot().unwrap(), 1)
                .unwrap();
            vault.save_sidecar(FileKind::Meta, b"meta plain").unwrap();
            let address = vault
                .evm_address(EvmKeySource::Derived(AccountIndex::ZERO))
                .unwrap();
            assert_eq!(address.to_checksum(), ACCOUNT_0);
        }
        for name in ["vault.ywv", "meta.ywm"] {
            assert_eq!(&files.raw(&Path::new(DIR).join(name)).unwrap()[..4], &MAGIC);
        }
        {
            let storage = platform.open_storage(Path::new(DIR)).unwrap();
            let mut vault = Vault::load(storage).unwrap();
            assert_eq!(vault.status(), VaultStatus::Locked);
            vault
                .unlock(&password, platform.new_slot().unwrap())
                .unwrap();
            let address = vault
                .evm_address(EvmKeySource::Derived(AccountIndex::ZERO))
                .unwrap();
            assert_eq!(address.to_checksum(), ACCOUNT_0);
            let meta = vault.open_sidecar(FileKind::Meta).unwrap().unwrap();
            assert_eq!(meta.1.expose(), b"meta plain");
        }
        // A damaged meta envelope: spec/02's damaged-sidecar error.
        let meta_path = Path::new(DIR).join("meta.ywm");
        let mut raw = files.raw(&meta_path).unwrap();
        raw[100] ^= 1;
        files.put(&meta_path, &raw);
        {
            let storage = platform.open_storage(Path::new(DIR)).unwrap();
            let mut vault = Vault::load(storage).unwrap();
            vault
                .unlock(&password, platform.new_slot().unwrap())
                .unwrap();
            assert_eq!(
                vault.open_sidecar(FileKind::Meta).map(|_| ()),
                Err(VaultError::SidecarCorrupt(FileKind::Meta))
            );
        }
        // A refusing device key: the vault does not even load; no file changes.
        let before = files.names();
        key.refuse(Some(0x7977_0001));
        let storage = platform.open_storage(Path::new(DIR)).unwrap();
        assert!(matches!(
            Vault::load(storage).map(|_| ()),
            Err(VaultError::Storage(StorageError::Io(0x7977_0001)))
        ));
        assert_eq!(files.names(), before);
        // The reset is refused and moves nothing.
        assert!(
            platform
                .move_wallet_files(Path::new(DIR), "x", true, yw_core::lang::Lang::Ko)
                .is_err()
        );
    }

    /// 2026-11-25 A2-8 (spec/15 §5.3): the platform asks its gate before every Argon2-bound call
    /// (a refusal is the call's error) and its leave runs the purge hook once, when dropped.
    #[test]
    fn the_platform_asks_its_kdf_hooks() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use yw_engine::workers::key::platform::KdfRuns;

        static DONE: AtomicUsize = AtomicUsize::new(0);
        fn one_only(runs: KdfRuns) -> Result<(), VaultError> {
            if runs == KdfRuns::One {
                Ok(())
            } else {
                Err(VaultError::OutOfMemory)
            }
        }
        fn done() {
            DONE.fetch_add(1, Ordering::SeqCst);
        }
        let platform = DataPlatform::new(
            MemFiles::default(),
            SharedKey::default(),
            heap_slot,
            super::KdfHooks {
                gate: one_only,
                done,
            },
        );
        let pass = platform.kdf_begin(KdfRuns::One).unwrap();
        assert_eq!(DONE.load(Ordering::SeqCst), 0, "not before the call ended");
        drop(pass);
        assert_eq!(DONE.load(Ordering::SeqCst), 1);
        assert!(matches!(
            platform.kdf_begin(KdfRuns::Two),
            Err(VaultError::OutOfMemory)
        ));
        assert_eq!(
            DONE.load(Ordering::SeqCst),
            1,
            "a refusal has nothing to purge"
        );
    }

    #[test]
    fn the_app_store() {
        let files = MemFiles::default();
        let key = SharedKey::default();
        let store = DataStore::new(files.clone(), key.clone(), Path::new(DIR));
        assert!(matches!(store.read_sealed_keys(), SealedRead::NotFound));
        assert!(store.write_sealed_keys(b"rpc:keys"));
        let raw = files.raw(&Path::new(DIR).join("apikeys.ks")).unwrap();
        assert_eq!(&raw[..4], &MAGIC);
        assert_eq!(raw[5], SealKind::ApiKeys.number());
        let read = store.read_sealed_keys();
        assert!(
            matches!(&read, SealedRead::Plain(plain) if plain.as_slice() == b"rpc:keys"),
            "{read:?}"
        );
        assert!(store.write_settings(b"{\"a\":1}"));
        assert_eq!(
            files.raw(&Path::new(DIR).join("settings.json")).unwrap(),
            b"{\"a\":1}",
            "settings stay plain"
        );
        assert_eq!(files.names(), ["apikeys.ks", "settings.json"]);
        let mut damaged = raw;
        damaged[95] ^= 1;
        files.put(&Path::new(DIR).join("apikeys.ks"), &damaged);
        assert!(matches!(store.read_sealed_keys(), SealedRead::Unreadable));
        key.refuse(Some(0x7977_0002));
        assert!(!store.write_sealed_keys(b"x"));
        assert!(store.vault_file_info().is_none());
        assert!(!store.prev_exists(FileKind::Vault));
        assert!(store.reset_candidates(true).is_empty());
    }
}
