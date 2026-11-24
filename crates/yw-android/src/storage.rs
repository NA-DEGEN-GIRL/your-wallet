//! The Android key-worker platform and app store over the sealed files (spec/15 §5.1–§5.3, §11.2;
//! 2026-11-25 A2-4b).
//!
//! - [`DataPlatform`] is the engine's [`KeyPlatform`]: [`KeyPlatform::open_storage`] gives yw-engine's
//!   `FileStorage` over [`SealedFiles`] (the commit sequence of spec/02 §6.2 unchanged, every file a
//!   `YWK2` envelope), [`KeyPlatform::new_slot`] the platform's locked slot (Android:
//!   `slot::AndroidSlot`, `mmap` + `mlock` + `madvise(MADV_DONTDUMP)`, fail closed).
//!   `move_wallet_files` (the wallet reset, spec/04 §2.20) is not on Android before its settings
//!   screen: it refuses and moves nothing.
//! - [`DataStore`] is the engine's [`AppStore`]: `settings.json` plain and atomic (temp → sync →
//!   rename → folder sync), `apikeys.ks` sealed ([`SealKind::ApiKeys`]; a damaged file is
//!   "unreadable", never its raw bytes), the `vault.ywv` facts (the generation needs the device key:
//!   the inner header is inside the envelope), `.prev` checks; no reset candidates (as above).
//!
//! Platform-neutral over any [`Files`] (the Windows gate tests it in memory); Android passes
//! `android_files::AndroidFiles` and the broker's device key.

use core::fmt;
use std::path::{Path, PathBuf};

use yw_core::error::{StorageError, VaultError};
use yw_core::lang::Lang;
use yw_core::vault::envelope::{DeviceKey, SealKind};
use yw_core::vault::{FileKind, LockedSlot, peek_generation};
use yw_engine::app_store::{AppStore, SealedRead};
use yw_engine::file_storage::FileStorage;
use yw_engine::wallet_files::{ResetError, ResetReport, file_name, with_suffix};
use yw_engine::workers::key::platform::{KeyPlatform, WalletStore};
use yw_platform::files::{Files, FsError};

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

/// The key worker's platform on Android (module doc).
pub struct DataPlatform<F, D> {
    files: F,
    device: D,
    slot: SlotMaker,
}

impl<F, D> fmt::Debug for DataPlatform<F, D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DataPlatform")
    }
}

impl<F, D> DataPlatform<F, D> {
    /// The platform over `files` and `device`, making slots with `slot`.
    pub const fn new(files: F, device: D, slot: SlotMaker) -> Self {
        Self {
            files,
            device,
            slot,
        }
    }
}

impl<F, D> KeyPlatform for DataPlatform<F, D>
where
    F: Files + Clone + 'static,
    D: DeviceKey + Send + Clone + 'static,
{
    fn open_storage(&self, dir: &Path) -> Result<Box<dyn WalletStore>, StorageError> {
        let sealed = SealedFiles::new(self.files.clone(), self.device.clone());
        Ok(Box::new(FileStorage::open(sealed, dir)?))
    }

    fn new_slot(&self) -> Result<Box<dyn LockedSlot>, VaultError> {
        (self.slot)()
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

impl<F: Files, D: DeviceKey + Send> DataStore<F, D> {
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

impl<F: Files, D: DeviceKey + Send> AppStore for DataStore<F, D> {
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
    use crate::sealed_files::SealedFiles;
    use crate::sealed_files::testing::{FakeKey, MemFiles};

    /// A shareable stand-in device key (the platform clones it per storage).
    #[derive(Clone, Debug, Default)]
    struct SharedKey(std::sync::Arc<std::sync::Mutex<Option<u32>>>);

    impl yw_core::vault::envelope::DeviceKey for SharedKey {
        fn wrap(
            &self,
            kind: SealKind,
            file_key: &[u8; 32],
        ) -> Result<[u8; 60], yw_core::vault::envelope::EnvelopeError> {
            let fake = FakeKey::default();
            fake.refuse.set(*self.0.lock().unwrap());
            fake.wrap(kind, file_key)
        }

        fn unwrap(
            &self,
            kind: SealKind,
            wrapped: &[u8; 60],
        ) -> Result<yw_core::secret::Zeroizing<[u8; 32]>, yw_core::vault::envelope::EnvelopeError>
        {
            let fake = FakeKey::default();
            fake.refuse.set(*self.0.lock().unwrap());
            fake.unwrap(kind, wrapped)
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
        *key.0.lock().unwrap() = Some(0x7977_0004);
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
        let platform = DataPlatform::new(files.clone(), key.clone(), heap_slot);
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
        *key.0.lock().unwrap() = Some(0x7977_0001);
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
        *key.0.lock().unwrap() = Some(0x7977_0002);
        assert!(!store.write_sealed_keys(b"x"));
        assert!(store.vault_file_info().is_none());
        assert!(!store.prev_exists(FileKind::Vault));
        assert!(store.reset_candidates(true).is_empty());
    }
}
