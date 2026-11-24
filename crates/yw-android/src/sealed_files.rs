//! The wallet data folder's [`Files`] with the device-key envelope (spec/15 §5.1–§5.2; 2026-11-25
//! A2-4b): yw-engine's `FileStorage` runs over this type unchanged (the commit sequence of spec/02
//! §6.2, `.prev`, quarantine, set-aside copies, the link refusal), and every file it reads or
//! writes is a `YWK2` envelope ([`yw_core::vault::envelope`]) on disk and its inner bytes above.
//!
//! - The kind (and so both AADs) comes from the file name: `vault.ywv`, `meta.ywm`, `journal.ywj`,
//!   `apikeys.ks`, alone or followed by `.` (`.prev`, `.tmp`, `.prev.tmp`, `.copy.tmp`,
//!   `.corrupt-<t>`). A rename keeps the kind, so a quarantined copy still opens as its kind. Any
//!   other name is refused for reading and writing ([`NOT_SEALED`]): nothing else may pass
//!   through this type unsealed (settings and logs use the plain `Files`).
//! - Each write seals with a fresh file key ([`envelope::seal`]); each read unwraps again.
//! - The device key is made here and nowhere else (spec/15 §5.2, spec/02 §5.5; 2026-11-25 A2-4b
//!   review): when a write's wrap answers "key missing" ([`DeviceCode::KEY_MISSING`]) and the
//!   folder of the file holds no file with a sealed name (any of the four names above, alone or
//!   with a suffix, `.corrupt-<t>` copies included; a folder that cannot be listed counts as
//!   holding one), [`MakeKey::make_key`] makes it and the write seals again. That is the first
//!   write of a new data folder (or one whose files the user moved away). With any sealed file
//!   there, the write fails with "key missing" and writes nothing: a lost key is reported as lost
//!   and never replaced by a new one without a word (the old files would then answer "crypto
//!   failed", and a false "missing" would make every file unreadable for good). A read never
//!   makes the key.
//! - A file that is no envelope of its kind, or whose payload tag fails, reads as **zero bytes**:
//!   no inner format parses an empty file (the vault header, meta and journal decoders all refuse
//!   it), so spec/02's handling of a damaged file applies unchanged (E-VLT-006 for a sidecar, the
//!   vault's own corrupt state). A plain (unsealed) inner file is such a file: it is never read
//!   as its inner bytes.
//! - A device-key failure (missing or unusable key, a refused GCM tag, a locked device, no answer
//!   in time) is an error ([`FsError::Os`] with the [`crate::device_key::DeviceCode`]) and never
//!   zero bytes: a key problem must not be mistaken for a damaged file and lead to a quarantine.
//! - Size limits apply to the inner bytes: the raw read allows [`OVERHEAD`] more.
//!
//! Platform-neutral (no `unsafe`, no OS call of its own): the Windows gate tests it over an
//! in-memory `Files`.
#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::path::Path;

use yw_core::secret::Zeroizing;
use yw_core::vault::envelope::{self, EnvelopeError, OVERHEAD, SealKind};
use yw_platform::files::{Files, FsError};

use crate::device_key::{DeviceCode, MakeKey};

/// The error code of a name that is not one of the sealed files.
pub const NOT_SEALED: u32 = DeviceCode::BASE + 0x110;
/// The error code of an envelope that could not be made (no randomness, too large).
pub const SEAL_FAILED: u32 = DeviceCode::BASE + 0x111;

/// The kind of a sealed file by its name (module doc), `None` for any other name.
#[must_use]
pub fn kind_of(path: &Path) -> Option<SealKind> {
    let name = path.file_name()?.to_str()?;
    [
        ("vault.ywv", SealKind::Vault),
        ("meta.ywm", SealKind::Meta),
        ("journal.ywj", SealKind::Journal),
        ("apikeys.ks", SealKind::ApiKeys),
    ]
    .into_iter()
    .find_map(|(base, kind)| {
        let rest = name.strip_prefix(base)?;
        (rest.is_empty() || rest.starts_with('.')).then_some(kind)
    })
}

fn device_error(error: EnvelopeError) -> FsError {
    match error {
        EnvelopeError::Device(code) => FsError::Os(code),
        EnvelopeError::Damaged | EnvelopeError::Random | EnvelopeError::TooLarge => {
            FsError::Os(SEAL_FAILED)
        }
    }
}

/// [`Files`] that seal what they write and open what they read (module doc).
#[derive(Debug)]
pub struct SealedFiles<F, D> {
    files: F,
    device: D,
}

impl<F: Files, D: MakeKey + Send> SealedFiles<F, D> {
    /// The sealed view of `files` with `device`.
    pub const fn new(files: F, device: D) -> Self {
        Self { files, device }
    }

    /// The plain files underneath (settings, logs, the raw bytes of a check).
    pub const fn plain(&self) -> &F {
        &self.files
    }

    /// Reads and opens `path` as `kind` (at most `max` inner bytes), wiped on drop.
    /// `Ok(None)`: the file is damaged (see the module doc).
    ///
    /// # Errors
    ///
    /// The plain read's error (not found, a link, too large) or a device-key error.
    pub fn read_sealed(
        &self,
        path: &Path,
        kind: SealKind,
        max: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, FsError> {
        let raw_max = max.saturating_add(OVERHEAD as u64);
        let raw = self.files.read_limited_no_follow(path, raw_max)?;
        match envelope::open(kind, &raw, &self.device) {
            Ok(plain) => {
                if u64::try_from(plain.len()).map_or(true, |len| len > max) {
                    return Err(FsError::TooLarge);
                }
                Ok(Some(plain))
            }
            Err(EnvelopeError::Damaged) => Ok(None),
            Err(error) => Err(device_error(error)),
        }
    }

    /// Seals `bytes` as `kind` and writes them create-new to `path`, synced. Makes the device key
    /// first only when it is missing and the folder holds no sealed file (module doc).
    ///
    /// # Errors
    ///
    /// A device-key error (`KEY_MISSING` when the key is missing and sealed files exist; nothing is
    /// written then) or the plain write's error.
    pub fn write_sealed(&self, path: &Path, kind: SealKind, bytes: &[u8]) -> Result<(), FsError> {
        let sealed = match envelope::seal(kind, bytes, &self.device) {
            Err(EnvelopeError::Device(DeviceCode::KEY_MISSING)) if self.holds_no_sealed(path) => {
                self.device.make_key().map_err(device_error)?;
                envelope::seal(kind, bytes, &self.device)
            }
            other => other,
        }
        .map_err(device_error)?;
        self.files.write_new_synced(path, &sealed)
    }

    /// Whether the folder of `path` holds no file with a sealed name (module doc); `false` when
    /// it cannot be listed.
    fn holds_no_sealed(&self, path: &Path) -> bool {
        path.parent()
            .and_then(|dir| self.files.list_dir(dir).ok())
            .is_some_and(|names| names.iter().all(|name| kind_of(Path::new(name)).is_none()))
    }
}

impl<F: Files, D: MakeKey + Send> Files for SealedFiles<F, D> {
    fn ensure_dir(&self, dir: &Path) -> Result<(), FsError> {
        self.files.ensure_dir(dir)
    }

    fn reject_link(&self, path: &Path) -> Result<(), FsError> {
        self.files.reject_link(path)
    }

    fn read_limited_no_follow(&self, path: &Path, max: u64) -> Result<Vec<u8>, FsError> {
        let kind = kind_of(path).ok_or(FsError::Os(NOT_SEALED))?;
        // The trait returns a plain `Vec`: what it carries here is the inner bytes of the vault
        // and the sidecars, which are DEK-sealed themselves (spec/02 §4–§5).
        Ok(self
            .read_sealed(path, kind, max)?
            .map(|plain| plain.to_vec())
            .unwrap_or_default())
    }

    fn write_new_synced(&self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        let kind = kind_of(path).ok_or(FsError::Os(NOT_SEALED))?;
        self.write_sealed(path, kind, bytes)
    }

    fn replace(&self, from: &Path, to: &Path) -> Result<(), FsError> {
        self.files.replace(from, to)
    }

    fn rename_no_replace(&self, from: &Path, to: &Path) -> Result<(), FsError> {
        self.files.rename_no_replace(from, to)
    }

    fn flush_dir(&self, dir: &Path) -> Result<(), FsError> {
        self.files.flush_dir(dir)
    }

    fn remove_file(&self, path: &Path) -> Result<(), FsError> {
        self.files.remove_file(path)
    }

    fn exists(&self, path: &Path) -> bool {
        self.files.exists(path)
    }

    fn is_file(&self, path: &Path) -> bool {
        self.files.is_file(path)
    }

    fn list_dir(&self, dir: &Path) -> Result<Vec<OsString>, FsError> {
        self.files.list_dir(dir)
    }
}

/// An in-memory `Files` and a stand-in device key for the tests of this crate.
#[cfg(test)]
pub(crate) mod testing {
    use std::cell::Cell;
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    use yw_core::secret::Zeroizing;
    use yw_core::vault::envelope::{DeviceKey, EnvelopeError, SealKind, WRAPPED_KEY_LEN};
    use yw_platform::files::{Files, FsError};

    use crate::device_key::{DeviceCode, MakeKey};

    /// One shared in-memory folder tree (files only; folders are implied).
    #[derive(Clone, Default, Debug)]
    pub(crate) struct MemFiles(pub(crate) Arc<Mutex<BTreeMap<PathBuf, Vec<u8>>>>);

    impl MemFiles {
        pub(crate) fn raw(&self, path: &Path) -> Option<Vec<u8>> {
            self.0.lock().unwrap().get(path).cloned()
        }

        pub(crate) fn put(&self, path: &Path, bytes: &[u8]) {
            self.0
                .lock()
                .unwrap()
                .insert(path.to_path_buf(), bytes.to_vec());
        }

        pub(crate) fn names(&self) -> Vec<String> {
            self.0
                .lock()
                .unwrap()
                .keys()
                .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
                .collect()
        }
    }

    impl Files for MemFiles {
        fn ensure_dir(&self, _dir: &Path) -> Result<(), FsError> {
            Ok(())
        }

        fn reject_link(&self, _path: &Path) -> Result<(), FsError> {
            Ok(())
        }

        fn read_limited_no_follow(&self, path: &Path, max: u64) -> Result<Vec<u8>, FsError> {
            let bytes = self.raw(path).ok_or(FsError::NotFound)?;
            if bytes.len() as u64 > max {
                return Err(FsError::TooLarge);
            }
            Ok(bytes)
        }

        fn write_new_synced(&self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
            let mut files = self.0.lock().unwrap();
            if files.contains_key(path) {
                return Err(FsError::Io(std::io::ErrorKind::AlreadyExists));
            }
            files.insert(path.to_path_buf(), bytes.to_vec());
            Ok(())
        }

        fn replace(&self, from: &Path, to: &Path) -> Result<(), FsError> {
            let mut files = self.0.lock().unwrap();
            let bytes = files.remove(from).ok_or(FsError::NotFound)?;
            files.insert(to.to_path_buf(), bytes);
            Ok(())
        }

        fn rename_no_replace(&self, from: &Path, to: &Path) -> Result<(), FsError> {
            let mut files = self.0.lock().unwrap();
            if files.contains_key(to) {
                return Err(FsError::Os(183));
            }
            let bytes = files.remove(from).ok_or(FsError::NotFound)?;
            files.insert(to.to_path_buf(), bytes);
            Ok(())
        }

        fn flush_dir(&self, _dir: &Path) -> Result<(), FsError> {
            Ok(())
        }

        fn remove_file(&self, path: &Path) -> Result<(), FsError> {
            self.0
                .lock()
                .unwrap()
                .remove(path)
                .map(|_| ())
                .ok_or(FsError::NotFound)
        }

        fn exists(&self, path: &Path) -> bool {
            self.0.lock().unwrap().contains_key(path)
        }

        fn is_file(&self, path: &Path) -> bool {
            self.exists(path)
        }

        fn list_dir(&self, dir: &Path) -> Result<Vec<OsString>, FsError> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .keys()
                .filter(|path| path.parent() == Some(dir))
                .filter_map(|path| path.file_name().map(OsString::from))
                .collect())
        }
    }

    /// A stand-in device key (XOR with a pad and the kind byte); `refuse` fails every call;
    /// `missing` answers `KEY_MISSING` to a wrap and an unwrap until `make_key` (counted in `made`).
    #[derive(Debug, Default)]
    pub(crate) struct FakeKey {
        pub(crate) refuse: Cell<Option<u32>>,
        pub(crate) missing: Cell<bool>,
        pub(crate) made: Cell<u32>,
        pub(crate) calls: Cell<u32>,
    }

    impl FakeKey {
        fn check(&self) -> Result<(), EnvelopeError> {
            self.calls.set(self.calls.get() + 1);
            if let Some(code) = self.refuse.get() {
                return Err(EnvelopeError::Device(code));
            }
            if self.missing.get() {
                return Err(EnvelopeError::Device(DeviceCode::KEY_MISSING));
            }
            Ok(())
        }
    }

    impl MakeKey for FakeKey {
        fn make_key(&self) -> Result<(), EnvelopeError> {
            if let Some(code) = self.refuse.get() {
                return Err(EnvelopeError::Device(code));
            }
            if self.missing.get() {
                self.missing.set(false);
                self.made.set(self.made.get() + 1);
            }
            Ok(())
        }
    }

    impl DeviceKey for FakeKey {
        fn wrap(
            &self,
            kind: SealKind,
            file_key: &[u8; 32],
        ) -> Result<[u8; WRAPPED_KEY_LEN], EnvelopeError> {
            self.check()?;
            let mut out = [0x11_u8; WRAPPED_KEY_LEN];
            for (at, byte) in file_key.iter().enumerate() {
                out[12 + at] = byte ^ 0x5a ^ kind.number();
            }
            Ok(out)
        }

        fn unwrap(
            &self,
            kind: SealKind,
            wrapped: &[u8; WRAPPED_KEY_LEN],
        ) -> Result<Zeroizing<[u8; 32]>, EnvelopeError> {
            self.check()?;
            let mut key = Zeroizing::new([0_u8; 32]);
            for (at, byte) in key.iter_mut().enumerate() {
                *byte = wrapped[12 + at] ^ 0x5a ^ kind.number();
            }
            Ok(key)
        }
    }
}
