//! The wallet data folder storage over the platform's [`Files`] (spec/02 §6.2, spec/15 §5.1,
//! §11.2): the `VaultStorage` of `vault.ywv`, `meta.ywm` and `journal.ywj` and the key worker's
//! [`WalletStore`].
//!
//! 2026-11-25 (spec/15 §17 A2-4a): moved here from yw-app `store::FileStorage` unchanged but for
//! the file calls, which go through [`Files`] (Windows: `yw_win::file::WinFiles`, the same
//! `yw_win::file` functions and std calls in the same order), so Android runs the same commit
//! sequence. yw-app's `store::FileStorage` wraps this type and keeps the V-FS fault point of its
//! tests ([`FileStorage::commit_with_steps`]).
//!
//! Commit sequence (spec/02 §6.2, pattern from
//! `archive/spec-v2.4:demo/sepolia-wallet/src/backend.rs:6148-6403`): (1) read and CAS-check the
//! main file, (2) previous bytes → `<name>.prev.tmp` → flush → replace to `<name>.prev`,
//! (3) new bytes → `<name>.tmp` (create-new) → flush → close, (4) replace the main file,
//! (5) flush the folder, (6) read back and compare. Orphan `*.tmp` files are removed when the
//! storage is opened.
//!
//! Links (review L8): `vault.ywv`, `meta.ywm`, `journal.ywj` and their `.prev` are never followed.
//! Reads open the file itself ([`Files::read_limited_no_follow`]) and refuse a link; a commit
//! refuses before writing anything when the folder, the main file or `.prev` is one. Folder
//! flush failures are errors (step 5 and `restore_prev`), and the folder is flushed once before
//! anything is written too, so a folder that cannot be flushed fails the commit up front.
//!
//! A failure reported after step 4 (the read-back of step 6) does not mean nothing was written:
//! the replace already happened. `Vault` re-reads the main file after every failed commit and
//! treats bytes identical to the ones it wrote as success (spec/02 §6.2), so its in-memory
//! generation never falls behind the disk.

use std::io;
use std::path::{Path, PathBuf};

use yw_core::error::StorageError;
use yw_core::vault::{FileKind, VaultStorage, peek_generation};
use yw_platform::files::{Files, FsError};

use crate::wallet_files::{file_name, is_set_aside, with_suffix};
use crate::workers::key::platform::WalletStore;

const VAULT_MAX: u64 = 65_536;
const META_MAX: u64 = 8 * 1_048_576 + 80;
const JOURNAL_MAX: u64 = 16 * 1_048_576 + 80;

const fn max_size(kind: FileKind) -> u64 {
    match kind {
        FileKind::Vault => VAULT_MAX,
        FileKind::Meta => META_MAX,
        FileKind::Journal => JOURNAL_MAX,
    }
}

/// Temporary file of [`VaultStorage::replace_copy`] (removed as an orphan on open).
const COPY_TMP: &str = ".copy.tmp";

/// The storage error of a file error: the values yw-app's `store` gave before 2026-11-25 (a
/// refused link is `Io(0x1126)`, an OS error keeps its code, a std I/O error its Win32 number).
const fn storage_error(error: FsError) -> StorageError {
    match error {
        FsError::NotFound => StorageError::NotFound,
        FsError::TooLarge => StorageError::TooLarge,
        FsError::Link => StorageError::Io(0x0000_1126),
        FsError::Os(code) => StorageError::Io(code),
        FsError::Io(kind) => StorageError::Io(match kind {
            io::ErrorKind::AlreadyExists => 183,
            io::ErrorKind::PermissionDenied => 5,
            _ => 0xFFFF_FFFF,
        }),
    }
}

/// The wallet data folder storage.
#[derive(Debug)]
pub struct FileStorage<F> {
    files: F,
    dir: PathBuf,
}

impl<F: Files> FileStorage<F> {
    /// Opens the folder (creating it) and removes orphan temporary files (spec/02 §6.2).
    ///
    /// # Errors
    ///
    /// [`StorageError`] if the folder cannot be created or a temporary file cannot be removed.
    pub fn open(files: F, dir: &Path) -> Result<Self, StorageError> {
        files.ensure_dir(dir).map_err(storage_error)?;
        let storage = Self {
            files,
            dir: dir.to_path_buf(),
        };
        for kind in [FileKind::Vault, FileKind::Meta, FileKind::Journal] {
            storage.remove_if_present(&with_suffix(dir, kind, ".tmp"))?;
            storage.remove_if_present(&with_suffix(dir, kind, ".prev.tmp"))?;
            storage.remove_if_present(&with_suffix(dir, kind, COPY_TMP))?;
        }
        Ok(storage)
    }

    /// Path of the main file.
    #[must_use]
    pub fn path(&self, kind: FileKind) -> PathBuf {
        with_suffix(&self.dir, kind, "")
    }

    /// Whether `<name>` or `<name>.prev` exists (leftover sidecar detection, spec/04 §2.2).
    #[must_use]
    pub fn any_present(&self, kind: FileKind) -> bool {
        self.files.exists(&self.path(kind))
            || self.files.exists(&with_suffix(&self.dir, kind, ".prev"))
    }

    fn remove_if_present(&self, path: &Path) -> Result<(), StorageError> {
        match self.files.remove_file(path) {
            Ok(()) | Err(FsError::NotFound) => Ok(()),
            Err(error) => Err(storage_error(error)),
        }
    }

    fn read(&self, path: &Path, kind: FileKind) -> Result<Option<Vec<u8>>, StorageError> {
        match self.files.read_limited_no_follow(path, max_size(kind)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(FsError::NotFound) => Ok(None),
            Err(error) => Err(storage_error(error)),
        }
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
        let prev = self
            .read(&with_suffix(&self.dir, kind, ".prev"), kind)?
            .ok_or(StorageError::NotFound)?;
        let quarantined = self.quarantine_main(kind, now_unix)?;
        let tmp = with_suffix(&self.dir, kind, ".tmp");
        self.remove_if_present(&tmp)?;
        self.files
            .write_new_synced(&tmp, &prev)
            .map_err(storage_error)?;
        self.files
            .replace(&tmp, &self.path(kind))
            .map_err(storage_error)?;
        self.files.flush_dir(&self.dir).map_err(storage_error)?;
        Ok(quarantined)
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
        if !self.files.exists(&self.path(kind)) {
            return Ok(None);
        }
        self.quarantine(kind, now_unix)?;
        self.files.flush_dir(&self.dir).map_err(storage_error)?;
        Ok(Some(format!("{}.corrupt-{now_unix}", file_name(kind))))
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
        let prev = with_suffix(&self.dir, kind, ".prev");
        if !self.files.exists(&prev) {
            return Ok(None);
        }
        let name = format!("{}.prev.corrupt-{now_unix}", file_name(kind));
        self.files
            .rename_no_replace(&prev, &self.dir.join(&name))
            .map_err(storage_error)?;
        self.files.flush_dir(&self.dir).map_err(storage_error)?;
        Ok(Some(name))
    }

    /// Refuses (before anything is written) a folder, main file or `.prev` that is a link, and
    /// a folder that cannot be flushed (review L8).
    fn precheck(&self, kind: FileKind) -> Result<(), StorageError> {
        self.files.reject_link(&self.dir).map_err(storage_error)?;
        self.files
            .reject_link(&self.path(kind))
            .map_err(storage_error)?;
        self.files
            .reject_link(&with_suffix(&self.dir, kind, ".prev"))
            .map_err(storage_error)?;
        self.files.flush_dir(&self.dir).map_err(storage_error)
    }

    /// [`VaultStorage::commit`] that calls `after_step(k)` right after each step k (1–6) and
    /// stops with its error. [`VaultStorage::commit`] passes `|_| Ok(())`; yw-app's
    /// `store::FileStorage` passes its `#[cfg(test)]` V-FS fault point (spec/09 §4.1), so no
    /// fault hook is kept in a production storage.
    ///
    /// # Errors
    ///
    /// As [`VaultStorage::commit`], or the error of `after_step`.
    pub fn commit_with_steps(
        &mut self,
        kind: FileKind,
        expected_generation: Option<u64>,
        bytes: &[u8],
        mut after_step: impl FnMut(u8) -> Result<(), StorageError>,
    ) -> Result<(), StorageError> {
        if u64::try_from(bytes.len()).map_or(true, |len| len > max_size(kind)) {
            return Err(StorageError::TooLarge);
        }
        // 1. Read the main file and check the precondition; nothing is written on failure.
        self.precheck(kind)?;
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
        after_step(1)?;
        // 2. The previous bytes become `<name>.prev`.
        if let Some(existing) = &current {
            let prev_tmp = with_suffix(&self.dir, kind, ".prev.tmp");
            self.remove_if_present(&prev_tmp)?;
            self.files
                .write_new_synced(&prev_tmp, existing)
                .map_err(storage_error)?;
            self.files
                .replace(&prev_tmp, &with_suffix(&self.dir, kind, ".prev"))
                .map_err(storage_error)?;
        }
        after_step(2)?;
        // 3. The new bytes go to `<name>.tmp` (create-new).
        let tmp = with_suffix(&self.dir, kind, ".tmp");
        self.remove_if_present(&tmp)?;
        self.files
            .write_new_synced(&tmp, bytes)
            .map_err(storage_error)?;
        after_step(3)?;
        // 4. Atomic replace.
        if let Err(error) = self.files.replace(&tmp, &self.path(kind)) {
            let _ = self.files.remove_file(&tmp);
            return Err(storage_error(error));
        }
        after_step(4)?;
        // 5. Folder flush. A failure is an error (review L8); the replace already happened, so
        //    `Vault`'s re-read (commit_landed) still follows the disk.
        self.files.flush_dir(&self.dir).map_err(storage_error)?;
        after_step(5)?;
        // 6. Read back.
        if self.load(kind)?.as_deref() != Some(bytes) {
            return Err(StorageError::Io(0xFFFF_FFFE));
        }
        after_step(6)?;
        Ok(())
    }

    /// The path of a copy named by [`VaultStorage::copies`]; any other name is refused.
    fn copy_path(&self, kind: FileKind, name: &str) -> Result<PathBuf, StorageError> {
        let lone_prev = format!("{}.prev", file_name(kind));
        if kind == FileKind::Vault || !(is_set_aside(kind, name) || name == lone_prev) {
            return Err(StorageError::NotFound);
        }
        Ok(self.dir.join(name))
    }
}

impl<F: Files> VaultStorage for FileStorage<F> {
    fn load(&self, kind: FileKind) -> Result<Option<Vec<u8>>, StorageError> {
        self.read(&self.path(kind), kind)
    }

    fn load_prev(&self, kind: FileKind) -> Result<Option<Vec<u8>>, StorageError> {
        self.read(&with_suffix(&self.dir, kind, ".prev"), kind)
    }

    fn commit(
        &mut self,
        kind: FileKind,
        expected_generation: Option<u64>,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        self.commit_with_steps(kind, expected_generation, bytes, |_| Ok(()))
    }

    fn quarantine(&mut self, kind: FileKind, now_unix: u64) -> Result<(), StorageError> {
        let target = with_suffix(&self.dir, kind, &format!(".corrupt-{now_unix}"));
        self.files
            .rename_no_replace(&self.path(kind), &target)
            .map_err(storage_error)
    }

    /// The set-aside `<name>.corrupt-<t>` / `<name>.prev.corrupt-<t>` files of a sidecar, and
    /// `<name>.prev` when there is no main file (2026-11-13, spec/02 §4.4 step 3). Links are left
    /// out (never followed, review L8), and so are names that are not Unicode.
    fn copies(&self, kind: FileKind) -> Result<Vec<String>, StorageError> {
        if kind == FileKind::Vault {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        for entry in self.files.list_dir(&self.dir).map_err(storage_error)? {
            let Some(name) = entry.to_str().map(str::to_owned) else {
                continue;
            };
            if is_set_aside(kind, &name) && self.files.reject_link(&self.dir.join(&name)).is_ok() {
                names.push(name);
            }
        }
        names.sort();
        let prev = with_suffix(&self.dir, kind, ".prev");
        if !self.files.exists(&self.path(kind))
            && self.files.is_file(&prev)
            && self.files.reject_link(&prev).is_ok()
        {
            names.push(format!("{}.prev", file_name(kind)));
        }
        Ok(names)
    }

    fn load_copy(&self, kind: FileKind, name: &str) -> Result<Option<Vec<u8>>, StorageError> {
        self.read(&self.copy_path(kind, name)?, kind)
    }

    fn replace_copy(
        &mut self,
        kind: FileKind,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        if u64::try_from(bytes.len()).map_or(true, |len| len > max_size(kind)) {
            return Err(StorageError::TooLarge);
        }
        let target = self.copy_path(kind, name)?;
        self.files.reject_link(&self.dir).map_err(storage_error)?;
        self.files.reject_link(&target).map_err(storage_error)?;
        if !self.files.is_file(&target) {
            return Err(StorageError::NotFound);
        }
        let tmp = with_suffix(&self.dir, kind, COPY_TMP);
        self.remove_if_present(&tmp)?;
        self.files
            .write_new_synced(&tmp, bytes)
            .map_err(storage_error)?;
        if let Err(error) = self.files.replace(&tmp, &target) {
            let _ = self.files.remove_file(&tmp);
            return Err(storage_error(error));
        }
        self.files.flush_dir(&self.dir).map_err(storage_error)
    }
}

impl<F: Files> WalletStore for FileStorage<F> {
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

/// The commit sequence on an in-memory [`Files`] that logs every call (2026-11-25, A2-4a): the
/// order of the file operations is what every platform's `Files` gets. The real-file V-FS tests
/// stay in yw-app `store` (spec/09 §4.1).
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    use yw_core::error::StorageError;
    use yw_core::vault::{FileKind, META_MAGIC, VaultStorage, peek_generation};
    use yw_platform::files::{Files, FsError};

    use super::FileStorage;

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Entry {
        File(Vec<u8>),
        Link,
    }

    #[derive(Default)]
    struct State {
        entries: BTreeMap<PathBuf, Entry>,
        log: Vec<String>,
    }

    /// One in-memory folder; clones share it.
    #[derive(Clone, Default)]
    struct MemFiles(Arc<Mutex<State>>);

    fn name(path: &Path) -> String {
        path.file_name()
            .map_or_else(String::new, |name| name.to_string_lossy().into_owned())
    }

    impl MemFiles {
        fn with<T>(&self, op: &str, paths: &[&Path], f: impl FnOnce(&mut State) -> T) -> T {
            let mut state = self.0.lock().unwrap();
            let names: Vec<String> = paths.iter().map(|path| name(path)).collect();
            state.log.push(format!("{op} {}", names.join(" -> ")));
            f(&mut state)
        }

        fn take_log(&self) -> Vec<String> {
            std::mem::take(&mut self.0.lock().unwrap().log)
        }

        fn put(&self, path: &Path, entry: Entry) {
            self.0
                .lock()
                .unwrap()
                .entries
                .insert(path.to_path_buf(), entry);
        }

        fn get(&self, path: &Path) -> Option<Entry> {
            self.0.lock().unwrap().entries.get(path).cloned()
        }

        fn names(&self) -> Vec<String> {
            self.0
                .lock()
                .unwrap()
                .entries
                .keys()
                .map(|path| name(path))
                .collect()
        }
    }

    impl Files for MemFiles {
        fn ensure_dir(&self, dir: &Path) -> Result<(), FsError> {
            self.with("ensure_dir", &[dir], |_| Ok(()))
        }

        fn reject_link(&self, path: &Path) -> Result<(), FsError> {
            self.with("reject_link", &[path], |state| {
                match state.entries.get(path) {
                    Some(Entry::Link) => Err(FsError::Link),
                    _ => Ok(()),
                }
            })
        }

        fn read_limited_no_follow(&self, path: &Path, max: u64) -> Result<Vec<u8>, FsError> {
            self.with("read", &[path], |state| match state.entries.get(path) {
                None => Err(FsError::NotFound),
                Some(Entry::Link) => Err(FsError::Link),
                Some(Entry::File(bytes)) if bytes.len() as u64 > max => Err(FsError::TooLarge),
                Some(Entry::File(bytes)) => Ok(bytes.clone()),
            })
        }

        fn write_new_synced(&self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
            self.with("write", &[path], |state| {
                if state.entries.contains_key(path) {
                    return Err(FsError::Io(std::io::ErrorKind::AlreadyExists));
                }
                state
                    .entries
                    .insert(path.to_path_buf(), Entry::File(bytes.to_vec()));
                Ok(())
            })
        }

        fn replace(&self, from: &Path, to: &Path) -> Result<(), FsError> {
            self.with("replace", &[from, to], |state| {
                let entry = state.entries.remove(from).ok_or(FsError::NotFound)?;
                state.entries.insert(to.to_path_buf(), entry);
                Ok(())
            })
        }

        fn rename_no_replace(&self, from: &Path, to: &Path) -> Result<(), FsError> {
            self.with("rename", &[from, to], |state| {
                if state.entries.contains_key(to) {
                    return Err(FsError::Os(183));
                }
                let entry = state.entries.remove(from).ok_or(FsError::NotFound)?;
                state.entries.insert(to.to_path_buf(), entry);
                Ok(())
            })
        }

        fn flush_dir(&self, dir: &Path) -> Result<(), FsError> {
            self.with("flush_dir", &[dir], |_| Ok(()))
        }

        fn remove_file(&self, path: &Path) -> Result<(), FsError> {
            self.with("remove", &[path], |state| {
                state
                    .entries
                    .remove(path)
                    .map(|_| ())
                    .ok_or(FsError::NotFound)
            })
        }

        fn exists(&self, path: &Path) -> bool {
            self.with("exists", &[path], |state| state.entries.contains_key(path))
        }

        fn is_file(&self, path: &Path) -> bool {
            self.with("is_file", &[path], |state| {
                matches!(state.entries.get(path), Some(Entry::File(_)))
            })
        }

        fn list_dir(&self, dir: &Path) -> Result<Vec<OsString>, FsError> {
            self.with("list_dir", &[dir], |state| {
                Ok(state
                    .entries
                    .keys()
                    .filter(|path| path.parent() == Some(dir))
                    .filter_map(|path| path.file_name().map(ToOwned::to_owned))
                    .collect())
            })
        }
    }

    fn dir() -> PathBuf {
        PathBuf::from("wallet")
    }

    /// A structurally valid `meta.ywm` of `generation` (header of spec/02 §5.2 and a bare tag).
    fn meta(generation: u64) -> Vec<u8> {
        let mut bytes = META_MAGIC.to_vec();
        bytes.extend_from_slice(&3_u16.to_be_bytes());
        bytes.extend_from_slice(&64_u16.to_be_bytes());
        bytes.extend_from_slice(&[7; 16]);
        bytes.extend_from_slice(&generation.to_be_bytes());
        bytes.extend_from_slice(&[0; 24]);
        bytes.extend_from_slice(&16_u32.to_be_bytes());
        bytes.extend_from_slice(&[generation.to_le_bytes()[0]; 16]);
        assert_eq!(peek_generation(FileKind::Meta, &bytes), Some(generation));
        bytes
    }

    fn generation_of(files: &MemFiles, file: &str) -> Option<u64> {
        match files.get(&dir().join(file))? {
            Entry::File(bytes) => peek_generation(FileKind::Meta, &bytes),
            Entry::Link => None,
        }
    }

    #[test]
    fn open_and_commit_run_the_spec_02_sequence() {
        let files = MemFiles::default();
        files.put(&dir().join("meta.ywm.tmp"), Entry::File(b"orphan".to_vec()));
        let mut storage = FileStorage::open(files.clone(), &dir()).unwrap();
        let mut open = vec!["ensure_dir wallet".to_owned()];
        for base in ["vault.ywv", "meta.ywm", "journal.ywj"] {
            for suffix in [".tmp", ".prev.tmp", ".copy.tmp"] {
                open.push(format!("remove {base}{suffix}"));
            }
        }
        assert_eq!(files.take_log(), open);
        assert!(files.names().is_empty(), "the orphan is gone");

        storage.commit(FileKind::Meta, None, &meta(1)).unwrap();
        assert_eq!(
            files.take_log(),
            [
                "reject_link wallet",
                "reject_link meta.ywm",
                "reject_link meta.ywm.prev",
                "flush_dir wallet",
                "read meta.ywm",
                "remove meta.ywm.tmp",
                "write meta.ywm.tmp",
                "replace meta.ywm.tmp -> meta.ywm",
                "flush_dir wallet",
                "read meta.ywm",
            ]
        );
        storage.commit(FileKind::Meta, Some(1), &meta(2)).unwrap();
        assert_eq!(
            files.take_log(),
            [
                "reject_link wallet",
                "reject_link meta.ywm",
                "reject_link meta.ywm.prev",
                "flush_dir wallet",
                "read meta.ywm",
                "remove meta.ywm.prev.tmp",
                "write meta.ywm.prev.tmp",
                "replace meta.ywm.prev.tmp -> meta.ywm.prev",
                "remove meta.ywm.tmp",
                "write meta.ywm.tmp",
                "replace meta.ywm.tmp -> meta.ywm",
                "flush_dir wallet",
                "read meta.ywm",
            ]
        );
        assert_eq!(files.names(), ["meta.ywm", "meta.ywm.prev"]);
        assert_eq!(generation_of(&files, "meta.ywm"), Some(2));
        assert_eq!(generation_of(&files, "meta.ywm.prev"), Some(1));
        assert_eq!(storage.load_prev(FileKind::Meta), Ok(Some(meta(1))));
    }

    /// The V-FS classification of spec/09 §4.1 on the in-memory folder: a commit stopped right
    /// after step k leaves the old generation for k ≤ 3 and the new one from k = 4, and a reopen
    /// removes every temporary file.
    #[test]
    fn a_commit_stopped_after_each_step() {
        for step in 1..=6_u8 {
            let files = MemFiles::default();
            let mut storage = FileStorage::open(files.clone(), &dir()).unwrap();
            storage.commit(FileKind::Meta, None, &meta(1)).unwrap();
            let stopped = storage.commit_with_steps(FileKind::Meta, Some(1), &meta(2), |at| {
                if at == step {
                    Err(StorageError::Io(0))
                } else {
                    Ok(())
                }
            });
            assert_eq!(stopped, Err(StorageError::Io(0)), "step {step}");
            drop(storage);
            let reopened = FileStorage::open(files.clone(), &dir()).unwrap();
            assert!(
                files.names().iter().all(|name| !Path::new(name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("tmp"))),
                "step {step}: {:?}",
                files.names()
            );
            let expected = if step <= 3 { 1 } else { 2 };
            assert_eq!(
                generation_of(&files, "meta.ywm"),
                Some(expected),
                "step {step}"
            );
            assert_eq!(
                generation_of(&files, "meta.ywm.prev"),
                (step >= 2).then_some(1),
                "step {step}"
            );
            assert!(reopened.any_present(FileKind::Meta));
        }
    }

    #[test]
    fn refused_commits_write_nothing() {
        const LINK: StorageError = StorageError::Io(0x0000_1126);
        let files = MemFiles::default();
        let mut storage = FileStorage::open(files.clone(), &dir()).unwrap();
        files.take_log();
        let writes = |log: &[String]| {
            log.iter()
                .filter(|line| {
                    ["write", "replace", "rename", "remove"]
                        .iter()
                        .any(|op| line.starts_with(op))
                })
                .count()
        };
        assert_eq!(
            storage.commit(FileKind::Meta, Some(1), &meta(1)),
            Err(StorageError::GenerationConflict)
        );
        files.put(
            &dir().join("meta.ywm"),
            Entry::File(b"not a sidecar".to_vec()),
        );
        assert_eq!(
            storage.commit(FileKind::Meta, None, &meta(1)),
            Err(StorageError::AlreadyExists)
        );
        assert_eq!(
            storage.commit(FileKind::Meta, Some(1), &meta(2)),
            Err(StorageError::Corrupt)
        );
        files.put(&dir().join("journal.ywj.prev"), Entry::Link);
        assert_eq!(storage.commit(FileKind::Journal, None, b"x"), Err(LINK));
        assert_eq!(storage.load_prev(FileKind::Journal), Err(LINK));
        assert_eq!(
            storage.commit(FileKind::Vault, None, &vec![0; 65_537].into_boxed_slice()),
            Err(StorageError::TooLarge)
        );
        assert_eq!(writes(&files.take_log()), 0);
        assert_eq!(files.names(), ["journal.ywj.prev", "meta.ywm"]);
    }

    #[test]
    fn sidecar_moves_and_copies() {
        let files = MemFiles::default();
        let mut storage = FileStorage::open(files.clone(), &dir()).unwrap();
        storage.commit(FileKind::Meta, None, &meta(1)).unwrap();
        storage.commit(FileKind::Meta, Some(1), &meta(2)).unwrap();
        assert_eq!(
            storage.quarantine_main(FileKind::Meta, 17),
            Ok(Some("meta.ywm.corrupt-17".to_owned()))
        );
        assert_eq!(storage.quarantine_main(FileKind::Meta, 18), Ok(None));
        // No main file: the lone `.prev` is a copy too, after the set-aside ones.
        assert_eq!(
            storage.copies(FileKind::Meta),
            Ok(vec![
                "meta.ywm.corrupt-17".to_owned(),
                "meta.ywm.prev".to_owned()
            ])
        );
        storage
            .replace_copy(FileKind::Meta, "meta.ywm.corrupt-17", &meta(3))
            .unwrap();
        assert_eq!(
            storage.load_copy(FileKind::Meta, "meta.ywm.corrupt-17"),
            Ok(Some(meta(3)))
        );
        assert_eq!(
            storage.load_copy(FileKind::Meta, "vault.ywv"),
            Err(StorageError::NotFound)
        );
        assert_eq!(
            storage.restore_prev(FileKind::Meta, 19),
            Ok(None),
            "no main file to quarantine"
        );
        assert_eq!(generation_of(&files, "meta.ywm"), Some(1));
        assert_eq!(
            storage.set_prev_aside(FileKind::Meta, 20),
            Ok(Some("meta.ywm.prev.corrupt-20".to_owned()))
        );
        assert_eq!(storage.set_prev_aside(FileKind::Meta, 21), Ok(None));
        assert_eq!(
            files.names(),
            [
                "meta.ywm",
                "meta.ywm.corrupt-17",
                "meta.ywm.prev.corrupt-20"
            ]
        );
        assert_eq!(storage.copies(FileKind::Vault), Ok(Vec::new()));
    }
}
