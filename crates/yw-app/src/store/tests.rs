//! V-FS (spec/09 §4.1, spec/02 §6): the real `FileStorage` on a temp folder is stopped right after
//! each commit step k (1–6) via `commit_until`; a fresh storage then classifies the folder with
//! `Vault::load`. Generation 1/2 vault bytes come from a real create → backup-confirm flow.

use std::fs;
use std::path::{Path, PathBuf};

use yw_core::error::StorageError;
use yw_core::password::VaultPassword;
use yw_core::vault::{FileKind, Vault, VaultStatus, VaultStorage, peek_generation};

use super::{FileStorage, LockedSlotBox, file_name};

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "yw-app-vfs-{tag}-{}-{}",
        std::process::id(),
        yw_win::time::monotonic_ms()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn main_generation(dir: &Path) -> Option<u64> {
    peek_generation(
        FileKind::Vault,
        &fs::read(dir.join(file_name(FileKind::Vault))).ok()?,
    )
}

fn tmp_files(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| {
            std::path::Path::new(name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("tmp"))
        })
        .collect()
}

/// Generation 1 (created) and generation 2 (backup confirmed) `vault.ywv` bytes.
fn generations() -> (Vec<u8>, Vec<u8>) {
    let dir = temp_dir("seed");
    let mut vault = Vault::load(Box::new(FileStorage::open(&dir).unwrap())).unwrap();
    assert_eq!(vault.status(), VaultStatus::NoVault);
    let password = VaultPassword::new(b"m3-test-password!").unwrap();
    let slot = Box::new(LockedSlotBox::new().unwrap());
    let phrase = vault.create_wallet(&password, slot, 1_800_000_000).unwrap();
    let first = fs::read(dir.join("vault.ywv")).unwrap();
    let challenge = vault.backup_challenge().unwrap();
    let words: Vec<&str> = phrase.expose().split(' ').collect();
    let picked = challenge
        .positions
        .map(|position| words[usize::from(position) - 1]);
    vault.confirm_backup(challenge.id, picked).unwrap();
    assert_eq!(
        vault.status(),
        VaultStatus::Unlocked {
            alt_passphrase: false
        }
    );
    let second = fs::read(dir.join("vault.ywv")).unwrap();
    assert_eq!(peek_generation(FileKind::Vault, &first), Some(1));
    assert_eq!(peek_generation(FileKind::Vault, &second), Some(2));
    drop(vault);
    fs::remove_dir_all(&dir).unwrap();
    (first, second)
}

#[test]
fn v_fs_interrupted_commit_classification() {
    let (first, second) = generations();
    for step in 1..=6_u8 {
        let dir = temp_dir(&format!("k{step}"));
        let mut storage = FileStorage::open(&dir).unwrap();
        storage.commit(FileKind::Vault, None, &first).unwrap();
        storage.commit_until(step);
        assert_eq!(
            storage.commit(FileKind::Vault, Some(1), &second),
            Err(StorageError::Io(0)),
            "step {step}"
        );
        drop(storage);
        let reopened = FileStorage::open(&dir).unwrap();
        assert!(tmp_files(&dir).is_empty(), "orphan .tmp after step {step}");
        let vault = Vault::load(Box::new(reopened)).unwrap();
        assert_eq!(vault.status(), VaultStatus::Locked, "step {step}");
        let expected = if step <= 3 { 1 } else { 2 };
        assert_eq!(main_generation(&dir), Some(expected), "step {step}");
        fs::remove_dir_all(&dir).unwrap();
    }

    // Main file deleted with a .prev present → MainMissing.
    let dir = temp_dir("missing");
    let mut storage = FileStorage::open(&dir).unwrap();
    storage.commit(FileKind::Vault, None, &first).unwrap();
    storage.commit(FileKind::Vault, Some(1), &second).unwrap();
    drop(storage);
    fs::remove_file(dir.join("vault.ywv")).unwrap();
    let vault = Vault::load(Box::new(FileStorage::open(&dir).unwrap())).unwrap();
    assert_eq!(vault.status(), VaultStatus::MainMissing);
    drop(vault);
    fs::remove_dir_all(&dir).unwrap();

    // Main file truncated → Corrupt { prev_available: true }; the main bytes are untouched.
    let dir = temp_dir("truncated");
    let mut storage = FileStorage::open(&dir).unwrap();
    storage.commit(FileKind::Vault, None, &first).unwrap();
    storage.commit(FileKind::Vault, Some(1), &second).unwrap();
    drop(storage);
    let truncated = &second[..second.len() / 2];
    fs::write(dir.join("vault.ywv"), truncated).unwrap();
    let vault = Vault::load(Box::new(FileStorage::open(&dir).unwrap())).unwrap();
    assert_eq!(
        vault.status(),
        VaultStatus::Corrupt {
            prev_available: true
        }
    );
    drop(vault);
    assert_eq!(fs::read(dir.join("vault.ywv")).unwrap(), truncated);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn commit_preconditions_write_nothing() {
    let dir = temp_dir("cas");
    let mut storage = FileStorage::open(&dir).unwrap();
    assert_eq!(
        storage.commit(FileKind::Meta, Some(1), b"x"),
        Err(StorageError::GenerationConflict)
    );
    assert!(fs::read_dir(&dir).unwrap().next().is_none());
    fs::write(dir.join("meta.ywm"), b"not a sidecar").unwrap();
    assert_eq!(
        storage.commit(FileKind::Meta, None, b"x"),
        Err(StorageError::AlreadyExists)
    );
    assert_eq!(
        storage.commit(FileKind::Meta, Some(1), b"x"),
        Err(StorageError::Corrupt)
    );
    assert_eq!(fs::read(dir.join("meta.ywm")).unwrap(), b"not a sidecar");
    storage.quarantine(FileKind::Meta, 1_800_000_000).unwrap();
    assert!(dir.join("meta.ywm.corrupt-1800000000").exists());
    assert!(!dir.join("meta.ywm").exists());
    fs::remove_dir_all(&dir).unwrap();
}

/// A commit that lands but reports a failure afterwards (stopped after the replace, steps 4–6:
/// e.g. the step 6 read-back fails) is success for the vault, which re-reads the main file;
/// one stopped before the replace (steps 1–3) is a failure that leaves the folder empty.
#[test]
fn landed_commit_reported_as_failure_is_success_for_the_vault() {
    let password = VaultPassword::new(b"m3-test-password!").unwrap();
    for step in 1..=6_u8 {
        let dir = temp_dir(&format!("landed{step}"));
        let mut storage = FileStorage::open(&dir).unwrap();
        storage.commit_until(step);
        let mut vault = Vault::load(Box::new(storage)).unwrap();
        let slot = Box::new(LockedSlotBox::new().unwrap());
        let created = vault.create_wallet(&password, slot, 1_800_000_000);
        if step >= 4 {
            assert!(created.is_ok(), "step {step}");
            assert_eq!(vault.status(), VaultStatus::BackupPending, "step {step}");
            assert_eq!(main_generation(&dir), Some(1), "step {step}");
        } else {
            assert_eq!(
                created.err(),
                Some(yw_core::error::VaultError::Storage(StorageError::Io(0))),
                "step {step}"
            );
            assert_eq!(vault.status(), VaultStatus::NoVault, "step {step}");
            assert_eq!(main_generation(&dir), None, "step {step}");
        }
        drop(vault);
        fs::remove_dir_all(&dir).unwrap();
    }
}
