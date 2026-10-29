//! Regressions from adversarial review: a deleted imported Bitcoin key whose follow-up meta write
//! fails, and a password change whose follow-up rewrite fails after the `Rewrap` landed.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use yw_app::events::KeyOutcome;
use yw_app::meta;
use yw_app::store::{FileStorage, LockedSlotBox};
use yw_app::workers::journal::JournalState;
use yw_app::workers::journal::btc::{BtcKeyError, BtcMetaOp};
use yw_core::btc::{BtcAccounts, BtcNetwork, ScriptType};
use yw_core::error::{StorageError, VaultError};
use yw_core::keyimport::{ImportChain, ImportKey, ImportSpec};
use yw_core::password::VaultPassword;
use yw_core::vault::{FileKind, PasswordChange, Vault, VaultStorage};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const WIF_TEST: &str = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA";

static NEXT_DIR: AtomicU32 = AtomicU32::new(0);

fn temp_dir(tag: &str) -> TestResult<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "yw-edge-{tag}-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn slot() -> TestResult<Box<LockedSlotBox>> {
    Ok(Box::new(
        LockedSlotBox::new().map_err(|e| format!("{e:?}"))?,
    ))
}

fn password(bytes: &[u8]) -> TestResult<VaultPassword> {
    Ok(VaultPassword::new(bytes).map_err(|e| format!("{e:?}"))?)
}

/// Storage whose next meta commit fails without writing (disk full, AV lock, ...).
struct FlakyMeta {
    inner: FileStorage,
    fail_next_meta: Arc<Mutex<bool>>,
}

impl VaultStorage for FlakyMeta {
    fn load(&self, kind: FileKind) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.load(kind)
    }
    fn load_prev(&self, kind: FileKind) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.load_prev(kind)
    }
    fn commit(
        &mut self,
        kind: FileKind,
        expected: Option<u64>,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        if kind == FileKind::Meta {
            let mut fail = self
                .fail_next_meta
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if *fail {
                *fail = false;
                return Err(StorageError::Io(112)); // ERROR_DISK_FULL
            }
        }
        self.inner.commit(kind, expected, bytes)
    }
    fn quarantine(&mut self, kind: FileKind, now_unix: u64) -> Result<(), StorageError> {
        self.inner.quarantine(kind, now_unix)
    }
}

/// Deleting an imported Bitcoin key whose meta write then fails: the session drops the account
/// anyway (the vault is the source of truth), no receive address of the deleted key is handed
/// out, and no later meta write brings the account back.
#[test]
fn deleted_btc_key_account_is_gone_although_the_meta_write_failed() -> TestResult {
    let dir = temp_dir("btcdel")?;
    let fail = Arc::new(Mutex::new(false));
    let mut vault = Vault::load(Box::new(FlakyMeta {
        inner: FileStorage::open(&dir).map_err(|e| format!("{e:?}"))?,
        fail_next_meta: Arc::clone(&fail),
    }))?;
    let pw = password(b"edge-password-123")?;
    vault.import_mnemonic(&pw, ABANDON, None, slot()?, 1_793_000_000)?;

    let key = ImportKey::parse(ImportSpec::Btc(ScriptType::P2wpkh), WIF_TEST)
        .map_err(|e| format!("{e:?}"))?;
    let id = vault.import_key(key, 1_793_000_001)?;
    let keys = vault.imported_keys()?;
    let (_, info) = keys.btc.first().ok_or("btc key")?;
    let account_key = info
        .account_key(*id.as_bytes())
        .map_err(|e| format!("{e:?}"))?;

    let mut state = JournalState::default();
    state.set_btc_meta(None, BtcAccounts::default());
    let out = state.btc_meta_op(
        &mut vault,
        BtcMetaOp::AddImported {
            network: BtcNetwork::Testnet4,
            key: account_key,
        },
        false,
    );
    assert!(matches!(out.first(), Some(KeyOutcome::BtcMeta(Ok(_)))));
    let receive = BtcMetaOp::ReceiveAddress {
        network: BtcNetwork::Testnet4,
        account: account_key.id(),
    };
    assert!(matches!(
        state
            .btc_meta_op(&mut vault, receive.clone(), false)
            .first(),
        Some(KeyOutcome::BtcMeta(Ok(_)))
    ));
    // Keep a copy of the account list as the session had it (for the stale-state check below).
    let held_accounts = state.btc_accounts().clone();

    assert_eq!(vault.remove_imported_key(&pw, id)?, ImportChain::Btc);
    *fail.lock().unwrap_or_else(PoisonError::into_inner) = true;
    let out = state.btc_remove_imported(&mut vault, *id.as_bytes(), false);
    assert!(
        out.iter()
            .any(|outcome| matches!(outcome, KeyOutcome::BtcMeta(Err(BtcKeyError::Vault(_))))),
        "the write error is reported: {out:?}"
    );
    assert!(
        state
            .btc_accounts()
            .get(BtcNetwork::Testnet4, account_key.id())
            .is_none(),
        "the session no longer lists the deleted key's account"
    );
    assert!(
        matches!(
            state
                .btc_meta_op(&mut vault, receive.clone(), false)
                .first(),
            Some(KeyOutcome::BtcMeta(Err(_)))
        ),
        "no receive address of the deleted key"
    );

    // Even a session still holding the account (stale state) refuses it and never writes it.
    let mut stale_state = JournalState::default();
    stale_state.set_btc_meta(None, held_accounts);
    assert!(matches!(
        stale_state.btc_meta_op(&mut vault, receive, false).first(),
        Some(KeyOutcome::BtcMeta(Err(BtcKeyError::KeyRemoved)))
    ));
    assert!(matches!(
        stale_state
            .btc_meta_op(
                &mut vault,
                BtcMetaOp::NewReceiveAddress {
                    network: BtcNetwork::Testnet4,
                    account: account_key.id(),
                    gap_confirmed: true,
                },
                false,
            )
            .first(),
        Some(KeyOutcome::BtcMeta(Err(BtcKeyError::KeyRemoved)))
    ));
    for journal in [&state, &stale_state] {
        let mut document = meta::Meta::default();
        journal.merge_overlay(&vault, &mut document);
        vault.save_sidecar(FileKind::Meta, &document.to_json())?;
        let (_, plain) = vault.open_sidecar(FileKind::Meta)?.ok_or("meta")?;
        let on_disk = meta::parse(plain.expose()).map_err(|_| "parse")?.meta;
        assert!(
            on_disk
                .btc_accounts
                .get(BtcNetwork::Testnet4, account_key.id())
                .is_none(),
            "the deleted key's account is not written back to meta"
        );
    }
    drop(vault);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// `FileStorage` whose N-th vault commit stops after spec/02 §6.2 step 2 (the old main bytes were
/// already copied to `vault.ywv.prev`) and then fails at step 3 (`.tmp` write: disk full).
struct StopAfterPrev {
    inner: FileStorage,
    dir: PathBuf,
    vault_commits: Arc<Mutex<u32>>,
    fail_on: u32,
}

impl VaultStorage for StopAfterPrev {
    fn load(&self, kind: FileKind) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.load(kind)
    }
    fn load_prev(&self, kind: FileKind) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.load_prev(kind)
    }
    fn commit(
        &mut self,
        kind: FileKind,
        expected: Option<u64>,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        if kind == FileKind::Vault {
            let mut count = self
                .vault_commits
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            *count += 1;
            if *count == self.fail_on {
                let main =
                    std::fs::read(self.dir.join("vault.ywv")).map_err(|_| StorageError::Io(5))?;
                std::fs::write(self.dir.join("vault.ywv.prev"), main)
                    .map_err(|_| StorageError::Io(5))?;
                return Err(StorageError::Io(112));
            }
        }
        self.inner.commit(kind, expected, bytes)
    }
    fn quarantine(&mut self, kind: FileKind, now_unix: u64) -> Result<(), StorageError> {
        self.inner.quarantine(kind, now_unix)
    }
}

/// A password change whose follow-up rewrite fails after the `Rewrap` landed: the new password
/// is in effect, so the result is success (with the `.prev` warning), never "failed".
#[test]
fn password_change_after_landed_rewrap_reports_success() -> TestResult {
    let dir = temp_dir("pwchange")?;
    let commits = Arc::new(Mutex::new(0));
    let mut vault = Vault::load(Box::new(StopAfterPrev {
        inner: FileStorage::open(&dir).map_err(|e| format!("{e:?}"))?,
        dir: dir.clone(),
        vault_commits: Arc::clone(&commits),
        fail_on: 3, // 1 = import_mnemonic, 2 = Rewrap, 3 = the follow-up PayloadRewrite
    }))?;
    let old = password(b"old-password-123")?;
    let new = password(b"new-password-456")?;
    vault.import_mnemonic(&old, ABANDON, None, slot()?, 1_793_000_000)?;

    assert_eq!(
        vault.change_password(&old, &new),
        Ok(PasswordChange::PrevNotRefreshed)
    );
    assert!(
        yw_app::app::password_changed_text(PasswordChange::PrevNotRefreshed)
            .starts_with("비밀번호를 바꿨습니다.")
    );
    // The new password is the one in effect, in this session and after a restart.
    assert_eq!(
        vault.change_password(&old, &new),
        Err(VaultError::UnlockFailed)
    );
    vault.lock();
    assert_eq!(vault.unlock(&old, slot()?), Err(VaultError::UnlockFailed));
    assert!(vault.unlock(&new, slot()?).is_ok());
    drop(vault);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
