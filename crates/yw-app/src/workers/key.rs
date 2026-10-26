//! The key worker thread `yw-key` (spec/04 §1.2): sole owner of the `Vault` and of meta writes.
//! Argon2-bound calls never run on the UI thread. `Lock` is processed before any other queued job
//! and cancels the rest with `KeyJobError::Locked`.

use std::path::{Path, PathBuf};

use yw_core::bip32::path::AccountIndex;
use yw_core::bip32::preview_evm_address;
use yw_core::error::{KeyError, VaultError};
use yw_core::password::{Bip39Passphrase, VaultPassword};
use yw_core::secret::Zeroizing;
use yw_core::vault::{EvmKeySource, FileKind, Vault, VaultStatus, VaultStorage};

use crate::errors::ErrorCode;
use crate::events::{
    KeyJob, KeyJobError, KeyOutcome, KeyQueue, KeyResult, LockSignal, MetaLoaded, RevealWhat,
};
use crate::logging::{self, Field};
use crate::meta::{self, Account, Meta, RawAccount};
use crate::store::{FileStorage, LockedSlotBox};

struct PendingImport {
    phrase: Zeroizing<Vec<u8>>,
    passphrase: Option<Zeroizing<Vec<u8>>>,
}

/// Worker state.
pub struct KeyWorker {
    dir: PathBuf,
    vault: Option<Vault>,
    pending_password: Option<Zeroizing<Vec<u8>>>,
    pending: Option<PendingImport>,
}

impl core::fmt::Debug for KeyWorker {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("KeyWorker")
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn ascii(bytes: &[u8]) -> Result<&str, KeyError> {
    core::str::from_utf8(bytes).map_err(|_| KeyError::MnemonicFormat)
}

fn new_slot() -> Result<Box<LockedSlotBox>, VaultError> {
    LockedSlotBox::new()
        .map(Box::new)
        .map_err(|_| VaultError::OutOfMemory)
}

fn password(bytes: &[u8]) -> Result<VaultPassword, VaultError> {
    VaultPassword::new(bytes).map_err(VaultError::Key)
}

fn passphrase(bytes: &[u8]) -> Result<Bip39Passphrase, KeyError> {
    Bip39Passphrase::new(core::str::from_utf8(bytes).map_err(|_| KeyError::PassphraseInvalidChar)?)
}

impl KeyWorker {
    /// A worker for the data folder `dir`.
    #[must_use]
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
            vault: None,
            pending_password: None,
            pending: None,
        }
    }

    fn vault(&mut self) -> Result<&mut Vault, VaultError> {
        self.vault.as_mut().ok_or(VaultError::InvalidState)
    }

    fn is_alt(&self) -> bool {
        matches!(
            self.vault.as_ref().map(Vault::status),
            Some(VaultStatus::Unlocked {
                alt_passphrase: true
            })
        )
    }

    /// Locks the vault and wipes held import buffers.
    pub fn lock(&mut self) {
        self.pending = None;
        self.pending_password = None;
        if let Some(vault) = self.vault.as_mut() {
            vault.lock();
        }
    }

    fn load(&mut self) -> KeyOutcome {
        let storage = match FileStorage::open(&self.dir) {
            Ok(storage) => storage,
            Err(error) => {
                return KeyOutcome::Status(Err(VaultError::Storage(error)));
            }
        };
        let leftover =
            storage.any_present(FileKind::Meta) || storage.any_present(FileKind::Journal);
        match Vault::load(Box::new(storage)) {
            Ok(vault) => {
                let status = vault.status();
                self.vault = Some(vault);
                KeyOutcome::Loaded {
                    status,
                    leftover: leftover && status == VaultStatus::NoVault,
                }
            }
            Err(error) => KeyOutcome::Status(Err(error)),
        }
    }

    fn write_default_meta(vault: &mut Vault, address: &yw_core::evm::address::Address) {
        let mut document = Meta::default();
        if let Some(first) = document.evm_accounts.first_mut() {
            first.address = address.to_lower_hex();
        }
        if let Err(error) = vault.save_sidecar(FileKind::Meta, &document.to_json()) {
            logging::warn(
                "key",
                "meta.write_failed",
                &[("code", Field::Code(crate::errors::vault_code(error)))],
            );
        }
    }

    fn create(
        &mut self,
        password_bytes: &[u8],
    ) -> Result<(Zeroizing<String>, yw_core::evm::address::Address), VaultError> {
        let password = password(password_bytes)?;
        let slot = new_slot()?;
        let vault = self.vault()?;
        let phrase = vault.create_wallet(&password, slot, now_unix())?;
        let address = vault.evm_address(EvmKeySource::Derived(AccountIndex::ZERO))?;
        Self::write_default_meta(vault, &address);
        Ok((phrase, address))
    }

    fn preview(
        &mut self,
        pending: PendingImport,
    ) -> Result<yw_core::evm::address::Address, KeyError> {
        let result = (|| {
            let phrase = ascii(&pending.phrase)?;
            let passphrase = pending
                .passphrase
                .as_deref()
                .map(|bytes| passphrase(bytes))
                .transpose()?;
            preview_evm_address(phrase, passphrase.as_ref(), AccountIndex::ZERO)
        })();
        if result.is_ok() {
            self.pending = Some(pending);
        }
        result
    }

    fn commit_import(&mut self) -> Result<(), VaultError> {
        let pending = self.pending.take().ok_or(VaultError::InvalidState)?;
        let held = self
            .pending_password
            .take()
            .ok_or(VaultError::InvalidState)?;
        let password = password(&held)?;
        let phrase = ascii(&pending.phrase).map_err(VaultError::Key)?;
        let passphrase = pending
            .passphrase
            .as_deref()
            .map(|bytes| passphrase(bytes))
            .transpose()
            .map_err(VaultError::Key)?;
        let slot = new_slot()?;
        let vault = self.vault()?;
        vault.import_mnemonic(&password, phrase, passphrase, slot, now_unix())?;
        let address = vault.evm_address(EvmKeySource::Derived(AccountIndex::ZERO))?;
        Self::write_default_meta(vault, &address);
        Ok(())
    }

    fn reveal(
        &mut self,
        password_bytes: &[u8],
        what: RevealWhat,
    ) -> Result<
        (
            RevealWhat,
            Zeroizing<String>,
            Option<yw_core::evm::address::Address>,
        ),
        VaultError,
    > {
        let password = password(password_bytes).map_err(|_| VaultError::UnlockFailed)?;
        let vault = self.vault()?;
        match what {
            RevealWhat::Mnemonic => {
                let phrase = vault.reveal_mnemonic(&password)?;
                let address = vault.evm_address(EvmKeySource::Derived(AccountIndex::ZERO))?;
                Ok((what, phrase, Some(address)))
            }
            RevealWhat::PrivateKey(source) => {
                let hex = vault.reveal_evm_private_key(&password, source)?;
                Ok((what, hex, None))
            }
        }
    }

    fn load_meta(&mut self) -> Result<MetaLoaded, VaultError> {
        let alt = self.is_alt();
        let vault = self.vault()?;
        let (mut document, prefs_reset) = if alt {
            (Meta::default(), false)
        } else {
            match vault.open_sidecar(FileKind::Meta)? {
                None => (Meta::default(), false),
                Some((_, plaintext)) => {
                    let parsed = meta::parse(&plaintext)
                        .map_err(|_| VaultError::SidecarCorrupt(FileKind::Meta))?;
                    (parsed.meta, parsed.prefs_reset)
                }
            }
        };
        let indices: Vec<AccountIndex> = document
            .evm_accounts
            .iter()
            .filter_map(|account| AccountIndex::new(account.index).ok())
            .collect();
        let addresses = vault.evm_addresses(&indices)?;
        let mut mismatch = false;
        for (account, address) in document.evm_accounts.iter_mut().zip(addresses) {
            let text = address.to_lower_hex();
            if account.address != text {
                mismatch = true;
                account.address = text;
            }
        }
        let raw_keys = vault.raw_keys()?;
        let mut raw_accounts: Vec<RawAccount> = Vec::with_capacity(raw_keys.len());
        for (position, (id, address)) in raw_keys.iter().enumerate() {
            let text = address.to_lower_hex();
            let existing = document
                .evm_raw_accounts
                .iter()
                .find(|raw| raw.record_id == *id.as_bytes());
            let label = existing.map_or_else(
                || format!("가져온 계정 {}", position.saturating_add(1)),
                |raw| raw.label.clone(),
            );
            if existing.is_none_or(|raw| raw.address != text) {
                mismatch = true;
            }
            raw_accounts.push(RawAccount {
                record_id: *id.as_bytes(),
                label,
                address: text,
            });
        }
        if raw_accounts.len() != document.evm_raw_accounts.len() {
            mismatch = true;
        }
        document.evm_raw_accounts = raw_accounts;
        if mismatch {
            logging::warn("key", "MetaAddressMismatch", &[]);
            if !alt {
                vault.save_sidecar(FileKind::Meta, &document.to_json())?;
            }
        }
        Ok(MetaLoaded {
            meta: document,
            mismatch,
            prefs_reset,
        })
    }

    fn resolve_sidecar(&mut self, kind: FileKind, use_prev: bool) -> Result<(), ErrorCode> {
        let mut storage = FileStorage::open(&self.dir).map_err(|_| ErrorCode::Vlt006)?;
        let now = now_unix();
        if use_prev {
            storage
                .restore_prev(kind, now)
                .map_err(|_| ErrorCode::Vlt006)
        } else {
            storage.quarantine(kind, now).map_err(|_| ErrorCode::Vlt006)
        }
    }

    /// Runs one non-control job.
    #[expect(clippy::too_many_lines, reason = "one arm per job kind")]
    pub fn handle(&mut self, job: KeyJob) -> KeyOutcome {
        match job {
            KeyJob::Load => self.load(),
            KeyJob::CreateWallet { password } => KeyOutcome::Created(self.create(&password)),
            KeyJob::PreviewImport {
                password,
                phrase,
                passphrase,
            } => {
                if let Some(password) = password {
                    self.pending_password = Some(password);
                }
                KeyOutcome::Preview(self.preview(PendingImport { phrase, passphrase }))
            }
            KeyJob::DiscardImport { keep_password } => {
                self.pending = None;
                if !keep_password {
                    self.pending_password = None;
                }
                KeyOutcome::Imported(Err(VaultError::InvalidState))
            }
            KeyJob::CommitImport => KeyOutcome::Imported(self.commit_import()),
            KeyJob::Unlock { password: bytes } => KeyOutcome::Status((|| {
                let password = password(&bytes).map_err(|_| VaultError::UnlockFailed)?;
                let slot = new_slot()?;
                self.vault()?.unlock(&password, slot)
            })()),
            KeyJob::EnterPassphrase { passphrase: bytes } => KeyOutcome::Status((|| {
                let passphrase = passphrase(&bytes).map_err(VaultError::Key)?;
                self.vault()?.enter_passphrase(passphrase)
            })()),
            KeyJob::RetryPassphrase => {
                KeyOutcome::Status(self.vault().and_then(Vault::retry_passphrase))
            }
            KeyJob::AcceptMismatch => {
                KeyOutcome::Status(self.vault().and_then(Vault::accept_mismatched_passphrase))
            }
            KeyJob::BackupChallenge => {
                KeyOutcome::Challenge(self.vault().and_then(Vault::backup_challenge))
            }
            KeyJob::ConfirmBackup { id, words, suffix } => KeyOutcome::BackupConfirmed((|| {
                let texts: Vec<&str> = words
                    .iter()
                    .map(|word| core::str::from_utf8(word).unwrap_or(""))
                    .collect();
                let answers = [
                    texts.first().copied().unwrap_or(""),
                    texts.get(1).copied().unwrap_or(""),
                    texts.get(2).copied().unwrap_or(""),
                    texts.get(3).copied().unwrap_or(""),
                ];
                let suffix = core::str::from_utf8(&suffix).unwrap_or("");
                self.vault()?.confirm_backup(id, answers, suffix)
            })(
            )),
            KeyJob::Reveal { password, what } => KeyOutcome::Revealed(self.reveal(&password, what)),
            KeyJob::ChangePassword { old, new } => KeyOutcome::PasswordChanged((|| {
                let old = password(&old).map_err(|_| VaultError::UnlockFailed)?;
                let new = password(&new)?;
                self.vault()?.change_password(&old, &new)
            })()),
            KeyJob::ImportPrivateKey { hex } => KeyOutcome::RawKeyImported((|| {
                let text = core::str::from_utf8(&hex)
                    .map_err(|_| VaultError::Key(KeyError::InvalidPrivateKey))?;
                let vault = self.vault()?;
                let id = vault.import_evm_private_key(text, now_unix())?;
                let address = vault.evm_address(EvmKeySource::Raw(id))?;
                Ok((id, address))
            })()),
            KeyJob::RemoveRawKey {
                password: bytes,
                id,
            } => KeyOutcome::RawKeyRemoved((|| {
                let password = password(&bytes).map_err(|_| VaultError::UnlockFailed)?;
                self.vault()?.remove_evm_raw_key(&password, id)?;
                Ok(id)
            })()),
            KeyJob::RecoverFromPrev { password: bytes } => KeyOutcome::Status((|| {
                let password = password(&bytes).map_err(|_| VaultError::UnlockFailed)?;
                let slot = new_slot()?;
                self.vault()?.recover_from_prev(&password, slot, now_unix())
            })()),
            KeyJob::LoadMeta => KeyOutcome::Meta(self.load_meta()),
            KeyJob::SaveMeta { meta } => KeyOutcome::MetaSaved((|| {
                if self.is_alt() {
                    return Ok(());
                }
                self.vault()?
                    .save_sidecar(FileKind::Meta, &meta.to_json())
                    .map(|_| ())
            })()),
            KeyJob::ResolveSidecar { kind, use_prev } => {
                KeyOutcome::SidecarResolved(self.resolve_sidecar(kind, use_prev))
            }
            KeyJob::DeriveAddresses { indices } => KeyOutcome::Addresses((|| {
                let parsed: Vec<AccountIndex> = indices
                    .iter()
                    .map(|index| AccountIndex::new(*index))
                    .collect::<Result<_, _>>()
                    .map_err(VaultError::Key)?;
                let addresses = self.vault()?.evm_addresses(&parsed)?;
                Ok(indices.into_iter().zip(addresses).collect())
            })()),
            KeyJob::Lock | KeyJob::Shutdown => {
                self.lock();
                KeyOutcome::LockDone
            }
        }
    }
}

/// A default account entry for `계정 추가`.
#[must_use]
pub fn new_account(index: u32, address: &yw_core::evm::address::Address) -> Account {
    Account {
        index,
        label: format!("계정 {}", index.saturating_add(1)),
        address: address.to_lower_hex(),
        hidden: false,
    }
}

/// The worker loop: runs until `Shutdown`.
pub fn run(
    mut worker: KeyWorker,
    queue: &KeyQueue,
    sink: &dyn Fn(KeyResult),
    lock_signal: &LockSignal,
) {
    while let Some((epoch, job)) = queue.pop() {
        match job {
            KeyJob::Shutdown => {
                worker.lock();
                lock_signal.signal();
                break;
            }
            KeyJob::Lock => {
                worker.lock();
                for (cancelled_epoch, cancelled) in queue.cancel_pending() {
                    sink(KeyResult {
                        epoch: cancelled_epoch,
                        outcome: KeyOutcome::Cancelled(cancelled.name(), KeyJobError::Locked),
                    });
                }
                lock_signal.signal();
                sink(KeyResult {
                    epoch,
                    outcome: KeyOutcome::LockDone,
                });
            }
            other => {
                let outcome = worker.handle(other);
                sink(KeyResult { epoch, outcome });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::{KeyWorker, run};
    use crate::events::{
        KeyJob, KeyJobError, KeyOutcome, KeyQueue, KeyResult, LockSignal, accept_result,
    };

    #[test]
    fn lk2_lock_jumps_the_queue_and_cancels_pending_jobs() {
        let dir = std::env::temp_dir().join(format!(
            "yw-app-lk2-{}-{}",
            std::process::id(),
            yw_win::time::monotonic_ms()
        ));
        let queue = KeyQueue::default();
        queue.push(1, KeyJob::Load);
        queue.push(1, KeyJob::BackupChallenge);
        queue.push(2, KeyJob::Lock);
        queue.push(2, KeyJob::Shutdown);
        let results: Mutex<Vec<KeyResult>> = Mutex::new(Vec::new());
        let signal = LockSignal::default();
        let before = signal.count();
        run(
            KeyWorker::new(&dir),
            &queue,
            &|result| results.lock().unwrap().push(result),
            &signal,
        );
        let results = results.into_inner().unwrap();
        let names: Vec<String> = results
            .iter()
            .map(|result| match &result.outcome {
                KeyOutcome::Cancelled(name, KeyJobError::Locked) => {
                    format!("cancelled:{name}:{}", result.epoch)
                }
                KeyOutcome::LockDone => format!("lockdone:{}", result.epoch),
                _ => "other".to_owned(),
            })
            .collect();
        assert_eq!(
            names,
            [
                "cancelled:Load:1",
                "cancelled:BackupChallenge:1",
                "lockdone:2"
            ]
        );
        assert!(signal.count() >= before + 2);
        // A result from before the lock (epoch 1) is dropped once the UI is at epoch 2.
        let stale = KeyResult {
            epoch: 1,
            outcome: KeyOutcome::Preview(Err(yw_core::error::KeyError::MnemonicChecksum)),
        };
        assert!(!accept_result(&stale, 2));
        assert!(accept_result(&results[2], 7));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
