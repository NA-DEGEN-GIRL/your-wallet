//! The key worker thread `yw-key` (spec/04 §1.2): sole owner of the `Vault` and of meta writes.
//! Argon2-bound calls never run on the UI thread. `Lock` is processed before any other queued job
//! and cancels the rest with `KeyJobError::Locked`.

use std::path::{Path, PathBuf};

use yw_core::bip32::path::AccountIndex;
use yw_core::bip32::preview_evm_address;
use yw_core::error::{KeyError, VaultError};
use yw_core::password::{Bip39Passphrase, VaultPassword};
use yw_core::secret::{SecretString, Zeroizing};
use yw_core::slip10::SolKeySource;
use yw_core::sol::SolAddress;
use yw_core::vault::{EvmKeySource, FileKind, Vault, VaultStatus, VaultStorage};

use crate::errors::ErrorCode;
use crate::events::{KeyJob, KeyOutcome, KeyQueue, KeyResult, LockSignal, MetaLoaded, RevealWhat};
use crate::logging::{self, Field};
use crate::meta::{self, Account, Meta, RawAccount};
use crate::store::{FileStorage, LockedSlotBox};
use crate::workers::journal::{JournalState, SolSignTimes};

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
    journal: JournalState,
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
            journal: JournalState::default(),
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
        self.journal.clear();
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
    ) -> Result<(SecretString, yw_core::evm::address::Address), VaultError> {
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
            SecretString,
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
                    let parsed = meta::parse(plaintext.expose())
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
        let sol_sources: Vec<SolKeySource> = document
            .sol_accounts
            .iter()
            .filter_map(|account| AccountIndex::new(account.index).ok())
            .map(SolKeySource::Standard)
            .collect();
        let sol_keys = vault.sol_public_keys(&sol_sources)?;
        for (account, key) in document.sol_accounts.iter_mut().zip(sol_keys) {
            let text = SolAddress::from_bytes(key).to_base58();
            if account.address != text {
                mismatch = true;
                account.address = text;
            }
        }
        if mismatch {
            logging::warn("key", "MetaAddressMismatch", &[]);
            if !alt {
                vault.save_sidecar(FileKind::Meta, &document.to_json())?;
            }
        }
        self.journal.set_btc_meta(document.btc.as_deref().cloned());
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

    /// Runs one non-control job; journal jobs can report several outcomes (signing result,
    /// journal view, moved activity).
    pub fn handle(&mut self, job: KeyJob) -> Vec<KeyOutcome> {
        let alt = self.is_alt();
        match job {
            KeyJob::LoadJournal => match self.vault.as_mut() {
                Some(vault) => match self.journal.load(vault) {
                    Ok(view) => {
                        let mut out = self.journal.btc_startup(vault, now_unix(), alt);
                        if !out
                            .iter()
                            .any(|outcome| matches!(outcome, KeyOutcome::Journal(Ok(_))))
                        {
                            out.push(KeyOutcome::Journal(Ok(view)));
                        }
                        out
                    }
                    Err(error) => vec![KeyOutcome::Journal(Err(error))],
                },
                None => vec![KeyOutcome::Journal(Err(VaultError::InvalidState))],
            },
            KeyJob::BtcMeta { op } => match self.vault.as_mut() {
                Some(vault) => self.journal.btc_meta_op(vault, op, alt),
                None => vec![KeyOutcome::BtcMeta(Err(
                    crate::workers::journal::btc::BtcKeyError::Vault(VaultError::InvalidState),
                ))],
            },
            KeyJob::SignBtc {
                approved,
                plan,
                tip_height,
                now_unix_ms,
            } => match self.vault.as_mut() {
                Some(vault) => {
                    self.journal
                        .sign_btc(vault, approved, &plan, tip_height, now_unix_ms, alt)
                }
                None => vec![KeyOutcome::SignedBtc(Err(
                    crate::workers::journal::btc::BtcSignFailure::JournalWrite(
                        VaultError::InvalidState,
                    ),
                ))],
            },
            KeyJob::BtcJournal { op, now_unix_ms } => match self.vault.as_mut() {
                Some(vault) => self.journal.btc_journal(vault, op, now_unix_ms, alt),
                None => vec![KeyOutcome::BtcJournal(Err(
                    crate::workers::journal::btc::BtcKeyError::Vault(VaultError::InvalidState),
                ))],
            },
            KeyJob::SignEvm {
                ticket,
                approved,
                info,
            } => match self.vault.as_mut() {
                Some(vault) => self.journal.sign(vault, ticket, approved, &info, alt),
                None => vec![KeyOutcome::SignedEvm(crate::events::EvmSigned {
                    ticket,
                    result: Err(crate::events::SignFailure::JournalWrite(
                        VaultError::InvalidState,
                    )),
                })],
            },
            KeyJob::JournalApply {
                transitions,
                now_unix_ms,
            } => match self.vault.as_mut() {
                Some(vault) => self.journal.apply(vault, &transitions, now_unix_ms, alt),
                None => vec![KeyOutcome::Journal(Err(VaultError::InvalidState))],
            },
            KeyJob::SignSol {
                approved,
                consumed_at_ms,
                blockhash,
                last_valid_block_height,
                now_unix_ms,
            } => match self.vault.as_mut() {
                Some(vault) => self.journal.sign_sol(
                    vault,
                    approved,
                    SolSignTimes {
                        consumed_at_ms,
                        blockhash,
                        last_valid_block_height,
                        now_unix_ms,
                    },
                    alt,
                ),
                None => vec![KeyOutcome::SignedSol(Err(
                    crate::events::SolSignFailure::JournalWrite(VaultError::InvalidState),
                ))],
            },
            KeyJob::SolApply {
                transition,
                now_unix_ms,
            } => match self.vault.as_mut() {
                Some(vault) => self.journal.apply_sol(vault, &transition, now_unix_ms, alt),
                None => vec![KeyOutcome::Journal(Err(VaultError::InvalidState))],
            },
            other => vec![self.handle_single(other)],
        }
    }

    #[expect(clippy::too_many_lines, reason = "one arm per job kind")]
    fn handle_single(&mut self, job: KeyJob) -> KeyOutcome {
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
                let mut document = *meta;
                self.journal.merge_overlay(&mut document);
                self.vault()?
                    .save_sidecar(FileKind::Meta, &document.to_json())
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
            KeyJob::SignMessage {
                ticket,
                approved,
                typed,
            } => KeyOutcome::SignedMessage(crate::events::MessageSigned {
                ticket,
                result: match self.vault.as_ref() {
                    Some(vault) if typed => yw_core::evm::sign::sign_typed_data(vault, *approved),
                    Some(vault) => yw_core::evm::sign::sign_personal(vault, *approved),
                    None => Err(yw_core::evm::sign::SignError::Vault(
                        VaultError::InvalidState,
                    )),
                }
                .map_err(crate::events::MessageSignFailure::Sign),
            }),
            KeyJob::SolKeys { purpose, sources } => KeyOutcome::SolKeys(
                purpose,
                self.vault().and_then(|vault| {
                    let keys = vault.sol_public_keys(&sources)?;
                    Ok(sources
                        .into_iter()
                        .zip(keys)
                        .map(|(source, key)| (source, SolAddress::from_bytes(key)))
                        .collect())
                }),
            ),
            KeyJob::LoadJournal
            | KeyJob::SignEvm { .. }
            | KeyJob::JournalApply { .. }
            | KeyJob::SignSol { .. }
            | KeyJob::SolApply { .. }
            | KeyJob::BtcMeta { .. }
            | KeyJob::SignBtc { .. }
            | KeyJob::BtcJournal { .. } => KeyOutcome::Journal(Err(VaultError::InvalidState)),
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

/// Runs one popped job; `false` after `Shutdown` (the loop ends).
pub fn step(
    worker: &mut KeyWorker,
    queue: &KeyQueue,
    (epoch, job): (u64, KeyJob),
    sink: &dyn Fn(KeyResult),
    lock_signal: &LockSignal,
) -> bool {
    match job {
        KeyJob::Shutdown => {
            worker.lock();
            lock_signal.signal();
            false
        }
        KeyJob::Lock => {
            worker.lock();
            for (cancelled_epoch, cancelled) in queue.cancel_pending() {
                sink(KeyResult {
                    epoch: cancelled_epoch,
                    outcome: cancelled.cancelled_outcome(),
                });
            }
            lock_signal.signal();
            sink(KeyResult {
                epoch,
                outcome: KeyOutcome::LockDone,
            });
            true
        }
        other => {
            for outcome in worker.handle(other) {
                sink(KeyResult { epoch, outcome });
            }
            true
        }
    }
}

/// The worker loop: runs until `Shutdown`.
pub fn run(
    mut worker: KeyWorker,
    queue: &KeyQueue,
    sink: &dyn Fn(KeyResult),
    lock_signal: &LockSignal,
) {
    while let Some(entry) = queue.pop() {
        if !step(&mut worker, queue, entry, sink, lock_signal) {
            break;
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
        // `Load` is a control job: it survives the lock (spec/04 §5.3 reloads after locking).
        assert_eq!(
            names,
            ["cancelled:BackupChallenge:1", "lockdone:2", "other"]
        );
        assert!(signal.count() >= before + 2);
        // A result from before the lock (epoch 1) is dropped once the UI is at epoch 2.
        let stale = KeyResult {
            epoch: 1,
            outcome: KeyOutcome::Preview(Err(yw_core::error::KeyError::MnemonicChecksum)),
        };
        assert!(!accept_result(&stale, 2));
        assert!(accept_result(&results[1], 7));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
