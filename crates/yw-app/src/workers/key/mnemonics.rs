//! The key worker's recovery-phrase jobs (several mnemonics in one wallet, spec/02 §8.6,
//! spec/04 §2.22): "복구 단어 추가 가져오기" (the entered words and passphrase are held between the
//! address preview and the commit, never on disk, wiped by [`MnJob::Discard`] and every lock),
//! "새 복구 단어 만들기 (추가)" with its backup quiz, reveal, removal, the accounts of an added
//! mnemonic, and the meta `mnemonics` reconciliation at meta load.

use yw_core::bip32::path::AccountIndex;
use yw_core::bip32::preview_evm_address;
use yw_core::error::{KeyError, VaultError};
use yw_core::evm::address::Address;
use yw_core::secret::{SecretString, Zeroizing};
use yw_core::vault::{BackupChallenge, ChallengeId, EvmKeySource, RecordId, Vault};

use super::{KeyWorker, PendingImport, ascii, now_unix, passphrase, password};
use crate::events::KeyOutcome;
use crate::meta::{self, Account, EvmAccountPref, Meta, MnemonicEntry};

/// A recovery-phrase job of the key worker.
pub enum MnJob {
    /// Parse the entered words (+ passphrase), hold them and derive account 0 for the preview.
    Preview {
        /// Recovery words (W05).
        phrase: Zeroizing<Vec<u8>>,
        /// BIP39 passphrase (W06), if used.
        passphrase: Option<Zeroizing<Vec<u8>>>,
    },
    /// Wipe the held words.
    Discard,
    /// Add the held words to the vault (`Vault::add_mnemonic`; the password is checked there).
    CommitImport {
        /// Vault password (W03).
        password: Zeroizing<Vec<u8>>,
    },
    /// `Vault::generate_mnemonic`: the words come back once for W08.
    Generate {
        /// Vault password (W03).
        password: Zeroizing<Vec<u8>>,
    },
    /// The backup quiz of mnemonic `id`.
    Challenge {
        /// Mnemonic.
        id: RecordId,
    },
    /// The four answers of the quiz.
    Confirm {
        /// Mnemonic.
        id: RecordId,
        /// Challenge.
        challenge: ChallengeId,
        /// Answers in position order.
        words: [Zeroizing<Vec<u8>>; 4],
    },
    /// The words of mnemonic `id` (W08).
    Reveal {
        /// Vault password (W03).
        password: Zeroizing<Vec<u8>>,
        /// Mnemonic.
        id: RecordId,
        /// Continue with the backup quiz (an added mnemonic whose backup is open).
        then_backup: bool,
    },
    /// Remove the added mnemonic `id`.
    Remove {
        /// Vault password (W03).
        password: Zeroizing<Vec<u8>>,
        /// Mnemonic.
        id: RecordId,
    },
    /// The address of EVM account `index` of mnemonic `id` ("계정 추가").
    Derive {
        /// Mnemonic.
        id: RecordId,
        /// Account index.
        index: u32,
    },
}

impl core::fmt::Debug for MnJob {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.name())
    }
}

impl MnJob {
    /// Static name for logs.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Preview { .. } => "MnPreview",
            Self::Discard => "MnDiscard",
            Self::CommitImport { .. } => "MnCommitImport",
            Self::Generate { .. } => "MnGenerate",
            Self::Challenge { .. } => "MnChallenge",
            Self::Confirm { .. } => "MnConfirm",
            Self::Reveal { .. } => "MnReveal",
            Self::Remove { .. } => "MnRemove",
            Self::Derive { .. } => "MnDerive",
        }
    }
}

/// What a recovery-phrase job produced.
#[derive(Debug)]
pub enum MnOutcome {
    /// `Preview`: account 0 of the entered words.
    Preview(Result<Address, KeyError>),
    /// `Discard` done.
    Discarded,
    /// `CommitImport` (`UnlockFailed` keeps the held words for another password try).
    Added(Result<RecordId, VaultError>),
    /// `Generate`: the new mnemonic, its words (W08) and account 0.
    Generated(Result<(RecordId, SecretString, Address), VaultError>),
    /// `Challenge`.
    Challenge(Result<(RecordId, BackupChallenge), VaultError>),
    /// `Confirm` (`BackupMismatch`/`ChallengeStale`: ask again with new positions).
    Confirmed(Result<RecordId, VaultError>),
    /// `Reveal`: the words and whether the quiz follows.
    Revealed(Result<(RecordId, SecretString, bool), VaultError>),
    /// `Remove`.
    Removed(Result<RecordId, VaultError>),
    /// `Derive`.
    Derived(Result<(RecordId, u32, Address), VaultError>),
    /// The passphrase window asks for mnemonic `position` of `count` (sent before the
    /// `PassphraseRequired` status when the vault has several mnemonics).
    PassphraseFor(usize, usize),
}

fn text(word: &Zeroizing<Vec<u8>>) -> &str {
    core::str::from_utf8(word).unwrap_or("")
}

fn answers(words: &[Zeroizing<Vec<u8>>; 4]) -> [&str; 4] {
    let [a, b, c, d] = words;
    [text(a), text(b), text(c), text(d)]
}

impl KeyWorker {
    pub(super) fn mnemonic_job(&mut self, job: MnJob) -> KeyOutcome {
        KeyOutcome::Mnemonics(match job {
            MnJob::Preview { phrase, passphrase } => {
                MnOutcome::Preview(self.mn_preview(PendingImport { phrase, passphrase }))
            }
            MnJob::Discard => {
                self.pending_mnemonic = None;
                MnOutcome::Discarded
            }
            MnJob::CommitImport { password } => MnOutcome::Added(self.mn_commit(&password)),
            MnJob::Generate { password: bytes } => MnOutcome::Generated((|| {
                let password = password(&bytes).map_err(|_| VaultError::UnlockFailed)?;
                let vault = self.vault()?;
                let (id, phrase) = vault.generate_mnemonic(&password, now_unix())?;
                let address = vault.evm_address(EvmKeySource::Mnemonic(id, AccountIndex::ZERO))?;
                Ok((id, phrase, address))
            })()),
            MnJob::Challenge { id } => MnOutcome::Challenge(
                self.vault()
                    .and_then(|vault| vault.backup_challenge_for(id))
                    .map(|challenge| (id, challenge)),
            ),
            MnJob::Confirm {
                id,
                challenge,
                words,
            } => MnOutcome::Confirmed(
                self.vault()
                    .and_then(|vault| vault.confirm_backup_for(id, challenge, answers(&words)))
                    .map(|()| id),
            ),
            MnJob::Reveal {
                password: bytes,
                id,
                then_backup,
            } => MnOutcome::Revealed((|| {
                let password = password(&bytes).map_err(|_| VaultError::UnlockFailed)?;
                let phrase = self.vault()?.reveal_mnemonic_of(&password, id)?;
                Ok((id, phrase, then_backup))
            })()),
            MnJob::Remove {
                password: bytes,
                id,
            } => MnOutcome::Removed((|| {
                let password = password(&bytes).map_err(|_| VaultError::UnlockFailed)?;
                self.vault()?.remove_mnemonic(&password, id)?;
                Ok(id)
            })()),
            MnJob::Derive { id, index } => MnOutcome::Derived((|| {
                let account = AccountIndex::new(index).map_err(VaultError::Key)?;
                let address = self
                    .vault()?
                    .evm_address(EvmKeySource::Mnemonic(id, account))?;
                Ok((id, index, address))
            })()),
        })
    }

    fn mn_preview(&mut self, pending: PendingImport) -> Result<Address, KeyError> {
        let result = (|| {
            let phrase = ascii(&pending.phrase)?;
            let passphrase = pending
                .passphrase
                .as_deref()
                .map(|bytes| passphrase(bytes))
                .transpose()?;
            preview_evm_address(phrase, passphrase.as_ref(), AccountIndex::ZERO)
        })();
        self.pending_mnemonic = result.is_ok().then_some(pending);
        result
    }

    fn mn_commit(&mut self, bytes: &[u8]) -> Result<RecordId, VaultError> {
        let password = password(bytes).map_err(|_| VaultError::UnlockFailed)?;
        let pending = self
            .pending_mnemonic
            .take()
            .ok_or(VaultError::InvalidState)?;
        let result = (|| {
            let phrase = ascii(&pending.phrase).map_err(VaultError::Key)?;
            let passphrase = pending
                .passphrase
                .as_deref()
                .map(|bytes| passphrase(bytes))
                .transpose()
                .map_err(VaultError::Key)?;
            self.vault()?
                .add_mnemonic(&password, phrase, passphrase, now_unix())
        })();
        if result == Err(VaultError::UnlockFailed) {
            // A mistyped password: the words stay held for the next try.
            self.pending_mnemonic = Some(pending);
        }
        result
    }
}

/// The default label of the `n`-th recovery phrase (`니모닉 n`).
#[must_use]
pub fn default_label(n: usize) -> String {
    format!("{}{n}", meta::MNEMONIC_LABEL_PREFIX)
}

/// Reconciles meta `mnemonics` with the vault's `Bip39` records (like the imported keys): every
/// mnemonic gets an entry in vault order (labels kept by record id, new ones `니모닉 N`), an added
/// mnemonic always lists its account 0, address caches are recomputed, entries of removed
/// mnemonics are dropped and a selection naming one falls back to account 0. A wallet with one
/// mnemonic under its default label stores nothing. Returns whether anything changed.
///
/// # Errors
///
/// The vault is locked, or a derivation failed.
pub(super) fn reconcile_mnemonics(document: &mut Meta, vault: &Vault) -> Result<bool, VaultError> {
    let infos = vault.mnemonics()?;
    let mut entries: Vec<MnemonicEntry> = Vec::with_capacity(infos.len());
    for info in &infos {
        let id = *info.id.as_bytes();
        let existing = document
            .mnemonics
            .iter()
            .find(|entry| entry.record_id == id);
        let label = existing.map_or_else(
            || {
                let kept = document.mnemonics.iter().filter(|entry| {
                    infos
                        .iter()
                        .any(|other| *other.id.as_bytes() == entry.record_id)
                });
                meta::next_imported_label(
                    meta::MNEMONIC_LABEL_PREFIX,
                    kept.chain(&entries).map(|entry| entry.label.as_str()),
                )
            },
            |entry| entry.label.clone(),
        );
        let mut evm = Vec::new();
        if !info.primary {
            evm = existing.map(|entry| entry.evm.clone()).unwrap_or_default();
            if evm.first().is_none_or(|account| account.index != 0) {
                evm.insert(
                    0,
                    Account {
                        index: 0,
                        label: "계정 1".to_owned(),
                        address: String::new(),
                        hidden: false,
                    },
                );
            }
            let indices: Vec<AccountIndex> = evm
                .iter()
                .filter_map(|account| AccountIndex::new(account.index).ok())
                .collect();
            let addresses = vault.evm_addresses_of(info.id, &indices)?;
            for (account, address) in evm.iter_mut().zip(addresses) {
                account.address = address.to_lower_hex();
            }
        }
        entries.push(MnemonicEntry {
            record_id: id,
            label,
            evm,
        });
    }
    if let [only] = entries.as_slice()
        && only.label == default_label(1)
    {
        entries.clear();
    }
    let mut changed = entries != document.mnemonics;
    document.mnemonics = entries;
    if let EvmAccountPref::Mnemonic(id, index) = document.prefs.evm_account
        && !document.mnemonics.iter().any(|entry| {
            entry.record_id == id && entry.evm.iter().any(|account| account.index == index)
        })
    {
        document.prefs.evm_account = EvmAccountPref::Index(0);
        changed = true;
    }
    Ok(changed)
}
