//! The key worker's recovery-phrase jobs (several mnemonics in one wallet, spec/02 §8.6,
//! spec/04 §2.24): "복구 단어 추가 가져오기" (the entered words and passphrase are held between the
//! address preview and the commit, never on disk, wiped by [`MnJob::Discard`] and every lock),
//! "새 복구 단어 만들기 (추가)" with its backup quiz, reveal, removal, the accounts of an added
//! mnemonic, and the meta `mnemonics` reconciliation at meta load.

use yw_core::bip32::path::AccountIndex;
use yw_core::bip32::preview_evm_address;
use yw_core::bip39::Mnemonic;
use yw_core::error::{KeyError, VaultError};
use yw_core::evm::address::Address;
use yw_core::password::Bip39Passphrase;
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
    /// `Preview`: account 0 of the entered words and the enrolled `YubiKey`s made from them.
    Preview(Result<(Address, Vec<u32>), KeyError>),
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
    /// `Remove` refused: a Solana, Bitcoin or Zcash transaction of the mnemonic's accounts may
    /// still confirm (nothing was asked of the vault).
    Busy(RecordId),
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
    /// `지우기` of an added mnemonic (spec/02 §8.6): refused while a Solana, Bitcoin or Zcash
    /// journal record of its accounts may still confirm (`Busy`, the imported-key rule); then
    /// the password check and the vault removal; then the journal records of its accounts —
    /// all final by now — are dropped, so the journal holds no record of a removed mnemonic
    /// (an earlier build would read such a record as damaged).
    pub(super) fn remove_mnemonic(&mut self, bytes: &[u8], id: RecordId) -> Vec<KeyOutcome> {
        let alt = self.is_alt();
        if let Some(vault) = self.vault.as_ref()
            && self.journal.mnemonic_busy(vault, id, now_unix())
        {
            return vec![KeyOutcome::Mnemonics(MnOutcome::Busy(id))];
        }
        let result = (|| {
            let password = password(bytes).map_err(|_| VaultError::UnlockFailed)?;
            self.vault()?.remove_mnemonic(&password, id)?;
            Ok(id)
        })();
        let removed = result.is_ok();
        let mut out = vec![KeyOutcome::Mnemonics(MnOutcome::Removed(result))];
        if removed && let Some(vault) = self.vault.as_mut() {
            out.extend(self.journal.purge_mnemonic(vault, id, alt));
        }
        out
    }

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
            } => {
                // `KeyWorker::handle` runs `remove_mnemonic` (busy check, journal clean-up);
                // this keeps the same rules for a direct call.
                let outcomes = self.remove_mnemonic(&bytes, id);
                return outcomes
                    .into_iter()
                    .find(|outcome| matches!(outcome, KeyOutcome::Mnemonics(_)))
                    .unwrap_or(KeyOutcome::Mnemonics(MnOutcome::Removed(Err(
                        VaultError::InvalidState,
                    ))));
            }
            MnJob::Derive { id, index } => MnOutcome::Derived((|| {
                let account = AccountIndex::new(index).map_err(VaultError::Key)?;
                let address = self
                    .vault()?
                    .evm_address(EvmKeySource::Mnemonic(id, account))?;
                Ok((id, index, address))
            })()),
        })
    }

    fn mn_preview(&mut self, pending: PendingImport) -> Result<(Address, Vec<u32>), KeyError> {
        let result = (|| {
            let phrase = ascii(&pending.phrase)?;
            let passphrase = pending
                .passphrase
                .as_deref()
                .map(|bytes| passphrase(bytes))
                .transpose()?;
            let address = preview_evm_address(phrase, passphrase.as_ref(), AccountIndex::ZERO)?;
            let empty = Bip39Passphrase::empty();
            let seed = Mnemonic::parse(phrase)?.to_seed(passphrase.as_ref().unwrap_or(&empty))?;
            Ok((address, self.cards_of_seed(seed.expose())))
        })();
        self.pending_mnemonic = result.is_ok().then_some(pending);
        result
    }

    /// The enrolled `YubiKey`s whose keys were made from `seed` (the master fingerprint of a
    /// record with a known path; spec/10 §7.1): adding these words would put the card's words
    /// on this PC (T-YK-SAME).
    fn cards_of_seed(&self, seed: &[u8; 64]) -> Vec<u32> {
        let Some(vault) = self.vault.as_ref() else {
            return Vec::new();
        };
        let (Ok(records), Ok((fingerprint, _))) = (
            Self::hardware_records(vault),
            yw_core::yubikey::enrol::seed_identity(seed),
        ) else {
            return Vec::new();
        };
        records
            .iter()
            .filter(|record| record.has_known_path() && record.fingerprint == fingerprint)
            .map(|record| record.serial)
            .collect()
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

/// Reconciles the Solana, Bitcoin and Zcash accounts of added mnemonics with the vault's
/// `Bip39` records (spec/02 §8.6): accounts of a removed mnemonic and a selection naming one are
/// dropped (a Zcash account falls back to the default key, made again by the tab); an added
/// mnemonic gets Solana account 0 when the wallet uses Solana (`sol_accounts` not empty) and
/// Bitcoin native segwit account 0 on the meta `btc` network when Bitcoin is on (discovery runs
/// when it is selected); Solana address caches are recomputed. Returns whether anything changed.
///
/// # Errors
///
/// The vault is locked, or a derivation failed.
pub(super) fn reconcile_mnemonic_chains(
    document: &mut Meta,
    vault: &Vault,
) -> Result<bool, VaultError> {
    let added: Vec<RecordId> = vault
        .mnemonics()?
        .iter()
        .filter(|info| !info.primary)
        .map(|info| info.id)
        .collect();
    let mut changed = reconcile_sol(document, vault, &added)?;
    changed |= reconcile_btc(document, vault, &added)?;
    // Zcash: an account on a removed mnemonic's key is made again from the default key.
    for network in yw_core::zec::ZecNetwork::ALL {
        let orphan = document
            .zcash
            .get(network)
            .and_then(|account| account.source.mnemonic())
            .is_some_and(|id| !added.contains(&id));
        if orphan {
            document.zcash.clear(network);
            changed = true;
        }
    }
    Ok(changed)
}

/// The Solana part of [`reconcile_mnemonic_chains`].
fn reconcile_sol(
    document: &mut Meta,
    vault: &Vault,
    added: &[RecordId],
) -> Result<bool, VaultError> {
    use yw_core::slip10::SolKeySource;
    let mut changed = false;
    let known: Vec<[u8; 16]> = document
        .mnemonic_accounts
        .sol
        .iter()
        .map(|(id, _)| *id)
        .collect();
    for id in known {
        if !added.iter().any(|other| *other.as_bytes() == id) {
            document.mnemonic_accounts.remove_mnemonic(id);
            changed = true;
        }
    }
    if !document.sol_accounts.is_empty() {
        for id in added {
            if document
                .mnemonic_accounts
                .sol_of(*id.as_bytes())
                .next()
                .is_none()
            {
                document.mnemonic_accounts.upsert_sol(
                    *id.as_bytes(),
                    Account {
                        index: 0,
                        label: "Solana 1".to_owned(),
                        address: String::new(),
                        hidden: false,
                    },
                );
                changed = true;
            }
        }
    }
    let sources: Vec<SolKeySource> = document
        .mnemonic_accounts
        .sol
        .iter()
        .filter_map(|(id, account)| {
            Some(SolKeySource::Mnemonic(
                RecordId::from_bytes(*id),
                AccountIndex::new(account.index).ok()?,
            ))
        })
        .collect();
    for chunk in sources.chunks(100) {
        let keys = vault.sol_public_keys(chunk)?;
        for (source, key) in chunk.iter().zip(keys) {
            let SolKeySource::Mnemonic(id, index) = source else {
                continue;
            };
            let text = yw_core::sol::SolAddress::from_bytes(key).to_base58();
            if let Some((_, account)) = document
                .mnemonic_accounts
                .sol
                .iter_mut()
                .find(|(of, account)| of == id.as_bytes() && account.index == index.get())
                && account.address != text
            {
                account.address = text;
                changed = true;
            }
        }
    }
    Ok(changed)
}

/// The Bitcoin part of [`reconcile_mnemonic_chains`].
fn reconcile_btc(
    document: &mut Meta,
    vault: &Vault,
    added: &[RecordId],
) -> Result<bool, VaultError> {
    use yw_core::btc::{BtcAccountKey, BtcMeta, ScriptType};
    let mut changed = false;
    let stale: Vec<RecordId> = document
        .btc_accounts
        .accounts
        .iter()
        .filter_map(|meta| meta.account().mnemonic())
        .filter(|id| !added.contains(id))
        .collect();
    for id in stale {
        changed |= document.btc_accounts.remove_mnemonic(id) > 0;
    }
    if let Some(network) = document.btc.as_deref().map(BtcMeta::network) {
        for id in added {
            let has_any = document
                .btc_accounts
                .of_network(network)
                .any(|meta| meta.account().mnemonic() == Some(*id));
            if has_any {
                continue;
            }
            let xpub = vault.btc_account_xpub_of(Some(*id), network.coin_type())?;
            let Ok(key) = BtcAccountKey::hd(ScriptType::P2wpkh, 0, xpub) else {
                continue;
            };
            if document
                .btc_accounts
                .upsert(BtcMeta::with_key(network, key.with_mnemonic(Some(*id))))
                .is_ok()
            {
                changed = true;
            }
        }
    }
    Ok(changed)
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
