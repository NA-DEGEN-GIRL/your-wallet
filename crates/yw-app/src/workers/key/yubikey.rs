//! The key worker's `YubiKey` wizard jobs (spec/10 §7, §9.3): the mnemonic of an enrolment held
//! between the confirmation screen and the card (never on disk, wiped by [`YkJob::Discard`], the
//! wizard's end and every lock), the 24 words of a new `YubiKey` wallet with their in-memory
//! backup confirmation, the card writes of the defaults change (PIN, PUK, management key) and
//! the read-only "다시 확인", and the removal of a `YubiKey` record.

use yw_core::bip39::{BACKUP_WORDS, Mnemonic};
use yw_core::error::{KeyError, VaultError};
use yw_core::evm::address::Address;
use yw_core::password::Bip39Passphrase;
use yw_core::secret::{SecretBytes, SecretString, Zeroizing};
use yw_core::vault::{FileKind, RecordId, Vault, VaultStatus};
use yw_core::yubikey::CardError;
use yw_core::yubikey::enrol::PreviewLine;
use yw_core::yubikey::plan::{PlanError, PlannedSlot};

use super::{KeyWorker, ascii, new_slot, now_unix, passphrase, password, reconcile_hardware};
use crate::events::{KeyOutcome, YubiKeyJobError};
use crate::logging::{self, Field};
use crate::meta::{EvmAccountPref, Meta, Tab};
use crate::yubikey::{CardJobError, PinTarget};

/// Recovery words and an optional BIP39 passphrase as entered (W05, W06).
pub type EnteredWords = (Zeroizing<Vec<u8>>, Option<Zeroizing<Vec<u8>>>);

/// A wizard job of the key worker.
pub enum YkJob {
    /// Parse the entered recovery words (+ passphrase) and hold their seed — `None` keeps the
    /// seed already held — then derive the planned keys for the confirmation screen (no card).
    Preview {
        /// Recovery words and optional BIP39 passphrase (moved, wiped after parsing).
        mnemonic: Option<EnteredWords>,
        /// The plan to preview.
        slots: Vec<PlannedSlot>,
    },
    /// New `YubiKey` wallet (spec/10 §7.1-1): hold the vault password, generate 24 words and
    /// hold them; the words come back once for W08.
    Generate {
        /// Vault password (W01).
        password: Zeroizing<Vec<u8>>,
    },
    /// Four word positions of the held new mnemonic (W10).
    Challenge,
    /// The four answers of W10 (constant-time check against the held mnemonic).
    ConfirmWords {
        /// Answers in position order.
        words: [Zeroizing<Vec<u8>>; BACKUP_WORDS],
    },
    /// Enrol (or adopt) the inserted card with the held seed. For a new `YubiKey` wallet this
    /// also creates the vault (`Vault::create_with_hardware`) with the held password.
    Enrol {
        /// The plan.
        slots: Vec<PlannedSlot>,
        /// `OpenPGP` admin PIN (empty without `OpenPGP` slots or when adopting).
        admin_pin: Zeroizing<Vec<u8>>,
        /// PIV management key (empty without PIV slots or when adopting).
        management_key: Zeroizing<Vec<u8>>,
        /// "가져오기 없이 등록": read the card's keys, write nothing (spec/10 §7.5).
        adopt: bool,
    },
    /// "다시 확인": read every recorded slot of card `serial` again (read-only).
    Check {
        /// Card.
        serial: u32,
    },
    /// Change a PIN or PUK of card `serial`.
    ChangePin {
        /// Card.
        serial: u32,
        /// Which secret.
        target: PinTarget,
        /// Current value.
        old: Zeroizing<Vec<u8>>,
        /// New value.
        new: Zeroizing<Vec<u8>>,
    },
    /// Generate a new random AES-192 management key for card `serial` and hold it; it comes
    /// back once for W13 and is set only by [`YkJob::SetManagementKey`].
    NewManagementKey {
        /// Card.
        serial: u32,
    },
    /// Authenticate with the current key and set the held new key.
    SetManagementKey {
        /// The current management key.
        old: Zeroizing<Vec<u8>>,
    },
    /// Wipe the held new management key (W13 closed without the acknowledgement).
    DiscardManagementKey,
    /// Remove a `YubiKey` record after the password (spec/10 §7.5).
    Remove {
        /// Password (W03).
        password: Zeroizing<Vec<u8>>,
        /// The record.
        id: RecordId,
    },
    /// The wizard ended: wipe the held mnemonic, seed and (new wallet) password.
    Discard,
}

impl core::fmt::Debug for YkJob {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.name())
    }
}

impl YkJob {
    /// Static name for logs.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Preview { .. } => "YkPreview",
            Self::Generate { .. } => "YkGenerate",
            Self::Challenge => "YkChallenge",
            Self::ConfirmWords { .. } => "YkConfirmWords",
            Self::Enrol { .. } => "YkEnrol",
            Self::Check { .. } => "YkCheck",
            Self::ChangePin { .. } => "YkChangePin",
            Self::NewManagementKey { .. } => "YkNewManagementKey",
            Self::SetManagementKey { .. } => "YkSetManagementKey",
            Self::DiscardManagementKey => "YkDiscardManagementKey",
            Self::Remove { .. } => "YkRemove",
            Self::Discard => "YkDiscard",
        }
    }
}

/// The confirmation screen's facts (spec/10 §7.2): no card was contacted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YkPreview {
    /// Every planned slot with its path, derived public key and addresses.
    pub lines: Vec<PreviewLine>,
    /// The entered words (+ passphrase) are the ones this vault stores (spec/10 §7.1-2).
    pub same_as_vault: bool,
    /// The plan checks that need no card (`plan::validate_before_card`).
    pub plan: Result<(), PlanError>,
}

/// What a wizard job produced.
#[derive(Debug)]
pub enum YkOutcome {
    /// `Preview` finished.
    Preview(Result<YkPreview, YubiKeyJobError>),
    /// `Generate` finished: the new words (W08) and their EVM account-0 address.
    Words(Result<(SecretString, Address), YubiKeyJobError>),
    /// `Challenge` finished.
    Challenge(Result<[u8; BACKUP_WORDS], YubiKeyJobError>),
    /// `ConfirmWords` finished (`Ok(false)` = wrong answers: ask again with new positions).
    WordsConfirmed(Result<bool, YubiKeyJobError>),
    /// `Check` finished: one result per recorded slot.
    Checked(u32, Result<Vec<Result<(), CardError>>, CardJobError>),
    /// `ChangePin` finished.
    PinChanged(u32, PinTarget, Result<(), CardJobError>),
    /// `NewManagementKey` finished: the key to show once (48 hex digits).
    ManagementKey(Result<SecretString, CardJobError>),
    /// `SetManagementKey` finished.
    ManagementKeySet(u32, Result<(), CardJobError>),
    /// `Remove` finished.
    Removed(Result<RecordId, VaultError>),
    /// `Discard` / `DiscardManagementKey` finished.
    Discarded,
}

/// The recovery words of an enrolment held between the confirmation and the card.
pub(super) struct PendingEnrol {
    seed: SecretBytes<64>,
    /// A new `YubiKey` wallet's words (kept for the backup confirmation).
    fresh: Option<Mnemonic>,
    challenge: Option<[u8; BACKUP_WORDS]>,
    /// The new words were confirmed (W10).
    confirmed: bool,
}

/// A new management key between W13 and the card.
pub(super) struct PendingKey {
    serial: u32,
    key: Zeroizing<[u8; 24]>,
}

fn job_key(error: KeyError) -> YubiKeyJobError {
    YubiKeyJobError::Key(error)
}

/// Hex of a key, in a redacting string.
fn hex_secret(key: &[u8]) -> Result<SecretString, KeyError> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = SecretString::with_capacity(key.len().saturating_mul(2));
    for byte in key {
        for nibble in [byte >> 4, byte & 0x0F] {
            let digit = DIGITS
                .get(usize::from(nibble))
                .copied()
                .ok_or(KeyError::Internal)?;
            let mut buffer = [0_u8; 4];
            text.push_str(char::from(digit).encode_utf8(&mut buffer))
                .map_err(|_| KeyError::Internal)?;
        }
    }
    Ok(text)
}

/// The default meta of a new `YubiKey` wallet: no derived account, the slot map's accounts
/// (`hw_accounts`, Bitcoin `key.yubikey` accounts), the first of each selected, the tab of the
/// first key.
fn write_yubikey_meta(vault: &mut Vault) -> Result<(), VaultError> {
    let mut document = Meta::key_only();
    reconcile_hardware(&mut document, vault)?;
    if let Some(first) = document.hw_accounts.evm.first() {
        document.prefs.evm_account = EvmAccountPref::Hardware(first.index);
    }
    document.hw_accounts.sol_selected = document
        .hw_accounts
        .sol
        .first()
        .map(|account| account.index);
    document.btc_accounts.selected = document
        .btc_accounts
        .accounts
        .first()
        .map(yw_core::btc::BtcMeta::id);
    document.prefs.tab = if !document.hw_accounts.evm.is_empty() {
        Tab::Evm
    } else if document.btc_accounts.accounts.is_empty() {
        Tab::Sol
    } else {
        Tab::Btc
    };
    if let Err(error) = vault.save_sidecar(FileKind::Meta, &document.to_json()) {
        logging::warn(
            "key",
            "meta.write_failed",
            &[("code", Field::Code(crate::errors::vault_code(error)))],
        );
    }
    Ok(())
}

impl KeyWorker {
    /// Runs one wizard job.
    pub(super) fn yubikey_job(&mut self, job: YkJob) -> KeyOutcome {
        match job {
            YkJob::Preview { mnemonic, slots } => {
                KeyOutcome::YubiKey(YkOutcome::Preview(self.yk_preview(mnemonic, &slots)))
            }
            YkJob::Generate { password } => {
                KeyOutcome::YubiKey(YkOutcome::Words(self.yk_generate(password)))
            }
            YkJob::Challenge => KeyOutcome::YubiKey(YkOutcome::Challenge(self.yk_challenge())),
            YkJob::ConfirmWords { words } => {
                KeyOutcome::YubiKey(YkOutcome::WordsConfirmed(self.yk_confirm_words(&words)))
            }
            YkJob::Enrol {
                slots,
                admin_pin,
                management_key,
                adopt,
            } => KeyOutcome::YubiKeyEnrolled(self.yk_enrol(
                &slots,
                &admin_pin,
                &management_key,
                adopt,
            )),
            YkJob::Check { serial } => {
                let result = self
                    .vault
                    .as_ref()
                    .and_then(|vault| Self::hardware_records(vault).ok())
                    .and_then(|records| records.into_iter().find(|record| record.serial == serial))
                    .map_or(Err(CardJobError::Card(CardError::NotFound)), |record| {
                        crate::yubikey::check_record(self.cards.as_mut(), &record)
                    });
                KeyOutcome::YubiKey(YkOutcome::Checked(serial, result))
            }
            YkJob::ChangePin {
                serial,
                target,
                old,
                new,
            } => {
                let result = crate::yubikey::change_card_pin(
                    self.cards.as_mut(),
                    serial,
                    target,
                    &old,
                    &new,
                );
                logging::info(
                    "key",
                    "yubikey.pin_change",
                    &[("ok", Field::Word(if result.is_ok() { "yes" } else { "no" }))],
                );
                KeyOutcome::YubiKey(YkOutcome::PinChanged(serial, target, result))
            }
            YkJob::NewManagementKey { serial } => {
                KeyOutcome::YubiKey(YkOutcome::ManagementKey(self.yk_new_management_key(serial)))
            }
            YkJob::SetManagementKey { old } => {
                let Some(pending) = self.pending_card_key.take() else {
                    return KeyOutcome::YubiKey(YkOutcome::ManagementKeySet(
                        0,
                        Err(CardJobError::Card(CardError::Internal)),
                    ));
                };
                let result = crate::yubikey::change_management_key(
                    self.cards.as_mut(),
                    pending.serial,
                    &old,
                    &pending.key,
                );
                logging::info(
                    "key",
                    "yubikey.management_key_change",
                    &[("ok", Field::Word(if result.is_ok() { "yes" } else { "no" }))],
                );
                KeyOutcome::YubiKey(YkOutcome::ManagementKeySet(pending.serial, result))
            }
            YkJob::DiscardManagementKey => {
                self.pending_card_key = None;
                KeyOutcome::YubiKey(YkOutcome::Discarded)
            }
            YkJob::Remove {
                password: bytes,
                id,
            } => KeyOutcome::YubiKey(YkOutcome::Removed((|| {
                let password = password(&bytes).map_err(|_| VaultError::UnlockFailed)?;
                self.vault()?.remove_hardware_key(&password, id)?;
                logging::info("key", "yubikey.removed", &[]);
                Ok(id)
            })())),
            YkJob::Discard => {
                self.yk_wipe();
                KeyOutcome::YubiKey(YkOutcome::Discarded)
            }
        }
    }

    /// Wipes everything a wizard held (also on lock).
    pub(super) fn yk_wipe(&mut self) {
        if self
            .pending_enrol
            .as_ref()
            .is_some_and(|pending| pending.fresh.is_some())
        {
            self.pending_password = None;
        }
        self.pending_enrol = None;
        self.pending_card_key = None;
    }

    fn yk_preview(
        &mut self,
        mnemonic: Option<EnteredWords>,
        slots: &[PlannedSlot],
    ) -> Result<YkPreview, YubiKeyJobError> {
        if let Some((phrase, extra)) = mnemonic {
            let parsed = Mnemonic::parse(ascii(&phrase).map_err(job_key)?).map_err(job_key)?;
            let passphrase = match extra.as_deref() {
                Some(bytes) => passphrase(bytes).map_err(job_key)?,
                None => Bip39Passphrase::empty(),
            };
            let seed = parsed.to_seed(&passphrase).map_err(job_key)?;
            self.pending_enrol = Some(PendingEnrol {
                seed,
                fresh: None,
                challenge: None,
                confirmed: false,
            });
        }
        let pending = self
            .pending_enrol
            .as_ref()
            .ok_or(YubiKeyJobError::Vault(VaultError::InvalidState))?;
        let seed = pending.seed.expose();
        let lines = yw_core::yubikey::enrol::preview_seed(seed, slots)
            .map_err(|error| YubiKeyJobError::Card(CardJobError::Enrol(error)))?;
        let (fingerprint, evm0) = yw_core::yubikey::enrol::seed_identity(seed)
            .map_err(|error| YubiKeyJobError::Card(CardJobError::Enrol(error)))?;
        let (records, same_as_vault) = match self.vault.as_ref() {
            Some(vault) if vault.status() != VaultStatus::NoVault => {
                let records = Self::hardware_records(vault).map_err(YubiKeyJobError::Vault)?;
                let same = vault.has_mnemonic().unwrap_or(false)
                    && vault
                        .evm_address(yw_core::vault::EvmKeySource::Derived(
                            yw_core::bip32::path::AccountIndex::ZERO,
                        ))
                        .is_ok_and(|address| address == evm0);
                (records, same)
            }
            _ => (Vec::new(), false),
        };
        Ok(YkPreview {
            lines,
            same_as_vault,
            plan: yw_core::yubikey::plan::validate_before_card(&records, fingerprint, slots),
        })
    }

    fn yk_generate(
        &mut self,
        password: Zeroizing<Vec<u8>>,
    ) -> Result<(SecretString, Address), YubiKeyJobError> {
        let vault = self
            .vault
            .as_ref()
            .ok_or(YubiKeyJobError::Vault(VaultError::InvalidState))?;
        if vault.status() != VaultStatus::NoVault {
            return Err(YubiKeyJobError::Vault(VaultError::InvalidState));
        }
        let mnemonic = Mnemonic::generate().map_err(job_key)?;
        let seed = mnemonic
            .to_seed(&Bip39Passphrase::empty())
            .map_err(job_key)?;
        let (_, evm0) = yw_core::yubikey::enrol::seed_identity(seed.expose())
            .map_err(|error| YubiKeyJobError::Card(CardJobError::Enrol(error)))?;
        let phrase = mnemonic.phrase().map_err(job_key)?;
        self.pending_password = Some(password);
        self.pending_enrol = Some(PendingEnrol {
            seed,
            fresh: Some(mnemonic),
            challenge: None,
            confirmed: false,
        });
        logging::info("key", "yubikey.wallet_words", &[]);
        Ok((phrase, evm0))
    }

    fn yk_challenge(&mut self) -> Result<[u8; BACKUP_WORDS], YubiKeyJobError> {
        let pending = self
            .pending_enrol
            .as_mut()
            .ok_or(YubiKeyJobError::Vault(VaultError::InvalidState))?;
        let mnemonic = pending
            .fresh
            .as_ref()
            .ok_or(YubiKeyJobError::Vault(VaultError::InvalidState))?;
        let positions = mnemonic.backup_positions().map_err(job_key)?;
        pending.challenge = Some(positions);
        Ok(positions)
    }

    fn yk_confirm_words(
        &mut self,
        words: &[Zeroizing<Vec<u8>>; BACKUP_WORDS],
    ) -> Result<bool, YubiKeyJobError> {
        let pending = self
            .pending_enrol
            .as_mut()
            .ok_or(YubiKeyJobError::Vault(VaultError::InvalidState))?;
        let positions = pending
            .challenge
            .take()
            .ok_or(YubiKeyJobError::Vault(VaultError::ChallengeStale))?;
        let mnemonic = pending
            .fresh
            .as_ref()
            .ok_or(YubiKeyJobError::Vault(VaultError::InvalidState))?;
        let text = |index: usize| {
            words
                .get(index)
                .and_then(|word| core::str::from_utf8(word).ok())
                .unwrap_or("")
        };
        let matched = mnemonic
            .backup_words_match(positions, [text(0), text(1), text(2), text(3)])
            .map_err(job_key)?;
        pending.confirmed |= matched;
        logging::info(
            "key",
            "yubikey.wallet_backup",
            &[("ok", Field::Word(if matched { "yes" } else { "no" }))],
        );
        Ok(matched)
    }

    fn yk_enrol(
        &mut self,
        slots: &[PlannedSlot],
        admin_pin: &[u8],
        management_key: &[u8],
        adopt: bool,
    ) -> Result<(RecordId, yw_core::yubikey::enrol::Enrolled), YubiKeyJobError> {
        let pending = self
            .pending_enrol
            .as_ref()
            .ok_or(YubiKeyJobError::Vault(VaultError::InvalidState))?;
        let fresh = pending.fresh.is_some();
        if fresh && !pending.confirmed {
            return Err(YubiKeyJobError::Vault(VaultError::BackupNotConfirmed));
        }
        let vault = self
            .vault
            .as_ref()
            .ok_or(YubiKeyJobError::Vault(VaultError::InvalidState))?;
        let records = if fresh {
            Vec::new()
        } else {
            Self::hardware_records(vault).map_err(YubiKeyJobError::Vault)?
        };
        let seed = pending.seed.expose();
        let enrolled = if adopt {
            crate::yubikey::adopt_first_card(self.cards.as_mut(), seed, slots, &records)
        } else {
            crate::yubikey::enrol_first_card(
                self.cards.as_mut(),
                seed,
                slots,
                &records,
                &crate::yubikey::EnrolSecrets {
                    admin_pin,
                    management_key,
                },
            )
        }
        .map_err(YubiKeyJobError::Card)?;
        let id = if fresh {
            let held = self
                .pending_password
                .as_ref()
                .ok_or(YubiKeyJobError::Vault(VaultError::InvalidState))?;
            let password = password(held).map_err(YubiKeyJobError::Vault)?;
            let slot = new_slot().map_err(YubiKeyJobError::Vault)?;
            let vault = self.vault().map_err(YubiKeyJobError::Vault)?;
            let id = vault
                .create_with_hardware(&password, enrolled.record.clone(), slot, now_unix())
                .map_err(YubiKeyJobError::Vault)?;
            write_yubikey_meta(vault).map_err(YubiKeyJobError::Vault)?;
            // The wallet exists: the password is not needed again. The words stay held for a
            // backup YubiKey until the wizard ends (`Discard`) or the wallet locks.
            self.pending_password = None;
            if let Some(pending) = self.pending_enrol.as_mut() {
                pending.fresh = None;
            }
            logging::info("key", "yubikey.wallet_created", &[]);
            id
        } else {
            self.vault()
                .map_err(YubiKeyJobError::Vault)?
                .add_hardware_key(enrolled.record.clone(), now_unix())
                .map_err(YubiKeyJobError::Vault)?
        };
        logging::info(
            "key",
            if adopt {
                "yubikey.adopted"
            } else {
                "yubikey.enrolled"
            },
            &[(
                "slots",
                Field::Num(u64::try_from(enrolled.record.slots.len()).unwrap_or(0)),
            )],
        );
        Ok((id, enrolled))
    }

    fn yk_new_management_key(&mut self, serial: u32) -> Result<SecretString, CardJobError> {
        let mut key = Zeroizing::new([0_u8; 24]);
        yw_core::entropy::fill_random(key.as_mut())
            .map_err(|_| CardJobError::Card(CardError::Internal))?;
        let text = hex_secret(key.as_ref()).map_err(|_| CardJobError::Card(CardError::Internal))?;
        self.pending_card_key = Some(PendingKey { serial, key });
        Ok(text)
    }
}
