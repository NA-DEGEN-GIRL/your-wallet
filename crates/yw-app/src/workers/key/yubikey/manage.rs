//! The key worker's jobs of the `YubiKey` list's card actions (spec/10 §15): "슬롯 구성 바꾸기"
//! (the recovery words are held like the wizard's — [`super::PendingEnrol`], wiped by
//! [`super::YkJob::Discard`], the flow's end and every lock) and "`YubiKey` 비우기". Each job
//! checks the vault change before the card is written, then changes the card, then the slot map.

use yw_core::error::VaultError;
use yw_core::secret::Zeroizing;
use yw_core::vault::{HardwareKey, RecordId};
use yw_core::yubikey::enrol::PreviewLine;
use yw_core::yubikey::manage::{ClearPlan, ClearReport, validate_reslot};
use yw_core::yubikey::plan::{PlanError, PlannedSlot};
use yw_core::yubikey::record::{HwKeyRecord, RecordedSlot};

use super::super::KeyWorker;
use super::EnteredWords;
use crate::events::YubiKeyJobError;
use crate::logging::{self, Field};
use crate::yubikey::CardJobError;

/// A card-action job.
pub enum ManageJob {
    /// Hold the entered words (`None`: keep the held ones) and derive the new `OpenPGP` slots
    /// of card `serial` for the confirmation (no card).
    ReslotPreview {
        /// Recovery words and optional passphrase (moved, wiped after parsing).
        mnemonic: Option<EnteredWords>,
        /// Card.
        serial: u32,
        /// The new `OpenPGP` slots.
        slots: Vec<PlannedSlot>,
    },
    /// Re-slot card `serial` with the held words and the admin PIN, then update its record.
    Reslot {
        /// Card.
        serial: u32,
        /// The new `OpenPGP` slots.
        slots: Vec<PlannedSlot>,
        /// `OpenPGP` admin PIN (wiped with the job).
        admin_pin: Zeroizing<Vec<u8>>,
        /// The user confirmed spending the admin PIN's last try (spec/10 §9.1).
        admin_last_try: bool,
    },
    /// Clear card `serial`, then update (or remove) its record.
    Clear {
        /// Card.
        serial: u32,
        /// What to clear.
        plan: ClearPlan,
        /// `OpenPGP` admin PIN (deleting our slots; empty otherwise).
        admin_pin: Zeroizing<Vec<u8>>,
        /// PIV PIN (deleting our slots; empty otherwise).
        piv_pin: Zeroizing<Vec<u8>>,
        /// The user confirmed spending the admin PIN's last try (spec/10 §9.1).
        admin_last_try: bool,
    },
}

impl core::fmt::Debug for ManageJob {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.name())
    }
}

impl ManageJob {
    /// Static name for logs.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::ReslotPreview { .. } => "YkReslotPreview",
            Self::Reslot { .. } => "YkReslot",
            Self::Clear { .. } => "YkClear",
        }
    }
}

/// The re-slot confirmation's facts (no card was contacted).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReslotPreview {
    /// The new `OpenPGP` slots with their paths, derived public keys and addresses.
    pub lines: Vec<PreviewLine>,
    /// The checks before the card (`manage::validate_reslot`, then the slot map consistency).
    pub plan: Result<(), PlanError>,
}

/// What a clear did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cleared {
    /// What was asked.
    pub asked: ClearPlan,
    /// The card's answer per applet.
    pub report: ClearReport,
    /// The record went (no wallet slot left on the card).
    pub removed: bool,
    /// The slot-map update after the card (the card is already changed when this fails).
    pub vault: Result<(), VaultError>,
}

/// What a card-action job produced.
#[derive(Debug)]
pub enum ManageOutcome {
    /// `ReslotPreview` of card `serial` finished.
    ReslotPreview(u32, Result<ReslotPreview, YubiKeyJobError>),
    /// `Reslot` of card `serial` finished: the new record.
    Reslotted(u32, Result<HwKeyRecord, YubiKeyJobError>),
    /// `Clear` of card `serial` finished.
    Cleared(u32, Result<Cleared, YubiKeyJobError>),
}

fn card_error(error: yw_core::yubikey::enrol::EnrolError) -> YubiKeyJobError {
    YubiKeyJobError::Card(CardJobError::Enrol(error))
}

impl KeyWorker {
    /// Runs one card-action job.
    pub(super) fn yubikey_manage(&mut self, job: ManageJob) -> ManageOutcome {
        match job {
            ManageJob::ReslotPreview {
                mnemonic,
                serial,
                slots,
            } => ManageOutcome::ReslotPreview(
                serial,
                self.yk_reslot_preview(mnemonic, serial, &slots),
            ),
            ManageJob::Reslot {
                serial,
                slots,
                admin_pin,
                admin_last_try,
            } => {
                let result = self.yk_reslot(serial, &slots, (&admin_pin, admin_last_try));
                logging::info(
                    "key",
                    "yubikey.reslot",
                    &[("ok", Field::Word(if result.is_ok() { "yes" } else { "no" }))],
                );
                ManageOutcome::Reslotted(serial, result)
            }
            ManageJob::Clear {
                serial,
                plan,
                admin_pin,
                piv_pin,
                admin_last_try,
            } => {
                let result = self.yk_clear(serial, plan, (&admin_pin, admin_last_try), &piv_pin);
                logging::info(
                    "key",
                    "yubikey.clear",
                    &[(
                        "ok",
                        Field::Word(match &result {
                            Ok(cleared) if cleared.report.done(cleared.asked) == cleared.asked => {
                                "yes"
                            }
                            Ok(_) => "partial",
                            Err(_) => "no",
                        }),
                    )],
                );
                ManageOutcome::Cleared(serial, result)
            }
        }
    }

    /// The enrolled cards with their record ids.
    fn yk_cards(&self) -> Result<Vec<HardwareKey>, YubiKeyJobError> {
        self.vault
            .as_ref()
            .ok_or(YubiKeyJobError::Vault(VaultError::InvalidState))?
            .hardware_keys()
            .map_err(YubiKeyJobError::Vault)
    }

    fn yk_card(
        &self,
        serial: u32,
    ) -> Result<(RecordId, HwKeyRecord, Vec<HwKeyRecord>), YubiKeyJobError> {
        let cards = self.yk_cards()?;
        let card = cards
            .iter()
            .find(|card| card.record.serial == serial)
            .ok_or(YubiKeyJobError::Vault(VaultError::RecordNotFound))?;
        let others = cards
            .iter()
            .filter(|other| other.record.serial != serial)
            .map(|other| other.record.clone())
            .collect();
        Ok((card.id, card.record.clone(), others))
    }
}

/// The record a card would have after the re-slot, from the held seed (the public keys are the
/// derived ones, which the card must read back).
fn reslot_record(record: &HwKeyRecord, lines: &[PreviewLine]) -> HwKeyRecord {
    let mut slots: Vec<RecordedSlot> = lines
        .iter()
        .map(|line| RecordedSlot {
            slot: line.planned.slot,
            role: line.planned.role,
            touch: line.planned.touch,
            pin: line.planned.pin,
            public: line.public,
            path_known: true,
        })
        .collect();
    slots.sort_by_key(|slot| slot.slot);
    slots.extend(
        record
            .slots
            .iter()
            .filter(|slot| matches!(slot.slot, yw_core::yubikey::plan::CardSlot::Piv(_)))
            .copied(),
    );
    HwKeyRecord {
        slots,
        ..record.clone()
    }
}

impl KeyWorker {
    fn yk_reslot_preview(
        &mut self,
        mnemonic: Option<EnteredWords>,
        serial: u32,
        slots: &[PlannedSlot],
    ) -> Result<ReslotPreview, YubiKeyJobError> {
        if let Some(words) = mnemonic {
            self.yk_hold_words(words)?;
        }
        let (id, record, _) = self.yk_card(serial)?;
        let seed = self
            .pending_enrol
            .as_ref()
            .ok_or(YubiKeyJobError::Vault(VaultError::InvalidState))?
            .seed
            .expose();
        let lines = yw_core::yubikey::enrol::preview_seed(seed, slots).map_err(card_error)?;
        let (fingerprint, _) = yw_core::yubikey::enrol::seed_identity(seed).map_err(card_error)?;
        let mut plan = validate_reslot(&record, fingerprint, slots);
        if plan.is_ok() {
            let next = reslot_record(&record, &lines);
            let consistent = self
                .vault
                .as_ref()
                .is_some_and(|vault| vault.check_replace_hardware_key(id, Some(&next)).is_ok());
            if !consistent {
                plan = Err(PlanError::DifferentMnemonic);
            }
        }
        Ok(ReslotPreview { lines, plan })
    }

    fn yk_reslot(
        &mut self,
        serial: u32,
        slots: &[PlannedSlot],
        admin_pin: (&[u8], bool),
    ) -> Result<HwKeyRecord, YubiKeyJobError> {
        let (id, record, others) = self.yk_card(serial)?;
        let pending = self
            .pending_enrol
            .as_ref()
            .ok_or(YubiKeyJobError::Vault(VaultError::InvalidState))?;
        let updated = crate::yubikey::reslot_card(
            self.cards.as_mut(),
            pending.seed.expose(),
            &record,
            slots,
            &others,
            admin_pin,
        )
        .map_err(YubiKeyJobError::Card)?;
        self.vault()
            .map_err(YubiKeyJobError::Vault)?
            .replace_hardware_key(id, Some(&updated))
            .map_err(YubiKeyJobError::Vault)?;
        Ok(updated)
    }

    fn yk_clear(
        &mut self,
        serial: u32,
        plan: ClearPlan,
        admin_pin: (&[u8], bool),
        piv_pin: &[u8],
    ) -> Result<Cleared, YubiKeyJobError> {
        let (id, record, _) = self.yk_card(serial)?;
        // The slot map must accept the result before the card is cleared (a wallet without
        // recovery words keeps its last key: `LastKey`).
        self.vault
            .as_ref()
            .ok_or(YubiKeyJobError::Vault(VaultError::InvalidState))?
            .check_replace_hardware_key(id, plan.remaining(&record).as_ref())
            .map_err(YubiKeyJobError::Vault)?;
        let report =
            crate::yubikey::clear_card(self.cards.as_mut(), &record, plan, admin_pin, piv_pin)
                .map_err(YubiKeyJobError::Card)?;
        let done = report.done(plan);
        let (removed, vault) = if done.any() {
            let remaining = done.remaining(&record);
            let result = self
                .vault()
                .and_then(|vault| vault.replace_hardware_key(id, remaining.as_ref()));
            (remaining.is_none() && result.is_ok(), result)
        } else {
            (false, Ok(()))
        };
        Ok(Cleared {
            asked: plan,
            report,
            removed,
            vault,
        })
    }
}
