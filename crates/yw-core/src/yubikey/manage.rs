//! Changing an enrolled card (spec/10 §15): "슬롯 구성 바꾸기" re-assigns the two `OpenPGP`
//! secp256k1 slots (SIG, AUT) to another chain combination from the same mnemonic, and "YubiKey
//! 비우기" removes the wallet's keys from the card (the `OpenPGP` slots, the PIV Solana slots, or
//! both) — by deleting only our slots where the applet allows it, or by the applet's factory
//! reset.
//!
//! | operation | `OpenPGP` | PIV |
//! |---|---|---|
//! | re-slot | VERIFY PW3 → per changed slot: attributes, import, UIF, read-back | untouched |
//! | delete our slots | VERIFY PW3 → per slot: attributes RSA 4096, then RSA 2048 (yubikit `delete_key`) → read-back empty | VERIFY PIN → management key → per slot `00 F6 FF <slot>` → GET METADATA `6A88` |
//! | reset | wrong VERIFY `81`/`83` until blocked → `00 E6 00 00` → `00 44 00 00` | wrong VERIFY until blocked → wrong `2C` until the PUK is blocked → `00 FB 00 00` |
//!
//! Nothing here touches FIDO2, OTP or OATH. Funds never move: a key removed from a card stays
//! derivable from the mnemonic, and re-assigning the same role later restores the same address.
//! Every derived private key lives only in a `Zeroizing` buffer for its import command.

use secp256k1::{All, Secp256k1};
use zeroize::Zeroizing;

use super::apdu::ApduMode;
use super::enrol::{EnrolError, identify, master_fingerprint};
use super::openpgp::{OpenPgp, Pw};
use super::piv::{DEFAULT_MANAGEMENT_KEY, ManagementCredential, MgmtCipher, Piv};
use super::plan::{CardSlot, KeyPath, PlanError, PlannedSlot, is_unknown_index, validate_plan};
use super::record::{HwKeyRecord, HwPublicKey, RecordedSlot, records_consistent};
use super::{CardError, CardTransport};
use crate::bip32::XPriv;

/// The full slot plan of card `record` after re-slotting: the new `OpenPGP` slots (in SIG,
/// AUT order) followed by the record's PIV slots, unchanged.
#[must_use]
pub fn reslot_plan(record: &HwKeyRecord, openpgp: &[PlannedSlot]) -> Vec<PlannedSlot> {
    let mut slots: Vec<PlannedSlot> = openpgp.to_vec();
    slots.sort_by_key(|planned| planned.slot);
    slots.extend(
        record
            .slots
            .iter()
            .filter(|slot| matches!(slot.slot, CardSlot::Piv(_)))
            .map(RecordedSlot::planned),
    );
    slots
}

/// The checks of a re-slot that need no card (spec/10 §15.1): the new `OpenPGP` slots are
/// `OpenPGP` slots, the card's full plan passes the per-card rules (§3.5 rules 1–5), and the
/// mnemonic is the card's (master fingerprint). A key that another card already holds is
/// allowed: it becomes a backup copy of that card's key (the same path is always the same key).
///
/// # Errors
///
/// [`PlanError::WrongApplet`] for a PIV slot in `openpgp`, [`PlanError::SlotCount`] for no
/// `OpenPGP` slot, [`PlanError::UnsupportedRole`] for a role index in the unknown-path band
/// (`900..=999`), [`PlanError::DifferentMnemonic`], the rules of [`validate_plan`].
pub fn validate_reslot(
    record: &HwKeyRecord,
    fingerprint: [u8; 4],
    openpgp: &[PlannedSlot],
) -> Result<(), PlanError> {
    if openpgp.is_empty() {
        return Err(PlanError::SlotCount);
    }
    if let Some(planned) = openpgp
        .iter()
        .find(|planned| !matches!(planned.slot, CardSlot::OpenPgp(_)))
    {
        return Err(PlanError::WrongApplet(planned.slot));
    }
    // The band of keys connected without recovery words is an account number, never a path
    // (spec/10 §7.6): a re-slot derives every new key from the words.
    if let Some(planned) = openpgp
        .iter()
        .find(|planned| is_unknown_index(planned.role.index()))
    {
        return Err(PlanError::UnsupportedRole(planned.slot));
    }
    validate_plan(&reslot_plan(record, openpgp))?;
    if record.fingerprint != fingerprint {
        return Err(PlanError::DifferentMnemonic);
    }
    Ok(())
}

fn secp_scalar(
    ctx: &Secp256k1<All>,
    seed: &[u8; 64],
    planned: &PlannedSlot,
) -> Result<Zeroizing<[u8; 32]>, EnrolError> {
    let KeyPath::Bip32(path) = planned.role.path()? else {
        return Err(EnrolError::Card(CardError::Internal));
    };
    let node = XPriv::from_seed(seed)?.derive_path(ctx, &path)?;
    Ok(Zeroizing::new(*node.key_bytes()))
}

/// "슬롯 구성 바꾸기" of card `record.serial` (spec/10 §15.1): imports the keys of the new
/// `OpenPGP` plan from `seed` (a slot keeping its key is only read back), compares every public
/// key read from the card with the derived one, and returns the card's new record (the PIV
/// slots unchanged). `others` are the other enrolled cards: the same path must keep the same
/// public key. Nothing is written before the serial, the mnemonic and the plan are checked.
///
/// # Errors
///
/// [`EnrolError::Plan`] (before any write), [`CardError::WrongCard`] (another card),
/// [`CardError::KeyMismatch`], PIN and status errors (earlier slots may have been written).
pub fn reslot_card(
    transport: &mut dyn CardTransport,
    mode: ApduMode,
    seed: &[u8; 64],
    record: &HwKeyRecord,
    openpgp: &[PlannedSlot],
    others: &[HwKeyRecord],
    admin_pin: &[u8],
) -> Result<HwKeyRecord, EnrolError> {
    let ctx = crate::entropy::secp_context(&mut crate::entropy::OsRandom)?;
    let fingerprint = master_fingerprint(&ctx, seed)?;
    validate_reslot(record, fingerprint, openpgp)?;
    let (serial, firmware) = identify(transport, mode, true, false)?;
    if serial != record.serial {
        return Err(EnrolError::Card(CardError::WrongCard));
    }
    let mut session = OpenPgp::open(transport, mode)?;
    session.verify(Pw::Admin, admin_pin)?;
    let mut recorded = Vec::with_capacity(openpgp.len());
    for planned in openpgp {
        let CardSlot::OpenPgp(key) = planned.slot else {
            return Err(EnrolError::Plan(PlanError::WrongApplet(planned.slot)));
        };
        let kept = record.slots.iter().find(|slot| {
            slot.slot == planned.slot
                && slot.role.key_identity() == planned.role.key_identity()
                && slot.touch == planned.touch
        });
        let unchanged = match kept {
            Some(slot) => session
                .public_key(key)
                .is_ok_and(|public| HwPublicKey::Secp256k1(public) == slot.public),
            None => false,
        };
        let public = if unchanged {
            session.public_key(key)?
        } else {
            let scalar = secp_scalar(&ctx, seed, planned)?;
            let public = session.import_secp256k1(&ctx, key, &scalar, planned.touch)?;
            drop(scalar);
            public
        };
        let expected = super::enrol::derive_public(&ctx, seed, planned.role)?;
        if expected != HwPublicKey::Secp256k1(public) {
            return Err(EnrolError::Card(CardError::KeyMismatch));
        }
        recorded.push(RecordedSlot {
            slot: planned.slot,
            role: planned.role,
            touch: planned.touch,
            pin: planned.pin,
            public: expected,
            path_known: true,
        });
    }
    recorded.sort_by_key(|slot| slot.slot);
    recorded.extend(
        record
            .slots
            .iter()
            .filter(|slot| matches!(slot.slot, CardSlot::Piv(_)))
            .copied(),
    );
    let updated = HwKeyRecord {
        serial,
        firmware,
        fingerprint,
        slots: recorded,
    };
    let mut all: Vec<HwKeyRecord> = others
        .iter()
        .filter(|other| other.serial != serial)
        .cloned()
        .collect();
    all.push(updated.clone());
    if !updated.is_valid() || !records_consistent(&all) {
        return Err(EnrolError::Card(CardError::KeyMismatch));
    }
    Ok(updated)
}

/// How one applet is cleared (spec/10 §15.2, §15.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClearMethod {
    /// Delete only the slots the record lists (`OpenPGP`: two attribute changes; PIV: DELETE
    /// KEY, 5.7+). Needs the `OpenPGP` admin PIN / the PIV PIN.
    OurSlots,
    /// The applet's factory reset: every key of that applet (also ones this wallet did not
    /// write) and its PINs (`OpenPGP` PW1/PW3; PIV PIN, PUK, management key) return to the
    /// factory values. Needs no PIN.
    Reset,
}

/// What "YubiKey 비우기" clears: per applet, nothing or a [`ClearMethod`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClearPlan {
    /// `OpenPGP` (SIG/AUT: EVM, Bitcoin, Zcash keys).
    pub openpgp: Option<ClearMethod>,
    /// PIV (Solana slots).
    pub piv: Option<ClearMethod>,
}

impl ClearPlan {
    /// Whether anything is cleared.
    #[must_use]
    pub const fn any(self) -> bool {
        self.openpgp.is_some() || self.piv.is_some()
    }

    /// Whether `slot` of the record is cleared by this plan.
    #[must_use]
    pub const fn clears(self, slot: CardSlot) -> bool {
        match slot {
            CardSlot::OpenPgp(_) => self.openpgp.is_some(),
            CardSlot::Piv(_) => self.piv.is_some(),
        }
    }

    /// The record left after clearing (`None`: no slot is left, the record goes).
    #[must_use]
    pub fn remaining(self, record: &HwKeyRecord) -> Option<HwKeyRecord> {
        let slots: Vec<RecordedSlot> = record
            .slots
            .iter()
            .filter(|slot| !self.clears(slot.slot))
            .copied()
            .collect();
        // Only keys connected without recovery words left: no mnemonic to name (spec/10 §8).
        let fingerprint = if slots.iter().any(|slot| slot.path_known) {
            record.fingerprint
        } else {
            [0; 4]
        };
        (!slots.is_empty()).then(|| HwKeyRecord {
            fingerprint,
            slots,
            ..record.clone()
        })
    }
}

/// Credentials of a clear (borrowed from the job's wiped buffers).
pub struct ClearAuth<'a> {
    /// `OpenPGP` admin PIN (only for [`ClearMethod::OurSlots`] on `OpenPGP`).
    pub admin_pin: &'a [u8],
    /// PIV PIN (only for [`ClearMethod::OurSlots`] on PIV): verified, and it opens a
    /// PIN-protected management key; otherwise the factory management key is used.
    pub piv_pin: &'a [u8],
    /// The management-key cipher.
    pub cipher: Option<&'a dyn MgmtCipher>,
    /// A fresh random challenge.
    pub challenge: [u8; 16],
}

impl core::fmt::Debug for ClearAuth<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ClearAuth([REDACTED])")
    }
}

/// What a clear did, per applet (`None`: not asked). `OpenPGP` runs first; when it fails PIV is
/// not attempted (`piv` stays `None` even if asked).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClearReport {
    /// `OpenPGP` result.
    pub openpgp: Option<Result<(), CardError>>,
    /// PIV result.
    pub piv: Option<Result<(), CardError>>,
}

impl ClearReport {
    /// The plan of what actually was cleared (successes only).
    #[must_use]
    pub fn done(self, asked: ClearPlan) -> ClearPlan {
        ClearPlan {
            openpgp: asked.openpgp.filter(|_| self.openpgp == Some(Ok(()))),
            piv: asked.piv.filter(|_| self.piv == Some(Ok(()))),
        }
    }
}

fn clear_openpgp(
    transport: &mut dyn CardTransport,
    mode: ApduMode,
    record: &HwKeyRecord,
    method: ClearMethod,
    admin_pin: &[u8],
) -> Result<(), CardError> {
    let mut session = OpenPgp::open(transport, mode)?;
    match method {
        ClearMethod::OurSlots => {
            session.verify(Pw::Admin, admin_pin)?;
            for slot in &record.slots {
                if let CardSlot::OpenPgp(key) = slot.slot {
                    session.delete_key(key)?;
                }
            }
            Ok(())
        }
        ClearMethod::Reset => {
            session.reset()?;
            // Read back: the applet answers again, with the factory counters and no key.
            let mut session = OpenPgp::open(transport, mode)?;
            for slot in &record.slots {
                if let CardSlot::OpenPgp(key) = slot.slot
                    && session
                        .public_key(key)
                        .is_ok_and(|public| HwPublicKey::Secp256k1(public) == slot.public)
                {
                    return Err(CardError::KeyMismatch);
                }
            }
            Ok(())
        }
    }
}

fn clear_piv(
    transport: &mut dyn CardTransport,
    mode: ApduMode,
    record: &HwKeyRecord,
    method: ClearMethod,
    auth: &ClearAuth<'_>,
) -> Result<(), CardError> {
    let mut session = Piv::open(transport, mode)?;
    match method {
        ClearMethod::OurSlots => {
            let state = session.management_state()?;
            if !state.protected && !state.default {
                return Err(CardError::ManagementKeyUnknown);
            }
            // The PIV PIN confirms the user's intent (and opens a protected management key).
            session.verify_pin(auth.piv_pin)?;
            let cipher = auth.cipher.ok_or(CardError::Internal)?;
            session.authenticate_management(
                ManagementCredential {
                    key: &DEFAULT_MANAGEMENT_KEY,
                    pin: auth.piv_pin,
                },
                cipher,
                &auth.challenge,
            )?;
            for slot in &record.slots {
                if let CardSlot::Piv(piv_slot) = slot.slot {
                    session.delete_key(piv_slot)?;
                }
            }
            Ok(())
        }
        ClearMethod::Reset => {
            session.reset()?;
            let mut session = Piv::open(transport, mode)?;
            for slot in &record.slots {
                if let CardSlot::Piv(piv_slot) = slot.slot {
                    match session.slot_metadata(piv_slot) {
                        Err(CardError::NotFound) => {}
                        Ok(_) => return Err(CardError::KeyMismatch),
                        Err(error) => return Err(error),
                    }
                }
            }
            Ok(())
        }
    }
}

/// "YubiKey 비우기" of card `record.serial` (spec/10 §15.2–§15.3). The serial is read first
/// (read-only) and must be the record's; then `OpenPGP`, then PIV (selecting PIV ends the PW3
/// session). Each applet's result is in the report; the vault is the caller's business
/// ([`ClearPlan::remaining`] of [`ClearReport::done`]).
///
/// # Errors
///
/// Before anything is written: [`CardError::WrongCard`], [`EnrolError::SerialMismatch`], card
/// errors of the identification.
pub fn clear_card(
    transport: &mut dyn CardTransport,
    mode: ApduMode,
    record: &HwKeyRecord,
    plan: ClearPlan,
    auth: &ClearAuth<'_>,
) -> Result<ClearReport, EnrolError> {
    if !plan.any() {
        return Ok(ClearReport::default());
    }
    let (serial, _) = identify(transport, mode, plan.openpgp.is_some(), plan.piv.is_some())?;
    if serial != record.serial {
        return Err(EnrolError::Card(CardError::WrongCard));
    }
    let mut report = ClearReport::default();
    if let Some(method) = plan.openpgp {
        let result = clear_openpgp(transport, mode, record, method, auth.admin_pin);
        let failed = result.is_err();
        report.openpgp = Some(result);
        if failed {
            return Ok(report);
        }
    }
    if let Some(method) = plan.piv {
        report.piv = Some(clear_piv(transport, mode, record, method, auth));
    }
    Ok(report)
}
