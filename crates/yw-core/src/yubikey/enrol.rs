//! Enrolment (spec/10 §7): derive the planned keys from the mnemonic seed, import them, read
//! the public keys back and compare them with the derived ones, and return the tag-5 record.
//!
//! Order on the card: read the serial(s) first and validate the plan against the enrolled
//! records (nothing is written before that), read every planned slot (a key the plan does not
//! derive is never overwritten unless the user saw it and agreed, [`occupied_slots`]; a fixed
//! touch policy other than the planned one is refused), then all OpenPGP work (VERIFY PW3 → per
//! slot: attributes, import, UIF, read-back), then PIV (selecting PIV ends the PW3 session): GET
//! METADATA 9B → ADMIN DATA (a PIN-protected key: VERIFY PIN → PRINTED) → management-key
//! mutual authentication → per slot import + metadata read-back.
//! Every derived private key lives only in a `Zeroizing` buffer for the import command and is
//! wiped right after it. A failure part-way ([`EnrolError::Partial`]) leaves earlier slots
//! written on the card but no record in the vault; repeating the enrolment overwrites them
//! (spec/10 §7.4).

use secp256k1::{All, PublicKey, Secp256k1, Signing};
use zeroize::Zeroizing;

use super::apdu::ApduMode;
use super::openpgp::{DEFAULT_PW3, OpenPgp, Pw, SlotKey};
use super::piv::{ManagementCredential, MgmtCipher, Piv};
use super::plan::{
    CardSlot, KeyPath, KeyRole, PlanError, PlannedSlot, TouchPolicy, validate_against,
};
use super::record::{HwKeyRecord, HwPublicKey, RecordedSlot};
use super::{CardError, CardTransport, Firmware};
use crate::bip32::XPriv;
use crate::error::KeyError;
use crate::slip10::slip10_ed25519;

/// Why an enrolment stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrolError {
    /// The plan was refused before anything was written.
    Plan(PlanError),
    /// A card operation failed before any key was written (identification, slot check, PIN,
    /// management key).
    Card(CardError),
    /// A card operation failed once a key import had started: earlier slots (or this one) may
    /// already hold new keys, the vault records nothing (spec/10 §7.4).
    Partial(CardError),
    /// Key derivation failed.
    Key(KeyError),
    /// The OpenPGP and PIV serials differ (two devices answering?).
    SerialMismatch,
}

impl From<CardError> for EnrolError {
    fn from(error: CardError) -> Self {
        Self::Card(error)
    }
}

impl From<KeyError> for EnrolError {
    fn from(error: KeyError) -> Self {
        Self::Key(error)
    }
}

impl From<PlanError> for EnrolError {
    fn from(error: PlanError) -> Self {
        Self::Plan(error)
    }
}

impl EnrolError {
    /// The user-facing text in `lang`; `Display` is the Korean text.
    #[must_use]
    pub fn text_in(self, lang: crate::lang::Lang) -> String {
        match self {
            Self::Plan(error) => error.text_in(lang),
            Self::Card(error) | Self::Partial(error) => error.text_in(lang),
            Self::Key(error) => error.to_string(),
            Self::SerialMismatch => super::text::ENROL_SERIAL_MISMATCH.get(lang).to_owned(),
        }
    }
}

impl core::fmt::Display for EnrolError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.text_in(crate::lang::Lang::Ko))
    }
}

/// The BIP32 master fingerprint (`HASH160(master pubkey)[0..4]`) of a seed: identifies the
/// mnemonic (+ passphrase) without revealing it (spec/10 §8).
///
/// # Errors
///
/// Derivation errors.
pub fn master_fingerprint<C: Signing>(
    ctx: &Secp256k1<C>,
    seed: &[u8; 64],
) -> Result<[u8; 4], KeyError> {
    let master = XPriv::from_seed(seed)?;
    let mut secret = master.secret_key()?;
    let public = PublicKey::from_secret_key(ctx, &secret).serialize();
    secret.non_secure_erase();
    let hash = crate::btc::address::hash160(&public);
    let mut out = [0_u8; 4];
    for (slot, byte) in out.iter_mut().zip(hash) {
        *slot = byte;
    }
    Ok(out)
}

fn secp_scalar(
    ctx: &Secp256k1<All>,
    seed: &[u8; 64],
    role: KeyRole,
) -> Result<Zeroizing<[u8; 32]>, EnrolError> {
    let KeyPath::Bip32(path) = role.path()? else {
        return Err(EnrolError::Card(CardError::Internal));
    };
    let node = XPriv::from_seed(seed)?.derive_path(ctx, &path)?;
    Ok(Zeroizing::new(*node.key_bytes()))
}

fn ed_seed(seed: &[u8; 64], role: KeyRole) -> Result<Zeroizing<[u8; 32]>, EnrolError> {
    let KeyPath::Slip10(path) = role.path()? else {
        return Err(EnrolError::Card(CardError::Internal));
    };
    Ok(slip10_ed25519(seed, &path)?)
}

/// The public key of `role` derived from `seed` (the pre-import preview, spec/10 §7.2).
///
/// # Errors
///
/// Derivation errors.
pub fn derive_public(
    ctx: &Secp256k1<All>,
    seed: &[u8; 64],
    role: KeyRole,
) -> Result<HwPublicKey, EnrolError> {
    role.validate()?;
    match role.curve() {
        super::plan::Curve::Secp256k1 => {
            let scalar = secp_scalar(ctx, seed, role)?;
            let mut secret = secp256k1::SecretKey::from_byte_array(*scalar)
                .map_err(|_| KeyError::DerivationFailed)?;
            let public = PublicKey::from_secret_key(ctx, &secret).serialize();
            secret.non_secure_erase();
            Ok(HwPublicKey::Secp256k1(public))
        }
        super::plan::Curve::Ed25519 => {
            let seed = ed_seed(seed, role)?;
            Ok(HwPublicKey::Ed25519(crate::sol::keys::public_key(&seed)))
        }
    }
}

/// One line of the pre-import confirmation: slot, path text, public key and addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewLine {
    /// The planned slot.
    pub planned: PlannedSlot,
    /// `m/…` path.
    pub path: String,
    /// Derived public key.
    pub public: HwPublicKey,
    /// Address text(s) ([`super::plan::addresses`]).
    pub addresses: Vec<String>,
}

/// Derives every planned key for the confirmation screen. Nothing touches a card.
///
/// # Errors
///
/// Derivation errors.
pub fn preview(
    ctx: &Secp256k1<All>,
    seed: &[u8; 64],
    slots: &[PlannedSlot],
) -> Result<Vec<PreviewLine>, EnrolError> {
    slots
        .iter()
        .map(|planned| {
            let public = derive_public(ctx, seed, planned.role)?;
            Ok(PreviewLine {
                planned: *planned,
                path: planned.role.path_text_in(crate::lang::Lang::Ko),
                public,
                addresses: super::plan::addresses(ctx, planned.role, &public)?,
            })
        })
        .collect()
}

/// [`preview`] with its own context (for callers outside yw-core: the app's key worker).
///
/// # Errors
///
/// Derivation errors.
pub fn preview_seed(
    seed: &[u8; 64],
    slots: &[PlannedSlot],
) -> Result<Vec<PreviewLine>, EnrolError> {
    let ctx = crate::entropy::secp_context(&mut crate::entropy::OsRandom)?;
    preview(&ctx, seed, slots)
}

/// What identifies a seed without revealing it: its BIP32 master fingerprint and the EVM
/// account-0 address (`m/44'/60'/0'/0/0`). The wizard compares the address with the vault's own
/// account 0 to warn when the entered recovery words are the ones this PC already stores
/// (spec/10 §7.1-2).
///
/// # Errors
///
/// Derivation errors.
pub fn seed_identity(
    seed: &[u8; 64],
) -> Result<([u8; 4], crate::evm::address::Address), EnrolError> {
    let ctx = crate::entropy::secp_context(&mut crate::entropy::OsRandom)?;
    let fingerprint = master_fingerprint(&ctx, seed)?;
    let public = derive_public(
        &ctx,
        seed,
        KeyRole::Evm {
            index: crate::bip32::path::AccountIndex::ZERO,
            btc: None,
        },
    )?;
    let address = super::plan::evm_address(&public)?;
    Ok((fingerprint, address))
}

/// "가져오기 없이 등록" (spec/10 §7.5): builds the record of a card that already holds the
/// planned keys, **without writing anything**. Reads the serial(s), validates the plan against
/// the enrolled records, then per slot the public key (`OpenPGP` `00 47 81 00`, PIV GET
/// METADATA) and requires it to equal the key derived from `seed`; the record takes the card's
/// own touch (and PIV PIN) policy. Only read-only commands are sent.
///
/// # Errors
///
/// [`EnrolError::Plan`], [`CardError::KeyMismatch`] (a slot holds another key or none:
/// [`CardError::NotFound`]), [`CardError::NotSupported`] (a PIV policy this wallet does not
/// use), card and derivation errors.
pub fn adopt_card(
    transport: &mut dyn CardTransport,
    mode: ApduMode,
    seed: &[u8; 64],
    slots: &[PlannedSlot],
    records: &[HwKeyRecord],
) -> Result<Enrolled, EnrolError> {
    let ctx = crate::entropy::secp_context(&mut crate::entropy::OsRandom)?;
    let fingerprint = master_fingerprint(&ctx, seed)?;
    let has_pgp = slots
        .iter()
        .any(|planned| matches!(planned.slot, CardSlot::OpenPgp(_)));
    let has_piv = slots
        .iter()
        .any(|planned| matches!(planned.slot, CardSlot::Piv(_)));
    let (serial, firmware) = identify(transport, mode, has_pgp, has_piv)?;
    validate_against(records, serial, fingerprint, slots)?;
    let mut defaults = DefaultsSeen::default();
    let mut recorded = Vec::with_capacity(slots.len());
    if has_pgp {
        let mut session = OpenPgp::open(transport, mode)?;
        for planned in slots {
            let CardSlot::OpenPgp(key) = planned.slot else {
                continue;
            };
            let expected = derive_public(&ctx, seed, planned.role)?;
            let public = session.public_key(key)?;
            if expected != HwPublicKey::Secp256k1(public) {
                return Err(EnrolError::Card(CardError::KeyMismatch));
            }
            let touch = session.touch_policy(key)?;
            recorded.push(RecordedSlot {
                slot: planned.slot,
                role: planned.role,
                touch,
                pin: super::plan::PinPolicy::NotApplicable,
                public: expected,
                path_known: true,
            });
        }
    }
    if has_piv {
        let mut session = Piv::open(transport, mode)?;
        let management = session.management_state()?;
        let (pin_default, _) = session.pin_metadata()?;
        defaults.piv_management = management.default;
        defaults.piv_management_protected = management.protected;
        defaults.piv_pin = pin_default;
        for planned in slots {
            let CardSlot::Piv(slot) = planned.slot else {
                continue;
            };
            let expected = derive_public(&ctx, seed, planned.role)?;
            let metadata = session.slot_metadata(slot)?;
            if metadata.algorithm != super::piv::ALG_ED25519
                || metadata.public.map(HwPublicKey::Ed25519) != Some(expected)
            {
                return Err(EnrolError::Card(CardError::KeyMismatch));
            }
            let pin = [super::plan::PinPolicy::Once, super::plan::PinPolicy::Always]
                .into_iter()
                .find(|policy| super::piv::pin_policy_byte(*policy) == metadata.pin_policy)
                .ok_or(CardError::NotSupported)?;
            let touch = [
                super::plan::TouchPolicy::Never,
                super::plan::TouchPolicy::Always,
                super::plan::TouchPolicy::Cached,
            ]
            .into_iter()
            .find(|policy| super::piv::touch_policy_byte(*policy) == metadata.touch_policy)
            .ok_or(CardError::NotSupported)?;
            recorded.push(RecordedSlot {
                slot: planned.slot,
                role: planned.role,
                touch,
                pin,
                public: expected,
                path_known: true,
            });
        }
    }
    recorded.sort_by_key(|slot| {
        slots
            .iter()
            .position(|planned| planned.slot == slot.slot)
            .unwrap_or(usize::MAX)
    });
    let record = HwKeyRecord {
        serial,
        firmware,
        fingerprint,
        slots: recorded,
    };
    let mut all = records.to_vec();
    all.push(record.clone());
    if !record.is_valid() || !super::record::records_consistent(&all) {
        return Err(EnrolError::Card(CardError::KeyMismatch));
    }
    Ok(Enrolled { record, defaults })
}

/// Card credentials for an enrolment (all wiped by their owners).
pub struct EnrolAuth<'a> {
    /// OpenPGP admin PIN (PW3), needed when the plan has OpenPGP slots.
    pub admin_pin: &'a [u8],
    /// PIV management key bytes (24 for 3DES/AES-192, 16 or 32 for AES-128/256), needed when
    /// the plan has PIV slots and the key is not PIN-protected; its algorithm is read from the
    /// card (GET METADATA 9B).
    pub management_key: &'a [u8],
    /// PIV PIN, needed when the management key is PIN-protected (ADMIN DATA flag `02`): the
    /// key is then read from PRINTED after VERIFY PIN and wiped after the authentication.
    pub piv_pin: &'a [u8],
    /// The CNG-backed cipher for the management key.
    pub cipher: Option<&'a dyn MgmtCipher>,
    /// A fresh random challenge (16 bytes; the first 8 are used for 3DES).
    pub challenge: [u8; 16],
    /// The user saw the keys [`occupied_slots`] found in the planned slots and confirmed that
    /// they are destroyed. Without it such a key stops the enrolment before anything is sent
    /// that needs a PIN ([`CardError::ForeignKey`]).
    pub overwrite: bool,
}

impl core::fmt::Debug for EnrolAuth<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("EnrolAuth([REDACTED])")
    }
}

/// Factory defaults seen during enrolment; the wizard then asks the user to change them
/// (spec/10 §9.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent facts read from the card"
)]
pub struct DefaultsSeen {
    /// The OpenPGP admin PIN that worked is `12345678`.
    pub openpgp_admin: bool,
    /// The PIV PIN is still `123456` (metadata).
    pub piv_pin: bool,
    /// The PIV management key is still the default (metadata).
    pub piv_management: bool,
    /// The PIV management key is stored PIN-protected (ADMIN DATA flag `02`).
    pub piv_management_protected: bool,
}

/// Result of one card enrolment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enrolled {
    /// The record to store (vault tag 5).
    pub record: HwKeyRecord,
    /// Defaults to change.
    pub defaults: DefaultsSeen,
}

/// The serial and firmware of the inserted card, without writing anything. Reads OpenPGP when
/// `pgp`, PIV when `piv`; both must agree.
///
/// # Errors
///
/// [`EnrolError::SerialMismatch`], card errors.
pub fn identify(
    transport: &mut dyn CardTransport,
    mode: ApduMode,
    pgp: bool,
    piv: bool,
) -> Result<(u32, Firmware), EnrolError> {
    let mut found: Option<(u32, Firmware)> = None;
    if pgp {
        let session = OpenPgp::open(transport, mode)?;
        found = Some((session.app.serial, session.firmware));
    }
    if piv {
        let session = Piv::open(transport, mode)?;
        match found {
            Some((serial, _)) if serial != session.serial => {
                return Err(EnrolError::SerialMismatch);
            }
            _ => found = Some((session.serial, session.firmware)),
        }
    }
    found.ok_or(EnrolError::Card(CardError::Internal))
}

/// A planned slot that already holds a key the enrolment would destroy ([`occupied_slots`],
/// spec/10 §7.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Occupant {
    /// The slot.
    pub slot: CardSlot,
    /// Its key, when it is one of the curves this wallet reads in that applet (secp256k1 in
    /// `OpenPGP`, Ed25519 in PIV); `None` for RSA, another curve or an unreadable key.
    pub public: Option<HwPublicKey>,
}

/// The planned slots of the card on `transport` that hold a key the enrolment would destroy
/// (read-only: SELECT, `00 47 81 00`, GET METADATA; no PIN): not empty, and not a key that
/// stays reachable — one the plan derives from `seed` (for this slot: a retry after a partial
/// write or the same words again; for another slot: it moves) or one an enrolled card of
/// `records` holds. The serial is the caller's business.
///
/// # Errors
///
/// Card (also applet and firmware) and derivation errors.
pub fn occupied_slots(
    transport: &mut dyn CardTransport,
    mode: ApduMode,
    seed: &[u8; 64],
    slots: &[PlannedSlot],
    records: &[HwKeyRecord],
) -> Result<Vec<Occupant>, EnrolError> {
    let ctx = crate::entropy::secp_context(&mut crate::entropy::OsRandom)?;
    let mut kept = Vec::with_capacity(slots.len());
    for planned in slots {
        kept.push(derive_public(&ctx, seed, planned.role)?);
    }
    kept.extend(
        records
            .iter()
            .flat_map(|record| &record.slots)
            .map(|held| held.public),
    );
    let mut found = Vec::new();
    let mut found_key = |slot: CardSlot, public: Option<HwPublicKey>| {
        if !public.is_some_and(|public| kept.contains(&public)) {
            found.push(Occupant { slot, public });
        }
    };
    if slots
        .iter()
        .any(|planned| matches!(planned.slot, CardSlot::OpenPgp(_)))
    {
        let mut session = OpenPgp::open(transport, mode)?;
        for planned in slots {
            let CardSlot::OpenPgp(key) = planned.slot else {
                continue;
            };
            match session.slot_key(key)? {
                SlotKey::Empty => {}
                SlotKey::Secp256k1(public) => {
                    found_key(planned.slot, Some(HwPublicKey::Secp256k1(public)));
                }
                SlotKey::Other => found_key(planned.slot, None),
            }
        }
    }
    if slots
        .iter()
        .any(|planned| matches!(planned.slot, CardSlot::Piv(_)))
    {
        let mut session = Piv::open(transport, mode)?;
        for planned in slots {
            let CardSlot::Piv(slot) = planned.slot else {
                continue;
            };
            match session.slot_metadata(slot) {
                Err(CardError::NotFound) => {}
                Ok(metadata) if metadata.algorithm == super::piv::ALG_ED25519 => {
                    found_key(planned.slot, metadata.public.map(HwPublicKey::Ed25519));
                }
                Ok(_) => found_key(planned.slot, None),
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(found)
}

/// A card error once an import has started ([`EnrolError::Partial`]): keys may be on the card.
const fn partial(error: CardError) -> EnrolError {
    EnrolError::Partial(error)
}

/// Enrols one card with `slots` (spec/10 §7.3).
///
/// # Errors
///
/// Before any write: [`EnrolError::Plan`], [`EnrolError::Card`] — among them
/// [`CardError::ForeignKey`] (a planned slot holds a key the plan does not derive and
/// `auth.overwrite` is not set) and [`CardError::Conditions`] (a fixed touch policy other than
/// the planned one) — and derivation errors; [`EnrolError::Partial`] once an import started.
#[expect(
    clippy::too_many_lines,
    reason = "one card sequence: checks, OpenPGP, PIV"
)]
pub fn enrol_card(
    transport: &mut dyn CardTransport,
    mode: ApduMode,
    seed: &[u8; 64],
    slots: &[PlannedSlot],
    records: &[HwKeyRecord],
    auth: &EnrolAuth<'_>,
) -> Result<Enrolled, EnrolError> {
    let ctx = crate::entropy::secp_context(&mut crate::entropy::OsRandom)?;
    let fingerprint = master_fingerprint(&ctx, seed)?;
    let has_pgp = slots
        .iter()
        .any(|planned| matches!(planned.slot, CardSlot::OpenPgp(_)));
    let has_piv = slots
        .iter()
        .any(|planned| matches!(planned.slot, CardSlot::Piv(_)));
    let (serial, firmware) = identify(transport, mode, has_pgp, has_piv)?;
    validate_against(records, serial, fingerprint, slots)?;
    // Read-only checks before any PIN or write: a key the plan does not derive is never
    // destroyed without the user's confirmation, and a fixed touch policy is never changed.
    if !auth.overwrite && !occupied_slots(transport, mode, seed, slots, records)?.is_empty() {
        return Err(EnrolError::Card(CardError::ForeignKey));
    }
    if has_pgp {
        let mut session = OpenPgp::open(transport, mode)?;
        for planned in slots {
            let CardSlot::OpenPgp(key) = planned.slot else {
                continue;
            };
            let current = session.touch_policy(key).ok();
            let fixed = matches!(
                current,
                Some(TouchPolicy::AlwaysFixed | TouchPolicy::CachedFixed)
            );
            if fixed && current != Some(planned.touch) {
                return Err(EnrolError::Card(CardError::Conditions));
            }
        }
    }

    let mut defaults = DefaultsSeen::default();
    let mut recorded = Vec::with_capacity(slots.len());
    // Set when the first import starts: every card error after it may leave new keys behind.
    let mut written = false;
    if has_pgp {
        let mut session = OpenPgp::open(transport, mode)?;
        if session.app.serial != serial {
            return Err(EnrolError::SerialMismatch);
        }
        session.verify(Pw::Admin, auth.admin_pin)?;
        defaults.openpgp_admin = auth.admin_pin == DEFAULT_PW3;
        for planned in slots {
            let CardSlot::OpenPgp(key) = planned.slot else {
                continue;
            };
            let scalar = secp_scalar(&ctx, seed, planned.role)?;
            written = true;
            let public = session
                .import_secp256k1(&ctx, key, &scalar, planned.touch)
                .map_err(partial)?;
            drop(scalar);
            recorded.push(RecordedSlot {
                slot: planned.slot,
                role: planned.role,
                touch: planned.touch,
                pin: planned.pin,
                public: HwPublicKey::Secp256k1(public),
                path_known: true,
            });
        }
    }
    if has_piv {
        // After OpenPGP keys were written, every failure is a partial enrolment.
        let after_openpgp = written;
        let stage = move |error: CardError| {
            if after_openpgp {
                EnrolError::Partial(error)
            } else {
                EnrolError::Card(error)
            }
        };
        let mut session = Piv::open(transport, mode).map_err(stage)?;
        if session.serial != serial {
            return Err(EnrolError::SerialMismatch);
        }
        let (pin_default, _) = session.pin_metadata().map_err(stage)?;
        let cipher = auth.cipher.ok_or(CardError::Internal).map_err(stage)?;
        let management = session
            .authenticate_management(
                ManagementCredential {
                    key: auth.management_key,
                    pin: auth.piv_pin,
                },
                cipher,
                &auth.challenge,
            )
            .map_err(stage)?;
        defaults.piv_management = management.default;
        defaults.piv_management_protected = management.protected;
        defaults.piv_pin = pin_default;
        for planned in slots {
            let CardSlot::Piv(slot) = planned.slot else {
                continue;
            };
            let ed = ed_seed(seed, planned.role)?;
            let before = written;
            written = true;
            let public = session
                .import_ed25519(slot, &ed, planned.pin, planned.touch)
                .map_err(|error| match error {
                    // The card refused the import command itself: nothing of this slot written.
                    CardError::Ed25519ImportRefused if !before => EnrolError::Card(error),
                    other => EnrolError::Partial(other),
                })?;
            drop(ed);
            recorded.push(RecordedSlot {
                slot: planned.slot,
                role: planned.role,
                touch: planned.touch,
                pin: planned.pin,
                public: HwPublicKey::Ed25519(public),
                path_known: true,
            });
        }
    }
    // Keep the plan order in the record.
    recorded.sort_by_key(|slot| {
        slots
            .iter()
            .position(|planned| planned.slot == slot.slot)
            .unwrap_or(usize::MAX)
    });
    let record = HwKeyRecord {
        serial,
        firmware,
        fingerprint,
        slots: recorded,
    };
    // The derived keys must also agree with what other cards hold for the same paths.
    let mut all = records.to_vec();
    all.push(record.clone());
    if !record.is_valid() || !super::record::records_consistent(&all) {
        return Err(partial(CardError::KeyMismatch));
    }
    Ok(Enrolled { record, defaults })
}
