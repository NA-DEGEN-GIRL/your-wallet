//! "YubiKey 연결하기 (복구 단어 없이)" (spec/10 §7.6): a card that already holds keys is connected
//! without its recovery words. Everything here is read-only on the card:
//!
//! 1. [`scan_card`] reads the public keys that need no PIN — `OpenPGP` SIG/AUT through the
//!    algorithm attributes (`C1`/`C3` of `6E`: secp256k1 ECDSA only) and GET PUBLIC KEY
//!    (`00 47 81 00`), PIV `9A 9C 9D 9E 82–95` through GET METADATA (Ed25519 only) — with the
//!    touch/PIN policies, the PIN tries left and the PIV defaults.
//! 2. The user says what each found key is ([`KeyUse`]); [`connect_record`] makes the tag-5
//!    record: every slot `path_known = false` with a role index in the unknown-path band
//!    ([`super::plan::UNKNOWN_PATH_FIRST`]..), or — when another enrolled card already holds the
//!    same public key for the same use — that card's role (a backup holder of one account).
//! 3. Optionally [`verify_pin`] checks that the user knows the PIN (one VERIFY, nothing else).
//!
//! The derivation path stays unknown: the screens say "경로를 알 수 없음" and ask the user to
//! compare the addresses with the wallet they used before. Signing is exactly as for an
//! enrolled card (serial, slot and recorded public key checked before the PIN).
#![deny(clippy::indexing_slicing)]

use super::apdu::ApduMode;
use super::enrol::{DefaultsSeen, EnrolError, Enrolled};
use super::openpgp::{ALG_ECDSA, OID_SECP256K1, OpenPgp, Pw};
use super::piv::{ALG_ED25519, Piv};
use super::plan::{
    CardSlot, Curve, KeyRole, MAX_BTC_INDEX, MAX_CARDS, PgpKey, PinPolicy, PivSlot, PlanError,
    TouchPolicy, UNKNOWN_PATH_FIRST, is_unknown_index,
};
use super::record::{HwKeyRecord, HwPublicKey, RecordedSlot, records_consistent};
use super::text as t;
use super::{CardError, CardTransport, Firmware};
use crate::bip32::path::AccountIndex;
use crate::btc::account::ScriptType;
use crate::btc::network::BtcNetwork;
use crate::lang::{Lang, Text};
use crate::zec::ZecNetwork;

/// One key found on the card (no PIN was needed to read it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FoundKey {
    /// The slot.
    pub slot: CardSlot,
    /// Its public key (secp256k1 in `OpenPGP` SIG/AUT, Ed25519 in PIV).
    pub public: HwPublicKey,
    /// The slot's touch policy.
    pub touch: TouchPolicy,
    /// The PIV PIN policy (`NotApplicable` for `OpenPGP`).
    pub pin: PinPolicy,
}

/// An applet the scan could not read, with the reason (shown in the app language).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanNote {
    /// `true` for PIV (Solana keys), `false` for `OpenPGP` (EVM, Bitcoin, Zcash keys).
    pub piv: bool,
    /// Why it could not be read.
    pub reason: Text,
}

impl ScanNote {
    /// The note in `lang`, e.g. `PIV(Solana 키): 애플릿이 없습니다`.
    #[must_use]
    pub fn text(self, lang: Lang) -> String {
        let template = if self.piv {
            t::NOTE_PIV
        } else {
            t::NOTE_OPENPGP
        };
        template.fill(lang, [self.reason.get(lang)])
    }
}

/// What a scan saw on the card.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CardScan {
    /// Serial (`OpenPGP` AID and PIV GET SERIAL agree when both answer).
    pub serial: u32,
    /// Firmware.
    pub firmware: Firmware,
    /// Usable keys in slot order (`OpenPGP` SIG, AUT, then PIV `9A 9C 9D 9E 82–95`).
    pub keys: Vec<FoundKey>,
    /// Slots holding a key this wallet cannot use, with the reason (RSA, another curve, …).
    pub unsupported: Vec<(CardSlot, Text)>,
    /// Applets that could not be read, with the reason.
    pub notes: Vec<ScanNote>,
    /// `OpenPGP` PIN (PW1) tries left.
    pub pgp_pin_retries: Option<u8>,
    /// PIV PIN tries left.
    pub piv_pin_retries: Option<u8>,
    /// Factory PIV values seen (PIN, management key).
    pub defaults: DefaultsSeen,
}

impl CardScan {
    /// The found key of `slot`.
    #[must_use]
    pub fn key(&self, slot: CardSlot) -> Option<&FoundKey> {
        self.keys.iter().find(|key| key.slot == slot)
    }
}

/// What the user says a found key is (spec/10 §7.6). Taproot is not offered (no BIP340 on the
/// card).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyUse {
    /// An EVM account (secp256k1).
    Evm,
    /// One Bitcoin address of `script` on `network` (P2PKH, P2SH-P2WPKH or P2WPKH).
    Btc {
        /// Network.
        network: BtcNetwork,
        /// Address type.
        script: ScriptType,
    },
    /// One Zcash transparent address on `network`.
    Zec {
        /// Network.
        network: ZecNetwork,
    },
    /// A Solana account (Ed25519).
    Sol,
}

impl KeyUse {
    /// The curve the use needs.
    #[must_use]
    pub const fn curve(self) -> Curve {
        match self {
            Self::Sol => Curve::Ed25519,
            Self::Evm | Self::Btc { .. } | Self::Zec { .. } => Curve::Secp256k1,
        }
    }

    /// The role of this use with `index` (`None` out of range or Taproot).
    #[must_use]
    pub fn role(self, index: u32) -> Option<KeyRole> {
        let role = match self {
            Self::Evm => KeyRole::Evm {
                index: AccountIndex::new(index).ok()?,
                btc: None,
            },
            Self::Btc { network, script } => KeyRole::Btc {
                network,
                script,
                index,
            },
            Self::Zec { network } => KeyRole::Zec { network, index },
            Self::Sol => KeyRole::Sol {
                index: AccountIndex::new(index).ok()?,
            },
        };
        role.validate().ok().map(|()| role)
    }

    /// Whether `role` is a key used this way (any index).
    #[must_use]
    pub fn matches(self, role: KeyRole) -> bool {
        match (self, role) {
            (Self::Evm, KeyRole::Evm { .. }) | (Self::Sol, KeyRole::Sol { .. }) => true,
            (
                Self::Btc { network, script },
                KeyRole::Btc {
                    network: other_network,
                    script: other_script,
                    ..
                },
            ) => network == other_network && script == other_script,
            (
                Self::Zec { network },
                KeyRole::Zec {
                    network: other_network,
                    ..
                },
            ) => network == other_network,
            _ => false,
        }
    }

    /// Kind number for the index band (roles of one kind share it).
    const fn kind(self) -> u8 {
        match self {
            Self::Evm => 0,
            Self::Btc { .. } => 1,
            Self::Zec { .. } => 2,
            Self::Sol => 3,
        }
    }
}

const fn role_kind(role: KeyRole) -> u8 {
    match role {
        KeyRole::Evm { .. } => 0,
        KeyRole::Btc { .. } => 1,
        KeyRole::Zec { .. } => 2,
        KeyRole::Sol { .. } => 3,
    }
}

/// The PIV slots scanned, in order.
fn piv_slots() -> impl Iterator<Item = PivSlot> {
    PivSlot::STANDARD
        .into_iter()
        .filter_map(|id| PivSlot::new(id).ok())
        .chain((0..20).filter_map(PivSlot::retired))
}

/// `OpenPGP` algorithm attributes of a secp256k1 ECDSA key: `13 ‖ OID` with an optional
/// import-format byte (`00` standard, `FF` with public key).
fn is_secp256k1_attributes(attributes: &[u8]) -> bool {
    match attributes.split_first() {
        Some((&ALG_ECDSA, rest)) => {
            rest == OID_SECP256K1
                || rest
                    .split_last()
                    .is_some_and(|(format, oid)| oid == OID_SECP256K1 && matches!(format, 0 | 0xFF))
        }
        _ => false,
    }
}

const fn attributes_name(attributes: &[u8]) -> Text {
    match attributes.first() {
        Some(0x01) => t::SCAN_RSA,
        Some(0x16) => t::SCAN_PGP_ED25519,
        Some(0x12 | 0x13) => t::SCAN_OTHER_CURVE,
        _ => t::SCAN_UNKNOWN_KEY,
    }
}

fn scan_openpgp(
    transport: &mut dyn CardTransport,
    mode: ApduMode,
    scan: &mut CardScan,
) -> Result<Option<(u32, Firmware)>, CardError> {
    let mut session = OpenPgp::open(transport, mode)?;
    let identity = (session.app.serial, session.firmware);
    scan.pgp_pin_retries = session.app.retries.first().copied();
    for key in [PgpKey::Sig, PgpKey::Aut] {
        let slot = CardSlot::OpenPgp(key);
        let index = match key {
            PgpKey::Sig => 0,
            PgpKey::Aut => 2,
        };
        let attributes = session
            .app
            .attributes
            .get(index)
            .cloned()
            .unwrap_or_default();
        // The card's key information says the slot is empty (2026-11-12: some firmware answers
        // READ PUBLIC KEY of an empty slot with a status other than 6A88).
        if session.app.slot_without_key(key) == Some(true) {
            continue;
        }
        let public = match session.public_key(key) {
            Ok(public) => public,
            // Empty slot (or, for a key of another algorithm, nothing we can parse).
            Err(CardError::NotFound) => continue,
            Err(_) if !is_secp256k1_attributes(&attributes) => {
                scan.unsupported.push((slot, attributes_name(&attributes)));
                continue;
            }
            // An answer that is not a key (some firmware answers an empty slot with an empty
            // point): shown, not fatal. Reader and card failures stop the scan.
            Err(CardError::Malformed | CardError::KeyMismatch | CardError::WrongData) => {
                scan.unsupported.push((slot, t::SCAN_NO_PUBLIC));
                continue;
            }
            Err(error) => return Err(error),
        };
        if !is_secp256k1_attributes(&attributes) {
            scan.unsupported.push((slot, attributes_name(&attributes)));
            continue;
        }
        let touch = session.touch_policy(key)?;
        scan.keys.push(FoundKey {
            slot,
            public: HwPublicKey::Secp256k1(public),
            touch,
            pin: PinPolicy::NotApplicable,
        });
    }
    Ok(Some(identity))
}

fn piv_policies(pin: u8, touch: u8) -> Option<(PinPolicy, TouchPolicy)> {
    let pin = [PinPolicy::Once, PinPolicy::Always]
        .into_iter()
        .find(|policy| super::piv::pin_policy_byte(*policy) == pin)?;
    let touch = [TouchPolicy::Never, TouchPolicy::Always, TouchPolicy::Cached]
        .into_iter()
        .find(|policy| super::piv::touch_policy_byte(*policy) == touch)?;
    Some((pin, touch))
}

fn scan_piv(
    transport: &mut dyn CardTransport,
    mode: ApduMode,
    scan: &mut CardScan,
) -> Result<Option<(u32, Firmware)>, CardError> {
    let mut session = Piv::open(transport, mode)?;
    let identity = (session.serial, session.firmware);
    if let Ok((default, retries)) = session.pin_metadata() {
        scan.defaults.piv_pin = default;
        scan.piv_pin_retries = Some(retries);
    }
    if let Ok(state) = session.management_state() {
        scan.defaults.piv_management = state.default;
        scan.defaults.piv_management_protected = state.protected;
    }
    for piv in piv_slots() {
        let slot = CardSlot::Piv(piv);
        let metadata = match session.slot_metadata(piv) {
            Ok(metadata) => metadata,
            Err(CardError::NotFound) => continue,
            Err(CardError::Malformed | CardError::NotSupported | CardError::WrongData) => {
                scan.unsupported.push((slot, t::SCAN_NO_METADATA));
                continue;
            }
            Err(error) => return Err(error),
        };
        if metadata.algorithm != ALG_ED25519 {
            scan.unsupported.push((slot, t::SCAN_NOT_ED25519));
            continue;
        }
        let (Some(public), Some((pin, touch))) = (
            metadata.public,
            piv_policies(metadata.pin_policy, metadata.touch_policy),
        ) else {
            scan.unsupported.push((slot, t::SCAN_POLICY));
            continue;
        };
        if ed25519_dalek::VerifyingKey::from_bytes(&public).is_err() {
            scan.unsupported.push((slot, t::SCAN_BAD_PUBLIC));
            continue;
        }
        scan.keys.push(FoundKey {
            slot,
            public: HwPublicKey::Ed25519(public),
            touch,
            pin,
        });
    }
    Ok(Some(identity))
}

const fn applet_note(error: CardError) -> Text {
    match error {
        CardError::AppletMissing => t::NOTE_APPLET_MISSING,
        CardError::FirmwareTooOld => t::NOTE_FIRMWARE,
        CardError::KdfEnabled => t::NOTE_KDF,
        _ => t::NOTE_UNREADABLE,
    }
}

/// Reads every key the card shows without a PIN (spec/10 §7.6). Only read commands are sent
/// (SELECT, GET VERSION / SERIAL, GET DATA, GET PUBLIC KEY `47 81`, GET METADATA).
///
/// # Errors
///
/// [`EnrolError::SerialMismatch`] (the applets report different serials), the card error when
/// neither applet answers.
pub fn scan_card(
    transport: &mut dyn CardTransport,
    mode: ApduMode,
) -> Result<CardScan, EnrolError> {
    let mut scan = CardScan {
        serial: 0,
        firmware: Firmware::new(0, 0, 0),
        keys: Vec::new(),
        unsupported: Vec::new(),
        notes: Vec::new(),
        pgp_pin_retries: None,
        piv_pin_retries: None,
        defaults: DefaultsSeen::default(),
    };
    let pgp = scan_openpgp(transport, mode, &mut scan);
    let piv = scan_piv(transport, mode, &mut scan);
    let identity = match (&pgp, &piv) {
        (Ok(Some(a)), Ok(Some(b))) if a.0 != b.0 => return Err(EnrolError::SerialMismatch),
        (Ok(Some(found)), _) | (_, Ok(Some(found))) => *found,
        (Err(error), _) => return Err(EnrolError::Card(*error)),
        _ => return Err(EnrolError::Card(CardError::Internal)),
    };
    if let Err(error) = pgp {
        scan.notes.push(ScanNote {
            piv: false,
            reason: applet_note(error),
        });
    }
    if let Err(error) = piv {
        scan.notes.push(ScanNote {
            piv: true,
            reason: applet_note(error),
        });
    }
    (scan.serial, scan.firmware) = identity;
    Ok(scan)
}

/// The smallest free index of the unknown-path band for `kind`.
fn free_index(taken: &[KeyRole], kind: u8) -> Option<u32> {
    (UNKNOWN_PATH_FIRST..=MAX_BTC_INDEX).find(|index| {
        !taken
            .iter()
            .any(|role| role_kind(*role) == kind && role.index() == *index)
    })
}

/// The tag-5 record of `scan` with the user's `choices` (slots not listed are left out),
/// checked against the enrolled `records` (spec/10 §7.6). A key another enrolled card holds for
/// the same use keeps that card's role (one account, two holders); every other key gets the
/// next free index of the unknown-path band of its kind. Nothing touches a card.
///
/// # Errors
///
/// [`EnrolError::Plan`]: `SlotCount` (no choice), `CardAlreadyEnrolled`, `TooManyCards`,
/// `WrongApplet` (a use of the other curve, or a slot the scan did not find), `DuplicatePath`
/// (the same key twice for one use), `UnsupportedRole` (the band is full); `KeyMismatch` for a
/// record that contradicts the enrolled ones.
pub fn connect_record(
    scan: &CardScan,
    choices: &[(CardSlot, KeyUse)],
    records: &[HwKeyRecord],
) -> Result<HwKeyRecord, EnrolError> {
    if choices.is_empty() || choices.len() > super::plan::MAX_SLOTS_PER_CARD {
        return Err(PlanError::SlotCount.into());
    }
    if records.iter().any(|record| record.serial == scan.serial) {
        return Err(PlanError::CardAlreadyEnrolled.into());
    }
    if records.len() >= MAX_CARDS {
        return Err(PlanError::TooManyCards.into());
    }
    let mut taken: Vec<KeyRole> = records
        .iter()
        .flat_map(|record| &record.slots)
        .map(|slot| slot.role)
        .collect();
    let mut slots: Vec<RecordedSlot> = Vec::with_capacity(choices.len());
    for (slot, use_) in choices {
        let found = scan
            .key(*slot)
            .filter(|found| found.slot.curve() == use_.curve())
            .ok_or(PlanError::WrongApplet(*slot))?;
        if slots
            .iter()
            .any(|other| other.public == found.public && use_.matches(other.role))
        {
            return Err(PlanError::DuplicatePath(*slot).into());
        }
        // The same key already enrolled for the same use: that account, another holder.
        let existing = records
            .iter()
            .flat_map(|record| &record.slots)
            .find(|held| held.public == found.public && use_.matches(held.role));
        let (role, path_known) = if let Some(held) = existing {
            (held.role, held.path_known)
        } else {
            let index = free_index(&taken, use_.kind()).ok_or(PlanError::UnsupportedRole(*slot))?;
            (
                use_.role(index).ok_or(PlanError::UnsupportedRole(*slot))?,
                false,
            )
        };
        taken.push(role);
        slots.push(RecordedSlot {
            slot: *slot,
            role,
            touch: found.touch,
            pin: found.pin,
            public: found.public,
            path_known,
        });
    }
    slots.sort_by_key(|recorded| recorded.slot);
    // A reused known path joins the mnemonic of the cards that hold it.
    let fingerprint = if slots.iter().any(|recorded| recorded.path_known) {
        records
            .iter()
            .find(|record| record.has_known_path())
            .map_or([0; 4], |record| record.fingerprint)
    } else {
        [0; 4]
    };
    let record = HwKeyRecord {
        serial: scan.serial,
        firmware: scan.firmware,
        fingerprint,
        slots,
    };
    let mut all = records.to_vec();
    all.push(record.clone());
    if !record.is_valid() || !records_consistent(&all) {
        return Err(EnrolError::Card(CardError::KeyMismatch));
    }
    debug_assert!(
        record
            .slots
            .iter()
            .all(|slot| slot.path_known || is_unknown_index(slot.role.index()))
    );
    Ok(record)
}

/// [`connect_record`] after a fresh [`scan_card`] of the card on `transport`, which must be
/// card `serial` and still hold the keys of `expected` (the record the user confirmed):
/// "저장" of the flow. Read-only.
///
/// # Errors
///
/// [`CardError::WrongCard`], [`CardError::KeyMismatch`] (a key changed since the
/// confirmation), and the errors of [`scan_card`] and [`connect_record`].
pub fn connect_card(
    transport: &mut dyn CardTransport,
    mode: ApduMode,
    serial: u32,
    choices: &[(CardSlot, KeyUse)],
    expected: &HwKeyRecord,
    records: &[HwKeyRecord],
) -> Result<Enrolled, EnrolError> {
    let scan = scan_card(transport, mode)?;
    if scan.serial != serial {
        return Err(EnrolError::Card(CardError::WrongCard));
    }
    let record = connect_record(&scan, choices, records)?;
    if record != *expected {
        return Err(EnrolError::Card(CardError::KeyMismatch));
    }
    Ok(Enrolled {
        record,
        defaults: scan.defaults,
    })
}

/// "PIN으로 소유 확인" (optional, spec/10 §7.6): one VERIFY of the user PIN of the applet holding
/// `curve` keys (`OpenPGP` PW1 for other operations `82`, PIV PIN `80`) on the card on
/// `transport`, which must be card `serial`. No signature, no write, no touch. A factory value
/// ([`super::FACTORY_SECRETS`]) is never sent (spec/10 §9.2: a card still on factory PINs is set
/// up first).
///
/// # Errors
///
/// [`CardError::WrongCard`], [`CardError::PinFormat`] (also for a factory value, never sent),
/// [`CardError::WrongPin`] with the tries left, [`CardError::PinBlocked`], card errors.
pub fn verify_pin(
    transport: &mut dyn CardTransport,
    mode: ApduMode,
    serial: u32,
    curve: Curve,
    pin: &[u8],
) -> Result<(), CardError> {
    if super::is_factory_secret(pin) {
        return Err(CardError::PinFormat);
    }
    match curve {
        Curve::Secp256k1 => {
            let mut session = OpenPgp::open(transport, mode)?;
            if session.app.serial != serial {
                return Err(CardError::WrongCard);
            }
            session.verify(Pw::UserOther, pin)
        }
        Curve::Ed25519 => {
            let mut session = Piv::open(transport, mode)?;
            if session.serial != serial {
                return Err(CardError::WrongCard);
            }
            session.verify_pin(pin)
        }
    }
}

/// The address text(s) of a connected slot (for the confirmation): the role's addresses.
///
/// # Errors
///
/// [`CardError::KeyMismatch`].
pub fn slot_addresses(slot: &RecordedSlot) -> Result<Vec<String>, CardError> {
    super::plan::address_texts(slot.role, &slot.public)
}
