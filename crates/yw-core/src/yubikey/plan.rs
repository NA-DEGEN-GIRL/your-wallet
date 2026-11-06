//! Slot plan (spec/10 §3): which derived key goes into which card slot, the derivation path of
//! each role, the validation rules for one card and against the cards already enrolled, and the
//! slot-map queries over the vault tag-5 records.
//!
//! | role | curve | path | applet |
//! |---|---|---|---|
//! | `Evm { index, btc: None }` | secp256k1 | `m/44'/60'/0'/0/i` | OpenPGP SIG/AUT |
//! | `Evm { index, btc: Some(use) }` ("EVM 공유 키") | secp256k1 | `m/44'/60'/0'/0/i`, also one BTC address of `use.script` | OpenPGP SIG/AUT |
//! | `Btc { network, script, index }` | secp256k1 | `m/{44\|49\|84}'/{coin}'/0'/0/i` | OpenPGP SIG/AUT |
//! | `Sol { index }` | Ed25519 | `m/44'/501'/i'/0'` | PIV 9A/9C/9D/9E/82–95 |
//!
//! The Bitcoin index is the **address index of account 0's receive chain** (spec/10 §3.3): a
//! standard wallet restoring account 0 of the same type finds it (gap limit 20 → indices below
//! 20 are found without extra settings). Taproot is not offered (no BIP340 on the card).
#![deny(clippy::indexing_slicing)]

use secp256k1::{PublicKey, Secp256k1, Verification};

use super::CardError;
use super::record::{HwKeyRecord, HwPublicKey};
use crate::bip32::Bip32Path;
use crate::bip32::path::{AccountIndex, BtcChain, BtcCoin, btc_path, evm_path};
use crate::btc::account::{ScriptType, kind_for_compressed};
use crate::btc::address::encode_address;
use crate::btc::network::BtcNetwork;
use crate::evm::address::Address;
use crate::slip10::{Slip10Path, sol_path};
use crate::sol::SolAddress;

/// Most slots one card can hold in a plan: OpenPGP SIG + AUT + 24 PIV slots would be 26; the
/// wallet caps a card at 24 planned slots (record size, spec/10 §8).
pub const MAX_SLOTS_PER_CARD: usize = 24;
/// Most enrolled cards (vault tag-5 records).
pub const MAX_CARDS: usize = 8;
/// Highest Bitcoin address index offered (non-hardened; standard wallets scan 20 by default).
pub const MAX_BTC_INDEX: u32 = 999;

/// OpenPGP key reference. DEC (decipher only) is never used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PgpKey {
    /// Signature key (`B6`, PSO: COMPUTE DIGITAL SIGNATURE).
    Sig,
    /// Authentication key (`A4`, INTERNAL AUTHENTICATE).
    Aut,
}

/// A PIV slot that may hold an imported Ed25519 key: `9A`, `9C`, `9D`, `9E`, retired `82`–`95`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PivSlot(u8);

impl PivSlot {
    /// The four standard slots in offer order after the retired ones.
    pub const STANDARD: [u8; 4] = [0x9A, 0x9C, 0x9D, 0x9E];

    /// Validates a slot id.
    ///
    /// # Errors
    ///
    /// [`CardError::NotSupported`] for `F9` (attestation) and anything else.
    pub fn new(id: u8) -> Result<Self, CardError> {
        if (0x82..=0x95).contains(&id) || Self::STANDARD.contains(&id) {
            Ok(Self(id))
        } else {
            Err(CardError::NotSupported)
        }
    }

    /// The slot id byte.
    #[must_use]
    pub const fn id(self) -> u8 {
        self.0
    }

    /// The `n`th retired slot (`0` → `82`, …, `19` → `95`).
    #[must_use]
    pub fn retired(n: u8) -> Option<Self> {
        (n < 20).then(|| Self(0x82_u8.wrapping_add(n)))
    }

    /// Display label, e.g. `PIV 9a`, `PIV 82 (보관 1)`.
    #[must_use]
    pub fn label(self) -> String {
        if (0x82..=0x95).contains(&self.0) {
            format!("PIV {:02x} (보관 {})", self.0, self.0.wrapping_sub(0x81))
        } else {
            format!("PIV {:02x}", self.0)
        }
    }
}

/// A key slot on the card.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CardSlot {
    /// OpenPGP SIG or AUT.
    OpenPgp(PgpKey),
    /// A PIV slot.
    Piv(PivSlot),
}

impl CardSlot {
    /// `(applet, slot)` codes of the record (applet 1 OpenPGP with slot 1 SIG / 3 AUT, applet 2
    /// PIV with the slot id).
    #[must_use]
    pub const fn codes(self) -> (u8, u8) {
        match self {
            Self::OpenPgp(PgpKey::Sig) => (1, 1),
            Self::OpenPgp(PgpKey::Aut) => (1, 3),
            Self::Piv(slot) => (2, slot.0),
        }
    }

    /// Inverse of [`CardSlot::codes`].
    #[must_use]
    pub fn from_codes(applet: u8, slot: u8) -> Option<Self> {
        match (applet, slot) {
            (1, 1) => Some(Self::OpenPgp(PgpKey::Sig)),
            (1, 3) => Some(Self::OpenPgp(PgpKey::Aut)),
            (2, id) => PivSlot::new(id).ok().map(Self::Piv),
            _ => None,
        }
    }

    /// Display label.
    #[must_use]
    pub fn label(self) -> String {
        match self {
            Self::OpenPgp(PgpKey::Sig) => "OpenPGP 서명(SIG)".to_owned(),
            Self::OpenPgp(PgpKey::Aut) => "OpenPGP 인증(AUT)".to_owned(),
            Self::Piv(slot) => slot.label(),
        }
    }

    /// The curve the slot is used with in this wallet.
    #[must_use]
    pub const fn curve(self) -> Curve {
        match self {
            Self::OpenPgp(_) => Curve::Secp256k1,
            Self::Piv(_) => Curve::Ed25519,
        }
    }
}

/// Key curve.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Curve {
    /// secp256k1 ECDSA (EVM, Bitcoin).
    Secp256k1,
    /// Ed25519 (Solana).
    Ed25519,
}

impl Curve {
    /// Record code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Secp256k1 => 1,
            Self::Ed25519 => 2,
        }
    }
}

/// How an EVM key is also used as one Bitcoin address ("EVM 공유 키", spec/10 §3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BtcUse {
    /// Network.
    pub network: BtcNetwork,
    /// Address type (P2PKH, P2SH-P2WPKH or P2WPKH; never P2TR).
    pub script: ScriptType,
}

/// What a slot holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyRole {
    /// EVM account `i` (`m/44'/60'/0'/0/i`), optionally also a Bitcoin single address.
    Evm {
        /// Account index.
        index: AccountIndex,
        /// Shared Bitcoin use of the same key.
        btc: Option<BtcUse>,
    },
    /// Bitcoin single address `m/{44|49|84}'/{coin}'/0'/0/i`.
    Btc {
        /// Network (coin type 0' / 1').
        network: BtcNetwork,
        /// Address type (purpose 44/49/84).
        script: ScriptType,
        /// Receive address index (non-hardened, ≤ [`MAX_BTC_INDEX`]).
        index: u32,
    },
    /// Solana account `i` (`m/44'/501'/i'/0'`).
    Sol {
        /// Account index.
        index: AccountIndex,
    },
    /// Zcash transparent address `m/44'/{133|1}'/0'/0/i` (spec/10 §3.1, spec/12 §2.2).
    Zec {
        /// Network (coin type `133'` / `1'`).
        network: crate::zec::ZecNetwork,
        /// Receive address index (non-hardened, ≤ [`MAX_BTC_INDEX`]).
        index: u32,
    },
}

/// A derivation path of either scheme.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyPath {
    /// BIP32 secp256k1.
    Bip32(Bip32Path),
    /// SLIP-0010 Ed25519.
    Slip10(Slip10Path),
}

impl KeyPath {
    /// `m/…'` text.
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            Self::Bip32(path) => path.to_string(),
            Self::Slip10(path) => path.to_string(),
        }
    }
}

fn btc_coin(network: BtcNetwork, script: ScriptType) -> Result<BtcCoin, CardError> {
    BtcCoin::new(network == BtcNetwork::Testnet4, script.purpose(), 0)
        .map_err(|_| CardError::Internal)
}

impl KeyRole {
    /// The curve of the key.
    #[must_use]
    pub const fn curve(self) -> Curve {
        match self {
            Self::Evm { .. } | Self::Btc { .. } | Self::Zec { .. } => Curve::Secp256k1,
            Self::Sol { .. } => Curve::Ed25519,
        }
    }

    /// Checks the role's own ranges (no Taproot, Bitcoin index bound).
    ///
    /// # Errors
    ///
    /// [`CardError::NotSupported`].
    pub fn validate(self) -> Result<(), CardError> {
        let script_ok = |script: ScriptType| script != ScriptType::P2tr;
        match self {
            Self::Evm {
                btc: Some(use_), ..
            } if !script_ok(use_.script) => Err(CardError::NotSupported),
            Self::Btc { script, index, .. } if !script_ok(script) || index > MAX_BTC_INDEX => {
                Err(CardError::NotSupported)
            }
            Self::Zec { index, .. } if index > MAX_BTC_INDEX => Err(CardError::NotSupported),
            _ => Ok(()),
        }
    }

    /// The derivation path.
    ///
    /// # Errors
    ///
    /// [`CardError::NotSupported`] for an invalid role ([`KeyRole::validate`]).
    pub fn path(self) -> Result<KeyPath, CardError> {
        self.validate()?;
        match self {
            Self::Evm { index, .. } => Ok(KeyPath::Bip32(evm_path(index))),
            Self::Btc {
                network,
                script,
                index,
            } => btc_path(btc_coin(network, script)?, BtcChain::Receive, index)
                .map(KeyPath::Bip32)
                .map_err(|_| CardError::NotSupported),
            Self::Sol { index } => Ok(KeyPath::Slip10(sol_path(index))),
            Self::Zec { network, index } => {
                crate::bip32::path::zec_path(network == crate::zec::ZecNetwork::Testnet, 0, index)
                    .map(KeyPath::Bip32)
                    .map_err(|_| CardError::NotSupported)
            }
        }
    }

    /// The path text shown before import (`m/44'/60'/0'/0/3`).
    #[must_use]
    pub fn path_text(self) -> String {
        self.path()
            .map_or_else(|_| "(지원하지 않는 경로)".to_owned(), |path| path.text())
    }

    /// Path identity (scheme + components) used by the duplicate rules: two roles are the same
    /// key exactly when these are equal. The shared Bitcoin use of an EVM key does not change
    /// the key, so `Evm { i, None }` and `Evm { i, Some(_) }` are the same key.
    #[must_use]
    pub fn key_identity(self) -> (Curve, Vec<u32>) {
        let components = match self.path() {
            Ok(KeyPath::Bip32(path)) => path.components().to_vec(),
            Ok(KeyPath::Slip10(path)) => path.components().to_vec(),
            Err(_) => Vec::new(),
        };
        (self.curve(), components)
    }

    /// Short title for lists (`EVM 계정 3`, `Bitcoin P2WPKH 주소 0`, `Solana 계정 1`).
    #[must_use]
    pub fn title(self) -> String {
        match self {
            Self::Evm { index, btc: None } => format!("EVM 계정 {}", index.get()),
            Self::Evm {
                index,
                btc: Some(use_),
            } => format!(
                "EVM 계정 {} + Bitcoin {} (공유 키)",
                index.get(),
                script_name(use_.script)
            ),
            Self::Btc { script, index, .. } => {
                format!("Bitcoin {} 주소 {index}", script_name(script))
            }
            Self::Sol { index } => format!("Solana 계정 {}", index.get()),
            Self::Zec { index, .. } => format!("Zcash 일반(transparent) 주소 {index}"),
        }
    }
}

const fn script_name(script: ScriptType) -> &'static str {
    match script {
        ScriptType::P2pkh => "레거시(P2PKH)",
        ScriptType::P2shP2wpkh => "호환 세그윗(P2SH-P2WPKH)",
        ScriptType::P2wpkh => "네이티브 세그윗(P2WPKH)",
        ScriptType::P2tr => "탭루트(미지원)",
    }
}

/// Touch policy (OpenPGP UIF `D6`/`D8` values, PIV `AB`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TouchPolicy {
    /// No touch (not offered by the wizard; accepted when reading an existing card).
    Never,
    /// Touch for every operation.
    Always,
    /// Touch, cached for 15 s after a touch (for several Bitcoin inputs).
    Cached,
    /// OpenPGP only: `Always`, and the policy cannot be changed without resetting the applet.
    AlwaysFixed,
    /// OpenPGP only: `Cached`, fixed.
    CachedFixed,
}

impl TouchPolicy {
    /// Record code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Never => 1,
            Self::Always => 2,
            Self::Cached => 3,
            Self::AlwaysFixed => 4,
            Self::CachedFixed => 5,
        }
    }

    /// Inverse of [`TouchPolicy::code`].
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Never),
            2 => Some(Self::Always),
            3 => Some(Self::Cached),
            4 => Some(Self::AlwaysFixed),
            5 => Some(Self::CachedFixed),
            _ => None,
        }
    }

    /// Whether the card asks for a touch.
    #[must_use]
    pub const fn needs_touch(self) -> bool {
        !matches!(self, Self::Never)
    }

    /// Whether the policy is allowed for `slot` (fixed variants are OpenPGP only).
    #[must_use]
    pub const fn fits(self, slot: CardSlot) -> bool {
        match slot {
            CardSlot::OpenPgp(_) => true,
            CardSlot::Piv(_) => matches!(self, Self::Never | Self::Always | Self::Cached),
        }
    }

    /// Display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Never => "터치 없음",
            Self::Always => "항상 터치",
            Self::Cached => "터치 후 15초 유지",
            Self::AlwaysFixed => "항상 터치(고정)",
            Self::CachedFixed => "터치 후 15초 유지(고정)",
        }
    }
}

/// PIV PIN policy (`AA`). OpenPGP has none per key (PW1 validity is global; this wallet requires
/// "PW1 valid for one signature" and verifies PW1 before every operation anyway).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PinPolicy {
    /// Not applicable (OpenPGP).
    NotApplicable,
    /// PIN once per PIV session.
    Once,
    /// PIN before every operation.
    Always,
}

impl PinPolicy {
    /// Record code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::NotApplicable => 0,
            Self::Once => 2,
            Self::Always => 3,
        }
    }

    /// Inverse of [`PinPolicy::code`].
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::NotApplicable),
            2 => Some(Self::Once),
            3 => Some(Self::Always),
            _ => None,
        }
    }
}

/// One planned slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlannedSlot {
    /// The slot.
    pub slot: CardSlot,
    /// The key.
    pub role: KeyRole,
    /// Touch policy.
    pub touch: TouchPolicy,
    /// PIN policy (PIV only).
    pub pin: PinPolicy,
    /// The user chose this slot as a backup copy of a key already on another enrolled card.
    pub backup_copy: bool,
}

impl PlannedSlot {
    /// The recommended defaults for `slot` holding `role`: touch "always" (changeable; the fixed
    /// variants are an explicit choice, user decision 2026-11-05), PIN "always" on PIV.
    #[must_use]
    pub const fn recommended(slot: CardSlot, role: KeyRole) -> Self {
        let (touch, pin) = match slot {
            CardSlot::OpenPgp(_) => (TouchPolicy::Always, PinPolicy::NotApplicable),
            CardSlot::Piv(_) => (TouchPolicy::Always, PinPolicy::Always),
        };
        Self {
            slot,
            role,
            touch,
            pin,
            backup_copy: false,
        }
    }
}

/// Why a plan was refused (spec/10 §3.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanError {
    /// No slot, or more than [`MAX_SLOTS_PER_CARD`].
    SlotCount,
    /// The same slot twice.
    DuplicateSlot(CardSlot),
    /// The same derivation path twice on one card.
    DuplicatePath(CardSlot),
    /// A secp256k1 role in a PIV slot or an Ed25519 role in an OpenPGP slot.
    WrongApplet(CardSlot),
    /// Taproot or an index out of range.
    UnsupportedRole(CardSlot),
    /// The touch or PIN policy does not fit the slot.
    Policy(CardSlot),
    /// This card (serial) is already enrolled.
    CardAlreadyEnrolled,
    /// [`MAX_CARDS`] cards are enrolled.
    TooManyCards,
    /// The path is already on another card but the slot is not marked as a backup copy.
    PathOnOtherCard(CardSlot),
    /// The slot is marked as a backup copy but no other card holds the path.
    NotACopy(CardSlot),
    /// The mnemonic is not the one of the cards already enrolled (master fingerprint differs).
    DifferentMnemonic,
}

impl core::fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SlotCount => formatter.write_str("슬롯을 1개 이상 24개 이하로 고르세요."),
            Self::DuplicateSlot(slot) => {
                write!(formatter, "{} 슬롯을 두 번 골랐습니다.", slot.label())
            }
            Self::DuplicatePath(slot) => write!(
                formatter,
                "{}: 같은 경로의 키가 이 YubiKey의 다른 슬롯에 이미 있습니다.",
                slot.label()
            ),
            Self::WrongApplet(slot) => write!(
                formatter,
                "{}: 이 슬롯에는 그 종류의 키를 넣을 수 없습니다(OpenPGP = secp256k1, PIV = Ed25519).",
                slot.label()
            ),
            Self::UnsupportedRole(slot) => write!(
                formatter,
                "{}: 지원하지 않는 키입니다(탭루트 불가, 인덱스 범위 확인).",
                slot.label()
            ),
            Self::Policy(slot) => write!(
                formatter,
                "{}: 터치·PIN 정책이 맞지 않습니다.",
                slot.label()
            ),
            Self::CardAlreadyEnrolled => formatter.write_str(
                "이 YubiKey는 이미 등록되어 있습니다. 다시 등록하려면 먼저 등록을 지우세요.",
            ),
            Self::TooManyCards => formatter.write_str("YubiKey는 최대 8개까지 등록할 수 있습니다."),
            Self::PathOnOtherCard(slot) => write!(
                formatter,
                "{}: 이 키는 다른 YubiKey에 이미 있습니다. 같은 키를 넣으려면 '백업 복사본'으로 고르세요.",
                slot.label()
            ),
            Self::NotACopy(slot) => write!(
                formatter,
                "{}: '백업 복사본'으로 골랐지만 다른 YubiKey에 같은 키가 없습니다.",
                slot.label()
            ),
            Self::DifferentMnemonic => formatter
                .write_str("입력한 복구 단어가 이미 등록한 YubiKey의 복구 단어와 다릅니다."),
        }
    }
}

/// Validates a plan for one card on its own (spec/10 §3.5 rules 1–5).
///
/// # Errors
///
/// The first violated [`PlanError`].
pub fn validate_plan(slots: &[PlannedSlot]) -> Result<(), PlanError> {
    if slots.is_empty() || slots.len() > MAX_SLOTS_PER_CARD {
        return Err(PlanError::SlotCount);
    }
    for (position, planned) in slots.iter().enumerate() {
        let earlier = slots.get(..position).unwrap_or(&[]);
        if earlier.iter().any(|other| other.slot == planned.slot) {
            return Err(PlanError::DuplicateSlot(planned.slot));
        }
        if planned.role.curve() != planned.slot.curve() {
            return Err(PlanError::WrongApplet(planned.slot));
        }
        if planned.role.validate().is_err() {
            return Err(PlanError::UnsupportedRole(planned.slot));
        }
        let pin_ok = match planned.slot {
            CardSlot::OpenPgp(_) => planned.pin == PinPolicy::NotApplicable,
            CardSlot::Piv(_) => planned.pin != PinPolicy::NotApplicable,
        };
        if !planned.touch.fits(planned.slot) || !pin_ok {
            return Err(PlanError::Policy(planned.slot));
        }
        let identity = planned.role.key_identity();
        if earlier
            .iter()
            .any(|other| other.role.key_identity() == identity)
        {
            return Err(PlanError::DuplicatePath(planned.slot));
        }
    }
    Ok(())
}

/// Validates a plan for card `serial` against the enrolled records (spec/10 §3.5 rules 6–9).
///
/// # Errors
///
/// The first violated [`PlanError`] (including [`validate_plan`]'s).
pub fn validate_against(
    records: &[HwKeyRecord],
    serial: u32,
    fingerprint: [u8; 4],
    slots: &[PlannedSlot],
) -> Result<(), PlanError> {
    validate_plan(slots)?;
    if records.iter().any(|record| record.serial == serial) {
        return Err(PlanError::CardAlreadyEnrolled);
    }
    validate_before_card(records, fingerprint, slots)
}

/// The rules of [`validate_against`] that do not need the card's serial (spec/10 §3.5 rules
/// 1–5 and 7–9): what the wizard's confirmation screen shows before any card contact (§7.2).
/// Rule 6 (`CardAlreadyEnrolled`) is checked at the card (`enrol_card`).
///
/// # Errors
///
/// The first violated [`PlanError`].
pub fn validate_before_card(
    records: &[HwKeyRecord],
    fingerprint: [u8; 4],
    slots: &[PlannedSlot],
) -> Result<(), PlanError> {
    validate_plan(slots)?;
    if records.len() >= MAX_CARDS {
        return Err(PlanError::TooManyCards);
    }
    if records
        .iter()
        .any(|record| record.fingerprint != fingerprint)
    {
        return Err(PlanError::DifferentMnemonic);
    }
    for planned in slots {
        let identity = planned.role.key_identity();
        let elsewhere = records.iter().any(|record| {
            record
                .slots
                .iter()
                .any(|held| held.role.key_identity() == identity)
        });
        match (elsewhere, planned.backup_copy) {
            (true, false) => return Err(PlanError::PathOnOtherCard(planned.slot)),
            (false, true) => return Err(PlanError::NotACopy(planned.slot)),
            _ => {}
        }
    }
    Ok(())
}

/// One card holding an account's key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Holder {
    /// Card serial.
    pub serial: u32,
    /// Slot on that card.
    pub slot: CardSlot,
    /// Touch policy of that slot.
    pub touch: TouchPolicy,
}

/// A YubiKey account: one key (path) and every card that holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HwAccount {
    /// The role (for an EVM key held with and without a shared Bitcoin use on different cards,
    /// the first record's role).
    pub role: KeyRole,
    /// The public key (identical on every holder; [`super::record`] enforces it).
    pub public: HwPublicKey,
    /// Cards holding it, in record order.
    pub holders: Vec<Holder>,
}

/// The accounts of the slot map: one per distinct key, ordered EVM (by index), Bitcoin, Solana.
#[must_use]
pub fn accounts(records: &[HwKeyRecord]) -> Vec<HwAccount> {
    let mut out: Vec<HwAccount> = Vec::new();
    for record in records {
        for held in &record.slots {
            let holder = Holder {
                serial: record.serial,
                slot: held.slot,
                touch: held.touch,
            };
            let identity = held.role.key_identity();
            if let Some(account) = out
                .iter_mut()
                .find(|account| account.role.key_identity() == identity)
            {
                account.holders.push(holder);
            } else {
                out.push(HwAccount {
                    role: held.role,
                    public: held.public,
                    holders: vec![holder],
                });
            }
        }
    }
    out.sort_by_key(|account| sort_key(account.role));
    out
}

fn sort_key(role: KeyRole) -> (u8, u8, u8, u32) {
    match role {
        KeyRole::Evm { index, .. } => (0, 0, 0, index.get()),
        KeyRole::Btc {
            network,
            script,
            index,
        } => (1, network.id(), script.code(), index),
        KeyRole::Sol { index } => (2, 0, 0, index.get()),
        KeyRole::Zec { network, index } => (3, network.id(), 0, index),
    }
}

/// The slot holding the key of `role` on card `serial`, if that card holds it.
#[must_use]
pub fn slot_on_card(records: &[HwKeyRecord], role: KeyRole, serial: u32) -> Option<Holder> {
    let identity = role.key_identity();
    let record = records.iter().find(|record| record.serial == serial)?;
    record
        .slots
        .iter()
        .find(|held| held.role.key_identity() == identity)
        .map(|held| Holder {
            serial,
            slot: held.slot,
            touch: held.touch,
        })
}

/// The EVM address of a secp256k1 key.
///
/// # Errors
///
/// [`CardError::KeyMismatch`] for an Ed25519 or invalid key.
pub fn evm_address(public: &HwPublicKey) -> Result<Address, CardError> {
    match public {
        HwPublicKey::Secp256k1(bytes) => PublicKey::from_slice(bytes)
            .map(|key| Address::from_public_key(&key))
            .map_err(|_| CardError::KeyMismatch),
        HwPublicKey::Ed25519(_) => Err(CardError::KeyMismatch),
    }
}

/// The Bitcoin address of a secp256k1 key under `use_`.
///
/// # Errors
///
/// [`CardError::KeyMismatch`] for an Ed25519 or invalid key.
pub fn btc_address<C: Verification>(
    ctx: &Secp256k1<C>,
    public: &HwPublicKey,
    use_: BtcUse,
) -> Result<String, CardError> {
    match public {
        HwPublicKey::Secp256k1(bytes) => kind_for_compressed(ctx, use_.script, bytes)
            .map(|kind| encode_address(&kind, use_.network))
            .map_err(|_| CardError::KeyMismatch),
        HwPublicKey::Ed25519(_) => Err(CardError::KeyMismatch),
    }
}

/// The Solana address of an Ed25519 key.
///
/// # Errors
///
/// [`CardError::KeyMismatch`] for a secp256k1 key.
pub const fn sol_address(public: &HwPublicKey) -> Result<SolAddress, CardError> {
    match public {
        HwPublicKey::Ed25519(bytes) => Ok(SolAddress::from_bytes(*bytes)),
        HwPublicKey::Secp256k1(_) => Err(CardError::KeyMismatch),
    }
}

/// The address text(s) of an account for the pre-import and account screens: EVM checksum
/// address (and the shared Bitcoin address), Bitcoin address, Solana base58.
///
/// # Errors
///
/// [`CardError::KeyMismatch`].
pub fn addresses<C: Verification>(
    ctx: &Secp256k1<C>,
    role: KeyRole,
    public: &HwPublicKey,
) -> Result<Vec<String>, CardError> {
    match role {
        KeyRole::Evm { btc, .. } => {
            let mut out = vec![evm_address(public)?.to_checksum()];
            if let Some(use_) = btc {
                out.push(btc_address(ctx, public, use_)?);
            }
            Ok(out)
        }
        KeyRole::Btc {
            network, script, ..
        } => Ok(vec![btc_address(ctx, public, BtcUse { network, script })?]),
        KeyRole::Sol { .. } => Ok(vec![sol_address(public)?.to_base58()]),
        KeyRole::Zec { network, .. } => Ok(vec![zec_address(public, network)?]),
    }
}

/// The Zcash transparent `t1…`/`tm…` address of a secp256k1 key.
///
/// # Errors
///
/// [`CardError::KeyMismatch`] for an Ed25519 or invalid key.
pub fn zec_address(
    public: &HwPublicKey,
    network: crate::zec::ZecNetwork,
) -> Result<String, CardError> {
    match public {
        HwPublicKey::Secp256k1(bytes) if PublicKey::from_slice(bytes).is_ok() => {
            Ok(crate::zec::ZecAccount {
                network,
                source: crate::zec::ZecKeySource::Hardware { index: 0 },
                pubkey: *bytes,
            }
            .address())
        }
        _ => Err(CardError::KeyMismatch),
    }
}

/// [`addresses`] with its own verification-only context (no secret is involved): for callers
/// outside yw-core (the app's slot-map screens).
///
/// # Errors
///
/// [`CardError::KeyMismatch`].
pub fn address_texts(role: KeyRole, public: &HwPublicKey) -> Result<Vec<String>, CardError> {
    addresses(&Secp256k1::verification_only(), role, public)
}

/// Whether `components` are all hardened (SLIP-0010 requirement; used in tests).
#[cfg(test)]
pub(crate) fn all_hardened(components: &[u32]) -> bool {
    components
        .iter()
        .all(|component| component & crate::bip32::HARDENED != 0)
}
