//! Vault tag-5 record body: the slot map of one enrolled YubiKey (spec/10 §8, spec/02 §4.6).
//! No secret: serial, firmware, the BIP32 master fingerprint of the enrolment mnemonic, and per
//! slot the role (derivation path), policies and the public key read back from the card.
//!
//! ```text
//! body (after tag ‖ record_id ‖ created_unix, which the vault codec writes)
//! 4  serial u32
//! 3  firmware major, minor, patch
//! 4  master_fingerprint (HASH160(master pubkey)[0..4])
//! 1  slot_count n (1..=24)
//! n × 48 slot entries:
//!   1  applet (1 OpenPGP, 2 PIV)        1  slot (OpenPGP 1 SIG / 3 AUT; PIV slot id)
//!   1  curve (1 secp256k1, 2 Ed25519)   1  role (1 EVM, 2 BTC, 3 SOL)
//!   1  btc_network (0, 1, 2)            1  btc_script (0, 1 P2PKH, 2 P2SH-P2WPKH, 3 P2WPKH)
//!   4  index u32                        1  touch (TouchPolicy code)   1  pin (PinPolicy code)
//!   33 public key (secp256k1 compressed; Ed25519: 00 ‖ 32 bytes)      3  reserved 0
//! ```
#![deny(clippy::indexing_slicing)]

use super::plan::{
    BtcUse, CardSlot, Curve, KeyRole, MAX_SLOTS_PER_CARD, PinPolicy, PlannedSlot, TouchPolicy,
    validate_plan,
};
use super::{CardError, Firmware};
use crate::bip32::path::AccountIndex;
use crate::btc::account::ScriptType;
use crate::btc::network::BtcNetwork;

/// Fixed part of the body.
pub const BODY_FIXED_LEN: usize = 12;
/// One slot entry.
pub const SLOT_ENTRY_LEN: usize = 48;
/// Largest body (24 slots).
pub const MAX_BODY_LEN: usize = BODY_FIXED_LEN + MAX_SLOTS_PER_CARD * SLOT_ENTRY_LEN;

/// A public key as read from the card.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HwPublicKey {
    /// Compressed secp256k1 point.
    Secp256k1([u8; 33]),
    /// Ed25519 public key.
    Ed25519([u8; 32]),
}

impl HwPublicKey {
    /// The 33-byte record field.
    #[must_use]
    pub fn field(&self) -> [u8; 33] {
        match self {
            Self::Secp256k1(bytes) => *bytes,
            Self::Ed25519(bytes) => {
                let mut out = [0_u8; 33];
                for (slot, byte) in out.iter_mut().skip(1).zip(bytes) {
                    *slot = *byte;
                }
                out
            }
        }
    }
}

/// One recorded slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordedSlot {
    /// The slot.
    pub slot: CardSlot,
    /// The key.
    pub role: KeyRole,
    /// Touch policy set at enrolment.
    pub touch: TouchPolicy,
    /// PIN policy (PIV).
    pub pin: PinPolicy,
    /// Public key read back from the card (equal to the mnemonic-derived key at enrolment).
    pub public: HwPublicKey,
}

impl RecordedSlot {
    /// The plan entry this slot corresponds to (`backup_copy` false).
    #[must_use]
    pub const fn planned(&self) -> PlannedSlot {
        PlannedSlot {
            slot: self.slot,
            role: self.role,
            touch: self.touch,
            pin: self.pin,
            backup_copy: false,
        }
    }
}

/// The slot map of one card.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HwKeyRecord {
    /// Card serial (OpenPGP AID / PIV GET SERIAL; both must agree at enrolment).
    pub serial: u32,
    /// Firmware at enrolment.
    pub firmware: Firmware,
    /// BIP32 master fingerprint of the enrolment seed.
    pub fingerprint: [u8; 4],
    /// Slots (1..=24, valid per [`validate_plan`]).
    pub slots: Vec<RecordedSlot>,
}

fn role_fields(role: KeyRole) -> (u8, u8, u8, u32) {
    match role {
        KeyRole::Evm { index, btc: None } => (1, 0, 0, index.get()),
        KeyRole::Evm {
            index,
            btc: Some(use_),
        } => (1, use_.network.id(), use_.script.code(), index.get()),
        KeyRole::Btc {
            network,
            script,
            index,
        } => (2, network.id(), script.code(), index),
        KeyRole::Sol { index } => (3, 0, 0, index.get()),
        KeyRole::Zec { network, index } => (4, network.id(), 0, index),
    }
}

fn role_from(kind: u8, network: u8, script: u8, index: u32) -> Option<KeyRole> {
    let role = match (kind, network, script) {
        (1, 0, 0) => KeyRole::Evm {
            index: AccountIndex::new(index).ok()?,
            btc: None,
        },
        (1, network, script) => KeyRole::Evm {
            index: AccountIndex::new(index).ok()?,
            btc: Some(BtcUse {
                network: BtcNetwork::from_id(network)?,
                script: ScriptType::from_code(script)?,
            }),
        },
        (2, network, script) => KeyRole::Btc {
            network: BtcNetwork::from_id(network)?,
            script: ScriptType::from_code(script)?,
            index,
        },
        (3, 0, 0) => KeyRole::Sol {
            index: AccountIndex::new(index).ok()?,
        },
        (4, network, 0) => KeyRole::Zec {
            network: crate::zec::ZecNetwork::from_id(network)?,
            index,
        },
        _ => return None,
    };
    role.validate().ok()?;
    Some(role)
}

impl HwKeyRecord {
    /// Encoded body length.
    #[must_use]
    pub fn body_len(&self) -> usize {
        BODY_FIXED_LEN.saturating_add(self.slots.len().saturating_mul(SLOT_ENTRY_LEN))
    }

    /// Whether the record satisfies the decode rules (used before encoding).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        let planned: Vec<PlannedSlot> = self.slots.iter().map(RecordedSlot::planned).collect();
        validate_plan(&planned).is_ok()
            && self.slots.iter().all(|slot| {
                matches!(
                    (slot.role.curve(), slot.public),
                    (Curve::Secp256k1, HwPublicKey::Secp256k1(_))
                        | (Curve::Ed25519, HwPublicKey::Ed25519(_))
                ) && public_ok(&slot.public)
            })
    }

    /// Appends the body.
    ///
    /// # Errors
    ///
    /// [`CardError::Internal`] for an invalid record ([`HwKeyRecord::is_valid`]).
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), CardError> {
        if !self.is_valid() {
            return Err(CardError::Internal);
        }
        let count = u8::try_from(self.slots.len()).map_err(|_| CardError::Internal)?;
        out.extend_from_slice(&self.serial.to_be_bytes());
        out.extend_from_slice(&[
            self.firmware.major,
            self.firmware.minor,
            self.firmware.patch,
        ]);
        out.extend_from_slice(&self.fingerprint);
        out.push(count);
        for slot in &self.slots {
            let (applet, id) = slot.slot.codes();
            let (kind, network, script, index) = role_fields(slot.role);
            out.extend_from_slice(&[applet, id, slot.role.curve().code(), kind, network, script]);
            out.extend_from_slice(&index.to_be_bytes());
            out.push(slot.touch.code());
            out.push(slot.pin.code());
            out.extend_from_slice(&slot.public.field());
            out.extend_from_slice(&[0, 0, 0]);
        }
        Ok(())
    }

    /// Decodes a body from the front of `bytes`, returning the record and the rest. `None` for
    /// any rule violation (unknown codes, reserved bytes, invalid plan, invalid public key).
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<(Self, &[u8])> {
        let (serial, rest) = bytes.split_first_chunk::<4>()?;
        let ([major, minor, patch], rest) = rest.split_first_chunk::<3>()?;
        let (fingerprint, rest) = rest.split_first_chunk::<4>()?;
        let (count, mut rest) = rest.split_first()?;
        let count = usize::from(*count);
        if count == 0 || count > MAX_SLOTS_PER_CARD {
            return None;
        }
        let mut slots = Vec::with_capacity(count);
        for _ in 0..count {
            let (entry, tail) = rest.split_first_chunk::<SLOT_ENTRY_LEN>()?;
            rest = tail;
            slots.push(decode_slot(entry)?);
        }
        let record = Self {
            serial: u32::from_be_bytes(*serial),
            firmware: Firmware::new(*major, *minor, *patch),
            fingerprint: *fingerprint,
            slots,
        };
        record.is_valid().then_some((record, rest))
    }
}

fn public_ok(public: &HwPublicKey) -> bool {
    match public {
        HwPublicKey::Secp256k1(bytes) => secp256k1::PublicKey::from_slice(bytes).is_ok(),
        HwPublicKey::Ed25519(bytes) => ed25519_dalek::VerifyingKey::from_bytes(bytes).is_ok(),
    }
}

fn decode_slot(entry: &[u8; SLOT_ENTRY_LEN]) -> Option<RecordedSlot> {
    let (head, rest) = entry.split_first_chunk::<6>()?;
    let [applet, id, curve, kind, network, script] = *head;
    let (index, rest) = rest.split_first_chunk::<4>()?;
    let ([touch, pin], rest) = rest.split_first_chunk::<2>()?;
    let (public, reserved) = rest.split_first_chunk::<33>()?;
    if reserved != [0, 0, 0] {
        return None;
    }
    let slot = CardSlot::from_codes(applet, id)?;
    let role = role_from(kind, network, script, u32::from_be_bytes(*index))?;
    if role.curve().code() != curve {
        return None;
    }
    let public = match role.curve() {
        Curve::Secp256k1 => HwPublicKey::Secp256k1(*public),
        Curve::Ed25519 => {
            let (pad, key) = public.split_first()?;
            if *pad != 0 {
                return None;
            }
            HwPublicKey::Ed25519(key.try_into().ok()?)
        }
    };
    Some(RecordedSlot {
        slot,
        role,
        touch: TouchPolicy::from_code(*touch)?,
        pin: PinPolicy::from_code(*pin)?,
        public,
    })
}

/// Cross-record rules of the slot map (spec/10 §8): serials distinct, one master fingerprint,
/// and the same path always with the same public key.
#[must_use]
pub fn records_consistent(records: &[HwKeyRecord]) -> bool {
    for (position, record) in records.iter().enumerate() {
        let earlier = records.get(..position).unwrap_or(&[]);
        if earlier
            .iter()
            .any(|other| other.serial == record.serial || other.fingerprint != record.fingerprint)
        {
            return false;
        }
        for slot in &record.slots {
            let identity = slot.role.key_identity();
            let conflict = earlier
                .iter()
                .flat_map(|other| &other.slots)
                .any(|other| other.role.key_identity() == identity && other.public != slot.public);
            if conflict {
                return false;
            }
        }
    }
    true
}
