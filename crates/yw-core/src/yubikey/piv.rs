//! PIV on YubiKey 5.7+ (spec/10 §5.3): Ed25519 keys in `9A`/`9C`/`9D`/`9E`/`82`–`95`.
//!
//! | step | APDU |
//! |---|---|
//! | SELECT | `00 A4 04 00 05 A0 00 00 03 08 00` |
//! | version / serial | `00 FD 00 00 00` / `00 F8 00 00 00` |
//! | metadata | `00 F7 00 <slot> 00` → `01 alg, 02 [pin, touch], 03 origin, 04 { 86 pub }, 05 default` |
//! | VERIFY PIN | `00 20 00 80 08 <PIN padded with FF>` |
//! | management key | `00 87 <type> 9B 7C 02 80 00` → `7C { 80 witness }`; `00 87 <type> 9B 7C { 80 D(witness), 81 challenge }` → `7C { 82 E(challenge) }` |
//! | import Ed25519 | `00 FE E0 <slot> 07 20 <seed> AA 01 <pin> AB 01 <touch>` |
//! | sign | `00 87 E0 <slot> 7C { 82 00, 81 <message> }` → `7C { 82 <signature> }` |
//! | change PIN / PUK | `00 24 00 80` / `81` `‖ old(8, FF) ‖ new(8, FF)` |
//! | set management key | `00 FF FF FF ‖ <type> 9B <len> <key>` |
//!
//! The management-key block cipher (3DES / AES-ECB, one block each way) is [`MgmtCipher`]: yw-win
//! implements it with Windows CNG; yw-core has no AES or 3DES of its own (D6).
#![deny(clippy::indexing_slicing)]

use zeroize::Zeroizing;

use super::apdu::{ApduMode, Command, SW_OK, exchange, exchange_ok};
use super::plan::{PinPolicy, PivSlot, TouchPolicy};
use super::{CardError, CardTransport, Firmware, tlv};

/// PIV application identifier (NIST SP 800-73-4 truncated AID).
pub const AID: [u8; 5] = [0xA0, 0x00, 0x00, 0x03, 0x08];
/// Algorithm id Ed25519 (YubiKey 5.7).
pub const ALG_ED25519: u8 = 0xE0;
/// Default PIN.
pub const DEFAULT_PIN: &[u8] = b"123456";
/// Default PUK.
pub const DEFAULT_PUK: &[u8] = b"12345678";
/// Default management key (3DES before 5.7, AES-192 from 5.7).
pub const DEFAULT_MANAGEMENT_KEY: [u8; 24] = [
    1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
];
/// PIN / PUK length bounds (6..=8 ASCII bytes, padded to 8 with `FF`).
pub const PIN_LEN: core::ops::RangeInclusive<usize> = 6..=8;
/// The management key slot.
pub const SLOT_MANAGEMENT: u8 = 0x9B;
/// The PIN "slot" of GET METADATA.
pub const SLOT_PIN: u8 = 0x80;
/// Longest message signed in one GENERAL AUTHENTICATE (fits one extended APDU; Solana messages
/// are at most 1,232 bytes).
pub const MAX_SIGN_MESSAGE: usize = 2_048;

const INS_SELECT: u8 = 0xA4;
const INS_VERIFY: u8 = 0x20;
const INS_CHANGE_REFERENCE: u8 = 0x24;
const INS_AUTHENTICATE: u8 = 0x87;
const INS_IMPORT: u8 = 0xFE;
const INS_GET_METADATA: u8 = 0xF7;
const INS_GET_SERIAL: u8 = 0xF8;
const INS_GET_VERSION: u8 = 0xFD;
const INS_SET_MGMKEY: u8 = 0xFF;

/// Management key algorithm (GET METADATA `9B` tag 01).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MgmtAlgorithm {
    /// Triple DES (3-key), 8-byte blocks, 24-byte key.
    TripleDes,
    /// AES-128.
    Aes128,
    /// AES-192 (default from 5.7).
    Aes192,
    /// AES-256.
    Aes256,
}

impl MgmtAlgorithm {
    /// The PIV key type byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::TripleDes => 0x03,
            Self::Aes128 => 0x08,
            Self::Aes192 => 0x0A,
            Self::Aes256 => 0x0C,
        }
    }

    /// Inverse of [`MgmtAlgorithm::code`].
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0x03 => Some(Self::TripleDes),
            0x08 => Some(Self::Aes128),
            0x0A => Some(Self::Aes192),
            0x0C => Some(Self::Aes256),
            _ => None,
        }
    }

    /// Block (and challenge) length.
    #[must_use]
    pub const fn block_len(self) -> usize {
        match self {
            Self::TripleDes => 8,
            _ => 16,
        }
    }

    /// Key length.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::TripleDes | Self::Aes192 => 24,
            Self::Aes256 => 32,
        }
    }
}

/// One-block ECB encryption/decryption with the management key (spec/10 §5.3.2).
pub trait MgmtCipher {
    /// Encrypts one block.
    ///
    /// # Errors
    ///
    /// [`CardError::Internal`] when the platform cipher fails or lengths are wrong.
    fn encrypt_block(
        &self,
        algorithm: MgmtAlgorithm,
        key: &[u8],
        block: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CardError>;

    /// Decrypts one block.
    ///
    /// # Errors
    ///
    /// As [`MgmtCipher::encrypt_block`].
    fn decrypt_block(
        &self,
        algorithm: MgmtAlgorithm,
        key: &[u8],
        block: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CardError>;
}

/// A management key (secret; wiped on drop, no `Clone`, `Debug` redacted).
pub struct MgmtKey {
    algorithm: MgmtAlgorithm,
    key: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for MgmtKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "MgmtKey({:?}, [REDACTED])", self.algorithm)
    }
}

impl MgmtKey {
    /// Wraps `key` for `algorithm`.
    ///
    /// # Errors
    ///
    /// [`CardError::PinFormat`] for a wrong length.
    pub fn new(algorithm: MgmtAlgorithm, key: &[u8]) -> Result<Self, CardError> {
        if key.len() != algorithm.key_len() {
            return Err(CardError::PinFormat);
        }
        Ok(Self {
            algorithm,
            key: Zeroizing::new(key.to_vec()),
        })
    }

    /// The factory default key for `algorithm` (3DES or AES-192).
    ///
    /// # Errors
    ///
    /// [`CardError::PinFormat`] for AES-128/256 (no such default).
    pub fn default_for(algorithm: MgmtAlgorithm) -> Result<Self, CardError> {
        Self::new(algorithm, &DEFAULT_MANAGEMENT_KEY)
    }

    /// The algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> MgmtAlgorithm {
        self.algorithm
    }

    /// Parses 48/32/64 hex digits (the form ykman prints).
    ///
    /// # Errors
    ///
    /// [`CardError::PinFormat`].
    pub fn from_hex(algorithm: MgmtAlgorithm, text: &str) -> Result<Self, CardError> {
        let digits = text.trim().as_bytes();
        let mut key = Zeroizing::new(vec![0_u8; algorithm.key_len()]);
        crate::hex::decode_into(digits, &mut key, true).map_err(|_| CardError::PinFormat)?;
        Self::new(algorithm, &key)
    }
}

/// A PIN padded to 8 bytes with `FF`.
///
/// # Errors
///
/// [`CardError::PinFormat`] outside 6..=8 bytes or for a byte `FF`.
pub fn padded_pin(pin: &[u8]) -> Result<Zeroizing<[u8; 8]>, CardError> {
    if !PIN_LEN.contains(&pin.len()) || pin.contains(&0xFF) {
        return Err(CardError::PinFormat);
    }
    let mut out = Zeroizing::new([0xFF_u8; 8]);
    for (slot, byte) in out.iter_mut().zip(pin) {
        *slot = *byte;
    }
    Ok(out)
}

/// PIN policy byte (`AA`).
#[must_use]
pub const fn pin_policy_byte(policy: PinPolicy) -> u8 {
    match policy {
        PinPolicy::NotApplicable => 0x00,
        PinPolicy::Once => 0x02,
        PinPolicy::Always => 0x03,
    }
}

/// Touch policy byte (`AB`): never 01, always 02, cached 03 (fixed variants are OpenPGP only).
#[must_use]
pub const fn touch_policy_byte(policy: TouchPolicy) -> u8 {
    match policy {
        TouchPolicy::Never => 0x01,
        TouchPolicy::Always | TouchPolicy::AlwaysFixed => 0x02,
        TouchPolicy::Cached | TouchPolicy::CachedFixed => 0x03,
    }
}

// ---- builders ----

/// SELECT the PIV application.
#[must_use]
pub fn select() -> Command {
    Command::new(0x00, INS_SELECT, 0x04, 0x00, AID.to_vec())
}

/// GET VERSION.
#[must_use]
pub fn get_version() -> Command {
    Command::new(0x00, INS_GET_VERSION, 0x00, 0x00, Vec::new())
}

/// GET SERIAL (5.0.3+).
#[must_use]
pub fn get_serial() -> Command {
    Command::new(0x00, INS_GET_SERIAL, 0x00, 0x00, Vec::new())
}

/// GET METADATA of a slot (5.3+).
#[must_use]
pub fn get_metadata(slot: u8) -> Command {
    Command::new(0x00, INS_GET_METADATA, 0x00, slot, Vec::new())
}

/// VERIFY PIN.
///
/// # Errors
///
/// [`CardError::PinFormat`].
pub fn verify_pin(pin: &[u8]) -> Result<Command, CardError> {
    Ok(Command::no_response(
        0x00,
        INS_VERIFY,
        0x00,
        0x80,
        padded_pin(pin)?.to_vec(),
    ))
}

/// CHANGE REFERENCE DATA for the PIN (`80`) or the PUK (`81`).
///
/// # Errors
///
/// [`CardError::PinFormat`].
pub fn change_reference(puk: bool, old: &[u8], new: &[u8]) -> Result<Command, CardError> {
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(padded_pin(old)?.as_slice());
    data.extend_from_slice(padded_pin(new)?.as_slice());
    Ok(Command::no_response(
        0x00,
        INS_CHANGE_REFERENCE,
        0x00,
        if puk { 0x81 } else { 0x80 },
        data,
    ))
}

/// The witness request `7C 02 80 00`.
#[must_use]
pub fn auth_witness_request(algorithm: MgmtAlgorithm) -> Command {
    Command::new(
        0x00,
        INS_AUTHENTICATE,
        algorithm.code(),
        SLOT_MANAGEMENT,
        vec![0x7C, 0x02, 0x80, 0x00],
    )
}

/// The mutual-authentication answer `7C { 80 decrypted, 81 challenge }`.
///
/// # Errors
///
/// [`CardError::TooLarge`] (never for block lengths).
pub fn auth_response(
    algorithm: MgmtAlgorithm,
    decrypted: &[u8],
    challenge: &[u8],
) -> Result<Command, CardError> {
    let mut inner = Vec::with_capacity(36);
    tlv::push(&mut inner, 0x80, decrypted)?;
    tlv::push(&mut inner, 0x81, challenge)?;
    Ok(Command::new(
        0x00,
        INS_AUTHENTICATE,
        algorithm.code(),
        SLOT_MANAGEMENT,
        tlv::encode(0x7C, &inner)?,
    ))
}

/// IMPORT ASYMMETRIC KEY of an Ed25519 seed with explicit policies.
///
/// # Errors
///
/// [`CardError::TooLarge`] (never).
pub fn import_ed25519(
    slot: PivSlot,
    seed: &[u8; 32],
    pin: PinPolicy,
    touch: TouchPolicy,
) -> Result<Command, CardError> {
    let mut data = Zeroizing::new(Vec::with_capacity(40));
    tlv::push(&mut data, 0x07, seed)?;
    tlv::push(&mut data, 0xAA, &[pin_policy_byte(pin)])?;
    tlv::push(&mut data, 0xAB, &[touch_policy_byte(touch)])?;
    Ok(Command::no_response(
        0x00,
        INS_IMPORT,
        ALG_ED25519,
        slot.id(),
        data.to_vec(),
    ))
}

/// GENERAL AUTHENTICATE signing `message` with the Ed25519 key in `slot`.
///
/// # Errors
///
/// [`CardError::TooLarge`] above [`MAX_SIGN_MESSAGE`].
pub fn sign_ed25519(slot: PivSlot, message: &[u8]) -> Result<Command, CardError> {
    if message.len() > MAX_SIGN_MESSAGE {
        return Err(CardError::TooLarge);
    }
    let mut inner = Vec::with_capacity(message.len().saturating_add(8));
    tlv::push(&mut inner, 0x82, &[])?;
    tlv::push(&mut inner, 0x81, message)?;
    Ok(Command::new(
        0x00,
        INS_AUTHENTICATE,
        ALG_ED25519,
        slot.id(),
        tlv::encode(0x7C, &inner)?,
    ))
}

/// SET MANAGEMENT KEY (no touch requirement).
#[must_use]
pub fn set_management_key(new: &MgmtKey) -> Command {
    let mut data = Vec::with_capacity(new.key.len().saturating_add(3));
    data.push(new.algorithm.code());
    data.push(SLOT_MANAGEMENT);
    data.push(u8::try_from(new.key.len()).unwrap_or(0));
    data.extend_from_slice(&new.key);
    Command::no_response(0x00, INS_SET_MGMKEY, 0xFF, 0xFF, data)
}

// ---- parsers ----

/// GET METADATA of a key slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotMetadata {
    /// Algorithm byte (`E0` Ed25519).
    pub algorithm: u8,
    /// PIN policy byte.
    pub pin_policy: u8,
    /// Touch policy byte.
    pub touch_policy: u8,
    /// Origin: 1 generated on the card, 2 imported.
    pub origin: u8,
    /// Ed25519 public key (tag 04 { 86 }).
    pub public: Option<[u8; 32]>,
}

/// Parses GET METADATA of a key slot.
///
/// # Errors
///
/// [`CardError::Malformed`].
pub fn parse_slot_metadata(response: &[u8]) -> Result<SlotMetadata, CardError> {
    let algorithm = *tlv::find(response, 0x01)?
        .first()
        .ok_or(CardError::Malformed)?;
    let policy = tlv::find(response, 0x02)?;
    let (pin_policy, touch_policy) = match policy {
        [pin, touch] => (*pin, *touch),
        _ => return Err(CardError::Malformed),
    };
    let origin = *tlv::find(response, 0x03)?
        .first()
        .ok_or(CardError::Malformed)?;
    let public = match tlv::find(response, 0x04) {
        Ok(encoded) if algorithm == ALG_ED25519 => Some(
            tlv::find(encoded, 0x86)?
                .try_into()
                .map_err(|_| CardError::Malformed)?,
        ),
        _ => None,
    };
    Ok(SlotMetadata {
        algorithm,
        pin_policy,
        touch_policy,
        origin,
        public,
    })
}

/// `(algorithm, is_default)` of the management key metadata (`9B`).
///
/// # Errors
///
/// [`CardError::Malformed`], [`CardError::NotSupported`] for an unknown type.
pub fn parse_management_metadata(response: &[u8]) -> Result<(MgmtAlgorithm, bool), CardError> {
    let algorithm = tlv::find(response, 0x01)?
        .first()
        .copied()
        .and_then(MgmtAlgorithm::from_code)
        .ok_or(CardError::NotSupported)?;
    let is_default = tlv::find(response, 0x05).is_ok_and(|value| value == [0x01]);
    Ok((algorithm, is_default))
}

/// `(is_default, retries_left)` of the PIN metadata (`80`).
///
/// # Errors
///
/// [`CardError::Malformed`].
pub fn parse_pin_metadata(response: &[u8]) -> Result<(bool, u8), CardError> {
    let is_default = tlv::find(response, 0x05).is_ok_and(|value| value == [0x01]);
    let retries = match tlv::find(response, 0x06)? {
        [_total, left] => *left,
        _ => return Err(CardError::Malformed),
    };
    Ok((is_default, retries))
}

fn parse_version(response: &[u8]) -> Result<Firmware, CardError> {
    match response {
        [major, minor, patch] => Ok(Firmware::new(*major, *minor, *patch)),
        _ => Err(CardError::Malformed),
    }
}

/// The value of `7C { tag value }` in a GENERAL AUTHENTICATE response.
///
/// # Errors
///
/// [`CardError::Malformed`].
pub fn dynamic_auth_value(response: &[u8], tag: u16) -> Result<&[u8], CardError> {
    tlv::find(tlv::unwrap_single(response, 0x7C)?, tag)
}

// ---- flows ----

/// A PIV session on a connected card (selected).
pub struct Piv<'t> {
    transport: &'t mut dyn CardTransport,
    mode: ApduMode,
    /// Firmware.
    pub firmware: Firmware,
    /// Serial.
    pub serial: u32,
}

impl core::fmt::Debug for Piv<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Piv")
            .field("serial", &self.serial)
            .field("firmware", &self.firmware)
            .finish_non_exhaustive()
    }
}

impl<'t> Piv<'t> {
    /// SELECT, version, serial; requires Ed25519 support (5.7+).
    ///
    /// # Errors
    ///
    /// [`CardError::AppletMissing`], [`CardError::FirmwareTooOld`], status errors.
    pub fn open(transport: &'t mut dyn CardTransport, mode: ApduMode) -> Result<Self, CardError> {
        let selected = exchange(transport, &select(), mode)?;
        if selected.sw != SW_OK {
            return Err(CardError::from_status(selected.sw));
        }
        let firmware = parse_version(&exchange_ok(transport, &get_version(), mode)?)?;
        if !firmware.at_least(super::MIN_FIRMWARE_PIV_ED25519) {
            return Err(CardError::FirmwareTooOld);
        }
        let serial = exchange_ok(transport, &get_serial(), mode)?;
        let serial = u32::from_be_bytes(
            serial
                .as_slice()
                .try_into()
                .map_err(|_| CardError::Malformed)?,
        );
        Ok(Self {
            transport,
            mode,
            firmware,
            serial,
        })
    }

    fn run(&mut self, command: &Command) -> Result<Zeroizing<Vec<u8>>, CardError> {
        exchange_ok(self.transport, command, self.mode)
    }

    /// VERIFY PIN.
    ///
    /// # Errors
    ///
    /// [`CardError::PinFormat`], [`CardError::WrongPin`], [`CardError::PinBlocked`].
    pub fn verify_pin(&mut self, pin: &[u8]) -> Result<(), CardError> {
        self.run(&verify_pin(pin)?).map(drop)
    }

    /// Changes the PIN or the PUK.
    ///
    /// # Errors
    ///
    /// As [`Piv::verify_pin`].
    pub fn change_reference(&mut self, puk: bool, old: &[u8], new: &[u8]) -> Result<(), CardError> {
        self.run(&change_reference(puk, old, new)?).map(drop)
    }

    /// The management key algorithm and whether it is still the default.
    ///
    /// # Errors
    ///
    /// Status and parse errors.
    pub fn management_metadata(&mut self) -> Result<(MgmtAlgorithm, bool), CardError> {
        parse_management_metadata(&self.run(&get_metadata(SLOT_MANAGEMENT))?)
    }

    /// Whether the PIN is still the default, and its remaining tries.
    ///
    /// # Errors
    ///
    /// Status and parse errors.
    pub fn pin_metadata(&mut self) -> Result<(bool, u8), CardError> {
        parse_pin_metadata(&self.run(&get_metadata(SLOT_PIN))?)
    }

    /// Mutual authentication with the management key (ykman `authenticate`): decrypt the card's
    /// witness, send it with our random challenge, and require the card's encryption of the
    /// challenge.
    ///
    /// # Errors
    ///
    /// [`CardError::SecurityStatus`] (wrong key: the card refuses the witness),
    /// [`CardError::ManagementKeyMismatch`] (the card's proof is wrong), cipher and status errors.
    pub fn authenticate(
        &mut self,
        key: &MgmtKey,
        cipher: &dyn MgmtCipher,
        challenge: &[u8],
    ) -> Result<(), CardError> {
        let algorithm = key.algorithm;
        if challenge.len() != algorithm.block_len() {
            return Err(CardError::Internal);
        }
        let response = self.run(&auth_witness_request(algorithm))?;
        let witness = dynamic_auth_value(&response, 0x80)?;
        if witness.len() != algorithm.block_len() {
            return Err(CardError::Malformed);
        }
        let decrypted = cipher.decrypt_block(algorithm, &key.key, witness)?;
        let response = self.run(&auth_response(algorithm, &decrypted, challenge)?)?;
        let proof = dynamic_auth_value(&response, 0x82)?;
        let expected = cipher.encrypt_block(algorithm, &key.key, challenge)?;
        if subtle::ConstantTimeEq::ct_eq(proof, expected.as_slice()).unwrap_u8() != 1 {
            return Err(CardError::ManagementKeyMismatch);
        }
        Ok(())
    }

    /// Replaces the management key (must be authenticated).
    ///
    /// # Errors
    ///
    /// Status errors.
    pub fn set_management_key(&mut self, new: &MgmtKey) -> Result<(), CardError> {
        self.run(&set_management_key(new)).map(drop)
    }

    /// Imports an Ed25519 seed (management key authenticated), then reads the metadata back
    /// and requires algorithm `E0`, origin imported, the policies and the public key of `seed`.
    ///
    /// # Errors
    ///
    /// [`CardError::KeyMismatch`], status errors.
    pub fn import_ed25519(
        &mut self,
        slot: PivSlot,
        seed: &[u8; 32],
        pin: PinPolicy,
        touch: TouchPolicy,
    ) -> Result<[u8; 32], CardError> {
        let expected = ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .to_bytes();
        let early = !self
            .firmware
            .at_least(super::DOCUMENTED_FIRMWARE_PIV_ED25519_IMPORT);
        self.run(&import_ed25519(slot, seed, pin, touch)?)
            .map_err(|error| match error {
                CardError::NotSupported | CardError::WrongData if early => {
                    CardError::Ed25519ImportRefused
                }
                other => other,
            })?;
        let metadata = self.slot_metadata(slot)?;
        if metadata.algorithm != ALG_ED25519
            || metadata.origin != 2
            || metadata.pin_policy != pin_policy_byte(pin)
            || metadata.touch_policy != touch_policy_byte(touch)
            || metadata.public != Some(expected)
        {
            return Err(CardError::KeyMismatch);
        }
        Ok(expected)
    }

    /// GET METADATA of a key slot.
    ///
    /// # Errors
    ///
    /// [`CardError::NotFound`] for an empty slot, status and parse errors.
    pub fn slot_metadata(&mut self, slot: PivSlot) -> Result<SlotMetadata, CardError> {
        parse_slot_metadata(&self.run(&get_metadata(slot.id()))?)
    }

    /// Verifies the PIN and signs `message` with the Ed25519 key in `slot` (64-byte signature).
    ///
    /// # Errors
    ///
    /// PIN, touch and status errors; [`CardError::Malformed`].
    pub fn sign_ed25519(
        &mut self,
        slot: PivSlot,
        pin: &[u8],
        message: &[u8],
    ) -> Result<[u8; 64], CardError> {
        self.verify_pin(pin)?;
        let response = self.run(&sign_ed25519(slot, message)?)?;
        dynamic_auth_value(&response, 0x82)?
            .try_into()
            .map_err(|_| CardError::Malformed)
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, reason = "test assertions on fixed frames")]
mod tests {
    use super::*;

    fn frame(command: &Command) -> Vec<u8> {
        super::super::apdu::encode(command, ApduMode::Short).unwrap()[0].to_vec()
    }

    #[test]
    fn builders_match_spec_bytes() {
        assert_eq!(
            frame(&select()),
            [
                0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00
            ]
        );
        assert_eq!(
            frame(&verify_pin(b"123456").unwrap()),
            [
                0x00, 0x20, 0x00, 0x80, 0x08, b'1', b'2', b'3', b'4', b'5', b'6', 0xFF, 0xFF
            ]
        );
        assert_eq!(
            frame(&auth_witness_request(MgmtAlgorithm::Aes192)),
            [0x00, 0x87, 0x0A, 0x9B, 0x04, 0x7C, 0x02, 0x80, 0x00, 0x00]
        );
        let slot = PivSlot::new(0x82).unwrap();
        let import =
            frame(&import_ed25519(slot, &[9; 32], PinPolicy::Always, TouchPolicy::Always).unwrap());
        assert_eq!(&import[..7], [0x00, 0xFE, 0xE0, 0x82, 40, 0x07, 0x20]);
        assert_eq!(
            &import[import.len() - 6..],
            [0xAA, 0x01, 0x03, 0xAB, 0x01, 0x02]
        );
        let sign = frame(&sign_ed25519(slot, b"msg").unwrap());
        assert_eq!(
            sign,
            [
                0x00, 0x87, 0xE0, 0x82, 0x09, 0x7C, 0x07, 0x82, 0x00, 0x81, 0x03, b'm', b's', b'g',
                0x00
            ]
        );
        assert!(padded_pin(b"12345").is_err());
        assert!(padded_pin(b"123456789").is_err());
        let key = MgmtKey::default_for(MgmtAlgorithm::Aes192).unwrap();
        assert_eq!(
            frame(&set_management_key(&key))[..8],
            [0x00, 0xFF, 0xFF, 0xFF, 27, 0x0A, 0x9B, 24]
        );
        assert!(!format!("{key:?}").contains("01"));
    }

    #[test]
    fn metadata_parsers() {
        let mut response = vec![0x01, 0x01, 0xE0, 0x02, 0x02, 0x03, 0x02, 0x03, 0x01, 0x02];
        response.extend_from_slice(&[0x04, 0x22, 0x86, 0x20]);
        response.extend_from_slice(&[0x5A; 32]);
        let metadata = parse_slot_metadata(&response).unwrap();
        assert_eq!(metadata.algorithm, ALG_ED25519);
        assert_eq!(
            (metadata.pin_policy, metadata.touch_policy, metadata.origin),
            (3, 2, 2)
        );
        assert_eq!(metadata.public, Some([0x5A; 32]));
        assert_eq!(
            parse_management_metadata(&[
                0x01, 0x01, 0x0A, 0x02, 0x02, 0x00, 0x01, 0x05, 0x01, 0x01
            ])
            .unwrap(),
            (MgmtAlgorithm::Aes192, true)
        );
        assert_eq!(
            parse_pin_metadata(&[0x01, 0x01, 0xFF, 0x05, 0x01, 0x00, 0x06, 0x02, 0x03, 0x02])
                .unwrap(),
            (false, 2)
        );
    }
}
