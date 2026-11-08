//! OpenPGP card 3.4 on YubiKey 5 (spec/10 §5.2): secp256k1 keys in SIG and AUT.
//!
//! | step | APDU |
//! |---|---|
//! | SELECT | `00 A4 04 00 06 D2 76 00 01 24 01 00` |
//! | version (Yubico) | `00 F1 00 00 00` → 3 bytes |
//! | application data | `00 CA 00 6E 00` → `6E { 4F AID, 73 { C0, C1 C2 C3, C4 … } }` |
//! | KDF-DO | `00 CA 00 F9 00` (KDF on → refuse) |
//! | VERIFY PW1 (sign) / PW1 (other) / PW3 | `00 20 00 81` / `82` / `83` `‖ PIN` |
//! | algorithm attributes | `00 DA 00 C1` (SIG) / `C3` (AUT) `‖ 13 2B 81 04 00 0A` (ECDSA secp256k1) |
//! | import | `00 DB 3F FF ‖ 4D { B6 00 \| A4 00, 7F48 { 92 20 }, 5F48 <32-byte scalar> }` |
//! | read public key | `00 47 81 00 ‖ B6 00 \| A4 00` → `7F49 { 86 04‖X‖Y }` |
//! | touch (UIF) | `00 DA 00 D6` (SIG) / `D8` (AUT) `‖ <uif> 20` |
//! | sign (SIG) | `00 2A 9E 9A ‖ digest(32) 00` → `r ‖ s` |
//! | sign (AUT) | `00 88 00 00 ‖ digest(32) 00` → `r ‖ s` |
//! | change PIN | `00 24 00 81` (PW1) / `83` (PW3) `‖ old ‖ new` |
#![deny(clippy::indexing_slicing)]

use secp256k1::{PublicKey, Secp256k1, SecretKey, Signing};
use zeroize::Zeroizing;

use super::apdu::{ApduMode, Command, exchange, exchange_ok};
use super::plan::{PgpKey, TouchPolicy};
use super::{CardError, CardTransport, Firmware, tlv};

/// OpenPGP application identifier prefix (RID D276000124, PIX 01).
pub const AID: [u8; 6] = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];
/// OID 1.3.132.0.10 (secp256k1).
pub const OID_SECP256K1: [u8; 5] = [0x2B, 0x81, 0x04, 0x00, 0x0A];
/// Algorithm id ECDSA (RFC 6637 / OpenPGP card §4.4.3.10).
pub const ALG_ECDSA: u8 = 0x13;
/// Default PW1 (user PIN).
pub const DEFAULT_PW1: &[u8] = b"123456";
/// Default PW3 (admin PIN).
pub const DEFAULT_PW3: &[u8] = b"12345678";
/// PW1 length bounds (OpenPGP card: 6..=127; YubiKey max 127).
pub const PW1_LEN: core::ops::RangeInclusive<usize> = 6..=127;
/// PW3 length bounds.
pub const PW3_LEN: core::ops::RangeInclusive<usize> = 8..=127;

const INS_SELECT: u8 = 0xA4;
const INS_GET_DATA: u8 = 0xCA;
const INS_GET_VERSION: u8 = 0xF1;
const INS_VERIFY: u8 = 0x20;
const INS_CHANGE_REFERENCE: u8 = 0x24;
const INS_PUT_DATA: u8 = 0xDA;
const INS_PUT_DATA_ODD: u8 = 0xDB;
const INS_GENERATE: u8 = 0x47;
const INS_PSO: u8 = 0x2A;
const INS_INTERNAL_AUTHENTICATE: u8 = 0x88;
const INS_TERMINATE: u8 = 0xE6;
const INS_ACTIVATE: u8 = 0x44;

/// RSA 2048 algorithm attributes (`01 0800 0020 00`, the factory value of every key slot).
pub const RSA2048_ATTRIBUTES: [u8; 6] = [0x01, 0x08, 0x00, 0x00, 0x20, 0x00];
/// RSA 4096 algorithm attributes (`01 1000 0020 00`): the first of yubikit's two attribute
/// changes of `delete_key` (spec/10 §15.2).
pub const RSA4096_ATTRIBUTES: [u8; 6] = [0x01, 0x10, 0x00, 0x00, 0x20, 0x00];
/// The wrong PIN yubikit's `reset` sends until PW1 and PW3 are blocked (`b"\0" * 8`).
pub const INVALID_PIN: [u8; 8] = [0; 8];
/// Most wrong VERIFY attempts sent to block one PIN (the counters are at most 15).
const MAX_BLOCK_ATTEMPTS: usize = 16;

/// Which PIN a VERIFY targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pw {
    /// PW1 for PSO: COMPUTE DIGITAL SIGNATURE (`81`).
    UserSign,
    /// PW1 for other operations (INTERNAL AUTHENTICATE, `82`).
    UserOther,
    /// PW3 admin (`83`).
    Admin,
}

impl Pw {
    /// VERIFY P2.
    #[must_use]
    pub const fn p2(self) -> u8 {
        match self {
            Self::UserSign => 0x81,
            Self::UserOther => 0x82,
            Self::Admin => 0x83,
        }
    }
}

impl PgpKey {
    /// Control reference template tag (`B6` SIG, `A4` AUT).
    #[must_use]
    pub const fn crt(self) -> u8 {
        match self {
            Self::Sig => 0xB6,
            Self::Aut => 0xA4,
        }
    }

    /// Algorithm attributes data object (`C1` SIG, `C3` AUT).
    #[must_use]
    pub const fn attributes_do(self) -> u8 {
        match self {
            Self::Sig => 0xC1,
            Self::Aut => 0xC3,
        }
    }

    /// Yubico user-interaction-flag data object (`D6` SIG, `D8` AUT).
    #[must_use]
    pub const fn uif_do(self) -> u8 {
        match self {
            Self::Sig => 0xD6,
            Self::Aut => 0xD8,
        }
    }

    /// The PW1 mode its operation needs.
    #[must_use]
    pub const fn pw(self) -> Pw {
        match self {
            Self::Sig => Pw::UserSign,
            Self::Aut => Pw::UserOther,
        }
    }
}

/// UIF byte (`00` off, `01` on, `02` fixed, `03` cached, `04` cached-fixed).
#[must_use]
pub const fn uif_byte(policy: TouchPolicy) -> u8 {
    match policy {
        TouchPolicy::Never => 0x00,
        TouchPolicy::Always => 0x01,
        TouchPolicy::AlwaysFixed => 0x02,
        TouchPolicy::Cached => 0x03,
        TouchPolicy::CachedFixed => 0x04,
    }
}

/// Inverse of [`uif_byte`].
#[must_use]
pub const fn touch_of_uif(byte: u8) -> Option<TouchPolicy> {
    match byte {
        0x00 => Some(TouchPolicy::Never),
        0x01 => Some(TouchPolicy::Always),
        0x02 => Some(TouchPolicy::AlwaysFixed),
        0x03 => Some(TouchPolicy::Cached),
        0x04 => Some(TouchPolicy::CachedFixed),
        _ => None,
    }
}

// ---- builders (pure) ----

/// SELECT the OpenPGP application.
#[must_use]
pub fn select() -> Command {
    Command::new(0x00, INS_SELECT, 0x04, 0x00, AID.to_vec())
}

/// Yubico GET VERSION.
#[must_use]
pub fn get_version() -> Command {
    Command::new(0x00, INS_GET_VERSION, 0x00, 0x00, Vec::new())
}

/// GET DATA for a one- or two-byte tag.
#[must_use]
pub fn get_data(tag: u16) -> Command {
    let [p1, p2] = tag.to_be_bytes();
    Command::new(0x00, INS_GET_DATA, p1, p2, Vec::new())
}

/// VERIFY `pw` with `pin` (the command data is wiped on drop).
#[must_use]
pub fn verify(pw: Pw, pin: &[u8]) -> Command {
    Command::no_response(0x00, INS_VERIFY, 0x00, pw.p2(), pin.to_vec())
}

/// CHANGE REFERENCE DATA (`old ‖ new`) for PW1 (`81`) or PW3 (`83`).
#[must_use]
pub fn change_pin(admin: bool, old: &[u8], new: &[u8]) -> Command {
    let mut data = Vec::with_capacity(old.len().saturating_add(new.len()));
    data.extend_from_slice(old);
    data.extend_from_slice(new);
    Command::no_response(
        0x00,
        INS_CHANGE_REFERENCE,
        0x00,
        if admin { 0x83 } else { 0x81 },
        data,
    )
}

/// Algorithm attributes of ECDSA secp256k1 (standard import format, no public key).
#[must_use]
pub fn secp256k1_attributes() -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + OID_SECP256K1.len());
    out.push(ALG_ECDSA);
    out.extend_from_slice(&OID_SECP256K1);
    out
}

/// PUT DATA of the algorithm attributes of `key` to ECDSA secp256k1.
#[must_use]
pub fn put_secp256k1_attributes(key: PgpKey) -> Command {
    Command::no_response(
        0x00,
        INS_PUT_DATA,
        0x00,
        key.attributes_do(),
        secp256k1_attributes(),
    )
}

/// PUT DATA of the touch policy of `key`.
#[must_use]
pub fn put_uif(key: PgpKey, policy: TouchPolicy) -> Command {
    Command::no_response(
        0x00,
        INS_PUT_DATA,
        0x00,
        key.uif_do(),
        vec![uif_byte(policy), 0x20],
    )
}

/// PUT DATA of raw algorithm attributes of `key` (the key slot is emptied when they change).
#[must_use]
pub fn put_attributes(key: PgpKey, attributes: &[u8]) -> Command {
    Command::no_response(
        0x00,
        INS_PUT_DATA,
        0x00,
        key.attributes_do(),
        attributes.to_vec(),
    )
}

/// TERMINATE DF (`00 E6 00 00`): accepted once PW3 is blocked; the applet then answers only
/// ACTIVATE FILE.
#[must_use]
pub fn terminate() -> Command {
    Command::no_response(0x00, INS_TERMINATE, 0x00, 0x00, Vec::new())
}

/// ACTIVATE FILE (`00 44 00 00`): after TERMINATE, the applet returns to its factory state.
#[must_use]
pub fn activate() -> Command {
    Command::no_response(0x00, INS_ACTIVATE, 0x00, 0x00, Vec::new())
}

/// The extended header list importing a 32-byte secp256k1 scalar into `key`
/// (`4D { CRT 00, 7F48 { 92 20 }, 5F48 scalar }`).
///
/// # Errors
///
/// [`CardError::TooLarge`] (never for 32 bytes).
pub fn import_data(key: PgpKey, scalar: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, CardError> {
    let mut inner = Zeroizing::new(Vec::with_capacity(48));
    inner.extend_from_slice(&[key.crt(), 0x00]);
    tlv::push(&mut inner, 0x7F48, &[0x92, 0x20])?;
    tlv::push(&mut inner, 0x5F48, scalar)?;
    let mut out = Zeroizing::new(Vec::with_capacity(52));
    tlv::push(&mut out, 0x4D, &inner)?;
    Ok(out)
}

/// PUT DATA (odd) importing `scalar` into `key`.
///
/// # Errors
///
/// As [`import_data`].
pub fn import_key(key: PgpKey, scalar: &[u8; 32]) -> Result<Command, CardError> {
    let data = import_data(key, scalar)?;
    Ok(Command::no_response(
        0x00,
        INS_PUT_DATA_ODD,
        0x3F,
        0xFF,
        data.to_vec(),
    ))
}

/// GENERATE ASYMMETRIC KEY PAIR, P1 `81`: read the existing public key of `key`.
#[must_use]
pub fn read_public_key(key: PgpKey) -> Command {
    Command::new(0x00, INS_GENERATE, 0x81, 0x00, vec![key.crt(), 0x00])
}

/// The signing command of `key` over a 32-byte digest (PSO:CDS for SIG, INTERNAL AUTHENTICATE
/// for AUT).
#[must_use]
pub fn sign(key: PgpKey, digest: &[u8; 32]) -> Command {
    match key {
        PgpKey::Sig => Command::new(0x00, INS_PSO, 0x9E, 0x9A, digest.to_vec()),
        PgpKey::Aut => Command::new(0x00, INS_INTERNAL_AUTHENTICATE, 0x00, 0x00, digest.to_vec()),
    }
}

// ---- parsers (pure) ----

/// The serial number in the AID (`D2 76 00 01 24 01 vv vv mm mm ss ss ss ss 00 00`). Yubico
/// writes the serial as BCD digits; a non-BCD value is read as plain big-endian (other vendors).
///
/// # Errors
///
/// [`CardError::Malformed`] for a short or foreign AID.
pub fn serial_from_aid(aid: &[u8]) -> Result<u32, CardError> {
    if aid.len() != 16 || aid.get(..6) != Some(&AID[..]) {
        return Err(CardError::Malformed);
    }
    let digits: &[u8; 4] = aid
        .get(10..14)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(CardError::Malformed)?;
    let bcd = digits.iter().all(|byte| byte >> 4 <= 9 && byte & 0x0F <= 9);
    if !bcd {
        return Ok(u32::from_be_bytes(*digits));
    }
    let mut value = 0_u32;
    for byte in digits {
        for nibble in [byte >> 4, byte & 0x0F] {
            value = value
                .checked_mul(10)
                .and_then(|value| value.checked_add(u32::from(nibble)))
                .ok_or(CardError::Malformed)?;
        }
    }
    Ok(value)
}

/// Parsed parts of the application related data (`6E`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppData {
    /// Full AID (16 bytes).
    pub aid: Vec<u8>,
    /// Card serial from the AID.
    pub serial: u32,
    /// OpenPGP spec version from the AID (`03 04` = 3.4).
    pub spec_version: (u8, u8),
    /// PW1 valid for one PSO:CDS only (`C4` byte 0 = `00`).
    pub pw1_single_use: bool,
    /// Remaining tries of PW1, reset code, PW3 (`C4` bytes 4..7).
    pub retries: [u8; 3],
    /// Algorithm attributes of SIG, DEC, AUT (`C1`, `C2`, `C3`).
    pub attributes: [Vec<u8>; 3],
}

fn find_nested(bytes: &[u8], tag: u16) -> Option<&[u8]> {
    for element in tlv::parse_all(bytes).ok()? {
        if element.tag == tag {
            return Some(element.value);
        }
        // Constructed tags that contain the DOs: 73 (discretionary data objects), 65, 7F74.
        if matches!(element.tag, 0x73 | 0x65 | 0x7F74)
            && let Some(found) = find_nested(element.value, tag)
        {
            return Some(found);
        }
    }
    None
}

/// Parses `GET DATA 6E`.
///
/// # Errors
///
/// [`CardError::Malformed`].
pub fn parse_app_data(response: &[u8]) -> Result<AppData, CardError> {
    let body = tlv::unwrap_single(response, 0x6E).or_else(|_| {
        // Some firmware returns the content without the outer 6E.
        tlv::parse_all(response).map(|_| response)
    })?;
    let aid = find_nested(body, 0x4F).ok_or(CardError::Malformed)?;
    let serial = serial_from_aid(aid)?;
    let spec_version = (
        *aid.get(6).ok_or(CardError::Malformed)?,
        *aid.get(7).ok_or(CardError::Malformed)?,
    );
    let status = find_nested(body, 0xC4).ok_or(CardError::Malformed)?;
    if status.len() < 7 {
        return Err(CardError::Malformed);
    }
    let attribute = |tag| {
        find_nested(body, tag)
            .map(<[u8]>::to_vec)
            .unwrap_or_default()
    };
    Ok(AppData {
        aid: aid.to_vec(),
        serial,
        spec_version,
        pw1_single_use: status.first() == Some(&0x00),
        retries: [
            *status.get(4).ok_or(CardError::Malformed)?,
            *status.get(5).ok_or(CardError::Malformed)?,
            *status.get(6).ok_or(CardError::Malformed)?,
        ],
        attributes: [attribute(0xC1), attribute(0xC2), attribute(0xC3)],
    })
}

/// Whether KDF-DO (`F9`) says PINs are hashed (`81 01 03`, iterated-salted S2K).
#[must_use]
pub fn kdf_enabled(response: &[u8]) -> bool {
    tlv::find(response, 0x81).is_ok_and(|value| value != [0x00])
}

/// The uncompressed point of a `7F49 { 86 point }` response, compressed.
///
/// # Errors
///
/// [`CardError::Malformed`] or [`CardError::KeyMismatch`] for a point not on secp256k1.
pub fn parse_public_key(response: &[u8]) -> Result<[u8; 33], CardError> {
    let inner = tlv::unwrap_single(response, 0x7F49)?;
    let point = tlv::find(inner, 0x86)?;
    if point.len() != 65 || point.first() != Some(&0x04) {
        return Err(CardError::Malformed);
    }
    PublicKey::from_slice(point)
        .map(|key| key.serialize())
        .map_err(|_| CardError::KeyMismatch)
}

/// What an `OpenPGP` key slot holds, as READ PUBLIC KEY (`00 47 81 00`) answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotKey {
    /// No key: `6A88`, or a template without a public key value.
    Empty,
    /// A secp256k1 key (compressed).
    Secp256k1([u8; 33]),
    /// Some other key: RSA, another curve, or a point that does not parse.
    Other,
}

/// Whether a `7F49` answer carries a key: an RSA modulus `81` or an EC point `86`, present
/// and non-empty.
fn holds_public_key(response: &[u8]) -> bool {
    tlv::unwrap_single(response, 0x7F49).is_ok_and(|inner| {
        [0x81_u16, 0x86]
            .into_iter()
            .any(|tag| tlv::find(inner, tag).is_ok_and(|value| !value.is_empty()))
    })
}

/// Classifies the answer (`sw`, data) of READ PUBLIC KEY.
///
/// # Errors
///
/// Every status word other than `9000` and `6A88` (empty slot).
pub fn parse_slot_key(sw: u16, response: &[u8]) -> Result<SlotKey, CardError> {
    match sw {
        super::apdu::SW_OK if holds_public_key(response) => {
            Ok(parse_public_key(response).map_or(SlotKey::Other, SlotKey::Secp256k1))
        }
        super::apdu::SW_OK | super::apdu::SW_REF_NOT_FOUND => Ok(SlotKey::Empty),
        other => Err(CardError::from_status(other)),
    }
}

/// Parses the 3-byte GET VERSION answer.
///
/// # Errors
///
/// [`CardError::Malformed`].
pub fn parse_version(response: &[u8]) -> Result<Firmware, CardError> {
    match response {
        [major, minor, patch] => Ok(Firmware::new(*major, *minor, *patch)),
        _ => Err(CardError::Malformed),
    }
}

// ---- flows over a transport ----

/// An OpenPGP session on a connected card (selected).
pub struct OpenPgp<'t> {
    transport: &'t mut dyn CardTransport,
    mode: ApduMode,
    /// Card facts read at selection.
    pub app: AppData,
    /// Firmware.
    pub firmware: Firmware,
}

impl core::fmt::Debug for OpenPgp<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OpenPgp")
            .field("serial", &self.app.serial)
            .field("firmware", &self.firmware)
            .finish_non_exhaustive()
    }
}

impl<'t> OpenPgp<'t> {
    /// SELECT, read the version, the application data and the KDF state.
    ///
    /// # Errors
    ///
    /// [`CardError::AppletMissing`], [`CardError::FirmwareTooOld`] (below
    /// [`super::MIN_FIRMWARE_OPENPGP`]), [`CardError::KdfEnabled`], transport and status errors.
    pub fn open(transport: &'t mut dyn CardTransport, mode: ApduMode) -> Result<Self, CardError> {
        let selected = exchange(transport, &select(), mode)?;
        if selected.sw != super::apdu::SW_OK {
            return Err(CardError::from_status(selected.sw));
        }
        let firmware = parse_version(&exchange_ok(transport, &get_version(), mode)?)?;
        if !firmware.at_least(super::MIN_FIRMWARE_OPENPGP) {
            return Err(CardError::FirmwareTooOld);
        }
        let app = parse_app_data(&exchange_ok(transport, &get_data(0x6E), mode)?)?;
        match exchange(transport, &get_data(0xF9), mode)? {
            response if response.sw == super::apdu::SW_OK && kdf_enabled(&response.data) => {
                return Err(CardError::KdfEnabled);
            }
            _ => {}
        }
        Ok(Self {
            transport,
            mode,
            app,
            firmware,
        })
    }

    fn run(&mut self, command: &Command) -> Result<Zeroizing<Vec<u8>>, CardError> {
        exchange_ok(self.transport, command, self.mode)
    }

    /// VERIFY a PIN.
    ///
    /// # Errors
    ///
    /// [`CardError::PinFormat`], [`CardError::WrongPin`] (also for `6982`, see
    /// [`OpenPgp::pin_refused`]), [`CardError::PinBlocked`].
    pub fn verify(&mut self, pw: Pw, pin: &[u8]) -> Result<(), CardError> {
        let range = if pw == Pw::Admin { PW3_LEN } else { PW1_LEN };
        if !range.contains(&pin.len()) {
            return Err(CardError::PinFormat);
        }
        let result = self.run(&verify(pw, pin)).map(drop);
        self.pin_refused(result, pw == Pw::Admin)
    }

    /// Changes PW1 or PW3.
    ///
    /// # Errors
    ///
    /// As [`OpenPgp::verify`].
    pub fn change_pin(&mut self, admin: bool, old: &[u8], new: &[u8]) -> Result<(), CardError> {
        let range = if admin { PW3_LEN } else { PW1_LEN };
        if !range.contains(&old.len()) || !range.contains(&new.len()) {
            return Err(CardError::PinFormat);
        }
        let result = self.run(&change_pin(admin, old, new)).map(drop);
        self.pin_refused(result, admin)
    }

    /// A `YubiKey`'s `OpenPGP` applet answers a wrong PIN with `6982` (security status not
    /// satisfied), not `63Cx` (spec/10 §9.1). After a refused VERIFY / CHANGE REFERENCE DATA the
    /// counters are read again (`6E`/`C4`, also into [`OpenPgp::app`]) and the refusal becomes
    /// [`CardError::WrongPin`] with the tries left of PW1 or PW3 (`0` = now blocked). When the
    /// counters cannot be read the original error stays.
    fn pin_refused(&mut self, result: Result<(), CardError>, admin: bool) -> Result<(), CardError> {
        match result {
            Err(error @ (CardError::SecurityStatus | CardError::WrongPin { .. })) => {
                let Ok(app) = exchange_ok(self.transport, &get_data(0x6E), self.mode)
                    .and_then(|response| parse_app_data(&response))
                else {
                    return Err(error);
                };
                let [pw1, _, pw3] = app.retries;
                self.app = app;
                Err(CardError::WrongPin {
                    retries: if admin { pw3 } else { pw1 },
                })
            }
            other => other,
        }
    }

    /// Imports a secp256k1 key into `key` (PW3 must be verified): attributes, key, touch policy,
    /// then reads the public key back and compares it with the one derived from `scalar`.
    ///
    /// # Errors
    ///
    /// [`CardError::KeyMismatch`] when the card's public key differs, status errors.
    pub fn import_secp256k1<C: Signing>(
        &mut self,
        ctx: &Secp256k1<C>,
        key: PgpKey,
        scalar: &[u8; 32],
        touch: TouchPolicy,
    ) -> Result<[u8; 33], CardError> {
        let mut secret = SecretKey::from_byte_array(*scalar).map_err(|_| CardError::Internal)?;
        let expected = PublicKey::from_secret_key(ctx, &secret).serialize();
        secret.non_secure_erase();
        // A fixed touch policy cannot be changed (spec/10 §1): re-enrolling a card whose slot
        // already has the wanted fixed policy skips the write; another fixed value is refused
        // before anything is written.
        let current = self.touch_policy(key).ok();
        let fixed = matches!(
            current,
            Some(TouchPolicy::AlwaysFixed | TouchPolicy::CachedFixed)
        );
        if fixed && current != Some(touch) {
            return Err(CardError::Conditions);
        }
        self.run(&put_secp256k1_attributes(key))?;
        self.run(&import_key(key, scalar)?)?;
        if current != Some(touch) {
            self.run(&put_uif(key, touch))?;
        }
        let read = self.public_key(key)?;
        if read != expected {
            return Err(CardError::KeyMismatch);
        }
        Ok(read)
    }

    /// Reads the public key of `key` (`00 47 81 00`).
    ///
    /// # Errors
    ///
    /// Status and parse errors.
    pub fn public_key(&mut self, key: PgpKey) -> Result<[u8; 33], CardError> {
        parse_public_key(&self.run(&read_public_key(key))?)
    }

    /// What `key` holds now (`00 47 81 00`, read-only): nothing, a secp256k1 key, or another
    /// key.
    ///
    /// # Errors
    ///
    /// Transport errors; status words other than `9000` / `6A88`.
    pub fn slot_key(&mut self, key: PgpKey) -> Result<SlotKey, CardError> {
        let response = exchange(self.transport, &read_public_key(key), self.mode)?;
        parse_slot_key(response.sw, &response.data)
    }

    /// The touch policy currently set for `key` (`GET DATA D6/D8`).
    ///
    /// # Errors
    ///
    /// Status and parse errors.
    pub fn touch_policy(&mut self, key: PgpKey) -> Result<TouchPolicy, CardError> {
        let data = self.run(&get_data(u16::from(key.uif_do())))?;
        touch_of_uif(*data.first().ok_or(CardError::Malformed)?).ok_or(CardError::Malformed)
    }

    /// Verifies PW1 for `key` and signs `digest`: raw `r ‖ s` (64 bytes) as the card returns it.
    ///
    /// # Errors
    ///
    /// PIN, touch (`6982`/`6985`) and status errors; [`CardError::Malformed`] for a wrong length.
    pub fn sign_digest(
        &mut self,
        key: PgpKey,
        pin: &[u8],
        digest: &[u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>, CardError> {
        self.verify(key.pw(), pin)?;
        let signature = self.run(&sign(key, digest))?;
        if signature.len() != 64 {
            return Err(CardError::Malformed);
        }
        Ok(signature)
    }

    /// Empties `key` the way yubikit's `delete_key` does on firmware 4+ (PW3 must be
    /// verified): OpenPGP card 3.4 has no DELETE command, but changing a slot's algorithm
    /// attributes removes its key — first to RSA 4096, then back to the factory RSA 2048. The
    /// touch policy (UIF) is not changed; a fixed one stays (only a reset clears it).
    ///
    /// # Errors
    ///
    /// [`CardError::KeyMismatch`] when the slot still answers with a public key afterwards,
    /// status errors.
    pub fn delete_key(&mut self, key: PgpKey) -> Result<(), CardError> {
        self.run(&put_attributes(key, &RSA4096_ATTRIBUTES))?;
        self.run(&put_attributes(key, &RSA2048_ATTRIBUTES))?;
        let response = exchange(self.transport, &read_public_key(key), self.mode)?;
        if response.sw == super::apdu::SW_OK && holds_public_key(&response.data) {
            Err(CardError::KeyMismatch)
        } else {
            Ok(())
        }
    }

    /// Factory reset of the `OpenPGP` applet (yubikit `reset`): VERIFY PW1 (`81`) and PW3
    /// (`83`) with a wrong value until each is blocked, then TERMINATE DF and ACTIVATE FILE.
    /// Every key, the touch policies (also fixed ones) and both PINs return to the factory
    /// state (PW1 `123456`, PW3 `12345678`). No PIN is needed — anyone holding the card can do
    /// this; it never touches PIV, FIDO, OTP or OATH.
    ///
    /// # Errors
    ///
    /// [`CardError::Conditions`] when a PIN did not block within the attempt bound, transport
    /// and status errors of TERMINATE / ACTIVATE.
    pub fn reset(mut self) -> Result<(), CardError> {
        for pw in [Pw::UserSign, Pw::Admin] {
            let mut blocked = false;
            for _ in 0..MAX_BLOCK_ATTEMPTS {
                match self.run(&verify(pw, &INVALID_PIN)) {
                    Err(CardError::PinBlocked | CardError::WrongPin { retries: 0 }) => {
                        blocked = true;
                        break;
                    }
                    Err(
                        error @ (CardError::Transport(_)
                        | CardError::CardRemoved
                        | CardError::Malformed
                        | CardError::TooLarge),
                    ) => return Err(error),
                    // Another wrong-PIN answer (or, impossibly, success): try again.
                    _ => {}
                }
            }
            if !blocked {
                return Err(CardError::Conditions);
            }
        }
        self.run(&terminate())?;
        self.run(&activate())?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, reason = "test assertions on fixed frames")]
mod tests {
    use super::*;

    #[test]
    fn builders_match_spec_bytes() {
        let frame = |command: &Command| {
            super::super::apdu::encode(command, ApduMode::Short).unwrap()[0].to_vec()
        };
        assert_eq!(
            frame(&select()),
            [
                0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x00
            ]
        );
        assert_eq!(
            frame(&put_secp256k1_attributes(PgpKey::Sig)),
            [
                0x00, 0xDA, 0x00, 0xC1, 0x06, 0x13, 0x2B, 0x81, 0x04, 0x00, 0x0A
            ]
        );
        assert_eq!(frame(&put_secp256k1_attributes(PgpKey::Aut))[3], 0xC3);
        assert_eq!(
            frame(&put_uif(PgpKey::Aut, TouchPolicy::CachedFixed)),
            [0x00, 0xDA, 0x00, 0xD8, 0x02, 0x04, 0x20]
        );
        assert_eq!(
            frame(&read_public_key(PgpKey::Aut)),
            [0x00, 0x47, 0x81, 0x00, 0x02, 0xA4, 0x00, 0x00]
        );
        assert_eq!(
            &frame(&sign(PgpKey::Sig, &[0; 32]))[..5],
            [0x00, 0x2A, 0x9E, 0x9A, 0x20]
        );
        assert_eq!(
            &frame(&sign(PgpKey::Aut, &[0; 32]))[..5],
            [0x00, 0x88, 0x00, 0x00, 0x20]
        );
        assert_eq!(frame(&verify(Pw::Admin, b"12345678"))[3], 0x83);
        let data = import_data(PgpKey::Sig, &[0x42; 32]).unwrap();
        let mut expected = vec![
            0x4D, 0x2A, 0xB6, 0x00, 0x7F, 0x48, 0x02, 0x92, 0x20, 0x5F, 0x48, 0x20,
        ];
        expected.extend_from_slice(&[0x42; 32]);
        assert_eq!(*data, expected);
    }

    #[test]
    fn aid_serial_is_bcd() {
        let mut aid = vec![0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0x00, 0x06];
        aid.extend_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x00, 0x00]);
        assert_eq!(serial_from_aid(&aid).unwrap(), 12_345_678);
        aid[10] = 0xAB;
        assert_eq!(serial_from_aid(&aid).unwrap(), 0xAB34_5678);
        assert!(serial_from_aid(&aid[..15]).is_err());
    }

    #[test]
    fn kdf_detection() {
        assert!(!kdf_enabled(&[0x81, 0x01, 0x00]));
        assert!(kdf_enabled(&[0x81, 0x01, 0x03, 0x82, 0x01, 0x08]));
        assert!(!kdf_enabled(&[]));
    }
}
