//! APDU-level emulator of the YubiKey OpenPGP and PIV applets (spec/10 §12.1), for tests only:
//! nothing outside `cfg(test)` code constructs it (yw-app's `MockSource` is `cfg(test)`). It is
//! compiled in every build because the dependency check forbids dev-dependencies, so another
//! crate's tests cannot turn on a feature for it. It implements exactly the commands this wallet
//! sends, with real secp256k1 ECDSA and Ed25519 signing, PIN counters, single-use PW1 for
//! PSO:CDS, PIV management-key mutual authentication (through a [`MgmtCipher`]), command
//! chaining and `61xx` GET RESPONSE for short APDUs. It never touches hardware.
//!
//! Every received command header is logged in [`MockCard::log`] so tests can assert that a
//! signing flow sends no write/import/reset instruction.
#![allow(
    clippy::missing_panics_doc,
    reason = "test emulator; it never panics on card input"
)]

use ed25519_dalek::Signer;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use zeroize::Zeroizing;

use super::piv::{MgmtAlgorithm, MgmtCipher};
use super::{CardError, CardTransport, Firmware, apdu::decode_frame, tlv};

/// Instructions that change card state (never sent by a signing flow).
pub const WRITE_INS: [u8; 7] = [0xDA, 0xDB, 0xFE, 0xFF, 0x24, 0x2C, 0xE6];

/// A reversible toy block cipher for the emulator and tests (byte-wise add / subtract of the
/// key). It is **not** AES or 3DES: those come from Windows CNG in yw-win and are checked
/// against FIPS-197 / SP 800-67 vectors there.
#[derive(Clone, Copy, Debug, Default)]
pub struct ToyCipher;

impl MgmtCipher for ToyCipher {
    fn encrypt_block(
        &self,
        algorithm: MgmtAlgorithm,
        key: &[u8],
        block: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CardError> {
        if block.len() != algorithm.block_len() || key.len() != algorithm.key_len() {
            return Err(CardError::Internal);
        }
        Ok(Zeroizing::new(
            block
                .iter()
                .zip(key.iter().cycle())
                .map(|(byte, k)| byte.wrapping_add(*k).rotate_left(3))
                .collect(),
        ))
    }

    fn decrypt_block(
        &self,
        algorithm: MgmtAlgorithm,
        key: &[u8],
        block: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CardError> {
        if block.len() != algorithm.block_len() || key.len() != algorithm.key_len() {
            return Err(CardError::Internal);
        }
        Ok(Zeroizing::new(
            block
                .iter()
                .zip(key.iter().cycle())
                .map(|(byte, k)| byte.rotate_right(3).wrapping_sub(*k))
                .collect(),
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Applet {
    None,
    OpenPgp,
    Piv,
}

/// One PIV key slot of the emulator.
#[derive(Clone, Debug)]
pub struct PivKey {
    /// Ed25519 seed.
    pub seed: [u8; 32],
    /// PIN policy byte.
    pub pin_policy: u8,
    /// Touch policy byte.
    pub touch_policy: u8,
}

/// The emulated YubiKey.
#[derive(Debug)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent emulator switches and PIN states"
)]
pub struct MockCard {
    /// Serial.
    pub serial: u32,
    /// Firmware.
    pub firmware: Firmware,
    /// OpenPGP applet present.
    pub has_openpgp: bool,
    /// PIV applet present.
    pub has_piv: bool,
    /// OpenPGP KDF-DO active.
    pub kdf: bool,
    /// Return high-s signatures (as a real card does half the time).
    pub high_s: bool,
    /// Return only high-R signatures (`r ≥ 2^255`, DER 71 bytes after low-s): a real card picks
    /// its own nonce and gives one about half the time (spec/10 §6.3).
    pub high_r: bool,
    /// The user does not touch (signing answers `6982`).
    pub refuse_touch: bool,
    /// Return a corrupted signature.
    pub corrupt_signature: bool,
    /// Refuse Ed25519 PIV import (`6A80`), as a 5.7.0–5.7.3 card might.
    pub refuse_ed25519_import: bool,
    /// Every command header received, in order.
    pub log: Vec<[u8; 4]>,
    /// Touches requested.
    pub touches: u32,
    /// OpenPGP PW1.
    pub pw1: Vec<u8>,
    /// OpenPGP PW3.
    pub pw3: Vec<u8>,
    /// Retries PW1 / PW3.
    pub pgp_retries: [u8; 2],
    /// OpenPGP keys SIG, DEC, AUT.
    pub pgp_keys: [Option<[u8; 32]>; 3],
    /// Algorithm attributes SIG, DEC, AUT.
    pub pgp_attributes: [Vec<u8>; 3],
    /// UIF SIG, DEC, AUT.
    pub pgp_uif: [u8; 3],
    /// PIV PIN.
    pub piv_pin: Vec<u8>,
    /// PIV PIN retries.
    pub piv_retries: u8,
    /// PIV PUK.
    pub piv_puk: Vec<u8>,
    /// Management key algorithm.
    pub mgmt_algorithm: MgmtAlgorithm,
    /// Management key.
    pub mgmt_key: Vec<u8>,
    /// PIV slots (id, key).
    pub piv_keys: Vec<(u8, PivKey)>,
    /// PIV data objects (3-byte id, content of `53`): ADMIN DATA, PRINTED. PRINTED is readable
    /// only after VERIFY PIN; PUT DATA needs the management key.
    pub piv_objects: Vec<(u32, Vec<u8>)>,
    applet: Applet,
    pw1_sign: bool,
    pw1_other: bool,
    pw3_ok: bool,
    piv_pin_ok: bool,
    mgmt_ok: bool,
    witness: Option<Vec<u8>>,
    witness_counter: u8,
    chain: Vec<u8>,
    pending: Vec<u8>,
}

const RSA2048_ATTRIBUTES: [u8; 6] = [0x01, 0x08, 0x00, 0x00, 0x20, 0x00];

fn sw(code: u16) -> Vec<u8> {
    code.to_be_bytes().to_vec()
}

fn ok(mut data: Vec<u8>) -> Vec<u8> {
    data.extend_from_slice(&[0x90, 0x00]);
    data
}

impl MockCard {
    /// A factory-fresh YubiKey 5 (firmware 5.7.4) with default PINs and management key.
    #[must_use]
    pub fn new(serial: u32) -> Self {
        Self {
            serial,
            firmware: Firmware::new(5, 7, 4),
            has_openpgp: true,
            has_piv: true,
            kdf: false,
            high_s: false,
            high_r: false,
            refuse_touch: false,
            corrupt_signature: false,
            refuse_ed25519_import: false,
            log: Vec::new(),
            touches: 0,
            pw1: super::openpgp::DEFAULT_PW1.to_vec(),
            pw3: super::openpgp::DEFAULT_PW3.to_vec(),
            pgp_retries: [3, 3],
            pgp_keys: [None, None, None],
            pgp_attributes: [
                RSA2048_ATTRIBUTES.to_vec(),
                RSA2048_ATTRIBUTES.to_vec(),
                RSA2048_ATTRIBUTES.to_vec(),
            ],
            pgp_uif: [0, 0, 0],
            piv_pin: super::piv::DEFAULT_PIN.to_vec(),
            piv_retries: 3,
            piv_puk: super::piv::DEFAULT_PUK.to_vec(),
            mgmt_algorithm: MgmtAlgorithm::Aes192,
            mgmt_key: super::piv::DEFAULT_MANAGEMENT_KEY.to_vec(),
            piv_keys: Vec::new(),
            piv_objects: Vec::new(),
            applet: Applet::None,
            pw1_sign: false,
            pw1_other: false,
            pw3_ok: false,
            piv_pin_ok: false,
            mgmt_ok: false,
            witness: None,
            witness_counter: 0,
            chain: Vec::new(),
            pending: Vec::new(),
        }
    }

    /// The card as `ykman piv access change-management-key --generate --protect` leaves it: an
    /// AES-192 management `key`, ADMIN DATA `80 { 81 02 }`, PRINTED `88 { 89 key }`.
    pub fn protect_management(&mut self, key: [u8; 24]) {
        self.mgmt_algorithm = MgmtAlgorithm::Aes192;
        self.mgmt_key = key.to_vec();
        self.piv_objects.retain(|(id, _)| {
            *id != super::piv::OBJECT_ADMIN_DATA && *id != super::piv::OBJECT_PRINTED
        });
        self.piv_objects.push((
            super::piv::OBJECT_ADMIN_DATA,
            vec![0x80, 0x03, 0x81, 0x01, 0x02],
        ));
        let mut printed = vec![0x88, 0x1A, 0x89, 0x18];
        printed.extend_from_slice(&key);
        self.piv_objects.push((super::piv::OBJECT_PRINTED, printed));
    }

    /// The content of PIV data object `id`.
    #[must_use]
    pub fn piv_object(&self, id: u32) -> Option<&[u8]> {
        self.piv_objects
            .iter()
            .find(|(other, _)| *other == id)
            .map(|(_, content)| content.as_slice())
    }

    fn object_id(data: &[u8]) -> Option<(u32, &[u8])> {
        match data {
            [0x5C, 0x03, high, middle, low, rest @ ..] => {
                Some((u32::from_be_bytes([0, *high, *middle, *low]), rest))
            }
            _ => None,
        }
    }

    fn piv_get_data(&self, data: &[u8]) -> Vec<u8> {
        let Some((id, [])) = Self::object_id(data) else {
            return sw(0x6A80);
        };
        if id == super::piv::OBJECT_PRINTED && !self.piv_pin_ok {
            return sw(0x6982);
        }
        match self.piv_object(id) {
            Some(content) => ok(tlv::encode(0x53, content).unwrap_or_default()),
            None => sw(0x6A82),
        }
    }

    fn piv_put_data(&mut self, data: &[u8]) -> Vec<u8> {
        if !self.mgmt_ok {
            return sw(0x6982);
        }
        let Some((id, rest)) = Self::object_id(data) else {
            return sw(0x6A80);
        };
        let Ok(content) = tlv::unwrap_single(rest, 0x53) else {
            return sw(0x6A80);
        };
        let content = content.to_vec();
        self.piv_objects.retain(|(other, _)| *other != id);
        if !content.is_empty() {
            self.piv_objects.push((id, content));
        }
        ok(Vec::new())
    }

    /// Whether any logged command is a write instruction (or GENERATE with P1 `80`).
    #[must_use]
    pub fn saw_write(&self) -> bool {
        self.log
            .iter()
            .any(|[_, ins, p1, _]| WRITE_INS.contains(ins) || (*ins == 0x47 && *p1 == 0x80))
    }

    fn bcd_serial(&self) -> [u8; 4] {
        let mut digits = [0_u8; 8];
        let mut value = self.serial;
        for slot in digits.iter_mut().rev() {
            *slot = u8::try_from(value % 10).unwrap_or(0);
            value /= 10;
        }
        let mut out = [0_u8; 4];
        for (position, byte) in out.iter_mut().enumerate() {
            let high = digits.get(position * 2).copied().unwrap_or(0);
            let low = digits.get(position * 2 + 1).copied().unwrap_or(0);
            *byte = (high << 4) | low;
        }
        out
    }

    fn deselect(&mut self) {
        self.pw1_sign = false;
        self.pw1_other = false;
        self.pw3_ok = false;
        self.piv_pin_ok = false;
        self.mgmt_ok = false;
        self.witness = None;
    }

    fn handle(&mut self, header: [u8; 4], data: &[u8]) -> Vec<u8> {
        let [_, ins, p1, p2] = header;
        if ins == 0xA4 && p1 == 0x04 {
            self.deselect();
            if data == super::openpgp::AID && self.has_openpgp {
                self.applet = Applet::OpenPgp;
                return ok(Vec::new());
            }
            if data == super::piv::AID && self.has_piv {
                self.applet = Applet::Piv;
                return ok(Vec::new());
            }
            self.applet = Applet::None;
            return sw(0x6A82);
        }
        match self.applet {
            Applet::OpenPgp => self.openpgp(ins, p1, p2, data),
            Applet::Piv => self.piv(ins, p1, p2, data),
            Applet::None => sw(0x6D00),
        }
    }

    // ---- OpenPGP ----

    fn app_data(&self) -> Vec<u8> {
        let mut aid = vec![0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0x00, 0x06];
        aid.extend_from_slice(&self.bcd_serial());
        aid.extend_from_slice(&[0x00, 0x00]);
        let mut discretionary = Vec::new();
        let _ = tlv::push(
            &mut discretionary,
            0xC0,
            &[0x7D, 0, 0, 0xFF, 0x04, 0xC0, 0, 0xFF, 0, 0],
        );
        for (tag, attributes) in [0xC1_u16, 0xC2, 0xC3].iter().zip(&self.pgp_attributes) {
            let _ = tlv::push(&mut discretionary, *tag, attributes);
        }
        let status = [
            0x00,
            0x7F,
            0x7F,
            0x7F,
            self.pgp_retries[0],
            0x00,
            self.pgp_retries[1],
        ];
        let _ = tlv::push(&mut discretionary, 0xC4, &status);
        let _ = tlv::push(&mut discretionary, 0xC5, &[0; 60]);
        let mut body = Vec::new();
        let _ = tlv::push(&mut body, 0x4F, &aid);
        let _ = tlv::push(
            &mut body,
            0x5F52,
            &[0x00, 0x73, 0x00, 0x00, 0xE0, 0x05, 0x90, 0x00],
        );
        let _ = tlv::push(&mut body, 0x73, &discretionary);
        tlv::encode(0x6E, &body).unwrap_or_default()
    }

    fn key_index(crt: u8) -> Option<usize> {
        match crt {
            0xB6 => Some(0),
            0xB8 => Some(1),
            0xA4 => Some(2),
            _ => None,
        }
    }

    fn verify_pgp(&mut self, p2: u8, data: &[u8]) -> Vec<u8> {
        let (secret, retries) = match p2 {
            0x81 | 0x82 => (self.pw1.clone(), 0),
            0x83 => (self.pw3.clone(), 1),
            _ => return sw(0x6A86),
        };
        let left = self.pgp_retries[retries];
        if data.is_empty() {
            let verified = match p2 {
                0x81 => self.pw1_sign,
                0x82 => self.pw1_other,
                _ => self.pw3_ok,
            };
            return if verified {
                ok(Vec::new())
            } else {
                sw(0x63C0 | u16::from(left))
            };
        }
        if left == 0 {
            return sw(0x6983);
        }
        if data != secret.as_slice() {
            self.pgp_retries[retries] = left.saturating_sub(1);
            return sw(0x63C0 | u16::from(left.saturating_sub(1)));
        }
        self.pgp_retries[retries] = 3;
        match p2 {
            0x81 => self.pw1_sign = true,
            0x82 => self.pw1_other = true,
            _ => self.pw3_ok = true,
        }
        ok(Vec::new())
    }

    fn pgp_public(&self, index: usize) -> Option<Vec<u8>> {
        let scalar = self.pgp_keys.get(index).copied().flatten()?;
        let secret = SecretKey::from_byte_array(scalar).ok()?;
        let point = PublicKey::from_secret_key(&Secp256k1::new(), &secret).serialize_uncompressed();
        let inner = tlv::encode(0x86, &point).ok()?;
        tlv::encode(0x7F49, &inner).ok()
    }

    fn import_pgp(&mut self, data: &[u8]) -> Vec<u8> {
        if !self.pw3_ok {
            return sw(0x6982);
        }
        let Ok(inner) = tlv::unwrap_single(data, 0x4D) else {
            return sw(0x6A80);
        };
        let (Some(crt), Some(0)) = (inner.first().copied(), inner.get(1).copied()) else {
            return sw(0x6A80);
        };
        let Some(index) = Self::key_index(crt) else {
            return sw(0x6A80);
        };
        let rest = inner.get(2..).unwrap_or_default();
        let (Ok(template), Ok(values)) = (tlv::find(rest, 0x7F48), tlv::find(rest, 0x5F48)) else {
            return sw(0x6A80);
        };
        let expected_attributes = super::openpgp::secp256k1_attributes();
        if self.pgp_attributes.get(index) != Some(&expected_attributes)
            || template != [0x92, 0x20]
            || values.len() != 32
        {
            return sw(0x6A80);
        }
        let mut scalar = [0_u8; 32];
        scalar.copy_from_slice(values);
        if SecretKey::from_byte_array(scalar).is_err() {
            return sw(0x6A80);
        }
        if let Some(slot) = self.pgp_keys.get_mut(index) {
            *slot = Some(scalar);
        }
        ok(Vec::new())
    }

    fn pgp_sign(&mut self, index: usize, data: &[u8]) -> Vec<u8> {
        let authorised = if index == 0 {
            self.pw1_sign
        } else {
            self.pw1_other
        };
        if !authorised {
            return sw(0x6982);
        }
        if index == 0 {
            self.pw1_sign = false; // PW1 valid for one PSO:CDS (C4 byte 0 = 00)
        }
        if self.pgp_uif.get(index).is_some_and(|uif| *uif != 0) {
            self.touches = self.touches.saturating_add(1);
            if self.refuse_touch {
                return sw(0x6982);
            }
        }
        let Some(scalar) = self.pgp_keys.get(index).copied().flatten() else {
            return sw(0x6A88);
        };
        let Ok(digest) = <[u8; 32]>::try_from(data) else {
            return sw(0x6700);
        };
        let Ok(secret) = SecretKey::from_byte_array(scalar) else {
            return sw(0x6F00);
        };
        let ctx = Secp256k1::new();
        let message = Message::from_digest(digest);
        let mut signature = ctx.sign_ecdsa(message, &secret).serialize_compact();
        let mut counter = 0_u32;
        while self.high_r && signature.first().is_some_and(|r| r & 0x80 == 0) && counter < 1_024 {
            counter = counter.saturating_add(1);
            let mut extra = [0_u8; 32];
            for (slot, byte) in extra.iter_mut().zip(counter.to_be_bytes()) {
                *slot = byte;
            }
            signature = ctx
                .sign_ecdsa_with_noncedata(message, &secret, &extra)
                .serialize_compact();
        }
        let mut out = signature.to_vec();
        if self.high_s {
            let mut s = [0_u8; 32];
            s.copy_from_slice(out.get(32..).unwrap_or(&[0; 32]));
            if let Ok(value) = SecretKey::from_byte_array(s) {
                out.truncate(32);
                out.extend_from_slice(&value.negate().secret_bytes());
            }
        }
        if self.corrupt_signature
            && let Some(byte) = out.get_mut(5)
        {
            *byte ^= 1;
        }
        ok(out)
    }

    fn openpgp(&mut self, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
        match (ins, p1, p2) {
            (0xF1, 0, 0) => ok(vec![
                self.firmware.major,
                self.firmware.minor,
                self.firmware.patch,
            ]),
            (0xCA, 0x00, 0x6E) => ok(self.app_data()),
            (0xCA, 0x00, 0xF9) => ok(if self.kdf {
                vec![0x81, 0x01, 0x03, 0x82, 0x01, 0x08]
            } else {
                vec![0x81, 0x01, 0x00]
            }),
            (0xCA, 0x00, tag @ 0xD6..=0xD8) => {
                ok(vec![self.pgp_uif[usize::from(tag - 0xD6)], 0x20])
            }
            (0x20, 0x00, _) => self.verify_pgp(p2, data),
            (0x24, 0x00, 0x81 | 0x83) => {
                let admin = p2 == 0x83;
                let current = if admin {
                    self.pw3.clone()
                } else {
                    self.pw1.clone()
                };
                if !data.starts_with(&current) {
                    return sw(0x63C2);
                }
                let new = data.get(current.len()..).unwrap_or_default().to_vec();
                if admin {
                    self.pw3 = new;
                } else {
                    self.pw1 = new;
                }
                ok(Vec::new())
            }
            (0xDA, 0x00, tag @ (0xC1..=0xC3)) => {
                if !self.pw3_ok {
                    return sw(0x6982);
                }
                let known = data == super::openpgp::secp256k1_attributes().as_slice()
                    || data == RSA2048_ATTRIBUTES;
                if !known {
                    return sw(0x6A80);
                }
                let index = usize::from(tag - 0xC1);
                self.pgp_attributes[index] = data.to_vec();
                self.pgp_keys[index] = None; // changing attributes deletes the key
                ok(Vec::new())
            }
            (0xDA, 0x00, tag @ (0xD6..=0xD8)) => {
                if !self.pw3_ok {
                    return sw(0x6982);
                }
                let index = usize::from(tag - 0xD6);
                let current = self.pgp_uif[index];
                if matches!(current, 0x02 | 0x04) {
                    return sw(0x6982); // fixed
                }
                match data {
                    [uif @ 0..=4, 0x20] => {
                        self.pgp_uif[index] = *uif;
                        ok(Vec::new())
                    }
                    _ => sw(0x6A80),
                }
            }
            (0xDB, 0x3F, 0xFF) => self.import_pgp(data),
            (0x47, 0x81, 0x00) => {
                let index = data.first().copied().and_then(Self::key_index);
                match index.and_then(|index| self.pgp_public(index)) {
                    Some(public) => ok(public),
                    None => sw(0x6A88),
                }
            }
            (0x2A, 0x9E, 0x9A) => self.pgp_sign(0, data),
            (0x88, 0x00, 0x00) => self.pgp_sign(2, data),
            _ => sw(0x6D00),
        }
    }

    // ---- PIV ----

    fn piv_key(&self, slot: u8) -> Option<&PivKey> {
        self.piv_keys
            .iter()
            .find(|(id, _)| *id == slot)
            .map(|(_, key)| key)
    }

    fn piv_metadata(&self, slot: u8) -> Vec<u8> {
        let mut out = Vec::new();
        match slot {
            0x9B => {
                let _ = tlv::push(&mut out, 0x01, &[self.mgmt_algorithm.code()]);
                let _ = tlv::push(&mut out, 0x02, &[0x00, 0x01]);
                let default = self.mgmt_key == super::piv::DEFAULT_MANAGEMENT_KEY;
                let _ = tlv::push(&mut out, 0x05, &[u8::from(default)]);
                ok(out)
            }
            0x80 => {
                let _ = tlv::push(&mut out, 0x01, &[0xFF]);
                let _ = tlv::push(&mut out, 0x02, &[0x00, 0x00]);
                let default = self.piv_pin == super::piv::DEFAULT_PIN;
                let _ = tlv::push(&mut out, 0x05, &[u8::from(default)]);
                let _ = tlv::push(&mut out, 0x06, &[3, self.piv_retries]);
                ok(out)
            }
            _ => match self.piv_key(slot) {
                None => sw(0x6A88),
                Some(key) => {
                    let public = ed25519_dalek::SigningKey::from_bytes(&key.seed)
                        .verifying_key()
                        .to_bytes();
                    let _ = tlv::push(&mut out, 0x01, &[super::piv::ALG_ED25519]);
                    let _ = tlv::push(&mut out, 0x02, &[key.pin_policy, key.touch_policy]);
                    let _ = tlv::push(&mut out, 0x03, &[0x02]);
                    let encoded = tlv::encode(0x86, &public).unwrap_or_default();
                    let _ = tlv::push(&mut out, 0x04, &encoded);
                    ok(out)
                }
            },
        }
    }

    fn piv_authenticate(&mut self, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
        let Ok(inner) = tlv::unwrap_single(data, 0x7C) else {
            return sw(0x6A80);
        };
        if p2 == 0x9B {
            if p1 != self.mgmt_algorithm.code() {
                return sw(0x6A86);
            }
            let block = self.mgmt_algorithm.block_len();
            if inner == [0x80, 0x00] {
                self.witness_counter = self.witness_counter.wrapping_add(1);
                let witness: Vec<u8> = (0..block)
                    .map(|i| u8::try_from(i).unwrap_or(0).wrapping_mul(7) ^ self.witness_counter)
                    .collect();
                let Ok(encrypted) =
                    ToyCipher.encrypt_block(self.mgmt_algorithm, &self.mgmt_key, &witness)
                else {
                    return sw(0x6F00);
                };
                self.witness = Some(witness);
                let mut out = Vec::new();
                let _ = tlv::push(&mut out, 0x80, &encrypted);
                return ok(tlv::encode(0x7C, &out).unwrap_or_default());
            }
            let (Ok(decrypted), Ok(challenge)) = (tlv::find(inner, 0x80), tlv::find(inner, 0x81))
            else {
                return sw(0x6A80);
            };
            let expected = self.witness.take();
            if expected.as_deref() != Some(decrypted) || challenge.len() != block {
                return sw(0x6982);
            }
            let Ok(proof) = ToyCipher.encrypt_block(self.mgmt_algorithm, &self.mgmt_key, challenge)
            else {
                return sw(0x6F00);
            };
            self.mgmt_ok = true;
            let mut out = Vec::new();
            let _ = tlv::push(&mut out, 0x82, &proof);
            return ok(tlv::encode(0x7C, &out).unwrap_or_default());
        }
        // Signing.
        if p1 != super::piv::ALG_ED25519 {
            return sw(0x6A86);
        }
        let Some(key) = self.piv_key(p2).cloned() else {
            return sw(0x6A88);
        };
        let (Ok(empty), Ok(message)) = (tlv::find(inner, 0x82), tlv::find(inner, 0x81)) else {
            return sw(0x6A80);
        };
        if !empty.is_empty() {
            return sw(0x6A80);
        }
        if key.pin_policy != 0x01 && !self.piv_pin_ok {
            return sw(0x6982);
        }
        if key.pin_policy == 0x03 {
            self.piv_pin_ok = false; // PIN always: one operation per VERIFY
        }
        if key.touch_policy != 0x01 {
            self.touches = self.touches.saturating_add(1);
            if self.refuse_touch {
                return sw(0x6982);
            }
        }
        let mut signature = ed25519_dalek::SigningKey::from_bytes(&key.seed)
            .sign(message)
            .to_bytes()
            .to_vec();
        if self.corrupt_signature
            && let Some(byte) = signature.get_mut(3)
        {
            *byte ^= 1;
        }
        let mut out = Vec::new();
        let _ = tlv::push(&mut out, 0x82, &signature);
        ok(tlv::encode(0x7C, &out).unwrap_or_default())
    }

    /// CHANGE REFERENCE DATA of the PIN (`80`) or the PUK (`81`): `old(8, FF) ‖ new(8, FF)`.
    fn piv_change_reference(&mut self, puk: bool, data: &[u8]) -> Vec<u8> {
        let mut padded = if puk {
            self.piv_puk.clone()
        } else {
            self.piv_pin.clone()
        };
        padded.resize(8, 0xFF);
        if data.get(..8) != Some(padded.as_slice()) {
            return sw(0x63C2);
        }
        let new: Vec<u8> = data
            .get(8..)
            .unwrap_or_default()
            .iter()
            .copied()
            .take_while(|byte| *byte != 0xFF)
            .collect();
        if puk {
            self.piv_puk = new;
        } else {
            self.piv_pin = new;
        }
        ok(Vec::new())
    }

    fn piv(&mut self, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
        match ins {
            0xFD => ok(vec![
                self.firmware.major,
                self.firmware.minor,
                self.firmware.patch,
            ]),
            0xF8 => ok(self.serial.to_be_bytes().to_vec()),
            0xF7 => self.piv_metadata(p2),
            0x20 if p2 == 0x80 => {
                if self.piv_retries == 0 {
                    return sw(0x6983);
                }
                let mut padded = self.piv_pin.clone();
                padded.resize(8, 0xFF);
                if data != padded.as_slice() {
                    self.piv_retries = self.piv_retries.saturating_sub(1);
                    return sw(0x63C0 | u16::from(self.piv_retries));
                }
                self.piv_retries = 3;
                self.piv_pin_ok = true;
                ok(Vec::new())
            }
            0x24 if matches!(p2, 0x80 | 0x81) => self.piv_change_reference(p2 == 0x81, data),
            0xCB if p1 == 0x3F && p2 == 0xFF => self.piv_get_data(data),
            0xDB if p1 == 0x3F && p2 == 0xFF => self.piv_put_data(data),
            0x87 => self.piv_authenticate(p1, p2, data),
            0xFE => {
                if !self.mgmt_ok {
                    return sw(0x6982);
                }
                if p1 != super::piv::ALG_ED25519 || super::plan::PivSlot::new(p2).is_err() {
                    return sw(0x6A86);
                }
                if self.refuse_ed25519_import {
                    return sw(0x6A80);
                }
                let (Ok(seed), Ok(pin), Ok(touch)) = (
                    tlv::find(data, 0x07),
                    tlv::find(data, 0xAA),
                    tlv::find(data, 0xAB),
                ) else {
                    return sw(0x6A80);
                };
                let (Ok(seed), [pin], [touch]) = (<[u8; 32]>::try_from(seed), pin, touch) else {
                    return sw(0x6A80);
                };
                self.piv_keys.retain(|(id, _)| *id != p2);
                self.piv_keys.push((
                    p2,
                    PivKey {
                        seed,
                        pin_policy: *pin,
                        touch_policy: *touch,
                    },
                ));
                ok(Vec::new())
            }
            0xFF if p1 == 0xFF && matches!(p2, 0xFE | 0xFF) => {
                if !self.mgmt_ok {
                    return sw(0x6982);
                }
                match data {
                    [algorithm, 0x9B, len, key @ ..] if usize::from(*len) == key.len() => {
                        let Some(algorithm) = MgmtAlgorithm::from_code(*algorithm) else {
                            return sw(0x6A80);
                        };
                        self.mgmt_algorithm = algorithm;
                        self.mgmt_key = key.to_vec();
                        ok(Vec::new())
                    }
                    _ => sw(0x6A80),
                }
            }
            _ => sw(0x6D00),
        }
    }
}

impl CardTransport for MockCard {
    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, CardError> {
        let Some((header, data, _expect)) = decode_frame(command) else {
            return Ok(sw(0x6700));
        };
        let [cla, ins, p1, p2] = header;
        if ins == 0xC0 && cla == 0x00 {
            // GET RESPONSE.
            let chunk: Vec<u8> = self.pending.drain(..self.pending.len().min(256)).collect();
            let mut out = chunk;
            if self.pending.is_empty() {
                out.extend_from_slice(&[0x90, 0x00]);
            } else {
                out.extend_from_slice(&[0x61, u8::try_from(self.pending.len()).unwrap_or(0)]);
            }
            return Ok(out);
        }
        self.log.push([cla & !0x10, ins, p1, p2]);
        if cla & 0x10 != 0 {
            self.chain.extend_from_slice(&data);
            return Ok(sw(0x9000));
        }
        let mut full = core::mem::take(&mut self.chain);
        full.extend_from_slice(&data);
        let response = self.handle([cla, ins, p1, p2], &full);
        // Short APDU (≤ 255 data, 1-byte Le): answers above 256 bytes go through 61xx.
        let short = command.get(4).is_some_and(|byte| *byte != 0) || command.len() == 5;
        let body_len = response.len().saturating_sub(2);
        if short && body_len > 256 {
            let (body, status) = response.split_at(body_len);
            if status == [0x90, 0x00] {
                self.pending = body.get(256..).unwrap_or_default().to_vec();
                let mut out = body.get(..256).unwrap_or_default().to_vec();
                out.extend_from_slice(&[0x61, u8::try_from(self.pending.len()).unwrap_or(0)]);
                return Ok(out);
            }
        }
        Ok(response)
    }
}
