//! The device-key envelope `YWK2` of the Android files (spec/15 §5.2, spec/02 §5.5; 2026-11-25
//! A2-4b): a per-write envelope around the bytes of `vault.ywv`, `meta.ywm`, `journal.ywj` and
//! `apikeys.ks`, whose inner formats stay byte for byte as they are (spec/02 §4–§5).
//!
//! Each [`seal`] draws a fresh 32-byte file key and a 24-byte nonce from the OS CSPRNG, seals the
//! bytes with XChaCha20-Poly1305 under that key (AAD = the kind's string ‖ the whole header), and
//! has the platform's device key wrap only the file key ([`DeviceKey::wrap`]; Android: the
//! Keystore AES-256-GCM key `yw.device.v1`, AAD = the kind's string, the GCM IV made by the
//! Keystore). [`open`] needs the device key every time ([`DeviceKey::unwrap`]); the file key is
//! wiped right after either call and never kept between them.
//!
//! Layout (integers little-endian):
//!
//! | offset | length | field |
//! |---:|---:|---|
//! | 0 | 4 | `"YWK2"` |
//! | 4 | 1 | version, 1 |
//! | 5 | 1 | kind number ([`SealKind::number`]) |
//! | 6 | 2 | wrapped-key length, 60 |
//! | 8 | 60 | wrapped key: Keystore GCM `iv(12) ‖ ct(32) ‖ tag(16)` |
//! | 68 | 24 | XChaCha20-Poly1305 nonce |
//! | 92 | n + 16 | the sealed bytes `ct ‖ tag` |
//!
//! A header this build does not know (magic, version, kind, wrapped-key length) or a failed
//! `XChaCha` tag is [`EnvelopeError::Damaged`]: the file's own bytes are wrong. A device key that
//! cannot wrap or unwrap (missing, unusable, a refused GCM tag, no answer in time) is
//! [`EnvelopeError::Device`]: the file may be fine, so nothing may treat it as damaged.
//! Consequence (2026-11-25 A2-4b review, a recorded residual of spec/15 §5.2 and spec/02 §5.5):
//! damage inside the wrapped key (bytes 8–67) fails the Keystore's GCM tag, so it is a device
//! error, not damage — such a file is never quarantined and never falls back to its `.prev`
//! automatically.
#![deny(clippy::indexing_slicing)]
#![deny(clippy::arithmetic_side_effects)]

use core::fmt;

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, Tag, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::entropy::{OsRandom, RandomSource};

/// The magic of a `YWK2` envelope.
pub const MAGIC: [u8; 4] = *b"YWK2";
/// The only version this build writes and reads.
pub const VERSION: u8 = 1;
/// A wrapped file key: Keystore GCM `iv(12) ‖ ct(32) ‖ tag(16)`.
pub const WRAPPED_KEY_LEN: usize = 60;
/// The XChaCha20-Poly1305 nonce.
pub const NONCE_LEN: usize = 24;
/// The Poly1305 tag.
pub const TAG_LEN: usize = 16;
/// Everything before the sealed bytes: magic, version, kind, length, wrapped key, nonce.
pub const HEADER_LEN: usize = 4 + 1 + 1 + 2 + WRAPPED_KEY_LEN + NONCE_LEN;
/// What an envelope adds to the bytes it seals.
pub const OVERHEAD: usize = HEADER_LEN + TAG_LEN;

/// Offset of the wrapped key.
const WRAPPED_AT: usize = 8;
/// Offset of the nonce.
const NONCE_AT: usize = WRAPPED_AT + WRAPPED_KEY_LEN;

/// What an envelope holds; its number is in the header and its string is the AAD of both layers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealKind {
    /// `vault.ywv`.
    Vault,
    /// `meta.ywm`.
    Meta,
    /// `journal.ywj`.
    Journal,
    /// `apikeys.ks` (spec/15 §5.1).
    ApiKeys,
}

impl SealKind {
    /// Every kind.
    pub const ALL: [Self; 4] = [Self::Vault, Self::Meta, Self::Journal, Self::ApiKeys];

    /// The header's kind number.
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::Vault => 1,
            Self::Meta => 2,
            Self::Journal => 3,
            Self::ApiKeys => 4,
        }
    }

    /// The kind's string (ASCII), the first part of both AADs.
    #[must_use]
    pub const fn aad(self) -> &'static [u8] {
        match self {
            Self::Vault => b"vault",
            Self::Meta => b"meta",
            Self::Journal => b"journal",
            Self::ApiKeys => b"apikeys",
        }
    }
}

/// Why an envelope could not be made or opened. No bytes, no key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The bytes are no `YWK2` envelope of this kind or their tag fails: the file is damaged.
    Damaged,
    /// The device key could not wrap or unwrap (the platform's code): not a damaged file.
    Device(u32),
    /// The OS CSPRNG failed (fail closed).
    Random,
    /// The bytes do not fit an envelope.
    TooLarge,
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Damaged => formatter.write_str("envelope damaged"),
            Self::Device(code) => write!(formatter, "device key error {code}"),
            Self::Random => formatter.write_str("randomness unavailable"),
            Self::TooLarge => formatter.write_str("envelope too large"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// The platform's device key, which only ever sees a 32-byte file key.
pub trait DeviceKey {
    /// Wraps `file_key` for `kind`.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::Device`] (never `Damaged`).
    fn wrap(
        &self,
        kind: SealKind,
        file_key: &[u8; 32],
    ) -> Result<[u8; WRAPPED_KEY_LEN], EnvelopeError>;

    /// Unwraps a file key wrapped for `kind`.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::Device`] (never `Damaged`: a refused tag may be a lost key).
    fn unwrap(
        &self,
        kind: SealKind,
        wrapped: &[u8; WRAPPED_KEY_LEN],
    ) -> Result<Zeroizing<[u8; 32]>, EnvelopeError>;
}

/// The header of a new envelope.
fn header(
    kind: SealKind,
    wrapped: &[u8; WRAPPED_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
) -> [u8; HEADER_LEN] {
    let mut out = [0_u8; HEADER_LEN];
    let (magic, rest) = out.split_at_mut(4);
    magic.copy_from_slice(&MAGIC);
    let (fixed, rest) = rest.split_at_mut(4);
    fixed.copy_from_slice(&[VERSION, kind.number(), 60, 0]);
    let (key, nonce_out) = rest.split_at_mut(WRAPPED_KEY_LEN);
    key.copy_from_slice(wrapped);
    nonce_out.copy_from_slice(nonce);
    out
}

/// The `XChaCha` AAD: the kind's string ‖ the header.
fn payload_aad(kind: SealKind, header: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(kind.aad().len().saturating_add(header.len()));
    aad.extend_from_slice(kind.aad());
    aad.extend_from_slice(header);
    aad
}

/// Seals `plain` as a `kind` envelope with a fresh file key and nonce.
///
/// # Errors
///
/// [`EnvelopeError::Random`], [`EnvelopeError::TooLarge`] or the device key's error.
pub fn seal(
    kind: SealKind,
    plain: &[u8],
    device: &dyn DeviceKey,
) -> Result<Vec<u8>, EnvelopeError> {
    seal_with(&mut OsRandom, kind, plain, device)
}

pub(crate) fn seal_with(
    rng: &mut impl RandomSource,
    kind: SealKind,
    plain: &[u8],
    device: &dyn DeviceKey,
) -> Result<Vec<u8>, EnvelopeError> {
    let total = plain
        .len()
        .checked_add(OVERHEAD)
        .ok_or(EnvelopeError::TooLarge)?;
    let mut file_key = Zeroizing::new([0_u8; 32]);
    rng.fill(file_key.as_mut())
        .map_err(|_| EnvelopeError::Random)?;
    let mut nonce = [0_u8; NONCE_LEN];
    rng.fill(&mut nonce).map_err(|_| EnvelopeError::Random)?;
    let wrapped = device.wrap(kind, &file_key)?;
    let head = header(kind, &wrapped, &nonce);
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&head);
    out.extend_from_slice(plain);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(file_key.as_ref()));
    let tag = {
        let body = out.get_mut(HEADER_LEN..).ok_or(EnvelopeError::TooLarge)?;
        cipher
            .encrypt_in_place_detached(XNonce::from_slice(&nonce), &payload_aad(kind, &head), body)
            .map_err(|_| EnvelopeError::TooLarge)?
    };
    out.extend_from_slice(tag.as_slice());
    Ok(out)
}

/// The parts of an envelope whose header this build knows.
struct Parts<'a> {
    header: &'a [u8],
    wrapped: [u8; WRAPPED_KEY_LEN],
    nonce: [u8; NONCE_LEN],
    body: &'a [u8],
    tag: [u8; TAG_LEN],
}

fn parts(kind: SealKind, bytes: &[u8]) -> Result<Parts<'_>, EnvelopeError> {
    if bytes.len() < OVERHEAD {
        return Err(EnvelopeError::Damaged);
    }
    let (header, rest) = bytes.split_at(HEADER_LEN);
    let fixed = header.get(..WRAPPED_AT).ok_or(EnvelopeError::Damaged)?;
    let length = u16::try_from(WRAPPED_KEY_LEN).map_err(|_| EnvelopeError::Damaged)?;
    let [m0, m1, m2, m3, version, number, len_lo, len_hi] = fixed else {
        return Err(EnvelopeError::Damaged);
    };
    if [*m0, *m1, *m2, *m3] != MAGIC
        || *version != VERSION
        || *number != kind.number()
        || u16::from_le_bytes([*len_lo, *len_hi]) != length
    {
        return Err(EnvelopeError::Damaged);
    }
    let wrapped = header
        .get(WRAPPED_AT..NONCE_AT)
        .and_then(|slice| <[u8; WRAPPED_KEY_LEN]>::try_from(slice).ok())
        .ok_or(EnvelopeError::Damaged)?;
    let nonce = header
        .get(NONCE_AT..HEADER_LEN)
        .and_then(|slice| <[u8; NONCE_LEN]>::try_from(slice).ok())
        .ok_or(EnvelopeError::Damaged)?;
    let body_len = rest
        .len()
        .checked_sub(TAG_LEN)
        .ok_or(EnvelopeError::Damaged)?;
    let (body, tag) = rest.split_at(body_len);
    let tag = <[u8; TAG_LEN]>::try_from(tag).map_err(|_| EnvelopeError::Damaged)?;
    Ok(Parts {
        header,
        wrapped,
        nonce,
        body,
        tag,
    })
}

/// Opens a `kind` envelope: the bytes it sealed, wiped on drop.
///
/// # Errors
///
/// [`EnvelopeError::Damaged`] for an unknown header (magic, version, another kind, length) or a
/// failed tag; the device key's error when it cannot unwrap (checked after the header, before the
/// payload).
pub fn open(
    kind: SealKind,
    bytes: &[u8],
    device: &dyn DeviceKey,
) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
    let parts = parts(kind, bytes)?;
    let file_key = device.unwrap(kind, &parts.wrapped)?;
    let mut plain = Zeroizing::new(parts.body.to_vec());
    let cipher = XChaCha20Poly1305::new(Key::from_slice(file_key.as_ref()));
    cipher
        .decrypt_in_place_detached(
            XNonce::from_slice(&parts.nonce),
            &payload_aad(kind, parts.header),
            plain.as_mut_slice(),
            Tag::from_slice(&parts.tag),
        )
        .map_err(|_| EnvelopeError::Damaged)?;
    Ok(plain)
}

/// Whether `bytes` start like an envelope of `kind` (magic, version, kind number; no key used).
#[must_use]
pub fn looks_sealed(kind: SealKind, bytes: &[u8]) -> bool {
    parts(kind, bytes).is_ok()
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test vectors index fixed offsets"
)]
mod tests {
    use core::cell::{Cell, RefCell};

    use zeroize::Zeroizing;

    use super::{
        DeviceKey, EnvelopeError, HEADER_LEN, MAGIC, OVERHEAD, SealKind, WRAPPED_KEY_LEN, open,
        seal, seal_with,
    };
    use crate::entropy::RandomSource;
    use crate::error::KeyError;

    /// A stand-in device key: "wraps" by XOR with a fixed pad and a kind byte, and like the
    /// Keystore's GCM it refuses (`Device(`[`CRYPTO_FAILED`]`)`) any wrapped key it did not make
    /// for that kind, so a flipped byte of the wrapped key is a device error, not damage
    /// (2026-11-25 A2-4b review: before, it unwrapped any bytes and the flip read as damage);
    /// `refuse` fails every call.
    struct FakeDevice {
        refuse: Cell<Option<u32>>,
        wraps: Cell<u32>,
        unwraps: Cell<u32>,
        made: RefCell<Vec<(SealKind, [u8; WRAPPED_KEY_LEN])>>,
    }

    /// Java's status `CRYPTO_FAILED` (spec/15 §3.2), the GCM tag's refusal.
    const CRYPTO_FAILED: u32 = 3;

    impl FakeDevice {
        fn new() -> Self {
            Self {
                refuse: Cell::new(None),
                wraps: Cell::new(0),
                unwraps: Cell::new(0),
                made: RefCell::new(Vec::new()),
            }
        }
    }

    const PAD: u8 = 0x5a;

    impl DeviceKey for FakeDevice {
        fn wrap(
            &self,
            kind: SealKind,
            file_key: &[u8; 32],
        ) -> Result<[u8; WRAPPED_KEY_LEN], EnvelopeError> {
            self.wraps.set(self.wraps.get() + 1);
            if let Some(code) = self.refuse.get() {
                return Err(EnvelopeError::Device(code));
            }
            let mut out = [0x11_u8; WRAPPED_KEY_LEN];
            for (at, byte) in file_key.iter().enumerate() {
                out[12 + at] = byte ^ PAD ^ kind.number();
            }
            self.made.borrow_mut().push((kind, out));
            Ok(out)
        }

        fn unwrap(
            &self,
            kind: SealKind,
            wrapped: &[u8; WRAPPED_KEY_LEN],
        ) -> Result<Zeroizing<[u8; 32]>, EnvelopeError> {
            self.unwraps.set(self.unwraps.get() + 1);
            if let Some(code) = self.refuse.get() {
                return Err(EnvelopeError::Device(code));
            }
            if !self.made.borrow().contains(&(kind, *wrapped)) {
                return Err(EnvelopeError::Device(CRYPTO_FAILED));
            }
            let mut key = Zeroizing::new([0_u8; 32]);
            for (at, byte) in key.iter_mut().enumerate() {
                *byte = wrapped[12 + at] ^ PAD ^ kind.number();
            }
            Ok(key)
        }
    }

    /// Counting bytes 0, 1, 2, … (file key first, then nonce).
    struct Counting(u8);

    impl RandomSource for Counting {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), KeyError> {
            for byte in out {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    struct Broken;

    impl RandomSource for Broken {
        fn fill(&mut self, _out: &mut [u8]) -> Result<(), KeyError> {
            Err(KeyError::RandomnessUnavailable)
        }
    }

    #[test]
    fn kinds_are_numbered_and_named() {
        let numbers: Vec<u8> = SealKind::ALL.iter().map(|kind| kind.number()).collect();
        assert_eq!(numbers, [1, 2, 3, 4]);
        let names: Vec<&[u8]> = SealKind::ALL.iter().map(|kind| kind.aad()).collect();
        assert_eq!(
            names,
            [
                &b"vault"[..],
                &b"meta"[..],
                &b"journal"[..],
                &b"apikeys"[..]
            ]
        );
        assert_eq!(HEADER_LEN, 92);
        assert_eq!(OVERHEAD, 108);
    }

    /// The sealed bytes `ct ‖ tag` of [`vector`] (2026-11-25: also computed independently
    /// with Node's `chacha20-poly1305` after a hand-written `HChaCha20`).
    const VECTOR: &str = "642e4c214f75473637a98cb97ae6862d15f5";

    /// The spec/02 §5.5 vector: file key 00..1f, nonce 20..37, the fake device above, kind meta,
    /// bytes "yw". Pins the header layout, both AADs and the `XChaCha` output.
    #[test]
    fn vector() {
        let device = FakeDevice::new();
        let sealed = seal_with(&mut Counting(0), SealKind::Meta, b"yw", &device).unwrap();
        assert_eq!(sealed.len(), OVERHEAD + 2);
        assert_eq!(&sealed[..8], b"YWK2\x01\x02\x3c\x00");
        assert_eq!(&sealed[8..20], &[0x11; 12]);
        assert_eq!(sealed[20], 0x5a ^ 2);
        assert_eq!(
            crate::hex::encode(&sealed[68..92]),
            "202122232425262728292a2b2c2d2e2f3031323334353637"
        );
        assert_eq!(crate::hex::encode(&sealed[HEADER_LEN..]), VECTOR);
        assert_eq!(
            open(SealKind::Meta, &sealed, &device).unwrap().as_slice(),
            b"yw"
        );
    }

    #[test]
    fn round_trip_for_every_kind_and_size() {
        let device = FakeDevice::new();
        for kind in SealKind::ALL {
            for size in [0_usize, 1, 31, 4096, 65_536] {
                let plain: Vec<u8> = (0..size)
                    .map(|at| u8::try_from(at % 251).unwrap())
                    .collect();
                let sealed = seal(kind, &plain, &device).unwrap();
                assert_eq!(sealed.len(), plain.len() + OVERHEAD);
                assert_eq!(&sealed[..4], &MAGIC);
                assert!(super::looks_sealed(kind, &sealed));
                if size > 16 {
                    assert!(
                        !sealed.windows(16).any(|window| window == &plain[..16]),
                        "no plain run in the envelope"
                    );
                }
                assert_eq!(open(kind, &sealed, &device).unwrap().as_slice(), &plain[..]);
            }
        }
        // Two seals of the same bytes differ (fresh key and nonce each write).
        let first = seal(SealKind::Vault, b"same", &device).unwrap();
        let second = seal(SealKind::Vault, b"same", &device).unwrap();
        assert_ne!(first, second);
    }

    /// Every one-byte change: of the header fields, the nonce, the sealed bytes or the tag it is
    /// damage; of the wrapped key (bytes 8..68) it is the device key's refusal, as with the real
    /// Keystore GCM (2026-11-25 A2-4b review; spec/02 §5.5 residual).
    #[test]
    fn header_and_payload_changes_are_damage_wrapped_key_changes_are_device_errors() {
        let device = FakeDevice::new();
        let sealed = seal(SealKind::Journal, b"journal bytes", &device).unwrap();
        // Another kind with the same bytes: the header's kind number refuses it.
        assert_eq!(
            open(SealKind::Meta, &sealed, &device).map(|_| ()),
            Err(EnvelopeError::Damaged)
        );
        assert!(!super::looks_sealed(SealKind::Meta, &sealed));
        for at in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[at] ^= 0x01;
            let result = open(SealKind::Journal, &bad, &device).map(|_| ());
            let want = if (8..8 + WRAPPED_KEY_LEN).contains(&at) {
                EnvelopeError::Device(CRYPTO_FAILED)
            } else {
                EnvelopeError::Damaged
            };
            assert_eq!(result, Err(want), "byte {at}");
        }
        for len in [0, 1, 4, OVERHEAD - 1] {
            assert_eq!(
                open(SealKind::Journal, &sealed[..len], &device).map(|_| ()),
                Err(EnvelopeError::Damaged)
            );
        }
        let mut longer = sealed.clone();
        longer.push(0);
        assert_eq!(
            open(SealKind::Journal, &longer, &device).map(|_| ()),
            Err(EnvelopeError::Damaged)
        );
        // A plain inner file is never accepted.
        let mut plain = b"YWMETA03".to_vec();
        plain.resize(200, 0);
        assert_eq!(
            open(SealKind::Meta, &plain, &device).map(|_| ()),
            Err(EnvelopeError::Damaged)
        );
    }

    #[test]
    fn device_errors_are_not_damage_and_header_comes_first() {
        let device = FakeDevice::new();
        let sealed = seal(SealKind::Vault, b"vault bytes", &device).unwrap();
        device.refuse.set(Some(7));
        assert_eq!(
            open(SealKind::Vault, &sealed, &device).map(|_| ()),
            Err(EnvelopeError::Device(7))
        );
        assert_eq!(
            seal(SealKind::Vault, b"x", &device).map(|_| ()),
            Err(EnvelopeError::Device(7))
        );
        // A damaged header is refused before the device key is asked.
        let before = device.unwraps.get();
        let mut bad = sealed;
        bad[0] = b'Z';
        assert_eq!(
            open(SealKind::Vault, &bad, &device).map(|_| ()),
            Err(EnvelopeError::Damaged)
        );
        assert_eq!(device.unwraps.get(), before);
    }

    #[test]
    fn no_randomness_no_envelope() {
        let device = FakeDevice::new();
        assert_eq!(
            seal_with(&mut Broken, SealKind::Vault, b"x", &device).map(|_| ()),
            Err(EnvelopeError::Random)
        );
        assert_eq!(device.wraps.get(), 0);
    }
}
