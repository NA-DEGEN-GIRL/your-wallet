//! Typed envelopes and key agreement (`clients/core/crypto/crypto-envelopes.md`,
//! `crypto-keys.md`; reference `packages/utils/src/crypto.ts`).
//!
//! - Type 0: `0x00 ‖ iv(12) ‖ ChaCha20-Poly1305(ct ‖ tag16)`, base64 with padding.
//! - Type 1: `0x01 ‖ senderPublicKey(32) ‖ iv(12) ‖ sealbox`: the receiver derives the key from
//!   its own X25519 private key and `senderPublicKey`.
//! - Session key: `HKDF-SHA256(ikm = X25519(priv, peerPub), salt = none, info = empty, L = 32)`;
//!   a topic is `sha256(symKey)` (hex on the wire).

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use curve25519_dalek::montgomery::MontgomeryPoint;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::error::KeyError;

/// Key and topic length.
pub const KEY_LEN: usize = 32;
const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// Largest decoded envelope accepted (relay messages are far smaller).
pub const MAX_ENVELOPE_BYTES: usize = 2 * 1_048_576;

/// An X25519 private key (wiped on drop).
pub struct X25519Secret([u8; 32]);

impl core::fmt::Debug for X25519Secret {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("X25519Secret([REDACTED])")
    }
}

impl Drop for X25519Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Clone for X25519Secret {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl X25519Secret {
    /// From stored bytes (clamped at use, as X25519 specifies).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// A fresh key from the OS CSPRNG.
    ///
    /// # Errors
    ///
    /// [`KeyError::RandomnessUnavailable`].
    pub fn generate() -> Result<Self, KeyError> {
        let mut bytes = [0_u8; 32];
        crate::entropy::fill_random(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// The stored bytes (for the encrypted session store only).
    #[must_use]
    pub const fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    /// The public key `X25519(k, 9)`.
    #[must_use]
    pub fn public(&self) -> [u8; 32] {
        MontgomeryPoint::mul_base_clamped(self.0).to_bytes()
    }

    /// The raw shared secret `X25519(k, peer)`; `None` for an all-zero result (a low-order peer
    /// point, which would make the key public).
    #[must_use]
    pub fn shared(&self, peer_public: &[u8; 32]) -> Option<Zeroizing<[u8; 32]>> {
        let shared = Zeroizing::new(MontgomeryPoint(*peer_public).mul_clamped(self.0).to_bytes());
        if shared.iter().all(|byte| *byte == 0) {
            None
        } else {
            Some(shared)
        }
    }
}

/// The session symmetric key: `HKDF-SHA256(X25519(secret, peer))` (no salt, empty info, 32 bytes;
/// `deriveSymKey`). `None` for a low-order peer key.
#[must_use]
pub fn derive_sym_key(
    secret: &X25519Secret,
    peer_public: &[u8; 32],
) -> Option<Zeroizing<[u8; 32]>> {
    let shared = secret.shared(peer_public)?;
    let hkdf = Hkdf::<Sha256>::new(None, shared.as_ref());
    let mut out = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&[], out.as_mut()).ok()?;
    Some(out)
}

/// `sha256(symKey)` (`hashKey`): the topic of a symmetric key.
#[must_use]
pub fn topic_of(sym_key: &[u8; 32]) -> [u8; 32] {
    crate::codec::sha256(sym_key)
}

/// A decoded envelope.
#[derive(Clone, PartialEq, Eq)]
pub enum Envelope {
    /// Type 0: both peers hold the symmetric key.
    Type0 {
        /// Nonce.
        iv: [u8; 12],
        /// Ciphertext ‖ tag.
        sealed: Vec<u8>,
    },
    /// Type 1: the receiver derives the key from `sender_public`.
    Type1 {
        /// The sender's X25519 public key.
        sender_public: [u8; 32],
        /// Nonce.
        iv: [u8; 12],
        /// Ciphertext ‖ tag.
        sealed: Vec<u8>,
    },
}

impl core::fmt::Debug for Envelope {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Type0 { .. } => "Envelope::Type0",
            Self::Type1 { .. } => "Envelope::Type1",
        })
    }
}

impl Envelope {
    /// Decodes the base64 wire form (type 0 or 1; type 2 — unencrypted link-mode — is refused).
    #[must_use]
    pub fn decode(text: &str) -> Option<Self> {
        if text.len() > MAX_ENVELOPE_BYTES.div_ceil(3) * 4 {
            return None;
        }
        let bytes = crate::codec::base64::decode(text)?;
        let (&kind, rest) = bytes.split_first()?;
        let take_iv = |slice: &[u8]| -> Option<([u8; 12], Vec<u8>)> {
            let iv = <[u8; IV_LEN]>::try_from(slice.get(..IV_LEN)?).ok()?;
            let sealed = slice.get(IV_LEN..)?.to_vec();
            (sealed.len() >= TAG_LEN).then_some((iv, sealed))
        };
        match kind {
            0 => {
                let (iv, sealed) = take_iv(rest)?;
                Some(Self::Type0 { iv, sealed })
            }
            1 => {
                let sender_public = <[u8; 32]>::try_from(rest.get(..32)?).ok()?;
                let (iv, sealed) = take_iv(rest.get(32..)?)?;
                Some(Self::Type1 {
                    sender_public,
                    iv,
                    sealed,
                })
            }
            _ => None,
        }
    }

    /// The type byte.
    #[must_use]
    pub const fn kind(&self) -> u8 {
        match self {
            Self::Type0 { .. } => 0,
            Self::Type1 { .. } => 1,
        }
    }
}

/// Seals `plaintext` (the JSON-RPC text) under `sym_key` with nonce `iv`: type 0, or type 1 when
/// `sender_public` is given. Returns the base64 wire form.
#[must_use]
pub fn seal_envelope(
    sym_key: &[u8; 32],
    iv: &[u8; 12],
    plaintext: &[u8],
    sender_public: Option<&[u8; 32]>,
) -> Option<String> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(sym_key));
    let sealed = cipher.encrypt(Nonce::from_slice(iv), plaintext).ok()?;
    let mut out = Vec::with_capacity(1 + 32 + IV_LEN + sealed.len());
    match sender_public {
        Some(public) => {
            out.push(1);
            out.extend_from_slice(public);
        }
        None => out.push(0),
    }
    out.extend_from_slice(iv);
    out.extend_from_slice(&sealed);
    Some(crate::codec::base64::encode(&out))
}

/// Opens an envelope with `sym_key` (for type 1, the key the caller derived from
/// `sender_public`). `None` when authentication fails.
#[must_use]
pub fn open_envelope(sym_key: &[u8; 32], envelope: &Envelope) -> Option<Vec<u8>> {
    let (iv, sealed) = match envelope {
        Envelope::Type0 { iv, sealed } | Envelope::Type1 { iv, sealed, .. } => (iv, sealed),
    };
    let cipher = ChaCha20Poly1305::new(Key::from_slice(sym_key));
    cipher
        .decrypt(Nonce::from_slice(iv), sealed.as_slice())
        .ok()
}
