//! Extended key strings (spec/02 §3.4). Not a product feature (no xprv/xpub import or export):
//! this API exists so the BIP32 vectors 1–5 can be compared as full strings.
//!
//! Serialization: `version(4) ‖ depth(1) ‖ parent_fingerprint(4) ‖ child_number(4, BE) ‖
//! chain_code(32) ‖ key(33)` = 78 bytes, `Base58Check`.
#![deny(clippy::indexing_slicing)]

use core::fmt;

use ripemd::Ripemd160;
use secp256k1::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{Bip32Path, XPriv};
use crate::codec::base58;
use crate::entropy::{OsRandom, secp_context};
use crate::error::KeyError;
use crate::secret::SecretString;

const SERIALIZED_LEN: usize = 78;

/// Extended key version bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XKeyVersion {
    /// Mainnet private `0488ADE4`.
    Xprv,
    /// Mainnet public `0488B21E`.
    Xpub,
    /// Testnet private `04358394`.
    Tprv,
    /// Testnet public `043587CF`.
    Tpub,
}

impl XKeyVersion {
    const fn bytes(self) -> [u8; 4] {
        match self {
            Self::Xprv => [0x04, 0x88, 0xad, 0xe4],
            Self::Xpub => [0x04, 0x88, 0xb2, 0x1e],
            Self::Tprv => [0x04, 0x35, 0x83, 0x94],
            Self::Tpub => [0x04, 0x35, 0x87, 0xcf],
        }
    }

    fn from_bytes(bytes: [u8; 4]) -> Option<Self> {
        [Self::Xprv, Self::Xpub, Self::Tprv, Self::Tpub]
            .into_iter()
            .find(|version| version.bytes() == bytes)
    }

    const fn is_private(self) -> bool {
        matches!(self, Self::Xprv | Self::Tprv)
    }
}

/// Decoded extended key fields. Secret type: no `Clone`/`Display`, redacted `Debug`.
pub struct XKeyParts {
    /// Version bytes.
    pub version: XKeyVersion,
    /// Depth (0 for the master node).
    pub depth: u8,
    /// First 4 bytes of HASH160 of the parent's compressed public key (0 for the master).
    pub parent_fingerprint: [u8; 4],
    /// Child number (0 for the master).
    pub child_number: u32,
    /// Chain code.
    pub chain_code: [u8; 32],
    /// Private: `0x00 ‖ k`; public: the compressed public key.
    pub key: Zeroizing<[u8; 33]>,
}

impl fmt::Debug for XKeyParts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XKeyParts([REDACTED])")
    }
}

/// `RIPEMD160(SHA256(pubkey))[0..4]`.
#[must_use]
pub fn fingerprint(pubkey: &[u8; 33]) -> [u8; 4] {
    let hash = Ripemd160::digest(Sha256::digest(pubkey));
    let mut out = [0_u8; 4];
    for (slot, byte) in out.iter_mut().zip(hash.iter()) {
        *slot = *byte;
    }
    out
}

/// Derives `path` from `seed` (spec/02 §3.1) and returns the node in `version` form.
///
/// # Errors
///
/// [`KeyError::InvalidEntropyLength`] for a seed outside 16–64 bytes,
/// [`KeyError::DerivationFailed`] for an invalid node, or [`KeyError::RandomnessUnavailable`].
pub fn derive_xkey(
    seed: &[u8],
    path: &Bip32Path,
    version: XKeyVersion,
) -> Result<XKeyParts, KeyError> {
    let ctx = secp_context(&mut OsRandom)?;
    let master = XPriv::from_seed(seed)?;
    let (node, parent_fingerprint) = match path.components().split_last() {
        None => (master, [0_u8; 4]),
        Some((last, parents)) => {
            let parent =
                master.derive_path(&ctx, &Bip32Path::from_components(parents.to_vec())?)?;
            let parent_fingerprint = fingerprint(&parent.public_key(&ctx)?.serialize());
            (parent.derive_child(&ctx, *last)?, parent_fingerprint)
        }
    };
    let mut key = Zeroizing::new([0_u8; 33]);
    if version.is_private() {
        let (_, rest) = key.split_at_mut(1);
        rest.copy_from_slice(node.key_bytes());
    } else {
        *key = node.public_key(&ctx)?.serialize();
    }
    Ok(XKeyParts {
        version,
        depth: node.depth(),
        parent_fingerprint,
        child_number: node.child_number(),
        chain_code: *node.chain_code(),
        key,
    })
}

/// Serializes and Base58Check-encodes the extended key (a redacting [`SecretString`]: an
/// `xprv` is a private key).
#[must_use]
pub fn encode_xkey(parts: &XKeyParts) -> SecretString {
    let mut raw: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(SERIALIZED_LEN));
    raw.extend_from_slice(&parts.version.bytes());
    raw.push(parts.depth);
    raw.extend_from_slice(&parts.parent_fingerprint);
    raw.extend_from_slice(&parts.child_number.to_be_bytes());
    raw.extend_from_slice(&parts.chain_code);
    raw.extend_from_slice(parts.key.as_slice());
    let mut out = Zeroizing::new(String::with_capacity(base58::max_encoded_len(
        SERIALIZED_LEN + 4,
    )));
    base58::encode_check_into(&raw, &mut out);
    SecretString::from_zeroizing(out)
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], KeyError> {
    let (head, rest) = bytes
        .split_first_chunk::<N>()
        .ok_or(KeyError::InvalidExtendedKey)?;
    *bytes = rest;
    Ok(*head)
}

/// Decodes and validates an extended key string. Every failure is [`KeyError::InvalidExtendedKey`]:
/// checksum, length ≠ 78, unknown version, private key not `0x00 ‖ k` with k in [1, n−1], public
/// key prefix not 02/03 or off the curve, depth 0 with a non-zero parent fingerprint or index.
///
/// # Errors
///
/// [`KeyError::InvalidExtendedKey`].
pub fn decode_xkey(text: &str) -> Result<XKeyParts, KeyError> {
    let raw = base58::decode_check_secret(text).map_err(|_| KeyError::InvalidExtendedKey)?;
    if raw.len() != SERIALIZED_LEN {
        return Err(KeyError::InvalidExtendedKey);
    }
    let mut cursor: &[u8] = &raw;
    let version =
        XKeyVersion::from_bytes(take::<4>(&mut cursor)?).ok_or(KeyError::InvalidExtendedKey)?;
    let [depth] = take::<1>(&mut cursor)?;
    let parent_fingerprint = take::<4>(&mut cursor)?;
    let child_number = u32::from_be_bytes(take::<4>(&mut cursor)?);
    let chain_code = take::<32>(&mut cursor)?;
    let key = Zeroizing::new(take::<33>(&mut cursor)?);
    if depth == 0 && (parent_fingerprint != [0; 4] || child_number != 0) {
        return Err(KeyError::InvalidExtendedKey);
    }
    if version.is_private() {
        let (prefix, scalar) = key.split_first().ok_or(KeyError::InvalidExtendedKey)?;
        let mut scalar_bytes = Zeroizing::new([0_u8; 32]);
        scalar_bytes.copy_from_slice(scalar);
        if *prefix != 0 {
            return Err(KeyError::InvalidExtendedKey);
        }
        let mut secret =
            SecretKey::from_byte_array(*scalar_bytes).map_err(|_| KeyError::InvalidExtendedKey)?;
        secret.non_secure_erase();
    } else {
        PublicKey::from_byte_array_compressed(*key).map_err(|_| KeyError::InvalidExtendedKey)?;
    }
    Ok(XKeyParts {
        version,
        depth,
        parent_fingerprint,
        child_number,
        chain_code,
        key,
    })
}
