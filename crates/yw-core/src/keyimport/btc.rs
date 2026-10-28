//! Script types of imported Bitcoin keys and their addresses (spec/02 §8.4, spec/08 §3.5).
//!
//! The output script is computed from the public key alone: P2PKH `HASH160(pubkey)` (33- or
//! 65-byte key), P2SH-P2WPKH `HASH160(00 14 ‖ HASH160(pubkey33))`, P2WPKH `HASH160(pubkey33)`,
//! P2TR the BIP86 key-path output key `x(P + H_TapTweak(x(P))·G)`. Address strings use the
//! shared encoder (`btc::address::encode_address`).
#![deny(clippy::indexing_slicing)]

use secp256k1::{PublicKey, Scalar, Secp256k1, Verification};
use sha2::{Digest, Sha256};

use crate::btc::address::{ScriptKind, encode_address, hash160};
use crate::btc::network::BtcNetwork;
use crate::error::KeyError;

/// The address type of an imported Bitcoin key (vault byte, spec/02 §4.6 tag 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BtcScriptType {
    /// Legacy `1…`/`m…`/`n…` (the only type of an uncompressed key). Byte 1.
    P2pkh = 1,
    /// Nested segwit `3…`/`2…` (BIP49 layout). Byte 2.
    P2shP2wpkh = 2,
    /// Native segwit v0 `bc1q…`/`tb1q…` (BIP84 layout). Byte 3.
    P2wpkh = 3,
    /// Taproot key path `bc1p…`/`tb1p…` (BIP86 tweak, no script tree). Byte 4.
    P2tr = 4,
}

impl BtcScriptType {
    /// Every type in byte order.
    pub const ALL: [Self; 4] = [Self::P2pkh, Self::P2shP2wpkh, Self::P2wpkh, Self::P2tr];

    /// The vault byte.
    #[must_use]
    pub const fn id(self) -> u8 {
        self as u8
    }

    /// Inverse of [`BtcScriptType::id`].
    #[must_use]
    pub const fn from_id(id: u8) -> Option<Self> {
        match id {
            1 => Some(Self::P2pkh),
            2 => Some(Self::P2shP2wpkh),
            3 => Some(Self::P2wpkh),
            4 => Some(Self::P2tr),
            _ => None,
        }
    }

    /// The meta name (`btc_raw_accounts[].script`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::P2pkh => "p2pkh",
            Self::P2shP2wpkh => "p2sh-p2wpkh",
            Self::P2wpkh => "p2wpkh",
            Self::P2tr => "p2tr",
        }
    }

    /// Inverse of [`BtcScriptType::name`].
    #[must_use]
    pub fn parse_name(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.name() == text)
    }

    /// The label shown to the user.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::P2pkh => "P2PKH (레거시, 1…)",
            Self::P2shP2wpkh => "P2SH-P2WPKH (중첩 세그윗, 3…)",
            Self::P2wpkh => "P2WPKH (네이티브 세그윗, bc1q…)",
            Self::P2tr => "P2TR (Taproot, bc1p…)",
        }
    }

    /// Whether a key used uncompressed may have this type (P2PKH only: segwit and taproot
    /// require compressed or x-only keys).
    #[must_use]
    pub const fn allows_uncompressed(self) -> bool {
        matches!(self, Self::P2pkh)
    }
}

/// `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ msg)` (BIP340 tagged hash).
fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut engine = Sha256::new();
    engine.update(tag_hash);
    engine.update(tag_hash);
    engine.update(msg);
    engine.finalize().into()
}

/// The BIP86 output key of an internal public key (x-only, 32 bytes).
///
/// # Errors
///
/// [`KeyError::DerivationFailed`] when the tweak is out of range or the sum is the point at
/// infinity (probability ≈ 2^-128).
pub fn taproot_output_key<C: Verification>(
    ctx: &Secp256k1<C>,
    public: &PublicKey,
) -> Result<[u8; 32], KeyError> {
    let (internal, _parity) = public.x_only_public_key();
    let tweak = Scalar::from_be_bytes(tagged_hash(b"TapTweak", &internal.serialize()))
        .map_err(|_| KeyError::DerivationFailed)?;
    let (output, _parity) = internal
        .add_tweak(ctx, &tweak)
        .map_err(|_| KeyError::DerivationFailed)?;
    Ok(output.serialize())
}

/// The output script kind of `public` used as `script` (compressed or not).
///
/// # Errors
///
/// [`KeyError::WifUncompressedScript`] for an uncompressed key with a type other than P2PKH,
/// [`KeyError::DerivationFailed`] for the (negligible) taproot tweak failure.
pub fn script_kind<C: Verification>(
    ctx: &Secp256k1<C>,
    public: &PublicKey,
    compressed: bool,
    script: BtcScriptType,
) -> Result<ScriptKind, KeyError> {
    if !compressed && !script.allows_uncompressed() {
        return Err(KeyError::WifUncompressedScript);
    }
    let compressed_key = public.serialize();
    Ok(match script {
        BtcScriptType::P2pkh if compressed => ScriptKind::P2pkh(hash160(&compressed_key)),
        BtcScriptType::P2pkh => ScriptKind::P2pkh(hash160(&public.serialize_uncompressed())),
        BtcScriptType::P2shP2wpkh => {
            let mut redeem = [0_u8; 22];
            let (prefix, program) = redeem.split_at_mut(2);
            prefix.copy_from_slice(&[0x00, 0x14]);
            program.copy_from_slice(&hash160(&compressed_key));
            ScriptKind::P2sh(hash160(&redeem))
        }
        BtcScriptType::P2wpkh => ScriptKind::P2wpkh(hash160(&compressed_key)),
        BtcScriptType::P2tr => ScriptKind::P2tr(taproot_output_key(ctx, public)?),
    })
}

/// The address of `public` used as `script` on `network`.
///
/// # Errors
///
/// As [`script_kind`].
pub fn address<C: Verification>(
    ctx: &Secp256k1<C>,
    public: &PublicKey,
    compressed: bool,
    script: BtcScriptType,
    network: BtcNetwork,
) -> Result<String, KeyError> {
    Ok(encode_address(
        &script_kind(ctx, public, compressed, script)?,
        network,
    ))
}
