//! Taproot key-path spending (BIP340/341/86, spec/08 §6.6b): tagged hashes, the `TapTweak` of an
//! internal key (BIP86 accounts use the empty script tree: `merkle_root = None`), the BIP341
//! `SIGHASH_DEFAULT` signature message of a key-path input (no annex, no script path), and the
//! 64-byte Schnorr signature with its strict check.
//!
//! The signature message commits to the amounts and scriptPubKeys of **every** input, so the
//! caller passes the hash-verified previous outputs of all inputs (spec/08 §5): an amount lie
//! about any input changes every input's sighash.
#![deny(clippy::indexing_slicing)]

use core::fmt;

use secp256k1::schnorr::Signature;
use secp256k1::{All, Keypair, Scalar, Secp256k1, SecretKey, Verification, XOnlyPublicKey};
use sha2::{Digest, Sha256};

use super::amount::Sats;
use super::tx::{Transaction, write_compact_size};
use crate::error::KeyError;

/// Length of a key-path signature with `SIGHASH_DEFAULT` (no sighash byte).
pub const SCHNORR_SIG_LEN: usize = 64;
/// `SIGHASH_DEFAULT` (BIP341): the only Taproot hash type we sign with.
pub const SIGHASH_DEFAULT: u8 = 0x00;

/// `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ parts…)` (BIP340 tagged hash).
#[must_use]
pub fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let tag_hash: [u8; 32] = Sha256::digest(tag).into();
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// `t = TaggedHash("TapTweak", P_x ‖ merkle_root)`; BIP86 key-only outputs have no merkle root
/// (`t = TaggedHash("TapTweak", P_x)`).
#[must_use]
pub fn tap_tweak_hash(internal: &XOnlyPublicKey, merkle_root: Option<&[u8; 32]>) -> [u8; 32] {
    let key = internal.serialize();
    match merkle_root {
        Some(root) => tagged_hash(b"TapTweak", &[&key, root]),
        None => tagged_hash(b"TapTweak", &[&key]),
    }
}

fn tweak_scalar(
    internal: &XOnlyPublicKey,
    merkle_root: Option<&[u8; 32]>,
) -> Result<Scalar, KeyError> {
    Scalar::from_be_bytes(tap_tweak_hash(internal, merkle_root))
        .map_err(|_| KeyError::DerivationFailed)
}

/// The output key `Q = P + t·G` (x-only) of internal key `P` (BIP341 `taproot_tweak_pubkey`).
///
/// # Errors
///
/// [`KeyError::DerivationFailed`] when `t ≥ n` or `Q` is the point at infinity (negligible).
pub fn output_key<C: Verification>(
    ctx: &Secp256k1<C>,
    internal: &XOnlyPublicKey,
    merkle_root: Option<&[u8; 32]>,
) -> Result<XOnlyPublicKey, KeyError> {
    let tweak = tweak_scalar(internal, merkle_root)?;
    internal
        .add_tweak(ctx, &tweak)
        .map(|(key, _parity)| key)
        .map_err(|_| KeyError::DerivationFailed)
}

/// The tweaked key pair of `secret` (BIP341 `taproot_tweak_seckey`: the secret is negated when
/// its point has an odd Y, then `t` is added). The caller erases the returned pair.
///
/// # Errors
///
/// [`KeyError::DerivationFailed`] as [`output_key`].
pub(crate) fn tweaked_keypair(
    ctx: &Secp256k1<All>,
    secret: &SecretKey,
    merkle_root: Option<&[u8; 32]>,
) -> Result<Keypair, KeyError> {
    let keypair = Keypair::from_secret_key(ctx, secret);
    let (internal, _parity) = keypair.x_only_public_key();
    let tweak = tweak_scalar(&internal, merkle_root)?;
    keypair
        .add_xonly_tweak(ctx, &tweak)
        .map_err(|_| KeyError::DerivationFailed)
}

/// A previous output as BIP341 commits to it: its amount and scriptPubKey.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Prevout {
    /// Hash-verified amount (spec/08 §5).
    pub value: Sats,
    /// The spent scriptPubKey.
    pub script_pubkey: Vec<u8>,
}

/// The BIP341 signature message of key-path input `index` with `SIGHASH_DEFAULT`, the epoch
/// byte `0x00` first (the `sigMsg` of the BIP341 wallet vectors):
///
/// ```text
/// 0x00 ‖ hash_type 0x00 ‖ nVersion ‖ nLockTime ‖ sha_prevouts ‖ sha_amounts
/// ‖ sha_scriptpubkeys ‖ sha_sequences ‖ sha_outputs ‖ spend_type 0x00 ‖ input_index u32
/// ```
///
/// `None` when `index` is not an input or `prevouts` does not have one entry per input.
#[must_use]
pub fn sig_msg_default(tx: &Transaction, index: usize, prevouts: &[Prevout]) -> Option<Vec<u8>> {
    if index >= tx.inputs.len() || prevouts.len() != tx.inputs.len() {
        return None;
    }
    let single = |update: &dyn Fn(&mut Sha256)| -> [u8; 32] {
        let mut hasher = Sha256::new();
        update(&mut hasher);
        hasher.finalize().into()
    };
    let sha_prevouts = single(&|hasher| {
        for input in &tx.inputs {
            hasher.update(input.prevout.txid.as_bytes());
            hasher.update(input.prevout.vout.to_le_bytes());
        }
    });
    let sha_amounts = single(&|hasher| {
        for prevout in prevouts {
            hasher.update(prevout.value.get().to_le_bytes());
        }
    });
    let sha_scripts = single(&|hasher| {
        let mut length = Vec::with_capacity(9);
        for prevout in prevouts {
            length.clear();
            write_compact_size(&mut length, prevout.script_pubkey.len());
            hasher.update(&length);
            hasher.update(&prevout.script_pubkey);
        }
    });
    let sha_sequences = single(&|hasher| {
        for input in &tx.inputs {
            hasher.update(input.sequence.to_le_bytes());
        }
    });
    let sha_outputs = single(&|hasher| {
        let mut length = Vec::with_capacity(9);
        for output in &tx.outputs {
            hasher.update(output.value.get().to_le_bytes());
            length.clear();
            write_compact_size(&mut length, output.script_pubkey.len());
            hasher.update(&length);
            hasher.update(&output.script_pubkey);
        }
    });
    let mut out = Vec::with_capacity(175);
    out.push(0x00);
    out.push(SIGHASH_DEFAULT);
    out.extend_from_slice(&tx.version.to_le_bytes());
    out.extend_from_slice(&tx.lock_time.to_le_bytes());
    out.extend_from_slice(&sha_prevouts);
    out.extend_from_slice(&sha_amounts);
    out.extend_from_slice(&sha_scripts);
    out.extend_from_slice(&sha_sequences);
    out.extend_from_slice(&sha_outputs);
    out.push(0x00);
    out.extend_from_slice(&u32::try_from(index).ok()?.to_le_bytes());
    Some(out)
}

/// `TaggedHash("TapSighash", sig_msg_default(..))`.
#[must_use]
pub fn sighash_default(tx: &Transaction, index: usize, prevouts: &[Prevout]) -> Option<[u8; 32]> {
    let message = sig_msg_default(tx, index, prevouts)?;
    Some(tagged_hash(b"TapSighash", &[&message]))
}

/// Why a key-path witness was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TaprootSigError {
    /// Not exactly one 64-byte item (a 65-byte item would carry a non-default hash type).
    Shape,
    /// The output key is not a valid x-only key.
    OutputKey,
    /// The signature does not verify for the sighash and output key.
    VerifyFailed,
    /// Tweaking failed.
    Tweak,
}

impl fmt::Display for TaprootSigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Shape => "taproot witness is not one 64-byte signature",
            Self::OutputKey => "taproot output key is invalid",
            Self::VerifyFailed => "schnorr signature does not verify",
            Self::Tweak => "taproot tweak failed",
        })
    }
}

impl std::error::Error for TaprootSigError {}

/// Strict check of a key-path witness: exactly one 64-byte BIP340 signature valid for `sighash`
/// under the output key `output` (the P2TR program).
///
/// # Errors
///
/// The failing rule's [`TaprootSigError`].
pub fn check_key_path_witness<C: Verification>(
    ctx: &Secp256k1<C>,
    witness: &[Vec<u8>],
    output: &[u8; 32],
    sighash: &[u8; 32],
) -> Result<(), TaprootSigError> {
    let [item] = witness else {
        return Err(TaprootSigError::Shape);
    };
    let bytes =
        <[u8; SCHNORR_SIG_LEN]>::try_from(item.as_slice()).map_err(|_| TaprootSigError::Shape)?;
    let key = XOnlyPublicKey::from_byte_array(*output).map_err(|_| TaprootSigError::OutputKey)?;
    ctx.verify_schnorr(&Signature::from_byte_array(bytes), sighash, &key)
        .map_err(|_| TaprootSigError::VerifyFailed)
}

/// Signs `sighash` with the BIP86-tweaked key of `secret` (`merkle_root = None` for our
/// accounts), BIP340 with the 32 bytes of auxiliary randomness `aux`, verifies at once against
/// the output key and returns `(signature, output key)`. Called only inside the key lending
/// closure; the tweaked pair is erased before returning.
///
/// # Errors
///
/// [`TaprootSigError::Tweak`], [`TaprootSigError::VerifyFailed`].
pub(crate) fn sign_key_path(
    ctx: &Secp256k1<All>,
    secret: &SecretKey,
    merkle_root: Option<&[u8; 32]>,
    sighash: &[u8; 32],
    aux: &[u8; 32],
) -> Result<([u8; SCHNORR_SIG_LEN], [u8; 32]), TaprootSigError> {
    let mut keypair =
        tweaked_keypair(ctx, secret, merkle_root).map_err(|_| TaprootSigError::Tweak)?;
    let signature = ctx.sign_schnorr_with_aux_rand(sighash, &keypair, aux);
    let (output, _parity) = keypair.x_only_public_key();
    keypair.non_secure_erase();
    let bytes = signature.to_byte_array();
    let output = output.serialize();
    check_key_path_witness(ctx, &[bytes.to_vec()], &output, sighash)?;
    Ok((bytes, output))
}
