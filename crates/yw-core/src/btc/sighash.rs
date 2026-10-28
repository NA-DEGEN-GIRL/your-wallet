//! ECDSA signature hashes with `SIGHASH_ALL` (spec/08 §6.6): BIP143 for P2WPKH and P2SH-P2WPKH
//! inputs, and the legacy hash for P2PKH inputs. Taproot inputs use `taproot::sighash_default`.
//!
//! ```text
//! preimage = version u32 | hashPrevouts | hashSequence | outpoint 36 | scriptCode 26
//!          | amount u64 | sequence u32 | hashOutputs | lock_time u32 | 0x01000000
//! ```
//! The amount is the verified previous-output value (spec/08 §5); BIP143 commits each input's
//! amount only to that input's signature. The legacy hash commits to no amount at all: a P2PKH
//! input's value is protected only by the previous-transaction verification (CVE-2020-14199
//! does not apply, but the fee shown must still come from verified values).
#![deny(clippy::indexing_slicing)]

use sha2::{Digest, Sha256};

use super::SIGHASH_ALL;
use super::amount::Sats;
use super::script::p2wpkh_script_code;
use super::tx::{Transaction, write_compact_size};

fn finish(hasher: Sha256) -> [u8; 32] {
    Sha256::digest(hasher.finalize()).into()
}

/// `SHA256d(txid ‖ vout)` over every input.
#[must_use]
pub fn hash_prevouts(tx: &Transaction) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for input in &tx.inputs {
        hasher.update(input.prevout.txid.as_bytes());
        hasher.update(input.prevout.vout.to_le_bytes());
    }
    finish(hasher)
}

/// `SHA256d(sequence)` over every input.
#[must_use]
pub fn hash_sequence(tx: &Transaction) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for input in &tx.inputs {
        hasher.update(input.sequence.to_le_bytes());
    }
    finish(hasher)
}

/// `SHA256d(value ‖ CompactSize(len) ‖ scriptPubKey)` over every output.
#[must_use]
pub fn hash_outputs(tx: &Transaction) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let mut length = Vec::with_capacity(9);
    for output in &tx.outputs {
        hasher.update(output.value.get().to_le_bytes());
        length.clear();
        write_compact_size(&mut length, output.script_pubkey.len());
        hasher.update(&length);
        hasher.update(&output.script_pubkey);
    }
    finish(hasher)
}

/// The BIP143 `SIGHASH_ALL` digest of input `index` spending the P2WPKH `program` worth
/// `amount`. `None` when `index` is not an input of `tx`. P2SH-P2WPKH inputs use the same
/// digest: their scriptCode is the P2WPKH one of the key hash (BIP143 "P2SH-P2WPKH").
#[must_use]
pub fn bip143_sighash_p2wpkh(
    tx: &Transaction,
    index: usize,
    program: &[u8; 20],
    amount: Sats,
) -> Option<[u8; 32]> {
    let input = tx.inputs.get(index)?;
    let mut hasher = Sha256::new();
    hasher.update(tx.version.to_le_bytes());
    hasher.update(hash_prevouts(tx));
    hasher.update(hash_sequence(tx));
    hasher.update(input.prevout.txid.as_bytes());
    hasher.update(input.prevout.vout.to_le_bytes());
    hasher.update(p2wpkh_script_code(program));
    hasher.update(amount.get().to_le_bytes());
    hasher.update(input.sequence.to_le_bytes());
    hasher.update(hash_outputs(tx));
    hasher.update(tx.lock_time.to_le_bytes());
    hasher.update(u32::from(SIGHASH_ALL).to_le_bytes());
    Some(finish(hasher))
}

/// Whether a legacy hash type has `SIGHASH_ALL` semantics in Core's `SignatureHash`: the low five
/// bits are neither `SIGHASH_NONE` (2) nor `SIGHASH_SINGLE` (3) and `ANYONECANPAY` (0x80) is
/// clear. (Other low values, 0 and 4–31, behave as `ALL`; the full 32-bit value is still
/// committed.)
#[must_use]
pub const fn legacy_is_all(hash_type: u32) -> bool {
    let base = hash_type & 0x1f;
    base != 2 && base != 3 && hash_type & 0x80 == 0
}

/// The legacy (pre-segwit) signature hash of input `index` with `script_code` (the spent
/// scriptPubKey without `OP_CODESEPARATOR`; ours is the P2PKH script) and a hash type with
/// `SIGHASH_ALL` semantics ([`legacy_is_all`]): `SHA256d` of the transaction serialized without
/// witnesses where input `index` carries `script_code` and every other input an empty script,
/// followed by `hash_type` as `u32` LE. Every input commits to every input's outpoint and
/// sequence and to every output.
///
/// `None` when `index` is not an input or the hash type is `NONE`/`SINGLE`/`ANYONECANPAY` (never
/// produced by this wallet).
#[must_use]
pub fn legacy_sighash(
    tx: &Transaction,
    index: usize,
    script_code: &[u8],
    hash_type: u32,
) -> Option<[u8; 32]> {
    if index >= tx.inputs.len() || !legacy_is_all(hash_type) {
        return None;
    }
    let mut hasher = Sha256::new();
    let mut length = Vec::with_capacity(9);
    hasher.update(tx.version.to_le_bytes());
    length.clear();
    write_compact_size(&mut length, tx.inputs.len());
    hasher.update(&length);
    for (position, input) in tx.inputs.iter().enumerate() {
        hasher.update(input.prevout.txid.as_bytes());
        hasher.update(input.prevout.vout.to_le_bytes());
        let script: &[u8] = if position == index { script_code } else { &[] };
        length.clear();
        write_compact_size(&mut length, script.len());
        hasher.update(&length);
        hasher.update(script);
        hasher.update(input.sequence.to_le_bytes());
    }
    length.clear();
    write_compact_size(&mut length, tx.outputs.len());
    hasher.update(&length);
    for output in &tx.outputs {
        hasher.update(output.value.get().to_le_bytes());
        length.clear();
        write_compact_size(&mut length, output.script_pubkey.len());
        hasher.update(&length);
        hasher.update(&output.script_pubkey);
    }
    hasher.update(tx.lock_time.to_le_bytes());
    hasher.update(hash_type.to_le_bytes());
    Some(finish(hasher))
}
