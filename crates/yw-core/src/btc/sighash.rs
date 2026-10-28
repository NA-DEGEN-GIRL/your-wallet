//! BIP143 signature hash for P2WPKH inputs with `SIGHASH_ALL` (spec/08 §6.6).
//!
//! ```text
//! preimage = version u32 | hashPrevouts | hashSequence | outpoint 36 | scriptCode 26
//!          | amount u64 | sequence u32 | hashOutputs | lock_time u32 | 0x01000000
//! ```
//! The amount is the verified previous-output value (spec/08 §5); BIP143 commits each input's
//! amount only to that input's signature.
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
/// `amount`. `None` when `index` is not an input of `tx`.
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
