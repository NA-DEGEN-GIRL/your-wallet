//! ZIP 244 signature digest of a transparent input with `SIGHASH_ALL` (spec/12 §6.2).
//!
//! `S = BLAKE2b-256("ZcashTxHash_" ‖ LE32(branch), header_digest ‖ transparent_sig_digest ‖
//! sapling_digest ‖ orchard_digest)` with
//! `transparent_sig_digest = BLAKE2b-256("ZTxIdTranspaHash", hash_type ‖ prevouts_digest ‖
//! amounts_sig_digest ‖ scriptpubkeys_sig_digest ‖ sequence_digest ‖ outputs_digest ‖
//! txin_sig_digest)`. `SIGHASH_ALL` commits to the amount and `scriptPubKey` of **every** input,
//! so a wrong indexer amount or script makes every signature invalid: no previous transaction
//! has to be fetched (spec/12 §5.3).
#![deny(clippy::indexing_slicing)]

use super::blake2b::blake2b_256;
use super::tx::{
    ZecTx, empty_orchard_digest, empty_sapling_digest, header_digest, outputs_digest,
    prevouts_digest, root_persona, sequence_digest,
};
use crate::btc::tx::write_compact_size;

/// `SIGHASH_ALL`: the only hash type this wallet signs with (and the scriptSig suffix byte).
pub const SIGHASH_ALL: u8 = 0x01;

/// The amount and `scriptPubKey` of a spent output (ZIP 244 `amounts`, `script_pubkeys`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZecPrevout {
    /// Value in zatoshis.
    pub value: u64,
    /// `scriptPubKey`.
    pub script_pubkey: Vec<u8>,
}

fn amounts_sig_digest(prevouts: &[ZecPrevout]) -> [u8; 32] {
    let bytes: Vec<u8> = prevouts
        .iter()
        .flat_map(|prevout| prevout.value.to_le_bytes())
        .collect();
    blake2b_256(b"ZTxTrAmountsHash", &[&bytes])
}

fn scriptpubkeys_sig_digest(prevouts: &[ZecPrevout]) -> [u8; 32] {
    let mut bytes = Vec::new();
    for prevout in prevouts {
        write_compact_size(&mut bytes, prevout.script_pubkey.len());
        bytes.extend_from_slice(&prevout.script_pubkey);
    }
    blake2b_256(b"ZTxTrScriptsHash", &[&bytes])
}

fn txin_sig_digest(tx: &ZecTx, index: usize, prevout: &ZecPrevout) -> Option<[u8; 32]> {
    let input = tx.inputs.get(index)?;
    let mut bytes = Vec::with_capacity(36 + 8 + 1 + prevout.script_pubkey.len() + 4);
    bytes.extend_from_slice(&input.prevout.to_bytes());
    bytes.extend_from_slice(&prevout.value.to_le_bytes());
    write_compact_size(&mut bytes, prevout.script_pubkey.len());
    bytes.extend_from_slice(&prevout.script_pubkey);
    bytes.extend_from_slice(&input.sequence.to_le_bytes());
    Some(blake2b_256(b"Zcash___TxInHash", &[&bytes]))
}

/// The `SIGHASH_ALL` signature digest of input `index` (ZIP 244 §S.2), given the spent outputs
/// of all inputs in order. `None` when `index` is out of range or `prevouts` does not have one
/// entry per input.
#[must_use]
pub fn sighash_all(tx: &ZecTx, index: usize, prevouts: &[ZecPrevout]) -> Option<[u8; 32]> {
    sighash_all_with(
        tx,
        index,
        prevouts,
        &empty_sapling_digest(),
        &empty_orchard_digest(),
    )
}

/// [`sighash_all`] with given Sapling / Orchard digests (official vectors).
pub(crate) fn sighash_all_with(
    tx: &ZecTx,
    index: usize,
    prevouts: &[ZecPrevout],
    sapling: &[u8; 32],
    orchard: &[u8; 32],
) -> Option<[u8; 32]> {
    if prevouts.len() != tx.inputs.len() {
        return None;
    }
    let own = prevouts.get(index)?;
    let transparent = blake2b_256(
        b"ZTxIdTranspaHash",
        &[
            &[SIGHASH_ALL],
            &prevouts_digest(tx),
            &amounts_sig_digest(prevouts),
            &scriptpubkeys_sig_digest(prevouts),
            &sequence_digest(tx),
            &outputs_digest(tx),
            &txin_sig_digest(tx, index, own)?,
        ],
    );
    Some(blake2b_256(
        &root_persona(tx.branch_id),
        &[&header_digest(tx), &transparent, sapling, orchard],
    ))
}
