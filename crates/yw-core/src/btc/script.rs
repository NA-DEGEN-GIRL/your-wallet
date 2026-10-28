//! Script templates, output sizes and dust (spec/08 §6.4).
//!
//! Dust follows Core `GetDustThreshold` at the 3 sat/vB dust relay fee:
//! `(output size + spending input size) × 3` with input sizes 148 (non-witness) and 67
//! (witness: `32 + 4 + 1 + 107/4 + 4`).
#![deny(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

use super::address::ScriptKind;
use super::amount::Sats;

/// P2PKH scriptPubKey length.
pub const P2PKH_SPK_LEN: usize = 25;
/// P2SH scriptPubKey length.
pub const P2SH_SPK_LEN: usize = 23;
/// P2WPKH scriptPubKey length.
pub const P2WPKH_SPK_LEN: usize = 22;
/// P2WSH scriptPubKey length.
pub const P2WSH_SPK_LEN: usize = 34;
/// P2TR scriptPubKey length.
pub const P2TR_SPK_LEN: usize = 34;
/// Dust relay fee (sat/vB) behind the dust thresholds.
pub const DUST_RELAY_SAT_PER_VB: u64 = 3;
/// Size of an input spending a non-witness output (Core `GetDustThreshold`).
pub const SPEND_SIZE_NON_WITNESS: u64 = 148;
/// Virtual size of an input spending a witness output (`32 + 4 + 1 + 107/4 + 4`).
pub const SPEND_SIZE_WITNESS: u64 = 67;

/// `76 a9 14 <h20> 88 ac`.
#[must_use]
pub fn p2pkh_script_pubkey(hash: &[u8; 20]) -> [u8; P2PKH_SPK_LEN] {
    let mut out = [0_u8; P2PKH_SPK_LEN];
    for (slot, byte) in out
        .iter_mut()
        .zip([0x76, 0xa9, 0x14].iter().chain(hash).chain(&[0x88, 0xac]))
    {
        *slot = *byte;
    }
    out
}

/// `a9 14 <h20> 87`.
#[must_use]
pub fn p2sh_script_pubkey(hash: &[u8; 20]) -> [u8; P2SH_SPK_LEN] {
    let mut out = [0_u8; P2SH_SPK_LEN];
    for (slot, byte) in out
        .iter_mut()
        .zip([0xa9, 0x14].iter().chain(hash).chain(&[0x87]))
    {
        *slot = *byte;
    }
    out
}

/// `00 14 <h20>` (our receive and change outputs, and the §5 expected script).
#[must_use]
pub fn p2wpkh_script_pubkey(program: &[u8; 20]) -> [u8; P2WPKH_SPK_LEN] {
    let mut out = [0_u8; P2WPKH_SPK_LEN];
    for (slot, byte) in out.iter_mut().zip([0x00, 0x14].iter().chain(program)) {
        *slot = *byte;
    }
    out
}

/// `00 20 <h32>`.
#[must_use]
pub fn p2wsh_script_pubkey(program: &[u8; 32]) -> [u8; P2WSH_SPK_LEN] {
    let mut out = [0_u8; P2WSH_SPK_LEN];
    for (slot, byte) in out.iter_mut().zip([0x00, 0x20].iter().chain(program)) {
        *slot = *byte;
    }
    out
}

/// `51 20 <x32>`.
#[must_use]
pub fn p2tr_script_pubkey(key: &[u8; 32]) -> [u8; P2TR_SPK_LEN] {
    let mut out = [0_u8; P2TR_SPK_LEN];
    for (slot, byte) in out.iter_mut().zip([0x51, 0x20].iter().chain(key)) {
        *slot = *byte;
    }
    out
}

/// BIP143 scriptCode of a P2WPKH input, length prefix included: `19 76 a9 14 <h20> 88 ac`.
#[must_use]
pub fn p2wpkh_script_code(program: &[u8; 20]) -> [u8; 26] {
    let mut out = [0_u8; 26];
    for (slot, byte) in out
        .iter_mut()
        .zip([0x19].iter().chain(&p2pkh_script_pubkey(program)))
    {
        *slot = *byte;
    }
    out
}

/// P2SH-P2WPKH redeem script `00 14 <h20>` (BIP49, BIP141 "P2WPKH nested in BIP16 P2SH").
#[must_use]
pub fn p2sh_p2wpkh_redeem_script(hash: &[u8; 20]) -> [u8; P2WPKH_SPK_LEN] {
    p2wpkh_script_pubkey(hash)
}

/// P2SH-P2WPKH scriptSig: one push of the redeem script, `16 00 14 <h20>` (23 bytes).
#[must_use]
pub fn p2sh_p2wpkh_script_sig(hash: &[u8; 20]) -> [u8; 23] {
    let mut out = [0_u8; 23];
    for (slot, byte) in out
        .iter_mut()
        .zip([0x16].iter().chain(&p2sh_p2wpkh_redeem_script(hash)))
    {
        *slot = *byte;
    }
    out
}

/// P2PKH scriptSig `<sig_item> <pubkey>` as two direct pushes (both items are 1–75 bytes:
/// `DER ‖ 0x01` ≤ 73, key 33 or 65). `None` for an item outside 1–75 bytes.
#[must_use]
pub fn p2pkh_script_sig(sig_item: &[u8], pubkey: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(
        sig_item
            .len()
            .saturating_add(pubkey.len())
            .saturating_add(2),
    );
    for item in [sig_item, pubkey] {
        let length = u8::try_from(item.len())
            .ok()
            .filter(|len| (1..=75).contains(len))?;
        out.push(length);
        out.extend_from_slice(item);
    }
    Some(out)
}

/// Splits a P2PKH scriptSig into its two direct pushes (`None` for any other shape).
#[must_use]
pub fn split_p2pkh_script_sig(script_sig: &[u8]) -> Option<(&[u8], &[u8])> {
    let (first_len, rest) = script_sig.split_first()?;
    let first_len = usize::from(*first_len);
    if !(1..=75).contains(&first_len) {
        return None;
    }
    let (sig, rest) = rest.split_at_checked(first_len)?;
    let (second_len, key) = rest.split_first()?;
    if !(1..=75).contains(second_len) || key.len() != usize::from(*second_len) {
        return None;
    }
    Some((sig, key))
}

/// scriptPubKey length of `kind`.
#[must_use]
pub const fn spk_len(kind: &ScriptKind) -> usize {
    match kind {
        ScriptKind::P2pkh(_) => P2PKH_SPK_LEN,
        ScriptKind::P2sh(_) => P2SH_SPK_LEN,
        ScriptKind::P2wpkh(_) => P2WPKH_SPK_LEN,
        ScriptKind::P2wsh(_) => P2WSH_SPK_LEN,
        ScriptKind::P2tr(_) => P2TR_SPK_LEN,
    }
}

/// Output size in vbytes: `8 (value) + 1 (length) + spk` = 34 / 32 / 31 / 43 / 43.
#[must_use]
pub const fn output_vbytes(kind: &ScriptKind) -> u64 {
    match kind {
        ScriptKind::P2pkh(_) => 34,
        ScriptKind::P2sh(_) => 32,
        ScriptKind::P2wpkh(_) => 31,
        ScriptKind::P2wsh(_) | ScriptKind::P2tr(_) => 43,
    }
}

/// Size of the input that would later spend an output of `kind`.
#[must_use]
pub const fn spend_size(kind: &ScriptKind) -> u64 {
    match kind {
        ScriptKind::P2pkh(_) | ScriptKind::P2sh(_) => SPEND_SIZE_NON_WITNESS,
        ScriptKind::P2wpkh(_) | ScriptKind::P2wsh(_) | ScriptKind::P2tr(_) => SPEND_SIZE_WITNESS,
    }
}

/// Dust threshold of `kind`: 546 / 540 / 294 / 330 / 330 sats.
#[must_use]
pub const fn dust_threshold(kind: &ScriptKind) -> Sats {
    match kind {
        ScriptKind::P2pkh(_) => DUST_P2PKH,
        ScriptKind::P2sh(_) => DUST_P2SH,
        ScriptKind::P2wpkh(_) => DUST_P2WPKH,
        ScriptKind::P2wsh(_) | ScriptKind::P2tr(_) => DUST_P2WSH_P2TR,
    }
}

const fn sats(value: u64) -> Sats {
    match Sats::new(value) {
        Some(amount) => amount,
        None => Sats::ZERO,
    }
}

const DUST_P2PKH: Sats = sats(546);
const DUST_P2SH: Sats = sats(540);
const DUST_P2WPKH: Sats = sats(294);
const DUST_P2WSH_P2TR: Sats = sats(330);
