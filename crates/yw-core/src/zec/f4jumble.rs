//! F4Jumble and its inverse (ZIP 316 §"Jumbling", spec/12 §3.3): a 4-round unbalanced Feistel
//! network over personalised BLAKE2b.
//!
//! `ℓ_L = min(64, ⌊ℓ_M/2⌋)`, `ℓ_R = ℓ_M − ℓ_L`;
//! `H_i(u) = BLAKE2b-(8ℓ_L)("UA_F4Jumble_H" ‖ [i, 0, 0], u)`;
//! `G_i(u)` = the first `ℓ_R` bytes of `‖_j BLAKE2b-512("UA_F4Jumble_G" ‖ [i] ‖ LE16(j), u)`.
//! Jumble: `x = b ⊕ G_0(a)`, `y = a ⊕ H_0(x)`, `d = x ⊕ G_1(y)`, `c = y ⊕ H_1(d)` → `c ‖ d`.
#![deny(clippy::indexing_slicing)]

use super::blake2b::{MAX_OUT_LEN, blake2b};

/// Shortest F4Jumble input (bytes, ZIP 316: `38 ≤ ℓ_M`).
pub const MIN_LEN: usize = 38;
/// Longest F4Jumble input (bytes, `4194368`).
pub const MAX_LEN: usize = 4_194_368;

fn h_persona(round: u8) -> [u8; 16] {
    let mut persona = *b"UA_F4Jumble_H\0\0\0";
    if let Some(slot) = persona.get_mut(13) {
        *slot = round;
    }
    persona
}

fn g_persona(round: u8, block: u16) -> [u8; 16] {
    let mut persona = *b"UA_F4Jumble_G\0\0\0";
    if let Some(slot) = persona.get_mut(13) {
        *slot = round;
    }
    if let Some(tail) = persona.get_mut(14..) {
        tail.copy_from_slice(&block.to_le_bytes());
    }
    persona
}

fn xor_in(target: &mut [u8], mask: &[u8]) {
    for (byte, mask) in target.iter_mut().zip(mask) {
        *byte ^= mask;
    }
}

fn h(round: u8, input: &[u8], out_len: usize) -> Vec<u8> {
    blake2b(&h_persona(round), input, out_len)
}

fn g(round: u8, input: &[u8], out_len: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(out_len);
    let blocks = out_len.div_ceil(MAX_OUT_LEN);
    for block in 0..blocks {
        let block = u16::try_from(block).ok()?;
        out.extend(blake2b(&g_persona(round, block), input, MAX_OUT_LEN));
    }
    out.truncate(out_len);
    Some(out)
}

fn split_lengths(total: usize) -> Option<(usize, usize)> {
    if !(MIN_LEN..=MAX_LEN).contains(&total) {
        return None;
    }
    let left = MAX_OUT_LEN.min(total / 2);
    Some((left, total.checked_sub(left)?))
}

/// F4Jumble of `message`; `None` outside 38–4194368 bytes.
#[must_use]
#[expect(
    clippy::many_single_char_names,
    reason = "the variable names of ZIP 316"
)]
pub fn f4jumble(message: &[u8]) -> Option<Vec<u8>> {
    let (left, right) = split_lengths(message.len())?;
    let (a, b) = message.split_at(left);
    let mut a = a.to_vec();
    let mut x = b.to_vec();
    xor_in(&mut x, &g(0, &a, right)?);
    xor_in(&mut a, &h(0, &x, left));
    let y = a;
    xor_in(&mut x, &g(1, &y, right)?);
    let d = x;
    let mut c = y;
    xor_in(&mut c, &h(1, &d, left));
    c.extend_from_slice(&d);
    Some(c)
}

/// The inverse of [`f4jumble`]; `None` outside 38–4194368 bytes.
#[must_use]
#[expect(
    clippy::many_single_char_names,
    reason = "the variable names of ZIP 316"
)]
pub fn f4jumble_inv(jumbled: &[u8]) -> Option<Vec<u8>> {
    let (left, right) = split_lengths(jumbled.len())?;
    let (c, d) = jumbled.split_at(left);
    let mut y = c.to_vec();
    xor_in(&mut y, &h(1, d, left));
    let mut x = d.to_vec();
    xor_in(&mut x, &g(1, &y, right)?);
    let mut a = y;
    xor_in(&mut a, &h(0, &x, left));
    let mut b = x;
    xor_in(&mut b, &g(0, &a, right)?);
    a.extend_from_slice(&b);
    Some(a)
}
