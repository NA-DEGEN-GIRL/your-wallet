//! Personalised BLAKE2b (RFC 7693 with the 16-byte personalisation of the parameter block),
//! used by the ZIP 244 digests (BLAKE2b-256) and ZIP 316 F4Jumble (BLAKE2b-ℓ, ℓ ≤ 512 bits).
//!
//! Built on `blake2::Blake2bVarCore::new_with_params(salt = [], persona, key_size = 0, out_len)`
//! with the crate's lazy block buffer (the last block must be compressed with the final flag).
//! `Blake2bMac` with an empty key is deliberately not used (spec/12 §6.1).
#![deny(clippy::indexing_slicing)]

use blake2::Blake2bVarCore;
use blake2::digest::core_api::{Buffer, UpdateCore, VariableOutputCore};

/// Personalisation length (bytes) of BLAKE2b.
pub const PERSONA_LEN: usize = 16;
/// Largest BLAKE2b output (bytes).
pub const MAX_OUT_LEN: usize = 64;

/// An incremental personalised BLAKE2b hasher with an output of `out_len` bytes (1–64).
pub struct Blake2bPersonal {
    core: Blake2bVarCore,
    buffer: Buffer<Blake2bVarCore>,
    out_len: usize,
}

impl core::fmt::Debug for Blake2bPersonal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Blake2bPersonal")
    }
}

impl Blake2bPersonal {
    /// A hasher with `persona` (exactly 16 bytes) and `out_len` (clamped to 1–64) output bytes.
    #[must_use]
    pub fn new(persona: &[u8; PERSONA_LEN], out_len: usize) -> Self {
        let out_len = out_len.clamp(1, MAX_OUT_LEN);
        Self {
            core: Blake2bVarCore::new_with_params(&[], persona, 0, out_len),
            buffer: Buffer::<Blake2bVarCore>::default(),
            out_len,
        }
    }

    /// Absorbs `data`.
    pub fn update(&mut self, data: &[u8]) {
        let core = &mut self.core;
        self.buffer
            .digest_blocks(data, |blocks| core.update_blocks(blocks));
    }

    /// The digest (`out_len` bytes).
    #[must_use]
    pub fn finalize(mut self) -> Vec<u8> {
        let mut full = blake2::digest::Output::<Blake2bVarCore>::default();
        self.core
            .finalize_variable_core(&mut self.buffer, &mut full);
        full.get(..self.out_len).unwrap_or_default().to_vec()
    }

    /// The 32-byte digest of a BLAKE2b-256 hasher (zero-padded if the hasher is shorter).
    #[must_use]
    pub fn finalize_32(self) -> [u8; 32] {
        let bytes = self.finalize();
        let mut out = [0_u8; 32];
        for (slot, byte) in out.iter_mut().zip(bytes) {
            *slot = byte;
        }
        out
    }
}

/// BLAKE2b-256 of the concatenation of `parts` with `persona`.
#[must_use]
pub fn blake2b_256(persona: &[u8; PERSONA_LEN], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2bPersonal::new(persona, 32);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize_32()
}

/// BLAKE2b with an `out_len`-byte output (1–64) of `data` with `persona`.
#[must_use]
pub fn blake2b(persona: &[u8; PERSONA_LEN], data: &[u8], out_len: usize) -> Vec<u8> {
    let mut hasher = Blake2bPersonal::new(persona, out_len);
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::{Blake2bPersonal, blake2b};
    use crate::hex;

    /// RFC 7693 Appendix A: BLAKE2b-512("abc") (personalisation all zero = no personalisation).
    #[test]
    fn rfc7693_abc() {
        let digest = blake2b(&[0; 16], b"abc", 64);
        assert_eq!(
            hex::encode(&digest),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
    }

    /// Incremental updates across block boundaries give the one-shot digest.
    #[test]
    fn incremental_matches_one_shot() {
        let data: Vec<u8> = (0..=255_u8).cycle().take(1000).collect();
        let one = blake2b(b"ZTxIdOutputsHash", &data, 32);
        for split in [0, 1, 127, 128, 129, 256, 999, 1000] {
            let (a, b) = data.split_at(split);
            let mut hasher = Blake2bPersonal::new(b"ZTxIdOutputsHash", 32);
            hasher.update(a);
            hasher.update(b);
            assert_eq!(hasher.finalize(), one, "split {split}");
        }
    }
}
