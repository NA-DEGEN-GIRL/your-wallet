//! Binary/text codecs shared across chains (spec/01 §2.2 `codec`).

pub mod base58;
pub mod transcript;

/// SHA-256 of `bytes` (digest helper for transcripts and independent golden checks).
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

/// Keccak-256 of `bytes` (EVM hashing helper for callers without a direct `sha3` dependency).
#[must_use]
pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    Keccak256::digest(bytes).into()
}
