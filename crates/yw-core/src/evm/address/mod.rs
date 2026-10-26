//! EVM addresses and EIP-55 (spec/03 §2.1–§2.2, spec/02 §3.3).
//!
//! Parsing accepts all-lowercase, all-uppercase, or mixed case that matches the EIP-55 checksum
//! exactly; the archive's lowercase-only rule
//! (`archive/spec-v2.4:crates/wallet-model/src/bounded.rs:354-360`) is reversed. The checksum
//! follows `archive/spec-v2.4:crates/wallet-protocol/src/authorization.rs:818-837`.

use core::fmt;

use secp256k1::PublicKey;
use sha3::{Digest, Keccak256};

use crate::hex;

/// A 20-byte EVM address. Public information (D28 allows logging addresses).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address([u8; 20]);

/// Address parsing failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressError {
    /// Not `0x` followed by exactly 40 hex digits.
    InvalidFormat,
    /// Mixed case that does not match the EIP-55 checksum.
    BadChecksum,
}

impl fmt::Display for AddressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFormat => "주소 형식이 올바르지 않습니다.",
            Self::BadChecksum => "주소의 대소문자 체크섬이 맞지 않습니다. 주소를 다시 확인하세요.",
        })
    }
}

impl std::error::Error for AddressError {}

impl Address {
    /// Wraps raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// `keccak256(uncompressed_pubkey[1..65])[12..32]`.
    #[must_use]
    pub fn from_public_key(public: &PublicKey) -> Self {
        let uncompressed = public.serialize_uncompressed();
        let (_, xy) = uncompressed.split_at(1);
        let digest = Keccak256::digest(xy);
        let mut out = [0_u8; 20];
        for (slot, byte) in out.iter_mut().zip(digest.iter().skip(12)) {
            *slot = *byte;
        }
        Self(out)
    }

    /// `0x` + 40 lowercase hex digits (RPC, JSON and meta form).
    #[must_use]
    pub fn to_lower_hex(self) -> String {
        let mut out = String::with_capacity(42);
        out.push_str("0x");
        hex::encode_into(&self.0, &mut out);
        out
    }

    /// The EIP-55 mixed-case form.
    #[must_use]
    pub fn to_checksum(self) -> String {
        to_checksum(&self)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_checksum())
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Address({})", self.to_lower_hex())
    }
}

/// EIP-55: uppercase the i-th hex letter when nibble i of `keccak256(lowercase hex)` is ≥ 8.
#[must_use]
pub fn to_checksum(address: &Address) -> String {
    let lower = hex::encode(&address.0);
    let digest = Keccak256::digest(lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (index, character) in lower.chars().enumerate() {
        let byte = digest.get(index / 2).copied().unwrap_or(0);
        let nibble = if index % 2 == 0 {
            byte >> 4
        } else {
            byte & 0x0f
        };
        out.push(if nibble >= 8 {
            character.to_ascii_uppercase()
        } else {
            character
        });
    }
    out
}

/// Parses `0x` + 40 hex digits (lowercase `x` only) with the EIP-55 rule of spec/03 §2.1.
/// The zero address parses (risk rules handle it).
///
/// # Errors
///
/// [`AddressError::InvalidFormat`] or [`AddressError::BadChecksum`].
pub fn parse_address(text: &str) -> Result<Address, AddressError> {
    let digits = text.strip_prefix("0x").ok_or(AddressError::InvalidFormat)?;
    let mut bytes = [0_u8; 20];
    hex::decode_into(digits.as_bytes(), &mut bytes, true)
        .map_err(|_| AddressError::InvalidFormat)?;
    let address = Address(bytes);
    let has_lower = digits.bytes().any(|byte| byte.is_ascii_lowercase());
    let has_upper = digits.bytes().any(|byte| byte.is_ascii_uppercase());
    if has_lower && has_upper && to_checksum(&address) != text {
        return Err(AddressError::BadChecksum);
    }
    Ok(address)
}

#[cfg(test)]
mod tests;
