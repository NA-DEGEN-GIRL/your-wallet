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

impl AddressError {
    /// The fixed text in `lang` (`Display` is the Korean one).
    #[must_use]
    pub const fn text_in(self, lang: crate::lang::Lang) -> &'static str {
        match self {
            Self::InvalidFormat => text::INVALID_FORMAT,
            Self::BadChecksum => text::BAD_CHECKSUM,
        }
        .get(lang)
    }
}

impl fmt::Display for AddressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.text_in(crate::lang::Lang::Ko))
    }
}

/// Address parsing texts (spec/03 §2.2; English spec/14 §5).
pub mod text {
    crate::texts! {
        INVALID_FORMAT = "주소 형식이 올바르지 않습니다." / "The address format is invalid.";
        BAD_CHECKSUM = "주소의 대소문자 체크섬이 맞지 않습니다. 주소를 다시 확인하세요."
            / "The address's upper/lower-case checksum does not match. Check the address again.";
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

/// An address the user knows (spec/04 §2.15 rows 6–7): an address-book entry, one of the
/// wallet's own accounts, or a past recipient (sent history). The send forms and the approval
/// rule E43 (spec/03 §10.2) compare recipients with these for look-alikes (W-ADDR-3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownAddress {
    /// Address.
    pub address: Address,
    /// Book name or account label (the lowercase address for a history entry).
    pub name: String,
    /// Book entry marked verified.
    pub verified: bool,
    /// One of the wallet's own accounts.
    pub mine: bool,
    /// A past recipient (journal record or activity row): compared for look-alikes only — an
    /// exact match gives no book note and it is not offered by the picker.
    pub history: bool,
}

impl KnownAddress {
    /// An exact match needs no look-alike check: the wallet's own account, or an address-book
    /// entry the user verified out of band. An unverified book entry may itself be a saved
    /// poisoned address, so a recipient equal to one is still compared with the others.
    #[must_use]
    pub const fn trusted(&self) -> bool {
        self.mine || (self.verified && !self.history)
    }
}

/// Matching end digits (prefix + suffix) that make two different addresses look-alikes.
pub const LOOK_ALIKE_MIN_ENDS: usize = 6;

fn nibbles(address: &Address) -> impl DoubleEndedIterator<Item = u8> + '_ {
    address
        .as_bytes()
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
}

/// W-ADDR-3 address-poisoning check: `Some((prefix, suffix))` when `typed` is a look-alike of
/// `known`.
///
/// Rule: the two addresses differ (so some middle digit mismatches), and there is a split
/// `p + s ≥ 6` where the first `p` and the last `s` of the 40 hex digits are equal (after `0x`,
/// case-insensitive: checksum casing is ignored). Any split counts — 6+0, 4+2, 3+3, 2+4, 0+6 —
/// because poisoners grind whichever ends a wallet shows, and some show only the head or only
/// the tail. Checking every split is the same as `P + S ≥ 6` for the longest common prefix `P`
/// and suffix `S`, which are returned.
///
/// False positives: for a random 40-digit address, `P(P + S ≥ 6) = 16⁻⁶ · (1 + 6 · 15/16) ≈
/// 3.9e-7` per known address (≈ the 7 splits × 16⁻⁶ ≈ 4e-7 union bound). Even with the full
/// activity history (3,000 rows) plus book and accounts that stays near 1e-3 per typed
/// address, and a false positive only asks for the `주소 전체를 직접 확인했습니다` checkbox; so no
/// per-side minimum is imposed. Five matching end digits (e.g. 3+2) are not flagged: that
/// would be ≈ 16⁻⁵ · 5.7 ≈ 5.4e-6 per known address, i.e. ~1.6 % of honest addresses warned
/// against a full history.
#[must_use]
pub fn look_alike(known: &Address, typed: &Address) -> Option<(usize, usize)> {
    if known == typed {
        return None;
    }
    let prefix = nibbles(known)
        .zip(nibbles(typed))
        .take_while(|(a, b)| a == b)
        .count();
    let suffix = nibbles(known)
        .rev()
        .zip(nibbles(typed).rev())
        .take_while(|(a, b)| a == b)
        .count();
    (prefix.saturating_add(suffix) >= LOOK_ALIKE_MIN_ENDS).then_some((prefix, suffix))
}

/// The look-alike entry with the most matching end digits; on a tie the earlier entry (book and
/// own accounts come before history).
#[must_use]
pub fn closest_look_alike<'k>(
    known: &'k [KnownAddress],
    address: &Address,
) -> Option<(&'k KnownAddress, (usize, usize))> {
    let mut best: Option<(&KnownAddress, (usize, usize))> = None;
    for entry in known {
        if let Some(ends) = look_alike(&entry.address, address)
            && best.is_none_or(|(_, (p, s))| ends.0.saturating_add(ends.1) > p.saturating_add(s))
        {
            best = Some((entry, ends));
        }
    }
    best
}

/// The W-ADDR-3 finding for a recipient (spec/04 §2.15 row 7, spec/03 E43): the closest
/// look-alike among `known`, unless the recipient is exactly a trusted entry
/// ([`KnownAddress::trusted`]). An exact match with an unverified book entry or a past
/// recipient does not end the check — a poisoned address saved to the book, or sent to once,
/// must not silence the warning against the address it imitates.
#[must_use]
pub fn poisoning_look_alike<'k>(
    known: &'k [KnownAddress],
    address: &Address,
) -> Option<(&'k KnownAddress, (usize, usize))> {
    if known
        .iter()
        .any(|entry| entry.address == *address && entry.trusted())
    {
        return None;
    }
    closest_look_alike(known, address)
}

#[cfg(test)]
mod tests;
