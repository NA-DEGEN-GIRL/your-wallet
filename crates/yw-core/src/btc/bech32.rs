//! bech32 / bech32m (BIP173, BIP350; spec/08 §6.2), implemented here (D6).
//!
//! Two layers: the string codec ([`decode`], [`encode`]) checks length, characters, case,
//! separator and the checksum constant and reports which variant matched; the segwit layer
//! ([`decode_segwit`], [`encode_segwit`]) adds the witness version, the 5→8-bit conversion with
//! its padding rules, the program length and the variant required by the version. Address policy
//! (networks, P2A, Taproot keys, v2–v16) is `btc::address`.
#![deny(clippy::indexing_slicing)]

use core::fmt;

/// The 32 data characters in value order.
pub const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
/// Shortest accepted string.
pub const MIN_LEN: usize = 8;
/// Longest accepted string.
pub const MAX_LEN: usize = 90;
/// Checksum length in characters.
pub const CHECKSUM_LEN: usize = 6;
/// Shortest witness program.
pub const MIN_PROGRAM_LEN: usize = 2;
/// Longest witness program.
pub const MAX_PROGRAM_LEN: usize = 40;
/// Highest witness version.
pub const MAX_WITNESS_VERSION: u8 = 16;

const GENERATOR: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];
const BECH32_CONST: u32 = 1;
const BECH32M_CONST: u32 = 0x2bc8_30a3;

/// Checksum variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Variant {
    /// BIP173 (constant 1): witness version 0.
    Bech32,
    /// BIP350 (constant `0x2bc830a3`): witness versions 1–16.
    Bech32m,
}

impl Variant {
    const fn constant(self) -> u32 {
        match self {
            Self::Bech32 => BECH32_CONST,
            Self::Bech32m => BECH32M_CONST,
        }
    }
}

/// bech32 decoding or encoding failure. Each rule has its own value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bech32Error {
    /// Shorter than 8 or longer than 90 characters.
    InvalidLength,
    /// A character outside 0x21–0x7E, or a data character outside [`CHARSET`].
    InvalidCharacter,
    /// Both lowercase and uppercase letters.
    MixedCase,
    /// No `'1'` separator.
    NoSeparator,
    /// Nothing before the separator.
    EmptyHrp,
    /// Fewer than 6 data characters (no room for the checksum).
    ShortData,
    /// The checksum matches neither variant.
    Checksum,
    /// No witness version, or a version above 16.
    InvalidWitnessVersion,
    /// More than 4 padding bits, or non-zero padding, in the 5→8-bit conversion.
    InvalidPadding,
    /// Program outside 2–40 bytes, or a v0 program that is not 20 or 32 bytes.
    InvalidProgramLength,
    /// v0 with a bech32m checksum, or v1+ with a bech32 checksum.
    WrongChecksumVariant,
}

impl fmt::Display for Bech32Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLength => "bech32 string length is out of range",
            Self::InvalidCharacter => "bech32 string has an invalid character",
            Self::MixedCase => "bech32 string mixes upper and lower case",
            Self::NoSeparator => "bech32 string has no separator",
            Self::EmptyHrp => "bech32 human-readable part is empty",
            Self::ShortData => "bech32 data part is shorter than the checksum",
            Self::Checksum => "bech32 checksum mismatch",
            Self::InvalidWitnessVersion => "invalid witness version",
            Self::InvalidPadding => "invalid bech32 padding",
            Self::InvalidProgramLength => "invalid witness program length",
            Self::WrongChecksumVariant => "wrong bech32 checksum variant for the witness version",
        })
    }
}

impl std::error::Error for Bech32Error {}

/// A decoded bech32 string: lowercase HRP, 5-bit data values without the checksum, variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decoded {
    /// Human-readable part, lowercase.
    pub hrp: String,
    /// Data values (each `< 32`), checksum removed.
    pub data: Vec<u8>,
    /// Which checksum constant matched.
    pub variant: Variant,
}

/// A decoded segwit address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegwitAddress {
    /// Human-readable part, lowercase.
    pub hrp: String,
    /// Witness version 0–16.
    pub version: u8,
    /// Witness program, 2–40 bytes (20 or 32 for v0).
    pub program: Vec<u8>,
}

fn polymod_step(checksum: u32, value: u8) -> u32 {
    let top = checksum >> 25;
    let mut next = ((checksum & 0x01ff_ffff) << 5) ^ u32::from(value);
    for (bit, generator) in GENERATOR.iter().enumerate() {
        if (top >> bit) & 1 == 1 {
            next ^= generator;
        }
    }
    next
}

/// `polymod(hrp_expand(hrp) ‖ values)`.
fn polymod(hrp: &[u8], values: impl Iterator<Item = u8>) -> u32 {
    let mut checksum = 1_u32;
    for byte in hrp {
        checksum = polymod_step(checksum, byte >> 5);
    }
    checksum = polymod_step(checksum, 0);
    for byte in hrp {
        checksum = polymod_step(checksum, byte & 0x1f);
    }
    for value in values {
        checksum = polymod_step(checksum, value);
    }
    checksum
}

fn charset_value(character: u8) -> Option<u8> {
    CHARSET
        .iter()
        .position(|candidate| *candidate == character)
        .and_then(|value| u8::try_from(value).ok())
}

fn charset_char(value: u8) -> char {
    char::from(
        CHARSET
            .get(usize::from(value & 0x1f))
            .copied()
            .unwrap_or(b'q'),
    )
}

/// Decodes a bech32/bech32m string (BIP173 rules, either checksum constant).
///
/// Order: length 8–90, every byte 0x21–0x7E, no mixed case, last `'1'` separator, non-empty
/// HRP, at least 6 data characters from [`CHARSET`], checksum constant 1 or `0x2bc830a3`.
///
/// # Errors
///
/// The first failing rule's [`Bech32Error`].
pub fn decode(text: &str) -> Result<Decoded, Bech32Error> {
    let bytes = text.as_bytes();
    if !(MIN_LEN..=MAX_LEN).contains(&bytes.len()) {
        return Err(Bech32Error::InvalidLength);
    }
    if !bytes.iter().all(|byte| (0x21..=0x7e).contains(byte)) {
        return Err(Bech32Error::InvalidCharacter);
    }
    if bytes.iter().any(u8::is_ascii_lowercase) && bytes.iter().any(u8::is_ascii_uppercase) {
        return Err(Bech32Error::MixedCase);
    }
    let lower = text.to_ascii_lowercase();
    let lower = lower.as_bytes();
    let separator = lower
        .iter()
        .rposition(|byte| *byte == b'1')
        .ok_or(Bech32Error::NoSeparator)?;
    let (hrp, rest) = lower.split_at(separator);
    if hrp.is_empty() {
        return Err(Bech32Error::EmptyHrp);
    }
    let data_chars = rest.get(1..).unwrap_or_default();
    if data_chars.len() < CHECKSUM_LEN {
        return Err(Bech32Error::ShortData);
    }
    let mut values = Vec::with_capacity(data_chars.len());
    for character in data_chars {
        values.push(charset_value(*character).ok_or(Bech32Error::InvalidCharacter)?);
    }
    let variant = match polymod(hrp, values.iter().copied()) {
        BECH32_CONST => Variant::Bech32,
        BECH32M_CONST => Variant::Bech32m,
        _ => return Err(Bech32Error::Checksum),
    };
    values.truncate(data_chars.len().saturating_sub(CHECKSUM_LEN));
    Ok(Decoded {
        hrp: String::from_utf8_lossy(hrp).into_owned(),
        data: values,
        variant,
    })
}

/// `hrp ‖ '1' ‖ data ‖ checksum` without validation (callers pass a valid lowercase HRP and
/// 5-bit values; out-of-range bits are masked).
fn assemble(hrp: &str, values: &[u8], variant: Variant) -> String {
    let checksum = polymod(
        hrp.as_bytes(),
        values
            .iter()
            .map(|value| value & 0x1f)
            .chain([0_u8; CHECKSUM_LEN]),
    ) ^ variant.constant();
    let mut out = String::with_capacity(
        hrp.len()
            .saturating_add(1)
            .saturating_add(values.len())
            .saturating_add(CHECKSUM_LEN),
    );
    out.push_str(hrp);
    out.push('1');
    for value in values {
        out.push(charset_char(*value));
    }
    for shift in (0..CHECKSUM_LEN).rev() {
        let value = (checksum >> (5 * shift)) & 0x1f;
        out.push(charset_char(u8::try_from(value).unwrap_or(0)));
    }
    out
}

/// Encodes `hrp` (lowercased) and 5-bit `values` with the `variant` checksum.
///
/// # Errors
///
/// [`Bech32Error::EmptyHrp`], [`Bech32Error::InvalidCharacter`] (HRP byte outside 0x21–0x7E or
/// a value ≥ 32) or [`Bech32Error::InvalidLength`] (result outside 8–90 characters).
pub fn encode(hrp: &str, values: &[u8], variant: Variant) -> Result<String, Bech32Error> {
    if hrp.is_empty() {
        return Err(Bech32Error::EmptyHrp);
    }
    if !hrp.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) || values.iter().any(|v| *v > 31) {
        return Err(Bech32Error::InvalidCharacter);
    }
    let total = hrp
        .len()
        .saturating_add(1)
        .saturating_add(values.len())
        .saturating_add(CHECKSUM_LEN);
    if !(MIN_LEN..=MAX_LEN).contains(&total) {
        return Err(Bech32Error::InvalidLength);
    }
    Ok(assemble(&hrp.to_ascii_lowercase(), values, variant))
}

/// 8-bit bytes → 5-bit values, zero-padding the last group.
fn to_five_bits(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len().saturating_mul(8).div_ceil(5));
    let mut accumulator = 0_u32;
    let mut bits = 0_u32;
    for byte in bytes {
        accumulator = ((accumulator << 8) | u32::from(*byte)) & 0x0fff;
        bits = bits.saturating_add(8);
        while bits >= 5 {
            bits = bits.saturating_sub(5);
            out.push(u8::try_from((accumulator >> bits) & 0x1f).unwrap_or(0));
        }
    }
    if bits > 0 {
        out.push(u8::try_from((accumulator << (5_u32.saturating_sub(bits))) & 0x1f).unwrap_or(0));
    }
    out
}

/// 5-bit values → bytes; at most 4 padding bits, all zero.
fn from_five_bits(values: &[u8]) -> Result<Vec<u8>, Bech32Error> {
    let mut out = Vec::with_capacity(values.len().saturating_mul(5) / 8);
    let mut accumulator = 0_u32;
    let mut bits = 0_u32;
    for value in values {
        accumulator = ((accumulator << 5) | u32::from(*value)) & 0x0fff;
        bits = bits.saturating_add(5);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            out.push(u8::try_from((accumulator >> bits) & 0xff).unwrap_or(0));
        }
    }
    if bits >= 5 || (accumulator << (8_u32.saturating_sub(bits))) & 0xff != 0 {
        return Err(Bech32Error::InvalidPadding);
    }
    Ok(out)
}

/// Decodes a segwit address (spec/08 §6.2): [`decode`], then the witness version (present,
/// ≤ 16), the 5→8-bit conversion (≤ 4 zero padding bits), program 2–40 bytes, v0 = bech32 with a
/// 20- or 32-byte program, v1+ = bech32m.
///
/// # Errors
///
/// The [`decode`] errors, then [`Bech32Error::InvalidWitnessVersion`],
/// [`Bech32Error::InvalidPadding`], [`Bech32Error::InvalidProgramLength`] or
/// [`Bech32Error::WrongChecksumVariant`].
pub fn decode_segwit(text: &str) -> Result<SegwitAddress, Bech32Error> {
    let decoded = decode(text)?;
    let (version, rest) = decoded
        .data
        .split_first()
        .ok_or(Bech32Error::InvalidWitnessVersion)?;
    if *version > MAX_WITNESS_VERSION {
        return Err(Bech32Error::InvalidWitnessVersion);
    }
    let program = from_five_bits(rest)?;
    if !(MIN_PROGRAM_LEN..=MAX_PROGRAM_LEN).contains(&program.len()) {
        return Err(Bech32Error::InvalidProgramLength);
    }
    let expected = if *version == 0 {
        Variant::Bech32
    } else {
        Variant::Bech32m
    };
    if decoded.variant != expected {
        return Err(Bech32Error::WrongChecksumVariant);
    }
    if *version == 0 && program.len() != 20 && program.len() != 32 {
        return Err(Bech32Error::InvalidProgramLength);
    }
    Ok(SegwitAddress {
        hrp: decoded.hrp,
        version: *version,
        program,
    })
}

/// Lowercase segwit address without validation (the caller guarantees version ≤ 16 and a
/// valid program length; used for our fixed 20/32-byte programs).
pub(crate) fn segwit_string(hrp: &str, version: u8, program: &[u8]) -> String {
    let mut values = Vec::with_capacity(
        program
            .len()
            .saturating_mul(8)
            .div_ceil(5)
            .saturating_add(1),
    );
    values.push(version & 0x1f);
    values.extend(to_five_bits(program));
    let variant = if version == 0 {
        Variant::Bech32
    } else {
        Variant::Bech32m
    };
    assemble(hrp, &values, variant)
}

/// Encodes a segwit address in lowercase (bech32 for v0, bech32m for v1+).
///
/// # Errors
///
/// [`Bech32Error::InvalidWitnessVersion`], [`Bech32Error::InvalidProgramLength`], or the
/// [`encode`] HRP errors.
pub fn encode_segwit(hrp: &str, version: u8, program: &[u8]) -> Result<String, Bech32Error> {
    if version > MAX_WITNESS_VERSION {
        return Err(Bech32Error::InvalidWitnessVersion);
    }
    if !(MIN_PROGRAM_LEN..=MAX_PROGRAM_LEN).contains(&program.len())
        || (version == 0 && program.len() != 20 && program.len() != 32)
    {
        return Err(Bech32Error::InvalidProgramLength);
    }
    let mut values = Vec::with_capacity(
        program
            .len()
            .saturating_mul(8)
            .div_ceil(5)
            .saturating_add(1),
    );
    values.push(version);
    values.extend(to_five_bits(program));
    let variant = if version == 0 {
        Variant::Bech32
    } else {
        Variant::Bech32m
    };
    encode(hrp, &values, variant)
}
