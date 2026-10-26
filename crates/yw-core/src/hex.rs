//! Strict hexadecimal (spec/01 §2.2 `hex`). Decoding is lowercase-only and fixed-width unless a
//! caller explicitly opts into mixed case (raw private key import, spec/02 §8.2). No prefix
//! handling here: callers strip `0x` themselves so each format keeps its own prefix rule.

use core::fmt;

const LOWER: &[u8; 16] = b"0123456789abcdef";

/// Hex decoding failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HexError {
    /// Wrong number of digits.
    InvalidLength,
    /// A character outside the accepted alphabet.
    InvalidDigit,
}

impl fmt::Display for HexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLength => "hex value has the wrong length",
            Self::InvalidDigit => "hex value contains an invalid digit",
        })
    }
}

impl std::error::Error for HexError {}

/// Lowercase hex without prefix.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    encode_into(bytes, &mut out);
    out
}

/// Appends lowercase hex to `out`. Callers holding secrets pre-size `out` so it never reallocates.
pub fn encode_into(bytes: &[u8], out: &mut String) {
    for byte in bytes {
        out.push(digit(byte >> 4));
        out.push(digit(byte & 0x0f));
    }
}

fn digit(nibble: u8) -> char {
    char::from(LOWER.get(usize::from(nibble)).copied().unwrap_or(b'0'))
}

const fn nibble(byte: u8, allow_upper: bool) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' if allow_upper => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decodes `digits` into `out` exactly (2 digits per byte).
pub(crate) fn decode_into(
    digits: &[u8],
    out: &mut [u8],
    allow_upper: bool,
) -> Result<(), HexError> {
    if digits.len() != out.len().saturating_mul(2) {
        return Err(HexError::InvalidLength);
    }
    for (slot, pair) in out.iter_mut().zip(digits.chunks_exact(2)) {
        let [high, low] = pair else {
            return Err(HexError::InvalidLength);
        };
        let high = nibble(*high, allow_upper).ok_or(HexError::InvalidDigit)?;
        let low = nibble(*low, allow_upper).ok_or(HexError::InvalidDigit)?;
        *slot = (high << 4) | low;
    }
    Ok(())
}

/// Decodes exactly `2 * N` lowercase digits.
///
/// # Errors
///
/// [`HexError`] for a wrong length or a non-lowercase-hex character.
pub fn decode_array<const N: usize>(digits: &str) -> Result<[u8; N], HexError> {
    let mut out = [0_u8; N];
    decode_into(digits.as_bytes(), &mut out, false)?;
    Ok(out)
}

/// Decodes an even number of lowercase digits.
///
/// # Errors
///
/// [`HexError`] for an odd length or a non-lowercase-hex character.
pub fn decode(digits: &str) -> Result<Vec<u8>, HexError> {
    if !digits.len().is_multiple_of(2) {
        return Err(HexError::InvalidLength);
    }
    let mut out = vec![0_u8; digits.len() / 2];
    decode_into(digits.as_bytes(), &mut out, false)?;
    Ok(out)
}

/// Compile-time decoding of trusted constant hex (`2 * N` digits, either case, no prefix).
/// Invalid digits decode as 0; every constant built with it is checked by a test.
pub(crate) const fn const_decode<const N: usize>(text: &str) -> [u8; N] {
    let digits = text.as_bytes();
    let mut out = [0_u8; N];
    let mut index = 0;
    while index < N {
        let high_index = index.wrapping_mul(2);
        let low_index = high_index.wrapping_add(1);
        let high = if high_index < digits.len() {
            digits[high_index]
        } else {
            b'0'
        };
        let low = if low_index < digits.len() {
            digits[low_index]
        } else {
            b'0'
        };
        let high = match nibble(high, true) {
            Some(value) => value,
            None => 0,
        };
        let low = match nibble(low, true) {
            Some(value) => value,
            None => 0,
        };
        out[index] = (high << 4) | low;
        index = index.wrapping_add(1);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{HexError, const_decode, decode, decode_array, decode_into, encode};

    #[test]
    fn const_decoding() {
        assert_eq!(const_decode::<3>("00aBff"), [0x00, 0xab, 0xff]);
    }

    #[test]
    fn strict_round_trip() {
        assert_eq!(encode(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(decode("00abff"), Ok(vec![0x00, 0xab, 0xff]));
        assert_eq!(decode(""), Ok(vec![]));
        assert_eq!(decode_array::<2>("0aff"), Ok([0x0a, 0xff]));
        assert_eq!(decode("0AFF"), Err(HexError::InvalidDigit));
        assert_eq!(decode("abc"), Err(HexError::InvalidLength));
        assert_eq!(decode_array::<2>("0aff00"), Err(HexError::InvalidLength));
        assert_eq!(decode("0g"), Err(HexError::InvalidDigit));
        assert_eq!(decode("0x00"), Err(HexError::InvalidDigit));
        let mut out = [0_u8; 2];
        decode_into(b"0AfF", &mut out, true).unwrap();
        assert_eq!(out, [0x0a, 0xff]);
    }
}
