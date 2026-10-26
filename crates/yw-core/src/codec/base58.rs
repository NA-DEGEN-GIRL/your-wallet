//! Base58 (Bitcoin alphabet) and `Base58Check` with a 4-byte SHA-256d checksum (D6).
//!
//! Shared by BIP32 extended keys (M1), Solana (M7) and Bitcoin (M8). Intermediate buffers are
//! zeroized because extended private keys pass through here.
#![deny(clippy::indexing_slicing)]

use core::fmt;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
/// Longest accepted text for decoding (callers have far shorter formats).
pub const MAX_DECODE_INPUT: usize = 1_024;
const CHECKSUM_LEN: usize = 4;

/// Base58 decoding failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Base58Error {
    /// A character outside the Base58 alphabet.
    InvalidCharacter,
    /// `Base58Check` checksum mismatch.
    InvalidChecksum,
    /// `Base58Check` input shorter than the checksum.
    InvalidLength,
    /// Input longer than [`MAX_DECODE_INPUT`].
    TooLong,
}

impl fmt::Display for Base58Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCharacter => "base58 text contains an invalid character",
            Self::InvalidChecksum => "base58check checksum mismatch",
            Self::InvalidLength => "base58check payload is too short",
            Self::TooLong => "base58 text is too long",
        })
    }
}

impl std::error::Error for Base58Error {}

/// Base58-encodes `bytes`.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(max_encoded_len(bytes.len()));
    encode_into(bytes, &mut out);
    out
}

/// Decodes Base58 text.
///
/// # Errors
///
/// [`Base58Error::TooLong`] or [`Base58Error::InvalidCharacter`].
pub fn decode(text: &str) -> Result<Vec<u8>, Base58Error> {
    let mut decoded = decode_secret(text)?;
    Ok(core::mem::take(&mut *decoded))
}

/// `Base58Check`-encodes `payload` (appends `SHA-256(SHA-256(payload))[0..4]`).
#[must_use]
pub fn encode_check(payload: &[u8]) -> String {
    let mut out =
        String::with_capacity(max_encoded_len(payload.len().saturating_add(CHECKSUM_LEN)));
    encode_check_into(payload, &mut out);
    out
}

/// Decodes `Base58Check` text and verifies the checksum; returns the payload.
///
/// # Errors
///
/// Any [`Base58Error`].
pub fn decode_check(text: &str) -> Result<Vec<u8>, Base58Error> {
    let mut payload = decode_check_secret(text)?;
    Ok(core::mem::take(&mut *payload))
}

/// Upper bound of the encoded length (log(256)/log(58) < 1.37).
pub(crate) const fn max_encoded_len(bytes: usize) -> usize {
    bytes
        .saturating_mul(137)
        .saturating_div(100)
        .saturating_add(1)
}

/// Appends the Base58 encoding of `bytes` to `out` (pre-sized by secret callers).
pub(crate) fn encode_into(bytes: &[u8], out: &mut String) {
    let zeros = bytes.iter().take_while(|byte| **byte == 0).count();
    // Little-endian base-58 digits.
    let mut digits: Zeroizing<Vec<u8>> =
        Zeroizing::new(Vec::with_capacity(max_encoded_len(bytes.len())));
    for byte in bytes.iter().skip(zeros) {
        let mut carry = u32::from(*byte);
        for digit in digits.iter_mut() {
            carry += u32::from(*digit) << 8;
            *digit = u8::try_from(carry % 58).unwrap_or(0);
            carry /= 58;
        }
        while carry > 0 {
            digits.push(u8::try_from(carry % 58).unwrap_or(0));
            carry /= 58;
        }
    }
    for _ in 0..zeros {
        out.push('1');
    }
    for digit in digits.iter().rev() {
        out.push(char::from(
            ALPHABET.get(usize::from(*digit)).copied().unwrap_or(b'1'),
        ));
    }
}

pub(crate) fn encode_check_into(payload: &[u8], out: &mut String) {
    let mut buffer: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(
        payload.len().saturating_add(CHECKSUM_LEN),
    ));
    buffer.extend_from_slice(payload);
    buffer.extend_from_slice(&checksum(payload));
    encode_into(&buffer, out);
}

fn checksum(payload: &[u8]) -> [u8; CHECKSUM_LEN] {
    let digest = Sha256::digest(Sha256::digest(payload));
    let mut out = [0_u8; CHECKSUM_LEN];
    for (slot, byte) in out.iter_mut().zip(digest.iter()) {
        *slot = *byte;
    }
    out
}

fn value_of(character: u8) -> Option<u8> {
    ALPHABET
        .iter()
        .position(|candidate| *candidate == character)
        .and_then(|index| u8::try_from(index).ok())
}

/// Decodes into a zeroizing buffer.
pub(crate) fn decode_secret(text: &str) -> Result<Zeroizing<Vec<u8>>, Base58Error> {
    if text.len() > MAX_DECODE_INPUT {
        return Err(Base58Error::TooLong);
    }
    let bytes = text.as_bytes();
    let zeros = bytes.iter().take_while(|byte| **byte == b'1').count();
    // Little-endian base-256 bytes.
    let mut number: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(bytes.len()));
    for character in bytes.iter().skip(zeros) {
        let mut carry = u32::from(value_of(*character).ok_or(Base58Error::InvalidCharacter)?);
        for byte in number.iter_mut() {
            carry += u32::from(*byte) * 58;
            *byte = u8::try_from(carry & 0xff).unwrap_or(0);
            carry >>= 8;
        }
        while carry > 0 {
            number.push(u8::try_from(carry & 0xff).unwrap_or(0));
            carry >>= 8;
        }
    }
    let mut out: Zeroizing<Vec<u8>> =
        Zeroizing::new(Vec::with_capacity(zeros.saturating_add(number.len())));
    out.resize(zeros, 0);
    out.extend(number.iter().rev());
    Ok(out)
}

pub(crate) fn decode_check_secret(text: &str) -> Result<Zeroizing<Vec<u8>>, Base58Error> {
    let mut decoded = decode_secret(text)?;
    let payload_len = decoded
        .len()
        .checked_sub(CHECKSUM_LEN)
        .ok_or(Base58Error::InvalidLength)?;
    let (payload, check) = decoded.split_at(payload_len);
    if check != checksum(payload) {
        return Err(Base58Error::InvalidChecksum);
    }
    decoded.truncate(payload_len);
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::{Base58Error, decode, decode_check, encode, encode_check};

    #[test]
    fn check_round_trip_and_rejections() {
        let text = encode_check(&[0x00, 0x01, 0x02]);
        assert_eq!(decode_check(&text), Ok(vec![0x00, 0x01, 0x02]));
        let mut tampered = text.into_bytes();
        if let Some(last) = tampered.last_mut() {
            *last = if *last == b'2' { b'3' } else { b'2' };
        }
        let tampered = String::from_utf8(tampered).unwrap();
        assert_eq!(decode_check(&tampered), Err(Base58Error::InvalidChecksum));
        assert_eq!(decode_check("1"), Err(Base58Error::InvalidLength));
        assert_eq!(decode("0OIl"), Err(Base58Error::InvalidCharacter));
        assert_eq!(decode(&"1".repeat(1_025)), Err(Base58Error::TooLong));
        assert_eq!(encode(&[]), "");
        assert_eq!(decode("111"), Ok(vec![0, 0, 0]));
    }
}
