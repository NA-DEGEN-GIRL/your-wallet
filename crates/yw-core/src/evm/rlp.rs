//! The single RLP implementation (spec/03 §4.1, D6).
//!
//! Encoder ported from `archive/spec-v2.4:crates/secret-core/src/signing.rs:167-248` with the
//! saturating length arithmetic replaced by exact conversions; strict decoder ported from
//! `archive/spec-v2.4:crates/key-agent/src/lib.rs:799-905` (`MAX_RLP_DEPTH` 4).
#![deny(clippy::indexing_slicing)]

use core::fmt;

use super::amount::U256;

/// Maximum decoder input (geth txpool transaction size, spec/03 §4.1).
pub const MAX_RLP_INPUT: usize = 131_072;
/// Maximum list nesting accepted by the decoder (the outer list is depth 0).
pub const MAX_RLP_DEPTH: usize = 4;

/// A decoded RLP item borrowing from the input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item<'a> {
    /// A byte string.
    Bytes(&'a [u8]),
    /// A list.
    List(Vec<Item<'a>>),
}

/// RLP decoding failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RlpError {
    /// Non-canonical or truncated encoding, or trailing bytes.
    Malformed,
    /// Input longer than [`MAX_RLP_INPUT`].
    TooLarge,
    /// Nesting deeper than [`MAX_RLP_DEPTH`].
    TooDeep,
    /// Expected a byte string.
    NotBytes,
    /// Expected a list.
    NotList,
    /// Integer with a leading zero byte, or longer than the field allows.
    InvalidInteger,
}

impl fmt::Display for RlpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "malformed RLP",
            Self::TooLarge => "RLP input too large",
            Self::TooDeep => "RLP nesting too deep",
            Self::NotBytes => "RLP item is not a byte string",
            Self::NotList => "RLP item is not a list",
            Self::InvalidInteger => "non-canonical RLP integer",
        })
    }
}

impl std::error::Error for RlpError {}

impl<'a> Item<'a> {
    /// The byte string, or [`RlpError::NotBytes`].
    ///
    /// # Errors
    ///
    /// [`RlpError::NotBytes`] for a list.
    pub fn as_bytes(&self) -> Result<&'a [u8], RlpError> {
        match self {
            Self::Bytes(bytes) => Ok(bytes),
            Self::List(_) => Err(RlpError::NotBytes),
        }
    }

    /// The list items, or [`RlpError::NotList`].
    ///
    /// # Errors
    ///
    /// [`RlpError::NotList`] for a byte string.
    pub fn as_list(&self) -> Result<&[Self], RlpError> {
        match self {
            Self::List(items) => Ok(items),
            Self::Bytes(_) => Err(RlpError::NotList),
        }
    }
}

fn minimal_len_bytes(length: usize) -> Vec<u8> {
    let bytes = u64::try_from(length).unwrap_or(u64::MAX).to_be_bytes();
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    bytes.get(start..).unwrap_or(&[]).to_vec()
}

fn encode_header(out: &mut Vec<u8>, short_base: u8, long_base: u8, length: usize) {
    if let Ok(short) = u8::try_from(length)
        && short <= 55
    {
        out.push(short_base.wrapping_add(short));
        return;
    }
    let length_bytes = minimal_len_bytes(length);
    let length_of_length = u8::try_from(length_bytes.len()).unwrap_or(8);
    out.push(long_base.wrapping_add(length_of_length));
    out.extend_from_slice(&length_bytes);
}

/// Appends an RLP byte string.
pub fn encode_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    if let [single] = bytes
        && *single < 0x80
    {
        out.push(*single);
        return;
    }
    encode_header(out, 0x80, 0xb7, bytes.len());
    out.extend_from_slice(bytes);
}

/// Appends an RLP list whose concatenated item encodings are `payload`.
pub fn encode_list(out: &mut Vec<u8>, payload: &[u8]) {
    encode_header(out, 0xc0, 0xf7, payload.len());
    out.extend_from_slice(payload);
}

/// Appends a minimal big-endian integer (zero is the empty string `0x80`).
pub fn encode_u64(out: &mut Vec<u8>, value: u64) {
    let bytes = value.to_be_bytes();
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    encode_bytes(out, bytes.get(start..).unwrap_or(&[]));
}

/// Appends a minimal big-endian 256-bit integer.
pub fn encode_u256(out: &mut Vec<u8>, value: &U256) {
    encode_bytes(out, value.minimal_be());
}

/// Re-encodes a decoded item (used by the fuzz-lite round-trip invariant).
#[must_use]
pub fn encode_item(item: &Item<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    write_item(&mut out, item);
    out
}

fn write_item(out: &mut Vec<u8>, item: &Item<'_>) {
    match item {
        Item::Bytes(bytes) => encode_bytes(out, bytes),
        Item::List(items) => {
            let mut payload = Vec::new();
            for inner in items {
                write_item(&mut payload, inner);
            }
            encode_list(out, &payload);
        }
    }
}

/// Strictly decodes exactly one item spanning all of `bytes`.
///
/// # Errors
///
/// [`RlpError`] for trailing bytes, `0x81` + byte < 0x80, a long form for ≤ 55 bytes, a leading
/// zero in the length, a length past the input, depth > 4, or input > 131,072 bytes.
pub fn decode_exact(bytes: &[u8]) -> Result<Item<'_>, RlpError> {
    if bytes.len() > MAX_RLP_INPUT {
        return Err(RlpError::TooLarge);
    }
    let (item, rest) = decode_item(bytes, 0)?;
    if rest.is_empty() {
        Ok(item)
    } else {
        Err(RlpError::Malformed)
    }
}

fn split(bytes: &[u8], length: usize) -> Result<(&[u8], &[u8]), RlpError> {
    if bytes.len() < length {
        return Err(RlpError::Malformed);
    }
    Ok(bytes.split_at(length))
}

fn long_length(bytes: &[u8]) -> Result<usize, RlpError> {
    match bytes.first() {
        None | Some(0) => return Err(RlpError::Malformed),
        Some(_) => {}
    }
    if bytes.len() > 8 {
        return Err(RlpError::Malformed);
    }
    let mut length = 0_usize;
    for byte in bytes {
        length = length
            .checked_mul(256)
            .and_then(|value| value.checked_add(usize::from(*byte)))
            .ok_or(RlpError::Malformed)?;
    }
    if length < 56 {
        return Err(RlpError::Malformed);
    }
    Ok(length)
}

fn decode_item(bytes: &[u8], depth: usize) -> Result<(Item<'_>, &[u8]), RlpError> {
    if depth > MAX_RLP_DEPTH {
        return Err(RlpError::TooDeep);
    }
    let (&prefix, tail) = bytes.split_first().ok_or(RlpError::Malformed)?;
    match prefix {
        0x00..=0x7f => {
            let (single, rest) = split(bytes, 1)?;
            Ok((Item::Bytes(single), rest))
        }
        0x80..=0xb7 => {
            let length = usize::from(prefix.wrapping_sub(0x80));
            let (payload, rest) = split(tail, length)?;
            if let [single] = payload
                && *single < 0x80
            {
                return Err(RlpError::Malformed);
            }
            Ok((Item::Bytes(payload), rest))
        }
        0xb8..=0xbf => {
            let length_of_length = usize::from(prefix.wrapping_sub(0xb7));
            let (length_bytes, tail) = split(tail, length_of_length)?;
            let (payload, rest) = split(tail, long_length(length_bytes)?)?;
            Ok((Item::Bytes(payload), rest))
        }
        0xc0..=0xf7 => decode_list(tail, usize::from(prefix.wrapping_sub(0xc0)), depth),
        0xf8..=0xff => {
            let length_of_length = usize::from(prefix.wrapping_sub(0xf7));
            let (length_bytes, tail) = split(tail, length_of_length)?;
            decode_list(tail, long_length(length_bytes)?, depth)
        }
    }
}

fn decode_list(tail: &[u8], length: usize, depth: usize) -> Result<(Item<'_>, &[u8]), RlpError> {
    let (mut payload, rest) = split(tail, length)?;
    let mut items = Vec::new();
    while !payload.is_empty() {
        let (item, remaining) = decode_item(payload, depth.saturating_add(1))?;
        items.push(item);
        payload = remaining;
    }
    Ok((Item::List(items), rest))
}

/// A canonical unsigned integer field of at most `max_len` bytes (no leading zero; zero is empty).
///
/// # Errors
///
/// [`RlpError::NotBytes`] for a list, [`RlpError::InvalidInteger`] for a leading zero or length.
pub fn decode_uint<'a>(item: &Item<'a>, max_len: usize) -> Result<&'a [u8], RlpError> {
    let bytes = item.as_bytes()?;
    if bytes.len() > max_len || bytes.first() == Some(&0) {
        return Err(RlpError::InvalidInteger);
    }
    Ok(bytes)
}

/// A canonical `u64` field.
///
/// # Errors
///
/// As [`decode_uint`].
pub fn decode_u64(item: &Item<'_>) -> Result<u64, RlpError> {
    let bytes = decode_uint(item, 8)?;
    let mut word = [0_u8; 8];
    let start = 8_usize.saturating_sub(bytes.len());
    word.get_mut(start..)
        .ok_or(RlpError::InvalidInteger)?
        .copy_from_slice(bytes);
    Ok(u64::from_be_bytes(word))
}

/// A canonical 256-bit field.
///
/// # Errors
///
/// As [`decode_uint`].
pub fn decode_u256(item: &Item<'_>) -> Result<U256, RlpError> {
    let bytes = decode_uint(item, 32)?;
    U256::from_be_slice(bytes).ok_or(RlpError::InvalidInteger)
}

#[cfg(test)]
mod tests {
    use super::{
        Item, RlpError, decode_exact, decode_u64, decode_uint, encode_bytes, encode_item,
        encode_list, encode_u64,
    };

    #[test]
    fn spec_rejection_vectors() {
        // archive/spec-v2.4:crates/key-agent/src/lib.rs:959-964
        assert_eq!(decode_exact(&[0x81, 0x01]), Err(RlpError::Malformed));
        assert_eq!(decode_exact(&[0x01, 0x02]), Err(RlpError::Malformed));
        assert_eq!(decode_exact(&[0xb8, 0x01, 0x80]), Err(RlpError::Malformed));
    }

    #[test]
    fn more_rejections() {
        // long form with leading zero length byte
        assert_eq!(decode_exact(&[0xb9, 0x00, 0x38]), Err(RlpError::Malformed));
        // list long form for a short payload
        assert_eq!(decode_exact(&[0xf8, 0x01, 0x80]), Err(RlpError::Malformed));
        // length past the input
        assert_eq!(decode_exact(&[0x82, 0x01]), Err(RlpError::Malformed));
        assert_eq!(decode_exact(&[]), Err(RlpError::Malformed));
        // depth 5
        assert_eq!(
            decode_exact(&[0xc5, 0xc4, 0xc3, 0xc2, 0xc1, 0xc0]),
            Err(RlpError::TooDeep)
        );
        assert!(decode_exact(&[0xc4, 0xc3, 0xc2, 0xc1, 0xc0]).is_ok());
        let big = vec![0_u8; 131_073];
        assert_eq!(decode_exact(&big), Err(RlpError::TooLarge));
    }

    #[test]
    fn round_trips() {
        for payload in [
            vec![],
            vec![0x00],
            vec![0x7f],
            vec![0x80],
            vec![0xab; 55],
            vec![0xab; 56],
            vec![0xab; 1024],
        ] {
            let mut out = Vec::new();
            encode_bytes(&mut out, &payload);
            let item = decode_exact(&out).unwrap();
            assert_eq!(item, Item::Bytes(&payload));
            assert_eq!(encode_item(&item), out);
        }
        let mut inner = Vec::new();
        for _ in 0..30 {
            encode_bytes(&mut inner, b"ab");
        }
        let mut list = Vec::new();
        encode_list(&mut list, &inner);
        assert_eq!(list.first(), Some(&0xf8));
        assert_eq!(encode_item(&decode_exact(&list).unwrap()), list);
    }

    #[test]
    fn integers() {
        let mut out = Vec::new();
        encode_u64(&mut out, 0);
        assert_eq!(out, [0x80]);
        let item = decode_exact(&out).unwrap();
        assert_eq!(decode_u64(&item), Ok(0));
        let mut out = Vec::new();
        encode_u64(&mut out, 1024);
        assert_eq!(out, [0x82, 0x04, 0x00]);
        assert_eq!(decode_u64(&decode_exact(&out).unwrap()), Ok(1024));
        assert_eq!(
            decode_uint(&decode_exact(&[0x82, 0x00, 0x01]).unwrap(), 8),
            Err(RlpError::InvalidInteger)
        );
        assert_eq!(
            decode_u64(&decode_exact(&[0x89, 1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap()),
            Err(RlpError::InvalidInteger)
        );
        assert_eq!(
            decode_u64(&decode_exact(&[0xc0]).unwrap()),
            Err(RlpError::NotBytes)
        );
    }
}
