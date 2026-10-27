//! compact-u16 (`short_vec`, spec/07 §6): 7 bits per byte, little-endian, continuation bit 0x80,
//! 1–3 bytes. The decoder rejects non-minimal encodings and values above `0xffff`.

use core::fmt;

/// compact-u16 decoding failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShortVecError {
    /// The input ends inside the value.
    Truncated,
    /// The third byte has more than 2 value bits or a continuation bit.
    Overflow,
    /// A non-minimal encoding (`80 00`, `80 80 00`).
    Alias,
}

impl fmt::Display for ShortVecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Truncated => "compact-u16 truncated",
            Self::Overflow => "compact-u16 overflow",
            Self::Alias => "compact-u16 non-minimal encoding",
        })
    }
}

impl std::error::Error for ShortVecError {}

/// Appends the encoding of `value`.
pub fn encode_into(value: u16, out: &mut Vec<u8>) {
    let mut rest = value;
    loop {
        let low = u8::try_from(rest & 0x7f).unwrap_or(0);
        rest >>= 7;
        if rest == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

/// The encoding of `value` (1–3 bytes).
#[must_use]
pub fn encode(value: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(3);
    encode_into(value, &mut out);
    out
}

/// Decodes one value from the start of `buf`; returns it and the bytes consumed.
///
/// # Errors
///
/// [`ShortVecError`].
pub fn decode(buf: &[u8]) -> Result<(u16, usize), ShortVecError> {
    let mut value: u32 = 0;
    for index in 0..3_usize {
        let byte = *buf.get(index).ok_or(ShortVecError::Truncated)?;
        if index == 2 && byte > 0x03 {
            return Err(ShortVecError::Overflow);
        }
        if index > 0 && byte == 0x00 {
            return Err(ShortVecError::Alias);
        }
        let shift = u32::try_from(index.saturating_mul(7)).unwrap_or(0);
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            let value = u16::try_from(value).map_err(|_| ShortVecError::Overflow)?;
            return Ok((value, index.saturating_add(1)));
        }
    }
    Err(ShortVecError::Overflow)
}

#[cfg(test)]
mod tests {
    use super::{ShortVecError, decode, encode};

    #[test]
    fn solana_sdk_short_vec_vectors() {
        let table: [(u16, &[u8]); 9] = [
            (0x0, &[0x00]),
            (0x7f, &[0x7f]),
            (0x80, &[0x80, 0x01]),
            (0xff, &[0xff, 0x01]),
            (0x100, &[0x80, 0x02]),
            (0x3fff, &[0xff, 0x7f]),
            (0x4000, &[0x80, 0x80, 0x01]),
            (0x7fff, &[0xff, 0xff, 0x01]),
            (0xffff, &[0xff, 0xff, 0x03]),
        ];
        for (value, bytes) in table {
            assert_eq!(encode(value), bytes, "{value:#x}");
            assert_eq!(decode(bytes), Ok((value, bytes.len())), "{value:#x}");
        }
        let mut with_tail = encode(0x80);
        with_tail.push(0x55);
        assert_eq!(decode(&with_tail), Ok((0x80, 2)));
    }

    #[test]
    fn rejections() {
        assert_eq!(decode(&[0x80, 0x00]), Err(ShortVecError::Alias));
        assert_eq!(decode(&[0x80, 0x80, 0x00]), Err(ShortVecError::Alias));
        assert_eq!(decode(&[0xff, 0xff, 0x04]), Err(ShortVecError::Overflow));
        assert_eq!(decode(&[0x80, 0x80, 0x80]), Err(ShortVecError::Overflow));
        assert_eq!(decode(&[0x80]), Err(ShortVecError::Truncated));
        assert_eq!(decode(&[]), Err(ShortVecError::Truncated));
    }

    #[test]
    fn every_value_round_trips() {
        for value in 0..=u16::MAX {
            let bytes = encode(value);
            assert_eq!(decode(&bytes), Ok((value, bytes.len())));
        }
    }
}
