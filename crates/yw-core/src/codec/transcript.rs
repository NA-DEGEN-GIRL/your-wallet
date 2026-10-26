//! Deterministic length-prefixed transcript (spec/03 §6.5, §11.3–§11.4).
//!
//! Ported unchanged in structure from `archive/spec-v2.4:crates/wallet-model/src/codec.rs:1-206`:
//! integers are big-endian, variable-length bytes and strings carry a `u32` big-endian length
//! prefix, and `push_optional` writes `0` or `1 ‖ value`. Top-level transcripts start with
//! [`Transcript::start_domain`].

use core::fmt;

/// Transcript construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecError {
    /// A variable-length field cannot be represented with a `u32` length.
    LengthOverflow,
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("canonical field length overflow")
    }
}

impl std::error::Error for CodecError {}

/// Values with a stable, architecture-independent binary representation.
pub trait CanonicalEncode {
    /// Appends the value to a transcript.
    ///
    /// # Errors
    ///
    /// [`CodecError::LengthOverflow`] for variable-length values longer than `u32::MAX`.
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError>;
}

/// A deterministic length-prefixed transcript writer.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Transcript {
    bytes: Vec<u8>,
}

impl Transcript {
    /// Creates a versioned top-level transcript with an ASCII domain separator.
    ///
    /// # Errors
    ///
    /// [`CodecError::LengthOverflow`] if the domain is longer than `u32::MAX` bytes.
    pub fn start_domain(domain: &str, version: u16) -> Result<Self, CodecError> {
        let mut transcript = Self::default();
        transcript.push_bytes(domain.as_bytes())?;
        transcript.push_u16(version);
        Ok(transcript)
    }

    /// Appends one byte.
    pub fn push_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    /// Appends a boolean as exactly 0 or 1.
    pub fn push_bool(&mut self, value: bool) {
        self.push_u8(u8::from(value));
    }

    /// Appends a big-endian `u16`.
    pub fn push_u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Appends a big-endian `u32`.
    pub fn push_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Appends a big-endian `u64`.
    pub fn push_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Appends length-prefixed bytes.
    ///
    /// # Errors
    ///
    /// [`CodecError::LengthOverflow`] if `value` is longer than `u32::MAX` bytes.
    pub fn push_bytes(&mut self, value: &[u8]) -> Result<(), CodecError> {
        let length = u32::try_from(value.len()).map_err(|_| CodecError::LengthOverflow)?;
        self.push_u32(length);
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    /// Appends a UTF-8 string with the same framing as bytes.
    ///
    /// # Errors
    ///
    /// [`CodecError::LengthOverflow`] if `value` is longer than `u32::MAX` bytes.
    pub fn push_str(&mut self, value: &str) -> Result<(), CodecError> {
        self.push_bytes(value.as_bytes())
    }

    /// Appends an optional value with an explicit presence tag (`0` or `1 ‖ value`).
    ///
    /// # Errors
    ///
    /// Propagates the inner value's encoding error.
    pub fn push_optional<T: CanonicalEncode>(
        &mut self,
        value: Option<&T>,
    ) -> Result<(), CodecError> {
        if let Some(inner) = value {
            self.push_u8(1);
            inner.encode(self)
        } else {
            self.push_u8(0);
            Ok(())
        }
    }

    /// Appends raw bytes without a length prefix (fixed-width values only).
    pub(crate) fn push_fixed(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    /// The transcript bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the transcript.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl CanonicalEncode for u8 {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        transcript.push_u8(*self);
        Ok(())
    }
}

impl CanonicalEncode for u16 {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        transcript.push_u16(*self);
        Ok(())
    }
}

impl CanonicalEncode for u32 {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        transcript.push_u32(*self);
        Ok(())
    }
}

impl CanonicalEncode for u64 {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        transcript.push_u64(*self);
        Ok(())
    }
}

impl CanonicalEncode for bool {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        transcript.push_bool(*self);
        Ok(())
    }
}

impl<const N: usize> CanonicalEncode for [u8; N] {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        transcript.push_fixed(self);
        Ok(())
    }
}

impl<T: CanonicalEncode> CanonicalEncode for Vec<T> {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        let length = u32::try_from(self.len()).map_err(|_| CodecError::LengthOverflow)?;
        transcript.push_u32(length);
        for item in self {
            item.encode(transcript)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{CanonicalEncode, Transcript};

    // archive/spec-v2.4:crates/wallet-model/src/codec.rs:190-205
    #[test]
    fn transcript_is_big_endian_and_length_prefixed() {
        let mut transcript = Transcript::start_domain("x", 1).unwrap();
        0x0203_u16.encode(&mut transcript).unwrap();
        let mut five = [0_u8; 32];
        five[31] = 5;
        five.encode(&mut transcript).unwrap();
        let bytes = transcript.as_bytes();
        assert_eq!(bytes.get(..7).unwrap(), &[0, 0, 0, 1, b'x', 0, 1]);
        assert_eq!(bytes.get(7..9).unwrap(), &[2, 3]);
        assert_eq!(bytes.get(bytes.len() - 2..).unwrap(), &[0, 5]);
    }

    #[test]
    fn optional_and_vectors() {
        let mut transcript = Transcript::default();
        transcript.push_optional::<u64>(None).unwrap();
        transcript.push_optional(Some(&7_u64)).unwrap();
        vec![1_u8, 2].encode(&mut transcript).unwrap();
        transcript.push_str("ab").unwrap();
        assert_eq!(
            transcript.into_bytes(),
            vec![
                0, 1, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 2, 1, 2, 0, 0, 0, 2, b'a', b'b'
            ]
        );
    }
}
