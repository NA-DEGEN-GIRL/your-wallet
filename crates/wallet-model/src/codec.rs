use core::fmt;

use crate::{Address20, BoundedBytes, BoundedText, Hash32, U256};

/// Deterministic transcript construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecError {
    /// A variable-length field cannot be represented as a `u32` length.
    LengthOverflow,
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthOverflow => formatter.write_str("canonical field length overflow"),
        }
    }
}

impl std::error::Error for CodecError {}

/// Trait for values with a stable, architecture-independent binary representation.
pub trait CanonicalEncode {
    /// Appends the value to a transcript.
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError>;
}

/// A deterministic length-prefixed transcript writer.
///
/// Integers are big-endian. Variable-length bytes and strings use a `u32`
/// length prefix. Callers must begin top-level objects with `start_domain`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Transcript {
    bytes: Vec<u8>,
}

impl Transcript {
    /// Creates a versioned top-level transcript with an ASCII domain separator.
    pub fn start_domain(domain: &str, version: u16) -> Result<Self, CodecError> {
        let mut transcript = Self::default();
        transcript.push_bytes(domain.as_bytes())?;
        transcript.push_u16(version);
        Ok(transcript)
    }

    /// Appends a single byte.
    pub fn push_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    /// Appends a boolean as exactly zero or one.
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
    pub fn push_bytes(&mut self, value: &[u8]) -> Result<(), CodecError> {
        let length = u32::try_from(value.len()).map_err(|_| CodecError::LengthOverflow)?;
        self.push_u32(length);
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    /// Appends a UTF-8 string using the same length framing as bytes.
    pub fn push_str(&mut self, value: &str) -> Result<(), CodecError> {
        self.push_bytes(value.as_bytes())
    }

    /// Appends an optional value with an explicit presence tag.
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

    /// Returns the transcript bytes without copying.
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

impl CanonicalEncode for U256 {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        transcript.bytes.extend_from_slice(self.as_be_bytes());
        Ok(())
    }
}

impl CanonicalEncode for Address20 {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        transcript.bytes.extend_from_slice(self.as_bytes());
        Ok(())
    }
}

impl CanonicalEncode for Hash32 {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        transcript.bytes.extend_from_slice(self.as_bytes());
        Ok(())
    }
}

impl<const MAX: usize> CanonicalEncode for BoundedBytes<MAX> {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        transcript.push_bytes(self.as_slice())
    }
}

impl<const MAX: usize> CanonicalEncode for BoundedText<MAX> {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        transcript.push_str(self.as_str())
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
    use crate::U256;

    #[test]
    fn transcript_is_big_endian_and_length_prefixed() -> Result<(), super::CodecError> {
        let mut transcript = Transcript::start_domain("x", 1)?;
        0x0203_u16.encode(&mut transcript)?;
        U256::from(5_u64).encode(&mut transcript)?;
        let bytes = transcript.as_bytes();
        assert_eq!(&bytes[..7], &[0, 0, 0, 1, b'x', 0, 1]);
        assert_eq!(&bytes[7..9], &[2, 3]);
        assert_eq!(&bytes[bytes.len() - 2..], &[0, 5]);
        Ok(())
    }
}
