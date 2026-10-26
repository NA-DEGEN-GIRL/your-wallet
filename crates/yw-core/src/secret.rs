//! Secret value wrappers (spec/01 §5.3).
//!
//! The wrappers implement neither `Clone`, `Copy`, `Display` nor `PartialEq`; comparison is
//! `subtle::ConstantTimeEq` and `Debug` prints only the type name and `[REDACTED]`. Variable
//! buffers fix their capacity at construction so a push can never reallocate and leave a copy.

use core::fmt;

use subtle::{Choice, ConstantTimeEq};
pub use zeroize::{Zeroize, Zeroizing};

/// A push would exceed the capacity fixed at construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapacityError;

impl fmt::Display for CapacityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("secret buffer capacity exceeded")
    }
}

impl std::error::Error for CapacityError {}

/// Fixed-size secret bytes (keys, seeds, DEK copies, entropy), zeroized on drop.
pub struct SecretBytes<const N: usize>(Zeroizing<[u8; N]>);

impl<const N: usize> SecretBytes<N> {
    /// Moves `src` into the wrapper and zeroes `src`.
    #[must_use]
    pub fn new(src: &mut [u8; N]) -> Self {
        let mut inner = Zeroizing::new([0_u8; N]);
        inner.copy_from_slice(src);
        src.zeroize();
        Self(inner)
    }

    /// Borrows the secret bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> ConstantTimeEq for SecretBytes<N> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.as_slice().ct_eq(other.0.as_slice())
    }
}

impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SecretBytes<{N}>([REDACTED])")
    }
}

/// A secret byte buffer whose capacity is fixed at construction.
pub struct SecretVec(Zeroizing<Vec<u8>>);

impl SecretVec {
    /// Allocates exactly `capacity` bytes.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Zeroizing::new(Vec::with_capacity(capacity)))
    }

    /// Appends bytes without reallocating.
    ///
    /// # Errors
    ///
    /// [`CapacityError`] if the bytes do not fit; nothing is appended.
    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), CapacityError> {
        let room = self.0.capacity().saturating_sub(self.0.len());
        if bytes.len() > room {
            return Err(CapacityError);
        }
        self.0.extend_from_slice(bytes);
        Ok(())
    }

    /// Borrows the bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Number of bytes stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no bytes are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl ConstantTimeEq for SecretVec {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.as_slice().ct_eq(other.0.as_slice())
    }
}

impl fmt::Debug for SecretVec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretVec([REDACTED])")
    }
}

/// A secret string (mnemonic phrase, password, API key) with a fixed capacity.
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Allocates exactly `capacity` bytes.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Zeroizing::new(String::with_capacity(capacity)))
    }

    /// Appends text without reallocating.
    ///
    /// # Errors
    ///
    /// [`CapacityError`] if the text does not fit; nothing is appended.
    pub fn push_str(&mut self, text: &str) -> Result<(), CapacityError> {
        let room = self.0.capacity().saturating_sub(self.0.len());
        if text.len() > room {
            return Err(CapacityError);
        }
        self.0.push_str(text);
        Ok(())
    }

    /// Borrows the text.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the string is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl ConstantTimeEq for SecretString {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.as_bytes().ct_eq(other.0.as_bytes())
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use subtle::ConstantTimeEq;

    use super::{CapacityError, SecretBytes, SecretString, SecretVec};

    #[test]
    fn wrappers_fix_capacity_zero_source_and_redact_debug() {
        let mut source = [0x5a_u8; 4];
        let bytes = SecretBytes::new(&mut source);
        assert_eq!(source, [0; 4]);
        assert_eq!(bytes.expose(), &[0x5a; 4]);
        assert_eq!(format!("{bytes:?}"), "SecretBytes<4>([REDACTED])");

        let mut vec = SecretVec::with_capacity(3);
        vec.extend_from_slice(&[1, 2]).unwrap();
        assert_eq!(vec.extend_from_slice(&[3, 4]), Err(CapacityError));
        assert_eq!(vec.expose(), &[1, 2]);
        assert_eq!(format!("{vec:?}"), "SecretVec([REDACTED])");

        let mut text = SecretString::with_capacity(8);
        text.push_str("hunter").unwrap();
        assert_eq!(text.push_str("xyz"), Err(CapacityError));
        assert_eq!(text.expose(), "hunter");
        assert!(!format!("{text:?}").contains("hunter"));
        let mut other = SecretString::with_capacity(8);
        other.push_str("hunter").unwrap();
        assert_eq!(text.ct_eq(&other).unwrap_u8(), 1);
    }
}
