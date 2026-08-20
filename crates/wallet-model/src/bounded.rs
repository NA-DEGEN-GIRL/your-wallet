use core::fmt;

/// Error returned when an externally supplied value is not canonical or bounded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseValueError {
    /// The value used an invalid prefix or alphabet.
    InvalidEncoding,
    /// The value had the wrong fixed width.
    InvalidLength,
    /// The value exceeded its type's maximum length.
    TooLarge,
    /// The value used a non-canonical representation.
    NonCanonical,
    /// The value included a forbidden control character.
    ForbiddenCharacter,
}

impl fmt::Display for ParseValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidEncoding => "invalid encoding",
            Self::InvalidLength => "invalid length",
            Self::TooLarge => "value exceeds its bound",
            Self::NonCanonical => "value is not canonical",
            Self::ForbiddenCharacter => "value contains a forbidden character",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ParseValueError {}

/// An unsigned 256-bit integer stored in canonical big-endian order.
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct U256([u8; 32]);

impl fmt::Debug for U256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("U256([REDACTED])")
    }
}

impl U256 {
    /// Zero.
    pub const ZERO: Self = Self([0; 32]);

    /// Creates a value from a `u64` without truncation.
    #[must_use]
    pub fn from_u64(value: u64) -> Self {
        let mut bytes = [0_u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Self(bytes)
    }

    /// Creates a value from an exact 32-byte big-endian representation.
    #[must_use]
    pub const fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Left-pads a shorter big-endian representation with zeroes.
    pub fn from_be_slice(bytes: &[u8]) -> Result<Self, ParseValueError> {
        if bytes.len() > 32 {
            return Err(ParseValueError::TooLarge);
        }
        let mut output = [0_u8; 32];
        let start = 32_usize.saturating_sub(bytes.len());
        output[start..].copy_from_slice(bytes);
        Ok(Self(output))
    }

    /// Parses a strict EIP-1474 `QUANTITY` such as `0x0` or `0x2a`.
    pub fn from_canonical_quantity(value: &str) -> Result<Self, ParseValueError> {
        let Some(digits) = value.strip_prefix("0x") else {
            return Err(ParseValueError::InvalidEncoding);
        };
        if digits.is_empty() {
            return Err(ParseValueError::InvalidLength);
        }
        if digits.len() > 64 {
            return Err(ParseValueError::TooLarge);
        }
        if digits.len() > 1 && digits.as_bytes().first() == Some(&b'0') {
            return Err(ParseValueError::NonCanonical);
        }

        let mut output = [0_u8; 32];
        let mut output_index = 32_usize.saturating_sub(digits.len().div_ceil(2));
        let mut input_index = 0_usize;
        if digits.len() % 2 == 1 {
            output[output_index] = decode_nibble(digits.as_bytes()[0])?;
            output_index += 1;
            input_index = 1;
        }
        while input_index < digits.len() {
            let high = decode_nibble(digits.as_bytes()[input_index])?;
            let low = decode_nibble(digits.as_bytes()[input_index + 1])?;
            output[output_index] = (high << 4) | low;
            output_index += 1;
            input_index += 2;
        }
        Ok(Self(output))
    }

    /// Returns the exact 32-byte big-endian representation.
    #[must_use]
    pub const fn as_be_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns whether this value is zero.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self == Self::ZERO
    }

    /// Multiplies two values and returns `None` if the 256-bit result overflows.
    #[must_use]
    pub fn checked_mul(self, right: Self) -> Option<Self> {
        let mut limbs = [0_u32; 64];
        for (left_index, left_byte) in self.0.iter().rev().enumerate() {
            for (right_index, right_byte) in right.0.iter().rev().enumerate() {
                let index = left_index.checked_add(right_index)?;
                let product = u32::from(*left_byte).checked_mul(u32::from(*right_byte))?;
                limbs[index] = limbs[index].checked_add(product)?;
            }
        }
        for index in 0..63 {
            let carry = limbs[index] >> 8;
            limbs[index] &= 0xff;
            limbs[index + 1] = limbs[index + 1].checked_add(carry)?;
        }
        if limbs[32..].iter().any(|value| *value != 0) {
            return None;
        }
        let mut output = [0_u8; 32];
        for (index, limb) in limbs[..32].iter().enumerate() {
            output[31_usize.checked_sub(index)?] = u8::try_from(*limb).ok()?;
        }
        Some(Self(output))
    }

    /// Returns the canonical EIP-1474 quantity representation.
    #[must_use]
    pub fn to_canonical_quantity(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(66);
        output.push_str("0x");
        let first_nonzero = self.0.iter().position(|byte| *byte != 0);
        let Some(first_index) = first_nonzero else {
            output.push('0');
            return output;
        };
        let first = self.0[first_index];
        if first >> 4 != 0 {
            output.push(char::from(HEX[usize::from(first >> 4)]));
        }
        output.push(char::from(HEX[usize::from(first & 0x0f)]));
        for byte in &self.0[first_index + 1..] {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }
}

impl From<u64> for U256 {
    fn from(value: u64) -> Self {
        Self::from_u64(value)
    }
}

impl fmt::Display for U256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_canonical_quantity())
    }
}

/// An Ethereum address represented as exactly 20 bytes.
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Address20([u8; 20]);

impl fmt::Debug for Address20 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Address20([REDACTED])")
    }
}

impl Address20 {
    /// Creates an address from exact bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// Parses a 0x-prefixed, fixed-width hexadecimal address.
    pub fn from_fixed_hex(value: &str) -> Result<Self, ParseValueError> {
        Ok(Self(decode_fixed_hex::<20>(value)?))
    }

    /// Returns the exact address bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Returns the lowercase fixed-width hexadecimal form.
    #[must_use]
    pub fn to_fixed_hex(self) -> String {
        encode_fixed_hex(&self.0)
    }
}

impl fmt::Display for Address20 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_fixed_hex())
    }
}

/// A fixed 32-byte digest or block hash.
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Hash32([u8; 32]);

impl fmt::Debug for Hash32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Hash32([REDACTED])")
    }
}

impl Hash32 {
    /// All-zero hash, used only where absence is separately tagged.
    pub const ZERO: Self = Self([0; 32]);

    /// Creates a hash from exact bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parses a 0x-prefixed, fixed-width hexadecimal hash.
    pub fn from_fixed_hex(value: &str) -> Result<Self, ParseValueError> {
        Ok(Self(decode_fixed_hex::<32>(value)?))
    }

    /// Returns the exact bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the lowercase fixed-width hexadecimal form.
    #[must_use]
    pub fn to_fixed_hex(self) -> String {
        encode_fixed_hex(&self.0)
    }
}

impl fmt::Display for Hash32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_fixed_hex())
    }
}

/// Owned bytes whose length is checked at construction.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BoundedBytes<const MAX: usize>(Vec<u8>);

impl<const MAX: usize> fmt::Debug for BoundedBytes<MAX> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedBytes")
            .field("bytes", &"[REDACTED]")
            .field("len", &self.0.len())
            .finish()
    }
}

impl<const MAX: usize> BoundedBytes<MAX> {
    /// Validates and owns a byte vector.
    pub fn new(bytes: Vec<u8>) -> Result<Self, ParseValueError> {
        if bytes.len() > MAX {
            return Err(ParseValueError::TooLarge);
        }
        Ok(Self(bytes))
    }

    /// Returns the contained bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns the number of contained bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the value is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consumes the wrapper.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

/// Owned UTF-8 text with byte and control-character bounds.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BoundedText<const MAX: usize>(String);

impl<const MAX: usize> fmt::Debug for BoundedText<MAX> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedText")
            .field("text", &"[REDACTED]")
            .field("bytes", &self.0.len())
            .finish()
    }
}

impl<const MAX: usize> BoundedText<MAX> {
    /// Validates text, rejecting NUL and non-whitespace control characters.
    pub fn new(value: impl Into<String>) -> Result<Self, ParseValueError> {
        let value = value.into();
        if value.len() > MAX {
            return Err(ParseValueError::TooLarge);
        }
        if value.chars().any(|character| {
            character == '\0' || (character.is_control() && !character.is_whitespace())
        }) {
            return Err(ParseValueError::ForbiddenCharacter);
        }
        Ok(Self(value))
    }

    /// Returns the validated string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the wrapper.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

fn decode_nibble(value: u8) -> Result<u8, ParseValueError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ParseValueError::InvalidEncoding),
    }
}

fn decode_fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], ParseValueError> {
    let Some(digits) = value.strip_prefix("0x") else {
        return Err(ParseValueError::InvalidEncoding);
    };
    if digits.len() != N.saturating_mul(2) {
        return Err(ParseValueError::InvalidLength);
    }
    let mut output = [0_u8; N];
    for (index, slot) in output.iter_mut().enumerate() {
        let input_index = index.saturating_mul(2);
        let high = decode_nibble(digits.as_bytes()[input_index])?;
        let low = decode_nibble(digits.as_bytes()[input_index + 1])?;
        *slot = (high << 4) | low;
    }
    Ok(output)
}

fn encode_fixed_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2).saturating_add(2));
    output.push_str("0x");
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{Address20, BoundedBytes, BoundedText, Hash32, ParseValueError, U256};

    #[test]
    fn sensitive_value_debug_is_redacted() -> Result<(), ParseValueError> {
        let amount = U256::from_u64(42_001);
        let address = Address20::new([0x5a; 20]);
        let digest = Hash32::new([0xa5; 32]);
        let bytes = BoundedBytes::<16>::new(vec![0xde, 0xad, 0xbe, 0xef])?;
        let text = BoundedText::<32>::new("sensitive.example")?;

        let rendered = format!("{amount:?} {address:?} {digest:?} {bytes:?} {text:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("164, 17"));
        assert!(!rendered.contains("90, 90, 90"));
        assert!(!rendered.contains("165, 165, 165"));
        assert!(!rendered.contains("222, 173, 190, 239"));
        assert!(!rendered.contains("sensitive.example"));
        Ok(())
    }

    #[test]
    fn quantity_round_trip_is_canonical() -> Result<(), ParseValueError> {
        for value in [
            "0x0",
            "0x1",
            "0xf",
            "0x10",
            "0xabcdef",
            "0xffffffffffffffff",
        ] {
            let parsed = U256::from_canonical_quantity(value)?;
            assert_eq!(parsed.to_canonical_quantity(), value);
        }
        Ok(())
    }

    #[test]
    fn quantity_rejects_ambiguous_inputs() {
        assert_eq!(
            U256::from_canonical_quantity("0x00"),
            Err(ParseValueError::NonCanonical)
        );
        assert_eq!(
            U256::from_canonical_quantity("0xA"),
            Err(ParseValueError::InvalidEncoding)
        );
        assert_eq!(
            U256::from_canonical_quantity("1"),
            Err(ParseValueError::InvalidEncoding)
        );
    }

    #[test]
    fn checked_multiplication_detects_overflow() {
        let two = U256::from_u64(2);
        assert_eq!(
            two.checked_mul(U256::from_u64(21_000)),
            Some(U256::from_u64(42_000))
        );
        assert_eq!(U256::from_be_bytes([0xff; 32]).checked_mul(two), None);
    }

    #[test]
    fn fixed_hex_rejects_case_and_width_changes() -> Result<(), ParseValueError> {
        let value = Address20::from_fixed_hex("0x00112233445566778899aabbccddeeff00112233")?;
        assert_eq!(
            value.to_fixed_hex(),
            "0x00112233445566778899aabbccddeeff00112233"
        );
        assert!(Address20::from_fixed_hex("0X00112233445566778899aabbccddeeff00112233").is_err());
        assert!(Address20::from_fixed_hex("0x001122").is_err());
        Ok(())
    }

    #[test]
    fn bounded_values_fail_closed() {
        assert_eq!(
            BoundedBytes::<2>::new(vec![1, 2, 3]),
            Err(ParseValueError::TooLarge)
        );
        assert_eq!(BoundedText::<2>::new("abc"), Err(ParseValueError::TooLarge));
        assert_eq!(
            BoundedText::<8>::new("a\0b"),
            Err(ParseValueError::ForbiddenCharacter)
        );
    }
}
