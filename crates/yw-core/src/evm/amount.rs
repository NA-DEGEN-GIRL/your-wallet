//! 256-bit unsigned integers and amount formatting (spec/03 §2.3–§2.4).
//!
//! `U256` extends the archive's `[u8; 32]` big-endian value
//! (`archive/spec-v2.4:crates/wallet-model/src/bounded.rs:33-262`) with checked arithmetic from
//! `archive/spec-v2.4:demo/sepolia-wallet/src/backend.rs:4204-4363` and the decimal amount rules
//! of `archive/spec-v2.4:demo/sepolia-wallet/src/erc20.rs:222-290`. Every operation is checked;
//! nothing saturates or wraps (fee overflow → E05, diff overflow → E09 at the call sites).
#![deny(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

use core::fmt;
use core::fmt::Write as _;
use core::num::NonZeroU64;

/// Maximum length of a user amount string (`parse_units`).
pub const MAX_AMOUNT_INPUT: usize = 128;
/// Maximum token decimals the wallet formats (spec/03 §2.5).
pub const MAX_DECIMALS: u8 = 36;

/// An unsigned 256-bit integer stored big-endian. Values are public (not secrets).
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct U256([u8; 32]);

/// Quantity parsing failure (`parse_quantity_lenient`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseValueError {
    /// Not `0x` followed by 1–64 hex digits.
    InvalidQuantity,
    /// A decimal string is malformed or does not fit in 256 bits.
    InvalidDecimal,
}

impl fmt::Display for ParseValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidQuantity => "invalid hex quantity",
            Self::InvalidDecimal => "invalid decimal integer",
        })
    }
}

impl std::error::Error for ParseValueError {}

/// User amount parsing failure (`parse_units`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AmountError {
    /// Empty, longer than 128 bytes, or outside `^(0|[1-9][0-9]*)(\.[0-9]+)?$`.
    Format,
    /// More fraction digits than the token's decimals.
    TooManyDecimals,
    /// The value does not fit in 256 bits.
    Overflow,
}

impl AmountError {
    /// The fixed text in `lang` (`Display` is the Korean one).
    #[must_use]
    pub const fn text_in(self, lang: crate::lang::Lang) -> &'static str {
        match self {
            Self::Format => text::FORMAT,
            Self::TooManyDecimals => text::TOO_MANY_DECIMALS,
            Self::Overflow => text::OVERFLOW,
        }
        .get(lang)
    }
}

impl fmt::Display for AmountError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.text_in(crate::lang::Lang::Ko))
    }
}

/// Amount input texts (`parse_units`; English spec/14 §5).
pub mod text {
    crate::texts! {
        FORMAT = "금액 형식이 올바르지 않습니다." / "The amount format is invalid.";
        TOO_MANY_DECIMALS = "소수점 아래 자릿수가 너무 많습니다."
            / "Too many digits after the decimal point.";
        OVERFLOW = "금액이 너무 큽니다." / "The amount is too large.";
    }
}

impl std::error::Error for AmountError {}

/// Σin − Σout of one asset (spec/03 §2.3, §6.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delta {
    /// No net change.
    Zero,
    /// Net receipt.
    In(U256),
    /// Net payment.
    Out(U256),
}

impl Delta {
    /// `received − sent` as a signed delta.
    #[must_use]
    pub fn from_sums(received: U256, sent: U256) -> Self {
        match received.cmp(&sent) {
            core::cmp::Ordering::Equal => Self::Zero,
            core::cmp::Ordering::Greater => {
                Self::In(received.checked_sub(sent).unwrap_or(U256::ZERO))
            }
            core::cmp::Ordering::Less => {
                Self::Out(sent.checked_sub(received).unwrap_or(U256::ZERO))
            }
        }
    }
}

fn lo(value: u128) -> u64 {
    u64::try_from(value & u128::from(u64::MAX)).unwrap_or(u64::MAX)
}

fn hi(value: u128) -> u64 {
    lo(value.wrapping_shr(64))
}

impl U256 {
    /// Zero.
    pub const ZERO: Self = Self([0; 32]);
    /// One.
    pub const ONE: Self = Self::from_u64(1);
    /// 2^256 − 1.
    pub const MAX: Self = Self([0xff; 32]);
    /// 2^160 − 1 (Permit2 unlimited amount, spec/03 §10.3).
    pub const MAX_U160: Self = Self([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ]);

    /// From big-endian bytes.
    #[must_use]
    pub const fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// From a `u64`.
    #[must_use]
    pub const fn from_u64(value: u64) -> Self {
        let [b0, b1, b2, b3, b4, b5, b6, b7] = value.to_be_bytes();
        Self([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, b0, b1, b2, b3,
            b4, b5, b6, b7,
        ])
    }

    /// From a big-endian slice of at most 32 bytes.
    #[must_use]
    pub fn from_be_slice(bytes: &[u8]) -> Option<Self> {
        let start = 32_usize.checked_sub(bytes.len())?;
        let mut out = [0_u8; 32];
        out.get_mut(start..)?.copy_from_slice(bytes);
        Some(Self(out))
    }

    /// Big-endian bytes.
    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Borrowed big-endian bytes.
    #[must_use]
    pub const fn as_be_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Minimal big-endian bytes; zero is the empty slice (RLP integers).
    #[must_use]
    pub fn minimal_be(&self) -> &[u8] {
        let start = self.0.iter().position(|byte| *byte != 0).unwrap_or(32);
        self.0.get(start..).unwrap_or(&[])
    }

    /// Whether the value is zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }

    /// The value as `u64` if it fits.
    #[must_use]
    pub fn to_u64(self) -> Option<u64> {
        let (high, low) = self.0.split_at(24);
        if high.iter().any(|byte| *byte != 0) {
            return None;
        }
        let low: [u8; 8] = low.try_into().ok()?;
        Some(u64::from_be_bytes(low))
    }

    /// Whether the value fits in `bits` bits (`bits` a multiple of 8, ≤ 256).
    #[must_use]
    pub fn fits_bits(&self, bits: u16) -> bool {
        let bytes = usize::from(bits / 8);
        let zero_prefix = 32_usize.saturating_sub(bytes);
        self.0
            .get(..zero_prefix)
            .is_some_and(|prefix| prefix.iter().all(|byte| *byte == 0))
    }

    fn limbs(&self) -> [u64; 4] {
        let mut limbs = [0_u64; 4];
        for (limb, chunk) in limbs.iter_mut().zip(self.0.rchunks_exact(8)) {
            let mut word = [0_u8; 8];
            word.copy_from_slice(chunk);
            *limb = u64::from_be_bytes(word);
        }
        limbs
    }

    fn from_limbs(limbs: [u64; 4]) -> Self {
        let mut bytes = [0_u8; 32];
        for (chunk, limb) in bytes.rchunks_exact_mut(8).zip(limbs) {
            chunk.copy_from_slice(&limb.to_be_bytes());
        }
        Self(bytes)
    }

    /// `self + other`, `None` on overflow.
    #[must_use]
    pub fn checked_add(self, other: Self) -> Option<Self> {
        let (a, b) = (self.limbs(), other.limbs());
        let mut out = [0_u64; 4];
        let mut carry = false;
        for ((slot, x), y) in out.iter_mut().zip(a).zip(b) {
            let (sum, c1) = x.overflowing_add(y);
            let (sum, c2) = sum.overflowing_add(u64::from(carry));
            *slot = sum;
            carry = c1 || c2;
        }
        (!carry).then(|| Self::from_limbs(out))
    }

    /// `self − other`, `None` when `other > self`.
    #[must_use]
    pub fn checked_sub(self, other: Self) -> Option<Self> {
        let (a, b) = (self.limbs(), other.limbs());
        let mut out = [0_u64; 4];
        let mut borrow = false;
        for ((slot, x), y) in out.iter_mut().zip(a).zip(b) {
            let (diff, b1) = x.overflowing_sub(y);
            let (diff, b2) = diff.overflowing_sub(u64::from(borrow));
            *slot = diff;
            borrow = b1 || b2;
        }
        (!borrow).then(|| Self::from_limbs(out))
    }

    /// `self × other`, `None` on overflow.
    #[must_use]
    pub fn checked_mul(self, other: Self) -> Option<Self> {
        let (a, b) = (self.limbs(), other.limbs());
        let mut wide = [0_u64; 8];
        for (i, x) in a.into_iter().enumerate() {
            let mut carry = 0_u64;
            for (j, y) in b.into_iter().enumerate() {
                let slot = wide.get_mut(i.wrapping_add(j))?;
                // (2^64−1)^2 + 2·(2^64−1) = 2^128 − 1: no overflow.
                let t = u128::from(x)
                    .wrapping_mul(u128::from(y))
                    .wrapping_add(u128::from(*slot))
                    .wrapping_add(u128::from(carry));
                *slot = lo(t);
                carry = hi(t);
            }
            *wide.get_mut(i.wrapping_add(4))? = carry;
        }
        let (low, high) = wide.split_at(4);
        if high.iter().any(|limb| *limb != 0) {
            return None;
        }
        let mut limbs = [0_u64; 4];
        limbs.copy_from_slice(low);
        Some(Self::from_limbs(limbs))
    }

    /// `self × m`, `None` on overflow.
    #[must_use]
    pub fn checked_mul_u64(self, m: u64) -> Option<Self> {
        self.checked_mul(Self::from_u64(m))
    }

    /// `(self / d, self % d)`.
    #[must_use]
    pub fn div_rem_u64(self, d: NonZeroU64) -> (Self, u64) {
        let divisor = u128::from(d.get());
        let mut quotient = [0_u64; 4];
        let mut remainder = 0_u128;
        for (slot, limb) in quotient.iter_mut().zip(self.limbs()).rev() {
            let current = remainder.wrapping_shl(64) | u128::from(limb);
            *slot = lo(current.checked_div(divisor).unwrap_or(0));
            remainder = current.checked_rem(divisor).unwrap_or(0);
        }
        (Self::from_limbs(quotient), lo(remainder))
    }

    /// `⌈self · num / den⌉`, `None` if the result exceeds 256 bits.
    #[must_use]
    pub fn ceil_mul_div_u64(self, num: u64, den: NonZeroU64) -> Option<Self> {
        // 320-bit product, then long division by `den`.
        let mut wide = [0_u64; 5];
        let mut carry = 0_u64;
        for (slot, limb) in wide.iter_mut().zip(self.limbs()) {
            let t = u128::from(limb)
                .wrapping_mul(u128::from(num))
                .wrapping_add(u128::from(carry));
            *slot = lo(t);
            carry = hi(t);
        }
        *wide.get_mut(4)? = carry;
        let divisor = u128::from(den.get());
        let mut quotient = [0_u64; 5];
        let mut remainder = 0_u128;
        for (slot, limb) in quotient.iter_mut().zip(wide).rev() {
            let current = remainder.wrapping_shl(64) | u128::from(limb);
            *slot = lo(current.checked_div(divisor).unwrap_or(0));
            remainder = current.checked_rem(divisor).unwrap_or(0);
        }
        if quotient.get(4).copied() != Some(0) {
            return None;
        }
        let mut limbs = [0_u64; 4];
        limbs.copy_from_slice(quotient.get(..4)?);
        let floor = Self::from_limbs(limbs);
        if remainder == 0 {
            Some(floor)
        } else {
            floor.checked_add(Self::ONE)
        }
    }

    /// `10^exponent`, `None` above 2^256.
    #[must_use]
    pub fn checked_pow10(exponent: u8) -> Option<Self> {
        let mut value = Self::ONE;
        for _ in 0..exponent {
            value = value.checked_mul_u64(10)?;
        }
        Some(value)
    }

    /// Parses `^0x[0-9a-fA-F]{1,64}$` (case and leading zeros allowed, spec/03 §3.2).
    ///
    /// # Errors
    ///
    /// [`ParseValueError::InvalidQuantity`].
    pub fn parse_quantity_lenient(text: &str) -> Result<Self, ParseValueError> {
        let digits = text
            .strip_prefix("0x")
            .ok_or(ParseValueError::InvalidQuantity)?;
        if digits.is_empty() || digits.len() > 64 {
            return Err(ParseValueError::InvalidQuantity);
        }
        let mut bytes = [0_u8; 32];
        // Fill nibbles from the least significant end.
        for (position, digit) in digits.bytes().rev().enumerate() {
            let nibble = match digit {
                b'0'..=b'9' => digit.wrapping_sub(b'0'),
                b'a'..=b'f' => digit.wrapping_sub(b'a').wrapping_add(10),
                b'A'..=b'F' => digit.wrapping_sub(b'A').wrapping_add(10),
                _ => return Err(ParseValueError::InvalidQuantity),
            };
            let index = 31_usize
                .checked_sub(position / 2)
                .ok_or(ParseValueError::InvalidQuantity)?;
            let slot = bytes
                .get_mut(index)
                .ok_or(ParseValueError::InvalidQuantity)?;
            if position % 2 == 0 {
                *slot |= nibble;
            } else {
                *slot |= nibble.wrapping_shl(4);
            }
        }
        Ok(Self(bytes))
    }

    /// Parses a canonical decimal integer (`0` or `[1-9][0-9]*`, at most 78 digits).
    ///
    /// # Errors
    ///
    /// [`ParseValueError::InvalidDecimal`].
    pub fn from_decimal_str(text: &str) -> Result<Self, ParseValueError> {
        let canonical = text == "0"
            || (!text.is_empty()
                && !text.starts_with('0')
                && text.bytes().all(|byte| byte.is_ascii_digit()));
        if !canonical || text.len() > 78 {
            return Err(ParseValueError::InvalidDecimal);
        }
        let mut value = Self::ZERO;
        for digit in text.bytes() {
            value = value
                .checked_mul_u64(10)
                .and_then(|scaled| {
                    scaled.checked_add(Self::from_u64(u64::from(digit.wrapping_sub(b'0'))))
                })
                .ok_or(ParseValueError::InvalidDecimal)?;
        }
        Ok(value)
    }

    /// EIP-1474 quantity: lowercase, no leading zeros, zero is `0x0`.
    #[must_use]
    pub fn to_quantity(self) -> String {
        let hex = crate::hex::encode(self.minimal_be());
        let trimmed = hex.trim_start_matches('0');
        let mut out = String::with_capacity(trimmed.len().saturating_add(3));
        out.push_str("0x");
        out.push_str(if trimmed.is_empty() { "0" } else { trimmed });
        out
    }

    /// Exact decimal representation.
    #[must_use]
    pub fn to_decimal_string(self) -> String {
        const CHUNK: u64 = 10_000_000_000_000_000_000;
        let Some(chunk) = NonZeroU64::new(CHUNK) else {
            return String::new();
        };
        let mut parts = Vec::new();
        let mut value = self;
        loop {
            let (quotient, remainder) = value.div_rem_u64(chunk);
            parts.push(remainder);
            if quotient.is_zero() {
                break;
            }
            value = quotient;
        }
        let mut out = String::new();
        for (index, part) in parts.iter().rev().enumerate() {
            if index == 0 {
                out.push_str(&part.to_string());
            } else {
                let _ = write!(out, "{part:019}");
            }
        }
        out
    }
}

impl fmt::Debug for U256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "U256({})", self.to_decimal_string())
    }
}

impl fmt::Display for U256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_decimal_string())
    }
}

impl From<u64> for U256 {
    fn from(value: u64) -> Self {
        Self::from_u64(value)
    }
}

fn group_thousands(digits: &str) -> String {
    let mut out = String::with_capacity(digits.len().saturating_add(digits.len() / 3));
    let length = digits.len();
    for (index, character) in digits.chars().enumerate() {
        let remaining = length.saturating_sub(index);
        if index != 0 && remaining % 3 == 0 {
            out.push(',');
        }
        out.push(character);
    }
    out
}

/// Exact decimal with thousands separators and trailing fraction zeros removed (spec/03 §2.4).
#[must_use]
pub fn format_units(value: &U256, decimals: u8) -> String {
    let digits = value.to_decimal_string();
    let decimals = usize::from(decimals);
    if decimals == 0 {
        return group_thousands(&digits);
    }
    let padded = if digits.len() <= decimals {
        let mut padded = "0".repeat(decimals.saturating_add(1).saturating_sub(digits.len()));
        padded.push_str(&digits);
        padded
    } else {
        digits
    };
    let split = padded.len().saturating_sub(decimals);
    let (integer, fraction) = padded.split_at(split);
    let fraction = fraction.trim_end_matches('0');
    let mut out = group_thousands(integer);
    if !fraction.is_empty() {
        out.push('.');
        out.push_str(fraction);
    }
    out
}

/// `format_units + " " + symbol`.
#[must_use]
pub fn format_amount(value: &U256, decimals: u8, symbol: &str) -> String {
    let mut out = format_units(value, decimals);
    out.push(' ');
    out.push_str(symbol);
    out
}

/// `format_units(v, 9) + " gwei"`.
#[must_use]
pub fn format_gwei(value: &U256) -> String {
    format_amount(value, 9, "gwei")
}

/// Parses a user amount (spec/03 §2.4): `^(0|[1-9][0-9]*)(\.[0-9]+)?$`, ≤ 128 bytes.
///
/// # Errors
///
/// [`AmountError`] for format, precision or range violations.
pub fn parse_units(text: &str, decimals: u8) -> Result<U256, AmountError> {
    if text.is_empty() || text.len() > MAX_AMOUNT_INPUT {
        return Err(AmountError::Format);
    }
    let (integer, fraction) = match text.split_once('.') {
        Some((integer, fraction)) => (integer, Some(fraction)),
        None => (text, None),
    };
    let integer_ok = integer == "0"
        || (!integer.is_empty()
            && !integer.starts_with('0')
            && integer.bytes().all(|byte| byte.is_ascii_digit()));
    let fraction_ok = fraction.is_none_or(|digits| {
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
    });
    if !integer_ok || !fraction_ok {
        return Err(AmountError::Format);
    }
    let fraction = fraction.unwrap_or("");
    let places = usize::from(decimals);
    if fraction.len() > places {
        return Err(AmountError::TooManyDecimals);
    }
    let mut all = String::with_capacity(integer.len().saturating_add(places));
    all.push_str(integer);
    all.push_str(fraction);
    for _ in fraction.len()..places {
        all.push('0');
    }
    let trimmed = all.trim_start_matches('0');
    if trimmed.is_empty() {
        return Ok(U256::ZERO);
    }
    U256::from_decimal_str(trimmed).map_err(|_| AmountError::Overflow)
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU64;

    use super::{AmountError, Delta, U256, format_gwei, format_units, parse_units};

    fn nz(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).unwrap()
    }

    #[test]
    fn spec_format_vectors() {
        let v = U256::from_u64(1_234_567_890_000_000_000);
        assert_eq!(format_units(&v, 18), "1.23456789");
        let million = U256::checked_pow10(24).unwrap();
        assert_eq!(format_units(&million, 18), "1,000,000");
        assert_eq!(format_units(&U256::ONE, 18), "0.000000000000000001");
        assert_eq!(format_units(&U256::from_u64(21_000_000_000), 9), "21");
        assert_eq!(format_units(&U256::ZERO, 18), "0");
        assert_eq!(format_units(&U256::ZERO, 0), "0");
        assert_eq!(format_units(&U256::from_u64(1_234_567), 0), "1,234,567");
        assert_eq!(format_units(&U256::from_u64(123), 0), "123");
        assert_eq!(format_gwei(&U256::from_u64(1_200_000_000)), "1.2 gwei");
        assert_eq!(
            U256::MAX.to_decimal_string(),
            "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        );
    }

    #[test]
    fn spec_parse_vectors() {
        assert_eq!(
            parse_units("0.1", 18),
            Ok(U256::from_u64(100_000_000_000_000_000))
        );
        assert_eq!(
            parse_units("1.0000001", 6),
            Err(AmountError::TooManyDecimals)
        );
        assert_eq!(parse_units("0", 18), Ok(U256::ZERO));
        assert_eq!(parse_units("12", 0), Ok(U256::from_u64(12)));
        for bad in [
            "", "+1", "-1", "1e3", " 1", "1 ", "1,000", ".5", "5.", "01", "0x1", "1..2",
        ] {
            assert_eq!(parse_units(bad, 18), Err(AmountError::Format), "{bad:?}");
        }
        assert_eq!(parse_units(&"9".repeat(129), 0), Err(AmountError::Format));
        assert_eq!(parse_units(&"9".repeat(78), 0), Err(AmountError::Overflow));
        assert_eq!(
            parse_units(&U256::MAX.to_decimal_string(), 0),
            Ok(U256::MAX)
        );
    }

    #[test]
    fn boundaries() {
        assert_eq!(U256::MAX.checked_add(U256::ONE), None);
        assert_eq!(U256::ZERO.checked_sub(U256::ONE), None);
        assert_eq!(U256::MAX.checked_mul_u64(2), None);
        assert_eq!(U256::MAX.checked_mul(U256::ONE), Some(U256::MAX));
        assert_eq!(
            U256::from_u64(u64::MAX).checked_mul(U256::from_u64(u64::MAX)),
            U256::from_be_slice(&[
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0, 0, 0, 0, 0, 0, 0, 1
            ])
        );
        assert_eq!(U256::parse_quantity_lenient("0x0"), Ok(U256::ZERO));
        assert_eq!(
            U256::parse_quantity_lenient("0x00Ff"),
            Ok(U256::from_u64(255))
        );
        assert_eq!(
            U256::parse_quantity_lenient(&format!("0x{}", "f".repeat(64))),
            Ok(U256::MAX)
        );
        for bad in ["0x", "0X1", "1", "0x1g", &format!("0x{}", "f".repeat(65))] {
            assert!(U256::parse_quantity_lenient(bad).is_err(), "{bad}");
        }
        assert_eq!(U256::ZERO.to_quantity(), "0x0");
        assert_eq!(U256::from_u64(0x31f38).to_quantity(), "0x31f38");
        assert_eq!(U256::ZERO.minimal_be(), &[] as &[u8]);
        assert_eq!(U256::from_u64(0x0102).minimal_be(), &[1, 2]);
        assert_eq!(U256::from_u64(7).to_u64(), Some(7));
        assert_eq!(U256::MAX.to_u64(), None);
        assert_eq!(U256::from_be_slice(&[0; 33]), None);
        assert!(U256::MAX_U160.fits_bits(160));
        assert!(
            !U256::MAX_U160
                .checked_add(U256::ONE)
                .unwrap()
                .fits_bits(160)
        );
        assert_eq!(
            U256::from_decimal_str(
                "115792089237316195423570985008687907853269984665640564039457584007913129639936"
            ),
            Err(super::ParseValueError::InvalidDecimal)
        );
    }

    #[test]
    fn division_helpers() {
        let (q, r) = U256::from_u64(100).div_rem_u64(nz(7));
        assert_eq!((q, r), (U256::from_u64(14), 2));
        assert_eq!(
            U256::from_u64(204_600).ceil_mul_div_u64(12, nz(10)),
            Some(U256::from_u64(245_520))
        );
        assert_eq!(
            U256::from_u64(21_000).ceil_mul_div_u64(12, nz(10)),
            Some(U256::from_u64(25_200))
        );
        assert_eq!(
            U256::from_u64(11).ceil_mul_div_u64(1, nz(10)),
            Some(U256::from_u64(2))
        );
        assert_eq!(U256::MAX.ceil_mul_div_u64(2, nz(1)), None);
        assert_eq!(U256::MAX.ceil_mul_div_u64(2, nz(2)), Some(U256::MAX));
    }

    #[test]
    fn delta_from_sums() {
        assert_eq!(Delta::from_sums(U256::ONE, U256::ONE), Delta::Zero);
        assert_eq!(
            Delta::from_sums(U256::from_u64(3), U256::ONE),
            Delta::In(U256::from_u64(2))
        );
        assert_eq!(
            Delta::from_sums(U256::ONE, U256::from_u64(3)),
            Delta::Out(U256::from_u64(2))
        );
    }
}
