//! Amounts in satoshis (spec/08 §7.3, §8.1). Every value is a `u64` of sats `<= MAX_MONEY`;
//! decimal BTC text is converted by moving the decimal point only (never through `f64`), and
//! every operation is checked.
#![deny(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

use core::fmt;

use super::MAX_MONEY;

/// Sats per BTC.
pub const SATS_PER_BTC: u64 = 100_000_000;
/// Decimal places of a BTC amount.
pub const BTC_DECIMALS: usize = 8;
/// Most integer digits of a decimal BTC text (`[1-9][0-9]{0,7}`).
const MAX_BTC_INT_DIGITS: usize = 8;
/// Most digits of a user sats input (`[1-9][0-9]{0,15}`).
const MAX_SATS_DIGITS: usize = 16;

/// An amount in sats, always `<= MAX_MONEY` (2,100,000,000,000,000).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sats(u64);

impl Sats {
    /// Zero.
    pub const ZERO: Self = Self(0);
    /// `MAX_MONEY`.
    pub const MAX: Self = Self(MAX_MONEY);

    /// `Some` when `value <= MAX_MONEY`.
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        if value <= MAX_MONEY {
            Some(Self(value))
        } else {
            None
        }
    }

    /// The value in sats.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// `self + other`, `None` above `MAX_MONEY`.
    #[must_use]
    pub const fn checked_add(self, other: Self) -> Option<Self> {
        match self.0.checked_add(other.0) {
            Some(sum) => Self::new(sum),
            None => None,
        }
    }

    /// `self - other`, `None` below zero.
    #[must_use]
    pub const fn checked_sub(self, other: Self) -> Option<Self> {
        match self.0.checked_sub(other.0) {
            Some(difference) => Some(Self(difference)),
            None => None,
        }
    }

    /// Sum of `items`, `None` above `MAX_MONEY`.
    #[must_use]
    pub fn checked_sum<I: IntoIterator<Item = Self>>(items: I) -> Option<Self> {
        items.into_iter().try_fold(Self::ZERO, Self::checked_add)
    }
}

impl TryFrom<u64> for Sats {
    type Error = AmountError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(AmountError::AboveMaxMoney)
    }
}

impl From<Sats> for u64 {
    fn from(value: Sats) -> Self {
        value.0
    }
}

/// Amount text or range failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AmountError {
    /// The text does not match the grammar (sign, exponent, separators, too many digits, …).
    InvalidFormat,
    /// The value is above `MAX_MONEY`.
    AboveMaxMoney,
}

impl fmt::Display for AmountError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFormat => "금액 형식이 올바르지 않습니다",
            Self::AboveMaxMoney => "금액이 최대값(21,000,000 BTC)을 넘습니다",
        })
    }
}

impl std::error::Error for AmountError {}

/// Accumulates ASCII digits into a `u64` (`None` on a non-digit or overflow).
fn digits_value(digits: &[u8]) -> Option<u64> {
    digits.iter().try_fold(0_u64, |value, byte| {
        if !byte.is_ascii_digit() {
            return None;
        }
        value
            .checked_mul(10)?
            .checked_add(u64::from(byte.checked_sub(b'0')?))
    })
}

/// Decimal BTC text → sats by moving the decimal point (spec/08 §8.1). Grammar
/// `^(0|[1-9][0-9]{0,7})(\.[0-9]{1,8})?$`: no sign, exponent, separators, whitespace, leading
/// zeros or more than 8 fraction digits. Used for JSON number literals from Core (`feerate`,
/// `fees.base`; BTC/kvB values give sat/kvB) and, through [`parse_user_btc`], for user input.
///
/// # Errors
///
/// [`AmountError::InvalidFormat`] for any grammar violation, [`AmountError::AboveMaxMoney`] above
/// 21,000,000 BTC.
pub fn parse_btc_decimal(text: &str) -> Result<Sats, AmountError> {
    let (integer, fraction) = match text.split_once('.') {
        Some((integer, fraction)) => (integer.as_bytes(), Some(fraction.as_bytes())),
        None => (text.as_bytes(), None),
    };
    let integer_ok = match integer {
        [b'0'] => true,
        [first, ..] => {
            (b'1'..=b'9').contains(first)
                && integer.len() <= MAX_BTC_INT_DIGITS
                && integer.iter().all(u8::is_ascii_digit)
        }
        [] => false,
    };
    if !integer_ok {
        return Err(AmountError::InvalidFormat);
    }
    let whole = digits_value(integer).ok_or(AmountError::InvalidFormat)?;
    let mut sats = whole
        .checked_mul(SATS_PER_BTC)
        .ok_or(AmountError::AboveMaxMoney)?;
    if let Some(fraction) = fraction {
        if fraction.is_empty()
            || fraction.len() > BTC_DECIMALS
            || !fraction.iter().all(u8::is_ascii_digit)
        {
            return Err(AmountError::InvalidFormat);
        }
        let mut part = digits_value(fraction).ok_or(AmountError::InvalidFormat)?;
        for _ in fraction.len()..BTC_DECIMALS {
            part = part.checked_mul(10).ok_or(AmountError::InvalidFormat)?;
        }
        sats = sats.checked_add(part).ok_or(AmountError::AboveMaxMoney)?;
    }
    Sats::try_from(sats)
}

/// User BTC input (spec/08 §7.3): the same grammar as [`parse_btc_decimal`]. Zero is accepted
/// here and rejected later by the recipient dust rule (`DustAmount`).
///
/// # Errors
///
/// As [`parse_btc_decimal`].
pub fn parse_user_btc(text: &str) -> Result<Sats, AmountError> {
    parse_btc_decimal(text)
}

/// User sats input (spec/08 §7.3): `^[1-9][0-9]{0,15}$`.
///
/// # Errors
///
/// [`AmountError::InvalidFormat`] for any grammar violation (including `0`),
/// [`AmountError::AboveMaxMoney`] above `MAX_MONEY`.
pub fn parse_user_sats(text: &str) -> Result<Sats, AmountError> {
    let bytes = text.as_bytes();
    let ok = matches!(bytes.first(), Some(b'1'..=b'9'))
        && bytes.len() <= MAX_SATS_DIGITS
        && bytes.iter().all(u8::is_ascii_digit);
    if !ok {
        return Err(AmountError::InvalidFormat);
    }
    let value = digits_value(bytes).ok_or(AmountError::InvalidFormat)?;
    Sats::try_from(value)
}

/// `0.00120000`: the integer part, a point and always 8 fraction digits.
#[must_use]
pub fn format_btc(amount: Sats) -> String {
    let value = amount.get();
    format!("{}.{:08}", value / SATS_PER_BTC, value % SATS_PER_BTC)
}

/// `120,000`: decimal digits grouped by three with commas.
#[must_use]
pub fn format_sats_grouped(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len().saturating_add(digits.len() / 3));
    let mut remaining = digits.len();
    for character in digits.chars() {
        if remaining != digits.len() && remaining.is_multiple_of(3) {
            out.push(',');
        }
        out.push(character);
        remaining = remaining.saturating_sub(1);
    }
    out
}

/// The approval amount text `0.00120000 BTC (120,000 sats)` (spec/08 §10 `0x0603`).
#[must_use]
pub fn format_btc_and_sats(amount: Sats) -> String {
    format!(
        "{} BTC ({} sats)",
        format_btc(amount),
        format_sats_grouped(amount.get())
    )
}
