//! Fee units and rules (spec/08 §8): the integer fee rate in sat/kvB (1 sat/vB = 1,000), Core
//! BTC/kvB literals converted by moving the decimal point only, the manual sat/vB grammar, the
//! floor and source choice of §8.2, the caps and ratio of §8.3, and the `maxfeerate` literal.
//! Every comparison is an integer comparison in sat/kvB; nothing goes through `f64`.
#![deny(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

use core::fmt;

use super::amount::{AmountError, Sats, format_btc, parse_btc_decimal};
use super::{
    BTC_CONF_TARGETS, BTC_FEE_ABS_CAP, BTC_FEE_FLOOR_DEFAULT, BTC_FEE_RATE_CAP,
    BTC_FEE_RATE_UNOVERRIDABLE, BTC_FEE_RATIO_CONFIRM,
};

/// sat/kvB per sat/vB.
pub const KVB_PER_VB: u64 = 1_000;
/// Most integer digits of a manual sat/vB input (`[0-9]{1,6}`).
const MAX_USER_INT_DIGITS: usize = 6;
/// Most fraction digits of a manual sat/vB input (`\.[0-9]{1,3}`).
const MAX_USER_FRAC_DIGITS: usize = 3;
/// Default `incrementalrelayfee` when `getmempoolinfo` does not report it (sat/kvB).
pub const BTC_INCREMENTAL_DEFAULT: u64 = 1_000;

/// A fee rate in sat/kvB (spec/08 §8.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FeeRate {
    sat_per_kvb: u64,
}

impl FeeRate {
    /// `BTC_FEE_FLOOR_DEFAULT` (1 sat/vB).
    pub const FLOOR_DEFAULT: Self = Self {
        sat_per_kvb: BTC_FEE_FLOOR_DEFAULT,
    };

    /// A rate of `sat_per_kvb` sat/kvB.
    #[must_use]
    pub const fn from_sat_per_kvb(sat_per_kvb: u64) -> Self {
        Self { sat_per_kvb }
    }

    /// The rate in sat/kvB.
    #[must_use]
    pub const fn sat_per_kvb(self) -> u64 {
        self.sat_per_kvb
    }
}

impl fmt::Display for FeeRate {
    /// `X.XXX sat/vB` with trailing fraction zeros removed (`1 sat/vB`, `10.2 sat/vB`,
    /// `0.474 sat/vB`).
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let whole = self.sat_per_kvb.checked_div(KVB_PER_VB).unwrap_or(0);
        let fraction = self.sat_per_kvb.checked_rem(KVB_PER_VB).unwrap_or(0);
        if fraction == 0 {
            return write!(formatter, "{whole} sat/vB");
        }
        let digits = format!("{fraction:03}");
        write!(formatter, "{whole}.{} sat/vB", digits.trim_end_matches('0'))
    }
}

/// A Core BTC/kvB number literal (`estimatesmartfee.feerate`, `getmempoolinfo` fields) as a rate:
/// the literal's sats are sat/kvB (`"0.00001000"` → 1,000 sat/kvB). Grammar of
/// [`parse_btc_decimal`]: no sign, exponent or more than 8 fraction digits.
///
/// # Errors
///
/// [`AmountError`] for a grammar violation or a value above `MAX_MONEY`.
pub fn fee_rate_from_btc_per_kvb(text: &str) -> Result<FeeRate, AmountError> {
    parse_btc_decimal(text).map(|sats| FeeRate::from_sat_per_kvb(sats.get()))
}

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

/// Manual sat/vB input (spec/08 §8.1): `^[0-9]{1,6}(\.[0-9]{1,3})?$`.
///
/// # Errors
///
/// [`AmountError::InvalidFormat`] for any grammar violation.
pub fn parse_user_sat_per_vb(text: &str) -> Result<FeeRate, AmountError> {
    let (integer, fraction) = match text.split_once('.') {
        Some((integer, fraction)) => (integer.as_bytes(), Some(fraction.as_bytes())),
        None => (text.as_bytes(), None),
    };
    if integer.is_empty()
        || integer.len() > MAX_USER_INT_DIGITS
        || !integer.iter().all(u8::is_ascii_digit)
    {
        return Err(AmountError::InvalidFormat);
    }
    let whole = digits_value(integer).ok_or(AmountError::InvalidFormat)?;
    let mut kvb = whole
        .checked_mul(KVB_PER_VB)
        .ok_or(AmountError::InvalidFormat)?;
    if let Some(fraction) = fraction {
        if fraction.is_empty()
            || fraction.len() > MAX_USER_FRAC_DIGITS
            || !fraction.iter().all(u8::is_ascii_digit)
        {
            return Err(AmountError::InvalidFormat);
        }
        let mut part = digits_value(fraction).ok_or(AmountError::InvalidFormat)?;
        for _ in fraction.len()..MAX_USER_FRAC_DIGITS {
            part = part.checked_mul(10).ok_or(AmountError::InvalidFormat)?;
        }
        kvb = kvb.checked_add(part).ok_or(AmountError::InvalidFormat)?;
    }
    Ok(FeeRate::from_sat_per_kvb(kvb))
}

/// `fee(rate, vsize) = ceil(rate × vsize / 1000)` sats; `None` on overflow or above `MAX_MONEY`.
#[must_use]
pub fn fee_for(rate: FeeRate, vsize: u64) -> Option<Sats> {
    let product = rate.sat_per_kvb.checked_mul(vsize)?;
    Sats::new(product.div_ceil(KVB_PER_VB))
}

/// `rate_kvb = ceil(fee × 1000 / vsize)` sat/kvB; `None` for `vsize == 0` or overflow.
#[must_use]
pub fn rate_kvb(fee: Sats, vsize: u64) -> Option<u64> {
    if vsize == 0 {
        return None;
    }
    Some(fee.get().checked_mul(KVB_PER_VB)?.div_ceil(vsize))
}

/// The floor `max(1,000 sat/kvB, mempoolminfee, minrelaytxfee)` (spec/08 §8.2); missing values
/// are ignored.
#[must_use]
pub fn fee_floor(mempoolminfee: Option<FeeRate>, minrelaytxfee: Option<FeeRate>) -> FeeRate {
    [mempoolminfee, minrelaytxfee]
        .into_iter()
        .flatten()
        .fold(FeeRate::FLOOR_DEFAULT, Ord::max)
}

/// `incrementalrelayfee`, or 1,000 sat/kvB when it is missing (spec/08 §9).
#[must_use]
pub fn incremental_or_default(incremental: Option<FeeRate>) -> FeeRate {
    incremental.unwrap_or(FeeRate::from_sat_per_kvb(BTC_INCREMENTAL_DEFAULT))
}

/// Where the planned rate came from (spec/08 §8.2, shown in field `0x0606`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FeeSource {
    /// `estimatesmartfee [target, "economical"]` at or above the floor.
    Estimate {
        /// Confirmation target (2 / 6 / 24).
        target: u32,
    },
    /// Manual sat/vB input at or above the floor.
    Manual,
    /// The floor: an estimate below it was raised ("하한 적용"), or the default without estimates.
    Floor,
}

impl FeeSource {
    /// The fixed source text of field `0x0606`.
    #[must_use]
    pub fn text(self) -> String {
        match self {
            Self::Estimate { target } => {
                let speed = match BTC_CONF_TARGETS {
                    [fast, _, _] if target == fast => "빠름, ",
                    [_, normal, _] if target == normal => "보통, ",
                    [_, _, slow] if target == slow => "느림, ",
                    _ => "",
                };
                format!("노드 추정({speed}{target}블록 목표)")
            }
            Self::Manual => "직접 입력".to_owned(),
            Self::Floor => "하한 적용".to_owned(),
        }
    }
}

/// What the user picked in the send form (spec/08 §8.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FeeSelection {
    /// Fast / normal / slow: the `estimatesmartfee` result of `target` (`None` when Core gave
    /// no `feerate`, e.g. testnet4).
    Estimate {
        /// Confirmation target.
        target: u32,
        /// The estimate, if any.
        estimate: Option<FeeRate>,
    },
    /// Manual input (`parse_user_sat_per_vb`).
    Manual(FeeRate),
    /// The floor itself (the default when there is no estimate).
    Floor,
}

/// The chosen rate and its source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FeeChoice {
    /// Rate used for planning.
    pub rate: FeeRate,
    /// Source shown in the approval.
    pub source: FeeSource,
}

/// Fee choice or arithmetic failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FeeError {
    /// An estimate was selected but Core returned none: manual input only.
    NoEstimate,
    /// A manual rate below the floor is refused.
    ManualBelowFloor {
        /// The floor.
        floor: FeeRate,
    },
    /// Fee arithmetic overflow.
    Overflow,
}

impl fmt::Display for FeeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoEstimate => formatter.write_str("수수료 추정이 없습니다. 직접 입력하세요"),
            Self::ManualBelowFloor { floor } => {
                write!(formatter, "수수료율이 노드 하한({floor})보다 낮습니다")
            }
            Self::Overflow => formatter.write_str("수수료 계산 범위를 넘었습니다"),
        }
    }
}

impl std::error::Error for FeeError {}

/// Applies the §8.2 rules: an estimate below the floor becomes the floor (`FeeSource::Floor`,
/// "하한 적용"), a manual rate below the floor is refused, a missing estimate needs manual input.
///
/// # Errors
///
/// [`FeeError::NoEstimate`] or [`FeeError::ManualBelowFloor`].
pub fn choose_fee_rate(selection: FeeSelection, floor: FeeRate) -> Result<FeeChoice, FeeError> {
    match selection {
        FeeSelection::Estimate {
            estimate: Some(rate),
            ..
        } if rate < floor => Ok(FeeChoice {
            rate: floor,
            source: FeeSource::Floor,
        }),
        FeeSelection::Estimate {
            target,
            estimate: Some(rate),
        } => Ok(FeeChoice {
            rate,
            source: FeeSource::Estimate { target },
        }),
        FeeSelection::Estimate { estimate: None, .. } => Err(FeeError::NoEstimate),
        FeeSelection::Manual(rate) if rate < floor => Err(FeeError::ManualBelowFloor { floor }),
        FeeSelection::Manual(rate) => Ok(FeeChoice {
            rate,
            source: FeeSource::Manual,
        }),
        FeeSelection::Floor => Ok(FeeChoice {
            rate: floor,
            source: FeeSource::Floor,
        }),
    }
}

/// The §8.3 checks of a final plan (all in sat/kvB integers).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FeeCheck {
    /// `ceil(fee × 1000 / vsize)`.
    pub rate_kvb: u64,
    /// `rate_kvb > BTC_FEE_RATE_UNOVERRIDABLE` (B01, nothing lifts it).
    pub unoverridable: bool,
    /// `rate_kvb > BTC_FEE_RATE_CAP` or `fee > BTC_FEE_ABS_CAP` (B02 without, B03 with the
    /// typed override).
    pub over_cap: bool,
    /// `fee × 50 > amount` (B04).
    pub ratio_high: bool,
}

/// Computes the §8.3 checks for `fee` over the planned `vsize` and the recipient `amount`.
/// `None` for `vsize == 0` or overflow.
#[must_use]
pub fn check_fee(fee: Sats, vsize: u64, amount: Sats) -> Option<FeeCheck> {
    let rate = rate_kvb(fee, vsize)?;
    let ratio = fee.get().checked_mul(BTC_FEE_RATIO_CONFIRM)?;
    Some(FeeCheck {
        rate_kvb: rate,
        unoverridable: rate > BTC_FEE_RATE_UNOVERRIDABLE,
        over_cap: rate > BTC_FEE_RATE_CAP || fee.get() > BTC_FEE_ABS_CAP,
        ratio_high: ratio > amount.get(),
    })
}

/// The `maxfeerate` JSON number literal for `testmempoolaccept`/`sendrawtransaction`
/// (spec/08 §8.3): `ceil(rate_kvb / 1000) + 1` sat/vB written as BTC/kvB with 8 decimals
/// (10.2 sat/vB → `"0.00012000"`). Insert it with `yw_json::Number::from_literal`.
#[must_use]
pub fn maxfeerate_literal(rate_kvb: u64) -> Option<String> {
    let sat_per_vb = rate_kvb.div_ceil(KVB_PER_VB).checked_add(1)?;
    let kvb = sat_per_vb.checked_mul(KVB_PER_VB)?;
    Sats::new(kvb).map(format_btc)
}
