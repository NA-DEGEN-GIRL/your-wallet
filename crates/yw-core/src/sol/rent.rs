//! Rent rules, "send max" and amount text (spec/07 §11). Balances, account existence and rent come
//! from RPC (reference values): a lying RPC can only make the transaction fail, never change the
//! recipient or the amount.

use core::fmt;

/// Upper sanity bound of `getMinimumBalanceForRentExemption(0)`.
pub const SOL_RENT0_SANITY_MAX: u64 = 2_000_000;
/// Upper sanity bound of `getMinimumBalanceForRentExemption(165)` (v1.1).
pub const SOL_RENT165_SANITY_MAX: u64 = 5_000_000;

/// A rent/balance rule violation (an `L01` block) or an implausible RPC value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RentError {
    /// New recipient account below the rent-exempt minimum (`rent0`).
    BelowRentForNewAccount {
        /// `rent0`.
        rent0: u64,
    },
    /// The sender would keep `0 < r < rent0` lamports.
    SenderDust {
        /// `rent0`.
        rent0: u64,
    },
    /// Balance (RPC) below amount + maximum fee, or nothing left for "send max".
    InsufficientBalance,
    /// Zero amount.
    ZeroAmount,
    /// Rent outside `1..=SOL_RENT0_SANITY_MAX`.
    RpcAnomaly,
}

impl fmt::Display for RentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BelowRentForNewAccount { rent0 } => write!(
                formatter,
                "새 계정에는 최소 {} SOL을 보내야 합니다",
                format_amount(*rent0, 9)
            ),
            Self::SenderDust { rent0 } => write!(
                formatter,
                "보낸 뒤 남는 잔액은 0이거나 {} SOL 이상이어야 합니다",
                format_amount(*rent0, 9)
            ),
            Self::InsufficientBalance => formatter.write_str("잔액이 부족합니다(수수료 포함)"),
            Self::ZeroAmount => formatter.write_str("0은 보낼 수 없습니다"),
            Self::RpcAnomaly => formatter.write_str("RPC 응답 값이 비정상입니다"),
        }
    }
}

impl std::error::Error for RentError {}

/// Range check of `rent0` (spec/07 §11).
///
/// # Errors
///
/// [`RentError::RpcAnomaly`].
pub const fn check_rent0(rent0: u64) -> Result<(), RentError> {
    if rent0 == 0 || rent0 > SOL_RENT0_SANITY_MAX {
        return Err(RentError::RpcAnomaly);
    }
    Ok(())
}

/// SOL transfer rules: a new recipient needs `amount ≥ rent0`, and the sender keeps
/// `r = balance − amount − max_fee` with `r == 0 || r ≥ rent0`. Returns `r`.
///
/// # Errors
///
/// [`RentError`].
pub const fn check_sol_send(
    balance: u64,
    amount: u64,
    max_fee: u64,
    rent0: u64,
    recipient_exists: bool,
) -> Result<u64, RentError> {
    if amount == 0 {
        return Err(RentError::ZeroAmount);
    }
    if let Err(error) = check_rent0(rent0) {
        return Err(error);
    }
    if !recipient_exists && amount < rent0 {
        return Err(RentError::BelowRentForNewAccount { rent0 });
    }
    let Some(spent) = amount.checked_add(max_fee) else {
        return Err(RentError::InsufficientBalance);
    };
    let Some(rest) = balance.checked_sub(spent) else {
        return Err(RentError::InsufficientBalance);
    };
    if rest != 0 && rest < rent0 {
        return Err(RentError::SenderDust { rent0 });
    }
    Ok(rest)
}

/// "Send max": `amount = balance − max_fee` (≥ 1), leaving exactly 0.
///
/// # Errors
///
/// [`RentError::InsufficientBalance`].
pub const fn send_max_amount(balance: u64, max_fee: u64) -> Result<u64, RentError> {
    match balance.checked_sub(max_fee) {
        Some(amount) if amount >= 1 => Ok(amount),
        _ => Err(RentError::InsufficientBalance),
    }
}

/// Amount text error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AmountError {
    /// Not `^(0|[1-9][0-9]*)(\.[0-9]{1,d})?$`.
    Format,
    /// Zero.
    Zero,
    /// Above `u64::MAX` raw units.
    Overflow,
}

impl fmt::Display for AmountError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("금액 형식이 올바르지 않습니다.")
    }
}

impl std::error::Error for AmountError {}

/// Parses `^(0|[1-9][0-9]*)(\.[0-9]{1,d})?$` into raw units (no sign, exponent, comma or space;
/// not zero; at most `u64::MAX`).
///
/// # Errors
///
/// [`AmountError`].
pub fn parse_amount(text: &str, decimals: u8) -> Result<u64, AmountError> {
    let (whole, fraction) = match text.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (text, None),
    };
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    if !digits(whole) || (whole.len() > 1 && whole.starts_with('0')) {
        return Err(AmountError::Format);
    }
    if let Some(fraction) = fraction
        && (!digits(fraction) || fraction.len() > usize::from(decimals))
    {
        return Err(AmountError::Format);
    }
    let scale = 10_u128
        .checked_pow(u32::from(decimals))
        .ok_or(AmountError::Overflow)?;
    let mut value: u128 = 0;
    for byte in whole.bytes() {
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(u128::from(byte - b'0')))
            .ok_or(AmountError::Overflow)?;
        if value > u128::from(u64::MAX) {
            return Err(AmountError::Overflow);
        }
    }
    value = value.checked_mul(scale).ok_or(AmountError::Overflow)?;
    if let Some(fraction) = fraction {
        let mut part: u128 = 0;
        for byte in fraction.bytes() {
            part = part
                .checked_mul(10)
                .and_then(|v| v.checked_add(u128::from(byte - b'0')))
                .ok_or(AmountError::Overflow)?;
        }
        let missing = u32::from(decimals)
            .checked_sub(u32::try_from(fraction.len()).map_err(|_| AmountError::Format)?)
            .ok_or(AmountError::Format)?;
        part = part
            .checked_mul(10_u128.checked_pow(missing).ok_or(AmountError::Overflow)?)
            .ok_or(AmountError::Overflow)?;
        value = value.checked_add(part).ok_or(AmountError::Overflow)?;
    }
    let value = u64::try_from(value).map_err(|_| AmountError::Overflow)?;
    if value == 0 {
        return Err(AmountError::Zero);
    }
    Ok(value)
}

/// `"<integer>.<d digits>"` with trailing zeros kept (e.g. `1.000000000`).
#[must_use]
pub fn format_amount(raw: u64, decimals: u8) -> String {
    let scale = 10_u64.checked_pow(u32::from(decimals)).unwrap_or(1);
    let whole = raw.checked_div(scale).unwrap_or(raw);
    let fraction = raw.checked_rem(scale).unwrap_or(0);
    if decimals == 0 {
        return whole.to_string();
    }
    format!("{whole}.{fraction:0width$}", width = usize::from(decimals))
}

/// The raw integer with thousands separators (`1,000,000,000`).
#[must_use]
pub fn format_raw(raw: u64) -> String {
    let digits = raw.to_string();
    let mut out = String::with_capacity(digits.len().saturating_add(digits.len() / 3));
    for (index, character) in digits.chars().enumerate() {
        if index != 0 && (digits.len().saturating_sub(index)) % 3 == 0 {
            out.push(',');
        }
        out.push(character);
    }
    out
}

/// `1.000000000 SOL` (`1,000,000,000 lamports`) style text of lamports.
#[must_use]
pub fn sol_text(lamports: u64) -> String {
    format!("{} SOL", format_amount(lamports, 9))
}

#[cfg(test)]
mod tests {
    use super::{
        AmountError, RentError, check_rent0, check_sol_send, format_amount, format_raw,
        parse_amount, send_max_amount,
    };

    const RENT0: u64 = 890_880;

    #[test]
    fn rent_boundaries() {
        // New account: exactly rent0 passes, one less is blocked.
        assert_eq!(
            check_sol_send(10_000_000, RENT0, 5_000, RENT0, false),
            Ok(10_000_000 - RENT0 - 5_000)
        );
        assert_eq!(
            check_sol_send(10_000_000, RENT0 - 1, 5_000, RENT0, false),
            Err(RentError::BelowRentForNewAccount { rent0: RENT0 })
        );
        assert!(check_sol_send(10_000_000, 1, 5_000, RENT0, true).is_ok());
        // Sender remainder r = rent0 − 1 is dust; r = rent0 and r = 0 pass.
        let balance = 2_000_000;
        let fee = 5_000;
        let amount = balance - fee - (RENT0 - 1);
        assert_eq!(
            check_sol_send(balance, amount, fee, RENT0, true),
            Err(RentError::SenderDust { rent0: RENT0 })
        );
        assert_eq!(
            check_sol_send(balance, amount - 1, fee, RENT0, true),
            Ok(RENT0)
        );
        assert_eq!(
            check_sol_send(balance, balance - fee, fee, RENT0, true),
            Ok(0)
        );
        assert_eq!(
            check_sol_send(balance, balance - fee + 1, fee, RENT0, true),
            Err(RentError::InsufficientBalance)
        );
        assert_eq!(
            check_sol_send(balance, 0, fee, RENT0, true),
            Err(RentError::ZeroAmount)
        );
        assert_eq!(check_rent0(0), Err(RentError::RpcAnomaly));
        assert_eq!(check_rent0(2_000_001), Err(RentError::RpcAnomaly));
        assert_eq!(check_rent0(2_000_000), Ok(()));
        assert_eq!(
            check_sol_send(u64::MAX, u64::MAX, 5_000, RENT0, true),
            Err(RentError::InsufficientBalance)
        );
    }

    #[test]
    fn send_max() {
        assert_eq!(send_max_amount(1_000_000, 5_000), Ok(995_000));
        assert_eq!(send_max_amount(5_001, 5_000), Ok(1));
        assert_eq!(
            send_max_amount(5_000, 5_000),
            Err(RentError::InsufficientBalance)
        );
        assert_eq!(
            send_max_amount(0, 5_000),
            Err(RentError::InsufficientBalance)
        );
        // Send max leaves exactly 0, which the remainder rule accepts.
        let amount = send_max_amount(1_000_000, 5_000).unwrap();
        assert_eq!(check_sol_send(1_000_000, amount, 5_000, RENT0, true), Ok(0));
    }

    #[test]
    fn amount_text() {
        assert_eq!(parse_amount("1", 9), Ok(1_000_000_000));
        assert_eq!(parse_amount("0.000000001", 9), Ok(1));
        assert_eq!(parse_amount("1.5", 9), Ok(1_500_000_000));
        assert_eq!(parse_amount("18446744073.709551615", 9), Ok(u64::MAX));
        assert_eq!(
            parse_amount("18446744073.709551616", 9),
            Err(AmountError::Overflow)
        );
        assert_eq!(parse_amount("0", 9), Err(AmountError::Zero));
        assert_eq!(parse_amount("0.0", 9), Err(AmountError::Zero));
        for bad in [
            "",
            "01",
            "1.",
            ".5",
            "-1",
            "+1",
            "1e3",
            "1,000",
            " 1",
            "1 ",
            "1.0000000001",
            "１",
        ] {
            assert_eq!(parse_amount(bad, 9), Err(AmountError::Format), "{bad:?}");
        }
        assert_eq!(parse_amount("1.1234567", 6), Err(AmountError::Format));
        assert_eq!(format_amount(1_000_000_000, 9), "1.000000000");
        assert_eq!(format_amount(1, 9), "0.000000001");
        assert_eq!(format_amount(0, 9), "0.000000000");
        assert_eq!(format_raw(1_000_000_000), "1,000,000,000");
        assert_eq!(format_raw(999), "999");
        assert_eq!(format_raw(1_000), "1,000");
        assert_eq!(format_raw(0), "0");
    }
}
