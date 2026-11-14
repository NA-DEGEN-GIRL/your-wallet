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
    /// An existing recipient below `rent0` (rent-paying) would stay below it: at least `needed`
    /// lamports must be sent (`rent0 − its lamports`).
    RecipientBelowRent {
        /// Lamports the transfer must at least carry.
        needed: u64,
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
    /// Rent outside `1..=SOL_RENT0_SANITY_MAX` (or `rent165` outside its range).
    RpcAnomaly,
    /// SPL: the sender has no token account (ATA) for this mint (RPC).
    NoTokenAccount,
    /// SPL: amount above the token balance (RPC), or nothing to send for "send max".
    InsufficientTokens,
    /// SPL: after the maximum fee and the possible ATA rent the sender must keep `rent0`
    /// lamports (no SPL transfer empties the SOL account).
    SolReserve {
        /// `max_fee + (to_ata missing ? rent165 : 0) + rent0`.
        needed: u64,
        /// `rent0`.
        rent0: u64,
    },
}

impl RentError {
    /// The fixed text in `lang` (`Display` is the Korean one).
    #[must_use]
    pub fn text_in(self, lang: crate::lang::Lang) -> String {
        use super::text as t;
        match self {
            Self::BelowRentForNewAccount { rent0 } => {
                t::RENT_NEW_ACCOUNT.fill(lang, [&format_amount(rent0, 9)])
            }
            Self::RecipientBelowRent { needed, rent0 } => t::RENT_RECIPIENT_BELOW
                .fill(lang, [&format_amount(rent0, 9), &format_amount(needed, 9)]),
            Self::SenderDust { rent0 } => {
                t::RENT_SENDER_DUST.fill(lang, [&format_amount(rent0, 9)])
            }
            Self::InsufficientBalance => t::RENT_INSUFFICIENT.get(lang).to_owned(),
            Self::ZeroAmount => t::RENT_ZERO.get(lang).to_owned(),
            Self::RpcAnomaly => t::RPC_ANOMALY.get(lang).to_owned(),
            Self::NoTokenAccount => t::RENT_NO_TOKEN_ACCOUNT.get(lang).to_owned(),
            Self::InsufficientTokens => t::RENT_INSUFFICIENT_TOKENS.get(lang).to_owned(),
            Self::SolReserve { needed, rent0 } => t::RENT_SOL_RESERVE
                .fill(lang, [&format_amount(rent0, 9), &format_amount(needed, 9)]),
        }
    }
}

impl fmt::Display for RentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text_in(crate::lang::Lang::Ko))
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

/// SOL transfer rules (spec/07 §11): the recipient must end at or above `rent0` —
/// `recipient_lamports` is `None` for a missing account; a missing account or one reported with
/// 0 lamports needs `amount ≥ rent0`, an existing one below `rent0` needs
/// `lamports + amount ≥ rent0` — and the sender keeps `r = balance − amount − max_fee` with
/// `r == 0 || r ≥ rent0`. Returns `r`; `r == 0` empties the account like "send max", so the
/// `getFeeForMessage` cross-check treats it as one (spec/07 §10).
///
/// # Errors
///
/// [`RentError`].
pub const fn check_sol_send(
    balance: u64,
    amount: u64,
    max_fee: u64,
    rent0: u64,
    recipient_lamports: Option<u64>,
) -> Result<u64, RentError> {
    if amount == 0 {
        return Err(RentError::ZeroAmount);
    }
    if let Err(error) = check_rent0(rent0) {
        return Err(error);
    }
    match recipient_lamports {
        None | Some(0) => {
            if amount < rent0 {
                return Err(RentError::BelowRentForNewAccount { rent0 });
            }
        }
        Some(lamports) => {
            let needed = rent0.saturating_sub(lamports);
            if amount < needed {
                return Err(RentError::RecipientBelowRent { needed, rent0 });
            }
        }
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

/// Range check of `rent165` (v1.1).
///
/// # Errors
///
/// [`RentError::RpcAnomaly`].
pub const fn check_rent165(rent165: u64) -> Result<(), RentError> {
    if rent165 == 0 || rent165 > SOL_RENT165_SANITY_MAX {
        return Err(RentError::RpcAnomaly);
    }
    Ok(())
}

/// What an allowed SPL transfer leaves (RPC reference values).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SplSendCheck {
    /// Lamports left: `balance − max_fee − rent`.
    pub sol_after: u64,
    /// Token raw units left.
    pub token_after: u64,
    /// The ATA rent the sender pays (`rent165` when the destination ATA is missing, else 0).
    pub rent: u64,
}

/// SPL rules (spec/07 §11): `0 < amount ≤ from_ata.amount` (no `from_ata` → `NoTokenAccount`)
/// and the SOL account keeps `r = balance − max_fee − (to_ata missing ? rent165 : 0) ≥ rent0`.
///
/// # Errors
///
/// [`RentError`].
pub const fn check_spl_send(
    balance: u64,
    max_fee: u64,
    rent0: u64,
    rent165: u64,
    to_ata_exists: bool,
    token_balance: Option<u64>,
    amount: u64,
) -> Result<SplSendCheck, RentError> {
    if let Err(error) = check_rent0(rent0) {
        return Err(error);
    }
    if let Err(error) = check_rent165(rent165) {
        return Err(error);
    }
    if amount == 0 {
        return Err(RentError::ZeroAmount);
    }
    let Some(tokens) = token_balance else {
        return Err(RentError::NoTokenAccount);
    };
    let Some(token_after) = tokens.checked_sub(amount) else {
        return Err(RentError::InsufficientTokens);
    };
    let rent = if to_ata_exists { 0 } else { rent165 };
    let needed = max_fee.saturating_add(rent).saturating_add(rent0);
    let sol_after = balance.saturating_sub(max_fee).saturating_sub(rent);
    if balance < needed {
        return Err(RentError::SolReserve { needed, rent0 });
    }
    Ok(SplSendCheck {
        sol_after,
        token_after,
        rent,
    })
}

/// SPL "send max": the whole token balance of `from_ata`.
///
/// # Errors
///
/// [`RentError::NoTokenAccount`] or [`RentError::InsufficientTokens`] (zero balance).
pub const fn spl_send_max_amount(token_balance: Option<u64>) -> Result<u64, RentError> {
    match token_balance {
        None => Err(RentError::NoTokenAccount),
        Some(0) => Err(RentError::InsufficientTokens),
        Some(amount) => Ok(amount),
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
        AmountError, RentError, SOL_RENT165_SANITY_MAX, SplSendCheck, check_rent0, check_rent165,
        check_sol_send, check_spl_send, format_amount, format_raw, parse_amount, send_max_amount,
        spl_send_max_amount,
    };

    const RENT0: u64 = 890_880;

    #[test]
    fn rent_boundaries() {
        // New account: exactly rent0 passes, one less is blocked.
        assert_eq!(
            check_sol_send(10_000_000, RENT0, 5_000, RENT0, None),
            Ok(10_000_000 - RENT0 - 5_000)
        );
        assert_eq!(
            check_sol_send(10_000_000, RENT0 - 1, 5_000, RENT0, None),
            Err(RentError::BelowRentForNewAccount { rent0: RENT0 })
        );
        assert!(check_sol_send(10_000_000, 1, 5_000, RENT0, Some(RENT0)).is_ok());
        // Sender remainder r = rent0 − 1 is dust; r = rent0 and r = 0 pass.
        let balance = 2_000_000;
        let fee = 5_000;
        let amount = balance - fee - (RENT0 - 1);
        assert_eq!(
            check_sol_send(balance, amount, fee, RENT0, Some(RENT0)),
            Err(RentError::SenderDust { rent0: RENT0 })
        );
        assert_eq!(
            check_sol_send(balance, amount - 1, fee, RENT0, Some(RENT0)),
            Ok(RENT0)
        );
        assert_eq!(
            check_sol_send(balance, balance - fee, fee, RENT0, Some(RENT0)),
            Ok(0)
        );
        assert_eq!(
            check_sol_send(balance, balance - fee + 1, fee, RENT0, Some(RENT0)),
            Err(RentError::InsufficientBalance)
        );
        assert_eq!(
            check_sol_send(balance, 0, fee, RENT0, Some(RENT0)),
            Err(RentError::ZeroAmount)
        );
        assert_eq!(check_rent0(0), Err(RentError::RpcAnomaly));
        assert_eq!(check_rent0(2_000_001), Err(RentError::RpcAnomaly));
        assert_eq!(check_rent0(2_000_000), Ok(()));
        assert_eq!(
            check_sol_send(u64::MAX, u64::MAX, 5_000, RENT0, Some(RENT0)),
            Err(RentError::InsufficientBalance)
        );
    }

    #[test]
    fn recipient_must_end_at_or_above_rent0() {
        let balance = 10_000_000;
        // An account reported with 0 lamports is a new account.
        assert_eq!(
            check_sol_send(balance, RENT0 - 1, 5_000, RENT0, Some(0)),
            Err(RentError::BelowRentForNewAccount { rent0: RENT0 })
        );
        assert!(check_sol_send(balance, RENT0, 5_000, RENT0, Some(0)).is_ok());
        // An existing rent-paying account below rent0 needs at least the difference.
        let lamports = RENT0 - 1_000;
        assert_eq!(
            check_sol_send(balance, 999, 5_000, RENT0, Some(lamports)),
            Err(RentError::RecipientBelowRent {
                needed: 1_000,
                rent0: RENT0
            })
        );
        assert!(check_sol_send(balance, 1_000, 5_000, RENT0, Some(lamports)).is_ok());
        // At or above rent0: any amount.
        assert!(check_sol_send(balance, 1, 5_000, RENT0, Some(RENT0)).is_ok());
        assert!(check_sol_send(balance, 1, 5_000, RENT0, Some(u64::MAX)).is_ok());
        assert_eq!(
            RentError::RecipientBelowRent {
                needed: 1_000,
                rent0: 650_240
            }
            .to_string(),
            "받는 계정의 잔액이 rent 기준(0.000650240 SOL)보다 적어 최소 0.000001000 SOL을 보내야 합니다"
        );
        // r == 0 is reported as such (the fee cross-check then treats it as send max).
        assert_eq!(
            check_sol_send(balance, balance - 5_000, 5_000, RENT0, Some(RENT0)),
            Ok(0)
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
        assert_eq!(
            check_sol_send(1_000_000, amount, 5_000, RENT0, Some(RENT0)),
            Ok(0)
        );
    }

    #[test]
    fn spl_rules_and_rent_display_values() {
        const RENT165: u64 = 2_039_280;
        const FEE: u64 = 5_040;
        // Missing destination ATA: the sender pays rent165 and keeps at least rent0.
        let needed = FEE + RENT165 + RENT0;
        assert_eq!(
            check_spl_send(needed, FEE, RENT0, RENT165, false, Some(10), 10),
            Ok(SplSendCheck {
                sol_after: RENT0,
                token_after: 0,
                rent: RENT165
            })
        );
        assert_eq!(
            check_spl_send(needed - 1, FEE, RENT0, RENT165, false, Some(10), 10),
            Err(RentError::SolReserve {
                needed,
                rent0: RENT0
            })
        );
        // Existing destination ATA: no rent.
        assert_eq!(
            check_spl_send(FEE + RENT0, FEE, RENT0, RENT165, true, Some(10), 3),
            Ok(SplSendCheck {
                sol_after: RENT0,
                token_after: 7,
                rent: 0
            })
        );
        // The SOL account is never emptied by an SPL transfer (r = 0 is not allowed).
        assert!(matches!(
            check_spl_send(FEE, FEE, RENT0, RENT165, true, Some(10), 3),
            Err(RentError::SolReserve { .. })
        ));
        // Token side.
        assert_eq!(
            check_spl_send(10 * RENT165, FEE, RENT0, RENT165, true, None, 1),
            Err(RentError::NoTokenAccount)
        );
        assert_eq!(
            check_spl_send(10 * RENT165, FEE, RENT0, RENT165, true, Some(9), 10),
            Err(RentError::InsufficientTokens)
        );
        assert_eq!(
            check_spl_send(10 * RENT165, FEE, RENT0, RENT165, true, Some(9), 0),
            Err(RentError::ZeroAmount)
        );
        // rent165 sanity range.
        for bad in [0, SOL_RENT165_SANITY_MAX + 1] {
            assert_eq!(check_rent165(bad), Err(RentError::RpcAnomaly));
            assert_eq!(
                check_spl_send(10 * RENT165, FEE, RENT0, bad, true, Some(9), 1),
                Err(RentError::RpcAnomaly)
            );
        }
        assert_eq!(check_rent165(SOL_RENT165_SANITY_MAX), Ok(()));
        // Send max = the whole token balance.
        assert_eq!(spl_send_max_amount(Some(42)), Ok(42));
        assert_eq!(
            spl_send_max_amount(Some(0)),
            Err(RentError::InsufficientTokens)
        );
        assert_eq!(spl_send_max_amount(None), Err(RentError::NoTokenAccount));
        assert_eq!(
            RentError::SolReserve {
                needed: 2_694_560,
                rent0: 650_240
            }
            .to_string(),
            "SOL이 부족합니다: 수수료와 받는 토큰 계정 생성비(필요할 때)를 내고도 0.000650240 SOL이 남아야 합니다(필요 0.002694560 SOL)"
        );
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
