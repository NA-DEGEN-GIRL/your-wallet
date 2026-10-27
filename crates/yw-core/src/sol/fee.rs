//! Fees (spec/07 §10): the maximum fee of a template, the CU price choice and the
//! `getFeeForMessage` cross-check.

use core::fmt;

/// Base fee per signature (protocol value, cross-checked with `getFeeForMessage`).
pub const SOL_BASE_FEE_LAMPORTS_PER_SIG: u64 = 5_000;
/// `T_SOL` compute-unit limit: measured maximum `unitsConsumed` + 150 (spec/07 §10). Measured on
/// devnet 2026-10-27 with `simulateTransaction` ×10 of the real template (max 450 CU;
/// `docs/acceptance/m7-live-20261027.md`), so 450 + 150 = 600.
pub const SOL_TRANSFER_CU_LIMIT: u32 = 600;
/// `T_SPL` compute-unit limit (v1.1; provisional until measured, spec/07 미결 5).
pub const SPL_TRANSFER_CU_LIMIT: u32 = 60_000;
/// Settings range of `max_fee_lamports` (spec/07 §10).
pub const MAX_FEE_RANGE: (u64, u64) = (10_000, 10_000_000);
/// Settings range of `max_cu_price_micro`.
pub const MAX_CU_PRICE_RANGE: (u64, u64) = (0, 100_000_000);
/// Default `max_fee_lamports`.
pub const DEFAULT_MAX_FEE_LAMPORTS: u64 = 100_000;
/// Default `max_cu_price_micro`.
pub const DEFAULT_MAX_CU_PRICE_MICRO: u64 = 1_000_000;

/// Fee arithmetic or cross-check failure (an `L01` block).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeError {
    /// The fee does not fit in `u64`.
    Overflow,
    /// `getFeeForMessage` returned `null` twice.
    FeeQueryFailed,
    /// The RPC fee is above the local maximum, or below it for "send max".
    FeeFormulaChanged,
    /// The maximum fee is above the user's cap.
    AboveCap,
}

impl fmt::Display for FeeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Overflow => "수수료 계산이 범위를 넘습니다",
            Self::FeeQueryFailed => "RPC에서 수수료를 확인하지 못했습니다",
            Self::FeeFormulaChanged => {
                "RPC 수수료가 지갑 계산과 다릅니다 — 수수료 공식이 바뀌었을 수 있습니다"
            }
            Self::AboveCap => "수수료가 설정한 상한을 넘습니다",
        })
    }
}

impl std::error::Error for FeeError {}

/// `ceil(cu_price_micro × cu_limit / 1_000_000)` in `u128`.
///
/// # Errors
///
/// [`FeeError::Overflow`] above `u64::MAX`.
pub fn priority_fee(cu_limit: u32, cu_price_micro: u64) -> Result<u64, FeeError> {
    let product = u128::from(cu_price_micro)
        .checked_mul(u128::from(cu_limit))
        .ok_or(FeeError::Overflow)?;
    let fee = product.div_ceil(1_000_000);
    u64::try_from(fee).map_err(|_| FeeError::Overflow)
}

/// `5_000 × 1 + priority_fee` (one signature).
///
/// # Errors
///
/// [`FeeError::Overflow`].
pub fn max_fee(cu_limit: u32, cu_price_micro: u64) -> Result<u64, FeeError> {
    SOL_BASE_FEE_LAMPORTS_PER_SIG
        .checked_add(priority_fee(cu_limit, cu_price_micro)?)
        .ok_or(FeeError::Overflow)
}

/// The p75 of `getRecentPrioritizationFees`: ascending, index `(n × 3) / 4`, 0 when empty.
#[must_use]
pub fn p75(fees: &[u64]) -> u64 {
    let mut sorted = fees.to_vec();
    sorted.sort_unstable();
    let index = sorted.len().saturating_mul(3) / 4;
    sorted.get(index).copied().unwrap_or(0)
}

/// `min(p75, max_cu_price_micro, floor((fee_cap − 5_000) × 1_000_000 / cu_limit))`, so the
/// maximum fee never exceeds the cap.
#[must_use]
pub fn choose_cu_price(p75: u64, max_cu_price_micro: u64, fee_cap: u64, cu_limit: u32) -> u64 {
    let budget = u128::from(fee_cap.saturating_sub(SOL_BASE_FEE_LAMPORTS_PER_SIG));
    let by_cap = budget
        .saturating_mul(1_000_000)
        .checked_div(u128::from(cu_limit))
        .unwrap_or(0);
    let by_cap = u64::try_from(by_cap).unwrap_or(u64::MAX);
    p75.min(max_cu_price_micro).min(by_cap)
}

/// Result of the `getFeeForMessage` cross-check that still allows approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeCheck {
    /// Same value.
    Match,
    /// The RPC estimate is lower (allowed for a normal send, shown with the value).
    RpcLower {
        /// RPC estimate.
        rpc: u64,
    },
}

/// The cross-check of spec/07 §10: `None` (after one retry) → `FeeQueryFailed`; higher →
/// `FeeFormulaChanged`; lower → allowed except for "send max"; equal → `Match`.
///
/// # Errors
///
/// [`FeeError::FeeQueryFailed`] or [`FeeError::FeeFormulaChanged`].
pub fn check_rpc_fee(
    rpc_fee: Option<u64>,
    max_fee: u64,
    send_max: bool,
) -> Result<FeeCheck, FeeError> {
    let rpc = rpc_fee.ok_or(FeeError::FeeQueryFailed)?;
    match rpc.cmp(&max_fee) {
        core::cmp::Ordering::Equal => Ok(FeeCheck::Match),
        core::cmp::Ordering::Greater => Err(FeeError::FeeFormulaChanged),
        core::cmp::Ordering::Less if send_max => Err(FeeError::FeeFormulaChanged),
        core::cmp::Ordering::Less => Ok(FeeCheck::RpcLower { rpc }),
    }
}

#[cfg(test)]
mod tests {
    use super::{FeeCheck, FeeError, check_rpc_fee, choose_cu_price, max_fee, p75, priority_fee};

    #[test]
    fn fee_formula_and_rounding() {
        assert_eq!(max_fee(450, 1_000), Ok(5_001));
        assert_eq!(max_fee(40_000, 1_000), Ok(5_040));
        assert_eq!(priority_fee(600, 0), Ok(0));
        assert_eq!(priority_fee(600, 1), Ok(1));
        assert_eq!(priority_fee(1_000_000, 1), Ok(1));
        assert_eq!(priority_fee(1_000_001, 1), Ok(2));
        // u128 intermediate: u64::MAX × 1_400_000 does not fit u64 but the quotient may not either.
        assert_eq!(priority_fee(1_400_000, u64::MAX), Err(FeeError::Overflow));
        assert_eq!(priority_fee(1_000_000, u64::MAX), Ok(u64::MAX));
        assert_eq!(max_fee(1_000_000, u64::MAX), Err(FeeError::Overflow));
    }

    #[test]
    fn p75_and_price_clamp() {
        assert_eq!(p75(&[]), 0);
        assert_eq!(p75(&[7]), 7);
        assert_eq!(p75(&[4, 1, 3, 2]), 4);
        assert_eq!(p75(&[0, 0, 0, 0, 0, 0, 0, 100]), 0);
        assert_eq!(p75(&[8, 7, 6, 5, 4, 3, 2, 1]), 7);
        assert_eq!(p75(&[5, 1, 9]), 9);
        // min(p75, setting cap, fee-cap budget)
        assert_eq!(choose_cu_price(500, 1_000_000, 100_000, 600), 500);
        assert_eq!(
            choose_cu_price(5_000_000, 1_000_000, 100_000_000, 600),
            1_000_000
        );
        let price = choose_cu_price(u64::MAX, u64::MAX, 10_000, 600);
        assert_eq!(price, 5_000 * 1_000_000 / 600);
        assert!(max_fee(600, price).unwrap() <= 10_000);
        assert!(max_fee(600, price + 1).unwrap() > 10_000);
        assert_eq!(choose_cu_price(9, 9, 4_000, 600), 0);
    }

    #[test]
    fn rpc_fee_cross_check() {
        assert_eq!(
            check_rpc_fee(Some(5_001), 5_001, false),
            Ok(FeeCheck::Match)
        );
        assert_eq!(check_rpc_fee(Some(5_001), 5_001, true), Ok(FeeCheck::Match));
        assert_eq!(
            check_rpc_fee(Some(5_000), 5_001, false),
            Ok(FeeCheck::RpcLower { rpc: 5_000 })
        );
        assert_eq!(
            check_rpc_fee(Some(5_000), 5_001, true),
            Err(FeeError::FeeFormulaChanged)
        );
        assert_eq!(
            check_rpc_fee(Some(5_002), 5_001, false),
            Err(FeeError::FeeFormulaChanged)
        );
        assert_eq!(
            check_rpc_fee(Some(5_002), 5_001, true),
            Err(FeeError::FeeFormulaChanged)
        );
        assert_eq!(
            check_rpc_fee(None, 5_001, false),
            Err(FeeError::FeeQueryFailed)
        );
    }
}
