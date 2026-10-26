//! Fees, gas limit and replacement fees (spec/03 §3.4–§3.5, §4.6, D20).
//!
//! Policy from `archive/spec-v2.4:demo/sepolia-wallet/src/backend.rs:6554-6773` and
//! `archive/spec-v2.4:demo/sepolia-wallet/src/rpc.rs:645-679`, re-specified for v3: the wallet
//! computes fees from `eth_feeHistory(["0xa","latest",[50]])`, dApp fee fields are ignored, and
//! the gas limit is `max(dApp gas, ⌈estimate × 1.2⌉)` capped at 16,777,216. All arithmetic is
//! checked (overflow → E05).
#![deny(clippy::arithmetic_side_effects)]

use core::fmt;
use core::num::NonZeroU64;

use super::address::Address;
use super::amount::{U256, format_amount, format_gwei};
use super::chain::ChainInfo;
use super::decode::revert_reason;
use super::risk::{self, E05, E10, E37, E38};
use super::tx::{Eip1559Tx, TX_GAS_CAP};
use crate::approval::Warning;

/// `eth_feeHistory` result as passed by yw-app (spec/03 §3.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeHistory {
    /// `n + 1` base fees (the last one is the next block's).
    pub base_fee_per_gas: Vec<U256>,
    /// `gasUsedRatio[i]` token is not zero (no floating point).
    pub nonempty: Vec<bool>,
    /// 50th-percentile reward per block.
    pub reward_p50: Vec<U256>,
}

/// Wallet-computed fees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fees {
    /// Tip.
    pub max_priority_fee_per_gas: U256,
    /// `2 × base_fee_next + tip`.
    pub max_fee_per_gas: U256,
    /// Next block's base fee.
    pub base_fee_next: U256,
}

/// Fee caps (spec/03 §1.1 defaults, user-adjustable in settings).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_field_names,
    reason = "field names fixed by spec/03 §3.4"
)]
pub struct FeeCaps {
    /// Cap on `max_fee_per_gas`.
    pub max_fee_per_gas: U256,
    /// Cap on the tip.
    pub max_priority_fee_per_gas: U256,
    /// Cap on `gas_limit × max_fee_per_gas`.
    pub max_total_fee: U256,
}

/// Fee computation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeError {
    /// The fee history has inconsistent lengths or is empty (E35).
    InvalidHistory,
    /// Arithmetic overflow (E05).
    Overflow,
}

impl fmt::Display for FeeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidHistory => "invalid fee history",
            Self::Overflow => "fee arithmetic overflow",
        })
    }
}

impl std::error::Error for FeeError {}

/// Which cap was exceeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapKind {
    /// Tip above `max_priority_fee_per_gas` cap.
    PriorityFee,
    /// `max_fee_per_gas` above its cap.
    MaxFee,
    /// `gas_limit × max_fee` above the total cap.
    TotalFee,
    /// The total could not be computed (overflow).
    Overflow,
}

/// A cap violation (E05, blocked).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapViolation {
    /// Violated cap.
    pub kind: CapKind,
    /// Computed value.
    pub value: U256,
    /// Cap.
    pub cap: U256,
}

impl CapViolation {
    /// The E05 warning with the computed value and the cap.
    #[must_use]
    pub fn warning(&self, chain: &ChainInfo) -> Warning {
        let native =
            |value: &U256| format_amount(value, chain.native_decimals, &chain.native_symbol);
        let cause = match self.kind {
            CapKind::PriorityFee => format!(
                "우선 수수료 {} > 상한 {}",
                format_gwei(&self.value),
                format_gwei(&self.cap)
            ),
            CapKind::MaxFee => format!(
                "최대 가스 가격 {} > 상한 {}",
                format_gwei(&self.value),
                format_gwei(&self.cap)
            ),
            CapKind::TotalFee => format!(
                "최대 수수료 {} > 상한 {}",
                native(&self.value),
                native(&self.cap)
            ),
            CapKind::Overflow => "수수료 계산이 범위를 넘었습니다".to_owned(),
        };
        risk::warning(E05, Some(&cause))
    }
}

/// Suggests fees from fee history (spec/03 §3.4 steps 1–5).
///
/// # Errors
///
/// [`FeeError::InvalidHistory`] (E35) or [`FeeError::Overflow`] (E05).
pub fn suggest_fees(history: &FeeHistory, chain: &ChainInfo) -> Result<Fees, FeeError> {
    let n = history.reward_p50.len();
    if n == 0
        || n > 10
        || history.nonempty.len() != n
        || history.base_fee_per_gas.len() != n.checked_add(1).ok_or(FeeError::InvalidHistory)?
    {
        return Err(FeeError::InvalidHistory);
    }
    let base_fee_next = *history
        .base_fee_per_gas
        .get(n)
        .ok_or(FeeError::InvalidHistory)?;
    let mut samples: Vec<U256> = history
        .reward_p50
        .iter()
        .zip(&history.nonempty)
        .filter_map(|(reward, nonempty)| nonempty.then_some(*reward))
        .collect();
    samples.sort();
    let floor = U256::from_u64(chain.tip_floor_wei);
    let median = samples
        .len()
        .checked_sub(1)
        .and_then(|last| samples.get(last / 2))
        .copied()
        .unwrap_or(floor);
    let tip = median.max(floor);
    let max_fee = base_fee_next
        .checked_mul_u64(2)
        .and_then(|doubled| doubled.checked_add(tip))
        .ok_or(FeeError::Overflow)?;
    Ok(Fees {
        max_priority_fee_per_gas: tip,
        max_fee_per_gas: max_fee,
        base_fee_next,
    })
}

/// `gas_limit × max_fee`, the maximum fee.
#[must_use]
pub fn max_total_fee(gas_limit: u64, max_fee: &U256) -> Option<U256> {
    max_fee.checked_mul_u64(gas_limit)
}

/// Checks the caps (spec/03 §3.4 step 6). Values are never lowered automatically.
///
/// # Errors
///
/// The first [`CapViolation`] (E05).
pub fn check_caps(fees: &Fees, gas_limit: u64, caps: &FeeCaps) -> Result<(), CapViolation> {
    if fees.max_priority_fee_per_gas > caps.max_priority_fee_per_gas {
        return Err(CapViolation {
            kind: CapKind::PriorityFee,
            value: fees.max_priority_fee_per_gas,
            cap: caps.max_priority_fee_per_gas,
        });
    }
    if fees.max_fee_per_gas > caps.max_fee_per_gas {
        return Err(CapViolation {
            kind: CapKind::MaxFee,
            value: fees.max_fee_per_gas,
            cap: caps.max_fee_per_gas,
        });
    }
    let Some(total) = max_total_fee(gas_limit, &fees.max_fee_per_gas) else {
        return Err(CapViolation {
            kind: CapKind::Overflow,
            value: U256::MAX,
            cap: caps.max_total_fee,
        });
    };
    if total > caps.max_total_fee {
        return Err(CapViolation {
            kind: CapKind::TotalFee,
            value: total,
            cap: caps.max_total_fee,
        });
    }
    Ok(())
}

/// Result of `eth_estimateGas` (spec/03 §3.5 step 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GasEstimate<'a> {
    /// Estimate succeeded.
    Estimated(u64),
    /// Any failure (revert, execution error, RPC or transport error, timeout).
    Failed {
        /// `error.data` of a revert, for the E37 cause line.
        revert_data: Option<&'a [u8]>,
    },
}

/// Gas limit decision with its warnings (E10 blocked, E37 high, E38 caution).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GasPlan {
    /// Gas limit used for simulation and signing.
    pub gas_limit: u64,
    /// Warnings produced by §3.5.
    pub warnings: Vec<Warning>,
}

/// Computes the gas limit (spec/03 §3.5). `fees` come first (§3.4) so the fallback never trips
/// the total cap.
#[must_use]
pub fn plan_gas_limit(
    estimate: GasEstimate<'_>,
    dapp_gas: Option<u64>,
    fees: &Fees,
    caps: &FeeCaps,
    chain: &ChainInfo,
) -> GasPlan {
    let mut warnings = Vec::new();
    let gas_limit = match estimate {
        GasEstimate::Estimated(estimate) => {
            if estimate > TX_GAS_CAP {
                warnings.push(risk::warning(E10, None));
            }
            let margin = U256::from_u64(estimate)
                .ceil_mul_div_u64(12, NonZeroU64::new(10).unwrap_or(NonZeroU64::MIN))
                .and_then(U256::to_u64)
                .unwrap_or(u64::MAX);
            dapp_gas.unwrap_or(0).max(margin).min(TX_GAS_CAP)
        }
        GasEstimate::Failed { revert_data } => {
            let cause = revert_data.map(|data| format!("이유: {}", revert_reason(data)));
            warnings.push(risk::warning(E37, cause.as_deref()));
            dapp_gas.unwrap_or_else(|| {
                let affordable =
                    divide(caps.max_total_fee, fees.max_fee_per_gas).unwrap_or(TX_GAS_CAP);
                TX_GAS_CAP
                    .min(chain.small_block_gas_limit.unwrap_or(TX_GAS_CAP))
                    .min(affordable)
            })
        }
    };
    if let Some(small) = chain.small_block_gas_limit
        && gas_limit > small
    {
        warnings.push(risk::warning_text(
            E38,
            format!(
                "HyperEVM 작은 블록 한도({})를 넘는 거래입니다 — 계정에 큰 블록 사용이 켜져 있지 않으면 포함되지 않을 수 있습니다",
                super::amount::format_units(&U256::from_u64(small), 0)
            ),
        ));
    }
    GasPlan {
        gas_limit,
        warnings,
    }
}

/// `⌊a / b⌋` as `u64` (saturating at `u64::MAX`), `None` for `b == 0`.
fn divide(a: U256, b: U256) -> Option<u64> {
    if b.is_zero() {
        return None;
    }
    // Binary long division on 256 bits; the quotient is clamped to u64.
    let mut quotient = U256::ZERO;
    let mut remainder = U256::ZERO;
    for byte in a.to_be_bytes() {
        for bit in (0..8_u32).rev() {
            remainder = remainder.checked_mul_u64(2)?;
            if (byte.wrapping_shr(bit) & 1) == 1 {
                remainder = remainder.checked_add(U256::ONE)?;
            }
            quotient = quotient.checked_mul_u64(2).unwrap_or(U256::MAX);
            if remainder >= b {
                remainder = remainder.checked_sub(b)?;
                quotient = quotient.checked_add(U256::ONE).unwrap_or(U256::MAX);
            }
        }
    }
    Some(quotient.to_u64().unwrap_or(u64::MAX))
}

/// Replacement fees for speed-up and cancel (spec/03 §4.6):
/// `tip' = max(⌈old_tip × 1.1⌉, f.tip)`, `max_fee' = max(⌈old_max × 1.1⌉, 2 × base_next + tip')`.
///
/// # Errors
///
/// [`FeeError::Overflow`].
pub fn replacement_fees(
    old_tip: &U256,
    old_max_fee: &U256,
    fresh: &Fees,
) -> Result<(U256, U256), FeeError> {
    let ten = NonZeroU64::new(10).ok_or(FeeError::Overflow)?;
    let bumped_tip = old_tip
        .ceil_mul_div_u64(11, ten)
        .ok_or(FeeError::Overflow)?;
    let tip = bumped_tip.max(fresh.max_priority_fee_per_gas);
    let bumped_max = old_max_fee
        .ceil_mul_div_u64(11, ten)
        .ok_or(FeeError::Overflow)?;
    let floor = fresh
        .base_fee_next
        .checked_mul_u64(2)
        .and_then(|doubled| doubled.checked_add(tip))
        .ok_or(FeeError::Overflow)?;
    Ok((tip, bumped_max.max(floor)))
}

/// Expected fee shown with a simulation: `gas_used × min(max_fee, base_fee + tip)` (spec/03 §6.4).
#[must_use]
pub fn expected_fee(gas_used: u64, max_fee: &U256, base_fee: &U256, tip: &U256) -> Option<U256> {
    let price = base_fee.checked_add(*tip)?.min(*max_fee);
    price.checked_mul_u64(gas_used)
}

/// The speed-up candidate (spec/03 §4.6): the newest candidate's `to`, `value`, `data`,
/// `access_list` and `gas_limit` with fees `tip' = max(⌈old_tip × 1.1⌉, f.tip)` and
/// `max_fee' = max(⌈old_max × 1.1⌉, 2 × f.base_fee_next + tip')`.
///
/// # Errors
///
/// [`FeeError::Overflow`] (E05).
pub fn speed_up_tx(latest: &Eip1559Tx, fresh: &Fees) -> Result<Eip1559Tx, FeeError> {
    let (tip, max_fee) = replacement_fees(
        &latest.max_priority_fee_per_gas,
        &latest.max_fee_per_gas,
        fresh,
    )?;
    Ok(Eip1559Tx {
        max_priority_fee_per_gas: tip,
        max_fee_per_gas: max_fee,
        ..latest.clone()
    })
}

/// The cancel candidate (spec/03 §4.6): a zero-value self-transfer with the same nonce, empty data
/// and access list, `gas_limit` (= ⌈estimate × 1.2⌉ from [`plan_gas_limit`]) and the +10 % fee
/// rule of [`speed_up_tx`].
///
/// # Errors
///
/// [`FeeError::Overflow`] (E05).
pub fn cancel_tx(
    latest: &Eip1559Tx,
    account: &Address,
    gas_limit: u64,
    fresh: &Fees,
) -> Result<Eip1559Tx, FeeError> {
    let (tip, max_fee) = replacement_fees(
        &latest.max_priority_fee_per_gas,
        &latest.max_fee_per_gas,
        fresh,
    )?;
    Ok(Eip1559Tx {
        chain_id: latest.chain_id,
        nonce: latest.nonce,
        max_priority_fee_per_gas: tip,
        max_fee_per_gas: max_fee,
        gas_limit,
        to: *account,
        value: U256::ZERO,
        data: Vec::new(),
        access_list: Vec::new(),
    })
}

/// The fees of a built transaction, for the cap check of a replacement (§4.6 "둘 다: 상한 검사").
#[must_use]
pub const fn fees_of(tx: &Eip1559Tx, base_fee_next: U256) -> Fees {
    Fees {
        max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
        max_fee_per_gas: tx.max_fee_per_gas,
        base_fee_next,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CapKind, FeeHistory, Fees, GasEstimate, check_caps, divide, expected_fee, plan_gas_limit,
        replacement_fees, suggest_fees,
    };
    use crate::evm::amount::U256;
    use crate::evm::chain::{ethereum_mainnet, hyperevm_mainnet, sepolia};
    use crate::evm::risk::{E10, E37, E38};

    fn gwei_milli(milli: u64) -> U256 {
        U256::from_u64(milli).checked_mul_u64(1_000_000).unwrap()
    }

    fn fees(max_fee: U256) -> Fees {
        Fees {
            max_priority_fee_per_gas: U256::ZERO,
            max_fee_per_gas: max_fee,
            base_fee_next: U256::ZERO,
        }
    }

    #[test]
    fn suggest_fee_vector() {
        // n = 10, one empty block, rewards [0.5,1,2,1.5,3,1,2,0.8,1.2] gwei, base_next 10 gwei.
        let rewards = [0, 500, 1_000, 2_000, 1_500, 3_000, 1_000, 2_000, 800, 1_200];
        let history = FeeHistory {
            base_fee_per_gas: (0..11).map(|_| gwei_milli(10_000)).collect(),
            nonempty: rewards.iter().map(|reward| *reward != 0).collect(),
            reward_p50: rewards.iter().map(|reward| gwei_milli(*reward)).collect(),
        };
        let fees = suggest_fees(&history, &sepolia()).unwrap();
        assert_eq!(fees.max_priority_fee_per_gas, gwei_milli(1_200));
        assert_eq!(fees.max_fee_per_gas, gwei_milli(21_200));
        assert_eq!(fees.base_fee_next, gwei_milli(10_000));
    }

    #[test]
    fn suggest_fee_floor_and_shape() {
        let history = FeeHistory {
            base_fee_per_gas: vec![U256::ZERO, U256::from_u64(5)],
            nonempty: vec![false],
            reward_p50: vec![U256::ZERO],
        };
        let fees = suggest_fees(&history, &sepolia()).unwrap();
        assert_eq!(fees.max_priority_fee_per_gas, U256::from_u64(10_000_000));
        assert_eq!(fees.max_fee_per_gas, U256::from_u64(10_000_010));
        let bad = FeeHistory {
            base_fee_per_gas: vec![U256::ZERO],
            nonempty: vec![false],
            reward_p50: vec![U256::ZERO],
        };
        assert!(suggest_fees(&bad, &sepolia()).is_err());
        let empty = FeeHistory {
            base_fee_per_gas: vec![U256::ZERO],
            nonempty: vec![],
            reward_p50: vec![],
        };
        assert!(suggest_fees(&empty, &sepolia()).is_err());
    }

    #[test]
    fn caps() {
        let chain = ethereum_mainnet();
        let ok = Fees {
            max_priority_fee_per_gas: gwei_milli(1_000),
            max_fee_per_gas: gwei_milli(25_000),
            base_fee_next: gwei_milli(12_000),
        };
        assert_eq!(check_caps(&ok, 21_000, &chain.default_caps), Ok(()));
        let violation = check_caps(&ok, 3_000_000, &chain.default_caps).unwrap_err();
        assert_eq!(violation.kind, CapKind::TotalFee);
        assert!(violation.warning(&chain).text.contains("상한"));
        let tip = Fees {
            max_priority_fee_per_gas: gwei_milli(6_000),
            ..ok
        };
        assert_eq!(
            check_caps(&tip, 21_000, &chain.default_caps)
                .unwrap_err()
                .kind,
            CapKind::PriorityFee
        );
        let max = Fees {
            max_fee_per_gas: gwei_milli(201_000),
            ..ok
        };
        assert_eq!(
            check_caps(&max, 21_000, &chain.default_caps)
                .unwrap_err()
                .kind,
            CapKind::MaxFee
        );
    }

    #[test]
    fn gas_vectors() {
        let mainnet = ethereum_mainnet();
        let hyper = hyperevm_mainnet();
        let any_fee = fees(gwei_milli(25_000));
        let plan = |estimate, dapp, chain: &crate::evm::chain::ChainInfo, fee: &Fees| {
            plan_gas_limit(estimate, dapp, fee, &chain.default_caps, chain)
        };
        let estimated = |gas| GasEstimate::Estimated(gas);
        assert_eq!(
            plan(estimated(21_000), None, &mainnet, &any_fee).gas_limit,
            25_200
        );
        assert_eq!(
            plan(estimated(204_600), Some(0x30000), &mainnet, &any_fee).gas_limit,
            245_520
        );
        assert_eq!(
            plan(estimated(50_000), Some(100_000), &mainnet, &any_fee).gas_limit,
            100_000
        );
        let capped = plan(estimated(15_000_000), None, &mainnet, &any_fee);
        assert_eq!(capped.gas_limit, 16_777_216);
        assert!(capped.warnings.is_empty());
        let over = plan(estimated(16_777_217), None, &mainnet, &any_fee);
        assert_eq!(over.warnings.first().unwrap().rule, E10);
        let failed = GasEstimate::Failed { revert_data: None };
        let fallback = plan(failed, None, &mainnet, &any_fee);
        assert_eq!(fallback.gas_limit, 2_000_000);
        assert_eq!(fallback.warnings.first().unwrap().rule, E37);
        assert_eq!(
            plan(failed, Some(0x30d40), &mainnet, &any_fee).gas_limit,
            200_000
        );
        let hyper_fee = fees(gwei_milli(200));
        let hyper_fallback = plan(failed, None, &hyper, &hyper_fee);
        assert_eq!(hyper_fallback.gas_limit, 3_000_000);
        assert!(hyper_fallback.warnings.iter().all(|w| w.rule != E38));
        let equal = plan(estimated(2_500_000), None, &hyper, &hyper_fee);
        assert_eq!(equal.gas_limit, 3_000_000);
        assert!(equal.warnings.is_empty());
        let over_small = plan(estimated(2_600_000), None, &hyper, &hyper_fee);
        assert_eq!(over_small.gas_limit, 3_120_000);
        let e38 = over_small.warnings.first().unwrap();
        assert_eq!(e38.rule, E38);
        assert!(e38.text.contains("3,000,000"));
        let revert = plan(
            GasEstimate::Failed {
                revert_data: Some(&[]),
            },
            None,
            &mainnet,
            &any_fee,
        );
        assert!(
            revert
                .warnings
                .first()
                .unwrap()
                .text
                .contains("이유 없이 되돌려짐")
        );
    }

    #[test]
    fn replacement_vector() {
        let fresh = Fees {
            max_priority_fee_per_gas: gwei_milli(1_000),
            max_fee_per_gas: gwei_milli(25_000),
            base_fee_next: gwei_milli(12_000),
        };
        let (tip, max_fee) =
            replacement_fees(&gwei_milli(1_200), &gwei_milli(21_200), &fresh).unwrap();
        assert_eq!(tip, U256::from_u64(1_320_000_000));
        assert_eq!(max_fee, U256::from_u64(25_320_000_000));
    }

    #[test]
    fn speed_up_and_cancel_builders() {
        use crate::evm::address::Address;
        use crate::evm::tx::{AccessListItem, Eip1559Tx};
        let fresh = Fees {
            max_priority_fee_per_gas: gwei_milli(1_000),
            max_fee_per_gas: gwei_milli(25_000),
            base_fee_next: gwei_milli(12_000),
        };
        let latest = Eip1559Tx {
            chain_id: 11_155_111,
            nonce: 9,
            max_priority_fee_per_gas: gwei_milli(1_200),
            max_fee_per_gas: gwei_milli(21_200),
            gas_limit: 65_000,
            to: Address::from_bytes([0x11; 20]),
            value: U256::from_u64(5),
            data: vec![0xa9, 0x05, 0x9c, 0xbb],
            access_list: vec![AccessListItem {
                address: Address::from_bytes([0x22; 20]),
                storage_keys: vec![[1; 32]],
            }],
        };
        let speed = super::speed_up_tx(&latest, &fresh).unwrap();
        assert_eq!(
            speed.max_priority_fee_per_gas,
            U256::from_u64(1_320_000_000)
        );
        assert_eq!(speed.max_fee_per_gas, U256::from_u64(25_320_000_000));
        assert_eq!(
            (
                speed.chain_id,
                speed.nonce,
                speed.gas_limit,
                speed.to,
                speed.value
            ),
            (
                latest.chain_id,
                latest.nonce,
                latest.gas_limit,
                latest.to,
                latest.value
            )
        );
        assert_eq!(speed.data, latest.data);
        assert_eq!(speed.access_list, latest.access_list);
        let account = Address::from_bytes([0x33; 20]);
        let cancel = super::cancel_tx(&latest, &account, 25_200, &fresh).unwrap();
        assert_eq!(cancel.to, account);
        assert_eq!(cancel.value, U256::ZERO);
        assert!(cancel.data.is_empty() && cancel.access_list.is_empty());
        assert_eq!((cancel.nonce, cancel.gas_limit), (9, 25_200));
        assert_eq!(cancel.max_fee_per_gas, U256::from_u64(25_320_000_000));
        let fees = super::fees_of(&cancel, fresh.base_fee_next);
        assert_eq!(fees.max_priority_fee_per_gas, U256::from_u64(1_320_000_000));
    }

    #[test]
    fn helpers() {
        assert_eq!(divide(U256::from_u64(10), U256::from_u64(3)), Some(3));
        assert_eq!(divide(U256::MAX, U256::ONE), Some(u64::MAX));
        assert_eq!(divide(U256::ONE, U256::ZERO), None);
        assert_eq!(
            expected_fee(
                21_000,
                &U256::from_u64(2_000_000_000),
                &U256::from_u64(1_000_000_000),
                &U256::from_u64(100_000_000)
            ),
            Some(U256::from_u64(23_100_000_000_000))
        );
    }
}
