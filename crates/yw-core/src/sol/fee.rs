//! Fees (spec/07 §10): the maximum fee of a template, the CU price choice and the
//! `getFeeForMessage` cross-check; the exact fee range of a dApp transaction (§20.4).

use core::fmt;

use super::address::{
    ADDRESS_LOOKUP_TABLE_PROGRAM, BPF_LOADER, BPF_LOADER_DEPRECATED, BPF_LOADER_UPGRADEABLE,
    COMPUTE_BUDGET_PROGRAM, CONFIG_PROGRAM, ED25519_PRECOMPILE, SECP256K1_PRECOMPILE,
    SECP256R1_PRECOMPILE, STAKE_PROGRAM, SYSTEM_PROGRAM, SolAddress, VOTE_PROGRAM,
};

/// Base fee per signature (protocol value, cross-checked with `getFeeForMessage`).
pub const SOL_BASE_FEE_LAMPORTS_PER_SIG: u64 = 5_000;
/// `T_SOL` compute-unit limit: measured maximum `unitsConsumed` + 150 (spec/07 §10). Measured on
/// devnet 2026-10-27 with `simulateTransaction` ×10 of the real template (max 450 CU;
/// `docs/acceptance/m7-live-20261027.md`), so 450 + 150 = 600.
pub const SOL_TRANSFER_CU_LIMIT: u32 = 600;
/// `T_SPL` compute-unit limit (v1.1, spec/07 §10). Measured 2026-10-28 with
/// `simulateTransaction` (`sigVerify:false`, `replaceRecentBlockhash:true`) ×10 per case on
/// devnet and mainnet (`docs/acceptance/m7-spl-20261028.md`): existing destination ATA 4,842 CU;
/// new ATA 13,923–28,923 CU, exactly `c255 + 1,500 × (255 − bump)` of the destination ATA
/// (`c255` = 13,923–13,932: each failed bump of the ATA program's `find_program_address` is one
/// 1,500-CU `create_program_address`). A sample maximum × 1.25 therefore depends on the sampled
/// bumps; 60,000 covers `c255 + 1,500 × 30` (every bump ≥ 225, all but ~2^-30 of recipients)
/// and `(c255 + 1,500 × 20) × 1.25` = 55,000.
pub const SPL_TRANSFER_CU_LIMIT: u32 = 60_000;

/// The fixed compute-unit limit of an asset's template (intent creation enforces it; the parser
/// accepts any `1..=1_400_000` so vectors can use other limits).
#[must_use]
pub const fn template_cu_limit(asset: super::template::SolAsset) -> u32 {
    match asset {
        super::template::SolAsset::Sol => SOL_TRANSFER_CU_LIMIT,
        super::template::SolAsset::Spl(_) => SPL_TRANSFER_CU_LIMIT,
    }
}
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

impl FeeError {
    /// The fixed text in `lang` (`Display` is the Korean one).
    #[must_use]
    pub const fn text_in(self, lang: crate::lang::Lang) -> &'static str {
        use super::text as t;
        match self {
            Self::Overflow => t::FEE_OVERFLOW,
            Self::FeeQueryFailed => t::FEE_QUERY_FAILED,
            Self::FeeFormulaChanged => t::FEE_FORMULA_CHANGED,
            Self::AboveCap => t::FEE_ABOVE_CAP,
        }
        .get(lang)
    }
}

impl fmt::Display for FeeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.text_in(crate::lang::Lang::Ko))
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

/// Default compute units of an instruction whose program is not a builtin (or a builtin already
/// migrated to Core BPF) when a dApp transaction sets no limit (Agave
/// `DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT`).
pub const DEFAULT_IX_COMPUTE_UNITS: u32 = 200_000;
/// Default compute units of a builtin instruction (`ComputeBudget` itself included) when a dApp
/// transaction sets no limit (Agave `MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT`, SIMD-0170
/// `reserve_minimal_cus_for_builtin_instructions`, active on mainnet and devnet).
pub const BUILTIN_IX_COMPUTE_UNITS: u32 = 3_000;

/// Loader v4 `LoaderV411111111111111111111111111111111111` (a builtin whose cost-table entry
/// varies by release, so it is bracketed).
const LOADER_V4: SolAddress = SolAddress::from_bytes([
    0x05, 0x12, 0xb4, 0x11, 0x51, 0x51, 0xe3, 0x7a, 0xad, 0x0a, 0x8b, 0xc5, 0xd3, 0x88, 0x2e, 0x7b,
    0x7f, 0xda, 0x4c, 0xf3, 0xd2, 0xc0, 0x28, 0xc8, 0xcf, 0x83, 0x36, 0x18, 0x00, 0x00, 0x00, 0x00,
]);
/// ZK `ElGamal` proof program `ZkE1Gama1Proof11111111111111111111111111111` (bracketed).
const ZK_ELGAMAL_PROOF: SolAddress = SolAddress::from_bytes([
    0x08, 0x63, 0x75, 0xac, 0xe2, 0xae, 0xea, 0x28, 0x1a, 0x6b, 0x37, 0x4d, 0x68, 0x1b, 0xa7, 0x6a,
    0x53, 0xcc, 0xf6, 0x38, 0xc0, 0x74, 0x55, 0x93, 0x6c, 0x05, 0xd0, 0x65, 0x40, 0x00, 0x00, 0x00,
]);
/// ZK token proof program `ZkTokenProof1111111111111111111111111111111` (bracketed).
const ZK_TOKEN_PROOF: SolAddress = SolAddress::from_bytes([
    0x08, 0x63, 0xba, 0x8d, 0xd9, 0xc4, 0xc2, 0xfb, 0x17, 0x4a, 0x05, 0xcb, 0xa2, 0x7e, 0x2a, 0x2c,
    0xd6, 0x23, 0x57, 0x3d, 0x79, 0xe9, 0x0b, 0x35, 0xb5, 0x79, 0xfc, 0x0d, 0x00, 0x00, 0x00, 0x00,
]);
/// Builtins that are not migrating: 3,000 CU each without a limit.
const BUILTIN_PROGRAMS: [SolAddress; 8] = [
    SYSTEM_PROGRAM,
    VOTE_PROGRAM,
    COMPUTE_BUDGET_PROGRAM,
    BPF_LOADER_DEPRECATED,
    BPF_LOADER,
    BPF_LOADER_UPGRADEABLE,
    ED25519_PRECOMPILE,
    SECP256K1_PRECOMPILE,
];
/// Programs that are 3,000 or 200,000 CU depending on the cluster's features and release.
const BRACKETED_PROGRAMS: [SolAddress; 7] = [
    STAKE_PROGRAM,
    CONFIG_PROGRAM,
    ADDRESS_LOOKUP_TABLE_PROGRAM,
    LOADER_V4,
    SECP256R1_PRECOMPILE,
    ZK_ELGAMAL_PROOF,
    ZK_TOKEN_PROOF,
];

/// The default compute units `(low, high)` of one instruction of `program` when the transaction
/// sets no limit (Agave `ComputeBudgetInstructionDetails::calculate_default_compute_unit_limit`
/// with SIMD-0170; program kinds from `solana-builtins-default-costs`):
/// - builtins that are not migrating (System, Vote, `ComputeBudget`, the three BPF loaders, the
///   Ed25519 and Secp256k1 precompiles) are 3,000 in both;
/// - builtins migrating to Core BPF (Stake, Config, ALT: 3,000 before their feature, 200,000
///   after it and once dropped from the table) and programs whose builtin status varies by
///   release (Loader v4, Secp256r1, the ZK proof programs) are 3,000 low and 200,000 high;
/// - every other program is 200,000 in both.
fn default_units(program: &SolAddress) -> (u32, u32) {
    if BUILTIN_PROGRAMS.contains(program) {
        (BUILTIN_IX_COMPUTE_UNITS, BUILTIN_IX_COMPUTE_UNITS)
    } else if BRACKETED_PROGRAMS.contains(program) {
        (BUILTIN_IX_COMPUTE_UNITS, DEFAULT_IX_COMPUTE_UNITS)
    } else {
        (DEFAULT_IX_COMPUTE_UNITS, DEFAULT_IX_COMPUTE_UNITS)
    }
}

/// The exact range of a dApp transaction's fee, computed from its message alone (spec/07 §20.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DappFeeBounds {
    /// The lowest fee the runtime can charge.
    pub low: u128,
    /// The highest fee the runtime can charge (`low` when the transaction sets a limit or no
    /// price).
    pub high: u128,
    /// The runtime rejects the transaction for its `ComputeBudget` instructions
    /// ([`runtime_compute_budget`]): it is never processed and pays nothing, and
    /// `getFeeForMessage` prices it without a priority fee, so `low == high` is the signature
    /// fee (X18).
    pub rejected: bool,
}

impl DappFeeBounds {
    /// Whether `fee` lies in `[low, high]`.
    #[must_use]
    pub const fn contains(&self, fee: u128) -> bool {
        self.low <= fee && fee <= self.high
    }
}

/// Smallest heap frame the runtime accepts (Agave `MIN_HEAP_FRAME_BYTES`).
const MIN_HEAP_FRAME_BYTES: u32 = 32 * 1_024;
/// Largest heap frame the runtime accepts (Agave `MAX_HEAP_FRAME_BYTES`).
const MAX_HEAP_FRAME_BYTES: u32 = 256 * 1_024;

/// A little-endian `u32` at the start of `bytes` (later bytes ignored).
fn le_u32(bytes: &[u8]) -> Option<u32> {
    bytes.get(..4)?.try_into().ok().map(u32::from_le_bytes)
}

/// A little-endian `u64` at the start of `bytes` (later bytes ignored).
fn le_u64(bytes: &[u8]) -> Option<u64> {
    bytes.get(..8)?.try_into().ok().map(u64::from_le_bytes)
}

/// The compute-unit limit and price the runtime takes from a message's `ComputeBudget`
/// instructions, or `None` when it rejects the transaction for them (Agave
/// `ComputeBudgetInstructionDetails::try_from` and `sanitize_and_convert_to_compute_budget_limits`;
/// `getFeeForMessage` then uses `unwrap_or_default()`: no priority fee):
/// - the data is the Borsh enum read with `try_from_slice_unchecked`: the tag byte, then the
///   little-endian field, and bytes after the field are ignored. The strict display decoder
///   shows such an instruction as `Unknown` (X02), but the runtime applies it (the
///   `ComputeBudget` program itself does nothing), so the fee must use this parse;
/// - a short field, tag 0 (`Unused`) or a tag above 4 is `InvalidInstructionData`, and a second
///   instruction of the same kind is `DuplicateInstruction`;
/// - a heap request outside 32..=256 KiB or not a multiple of 1 KiB, and a loaded-accounts
///   data-size limit of 0, are rejected as well.
fn runtime_compute_budget(
    message: &super::dapp::SolTxMessage,
) -> Option<(Option<u32>, Option<u64>)> {
    let (mut heap, mut limit, mut price, mut size) = (None, None, None, None);
    for index in 0..message.instruction_count() {
        let Some((program, _, data)) = message.instruction(index) else {
            continue;
        };
        if *program != COMPUTE_BUDGET_PROGRAM {
            continue;
        }
        let (tag, field) = data.split_first()?;
        let duplicate = match tag {
            1 => heap.replace(le_u32(field)?).is_some(),
            2 => limit.replace(le_u32(field)?).is_some(),
            3 => price.replace(le_u64(field)?).is_some(),
            4 => size.replace(le_u32(field)?).is_some(),
            _ => return None,
        };
        if duplicate {
            return None;
        }
    }
    let bad_heap = heap.is_some_and(|bytes: u32| {
        !(MIN_HEAP_FRAME_BYTES..=MAX_HEAP_FRAME_BYTES).contains(&bytes)
            || !bytes.is_multiple_of(1_024)
    });
    (!bad_heap && size != Some(0)).then_some((limit, price))
}

/// The fee of a dApp transaction from its message (spec/07 §20.4, Agave fee rules):
/// `5_000 × (required signatures + precompile signatures) + ceil(price × limit / 1_000_000)`,
/// where the price is the `SetComputeUnitPrice` (0 without one) and the limit the
/// `SetComputeUnitLimit` capped at 1,400,000 — exact, `low == high` — both read as the runtime
/// reads them ([`runtime_compute_budget`]). Without a limit the runtime uses
/// `min(Σ default units, 1,400,000)` with the per-instruction defaults of [`default_units`];
/// `low` and `high` bracket it where a program's builtin status depends on the cluster. When the
/// runtime rejects the `ComputeBudget` instructions the range is the signature fee alone
/// (`rejected`). `u128`: no overflow. [`max_fee`] stays the template formula.
///
/// 2026-11-13: this replaces `dapp_fee_estimate` (200,000 per instruction outside
/// `ComputeBudget`), which was shown only when `getFeeForMessage` gave no value. It was far too
/// high for builtins and 3,000 CU per `ComputeBudget` instruction too low, so it could not check
/// the RPC value, and an RPC that under-reported the fee hid X14. Later the same day (review):
/// the limit and price were read through the strict display decoder, so one byte after a
/// `SetComputeUnitPrice` made the wallet price it at 0 while the runtime charged it, and the
/// first of two duplicate instructions was used although the runtime rejects the transaction.
#[must_use]
pub fn dapp_fee_bounds(message: &super::dapp::SolTxMessage) -> DappFeeBounds {
    let signatures = u128::from(message.header.required)
        .saturating_add(u128::from(message.precompile_signatures()));
    let base = u128::from(SOL_BASE_FEE_LAMPORTS_PER_SIG).saturating_mul(signatures);
    let Some((limit, price)) = runtime_compute_budget(message) else {
        return DappFeeBounds {
            low: base,
            high: base,
            rejected: true,
        };
    };
    let max = super::template::SOL_MAX_COMPUTE_UNITS;
    let (low_limit, high_limit) = if let Some(units) = limit {
        (units.min(max), units.min(max))
    } else {
        let (mut low_units, mut high_units) = (0_u32, 0_u32);
        for index in 0..message.instruction_count() {
            // The parser makes every program a static key; an unresolved one is bracketed.
            let (low, high) = message.instruction(index).map_or(
                (BUILTIN_IX_COMPUTE_UNITS, DEFAULT_IX_COMPUTE_UNITS),
                |(program, _, _)| default_units(program),
            );
            low_units = low_units.saturating_add(low);
            high_units = high_units.saturating_add(high);
        }
        (low_units.min(max), high_units.min(max))
    };
    let fee = |limit: u32| {
        base.saturating_add(
            u128::from(price.unwrap_or(0))
                .saturating_mul(u128::from(limit))
                .div_ceil(1_000_000),
        )
    };
    DappFeeBounds {
        low: fee(low_limit),
        high: fee(high_limit),
        rejected: false,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FeeCheck, FeeError, check_rpc_fee, choose_cu_price, max_fee, p75, priority_fee,
        template_cu_limit,
    };

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
    fn template_limits() {
        use crate::sol::template::{SPL_ALLOWLIST, SolAsset};
        assert_eq!(template_cu_limit(SolAsset::Sol), 600);
        assert_eq!(template_cu_limit(SolAsset::Spl(&SPL_ALLOWLIST[0])), 60_000);
        // getFeeForMessage of T_SPL at 1,000 micro-lamports/CU (live 2026-10-28): 5,060.
        assert_eq!(max_fee(60_000, 1_000), Ok(5_060));
        // The default cap leaves room for the default price cap at the SPL limit.
        assert_eq!(
            choose_cu_price(u64::MAX, 1_000_000, 100_000, 60_000),
            1_000_000
        );
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
    fn default_units_by_program_kind() {
        use super::{
            BRACKETED_PROGRAMS, BUILTIN_PROGRAMS, LOADER_V4, SolAddress, ZK_ELGAMAL_PROOF,
            ZK_TOKEN_PROOF, default_units,
        };
        for (constant, text) in [
            (LOADER_V4, "LoaderV411111111111111111111111111111111111"),
            (
                ZK_ELGAMAL_PROOF,
                "ZkE1Gama1Proof11111111111111111111111111111",
            ),
            (
                ZK_TOKEN_PROOF,
                "ZkTokenProof1111111111111111111111111111111",
            ),
        ] {
            assert_eq!(SolAddress::parse(text).unwrap(), constant, "{text}");
        }
        for program in BUILTIN_PROGRAMS {
            assert_eq!(default_units(&program), (3_000, 3_000));
            assert!(!BRACKETED_PROGRAMS.contains(&program));
        }
        for program in BRACKETED_PROGRAMS {
            assert_eq!(default_units(&program), (3_000, 200_000));
        }
        for program in [
            crate::sol::address::TOKEN_PROGRAM,
            crate::sol::address::MEMO_PROGRAM_V2,
            SolAddress::from_bytes([9; 32]),
        ] {
            assert_eq!(default_units(&program), (200_000, 200_000));
        }
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
