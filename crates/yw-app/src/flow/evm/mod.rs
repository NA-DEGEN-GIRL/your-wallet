//! `flow::evm` (spec/03 §0, M4): the EVM processing order (§3.7), journal-driven broadcast and
//! receipt tracking (§4.4–§4.5, §5.4), re-simulation (§6.6) and user-chain checks (§1.6).
//!
//! Every function here runs on the `yw-rpc` worker (spec/04 §1.2) and never touches the DEK:
//! signing and journal commits happen on the key worker. Patterns: chain verification with
//! bounded retries from `archive/spec-v2.4:demo/sepolia-wallet/src/rpc.rs:491-524`; the frozen
//! fee/gas plan of `archive/spec-v2.4:demo/sepolia-wallet/src/backend.rs:3239-3296,3549-3770`
//! (the transaction shown is exactly the one signed; no automatic re-signing).

pub mod form;
pub mod prepare;
pub mod track;
pub mod user_chain;

use std::collections::HashMap;
use std::sync::Arc;

use yw_core::evm::amount::{U256, parse_units};
use yw_core::evm::chain::{
    ChainInfo, GenesisRule, HYPEREVM_MAINNET, UserChainInput, builtin_chain, user_chain_info,
};
use yw_core::evm::fee::FeeCaps;
use yw_win::http::HttpsUrl;

use crate::errors::ErrorCode;
use crate::rpc::evm::{chain_id_text, genesis_hash, parse_chain_id};
use crate::rpc::{RpcClient, RpcFailure, Transport, canonical_quantity, classify};
use crate::settings::{FeeCapsText, Settings, chain_decimals};

/// The shared transport handed to pipelines (the real `WinHTTP` client or a test fake).
pub type SharedTransport = Arc<dyn Transport>;

/// Chain-check retries after a transport failure (spec/03 §1.4: 3 retries 150 ms apart).
pub const CHAIN_CHECK_RETRIES: u32 = 3;
/// Delay between chain-check attempts.
pub const CHAIN_CHECK_RETRY_MS: u64 = 150;
/// Preparation budget for steps 3–9 (spec/03 §1.4).
pub const PREPARE_BUDGET_MS: u64 = 30_000;
/// Simulation wait bound (spec/04 §3.1 `SIM_WAIT_MAX_MS`).
pub const SIM_WAIT_MS: u64 = 10_000;
/// Token metadata and address classification lookups per request (spec/03 §2.5).
pub const MAX_FACT_LOOKUPS: usize = 16;

/// Time source of the pipelines (monotonic ms for budgets, wall clock for records).
pub trait Clock: Send + Sync {
    /// Monotonic milliseconds (yw-win `time::monotonic_ms`).
    fn now_ms(&self) -> u64;
    /// Wall-clock Unix milliseconds.
    fn now_unix_ms(&self) -> u64;
    /// Sleeps (retry delays).
    fn sleep_ms(&self, ms: u64);
}

/// The real clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        yw_win::time::monotonic_ms()
    }

    fn now_unix_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            })
    }

    fn sleep_ms(&self, ms: u64) {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
}

/// Pipeline time limits (production values from [`Limits::PRODUCTION`]; tests shrink them).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(clippy::struct_field_names, reason = "every limit is in milliseconds")]
pub struct Limits {
    /// Simulation wait (10 s).
    pub sim_wait_ms: u64,
    /// Steps 3–9 budget (30 s).
    pub budget_ms: u64,
    /// Chain-check retry delay (150 ms).
    pub retry_delay_ms: u64,
    /// Broadcast retry delays after transport errors (2 s, 5 s).
    pub broadcast_retry_ms: [u64; 2],
}

impl Limits {
    /// spec/03 §1.4 and §4.4 values.
    pub const PRODUCTION: Self = Self {
        sim_wait_ms: SIM_WAIT_MS,
        budget_ms: PREPARE_BUDGET_MS,
        retry_delay_ms: CHAIN_CHECK_RETRY_MS,
        broadcast_retry_ms: [2_000, 5_000],
    };
}

/// One chain as a job sees it: definition, fee caps and the endpoint URL (secret, D13).
#[derive(Clone)]
pub struct ChainJob {
    /// Chain definition (with the pinned genesis if any).
    pub info: ChainInfo,
    /// Fee caps from settings.
    pub caps: FeeCaps,
    /// `rpc:eip155:<chainId>` URL.
    pub url: HttpsUrl,
}

impl core::fmt::Debug for ChainJob {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "ChainJob(eip155:{})", self.info.chain_id)
    }
}

/// Why a chain is blocked (spec/03 §1.4 `RpcMismatch`, spec/04 §1.9 codes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MismatchKind {
    /// `eth_chainId` differs (`rpc` = the parsed value, if any).
    ChainId {
        /// RPC chain id.
        rpc: Option<u64>,
    },
    /// Genesis differs from a constant (1, 11155111): E-RPC-006.
    ConstantGenesis,
    /// Genesis differs from a first-use pin (999, user chains): E-CHN-008.
    PinnedGenesis {
        /// The block-0 hash the RPC reported (for `다시 고정`).
        observed: [u8; 32],
    },
}

impl MismatchKind {
    /// The error code shown (spec/04 §1.9).
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        match self {
            Self::ChainId { .. } | Self::ConstantGenesis => ErrorCode::Rpc006,
            Self::PinnedGenesis { .. } => ErrorCode::Chn008,
        }
    }
}

/// Chain-check result (spec/03 §1.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainCheck {
    /// Chain id and genesis match; `pinned_now` = the genesis was pinned by this check (999 first
    /// use).
    Verified {
        /// Verified genesis.
        genesis: [u8; 32],
        /// First-use pin happened now.
        pinned_now: bool,
    },
    /// Blocked until restart or a URL change.
    Mismatch(MismatchKind),
    /// Transport failure after retries (retried on next use).
    Unverified(RpcFailure),
}

impl ChainCheck {
    /// The code of a failed check (`None` when verified).
    #[must_use]
    pub const fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::Verified { .. } => None,
            Self::Mismatch(kind) => Some(kind.code()),
            Self::Unverified(failure) => Some(classify(*failure)),
        }
    }
}

fn check_once(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    chain: &ChainInfo,
) -> Result<ChainCheck, RpcFailure> {
    let text = chain_id_text(client, url)?;
    if text.to_ascii_lowercase() != canonical_quantity(chain.chain_id) {
        return Ok(ChainCheck::Mismatch(MismatchKind::ChainId {
            rpc: parse_chain_id(&text),
        }));
    }
    let observed = genesis_hash(client, url)?;
    Ok(match chain.genesis {
        GenesisRule::Fixed(expected) if expected == observed => ChainCheck::Verified {
            genesis: observed,
            pinned_now: false,
        },
        GenesisRule::Fixed(_) => ChainCheck::Mismatch(MismatchKind::ConstantGenesis),
        GenesisRule::PinOnFirstUse(Some(pinned)) if pinned == observed => ChainCheck::Verified {
            genesis: observed,
            pinned_now: false,
        },
        GenesisRule::PinOnFirstUse(Some(_)) => {
            ChainCheck::Mismatch(MismatchKind::PinnedGenesis { observed })
        }
        GenesisRule::PinOnFirstUse(None) => ChainCheck::Verified {
            genesis: observed,
            pinned_now: true,
        },
    })
}

/// The chain check of spec/03 §1.4: `eth_chainId` then the block-0 hash against the genesis
/// rule; transport failures are retried 3 times `retry_delay_ms` apart.
#[must_use]
pub fn check_chain(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    chain: &ChainInfo,
    clock: &dyn Clock,
    retry_delay_ms: u64,
) -> ChainCheck {
    let mut last = RpcFailure::Malformed;
    for attempt in 0..=CHAIN_CHECK_RETRIES {
        if attempt > 0 {
            clock.sleep_ms(retry_delay_ms);
        }
        match check_once(client, url, chain) {
            Ok(check) => return check,
            Err(failure) => last = failure,
        }
    }
    ChainCheck::Unverified(last)
}

/// Verification state per chain for this app run (spec/03 §1.4: checked once per connection,
/// again after a URL change; mismatches stick until restart or URL change).
#[derive(Debug, Default)]
pub struct ChainCache {
    states: HashMap<u64, ChainCheck>,
}

impl ChainCache {
    /// Forgets a chain (URL or definition changed).
    pub fn reset(&mut self, chain_id: u64) {
        self.states.remove(&chain_id);
    }

    /// The cached state.
    #[must_use]
    pub fn get(&self, chain_id: u64) -> Option<ChainCheck> {
        self.states.get(&chain_id).copied()
    }

    /// Returns the cached verified/mismatch state or checks now (unverified results are not
    /// cached). A first-use pin is stored as verified.
    pub fn ensure(
        &mut self,
        client: &RpcClient<'_>,
        url: &HttpsUrl,
        chain: &ChainInfo,
        clock: &dyn Clock,
        retry_delay_ms: u64,
    ) -> ChainCheck {
        if let Some(state) = self.states.get(&chain.chain_id) {
            return match *state {
                ChainCheck::Verified { genesis, .. } => ChainCheck::Verified {
                    genesis,
                    pinned_now: false,
                },
                other => other,
            };
        }
        let check = check_chain(client, url, chain, clock, retry_delay_ms);
        if !matches!(check, ChainCheck::Unverified(_)) {
            self.states.insert(chain.chain_id, check);
        }
        check
    }
}

/// `chain` with a first-use genesis filled in (the approval `ChainRef` binds it, spec/03 §11.1).
#[must_use]
pub fn with_genesis(chain: &ChainInfo, genesis: [u8; 32]) -> ChainInfo {
    let mut out = chain.clone();
    if matches!(out.genesis, GenesisRule::PinOnFirstUse(None)) {
        out.genesis = GenesisRule::PinOnFirstUse(Some(genesis));
    }
    out
}

/// The runtime [`ChainInfo`] of a registered chain (spec/03 §1.1, §1.6): built-ins with the
/// `HyperEVM` pin from `evmGenesisPins`, user chains from `evmChains`.
#[must_use]
pub fn chain_info(settings: &Settings, chain_id: u64) -> Option<ChainInfo> {
    if let Some(mut chain) = builtin_chain(chain_id) {
        if chain_id == HYPEREVM_MAINNET
            && let Some((_, pin)) = settings
                .evm_genesis_pins
                .iter()
                .find(|(id, _)| *id == chain_id)
        {
            chain.genesis = GenesisRule::PinOnFirstUse(Some(*pin));
        }
        return Some(chain);
    }
    let def = settings
        .evm_chains
        .iter()
        .find(|chain| chain.chain_id == chain_id)?;
    Some(user_chain_info(
        &UserChainInput {
            chain_id: def.chain_id,
            name: def.name.clone(),
            native_symbol: def.symbol.clone(),
            native_decimals: def.decimals,
            explorer: def.explorer.clone(),
            simulation: def.simulation,
        },
        def.genesis_hash,
    ))
}

/// Parses a `feeCaps` text entry into wei values.
#[must_use]
pub fn parse_caps(text: &FeeCapsText, decimals: u8) -> Option<FeeCaps> {
    Some(FeeCaps {
        max_fee_per_gas: parse_units(&text.max_fee_per_gas_gwei, 9).ok()?,
        max_priority_fee_per_gas: parse_units(&text.max_priority_fee_per_gas_gwei, 9).ok()?,
        max_total_fee: parse_units(&text.max_total_fee, decimals).ok()?,
    })
}

/// The fee caps of a chain: `feeCaps["eip155:<id>"]` or the chain default (spec/04 §6.1).
#[must_use]
pub fn fee_caps(settings: &Settings, chain: &ChainInfo) -> FeeCaps {
    settings
        .fee_caps
        .iter()
        .find(|(id, _)| *id == chain.chain_id)
        .and_then(|(_, text)| parse_caps(text, chain.native_decimals))
        .unwrap_or(chain.default_caps)
}

/// The default caps as settings text (`기본값으로`).
#[must_use]
pub fn default_caps_text(chain: &ChainInfo) -> FeeCapsText {
    use yw_core::evm::amount::format_units;
    let plain = |value: &U256, decimals: u8| format_units(value, decimals).replace(',', "");
    FeeCapsText {
        max_fee_per_gas_gwei: plain(&chain.default_caps.max_fee_per_gas, 9),
        max_priority_fee_per_gas_gwei: plain(&chain.default_caps.max_priority_fee_per_gas, 9),
        max_total_fee: plain(&chain.default_caps.max_total_fee, chain.native_decimals),
    }
}

/// The decimals of a registered chain's native asset.
#[must_use]
pub fn native_decimals(settings: &Settings, chain_id: u64) -> u8 {
    chain_decimals(&settings.evm_chains, chain_id).unwrap_or(18)
}
