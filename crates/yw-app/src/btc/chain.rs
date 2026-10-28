//! `btc::chain` (spec/08 §2 "연결 검사" `check_chain()`): the network pin by genesis, independent
//! of provider, URL and indexer format.
//!
//! 1. Core `getblockhash [0]` equals the network constant.
//! 2. Core `getblockchaininfo`: `chain`, `initialblockdownload == false`, `headers - blocks <= 2`,
//!    `now - 86400 <= mediantime <= now + 7200` (local UTC seconds), `blocks < 500,000,000` (a
//!    lock-time timestamp is never a height), `blocks` is the tip, and
//!    `blocks >= max_tip_seen - 6` (then `max_tip_seen = max(max_tip_seen, blocks)`, raised at
//!    most to the indexer tip + 3 when step 4 gave one: one endpoint alone cannot ratchet it to
//!    a wrong height that would block every later check).
//! 3. Indexer `GenesisHash` equals the constant (`esplora` mandatory; `bb-*` too). No address is
//!    sent to the indexer before this step passed in the session.
//! 4. `esplora` only, never blocking: indexer `TipHeight` more than 3 blocks from `blocks` →
//!    W-BTC-IDX-LAG; a failure is only logged.
//!
//! A mismatch in steps 1–3 blocks every BTC call of the session ([`ChainSession::blocked`]):
//! steps 1–2 "RPC가 다른 네트워크를 가리킵니다" (E-RPC-006), step 3 E-BTC-003. A failed call is
//! not a mismatch. Steps 1–4 run on the first call, after an endpoint / indexer /
//! `esploraBaseUrl` change ([`ChainSession::reset`]) and every `BTC_CHAIN_RECHECK_SECS`; steps
//! 1–2 also run right before `testmempoolaccept` / `sendrawtransaction` ([`check_core`]).

use yw_core::btc::{
    BTC_CHAIN_RECHECK_SECS, BTC_INDEXER_TIP_LAG_WARN, BTC_LOCKTIME_THRESHOLD, BtcNetwork,
};

use super::BtcError;
use super::client::{BtcClient, Tag};
use super::indexer::{self, BtcIndexerReq, BtcIndexerResp, IndexerError};
use super::rpc;
use crate::errors::ErrorCode;
use crate::logging::Field;
use crate::settings::{BtcIndexer, LogLevel};

/// `mediantime` may lag local time by this much.
pub const MEDIANTIME_PAST_SECS: u64 = 86_400;
/// `mediantime` may lead local time by this much.
pub const MEDIANTIME_FUTURE_SECS: u64 = 7_200;
/// Largest `headers - blocks`.
pub const HEADERS_AHEAD_MAX: u32 = 2;
/// Largest tip regression below `max_tip_seen`.
pub const TIP_REGRESSION_MAX: u32 = 6;
const RECHECK_MS: u64 = BTC_CHAIN_RECHECK_SECS * 1_000;

/// Which step-1/2 condition failed (log word; the display is E-RPC-006).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CoreCheckFailure {
    /// `getblockhash 0` differs (testnet3, signet, the other network…).
    Genesis,
    /// `getblockchaininfo.chain` differs.
    Chain,
    /// `initialblockdownload` is true.
    InitialBlockDownload,
    /// `headers - blocks > 2`.
    HeadersAhead,
    /// `mediantime` outside the window.
    MedianTime,
    /// `blocks < max_tip_seen - 6`.
    TipRegressed,
    /// `blocks >= 500,000,000`.
    TipImplausible,
}

impl CoreCheckFailure {
    /// Log word.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Genesis => "genesis",
            Self::Chain => "chain",
            Self::InitialBlockDownload => "ibd",
            Self::HeadersAhead => "headers",
            Self::MedianTime => "mediantime",
            Self::TipRegressed => "tip_regressed",
            Self::TipImplausible => "tip_implausible",
        }
    }
}

/// Why BTC is blocked for the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BtcBlock {
    /// Settings `bitcoin.network` differs from `BtcMeta.network` (spec/08 §2 `NetworkMismatch`).
    NetworkMismatch,
    /// `check_chain` step 1 or 2 (E-RPC-006).
    Core(CoreCheckFailure),
    /// `check_chain` step 3 (E-BTC-003).
    Indexer,
}

impl BtcBlock {
    /// The error code (`NetworkMismatch` has its own spec/08 §13 text).
    #[must_use]
    pub const fn code(self) -> Option<ErrorCode> {
        match self {
            Self::NetworkMismatch => None,
            Self::Core(_) => Some(ErrorCode::Rpc006),
            Self::Indexer => Some(ErrorCode::Btc003),
        }
    }

    /// The fixed text.
    #[must_use]
    pub fn text(self) -> String {
        match self.code() {
            Some(code) => code.text(),
            None => "BTC 네트워크 설정이 지갑 데이터와 다릅니다".to_owned(),
        }
    }
}

/// W-BTC-IDX-LAG (spec/04 §2.16).
#[must_use]
pub fn lag_warning_text(blocks: u32) -> String {
    format!(
        "인덱서와 노드의 블록 높이가 {blocks} 차이 납니다. 잔액·확인 수가 늦게 반영될 수 있습니다"
    )
}

/// The chain facts a job uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainStatus {
    /// Core `blocks` (server view, spec/08 §4.6).
    pub tip_height: u32,
    /// Updated `BtcMeta.max_tip_seen` for the caller to persist.
    pub max_tip_seen: u32,
    /// W-BTC-IDX-LAG difference (`esplora` step 4), if above 3.
    pub lag_warning: Option<u32>,
}

/// Inputs of a check: the persisted `max_tip_seen` and local UTC time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainInput {
    /// `BtcMeta.max_tip_seen`.
    pub max_tip_seen: u32,
    /// Local wall clock, Unix seconds.
    pub now_unix_secs: u64,
}

/// The connection-check state of one unlock session (kept by the worker).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainSession {
    settings_net: BtcNetwork,
    meta_net: BtcNetwork,
    blocked: Option<BtcBlock>,
    verified_at_ms: Option<u64>,
    indexer_verified: bool,
    tip_height: Option<u32>,
    max_tip_seen: u32,
    lag_warning: Option<u32>,
    indexer_tip: Option<u32>,
}

impl ChainSession {
    /// A session for settings `bitcoin.network` and `BtcMeta.network`; when they differ every
    /// BTC call is blocked (`NetworkMismatch`) without any request.
    #[must_use]
    pub const fn new(settings_net: BtcNetwork, meta_net: BtcNetwork) -> Self {
        Self {
            settings_net,
            meta_net,
            blocked: None,
            verified_at_ms: None,
            indexer_verified: false,
            tip_height: None,
            max_tip_seen: 0,
            lag_warning: None,
            indexer_tip: None,
        }
    }

    /// After a Core endpoint, `bitcoin.indexer` or `esploraBaseUrl` change: forget every check
    /// result (blocks included); the next job runs steps 1–4 again.
    pub fn reset(&mut self) {
        *self = Self::new(self.settings_net, self.meta_net);
    }

    /// The settings network.
    #[must_use]
    pub const fn network(&self) -> BtcNetwork {
        self.settings_net
    }

    /// Why BTC is blocked, if it is.
    #[must_use]
    pub const fn blocked(&self) -> Option<BtcBlock> {
        if !matches!(
            (self.settings_net, self.meta_net),
            (BtcNetwork::Mainnet, BtcNetwork::Mainnet)
                | (BtcNetwork::Testnet4, BtcNetwork::Testnet4)
        ) {
            return Some(BtcBlock::NetworkMismatch);
        }
        self.blocked
    }

    /// Step 3 passed since the last reset (addresses may be sent to the indexer).
    #[must_use]
    pub const fn indexer_verified(&self) -> bool {
        self.indexer_verified && self.blocked().is_none()
    }

    /// Steps 1–4 are due (first call, after a reset or a failed step 3, or 600 s later).
    #[must_use]
    pub fn full_check_due(&self, now_ms: u64) -> bool {
        !self.indexer_verified
            || self
                .verified_at_ms
                .is_none_or(|at| now_ms.saturating_sub(at) >= RECHECK_MS)
    }

    /// Last Core tip seen in this session.
    #[must_use]
    pub const fn tip_height(&self) -> Option<u32> {
        self.tip_height
    }

    /// Current W-BTC-IDX-LAG difference.
    #[must_use]
    pub const fn lag_warning(&self) -> Option<u32> {
        self.lag_warning
    }

    /// The `esplora` indexer tip of the last full check (step 4).
    #[must_use]
    pub const fn indexer_tip(&self) -> Option<u32> {
        self.indexer_tip
    }

    /// Raises the session's `max_tip_seen` with a Core tip that passed step 2, at most to the
    /// indexer tip + `BTC_INDEXER_TIP_LAG_WARN` when step 4 gave one.
    fn ratchet(&mut self, tip: u32) {
        let capped = self.indexer_tip.map_or(tip, |indexer| {
            tip.min(indexer.saturating_add(BTC_INDEXER_TIP_LAG_WARN))
        });
        self.max_tip_seen = self.max_tip_seen.max(capped);
    }

    fn block(&mut self, client: &BtcClient<'_>, block: BtcBlock) -> BtcError {
        self.blocked = Some(block);
        self.indexer_verified = false;
        let (event, reason) = match block {
            BtcBlock::Core(failure) => ("E-RPC-006", failure.word()),
            BtcBlock::Indexer => ("E-BTC-003", "indexer_genesis"),
            BtcBlock::NetworkMismatch => ("NetworkMismatch", "meta"),
        };
        client.log(
            LogLevel::Warn,
            event,
            Tag::core("check_chain", None),
            &[("reason", Field::Word(reason))],
        );
        BtcError::Blocked(block)
    }

    fn status(&self, input: ChainInput, tip_height: u32) -> ChainStatus {
        ChainStatus {
            tip_height,
            max_tip_seen: input.max_tip_seen.max(self.max_tip_seen),
            lag_warning: self.lag_warning,
        }
    }
}

fn gate(client: &BtcClient<'_>, session: &ChainSession) -> Result<(), BtcError> {
    if let Some(block) = session.blocked() {
        return Err(BtcError::Blocked(block));
    }
    if client.endpoint().net == session.settings_net {
        Ok(())
    } else {
        Err(BtcError::Blocked(BtcBlock::NetworkMismatch))
    }
}

/// Step 2 conditions on a `getblockchaininfo` result; returns the tip on success.
///
/// # Errors
///
/// The failed [`CoreCheckFailure`].
pub fn judge_blockchain_info(
    info: &rpc::BlockchainInfo,
    net: BtcNetwork,
    max_tip_seen: u32,
    now_unix_secs: u64,
) -> Result<u32, CoreCheckFailure> {
    if info.chain != Some(net) {
        return Err(CoreCheckFailure::Chain);
    }
    if info.initial_block_download {
        return Err(CoreCheckFailure::InitialBlockDownload);
    }
    if info.headers.saturating_sub(info.blocks) > HEADERS_AHEAD_MAX {
        return Err(CoreCheckFailure::HeadersAhead);
    }
    if info.median_time < now_unix_secs.saturating_sub(MEDIANTIME_PAST_SECS)
        || info.median_time > now_unix_secs.saturating_add(MEDIANTIME_FUTURE_SECS)
    {
        return Err(CoreCheckFailure::MedianTime);
    }
    if info.blocks >= BTC_LOCKTIME_THRESHOLD || info.headers >= BTC_LOCKTIME_THRESHOLD {
        return Err(CoreCheckFailure::TipImplausible);
    }
    if info.blocks < max_tip_seen.saturating_sub(TIP_REGRESSION_MAX) {
        return Err(CoreCheckFailure::TipRegressed);
    }
    Ok(info.blocks)
}

fn step2(
    client: &BtcClient<'_>,
    session: &mut ChainSession,
    input: ChainInput,
) -> Result<u32, BtcError> {
    let info = rpc::get_blockchain_info(client)?;
    let floor = input.max_tip_seen.max(session.max_tip_seen);
    match judge_blockchain_info(&info, session.settings_net, floor, input.now_unix_secs) {
        Ok(tip) => {
            session.tip_height = Some(tip);
            session.max_tip_seen = floor.max(session.max_tip_seen);
            Ok(tip)
        }
        Err(failure) => Err(session.block(client, BtcBlock::Core(failure))),
    }
}

/// Step 1 (`getblockhash 0`).
fn step1(client: &BtcClient<'_>, session: &mut ChainSession) -> Result<(), BtcError> {
    let genesis = rpc::get_block_hash_0(client)?;
    if genesis != session.settings_net.genesis() {
        return Err(session.block(client, BtcBlock::Core(CoreCheckFailure::Genesis)));
    }
    Ok(())
}

/// Steps 1–2 (Core), always both calls (also right before `testmempoolaccept` /
/// `sendrawtransaction`).
///
/// # Errors
///
/// [`BtcError::Blocked`] (mismatch, now blocking the session) or the failed call.
pub fn check_core(
    client: &BtcClient<'_>,
    session: &mut ChainSession,
    input: ChainInput,
) -> Result<ChainStatus, BtcError> {
    gate(client, session)?;
    step1(client, session)?;
    let tip = step2(client, session, input)?;
    session.ratchet(tip);
    Ok(session.status(input, tip))
}

/// Steps 1–4.
///
/// # Errors
///
/// [`BtcError::Blocked`] for a step 1–3 mismatch, the failed Core / indexer call otherwise
/// (a step-4 failure is only logged, except a rate-limit abort).
pub fn check_full(
    client: &BtcClient<'_>,
    session: &mut ChainSession,
    input: ChainInput,
) -> Result<ChainStatus, BtcError> {
    gate(client, session)?;
    step1(client, session)?;
    let tip = step2(client, session, input)?;
    match indexer::fetch(client, &BtcIndexerReq::GenesisHash) {
        Ok(BtcIndexerResp::GenesisHash(hash)) if hash == session.settings_net.genesis() => {}
        Ok(BtcIndexerResp::GenesisHash(_)) => {
            return Err(session.block(client, BtcBlock::Indexer));
        }
        Ok(_) => return Err(BtcError::Indexer(IndexerError::Malformed)),
        Err(error) => {
            session.indexer_verified = false;
            return Err(BtcError::Indexer(error));
        }
    }
    session.indexer_verified = true;
    session.verified_at_ms = Some(client.now_ms());
    session.lag_warning = None;
    if client.endpoint().indexer == BtcIndexer::Esplora {
        match indexer::fetch(client, &BtcIndexerReq::TipHeight) {
            Ok(BtcIndexerResp::TipHeight(height)) => {
                session.indexer_tip = Some(height);
                let lag = height.abs_diff(tip);
                if lag > BTC_INDEXER_TIP_LAG_WARN {
                    session.lag_warning = Some(lag);
                    client.log(
                        LogLevel::Info,
                        "W-BTC-IDX-LAG",
                        Tag::core("check_chain", None),
                        &[("lag", Field::Num(u64::from(lag)))],
                    );
                }
            }
            Err(IndexerError::RateLimited) => {
                return Err(BtcError::Indexer(IndexerError::RateLimited));
            }
            // Not blocking: the failure was logged by `fetch`.
            Ok(_) | Err(_) => {}
        }
    }
    session.ratchet(tip);
    Ok(session.status(input, tip))
}

/// Planning guard (review M2): the Core tip may not be more than `BTC_PLAN_TIP_AHEAD_MAX`
/// blocks above an `esplora` indexer tip (`lock_time = tip` would not be final elsewhere, and a
/// lying endpoint could ratchet `max_tip_seen`). A fresh `TipHeight`, else the last full
/// check's; nothing to compare with for `bb-*` or when both are unavailable.
///
/// # Errors
///
/// `(core tip, indexer tip)` when the Core tip is too far ahead; a rate-limit abort as
/// [`BtcError`].
pub fn tip_ahead_check(
    client: &BtcClient<'_>,
    session: &mut ChainSession,
    core_tip: u32,
) -> Result<Result<(), (u32, u32)>, BtcError> {
    if client.endpoint().indexer != BtcIndexer::Esplora {
        return Ok(Ok(()));
    }
    match indexer::fetch(client, &BtcIndexerReq::TipHeight) {
        Ok(BtcIndexerResp::TipHeight(height)) => session.indexer_tip = Some(height),
        Err(IndexerError::RateLimited) => {
            return Err(BtcError::Indexer(IndexerError::RateLimited));
        }
        Ok(_) | Err(_) => {}
    }
    Ok(match session.indexer_tip {
        Some(indexer)
            if core_tip > indexer.saturating_add(yw_core::btc::BTC_PLAN_TIP_AHEAD_MAX) =>
        {
            Err((core_tip, indexer))
        }
        _ => Ok(()),
    })
}

/// The check a job needs: blocked → error without requests; steps 1–4 when due; otherwise
/// step 2 only when `refresh_tip` (refresh needs a current tip), or the cached tip.
///
/// # Errors
///
/// As [`check_full`].
pub fn ensure_chain(
    client: &BtcClient<'_>,
    session: &mut ChainSession,
    input: ChainInput,
    refresh_tip: bool,
) -> Result<ChainStatus, BtcError> {
    gate(client, session)?;
    if session.full_check_due(client.now_ms()) {
        return check_full(client, session, input);
    }
    let tip = if let (false, Some(tip)) = (refresh_tip, session.tip_height) {
        tip
    } else {
        let tip = step2(client, session, input)?;
        session.ratchet(tip);
        tip
    };
    Ok(session.status(input, tip))
}
