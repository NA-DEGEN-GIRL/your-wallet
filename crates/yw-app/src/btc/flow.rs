//! `btc::flow`: the Bitcoin read pipelines of the `yw-rpc` worker. They take a client (transport,
//! clock, pacing, endpoint) and the session's [`ChainSession`], never meta or journal types:
//!
//! - [`esplora_test`]: the settings `테스트` (`GET <base>/block-height/0` once, 10 s, no retry,
//!   no address; allowed while locked, spec/04 §2.11).
//! - [`discover`]: address discovery driving yw-core's `Discovery` (spec/08 §3.4), also
//!   "더 찾기".
//! - [`refresh`]: spec/08 §4.7 steps 1–4 (chain check and mempool floor, history of the watch
//!   set, UTXO candidates checked against Core's `gettxout`, previous-transaction verification
//!   through Core with one indexer `TxRaw` fallback).
//! - [`observe_tx`]: one tracking observation (spec/08 §12.2): the inputs of yw-core's
//!   `journal::btc::observe`, which decides.
//!
//! Every pipeline checks the session first (blocked → no request) and, for automatic jobs, the
//! 429 cooldown (spec/08 §4.4).

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};

use yw_core::bip32::path::BtcChain;
use yw_core::btc::account::BtcAccountKey;
use yw_core::btc::address::BtcAddress;
use yw_core::btc::meta::{ListedUtxo, VerifiedUtxo as CoreVerifiedUtxo};
use yw_core::btc::prevtx::{PrevTxError, verify_prev_output};
use yw_core::btc::{BTC_MAX_ADDRESS_INDEX, BtcNetwork, Discovery, OutPoint, Sats, Txid, conf};
use yw_core::journal::btc::{TrackInput, TrackObservation, hold_confirmation, observe};
use yw_win::http::HttpsUrl;

use super::chain::{ChainInput, ChainSession, ChainStatus, ensure_chain};
use super::client::{BTC_CALL_DEADLINE_MS, BtcClient, http_word, is_rate_limited};
use super::indexer::{
    self, AddrSummary, BtcIndexerReq, BtcIndexerResp, CAP_GENESIS, IndexerError, TxSeen,
    UtxoCandidate, parse_esplora, transport_error,
};
use super::rpc::{self, MempoolEntry, MempoolInfo, TxOutAnswer};
use super::{BtcError, LogSink, Trigger, indexer_word, network_id};
use crate::errors::ErrorCode;
use crate::flow::evm::Clock;
use crate::logging::Field;
use crate::rpc::Transport;
use crate::settings::{BtcIndexer, LogLevel};

/// Highest non-hardened index.
pub const MAX_CHILD_INDEX: u32 = 0x7FFF_FFFF;

/// Core's view of a candidate (`gettxout`): the value and coinbase flag it reports, compared
/// with the hash-verified previous transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoreView {
    /// `gettxout.value`.
    pub value: Sats,
    /// `gettxout.coinbase`.
    pub coinbase: bool,
}

/// Settings `테스트` result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EsploraTestOutcome {
    /// Body is this network's genesis (T-BTC-IDX-OK).
    Ok,
    /// Body is another 64-hex hash (E-BTC-003).
    Mismatch,
    /// Classified failure (E-BTC-001 / 002 / 004 / 007).
    Failed(IndexerError),
}

impl EsploraTestOutcome {
    /// The fixed message in `lang`.
    #[must_use]
    pub fn message(self, lang: yw_core::lang::Lang, net: BtcNetwork) -> String {
        match self {
            Self::Ok => super::text::ESPLORA_OK.fill(lang, [net.display_name_in(lang)]),
            Self::Mismatch => ErrorCode::Btc003.text_in(lang),
            Self::Failed(error) => error.text(lang, BtcIndexer::Esplora),
        }
    }

    /// `ok` or the code.
    #[must_use]
    pub const fn log_word(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Mismatch => "E-BTC-003",
            Self::Failed(error) => error.code().code(),
        }
    }
}

/// The settings `테스트` of an Esplora base URL: one `GET <base>/block-height/0` (no pacing,
/// no retry, no address).
#[must_use]
pub fn esplora_test(
    transport: &dyn Transport,
    clock: &dyn Clock,
    log: &dyn LogSink,
    net: BtcNetwork,
    base: &HttpsUrl,
) -> EsploraTestOutcome {
    let text = base.expose();
    match HttpsUrl::parse(&format!(
        "{}/block-height/0",
        text.strip_suffix('/').unwrap_or(text)
    )) {
        Err(_) => EsploraTestOutcome::Failed(IndexerError::Refused),
        Ok(url) => {
            let started = clock.now_ms();
            let reply = transport.http_get(&url, CAP_GENESIS);
            let late = clock.now_ms().saturating_sub(started) > BTC_CALL_DEADLINE_MS;
            let mut fields = vec![
                ("net", Field::Net(network_id(net))),
                ("idx", Field::Word(indexer_word(BtcIndexer::Esplora))),
                ("path", Field::Word("block-height")),
            ];
            let outcome = match reply {
                Err(error) => {
                    fields.push(("transport", Field::Word(http_word(error))));
                    EsploraTestOutcome::Failed(transport_error(error))
                }
                Ok(_) if late => {
                    fields.push(("transport", Field::Word("late")));
                    EsploraTestOutcome::Failed(IndexerError::Unreachable(Some(ErrorCode::Rpc002)))
                }
                Ok(response) => {
                    fields.push(("http", Field::Num(u64::from(response.status))));
                    match parse_esplora(&BtcIndexerReq::GenesisHash, &response) {
                        Ok(BtcIndexerResp::GenesisHash(hash)) if hash == net.genesis() => {
                            EsploraTestOutcome::Ok
                        }
                        Ok(BtcIndexerResp::GenesisHash(_)) => EsploraTestOutcome::Mismatch,
                        Ok(_) => EsploraTestOutcome::Failed(IndexerError::Malformed),
                        Err(error) => EsploraTestOutcome::Failed(error),
                    }
                }
            };
            fields.push(("result", Field::Word(outcome.log_word())));
            log.log(LogLevel::Info, "esplora_test", &fields);
            outcome
        }
    }
}

fn our_address(
    account: &BtcAccountKey,
    net: BtcNetwork,
    chain: BtcChain,
    index: u32,
) -> Result<BtcAddress, BtcError> {
    account
        .address(net, chain, index)
        .map_err(|_| BtcError::Derivation)
}

/// Our scriptPubKey of `(chain, index)` (the account type's output).
fn our_script(account: &BtcAccountKey, chain: BtcChain, index: u32) -> Result<Vec<u8>, BtcError> {
    account
        .script(chain, index)
        .map_err(|_| BtcError::Derivation)
}

/// An address request is only sent after step 3 passed in this session.
pub(crate) fn address_request(
    client: &BtcClient<'_>,
    session: &ChainSession,
    request: &BtcIndexerReq,
) -> Result<BtcIndexerResp, BtcError> {
    if !session.indexer_verified() {
        return Err(BtcError::Indexer(IndexerError::Refused));
    }
    indexer::fetch(client, request).map_err(BtcError::Indexer)
}

fn address_summary(
    client: &BtcClient<'_>,
    session: &ChainSession,
    address: &BtcAddress,
) -> Result<AddrSummary, BtcError> {
    match address_request(client, session, &BtcIndexerReq::Address(address.clone()))? {
        BtcIndexerResp::Address(summary) => Ok(summary),
        _ => Err(BtcError::Indexer(IndexerError::Malformed)),
    }
}

fn utxos(
    client: &BtcClient<'_>,
    session: &ChainSession,
    address: &BtcAddress,
) -> Result<Vec<UtxoCandidate>, BtcError> {
    match address_request(client, session, &BtcIndexerReq::Utxo(address.clone()))? {
        BtcIndexerResp::Utxo(list) => Ok(list),
        _ => Err(BtcError::Indexer(IndexerError::Malformed)),
    }
}

pub(crate) fn cooldown_gate(client: &BtcClient<'_>, trigger: Trigger) -> Result<(), BtcError> {
    if trigger == Trigger::Automatic && client.env().pace.in_cooldown(client.now_ms()) {
        Err(BtcError::Cooldown)
    } else {
        Ok(())
    }
}

/// Discovery input (spec/08 §3.4): the cached account node and yw-core's discovery state
/// machine to drive (`Discovery::full()` for import / enable / network change,
/// `Discovery::more(&meta)` for "더 찾기", which scans each chain 20 more from its current
/// `next`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryJob {
    /// Cached account public key (`BtcMeta`).
    pub account: BtcAccountKey,
    /// The state machine to drive (yw-core decides the gap rule).
    pub discovery: Discovery,
    /// Chain-check inputs.
    pub chain: ChainInput,
}

/// One checked address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressInfo {
    /// Chain.
    pub chain: BtcChain,
    /// Index.
    pub index: u32,
    /// Address.
    pub address: BtcAddress,
    /// Indexer summary.
    pub summary: AddrSummary,
}

/// Discovery result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryResult {
    /// The finished state machine (`Discovery::apply` writes it to `BtcMeta`).
    pub discovery: Discovery,
    /// Every checked address in request order.
    pub addresses: Vec<AddressInfo>,
    /// Chain facts.
    pub chain: ChainStatus,
}

/// Discovery (spec/08 §3.4): asks yw-core's [`Discovery`] for the next `(chain, index)`, queries
/// the indexer `Address` of that address and feeds its `tx_count` back until the state machine
/// is done. `progress` gets the number of checked addresses after each one; `cancel` is checked
/// before every request.
///
/// # Errors
///
/// [`BtcError`] (`Cancelled` when cancelled); the caller keeps `discovery_done = false`.
pub fn discover(
    client: &BtcClient<'_>,
    session: &mut ChainSession,
    job: &DiscoveryJob,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(u32),
) -> Result<DiscoveryResult, BtcError> {
    if cancel.load(Ordering::Relaxed) {
        return Err(BtcError::Cancelled);
    }
    let status = ensure_chain(client, session, job.chain, false)?;
    let net = session.network();
    let mut discovery = job.discovery.clone();
    let mut addresses = Vec::new();
    while let Some((chain, index)) = discovery.next_request() {
        if cancel.load(Ordering::Relaxed) {
            return Err(BtcError::Cancelled);
        }
        let address = our_address(&job.account, net, chain, index)?;
        let summary = address_summary(client, session, &address)?;
        discovery.observe(summary.tx_count);
        progress(discovery.checked());
        addresses.push(AddressInfo {
            chain,
            index,
            address,
            summary,
        });
    }
    Ok(DiscoveryResult {
        discovery,
        addresses,
        chain: status,
    })
}

/// Refresh input (spec/08 §4.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefreshJob {
    /// Cached account public key.
    pub account: BtcAccountKey,
    /// Watch set receive `[0, receive_count)` (= `receive_next`).
    pub receive_count: u32,
    /// Watch set change `[0, change_count)` (= `change_next`).
    pub change_count: u32,
    /// Outpoints already in `BtcMeta.verified` (not fetched again).
    pub known: Vec<OutPoint>,
    /// `(chain, index)` of the addresses the change of in-flight journal entries pays
    /// (`BtcRecord::change_paid_to`: `(Change, i)` or the fixed address `(Receive, 0)`); no
    /// "미확정 입금" for them.
    pub inflight_change: Vec<(BtcChain, u32)>,
    /// Chain-check inputs.
    pub chain: ChainInput,
    /// Automatic (skipped during the 429 cooldown) or user.
    pub trigger: Trigger,
}

/// One watched address after step 2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressState {
    /// Chain.
    pub chain: BtcChain,
    /// Index.
    pub index: u32,
    /// Indexer summary (`tx_count > 0` = used).
    pub summary: AddrSummary,
    /// Show the "미확정 입금 있음" banner (`app_btc::PENDING_INCOMING`; in-flight change
    /// excluded).
    pub pending_incoming: bool,
}

/// A current candidate (`height` present and `conf >= 1`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// Outpoint.
    pub outpoint: OutPoint,
    /// Chain of the paid address.
    pub chain: BtcChain,
    /// Index of the paid address.
    pub index: u32,
    /// Block height: Core's (`tip + 1 - gettxout.confirmations`) when it answered, else the
    /// indexer's.
    pub height: u32,
    /// Indexer value (hint).
    pub value_hint: Sats,
    /// Core's `gettxout` view; `None` = indexer only (no `gettxout` on the endpoint, or the
    /// call failed this round): shown as such.
    pub core: Option<CoreView>,
}

/// Where a verified raw transaction came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawSource {
    /// Core `getrawtransaction`.
    Core,
    /// Indexer `TxRaw` fallback.
    Indexer,
}

/// A newly verified UTXO (spec/08 §5) for `BtcMeta.verified`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedUtxo {
    /// Outpoint.
    pub outpoint: OutPoint,
    /// Verified value (the only amount source).
    pub value: Sats,
    /// Coinbase (100 confirmations before selection).
    pub is_coinbase: bool,
    /// Chain.
    pub chain: BtcChain,
    /// Index.
    pub index: u32,
    /// Indexer height.
    pub height: u32,
    /// `value_hint != value` ("서버 응답 불일치").
    pub hint_mismatch: bool,
    /// Raw source.
    pub source: RawSource,
}

/// Why a candidate was not verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyFailure {
    /// The raw transaction failed spec/08 §5.
    Prev(PrevTxError),
    /// Neither Core nor the indexer gave the raw transaction.
    Unavailable,
    /// Core's `gettxout` value or coinbase flag differs from the verified previous output.
    CoreMismatch,
}

/// A candidate left out of balance and selection ("검증 실패 UTXO n개").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FailedUtxo {
    /// Outpoint.
    pub outpoint: OutPoint,
    /// Reason.
    pub reason: VerifyFailure,
}

/// Refresh result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefreshResult {
    /// Tip, updated `max_tip_seen`, lag warning.
    pub chain: ChainStatus,
    /// Mempool floor inputs.
    pub mempool: MempoolInfo,
    /// Watch set in request order.
    pub addresses: Vec<AddressState>,
    /// The full current candidate list (verified entries absent from it may be dropped by the
    /// caller, except outpoints of in-flight journal entries and of `skipped` addresses).
    pub candidates: Vec<Candidate>,
    /// Newly verified UTXOs.
    pub verified: Vec<VerifiedUtxo>,
    /// Candidates that failed verification.
    pub failed: Vec<FailedUtxo>,
    /// Paid addresses whose UTXO list was not usable this round (Esplora HTTP 400 — mempool.space
    /// refuses more than 500 outputs — or a list over 1,000 entries or 1 MiB): skipped instead of
    /// failing the refresh; their `verified` entries are kept (`BtcRefreshUpdate::skipped`).
    pub skipped: Vec<(BtcChain, u32)>,
}

impl RefreshResult {
    /// "검증 실패 UTXO n개".
    #[must_use]
    pub fn verify_failures(&self) -> u32 {
        u32::try_from(self.failed.len()).unwrap_or(u32::MAX)
    }

    /// The current candidate list as yw-core `ListedUtxo` (input of `BtcMeta::apply_refresh`).
    #[must_use]
    pub fn listed(&self) -> Vec<ListedUtxo> {
        self.candidates
            .iter()
            .map(|candidate| ListedUtxo {
                outpoint: candidate.outpoint,
                chain: candidate.chain,
                index: candidate.index,
                height: candidate.height,
            })
            .collect()
    }

    /// Candidates Core did not confirm (`gettxout` unavailable this round): "인덱서만 확인".
    #[must_use]
    pub fn indexer_only(&self) -> Vec<OutPoint> {
        self.candidates
            .iter()
            .filter(|candidate| candidate.core.is_none())
            .map(|candidate| candidate.outpoint)
            .collect()
    }

    /// The newly verified outputs as yw-core `VerifiedUtxo` (`own` is decided by
    /// `BtcMeta::apply_refresh` from the journal's change outpoints).
    #[must_use]
    pub fn newly(&self) -> Vec<CoreVerifiedUtxo> {
        self.verified
            .iter()
            .map(|utxo| CoreVerifiedUtxo {
                outpoint: utxo.outpoint,
                value: utxo.value,
                chain: utxo.chain,
                index: utxo.index,
                height: utxo.height,
                is_coinbase: utxo.is_coinbase,
                own: false,
            })
            .collect()
    }

    /// `(chain, index, tx_count)` of every watched address (input of `BtcMeta::mark_history`).
    #[must_use]
    pub fn history(&self) -> Vec<(BtcChain, u32, u64)> {
        self.addresses
            .iter()
            .map(|state| (state.chain, state.index, state.summary.tx_count))
            .collect()
    }

    /// "UTXO가 너무 많아 목록을 받지 못한 주소 n개".
    #[must_use]
    pub fn skipped_addresses(&self) -> u32 {
        u32::try_from(self.skipped.len()).unwrap_or(u32::MAX)
    }

    /// Whether any watched address shows the "미확정 입금 있음" banner.
    #[must_use]
    pub fn pending_incoming(&self) -> bool {
        self.addresses.iter().any(|state| state.pending_incoming)
    }
}

/// The raw (unverified) previous transaction of `txid` (spec/08 §4.7-4): Core
/// `getrawtransaction` first, one indexer `TxRaw` on any Core failure other than a rate-limit
/// abort (the indexer only after `check_chain` step 3 passed). `Ok(None)` when neither gave it.
/// The bytes are only usable after `verify_prev_output`.
///
/// # Errors
///
/// A rate-limit abort (Core E-RPC-004 or indexer E-BTC-002).
pub fn prev_transaction(
    client: &BtcClient<'_>,
    session: &ChainSession,
    txid: &Txid,
) -> Result<Option<(Vec<u8>, RawSource)>, BtcError> {
    match rpc::get_raw_transaction(client, txid) {
        Ok(raw) => return Ok(Some((raw, RawSource::Core))),
        Err(failure) if is_rate_limited(failure) => return Err(BtcError::Core(failure)),
        Err(_) => {}
    }
    match address_request(client, session, &BtcIndexerReq::TxRaw(*txid)) {
        Ok(BtcIndexerResp::TxRaw(raw)) => Ok(Some((raw, RawSource::Indexer))),
        Err(BtcError::Indexer(IndexerError::RateLimited)) => {
            Err(BtcError::Indexer(IndexerError::RateLimited))
        }
        Ok(_) | Err(_) => Ok(None),
    }
}

const fn verify_word(failure: VerifyFailure) -> &'static str {
    match failure {
        VerifyFailure::Prev(PrevTxError::TooLarge) => "too_large",
        VerifyFailure::Prev(PrevTxError::Malformed(_)) => "malformed",
        VerifyFailure::Prev(PrevTxError::TxidMismatch) => "txid_mismatch",
        VerifyFailure::Prev(PrevTxError::VoutOutOfRange) => "vout_out_of_range",
        VerifyFailure::Prev(PrevTxError::ScriptMismatch) => "script_mismatch",
        VerifyFailure::Prev(PrevTxError::ZeroValue) => "zero_value",
        VerifyFailure::Unavailable => "unavailable",
        VerifyFailure::CoreMismatch => "core_mismatch",
    }
}

/// Core's own view of every candidate (`gettxout [txid, vout, true]`, review M5): an output
/// Core does not have unspent (spent on chain or by a mempool transaction, unknown), has with
/// another script, or has with 0 confirmations is dropped (not listed); a confirmed one takes
/// Core's height `tip + 1 - confirmations`. Without `gettxout` (`-32601`) or after a failed
/// call the candidate keeps the indexer's height and stays indexer-only.
///
/// # Errors
///
/// A rate-limit abort.
fn core_check(
    client: &BtcClient<'_>,
    job: &RefreshJob,
    tip_height: u32,
    candidates: Vec<Candidate>,
) -> Result<Vec<Candidate>, BtcError> {
    let mut out = Vec::with_capacity(candidates.len());
    let mut supported = true;
    for mut candidate in candidates {
        if !supported {
            out.push(candidate);
            continue;
        }
        let outpoint = candidate.outpoint;
        let dropped = |reason: &'static str| {
            client.log(
                LogLevel::Warn,
                "candidate_dropped",
                super::client::Tag::core("gettxout", Some(outpoint.txid)),
                &[
                    ("vout", Field::Num(u64::from(outpoint.vout))),
                    ("reason", Field::Word(reason)),
                ],
            );
        };
        match rpc::get_tx_out(client, &outpoint) {
            Ok(TxOutAnswer::Unspent(info)) => {
                let expected = our_script(&job.account, candidate.chain, candidate.index)?;
                if info.script_pubkey != expected {
                    dropped("script");
                } else if info.confirmations == 0 {
                    dropped("unconfirmed");
                } else {
                    candidate.height = tip_height
                        .saturating_add(1)
                        .saturating_sub(info.confirmations);
                    candidate.core = Some(CoreView {
                        value: info.value,
                        coinbase: info.coinbase,
                    });
                    out.push(candidate);
                }
            }
            Ok(TxOutAnswer::Missing) => dropped("spent_or_unknown"),
            Ok(TxOutAnswer::Unsupported) => {
                supported = false;
                out.push(candidate);
            }
            Err(failure) if is_rate_limited(failure) => return Err(BtcError::Core(failure)),
            Err(_) => out.push(candidate),
        }
    }
    Ok(out)
}

/// Refresh (spec/08 §4.7 steps 1–4). One crowded address (its `Utxo` answer is E-BTC-005:
/// `Rejected` or `TooMany`) is skipped and reported in [`RefreshResult::skipped`]; the other
/// addresses still refresh.
///
/// # Errors
///
/// [`BtcError`]: `Cooldown` for an automatic job during the cooldown (no request), a blocked
/// session, or the failed Core / indexer call (rate-limit aborts included).
pub fn refresh(
    client: &BtcClient<'_>,
    session: &mut ChainSession,
    job: &RefreshJob,
) -> Result<RefreshResult, BtcError> {
    cooldown_gate(client, job.trigger)?;
    let status = ensure_chain(client, session, job.chain, true)?;
    let mempool = rpc::get_mempool_info(client)?;
    let net = session.network();
    let inflight: HashSet<(BtcChain, u32)> = job.inflight_change.iter().copied().collect();
    let mut addresses = Vec::new();
    let mut paid: Vec<(BtcChain, u32, BtcAddress)> = Vec::new();
    for (chain, count) in [
        (BtcChain::Receive, job.receive_count),
        (BtcChain::Change, job.change_count),
    ] {
        // The watch set never exceeds `BTC_MAX_ADDRESS_INDEX` addresses per chain.
        for index in 0..count.min(BTC_MAX_ADDRESS_INDEX) {
            let address = our_address(&job.account, net, chain, index)?;
            let summary = address_summary(client, session, &address)?;
            let excluded = inflight.contains(&(chain, index));
            addresses.push(AddressState {
                chain,
                index,
                summary,
                pending_incoming: summary.unconfirmed_incoming && !excluded,
            });
            if summary.confirmed_unspent {
                paid.push((chain, index, address));
            }
        }
    }
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut seen = HashSet::new();
    let mut skipped = Vec::new();
    for (chain, index, address) in &paid {
        let list = match utxos(client, session, address) {
            Ok(list) => list,
            // The indexer already logged the code; only this address is left out.
            Err(BtcError::Indexer(IndexerError::Rejected | IndexerError::TooMany)) => {
                skipped.push((*chain, *index));
                continue;
            }
            Err(error) => return Err(error),
        };
        for utxo in list {
            let Some(height) = utxo.height else {
                continue;
            };
            if conf(height, status.tip_height) >= 1 && seen.insert(utxo.outpoint) {
                candidates.push(Candidate {
                    outpoint: utxo.outpoint,
                    chain: *chain,
                    index: *index,
                    height,
                    value_hint: utxo.value_hint,
                    core: None,
                });
            }
        }
    }
    let candidates = core_check(client, job, status.tip_height, candidates)?;
    let (verified, failed) = verify_candidates(client, session, job, &candidates)?;
    Ok(RefreshResult {
        chain: status,
        mempool,
        addresses,
        candidates,
        verified,
        failed,
        skipped,
    })
}

fn verify_candidates(
    client: &BtcClient<'_>,
    session: &ChainSession,
    job: &RefreshJob,
    candidates: &[Candidate],
) -> Result<(Vec<VerifiedUtxo>, Vec<FailedUtxo>), BtcError> {
    let known: HashSet<OutPoint> = job.known.iter().copied().collect();
    let mut raws: HashMap<Txid, Option<(Vec<u8>, RawSource)>> = HashMap::new();
    let mut verified = Vec::new();
    let mut failed = Vec::new();
    for candidate in candidates
        .iter()
        .filter(|candidate| !known.contains(&candidate.outpoint))
    {
        let txid = candidate.outpoint.txid;
        if let Entry::Vacant(slot) = raws.entry(txid) {
            slot.insert(prev_transaction(client, session, &txid)?);
        }
        let expected = our_script(&job.account, candidate.chain, candidate.index)?;
        let outcome = match raws.get(&txid) {
            Some(Some((raw, source))) => {
                verify_prev_output(raw, &txid, candidate.outpoint.vout, &expected)
                    .map(|prev| (prev, *source))
                    .map_err(VerifyFailure::Prev)
            }
            _ => Err(VerifyFailure::Unavailable),
        }
        .and_then(|(prev, source)| match candidate.core {
            Some(core) if core.value != prev.value || core.coinbase != prev.is_coinbase => {
                Err(VerifyFailure::CoreMismatch)
            }
            _ => Ok((prev, source)),
        });
        match outcome {
            Ok((prev, source)) => verified.push(VerifiedUtxo {
                outpoint: prev.outpoint,
                value: prev.value,
                is_coinbase: prev.is_coinbase,
                chain: candidate.chain,
                index: candidate.index,
                height: candidate.height,
                hint_mismatch: prev.value != candidate.value_hint,
                source,
            }),
            Err(reason) => {
                client.log(
                    LogLevel::Warn,
                    "verify_failed",
                    super::client::Tag::core("verify_prev_output", Some(txid)),
                    &[
                        ("vout", Field::Num(u64::from(candidate.outpoint.vout))),
                        ("reason", Field::Word(verify_word(reason))),
                    ],
                );
                failed.push(FailedUtxo {
                    outpoint: candidate.outpoint,
                    reason,
                });
            }
        }
    }
    Ok((verified, failed))
}

/// One record of a tracking round (from yw-core `track_mode` and `in_flight_replacements`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrackItem {
    /// The tracked txid.
    pub txid: Txid,
    /// Step 2 only (yw-core `TrackMode::ConfirmationOnly`).
    pub indexer_only: bool,
    /// The record's in-flight replacements: an indexer `Confirmed` of `txid` would conflict
    /// them, so it is applied only after Core's `getmempoolentry` answered `-5` for each.
    pub replacements: Vec<Txid>,
}

/// Tracking input (spec/08 §12.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrackJob {
    /// The tracked txid.
    pub txid: Txid,
    /// `getmempoolentry` usable (false once the endpoint answered `-32601`, spec/08 §4.5 C2).
    pub mempool_entry: bool,
    /// Step 2 only (yw-core `TrackMode::ConfirmationOnly`: `Replaced` until its replacement
    /// confirms, `Abandoned` within 30 days).
    pub indexer_only: bool,
    /// In-flight replacements of `txid` (yw-core `in_flight_replacements`; usually empty).
    pub replacements: Vec<Txid>,
    /// Automatic (skipped during the cooldown) or user.
    pub trigger: Trigger,
    /// Chain-check inputs.
    pub chain: ChainInput,
}

/// Tracking result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrackResult {
    /// yw-core's decision for this round (`journal::btc::observe` then `hold_confirmation`;
    /// never `NeedRawProbe`).
    pub observation: TrackObservation,
    /// `getmempoolentry` answered `-32601` now (the caller stops using it).
    pub mempool_entry_unsupported: bool,
    /// Chain facts (tip for confirmations).
    pub chain: ChainStatus,
}

fn tx_status(client: &BtcClient<'_>, txid: &Txid) -> Result<TxSeen, BtcError> {
    match indexer::fetch(client, &BtcIndexerReq::TxStatus(*txid))? {
        BtcIndexerResp::TxStatus(seen) => Ok(seen),
        _ => Err(BtcError::Indexer(IndexerError::Malformed)),
    }
}

/// One observation of `txid` (spec/08 §12.2 steps 1–2): gathers yw-core's [`TrackInput`]
/// (`getmempoolentry`, then the indexer `TxStatus`; without `getmempoolentry` the indexer alone,
/// plus one Esplora `TxRaw` probe when yw-core asks for it with `NeedRawProbe`) and returns
/// yw-core's [`observe`] decision. A `Confirmed` of a record with in-flight replacements then
/// goes through yw-core's [`hold_confirmation`]: Core `getmempoolentry` of each replacement
/// must answer `-5`, else the confirmation is `Deferred` this round (an indexer alone never
/// turns a replacement Core still has into `Conflicted`). Without `getmempoolentry` (§4.5 C2)
/// there is no Core answer and the indexer's confirmation is applied as before.
///
/// # Errors
///
/// [`BtcError`] (`Cooldown` for an automatic job during the cooldown).
pub fn observe_tx(
    client: &BtcClient<'_>,
    session: &mut ChainSession,
    job: &TrackJob,
) -> Result<TrackResult, BtcError> {
    cooldown_gate(client, job.trigger)?;
    let status = ensure_chain(client, session, job.chain, false)?;
    let (observation, mut unsupported) = observe_steps(client, job)?;
    let mut replacement_in_mempool = false;
    if matches!(observation, TrackObservation::Confirmed { .. })
        && job.mempool_entry
        && !unsupported
    {
        for replacement in &job.replacements {
            match rpc::get_mempool_entry(client, replacement)? {
                MempoolEntry::Absent => {}
                MempoolEntry::InMempool => {
                    replacement_in_mempool = true;
                    break;
                }
                MempoolEntry::Unsupported => {
                    unsupported = true;
                    break;
                }
            }
        }
    }
    Ok(TrackResult {
        observation: hold_confirmation(observation, replacement_in_mempool),
        mempool_entry_unsupported: unsupported,
        chain: status,
    })
}

/// yw-core's decision for one `TxStatus` answer, with the one Esplora `TxRaw` probe it asks for
/// (`NeedRawProbe`: an ambiguous `{"confirmed":false}`).
fn decide(
    client: &BtcClient<'_>,
    txid: &Txid,
    input: impl Fn(Option<bool>) -> TrackInput,
) -> Result<TrackObservation, BtcError> {
    let first = observe(input(None));
    if first != TrackObservation::NeedRawProbe {
        return Ok(first);
    }
    let raw_found = match indexer::fetch(client, &BtcIndexerReq::TxRaw(*txid)) {
        Ok(_) => true,
        Err(IndexerError::NotFound) => false,
        Err(error) => return Err(BtcError::Indexer(error)),
    };
    Ok(observe(input(Some(raw_found))))
}

/// Steps 1–2 of [`observe_tx`]: yw-core's decision and whether `getmempoolentry` answered
/// `-32601` now. An indexer that still has the transaction unconfirmed counts as "in a
/// mempool" also when Core's mempool lacks it (review M1).
fn observe_steps(
    client: &BtcClient<'_>,
    job: &TrackJob,
) -> Result<(TrackObservation, bool), BtcError> {
    let not_in_mempool = |indexer| move |raw_found| TrackInput::NotInMempool { indexer, raw_found };
    if job.indexer_only {
        let indexer = tx_status(client, &job.txid)?;
        return Ok((decide(client, &job.txid, not_in_mempool(indexer))?, false));
    }
    let mut unsupported = false;
    if job.mempool_entry {
        match rpc::get_mempool_entry(client, &job.txid)? {
            MempoolEntry::InMempool => {
                return Ok((observe(TrackInput::MempoolEntry), false));
            }
            MempoolEntry::Absent => {
                let indexer = tx_status(client, &job.txid)?;
                return Ok((decide(client, &job.txid, not_in_mempool(indexer))?, false));
            }
            MempoolEntry::Unsupported => unsupported = true,
        }
    }
    let indexer = tx_status(client, &job.txid)?;
    let observation = decide(client, &job.txid, |raw_found| TrackInput::NoMempoolRpc {
        indexer,
        raw_found,
    })?;
    Ok((observation, unsupported))
}
