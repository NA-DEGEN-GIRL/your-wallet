//! `btc::work`: the Bitcoin jobs of the `yw-rpc` worker (spec/04 §1.2, spec/08 §2–§4, §11.3,
//! §12.2). [`BtcWorker`] keeps one session per network (`ChainSession` + `Pace`) and resets it
//! when the Core URL, `bitcoin.indexer`, `esploraBaseUrl` or `BtcMeta.network` of a job differ
//! from the session's (compared by a hash, the URL itself is not kept), and on
//! [`BtcRpcJob::Reset`] (lock, settings change). Every job answers with one [`BtcRpcEvent`]
//! (discovery also with progress events); nothing here touches keys, meta or the journal: the
//! UI thread hands the results to the key worker, and yw-core decides (`Discovery`,
//! `choose_fee_rate`, `plan_send`/`plan_fee_bump`, `check_mempool_accept`,
//! `broadcast_outcome`, `journal::btc::observe`).

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use yw_core::btc::address::ScriptKind;
use yw_core::btc::fee::{FeeError, choose_fee_rate, fee_floor};
use yw_core::btc::policy::{MempoolAccept, SendRawResult};
use yw_core::btc::select::BumpSource;
use yw_core::btc::{
    BTC_CONF_TARGETS, BtcMeta, BtcNetwork, BtcSendFacts, BumpRequest, FeeRate, FeeSelection,
    OutPoint, PlanError, Sats, SendAmount, SendPlan, SendRequest, Txid, plan_fee_bump, plan_send,
};
use yw_core::journal::btc::TrackObservation;
use yw_win::http::HttpsUrl;

use super::broadcast::{
    EsploraPostOutcome, ManualBroadcastGate, esplora_broadcast_confirmed, send_raw_transaction,
    test_mempool_accept,
};
use super::chain::{ChainInput, ChainSession, ChainStatus, ensure_chain, tip_ahead_check};
use super::flow::{
    DiscoveryJob, DiscoveryResult, RefreshJob, RefreshResult, TrackItem, TrackJob, cooldown_gate,
    discover, esplora_test, observe_tx, refresh,
};
use super::rpc::{self, MempoolInfo};
use super::{
    APP_LOG, BtcClient, BtcEndpoint, BtcEnv, BtcError, LogSink, Pace, Trigger, indexer_word,
    network_id,
};
use crate::flow::evm::Clock;
use crate::logging::Field;
use crate::rpc::Transport;
use crate::settings::{BtcIndexer, LogLevel};

/// The network a job runs on: its sources and the `BtcMeta.network` copy (a settings/meta
/// mismatch blocks every call without a request).
#[derive(Clone, Debug)]
pub struct BtcTarget {
    /// Sources (settings network, Core URL, indexer, Esplora base).
    pub endpoint: BtcEndpoint,
    /// `BtcMeta.network`.
    pub meta_net: BtcNetwork,
}

/// A signed transaction to pre-check, send or post (the journal's bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct SignedTxRef {
    /// Local txid.
    pub txid: Txid,
    /// Signed bytes (witness included).
    pub raw: Vec<u8>,
    /// yw-core's `maxfeerate` literal (BTC/kvB, 8 decimals).
    pub maxfeerate: String,
}

impl core::fmt::Debug for SignedTxRef {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "SignedTxRef({})", self.txid)
    }
}

/// The fee-rate input of a plan (spec/08 §8.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeInput {
    /// `estimatesmartfee [target, "economical"]` (2 / 6 / 24).
    Target(u32),
    /// Manual sat/vB (`parse_user_sat_per_vb`).
    Manual(FeeRate),
}

/// What to plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrepareKind {
    /// A send.
    Send {
        /// Recipient (`parse_address`).
        recipient: ScriptKind,
        /// Amount or send-max.
        amount: SendAmount,
    },
    /// An RBF fee bump of the current bump target.
    Bump {
        /// `BtcRecord::bump_source`.
        source: Box<BumpSource>,
    },
}

/// The plan job of the send / fee-bump form (spec/08 §7–§9): fresh chain check,
/// `getmempoolinfo`, `estimatesmartfee` for the chosen target (or the manual rate),
/// `choose_fee_rate`, `plan_send` / `plan_fee_bump` with candidates from `BtcMeta::spendable` at
/// the fresh tip, and the approval facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrepareJob {
    /// Snapshot of `BtcMeta` (public data: account node, indices, verified set).
    pub meta: BtcMeta,
    /// Outpoints of in-flight journal records (`journal::btc::in_flight_outpoints`).
    pub in_flight: Vec<OutPoint>,
    /// Input sets of live abandoned records (`journal::btc::abandoned_conflicts`): a send spends
    /// one outpoint of each (spec/08 §12.1).
    pub conflicts: Vec<Vec<OutPoint>>,
    /// Send or bump.
    pub kind: PrepareKind,
    /// Fee-rate input.
    pub fee: FeeInput,
    /// The exact fee typed to lift the cap (spec/08 §8.3), if any.
    pub typed_fee_override: Option<Sats>,
    /// 32 bytes from the OS RNG (input order and change position, spec/08 §7.5).
    pub layout_seed: [u8; 32],
    /// Chain-check inputs.
    pub chain: ChainInput,
}

/// A ready plan with the approval facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prepared {
    /// The plan (immutable; the approval binds its payload).
    pub plan: SendPlan,
    /// `BtcMeta::send_facts` at the fresh tip.
    pub facts: BtcSendFacts,
    /// Chain facts of the fresh check.
    pub chain: ChainStatus,
    /// The fee floor used.
    pub floor: FeeRate,
}

/// Why no plan was made (shown in the form; no approval request is created, spec/08 §10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrepareError {
    /// Chain check or Core call failed.
    Btc(BtcError),
    /// No estimate for the chosen target: manual input only, the default is the floor.
    NoEstimate {
        /// The floor.
        floor: FeeRate,
    },
    /// A manual rate below the floor.
    ManualBelowFloor {
        /// The floor.
        floor: FeeRate,
    },
    /// Fee arithmetic overflow.
    FeeOverflow,
    /// `plan_send` / `plan_fee_bump` refused (dust, funds, in flight, …).
    Plan(PlanError),
    /// The cap is exceeded: the form must show "수수료(sats)를 정확히 입력해 상한 해제" and the
    /// exact fee to type (spec/08 §8.3).
    NeedsTypedFee {
        /// The planned fee.
        fee: Sats,
        /// The planned rate, sat/kvB.
        rate_kvb: u64,
    },
    /// Above 10,000 sat/vB (B01): nothing lifts it.
    FeeUnoverridable,
    /// Public derivation failed while building the facts.
    Derivation,
    /// The Core tip is more than `BTC_PLAN_TIP_AHEAD_MAX` blocks above the indexer tip
    /// (review M2): nothing is planned.
    TipAhead {
        /// Core `blocks`.
        core: u32,
        /// Indexer `TipHeight`.
        indexer: u32,
    },
}

impl PrepareError {
    /// The fixed form text (never a server string).
    #[must_use]
    pub fn text(self, indexer: BtcIndexer) -> String {
        match self {
            Self::Btc(error) => error
                .text(indexer)
                .unwrap_or_else(|| "작업을 취소했습니다".to_owned()),
            Self::NoEstimate { floor } => {
                format!("노드가 수수료 추정을 주지 않았습니다. 직접 입력하세요(하한 {floor})")
            }
            Self::ManualBelowFloor { floor } => {
                format!("수수료율이 노드 하한({floor})보다 낮습니다")
            }
            Self::FeeOverflow => yw_core::btc::policy::texts::PLAN_OVERFLOW.to_owned(),
            Self::Plan(error) => error.to_string(),
            Self::NeedsTypedFee { fee, .. } => format!(
                "{} 상한을 풀려면 수수료(sats)를 정확히 입력하세요: {} sats",
                yw_core::btc::policy::texts::FEE_CAP_BLOCKED,
                yw_core::btc::amount::format_sats_grouped(fee.get())
            ),
            Self::FeeUnoverridable => yw_core::btc::policy::texts::FEE_UNOVERRIDABLE.to_owned(),
            Self::Derivation => yw_core::btc::policy::texts::DERIVATION_FAILED.to_owned(),
            Self::TipAhead { core, indexer } => format!(
                "노드 블록 높이({core})가 인덱서({indexer})보다 {}블록 넘게 앞서 보내기를 멈췄습니다. 잠시 뒤 다시 검토하거나 노드(RPC) 설정을 확인하세요",
                yw_core::btc::BTC_PLAN_TIP_AHEAD_MAX
            ),
        }
    }
}

/// The send form's fee preview (spec/08 §8, 2026-11-10): the node's floor and the economical
/// `estimatesmartfee` of the three targets (2·6·24 blocks; `None` = no estimate). Read-only: no
/// address is sent and nothing is planned, approved or reserved; `검토` reads both again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeQuote {
    /// `fee_floor(mempoolminfee, minrelaytxfee)`.
    pub floor: FeeRate,
    /// Fast, normal, slow.
    pub rates: [Option<FeeRate>; 3],
}

/// One tracking round over several records.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrackRound {
    /// Chain facts of the round (tip for confirmations; `max_tip_seen` to persist).
    pub chain: Option<ChainStatus>,
    /// yw-core decisions per txid, in request order.
    pub observations: Vec<(Txid, TrackObservation)>,
    /// `getmempoolentry` answered `-32601` (stop using it).
    pub mempool_entry_unsupported: bool,
    /// The failure that ended the round early (records after it were not observed).
    pub error: Option<BtcError>,
}

/// A Bitcoin job of the RPC worker.
pub enum BtcRpcJob {
    /// Settings `테스트` of an Esplora base URL (allowed while locked: no address is sent).
    EsploraTest {
        /// Network whose genesis is expected.
        net: BtcNetwork,
        /// Base URL (EDIT value or saved).
        base: HttpsUrl,
    },
    /// Forget every session (lock, URL / indexer / Esplora / network change, mismatch).
    Reset,
    /// Address discovery (full or "더 찾기").
    Discover {
        /// UI job id.
        job: u64,
        /// Network.
        target: BtcTarget,
        /// The discovery state machine and account.
        work: DiscoveryJob,
        /// Set by the UI to cancel (checked before every request).
        cancel: Arc<AtomicBool>,
    },
    /// Refresh (spec/08 §4.7).
    Refresh {
        /// UI job id.
        job: u64,
        /// Network.
        target: BtcTarget,
        /// Watch set and known outputs.
        work: RefreshJob,
    },
    /// The send form's fee preview ([`FeeQuote`]; the session's chain check like
    /// `Refresh`, then `getmempoolinfo` and `estimatesmartfee` 2·6·24 with their caps).
    FeeQuote {
        /// UI job id.
        job: u64,
        /// Network.
        target: BtcTarget,
        /// Chain-check inputs.
        chain: ChainInput,
    },
    /// Plan a send or fee bump.
    Prepare {
        /// UI job id.
        job: u64,
        /// Network.
        target: BtcTarget,
        /// Plan inputs.
        work: Box<PrepareJob>,
    },
    /// `testmempoolaccept` after steps 1–2.
    Precheck {
        /// UI job id.
        job: u64,
        /// Network.
        target: BtcTarget,
        /// The journal's signed bytes.
        tx: SignedTxRef,
        /// Chain-check inputs.
        chain: ChainInput,
    },
    /// `sendrawtransaction` after steps 1–2 (also the re-broadcast of the same bytes).
    Send {
        /// UI job id.
        job: u64,
        /// Network.
        target: BtcTarget,
        /// The journal's signed bytes.
        tx: SignedTxRef,
        /// Chain-check inputs.
        chain: ChainInput,
    },
    /// One tracking round (spec/08 §12.2).
    Track {
        /// UI job id.
        job: u64,
        /// Network.
        target: BtcTarget,
        /// The tracked records (step 2 only, in-flight replacements).
        items: Vec<TrackItem>,
        /// `getmempoolentry` usable.
        mempool_entry: bool,
        /// Automatic (skipped during the cooldown) or user.
        trigger: Trigger,
        /// Chain-check inputs.
        chain: ChainInput,
    },
    /// The user-confirmed Esplora `POST /tx` (spec/08 §11.3).
    EsploraBroadcast {
        /// UI job id.
        job: u64,
        /// Network.
        target: BtcTarget,
        /// The journal's signed bytes.
        tx: SignedTxRef,
        /// The journal facts of the offer.
        gate: ManualBroadcastGate,
    },
}

impl BtcRpcJob {
    /// Fixed name for logs.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::EsploraTest { .. } => "BtcEsploraTest",
            Self::Reset => "BtcReset",
            Self::Discover { .. } => "BtcDiscover",
            Self::Refresh { .. } => "BtcRefresh",
            Self::FeeQuote { .. } => "BtcFeeQuote",
            Self::Prepare { .. } => "BtcPrepare",
            Self::Precheck { .. } => "BtcPrecheck",
            Self::Send { .. } => "BtcSend",
            Self::Track { .. } => "BtcTrack",
            Self::EsploraBroadcast { .. } => "BtcEsploraBroadcast",
        }
    }
}

impl core::fmt::Debug for BtcRpcJob {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.name())
    }
}

/// A Bitcoin result of the RPC worker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BtcRpcEvent {
    /// Settings `테스트` (T-BTC-IDX-OK or a fixed error text).
    EsploraTest {
        /// Network tested.
        net: BtcNetwork,
        /// Fixed message (no URL, no server string).
        message: String,
        /// Genesis matched.
        ok: bool,
    },
    /// Discovery progress (addresses checked so far).
    Progress {
        /// UI job id.
        job: u64,
        /// Checked addresses.
        checked: u32,
    },
    /// Discovery finished.
    Discovered {
        /// UI job id.
        job: u64,
        /// Network.
        net: BtcNetwork,
        /// The finished state machine or why not.
        result: Result<Box<DiscoveryResult>, BtcError>,
    },
    /// Refresh finished.
    Refreshed {
        /// UI job id.
        job: u64,
        /// Network.
        net: BtcNetwork,
        /// Result.
        result: Result<Box<RefreshResult>, BtcError>,
    },
    /// The fee preview arrived.
    FeeQuote {
        /// UI job id.
        job: u64,
        /// Network.
        net: BtcNetwork,
        /// Floor and estimates, or why not.
        result: Result<FeeQuote, BtcError>,
    },
    /// Plan finished.
    Prepared {
        /// UI job id.
        job: u64,
        /// Network.
        net: BtcNetwork,
        /// Plan and facts or why not.
        result: Result<Box<Prepared>, PrepareError>,
    },
    /// `testmempoolaccept` finished.
    Prechecked {
        /// UI job id.
        job: u64,
        /// Network.
        net: BtcNetwork,
        /// The transaction.
        txid: Txid,
        /// The parsed element or the failure (the record stays `Signed`).
        result: Result<MempoolAccept, BtcError>,
    },
    /// `sendrawtransaction` finished.
    Sent {
        /// UI job id.
        job: u64,
        /// Network.
        net: BtcNetwork,
        /// The transaction.
        txid: Txid,
        /// The parsed result, or the failure before sending (nothing was sent).
        result: Result<SendRawResult, BtcError>,
    },
    /// A tracking round finished.
    Tracked {
        /// UI job id.
        job: u64,
        /// Network.
        net: BtcNetwork,
        /// Observations.
        round: Box<TrackRound>,
    },
    /// The manual Esplora broadcast finished.
    EsploraSent {
        /// UI job id.
        job: u64,
        /// Network.
        net: BtcNetwork,
        /// The transaction.
        txid: Txid,
        /// Outcome.
        result: Result<EsploraPostOutcome, BtcError>,
    },
}

struct Session {
    fingerprint: [u8; 32],
    chain: ChainSession,
    pace: Pace,
}

/// The worker's Bitcoin state: one session per network.
pub struct BtcWorker {
    mainnet: Option<Session>,
    testnet4: Option<Session>,
    log: &'static dyn LogSink,
}

impl core::fmt::Debug for BtcWorker {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BtcWorker")
    }
}

impl Default for BtcWorker {
    fn default() -> Self {
        Self::new()
    }
}

/// A hash of what defines a session (Core URL, indexer, Esplora base, both networks); the URL
/// itself is not kept.
fn fingerprint(target: &BtcTarget) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(target.endpoint.core_url.expose().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(indexer_word(target.endpoint.indexer).as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(target.endpoint.esplora_base.expose().as_bytes());
    bytes.push(0);
    bytes.push(target.endpoint.net.id());
    bytes.push(target.meta_net.id());
    yw_core::btc::tx::sha256d(&bytes)
}

fn prepare(
    client: &BtcClient<'_>,
    session: &mut ChainSession,
    work: &PrepareJob,
) -> Result<Prepared, PrepareError> {
    let status = ensure_chain(client, session, work.chain, true).map_err(PrepareError::Btc)?;
    if let Err((core, indexer)) =
        tip_ahead_check(client, session, status.tip_height).map_err(PrepareError::Btc)?
    {
        return Err(PrepareError::TipAhead { core, indexer });
    }
    let mempool: MempoolInfo =
        rpc::get_mempool_info(client).map_err(|failure| PrepareError::Btc(failure.into()))?;
    let floor = fee_floor(
        Some(FeeRate::from_sat_per_kvb(mempool.mempool_min)),
        Some(FeeRate::from_sat_per_kvb(mempool.min_relay)),
    );
    let selection = match work.fee {
        FeeInput::Target(target) => {
            let estimate = rpc::estimate_smart_fee(client, target)
                .map_err(|failure| PrepareError::Btc(failure.into()))?;
            FeeSelection::Estimate {
                target,
                estimate: estimate.map(FeeRate::from_sat_per_kvb),
            }
        }
        FeeInput::Manual(rate) => FeeSelection::Manual(rate),
    };
    let fee = choose_fee_rate(selection, floor).map_err(|error| match error {
        FeeError::NoEstimate => PrepareError::NoEstimate { floor },
        FeeError::ManualBelowFloor { floor } => PrepareError::ManualBelowFloor { floor },
        FeeError::Overflow => PrepareError::FeeOverflow,
    })?;
    let tip = status.tip_height;
    let candidates = work.meta.spendable(tip, &work.in_flight);
    let plan = match &work.kind {
        PrepareKind::Send { recipient, amount } => plan_send(&SendRequest {
            network: work.meta.network(),
            account: work.meta.account(),
            recipient: *recipient,
            amount: *amount,
            fee,
            candidates: &candidates,
            tip_height: tip,
            change_next: work.meta.change_next(),
            layout_seed: work.layout_seed,
            typed_fee_override: work.typed_fee_override,
            conflicts: &work.conflicts,
        }),
        PrepareKind::Bump { source } => plan_fee_bump(&BumpRequest {
            source,
            account: work.meta.account(),
            fee,
            incremental: Some(FeeRate::from_sat_per_kvb(mempool.incremental)),
            candidates: &candidates,
            tip_height: tip,
            change_next: work.meta.change_next(),
            layout_seed: work.layout_seed,
            typed_fee_override: work.typed_fee_override,
        }),
    }
    .map_err(PrepareError::Plan)?;
    if plan.fee_check().is_some_and(|check| check.unoverridable) {
        return Err(PrepareError::FeeUnoverridable);
    }
    if plan.needs_typed_override() {
        return Err(PrepareError::NeedsTypedFee {
            fee: plan.fee(),
            rate_kvb: plan.fee_check().map_or(0, |check| check.rate_kvb),
        });
    }
    let facts = work
        .meta
        .send_facts(&plan, tip, &work.in_flight)
        .map_err(|_| PrepareError::Derivation)?;
    Ok(Prepared {
        plan,
        facts,
        chain: status,
        floor,
    })
}

fn fee_quote(
    client: &BtcClient<'_>,
    session: &mut ChainSession,
    chain: ChainInput,
) -> Result<FeeQuote, BtcError> {
    ensure_chain(client, session, chain, false)?;
    let mempool = rpc::get_mempool_info(client)?;
    let floor = fee_floor(
        Some(FeeRate::from_sat_per_kvb(mempool.mempool_min)),
        Some(FeeRate::from_sat_per_kvb(mempool.min_relay)),
    );
    let mut rates = [None; 3];
    for (slot, target) in rates.iter_mut().zip(BTC_CONF_TARGETS) {
        *slot = rpc::estimate_smart_fee(client, target)?.map(FeeRate::from_sat_per_kvb);
    }
    Ok(FeeQuote { floor, rates })
}

fn track(
    client: &BtcClient<'_>,
    session: &mut ChainSession,
    items: &[TrackItem],
    mut mempool_entry: bool,
    trigger: Trigger,
    chain: ChainInput,
) -> TrackRound {
    let mut round = TrackRound::default();
    if let Err(error) = cooldown_gate(client, trigger)
        .and_then(|()| ensure_chain(client, session, chain, true))
        .map(|status| round.chain = Some(status))
    {
        round.error = Some(error);
        return round;
    }
    for item in items {
        let job = TrackJob {
            txid: item.txid,
            mempool_entry,
            indexer_only: item.indexer_only,
            replacements: item.replacements.clone(),
            trigger,
            chain,
        };
        match observe_tx(client, session, &job) {
            Ok(result) => {
                round.chain = Some(result.chain);
                if result.mempool_entry_unsupported {
                    mempool_entry = false;
                    round.mempool_entry_unsupported = true;
                }
                round.observations.push((item.txid, result.observation));
            }
            Err(error) => {
                round.error = Some(error);
                break;
            }
        }
    }
    round
}

impl BtcWorker {
    /// A worker logging to the process log.
    #[must_use]
    pub fn new() -> Self {
        Self::with_log(&APP_LOG)
    }

    /// A worker logging to `log` (tests).
    #[must_use]
    pub fn with_log(log: &'static dyn LogSink) -> Self {
        Self {
            mainnet: None,
            testnet4: None,
            log,
        }
    }

    /// Forgets every session (the next job runs `check_chain` steps 1–4 again).
    pub fn reset(&mut self) {
        self.mainnet = None;
        self.testnet4 = None;
    }

    /// The session of the job's network, new when its fingerprint changed.
    fn session(&mut self, target: &BtcTarget) -> &mut Session {
        let print = fingerprint(target);
        let slot = match target.endpoint.net {
            BtcNetwork::Mainnet => &mut self.mainnet,
            BtcNetwork::Testnet4 => &mut self.testnet4,
        };
        if slot
            .as_ref()
            .is_some_and(|session| session.fingerprint != print)
        {
            *slot = None;
        }
        slot.get_or_insert_with(|| Session {
            fingerprint: print,
            chain: ChainSession::new(target.endpoint.net, target.meta_net),
            pace: Pace::new(),
        })
    }

    fn log_result(&self, net: BtcNetwork, job: &'static str, error: Option<BtcError>) {
        let mut fields = vec![
            ("net", Field::Net(network_id(net))),
            ("job", Field::Word(job)),
        ];
        match error {
            None => {
                fields.push(("result", Field::Word("ok")));
                self.log.log(LogLevel::Info, "btc.job", &fields);
            }
            Some(error) => {
                fields.push(("result", Field::Word(error.log_word())));
                self.log.log(LogLevel::Warn, "btc.job", &fields);
            }
        }
    }

    /// Runs one job and emits its events.
    #[expect(clippy::too_many_lines, reason = "one arm per job kind")]
    pub fn handle(
        &mut self,
        transport: &dyn Transport,
        clock: &dyn Clock,
        job: BtcRpcJob,
        emit: &mut dyn FnMut(BtcRpcEvent),
    ) {
        let log = self.log;
        match job {
            BtcRpcJob::Reset => self.reset(),
            BtcRpcJob::EsploraTest { net, base } => {
                let outcome = esplora_test(transport, clock, log, net, &base);
                emit(BtcRpcEvent::EsploraTest {
                    net,
                    message: outcome.message(net),
                    ok: outcome == super::flow::EsploraTestOutcome::Ok,
                });
            }
            BtcRpcJob::Discover {
                job,
                target,
                work,
                cancel,
            } => {
                let net = target.endpoint.net;
                let Session { chain, pace, .. } = self.session(&target);
                let client = BtcClient::new(
                    BtcEnv {
                        transport,
                        clock,
                        pace,
                        log,
                    },
                    &target.endpoint,
                );
                let result = discover(&client, chain, &work, &cancel, &mut |checked| {
                    emit(BtcRpcEvent::Progress { job, checked });
                });
                self.log_result(net, "discover", result.as_ref().err().copied());
                emit(BtcRpcEvent::Discovered {
                    job,
                    net,
                    result: result.map(Box::new),
                });
            }
            BtcRpcJob::Refresh { job, target, work } => {
                let net = target.endpoint.net;
                let Session { chain, pace, .. } = self.session(&target);
                let client = BtcClient::new(
                    BtcEnv {
                        transport,
                        clock,
                        pace,
                        log,
                    },
                    &target.endpoint,
                );
                let result = refresh(&client, chain, &work);
                if !matches!(result, Err(BtcError::Cooldown)) {
                    self.log_result(net, "refresh", result.as_ref().err().copied());
                }
                emit(BtcRpcEvent::Refreshed {
                    job,
                    net,
                    result: result.map(Box::new),
                });
            }
            BtcRpcJob::FeeQuote {
                job,
                target,
                chain: input,
            } => {
                let net = target.endpoint.net;
                let Session { chain, pace, .. } = self.session(&target);
                let client = BtcClient::new(
                    BtcEnv {
                        transport,
                        clock,
                        pace,
                        log,
                    },
                    &target.endpoint,
                );
                let result = fee_quote(&client, chain, input);
                self.log_result(net, "fee_quote", result.as_ref().err().copied());
                emit(BtcRpcEvent::FeeQuote { job, net, result });
            }
            BtcRpcJob::Prepare { job, target, work } => {
                let net = target.endpoint.net;
                let Session { chain, pace, .. } = self.session(&target);
                let client = BtcClient::new(
                    BtcEnv {
                        transport,
                        clock,
                        pace,
                        log,
                    },
                    &target.endpoint,
                );
                let result = prepare(&client, chain, &work);
                let error = match &result {
                    Err(PrepareError::Btc(error)) => Some(*error),
                    _ => None,
                };
                self.log_result(net, "prepare", error);
                emit(BtcRpcEvent::Prepared {
                    job,
                    net,
                    result: result.map(Box::new),
                });
            }
            BtcRpcJob::Precheck {
                job,
                target,
                tx,
                chain: input,
            } => {
                let net = target.endpoint.net;
                let Session { chain, pace, .. } = self.session(&target);
                let client = BtcClient::new(
                    BtcEnv {
                        transport,
                        clock,
                        pace,
                        log,
                    },
                    &target.endpoint,
                );
                let result = test_mempool_accept(&client, chain, &tx.raw, &tx.maxfeerate, input);
                self.log_result(net, "precheck", result.as_ref().err().copied());
                emit(BtcRpcEvent::Prechecked {
                    job,
                    net,
                    txid: tx.txid,
                    result,
                });
            }
            BtcRpcJob::Send {
                job,
                target,
                tx,
                chain: input,
            } => {
                let net = target.endpoint.net;
                let Session { chain, pace, .. } = self.session(&target);
                let client = BtcClient::new(
                    BtcEnv {
                        transport,
                        clock,
                        pace,
                        log,
                    },
                    &target.endpoint,
                );
                let result =
                    send_raw_transaction(&client, chain, &tx.raw, &tx.maxfeerate, &tx.txid, input);
                self.log_result(net, "send", result.as_ref().err().copied());
                emit(BtcRpcEvent::Sent {
                    job,
                    net,
                    txid: tx.txid,
                    result,
                });
            }
            BtcRpcJob::Track {
                job,
                target,
                items,
                mempool_entry,
                trigger,
                chain: input,
            } => {
                let net = target.endpoint.net;
                let Session { chain, pace, .. } = self.session(&target);
                let client = BtcClient::new(
                    BtcEnv {
                        transport,
                        clock,
                        pace,
                        log,
                    },
                    &target.endpoint,
                );
                let round = track(&client, chain, &items, mempool_entry, trigger, input);
                if !matches!(round.error, Some(BtcError::Cooldown)) {
                    self.log_result(net, "track", round.error);
                }
                emit(BtcRpcEvent::Tracked {
                    job,
                    net,
                    round: Box::new(round),
                });
            }
            BtcRpcJob::EsploraBroadcast {
                job,
                target,
                tx,
                gate,
            } => {
                let net = target.endpoint.net;
                let Session { chain, pace, .. } = self.session(&target);
                let client = BtcClient::new(
                    BtcEnv {
                        transport,
                        clock,
                        pace,
                        log,
                    },
                    &target.endpoint,
                );
                let result = esplora_broadcast_confirmed(&client, chain, gate, &tx.raw, &tx.txid);
                self.log_result(net, "esplora_broadcast", result.as_ref().err().copied());
                emit(BtcRpcEvent::EsploraSent {
                    job,
                    net,
                    txid: tx.txid,
                    result,
                });
            }
        }
    }
}
