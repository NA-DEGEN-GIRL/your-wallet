//! Preparation of an EVM transaction approval (spec/03 §3.7 steps 3–10) and the re-simulation at
//! click (§6.6).
//!
//! Blocking conditions without a buildable transaction (chain mismatch E34, no endpoint or failed
//! required lookups E35, in-flight or journal-full E06) end as [`PrepareFailure`] — the approval
//! window shows them and only `거부` is possible (spec/04 §3.5 `Failed`). Fee-cap, gas-cap and
//! size violations (E05, E10, E11) keep the built transaction and become a blocked draft. The
//! simulation never blocks (D15): every failure becomes a high-risk binding.

use std::sync::mpsc;

use yw_core::approval::{
    ApprovalDraft, ApprovalId, ApprovalKind, ApprovalOrigin, ApprovalRequest, ChainFacts, CodeKind,
    RiskLevel, RuleId, SimulationBinding, TokenMeta, Warning, build_evm_tx_request,
};
use yw_core::evm::abi::{
    SEL_DECIMALS, SEL_SYMBOL, balance_of_data, decode_decimals, decode_symbol,
    decode_uint256_result,
};
use yw_core::evm::address::Address;
use yw_core::evm::amount::U256;
use yw_core::evm::chain::{ChainInfo, SimulationSupport};
use yw_core::evm::decode::{DecodedCall, DecodedTx, decode_call};
use yw_core::evm::display::add_replacement;
use yw_core::evm::fee::{
    FeeError, Fees, GasEstimate, cancel_tx, check_caps, fees_of, max_total_fee, plan_gas_limit,
    speed_up_tx, suggest_fees,
};
use yw_core::evm::risk::{E05, E11, E27, E34, E35, calldata_approvals, warning};
use yw_core::evm::simulate::{AssetId, SimOutcome, SimResult, TransportKind, interpret};
use yw_core::evm::tx::{AccessListItem, Eip1559Tx, MAX_SIGNED_TX_BYTES, SIGNATURE_OVERHEAD};
use yw_core::journal::evm::{
    EvmRecord, MAX_CANDIDATES, NonceBlock, Role, Transition, apply, groups, in_flight,
    journal_full_warning, latest_candidate, plan_nonce,
};
use yw_core::vault::EvmKeySource;
use yw_win::http::HttpsUrl;

use super::track::{TrackInput, track_group};
use super::{
    ChainCache, ChainCheck, ChainJob, Clock, Limits, MAX_FACT_LOOKUPS, SharedTransport,
    with_genesis,
};
use crate::errors::ErrorCode;
use crate::rpc::evm::{self as rpc, EstimateOutcome};
use crate::rpc::{RpcClient, RpcFailure, classify};

/// What the user asked to send (spec/03 §3.3 wallet send; dApp parameters at M5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendIntent {
    /// Recipient or contract.
    pub to: Address,
    /// Native value.
    pub value: U256,
    /// Calldata.
    pub data: Vec<u8>,
    /// Access list.
    pub access_list: Vec<AccessListItem>,
    /// dApp `gas` (wallet sends: `None`).
    pub dapp_gas: Option<u64>,
    /// dApp `nonce` (spec/03 §3.2: must equal the nonce of §3.6; wallet sends: `None`).
    pub dapp_nonce: Option<u64>,
}

/// Replacement mode (spec/03 §4.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplaceMode {
    /// Speed-up.
    SpeedUp,
    /// Cancel.
    Cancel,
}

/// The nonce group to replace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplaceTarget {
    /// Mode.
    pub mode: ReplaceMode,
    /// All records of the nonce group.
    pub group: Vec<EvmRecord>,
}

/// A preparation request (spec/03 §3.7).
#[derive(Clone, Debug)]
pub struct PrepareJob {
    /// UI job id (late results with another id are dropped).
    pub job: u64,
    /// Chain and endpoint.
    pub chain: ChainJob,
    /// Approval id.
    pub id: ApprovalId,
    /// Origin.
    pub origin: ApprovalOrigin,
    /// Signing account.
    pub account: Address,
    /// Key source.
    pub signer: EvmKeySource,
    /// What to send (ignored for replacements).
    pub intent: SendIntent,
    /// Replacement target.
    pub replace: Option<ReplaceTarget>,
    /// Journal records of all chains (for the in-flight rule and reconcile).
    pub records: Vec<EvmRecord>,
    /// A new record fits after clean-up (spec/02 §5.4 pre-add check).
    pub journal_room: bool,
    /// Address-book names.
    pub address_book: Vec<(Address, String)>,
    /// Step 1–2 warnings (E31 for dApp fee fields).
    pub extra_warnings: Vec<Warning>,
    /// Time limits.
    pub limits: Limits,
}

/// What preparation found besides the display (kept for signing, the journal and re-simulation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxContext {
    /// The transaction to sign.
    pub tx: Eip1559Tx,
    /// Approval kind.
    pub kind: ApprovalKind,
    /// Journal role.
    pub role: Role,
    /// Facts used by the display.
    pub facts: ChainFacts,
    /// Steps 1–7 warnings (gas, E31).
    pub pre_warnings: Vec<Warning>,
    /// Replaced candidate hash and its maximum fee.
    pub replaced: Option<([u8; 32], Option<U256>)>,
    /// Chain with the verified genesis.
    pub chain: ChainInfo,
}

/// A ready draft.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prepared {
    /// Display model.
    pub draft: ApprovalDraft,
    /// Context.
    pub context: TxContext,
    /// When the simulation answer arrived (monotonic ms; freshness, §6.6).
    pub sim_received_ms: u64,
    /// The native emitter differs from the fork expectation (log only, §1.3-3).
    pub native_emitter_mismatch: bool,
    /// The simulated call's `gasUsed` (logged for spec/09 M4-2), `None` without a block.
    pub sim_gas_used: Option<u64>,
    /// The interpreted simulation the draft was built from (the AI explanation input, spec/06
    /// §4.3; never part of the digest by itself — the draft's binding is).
    pub sim: SimResult,
}

/// A preparation that produced no signable transaction (only `거부`, spec/04 §3.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrepareFailure {
    /// E34, E35 or E06 warning (blocked).
    pub warning: Warning,
    /// Error code shown with it.
    pub code: ErrorCode,
    /// `다시 시도` offered (E-RPC-001/002/004).
    pub retryable: bool,
    /// The dApp's `nonce` differs from the wallet's (spec/03 §3.2): answered -32602 without
    /// showing the failure.
    pub invalid_params: bool,
}

impl PrepareFailure {
    fn new(warning: Warning, code: ErrorCode) -> Self {
        Self {
            warning,
            code,
            retryable: matches!(
                code,
                ErrorCode::Rpc001 | ErrorCode::Rpc002 | ErrorCode::Rpc004
            ),
            invalid_params: false,
        }
    }

    fn e35(code: ErrorCode) -> Self {
        let cause = if code == ErrorCode::Key005 {
            "RPC 엔드포인트 없음 — 설정에서 이 네트워크의 RPC URL을 저장하세요".to_owned()
        } else {
            code.text()
        };
        Self::new(warning(E35, Some(&cause)), code)
    }

    fn rpc(failure: RpcFailure) -> Self {
        Self::e35(classify(failure))
    }

    /// No endpoint for the chain: E35 without any call (spec/04 §1.9).
    #[must_use]
    pub fn no_endpoint() -> Self {
        Self::e35(ErrorCode::Key005)
    }

    /// The text shown in the approval window.
    #[must_use]
    pub fn message(&self) -> String {
        format!("{}\n{}", self.warning.text, self.code.text())
    }

    /// The blocking rule.
    #[must_use]
    pub const fn rule(&self) -> RuleId {
        self.warning.rule
    }
}

/// Preparation outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrepareOutcome {
    /// A draft to show (possibly blocked).
    Ready(Box<Prepared>),
    /// Nothing to sign.
    Failed(PrepareFailure),
}

/// Chain state changes observed by a pipeline (shown by the UI, pins written to settings).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainEvent {
    /// The chain was checked.
    Checked {
        /// Chain id.
        chain_id: u64,
        /// Result.
        check: ChainCheck,
    },
}

/// Result of a preparation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrepareResult {
    /// Job id.
    pub job: u64,
    /// Outcome.
    pub outcome: PrepareOutcome,
    /// Reconcile transitions to commit (spec/03 §5.4).
    pub transitions: Vec<Transition>,
    /// Chain checks.
    pub chain_events: Vec<ChainEvent>,
}

struct Budget<'c> {
    clock: &'c dyn Clock,
    started: u64,
    limit: u64,
}

impl Budget<'_> {
    fn over(&self) -> bool {
        self.clock.now_ms().saturating_sub(self.started) > self.limit
    }
}

/// Runs `eth_simulateV1` on a helper thread and waits at most `wait_ms`; a later answer is
/// dropped with its channel (spec/04 §3.2.1: "늦게 온 응답은 버린다").
#[must_use]
pub fn simulate_bounded(
    transport: &SharedTransport,
    url: &HttpsUrl,
    tx: &Eip1559Tx,
    from: &Address,
    chain_and_type: bool,
    wait_ms: u64,
) -> SimOutcome {
    let (sender, receiver) = mpsc::channel();
    let transport = std::sync::Arc::clone(transport);
    let url = url.clone();
    let tx = tx.clone();
    let from = *from;
    let spawned = std::thread::Builder::new()
        .name("yw-rpc-sim".to_owned())
        .spawn(move || {
            let client = RpcClient::new(&*transport);
            let outcome = rpc::simulate(&client, &url, &tx, &from, chain_and_type);
            let _ = sender.send(outcome);
        });
    if spawned.is_err() {
        return SimOutcome::Transport(TransportKind::Other);
    }
    receiver
        .recv_timeout(std::time::Duration::from_millis(wait_ms))
        .unwrap_or(SimOutcome::Transport(TransportKind::Timeout))
}

fn fresh_fees(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    chain: &ChainInfo,
) -> Result<Fees, PrepareFailure> {
    let history = rpc::fee_history(client, url, 10).map_err(PrepareFailure::rpc)?;
    suggest_fees(&history, chain).map_err(|error| match error {
        FeeError::InvalidHistory => PrepareFailure::e35(ErrorCode::Rpc005),
        FeeError::Overflow => PrepareFailure::new(
            warning(E05, Some("수수료 계산이 범위를 넘었습니다")),
            ErrorCode::Tx001,
        ),
    })
}

fn gas_estimate(outcome: &EstimateOutcome) -> GasEstimate<'_> {
    match outcome {
        EstimateOutcome::Estimated(estimate) => GasEstimate::Estimated(*estimate),
        EstimateOutcome::Failed { revert_data, .. } => GasEstimate::Failed {
            revert_data: revert_data.as_deref(),
        },
    }
}

/// Collects the tokens and addresses whose facts the display and rules use (spec/03 §2.5, §8.5).
fn fact_targets(decoded: &DecodedTx, sim: &SimResult) -> (Vec<Address>, Vec<Address>) {
    let mut tokens: Vec<Address> = Vec::new();
    let mut addresses: Vec<Address> = vec![decoded.tx.to];
    let push = |list: &mut Vec<Address>, address: Address| {
        if !list.contains(&address) {
            list.push(address);
        }
    };
    let call_kinds: Vec<&str> = match &decoded.call {
        DecodedCall::Multicall { inner, .. } => {
            inner.iter().filter_map(DecodedCall::kind).collect()
        }
        call => call.kind().into_iter().collect(),
    };
    if call_kinds
        .iter()
        .any(|kind| kind.starts_with("erc20_") || kind.ends_with("permit_submit"))
    {
        push(&mut tokens, decoded.tx.to);
    }
    for intent in calldata_approvals(&decoded.call, &decoded.tx.to) {
        push(&mut tokens, intent.token);
        push(&mut addresses, intent.spender);
    }
    if let Some(diff) = sim.diff() {
        for change in &diff.changes {
            if let AssetId::Token(token) = change.asset {
                push(&mut tokens, token);
            }
        }
        for approval in &diff.approvals {
            push(&mut tokens, approval.asset);
            push(&mut addresses, approval.spender);
        }
    }
    (tokens, addresses)
}

fn token_meta(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    chain: &ChainInfo,
    token: &Address,
) -> TokenMeta {
    if let Some(known) = chain.token(token) {
        return TokenMeta {
            symbol: Some(known.symbol.to_owned()),
            decimals: Some(known.decimals),
            registered: true,
        };
    }
    let decimals = rpc::eth_call(client, url, token, &SEL_DECIMALS, "latest")
        .ok()
        .and_then(|output| decode_decimals(&output));
    let symbol = rpc::eth_call(client, url, token, &SEL_SYMBOL, "latest")
        .ok()
        .and_then(|output| decode_symbol(&output));
    TokenMeta {
        symbol,
        decimals,
        registered: false,
    }
}

/// What step 9 could not settle.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct FactGaps {
    /// Lookup limit or budget reached (E27).
    limited: bool,
    /// An `eth_getCode` failed: an address stays unclassified (see [`unclassified_warning`]).
    unclassified: bool,
}

/// An address whose `eth_getCode` failed cannot be ruled out as an EOA spender (E16) or an
/// unregistered contract (E21): the request is raised to high risk instead of silently showing
/// it unclassified. (Stands in for an `Unknown` code classification in the core rules.)
fn unclassified_warning() -> Warning {
    Warning {
        rule: E27,
        level: RiskLevel::High,
        text: "주소 분류 조회(eth_getCode)에 실패했습니다 — 승인 대상이 일반 계정(EOA)인지 확인할 수 없습니다"
            .to_owned(),
    }
}

/// Adds `warning` once.
fn push_unique(warnings: &mut Vec<Warning>, warning: Warning) {
    if !warnings.contains(&warning) {
        warnings.push(warning);
    }
}

/// Step 9 lookups (token metadata, classification, approval balances) within the budget and the
/// 16-lookup limits. Facts already in `facts` are not looked up again, so a re-simulation only
/// classifies the spenders and tokens its new diff adds (spec/03 §6.6-3).
#[expect(
    clippy::too_many_arguments,
    reason = "the step 9 inputs of spec/03 §3.7"
)]
fn gather_facts(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    chain: &ChainInfo,
    account: &Address,
    decoded: &DecodedTx,
    sim: &SimResult,
    facts: &mut ChainFacts,
    budget: &Budget<'_>,
) -> FactGaps {
    let (tokens, addresses) = fact_targets(decoded, sim);
    let mut gaps = FactGaps {
        limited: tokens.len() > MAX_FACT_LOOKUPS || addresses.len() > MAX_FACT_LOOKUPS,
        unclassified: false,
    };
    for token in tokens.iter().take(MAX_FACT_LOOKUPS) {
        if facts.token(token).is_some() {
            continue;
        }
        if budget.over() {
            gaps.limited = true;
            break;
        }
        let meta = token_meta(client, url, chain, token);
        facts.tokens.push((*token, meta));
    }
    let approvals = calldata_approvals(&decoded.call, &decoded.tx.to);
    for intent in approvals.iter().take(MAX_FACT_LOOKUPS) {
        if budget.over() {
            gaps.limited = true;
            break;
        }
        if facts.balance(&intent.token).is_none()
            && let Ok(output) = rpc::eth_call(
                client,
                url,
                &intent.token,
                &balance_of_data(account),
                "latest",
            )
            && let Some(balance) = decode_uint256_result(&output)
        {
            facts.balances.push((intent.token, balance));
        }
    }
    for address in addresses.iter().take(MAX_FACT_LOOKUPS) {
        if chain.label(address).is_some() || facts.code_of(address).is_some() {
            continue;
        }
        if budget.over() {
            gaps.limited = true;
            break;
        }
        match rpc::code(client, url, address) {
            Ok(code) => facts.code.push((*address, CodeKind::from_code(&code))),
            Err(_) => gaps.unclassified = true,
        }
    }
    gaps
}

/// Step 9 warnings of `gaps` added to `warnings` (once each).
fn gap_warnings(gaps: FactGaps, warnings: &mut Vec<Warning>) {
    if gaps.limited {
        push_unique(warnings, warning(E27, None));
    }
    if gaps.unclassified {
        push_unique(warnings, unclassified_warning());
    }
}

fn blocked(text: Option<&str>, rule: RuleId) -> Warning {
    warning(rule, text)
}

struct Built {
    tx: Eip1559Tx,
    role: Role,
    kind: ApprovalKind,
    pre_warnings: Vec<Warning>,
    blocking: Vec<Warning>,
    replaced: Option<([u8; 32], Option<U256>)>,
}

/// Steps 5–7 for a new transaction.
fn build_new(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    job: &PrepareJob,
    chain: &ChainInfo,
    nonce: u64,
) -> Result<Built, PrepareFailure> {
    let fees = fresh_fees(client, url, chain)?;
    let provisional = Eip1559Tx {
        chain_id: chain.chain_id,
        nonce,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
        max_fee_per_gas: fees.max_fee_per_gas,
        gas_limit: 0,
        to: job.intent.to,
        value: job.intent.value,
        data: job.intent.data.clone(),
        access_list: job.intent.access_list.clone(),
    };
    let estimate = rpc::estimate_gas(client, url, &job.account, &provisional);
    let plan = plan_gas_limit(
        gas_estimate(&estimate),
        job.intent.dapp_gas,
        &fees,
        &job.chain.caps,
        chain,
    );
    let mut tx = provisional;
    tx.gas_limit = plan.gas_limit;
    let (blocking, pre): (Vec<Warning>, Vec<Warning>) = plan
        .warnings
        .into_iter()
        .partition(|warning| warning.level == RiskLevel::Blocked);
    let mut blocking = blocking;
    if let Err(violation) = check_caps(&fees, tx.gas_limit, &job.chain.caps) {
        blocking.push(violation.warning(chain));
    }
    Ok(Built {
        tx,
        role: Role::Original,
        kind: ApprovalKind::EvmTransaction,
        pre_warnings: pre,
        blocking,
        replaced: None,
    })
}

/// Steps 5–7 for a speed-up or cancel (spec/03 §4.6).
fn build_replacement(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    job: &PrepareJob,
    chain: &ChainInfo,
    mode: ReplaceMode,
    latest: &EvmRecord,
) -> Result<Built, PrepareFailure> {
    let old = latest
        .tx()
        .ok_or_else(|| PrepareFailure::new(journal_full_warning(), ErrorCode::App009))?;
    let fees = fresh_fees(client, url, chain)?;
    let overflow = |_| {
        PrepareFailure::new(
            warning(E05, Some("수수료 계산이 범위를 넘었습니다")),
            ErrorCode::Tx001,
        )
    };
    let mut pre = Vec::new();
    let mut blocking = Vec::new();
    let tx = match mode {
        ReplaceMode::SpeedUp => speed_up_tx(&old, &fees).map_err(overflow)?,
        ReplaceMode::Cancel => {
            let probe = Eip1559Tx {
                to: job.account,
                value: U256::ZERO,
                data: Vec::new(),
                access_list: Vec::new(),
                ..old.clone()
            };
            let estimate = rpc::estimate_gas(client, url, &job.account, &probe);
            let plan = plan_gas_limit(gas_estimate(&estimate), None, &fees, &job.chain.caps, chain);
            for warning in plan.warnings {
                if warning.level == RiskLevel::Blocked {
                    blocking.push(warning);
                } else {
                    pre.push(warning);
                }
            }
            cancel_tx(&old, &job.account, plan.gas_limit, &fees).map_err(overflow)?
        }
    };
    if let Err(violation) = check_caps(
        &fees_of(&tx, fees.base_fee_next),
        tx.gas_limit,
        &job.chain.caps,
    ) {
        blocking.push(violation.warning(chain));
    }
    let (role, kind) = match mode {
        ReplaceMode::SpeedUp => (Role::SpeedUp, ApprovalKind::EvmSpeedUp),
        ReplaceMode::Cancel => (Role::Cancel, ApprovalKind::EvmCancel),
    };
    Ok(Built {
        tx,
        role,
        kind,
        pre_warnings: pre,
        blocking,
        replaced: Some((
            latest.tx_hash,
            max_total_fee(old.gas_limit, &old.max_fee_per_gas),
        )),
    })
}

/// What reconcile produced: transitions, the records after them, and a chain mismatch found by
/// the re-check before a re-broadcast (nothing was sent then).
struct Reconciled {
    transitions: Vec<Transition>,
    records: Vec<EvmRecord>,
    mismatch: Option<super::MismatchKind>,
}

/// Reconciles the open groups of `(chain, account)` before the nonce rule (spec/03 §3.6, §5.4);
/// a re-broadcast re-checks `chain` first (§1.4) and honours `manual_resend`.
fn reconcile_account(
    transport: &SharedTransport,
    url: &HttpsUrl,
    chain: &ChainInfo,
    job: &PrepareJob,
    clock: &dyn Clock,
) -> Reconciled {
    let mut records = job.records.clone();
    let mut transitions = Vec::new();
    let mut mismatch = None;
    let open: Vec<Vec<EvmRecord>> = groups(&records)
        .into_iter()
        .filter(|(key, members)| {
            key.chain_id == job.chain.info.chain_id
                && key.account == job.account
                && members.iter().any(|record| !record.is_terminal())
        })
        .map(|(_, members)| members.into_iter().cloned().collect())
        .collect();
    for group in open {
        let result = track_group(
            transport,
            url,
            chain,
            &TrackInput {
                group,
                drop_seen_unix_ms: None,
                now_unix_ms: clock.now_unix_ms(),
                allow_rebroadcast: true,
            },
        );
        mismatch = mismatch.or(result.chain_mismatch);
        for transition in result.transitions {
            let _ = apply(&mut records, &transition);
            transitions.push(transition);
        }
    }
    Reconciled {
        transitions,
        records,
        mismatch,
    }
}

/// Step 4 nonce: the in-flight rule for new transactions, or the replaced group's nonce.
fn nonce_step(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    job: &PrepareJob,
    records: &[EvmRecord],
) -> Result<(u64, Option<EvmRecord>), PrepareFailure> {
    let latest =
        rpc::transaction_count(client, url, &job.account, "latest").map_err(PrepareFailure::rpc)?;
    let Some(target) = &job.replace else {
        let pending = rpc::transaction_count(client, url, &job.account, "pending")
            .map_err(PrepareFailure::rpc)?;
        let nonce = plan_nonce(
            in_flight(records, job.chain.info.chain_id, &job.account),
            latest,
            pending,
        )
        .map_err(|block| PrepareFailure::new(block.warning(), ErrorCode::Tx002))?;
        if job
            .intent
            .dapp_nonce
            .is_some_and(|requested| requested != nonce)
        {
            let mut failure = PrepareFailure::new(
                warning(E35, Some("dApp이 지정한 nonce가 지갑의 nonce와 다릅니다")),
                ErrorCode::Tx002,
            );
            failure.invalid_params = true;
            return Err(failure);
        }
        return Ok((nonce, None));
    };
    let key = target
        .group
        .first()
        .map(EvmRecord::key)
        .ok_or_else(|| PrepareFailure::new(journal_full_warning(), ErrorCode::App009))?;
    let current: Vec<&EvmRecord> = records
        .iter()
        .filter(|record| record.key() == key)
        .collect();
    let resolved = PrepareFailure::new(
        NonceBlock::InFlight { nonce: key.nonce }
            .warning()
            .with_text(format!(
                "대체할 거래가 이미 처리되었습니다 (nonce {})",
                key.nonce
            )),
        ErrorCode::Tx002,
    );
    let Some(latest_record) = latest_candidate(&current) else {
        return Err(resolved);
    };
    if latest != key.nonce {
        return Err(resolved);
    }
    if current.len() >= MAX_CANDIDATES {
        return Err(PrepareFailure::new(
            NonceBlock::InFlight { nonce: key.nonce }
                .warning()
                .with_text(format!(
                    "같은 nonce의 대체 거래는 최대 {} 번입니다 (nonce {})",
                    MAX_CANDIDATES - 1,
                    key.nonce
                )),
            ErrorCode::Tx002,
        ));
    }
    Ok((key.nonce, Some(latest_record.clone())))
}

trait WithText {
    fn with_text(self, text: String) -> Self;
}

impl WithText for Warning {
    fn with_text(mut self, text: String) -> Self {
        self.text = text;
        self
    }
}

fn finish(
    job: &PrepareJob,
    chain: &ChainInfo,
    built: Built,
    sim: &SimResult,
    facts: ChainFacts,
    sim_received_ms: u64,
    now_unix_ms: u64,
) -> PrepareOutcome {
    let decoded = DecodedTx {
        call: decode_call(chain, &built.tx.to, &built.tx.data),
        tx: built.tx.clone(),
    };
    let mut warnings = job.extra_warnings.clone();
    warnings.extend(built.pre_warnings.iter().cloned());
    warnings.extend(built.blocking.iter().cloned());
    let draft = build_evm_tx_request(
        job.id,
        job.origin.clone(),
        job.signer,
        job.account,
        built.kind,
        chain,
        &decoded,
        sim,
        &facts,
        warnings,
        now_unix_ms,
    );
    let draft = match (draft, built.replaced) {
        (Ok(draft), Some((hash, old))) => add_replacement(draft, chain, &hash, old),
        (draft, _) => draft,
    };
    let Ok(draft) = draft else {
        return PrepareOutcome::Failed(PrepareFailure::new(
            warning(E35, Some(&ErrorCode::Ui001.text())),
            ErrorCode::Ui001,
        ));
    };
    let native_emitter_mismatch = matches!(
        sim,
        SimResult::Simulated { diff, .. } if diff.native_emitter_mismatch
    );
    let sim_gas_used = match sim {
        SimResult::Simulated { diff, .. } => Some(diff.gas_used),
        SimResult::Unavailable { .. } => None,
    };
    PrepareOutcome::Ready(Box::new(Prepared {
        draft,
        context: TxContext {
            tx: built.tx,
            kind: built.kind,
            role: built.role,
            facts,
            pre_warnings: built.pre_warnings,
            replaced: built.replaced,
            chain: chain.clone(),
        },
        sim_received_ms,
        native_emitter_mismatch,
        sim_gas_used,
        sim: sim.clone(),
    }))
}

/// The preparation pipeline of spec/03 §3.7 steps 3–10. `on_simulating(since_ms)` is called right
/// before `eth_simulateV1` (spec/04 §3.5 `Preparing(Simulating)`).
#[must_use]
#[expect(
    clippy::too_many_lines,
    reason = "the spec/03 §3.7 steps in order, each with its failure rule"
)]
pub fn prepare(
    transport: &SharedTransport,
    cache: &mut ChainCache,
    job: &PrepareJob,
    clock: &dyn Clock,
    on_simulating: &dyn Fn(u64),
) -> PrepareResult {
    let client = RpcClient::new(&**transport);
    let url = &job.chain.url;
    let budget = Budget {
        clock,
        started: clock.now_ms(),
        limit: job.limits.budget_ms,
    };
    let mut result = PrepareResult {
        job: job.job,
        outcome: PrepareOutcome::Failed(PrepareFailure::e35(ErrorCode::App009)),
        transitions: Vec::new(),
        chain_events: Vec::new(),
    };
    let fail = |mut result: PrepareResult, failure: PrepareFailure| {
        result.outcome = PrepareOutcome::Failed(failure);
        result
    };
    // Step 3: chain check.
    let check = cache.ensure(
        &client,
        url,
        &job.chain.info,
        clock,
        job.limits.retry_delay_ms,
    );
    result.chain_events.push(ChainEvent::Checked {
        chain_id: job.chain.info.chain_id,
        check,
    });
    let chain = match check {
        ChainCheck::Verified { genesis, .. } => with_genesis(&job.chain.info, genesis),
        ChainCheck::Mismatch(kind) => {
            return fail(result, PrepareFailure::new(blocked(None, E34), kind.code()));
        }
        ChainCheck::Unverified(failure) => return fail(result, PrepareFailure::rpc(failure)),
    };
    // Step 4: account code, reconcile, nonce, journal room.
    let mut facts = ChainFacts {
        address_book: job.address_book.clone(),
        ..ChainFacts::default()
    };
    match rpc::code(&client, url, &job.account) {
        Ok(code) => facts.account_code = CodeKind::from_code(&code),
        Err(failure) => return fail(result, PrepareFailure::rpc(failure)),
    }
    let reconciled = reconcile_account(transport, url, &chain, job, clock);
    result.transitions = reconciled.transitions;
    if let Some(kind) = reconciled.mismatch {
        let check = ChainCheck::Mismatch(kind);
        cache.store(job.chain.info.chain_id, check);
        result.chain_events.push(ChainEvent::Checked {
            chain_id: job.chain.info.chain_id,
            check,
        });
        return fail(result, PrepareFailure::new(blocked(None, E34), kind.code()));
    }
    let records = reconciled.records;
    let (nonce, latest) = match nonce_step(&client, url, job, &records) {
        Ok(found) => found,
        Err(failure) => return fail(result, failure),
    };
    if !job.journal_room {
        return fail(
            result,
            PrepareFailure::new(journal_full_warning(), ErrorCode::Tx005),
        );
    }
    if budget.over() {
        return fail(result, PrepareFailure::e35(ErrorCode::Rpc002));
    }
    // Steps 5–7: fees, gas, transaction.
    let built = match (&job.replace, latest) {
        (Some(target), Some(latest)) => {
            build_replacement(&client, url, job, &chain, target.mode, &latest)
        }
        _ => build_new(&client, url, job, &chain, nonce),
    };
    let mut built = match built {
        Ok(built) => built,
        Err(failure) => return fail(result, failure),
    };
    if built.tx.validate().is_err()
        || built
            .tx
            .signing_preimage()
            .len()
            .saturating_add(SIGNATURE_OVERHEAD)
            > MAX_SIGNED_TX_BYTES
    {
        built.blocking.push(warning(E11, None));
    }
    if budget.over() {
        return fail(result, PrepareFailure::e35(ErrorCode::Rpc002));
    }
    let now_unix = clock.now_unix_ms();
    if !built.blocking.is_empty() {
        result.outcome = finish(
            job,
            &chain,
            built,
            &SimResult::skipped(),
            facts,
            clock.now_ms(),
            now_unix,
        );
        return result;
    }
    // Step 8: simulation (always attempted unless unsupported; never blocks).
    let outcome = if chain.simulation == SimulationSupport::Unsupported {
        SimOutcome::Unsupported
    } else if budget.over() {
        SimOutcome::Transport(TransportKind::Timeout)
    } else {
        on_simulating(clock.now_ms());
        simulate_bounded(
            transport,
            url,
            &built.tx,
            &job.account,
            true,
            job.limits.sim_wait_ms,
        )
    };
    let sim_received_ms = clock.now_ms();
    let sim = interpret(
        &chain,
        &built.tx,
        &job.account,
        &outcome,
        clock.now_unix_ms(),
    );
    // Step 9: facts.
    let decoded = DecodedTx {
        call: decode_call(&chain, &built.tx.to, &built.tx.data),
        tx: built.tx.clone(),
    };
    let gaps = gather_facts(
        &client,
        url,
        &chain,
        &job.account,
        &decoded,
        &sim,
        &mut facts,
        &budget,
    );
    gap_warnings(gaps, &mut built.pre_warnings);
    // Step 10: draft.
    result.outcome = finish(
        job,
        &chain,
        built,
        &sim,
        facts,
        sim_received_ms,
        clock.now_unix_ms(),
    );
    result
}

/// Re-simulation request (spec/03 §6.6).
#[derive(Clone, Debug)]
pub struct ResimJob {
    /// UI job id.
    pub job: u64,
    /// Chain and endpoint.
    pub chain: ChainJob,
    /// The issued request being replaced.
    pub request: ApprovalRequest,
    /// Its context.
    pub context: TxContext,
    /// Address book (facts).
    pub address_book: Vec<(Address, String)>,
    /// Origin warnings kept from the first preparation.
    pub extra_warnings: Vec<Warning>,
    /// Limits.
    pub limits: Limits,
}

/// How a re-simulation compares with the shown request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResimKind {
    /// Simulated and the stable part is unchanged: replace and consume with this click.
    Same,
    /// Simulated with a different stable part: replace, `T-SIM-CHANGED`, new click.
    Changed,
    /// No result: replace with a `None` binding, `T-SIM-RESIM-FAILED`, new click.
    NoResult,
    /// The fee recomputation broke a cap (E05): replace with a blocked request.
    Blocked,
    /// The chain check found another chain (E34): nothing to replace, the window shows the
    /// failure and only `거부` remains (spec/03 §3.7 steps 3–4 rule, spec/04 §3.5 `Failed`).
    Failed,
}

/// Re-simulation result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResimResult {
    /// Job id.
    pub job: u64,
    /// Comparison.
    pub kind: ResimKind,
    /// The replacement draft (same id, kind, origin, chain, account and signer).
    pub prepared: Option<Box<Prepared>>,
    /// The blocking failure of [`ResimKind::Failed`].
    pub failure: Option<PrepareFailure>,
}

fn stable_equal(a: &ApprovalRequest, b: &ApprovalDraft) -> bool {
    match (a.display.stable_bytes(), b.display.stable_bytes()) {
        (Ok(left), Ok(right)) => left == right && a.payload == b.payload,
        _ => false,
    }
}

fn rebuild(
    job: &ResimJob,
    context: TxContext,
    sim: &SimResult,
    sim_received_ms: u64,
    now_unix_ms: u64,
) -> Option<Box<Prepared>> {
    let (yw_core::approval::AccountRef::Evm(account), yw_core::approval::Signer::Evm(signer)) =
        (job.request.account, job.request.signer)
    else {
        return None;
    };
    let prepare_job = PrepareJob {
        job: job.job,
        chain: job.chain.clone(),
        id: job.request.id,
        origin: job.request.origin.clone(),
        account,
        signer,
        intent: SendIntent {
            to: context.tx.to,
            value: context.tx.value,
            data: context.tx.data.clone(),
            access_list: context.tx.access_list.clone(),
            dapp_gas: None,
            dapp_nonce: None,
        },
        replace: None,
        records: Vec::new(),
        journal_room: true,
        address_book: job.address_book.clone(),
        extra_warnings: job.extra_warnings.clone(),
        limits: job.limits,
    };
    let chain = context.chain.clone();
    let built = Built {
        tx: context.tx,
        role: context.role,
        kind: context.kind,
        pre_warnings: context.pre_warnings,
        blocking: Vec::new(),
        replaced: context.replaced,
    };
    match finish(
        &prepare_job,
        &chain,
        built,
        sim,
        context.facts,
        sim_received_ms,
        now_unix_ms,
    ) {
        PrepareOutcome::Ready(prepared) => Some(prepared),
        PrepareOutcome::Failed(_) => None,
    }
}

/// §6.6-3: the re-simulated diff may name spenders and tokens the first preparation never
/// classified (an approval that appeared since): they are looked up now instead of reusing the
/// old facts; what cannot be settled adds E27 / the unclassified warning.
fn reclassify(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    account: &Address,
    sim: &SimResult,
    context: &mut TxContext,
    budget: &Budget<'_>,
) {
    let decoded = DecodedTx {
        call: decode_call(&context.chain, &context.tx.to, &context.tx.data),
        tx: context.tx.clone(),
    };
    let gaps = gather_facts(
        client,
        url,
        &context.chain,
        account,
        &decoded,
        sim,
        &mut context.facts,
        budget,
    );
    gap_warnings(gaps, &mut context.pre_warnings);
}

/// Re-simulates the shown transaction at click (spec/03 §6.6-3/4). The expiry is unchanged by
/// the caller (`ApprovalStore::replace`).
#[must_use]
pub fn resimulate(
    transport: &SharedTransport,
    cache: &mut ChainCache,
    job: &ResimJob,
    clock: &dyn Clock,
) -> ResimResult {
    let client = RpcClient::new(&**transport);
    let url = &job.chain.url;
    let mut result = ResimResult {
        job: job.job,
        kind: ResimKind::NoResult,
        prepared: None,
        failure: None,
    };
    let yw_core::approval::AccountRef::Evm(account) = job.request.account else {
        return result;
    };
    let started = clock.now_ms();
    let check = cache.ensure(
        &client,
        url,
        &job.chain.info,
        clock,
        job.limits.retry_delay_ms,
    );
    let outcome = match check {
        ChainCheck::Verified { .. } => simulate_bounded(
            transport,
            url,
            &job.context.tx,
            &account,
            true,
            job.limits.sim_wait_ms,
        ),
        // A chain mismatch blocks: it is never an approvable "no simulation" warning.
        ChainCheck::Mismatch(kind) => {
            result.kind = ResimKind::Failed;
            result.failure = Some(PrepareFailure::new(blocked(None, E34), kind.code()));
            return result;
        }
        ChainCheck::Unverified(_) => SimOutcome::Transport(TransportKind::Other),
    };
    let mut context = job.context.clone();
    let mut outcome = outcome;
    // §6.6-4: the base fee rose above the max fee — recompute fees, rebuild, simulate once more.
    if matches!(
        outcome,
        SimOutcome::RpcError {
            code: -38_012 | -32_005
        }
    ) && let Ok(fees) = fresh_fees(&client, url, &context.chain)
    {
        let mut tx = context.tx.clone();
        tx.max_priority_fee_per_gas = fees.max_priority_fee_per_gas;
        tx.max_fee_per_gas = fees.max_fee_per_gas;
        if let Err(violation) = check_caps(&fees, tx.gas_limit, &job.chain.caps) {
            context.tx = tx;
            context.pre_warnings.push(violation.warning(&context.chain));
            result.kind = ResimKind::Blocked;
            result.prepared = rebuild(
                job,
                context,
                &SimResult::skipped(),
                clock.now_ms(),
                clock.now_unix_ms(),
            );
            return result;
        }
        context.tx = tx;
        outcome = simulate_bounded(
            transport,
            url,
            &context.tx,
            &account,
            true,
            job.limits.sim_wait_ms,
        );
    }
    let received = clock.now_ms();
    let sim = interpret(
        &context.chain,
        &context.tx,
        &account,
        &outcome,
        clock.now_unix_ms(),
    );
    if matches!(check, ChainCheck::Verified { .. }) {
        let budget = Budget {
            clock,
            started,
            limit: job.limits.budget_ms,
        };
        reclassify(&client, url, &account, &sim, &mut context, &budget);
    }
    let simulated = matches!(sim.binding(), SimulationBinding::Simulated { .. });
    result.prepared = rebuild(job, context, &sim, received, clock.now_unix_ms());
    result.kind = match &result.prepared {
        Some(prepared) if simulated && stable_equal(&job.request, &prepared.draft) => {
            ResimKind::Same
        }
        Some(_) if simulated => ResimKind::Changed,
        _ => ResimKind::NoResult,
    };
    result
}

fn collect_addresses(
    node: &yw_core::evm::eip712::TdNode,
    under_token: bool,
    addresses: &mut Vec<Address>,
    tokens: &mut Vec<Address>,
) {
    use yw_core::evm::eip712::{TdNode, TdValue};
    match node {
        TdNode::Value(TdValue::Address(address)) => {
            if !addresses.contains(address) {
                addresses.push(*address);
            }
            if under_token && !tokens.contains(address) {
                tokens.push(*address);
            }
        }
        TdNode::Value(_) => {}
        TdNode::Array(items) => {
            for item in items {
                collect_addresses(item, under_token, addresses, tokens);
            }
        }
        TdNode::Struct { fields, .. } => {
            for (name, item) in fields {
                collect_addresses(item, name == "token", addresses, tokens);
            }
        }
    }
}

/// Facts for a typed-data display (spec/03 §8.5 address classification, §2.5 token metadata of
/// `token` fields and of an EIP-2612/DAI verifying contract), at most 16 lookups each. When the
/// chain check does not verify, no lookup is made (the display shows unclassified addresses).
#[expect(
    clippy::too_many_arguments,
    reason = "the inputs of one typed-data preparation"
)]
#[must_use]
pub fn typed_facts(
    transport: &SharedTransport,
    cache: &mut ChainCache,
    chain: &super::ChainJob,
    account: &Address,
    typed: &yw_core::evm::eip712::DecodedTypedData,
    address_book: Vec<(Address, String)>,
    clock: &dyn Clock,
    retry_delay_ms: u64,
) -> (ChainFacts, ChainCheck) {
    use yw_core::evm::eip712::KnownSchema;
    let mut facts = ChainFacts {
        address_book,
        ..ChainFacts::default()
    };
    let client = RpcClient::new(&**transport);
    let url = &chain.url;
    let check = cache.ensure(&client, url, &chain.info, clock, retry_delay_ms);
    if !matches!(check, ChainCheck::Verified { .. }) {
        return (facts, check);
    }
    let mut addresses = vec![*account];
    let mut tokens = Vec::new();
    if let Some(contract) = typed.domain.verifying_contract {
        addresses.push(contract);
        if matches!(
            typed.schema,
            Some(KnownSchema::Eip2612Permit | KnownSchema::DaiPermit)
        ) {
            tokens.push(contract);
        }
    }
    collect_addresses(&typed.root, false, &mut addresses, &mut tokens);
    let started = clock.now_ms();
    let over = || clock.now_ms().saturating_sub(started) > PREPARE_TYPED_BUDGET_MS;
    for token in tokens.iter().take(MAX_FACT_LOOKUPS) {
        if over() {
            break;
        }
        let meta = token_meta(&client, url, &chain.info, token);
        facts.tokens.push((*token, meta));
    }
    for address in addresses.iter().take(MAX_FACT_LOOKUPS) {
        if over() {
            break;
        }
        if chain.info.label(address).is_some() || facts.code_of(address).is_some() {
            continue;
        }
        if let Ok(code) = rpc::code(&client, url, address) {
            let kind = CodeKind::from_code(&code);
            if address == account {
                facts.account_code = kind;
            }
            facts.code.push((*address, kind));
        }
    }
    (facts, check)
}

/// Lookup budget of a typed-data preparation (the spec/03 §1.4 30 s budget).
pub const PREPARE_TYPED_BUDGET_MS: u64 = super::PREPARE_BUDGET_MS;
