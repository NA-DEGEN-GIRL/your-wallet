//! `sol::flow` (spec/07 §13–§14): the Solana pipelines that run on the `yw-rpc` worker — the
//! step-2 preview, the step-5 pre-sign lookup, one broadcast/expiry round, balances and the
//! recovery scan. They never touch keys: the intent is built and issued on the UI thread at
//! first Ready display, signing and journal commits happen on the key worker. Every pipeline
//! checks `getGenesisHash` against the selected cluster first (spec/07 §15.1).

use yw_core::slip10::SolKeySource;
use yw_core::sol::broadcast::{
    LoopState, Observation, Outcome, PendingTx, SigStatus, decide, plan, wants_history,
};
use yw_core::sol::display::{SimSummary, SolBlock, SolPreviewFacts, intent_flags};
use yw_core::sol::fee::{
    FeeError, SOL_TRANSFER_CU_LIMIT, check_rpc_fee, choose_cu_price, max_fee, p75,
};
use yw_core::sol::intent::SolTransferIntent;
use yw_core::sol::message::{assemble_transaction, encode_message};
use yw_core::sol::recipient::{AccountClass, RecipientCheck, classify_account};
use yw_core::sol::rent::{check_rent0, check_sol_send, send_max_amount};
use yw_core::sol::sign::SOL_MAX_LVBH_AHEAD;
use yw_core::sol::{SolAddress, SolAsset, SolCluster, SolTransferCore};
use yw_win::http::HttpsUrl;

use super::rpc as sol_rpc;
use crate::errors::ErrorCode;
use crate::flow::evm::Clock;
use crate::rpc::{RpcClient, RpcFailure, Transport, classify};

/// A cluster and its endpoint URL (secret, D13).
#[derive(Clone)]
pub struct SolEndpoint {
    /// Cluster.
    pub cluster: SolCluster,
    /// `rpc:solana:<cluster>` URL.
    pub url: HttpsUrl,
}

impl core::fmt::Debug for SolEndpoint {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "SolEndpoint({})", self.cluster.network_id())
    }
}

/// Retryable RPC failures (spec/04 §3.5: E-RPC-001·002·004).
#[must_use]
pub const fn retryable(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::Rpc001 | ErrorCode::Rpc002 | ErrorCode::Rpc004
    )
}

/// `getGenesisHash` against the cluster: `Ok(true)` match, `Ok(false)` mismatch.
///
/// # Errors
///
/// The classified transport/RPC failure.
pub fn check_genesis(client: &RpcClient<'_>, endpoint: &SolEndpoint) -> Result<bool, ErrorCode> {
    sol_rpc::genesis_hash(client, &endpoint.url)
        .map(|genesis| genesis == endpoint.cluster.genesis())
        .map_err(classify)
}

/// Step 2 input (spec/07 §13.1): the local checks are already done on the UI thread.
#[derive(Clone, Debug)]
pub struct PreviewJob {
    /// UI job id.
    pub job: u64,
    /// Endpoint.
    pub endpoint: SolEndpoint,
    /// Key source of `from`.
    pub source: SolKeySource,
    /// Sender.
    pub from: SolAddress,
    /// Sender label (meta).
    pub account_label: String,
    /// §12.1 result.
    pub recipient: RecipientCheck,
    /// Lamports, `None` = send max.
    pub amount: Option<u64>,
    /// Settings `max_fee_lamports`.
    pub fee_cap: u64,
    /// Settings `max_cu_price_micro`.
    pub max_cu_price: u64,
    /// A `Pending` record of the same (cluster, from) exists.
    pub pending_exists: bool,
    /// A new `Pending` record fits after clean-up (spec/07 §14.1).
    pub journal_room: bool,
}

/// What the preview found: everything of the intent except id and display time, plus the facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolPrepared {
    /// Cluster.
    pub cluster: SolCluster,
    /// Key source.
    pub source: SolKeySource,
    /// Message content.
    pub core: SolTransferCore,
    /// Maximum fee of `core`.
    pub max_fee: u64,
    /// User cap.
    pub fee_cap: u64,
    /// Warning flags.
    pub flags: u8,
    /// Shown facts and `L01` blocks.
    pub facts: SolPreviewFacts,
    /// `getGenesisHash` value.
    pub genesis: [u8; 32],
}

impl SolPrepared {
    /// The intent issued at first Ready display.
    #[must_use]
    pub const fn intent(&self, id: [u8; 16], created_at_ms: u64) -> SolTransferIntent {
        SolTransferIntent {
            id,
            cluster: self.cluster,
            source: self.source,
            core: self.core,
            max_fee_lamports: self.max_fee,
            fee_cap_lamports: self.fee_cap,
            flags: self.flags,
            created_at_ms,
        }
    }
}

/// Preview outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreviewOutcome {
    /// Ready (possibly with `L01` blocks).
    Ready(Box<SolPrepared>),
    /// A required lookup failed: no request can be built (spec/04 §3.5 `Failed`).
    Failed {
        /// Code.
        code: ErrorCode,
        /// `다시 시도` offered.
        retryable: bool,
    },
}

/// Preview result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewResult {
    /// UI job id.
    pub job: u64,
    /// Outcome.
    pub outcome: PreviewOutcome,
}

fn failed(job: u64, failure: RpcFailure) -> PreviewResult {
    let code = classify(failure);
    PreviewResult {
        job,
        outcome: PreviewOutcome::Failed {
            code,
            retryable: retryable(code),
        },
    }
}

fn blocked(job: &PreviewJob, genesis: [u8; 32], block: SolBlock) -> PreviewResult {
    let core = SolTransferCore {
        from: job.from,
        to: job.recipient.to,
        asset: SolAsset::Sol,
        amount: job.amount.unwrap_or(0),
        cu_limit: SOL_TRANSFER_CU_LIMIT,
        cu_price_micro: 0,
    };
    let max_fee = max_fee(SOL_TRANSFER_CU_LIMIT, 0).unwrap_or(0);
    let facts = SolPreviewFacts {
        account_label: job.account_label.clone(),
        recipient: job.recipient.clone(),
        recipient_account: AccountClass::SystemWallet,
        balance: 0,
        rent0: 0,
        rpc_fee: None,
        simulation: SimSummary::NoResult,
        blocks: vec![block],
    };
    PreviewResult {
        job: job.job,
        outcome: PreviewOutcome::Ready(Box::new(SolPrepared {
            cluster: job.endpoint.cluster,
            source: job.source,
            core,
            max_fee,
            fee_cap: job.fee_cap,
            flags: intent_flags(
                job.amount.is_none(),
                &job.recipient,
                AccountClass::SystemWallet,
                SimSummary::NoResult,
                SOL_TRANSFER_CU_LIMIT,
                job.source,
            ),
            facts,
            genesis,
        })),
    }
}

/// Step 2 (spec/07 §13.1): genesis → balance → recipient account → rent → priority fees →
/// preview blockhash → `getFeeForMessage` (one retry with a new blockhash on `null`) →
/// `simulateTransaction` (reference). Approval-impossible conditions become `L01` blocks.
#[must_use]
#[expect(
    clippy::too_many_lines,
    reason = "the spec/07 §13.1-2 call order in one place"
)]
pub fn preview(transport: &dyn Transport, job: &PreviewJob) -> PreviewResult {
    let client = RpcClient::new(transport);
    let url = &job.endpoint.url;
    let genesis = match sol_rpc::genesis_hash(&client, url) {
        Ok(genesis) => genesis,
        Err(failure) => return failed(job.job, failure),
    };
    if genesis != job.endpoint.cluster.genesis() {
        return blocked(job, genesis, SolBlock::ClusterMismatch);
    }
    let balance = match sol_rpc::balance(&client, url, &job.from) {
        Ok(balance) => balance,
        Err(failure) => return failed(job.job, failure),
    };
    let account = match sol_rpc::account_info(&client, url, &job.recipient.to) {
        Ok(info) => classify_account(info.as_ref().map(|info| (&info.owner, info.executable))),
        Err(failure) => return failed(job.job, failure),
    };
    let rent0 = match sol_rpc::minimum_rent(&client, url, 0) {
        Ok(rent0) => rent0,
        Err(failure) => return failed(job.job, failure),
    };
    let mut blocks: Vec<SolBlock> = Vec::new();
    let rent_ok = check_rent0(rent0).is_ok();
    if !rent_ok {
        blocks.push(SolBlock::RpcAnomaly);
    }
    // Reference only: a failing lookup leaves the price at 0 (no priority fee).
    let fees = sol_rpc::prioritization_fees(&client, url, &[job.from, job.recipient.to])
        .unwrap_or_default();
    let cu_limit = SOL_TRANSFER_CU_LIMIT;
    let price = choose_cu_price(p75(&fees), job.max_cu_price, job.fee_cap, cu_limit);
    let maximum = match max_fee(cu_limit, price) {
        Ok(fee) if fee <= job.fee_cap => fee,
        Ok(_) => {
            blocks.push(SolBlock::Fee(FeeError::AboveCap));
            max_fee(cu_limit, 0).unwrap_or(0)
        }
        Err(error) => {
            blocks.push(SolBlock::Fee(error));
            max_fee(cu_limit, 0).unwrap_or(0)
        }
    };
    let send_max = job.amount.is_none();
    let amount = match job.amount {
        Some(amount) => amount,
        None => send_max_amount(balance, maximum).unwrap_or_else(|error| {
            blocks.push(SolBlock::Rent(error));
            0
        }),
    };
    let exists = account != AccountClass::Missing;
    if rent_ok
        && amount > 0
        && let Err(error) = check_sol_send(balance, amount, maximum, rent0, exists)
    {
        blocks.push(SolBlock::Rent(error));
    }
    match account {
        AccountClass::TokenAccount => blocks.push(SolBlock::RecipientIsTokenAccount),
        AccountClass::Program => blocks.push(SolBlock::RecipientIsProgram),
        AccountClass::Missing | AccountClass::SystemWallet | AccountClass::ProgramOwned => {}
    }
    let core = SolTransferCore {
        from: job.from,
        to: job.recipient.to,
        asset: SolAsset::Sol,
        amount,
        cu_limit,
        cu_price_micro: price,
    };
    let mut rpc_fee = None;
    for _ in 0..2 {
        let blockhash = match sol_rpc::latest_blockhash(&client, url) {
            Ok((blockhash, _)) => blockhash,
            Err(failure) => return failed(job.job, failure),
        };
        match sol_rpc::fee_for_message(&client, url, &encode_message(&core, &blockhash)) {
            Ok(Some(fee)) => {
                rpc_fee = Some(fee);
                break;
            }
            Ok(None) => {}
            Err(failure) => return failed(job.job, failure),
        }
    }
    if let Err(error) = check_rpc_fee(rpc_fee, maximum, send_max) {
        blocks.push(SolBlock::Fee(error));
    }
    let simulation = sol_rpc::simulate(
        &client,
        url,
        &assemble_transaction(&[0; 64], &encode_message(&core, &[0; 32])),
    );
    if job.pending_exists {
        blocks.push(SolBlock::PendingExists);
    }
    if !job.journal_room {
        blocks.push(SolBlock::JournalFull);
    }
    let flags = intent_flags(
        send_max,
        &job.recipient,
        account,
        simulation,
        cu_limit,
        job.source,
    );
    PreviewResult {
        job: job.job,
        outcome: PreviewOutcome::Ready(Box::new(SolPrepared {
            cluster: job.endpoint.cluster,
            source: job.source,
            core,
            max_fee: maximum,
            fee_cap: job.fee_cap,
            flags,
            facts: SolPreviewFacts {
                account_label: job.account_label.clone(),
                recipient: job.recipient.clone(),
                recipient_account: account,
                balance,
                rent0,
                rpc_fee,
                simulation,
                blocks,
            },
            genesis,
        })),
    }
}

/// Why the step-5 lookup stopped (nothing signed; the approval is consumed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreSignError {
    /// Transport/RPC failure.
    Rpc(ErrorCode),
    /// `getGenesisHash` differs.
    ClusterMismatch,
    /// `lastValidBlockHeight` outside `h..=h + 300`.
    RpcAnomaly,
}

/// Step 5 (spec/07 §13.1): genesis again, `getLatestBlockhash(finalized)`,
/// `getBlockHeight(finalized)` and the range check. Returns `(blockhash, lastValidBlockHeight)`.
///
/// # Errors
///
/// [`PreSignError`].
pub fn pre_sign(
    transport: &dyn Transport,
    endpoint: &SolEndpoint,
) -> Result<([u8; 32], u64), PreSignError> {
    let client = RpcClient::new(transport);
    if !check_genesis(&client, endpoint).map_err(PreSignError::Rpc)? {
        return Err(PreSignError::ClusterMismatch);
    }
    let (blockhash, last_valid) = sol_rpc::latest_blockhash(&client, &endpoint.url)
        .map_err(|failure| PreSignError::Rpc(classify(failure)))?;
    let height = sol_rpc::block_height(&client, &endpoint.url)
        .map_err(|failure| PreSignError::Rpc(classify(failure)))?;
    if last_valid < height || last_valid > height.saturating_add(SOL_MAX_LVBH_AHEAD) {
        return Err(PreSignError::RpcAnomaly);
    }
    Ok((blockhash, last_valid))
}

/// One broadcast-loop round of a `Pending` record.
#[derive(Clone, Debug)]
pub struct TrackJob {
    /// Endpoint.
    pub endpoint: SolEndpoint,
    /// Signature.
    pub signature: [u8; 64],
    /// Signed bytes (re-sent unchanged).
    pub tx: Vec<u8>,
    /// Journal timing.
    pub pending: PendingTx,
    /// In-memory loop state.
    pub state: LoopState,
    /// Check `getGenesisHash` first (first round after start/unlock/URL change).
    pub check_genesis: bool,
}

/// A round's result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrackResult {
    /// Signature (the record key).
    pub signature: [u8; 64],
    /// Updated loop state.
    pub state: LoopState,
    /// The decision, or the round's failure (state kept, retried next period).
    pub outcome: Result<Outcome, ErrorCode>,
    /// `Some(false)`: genesis mismatch (tracking stops until restart or URL change).
    pub genesis_ok: Option<bool>,
    /// `sendTransaction` calls made this round (tests: never more than one, same bytes).
    pub sends: u32,
}

/// One round (spec/07 §14.2–§14.3): status (history off) → plan → re-send the same bytes and/or
/// `getBlockHeight` → history lookup only when the height is past `lastValidBlockHeight` →
/// [`decide`]. No re-signing exists here.
#[must_use]
pub fn track_round(transport: &dyn Transport, job: &TrackJob, clock: &dyn Clock) -> TrackResult {
    let client = RpcClient::new(transport);
    let url = &job.endpoint.url;
    let mut result = TrackResult {
        signature: job.signature,
        state: job.state,
        outcome: Ok(Outcome::Pending { notice: false }),
        genesis_ok: None,
        sends: 0,
    };
    if job.check_genesis {
        match check_genesis(&client, &job.endpoint) {
            Ok(true) => result.genesis_ok = Some(true),
            Ok(false) => {
                result.genesis_ok = Some(false);
                result.outcome = Err(ErrorCode::Rpc006);
                return result;
            }
            Err(code) => {
                result.outcome = Err(code);
                return result;
            }
        }
    }
    let signature_text = yw_core::codec::base58::base58_encode(&job.signature);
    let status = match sol_rpc::signature_status(&client, url, &signature_text, false) {
        Ok(status) => status,
        Err(failure) => {
            result.outcome = Err(classify(failure));
            return result;
        }
    };
    let now_ms = clock.now_ms();
    let round = plan(&job.state, status, now_ms);
    let send = round.send.then(|| {
        result.sends = result.sends.saturating_add(1);
        sol_rpc::send_transaction(&client, url, &job.tx, &signature_text)
    });
    let height = if round.height {
        sol_rpc::block_height(&client, url).ok()
    } else {
        None
    };
    let history = if status == SigStatus::NotFound && wants_history(&job.pending, height) {
        sol_rpc::signature_status(&client, url, &signature_text, true).ok()
    } else {
        None
    };
    let observation = Observation {
        status,
        send,
        height,
        history,
    };
    let mut state = job.state;
    result.outcome = Ok(decide(
        &job.pending,
        &mut state,
        &observation,
        now_ms,
        clock.now_unix_ms(),
    ));
    result.state = state;
    result
}

/// Balances of `accounts` after the genesis check.
///
/// # Errors
///
/// The classified failure, or E-RPC-006 for a genesis mismatch.
pub fn balances(
    transport: &dyn Transport,
    endpoint: &SolEndpoint,
    accounts: &[SolAddress],
) -> Result<Vec<(SolAddress, u64)>, ErrorCode> {
    let client = RpcClient::new(transport);
    if !check_genesis(&client, endpoint)? {
        return Err(ErrorCode::Rpc006);
    }
    accounts
        .iter()
        .map(|account| {
            sol_rpc::balance(&client, &endpoint.url, account)
                .map(|balance| (*account, balance))
                .map_err(classify)
        })
        .collect()
}
