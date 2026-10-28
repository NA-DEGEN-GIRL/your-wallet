//! `sol::flow` (spec/07 §13–§14): the Solana pipelines that run on the `yw-rpc` worker — the
//! step-2 preview (SOL and allowlisted SPL), the step-5 pre-sign lookup, one broadcast/expiry
//! round, balances (SOL and the allowlisted tokens' derived ATAs) and the recovery scan. They
//! never touch keys: the intent is built and issued on the UI thread at first Ready display,
//! signing and journal commits happen on the key worker. Every pipeline checks `getGenesisHash`
//! against the selected cluster first (spec/07 §15.1).

use yw_core::slip10::SolKeySource;
use yw_core::sol::broadcast::{
    LoopState, Observation, Outcome, PendingTx, RoundTimes, SigStatus, decide, note_round, plan,
    wants_history,
};
use yw_core::sol::display::{SimSummary, SolBlock, SolPreviewFacts, SplPreviewFacts, intent_flags};
use yw_core::sol::fee::{
    FeeError, check_rpc_fee, choose_cu_price, max_fee, p75, template_cu_limit,
};
use yw_core::sol::intent::SolTransferIntent;
use yw_core::sol::message::{assemble_transaction, encode_message};
use yw_core::sol::pda::associated_token_address;
use yw_core::sol::recipient::{AccountClass, RecipientCheck, classify_account};
use yw_core::sol::rent::{
    check_rent0, check_rent165, check_sol_send, check_spl_send, send_max_amount,
    spl_send_max_amount,
};
use yw_core::sol::sign::{SOL_MAX_LVBH_AHEAD, SOL_MIN_LVBH_AHEAD};
use yw_core::sol::template::{SplAccounts, spl_entries};
use yw_core::sol::token::{TokenHolding, check_mint, classify_holding};
use yw_core::sol::{SolAddress, SolAsset, SolCluster, SolTransferCore, SplAllowEntry};
use yw_win::http::HttpsUrl;

use super::rpc::{self as sol_rpc, AccountData};
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
    /// §12.1 result (for SPL already checked with `check_recipient_for`: on-curve only).
    pub recipient: RecipientCheck,
    /// SOL or an allowlisted SPL token of `endpoint.cluster`.
    pub asset: SolAsset,
    /// Lamports or raw token units, `None` = send max.
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
    let cu_limit = template_cu_limit(job.asset);
    let core = SolTransferCore {
        from: job.from,
        to: job.recipient.to,
        asset: job.asset,
        amount: job.amount.unwrap_or(0),
        cu_limit,
        cu_price_micro: 0,
    };
    let max_fee = max_fee(cu_limit, 0).unwrap_or(0);
    let facts = SolPreviewFacts {
        account_label: job.account_label.clone(),
        recipient: job.recipient.clone(),
        recipient_account: AccountClass::SystemWallet,
        balance: 0,
        rent0: 0,
        rpc_fee: None,
        simulation: SimSummary::NoResult,
        spl: job.asset.spl().map(|_| SplPreviewFacts {
            token_balance: None,
            to_ata_exists: true,
            rent165: 0,
        }),
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
                cu_limit,
                job.source,
            ),
            facts,
            genesis,
        })),
    }
}

/// The SPL lookups of step 2 (spec/07 §13.1-2, §15.4): mint, `from_ata`, `to_ata`.
struct SplLookup {
    /// `from_ata` raw balance (`None`: missing or unusable).
    token_balance: Option<u64>,
    /// `to_ata` exists (any account at the address).
    to_ata_exists: bool,
    /// The blocks found (mint/ATA mismatch → `RpcAnomaly`, frozen accounts).
    blocks: Vec<SolBlock>,
    /// `from_ata`, `to_ata` (writable accounts for the priority-fee lookup).
    writable: [SolAddress; 2],
}

fn spl_lookup(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    job: &PreviewJob,
    entry: &'static SplAllowEntry,
) -> Result<SplLookup, RpcFailure> {
    let probe = SolTransferCore {
        from: job.from,
        to: job.recipient.to,
        asset: SolAsset::Spl(entry),
        amount: 1,
        cu_limit: 1,
        cu_price_micro: 0,
    };
    // The ATAs are local derivations (never RPC values); failing to derive is impossible in
    // practice and treated as malformed input.
    let accounts = SplAccounts::of(&probe).ok_or(RpcFailure::Malformed)?;
    let mint = sol_rpc::account_data(client, url, &entry.mint)?;
    let from_ata = sol_rpc::account_data(client, url, &accounts.from_ata)?;
    let to_ata = sol_rpc::account_data(client, url, &accounts.to_ata)?;
    let mut blocks = Vec::new();
    if check_mint(entry, mint.as_ref().map(AccountData::view)).is_err() {
        blocks.push(SolBlock::RpcAnomaly);
    }
    let token_balance =
        match classify_holding(entry, &job.from, from_ata.as_ref().map(AccountData::view)) {
            TokenHolding::Missing => None,
            TokenHolding::Active(amount) => Some(amount),
            TokenHolding::Frozen(amount) => {
                blocks.push(SolBlock::TokenAccountFrozen);
                Some(amount)
            }
            TokenHolding::Invalid => {
                blocks.push(SolBlock::RpcAnomaly);
                None
            }
        };
    let to_ata_exists = match classify_holding(
        entry,
        &job.recipient.to,
        to_ata.as_ref().map(AccountData::view),
    ) {
        TokenHolding::Missing => false,
        TokenHolding::Active(_) => true,
        TokenHolding::Frozen(_) | TokenHolding::Invalid => {
            blocks.push(SolBlock::RecipientTokenAccountUnusable);
            true
        }
    };
    Ok(SplLookup {
        token_balance,
        to_ata_exists,
        blocks,
        writable: [accounts.from_ata, accounts.to_ata],
    })
}

/// Step 2 (spec/07 §13.1): genesis → balance → recipient account → (SPL) mint, `from_ata`,
/// `to_ata` → rent (0, and 165 for SPL) → priority fees → preview blockhash →
/// `getFeeForMessage` (one retry with a new blockhash on `null`) → `simulateTransaction`
/// (reference). Approval-impossible conditions become `L01` blocks. Mint, decimals, token
/// program and ATAs come from the allowlist and local derivation; RPC data only blocks.
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
    let (account, recipient_lamports) = match sol_rpc::account_info(&client, url, &job.recipient.to)
    {
        Ok(info) => (
            classify_account(info.as_ref().map(|info| (&info.owner, info.executable))),
            info.map(|info| info.lamports),
        ),
        Err(failure) => return failed(job.job, failure),
    };
    let spl = match job.asset.spl() {
        Some(entry) => match spl_lookup(&client, url, job, entry) {
            Ok(lookup) => Some(lookup),
            Err(failure) => return failed(job.job, failure),
        },
        None => None,
    };
    let rent0 = match sol_rpc::minimum_rent(&client, url, 0) {
        Ok(rent0) => rent0,
        Err(failure) => return failed(job.job, failure),
    };
    let rent165 = if spl.is_some() {
        match sol_rpc::minimum_rent(&client, url, 165) {
            Ok(rent165) => rent165,
            Err(failure) => return failed(job.job, failure),
        }
    } else {
        0
    };
    let mut blocks: Vec<SolBlock> = spl
        .as_ref()
        .map(|lookup| lookup.blocks.clone())
        .unwrap_or_default();
    let rent_ok = check_rent0(rent0).is_ok() && (spl.is_none() || check_rent165(rent165).is_ok());
    if !rent_ok {
        blocks.push(SolBlock::RpcAnomaly);
    }
    // Reference only: a failing lookup leaves the price at 0 (no priority fee).
    let writable = match &spl {
        Some(lookup) => vec![job.from, lookup.writable[0], lookup.writable[1]],
        None => vec![job.from, job.recipient.to],
    };
    let fees = sol_rpc::prioritization_fees(&client, url, &writable).unwrap_or_default();
    let cu_limit = template_cu_limit(job.asset);
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
    let amount = match (job.amount, &spl) {
        (Some(amount), _) => amount,
        (None, None) => send_max_amount(balance, maximum).unwrap_or_else(|error| {
            blocks.push(SolBlock::Rent(error));
            0
        }),
        (None, Some(lookup)) => spl_send_max_amount(lookup.token_balance).unwrap_or_else(|error| {
            blocks.push(SolBlock::Rent(error));
            0
        }),
    };
    // What a SOL transfer leaves the sender (`Some(0)`: it empties the account).
    let mut sender_rest = None;
    if rent_ok && amount > 0 {
        let rule = match &spl {
            None => match check_sol_send(balance, amount, maximum, rent0, recipient_lamports) {
                Ok(rest) => {
                    sender_rest = Some(rest);
                    None
                }
                Err(error) => Some(error),
            },
            Some(lookup) => check_spl_send(
                balance,
                maximum,
                rent0,
                rent165,
                lookup.to_ata_exists,
                lookup.token_balance,
                amount,
            )
            .err(),
        };
        if let Some(error) = rule {
            blocks.push(SolBlock::Rent(error));
        }
    }
    match account {
        AccountClass::TokenAccount => blocks.push(SolBlock::RecipientIsTokenAccount),
        AccountClass::Program => blocks.push(SolBlock::RecipientIsProgram),
        AccountClass::Missing | AccountClass::SystemWallet | AccountClass::ProgramOwned => {}
    }
    let core = SolTransferCore {
        from: job.from,
        to: job.recipient.to,
        asset: job.asset,
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
    // A SOL transfer that leaves the sender exactly 0 is a "send max" for the cross-check
    // whatever the amount field said: a lower real fee would leave dust below rent0 (spec/07 §10).
    let empties_sender = spl.is_none() && (send_max || sender_rest == Some(0));
    if let Err(error) = check_rpc_fee(rpc_fee, maximum, empties_sender) {
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
                spl: spl.map(|lookup| SplPreviewFacts {
                    token_balance: lookup.token_balance,
                    to_ata_exists: lookup.to_ata_exists,
                    rent165,
                }),
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
    /// `lastValidBlockHeight` outside `h + 100..=h + 300`.
    RpcAnomaly,
}

/// Step 5 (spec/07 §13.1): genesis again, `getLatestBlockhash(finalized)`,
/// `getBlockHeight(finalized)` and the range check `h + SOL_MIN_LVBH_AHEAD ≤ lvbh ≤ h +
/// SOL_MAX_LVBH_AHEAD`. Returns `(blockhash, lastValidBlockHeight)`.
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
    if last_valid < height.saturating_add(SOL_MIN_LVBH_AHEAD)
        || last_valid > height.saturating_add(SOL_MAX_LVBH_AHEAD)
    {
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
    /// Monotonic ms (the [`Clock::now_ms`] clock) at which this session started tracking the
    /// record: its signing, or the loop's resumption after start or unlock (spec/07 §14.3).
    pub tracked_since_ms: u64,
    /// The UI's endpoint generation when the round started (echoed in [`TrackResult`]).
    pub generation: u64,
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
    /// [`TrackJob::generation`]: a result of an older generation is stale (the URL changed while
    /// it ran) and is discarded.
    pub generation: u64,
}

/// One round (spec/07 §14.2–§14.3): (first round of the session: send first) → status (history
/// off) → plan → re-send the same bytes and/or `getEpochInfo` (block height and slot of one view)
/// → history lookup (with its `context.slot`) only when that height is past
/// `lastValidBlockHeight` → [`decide`] with the wall clock and the monotonic time since
/// [`TrackJob::tracked_since_ms`]. No re-signing exists here.
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
        generation: job.generation,
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
    let programs = sol_rpc::programs_of(&job.tx);
    let now_ms = clock.now_ms();
    // The first round of the session (just signed, or resumed after start/unlock) sends before it
    // asks the status: a failing status lookup must not hold back the first broadcast. Sending
    // the same bytes again is harmless even if they already landed.
    let first = job.state.last_round_ms.is_none() && !job.state.stop_rebroadcast;
    let early = first.then(|| {
        result.sends = result.sends.saturating_add(1);
        sol_rpc::send_transaction(&client, url, &job.tx, &signature_text)
    });
    let status = match sol_rpc::signature_status(&client, url, &signature_text, false, programs) {
        Ok(status) => status,
        Err(failure) => {
            let mut state = job.state;
            note_round(&mut state, early, false, now_ms);
            result.state = state;
            result.outcome = Err(classify(failure));
            return result;
        }
    };
    let round = plan(&job.state, status, now_ms);
    let send = early.or_else(|| {
        round.send.then(|| {
            result.sends = result.sends.saturating_add(1);
            sol_rpc::send_transaction(&client, url, &job.tx, &signature_text)
        })
    });
    let chain = if round.height {
        sol_rpc::epoch_view(&client, url).ok()
    } else {
        None
    };
    let history = if status == SigStatus::NotFound && wants_history(&job.pending, chain) {
        sol_rpc::signature_history(&client, url, &signature_text, programs).ok()
    } else {
        None
    };
    let observation = Observation {
        status,
        send,
        chain,
        history,
    };
    let times = RoundTimes {
        now_ms,
        now_unix_ms: clock.now_unix_ms(),
        mono_elapsed: now_ms.saturating_sub(job.tracked_since_ms),
    };
    let mut state = job.state;
    result.outcome = Ok(decide(&job.pending, &mut state, &observation, &times));
    result.state = state;
    result
}

/// The balances of one account: lamports and, for each allowlisted token of the cluster, what
/// its derived ATA holds (unknown tokens and other token accounts are never asked for, so they
/// are never shown; spec/07 §12.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolBalanceRow {
    /// Account.
    pub address: SolAddress,
    /// Lamports (finalized).
    pub lamports: u64,
    /// Allowlist order of the cluster.
    pub tokens: Vec<(&'static SplAllowEntry, TokenHolding)>,
}

/// `getAccountInfo(ATA(wallet, entry))` with the raw data, classified (spec/07 §15.4). The ATA
/// is derived locally; decimals are never read from it.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn token_holding(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    wallet: &SolAddress,
    entry: &'static SplAllowEntry,
) -> Result<TokenHolding, RpcFailure> {
    let Ok((ata, _)) = associated_token_address(wallet, &entry.token_program, &entry.mint) else {
        return Ok(TokenHolding::Invalid);
    };
    let account = sol_rpc::account_data(client, url, &ata)?;
    Ok(classify_holding(
        entry,
        wallet,
        account.as_ref().map(AccountData::view),
    ))
}

/// The allowlisted token holdings of `wallet` on `cluster`, in allowlist order.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn token_holdings(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    cluster: SolCluster,
    wallet: &SolAddress,
) -> Result<Vec<(&'static SplAllowEntry, TokenHolding)>, RpcFailure> {
    spl_entries(cluster)
        .map(|entry| token_holding(client, url, wallet, entry).map(|holding| (entry, holding)))
        .collect()
}

/// Balances (SOL and allowlisted tokens) of `accounts` after the genesis check.
///
/// # Errors
///
/// The classified failure, or E-RPC-006 for a genesis mismatch.
pub fn balances(
    transport: &dyn Transport,
    endpoint: &SolEndpoint,
    accounts: &[SolAddress],
) -> Result<Vec<SolBalanceRow>, ErrorCode> {
    let client = RpcClient::new(transport);
    if !check_genesis(&client, endpoint)? {
        return Err(ErrorCode::Rpc006);
    }
    accounts
        .iter()
        .map(|account| {
            let lamports = sol_rpc::balance(&client, &endpoint.url, account).map_err(classify)?;
            let tokens = token_holdings(&client, &endpoint.url, endpoint.cluster, account)
                .map_err(classify)?;
            Ok(SolBalanceRow {
                address: *account,
                lamports,
                tokens,
            })
        })
        .collect()
}
