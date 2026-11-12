//! `sol::flow` (spec/07 §13–§14): the Solana pipelines that run on the `yw-rpc` worker — the
//! step-2 preview (SOL and allowlisted SPL), the step-5 pre-sign lookup, the dApp transaction
//! preview and pre-sign check (spec/07 §20), one broadcast/expiry round, balances (SOL and the
//! allowlisted tokens' derived ATAs) and the recovery scan. They never touch keys: the intent is
//! built and issued on the UI thread at first Ready display, signing and journal commits happen
//! on the key worker. Every pipeline checks `getGenesisHash` against the selected cluster first
//! (spec/07 §15.1).

use yw_core::slip10::SolKeySource;
use yw_core::sol::address::TOKEN_2022_PROGRAM;
use yw_core::sol::broadcast::{
    LoopState, Observation, Outcome, PendingTx, RoundTimes, SigStatus, decide, err, note_round,
    plan, wants_history,
};
use yw_core::sol::dapp::alt::{
    LOOKUP_TABLE_MAX_DATA, SOL_DAPP_MAX_TABLES, full_keys, lookup_tables, parse_lookup_table,
    resolve,
};
use yw_core::sol::dapp::decode::decode_message;
use yw_core::sol::dapp::diff::watch_set;
use yw_core::sol::dapp::{
    AccountSnapshot, AltError, DecodedIx, KeyRole, LookupTable, PreSignCheck, ResolvedKeys,
    SolTxFacts, SolTxItemFacts, SolTxMessage, SolWireTx, parse_wire_tx,
};
use yw_core::sol::display::{SimSummary, SolBlock, SolPreviewFacts, SplPreviewFacts, intent_flags};
use yw_core::sol::fee::{
    FeeError, check_rpc_fee, choose_cu_price, max_fee, p75, template_cu_limit,
};
use yw_core::sol::intent::SolTransferIntent;
use yw_core::sol::message::{assemble_transaction, encode_message};
use yw_core::sol::pda::associated_token_address;
use yw_core::sol::recipient::{AccountClass, KnownAddress, RecipientCheck, classify_account};
use yw_core::sol::rent::{
    check_rent0, check_rent165, check_sol_send, check_spl_send, send_max_amount,
    spl_send_max_amount,
};
use yw_core::sol::sign::{SOL_MAX_LVBH_AHEAD, SOL_MIN_LVBH_AHEAD};
use yw_core::sol::template::{SplAccounts, spl_entries};
use yw_core::sol::token::{MintView, TokenHolding, check_mint, classify_holding, parse_mint_any};
use yw_core::sol::{SolAddress, SolAsset, SolCluster, SolTransferCore, SplAllowEntry};
use yw_win::http::HttpsUrl;

use super::rpc::{self as sol_rpc, AccountData, SendConfig};
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
    // A blocked fee falls back to price 0 so the core and its maximum fee still agree (the
    // approval request refuses an intent whose maximum fee is not the formula's value).
    let (price, maximum) = match max_fee(cu_limit, price) {
        Ok(fee) if fee <= job.fee_cap => (price, fee),
        Ok(_) => {
            blocks.push(SolBlock::Fee(FeeError::AboveCap));
            (0, max_fee(cu_limit, 0).unwrap_or(0))
        }
        Err(error) => {
            blocks.push(SolBlock::Fee(error));
            (0, max_fee(cu_limit, 0).unwrap_or(0))
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
    /// A dApp send: `isBlockhashValid(processed)` says the transaction's blockhash is no longer
    /// valid (spec/07 §20.10).
    BlockhashExpired,
    /// A dApp send: the lookup tables no longer resolve to the approved addresses (or not at
    /// all).
    TablesChanged,
}

/// Step 5 (spec/07 §13.1): genesis again, `getLatestBlockhash(confirmed)`,
/// `getBlockHeight(confirmed)` and the range check `h + SOL_MIN_LVBH_AHEAD ≤ lvbh ≤ h +
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

/// Budget of the dApp preview's reference calls (blockhash check, fee, simulation): later
/// transactions keep no result (X09).
pub const DAPP_PREVIEW_BUDGET_MS: u64 = 30_000;
/// Most writable accounts whose pre-state is read for one transaction.
pub const DAPP_MAX_PRE_STATE: usize = 128;
/// Pre-state `dataSlice` length: a token account and the Token-2022 account-type byte
/// (`data[165]`).
pub const DAPP_PRE_STATE_SLICE: u64 = 166;
/// Largest mint read whole. A Token-2022 account named as a mint that is longer (or does not
/// parse) is unread: X17 and X12 as if it had every extension (spec/07 §20.7 ④).
pub const DAPP_MINT_MAX_DATA: usize = 16_384;

/// `dataSlice` of an account read bounded by `max` bytes: one byte past it, so a longer account
/// is seen as such (`truncated`) and a `getMultipleAccounts` chunk of a site's large accounts
/// stays far below [`sol_rpc::DAPP_MAX_RESPONSE`] instead of failing the whole request.
fn slice_past(max: usize) -> (u64, u64) {
    (
        0,
        u64::try_from(max).map_or(u64::MAX, |max| max.saturating_add(1)),
    )
}

/// The dApp preview input (spec/07 §20.7): the request's transactions, already validated by the
/// params check.
#[derive(Clone, Debug)]
pub struct DappPreviewJob {
    /// UI job id.
    pub job: u64,
    /// Endpoint.
    pub endpoint: SolEndpoint,
    /// The signing account.
    pub wallet: SolAddress,
    /// The wire transactions, in request order.
    pub txs: Vec<Vec<u8>>,
}

/// What the RPC said about a dApp request: the RPC part of [`SolTxFacts`] (the UI thread adds
/// the known addresses and the fee cap).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DappPreview {
    /// One entry per transaction, in request order.
    pub items: Vec<SolTxItemFacts>,
    /// The mints read (Token-2022 extensions, decimals).
    pub mints: Vec<(SolAddress, MintView)>,
    /// Token-2022 accounts named as mints that were over [`DAPP_MINT_MAX_DATA`] or did not parse.
    pub unread_mints: Vec<SolAddress>,
}

impl DappPreview {
    /// The builder's facts with the address book, own accounts and sent history and the user's
    /// fee cap.
    #[must_use]
    pub fn into_facts(self, known: Vec<KnownAddress>, fee_cap: u64) -> SolTxFacts {
        SolTxFacts {
            items: self.items,
            mints: self.mints,
            unread_mints: self.unread_mints,
            known,
            fee_cap,
        }
    }
}

/// A lookup table account as read: the table, or why it is not one.
type TableRead = (SolAddress, Result<LookupTable, AltError>);

/// `getMultipleAccounts` of `tables` (`dataSlice` one byte past the table maximum: a longer
/// account is that transaction's `NotTable`) → the lowest context slot and each table parsed.
fn read_tables(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    tables: &[SolAddress],
) -> Result<(u64, Vec<TableRead>), RpcFailure> {
    if tables.is_empty() {
        return Ok((0, Vec::new()));
    }
    let (slot, accounts) = sol_rpc::multiple_accounts(
        client,
        url,
        tables,
        LOOKUP_TABLE_MAX_DATA,
        Some(slice_past(LOOKUP_TABLE_MAX_DATA)),
        None,
    )?;
    let read = tables
        .iter()
        .zip(accounts)
        .map(|(table, account)| {
            let parsed = match account {
                None => Err(AltError::Missing(*table)),
                Some(account) => parse_lookup_table(&account.owner, &account.data)
                    .ok_or(AltError::NotTable(*table)),
            };
            (*table, parsed)
        })
        .collect();
    Ok((slot, read))
}

/// The tables `message` looks up, from `read`. A table that was not read (past
/// [`SOL_DAPP_MAX_TABLES`] in one request) counts as missing.
fn message_tables(
    message: &SolTxMessage,
    read: &[TableRead],
) -> Result<Vec<(SolAddress, LookupTable)>, AltError> {
    lookup_tables(message)
        .into_iter()
        .map(
            |table| match read.iter().find(|(address, _)| *address == table) {
                Some((_, Ok(parsed))) => Ok((table, parsed.clone())),
                Some((_, Err(error))) => Err(*error),
                None => Err(AltError::Missing(table)),
            },
        )
        .collect()
}

fn snapshot(account: AccountData) -> AccountSnapshot {
    AccountSnapshot {
        owner: account.owner,
        lamports: account.lamports,
        data: account.data,
    }
}

/// One parsed transaction of the request with what the required lookups found.
struct DappItem<'a> {
    tx: &'a [u8],
    wire: SolWireTx,
    tables: Result<(u64, Vec<(SolAddress, LookupTable)>), AltError>,
    roles: Vec<(SolAddress, KeyRole)>,
    writable: Vec<SolAddress>,
    pre: Vec<(SolAddress, Option<AccountSnapshot>)>,
}

/// Facts of a transaction the RPC could not be asked about (it does not parse, which the params
/// check excludes; the builder refuses it).
fn unasked() -> SolTxItemFacts {
    SolTxItemFacts {
        tables: Ok((0, Vec::new())),
        pre: Vec::new(),
        post: None,
        sim: SimSummary::NoResult,
        sim_replaced_blockhash: false,
        rpc_fee: None,
        blockhash_valid: None,
    }
}

/// The dApp transaction preview (spec/07 §20.7), in this order: genesis → the request's lookup
/// tables (at most [`SOL_DAPP_MAX_TABLES`], resolved per transaction at the answer's slot) →
/// per transaction the pre-state of its writable accounts (`dataSlice 0/166`, at most
/// [`DAPP_MAX_PRE_STATE`]) → the mints its token instructions name or its token accounts hold
/// (`dataSlice` one byte past [`DAPP_MINT_MAX_DATA`]; a Token-2022 account over it or not
/// parsing is unread, which the builder treats as every extension: X17, X12) →
/// then, within [`DAPP_PREVIEW_BUDGET_MS`], per transaction `isBlockhashValid(processed)` (not
/// for a durable nonce), `getFeeForMessage` and `simulateTransaction` with the watched accounts
/// (`replaceRecentBlockhash:false`; once more with `true` on `BlockhashNotFound`, never for a
/// durable nonce). Tables, pre-state and mints are required (a failure fails the preview); an
/// unresolvable table is that transaction's X01. The rest is reference: a failure or the spent
/// budget leaves `None` / `NoResult` (X09).
///
/// # Errors
///
/// The classified transport/RPC failure of a required call, or E-RPC-006 for a genesis
/// mismatch.
#[expect(
    clippy::too_many_lines,
    reason = "the spec/07 §20.7 call order in one place"
)]
pub fn dapp_preview(
    transport: &dyn Transport,
    job: &DappPreviewJob,
    clock: &dyn Clock,
) -> Result<DappPreview, ErrorCode> {
    let client = RpcClient::new(transport);
    let url = &job.endpoint.url;
    let started = clock.now_ms();
    if !check_genesis(&client, &job.endpoint)? {
        return Err(ErrorCode::Rpc006);
    }
    let parsed: Vec<Option<(&[u8], SolWireTx)>> = job
        .txs
        .iter()
        .map(|tx| parse_wire_tx(tx).ok().map(|wire| (tx.as_slice(), wire)))
        .collect();
    let mut tables: Vec<SolAddress> = Vec::new();
    for (_, wire) in parsed.iter().flatten() {
        for table in lookup_tables(&wire.message) {
            if tables.len() < SOL_DAPP_MAX_TABLES && !tables.contains(&table) {
                tables.push(table);
            }
        }
    }
    let (table_slot, table_read) = read_tables(&client, url, &tables).map_err(classify)?;
    let mut items: Vec<Option<DappItem>> = Vec::with_capacity(parsed.len());
    for entry in parsed {
        let Some((tx, wire)) = entry else {
            items.push(None);
            continue;
        };
        let message = &wire.message;
        let tables = message_tables(message, &table_read).map(|list| (table_slot, list));
        let loaded = if message.lookups.is_empty() {
            Some(ResolvedKeys::default())
        } else {
            tables
                .as_ref()
                .ok()
                .and_then(|(slot, list)| resolve(message, list, *slot).ok())
        };
        let roles = full_keys(message, loaded.as_ref());
        let writable: Vec<SolAddress> = roles
            .iter()
            .filter(|(_, role)| role.writable)
            .map(|(key, _)| *key)
            .take(DAPP_MAX_PRE_STATE)
            .collect();
        let pre = if writable.is_empty() {
            Vec::new()
        } else {
            let (_, accounts) = sol_rpc::multiple_accounts(
                &client,
                url,
                &writable,
                usize::try_from(DAPP_PRE_STATE_SLICE).unwrap_or(usize::MAX),
                Some((0, DAPP_PRE_STATE_SLICE)),
                None,
            )
            .map_err(classify)?;
            writable
                .iter()
                .zip(accounts)
                .map(|(key, account)| (*key, account.map(snapshot)))
                .collect()
        };
        items.push(Some(DappItem {
            tx,
            wire,
            tables,
            roles,
            writable,
            pre,
        }));
    }
    // Mints: named by token and ATA instructions, or held by a pre-state token account.
    let mut mint_keys: Vec<SolAddress> = Vec::new();
    for item in items.iter().flatten() {
        let named = decode_message(&item.wire.message, &item.roles)
            .iter()
            .filter_map(DecodedIx::named_mint)
            .collect::<Vec<_>>();
        let held = item
            .pre
            .iter()
            .filter_map(|(_, snapshot)| snapshot.as_ref()?.token().map(|view| view.mint));
        for mint in named.into_iter().chain(held) {
            if !mint_keys.contains(&mint) {
                mint_keys.push(mint);
            }
        }
    }
    let mut mints = Vec::new();
    let mut unread_mints = Vec::new();
    if !mint_keys.is_empty() {
        let (_, accounts) = sol_rpc::multiple_accounts(
            &client,
            url,
            &mint_keys,
            DAPP_MINT_MAX_DATA,
            Some(slice_past(DAPP_MINT_MAX_DATA)),
            None,
        )
        .map_err(classify)?;
        for (mint, account) in mint_keys.iter().zip(accounts) {
            let Some(account) = account else {
                continue;
            };
            // A missing account or one of another program is no mint (the token instruction
            // fails); only Token-2022 can carry extensions, so its unread accounts fail closed.
            match parse_mint_any(&account.owner, &account.data) {
                Some(view) => mints.push((*mint, view)),
                None if account.owner == TOKEN_2022_PROGRAM => unread_mints.push(*mint),
                None => {}
            }
        }
    }
    // References within the budget.
    let in_budget = || clock.now_ms().saturating_sub(started) < DAPP_PREVIEW_BUDGET_MS;
    let mut checked: Vec<([u8; 32], bool)> = Vec::new();
    let mut facts = Vec::with_capacity(items.len());
    for item in items {
        let Some(item) = item else {
            facts.push(unasked());
            continue;
        };
        let nonce = item.wire.message.durable_nonce().is_some();
        let blockhash = item.wire.message.blockhash;
        let blockhash_valid = if nonce {
            None
        } else if let Some((_, valid)) = checked.iter().find(|(hash, _)| *hash == blockhash) {
            Some(*valid)
        } else if in_budget() {
            sol_rpc::blockhash_valid(&client, url, &blockhash)
                .ok()
                .map(|(valid, _)| {
                    checked.push((blockhash, valid));
                    valid
                })
        } else {
            None
        };
        let rpc_fee = if in_budget() {
            sol_rpc::fee_for_message(&client, url, &item.wire.message_bytes)
                .ok()
                .flatten()
        } else {
            None
        };
        let keys: Vec<SolAddress> = item.roles.iter().map(|(key, _)| *key).collect();
        let watch = watch_set(&job.wallet, &keys, &item.writable, &item.pre);
        let mut sim = None;
        let mut replaced = false;
        if in_budget() {
            let first = sol_rpc::simulate_dapp(&client, url, item.tx, &watch, false);
            let stale = matches!(
                first.summary,
                SimSummary::Failed {
                    err: err::BLOCKHASH_NOT_FOUND,
                    ..
                }
            );
            sim = Some(first);
            if stale && !nonce && in_budget() {
                sim = Some(sol_rpc::simulate_dapp(&client, url, item.tx, &watch, true));
                replaced = true;
            }
        }
        let (summary, post) = sim.map_or((SimSummary::NoResult, None), |sim| {
            let post = sim.accounts.map(|accounts| {
                watch
                    .iter()
                    .zip(accounts)
                    .map(|(key, account)| (*key, account.map(snapshot)))
                    .collect()
            });
            (sim.summary, post)
        });
        facts.push(SolTxItemFacts {
            tables: item.tables,
            pre: item.pre,
            post,
            sim: summary,
            sim_replaced_blockhash: replaced,
            rpc_fee,
            blockhash_valid,
        });
    }
    Ok(DappPreview {
        items: facts,
        mints,
        unread_mints,
    })
}

/// The pre-sign check of a dApp send (spec/07 §20.10-2, §14.3), on the approved message:
/// genesis → `isBlockhashValid(blockhash, processed)` (`false`:
/// [`PreSignError::BlockhashExpired`]) → the lookup tables read and resolved again → at the
/// validity answer's slot S `getLatestBlockhash({processed, minContextSlot: S})`, whose
/// `lastValidBlockHeight` bounds the transaction's (its blockhash is not newer) →
/// `getBlockHeight(confirmed)` with the range check of [`pre_sign`]. Both blockhash calls use
/// `processed`, so `minContextSlot` cannot fail on a commitment gap. Returns the
/// `lastValidBlockHeight` to journal and the check the signer compares with the approval.
///
/// # Errors
///
/// [`PreSignError`]; a table that is missing, not a table or does not resolve is
/// [`PreSignError::TablesChanged`].
pub fn pre_sign_dapp(
    transport: &dyn Transport,
    endpoint: &SolEndpoint,
    message: &SolTxMessage,
) -> Result<(u64, PreSignCheck), PreSignError> {
    let client = RpcClient::new(transport);
    let url = &endpoint.url;
    let rpc = |failure: RpcFailure| PreSignError::Rpc(classify(failure));
    if !check_genesis(&client, endpoint).map_err(PreSignError::Rpc)? {
        return Err(PreSignError::ClusterMismatch);
    }
    let (valid, valid_slot) =
        sol_rpc::blockhash_valid(&client, url, &message.blockhash).map_err(rpc)?;
    if !valid {
        return Err(PreSignError::BlockhashExpired);
    }
    let loaded = if message.lookups.is_empty() {
        None
    } else {
        let (slot, read) = read_tables(&client, url, &lookup_tables(message)).map_err(rpc)?;
        let tables = message_tables(message, &read).map_err(|_| PreSignError::TablesChanged)?;
        Some(resolve(message, &tables, slot).map_err(|_| PreSignError::TablesChanged)?)
    };
    let (_, last_valid) =
        sol_rpc::latest_blockhash_at(&client, url, "processed", Some(valid_slot)).map_err(rpc)?;
    let height = sol_rpc::block_height(&client, url).map_err(rpc)?;
    if last_valid < height.saturating_add(SOL_MIN_LVBH_AHEAD)
        || last_valid > height.saturating_add(SOL_MAX_LVBH_AHEAD)
    {
        return Err(PreSignError::RpcAnomaly);
    }
    Ok((
        last_valid,
        PreSignCheck {
            blockhash: message.blockhash,
            loaded,
        },
    ))
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
    /// The UI's endpoint generation when the round started (echoed in [`TrackResult`]).
    pub generation: u64,
    /// The `sendTransaction` options of this round's sends (the wallet's default, or a dApp
    /// record's `skipPreflight` and preflight commitment, spec/07 §20.8).
    pub send: SendConfig,
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

/// One round (spec/07 §14.2–§14.3): (first round of the session, or a user "지금 다시 전송":
/// send first) → status (history off) → plan → re-send the same bytes and/or `getEpochInfo`
/// (confirmed block height and slot of one view) → history lookup (with its `context.slot`) only
/// when that height is past `lastValidBlockHeight` → [`decide`]. One such round with a `null`
/// history proves expiry. No re-signing exists here.
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
    // The first round of the session (just signed, resumed after start/unlock, or the user asked
    // for an immediate re-send) sends before it asks the status: a failing status lookup must not
    // hold back that broadcast. Sending the same bytes again is harmless even if they landed.
    let first = job.state.last_round_ms.is_none() && !job.state.stop_rebroadcast;
    let early = first.then(|| {
        result.sends = result.sends.saturating_add(1);
        sol_rpc::send_transaction_opts(&client, url, &job.tx, &signature_text, &job.send)
    });
    let status = match sol_rpc::signature_status(&client, url, &signature_text, false, &programs) {
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
            sol_rpc::send_transaction_opts(&client, url, &job.tx, &signature_text, &job.send)
        })
    });
    let chain = if round.height {
        sol_rpc::epoch_view(&client, url).ok()
    } else {
        None
    };
    let history = if status == SigStatus::NotFound && wants_history(&job.pending, chain) {
        sol_rpc::signature_history(&client, url, &signature_text, &programs).ok()
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
    /// Lamports (confirmed).
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
