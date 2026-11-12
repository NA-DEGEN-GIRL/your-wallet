//! `sol::rpc` (spec/07 §15.2): the Solana JSON-RPC calls over the shared transport and their
//! JSON → core-type conversions. Integers are read with `Number::as_u64` (no `f64`); unknown
//! fields are ignored; missing or mistyped required fields are `Malformed` (`RpcAnomaly`). RPC
//! strings (`message`, logs) are never read or shown: errors are classified from their JSON
//! structure only (spec/07 §15.3). Every request uses `"commitment":"confirmed"` (the configured RPC is trusted: confirmed
//! is final, spec.md §2.2) and base64, except the dApp blockhash checks at `processed`
//! (spec/07 §20.10).

use yw_core::sol::address::{
    ATA_PROGRAM, COMPUTE_BUDGET_PROGRAM, SYSTEM_PROGRAM, TOKEN_2022_PROGRAM, TOKEN_PROGRAM,
};
use yw_core::sol::broadcast::{ChainView, HistoryView, SendResult, SigStatus, err};
use yw_core::sol::dapp::parse_wire_tx;
use yw_core::sol::display::SimSummary;
use yw_core::sol::template::T_SPL_HEADER;
use yw_core::sol::{SolAddress, SolAsset};
use yw_json::{Number, Value};
use yw_win::http::HttpsUrl;

use crate::rpc::{CallError, DEFAULT_MAX_RESPONSE, RpcClient, RpcFailure};
use crate::text::{json_object, json_str, json_u64};

/// Program of an instruction, for the `InstructionError` classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IxProgram {
    /// `ComputeBudget`.
    ComputeBudget,
    /// System.
    System,
    /// Token, Token-2022 or ATA (v1.1).
    Token,
    /// Any other program (a dApp transaction, spec/07 §20.8).
    Other,
}

/// `T_SOL` instruction programs (limit, price, transfer).
pub const T_SOL_PROGRAMS: [IxProgram; 3] = [
    IxProgram::ComputeBudget,
    IxProgram::ComputeBudget,
    IxProgram::System,
];

/// `T_SPL` instruction programs (limit, price, ATA `CreateIdempotent`, `TransferChecked`).
pub const T_SPL_PROGRAMS: [IxProgram; 4] = [
    IxProgram::ComputeBudget,
    IxProgram::ComputeBudget,
    IxProgram::Token,
    IxProgram::Token,
];

/// The instruction programs of an asset's template (for `InstructionError` classification).
#[must_use]
pub const fn programs_for(asset: SolAsset) -> &'static [IxProgram] {
    match asset {
        SolAsset::Sol => &T_SOL_PROGRAMS,
        SolAsset::Spl(_) => &T_SPL_PROGRAMS,
    }
}

/// The instruction programs of a transaction, in instruction order, read from its parsed
/// message: a wallet template gives exactly [`T_SOL_PROGRAMS`] or [`T_SPL_PROGRAMS`], a dApp
/// transaction [`IxProgram::Other`] for every program outside System, Token, Token-2022, ATA and
/// `ComputeBudget`. Bytes that do not parse fall back to the template header: `T_SPL` for
/// `[1, 0, 6]`, otherwise `T_SOL`. Only the error class shown depends on it.
#[must_use]
pub fn programs_of(tx: &[u8]) -> Vec<IxProgram> {
    let Ok(wire) = parse_wire_tx(tx) else {
        return match tx.get(65..68) {
            Some(header) if header == T_SPL_HEADER => T_SPL_PROGRAMS.to_vec(),
            _ => T_SOL_PROGRAMS.to_vec(),
        };
    };
    wire.message
        .program_ids()
        .iter()
        .map(|program| {
            if *program == SYSTEM_PROGRAM {
                IxProgram::System
            } else if *program == COMPUTE_BUDGET_PROGRAM {
                IxProgram::ComputeBudget
            } else if [TOKEN_PROGRAM, TOKEN_2022_PROGRAM, ATA_PROGRAM].contains(program) {
                IxProgram::Token
            } else {
                IxProgram::Other
            }
        })
        .collect()
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Strict standard base64 (RFC 4648 §4, padded): length a multiple of 4, padding only at the end
/// (at most two `=`), unused bits zero (canonical). Account data of `getAccountInfo`.
#[must_use]
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let value = |byte: u8| -> Option<u32> {
        let index = ALPHABET.iter().position(|symbol| *symbol == byte)?;
        u32::try_from(index).ok()
    };
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let chunks = bytes.chunks_exact(4);
    let last = chunks.len().saturating_sub(1);
    for (index, chunk) in chunks.enumerate() {
        let [s0, s1, s2, s3] = <[u8; 4]>::try_from(chunk).ok()?;
        let padding = match (s2, s3) {
            (b'=', b'=') => 2,
            (_, b'=') => 1,
            _ => 0,
        };
        if padding > 0 && index != last {
            return None;
        }
        let triple = (value(s0)? << 18)
            | (value(s1)? << 12)
            | if padding == 2 { 0 } else { value(s2)? << 6 }
            | if padding == 0 { value(s3)? } else { 0 };
        let [_, first, second, third] = triple.to_be_bytes();
        out.push(first);
        match padding {
            0 => {
                out.push(second);
                out.push(third);
            }
            1 if third == 0 => out.push(second),
            2 if second == 0 && third == 0 => {}
            _ => return None,
        }
    }
    Some(out)
}

/// Standard base64 with padding (transactions and messages are sent as base64, spec/07 §15.2).
#[must_use]
pub fn base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));
    let symbol = |index: u32| {
        char::from(
            ALPHABET
                .get(usize::try_from(index & 0x3f).unwrap_or(0))
                .copied()
                .unwrap_or(b'A'),
        )
    };
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk.first().copied().unwrap_or(0));
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(symbol(triple >> 18));
        out.push(symbol(triple >> 12));
        if chunk.len() > 1 {
            out.push(symbol(triple >> 6));
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(symbol(triple));
        } else {
            out.push('=');
        }
    }
    out
}

fn confirmed() -> Value {
    json_object(vec![("commitment", json_str("confirmed"))])
}

fn u64_of(value: &Value) -> Result<u64, RpcFailure> {
    value
        .as_number()
        .and_then(Number::as_u64)
        .ok_or(RpcFailure::Malformed)
}

fn context_value(result: &Value) -> Result<&Value, RpcFailure> {
    result
        .as_object()
        .and_then(|object| object.get("value"))
        .ok_or(RpcFailure::Malformed)
}

fn address_of(value: &Value) -> Result<SolAddress, RpcFailure> {
    value
        .as_str()
        .and_then(|text| SolAddress::parse(text).ok())
        .ok_or(RpcFailure::Malformed)
}

/// `getGenesisHash` → 32 bytes.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn genesis_hash(client: &RpcClient<'_>, url: &HttpsUrl) -> Result<[u8; 32], RpcFailure> {
    let result = client.call(url, "getGenesisHash", Value::Array(Vec::new()))?;
    address_of(&result).map(SolAddress::to_bytes)
}

/// `getBalance(addr, confirmed)` → lamports.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn balance(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    address: &SolAddress,
) -> Result<u64, RpcFailure> {
    let result = client.call(
        url,
        "getBalance",
        Value::Array(vec![json_str(&address.to_base58()), confirmed()]),
    )?;
    u64_of(context_value(&result)?)
}

/// What `getAccountInfo` says about an account (data is not requested: `dataSlice` 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountInfo {
    /// Owner program.
    pub owner: SolAddress,
    /// Executable.
    pub executable: bool,
    /// Lamports.
    pub lamports: u64,
}

/// `getAccountInfo(addr, {base64, confirmed, dataSlice 0/0})` → `None` for a missing account.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn account_info(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    address: &SolAddress,
) -> Result<Option<AccountInfo>, RpcFailure> {
    let config = json_object(vec![
        ("encoding", json_str("base64")),
        ("commitment", json_str("confirmed")),
        (
            "dataSlice",
            json_object(vec![("offset", json_u64(0)), ("length", json_u64(0))]),
        ),
    ]);
    let result = client.call(
        url,
        "getAccountInfo",
        Value::Array(vec![json_str(&address.to_base58()), config]),
    )?;
    let value = context_value(&result)?;
    if value.is_null() {
        return Ok(None);
    }
    let object = value.as_object().ok_or(RpcFailure::Malformed)?;
    Ok(Some(AccountInfo {
        owner: address_of(object.get("owner").ok_or(RpcFailure::Malformed)?)?,
        executable: object
            .get("executable")
            .and_then(Value::as_bool)
            .ok_or(RpcFailure::Malformed)?,
        lamports: u64_of(object.get("lamports").ok_or(RpcFailure::Malformed)?)?,
    }))
}

/// An account with its data (`getAccountInfo` without `dataSlice`, base64).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountData {
    /// Owner program.
    pub owner: SolAddress,
    /// Executable.
    pub executable: bool,
    /// Lamports.
    pub lamports: u64,
    /// Raw data (strict base64).
    pub data: Vec<u8>,
    /// The data was longer than the caller's bound and is left out (`data` empty; only from
    /// [`multiple_accounts`] and [`simulate_dapp`]).
    pub truncated: bool,
}

impl AccountData {
    /// `(owner program, data)` for the yw-core SPL classifiers.
    #[must_use]
    pub fn view(&self) -> (&SolAddress, &[u8]) {
        (&self.owner, &self.data)
    }
}

/// Largest account data read: a mint (82 B) or token account (165 B) is far below; anything
/// longer is not an SPL account of the allowlist and is refused as `Malformed`.
const MAX_ACCOUNT_DATA: usize = 4_096;

/// `getAccountInfo(addr, {base64, confirmed})` with the data (mint and token accounts,
/// spec/07 §15.2, §15.4) → `None` for a missing account. The data must be `[<base64>, "base64"]`.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn account_data(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    address: &SolAddress,
) -> Result<Option<AccountData>, RpcFailure> {
    let config = json_object(vec![
        ("encoding", json_str("base64")),
        ("commitment", json_str("confirmed")),
    ]);
    let result = client.call(
        url,
        "getAccountInfo",
        Value::Array(vec![json_str(&address.to_base58()), config]),
    )?;
    account_of(context_value(&result)?, MAX_ACCOUNT_DATA)
}

/// What [`account_entry`] does with data longer than its bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Oversize {
    /// `Malformed` (`getAccountInfo` of a mint or token account).
    Refuse,
    /// Kept without its data, `truncated` (dApp references: tables, mints, simulated accounts).
    Truncate,
}

/// One account object of an RPC answer (`{data:[<base64>,"base64"], executable, lamports,
/// owner, …}`) with at most `max_data` data bytes; `null` is a missing account.
fn account_entry(
    value: &Value,
    max_data: usize,
    oversize: Oversize,
) -> Result<Option<AccountData>, RpcFailure> {
    if value.is_null() {
        return Ok(None);
    }
    let object = value.as_object().ok_or(RpcFailure::Malformed)?;
    let (data, truncated) = match object.get("data").and_then(Value::as_array) {
        Some([Value::String(text), Value::String(encoding)]) if encoding == "base64" => {
            if text.len() <= max_data.div_ceil(3).saturating_mul(4) {
                (base64_decode(text).ok_or(RpcFailure::Malformed)?, false)
            } else if oversize == Oversize::Truncate {
                (Vec::new(), true)
            } else {
                return Err(RpcFailure::Malformed);
            }
        }
        _ => return Err(RpcFailure::Malformed),
    };
    Ok(Some(AccountData {
        owner: address_of(object.get("owner").ok_or(RpcFailure::Malformed)?)?,
        executable: object
            .get("executable")
            .and_then(Value::as_bool)
            .ok_or(RpcFailure::Malformed)?,
        lamports: u64_of(object.get("lamports").ok_or(RpcFailure::Malformed)?)?,
        data,
        truncated,
    }))
}

/// An account of an RPC answer whose data must fit `max_data` bytes (`null`: missing).
///
/// # Errors
///
/// [`RpcFailure::Malformed`], also for longer data.
pub fn account_of(value: &Value, max_data: usize) -> Result<Option<AccountData>, RpcFailure> {
    account_entry(value, max_data, Oversize::Refuse)
}

/// An account of an RPC answer; data longer than `max_data` bytes is left out and marked
/// `truncated` (`null`: missing).
///
/// # Errors
///
/// [`RpcFailure::Malformed`].
pub fn account_of_capped(
    value: &Value,
    max_data: usize,
) -> Result<Option<AccountData>, RpcFailure> {
    account_entry(value, max_data, Oversize::Truncate)
}

/// Addresses per `getMultipleAccounts` call (the RPC's limit).
pub const MULTIPLE_ACCOUNTS_CHUNK: usize = 100;

/// Response bound of the dApp reference calls (a `getMultipleAccounts` chunk, a
/// `simulateTransaction` with accounts): 4 MiB, as `eth_simulateV1` (spec/03 §1.4).
pub const DAPP_MAX_RESPONSE: usize = 4 * 1_048_576;

/// `getMultipleAccounts(addrs, {base64, confirmed, dataSlice?, minContextSlot?})` in chunks of
/// [`MULTIPLE_ACCOUNTS_CHUNK`] (spec/07 §15.2) → the lowest `context.slot` of the chunks and one
/// entry per address in order (`None`: missing). Data longer than `max_data` is `truncated`;
/// `slice` is `(offset, length)`.
///
/// # Errors
///
/// [`RpcFailure`]; an answer with another number of entries than asked is `Malformed`.
pub fn multiple_accounts(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    addresses: &[SolAddress],
    max_data: usize,
    slice: Option<(u64, u64)>,
    min_context_slot: Option<u64>,
) -> Result<(u64, Vec<Option<AccountData>>), RpcFailure> {
    let mut slot: Option<u64> = None;
    let mut out = Vec::with_capacity(addresses.len());
    for chunk in addresses.chunks(MULTIPLE_ACCOUNTS_CHUNK) {
        let mut config = vec![
            ("encoding", json_str("base64")),
            ("commitment", json_str("confirmed")),
        ];
        if let Some((offset, length)) = slice {
            config.push((
                "dataSlice",
                json_object(vec![
                    ("offset", json_u64(offset)),
                    ("length", json_u64(length)),
                ]),
            ));
        }
        if let Some(min) = min_context_slot {
            config.push(("minContextSlot", json_u64(min)));
        }
        let keys = chunk
            .iter()
            .map(|address| json_str(&address.to_base58()))
            .collect();
        let result = client.call_limited(
            url,
            "getMultipleAccounts",
            Value::Array(vec![Value::Array(keys), json_object(config)]),
            DAPP_MAX_RESPONSE,
        )?;
        let list = context_value(&result)?
            .as_array()
            .ok_or(RpcFailure::Malformed)?;
        if list.len() != chunk.len() {
            return Err(RpcFailure::Malformed);
        }
        for entry in list {
            out.push(account_of_capped(entry, max_data)?);
        }
        let at = context_slot(&result)?;
        slot = Some(slot.map_or(at, |known| known.min(at)));
    }
    Ok((slot.unwrap_or(0), out))
}

/// `getMinimumBalanceForRentExemption(size, confirmed)`.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn minimum_rent(client: &RpcClient<'_>, url: &HttpsUrl, size: u64) -> Result<u64, RpcFailure> {
    let result = client.call(
        url,
        "getMinimumBalanceForRentExemption",
        Value::Array(vec![json_u64(size), confirmed()]),
    )?;
    u64_of(&result)
}

/// `getRecentPrioritizationFees([writable…])` → the `prioritizationFee` values.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn prioritization_fees(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    writable: &[SolAddress],
) -> Result<Vec<u64>, RpcFailure> {
    let accounts = writable
        .iter()
        .map(|address| json_str(&address.to_base58()))
        .collect();
    let result = client.call(
        url,
        "getRecentPrioritizationFees",
        Value::Array(vec![Value::Array(accounts)]),
    )?;
    result
        .as_array()
        .ok_or(RpcFailure::Malformed)?
        .iter()
        .map(|entry| {
            entry
                .as_object()
                .and_then(|object| object.get("prioritizationFee"))
                .ok_or(RpcFailure::Malformed)
                .and_then(u64_of)
        })
        .collect()
}

/// `getLatestBlockhash(confirmed)` → `(blockhash, lastValidBlockHeight)`.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn latest_blockhash(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
) -> Result<([u8; 32], u64), RpcFailure> {
    latest_blockhash_at(client, url, "confirmed", None)
}

/// `getLatestBlockhash({commitment, minContextSlot?})` → `(blockhash, lastValidBlockHeight)`.
/// A dApp send asks at `processed` with the slot of its `isBlockhashValid` answer (spec/07
/// §20.10): one commitment for both calls, so `minContextSlot` cannot fail on a commitment gap.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn latest_blockhash_at(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    commitment: &str,
    min_context_slot: Option<u64>,
) -> Result<([u8; 32], u64), RpcFailure> {
    let mut config = vec![("commitment", json_str(commitment))];
    if let Some(min) = min_context_slot {
        config.push(("minContextSlot", json_u64(min)));
    }
    let result = client.call(
        url,
        "getLatestBlockhash",
        Value::Array(vec![json_object(config)]),
    )?;
    let value = context_value(&result)?
        .as_object()
        .ok_or(RpcFailure::Malformed)?;
    let blockhash = address_of(value.get("blockhash").ok_or(RpcFailure::Malformed)?)?;
    let height = u64_of(
        value
            .get("lastValidBlockHeight")
            .ok_or(RpcFailure::Malformed)?,
    )?;
    Ok((blockhash.to_bytes(), height))
}

/// `getBlockHeight(confirmed)`.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn block_height(client: &RpcClient<'_>, url: &HttpsUrl) -> Result<u64, RpcFailure> {
    let result = client.call(url, "getBlockHeight", Value::Array(vec![confirmed()]))?;
    u64_of(&result)
}

/// `isBlockhashValid(base58(hash), {commitment:"processed"})` → `(valid, context.slot)` (a dApp
/// transaction's own blockhash, spec/07 §20.10; the RPC default would be `finalized`).
///
/// # Errors
///
/// [`RpcFailure`].
pub fn blockhash_valid(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    hash: &[u8; 32],
) -> Result<(bool, u64), RpcFailure> {
    let result = client.call(
        url,
        "isBlockhashValid",
        Value::Array(vec![
            json_str(&SolAddress::from_bytes(*hash).to_base58()),
            json_object(vec![("commitment", json_str("processed"))]),
        ]),
    )?;
    let valid = context_value(&result)?
        .as_bool()
        .ok_or(RpcFailure::Malformed)?;
    Ok((valid, context_slot(&result)?))
}

/// `getEpochInfo(confirmed)` → `blockHeight` and `absoluteSlot` of the same answer (one RPC view
/// for the expiry proof, spec/07 §14.3).
///
/// # Errors
///
/// [`RpcFailure`].
pub fn epoch_view(client: &RpcClient<'_>, url: &HttpsUrl) -> Result<ChainView, RpcFailure> {
    let result = client.call(url, "getEpochInfo", Value::Array(vec![confirmed()]))?;
    let object = result.as_object().ok_or(RpcFailure::Malformed)?;
    Ok(ChainView {
        block_height: u64_of(object.get("blockHeight").ok_or(RpcFailure::Malformed)?)?,
        slot: u64_of(object.get("absoluteSlot").ok_or(RpcFailure::Malformed)?)?,
    })
}

/// `getFeeForMessage(base64(message), confirmed)` → `None` for `null`.
///
/// # Errors
///
/// [`RpcFailure`].
pub fn fee_for_message(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    message: &[u8],
) -> Result<Option<u64>, RpcFailure> {
    let result = client.call(
        url,
        "getFeeForMessage",
        Value::Array(vec![json_str(&base64(message)), confirmed()]),
    )?;
    let value = context_value(&result)?;
    if value.is_null() {
        return Ok(None);
    }
    u64_of(value).map(Some)
}

/// Classifies a `TransactionError` JSON value (spec/07 §15.3) by structure only.
#[must_use]
pub fn classify_tx_error(value: &Value, programs: &[IxProgram]) -> u16 {
    match value {
        Value::String(name) => match name.as_str() {
            "InsufficientFundsForFee" => err::INSUFFICIENT_FUNDS_FOR_FEE,
            "AccountNotFound" => err::ACCOUNT_NOT_FOUND,
            "BlockhashNotFound" => err::BLOCKHASH_NOT_FOUND,
            "AlreadyProcessed" => err::ALREADY_PROCESSED,
            _ => err::OTHER,
        },
        Value::Object(object) => {
            if object.get("InsufficientFundsForRent").is_some() {
                return err::INSUFFICIENT_FUNDS_FOR_RENT;
            }
            let Some(pair) = object.get("InstructionError").and_then(Value::as_array) else {
                return err::OTHER;
            };
            let (Some(index), Some(inner)) = (
                pair.first()
                    .and_then(Value::as_number)
                    .and_then(Number::as_u64),
                pair.get(1),
            ) else {
                return err::OTHER;
            };
            if inner.as_str() == Some("ComputationalBudgetExceeded") {
                return err::COMPUTE_EXCEEDED;
            }
            match usize::try_from(index)
                .ok()
                .and_then(|index| programs.get(index))
            {
                Some(IxProgram::System) => err::SYSTEM_INSTRUCTION,
                Some(IxProgram::Token) => err::TOKEN_INSTRUCTION,
                Some(IxProgram::Other) => err::PROGRAM_INSTRUCTION,
                Some(IxProgram::ComputeBudget) | None => err::OTHER,
            }
        }
        _ => err::OTHER,
    }
}

/// `simulateTransaction(base64(tx), {sigVerify:false, replaceRecentBlockhash:true})` (reference
/// only, D27). Transport/RPC failures are `NoResult`.
#[must_use]
pub fn simulate(client: &RpcClient<'_>, url: &HttpsUrl, tx: &[u8]) -> SimSummary {
    let config = json_object(vec![
        ("encoding", json_str("base64")),
        ("sigVerify", Value::Bool(false)),
        ("replaceRecentBlockhash", Value::Bool(true)),
        ("commitment", json_str("confirmed")),
    ]);
    let Ok(result) = client.call(
        url,
        "simulateTransaction",
        Value::Array(vec![json_str(&base64(tx)), config]),
    ) else {
        return SimSummary::NoResult;
    };
    let Some(value) = context_value(&result).ok().and_then(Value::as_object) else {
        return SimSummary::NoResult;
    };
    let units = value
        .get("unitsConsumed")
        .and_then(|units| u64_of(units).ok());
    match value.get("err") {
        Some(Value::Null) => units.map_or(SimSummary::NoResult, |units| SimSummary::Ok { units }),
        Some(error) => SimSummary::Failed {
            err: classify_tx_error(error, &programs_of(tx)),
            units,
        },
        None => SimSummary::NoResult,
    }
}

/// Largest data of an account the dApp simulation returns: longer data is left out
/// (`truncated`); its owner and lamports are still compared.
pub const DAPP_SIM_MAX_DATA: usize = 16_384;

/// The simulation of a dApp transaction (spec/07 §20.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DappSim {
    /// The verdict.
    pub summary: SimSummary,
    /// The post-state of the asked addresses, in order (`None`: absent from the answer, of
    /// another length or malformed; an entry `None`: no account after the transaction).
    pub accounts: Option<Vec<Option<AccountData>>>,
}

/// `simulateTransaction(base64(tx), {sigVerify:false, replaceRecentBlockhash:replace,
/// commitment:confirmed, innerInstructions:false, accounts:{base64, addresses}})` of a dApp
/// transaction (reference only, D27). `addresses` are keys of the transaction itself
/// (`dapp::diff::watch_set`). Transport/RPC failures are `NoResult`; the logs are never read.
#[must_use]
pub fn simulate_dapp(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    tx: &[u8],
    addresses: &[SolAddress],
    replace: bool,
) -> DappSim {
    let no_result = DappSim {
        summary: SimSummary::NoResult,
        accounts: None,
    };
    let keys = addresses
        .iter()
        .map(|address| json_str(&address.to_base58()))
        .collect();
    let config = json_object(vec![
        ("encoding", json_str("base64")),
        ("sigVerify", Value::Bool(false)),
        ("replaceRecentBlockhash", Value::Bool(replace)),
        ("commitment", json_str("confirmed")),
        ("innerInstructions", Value::Bool(false)),
        (
            "accounts",
            json_object(vec![
                ("encoding", json_str("base64")),
                ("addresses", Value::Array(keys)),
            ]),
        ),
    ]);
    let Ok(result) = client.call_limited(
        url,
        "simulateTransaction",
        Value::Array(vec![json_str(&base64(tx)), config]),
        DAPP_MAX_RESPONSE,
    ) else {
        return no_result;
    };
    let Some(value) = context_value(&result).ok().and_then(Value::as_object) else {
        return no_result;
    };
    let units = value
        .get("unitsConsumed")
        .and_then(|units| u64_of(units).ok());
    let summary = match value.get("err") {
        Some(Value::Null) => units.map_or(SimSummary::NoResult, |units| SimSummary::Ok { units }),
        Some(error) => SimSummary::Failed {
            err: classify_tx_error(error, &programs_of(tx)),
            units,
        },
        None => SimSummary::NoResult,
    };
    let accounts = value
        .get("accounts")
        .and_then(Value::as_array)
        .filter(|list| list.len() == addresses.len())
        .and_then(|list| {
            list.iter()
                .map(|entry| account_of_capped(entry, DAPP_SIM_MAX_DATA).ok())
                .collect::<Option<Vec<_>>>()
        });
    DappSim { summary, accounts }
}

/// The `sendTransaction` options of a record (spec/07 §14.2, §20.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendConfig {
    /// `skipPreflight` (only a dApp send sets it).
    pub skip_preflight: bool,
    /// `preflightCommitment`.
    pub preflight_commitment: &'static str,
    /// `minContextSlot` (a dApp's first send only).
    pub min_context_slot: Option<u64>,
}

impl Default for SendConfig {
    /// The wallet's own sends: preflight at `confirmed`.
    fn default() -> Self {
        Self {
            skip_preflight: false,
            preflight_commitment: "confirmed",
            min_context_slot: None,
        }
    }
}

/// `sendTransaction(base64(tx), {skipPreflight:false, preflightCommitment:confirmed,
/// maxRetries:0})`, classified for the broadcast loop (spec/07 §14.2): a returned signature is
/// compared with the local one; preflight errors with a deterministic structure (§15.3 codes 1–6
/// and 9) stop re-sending; everything else is transient.
#[must_use]
pub fn send_transaction(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    tx: &[u8],
    local_signature: &str,
) -> SendResult {
    send_transaction_opts(client, url, tx, local_signature, &SendConfig::default())
}

/// [`send_transaction`] with a record's options. `maxRetries` stays 0 (the loop re-sends);
/// `minContextSlot` is added only when set, so the default request is the wallet's own.
#[must_use]
pub fn send_transaction_opts(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    tx: &[u8],
    local_signature: &str,
    send: &SendConfig,
) -> SendResult {
    let mut config = vec![
        ("encoding", json_str("base64")),
        ("skipPreflight", Value::Bool(send.skip_preflight)),
        ("preflightCommitment", json_str(send.preflight_commitment)),
        ("maxRetries", json_u64(0)),
    ];
    if let Some(min) = send.min_context_slot {
        config.push(("minContextSlot", json_u64(min)));
    }
    match client.call_detailed(
        url,
        "sendTransaction",
        Value::Array(vec![json_str(&base64(tx)), json_object(config)]),
        DEFAULT_MAX_RESPONSE,
    ) {
        Ok(Value::String(signature)) => SendResult::Accepted {
            matches: signature == local_signature,
        },
        Err(CallError {
            failure: RpcFailure::Rpc(_),
            data_value: Some(data),
            ..
        }) => {
            let code = data
                .as_object()
                .and_then(|object| object.get("err"))
                .map_or(err::OTHER, |error| {
                    classify_tx_error(error, &programs_of(tx))
                });
            if err::is_deterministic(code) {
                SendResult::Deterministic(code)
            } else {
                SendResult::Transient
            }
        }
        Ok(_) | Err(_) => SendResult::Transient,
    }
}

/// `getSignatureStatuses([sig], {searchTransactionHistory})` for one signature; `programs` names
/// the template's instruction programs for the error class ([`programs_of`]).
///
/// # Errors
///
/// [`RpcFailure`].
pub fn signature_status(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    signature: &str,
    history: bool,
    programs: &[IxProgram],
) -> Result<SigStatus, RpcFailure> {
    signature_status_at(client, url, signature, history, programs).map(|(status, _)| status)
}

/// `result.context.slot` of an `RpcResponse`.
fn context_slot(result: &Value) -> Result<u64, RpcFailure> {
    u64_of(
        result
            .as_object()
            .and_then(|object| object.get("context"))
            .and_then(Value::as_object)
            .and_then(|context| context.get("slot"))
            .ok_or(RpcFailure::Malformed)?,
    )
}

/// `getSignatureStatuses([sig], {searchTransactionHistory:true})` with the response's
/// `context.slot` (the expiry proof only trusts a `null` answered at or after the slot of its
/// height view, spec/07 §14.3).
///
/// # Errors
///
/// [`RpcFailure`] (a missing `context.slot` is `Malformed`).
pub fn signature_history(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    signature: &str,
    programs: &[IxProgram],
) -> Result<HistoryView, RpcFailure> {
    let (status, result) = signature_status_at(client, url, signature, true, programs)?;
    Ok(HistoryView {
        status,
        context_slot: context_slot(&result)?,
    })
}

/// The status and the whole `result` (for its `context`).
fn signature_status_at(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    signature: &str,
    history: bool,
    programs: &[IxProgram],
) -> Result<(SigStatus, Value), RpcFailure> {
    let config = json_object(vec![("searchTransactionHistory", Value::Bool(history))]);
    let result = client.call(
        url,
        "getSignatureStatuses",
        Value::Array(vec![Value::Array(vec![json_str(signature)]), config]),
    )?;
    let status = status_of(&result, programs)?;
    Ok((status, result))
}

fn status_of(result: &Value, programs: &[IxProgram]) -> Result<SigStatus, RpcFailure> {
    let list = context_value(result)?
        .as_array()
        .ok_or(RpcFailure::Malformed)?;
    let entry = list.first().ok_or(RpcFailure::Malformed)?;
    if entry.is_null() {
        return Ok(SigStatus::NotFound);
    }
    let object = entry.as_object().ok_or(RpcFailure::Malformed)?;
    let slot = u64_of(object.get("slot").ok_or(RpcFailure::Malformed)?)?;
    let status = object
        .get("confirmationStatus")
        .and_then(Value::as_str)
        .ok_or(RpcFailure::Malformed)?;
    match status {
        "confirmed" | "finalized" => {
            let error = object.get("err").ok_or(RpcFailure::Malformed)?;
            Ok(SigStatus::Confirmed {
                slot,
                err: (!error.is_null()).then(|| classify_tx_error(error, programs)),
            })
        }
        "processed" => Ok(SigStatus::Processing),
        _ => Err(RpcFailure::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use yw_core::sol::broadcast::err;
    use yw_json::Limits;

    use yw_core::sol::address::{COMPUTE_BUDGET_PROGRAM, TOKEN_2022_PROGRAM};
    use yw_core::sol::message::{assemble_transaction, encode_message};
    use yw_core::sol::template::spl_entries;
    use yw_core::sol::{SolAddress, SolAsset, SolCluster, SolTransferCore};

    use super::{
        IxProgram, T_SOL_PROGRAMS, T_SPL_PROGRAMS, account_of, account_of_capped, base64,
        base64_decode, classify_tx_error, programs_of,
    };
    use crate::rpc::RpcFailure;

    fn json(text: &str) -> yw_json::Value {
        yw_json::parse(text.as_bytes(), &Limits::RESPONSE).unwrap()
    }

    #[test]
    fn base64_rfc4648_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), expected);
            assert_eq!(
                base64_decode(expected).as_deref(),
                Some(input.as_bytes()),
                "{expected}"
            );
        }
        assert_eq!(base64(&[0xfb, 0xff]), "+/8=");
        assert_eq!(base64_decode("+/8=").as_deref(), Some(&[0xfb, 0xff][..]));
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(base64_decode(&base64(&all)), Some(all));
    }

    #[test]
    fn base64_decoder_is_strict() {
        for bad in [
            "Zg", "Zg=", "Zg===", "Z===", "Zh==", "Zm9=", "Zg==Zg==", "Zm9v\n", " Zm9v", "Zm-v",
            "Zm_v", "Zm9v=", "====",
        ] {
            assert_eq!(base64_decode(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn programs_are_read_from_the_parsed_message() {
        // Wallet templates parse to exactly their program arrays.
        let core = |asset| SolTransferCore {
            from: SolAddress::from_bytes([1; 32]),
            to: SolAddress::from_bytes([2; 32]),
            asset,
            amount: 1,
            cu_limit: 1,
            cu_price_micro: 0,
        };
        let tx = |core: &SolTransferCore| {
            assemble_transaction(&[0; 64], &encode_message(core, &[3; 32]))
        };
        assert_eq!(programs_of(&tx(&core(SolAsset::Sol))), &T_SOL_PROGRAMS);
        let entry = spl_entries(SolCluster::Devnet).next();
        assert!(entry.is_some());
        if let Some(entry) = entry {
            assert_eq!(
                programs_of(&tx(&core(SolAsset::Spl(entry)))),
                &T_SPL_PROGRAMS
            );
        }
        // A dApp v0 message: ComputeBudget, an unknown program, Token-2022.
        let mut message = vec![0x80, 1, 0, 3, 4];
        for key in [
            [9; 32],
            COMPUTE_BUDGET_PROGRAM.to_bytes(),
            [8; 32],
            TOKEN_2022_PROGRAM.to_bytes(),
        ] {
            message.extend_from_slice(&key);
        }
        message.extend_from_slice(&[3; 32]);
        message.extend_from_slice(&[3, 1, 0, 1, 2, 2, 1, 0, 0, 3, 1, 0, 0, 0]);
        let mut wire = vec![1];
        wire.extend_from_slice(&[0; 64]);
        wire.extend_from_slice(&message);
        let programs = programs_of(&wire);
        assert_eq!(
            programs,
            [IxProgram::ComputeBudget, IxProgram::Other, IxProgram::Token]
        );
        // A failing instruction of another program is code 9 (deterministic).
        assert_eq!(
            classify_tx_error(
                &json(r#"{"InstructionError":[1,{"Custom":6001}]}"#),
                &programs
            ),
            err::PROGRAM_INSTRUCTION
        );
        assert!(err::is_deterministic(err::PROGRAM_INSTRUCTION));
    }

    #[test]
    fn account_entries_refuse_or_truncate_long_data() {
        let entry = json(
            r#"{"data":["AQIDBA==","base64"],"executable":false,"lamports":7,"owner":"11111111111111111111111111111111","rentEpoch":0,"space":4}"#,
        );
        let full = account_of(&entry, 4).ok().flatten();
        assert_eq!(
            full.as_ref().map(|account| account.data.clone()),
            Some(vec![1, 2, 3, 4])
        );
        assert_eq!(full.map(|account| account.truncated), Some(false));
        assert_eq!(account_of(&entry, 2), Err(RpcFailure::Malformed));
        let cut = account_of_capped(&entry, 2).ok().flatten();
        assert_eq!(
            cut.map(|account| (account.data.is_empty(), account.truncated, account.lamports)),
            Some((true, true, 7))
        );
        assert_eq!(account_of_capped(&json("null"), 2), Ok(None));
        assert_eq!(
            account_of_capped(&json(r#"{"data":"AQ==","lamports":1}"#), 2),
            Err(RpcFailure::Malformed)
        );
    }

    #[test]
    fn programs_follow_the_template_header() {
        let mut tx = vec![1_u8];
        tx.extend_from_slice(&[0; 64]);
        tx.extend_from_slice(&[1, 0, 6, 9]);
        assert_eq!(programs_of(&tx), &T_SPL_PROGRAMS);
        tx[67] = 2;
        assert_eq!(programs_of(&tx), &T_SOL_PROGRAMS);
        assert_eq!(programs_of(&[]), &T_SOL_PROGRAMS);
        assert_eq!(
            classify_tx_error(
                &json(r#"{"InstructionError":[2,{"Custom":0}]}"#),
                &T_SPL_PROGRAMS
            ),
            err::TOKEN_INSTRUCTION
        );
        assert_eq!(
            classify_tx_error(
                &json(r#"{"InstructionError":[3,{"Custom":1}]}"#),
                &T_SPL_PROGRAMS
            ),
            err::TOKEN_INSTRUCTION
        );
    }

    #[test]
    fn transaction_error_classification() {
        let cases = [
            (
                r#""InsufficientFundsForFee""#,
                err::INSUFFICIENT_FUNDS_FOR_FEE,
            ),
            (
                r#"{"InsufficientFundsForRent":{"account_index":1}}"#,
                err::INSUFFICIENT_FUNDS_FOR_RENT,
            ),
            (r#""AccountNotFound""#, err::ACCOUNT_NOT_FOUND),
            (
                r#"{"InstructionError":[2,{"Custom":1}]}"#,
                err::SYSTEM_INSTRUCTION,
            ),
            (
                r#"{"InstructionError":[0,"ComputationalBudgetExceeded"]}"#,
                err::COMPUTE_EXCEEDED,
            ),
            (
                r#"{"InstructionError":[0,"InvalidInstructionData"]}"#,
                err::OTHER,
            ),
            (r#"{"InstructionError":[9,{"Custom":1}]}"#, err::OTHER),
            (r#""BlockhashNotFound""#, err::BLOCKHASH_NOT_FOUND),
            (r#""AlreadyProcessed""#, err::ALREADY_PROCESSED),
            (r#""SomethingNew""#, err::OTHER),
            ("7", err::OTHER),
        ];
        for (text, code) in cases {
            assert_eq!(
                classify_tx_error(&json(text), &T_SOL_PROGRAMS),
                code,
                "{text}"
            );
        }
        assert_eq!(
            classify_tx_error(
                &json(r#"{"InstructionError":[1,{"Custom":4}]}"#),
                &[IxProgram::System, IxProgram::Token]
            ),
            err::TOKEN_INSTRUCTION
        );
    }
}
