//! Bitcoin received history (spec/04 §2.6, spec/08 §4.3, 2026-11-11): on the session's paced
//! request line (`BtcClient`: ≥ 200 ms apart, 429 back-off, an automatic read skipped during the
//! 300 s cooldown) and only after the session's chain check passed step 3, one `AddressTxs` per
//! receive address the UI chose ([`BtcReceivedWork::fetch`]): Esplora `GET /address/{a}/txs` (up
//! to 50 mempool and 25 confirmed transactions), Blockbook `details=txs` page 1 (every mempool
//! transaction plus [`BB_PAGE_SIZE`] confirmed ones). A transaction is incoming when none of its
//! inputs spends from the account's watch set (receive and change) and its outputs pay the
//! account; the amount is the sum paid to the account.
//!
//! Unconfirmed (mempool) deposits (2026-11-13): listed as pending rows, display only. A pending
//! row the read no longer lists is resolved only when every address that paid it got a complete
//! answer, and then with one indexer `TxStatus` ([`BTC_PENDING_CHECK_MAX`] per read): confirmed →
//! a confirmed row, not found → gone. Anything less keeps the row. Inputs the indexer could not
//! resolve make that transaction unknown (never a row) and its address incomplete (fail closed:
//! our own unconfirmed send must never look like a deposit of its change). Before 2026-11-13
//! only Esplora was read (`bb-*` showed a fixed line) and only the newest 5 used addresses.

use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;

use yw_core::bip32::path::BtcChain;
use yw_core::btc::account::BtcAccountKey;
use yw_core::btc::amount::format_btc;
use yw_core::btc::{BTC_MAX_ADDRESS_INDEX, MAX_MONEY, Sats, Txid};
use yw_json::{Number, Object, Value};

use super::{Cursor, DUST_BTC_SATS, Fetched, Found, Incoming};
use crate::btc::chain::{ChainInput, ChainSession, ensure_chain};
use crate::btc::client::BtcClient;
use crate::btc::flow::{address_request, cooldown_gate};
use crate::btc::indexer::{
    BtcIndexerReq, BtcIndexerResp, IndexerError, TxSeen, bb_amount, esplora_uint,
};
use crate::btc::{BtcError, Trigger};
use crate::settings::BtcIndexer;

/// Most used receive addresses read (the newest ones).
pub const MAX_ADDRESSES: usize = 5;
/// Most receive addresses read per refresh: the 받기 address, the newest issued one, the
/// addresses the refresh saw pending deposits on, those of the list's pending rows and the
/// newest [`MAX_ADDRESSES`] used ones (2026-11-13; 5 used ones only before).
pub const MAX_READ_ADDRESSES: usize = 12;
/// Most transactions taken from one answer (Esplora sends at most 75).
pub const MAX_TXS: usize = 200;
/// Esplora's mempool page: an answer with this many unconfirmed entries may hide more.
pub const ESPLORA_MEMPOOL_PAGE: usize = 50;
/// Blockbook confirmed transactions per page (mempool ones come on top, all on page 1).
pub const BB_PAGE_SIZE: u32 = 25;
/// Most `TxStatus` checks of vanished pending rows per read.
pub const BTC_PENDING_CHECK_MAX: usize = 5;
/// The card's line when a Blockbook indexer refuses `details=txs` for every address.
pub const T_BB_NO_TXS: &str = "이 Bitcoin 인덱서(Blockbook)는 주소 거래 목록(details=txs)을 주지 않아 받은 내역을 표시하지 않습니다 — 탐색기에서 확인하세요. '새로고침'으로 다시 시도합니다.";

/// One transaction of an address's recent list, as much as the history needs (Esplora and
/// Blockbook answers parse into this).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddrTx {
    /// Txid (display hex).
    pub txid: String,
    /// `(height, block_time)` when confirmed.
    pub confirmed: Option<(u32, u64)>,
    /// Each input's spent output: its address (`None`: coinbase or no address form) and value.
    pub inputs: Vec<(Option<String>, u64)>,
    /// Each output: its address (`None`: no address form) and value.
    pub outputs: Vec<(Option<String>, u64)>,
    /// An input the indexer could not resolve (no prevout, no address): the transaction is
    /// never a row (it could be our own send) and its address answer is incomplete.
    pub unknown_inputs: bool,
}

fn address_text(text: &str) -> Option<String> {
    ((14..=90).contains(&text.len()) && text.is_ascii()).then(|| text.to_ascii_lowercase())
}

fn address_of(object: &Object) -> Option<String> {
    object
        .get("scriptpubkey_address")
        .and_then(Value::as_str)
        .and_then(address_text)
}

fn value_of(object: &Object) -> Result<u64, IndexerError> {
    esplora_uint(
        object.get("value").ok_or(IndexerError::Malformed)?,
        MAX_MONEY,
    )
}

fn status_of(value: &Value) -> Result<Option<(u32, u64)>, IndexerError> {
    let object = value.as_object().ok_or(IndexerError::Malformed)?;
    match object.get("confirmed").and_then(Value::as_bool) {
        Some(true) => {
            let height = esplora_uint(
                object.get("block_height").ok_or(IndexerError::Malformed)?,
                u64::from(u32::MAX),
            )?;
            let time = esplora_uint(
                object.get("block_time").ok_or(IndexerError::Malformed)?,
                u64::from(u32::MAX),
            )?;
            Ok(Some((
                u32::try_from(height).map_err(|_| IndexerError::Malformed)?,
                time,
            )))
        }
        Some(false) => Ok(None),
        None => Err(IndexerError::Malformed),
    }
}

fn txid_of(object: &Object) -> Result<String, IndexerError> {
    object
        .get("txid")
        .and_then(Value::as_str)
        .filter(|text| {
            text.len() == 64
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .map(str::to_owned)
        .ok_or(IndexerError::Malformed)
}

fn list<'v>(object: &'v Object, key: &str) -> Result<&'v [Value], IndexerError> {
    object
        .get(key)
        .and_then(Value::as_array)
        .ok_or(IndexerError::Malformed)
}

fn tx_of(object: &Object) -> Result<AddrTx, IndexerError> {
    let txid = txid_of(object)?;
    let mut inputs = Vec::new();
    let mut unknown_inputs = false;
    for input in list(object, "vin")? {
        let input = input.as_object().ok_or(IndexerError::Malformed)?;
        match input.get("prevout") {
            Some(Value::Object(prevout)) => inputs.push((address_of(prevout), value_of(prevout)?)),
            Some(Value::Null) | None => {
                // Coinbase; any other input without its prevout is unknown (2026-11-13: it was
                // read as a coinbase before).
                unknown_inputs |= input.get("is_coinbase").and_then(Value::as_bool) != Some(true);
                inputs.push((None, 0));
            }
            Some(_) => return Err(IndexerError::Malformed),
        }
    }
    let mut outputs = Vec::new();
    for output in list(object, "vout")? {
        let output = output.as_object().ok_or(IndexerError::Malformed)?;
        outputs.push((address_of(output), value_of(output)?));
    }
    Ok(AddrTx {
        txid,
        confirmed: status_of(object.get("status").ok_or(IndexerError::Malformed)?)?,
        inputs,
        outputs,
        unknown_inputs,
    })
}

/// Parses an Esplora `/address/{a}/txs` answer.
///
/// # Errors
///
/// [`IndexerError::Malformed`].
pub fn parse_txs(value: &Value) -> Result<Vec<AddrTx>, IndexerError> {
    let list = value.as_array().ok_or(IndexerError::Malformed)?;
    if list.len() > MAX_TXS {
        return Err(IndexerError::Malformed);
    }
    list.iter()
        .map(|item| tx_of(item.as_object().ok_or(IndexerError::Malformed)?))
        .collect()
}

/// A Blockbook `addresses` array: the address when it has exactly one usable entry.
fn bb_address(object: &Object) -> Result<Option<String>, IndexerError> {
    match object.get("addresses") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) => Ok(match items.as_slice() {
            [Value::String(text)] => address_text(text),
            _ => None,
        }),
        Some(_) => Err(IndexerError::Malformed),
    }
}

fn bb_u32(object: &Object, key: &str) -> Result<u32, IndexerError> {
    esplora_uint(
        object.get(key).ok_or(IndexerError::Malformed)?,
        u64::from(u32::MAX),
    )
    .and_then(|value| u32::try_from(value).map_err(|_| IndexerError::Malformed))
}

fn bb_tx(object: &Object) -> Result<AddrTx, IndexerError> {
    let txid = txid_of(object)?;
    let confirmations = bb_u32(object, "confirmations")?;
    // A mempool entry's `blockHeight` (−1 or 0) and first-seen `blockTime` are ignored.
    let confirmed = if confirmations == 0 {
        None
    } else {
        let height = object
            .get("blockHeight")
            .and_then(Value::as_number)
            .and_then(Number::as_i64)
            .and_then(|height| u32::try_from(height).ok())
            .filter(|height| *height >= 1)
            .ok_or(IndexerError::Malformed)?;
        Some((height, u64::from(bb_u32(object, "blockTime")?)))
    };
    let mut inputs = Vec::new();
    let mut unknown_inputs = false;
    for input in list(object, "vin")? {
        let input = input.as_object().ok_or(IndexerError::Malformed)?;
        if input.get("coinbase").is_some() {
            inputs.push((None, 0));
            continue;
        }
        let value = match input.get("value") {
            Some(value) => Some(bb_amount(Some(value), false)?.1),
            None => None,
        };
        let address = bb_address(input)?;
        let no_address = input.get("isAddress").and_then(Value::as_bool) == Some(false);
        match (value, address) {
            // A non-address script (never one of ours).
            (Some(value), _) if no_address => inputs.push((None, value)),
            (Some(value), Some(address)) => inputs.push((Some(address), value)),
            // Unresolved (often a parent still in the mempool): fail closed.
            _ => {
                unknown_inputs = true;
                inputs.push((None, 0));
            }
        }
    }
    let mut outputs = Vec::new();
    for output in list(object, "vout")? {
        let output = output.as_object().ok_or(IndexerError::Malformed)?;
        let (_, value) = bb_amount(output.get("value"), false)?;
        let address = bb_address(output)?
            .filter(|_| output.get("isAddress").and_then(Value::as_bool) != Some(false));
        outputs.push((address, value));
    }
    Ok(AddrTx {
        txid,
        confirmed,
        inputs,
        outputs,
        unknown_inputs,
    })
}

/// Parses a Blockbook `address/{a}?details=txs` answer (`bb-rest` body or `bb-rpc`
/// `bb_getAddress` result): the address echo must match; `transactions` may be absent (none).
///
/// # Errors
///
/// [`IndexerError::Malformed`].
pub fn parse_bb_txs(value: &Value, requested: &str) -> Result<Vec<AddrTx>, IndexerError> {
    let object = value.as_object().ok_or(IndexerError::Malformed)?;
    if object
        .get("address")
        .is_some_and(|echo| echo.as_str() != Some(requested))
    {
        return Err(IndexerError::Malformed);
    }
    let items = match object.get("transactions") {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(items)) => items,
        Some(_) => return Err(IndexerError::Malformed),
    };
    if items.len() > MAX_TXS {
        return Err(IndexerError::Malformed);
    }
    items
        .iter()
        .map(|item| bb_tx(item.as_object().ok_or(IndexerError::Malformed)?))
        .collect()
}

/// Whether one address's answer shows everything it has in the mempool: no transaction with
/// unknown inputs and, on Esplora, fewer than [`ESPLORA_MEMPOOL_PAGE`] unconfirmed ones
/// (Blockbook lists every mempool transaction on page 1; a flood is over the cap instead).
#[must_use]
pub fn answer_complete(indexer: BtcIndexer, txs: &[AddrTx]) -> bool {
    let mempool = txs.iter().filter(|tx| tx.confirmed.is_none()).count();
    !txs.iter().any(|tx| tx.unknown_inputs)
        && (indexer != BtcIndexer::Esplora || mempool < ESPLORA_MEMPOOL_PAGE)
}

/// The incoming transactions of `txs` for the account whose watch-set addresses (lowercase) are
/// `own`: no input from `own`, outputs paying `own`, inputs all known.
#[must_use]
pub fn derive<S: BuildHasher>(txs: &[AddrTx], own: &HashSet<String, S>) -> Found {
    let mut found = Found::default();
    let mut seen = HashSet::new();
    let ours = |address: &Option<String>| address.as_ref().is_some_and(|text| own.contains(text));
    for tx in txs {
        if !seen.insert(tx.txid.clone())
            || tx.unknown_inputs
            || tx.inputs.iter().any(|(address, _)| ours(address))
        {
            continue;
        }
        let paid: u64 = tx
            .outputs
            .iter()
            .filter(|(address, _)| ours(address))
            .map(|(_, value)| *value)
            .fold(0, u64::saturating_add);
        if !tx.outputs.iter().any(|(address, _)| ours(address)) {
            continue;
        }
        if paid < DUST_BTC_SATS {
            found.dust.push(tx.txid.clone());
            continue;
        }
        found.entries.push(Incoming {
            key: tx.txid.clone(),
            hash: tx.txid.clone(),
            time_ms: tx
                .confirmed
                .map(|(_, seconds)| seconds.saturating_mul(1_000)),
            block: tx.confirmed.map(|(height, _)| u64::from(height)),
            amount: Sats::new(paid).map_or_else(|| paid.to_string(), format_btc),
            symbol: "BTC".to_owned(),
            from: tx.inputs.iter().find_map(|(address, _)| address.clone()),
            from_note: None,
            pending: tx.confirmed.is_none(),
            amount_units: paid,
            via: Vec::new(),
        });
    }
    found
}

/// The read of one account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcReceivedWork {
    /// Cached account public key.
    pub account: BtcAccountKey,
    /// Watch set receive `[0, receive_count)`.
    pub receive_count: u32,
    /// Watch set change `[0, change_count)`.
    pub change_count: u32,
    /// The receive indices to read, in order (at most [`MAX_READ_ADDRESSES`], from
    /// [`read_indices`]).
    pub fetch: Vec<u32>,
    /// The list's pending rows (with the indices that paid them).
    pub pending: Vec<Incoming>,
    /// Chain-check inputs.
    pub chain: ChainInput,
    /// Automatic (skipped during the cooldown) or the user's `새로고침`.
    pub trigger: Trigger,
}

/// The receive indices a read asks for, in order (spec/04 §2.6, 2026-11-13): the 받기 address
/// (`last_used + 1`, or 0; also 0 in fixed-address mode), the newest issued one, the indices the
/// refresh saw a pending deposit on, those of the list's pending rows, then the newest
/// [`MAX_ADDRESSES`] used ones; each below `receive_next`, once, at most [`MAX_READ_ADDRESSES`].
/// Every one of them is already sent to the same indexer by the refresh (`[0, receive_next)`).
#[must_use]
pub fn read_indices(
    receive_next: u32,
    last_used: Option<u32>,
    fixed: bool,
    flagged: &[u32],
    pending: &[u32],
) -> Vec<u32> {
    let start = last_used.map_or(0, |last| last.saturating_add(1));
    let used = last_used.map_or_else(Vec::new, |last| {
        (0..=last.min(receive_next.saturating_sub(1)))
            .rev()
            .take(MAX_ADDRESSES)
            .collect::<Vec<u32>>()
    });
    let mut out: Vec<u32> = Vec::new();
    let candidates = fixed
        .then_some(0)
        .into_iter()
        .chain(core::iter::once(start))
        .chain(receive_next.checked_sub(1))
        .chain(flagged.iter().copied())
        .chain(pending.iter().copied())
        .chain(used);
    for index in candidates {
        if index < receive_next && !out.contains(&index) && out.len() < MAX_READ_ADDRESSES {
            out.push(index);
        }
    }
    out
}

fn error_text(error: BtcError, indexer: BtcIndexer) -> String {
    error
        .text(indexer)
        .unwrap_or_else(|| "Bitcoin 조회를 잠시 멈췄습니다".to_owned())
}

/// The vanished pending rows: up to [`BTC_PENDING_CHECK_MAX`] `TxStatus` checks of the rows
/// absent from `listed` whose addresses were all `covered`. Returns the confirmed rows and the
/// gone keys; everything else stays.
fn resolve_vanished(
    client: &BtcClient<'_>,
    session: &ChainSession,
    pending: &[Incoming],
    listed: &HashSet<&str>,
    covered: &[u32],
) -> (Vec<Incoming>, Vec<String>) {
    let mut confirmed = Vec::new();
    let mut gone = Vec::new();
    let candidates = pending.iter().filter(|row| {
        row.pending
            && !listed.contains(row.key.as_str())
            && !row.via.is_empty()
            && row.via.iter().all(|index| covered.contains(index))
    });
    for row in candidates.take(BTC_PENDING_CHECK_MAX) {
        let Ok(txid) = Txid::from_display_hex(&row.hash) else {
            continue;
        };
        match address_request(client, session, &BtcIndexerReq::TxStatus(txid)) {
            Ok(BtcIndexerResp::TxStatus(TxSeen::Confirmed { height })) => {
                confirmed.push(Incoming {
                    pending: false,
                    block: Some(u64::from(height)),
                    time_ms: None,
                    ..row.clone()
                });
            }
            // The complete address lists no longer have it: replaced or dropped. Esplora also
            // answers `{"confirmed":false}` for an unknown txid.
            Ok(BtcIndexerResp::TxStatus(TxSeen::NotFound | TxSeen::UnconfirmedOrUnknown)) => {
                gone.push(row.key.clone());
            }
            // Blockbook still has it in its mempool, or no usable answer: decided next read.
            _ => {}
        }
    }
    (confirmed, gone)
}

/// One read on the session's request line.
///
/// # Errors
///
/// A fixed error text.
pub fn fetch(
    client: &BtcClient<'_>,
    session: &mut ChainSession,
    work: &BtcReceivedWork,
) -> Result<Fetched, String> {
    let indexer = client.endpoint().indexer;
    if work.fetch.is_empty() {
        return Ok(Fetched::default());
    }
    match cooldown_gate(client, work.trigger) {
        // An automatic read during the 429 cooldown: nothing asked, nothing changes.
        Err(BtcError::Cooldown) => return Ok(Fetched::default()),
        Err(error) => return Err(error_text(error, indexer)),
        Ok(()) => {}
    }
    ensure_chain(client, session, work.chain, false).map_err(|e| error_text(e, indexer))?;
    let net = session.network();
    let mut own = HashSet::new();
    for (chain, count) in [
        (BtcChain::Receive, work.receive_count),
        (BtcChain::Change, work.change_count),
    ] {
        for index in 0..count.min(BTC_MAX_ADDRESS_INDEX) {
            let address = work
                .account
                .address(net, chain, index)
                .map_err(|_| error_text(BtcError::Derivation, indexer))?;
            own.insert(address.as_str().to_ascii_lowercase());
        }
    }
    let mut txs: Vec<AddrTx> = Vec::new();
    let mut paid_at: HashMap<String, Vec<u32>> = HashMap::new();
    let mut covered = Vec::new();
    let mut answered = 0_usize;
    let mut rejected = 0_usize;
    let mut skipped = None;
    // The UI bounds and orders the list ([`read_indices`]); before 2026-11-13 this loop cut it
    // to the first `MAX_ADDRESSES`.
    let asked: Vec<u32> = work
        .fetch
        .iter()
        .copied()
        .take(MAX_READ_ADDRESSES)
        .collect();
    for index in &asked {
        let address = work
            .account
            .address(net, BtcChain::Receive, *index)
            .map_err(|_| error_text(BtcError::Derivation, indexer))?;
        match address_request(client, session, &BtcIndexerReq::AddressTxs(address)) {
            Ok(BtcIndexerResp::AddressTxs(list)) => {
                answered = answered.saturating_add(1);
                if answer_complete(indexer, &list) {
                    covered.push(*index);
                }
                for tx in &list {
                    let at = paid_at.entry(tx.txid.clone()).or_default();
                    if !at.contains(index) {
                        at.push(*index);
                    }
                }
                txs.extend(list);
            }
            Ok(_) => skipped = Some(BtcError::Indexer(IndexerError::Malformed)),
            // One address the indexer cannot answer: the others still count (that address is
            // incomplete, so its pending rows stay).
            Err(error @ BtcError::Indexer(IndexerError::Rejected)) => {
                rejected = rejected.saturating_add(1);
                skipped = Some(error);
            }
            Err(error @ BtcError::Indexer(IndexerError::Malformed)) => skipped = Some(error),
            Err(error) => return Err(error_text(error, indexer)),
        }
    }
    if answered == 0 {
        if indexer != BtcIndexer::Esplora && rejected == asked.len() {
            // A Blockbook without `details=txs`: no more automatic reads (`새로고침` retries).
            return Ok(Fetched {
                unsupported: Some(T_BB_NO_TXS),
                ..Fetched::default()
            });
        }
        if let Some(error) = skipped {
            return Err(error_text(error, indexer));
        }
    }
    let mut found = derive(&txs, &own);
    for entry in &mut found.entries {
        entry.via = paid_at.get(&entry.key).cloned().unwrap_or_default();
    }
    let listed: HashSet<&str> = txs.iter().map(|tx| tx.txid.as_str()).collect();
    let (confirmed, gone) = resolve_vanished(client, session, &work.pending, &listed, &covered);
    found.entries.extend(confirmed);
    Ok(Fetched {
        found,
        cursor: Cursor::Start,
        gone,
        covered,
        ..Fetched::default()
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use yw_json::Limits;

    use super::{derive, parse_txs, read_indices};

    const OURS: &str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    const CHANGE: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
    const THEIRS: &str = "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";

    fn tx(txid: char, vin: &str, vout: &str, status: &str) -> String {
        format!(
            r#"{{"txid":"{}","version":2,"locktime":0,"vin":[{vin}],"vout":[{vout}],"size":200,"weight":600,"fee":300,"status":{status}}}"#,
            txid.to_string().repeat(64)
        )
    }

    fn input(address: &str, value: u64) -> String {
        format!(
            r#"{{"txid":"{}","vout":0,"prevout":{{"scriptpubkey":"0014","scriptpubkey_address":"{address}","value":{value}}},"is_coinbase":false}}"#,
            "f".repeat(64)
        )
    }

    fn output(address: &str, value: u64) -> String {
        format!(r#"{{"scriptpubkey":"0014","scriptpubkey_address":"{address}","value":{value}}}"#)
    }

    const CONFIRMED: &str =
        r#"{"confirmed":true,"block_height":870000,"block_hash":"00","block_time":1730000000}"#;
    const MEMPOOL: &str = r#"{"confirmed":false}"#;

    /// A small `/address/{a}/txs` fixture: a deposit, a pending deposit, our own send with
    /// change, a dust (poisoning) output and a coinbase.
    #[test]
    fn esplora_txs_to_own_addresses_become_rows_and_dust() {
        let text = format!(
            "[{},{},{},{},{}]",
            tx(
                'a',
                &input(THEIRS, 60_000),
                &format!("{},{}", output(OURS, 50_000), output(THEIRS, 9_000)),
                CONFIRMED
            ),
            tx('b', &input(THEIRS, 30_000), &output(OURS, 25_000), MEMPOOL),
            tx(
                'c',
                &input(OURS, 50_000),
                &format!("{},{}", output(THEIRS, 20_000), output(CHANGE, 29_000)),
                CONFIRMED
            ),
            tx('d', &input(THEIRS, 2_000), &output(OURS, 546), CONFIRMED),
            tx(
                'e',
                r#"{"txid":"0000000000000000000000000000000000000000000000000000000000000000","vout":4294967295,"prevout":null,"is_coinbase":true}"#,
                &output(OURS, 312_500_000),
                CONFIRMED
            ),
        );
        let value = yw_json::parse(text.as_bytes(), &Limits::RESPONSE).unwrap();
        let txs = parse_txs(&value).unwrap();
        assert_eq!(txs.len(), 5);
        let own: HashSet<String> = [OURS, CHANGE].iter().map(|a| (*a).to_owned()).collect();
        let found = derive(&txs, &own);
        let rows: Vec<(&str, bool, Option<&str>)> = found
            .entries
            .iter()
            .map(|row| (row.amount.as_str(), row.pending, row.from.as_deref()))
            .collect();
        assert_eq!(
            rows,
            [
                ("0.00050000", false, Some(THEIRS)),
                ("0.00025000", true, Some(THEIRS)),
                ("3.12500000", false, None),
            ]
        );
        assert_eq!(found.entries[0].time_ms, Some(1_730_000_000_000));
        assert_eq!(found.entries[0].block, Some(870_000));
        assert_eq!(found.entries[1].block, None);
        assert_eq!(
            found.dust,
            ["d".repeat(64)],
            "546 sats is dust; our send is skipped"
        );
        // Malformed answers are refused.
        for bad in [
            "{}".to_owned(),
            tx('A', "", &output(OURS, 1), CONFIRMED),
            tx('a', "", &output(OURS, 1), r#"{"x":1}"#),
            tx('a', "", &output(OURS, 1), r#"{"confirmed":true}"#),
            tx('a', "", &output(OURS, 1).replace("1}", "-1}"), CONFIRMED),
        ] {
            let value = yw_json::parse(format!("[{bad}]").as_bytes(), &Limits::RESPONSE).unwrap();
            assert!(parse_txs(&value).is_err(), "{bad}");
        }
    }

    /// 2026-11-13 (spec/04 §2.6): the 받기 address and the newest issued one come first, then
    /// the refresh-flagged and pending-row addresses, then the newest used ones; each once,
    /// below `receive_next`, at most 12.
    #[test]
    fn read_indices_take_the_receive_address_first() {
        assert_eq!(read_indices(3, None, false, &[], &[]), [0, 2]);
        assert_eq!(
            read_indices(12, Some(7), false, &[], &[]),
            [8, 11, 7, 6, 5, 4, 3]
        );
        assert_eq!(
            read_indices(12, Some(7), false, &[1, 40], &[0, 8]),
            [8, 11, 1, 0, 7, 6, 5, 4, 3]
        );
        // Fixed-address mode: always index 0.
        assert_eq!(read_indices(1, Some(0), true, &[], &[]), [0]);
        assert!(read_indices(0, None, false, &[], &[]).is_empty());
        let many: Vec<u32> = (20..40).collect();
        assert_eq!(read_indices(100, Some(50), false, &many, &[]).len(), 12);
    }

    /// Fail closed: an Esplora input without its prevout that is not a coinbase makes the
    /// transaction unknown (no row, no dust) and the answer incomplete; 50 unconfirmed entries
    /// (Esplora's mempool page) are incomplete too.
    #[test]
    fn unknown_inputs_and_full_mempool_pages_are_incomplete() {
        use super::{ESPLORA_MEMPOOL_PAGE, answer_complete};
        use crate::settings::BtcIndexer;
        let orphan = r#"{"txid":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","vout":0,"prevout":null,"is_coinbase":false}"#;
        let text = format!("[{}]", tx('a', orphan, &output(OURS, 90_000), MEMPOOL));
        let value = yw_json::parse(text.as_bytes(), &Limits::RESPONSE).unwrap();
        let txs = parse_txs(&value).unwrap();
        assert!(txs[0].unknown_inputs);
        assert!(!answer_complete(BtcIndexer::Esplora, &txs));
        let own: HashSet<String> = [OURS.to_owned()].into_iter().collect();
        let found = derive(&txs, &own);
        assert!(found.entries.is_empty() && found.dust.is_empty());
        // A page of mempool entries.
        let page: Vec<String> = (0..ESPLORA_MEMPOOL_PAGE)
            .map(|n| {
                format!(
                    r#"{{"txid":"{n:064x}","vin":[{}],"vout":[{}],"status":{MEMPOOL}}}"#,
                    input(THEIRS, 2_000),
                    output(OURS, 1_000)
                )
            })
            .collect();
        let value = yw_json::parse(
            format!("[{}]", page.join(",")).as_bytes(),
            &Limits::RESPONSE,
        )
        .unwrap();
        let txs = parse_txs(&value).unwrap();
        assert!(!answer_complete(BtcIndexer::Esplora, &txs));
        assert!(answer_complete(BtcIndexer::Esplora, &txs[1..]));
        // Blockbook lists every mempool transaction on page 1: its size is no signal.
        assert!(answer_complete(BtcIndexer::BbRest, &txs));
    }

    fn bb_tx(txid: char, confirmations: u32, vin: &str, vout: &str) -> String {
        format!(
            r#"{{"txid":"{}","version":2,"vin":[{vin}],"vout":[{vout}],"blockHash":"00","blockHeight":{},"confirmations":{confirmations},"blockTime":{},"value":"1","valueIn":"1","fees":"0"}}"#,
            txid.to_string().repeat(64),
            if confirmations == 0 { -1 } else { 870_000 },
            if confirmations == 0 {
                1_731_000_000
            } else {
                1_730_000_000
            }
        )
    }

    fn bb_in(address: &str, value: u64) -> String {
        format!(
            r#"{{"txid":"{}","vout":1,"n":0,"addresses":["{address}"],"isAddress":true,"value":"{value}"}}"#,
            "e".repeat(64)
        )
    }

    fn bb_out(address: &str, value: u64) -> String {
        format!(r#"{{"value":"{value}","n":0,"addresses":["{address}"],"isAddress":true}}"#)
    }

    /// Blockbook `details=txs` (2026-11-13, spec/08 §4.3): a mempool deposit (its first-seen
    /// `blockTime` ignored), a confirmed one, a coinbase, an `OP_RETURN` output, a
    /// multi-address output, and an input Blockbook could not resolve (fail closed).
    #[test]
    fn blockbook_address_txs_become_rows() {
        use super::parse_bb_txs;
        let coinbase = r#"{"n":0,"coinbase":"03aabbcc","isAddress":false,"value":"0"}"#;
        let op_return = r#"{"value":"0","n":1,"addresses":["OP_RETURN 6869"],"isAddress":false}"#;
        let multi = r#"{"value":"5000","n":2,"addresses":["a1","b2"],"isAddress":true}"#;
        let unresolved = format!(r#"{{"txid":"{}","vout":0,"n":0}}"#, "d".repeat(64));
        let text = format!(
            r#"{{"page":1,"totalPages":1,"itemsOnPage":25,"address":"{OURS}","balance":"0","txs":4,"transactions":[{},{},{},{}]}}"#,
            bb_tx(
                'a',
                0,
                &bb_in(THEIRS, 60_000),
                &format!("{},{}", bb_out(OURS, 50_000), op_return)
            ),
            bb_tx(
                'b',
                3,
                &bb_in(THEIRS, 30_000),
                &format!("{},{multi}", bb_out(OURS, 25_000))
            ),
            bb_tx('c', 9, coinbase, &bb_out(OURS, 312_500_000)),
            bb_tx('d', 0, &unresolved, &bb_out(OURS, 80_000)),
        );
        let value = yw_json::parse(text.as_bytes(), &Limits::RESPONSE).unwrap();
        let txs = parse_bb_txs(&value, OURS).unwrap();
        assert_eq!(txs.len(), 4);
        assert_eq!(txs[0].confirmed, None);
        assert_eq!(txs[1].confirmed, Some((870_000, 1_730_000_000)));
        assert_eq!(txs[0].outputs[1].0, None, "OP_RETURN");
        assert_eq!(txs[1].outputs[1].0, None, "two addresses");
        assert!(txs[3].unknown_inputs);
        let own: HashSet<String> = [OURS.to_owned()].into_iter().collect();
        let found = derive(&txs, &own);
        let rows: Vec<(&str, bool, u64)> = found
            .entries
            .iter()
            .map(|row| (row.amount.as_str(), row.pending, row.amount_units))
            .collect();
        assert_eq!(
            rows,
            [
                ("0.00050000", true, 50_000),
                ("0.00025000", false, 25_000),
                ("3.12500000", false, 312_500_000),
            ]
        );
        assert_eq!(found.entries[0].time_ms, None, "first-seen time ignored");
        // No `transactions`: an empty list.
        let empty = yw_json::parse(
            format!(r#"{{"address":"{OURS}","txs":0}}"#).as_bytes(),
            &Limits::RESPONSE,
        )
        .unwrap();
        assert!(parse_bb_txs(&empty, OURS).unwrap().is_empty());
    }

    /// Tampered Blockbook answers are refused as a whole (spec/09 BTC-N9).
    #[test]
    fn blockbook_address_txs_malformed() {
        use super::{MAX_TXS, parse_bb_txs};
        let page =
            |transactions: &str| format!(r#"{{"address":"{OURS}","transactions":{transactions}}}"#);
        let deposit = |vout: &str| bb_tx('a', 0, &bb_in(THEIRS, 60_000), vout);
        let too_many = format!(
            "[{}]",
            vec![deposit(&bb_out(OURS, 5_000)); MAX_TXS + 1].join(",")
        );
        for bad in [
            format!(r#"{{"address":"{THEIRS}","transactions":[]}}"#),
            page(&format!(
                "[{}]",
                deposit(r#"{"value":5000,"addresses":["x"]}"#)
            )),
            page(&format!(
                "[{}]",
                deposit(&bb_out(OURS, 5_000).replace("\"5000\"", "\"-5000\""))
            )),
            page(&format!(
                "[{}]",
                deposit(&bb_out(OURS, 5_000).replace("\"5000\"", "\"05000\""))
            )),
            page(&format!(
                "[{}]",
                deposit(&bb_out(OURS, 5_000).replace("\"5000\"", "\"2100000000000001\""))
            )),
            page(&format!(
                "[{}]",
                bb_tx('a', 1, &bb_in(THEIRS, 1), &bb_out(OURS, 5_000))
                    .replace("\"blockHeight\":870000", "\"blockHeight\":-1")
            )),
            page(r#"{"x":1}"#),
            page(&too_many),
        ] {
            let value = yw_json::parse(bad.as_bytes(), &Limits::RESPONSE).unwrap();
            assert!(parse_bb_txs(&value, OURS).is_err(), "{bad}");
        }
    }
}
