//! Bitcoin received history (spec/04 §2.6, spec/08, 2026-11-11): on the session's paced request
//! line (`BtcClient`: ≥ 200 ms apart, 429 back-off, an automatic read skipped during the 300 s
//! cooldown) and only after the session's chain check passed step 3, one Esplora
//! `GET /address/{a}/txs` (up to 50 mempool and 25 confirmed transactions) for each of the
//! newest used receive addresses of the selected account ([`MAX_ADDRESSES`]). A transaction is
//! incoming when none of its inputs spends from the account's watch set (receive and change) and
//! its outputs pay the account; the amount is the sum paid to the account. Other indexers
//! (`bb-rpc`, `bb-rest`) are not used for this.

use std::collections::HashSet;
use std::hash::BuildHasher;

use yw_core::bip32::path::BtcChain;
use yw_core::btc::account::BtcAccountKey;
use yw_core::btc::amount::format_btc;
use yw_core::btc::{BTC_MAX_ADDRESS_INDEX, MAX_MONEY, Sats};
use yw_json::{Object, Value};

use super::{Cursor, DUST_BTC_SATS, Fetched, Found, Incoming};
use crate::btc::chain::{ChainInput, ChainSession, ensure_chain};
use crate::btc::client::BtcClient;
use crate::btc::flow::{address_request, cooldown_gate};
use crate::btc::indexer::{BtcIndexerReq, BtcIndexerResp, IndexerError, esplora_uint};
use crate::btc::{BtcError, Trigger};
use crate::settings::BtcIndexer;

/// Most receive addresses read per refresh (the newest used ones).
pub const MAX_ADDRESSES: usize = 5;
/// Most transactions taken from one answer (Esplora sends at most 75).
pub const MAX_TXS: usize = 200;
/// The card's line when the indexer is not Esplora.
pub const T_NOT_ESPLORA: &str = "Bitcoin 받은 내역은 Esplora 인덱서로만 읽습니다(설정 → Bitcoin의 인덱서). 지금 인덱서에서는 표시하지 않습니다 — 탐색기에서 확인하세요.";

/// One transaction of `/address/{a}/txs`, as much as the history needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EsploraTx {
    /// Txid (display hex).
    pub txid: String,
    /// `(height, block_time)` when confirmed.
    pub confirmed: Option<(u32, u64)>,
    /// Each input's spent output: its address (`None`: coinbase or no address form) and value.
    pub inputs: Vec<(Option<String>, u64)>,
    /// Each output: its address (`None`: no address form) and value.
    pub outputs: Vec<(Option<String>, u64)>,
}

fn address_of(object: &Object) -> Option<String> {
    object
        .get("scriptpubkey_address")
        .and_then(Value::as_str)
        .filter(|text| (14..=90).contains(&text.len()) && text.is_ascii())
        .map(str::to_ascii_lowercase)
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

fn tx_of(object: &Object) -> Result<EsploraTx, IndexerError> {
    let txid = object
        .get("txid")
        .and_then(Value::as_str)
        .filter(|text| {
            text.len() == 64
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or(IndexerError::Malformed)?
        .to_owned();
    let list = |key: &str| {
        object
            .get(key)
            .and_then(Value::as_array)
            .ok_or(IndexerError::Malformed)
    };
    let mut inputs = Vec::new();
    for input in list("vin")? {
        let input = input.as_object().ok_or(IndexerError::Malformed)?;
        match input.get("prevout") {
            Some(Value::Object(prevout)) => inputs.push((address_of(prevout), value_of(prevout)?)),
            // Coinbase.
            Some(Value::Null) | None => inputs.push((None, 0)),
            Some(_) => return Err(IndexerError::Malformed),
        }
    }
    let mut outputs = Vec::new();
    for output in list("vout")? {
        let output = output.as_object().ok_or(IndexerError::Malformed)?;
        outputs.push((address_of(output), value_of(output)?));
    }
    Ok(EsploraTx {
        txid,
        confirmed: status_of(object.get("status").ok_or(IndexerError::Malformed)?)?,
        inputs,
        outputs,
    })
}

/// Parses an Esplora `/address/{a}/txs` answer.
///
/// # Errors
///
/// [`IndexerError::Malformed`].
pub fn parse_txs(value: &Value) -> Result<Vec<EsploraTx>, IndexerError> {
    let list = value.as_array().ok_or(IndexerError::Malformed)?;
    if list.len() > MAX_TXS {
        return Err(IndexerError::Malformed);
    }
    list.iter()
        .map(|item| tx_of(item.as_object().ok_or(IndexerError::Malformed)?))
        .collect()
}

/// The incoming transactions of `txs` for the account whose watch-set addresses (lowercase) are
/// `own`: no input from `own`, outputs paying `own`.
#[must_use]
pub fn derive<S: BuildHasher>(txs: &[EsploraTx], own: &HashSet<String, S>) -> Found {
    let mut found = Found::default();
    let mut seen = HashSet::new();
    let ours = |address: &Option<String>| address.as_ref().is_some_and(|text| own.contains(text));
    for tx in txs {
        if !seen.insert(tx.txid.clone()) || tx.inputs.iter().any(|(address, _)| ours(address)) {
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
    /// The receive indices to read, newest first (at most [`MAX_ADDRESSES`] are read).
    pub fetch: Vec<u32>,
    /// Chain-check inputs.
    pub chain: ChainInput,
    /// Automatic (skipped during the cooldown) or the user's `새로고침`.
    pub trigger: Trigger,
}

fn error_text(error: BtcError, indexer: BtcIndexer) -> String {
    error
        .text(indexer)
        .unwrap_or_else(|| "Bitcoin 조회를 잠시 멈췄습니다".to_owned())
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
    if indexer != BtcIndexer::Esplora {
        return Ok(Fetched {
            unsupported: Some(T_NOT_ESPLORA),
            ..Fetched::default()
        });
    }
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
    let mut txs = Vec::new();
    let mut skipped = None;
    for index in work.fetch.iter().take(MAX_ADDRESSES) {
        let address = work
            .account
            .address(net, BtcChain::Receive, *index)
            .map_err(|_| error_text(BtcError::Derivation, indexer))?;
        match address_request(client, session, &BtcIndexerReq::AddressTxs(address)) {
            Ok(BtcIndexerResp::AddressTxs(list)) => txs.extend(list),
            Ok(_) => skipped = Some(BtcError::Indexer(IndexerError::Malformed)),
            // One address the indexer cannot answer: the others still count.
            Err(error @ BtcError::Indexer(IndexerError::Malformed | IndexerError::Rejected)) => {
                skipped = Some(error);
            }
            Err(error) => return Err(error_text(error, indexer)),
        }
    }
    if txs.is_empty()
        && let Some(error) = skipped
    {
        return Err(error_text(error, indexer));
    }
    Ok(Fetched {
        found: derive(&txs, &own),
        cursor: Cursor::Start,
        ..Fetched::default()
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use yw_json::Limits;

    use super::{derive, parse_txs};

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
}
