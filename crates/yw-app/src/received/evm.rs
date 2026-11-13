//! EVM received history (spec/04 §2.6, 2026-11-11): ERC-20 `Transfer(address,address,uint256)`
//! logs of the chain's token-card tokens with `topics[2]` = the selected account, one
//! `eth_getLogs` over all of them per span. The scan is incremental: the first read looks back
//! [`FIRST_WINDOW`] blocks, later reads continue after the last block scanned (never more than
//! the window back). A provider "range too large / too many results" answer halves the span
//! (down to 1 block) and the span that worked is kept for the next read. At most
//! [`MAX_LOG_CALLS`] `eth_getLogs` per read; the rest continues on the next one.
//!
//! Native-coin deposits are plain value transfers without logs: standard RPC cannot list them,
//! so the card says so instead (no indexer is used).

use std::collections::HashSet;

use yw_core::evm::abi::{TOPIC_TRANSFER, pad_address};
use yw_core::evm::address::Address;
use yw_core::evm::amount::{U256, format_units};
use yw_json::{Object, Value};
use yw_win::http::{HttpError, HttpsUrl};

use super::{Cursor, Fetched, Found, Incoming, TokenRef, token_dust_units};
use crate::rpc::{RpcClient, RpcFailure, Transport, classify};
use crate::text::{json_object, json_str};

/// Blocks the first read looks back (and the most a later read looks back).
pub const FIRST_WINDOW: u64 = 5_000;
/// Most `eth_getLogs` calls of one read (range halvings included).
pub const MAX_LOG_CALLS: u32 = 8;
/// Most block headers read for the time of new rows per read (`blockTimestamp` of the log is
/// used when the provider sends it).
pub const MAX_TIME_LOOKUPS: usize = 5;
/// `eth_getLogs` response bound.
pub const MAX_LOGS_RESPONSE: usize = 2 * 1_048_576;
/// Most logs taken from one answer.
pub const MAX_LOGS: usize = 1_000;

/// The line of the card when `eth_getLogs` is missing on the endpoint.
pub const T_NO_GET_LOGS: &str = "이 RPC는 eth_getLogs를 지원하지 않아 받은 토큰 내역을 표시하지 않습니다 — 탐색기에서 확인하세요.";

/// One parsed `Transfer` log to the owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferLog {
    /// Token contract.
    pub token: Address,
    /// Sender (`topics[1]`).
    pub from: Address,
    /// Amount (`data`).
    pub value: U256,
    /// Block.
    pub block: u64,
    /// `blockTimestamp` (seconds) when the provider sent it.
    pub timestamp: Option<u64>,
    /// Transaction hash.
    pub tx_hash: [u8; 32],
    /// Log index.
    pub log_index: u64,
}

/// Why one `eth_getLogs` failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogsError {
    /// The provider limits the range or result count (any JSON-RPC error other than a missing
    /// method or HTTP-style 429, HTTP 400/413, or an answer over the response bound): halve.
    TooLarge,
    /// `-32601`: the endpoint has no `eth_getLogs`.
    Unsupported,
    /// Anything else (transport, timeout, auth, rate limit): stop this read.
    Failed(RpcFailure),
}

/// Classifies a failed `eth_getLogs` (the remote `error.message` is never read).
#[must_use]
pub const fn logs_error(failure: RpcFailure, over_limit: bool) -> LogsError {
    if over_limit {
        return LogsError::TooLarge;
    }
    match failure {
        RpcFailure::Rpc(-32_601) => LogsError::Unsupported,
        RpcFailure::Rpc(429) => LogsError::Failed(failure),
        RpcFailure::Rpc(_)
        | RpcFailure::Status(400 | 413)
        | RpcFailure::Http(HttpError::TooLarge) => LogsError::TooLarge,
        other => LogsError::Failed(other),
    }
}

fn quantity(value: u64) -> Value {
    json_str(&crate::rpc::canonical_quantity(value))
}

fn hex_value(value: &Value) -> Option<Vec<u8>> {
    let digits = value.as_str()?.strip_prefix("0x")?;
    yw_core::hex::decode(digits).ok()
}

fn u64_quantity(value: Option<&Value>) -> Option<u64> {
    U256::parse_quantity_lenient(value?.as_str()?)
        .ok()?
        .to_u64()
}

fn word(value: &Value) -> Option<[u8; 32]> {
    hex_value(value)?.try_into().ok()
}

fn tail_address(word: &[u8; 32]) -> Option<Address> {
    let (head, tail) = word.split_at(12);
    if head.iter().any(|byte| *byte != 0) {
        return None;
    }
    Some(Address::from_bytes(tail.try_into().ok()?))
}

/// The `eth_getLogs` filter: `Transfer` to `owner` from any of `tokens` in `[from, to]`.
#[must_use]
pub fn filter(tokens: &[TokenRef], owner: &Address, from: u64, to: u64) -> Value {
    json_object(vec![
        ("fromBlock", quantity(from)),
        ("toBlock", quantity(to)),
        (
            "address",
            Value::Array(
                tokens
                    .iter()
                    .map(|token| json_str(&token.address.to_lower_hex()))
                    .collect(),
            ),
        ),
        (
            "topics",
            Value::Array(vec![
                json_str(&format!("0x{}", yw_core::hex::encode(&TOPIC_TRANSFER))),
                Value::Null,
                json_str(&format!("0x{}", yw_core::hex::encode(&pad_address(owner)))),
            ]),
        ),
    ])
}

fn parse_log(object: &Object, tokens: &[TokenRef], owner: &Address) -> Option<TransferLog> {
    if object.get("removed").and_then(Value::as_bool) == Some(true) {
        return None;
    }
    let token = Address::from_bytes(hex_value(object.get("address")?)?.try_into().ok()?);
    // Only the tokens asked for: an endpoint cannot add another contract's logs.
    if !tokens.iter().any(|known| known.address == token) {
        return None;
    }
    let topics = object.get("topics")?.as_array()?;
    // ERC-20 only: three topics and a 32-byte amount (ERC-721 `Transfer` has four topics).
    let [event, sender, recipient] = topics else {
        return None;
    };
    if word(event)? != TOPIC_TRANSFER || word(recipient)? != pad_address(owner) {
        return None;
    }
    let data: [u8; 32] = hex_value(object.get("data")?)?.try_into().ok()?;
    Some(TransferLog {
        token,
        from: tail_address(&word(sender)?)?,
        value: U256::from_be_bytes(data),
        block: u64_quantity(object.get("blockNumber"))?,
        timestamp: u64_quantity(object.get("blockTimestamp")),
        tx_hash: word(object.get("transactionHash")?)?,
        log_index: u64_quantity(object.get("logIndex"))?,
    })
}

/// The `Transfer` logs to `owner` of `tokens` in an `eth_getLogs` result; entries of another
/// shape, another contract or another recipient are skipped.
///
/// # Errors
///
/// `Malformed` when the result is not an array.
pub fn parse_logs(
    result: &Value,
    tokens: &[TokenRef],
    owner: &Address,
) -> Result<Vec<TransferLog>, RpcFailure> {
    let list = result.as_array().ok_or(RpcFailure::Malformed)?;
    Ok(list
        .iter()
        .take(MAX_LOGS)
        .filter_map(Value::as_object)
        .filter_map(|object| parse_log(object, tokens, owner))
        .collect())
}

/// One `eth_getLogs` over `[from, to]`.
///
/// # Errors
///
/// [`LogsError`].
pub fn get_logs(
    client: &RpcClient<'_>,
    url: &HttpsUrl,
    tokens: &[TokenRef],
    owner: &Address,
    from: u64,
    to: u64,
) -> Result<Vec<TransferLog>, LogsError> {
    let params = Value::Array(vec![filter(tokens, owner, from, to)]);
    let result = client
        .call_detailed(url, "eth_getLogs", params, MAX_LOGS_RESPONSE)
        .map_err(|error| logs_error(error.failure, error.over_limit))?;
    parse_logs(&result, tokens, owner).map_err(LogsError::Failed)
}

/// The listed rows and dust keys of `logs` (amounts below [`token_dust_units`] are dust).
#[must_use]
pub fn derive(logs: &[TransferLog], tokens: &[TokenRef]) -> Found {
    let mut found = Found::default();
    let mut keys = HashSet::new();
    for log in logs {
        let hash = format!("0x{}", yw_core::hex::encode(&log.tx_hash));
        let key = format!("{hash}:{}", log.log_index);
        if !keys.insert(key.clone()) {
            continue;
        }
        let Some(token) = tokens.iter().find(|token| token.address == log.token) else {
            continue;
        };
        if log.value < token_dust_units(token.decimals) {
            found.dust.push(key);
            continue;
        }
        found.entries.push(Incoming {
            key,
            hash,
            time_ms: log.timestamp.map(|seconds| seconds.saturating_mul(1_000)),
            block: Some(log.block),
            amount: format_units(&log.value, token.decimals),
            symbol: token.symbol.clone(),
            from: Some(log.from.to_lower_hex()),
            from_note: None,
            pending: false,
            ..Incoming::default()
        });
    }
    found
}

/// `eth_getBlockByNumber(n, false).timestamp` in seconds.
fn block_time(client: &RpcClient<'_>, url: &HttpsUrl, block: u64) -> Option<u64> {
    let result = client
        .call(
            url,
            "eth_getBlockByNumber",
            Value::Array(vec![quantity(block), Value::Bool(false)]),
        )
        .ok()?;
    u64_quantity(result.as_object()?.get("timestamp"))
}

/// The range plan of one read: `(from, span)` where the scan starts and with which span.
#[must_use]
pub fn start(cursor: &Cursor, latest: u64) -> (u64, u64) {
    let floor = latest.saturating_sub(FIRST_WINDOW.saturating_sub(1));
    match cursor {
        Cursor::Block { next, span } => ((*next).max(floor), (*span).clamp(1, FIRST_WINDOW)),
        _ => (floor, FIRST_WINDOW),
    }
}

/// Scans `[from, latest]` in spans, halving on [`LogsError::TooLarge`]. Returns the logs, the
/// next block to scan and the span that worked; an error only when nothing could be scanned.
///
/// # Errors
///
/// The first failure when no span succeeded ([`LogsError::TooLarge`] at span 1 included).
pub fn scan(
    get: &mut dyn FnMut(u64, u64) -> Result<Vec<TransferLog>, LogsError>,
    from: u64,
    latest: u64,
    mut span: u64,
) -> Result<(Vec<TransferLog>, u64, u64), LogsError> {
    let mut next = from;
    let mut logs = Vec::new();
    let mut calls = 0_u32;
    while next <= latest && calls < MAX_LOG_CALLS {
        let to = latest.min(next.saturating_add(span.saturating_sub(1)));
        calls = calls.saturating_add(1);
        match get(next, to) {
            Ok(batch) => {
                logs.extend(batch);
                next = to.saturating_add(1);
            }
            Err(LogsError::TooLarge) if span > 1 => span = (span / 2).max(1),
            Err(error) if next == from => return Err(error),
            // Progress was made: keep it, the next read retries from here.
            Err(_) => break,
        }
    }
    Ok((logs, next, span))
}

/// One read (after the worker's chain check).
///
/// # Errors
///
/// A fixed error text.
pub fn fetch(
    transport: &dyn Transport,
    url: &HttpsUrl,
    owner: &Address,
    tokens: &[TokenRef],
    cursor: &Cursor,
) -> Result<Fetched, String> {
    if tokens.is_empty() {
        return Ok(Fetched {
            cursor: cursor.clone(),
            ..Fetched::default()
        });
    }
    let client = RpcClient::new(transport);
    let latest = crate::rpc::evm::block_number(&client, url).map_err(|f| classify(f).text())?;
    let (from, span) = start(cursor, latest);
    if from > latest {
        return Ok(Fetched {
            cursor: cursor.clone(),
            ..Fetched::default()
        });
    }
    let mut get = |from, to| get_logs(&client, url, tokens, owner, from, to);
    let (logs, next, span) = match scan(&mut get, from, latest, span) {
        Ok(done) => done,
        Err(LogsError::Unsupported) => {
            return Ok(Fetched {
                found: Found::default(),
                cursor: cursor.clone(),
                unsupported: Some(T_NO_GET_LOGS),
                ..Fetched::default()
            });
        }
        Err(LogsError::Failed(failure)) => return Err(classify(failure).text()),
        Err(LogsError::TooLarge) => {
            return Err("RPC가 eth_getLogs 범위를 1블록으로 줄여도 답하지 않았습니다".to_owned());
        }
    };
    let mut found = derive(&logs, tokens);
    // Times of the listed rows without `blockTimestamp` (a few headers per read).
    let mut times: Vec<(u64, u64)> = Vec::new();
    for entry in &mut found.entries {
        let Some(block) = entry.block.filter(|_| entry.time_ms.is_none()) else {
            continue;
        };
        let known = times.iter().find(|(at, _)| *at == block).map(|(_, t)| *t);
        let seconds = match known {
            Some(seconds) => Some(seconds),
            None if times.len() < MAX_TIME_LOOKUPS => {
                let seconds = block_time(&client, url, block);
                if let Some(seconds) = seconds {
                    times.push((block, seconds));
                }
                seconds
            }
            None => None,
        };
        entry.time_ms = seconds.map(|seconds| seconds.saturating_mul(1_000));
    }
    Ok(Fetched {
        found,
        cursor: Cursor::Block { next, span },
        ..Fetched::default()
    })
}

#[cfg(test)]
mod tests {
    use yw_core::evm::address::Address;
    use yw_core::evm::amount::U256;
    use yw_json::Limits;

    use super::{
        Cursor, FIRST_WINDOW, LogsError, MAX_LOG_CALLS, TokenRef, TransferLog, derive, logs_error,
        parse_logs, scan, start,
    };
    use crate::rpc::RpcFailure;

    const OWNER: &str = "9858effd232b4033e47d90003d41ec34ecaeda94";
    const USDC: &str = "1c7d4b196cb0c7b01d743fbc6116a902379c7238";
    const OTHER: &str = "00000000000000000000000000000000000000aa";

    fn address(hex: &str) -> Address {
        Address::from_bytes(yw_core::hex::decode_array::<20>(hex).unwrap())
    }

    fn tokens() -> Vec<TokenRef> {
        vec![TokenRef {
            address: address(USDC),
            symbol: "USDC".to_owned(),
            decimals: 6,
        }]
    }

    fn log(token: &str, to: &str, value: u64, index: u64, extra: &str) -> String {
        format!(
            r#"{{"address":"0x{token}","topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","0x000000000000000000000000{from}","0x000000000000000000000000{to}"],"data":"0x{value:064x}","blockNumber":"0x10","transactionHash":"0x{hash}","logIndex":"0x{index:x}"{extra}}}"#,
            from = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
            hash = "ab".repeat(32),
        )
    }

    /// A small `eth_getLogs` fixture: one real transfer, one zero (poisoning), one dust, one of
    /// another contract, one to another account, a removed one and an ERC-721 shape.
    #[test]
    fn transfer_logs_to_the_account_become_rows_and_dust() {
        let erc721 = r#"{"address":"0x1c7d4b196cb0c7b01d743fbc6116a902379c7238","topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","0x0000000000000000000000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a","0x0000000000000000000000009858effd232b4033e47d90003d41ec34ecaeda94","0x0000000000000000000000000000000000000000000000000000000000000001"],"data":"0x","blockNumber":"0x10","transactionHash":"0x00","logIndex":"0x9"}"#;
        let text = format!(
            "[{},{},{},{},{},{},{erc721}]",
            log(
                USDC,
                OWNER,
                12_500_000,
                1,
                r#","blockTimestamp":"0x6553f100""#
            ),
            log(USDC, OWNER, 0, 2, ""),
            log(USDC, OWNER, 99, 3, ""),
            log(OTHER, OWNER, 5_000_000, 4, ""),
            log(USDC, OTHER, 5_000_000, 5, ""),
            log(USDC, OWNER, 5_000_000, 6, r#","removed":true"#),
        );
        let value = yw_json::parse(text.as_bytes(), &Limits::RESPONSE).unwrap();
        let logs = parse_logs(&value, &tokens(), &address(OWNER)).unwrap();
        assert_eq!(logs.len(), 3, "{logs:?}");
        let found = derive(&logs, &tokens());
        assert_eq!(found.entries.len(), 1);
        let row = &found.entries[0];
        assert_eq!(row.amount, "12.5");
        assert_eq!(row.symbol, "USDC");
        assert_eq!(row.block, Some(16));
        assert_eq!(row.time_ms, Some(0x6553_f100 * 1_000));
        assert_eq!(
            row.from.as_deref(),
            Some("0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a")
        );
        assert_eq!(row.key, format!("0x{}:1", "ab".repeat(32)));
        assert_eq!(found.dust.len(), 2, "zero and 99 units (< 0.0001 USDC)");
        assert!(parse_logs(&yw_json::Value::Null, &tokens(), &address(OWNER)).is_err());
    }

    #[test]
    fn getlogs_errors_halve_the_range_or_stop() {
        assert_eq!(
            logs_error(RpcFailure::Rpc(-32_005), false),
            LogsError::TooLarge
        );
        assert_eq!(
            logs_error(RpcFailure::Rpc(-32_602), false),
            LogsError::TooLarge
        );
        assert_eq!(
            logs_error(RpcFailure::Status(413), false),
            LogsError::TooLarge
        );
        assert_eq!(logs_error(RpcFailure::Malformed, true), LogsError::TooLarge);
        assert_eq!(
            logs_error(RpcFailure::Rpc(-32_601), false),
            LogsError::Unsupported
        );
        assert!(matches!(
            logs_error(RpcFailure::Status(429), false),
            LogsError::Failed(_)
        ));
    }

    /// A provider that answers only ranges of at most 1,000 blocks: 5,000 → 2,500 → 1,250 → 625
    /// works, then the read goes on with 625 until its call budget ends; the next read starts
    /// where it stopped with the span that worked.
    #[test]
    fn range_halves_on_a_limit_error_and_keeps_the_span() {
        let latest = 1_000_000;
        let (from, span) = start(&Cursor::Start, latest);
        assert_eq!((from, span), (latest - FIRST_WINDOW + 1, FIRST_WINDOW));
        let mut asked = Vec::new();
        let mut get = |from: u64, to: u64| {
            asked.push((from, to));
            if to - from + 1 > 1_000 {
                Err(LogsError::TooLarge)
            } else {
                Ok(Vec::<TransferLog>::new())
            }
        };
        let (_, next, span) = scan(&mut get, from, latest, span).unwrap();
        assert_eq!(span, 625);
        assert_eq!(asked.len(), MAX_LOG_CALLS as usize);
        assert_eq!(asked[3], (from, from + 624));
        assert_eq!(next, from + 5 * 625);
        assert_eq!(
            start(&Cursor::Block { next, span }, latest),
            (next, 625),
            "continues"
        );
        // Far behind (the window moved on): never more than the window back.
        assert_eq!(
            start(&Cursor::Block { next: 5, span: 625 }, latest),
            (latest - FIRST_WINDOW + 1, 625)
        );
        // Down to one block, then the error.
        let mut always = |_: u64, _: u64| Err(LogsError::TooLarge);
        assert_eq!(scan(&mut always, 10, 10_000, 4), Err(LogsError::TooLarge));
        let mut calls = 0;
        let mut once = |_: u64, _: u64| {
            calls += 1;
            if calls == 1 {
                Ok(Vec::new())
            } else {
                Err(LogsError::Failed(RpcFailure::Status(503)))
            }
        };
        assert_eq!(scan(&mut once, 10, 100, 50).unwrap().1, 60, "progress kept");
        assert_eq!(U256::from_u64(1), super::token_dust_units(2));
    }
}
