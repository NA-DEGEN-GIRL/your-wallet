//! Zcash received history (spec/04 §2.6, spec/12 §4.1, 2026-11-11), transparent address only.
//!
//! Confirmed deposits: one insight-style `getaddressdeltas {"addresses":[a],"start":h,"end":tip}`
//! per read on the configured node (zcashd `-insightexplorer`), from the tip of the last
//! chain-checked refresh. The first read looks back [`FIRST_WINDOW`] blocks, later ones continue
//! after the last height scanned. A transaction is incoming when all of its deltas for the
//! address are positive (no spend of ours); the node names no sender.
//!
//! Unconfirmed deposits (2026-11-13), display only:
//! - `node`: the node's mempool, **without sending any address**: `getrawmempool` (txids), then
//!   `getrawtransaction <txid> 1` of txids not looked at before ([`ZEC_MEMPOOL_SCAN_MAX`] per
//!   read), each checked for an output to our P2PKH script (verbose `vout`, else the `hex`
//!   through `yw_core::zec::tx::transparent_parts`, v4/v5 only). A transaction spending one of
//!   our known outputs, or whose inputs cannot be read, is never a deposit (fail closed).
//! - `bb-rest`: no new request: the refresh snapshot's unconfirmed outputs (`height: None`) whose
//!   txid is not one of our journal sends.
//! - A pending row the source no longer has gets one `getrawtransaction <txid> 1`
//!   ([`ZEC_PENDING_CHECK_MAX`] per read): mined → a confirmed row; `-5` → gone when the endpoint
//!   can look up mined transactions (working deltas), else removed with neutral wording.
//! - The whole read has one time budget ([`ZEC_READ_BUDGET_MS`], worker clock, checked before
//!   every call after the first): the RPC worker is shared with approvals and broadcasts.
//!
//! Before 2026-11-13 a node without `getaddressdeltas` (`-32601`, e.g. Zebra) and the Blockbook
//! source showed a fixed "unsupported" line and stopped reading; now the card shows a muted
//! `limited` line and the unconfirmed part still runs.

use std::collections::{BTreeMap, HashSet};

use yw_core::zec::format_zec;
use yw_core::zec::tx::{MAX_MONEY, transparent_parts, txid_display};
use yw_json::{Number, Object, Value};
use yw_win::http::HttpsUrl;

use super::{Cursor, DUST_ZEC_ZATS, Fetched, Found, Incoming};
use crate::flow::evm::Clock;
use crate::logging::Field;
use crate::network::NetworkId;
use crate::rpc::{RpcClient, RpcFailure, Transport, classify};
use crate::settings::ZecIndexer;
use crate::zec::rpc::{TxStatus, tx_status};

/// Blocks the first read looks back (≈ 17 days at 75 s).
pub const FIRST_WINDOW: u32 = 20_000;
/// `getaddressdeltas` response bound.
pub const MAX_RESPONSE: usize = 4 * 1_048_576;
/// Most `getrawtransaction` calls of new mempool txids per read.
pub const ZEC_MEMPOOL_SCAN_MAX: usize = 30;
/// Time budget of one whole read (ms, worker clock).
pub const ZEC_READ_BUDGET_MS: u64 = 5_000;
/// Most status checks of vanished pending rows per read.
pub const ZEC_PENDING_CHECK_MAX: usize = 5;
/// Most mempool txids remembered as looked at.
pub const ZEC_SEEN_MAX: usize = 5_000;
/// A mempool larger than this is not scanned this read.
pub const ZEC_MEMPOOL_MAX_TXIDS: usize = 5_000;
/// `getrawmempool` response bound.
pub const MAX_MEMPOOL_RESPONSE: usize = 512 * 1_024;
/// `getrawtransaction <txid> 1` response bound.
pub const MAX_TX_RESPONSE: usize = 1_048_576;
/// Longest verbose `scriptPubKey.hex` read.
const MAX_SCRIPT_HEX: usize = 20_000;

/// The card's line when the node or source has no address deltas (before 2026-11-13 it ended the
/// reads; kept for that meaning, no longer returned).
pub const T_NO_DELTAS: &str = "이 Zcash 엔드포인트는 주소 내역 조회(getaddressdeltas)를 지원하지 않아 받은 내역을 표시하지 않습니다 — 탐색기에서 확인하세요.";
/// The muted `limited` line of a source without deltas (Zebra, `bb-rest`).
pub const T_NO_DELTAS_PENDING: &str = "이 Zcash 엔드포인트는 주소 내역 조회(getaddressdeltas)를 지원하지 않아 확인된 받은 내역은 표시하지 않습니다 — 미확정 입금과, 여기서 미확정으로 본 뒤 채굴된 입금만 보입니다.";
/// The mempool was too large to scan this read.
pub const T_MEMPOOL_BIG: &str = "멤풀 거래가 너무 많아 이번에는 미확정 입금을 찾지 않았습니다.";
/// The node has no `getrawmempool`.
pub const T_MEMPOOL_NONE: &str = "이 Zcash 엔드포인트는 멤풀 조회(getrawmempool)를 지원하지 않아 미확정 입금을 표시하지 않습니다.";
/// `getrawmempool` failed this read.
pub const T_MEMPOOL_ERR: &str = "이번에는 멤풀을 읽지 못해 미확정 입금을 갱신하지 않았습니다.";
/// The scan stopped at its count or time bound.
pub const T_MEMPOOL_PARTIAL: &str =
    "멤풀 거래가 많아 일부만 확인했습니다 — 나머지는 다음 읽기에서 확인합니다.";
/// The sender line of every row (the deltas carry only our own address).
pub const T_NO_SENDER: &str = "보낸 주소: 노드 응답에 없어 표시하지 않습니다";
/// The error when the answer is over its bound (a dust flood): that range is skipped.
pub const T_TOO_MANY: &str = "이 범위의 주소 내역이 너무 많아(먼지 입금 등) 건너뛰었습니다";

/// One `getaddressdeltas` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delta {
    /// Txid (display hex).
    pub txid: String,
    /// Zats (negative: a spend of ours).
    pub zats: i64,
    /// Height.
    pub height: u64,
}

fn delta_of(object: &Object) -> Option<Delta> {
    let txid = object.get("txid")?.as_str()?;
    if txid.len() != 64 || !txid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(Delta {
        txid: txid.to_ascii_lowercase(),
        zats: object
            .get("satoshis")?
            .as_number()
            .and_then(Number::as_i64)?,
        height: object.get("height")?.as_number().and_then(Number::as_u64)?,
    })
}

/// Parses a `getaddressdeltas` result (an array, or `{"deltas": […]}` with `chainInfo`).
///
/// # Errors
///
/// `Malformed` when there is no list.
pub fn parse_deltas(result: &Value) -> Result<Vec<Delta>, RpcFailure> {
    let list = match result {
        Value::Array(list) => list,
        Value::Object(object) => object
            .get("deltas")
            .and_then(Value::as_array)
            .ok_or(RpcFailure::Malformed)?,
        _ => return Err(RpcFailure::Malformed),
    };
    Ok(list
        .iter()
        .filter_map(Value::as_object)
        .filter_map(delta_of)
        .collect())
}

/// A row of `zats` paid by `txid`: pending unless `mined`.
fn row(txid: &str, zats: u64, mined: Option<u32>) -> Incoming {
    Incoming {
        key: txid.to_owned(),
        hash: txid.to_owned(),
        time_ms: None,
        block: mined.map(u64::from),
        amount: format_zec(zats),
        symbol: "ZEC".to_owned(),
        from: None,
        from_note: Some(T_NO_SENDER),
        pending: mined.is_none(),
        amount_units: zats,
        via: Vec::new(),
    }
}

/// The incoming transactions of `deltas`: every delta of the txid positive (a zero sum is dust).
#[must_use]
pub fn derive(deltas: &[Delta]) -> Found {
    let mut by_tx: BTreeMap<&str, (i128, bool, u64)> = BTreeMap::new();
    for delta in deltas {
        let slot = by_tx.entry(&delta.txid).or_insert((0, false, delta.height));
        slot.0 = slot.0.saturating_add(i128::from(delta.zats));
        slot.1 |= delta.zats < 0;
        slot.2 = slot.2.max(delta.height);
    }
    let mut found = Found::default();
    for (txid, (sum, spent, height)) in by_tx {
        if spent {
            continue;
        }
        let zats = u64::try_from(sum).unwrap_or(0);
        if zats < DUST_ZEC_ZATS {
            found.dust.push(txid.to_owned());
            continue;
        }
        found.entries.push(Incoming {
            block: Some(height),
            pending: false,
            ..row(txid, zats, None)
        });
    }
    found
}

fn is_txid(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Parses a `getrawmempool` (non-verbose) answer: the valid txids, lowercase, once each, in
/// order (bad elements are dropped). `None` when it is not an array.
#[must_use]
pub fn parse_mempool(value: &Value) -> Option<Vec<String>> {
    let mut seen = HashSet::new();
    Some(
        value
            .as_array()?
            .iter()
            .filter_map(Value::as_str)
            .filter(|text| is_txid(text))
            .map(str::to_ascii_lowercase)
            .filter(|txid| seen.insert(txid.clone()))
            .collect(),
    )
}

/// What one mempool transaction is to us.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Look {
    /// Outputs or inputs could not be read (or the answer names another txid).
    Unreadable,
    /// No output to our script.
    Foreign,
    /// It spends one of our known outputs (our own send, here or in another wallet).
    OwnSpend,
    /// It pays our script `zats` in total; `mined` when the node already has it in a block.
    Paid {
        /// Sum of the outputs to our script.
        zats: u64,
        /// The block height when mined.
        mined: Option<u32>,
    },
}

fn verbose_outputs(object: &Object) -> Option<Vec<(u64, Vec<u8>)>> {
    object
        .get("vout")?
        .as_array()?
        .iter()
        .map(|output| {
            let output = output.as_object()?;
            let value = output
                .get("valueZat")?
                .as_number()
                .and_then(Number::as_u64)
                .filter(|value| *value <= MAX_MONEY)?;
            let hex = output
                .get("scriptPubKey")?
                .as_object()?
                .get("hex")?
                .as_str()
                .filter(|hex| hex.len() <= MAX_SCRIPT_HEX)?;
            Some((value, yw_core::hex::decode(hex).ok()?))
        })
        .collect()
}

fn verbose_inputs(object: &Object) -> Option<Vec<(String, u32)>> {
    let mut out = Vec::new();
    for input in object.get("vin")?.as_array()? {
        let input = input.as_object()?;
        if input.get("coinbase").is_some() {
            continue;
        }
        let txid = input.get("txid")?.as_str().filter(|text| is_txid(text))?;
        let index = input
            .get("vout")?
            .as_number()
            .and_then(Number::as_u64)
            .and_then(|index| u32::try_from(index).ok())?;
        out.push((txid.to_ascii_lowercase(), index));
    }
    Some(out)
}

/// Classifies a `getrawtransaction <txid> 1` answer for `txid` against our `script` and our
/// known outputs `own` (`(display txid, index)`). Verbose fields first, the `hex` (v4/v5) for
/// whatever they lack; anything unreadable is never a deposit.
#[must_use]
pub fn look<S: core::hash::BuildHasher>(
    value: &Value,
    txid: &str,
    script: &[u8],
    own: &HashSet<(String, u32), S>,
) -> Look {
    let Some(object) = value.as_object() else {
        return Look::Unreadable;
    };
    if let Some(echo) = object.get("txid")
        && !echo
            .as_str()
            .is_some_and(|echo| echo.eq_ignore_ascii_case(txid))
    {
        return Look::Unreadable;
    }
    let mined = object
        .get("height")
        .and_then(Value::as_number)
        .and_then(Number::as_u64)
        .filter(|height| *height > 0)
        .and_then(|height| u32::try_from(height).ok());
    let mut outputs = verbose_outputs(object);
    let mut inputs = verbose_inputs(object);
    if outputs.is_none() || inputs.is_none() {
        let Some(parts) = object
            .get("hex")
            .and_then(Value::as_str)
            .and_then(|hex| yw_core::hex::decode(hex).ok())
            .and_then(|bytes| transparent_parts(&bytes).ok())
        else {
            return Look::Unreadable;
        };
        outputs = outputs.or_else(|| {
            Some(
                parts
                    .outputs
                    .into_iter()
                    .map(|output| (output.value, output.script_pubkey))
                    .collect(),
            )
        });
        inputs = inputs.or_else(|| {
            Some(
                parts
                    .inputs
                    .iter()
                    .map(|point| (txid_display(&point.txid), point.index))
                    .collect(),
            )
        });
    }
    let (Some(outputs), Some(inputs)) = (outputs, inputs) else {
        return Look::Unreadable;
    };
    if inputs.iter().any(|input| own.contains(input)) {
        return Look::OwnSpend;
    }
    let ours: Vec<u64> = outputs
        .iter()
        .filter(|(_, bytes)| bytes.as_slice() == script)
        .map(|(value, _)| *value)
        .collect();
    if ours.is_empty() {
        return Look::Foreign;
    }
    let zats = ours.into_iter().fold(0_u64, u64::saturating_add);
    if zats > MAX_MONEY {
        return Look::Unreadable;
    }
    Look::Paid { zats, mined }
}

/// One Zcash read's inputs (built on the UI thread).
pub struct ZecReceivedWork {
    /// Network.
    pub network: yw_core::zec::ZecNetwork,
    /// Endpoint URL (secret).
    pub url: HttpsUrl,
    /// UTXO source (`bb-rest` has no address deltas and no mempool scan here).
    pub indexer: ZecIndexer,
    /// Our transparent address.
    pub address: String,
    /// The node tip of the last refresh (already chain-checked).
    pub tip: u32,
    /// Our P2PKH `scriptPubKey`.
    pub script: Vec<u8>,
    /// Txids of our journal sends (display hex, lowercase): never deposits.
    pub own_txids: Vec<String>,
    /// Our known outputs (snapshot UTXOs) as `(display txid, index)`.
    pub own_outpoints: Vec<(String, u32)>,
    /// The list's pending rows.
    pub pending: Vec<Incoming>,
    /// `bb-rest`: the snapshot's unconfirmed outputs summed per txid, journal txids removed.
    pub bb_pending: Vec<(String, u64)>,
    /// The user's `새로고침` (retries `getaddressdeltas` after a `-32601`).
    pub user: bool,
}

impl core::fmt::Debug for ZecReceivedWork {
    /// No URL (secret) and no address.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ZecReceivedWork")
    }
}

/// Counts of one mempool scan (logged as `received.mempool`; counts and fixed words only).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScanStats {
    /// Mempool txids listed.
    pub txids: usize,
    /// `getrawtransaction` calls made for new txids.
    pub scanned: usize,
    /// Deposits found.
    pub found: usize,
    /// Dust deposits.
    pub dust: usize,
    /// Unreadable answers.
    pub unreadable: usize,
    /// Answers over their bound.
    pub oversized: usize,
    /// Calls that failed (retried next read).
    pub failed: usize,
    /// Status checks of vanished rows.
    pub checked: usize,
    /// Where the scan stopped early: `none`, `count` or `time`.
    pub cap: &'static str,
}

impl ScanStats {
    /// The log fields (no address, amount, txid, URL or host).
    #[must_use]
    pub fn fields(&self, net: NetworkId) -> Vec<(&'static str, Field<'static>)> {
        let count = |items: usize| Field::Num(u64::try_from(items).unwrap_or(u64::MAX));
        vec![
            ("net", Field::Net(net)),
            ("txids", count(self.txids)),
            ("scanned", count(self.scanned)),
            ("found", count(self.found)),
            ("dust", count(self.dust)),
            ("unreadable", count(self.unreadable)),
            ("oversized", count(self.oversized)),
            ("failed", count(self.failed)),
            ("checked", count(self.checked)),
            ("cap", Field::Word(self.cap)),
        ]
    }
}

fn deltas_params(address: &str, start: u32, end: u32) -> Value {
    Value::Array(vec![Value::Object(
        Object::from_pairs(vec![
            (
                "addresses".to_owned(),
                Value::Array(vec![Value::String(address.to_owned())]),
            ),
            (
                "start".to_owned(),
                Value::Number(Number::from_u64(u64::from(start))),
            ),
            (
                "end".to_owned(),
                Value::Number(Number::from_u64(u64::from(end))),
            ),
        ])
        .unwrap_or_default(),
    )])
}

/// The mutable state of one read.
struct Read<'a> {
    client: RpcClient<'a>,
    clock: &'a dyn Clock,
    started: u64,
    work: &'a ZecReceivedWork,
    found: Found,
    stats: ScanStats,
    partial: bool,
}

impl Read<'_> {
    /// The read's time budget is spent (checked before every call after the first).
    fn spent(&mut self) -> bool {
        let over = self.clock.now_ms().saturating_sub(self.started) >= ZEC_READ_BUDGET_MS;
        if over {
            self.partial = true;
            self.stats.cap = "time";
        }
        over
    }

    /// Scans `fresh` mempool txids; returns those looked at for good (never a failed call).
    fn scan(&mut self, fresh: &[&String], own: &HashSet<(String, u32)>) -> Vec<String> {
        let mut seen = Vec::new();
        for txid in fresh {
            if self.stats.scanned >= ZEC_MEMPOOL_SCAN_MAX {
                self.partial = true;
                self.stats.cap = "count";
                break;
            }
            if self.spent() {
                break;
            }
            self.stats.scanned = self.stats.scanned.saturating_add(1);
            let params = Value::Array(vec![
                Value::String((*txid).clone()),
                Value::Number(Number::from_u64(1)),
            ]);
            match self.client.call_detailed(
                &self.work.url,
                "getrawtransaction",
                params,
                MAX_TX_RESPONSE,
            ) {
                Ok(value) => {
                    match look(&value, txid, &self.work.script, own) {
                        Look::Unreadable => {
                            self.stats.unreadable = self.stats.unreadable.saturating_add(1);
                        }
                        Look::Foreign | Look::OwnSpend => {}
                        Look::Paid { zats, .. } if zats < DUST_ZEC_ZATS => {
                            self.stats.dust = self.stats.dust.saturating_add(1);
                            self.found.dust.push((*txid).clone());
                        }
                        Look::Paid { zats, mined } => {
                            self.stats.found = self.stats.found.saturating_add(1);
                            self.found.entries.push(row(txid, zats, mined));
                            // A deposit is not `seen`: it is a list row from now on.
                            continue;
                        }
                    }
                    seen.push((*txid).clone());
                }
                Err(error) if error.over_limit => {
                    self.stats.oversized = self.stats.oversized.saturating_add(1);
                    seen.push((*txid).clone());
                }
                // Left the mempool meanwhile.
                Err(error) if error.failure == RpcFailure::Rpc(-5) => seen.push((*txid).clone()),
                // Any other failure: not `seen`, asked again next read.
                Err(_) => {
                    self.stats.failed = self.stats.failed.saturating_add(1);
                    self.partial = true;
                }
            }
        }
        seen
    }
}

/// One read.
///
/// # Errors
///
/// A fixed error text (a failed `getaddressdeltas`; the unconfirmed part never fails a read).
#[expect(
    clippy::too_many_lines,
    reason = "the read's steps in order (spec/12 §4.1)"
)]
pub fn fetch(
    transport: &dyn Transport,
    clock: &dyn Clock,
    work: &ZecReceivedWork,
    cursor: &Cursor,
) -> Result<Fetched, String> {
    let (mut next, mut deltas, old_seen) = match cursor {
        Cursor::Zec { next, deltas, seen } => (*next, *deltas, seen.clone()),
        _ => (None, true, Vec::new()),
    };
    let mut read = Read {
        client: RpcClient::new(transport),
        clock,
        started: clock.now_ms(),
        work,
        found: Found::default(),
        stats: ScanStats {
            cap: "none",
            ..ScanStats::default()
        },
        partial: false,
    };
    let mut note = None;
    let mut calls = 0_usize;
    // 1. Confirmed deposits (the node source only; after a `-32601` only on `새로고침`).
    if work.indexer == ZecIndexer::Node && (deltas || work.user) {
        let floor = work
            .tip
            .saturating_sub(FIRST_WINDOW.saturating_sub(1))
            .max(1);
        let start = next.map_or(floor, |next| next.max(floor));
        if start <= work.tip {
            calls = calls.saturating_add(1);
            match read.client.call_detailed(
                &work.url,
                "getaddressdeltas",
                deltas_params(&work.address, start, work.tip),
                MAX_RESPONSE,
            ) {
                Ok(result) => {
                    read.found =
                        derive(&parse_deltas(&result).map_err(|failure| classify(failure).text())?);
                    next = Some(work.tip.saturating_add(1));
                    deltas = true;
                }
                Err(error) if error.failure == RpcFailure::Rpc(-32_601) => deltas = false,
                // A dust flood: that range is skipped (never asked again) and the card says so.
                Err(error) if error.over_limit => {
                    next = Some(work.tip.saturating_add(1));
                    deltas = true;
                    note = Some(T_TOO_MANY);
                }
                Err(error) => return Err(classify(error.failure).text()),
            }
        }
    }
    let limited = (work.indexer != ZecIndexer::Node || !deltas).then_some(T_NO_DELTAS_PENDING);
    // 2. Unconfirmed deposits.
    let pending_keys: HashSet<&str> = work
        .pending
        .iter()
        .filter(|entry| entry.pending)
        .map(|entry| entry.key.as_str())
        .collect();
    let own_txids: HashSet<&str> = work.own_txids.iter().map(String::as_str).collect();
    let own: HashSet<(String, u32)> = work.own_outpoints.iter().cloned().collect();
    // The unconfirmed set as the source sees it now (`None`: unknown this read).
    let mut view: Option<HashSet<String>> = None;
    let mut mempool: Option<Vec<String>> = None;
    let mut new_seen = Vec::new();
    match work.indexer {
        ZecIndexer::BbRest => {
            let mut set = HashSet::new();
            for (txid, zats) in &work.bb_pending {
                if own_txids.contains(txid.as_str()) {
                    continue;
                }
                set.insert(txid.clone());
                if pending_keys.contains(txid.as_str()) {
                    continue;
                }
                if *zats < DUST_ZEC_ZATS {
                    read.found.dust.push(txid.clone());
                } else {
                    read.found.entries.push(row(txid, *zats, None));
                }
            }
            view = Some(set);
        }
        ZecIndexer::Node if calls > 0 && read.spent() => {}
        ZecIndexer::Node => {
            match read.client.call_detailed(
                &work.url,
                "getrawmempool",
                Value::Array(Vec::new()),
                MAX_MEMPOOL_RESPONSE,
            ) {
                Ok(value) => match parse_mempool(&value) {
                    Some(list) if list.len() <= ZEC_MEMPOOL_MAX_TXIDS => mempool = Some(list),
                    Some(_) => note = note.or(Some(T_MEMPOOL_BIG)),
                    None => note = note.or(Some(T_MEMPOOL_ERR)),
                },
                Err(error) if error.over_limit => note = note.or(Some(T_MEMPOOL_BIG)),
                Err(error) if error.failure == RpcFailure::Rpc(-32_601) => {
                    note = note.or(Some(T_MEMPOOL_NONE));
                }
                Err(_) => note = note.or(Some(T_MEMPOOL_ERR)),
            }
            if let Some(list) = &mempool {
                read.stats.txids = list.len();
                let old: HashSet<&str> = old_seen.iter().map(String::as_str).collect();
                let fresh: Vec<&String> = list
                    .iter()
                    .filter(|txid| {
                        !old.contains(txid.as_str())
                            && !pending_keys.contains(txid.as_str())
                            && !own_txids.contains(txid.as_str())
                    })
                    .collect();
                new_seen = read.scan(&fresh, &own);
                view = Some(list.iter().cloned().collect());
            }
        }
    }
    // 3. Pending rows the source no longer has.
    let mut gone = Vec::new();
    let mut dropped = Vec::new();
    if let Some(view) = &view {
        // `-5` means "never mined" only where mined transactions can be looked up: zcashd with
        // the insight index (which needs `-txindex`). Elsewhere the row goes with neutral words.
        let definitive = work.indexer == ZecIndexer::Node && deltas;
        let listed: HashSet<String> = read
            .found
            .entries
            .iter()
            .map(|entry| entry.key.clone())
            .collect();
        let vanished: Vec<&Incoming> = work
            .pending
            .iter()
            .filter(|entry| {
                entry.pending && !view.contains(&entry.key) && !listed.contains(&entry.key)
            })
            .collect();
        for entry in vanished {
            if read.stats.checked >= ZEC_PENDING_CHECK_MAX || read.spent() {
                break;
            }
            read.stats.checked = read.stats.checked.saturating_add(1);
            match tx_status(&read.client, &work.url, &entry.hash) {
                Ok(TxStatus::Mined(height)) => read.found.entries.push(Incoming {
                    pending: false,
                    block: Some(u64::from(height)),
                    time_ms: None,
                    ..entry.clone()
                }),
                Ok(TxStatus::NotFound) if definitive => gone.push(entry.key.clone()),
                Ok(TxStatus::NotFound) => dropped.push(entry.key.clone()),
                // Still known, or no answer: decided next read.
                Ok(TxStatus::Known) | Err(_) => {}
            }
        }
    }
    // 4. Txids looked at for good: those still in the mempool plus the new ones (unchanged
    // when there was no mempool list this read).
    let mut seen: Vec<String> = match &mempool {
        Some(list) => {
            let current: HashSet<&str> = list.iter().map(String::as_str).collect();
            old_seen
                .into_iter()
                .filter(|txid| current.contains(txid.as_str()))
                .collect()
        }
        None => old_seen,
    };
    seen.extend(new_seen);
    if seen.len() > ZEC_SEEN_MAX {
        seen.drain(..seen.len().saturating_sub(ZEC_SEEN_MAX));
    }
    if read.partial {
        note = note.or(Some(T_MEMPOOL_PARTIAL));
    }
    if work.indexer == ZecIndexer::Node {
        let network_id = NetworkId::Zcash(work.network);
        crate::logging::info("rpc", "received.mempool", &read.stats.fields(network_id));
        if read.stats.cap != "none" {
            crate::logging::info(
                "rpc",
                "received.mempool_cap",
                &[
                    ("net", Field::Net(network_id)),
                    ("limit", Field::Word(read.stats.cap)),
                ],
            );
        }
    }
    Ok(Fetched {
        found: read.found,
        cursor: Cursor::Zec { next, deltas, seen },
        limited,
        note,
        gone,
        dropped,
        ..Fetched::default()
    })
}

#[cfg(test)]
mod tests {
    use yw_json::Limits;

    use super::{T_NO_SENDER, derive, parse_deltas};

    /// A `getaddressdeltas` fixture (zcashd insight shape): a deposit in two outputs, our send
    /// (a spend and its change), a dust deposit.
    #[test]
    fn address_deltas_become_rows_and_dust() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let c = "c".repeat(64);
        let text = format!(
            r#"[
            {{"satoshis":150000,"txid":"{a}","index":0,"blockindex":3,"height":2800000,"address":"t1x"}},
            {{"satoshis":50000,"txid":"{a}","index":1,"blockindex":3,"height":2800000,"address":"t1x"}},
            {{"satoshis":-200000,"txid":"{b}","index":0,"blockindex":1,"height":2800100,"address":"t1x"}},
            {{"satoshis":90000,"txid":"{b}","index":2,"blockindex":1,"height":2800100,"address":"t1x"}},
            {{"satoshis":5000,"txid":"{c}","index":0,"blockindex":9,"height":2800200,"address":"t1x"}}
        ]"#
        );
        let value = yw_json::parse(text.as_bytes(), &Limits::RESPONSE).unwrap();
        let deltas = parse_deltas(&value).unwrap();
        assert_eq!(deltas.len(), 5);
        let found = derive(&deltas);
        assert_eq!(found.entries.len(), 1);
        assert_eq!(found.entries[0].amount, "0.00200000");
        assert_eq!(found.entries[0].block, Some(2_800_000));
        assert_eq!(found.entries[0].from_note, Some(T_NO_SENDER));
        assert_eq!(found.dust, [c]);
        let wrapped = yw_json::parse(
            format!(r#"{{"deltas":{text}}}"#).as_bytes(),
            &Limits::RESPONSE,
        )
        .unwrap();
        assert_eq!(parse_deltas(&wrapped).unwrap().len(), 5);
        assert!(parse_deltas(&yw_json::Value::Null).is_err());
    }

    /// The mempool scan over a scripted JSON-RPC fake and a manual clock (spec/12 §4.1, §14.1,
    /// spec/09 ZEC-N1, 2026-11-13).
    mod mempool {
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicU64, Ordering};

        use yw_core::zec::ZecNetwork;
        use yw_core::zec::tx::{ZecOutPoint, ZecTx, ZecTxIn, ZecTxOut, serialize_tx, txid_display};
        use yw_json::{Limits, Number, Object, Value};
        use yw_win::http::{HttpError, HttpsUrl};

        use super::super::{
            T_MEMPOOL_BIG, T_MEMPOOL_PARTIAL, T_NO_DELTAS_PENDING, ZEC_MEMPOOL_SCAN_MAX,
            ZEC_PENDING_CHECK_MAX, ZecReceivedWork, fetch,
        };
        use crate::flow::evm::Clock;
        use crate::received::{Cursor, Fetched, Incoming};
        use crate::rpc::{HttpReply, Transport};
        use crate::settings::ZecIndexer;

        const ADDRESS: &str = "tmTESTADDRESSxxxxxxxxxxxxxxxxxxxxxx";

        fn ours() -> Vec<u8> {
            yw_core::hex::decode(&format!("76a914{}88ac", "11".repeat(20))).unwrap()
        }

        fn script_hex(fill: &str) -> String {
            format!("76a914{}88ac", fill.repeat(20))
        }

        fn id(n: u32) -> String {
            format!("{n:064x}")
        }

        /// A scripted answer.
        #[derive(Clone)]
        enum Answer {
            Result(String),
            Code(i64),
            Big,
            Fail,
        }

        struct TestClock(AtomicU64);

        impl Clock for TestClock {
            fn now_ms(&self) -> u64 {
                self.0.load(Ordering::SeqCst)
            }
            fn now_unix_ms(&self) -> u64 {
                self.now_ms()
            }
            fn sleep_ms(&self, ms: u64) {
                self.0.fetch_add(ms, Ordering::SeqCst);
            }
        }

        type Handler = dyn Fn(&str, &[Value]) -> Answer + Send + Sync;

        struct Fake<'c> {
            handler: Box<Handler>,
            clock: &'c TestClock,
            step_ms: u64,
            calls: Mutex<Vec<(String, String)>>,
        }

        impl<'c> Fake<'c> {
            fn new(
                clock: &'c TestClock,
                step_ms: u64,
                handler: impl Fn(&str, &[Value]) -> Answer + Send + Sync + 'static,
            ) -> Self {
                Self {
                    handler: Box::new(handler),
                    clock,
                    step_ms,
                    calls: Mutex::new(Vec::new()),
                }
            }

            fn methods(&self) -> Vec<String> {
                self.calls
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|(method, _)| method.clone())
                    .collect()
            }

            fn count(&self, method: &str) -> usize {
                self.methods().iter().filter(|m| *m == method).count()
            }

            fn bodies(&self) -> Vec<String> {
                self.calls
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|(_, body)| body.clone())
                    .collect()
            }
        }

        impl Transport for Fake<'_> {
            fn post_json(
                &self,
                _url: &HttpsUrl,
                body: &[u8],
                _max_response: usize,
            ) -> Result<HttpReply, HttpError> {
                let request = yw_json::parse(body, &Limits::RESPONSE).unwrap();
                let object = request.as_object().unwrap();
                let method = object.get("method").and_then(Value::as_str).unwrap();
                let id = object
                    .get("id")
                    .and_then(Value::as_number)
                    .and_then(Number::as_u64)
                    .unwrap();
                let params = object
                    .get("params")
                    .and_then(Value::as_array)
                    .unwrap_or_default();
                self.calls
                    .lock()
                    .unwrap()
                    .push((method.to_owned(), String::from_utf8(body.to_vec()).unwrap()));
                self.clock.sleep_ms(self.step_ms);
                let member = match (self.handler)(method, params) {
                    Answer::Result(text) => (
                        "result",
                        yw_json::parse(
                            text.as_bytes(),
                            &Limits {
                                max_bytes: 8 << 20,
                                ..Limits::RESPONSE
                            },
                        )
                        .unwrap(),
                    ),
                    Answer::Code(code) => (
                        "error",
                        Value::Object(
                            Object::from_pairs(vec![
                                (
                                    "code".to_owned(),
                                    Value::Number(Number::from_literal(&code.to_string()).unwrap()),
                                ),
                                ("message".to_owned(), Value::String("x".to_owned())),
                            ])
                            .unwrap(),
                        ),
                    ),
                    Answer::Big => return Err(HttpError::TooLarge),
                    Answer::Fail => {
                        return Ok(HttpReply {
                            status: 502,
                            body: Vec::new(),
                        });
                    }
                };
                let envelope = Object::from_pairs(vec![
                    ("jsonrpc".to_owned(), Value::String("2.0".to_owned())),
                    ("id".to_owned(), Value::Number(Number::from_u64(id))),
                    (member.0.to_owned(), member.1),
                ])
                .unwrap();
                Ok(HttpReply {
                    status: 200,
                    body: yw_json::to_vec(&Value::Object(envelope)),
                })
            }
        }

        fn verbose(txid: &str, outputs: &[(u64, &str)], inputs: &[(&str, u32)]) -> String {
            let vin: Vec<String> = inputs
                .iter()
                .map(|(txid, vout)| format!(r#"{{"txid":"{txid}","vout":{vout}}}"#))
                .collect();
            let vout: Vec<String> = outputs
                .iter()
                .map(|(value, hex)| {
                    format!(r#"{{"valueZat":{value},"scriptPubKey":{{"hex":"{hex}"}}}}"#)
                })
                .collect();
            format!(
                r#"{{"txid":"{txid}","vin":[{}],"vout":[{}]}}"#,
                vin.join(","),
                vout.join(",")
            )
        }

        fn mempool_of(ids: &[String]) -> String {
            let quoted: Vec<String> = ids.iter().map(|id| format!("\"{id}\"")).collect();
            format!("[{}]", quoted.join(","))
        }

        fn txid_param(params: &[Value]) -> String {
            params
                .first()
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned()
        }

        fn work(indexer: ZecIndexer) -> ZecReceivedWork {
            ZecReceivedWork {
                network: ZecNetwork::Testnet,
                url: HttpsUrl::parse("https://zec.example.test/node").unwrap(),
                indexer,
                address: ADDRESS.to_owned(),
                tip: 100_000,
                script: ours(),
                own_txids: Vec::new(),
                own_outpoints: Vec::new(),
                pending: Vec::new(),
                bb_pending: Vec::new(),
                user: false,
            }
        }

        fn pending(key: &str) -> Incoming {
            Incoming {
                key: key.to_owned(),
                hash: key.to_owned(),
                amount: "0.00050000".to_owned(),
                symbol: "ZEC".to_owned(),
                pending: true,
                amount_units: 50_000,
                ..Incoming::default()
            }
        }

        fn seen_of(fetched: &Fetched) -> Vec<String> {
            match &fetched.cursor {
                Cursor::Zec { seen, .. } => seen.clone(),
                other => unreachable!("{other:?}"),
            }
        }

        fn clock() -> TestClock {
            TestClock(AtomicU64::new(1_000_000))
        }

        /// ZEC-N1: one deposit (a pending row with its txid), one dust deposit (counted), one
        /// foreign transaction (`seen`). No call names the address except `getaddressdeltas`.
        #[test]
        fn mempool_incoming_from_verbose_vout() {
            let ids = [id(1), id(2), id(3)];
            let answers = ids.clone();
            let clock = clock();
            let fake = Fake::new(&clock, 10, move |method, params| match method {
                "getaddressdeltas" => Answer::Result("[]".to_owned()),
                "getrawmempool" => Answer::Result(mempool_of(&answers)),
                "getrawtransaction" => {
                    let txid = txid_param(params);
                    let (value, hex) = if txid == answers[0] {
                        (50_000, script_hex("11"))
                    } else if txid == answers[1] {
                        (5_000, script_hex("11"))
                    } else {
                        (90_000, script_hex("22"))
                    };
                    Answer::Result(verbose(&txid, &[(value, &hex)], &[(&id(9), 0)]))
                }
                _ => Answer::Code(-32_601),
            });
            let fetched = fetch(&fake, &clock, &work(ZecIndexer::Node), &Cursor::Start).unwrap();
            assert_eq!(fetched.found.entries.len(), 1);
            let row = &fetched.found.entries[0];
            assert_eq!(
                (
                    row.key.as_str(),
                    row.pending,
                    row.amount.as_str(),
                    row.amount_units
                ),
                (ids[0].as_str(), true, "0.00050000", 50_000)
            );
            assert_eq!(row.hash, ids[0]);
            assert_eq!(fetched.found.dust, [ids[1].clone()]);
            assert_eq!(seen_of(&fetched), [ids[1].clone(), ids[2].clone()]);
            assert_eq!(fetched.limited, None);
            assert_eq!(fetched.note, None);
            assert_eq!(
                fake.methods(),
                [
                    "getaddressdeltas",
                    "getrawmempool",
                    "getrawtransaction",
                    "getrawtransaction",
                    "getrawtransaction"
                ]
            );
            let bodies = fake.bodies();
            assert!(bodies[0].contains(ADDRESS));
            assert!(bodies[1..].iter().all(|body| !body.contains(ADDRESS)));
        }

        fn v5_hex(outputs: &[(u64, Vec<u8>)], header: Option<u32>) -> String {
            let tx = ZecTx {
                branch_id: 0x4dec_4df0,
                lock_time: 0,
                expiry_height: 0,
                inputs: vec![ZecTxIn {
                    prevout: ZecOutPoint {
                        txid: [9; 32],
                        index: 1,
                    },
                    script_sig: vec![0x51],
                    sequence: u32::MAX,
                }],
                outputs: outputs
                    .iter()
                    .map(|(value, script)| ZecTxOut {
                        value: *value,
                        script_pubkey: script.clone(),
                    })
                    .collect(),
            };
            let mut raw = serialize_tx(&tx);
            if let Some(header) = header {
                raw[..4].copy_from_slice(&header.to_le_bytes());
            }
            yw_core::hex::encode(&raw)
        }

        /// Verbose answers without `vout` fall back to the `hex` (v5 here); a v6 one is unreadable
        /// (no row); a spend of one of our known outputs found through the hex is not a deposit.
        #[test]
        fn mempool_incoming_from_hex_and_unreadable_v6() {
            let ids = [id(1), id(2), id(3)];
            let answers = ids.clone();
            let clock = clock();
            let fake = Fake::new(&clock, 10, move |method, params| match method {
                "getrawmempool" => Answer::Result(mempool_of(&answers)),
                "getrawtransaction" => {
                    let txid = txid_param(params);
                    let header = (txid == answers[1]).then_some(0x8000_0006);
                    let paid = if txid == answers[2] { 70_000 } else { 60_000 };
                    Answer::Result(format!(
                        r#"{{"txid":"{txid}","hex":"{}"}}"#,
                        v5_hex(&[(paid, ours())], header)
                    ))
                }
                _ => Answer::Code(-32_601),
            });
            let mut job = work(ZecIndexer::Node);
            // The third one spends our output (09…09):1 — our own send from another wallet.
            job.own_outpoints = vec![(txid_display(&[9; 32]), 1)];
            let only_two = fetch(
                &fake,
                &clock,
                &job,
                &Cursor::Zec {
                    next: None,
                    deltas: false,
                    seen: Vec::new(),
                },
            )
            .unwrap();
            assert!(only_two.found.entries.is_empty(), "every input is ours");
            job.own_outpoints.clear();
            let fresh = Fake::new(&clock, 10, {
                let answers = ids.clone();
                move |method, params| match method {
                    "getrawmempool" => Answer::Result(mempool_of(&answers[..2])),
                    "getrawtransaction" => {
                        let txid = txid_param(params);
                        let header = (txid == answers[1]).then_some(0x8000_0006);
                        Answer::Result(format!(
                            r#"{{"txid":"{txid}","hex":"{}"}}"#,
                            v5_hex(&[(60_000, ours())], header)
                        ))
                    }
                    _ => Answer::Code(-32_601),
                }
            });
            let fetched = fetch(
                &fresh,
                &clock,
                &job,
                &Cursor::Zec {
                    next: None,
                    deltas: false,
                    seen: Vec::new(),
                },
            )
            .unwrap();
            assert_eq!(fetched.found.entries.len(), 1);
            assert_eq!(fetched.found.entries[0].key, ids[0]);
            assert_eq!(fetched.found.entries[0].amount_units, 60_000);
            assert_eq!(seen_of(&fetched), [ids[1].clone()], "v6: unreadable, seen");
            assert_eq!(fetched.limited, Some(T_NO_DELTAS_PENDING));
            assert_eq!(
                fresh.count("getaddressdeltas"),
                0,
                "automatic read after -32601"
            );
        }

        /// At most 30 new txids per read; the rest are taken next read. One budget covers the whole
        /// read: with 10 s calls (the per-call deadline) a read stops after the first call that
        /// passes 5 s, and keeps everything.
        #[test]
        fn mempool_scan_cap_and_time_budget() {
            let ids: Vec<String> = (0..100).map(id).collect();
            let answers = ids.clone();
            let clock = clock();
            let foreign = move |method: &str, params: &[Value]| match method {
                "getrawmempool" => Answer::Result(mempool_of(&answers)),
                "getrawtransaction" => Answer::Result(verbose(
                    &txid_param(params),
                    &[(90_000, &script_hex("22"))],
                    &[(&id(999), 0)],
                )),
                _ => Answer::Code(-32_601),
            };
            let fake = Fake::new(&clock, 10, foreign.clone());
            let cursor = Cursor::Zec {
                next: None,
                deltas: false,
                seen: Vec::new(),
            };
            let first = fetch(&fake, &clock, &work(ZecIndexer::Node), &cursor).unwrap();
            assert_eq!(fake.count("getrawtransaction"), ZEC_MEMPOOL_SCAN_MAX);
            assert_eq!(first.note, Some(T_MEMPOOL_PARTIAL));
            assert_eq!(seen_of(&first), ids[..30]);
            let second = fetch(&fake, &clock, &work(ZecIndexer::Node), &first.cursor).unwrap();
            assert_eq!(seen_of(&second), ids[..60]);
            // Slow provider: every call takes 10 s.
            let slow = Fake::new(&clock, 10_000, foreign);
            let mut job = work(ZecIndexer::Node);
            job.pending = vec![pending(&id(5_000))];
            let read = fetch(&slow, &clock, &job, &Cursor::Start).unwrap();
            assert_eq!(
                slow.methods(),
                ["getaddressdeltas"],
                "one call, then the budget"
            );
            assert_eq!(read.note, Some(T_MEMPOOL_PARTIAL));
            assert!(read.gone.is_empty() && read.dropped.is_empty());
            let slow_no_deltas = Fake::new(&clock, 10_000, move |method, params| match method {
                "getrawmempool" => Answer::Result(mempool_of(&[id(1), id(2)])),
                _ => Answer::Result(verbose(&txid_param(params), &[], &[])),
            });
            let read = fetch(&slow_no_deltas, &clock, &work(ZecIndexer::Node), &cursor).unwrap();
            assert_eq!(slow_no_deltas.methods(), ["getrawmempool"]);
            assert!(seen_of(&read).is_empty(), "unscanned txids stay unseen");
        }

        /// Oversized or malformed answers: a big mempool is not scanned (and `seen` is kept), bad
        /// elements are dropped, an oversized transaction is `seen`, a txid mismatch or a negative
        /// `valueZat` is unreadable, and a failed call is retried next read (not `seen`).
        #[test]
        fn mempool_oversized_and_malformed_answers() {
            let clock = clock();
            let cursor = Cursor::Zec {
                next: None,
                deltas: false,
                seen: vec![id(77)],
            };
            let big = Fake::new(&clock, 10, |_, _| Answer::Big);
            let read = fetch(&big, &clock, &work(ZecIndexer::Node), &cursor).unwrap();
            assert_eq!(read.note, Some(T_MEMPOOL_BIG));
            assert_eq!(seen_of(&read), [id(77)], "no mempool list: seen unchanged");
            let many: Vec<String> = (0..5_001).map(id).collect();
            let crowded = Fake::new(&clock, 10, move |_, _| Answer::Result(mempool_of(&many)));
            let read = fetch(&crowded, &clock, &work(ZecIndexer::Node), &cursor).unwrap();
            assert_eq!(read.note, Some(T_MEMPOOL_BIG));
            assert_eq!(crowded.methods(), ["getrawmempool"]);
            let mixed = format!(
                r#"[1,"zz","{}","{}","{}","{}","{}"]"#,
                id(1),
                id(2),
                id(3),
                id(4),
                id(1).to_uppercase()
            );
            let fake = Fake::new(&clock, 10, move |method, params| {
                let txid = txid_param(params);
                match (method, txid.as_str()) {
                    ("getrawmempool", _) => Answer::Result(mixed.clone()),
                    (_, t) if t == id(1) => Answer::Big,
                    (_, t) if t == id(2) => {
                        Answer::Result(verbose(&id(8), &[(60_000, &script_hex("11"))], &[]))
                    }
                    (_, t) if t == id(3) => Answer::Result(
                        verbose(t, &[(60_000, &script_hex("11"))], &[]).replace("60000", "-60000"),
                    ),
                    _ => Answer::Fail,
                }
            });
            let read = fetch(&fake, &clock, &work(ZecIndexer::Node), &cursor).unwrap();
            assert_eq!(
                fake.count("getrawtransaction"),
                4,
                "bad and duplicate ids dropped"
            );
            assert!(read.found.entries.is_empty());
            assert_eq!(
                seen_of(&read),
                [id(1), id(2), id(3)],
                "the failed one is retried"
            );
            assert_eq!(read.note, Some(T_MEMPOOL_PARTIAL));
        }

        /// Our own journal sends are never fetched.
        #[test]
        fn own_sends_are_never_fetched() {
            let clock = clock();
            let fake = Fake::new(&clock, 10, |method, _| match method {
                "getaddressdeltas" => Answer::Result("[]".to_owned()),
                "getrawmempool" => Answer::Result(mempool_of(&[id(1)])),
                _ => Answer::Fail,
            });
            let mut job = work(ZecIndexer::Node);
            job.own_txids = vec![id(1)];
            let read = fetch(&fake, &clock, &job, &Cursor::Start).unwrap();
            assert_eq!(fake.count("getrawtransaction"), 0);
            assert!(read.found.entries.is_empty());
        }

        /// Pending rows the mempool no longer has: mined → a confirmed row; `-5` → gone where mined
        /// transactions can be looked up (deltas), dropped with neutral words elsewhere; still
        /// known or no answer → kept; at most 5 checks per read.
        #[test]
        fn vanished_pending_rows() {
            let clock = clock();
            let handler = |method: &str, params: &[Value]| {
                let txid = txid_param(params);
                match method {
                    "getaddressdeltas" | "getrawmempool" => Answer::Result("[]".to_owned()),
                    _ if txid == id(1) => Answer::Result(r#"{"height":99990}"#.to_owned()),
                    _ if txid == id(2) => Answer::Code(-5),
                    _ if txid == id(3) => Answer::Result(r#"{"height":-1}"#.to_owned()),
                    _ => Answer::Fail,
                }
            };
            let mut job = work(ZecIndexer::Node);
            job.pending = (1..=7).map(|n| pending(&id(n))).collect();
            let fake = Fake::new(&clock, 10, handler);
            let read = fetch(&fake, &clock, &job, &Cursor::Start).unwrap();
            assert_eq!(fake.count("getrawtransaction"), ZEC_PENDING_CHECK_MAX);
            assert_eq!(read.found.entries.len(), 1);
            assert_eq!(read.found.entries[0].key, id(1));
            assert!(!read.found.entries[0].pending);
            assert_eq!(read.found.entries[0].block, Some(99_990));
            assert_eq!(read.gone, [id(2)]);
            assert!(read.dropped.is_empty());
            // Zebra (no deltas): `-5` cannot tell "never mined" from "mined": neutral words.
            let zebra = Fake::new(&clock, 10, move |method, params| match method {
                "getaddressdeltas" => Answer::Code(-32_601),
                other => handler(other, params),
            });
            let read = fetch(&zebra, &clock, &job, &Cursor::Start).unwrap();
            assert!(read.gone.is_empty());
            assert_eq!(read.dropped, [id(2)]);
            assert_eq!(read.limited, Some(T_NO_DELTAS_PENDING));
            match &read.cursor {
                Cursor::Zec { deltas, .. } => assert!(!deltas),
                other => unreachable!("{other:?}"),
            }
            // `새로고침` asks for deltas again.
            let mut user = job;
            user.user = true;
            let retry = Fake::new(&clock, 10, |_, _| Answer::Result("[]".to_owned()));
            let read = fetch(&retry, &clock, &user, &read.cursor).unwrap();
            assert_eq!(retry.count("getaddressdeltas"), 1);
            assert_eq!(read.limited, None);
        }

        /// `bb-rest`: the snapshot's unconfirmed outputs (journal sends already left out) become
        /// pending rows without any new request; a row that left the snapshot gets one status
        /// check (neutral words on `-5`: this source cannot look up mined transactions).
        #[test]
        fn blockbook_pending_from_the_snapshot() {
            let clock = clock();
            let fake = Fake::new(&clock, 10, |_, _| Answer::Code(-5));
            let mut job = work(ZecIndexer::BbRest);
            job.bb_pending = vec![(id(1), 50_000), (id(2), 5_000), (id(3), 70_000)];
            job.pending = vec![pending(&id(3)), pending(&id(4))];
            let read = fetch(&fake, &clock, &job, &Cursor::Start).unwrap();
            assert_eq!(fake.methods(), ["getrawtransaction"]);
            assert_eq!(read.found.entries.len(), 1);
            assert_eq!(read.found.entries[0].key, id(1));
            assert_eq!(read.found.dust, [id(2)]);
            assert_eq!(read.dropped, [id(4)]);
            assert_eq!(read.limited, Some(T_NO_DELTAS_PENDING));
        }

        /// The scan's log fields are counts and fixed words only (no address, txid or amount).
        #[test]
        fn scan_log_fields_carry_counts_only() {
            let stats = super::super::ScanStats {
                txids: 3,
                scanned: 3,
                found: 1,
                dust: 1,
                cap: "count",
                ..super::super::ScanStats::default()
            };
            let line = crate::logging::format_line(
                0,
                crate::settings::LogLevel::Info,
                "rpc",
                "received.mempool",
                &stats.fields(crate::network::NetworkId::Zcash(ZecNetwork::Testnet)),
            );
            assert!(line.contains("scanned=3"), "{line}");
            for absent in [ADDRESS, "0.0005", "50000", "76a914"] {
                assert!(!line.contains(absent), "{absent} in {line}");
            }
        }
    }
}
