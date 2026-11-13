//! Bitcoin received history with unconfirmed (mempool) deposits over the recording fake transport
//! (spec/04 §2.6, spec/08 §4.3, spec/09 §4.4 BTC-N9 / BTC-N10, 2026-11-13): pending rows are
//! resolved per address — gone only when every address that paid them answered completely and
//! the indexer's `TxStatus` agrees, confirmed when it says so, kept otherwise — and Blockbook
//! `details=txs` (`bb-rest` `pageSize`, `bb-rpc` `size`) gives the same rows as Esplora.

mod btc_support;

use btc_support::{
    CORE_URL, Call, Reply, Rig, TESTNET4_GENESIS, TestResult, Verb, account, chain_input, healthy,
    params, xpub,
};
use yw_app::app_received::RecvList;
use yw_app::btc::{BtcClient, ChainSession, Trigger};
use yw_app::received::btc::{
    BTC_PENDING_CHECK_MAX, BtcReceivedWork, ESPLORA_MEMPOOL_PAGE, T_BB_NO_TXS, T_BB_NO_TXS_ONCE,
    fetch,
};
use yw_app::received::{Cursor, Fetched, Incoming, PENDING_MISS_MAX};
use yw_app::settings::BtcIndexer;
use yw_core::bip32::path::BtcChain;
use yw_core::btc::BtcNetwork;
use yw_core::btc::address::{BtcAddress, p2wpkh_program};

/// A made-up sender (not a valid address of anyone).
const THEIRS: &str = "tb1qsenderxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

fn ours(index: u32) -> TestResult<String> {
    let program =
        p2wpkh_program(&xpub(), BtcChain::Receive, index).map_err(|error| format!("{error:?}"))?;
    Ok(BtcAddress::p2wpkh(BtcNetwork::Testnet4, &program)
        .as_str()
        .to_owned())
}

fn txid(fill: char) -> String {
    fill.to_string().repeat(64)
}

fn esplora_tx(id: &str, to: &str, value: u64, height: Option<u32>) -> String {
    let status = height.map_or_else(
        || r#"{"confirmed":false}"#.to_owned(),
        |height| {
            format!(
                r#"{{"confirmed":true,"block_height":{height},"block_hash":"{}","block_time":1793000000}}"#,
                "0".repeat(64)
            )
        },
    );
    format!(
        r#"{{"txid":"{id}","vin":[{{"txid":"{}","vout":0,"prevout":{{"scriptpubkey":"0014","scriptpubkey_address":"{THEIRS}","value":{}}},"is_coinbase":false}}],"vout":[{{"scriptpubkey":"0014","scriptpubkey_address":"{to}","value":{value}}}],"status":{status}}}"#,
        "f".repeat(64),
        value + 500
    )
}

fn pending_row(id: &str, via: &[u32]) -> Incoming {
    Incoming {
        key: id.to_owned(),
        hash: id.to_owned(),
        amount: "0.00050000".to_owned(),
        symbol: "BTC".to_owned(),
        from: Some(THEIRS.to_owned()),
        pending: true,
        amount_units: 50_000,
        via: via.to_vec(),
        ..Incoming::default()
    }
}

fn work(fetch: Vec<u32>, pending: Vec<Incoming>) -> BtcReceivedWork {
    BtcReceivedWork {
        account: account(),
        receive_count: 12,
        change_count: 2,
        fetch,
        pending,
        rejected_before: false,
        chain: chain_input(),
        trigger: Trigger::User,
    }
}

fn session() -> ChainSession {
    ChainSession::new(BtcNetwork::Testnet4, BtcNetwork::Testnet4)
}

fn tx_status_paths(rig: &Rig) -> Vec<String> {
    rig.fake
        .get_paths()
        .into_iter()
        .filter(|path| path.ends_with("/status"))
        .collect()
}

/// BTC-N10: a pending row whose address answered completely and that the indexer no longer
/// knows is gone; one it reports in a block becomes a confirmed row (beyond the 25-confirmed
/// window); one on an address that failed this read is kept and not even checked. A new
/// mempool deposit is a pending row with its address index; a dust one is only counted.
#[test]
fn esplora_pending_rows_resolve_per_address() -> TestResult {
    let (zero, one) = (ours(0)?, ours(1)?);
    let answer = format!(
        "[{},{}]",
        esplora_tx(&txid('d'), &zero, 50_000, None),
        esplora_tx(&txid('e'), &zero, 600, None)
    );
    let (zero_c, one_c) = (zero.clone(), one.clone());
    let rig = Rig::new(BtcIndexer::Esplora, move |call: &Call| {
        let path = call.path();
        if path == format!("/address/{zero_c}/txs") {
            Reply::json(&answer)
        } else if path == format!("/address/{one_c}/txs") {
            Reply::json("not json")
        } else if path == format!("/tx/{}/status", txid('c')) {
            Reply::json(&format!(
                r#"{{"confirmed":true,"block_height":157700,"block_hash":"{}","block_time":1793000000}}"#,
                "0".repeat(64)
            ))
        } else if path.ends_with("/status") {
            Reply::status(404)
        } else {
            healthy(call)
        }
    });
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let mut session = session();
    let pending = vec![
        pending_row(&txid('a'), &[0]),
        pending_row(&txid('b'), &[1]),
        pending_row(&txid('c'), &[0]),
    ];
    let fetched = fetch(&client, &mut session, &work(vec![0, 1], pending))?;
    assert_eq!(fetched.covered, [0]);
    assert_eq!(fetched.gone, [txid('a')]);
    assert!(fetched.dropped.is_empty());
    assert_eq!(fetched.found.dust, [txid('e')]);
    let rows: Vec<(&str, bool, Option<u64>, &[u32])> = fetched
        .found
        .entries
        .iter()
        .map(|row| (row.key.as_str(), row.pending, row.block, row.via.as_slice()))
        .collect();
    assert_eq!(
        rows,
        [
            (txid('d').as_str(), true, None, &[0_u32][..]),
            (txid('c').as_str(), false, Some(157_700), &[0_u32][..]),
        ]
    );
    assert_eq!(fetched.found.entries[0].amount_units, 50_000);
    // Only the rows of the complete address were checked; never the one of address 1.
    let mut checked = tx_status_paths(&rig);
    checked.sort();
    assert_eq!(
        checked,
        [
            format!("/tx/{}/status", txid('a')),
            format!("/tx/{}/status", txid('c')),
        ]
    );
    let asked: Vec<String> = rig
        .fake
        .get_paths()
        .into_iter()
        .filter(|path| path.ends_with("/txs"))
        .collect();
    assert_eq!(
        asked,
        [
            format!("/address/{zero}/txs"),
            format!("/address/{one}/txs")
        ]
    );
    Ok(())
}

/// A dust flood (Esplora's 50-entry mempool page) makes that address incomplete: its pending
/// rows are kept and never checked; a read during the cooldown or with no address asks nothing
/// and keeps everything.
#[test]
fn esplora_flood_and_empty_reads_keep_pending_rows() -> TestResult {
    let zero = ours(0)?;
    let flood: Vec<String> = (0..ESPLORA_MEMPOOL_PAGE)
        .map(|n| esplora_tx(&format!("{n:064x}"), &zero, 600, None))
        .collect();
    let body = format!("[{}]", flood.join(","));
    let zero_c = zero.clone();
    let rig = Rig::new(BtcIndexer::Esplora, move |call: &Call| {
        if call.path() == format!("/address/{zero_c}/txs") {
            Reply::json(&body)
        } else {
            healthy(call)
        }
    });
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let mut session = session();
    let pending = vec![pending_row(&txid('a'), &[0])];
    let fetched = fetch(&client, &mut session, &work(vec![0], pending.clone()))?;
    assert!(fetched.covered.is_empty());
    assert!(fetched.gone.is_empty());
    assert!(tx_status_paths(&rig).is_empty());
    let before = rig.fake.count();
    let nothing = fetch(&client, &mut session, &work(Vec::new(), pending))?;
    assert_eq!(rig.fake.count(), before, "no address, no request");
    assert!(nothing.gone.is_empty() && nothing.found.entries.is_empty());
    Ok(())
}

fn bb_body(address: &str, deposit: &str) -> String {
    format!(
        r#"{{"page":1,"totalPages":1,"itemsOnPage":25,"address":"{address}","balance":"0","unconfirmedBalance":"50000","txs":0,"unconfirmedTxs":1,"transactions":[{{"txid":"{deposit}","vin":[{{"txid":"{}","vout":0,"n":0,"addresses":["{THEIRS}"],"isAddress":true,"value":"60000"}}],"vout":[{{"value":"50000","n":0,"addresses":["{address}"],"isAddress":true}}],"blockHeight":-1,"confirmations":0,"blockTime":1793000000,"value":"50000","valueIn":"60000","fees":"10000"}}]}}"#,
        "f".repeat(64)
    )
}

/// BTC-N9: Blockbook `details=txs` page 1 through `bb-rest` (`pageSize`) and `bb-rpc`
/// (`size`, spec/08 §4.3) gives the same pending row; a Blockbook that refuses the call for
/// every address shows the fixed line instead of an error.
#[test]
fn blockbook_rest_and_rpc_list_mempool_deposits() -> TestResult {
    let zero = ours(0)?;
    let deposit = txid('d');
    let api = format!("{}/api/v2/", CORE_URL.trim_end_matches('/'));
    let (zero_c, deposit_c, api_c) = (zero.clone(), deposit.clone(), api.clone());
    let rest = Rig::new(BtcIndexer::BbRest, move |call: &Call| {
        if call.verb == Verb::Get && call.url == format!("{api_c}block-index/0") {
            Reply::json(&format!(r#"{{"blockHash":"{TESTNET4_GENESIS}"}}"#))
        } else if call.verb == Verb::Get
            && call.url == format!("{api_c}address/{zero_c}?details=txs&page=1&pageSize=25")
        {
            Reply::json(&bb_body(&zero_c, &deposit_c))
        } else {
            healthy(call)
        }
    });
    let (zero_c, deposit_c) = (zero.clone(), deposit.clone());
    let rpc = Rig::new(BtcIndexer::BbRpc, move |call: &Call| {
        if call.method == "bb_getAddress" {
            Reply::Result(bb_body(&zero_c, &deposit_c))
        } else {
            healthy(call)
        }
    });
    let mut results = Vec::new();
    for rig in [&rest, &rpc] {
        let client = BtcClient::new(rig.env(), &rig.endpoint);
        let fetched = fetch(&client, &mut session(), &work(vec![0], Vec::new()))?;
        assert_eq!(fetched.covered, [0]);
        assert_eq!(fetched.unsupported, None);
        results.push(fetched.found);
    }
    assert_eq!(results[0], results[1]);
    assert_eq!(results[0].entries.len(), 1);
    assert!(results[0].entries[0].pending);
    assert_eq!(results[0].entries[0].time_ms, None);
    // The exact bb-rpc params.
    let call = rpc
        .fake
        .calls()
        .into_iter()
        .find(|call| call.method == "bb_getAddress")
        .ok_or("no bb_getAddress")?;
    assert_eq!(
        yw_json::to_vec(&params(&call)),
        format!(r#"["{zero}",{{"details":"txs","page":1,"size":25}}]"#).into_bytes()
    );
    // Refused for every address: a note and the `BtcRejected` cursor the first time (a passing
    // provider error looks the same, 2026-11-13 review), the fixed line on the next read in a
    // row; never an error.
    let refusing = Rig::new(BtcIndexer::BbRest, move |call: &Call| {
        if call.verb == Verb::Get && call.url == format!("{api}block-index/0") {
            Reply::json(&format!(r#"{{"blockHash":"{TESTNET4_GENESIS}"}}"#))
        } else if call.url.contains("details=txs") {
            Reply::status(400)
        } else {
            healthy(call)
        }
    });
    let client = BtcClient::new(refusing.env(), &refusing.endpoint);
    let first = fetch(&client, &mut session(), &work(vec![0, 1], Vec::new()))?;
    assert_eq!(first.unsupported, None);
    assert_eq!(first.note, Some(T_BB_NO_TXS_ONCE));
    assert_eq!(first.cursor, Cursor::BtcRejected);
    let mut again = work(vec![0, 1], Vec::new());
    again.rejected_before = true;
    let second = fetch(&client, &mut session(), &again)?;
    assert_eq!(second.unsupported, Some(T_BB_NO_TXS));
    // A bb-rpc internal error (-32603) on every address is the same first strike only.
    let rpc_failing = Rig::new(BtcIndexer::BbRpc, |call: &Call| {
        if call.method == "bb_getAddress" {
            Reply::RpcError(-32_603)
        } else {
            healthy(call)
        }
    });
    let client = BtcClient::new(rpc_failing.env(), &rpc_failing.endpoint);
    let first = fetch(&client, &mut session(), &work(vec![0], Vec::new()))?;
    assert_eq!(first.unsupported, None);
    assert_eq!(first.cursor, Cursor::BtcRejected);
    Ok(())
}

/// A Blockbook page for `address` without the vanished deposit (its other transactions are
/// irrelevant here).
fn bb_empty(address: &str) -> String {
    format!(r#"{{"page":1,"totalPages":1,"itemsOnPage":25,"address":"{address}","txs":0}}"#)
}

/// 2026-11-13 review (spec/08 §4.3 "미확정 행 정리"): a pending row that every address answered
/// completely without listing. `bb-rest`: `tx/{t}` 404 → gone. `bb-rpc`: `bb_getTx` answers a
/// JSON-RPC error (no "not found" code is recorded, §4.5 B3) → missed; after `PENDING_MISS_MAX`
/// such reads in a row the list removes it with neutral wording and stops asking.
#[test]
fn blockbook_vanished_pending_rows() -> TestResult {
    let zero = ours(0)?;
    let gone = txid('a');
    let api = format!("{}/api/v2/", CORE_URL.trim_end_matches('/'));
    let (zero_c, api_c) = (zero.clone(), api.clone());
    let rest = Rig::new(BtcIndexer::BbRest, move |call: &Call| {
        if call.verb == Verb::Get && call.url == format!("{api_c}block-index/0") {
            Reply::json(&format!(r#"{{"blockHash":"{TESTNET4_GENESIS}"}}"#))
        } else if call.verb == Verb::Get && call.url.contains("details=txs") {
            Reply::json(&bb_empty(&zero_c))
        } else if call.verb == Verb::Get && call.url.starts_with(&format!("{api_c}tx/")) {
            Reply::status(404)
        } else {
            healthy(call)
        }
    });
    let client = BtcClient::new(rest.env(), &rest.endpoint);
    let fetched = fetch(
        &client,
        &mut session(),
        &work(vec![0], vec![pending_row(&gone, &[0])]),
    )?;
    assert_eq!(fetched.covered, [0]);
    assert_eq!(fetched.gone, [gone.as_str()]);
    assert!(fetched.missed.is_empty());
    assert!(
        rest.fake
            .calls()
            .iter()
            .any(|call| call.url == format!("{api}tx/{gone}"))
    );

    let zero_c = zero.clone();
    let rpc = Rig::new(BtcIndexer::BbRpc, move |call: &Call| {
        match call.method.as_str() {
            "bb_getAddress" => Reply::Result(bb_empty(&zero_c)),
            "bb_getTx" => Reply::RpcError(-32_000),
            _ => healthy(call),
        }
    });
    let client = BtcClient::new(rpc.env(), &rpc.endpoint);
    let bb_get_tx = || {
        rpc.fake
            .calls()
            .iter()
            .filter(|call| call.method == "bb_getTx")
            .count()
    };
    let mut list = RecvList::default();
    list.apply(Fetched {
        found: yw_app::received::Found {
            entries: vec![pending_row(&gone, &[0])],
            dust: Vec::new(),
        },
        ..Fetched::default()
    });
    for read in 1..=PENDING_MISS_MAX {
        assert_eq!(list.pending_sum(), Some(50_000), "read {read}");
        let fetched = fetch(&client, &mut session(), &work(vec![0], list.pending_rows()))?;
        assert!(fetched.gone.is_empty());
        assert_eq!(fetched.missed, [gone.as_str()]);
        list.apply(fetched);
    }
    assert_eq!(list.pending_sum(), None);
    assert_eq!((list.gone, list.dropped), (0, 1));
    // Nothing left to ask about: no more paid `bb_getTx` calls.
    let before = bb_get_tx();
    assert_eq!(before, usize::from(PENDING_MISS_MAX));
    let fetched = fetch(&client, &mut session(), &work(vec![0], list.pending_rows()))?;
    assert!(fetched.missed.is_empty());
    assert_eq!(bb_get_tx(), before);
    Ok(())
}

/// 2026-11-13 review: Esplora answers `{"confirmed":false}` for an unknown txid too, and a
/// load-balanced Esplora can list the addresses from a lagging backend. One `/tx/{t}/hex`
/// probe decides: 404 → gone, the raw transaction → kept. Status and probe requests together
/// stay within `BTC_PENDING_CHECK_MAX` per read.
#[test]
fn esplora_unconfirmed_status_is_probed() -> TestResult {
    let zero = ours(0)?;
    let (kept, gone) = (txid('b'), txid('c'));
    let (zero_c, kept_c) = (zero.clone(), kept.clone());
    let rig = Rig::new(BtcIndexer::Esplora, move |call: &Call| {
        let path = call.path();
        if path == format!("/address/{zero_c}/txs") {
            Reply::json("[]")
        } else if path.ends_with("/status") {
            Reply::json(r#"{"confirmed":false}"#)
        } else if path == format!("/tx/{kept_c}/hex") {
            Reply::text("0200")
        } else if path.ends_with("/hex") {
            Reply::status(404)
        } else {
            healthy(call)
        }
    });
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let fetched = fetch(
        &client,
        &mut session(),
        &work(
            vec![0],
            vec![pending_row(&kept, &[0]), pending_row(&gone, &[0])],
        ),
    )?;
    assert_eq!(fetched.gone, [gone.as_str()]);
    assert!(fetched.missed.is_empty());
    let probes: Vec<String> = rig
        .fake
        .get_paths()
        .into_iter()
        .filter(|path| path.starts_with("/tx/"))
        .collect();
    assert_eq!(
        probes,
        [
            format!("/tx/{kept}/status"),
            format!("/tx/{kept}/hex"),
            format!("/tx/{gone}/status"),
            format!("/tx/{gone}/hex"),
        ]
    );
    // Many vanished rows: at most BTC_PENDING_CHECK_MAX requests, the rest wait.
    let many: Vec<Incoming> = (0..10)
        .map(|n| pending_row(&format!("{n:064x}"), &[0]))
        .collect();
    let before = rig.fake.get_paths().len();
    fetch(&client, &mut session(), &work(vec![0], many))?;
    let asked = rig.fake.get_paths()[before..]
        .iter()
        .filter(|path| path.starts_with("/tx/"))
        .count();
    assert_eq!(asked, BTC_PENDING_CHECK_MAX);
    Ok(())
}
