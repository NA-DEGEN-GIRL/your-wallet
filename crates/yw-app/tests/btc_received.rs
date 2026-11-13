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
use yw_app::btc::{BtcClient, ChainSession, Trigger};
use yw_app::received::Incoming;
use yw_app::received::btc::{BtcReceivedWork, ESPLORA_MEMPOOL_PAGE, T_BB_NO_TXS, fetch};
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
    // Refused for every address: the fixed line, no error.
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
    let fetched = fetch(&client, &mut session(), &work(vec![0, 1], Vec::new()))?;
    assert_eq!(fetched.unsupported, Some(T_BB_NO_TXS));
    Ok(())
}
