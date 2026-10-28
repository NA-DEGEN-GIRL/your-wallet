//! Bitcoin read pipelines and broadcast primitives over the recording fake transport and the
//! manual clock (spec/08 §3.4, §4.4, §4.7, §11.3, §12.2; spec/04 §2.11 / §6.5 ST-4; spec/09
//! §4.4 BTC-N1, BTC-N6, BTC-N8): discovery (gap rule, "더 찾기", cancel, progress), refresh with
//! previous-transaction verification (`prev_tx_fallback_txraw`, `prev_tx_amount_forgery_rejected`),
//! tracking observations (`esplora_tx_status_ambiguous`), HTTP 429 back-off and cooldown
//! (`indexer_429_backoff`), the settings Esplora `테스트`, and the manual Esplora broadcast
//! (`esplora_broadcast_manual_only`). Logs never carry a URL, host or token.

mod btc_support;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use btc_support::{
    ADDRESS_0_0, ESPLORA_BASE, MAINNET_GENESIS, REAL_PROGRAM, REAL_TXID, REAL_VALUE, Reply, Rig,
    SERVER_STRING, TESTNET3_GENESIS, TESTNET4_GENESIS, TIP, TestResult, Verb, account,
    address_json, chain_input, core, esplora, first_param, fixture_body, healthy, path_address,
};
use yw_app::btc::broadcast::{
    EsploraPostOutcome, ManualBroadcastGate, esplora_broadcast_confirmed, manual_broadcast_offered,
    send_raw_transaction, test_mempool_accept,
};
use yw_app::btc::flow::{
    DiscoveryJob, EsploraTestOutcome, RawSource, RefreshJob, TrackJob, VerifyFailure, discover,
    esplora_test, observe_tx, prev_transaction, refresh,
};
use yw_app::btc::{BtcClient, BtcError, ChainSession, IndexerError, Trigger};
use yw_app::errors::ErrorCode;
use yw_app::settings::BtcIndexer;
use yw_core::bip32::path::BtcChain;
use yw_core::btc::address::{BtcAddress, p2wpkh_program};
use yw_core::btc::policy::{BroadcastOutcome, SendRawResult, broadcast_outcome};
use yw_core::btc::prevtx::{PrevTxError, verify_prev_output};
use yw_core::btc::script::p2wpkh_script_pubkey;
use yw_core::btc::tx::{Transaction, TxIn, TxOut, serialize, txid as compute_txid};
use yw_core::btc::{BtcMeta, Discovery};
use yw_core::btc::{BtcNetwork, OutPoint, Sats, Txid};
use yw_core::journal::btc::TrackObservation;
use yw_win::http::{HttpError, HttpsUrl};

fn new_session() -> ChainSession {
    ChainSession::new(BtcNetwork::Testnet4, BtcNetwork::Testnet4)
}

fn ours(chain: BtcChain, index: u32) -> TestResult<BtcAddress> {
    let program = p2wpkh_program(&account(), chain, index).map_err(|error| format!("{error:?}"))?;
    Ok(BtcAddress::p2wpkh(BtcNetwork::Testnet4, &program))
}

/// Address text → (chain index, address index) for the first 64 of each chain.
fn index_map() -> TestResult<HashMap<String, (u32, u32)>> {
    let mut map = HashMap::new();
    for (chain, number) in [(BtcChain::Receive, 0), (BtcChain::Change, 1)] {
        for index in 0..64 {
            map.insert(ours(chain, index)?.as_str().to_owned(), (number, index));
        }
    }
    Ok(map)
}

fn refresh_job(receive: u32, change: u32) -> RefreshJob {
    RefreshJob {
        account: account(),
        receive_count: receive,
        change_count: change,
        known: Vec::new(),
        inflight_change: Vec::new(),
        chain: chain_input(),
        trigger: Trigger::User,
    }
}

#[test]
fn discovery_gap_rule_and_more() -> TestResult {
    let map = index_map()?;
    assert_eq!(map.get(ADDRESS_0_0), Some(&(0, 0)));
    let used = [(0_u32, 0_u32), (0, 3), (0, 25), (1, 1)];
    let rig = Rig::new(BtcIndexer::Esplora, move |call| {
        if call.verb == Verb::Get
            && let Some(address) = path_address(call.path())
            && let Some(key) = map.get(address)
            && used.contains(key)
        {
            return Reply::json(&address_json(address, [1, 1, 2], [0, 0, 0]));
        }
        healthy(call)
    });
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let mut session = new_session();
    let mut seen = Vec::new();
    let job = DiscoveryJob {
        account: account(),
        discovery: Discovery::full(),
        chain: chain_input(),
    };
    let result = discover(
        &client,
        &mut session,
        &job,
        &AtomicBool::new(false),
        &mut |n| {
            seen.push(n);
        },
    )?;
    assert!(result.discovery.is_done());
    assert_eq!(result.discovery.checked(), 46);
    let mut meta = BtcMeta::new(BtcNetwork::Testnet4, account());
    result.discovery.apply(&mut meta)?;
    // Receive: 0 and 3 used, then 20 unused (4..=23); index 25 is beyond the gap.
    assert_eq!(meta.receive_next(), 4);
    assert_eq!(meta.last_used_receive(), Some(3));
    // Change: 1 used, then 2..=21 unused.
    assert_eq!(meta.change_next(), 2);
    assert_eq!(meta.last_used_change(), Some(1));
    assert!(meta.discovery_done());
    assert_eq!(seen, (1..=46).collect::<Vec<u32>>());
    assert_eq!(result.addresses.len(), 46);
    assert_eq!(result.addresses[0].address.as_str(), ADDRESS_0_0);
    assert_eq!(result.chain.tip_height, TIP);
    // Only address requests after the chain check; never a UTXO, tx or xpub request.
    let paths = rig.fake.get_paths();
    assert_eq!(paths[..2], ["/block-height/0", "/blocks/tip/height"]);
    assert!(
        paths[2..]
            .iter()
            .all(|path| path.starts_with("/address/tb1q") && !path.ends_with("/utxo"))
    );
    assert_eq!(paths.len(), 48);

    // "더 찾기" (yw-core `Discovery::more`): each chain 20 more from its current `next`. With
    // receive addresses issued up to index 23 the window reaches index 25, finds it and
    // continues the gap rule from there; the change chain re-checks 2..=21.
    for _ in 0..20 {
        meta.new_receive_address(true)?;
    }
    assert_eq!(meta.receive_next(), 24);
    let more = DiscoveryJob {
        discovery: Discovery::more(&meta),
        ..job
    };
    let before = rig.fake.count();
    let result = discover(
        &client,
        &mut session,
        &more,
        &AtomicBool::new(false),
        &mut |_| {},
    )?;
    result.discovery.apply(&mut meta)?;
    assert_eq!(meta.last_used_receive(), Some(25));
    assert_eq!(meta.receive_next(), 26);
    assert_eq!(meta.change_next(), 2);
    assert_eq!(meta.last_used_change(), Some(1));
    // 24, 25, then 26..=45 on receive; 2..=21 on change.
    assert_eq!(result.discovery.checked(), 42);
    // The chain check is cached (no request), only the 42 addresses are asked.
    assert_eq!(rig.fake.count() - before, 42);
    rig.log.assert_no_url();
    Ok(())
}

#[test]
fn discovery_cancel_and_progress() {
    let rig = Rig::new(BtcIndexer::Esplora, healthy);
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let mut session = new_session();
    let cancel = AtomicBool::new(false);
    let job = DiscoveryJob {
        account: account(),
        discovery: Discovery::full(),
        chain: chain_input(),
    };
    let result = discover(&client, &mut session, &job, &cancel, &mut |checked| {
        if checked == 5 {
            cancel.store(true, Ordering::Relaxed);
        }
    });
    assert_eq!(result, Err(BtcError::Cancelled));
    assert_eq!(rig.fake.count(), 4 + 5);
    // Cancelled before starting: nothing at all.
    let rig = Rig::new(BtcIndexer::Esplora, healthy);
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let result = discover(
        &client,
        &mut session,
        &job,
        &AtomicBool::new(true),
        &mut |_| {},
    );
    assert_eq!(result, Err(BtcError::Cancelled));
    assert_eq!(rig.fake.count(), 0);
}

/// A segwit previous transaction with `outputs`; returns (raw, txid).
fn prev_tx(outputs: &[([u8; 22], u64)], salt: u8) -> TestResult<(Vec<u8>, Txid)> {
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            prevout: OutPoint {
                txid: Txid::from_bytes([salt; 32]),
                vout: 3,
            },
            script_sig: Vec::new(),
            sequence: 0xffff_fffd,
            witness: vec![vec![0x30; 71], vec![0x02; 33]],
        }],
        outputs: outputs
            .iter()
            .map(|(script, value)| {
                Ok(TxOut {
                    value: Sats::new(*value).ok_or("sats")?,
                    script_pubkey: script.to_vec(),
                })
            })
            .collect::<TestResult<Vec<TxOut>>>()?,
        lock_time: 0,
    };
    Ok((serialize(&tx, true), compute_txid(&tx)))
}

/// Flips one byte of the first output value (amount forgery, CVE-2020-14199).
fn forge_amount(raw: &[u8], value: u64) -> TestResult<Vec<u8>> {
    let needle = value.to_le_bytes();
    let at = raw
        .windows(8)
        .position(|window| window == needle)
        .ok_or("value bytes")?;
    let mut forged = raw.to_vec();
    forged[at] ^= 0x01;
    Ok(forged)
}

fn utxo_entry(txid: &Txid, vout: u32, value: u64, height: Option<u32>) -> String {
    let status = height.map_or_else(
        || "{\"confirmed\":false}".to_owned(),
        |height| {
            format!(
                "{{\"confirmed\":true,\"block_height\":{height},\"block_hash\":\"{}\",\"block_time\":1793055496}}",
                "ab".repeat(32)
            )
        },
    );
    format!(
        "{{\"txid\":\"{}\",\"vout\":{vout},\"status\":{status},\"value\":{value}}}",
        txid.to_display_hex()
    )
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one scenario covering spec/08 §4.7 steps 1–4"
)]
fn refresh_verifies_candidates_through_core() -> TestResult {
    let r0 = ours(BtcChain::Receive, 0)?;
    let r1 = ours(BtcChain::Receive, 1)?;
    let c0 = ours(BtcChain::Change, 0)?;
    // One transaction pays r0 (vout 0) and c0 (vout 1); another pays r1.
    let (raw_a, txid_a) = prev_tx(
        &[(r0.script_pubkey(), 50_000), (c0.script_pubkey(), 7_000)],
        1,
    )?;
    let (raw_b, txid_b) = prev_tx(&[(r1.script_pubkey(), 9_000)], 2)?;
    let (_, txid_known) = prev_tx(&[(r1.script_pubkey(), 1)], 3)?;
    let (_, txid_pending) = prev_tx(&[(r1.script_pubkey(), 2)], 4)?;
    let (_, txid_future) = prev_tx(&[(r1.script_pubkey(), 3)], 5)?;
    let raws: HashMap<String, Vec<u8>> = [(txid_a, raw_a), (txid_b, raw_b)]
        .into_iter()
        .map(|(txid, raw)| (txid.to_display_hex(), raw))
        .collect();
    let utxos: HashMap<String, String> = [
        (
            r0.as_str().to_owned(),
            format!("[{}]", utxo_entry(&txid_a, 0, 50_000, Some(TIP - 2))),
        ),
        (
            r1.as_str().to_owned(),
            format!(
                "[{},{},{},{}]",
                // Indexer hint differs from the verified value.
                utxo_entry(&txid_b, 0, 9_999, Some(TIP)),
                utxo_entry(&txid_known, 0, 1, Some(TIP - 100)),
                utxo_entry(&txid_pending, 0, 2, None),
                utxo_entry(&txid_future, 0, 3, Some(TIP + 1)),
            ),
        ),
        (
            c0.as_str().to_owned(),
            format!("[{}]", utxo_entry(&txid_a, 1, 7_000, Some(TIP - 2))),
        ),
    ]
    .into_iter()
    .collect();
    let (r0_text, r1_text, c0_text) = (
        r0.as_str().to_owned(),
        r1.as_str().to_owned(),
        c0.as_str().to_owned(),
    );
    let rig = Rig::new(BtcIndexer::Esplora, move |call| match call.verb {
        Verb::Rpc if call.method == "getrawtransaction" => raws
            .get(&first_param(call))
            .map_or(Reply::RpcError(-5), |raw| {
                Reply::Result(format!("\"{}\"", yw_core::hex::encode(raw)))
            }),
        Verb::Get => {
            let path = call.path();
            match path_address(path) {
                Some(address) if path.ends_with("/utxo") => {
                    Reply::json(utxos.get(address).map_or("[]", String::as_str))
                }
                Some(address) if address == r0_text => {
                    Reply::json(&address_json(address, [1, 0, 1], [0, 0, 0]))
                }
                Some(address) if address == r1_text => {
                    Reply::json(&address_json(address, [4, 0, 4], [1, 0, 1]))
                }
                Some(address) if address == c0_text => {
                    Reply::json(&address_json(address, [1, 0, 1], [1, 0, 1]))
                }
                _ => healthy(call),
            }
        }
        _ => healthy(call),
    });
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let mut session = new_session();
    let mut job = refresh_job(3, 2);
    job.known = vec![OutPoint {
        txid: txid_known,
        vout: 0,
    }];
    job.inflight_change = vec![0];
    let result = refresh(&client, &mut session, &job)?;
    assert_eq!(result.chain.tip_height, TIP);
    assert_eq!(result.mempool.mempool_min, 100);
    // History of the watch set: receive 0..3, change 0..2.
    assert_eq!(result.addresses.len(), 5);
    let r1_state = result.addresses[1];
    assert_eq!(r1_state.summary.tx_count, 5);
    assert!(r1_state.pending_incoming);
    // c0 is an in-flight change address: no "미확정 입금".
    let c0_state = result.addresses[3];
    assert_eq!((c0_state.chain, c0_state.index), (BtcChain::Change, 0));
    assert!(c0_state.summary.unconfirmed_incoming && !c0_state.pending_incoming);
    // Candidates: confirmed with conf ≥ 1 only (the unconfirmed and above-tip ones are left out).
    let outpoints: Vec<(Txid, u32)> = result
        .candidates
        .iter()
        .map(|candidate| (candidate.outpoint.txid, candidate.outpoint.vout))
        .collect();
    assert_eq!(
        outpoints,
        [(txid_a, 0), (txid_b, 0), (txid_known, 0), (txid_a, 1)]
    );
    // Verified: everything not known, through Core; tx A fetched once for both outputs.
    let verified: Vec<(Txid, u32, u64, bool, RawSource)> = result
        .verified
        .iter()
        .map(|utxo| {
            (
                utxo.outpoint.txid,
                utxo.outpoint.vout,
                utxo.value.get(),
                utxo.hint_mismatch,
                utxo.source,
            )
        })
        .collect();
    assert_eq!(
        verified,
        [
            (txid_a, 0, 50_000, false, RawSource::Core),
            (txid_b, 0, 9_000, true, RawSource::Core),
            (txid_a, 1, 7_000, false, RawSource::Core),
        ]
    );
    assert_eq!(result.verified[2].chain, BtcChain::Change);
    assert_eq!(result.verify_failures(), 0);
    let fetched: Vec<String> = rig
        .fake
        .calls()
        .iter()
        .filter(|call| call.method == "getrawtransaction")
        .map(first_param)
        .collect();
    assert_eq!(fetched, [txid_a.to_display_hex(), txid_b.to_display_hex()]);
    // UTXO lists only for addresses with confirmed unspent outputs.
    let utxo_requests = rig
        .fake
        .get_paths()
        .iter()
        .filter(|path| path.ends_with("/utxo"))
        .count();
    assert_eq!(utxo_requests, 3);
    // Every request start is ≥ 200 ms after the previous one.
    let starts: Vec<u64> = rig.fake.calls().iter().map(|call| call.at_ms).collect();
    assert!(starts.windows(2).all(|pair| pair[1] - pair[0] >= 200));
    rig.log.assert_no_url();
    Ok(())
}

#[test]
fn prev_tx_fallback_txraw() -> TestResult {
    // Core -5 → one indexer TxRaw → the recorded testnet4 transaction verifies.
    let real = Txid::from_display_hex(REAL_TXID).map_err(|error| format!("{error:?}"))?;
    let program = yw_core::hex::decode_array::<20>(REAL_PROGRAM)?;
    let hex = fixture_body(esplora::TESTNET4_TX_HEX);
    let forged_hex = yw_core::hex::encode(&forge_amount(&yw_core::hex::decode(&hex)?, REAL_VALUE)?);
    for (indexer_hex, expected) in [
        (hex.clone(), Ok(REAL_VALUE)),
        (forged_hex, Err(PrevTxError::TxidMismatch)),
    ] {
        let rig = Rig::new(BtcIndexer::Esplora, move |call| {
            match (call.verb, call.method.as_str()) {
                (Verb::Rpc, "getrawtransaction") => {
                    Reply::Envelope(core::TESTNET4_GETRAWTRANSACTION_MISSING.to_vec())
                }
                (Verb::Get, _) if call.path().ends_with("/hex") => Reply::text(&indexer_hex),
                _ => healthy(call),
            }
        });
        let client = BtcClient::new(rig.env(), &rig.endpoint);
        let mut session = new_session();
        yw_app::btc::chain::ensure_chain(&client, &mut session, chain_input(), false)?;
        let (raw, source) = prev_transaction(&client, &session, &real)?.ok_or("raw")?;
        assert_eq!(source, RawSource::Indexer);
        assert_eq!(
            verify_prev_output(&raw, &real, 0, &p2wpkh_script_pubkey(&program))
                .map(|prev| prev.value.get()),
            expected
        );
        let hex_requests: Vec<String> = rig
            .fake
            .get_paths()
            .into_iter()
            .filter(|path| path.ends_with("/hex"))
            .collect();
        assert_eq!(hex_requests, [format!("/tx/{REAL_TXID}/hex")]);
        assert_eq!(
            rig.fake
                .methods()
                .iter()
                .filter(|method| *method == "getrawtransaction")
                .count(),
            1
        );
    }
    // Core gives the recorded transaction: no indexer request.
    let rig = Rig::new(BtcIndexer::Esplora, |call| match call.method.as_str() {
        "getrawtransaction" => Reply::Envelope(core::TESTNET4_GETRAWTRANSACTION.to_vec()),
        _ => healthy(call),
    });
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let mut session = new_session();
    yw_app::btc::chain::ensure_chain(&client, &mut session, chain_input(), false)?;
    let (raw, source) = prev_transaction(&client, &session, &real)?.ok_or("raw")?;
    assert_eq!(source, RawSource::Core);
    assert!(verify_prev_output(&raw, &real, 0, &p2wpkh_script_pubkey(&program)).is_ok());
    assert!(
        !rig.fake
            .get_paths()
            .iter()
            .any(|path| path.ends_with("/hex"))
    );
    // Neither gives it: unavailable.
    let rig = Rig::new(BtcIndexer::Esplora, |call| {
        match (call.verb, call.method.as_str()) {
            (Verb::Rpc, "getrawtransaction") => Reply::Transport(HttpError::Timeout),
            (Verb::Get, _) if call.path().ends_with("/hex") => {
                Reply::fixture(esplora::TESTNET4_TX_HEX_MISSING)
            }
            _ => healthy(call),
        }
    });
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let mut session = new_session();
    yw_app::btc::chain::ensure_chain(&client, &mut session, chain_input(), false)?;
    assert_eq!(prev_transaction(&client, &session, &real)?, None);
    Ok(())
}

#[test]
fn prev_tx_amount_forgery_rejected() -> TestResult {
    let r0 = ours(BtcChain::Receive, 0)?;
    let (raw, txid) = prev_tx(&[(r0.script_pubkey(), 80_000)], 9)?;
    let forged = forge_amount(&raw, 80_000)?;
    // Through the Core path and through the indexer fallback.
    for via_core in [true, false] {
        let forged = forged.clone();
        let r0_text = r0.as_str().to_owned();
        let rig = Rig::new(BtcIndexer::Esplora, move |call| match call.verb {
            Verb::Rpc if call.method == "getrawtransaction" => {
                if via_core {
                    Reply::Result(format!("\"{}\"", yw_core::hex::encode(&forged)))
                } else {
                    Reply::RpcError(-5)
                }
            }
            Verb::Get => match path_address(call.path()) {
                Some(address) if address == r0_text && call.path().ends_with("/utxo") => {
                    Reply::json(&format!("[{}]", utxo_entry(&txid, 0, 80_000, Some(TIP))))
                }
                Some(address) if address == r0_text => {
                    Reply::json(&address_json(address, [1, 0, 1], [0, 0, 0]))
                }
                _ if call.path().ends_with("/hex") => Reply::text(&yw_core::hex::encode(&forged)),
                _ => healthy(call),
            },
            Verb::Rpc | Verb::PostText => healthy(call),
        });
        let client = BtcClient::new(rig.env(), &rig.endpoint);
        let mut session = new_session();
        let result = refresh(&client, &mut session, &refresh_job(1, 0))?;
        assert!(result.verified.is_empty());
        assert_eq!(result.verify_failures(), 1);
        assert_eq!(
            result.failed[0].reason,
            VerifyFailure::Prev(PrevTxError::TxidMismatch)
        );
        assert_eq!(result.candidates.len(), 1);
        // A forged Core answer is not retried through the indexer.
        let hex_requests = rig
            .fake
            .get_paths()
            .iter()
            .filter(|path| path.ends_with("/hex"))
            .count();
        assert_eq!(hex_requests, usize::from(!via_core));
    }
    Ok(())
}

#[test]
#[expect(clippy::too_many_lines, reason = "the spec/08 §12.2 observation table")]
fn esplora_tx_status_ambiguous() -> TestResult {
    let tx = Txid::from_display_hex(REAL_TXID).map_err(|error| format!("{error:?}"))?;
    let unknown = "{\"confirmed\":false}";
    let confirmed = fixture_body(esplora::TESTNET4_TX_STATUS_CONFIRMED);
    let cases: Vec<(Reply, String, Option<Reply>, bool, TrackObservation, bool)> = vec![
        // getmempoolentry object → InMempool (no indexer request).
        (
            Reply::Result("{\"vsize\":141}".to_owned()),
            unknown.to_owned(),
            None,
            true,
            TrackObservation::InMempool,
            false,
        ),
        // -5 + {"confirmed":false} → NotFound (not_found_count + 1).
        (
            Reply::RpcError(-5),
            unknown.to_owned(),
            None,
            true,
            TrackObservation::NotFound,
            false,
        ),
        // -5 + confirmed → Confirmed{height}.
        (
            Reply::RpcError(-5),
            confirmed.clone(),
            None,
            true,
            TrackObservation::Confirmed { height: 157_695 },
            false,
        ),
        // getmempoolentry unsupported (-32601): {"confirmed":false} + /hex 200 → InMempool.
        (
            Reply::RpcError(-32_601),
            unknown.to_owned(),
            Some(Reply::fixture(esplora::TESTNET4_TX_HEX)),
            true,
            TrackObservation::InMempool,
            true,
        ),
        // … + /hex 404 → NotFound.
        (
            Reply::RpcError(-32_601),
            unknown.to_owned(),
            Some(Reply::fixture(esplora::TESTNET4_TX_HEX_MISSING)),
            true,
            TrackObservation::NotFound,
            true,
        ),
        // Known unsupported mode (no getmempoolentry call): confirmed → Confirmed.
        (
            Reply::status(500),
            confirmed,
            None,
            false,
            TrackObservation::Confirmed { height: 157_695 },
            false,
        ),
    ];
    for (entry, status_body, hex, mempool_entry, expected, unsupported) in cases {
        let probe = hex.clone();
        let rig = Rig::new(BtcIndexer::Esplora, move |call| {
            match (call.verb, call.method.as_str()) {
                (Verb::Rpc, "getmempoolentry") => entry.clone(),
                (Verb::Get, _) if call.path().ends_with("/status") => Reply::json(&status_body),
                (Verb::Get, _) if call.path().ends_with("/hex") => {
                    probe.clone().unwrap_or_else(|| Reply::status(404))
                }
                _ => healthy(call),
            }
        });
        let client = BtcClient::new(rig.env(), &rig.endpoint);
        let mut session = new_session();
        let job = TrackJob {
            txid: tx,
            mempool_entry,
            indexer_only: false,
            replacements: Vec::new(),
            trigger: Trigger::Automatic,
            chain: chain_input(),
        };
        let result = observe_tx(&client, &mut session, &job)?;
        assert_eq!(result.observation, expected);
        assert_eq!(result.mempool_entry_unsupported, unsupported);
        let hex_requests = rig
            .fake
            .get_paths()
            .iter()
            .filter(|path| path.ends_with("/hex"))
            .count();
        assert_eq!(hex_requests, usize::from(hex.is_some()));
        assert_eq!(
            rig.fake.methods().contains(&"getmempoolentry".to_owned()),
            mempool_entry
        );
        // Tracking never posts anything.
        assert_eq!(rig.fake.count_verb(Verb::PostText), 0);
    }
    // Abandoned entries: indexer TxStatus only.
    let rig = Rig::new(BtcIndexer::Esplora, |call| {
        if call.path().ends_with("/status") {
            Reply::json("{\"confirmed\":false}")
        } else {
            healthy(call)
        }
    });
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let mut session = new_session();
    let job = TrackJob {
        txid: tx,
        mempool_entry: true,
        indexer_only: true,
        replacements: Vec::new(),
        trigger: Trigger::User,
        chain: chain_input(),
    };
    assert_eq!(
        observe_tx(&client, &mut session, &job)?.observation,
        TrackObservation::NotFound
    );
    assert!(!rig.fake.methods().contains(&"getmempoolentry".to_owned()));
    Ok(())
}

/// Review fix (spec/08 §12.2): an indexer `Confirmed` of a record with an in-flight replacement
/// is applied only after Core `getmempoolentry` answered `-5` for that replacement; while Core
/// still has it the confirmation is `Deferred` (no `Conflicted` replacement on the indexer's
/// word alone).
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the replacement guard table in one place"
)]
fn confirmation_waits_for_replacement_absent_from_core() -> TestResult {
    let tx = Txid::from_display_hex(REAL_TXID).map_err(|error| format!("{error:?}"))?;
    let replacement = Txid::from_bytes([0x77; 32]);
    let replacement_hex = replacement.to_display_hex();
    let confirmed = fixture_body(esplora::TESTNET4_TX_STATUS_CONFIRMED);
    let in_mempool = || Reply::Result("{\"vsize\":141}".to_owned());
    // (replacement's getmempoolentry, step 2 only, getmempoolentry usable, expected,
    //  unsupported now, getmempoolentry calls)
    let cases: Vec<(Reply, bool, bool, TrackObservation, bool, usize)> = vec![
        // Full tracking (original -5, indexer confirmed), replacement in the Core mempool.
        (
            in_mempool(),
            false,
            true,
            TrackObservation::Deferred,
            false,
            2,
        ),
        // … replacement absent: confirmed.
        (
            Reply::RpcError(-5),
            false,
            true,
            TrackObservation::Confirmed { height: 157_695 },
            false,
            2,
        ),
        // Confirmation-only tracking of a `Replaced` original: same guard.
        (
            in_mempool(),
            true,
            true,
            TrackObservation::Deferred,
            false,
            1,
        ),
        (
            Reply::RpcError(-5),
            true,
            true,
            TrackObservation::Confirmed { height: 157_695 },
            false,
            1,
        ),
        // The endpoint has no getmempoolentry: no Core answer, server based as before.
        (
            Reply::RpcError(-32_601),
            true,
            true,
            TrackObservation::Confirmed { height: 157_695 },
            true,
            1,
        ),
        (
            in_mempool(),
            true,
            false,
            TrackObservation::Confirmed { height: 157_695 },
            false,
            0,
        ),
    ];
    for (entry, indexer_only, mempool_entry, expected, unsupported, calls) in cases {
        let wanted = replacement_hex.clone();
        let status_body = confirmed.clone();
        let rig = Rig::new(BtcIndexer::Esplora, move |call| {
            match (call.verb, call.method.as_str()) {
                (Verb::Rpc, "getmempoolentry") if first_param(call) == wanted => entry.clone(),
                (Verb::Rpc, "getmempoolentry") => Reply::RpcError(-5),
                (Verb::Get, _) if call.path().ends_with("/status") => Reply::json(&status_body),
                _ => healthy(call),
            }
        });
        let client = BtcClient::new(rig.env(), &rig.endpoint);
        let mut session = new_session();
        let job = TrackJob {
            txid: tx,
            mempool_entry,
            indexer_only,
            replacements: vec![replacement],
            trigger: Trigger::Automatic,
            chain: chain_input(),
        };
        let result = observe_tx(&client, &mut session, &job)?;
        assert_eq!(
            result.observation, expected,
            "{indexer_only} {mempool_entry}"
        );
        assert_eq!(result.mempool_entry_unsupported, unsupported);
        let methods = rig.fake.methods();
        assert_eq!(
            methods
                .iter()
                .filter(|method| *method == "getmempoolentry")
                .count(),
            calls
        );
    }
    // Not a confirmation: the replacements are not queried.
    let rig = Rig::new(BtcIndexer::Esplora, |call| {
        match (call.verb, call.method.as_str()) {
            (Verb::Rpc, "getmempoolentry") => Reply::RpcError(-5),
            (Verb::Get, _) if call.path().ends_with("/status") => {
                Reply::json("{\"confirmed\":false}")
            }
            _ => healthy(call),
        }
    });
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let mut session = new_session();
    let job = TrackJob {
        txid: tx,
        mempool_entry: true,
        indexer_only: false,
        replacements: vec![replacement],
        trigger: Trigger::Automatic,
        chain: chain_input(),
    };
    assert_eq!(
        observe_tx(&client, &mut session, &job)?.observation,
        TrackObservation::NotFound
    );
    assert_eq!(
        rig.fake
            .methods()
            .iter()
            .filter(|method| *method == "getmempoolentry")
            .count(),
        1
    );
    Ok(())
}

#[test]
fn indexer_429_backoff() -> TestResult {
    // 429 × 3 then 200: success after 2 s, 4 s, 8 s.
    let limited = AtomicU32::new(0);
    let rig = Rig::new(BtcIndexer::Esplora, move |call| {
        if call.path().starts_with("/address/") && limited.fetch_add(1, Ordering::SeqCst) < 3 {
            Reply::status(429)
        } else {
            healthy(call)
        }
    });
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let mut session = new_session();
    let result = refresh(&client, &mut session, &refresh_job(1, 0))?;
    assert_eq!(result.addresses.len(), 1);
    assert_eq!(rig.clock.backoffs(), [2_000, 4_000, 8_000]);
    assert!(!rig.pace.in_cooldown(client.now_ms()));

    // 429 × 4: the job stops with E-BTC-002 and the 300 s cooldown starts.
    let limiting = Arc::new(AtomicBool::new(true));
    let server = Arc::clone(&limiting);
    let rig = Rig::new(BtcIndexer::Esplora, move |call| {
        if call.path().starts_with("/address/") && server.load(Ordering::SeqCst) {
            Reply::status(429)
        } else {
            healthy(call)
        }
    });
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let mut session = new_session();
    let error = refresh(&client, &mut session, &refresh_job(3, 0))
        .err()
        .ok_or("aborted")?;
    assert_eq!(error, BtcError::Indexer(IndexerError::RateLimited));
    assert!(error.is_rate_limited());
    assert_eq!(error.code(), Some(ErrorCode::Btc002));
    assert_eq!(rig.clock.backoffs(), [2_000, 4_000, 8_000]);
    let address_requests = rig
        .fake
        .get_paths()
        .iter()
        .filter(|path| path.starts_with("/address/"))
        .count();
    assert_eq!(address_requests, 4, "the job stops at the first address");
    // Discovery aborts the same way (the caller leaves discovery_done = false).
    let job = DiscoveryJob {
        account: account(),
        discovery: Discovery::full(),
        chain: chain_input(),
    };
    assert_eq!(
        discover(
            &client,
            &mut session,
            &job,
            &AtomicBool::new(false),
            &mut |_| {}
        )
        .err(),
        Some(BtcError::Indexer(IndexerError::RateLimited))
    );
    // During the cooldown automatic refreshes and tracking send nothing; user refreshes run.
    let before = rig.fake.count();
    let mut automatic = refresh_job(1, 0);
    automatic.trigger = Trigger::Automatic;
    assert_eq!(
        refresh(&client, &mut session, &automatic).err(),
        Some(BtcError::Cooldown)
    );
    let track = TrackJob {
        txid: Txid::from_bytes([3; 32]),
        mempool_entry: true,
        indexer_only: false,
        replacements: Vec::new(),
        trigger: Trigger::Automatic,
        chain: chain_input(),
    };
    assert_eq!(
        observe_tx(&client, &mut session, &track).err(),
        Some(BtcError::Cooldown)
    );
    assert_eq!(rig.fake.count(), before);
    limiting.store(false, Ordering::SeqCst);
    rig.clock.advance(250_000);
    assert_eq!(
        refresh(&client, &mut session, &automatic).err(),
        Some(BtcError::Cooldown)
    );
    assert_eq!(rig.fake.count(), before);
    refresh(&client, &mut session, &refresh_job(1, 0))?;
    assert!(
        rig.fake.count() > before,
        "a user refresh runs during the cooldown"
    );
    rig.clock.advance(60_000);
    let before = rig.fake.count();
    refresh(&client, &mut session, &automatic)?;
    assert!(
        rig.fake.count() > before,
        "automatic refreshes resume after 300 s"
    );
    // Request starts are ≥ 200 ms apart throughout.
    let starts: Vec<u64> = rig.fake.calls().iter().map(|call| call.at_ms).collect();
    assert!(starts.windows(2).all(|pair| pair[1] - pair[0] >= 200));
    rig.log.assert_no_url();
    Ok(())
}

#[test]
fn pacing_spaces_request_starts() -> TestResult {
    // Each fake request takes 10 ms: the request line waits the remaining 190 ms.
    let rig = Rig::new(BtcIndexer::Esplora, healthy);
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let mut session = new_session();
    refresh(&client, &mut session, &refresh_job(2, 2))?;
    let starts: Vec<u64> = rig.fake.calls().iter().map(|call| call.at_ms).collect();
    assert_eq!(starts.len(), 4 + 1 + 4);
    assert!(starts.windows(2).all(|pair| pair[1] - pair[0] == 200));
    assert!(rig.clock.sleeps().iter().all(|ms| *ms == 190));
    // The line is shared across jobs of the session: a new job waits too.
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    refresh(&client, &mut session, &refresh_job(1, 0))?;
    let starts: Vec<u64> = rig.fake.calls().iter().map(|call| call.at_ms).collect();
    assert!(starts.windows(2).all(|pair| pair[1] - pair[0] >= 200));
    Ok(())
}

#[test]
fn esplora_settings_test() -> TestResult {
    let cases = [
        (
            Reply::fixture(esplora::TESTNET4_BLOCK_HEIGHT_0),
            EsploraTestOutcome::Ok,
        ),
        (
            Reply::fixture(esplora::MAINNET_BLOCK_HEIGHT_0),
            EsploraTestOutcome::Mismatch,
        ),
        (Reply::text(TESTNET3_GENESIS), EsploraTestOutcome::Mismatch),
        (
            Reply::fixture(esplora::MAINNET_BLOCK_HEIGHT_0_SLASH),
            EsploraTestOutcome::Failed(IndexerError::Malformed),
        ),
        (
            Reply::text(&format!("{TESTNET4_GENESIS}\n")),
            EsploraTestOutcome::Failed(IndexerError::Malformed),
        ),
        (
            Reply::status(500),
            EsploraTestOutcome::Failed(IndexerError::Unreachable(None)),
        ),
        (
            Reply::status(403),
            EsploraTestOutcome::Failed(IndexerError::Auth),
        ),
        (
            Reply::status(429),
            EsploraTestOutcome::Failed(IndexerError::RateLimited),
        ),
        (
            Reply::Transport(HttpError::Tls),
            EsploraTestOutcome::Failed(IndexerError::Unreachable(Some(ErrorCode::Rpc008))),
        ),
    ];
    let base = HttpsUrl::parse(ESPLORA_BASE)?;
    for (reply, expected) in cases {
        let rig = Rig::new(BtcIndexer::Esplora, move |_| reply.clone());
        let outcome = esplora_test(
            &*rig.fake,
            &*rig.clock,
            &rig.log,
            BtcNetwork::Testnet4,
            &base,
        );
        assert_eq!(outcome, expected);
        // Exactly one GET of `/block-height/0`, no retry, no address.
        assert_eq!(rig.fake.get_paths(), ["/block-height/0"]);
        assert!(rig.clock.sleeps().is_empty());
        let message = outcome.message(BtcNetwork::Testnet4);
        assert!(!message.contains(SERVER_STRING));
        rig.log.assert_no_url();
        assert!(rig.log.lines()[0].contains("net=bitcoin:testnet4 idx=esplora path=block-height"));
    }
    assert_eq!(
        EsploraTestOutcome::Ok.message(BtcNetwork::Testnet4),
        "Esplora 서버가 작동합니다. (Bitcoin testnet4, genesis 일치)"
    );
    assert_eq!(
        EsploraTestOutcome::Mismatch.message(BtcNetwork::Testnet4),
        "Bitcoin 인덱서가 다른 네트워크를 가리킵니다. 설정 → Bitcoin에서 인덱서와 Esplora URL을 확인하세요. (E-BTC-003)"
    );
    // The mainnet line with the mainnet genesis passes.
    let rig = Rig::new(BtcIndexer::Esplora, |_| Reply::text(MAINNET_GENESIS));
    let mainnet = HttpsUrl::parse("https://mempool.example.test/api")?;
    assert_eq!(
        esplora_test(
            &*rig.fake,
            &*rig.clock,
            &rig.log,
            BtcNetwork::Mainnet,
            &mainnet
        ),
        EsploraTestOutcome::Ok
    );
    assert_eq!(
        rig.fake.calls()[0].url,
        "https://mempool.example.test/api/block-height/0"
    );
    Ok(())
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "automatic paths, the offer gate and every POST outcome"
)]
fn esplora_broadcast_manual_only() -> TestResult {
    let local = Txid::from_bytes([0x5a; 32]);
    let raw = [0x02, 0x00, 0xab, 0xcd];
    let rig = Rig::new(BtcIndexer::Esplora, move |call| {
        match (call.verb, call.method.as_str()) {
            (Verb::Rpc, "sendrawtransaction") => Reply::Transport(HttpError::Timeout),
            (Verb::Rpc, "testmempoolaccept") => Reply::Http(503, None, Vec::new()),
            (Verb::Rpc, "getmempoolentry") => Reply::RpcError(-32_601),
            (Verb::Get, _) if call.path().ends_with("/status") => {
                Reply::json("{\"confirmed\":false}")
            }
            (Verb::Get, _) if call.path().ends_with("/hex") => Reply::status(404),
            (Verb::PostText, _) => Reply::text(&local.to_display_hex()),
            _ => healthy(call),
        }
    });
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let mut session = new_session();
    let input = chain_input();
    // Automatic paths: broadcast, tracking, refresh → zero POSTs to the Esplora base.
    assert!(test_mempool_accept(&client, &mut session, &raw, "0.00002000", input).is_err());
    let sent = send_raw_transaction(&client, &mut session, &raw, "0.00002000", &local, input)?;
    assert_eq!(sent, SendRawResult::Transport);
    let comm_failure = matches!(
        broadcast_outcome(&sent, &local),
        BroadcastOutcome::BroadcastUnknown {
            comm_failure: true,
            ..
        }
    );
    assert!(comm_failure);
    let track = TrackJob {
        txid: local,
        mempool_entry: true,
        indexer_only: false,
        replacements: Vec::new(),
        trigger: Trigger::Automatic,
        chain: input,
    };
    assert_eq!(
        observe_tx(&client, &mut session, &track)?.observation,
        TrackObservation::NotFound
    );
    refresh(&client, &mut session, &refresh_job(2, 1))?;
    assert_eq!(rig.fake.count_verb(Verb::PostText), 0);

    // Offered only for esplora + BroadcastUnknown + a Core communication failure + step 3 passed.
    let gate = ManualBroadcastGate {
        broadcast_unknown: true,
        comm_failure,
    };
    assert!(manual_broadcast_offered(&rig.endpoint, &session, gate));
    // Not a communication failure: RPC rejections and other codes (yw-core decides).
    for result in [
        SendRawResult::RpcError { code: -26 },
        SendRawResult::RpcError { code: -5 },
        SendRawResult::Refused,
        SendRawResult::NotTxid,
    ] {
        assert!(!matches!(
            broadcast_outcome(&result, &local),
            BroadcastOutcome::BroadcastUnknown {
                comm_failure: true,
                ..
            }
        ));
    }
    for refused in [
        ManualBroadcastGate {
            broadcast_unknown: false,
            comm_failure: true,
        },
        ManualBroadcastGate {
            broadcast_unknown: true,
            comm_failure: false,
        },
    ] {
        assert!(!manual_broadcast_offered(&rig.endpoint, &session, refused));
        assert_eq!(
            esplora_broadcast_confirmed(&client, &session, refused, &raw, &local),
            Err(BtcError::Indexer(IndexerError::Refused))
        );
    }
    let mut changed = session.clone();
    changed.reset(); // e.g. esploraBaseUrl changed after step 3
    assert!(!manual_broadcast_offered(&rig.endpoint, &changed, gate));
    let bb = btc_support::endpoint(BtcNetwork::Testnet4, BtcIndexer::BbRpc);
    assert!(!manual_broadcast_offered(&bb, &session, gate));
    assert_eq!(rig.fake.count_verb(Verb::PostText), 0);

    // User-confirmed: one POST of the lowercase hex to `<base>/tx`.
    assert_eq!(
        esplora_broadcast_confirmed(&client, &session, gate, &raw, &local)?,
        EsploraPostOutcome::Submitted
    );
    let posts: Vec<_> = rig
        .fake
        .calls()
        .into_iter()
        .filter(|call| call.verb == Verb::PostText)
        .collect();
    assert_eq!(posts.len(), 1);
    assert_eq!(posts[0].url, format!("{ESPLORA_BASE}/tx"));
    assert_eq!(posts[0].body, b"0200abcd");
    assert_eq!(posts[0].cap, 4_096);

    for (reply, expected) in [
        (
            Reply::text(&Txid::from_bytes([1; 32]).to_display_hex()),
            EsploraPostOutcome::TxidMismatch,
        ),
        (
            Reply::text(&local.to_display_hex().to_ascii_uppercase()),
            EsploraPostOutcome::TxidMismatch,
        ),
        (
            Reply::json(&format!("\"{}\"", local.to_display_hex())),
            EsploraPostOutcome::TxidMismatch,
        ),
        (Reply::status(400), EsploraPostOutcome::Rejected),
        (
            Reply::status(500),
            EsploraPostOutcome::Failed(IndexerError::Unreachable(None)),
        ),
        (
            Reply::Transport(HttpError::Timeout),
            EsploraPostOutcome::Failed(IndexerError::Unreachable(Some(ErrorCode::Rpc002))),
        ),
    ] {
        let post_rig = Rig::new(BtcIndexer::Esplora, move |call| {
            if call.verb == Verb::PostText {
                reply.clone()
            } else {
                healthy(call)
            }
        });
        let client = BtcClient::new(post_rig.env(), &post_rig.endpoint);
        let mut session = ChainSession::new(BtcNetwork::Testnet4, BtcNetwork::Testnet4);
        yw_app::btc::chain::ensure_chain(&client, &mut session, input, false)?;
        let outcome = esplora_broadcast_confirmed(&client, &session, gate, &raw, &local)?;
        assert_eq!(outcome, expected);
        assert_eq!(post_rig.fake.count_verb(Verb::PostText), 1);
        assert!(!outcome.text().contains(SERVER_STRING));
        post_rig.log.assert_no_url();
    }
    assert_eq!(
        EsploraPostOutcome::Rejected.text(),
        "Esplora 서버가 거래 전송을 거부했습니다. 활동에서 상태를 확인하고 필요하면 수수료를 올리세요. (E-BTC-008)"
    );
    Ok(())
}
