//! Bitcoin Core JSON-RPC (spec/08 §4.2, §8.3, §11.3, §13; spec/09 §4.4 BTC-N6): the recorded
//! `QuickNode` responses parse; the Bitcoin envelope rule; per-method response caps; strict
//! decimal amounts; `testmempoolaccept` / `sendrawtransaction` / `getmempoolentry`
//! classification (`testmempoolaccept_mismatch_rejects`); HTTP 429 back-off; server strings never
//! reach a result, an error or a text (`server_strings_never_rendered`).

mod btc_support;

use btc_support::{
    MAINNET_GENESIS, REAL_PROGRAM, REAL_TXID, REAL_VALUE, Reply, Rig, SERVER_STRING,
    TESTNET4_GENESIS, TestResult, chain_info, core, first_param,
};
use yw_app::btc::BtcClient;
use yw_app::btc::client::parse_envelope;
use yw_app::btc::rpc::{
    BlockchainInfo, MempoolEntry, MempoolInfo, TxOutAnswer, TxOutInfo, estimate_smart_fee,
    get_block_hash_0, get_blockchain_info, get_mempool_entry, get_mempool_info,
    get_raw_transaction, get_tx_out, maxfeerate_value, send_failure, send_raw_transaction,
    test_mempool_accept,
};
use yw_app::errors::ErrorCode;
use yw_app::rpc::{RpcFailure, classify};
use yw_app::settings::BtcIndexer;
use yw_core::btc::fee::maxfeerate_literal;
use yw_core::btc::policy::{
    BroadcastOutcome, LocalTx, MempoolAccept, PrecheckOutcome, SendRawResult, broadcast_outcome,
    check_mempool_accept, reject_reason_text,
};
use yw_core::btc::prevtx::verify_prev_output;
use yw_core::btc::script::p2wpkh_script_pubkey;
use yw_core::btc::{BtcNetwork, Sats, Txid};
use yw_win::http::HttpError;

fn rig(handler: impl Fn(&btc_support::Call) -> Reply + Send + Sync + 'static) -> Rig {
    Rig::new(BtcIndexer::Esplora, handler)
}

fn txid(text: &str) -> TestResult<Txid> {
    Ok(Txid::from_display_hex(text).map_err(|error| format!("{error:?}"))?)
}

#[test]
fn recorded_core_fixtures_parse() -> TestResult {
    let world = rig(|call| match call.method.as_str() {
        "getblockhash" => Reply::Envelope(core::TESTNET4_GETBLOCKHASH_0.to_vec()),
        "getblockchaininfo" => Reply::Envelope(core::TESTNET4_GETBLOCKCHAININFO.to_vec()),
        "getmempoolinfo" => Reply::Envelope(core::TESTNET4_GETMEMPOOLINFO.to_vec()),
        "getrawtransaction" if first_param(call) == REAL_TXID => {
            Reply::Envelope(core::TESTNET4_GETRAWTRANSACTION.to_vec())
        }
        "getrawtransaction" => Reply::Envelope(core::TESTNET4_GETRAWTRANSACTION_MISSING.to_vec()),
        "testmempoolaccept" => {
            Reply::Envelope(core::TESTNET4_TESTMEMPOOLACCEPT_MISSING_INPUTS.to_vec())
        }
        _ => Reply::RpcError(-32_601),
    });
    let client = BtcClient::new(world.env(), &world.endpoint);
    assert_eq!(
        get_block_hash_0(&client)?,
        yw_core::hex::decode_array::<32>(TESTNET4_GENESIS)?
    );
    assert_eq!(
        get_blockchain_info(&client)?,
        BlockchainInfo {
            chain: Some(BtcNetwork::Testnet4),
            blocks: 157_717,
            headers: 157_717,
            initial_block_download: false,
            median_time: 1_793_068_708,
        }
    );
    assert_eq!(
        get_mempool_info(&client)?,
        MempoolInfo {
            mempool_min: 100,
            min_relay: 100,
            incremental: 100,
        }
    );
    let real = txid(REAL_TXID)?;
    let raw = get_raw_transaction(&client, &real)?;
    let program = yw_core::hex::decode_array::<20>(REAL_PROGRAM)?;
    let verified = verify_prev_output(&raw, &real, 0, &p2wpkh_script_pubkey(&program))
        .map_err(|error| format!("{error:?}"))?;
    assert_eq!(verified.value.get(), REAL_VALUE);
    let missing = txid("05a4e2d0e59fa96e8aa280038aec7e3bc517d12a0bb8c6b7e1b411422446217a")?;
    assert_eq!(
        get_raw_transaction(&client, &missing),
        Err(RpcFailure::Rpc(-5))
    );
    let accept = test_mempool_accept(&client, &[0x02; 60], "0.00012000")?;
    assert!(!accept.allowed);
    assert_eq!(accept.reject_reason.as_deref(), Some("missing-inputs"));
    assert_eq!(
        accept.txid,
        txid("ac7570a8996b6cf9cdc579c0e8cef0ce87a93988f7158a03fd5f9a29cc5f028a")?
    );
    assert_eq!(
        accept
            .reject_reason
            .as_deref()
            .map(|token| reject_reason_text(yw_core::lang::Lang::Ko, token)),
        Some("입력이 없거나 이미 사용되었습니다")
    );

    let mainnet = Rig {
        endpoint: btc_support::endpoint(BtcNetwork::Mainnet, BtcIndexer::Esplora),
        ..btc_support::Rig::new(BtcIndexer::Esplora, |call| match call.method.as_str() {
            "getblockchaininfo" => Reply::Envelope(core::MAINNET_GETBLOCKCHAININFO.to_vec()),
            "estimatesmartfee" => Reply::Envelope(core::MAINNET_ESTIMATESMARTFEE_6.to_vec()),
            "getblockhash" => Reply::Result(format!("\"{MAINNET_GENESIS}\"")),
            _ => Reply::RpcError(-32_601),
        })
    };
    let client = BtcClient::new(mainnet.env(), &mainnet.endpoint);
    let info = get_blockchain_info(&client)?;
    assert_eq!(info.chain, Some(BtcNetwork::Mainnet));
    assert_eq!(info.blocks, 973_327);
    assert_eq!(info.median_time, 1_793_065_432);
    // 0.00000128 BTC/kvB = 128 sat/kvB.
    assert_eq!(estimate_smart_fee(&client, 6)?, Some(128));
    assert_eq!(
        get_block_hash_0(&client)?,
        yw_core::hex::decode_array::<32>(MAINNET_GENESIS)?
    );
    let testnet = rig(|_| Reply::Envelope(core::TESTNET4_ESTIMATESMARTFEE_6.to_vec()));
    let client = BtcClient::new(testnet.env(), &testnet.endpoint);
    assert_eq!(estimate_smart_fee(&client, 6)?, None);
    let params = testnet.fake.calls()[0].params.clone();
    assert_eq!(params, "[6,\"economical\"]");
    Ok(())
}

#[test]
fn envelope_rules() {
    let cap = 4_096;
    let ok = |body: &str| parse_envelope(200, body.as_bytes(), 7, cap);
    assert!(ok(r#"{"jsonrpc":"2.0","result":"x","id":7}"#).is_ok());
    // Core 1.0 style: no `jsonrpc`, explicit `"error":null`.
    assert!(ok(r#"{"result":"x","error":null,"id":7}"#).is_ok());
    assert_eq!(
        ok(r#"{"result":null,"error":{"code":-5,"message":"m"},"id":7}"#),
        Err(RpcFailure::Rpc(-5))
    );
    for bad in [
        r#"{"jsonrpc":"2.0","result":"x","id":8}"#,
        r#"{"jsonrpc":"2.0","result":"x","id":"7"}"#,
        r#"{"jsonrpc":"2.0","result":"x"}"#,
        r#"{"jsonrpc":"1.0","result":"x","id":7}"#,
        r#"{"jsonrpc":2,"result":"x","id":7}"#,
        r#"{"jsonrpc":"2.0","result":null,"id":7}"#,
        r#"{"jsonrpc":"2.0","id":7}"#,
        r#"{"jsonrpc":"2.0","result":"x","error":{"code":-5},"id":7}"#,
        r#"{"jsonrpc":"2.0","error":{"message":"m"},"id":7}"#,
        r#"{"jsonrpc":"2.0","error":{"code":-5.0},"id":7}"#,
        r#"{"jsonrpc":"2.0","error":"m","id":7}"#,
        r#"[{"jsonrpc":"2.0","result":"x","id":7}]"#,
        "not json",
    ] {
        assert_eq!(ok(bad), Err(RpcFailure::Malformed), "{bad}");
    }
    // Over the cap.
    let long = format!(
        "{{\"jsonrpc\":\"2.0\",\"result\":\"{}\",\"id\":7}}",
        "a".repeat(cap)
    );
    assert_eq!(ok(&long), Err(RpcFailure::Malformed));
    // Statuses: 401/403/429 stay statuses, other statuses carry an error envelope when present.
    let error = br#"{"result":null,"error":{"code":-26,"message":"m"},"id":7}"#;
    assert_eq!(
        parse_envelope(500, error, 7, cap),
        Err(RpcFailure::Rpc(-26))
    );
    assert_eq!(
        parse_envelope(404, error, 7, cap),
        Err(RpcFailure::Rpc(-26))
    );
    assert_eq!(
        parse_envelope(500, b"<html>", 7, cap),
        Err(RpcFailure::Status(500))
    );
    assert_eq!(
        parse_envelope(500, br#"{"result":"x","error":null,"id":7}"#, 7, cap),
        Err(RpcFailure::Status(500))
    );
    for status in [401, 403, 429] {
        assert_eq!(
            parse_envelope(status, error, 7, cap),
            Err(RpcFailure::Status(status))
        );
    }
}

#[test]
fn response_caps_per_method() -> TestResult {
    let rig = rig(|_| Reply::RpcError(-1));
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let tx = txid(REAL_TXID)?;
    let _ = get_block_hash_0(&client);
    let _ = get_blockchain_info(&client);
    let _ = get_raw_transaction(&client, &tx);
    let _ = estimate_smart_fee(&client, 2);
    let _ = get_mempool_info(&client);
    let _ = test_mempool_accept(&client, &[1, 2, 3], "0.00002000");
    let _ = send_raw_transaction(&client, &[1, 2, 3], "0.00002000", &tx);
    let _ = get_mempool_entry(&client, &tx);
    let caps: Vec<(String, usize)> = rig
        .fake
        .calls()
        .into_iter()
        .map(|call| (call.method, call.cap))
        .collect();
    let expected = [
        ("getblockhash", 4_096),
        ("getblockchaininfo", 16_384),
        ("getrawtransaction", 820_224),
        ("estimatesmartfee", 4_096),
        ("getmempoolinfo", 4_096),
        ("testmempoolaccept", 16_384),
        ("sendrawtransaction", 4_096),
        ("getmempoolentry", 16_384),
    ];
    assert_eq!(
        caps,
        expected
            .iter()
            .map(|(method, cap)| ((*method).to_owned(), *cap))
            .collect::<Vec<_>>()
    );
    // Requests are JSON-RPC 2.0 with increasing ids.
    let ids: Vec<String> = rig
        .fake
        .calls()
        .iter()
        .map(|call| String::from_utf8_lossy(&call.body).into_owned())
        .collect();
    assert!(
        ids[0].starts_with(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getblockhash\",\"params\":[0]}"
        )
    );
    assert!(ids[7].contains("\"id\":8"));
    Ok(())
}

#[test]
fn strict_core_numbers() -> TestResult {
    // Review fix: a `feerate` that is not a plain positive BTC decimal is "no estimate" (manual
    // input with the floor), not a failed call; amounts stay strict (never through f64).
    for (feerate, expected) in [
        ("0.00001000", Ok(Some(1_000))),
        ("0", Ok(None)),
        ("1e-05", Ok(None)),
        ("-0.1", Ok(None)),
        ("0.000010001", Ok(None)),
        ("\"0.00001\"", Ok(None)),
        ("null", Ok(None)),
    ] {
        let body = format!("{{\"feerate\":{feerate},\"blocks\":2}}");
        let rig = rig(move |_| Reply::Result(body.clone()));
        let client = BtcClient::new(rig.env(), &rig.endpoint);
        assert_eq!(estimate_smart_fee(&client, 2), expected, "{feerate}");
    }
    for bad in ["1.0", "-1", "1e3", "\"5\"", "4294967296"] {
        let body = chain_info("testnet4", 1, 1, false, 1)
            .replace("\"blocks\":1,", &format!("\"blocks\":{bad},"));
        let rig = rig(move |_| Reply::Result(body.clone()));
        let client = BtcClient::new(rig.env(), &rig.endpoint);
        assert_eq!(
            get_blockchain_info(&client),
            Err(RpcFailure::Malformed),
            "{bad}"
        );
    }
    for bad in [
        format!("\"{}\"", TESTNET4_GENESIS.to_ascii_uppercase()),
        format!("\"{}\"", &TESTNET4_GENESIS[2..]),
        format!("\"0x{TESTNET4_GENESIS}\""),
        "0".to_owned(),
    ] {
        let rig = rig(move |_| Reply::Result(bad.clone()));
        let client = BtcClient::new(rig.env(), &rig.endpoint);
        assert_eq!(get_block_hash_0(&client), Err(RpcFailure::Malformed));
    }
    for bad in ["\"0\"", "\"abc\"", "\"ABCD\"", "12", "\"\""] {
        let rig = rig(move |_| Reply::Result(bad.to_owned()));
        let client = BtcClient::new(rig.env(), &rig.endpoint);
        assert_eq!(
            get_raw_transaction(&client, &txid(REAL_TXID)?),
            Err(RpcFailure::Malformed)
        );
    }
    let huge = format!("\"{}\"", "00".repeat(400_001));
    let rig = rig(move |_| Reply::Result(huge.clone()));
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    assert_eq!(
        get_raw_transaction(&client, &txid(REAL_TXID)?),
        Err(RpcFailure::Malformed)
    );
    // maxfeerate: yw-core's literal (ceil(rate / 1000) + 1 sat/vB as BTC/kvB, 8 decimals) is
    // sent as a JSON number literal unchanged.
    assert_eq!(maxfeerate_literal(10_200).as_deref(), Some("0.00012000"));
    assert_eq!(maxfeerate_literal(1_000).as_deref(), Some("0.00002000"));
    assert_eq!(
        yw_json::to_vec(&maxfeerate_value("0.00012000")?),
        b"0.00012000".to_vec()
    );
    assert_eq!(maxfeerate_value("x"), Err(RpcFailure::Malformed));
    Ok(())
}

/// Review fix: `incrementalrelayfee` missing or malformed is 1,000 sat/kvB (spec/08 §9); the
/// floor inputs stay required.
#[test]
fn mempool_info_incremental_default() {
    for (incremental, expected) in [
        (",\"incrementalrelayfee\":0.00002000", Ok(2_000)),
        ("", Ok(1_000)),
        (",\"incrementalrelayfee\":1e-05", Ok(1_000)),
        (",\"incrementalrelayfee\":\"0.00001\"", Ok(1_000)),
        (",\"incrementalrelayfee\":0", Ok(1_000)),
    ] {
        let body = format!(
            "{{\"loaded\":true,\"mempoolminfee\":0.00001000,\"minrelaytxfee\":0.00000100{incremental}}}"
        );
        let rig = rig(move |_| Reply::Result(body.clone()));
        let client = BtcClient::new(rig.env(), &rig.endpoint);
        assert_eq!(
            get_mempool_info(&client).map(|info| info.incremental),
            expected,
            "{incremental}"
        );
    }
    let rig = rig(|_| Reply::Result("{\"minrelaytxfee\":0.00000100}".to_owned()));
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    assert_eq!(get_mempool_info(&client), Err(RpcFailure::Malformed));
}

/// Review M5: `gettxout [txid, vout, true]` — an object is Core's view of an unspent output,
/// `null` (also without `error`) is spent or unknown, `-32601` means the endpoint lacks it.
#[test]
fn gettxout_answers() -> TestResult {
    let outpoint = yw_core::btc::OutPoint {
        txid: txid(REAL_TXID)?,
        vout: 1,
    };
    let script = format!("0014{REAL_PROGRAM}");
    let object = format!(
        "{{\"bestblock\":\"{}\",\"confirmations\":12,\"value\":0.00050000,\"scriptPubKey\":{{\"asm\":\"{SERVER_STRING}\",\"hex\":\"{script}\",\"type\":\"witness_v0_keyhash\"}},\"coinbase\":false}}",
        "00".repeat(32)
    );
    let rig_object = rig(move |_| Reply::Result(object.clone()));
    let client = BtcClient::new(rig_object.env(), &rig_object.endpoint);
    assert_eq!(
        get_tx_out(&client, &outpoint)?,
        TxOutAnswer::Unspent(TxOutInfo {
            value: Sats::new(50_000).ok_or("sats")?,
            script_pubkey: yw_core::hex::decode(&script)?,
            confirmations: 12,
            coinbase: false,
        })
    );
    let call = rig_object.fake.calls();
    assert_eq!(call[0].method, "gettxout");
    assert!(call[0].params.ends_with(",1,true]"), "{}", call[0].params);
    let rig_null = rig(|_| Reply::Result("null".to_owned()));
    let client = BtcClient::new(rig_null.env(), &rig_null.endpoint);
    assert_eq!(get_tx_out(&client, &outpoint)?, TxOutAnswer::Missing);
    let rig_missing = rig(|_| Reply::RpcError(-32_601));
    let client = BtcClient::new(rig_missing.env(), &rig_missing.endpoint);
    assert_eq!(get_tx_out(&client, &outpoint)?, TxOutAnswer::Unsupported);
    // Other methods still refuse a null result.
    let rig_strict = rig(|_| Reply::Result("null".to_owned()));
    let client = BtcClient::new(rig_strict.env(), &rig_strict.endpoint);
    assert_eq!(get_mempool_info(&client), Err(RpcFailure::Malformed));
    for bad in [
        "{\"confirmations\":1,\"value\":0.0005,\"scriptPubKey\":{\"hex\":\"0014AB\"},\"coinbase\":false}",
        "{\"confirmations\":1,\"value\":1e-3,\"scriptPubKey\":{\"hex\":\"00\"},\"coinbase\":false}",
        "{\"confirmations\":-1,\"value\":0.0005,\"scriptPubKey\":{\"hex\":\"00\"},\"coinbase\":false}",
        "{\"confirmations\":1,\"value\":0.0005,\"scriptPubKey\":{\"hex\":\"00\"}}",
        "7",
    ] {
        let rig_bad = rig(move |_| Reply::Result(bad.to_owned()));
        let client = BtcClient::new(rig_bad.env(), &rig_bad.endpoint);
        assert_eq!(
            get_tx_out(&client, &outpoint),
            Err(RpcFailure::Malformed),
            "{bad}"
        );
    }
    Ok(())
}

fn accept_body(
    allowed: bool,
    txid: &str,
    wtxid: &str,
    vsize: u64,
    base: &str,
    reason: &str,
) -> String {
    if allowed {
        format!(
            "[{{\"txid\":\"{txid}\",\"wtxid\":\"{wtxid}\",\"allowed\":true,\"vsize\":{vsize},\"fees\":{{\"base\":{base},\"effective-feerate\":0.00002000,\"effective-includes\":[\"{wtxid}\"]}}}}]"
        )
    } else {
        format!(
            "[{{\"txid\":\"{txid}\",\"wtxid\":\"{wtxid}\",\"allowed\":false,\"reject-reason\":\"{reason}\",\"reject-details\":\"{SERVER_STRING}\"}}]"
        )
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "every spec/08 §13 token in one table"
)]
fn testmempoolaccept_mismatch_rejects() -> TestResult {
    let plain_id = REAL_TXID;
    let witness_id = "ac7570a8996b6cf9cdc579c0e8cef0ce87a93988f7158a03fd5f9a29cc5f028a";
    let local = LocalTx {
        txid: txid(plain_id)?,
        wtxid: txid(witness_id)?.to_bytes(),
        vsize: 141,
        fee: Sats::new(2_820).ok_or("sats")?,
    };
    let run = |body: String| -> TestResult<(MempoolAccept, String)> {
        let rig = rig(move |_| Reply::Result(body.clone()));
        let client = BtcClient::new(rig.env(), &rig.endpoint);
        let accept = test_mempool_accept(&client, &[0xab; 10], "0.00012000")?;
        Ok((accept, rig.fake.calls()[0].params.clone()))
    };
    let (accept, params) = run(accept_body(
        true,
        plain_id,
        witness_id,
        141,
        "0.00002820",
        "",
    ))?;
    assert_eq!(params, "[[\"abababababababababab\"],0.00012000]");
    assert_eq!(
        check_mempool_accept(yw_core::lang::Lang::Ko, &accept, &local),
        PrecheckOutcome::Accepted
    );
    for body in [
        accept_body(true, plain_id, witness_id, 141, "0.00002821", ""),
        accept_body(true, plain_id, witness_id, 142, "0.00002820", ""),
        accept_body(true, witness_id, witness_id, 141, "0.00002820", ""),
        accept_body(true, plain_id, plain_id, 141, "0.00002820", ""),
    ] {
        let (accept, _) = run(body)?;
        assert_eq!(
            check_mempool_accept(yw_core::lang::Lang::Ko, &accept, &local),
            PrecheckOutcome::Rejected {
                text: "노드 검사 결과가 로컬 계산과 다릅니다"
            }
        );
    }
    for (token, kept, text) in [
        (
            "min relay fee not met",
            "min relay fee not met",
            "수수료율이 노드 최소값보다 낮습니다",
        ),
        (
            "mempool min fee not met",
            "mempool min fee not met",
            "수수료율이 노드 최소값보다 낮습니다",
        ),
        (
            "insufficient fee",
            "insufficient fee",
            "교체 수수료가 부족합니다",
        ),
        (
            "txn-mempool-conflict",
            "txn-mempool-conflict",
            "다른 미확정 거래와 충돌합니다",
        ),
        (
            "bad-txns-inputs-missingorspent",
            "bad-txns-inputs-missingorspent",
            "입력이 없거나 이미 사용되었습니다",
        ),
        (
            "non-final",
            "non-final",
            "잠금 시간이 아직 지나지 않았습니다(노드 높이 확인)",
        ),
        ("dust", "dust", "먼지 출력이 있습니다"),
        (
            "max-fee-exceeded",
            "max-fee-exceeded",
            "수수료 상한을 넘었습니다",
        ),
        (
            "txn-already-in-mempool",
            "txn-already-in-mempool",
            "이미 전송된 거래입니다",
        ),
        (
            "txn-already-known",
            "txn-already-known",
            "이미 전송된 거래입니다",
        ),
        ("Dust", "unknown", "알 수 없는 거부 사유"),
        ("dust ", "unknown", "알 수 없는 거부 사유"),
        (SERVER_STRING, "unknown", "알 수 없는 거부 사유"),
    ] {
        let (accept, _) = run(accept_body(false, plain_id, witness_id, 0, "", token))?;
        // Only the known token (or `unknown`) is kept; yw-core maps it to the fixed text.
        assert_eq!(accept.reject_reason.as_deref(), Some(kept));
        // The node already has our transaction: never `Rejected` (spec/08 §11.3).
        let expected = if kept.starts_with("txn-already-") {
            PrecheckOutcome::AlreadyKnown { text }
        } else {
            PrecheckOutcome::Rejected { text }
        };
        assert_eq!(
            check_mempool_accept(yw_core::lang::Lang::Ko, &accept, &local),
            expected
        );
        assert!(!format!("{accept:?}").contains(SERVER_STRING));
    }
    // An already-known answer about another transaction is a mismatch.
    let (accept, _) = run(accept_body(
        false,
        witness_id,
        witness_id,
        0,
        "",
        "txn-already-in-mempool",
    ))?;
    assert_eq!(
        check_mempool_accept(yw_core::lang::Lang::Ko, &accept, &local),
        PrecheckOutcome::Rejected {
            text: "노드 검사 결과가 로컬 계산과 다릅니다"
        }
    );
    // Exactly one element; allowed needs vsize and fees.base.
    for bad in [
        "[]".to_owned(),
        format!(
            "[{0},{0}]",
            accept_body(true, plain_id, witness_id, 141, "0.00002820", "")
                .trim_start_matches('[')
                .trim_end_matches(']')
        ),
        accept_body(true, plain_id, witness_id, 141, "2.82e-5", ""),
        format!("[{{\"txid\":\"{plain_id}\",\"wtxid\":\"{witness_id}\",\"allowed\":true}}]"),
    ] {
        let rig = rig(move |_| Reply::Result(bad.clone()));
        let client = BtcClient::new(rig.env(), &rig.endpoint);
        assert_eq!(
            test_mempool_accept(&client, &[1], "0.00002000"),
            Err(RpcFailure::Malformed)
        );
    }
    Ok(())
}

#[test]
fn sendrawtransaction_outcomes() -> TestResult {
    let local = txid(REAL_TXID)?;
    let other = txid("05a4e2d0e59fa96e8aa280038aec7e3bc517d12a0bb8c6b7e1b411422446217a")?;
    let cases = [
        (
            Reply::Result(format!("\"{REAL_TXID}\"")),
            SendRawResult::Txid(local),
            false,
        ),
        (
            Reply::Result(format!("\"{other}\"")),
            SendRawResult::Txid(other),
            false,
        ),
        (
            Reply::Result(format!("\"{}\"", REAL_TXID.to_ascii_uppercase())),
            SendRawResult::NotTxid,
            false,
        ),
        (
            Reply::RpcError(-27),
            SendRawResult::RpcError { code: -27 },
            false,
        ),
        (
            Reply::RpcError(-26),
            SendRawResult::RpcError { code: -26 },
            false,
        ),
        (
            Reply::RpcError(-25),
            SendRawResult::RpcError { code: -25 },
            false,
        ),
        (
            Reply::RpcError(-5),
            SendRawResult::RpcError { code: -5 },
            false,
        ),
        (
            Reply::RpcError(-32_601),
            SendRawResult::RpcError { code: -32_601 },
            false,
        ),
        (
            Reply::Transport(HttpError::Timeout),
            SendRawResult::Transport,
            true,
        ),
        (
            Reply::Http(502, None, b"bad gateway".to_vec()),
            SendRawResult::Transport,
            true,
        ),
        (
            Reply::Http(401, None, Vec::new()),
            SendRawResult::Refused,
            false,
        ),
        (
            Reply::Late(10_001, Box::new(Reply::Result(format!("\"{REAL_TXID}\"")))),
            SendRawResult::Timeout,
            true,
        ),
    ];
    for (reply, expected, communication) in cases {
        let rig = rig(move |_| reply.clone());
        let client = BtcClient::new(rig.env(), &rig.endpoint);
        let outcome = send_raw_transaction(&client, &[0xcd, 0x01], "0.00012000", &local);
        assert_eq!(outcome, expected);
        // yw-core decides the state and whether it was a communication failure.
        let comm_failure = matches!(
            broadcast_outcome(yw_core::lang::Lang::Ko, &outcome, &local),
            BroadcastOutcome::BroadcastUnknown {
                comm_failure: true,
                ..
            }
        );
        assert_eq!(comm_failure, communication, "{outcome:?}");
        // Sent once (no retry for timeouts, 5xx or RPC errors) with [hex, maxfeerate, 0].
        assert_eq!(send_failure(RpcFailure::Malformed), SendRawResult::Refused);
        let calls = rig.fake.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].params, "[\"cd01\",0.00012000,0]");
        assert!(!format!("{outcome:?}").contains(SERVER_STRING));
    }
    Ok(())
}

#[test]
fn getmempoolentry_outcomes() -> TestResult {
    let tx = txid(REAL_TXID)?;
    for (reply, expected) in [
        (
            Reply::Result("{\"vsize\":141,\"fees\":{\"base\":0.00000282}}".to_owned()),
            Ok(MempoolEntry::InMempool),
        ),
        (Reply::RpcError(-5), Ok(MempoolEntry::Absent)),
        (Reply::RpcError(-32_601), Ok(MempoolEntry::Unsupported)),
        (
            Reply::Result("\"x\"".to_owned()),
            Err(RpcFailure::Malformed),
        ),
        (
            Reply::Http(503, None, Vec::new()),
            Err(RpcFailure::Status(503)),
        ),
    ] {
        let rig = rig(move |_| reply.clone());
        let client = BtcClient::new(rig.env(), &rig.endpoint);
        assert_eq!(get_mempool_entry(&client, &tx), expected);
        assert_eq!(rig.fake.calls()[0].params, format!("[\"{REAL_TXID}\"]"));
    }
    Ok(())
}

#[test]
fn core_429_backoff_and_cooldown() -> TestResult {
    use std::sync::atomic::{AtomicU32, Ordering};
    for limited in [
        Reply::Http(429, None, Vec::new()),
        Reply::RpcError(-32_005),
        Reply::RpcError(429),
    ] {
        let seen = AtomicU32::new(0);
        let rig = rig(move |_| {
            if seen.fetch_add(1, Ordering::SeqCst) < 3 {
                limited.clone()
            } else {
                Reply::Envelope(core::TESTNET4_GETBLOCKHASH_0.to_vec())
            }
        });
        let client = BtcClient::new(rig.env(), &rig.endpoint);
        assert!(get_block_hash_0(&client).is_ok());
        assert_eq!(rig.clock.sleeps(), [2_000, 4_000, 8_000]);
        assert_eq!(rig.fake.count(), 4);
        assert!(!rig.pace.in_cooldown(client.now_ms()));
    }
    let rig = rig(|_| Reply::Http(429, None, Vec::new()));
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let failure = get_block_hash_0(&client).err().ok_or("429 abort")?;
    assert_eq!(failure, RpcFailure::Status(429));
    assert_eq!(classify(failure), ErrorCode::Rpc004);
    assert_eq!(rig.fake.count(), 4);
    assert_eq!(rig.clock.sleeps(), [2_000, 4_000, 8_000]);
    assert!(rig.pace.in_cooldown(client.now_ms()));
    // Request starts are ≥ 200 ms apart.
    let starts: Vec<u64> = rig.fake.calls().iter().map(|call| call.at_ms).collect();
    assert!(starts.windows(2).all(|pair| pair[1] - pair[0] >= 200));
    Ok(())
}

#[test]
fn server_strings_never_rendered() -> TestResult {
    let rig = rig(|call| match call.method.as_str() {
        "getblockchaininfo" => Reply::Result(chain_info("testnet4", 1, 1, false, 1)),
        "estimatesmartfee" => {
            Reply::Result(format!("{{\"errors\":[\"{SERVER_STRING}\"],\"blocks\":2}}"))
        }
        "testmempoolaccept" => Reply::Result(accept_body(
            false,
            REAL_TXID,
            REAL_TXID,
            0,
            "",
            SERVER_STRING,
        )),
        _ => Reply::RpcError(-26),
    });
    let client = BtcClient::new(rig.env(), &rig.endpoint);
    let mut rendered = Vec::new();
    rendered.push(format!("{:?}", get_blockchain_info(&client)));
    rendered.push(format!("{:?}", estimate_smart_fee(&client, 2)));
    let accept = test_mempool_accept(&client, &[1], "0.00002000")?;
    rendered.push(format!("{accept:?}"));
    rendered.push(
        accept
            .reject_reason
            .as_deref()
            .map_or("", |token| {
                reject_reason_text(yw_core::lang::Lang::Ko, token)
            })
            .to_owned(),
    );
    let tx = txid(REAL_TXID)?;
    let sent = send_raw_transaction(&client, &[1], "0.00002000", &tx);
    rendered.push(format!("{sent:?}"));
    let failure = get_raw_transaction(&client, &tx).err().ok_or("rpc error")?;
    rendered.push(format!("{failure:?}"));
    rendered.push(classify(failure).text_in(yw_core::lang::Lang::Ko));
    for text in &rendered {
        assert!(!text.contains(SERVER_STRING), "{text}");
        assert!(!text.contains("evil"), "{text}");
    }
    rig.log.assert_no_url();
    for line in rig.log.lines() {
        assert!(!line.contains("evil"), "{line}");
    }
    Ok(())
}
