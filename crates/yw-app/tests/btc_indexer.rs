//! Bitcoin address indexer (spec/08 §4.1, §4.3; spec/09 §4.4 BTC-N6, BTC-N7): the recorded
//! mempool.space responses parse as expected; requests come only from `BtcIndexerReq`
//! (`indexer_req_types_only`); Blockbook amounts are decimal strings
//! (`indexer_amount_strings`); the Esplora integer, status-field, address-stats and text
//! endpoint rules are strict (`esplora_integer_strict`, `esplora_utxo_status_fields`,
//! `esplora_address_stats`, `esplora_text_endpoints`); HTTP statuses map per §4.3
//! (`esplora_http_status`), without retries for 3xx/5xx and without server text.

mod btc_support;

use btc_support::{
    ADDRESS_0_0, CORE_URL, ESPLORA_BASE, MAINNET_GENESIS, REAL_PROGRAM, REAL_TXID, REAL_VALUE,
    Reply, Rig, SERVER_STRING, TESTNET4_GENESIS, TestResult, Verb, esplora, fixture_body,
    http_fixture,
};
use yw_app::btc::BtcClient;
use yw_app::btc::indexer::{
    AddrSummary, BtcIndexerReq, BtcIndexerResp, IndexerError, TxSeen, fetch, parse_bb,
    parse_bb_rest, parse_esplora,
};
use yw_app::errors::ErrorCode;
use yw_app::settings::BtcIndexer;
use yw_core::btc::address::BtcAddress;
use yw_core::btc::prevtx::{PrevTxError, verify_prev_output};
use yw_core::btc::script::p2wpkh_script_pubkey;
use yw_core::btc::{BtcNetwork, ScriptKind, Txid, parse_address};
use yw_json::{Limits, Value};
use yw_win::http::{HttpError, Response};

fn address(text: &str, net: BtcNetwork) -> TestResult<BtcAddress> {
    match parse_address(text, net).map_err(|error| format!("{error:?}"))? {
        ScriptKind::P2wpkh(program) => Ok(BtcAddress::p2wpkh(net, &program)),
        other => Err(format!("not p2wpkh: {other:?}").into()),
    }
}

fn txid(text: &str) -> TestResult<Txid> {
    Ok(Txid::from_display_hex(text).map_err(|error| format!("{error:?}"))?)
}

fn genesis(text: &str) -> TestResult<[u8; 32]> {
    Ok(yw_core::hex::decode_array::<32>(text)?)
}

fn json(body: &str) -> Response {
    Response {
        status: 200,
        content_type: Some("application/json; charset=utf-8".to_owned()),
        body: body.as_bytes().to_vec(),
    }
}

fn text(body: &str) -> Response {
    Response {
        status: 200,
        content_type: Some("text/plain".to_owned()),
        body: body.as_bytes().to_vec(),
    }
}

fn value(text: &str) -> TestResult<Value> {
    Ok(yw_json::parse(text.as_bytes(), &Limits::RESPONSE)?)
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "every recorded mempool.space capture"
)]
fn recorded_esplora_fixtures_parse() -> TestResult {
    let parse = |request: &BtcIndexerReq, raw: &[u8]| parse_esplora(request, &http_fixture(raw));
    assert_eq!(
        parse(
            &BtcIndexerReq::GenesisHash,
            esplora::TESTNET4_BLOCK_HEIGHT_0
        ),
        Ok(BtcIndexerResp::GenesisHash(genesis(TESTNET4_GENESIS)?))
    );
    assert_eq!(
        parse(&BtcIndexerReq::GenesisHash, esplora::MAINNET_BLOCK_HEIGHT_0),
        Ok(BtcIndexerResp::GenesisHash(genesis(MAINNET_GENESIS)?))
    );
    assert_eq!(
        parse(
            &BtcIndexerReq::GenesisHash,
            esplora::MAINNET_BLOCK_HEIGHT_0_SLASH
        ),
        Err(IndexerError::Malformed)
    );
    assert_eq!(
        parse(&BtcIndexerReq::TipHeight, esplora::TESTNET4_TIP_HEIGHT),
        Ok(BtcIndexerResp::TipHeight(157_717))
    );
    assert_eq!(
        parse(&BtcIndexerReq::TipHeight, esplora::MAINNET_TIP_HEIGHT),
        Ok(BtcIndexerResp::TipHeight(973_327))
    );
    let mainnet_used = address(
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        BtcNetwork::Mainnet,
    )?;
    assert_eq!(
        parse(
            &BtcIndexerReq::Address(mainnet_used),
            esplora::MAINNET_ADDRESS_USED
        ),
        Ok(BtcIndexerResp::Address(AddrSummary {
            tx_count: 178,
            confirmed_unspent: false,
            unconfirmed_incoming: false
        }))
    );
    let used = address(ADDRESS_0_0, BtcNetwork::Testnet4)?;
    assert_eq!(
        parse(
            &BtcIndexerReq::Address(used.clone()),
            esplora::TESTNET4_ADDRESS_USED
        ),
        Ok(BtcIndexerResp::Address(AddrSummary {
            tx_count: 119,
            confirmed_unspent: false,
            unconfirmed_incoming: false
        }))
    );
    let unused = address(
        "tb1q0nadvfv0ystndehjeldlac8alzu06hd05gqd6n",
        BtcNetwork::Testnet4,
    )?;
    assert_eq!(
        parse(
            &BtcIndexerReq::Address(unused.clone()),
            esplora::TESTNET4_ADDRESS_UNUSED
        ),
        Ok(BtcIndexerResp::Address(AddrSummary {
            tx_count: 0,
            confirmed_unspent: false,
            unconfirmed_incoming: false
        }))
    );
    // The echo must be the requested address.
    assert_eq!(
        parse(
            &BtcIndexerReq::Address(unused),
            esplora::TESTNET4_ADDRESS_USED
        ),
        Err(IndexerError::Malformed)
    );
    assert_eq!(
        parse(
            &BtcIndexerReq::Address(used),
            esplora::TESTNET4_ADDRESS_MAINNET_400
        ),
        Err(IndexerError::Rejected)
    );
    let payee = address(
        "tb1q0dzcgv7scppjxsnwlzpkt02vlmc5rtr40wyjgr",
        BtcNetwork::Testnet4,
    )?;
    let Ok(BtcIndexerResp::Utxo(list)) = parse(&BtcIndexerReq::Utxo(payee), esplora::TESTNET4_UTXO)
    else {
        return Err("utxo fixture".into());
    };
    assert_eq!(list.len(), 26);
    assert!(list.iter().all(|utxo| utxo.height.is_some()));
    let real = list
        .iter()
        .find(|utxo| utxo.outpoint.txid == txid(REAL_TXID).unwrap_or_default())
        .ok_or("real tx in utxo list")?;
    assert_eq!(real.outpoint.vout, 0);
    assert_eq!(real.value_hint.get(), REAL_VALUE);
    let real_txid = txid(REAL_TXID)?;
    assert_eq!(
        parse(
            &BtcIndexerReq::TxStatus(real_txid),
            esplora::TESTNET4_TX_STATUS_CONFIRMED
        ),
        Ok(BtcIndexerResp::TxStatus(TxSeen::Confirmed {
            height: 157_695
        }))
    );
    let missing = txid("05a4e2d0e59fa96e8aa280038aec7e3bc517d12a0bb8c6b7e1b411422446217a")?;
    assert_eq!(
        parse(
            &BtcIndexerReq::TxStatus(missing),
            esplora::TESTNET4_TX_STATUS_MISSING
        ),
        Ok(BtcIndexerResp::TxStatus(TxSeen::UnconfirmedOrUnknown))
    );
    assert_eq!(
        parse(
            &BtcIndexerReq::TxRaw(missing),
            esplora::TESTNET4_TX_HEX_MISSING
        ),
        Err(IndexerError::NotFound)
    );
    let Ok(BtcIndexerResp::TxRaw(raw)) =
        parse(&BtcIndexerReq::TxRaw(real_txid), esplora::TESTNET4_TX_HEX)
    else {
        return Err("tx hex fixture".into());
    };
    let program = yw_core::hex::decode_array::<20>(REAL_PROGRAM)?;
    let verified = verify_prev_output(&raw, &real_txid, 0, &p2wpkh_script_pubkey(&program))
        .map_err(|error| format!("{error:?}"))?;
    assert_eq!(verified.value.get(), REAL_VALUE);
    assert!(!verified.is_coinbase);
    Ok(())
}

fn rig(indexer: BtcIndexer) -> Rig {
    Rig::new(indexer, |call| match call.verb {
        Verb::Rpc => Reply::Result("{}".to_owned()),
        Verb::Get | Verb::PostText => Reply::json("{}"),
    })
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the three indexer formats side by side"
)]
fn indexer_req_types_only() -> TestResult {
    let ours = address(ADDRESS_0_0, BtcNetwork::Testnet4)?;
    let tx = txid(REAL_TXID)?;
    let requests = [
        BtcIndexerReq::Utxo(ours.clone()),
        BtcIndexerReq::Address(ours.clone()),
        BtcIndexerReq::TxStatus(tx),
        BtcIndexerReq::TxRaw(tx),
        BtcIndexerReq::GenesisHash,
        BtcIndexerReq::TipHeight,
    ];
    // esplora: GET only, `<base>` ‖ fixed paths, no trailing `/`, no query.
    let esplora_rig = rig(BtcIndexer::Esplora);
    let client = BtcClient::new(esplora_rig.env(), &esplora_rig.endpoint);
    for request in &requests {
        let _ = fetch(&client, request);
    }
    let calls = esplora_rig.fake.calls();
    assert!(calls.iter().all(|call| call.verb == Verb::Get));
    let urls: Vec<String> = calls.iter().map(|call| call.url.clone()).collect();
    assert_eq!(
        urls,
        [
            format!("{ESPLORA_BASE}/address/{ADDRESS_0_0}/utxo"),
            format!("{ESPLORA_BASE}/address/{ADDRESS_0_0}"),
            format!("{ESPLORA_BASE}/tx/{REAL_TXID}/status"),
            format!("{ESPLORA_BASE}/tx/{REAL_TXID}/hex"),
            format!("{ESPLORA_BASE}/block-height/0"),
            format!("{ESPLORA_BASE}/blocks/tip/height"),
        ]
    );
    let caps: Vec<usize> = calls.iter().map(|call| call.cap).collect();
    assert_eq!(caps, [1_048_576, 16_384, 4_096, 820_224, 4_096, 4_096]);
    for url in &urls {
        assert!(!url.ends_with('/') && !url.contains('?'), "{url}");
    }

    // bb-rpc: the four bb_* methods with fixed params; TipHeight builds nothing.
    let rpc_rig = rig(BtcIndexer::BbRpc);
    let client = BtcClient::new(rpc_rig.env(), &rpc_rig.endpoint);
    for request in &requests {
        let _ = fetch(&client, request);
    }
    assert_eq!(
        fetch(&client, &BtcIndexerReq::TipHeight),
        Err(IndexerError::Refused)
    );
    let calls = rpc_rig.fake.calls();
    assert!(
        calls
            .iter()
            .all(|call| call.verb == Verb::Rpc && call.url == CORE_URL)
    );
    let shapes: Vec<(String, String)> = calls
        .iter()
        .map(|call| (call.method.clone(), call.params.clone()))
        .collect();
    assert_eq!(
        shapes,
        [
            (
                "bb_getUTXOs".to_owned(),
                format!("[\"{ADDRESS_0_0}\",{{\"confirmed\":true}}]")
            ),
            (
                "bb_getAddress".to_owned(),
                format!("[\"{ADDRESS_0_0}\",{{\"details\":\"basic\"}}]")
            ),
            ("bb_getTx".to_owned(), format!("[\"{REAL_TXID}\"]")),
            ("bb_getTx".to_owned(), format!("[\"{REAL_TXID}\"]")),
            ("bb_getBlockHash".to_owned(), "[\"0\"]".to_owned()),
        ]
    );

    // bb-rest: GET under `<Core URL without '/'>/api/v2/`.
    let rest_rig = rig(BtcIndexer::BbRest);
    let client = BtcClient::new(rest_rig.env(), &rest_rig.endpoint);
    for request in &requests {
        let _ = fetch(&client, request);
    }
    let api = format!("{}/api/v2/", CORE_URL.trim_end_matches('/'));
    let urls: Vec<String> = rest_rig
        .fake
        .calls()
        .iter()
        .map(|call| call.url.clone())
        .collect();
    assert_eq!(
        urls,
        [
            format!("{api}utxo/{ADDRESS_0_0}?confirmed=true"),
            format!("{api}address/{ADDRESS_0_0}?details=basic"),
            format!("{api}tx/{REAL_TXID}"),
            format!("{api}tx/{REAL_TXID}"),
            format!("{api}block-index/0"),
        ]
    );

    // Nothing else is ever built.
    for fake in [&esplora_rig.fake, &rpc_rig.fake, &rest_rig.fake] {
        for call in fake.calls() {
            let all = format!("{} {} {}", call.url, call.method, call.params);
            for forbidden in [
                "xpub",
                "bb_getXpub",
                "bb_sendTransaction",
                "sendtx",
                "/txs",
                "fee-estimates",
                "/v1/fees",
                "scripthash",
                "outspend",
                "mempool",
            ] {
                assert!(!all.contains(forbidden), "{forbidden}: {all}");
            }
            assert_ne!(call.verb, Verb::PostText);
        }
    }

    // An address of the other network is refused without a request.
    let mainnet = address(
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        BtcNetwork::Mainnet,
    )?;
    let before = esplora_rig.fake.count();
    let client = BtcClient::new(esplora_rig.env(), &esplora_rig.endpoint);
    assert_eq!(
        fetch(&client, &BtcIndexerReq::Address(mainnet)),
        Err(IndexerError::Refused)
    );
    assert_eq!(esplora_rig.fake.count(), before);
    Ok(())
}

const BB_UTXOS: &str = r#"[{"txid":"005aa50eb8346e3f199f2b9292049b3eea0dcc4567cb3d45853c11a0b0eb77f1","vout":0,"value":"5840453620191","height":157695,"confirmations":23,"coinbase":false},{"txid":"542d41b14730fa7db5d834e30417d7475509f216211d5888f673cc89eb7e7e04","vout":1,"value":"479620","confirmations":0}]"#;
const BB_ADDRESS: &str = r#"{"page":1,"totalPages":1,"itemsOnPage":1000,"address":"tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl","balance":"0","totalReceived":"20768597","totalSent":"20768597","unconfirmedBalance":"-1500","unconfirmedTxs":1,"txs":119}"#;

#[test]
fn indexer_amount_strings() -> TestResult {
    let ours = address(ADDRESS_0_0, BtcNetwork::Testnet4)?;
    let payee = address(
        "tb1q0dzcgv7scppjxsnwlzpkt02vlmc5rtr40wyjgr",
        BtcNetwork::Testnet4,
    )?;
    let utxo_request = BtcIndexerReq::Utxo(payee);
    let address_request = BtcIndexerReq::Address(ours);
    let Ok(BtcIndexerResp::Utxo(list)) = parse_bb(&utxo_request, &value(BB_UTXOS)?) else {
        return Err("bb utxos".into());
    };
    // The unconfirmed element is dropped.
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].height, Some(157_695));
    assert_eq!(list[0].value_hint.get(), REAL_VALUE);
    assert_eq!(
        parse_bb(&address_request, &value(BB_ADDRESS)?),
        Ok(BtcIndexerResp::Address(AddrSummary {
            tx_count: 120,
            confirmed_unspent: false,
            unconfirmed_incoming: false
        }))
    );
    let positive = BB_ADDRESS
        .replace("\"balance\":\"0\"", "\"balance\":\"1\"")
        .replace("\"-1500\"", "\"1500\"");
    assert_eq!(
        parse_bb(&address_request, &value(&positive)?),
        Ok(BtcIndexerResp::Address(AddrSummary {
            tx_count: 120,
            confirmed_unspent: true,
            unconfirmed_incoming: true
        }))
    );
    // JSON numbers, exponents, fractions, leading zeros, signs, overflow → Malformed.
    for bad in [
        "5840453620191",
        "\"5.8e12\"",
        "\"1.0\"",
        "\"01\"",
        "\"-1\"",
        "\"+1\"",
        "\"\"",
        "\"2100000000000001\"",
        "null",
    ] {
        let text = BB_UTXOS.replacen("\"5840453620191\"", bad, 1);
        assert_eq!(
            parse_bb(&utxo_request, &value(&text)?),
            Err(IndexerError::Malformed),
            "value {bad}"
        );
    }
    for bad in ["0", "\"-1\"", "\"1e3\"", "\"007\""] {
        let text = BB_ADDRESS.replacen("\"balance\":\"0\"", &format!("\"balance\":{bad}"), 1);
        assert_eq!(
            parse_bb(&address_request, &value(&text)?),
            Err(IndexerError::Malformed),
            "balance {bad}"
        );
    }
    for bad in ["-1500", "\"-01\"", "\"--1\"", "\"1.5\""] {
        let text = BB_ADDRESS.replacen("\"-1500\"", bad, 1);
        assert_eq!(
            parse_bb(&address_request, &value(&text)?),
            Err(IndexerError::Malformed),
            "unconfirmedBalance {bad}"
        );
    }
    // The same fixture through bb-rpc (JSON-RPC result) and bb-rest (GET body) parses the same.
    let rpc_rig = Rig::new(BtcIndexer::BbRpc, |call| match call.method.as_str() {
        "bb_getUTXOs" => Reply::Result(BB_UTXOS.to_owned()),
        _ => Reply::Result(BB_ADDRESS.to_owned()),
    });
    let rest_rig = Rig::new(BtcIndexer::BbRest, |call| {
        if call.url.contains("/utxo/") {
            Reply::json(BB_UTXOS)
        } else {
            Reply::json(BB_ADDRESS)
        }
    });
    for request in [&utxo_request, &address_request] {
        let via_rpc = fetch(&BtcClient::new(rpc_rig.env(), &rpc_rig.endpoint), request);
        let via_rest = fetch(&BtcClient::new(rest_rig.env(), &rest_rig.endpoint), request);
        assert!(via_rpc.is_ok());
        assert_eq!(via_rpc, via_rest);
        assert_eq!(
            via_rpc,
            parse_bb(
                request,
                &value(if matches!(request, BtcIndexerReq::Utxo(_)) {
                    BB_UTXOS
                } else {
                    BB_ADDRESS
                })?
            )
        );
    }
    Ok(())
}

const UTXO_ONE: &str = r#"[{"txid":"005aa50eb8346e3f199f2b9292049b3eea0dcc4567cb3d45853c11a0b0eb77f1","vout":VOUT,"status":{"confirmed":true,"block_height":HEIGHT,"block_hash":"000000000000000054a4a23be549251b620a323a7fb57253e03ef8ac33220877","block_time":1793055496},"value":VALUE}]"#;

fn utxo_body(vout: &str, height: &str, value: &str) -> String {
    UTXO_ONE
        .replace("VOUT", vout)
        .replace("HEIGHT", height)
        .replace("VALUE", value)
}

fn utxo_request() -> TestResult<BtcIndexerReq> {
    Ok(BtcIndexerReq::Utxo(address(
        ADDRESS_0_0,
        BtcNetwork::Testnet4,
    )?))
}

#[test]
fn esplora_integer_strict() -> TestResult {
    let request = utxo_request()?;
    for good in ["0", "1", "2100000000000000"] {
        let parsed = parse_esplora(&request, &json(&utxo_body("0", "1", good)));
        let Ok(BtcIndexerResp::Utxo(list)) = parsed else {
            return Err(format!("value {good}: {parsed:?}").into());
        };
        assert_eq!(list[0].value_hint.get().to_string(), good);
    }
    for bad in [
        "2100000000000001",
        "99999999999999999",
        "1.0",
        "1e3",
        "1E3",
        "-1",
        "01",
        "\"1000\"",
        "null",
        "18446744073709551616",
    ] {
        assert_eq!(
            parse_esplora(&request, &json(&utxo_body("0", "1", bad))),
            Err(IndexerError::Malformed),
            "value {bad}"
        );
    }
    for good in ["0", "4294967295"] {
        assert!(parse_esplora(&request, &json(&utxo_body(good, good, "1"))).is_ok());
    }
    for bad in ["4294967296", "-1", "1.5", "\"1\"", "1e0"] {
        assert_eq!(
            parse_esplora(&request, &json(&utxo_body(bad, "1", "1"))),
            Err(IndexerError::Malformed),
            "vout {bad}"
        );
        assert_eq!(
            parse_esplora(&request, &json(&utxo_body("0", bad, "1"))),
            Err(IndexerError::Malformed),
            "block_height {bad}"
        );
    }
    // `*_txo_count` / `tx_count` bounds.
    let ours = BtcIndexerReq::Address(address(ADDRESS_0_0, BtcNetwork::Testnet4)?);
    let stats = |funded: &str, spent: &str, txs: &str| {
        format!(
            "{{\"address\":\"{ADDRESS_0_0}\",\"chain_stats\":{{\"funded_txo_count\":{funded},\"spent_txo_count\":{spent},\"tx_count\":{txs}}},\"mempool_stats\":{{\"funded_txo_count\":0,\"spent_txo_count\":0,\"tx_count\":0}}}}"
        )
    };
    assert_eq!(
        parse_esplora(&ours, &json(&stats("4294967295", "0", "4294967295"))),
        Ok(BtcIndexerResp::Address(AddrSummary {
            tx_count: 4_294_967_295,
            confirmed_unspent: true,
            unconfirmed_incoming: false
        }))
    );
    for bad in ["4294967296", "-1", "1.5", "\"2\""] {
        assert_eq!(
            parse_esplora(&ours, &json(&stats(bad, "0", "1"))),
            Err(IndexerError::Malformed)
        );
        assert_eq!(
            parse_esplora(&ours, &json(&stats("1", "0", bad))),
            Err(IndexerError::Malformed)
        );
    }
    Ok(())
}

#[test]
fn esplora_utxo_status_fields() -> TestResult {
    let request = utxo_request()?;
    let element = |status: &str| {
        format!("[{{\"txid\":\"{REAL_TXID}\",\"vout\":0,\"status\":{status},\"value\":1000}}]")
    };
    let hash = "000000000000000054a4a23be549251b620a323a7fb57253e03ef8ac33220877";
    let confirmed = format!(
        "{{\"confirmed\":true,\"block_height\":157695,\"block_hash\":\"{hash}\",\"block_time\":1793055496}}"
    );
    let Ok(BtcIndexerResp::Utxo(list)) = parse_esplora(&request, &json(&element(&confirmed)))
    else {
        return Err("confirmed".into());
    };
    assert_eq!(list[0].height, Some(157_695));
    for bad in [
        format!("{{\"confirmed\":true,\"block_hash\":\"{hash}\",\"block_time\":1}}"),
        "{\"confirmed\":true,\"block_height\":1,\"block_time\":1}".to_owned(),
        format!("{{\"confirmed\":true,\"block_height\":1,\"block_hash\":\"{hash}\"}}"),
        format!(
            "{{\"confirmed\":true,\"block_height\":1,\"block_hash\":\"{}\",\"block_time\":1}}",
            hash.to_ascii_uppercase()
        ),
        format!(
            "{{\"confirmed\":true,\"block_height\":1,\"block_hash\":\"{}\",\"block_time\":1}}",
            &hash[1..]
        ),
        "{\"confirmed\":false,\"block_height\":157695}".to_owned(),
        "{\"confirmed\":\"false\"}".to_owned(),
        "{}".to_owned(),
    ] {
        assert_eq!(
            parse_esplora(&request, &json(&element(&bad))),
            Err(IndexerError::Malformed),
            "{bad}"
        );
    }
    for unconfirmed in [
        "{\"confirmed\":false}",
        "{\"confirmed\":false,\"block_height\":null,\"block_hash\":null,\"block_time\":null}",
    ] {
        let Ok(BtcIndexerResp::Utxo(list)) = parse_esplora(&request, &json(&element(unconfirmed)))
        else {
            return Err("unconfirmed".into());
        };
        assert_eq!(list[0].height, None);
    }
    // No status, duplicate outpoint, 1,001 elements.
    assert_eq!(
        parse_esplora(
            &request,
            &json(&format!(
                "[{{\"txid\":\"{REAL_TXID}\",\"vout\":0,\"value\":1}}]"
            ))
        ),
        Err(IndexerError::Malformed)
    );
    let one = element(&confirmed);
    let inner = one.trim_start_matches('[').trim_end_matches(']');
    assert_eq!(
        parse_esplora(&request, &json(&format!("[{inner},{inner}]"))),
        Err(IndexerError::Malformed)
    );
    let many = |count: u32| {
        let items: Vec<String> = (0..count)
            .map(|vout| inner.replacen("\"vout\":0", &format!("\"vout\":{vout}"), 1))
            .collect();
        format!("[{}]", items.join(","))
    };
    assert!(matches!(
        parse_esplora(&request, &json(&many(1_000))),
        Ok(BtcIndexerResp::Utxo(list)) if list.len() == 1_000
    ));
    assert_eq!(
        parse_esplora(&request, &json(&many(1_001))),
        Err(IndexerError::Malformed)
    );
    // The recorded mempool.space shape passes (also checked in `recorded_esplora_fixtures_parse`).
    let recorded = fixture_body(esplora::TESTNET4_UTXO);
    assert!(parse_esplora(&request, &json(&recorded)).is_ok());
    Ok(())
}

#[test]
fn esplora_address_stats() -> TestResult {
    let request = BtcIndexerReq::Address(address(ADDRESS_0_0, BtcNetwork::Testnet4)?);
    let body =
        |chain: [u32; 3], mempool: [u32; 3]| btc_support::address_json(ADDRESS_0_0, chain, mempool);
    assert_eq!(
        parse_esplora(&request, &json(&body([3, 1, 4], [1, 0, 1]))),
        Ok(BtcIndexerResp::Address(AddrSummary {
            tx_count: 5,
            confirmed_unspent: true,
            unconfirmed_incoming: true
        }))
    );
    // The mempool spends confirmed outputs: m.spent > m.funded with the sums consistent.
    assert_eq!(
        parse_esplora(&request, &json(&body([2, 0, 2], [0, 2, 1]))),
        Ok(BtcIndexerResp::Address(AddrSummary {
            tx_count: 3,
            confirmed_unspent: true,
            unconfirmed_incoming: false
        }))
    );
    for (chain, mempool) in [
        ([1, 0, 0], [0, 0, 0]), // tx_count 0 with funded > 0
        ([0, 0, 0], [0, 1, 0]), // mempool tx_count 0 with spent > 0
        ([1, 2, 2], [0, 0, 0]), // chain spent > funded
        ([1, 1, 2], [0, 1, 1]), // sums: spent 2 > funded 1
    ] {
        assert_eq!(
            parse_esplora(&request, &json(&body(chain, mempool))),
            Err(IndexerError::Malformed),
            "{chain:?} {mempool:?}"
        );
    }
    let other =
        btc_support::address_json("tb1q0nadvfv0ystndehjeldlac8alzu06hd05gqd6n", [0; 3], [0; 3]);
    assert_eq!(
        parse_esplora(&request, &json(&other)),
        Err(IndexerError::Malformed)
    );
    let upper = body([0; 3], [0; 3]).replace(ADDRESS_0_0, &ADDRESS_0_0.to_ascii_uppercase());
    assert_eq!(
        parse_esplora(&request, &json(&upper)),
        Err(IndexerError::Malformed)
    );
    let no_mempool = format!(
        "{{\"address\":\"{ADDRESS_0_0}\",\"chain_stats\":{{\"funded_txo_count\":0,\"spent_txo_count\":0,\"tx_count\":0}}}}"
    );
    assert_eq!(
        parse_esplora(&request, &json(&no_mempool)),
        Err(IndexerError::Malformed)
    );
    // Wrong media type.
    let mut wrong = json(&body([0; 3], [0; 3]));
    wrong.content_type = Some("text/plain".to_owned());
    assert_eq!(
        parse_esplora(&request, &wrong),
        Err(IndexerError::Malformed)
    );
    wrong.content_type = None;
    assert_eq!(
        parse_esplora(&request, &wrong),
        Err(IndexerError::Malformed)
    );
    let recorded = http_fixture(esplora::TESTNET4_ADDRESS_USED);
    assert!(matches!(
        parse_esplora(&request, &recorded),
        Ok(BtcIndexerResp::Address(AddrSummary { tx_count: 119, .. }))
    ));
    Ok(())
}

#[test]
fn esplora_text_endpoints() -> TestResult {
    let genesis_ok = parse_esplora(&BtcIndexerReq::GenesisHash, &text(TESTNET4_GENESIS));
    assert_eq!(
        genesis_ok,
        Ok(BtcIndexerResp::GenesisHash(genesis(TESTNET4_GENESIS)?))
    );
    for bad in [
        format!("{TESTNET4_GENESIS}\n"),
        format!(" {TESTNET4_GENESIS}"),
        TESTNET4_GENESIS.to_ascii_uppercase(),
        TESTNET4_GENESIS[1..].to_owned(),
        format!("\"{TESTNET4_GENESIS}\""),
        String::new(),
    ] {
        assert_eq!(
            parse_esplora(&BtcIndexerReq::GenesisHash, &text(&bad)),
            Err(IndexerError::Malformed),
            "{bad:?}"
        );
    }
    let mut as_json = text(TESTNET4_GENESIS);
    as_json.content_type = Some("application/json".to_owned());
    assert_eq!(
        parse_esplora(&BtcIndexerReq::GenesisHash, &as_json),
        Err(IndexerError::Malformed)
    );
    // Parameters and case of the media type are ignored.
    as_json.content_type = Some("Text/Plain; charset=utf-8".to_owned());
    assert!(parse_esplora(&BtcIndexerReq::GenesisHash, &as_json).is_ok());

    let real_txid = txid(REAL_TXID)?;
    let hex = fixture_body(esplora::TESTNET4_TX_HEX);
    let raw_request = BtcIndexerReq::TxRaw(real_txid);
    assert!(parse_esplora(&raw_request, &text(&hex)).is_ok());
    for bad in [
        hex[1..].to_owned(),
        hex.to_ascii_uppercase(),
        format!("{hex}\n"),
        "00".repeat(400_001),
        String::new(),
    ] {
        assert_eq!(
            parse_esplora(&raw_request, &text(&bad)),
            Err(IndexerError::Malformed)
        );
    }
    // A raw transaction whose hash differs is caught by spec/08 §5.
    let mut tampered = yw_core::hex::decode(&hex)?;
    tampered[49] ^= 0x01;
    let Ok(BtcIndexerResp::TxRaw(raw)) =
        parse_esplora(&raw_request, &text(&yw_core::hex::encode(&tampered)))
    else {
        return Err("tampered hex parses".into());
    };
    let program = yw_core::hex::decode_array::<20>(REAL_PROGRAM)?;
    assert_eq!(
        verify_prev_output(&raw, &real_txid, 0, &p2wpkh_script_pubkey(&program)),
        Err(PrevTxError::TxidMismatch)
    );
    for good in ["0", "157717", "4294967295"] {
        assert!(parse_esplora(&BtcIndexerReq::TipHeight, &text(good)).is_ok());
    }
    for bad in ["-1", "1.5", "4294967296", "01", "", "1\n", "12345678901"] {
        assert_eq!(
            parse_esplora(&BtcIndexerReq::TipHeight, &text(bad)),
            Err(IndexerError::Malformed),
            "{bad:?}"
        );
    }
    Ok(())
}

#[test]
#[expect(clippy::too_many_lines, reason = "the spec/08 §4.3 status table")]
fn esplora_http_status() -> TestResult {
    let ours = address(ADDRESS_0_0, BtcNetwork::Testnet4)?;
    let tx = txid(REAL_TXID)?;
    let cases: Vec<(BtcIndexerReq, Reply, Result<BtcIndexerResp, IndexerError>)> = vec![
        (
            BtcIndexerReq::Utxo(ours.clone()),
            Reply::status(400),
            Err(IndexerError::Rejected),
        ),
        (
            BtcIndexerReq::Address(ours.clone()),
            Reply::status(400),
            Err(IndexerError::Rejected),
        ),
        (
            BtcIndexerReq::TxStatus(tx),
            Reply::status(404),
            Ok(BtcIndexerResp::TxStatus(TxSeen::NotFound)),
        ),
        (
            BtcIndexerReq::TxRaw(tx),
            Reply::status(404),
            Err(IndexerError::NotFound),
        ),
        (
            BtcIndexerReq::Address(ours.clone()),
            Reply::status(404),
            Err(IndexerError::Malformed),
        ),
        (
            BtcIndexerReq::GenesisHash,
            Reply::status(404),
            Err(IndexerError::Malformed),
        ),
        (
            BtcIndexerReq::Utxo(ours.clone()),
            Reply::status(401),
            Err(IndexerError::Auth),
        ),
        (
            BtcIndexerReq::Utxo(ours.clone()),
            Reply::status(403),
            Err(IndexerError::Auth),
        ),
        (
            BtcIndexerReq::Utxo(ours.clone()),
            Reply::status(301),
            Err(IndexerError::Unreachable(None)),
        ),
        (
            BtcIndexerReq::Address(ours.clone()),
            Reply::status(500),
            Err(IndexerError::Unreachable(None)),
        ),
        (
            BtcIndexerReq::TxStatus(tx),
            Reply::status(503),
            Err(IndexerError::Unreachable(None)),
        ),
        (
            BtcIndexerReq::TxStatus(tx),
            Reply::status(400),
            Err(IndexerError::Unreachable(None)),
        ),
        (
            BtcIndexerReq::GenesisHash,
            Reply::Transport(HttpError::Timeout),
            Err(IndexerError::Unreachable(Some(ErrorCode::Rpc002))),
        ),
        (
            BtcIndexerReq::GenesisHash,
            Reply::Transport(HttpError::Tls),
            Err(IndexerError::Unreachable(Some(ErrorCode::Rpc008))),
        ),
        (
            BtcIndexerReq::GenesisHash,
            Reply::Late(10_001, Box::new(Reply::text(TESTNET4_GENESIS))),
            Err(IndexerError::Unreachable(Some(ErrorCode::Rpc002))),
        ),
        (
            BtcIndexerReq::GenesisHash,
            Reply::Transport(HttpError::TooLarge),
            Err(IndexerError::Malformed),
        ),
    ];
    for (request, reply, expected) in cases {
        let rig = Rig::new(BtcIndexer::Esplora, move |_| reply.clone());
        let client = BtcClient::new(rig.env(), &rig.endpoint);
        let result = fetch(&client, &request);
        assert_eq!(result, expected, "{request:?}");
        // No retry for 3xx/4xx/5xx/timeouts.
        assert_eq!(rig.fake.count(), 1, "{request:?}");
        assert!(!format!("{result:?}").contains(SERVER_STRING));
        if let Err(error) = result {
            let shown = error.text(BtcIndexer::Esplora);
            assert!(!shown.contains(SERVER_STRING));
            assert!(shown.contains(error.code().code()));
        }
        rig.log.assert_no_url();
    }
    assert_eq!(
        IndexerError::Unreachable(Some(ErrorCode::Rpc002)).text(BtcIndexer::Esplora),
        "Bitcoin 인덱서(Esplora)에 연결할 수 없습니다. 잠시 후 다시 시도하거나 설정 → Bitcoin에서 인덱서를 바꾸세요. (E-BTC-001, E-RPC-002)"
    );
    assert_eq!(
        IndexerError::Unreachable(None).text(BtcIndexer::BbRest),
        "Bitcoin 인덱서(Blockbook REST)에 연결할 수 없습니다. 잠시 후 다시 시도하거나 설정 → Bitcoin에서 인덱서를 바꾸세요. (E-BTC-001)"
    );
    assert_eq!(IndexerError::Rejected.code(), ErrorCode::Btc005);
    assert_eq!(IndexerError::Auth.code(), ErrorCode::Btc007);
    Ok(())
}

#[test]
fn blockbook_statuses_and_errors() -> TestResult {
    let tx = txid(REAL_TXID)?;
    // bb-rpc: add-on disabled (-32601) → E-BTC-007; HTTP 401 → E-BTC-007; other code → E-BTC-001.
    for (reply, expected) in [
        (Reply::RpcError(-32_601), IndexerError::Auth),
        (Reply::Http(401, None, Vec::new()), IndexerError::Auth),
        (Reply::RpcError(-8), IndexerError::Unreachable(None)),
        (
            Reply::Http(502, None, Vec::new()),
            IndexerError::Unreachable(None),
        ),
        (Reply::Result("[1]".to_owned()), IndexerError::Malformed),
    ] {
        let rig = Rig::new(BtcIndexer::BbRpc, move |_| reply.clone());
        let client = BtcClient::new(rig.env(), &rig.endpoint);
        assert_eq!(fetch(&client, &BtcIndexerReq::GenesisHash), Err(expected));
        assert_eq!(rig.fake.count(), 1);
    }
    // bb-rest: 404 of a tx → NotFound; 404 of block-index → Malformed.
    let rest = |status: u16, request: &BtcIndexerReq| {
        parse_bb_rest(
            request,
            &Response {
                status,
                content_type: Some("application/json".to_owned()),
                body: SERVER_STRING.as_bytes().to_vec(),
            },
        )
    };
    assert_eq!(
        rest(404, &BtcIndexerReq::TxRaw(tx)),
        Err(IndexerError::NotFound)
    );
    assert_eq!(
        rest(404, &BtcIndexerReq::TxStatus(tx)),
        Ok(BtcIndexerResp::TxStatus(TxSeen::NotFound))
    );
    assert_eq!(
        rest(404, &BtcIndexerReq::GenesisHash),
        Err(IndexerError::Malformed)
    );
    assert_eq!(
        rest(403, &BtcIndexerReq::GenesisHash),
        Err(IndexerError::Auth)
    );
    assert_eq!(
        rest(500, &BtcIndexerReq::GenesisHash),
        Err(IndexerError::Unreachable(None))
    );
    // bb_getTx: confirmations → status, hex → raw, txid echo checked.
    let hex = fixture_body(esplora::TESTNET4_TX_HEX);
    let tx_json = format!(
        "{{\"txid\":\"{REAL_TXID}\",\"blockHeight\":157695,\"confirmations\":23,\"hex\":\"{hex}\"}}"
    );
    assert_eq!(
        parse_bb(&BtcIndexerReq::TxStatus(tx), &value(&tx_json)?),
        Ok(BtcIndexerResp::TxStatus(TxSeen::Confirmed {
            height: 157_695
        }))
    );
    let pending = tx_json
        .replace("\"confirmations\":23", "\"confirmations\":0")
        .replace("157695", "-1");
    assert_eq!(
        parse_bb(&BtcIndexerReq::TxStatus(tx), &value(&pending)?),
        Ok(BtcIndexerResp::TxStatus(TxSeen::Unconfirmed))
    );
    assert!(matches!(
        parse_bb(&BtcIndexerReq::TxRaw(tx), &value(&tx_json)?),
        Ok(BtcIndexerResp::TxRaw(raw)) if raw.len() == hex.len() / 2
    ));
    let other = txid("05a4e2d0e59fa96e8aa280038aec7e3bc517d12a0bb8c6b7e1b411422446217a")?;
    assert_eq!(
        parse_bb(&BtcIndexerReq::TxRaw(other), &value(&tx_json)?),
        Err(IndexerError::Malformed)
    );
    assert_eq!(
        parse_bb(
            &BtcIndexerReq::GenesisHash,
            &value(&format!("{{\"blockHash\":\"{TESTNET4_GENESIS}\"}}"))?
        ),
        Ok(BtcIndexerResp::GenesisHash(genesis(TESTNET4_GENESIS)?))
    );
    assert_eq!(
        parse_bb(
            &BtcIndexerReq::GenesisHash,
            &value(&format!("\"{TESTNET4_GENESIS}\""))?
        ),
        Err(IndexerError::Malformed)
    );
    Ok(())
}
