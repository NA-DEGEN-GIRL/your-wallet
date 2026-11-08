//! Zcash app layer (spec/12 §4, §12.3, spec/04 §6.1): node / Blockbook answer parsing, the
//! `zcash` settings object and the meta `zcash` key round trips.

use yw_app::settings::{Settings, ZecIndexer};
use yw_app::zec::meta::{ZCASH_KEY, ZcashMeta};
use yw_app::zec::rpc::{
    TxStatus, ZecRpcError, parse_blockbook_utxos, parse_chain_info, parse_node_utxos,
    parse_tx_status,
};
use yw_core::zec::{ZecAccount, ZecKeySource, ZecNetwork};
use yw_json::{Limits, Value};

#[expect(clippy::unwrap_used, reason = "fixture JSON is valid")]
fn json(text: &str) -> Value {
    yw_json::parse(text.as_bytes(), &Limits::RESPONSE).unwrap()
}

const TXID: &str = "1111111111111111111111111111111111111111111111111111111111111111";

#[test]
fn chain_info_is_checked() {
    let info = json(
        r#"{"chain":"test","blocks":4470000,"headers":4470001,
            "consensus":{"chaintip":"77190ad9","nextblock":"77190ad9"},
            "upgrades":{"c2d6d0b4":{"name":"NU5","activationheight":1842420,"status":"active"},
                        "77190ad9":{"name":"NU7","activationheight":4465026,"status":"active"}}}"#,
    );
    let view = parse_chain_info(&info, ZecNetwork::Testnet).unwrap();
    assert_eq!(view.tip, 4_470_000);
    assert_eq!(view.consensus.next_branch, 0x7719_0AD9);
    assert_eq!(view.consensus.upgrades.len(), 2);
    assert_eq!(
        parse_chain_info(&info, ZecNetwork::Mainnet),
        Err(ZecRpcError::WrongChain)
    );
    let lagging =
        json(r#"{"chain":"main","blocks":10,"headers":100,"consensus":{"nextblock":"77190ad9"}}"#);
    assert_eq!(
        parse_chain_info(&lagging, ZecNetwork::Mainnet),
        Err(ZecRpcError::NotSynced)
    );
}

#[test]
fn node_and_blockbook_utxos() {
    let address = "tmXYZ";
    let script = "76a914000000000000000000000000000000000000000088ac";
    let rows = json(&format!(
        r#"[{{"address":"{address}","txid":"{TXID}","outputIndex":1,"script":"{script}","satoshis":150000,"height":4469000}},
            {{"address":"{address}","txid":"{TXID}","outputIndex":2,"script":"a914000000000000000000000000000000000000000087","satoshis":5,"height":1}}]"#
    ));
    let utxos = parse_node_utxos(&rows, address, script).unwrap();
    assert_eq!(utxos.len(), 1, "a foreign script is skipped");
    assert_eq!(utxos[0].value, 150_000);
    assert_eq!(utxos[0].height, Some(4_469_000));
    assert_eq!(utxos[0].outpoint.index, 1);
    let other = json(&format!(
        r#"[{{"address":"tmOTHER","txid":"{TXID}","outputIndex":1,"script":"{script}","satoshis":1,"height":1}}]"#
    ));
    assert_eq!(
        parse_node_utxos(&other, address, script),
        Err(ZecRpcError::Malformed)
    );
    let bb = json(&format!(
        r#"[{{"txid":"{TXID}","vout":0,"value":"20000","height":0,"confirmations":0}},
            {{"txid":"{TXID}","vout":3,"value":"70000","height":4469001,"confirmations":3,"coinbase":true}}]"#
    ));
    let utxos = parse_blockbook_utxos(&bb).unwrap();
    assert_eq!(utxos[0].height, None);
    assert!(utxos[1].coinbase);
    assert_eq!(utxos[1].value, 70_000);
}

/// Dust griefing (spec/12 §4.3): thousands of tiny outputs never fail the parse; dust is
/// dropped and the largest `ZEC_MAX_UTXOS` are kept.
#[test]
fn dust_flood_is_trimmed_not_refused() {
    let address = "tmXYZ";
    let script = "76a914000000000000000000000000000000000000000088ac";
    let row = |index: u64, zats: u64| {
        format!(
            r#"{{"address":"{address}","txid":"{TXID}","outputIndex":{index},"script":"{script}","satoshis":{zats},"height":10}}"#
        )
    };
    let rows: Vec<String> = (0..1_500_u64)
        .map(|index| row(index, 1_000))
        .chain((1_500..2_700_u64).map(|index| row(index, 6_000 + index)))
        .chain(core::iter::once(row(9_999, 5_000_000)))
        .collect();
    let all = parse_node_utxos(&json(&format!("[{}]", rows.join(","))), address, script).unwrap();
    assert_eq!(all.len(), 2_701);
    let useful = yw_app::zec::rpc::keep_useful(all);
    assert_eq!(useful.utxos.len(), yw_core::zec::ZEC_MAX_UTXOS);
    assert_eq!(useful.ignored, 2_701 - yw_core::zec::ZEC_MAX_UTXOS);
    assert_eq!(useful.utxos[0].value, 5_000_000);
    assert!(
        useful
            .utxos
            .iter()
            .all(|utxo| utxo.value > yw_core::zec::ZEC_MIN_UTXO)
    );
}

#[test]
fn tx_status_from_getrawtransaction() {
    assert_eq!(
        parse_tx_status(&json(r#"{"height":4469002,"confirmations":2}"#)),
        TxStatus::Mined(4_469_002)
    );
    assert_eq!(parse_tx_status(&json(r#"{"hex":"00"}"#)), TxStatus::Known);
    assert_eq!(
        parse_tx_status(&json(r#"{"height":-1,"confirmations":0}"#)),
        TxStatus::Known
    );
}

#[test]
fn zcash_settings_round_trip() {
    let mut settings = Settings::default();
    assert!(!settings.zcash.enabled);
    settings.zcash.enabled = true;
    settings.zcash.network = ZecNetwork::Testnet;
    settings.zcash.indexer = ZecIndexer::BbRest;
    let text = settings.to_json();
    assert!(
        String::from_utf8_lossy(&text)
            .contains(r#""zcash":{"enabled":true,"network":"testnet","indexer":"bb-rest"}"#)
    );
    let loaded = yw_app::settings::load(Some(&text));
    assert_eq!(loaded.settings.zcash, settings.zcash);
    assert!(loaded.banners.is_empty());
}

#[test]
fn zcash_meta_round_trip() {
    let mut meta = ZcashMeta::default();
    assert!(meta.is_default());
    let mut pubkey = [0x11_u8; 33];
    pubkey[0] = 0x02;
    meta.set(ZecAccount {
        network: ZecNetwork::Testnet,
        source: ZecKeySource::EvmShared { evm_index: 3 },
        pubkey,
    });
    let value = meta.to_json();
    assert_eq!(ZcashMeta::from_json(Some(&value)), meta);
    assert_eq!(ZCASH_KEY, "zcash");
    // A broken entry drops that account only.
    let broken = json(r#"{"testnet":{"source":9,"a":0,"b":0,"pubkey":"02"}}"#);
    assert!(ZcashMeta::from_json(Some(&broken)).is_default());
}

/// The Zcash approval draft passes the window's own display check (every key has a label).
#[test]
fn zec_draft_is_displayable() {
    use yw_core::zec::upgrade::{ConsensusObservation, tx_consensus};
    use yw_core::zec::{ZecAmount, ZecDest, ZecOutPoint, ZecSendRequest, ZecUtxo, plan_send};
    let account = ZecAccount {
        network: ZecNetwork::Testnet,
        source: ZecKeySource::DEFAULT,
        pubkey: [2; 33],
    };
    let to = ZecDest::P2sh([7; 20]).encode(ZecNetwork::Testnet);
    let recipient = yw_core::zec::parse_recipient(&to, ZecNetwork::Testnet).unwrap();
    let consensus = tx_consensus(
        ZecNetwork::Testnet,
        &ConsensusObservation {
            tip: 4_470_000,
            next_branch: 0x7719_0AD9,
            upgrades: Vec::new(),
        },
    )
    .unwrap();
    let plan = plan_send(
        &account,
        &ZecSendRequest {
            recipient,
            amount: ZecAmount::Exact(40_000),
            utxos: vec![ZecUtxo {
                outpoint: ZecOutPoint {
                    txid: [1; 32],
                    index: 0,
                },
                value: 100_000,
                height: Some(4_469_000),
                coinbase: false,
            }],
            reserved: Vec::new(),
            consensus,
        },
    )
    .unwrap();
    let draft =
        yw_core::zec::display::build_zec_request(yw_core::approval::ApprovalId([3; 16]), &plan)
            .unwrap();
    assert!(yw_app::ui::approval::validate_for_display(&draft.display).is_ok());
}

/// A node whose `getaddressutxos` answer is over the limits; `gettxout` answers from `unspent`
/// (`None`: the method is missing).
#[derive(Debug)]
struct OverLimitNode {
    unspent: Option<Vec<u32>>,
}

impl yw_app::rpc::Transport for OverLimitNode {
    fn post_json(
        &self,
        _url: &yw_win::http::HttpsUrl,
        body: &[u8],
        _max_response: usize,
    ) -> Result<yw_app::rpc::HttpReply, yw_win::http::HttpError> {
        let request = yw_json::parse(body, &Limits::REQUEST)
            .map_err(|_| yw_win::http::HttpError::InvalidHeader)?;
        let object = request
            .as_object()
            .ok_or(yw_win::http::HttpError::InvalidHeader)?;
        let id = object
            .get("id")
            .and_then(Value::as_number)
            .and_then(yw_json::Number::as_u64);
        let params = object.get("params").and_then(Value::as_array);
        let answer = match object.get("method").and_then(Value::as_str) {
            Some("getblockhash") => format!(r#""result":"{}""#, ZecNetwork::Testnet.genesis_hex()),
            Some("getblockchaininfo") => format!(
                r#""result":{{"chain":"{}","blocks":4469100,"headers":4469100,"consensus":{{"nextblock":"77190ad9"}}}}"#,
                ZecNetwork::Testnet.chain_name()
            ),
            Some("getaddressutxos") => return Err(yw_win::http::HttpError::TooLarge),
            Some("gettxout") => {
                let index = params
                    .and_then(|params| params.get(1))
                    .and_then(Value::as_number)
                    .and_then(yw_json::Number::as_u64)
                    .and_then(|index| u32::try_from(index).ok());
                match (&self.unspent, index) {
                    (None, _) => r#""error":{"code":-32601,"message":"x"}"#.to_owned(),
                    (Some(unspent), Some(index)) if unspent.contains(&index) => {
                        r#""result":{"value":0.001,"confirmations":5}"#.to_owned()
                    }
                    _ => r#""result":null"#.to_owned(),
                }
            }
            _ => r#""error":{"code":-5,"message":"x"}"#.to_owned(),
        };
        Ok(yw_app::rpc::HttpReply {
            status: 200,
            body: format!(r#"{{"jsonrpc":"2.0","id":{},{answer}}}"#, id.unwrap_or(0)).into_bytes(),
        })
    }
}

/// spec/12 §4.3: a `getaddressutxos` answer over the limits is not a dead end — the outputs
/// already known that `gettxout` still finds stay sendable and the watched inputs are resolved;
/// without `gettxout` the known outputs stay as they were and the watch is marked unknowable
/// (an expired record is then closed instead of blocking sends forever).
#[test]
fn over_limit_answer_keeps_what_is_known() {
    use yw_app::zec::work::{ZecRpcEvent, ZecRpcJob, handle};
    use yw_core::zec::{ZecOutPoint, ZecUtxo};

    let point = |index: u32| ZecOutPoint {
        txid: [0x11; 32],
        index,
    };
    let utxo = |index: u32, value: u64| ZecUtxo {
        outpoint: point(index),
        value,
        height: Some(4_469_000),
        coinbase: false,
    };
    let run = |unspent: Option<Vec<u32>>| {
        let job = ZecRpcJob::Refresh {
            job: 1,
            network: ZecNetwork::Testnet,
            url: yw_win::http::HttpsUrl::parse("https://zec.example/").unwrap(),
            indexer: ZecIndexer::Node,
            address: "tmXYZ".to_owned(),
            script_hex: "76a914000000000000000000000000000000000000000088ac".to_owned(),
            track: Vec::new(),
            watch: vec![point(3)],
            known: vec![utxo(1, 90_000), utxo(2, 80_000)],
        };
        let ZecRpcEvent::Refreshed {
            result: Ok(snapshot),
            ..
        } = handle(&OverLimitNode { unspent }, job)
        else {
            unreachable!("a refresh snapshot");
        };
        snapshot
    };
    let checked = run(Some(vec![1, 3]));
    assert_eq!(checked.utxo_error, Some(ZecRpcError::TooMany));
    assert_eq!(checked.utxos, vec![utxo(1, 90_000)]);
    assert_eq!(checked.unspent_watch, Some(vec![point(3)]));
    assert!(!checked.watch_unknowable);
    let blind = run(None);
    assert_eq!(blind.utxo_error, Some(ZecRpcError::TooMany));
    assert_eq!(blind.utxos, vec![utxo(1, 90_000), utxo(2, 80_000)]);
    assert_eq!(blind.unspent_watch, None);
    assert!(blind.watch_unknowable);
}
