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
    let lagging = json(
        r#"{"chain":"main","blocks":10,"headers":100,"consensus":{"nextblock":"77190ad9"}}"#,
    );
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
