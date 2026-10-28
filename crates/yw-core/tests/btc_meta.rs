//! spec/08 §2, §3.2–§3.4, §4.7, §7.6, §12.3 through the public API: the `BtcMeta` JSON codec
//! (exact output and strict rejection), discovery as a state machine, receive issuance and the
//! gap rules, history marking, the verified-set refresh rules (auto-freeze, unfrozen memory,
//! in-flight retention), spendable candidates and balance, sent scripts, the tip regression
//! rule, `change_next` reconciliation and own-address detection.
#![allow(
    clippy::unwrap_used,
    reason = "fixture helpers outside #[test] functions panic on broken fixtures"
)]

mod btc_common;

use btc_common::{NET, TIP, simple_plan, xpub};
use yw_core::bip32::path::BtcChain;
use yw_core::btc::address::p2wpkh_program;
use yw_core::btc::amount::Sats;
use yw_core::btc::meta::{
    BtcMeta, Discovery, FreezeReason, ListedUtxo, MAX_FROZEN, MAX_SENT_SCRIPTS, MetaError,
    ReceiveAddress, VerifiedUtxo, btc_meta_from_json, btc_meta_to_json, parse_outpoint,
};
use yw_core::btc::network::BtcNetwork;
use yw_core::btc::script::p2wpkh_script_pubkey;
use yw_core::btc::tx::{OutPoint, Txid};
use yw_json::{Limits, Value};

fn op(tag: u8, vout: u32) -> OutPoint {
    OutPoint {
        txid: Txid::from_bytes([tag; 32]),
        vout,
    }
}

fn sats(value: u64) -> Sats {
    Sats::new(value).unwrap()
}

fn listed(tag: u8, chain: BtcChain, index: u32, height: u32) -> ListedUtxo {
    ListedUtxo {
        outpoint: op(tag, 0),
        chain,
        index,
        height,
    }
}

fn verified(item: &ListedUtxo, value: u64) -> VerifiedUtxo {
    VerifiedUtxo {
        outpoint: item.outpoint,
        value: sats(value),
        chain: item.chain,
        index: item.index,
        height: item.height,
        is_coinbase: false,
        own: false,
    }
}

fn parse(text: &str) -> Value {
    yw_json::parse(text.as_bytes(), &Limits::RESPONSE).unwrap()
}

fn json_text(meta: &BtcMeta) -> String {
    String::from_utf8(yw_json::to_vec(&meta.to_json())).unwrap()
}

/// The exact §12.3 JSON of a populated meta and its strict decoder.
#[test]
#[expect(clippy::too_many_lines, reason = "one corruption per field")]
fn json_codec_exact_and_strict() {
    let fresh = BtcMeta::new(NET, xpub());
    assert_eq!(
        json_text(&fresh),
        concat!(
            r#"{"version":1,"network":"testnet4","#,
            r#""account_pubkey":"03b88e0fbe3f646337ed93bc0c0f3b843fcf7d2589e5ec884754e6402027a890b4","#,
            r#""account_chain_code":"3c8c2037ee4c1621da0d348db51163709a622d0d2838dde6d8419c51f6301c62","#,
            r#""receive_next":0,"change_next":0,"last_used_receive":null,"last_used_change":null,"#,
            r#""discovery_done":false,"max_tip_seen":0,"verified":[],"frozen":[],"unfrozen":[],"sent_scripts":[]}"#
        )
    );
    assert_eq!(BtcMeta::from_json(&fresh.to_json()).unwrap(), fresh);
    assert_eq!(btc_meta_from_json(&Value::Null), Ok(None));
    assert_eq!(btc_meta_to_json(None), Value::Null);

    let mut meta = fresh.clone();
    let mut discovery = Discovery::full();
    while let Some((chain, index)) = discovery.next_request() {
        discovery.observe(u64::from(chain == BtcChain::Receive && index == 1));
    }
    discovery.apply(&mut meta).unwrap();
    meta.observe_tip(TIP).unwrap();
    let small = listed(0xab, BtcChain::Receive, 1, TIP - 2);
    let big = listed(0xcd, BtcChain::Receive, 0, TIP - 3);
    meta.apply_refresh(
        &[small, big],
        &[verified(&small, 999), verified(&big, 2_100_000_000_000_000)],
        &[],
        &[],
    );
    meta.unfreeze(op(0x01, 7));
    meta.record_sent_script(&[0x00, 0x14]);
    let text = json_text(&meta);
    let hash: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest([0x00, 0x14]).into();
    let ab = "abababababababababababababababababababababababababababababababab";
    let cd = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
    let expected_tail = format!(
        concat!(
            r#""receive_next":2,"change_next":0,"last_used_receive":1,"last_used_change":null,"#,
            r#""discovery_done":true,"max_tip_seen":200000,"#,
            r#""verified":[{{"outpoint":"{ab}:0","value":"999","chain":0,"index":1,"height":199998,"is_coinbase":false,"own":false}},"#,
            r#"{{"outpoint":"{cd}:0","value":"2100000000000000","chain":0,"index":0,"height":199997,"is_coinbase":false,"own":false}}],"#,
            r#""frozen":[{{"outpoint":"{ab}:0","reason":2}}],"#,
            r#""unfrozen":["0101010101010101010101010101010101010101010101010101010101010101:7"],"#,
            r#""sent_scripts":["{hash}"]}}"#
        ),
        ab = ab,
        cd = cd,
        hash = yw_core::hex::encode(&hash)
    );
    assert!(text.ends_with(&expected_tail), "{text}");
    let decoded = BtcMeta::from_json(&parse(&text)).unwrap();
    assert_eq!(decoded, meta);
    assert_eq!(json_text(&decoded), text);

    // Every single-field corruption is rejected.
    let reject = |from: &str, to: &str| {
        assert!(text.contains(from), "{from}");
        let changed = text.replacen(from, to, 1);
        assert!(
            BtcMeta::from_json(&parse(&changed)).is_err(),
            "{from} → {to}"
        );
    };
    reject(r#""version":1"#, r#""version":2"#);
    reject(r#""version":1"#, r#""version":"1""#);
    reject(r#""network":"testnet4""#, r#""network":"signet""#);
    reject(r#""network":"testnet4""#, r#""network":"Testnet4""#);
    reject(r#""account_pubkey":"03b8"#, r#""account_pubkey":"03B8"#);
    reject(r#""account_pubkey":"03b8"#, r#""account_pubkey":"04b8"#);
    reject(r#""account_pubkey":"03b8"#, r#""account_pubkey":"03b"#);
    reject(
        r#""account_chain_code":"3c8c"#,
        r#""account_chain_code":"3c8"#,
    );
    reject(r#""receive_next":2"#, r#""receive_next":2147483648"#);
    reject(r#""receive_next":2"#, r#""receive_next":1"#);
    reject(r#""receive_next":2"#, r#""receive_next":2.0"#);
    reject(r#""receive_next":2"#, r#""receive_next":-2"#);
    reject(r#""last_used_change":null"#, r#""last_used_change":0"#);
    reject(r#""discovery_done":true"#, r#""discovery_done":1"#);
    reject(r#""max_tip_seen":200000"#, r#""max_tip_seen":4294967296"#);
    reject(r#""value":"999""#, r#""value":999"#);
    reject(r#""value":"999""#, r#""value":"0999""#);
    reject(r#""value":"999""#, r#""value":"0""#);
    reject(r#""value":"999""#, r#""value":"-999""#);
    reject(
        r#""value":"2100000000000000""#,
        r#""value":"2100000000000001""#,
    );
    reject(r#""chain":0,"index":1"#, r#""chain":2,"index":1"#);
    reject(r#""index":1,"#, r#""index":2147483648,"#);
    reject(
        r#""is_coinbase":false,"own":false}"#,
        r#""is_coinbase":false}"#,
    );
    reject(r#""own":false}"#, r#""own":false,"extra":1}"#);
    reject(&format!("{ab}:0\",\"value"), &format!("{ab}:00\",\"value"));
    reject(
        &format!("{ab}:0\",\"value"),
        &format!("{}:0\",\"value", ab.to_uppercase()),
    );
    reject(
        &format!("{ab}:0\",\"value"),
        &format!("{ab}:4294967296\",\"value"),
    );
    reject(&format!("{ab}:0\",\"value"), &format!("{ab}\",\"value"));
    reject(r#""reason":2"#, r#""reason":3"#);
    reject(r#""reason":2"#, r#""reason":0"#);
    reject(r#""unfrozen":["01"#, r#""unfrozen":["x1"#);
    reject(r#""sent_scripts":[""#, r#""sent_scripts":["00"#);
    reject(r#""version":1,"#, r#""version":1,"unknown":0,"#);
    reject(r#""frozen":[{"#, r#""frozen":[{"outpoint":"a"},{"#);
    // Duplicates.
    let duplicated = text.replacen(
        &format!(r#""verified":[{{"outpoint":"{ab}:0""#),
        &format!(
            r#""verified":[{{"outpoint":"{cd}:0","value":"1","chain":0,"index":0,"height":1,"is_coinbase":false,"own":false}},{{"outpoint":"{ab}:0""#
        ),
        1,
    );
    assert!(BtcMeta::from_json(&parse(&duplicated)).is_err());
    let duplicated = text.replacen(
        r#""unfrozen":["#,
        r#""unfrozen":["0101010101010101010101010101010101010101010101010101010101010101:7","#,
        1,
    );
    assert!(BtcMeta::from_json(&parse(&duplicated)).is_err());
    // Not an object / missing key.
    assert!(BtcMeta::from_json(&Value::Array(Vec::new())).is_err());
    assert!(
        BtcMeta::from_json(&parse(&text.replacen(r#""max_tip_seen":200000,"#, "", 1))).is_err()
    );
    // Outpoint text.
    assert_eq!(parse_outpoint(&format!("{ab}:0")), Some(op(0xab, 0)));
    assert_eq!(
        parse_outpoint(&format!("{ab}:4294967295")).map(|o| o.vout),
        Some(u32::MAX)
    );
    for bad in [
        format!("{ab}:"),
        format!("{ab}:+1"),
        format!("{ab}: 1"),
        format!("{ab}:1:2"),
        ":1".to_owned(),
    ] {
        assert_eq!(parse_outpoint(&bad), None, "{bad}");
    }
}

/// spec/08 §3.4 discovery: gap 20 per chain, `next = last + 1`, "더 찾기" from `next`.
#[test]
fn discovery_gap_rules() {
    let mut meta = BtcMeta::new(NET, xpub());
    let mut discovery = Discovery::full();
    let used_receive = [0_u32, 5, 25];
    let mut requests = Vec::new();
    while let Some((chain, index)) = discovery.next_request() {
        requests.push((chain, index));
        let used = chain == BtcChain::Receive && used_receive.contains(&index);
        discovery.observe(u64::from(used) * 3);
        assert!(discovery.apply(&mut meta.clone()).is_err() || discovery.is_done());
    }
    assert_eq!(requests.len(), 46 + 20);
    assert_eq!(requests[45], (BtcChain::Receive, 45));
    assert_eq!(requests[46], (BtcChain::Change, 0));
    assert_eq!(discovery.checked(), 66);
    assert!(!meta.discovery_done());
    discovery.apply(&mut meta).unwrap();
    assert_eq!(meta.receive_next(), 26);
    assert_eq!(meta.last_used_receive(), Some(25));
    assert_eq!(meta.change_next(), 0);
    assert_eq!(meta.last_used_change(), None);
    assert!(meta.discovery_done());
    // "더 찾기": history at receive 30 continues the scan.
    let mut more = Discovery::more(&meta);
    let mut requests = Vec::new();
    while let Some((chain, index)) = more.next_request() {
        requests.push((chain, index));
        more.observe(u64::from(chain == BtcChain::Receive && index == 30));
    }
    assert_eq!(requests.first(), Some(&(BtcChain::Receive, 26)));
    assert_eq!(
        requests
            .iter()
            .filter(|(chain, _)| *chain == BtcChain::Receive)
            .count(),
        25
    );
    assert_eq!(
        requests
            .iter()
            .filter(|(chain, _)| *chain == BtcChain::Change)
            .count(),
        20
    );
    more.apply(&mut meta).unwrap();
    assert_eq!(
        (meta.receive_next(), meta.last_used_receive()),
        (31, Some(30))
    );
    // Nothing found: indices never decrease.
    let mut idle = Discovery::more(&meta);
    while idle.next_request().is_some() {
        idle.observe(0);
    }
    idle.apply(&mut meta).unwrap();
    assert_eq!(meta.receive_next(), 31);
    // A cancelled discovery changes nothing and is reported incomplete.
    let partial = Discovery::full();
    assert_eq!(
        partial.apply(&mut meta),
        Err(MetaError::DiscoveryIncomplete)
    );
    meta.mark_discovery_pending();
    assert!(!meta.discovery_done());
}

/// spec/08 §3.2 receive addresses: smallest unused, issue-before-show, gap warning and limit.
#[test]
fn receive_issuance_and_gap() {
    let mut meta = BtcMeta::new(NET, xpub());
    assert_eq!(meta.receive_address(), Ok(ReceiveAddress::Issued(0)));
    assert_eq!(meta.receive_next(), 1);
    assert_eq!(meta.receive_address(), Ok(ReceiveAddress::Existing(0)));
    assert_eq!(meta.mark_history(BtcChain::Receive, 0, 2), Ok(true));
    assert_eq!(meta.mark_history(BtcChain::Receive, 0, 2), Ok(false));
    assert_eq!(meta.mark_history(BtcChain::Receive, 0, 0), Ok(false));
    assert_eq!(
        meta.mark_history(BtcChain::Receive, 1, 1),
        Err(MetaError::OutOfRange)
    );
    assert_eq!(
        meta.mark_history(BtcChain::Change, 0, 1),
        Err(MetaError::OutOfRange)
    );
    assert_eq!(meta.receive_address(), Ok(ReceiveAddress::Issued(1)));
    assert_eq!(meta.receive_address().map(ReceiveAddress::index), Ok(1));
    assert_eq!(meta.unused_receive_tail(), 1);
    for expected in 2..=20 {
        assert_eq!(meta.new_receive_address(false), Ok(expected));
    }
    assert_eq!(meta.unused_receive_tail(), 20);
    assert_eq!(
        meta.new_receive_address(false),
        Err(MetaError::GapWarning { unused: 20 })
    );
    assert_eq!(meta.receive_next(), 21, "refused issuance writes nothing");
    for expected in 21..=100 {
        assert_eq!(meta.new_receive_address(true), Ok(expected));
    }
    assert_eq!(meta.unused_receive_tail(), 100);
    assert_eq!(meta.new_receive_address(true), Err(MetaError::GapHardLimit));
    // History in the middle shrinks the unused tail.
    assert_eq!(meta.mark_history(BtcChain::Receive, 90, 1), Ok(true));
    assert_eq!(meta.unused_receive_tail(), 10);
    assert_eq!(meta.receive_address(), Ok(ReceiveAddress::Existing(91)));
    // Addresses and the watch set.
    let address = meta.address(BtcChain::Receive, 0).unwrap();
    assert_eq!(
        address.as_str(),
        "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl"
    );
    let watch = meta.watch_set().unwrap();
    assert_eq!(watch.len(), 101);
    assert_eq!(watch[0].2, address);
    assert_eq!(
        meta.expected_script(BtcChain::Change, 4).unwrap(),
        p2wpkh_script_pubkey(&p2wpkh_program(&xpub(), BtcChain::Change, 4).unwrap())
    );
}

/// spec/08 §4.7-4/5 and §7.6: refresh, auto-freeze, unfreeze memory, in-flight retention,
/// spendable/balance.
#[test]
#[expect(clippy::too_many_lines, reason = "one block per refresh rule")]
fn verified_set_refresh_rules() {
    let mut meta = BtcMeta::new(NET, xpub());
    let a = listed(1, BtcChain::Receive, 0, TIP - 1);
    let small = listed(2, BtcChain::Receive, 1, TIP - 2);
    let edge = listed(3, BtcChain::Receive, 1, TIP - 3);
    let own_small = listed(4, BtcChain::Change, 0, TIP - 4);
    let all = [a, small, edge, own_small];
    assert_eq!(meta.unverified(&all).len(), 4);
    let report = meta.apply_refresh(
        &all,
        &[
            verified(&a, 50_000),
            verified(&small, 999),
            verified(&edge, 1_000),
            verified(&own_small, 500),
        ],
        &[],
        &[own_small.outpoint],
    );
    assert_eq!(
        (report.inserted, report.auto_frozen, report.removed),
        (4, 1, 0)
    );
    assert_eq!(
        meta.frozen_reason(&small.outpoint),
        Some(FreezeReason::Auto)
    );
    assert_eq!(meta.frozen_reason(&edge.outpoint), None);
    assert_eq!(meta.frozen_reason(&own_small.outpoint), None);
    assert!(
        meta.verified()
            .iter()
            .any(|v| v.outpoint == own_small.outpoint && v.own)
    );
    assert!(meta.unverified(&all).is_empty());
    let balance = meta.balance(TIP, &[]);
    assert_eq!(balance.available, sats(51_500));
    assert_eq!(balance.frozen, sats(999));
    assert_eq!(balance.pending, Sats::ZERO);
    assert_eq!(meta.spendable(TIP, &[]).len(), 3);
    // User freeze/unfreeze.
    meta.freeze(a.outpoint).unwrap();
    assert_eq!(meta.frozen_reason(&a.outpoint), Some(FreezeReason::User));
    assert_eq!(meta.spendable(TIP, &[]).len(), 2);
    assert_eq!(meta.freeze(op(9, 9)), Err(MetaError::NotVerified));
    meta.unfreeze(a.outpoint);
    meta.unfreeze(small.outpoint);
    assert_eq!(meta.spendable(TIP, &[]).len(), 4);
    assert_eq!(meta.unfrozen(), &[a.outpoint, small.outpoint]);
    // Vanished outputs go (with their freeze), in-flight ones stay; heights follow the listing.
    let moved = ListedUtxo {
        height: TIP - 30,
        ..edge
    };
    meta.freeze(edge.outpoint).unwrap();
    let report = meta.apply_refresh(&[moved], &[], &[a.outpoint], &[]);
    assert_eq!(report.removed, 2);
    let kept: Vec<OutPoint> = meta.verified().iter().map(|v| v.outpoint).collect();
    assert_eq!(kept, vec![a.outpoint, edge.outpoint]);
    assert_eq!(meta.verified()[1].height, TIP - 30);
    assert_eq!(meta.frozen().len(), 1, "only edge's user freeze remains");
    // In-flight outputs are neither spendable nor counted.
    assert_eq!(meta.spendable(TIP, &[a.outpoint]).len(), 0);
    assert_eq!(meta.balance(TIP, &[a.outpoint]).frozen, sats(1_000));
    assert_eq!(meta.balance(TIP, &[a.outpoint]).available, Sats::ZERO);
    // The unfrozen record survives: a re-listed small deposit is not frozen again.
    let report = meta.apply_refresh(&[a, small, edge], &[verified(&small, 999)], &[], &[]);
    assert_eq!((report.inserted, report.auto_frozen), (1, 0));
    // Unlisted "newly verified" items are ignored.
    let stray = listed(7, BtcChain::Receive, 0, TIP - 1);
    let report = meta.apply_refresh(&[a, small, edge], &[verified(&stray, 5_000)], &[], &[]);
    assert_eq!(report.inserted, 0);
    // Confirmation rules: unconfirmed and immature coinbase are pending.
    let mut meta = BtcMeta::new(NET, xpub());
    let unconfirmed = listed(8, BtcChain::Receive, 0, TIP + 1);
    let coinbase = listed(9, BtcChain::Receive, 0, TIP - 98);
    let mut coinbase_utxo = verified(&coinbase, 10_000);
    coinbase_utxo.is_coinbase = true;
    meta.apply_refresh(
        &[unconfirmed, coinbase],
        &[verified(&unconfirmed, 20_000), coinbase_utxo],
        &[],
        &[],
    );
    assert_eq!(meta.balance(TIP, &[]).pending, sats(30_000));
    assert!(meta.spendable(TIP, &[]).is_empty());
    assert_eq!(meta.balance(TIP + 1, &[]).available, sats(30_000));
    assert_eq!(
        meta.min_confirmations(&[unconfirmed.outpoint, coinbase.outpoint], TIP + 1),
        Some(1)
    );
    assert_eq!(meta.min_confirmations(&[op(1, 1)], TIP), None);
    // Own change inserted on confirmation.
    let own = VerifiedUtxo {
        outpoint: op(10, 1),
        value: sats(400),
        chain: BtcChain::Change,
        index: 3,
        height: TIP,
        is_coinbase: false,
        own: false,
    };
    assert_eq!(meta.insert_own(own), Ok(true));
    assert_eq!(meta.insert_own(own), Ok(false));
    assert!(
        meta.verified()
            .iter()
            .any(|v| v.outpoint == own.outpoint && v.own)
    );
    assert_eq!(meta.frozen_reason(&own.outpoint), None);
}

/// The frozen bound: small deposits beyond 1,024 frozen entries are not added (reported).
#[test]
fn frozen_bound_skips() {
    let mut meta = BtcMeta::new(NET, xpub());
    let items: Vec<ListedUtxo> = (0..=u32::try_from(MAX_FROZEN).unwrap())
        .map(|n| ListedUtxo {
            outpoint: OutPoint {
                txid: Txid::from_bytes([7; 32]),
                vout: n,
            },
            chain: BtcChain::Receive,
            index: 0,
            height: TIP - 1,
        })
        .collect();
    let newly: Vec<VerifiedUtxo> = items.iter().map(|item| verified(item, 10)).collect();
    let report = meta.apply_refresh(&items, &newly, &[], &[]);
    assert_eq!(report.auto_frozen, u32::try_from(MAX_FROZEN).unwrap());
    assert_eq!(report.skipped, 1);
    assert_eq!(meta.frozen().len(), MAX_FROZEN);
    assert!(BtcMeta::from_json(&meta.to_json()).is_ok());
}

/// Sent scripts (B05), the tip rule, `change_next`, network check and own-address detection.
#[test]
fn sent_scripts_tip_change_and_own() {
    let mut meta = BtcMeta::new(NET, xpub());
    assert!(meta.is_first_time(&[0x51]));
    assert!(meta.record_sent_script(&[0x51]));
    assert!(!meta.record_sent_script(&[0x51]));
    assert!(!meta.is_first_time(&[0x51]));
    for n in 0..u32::try_from(MAX_SENT_SCRIPTS).unwrap() {
        meta.record_sent_script(&n.to_be_bytes());
    }
    assert_eq!(meta.sent_scripts().len(), MAX_SENT_SCRIPTS);
    assert!(meta.is_first_time(&[0x51]), "the oldest entry was dropped");
    // §2 step 2: refuse a tip more than 6 below the highest seen.
    assert_eq!(meta.observe_tip(1_000), Ok(true));
    assert_eq!(meta.observe_tip(994), Ok(false));
    assert_eq!(
        meta.observe_tip(993),
        Err(MetaError::TipRegression {
            blocks: 993,
            max_tip_seen: 1_000
        })
    );
    assert_eq!(meta.observe_tip(1_001), Ok(true));
    assert_eq!(meta.max_tip_seen(), 1_001);
    // change_next: journal floor and Broadcasting.
    assert!(!meta.reconcile_change_next(None));
    assert!(meta.reconcile_change_next(Some(5)));
    assert!(!meta.reconcile_change_next(Some(4)));
    assert_eq!(meta.change_next(), 5);
    assert_eq!(meta.on_broadcasting(Some(4)), Ok(false));
    assert_eq!(meta.on_broadcasting(Some(7)), Ok(true));
    assert_eq!(meta.on_broadcasting(None), Ok(false));
    assert_eq!(meta.change_next(), 8);
    assert_eq!(
        meta.on_broadcasting(Some(0x7FFF_FFFF)),
        Err(MetaError::IndexExhausted)
    );
    // Network copy.
    assert_eq!(meta.check_network(NET), Ok(()));
    assert_eq!(
        meta.check_network(BtcNetwork::Mainnet),
        Err(MetaError::NetworkMismatch)
    );
    assert_eq!(
        MetaError::NetworkMismatch.to_string(),
        "BTC 네트워크 설정이 지갑 데이터와 다릅니다"
    );
    // Own addresses within next + 20.
    let program = |chain, index| p2wpkh_program(&xpub(), chain, index).unwrap();
    let script = |chain, index| p2wpkh_script_pubkey(&program(chain, index)).to_vec();
    assert_eq!(
        meta.own_recipient(&script(BtcChain::Receive, 19)),
        Ok(Some((BtcChain::Receive, 19)))
    );
    assert_eq!(meta.own_recipient(&script(BtcChain::Receive, 20)), Ok(None));
    assert_eq!(
        meta.own_recipient(&script(BtcChain::Change, 27)),
        Ok(Some((BtcChain::Change, 27)))
    );
    assert_eq!(meta.own_recipient(&[0x51, 0x20, 0, 0]), Ok(None));
    // Send facts of a plan.
    let plan = simple_plan(2, 20_000);
    let facts = meta.send_facts(&plan, TIP, &[]).unwrap();
    assert!(facts.first_time_recipient);
    assert_eq!(facts.own_recipient, None);
    assert_eq!(facts.min_confirmations, None);
    assert_eq!(facts.verified_balance, Sats::ZERO);
}
