//! spec/04 §2.6 (2026-11-11) at the App level: the opt-in received history queues nothing while
//! its switch is off, reads the shown card's list once it is on (then at most once per 60 s),
//! and shows rows with read-only senders, the look-alike tag and the hidden-dust count.

use std::sync::mpsc::Receiver;

use super::{controls, ctl, has_text, unlocked_app};
use crate::network::NetworkId;
use crate::received::{Cursor, Fetched, Found, Incoming, ReceivedEvent, ReceivedJob, RecvChain};
use crate::ui::main_window::{Item, Tone};
use crate::ui::screens_received::{T_EVM_NATIVE, T_RECEIVED_HELP, dust_line, ids};
use crate::workers::rpc::RpcJob;

fn received(rx: &Receiver<RpcJob>) -> Vec<ReceivedJob> {
    rx.try_iter()
        .filter_map(|job| match job {
            RpcJob::Received(job) => Some(*job),
            _ => None,
        })
        .collect()
}

fn row(key: &str, from: &str) -> Incoming {
    Incoming {
        key: key.to_owned(),
        hash: format!("0x{}", "ab".repeat(32)),
        time_ms: Some(1_700_000_000_000),
        block: Some(16),
        amount: "12.5".to_owned(),
        symbol: "USDC".to_owned(),
        from: Some(from.to_owned()),
        from_note: None,
        pending: false,
        ..Incoming::default()
    }
}

#[test]
#[expect(clippy::too_many_lines, reason = "one walk through the switch states")]
fn switch_off_queues_nothing_and_on_reads_the_shown_card() {
    let (mut app, dir) = unlocked_app("received", false);
    let (tx, rx) = std::sync::mpsc::channel();
    app.rpc_tx = Some(tx);
    let url = yw_win::http::HttpsUrl::parse("https://rpc.example.test/key").unwrap();
    app.apikeys
        .set_rpc(NetworkId::Eip155(app.settings.evm_chain_id), &url);
    let now = yw_win::time::monotonic_ms();

    // Off (the default): no read is ever queued; the card has only the switch.
    assert!(!app.settings.received_history);
    for later in [0, 61_000, 3_600_000] {
        app.received_tick(now + later);
    }
    app.on_command(crate::ui::screens_evm::ids::REFRESH);
    assert!(received(&rx).is_empty(), "nothing while off");
    assert!(app.received.lists.is_empty());
    let items = app.items();
    assert_eq!(
        ctl(&items, ids::toggle(RecvChain::Evm)).map(|ctl| ctl.checked),
        Some(Some(false))
    );
    assert!(!has_text(&items, T_RECEIVED_HELP));

    // On: saved, and the EVM card's list is read at once with the token-card tokens.
    app.on_command(ids::toggle(RecvChain::Evm));
    assert!(app.settings.received_history);
    let saved = std::fs::read_to_string(dir.join("settings.json")).unwrap();
    assert!(saved.contains(r#""receivedHistory":true"#), "{saved}");
    let jobs = received(&rx);
    assert_eq!(jobs.len(), 1);
    let job = &jobs[0];
    assert_eq!(job.key.chain, RecvChain::Evm);
    assert_eq!(job.cursor, Cursor::Start);
    assert!(matches!(
        &job.kind,
        crate::received::JobKind::Evm { tokens, .. } if !tokens.is_empty()
    ));
    // In flight: no second read, not even after 60 s.
    app.received_tick(now + 120_000);
    assert!(received(&rx).is_empty());
    let items = app.items();
    assert!(has_text(&items, T_RECEIVED_HELP));
    assert!(has_text(&items, T_EVM_NATIVE));
    assert!(has_text(&items, "받은 내역을 불러오는 중…"));

    // The answer: one row from a stranger, one imitating our own account, two dust transfers.
    // Our account is 0x9858effd…ecaeda94: same first 4 and last 4 hex digits, other middle.
    let poison = format!("0x9858{}da94", "0".repeat(32));
    let stranger = "0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
    let mut second = row("b", &poison);
    second.time_ms = Some(1_600_000_000_000);
    app.received_event(ReceivedEvent {
        job: job.job,
        key: job.key.clone(),
        result: Ok(Fetched {
            found: Found {
                entries: vec![row("a", stranger), second],
                dust: vec!["d1".to_owned(), "d2".to_owned()],
            },
            cursor: Cursor::Block {
                next: 100,
                span: 625,
            },
            ..Fetched::default()
        }),
    });
    let items = app.items();
    assert!(has_text(&items, "받음 12.5 USDC"));
    assert!(has_text(&items, &dust_line(2)));
    assert!(items.iter().any(|item| matches!(
        item,
        Item::Pill(text, Tone::HighRisk) if text.contains("주소 오염 의심") && text.contains("내 계정")
    )));
    // Each row has `해시 복사` (and `탐색기에서 열기` when the hash has a page): no copy or
    // select control for a sender.
    let row_ids: Vec<u16> = controls(&items)
        .into_iter()
        .map(|ctl| ctl.id)
        .filter(|id| (ids::ROW_BASE..ids::ROW_BASE + ids::ROW_SPAN).contains(id))
        .collect();
    let rows = [
        ids::row(RecvChain::Evm, 0).unwrap(),
        ids::row(RecvChain::Evm, 1).unwrap(),
    ];
    assert_eq!(
        row_ids
            .iter()
            .copied()
            .filter(|id| (id - ids::ROW_BASE).is_multiple_of(ids::ROW_STRIDE))
            .collect::<Vec<_>>(),
        rows
    );
    assert!(
        row_ids
            .iter()
            .all(|id| rows.contains(id) || rows.contains(&(id - 1)))
    );
    // The same dust again is not counted twice; the cursor is kept for the next read.
    let list = app.received.lists.get(&job.key).expect("the list is kept");
    assert_eq!(list.entries[0].key, "a", "newest first");
    assert_eq!(
        list.cursor,
        Cursor::Block {
            next: 100,
            span: 625
        }
    );

    // The next read is due 60 s after the last one started, not before.
    app.received_tick(yw_win::time::monotonic_ms() + 1_000);
    assert!(received(&rx).is_empty());
    app.received_tick(yw_win::time::monotonic_ms() + 61_000);
    let next = received(&rx);
    assert_eq!(next.len(), 1);
    assert_eq!(
        next[0].cursor,
        Cursor::Block {
            next: 100,
            span: 625
        }
    );
    app.received_event(ReceivedEvent {
        job: next[0].job,
        key: next[0].key.clone(),
        result: Ok(Fetched {
            found: Found {
                entries: Vec::new(),
                dust: vec!["d2".to_owned()],
            },
            cursor: Cursor::Block {
                next: 120,
                span: 625,
            },
            ..Fetched::default()
        }),
    });
    assert!(has_text(&app.items(), &dust_line(2)));

    // Another screen than the main one: no reads.
    app.screen = crate::app::Screen::Settings(crate::app::SettingsSection::Security);
    app.received_tick(yw_win::time::monotonic_ms() + 3_600_000);
    assert!(received(&rx).is_empty());
    app.screen = crate::app::Screen::Main;

    // Off again: the lists go and nothing is queued any more.
    app.on_command(ids::toggle(RecvChain::Evm));
    assert!(!app.settings.received_history);
    assert!(app.received.lists.is_empty());
    app.received_tick(yw_win::time::monotonic_ms() + 3_600_000);
    app.on_command(crate::ui::screens_evm::ids::REFRESH);
    assert!(received(&rx).is_empty());
    let saved = std::fs::read_to_string(dir.join("settings.json")).unwrap();
    assert!(!saved.contains("receivedHistory"), "{saved}");
    let _ = std::fs::remove_dir_all(&dir);
}

// ----- unconfirmed (mempool) deposits, 2026-11-13 -------------------------------------------

fn pending_row(key: &str, units: u64) -> Incoming {
    Incoming {
        key: key.to_owned(),
        hash: key.to_owned(),
        amount: yw_core::zec::format_zec(units),
        symbol: "ZEC".to_owned(),
        from_note: Some(crate::received::zec::T_NO_SENDER),
        pending: true,
        amount_units: units,
        ..Incoming::default()
    }
}

fn confirmed(row: &Incoming, block: u64) -> Incoming {
    Incoming {
        pending: false,
        block: Some(block),
        ..row.clone()
    }
}

fn read(entries: Vec<Incoming>, gone: &[&str], dropped: &[&str]) -> Fetched {
    Fetched {
        found: Found {
            entries,
            dust: Vec::new(),
        },
        gone: gone.iter().map(|key| (*key).to_owned()).collect(),
        dropped: dropped.iter().map(|key| (*key).to_owned()).collect(),
        ..Fetched::default()
    }
}

/// spec/04 §2.6 (2026-11-13): a pending row goes only when a read names it gone (counted
/// once), never because a read did not list it (cooldown, a failed address, an empty read); a
/// key that comes back is taken off the count; pending → confirmed is replaced in place and a
/// confirmed row never turns back; a replacement is its own new pending row.
#[test]
fn pending_rows_go_only_when_a_read_says_so() {
    use crate::app_received::RecvList;
    let (a, b) = (pending_row("a", 50_000), pending_row("b", 70_000));
    let mut list = RecvList::default();
    list.apply(read(vec![a.clone(), b.clone()], &[], &[]));
    assert_eq!(list.pending_sum(), Some(120_000));
    // An empty or incomplete read keeps both.
    list.apply(Fetched::default());
    list.apply(read(Vec::new(), &[], &[]));
    assert_eq!(list.entries.len(), 2);
    // B is gone (replaced by C, which pays us too): counted once, even if named again.
    let c = pending_row("c", 69_000);
    list.apply(read(vec![c.clone()], &["b"], &[]));
    list.apply(read(Vec::new(), &["b"], &[]));
    assert_eq!(list.gone, 1);
    let keys: Vec<&str> = list.entries.iter().map(|row| row.key.as_str()).collect();
    assert_eq!(keys, ["a", "c"]);
    // A confirms in place; a lagging read listing it as pending again changes nothing.
    list.apply(read(vec![confirmed(&a, 900)], &[], &[]));
    list.apply(read(vec![a.clone()], &[], &[]));
    let row = list.entries.iter().find(|row| row.key == "a").unwrap();
    assert!(!row.pending);
    assert_eq!(row.block, Some(900));
    assert_eq!(list.pending_sum(), Some(69_000));
    // B comes back (a load-balanced indexer) and confirms: off the count.
    list.apply(read(vec![b.clone()], &[], &[]));
    assert_eq!(list.gone, 0);
    list.apply(read(vec![confirmed(&b, 901)], &[], &[]));
    assert_eq!(list.gone, 0);
    // Removed without a definitive answer: the neutral count.
    list.apply(read(Vec::new(), &[], &["c"]));
    assert_eq!((list.gone, list.dropped), (0, 1));
    assert_eq!(list.pending_sum(), None);
    // A gone key of a confirmed row never removes it.
    list.apply(read(Vec::new(), &["a"], &[]));
    assert!(list.entries.iter().any(|row| row.key == "a"));
}

/// spec/08 §4.7-2 (2026-11-13): the refresh banner points to the switch while the history is
/// off, stays while the list has not covered every flagged address, and gives way to the
/// "미확정 입금 {amount}" line when it has.
#[test]
fn bitcoin_pending_banner_follows_the_history_coverage() {
    use crate::app_btc::{PENDING_INCOMING, PENDING_INCOMING_UNREAD};
    use crate::ui::screens_btc::pending_banner;
    use yw_core::bip32::path::BtcChain;
    let at = [(BtcChain::Receive, 3)];
    assert_eq!(pending_banner(false, &[], true, None), None);
    assert_eq!(
        pending_banner(true, &at, false, None),
        Some(PENDING_INCOMING)
    );
    assert_eq!(
        pending_banner(true, &at, true, None),
        Some(PENDING_INCOMING_UNREAD)
    );
    assert_eq!(
        pending_banner(true, &at, true, Some((&[0, 2], true))),
        Some(PENDING_INCOMING_UNREAD)
    );
    assert_eq!(
        pending_banner(true, &at, true, Some((&[3], false))),
        Some(PENDING_INCOMING_UNREAD)
    );
    assert_eq!(pending_banner(true, &at, true, Some((&[3], true))), None);
    // A change address is never read by the history.
    assert_eq!(
        pending_banner(true, &[(BtcChain::Change, 0)], true, Some((&[0], true))),
        Some(PENDING_INCOMING_UNREAD)
    );
}

fn zec_snapshot(utxos: Vec<yw_core::zec::ZecUtxo>) -> crate::zec::work::ZecSnapshot {
    let info = yw_json::parse(
        br#"{"chain":"test","blocks":4470000,"headers":4470001,
            "consensus":{"chaintip":"77190ad9","nextblock":"77190ad9"},
            "upgrades":{"77190ad9":{"name":"NU7","activationheight":4465026,"status":"active"}}}"#,
        &yw_json::Limits::RESPONSE,
    )
    .unwrap();
    crate::zec::work::ZecSnapshot {
        chain: crate::zec::rpc::parse_chain_info(&info, yw_core::zec::ZecNetwork::Testnet).unwrap(),
        utxos,
        ignored_utxos: 0,
        utxo_error: None,
        unspent_watch: None,
        watch_unknowable: false,
        tracked: Vec::new(),
    }
}

/// spec/12 §11 (2026-11-13) on the Zcash card: the confirmed balance has no "· 미확인" suffix
/// any more; unconfirmed outputs of others are the "미확정 입금" line (from the `bb-rest`
/// snapshot, or the history list while it is on), never part of the balance. With the switch
/// off no read is queued; on, the read carries our script, our outputs and the snapshot pending
/// set; pending rows show no sender and the 0-confirmation status; a gone row is counted.
#[test]
#[expect(clippy::too_many_lines, reason = "one walk through the Zcash card")]
fn zcash_unconfirmed_deposits_on_the_card() {
    use yw_core::zec::{ZecNetwork, ZecOutPoint, ZecUtxo};
    let (mut app, dir) = unlocked_app("received-zec", false);
    let (tx, rx) = std::sync::mpsc::channel();
    app.rpc_tx = Some(tx);
    app.meta.as_mut().unwrap().prefs.tab = crate::meta::Tab::Zec;
    app.settings.zcash.enabled = true;
    app.settings.zcash.network = ZecNetwork::Testnet;
    app.settings.zcash.indexer = crate::settings::ZecIndexer::BbRest;
    let account = yw_core::zec::ZecAccount {
        network: ZecNetwork::Testnet,
        source: yw_core::zec::ZecKeySource::DEFAULT,
        pubkey: yw_core::hex::decode_array::<33>(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap(),
    };
    app.meta.as_mut().unwrap().zcash.set(account);
    let url = yw_win::http::HttpsUrl::parse("https://zec.example.test/key").unwrap();
    app.apikeys
        .set_rpc(NetworkId::Zcash(ZecNetwork::Testnet), &url);
    let utxo = |fill: u8, value: u64, height: Option<u32>| ZecUtxo {
        outpoint: ZecOutPoint {
            txid: [fill; 32],
            index: 0,
        },
        value,
        height,
        coinbase: false,
    };
    app.zec.snapshot = Some((
        ZecNetwork::Testnet,
        Box::new(zec_snapshot(vec![
            utxo(1, 100_000_000, Some(4_469_000)),
            utxo(3, 50_000_000, None),
        ])),
    ));
    let deposit = yw_core::zec::tx::txid_display(&[3; 32]);

    // Off: no read; the snapshot's unconfirmed deposit is its own line, not in the balance.
    let now = yw_win::time::monotonic_ms();
    app.received_tick(now);
    assert!(received(&rx).is_empty(), "nothing while off");
    let items = app.items();
    assert!(has_text(
        &items,
        "확인된 잔액 1.00000000 ZEC (100,000,000 zats) (서버 기준, 진행 중 거래의 입력 제외)"
    ));
    assert!(!has_text(&items, "· 미확인"));
    assert!(has_text(
        &items,
        "미확정 입금 0.50000000 ZEC (50,000,000 zats) (0 확인 — 바뀌거나 취소될 수 있습니다, 아직 쓸 수 없음)"
    ));
    assert!(items.iter().any(|item| matches!(
        item,
        Item::Field(_, value) if value.starts_with("미확정 (0 확인) · ")
    )));

    // On: one read with the snapshot pending set, our script and our outputs.
    app.on_command(ids::toggle(RecvChain::Zec));
    let jobs = received(&rx);
    assert_eq!(jobs.len(), 1);
    let crate::received::JobKind::Zec(work) = &jobs[0].kind else {
        unreachable!("{:?}", jobs[0].kind);
    };
    assert_eq!(work.bb_pending, [(deposit.clone(), 50_000_000)]);
    assert_eq!(work.own_outpoints.len(), 2);
    assert_eq!(work.script, account.script_pubkey());
    assert!(work.user && work.pending.is_empty());

    // The answer: the deposit as a pending row (0.4 ZEC here), the limited line.
    let row = pending_row(&deposit, 40_000_000);
    app.received_event(ReceivedEvent {
        job: jobs[0].job,
        key: jobs[0].key.clone(),
        result: Ok(Fetched {
            found: Found {
                entries: vec![row.clone()],
                dust: Vec::new(),
            },
            limited: Some(crate::received::zec::T_NO_DELTAS_PENDING),
            ..Fetched::default()
        }),
    });
    let items = app.items();
    assert!(has_text(
        &items,
        "미확정 입금 0.40000000 ZEC (40,000,000 zats)"
    ));
    assert!(has_text(&items, "미확정 · 받음 0.40000000 ZEC"));
    assert!(has_text(
        &items,
        crate::ui::screens_received::T_PENDING_STATUS
    ));
    assert!(has_text(
        &items,
        crate::ui::screens_received::T_PENDING_HELP
    ));
    assert!(has_text(&items, crate::received::zec::T_NO_DELTAS_PENDING));

    // The next automatic read carries the pending row; the row goes, counted.
    app.received_tick(yw_win::time::monotonic_ms() + 61_000);
    let next = received(&rx);
    assert_eq!(next.len(), 1, "a limited source keeps reading");
    let crate::received::JobKind::Zec(work) = &next[0].kind else {
        unreachable!("{:?}", next[0].kind);
    };
    assert_eq!(work.pending, [row]);
    assert!(!work.user);
    app.received_event(ReceivedEvent {
        job: next[0].job,
        key: next[0].key.clone(),
        result: Ok(read(Vec::new(), &[&deposit], &[])),
    });
    let items = app.items();
    assert!(has_text(&items, &crate::ui::screens_received::gone_line(1)));
    assert!(!has_text(&items, "미확정 · 받음"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A pending row shows no sender until it confirms (a replaceable look-alike payment costs
/// only fees); the confirmed row shows it.
#[test]
fn pending_rows_hide_the_sender() {
    let (mut app, dir) = unlocked_app("received-sender", false);
    app.settings.received_history = true;
    let key = app.received_key(RecvChain::Evm).unwrap();
    let stranger = "0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
    let mut processed = row("p", stranger);
    processed.pending = true;
    app.received
        .lists
        .entry(key.clone())
        .or_default()
        .apply(read(vec![processed], &[], &[]));
    let items = app.items();
    assert!(has_text(
        &items,
        crate::ui::screens_received::T_PENDING_SENDER
    ));
    assert!(!has_text(&items, "5a5a 5a5a"));
    app.received
        .lists
        .get_mut(&key)
        .unwrap()
        .apply(read(vec![row("p", stranger)], &[], &[]));
    assert!(!has_text(
        &app.items(),
        crate::ui::screens_received::T_PENDING_SENDER
    ));
    let _ = std::fs::remove_dir_all(&dir);
}
