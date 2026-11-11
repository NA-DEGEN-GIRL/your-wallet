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
    // Each row has `해시 복사` only: no copy or select control for a sender.
    let row_ids: Vec<u16> = controls(&items)
        .into_iter()
        .map(|ctl| ctl.id)
        .filter(|id| (ids::ROW_BASE..ids::ROW_BASE + ids::ROW_SPAN).contains(id))
        .collect();
    assert_eq!(
        row_ids,
        [
            ids::row(RecvChain::Evm, 0).unwrap(),
            ids::row(RecvChain::Evm, 1).unwrap()
        ]
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
