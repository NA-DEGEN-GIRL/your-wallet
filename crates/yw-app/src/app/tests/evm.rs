//! The tests of `app_evm.rs` that build an `App` (2026-11-21, S4 W0, spec/09 §2.1),
//! moved unchanged from its inline `mod tests` (which keeps the tests that build no `App`).
//! It was a `#[cfg(test)] #[path]` child of `crate::app_evm`, not of `app::tests`, to keep the
//! access of the inline module, so no production item of that file was widened. 2026-11-22 (S4d
//! E0c, spec/09 §2.1): a child of `app::tests` (that file moves to yw-engine at S4d E1 and these
//! tests need `App`); what it reaches is `pub(crate)` now (test-only use): `Wallet::on_quote` and
//! the shared helper `app_evm::tests::record` (its `tests` module too). 2026-11-23 (S4d E1):
//! `record` is a copy here (the inline module moved to yw-engine and is private again).

use yw_engine::testkit::WalletTestExt;
use yw_engine::wallet::app_evm::{SEND_DEBOUNCE_MS, SEND_QUICK_MS};
use yw_engine::wallet::app_sol::ReviewBlocker;

const BESU_SIGNED: &str = "02f86e048203338301284d8301d97c828ae094000000000000000000000000000000000000aaaa8402933bc980c080a00f924cb68412c8f1cfd74d9b581c71eeaf94fff6abdde3e5b02ca6b2931dcf47a07dd1c50027c3e31f8b565e25ce68a5072110f61fce5eee81b195dd51273c2f83";

/// A signed record of the shared Besu transaction with `flags` (2026-11-23, spec/15 §11.4 S4d E1:
/// a copy of the inline test helper `app_evm::tests::record`, which moved to yw-engine as a
/// private test item; `cfg(test)` does not cross crates).
fn record(flags: u8) -> yw_core::journal::evm::EvmRecord {
    let sender = yw_core::evm::address::parse_address("0xFE3B557E8Fb62b89F4916B721be55cEb828dBd73")
        .unwrap_or(yw_core::evm::address::Address::from_bytes([0; 20]));
    let mut record = yw_core::journal::evm::EvmRecord::new_signed(
        4,
        sender,
        819,
        yw_core::journal::evm::Role::Original,
        1_790_000_000_000,
        [7; 32],
        "https://app.example",
        "x",
        yw_core::hex::decode(BESU_SIGNED).unwrap(),
    )
    .unwrap();
    record.flags = flags;
    record
}

/// Journal records (every chain) and EVM activity rows feed the look-alike history; book
/// entries are not repeated and history is not offered by the picker.
#[test]
fn past_recipients_join_the_known_addresses_as_history() {
    use crate::app::{App, Paths};
    use yw_engine::apikeys::ApiKeys;
    use yw_engine::events::JournalView;
    use yw_engine::meta::{ActivityEntry, BookEntry, Meta};
    use yw_engine::settings::Settings;
    use yw_engine::wallet::AppMode;

    let dir = std::env::temp_dir().join(format!("yw-app-evm-known-{}", std::process::id()));
    let mut app = App::new(
        Paths {
            data: dir.clone(),
            logs: dir.join("logs"),
        },
        true,
        Settings::default(),
        ApiKeys::default(),
    );
    app.mode = AppMode::Unlocked {
        alt_passphrase: false,
    };
    let book = "0x52908400098527886e0f7030069857d2e4169ee7";
    let from_activity = "0xf278cf59f82edcf871d630f28ecc8056f25c1cdb";
    let mut meta = Meta::default();
    meta.add_book(&BookEntry {
        address: book.to_owned(),
        label: "거래소".to_owned(),
        verified: false,
        added_at_unix_ms: 1,
    })
    .unwrap();
    let row = |counterparty: &str, sig: u8| ActivityEntry {
        account: "0xfe3b557e8fb62b89f4916b721be55ceb828dbd73".to_owned(),
        tx_id: format!("0x{}", "ab".repeat(31) + &format!("{sig:02x}")),
        title: "보내기".to_owned(),
        asset: "native".to_owned(),
        amount: "1".to_owned(),
        counterparty: counterparty.to_owned(),
        status: "succeeded".to_owned(),
        time_unix_ms: u64::from(sig),
    };
    meta.upsert_activity("eip155:84532", &row(from_activity, 1));
    meta.upsert_activity("eip155:84532", &row(book, 2));
    // A Solana row is not an EVM recipient.
    meta.upsert_activity("solana:devnet", &row(from_activity, 3));
    app.meta = Some(meta);
    // The Besu record (chain 4) sends to 0x…aaaa.
    app.evm.journal = Some(JournalView {
        records: vec![record(0)],
        ..JournalView::default()
    });
    let known = app.known_addresses();
    let history: Vec<String> = known
        .iter()
        .filter(|entry| entry.history)
        .map(|entry| entry.address.to_lower_hex())
        .collect();
    assert_eq!(
        history,
        vec![
            "0x000000000000000000000000000000000000aaaa".to_owned(),
            from_activity.to_owned(),
        ]
    );
    assert_eq!(
        known
            .iter()
            .filter(|entry| entry.address.to_lower_hex() == book)
            .count(),
        1
    );
    assert!(
        app.picker_entries()
            .iter()
            .all(|address| address.to_lower_hex() == book)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// spec/04 §2.7 (security review M2): `검토` validates again without a call and refuses when
/// the fresh recipient or amount differs from the shown one (an edit inside the debounce);
/// it is off while an edit awaits validation; the item is built from the fresh result only.
#[test]
fn review_revalidates_and_refuses_an_edit_inside_the_debounce() {
    use crate::app::{App, Paths};
    use yw_core::evm::amount::U256;
    use yw_engine::apikeys::ApiKeys;
    use yw_engine::events::JournalView;
    use yw_engine::flow::evm::form::Quote;
    use yw_engine::meta::{Account, Meta};
    use yw_engine::settings::Settings;
    use yw_engine::wallet::AppMode;
    use yw_engine::wallet::app_sol::{ReviewRefusal, SOL_REVIEW_CHANGED_TEXT};

    const TO_A: &str = "0x52908400098527886e0f7030069857d2e4169ee7";
    const TO_B: &str = "0xf278cf59f82edcf871d630f28ecc8056f25c1cdb";
    let dir = std::env::temp_dir().join(format!("yw-app-evm-review-{}", std::process::id()));
    let mut app = App::new(
        Paths {
            data: dir.clone(),
            logs: dir.join("logs"),
        },
        true,
        Settings::default(),
        ApiKeys::default(),
    );
    app.mode = AppMode::Unlocked {
        alt_passphrase: false,
    };
    app.meta = Some(Meta {
        evm_accounts: vec![Account {
            index: 0,
            label: "계정 1".to_owned(),
            address: "0xfe3b557e8fb62b89f4916b721be55ceb828dbd73".to_owned(),
            hidden: false,
        }],
        ..Meta::default()
    });
    app.evm.journal = Some(JournalView::default());
    let quote = Quote {
        gas_limit: 21_000,
        max_fee_per_gas: U256::from_u64(1),
        max_total: U256::from_u64(21_000),
        cap_violation: None,
        estimate_failed: false,
    };
    let to = |text: &str| yw_core::evm::address::parse_address(text).unwrap();
    let one_eth = U256::from_u64(1_000_000_000_000_000_000);
    app.evm.send.to_text = TO_A.to_owned();
    app.evm.send.amount_text = "1".to_owned();
    app.validate_send(false);
    // The line under `검토` names what is missing: here the fee quote.
    assert_eq!(app.review_blocker(), Some(ReviewBlocker::NoFee));
    app.evm.send.quote = Some(quote.clone());
    assert!(app.can_review());
    // B / 10 pasted, the debounce has not run: `검토` is off and the shown result is A / 1.
    app.evm.send.to_text = TO_B.to_owned();
    app.evm.send.amount_text = "10".to_owned();
    app.evm.send.dirty_ms = Some(1);
    assert!(!app.can_review());
    assert_eq!(app.review_blocker(), Some(ReviewBlocker::Checking));
    // A whole address or amount is validated at once, half-typed text after the pause.
    assert_eq!(app.send_edit_wait_ms(true), SEND_QUICK_MS);
    assert_eq!(app.send_edit_wait_ms(false), SEND_QUICK_MS);
    app.evm.send.to_text.truncate(20);
    app.evm.send.amount_text = "0.".to_owned();
    assert_eq!(app.send_edit_wait_ms(true), SEND_DEBOUNCE_MS);
    assert_eq!(app.send_edit_wait_ms(false), SEND_DEBOUNCE_MS);
    app.evm.send.to_text = TO_B.to_owned();
    app.evm.send.amount_text = "10".to_owned();
    assert_eq!(app.review_item().unwrap_err(), ReviewRefusal::Changed);
    assert_eq!(app.evm.send.dirty_ms, None);
    assert_eq!(app.evm.send.recipient.as_ref().unwrap().0, to(TO_B));
    // `review_send` itself shows the fixed text and queues nothing.
    app.evm.send.amount_text = "2".to_owned();
    app.review_send();
    assert_eq!(app.evm.send.info.as_deref(), Some(SOL_REVIEW_CHANGED_TEXT));
    assert!(app.evm.slots.is_empty());
    // The fresh validation is now on screen: the item is built from it (B / 2).
    app.evm.send.quote = Some(quote);
    let item = app.review_item().unwrap();
    assert_eq!(item.intent.to, to(TO_B));
    assert_eq!(item.intent.value, one_eth.checked_mul_u64(2).unwrap());
    // An input error is "not ready", not a change.
    app.evm.send.amount_text = "x".to_owned();
    app.validate_send(false);
    assert_eq!(app.review_item().unwrap_err(), ReviewRefusal::NotReady);
    assert_eq!(app.review_blocker(), Some(ReviewBlocker::InputError));
    app.evm.send.amount_text.clear();
    app.validate_send(false);
    assert_eq!(app.review_blocker(), Some(ReviewBlocker::NoAmount));
    app.evm.send.to_text.clear();
    app.validate_send(false);
    assert_eq!(app.review_blocker(), Some(ReviewBlocker::NoRecipient));
    let _ = std::fs::remove_dir_all(&dir);
}

/// spec/04 §2.7 `최대` without a quote: one quote is asked for (a click while it is in
/// flight waits for it), and a failed quote shows its error and ends the wait — it is never
/// asked again by itself (a failing or rate-limited RPC used to loop quote → refresh).
#[test]
fn max_with_a_failing_quote_asks_once() {
    use crate::app::{App, Paths};
    use yw_engine::apikeys::ApiKeys;
    use yw_engine::errors::ErrorCode;
    use yw_engine::events::JournalView;
    use yw_engine::meta::{Account, Meta};
    use yw_engine::network::NetworkId;
    use yw_engine::settings::Settings;
    use yw_engine::wallet::AppMode;
    use yw_engine::workers::rpc::RpcJob;

    let dir = std::env::temp_dir().join(format!("yw-app-evm-max-{}", std::process::id()));
    let mut app = App::new(
        Paths {
            data: dir.clone(),
            logs: dir.join("logs"),
        },
        true,
        Settings::default(),
        ApiKeys::default(),
    );
    app.mode = AppMode::Unlocked {
        alt_passphrase: false,
    };
    app.meta = Some(Meta {
        evm_accounts: vec![Account {
            index: 0,
            label: "계정 1".to_owned(),
            address: "0xfe3b557e8fb62b89f4916b721be55ceb828dbd73".to_owned(),
            hidden: false,
        }],
        ..Meta::default()
    });
    app.evm.journal = Some(JournalView::default());
    app.wallet.apikeys.set_rpc(
        NetworkId::Eip155(app.wallet.settings.evm_chain_id),
        &yw_platform::http::HttpsUrl::parse("https://rpc.example.test/").unwrap(),
    );
    let (tx, rx) = std::sync::mpsc::channel();
    app.rpc_tx = Some(tx);
    let quotes = |rx: &std::sync::mpsc::Receiver<RpcJob>| {
        rx.try_iter()
            .filter(|job| matches!(job, RpcJob::Quote { .. }))
            .count()
    };
    app.fill_max();
    assert_eq!(quotes(&rx), 1);
    assert!(app.evm.send.max_pending);
    // A second click while that quote is in flight waits for it.
    app.fill_max();
    assert_eq!(quotes(&rx), 0);
    // The quote fails: its error shows, the wait ends, nothing is asked again.
    let job = app.evm.send.quote_job;
    app.on_quote(job, Err(ErrorCode::Rpc001));
    assert!(!app.evm.send.max_pending);
    assert_eq!(app.evm.send.quote_error, Some(ErrorCode::Rpc001));
    assert_eq!(quotes(&rx), 0);
    // A new click asks once more.
    app.fill_max();
    assert_eq!(quotes(&rx), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// spec/03 §4.6, spec/10 §10: `가속`/`취소` of a `YubiKey` account's open group is signed by
/// that account's card key (`EvmKeySource::Hardware`, so the card step follows approval);
/// a group whose account has no key any more gets a notice and no approval (never a
/// stand-in key).
#[test]
fn replacing_a_group_uses_the_account_key_or_refuses() {
    use yw_core::bip32::path::AccountIndex;
    use yw_core::vault::EvmKeySource;

    use crate::app::{App, Paths};
    use yw_engine::apikeys::ApiKeys;
    use yw_engine::events::JournalView;
    use yw_engine::flow::evm::prepare::ReplaceMode;
    use yw_engine::meta::{Account, Meta};
    use yw_engine::settings::Settings;
    use yw_engine::wallet::AppMode;
    use yw_engine::wallet::app_evm::QueuedItem;

    let dir = std::env::temp_dir().join(format!("yw-app-evm-replace-{}", std::process::id()));
    let mut app = App::new(
        Paths {
            data: dir.clone(),
            logs: dir.join("logs"),
        },
        true,
        Settings::default(),
        ApiKeys::default(),
    );
    // Locked: the queued approval waits (no window); its signer is what is checked.
    app.mode = AppMode::Locked;
    app.meta = Some(Meta::default());
    let open = record(0);
    let key = open.key();
    app.evm.journal = Some(JournalView {
        records: vec![open],
        ..JournalView::default()
    });
    // No key for the sender: nothing is queued, no slot is held, a notice says why.
    app.replace_group(key, ReplaceMode::SpeedUp);
    assert!(app.evm.queue.is_empty());
    assert!(app.evm.slots.is_empty());
    assert!(
        app.banners
            .iter()
            .any(|banner| banner.text == yw_engine::wallet::app_evm::text::REPLACE_NO_KEY.ko)
    );
    // The sender is YubiKey EVM account 3.
    app.meta.as_mut().unwrap().hw_accounts.evm = vec![Account {
        index: 3,
        label: "YubiKey 계정 4".to_owned(),
        address: key.account.to_lower_hex(),
        hidden: false,
    }];
    let hardware = EvmKeySource::Hardware(AccountIndex::new(3).unwrap());
    assert_eq!(app.account_source(&key.account), Some(hardware));
    app.replace_group(key, ReplaceMode::Cancel);
    let queued: Vec<_> = app.evm.queue.waiting_payloads().collect();
    assert!(matches!(
        queued.as_slice(),
        [QueuedItem::App(item)]
            if item.signer == hardware && item.account == key.account && item.replace.is_some()
    ));
    let _ = std::fs::remove_dir_all(&dir);
}
