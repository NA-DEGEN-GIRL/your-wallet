//! The tests of `app_chain_sites.rs` that build an `App` (2026-11-21, S4 W0, spec/09 §2.1),
//! moved unchanged from its inline `mod tests`. That module keeps its helpers (pinned in
//! `frozen-helpers.txt` in their F-A file) and the two tests that build no `App`. A
//! `#[cfg(test)] #[path]` child of `crate::app_chain_sites::tests`, not of `app::tests`: it
//! reaches the helpers as the inline tests did, so no item is widened.

use super::*;

#[test]
fn connect_refusals_and_choices() {
    let mut empty = app(false);
    assert_eq!(
        empty.chain_unlocked_refusal(&site(SiteKind::SolConnect)),
        Some(ProviderError::NoSolAccount)
    );
    let ordinals = site(SiteKind::BtcConnect(vec![BtcPurpose::Ordinals]));
    // Bitcoin off (the default) is its own reason; on, the missing account type.
    assert!(!empty.settings.bitcoin.enabled);
    assert_eq!(
        empty.chain_unlocked_refusal(&ordinals),
        Some(ProviderError::BtcDisabled)
    );
    empty.settings.bitcoin.enabled = true;
    assert_eq!(
        empty.chain_unlocked_refusal(&ordinals),
        Some(ProviderError::NoBtcAccount)
    );
    // The app says what to add (once, however often the page asks).
    empty.refuse_site(&ordinals, ProviderError::NoBtcAccount);
    empty.refuse_site(&ordinals, ProviderError::NoBtcAccount);
    let notices: Vec<&str> = empty
        .banners
        .iter()
        .map(|banner| banner.text.as_str())
        .collect();
    assert_eq!(notices.len(), 1);
    assert!(notices[0].contains("오디널스용 Taproot(P2TR) 주소가 없습니다"));
    let app = app(true);
    assert_eq!(
        app.chain_unlocked_refusal(&site(SiteKind::SolConnect)),
        None
    );
    let (choices, selected, network) = app.chain_connect_choices(&site(SiteKind::SolConnect));
    assert_eq!(choices.len(), 1);
    assert_eq!(selected, vec![true]);
    assert!(matches!(&choices[0].0, ConnectChoice::Sol(key) if *key == public()));
    assert_eq!(choices[0].2, SOL_KEY);
    assert!(network.starts_with("Solana"));
}

#[test]
fn signing_preflight_and_drafts() {
    let mut app = app(true);
    let sign = site(SiteKind::SolSign {
        public: public(),
        message: b"Prove it".to_vec(),
        sign_in: false,
    });
    // Not granted: revoked (4100).
    assert_eq!(
        app.chain_site_preflight(&sign),
        Some(Some(QueueOutcome::Revoked))
    );
    if let Some(browser) = app.browser.as_ref() {
        browser.core.upsert_sol_grant(yw_core::policy::SolGrant {
            origin: sign.origin.clone(),
            public: public(),
            granted_at_unix_ms: 1,
        });
    }
    assert_eq!(app.chain_site_preflight(&sign), Some(None));
    let draft = app.chain_sign_draft(&sign).unwrap();
    assert_eq!(draft.kind, ApprovalKind::SolMessage);
    assert_eq!(draft.display.risk, RiskLevel::Info);
    // A message signature moves no assets: no "자산 변화" card in the window.
    let request = yw_core::approval::ApprovalStore::new()
        .issue(draft.clone(), 1, 1_793_074_713_000)
        .unwrap();
    let view =
        crate::ui::approval_view::signing_view(&request, false, true, Vec::new(), true).unwrap();
    assert!(!view.blocks.iter().any(|block| matches!(
        block,
        crate::ui::approval_view::Block::Section(title) if title.starts_with("자산 변화")
    )));
    // Transaction bytes are blocked in the window.
    let mut tx = vec![1, 0, 1, 2];
    tx.extend_from_slice(&[0x11; 96]);
    tx.extend_from_slice(&[1, 1, 1, 0, 4, 2, 0, 0, 0]);
    let blocked = site(SiteKind::SolSign {
        public: public(),
        message: tx,
        sign_in: false,
    });
    assert_eq!(
        app.chain_sign_draft(&blocked).unwrap().display.risk,
        RiskLevel::Blocked
    );
    let waiter = crate::app::Wallet::chain_waiter(&sign, &draft.payload);
    assert!(matches!(
        waiter,
        Some(crate::app_browser::SignWaiter::Chain(_, _))
    ));
    // EVM kinds are not chain kinds.
    assert_eq!(
        app.chain_site_preflight(&site(SiteKind::RequestAccounts)),
        None
    );
}

#[test]
fn removed_or_hidden_solana_accounts_lose_their_grants_for_good() {
    let mut app = app(true);
    let key7 = yw_core::sol::SolAddress::from_bytes([7; 32]).to_base58();
    let imported = crate::meta::SolRawAccount {
        record_id: [5; 16],
        label: "가져온 키".to_owned(),
        address: key7,
    };
    // A second imported copy of the derived account 0 key.
    let duplicate = crate::meta::SolRawAccount {
        record_id: [6; 16],
        label: "같은 키".to_owned(),
        address: SOL_KEY.to_owned(),
    };
    let meta = app.meta.as_mut().unwrap();
    meta.sol_raw_accounts.push(imported.clone());
    meta.sol_raw_accounts.push(duplicate);
    let core = core(&app);
    assert!(core.upsert_sol_grant(sol_grant("https://app.example", [7; 32])));
    assert!(core.upsert_sol_grant(sol_grant("https://other.example", [9; 32])));
    assert!(core.upsert_sol_grant(sol_grant("https://dup.example", public())));
    app.write_grants();
    assert_eq!(app.meta.as_ref().unwrap().chain_sites.sol.len(), 3);
    // The imported key is removed: its grant leaves the dispatcher and meta.
    app.on_imported_key_removed(
        yw_core::vault::RecordId::from_bytes([5; 16]),
        yw_core::keyimport::ImportChain::Sol,
    );
    let left: Vec<[u8; 32]> = core.sol_grants().iter().map(|g| g.public).collect();
    assert_eq!(left, vec![[9; 32], public()]);
    assert_eq!(app.meta.as_ref().unwrap().chain_sites.sol.len(), 2);
    // Removing an imported copy of a key that is still a visible account keeps its grant.
    app.on_imported_key_removed(
        yw_core::vault::RecordId::from_bytes([6; 16]),
        yw_core::keyimport::ImportChain::Sol,
    );
    assert_eq!(core.sol_grants().len(), 2);
    // Importing the same key again does not bring the connection back.
    app.meta.as_mut().unwrap().sol_raw_accounts.push(imported);
    assert!(!relock(&app));
    assert!(
        core.sol_grants()
            .iter()
            .all(|grant| grant.public != [7; 32])
    );
    // Hiding a derived account (index 1) drops its grants the same way.
    let meta = app.meta.as_mut().unwrap();
    meta.sol_raw_accounts.clear();
    meta.sol_accounts.push(crate::meta::Account {
        index: 1,
        label: "SOL 2".to_owned(),
        address: yw_core::sol::SolAddress::from_bytes([9; 32]).to_base58(),
        hidden: false,
    });
    meta.prefs.sol_account = 1;
    app.sol_hide_selected();
    let left: Vec<[u8; 32]> = core.sol_grants().iter().map(|g| g.public).collect();
    assert_eq!(left, vec![public()]);
    assert_eq!(app.meta.as_ref().unwrap().chain_sites.sol.len(), 1);
}

#[test]
fn removed_bitcoin_account_drops_every_grant_listing_its_address() {
    use yw_core::btc::{BtcAccountKey, BtcAccounts, BtcMeta, BtcNetwork};
    let mut app = app(false);
    let node = yw_core::bip32::AccountXpub {
        pubkey: yw_core::hex::decode_array::<33>(
            "03b88e0fbe3f646337ed93bc0c0f3b843fcf7d2589e5ec884754e6402027a890b4",
        )
        .unwrap(),
        chain_code: [7; 32],
    };
    let key = BtcAccountKey::hd(ScriptType::P2wpkh, 1, node).unwrap();
    let account = BtcMeta::with_key(BtcNetwork::Mainnet, key);
    let address = account
        .address(yw_core::bip32::path::BtcChain::Receive, 0)
        .unwrap()
        .as_str()
        .to_owned();
    let mut accounts = BtcAccounts::default();
    accounts.upsert(account).unwrap();
    app.meta.as_mut().unwrap().btc_accounts = accounts;
    let grant = yw_core::policy::BtcGrant::new(
        BrowserOrigin::parse("https://app.example").unwrap(),
        BtcNetwork::Mainnet,
        vec![BtcGrantAddress {
            purpose: BtcPurpose::Payment,
            address,
            pubkey: BtcPubKey::Compressed([2; 33]),
            script_type: ScriptType::P2wpkh,
        }],
        1,
    )
    .unwrap();
    let core = core(&app);
    assert!(core.upsert_btc_grant(grant));
    app.write_grants();
    // The key worker reports the account gone (imported key removed).
    app.btc_apply(vec![crate::app_btc::BtcAction::SetMeta(
        None,
        Box::default(),
    )]);
    assert!(core.btc_grants().is_empty());
    assert!(app.meta.as_ref().unwrap().chain_sites.btc.is_empty());
}

/// spec/05 §4.9 (2026-11-15): hiding a Bitcoin account deletes every grant listing its
/// stable address (the dispatcher's and meta's) like a removed key, leaves the other
/// accounts' grants, takes it out of the connect choices, and `다시 보이기` brings no
/// connection back.
#[test]
fn hidden_bitcoin_account_drops_its_grants_and_leaves_the_connect_list() {
    use yw_core::btc::{BtcAccountKey, BtcMeta, BtcNetwork};
    let mut app = app(false);
    app.settings.bitcoin.enabled = true;
    app.settings.bitcoin.network = crate::network::BtcNet::Mainnet;
    let node = yw_core::bip32::AccountXpub {
        pubkey: yw_core::hex::decode_array::<33>(
            "03b88e0fbe3f646337ed93bc0c0f3b843fcf7d2589e5ec884754e6402027a890b4",
        )
        .unwrap(),
        chain_code: [7; 32],
    };
    let primary = BtcMeta::new(BtcNetwork::Mainnet, node);
    // Another account node (the generator point, public test data): another address.
    let other = yw_core::bip32::AccountXpub {
        pubkey: yw_core::hex::decode_array::<33>(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap(),
        chain_code: [9; 32],
    };
    let second = BtcMeta::with_key(
        BtcNetwork::Mainnet,
        BtcAccountKey::hd(ScriptType::P2wpkh, 1, other).unwrap(),
    );
    let address_of = |meta: &BtcMeta| {
        meta.address(yw_core::bip32::path::BtcChain::Receive, 0)
            .unwrap()
            .as_str()
            .to_owned()
    };
    let (kept, hidden) = (address_of(&primary), address_of(&second));
    let id = second.id();
    let meta = app.meta.as_mut().unwrap();
    meta.btc = Some(Box::new(primary));
    meta.btc_accounts.upsert(second).unwrap();
    meta.btc_accounts.selected = Some(id);
    let grant = |origin: &str, address: &str| {
        yw_core::policy::BtcGrant::new(
            BrowserOrigin::parse(origin).unwrap(),
            BtcNetwork::Mainnet,
            vec![BtcGrantAddress {
                purpose: BtcPurpose::Payment,
                address: address.to_owned(),
                pubkey: BtcPubKey::Compressed([2; 33]),
                script_type: ScriptType::P2wpkh,
            }],
            1,
        )
        .unwrap()
    };
    let core = core(&app);
    assert!(core.upsert_btc_grant(grant("https://app.example", &hidden)));
    assert!(core.upsert_btc_grant(grant("https://other.example", &kept)));
    app.write_grants();
    let offered = |app: &App| {
        app.btc_connect_choices(
            &BrowserOrigin::parse("https://new.example").unwrap(),
            &[BtcPurpose::Payment],
        )
        .0
        .into_iter()
        .map(|(_, _, address, _)| address)
        .collect::<Vec<_>>()
    };
    assert_eq!(offered(&app), [kept.clone(), hidden.clone()]);
    app.btc_hide_selected();
    assert!(
        app.meta
            .as_ref()
            .unwrap()
            .btc_hidden(BtcNetwork::Mainnet, id)
    );
    let left: Vec<String> = core
        .btc_grants()
        .iter()
        .flat_map(|grant| grant.addresses.iter().map(|entry| entry.address.clone()))
        .collect();
    assert_eq!(left, std::slice::from_ref(&kept));
    assert_eq!(app.meta.as_ref().unwrap().chain_sites.btc.len(), 1);
    assert_eq!(offered(&app), std::slice::from_ref(&kept));
    // Shown again: still no connection for it.
    assert!(app.on_hidden_command(crate::ui::screens_hidden::ids::BTC_ROW_BASE));
    assert!(
        !app.meta
            .as_ref()
            .unwrap()
            .btc_hidden(BtcNetwork::Mainnet, id)
    );
    assert_eq!(core.btc_grants().len(), 1);
    assert_eq!(offered(&app), [kept, hidden]);
}

/// spec/05 §4.9, spec/02 §8.6: removing an added recovery phrase drops the dApp grants of its
/// Solana and Bitcoin accounts (the accounts leave meta first, so the "still an account"
/// guards do not keep them); adding the same words again brings the accounts back, not the
/// grants.
#[test]
fn removed_recovery_phrase_drops_its_chain_grants_for_good() {
    use crate::workers::key::mnemonics::MnOutcome;
    use yw_core::btc::{BtcAccountKey, BtcMeta, BtcNetwork};
    use yw_core::vault::RecordId;
    let mut app = app(false);
    let first = RecordId::from_bytes([4; 16]);
    let sol = crate::meta::Account {
        index: 0,
        label: "SOL 1".to_owned(),
        address: yw_core::sol::SolAddress::from_bytes([7; 32]).to_base58(),
        hidden: false,
    };
    let node = yw_core::bip32::AccountXpub {
        pubkey: yw_core::hex::decode_array::<33>(
            "03b88e0fbe3f646337ed93bc0c0f3b843fcf7d2589e5ec884754e6402027a890b4",
        )
        .unwrap(),
        chain_code: [7; 32],
    };
    let btc_of = |id: RecordId| {
        BtcMeta::with_key(
            BtcNetwork::Mainnet,
            BtcAccountKey::hd(ScriptType::P2wpkh, 0, node)
                .unwrap()
                .with_mnemonic(Some(id)),
        )
    };
    let address = btc_of(first)
        .address(yw_core::bip32::path::BtcChain::Receive, 0)
        .unwrap()
        .as_str()
        .to_owned();
    let add = |app: &mut App, id: RecordId| {
        let meta = app.meta.as_mut().unwrap();
        meta.mnemonic_accounts
            .upsert_sol(*id.as_bytes(), sol.clone());
        meta.btc_accounts.upsert(btc_of(id)).unwrap();
    };
    add(&mut app, first);
    assert_eq!(app.sol_dapp_rows().len(), 1);
    assert_eq!(app.btc_dapp_rows().len(), 1);
    let core = core(&app);
    assert!(core.upsert_sol_grant(sol_grant("https://app.example", [7; 32])));
    let grant = yw_core::policy::BtcGrant::new(
        BrowserOrigin::parse("https://app.example").unwrap(),
        BtcNetwork::Mainnet,
        vec![BtcGrantAddress {
            purpose: BtcPurpose::Payment,
            address,
            pubkey: BtcPubKey::Compressed(node.pubkey),
            script_type: ScriptType::P2wpkh,
        }],
        1,
    )
    .unwrap();
    assert!(core.upsert_btc_grant(grant));
    app.write_grants();
    app.on_mn_outcome(MnOutcome::Removed(Ok(first)), 0);
    assert!(core.sol_grants().is_empty());
    assert!(core.btc_grants().is_empty());
    let meta = app.meta.as_ref().unwrap();
    assert!(meta.chain_sites.sol.is_empty() && meta.chain_sites.btc.is_empty());
    assert!(meta.mnemonic_accounts.sol.is_empty() && meta.btc_accounts.accounts.is_empty());
    // The same words added again (a new record id, the same accounts): no grant returns.
    add(&mut app, RecordId::from_bytes([5; 16]));
    assert!(!relock(&app));
    assert!(core.sol_grants().is_empty());
    assert!(core.btc_grants().is_empty());
}

/// spec/05 §4.9, spec/07 §3.1: a recovery-phrase wallet's Solana connect that arrives while
/// account 0 is still being derived (it comes with the session's meta) waits in the queue
/// instead of ending `NoSolAccount`, and reaches its window once the account is there; with
/// no account on its way it still ends `NoSolAccount`, never an empty window.
#[test]
fn a_solana_connect_waits_for_account_zero() {
    use crate::app_evm::QueuedItem;
    use crate::ui::approval::QueueSource;
    let mut app = app(false);
    app.mode = crate::app::AppMode::Unlocked {
        alt_passphrase: false,
    };
    app.keys.has_mnemonic = true;
    let connect = site(SiteKind::SolConnect);
    let enqueue = |app: &mut App| {
        let source = QueueSource::Site {
            origin: connect.origin.as_str().to_owned(),
            deadline_ms: u64::MAX,
        };
        app.evm
            .queue
            .enqueue(source, QueuedItem::Site(Box::new(connect.clone())))
            .unwrap();
    };
    app.sol_ensure_account();
    assert!(app.sol.creating, "account 0 on its way");
    assert_eq!(app.chain_unlocked_refusal(&connect), None);
    enqueue(&mut app);
    assert!(app.sol_connect_waits_for_account());
    app.show_next_approval();
    assert!(app.evm.queue.shown().is_none(), "the queue waits");
    // The account arrives: the connect gets its window with it.
    app.on_sol_keys(
        crate::events::SolKeysPurpose::AddAccount { index: 0 },
        Ok(vec![(
            yw_core::slip10::SolKeySource::Standard(
                yw_core::bip32::path::AccountIndex::new(0).unwrap(),
            ),
            yw_core::sol::SolAddress::parse(SOL_KEY).unwrap(),
        )]),
    );
    assert!(!app.sol.creating);
    assert!(!app.sol_connect_waits_for_account());
    assert_eq!(
        next_window(&mut app).map(|shown| shown.kind),
        Some(SiteKind::SolConnect)
    );
    if let Some((done, outcome)) = app.evm.queue.finish_shown(QueueOutcome::Rejected) {
        app.approval_finished(&done.payload, outcome);
    }
    // Nothing on its way (a derivation that failed, a key-only wallet): refused, no window.
    app.meta.as_mut().unwrap().sol_accounts.clear();
    assert_eq!(
        app.chain_unlocked_refusal(&connect),
        Some(ProviderError::NoSolAccount)
    );
    enqueue(&mut app);
    assert!(!app.sol_connect_waits_for_account());
    assert!(next_window(&mut app).is_none());
    assert!(app.evm.queue.is_empty());
}

/// spec/05 §4.9: the Bitcoin connect window starts on the origin's granted address of each
/// purpose (not the group's first account), and a reconnect queued while locked that a
/// usable grant covers is answered without a window; a purpose the grant lacks opens it.
#[test]
fn btc_reconnect_starts_on_and_answers_with_the_granted_address() {
    use yw_core::btc::{BtcAccountKey, BtcMeta, BtcNetwork};
    let mut app = app(false);
    app.settings.bitcoin.enabled = true;
    let account = |script_type, number: u32, byte: u8| {
        let node = yw_core::bip32::AccountXpub {
            pubkey: yw_core::hex::decode_array::<33>(
                "03b88e0fbe3f646337ed93bc0c0f3b843fcf7d2589e5ec884754e6402027a890b4",
            )
            .unwrap(),
            chain_code: [byte; 32],
        };
        BtcMeta::with_key(
            BtcNetwork::Mainnet,
            BtcAccountKey::hd(script_type, number, node).unwrap(),
        )
    };
    let meta = app.meta.as_mut().unwrap();
    for (script_type, number, byte) in [
        (ScriptType::P2wpkh, 1, 7),
        (ScriptType::P2wpkh, 2, 8),
        (ScriptType::P2tr, 3, 9),
    ] {
        meta.btc_accounts
            .upsert(account(script_type, number, byte))
            .unwrap();
    }
    // Connected to the second payment account.
    let rows = app.btc_dapp_rows();
    let payment: Vec<&super::BtcRow> = rows
        .iter()
        .filter(|row| row.entry.script_type == ScriptType::P2wpkh)
        .collect();
    assert_eq!(payment.len(), 2);
    let mut entry = payment[1].entry.clone();
    entry.purpose = BtcPurpose::Payment;
    let granted = entry.address.clone();
    let grant = yw_core::policy::BtcGrant::new(
        BrowserOrigin::parse("https://app.example").unwrap(),
        BtcNetwork::Mainnet,
        vec![entry],
        1,
    )
    .unwrap();
    assert!(core(&app).upsert_btc_grant(grant));
    let both = site(SiteKind::BtcConnect(vec![
        BtcPurpose::Payment,
        BtcPurpose::Ordinals,
    ]));
    let (choices, selected, _) = app.chain_connect_choices(&both);
    let picked: Vec<(u8, &str)> = choices
        .iter()
        .zip(&selected)
        .filter(|(_, on)| **on)
        .map(|((_, _, address, group), _)| (*group, address.as_str()))
        .collect();
    assert_eq!(picked.len(), 2, "one per group");
    assert_eq!(picked[0], (0, granted.as_str()));
    assert_eq!(picked[1].0, 1);
    // Queued: payment only is covered (answered), payment + ordinals needs the window.
    let payment_only = site(SiteKind::BtcConnect(vec![BtcPurpose::Payment]));
    assert_eq!(
        app.chain_site_preflight(&payment_only),
        Some(Some(QueueOutcome::Approved))
    );
    assert_eq!(app.chain_site_preflight(&both), Some(None));
}

#[test]
fn preflight_checks_hidden_accounts_bitcoin_off_and_the_grant_limit() {
    let mut app = app(true);
    let core = core(&app);
    // A grant of a key that is no longer a visible account: the window, not the old key.
    assert!(core.upsert_sol_grant(sol_grant("https://app.example", [9; 32])));
    assert_eq!(
        app.chain_site_preflight(&site(SiteKind::SolConnect)),
        Some(None)
    );
    assert!(core.upsert_sol_grant(sol_grant("https://app.example", public())));
    assert_eq!(
        app.chain_site_preflight(&site(SiteKind::SolConnect)),
        Some(Some(QueueOutcome::Approved))
    );
    // Bitcoin off: every Bitcoin request ends with BtcDisabled, without a window; a refused
    // connect (not a signature) says in the app where Bitcoin is turned on.
    app.settings.bitcoin.enabled = false;
    let btc_connect = site(SiteKind::BtcConnect(vec![BtcPurpose::Payment]));
    assert_eq!(
        app.chain_unlocked_refusal(&btc_connect),
        Some(ProviderError::BtcDisabled)
    );
    let btc_sign = site(SiteKind::BtcSign {
        address: "bc1q".to_owned(),
        message: b"hi".to_vec(),
        protocol: None,
    });
    assert_eq!(
        app.chain_site_preflight(&btc_sign),
        Some(Some(QueueOutcome::Cancelled))
    );
    assert!(app.banners.is_empty());
    assert_eq!(
        app.chain_site_preflight(&btc_connect),
        Some(Some(QueueOutcome::Cancelled))
    );
    assert!(
        app.banners
            .iter()
            .any(|banner| banner.text.contains("Bitcoin이 꺼져 있습니다"))
    );
    // 256 Solana grants (queued while locked, so the dispatcher never checked): a new origin
    // is refused before the window; the granted origin is still answered.
    for index in 0..yw_core::policy::MAX_CHAIN_GRANTS - 1 {
        assert!(core.upsert_sol_grant(sol_grant(&format!("https://s{index}.example"), [9; 32])));
    }
    let mut other = site(SiteKind::SolConnect);
    other.origin = BrowserOrigin::parse("https://new.example").unwrap();
    assert_eq!(
        app.chain_site_preflight(&other),
        Some(Some(QueueOutcome::Cancelled))
    );
    assert_eq!(
        app.chain_site_preflight(&site(SiteKind::SolConnect)),
        Some(Some(QueueOutcome::Approved))
    );
    // An approval that would pass the limit stores nothing.
    app.chain_connect_approved(&other, &[ConnectChoice::Sol(public())]);
    assert_eq!(core.sol_grants().len(), yw_core::policy::MAX_CHAIN_GRANTS);
    assert!(core.sol_grants().iter().all(|g| g.origin != other.origin));
}

#[test]
fn stale_connect_choices_are_refused() {
    let mut app = app(true);
    let core = core(&app);
    // The chosen key is not (or no longer) one of the wallet's accounts.
    app.chain_connect_approved(&site(SiteKind::SolConnect), &[ConnectChoice::Sol([9; 32])]);
    assert!(core.sol_grants().is_empty());
    // A Bitcoin address of the other network (the network changed while the window was open).
    let choice = ConnectChoice::Btc(BtcGrantAddress {
        purpose: BtcPurpose::Payment,
        address: "tb1qstale".to_owned(),
        pubkey: BtcPubKey::Compressed([2; 33]),
        script_type: ScriptType::P2wpkh,
    });
    app.settings.bitcoin.enabled = true;
    app.chain_connect_approved(
        &site(SiteKind::BtcConnect(vec![BtcPurpose::Payment])),
        &[choice],
    );
    assert!(core.btc_grants().is_empty());
    app.chain_connect_approved(&site(SiteKind::SolConnect), &[ConnectChoice::Sol(public())]);
    assert_eq!(core.sol_grants().len(), 1);
}

#[test]
fn site_rows_disconnect_the_grant_they_were_drawn_for_and_page() {
    use crate::ui::screens_sites::ids;
    let mut app = app(true);
    let core = core(&app);
    for index in 0..120 {
        assert!(core.upsert_sol_grant(sol_grant(&format!("https://s{index}.example"), [9; 32])));
    }
    let keys = |app: &App| -> Vec<String> {
        app.browser
            .as_ref()
            .unwrap()
            .site_rows
            .keys
            .borrow()
            .iter()
            .map(|(origin, family)| {
                assert_eq!(*family, Family::Solana);
                origin.as_str().to_owned()
            })
            .collect()
    };
    let mut items = Vec::new();
    app.sites_screen(&mut items);
    let drawn = keys(&app);
    assert_eq!(drawn.len(), ids::SITES_PAGE_ROWS);
    assert_eq!(drawn[0], "https://s0.example");
    // One order for every family's card: network, what the connection allows, connection
    // time, `연결 해제`, then the account with its address in 4-character groups.
    let card = items
        .iter()
        .position(|item| {
            matches!(item, crate::ui::main_window::Item::CardStart(Some(title))
                if title == "https://s0.example  ·  Solana")
        })
        .unwrap();
    let fields: Vec<String> = items[card + 1..card + 7]
        .iter()
        .map(|item| match item {
            crate::ui::main_window::Item::Badged(_, inner) => match &**inner {
                crate::ui::main_window::Item::Field(label, value) => {
                    format!("{label}={value}")
                }
                _ => String::new(),
            },
            crate::ui::main_window::Item::Field(label, _) => label.clone(),
            crate::ui::main_window::Item::Row(row) => {
                assert_eq!(row[0].id, ids::SITE_ROW_BASE);
                row[0].text.clone()
            }
            crate::ui::main_window::Item::Help(_) => "계정".to_owned(),
            crate::ui::main_window::Item::Mono(address) => {
                assert_eq!(address.find(' '), Some(4));
                "주소".to_owned()
            }
            _ => String::new(),
        })
        .collect();
    assert_eq!(
        fields,
        [
            "네트워크=Solana",
            "권한",
            "연결 시각",
            "연결 해제",
            "계정",
            "주소"
        ]
    );
    // The list changes under the screen (a dApp disconnected s0 meanwhile): the first
    // button still means s0 — nothing else is disconnected.
    assert!(core.remove_sol_grant(&BrowserOrigin::parse("https://s0.example").unwrap()));
    assert!(app.on_sites_command(ids::SITE_ROW_BASE));
    assert_eq!(core.sol_grants().len(), 119);
    assert!(app.on_sites_command(ids::SITE_ROW_BASE + 1));
    assert_eq!(core.sol_grants().len(), 118);
    assert_eq!(
        app.info.as_deref(),
        Some("https://s1.example  ·  Solana 연결을 해제했습니다.")
    );
    assert!(
        core.sol_grants()
            .iter()
            .all(|g| g.origin.as_str() != "https://s1.example")
    );
    // Pages: every grant gets a button (no 256-row limit), 50 per page.
    assert!(app.on_sites_command(ids::SITES_NEXT));
    app.sites_screen(&mut Vec::new());
    assert_eq!(keys(&app)[0], "https://s52.example");
    assert!(app.on_sites_command(ids::SITES_NEXT));
    assert!(app.on_sites_command(ids::SITES_NEXT));
    app.sites_screen(&mut Vec::new());
    assert_eq!(keys(&app).len(), 18);
    assert_eq!(keys(&app).last().unwrap(), "https://s119.example");
    assert!(app.on_sites_command(ids::SITES_PREV));
    app.sites_screen(&mut Vec::new());
    assert_eq!(keys(&app)[0], "https://s52.example");
}

/// Regression (screenshot tour): after a rejected `sol_signMessage`, the following
/// `btc_signMessage` of the same site never got a window. The queue was fine; every Bitcoin
/// message draft (and every SIWS / off-chain Solana draft) carried a display key without a
/// window label (0x0406 `서명 방식`, 0x0405 SIWS), so `validate_for_display` failed and the
/// window closed at once with E-UI-001.
#[test]
fn chain_message_windows_follow_each_other_after_a_rejection() {
    use crate::app_evm::QueuedItem;
    use crate::ui::approval::{QueueSource, field_label, validate_for_display};
    use yw_core::btc::{BtcAccountKey, BtcMeta};
    for key in 0..=u16::MAX {
        let key = yw_core::approval::FieldKey(key);
        assert!(
            key.flags().is_none()
                || yw_core::lang::Lang::ALL
                    .iter()
                    .all(|lang| field_label(key, *lang).is_some()),
            "display key {key:?} has no window label"
        );
    }
    let mut app = app(true);
    app.settings.bitcoin.enabled = true;
    let node = yw_core::bip32::AccountXpub {
        pubkey: yw_core::hex::decode_array::<33>(
            "03b88e0fbe3f646337ed93bc0c0f3b843fcf7d2589e5ec884754e6402027a890b4",
        )
        .unwrap(),
        chain_code: [7; 32],
    };
    let key = BtcAccountKey::hd(ScriptType::P2wpkh, 1, node).unwrap();
    let account = BtcMeta::with_key(app.btc_network_now(), key);
    app.meta
        .as_mut()
        .unwrap()
        .btc_accounts
        .upsert(account)
        .unwrap();
    let row = app.btc_dapp_rows().pop().unwrap();
    let core = core(&app);
    assert!(core.upsert_sol_grant(sol_grant("https://app.example", public())));
    let grant = yw_core::policy::BtcGrant::new(
        BrowserOrigin::parse("https://app.example").unwrap(),
        app.btc_network_now(),
        vec![BtcGrantAddress {
            purpose: BtcPurpose::Payment,
            ..row.entry.clone()
        }],
        1,
    )
    .unwrap();
    assert!(core.upsert_btc_grant(grant));
    let siws = yw_core::sol::msgsign::SiwsMessage {
        domain: "app.example".to_owned(),
        address: SOL_KEY.to_owned(),
        statement: Some("Sign in".to_owned()),
        ..yw_core::sol::msgsign::SiwsMessage::default()
    };
    let sol = |sign_in: bool| {
        site(SiteKind::SolSign {
            public: public(),
            message: if sign_in {
                siws.to_text().into_bytes()
            } else {
                b"Prove it".to_vec()
            },
            sign_in,
        })
    };
    let btc = site(SiteKind::BtcSign {
        address: row.entry.address.clone(),
        message: b"Prove it".to_vec(),
        protocol: None,
    });
    let evm = site(SiteKind::RequestAccounts);
    for order in [
        vec![sol(false), btc.clone()],
        vec![btc.clone(), sol(false)],
        vec![sol(true), evm.clone(), btc.clone(), sol(false)],
        vec![evm.clone(), btc.clone(), evm.clone(), sol(true)],
    ] {
        for request in &order {
            let source = QueueSource::Site {
                origin: request.origin.as_str().to_owned(),
                deadline_ms: u64::MAX,
            };
            app.evm
                .queue
                .enqueue(source, QueuedItem::Site(Box::new(request.clone())))
                .unwrap();
        }
        for expected in &order {
            // Each request of the site gets its window in turn, and is then rejected.
            let shown = next_window(&mut app).expect("a window for the next request");
            assert_eq!(shown.kind, expected.kind);
            if shown.kind.is_signing() {
                let draft = app.chain_sign_draft(&shown).unwrap();
                assert_eq!(validate_for_display(&draft.display), Ok(()));
                let request = app.evm.store.issue(draft, 0, 0).unwrap();
                app.evm.store.reject(request.id);
            }
            if let Some((done, outcome)) = app.evm.queue.finish_shown(QueueOutcome::Rejected) {
                app.approval_finished(&done.payload, outcome);
            }
        }
        assert!(next_window(&mut app).is_none());
        assert!(app.evm.queue.is_empty());
    }
}

/// spec/05 §3.6: a granted dApp transaction request opens its window only with an endpoint
/// (4901 otherwise) and while its cluster is still the wallet's (-32602, Q16); a send is
/// refused at the pending caps (-32002: 16 of the signer, 32 in the journal). Not granted:
/// revoked (4100).
#[test]
fn sol_tx_preflight_refusals() {
    use yw_core::sol::dapp::SolTxMode;
    let mut app = app(true);
    app.settings.solana.cluster = crate::network::SolCluster::Devnet;
    let sign = site(sol_tx_kind(SolTxMode::SignOnly));
    assert_eq!(
        app.chain_site_preflight(&sign),
        Some(Some(QueueOutcome::Revoked))
    );
    if let Some(browser) = app.browser.as_ref() {
        browser
            .core
            .upsert_sol_grant(sol_grant("https://app.example", public()));
    }
    assert_eq!(
        app.sol_dapp_refusal(&public(), DEVNET, SolTxMode::SignOnly),
        Some(ProviderError::ChainUnavailable)
    );
    assert_eq!(
        app.chain_site_preflight(&sign),
        Some(Some(QueueOutcome::Cancelled))
    );
    let url = yw_platform::http::HttpsUrl::parse("https://sol.example.test/").unwrap();
    app.apikeys.set_rpc(
        crate::network::NetworkId::Solana(crate::network::SolCluster::Devnet),
        &url,
    );
    assert_eq!(
        app.sol_dapp_refusal(&public(), DEVNET, SolTxMode::SignOnly),
        None
    );
    assert_eq!(app.chain_site_preflight(&sign), Some(None));
    let send = site(sol_tx_kind(SolTxMode::SignAndSend));
    assert_eq!(
        app.sol_dapp_refusal(&public(), DEVNET, SolTxMode::SignAndSend),
        None
    );
    assert_eq!(app.chain_site_preflight(&send), Some(None));
    // 15 pending sends of the key still open the window; the 16th is the cap.
    let mut journal = crate::events::JournalView {
        sol_records: vec![dapp_pending(public()); 15],
        ..crate::events::JournalView::default()
    };
    app.evm.journal = Some(journal.clone());
    assert_eq!(
        app.sol_dapp_refusal(&public(), DEVNET, SolTxMode::SignAndSend),
        None
    );
    journal.sol_records.push(dapp_pending(public()));
    app.evm.journal = Some(journal.clone());
    assert_eq!(
        app.sol_dapp_refusal(&public(), DEVNET, SolTxMode::SignAndSend),
        Some(ProviderError::TransactionPending)
    );
    assert_eq!(
        app.chain_site_preflight(&send),
        Some(Some(QueueOutcome::Cancelled))
    );
    // 32 pending sends of other keys: the whole-journal cap.
    journal.sol_records = vec![dapp_pending([9; 32]); 32];
    app.evm.journal = Some(journal);
    assert_eq!(
        app.sol_dapp_refusal(&public(), DEVNET, SolTxMode::SignAndSend),
        Some(ProviderError::TransactionPending)
    );
    // Sign-only never counts pending sends.
    assert_eq!(
        app.sol_dapp_refusal(&public(), DEVNET, SolTxMode::SignOnly),
        None
    );
    // The wallet switched to mainnet while a devnet request waited (an endpoint for both).
    app.apikeys.set_rpc(
        crate::network::NetworkId::Solana(crate::network::SolCluster::Mainnet),
        &url,
    );
    app.settings.solana.cluster = crate::network::SolCluster::Mainnet;
    assert_eq!(
        app.sol_dapp_refusal(&public(), DEVNET, SolTxMode::SignOnly),
        Some(ProviderError::InvalidParams)
    );
    assert_eq!(
        app.chain_site_preflight(&sign),
        Some(Some(QueueOutcome::Cancelled))
    );
}

/// spec/05 §3.6, R-SOLTX: the backup and card gates of `sol_signMessage` hold for a dApp
/// transaction too — an account of an added phrase whose backup quiz has not passed, and a
/// `YubiKey` account on its factory PINs, are refused before the window (4100, one notice);
/// once cleared the request reaches its window.
#[test]
fn sol_tx_preflight_backup_and_card_gates() {
    use yw_core::bip32::path::AccountIndex;
    use yw_core::sol::dapp::SolTxMode;
    use yw_core::vault::{MnemonicInfo, RecordId};
    use yw_core::yubikey::plan::{CardSlot, KeyRole, PinPolicy, PivSlot, TouchPolicy};
    use yw_core::yubikey::record::{HwKeyRecord, HwPublicKey, RecordedSlot};
    const SERIAL: u32 = 7_700_011;
    let mut app = app(false);
    app.settings.solana.cluster = crate::network::SolCluster::Devnet;
    let url = yw_platform::http::HttpsUrl::parse("https://sol.example.test/").unwrap();
    app.apikeys.set_rpc(
        crate::network::NetworkId::Solana(crate::network::SolCluster::Devnet),
        &url,
    );
    core(&app).upsert_sol_grant(sol_grant("https://app.example", public()));
    let sign = site(sol_tx_kind(SolTxMode::SignOnly));
    let account = || crate::meta::Account {
        index: 0,
        label: "SOL 1".to_owned(),
        address: SOL_KEY.to_owned(),
        hidden: false,
    };
    let notices = |app: &App, text: &str| {
        app.banners
            .iter()
            .filter(|banner| banner.text.contains(text))
            .count()
    };
    // An added phrase's account before its backup quiz.
    let phrase = RecordId::from_bytes([7; 16]);
    app.meta
        .as_mut()
        .unwrap()
        .mnemonic_accounts
        .sol
        .push((*phrase.as_bytes(), account()));
    app.mn.infos = vec![MnemonicInfo {
        id: phrase,
        created_unix: 0,
        words: 12,
        passphrase_used: false,
        backup_confirmed: false,
        primary: false,
    }];
    for _ in 0..2 {
        assert_eq!(
            app.chain_site_preflight(&sign),
            Some(Some(QueueOutcome::Cancelled))
        );
    }
    assert_eq!(notices(&app, "백업 확인 전이라"), 1);
    app.mn.infos[0].backup_confirmed = true;
    assert_eq!(app.chain_site_preflight(&sign), Some(None));
    // A YubiKey account whose card is still on its factory PINs.
    let meta = app.meta.as_mut().unwrap();
    meta.mnemonic_accounts.sol.clear();
    meta.hw_accounts.sol = vec![account()];
    meta.hw_accounts.defaults = vec![SERIAL];
    app.card.records = vec![HwKeyRecord {
        serial: SERIAL,
        firmware: yw_core::yubikey::Firmware::new(5, 7, 4),
        fingerprint: [0; 4],
        slots: vec![RecordedSlot {
            slot: CardSlot::Piv(PivSlot::new(0x82).unwrap()),
            role: KeyRole::Sol {
                index: AccountIndex::ZERO,
            },
            touch: TouchPolicy::Always,
            pin: PinPolicy::NotApplicable,
            public: HwPublicKey::Ed25519(public()),
            path_known: true,
        }],
    }];
    for _ in 0..2 {
        assert_eq!(
            app.chain_site_preflight(&sign),
            Some(Some(QueueOutcome::Cancelled))
        );
    }
    assert_eq!(
        notices(&app, "PIN이 아직 공장 기본값이라 서명하지 않았습니다"),
        1
    );
    app.meta.as_mut().unwrap().hw_accounts.defaults.clear();
    assert_eq!(app.chain_site_preflight(&sign), Some(None));
}

/// R-SOLTX, spec/07 §20.7: a failed preview is the window's failure, never a draft without
/// it (no X01) — a genesis mismatch E-RPC-006 not retried, a transport error retried; a
/// preview of a request whose cluster is no longer the wallet's (switched during the
/// preview) is E-RPC-006 too. The draft names the request's cluster. Closing the window
/// answers 4001.
#[test]
fn a_failed_preview_is_the_window_failure_and_closing_answers_4001() {
    use crate::app_evm::QueuedItem;
    use crate::errors::ErrorCode;
    use crate::ui::approval::QueueSource;
    let mut app = app(true);
    app.settings.solana.cluster = crate::network::SolCluster::Devnet;
    let url = yw_platform::http::HttpsUrl::parse("https://sol.example.test/").unwrap();
    app.apikeys.set_rpc(
        crate::network::NetworkId::Solana(crate::network::SolCluster::Devnet),
        &url,
    );
    let (events, frames, conn) = recorded(&mut app);
    let request = queued_sol_tx(&app, &events, conn, 1);
    assert!(matches!(
        request.kind,
        SiteKind::SolTx {
            cluster: DEVNET,
            ..
        }
    ));
    assert_eq!(
        app.sol_dapp_draft(&request, Err(ErrorCode::Rpc006)),
        Err((ErrorCode::Rpc006, false))
    );
    assert_eq!(
        app.sol_dapp_draft(&request, Err(ErrorCode::Rpc001)),
        Err((ErrorCode::Rpc001, true))
    );
    let draft = app.sol_dapp_draft(&request, Ok(preview(1))).unwrap();
    assert!(matches!(
        draft.chain,
        yw_core::approval::ChainRef::Solana {
            cluster: DEVNET,
            ..
        }
    ));
    app.settings.solana.cluster = crate::network::SolCluster::Mainnet;
    assert_eq!(
        app.sol_dapp_draft(&request, Ok(preview(1))),
        Err((ErrorCode::Rpc006, false))
    );
    app.settings.solana.cluster = crate::network::SolCluster::Devnet;
    // The failed window is closed: the dApp gets 4001.
    let source = QueueSource::Site {
        origin: request.origin.as_str().to_owned(),
        deadline_ms: u64::MAX,
    };
    app.evm
        .queue
        .enqueue(source, QueuedItem::Site(Box::new(request.clone())))
        .unwrap();
    assert_eq!(next_window(&mut app), Some(request));
    assert!(answers(&frames).is_empty());
    if let Some((done, outcome)) = app.evm.queue.finish_shown(QueueOutcome::Rejected) {
        app.approval_finished(&done.payload, outcome);
    }
    assert_eq!(answers(&frames), vec![Err(ProviderError::UserRejected)]);
}

/// spec/07 §20.8: an approved sign-only request leaves one chain-message waiter
/// (`ChainAnswer::SolTx`, not a send) and a `SignChainMessage` job for its ticket. An
/// approved send leaves a send waiter and its pre-sign check on the RPC worker (the
/// approved message on the request's cluster), then `SignSolDapp` with the bound
/// `lastValidBlockHeight`, the check and the origin; nothing is signed before. A failed
/// check answers -32603 with the reason in a band, a late check is dropped, and no
/// endpoint answers 4901.
#[test]
#[expect(clippy::too_many_lines, reason = "one request of each kind, in order")]
fn approved_requests_go_to_the_key_worker_or_the_presign_check() {
    use crate::app_browser::SignWaiter;
    use crate::events::KeyJob;
    use crate::sol::flow::PreSignError;
    use crate::workers::rpc::RpcJob;
    use yw_core::sol::dapp::PreSignCheck;
    let mut app = app(true);
    devnet(&mut app);
    let (events, frames, conn) = recorded(&mut app);
    let sign = queued_sol_tx(&app, &events, conn, 1);
    app.sol_dapp_consumed(approve_site(&app, &sign), &sign);
    let waiters: Vec<_> = app.browser.as_ref().unwrap().waiters.iter().collect();
    let [(ticket, SignWaiter::Chain(reply, answer))] = waiters.as_slice() else {
        unreachable!("one chain waiter, got {}", waiters.len());
    };
    let ticket = **ticket;
    assert_eq!(*reply, sign.reply);
    assert_eq!(
        **answer,
        ChainAnswer::SolTx {
            public: public(),
            origin: sign.origin.clone(),
            batch: false,
            send: false,
        }
    );
    let Some((_, KeyJob::SignChainMessage { ticket: job, .. })) = app.key_queue.pop() else {
        unreachable!("a SignChainMessage job");
    };
    assert_eq!(job, ticket);
    assert!(app.key_queue.is_empty());
    assert!(answers(&frames).is_empty());
    app.browser.as_mut().unwrap().waiters.clear();
    // A send: its pre-sign check first, nothing signed yet.
    let (rpc, jobs) = std::sync::mpsc::channel();
    app.rpc_tx = Some(rpc);
    let send = queued_send(&app, &events, conn, 2);
    app.sol_dapp_consumed(approve_site(&app, &send), &send);
    let ticket = {
        let waiters: Vec<_> = app.browser.as_ref().unwrap().waiters.iter().collect();
        let [(ticket, SignWaiter::Chain(_, answer))] = waiters.as_slice() else {
            unreachable!("one send waiter");
        };
        assert!(matches!(**answer, ChainAnswer::SolTx { send: true, .. }));
        **ticket
    };
    let Ok(RpcJob::SolDappPreSign {
        job,
        endpoint,
        message,
    }) = jobs.try_recv()
    else {
        unreachable!("a pre-sign check");
    };
    assert_eq!(endpoint.cluster, DEVNET);
    assert_eq!(message.blockhash, [7; 32]);
    assert!(app.key_queue.is_empty());
    let check = PreSignCheck {
        blockhash: [7; 32],
        loaded: None,
    };
    app.on_sol_dapp_presigned(job, Ok((1_150, check.clone())));
    let Some((
        _,
        KeyJob::SignSolDapp {
            ticket: signing,
            last_valid_block_height,
            check: passed,
            origin,
            ..
        },
    )) = app.key_queue.pop()
    else {
        unreachable!("a SignSolDapp job");
    };
    assert_eq!(signing, ticket);
    assert_eq!(last_valid_block_height, 1_150);
    assert_eq!(passed, check);
    assert_eq!(origin, "https://app.example");
    assert!(app.sol.dapp_presign.is_empty());
    assert!(answers(&frames).is_empty());
    app.browser.as_mut().unwrap().waiters.clear();
    // The check found the blockhash expired: -32603 and a band, the waiter gone.
    let expired = queued_send(&app, &events, conn, 3);
    app.sol_dapp_consumed(approve_site(&app, &expired), &expired);
    let Ok(RpcJob::SolDappPreSign { job, .. }) = jobs.try_recv() else {
        unreachable!("a pre-sign check");
    };
    app.on_sol_dapp_presigned(job, Err(PreSignError::BlockhashExpired));
    assert_eq!(answers(&frames), vec![Err(ProviderError::BroadcastFailed)]);
    assert!(app.banners.iter().any(|banner| {
        banner
            .text
            .starts_with("사이트 거래를 보내지 못했습니다: 거래의 블록해시가 만료")
    }));
    assert!(app.browser.as_ref().unwrap().waiters.is_empty());
    // A check whose entry is gone (answered) is dropped.
    app.on_sol_dapp_presigned(job, Ok((1_150, check)));
    assert!(app.key_queue.is_empty());
    // No endpoint any more: 4901 before any RPC.
    app.apikeys = ApiKeys::default();
    let late = queued_send(&app, &events, conn, 4);
    app.sol_dapp_consumed(approve_site(&app, &late), &late);
    assert_eq!(answers(&frames), vec![Err(ProviderError::ChainUnavailable)]);
    assert!(jobs.try_recv().is_err());
    assert!(app.sol.dapp_presign.is_empty());
    // A card send takes one touch and says so as any single-touch step.
    let kind = crate::app_card::CardJobKind::SolDappSend { cluster: DEVNET };
    assert_eq!(
        crate::app_card::approval_touches(&approve_site(&app, &late), &kind),
        1
    );
    assert_eq!(
        crate::app_card::touch_text(&kind, 1),
        crate::app_card::T_CARD_TOUCH
    );
}

/// spec/07 §20.8, spec/05 §3.6: a journaled send is tracked at once (its first round sends
/// with `minContextSlot` and the record's own options) and answered `{publicKey,
/// signature}` with the transaction id after that round; later sends drop
/// `minContextSlot`. The same bytes approved twice are one record and both are answered.
/// A deterministic preflight error answers -32603; a site disconnected before the round,
/// or before the signature came, gets 4100 (the transaction is still journaled and
/// tracked).
#[test]
#[expect(clippy::too_many_lines, reason = "one record's answers, in order")]
fn a_send_is_answered_after_its_first_round() {
    use crate::events::SolDappSigned;
    use crate::workers::rpc::RpcJob;
    use yw_core::sol::broadcast::{LoopState, Outcome};
    let mut app = app(true);
    devnet(&mut app);
    app.mode = crate::app::AppMode::Unlocked {
        alt_passphrase: false,
    };
    let (events, frames, conn) = recorded(&mut app);
    // The dispatcher already holds the unlocked grants (no unlock merge from meta).
    app.browser.as_mut().unwrap().unlocked = true;
    let (rpc, jobs) = std::sync::mpsc::channel();
    app.rpc_tx = Some(rpc);
    let record = dapp_pending(public());
    let tx_id = record.signature();
    app.evm.journal = Some(crate::events::JournalView {
        sol_records: vec![record],
        ..crate::events::JournalView::default()
    });
    let pending = |app: &App| {
        app.browser
            .as_ref()
            .unwrap()
            .sol_broadcasts
            .get(&tx_id)
            .map_or(0, Vec::len)
    };
    let first = queued_send(&app, &events, conn, 1);
    let ticket = send_waiter(&mut app, &first);
    app.on_sol_dapp_signed(SolDappSigned {
        ticket,
        result: Ok(summary(tx_id, false, Some(77))),
    });
    assert!(answers(&frames).is_empty());
    assert_eq!(pending(&app), 1);
    assert_eq!(app.sol_dapp_min_context_slot(&tx_id), Some(77));
    let Ok(RpcJob::SolTrack(job)) = jobs.try_recv() else {
        unreachable!("the first round");
    };
    assert_eq!(job.signature, tx_id);
    assert_eq!(job.send.min_context_slot, Some(77));
    assert!(!job.send.skip_preflight);
    assert!(!job.check_genesis, "checked at pre-sign");
    app.sol_rpc_event(first_round(
        tx_id,
        LoopState::default(),
        Ok(Outcome::Pending { notice: false }),
    ));
    assert_eq!(texts(answers(&frames)), vec![Ok(send_answer_text(tx_id))]);
    assert_eq!(pending(&app), 0);
    assert_eq!(app.sol_dapp_min_context_slot(&tx_id), None);
    // The next round's sends: no minContextSlot.
    app.sol_tick_tracking(u64::MAX);
    let Ok(RpcJob::SolTrack(job)) = jobs.try_recv() else {
        unreachable!("the next round");
    };
    assert_eq!(job.send.min_context_slot, None);
    app.sol_rpc_event(first_round(
        tx_id,
        LoopState::default(),
        Ok(Outcome::Pending { notice: false }),
    ));
    assert!(answers(&frames).is_empty());
    // The same bytes approved twice (the second found the record): both get the same id.
    // The reused one's `minContextSlot` is dropped: that record was already sent.
    for (n, reused, min_context_slot) in [(2, false, None), (3, true, Some(88))] {
        let site = queued_send(&app, &events, conn, n);
        let ticket = send_waiter(&mut app, &site);
        app.on_sol_dapp_signed(SolDappSigned {
            ticket,
            result: Ok(summary(tx_id, reused, min_context_slot)),
        });
    }
    assert_eq!(pending(&app), 2);
    assert!(answers(&frames).is_empty());
    assert_eq!(app.sol_dapp_min_context_slot(&tx_id), None);
    app.sol_tick_tracking(u64::MAX);
    let Some(RpcJob::SolTrack(job)) = jobs.try_iter().last() else {
        unreachable!("the reused waiters' round");
    };
    assert_eq!(job.send.min_context_slot, None);
    app.sol_rpc_event(first_round(
        tx_id,
        LoopState::default(),
        Err(crate::errors::ErrorCode::Rpc002),
    ));
    assert_eq!(
        texts(answers(&frames)),
        vec![Ok(send_answer_text(tx_id)), Ok(send_answer_text(tx_id))]
    );
    // A deterministic preflight error stopped the re-sends: -32603.
    let site = queued_send(&app, &events, conn, 4);
    let ticket = send_waiter(&mut app, &site);
    app.on_sol_dapp_signed(SolDappSigned {
        ticket,
        result: Ok(summary(tx_id, true, None)),
    });
    app.sol_rpc_event(first_round(
        tx_id,
        LoopState {
            stop_rebroadcast: true,
            preflight_err: Some(9),
            ..LoopState::default()
        },
        Ok(Outcome::Pending { notice: false }),
    ));
    assert_eq!(answers(&frames), vec![Err(ProviderError::BroadcastFailed)]);
    // Disconnected before the round: 4100.
    let site = queued_send(&app, &events, conn, 5);
    let later = queued_send(&app, &events, conn, 6);
    let ticket = send_waiter(&mut app, &site);
    app.on_sol_dapp_signed(SolDappSigned {
        ticket,
        result: Ok(summary(tx_id, true, None)),
    });
    assert!(core(&app).remove_sol_grant(&site.origin));
    app.sol_rpc_event(first_round(
        tx_id,
        LoopState::default(),
        Ok(Outcome::Pending { notice: false }),
    ));
    assert_eq!(answers(&frames), vec![Err(ProviderError::Unauthorized)]);
    // Disconnected before the signature came: 4100 at once, the record still tracked.
    let ticket = send_waiter(&mut app, &later);
    app.on_sol_dapp_signed(SolDappSigned {
        ticket,
        result: Ok(summary(tx_id, true, None)),
    });
    assert_eq!(answers(&frames), vec![Err(ProviderError::Unauthorized)]);
    assert_eq!(pending(&app), 0);
    assert!(app.sol.tracking.contains_key(&tx_id));
}

/// spec/07 §20.8, §20.10-5: a send cancelled by the lock before it ran answers 4001, the
/// pending caps -32002, a signer refusal -32603 with the reason in a band; a send whose
/// record already ended (approved again) is answered at once. The lock answers a send
/// still waiting for its pre-sign check 4001 (approval and PIN dropped) and a journaled
/// one waiting for its first round with its transaction id; a signature that comes while
/// locked is answered at once.
#[test]
fn send_failures_and_the_lock_answer_every_waiter() {
    use crate::events::{SolDappSigned, SolSignFailure};
    use yw_core::sol::dapp::SolTxSignError;
    let mut app = app(true);
    devnet(&mut app);
    app.mode = crate::app::AppMode::Unlocked {
        alt_passphrase: false,
    };
    let (events, frames, conn) = recorded(&mut app);
    // The dispatcher already holds the unlocked grants (no unlock merge from meta).
    app.browser.as_mut().unwrap().unlocked = true;
    let mut landed = dapp_pending(public());
    landed.state = yw_core::journal::sol::SolTxState::Landed;
    let tx_id = landed.signature();
    app.evm.journal = Some(crate::events::JournalView {
        sol_records: vec![landed],
        ..crate::events::JournalView::default()
    });
    let mut n = 0_u8;
    let mut next = |app: &mut App| {
        n += 1;
        let site = queued_send(app, &events, conn, n);
        (send_waiter(app, &site), site)
    };
    for failure in [
        SolSignFailure::Locked,
        SolSignFailure::TooManyPending,
        SolSignFailure::DappSign(SolTxSignError::DeadlineExceeded),
    ] {
        let (ticket, _) = next(&mut app);
        app.on_sol_dapp_signed(SolDappSigned {
            ticket,
            result: Err(failure),
        });
    }
    assert_eq!(
        answers(&frames),
        vec![
            Err(ProviderError::UserRejected),
            Err(ProviderError::TransactionPending),
            Err(ProviderError::Internal)
        ]
    );
    assert!(app.banners.iter().any(|banner| {
        banner.text
            == "사이트 거래에 서명하지 못했습니다: 승인 후 서명까지 시간이 너무 오래 걸려 서명하지 않았습니다"
    }));
    // Approved again after the record landed: its id at once.
    let (ticket, _) = next(&mut app);
    app.on_sol_dapp_signed(SolDappSigned {
        ticket,
        result: Ok(summary(tx_id, true, None)),
    });
    assert_eq!(texts(answers(&frames)), vec![Ok(send_answer_text(tx_id))]);
    // The lock: one send waiting for its check, one for its first round.
    let (waiting, site) = next(&mut app);
    let approved = approve_site(&app, &site);
    app.sol.dapp_presign.insert(
        41,
        crate::app_sol_dapp::PendingDappSign {
            ticket: waiting,
            approved: Box::new(approved),
            pin: None,
            origin: site.origin.as_str().to_owned(),
        },
    );
    let (ticket, site) = next(&mut app);
    app.browser.as_mut().unwrap().waiters.remove(&ticket);
    app.browser
        .as_mut()
        .unwrap()
        .sol_broadcasts
        .entry([3; 64])
        .or_default()
        .push(crate::app_sol_dapp::SolBroadcast {
            reply: site.reply,
            public: public(),
            origin: site.origin.clone(),
            min_context_slot: None,
        });
    app.sol_lock();
    assert_eq!(
        texts(answers(&frames)),
        vec![
            Err(ProviderError::UserRejected),
            Ok(send_answer_text([3; 64]))
        ]
    );
    assert!(app.sol.dapp_presign.is_empty());
    assert!(app.browser.as_ref().unwrap().sol_broadcasts.is_empty());
    // A signature that comes after the lock: answered at once (tracked after unlock).
    app.mode = crate::app::AppMode::Locked;
    let (ticket, _) = next(&mut app);
    app.on_sol_dapp_signed(SolDappSigned {
        ticket,
        result: Ok(summary([4; 64], false, None)),
    });
    assert_eq!(texts(answers(&frames)), vec![Ok(send_answer_text([4; 64]))]);
    assert!(app.sol.tracking.is_empty());
    assert!(app.browser.as_ref().unwrap().waiters.is_empty());
}

/// spec/07 §20.10-4 and E10: signed dApp transactions are answered `{publicKey,
/// signedTransaction}` while the origin's grant still names the key; a site disconnected
/// before the answer gets 4100 and no bytes; a waiter cancelled by the lock (or a
/// lock-cancelled job) gets 4001 like any chain message.
#[test]
fn signed_transactions_answer_only_while_the_grant_holds() {
    use crate::app_browser::SignWaiter;
    use crate::events::ChainMessageSigned;
    let mut app = app(true);
    let (events, frames, conn) = recorded(&mut app);
    let waiter = |app: &mut App, site: &SiteRequest| {
        app.push_sign_waiter(SignWaiter::Chain(
            site.reply,
            Box::new(ChainAnswer::SolTx {
                public: public(),
                origin: site.origin.clone(),
                batch: false,
                send: false,
            }),
        ))
    };
    let first = queued_sol_tx(&app, &events, conn, 1);
    assert!(matches!(first.kind, SiteKind::SolTx { .. }));
    let ticket = waiter(&mut app, &first);
    app.browser_chain_message_signed(&ChainMessageSigned {
        ticket,
        result: Ok(ChainSignature::SolTxs(vec![vec![0xab]])),
    });
    let found = answers(&frames);
    let [Ok(value)] = found.as_slice() else {
        unreachable!("one answer");
    };
    let text = String::from_utf8(yw_json::to_vec(value)).unwrap();
    assert_eq!(
        text,
        format!(r#"{{"publicKey":"{SOL_KEY}","signedTransaction":"ab"}}"#)
    );
    // Lock: the waiter itself (E10) and a lock-cancelled job.
    let second = queued_sol_tx(&app, &events, conn, 2);
    let ticket = waiter(&mut app, &second);
    app.browser_sign_cancelled(ticket);
    let third = queued_sol_tx(&app, &events, conn, 3);
    let ticket = waiter(&mut app, &third);
    app.browser_chain_message_signed(&ChainMessageSigned {
        ticket,
        result: Err(true),
    });
    assert_eq!(
        answers(&frames),
        vec![
            Err(ProviderError::UserRejected),
            Err(ProviderError::UserRejected)
        ]
    );
    // Disconnected while the key worker signed: 4100, the bytes never leave.
    let fourth = queued_sol_tx(&app, &events, conn, 4);
    let ticket = waiter(&mut app, &fourth);
    assert!(core(&app).remove_sol_grant(&fourth.origin));
    assert!(!app.sol_grant_holds(&fourth.origin, &public()));
    app.browser_chain_message_signed(&ChainMessageSigned {
        ticket,
        result: Ok(ChainSignature::SolTxs(vec![vec![0xab]])),
    });
    assert_eq!(answers(&frames), vec![Err(ProviderError::Unauthorized)]);
    assert!(app.browser.as_ref().unwrap().waiters.is_empty());
}

/// spec/05 §4.5 (2026-11-13): every dApp signature and EVM transaction hash is answered only
/// while the origin's grant still names the signer — EVM `personal_sign` and
/// `eth_signTypedData_v4`, Solana messages and sign-ins, Bitcoin messages like Solana
/// transactions; a site disconnected between the approval and the answer gets 4100 and the
/// signature is dropped, and so does one whose grant stays but no longer lists the account
/// (hidden). The hash of a broadcast transaction (journaled and sent all the same) is checked
/// only while unlocked, like a Solana send's.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one answer per family, held and gone"
)]
fn signatures_and_hashes_answer_only_while_the_grant_holds() {
    use crate::app_browser::SignWaiter;
    use crate::events::{ChainMessageSigned, MessageSigned};
    use crate::flow::evm::track::BroadcastOutcome;
    let mut app = app(true);
    let (events, frames, conn) = recorded(&mut app);
    let origin = BrowserOrigin::parse("https://app.example").unwrap();
    let btc_address = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
    let core = core(&app);
    core.upsert_grant(evm_grant());
    assert!(core.upsert_btc_grant(yw_core::policy::BtcGrant {
        origin: origin.clone(),
        network: yw_core::btc::BtcNetwork::Mainnet,
        addresses: vec![BtcGrantAddress {
            purpose: BtcPurpose::Payment,
            address: btc_address.to_owned(),
            pubkey: BtcPubKey::Compressed([2; 33]),
            script_type: ScriptType::P2wpkh,
        }],
        granted_at_unix_ms: 1,
    }));
    let mut n = 0_u8;
    let mut reply = |app: &App| {
        n += 1;
        queued_sol_tx(app, &events, conn, n).reply
    };
    let sol = |sign_in: bool| ChainAnswer::Sol {
        public: public(),
        origin: origin.clone(),
        message: b"hi".to_vec(),
        sign_in,
    };
    let btc = || ChainAnswer::Btc {
        address: btc_address.to_owned(),
        origin: origin.clone(),
        protocol: BtcMessageProtocol::Ecdsa,
    };
    let btc_signature = || {
        ChainSignature::Btc(BtcMessageSignature {
            signature: "AA==".to_owned(),
            message_hash: [0; 32],
        })
    };
    // Every grant holds: each answer goes out (`personal_sign` and `eth_signTypedData_v4`
    // share the message waiter; `sol_signMessage` and `sol_signIn` the Solana one).
    for _ in ["personal_sign", "eth_signTypedData_v4"] {
        let ticket = app.push_sign_waiter(SignWaiter::Message(reply(&app), evm_signer()));
        app.browser_message_signed(MessageSigned {
            ticket,
            result: Ok([1; 65]),
        });
    }
    for sign_in in [false, true] {
        let ticket = app.push_sign_waiter(SignWaiter::Chain(reply(&app), Box::new(sol(sign_in))));
        app.browser_chain_message_signed(&ChainMessageSigned {
            ticket,
            result: Ok(ChainSignature::Sol([2; 64])),
        });
    }
    let ticket = app.push_sign_waiter(SignWaiter::Chain(reply(&app), Box::new(btc())));
    app.browser_chain_message_signed(&ChainMessageSigned {
        ticket,
        result: Ok(btc_signature()),
    });
    app.mode = crate::app::AppMode::Unlocked {
        alt_passphrase: false,
    };
    let ticket = app.push_sign_waiter(SignWaiter::Tx(reply(&app), evm_signer()));
    app.browser_tx_signed(ticket, Ok([0x11; 32]));
    app.browser_broadcast([0x11; 32], BroadcastOutcome::Sent);
    let found = answers(&frames);
    assert_eq!(found.len(), 6);
    assert!(found.iter().all(Result::is_ok), "{found:?}");
    // Each family disconnected after the approval: 4100, nothing sent.
    let mut messages = Vec::new();
    for _ in 0..2 {
        let message = reply(&app);
        messages.push(app.push_sign_waiter(SignWaiter::Message(message, evm_signer())));
    }
    let mut sol_messages = Vec::new();
    for sign_in in [false, true] {
        let sol_message = reply(&app);
        sol_messages
            .push(app.push_sign_waiter(SignWaiter::Chain(sol_message, Box::new(sol(sign_in)))));
    }
    let btc_message = reply(&app);
    let tx = reply(&app);
    let btc_message = app.push_sign_waiter(SignWaiter::Chain(btc_message, Box::new(btc())));
    let tx = app.push_sign_waiter(SignWaiter::Tx(tx, evm_signer()));
    app.browser_tx_signed(tx, Ok([0x22; 32]));
    assert!(core.remove_grant(&origin));
    assert!(core.remove_sol_grant(&origin));
    assert!(core.remove_btc_grant(&origin));
    for ticket in messages {
        app.browser_message_signed(MessageSigned {
            ticket,
            result: Ok([1; 65]),
        });
    }
    for ticket in sol_messages {
        app.browser_chain_message_signed(&ChainMessageSigned {
            ticket,
            result: Ok(ChainSignature::Sol([2; 64])),
        });
    }
    app.browser_chain_message_signed(&ChainMessageSigned {
        ticket: btc_message,
        result: Ok(btc_signature()),
    });
    app.browser_broadcast([0x22; 32], BroadcastOutcome::Sent);
    assert_eq!(answers(&frames), vec![Err(ProviderError::Unauthorized); 6]);
    assert!(app.browser.as_ref().unwrap().waiters.is_empty());
    assert!(app.browser.as_ref().unwrap().broadcasts.is_empty());
    // The account hidden: the grant stays for the site's other account, but neither a
    // message nor a transaction hash of the hidden one is answered.
    core.upsert_sol_grant(sol_grant("https://app.example", public()));
    let other = yw_core::evm::address::Address::from_bytes([0x70; 20]);
    core.upsert_grant(
        yw_core::policy::ConnectedSite::new(
            origin.clone(),
            vec![evm_account(), other],
            yw_core::evm::chain::SEPOLIA,
            1,
        )
        .unwrap(),
    );
    let message = reply(&app);
    let message = app.push_sign_waiter(SignWaiter::Message(message, evm_signer()));
    let tx = reply(&app);
    let tx = app.push_sign_waiter(SignWaiter::Tx(tx, evm_signer()));
    app.browser_tx_signed(tx, Ok([0x24; 32]));
    let _ = core.remove_account(&evm_account());
    assert!(
        app.browser_grants()
            .iter()
            .any(|grant| grant.origin == origin && grant.allows(&other))
    );
    app.browser_message_signed(MessageSigned {
        ticket: message,
        result: Ok([1; 65]),
    });
    app.browser_broadcast([0x24; 32], BroadcastOutcome::Sent);
    assert_eq!(answers(&frames), vec![Err(ProviderError::Unauthorized); 2]);
    assert!(core.remove_grant(&origin));
    // Locked (the grants put away): a broadcast hash is answered as before.
    let tx = reply(&app);
    let tx = app.push_sign_waiter(SignWaiter::Tx(tx, evm_signer()));
    app.browser_tx_signed(tx, Ok([0x33; 32]));
    app.mode = crate::app::AppMode::Locked;
    app.browser_broadcast([0x33; 32], BroadcastOutcome::Sent);
    let found = answers(&frames);
    assert!(matches!(found.as_slice(), [Ok(_)]), "{found:?}");
}

/// spec/05 §4.5, spec/10 §9.2 (2026-11-13): an approved `YubiKey` request still waiting for
/// its PIN ends when its site is disconnected (4100) or its page goes away (4001): W11 is
/// gone, nothing is signed, the PIN is never sent, the header band says why. Another site's
/// or another family's disconnect and an app step leave it alone; a grant removed without
/// the hook (the retry gap) is caught at PIN submission; a step past its PIN finishes and its
/// signature is answered 4100 once the site is gone, or as usual while the grant holds.
#[test]
fn a_card_step_waiting_for_its_pin_ends_when_its_site_goes() {
    use crate::app_browser::SignWaiter;
    use crate::app_card::{CardJobKind, T_CARD_SITE_GONE, T_CARD_SITE_REVOKED};
    use crate::events::MessageSigned;
    use yw_core::secret::Zeroizing;
    let mut app = app(true);
    let (events, frames, conn) = recorded(&mut app);
    let origin = BrowserOrigin::parse("https://app.example").unwrap();
    let core = core(&app);
    core.upsert_grant(evm_grant());
    let pin = || Zeroizing::new(b"135790".to_vec());
    let mut n = 0_u8;
    // A YubiKey `personal_sign` approved for a live request: the step waits for its PIN.
    let mut begin = |app: &mut App| {
        n += 1;
        let site = queued_sol_tx(app, &events, conn, n);
        let ticket = app.push_sign_waiter(SignWaiter::Message(site.reply, evm_signer()));
        assert!(
            app.card_begin(
                approved_card_message(),
                CardJobKind::EvmMessage { typed: false },
                Some(ticket),
            )
            .is_ok()
        );
        assert!(job_names(app).contains(&"YkCounters"));
        (app.card_waiting_id().unwrap(), ticket)
    };
    // An app step (no site) is never ended by a disconnect.
    let own = app.push_sign_waiter(SignWaiter::App);
    assert!(
        app.card_begin(
            approved_card_message(),
            CardJobKind::EvmMessage { typed: false },
            Some(own),
        )
        .is_ok()
    );
    let id = app.card_waiting_id().unwrap();
    app.disconnect_site(&origin);
    assert!(app.card_waiting(id));
    app.card_cancel(id);
    core.upsert_grant(evm_grant());
    let _ = job_names(&app);

    // Another origin's disconnect and this origin's Solana disconnect leave it waiting; the
    // EVM disconnect ends it: 4100, nothing signed, the PIN never sent.
    let (id, _) = begin(&mut app);
    app.disconnect_site(&BrowserOrigin::parse("https://other.example").unwrap());
    app.disconnect_chain_site(&origin, Family::Solana);
    assert!(app.card_waiting(id));
    core.upsert_sol_grant(sol_grant("https://app.example", public()));
    assert!(answers(&frames).is_empty());
    app.disconnect_site(&origin);
    assert_eq!(app.card_waiting_id(), None);
    assert!(app.card.step.is_none());
    assert_eq!(answers(&frames), vec![Err(ProviderError::Unauthorized)]);
    assert!(app.browser.as_ref().unwrap().waiters.is_empty());
    assert_eq!(app.info.as_deref(), Some(T_CARD_SITE_REVOKED));
    app.card_submit(id, pin());
    assert!(!job_names(&app).contains(&"SignMessageCard"));
    assert!(answers(&frames).is_empty());

    // The grant gone without the hook (a revoke during a refused PIN's round trip): PIN
    // submission ends the step instead of signing.
    core.upsert_grant(evm_grant());
    let (id, _) = begin(&mut app);
    assert!(core.remove_grant(&origin));
    assert!(app.card_waiting(id));
    app.card_submit(id, pin());
    assert!(app.card.step.is_none());
    assert!(!job_names(&app).contains(&"SignMessageCard"));
    assert_eq!(answers(&frames), vec![Err(ProviderError::Unauthorized)]);

    // The grant holds: the PIN goes to the card and the signature is answered as before.
    core.upsert_grant(evm_grant());
    let (id, ticket) = begin(&mut app);
    app.card_submit(id, pin());
    assert!(job_names(&app).contains(&"SignMessageCard"));
    app.card.step = None;
    app.browser_message_signed(MessageSigned {
        ticket,
        result: Ok([1; 65]),
    });
    let found = answers(&frames);
    assert!(matches!(found.as_slice(), [Ok(_)]), "{found:?}");

    // Past its PIN the card job is not cancelled by a disconnect; its signature is not sent.
    let (id, ticket) = begin(&mut app);
    app.card_submit(id, pin());
    assert!(job_names(&app).contains(&"SignMessageCard"));
    app.disconnect_site(&origin);
    assert!(app.card.step.as_ref().is_some_and(|step| step.id == id));
    app.card.step = None;
    app.browser_message_signed(MessageSigned {
        ticket,
        result: Ok([1; 65]),
    });
    assert_eq!(answers(&frames), vec![Err(ProviderError::Unauthorized)]);

    // The page goes away (the connection closes, the dispatcher cancels the request): the
    // step waiting for its PIN ends as cancelled (4001, the answer has nowhere to go).
    core.upsert_grant(evm_grant());
    let (id, _) = begin(&mut app);
    core.close_connection(conn);
    for event in events.drain() {
        if let crate::events::UiEvent::Dapp(event) = event {
            app.on_dapp_event(event);
        }
    }
    assert!(!app.card_waiting(id));
    assert!(app.card.step.is_none());
    assert!(app.browser.as_ref().unwrap().waiters.is_empty());
    assert_eq!(app.info.as_deref(), Some(T_CARD_SITE_GONE));
    app.card_submit(id, pin());
    assert!(!job_names(&app).contains(&"SignMessageCard"));
}

/// spec/05 §4.5, spec/10 §9.2 (2026-11-13), per card step kind and per trigger: an EVM
/// transaction waiting for its PIN ends on the dApp's own `wallet_revokePermissions` (4100,
/// its send slot released so the account can send again, no `SignEvmCard`); an EVM message
/// whose account is hidden ends although the grant stays for another account; Solana
/// message and sign-in steps end on `disconnect_chain_site`, on the dApp's `sol_disconnect`
/// and on the account being hidden; a Bitcoin message step on the dApp's `btc_disconnect`
/// and on its address leaving the wallet; a Solana dApp send on a Solana disconnect (no
/// pre-sign entry kept). Each step outlives another family's disconnect of the same origin.
#[test]
#[expect(clippy::too_many_lines, reason = "one case per card kind and trigger")]
fn each_card_step_kind_ends_on_its_own_familys_revoke() {
    use crate::app_browser::SignWaiter;
    use crate::app_card::{CardJobKind, T_CARD_SITE_REVOKED};
    use crate::browser::{DappEvent, GrantChange};
    let mut app = app(true);
    let (events, frames, conn) = recorded(&mut app);
    let origin = BrowserOrigin::parse("https://app.example").unwrap();
    let btc_address = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
    let core = core(&app);
    let btc_grant = || yw_core::policy::BtcGrant {
        origin: origin.clone(),
        network: yw_core::btc::BtcNetwork::Mainnet,
        addresses: vec![BtcGrantAddress {
            purpose: BtcPurpose::Payment,
            address: btc_address.to_owned(),
            pubkey: BtcPubKey::Compressed([2; 33]),
            script_type: ScriptType::P2wpkh,
        }],
        granted_at_unix_ms: 1,
    };
    let mut n = 0_u8;
    let mut reply = |app: &App| {
        n += 1;
        queued_sol_tx(app, &events, conn, n).reply
    };
    // The step's held approval: the site check reads only the waiter and the kind, so the
    // chain-message and dApp-send steps hold the EVM card message as a stand-in.
    let begin = |app: &mut App, waiter: SignWaiter, kind: CardJobKind| {
        let ticket = app.push_sign_waiter(waiter);
        assert!(
            app.card_begin(approved_card_message(), kind, Some(ticket))
                .is_ok()
        );
        let _ = job_names(app);
        (app.card_waiting_id().unwrap(), ticket)
    };
    let ended = |app: &mut App, id: u64| {
        assert!(!app.card_waiting(id));
        assert!(app.card.step.is_none());
        assert_eq!(app.info.as_deref(), Some(T_CARD_SITE_REVOKED));
        assert!(app.browser.as_ref().unwrap().waiters.is_empty());
        let jobs = job_names(app);
        assert!(
            !jobs.iter().any(|job| job.starts_with("Sign")),
            "nothing goes to the card: {jobs:?}"
        );
        app.info = None;
    };

    // EVM transaction: the slot preflight took and the signing job's entry are released.
    core.upsert_grant(evm_grant());
    let tx_reply = reply(&app);
    let ticket = app.push_sign_waiter(SignWaiter::Tx(tx_reply, evm_signer()));
    app.evm
        .slots
        .push((yw_core::evm::chain::SEPOLIA, evm_account()));
    app.dispatch_evm_sign(ticket, approved_card_tx(), card_tx_info(), false);
    let id = app.card_waiting_id().unwrap();
    assert!(app.evm.signing.contains_key(&ticket));
    let _ = job_names(&app);
    app.disconnect_chain_site(&origin, Family::Solana);
    assert!(app.card_waiting(id));
    assert!(core.remove_grant(&origin));
    app.on_dapp_event(DappEvent::GrantChanged {
        origin: origin.clone(),
        change: GrantChange::Revoked,
    });
    ended(&mut app, id);
    assert_eq!(answers(&frames), vec![Err(ProviderError::Unauthorized)]);
    assert!(app.evm.signing.is_empty());
    assert!(app.evm.slots.is_empty());

    // EVM message, account hidden: the grant stays for the other account.
    let other = yw_core::evm::address::Address::from_bytes([0x70; 20]);
    core.upsert_grant(
        yw_core::policy::ConnectedSite::new(
            origin.clone(),
            vec![evm_account(), other],
            yw_core::evm::chain::SEPOLIA,
            1,
        )
        .unwrap(),
    );
    let message = reply(&app);
    let (id, _) = begin(
        &mut app,
        SignWaiter::Message(message, evm_signer()),
        CardJobKind::EvmMessage { typed: true },
    );
    app.account_removed_from_sites(&evm_account());
    assert!(
        app.browser_grants()
            .iter()
            .any(|grant| grant.origin == origin && grant.allows(&other))
    );
    ended(&mut app, id);
    assert_eq!(answers(&frames), vec![Err(ProviderError::Unauthorized)]);

    // Solana message and sign-in: S13, the dApp's `sol_disconnect`, the account hidden.
    let sol = |sign_in: bool| ChainAnswer::Sol {
        public: public(),
        origin: origin.clone(),
        message: b"hi".to_vec(),
        sign_in,
    };
    for (sign_in, trigger) in [(false, 0), (true, 1), (true, 2)] {
        core.upsert_sol_grant(sol_grant("https://app.example", public()));
        let message = reply(&app);
        let (id, _) = begin(
            &mut app,
            SignWaiter::Chain(message, Box::new(sol(sign_in))),
            CardJobKind::ChainMessage,
        );
        app.disconnect_site(&origin);
        app.disconnect_chain_site(&origin, Family::Bitcoin);
        assert!(app.card_waiting(id));
        match trigger {
            0 => app.disconnect_chain_site(&origin, Family::Solana),
            1 => {
                assert!(core.remove_sol_grant(&origin));
                app.on_dapp_event(DappEvent::GrantChanged {
                    origin: origin.clone(),
                    change: GrantChange::SolRevoked,
                });
            }
            _ => {
                app.meta.as_mut().unwrap().sol_accounts[0].hidden = true;
                app.sol_account_removed_from_sites(&public());
                app.meta.as_mut().unwrap().sol_accounts[0].hidden = false;
            }
        }
        ended(&mut app, id);
        assert_eq!(answers(&frames), vec![Err(ProviderError::Unauthorized)]);
    }

    // Bitcoin message: the dApp's `btc_disconnect`, the address leaving the wallet.
    let btc = || ChainAnswer::Btc {
        address: btc_address.to_owned(),
        origin: origin.clone(),
        protocol: BtcMessageProtocol::Ecdsa,
    };
    for removed in [false, true] {
        assert!(core.upsert_btc_grant(btc_grant()));
        let message = reply(&app);
        let (id, _) = begin(
            &mut app,
            SignWaiter::Chain(message, Box::new(btc())),
            CardJobKind::ChainMessage,
        );
        app.disconnect_site(&origin);
        app.disconnect_chain_site(&origin, Family::Solana);
        assert!(app.card_waiting(id));
        if removed {
            app.btc_addresses_removed_from_sites(&[btc_address.to_owned()]);
        } else {
            assert!(core.remove_btc_grant(&origin));
            app.on_dapp_event(DappEvent::GrantChanged {
                origin: origin.clone(),
                change: GrantChange::BtcRevoked,
            });
        }
        ended(&mut app, id);
        assert_eq!(answers(&frames), vec![Err(ProviderError::Unauthorized)]);
    }

    // Solana dApp send (it used to keep W11 open): a Solana disconnect ends it.
    core.upsert_sol_grant(sol_grant("https://app.example", public()));
    let send = reply(&app);
    let (id, ticket) = begin(
        &mut app,
        SignWaiter::Chain(
            send,
            Box::new(ChainAnswer::SolTx {
                public: public(),
                origin: origin.clone(),
                batch: false,
                send: true,
            }),
        ),
        CardJobKind::SolDappSend {
            cluster: yw_core::sol::SolCluster::Devnet,
        },
    );
    app.disconnect_site(&origin);
    assert!(app.card_waiting(id));
    app.disconnect_chain_site(&origin, Family::Solana);
    ended(&mut app, id);
    assert_eq!(answers(&frames), vec![Err(ProviderError::Unauthorized)]);
    assert!(
        !app.sol
            .dapp_presign
            .values()
            .any(|pending| pending.ticket == ticket)
    );
}

/// spec/10 §9.2 (2026-11-13): a PIN refused by the card after the site was disconnected —
/// the grant gone during the card's round trip, no hook ran — ends the step instead of
/// opening W11 again (4100, the send slot released), and the job's trailing failure shows
/// no card-error band beside the site notice (it used to reach `on_signed`).
#[test]
fn a_refused_pin_after_the_site_went_ends_the_step_quietly() {
    use crate::app::Purpose;
    use crate::app_browser::SignWaiter;
    use crate::app_card::T_CARD_SITE_REVOKED;
    use crate::events::{EvmSigned, KeyJob, KeyOutcome, KeyResult, SignFailure};
    use crate::yubikey::CardJobError;
    use yw_core::yubikey::CardError;
    let mut app = app(true);
    let (events, frames, conn) = recorded(&mut app);
    let origin = BrowserOrigin::parse("https://app.example").unwrap();
    let core = core(&app);
    core.upsert_grant(evm_grant());
    let site = queued_sol_tx(&app, &events, conn, 1);
    let ticket = app.push_sign_waiter(SignWaiter::Tx(site.reply, evm_signer()));
    app.evm
        .slots
        .push((yw_core::evm::chain::SEPOLIA, evm_account()));
    app.dispatch_evm_sign(ticket, approved_card_tx(), card_tx_info(), false);
    let id = app.card_waiting_id().unwrap();
    let _ = job_names(&app);
    app.card_submit(id, yw_core::secret::Zeroizing::new(b"135790".to_vec()));
    let approved = std::iter::from_fn(|| {
        (!app.key_queue.is_empty())
            .then(|| app.key_queue.pop())
            .flatten()
    })
    .find_map(|(_, job)| match job {
        KeyJob::SignEvmCard { approved, .. } => Some(approved),
        _ => None,
    })
    .expect("SignEvmCard");
    // The grant goes while the card checks the PIN (no hook: the step is past its PIN).
    assert!(core.remove_grant(&origin));
    let banners = app.banners.len();
    let wrong = CardJobError::Card(CardError::WrongPin { retries: 2 });
    let epoch = app.lock_epoch;
    app.on_key_result(KeyResult {
        epoch,
        outcome: KeyOutcome::CardUnused(approved, wrong),
    });
    assert_ne!(app.secret_purpose(), Some(Purpose::CardSign(id)));
    assert!(app.card.step.is_none());
    assert_eq!(answers(&frames), vec![Err(ProviderError::Unauthorized)]);
    assert!(app.evm.signing.is_empty());
    assert!(app.evm.slots.is_empty());
    assert_eq!(app.info.as_deref(), Some(T_CARD_SITE_REVOKED));
    app.on_key_result(KeyResult {
        epoch,
        outcome: KeyOutcome::SignedEvm(EvmSigned {
            ticket,
            result: Err(SignFailure::Card(wrong)),
        }),
    });
    assert_eq!(app.banners.len(), banners, "no card-error band");
    assert_eq!(app.info.as_deref(), Some(T_CARD_SITE_REVOKED));
    assert!(answers(&frames).is_empty());
    assert!(job_names(&app).is_empty());
}

/// Two frozen tests of this file (`approved_requests_go_to_the_key_worker_or_the_presign_check`,
/// `signatures_and_hashes_answer_only_while_the_grant_holds`; `frozen-tests.txt` never changes)
/// call a wallet fn on an `App` with an argument that reads the same `App`
/// (`app.push_sign_waiter(SignWaiter::Tx(reply(&app), …))`). Since S4c W14c-2 (2026-11-22) those
/// fns are `impl Wallet`, reached through `DerefMut`, and a call through an overloaded deref
/// gets no two-phase borrow, so that form no longer compiles. These private forwards, visible
/// only in this test module, take the `App` itself as before (autoref, two-phase borrow) and
/// hand the call to the wallet unchanged. Test builds only; no production path names them.
impl App {
    fn push_sign_waiter(
        &mut self,
        waiter: crate::app_browser::SignWaiter,
    ) -> crate::events::SignTicket {
        self.wallet.push_sign_waiter(waiter)
    }

    fn sol_dapp_consumed(&mut self, approved: yw_core::approval::Approved, site: &SiteRequest) {
        self.wallet.sol_dapp_consumed(approved, site);
    }
}
