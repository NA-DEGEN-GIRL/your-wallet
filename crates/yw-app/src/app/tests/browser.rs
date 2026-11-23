//! The tests of `app_browser.rs` that build an `App` (2026-11-21, S4 W0, spec/09 §2.1),
//! moved unchanged from its inline `mod tests` (which keeps the tests that build no `App`).
//! It was a `#[cfg(test)] #[path]` child of `crate::app_browser`, not of `app::tests`, to keep the
//! access of the inline module, so no production item of that file was widened. 2026-11-22 (S4d
//! E0c, spec/09 §2.1): a child of `app::tests` (that file moves to yw-engine at S4d E1 and these
//! tests need `App`); it reaches nothing private there, so nothing was widened.

// 2026-11-23 (S4d E1): the wallet's crate-private steps, buffers and flow state as the tests reach
// them across the crate boundary (`yw_engine::testkit`).
use std::collections::HashMap;
use std::sync::Arc;
use yw_engine::testkit::WalletTestExt;

use crate::app::{App, Paths};
use yw_engine::apikeys::ApiKeys;
use yw_engine::browser::Reply;
use yw_engine::browser::envelope::{Correlation, Id16, Id32};
use yw_engine::events::{EventQueue, MessageSignFailure, MessageSigned};
use yw_engine::settings::Settings;
use yw_engine::wallet::app_browser::{BrowserUi, GrantWrite, SignWaiter};

fn app() -> App {
    let dir = std::env::temp_dir().join(format!("yw-app-tickets-{}", std::process::id()));
    let mut app = App::new(
        Paths {
            data: dir.clone(),
            logs: dir.join("logs"),
        },
        true,
        Settings::default(),
        ApiKeys::default(),
    );
    let events = Arc::new(EventQueue::new(Box::new(|| {})));
    let core = yw_engine::browser::BrowserCore::new(
        "abcdefghijklmnopabcdefghijklmnop",
        events as Arc<dyn yw_engine::browser::DappSink>,
        Arc::clone(&app.clock),
    );
    app.browser = Some(BrowserUi {
        core,
        reads: Arc::new(yw_engine::browser::read::ReadContext::new(None)),
        connections: 0,
        waiters: HashMap::new(),
        broadcasts: HashMap::new(),
        sol_broadcasts: HashMap::new(),
        dapp_unlock: false,
        unlocked: false,
        locking: false,
        grant_write: GrantWrite::default(),
        site_rows: yw_engine::wallet::app_browser::SiteRows::default(),
    });
    app
}

fn reply(n: u8) -> Reply {
    Reply {
        conn: 1,
        correlation: Correlation {
            session_id: Id32([1; 32]),
            sequence: u64::from(n),
            activation_nonce: Id32([2; 32]),
            request_id: Id16([n; 16]),
        },
    }
}

fn broadcast_reply(app: &App, hash: [u8; 32]) -> Option<Reply> {
    app.browser
        .as_ref()
        .and_then(|browser| browser.broadcasts.get(&hash).map(|(reply, _)| *reply))
}

/// `account` signing for `https://app.example`.
fn signer(account: [u8; 20]) -> yw_engine::wallet::app_browser::SiteSigner {
    yw_engine::wallet::app_browser::SiteSigner {
        origin: yw_core::policy::BrowserOrigin::parse("https://app.example").unwrap(),
        account: yw_core::evm::address::Address::from_bytes(account),
    }
}

/// C2: signing results are matched to their waiters by ticket, so a result for a later job
/// (or a dropped one) never answers another dApp request — a Solana dApp transaction's
/// waiter (`ChainAnswer::SolTx`) included.
#[test]
fn signing_results_answer_their_own_ticket() {
    let mut app = app();
    let first = app.push_sign_waiter(SignWaiter::Tx(reply(1), signer([1; 20])));
    let message = app.push_sign_waiter(SignWaiter::Message(reply(2), signer([1; 20])));
    let sol = app.push_sign_waiter(SignWaiter::Chain(
        reply(4),
        Box::new(crate::app_chain_sites::ChainAnswer::SolTx {
            public: [1; 32],
            origin: yw_core::policy::BrowserOrigin::parse("https://app.example").unwrap(),
            batch: false,
            send: false,
        }),
    ));
    let second = app.push_sign_waiter(SignWaiter::Tx(reply(3), signer([1; 20])));
    let own = app.push_sign_waiter(SignWaiter::App);
    assert!(first != message && message != sol && sol != second && second != own);
    // Out of queue order: the second transaction finishes first.
    app.browser_tx_signed(second, Ok([0x33; 32]));
    assert_eq!(broadcast_reply(&app, [0x33; 32]), Some(reply(3)));
    // The message result only takes the message waiter.
    app.browser_message_signed(MessageSigned {
        ticket: message,
        result: Err(MessageSignFailure::Locked),
    });
    app.browser_tx_signed(first, Ok([0x11; 32]));
    assert_eq!(broadcast_reply(&app, [0x11; 32]), Some(reply(1)));
    // The app send's result answers nobody; an unknown ticket is ignored.
    app.browser_tx_signed(own, Ok([0x44; 32]));
    app.browser_tx_signed(yw_engine::events::SignTicket(999), Ok([0x55; 32]));
    assert_eq!(broadcast_reply(&app, [0x44; 32]), None);
    assert_eq!(broadcast_reply(&app, [0x55; 32]), None);
    // The Solana transactions' waiter is still there; its own result takes it.
    assert!(app.browser.as_ref().is_some_and(|browser| {
        browser.waiters.len() == 1 && browser.waiters.contains_key(&sol)
    }));
    app.browser_chain_message_signed(&yw_engine::events::ChainMessageSigned {
        ticket: sol,
        result: Ok(yw_engine::events::ChainSignature::SolTxs(vec![vec![0xab]])),
    });
    assert!(
        app.browser
            .as_ref()
            .is_some_and(|browser| browser.waiters.is_empty())
    );
}

fn site(n: u8, kind: yw_engine::browser::SiteKind) -> yw_engine::browser::SiteRequest {
    let method = match kind {
        yw_engine::browser::SiteKind::RequestAccounts => yw_core::policy::Method::RequestAccounts,
        yw_engine::browser::SiteKind::Revoke => yw_core::policy::Method::RevokePermissions,
        _ => yw_core::policy::Method::PersonalSign,
    };
    yw_engine::browser::SiteRequest {
        reply: reply(n),
        origin: yw_core::policy::BrowserOrigin::parse("https://app.example").unwrap(),
        chain_id: yw_core::evm::chain::SEPOLIA,
        deadline_ms: u64::MAX,
        method,
        kind,
        compat_mode: None,
    }
}

fn sign_kind() -> yw_engine::browser::SiteKind {
    yw_engine::browser::SiteKind::PersonalSign {
        account: yw_core::evm::address::parse_address("0x9858effd232b4033e47d90003d41ec34ecaeda94")
            .unwrap(),
        message: b"hi".to_vec(),
    }
}

/// A `sol_signTransaction` request of key `[1; 32]` (an empty transaction list: the
/// passphrase check comes before any other).
fn sol_tx_kind() -> yw_engine::browser::SiteKind {
    yw_engine::browser::SiteKind::SolTx {
        public: [1; 32],
        cluster: yw_core::sol::SolCluster::Devnet,
        txs: Vec::new(),
        mode: yw_core::sol::dapp::SolTxMode::SignOnly,
        batch: false,
        options: yw_core::sol::dapp::SolSendOptions::default(),
    }
}

/// spec/02 §7.5: while `Wallet::passphrase_unverified` the dispatcher view refuses connect and
/// signing (4100 `PassphraseUnverified`; Solana dApp transactions included), a request that
/// slipped through is answered without a queue entry, and site requests queued while locked
/// end `PassphraseUnverified` once the session turns out unverified. A verified session is
/// unaffected.
#[test]
fn unverified_passphrase_refuses_dapp_connect_and_signing() {
    use yw_engine::approval::QueueOutcome;
    use yw_engine::browser::{DappEvent, SiteKind, VaultView};
    use yw_engine::wallet::AppMode;

    let mut app = app();
    app.meta = Some(yw_engine::meta::Meta::default());
    app.mode = AppMode::Unlocked {
        alt_passphrase: false,
    };
    assert_eq!(app.vault_view(), VaultView::Unlocked);
    app.mode = AppMode::Unlocked {
        alt_passphrase: true,
    };
    assert!(app.passphrase_unverified());
    assert_eq!(app.vault_view(), VaultView::PassphraseUnverified);
    app.sync_browser();
    let core = Arc::clone(&app.browser.as_ref().unwrap().core);
    assert_eq!(core.wallet().vault, VaultView::PassphraseUnverified);
    assert!(core.grants().is_empty());
    // Preflight of queued items: connect and signing refused, revoke still answered.
    for kind in [
        SiteKind::RequestAccounts,
        SiteKind::RequestPermissions,
        sign_kind(),
        sol_tx_kind(),
    ] {
        assert_eq!(
            app.site_preflight(&site(1, kind)),
            Some(QueueOutcome::PassphraseUnverified)
        );
    }
    assert_eq!(
        app.site_preflight(&site(1, SiteKind::Revoke)),
        Some(QueueOutcome::Approved)
    );
    // A request delivered with a stale view is answered at once, never queued.
    app.on_dapp_event(DappEvent::Request(Box::new(site(2, sign_kind()))));
    app.on_dapp_event(DappEvent::Request(Box::new(site(
        3,
        SiteKind::RequestAccounts,
    ))));
    app.on_dapp_event(DappEvent::Request(Box::new(site(7, sol_tx_kind()))));
    assert!(app.evm.queue.is_empty());
    // Queued while locked, then unlocked with the unverified passphrase: finished, no window.
    app.mode = AppMode::Locked;
    app.sync_browser();
    app.on_dapp_event(DappEvent::Request(Box::new(site(4, sign_kind()))));
    app.on_dapp_event(DappEvent::Request(Box::new(site(
        5,
        SiteKind::RequestAccounts,
    ))));
    app.on_dapp_event(DappEvent::Request(Box::new(site(8, sol_tx_kind()))));
    assert_eq!(app.evm.queue.len(), 3);
    app.mode = AppMode::Unlocked {
        alt_passphrase: true,
    };
    // The refresh after the unlock (meta loaded) drains the queue: no window opens.
    app.sync_browser();
    assert!(app.evm.queue.is_empty());
    assert!(app.evm.approval.is_none());
    // The same queued request in a verified session reaches its preflight checks normally.
    app.mode = AppMode::Unlocked {
        alt_passphrase: false,
    };
    assert_eq!(
        app.site_preflight(&site(6, SiteKind::RequestAccounts)),
        None
    );
}

const ACCOUNT_A: &str = "0x9858effd232b4033e47d90003d41ec34ecaeda94";
const ACCOUNT_B: &str = "0xf278cf59f82edcf871d630f28ecc8056f25c1cdb";

fn addr(text: &str) -> yw_core::evm::address::Address {
    yw_core::evm::address::parse_address(text).unwrap()
}

/// `app()` unlocked with EVM accounts A (index 0) and B (index 1, hidden when `b_hidden`).
fn accounts_app(b_hidden: bool) -> App {
    let mut app = app();
    app.mode = yw_engine::wallet::AppMode::Unlocked {
        alt_passphrase: false,
    };
    let account = |index: u32, address: &str, hidden: bool| yw_engine::meta::Account {
        index,
        label: format!("계정 {}", index + 1),
        address: address.to_owned(),
        hidden,
    };
    app.meta = Some(yw_engine::meta::Meta {
        evm_accounts: vec![
            account(0, ACCOUNT_A, false),
            account(1, ACCOUNT_B, b_hidden),
        ],
        ..yw_engine::meta::Meta::default()
    });
    app
}

/// Security review L4(a): an account hidden while the connect window was open is not
/// granted (4100, nothing stored); visible accounts are, on the chain passed (L4(c): the
/// shown one).
#[test]
fn connect_approval_rechecks_the_accounts_and_stores_the_shown_chain() {
    use yw_engine::browser::SiteKind;
    let mut app = accounts_app(true);
    let core = Arc::clone(&app.browser.as_ref().unwrap().core);
    let request = site(1, SiteKind::RequestAccounts);
    app.connect_approved(
        &request,
        vec![addr(ACCOUNT_A), addr(ACCOUNT_B)],
        yw_core::evm::chain::SEPOLIA,
    );
    assert!(
        core.grants().is_empty(),
        "hidden B: refused, nothing stored"
    );
    app.connect_approved(
        &request,
        vec![addr("0x000000000000000000000000000000000000dead")],
        yw_core::evm::chain::SEPOLIA,
    );
    assert!(core.grants().is_empty(), "not an account of this wallet");
    app.connect_approved(&request, vec![addr(ACCOUNT_A)], 1);
    let grants = core.grants();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].accounts, vec![addr(ACCOUNT_A)]);
    assert_eq!(grants[0].chain_id, 1);
}

/// Security review L4(c): the connect window shows the origin's chain of now (not the
/// request-time chain), the same value the approval then stores.
#[test]
fn connect_window_shows_the_origin_chain_of_now() {
    use yw_engine::browser::SiteKind;
    let mut app = accounts_app(false);
    app.sync_browser();
    let core = Arc::clone(&app.browser.as_ref().unwrap().core);
    let request = site(1, SiteKind::RequestPermissions);
    assert_eq!(request.chain_id, yw_core::evm::chain::SEPOLIA);
    // The origin's grant moved to mainnet after the request was queued.
    core.upsert_grant(
        yw_core::policy::ConnectedSite::new(
            request.origin.clone(),
            vec![addr(ACCOUNT_A)],
            yw_core::evm::chain::ETHEREUM_MAINNET,
            0,
        )
        .unwrap(),
    );
    let state = app.connect_state(&request);
    assert_eq!(state.chain_id, yw_core::evm::chain::ETHEREUM_MAINNET);
    assert_eq!(
        Some(state.chain_name),
        app.settings.evm_chain_name_in(
            yw_core::lang::Lang::Ko,
            yw_core::evm::chain::ETHEREUM_MAINNET
        )
    );
}

/// Security review L4(b): hiding or removing an account ends the dApp signing requests for
/// it (4100 `Revoked`); other accounts' requests stay queued.
#[test]
fn removing_an_account_revokes_its_waiting_signing_requests() {
    use yw_engine::browser::{DappEvent, SiteKind};
    let mut app = accounts_app(false);
    // Queued while locked: they wait.
    app.mode = yw_engine::wallet::AppMode::Locked;
    app.sync_browser();
    let sign = |account: &str| SiteKind::PersonalSign {
        account: addr(account),
        message: b"hi".to_vec(),
    };
    app.on_dapp_event(DappEvent::Request(Box::new(site(1, sign(ACCOUNT_B)))));
    app.on_dapp_event(DappEvent::Request(Box::new(site(2, sign(ACCOUNT_A)))));
    app.on_dapp_event(DappEvent::Request(Box::new(site(3, sign(ACCOUNT_B)))));
    assert_eq!(app.evm.queue.len(), 3);
    app.account_removed_from_sites(&addr(ACCOUNT_B));
    assert_eq!(app.evm.queue.len(), 1);
    assert!(app.evm.queue.waiting_payloads().all(|item| matches!(
        item,
        yw_engine::wallet::app_evm::QueuedItem::Site(site)
            if matches!(&site.kind, SiteKind::PersonalSign { account, .. } if *account == addr(ACCOUNT_A))
    )));
}

/// spec/13 §5.2: a `WalletConnect` request that ends unanswered takes its session's waiting
/// ones along (requests lined up in advance cannot follow each other on screen), and a lock
/// ends every waiting `WalletConnect` request instead of keeping it for the password window,
/// which only the extension's requests open. Other origins' requests are untouched.
#[test]
fn walletconnect_requests_end_with_their_window_and_at_lock() {
    use yw_engine::approval::{QueueOutcome, QueueSource};
    use yw_engine::wallet::app_evm::QueuedItem;
    let mut app = accounts_app(false);
    // The unlock merge (it moves the queue) is behind us, as in the app.
    app.sync_browser();
    let wc = |n: u8, session: u8| {
        let mut request = site(n, sign_kind());
        request.origin = yw_engine::walletconnect::session_origin(&[session; 32]).unwrap();
        request
    };
    let enqueue = |app: &mut App, request: yw_engine::browser::SiteRequest| {
        let source = QueueSource::Site {
            origin: request.origin.as_str().to_owned(),
            deadline_ms: u64::MAX,
        };
        app.evm
            .queue
            .enqueue(source, QueuedItem::Site(Box::new(request)))
            .unwrap();
    };
    let is_wc = |item: &QueuedItem| {
        matches!(item, QueuedItem::Site(site)
            if yw_engine::walletconnect::is_session_origin(&site.origin))
    };
    for request in [wc(1, 1), wc(2, 1), site(3, sign_kind()), wc(4, 2), wc(5, 1)] {
        enqueue(&mut app, request);
    }
    // Session 1's shown request expires unanswered: its two waiting ones end with it.
    let mut finished = Vec::new();
    assert!(app.evm.queue.show_next(0, &mut finished).is_some());
    let (item, outcome) = app.evm.queue.finish_shown(QueueOutcome::Expired).unwrap();
    app.approval_finished(&item.payload, outcome);
    assert_eq!(
        app.evm.queue.len(),
        2,
        "the extension's and session 2's remain"
    );
    // Lock: the waiting WalletConnect request ends; the extension's waits for the unlock.
    app.evm_lock();
    app.mode = yw_engine::wallet::AppMode::Locked;
    assert_eq!(app.evm.queue.len(), 1);
    assert!(app.evm.queue.waiting_payloads().all(|item| !is_wc(item)));
    // The reload after the lock: the password window for the extension's request only.
    app.browser_vault_loaded();
    assert!(app.browser.as_ref().is_some_and(|b| b.dapp_unlock));
    app.browser.as_mut().unwrap().dapp_unlock = false;
    let _ = app
        .evm
        .queue
        .drain_waiting_matching(|_| true, QueueOutcome::Revoked);
    enqueue(&mut app, wc(6, 3));
    app.browser_vault_loaded();
    assert!(app.browser.as_ref().is_some_and(|b| !b.dapp_unlock));
}

/// spec/05 §4.1, spec/02 §8.4: removing an imported EVM key or an added recovery phrase
/// takes an address out of the grants only when no other visible account has it (the same
/// key may be imported beside a derived or added-phrase account).
#[test]
fn a_removed_key_or_phrase_keeps_the_grants_of_addresses_still_shown() {
    use yw_core::vault::RecordId;
    use yw_engine::meta::{Account, MnemonicEntry, RawAccount};
    use yw_engine::workers::key::mnemonics::MnOutcome;
    const ACCOUNT_C: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
    let phrase = [7_u8; 16];
    let mut app = accounts_app(false);
    let raw = |n: u8, address: &str| RawAccount {
        record_id: [n; 16],
        label: format!("가져온 계정 {n}"),
        address: address.to_owned(),
    };
    let meta = app.meta.as_mut().unwrap();
    meta.evm_raw_accounts = vec![raw(1, ACCOUNT_B), raw(2, ACCOUNT_C)];
    meta.mnemonics = vec![MnemonicEntry {
        record_id: phrase,
        label: "복구 단어 2".to_owned(),
        evm: vec![Account {
            index: 0,
            label: "계정 1".to_owned(),
            address: ACCOUNT_C.to_owned(),
            hidden: false,
        }],
    }];
    app.sync_browser();
    let core = Arc::clone(&app.browser.as_ref().unwrap().core);
    core.upsert_grant(
        yw_core::policy::ConnectedSite::new(
            yw_core::policy::BrowserOrigin::parse("https://app.example").unwrap(),
            vec![addr(ACCOUNT_A), addr(ACCOUNT_B), addr(ACCOUNT_C)],
            yw_core::evm::chain::SEPOLIA,
            0,
        )
        .unwrap(),
    );
    let granted = || {
        core.grants()
            .first()
            .map(|site| site.accounts.clone())
            .unwrap_or_default()
    };
    // B stays derived account 2 and C the added phrase's account: both stay connected.
    app.on_evm_raw_key_removed(RecordId::from_bytes([1; 16]));
    app.on_evm_raw_key_removed(RecordId::from_bytes([2; 16]));
    assert!(app.meta.as_ref().unwrap().evm_raw_accounts.is_empty());
    assert_eq!(
        granted(),
        vec![addr(ACCOUNT_A), addr(ACCOUNT_B), addr(ACCOUNT_C)]
    );
    // The phrase was C's last source: C leaves.
    app.on_mn_outcome(MnOutcome::Removed(Ok(RecordId::from_bytes(phrase))), 0);
    assert_eq!(granted(), vec![addr(ACCOUNT_A), addr(ACCOUNT_B)]);
}

/// spec/05 §4.1, §4.9, spec/10 §13: a meta reload (`KeyOutcome::Meta`) whose reconcile
/// dropped a `YubiKey`'s accounts (its record removed, the card cleared or re-slotted) takes
/// them out of the dispatcher's grants and meta — the same card enrolled again (the next
/// reload) does not reconnect — while an address another visible account has (derived B,
/// enrolled from the same words) stays.
#[test]
fn a_reload_without_a_cards_accounts_drops_them_from_the_grants() {
    use yw_engine::browser::grants::{sites_from_values, sol_sites_from_values};
    use yw_engine::events::{KeyOutcome, KeyResult, MetaLoaded};
    const ACCOUNT_YK: &str = "0x6fac4d18c912343bf86fa7049364dd4e424ab9c0";
    const SOL_YK: &str = "FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z";
    let card = |index: u32, address: &str| yw_engine::meta::Account {
        index,
        label: format!("YubiKey 계정 {}", index + 1),
        address: address.to_owned(),
        hidden: false,
    };
    let mut app = accounts_app(false);
    let enrolled = |meta: &mut yw_engine::meta::Meta| {
        meta.hw_accounts.evm = vec![card(0, ACCOUNT_YK), card(1, ACCOUNT_B)];
        meta.hw_accounts.sol = vec![card(0, SOL_YK)];
    };
    let reload = |app: &mut App, meta: yw_engine::meta::Meta| {
        app.on_key_result(KeyResult {
            epoch: app.lock_epoch,
            outcome: KeyOutcome::Meta(Ok(MetaLoaded {
                meta: Box::new(meta),
                mismatch: false,
                prefs_reset: false,
                has_mnemonic: true,
                zec_keys: Vec::new(),
                mnemonics: Vec::new(),
            })),
        });
    };
    enrolled(app.meta.as_mut().unwrap());
    app.sync_browser();
    let core = Arc::clone(&app.browser.as_ref().unwrap().core);
    let origin = yw_core::policy::BrowserOrigin::parse("https://app.example").unwrap();
    core.upsert_grant(
        yw_core::policy::ConnectedSite::new(
            origin.clone(),
            vec![addr(ACCOUNT_A), addr(ACCOUNT_YK), addr(ACCOUNT_B)],
            yw_core::evm::chain::SEPOLIA,
            0,
        )
        .unwrap(),
    );
    let public = yw_core::codec::base58::base58_decode_32(SOL_YK).unwrap();
    assert!(core.upsert_sol_grant(yw_core::policy::SolGrant {
        origin,
        public,
        granted_at_unix_ms: 0,
    }));
    assert!(app.hardware_site_accounts().is_some());
    // The reloaded document: no card holds the keys any more.
    let mut gone = app.meta.clone().unwrap();
    gone.hw_accounts.evm.clear();
    gone.hw_accounts.sol.clear();
    reload(&mut app, gone);
    let expected = vec![addr(ACCOUNT_A), addr(ACCOUNT_B)];
    assert_eq!(core.grants()[0].accounts, expected);
    assert!(core.sol_grants().is_empty());
    let meta = app.meta.clone().unwrap();
    assert_eq!(
        sites_from_values(&meta.connected_sites)[0].accounts,
        expected
    );
    assert!(sol_sites_from_values(&meta.chain_sites.sol).is_empty());
    // The same card enrolled again (the next reload): nothing comes back.
    let mut again = meta;
    enrolled(&mut again);
    reload(&mut app, again);
    assert_eq!(core.grants()[0].accounts, expected);
    assert!(core.sol_grants().is_empty());
}

/// spec/02 §8.6, spec/05 §4.5, §4.9: an account of an added phrase whose backup quiz has not
/// passed can receive but not sign. Its connect-window row says so and is not a new site's
/// default; a signing request for it ends 4100 `BackupUnconfirmed` before any window (the
/// vault would refuse the key only after the approval) with one notice in the app; once the
/// quiz passes it reaches its window.
#[test]
fn an_unconfirmed_phrase_account_is_tagged_and_refused_before_the_window() {
    use yw_core::vault::{MnemonicInfo, RecordId};
    use yw_engine::approval::QueueOutcome;
    use yw_engine::browser::SiteKind;
    use yw_engine::meta::{Account, EvmAccountPref, MnemonicEntry};
    const ACCOUNT_C: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
    let phrase = RecordId::from_bytes([7; 16]);
    let mut app = accounts_app(false);
    let meta = app.meta.as_mut().unwrap();
    meta.mnemonics = vec![MnemonicEntry {
        record_id: *phrase.as_bytes(),
        label: "복구 단어 2".to_owned(),
        evm: vec![Account {
            index: 0,
            label: "계정 1".to_owned(),
            address: ACCOUNT_C.to_owned(),
            hidden: false,
        }],
    }];
    // The main screen shows the unconfirmed phrase's account.
    meta.prefs.evm_account = EvmAccountPref::Mnemonic(*phrase.as_bytes(), 0);
    let info = |id: RecordId, primary: bool, backup_confirmed: bool| MnemonicInfo {
        id,
        created_unix: 0,
        words: 12,
        passphrase_used: false,
        backup_confirmed,
        primary,
    };
    app.mn.infos = vec![
        info(RecordId::from_bytes([1; 16]), true, true),
        info(phrase, false, false),
    ];
    app.sync_browser();
    let state = app.connect_state(&site(1, SiteKind::RequestAccounts));
    let row = |address: &str| {
        state
            .accounts
            .iter()
            .position(|(choice, ..)| {
                *choice == crate::app_chain_sites::ConnectChoice::Evm(addr(address))
            })
            .unwrap()
    };
    assert!(state.accounts[row(ACCOUNT_C)].1.contains("백업 확인 전"));
    assert!(!state.accounts[row(ACCOUNT_A)].1.contains("백업 확인 전"));
    assert!(!state.selected[row(ACCOUNT_C)], "not the default");
    assert!(state.selected[row(ACCOUNT_A)]);
    // Connected anyway: its signing request is refused before the window, once noted.
    let core = Arc::clone(&app.browser.as_ref().unwrap().core);
    core.upsert_grant(
        yw_core::policy::ConnectedSite::new(
            yw_core::policy::BrowserOrigin::parse("https://app.example").unwrap(),
            vec![addr(ACCOUNT_C)],
            yw_core::evm::chain::SEPOLIA,
            0,
        )
        .unwrap(),
    );
    let sign = SiteKind::PersonalSign {
        account: addr(ACCOUNT_C),
        message: b"hi".to_vec(),
    };
    for n in [2, 3] {
        assert_eq!(
            app.site_preflight(&site(n, sign.clone())),
            Some(QueueOutcome::Cancelled)
        );
    }
    let notices = app
        .banners
        .iter()
        .filter(|banner| banner.text.contains("백업 확인 전이라"))
        .count();
    assert_eq!(notices, 1);
    // A WalletConnect session's request: the notice names the dApp, never the session's
    // internal `….walletconnect.invalid` origin.
    let session = yw_engine::walletconnect::session_origin(&[9; 32]).unwrap();
    core.upsert_grant(
        yw_core::policy::ConnectedSite::new(
            session.clone(),
            vec![addr(ACCOUNT_C)],
            yw_core::evm::chain::SEPOLIA,
            0,
        )
        .unwrap(),
    );
    let mut request = site(5, sign.clone());
    request.origin = session;
    assert_eq!(app.site_preflight(&request), Some(QueueOutcome::Cancelled));
    let notice = app
        .banners
        .iter()
        .find(|banner| {
            banner.text.contains("백업 확인 전이라") && !banner.text.contains("app.example")
        })
        .map(|banner| banner.text.clone())
        .unwrap();
    assert!(notice.starts_with("WalletConnect dApp의 서명 요청을 거부했습니다"));
    assert!(!notice.contains("walletconnect.invalid"));
    // The app's own send forms keep `검토` off for that account (U7) instead of building an
    // approval the vault would refuse.
    assert!(app.mn_send_blocked(app.evm_selected_gate()));
    // The quiz passed: the request reaches its window, and the forms can review.
    app.mn.infos[1].backup_confirmed = true;
    assert_eq!(app.site_preflight(&site(4, sign)), None);
    assert!(!app.mn_send_blocked(app.evm_selected_gate()));
}

/// spec/10 §10: a site connected to a `YubiKey` EVM account may ask it to sign (the request
/// reaches its window, signer `EvmKeySource::Hardware`); an address that is no account of
/// this wallet is still refused (4100).
#[test]
fn a_yubikey_account_signs_for_a_connected_site() {
    use yw_engine::approval::QueueOutcome;
    use yw_engine::browser::SiteKind;
    const ACCOUNT_YK: &str = "0x6fac4d18c912343bf86fa7049364dd4e424ab9c0";
    let mut app = accounts_app(false);
    app.meta.as_mut().unwrap().hw_accounts.evm = vec![yw_engine::meta::Account {
        index: 1,
        label: "YubiKey 계정 2".to_owned(),
        address: ACCOUNT_YK.to_owned(),
        hidden: false,
    }];
    app.sync_browser();
    let core = Arc::clone(&app.browser.as_ref().unwrap().core);
    let stranger = "0x000000000000000000000000000000000000dead";
    let request = site(1, SiteKind::RequestAccounts);
    core.upsert_grant(
        yw_core::policy::ConnectedSite::new(
            request.origin,
            vec![addr(ACCOUNT_YK), addr(stranger)],
            yw_core::evm::chain::SEPOLIA,
            0,
        )
        .unwrap(),
    );
    assert_eq!(
        app.account_source(&addr(ACCOUNT_YK)),
        Some(yw_core::vault::EvmKeySource::Hardware(
            yw_core::bip32::path::AccountIndex::new(1).unwrap()
        ))
    );
    let sign = |account: &str| SiteKind::PersonalSign {
        account: addr(account),
        message: b"hi".to_vec(),
    };
    assert_eq!(app.site_preflight(&site(2, sign(ACCOUNT_YK))), None);
    assert_eq!(
        app.site_preflight(&site(3, sign(stranger))),
        Some(QueueOutcome::Revoked)
    );
}

/// spec/10 §9.3 (2026-11-10): a `YubiKey` account whose card is still on its factory PINs
/// (`hw_accounts.defaults`, the card step's own check) is stopped at the send form — its
/// band with `PIN 설정` and `검토` off — and a dApp's signing request for it ends 4100 before
/// any window, with one notice; out of the defaults both open again.
#[test]
fn a_factory_pin_card_is_stopped_at_the_form_and_before_the_window() {
    use yw_core::bip32::path::AccountIndex;
    use yw_core::yubikey::plan::{CardSlot, KeyRole, PgpKey, PinPolicy, TouchPolicy};
    use yw_core::yubikey::record::{HwKeyRecord, HwPublicKey, RecordedSlot};
    use yw_engine::approval::QueueOutcome;
    use yw_engine::browser::SiteKind;
    const ACCOUNT_YK: &str = "0x6fac4d18c912343bf86fa7049364dd4e424ab9c0";
    const SERIAL: u32 = 7_700_011;
    let mut app = accounts_app(false);
    let meta = app.meta.as_mut().unwrap();
    meta.hw_accounts.evm = vec![yw_engine::meta::Account {
        index: 1,
        label: "YubiKey 계정 2".to_owned(),
        address: ACCOUNT_YK.to_owned(),
        hidden: false,
    }];
    meta.prefs.evm_account = yw_engine::meta::EvmAccountPref::Hardware(1);
    meta.hw_accounts.defaults = vec![SERIAL];
    app.card.records = vec![HwKeyRecord {
        serial: SERIAL,
        firmware: yw_core::yubikey::Firmware::new(5, 7, 4),
        fingerprint: [0; 4],
        slots: vec![RecordedSlot {
            slot: CardSlot::OpenPgp(PgpKey::Sig),
            role: KeyRole::Evm {
                index: AccountIndex::new(1).unwrap(),
                btc: None,
            },
            touch: TouchPolicy::Always,
            pin: PinPolicy::NotApplicable,
            public: HwPublicKey::Secp256k1([2; 33]),
            path_known: true,
        }],
    }];
    app.sync_browser();
    let core = Arc::clone(&app.browser.as_ref().unwrap().core);
    core.upsert_grant(
        yw_core::policy::ConnectedSite::new(
            yw_core::policy::BrowserOrigin::parse("https://app.example").unwrap(),
            vec![addr(ACCOUNT_YK)],
            yw_core::evm::chain::SEPOLIA,
            0,
        )
        .unwrap(),
    );
    let sign = SiteKind::PersonalSign {
        account: addr(ACCOUNT_YK),
        message: b"hi".to_vec(),
    };
    // The send form: the band and its `PIN 설정`, `검토` off.
    assert_eq!(app.evm_selected_card_gate(), Some(SERIAL));
    assert!(!app.can_review());
    app.screen = yw_engine::wallet::Screen::Send;
    let items = app.items();
    let band = format!(
        "YubiKey #{SERIAL} PIN 설정 전 — 이 계정은 받기만 되고, 보내기·서명은 PIN을 바꾼 뒤에 됩니다."
    );
    assert!(items.iter().any(|item| matches!(
        item,
        crate::ui::main_window::Item::Banner(text, _) if *text == band
    )));
    assert!(items.iter().any(|item| matches!(
        item,
        crate::ui::main_window::Item::Row(row)
            if row.iter().any(|ctl| ctl.id == crate::ui::screens_yubikey::ids::PIN_GATE_BASE)
    )));
    // A dApp request: refused before any window, one notice.
    for n in [2, 3] {
        assert_eq!(
            app.site_preflight(&site(n, sign.clone())),
            Some(QueueOutcome::Cancelled)
        );
    }
    let notices = app
        .banners
        .iter()
        .filter(|banner| {
            banner
                .text
                .contains("PIN이 아직 공장 기본값이라 서명하지 않았습니다")
        })
        .count();
    assert_eq!(notices, 1);
    // The PINs were set ("PIN 설정" takes the card out of the defaults): both open again.
    app.meta.as_mut().unwrap().hw_accounts.defaults.clear();
    assert_eq!(app.evm_selected_card_gate(), None);
    assert_eq!(app.site_preflight(&site(4, sign)), None);
    assert!(!app.items().iter().any(|item| matches!(
        item,
        crate::ui::main_window::Item::Banner(text, _) if *text == band
    )));
}

/// Security review L12: `personal_sign`/`eth_signTypedData_v4` on a chain whose check found
/// `RpcMismatch` are blocked with E34 (as sends are); an unchecked chain is not blocked.
#[test]
fn message_signing_is_blocked_on_a_mismatched_chain() {
    use yw_engine::flow::evm::{ChainCheck, MismatchKind};
    let mut app = app();
    let sepolia = yw_core::evm::chain::SEPOLIA;
    assert!(app.message_chain_failure(sepolia).is_none());
    app.evm
        .chain_checks
        .insert(sepolia, ChainCheck::Mismatch(MismatchKind::ConstantGenesis));
    let failure = app.message_chain_failure(sepolia).unwrap();
    assert_eq!(failure.rule(), yw_core::evm::risk::E34);
    assert_eq!(failure.code, yw_engine::errors::ErrorCode::Rpc006);
    assert!(!failure.retryable);
    assert!(
        app.message_chain_failure(yw_core::evm::chain::ETHEREUM_MAINNET)
            .is_none()
    );
}
