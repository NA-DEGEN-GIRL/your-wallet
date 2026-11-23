//! Approval lifecycle scenarios (2026-11-18, S4 A6; spec/15 §11.4 S4, spec/04 §3.6, §5.3,
//! spec/05 §4.5, spec/10 §9.2, spec/09 §2.2): the golden `app/tests/s4_flow/lifecycle.txt`,
//! recorded from today's code before S4 moves a line of the approval flow (owner decision O-2;
//! reviewed at the F-A checkpoint).
//!
//! A child of `flow_tests` (gate step `winui` runs it with that filter): the same A3 fixture
//! (hidden approval windows, the shared test clock, the scripted trusted-signal oracle, the RPC
//! channel and key queue captured and never run, the recorded dApp outlet) and the same recorder
//! and line format as `s4_flow/flow.txt`. What a shown approval meets after it opened: a lock
//! (one scenario per `LockReason`, entered through the main window's own handler: the
//! session/power/end-session messages, the Ctrl+L shortcut, the main timer), a revoke, an
//! account removal, a chain deletion and a page cancel, the grant re-check between the approval
//! and the dApp answer (critique A-17: the key and RPC results enter through the event drain of
//! the main window, `WM_YW_EVENTS`, never through the answer helpers), the `YubiKey` card step
//! reached from the window (mock card wallet of `yw_engine::testkit::yubikey_wallet`), the
//! queue limits through the dApp entry (the dispatcher's and, with the app's own send shown, the
//! App queue's), the journal-before-broadcast order per chain at the App
//! (critique A-5), the `rpc.json` import on temp data (critique B-5) and the balance polling
//! while the main window is hidden (critique B-10).
//!
//! Nothing here touches the network (the RPC channel is captured; RPC answers are built here),
//! a card reader (the mock card's wallet is built by the key worker in a `card` folder below the
//! fixture's own temp folder, which the fixture removes when it drops; no card job runs), a
//! process, the clipboard or the registry; files are written only below the fixtures' own temp
//! folders (and by `print`, into `YW_S4_FLOW_OUT` when it is set). The
//! `rpc.json` of the import scenario is a file in the fixture's folder named by the
//! `TEST_RPC_JSON` seam before any press, never `%USERPROFILE%\.yw-dev\rpc.json`.
//!
//! Run (`#[ignore]`, gate step `winui`): `cargo test -p yw-app --lib --locked --offline --
//! --ignored --test-threads=1 app_approval::flow_tests::lifecycle`. Regenerate for review
//! (PowerShell): `$env:YW_S4_FLOW_OUT='<folder>'; cargo test -p yw-app --lib --locked --offline
//! -- --ignored --test-threads=1 app_approval::flow_tests::lifecycle::print`.

// 2026-11-23 (S4d E1): the wallet's crate-private steps, buffers and flow state as the tests reach
// them across the crate boundary (`yw_engine::testkit`).
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use yw_engine::testkit::{CardStepTestExt, FlowTestExt, WalletTestExt};

use yw_core::evm::address::parse_address;
use yw_core::policy::{BrowserOrigin, ConnectedSite};
use yw_win::ui::{Msg, Window};

use super::super::flow_support::{Fixture, Outlet};
use super::{
    ACCOUNT_A, ACCOUNT_B, Rec, SOL_KEY, app_send, approve_by_risk, at, click, ev, fixture, origin,
    personal_sign, request, spare_window,
};
use crate::shell_msg::{WM_YW_EVENTS, WM_YW_LOCK_SHORTCUT};
use yw_engine::approval::interaction::InteractionEvent;
use yw_engine::events::{
    ChainMessageSigned, ChainSignature, EvmSigned, KeyJob, KeyOutcome, KeyResult, MessageSigned,
    RpcEvent, SignFailure, SignTicket, SignedSummary, UiEvent,
};
use yw_engine::wallet::app_browser::SignWaiter;
use yw_engine::wallet::lock::LockReason;
use yw_engine::workers::rpc::RpcJob;

/// The committed golden.
const GOLDEN: &str = include_str!("app/tests/s4_flow/lifecycle.txt");

/// A second site (its own grant; the queue's next item in the revoke scenarios).
const OTHER: &str = "https://other.example";

// ----- entries --------------------------------------------------------------------------------

/// One message to the main window's handler (`App::on_main`), the App borrowed as the window's
/// `Forward` borrows it.
fn main_msg(fx: &Fixture, main: &Window, msg: &Msg) {
    let _ = fx.app().test_on_main(main, msg);
}

/// The main timer (`App::tick`: the event drain, the idle check, the approval and polling ticks).
fn main_tick(fx: &Fixture, main: &Window) {
    let _ = fx.app().test_main_timer(main);
}

/// Gives the App its event queue (the outlet's when there is one: one queue, as in the app).
fn install_events(fx: &Fixture, outlet: Option<&Outlet>) {
    let queue = outlet.map_or_else(
        || Arc::new(yw_engine::events::EventQueue::new(Box::new(|| {}))),
        |outlet| Arc::clone(&outlet.events),
    );
    fx.app().events = Some(queue);
}

/// A worker result, through the main window's event drain (`WM_YW_EVENTS`).
fn deliver(fx: &Fixture, main: &Window, event: UiEvent) {
    let queue = fx.app.borrow().events.clone().expect("an event queue");
    assert!(queue.push(event).is_ok());
    main_msg(
        fx,
        main,
        &Msg::App {
            msg: WM_YW_EVENTS,
            wparam: 0,
        },
    );
}

/// Key worker outcomes of the current lock epoch, in order, through one event drain (one job's
/// outcomes: a signature, then the journal view it committed).
fn deliver_keys(fx: &Fixture, main: &Window, outcomes: Vec<KeyOutcome>) {
    let epoch = fx.app.borrow().lock_epoch();
    let queue = fx.app.borrow().events.clone().expect("an event queue");
    for outcome in outcomes {
        assert!(
            queue
                .push(UiEvent::Key(Box::new(KeyResult { epoch, outcome })))
                .is_ok()
        );
    }
    main_msg(
        fx,
        main,
        &Msg::App {
            msg: WM_YW_EVENTS,
            wparam: 0,
        },
    );
}

/// The journal view the key worker sends after committing `record` (the App's view plus it).
fn journal_with(fx: &Fixture, record: yw_core::journal::sol::SolRecord) -> KeyOutcome {
    let mut view = fx.app.borrow().evm.journal.clone().unwrap_or_default();
    view.sol_records.push(record);
    KeyOutcome::Journal(Ok(view))
}

/// A key worker outcome of the current lock epoch, through the event drain.
fn deliver_key(fx: &Fixture, main: &Window, outcome: KeyOutcome) {
    deliver_keys(fx, main, vec![outcome]);
}

/// Answers the lock's wait for the key worker (`LockSignal`, 1.5 s on `Suspend`, 5 s at the
/// shutdown) the way the worker would, so no scenario sleeps; the answer is not recorded.
struct LockAck {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl LockAck {
    fn start(fx: &Fixture) -> Self {
        let signal = Arc::clone(&fx.app.borrow().lock_signal);
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                signal.signal();
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        });
        Self {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for LockAck {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The number of approval windows (A01) of this process (real Win32 lookup). The panel shares
/// its class with this module's stand-in main window, so A01 alone is counted; a panel is never
/// left without its A01 (`close_approval_window` drops both).
fn approval_windows() -> usize {
    let pid = std::process::id();
    yw_win::ui::find_windows(super::super::APPROVAL_CLASS)
        .iter()
        .filter(|(_, owner)| *owner == pid)
        .count()
}

/// Sends request `n` from `site` (tab `tab`, its own document: activation nonce `tab`, so its own
/// rate bucket) on the outlet's connection, due `due_ms` after now (the outlet's frame with
/// another top origin and tab; one extension session, as in the app).
#[expect(clippy::too_many_arguments, reason = "one envelope field each")]
fn send_from(
    fx: &Fixture,
    outlet: &Outlet,
    n: u8,
    site: &str,
    tab: u8,
    method: &str,
    params: &str,
    route: &str,
    due_ms: u64,
) {
    let frame = format!(
        concat!(
            r#"{{"namespace":"your-wallet","version":1,"role":"extension","kind":"request","#,
            r#""sessionId":"{session}","sequence":{n},"deadlineUnixMs":{deadline},"#,
            r#""profileInstallId":"{profile}","activationNonce":"{activation}","#,
            r#""requestId":"{request}","method":"{method}","params":{params},"#,
            r#""route":"{route}","context":{{"browserFamily":"chrome","#,
            r#""extensionId":"abcdefghijklmnopabcdefghijklmnop","tabId":{tab},"frameId":0,"#,
            r#""documentId":"document-{tab}","topOrigin":"{site}","#,
            r#""frameOrigin":"{site}","documentLifecycle":"active","#,
            r#""channelNonce":"{channel}"}}}}"#
        ),
        session = "bb".repeat(32),
        n = n,
        deadline = fx.clock.unix_at(fx.clock.peek() + due_ms),
        profile = "aa".repeat(32),
        activation = format!("{}{tab:02x}", "00".repeat(31)),
        request = format!("{n:02x}").repeat(16),
        method = method,
        params = params,
        route = route,
        tab = tab,
        site = site,
        channel = format!("{}0d", "00".repeat(31)),
    );
    handle_frame(fx, outlet, &frame);
}

/// The page cancels request `n` (the extension's `cancel` envelope, spec/05 §6), sent as
/// sequence `sequence`.
fn cancel_request(fx: &Fixture, outlet: &Outlet, n: u8, sequence: u8) {
    let frame = format!(
        concat!(
            r#"{{"namespace":"your-wallet","version":1,"role":"extension","kind":"cancel","#,
            r#""sessionId":"{session}","sequence":{sequence},"activationNonce":"{activation}","#,
            r#""requestId":"{request}","requestSequence":{n},"reason":"navigation"}}"#
        ),
        session = "bb".repeat(32),
        sequence = sequence,
        activation = format!("{}0c", "00".repeat(31)),
        request = format!("{n:02x}").repeat(16),
        n = n,
    );
    handle_frame(fx, outlet, &frame);
}

/// One frame into the dispatcher; what it queued for the App goes through the event drain of
/// the outlet (as `Outlet::send`).
fn handle_frame(fx: &Fixture, outlet: &Outlet, frame: &str) {
    let core = fx
        .app
        .borrow()
        .browser
        .as_ref()
        .map(|browser| Arc::clone(&browser.core));
    if let Some(core) = core {
        core.handle_frame(outlet.conn, frame.as_bytes());
    }
    for event in outlet.events.drain() {
        if let UiEvent::Dapp(event) = event {
            fx.app().on_dapp_event(event);
        }
    }
}

/// Grants `site` the EVM `account` on Sepolia.
fn grant(fx: &Fixture, site: &str, account: &str) {
    if let Some(browser) = fx.app.borrow().browser.as_ref() {
        browser.core.upsert_grant(
            ConnectedSite::new(
                BrowserOrigin::parse(site).unwrap(),
                vec![parse_address(account).unwrap()],
                yw_core::evm::chain::SEPOLIA,
                1,
            )
            .unwrap(),
        );
    }
}

fn personal_sign_from(fx: &Fixture, outlet: &Outlet, n: u8, site: &str, tab: u8, account: &str) {
    send_from(
        fx,
        outlet,
        n,
        site,
        tab,
        "personal_sign",
        &format!(r#"["0x6869","{account}"]"#),
        "signing",
        600_000,
    );
}

/// The ticket of the last signing job captured by `rec`.
fn last_ticket(rec: &Rec<'_>) -> Option<SignTicket> {
    rec.keys.iter().rev().find_map(|job| match job {
        KeyJob::SignEvm { ticket, .. }
        | KeyJob::SignMessage { ticket, .. }
        | KeyJob::SignEvmCard { ticket, .. }
        | KeyJob::SignMessageCard { ticket, .. }
        | KeyJob::SignChainMessage { ticket, .. }
        | KeyJob::SignChainMessageCard { ticket, .. }
        | KeyJob::SignSolDapp { ticket, .. } => Some(*ticket),
        _ => None,
    })
}

/// The signer the waiter of `ticket` will check the grant against, as a fact (critique A-17,
/// scout C T2 #18: `SiteSigner == {origin, approved.account()}`, `consume_and_sign`).
fn waiter_fact(fx: &Fixture, ticket: Option<SignTicket>, account: &str) -> String {
    let app = fx.app.borrow();
    let waiter = ticket.and_then(|ticket| {
        app.browser
            .as_ref()
            .and_then(|browser| browser.waiters.get(&ticket))
    });
    let expected = parse_address(account).unwrap();
    match waiter {
        None => "waiter none".to_owned(),
        Some(SignWaiter::App) => "waiter app".to_owned(),
        Some(SignWaiter::Tx(_, signer)) => format!(
            "waiter tx signer=origin+account of the approval: {}",
            signer.origin == origin() && signer.account == expected
        ),
        Some(SignWaiter::Message(_, signer)) => format!(
            "waiter message signer=origin+account of the approval: {}",
            signer.origin == origin() && signer.account == expected
        ),
        Some(SignWaiter::Chain(..)) => "waiter chain".to_owned(),
    }
}

fn waiters(fx: &Fixture) -> usize {
    fx.app
        .borrow()
        .browser
        .as_ref()
        .map_or(0, |browser| browser.waiters.len())
}

/// The shown request with its arm delay passed: a tick at `t`, then the clock at `t + 1 000`.
fn armed(fx: &Fixture, t: u64) {
    at(fx, t);
    ev(fx, InteractionEvent::Tick);
    at(fx, t + 1_000);
    ev(fx, InteractionEvent::Tick);
}

// ----- lock (scout C T2 #16, critique A-3, A-14) ----------------------------------------------

/// T2 #16: Ctrl+L (the loop observer's `WM_YW_LOCK_SHORTCUT`) while a site `personal_sign` is
/// shown and armed, with a second request of the same site and a `WalletConnect` request
/// waiting.
fn lock_shortcut_while_shown() -> Vec<String> {
    let fx = fixture("lock-shortcut");
    let main = spare_window();
    let outlet = super::dapp(&fx, false, true);
    let mut rec = Rec::new("lock_shortcut_while_shown", &fx, Some(&outlet));
    personal_sign(&fx, &outlet, 1, 600_000);
    personal_sign(&fx, &outlet, 2, 600_000);
    let wc = wc_waiting(&fx, &outlet);
    armed(&fx, 0);
    rec.snap("armed-2-waiting");
    main_msg(
        &fx,
        &main,
        &Msg::App {
            msg: WM_YW_LOCK_SHORTCUT,
            wparam: 0,
        },
    );
    rec.snap("ctrl-l");
    rec.fact(
        "walletconnect",
        &format!("walletconnect request: dapp {}", super::dapp_answers(&wc)),
    );
    let mode = format!("{:?}", fx.app.borrow().mode);
    rec.fact("mode", &format!("mode={mode}"));
    rec.fact(
        "windows",
        &format!("approval windows={}", approval_windows()),
    );
    at(&fx, 2_000);
    click(&fx);
    rec.snap("click-after-lock");
    rec.lines
}

/// A `personal_sign` of a `WalletConnect` session origin with no session (waiting behind the
/// shown request), on a virtual connection of the dispatcher (the bridge's path, spec/13 §5);
/// its answers reach the returned outlet.
fn wc_waiting(fx: &Fixture, outlet: &Outlet) -> Outlet {
    let wc_origin = yw_engine::walletconnect::session_origin(&[9; 32]).unwrap();
    let core = fx
        .app
        .borrow()
        .browser
        .as_ref()
        .map(|browser| Arc::clone(&browser.core))
        .unwrap();
    core.upsert_grant(
        ConnectedSite::new(
            wc_origin.clone(),
            vec![parse_address(ACCOUNT_A).unwrap()],
            yw_core::evm::chain::SEPOLIA,
            1,
        )
        .unwrap(),
    );
    let (sender, frames) = std::sync::mpsc::channel();
    let wc = Outlet {
        events: Arc::clone(&outlet.events),
        frames,
        conn: core.open_virtual_connection(Box::new(sender)),
    };
    super::wc_personal_sign(fx, &core, &wc, wc_origin);
    wc
}

/// T2 #16 variant: a lock while a re-simulation is in flight; its later result is dropped and
/// nothing is signed.
fn lock_with_resimulation_in_flight() -> Vec<String> {
    let fx = fixture("lock-resim");
    let main = spare_window();
    let mut rec = Rec::new("lock_with_resimulation_in_flight", &fx, None);
    app_send(&fx, &mut rec, "S2");
    ev(&fx, InteractionEvent::Tick);
    at(&fx, 61_000);
    click(&fx);
    rec.snap("click-stale");
    let job = rec.take_resim();
    main_msg(
        &fx,
        &main,
        &Msg::App {
            msg: WM_YW_LOCK_SHORTCUT,
            wparam: 0,
        },
    );
    rec.snap("ctrl-l");
    at(&fx, 61_500);
    super::answer_resim(&fx, &job, "S2");
    rec.snap("resim-result-after-lock");
    rec.lines
}

/// Critique A-14: one lock per `LockReason`, each entered as the window sees it, with a site
/// `personal_sign` shown: the approval closes in the same entry (`Manual` is
/// `lock_shortcut_while_shown`, `Idle` is `lock_idle_after_the_window`).
fn lock_by_message(msg: &Msg, name: &'static str) -> Vec<String> {
    let fx = fixture(name);
    let main = spare_window();
    let outlet = super::dapp(&fx, false, true);
    let mut rec = Rec::new(name, &fx, Some(&outlet));
    personal_sign(&fx, &outlet, 1, 600_000);
    armed(&fx, 0);
    rec.snap("armed");
    {
        let _ack = LockAck::start(&fx);
        main_msg(&fx, &main, msg);
    }
    rec.snap("message");
    let app = fx.app.borrow();
    let fact = format!(
        "mode={:?} screen={:?} windows={}",
        app.mode,
        app.screen,
        approval_windows()
    );
    drop(app);
    rec.fact("after", &fact);
    rec.lines
}

/// Critique A-14 (`Idle`): the main timer's idle check while a site request is shown (the
/// window pauses the idle clock, spec/04 §5.1), then after its 120 s lifetime ended it.
fn lock_idle_after_the_window() -> Vec<String> {
    let fx = fixture("lock-idle");
    let main = spare_window();
    let outlet = super::dapp(&fx, false, true);
    let minutes = u64::from(fx.app.borrow().settings.auto_lock_minutes);
    let limit = minutes * 60_000;
    let mut rec = Rec::new("lock_idle_after_the_window", &fx, Some(&outlet));
    rec.fact("limit", &format!("auto-lock minutes={minutes}"));
    personal_sign(&fx, &outlet, 1, 600_000);
    armed(&fx, 0);
    main_tick(&fx, &main);
    rec.snap("tick-shown");
    at(&fx, limit + 1_000);
    main_tick(&fx, &main);
    rec.snap("tick-past-limit");
    at(&fx, limit + 2_000);
    main_tick(&fx, &main);
    rec.snap("tick-after-close");
    at(&fx, 2 * limit + 3_000);
    main_tick(&fx, &main);
    rec.snap("tick-past-limit-again");
    let mode = format!("{:?}", fx.app.borrow().mode);
    rec.fact("mode", &format!("mode={mode}"));
    rec.lines
}

/// Critique A-3: a request opened and a lock in the same entry (one App borrow): no orphan
/// window, today's open-then-close.
fn open_then_lock_same_entry() -> Vec<String> {
    let fx = fixture("open-lock");
    let outlet = super::dapp(&fx, false, true);
    let mut rec = Rec::new("open_then_lock_same_entry", &fx, Some(&outlet));
    let core = fx
        .app
        .borrow()
        .browser
        .as_ref()
        .map(|browser| Arc::clone(&browser.core))
        .unwrap();
    super::super::flow_support::start_log();
    // The request reaches the dispatcher; the App takes it and locks in one borrow.
    personal_sign_frame_only(&fx, &outlet, &core);
    {
        let mut app = fx.app();
        for event in outlet.events.drain() {
            if let UiEvent::Dapp(event) = event {
                app.on_dapp_event(event);
            }
        }
        app.lock(LockReason::Manual);
    }
    rec.snap("open-and-lock");
    // Each A01 effect counted on its own (A6 review: a `SetCapture` is not a show).
    let log = super::super::flow_support::take_log();
    let count = |wanted: super::super::flow_support::Fx| {
        log.iter()
            .filter(|entry| {
                matches!(
                    entry,
                    super::super::flow_support::Logged::Effect { fx, .. } if *fx == wanted
                )
            })
            .count()
    };
    let shows = count(super::super::flow_support::Fx::Show);
    let captures = count(super::super::flow_support::Fx::SetCapture);
    let releases = count(super::super::flow_support::Fx::ReleaseCapture);
    rec.fact(
        "windows",
        &format!(
            "approval windows={} show calls={shows} capture calls={captures} release calls={releases}",
            approval_windows()
        ),
    );
    rec.lines
}

/// A `personal_sign` frame into the dispatcher only (its event stays queued for the caller).
fn personal_sign_frame_only(fx: &Fixture, outlet: &Outlet, core: &yw_engine::browser::BrowserCore) {
    let frame = format!(
        concat!(
            r#"{{"namespace":"your-wallet","version":1,"role":"extension","kind":"request","#,
            r#""sessionId":"{session}","sequence":1,"deadlineUnixMs":{deadline},"#,
            r#""profileInstallId":"{profile}","activationNonce":"{activation}","#,
            r#""requestId":"{request}","method":"personal_sign","params":["0x6869","{account}"],"#,
            r#""route":"signing","context":{{"browserFamily":"chrome","#,
            r#""extensionId":"abcdefghijklmnopabcdefghijklmnop","tabId":17,"frameId":0,"#,
            r#""documentId":"document-17","topOrigin":"https://app.example","#,
            r#""frameOrigin":"https://app.example","documentLifecycle":"active","#,
            r#""channelNonce":"{channel}"}}}}"#
        ),
        session = "bb".repeat(32),
        deadline = fx.clock.unix_at(fx.clock.peek() + 600_000),
        profile = "aa".repeat(32),
        activation = format!("{}0c", "00".repeat(31)),
        request = "01".repeat(16),
        account = ACCOUNT_A,
        channel = format!("{}0d", "00".repeat(31)),
    );
    core.handle_frame(outlet.conn, frame.as_bytes());
}

// ----- revoke, removal, chain deletion, cancel (scout C T2 #17) -------------------------------

/// The id of the request the approval window shows.
fn shown_id(fx: &Fixture) -> Option<yw_core::approval::ApprovalId> {
    fx.app
        .borrow()
        .evm
        .approval
        .as_ref()
        .and_then(|flow| flow.issued().map(|request| request.id))
}

/// The store state of request `id` (shown before a revoke or cancel; the recorder's `store`
/// column follows the request shown after it, A6 review) and the approval windows left.
fn entry_fact(fx: &Fixture, id: Option<yw_core::approval::ApprovalId>) -> String {
    let state = id
        .and_then(|id| fx.app.borrow().evm_store().state(id))
        .map_or_else(|| "-".to_owned(), |state| format!("{state:?}"));
    format!(
        "store of the request shown before={state} approval windows={}",
        approval_windows()
    )
}

/// Two sites: `https://app.example` (account A) and [`OTHER`] (account B), each granted; request
/// 1 (app, A) shown and armed, request 2 ([`OTHER`], B) and 3 (app, A) waiting.
fn two_sites(fx: &Fixture, rec: &mut Rec<'_>, outlet: &Outlet) {
    grant(fx, OTHER, ACCOUNT_B);
    personal_sign(fx, outlet, 1, 600_000);
    personal_sign_from(fx, outlet, 2, OTHER, 18, ACCOUNT_B);
    personal_sign(fx, outlet, 3, 600_000);
    armed(fx, 0);
    rec.snap("shown-2-waiting");
}

/// T2 #17: S13 `연결 해제` of the shown request's site.
fn revoke_disconnect_while_shown() -> Vec<String> {
    let fx = fixture("revoke-disconnect");
    let outlet = super::dapp(&fx, false, true);
    let mut rec = Rec::new("revoke_disconnect_while_shown", &fx, Some(&outlet));
    two_sites(&fx, &mut rec, &outlet);
    let shown = shown_id(&fx);
    fx.app().disconnect_site(&origin());
    rec.snap("disconnect");
    rec.fact("first", &entry_fact(&fx, shown));
    rec.lines
}

/// T2 #17: the shown request's account hidden or its key removed.
fn revoke_account_removed_while_shown() -> Vec<String> {
    let fx = fixture("revoke-account");
    let outlet = super::dapp(&fx, false, true);
    let mut rec = Rec::new("revoke_account_removed_while_shown", &fx, Some(&outlet));
    two_sites(&fx, &mut rec, &outlet);
    let shown = shown_id(&fx);
    fx.app()
        .account_removed_from_sites(&parse_address(ACCOUNT_A).unwrap());
    rec.snap("account-removed");
    rec.fact("first", &entry_fact(&fx, shown));
    rec.lines
}

/// T2 #17: the shown request's chain deleted (spec/05 §4.3: 4901).
fn revoke_chain_deleted_while_shown() -> Vec<String> {
    let fx = fixture("revoke-chain");
    let outlet = super::dapp(&fx, false, true);
    let mut rec = Rec::new("revoke_chain_deleted_while_shown", &fx, Some(&outlet));
    two_sites(&fx, &mut rec, &outlet);
    let shown = shown_id(&fx);
    fx.app()
        .chain_removed_from_sites(yw_core::evm::chain::SEPOLIA);
    rec.snap("chain-deleted");
    rec.fact("first", &entry_fact(&fx, shown));
    rec.lines
}

/// T2 #17: the page cancels the shown request (the extension's `cancel` envelope), then the
/// connection closes (the page goes away) with the next one shown.
fn cancel_while_shown() -> Vec<String> {
    let fx = fixture("cancel");
    let outlet = super::dapp(&fx, false, true);
    let mut rec = Rec::new("cancel_while_shown", &fx, Some(&outlet));
    two_sites(&fx, &mut rec, &outlet);
    let first = shown_id(&fx);
    cancel_request(&fx, &outlet, 1, 10);
    rec.snap("page-cancel");
    rec.fact("first", &entry_fact(&fx, first));
    let second = shown_id(&fx);
    let core = fx
        .app
        .borrow()
        .browser
        .as_ref()
        .map(|browser| Arc::clone(&browser.core))
        .unwrap();
    core.close_connection(outlet.conn);
    for event in outlet.events.drain() {
        if let UiEvent::Dapp(event) = event {
            fx.app().on_dapp_event(event);
        }
    }
    rec.snap("connection-closed");
    rec.fact("second", &entry_fact(&fx, second));
    rec.lines
}

// ----- grant re-check between the approval and the answer (T2 #18, critique A-17) ------------

/// T2 #18 (EVM `personal_sign`): approved through the window, the signature answered while the
/// grant holds; approved again, the site disconnected before the key worker's answer: 4100 and
/// the signature dropped.
fn grant_evm_message() -> Vec<String> {
    let fx = fixture("grant-message");
    let main = spare_window();
    let outlet = super::dapp(&fx, false, true);
    install_events(&fx, Some(&outlet));
    let mut rec = Rec::new("grant_evm_message", &fx, Some(&outlet));
    personal_sign(&fx, &outlet, 1, 600_000);
    approve_by_risk(&fx, &mut rec, 0);
    rec.snap("approved");
    let ticket = last_ticket(&rec);
    rec.fact("signer", &waiter_fact(&fx, ticket, ACCOUNT_A));
    if let Some(ticket) = ticket {
        deliver_key(
            &fx,
            &main,
            KeyOutcome::SignedMessage(MessageSigned {
                ticket,
                result: Ok([1; 65]),
            }),
        );
    }
    rec.snap("signed-grant-holds");
    at(&fx, 10_000);
    personal_sign(&fx, &outlet, 2, 600_000);
    approve_by_risk(&fx, &mut rec, 10_000);
    rec.snap("approved-2");
    let ticket = last_ticket(&rec);
    fx.app().disconnect_site(&origin());
    rec.snap("disconnected");
    if let Some(ticket) = ticket {
        deliver_key(
            &fx,
            &main,
            KeyOutcome::SignedMessage(MessageSigned {
                ticket,
                result: Ok([1; 65]),
            }),
        );
    }
    rec.snap("signed-grant-gone");
    rec.fact("waiters", &format!("sign waiters={}", waiters(&fx)));
    rec.lines
}

/// An `eth_sendTransaction` of account A prepared from the `eth_simulateV1` fixture `sim`.
fn site_send(fx: &Fixture, rec: &mut Rec<'_>, outlet: &Outlet, n: u8) {
    request(
        fx,
        outlet,
        n,
        "eth_sendTransaction",
        &format!(
            r#"[{{"from":"{ACCOUNT_A}","to":"0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb","value":"0x2386f26fc10000"}}]"#
        ),
        "signing",
        600_000,
    );
    let job = rec.take_prepare();
    fx.answer_prepare(&job, "S2");
    rec.snap("ready");
}

/// The key worker's journaled transaction for `ticket` (a stand-in hash, never broadcast).
fn signed_evm(ticket: SignTicket, hash: u8) -> KeyOutcome {
    KeyOutcome::SignedEvm(EvmSigned {
        ticket,
        result: Ok(SignedSummary {
            chain_id: 11_155_111,
            account: parse_address(ACCOUNT_A).unwrap(),
            nonce: 0,
            raw: vec![0x02, 0xc0],
            tx_hash: [hash; 32],
        }),
    })
}

/// The RPC worker's broadcast answer for `hash`.
fn broadcast(fx: &Fixture, hash: u8) -> UiEvent {
    UiEvent::Rpc(RpcEvent::Broadcast {
        chain_id: 11_155_111,
        tx_hash: [hash; 32],
        outcome: yw_engine::flow::evm::track::BroadcastOutcome::Sent,
        at_unix_ms: fx.clock.unix_at(fx.clock.peek()),
    })
}

/// T2 #18 and critique A-5 (EVM dApp send): the key worker's journaled transaction queues the
/// broadcast and the hash is answered after it while the grant holds; a site disconnected
/// between the signature and the broadcast gets 4100 (the transaction is still sent); a journal
/// failure (write, full) sends nothing and answers -32603.
fn grant_evm_tx() -> Vec<String> {
    let fx = fixture("grant-tx");
    let main = spare_window();
    let outlet = super::dapp(&fx, false, true);
    install_events(&fx, Some(&outlet));
    let mut rec = Rec::new("grant_evm_tx", &fx, Some(&outlet));
    site_send(&fx, &mut rec, &outlet, 1);
    approve_by_risk(&fx, &mut rec, 0);
    rec.snap("approved");
    let ticket = last_ticket(&rec);
    rec.fact("signer", &waiter_fact(&fx, ticket, ACCOUNT_A));
    if let Some(ticket) = ticket {
        deliver_key(&fx, &main, signed_evm(ticket, 0x11));
    }
    rec.snap("signed");
    deliver(&fx, &main, broadcast(&fx, 0x11));
    rec.snap("broadcast-grant-holds");
    // Revoked between the signature and the broadcast.
    at(&fx, 20_000);
    site_send(&fx, &mut rec, &outlet, 2);
    approve_by_risk(&fx, &mut rec, 20_000);
    let ticket = last_ticket(&rec);
    if let Some(ticket) = ticket {
        deliver_key(&fx, &main, signed_evm(ticket, 0x22));
    }
    rec.snap("signed-2");
    fx.app().disconnect_site(&origin());
    deliver(&fx, &main, broadcast(&fx, 0x22));
    rec.snap("broadcast-grant-gone");
    // Journal failures: nothing to broadcast.
    grant(&fx, "https://app.example", ACCOUNT_A);
    for (n, failure, step) in [
        (
            3_u8,
            SignFailure::JournalWrite(yw_core::error::VaultError::Storage(
                yw_core::error::StorageError::Io(5),
            )),
            "journal-write-failed",
        ),
        (4, SignFailure::JournalFull, "journal-full"),
    ] {
        at(&fx, 20_000 * u64::from(n));
        site_send(&fx, &mut rec, &outlet, n);
        approve_by_risk(&fx, &mut rec, 20_000 * u64::from(n));
        if let Some(ticket) = last_ticket(&rec) {
            deliver_key(
                &fx,
                &main,
                KeyOutcome::SignedEvm(EvmSigned {
                    ticket,
                    result: Err(failure),
                }),
            );
        }
        rec.snap(step);
    }
    rec.fact("waiters", &format!("sign waiters={}", waiters(&fx)));
    rec.lines
}

/// Critique A-5 (EVM app send): the journaled transaction queues its broadcast; a journal
/// failure (write, full) queues none.
fn journal_evm_app_send() -> Vec<String> {
    let fx = fixture("journal-evm");
    let main = spare_window();
    install_events(&fx, None);
    let mut rec = Rec::new("journal_evm_app_send", &fx, None);
    for (round, result, step) in [
        (0_u64, None, "signed"),
        (
            1,
            Some(SignFailure::JournalWrite(
                yw_core::error::VaultError::Storage(yw_core::error::StorageError::Io(5)),
            )),
            "journal-write-failed",
        ),
        (2, Some(SignFailure::JournalFull), "journal-full"),
    ] {
        at(&fx, round * 20_000);
        app_send(&fx, &mut rec, "S2");
        approve_by_risk(&fx, &mut rec, round * 20_000);
        if let Some(ticket) = last_ticket(&rec) {
            let outcome = match result {
                None => signed_evm(ticket, 0x33),
                Some(failure) => KeyOutcome::SignedEvm(EvmSigned {
                    ticket,
                    result: Err(failure),
                }),
            };
            deliver_key(&fx, &main, outcome);
        }
        rec.snap(step);
    }
    rec.lines
}

/// T2 #18 (Solana message): `sol_signMessage` approved through the window, answered while the
/// grant holds; approved again and the site's Solana grant revoked before the answer: 4100.
fn grant_sol_message() -> Vec<String> {
    let fx = fixture("grant-sol");
    let main = spare_window();
    let outlet = super::dapp(&fx, true, true);
    install_events(&fx, Some(&outlet));
    let mut rec = Rec::new("grant_sol_message", &fx, Some(&outlet));
    let params = format!(r#"[{{"publicKey":"{SOL_KEY}","message":"50726f7665206974"}}]"#);
    request(
        &fx,
        &outlet,
        1,
        "sol_signMessage",
        &params,
        "signing",
        600_000,
    );
    approve_by_risk(&fx, &mut rec, 0);
    rec.snap("approved");
    if let Some(ticket) = last_ticket(&rec) {
        deliver_key(
            &fx,
            &main,
            KeyOutcome::SignedChainMessage(ChainMessageSigned {
                ticket,
                result: Ok(ChainSignature::Sol([2; 64])),
            }),
        );
    }
    rec.snap("signed-grant-holds");
    at(&fx, 10_000);
    request(
        &fx,
        &outlet,
        2,
        "sol_signMessage",
        &params,
        "signing",
        600_000,
    );
    approve_by_risk(&fx, &mut rec, 10_000);
    let ticket = last_ticket(&rec);
    fx.app()
        .disconnect_chain_site(&origin(), yw_core::policy::Family::Solana);
    rec.snap("disconnected");
    if let Some(ticket) = ticket {
        deliver_key(
            &fx,
            &main,
            KeyOutcome::SignedChainMessage(ChainMessageSigned {
                ticket,
                result: Ok(ChainSignature::Sol([2; 64])),
            }),
        );
    }
    rec.snap("signed-grant-gone");
    rec.lines
}

// ----- queue limits through the dApp entry ----------------------------------------------------

/// Queue limits 16 per origin and 64 in all (spec/04 §3.6) through the dApp entry: the shown
/// request counts; the 17th request of one site and the 65th in all are refused.
fn queue_limits() -> Vec<String> {
    let fx = fixture("queue-limits");
    let outlet = super::dapp(&fx, false, true);
    let mut rec = Rec::new("queue_limits", &fx, Some(&outlet));
    let sites = [
        "https://app.example",
        "https://b.example",
        "https://c.example",
        "https://d.example",
        "https://e.example",
    ];
    for site in &sites[1..] {
        grant(&fx, site, ACCOUNT_A);
    }
    let mut n = 0_u8;
    let mut send = |fx: &Fixture, site: &str, tab: u8| {
        n += 1;
        personal_sign_from(fx, &outlet, n, site, tab, ACCOUNT_A);
    };
    for _ in 0..16 {
        send(&fx, sites[0], 17);
    }
    rec.snap("16-of-one-site");
    send(&fx, sites[0], 17);
    rec.snap("17th-of-one-site");
    for (index, site) in sites[1..4].iter().enumerate() {
        let tab = 18 + u8::try_from(index).unwrap();
        for _ in 0..16 {
            send(&fx, site, tab);
        }
    }
    rec.snap("64-in-all");
    send(&fx, sites[4], 22);
    rec.snap("65th-in-all");
    rec.lines
}

/// The App queue's own limit (A6 review; `App::on_site_request`: `enqueue(..).is_err()` ->
/// -32005), reached while the dispatcher still has room. The app's own send is shown first (an
/// app item counts in the App's 64 but not in the dispatcher's site count), then 63 site
/// requests (16 + 16 + 16 + 15 from four sites) fill the App queue; the next site request (a
/// fifth site, the dispatcher at 63) passes the dispatcher and is refused by the App. Rejecting
/// the app send (Enter on `거부`) frees one place and the same request is then queued. The App's
/// 16 per origin cannot be reached this way (the dispatcher counts the same site requests per
/// origin and refuses first); `ap3_queue_limits` (yw-engine) pins the queue's own check.
fn queue_limit_at_the_app() -> Vec<String> {
    let fx = fixture("queue-limit-app");
    let outlet = super::dapp(&fx, false, true);
    let mut rec = Rec::new("queue_limit_at_the_app", &fx, Some(&outlet));
    let sites = [
        "https://app.example",
        "https://b.example",
        "https://c.example",
        "https://d.example",
        "https://e.example",
    ];
    for site in &sites[1..] {
        grant(&fx, site, ACCOUNT_A);
    }
    fx.enqueue_sepolia_send();
    rec.snap("app-send-shown");
    let mut n = 0_u8;
    for (index, site) in sites[..4].iter().enumerate() {
        let tab = 17 + u8::try_from(index).unwrap();
        let count = if index == 3 { 15 } else { 16 };
        for _ in 0..count {
            n += 1;
            personal_sign_from(&fx, &outlet, n, site, tab, ACCOUNT_A);
        }
    }
    rec.snap("63-site-requests");
    n += 1;
    personal_sign_from(&fx, &outlet, n, sites[4], 21, ACCOUNT_A);
    rec.snap("64th-site-request");
    at(&fx, 0);
    ev(&fx, InteractionEvent::Tick);
    at(&fx, 1_500);
    super::key(&fx, super::VK_RETURN, false);
    rec.snap("app-send-rejected");
    n += 1;
    personal_sign_from(&fx, &outlet, n, sites[4], 21, ACCOUNT_A);
    rec.snap("64th-site-request-again");
    rec.lines
}

// ----- the card step reached from the window (scout C T2 #19) ---------------------------------

/// The mock card wallet (an explicit `cfg(test)` module: `card_pcsc`'s source scan
/// `testkit_is_named_only_by_tests` lets only test modules name yw-engine's test kit, and it
/// reads this file, a `#[path]` child, as a plain source file).
#[cfg(test)]
mod card_wallet {
    /// Builds `yw_engine::testkit::yubikey_wallet` (the `abandon … about` vault with an enrolled
    /// emulator card) in `dir` with the key worker's deps on real files there and no card readers
    /// (AGENTS rule 3), and returns the wallet folder and its loaded meta; no card job runs.
    pub(super) fn meta(
        dir: std::path::PathBuf,
    ) -> (std::path::PathBuf, yw_engine::events::MetaLoaded) {
        let deps =
            crate::store::WinKeyPlatform::deps_with_cards(Box::new(yw_engine::yubikey::NoReaders));
        let (worker, _cards, wallet_dir, loaded) = yw_engine::testkit::yubikey_wallet(dir, deps);
        drop(worker);
        (wallet_dir, loaded)
    }
}

/// The `YubiKey` card step's state as a fact: waiting for its PIN, past it, or none.
fn card_fact(fx: &Fixture) -> String {
    let app = fx.app.borrow();
    match app.card.step.as_ref() {
        None => "card step none".to_owned(),
        Some(step) if step.holds_approval() => "card step waiting for its PIN".to_owned(),
        Some(_) => "card step past its PIN".to_owned(),
    }
}

/// T2 #19: a site `personal_sign` of the `YubiKey` account 1 (mock card wallet) approved through
/// the window opens the card step (no software job; W11 cannot open headless, E-SEC-001) and the
/// card's tries-left read; a disconnect before the PIN ends it (4100, the approval dropped, a
/// later PIN signs nothing); a step past its PIN is not aborted by a disconnect and its
/// signature is answered 4100.
fn card_step_from_the_window() -> Vec<String> {
    let fx = fixture("card-step");
    let main = spare_window();
    let outlet = super::dapp(&fx, false, false);
    install_events(&fx, Some(&outlet));
    // Below the fixture's folder, which the fixture removes when it drops (a panic included;
    // A6 review: it was a separate `%TEMP%` folder removed on the success path only).
    let dir = fx.dir().join("card");
    std::fs::create_dir_all(&dir).unwrap();
    let (wallet_dir, loaded) = card_wallet::meta(dir.clone());
    {
        let mut app = fx.app();
        app.meta = Some(*loaded.meta);
        app.card_after_meta();
        app.sync_browser();
    }
    let _ = std::fs::remove_dir_all(&wallet_dir);
    let _ = std::fs::remove_dir_all(&dir);
    grant(&fx, "https://app.example", ACCOUNT_B);
    let mut rec = Rec::new("card_step_from_the_window", &fx, Some(&outlet));
    let pin = || yw_core::secret::Zeroizing::new(b"135790".to_vec());
    personal_sign_from(&fx, &outlet, 1, "https://app.example", 17, ACCOUNT_B);
    approve_by_risk(&fx, &mut rec, 0);
    rec.snap("approved");
    rec.fact("card", &card_fact(&fx));
    let ticket = fx
        .app
        .borrow()
        .card
        .step
        .as_ref()
        .and_then(|step| step.ticket);
    rec.fact("signer", &waiter_fact(&fx, ticket, ACCOUNT_B));
    let id = fx.app.borrow().card_waiting_id();
    fx.app().disconnect_site(&origin());
    rec.snap("disconnected-before-pin");
    rec.fact("card", &card_fact(&fx));
    if let Some(id) = id {
        fx.app().card_submit(id, pin());
    }
    rec.snap("pin-after-the-end");
    // Past its PIN: the card job runs; a disconnect then does not abort it.
    grant(&fx, "https://app.example", ACCOUNT_B);
    at(&fx, 10_000);
    personal_sign_from(&fx, &outlet, 2, "https://app.example", 17, ACCOUNT_B);
    approve_by_risk(&fx, &mut rec, 10_000);
    rec.snap("approved-2");
    let id = fx.app.borrow().card_waiting_id();
    if let Some(id) = id {
        fx.app().card_submit(id, pin());
    }
    rec.snap("pin");
    let ticket = last_ticket(&rec);
    fx.app().disconnect_site(&origin());
    rec.snap("disconnected-past-pin");
    rec.fact("card", &card_fact(&fx));
    if let Some(ticket) = ticket {
        deliver_key(
            &fx,
            &main,
            KeyOutcome::SignedMessage(MessageSigned {
                ticket,
                result: Ok([1; 65]),
            }),
        );
    }
    rec.snap("signed-grant-gone");
    rec.fact("card", &card_fact(&fx));
    rec.lines
}

// ----- journal before broadcast: Zcash and Solana (critique A-5) -----------------------------

/// Critique A-5 (Zcash): the signed transaction queues only the journal's `Disclose` mark; the
/// node gets it after that commit; a failed commit sends nothing.
fn journal_zec() -> Vec<String> {
    use yw_core::zec::ZecNetwork;
    use yw_engine::workers::journal::zec::{ZecKeyOutcome, ZecSignedSummary};
    let fx = fixture("journal-zec");
    let main = spare_window();
    install_events(&fx, None);
    {
        let mut app = fx.app();
        app.settings.zcash.network = ZecNetwork::Testnet;
        app.apikeys.set_rpc(
            yw_engine::network::NetworkId::Zcash(ZecNetwork::Testnet),
            &yw_platform::http::HttpsUrl::parse("https://zec.example.test/").unwrap(),
        );
    }
    let mut rec = Rec::new("journal_zec", &fx, None);
    for (round, txid, committed) in [(0_u64, 0x44_u8, true), (1, 0x55, false)] {
        at(&fx, round * 20_000);
        super::enqueue_app_item(&fx, super::zec_item());
        rec.snap("ready");
        approve_by_risk(&fx, &mut rec, round * 20_000);
        deliver_key(
            &fx,
            &main,
            KeyOutcome::Zec(Box::new(ZecKeyOutcome::Signed(Ok(ZecSignedSummary {
                network: ZecNetwork::Testnet,
                raw: vec![0x05, 0x00],
                txid: [txid; 32],
            })))),
        );
        rec.snap("signed");
        let outcome = if committed {
            ZecKeyOutcome::Journal {
                txid: [txid; 32],
                state: Some(yw_core::journal::zec::ZecTxState::Signed),
            }
        } else {
            ZecKeyOutcome::JournalFailed { txid: [txid; 32] }
        };
        deliver_key(&fx, &main, KeyOutcome::Zec(Box::new(outcome)));
        rec.snap(if committed {
            "disclose-committed"
        } else {
            "disclose-failed"
        });
    }
    rec.lines
}

/// `SOL_KEY` as bytes.
fn sol_public() -> [u8; 32] {
    yw_core::codec::base58::base58_decode_32(SOL_KEY).unwrap()
}

/// Devnet with an endpoint (never contacted).
fn devnet(fx: &Fixture) {
    let mut app = fx.app();
    app.settings.solana.cluster = yw_engine::network::SolCluster::Devnet;
    app.apikeys.set_rpc(
        yw_engine::network::NetworkId::Solana(yw_engine::network::SolCluster::Devnet),
        &yw_platform::http::HttpsUrl::parse("https://sol.example.test/").unwrap(),
    );
    // The dispatcher's view follows the cluster (a dApp request names the wallet's cluster).
    app.sync_browser();
}

/// The app's SOL transfer of 0.001 SOL from account 0 to a synthetic address.
fn sol_transfer() -> yw_engine::wallet::app_evm::QueuedItem {
    use yw_core::sol::recipient::RecipientCheck;
    yw_engine::wallet::app_evm::QueuedItem::Sol(Box::new(
        yw_engine::wallet::app_sol::SolApprovalItem {
            cluster: yw_core::sol::SolCluster::Devnet,
            source: yw_core::slip10::SolKeySource::Standard(
                yw_core::bip32::path::AccountIndex::ZERO,
            ),
            from: yw_core::sol::SolAddress::from_bytes(sol_public()),
            label: "SOL 1".to_owned(),
            recipient: RecipientCheck {
                to: yw_core::sol::SolAddress::from_bytes([0x55; 32]),
                exact: None,
                off_curve: false,
                lookalikes: Vec::new(),
                first_time: true,
            },
            asset: yw_core::sol::SolAsset::Sol,
            amount: Some(1_000_000),
        },
    ))
}

/// The RPC worker's preview of `job`: ready, 10 SOL balance, no simulation result, no blocks.
fn sol_preview(job: &yw_engine::sol::flow::PreviewJob) -> UiEvent {
    use yw_core::sol::display::{SimSummary, SolPreviewFacts, intent_flags};
    use yw_core::sol::recipient::AccountClass;
    let cu_limit = yw_core::sol::fee::template_cu_limit(job.asset);
    let simulation = SimSummary::NoResult;
    let prepared = yw_engine::sol::flow::SolPrepared {
        cluster: job.endpoint.cluster,
        source: job.source,
        core: yw_core::sol::SolTransferCore {
            from: job.from,
            to: job.recipient.to,
            asset: job.asset,
            amount: job.amount.unwrap_or(0),
            cu_limit,
            cu_price_micro: 0,
        },
        max_fee: yw_core::sol::fee::max_fee(cu_limit, 0).unwrap_or(0),
        fee_cap: job.fee_cap,
        flags: intent_flags(
            job.amount.is_none(),
            &job.recipient,
            AccountClass::SystemWallet,
            simulation,
            cu_limit,
            job.source,
        ),
        facts: SolPreviewFacts {
            account_label: job.account_label.clone(),
            recipient: job.recipient.clone(),
            recipient_account: AccountClass::SystemWallet,
            balance: 10_000_000_000,
            rent0: 890_880,
            rpc_fee: Some(5_000),
            simulation,
            spl: None,
            blocks: Vec::new(),
        },
        genesis: yw_core::sol::address::DEVNET_GENESIS,
    };
    UiEvent::Rpc(RpcEvent::SolPreviewed(Box::new(
        yw_engine::sol::flow::PreviewResult {
            job: job.job,
            outcome: yw_engine::sol::flow::PreviewOutcome::Ready(Box::new(prepared)),
        },
    )))
}

/// Critique A-5 (Solana app send): the approval fetches the blockhash first, then the key
/// worker signs; its journaled transfer starts the tracking round that sends it; a journal
/// failure starts none.
fn journal_sol_app_send() -> Vec<String> {
    use yw_engine::events::{SolSignFailure, SolSignedSummary};
    let fx = fixture("journal-sol");
    let main = spare_window();
    let _outlet = super::dapp(&fx, true, false);
    devnet(&fx);
    install_events(&fx, None);
    let mut rec = Rec::new("journal_sol_app_send", &fx, None);
    for (round, signature, journaled) in [(0_u64, 0x66_u8, true), (1, 0x77, false)] {
        at(&fx, round * 20_000);
        super::enqueue_app_item(&fx, sol_transfer());
        rec.snap("open");
        let preview = rec.rpc.iter().find_map(|job| match job {
            RpcJob::SolPreview(job) => Some(job.clone()),
            _ => None,
        });
        rec.rpc.clear();
        if let Some(job) = preview {
            deliver(&fx, &main, sol_preview(&job));
        }
        rec.snap("ready");
        approve_by_risk(&fx, &mut rec, round * 20_000);
        rec.pull();
        let presign = rec.rpc.iter().find_map(|job| match job {
            RpcJob::SolPreSign { job, .. } => Some(*job),
            _ => None,
        });
        rec.rpc.clear();
        if let Some(job) = presign {
            deliver(
                &fx,
                &main,
                UiEvent::Rpc(RpcEvent::SolPreSigned {
                    job,
                    result: Ok(([9; 32], 1_000)),
                }),
            );
        }
        rec.snap("blockhash");
        let record = sol_record(signature, None);
        let outcomes = if journaled {
            vec![
                KeyOutcome::SignedSol(Ok(SolSignedSummary {
                    cluster: yw_core::sol::SolCluster::Devnet,
                    from: yw_core::sol::SolAddress::from_bytes(sol_public()),
                    signature: [signature; 64],
                    tx: record.tx.clone(),
                    signed_at_ms: fx.clock.unix_at(fx.clock.peek()),
                    last_valid_block_height: 1_000,
                })),
                journal_with(&fx, record),
            ]
        } else {
            vec![KeyOutcome::SignedSol(Err(SolSignFailure::JournalWrite(
                yw_core::error::VaultError::Storage(yw_core::error::StorageError::Io(5)),
            )))]
        };
        deliver_keys(&fx, &main, outcomes);
        rec.snap(if journaled {
            "signed"
        } else {
            "journal-write-failed"
        });
        main_tick(&fx, &main);
        rec.snap("next-main-tick");
    }
    rec.lines
}

/// A legacy transaction the Solana account signs and pays for (one unknown-program instruction
/// with data `[tag]`; the `app_chain_sites` tests' fixture).
fn sol_tx(tag: u8) -> Vec<u8> {
    let mut out = vec![1_u8];
    out.extend_from_slice(&[0; 64]);
    out.extend_from_slice(&[1, 0, 1, 2]);
    out.extend_from_slice(&sol_public());
    out.extend_from_slice(&[5; 32]);
    out.extend_from_slice(&[7; 32]);
    out.extend_from_slice(&[1, 1, 1, 0, 1, tag]);
    out
}

/// A Solana dApp transaction request `n` (`method`) with its preview answered (one item, no
/// tables, no simulation result).
fn sol_dapp_request(
    fx: &Fixture,
    rec: &mut Rec<'_>,
    outlet: &Outlet,
    main: &Window,
    n: u8,
    method: &str,
) {
    request(
        fx,
        outlet,
        n,
        method,
        &format!(
            r#"[{{"publicKey":"{SOL_KEY}","transaction":"{}"}}]"#,
            yw_core::hex::encode(&sol_tx(n))
        ),
        "signing",
        600_000,
    );
    rec.snap("open");
    let preview = rec.rpc.iter().find_map(|job| match job {
        RpcJob::SolDappPreview(job) => Some(job.job),
        _ => None,
    });
    rec.rpc.clear();
    if let Some(job) = preview {
        let item = yw_core::sol::dapp::SolTxItemFacts {
            tables: Ok((0, Vec::new())),
            pre: Vec::new(),
            post: None,
            sim: yw_core::sol::display::SimSummary::NoResult,
            sim_replaced_blockhash: false,
            rpc_fee: Some(5_000),
            blockhash_valid: Some(true),
        };
        deliver(
            fx,
            main,
            UiEvent::Rpc(RpcEvent::SolDappPreviewed(Box::new((
                job,
                Ok(yw_engine::sol::flow::DappPreview {
                    items: vec![item],
                    mints: Vec::new(),
                    unread_mints: Vec::new(),
                }),
            )))),
        );
    }
    rec.snap("ready");
}

/// T2 #18 (Solana dApp `sol_signTransaction`): approved through the window, the signed bytes
/// answered while the grant holds; approved again and the Solana grant revoked before the
/// answer: 4100, the bytes dropped.
fn grant_sol_dapp_sign() -> Vec<String> {
    let fx = fixture("grant-sol-dapp");
    let main = spare_window();
    let outlet = super::dapp(&fx, true, true);
    devnet(&fx);
    install_events(&fx, Some(&outlet));
    let mut rec = Rec::new("grant_sol_dapp_sign", &fx, Some(&outlet));
    for (n, revoke) in [(1_u8, false), (2, true)] {
        let t = u64::from(n - 1) * 10_000;
        at(&fx, t);
        sol_dapp_request(&fx, &mut rec, &outlet, &main, n, "sol_signTransaction");
        approve_by_risk(&fx, &mut rec, t);
        let ticket = last_ticket(&rec);
        if revoke {
            fx.app()
                .disconnect_chain_site(&origin(), yw_core::policy::Family::Solana);
            rec.snap("disconnected");
        }
        if let Some(ticket) = ticket {
            deliver_key(
                &fx,
                &main,
                KeyOutcome::SignedChainMessage(ChainMessageSigned {
                    ticket,
                    result: Ok(ChainSignature::SolTxs(vec![sol_tx(n)])),
                }),
            );
        }
        rec.snap(if revoke {
            "signed-grant-gone"
        } else {
            "signed-grant-holds"
        });
    }
    rec.lines
}

/// Critique A-5 and T2 #18 (Solana dApp `sol_signAndSendTransaction`): the approval runs the
/// pre-sign check, then the key worker signs and journals; the journaled send starts its first
/// tracking round (the broadcast) and is answered after that round; a journal failure starts no
/// round and answers -32603; a site disconnected before the first round gets 4100 (the
/// transaction is still tracked).
#[expect(
    clippy::too_many_lines,
    reason = "three sends in order, one per outcome"
)]
fn journal_sol_dapp_send() -> Vec<String> {
    use yw_engine::events::{SolDappSigned, SolDappSignedSummary, SolSignFailure};
    let fx = fixture("journal-sol-dapp");
    let main = spare_window();
    let outlet = super::dapp(&fx, true, true);
    devnet(&fx);
    install_events(&fx, Some(&outlet));
    // The dispatcher already holds the unlocked grants (no unlock merge from meta).
    if let Some(browser) = fx.app().browser.as_mut() {
        browser.unlocked = true;
    }
    let mut rec = Rec::new("journal_sol_dapp_send", &fx, Some(&outlet));
    for (n, journaled, revoke) in [(1_u8, true, false), (2, false, false), (3, true, true)] {
        let t = u64::from(n - 1) * 10_000;
        at(&fx, t);
        sol_dapp_request(
            &fx,
            &mut rec,
            &outlet,
            &main,
            n,
            "sol_signAndSendTransaction",
        );
        approve_by_risk(&fx, &mut rec, t);
        rec.pull();
        let presign = rec.rpc.iter().find_map(|job| match job {
            RpcJob::SolDappPreSign { job, .. } => Some(*job),
            _ => None,
        });
        rec.rpc.clear();
        if let Some(job) = presign {
            deliver(
                &fx,
                &main,
                UiEvent::Rpc(RpcEvent::SolDappPreSigned {
                    job,
                    result: Ok((
                        1_150,
                        yw_core::sol::dapp::PreSignCheck {
                            blockhash: [7; 32],
                            loaded: None,
                        },
                    )),
                }),
            );
        }
        rec.snap("pre-sign-checked");
        let tx_id = [0x80 + n; 64];
        let record = sol_record(0x80 + n, Some(n));
        let result = if journaled {
            Ok(SolDappSignedSummary {
                cluster: yw_core::sol::SolCluster::Devnet,
                public: sol_public(),
                tx_id,
                own_signature: tx_id,
                tx: record.tx.clone(),
                signed_at_ms: fx.clock.unix_at(fx.clock.peek()),
                last_valid_block_height: 1_150,
                min_context_slot: None,
                reused: false,
            })
        } else {
            Err(SolSignFailure::JournalWrite(
                yw_core::error::VaultError::Storage(yw_core::error::StorageError::Io(5)),
            ))
        };
        if let Some(ticket) = last_ticket(&rec) {
            let mut outcomes = vec![KeyOutcome::SignedSolDapp(SolDappSigned { ticket, result })];
            if journaled {
                outcomes.push(journal_with(&fx, record));
            }
            deliver_keys(&fx, &main, outcomes);
        }
        rec.snap(if journaled {
            "signed"
        } else {
            "journal-write-failed"
        });
        if !journaled {
            continue;
        }
        if revoke {
            fx.app()
                .disconnect_chain_site(&origin(), yw_core::policy::Family::Solana);
            rec.snap("disconnected");
        }
        deliver(
            &fx,
            &main,
            UiEvent::Rpc(RpcEvent::SolTracked(Box::new(
                yw_engine::sol::flow::TrackResult {
                    signature: tx_id,
                    state: yw_core::sol::broadcast::LoopState::default(),
                    outcome: Ok(yw_core::sol::broadcast::Outcome::Pending { notice: false }),
                    genesis_ok: Some(true),
                    sends: 1,
                    generation: 0,
                },
            ))),
        );
        rec.snap("first-round");
    }
    rec.lines
}

/// The `Pending` record the key worker commits before it answers: signature `[sig; 64]`, a
/// transfer of the app (`dapp == None`) or the dApp send of request `n`.
fn sol_record(sig: u8, dapp: Option<u8>) -> yw_core::journal::sol::SolRecord {
    let tag = dapp.unwrap_or(sig);
    let mut tx = sol_tx(tag);
    if let Some(slot) = tx.get_mut(1..65) {
        slot.copy_from_slice(&[sig; 64]);
    }
    yw_core::journal::sol::SolRecord {
        state: yw_core::journal::sol::SolTxState::Pending,
        cluster: yw_core::sol::SolCluster::Devnet,
        source: yw_core::slip10::SolKeySource::Standard(yw_core::bip32::path::AccountIndex::ZERO),
        intent_id: [sig; 16],
        intent_hash: [sig; 32],
        signed_at_ms: 1,
        last_valid_block_height: 1_150,
        terminal_slot: 0,
        terminal_err: 0,
        tx,
        dapp: dapp.map(|_| yw_core::journal::sol::SolDappMeta {
            public: sol_public(),
            signer_slot: 0,
            flags: 1,
            origin: "https://app.example".to_owned(),
        }),
    }
}

/// A token-shaped value (not a real token; the S3 census's).
const QN_TOKEN: &str = "abcdef0123456789abcdef0123456789";

// ----- rpc.json import on temp data (critique B-5) --------------------------------------------

/// Clears the `rpc.json` test seam when the scenario ends (a panic included).
struct RpcJsonSeam;

impl Drop for RpcJsonSeam {
    fn drop(&mut self) {
        crate::app_rpc_import::TEST_RPC_JSON.with(|path| *path.borrow_mut() = None);
    }
}

/// Critique B-5: Settings → the `rpc.json` import on a file in the fixture's folder (named by the
/// `TEST_RPC_JSON` seam before any press): the plan, `덮어쓰기` (the URLs saved sealed with DPAPI
/// into the fixture's folder, each imported network tested in turn), then the file's deletion
/// and its confirmation. Only counts, file presence and catalogue keys are recorded.
fn rpc_import_on_temp_data() -> Vec<String> {
    use yw_engine::cmd::RpcImportPress;
    let fx = fixture("rpc-import");
    let file = fx.dir().join("rpc.json");
    // A QuickNode-shaped endpoint with a token-shaped value (not a real token; built like the S3
    // census's), one plain `http` URL and one non-provider HTTPS URL (both rejected), one unknown
    // key (ignored).
    let quicknode = format!("https://my-node.quiknode.pro/{QN_TOKEN}/");
    std::fs::write(
        &file,
        format!(
            concat!(
                r#"{{"eip155:1":"{quicknode}","solana:devnet":"https://sol.example.test/","#,
                r#""eip155:10":"http://plain.example.test/","unknown:1":"x"}}"#
            ),
            quicknode = quicknode
        ),
    )
    .unwrap();
    let _seam = RpcJsonSeam;
    crate::app_rpc_import::TEST_RPC_JSON.with(|path| *path.borrow_mut() = Some(file.clone()));
    let mut rec = Rec::new("rpc_import_on_temp_data", &fx, None);
    let key = |fx: &Fixture| -> &'static str {
        let app = fx.app.borrow();
        let lang = app.settings.language;
        let imported = yw_engine::wallet::app_rpc_plan::text::IMPORTED.fill(lang, ["1"]);
        match app.info.as_deref() {
            None => "-",
            Some(info) if info.starts_with(&imported) => "IMPORTED",
            Some(info) if info == yw_engine::wallet::app_rpc_plan::text::DELETED.get(lang) => {
                "DELETED"
            }
            Some(info) if info == yw_engine::wallet::app_rpc_plan::text::UNREADABLE.get(lang) => {
                "UNREADABLE"
            }
            Some(info) if info == yw_engine::wallet::app_rpc_plan::text::FORMAT.get(lang) => {
                "FORMAT"
            }
            Some(_) => "other",
        }
    };
    let plan = |fx: &Fixture| {
        let app = fx.app.borrow();
        app.rpc_import.plan.as_ref().map_or_else(
            || "plan none".to_owned(),
            |plan| {
                format!(
                    "plan entries={} rejected={} ignored={}",
                    plan.entries.len(),
                    plan.rejected.len(),
                    plan.ignored
                )
            },
        )
    };
    fx.app().on_rpc_import(RpcImportPress::Import);
    rec.snap("import");
    rec.fact("plan", &plan(&fx));
    fx.app().on_rpc_import(RpcImportPress::Overwrite);
    rec.snap("overwrite");
    let app = fx.app.borrow();
    let fact = format!(
        "info={} imported={} sealed file={} stored eth={} sol={} sepolia={} tests running={} waiting={} total={}",
        key(&fx),
        app.rpc_import.imported,
        fx.dir().join("apikeys.dpapi").exists(),
        app.apikeys
            .rpc_url(yw_engine::network::NetworkId::Eip155(1))
            .is_some(),
        app.apikeys
            .rpc_url(yw_engine::network::NetworkId::Solana(
                yw_engine::network::SolCluster::Devnet
            ))
            .is_some(),
        app.apikeys
            .rpc_url(yw_engine::network::NetworkId::Eip155(11_155_111))
            .is_some(),
        app.rpc_tests.running.is_some(),
        app.rpc_tests.waiting.len(),
        app.rpc_tests.total,
    );
    drop(app);
    rec.fact("saved", &fact);
    fx.app().on_rpc_import(RpcImportPress::Delete);
    fx.app().on_rpc_import(RpcImportPress::DeleteConfirm);
    rec.snap("delete");
    rec.fact(
        "deleted",
        &format!("info={} file left={}", key(&fx), file.exists()),
    );
    rec.lines
}

// ----- balance polling while the main window is hidden (critique B-10) ------------------------

/// Critique B-10: the main timer's balance, `HyperCore` and received-history reads with the main
/// window shown (no window: tests are "not hidden") and hidden (a hidden stand-in main window),
/// on the EVM and the Solana tab; every due time reset before each tick.
///
/// The "shown" case is `App::main == None` (`main_hidden()` is false without a main window), not
/// a main window that is visible or restored: `main_hidden` reads `is_hidden_or_minimized` of
/// the real window, and these tests never show a window (A6 review). A W3 `main_hidden` mirror
/// that got the visible-window case wrong (e.g. hidden by default once `main` is `Some`) would
/// not change these lines; that case stays an open item for W3 (its own check there).
///
/// 2026-11-21 (S4 W3, critique B-10, preflight critic C7): `main_hidden()` is the wallet's
/// mirror (`Cmd::MainHidden`). The test puts the stand-in window in (or takes it out) itself, as
/// no message does, so it then runs the shell's own sync (`App::sync_main_hidden`, which reads
/// the window as `main_hidden` did before W3) inside the same entry; the lines are unchanged.
/// The visible-window case is still not checked here, nor anywhere in the gate (2026-11-21, S4
/// W3 review; the W3 note here said `ui::tour_forms` and the end-of-drain debug check covered it,
/// but the first did not look at the mirror and the second compares it with the same live read,
/// `App::main_hidden_now`). The gate pins that read's body exactly (source check
/// `the_main_hidden_mirror_changes_where_the_window_does`), and the on-request windowed
/// `ui::tour_forms` (`main_hidden_follows_the_window`) checks it on a real main window shown,
/// minimized, hidden and shown again, with a due balance tick each time.
fn polling_while_hidden() -> Vec<String> {
    let fx = fixture("polling");
    let timer = spare_window();
    let _outlet = super::dapp(&fx, true, false);
    devnet(&fx);
    {
        let mut app = fx.app();
        app.settings.evm_chain_id = 11_155_111;
        app.settings.received_history = true;
        app.screen = yw_engine::wallet::Screen::Main;
    }
    let mut rec = Rec::new("polling_while_hidden", &fx, None);
    for hidden in [false, true] {
        {
            let mut app = fx.app();
            app.main = hidden.then(spare_window);
            app.sync_main_hidden();
        }
        rec.fact(
            if hidden { "hidden" } else { "shown" },
            &format!("main hidden={}", fx.app.borrow().main_hidden()),
        );
        for tab in [yw_engine::meta::Tab::Evm, yw_engine::meta::Tab::Sol] {
            {
                let mut app = fx.app();
                if let Some(meta) = app.meta.as_mut() {
                    meta.prefs.tab = tab;
                }
                app.evm.next_balance_ms = 0;
                app.sol.next_balance_ms = 0;
                app.hypercore.loaded_ms = None;
                app.hypercore.loading = false;
                app.received.lists.clear();
            }
            at(&fx, 60_000);
            main_tick(&fx, &timer);
            rec.snap(match (hidden, tab) {
                (false, yw_engine::meta::Tab::Evm) => "shown-evm-tab",
                (false, _) => "shown-sol-tab",
                (true, yw_engine::meta::Tab::Evm) => "hidden-evm-tab",
                (true, _) => "hidden-sol-tab",
            });
        }
    }
    {
        let mut app = fx.app();
        app.main = None;
        app.sync_main_hidden();
    }
    rec.lines
}

// ----- the scenario table ---------------------------------------------------------------------

type Scenario = fn() -> Vec<String>;

/// Every scenario, in golden order.
const SCENARIOS: [(&str, Scenario); 25] = [
    ("lock_shortcut_while_shown", lock_shortcut_while_shown),
    (
        "lock_with_resimulation_in_flight",
        lock_with_resimulation_in_flight,
    ),
    ("lock_session_lock", || {
        lock_by_message(&Msg::SessionLock, "lock_session_lock")
    }),
    ("lock_session_disconnect", || {
        lock_by_message(&Msg::SessionDisconnect, "lock_session_disconnect")
    }),
    ("lock_suspend", || {
        lock_by_message(&Msg::Suspend, "lock_suspend")
    }),
    ("lock_end_session", || {
        lock_by_message(&Msg::EndSession, "lock_end_session")
    }),
    ("lock_idle_after_the_window", lock_idle_after_the_window),
    ("open_then_lock_same_entry", open_then_lock_same_entry),
    (
        "revoke_disconnect_while_shown",
        revoke_disconnect_while_shown,
    ),
    (
        "revoke_account_removed_while_shown",
        revoke_account_removed_while_shown,
    ),
    (
        "revoke_chain_deleted_while_shown",
        revoke_chain_deleted_while_shown,
    ),
    ("cancel_while_shown", cancel_while_shown),
    ("grant_evm_message", grant_evm_message),
    ("grant_evm_tx", grant_evm_tx),
    ("journal_evm_app_send", journal_evm_app_send),
    ("grant_sol_message", grant_sol_message),
    ("grant_sol_dapp_sign", grant_sol_dapp_sign),
    ("journal_sol_dapp_send", journal_sol_dapp_send),
    ("journal_sol_app_send", journal_sol_app_send),
    ("journal_zec", journal_zec),
    ("card_step_from_the_window", card_step_from_the_window),
    ("queue_limits", queue_limits),
    ("queue_limit_at_the_app", queue_limit_at_the_app),
    ("rpc_import_on_temp_data", rpc_import_on_temp_data),
    ("polling_while_hidden", polling_while_hidden),
];

/// The golden lines of `name` (in order).
fn golden_of(name: &str) -> Vec<&'static str> {
    let prefix = format!("{name} ");
    GOLDEN
        .lines()
        .filter(|line| line.starts_with(&prefix))
        .collect()
}

/// Runs scenario `name` and compares its lines with its golden lines.
fn run(name: &str) {
    let (_, scenario) = SCENARIOS
        .iter()
        .find(|(known, _)| *known == name)
        .expect("a scenario of the table");
    let lines = scenario();
    let generated: Vec<&str> = lines.iter().map(String::as_str).collect();
    let committed = golden_of(name);
    assert!(
        generated == committed,
        "{}",
        super::first_difference(name, &generated, &committed)
    );
}

macro_rules! lifecycle_tests {
    ($($test:ident => $name:literal),* $(,)?) => {
        $(
            #[test]
            #[ignore = "creates hidden approval windows (S4 flow harness, gate step winui)"]
            fn $test() {
                run($name);
            }
        )*
    };
}

lifecycle_tests! {
    golden_lock_shortcut_while_shown => "lock_shortcut_while_shown",
    golden_lock_with_resimulation_in_flight => "lock_with_resimulation_in_flight",
    golden_lock_session_lock => "lock_session_lock",
    golden_lock_session_disconnect => "lock_session_disconnect",
    golden_lock_suspend => "lock_suspend",
    golden_lock_end_session => "lock_end_session",
    golden_lock_idle_after_the_window => "lock_idle_after_the_window",
    golden_open_then_lock_same_entry => "open_then_lock_same_entry",
    golden_revoke_disconnect_while_shown => "revoke_disconnect_while_shown",
    golden_revoke_account_removed_while_shown => "revoke_account_removed_while_shown",
    golden_revoke_chain_deleted_while_shown => "revoke_chain_deleted_while_shown",
    golden_cancel_while_shown => "cancel_while_shown",
    golden_grant_evm_message => "grant_evm_message",
    golden_grant_evm_tx => "grant_evm_tx",
    golden_journal_evm_app_send => "journal_evm_app_send",
    golden_grant_sol_message => "grant_sol_message",
    golden_grant_sol_dapp_sign => "grant_sol_dapp_sign",
    golden_journal_sol_dapp_send => "journal_sol_dapp_send",
    golden_journal_sol_app_send => "journal_sol_app_send",
    golden_journal_zec => "journal_zec",
    golden_card_step_from_the_window => "card_step_from_the_window",
    golden_queue_limits => "queue_limits",
    golden_queue_limit_at_the_app => "queue_limit_at_the_app",
    golden_rpc_import_on_temp_data => "rpc_import_on_temp_data",
    golden_polling_while_hidden => "polling_while_hidden",
}

/// Every scenario in table order: writes `lifecycle.txt` into `YW_S4_FLOW_OUT` when it is set
/// (for review), else compares the whole golden file (order and completeness). Each scenario
/// runs on a thread of its own, as each `golden_*` test does (A6 review: `lock_end_session`
/// runs the real shutdown, which posts `WM_QUIT` to its thread; the scenarios after it must not
/// run with that message pending once effects or message pumps reach them).
#[test]
#[ignore = "creates hidden approval windows (S4 flow harness, gate step winui)"]
fn print() {
    let mut out = String::new();
    for (_, scenario) in &SCENARIOS {
        let lines = std::thread::spawn(*scenario)
            .join()
            .expect("the scenario's thread");
        for line in lines {
            out.push_str(&line);
            out.push('\n');
        }
    }
    if let Some(dir) = std::env::var_os("YW_S4_FLOW_OUT") {
        let dir = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("lifecycle.txt"), &out).unwrap();
        return;
    }
    let generated: Vec<&str> = out.lines().collect();
    let committed: Vec<&str> = GOLDEN.lines().collect();
    assert!(
        generated == committed,
        "{}",
        super::first_difference("lifecycle.txt", &generated, &committed)
    );
}

/// The golden names only scenarios of the table, each with lines, grouped in table order, and
/// holds no address, URL, e-mail, local path or non-ASCII text (gate test step; no window).
#[test]
fn the_lifecycle_golden_names_only_known_scenarios() {
    let mut order = Vec::new();
    for line in GOLDEN.lines() {
        let name = line.split(' ').next().unwrap_or_default();
        assert!(
            SCENARIOS.iter().any(|(known, _)| *known == name),
            "unknown scenario: {line}"
        );
        if order.last() != Some(&name) {
            assert!(!order.contains(&name), "{name} is not one block");
            order.push(name);
        }
        for banned in ["0x", "://", "@", "\\", "Users", ".example", "rpc.json"] {
            assert!(!line.contains(banned), "{banned:?} in {line}");
        }
        assert!(line.is_ascii(), "non-ASCII text in {line}");
    }
    let table: Vec<&str> = SCENARIOS.iter().map(|(name, _)| *name).collect();
    assert_eq!(order, table, "every scenario, in table order");
}

/// The flow and lifecycle scenarios with the shell half absent (2026-11-20, S4 B7):
/// `s4_flow/headless.txt` and the cross-check with this file's and `flow.txt`'s goldens (gate
/// test step, no window). A child of this module so that it runs the same helpers.
#[path = "app_approval_headless_tests.rs"]
mod headless;
