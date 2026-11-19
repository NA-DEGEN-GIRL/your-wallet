//! Approval flow test seams and fixture (2026-11-18, S4 A3; spec/15 §11.4 S4, spec/09 §2.2).
//!
//! `cfg(test)` only: release builds compile none of this, and the production functions that
//! read it (the A01 trusted-signal reads and Win32 side effects, `open_approval`) behave exactly
//! as before while no seam is installed. Every seam is a thread-local of the test thread, set by
//! [`Fixture`] and cleared when it drops:
//!
//! - [`TestClock`] (manual, or stepping by a fixed amount at every read) is not a seam since S4
//!   B1b (2026-11-19): the fixture's App gets it as its injected clock ([`App::with_clock`]), and
//!   the prepare fixture and the test `BrowserCore`s read the same `Arc`, so `sim_received_ms`,
//!   the site deadline and the App's own reads have one base (S4 critique A-9/B-19). Before: S4
//!   A3 (2026-11-18) installed it as the thread-local `TEST_CLOCK`, which every App
//!   `now_ms`/`now_unix_ms` wrapper (18, `every_app_time_wrapper_reads_the_test_clock`) and a few
//!   inline reads read first, and the test `BrowserCore`s got it from `core_clock()`; S4 B1a
//!   (2026-11-19) injected it and turned the wrappers and inline reads of `app`, `app_approval`,
//!   `app_card`, `app_browser`, `app_evm`, `app_sol` and `app_sol_dapp` into `self.clock` reads;
//!   S4 B1b turned the rest into `self.clock` reads at their lines (the wrappers of
//!   `app_chain_sites`, `app_btc`, `app_hypercore`, `app_zec`, `app_book`, `app_received` and
//!   `app_reset`, and the reads that were still on the real clock under a fixture: form-edit
//!   times of `app_evm_commands`, `app_sol_commands` and `ui/screens_hypercore`, the refresh and
//!   wait timers of `app_hypercore`, `app_zec`, `app_received` and `app_reset`, `app_sidecar`'s
//!   journal-reset time, `app_yubikey`'s password and idle times and `app_walletconnect`'s join
//!   wait) and removed `TEST_CLOCK` (`app_time_reads_go_through_the_clock`).
//!   A manual `TestClock` moves only when the test moves it, so the bounded busy waits that read
//!   the App's clock (`App::shutdown`'s worker join wait, `wc_shutdown`'s relay worker join wait
//!   and `clear_secret_clip_at_exit`'s clipboard retry, 1–2 s in production) never run out under
//!   it (2026-11-19, B1 review): a fixture App must not reach them while a live thread could fail
//!   to finish or the clipboard could fail. No fixture starts a WalletConnect worker or a real
//!   worker thread, or touches the clipboard; a test that does advances the clock (or uses a
//!   stepping one) before it shuts the App down.
//! - `TEST_APPROVAL_HOST`: [`HostMode::Hidden`] creates A01, its panel and AI body as hidden
//!   windows and skips every call that could show or activate one (`center_on`, `show`,
//!   `set_foreground`, `flash`, `set_focus`; capture is still taken and released);
//!   [`HostMode::FailOpen`] refuses the window like a failed `CreateWindowExW` (the open-failure
//!   path). Removed in B7.
//! - `TEST_SIGNALS`: a scripted trusted-signal oracle ([`Signals`]) that answers the foreground,
//!   key-state, Enter-in-message and injected reads (critique A-7).
//! - `TEST_INPUT_LOG`: every `interaction(event)` with its foreground sample and focus, the
//!   `ActivateApp(true)` arm, the toggles, retries and scrolls (A-19), every scripted read with
//!   its program point and every A01 side effect, in one ordered list (the call index is the
//!   position); since S4 A5 (2026-11-18, A-8) also every message the approval `Forward` drops
//!   because the App is borrowed (re-entrancy). Removed in B2.
//!
//! The fixture never touches the network (the RPC channel and the key queue are captured, never
//! run; the prepare job is answered by the smoke harness's fixture transport), a card reader, a
//! process, the clipboard or the registry, and writes only below its own temp folder.

use std::cell::{Cell, RefCell, RefMut};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};

use yw_core::bip32::path::AccountIndex;
use yw_core::evm::address::parse_address;
use yw_core::evm::amount::U256;
use yw_core::policy::ProviderError;
use yw_core::vault::EvmKeySource;
use yw_platform::http::HttpsUrl;
use yw_win::ui::{self, CaptureExclusion, ClassSpec, Msg};

use super::{APPROVAL_CLASS, Focus, PANEL_CLASS};
use crate::apikeys::ApiKeys;
use crate::app::{App, AppMode, Paths};
use crate::app_evm::AppApproval;
use crate::events::{EventQueue, JournalView, KeyJob, UiEvent};
use crate::flow::evm::prepare::{PrepareJob, SendIntent, prepare};
use crate::flow::evm::{ChainCache, Clock, SharedTransport};
use crate::network::NetworkId;
use crate::settings::Settings;
use crate::ui::interaction::InteractionEvent;
use crate::workers::rpc::RpcJob;

/// The fixture clock's first reading (ms): far from zero, so no "now - x" saturates.
pub(crate) const START_MS: u64 = 1_000_000;
/// The extension id the fixture's `BrowserCore` pins (the `app_chain_sites` tests' value).
const EXTENSION_ID: &str = "abcdefghijklmnopabcdefghijklmnop";

// ----- test clock ---------------------------------------------------------------------------

/// A test time source: manual (`step == 0`) or stepping (every read returns the current value,
/// then advances it by `step`). Wall time is `unix_base + monotonic`, where the first reading is
/// the smoke fixture's block time (so the prepare pipeline's 300 s block-time rule holds for the
/// `eth_simulateV1` fixtures).
#[derive(Debug)]
pub(crate) struct TestClock {
    at: AtomicU64,
    step: AtomicU64,
    unix_base: u64,
}

impl TestClock {
    /// A manual clock at `at`.
    pub(crate) fn manual(at: u64) -> Arc<Self> {
        Self::stepping(at, 0)
    }

    /// A clock at `at` that advances by `step` at every read.
    pub(crate) fn stepping(at: u64, step: u64) -> Arc<Self> {
        Arc::new(Self {
            at: AtomicU64::new(at),
            step: AtomicU64::new(step),
            unix_base: super::smoke::S2_UNIX_MS.saturating_sub(at),
        })
    }

    /// The current value, without stepping.
    pub(crate) fn peek(&self) -> u64 {
        self.at.load(Ordering::SeqCst)
    }

    /// Sets the current value.
    pub(crate) fn set(&self, at: u64) {
        self.at.store(at, Ordering::SeqCst);
    }

    /// Moves the clock forward by `ms`.
    pub(crate) fn advance(&self, ms: u64) {
        self.at.fetch_add(ms, Ordering::SeqCst);
    }

    /// Changes the step (`0` = manual).
    pub(crate) fn set_step(&self, step: u64) {
        self.step.store(step, Ordering::SeqCst);
    }

    /// The wall time this clock gives for monotonic `ms`.
    pub(crate) const fn unix_at(&self, ms: u64) -> u64 {
        self.unix_base.saturating_add(ms)
    }

    fn read(&self) -> u64 {
        self.at
            .fetch_add(self.step.load(Ordering::SeqCst), Ordering::SeqCst)
    }
}

impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.read()
    }

    fn now_unix_ms(&self) -> u64 {
        self.unix_at(self.read())
    }

    fn sleep_ms(&self, ms: u64) {
        self.advance(ms);
    }
}

// ----- seams --------------------------------------------------------------------------------

/// How `open_approval` treats the approval window while a fixture is installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HostMode {
    /// Real, hidden windows: nothing is shown, centred, activated, flashed or focused.
    Hidden,
    /// The window is refused before it is created (the open-failure path).
    FailOpen,
}

/// The scripted trusted-signal oracle (critique A-7): the value every A01 read returns while it
/// is installed. Keys other than the left button, Space and Shift read as up.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "one independent value per Win32 read"
)]
pub(crate) struct Signals {
    /// `window_is_foreground` (the gate input; it wins over `TEST_FORCE_FOREGROUND`).
    pub(crate) foreground: bool,
    /// The raw `window.is_foreground()` of the activating click and the click-through check.
    pub(crate) foreground_raw: bool,
    pub(crate) lbutton_down: bool,
    pub(crate) space_down: bool,
    pub(crate) shift_down: bool,
    /// `is_down_in_message(VK_RETURN)`.
    pub(crate) enter_in_message: bool,
    /// `injected()`.
    pub(crate) injected: bool,
    /// What a skipped `set_foreground` returns under [`HostMode::Hidden`].
    pub(crate) set_foreground_ok: bool,
}

/// One trusted-signal read and its program point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Read {
    /// `window_is_foreground` in `interaction()`.
    Foreground,
    /// The raw foreground read at the named point.
    RawForeground(&'static str),
    /// `is_down(vk)` at the named point.
    KeyDown(u16, &'static str),
    EnterInMessage,
    Injected,
}

/// One A01 Win32 side effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fx {
    Show,
    CenterOn,
    /// `set_foreground` of A01 (`"approval"`) or the main window (`"main"`).
    SetForeground(&'static str),
    Flash,
    SetFocus,
    SetCapture,
    ReleaseCapture,
    /// [`HostMode::FailOpen`] refused the window.
    CreateRefused,
}

impl Fx {
    /// Whether a hidden host skips it (it could show or activate a window).
    const fn hidden_skips(self) -> bool {
        matches!(
            self,
            Self::Show | Self::CenterOn | Self::SetForeground(_) | Self::Flash | Self::SetFocus
        )
    }
}

/// A flow call logged with the focus at the time of the call (critique A-19).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Call {
    ToggleAck,
    ToggleRaw,
    ToggleAccount(usize),
    Retry,
    AiRetry,
    Scroll(i32),
}

/// One entry of the ordered input log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Logged {
    /// `interaction(event)`: its foreground sample and the focus (`None`: no window open).
    Event {
        event: InteractionEvent,
        foreground: Option<bool>,
        focus: Option<Focus>,
    },
    /// The `ActivateApp(true)` arm (`restart_arm_delay`, then foreground `true`).
    Activated { focus: Option<Focus> },
    /// A toggle, retry or scroll.
    Call { call: Call, focus: Option<Focus> },
    /// A read the oracle answered.
    Read { read: Read, value: bool },
    /// A side effect; `performed == false` when the hidden host skipped it.
    Effect { fx: Fx, performed: bool },
    /// A message the approval `Forward` dropped (or deferred, `Paint`) because the App was
    /// borrowed: a re-entrant message (2026-11-18, S4 A5, critique A-8).
    Dropped { target: &'static str, msg: Msg },
}

thread_local! {
    static TEST_APPROVAL_HOST: Cell<Option<HostMode>> = const { Cell::new(None) };
    static TEST_SIGNALS: Cell<Option<Signals>> = const { Cell::new(None) };
    static TEST_INPUT_LOG: RefCell<Option<Vec<Logged>>> = const { RefCell::new(None) };
}

/// Sets this thread's approval host mode (`None`: real windows).
pub(crate) fn set_host(mode: Option<HostMode>) {
    let _ = TEST_APPROVAL_HOST.try_with(|slot| slot.set(mode));
}

fn host() -> Option<HostMode> {
    TEST_APPROVAL_HOST.try_with(Cell::get).ok().flatten()
}

/// Installs (or removes) the scripted trusted-signal oracle.
pub(crate) fn set_signals(signals: Option<Signals>) {
    let _ = TEST_SIGNALS.try_with(|slot| slot.set(signals));
}

/// Starts (or restarts) the input log.
pub(crate) fn start_log() {
    let _ = TEST_INPUT_LOG.try_with(|slot| *slot.borrow_mut() = Some(Vec::new()));
}

/// The entries logged since the last call (the log keeps running).
pub(crate) fn take_log() -> Vec<Logged> {
    TEST_INPUT_LOG
        .try_with(|slot| slot.borrow_mut().as_mut().map(std::mem::take))
        .ok()
        .flatten()
        .unwrap_or_default()
}

fn stop_log() {
    let _ = TEST_INPUT_LOG.try_with(|slot| *slot.borrow_mut() = None);
}

/// Appends to the input log while it runs.
pub(crate) fn log_input(entry: Logged) {
    let _ = TEST_INPUT_LOG.try_with(|slot| {
        if let Ok(mut log) = slot.try_borrow_mut()
            && let Some(log) = log.as_mut()
        {
            log.push(entry);
        }
    });
}

/// The scripted value of `read` (logged), or `None` without an oracle (the real read follows).
pub(crate) fn scripted(read: Read) -> Option<bool> {
    let signals = TEST_SIGNALS.try_with(Cell::get).ok().flatten()?;
    let value = match read {
        Read::Foreground => signals.foreground,
        Read::RawForeground(_) => signals.foreground_raw,
        Read::KeyDown(vk, _) => match vk {
            0x01 => signals.lbutton_down,
            0x20 => signals.space_down,
            0x10 => signals.shift_down,
            _ => false,
        },
        Read::EnterInMessage => signals.enter_in_message,
        Read::Injected => signals.injected,
    };
    log_input(Logged::Read { read, value });
    Some(value)
}

/// Logs a side effect; `true` = skip the Win32 call (hidden host).
pub(crate) fn effect(fx: Fx) -> bool {
    let skip = host() == Some(HostMode::Hidden) && fx.hidden_skips();
    log_input(Logged::Effect {
        fx,
        performed: !skip,
    });
    skip
}

/// `set_foreground` of `of`: `Some(result)` when the hidden host skipped it.
pub(crate) fn foreground_request(of: &'static str) -> Option<bool> {
    effect(Fx::SetForeground(of)).then(|| {
        TEST_SIGNALS
            .try_with(Cell::get)
            .ok()
            .flatten()
            .is_some_and(|signals| signals.set_foreground_ok)
    })
}

/// Whether `open_approval` must refuse the window now (logged).
pub(crate) fn fail_open() -> bool {
    let refuse = host() == Some(HostMode::FailOpen);
    if refuse {
        log_input(Logged::Effect {
            fx: Fx::CreateRefused,
            performed: false,
        });
    }
    refuse
}

impl App {
    /// Logs a toggle, retry or scroll of the open approval window with its focus (A-19).
    pub(crate) fn log_approval_call(&self, call: Call) {
        log_input(Logged::Call {
            call,
            focus: self.evm.window.as_ref().map(|ui| ui.focus),
        });
    }
}

// ----- fixture ------------------------------------------------------------------------------

/// The App of an approval flow test: unlocked, with an RPC channel (jobs captured, never run),
/// its key queue (jobs captured, never run), an EVM journal view, and the seams installed on
/// this thread (test clock at [`START_MS`], `host`, the input log; no signal script until the
/// test sets one). Dropping it closes the window, clears the seams and removes its folder.
pub(crate) struct Fixture {
    pub(crate) app: Rc<RefCell<App>>,
    pub(crate) clock: Arc<TestClock>,
    rpc: Receiver<RpcJob>,
    dir: PathBuf,
}

impl Fixture {
    pub(crate) fn new(tag: &str, host: HostMode) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for class in [APPROVAL_CLASS, PANEL_CLASS] {
            ui::register_class(&ClassSpec {
                name: class,
                secret: false,
                capture: CaptureExclusion::Preferred,
            })
            .unwrap();
        }
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("yw-s4-flow-{tag}-{}-{serial}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let clock = TestClock::manual(START_MS);
        set_host(Some(host));
        set_signals(None);
        start_log();
        let mut apikeys = ApiKeys::default();
        // Never contacted: preparation jobs are answered by the fixture transport.
        apikeys.set_rpc(
            NetworkId::Eip155(11_155_111),
            &HttpsUrl::parse("https://rpc.example.test/").unwrap(),
        );
        // The App reads the same clock (injected since S4 B1a, 2026-11-19; before, through the
        // `TEST_CLOCK` seam of its wrappers, removed in S4 B1b).
        let app = Rc::new(RefCell::new(App::with_clock(
            Paths {
                data: dir.clone(),
                logs: dir.join("logs"),
            },
            true,
            Settings::default(),
            apikeys,
            Arc::clone(&clock) as Arc<dyn Clock>,
        )));
        let (tx, rpc) = mpsc::channel();
        {
            let mut state = app.borrow_mut();
            state.self_ref = Rc::downgrade(&app);
            state.mode = AppMode::Unlocked {
                alt_passphrase: false,
            };
            state.rpc_tx = Some(tx);
            state.evm.journal = Some(JournalView {
                records: Vec::new(),
                corrupt: 0,
                room: true,
                sol_room: true,
                ..JournalView::default()
            });
        }
        Self {
            app,
            clock,
            rpc,
            dir,
        }
    }

    /// The App (one borrow at a time; window messages sent meanwhile are dropped by `Forward`).
    pub(crate) fn app(&self) -> RefMut<'_, App> {
        self.app.borrow_mut()
    }

    /// The fixture's own temp folder (the App's data folder; removed when it drops).
    pub(crate) fn dir(&self) -> &std::path::Path {
        &self.dir
    }

    /// The RPC jobs sent since the last call.
    pub(crate) fn rpc_jobs(&self) -> Vec<RpcJob> {
        self.rpc.try_iter().collect()
    }

    /// The key jobs queued since the last call.
    pub(crate) fn key_jobs(&self) -> Vec<KeyJob> {
        let app = self.app.borrow();
        std::iter::from_fn(|| {
            (!app.key_queue.is_empty())
                .then(|| app.key_queue.pop())
                .flatten()
        })
        .map(|(_, job)| job)
        .collect()
    }

    /// Queues the smoke harness's Sepolia send (account 0 of the public test phrase) as an app
    /// approval; its preparation job goes to the RPC channel.
    pub(crate) fn enqueue_sepolia_send(&self) {
        self.app().enqueue_app(AppApproval {
            chain_id: 11_155_111,
            account: parse_address("0x9858EfFD232B4033E47d90003D41EC34EcaEda94").unwrap(),
            signer: EvmKeySource::Derived(AccountIndex::ZERO),
            intent: SendIntent {
                to: parse_address("0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb").unwrap(),
                value: U256::from_u64(0x0023_86f2_6fc1_0000),
                data: Vec::new(),
                access_list: Vec::new(),
                dapp_gas: None,
                dapp_nonce: None,
            },
            replace: None,
        });
    }

    /// Answers `job` as the RPC worker would, from the `eth_simulateV1` fixture `name`, on the
    /// shared test clock, and delivers `on_simulating` / `on_prepared`.
    pub(crate) fn answer_prepare(&self, job: &PrepareJob, name: &str) {
        let transport: SharedTransport = Arc::new(super::smoke::FixtureRpc {
            simulate: super::smoke::fixture(name),
        });
        let since = RefCell::new(None);
        let result = prepare(
            &transport,
            &mut ChainCache::default(),
            job,
            &*self.clock,
            &|at| {
                *since.borrow_mut() = Some(at);
            },
        );
        if let Some(at) = since.into_inner() {
            self.app().on_simulating(job.job, at);
        }
        self.app().on_prepared(result);
    }

    /// A dApp connection recorded on a fresh dispatcher (the shared clock) that the App uses
    /// from now on (lifted from the `app_chain_sites` tests' `recorded()`).
    pub(crate) fn connect_outlet(&self) -> Outlet {
        let events = Arc::new(EventQueue::new(Box::new(|| {})));
        let core = crate::browser::BrowserCore::new(
            EXTENSION_ID,
            Arc::clone(&events) as Arc<dyn crate::browser::DappSink>,
            Arc::clone(&self.clock) as Arc<dyn Clock>,
        );
        let (sender, frames) = mpsc::channel();
        let conn = core.open_connection(Box::new(sender));
        {
            let mut app = self.app();
            app.browser = Some(crate::app_browser::BrowserUi {
                core,
                reads: Arc::new(crate::browser::read::ReadContext::new(None)),
                server: None,
                pipe_error: None,
                threads: Vec::new(),
                connections: 0,
                waiters: std::collections::HashMap::new(),
                broadcasts: std::collections::HashMap::new(),
                sol_broadcasts: std::collections::HashMap::new(),
                dapp_unlock: false,
                unlocked: false,
                locking: false,
                grant_write: crate::app_browser::GrantWrite::default(),
                site_rows: crate::app_browser::SiteRows::default(),
            });
            app.sync_browser();
        }
        let _ = events.drain();
        Outlet {
            events,
            frames,
            conn,
        }
    }

    /// Approves the shown Standard request as a user does (2026-11-18, S4 A7: the secret
    /// characterization's card step, `ui::tour_secrets`): the window is foreground (oracle), a
    /// tick arms it now, and a click on `승인` 1 s later approves it. Debug test builds only,
    /// like its user.
    #[cfg(debug_assertions)]
    pub(crate) fn approve_standard(&self) {
        set_signals(Some(Signals {
            foreground: true,
            enter_in_message: true,
            ..Signals::default()
        }));
        self.app().interaction(InteractionEvent::Tick);
        self.clock.advance(1_000);
        self.app().interaction(InteractionEvent::PointerPressed {
            inside: true,
            click_through: false,
            physical_down: true,
        });
        self.app().interaction(InteractionEvent::PointerReleased {
            physical_down: false,
        });
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Ok(mut app) = self.app.try_borrow_mut() {
            app.close_approval_window();
        }
        set_signals(None);
        set_host(None);
        stop_log();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A recorded dApp connection: the dispatcher's request queue, the frames it answers with and
/// the connection id.
pub(crate) struct Outlet {
    pub(crate) events: Arc<EventQueue>,
    pub(crate) frames: Receiver<crate::browser::Outbound>,
    pub(crate) conn: crate::browser::ConnId,
}

impl Outlet {
    /// Sends request number `n` (`method`, JSON `params`, `route`) on the connection, due
    /// `deadline_unix_ms`, and hands what the dispatcher queued to the App.
    pub(crate) fn send(
        &self,
        fixture: &Fixture,
        n: u8,
        method: &str,
        params: &str,
        route: &str,
        deadline_unix_ms: u64,
    ) {
        let frame = format!(
            concat!(
                r#"{{"namespace":"your-wallet","version":1,"role":"extension","kind":"request","#,
                r#""sessionId":"{session}","sequence":{n},"deadlineUnixMs":{deadline},"#,
                r#""profileInstallId":"{profile}","activationNonce":"{activation}","#,
                r#""requestId":"{request}","method":"{method}","params":{params},"#,
                r#""route":"{route}","context":{{"browserFamily":"chrome","#,
                r#""extensionId":"{extension}","tabId":17,"frameId":0,"#,
                r#""documentId":"document-17","topOrigin":"https://app.example","#,
                r#""frameOrigin":"https://app.example","documentLifecycle":"active","#,
                r#""channelNonce":"{channel}"}}}}"#
            ),
            session = "bb".repeat(32),
            n = n,
            deadline = deadline_unix_ms,
            profile = "aa".repeat(32),
            activation = format!("{}0c", "00".repeat(31)),
            request = format!("{n:02x}").repeat(16),
            method = method,
            params = params,
            route = route,
            extension = EXTENSION_ID,
            channel = format!("{}0d", "00".repeat(31)),
        );
        let core = fixture
            .app
            .borrow()
            .browser
            .as_ref()
            .map(|browser| Arc::clone(&browser.core));
        if let Some(core) = core {
            core.handle_frame(self.conn, frame.as_bytes());
        }
        for event in self.events.drain() {
            if let UiEvent::Dapp(event) = event {
                fixture.app().on_dapp_event(event);
            }
        }
    }

    /// The answers since the last call (results and provider errors; events skipped).
    pub(crate) fn answers(&self) -> Vec<Result<yw_json::Value, ProviderError>> {
        self.frames
            .try_iter()
            .filter_map(|frame| match frame {
                crate::browser::Outbound::Response { body, .. } => Some(body),
                crate::browser::Outbound::Event { .. } => None,
            })
            .collect()
    }
}

// ----- self-tests ---------------------------------------------------------------------------

/// The seams are inert without a fixture, and the test clock reads as documented.
#[test]
fn seams_are_inert_without_a_fixture_and_the_clock_steps() {
    assert_eq!(scripted(Read::Injected), None);
    assert!(!effect(Fx::Show));
    assert!(foreground_request("approval").is_none());
    assert!(!fail_open());
    assert!(take_log().is_empty());
    let clock = TestClock::stepping(10, 5);
    let shared = Arc::clone(&clock) as Arc<dyn Clock>;
    assert_eq!(shared.now_ms(), 10);
    assert_eq!(shared.now_unix_ms(), clock.unix_at(15));
    assert_eq!(shared.now_ms(), 20);
    clock.set_step(0);
    clock.set(100);
    clock.advance(1);
    assert_eq!((shared.now_ms(), clock.peek()), (101, 101));
}

/// No production code of yw-app reads the time except through the App's injected clock (S4
/// B1b, 2026-11-19; it replaces `every_app_time_wrapper_reads_the_test_clock`, which pinned that
/// the 18 wrappers read the A3 `TEST_CLOCK` first). Read-only source scan of `src` (the
/// `card_pcsc` precedent): a time source is named only in `system_clock.rs` (the clock itself:
/// one `monotonic_ms`, one `SystemTime`) and `browser/server.rs` (one `monotonic_ms`, the pipe
/// accept back-off warnings, shell only, plan critique B-13); test files and inline
/// `#[cfg(test)]` modules are not production code (temp-folder names, test ticks); `log_file.rs`,
/// `store.rs` and `store/*` read none outside their tests.
///
/// 2026-11-19 (B1 review): files are compared by their path below `src` (before, by bare file
/// name, so any `server.rs` passed), each exempt file by its number of uses (before, the whole
/// file was exempt), and a use is any `monotonic_ms`, `SystemTime` or `Instant` identifier in a
/// line that is not a comment, so a function pointer, an aliased import (`use
/// yw_win::time::monotonic_ms as tick`) or other spacing is found too (before, only the literal
/// texts `monotonic_ms()`, `SystemTime::now()` and `Instant::now()`).
#[test]
fn app_time_reads_go_through_the_clock() {
    fn sources(root: &std::path::Path, dir: &std::path::Path, found: &mut Vec<(String, String)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if path.is_dir() {
                if name != "tests" {
                    sources(root, &path, found);
                }
            } else if std::path::Path::new(&name)
                .extension()
                .is_some_and(|extension| extension == "rs")
                && name != "tests.rs"
                && !name.ends_with("_tests.rs")
                && !relative.starts_with("ui/tour")
                && !matches!(
                    relative.as_str(),
                    "app_approval_flow_support.rs" | "app_approval_smoke.rs" | "app/secret_seam.rs"
                )
            {
                found.push((relative, std::fs::read_to_string(&path).unwrap()));
            }
        }
    }
    /// The text without its comment lines and its `#[cfg(test)]` `mod … {` blocks (a top-level
    /// block ends at the first line that is `}`).
    fn production(text: &str) -> String {
        let mut kept = String::new();
        let mut lines = text.lines().peekable();
        while let Some(line) = lines.next() {
            if line == "#[cfg(test)]"
                && lines
                    .peek()
                    .is_some_and(|next| next.starts_with("mod ") && next.ends_with('{'))
            {
                for skipped in lines.by_ref() {
                    if skipped == "}" {
                        break;
                    }
                }
                continue;
            }
            if line.trim_start().starts_with("//") {
                continue;
            }
            kept.push_str(line);
            kept.push('\n');
        }
        kept
    }
    /// Uses of a time source: each `monotonic_ms`, `SystemTime` or `Instant` that is a whole
    /// identifier.
    fn uses(code: &str) -> usize {
        let identifier = |c: char| c.is_alphanumeric() || c == '_';
        ["monotonic_ms", "SystemTime", "Instant"]
            .iter()
            .map(|source| {
                code.match_indices(source)
                    .filter(|(at, _)| {
                        !code[..*at].chars().next_back().is_some_and(identifier)
                            && !code[*at + source.len()..]
                                .chars()
                                .next()
                                .is_some_and(identifier)
                    })
                    .count()
            })
            .sum()
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    sources(&root, &root, &mut found);
    assert!(found.len() > 50, "{}", found.len());
    let mut readers: Vec<(&str, usize)> = found
        .iter()
        .filter_map(|(path, text)| {
            let count = uses(&production(text));
            (count > 0).then_some((path.as_str(), count))
        })
        .collect();
    readers.sort_unstable();
    assert_eq!(readers, [("browser/server.rs", 1), ("system_clock.rs", 2)]);
}

/// No top-level approval or panel window of this process exists (real Win32 lookup).
fn assert_no_approval_window() {
    let pid = std::process::id();
    for class in [APPROVAL_CLASS, PANEL_CLASS] {
        assert!(
            ui::find_windows(class)
                .iter()
                .all(|(_, owner)| *owner != pid),
            "a {class} window of this process"
        );
    }
}

fn assert_hidden(fixture: &Fixture) {
    let app = fixture.app.borrow();
    let ui = app.evm.window.as_ref().expect("window open");
    // Real Win32 reads, not the scripted ones.
    assert!(ui.window.is_alive() && ui.window.is_hidden_or_minimized());
    assert!(ui.panel.is_hidden_or_minimized());
    assert!(!ui.window.is_foreground() && !ui.panel.is_foreground());
}

/// A3 self-test: a hidden host opens A01 that is never visible and never the foreground; every
/// call that could show or activate it was skipped (and traced); the prepare fixture, the App
/// and the gate share the test clock; the scripted oracle answers the gate's reads; one
/// physical Enter approves the Standard send exactly once (one key job, no re-simulation).
#[test]
#[ignore = "creates hidden approval windows (S4 flow harness, gate step s4fl)"]
#[expect(clippy::too_many_lines, reason = "one scenario, open to approval")]
fn hidden_approval_window_is_never_shown_and_the_seams_drive_it() {
    let fixture = Fixture::new("selftest", HostMode::Hidden);
    fixture.enqueue_sepolia_send();
    assert_hidden(&fixture);
    let opened = take_log();
    for fx in [
        Fx::CenterOn,
        Fx::Show,
        Fx::SetForeground("approval"),
        Fx::Flash,
        Fx::SetFocus,
    ] {
        assert!(
            opened.contains(&Logged::Effect {
                fx,
                performed: false
            }),
            "{fx:?} skipped: {opened:?}"
        );
    }
    assert!(
        !opened.iter().any(|entry| matches!(
            entry,
            Logged::Effect {
                performed: true,
                ..
            }
        )),
        "{opened:?}"
    );
    let jobs = fixture.rpc_jobs();
    let names: Vec<&str> = jobs.iter().map(RpcJob::name).collect();
    assert_eq!(names.len(), 1, "{names:?}");
    let Some(RpcJob::Prepare(job)) = jobs.into_iter().next() else {
        unreachable!("the preparation job");
    };
    fixture.answer_prepare(&job, "S2");
    assert_hidden(&fixture);
    {
        let app = fixture.app.borrow();
        let ui = app.evm.window.as_ref().expect("window open");
        assert!(ui.request.is_some(), "issued at the first Ready display");
        assert!(!ui.view.high, "S2 is a Standard send");
        assert_eq!(ui.session.gate.ready_at_ms, START_MS, "the test clock");
        assert_eq!(
            ui.prepared
                .as_ref()
                .map(|prepared| prepared.sim_received_ms),
            Some(START_MS),
            "the prepare fixture reads the same clock"
        );
        assert!(!ui.session.gate.is_foreground);
    }
    // The oracle answers the gate's foreground read although the real window is not foreground.
    set_signals(Some(Signals {
        foreground: true,
        enter_in_message: true,
        ..Signals::default()
    }));
    let _ = take_log();
    fixture.app().interaction(InteractionEvent::Tick);
    assert!(
        fixture
            .app
            .borrow()
            .evm
            .window
            .as_ref()
            .is_some_and(|ui| ui.session.gate.is_foreground)
    );
    assert_eq!(
        take_log(),
        [
            Logged::Read {
                read: Read::Foreground,
                value: true
            },
            Logged::Event {
                event: InteractionEvent::Tick,
                foreground: Some(true),
                focus: Some(Focus::Reject)
            }
        ]
    );
    assert!(fixture.key_jobs().is_empty());
    // The gate is foreground by the oracle only: the real windows stay hidden and background.
    assert_hidden(&fixture);
    // 1 s later a physical Enter on `승인` approves once: one key job, no re-simulation.
    fixture.clock.advance(1_000);
    if let Some(ui) = fixture.app().evm.window.as_mut() {
        ui.focus = Focus::Approve;
    }
    assert_hidden(&fixture);
    fixture.app().on_approval_key(super::VK_RETURN, false);
    let log = take_log();
    assert_eq!(
        log.get(..2),
        Some(
            &[
                Logged::Read {
                    read: Read::EnterInMessage,
                    value: true
                },
                Logged::Read {
                    read: Read::Injected,
                    value: false
                },
            ][..]
        ),
        "{log:?}"
    );
    assert!(log.contains(&Logged::Event {
        event: InteractionEvent::ApproveActivated { physical: true },
        foreground: Some(true),
        focus: Some(Focus::Approve)
    }));
    let keys: Vec<&str> = fixture.key_jobs().iter().map(KeyJob::name).collect();
    assert_eq!(keys, ["SignEvm"]);
    assert!(
        fixture.rpc_jobs().is_empty(),
        "a fresh simulation: no re-simulation"
    );
    // Consumed: the window closed (`finish_approval(Approved)`) and the main window had none to
    // raise (no main window in the fixture, so no `set_foreground` of it either).
    assert!(fixture.app.borrow().evm.window.is_none());
    assert!(!log.iter().any(|entry| matches!(
        entry,
        Logged::Effect {
            fx: Fx::SetForeground("main"),
            ..
        }
    )));
    // Nothing on the way to the approval showed or activated a window.
    assert!(
        !log.iter().any(|entry| matches!(
            entry,
            Logged::Effect {
                fx,
                performed: true,
            } if fx.hidden_skips()
        )),
        "{log:?}"
    );
    assert_no_approval_window();
}

/// A3 self-test: a refused window rejects the item, shows E-APP-009 and prepares nothing.
#[test]
#[ignore = "approval host seam (S4 flow harness, gate step s4fl)"]
fn a_refused_approval_window_rejects_with_app009() {
    let fixture = Fixture::new("failopen", HostMode::FailOpen);
    fixture.enqueue_sepolia_send();
    {
        let app = fixture.app.borrow();
        assert!(app.evm.window.is_none());
        assert!(app.evm.queue.is_empty());
        assert!(app.evm.slots.is_empty(), "the send slot is free again");
        assert!(
            app.banners
                .iter()
                .any(|banner| banner.code == Some(crate::errors::ErrorCode::App009))
        );
    }
    assert!(fixture.rpc_jobs().is_empty(), "no preparation");
    assert!(fixture.key_jobs().is_empty());
    // The refusal is the only effect: no window was created, shown or activated.
    assert_eq!(
        take_log(),
        [Logged::Effect {
            fx: Fx::CreateRefused,
            performed: false
        }]
    );
    assert_no_approval_window();
}

/// A3 self-test: the recorded outlet carries a dApp request through the real dispatcher (on the
/// shared clock) to the App and records its answer.
#[test]
#[ignore = "approval host seam (S4 flow harness, gate step s4fl)"]
fn the_outlet_records_a_dapp_answer() {
    let fixture = Fixture::new("outlet", HostMode::Hidden);
    let outlet = fixture.connect_outlet();
    let due = fixture.clock.unix_at(fixture.clock.peek() + 600_000);
    outlet.send(&fixture, 1, "eth_requestAccounts", "[]", "permission", due);
    let answers = outlet.answers();
    // No EVM account in the fixture: 4100 at once, no window (spec/05 §5).
    assert_eq!(answers, [Err(ProviderError::NoEvmAccount)]);
    assert!(fixture.app.borrow().evm.window.is_none());
    assert!(fixture.key_jobs().is_empty());
}
