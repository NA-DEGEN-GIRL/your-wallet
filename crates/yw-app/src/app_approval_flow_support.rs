//! Approval flow test seams and fixture (2026-11-18, S4 A3; spec/15 §11.4 S4, spec/09 §2.2).
//!
//! `cfg(test)` only: release builds compile none of this, and the production functions that
//! read it (every `now_ms`/`now_unix_ms` wrapper of the App, a few inline reads, the A01
//! trusted-signal reads and Win32 side effects, `open_approval`) behave exactly as before while
//! no seam is installed. Every seam is a thread-local of the test thread, set by [`Fixture`] and
//! cleared when it drops:
//!
//! - `TEST_CLOCK`: one [`TestClock`] (manual, or stepping by a fixed amount at every read)
//!   shared by the App wrappers, the prepare fixture and the test `BrowserCore`s
//!   ([`core_clock`]), so `sim_received_ms`, the site deadline and the App's own reads have one
//!   base (S4 critique A-9/B-19). B1a/B1b replace it with the injected `Clock`. The wrappers:
//!   `now_ms`/`now_unix_ms` of `app_approval`, `app_card`, `app_browser`, `app_evm`, `app`,
//!   `app_sol` (plan §4.5), and since the A3 review (2026-11-18) also those of `app_chain_sites`
//!   (SOL/BTC connect grant time, SIWS check), `app_btc` (its `BtcCtx` times: fee-quote
//!   freshness), `app_hypercore` (action nonce), `app_zec`, `app_book`, `app_received` and
//!   `app_reset` (`every_app_time_wrapper_reads_the_test_clock`). Inline reads: the consume
//!   time of `app_sol_dapp` and its tracking tick after a broadcast, and the EVM connect grant
//!   time in `app_browser`. Still on the real clock under a fixture (not on an approval path; B1b
//!   converts them): form-edit times (`app_evm_commands`, `app_sol_commands`), refresh and wait
//!   timers (`app_hypercore` `loaded_ms`, `app_zec`, `app_received`, `app_reset`,
//!   `app_rpc_import`, `app_extension`, `ui/screens_*`), `app_sidecar`'s backup time,
//!   `app_yubikey`'s password and idle times and `app_walletconnect`'s join wait.
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
    static TEST_CLOCK: RefCell<Option<Arc<TestClock>>> = const { RefCell::new(None) };
    static TEST_APPROVAL_HOST: Cell<Option<HostMode>> = const { Cell::new(None) };
    static TEST_SIGNALS: Cell<Option<Signals>> = const { Cell::new(None) };
    static TEST_INPUT_LOG: RefCell<Option<Vec<Logged>>> = const { RefCell::new(None) };
}

/// Installs (or with `None` removes) this thread's test clock.
pub(crate) fn set_clock(clock: Option<Arc<TestClock>>) {
    let _ = TEST_CLOCK.try_with(|slot| *slot.borrow_mut() = clock);
}

/// The installed test clock, if any.
pub(crate) fn installed_clock() -> Option<Arc<TestClock>> {
    TEST_CLOCK
        .try_with(|slot| slot.borrow().clone())
        .ok()
        .flatten()
}

/// The App wrappers' monotonic read while a test clock is installed.
pub(crate) fn clock_now_ms() -> Option<u64> {
    installed_clock().map(|clock| clock.read())
}

/// The App wrappers' wall-clock read while a test clock is installed.
pub(crate) fn clock_now_unix_ms() -> Option<u64> {
    installed_clock().map(|clock| clock.unix_at(clock.read()))
}

/// The clock of a test `BrowserCore`: the installed test clock, else the system clock (what
/// the tests that install none had before 2026-11-18).
pub(crate) fn core_clock() -> Arc<dyn Clock> {
    installed_clock().map_or_else(
        || Arc::new(crate::system_clock::SystemClock) as Arc<dyn Clock>,
        |clock| clock as Arc<dyn Clock>,
    )
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
        set_clock(Some(Arc::clone(&clock)));
        set_host(Some(host));
        set_signals(None);
        start_log();
        let mut apikeys = ApiKeys::default();
        // Never contacted: preparation jobs are answered by the fixture transport.
        apikeys.set_rpc(
            NetworkId::Eip155(11_155_111),
            &HttpsUrl::parse("https://rpc.example.test/").unwrap(),
        );
        let app = Rc::new(RefCell::new(App::new(
            Paths {
                data: dir.clone(),
                logs: dir.join("logs"),
            },
            true,
            Settings::default(),
            apikeys,
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
            core_clock(),
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
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Ok(mut app) = self.app.try_borrow_mut() {
            app.close_approval_window();
        }
        set_signals(None);
        set_host(None);
        set_clock(None);
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
    assert_eq!(clock_now_ms(), None);
    assert_eq!(clock_now_unix_ms(), None);
    assert_eq!(scripted(Read::Injected), None);
    assert!(!effect(Fx::Show));
    assert!(foreground_request("approval").is_none());
    assert!(!fail_open());
    assert!(take_log().is_empty());
    let clock = TestClock::stepping(10, 5);
    set_clock(Some(Arc::clone(&clock)));
    assert_eq!(clock_now_ms(), Some(10));
    assert_eq!(clock_now_unix_ms(), Some(clock.unix_at(15)));
    assert_eq!(core_clock().now_ms(), 20);
    clock.set_step(0);
    clock.set(100);
    clock.advance(1);
    assert_eq!((clock_now_ms(), clock.peek()), (Some(101), 101));
    set_clock(None);
    assert_eq!(clock_now_ms(), None);
}

/// Every `now_ms`/`now_unix_ms` wrapper of the App reads the test clock first (S4 A3 review,
/// 2026-11-18), so a fixture's App, its prepare fixture and its `BrowserCore` share one time base
/// on every approval path (the inline reads are listed in the module doc).
#[test]
fn every_app_time_wrapper_reads_the_test_clock() {
    let sources = [
        ("app.rs", include_str!("app.rs")),
        ("app_approval.rs", include_str!("app_approval.rs")),
        ("app_book.rs", include_str!("app_book.rs")),
        ("app_browser.rs", include_str!("app_browser.rs")),
        ("app_btc.rs", include_str!("app_btc.rs")),
        ("app_card.rs", include_str!("app_card.rs")),
        ("app_chain_sites.rs", include_str!("app_chain_sites.rs")),
        ("app_evm.rs", include_str!("app_evm.rs")),
        ("app_hypercore.rs", include_str!("app_hypercore.rs")),
        ("app_received.rs", include_str!("app_received.rs")),
        ("app_reset.rs", include_str!("app_reset.rs")),
        ("app_sol.rs", include_str!("app_sol.rs")),
        ("app_zec.rs", include_str!("app_zec.rs")),
    ];
    let mut wrappers = 0_usize;
    for (file, text) in sources {
        for (head, seam) in [
            ("fn now_ms() -> u64 {", "flow_support::clock_now_ms()"),
            (
                "fn now_unix_ms() -> u64 {",
                "flow_support::clock_now_unix_ms()",
            ),
        ] {
            for (at, _) in text.match_indices(head) {
                let rest = text.get(at..).unwrap_or_default();
                let body = rest
                    .find(
                        "
}
",
                    )
                    .and_then(|end| rest.get(..end));
                assert!(
                    body.is_some_and(|body| body.contains(seam)),
                    "{file}: {head} without the test clock"
                );
                wrappers += 1;
            }
        }
    }
    assert_eq!(wrappers, 18, "the wrappers of plan §4.5 and the A3 review");
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
