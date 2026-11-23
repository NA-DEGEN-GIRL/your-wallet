//! The tests of `app_walletconnect.rs` that build an `App` (2026-11-21, S4 W0, spec/09 §2.1),
//! moved unchanged from its inline `mod tests` (which keeps the tests that build no `App`).
//! It was a `#[cfg(test)] #[path]` child of `crate::app_walletconnect`, not of `app::tests`, to
//! keep the access of the inline module, so no production item of that file was widened. 2026-11-22
//! (S4d E0c, spec/09 §2.1): a child of `app::tests` (that file moves to yw-engine at S4d E1 and
//! these tests need `App`); what it reaches is `pub(crate)` now (test-only use):
//! `Wallet::wc_start`.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use yw_engine::services::WcPlatform;

use crate::app::{App, Paths};
use yw_engine::apikeys::ApiKeys;
use yw_engine::events::EventQueue;
use yw_engine::settings::Settings;
use yw_engine::wallet::app_browser::{BrowserUi, GrantWrite, SiteRows};
use yw_engine::walletconnect::verify::{P256Verify, VerifyHttp};
use yw_engine::walletconnect::worker::{ConnectError, RelayConnector, RelayLink};

/// How often each part was asked for: `[connector, verify_http, p256, connect]`.
type Counts = Arc<[AtomicUsize; 4]>;

/// A relay connector that never connects (no socket) and counts its calls.
struct NoRelay(Counts);

impl RelayConnector for NoRelay {
    fn connect(&mut self, _url: &str) -> Result<Arc<dyn RelayLink>, ConnectError> {
        self.0[3].fetch_add(1, Ordering::SeqCst);
        Err(ConnectError::Network)
    }
}

/// `WalletConnect` platform parts that open nothing and count what the app asks for.
struct CountingWc(Counts);

impl WcPlatform for CountingWc {
    fn connector(&self) -> Box<dyn RelayConnector> {
        self.0[0].fetch_add(1, Ordering::SeqCst);
        Box::new(NoRelay(Arc::clone(&self.0)))
    }

    fn verify_http(&self) -> Option<Box<dyn VerifyHttp + Send>> {
        self.0[1].fetch_add(1, Ordering::SeqCst);
        None
    }

    fn p256(&self) -> P256Verify {
        self.0[2].fetch_add(1, Ordering::SeqCst);
        |_, _, _, _| false
    }
}

/// An app with the dispatcher and the events queue the worker needs (no pipe server, no
/// window, nothing on disk).
fn app_with_browser(tag: &str) -> App {
    let dir = std::env::temp_dir().join(format!("yw-app-wc-{tag}-{}", std::process::id()));
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
        Arc::clone(&events) as Arc<dyn yw_engine::browser::DappSink>,
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
        site_rows: SiteRows::default(),
    });
    let (tx, _rx) = std::sync::mpsc::channel();
    app.attach_workers(events, Vec::new(), tx);
    assert!(!dir.exists(), "nothing written");
    app
}

fn counts(counts: &Counts) -> [usize; 4] {
    [0, 1, 2, 3].map(|i| counts[i].load(Ordering::SeqCst))
}

/// S4 P2 (spec/13 §4, §7; spec/15 §11.2): the relay worker starts from the injected
/// `Services` — the Verify client, the connector and the P-256 check are each asked for once
/// per start (counts only, not their order) and never again while the worker runs; without
/// `WalletConnect` parts no worker starts. No socket, HTTP session or CNG call: the counting
/// parts open nothing and no `Configure` is sent, so the worker never connects.
#[test]
fn the_relay_worker_starts_from_the_injected_services() {
    let mut app = app_with_browser("services");
    let shared: Counts = Arc::new([0, 0, 0, 0].map(AtomicUsize::new));
    app.services.walletconnect = Some(Box::new(CountingWc(Arc::clone(&shared))));
    app.wc_start();
    assert!(app.wc.handle.is_some());
    assert_eq!(counts(&shared), [1, 1, 1, 0]);
    app.wc_start();
    assert_eq!(counts(&shared), [1, 1, 1, 0], "one start per worker");
    app.wc_shutdown();
    assert!(app.wc.handle.is_none());
    assert_eq!(counts(&shared), [1, 1, 1, 0], "never connected");

    let mut app = app_with_browser("none");
    app.services.walletconnect = None;
    app.wc_start();
    assert!(app.wc.handle.is_none(), "no platform parts, no worker");
}

/// S4 P2 (spec/13 §4): the Windows services keep the relay user agent word `windows` (the same
/// `…/windows` bytes as before) and carry the `WalletConnect` parts. 2026-11-23 (spec/15 §11.4
/// S4d E1): moved here unchanged from the inline tests of `app_walletconnect` (the services are
/// the shell's `app::windows_services`).
#[test]
fn the_windows_services_keep_the_user_agent_word() {
    let services = crate::app::windows_services();
    assert_eq!(services.ua_platform, "windows");
    assert!(yw_engine::walletconnect::worker::relay_ua(services.ua_platform).ends_with("/windows"));
    assert!(services.walletconnect.is_some());
    assert_eq!(
        format!("{services:?}"),
        r#"Services { walletconnect: true, ua_platform: "windows", .. }"#
    );
}
