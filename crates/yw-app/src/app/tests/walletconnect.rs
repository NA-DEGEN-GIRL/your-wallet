//! The tests of `app_walletconnect.rs` that build an `App` (2026-11-21, S4 W0, spec/09 §2.1),
//! moved unchanged from its inline `mod tests` (which keeps the tests that build no `App`).
//! A `#[cfg(test)] #[path]` child of `crate::app_walletconnect`, not of `app::tests`: it keeps the
//! access of the inline module, so no production item of that file is widened.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use yw_engine::services::WcPlatform;

use crate::apikeys::ApiKeys;
use crate::app::{App, Paths};
use crate::app_browser::{BrowserUi, GrantWrite, SiteRows};
use crate::events::EventQueue;
use crate::settings::Settings;
use crate::walletconnect::verify::{P256Verify, VerifyHttp};
use crate::walletconnect::worker::{ConnectError, RelayConnector, RelayLink};

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
    let core = crate::browser::BrowserCore::new(
        "abcdefghijklmnopabcdefghijklmnop",
        Arc::clone(&events) as Arc<dyn crate::browser::DappSink>,
        Arc::clone(&app.clock),
    );
    app.browser = Some(BrowserUi {
        core,
        reads: Arc::new(crate::browser::read::ReadContext::new(None)),
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
