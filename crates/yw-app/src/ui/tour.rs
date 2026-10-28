//! Screenshot tour — **DEV ONLY**: an `#[ignore]` test compiled only for tests (never in a
//! release build). It renders the main screens and windows with fake, non-secret data and saves
//! each client area as a BMP (`yw_win::ui::capture`: synchronous repaint, then `BitBlt` from the
//! window's client DC) for
//! `scripts/screenshot-tour.ps1`, which converts them to `docs/screenshots/*.png`.
//!
//! Safety rules of the tour:
//! - the data folder is a throwaway temp directory (deleted at the end); `%LOCALAPPDATA%` is never
//!   read or written, no vault is created, no key worker or RPC worker runs;
//! - the only mnemonic is the public BIP39 test vector (entropy 0, built at run time), and every
//!   balance, site and transaction shown is made up;
//! - RPC URLs are `*.example.test` placeholders that are never contacted (approval windows are
//!   prepared against the fixture transport of `app_approval::smoke`);
//! - the capture exclusion of the tour's own secret windows is lifted right before capture with
//!   `dev_tour_lift_capture_exclusion` (debug builds only) — the app's code path is unchanged.
//!
//! `cargo test -p yw-app --lib ui::tour -- --ignored --nocapture` (`YW_TOUR_DIR` = output
//! folder, default `target/screenshot-tour`).

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::AtomicU64;
use std::sync::mpsc;

use yw_core::bip32::path::AccountIndex;
use yw_core::evm::address::Address;
use yw_core::evm::amount::U256;
use yw_core::evm::chain::SEPOLIA;
use yw_core::sol::SolAddress;
use yw_core::vault::EvmKeySource;
use yw_win::http::HttpsUrl;
use yw_win::ui::{
    self, CaptureExclusion, ClassSpec, Handler, Hwnd, Msg, Reply, Window, WindowKind, WindowSpec,
};

use crate::apikeys::ApiKeys;
use crate::app::{
    App, AppMode, MAIN_CLASS, Paths, Purpose, SECRET_INPUT_CLASS, SECRET_VIEW_CLASS, Screen,
    SettingsSection,
};
use crate::app_approval::smoke::{FixtureClock, FixtureRpc, fixture};
use crate::app_approval::{APPROVAL_CLASS, PANEL_CLASS};
use crate::app_evm::{AppApproval, BalanceState};
use crate::events::{BalanceSnapshot, JournalView};
use crate::flow::evm::prepare::{SendIntent, prepare};
use crate::flow::evm::{ChainCache, ChainCheck, SharedTransport};
use crate::meta::{Account, Meta, Tab};
use crate::network::{BtcNet, NetworkId, SolCluster};
use crate::settings::Settings;
use crate::ui::secret::{DisplaySecret, SecretKind};
use crate::workers::rpc::RpcJob;

const TIMER_CLASS: &str = "YourWalletV3TourTimer";
const SETTLE_MS: u32 = 450;

struct QuitOnTimer;

impl Handler for QuitOnTimer {
    fn on(&mut self, _window: &Window, msg: &Msg) -> Reply {
        if matches!(msg, Msg::Timer(1)) {
            ui::quit(0);
            return Reply::Handled(0);
        }
        Reply::Default
    }
}

/// Runs the message loop for `ms` milliseconds (layout, paint, timers).
fn pump(ms: u32) {
    let timer = ui::create_window(
        &WindowSpec::new(TIMER_CLASS, WindowKind::HiddenTopLevel),
        Box::new(QuitOnTimer),
    )
    .unwrap();
    timer.set_timer(1, ms).unwrap();
    let _ = ui::run_loop(&mut |_, _| {});
}

fn out_dir() -> PathBuf {
    std::env::var_os("YW_TOUR_DIR").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/screenshot-tour"),
        PathBuf::from,
    )
}

#[expect(clippy::print_stdout, reason = "the tour lists what it saved")]
fn save(target: Option<Hwnd>, name: &str) {
    let Some(target) = target else {
        println!("tour: {name} skipped (no window)");
        return;
    };
    pump(SETTLE_MS);
    yw_win::ui::capture::dev_tour_redraw(target);
    // The synchronous repaint above is the frame; no message is processed before the copy.
    yw_win::ui::capture::dev_tour_flush();
    let capture = yw_win::ui::capture::capture_client(target).unwrap();
    let path = out_dir().join(format!("{name}.bmp"));
    std::fs::write(&path, &capture.bmp).unwrap();
    println!(
        "tour: {} ({}x{})",
        path.display(),
        capture.width,
        capture.height
    );
}

fn main_hwnd(app: &Rc<RefCell<App>>) -> Option<Hwnd> {
    app.borrow().main.as_ref().map(Window::hwnd)
}

fn secret_hwnd(app: &Rc<RefCell<App>>) -> Option<Hwnd> {
    let state = app.borrow();
    let window = state.tour_secret_window()?;
    // DEV ONLY: the tour's own window holds the public test mnemonic at most.
    assert!(yw_win::ui::capture::dev_tour_lift_capture_exclusion(window));
    Some(window.hwnd())
}

fn approval_hwnd(app: &Rc<RefCell<App>>) -> Option<Hwnd> {
    app.borrow().tour_approval_window().map(Window::hwnd)
}

/// The public BIP39 test vector of entropy 0 (24 words), built at run time: what the create
/// flow shows (a new wallet always has 24 words).
fn test_phrase_24() -> String {
    let mut words = vec!["abandon"; 23];
    words.push("art");
    words.join(" ")
}

/// The widely used public 12-word test mnemonic (`abandon` × 11 + `about`, the M7/M8 smoke
/// wallet), built at run time: the wallet of the main screens.
fn test_phrase_12() -> String {
    let mut words = vec!["abandon"; 11];
    words.push("about");
    words.join(" ")
}

fn address_of(phrase: &str, index: u32) -> Address {
    yw_core::bip32::preview_evm_address(phrase, None, AccountIndex::new(index).unwrap()).unwrap()
}

/// Account index of the tour wallet (12 words).
fn evm_address(index: u32) -> Address {
    address_of(&test_phrase_12(), index)
}

/// The recipient of the tour's sends: account 0 of the 24-word vector, saved in the address
/// book (the `eth_simulateV1` fixtures S2/S4 send 0.01 ETH from 0x9858… to it).
fn recipient() -> Address {
    address_of(&test_phrase_24(), 0)
}

fn eth(milli: u64) -> U256 {
    U256::from_u64(milli)
        .checked_mul(U256::from_u64(1_000_000_000_000_000))
        .unwrap()
}

fn tour_settings() -> Settings {
    let mut settings = Settings {
        evm_chain_id: SEPOLIA,
        ..Settings::default()
    };
    settings.solana.cluster = SolCluster::Devnet;
    settings.bitcoin.network = BtcNet::Testnet4;
    settings
}

fn tour_apikeys() -> ApiKeys {
    let mut apikeys = ApiKeys::default();
    // Placeholders (`.test` is reserved, never resolved; nothing is contacted).
    for (network, url) in [
        (NetworkId::Eip155(SEPOLIA), "https://sepolia.example.test/"),
        (NetworkId::Eip155(1), "https://mainnet.example.test/"),
        (
            NetworkId::Solana(SolCluster::Devnet),
            "https://solana-devnet.example.test/",
        ),
        (
            NetworkId::Bitcoin(BtcNet::Testnet4),
            "https://btc-testnet4.example.test/",
        ),
    ] {
        apikeys.set_rpc(network, &HttpsUrl::parse(url).unwrap());
    }
    apikeys
}

fn tour_meta() -> Meta {
    let mut meta = Meta {
        evm_accounts: vec![
            Account {
                index: 0,
                label: "계정 1".to_owned(),
                address: evm_address(0).to_lower_hex(),
                hidden: false,
            },
            Account {
                index: 1,
                label: "저축".to_owned(),
                address: evm_address(1).to_lower_hex(),
                hidden: false,
            },
        ],
        sol_accounts: vec![Account {
            index: 0,
            label: "Solana 1".to_owned(),
            address: "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk".to_owned(),
            hidden: false,
        }],
        ..Meta::default()
    };
    let _ = meta.add_book(&crate::meta::BookEntry {
        address: recipient().to_lower_hex(),
        label: "테스트 받는 사람".to_owned(),
        verified: true,
        added_at_unix_ms: 1_793_000_000_000,
    });
    meta
}

fn register_classes() {
    for (name, secret, capture) in [
        (MAIN_CLASS, false, CaptureExclusion::Preferred),
        (SECRET_INPUT_CLASS, true, CaptureExclusion::Preferred),
        (SECRET_VIEW_CLASS, true, CaptureExclusion::Required),
        (APPROVAL_CLASS, false, CaptureExclusion::Preferred),
        (PANEL_CLASS, false, CaptureExclusion::Preferred),
        (TIMER_CLASS, false, CaptureExclusion::Preferred),
    ] {
        ui::register_class(&ClassSpec {
            name,
            secret,
            capture,
        })
        .unwrap();
    }
}

fn set_screen(app: &Rc<RefCell<App>>, mode: AppMode, screen: Screen) {
    let mut state = app.borrow_mut();
    state.mode = mode;
    state.set_screen(screen);
}

const UNLOCKED: AppMode = AppMode::Unlocked {
    alt_passphrase: false,
};

fn unlocked_state(state: &mut App) {
    state.mode = UNLOCKED;
    state.meta = Some(tour_meta());
    state.evm.journal = Some(JournalView {
        room: true,
        sol_room: true,
        btc_room: true,
        ..JournalView::default()
    });
    state.evm.chain_checks.insert(
        SEPOLIA,
        ChainCheck::Verified {
            genesis: yw_core::evm::chain::SEPOLIA_GENESIS,
            pinned_now: false,
        },
    );
    state.evm.balances.insert(
        SEPOLIA,
        BalanceState {
            snapshot: Some(BalanceSnapshot {
                block: 7_412_096,
                native: vec![(evm_address(0), eth(1_250)), (evm_address(1), eth(40))],
                tokens: Vec::new(),
            }),
            error: None,
            job: 0,
        },
    );
    let sol = SolAddress::parse("HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk").unwrap();
    state
        .sol
        .balances
        .insert((yw_core::sol::SolCluster::Devnet, sol), 2_500_000_000);
    if state.browser.is_none() {
        tour_browser(state);
    }
}

/// The browser bridge on a tour-only pipe name (`\\.\pipe\YourWallet.tour.<pid>`, never the
/// wallet's pipe; nobody connects to it) and two made-up connected sites.
fn tour_browser(state: &mut App) {
    use std::sync::Arc;
    let events = Arc::new(crate::events::EventQueue::new(Box::new(|| {})));
    let sink = Arc::clone(&events) as Arc<dyn crate::browser::DappSink>;
    let core = crate::browser::BrowserCore::new(
        crate::browser::pinned_extension_id().unwrap_or_default(),
        sink,
        Arc::new(crate::flow::evm::SystemClock),
    );
    let name = format!(r"\\.\pipe\YourWallet.tour.{}", std::process::id());
    let server = crate::browser::pinned_origin()
        .and_then(|origin| crate::browser::server::start(Arc::clone(&core), &name, origin).ok());
    state.browser = Some(crate::app_browser::BrowserUi {
        core,
        reads: Arc::new(crate::browser::read::ReadContext::new(None)),
        server,
        threads: Vec::new(),
        connections: 1,
        waiters: std::collections::VecDeque::new(),
        broadcasts: std::collections::HashMap::new(),
        dapp_unlock: false,
        unlocked: false,
    });
    let sites = [
        (
            "https://app.example.org",
            vec![evm_address(0)],
            1_793_074_000_000,
        ),
        (
            "http://localhost:5173",
            vec![evm_address(0), evm_address(1)],
            1_793_160_000_000,
        ),
    ]
    .into_iter()
    .filter_map(|(origin, accounts, at)| {
        Some(yw_core::policy::ConnectedSite {
            origin: yw_core::policy::BrowserOrigin::parse(origin)?,
            accounts,
            chain_id: SEPOLIA,
            granted_at_unix_ms: at,
        })
    })
    .collect::<Vec<_>>();
    if let Some(meta) = state.meta.as_mut() {
        meta.connected_sites = crate::browser::grants::sites_to_values(&sites);
    }
}

/// A testnet4 Bitcoin account with discovery done and two made-up verified UTXOs. The account key
/// is the synthetic test value of `screens_btc`'s tests (not derived from any mnemonic).
fn tour_btc(state: &mut App) {
    use yw_core::bip32::path::BtcChain;
    use yw_core::btc::meta::{ListedUtxo, VerifiedUtxo};
    use yw_core::btc::{BtcMeta, BtcNetwork, Discovery, OutPoint, Sats, Txid};
    const ACCOUNT: &str = "03b88e0fbe3f646337ed93bc0c0f3b843fcf7d2589e5ec884754e6402027a890b4";
    let account = yw_core::bip32::AccountXpub {
        pubkey: yw_core::hex::decode_array::<33>(ACCOUNT).unwrap(),
        chain_code: [7; 32],
    };
    let mut meta = BtcMeta::new(BtcNetwork::Testnet4, account);
    let mut discovery = Discovery::full();
    let mut first = true;
    while discovery.next_request().is_some() {
        discovery.observe(u64::from(first));
        first = false;
    }
    discovery.apply(&mut meta).unwrap();
    let utxos = [(0x5a, 1, 1_250_000, 118_903), (0x7c, 0, 300_000, 119_870)];
    let listed: Vec<ListedUtxo> = utxos
        .iter()
        .map(|(byte, vout, _, height)| ListedUtxo {
            outpoint: OutPoint {
                txid: Txid::from_bytes([*byte; 32]),
                vout: *vout,
            },
            chain: BtcChain::Receive,
            index: 0,
            height: *height,
        })
        .collect();
    let verified: Vec<VerifiedUtxo> = utxos
        .iter()
        .zip(&listed)
        .map(|((_, _, value, height), item)| VerifiedUtxo {
            outpoint: item.outpoint,
            value: Sats::new(*value).unwrap(),
            chain: BtcChain::Receive,
            index: 0,
            height: *height,
            is_coinbase: false,
            own: false,
        })
        .collect();
    let _ = meta.apply_refresh(&listed, &verified, &[], &[]);
    if let Some(app_meta) = state.meta.as_mut() {
        app_meta.btc = Some(Box::new(meta));
    }
    state.btc.tip = Some(120_100);
    state.btc.indexer_verified = true;
}

/// Opens the approval window for a Sepolia send and prepares it against `fixture_name`
/// (`S2` = simulation succeeded, `S4` = no simulation result).
fn approval(app: &Rc<RefCell<App>>, fixture_name: &str) {
    let (tx, rx) = mpsc::channel();
    {
        let mut state = app.borrow_mut();
        state.rpc_tx = Some(tx);
        state.enqueue_app(AppApproval {
            chain_id: SEPOLIA,
            account: evm_address(0),
            signer: EvmKeySource::Derived(AccountIndex::ZERO),
            intent: SendIntent {
                to: recipient(),
                value: U256::from_u64(10_000_000_000_000_000),
                data: Vec::new(),
                access_list: Vec::new(),
                dapp_gas: None,
                dapp_nonce: None,
            },
            replace: None,
        });
    }
    let job = loop {
        match rx.try_recv() {
            Ok(RpcJob::Prepare(job)) => break job,
            Ok(_) => {}
            Err(_) => unreachable!("no preparation job"),
        }
    };
    let transport: SharedTransport = std::sync::Arc::new(FixtureRpc {
        simulate: fixture(fixture_name),
    });
    let clock = FixtureClock {
        now_ms: AtomicU64::new(0),
    };
    let since = RefCell::new(None);
    let result = prepare(
        &transport,
        &mut ChainCache::default(),
        &job,
        &clock,
        &|at| {
            *since.borrow_mut() = Some(at);
        },
    );
    if let Some(at) = since.into_inner() {
        app.borrow_mut().on_simulating(job.job, at);
    }
    app.borrow_mut().on_prepared(result);
}

#[test]
#[ignore = "DEV ONLY: opens windows on the desktop and writes BMPs (scripts/screenshot-tour.ps1)"]
#[expect(clippy::too_many_lines, reason = "one scene after another")]
fn screenshot_tour() {
    register_classes();
    std::fs::create_dir_all(out_dir()).unwrap();
    let dir = std::env::temp_dir().join(format!("yw-tour-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let app = Rc::new(RefCell::new(App::new(
        Paths {
            data: dir.clone(),
            logs: dir.join("logs"),
        },
        false,
        tour_settings(),
        tour_apikeys(),
    )));
    App::create_main_window(&app).unwrap();
    {
        let mut state = app.borrow_mut();
        state.mode = AppMode::NoVault;
        state.screen = Screen::FirstRun;
        state.show_main();
    }

    // Onboarding.
    set_screen(&app, AppMode::NoVault, Screen::FirstRun);
    save(main_hwnd(&app), "01-welcome");
    set_screen(&app, AppMode::NoVault, Screen::CreateIntro);
    save(main_hwnd(&app), "02-create-start");
    app.borrow_mut()
        .open_input(SecretKind::SetPassword, Purpose::CreatePassword, false);
    app.borrow_mut().tour_type("correct horse battery");
    app.borrow_mut().tour_next_field();
    app.borrow_mut().tour_type("correct horse");
    save(secret_hwnd(&app), "03-create-password");
    set_screen(
        &app,
        AppMode::BackupPending,
        Screen::Processing("지갑을 만드는 중입니다. 몇 초 걸립니다."),
    );
    app.borrow_mut().tour_open_display(
        SecretKind::ShowMnemonic { create: true },
        Purpose::ShowForBackup,
        DisplaySecret {
            text: yw_core::secret::Zeroizing::new(test_phrase_24()),
            address: Some(recipient().to_checksum()),
            passphrase_note: false,
            copy_allowed: false,
        },
    );
    save(secret_hwnd(&app), "04-create-recovery-words");
    app.borrow_mut().open_input(
        SecretKind::Backup {
            positions: [3, 9, 16, 22],
        },
        Purpose::Backup,
        false,
    );
    app.borrow_mut().tour_type("abandon");
    save(secret_hwnd(&app), "05-create-backup-check");
    app.borrow_mut().close_secret();
    let endpoints = {
        let mut state = app.borrow_mut();
        state.meta = Some(tour_meta());
        // The done screen as on a fresh install: no RPC endpoint yet.
        core::mem::take(&mut state.apikeys)
    };
    set_screen(&app, UNLOCKED, Screen::Done);
    save(main_hwnd(&app), "06-create-done");
    app.borrow_mut().apikeys = endpoints;
    set_screen(&app, AppMode::NoVault, Screen::ImportIntro);
    save(main_hwnd(&app), "07-import-start");

    // Unlock.
    {
        let mut state = app.borrow_mut();
        state.meta = None;
    }
    set_screen(&app, AppMode::Locked, Screen::Locked);
    app.borrow_mut()
        .open_input(SecretKind::Unlock, Purpose::Unlock, false);
    app.borrow_mut().tour_type("correct horse battery");
    save(main_hwnd(&app), "08-locked");
    save(secret_hwnd(&app), "09-unlock-password");
    app.borrow_mut().close_secret();

    // Main screens.
    unlocked_state(&mut app.borrow_mut());
    set_screen(&app, UNLOCKED, Screen::Main);
    save(main_hwnd(&app), "10-main-evm");
    {
        let mut state = app.borrow_mut();
        state.evm.send.to_text = recipient().to_checksum();
        state.evm.send.recipient = Some((
            recipient(),
            vec![crate::flow::evm::form::AddressNote::Book {
                name: "테스트 받는 사람".to_owned(),
                verified: true,
            }],
        ));
        state.evm.send.amount = Some(U256::from_u64(10_000_000_000_000_000));
        state.evm.send.quote = Some(crate::flow::evm::form::Quote {
            gas_limit: 21_000,
            max_fee_per_gas: U256::from_u64(3_000_000_000),
            max_total: U256::from_u64(63_000_000_000_000),
            cap_violation: None,
            estimate_failed: false,
        });
        state.evm.send.amount_text = "0.01".to_owned();
    }
    set_screen(&app, UNLOCKED, Screen::Send);
    save(main_hwnd(&app), "11-send");
    set_screen(&app, UNLOCKED, Screen::Main);
    approval(&app, "S2");
    save(approval_hwnd(&app), "12-approval-simulated");
    app.borrow_mut().tour_reject_approval();
    approval(&app, "S4");
    save(approval_hwnd(&app), "13-approval-no-simulation");
    app.borrow_mut().tour_reject_approval();
    set_screen(&app, UNLOCKED, Screen::Receive);
    save(main_hwnd(&app), "14-receive");
    {
        let mut state = app.borrow_mut();
        if let Some(meta) = state.meta.as_mut() {
            meta.prefs.tab = Tab::Sol;
        }
    }
    set_screen(&app, UNLOCKED, Screen::Main);
    save(main_hwnd(&app), "15-main-solana");
    {
        let mut state = app.borrow_mut();
        if let Some(meta) = state.meta.as_mut() {
            meta.prefs.tab = Tab::Btc;
        }
        state.settings.bitcoin.enabled = true;
        tour_btc(&mut state);
    }
    set_screen(&app, UNLOCKED, Screen::Main);
    save(main_hwnd(&app), "16-main-bitcoin");
    {
        let mut state = app.borrow_mut();
        if let Some(meta) = state.meta.as_mut() {
            meta.prefs.tab = Tab::Evm;
        }
    }
    set_screen(&app, UNLOCKED, Screen::Settings(SettingsSection::Network));
    save(main_hwnd(&app), "17-settings-rpc");
    set_screen(&app, UNLOCKED, Screen::Sites);
    save(main_hwnd(&app), "18-sites");

    if let Some(browser) = app.borrow_mut().browser.as_mut() {
        browser.stop();
    }
    drop(app);
    let _ = std::fs::remove_dir_all(&dir);
}
