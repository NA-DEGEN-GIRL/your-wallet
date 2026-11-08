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
//! - RPC URLs are `*.example.test` placeholders that are never contacted (EVM approval windows
//!   are prepared against the fixture transport of `app_approval::smoke`, the Solana token
//!   approval against `SolTourRpc`);
//! - the AI explanation scene (M6) talks to a loopback mock on `127.0.0.1:<random port>` that the
//!   tour itself serves with one fixed, made-up answer; no external endpoint or key is used;
//! - the capture exclusion of the tour's own secret windows is lifted right before capture with
//!   `dev_tour_lift_capture_exclusion` (debug builds only) — the app's code path is unchanged.
//!
//! `cargo test -p yw-app --lib ui::tour::screenshot_tour -- --ignored --exact --nocapture`
//! (`YW_TOUR_DIR` = output folder, default `target/screenshot-tour`; a bare `ui::tour` filter
//! also runs the scroll check, `ui::tour::scroll`).

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
/// A made-up user token contract (shot 31, hidden like an unwanted airdrop).
const TOUR_AIRDROP: &str = "0x00000000000000000000000000000000000a1d40";
const SETTLE_MS: u32 = 450;
/// The public key at `m/44'/1'/0'/0/0` of the public test mnemonic (`abandon` × 11 + `about`):
/// the well-known BIP44 testnet vector, shown as the tour's Zcash testnet account (shot 48).
const TOUR_ZEC_TESTNET_KEY: &str =
    "02a7451395735369f2ecdfc829c0f774e88ef1303dfe5b2f04dbaab30a535dfdd6";

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
    let _ = meta.add_sol_book(&crate::meta::SolBookEntry {
        address: SOL_RECIPIENT.to_owned(),
        label: "테스트 받는 사람".to_owned(),
        verified: true,
        added_at_unix_ms: 1_793_000_000_000,
    });
    // S14 (2026-11-06): a second, unverified EVM entry (the well-known burn address) and a
    // Bitcoin testnet4 entry (the BIP173 testnet example address); the test recipients are
    // favorites, so the send forms show them as `즐겨찾기` chips.
    let extra = [
        (
            crate::meta::BookChain::Evm,
            "0x000000000000000000000000000000000000dead",
            "시험용 소각 주소",
        ),
        (
            crate::meta::BookChain::Btc,
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            "BIP173 예시 주소",
        ),
    ];
    for (chain, address, label) in extra {
        let _ = meta.add_contact(&crate::meta::Contact {
            chain,
            address: address.to_owned(),
            label: label.to_owned(),
            verified: false,
            added_at_unix_ms: 1_793_000_000_000,
        });
    }
    meta.set_favorite(
        crate::meta::BookChain::Evm,
        &recipient().to_lower_hex(),
        true,
    );
    meta.set_favorite(crate::meta::BookChain::Sol, SOL_RECIPIENT, true);
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
    // Made-up allowlisted token holding (devnet USDC, 25.000000) for the token card.
    if let Some(entry) =
        yw_core::sol::template::spl_entries(yw_core::sol::SolCluster::Devnet).next()
    {
        state.sol.tokens.insert(
            (yw_core::sol::SolCluster::Devnet, sol),
            vec![(entry, yw_core::sol::token::TokenHolding::Active(25_000_000))],
        );
    }
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
        pipe_error: None,
        threads: Vec::new(),
        connections: 1,
        waiters: std::collections::HashMap::new(),
        broadcasts: std::collections::HashMap::new(),
        dapp_unlock: false,
        unlocked: false,
        locking: false,
        grant_write: crate::app_browser::GrantWrite::default(),
        site_rows: crate::app_browser::SiteRows::default(),
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

/// A testnet4 Bitcoin account with discovery done and two made-up verified UTXOs, in
/// fixed-address mode (the default). The account node is the public testnet4 node
/// `m/84'/1'/0'` of the tour's `abandon`×11 `about` wallet (spec/08 §14.1), so the receive
/// screen shows its real first address `m/84'/1'/0'/0/0`.
fn tour_btc(state: &mut App) {
    use yw_core::bip32::path::BtcChain;
    use yw_core::btc::meta::{ListedUtxo, VerifiedUtxo};
    use yw_core::btc::{BtcMeta, BtcNetwork, Discovery, OutPoint, Sats, Txid};
    const ACCOUNT: &str = "03b88e0fbe3f646337ed93bc0c0f3b843fcf7d2589e5ec884754e6402027a890b4";
    const CHAIN_CODE: &str = "3c8c2037ee4c1621da0d348db51163709a622d0d2838dde6d8419c51f6301c62";
    let account = yw_core::bip32::AccountXpub {
        pubkey: yw_core::hex::decode_array::<33>(ACCOUNT).unwrap(),
        chain_code: yw_core::hex::decode_array::<32>(CHAIN_CODE).unwrap(),
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
    // An imported key's account next to it (public data only: the BIP84 test vector's public key
    // used as a testnet4 Taproot key), with one made-up verified output.
    let imported = yw_core::btc::BtcAccountKey::single(
        [0x42; 16],
        yw_core::btc::ScriptType::P2tr,
        yw_core::btc::BtcPubKey::parse(
            &yw_core::hex::decode(
                "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c",
            )
            .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let mut single = BtcMeta::with_key(BtcNetwork::Testnet4, imported);
    let listed = vec![ListedUtxo {
        outpoint: OutPoint {
            txid: Txid::from_bytes([0x3e; 32]),
            vout: 0,
        },
        chain: BtcChain::Receive,
        index: 0,
        height: 119_400,
    }];
    let verified = vec![VerifiedUtxo {
        outpoint: listed[0].outpoint,
        value: Sats::new(420_000).unwrap(),
        chain: BtcChain::Receive,
        index: 0,
        height: 119_400,
        is_coinbase: false,
        own: false,
    }];
    let _ = single.apply_refresh(&listed, &verified, &[], &[]);
    if let Some(app_meta) = state.meta.as_mut() {
        app_meta.btc = Some(Box::new(meta));
        let _ = app_meta.btc_accounts.upsert(single);
    }
    state.btc.tip = Some(120_100);
    state.btc.indexer_verified = true;
}

/// The Solana recipient of the token scenes: account 1 of the 12-word test mnemonic
/// (`m/44'/501'/1'/0'`, spec/07 §17.1), saved in the address book.
const SOL_RECIPIENT: &str = "Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb";

/// A made-up devnet for the SPL approval scene (never contacted): the sender holds 2.5 SOL and
/// 25 USDC, the recipient has no USDC token account yet (so the ATA is created and its rent
/// shown), rents are the 2026-10-28 live values.
struct SolTourRpc;

impl crate::rpc::Transport for SolTourRpc {
    fn post_json(
        &self,
        _url: &HttpsUrl,
        body: &[u8],
        _max_response: usize,
    ) -> Result<crate::rpc::HttpReply, yw_win::http::HttpError> {
        use yw_json::{Limits, Object, Value};
        let request = yw_json::parse(body, &Limits::REQUEST)
            .map_err(|_| yw_win::http::HttpError::InvalidUrl)?;
        let object = request
            .as_object()
            .ok_or(yw_win::http::HttpError::InvalidUrl)?;
        let id = object.get("id").cloned().unwrap_or(Value::Null);
        let method = object.get("method").and_then(Value::as_str).unwrap_or("");
        let first = object
            .get("params")
            .and_then(Value::as_array)
            .and_then(|params| params.first())
            .map(|value| match value {
                Value::String(text) => text.clone(),
                other => String::from_utf8(yw_json::to_vec(other)).unwrap_or_default(),
            })
            .unwrap_or_default();
        let entry = yw_core::sol::template::spl_entries(yw_core::sol::SolCluster::Devnet)
            .next()
            .unwrap();
        let from = SolAddress::parse("HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk").unwrap();
        let ata = |wallet: &SolAddress| {
            yw_core::sol::pda::associated_token_address(wallet, &entry.token_program, &entry.mint)
                .unwrap()
                .0
                .to_base58()
        };
        let account = |data: &[u8]| {
            format!(
                "{{\"data\":[\"{}\",\"base64\"],\"executable\":false,\"lamports\":1461600,\"owner\":\"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA\",\"rentEpoch\":0,\"space\":{}}}",
                crate::sol::rpc::base64(data),
                data.len()
            )
        };
        let context = |value: &str| format!("{{\"context\":{{\"slot\":7}},\"value\":{value}}}");
        let result = match method {
            "getGenesisHash" => "\"EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG\"".to_owned(),
            "getBalance" => context("2500000000"),
            "getAccountInfo" if first == entry.mint.to_base58() => {
                let mut mint = vec![0_u8; 82];
                mint[44] = entry.decimals;
                mint[45] = 1;
                context(&account(&mint))
            }
            "getAccountInfo" if first == ata(&from) => {
                let mut token = vec![0_u8; 165];
                token[0..32].copy_from_slice(entry.mint.as_bytes());
                token[32..64].copy_from_slice(from.as_bytes());
                token[64..72].copy_from_slice(&25_000_000_u64.to_le_bytes());
                token[108] = 1;
                context(&account(&token))
            }
            "getAccountInfo" => context("null"),
            "getMinimumBalanceForRentExemption" if first == "165" => "1488440".to_owned(),
            "getMinimumBalanceForRentExemption" => "650240".to_owned(),
            "getRecentPrioritizationFees" => "[{\"slot\":1,\"prioritizationFee\":0}]".to_owned(),
            "getLatestBlockhash" => context(
                "{\"blockhash\":\"US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx\",\"lastValidBlockHeight\":1150}",
            ),
            "getFeeForMessage" => context("5000"),
            "simulateTransaction" => context(
                "{\"err\":null,\"logs\":[],\"accounts\":null,\"unitsConsumed\":15423,\"returnData\":null}",
            ),
            _ => "null".to_owned(),
        };
        let value = yw_json::parse(result.as_bytes(), &Limits::RESPONSE).unwrap_or(Value::Null);
        let pairs = vec![
            ("jsonrpc".to_owned(), Value::String("2.0".to_owned())),
            ("id".to_owned(), id),
            ("result".to_owned(), value),
        ];
        let body = Object::from_pairs(pairs)
            .map_or_else(Vec::new, |object| yw_json::to_vec(&Value::Object(object)));
        Ok(crate::rpc::HttpReply { status: 200, body })
    }
}

/// `검토` of the prepared Solana send form: the approval window opens and its step-2 preview is
/// answered by [`SolTourRpc`] as the RPC worker would deliver it (no key, nothing signed).
fn sol_approval(app: &Rc<RefCell<App>>) {
    let (tx, rx) = mpsc::channel();
    {
        let mut state = app.borrow_mut();
        state.rpc_tx = Some(tx);
        state.sol_review();
    }
    let job = loop {
        match rx.try_recv() {
            Ok(RpcJob::SolPreview(job)) => break job,
            Ok(_) => {}
            Err(_) => unreachable!("no Solana preview job"),
        }
    };
    let result = crate::sol::flow::preview(&SolTourRpc, &job);
    app.borrow_mut()
        .sol_rpc_event(crate::events::RpcEvent::SolPreviewed(Box::new(result)));
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

/// The made-up AI answer of the tour: for the S2 send (0.01 `SepoliaETH` from account 0 to the
/// address-book recipient), or for the settings' connection-test sample (`0x…dEaD` →
/// `0x…beef`) when the request carries that sample.
fn tour_llm_answer(request: &[u8]) -> Vec<u8> {
    use crate::text::{json_object, json_str};
    let sample =
        String::from_utf8_lossy(request).contains("000000000000000000000000000000000000dead");
    let (from, to, summary) = if sample {
        (
            crate::app_llm::SAMPLE_FROM.to_ascii_lowercase(),
            crate::app_llm::SAMPLE_TO.to_owned(),
            format!(
                "표본 요청입니다. 실행되면 {}에서 0.01 SepoliaETH가 {}로 이동합니다. 이 요청에는 시뮬레이션 결과가 없습니다.",
                crate::app_llm::SAMPLE_FROM,
                crate::app_llm::SAMPLE_TO
            ),
        )
    } else {
        (
            evm_address(0).to_lower_hex(),
            recipient().to_lower_hex(),
            format!(
                "이 거래가 실행되면 내 계정 {}에서 0.01 SepoliaETH가 받는 주소 {}로 이동합니다. 시뮬레이션에서도 내 SepoliaETH 잔액이 0.01 줄어들었고, 토큰 권한이 바뀌는 내용은 없습니다.",
                evm_address(0).to_checksum(),
                recipient().to_checksum()
            ),
        )
    };
    let content = json_object(vec![
        ("summary", json_str(&summary)),
        (
            "actions",
            yw_json::Value::Array(vec![json_object(vec![
                ("type", json_str("send")),
                ("asset", json_str("native")),
                ("amount", json_str("0.01")),
                ("from", json_str(&from)),
                ("to", json_str(&to)),
            ])]),
        ),
        (
            "unknowns",
            yw_json::Value::Array(vec![json_str(
                "받는 주소의 주인이 누구인지는 입력 데이터만으로 알 수 없습니다.",
            )]),
        ),
    ]);
    let content = String::from_utf8(yw_json::to_vec(&content)).unwrap();
    yw_json::to_vec(&json_object(vec![
        ("object", json_str("chat.completion")),
        (
            "choices",
            yw_json::Value::Array(vec![json_object(vec![
                (
                    "message",
                    json_object(vec![
                        ("role", json_str("assistant")),
                        ("content", json_str(&content)),
                    ]),
                ),
                ("finish_reason", json_str("stop")),
            ])]),
        ),
    ]))
}

/// A loopback chat-completions mock (DEV ONLY, tour process only): every request gets
/// [`tour_llm_answer`]. Returns the endpoint URL.
fn tour_llm_mock() -> String {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                continue;
            };
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
            let mut data = Vec::new();
            let mut buffer = [0_u8; 8_192];
            let mut expected = None;
            loop {
                match stream.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => data.extend_from_slice(&buffer[..read]),
                }
                if expected.is_none()
                    && let Some(end) = data.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    let head = String::from_utf8_lossy(&data[..end]).to_ascii_lowercase();
                    let length = head
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    expected = Some(end + 4 + length);
                }
                if expected.is_some_and(|total| data.len() >= total) {
                    break;
                }
            }
            let body = tour_llm_answer(&data);
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
        }
    });
    format!("http://127.0.0.1:{port}/v1/chat/completions")
}

/// A dApp `eth_sendTransaction` from the connected `https://app.example.org` (0.01 `SepoliaETH` to
/// the address-book recipient), prepared against the S2 fixture like [`approval`].
fn site_approval(app: &Rc<RefCell<App>>) {
    use crate::browser::envelope::{Correlation, Id16, Id32};
    use crate::browser::params::TxParams;
    use crate::browser::{DappEvent, Reply, SiteKind, SiteRequest};
    let (tx, rx) = mpsc::channel();
    {
        let mut state = app.borrow_mut();
        state.rpc_tx = Some(tx);
        let site = SiteRequest {
            reply: Reply {
                conn: 1,
                correlation: Correlation {
                    session_id: Id32([1; 32]),
                    sequence: 1,
                    activation_nonce: Id32([2; 32]),
                    request_id: Id16([3; 16]),
                },
            },
            origin: yw_core::policy::BrowserOrigin::parse("https://app.example.org").unwrap(),
            chain_id: SEPOLIA,
            deadline_ms: yw_win::time::monotonic_ms().saturating_add(600_000),
            method: yw_core::policy::Method::SendTransaction,
            kind: SiteKind::Send(Box::new(TxParams {
                from: evm_address(0),
                to: recipient(),
                value: U256::from_u64(10_000_000_000_000_000),
                data: Vec::new(),
                gas: None,
                nonce: None,
                chain_id: Some(SEPOLIA),
                fee_fields: false,
                access_list: Vec::new(),
            })),
            compat_mode: None,
        };
        state.on_dapp_event(DappEvent::Request(Box::new(site)));
    }
    let job = loop {
        match rx.try_recv() {
            Ok(RpcJob::Prepare(job)) => break job,
            Ok(_) => {}
            Err(_) => unreachable!("no preparation job"),
        }
    };
    let transport: SharedTransport = std::sync::Arc::new(FixtureRpc {
        simulate: fixture("S2"),
    });
    let clock = FixtureClock {
        now_ms: AtomicU64::new(0),
    };
    let result = prepare(
        &transport,
        &mut ChainCache::default(),
        &job,
        &clock,
        &|_| {},
    );
    app.borrow_mut().on_prepared(result);
}

/// A dApp request from `origin` (no RPC needed: connect windows and message signing).
fn dapp_request(
    app: &Rc<RefCell<App>>,
    origin: &str,
    method: yw_core::policy::Method,
    kind: crate::browser::SiteKind,
) {
    use crate::browser::envelope::{Correlation, Id16, Id32};
    use crate::browser::{DappEvent, Reply, SiteRequest};
    use std::sync::atomic::{AtomicU8, Ordering};
    // A fresh request id and sequence per request (a repeated id is a duplicate).
    static NEXT: AtomicU8 = AtomicU8::new(10);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let site = SiteRequest {
        reply: Reply {
            conn: 1,
            correlation: Correlation {
                session_id: Id32([1; 32]),
                sequence: u64::from(n),
                activation_nonce: Id32([2; 32]),
                request_id: Id16([n; 16]),
            },
        },
        origin: yw_core::policy::BrowserOrigin::parse(origin).unwrap(),
        chain_id: SEPOLIA,
        deadline_ms: yw_win::time::monotonic_ms().saturating_add(600_000),
        method,
        kind,
        compat_mode: None,
    };
    app.borrow_mut()
        .on_dapp_event(DappEvent::Request(Box::new(site)));
}

/// Made-up Solana and Bitcoin connections of `https://app.example.org` (the tour's own browser
/// core; nothing is written): Solana account 0, and the Bitcoin native segwit account 0 for
/// payments with the imported Taproot key for ordinals (testnet4).
fn tour_chain_grants(state: &App) {
    let origin = yw_core::policy::BrowserOrigin::parse("https://app.example.org").unwrap();
    let sol = SolAddress::parse("HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk").unwrap();
    let rows = state.btc_dapp_rows();
    let pick = |script: yw_core::btc::ScriptType, purpose: yw_core::policy::BtcPurpose| {
        rows.iter()
            .find(|row| row.entry.script_type == script)
            .map(|row| yw_core::policy::BtcGrantAddress {
                purpose,
                ..row.entry.clone()
            })
    };
    let addresses: Vec<_> = [
        pick(
            yw_core::btc::ScriptType::P2wpkh,
            yw_core::policy::BtcPurpose::Payment,
        ),
        pick(
            yw_core::btc::ScriptType::P2tr,
            yw_core::policy::BtcPurpose::Ordinals,
        ),
    ]
    .into_iter()
    .flatten()
    .collect();
    if let Some(browser) = state.browser.as_ref() {
        browser.core.upsert_sol_grant(yw_core::policy::SolGrant {
            origin: origin.clone(),
            public: sol.to_bytes(),
            granted_at_unix_ms: 1_793_246_000_000,
        });
        if let Some(grant) = yw_core::policy::BtcGrant::new(
            origin,
            yw_core::btc::BtcNetwork::Testnet4,
            addresses,
            1_793_247_000_000,
        ) {
            browser.core.upsert_btc_grant(grant);
        }
    }
}

/// Pumps until the AI panel left `Waiting`/`Requesting` (at most 5 s).
fn wait_for_ai(app: &Rc<RefCell<App>>) {
    for _ in 0..50 {
        pump(100);
        app.borrow_mut().tour_drain_events();
        let state = app.borrow().tour_ai_state();
        if !matches!(
            state,
            Some(
                crate::explain::AiPanelState::Waiting
                    | crate::explain::AiPanelState::Requesting { .. }
            )
        ) {
            return;
        }
    }
}

/// The `YubiKey` scenes (spec/10 §7, §9.2): the wizard's four steps, W12, settings → `YubiKey`
/// and W11. No card and no key worker: the preview and the record are computed here from the
/// public test mnemonic (`abandon`×11 `about`) — SIG = EVM 0, AUT = Bitcoin P2WPKH 0 (testnet4),
/// PIV 82 = Solana 0 — and the serial `12345678` is made up.
#[expect(clippy::too_many_lines, reason = "one scene after another")]
fn tour_yubikey(app: &Rc<RefCell<App>>) {
    use yw_core::btc::ScriptType;
    use yw_core::yubikey::Firmware;
    use yw_core::yubikey::enrol::{DefaultsSeen, Enrolled};
    use yw_core::yubikey::plan::{CardSlot, KeyRole, PgpKey, PivSlot, PlannedSlot};
    use yw_core::yubikey::record::{HwKeyRecord, RecordedSlot};

    use crate::app_yubikey::{WizardOrigin, WizardStep, YkPurpose, YkWizard};
    use crate::ui::secret::CardSecretKind;
    use crate::workers::key::yubikey::YkPreview;

    let network = app.borrow().yk_network();
    let seed = *yw_core::bip39::Mnemonic::parse(&test_phrase_12())
        .unwrap()
        .to_seed(&yw_core::password::Bip39Passphrase::empty())
        .unwrap()
        .expose();
    let slots = vec![
        PlannedSlot::recommended(
            CardSlot::OpenPgp(PgpKey::Sig),
            KeyRole::Evm {
                index: AccountIndex::ZERO,
                btc: None,
            },
        ),
        PlannedSlot::recommended(
            CardSlot::OpenPgp(PgpKey::Aut),
            KeyRole::Btc {
                network,
                script: ScriptType::P2wpkh,
                index: 0,
            },
        ),
        PlannedSlot::recommended(
            CardSlot::Piv(PivSlot::new(0x82).unwrap()),
            KeyRole::Sol {
                index: AccountIndex::ZERO,
            },
        ),
    ];
    let lines = yw_core::yubikey::enrol::preview_seed(&seed, &slots).unwrap();
    let (fingerprint, _) = yw_core::yubikey::enrol::seed_identity(&seed).unwrap();
    let record = HwKeyRecord {
        serial: 12_345_678,
        firmware: Firmware::new(5, 7, 4),
        fingerprint,
        slots: lines
            .iter()
            .map(|line| RecordedSlot {
                slot: line.planned.slot,
                role: line.planned.role,
                touch: line.planned.touch,
                pin: line.planned.pin,
                public: line.public,
                path_known: true,
            })
            .collect(),
    };
    {
        let mut state = app.borrow_mut();
        let mut wizard = YkWizard::new(WizardOrigin::Vault, &[], network);
        wizard.slots.clone_from(&slots);
        state.card.wizard = Some(wizard);
    }
    set_screen(app, UNLOCKED, Screen::YubiKey);
    save(main_hwnd(app), "37-yubikey-slots");
    let step = |app: &Rc<RefCell<App>>, change: &dyn Fn(&mut YkWizard)| {
        let mut state = app.borrow_mut();
        if let Some(wizard) = state.card.wizard.as_mut() {
            change(wizard);
        }
        state.scroll = 0;
        state.refresh();
    };
    step(app, &|wizard| {
        wizard.step = WizardStep::Confirm;
        wizard.seed_held = true;
        wizard.preview = Some(YkPreview {
            lines: lines.clone(),
            same_as_vault: false,
            plan: Ok(()),
        });
    });
    save(main_hwnd(app), "38-yubikey-confirm");
    step(app, &|wizard| wizard.step = WizardStep::Credentials);
    save(main_hwnd(app), "39-yubikey-credentials");
    app.borrow_mut().open_input(
        SecretKind::CardSecret(CardSecretKind::AdminPin),
        Purpose::YubiKey(YkPurpose::AdminPin),
        false,
    );
    app.borrow_mut().tour_type("12345678");
    save(secret_hwnd(app), "40-yubikey-admin-pin");
    app.borrow_mut().close_secret();
    app.borrow_mut().card.records = vec![record.clone()];
    step(app, &|wizard| {
        wizard.step = WizardStep::Result;
        let defaults = DefaultsSeen {
            openpgp_admin: true,
            piv_pin: true,
            piv_management: true,
            piv_management_protected: false,
        };
        wizard.defaults = defaults;
        wizard.enrolled = Some(Enrolled {
            record: record.clone(),
            defaults,
        });
        wizard.check = Some(
            record
                .slots
                .iter()
                .map(|slot| format!("{} — 공개키가 기록과 같습니다 ✓", slot.slot.label()))
                .collect(),
        );
    });
    save(main_hwnd(app), "41-yubikey-result");
    app.borrow_mut().card.wizard = None;
    set_screen(app, UNLOCKED, Screen::Settings(SettingsSection::YubiKey));
    save(main_hwnd(app), "42-settings-yubikey");
    // W11: the card step of an approved EVM send of the YubiKey account (made-up step id).
    set_screen(app, UNLOCKED, Screen::Main);
    app.borrow_mut().open_input(
        SecretKind::CardPin {
            min: 6,
            max: 127,
            touches: 1,
        },
        Purpose::CardSign(0),
        false,
    );
    app.borrow_mut().with_form(|form| {
        form.set_details(vec![
            "서명할 키: EVM 계정 0 (m/44'/60'/0'/0/0)".to_owned(),
            "이 키를 가진 YubiKey: #12345678".to_owned(),
        ]);
    });
    app.borrow_mut().tour_type("123456");
    save(secret_hwnd(app), "43-yubikey-card-pin");
    app.borrow_mut().close_secret();
    app.borrow_mut().card.records.clear();
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
            text: yw_core::secret::SecretString::from_zeroizing(yw_core::secret::Zeroizing::new(
                test_phrase_24(),
            )),
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
    {
        // "개인키로 시작하기" (S18) with a Bitcoin key: the address-type radios.
        let mut state = app.borrow_mut();
        state.keys.start.chain = yw_core::keyimport::ImportChain::Btc;
        state.keys.start.script = yw_core::btc::ScriptType::P2tr;
    }
    set_screen(&app, AppMode::NoVault, Screen::KeyStartIntro);
    save(main_hwnd(&app), "24-key-start-bitcoin");
    app.borrow_mut().keys.start = crate::app_keys::KeyStartFlow::default();
    // The YubiKey wallet (spec/10 §7.1-1): S01 shows every way on its first view now
    // (2026-11-08), so scene 35 is where a new YubiKey wallet ends — S08 with the RPC step.
    app.borrow_mut().done_yubikey = Some(crate::app_yubikey::YkDone::Created(12_345_678));
    set_screen(&app, AppMode::NoVault, Screen::Done);
    save(main_hwnd(&app), "35-yubikey-done");
    app.borrow_mut().done_yubikey = None;
    set_screen(&app, AppMode::NoVault, Screen::YubiKeyWalletIntro);
    save(main_hwnd(&app), "36-yubikey-wallet-start");

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
    {
        // S22 지갑 초기화 from the lock screen: the phrase typed, the hold not started. The file
        // list is made up (the tour's data folder has no wallet files).
        let mut state = app.borrow_mut();
        state.open_reset();
        state.reset.files = [
            "vault.ywv",
            "vault.ywv.prev",
            "meta.ywm",
            "meta.ywm.prev",
            "journal.ywj",
        ]
        .map(str::to_owned)
        .to_vec();
        state.refresh();
        state
            .controls
            .set_text(crate::ui::screens_reset::ids::RESET_PHRASE, "초기화");
        state.reset.phrase_ok = true;
        state.refresh();
    }
    save(main_hwnd(&app), "44-wallet-reset");
    app.borrow_mut().cancel_reset();

    // Main screens.
    unlocked_state(&mut app.borrow_mut());
    set_screen(&app, UNLOCKED, Screen::Main);
    save(main_hwnd(&app), "10-main-evm");
    {
        // The token card (2026-11-03): a made-up airdrop token hidden with the hidden list open,
        // `잔액 0인 토큰 숨기기` on (WETH 0 is tucked away), made-up USDC balance; scrolled to it.
        let mut state = app.borrow_mut();
        let registry: Vec<Address> = state
            .chain_tokens(SEPOLIA)
            .into_iter()
            .map(|(address, ..)| address)
            .collect();
        let network = NetworkId::Eip155(SEPOLIA).to_string();
        if let Some(meta) = state.meta.as_mut() {
            let _ = meta.add_token(
                &network,
                &crate::meta::TokenEntry {
                    address: TOUR_AIRDROP.to_owned(),
                    label: "FREE-AIRDROP".to_owned(),
                    decimals: 18,
                },
            );
            meta.token_view.set_hidden(&network, TOUR_AIRDROP, true);
            meta.token_view.hide_zero = true;
        }
        if let Some(snapshot) = state
            .evm
            .balances
            .get_mut(&SEPOLIA)
            .and_then(|balance| balance.snapshot.as_mut())
        {
            snapshot.tokens = registry
                .iter()
                .enumerate()
                .map(|(index, address)| {
                    (
                        *address,
                        Some(if index == 0 {
                            U256::ZERO
                        } else {
                            U256::from_u64(125_500_000)
                        }),
                    )
                })
                .collect();
        }
        state.evm.show_hidden_tokens = true;
        state.scroll = 600;
        state.refresh();
    }
    save(main_hwnd(&app), "31-main-evm-tokens");
    {
        let mut state = app.borrow_mut();
        let network = NetworkId::Eip155(SEPOLIA).to_string();
        if let Some(meta) = state.meta.as_mut() {
            meta.remove_token(&network, TOUR_AIRDROP);
            *meta.token_view = crate::token_view::TokenView::default();
        }
        if let Some(snapshot) = state
            .evm
            .balances
            .get_mut(&SEPOLIA)
            .and_then(|balance| balance.snapshot.as_mut())
        {
            snapshot.tokens = Vec::new();
        }
        state.evm.show_hidden_tokens = false;
        // The HyperCore card under the token card (balances not loaded: no network; the tour
        // has no RPC worker, so its "worker unavailable" note is cleared).
        state.hypercore.error = None;
        state.scroll = 1_000;
        state.refresh();
    }
    save(main_hwnd(&app), "49-main-evm-hypercore");
    app.borrow_mut().scroll = 0;
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
    set_screen(&app, UNLOCKED, Screen::AddressBook);
    save(main_hwnd(&app), "46-address-book");
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
        state.sol.send = crate::app_sol::SolSendForm {
            token: yw_core::sol::template::spl_entries(yw_core::sol::SolCluster::Devnet).next(),
            to_text: SOL_RECIPIENT.to_owned(),
            amount_text: "5".to_owned(),
            ..crate::app_sol::SolSendForm::default()
        };
        state.sol_validate_send();
    }
    set_screen(&app, UNLOCKED, Screen::SolSend);
    save(main_hwnd(&app), "20-send-solana-usdc");
    sol_approval(&app);
    save(approval_hwnd(&app), "21-approval-solana-usdc");
    app.borrow_mut().tour_reject_approval();
    {
        let mut state = app.borrow_mut();
        state.sol.send = crate::app_sol::SolSendForm::default();
    }
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
        // The account card scrolled to the selected account's address mode (fixed by default).
        let mut state = app.borrow_mut();
        state.scroll = 300;
        state.refresh();
    }
    save(main_hwnd(&app), "32-bitcoin-address-mode");
    {
        // The account card with `계정 추가`'s chooser open (key source at its default, the
        // standard BTC path), scrolled to it.
        let mut state = app.borrow_mut();
        state.btc.add_account_open = true;
        state.scroll = 520;
        state.refresh();
    }
    save(main_hwnd(&app), "25-bitcoin-account-types");
    {
        // The explicit choice "EVM 계정과 같은 키": the warning and the EVM accounts.
        let mut state = app.borrow_mut();
        state.btc.add_source = crate::app_btc::BtcAddSource::EvmShared;
        state.btc.add_evm_index = 0;
        state.scroll = 640;
        state.refresh();
    }
    save(main_hwnd(&app), "33-bitcoin-evm-key-choice");
    {
        let mut state = app.borrow_mut();
        state.btc.add_account_open = false;
        state.btc.add_source = crate::app_btc::BtcAddSource::Standard;
        state.scroll = 0;
        // S12 of BIP84 account 0 in fixed-address mode: `m/84'/1'/0'/0/0` only.
        let primary = state
            .meta
            .as_ref()
            .and_then(|meta| meta.btc.as_deref().cloned());
        state.btc.receive = primary.and_then(|meta| crate::app_btc::BtcUi::receive_view(&meta, 0));
    }
    set_screen(&app, UNLOCKED, Screen::BtcReceive);
    save(main_hwnd(&app), "34-receive-bitcoin");
    set_screen(&app, UNLOCKED, Screen::Main);
    {
        let mut state = app.borrow_mut();
        state.btc.receive = None;
        tour_chain_grants(&state);
    }
    // Message signing on Solana (ownership proof only, no transaction).
    dapp_request(
        &app,
        "https://app.example.org",
        yw_core::policy::Method::SolSignMessage,
        crate::browser::SiteKind::SolSign {
            public: SolAddress::parse("HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk")
                .unwrap()
                .to_bytes(),
            message: "app.example.org 로그인: 이 지갑의 소유를 확인합니다. (nonce 7f3a91)"
                .as_bytes()
                .to_vec(),
            sign_in: false,
        },
    );
    save(approval_hwnd(&app), "27-approval-sol-message");
    app.borrow_mut().tour_reject_approval();
    // Sign-In-With-Solana from the same site (the app builds the text from the dApp's fields).
    let siws = yw_core::sol::msgsign::SiwsMessage {
        domain: "app.example.org".to_owned(),
        address: "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk".to_owned(),
        statement: Some("app.example.org에 로그인합니다.".to_owned()),
        uri: Some("https://app.example.org/login".to_owned()),
        version: Some("1".to_owned()),
        chain_id: Some("devnet".to_owned()),
        nonce: Some("7f3a91c2".to_owned()),
        ..yw_core::sol::msgsign::SiwsMessage::default()
    };
    dapp_request(
        &app,
        "https://app.example.org",
        yw_core::policy::Method::SolSignIn,
        crate::browser::SiteKind::SolSign {
            public: SolAddress::parse("HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk")
                .unwrap()
                .to_bytes(),
            message: siws.to_text().into_bytes(),
            sign_in: true,
        },
    );
    save(approval_hwnd(&app), "28-approval-sol-signin");
    app.borrow_mut().tour_reject_approval();
    // Bitcoin message signing right after (the payment address of the site's grant).
    let payment = app
        .borrow()
        .btc_dapp_rows()
        .into_iter()
        .find(|row| row.entry.script_type == yw_core::btc::ScriptType::P2wpkh)
        .map(|row| row.entry.address)
        .unwrap();
    dapp_request(
        &app,
        "https://app.example.org",
        yw_core::policy::Method::BtcSignMessage,
        crate::browser::SiteKind::BtcSign {
            address: payment,
            message: "app.example.org 로그인: 이 주소의 소유를 확인합니다. (nonce 7f3a91)"
                .as_bytes()
                .to_vec(),
            protocol: None,
        },
    );
    save(approval_hwnd(&app), "30-approval-btc-message");
    app.borrow_mut().tour_reject_approval();
    {
        // The Zcash tab while off: what it is and the two `켜기` buttons.
        let mut state = app.borrow_mut();
        if let Some(meta) = state.meta.as_mut() {
            meta.prefs.tab = Tab::Zec;
        }
        state.settings.zcash.enabled = false;
    }
    set_screen(&app, UNLOCKED, Screen::Main);
    save(main_hwnd(&app), "47-main-zcash-off");
    {
        // On (testnet) with the test mnemonic's public key at m/44'/1'/0'/0/0 (public BIP44
        // testnet vector) and no `zcash:testnet` URL: the endpoint line with `RPC 설정하기`.
        let mut state = app.borrow_mut();
        state.settings.zcash.enabled = true;
        state.settings.zcash.network = yw_core::zec::ZecNetwork::Testnet;
        if let Some(meta) = state.meta.as_mut() {
            meta.zcash.set(yw_core::zec::ZecAccount {
                network: yw_core::zec::ZecNetwork::Testnet,
                source: yw_core::zec::ZecKeySource::DEFAULT,
                pubkey: yw_core::hex::decode_array::<33>(TOUR_ZEC_TESTNET_KEY).unwrap(),
            });
        }
    }
    set_screen(&app, UNLOCKED, Screen::Main);
    save(main_hwnd(&app), "48-main-zcash");
    {
        let mut state = app.borrow_mut();
        state.settings.zcash.enabled = false;
        if let Some(meta) = state.meta.as_mut() {
            *meta.zcash = crate::zec::meta::ZcashMeta::default();
        }
    }
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
    {
        // Scrolled past the EVM cards: the Solana and Bitcoin connections of the same site.
        let mut state = app.borrow_mut();
        state.scroll = 560;
        state.refresh();
    }
    save(main_hwnd(&app), "29-sites-solana-bitcoin");
    app.borrow_mut().scroll = 0;
    // Settings → 브라우저·정보: the section map line, Chrome 확장, WalletConnect.
    set_screen(&app, UNLOCKED, Screen::Settings(SettingsSection::Other));
    save(main_hwnd(&app), "50-settings-browser");
    // S23 Chrome 확장 설치 (from settings → 브라우저·정보).
    set_screen(&app, UNLOCKED, Screen::Settings(SettingsSection::Other));
    app.borrow_mut().open_extension_help();
    save(main_hwnd(&app), "45-chrome-extension");
    // A new site asks to connect (EVM): the account chooser of the connect window.
    set_screen(&app, UNLOCKED, Screen::Main);
    dapp_request(
        &app,
        "https://swap.example.org",
        yw_core::policy::Method::RequestAccounts,
        crate::browser::SiteKind::RequestAccounts,
    );
    save(approval_hwnd(&app), "26-approval-connect");
    app.borrow_mut().tour_reject_approval();
    // YubiKey: the enrolment wizard, settings → YubiKey and the card step (W11).
    tour_yubikey(&app);

    // M6: the optional AI explanation, answered by the tour's own loopback mock.
    let endpoint = tour_llm_mock();
    {
        let mut state = app.borrow_mut();
        state.settings.llm_explain = crate::settings::LlmSettings {
            enabled: true,
            endpoint,
            model: "mock-model".to_owned(),
            privacy_notice_version: u64::from(crate::explain::PRIVACY_NOTICE_VERSION),
            ..crate::settings::LlmSettings::default()
        };
        state.events = Some(std::sync::Arc::new(crate::events::EventQueue::new(
            Box::new(|| {}),
        )));
        // The tour's wallet is unlocked: the settings snapshot check has run.
        state.guard.verified = true;
        state.llm_reconfigure();
    }
    set_screen(&app, UNLOCKED, Screen::Main);
    site_approval(&app);
    wait_for_ai(&app);
    save(approval_hwnd(&app), "22-approval-ai-explain");
    app.borrow_mut().tour_reject_approval();
    app.borrow_mut().open_llm_settings();
    let _ = app
        .borrow_mut()
        .on_llm_command(crate::ui::screens_llm::ids::TEST);
    for _ in 0..50 {
        pump(100);
        app.borrow_mut().tour_drain_events();
        if !app.borrow().llm_ui.test_running {
            break;
        }
    }
    {
        // Past the back link and the title, so the test result under the buttons is in view.
        let mut state = app.borrow_mut();
        state.scroll = 96;
        state.refresh();
    }
    save(main_hwnd(&app), "23-settings-ai");
    app.borrow_mut().llm_shutdown();

    if let Some(browser) = app.borrow_mut().browser.as_mut() {
        browser.stop();
    }
    drop(app);
    let _ = std::fs::remove_dir_all(&dir);
}

// DEV ONLY: the scroll repaint check reuses the tour's window setup.
mod scroll;
