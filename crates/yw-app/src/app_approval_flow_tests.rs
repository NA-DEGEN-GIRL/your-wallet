//! App-level approval flow scenarios (2026-11-18, S4 A4; spec/15 §11.4 S4, spec/04 §3,
//! spec/09 §2.2): the golden `app/tests/s4_flow/flow.txt`, recorded from today's code before S4
//! moves a line of the approval flow (owner decision O-2; reviewed at the F-A checkpoint).
//!
//! Every scenario drives the real `App` approval path on the A3 fixture (`flow_support`): hidden
//! approval windows that are never shown nor the foreground, the test clock shared by the App,
//! the prepare fixture and the test `BrowserCore`, the scripted trusted-signal oracle, the RPC
//! channel and key queue captured (never run) and the recorded dApp outlet. Inputs go through
//! the private `interaction(event)` with explicit events and through `on_approval_key` /
//! `on_approval_msg` / `on_panel_msg` (plan §4.6 rule 3). (2026-11-19, S4 B6: those are the
//! tests' entries for the window opened last, `interaction(event)` sends the `Event` input a
//! window step sends, and keys go through `on_approval_msg`.) Nothing here touches the network, a
//! card reader, a process, the clipboard or the registry; files are written only below the
//! fixture's own temp folder (and by `print`, into `YW_S4_FLOW_OUT` when it is set).
//!
//! A line: `<scenario> <step> | t=<ms since the clock origin> | win <open|closed>` (open: `status`
//! of the interaction, `prep` of the gate, `risk`, the gate's `ready`/`ack`/`sel`/`submitting`/
//! `fg`/`deadline`, the keyboard `focus`, the `status-text` catalogue key) `| store <state of the
//! last issued request> | queue len=<n> shown=<kind> | rpc <jobs since the last line> | key
//! <jobs since the last line> | dapp <answers since the last line: code and fixed message> |
//! banners <codes> | info <send-form note> | card <step|->`. No address, digest, URL or value:
//! digest equality is asserted in code and printed as `same`/`new`. A fact line is
//! `<scenario> <step> | <fact>`. (2026-11-18, S4 A4 review: this format, not the shorter line of
//! plan §4.2, is the canonical one of `s4_flow/flow.txt`; later S4 commits compare against it byte
//! for byte.)
//!
//! The three latent behaviours of plan §0.1 are pinned as the code does them today: L-1
//! (`l1_close_with_a_second_request_queued`), L-2 (`l2_connect_chain_change_*`) and L-3
//! (`l3_site_deadline_*`). 2026-11-19 (S4 F1, owner decision O-4): L-1 is fixed; its lines now
//! pin one rejection and the queued request shown next (only the `l1_*` lines changed). Same day
//! (F1 review): the key and mouse guards of F1 are pinned too (`l1_press_past_deadline_*`: Esc,
//! Enter, Space, Tab and a `MouseDown` on `거부` past the first window's deadline), and the
//! `l1_close_*` block gained a `shown` fact (the request shown after the close box). 2026-11-19
//! (S4 F2, owner decision O-5): L-2 is fixed; only the `l2_*` lines changed: the two scenarios
//! of A4 now pin the window `Pending` again after the chain change and a too-soon click that
//! stores nothing, and five new ones pin `거부` by Enter and by mouse, Escape, the window's own
//! expiry and a new armed click that stores the redrawn chain. Run
//! (`#[ignore]`, gate step `winui`):
//! `cargo test -p yw-app --lib --locked --offline -- --ignored --test-threads=1 app_approval::flow_tests`.
//! Regenerate for review (PowerShell): `$env:YW_S4_FLOW_OUT='<folder>'; cargo test -p yw-app
//! --lib --locked --offline -- --ignored --test-threads=1 app_approval::flow_tests::print`.

// 2026-11-23 (S4d E1): the wallet's crate-private steps, buffers and flow state as the tests reach
// them across the crate boundary (`yw_engine::testkit`).
// 2026-11-23 (S4d E1): the approval flow's state as the tests read it across the crate boundary.
use std::fmt::Write as _;
use std::sync::Arc;
use yw_engine::testkit::{FlowTestExt, WalletTestExt};

use yw_core::approval::ApprovalId;
use yw_core::bip32::AccountXpub;
use yw_core::bip32::path::{AccountIndex, BtcChain};
use yw_core::evm::address::parse_address;
use yw_core::evm::amount::U256;
use yw_core::policy::{BrowserOrigin, ConnectedSite, SolGrant};
use yw_core::vault::EvmKeySource;
use yw_win::ui::{Handler, Msg, Reply, Window, WindowKind, WindowSpec, create_window};

use super::flow_support::{self, Fixture, HostMode, Outlet, START_MS, Signals};
use super::{Focus, PANEL_CLASS, text};
use crate::ui::approval_input::{VK_ESCAPE, VK_RETURN, VK_SPACE, VK_TAB};
use yw_engine::approval::QueueSource;
use yw_engine::approval::interaction::{
    InteractionEvent, PrepareStage, PrepareState, ReadyContent,
};
use yw_engine::events::KeyJob;
use yw_engine::flow::evm::prepare::{
    PrepareFailure, PrepareJob, ResimJob, ResimKind, ResimResult, resimulate,
};
use yw_engine::flow::evm::{ChainCache, SharedTransport};
use yw_engine::wallet::app_evm::QueuedItem;
use yw_engine::workers::rpc::RpcJob;

/// The committed golden.
const GOLDEN: &str = include_str!("app/tests/s4_flow/flow.txt");

/// `abandon`×11 `about`, `m/44'/60'/0'/0/0` and `/1` (public test vectors).
const ACCOUNT_A: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
const ACCOUNT_B: &str = "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0";
/// Solana `abandon`×11 `about` account 0 (the `app_chain_sites` tests' key).
const SOL_KEY: &str = "FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z";
/// testnet4 `m/84'/1'/0'` of `abandon`×11 `about` (spec/08 §14.1, public data).
const BTC_ABOUT_XPUB: &str = "03b88e0fbe3f646337ed93bc0c0f3b843fcf7d2589e5ec884754e6402027a890b4";
const BTC_ABOUT_CHAIN_CODE: &str =
    "3c8c2037ee4c1621da0d348db51163709a622d0d2838dde6d8419c51f6301c62";
/// BIP173 P2WPKH vector program (HASH160 of the secp256k1 generator).
const BIP173_PROGRAM: &str = "751e76e8199196d454941c45d1b3a323f1433bd6";
/// secp256k1 public key of the private key 2 (compressed).
const KEY2_PUBKEY: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
/// testnet P2PKH of the private key 1 (spec/12 §2.3 vector).
const ZEC_KEY1_TESTNET: &str = "tmLPctKo9j49rtCSKpwEBpLBeykiTGomGQs";
/// The EIP-712 Ether Mail example with the Sepolia chain id (spec/09 §4.2).
const ETHER_MAIL_SEPOLIA: &str = r#"{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallet","type":"address"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person"},{"name":"contents","type":"string"}]},"primaryType":"Mail","domain":{"name":"Ether Mail","version":"1","chainId":11155111,"verifyingContract":"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},"message":{"from":{"name":"Cow","wallet":"0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},"to":{"name":"Bob","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},"contents":"Hello, Bob!"}}"#;

const PRESS: InteractionEvent = InteractionEvent::PointerPressed {
    inside: true,
    click_through: false,
    physical_down: true,
};
const RELEASE: InteractionEvent = InteractionEvent::PointerReleased {
    physical_down: false,
};
const VK_A: u16 = 0x41;

// ----- recorder -----------------------------------------------------------------------------

/// The lines of one scenario and what was captured on the way.
struct Rec<'a> {
    name: &'static str,
    fx: &'a Fixture,
    outlet: Option<&'a Outlet>,
    lines: Vec<String>,
    issued: Option<ApprovalId>,
    rpc: Vec<RpcJob>,
    keys: Vec<KeyJob>,
    rpc_new: Vec<&'static str>,
    key_new: Vec<String>,
}

impl<'a> Rec<'a> {
    fn new(name: &'static str, fx: &'a Fixture, outlet: Option<&'a Outlet>) -> Self {
        Self {
            name,
            fx,
            outlet,
            lines: Vec::new(),
            issued: None,
            rpc: Vec::new(),
            keys: Vec::new(),
            rpc_new: Vec::new(),
            key_new: Vec::new(),
        }
    }

    /// Moves the jobs sent since the last pull into the recorder.
    fn pull(&mut self) {
        for job in self.fx.rpc_jobs() {
            self.rpc_new.push(job.name());
            self.rpc.push(job);
        }
        for job in self.fx.key_jobs() {
            self.key_new.push(key_name(&job));
            self.keys.push(job);
        }
    }

    /// The first preparation job captured and not yet taken.
    fn take_prepare(&mut self) -> Box<PrepareJob> {
        self.pull();
        let at = self
            .rpc
            .iter()
            .position(|job| matches!(job, RpcJob::Prepare(_)))
            .expect("a preparation job");
        match self.rpc.remove(at) {
            RpcJob::Prepare(job) => job,
            _ => unreachable!("matched above"),
        }
    }

    /// The first re-simulation job captured and not yet taken.
    fn take_resim(&mut self) -> Box<ResimJob> {
        self.pull();
        let at = self
            .rpc
            .iter()
            .position(|job| matches!(job, RpcJob::Resimulate(_)))
            .expect("a re-simulation job");
        match self.rpc.remove(at) {
            RpcJob::Resimulate(job) => job,
            _ => unreachable!("matched above"),
        }
    }

    /// Records one line (format in the module doc).
    fn snap(&mut self, step: &str) {
        self.pull();
        let rpc = names(self.rpc_new.drain(..));
        let key = names(self.key_new.drain(..));
        let dapp = self.outlet.map_or_else(|| "-".to_owned(), dapp_answers);
        let app = self.fx.app.borrow();
        if let Some(id) = app
            .evm
            .approval
            .as_ref()
            .and_then(|flow| flow.issued().map(|request| request.id))
        {
            self.issued = Some(id);
        }
        let mut line = format!("{} {step} | t={}", self.name, rel(self.fx.clock.peek()));
        match (app.evm.approval.as_ref(), app.approval_win.as_ref()) {
            (Some(flow), Some(win)) => {
                let gate = flow.gate();
                let _ = write!(
                    line,
                    " | win open status={:?} prep={} risk={} | gate ready={} ack={} sel={} \
                     submitting={} fg={} deadline={} | focus={:?} | status-text {}",
                    flow.session().interaction().status(),
                    prep_name(&gate.prepare),
                    if flow.view().blocked {
                        "blocked"
                    } else if flow.view().high {
                        "high"
                    } else {
                        "std"
                    },
                    rel(gate.ready_at_ms),
                    gate.ack_checked,
                    flow.connect().map_or_else(
                        || "-".to_owned(),
                        |connect| connect
                            .selected
                            .iter()
                            .map(|checked| if *checked { '1' } else { '0' })
                            .collect()
                    ),
                    gate.submitting,
                    gate.is_foreground,
                    rel(gate.deadline_ms),
                    win.focus,
                    status_key(flow),
                );
            }
            _ => line.push_str(" | win closed"),
        }
        let store = self
            .issued
            .and_then(|id| app.evm_store().state(id))
            .map_or_else(|| "-".to_owned(), |state| format!("{state:?}"));
        let shown = app
            .evm
            .queue
            .shown()
            .map_or("-", |shown| item_name(&shown.payload));
        let banners = names(
            app.banners
                .iter()
                .filter_map(|banner| banner.code.map(yw_engine::errors::ErrorCode::code)),
        );
        let info = match app.evm.send.info.as_deref() {
            None => "-",
            Some(info)
                if info
                    == yw_engine::wallet::app_evm::text::APPROVAL_EXPIRED
                        .get(app.settings.language) =>
            {
                "APPROVAL_EXPIRED"
            }
            Some(_) => "other",
        };
        let _ = write!(
            line,
            " | store {store} | queue len={} shown={shown} | rpc {rpc} | key {key} | dapp {dapp} \
             | banners {banners} | info {info} | card {}",
            app.evm.queue.len(),
            if app.card.step.is_some() { "step" } else { "-" },
        );
        drop(app);
        self.lines.push(line);
    }

    /// A free-form fact line (`<scenario> <step> | <fact>`).
    fn fact(&mut self, step: &str, fact: &str) {
        self.lines.push(format!("{} {step} | {fact}", self.name));
    }
}

fn names<S: AsRef<str>>(items: impl Iterator<Item = S>) -> String {
    let joined = items
        .map(|item| item.as_ref().to_owned())
        .collect::<Vec<_>>()
        .join(",");
    if joined.is_empty() {
        "-".to_owned()
    } else {
        joined
    }
}

fn key_name(job: &KeyJob) -> String {
    match job {
        KeyJob::SignMessage { typed: true, .. } => "SignMessage(typed)".to_owned(),
        other => other.name().to_owned(),
    }
}

/// Monotonic `ms` relative to the clock origin (`max` for a far deadline).
fn rel(ms: u64) -> String {
    if ms >= u64::MAX / 2 {
        "max".to_owned()
    } else if ms >= START_MS {
        format!("+{}", ms - START_MS)
    } else {
        format!("-{}", START_MS - ms)
    }
}

fn prep_name(prepare: &PrepareState) -> String {
    match prepare {
        PrepareState::Preparing(PrepareStage::Building) => "building".to_owned(),
        PrepareState::Preparing(PrepareStage::Simulating { .. }) => "simulating".to_owned(),
        PrepareState::Ready(ReadyContent::Signing(_)) => "ready".to_owned(),
        PrepareState::Ready(ReadyContent::Connect(_)) => "connect".to_owned(),
        PrepareState::Failed { code, retryable } => {
            format!(
                "failed:{}{}",
                code.code(),
                if *retryable { "+retry" } else { "" }
            )
        }
    }
}

/// The catalogue key of the window's status message.
fn status_key(flow: &yw_engine::wallet::approval_flow::ApprovalFlow) -> &'static str {
    let Some(status) = flow.status() else {
        return "-";
    };
    let lang = flow.lang();
    for (key, fact) in [
        ("SIM_CHANGED", text::SIM_CHANGED),
        ("SIM_RESIM_FAILED", text::SIM_RESIM_FAILED),
        ("SIMULATING_START", text::SIMULATING_START),
        ("CHECKING", text::CHECKING),
    ] {
        if status.starts_with(fact.get(lang)) {
            return key;
        }
    }
    if status == yw_engine::errors::ErrorCode::Rpc001.text_in(lang) {
        "E-RPC-001"
    } else {
        "other"
    }
}

fn item_name(item: &QueuedItem) -> &'static str {
    match item {
        QueuedItem::App(_) => "app-send",
        QueuedItem::Site(site) => site.method.as_str(),
        QueuedItem::Sol(_) => "sol-transfer",
        QueuedItem::Btc(_) => "btc-send",
        QueuedItem::Zec(_) => "zec-send",
        QueuedItem::HyperCore(_) => "hypercore",
    }
}

pub(super) fn dapp_answers(outlet: &Outlet) -> String {
    let answers: Vec<String> = outlet
        .answers()
        .into_iter()
        .map(|answer| match answer {
            Ok(_) => "result".to_owned(),
            Err(error) => format!("{} {}", error.code(), error.message()),
        })
        .collect();
    if answers.is_empty() {
        "-".to_owned()
    } else {
        answers.join("; ")
    }
}

/// The golden lines of `name` (in order).
fn golden_of(name: &str) -> Vec<&'static str> {
    let prefix = format!("{name} ");
    GOLDEN
        .lines()
        .filter(|line| line.starts_with(&prefix))
        .collect()
}

// ----- drivers ------------------------------------------------------------------------------

/// The oracle of the scenarios: A01 is the foreground window and an Enter is in the message's
/// own key state (not injected); `enter == false` is a posted Enter.
fn signals(enter: bool) -> Signals {
    Signals {
        foreground: true,
        enter_in_message: enter,
        ..Signals::default()
    }
}

fn fixture(tag: &str) -> Fixture {
    let fixture = Fixture::new(tag, HostMode::Hidden);
    flow_support::set_signals(Some(signals(true)));
    fixture
}

fn at(fx: &Fixture, ms: u64) {
    fx.clock.set(START_MS + ms);
}

fn ev(fx: &Fixture, event: InteractionEvent) {
    fx.app().interaction(event);
}

fn click(fx: &Fixture) {
    ev(fx, PRESS);
    ev(fx, RELEASE);
}

/// A key to A01 of the window opened last (2026-11-19, S4 B6: through the message entry, on a
/// spare window the key arms read nothing from; was `on_approval_key`, the window-less key entry,
/// which went with B6).
fn key(fx: &Fixture, vk: u16, repeat: bool) {
    let spare = spare_window();
    let _ = fx
        .app()
        .on_approval_msg(&spare, &Msg::KeyDown { vk, repeat });
}

/// A hidden top-level window for the `window` argument of the message handlers (the arms
/// these scenarios use read nothing from it but its DPI and size).
struct Inert;

impl Handler for Inert {
    fn on(&mut self, _window: &Window, _msg: &Msg) -> Reply {
        Reply::Default
    }
}

pub(super) fn spare_window() -> Window {
    let window = create_window(
        &WindowSpec::new(PANEL_CLASS, WindowKind::Floating).size(820, 710),
        Box::new(Inert),
    )
    .unwrap();
    assert!(window.is_hidden_or_minimized());
    window
}

/// The S2 Sepolia app send, prepared from the `eth_simulateV1` fixture `sim`.
fn app_send(fx: &Fixture, rec: &mut Rec<'_>, sim: &str) {
    fx.enqueue_sepolia_send();
    rec.snap("open");
    let job = rec.take_prepare();
    fx.answer_prepare(&job, sim);
    rec.snap("ready");
}

/// Answers a re-simulation job from the `eth_simulateV1` fixture `sim` on the shared clock.
fn answer_resim(fx: &Fixture, job: &ResimJob, sim: &str) {
    let transport: SharedTransport = Arc::new(super::smoke::FixtureRpc {
        simulate: super::smoke::fixture(sim),
    });
    let result = resimulate(&transport, &mut ChainCache::default(), job, &*fx.clock);
    fx.app().on_resimulated(result);
}

pub(super) fn origin() -> BrowserOrigin {
    BrowserOrigin::parse("https://app.example").unwrap()
}

/// The fixture's dispatcher with EVM accounts A and B (and the Solana account when `sol`),
/// unlocked, and the origin connected to account A on Sepolia when `granted`.
pub(super) fn dapp(fx: &Fixture, sol: bool, granted: bool) -> Outlet {
    let outlet = fx.connect_outlet();
    {
        let mut app = fx.app();
        let account = |index: u32, address: &str| yw_engine::meta::Account {
            index,
            label: format!("Account {}", index + 1),
            address: address.to_owned(),
            hidden: false,
        };
        // Meta keeps EVM addresses in lower-case hex (`account_source` compares that text).
        let mut meta = yw_engine::meta::Meta {
            evm_accounts: vec![
                account(0, &ACCOUNT_A.to_ascii_lowercase()),
                account(1, &ACCOUNT_B.to_ascii_lowercase()),
            ],
            ..yw_engine::meta::Meta::default()
        };
        if sol {
            meta.sol_accounts.push(account(0, SOL_KEY));
        }
        app.meta = Some(meta);
        app.sync_browser();
        if let Some(browser) = app.browser.as_ref() {
            if granted {
                browser.core.upsert_grant(
                    ConnectedSite::new(
                        origin(),
                        vec![parse_address(ACCOUNT_A).unwrap()],
                        yw_core::evm::chain::SEPOLIA,
                        1,
                    )
                    .unwrap(),
                );
            }
            if sol {
                let _ = browser.core.upsert_sol_grant(SolGrant {
                    origin: origin(),
                    public: yw_core::codec::base58::base58_decode_32(SOL_KEY).unwrap(),
                    granted_at_unix_ms: 1,
                });
            }
        }
    }
    let _ = outlet.events.drain();
    let _ = outlet.answers();
    outlet
}

/// Sends request `n` due `due_ms` after now (monotonic, converted to the wall clock).
pub(super) fn request(
    fx: &Fixture,
    outlet: &Outlet,
    n: u8,
    method: &str,
    params: &str,
    route: &str,
    due_ms: u64,
) {
    let due = fx.clock.unix_at(fx.clock.peek() + due_ms);
    outlet.send(fx, n, method, params, route, due);
}

pub(super) fn personal_sign(fx: &Fixture, outlet: &Outlet, n: u8, due_ms: u64) {
    request(
        fx,
        outlet,
        n,
        "personal_sign",
        &format!(r#"["0x6869","{ACCOUNT_A}"]"#),
        "signing",
        due_ms,
    );
}

/// The current window's language.
fn approval_lang(fx: &Fixture) -> yw_core::lang::Lang {
    fx.app.borrow().approval_lang()
}

/// Opens an app chain item (BTC, ZEC, `HyperCore`): queued like the send forms do, shown at once
/// (their drafts are built without a worker).
fn enqueue_app_item(fx: &Fixture, item: QueuedItem) {
    let mut app = fx.app();
    app.evm.queue.enqueue(QueueSource::App, item).unwrap();
    app.show_next_approval();
}

fn btc_item() -> QueuedItem {
    use yw_core::btc::account::BtcAccountKey;
    use yw_core::btc::address::ScriptKind;
    use yw_core::btc::amount::Sats;
    use yw_core::btc::display::BtcSendFacts;
    use yw_core::btc::fee::{FeeChoice, FeeRate, FeeSource};
    use yw_core::btc::network::BtcNetwork;
    use yw_core::btc::select::{SendAmount, SendRequest, Utxo, plan_send};
    use yw_core::btc::tx::{OutPoint, Txid};
    let account = BtcAccountKey::primary(AccountXpub {
        pubkey: yw_core::hex::decode_array::<33>(BTC_ABOUT_XPUB).unwrap(),
        chain_code: yw_core::hex::decode_array::<32>(BTC_ABOUT_CHAIN_CODE).unwrap(),
    })
    .with_single_address(false);
    let candidates = [Utxo {
        outpoint: OutPoint {
            txid: Txid::from_bytes([0x11; 32]),
            vout: 0,
        },
        value: Sats::new(100_000).unwrap(),
        chain: BtcChain::Receive,
        index: 0,
        height: 199_990,
        is_coinbase: false,
    }];
    let plan = plan_send(&SendRequest {
        network: BtcNetwork::Testnet4,
        account: &account,
        recipient: ScriptKind::P2wpkh(yw_core::hex::decode_array::<20>(BIP173_PROGRAM).unwrap()),
        amount: SendAmount::Exact(Sats::new(40_000).unwrap()),
        fee: FeeChoice {
            rate: FeeRate::from_sat_per_kvb(1_000),
            source: FeeSource::Manual,
        },
        candidates: &candidates,
        tip_height: 200_000,
        change_next: 3,
        layout_seed: [0x5a; 32],
        typed_fee_override: None,
        conflicts: &[],
    })
    .unwrap();
    QueuedItem::Btc(Box::new(yw_engine::wallet::app_btc::BtcApprovalItem {
        network: BtcNetwork::Testnet4,
        plan,
        facts: BtcSendFacts {
            verified_balance: Sats::new(100_000).unwrap(),
            min_confirmations: Some(10),
            first_time_recipient: true,
            own_recipient: None,
        },
        account,
        tip_height: 200_000,
        look_alike: None,
    }))
}

fn zec_item() -> QueuedItem {
    use yw_core::zec::upgrade::{ConsensusObservation, tx_consensus};
    use yw_core::zec::{
        ZecAccount, ZecAmount, ZecKeySource, ZecNetwork, ZecOutPoint, ZecSendRequest, ZecUtxo,
        parse_recipient,
    };
    let account = ZecAccount {
        network: ZecNetwork::Testnet,
        source: ZecKeySource::Imported,
        pubkey: yw_core::hex::decode_array::<33>(KEY2_PUBKEY).unwrap(),
    };
    let consensus = tx_consensus(
        ZecNetwork::Testnet,
        &ConsensusObservation {
            tip: 4_470_000,
            next_branch: 0x7719_0AD9,
            upgrades: Vec::new(),
        },
    )
    .unwrap();
    let plan = yw_core::zec::plan_send(
        &account,
        &ZecSendRequest {
            recipient: parse_recipient(ZEC_KEY1_TESTNET, ZecNetwork::Testnet).unwrap(),
            amount: ZecAmount::Exact(40_000),
            utxos: vec![ZecUtxo {
                outpoint: ZecOutPoint {
                    txid: [0x21; 32],
                    index: 0,
                },
                value: 100_000,
                height: Some(4_469_000),
                coinbase: false,
            }],
            reserved: Vec::new(),
            consensus,
        },
    )
    .unwrap();
    QueuedItem::Zec(Box::new(yw_engine::wallet::app_zec::ZecApprovalItem {
        plan,
        look_alike: None,
        first_time: true,
    }))
}

fn hypercore_item(fx: &Fixture, look_alike: bool) -> QueuedItem {
    use yw_core::hypercore::display::HcRecipient;
    use yw_core::hypercore::{HcAction, HcNetwork, HcPayload};
    let action = HcAction::new(
        HcNetwork::Testnet,
        fx.clock.unix_at(fx.clock.peek()),
        HcPayload::UsdSend {
            destination: parse_address(ACCOUNT_B).unwrap(),
            amount: "1".to_owned(),
        },
    );
    QueuedItem::HyperCore(Box::new(yw_engine::wallet::app_hypercore::HcApprovalItem {
        action,
        account: parse_address(ACCOUNT_A).unwrap(),
        signer: EvmKeySource::Derived(AccountIndex::ZERO),
        token: None,
        recipient: HcRecipient {
            notes: Vec::new(),
            look_alike,
            not_in_book: true,
        },
    }))
}

/// Approves the shown request the way its risk asks (spec/04 §3.4), from `t` on, recording each
/// step: Standard = one click at `t + 1 000`; High = the checkbox, an Enter on `승인` (ignored),
/// a 1 900 ms hold (not enough), then a 2 000 ms hold.
fn approve_by_risk(fx: &Fixture, rec: &mut Rec<'_>, t: u64) {
    at(fx, t);
    ev(fx, InteractionEvent::Tick);
    rec.snap("tick");
    let high = fx
        .app
        .borrow()
        .evm
        .approval
        .as_ref()
        .is_some_and(|flow| flow.view().high);
    if !high {
        at(fx, t + 1_000);
        click(fx);
        rec.snap("click");
        return;
    }
    fx.app().toggle_ack();
    rec.snap("ack");
    if let Some(win) = fx.app().approval_win.as_mut() {
        win.focus = Focus::Approve;
    }
    at(fx, t + 1_000);
    key(fx, VK_RETURN, false);
    rec.snap("enter-high");
    at(fx, t + 2_100);
    ev(fx, PRESS);
    at(fx, t + 4_000);
    ev(fx, InteractionEvent::Tick);
    rec.snap("hold-1900");
    ev(fx, RELEASE);
    rec.snap("release-early");
    at(fx, t + 5_100);
    ev(fx, PRESS);
    at(fx, t + 7_100);
    ev(fx, InteractionEvent::Tick);
    rec.snap("hold-2000");
    ev(fx, RELEASE);
}

// ----- scenarios ----------------------------------------------------------------------------

/// T2 #1 reject-first: the window opens with `거부` focused; Enter rejects, nothing is signed,
/// the send slot is freed.
fn reject_first() -> Vec<String> {
    let fx = fixture("reject-first");
    let mut rec = Rec::new("reject_first", &fx, None);
    app_send(&fx, &mut rec, "S2");
    ev(&fx, InteractionEvent::Tick);
    rec.snap("tick");
    at(&fx, 1_500);
    key(&fx, VK_RETURN, false);
    rec.snap("enter");
    let slots = fx.app.borrow().evm.slots.len();
    rec.fact("slots", &format!("send slots held={slots}"));
    rec.lines
}

/// T2 #2: an auto-repeated Enter on `거부` never rejects but is a press (restarts the unarmed
/// delay); a fresh Enter rejects.
fn repeat_enter_on_reject() -> Vec<String> {
    let fx = fixture("repeat-enter");
    let mut rec = Rec::new("repeat_enter_on_reject", &fx, None);
    app_send(&fx, &mut rec, "S2");
    ev(&fx, InteractionEvent::Tick);
    rec.snap("tick");
    at(&fx, 500);
    key(&fx, VK_RETURN, true);
    rec.snap("enter-repeat-unarmed");
    at(&fx, 2_000);
    key(&fx, VK_RETURN, true);
    rec.snap("enter-repeat-armed");
    at(&fx, 2_100);
    key(&fx, VK_RETURN, false);
    rec.snap("enter");
    rec.lines
}

/// T2 #3: a posted Enter on `승인` (not in the message's key state) never approves and counts as
/// a press; a physical Enter a second later approves once.
fn posted_enter_on_approve() -> Vec<String> {
    let fx = fixture("posted-enter");
    let mut rec = Rec::new("posted_enter_on_approve", &fx, None);
    app_send(&fx, &mut rec, "S2");
    ev(&fx, InteractionEvent::Tick);
    at(&fx, 100);
    key(&fx, VK_TAB, false);
    rec.snap("tab");
    flow_support::set_signals(Some(signals(false)));
    at(&fx, 1_200);
    key(&fx, VK_RETURN, false);
    rec.snap("enter-posted");
    flow_support::set_signals(Some(signals(true)));
    at(&fx, 1_700);
    key(&fx, VK_RETURN, false);
    rec.snap("enter-too-soon");
    at(&fx, 2_800);
    key(&fx, VK_RETURN, false);
    rec.snap("enter-physical");
    rec.lines
}

/// T2 #4: a stray key while unarmed restarts the delay; clicks too early are presses.
fn stray_key_unarmed() -> Vec<String> {
    let fx = fixture("stray-key");
    let mut rec = Rec::new("stray_key_unarmed", &fx, None);
    app_send(&fx, &mut rec, "S2");
    ev(&fx, InteractionEvent::Tick);
    at(&fx, 900);
    key(&fx, VK_A, false);
    rec.snap("key-a");
    at(&fx, 1_500);
    click(&fx);
    rec.snap("click-unarmed");
    at(&fx, 1_900);
    click(&fx);
    rec.snap("click-1900");
    at(&fx, 3_000);
    click(&fx);
    rec.snap("click-3000");
    rec.lines
}

/// T2 #5: losing and regaining the foreground restarts the delay (the per-event foreground
/// sample), and so does `WM_ACTIVATEAPP(true)`.
fn reactivation_restarts_the_delay() -> Vec<String> {
    let fx = fixture("reactivation");
    let spare = spare_window();
    let mut rec = Rec::new("reactivation_restarts_the_delay", &fx, None);
    app_send(&fx, &mut rec, "S2");
    ev(&fx, InteractionEvent::Tick);
    at(&fx, 1_500);
    flow_support::set_signals(Some(Signals {
        foreground: false,
        ..signals(true)
    }));
    ev(&fx, InteractionEvent::Tick);
    rec.snap("background");
    flow_support::set_signals(Some(signals(true)));
    at(&fx, 1_600);
    ev(&fx, InteractionEvent::Tick);
    rec.snap("foreground");
    at(&fx, 2_000);
    click(&fx);
    rec.snap("click-2000");
    at(&fx, 3_500);
    let _ = fx.app().on_approval_msg(&spare, &Msg::ActivateApp(true));
    rec.snap("activate-app");
    at(&fx, 4_000);
    click(&fx);
    rec.snap("click-4000");
    at(&fx, 5_100);
    click(&fx);
    rec.snap("click-5100");
    rec.lines
}

/// T2 #6 (C1) with a message: one approval, exactly one signing job; later inputs find no
/// window.
fn c1_message_one_job() -> Vec<String> {
    let fx = fixture("c1-message");
    let outlet = dapp(&fx, false, true);
    let mut rec = Rec::new("c1_message_one_job", &fx, Some(&outlet));
    personal_sign(&fx, &outlet, 1, 600_000);
    rec.snap("ready");
    approve_by_risk(&fx, &mut rec, 0);
    for step in 0..5 {
        at(&fx, 1_100 + 1_100 * step);
        click(&fx);
        ev(&fx, InteractionEvent::Tick);
    }
    rec.snap("after-5-clicks");
    let waiters = fx
        .app
        .borrow()
        .browser
        .as_ref()
        .map_or(0, |browser| browser.waiters.len());
    rec.fact("waiters", &format!("sign waiters={waiters}"));
    rec.lines
}

/// T2 #6 (C1) with a stale simulation: one re-simulation, `submitting` holds every later
/// input until its result.
fn c1_stale_sim_one_resim() -> Vec<String> {
    let fx = fixture("c1-stale");
    let mut rec = Rec::new("c1_stale_sim_one_resim", &fx, None);
    app_send(&fx, &mut rec, "S2");
    ev(&fx, InteractionEvent::Tick);
    at(&fx, 61_000);
    click(&fx);
    rec.snap("click-stale");
    for step in 0..3 {
        at(&fx, 62_100 + 1_100 * step);
        click(&fx);
        ev(&fx, InteractionEvent::Tick);
    }
    rec.snap("after-3-clicks");
    rec.lines
}

/// A-9 resimulation boundaries: a click exactly 60 000 ms after the simulation result consumes
/// it as is; 60 001 ms re-simulates (spec/03 §6.6, `SIM_FRESHNESS_MS`).
fn resim_boundary(after_ms: u64, name: &'static str) -> Vec<String> {
    let fx = fixture(name);
    let mut rec = Rec::new(name, &fx, None);
    app_send(&fx, &mut rec, "S2");
    ev(&fx, InteractionEvent::Tick);
    at(&fx, after_ms);
    click(&fx);
    rec.snap("click");
    rec.lines
}

/// The digest of the shown request.
fn shown_digest(fx: &Fixture) -> Option<(ApprovalId, [u8; 32])> {
    fx.app
        .borrow()
        .evm
        .approval
        .as_ref()
        .and_then(|flow| flow.issued().map(|request| (request.id, request.digest)))
}

fn signed_digest(rec: &Rec<'_>) -> Option<[u8; 32]> {
    rec.keys.iter().find_map(|job| match job {
        KeyJob::SignEvm { approved, .. } => Some(approved.digest()),
        _ => None,
    })
}

/// T2 #7: re-simulation `Same` after the click consumes the replaced request; its digest equals
/// the one shown before, so the `old-digest` line pins single use only (H1, a pre-replace digest
/// refused after a change, is `resim_changed_old_digest`; S4 A4 review, 2026-11-18).
fn resim_same_after_click() -> Vec<String> {
    let fx = fixture("resim-same");
    let mut rec = Rec::new("resim_same_after_click", &fx, None);
    app_send(&fx, &mut rec, "S2");
    ev(&fx, InteractionEvent::Tick);
    let (id, old) = shown_digest(&fx).unwrap();
    at(&fx, 61_000);
    click(&fx);
    rec.snap("click-stale");
    let job = rec.take_resim();
    at(&fx, 61_500);
    answer_resim(&fx, &job, "S2");
    rec.snap("resim-same");
    let signed = signed_digest(&rec);
    rec.fact(
        "digest",
        &format!(
            "signed digest vs pre-resim digest={}",
            match signed {
                Some(digest) if digest == old => "same",
                Some(_) => "new",
                None => "none",
            }
        ),
    );
    let again = fx.app().evm_store_mut().consume(id, old, START_MS + 61_600);
    rec.fact(
        "old-digest",
        &format!(
            "consume with the pre-resim digest={:?}",
            again.map(|_| "approved")
        ),
    );
    rec.lines
}

/// T2 #8: re-simulation `Changed` after the click never consumes; the changed content needs
/// a new approval with its own rules.
fn resim_changed_needs_a_new_click() -> Vec<String> {
    let fx = fixture("resim-changed");
    let mut rec = Rec::new("resim_changed_needs_a_new_click", &fx, None);
    app_send(&fx, &mut rec, "S2");
    ev(&fx, InteractionEvent::Tick);
    let (_, old) = shown_digest(&fx).unwrap();
    at(&fx, 61_000);
    click(&fx);
    rec.snap("click-stale");
    let job = rec.take_resim();
    at(&fx, 61_500);
    answer_resim(&fx, &job, "S3");
    rec.snap("resim-changed");
    let changed = shown_digest(&fx).map(|(_, digest)| digest != old);
    rec.fact("digest", &format!("shown digest changed={changed:?}"));
    approve_by_risk(&fx, &mut rec, 61_600);
    let signed = signed_digest(&rec);
    rec.fact(
        "signed",
        &format!(
            "signed digest vs pre-resim digest={}",
            match signed {
                Some(digest) if digest == old => "same",
                Some(_) => "new",
                None => "none",
            }
        ),
    );
    rec.lines
}

/// H1 at App level (S4 A4 review, 2026-11-18): after a `Changed` re-simulation replaced the
/// request, the digest shown before it is refused (`DigestMismatch`, which invalidates the entry
/// in the store: a separate scenario, so `resim_changed_needs_a_new_click` keeps its approval).
fn resim_changed_old_digest() -> Vec<String> {
    let fx = fixture("resim-old-digest");
    let mut rec = Rec::new("resim_changed_old_digest", &fx, None);
    app_send(&fx, &mut rec, "S2");
    ev(&fx, InteractionEvent::Tick);
    let (id, old) = shown_digest(&fx).unwrap();
    at(&fx, 61_000);
    click(&fx);
    rec.snap("click-stale");
    let job = rec.take_resim();
    at(&fx, 61_500);
    answer_resim(&fx, &job, "S3");
    rec.snap("resim-changed");
    let replaced = shown_digest(&fx).map(|(new_id, digest)| (new_id == id, digest != old));
    rec.fact(
        "digest",
        &format!("shown (same id, digest changed)={replaced:?}"),
    );
    let again = fx.app().evm_store_mut().consume(id, old, START_MS + 61_600);
    rec.fact(
        "old-digest",
        &format!(
            "consume with the pre-resim digest={:?}",
            again.map(|_| "approved")
        ),
    );
    rec.snap("after-old-digest");
    rec.lines
}

/// T2 #9: a re-simulation without a result shows `T-SIM-RESIM-FAILED` and resets the approval;
/// a blocking failure turns the window into `Failed`.
fn resim_no_result_and_failed() -> Vec<String> {
    let fx = fixture("resim-noresult");
    let mut rec = Rec::new("resim_no_result_and_failed", &fx, None);
    app_send(&fx, &mut rec, "S2");
    ev(&fx, InteractionEvent::Tick);
    at(&fx, 61_000);
    click(&fx);
    rec.snap("click-stale");
    let job = rec.take_resim();
    at(&fx, 61_500);
    fx.app().on_resimulated(ResimResult {
        job: job.job,
        kind: ResimKind::NoResult,
        prepared: None,
        failure: None,
    });
    rec.snap("no-result");
    approve_by_risk(&fx, &mut rec, 61_600);
    let job = rec.take_resim();
    at(&fx, 63_000);
    let lang = approval_lang(&fx);
    fx.app().on_resimulated(ResimResult {
        job: job.job,
        kind: ResimKind::Failed,
        prepared: None,
        failure: Some(PrepareFailure::no_endpoint(lang)),
    });
    rec.snap("failed");
    at(&fx, 64_100);
    click(&fx);
    rec.snap("click-failed");
    rec.lines
}

/// T2 #10: a re-simulation result for another job is dropped.
fn stale_resim_result_is_dropped() -> Vec<String> {
    let fx = fixture("resim-stale");
    let mut rec = Rec::new("stale_resim_result_is_dropped", &fx, None);
    app_send(&fx, &mut rec, "S2");
    ev(&fx, InteractionEvent::Tick);
    at(&fx, 61_000);
    click(&fx);
    rec.snap("click-stale");
    let job = rec.take_resim();
    at(&fx, 61_500);
    fx.app().on_resimulated(ResimResult {
        job: job.job - 1,
        kind: ResimKind::NoResult,
        prepared: None,
        failure: None,
    });
    rec.snap("other-job");
    answer_resim(&fx, &job, "S2");
    rec.snap("own-job");
    rec.lines
}

/// T2 #11: a display change in the middle of a high-risk hold clears the hold and the checkbox.
fn display_change_mid_hold() -> Vec<String> {
    let fx = fixture("mid-hold");
    let mut rec = Rec::new("display_change_mid_hold", &fx, None);
    app_send(&fx, &mut rec, "S3");
    ev(&fx, InteractionEvent::Tick);
    fx.app().toggle_ack();
    rec.snap("ack");
    at(&fx, 2_000);
    ev(&fx, PRESS);
    at(&fx, 3_500);
    ev(&fx, InteractionEvent::Tick);
    rec.snap("holding");
    let job = fx
        .app
        .borrow()
        .evm
        .approval
        .as_ref()
        .map_or(0, yw_engine::wallet::approval_flow::ApprovalFlow::job);
    fx.app().on_simulating(job, START_MS + 3_500);
    rec.snap("display-changed");
    at(&fx, 4_000);
    ev(&fx, InteractionEvent::Tick);
    rec.snap("old-hold-2000");
    ev(&fx, RELEASE);
    rec.snap("release");
    rec.lines
}

/// T2 #12 (EVM): high risk (S3, the reverted simulation) needs the checkbox and a 2 s hold;
/// Enter is ignored.
fn high_risk_evm() -> Vec<String> {
    let fx = fixture("high-evm");
    let mut rec = Rec::new("high_risk_evm", &fx, None);
    app_send(&fx, &mut rec, "S3");
    approve_by_risk(&fx, &mut rec, 0);
    rec.lines
}

/// T2 #12/#20 (BTC): the app's Bitcoin send through the window to its signing job.
fn chain_btc() -> Vec<String> {
    let fx = fixture("chain-btc");
    let mut rec = Rec::new("chain_btc", &fx, None);
    enqueue_app_item(&fx, btc_item());
    rec.snap("ready");
    approve_by_risk(&fx, &mut rec, 0);
    rec.lines
}

/// T2 #12/#20 (ZEC).
fn chain_zec() -> Vec<String> {
    let fx = fixture("chain-zec");
    let mut rec = Rec::new("chain_zec", &fx, None);
    enqueue_app_item(&fx, zec_item());
    rec.snap("ready");
    approve_by_risk(&fx, &mut rec, 0);
    rec.lines
}

/// T2 #12/#20 (`HyperCore`); `look_alike` makes it high risk (H03).
fn chain_hypercore(look_alike: bool, name: &'static str) -> Vec<String> {
    let fx = fixture(name);
    let mut rec = Rec::new(name, &fx, None);
    let item = hypercore_item(&fx, look_alike);
    enqueue_app_item(&fx, item);
    rec.snap("ready");
    approve_by_risk(&fx, &mut rec, 0);
    rec.lines
}

/// T2 #12/#20 (Solana message from a site): the chain-message branch and its waiter.
fn chain_sol_message() -> Vec<String> {
    let fx = fixture("chain-sol");
    let outlet = dapp(&fx, true, true);
    let mut rec = Rec::new("chain_sol_message", &fx, Some(&outlet));
    request(
        &fx,
        &outlet,
        1,
        "sol_signMessage",
        &format!(r#"[{{"publicKey":"{SOL_KEY}","message":"50726f7665206974"}}]"#),
        "signing",
        600_000,
    );
    rec.snap("ready");
    approve_by_risk(&fx, &mut rec, 0);
    rec.lines
}

/// T2 #20 (site personal sign and typed data): `SignMessage` and its typed flag.
fn consume_site_messages() -> Vec<String> {
    let fx = fixture("site-messages");
    let outlet = dapp(&fx, false, true);
    let mut rec = Rec::new("consume_site_messages", &fx, Some(&outlet));
    personal_sign(&fx, &outlet, 1, 600_000);
    rec.snap("personal-ready");
    approve_by_risk(&fx, &mut rec, 0);
    let typed = ETHER_MAIL_SEPOLIA.replace('"', "\\\"");
    at(&fx, 10_000);
    request(
        &fx,
        &outlet,
        2,
        "eth_signTypedData_v4",
        &format!(r#"["{ACCOUNT_A}","{typed}"]"#),
        "signing",
        600_000,
    );
    rec.snap("typed-open");
    rec.pull();
    let facts = rec.rpc.iter().find_map(|job| match job {
        RpcJob::TypedFacts {
            job,
            address_book,
            own_accounts,
            ..
        } => Some((*job, address_book.clone(), own_accounts.clone())),
        _ => None,
    });
    if let Some((job, address_book, own_accounts)) = facts {
        fx.app().on_typed_facts(
            job,
            &yw_core::approval::ChainFacts {
                address_book,
                own_accounts,
                ..yw_core::approval::ChainFacts::default()
            },
            None,
        );
    }
    rec.snap("typed-ready");
    approve_by_risk(&fx, &mut rec, 10_000);
    rec.lines
}

/// T2 #20/#23: a site send with a reverted (S3) and a failed (S4) simulation stays approvable
/// (spec/03 §6: the simulation never changes the dApp's answer); approving gives one
/// `SignEvm` and a transaction waiter, rejecting answers 4001.
fn site_send(sim: &'static str, approve: bool, name: &'static str) -> Vec<String> {
    let fx = fixture(name);
    let outlet = dapp(&fx, false, true);
    let mut rec = Rec::new(name, &fx, Some(&outlet));
    request(
        &fx,
        &outlet,
        1,
        "eth_sendTransaction",
        &format!(
            r#"[{{"from":"{ACCOUNT_A}","to":"0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb","value":"0x2386f26fc10000"}}]"#
        ),
        "signing",
        600_000,
    );
    rec.snap("open");
    rec.pull();
    if !rec.rpc.iter().any(|job| matches!(job, RpcJob::Prepare(_))) {
        return rec.lines;
    }
    let job = rec.take_prepare();
    fx.answer_prepare(&job, sim);
    rec.snap("ready");
    if approve {
        approve_by_risk(&fx, &mut rec, 0);
        let waiters = fx
            .app
            .borrow()
            .browser
            .as_ref()
            .map_or(0, |browser| browser.waiters.len());
        rec.fact("waiters", &format!("sign waiters={waiters}"));
    } else {
        ev(&fx, InteractionEvent::Tick);
        at(&fx, 1_000);
        key(&fx, VK_ESCAPE, false);
        rec.snap("escape");
    }
    rec.lines
}

/// T2 #20, the non-site branches that end in E-APP-009: a chain message and a transaction
/// without its preparation shown on an app item (drafts put on the window directly; the App
/// never builds these, the branches are its fail-closed ends).
fn consume_app009_branches() -> Vec<String> {
    let fx = fixture("app009");
    let mut rec = Rec::new("consume_app009_branches", &fx, None);
    app_send(&fx, &mut rec, "S2");
    // A Solana message draft on the app send's window.
    let lang = approval_lang(&fx);
    let draft = yw_core::sol::msgsign::build_sol_message_request(
        lang,
        &yw_core::sol::msgsign::SolMessageRequest {
            id: ApprovalId([7; 16]),
            origin: origin(),
            cluster: yw_core::sol::address::SolCluster::Devnet,
            source: yw_core::slip10::SolKeySource::Standard(AccountIndex::ZERO),
            public: yw_core::codec::base58::base58_decode_32(SOL_KEY).unwrap(),
            label: "SOL 1".to_owned(),
            message: b"Prove it".to_vec(),
            sign_in: false,
        },
        fx.clock.unix_at(fx.clock.peek()),
    )
    .unwrap();
    fx.app().show_ready_draft(draft, None);
    rec.snap("chain-message-on-app-item");
    approve_by_risk(&fx, &mut rec, 0);
    // The app send's own draft again, without its preparation.
    let fx2 = fixture("app009-tx");
    let mut rec2 = Rec::new("consume_app009_branches", &fx2, None);
    fx2.enqueue_sepolia_send();
    let job = rec2.take_prepare();
    fx2.answer_prepare(&job, "S2");
    let draft = fx2
        .app
        .borrow()
        .evm
        .approval
        .as_ref()
        .and_then(|flow| flow.prepared().map(|prepared| prepared.draft.clone()))
        .unwrap();
    // A new id: the store issues an id once.
    let draft = yw_core::approval::ApprovalDraft {
        id: ApprovalId([8; 16]),
        ..draft
    };
    fx2.app().show_ready_draft(draft, None);
    rec2.snap("tx-without-preparation");
    approve_by_risk(&fx2, &mut rec2, 0);
    let mut lines = rec.lines;
    lines.append(&mut rec2.lines);
    lines
}

/// T2 #13: the E05 fee-cap draft (`Blocked`) is never consumed, whatever the input; Escape
/// rejects it.
fn blocked_is_never_consumed() -> Vec<String> {
    let fx = fixture("blocked");
    let mut rec = Rec::new("blocked_is_never_consumed", &fx, None);
    fx.enqueue_sepolia_send();
    rec.snap("open");
    let mut job = rec.take_prepare();
    job.chain.caps.max_total_fee = U256::from_u64(1_000);
    fx.answer_prepare(&job, "S2");
    rec.snap("ready");
    ev(&fx, InteractionEvent::Tick);
    at(&fx, 1_500);
    click(&fx);
    rec.snap("click");
    if let Some(win) = fx.app().approval_win.as_mut() {
        win.focus = Focus::Approve;
    }
    at(&fx, 2_600);
    key(&fx, VK_RETURN, false);
    rec.snap("enter");
    at(&fx, 3_700);
    ev(&fx, PRESS);
    at(&fx, 6_000);
    ev(&fx, InteractionEvent::Tick);
    ev(&fx, RELEASE);
    rec.snap("hold");
    at(&fx, 7_000);
    key(&fx, VK_ESCAPE, false);
    rec.snap("escape");
    rec.lines
}

/// T2 #14: the 120 s display lifetime, ended by the window's 50 ms tick (`main == false`) or by
/// the main timer's queue tick (`main == true`).
fn expiry(main: bool, name: &'static str) -> Vec<String> {
    let fx = fixture(name);
    let mut rec = Rec::new(name, &fx, None);
    app_send(&fx, &mut rec, "S2");
    ev(&fx, InteractionEvent::Tick);
    at(&fx, 119_999);
    ev(&fx, InteractionEvent::Tick);
    fx.app().tick_approval(START_MS + 119_999);
    rec.snap("tick-119999");
    at(&fx, 120_000);
    if main {
        fx.app().tick_approval(START_MS + 120_000);
        rec.snap("main-tick-120000");
        ev(&fx, InteractionEvent::Tick);
        rec.snap("window-tick-after");
    } else {
        ev(&fx, InteractionEvent::Tick);
        rec.snap("window-tick-120000");
        fx.app().tick_approval(START_MS + 120_000);
        rec.snap("main-tick-after");
    }
    rec.lines
}

/// L-3 (plan §0.1): a site request whose deadline (30 s) binds before the 120 s display
/// lifetime, ended by the window tick (`main == false`) or the main tick (`main == true`).
fn l3_site_deadline(main: bool, name: &'static str) -> Vec<String> {
    let fx = fixture(name);
    let outlet = dapp(&fx, false, true);
    let mut rec = Rec::new(name, &fx, Some(&outlet));
    personal_sign(&fx, &outlet, 1, 30_000);
    rec.snap("ready");
    ev(&fx, InteractionEvent::Tick);
    let deadline = fx
        .app
        .borrow()
        .evm
        .approval
        .as_ref()
        .map_or(0, |flow| flow.gate().deadline_ms);
    rec.fact("deadline", &format!("gate deadline={}", rel(deadline)));
    fx.clock.set(deadline);
    if main {
        fx.app().tick_approval(deadline);
        rec.snap("main-tick-at-deadline");
        ev(&fx, InteractionEvent::Tick);
        rec.snap("window-tick-after");
    } else {
        ev(&fx, InteractionEvent::Tick);
        rec.snap("window-tick-at-deadline");
        fx.app().tick_approval(deadline);
        rec.snap("main-tick-after");
    }
    rec.lines
}

/// T2 #21: drafts with an unsafe display (refused at issue, E-APP-009) and a `WalletConnect`
/// request whose session label cannot be added (E-UI-001, rejected with 4001) are never shown
/// as approvable. The post-issue E-UI-001 re-check is not reached here (S4 A4 review,
/// 2026-11-18).
fn ui001_and_wc_label() -> Vec<String> {
    let fx = fixture("ui001");
    let mut rec = Rec::new("ui001_and_wc_label", &fx, None);
    fx.enqueue_sepolia_send();
    let job = rec.take_prepare();
    fx.answer_prepare(&job, "S2");
    let mut draft = fx
        .app
        .borrow()
        .evm
        .approval
        .as_ref()
        .and_then(|flow| flow.prepared().map(|prepared| prepared.draft.clone()))
        .unwrap();
    // A new id (the store issues an id once) and a title with a bidi override: the store's
    // own display check refuses it at issue (E-APP-009), before the E-UI-001 re-check.
    let mut unsafe_title = draft.clone();
    unsafe_title.id = ApprovalId([9; 16]);
    unsafe_title.display.title = "\u{202e}title".to_owned();
    fx.app().show_ready_draft(unsafe_title, None);
    rec.snap("unsafe-title");
    // The `store` column above is the earlier S2 request's; the refused draft has no entry.
    let refused = fx.app.borrow().evm_store().state(ApprovalId([9; 16]));
    rec.fact(
        "unsafe-title-id",
        &format!("store state of the draft={refused:?}"),
    );
    // A field key the window has no label for: the store's display check refuses it at issue
    // too (E-APP-009). The post-issue E-UI-001 re-check (`show_ready_draft_at`) is reached by
    // no scenario here (open for the F-A checkpoint).
    let fx3 = fixture("ui001-key");
    let mut rec3 = Rec::new("ui001_and_wc_label", &fx3, None);
    fx3.enqueue_sepolia_send();
    let job = rec3.take_prepare();
    fx3.answer_prepare(&job, "S2");
    draft.id = ApprovalId([10; 16]);
    if let Some(mut field) = draft.display.fields.first().cloned() {
        field.key = yw_core::approval::FieldKey(0x7fff);
        draft.display.fields.push(field);
    }
    fx3.app().show_ready_draft(draft, None);
    rec3.snap("unlabelled-field");
    let refused = fx3.app.borrow().evm_store().state(ApprovalId([10; 16]));
    rec3.fact(
        "unlabelled-field-id",
        &format!("store state of the draft={refused:?}"),
    );
    rec.lines.append(&mut rec3.lines);
    // A WalletConnect session origin with no session: the label cannot be added. The request
    // goes through a virtual connection of the dispatcher (the bridge's path, spec/13 §5), so
    // the reject answer reaches a recorded frame (S4 A4 review, 2026-11-18: was a hand-built
    // `SiteRequest` whose answer reached no frame).
    let fx2 = fixture("wc-label");
    let outlet = dapp(&fx2, false, true);
    let wc_origin = yw_engine::walletconnect::session_origin(&[9; 32]).unwrap();
    let (sender, frames) = std::sync::mpsc::channel();
    let core = fx2
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
    let wc = Outlet {
        events: Arc::clone(&outlet.events),
        frames,
        conn: core.open_virtual_connection(Box::new(sender)),
    };
    let _ = wc.events.drain();
    let mut rec2 = Rec::new("ui001_and_wc_label", &fx2, Some(&wc));
    wc_personal_sign(&fx2, &core, &wc, wc_origin);
    rec2.snap("wc-no-session");
    let mut lines = rec.lines;
    lines.append(&mut rec2.lines);
    lines
}

/// A `personal_sign` of `origin` on the virtual connection `wc` (as the `WalletConnect` bridge
/// submits it, spec/13 §5), handed to the App.
fn wc_personal_sign(
    fx: &Fixture,
    core: &yw_engine::browser::BrowserCore,
    wc: &Outlet,
    wc_origin: BrowserOrigin,
) {
    let method = yw_core::policy::Method::PersonalSign;
    core.submit(
        wc.conn,
        &yw_engine::browser::envelope::RequestEnvelope {
            correlation: yw_engine::browser::envelope::Correlation {
                session_id: yw_engine::browser::envelope::Id32([0x57; 32]),
                sequence: 1,
                activation_nonce: yw_engine::browser::envelope::Id32([9; 32]),
                request_id: yw_engine::browser::envelope::Id16([3; 16]),
            },
            deadline_unix_ms: fx.clock.unix_at(fx.clock.peek() + 600_000),
            profile_install_id: yw_engine::browser::envelope::Id32([0; 32]),
            method: method.as_str().to_owned(),
            params: yw_json::Value::Array(vec![
                yw_json::Value::String("0x6869".to_owned()),
                yw_json::Value::String(ACCOUNT_A.to_owned()),
            ]),
            route: method.route(),
            context: yw_engine::browser::envelope::BrowserContext {
                tab_id: 0,
                document_id: "walletconnect".to_owned(),
                origin: wc_origin,
                channel_nonce: yw_engine::browser::envelope::Id32([9; 32]),
                compat_mode: None,
            },
        },
        yw_core::evm::chain::SEPOLIA,
    );
    for event in wc.events.drain() {
        if let yw_engine::events::UiEvent::Dapp(event) = event {
            fx.app().on_dapp_event(event);
        }
    }
}

/// T2 #22: a refused window rejects the request with E-APP-009 and prepares nothing.
fn open_failure() -> Vec<String> {
    let fx = Fixture::new("open-failure", HostMode::FailOpen);
    let mut rec = Rec::new("open_failure", &fx, None);
    fx.enqueue_sepolia_send();
    rec.snap("enqueue");
    let slots = fx.app.borrow().evm.slots.len();
    rec.fact("slots", &format!("send slots held={slots}"));
    rec.lines
}

/// `issue_uses_one_instant`: with a clock that steps at every read, the request issue, the
/// queue's Ready time, the session's `ready_at` and the deadline come from one reading.
fn issue_uses_one_instant() -> Vec<String> {
    let fx = fixture("one-instant");
    let mut rec = Rec::new("issue_uses_one_instant", &fx, None);
    fx.enqueue_sepolia_send();
    let job = rec.take_prepare();
    fx.clock.set_step(7);
    fx.answer_prepare(&job, "S2");
    fx.clock.set_step(0);
    rec.snap("ready");
    let app = fx.app.borrow();
    let flow = app.evm.approval.as_ref().unwrap();
    let request = flow.issued().unwrap();
    let queue_deadline = app.evm.queue.shown_deadline().unwrap_or(0);
    let received = flow
        .prepared()
        .map_or(0, |prepared| prepared.sim_received_ms);
    let fact = format!(
        "sim received={} session ready={} gate deadline={} queue deadline={} issued(unix-base)={} \
         expires-issued={}",
        rel(received),
        rel(flow.gate().ready_at_ms),
        rel(flow.gate().deadline_ms),
        rel(queue_deadline),
        rel(request.created_unix_ms - fx.clock.unix_at(0)),
        request.expires_unix_ms - request.created_unix_ms,
    );
    drop(app);
    rec.fact("instants", &fact);
    rec.lines
}

/// L-1 (plan §0.1): the close box of the first request's window, with a second request queued.
/// 2026-11-19 (S4 F1): one 4001 and the second request's window shown (`Pending`, focus
/// `Reject`); before F1 both requests got 4001 and no window was left.
fn l1_close_with_a_second_request_queued() -> Vec<String> {
    let fx = fixture("l1");
    let spare = spare_window();
    let outlet = dapp(&fx, false, true);
    let mut rec = Rec::new("l1_close_with_a_second_request_queued", &fx, Some(&outlet));
    personal_sign(&fx, &outlet, 1, 600_000);
    personal_sign(&fx, &outlet, 2, 600_000);
    rec.snap("two-queued");
    ev(&fx, InteractionEvent::Tick);
    at(&fx, 1_500);
    let reply = fx.app().on_approval_msg(&spare, &Msg::Close);
    rec.snap("close-box");
    rec.fact("reply", &format!("close reply={reply:?}"));
    // 2026-11-19 (S4 F1 review): the one 4001 above is the first request's; the second is the
    // one shown now.
    let shown = shown_request(&fx);
    rec.fact("shown", &format!("shown request={shown}"));
    rec.lines
}

/// The `sequence` of the shown site request (`-`: none or not a site request).
fn shown_request(fx: &Fixture) -> String {
    match fx.app.borrow().evm.queue.shown().map(|item| &item.payload) {
        Some(QueuedItem::Site(site)) => site.reply.correlation.sequence.to_string(),
        _ => "-".to_owned(),
    }
}

/// The interaction events, A01 Win32 side effects and flow calls of an input log, in order.
fn press_trace(log: &[flow_support::Logged]) -> String {
    names(log.iter().filter_map(|entry| match *entry {
        flow_support::Logged::Event { event, .. } => {
            let text = format!("{event:?}");
            Some(format!(
                "ev {}",
                text.split([' ', '{', '(']).next().unwrap_or_default()
            ))
        }
        flow_support::Logged::Effect { fx, performed } => {
            Some(format!("fx {fx:?}{}", if performed { "" } else { "/skip" }))
        }
        flow_support::Logged::Call { call, .. } => Some(format!("call {call:?}")),
        flow_support::Logged::Activated { .. } => Some("activated".to_owned()),
        flow_support::Logged::Read { .. } | flow_support::Logged::Dropped { .. } => None,
    }))
}

/// L-1, the key and mouse guards of F1 (2026-11-19, S4 F1 review): the first request's window
/// is shown and armed, a second request is queued, and one press comes past the first window's
/// deadline (`escape`, `enter` and `space` with the focus on `거부`, `tab`, or a `MouseDown` on
/// `거부`). The press's `OtherPress` ends the first request (expired) and opens the second
/// request's window; the rest of the message must not act on that window: one dApp answer, the
/// second request shown `Pending` with the focus on `거부` and no button pressed, the
/// `MouseDown` reply `Default`. Before F1, Esc, Enter and Space rejected the second request
/// unseen, Tab moved its focus and the `MouseDown` focused it (`Handled(0)`).
fn l1_press_past_deadline(press: &'static str, name: &'static str) -> Vec<String> {
    let fx = fixture(name);
    let spare = spare_window();
    let outlet = dapp(&fx, false, true);
    let mut rec = Rec::new(name, &fx, Some(&outlet));
    personal_sign(&fx, &outlet, 1, 600_000);
    personal_sign(&fx, &outlet, 2, 600_000);
    rec.snap("two-queued");
    let first = rec.issued;
    ev(&fx, InteractionEvent::Tick);
    // The buttons as painted (the hidden host never paints): `거부` at (460, 640, 120, 40).
    if let Some(win) = fx.app().approval_win.as_mut() {
        win.bottom.reject = yw_win::ui::Rect::new(460, 640, 120, 40);
        win.bottom.approve = yw_win::ui::Rect::new(600, 640, 120, 40);
    }
    at(&fx, 121_000);
    let _ = flow_support::take_log();
    let msg = match press {
        "escape" => Msg::KeyDown {
            vk: VK_ESCAPE,
            repeat: false,
        },
        "enter" => Msg::KeyDown {
            vk: VK_RETURN,
            repeat: false,
        },
        "space" => Msg::KeyDown {
            vk: VK_SPACE,
            repeat: false,
        },
        "tab" => Msg::KeyDown {
            vk: VK_TAB,
            repeat: false,
        },
        _ => Msg::MouseDown { x: 520, y: 660 },
    };
    let reply = fx.app().on_approval_msg(&spare, &msg);
    let log = flow_support::take_log();
    rec.snap(press);
    let app = fx.app.borrow();
    let first = first
        .and_then(|id| app.evm_store().state(id))
        .map_or_else(|| "-".to_owned(), |state| format!("{state:?}"));
    let pressed = app
        .approval_win
        .as_ref()
        .and_then(|win| win.pressed)
        .map_or_else(|| "-".to_owned(), |pressed| format!("{pressed:?}"));
    drop(app);
    let shown = shown_request(&fx);
    rec.fact(
        "after",
        &format!(
            "first store={first} shown request={shown} pressed={pressed} reply={reply:?} | \
             trace {}",
            press_trace(&log)
        ),
    );
    rec.lines
}

/// EVM connect (`eth_requestAccounts` of an origin not connected yet) up to the Ready window.
fn connect_window(fx: &Fixture, outlet: &Outlet, rec: &mut Rec<'_>) {
    request(
        fx,
        outlet,
        1,
        "eth_requestAccounts",
        "[]",
        "permission",
        600_000,
    );
    rec.snap("connect-ready");
    ev(fx, InteractionEvent::Tick);
}

/// L-2 (plan §0.1): the origin's chain changes between the drawing and the approval of an EVM
/// connect window (L4(c)); the click that finds the change redraws the window with the new chain
/// and stores nothing. Then `end` follows. 2026-11-19 (S4 F2, owner decision O-5): the click
/// starts a fresh interaction, so the window is `Pending` again with the arm delay restarted at
/// the click; a click 200 ms later (`click-too-soon`, every variant) stores nothing, and then:
/// `close-box` and `main-tick` (the two ends that worked before F2 too), `enter-on-reject`,
/// `mouse-reject`, `escape` and `window-tick` (dead before F2: the interaction stayed `Approved`)
/// end it as rejected or expired, and `approve` (a new click 1 s after the last press) stores the
/// redrawn chain. Before F2 the window stayed `Approved` after the change and every click, `거부`,
/// Escape and the window tick did nothing.
fn l2_connect_chain_change(end: &'static str, name: &'static str) -> Vec<String> {
    let fx = fixture(name);
    let spare = spare_window();
    let outlet = dapp(&fx, false, false);
    let mut rec = Rec::new(name, &fx, Some(&outlet));
    connect_window(&fx, &outlet, &mut rec);
    if let Some(browser) = fx.app.borrow().browser.as_ref() {
        browser
            .core
            .set_origin_chain(&origin(), yw_core::evm::chain::ETHEREUM_MAINNET);
    }
    let grants = |fx: &Fixture| {
        fx.app.borrow().browser.as_ref().map_or_else(
            || "-".to_owned(),
            |browser| {
                let sites = browser.core.grants();
                let chains = names(sites.iter().map(|site| site.chain_id.to_string()));
                let accounts = names(sites.iter().map(|site| site.accounts.len().to_string()));
                format!("grants={} chain={chains} accounts={accounts}", sites.len())
            },
        )
    };
    at(&fx, 1_500);
    click(&fx);
    rec.snap("click-chain-changed");
    rec.fact("grants", &grants(&fx));
    at(&fx, 1_700);
    click(&fx);
    rec.snap("click-too-soon");
    rec.fact("grants", &grants(&fx));
    match end {
        "close-box" => {
            at(&fx, 2_000);
            let reply = fx.app().on_approval_msg(&spare, &Msg::Close);
            rec.snap(end);
            rec.fact("reply", &format!("close reply={reply:?}"));
        }
        "main-tick" => {
            at(&fx, 121_000);
            fx.app().tick_approval(START_MS + 121_000);
            rec.snap(end);
        }
        "enter-on-reject" => {
            at(&fx, 2_000);
            key(&fx, VK_RETURN, false);
            rec.snap(end);
        }
        "mouse-reject" => {
            // The buttons as painted (the hidden host never paints): `거부` at (460, 640, 120, 40).
            if let Some(win) = fx.app().approval_win.as_mut() {
                win.bottom.reject = yw_win::ui::Rect::new(460, 640, 120, 40);
                win.bottom.approve = yw_win::ui::Rect::new(600, 640, 120, 40);
            }
            at(&fx, 2_000);
            let down = fx
                .app()
                .on_approval_msg(&spare, &Msg::MouseDown { x: 520, y: 660 });
            let up = fx
                .app()
                .on_approval_msg(&spare, &Msg::MouseUp { x: 520, y: 660 });
            rec.snap(end);
            rec.fact("reply", &format!("down={down:?} up={up:?}"));
        }
        "escape" => {
            at(&fx, 2_000);
            key(&fx, VK_ESCAPE, false);
            rec.snap(end);
        }
        "window-tick" => {
            at(&fx, 121_000);
            ev(&fx, InteractionEvent::Tick);
            rec.snap(end);
        }
        "approve" => {
            at(&fx, 2_700);
            click(&fx);
            rec.snap("click-armed");
            rec.fact("grants", &grants(&fx));
        }
        // 2026-11-19 F2 review: a misspelt `end` used to run the approve path through this arm;
        // it now records an error line, so the golden comparison fails.
        _ => rec.fact("error", &format!("unknown end {end}")),
    }
    rec.lines
}

/// A-13 (as today): connect toggles go by the panel layout's account rows. Before the panel is
/// painted there is no layout and a click toggles nothing; after a paint a click on row 1
/// toggles it; the toggle rebuilds the view (layout gone) and a click before the next paint
/// toggles nothing; a chain change shown without a rebuild keeps the drawn layout, and a click
/// on it toggles the drawn row.
fn connect_toggle_layout() -> Vec<String> {
    let fx = fixture("connect-layout");
    let spare = spare_window();
    let outlet = dapp(&fx, false, false);
    let mut rec = Rec::new("connect_toggle_layout", &fx, Some(&outlet));
    connect_window(&fx, &outlet, &mut rec);
    let row = |fx: &Fixture, index: usize| {
        fx.app.borrow().approval_win.as_ref().and_then(|win| {
            win.layout.as_ref().and_then(|layout| {
                layout
                    .accounts
                    .iter()
                    .find(|(at, _)| *at == index)
                    .map(|(_, rect)| (rect.x + rect.w / 2, rect.y + rect.h / 2))
            })
        })
    };
    let press = |fx: &Fixture, (x, y): (i32, i32)| {
        let _ = fx.app().on_panel_msg(&spare, &Msg::MouseDown { x, y });
    };
    rec.fact(
        "layout",
        &format!("row 1 before paint={:?}", row(&fx, 1).is_some()),
    );
    at(&fx, 1_000);
    press(&fx, (40, 40));
    rec.snap("click-without-layout");
    fx.app().paint_panel(&spare);
    let target = row(&fx, 1);
    rec.fact(
        "layout",
        &format!("row 1 after paint={:?}", target.is_some()),
    );
    let Some(target) = target else {
        return rec.lines;
    };
    at(&fx, 2_000);
    press(&fx, target);
    rec.snap("click-row-1");
    rec.fact(
        "layout",
        &format!("row 1 after the toggle={:?}", row(&fx, 1).is_some()),
    );
    at(&fx, 3_000);
    press(&fx, target);
    rec.snap("click-row-1-stale");
    fx.app().paint_panel(&spare);
    if let Some(browser) = fx.app.borrow().browser.as_ref() {
        browser
            .core
            .set_origin_chain(&origin(), yw_core::evm::chain::ETHEREUM_MAINNET);
    }
    at(&fx, 4_000);
    press(&fx, target);
    rec.snap("click-after-chain-change");
    rec.lines
}

/// The shown window's gate, interaction, store and queue as one comparable text (the A-12
/// scenario's "nothing changed" check; no address or value).
fn gate_state(fx: &Fixture) -> String {
    let app = fx.app.borrow();
    app.evm.approval.as_ref().map_or_else(
        || "-".to_owned(),
        |flow| {
            let gate = flow.gate();
            format!(
                "{:?} {:?} ready={} fg={} ack={} sel={} submitting={} deadline={} issued={:?}                  queue={}",
                flow.shown(),
                flow.session().interaction().status(),
                rel(gate.ready_at_ms),
                gate.is_foreground,
                gate.ack_checked,
                gate.connect_selected,
                gate.submitting,
                rel(gate.deadline_ms),
                flow.issued()
                    .and_then(|request| app.evm_store().state(request.id)),
                app.evm.queue.len(),
            )
        },
    )
}

/// Critique A-12 (2026-11-19, S4 B6): the first request's window ends (Escape) and the second
/// request's window opens and is armed; messages still queued for the first window's `HWND` are
/// then delivered through the first window's `Forward`, whose `ShownId` is the first window's:
/// the close box, Escape, Enter, `WM_ACTIVATEAPP(TRUE)` and the 50 ms timer, then a
/// `Cmd::Approval` with an approving physical Enter for the first window. Every input is dropped:
/// the second window's gate, interaction, store, queue and answers stay as they were (and the
/// approving input signs nothing). The same close box through the second window's `Forward`
/// rejects the second request. On Windows a window that has gone gets no message while effects
/// are applied at once; under a deferred schedule (S4b, S4d) one can.
fn stale_window_input_is_dropped() -> Vec<String> {
    use yw_engine::approval::flow::{ApprovalInput, ApprovalSignal};
    use yw_engine::cmd::Cmd;

    use super::{Forward, Target};
    use crate::ui::approval_input::APPROVAL_TIMER_ID;

    let fx = fixture("stale-window");
    let spare = spare_window();
    let outlet = dapp(&fx, false, true);
    let mut rec = Rec::new("stale_window_input_is_dropped", &fx, Some(&outlet));
    personal_sign(&fx, &outlet, 1, 600_000);
    personal_sign(&fx, &outlet, 2, 600_000);
    rec.snap("two-queued");
    let first = fx.app.borrow().last_opened();
    let mut stale = Forward {
        app: std::rc::Rc::downgrade(&fx.app),
        target: Target::Approval(first),
    };
    ev(&fx, InteractionEvent::Tick);
    at(&fx, 1_500);
    key(&fx, VK_ESCAPE, false);
    ev(&fx, InteractionEvent::Tick);
    rec.snap("first-rejected");
    let second = fx.app.borrow().last_opened();
    rec.fact(
        "windows",
        &format!(
            "first={} second={} shown request={}",
            first.0,
            second.0,
            shown_request(&fx)
        ),
    );
    at(&fx, 2_600);
    let before = gate_state(&fx);
    let _ = flow_support::take_log();
    for (name, msg) in [
        ("stale-close", Msg::Close),
        (
            "stale-escape",
            Msg::KeyDown {
                vk: VK_ESCAPE,
                repeat: false,
            },
        ),
        (
            "stale-enter",
            Msg::KeyDown {
                vk: VK_RETURN,
                repeat: false,
            },
        ),
        ("stale-activate", Msg::ActivateApp(true)),
        ("stale-timer", Msg::Timer(APPROVAL_TIMER_ID)),
    ] {
        let reply = stale.on(&spare, &msg);
        let log = flow_support::take_log();
        rec.snap(name);
        rec.fact(
            "dropped",
            &format!(
                "reply={reply:?} trace {} | second unchanged={}",
                press_trace(&log),
                gate_state(&fx) == before
            ),
        );
    }
    fx.app().on_cmd(Cmd::Approval(ApprovalInput {
        shown: first,
        foreground: true,
        signal: ApprovalSignal::Event(InteractionEvent::ApproveActivated { physical: true }),
    }));
    rec.snap("stale-approving-input");
    rec.fact(
        "dropped",
        &format!("second unchanged={}", gate_state(&fx) == before),
    );
    let mut current = Forward {
        app: std::rc::Rc::downgrade(&fx.app),
        target: Target::Approval(second),
    };
    let reply = current.on(&spare, &Msg::Close);
    rec.snap("second-close-box");
    rec.fact("reply", &format!("close reply={reply:?}"));
    rec.lines
}

/// Critique A-13 (2026-11-19, S4 B6): a connect toggle carries the revision of the view its panel
/// layout was drawn from. After a toggle redraws the view, the layout drawn before it (put back,
/// as a deferred schedule could leave it) still hit-tests a row, but that click toggles nothing,
/// and neither does a `Cmd::Approval` toggle of that older view; a click on a layout drawn from
/// the view shown toggles its row. On Windows every new view drops the layout before a click
/// can reach it (`connect_toggle_layout`), so no click is ever dropped there.
fn connect_toggle_stale_layout() -> Vec<String> {
    use yw_engine::approval::flow::{ApprovalInput, ApprovalSignal};
    use yw_engine::cmd::Cmd;

    let fx = fixture("connect-stale-layout");
    let spare = spare_window();
    let outlet = dapp(&fx, false, false);
    let mut rec = Rec::new("connect_toggle_stale_layout", &fx, Some(&outlet));
    connect_window(&fx, &outlet, &mut rec);
    let row = |fx: &Fixture, index: usize| {
        fx.app.borrow().approval_win.as_ref().and_then(|win| {
            win.layout.as_ref().and_then(|layout| {
                layout
                    .accounts
                    .iter()
                    .find(|(at, _)| *at == index)
                    .map(|(_, rect)| (rect.x + rect.w / 2, rect.y + rect.h / 2))
            })
        })
    };
    let press = |fx: &Fixture, (x, y): (i32, i32)| {
        let _ = fx.app().on_panel_msg(&spare, &Msg::MouseDown { x, y });
    };
    let revision = |fx: &Fixture| {
        fx.app
            .borrow()
            .evm
            .approval
            .as_ref()
            .map_or(0, yw_engine::wallet::approval_flow::ApprovalFlow::view_rev)
    };
    fx.app().paint_panel(&spare);
    let drawn = fx
        .app
        .borrow()
        .approval_win
        .as_ref()
        .and_then(|win| win.layout.clone());
    let (Some(drawn), Some(row_0), Some(row_1)) = (drawn, row(&fx, 0), row(&fx, 1)) else {
        rec.fact("error", "no layout after the paint");
        return rec.lines;
    };
    let old = revision(&fx);
    rec.fact(
        "layout",
        &format!("drawn from the view shown={}", drawn.view_rev == old),
    );
    at(&fx, 1_000);
    press(&fx, row_1);
    rec.snap("click-row-1");
    rec.fact(
        "layout",
        &format!(
            "new view={} layout kept={}",
            revision(&fx) != old,
            row(&fx, 1).is_some()
        ),
    );
    if let Some(win) = fx.app().approval_win.as_mut() {
        win.layout = Some(drawn);
    }
    at(&fx, 2_000);
    press(&fx, row_0);
    rec.snap("click-row-0-older-layout");
    let shown = fx.app.borrow().last_opened();
    at(&fx, 2_500);
    fx.app().on_cmd(Cmd::Approval(ApprovalInput {
        shown,
        foreground: false,
        signal: ApprovalSignal::ToggleAccount {
            index: 0,
            view_rev: old,
        },
    }));
    rec.snap("toggle-older-view");
    if let Some(win) = fx.app().approval_win.as_mut() {
        win.layout = None;
    }
    fx.app().paint_panel(&spare);
    at(&fx, 3_000);
    press(&fx, row_0);
    rec.snap("click-row-0-shown-layout");
    rec.lines
}

// ----- the scenario table -------------------------------------------------------------------

type Scenario = fn() -> Vec<String>;

/// Every scenario, in golden order.
const SCENARIOS: [(&str, Scenario); 51] = [
    ("reject_first", reject_first),
    ("repeat_enter_on_reject", repeat_enter_on_reject),
    ("posted_enter_on_approve", posted_enter_on_approve),
    ("stray_key_unarmed", stray_key_unarmed),
    (
        "reactivation_restarts_the_delay",
        reactivation_restarts_the_delay,
    ),
    ("c1_message_one_job", c1_message_one_job),
    ("c1_stale_sim_one_resim", c1_stale_sim_one_resim),
    ("resim_fresh_59999", || {
        resim_boundary(59_999, "resim_fresh_59999")
    }),
    ("resim_fresh_60000", || {
        resim_boundary(60_000, "resim_fresh_60000")
    }),
    ("resim_stale_60001", || {
        resim_boundary(60_001, "resim_stale_60001")
    }),
    ("resim_same_after_click", resim_same_after_click),
    (
        "resim_changed_needs_a_new_click",
        resim_changed_needs_a_new_click,
    ),
    ("resim_changed_old_digest", resim_changed_old_digest),
    ("resim_no_result_and_failed", resim_no_result_and_failed),
    (
        "stale_resim_result_is_dropped",
        stale_resim_result_is_dropped,
    ),
    ("display_change_mid_hold", display_change_mid_hold),
    ("high_risk_evm", high_risk_evm),
    ("chain_btc", chain_btc),
    ("chain_zec", chain_zec),
    ("chain_hypercore", || {
        chain_hypercore(false, "chain_hypercore")
    }),
    ("chain_hypercore_look_alike", || {
        chain_hypercore(true, "chain_hypercore_look_alike")
    }),
    ("chain_sol_message", chain_sol_message),
    ("consume_site_messages", consume_site_messages),
    ("site_send_s3_approve", || {
        site_send("S3", true, "site_send_s3_approve")
    }),
    ("site_send_s4_approve", || {
        site_send("S4", true, "site_send_s4_approve")
    }),
    ("site_send_s3_reject", || {
        site_send("S3", false, "site_send_s3_reject")
    }),
    ("consume_app009_branches", consume_app009_branches),
    ("blocked_is_never_consumed", blocked_is_never_consumed),
    ("expiry_window_tick", || expiry(false, "expiry_window_tick")),
    ("expiry_main_tick", || expiry(true, "expiry_main_tick")),
    ("l3_site_deadline_window_tick", || {
        l3_site_deadline(false, "l3_site_deadline_window_tick")
    }),
    ("l3_site_deadline_main_tick", || {
        l3_site_deadline(true, "l3_site_deadline_main_tick")
    }),
    ("ui001_and_wc_label", ui001_and_wc_label),
    ("open_failure", open_failure),
    ("issue_uses_one_instant", issue_uses_one_instant),
    (
        "l1_close_with_a_second_request_queued",
        l1_close_with_a_second_request_queued,
    ),
    ("l1_press_past_deadline_escape", || {
        l1_press_past_deadline("escape", "l1_press_past_deadline_escape")
    }),
    ("l1_press_past_deadline_enter", || {
        l1_press_past_deadline("enter", "l1_press_past_deadline_enter")
    }),
    ("l1_press_past_deadline_space", || {
        l1_press_past_deadline("space", "l1_press_past_deadline_space")
    }),
    ("l1_press_past_deadline_tab", || {
        l1_press_past_deadline("tab", "l1_press_past_deadline_tab")
    }),
    ("l1_press_past_deadline_mouse_reject", || {
        l1_press_past_deadline("mouse-reject", "l1_press_past_deadline_mouse_reject")
    }),
    ("l2_connect_chain_change_close_box", || {
        l2_connect_chain_change("close-box", "l2_connect_chain_change_close_box")
    }),
    ("l2_connect_chain_change_main_tick", || {
        l2_connect_chain_change("main-tick", "l2_connect_chain_change_main_tick")
    }),
    ("l2_connect_chain_change_enter_on_reject", || {
        l2_connect_chain_change("enter-on-reject", "l2_connect_chain_change_enter_on_reject")
    }),
    ("l2_connect_chain_change_mouse_reject", || {
        l2_connect_chain_change("mouse-reject", "l2_connect_chain_change_mouse_reject")
    }),
    ("l2_connect_chain_change_escape", || {
        l2_connect_chain_change("escape", "l2_connect_chain_change_escape")
    }),
    ("l2_connect_chain_change_window_tick", || {
        l2_connect_chain_change("window-tick", "l2_connect_chain_change_window_tick")
    }),
    ("l2_connect_chain_change_approve", || {
        l2_connect_chain_change("approve", "l2_connect_chain_change_approve")
    }),
    ("connect_toggle_layout", connect_toggle_layout),
    (
        "stale_window_input_is_dropped",
        stale_window_input_is_dropped,
    ),
    ("connect_toggle_stale_layout", connect_toggle_stale_layout),
];

/// The first line where `generated` and `committed` differ, as an assertion message.
fn first_difference(name: &str, generated: &[&str], committed: &[&str]) -> String {
    let at = generated
        .iter()
        .zip(committed)
        .position(|(left, right)| left != right)
        .unwrap_or_else(|| generated.len().min(committed.len()));
    format!(
        "{name}: line {} differs (generated {}, committed {}):\n  generated: {:?}\n  committed: \
         {:?}\nevery generated line:\n{}",
        at + 1,
        generated.len(),
        committed.len(),
        generated.get(at),
        committed.get(at),
        generated.join("\n")
    )
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
        first_difference(name, &generated, &committed)
    );
}

macro_rules! scenario_tests {
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

scenario_tests! {
    golden_reject_first => "reject_first",
    golden_repeat_enter_on_reject => "repeat_enter_on_reject",
    golden_posted_enter_on_approve => "posted_enter_on_approve",
    golden_stray_key_unarmed => "stray_key_unarmed",
    golden_reactivation_restarts_the_delay => "reactivation_restarts_the_delay",
    golden_c1_message_one_job => "c1_message_one_job",
    golden_c1_stale_sim_one_resim => "c1_stale_sim_one_resim",
    golden_resim_fresh_59999 => "resim_fresh_59999",
    golden_resim_fresh_60000 => "resim_fresh_60000",
    golden_resim_stale_60001 => "resim_stale_60001",
    golden_resim_same_after_click => "resim_same_after_click",
    golden_resim_changed_needs_a_new_click => "resim_changed_needs_a_new_click",
    golden_resim_changed_old_digest => "resim_changed_old_digest",
    golden_resim_no_result_and_failed => "resim_no_result_and_failed",
    golden_stale_resim_result_is_dropped => "stale_resim_result_is_dropped",
    golden_display_change_mid_hold => "display_change_mid_hold",
    golden_high_risk_evm => "high_risk_evm",
    golden_chain_btc => "chain_btc",
    golden_chain_zec => "chain_zec",
    golden_chain_hypercore => "chain_hypercore",
    golden_chain_hypercore_look_alike => "chain_hypercore_look_alike",
    golden_chain_sol_message => "chain_sol_message",
    golden_consume_site_messages => "consume_site_messages",
    golden_site_send_s3_approve => "site_send_s3_approve",
    golden_site_send_s4_approve => "site_send_s4_approve",
    golden_site_send_s3_reject => "site_send_s3_reject",
    golden_consume_app009_branches => "consume_app009_branches",
    golden_blocked_is_never_consumed => "blocked_is_never_consumed",
    golden_expiry_window_tick => "expiry_window_tick",
    golden_expiry_main_tick => "expiry_main_tick",
    golden_l3_site_deadline_window_tick => "l3_site_deadline_window_tick",
    golden_l3_site_deadline_main_tick => "l3_site_deadline_main_tick",
    golden_ui001_and_wc_label => "ui001_and_wc_label",
    golden_open_failure => "open_failure",
    golden_issue_uses_one_instant => "issue_uses_one_instant",
    golden_l1_close_with_a_second_request_queued => "l1_close_with_a_second_request_queued",
    golden_l1_press_past_deadline_escape => "l1_press_past_deadline_escape",
    golden_l1_press_past_deadline_enter => "l1_press_past_deadline_enter",
    golden_l1_press_past_deadline_space => "l1_press_past_deadline_space",
    golden_l1_press_past_deadline_tab => "l1_press_past_deadline_tab",
    golden_l1_press_past_deadline_mouse_reject => "l1_press_past_deadline_mouse_reject",
    golden_l2_connect_chain_change_close_box => "l2_connect_chain_change_close_box",
    golden_l2_connect_chain_change_main_tick => "l2_connect_chain_change_main_tick",
    golden_l2_connect_chain_change_enter_on_reject => "l2_connect_chain_change_enter_on_reject",
    golden_l2_connect_chain_change_mouse_reject => "l2_connect_chain_change_mouse_reject",
    golden_l2_connect_chain_change_escape => "l2_connect_chain_change_escape",
    golden_l2_connect_chain_change_window_tick => "l2_connect_chain_change_window_tick",
    golden_l2_connect_chain_change_approve => "l2_connect_chain_change_approve",
    golden_connect_toggle_layout => "connect_toggle_layout",
    golden_stale_window_input_is_dropped => "stale_window_input_is_dropped",
    golden_connect_toggle_stale_layout => "connect_toggle_stale_layout",
}

/// Every scenario in table order: writes `flow.txt` into `YW_S4_FLOW_OUT` when it is set (for
/// review), else compares the whole golden file (order and completeness).
#[test]
#[ignore = "creates hidden approval windows (S4 flow harness, gate step winui)"]
fn print() {
    let mut out = String::new();
    for (_, scenario) in &SCENARIOS {
        for line in scenario() {
            out.push_str(&line);
            out.push('\n');
        }
    }
    if let Some(dir) = std::env::var_os("YW_S4_FLOW_OUT") {
        let dir = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("flow.txt"), &out).unwrap();
        return;
    }
    let generated: Vec<&str> = out.lines().collect();
    let committed: Vec<&str> = GOLDEN.lines().collect();
    assert!(
        generated == committed,
        "{}",
        first_difference("flow.txt", &generated, &committed)
    );
}

/// The golden names only scenarios of the table, each with lines, grouped in table order, and
/// holds no address, URL, e-mail or local path (gate test step; no window).
#[test]
fn the_flow_golden_names_only_known_scenarios() {
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
        for banned in ["0x", "://", "@", "\\", "Users"] {
            assert!(!line.contains(banned), "{banned:?} in {line}");
        }
        assert!(line.is_ascii(), "non-ASCII text in {line}");
    }
    let table: Vec<&str> = SCENARIOS.iter().map(|(name, _)| *name).collect();
    assert_eq!(order, table, "every scenario, in table order");
}

/// Critique A-3, both halves (2026-11-19, S4 B5 review; no golden line): the shell's open for a
/// `shown` that is not the current flow's makes no window and answers `Failed(E-APP-009)`, which
/// the flow drops as stale (the shown window, flow and queue stay as they were); and a `Shown`
/// answer for a `shown` whose flow has ended closes the window made for it. Neither can happen
/// while effects are applied at once (the open runs right after its flow was stored); the race is
/// built here by calling the executor arm and the answer directly. A deferred-schedule scenario
/// pins it again when the outbox lands (P10, E2).
#[test]
#[ignore = "creates hidden approval windows (S4 flow harness, gate step winui)"]
fn stale_open_and_stale_answer_leave_no_orphan_window() {
    use yw_engine::approval::flow::{ApprovalEffect, OpenOutcome, ShownId};
    use yw_engine::cmd::Cmd;

    use yw_engine::errors::ErrorCode;
    use yw_engine::wallet::approval_flow::ApprovalFlow;

    let fx = fixture("stale-open");
    fx.enqueue_sepolia_send();
    let mut app = fx.app();
    let current = app.evm.approval.as_ref().map(ApprovalFlow::shown).unwrap();
    let window_of = |app: &crate::app::App| app.approval_win.as_ref().map(|win| win.shown);
    assert_eq!(window_of(&app), Some(current));
    let queued = app.evm.queue.len();
    let stale = ShownId(current.0 + 1_000);
    let answer = app.apply_approval_effect(ApprovalEffect::Open {
        shown: stale,
        lang: yw_core::lang::Lang::En,
        ai_reserved: false,
        connect: false,
    });
    assert_eq!(
        answer.map(|cmd| match cmd {
            Cmd::ApprovalOpened {
                shown,
                outcome,
                wide,
            } => Some((shown, outcome, wide)),
            _ => None,
        }),
        Some(Some((stale, OpenOutcome::Failed(ErrorCode::App009), false))),
        "a stale open answers Failed"
    );
    assert_eq!(
        window_of(&app),
        Some(current),
        "no window made, none replaced"
    );
    app.on_approval_opened(stale, OpenOutcome::Failed(ErrorCode::App009), false);
    assert_eq!(
        app.evm.approval.as_ref().map(ApprovalFlow::shown),
        Some(current),
        "a stale Failed answer is dropped"
    );
    assert_eq!(window_of(&app), Some(current));
    assert_eq!(app.evm.queue.len(), queued, "nothing rejected");
    // The flow of the shown window ends before its answer arrives (a deferred schedule).
    assert!(app.evm.approval.take().is_some());
    app.on_approval_opened(
        current,
        OpenOutcome::Shown {
            capture_excluded: false,
        },
        true,
    );
    // 2026-11-20 (S4 P10b, owner decision B): the close it emitted is applied when the entry
    // drains (the outbox; before, `emit` applied it at once).
    app.drain();
    assert_eq!(
        window_of(&app),
        None,
        "the window of an ended flow is closed"
    );
}

/// The lock, revoke, cancel, card-step and grant re-check scenarios of a shown approval
/// (2026-11-18, S4 A6): `s4_flow/lifecycle.txt`, on this module's recorder and drivers.
#[path = "app_approval_lifecycle_tests.rs"]
mod lifecycle;
