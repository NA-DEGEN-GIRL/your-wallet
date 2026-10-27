//! Render harness for the approval window A01 with a fixture dry run (no network, no key, no
//! signing): the real `App` approval path opens the window for a Sepolia send, the preparation job
//! it emits is run through `flow::evm::prepare` against a fixture transport (chain, nonce, fees,
//! gas and an `eth_simulateV1` response from `tests/fixtures/eth_simulateV1/`), and the result goes
//! back through `App::on_simulating` / `App::on_prepared` as the RPC worker would deliver it. The
//! window then runs its own message loop for `YW_SMOKE_HOLD_MS` (default 3,000 ms) so it can be
//! captured from outside, and the test checks that it painted a Ready view.
//!
//! `cargo test -p yw-app --lib app_approval::smoke -- --ignored --nocapture`
//! (`YW_SMOKE_FIXTURE=S3` for a reverted simulation, default `S2`).

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;

use yw_core::bip32::path::AccountIndex;
use yw_core::evm::address::parse_address;
use yw_core::evm::amount::U256;
use yw_core::evm::chain::SEPOLIA_GENESIS;
use yw_core::vault::EvmKeySource;
use yw_json::{Limits, Number, Object, Value};
use yw_win::http::{HttpError, HttpsUrl};
use yw_win::ui::{
    self, CaptureExclusion, ClassSpec, Handler, Msg, Reply, Window, WindowKind, WindowSpec,
};

use super::{APPROVAL_CLASS, PANEL_CLASS};
use crate::apikeys::ApiKeys;
use crate::app::{App, AppMode, Paths};
use crate::app_evm::AppApproval;
use crate::events::JournalView;
use crate::flow::evm::prepare::{SendIntent, prepare};
use crate::flow::evm::{ChainCache, Clock, SharedTransport};
use crate::network::NetworkId;
use crate::rpc::{HttpReply, Transport};
use crate::settings::Settings;
use crate::ui::interaction::{PrepareState, ReadyContent};
use crate::workers::rpc::RpcJob;

const TIMER_CLASS: &str = "YourWalletV3SmokeTimer";
const S2_UNIX_MS: u64 = 0x6ac6_4ee0 * 1_000;

struct FixtureRpc {
    simulate: Vec<u8>,
}

fn envelope(id: &Value, member: &str, value: Value) -> Vec<u8> {
    let pairs = vec![
        ("jsonrpc".to_owned(), Value::String("2.0".to_owned())),
        ("id".to_owned(), id.clone()),
        (member.to_owned(), value),
    ];
    Object::from_pairs(pairs)
        .map_or_else(Vec::new, |object| yw_json::to_vec(&Value::Object(object)))
}

fn parse(text: &str) -> Value {
    let limits = Limits {
        max_bytes: 8 * 1_024 * 1_024,
        ..Limits::RESPONSE
    };
    yw_json::parse(text.as_bytes(), &limits).unwrap_or(Value::Null)
}

impl Transport for FixtureRpc {
    fn post_json(
        &self,
        _url: &HttpsUrl,
        body: &[u8],
        _max_response: usize,
    ) -> Result<HttpReply, HttpError> {
        let request = yw_json::parse(body, &Limits::REQUEST).map_err(|_| HttpError::InvalidUrl)?;
        let object = request.as_object().ok_or(HttpError::InvalidUrl)?;
        let id = object.get("id").cloned().unwrap_or(Value::Null);
        let method = object.get("method").and_then(Value::as_str).unwrap_or("");
        let base = ["\"0x3b9aca00\""; 11].join(",");
        let ratios = ["0.5"; 10].join(",");
        let rewards = ["[\"0x5f5e100\"]"; 10].join(",");
        let result = match method {
            "eth_chainId" => "\"0xaa36a7\"".to_owned(),
            "eth_getBlockByNumber" => format!(
                "{{\"number\":\"0x0\",\"hash\":\"0x{}\"}}",
                yw_core::hex::encode(&SEPOLIA_GENESIS)
            ),
            "eth_getCode" => "\"0x\"".to_owned(),
            "eth_getTransactionCount" => "\"0x5\"".to_owned(),
            "eth_feeHistory" => format!(
                "{{\"oldestBlock\":\"0x1\",\"baseFeePerGas\":[{base}],\"gasUsedRatio\":[{ratios}],\"reward\":[{rewards}]}}"
            ),
            "eth_estimateGas" => "\"0x31f38\"".to_owned(),
            "eth_simulateV1" => {
                let fixture =
                    yw_json::parse(&self.simulate, &Limits::RESPONSE).unwrap_or(Value::Null);
                let pairs: Vec<(String, Value)> = fixture
                    .as_object()
                    .map(|object| {
                        object
                            .iter()
                            .map(|(key, item)| {
                                let item = if key == "id" {
                                    id.clone()
                                } else {
                                    item.clone()
                                };
                                (key.to_owned(), item)
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let body = Object::from_pairs(pairs)
                    .map_or_else(Vec::new, |object| yw_json::to_vec(&Value::Object(object)));
                return Ok(HttpReply { status: 200, body });
            }
            _ => {
                let error = Object::from_pairs(vec![(
                    "code".to_owned(),
                    Value::Number(Number::from_u64(32_601)),
                )])
                .map_or(Value::Null, Value::Object);
                return Ok(HttpReply {
                    status: 200,
                    body: envelope(&id, "error", error),
                });
            }
        };
        Ok(HttpReply {
            status: 200,
            body: envelope(&id, "result", parse(&result)),
        })
    }
}

/// The fixture block's wall time (so the 300 s block-time rule holds).
struct FixtureClock {
    now_ms: AtomicU64,
}

impl Clock for FixtureClock {
    fn now_ms(&self) -> u64 {
        self.now_ms.load(Ordering::SeqCst)
    }

    fn now_unix_ms(&self) -> u64 {
        S2_UNIX_MS.saturating_add(self.now_ms())
    }

    fn sleep_ms(&self, ms: u64) {
        self.now_ms.fetch_add(ms, Ordering::SeqCst);
    }
}

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

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/eth_simulateV1")
        .join(format!("{name}.response.json"));
    std::fs::read(path).unwrap_or_default()
}

#[test]
#[expect(clippy::print_stdout, reason = "the harness reports what it painted")]
#[expect(clippy::too_many_lines, reason = "one end-to-end render scenario")]
#[ignore = "opens a window for a few seconds (render harness, spec/09 smoke run)"]
fn approval_window_renders_a_fixture_dry_run() {
    let name = std::env::var("YW_SMOKE_FIXTURE").unwrap_or_else(|_| "S2".to_owned());
    let hold: u32 = std::env::var("YW_SMOKE_HOLD_MS")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(3_000);
    for (class, secret) in [
        (APPROVAL_CLASS, false),
        (PANEL_CLASS, false),
        (TIMER_CLASS, false),
    ] {
        ui::register_class(&ClassSpec {
            name: class,
            secret,
            capture: CaptureExclusion::Preferred,
        })
        .unwrap();
    }
    let dir = std::env::temp_dir().join(format!("yw-app-a01-{}", std::process::id()));
    let mut apikeys = ApiKeys::default();
    // Never contacted: the preparation job is answered by the fixture transport below.
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
    let (tx, rx) = mpsc::channel();
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
        });
        state.enqueue_app(AppApproval {
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
    // The job the app sent to the RPC worker, answered like the worker would.
    let Ok(RpcJob::Prepare(job)) = rx.try_recv() else {
        unreachable!("no preparation job");
    };
    let transport: SharedTransport = std::sync::Arc::new(FixtureRpc {
        simulate: fixture(&name),
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
    let timer = ui::create_window(
        &WindowSpec::new(TIMER_CLASS, WindowKind::HiddenTopLevel),
        Box::new(QuitOnTimer),
    )
    .unwrap();
    timer.set_timer(1, hold).unwrap();
    let _ = ui::run_loop(&mut |_, _| {});
    {
        let state = app.borrow();
        let window = state.evm.window.as_ref().expect("window open");
        assert!(matches!(
            window.session.gate.prepare,
            PrepareState::Ready(ReadyContent::Signing(_))
        ));
        assert!(window.layout.is_some(), "the panel painted");
        println!(
            "fixture={name} title={:?} band={:?} blocks={} high={} blocked={}",
            window.view.blocks.first(),
            window.view.band.as_ref().map(|band| band.head.clone()),
            window.view.blocks.len(),
            window.view.high,
            window.view.blocked
        );
    }
    app.borrow_mut().close_approval_window();
    drop(timer);
    let _ = std::fs::remove_dir_all(&dir);
}
