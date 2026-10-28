//! spec/05 §10.2 R-D1–R-D5 (dispatcher), R-G1 (grants, lock table, chain cache, limits), R-G2
//! (registered/user chains), R-ERR (yw-app: upstream error sanitizing) and spec/09 §4.2 X-3,
//! X-25 — all without pipes or windows: frames go into [`BrowserCore::handle_frame`], outbound
//! frames and UI events are recorded, reads run through `browser::read::execute` over a fake
//! transport, and the UI side is played by the test (queue outcomes via `outcome_error`).

mod common;

use std::sync::{Arc, Mutex};

use common::browser::{
    Harness, NOW_UNIX, RequestSpec, activation, events_of, json, request_frame, wallet,
};
use common::{Answer, FakeRpc, hex};
use yw_app::browser::envelope::{BrowserEvent, CompatMode, Correlation};
use yw_app::browser::read::{ReadContext, execute};
use yw_app::browser::{BrowserCore, DappEvent, GrantChange, SiteKind, VaultView, outcome_error};
use yw_app::flow::evm::SharedTransport;
use yw_app::rpc::{HttpReply, Transport};
use yw_app::settings::{EvmChainDef, Settings};
use yw_app::ui::approval::{ApprovalQueue, QueueOutcome, QueueSource};
use yw_core::evm::address::{Address, parse_address};
use yw_core::evm::chain::{SEPOLIA, SimulationSupport};
const MAINNET: u64 = 1;
use yw_core::policy::{BrowserOrigin, ConnectedSite, ProviderError};
use yw_json::{Limits, Object, Value};
use yw_win::http::{HttpError, HttpsUrl};

const SITE: &str = "https://app.example";
const OTHER: &str = "https://other.example";
const A0: &str = "0x9858effd232b4033e47d90003d41ec34ecaeda94";
const A1: &str = "0x6fac4d18c912343bf86fa7049364dd4e424ab9c0";
const SEPOLIA_GENESIS: &str = "25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9";

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn origin(text: &str) -> TestResult<BrowserOrigin> {
    BrowserOrigin::parse(text).ok_or_else(|| "origin".into())
}

fn account(text: &str) -> TestResult<Address> {
    Ok(parse_address(text)?)
}

fn grant(site: &str, accounts: &[&str], chain_id: u64) -> TestResult<ConnectedSite> {
    let accounts = accounts
        .iter()
        .map(|a| account(a))
        .collect::<TestResult<Vec<_>>>()?;
    ConnectedSite::new(origin(site)?, accounts, chain_id, NOW_UNIX).ok_or_else(|| "grant".into())
}

fn single(h: &Harness, correlation: &Correlation) -> TestResult<Result<Value, ProviderError>> {
    let mut found = h.take_response(correlation);
    if found.len() != 1 {
        return Err(format!("expected exactly one response, got {}", found.len()).into());
    }
    found.pop().ok_or_else(|| "no response".into())
}

fn text(value: &Result<Value, ProviderError>) -> String {
    match value {
        Ok(value) => String::from_utf8_lossy(&yw_json::to_vec(value)).into_owned(),
        Err(error) => format!("error {} {}", error.code(), error.message()),
    }
}

fn user_chain_settings() -> Settings {
    let mut settings = Settings::default();
    settings.evm_chains.push(EvmChainDef {
        chain_id: 8453,
        name: "Base".to_owned(),
        symbol: "ETH".to_owned(),
        decimals: 18,
        quicknode_subdomain: None,
        alchemy_label: None,
        explorer: None,
        simulation: SimulationSupport::Auto,
        genesis_hash: [0x84; 32],
    });
    settings
}

/// A transport that records the URL of every call and answers `eth_chainId`/genesis per URL.
struct ByUrl {
    calls: Mutex<Vec<(HttpsUrl, String)>>,
    chains: Vec<(HttpsUrl, u64, [u8; 32])>,
}

impl Transport for ByUrl {
    fn post_json(&self, url: &HttpsUrl, body: &[u8], _max: usize) -> Result<HttpReply, HttpError> {
        let request =
            yw_json::parse(body, &yw_json::Limits::REQUEST).map_err(|_| HttpError::InvalidUrl)?;
        let object = request.as_object().ok_or(HttpError::InvalidUrl)?;
        let method = object
            .get("method")
            .and_then(Value::as_str)
            .ok_or(HttpError::InvalidUrl)?
            .to_owned();
        let id = object.get("id").cloned().ok_or(HttpError::InvalidUrl)?;
        if let Ok(mut calls) = self.calls.lock() {
            calls.push((url.clone(), method.clone()));
        }
        let (_, chain_id, genesis) = self
            .chains
            .iter()
            .find(|(known, ..)| known == url)
            .ok_or(HttpError::Timeout)?;
        let result = match method.as_str() {
            "eth_chainId" => format!("\"0x{chain_id:x}\""),
            "eth_getBlockByNumber" => format!("{{\"hash\":\"{}\"}}", hex(genesis)),
            _ => "\"0x1234\"".to_owned(),
        };
        let id = String::from_utf8_lossy(&yw_json::to_vec(&id)).into_owned();
        Ok(HttpReply {
            status: 200,
            body: format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{result}}}").into_bytes(),
        })
    }
}

fn run_reads(core: &BrowserCore, context: &ReadContext) {
    while let Some(task) = core.try_next_read() {
        let body = execute(core, context, &task);
        core.finish_read(&task, body);
    }
}

fn sepolia_rpc(extra: Vec<(&'static str, Answer)>) -> Arc<FakeRpc> {
    FakeRpc::new(move |method, _| {
        if let Some((_, answer)) = extra.iter().find(|(name, _)| *name == method) {
            return answer.clone();
        }
        match method {
            "eth_chainId" => Answer::Result("\"0xaa36a7\"".to_owned()),
            "eth_getBlockByNumber" => {
                Answer::Result(format!("{{\"hash\":\"0x{SEPOLIA_GENESIS}\"}}"))
            }
            "eth_blockNumber" => Answer::Result("\"0x4e20\"".to_owned()),
            _ => Answer::Result("\"0x1\"".to_owned()),
        }
    })
}

#[test]
fn r_d1_no_lifetime_cap_and_burst_limit() -> TestResult {
    let mut h = Harness::new();
    for _ in 0..10_000 {
        let c = h.send(SITE, 1, "eth_chainId", json("[]"));
        assert_eq!(text(&single(&h, &c)?), "\"0xaa36a7\"");
        h.clock.advance(50);
    }
    let mut burst = Harness::new();
    let mut answers = Vec::new();
    for _ in 0..41 {
        let c = burst.send(SITE, 2, "eth_chainId", json("[]"));
        answers.push(single(&burst, &c)?);
    }
    assert!(answers[..40].iter().all(Result::is_ok));
    assert_eq!(answers[40], Err(ProviderError::RateLimited));
    // Another document has its own bucket.
    let c = burst.send(SITE, 3, "eth_chainId", json("[]"));
    assert!(single(&burst, &c)?.is_ok());
    Ok(())
}

#[test]
fn r_d2_errors_keep_the_connection() -> TestResult {
    let mut h = Harness::new();
    h.raw(b"not json");
    h.raw(b"{\"kind\":\"request\"}");
    assert!(h.responses().is_empty(), "uncorrelated frames are dropped");
    let unsupported = h.send(SITE, 1, "eth_sign", json("[]"));
    assert_eq!(
        text(&single(&h, &unsupported)?),
        "error 4200 Unsupported method."
    );
    let route = h.send_with(SITE, 1, "eth_chainId", json("[]"), "read", None);
    assert_eq!(text(&single(&h, &route)?), "error -32600 Invalid request.");
    let params = h.send(SITE, 1, "eth_accounts", json("[1]"));
    assert_eq!(text(&single(&h, &params)?), "error -32602 Invalid params.");
    let expired = h.send_with(
        SITE,
        1,
        "eth_chainId",
        json("[]"),
        "permission",
        Some(NOW_UNIX),
    );
    assert_eq!(
        text(&single(&h, &expired)?),
        "error -32603 Request timed out."
    );
    // A request whose sequence goes backwards: -32600, the connection stays.
    let frame = common::browser::request_frame(&common::browser::RequestSpec {
        sequence: 2,
        request: 0x77,
        document: 1,
        origin: SITE,
        method: "eth_chainId",
        params: json("[]"),
        route: "permission",
        deadline: NOW_UNIX + 600_000,
    });
    h.raw(&frame);
    let regressed = h.responses();
    assert_eq!(regressed.len(), 1);
    assert_eq!(regressed[0].1, Err(ProviderError::InvalidRequest));
    let next = h.send(SITE, 1, "eth_chainId", json("[]"));
    assert_eq!(text(&single(&h, &next)?), "\"0xaa36a7\"");
    Ok(())
}

#[test]
fn r_d3_reads_finish_while_an_approval_waits_and_cancel_is_silent() -> TestResult {
    let mut h = Harness::with(VaultView::Locked, &Settings::default());
    let signing = h.send(
        SITE,
        1,
        "personal_sign",
        json(&format!(r#"["0x68656c6c6f","{A0}"]"#)),
    );
    let requests = h.sink.requests();
    assert_eq!(requests.len(), 1);
    assert!(matches!(requests[0].kind, SiteKind::PersonalSign { .. }));
    // Locked: eth_accounts is [] and reads still work.
    let accounts = h.send(SITE, 2, "eth_accounts", json("[]"));
    assert_eq!(text(&single(&h, &accounts)?), "[]");
    let read = h.send(SITE, 2, "eth_blockNumber", json("[]"));
    let rpc = sepolia_rpc(Vec::new());
    let context = ReadContext {
        transport: Some(rpc.shared()),
        checks: Mutex::new(yw_app::flow::evm::ChainCache::default()),
        retry_delay_ms: 0,
    };
    run_reads(&h.core, &context);
    assert_eq!(text(&single(&h, &read)?), "\"0x4e20\"");
    assert!(matches!(
        h.sink.take().as_slice(),
        [DappEvent::ChainChecked {
            chain_id: SEPOLIA,
            ..
        }]
    ));
    // Cancel of the approval: the UI is told, nothing is answered, later answers are dropped.
    let cancel = format!(
        r#"{{"namespace":"your-wallet","version":1,"role":"extension","kind":"cancel","sessionId":"{}","sequence":{},"activationNonce":"{}","requestId":"{}","requestSequence":{},"reason":"page-cancel"}}"#,
        "bb".repeat(32),
        h.next_sequence(),
        activation(1).hex(),
        signing.request_id.hex(),
        signing.sequence
    );
    h.raw(cancel.as_bytes());
    assert_eq!(
        h.sink.take(),
        vec![DappEvent::Cancel(requests[0].reply.key())]
    );
    assert!(!h.core.respond(&requests[0].reply, Ok(Value::Null)));
    assert!(h.responses().is_empty());
    Ok(())
}

#[test]
fn r_d3_deadlines_and_queue_outcomes() -> TestResult {
    // Read deadline: 60 s after receipt.
    let mut h = Harness::new();
    let read = h.send(SITE, 1, "eth_blockNumber", json("[]"));
    h.clock.advance(60_000);
    let context = ReadContext::new(None);
    run_reads(&h.core, &context);
    assert_eq!(text(&single(&h, &read)?), "error -32603 Request timed out.");
    // Signing deadline: 600 s in the queue → TimedOut → -32603; shown + 120 s → 4001 expired.
    let mut h = Harness::with(VaultView::Locked, &Settings::default());
    let first = h.send(
        SITE,
        1,
        "personal_sign",
        json(&format!(r#"["0x00","{A0}"]"#)),
    );
    let second = h.send(
        SITE,
        1,
        "personal_sign",
        json(&format!(r#"["0x01","{A0}"]"#)),
    );
    let requests = h.sink.requests();
    assert_eq!(requests[0].deadline_ms - h.clock_now(), 600_000);
    let mut queue = ApprovalQueue::default();
    for request in &requests {
        queue
            .enqueue(
                QueueSource::Site {
                    origin: request.origin.as_str().to_owned(),
                    deadline_ms: request.deadline_ms,
                },
                request.clone(),
            )
            .unwrap();
    }
    let now = h.clock_now();
    let mut finished = Vec::new();
    queue.show_next(now, &mut finished);
    queue.mark_ready(now);
    let mut done = queue.tick(now + 120_000);
    done.extend(queue.tick(now + 600_000));
    assert_eq!(done.len(), 2);
    for (item, outcome) in done {
        let error = outcome_error(outcome).unwrap();
        assert!(h.core.respond(&item.payload.reply, Err(error)));
    }
    assert_eq!(text(&single(&h, &first)?), "error 4001 Request expired.");
    assert_eq!(
        text(&single(&h, &second)?),
        "error -32603 Request timed out."
    );
    // Outcome table.
    assert_eq!(
        outcome_error(QueueOutcome::Rejected),
        Some(ProviderError::UserRejected)
    );
    assert_eq!(outcome_error(QueueOutcome::Cancelled), None);
    assert_eq!(
        outcome_error(QueueOutcome::Revoked),
        Some(ProviderError::Unauthorized)
    );
    assert_eq!(
        outcome_error(QueueOutcome::NotReady),
        Some(ProviderError::Unauthorized)
    );
    assert_eq!(
        outcome_error(QueueOutcome::Shutdown),
        Some(ProviderError::ConnectionClosed)
    );
    assert_eq!(
        outcome_error(QueueOutcome::TooManyPending),
        Some(ProviderError::TooManyPending)
    );
    Ok(())
}

#[test]
fn r_d3_simulation_failure_never_changes_the_send_answer() -> TestResult {
    use common::evm::{fake, job, limits, world};
    use yw_app::flow::evm::ChainCache;
    use yw_app::flow::evm::prepare::{PrepareOutcome, prepare};
    let mut h = Harness::new();
    h.core.unlock_wallet(vec![grant(SITE, &[A0], SEPOLIA)?]);
    h.out.take();
    let tx = format!(r#"[{{"from":"{A0}","to":"{A1}","value":"0x1"}}]"#);
    let approve = h.send(SITE, 1, "eth_sendTransaction", json(&tx));
    let reject = h.send(SITE, 1, "eth_sendTransaction", json(&tx));
    let requests = h.sink.requests();
    assert_eq!(
        requests.len(),
        2,
        "slots are the UI's; the dispatcher forwards both"
    );
    for fixture in ["S3", "S4"] {
        let rpc = fake(world(
            SEPOLIA,
            yw_core::evm::chain::SEPOLIA_GENESIS,
            vec![(
                "eth_simulateV1",
                Answer::Envelope(common::evm::fixture(fixture)),
            )],
        ));
        let SiteKind::Send(params) = &requests[0].kind else {
            return Err("not a send".into());
        };
        let mut prepared = job(
            yw_core::evm::chain::builtin_chain(SEPOLIA).unwrap(),
            params.from,
            yw_app::flow::evm::prepare::SendIntent {
                to: params.to,
                value: params.value,
                data: params.data.clone(),
                access_list: Vec::new(),
                dapp_gas: params.gas,
                dapp_nonce: params.nonce,
            },
        );
        prepared.origin = yw_core::approval::ApprovalOrigin::Site(origin(SITE)?);
        prepared.limits = limits();
        let result = prepare(
            &rpc.shared(),
            &mut ChainCache::default(),
            &prepared,
            &common::FakeClock::at(NOW_UNIX),
            &|_| {},
        );
        let PrepareOutcome::Ready(ready) = result.outcome else {
            return Err("simulation failure must still produce an approvable request".into());
        };
        assert_ne!(
            ready.draft.display.risk,
            yw_core::approval::RiskLevel::Blocked
        );
    }
    let hash = format!("0x{}", "ab".repeat(32));
    assert!(
        h.core
            .respond(&requests[0].reply, Ok(Value::String(hash.clone())))
    );
    assert!(h.core.respond(
        &requests[1].reply,
        Err(outcome_error(QueueOutcome::Rejected).unwrap())
    ));
    assert_eq!(text(&single(&h, &approve)?), format!("\"{hash}\""));
    assert_eq!(
        text(&single(&h, &reject)?),
        "error 4001 User rejected the request."
    );
    Ok(())
}

#[test]
fn r_d4_approval_limits_and_duplicate_connect() -> TestResult {
    let mut h = Harness::with(VaultView::Locked, &Settings::default());
    let sign = |h: &mut Harness, site: &str| {
        h.clock.advance(100);
        h.send(
            site,
            1,
            "personal_sign",
            json(&format!(r#"["0x00","{A0}"]"#)),
        )
    };
    for _ in 0..16 {
        sign(&mut h, SITE);
    }
    let seventeenth = sign(&mut h, SITE);
    assert_eq!(
        text(&single(&h, &seventeenth)?),
        "error -32005 Too many pending requests."
    );
    for site in [
        "https://b.example",
        "https://c.example",
        "https://d.example",
    ] {
        for _ in 0..16 {
            sign(&mut h, site);
        }
    }
    assert!(h.responses().is_empty());
    let sixty_fifth = sign(&mut h, "https://e.example");
    assert_eq!(
        text(&single(&h, &sixty_fifth)?),
        "error -32005 Too many pending requests."
    );
    let mut h = Harness::new();
    h.send(SITE, 1, "eth_requestAccounts", json("[]"));
    let duplicate = h.send(
        SITE,
        2,
        "wallet_requestPermissions",
        json(r#"[{"eth_accounts":{}}]"#),
    );
    assert_eq!(
        text(&single(&h, &duplicate)?),
        "error -32002 Request already pending."
    );
    let other = h.send(OTHER, 3, "eth_requestAccounts", json("[]"));
    assert!(h.responses().iter().all(|(c, _)| *c != other));
    assert_eq!(h.sink.requests().len(), 2);
    Ok(())
}

/// A request frame whose context carries `compatMode` (spec/05 §2.12, §6.1).
fn compat_frame(spec: &RequestSpec<'_>, mode: Option<&str>) -> TestResult<Vec<u8>> {
    let frame = request_frame(spec);
    let Some(mode) = mode else {
        return Ok(frame);
    };
    let value = yw_json::parse(&frame, &Limits::REQUEST)?;
    let mut pairs = Vec::new();
    for (key, item) in value.as_object().ok_or("not an object")?.iter() {
        if key == "context" {
            let mut context: Vec<(String, Value)> = item
                .as_object()
                .ok_or("no context")?
                .iter()
                .map(|(name, entry)| (name.to_owned(), entry.clone()))
                .collect();
            context.push(("compatMode".to_owned(), Value::String(mode.to_owned())));
            pairs.push((
                key.to_owned(),
                Value::Object(Object::from_pairs(context).ok_or("duplicate")?),
            ));
        } else {
            pairs.push((key.to_owned(), item.clone()));
        }
    }
    Ok(yw_json::to_vec(&Value::Object(
        Object::from_pairs(pairs).ok_or("duplicate")?,
    )))
}

#[test]
fn r_e3_compat_mode_reaches_the_approval_queue_with_the_real_origin() -> TestResult {
    let mut h = Harness::new();
    let cases = [
        (SITE, Some("metamask"), Some(CompatMode::MetaMask)),
        (OTHER, Some("rabby"), Some(CompatMode::Rabby)),
        ("https://third.example", None, None),
    ];
    for (index, (site, wire, _)) in cases.iter().enumerate() {
        let document = u8::try_from(index + 1)?;
        let sequence = h.next_sequence();
        let frame = compat_frame(
            &RequestSpec {
                sequence,
                request: 0x40 + document,
                document,
                origin: site,
                method: "eth_requestAccounts",
                params: json("[]"),
                route: "permission",
                deadline: NOW_UNIX + 600_000,
            },
            *wire,
        )?;
        h.raw(&frame);
    }
    // Queued for the connect window without an answer; the mode is a note, not a rule change.
    assert!(h.responses().is_empty());
    let requests = h.sink.requests();
    assert_eq!(requests.len(), cases.len());
    for (request, (site, _, expected)) in requests.iter().zip(cases) {
        assert_eq!(request.origin.as_str(), site);
        assert_eq!(request.compat_mode, expected);
        assert!(matches!(request.kind, SiteKind::RequestAccounts));
    }
    // An invalid mode is an invalid envelope for that request only (-32600); the stream lives on.
    let sequence = h.next_sequence();
    let bad = compat_frame(
        &RequestSpec {
            sequence,
            request: 0x50,
            document: 9,
            origin: "https://fourth.example",
            method: "eth_chainId",
            params: json("[]"),
            route: "permission",
            deadline: NOW_UNIX + 600_000,
        },
        Some("off"),
    )?;
    h.raw(&bad);
    let answered = h.responses();
    assert_eq!(answered.len(), 1);
    assert_eq!(answered[0].1, Err(ProviderError::InvalidRequest));
    let next = h.send(SITE, 1, "eth_chainId", json("[]"));
    assert_eq!(text(&single(&h, &next)?), "\"0xaa36a7\"");
    Ok(())
}

#[test]
fn r_d5_get_logs_tags_use_the_block_cache_on_the_worker() -> TestResult {
    let mut h = Harness::new();
    let rpc = sepolia_rpc(Vec::new());
    let context = ReadContext {
        transport: Some(rpc.shared()),
        checks: Mutex::new(yw_app::flow::evm::ChainCache::default()),
        retry_delay_ms: 0,
    };
    // No cache: one eth_blockNumber (B = 20,000), then the range check.
    let ok = h.send(
        SITE,
        1,
        "eth_getLogs",
        json(r#"[{"fromBlock":"0x2710","toBlock":"latest"}]"#),
    );
    assert_eq!(
        rpc.count("eth_blockNumber"),
        0,
        "the reader thread made no RPC call"
    );
    run_reads(&h.core, &context);
    assert_eq!(rpc.count("eth_blockNumber"), 1);
    assert!(single(&h, &ok)?.is_ok());
    assert_eq!(
        rpc.params_of("eth_getLogs"),
        vec![r#"[{"fromBlock":"0x2710","toBlock":"latest"}]"#]
    );
    // Cached (≤ 12 s): no lookup; range violation → -32602.
    h.clock.advance(12_000);
    let too_wide = h.send(
        SITE,
        1,
        "eth_getLogs",
        json(r#"[{"fromBlock":"0x270f","toBlock":"latest"}]"#),
    );
    run_reads(&h.core, &context);
    assert_eq!(rpc.count("eth_blockNumber"), 1);
    assert_eq!(
        text(&single(&h, &too_wide)?),
        "error -32602 Invalid params."
    );
    // 12,001 ms after the last lookup: one more lookup.
    h.clock.advance(1);
    let again = h.send(
        SITE,
        1,
        "eth_getLogs",
        json(r#"[{"fromBlock":"0x4e20","toBlock":"safe"}]"#),
    );
    run_reads(&h.core, &context);
    assert_eq!(rpc.count("eth_blockNumber"), 2);
    assert!(single(&h, &again)?.is_ok());
    // Both tags: no lookup.
    h.clock.advance(20_000);
    let tags = h.send(
        SITE,
        1,
        "eth_getLogs",
        json(r#"[{"fromBlock":"latest","toBlock":"finalized"}]"#),
    );
    run_reads(&h.core, &context);
    assert_eq!(rpc.count("eth_blockNumber"), 2);
    assert!(single(&h, &tags)?.is_ok());
    // eth_blockNumber failure → 4901.
    let failing = sepolia_rpc(vec![(
        "eth_blockNumber",
        Answer::Transport(HttpError::Timeout),
    )]);
    let failing_context = ReadContext {
        transport: Some(failing.shared()),
        checks: Mutex::new(yw_app::flow::evm::ChainCache::default()),
        retry_delay_ms: 0,
    };
    let mut h = Harness::new();
    let broken = h.send(SITE, 1, "eth_getLogs", json(r#"[{"fromBlock":"0x1"}]"#));
    run_reads(&h.core, &failing_context);
    assert_eq!(
        text(&single(&h, &broken)?),
        "error 4901 Chain RPC is unavailable."
    );
    assert_eq!(failing.count("eth_getLogs"), 0);
    Ok(())
}

#[test]
fn r_err_upstream_errors_are_sanitized() {
    let rpc = sepolia_rpc(vec![
        ("eth_call", Answer::Error(3, Some("0xDEADBEEF".to_owned()))),
        (
            "eth_estimateGas",
            Answer::Error(-32_700, Some("nothex".to_owned())),
        ),
        ("eth_gasPrice", Answer::Status(429)),
        ("eth_maxPriorityFeePerGas", Answer::Status(500)),
        ("eth_getCode", Answer::Transport(HttpError::TooLarge)),
        ("eth_getBalance", Answer::Transport(HttpError::Tls)),
    ]);
    let context = ReadContext {
        transport: Some(rpc.shared()),
        checks: Mutex::new(yw_app::flow::evm::ChainCache::default()),
        retry_delay_ms: 0,
    };
    let mut h = Harness::new();
    let call = h.send(SITE, 1, "eth_call", json(&format!(r#"[{{"to":"{A1}"}}]"#)));
    let estimate = h.send(
        SITE,
        1,
        "eth_estimateGas",
        json(&format!(r#"[{{"to":"{A1}"}}]"#)),
    );
    let price = h.send(SITE, 1, "eth_gasPrice", json("[]"));
    let tip = h.send(SITE, 1, "eth_maxPriorityFeePerGas", json("[]"));
    let code = h.send(SITE, 1, "eth_getCode", json(&format!(r#"["{A1}"]"#)));
    let balance = h.send(SITE, 1, "eth_getBalance", json(&format!(r#"["{A1}"]"#)));
    run_reads(&h.core, &context);
    let responses = h.responses();
    let get = |c: &Correlation| responses.iter().find(|(k, _)| k == c).unwrap().1.clone();
    assert_eq!(
        get(&call),
        Err(ProviderError::Upstream {
            code: 3,
            message: "scripted".to_owned(),
            data: Some("0xdeadbeef".to_owned())
        })
    );
    assert_eq!(
        get(&estimate),
        Err(ProviderError::Upstream {
            code: -32_603,
            message: "scripted".to_owned(),
            data: None
        })
    );
    assert_eq!(get(&price), Err(ProviderError::RateLimited));
    assert_eq!(get(&tip), Err(ProviderError::ChainUnavailable));
    assert_eq!(get(&code), Err(ProviderError::ResponseTooLarge));
    assert_eq!(get(&balance), Err(ProviderError::ChainUnavailable));
}

#[test]
fn r_g1_connect_lock_unlock_events_and_reads() -> TestResult {
    let mut h = Harness::new();
    // Two documents of the site, one of another origin.
    let _ = h.send(SITE, 1, "eth_chainId", json("[]"));
    let _ = h.send(SITE, 2, "eth_chainId", json("[]"));
    let _ = h.send(OTHER, 3, "eth_chainId", json("[]"));
    h.out.take();
    let before = h.send(SITE, 1, "eth_accounts", json("[]"));
    assert_eq!(text(&single(&h, &before)?), "[]");
    let permissions = h.send(SITE, 1, "wallet_getPermissions", json("[]"));
    assert_eq!(text(&single(&h, &permissions)?), "[]");
    let connect = h.send(SITE, 1, "eth_requestAccounts", json("[]"));
    let requests = h.sink.requests();
    assert_eq!(requests[0].kind, SiteKind::RequestAccounts);
    // The UI approves: answer first, then the grant and its event.
    assert!(
        h.core
            .respond(&requests[0].reply, Ok(json(&format!(r#"["{A0}"]"#))))
    );
    h.core.upsert_grant(grant(SITE, &[A0], SEPOLIA)?);
    let out = h.out.take();
    assert!(
        matches!(&out[0], yw_app::browser::Outbound::Response { correlation, .. } if *correlation == connect)
    );
    let a0 = *account(A0)?.as_bytes();
    for document in [1, 2] {
        assert_eq!(
            events_of(&out, document),
            vec![BrowserEvent::AccountsChanged(vec![a0])]
        );
    }
    assert!(events_of(&out, 3).is_empty());
    let after = h.send(SITE, 1, "eth_accounts", json("[]"));
    assert_eq!(text(&single(&h, &after)?), format!(r#"["{A0}"]"#));
    let again = h.send(SITE, 1, "eth_requestAccounts", json("[]"));
    assert_eq!(text(&single(&h, &again)?), format!(r#"["{A0}"]"#));
    assert!(h.sink.requests().is_empty(), "connected: no window");
    let permissions = h.send(SITE, 1, "wallet_getPermissions", json("[]"));
    assert_eq!(
        text(&single(&h, &permissions)?),
        format!(
            r#"[{{"invoker":"{SITE}","parentCapability":"eth_accounts","caveats":[{{"type":"restrictReturnedAccounts","value":["{A0}"]}}],"date":{NOW_UNIX}}}]"#
        )
    );
    // Lock: accountsChanged([]) to the site's documents; eth_accounts [] and chainId still work.
    h.core.lock_wallet();
    h.core
        .set_wallet(wallet(VaultView::Locked, &Settings::default()));
    let out = h.out.take();
    assert_eq!(
        events_of(&out, 1),
        vec![BrowserEvent::AccountsChanged(Vec::new())]
    );
    assert_eq!(
        events_of(&out, 2),
        vec![BrowserEvent::AccountsChanged(Vec::new())]
    );
    assert!(events_of(&out, 3).is_empty());
    let locked = h.send(SITE, 1, "eth_accounts", json("[]"));
    assert_eq!(text(&single(&h, &locked)?), "[]");
    let chain = h.send(SITE, 1, "eth_chainId", json("[]"));
    assert_eq!(text(&single(&h, &chain)?), "\"0xaa36a7\"");
    // Locked eth_requestAccounts waits for the unlock window.
    h.send(SITE, 1, "eth_requestAccounts", json("[]"));
    assert_eq!(h.sink.requests()[0].kind, SiteKind::RequestAccounts);
    // Unlock: accountsChanged(accounts), no chainChanged (same chain).
    h.core
        .set_wallet(wallet(VaultView::Unlocked, &Settings::default()));
    let changed = h.core.unlock_wallet(vec![grant(SITE, &[A0], SEPOLIA)?]);
    assert!(changed.is_empty());
    let out = h.out.take();
    assert_eq!(
        events_of(&out, 1),
        vec![BrowserEvent::AccountsChanged(vec![a0])]
    );
    // Revoke: null, accountsChanged([]), persisted by the UI.
    let revoke = h.send(
        SITE,
        2,
        "wallet_revokePermissions",
        json(r#"[{"eth_accounts":{}}]"#),
    );
    let out = h.out.take();
    assert!(
        matches!(&out[0], yw_app::browser::Outbound::Response { correlation, body: Ok(Value::Null) } if *correlation == revoke)
    );
    assert_eq!(
        events_of(&out, 1),
        vec![BrowserEvent::AccountsChanged(Vec::new())]
    );
    assert_eq!(
        h.sink.take(),
        vec![DappEvent::GrantChanged {
            origin: origin(SITE)?,
            change: GrantChange::Revoked
        }]
    );
    assert!(h.core.grants().is_empty());
    Ok(())
}

/// spec/02 §7.5: a session opened with an unverified BIP39 passphrase refuses connect and
/// signing requests with 4100 and the reason (no window), while reads continue.
#[test]
fn passphrase_unverified_refuses_connect_and_signing_but_serves_reads() -> TestResult {
    let refused = format!(
        "error 4100 {}",
        ProviderError::PassphraseUnverified.message()
    );
    assert!(refused.contains("unverified passphrase"));
    let mut h = Harness::with(VaultView::PassphraseUnverified, &Settings::default());
    for (method, params) in [
        ("eth_requestAccounts", "[]".to_owned()),
        (
            "wallet_requestPermissions",
            r#"[{"eth_accounts":{}}]"#.to_owned(),
        ),
        ("personal_sign", format!(r#"["0x00","{A0}"]"#)),
        (
            "eth_sendTransaction",
            format!(r#"[{{"from":"{A0}","to":"{A1}"}}]"#),
        ),
        (
            "eth_signTypedData_v4",
            format!(
                r#"["{A0}","{{\"types\":{{\"EIP712Domain\":[{{\"name\":\"chainId\",\"type\":\"uint256\"}}],\"Note\":[{{\"name\":\"text\",\"type\":\"string\"}}]}},\"primaryType\":\"Note\",\"domain\":{{\"chainId\":11155111}},\"message\":{{\"text\":\"hi\"}}}}"]"#
            ),
        ),
    ] {
        let request = h.send(SITE, 1, method, json(&params));
        assert_eq!(text(&single(&h, &request)?), refused, "{method}");
    }
    assert!(h.sink.requests().is_empty(), "no approval window");
    // Reads continue: account reads are empty (no grants), chain reads go to the read workers.
    let accounts = h.send(SITE, 1, "eth_accounts", json("[]"));
    assert_eq!(text(&single(&h, &accounts)?), "[]");
    let chain = h.send(SITE, 1, "eth_chainId", json("[]"));
    assert_eq!(text(&single(&h, &chain)?), "\"0xaa36a7\"");
    let revoke = h.send(
        SITE,
        1,
        "wallet_revokePermissions",
        json(r#"[{"eth_accounts":{}}]"#),
    );
    assert_eq!(text(&single(&h, &revoke)?), "null");
    let read = h.send(SITE, 1, "eth_blockNumber", json("[]"));
    let context = ReadContext {
        transport: Some(sepolia_rpc(Vec::new()).shared()),
        checks: Mutex::new(yw_app::flow::evm::ChainCache::default()),
        retry_delay_ms: 0,
    };
    run_reads(&h.core, &context);
    assert_eq!(text(&single(&h, &read)?), "\"0x4e20\"");
    // The outcome of a queued item (queued while locked, then unlocked unverified).
    assert_eq!(
        outcome_error(QueueOutcome::PassphraseUnverified),
        Some(ProviderError::PassphraseUnverified)
    );
    Ok(())
}

#[test]
fn r_g1_x3_backup_pending_no_vault_and_unconnected_accounts() -> TestResult {
    for vault in [VaultView::BackupPending, VaultView::NoVault] {
        let mut h = Harness::with(vault, &Settings::default());
        let connect = h.send(SITE, 1, "eth_requestAccounts", json("[]"));
        assert_eq!(text(&single(&h, &connect)?), "error 4100 Unauthorized.");
        let sign = h.send(
            SITE,
            1,
            "personal_sign",
            json(&format!(r#"["0x00","{A0}"]"#)),
        );
        assert_eq!(text(&single(&h, &sign)?), "error 4100 Unauthorized.");
        let accounts = h.send(SITE, 1, "eth_accounts", json("[]"));
        assert_eq!(text(&single(&h, &accounts)?), "[]");
        assert!(h.sink.requests().is_empty());
    }
    // X-3: `from` not a granted account → 4100, no window; unconnected origin → 4100.
    let mut h = Harness::new();
    h.core.unlock_wallet(vec![grant(SITE, &[A0], SEPOLIA)?]);
    let other = h.send(
        SITE,
        1,
        "eth_sendTransaction",
        json(&format!(r#"[{{"from":"{A1}","to":"{A0}"}}]"#)),
    );
    assert_eq!(text(&single(&h, &other)?), "error 4100 Unauthorized.");
    let stranger = h.send(
        OTHER,
        2,
        "personal_sign",
        json(&format!(r#"["0x00","{A0}"]"#)),
    );
    assert_eq!(text(&single(&h, &stranger)?), "error 4100 Unauthorized.");
    // chainId of the transaction ≠ origin chain → -32602; typed data T01 → -32602 (no window).
    let wrong_chain = h.send(
        SITE,
        1,
        "eth_sendTransaction",
        json(&format!(
            r#"[{{"from":"{A0}","to":"{A1}","chainId":"0x1"}}]"#
        )),
    );
    assert_eq!(
        text(&single(&h, &wrong_chain)?),
        "error -32602 Invalid params."
    );
    let typed = r#"{"types":{"EIP712Domain":[{"name":"chainId","type":"uint256"}],"Mail":[{"name":"x","type":"uint256"}]},"primaryType":"Mail","domain":{"chainId":1},"message":{"x":1}}"#;
    let t01 = h.send(
        SITE,
        1,
        "eth_signTypedData_v4",
        json(&format!(r#"["{A0}",{typed}]"#)),
    );
    assert_eq!(text(&single(&h, &t01)?), "error -32602 Invalid params.");
    assert!(h.sink.requests().is_empty());
    Ok(())
}

#[test]
fn r_g1_chain_cache_follows_first_use() -> TestResult {
    let mut settings = Settings {
        evm_chain_id: MAINNET,
        ..Settings::default()
    };
    let mut h = Harness::with(VaultView::Locked, &settings);
    let first = h.send(SITE, 1, "eth_chainId", json("[]"));
    assert_eq!(text(&single(&h, &first)?), "\"0x1\"");
    h.core.set_wallet(wallet(VaultView::Unlocked, &settings));
    let unlocked = h.send(SITE, 1, "eth_chainId", json("[]"));
    assert_eq!(text(&single(&h, &unlocked)?), "\"0x1\"");
    settings.evm_chain_id = SEPOLIA;
    h.core.set_wallet(wallet(VaultView::Unlocked, &settings));
    let same_origin = h.send(SITE, 1, "eth_chainId", json("[]"));
    assert_eq!(text(&single(&h, &same_origin)?), "\"0x1\"");
    let fresh = h.send(OTHER, 2, "net_version", json("[]"));
    assert_eq!(text(&single(&h, &fresh)?), "\"11155111\"");
    assert!(events_of(&h.out.take(), 1).is_empty());
    let version = h.send(SITE, 1, "web3_clientVersion", json("[]"));
    assert_eq!(
        text(&single(&h, &version)?),
        format!("\"YourWallet/{}\"", env!("CARGO_PKG_VERSION"))
    );
    Ok(())
}

#[test]
fn r_g1_grant_limits() -> TestResult {
    let mut h = Harness::new();
    let sixteen: Vec<String> = (1..=16).map(|i| format!("0x{i:040x}")).collect();
    let refs: Vec<&str> = sixteen.iter().map(String::as_str).collect();
    let _ = h.send(SITE, 1, "eth_chainId", json("[]"));
    h.out.take();
    h.core.upsert_grant(grant(SITE, &refs, SEPOLIA)?);
    match events_of(&h.out.take(), 1).as_slice() {
        [BrowserEvent::AccountsChanged(list)] => assert_eq!(list.len(), 16),
        other => return Err(format!("{other:?}").into()),
    }
    let mut seventeen: Vec<Address> = refs.iter().map(|a| account(a)).collect::<TestResult<_>>()?;
    seventeen.push(account(A0)?);
    assert!(ConnectedSite::new(origin(OTHER)?, seventeen, SEPOLIA, 0).is_none());
    // 256 grants: existing origin reconnects normally, a new origin gets 4100 without a window.
    let mut grants: Vec<ConnectedSite> = (0..255)
        .map(|i| grant(&format!("https://s{i}.example"), &[A0], SEPOLIA))
        .collect::<TestResult<_>>()?;
    grants.push(grant(SITE, &[A0], SEPOLIA)?);
    let mut h = Harness::new();
    h.core.unlock_wallet(grants);
    let existing = h.send(SITE, 1, "eth_requestAccounts", json("[]"));
    assert_eq!(text(&single(&h, &existing)?), format!(r#"["{A0}"]"#));
    h.send(
        SITE,
        1,
        "wallet_requestPermissions",
        json(r#"[{"eth_accounts":{}}]"#),
    );
    assert_eq!(
        h.sink.requests().len(),
        1,
        "re-selection window for a connected origin"
    );
    let new = h.send(OTHER, 2, "eth_requestAccounts", json("[]"));
    assert_eq!(text(&single(&h, &new)?), "error 4100 Unauthorized.");
    assert!(h.sink.requests().is_empty());
    Ok(())
}

#[test]
fn r_g2_x25_switching_registered_and_user_chains() -> TestResult {
    let settings = user_chain_settings();
    let mut h = Harness::with(VaultView::Unlocked, &settings);
    h.core.unlock_wallet(vec![grant(SITE, &[A0], SEPOLIA)?]);
    let _ = h.send(SITE, 1, "eth_chainId", json("[]"));
    let _ = h.send(OTHER, 2, "eth_chainId", json("[]"));
    h.out.take();
    h.sink.take();
    let switch = h.send(
        SITE,
        1,
        "wallet_switchEthereumChain",
        json(r#"[{"chainId":"0x2105"}]"#),
    );
    let out = h.out.take();
    assert!(
        matches!(&out[0], yw_app::browser::Outbound::Response { correlation, body: Ok(Value::Null) } if *correlation == switch)
    );
    assert_eq!(events_of(&out, 1), vec![BrowserEvent::ChainChanged(8453)]);
    assert!(events_of(&out, 2).is_empty());
    assert_eq!(
        h.sink.take(),
        vec![DappEvent::GrantChanged {
            origin: origin(SITE)?,
            change: GrantChange::Chain(8453)
        }]
    );
    assert_eq!(h.core.grants()[0].chain_id, 8453);
    let chain = h.send(SITE, 1, "eth_chainId", json("[]"));
    assert_eq!(text(&single(&h, &chain)?), "\"0x2105\"");
    let version = h.send(SITE, 1, "net_version", json("[]"));
    assert_eq!(text(&single(&h, &version)?), "\"8453\"");
    // Same chain again: null, no event.
    let again = h.send(
        SITE,
        1,
        "wallet_switchEthereumChain",
        json(r#"[{"chainId":"0x2105"}]"#),
    );
    let out = h.out.take();
    assert_eq!(out.len(), 1);
    assert!(
        matches!(&out[0], yw_app::browser::Outbound::Response { correlation, body: Ok(Value::Null) } if *correlation == again)
    );
    // Built-in 999.
    let hyper = h.send(
        OTHER,
        2,
        "wallet_switchEthereumChain",
        json(r#"[{"chainId":"0x3e7"}]"#),
    );
    assert_eq!(text(&single(&h, &hyper)?), "null");
    let hyper_id = h.send(OTHER, 2, "eth_chainId", json("[]"));
    assert_eq!(text(&single(&h, &hyper_id)?), "\"0x3e7\"");
    // Unregistered → 4902; wallet_addEthereumChain → 4200 and the registry is unchanged.
    for target in ["0x89", "0x0"] {
        let unknown = h.send(
            SITE,
            1,
            "wallet_switchEthereumChain",
            json(&format!(r#"[{{"chainId":"{target}"}}]"#)),
        );
        assert_eq!(
            text(&single(&h, &unknown)?),
            "error 4902 Unrecognized chain."
        );
    }
    for chain_id in ["0x89", "0x2105"] {
        let add = h.send(
            SITE,
            1,
            "wallet_addEthereumChain",
            json(&format!(r#"[{{"chainId":"{chain_id}","chainName":"X","nativeCurrency":{{"name":"X","symbol":"X","decimals":18}},"rpcUrls":["https://rpc.example"]}}]"#)),
        );
        assert_eq!(text(&single(&h, &add)?), "error 4200 Unsupported method.");
    }
    let still = h.send(
        SITE,
        1,
        "wallet_switchEthereumChain",
        json(r#"[{"chainId":"0x89"}]"#),
    );
    assert_eq!(text(&single(&h, &still)?), "error 4902 Unrecognized chain.");
    assert_eq!(h.core.wallet().chains.len(), 4);
    Ok(())
}

#[test]
fn r_g2_reads_go_to_the_origin_chain_endpoint_only() -> TestResult {
    let settings = user_chain_settings();
    let base_url = HttpsUrl::parse("https://rpc.example.test/base").unwrap();
    let sepolia_url = HttpsUrl::parse("https://rpc.example.test/sepolia").unwrap();
    let transport = Arc::new(ByUrl {
        calls: Mutex::new(Vec::new()),
        chains: vec![
            (base_url.clone(), 8453, [0x84; 32]),
            (
                sepolia_url.clone(),
                SEPOLIA,
                yw_core::hex::decode_array::<32>(SEPOLIA_GENESIS).unwrap(),
            ),
        ],
    });
    let mut h = Harness::with(VaultView::Unlocked, &settings);
    let mut view = wallet(VaultView::Unlocked, &settings);
    for entry in &mut view.chains {
        entry.url = match entry.info.chain_id {
            8453 => Some(base_url.clone()),
            SEPOLIA => Some(sepolia_url.clone()),
            _ => None,
        };
    }
    h.core.set_wallet(view.clone());
    let context = ReadContext {
        transport: Some(Arc::clone(&transport) as SharedTransport),
        checks: Mutex::new(yw_app::flow::evm::ChainCache::default()),
        retry_delay_ms: 0,
    };
    let switch = h.send(
        SITE,
        1,
        "wallet_switchEthereumChain",
        json(r#"[{"chainId":"0x2105"}]"#),
    );
    assert_eq!(text(&single(&h, &switch)?), "null");
    assert!(
        transport.calls.lock().unwrap().is_empty(),
        "switching makes no RPC call"
    );
    let read = h.send(SITE, 1, "eth_blockNumber", json("[]"));
    run_reads(&h.core, &context);
    assert_eq!(text(&single(&h, &read)?), "\"0x1234\"");
    let calls = transport.calls.lock().unwrap().clone();
    assert!(!calls.is_empty());
    assert!(calls.iter().all(|(url, _)| *url == base_url));
    assert_eq!(
        calls.last().map(|(_, m)| m.as_str()),
        Some("eth_blockNumber")
    );
    // No endpoint (999 here): switching works, reads are 4901 with zero RPC calls.
    let hyper = h.send(
        OTHER,
        2,
        "wallet_switchEthereumChain",
        json(r#"[{"chainId":"0x3e7"}]"#),
    );
    assert_eq!(text(&single(&h, &hyper)?), "null");
    let before = transport.calls.lock().unwrap().len();
    let no_endpoint = h.send(OTHER, 2, "eth_blockNumber", json("[]"));
    run_reads(&h.core, &context);
    assert_eq!(
        text(&single(&h, &no_endpoint)?),
        "error 4901 Chain RPC is unavailable."
    );
    assert_eq!(transport.calls.lock().unwrap().len(), before);
    // Blocked (RpcMismatch): switch 4901, no cache/grant/event change; cleared → works.
    view.blocked = vec![8453];
    h.core.set_wallet(view.clone());
    let blocked_switch = h.send(
        OTHER,
        2,
        "wallet_switchEthereumChain",
        json(r#"[{"chainId":"0x2105"}]"#),
    );
    assert_eq!(
        text(&single(&h, &blocked_switch)?),
        "error 4901 Chain RPC is unavailable."
    );
    let unchanged = h.send(OTHER, 2, "eth_chainId", json("[]"));
    assert_eq!(text(&single(&h, &unchanged)?), "\"0x3e7\"");
    let blocked_read = h.send(SITE, 1, "eth_blockNumber", json("[]"));
    run_reads(&h.core, &context);
    assert_eq!(
        text(&single(&h, &blocked_read)?),
        "error 4901 Chain RPC is unavailable."
    );
    view.blocked.clear();
    h.core.set_wallet(view);
    let cleared = h.send(
        OTHER,
        2,
        "wallet_switchEthereumChain",
        json(r#"[{"chainId":"0x2105"}]"#),
    );
    assert_eq!(text(&single(&h, &cleared)?), "null");
    Ok(())
}

#[test]
fn r_g2_locked_switch_unlock_merge_and_chain_removal() -> TestResult {
    let settings = user_chain_settings();
    let mut h = Harness::with(VaultView::Locked, &settings);
    let _ = h.send(SITE, 1, "eth_chainId", json("[]"));
    h.out.take();
    // Locked: the cache changes (with chainChanged); the grant is merged at unlock.
    let switch = h.send(
        SITE,
        1,
        "wallet_switchEthereumChain",
        json(r#"[{"chainId":"0x2105"}]"#),
    );
    let out = h.out.take();
    assert!(
        matches!(&out[0], yw_app::browser::Outbound::Response { correlation, .. } if *correlation == switch)
    );
    assert_eq!(events_of(&out, 1), vec![BrowserEvent::ChainChanged(8453)]);
    assert!(
        h.sink
            .take()
            .iter()
            .all(|e| !matches!(e, DappEvent::GrantChanged { .. }))
    );
    h.core.set_wallet(wallet(VaultView::Unlocked, &settings));
    let changed = h.core.unlock_wallet(vec![
        grant(SITE, &[A0], SEPOLIA)?,
        grant(OTHER, &[A0], 999)?,
        grant("https://gone.example", &[A0], 137)?,
    ]);
    let mut ids: Vec<(String, u64)> = changed
        .iter()
        .map(|site| (site.origin.as_str().to_owned(), site.chain_id))
        .collect();
    ids.sort();
    assert_eq!(
        ids,
        vec![
            (SITE.to_owned(), 8453),
            ("https://gone.example".to_owned(), SEPOLIA)
        ]
    );
    let out = h.out.take();
    assert_eq!(
        events_of(&out, 1),
        vec![BrowserEvent::AccountsChanged(vec![
            *account(A0)?.as_bytes()
        ])]
    );
    // An origin whose cache was filled from its grant (999) learns the chain at its next query.
    let other = h.send(OTHER, 2, "eth_chainId", json("[]"));
    assert_eq!(text(&single(&h, &other)?), "\"0x3e7\"");
    // User chain deleted: chainChanged(evmChainId) to its origins, grants rewritten.
    let rewritten = h.core.chain_removed(8453, SEPOLIA);
    assert_eq!(rewritten.len(), 1);
    assert_eq!(rewritten[0].chain_id, SEPOLIA);
    let out = h.out.take();
    assert_eq!(
        events_of(&out, 1),
        vec![BrowserEvent::ChainChanged(SEPOLIA)]
    );
    let chain = h.send(SITE, 1, "eth_chainId", json("[]"));
    assert_eq!(text(&single(&h, &chain)?), "\"0xaa36a7\"");
    Ok(())
}

/// C8: while locked, typed data is queued for the unlock window without being validated by the
/// dispatcher (the approval flow validates it later); cheap limits still apply first.
#[test]
fn locked_typed_data_is_queued_without_validation() -> TestResult {
    let mut h = Harness::with(VaultView::Locked, &Settings::default());
    // Domain chainId 1 on a Sepolia origin: unlocked this is -32602 at once (X-3 above).
    let typed = r#"{"types":{"EIP712Domain":[{"name":"chainId","type":"uint256"}],"Mail":[{"name":"x","type":"uint256"}]},"primaryType":"Mail","domain":{"chainId":1},"message":{"x":1}}"#;
    let params = json(&format!(r#"["{A0}",{typed}]"#));
    for _ in 0..16 {
        h.clock.advance(100);
        h.send(SITE, 1, "eth_signTypedData_v4", params.clone());
    }
    assert!(h.responses().is_empty());
    assert_eq!(h.sink.requests().len(), 16);
    let over = h.send(SITE, 1, "eth_signTypedData_v4", params);
    assert_eq!(
        text(&single(&h, &over)?),
        "error -32005 Too many pending requests."
    );
    Ok(())
}

/// A stale answer for request ids that another pending request reuses leaves that request's
/// approval record alone (the duplicate-connect rule still sees it).
#[test]
fn respond_checks_the_sequence_before_dropping_the_approval() -> TestResult {
    let mut h = Harness::new();
    let connect = h.send(SITE, 1, "eth_requestAccounts", json("[]"));
    let stale = yw_app::browser::Reply {
        conn: h.conn,
        correlation: Correlation {
            sequence: connect.sequence + 100,
            ..connect
        },
    };
    assert!(!h.core.respond(&stale, Err(ProviderError::Internal)));
    let duplicate = h.send(SITE, 2, "eth_requestAccounts", json("[]"));
    assert_eq!(
        text(&single(&h, &duplicate)?),
        "error -32002 Request already pending."
    );
    assert!(h.take_response(&connect).is_empty());
    Ok(())
}

/// spec/05 §4.6: with the localhost toggle off, localhost documents get no events either.
#[test]
fn localhost_events_follow_the_toggle() -> TestResult {
    const LOCAL: &str = "http://localhost:5173";
    let mut settings = Settings {
        allow_localhost_dapps: true,
        ..Settings::default()
    };
    let mut h = Harness::with(VaultView::Unlocked, &settings);
    let _ = h.send(LOCAL, 1, "eth_chainId", json("[]"));
    h.out.take();
    settings.allow_localhost_dapps = false;
    h.core.set_wallet(wallet(VaultView::Unlocked, &settings));
    h.core.upsert_grant(grant(LOCAL, &[A0], SEPOLIA)?);
    assert!(events_of(&h.out.take(), 1).is_empty());
    settings.allow_localhost_dapps = true;
    h.core.set_wallet(wallet(VaultView::Unlocked, &settings));
    h.core.remove_grant(&origin(LOCAL)?);
    assert_eq!(
        events_of(&h.out.take(), 1),
        vec![BrowserEvent::AccountsChanged(Vec::new())]
    );
    Ok(())
}

/// spec/05 §8.4: an unconnected origin has a read budget over all its documents; connected
/// origins and other sites keep their reads.
#[test]
fn unconnected_origins_have_a_read_budget() -> TestResult {
    let mut h = Harness::new();
    let mut answered = Vec::new();
    for document in 1..=4 {
        for _ in 0..16 {
            let c = h.send(OTHER, document, "eth_blockNumber", json("[]"));
            answered.extend(h.take_response(&c));
        }
    }
    assert!(answered.is_empty(), "64 reads queued");
    let over = h.send(OTHER, 5, "eth_blockNumber", json("[]"));
    assert_eq!(
        text(&single(&h, &over)?),
        "error -32005 Too many pending requests."
    );
    let elsewhere = h.send(SITE, 6, "eth_blockNumber", json("[]"));
    assert!(
        h.take_response(&elsewhere).is_empty(),
        "another site still reads"
    );
    // A connected origin is not held to the per-origin budget.
    h.core.unlock_wallet(vec![grant(SITE, &[A0], SEPOLIA)?]);
    for document in 7..=11 {
        for _ in 0..14 {
            let c = h.send(SITE, document, "eth_blockNumber", json("[]"));
            assert!(h.take_response(&c).is_empty());
        }
    }
    // Finishing reads frees the budget.
    while let Some(task) = h.core.try_next_read() {
        h.core
            .finish_read(&task, Err(ProviderError::ChainUnavailable));
    }
    h.out.take();
    let again = h.send(OTHER, 12, "eth_blockNumber", json("[]"));
    assert!(h.take_response(&again).is_empty());
    Ok(())
}

/// A signing request sent while the site's connect window is still pending waits behind it in
/// the queue (the UI checks the grant when it is shown) instead of failing with 4100.
#[test]
fn signing_waits_behind_a_pending_connect() -> TestResult {
    let mut h = Harness::new();
    h.send(SITE, 1, "eth_requestAccounts", json("[]"));
    let sign = h.send(
        SITE,
        1,
        "personal_sign",
        json(&format!(r#"["0x00","{A0}"]"#)),
    );
    assert!(h.take_response(&sign).is_empty());
    let kinds: Vec<SiteKind> = h.sink.requests().into_iter().map(|r| r.kind).collect();
    assert!(matches!(
        kinds.as_slice(),
        [SiteKind::RequestAccounts, SiteKind::PersonalSign { .. }]
    ));
    // Another origin without a pending connect: 4100 as before.
    let stranger = h.send(
        OTHER,
        2,
        "personal_sign",
        json(&format!(r#"["0x00","{A0}"]"#)),
    );
    assert_eq!(text(&single(&h, &stranger)?), "error 4100 Unauthorized.");
    Ok(())
}

/// spec/05 §4.4: after `나중에` on the dApp unlock window, origins that were not connected at
/// lock time cannot pop it again for the cooldown (4001 at once); connected ones still can.
#[test]
fn unlock_window_cooldown_for_unconnected_origins() -> TestResult {
    let mut h = Harness::new();
    h.core.unlock_wallet(vec![grant(SITE, &[A0], SEPOLIA)?]);
    h.core.lock_wallet();
    h.core
        .set_wallet(wallet(VaultView::Locked, &Settings::default()));
    h.out.take();
    // Before any dismissal every origin queues for the unlock window.
    let first = h.send(OTHER, 2, "eth_requestAccounts", json("[]"));
    assert!(h.take_response(&first).is_empty());
    // `나중에`: the UI answers the waiting requests with 4001 and tells the dispatcher.
    for request in h.sink.requests() {
        h.core
            .respond(&request.reply, Err(ProviderError::UserRejected));
    }
    h.out.take();
    h.core.dapp_unlock_dismissed();
    let stranger = h.send(OTHER, 3, "eth_requestAccounts", json("[]"));
    assert_eq!(
        text(&single(&h, &stranger)?),
        "error 4001 User rejected the request."
    );
    let connected = h.send(
        SITE,
        1,
        "personal_sign",
        json(&format!(r#"["0x00","{A0}"]"#)),
    );
    assert!(h.take_response(&connected).is_empty());
    assert_eq!(h.sink.requests().len(), 1);
    h.clock
        .advance(yw_app::browser::UNLOCK_PROMPT_COOLDOWN_MS + 1);
    let later = h.send(OTHER, 4, "eth_requestAccounts", json("[]"));
    assert!(h.take_response(&later).is_empty());
    assert_eq!(h.sink.requests().len(), 1);
    Ok(())
}

trait ClockNow {
    fn clock_now(&self) -> u64;
}

impl ClockNow for Harness {
    fn clock_now(&self) -> u64 {
        use yw_app::flow::evm::Clock;
        self.clock.now_ms()
    }
}
