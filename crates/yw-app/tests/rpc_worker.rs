//! The `yw-rpc` worker with a fake transport (spec/04 §1.2, spec/09 §2.1): balances read at one
//! block for every account, token balances and metadata through `eth_call`, the chain check event
//! before results, the preparation's `Simulating` → `Prepared` events, broadcast, the user-chain
//! probe, and a worker without an HTTPS client answering every job with E-RPC-001.

mod common;

use std::sync::Arc;

use common::evm::{S2_UNIX_MS, TestResult, USER, address, job, limits, send_intent, world};
use common::{Answer, FakeClock, FakeRpc, param_str, url};
use yw_app::errors::ErrorCode;
use yw_app::events::{EventQueue, RpcEvent, UiEvent};
use yw_app::flow::evm::prepare::PrepareOutcome;
use yw_app::flow::evm::track::BroadcastOutcome;
use yw_app::flow::evm::{ChainCheck, ChainJob};
use yw_app::workers::rpc::{RpcJob, RpcWorker};
use yw_core::evm::amount::U256;
use yw_core::evm::chain::{SEPOLIA_GENESIS, sepolia};
use yw_json::Value;

const TOKEN_OK: &str = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";
const TOKEN_BAD: &str = "0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9";

fn word(value: u64) -> String {
    format!("\"0x{value:064x}\"")
}

fn symbol_abi(text: &str) -> String {
    let mut hex = format!("{:064x}{:064x}", 32, text.len());
    let mut bytes = yw_core::hex::encode(text.as_bytes());
    while !bytes.len().is_multiple_of(64) {
        bytes.push('0');
    }
    hex.push_str(&bytes);
    format!("\"0x{hex}\"")
}

fn call_field(params: &Value, key: &str) -> String {
    params
        .as_array()
        .and_then(|items| items.first())
        .and_then(Value::as_object)
        .and_then(|call| call.get(key))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn chain_world() -> Arc<FakeRpc> {
    let script = world(11_155_111, SEPOLIA_GENESIS, Vec::new());
    FakeRpc::new(move |method, params| match method {
        "eth_blockNumber" => Answer::Result("\"0x9a0000\"".to_owned()),
        "eth_getBalance" => Answer::Result("\"0x2386f26fc10000\"".to_owned()),
        "eth_call" => {
            let to = call_field(params, "to");
            let input = call_field(params, "input");
            if to != TOKEN_OK.to_ascii_lowercase() {
                return Answer::Error(3, Some("0x".to_owned()));
            }
            if input.starts_with("0x70a08231") {
                Answer::Result(word(1_500_000))
            } else if input == "0x313ce567" {
                Answer::Result(word(6))
            } else if input == "0x95d89b41" {
                Answer::Result(symbol_abi("USDC"))
            } else {
                Answer::Error(-32_000, None)
            }
        }
        other => script.get(other),
    })
}

fn sepolia_job() -> ChainJob {
    let info = sepolia();
    ChainJob {
        caps: info.default_caps,
        info,
        url: url(),
    }
}

fn worker(rpc: Option<&Arc<FakeRpc>>) -> RpcWorker {
    RpcWorker::new(
        rpc.map(FakeRpc::shared),
        Box::new(FakeClock::at(S2_UNIX_MS)),
        limits(),
    )
}

fn rpc_events(queue: &EventQueue) -> Vec<RpcEvent> {
    queue
        .drain()
        .into_iter()
        .filter_map(|event| match event {
            UiEvent::Rpc(event) => Some(event),
            UiEvent::Key(_) | UiEvent::Dapp(_) | UiEvent::Llm(_) | UiEvent::LlmTest(_) => None,
        })
        .collect()
}

#[test]
fn balances_use_one_block_and_tolerate_token_failures() -> TestResult {
    let rpc = chain_world();
    let mut worker = worker(Some(&rpc));
    let queue = EventQueue::new(Box::new(|| {}));
    let user = address(USER)?;
    let other = address("0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb")?;
    worker.handle(
        RpcJob::Balances {
            job: 7,
            chain: sepolia_job(),
            accounts: vec![user, other],
            tokens: vec![address(TOKEN_OK)?, address(TOKEN_BAD)?],
            token_owner: user,
        },
        &queue,
    );
    let events = rpc_events(&queue);
    assert!(matches!(
        events.first(),
        Some(RpcEvent::Chain {
            chain_id: 11_155_111,
            check: ChainCheck::Verified { .. }
        })
    ));
    let Some(RpcEvent::Balances {
        job: 7,
        chain_id: 11_155_111,
        result: Ok(snapshot),
    }) = events.get(1)
    else {
        return Err("no balances".into());
    };
    assert_eq!(snapshot.block, 0x009a_0000);
    assert_eq!(snapshot.native.len(), 2);
    assert!(
        snapshot
            .native
            .iter()
            .all(|(_, balance)| *balance == U256::from_u64(10_000_000_000_000_000))
    );
    assert_eq!(
        snapshot.tokens,
        vec![
            (address(TOKEN_OK)?, Some(U256::from_u64(1_500_000))),
            (address(TOKEN_BAD)?, None)
        ]
    );
    // Every balance read names the same block number (not "latest").
    for params in rpc.params_of("eth_getBalance") {
        assert!(params.ends_with(",\"0x9a0000\"]"), "{params}");
    }
    // Token metadata (S16).
    worker.handle(
        RpcJob::TokenMeta {
            job: 8,
            chain: sepolia_job(),
            token: address(TOKEN_OK)?,
        },
        &queue,
    );
    let events = rpc_events(&queue);
    let Some(RpcEvent::TokenMeta {
        job: 8,
        result: Ok(meta),
        ..
    }) = events.last()
    else {
        return Err("no token meta".into());
    };
    assert_eq!(
        (meta.symbol.as_deref(), meta.decimals),
        (Some("USDC"), Some(6))
    );
    // The chain was verified once for the whole run.
    assert_eq!(rpc.count("eth_chainId"), 1);
    Ok(())
}

#[test]
fn prepare_broadcast_and_probe_events() -> TestResult {
    let rpc = chain_world();
    let mut worker = worker(Some(&rpc));
    let queue = EventQueue::new(Box::new(|| {}));
    let prepare_job = job(sepolia(), address(USER)?, send_intent()?);
    worker.handle(RpcJob::Prepare(Box::new(prepare_job)), &queue);
    let events = rpc_events(&queue);
    let simulating = events
        .iter()
        .position(|event| matches!(event, RpcEvent::Simulating { job: 1, .. }));
    let prepared = events
        .iter()
        .position(|event| matches!(event, RpcEvent::Prepared(_)));
    assert!(simulating.is_some() && prepared.is_some() && simulating < prepared);
    let Some(RpcEvent::Prepared(result)) = events.last() else {
        return Err("no prepared".into());
    };
    let PrepareOutcome::Ready(ready) = &result.outcome else {
        return Err("not ready".into());
    };
    assert_eq!(ready.context.tx.nonce, 5);
    // Broadcast: the node returns our hash.
    let raw = vec![0x02, 0x01];
    let hash = yw_core::codec::keccak256(&raw);
    let sender = FakeRpc::new(move |method, params| match method {
        "eth_chainId" => Answer::Result("\"0xaa36a7\"".to_owned()),
        "eth_getBlockByNumber" => Answer::Result(common::evm::block(&SEPOLIA_GENESIS, 0)),
        "eth_sendRawTransaction" if param_str(params, 0) == "0x0201" => {
            Answer::Result(format!("\"0x{}\"", yw_core::hex::encode(&hash)))
        }
        _ => Answer::Error(-32_601, None),
    });
    let mut sending = RpcWorker::new(
        Some(sender.shared()),
        Box::new(FakeClock::at(S2_UNIX_MS)),
        limits(),
    );
    sending.handle(
        RpcJob::Broadcast {
            chain: sepolia_job(),
            raw,
            tx_hash: hash,
        },
        &queue,
    );
    assert!(matches!(
        rpc_events(&queue).as_slice(),
        [RpcEvent::Broadcast {
            chain_id: 11_155_111,
            outcome: BroadcastOutcome::Sent,
            at_unix_ms: S2_UNIX_MS,
            ..
        }]
    ));
    // User-chain probe.
    worker.handle(
        RpcJob::Probe {
            job: 9,
            url: url(),
            chain_id: 11_155_111,
            pinned: None,
            check_base_fee: true,
        },
        &queue,
    );
    assert_eq!(
        rpc_events(&queue),
        vec![RpcEvent::Probe {
            job: 9,
            result: Ok(SEPOLIA_GENESIS)
        }]
    );
    Ok(())
}

#[test]
fn a_worker_without_client_answers_every_job() -> TestResult {
    let mut worker = worker(None);
    let queue = EventQueue::new(Box::new(|| {}));
    worker.handle(
        RpcJob::Balances {
            job: 1,
            chain: sepolia_job(),
            accounts: vec![address(USER)?],
            tokens: Vec::new(),
            token_owner: address(USER)?,
        },
        &queue,
    );
    let events = rpc_events(&queue);
    assert!(events.iter().any(|event| matches!(
        event,
        RpcEvent::Balances {
            result: Err(ErrorCode::Rpc001),
            ..
        }
    )));
    worker.handle(
        RpcJob::Prepare(Box::new(job(sepolia(), address(USER)?, send_intent()?))),
        &queue,
    );
    let events = rpc_events(&queue);
    let Some(RpcEvent::Prepared(result)) = events.last() else {
        return Err("no answer".into());
    };
    let PrepareOutcome::Failed(failure) = &result.outcome else {
        return Err("ready without a client".into());
    };
    assert_eq!(failure.code, ErrorCode::Rpc001);
    assert!(failure.retryable);
    worker.handle(
        RpcJob::Test {
            network: yw_app::network::NetworkId::Eip155(11_155_111),
            name: "Sepolia".to_owned(),
            url: url(),
        },
        &queue,
    );
    assert!(matches!(
        rpc_events(&queue).as_slice(),
        [RpcEvent::Test { ok: false, .. }]
    ));
    Ok(())
}

/// D14: another genesis at broadcast time sends nothing, blocks the chain (the Chain event comes
/// before the outcome) and later jobs see the mismatch without new calls.
#[test]
fn broadcast_rechecks_the_genesis_and_blocks_a_mismatch() -> TestResult {
    let queue = EventQueue::new(Box::new(|| {}));
    let forked = FakeRpc::new(move |method, _| match method {
        "eth_chainId" => Answer::Result("\"0xaa36a7\"".to_owned()),
        "eth_getBlockByNumber" => Answer::Result(common::evm::block(&[0xee; 32], 0)),
        _ => Answer::Error(-32_601, None),
    });
    let mut blocked = RpcWorker::new(
        Some(forked.shared()),
        Box::new(FakeClock::at(S2_UNIX_MS)),
        limits(),
    );
    let raw = vec![0x02, 0x01];
    let hash = yw_core::codec::keccak256(&raw);
    blocked.handle(
        RpcJob::Broadcast {
            chain: sepolia_job(),
            raw,
            tx_hash: hash,
        },
        &queue,
    );
    assert!(matches!(
        rpc_events(&queue).as_slice(),
        [
            RpcEvent::Chain {
                chain_id: 11_155_111,
                check: ChainCheck::Mismatch(_)
            },
            RpcEvent::Broadcast {
                outcome: BroadcastOutcome::ChainMismatch,
                ..
            }
        ]
    ));
    assert_eq!(forked.count("eth_sendRawTransaction"), 0);
    let calls = forked.methods().len();
    blocked.handle(
        RpcJob::Code {
            job: 1,
            chain: sepolia_job(),
            address: address(USER)?,
        },
        &queue,
    );
    assert_eq!(forked.methods().len(), calls, "the mismatch sticks");
    assert!(rpc_events(&queue).iter().any(|event| matches!(
        event,
        RpcEvent::Code {
            result: Err(ErrorCode::Rpc006),
            ..
        }
    )));
    Ok(())
}

/// C1: a re-simulation with a newer one already queued is dropped by the worker loop (only the
/// newest window job's result is ever used); other jobs keep their FIFO order.
#[test]
fn superseded_resimulations_are_dropped() -> TestResult {
    use yw_app::flow::evm::ChainCache;
    use yw_app::flow::evm::prepare::{ResimJob, prepare};
    use yw_app::workers::rpc::{run, superseded};
    let rpc = chain_world();
    let prepared = common::evm::ready(
        prepare(
            &rpc.shared(),
            &mut ChainCache::default(),
            &job(sepolia(), address(USER)?, send_intent()?),
            &FakeClock::at(S2_UNIX_MS),
            &|_| {},
        )
        .outcome,
    )?;
    let mut store = yw_core::approval::ApprovalStore::new();
    let request = store.issue(prepared.draft.clone(), 1, S2_UNIX_MS)?;
    let resim = |id| {
        RpcJob::Resimulate(Box::new(ResimJob {
            job: id,
            chain: sepolia_job(),
            request: request.clone(),
            context: prepared.context.clone(),
            address_book: Vec::new(),
            extra_warnings: Vec::new(),
            limits: limits(),
        }))
    };
    let later: std::collections::VecDeque<RpcJob> = [resim(9)].into_iter().collect();
    assert!(superseded(&resim(8), &later));
    assert!(!superseded(&resim(9), &std::collections::VecDeque::new()));
    let simulated = rpc.count("eth_simulateV1");
    let (tx, rx) = std::sync::mpsc::channel();
    for job in [
        resim(1),
        resim(2),
        RpcJob::ResetChain { chain_id: 1 },
        resim(3),
    ] {
        tx.send(job).map_err(|_| "send")?;
    }
    tx.send(RpcJob::Shutdown).map_err(|_| "send")?;
    let queue = EventQueue::new(Box::new(|| {}));
    run(worker(Some(&rpc)), &rx, &queue);
    let finished: Vec<u64> = rpc_events(&queue)
        .into_iter()
        .filter_map(|event| match event {
            RpcEvent::Resimulated(result) => Some(result.job),
            _ => None,
        })
        .collect();
    assert_eq!(finished, vec![3]);
    assert_eq!(rpc.count("eth_simulateV1"), simulated + 1);
    Ok(())
}
