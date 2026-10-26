//! `flow::evm` with a fake transport (spec/09 §2.1): the §3.7 preparation steps (chain check,
//! nonce/in-flight rule, journal room, fees and caps, gas plan, simulation incl. `unsupported` and
//! the 10 s bound), speed-up/cancel drafts with field `0x0125`, re-simulation (§6.6), broadcast
//! (§4.4, X-18), receipt tracking and reconcile (§4.5, §5.4), chain checks with first-use pins and
//! mismatches (EVM-V16, X-21–X-24) and the user-chain probe.

mod common;

use std::time::Duration;

use common::evm::{
    NEW, S2_UNIX_MS, TestResult, USER, address, block, fake, fee_history, job, limits, ready,
    rules, send_intent, user_chain, world,
};
use common::{Answer, FakeClock, FakeRpc, Script, hex, param_str, url};
use yw_app::errors::ErrorCode;
use yw_app::flow::evm::prepare::{
    PrepareJob, PrepareOutcome, Prepared, ReplaceMode, ReplaceTarget, ResimJob, ResimKind, prepare,
    resimulate,
};
use yw_app::flow::evm::track::{BroadcastOutcome, TrackInput, broadcast, track_group};
use yw_app::flow::evm::user_chain::{ProbeError, probe_chain};
use yw_app::flow::evm::{ChainCache, ChainCheck, ChainJob, MismatchKind, check_chain};
use yw_app::rpc::RpcClient;
use yw_core::approval::{
    ApprovalKind, ApprovalStore, FieldKey, RiskLevel, SimNoneReason, SimVerdict, SimulationBinding,
};
use yw_core::evm::amount::U256;
use yw_core::evm::chain::{
    GenesisRule, SEPOLIA_GENESIS, SimulationSupport, hyperevm_mainnet, sepolia,
};
use yw_core::evm::risk::{E05, E06, E34, E35, E36, E37, E38};
use yw_core::journal::evm::{EvmRecord, FLAG_RPC_HASH_MISMATCH, Role, Transition, TxState};
use yw_json::Value;

const BESU_SIGNED: &str = "02f86e048203338301284d8301d97c828ae094000000000000000000000000000000000000aaaa8402933bc980c080a00f924cb68412c8f1cfd74d9b581c71eeaf94fff6abdde3e5b02ca6b2931dcf47a07dd1c50027c3e31f8b565e25ce68a5072110f61fce5eee81b195dd51273c2f83";
const BESU_HASH: &str = "0x2e564c87eb4b40e7f469b2eec5aa5d18b0b46a24e8bf0919439cfb0e8fcae446";
const BESU_SENDER: &str = "0xFE3B557E8Fb62b89F4916B721be55cEb828dBd73";

macro_rules! fixture {
    ($name:literal) => {
        include_bytes!(concat!("fixtures/eth_simulateV1/", $name, ".response.json")).to_vec()
    };
}

fn besu_record() -> TestResult<EvmRecord> {
    Ok(EvmRecord::new_signed(
        4,
        address(BESU_SENDER)?,
        819,
        Role::Original,
        1_790_000_000_000,
        [7; 32],
        "yw-app",
        "[t] x",
        yw_core::hex::decode(BESU_SIGNED)?,
    )?)
}

#[test]
fn prepare_happy_path_sepolia() -> TestResult {
    let rpc = fake(world(11_155_111, SEPOLIA_GENESIS, Vec::new()));
    let clock = FakeClock::at(S2_UNIX_MS);
    let mut cache = ChainCache::default();
    let job = job(sepolia(), address(USER)?, send_intent()?);
    let stages = std::sync::Mutex::new(Vec::new());
    let result = prepare(&rpc.shared(), &mut cache, &job, &clock, &|since| {
        if let Ok(mut stages) = stages.lock() {
            stages.push(since);
        }
    });
    assert!(result.transitions.is_empty());
    let prepared = ready(result.outcome)?;
    let tx = &prepared.context.tx;
    assert_eq!(tx.nonce, 5);
    assert_eq!(tx.gas_limit, 245_520);
    assert_eq!(prepared.sim_gas_used, Some(204_600));
    assert_eq!(tx.max_priority_fee_per_gas, U256::from_u64(100_000_000));
    assert_eq!(tx.max_fee_per_gas, U256::from_u64(2_100_000_000));
    assert_eq!(prepared.draft.kind, ApprovalKind::EvmTransaction);
    assert!(matches!(
        prepared.draft.simulation,
        SimulationBinding::Simulated {
            verdict: SimVerdict::Ok,
            ..
        }
    ));
    assert_eq!(rpc.count("eth_simulateV1"), 1);
    assert_eq!(stages.into_inner()?.len(), 1);
    assert!(
        prepared.draft.display.risk < RiskLevel::High,
        "{:?}",
        rules(&prepared)
    );
    assert!(
        prepared
            .draft
            .display
            .title
            .starts_with("[Sepolia 테스트넷]")
    );
    // The request sent to eth_simulateV1 is exactly the transaction (chainId + type, §6.1).
    let sent = rpc.params_of("eth_simulateV1");
    assert!(
        sent.first()
            .is_some_and(|params| params.contains("\"nonce\":\"0x5\"")
                && params.contains("\"gas\":\"0x3bf10\"")
                && params.contains("\"chainId\":\"0xaa36a7\"")
                && params.contains("\"traceTransfers\":true")
                && params.contains("\"validation\":true"))
    );
    // The chain is cached as verified: a second preparation checks nothing again.
    let before = rpc.count("eth_chainId");
    let _ = prepare(&rpc.shared(), &mut cache, &job, &clock, &|_| {});
    assert_eq!(rpc.count("eth_chainId"), before);
    Ok(())
}

#[test]
fn unsupported_chain_never_calls_simulate_and_is_high_risk() -> TestResult {
    let genesis = [0x11; 32];
    let chain = user_chain(84_532, genesis, SimulationSupport::Unsupported);
    let rpc = fake(world(84_532, genesis, Vec::new()));
    let clock = FakeClock::at(S2_UNIX_MS);
    let job = job(chain, address(USER)?, send_intent()?);
    let prepared = ready(
        prepare(
            &rpc.shared(),
            &mut ChainCache::default(),
            &job,
            &clock,
            &|_| {},
        )
        .outcome,
    )?;
    assert_eq!(rpc.count("eth_simulateV1"), 0);
    assert_eq!(
        prepared.draft.simulation,
        SimulationBinding::None {
            reason: SimNoneReason::Unsupported
        }
    );
    assert_eq!(prepared.draft.display.risk, RiskLevel::High);
    assert!(prepared.draft.display.ack_required);
    assert_eq!(
        prepared.draft.display.warnings.first().map(|w| w.rule),
        Some(E36)
    );
    // Issue → consume works with the high-risk binding (approval is possible, D15).
    let mut store = ApprovalStore::new();
    let request = store.issue(prepared.draft, 10, S2_UNIX_MS)?;
    assert!(store.consume(request.id, request.digest, 11).is_ok());
    Ok(())
}

#[test]
fn chain_mismatch_blocks_with_e34_and_stays_cached() -> TestResult {
    let rpc = fake(world(11_155_111, [0xee; 32], Vec::new()));
    let clock = FakeClock::at(S2_UNIX_MS);
    let mut cache = ChainCache::default();
    let job = job(sepolia(), address(USER)?, send_intent()?);
    let result = prepare(&rpc.shared(), &mut cache, &job, &clock, &|_| {});
    let PrepareOutcome::Failed(failure) = result.outcome else {
        return Err("expected failure".into());
    };
    assert_eq!(failure.rule(), E34);
    assert_eq!(failure.code, ErrorCode::Rpc006);
    assert!(!failure.retryable);
    assert_eq!(rpc.count("eth_simulateV1"), 0);
    let calls = rpc.methods().len();
    let again = prepare(&rpc.shared(), &mut cache, &job, &clock, &|_| {});
    assert!(matches!(again.outcome, PrepareOutcome::Failed(_)));
    assert_eq!(
        rpc.methods().len(),
        calls,
        "RpcMismatch sticks without new calls"
    );
    // Wrong chain id → also E34 (E-RPC-006).
    let other = fake(world(1, SEPOLIA_GENESIS, Vec::new()));
    let check = check_chain(
        &RpcClient::new(&*other.shared()),
        &url(),
        &sepolia(),
        &clock,
        0,
    );
    assert_eq!(
        check,
        ChainCheck::Mismatch(MismatchKind::ChainId { rpc: Some(1) })
    );
    Ok(())
}

#[test]
fn transport_failures_retry_three_times_then_unverified() -> TestResult {
    let rpc = fake(world(
        11_155_111,
        SEPOLIA_GENESIS,
        vec![(
            "eth_chainId",
            Answer::Transport(yw_win::http::HttpError::Timeout),
        )],
    ));
    let clock = FakeClock::at(S2_UNIX_MS);
    let job = job(sepolia(), address(USER)?, send_intent()?);
    let result = prepare(
        &rpc.shared(),
        &mut ChainCache::default(),
        &job,
        &clock,
        &|_| {},
    );
    let PrepareOutcome::Failed(failure) = result.outcome else {
        return Err("expected failure".into());
    };
    assert_eq!(failure.rule(), E35);
    assert_eq!(failure.code, ErrorCode::Rpc002);
    assert!(failure.retryable);
    assert_eq!(rpc.count("eth_chainId"), 4);
    Ok(())
}

#[test]
fn hyperevm_pins_on_first_use_and_compares_later() {
    let first = [0xd8; 32];
    let rpc = fake(world(999, first, Vec::new()));
    let clock = FakeClock::at(S2_UNIX_MS);
    let mut cache = ChainCache::default();
    let mut chain = hyperevm_mainnet();
    assert_eq!(chain.genesis, GenesisRule::PinOnFirstUse(None));
    let client = RpcClient::new(&*rpc);
    assert_eq!(
        cache.ensure(&client, &url(), &chain, &clock, 0),
        ChainCheck::Verified {
            genesis: first,
            pinned_now: true
        }
    );
    assert_eq!(
        cache.ensure(&client, &url(), &chain, &clock, 0),
        ChainCheck::Verified {
            genesis: first,
            pinned_now: false
        }
    );
    // Next run: the pin is stored; another genesis is a pinned mismatch (E-CHN-008).
    chain.genesis = GenesisRule::PinOnFirstUse(Some(first));
    let other = fake(world(999, [0x01; 32], Vec::new()));
    let check = check_chain(&RpcClient::new(&*other), &url(), &chain, &clock, 0);
    assert_eq!(
        check,
        ChainCheck::Mismatch(MismatchKind::PinnedGenesis {
            observed: [0x01; 32]
        })
    );
    assert_eq!(check.code(), Some(ErrorCode::Chn008));
}

#[test]
fn user_chain_pinned_mismatch_blocks_sends() -> TestResult {
    let chain = user_chain(8_453, [0x11; 32], SimulationSupport::Auto);
    let rpc = fake(world(8_453, [0x22; 32], Vec::new()));
    let clock = FakeClock::at(S2_UNIX_MS);
    let job = job(chain, address(USER)?, send_intent()?);
    let PrepareOutcome::Failed(failure) = prepare(
        &rpc.shared(),
        &mut ChainCache::default(),
        &job,
        &clock,
        &|_| {},
    )
    .outcome
    else {
        return Err("expected failure".into());
    };
    assert_eq!((failure.rule(), failure.code), (E34, ErrorCode::Chn008));
    Ok(())
}

#[test]
fn in_flight_record_blocks_with_e06_after_reconcile() -> TestResult {
    let record = besu_record()?;
    let chain = user_chain(4, [0x44; 32], SimulationSupport::Auto);
    let script = world(
        4,
        [0x44; 32],
        vec![
            (
                "eth_getTransactionCount",
                Answer::Result(format!("\"0x{:x}\"", 819)),
            ),
            (
                "eth_sendRawTransaction",
                Answer::Result(format!("\"{BESU_HASH}\"")),
            ),
        ],
    );
    let rpc = fake(script);
    let clock = FakeClock::at(1_790_000_100_000);
    let mut prepare_job = job(chain, address(BESU_SENDER)?, send_intent()?);
    prepare_job.records = vec![record.clone()];
    let result = prepare(
        &rpc.shared(),
        &mut ChainCache::default(),
        &prepare_job,
        &clock,
        &|_| {},
    );
    // Reconcile re-sent the exact signed bytes once (spec/03 §5.4-2) and saw the same hash.
    assert_eq!(rpc.count("eth_sendRawTransaction"), 1);
    assert!(result.transitions.contains(&Transition::Broadcast {
        tx_hash: record.tx_hash,
        at_unix_ms: 1_790_000_100_000
    }));
    let PrepareOutcome::Failed(failure) = result.outcome else {
        return Err("expected E06".into());
    };
    assert_eq!(failure.rule(), E06);
    assert_eq!(failure.code, ErrorCode::Tx002);
    assert!(failure.warning.text.contains("nonce 819"));
    Ok(())
}

#[test]
fn external_pending_and_journal_full_block_with_e06() -> TestResult {
    let clock = FakeClock::at(S2_UNIX_MS);
    let rpc = FakeRpc::new(|method, params| {
        let base = world(11_155_111, SEPOLIA_GENESIS, Vec::new());
        if method == "eth_getTransactionCount" {
            return Answer::Result(if param_str(params, 1) == "pending" {
                "\"0x6\"".to_owned()
            } else {
                "\"0x5\"".to_owned()
            });
        }
        base.get(method)
    });
    let job_pending = job(sepolia(), address(USER)?, send_intent()?);
    let PrepareOutcome::Failed(failure) = prepare(
        &rpc.shared(),
        &mut ChainCache::default(),
        &job_pending,
        &clock,
        &|_| {},
    )
    .outcome
    else {
        return Err("expected E06".into());
    };
    assert_eq!(failure.rule(), E06);
    assert_eq!(
        failure.warning.text,
        "이 계정에서 다른 곳으로 보낸 대기 중 거래가 있습니다"
    );
    let rpc = fake(world(11_155_111, SEPOLIA_GENESIS, Vec::new()));
    let mut job_full = job(sepolia(), address(USER)?, send_intent()?);
    job_full.journal_room = false;
    let PrepareOutcome::Failed(failure) = prepare(
        &rpc.shared(),
        &mut ChainCache::default(),
        &job_full,
        &clock,
        &|_| {},
    )
    .outcome
    else {
        return Err("expected journal full".into());
    };
    assert_eq!((failure.rule(), failure.code), (E06, ErrorCode::Tx005));
    assert_eq!(failure.warning.text, "거래 저널 공간이 부족합니다");
    assert_eq!(rpc.count("eth_simulateV1"), 0);
    Ok(())
}

#[test]
fn fee_cap_violation_is_a_blocked_draft_without_simulation() -> TestResult {
    let rpc = fake(world(11_155_111, SEPOLIA_GENESIS, Vec::new()));
    let clock = FakeClock::at(S2_UNIX_MS);
    let mut capped = job(sepolia(), address(USER)?, send_intent()?);
    capped.chain.caps.max_total_fee = U256::from_u64(1_000);
    let prepared = ready(
        prepare(
            &rpc.shared(),
            &mut ChainCache::default(),
            &capped,
            &clock,
            &|_| {},
        )
        .outcome,
    )?;
    assert_eq!(prepared.draft.display.risk, RiskLevel::Blocked);
    assert!(rules(&prepared).contains(&E05.label()));
    assert_eq!(
        prepared.draft.simulation,
        SimulationBinding::None {
            reason: SimNoneReason::Skipped
        }
    );
    assert_eq!(rpc.count("eth_simulateV1"), 0);
    let mut store = ApprovalStore::new();
    let request = store.issue(prepared.draft, 1, S2_UNIX_MS)?;
    assert!(store.consume(request.id, request.digest, 2).is_err());
    Ok(())
}

#[test]
fn gas_estimate_failure_uses_the_fallback_and_e37() -> TestResult {
    let rpc = fake(world(
        11_155_111,
        SEPOLIA_GENESIS,
        vec![(
            "eth_estimateGas",
            Answer::Error(3, Some("0x08c379a0".to_owned())),
        )],
    ));
    let clock = FakeClock::at(S2_UNIX_MS);
    let job = job(sepolia(), address(USER)?, send_intent()?);
    let prepared = ready(
        prepare(
            &rpc.shared(),
            &mut ChainCache::default(),
            &job,
            &clock,
            &|_| {},
        )
        .outcome,
    )?;
    // ⌊1 SepoliaETH / 2.1 gwei⌋ capped at 16,777,216.
    assert_eq!(prepared.context.tx.gas_limit, 16_777_216);
    assert!(rules(&prepared).contains(&E37.label()));
    assert_eq!(
        rpc.count("eth_simulateV1"),
        1,
        "simulation is still attempted"
    );
    assert_eq!(prepared.draft.display.risk, RiskLevel::High);
    Ok(())
}

#[test]
fn hyperevm_small_block_limit_caution() -> TestResult {
    let genesis = [0xd8; 32];
    let mut chain = hyperevm_mainnet();
    chain.genesis = GenesisRule::PinOnFirstUse(Some(genesis));
    chain.simulation = SimulationSupport::Unsupported;
    for (estimate, expected_gas, caution) in [
        (2_500_000_u64, 3_000_000_u64, false),
        (2_600_000, 3_120_000, true),
    ] {
        let rpc = fake(world(
            999,
            genesis,
            vec![(
                "eth_estimateGas",
                Answer::Result(format!("\"0x{estimate:x}\"")),
            )],
        ));
        let clock = FakeClock::at(S2_UNIX_MS);
        let job = job(chain.clone(), address(USER)?, send_intent()?);
        let prepared = ready(
            prepare(
                &rpc.shared(),
                &mut ChainCache::default(),
                &job,
                &clock,
                &|_| {},
            )
            .outcome,
        )?;
        assert_eq!(prepared.context.tx.gas_limit, expected_gas);
        assert_eq!(rules(&prepared).contains(&E38.label()), caution);
    }
    Ok(())
}

#[test]
fn simulation_wait_is_bounded_and_late_answers_are_dropped() -> TestResult {
    let rpc = fake(world(
        11_155_111,
        SEPOLIA_GENESIS,
        vec![(
            "eth_simulateV1",
            Answer::Delayed(
                Duration::from_millis(400),
                Box::new(Answer::Envelope(fixture!("S2"))),
            ),
        )],
    ));
    let clock = FakeClock::at(S2_UNIX_MS);
    let mut quick = job(sepolia(), address(USER)?, send_intent()?);
    quick.limits.sim_wait_ms = 50;
    let prepared = ready(
        prepare(
            &rpc.shared(),
            &mut ChainCache::default(),
            &quick,
            &clock,
            &|_| {},
        )
        .outcome,
    )?;
    assert_eq!(
        prepared.draft.simulation,
        SimulationBinding::None {
            reason: SimNoneReason::Timeout
        }
    );
    assert_eq!(prepared.draft.display.risk, RiskLevel::High);
    std::thread::sleep(Duration::from_millis(500));
    Ok(())
}

fn replace_job(mode: ReplaceMode) -> TestResult<PrepareJob> {
    let record = besu_record()?;
    let chain = user_chain(4, [0x44; 32], SimulationSupport::Unsupported);
    let mut replace = job(chain, address(BESU_SENDER)?, send_intent()?);
    replace.records = vec![record.clone()];
    replace.replace = Some(ReplaceTarget {
        mode,
        group: vec![record],
    });
    Ok(replace)
}

fn replace_world() -> std::sync::Arc<FakeRpc> {
    fake(world(
        4,
        [0x44; 32],
        vec![
            (
                "eth_getTransactionCount",
                Answer::Result("\"0x333\"".to_owned()),
            ),
            (
                "eth_getTransactionByHash",
                Answer::Result("{\"hash\":\"0x01\"}".to_owned()),
            ),
        ],
    ))
}

#[test]
fn speed_up_and_cancel_drafts() -> TestResult {
    let clock = FakeClock::at(1_790_000_100_000);
    for mode in [ReplaceMode::SpeedUp, ReplaceMode::Cancel] {
        let rpc = replace_world();
        let job = replace_job(mode)?;
        let result = prepare(
            &rpc.shared(),
            &mut ChainCache::default(),
            &job,
            &clock,
            &|_| {},
        );
        let prepared = ready(result.outcome)?;
        let tx = &prepared.context.tx;
        assert_eq!(tx.nonce, 819);
        assert!(tx.max_priority_fee_per_gas >= U256::from_u64(83_439));
        assert!(tx.max_fee_per_gas > U256::from_u64(121_212));
        let replaces: Vec<&str> = prepared
            .draft
            .display
            .fields
            .iter()
            .filter(|field| field.key == FieldKey::REPLACES)
            .map(|field| field.value.as_str())
            .collect();
        assert_eq!(replaces.len(), 1);
        assert!(replaces[0].starts_with(BESU_HASH));
        assert!(replaces[0].contains("기존 최대 수수료"));
        match mode {
            ReplaceMode::SpeedUp => {
                assert_eq!(prepared.draft.kind, ApprovalKind::EvmSpeedUp);
                assert_eq!(prepared.context.role, Role::SpeedUp);
                assert_eq!(tx.gas_limit, 35_552);
                assert_eq!(tx.value, U256::from_u64(43_203_529));
            }
            ReplaceMode::Cancel => {
                assert_eq!(prepared.draft.kind, ApprovalKind::EvmCancel);
                assert_eq!(prepared.context.role, Role::Cancel);
                assert_eq!(tx.to, address(BESU_SENDER)?);
                assert_eq!(tx.value, U256::ZERO);
                assert!(tx.data.is_empty());
                assert_eq!(tx.gas_limit, 245_520);
                assert!(
                    prepared
                        .draft
                        .display
                        .title
                        .contains("거래 취소 (nonce 819)")
                );
            }
        }
    }
    // The group was resolved meanwhile (latest nonce moved): no replacement.
    let moved = fake(world(
        4,
        [0x44; 32],
        vec![(
            "eth_getTransactionCount",
            Answer::Result("\"0x334\"".to_owned()),
        )],
    ));
    let job = replace_job(ReplaceMode::SpeedUp)?;
    let PrepareOutcome::Failed(failure) = prepare(
        &moved.shared(),
        &mut ChainCache::default(),
        &job,
        &clock,
        &|_| {},
    )
    .outcome
    else {
        return Err("expected failure".into());
    };
    assert_eq!(failure.rule(), E06);
    Ok(())
}

fn issued_happy() -> TestResult<(Prepared, yw_core::approval::ApprovalRequest, ApprovalStore)> {
    let rpc = fake(world(11_155_111, SEPOLIA_GENESIS, Vec::new()));
    let clock = FakeClock::at(S2_UNIX_MS);
    let job = job(sepolia(), address(USER)?, send_intent()?);
    let prepared = ready(
        prepare(
            &rpc.shared(),
            &mut ChainCache::default(),
            &job,
            &clock,
            &|_| {},
        )
        .outcome,
    )?;
    let mut store = ApprovalStore::new();
    let request = store.issue(prepared.draft.clone(), 100, S2_UNIX_MS)?;
    Ok((prepared, request, store))
}

fn resim(
    request: &yw_core::approval::ApprovalRequest,
    prepared: &Prepared,
    script: Script,
) -> (
    yw_app::flow::evm::prepare::ResimResult,
    std::sync::Arc<FakeRpc>,
) {
    let rpc = fake(script);
    let clock = FakeClock::at(S2_UNIX_MS + 61_000);
    let chain = sepolia();
    let resim_job = ResimJob {
        job: 2,
        chain: ChainJob {
            caps: chain.default_caps,
            info: chain,
            url: url(),
        },
        request: request.clone(),
        context: prepared.context.clone(),
        address_book: Vec::new(),
        extra_warnings: Vec::new(),
        limits: limits(),
    };
    let result = resimulate(
        &rpc.shared(),
        &mut ChainCache::default(),
        &resim_job,
        &clock,
    );
    (result, rpc)
}

#[test]
fn resimulation_same_changed_and_no_result() -> TestResult {
    let (prepared, request, mut store) = issued_happy()?;
    // Same stable part → replace and consume with the click (spec/03 §6.6-3).
    let (same, _) = resim(
        &request,
        &prepared,
        world(11_155_111, SEPOLIA_GENESIS, Vec::new()),
    );
    assert_eq!(same.kind, ResimKind::Same);
    let replacement = same.prepared.ok_or("no draft")?;
    let replaced = store.replace(request.id, request.digest, replacement.draft.clone())?;
    assert_eq!(replaced.expires_unix_ms, request.expires_unix_ms);
    assert!(store.consume(replaced.id, replaced.digest, 101).is_ok());
    // Revert on re-simulation → changed (new click needed).
    let (prepared, request, _) = issued_happy()?;
    let (changed, _) = resim(
        &request,
        &prepared,
        world(
            11_155_111,
            SEPOLIA_GENESIS,
            vec![("eth_simulateV1", Answer::Envelope(fixture!("S3")))],
        ),
    );
    assert_eq!(changed.kind, ResimKind::Changed);
    // No result → None binding, new click; that click does not re-simulate (§6.6-1).
    let (none, _) = resim(
        &request,
        &prepared,
        world(
            11_155_111,
            SEPOLIA_GENESIS,
            vec![("eth_simulateV1", Answer::Envelope(fixture!("S4")))],
        ),
    );
    assert_eq!(none.kind, ResimKind::NoResult);
    let draft = none.prepared.ok_or("no draft")?.draft;
    assert_eq!(
        draft.simulation,
        SimulationBinding::None {
            reason: SimNoneReason::RpcError
        }
    );
    assert!(!yw_core::evm::simulate::needs_resimulation(
        &draft.simulation,
        0,
        u64::MAX / 2
    ));
    // -38012 → fees recomputed, simulated once more (§6.6-4); caps broken → blocked.
    let (blocked, rpc) = resim(
        &request,
        &prepared,
        world(
            11_155_111,
            SEPOLIA_GENESIS,
            vec![
                ("eth_simulateV1", Answer::Error(-38_012, None)),
                (
                    "eth_feeHistory",
                    Answer::Result(fee_history().replace("0x3b9aca00", "0x174876e800000")),
                ),
            ],
        ),
    );
    assert_eq!(blocked.kind, ResimKind::Blocked);
    assert_eq!(rpc.count("eth_simulateV1"), 1);
    let draft = blocked.prepared.ok_or("no draft")?.draft;
    assert_eq!(draft.display.risk, RiskLevel::Blocked);
    let (refeed, rpc) = resim(
        &request,
        &prepared,
        world(
            11_155_111,
            SEPOLIA_GENESIS,
            vec![("eth_simulateV1", Answer::Error(-38_012, None))],
        ),
    );
    assert_eq!(rpc.count("eth_simulateV1"), 2);
    assert_eq!(refeed.kind, ResimKind::NoResult);
    Ok(())
}

#[test]
fn broadcast_outcomes() -> TestResult {
    let raw = yw_core::hex::decode(BESU_SIGNED)?;
    let hash: [u8; 32] = yw_core::hex::decode_array(BESU_HASH.trim_start_matches("0x"))?;
    let clock = FakeClock::at(1_790_000_000_000);
    let run = |overrides: Vec<(&str, Answer)>| {
        let rpc = fake(world(4, [0x44; 32], overrides));
        let outcome = broadcast(
            &rpc.shared(),
            &url(),
            4,
            &raw,
            &hash,
            &clock,
            [2_000, 5_000],
        );
        (outcome, rpc)
    };
    let (sent, _) = run(vec![(
        "eth_sendRawTransaction",
        Answer::Result(format!("\"{BESU_HASH}\"")),
    )]);
    assert_eq!(sent, BroadcastOutcome::Sent);
    assert_eq!(
        sent.transition(hash, 5),
        Some(Transition::Broadcast {
            tx_hash: hash,
            at_unix_ms: 5
        })
    );
    // X-18: another hash → Signed + rpc_hash_mismatch, no automatic resend.
    let (mismatch, rpc) = run(vec![(
        "eth_sendRawTransaction",
        Answer::Result(format!("\"0x{}\"", "11".repeat(32))),
    )]);
    assert_eq!(mismatch, BroadcastOutcome::HashMismatch);
    assert_eq!(rpc.count("eth_sendRawTransaction"), 1);
    let mut record = besu_record()?;
    let mut records = vec![record.clone()];
    let _ = yw_core::journal::evm::apply(
        &mut records,
        &mismatch.transition(hash, 9).ok_or("transition")?,
    );
    assert_eq!(records[0].state, TxState::Signed);
    assert!(records[0].has_flag(FLAG_RPC_HASH_MISMATCH));
    // JSON-RPC error and unknown → stays Signed (manual resend/discard).
    let (rejected, _) = run(vec![(
        "eth_sendRawTransaction",
        Answer::Error(-32_000, None),
    )]);
    assert_eq!(rejected, BroadcastOutcome::Rejected { known: false });
    assert_eq!(rejected.transition(hash, 1), None);
    // Transport errors: resent after 2 s and 5 s, then asked; known → Broadcast.
    let (unconfirmed, rpc) = run(vec![
        (
            "eth_sendRawTransaction",
            Answer::Transport(yw_win::http::HttpError::Timeout),
        ),
        (
            "eth_getTransactionByHash",
            Answer::Result("{\"hash\":\"0x01\"}".to_owned()),
        ),
    ]);
    assert_eq!(unconfirmed, BroadcastOutcome::Unconfirmed { known: true });
    assert_eq!(rpc.count("eth_sendRawTransaction"), 3);
    // eth_chainId re-check before sending.
    let (wrong, rpc) = run(vec![("eth_chainId", Answer::Result("\"0x1\"".to_owned()))]);
    assert_eq!(wrong, BroadcastOutcome::ChainMismatch);
    assert_eq!(rpc.count("eth_sendRawTransaction"), 0);
    record.state = TxState::Broadcast;
    Ok(())
}

fn receipt_json(hash: &str, from: &str, status: &str, block_hash: &[u8; 32]) -> String {
    format!(
        "{{\"transactionHash\":\"{hash}\",\"from\":\"{}\",\"status\":\"{status}\",\"blockNumber\":\"0x64\",\"blockHash\":\"{}\",\"gasUsed\":\"0x5208\",\"effectiveGasPrice\":\"0x3b9aca00\"}}",
        from.to_ascii_lowercase(),
        hex(block_hash)
    )
}

fn track(
    records: Vec<EvmRecord>,
    script: Script,
    drop_seen: Option<u64>,
    now: u64,
) -> yw_app::flow::evm::track::TrackResult {
    let rpc = fake(script);
    track_group(
        &rpc.shared(),
        &url(),
        &TrackInput {
            group: records,
            drop_seen_unix_ms: drop_seen,
            now_unix_ms: now,
            allow_rebroadcast: true,
        },
    )
}

#[test]
#[expect(clippy::too_many_lines, reason = "one block per tracking outcome")]
fn tracking_receipts_finality_reorg_and_drop() -> TestResult {
    let record = besu_record()?;
    let block_hash = [0x5b; 32];
    let receipt = receipt_json(BESU_HASH, BESU_SENDER, "0x1", &block_hash);
    // Receipt → Included.
    let result = track(
        vec![record.clone()],
        world(
            4,
            [0x44; 32],
            vec![("eth_getTransactionReceipt", Answer::Result(receipt.clone()))],
        ),
        None,
        10,
    );
    assert_eq!(
        result.transitions,
        vec![Transition::Included {
            tx_hash: record.tx_hash,
            block_number: 100,
            block_hash,
            success: true,
            at_unix_ms: 10
        }]
    );
    // A receipt from another sender is ignored (§4.5), counted as invalid.
    let bad = receipt_json(BESU_HASH, NEW, "0x1", &block_hash);
    let result = track(
        vec![record.clone()],
        world(
            4,
            [0x44; 32],
            vec![
                ("eth_getTransactionReceipt", Answer::Result(bad)),
                (
                    "eth_getTransactionCount",
                    Answer::Result("\"0x333\"".to_owned()),
                ),
                (
                    "eth_getTransactionByHash",
                    Answer::Result("{\"hash\":\"0x01\"}".to_owned()),
                ),
            ],
        ),
        None,
        10,
    );
    assert_eq!(result.invalid_receipts, 1);
    assert_eq!(
        result.transitions,
        vec![Transition::Broadcast {
            tx_hash: record.tx_hash,
            at_unix_ms: 10
        }]
    );
    // Included + finalized ≥ N with the same hash → Finalized; another hash → Reorged.
    let mut included = record.clone();
    included.state = TxState::Included;
    included.included_block_number = 100;
    included.included_block_hash = block_hash;
    let finality = |hash_at_n: [u8; 32]| {
        FakeRpc::new(
            move |method, params| match (method, param_str(params, 0).as_str()) {
                ("eth_getBlockByNumber", "finalized") => Answer::Result(block(&[0x99; 32], 120)),
                ("eth_getBlockByNumber", "0x64") => Answer::Result(block(&hash_at_n, 100)),
                _ => Answer::Error(-32_601, None),
            },
        )
    };
    for (hash_at_n, finalized) in [(block_hash, true), ([0x77; 32], false)] {
        let rpc = finality(hash_at_n);
        let result = track_group(
            &rpc.shared(),
            &url(),
            &TrackInput {
                group: vec![included.clone()],
                drop_seen_unix_ms: None,
                now_unix_ms: 20,
                allow_rebroadcast: true,
            },
        );
        let expected = if finalized {
            Transition::Finalized {
                tx_hash: record.tx_hash,
                at_unix_ms: 20,
            }
        } else {
            Transition::Reorged {
                tx_hash: record.tx_hash,
                at_unix_ms: 20,
            }
        };
        assert_eq!(result.transitions, vec![expected]);
    }
    // `finalized` rejected by the node → latest − 64 (spec/03 §4.5 note).
    let fallback =
        FakeRpc::new(
            move |method, params| match (method, param_str(params, 0).as_str()) {
                ("eth_getBlockByNumber", "finalized") => Answer::Error(-32_602, None),
                ("eth_blockNumber", _) => Answer::Result("\"0xa4\"".to_owned()),
                ("eth_getBlockByNumber", "0x64") => Answer::Result(block(&[0x5b; 32], 100)),
                _ => Answer::Error(-32_601, None),
            },
        );
    let result = track_group(
        &fallback.shared(),
        &url(),
        &TrackInput {
            group: vec![included],
            drop_seen_unix_ms: None,
            now_unix_ms: 30,
            allow_rebroadcast: true,
        },
    );
    assert!(matches!(
        result.transitions.as_slice(),
        [Transition::Finalized { .. }]
    ));
    // No receipt and latest > nonce twice ≥ 30 s apart → Dropped.
    let moved = || {
        world(
            4,
            [0x44; 32],
            vec![(
                "eth_getTransactionCount",
                Answer::Result("\"0x334\"".to_owned()),
            )],
        )
    };
    let first = track(vec![record.clone()], moved(), None, 1_000);
    assert!(first.transitions.is_empty());
    assert_eq!(first.drop_seen_unix_ms, Some(1_000));
    let early = track(vec![record.clone()], moved(), Some(1_000), 20_000);
    assert!(early.transitions.is_empty());
    let dropped = track(vec![record.clone()], moved(), Some(1_000), 31_000);
    assert_eq!(
        dropped.transitions,
        vec![Transition::Dropped {
            key: record.key(),
            at_unix_ms: 31_000
        }]
    );
    Ok(())
}

#[test]
fn reconcile_rebroadcast_rules() -> TestResult {
    let mut record = besu_record()?;
    let script = || {
        world(
            4,
            [0x44; 32],
            vec![
                (
                    "eth_getTransactionCount",
                    Answer::Result("\"0x333\"".to_owned()),
                ),
                (
                    "eth_sendRawTransaction",
                    Answer::Result(format!("\"{BESU_HASH}\"")),
                ),
            ],
        )
    };
    // Unknown to the node, last broadcast long ago → re-sent as is.
    let result = track(vec![record.clone()], script(), None, 1_790_000_100_000);
    assert!(result.rebroadcast);
    // Within 60 s of the last broadcast → not re-sent.
    record.last_broadcast_unix_ms = 1_790_000_090_000;
    let result = track(vec![record.clone()], script(), None, 1_790_000_100_000);
    assert!(!result.rebroadcast);
    // rpc_hash_mismatch → never re-sent automatically.
    record.last_broadcast_unix_ms = 0;
    record.flags = FLAG_RPC_HASH_MISMATCH;
    let rpc = fake(script());
    let result = track_group(
        &rpc.shared(),
        &url(),
        &TrackInput {
            group: vec![record],
            drop_seen_unix_ms: None,
            now_unix_ms: 1_790_000_100_000,
            allow_rebroadcast: true,
        },
    );
    assert!(!result.rebroadcast);
    assert_eq!(rpc.count("eth_sendRawTransaction"), 0);
    Ok(())
}

#[test]
fn user_chain_probe() {
    let genesis = [0x31; 32];
    // OK: chain id, block 0, base fee.
    let rpc = fake(world(84_532, genesis, Vec::new()));
    assert_eq!(
        probe_chain(&rpc.shared(), &url(), 84_532, None, true),
        Ok(genesis)
    );
    // X-21: 8453 entered, RPC says 0x1 → E-CHN-001 with the parsed value.
    let rpc = fake(world(1, genesis, Vec::new()));
    let error = probe_chain(&rpc.shared(), &url(), 8_453, None, true);
    assert_eq!(error, Err(ProbeError::ChainId { rpc: Some(1) }));
    assert!(
        error
            .err()
            .map(|error| error.message())
            .is_some_and(|text| text.contains("(1)"))
    );
    assert_eq!(rpc.count("eth_getBlockByNumber"), 0);
    // Block 0 hash of 31 bytes → E-CHN-002 + E-RPC-005.
    let short = fake(world(
        84_532,
        genesis,
        vec![(
            "eth_getBlockByNumber",
            Answer::Result(format!("{{\"hash\":\"0x{}\"}}", "ab".repeat(31))),
        )],
    ));
    let error = probe_chain(&short.shared(), &url(), 84_532, None, true);
    assert_eq!(error, Err(ProbeError::NoBlockZero));
    assert!(
        error
            .err()
            .map(|e| e.message())
            .is_some_and(|text| text.contains("E-CHN-002") && text.contains("E-RPC-005"))
    );
    // Edit with another genesis → E-CHN-008, nothing to save.
    let rpc = fake(world(84_532, genesis, Vec::new()));
    assert_eq!(
        probe_chain(&rpc.shared(), &url(), 84_532, Some([0x32; 32]), false),
        Err(ProbeError::GenesisMismatch)
    );
    // No base fee → not EIP-1559.
    let legacy = fake(world(
        84_532,
        genesis,
        vec![(
            "eth_feeHistory",
            Answer::Result("{\"oldestBlock\":\"0x1\",\"gasUsedRatio\":[0.5]}".to_owned()),
        )],
    ));
    assert_eq!(
        probe_chain(&legacy.shared(), &url(), 84_532, None, true),
        Err(ProbeError::NoBaseFee)
    );
    // HTTP 401 → E-CHN-002 with E-RPC-003.
    let denied = FakeRpc::new(|_, _| Answer::Status(401));
    assert_eq!(
        probe_chain(&denied.shared(), &url(), 84_532, None, true),
        Err(ProbeError::Rpc(ErrorCode::Rpc003))
    );
    let _ = Value::Null;
}
