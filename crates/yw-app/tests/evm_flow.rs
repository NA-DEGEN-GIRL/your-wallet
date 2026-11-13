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
use yw_core::journal::evm::{
    EvmRecord, FLAG_MANUAL_RESEND, FLAG_RPC_HASH_MISMATCH, Role, Transition, TxState,
};
use yw_json::Value;

const BESU_SIGNED: &str = "02f86e048203338301284d8301d97c828ae094000000000000000000000000000000000000aaaa8402933bc980c080a00f924cb68412c8f1cfd74d9b581c71eeaf94fff6abdde3e5b02ca6b2931dcf47a07dd1c50027c3e31f8b565e25ce68a5072110f61fce5eee81b195dd51273c2f83";
const BESU_HASH: &str = "0x2e564c87eb4b40e7f469b2eec5aa5d18b0b46a24e8bf0919439cfb0e8fcae446";
const BESU_SENDER: &str = "0xFE3B557E8Fb62b89F4916B721be55cEb828dBd73";

macro_rules! fixture {
    ($name:literal) => {
        include_bytes!(concat!("fixtures/eth_simulateV1/", $name, ".response.json")).to_vec()
    };
}

/// The chain of the Besu record (chain id 4, genesis `0x44…`).
fn besu_chain() -> yw_core::evm::chain::ChainInfo {
    user_chain(4, [0x44; 32], SimulationSupport::Auto)
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
    let chain = user_chain(10, genesis, SimulationSupport::Unsupported);
    let rpc = fake(world(10, genesis, Vec::new()));
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
    let chain = user_chain(10, [0x11; 32], SimulationSupport::Auto);
    let rpc = fake(world(10, [0x22; 32], Vec::new()));
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
    assert!(!prepared.context.blocking.is_empty());
    let mut store = ApprovalStore::new();
    let request = store.issue(prepared.draft.clone(), 1, S2_UNIX_MS)?;
    assert!(store.consume(request.id, request.digest, 2).is_err());
    // Review: a re-simulation of the blocked request never simulates and never drops the
    // blocking warning (the rebuilt draft used to lose E05 and become approvable).
    let (resimulated, resim_rpc) = resim(
        &request,
        &prepared,
        world(11_155_111, SEPOLIA_GENESIS, Vec::new()),
    );
    assert_eq!(resimulated.kind, ResimKind::Blocked);
    assert_eq!(resim_rpc.count("eth_simulateV1"), 0);
    let rebuilt = resimulated.prepared.ok_or("no draft")?;
    assert_eq!(rebuilt.draft.display.risk, RiskLevel::Blocked);
    assert!(rules(&rebuilt).contains(&E05.label()));
    assert_eq!(rebuilt.context.blocking, prepared.context.blocking);
    let replaced = store.replace(request.id, request.digest, rebuilt.draft.clone())?;
    assert!(store.consume(replaced.id, replaced.digest, 3).is_err());
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

const SPENDER: &str = "0x5555555555555555555555555555555555555555";

/// The S2 answer with its transfer log turned into an ERC-20 `Approval(USER → SPENDER)` of a
/// token the first preparation never saw.
fn approval_envelope() -> Vec<u8> {
    let text = String::from_utf8_lossy(&fixture!("S2"))
        .replace(
            "0xfffffffffffffffffffffffffffffffffffffffe",
            "0x1111111111111111111111111111111111111111",
        )
        .replace(
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
            "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
        )
        .replace(
            "0x000000000000000000000000f278cf59f82edcf871d630f28ecc8056f25c1cdb",
            "0x0000000000000000000000005555555555555555555555555555555555555555",
        );
    text.into_bytes()
}

fn resim_with(
    request: &yw_core::approval::ApprovalRequest,
    prepared: &Prepared,
    rpc: &std::sync::Arc<FakeRpc>,
) -> yw_app::flow::evm::prepare::ResimResult {
    let clock = FakeClock::at(S2_UNIX_MS + 61_000);
    let chain = sepolia();
    let resim_job = ResimJob {
        job: 3,
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
    resimulate(
        &rpc.shared(),
        &mut ChainCache::default(),
        &resim_job,
        &clock,
    )
}

/// spec/03 §6.6-3: a spender that appears only in the re-simulated diff is classified now (E16
/// for an EOA), and an `eth_getCode` failure records it as `CodeKind::Unknown` (E39, high risk,
/// spec/03 §8.5) instead of leaving the spender silently unclassified.
#[test]
fn resimulation_classifies_new_spenders() -> TestResult {
    let (prepared, request, _) = issued_happy()?;
    assert!(prepared.context.facts.code_of(&address(SPENDER)?).is_none());
    let script = world(
        11_155_111,
        SEPOLIA_GENESIS,
        vec![("eth_simulateV1", Answer::Envelope(approval_envelope()))],
    );
    let rpc = fake(script.clone());
    let result = resim_with(&request, &prepared, &rpc);
    assert_eq!(result.kind, ResimKind::Changed);
    assert!(
        rpc.params_of("eth_getCode")
            .iter()
            .any(|params| params.contains(&SPENDER[2..]))
    );
    let replacement = result.prepared.ok_or("no draft")?;
    assert_eq!(
        replacement.context.facts.code_of(&address(SPENDER)?),
        Some(yw_core::approval::CodeKind::Eoa)
    );
    assert!(rules(&replacement).contains(&yw_core::evm::risk::E16.label()));
    // The spender's code lookup fails: `Unknown`, E39 (high risk), no interim E27 stand-in.
    let failing = FakeRpc::new(move |method, params| {
        if method == "eth_getCode" && param_str(params, 0).eq_ignore_ascii_case(SPENDER) {
            return Answer::Transport(yw_win::http::HttpError::Timeout);
        }
        script.get(method)
    });
    let result = resim_with(&request, &prepared, &failing);
    let replacement = result.prepared.ok_or("no draft")?;
    assert_eq!(
        replacement.context.facts.code_of(&address(SPENDER)?),
        Some(yw_core::approval::CodeKind::Unknown)
    );
    let found = rules(&replacement);
    assert!(
        found.contains(&yw_core::evm::risk::E39.label()),
        "{found:?}"
    );
    assert!(
        !found.contains(&yw_core::evm::risk::E16.label()),
        "{found:?}"
    );
    assert!(
        !found.contains(&yw_core::evm::risk::E27.label()),
        "{found:?}"
    );
    assert!(replacement.draft.display.risk >= RiskLevel::High);
    Ok(())
}

/// spec/03 §8.5: a typed-data spender whose `eth_getCode` fails is recorded as
/// `CodeKind::Unknown` (T18, high risk) instead of being left unclassified; a working lookup
/// classifies it (an EOA spender is T09, not T18); without a verified chain it is `Unknown` too.
#[test]
fn typed_facts_failed_code_lookup_is_unknown_and_t18() -> TestResult {
    use yw_core::approval::CodeKind;
    use yw_core::evm::risk::{T09, T18, TypedRiskInput, typed_rules};
    const TYPED_SPENDER: &str = "0x2222222222222222222222222222222222222222";
    let deadline = S2_UNIX_MS / 1_000 + 600;
    let source = format!(
        r#"{{"types":{{"EIP712Domain":[{{"name":"name","type":"string"}},{{"name":"version","type":"string"}},{{"name":"chainId","type":"uint256"}},{{"name":"verifyingContract","type":"address"}}],"Permit":[{{"name":"owner","type":"address"}},{{"name":"spender","type":"address"}},{{"name":"value","type":"uint256"}},{{"name":"nonce","type":"uint256"}},{{"name":"deadline","type":"uint256"}}]}},"primaryType":"Permit","domain":{{"name":"USDC","version":"2","chainId":11155111,"verifyingContract":"0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"}},"message":{{"owner":"{USER}","spender":"{TYPED_SPENDER}","value":"5","nonce":"0","deadline":"{deadline}"}}}}"#
    );
    let value = yw_json::parse(source.as_bytes(), &yw_json::Limits::REQUEST)?;
    let typed =
        yw_core::evm::eip712::validate_typed_data_v4(source.as_bytes(), &value, 11_155_111)?;
    let chain = ChainJob {
        caps: sepolia().default_caps,
        info: sepolia(),
        url: url(),
    };
    let account = address(USER)?;
    let run = |rpc: &std::sync::Arc<FakeRpc>| {
        yw_app::flow::evm::prepare::typed_facts(
            &rpc.shared(),
            &mut ChainCache::default(),
            &chain,
            &account,
            &typed,
            Vec::new(),
            Vec::new(),
            &FakeClock::at(S2_UNIX_MS),
            0,
        )
    };
    let rules_of = |facts: &yw_core::approval::ChainFacts| {
        typed_rules(
            &TypedRiskInput {
                chain: &chain.info,
                account: &account,
                typed: &typed,
                facts,
                now_unix_ms: S2_UNIX_MS,
            },
            false,
        )
        .iter()
        .map(|warning| warning.rule)
        .collect::<Vec<_>>()
    };
    let script = world(11_155_111, SEPOLIA_GENESIS, Vec::new());
    let failing_script = script.clone();
    let failing = FakeRpc::new(move |method, params| {
        if method == "eth_getCode" && param_str(params, 0).eq_ignore_ascii_case(TYPED_SPENDER) {
            return Answer::Transport(yw_win::http::HttpError::Timeout);
        }
        failing_script.get(method)
    });
    let (facts, check) = run(&failing);
    assert!(matches!(check, ChainCheck::Verified { .. }), "{check:?}");
    assert_eq!(
        facts.code_of(&address(TYPED_SPENDER)?),
        Some(CodeKind::Unknown)
    );
    let found = rules_of(&facts);
    assert!(found.contains(&T18), "{found:?}");
    assert!(!found.contains(&T09), "{found:?}");
    // The same request with a working lookup: an EOA spender (T09), no T18.
    let (facts, _) = run(&fake(script));
    assert_eq!(facts.code_of(&address(TYPED_SPENDER)?), Some(CodeKind::Eoa));
    let found = rules_of(&facts);
    assert!(found.contains(&T09) && !found.contains(&T18), "{found:?}");
    // No verified chain (transport failure): no lookups, and the spender is still `Unknown`
    // (T18), never silently unclassified.
    let (facts, check) = run(&fake(world(
        11_155_111,
        SEPOLIA_GENESIS,
        vec![(
            "eth_chainId",
            Answer::Transport(yw_win::http::HttpError::Timeout),
        )],
    )));
    assert!(matches!(check, ChainCheck::Unverified(_)), "{check:?}");
    assert_eq!(
        facts.code_of(&address(TYPED_SPENDER)?),
        Some(CodeKind::Unknown)
    );
    assert!(rules_of(&facts).contains(&T18));
    Ok(())
}

/// A chain mismatch found at re-simulation blocks (`Failed`, E34) instead of becoming an
/// approvable "no simulation" request.
#[test]
fn resimulation_chain_mismatch_fails() -> TestResult {
    let (prepared, request, _) = issued_happy()?;
    let rpc = fake(world(11_155_111, [0xee; 32], Vec::new()));
    let result = resim_with(&request, &prepared, &rpc);
    assert_eq!(result.kind, ResimKind::Failed);
    assert!(result.prepared.is_none());
    let failure = result.failure.ok_or("no failure")?;
    assert_eq!(failure.rule(), E34);
    assert_eq!(failure.code, ErrorCode::Rpc006);
    assert_eq!(rpc.count("eth_simulateV1"), 0);
    Ok(())
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one block per row of the spec/03 §4.4 table"
)]
fn broadcast_outcomes() -> TestResult {
    let raw = yw_core::hex::decode(BESU_SIGNED)?;
    let hash: [u8; 32] = yw_core::hex::decode_array(BESU_HASH.trim_start_matches("0x"))?;
    let clock = FakeClock::at(1_790_000_000_000);
    let chain = besu_chain();
    let run = |overrides: Vec<(&str, Answer)>| {
        let rpc = fake(world(4, [0x44; 32], overrides));
        let outcome = broadcast(
            &rpc.shared(),
            &url(),
            &chain,
            &raw,
            &hash,
            &clock,
            &yw_app::flow::evm::Limits {
                broadcast_retry_ms: [2_000, 5_000],
                ..limits()
            },
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
    // The dApp is told it failed, so the record is journaled manual-resend-only (no automatic
    // re-broadcast, not even after a restart).
    assert_eq!(
        rejected.transition(hash, 1),
        Some(Transition::ManualResend {
            tx_hash: hash,
            at_unix_ms: 1
        })
    );
    assert!(!rejected.resends_automatically());
    let mut manual = vec![besu_record()?];
    let _ = yw_core::journal::evm::apply(
        &mut manual,
        &Transition::ManualResend {
            tx_hash: hash,
            at_unix_ms: 1,
        },
    );
    assert!(manual[0].has_flag(FLAG_MANUAL_RESEND));
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
    assert_eq!(
        wrong.transition(hash, 2),
        Some(Transition::ManualResend {
            tx_hash: hash,
            at_unix_ms: 2
        })
    );
    // D14: the genesis is re-checked on every broadcast too (not once per app run).
    let (genesis, rpc) = run(vec![(
        "eth_getBlockByNumber",
        Answer::Result(block(&[0x45; 32], 0)),
    )]);
    assert_eq!(genesis, BroadcastOutcome::ChainMismatch);
    assert_eq!(rpc.count("eth_getBlockByNumber"), 1);
    assert_eq!(rpc.count("eth_sendRawTransaction"), 0);
    // A transport failure of the chain check is retried (3×), never a "chain mismatch": nothing
    // is sent, the record stays Signed and tracking re-sends it — the dApp gets the hash.
    let (unverified, rpc) = run(vec![(
        "eth_chainId",
        Answer::Transport(yw_win::http::HttpError::Timeout),
    )]);
    assert_eq!(unverified, BroadcastOutcome::ChainUnverified);
    assert_eq!(rpc.count("eth_chainId"), 4);
    assert_eq!(rpc.count("eth_sendRawTransaction"), 0);
    assert_eq!(unverified.transition(hash, 3), None);
    assert!(unverified.resends_automatically());
    assert_eq!(
        yw_app::app_browser::broadcast_answer(hash, unverified),
        Ok(yw_json::Value::String(BESU_HASH.to_owned()))
    );
    for failed in [
        BroadcastOutcome::ChainMismatch,
        BroadcastOutcome::Rejected { known: false },
        BroadcastOutcome::HashMismatch,
    ] {
        assert_eq!(
            yw_app::app_browser::broadcast_answer(hash, failed),
            Err(yw_core::policy::ProviderError::BroadcastFailed)
        );
    }
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
        &besu_chain(),
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
fn tracking_receipts_one_confirmation_final_and_drop() -> TestResult {
    let record = besu_record()?;
    let block_hash = [0x5b; 32];
    let receipt = receipt_json(BESU_HASH, BESU_SENDER, "0x1", &block_hash);
    // A verified receipt in a block (one confirmation) is final: Included and Finalized in the
    // same round, no `finalized`-tag lookup, no depth.
    let rpc = fake(world(
        4,
        [0x44; 32],
        vec![("eth_getTransactionReceipt", Answer::Result(receipt.clone()))],
    ));
    let _ = track_group(
        &rpc.shared(),
        &url(),
        &besu_chain(),
        &TrackInput {
            group: vec![record.clone()],
            drop_seen_unix_ms: None,
            now_unix_ms: 10,
            allow_rebroadcast: true,
        },
    );
    assert_eq!(rpc.count("eth_getBlockByNumber"), 0);
    assert_eq!(rpc.count("eth_blockNumber"), 0);
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
        vec![
            Transition::Included {
                tx_hash: record.tx_hash,
                block_number: 100,
                block_hash,
                success: true,
                at_unix_ms: 10
            },
            Transition::Finalized {
                tx_hash: record.tx_hash,
                at_unix_ms: 10
            }
        ]
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
    // A record an earlier build left `Included` (waiting for the `finalized` tag) is finalized
    // by the next round without any RPC call.
    let mut included = record.clone();
    included.state = TxState::Included;
    included.included_block_number = 100;
    included.included_block_hash = block_hash;
    let silent = FakeRpc::new(|_, _| Answer::Error(-32_601, None));
    let result = track_group(
        &silent.shared(),
        &url(),
        &besu_chain(),
        &TrackInput {
            group: vec![included],
            drop_seen_unix_ms: None,
            now_unix_ms: 20,
            allow_rebroadcast: true,
        },
    );
    assert_eq!(
        result.transitions,
        vec![Transition::Finalized {
            tx_hash: record.tx_hash,
            at_unix_ms: 20,
        }]
    );
    assert!(silent.methods().is_empty());
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
#[expect(clippy::too_many_lines, reason = "one block per spec/03 §5.4 rule")]
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
        &besu_chain(),
        &TrackInput {
            group: vec![record.clone()],
            drop_seen_unix_ms: None,
            now_unix_ms: 1_790_000_100_000,
            allow_rebroadcast: true,
        },
    );
    assert!(!result.rebroadcast);
    assert_eq!(rpc.count("eth_sendRawTransaction"), 0);
    // manual_resend (the dApp was told the broadcast failed) → never re-sent automatically.
    record.flags = FLAG_MANUAL_RESEND;
    let rpc = fake(script());
    let result = track_group(
        &rpc.shared(),
        &url(),
        &besu_chain(),
        &TrackInput {
            group: vec![record.clone()],
            drop_seen_unix_ms: None,
            now_unix_ms: 1_790_000_100_000,
            allow_rebroadcast: true,
        },
    );
    assert!(!result.rebroadcast);
    assert_eq!(rpc.count("eth_sendRawTransaction"), 0);
    assert!(result.transitions.is_empty());
    // D14: right before a re-broadcast the chain id and genesis are checked again; another
    // genesis sends nothing and reports the mismatch (the worker blocks the chain).
    record.flags = 0;
    let other_genesis = fake(world(
        4,
        [0x45; 32],
        vec![(
            "eth_getTransactionCount",
            Answer::Result("\"0x333\"".to_owned()),
        )],
    ));
    let result = track_group(
        &other_genesis.shared(),
        &url(),
        &besu_chain(),
        &TrackInput {
            group: vec![record.clone()],
            drop_seen_unix_ms: None,
            now_unix_ms: 1_790_000_100_000,
            allow_rebroadcast: true,
        },
    );
    assert!(!result.rebroadcast);
    assert_eq!(other_genesis.count("eth_sendRawTransaction"), 0);
    assert_eq!(other_genesis.count("eth_getBlockByNumber"), 1);
    assert_eq!(
        result.chain_mismatch,
        Some(MismatchKind::PinnedGenesis {
            observed: [0x45; 32]
        })
    );
    // The same found during preparation's reconcile blocks the preparation with E34.
    let mut prepare_job = job(besu_chain(), address(BESU_SENDER)?, send_intent()?);
    prepare_job.records = vec![record];
    let mut cache = ChainCache::default();
    cache.store(
        4,
        ChainCheck::Verified {
            genesis: [0x44; 32],
            pinned_now: false,
        },
    );
    let result = prepare(
        &other_genesis.shared(),
        &mut cache,
        &prepare_job,
        &FakeClock::at(1_790_000_100_000),
        &|_| {},
    );
    let PrepareOutcome::Failed(failure) = result.outcome else {
        return Err("expected E34".into());
    };
    assert_eq!((failure.rule(), failure.code), (E34, ErrorCode::Chn008));
    assert_eq!(other_genesis.count("eth_sendRawTransaction"), 0);
    assert!(matches!(
        cache.get(4),
        Some(ChainCheck::Mismatch(MismatchKind::PinnedGenesis { .. }))
    ));
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
    // X-21: 10 entered, RPC says 0x1 → E-CHN-001 with the parsed value (2026-11-13: 10, not
    // 8453, which is the built-in Base since 2026-11-06).
    let rpc = fake(world(1, genesis, Vec::new()));
    let error = probe_chain(&rpc.shared(), &url(), 10, None, true);
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

/// The S2 answer with its one log replaced by `count` ERC-20 `Approval(USER → 0x55…{i})` logs of
/// token `0x1111…` (0.01 × 10^18 each).
fn approvals_envelope(count: usize) -> Vec<u8> {
    let text = String::from_utf8_lossy(&approval_envelope()).into_owned();
    let start = text.find("\"logs\":[").unwrap_or(0) + "\"logs\":[".len();
    let end = text[start..]
        .find("}]")
        .map_or(text.len(), |offset| start + offset + 1);
    let log = &text[start..end];
    let logs: Vec<String> = (1..=count)
        .map(|index| {
            log.replace(
                "0x0000000000000000000000005555555555555555555555555555555555555555",
                &format!("0x{:064x}", 0x5500 + index),
            )
            .replace(
                "\"logIndex\":\"0x0\"",
                &format!("\"logIndex\":\"0x{index:x}\""),
            )
        })
        .collect();
    format!("{}{}{}", &text[..start], logs.join(","), &text[end..]).into_bytes()
}

fn spender(index: usize) -> TestResult<yw_core::evm::address::Address> {
    address(&format!("0x{:040x}", 0x5500 + index))
}

/// The `eth_call` data of a `balanceOf` call, or "".
fn call_data(params: &Value) -> String {
    params
        .as_array()
        .and_then(|items| items.first())
        .and_then(Value::as_object)
        .and_then(|call| call.get("data").or_else(|| call.get("input")))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

/// Security review L2: an ERC-20 approval seen only in the simulation diff (not in the calldata)
/// has its balance looked up too, so "잔액보다 큰 승인" (E14) can fire for it. L3: `to` has its
/// own classification slot — 16 diff spenders are all classified and no E27 is added.
#[test]
fn diff_only_approvals_get_balances_and_sixteen_spenders_are_classified() -> TestResult {
    let token = "0x1111111111111111111111111111111111111111";
    let script = world(
        11_155_111,
        SEPOLIA_GENESIS,
        vec![("eth_simulateV1", Answer::Envelope(approvals_envelope(16)))],
    );
    let rpc = FakeRpc::new(move |method, params| {
        if method == "eth_call" && call_data(params).starts_with("0x70a08231") {
            // balanceOf(USER) = 1 wei, far below the 0.01 × 10^18 approvals.
            return Answer::Result(format!("\"0x{:064x}\"", 1));
        }
        if method == "eth_call" {
            return Answer::Error(-32_000, None);
        }
        script.get(method)
    });
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
    let facts = &prepared.context.facts;
    assert_eq!(facts.balance(&address(token)?), Some(U256::from_u64(1)));
    assert!(
        rpc.params_of("eth_call")
            .iter()
            .any(|params| params.contains("70a08231") && params.contains(&token[2..])),
        "balanceOf of the diff-only token"
    );
    for index in 1..=16 {
        assert!(
            facts.code_of(&spender(index)?).is_some(),
            "spender {index} classified"
        );
    }
    assert!(facts.code_of(&address(NEW)?).is_some(), "`to` classified");
    let found = rules(&prepared);
    assert!(
        found.contains(&yw_core::evm::risk::E14.label()),
        "{found:?}"
    );
    assert!(
        prepared
            .draft
            .display
            .warnings
            .iter()
            .any(|warning| warning.text.contains("잔액보다 큰 승인")),
        "{found:?}"
    );
    assert!(
        !found.contains(&yw_core::evm::risk::E27.label()),
        "{found:?}"
    );
    // 17 spenders exceed the limit: E27.
    let script = world(
        11_155_111,
        SEPOLIA_GENESIS,
        vec![("eth_simulateV1", Answer::Envelope(approvals_envelope(17)))],
    );
    let prepared = ready(
        prepare(
            &fake(script).shared(),
            &mut ChainCache::default(),
            &job,
            &clock,
            &|_| {},
        )
        .outcome,
    )?;
    assert!(rules(&prepared).contains(&yw_core::evm::risk::E27.label()));
    Ok(())
}

/// spec/03 §10.2a, §8.5: the decoded recipient of an ERC-20 `transfer` is classified in its own
/// slot (next to `to`, the token), so its "호출 인수 · to" row carries the account-kind note.
#[test]
fn erc20_transfer_recipient_is_classified() -> TestResult {
    let chain = sepolia();
    let token = chain.tokens.first().ok_or("no registry token")?.address;
    let recipient = address(NEW)?;
    let intent = yw_app::flow::evm::prepare::SendIntent {
        to: token,
        value: U256::ZERO,
        data: yw_core::evm::abi::erc20_transfer_data(&recipient, &U256::from_u64(1_000_000)),
        access_list: Vec::new(),
        dapp_gas: None,
        dapp_nonce: None,
    };
    let rpc = fake(world(11_155_111, SEPOLIA_GENESIS, Vec::new()));
    let clock = FakeClock::at(S2_UNIX_MS);
    let job = job(chain, address(USER)?, intent);
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
    let needle = NEW[2..].to_ascii_lowercase();
    assert!(
        rpc.params_of("eth_getCode")
            .iter()
            .any(|params| params.to_ascii_lowercase().contains(&needle))
    );
    assert_eq!(
        prepared.context.facts.code_of(&recipient),
        Some(yw_core::approval::CodeKind::Eoa)
    );
    assert!(
        prepared
            .draft
            .display
            .fields
            .iter()
            .any(|field| field.sub_label.ends_with("to")
                && field.value.replace(' ', "").contains(NEW)
                && field.value.contains("[일반 계정(EOA)]")),
        "{:?}",
        prepared.draft.display.fields
    );
    Ok(())
}

/// A Base-like world whose `GasPriceOracle` answers `getL1Fee` and `getOperatorFee` (or nothing).
fn op_stack_world(oracle: bool) -> std::sync::Arc<FakeRpc> {
    use yw_core::evm::chain::{BASE_GENESIS, BASE_MAINNET};
    let script = world(BASE_MAINNET, BASE_GENESIS, Vec::new());
    FakeRpc::new(move |method, params| {
        if method != "eth_call" {
            return script.get(method);
        }
        let call = params
            .as_array()
            .and_then(|items| items.first())
            .and_then(Value::as_object);
        let field = |key: &str| {
            call.and_then(|object| object.get(key))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_ascii_lowercase()
        };
        if !oracle || field("to") != "0x420000000000000000000000000000000000000f" {
            return Answer::Error(-32_000, None);
        }
        let word = |value: u64| format!("\"0x{value:064x}\"");
        if field("input").starts_with("0x49948e0e") {
            // getL1Fee: 0.000001 ETH.
            Answer::Result(word(1_000_000_000_000))
        } else {
            // getOperatorFee(gas_limit): 0.0000001 ETH.
            Answer::Result(word(100_000_000_000))
        }
    })
}

/// spec/03 §3.4a: on Base the L1 data fee (oracle, mocked) is in the max fee and the cap check;
/// a silent oracle adds E41 and the fee shows only the L2 part; a user chain without oracle code
/// is never asked.
#[test]
fn op_stack_l1_fee_is_in_the_max_fee_and_the_caps() -> TestResult {
    use yw_core::evm::chain::base_mainnet;
    use yw_core::evm::risk::E41;
    let clock = FakeClock::at(S2_UNIX_MS);
    let max_fee_text = |prepared: &Prepared| {
        prepared
            .draft
            .display
            .fields
            .iter()
            .find(|field| field.key == FieldKey::MAX_FEE)
            .map(|field| field.value.clone())
            .unwrap_or_default()
    };
    let run = |rpc: &std::sync::Arc<FakeRpc>, job: &PrepareJob| {
        ready(
            prepare(
                &rpc.shared(),
                &mut ChainCache::default(),
                job,
                &clock,
                &|_| {},
            )
            .outcome,
        )
    };
    let rpc = op_stack_world(true);
    let base_job = job(base_mainnet(), address(USER)?, send_intent()?);
    let prepared = run(&rpc, &base_job)?;
    // 245,520 gas × 2.1 gwei = 0.000515592 ETH, + L1 2 × 0.000001 + operator 0.0000001.
    assert_eq!(
        max_fee_text(&prepared),
        "0.000517692 ETH (L1 데이터 수수료 최대 0.0000021 ETH 포함)"
    );
    let quote = prepared.context.facts.l1_fee.ok_or("no l1 quote")?;
    assert_eq!(quote.estimate, U256::from_u64(1_100_000_000_000));
    assert!(!rules(&prepared).contains(&E41.label()));
    assert!(rpc.count("eth_call") >= 2);
    // The L1 part alone trips a total cap the L2 part fits under (E05, blocked).
    let mut capped = job(base_mainnet(), address(USER)?, send_intent()?);
    capped.chain.caps.max_total_fee = U256::from_u64(516_000_000_000_000);
    let blocked = run(&op_stack_world(true), &capped)?;
    assert_eq!(blocked.draft.display.risk, RiskLevel::Blocked);
    assert!(rules(&blocked).contains(&E05.label()));
    // No oracle answer: E41, the max fee is the L2 part only.
    let silent = run(&op_stack_world(false), &base_job)?;
    assert!(rules(&silent).contains(&E41.label()));
    assert_eq!(max_fee_text(&silent), "0.000515592 ETH");
    assert_eq!(silent.context.facts.l1_fee, None);
    // A user chain without oracle code is never asked (the world's eth_getCode is empty).
    let genesis = [0x11; 32];
    let user = fake(world(84_532, genesis, Vec::new()));
    let plain = run(
        &user,
        &job(
            user_chain(84_532, genesis, SimulationSupport::Auto),
            address(USER)?,
            send_intent()?,
        ),
    )?;
    assert!(!rules(&plain).contains(&E41.label()));
    assert_eq!(user.count("eth_call"), 0);
    assert_eq!(plain.context.facts.l1_fee, None);
    Ok(())
}
