//! `eth_simulateV1` fixtures S1–S16 (spec/09 §3.8, spec/03 EVM-V08, X-11, X-12) through the
//! yw-app response parser and the yw-core interpretation, display and approval model.
//! Fixture shapes follow the 2026-10-27 probe (docs/acceptance/probe-20261027.md).

use yw_app::rpc::evm::{parse_simulate_response, simulate_http_outcome};
use yw_core::approval::{
    ApprovalDraft, ApprovalId, ApprovalKind, ApprovalOrigin, ApprovalStore, ChainFacts, CodeKind,
    FieldKey, RiskLevel, SimNoneReason, SimVerdict, SimulationBinding, TokenMeta, Warning,
    build_evm_tx_request,
};
use yw_core::bip32::path::AccountIndex;
use yw_core::evm::abi::erc20_transfer_data;
use yw_core::evm::address::{Address, AddressError, parse_address};
use yw_core::evm::amount::{Delta, U256};
use yw_core::evm::chain::{ChainInfo, ethereum_mainnet, hyperevm_mainnet, sepolia};
use yw_core::evm::decode::{DecodedTx, decode_call};
use yw_core::evm::risk::{E01, E02, E03, E04, E07, E13, E33, is_simulation_status, request_risk};
use yw_core::evm::simulate::{
    AssetId, LogEvent, SimOutcome, SimResult, TransportKind, interpret, sim_digest,
};
use yw_core::evm::tx::Eip1559Tx;
use yw_core::vault::EvmKeySource;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const USER: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
const EXISTING: &str = "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0";
const NEW: &str = "0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb";
const TOKEN: &str = "0x1111111111111111111111111111111111111111";
const S2_TIMESTAMP: u64 = 0x6ac6_4ee0;
const S1_TIMESTAMP: u64 = 0x6a00_0000;

macro_rules! fixture {
    ($name:literal) => {
        include_bytes!(concat!("fixtures/eth_simulateV1/", $name, ".response.json")).as_slice()
    };
}

fn address(text: &str) -> Result<Address, AddressError> {
    parse_address(text)
}

fn base_tx(chain_id: u64, to: &str, gas_limit: u64) -> TestResult<Eip1559Tx> {
    Ok(Eip1559Tx {
        chain_id,
        nonce: 0,
        max_priority_fee_per_gas: U256::from_u64(0x05f5_e100),
        max_fee_per_gas: U256::from_u64(0x7735_9400),
        gas_limit,
        to: address(to)?,
        value: U256::from_u64(0x0023_86f2_6fc1_0000),
        data: Vec::new(),
        access_list: Vec::new(),
    })
}

fn s2_tx() -> TestResult<Eip1559Tx> {
    base_tx(11_155_111, NEW, 0x3bf10)
}

fn s1_tx() -> TestResult<Eip1559Tx> {
    base_tx(1, EXISTING, 0x6270)
}

fn s10_tx() -> TestResult<Eip1559Tx> {
    let mut tx = base_tx(11_155_111, TOKEN, 0x3bf10)?;
    tx.value = U256::ZERO;
    tx.data = erc20_transfer_data(&address(EXISTING)?, &U256::from_u64(1_000_000));
    Ok(tx)
}

fn now_ms(timestamp: u64, offset: u64) -> u64 {
    (timestamp + offset) * 1_000
}

struct Run {
    outcome: SimOutcome,
    sim: SimResult,
    draft: ApprovalDraft,
}

fn evaluate(chain: &ChainInfo, tx: &Eip1559Tx, outcome: SimOutcome, now: u64) -> TestResult<Run> {
    let user = address(USER)?;
    let sim = interpret(chain, tx, &user, &outcome, now);
    let decoded = DecodedTx {
        tx: tx.clone(),
        call: decode_call(chain, &tx.to, &tx.data),
    };
    let facts = ChainFacts {
        account_code: CodeKind::Eoa,
        code: vec![(tx.to, CodeKind::Eoa)],
        tokens: vec![(
            address(TOKEN)?,
            TokenMeta {
                symbol: Some("TT".to_owned()),
                decimals: Some(6),
                registered: false,
            },
        )],
        balances: Vec::new(),
        address_book: Vec::new(),
        own_accounts: Vec::new(),
        known: Vec::new(),
        lookups_limited: false,
        l1_fee: None,
        hyperliquid: None,
    };
    let draft = build_evm_tx_request(
        ApprovalId([7; 16]),
        ApprovalOrigin::App,
        EvmKeySource::Derived(AccountIndex::ZERO),
        user,
        ApprovalKind::EvmTransaction,
        chain,
        &decoded,
        &sim,
        &facts,
        Vec::new(),
        now,
    )?;
    Ok(Run {
        outcome,
        sim,
        draft,
    })
}

fn rules(warnings: &[Warning]) -> Vec<String> {
    warnings
        .iter()
        .map(|warning| warning.rule.label())
        .collect()
}

fn field(draft: &ApprovalDraft, key: FieldKey) -> Vec<&str> {
    draft
        .display
        .fields
        .iter()
        .filter(|field| field.key == key)
        .map(|field| field.value.as_str())
        .collect()
}

/// Common expectation for a non-success simulation (spec/09 §3.8): the banner rule is the first
/// warning, the request is high risk (not blocked), and it can be issued and consumed.
fn assert_banner(run: &Run, rule: yw_core::approval::RuleId, cause: &str) -> TestResult {
    let display = &run.draft.display;
    let first = display.warnings.first().ok_or("no warnings")?;
    assert_eq!(first.rule, rule, "{:?}", rules(&display.warnings));
    assert!(first.text.ends_with(cause), "{:?}", first.text);
    assert_eq!(display.risk, RiskLevel::High);
    assert!(display.ack_required);
    assert!(
        display
            .warnings
            .iter()
            .all(|w| w.level != RiskLevel::Blocked)
    );
    let mut store = ApprovalStore::new();
    let request = store.issue(run.draft.clone(), 1_000, 1_791_381_216_000)?;
    let approved = store.consume(request.id, request.digest, 1_000 + 119_999)?;
    assert_eq!(approved.kind(), ApprovalKind::EvmTransaction);
    Ok(())
}

fn assert_pass(run: &Run) {
    let display = &run.draft.display;
    assert!(
        display.warnings.iter().all(|w| w.level < RiskLevel::High),
        "{:?}",
        rules(&display.warnings)
    );
    assert!(!display.ack_required);
}

#[test]
fn s1_mainnet_pre_glamsterdam() -> TestResult {
    let chain = ethereum_mainnet();
    let run = evaluate(
        &chain,
        &s1_tx()?,
        parse_simulate_response(fixture!("S1"), 1),
        now_ms(S1_TIMESTAMP, 12),
    )?;
    assert_pass(&run);
    let SimResult::Simulated { verdict, diff, .. } = &run.sim else {
        return Err("not simulated".into());
    };
    assert_eq!(*verdict, SimVerdict::Ok);
    assert!(!diff.native_emitter_mismatch);
    assert_eq!(diff.gas_used, 21_000);
    assert_eq!(field(&run.draft, FieldKey::SENT), ["0.01 ETH"]);
    assert_eq!(field(&run.draft, FieldKey::EXPECTED_FEE), ["0.0000231 ETH"]);
    // maxUsedGas absent (HyperEVM shape) parses the same.
    let hyper = hyperevm_mainnet();
    let mut tx = s1_tx()?;
    tx.chain_id = 999;
    let without = evaluate(
        &hyper,
        &tx,
        parse_simulate_response(fixture!("S1h"), 1),
        now_ms(S1_TIMESTAMP, 12),
    )?;
    let SimOutcome::Block(block) = &without.outcome else {
        return Err("no block".into());
    };
    assert_eq!(block.call.max_used_gas, None);
    assert_pass(&without);
    assert_eq!(field(&without.draft, FieldKey::SENT), ["0.01 HYPE"]);
    Ok(())
}

#[test]
fn s2_sepolia_post_glamsterdam() -> TestResult {
    let chain = sepolia();
    let run = evaluate(
        &chain,
        &s2_tx()?,
        parse_simulate_response(fixture!("S2"), 1),
        now_ms(S2_TIMESTAMP, 12),
    )?;
    assert_pass(&run);
    let SimResult::Simulated { verdict, diff, .. } = &run.sim else {
        return Err("not simulated".into());
    };
    assert_eq!(*verdict, SimVerdict::Ok);
    assert!(!diff.native_emitter_mismatch);
    assert_eq!(diff.gas_used, 204_600);
    assert_eq!(diff.changes.len(), 1);
    let change = diff.changes.first().ok_or("no change")?;
    assert_eq!(change.asset, AssetId::Native);
    assert_eq!(
        change.delta,
        Some(Delta::Out(U256::from_u64(10_000_000_000_000_000)))
    );
    assert_eq!(field(&run.draft, FieldKey::SENT), ["0.01 SepoliaETH"]);
    assert_eq!(
        field(&run.draft, FieldKey::EXPECTED_FEE),
        ["0.00022506 SepoliaETH"]
    );
    assert_eq!(
        run.draft.display.title,
        "[Sepolia 테스트넷] SepoliaETH 보내기: 0.01 SepoliaETH"
    );
    Ok(())
}

#[test]
fn s3_revert_with_reason_hides_rpc_message() -> TestResult {
    let chain = sepolia();
    let run = evaluate(
        &chain,
        &s2_tx()?,
        parse_simulate_response(fixture!("S3"), 1),
        now_ms(S2_TIMESTAMP, 12),
    )?;
    assert_banner(
        &run,
        E02,
        "이유: (검증되지 않은 컨트랙트 메시지) \"insufficient balance\"",
    )?;
    assert!(matches!(
        run.sim,
        SimResult::Simulated {
            verdict: SimVerdict::Reverted,
            ..
        }
    ));
    assert!(field(&run.draft, FieldKey::SENT).is_empty());
    let bytes = run.draft.display.bytes()?;
    assert!(!String::from_utf8_lossy(&bytes).contains("SECRET-MARKER"));
    Ok(())
}

#[test]
fn s3b_s3c_other_revert_shapes() -> TestResult {
    let chain = sepolia();
    let run_b = evaluate(
        &chain,
        &s2_tx()?,
        parse_simulate_response(fixture!("S3b"), 1),
        now_ms(S2_TIMESTAMP, 12),
    )?;
    assert_banner(&run_b, E02, "이유: 실행 오류(가스 부족 등, 코드 -32015)")?;
    // Probe shape: `revert` with data 0xdeadbeef (L-REVERT).
    let run_c = evaluate(
        &chain,
        &s2_tx()?,
        parse_simulate_response(fixture!("S3c"), 1),
        now_ms(S2_TIMESTAMP, 12),
    )?;
    assert_banner(&run_c, E02, "이유: 사용자 정의 오류 0xdeadbeef (4바이트)")?;
    Ok(())
}

#[test]
fn s4_top_level_errors() -> TestResult {
    let chain = sepolia();
    for name in [fixture!("S4"), fixture!("S4h")] {
        let run = evaluate(
            &chain,
            &s2_tx()?,
            parse_simulate_response(name, 1),
            now_ms(S2_TIMESTAMP, 12),
        )?;
        assert_banner(
            &run,
            E01,
            "잔액이 보낼 금액과 최대 수수료의 합보다 적습니다",
        )?;
        assert_eq!(
            run.draft.simulation,
            SimulationBinding::None {
                reason: SimNoneReason::RpcError
            }
        );
        assert_eq!(field(&run.draft, FieldKey::EXPECTED_FEE), ["알 수 없음"]);
        assert!(field(&run.draft, FieldKey::SENT).is_empty());
        let bytes = run.draft.display.bytes()?;
        assert!(!String::from_utf8_lossy(&bytes).contains("insufficient funds"));
    }
    Ok(())
}

#[test]
fn s5_unknown_fields_are_ignored() -> TestResult {
    let (SimOutcome::Block(s2), SimOutcome::Block(s5)) = (
        parse_simulate_response(fixture!("S2"), 1),
        parse_simulate_response(fixture!("S5"), 1),
    ) else {
        return Err("parse".into());
    };
    assert_eq!(s2, s5);
    let tx = s2_tx()?;
    assert_eq!(sim_digest(&tx, &s2)?, sim_digest(&tx, &s5)?);
    Ok(())
}

#[test]
fn s6_both_emitters_count_once() -> TestResult {
    let chain = sepolia();
    let run = evaluate(
        &chain,
        &s2_tx()?,
        parse_simulate_response(fixture!("S6"), 1),
        now_ms(S2_TIMESTAMP, 12),
    )?;
    assert_pass(&run);
    let SimResult::Simulated { diff, .. } = &run.sim else {
        return Err("not simulated".into());
    };
    assert_eq!(field(&run.draft, FieldKey::SENT), ["0.01 SepoliaETH"]);
    assert_eq!(diff.other_events, 0);
    assert_eq!(
        diff.events
            .iter()
            .filter(|event| matches!(event, LogEvent::Native { .. }))
            .count(),
        1
    );
    Ok(())
}

#[test]
fn s7_missing_native_log_and_s7b_emitter_mismatch() -> TestResult {
    let chain = sepolia();
    let s7 = evaluate(
        &chain,
        &s2_tx()?,
        parse_simulate_response(fixture!("S7"), 1),
        now_ms(S2_TIMESTAMP, 12),
    )?;
    assert_banner(&s7, E04, "SepoliaETH 이동이 확인되지 않습니다")?;
    assert!(matches!(
        s7.sim,
        SimResult::Simulated {
            verdict: SimVerdict::Incomplete,
            ..
        }
    ));
    let s7b = evaluate(
        &chain,
        &s2_tx()?,
        parse_simulate_response(fixture!("S7b"), 1),
        now_ms(S2_TIMESTAMP, 12),
    )?;
    assert_pass(&s7b);
    let SimResult::Simulated { diff, .. } = &s7b.sim else {
        return Err("not simulated".into());
    };
    assert!(diff.native_emitter_mismatch);
    assert_eq!(field(&s7b.draft, FieldKey::SENT), ["0.01 SepoliaETH"]);
    Ok(())
}

#[test]
fn s8_gas_above_limit() -> TestResult {
    let chain = sepolia();
    for name in [fixture!("S8"), fixture!("S8b")] {
        let run = evaluate(
            &chain,
            &s2_tx()?,
            parse_simulate_response(name, 1),
            now_ms(S2_TIMESTAMP, 12),
        )?;
        assert_banner(&run, E03, "사용 가스가 가스 한도를 넘습니다")?;
        assert!(matches!(
            run.sim,
            SimResult::Simulated {
                verdict: SimVerdict::Incomplete,
                ..
            }
        ));
    }
    Ok(())
}

#[test]
fn s9_s11_malformed_responses() -> TestResult {
    let chain = sepolia();
    for (name, body) in [
        ("S9a", fixture!("S9a")),
        ("S9b", fixture!("S9b")),
        ("S9c", fixture!("S9c")),
        ("S9d", fixture!("S9d")),
        ("S9e", fixture!("S9e")),
        ("S9f", fixture!("S9f")),
        ("S9g", fixture!("S9g")),
        ("S9h", fixture!("S9h")),
        ("S9i", fixture!("S9i")),
        ("S11", fixture!("S11")),
    ] {
        let outcome = parse_simulate_response(body, 1);
        assert_eq!(outcome, SimOutcome::Malformed, "{name}");
        let run = evaluate(&chain, &s2_tx()?, outcome, now_ms(S2_TIMESTAMP, 12))?;
        assert_banner(&run, E01, "시뮬레이션 응답 형식이 올바르지 않습니다")?;
    }
    Ok(())
}

#[test]
fn s10_token_transfer_and_s10b_mismatch() -> TestResult {
    let chain = sepolia();
    let s10 = evaluate(
        &chain,
        &s10_tx()?,
        parse_simulate_response(fixture!("S10"), 1),
        now_ms(S2_TIMESTAMP, 12),
    )?;
    assert_pass(&s10);
    assert!(rules(&s10.draft.display.warnings).contains(&E33.label()));
    let SimResult::Simulated { diff, .. } = &s10.sim else {
        return Err("not simulated".into());
    };
    let change = diff.changes.first().ok_or("no change")?;
    assert_eq!(change.asset, AssetId::Token(address(TOKEN)?));
    assert_eq!(change.delta, Some(Delta::Out(U256::from_u64(1_000_000))));
    let s10b = evaluate(
        &chain,
        &s10_tx()?,
        parse_simulate_response(fixture!("S10b"), 1),
        now_ms(S2_TIMESTAMP, 12),
    )?;
    assert!(rules(&s10b.draft.display.warnings).contains(&E13.label()));
    assert_eq!(s10b.draft.display.risk, RiskLevel::High);
    assert!(s10b.draft.display.ack_required);
    Ok(())
}

#[test]
fn s12_timeout_differs_from_s2() -> TestResult {
    let chain = sepolia();
    let s2 = evaluate(
        &chain,
        &s2_tx()?,
        parse_simulate_response(fixture!("S2"), 1),
        now_ms(S2_TIMESTAMP, 12),
    )?;
    let s12 = evaluate(
        &chain,
        &s2_tx()?,
        SimOutcome::Transport(TransportKind::Timeout),
        now_ms(S2_TIMESTAMP, 12),
    )?;
    assert_banner(&s12, E01, "시뮬레이션 응답이 없습니다(10초)")?;
    assert_eq!(
        s12.draft.simulation,
        SimulationBinding::None {
            reason: SimNoneReason::Timeout
        }
    );
    assert_ne!(s2.draft.display.bytes()?, s12.draft.display.bytes()?);
    let mut store = ApprovalStore::new();
    let a = store.issue(s2.draft, 0, 1)?;
    let mut s12_draft = s12.draft;
    s12_draft.id = ApprovalId([8; 16]);
    let b = store.issue(s12_draft, 0, 1)?;
    assert_ne!(a.digest, b.digest);
    Ok(())
}

#[test]
fn s13_clock_skew() -> TestResult {
    let chain = sepolia();
    let run = evaluate(
        &chain,
        &s2_tx()?,
        parse_simulate_response(fixture!("S2"), 1),
        now_ms(S2_TIMESTAMP, 301),
    )?;
    assert_banner(&run, E07, "기준 블록 시각이 현재와 301초 다릅니다")?;
    Ok(())
}

#[test]
fn s14_parent_hash_changes_digest_only() -> TestResult {
    let chain = sepolia();
    let s2 = evaluate(
        &chain,
        &s2_tx()?,
        parse_simulate_response(fixture!("S2"), 1),
        now_ms(S2_TIMESTAMP, 12),
    )?;
    let s14 = evaluate(
        &chain,
        &s2_tx()?,
        parse_simulate_response(fixture!("S14"), 1),
        now_ms(S2_TIMESTAMP, 12),
    )?;
    assert_eq!(s2.draft.display.bytes()?, s14.draft.display.bytes()?);
    let mut store = ApprovalStore::new();
    let a = store.issue(s2.draft, 0, 1)?;
    let mut s14_draft = s14.draft;
    s14_draft.id = ApprovalId([8; 16]);
    let b = store.issue(s14_draft, 0, 1)?;
    let mut b_same_id = b.clone();
    b_same_id.id = a.id;
    assert_ne!(a.digest, b.digest);
    Ok(())
}

#[test]
fn s16_self_transfer_without_log_is_not_e04() -> TestResult {
    // Sepolia probe: a 1-wei transfer to oneself has no log and uses 12,000 gas (EIP-7708).
    let chain = sepolia();
    let mut tx = base_tx(11_155_111, USER, 0x3bf10)?;
    tx.value = U256::ONE;
    let run = evaluate(
        &chain,
        &tx,
        parse_simulate_response(fixture!("S16"), 1),
        now_ms(S2_TIMESTAMP, 12),
    )?;
    assert_pass(&run);
    assert!(!rules(&run.draft.display.warnings).contains(&E04.label()));
    Ok(())
}

#[test]
fn http_status_classification() {
    assert_eq!(
        simulate_http_outcome(429, b"", 1),
        SimOutcome::Transport(TransportKind::RateLimited)
    );
    assert_eq!(
        simulate_http_outcome(503, b"", 1),
        SimOutcome::Transport(TransportKind::Other)
    );
    assert_eq!(
        parse_simulate_response(
            br#"{"jsonrpc":"2.0","id":1,"error":{"code":429,"message":"x"}}"#,
            1
        ),
        SimOutcome::Transport(TransportKind::RateLimited)
    );
    let oversized = vec![b' '; 4 * 1_024 * 1_024 + 1];
    assert_eq!(parse_simulate_response(&oversized, 1), SimOutcome::TooLarge);
}

#[test]
fn log_limits_are_too_large() {
    let topics = (0..5)
        .map(|_| format!("\"0x{}\"", "11".repeat(32)))
        .collect::<Vec<_>>()
        .join(",");
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":[{{"number":"0x1","parentHash":"0x{}","timestamp":"0x1","baseFeePerGas":"0x1","calls":[{{"status":"0x1","gasUsed":"0x1","logs":[{{"address":"0x{}","topics":[{topics}],"data":"0x"}}]}}]}}]}}"#,
        "00".repeat(32),
        "22".repeat(20)
    );
    assert_eq!(
        parse_simulate_response(body.as_bytes(), 1),
        SimOutcome::TooLarge
    );
    let data = "00".repeat(65_537);
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":[{{"number":"0x1","parentHash":"0x{}","timestamp":"0x1","baseFeePerGas":"0x1","calls":[{{"status":"0x1","gasUsed":"0x1","logs":[{{"address":"0x{}","topics":[],"data":"0x{data}"}}]}}]}}]}}"#,
        "00".repeat(32),
        "22".repeat(20)
    );
    assert_eq!(
        parse_simulate_response(body.as_bytes(), 1),
        SimOutcome::TooLarge
    );
}

#[test]
fn simulation_status_rules_lead_the_warning_list() -> TestResult {
    let chain = sepolia();
    let mut tx = s2_tx()?;
    tx.data = vec![0xde, 0xad, 0xbe, 0xef];
    let run = evaluate(
        &chain,
        &tx,
        SimOutcome::Transport(TransportKind::Other),
        now_ms(S2_TIMESTAMP, 12),
    )?;
    let labels = rules(&run.draft.display.warnings);
    assert_eq!(labels.first().map(String::as_str), Some("E01"));
    assert!(labels.contains(&"E12".to_owned()));
    let (risk, ack) = request_risk(&run.draft.display.warnings);
    assert_eq!((risk, ack), (RiskLevel::High, true));
    let high: Vec<_> = run
        .draft
        .display
        .warnings
        .iter()
        .filter(|w| w.level == RiskLevel::High)
        .collect();
    let first_non_sim = high.iter().position(|w| !is_simulation_status(w.rule));
    let last_sim = high.iter().rposition(|w| is_simulation_status(w.rule));
    if let (Some(first_non_sim), Some(last_sim)) = (first_non_sim, last_sim) {
        assert!(last_sim < first_non_sim);
    }
    Ok(())
}
