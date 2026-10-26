//! Simulation interpretation and transaction risk rules on constructed outcomes (spec/03 §6,
//! §10.2; EVM-V09 diff, EVM-V17 core cases). Fixture-based cases S1–S16 live in
//! `crates/yw-app/tests/evm_simulate.rs` next to the response parser.

use yw_core::approval::{
    ApprovalDraft, ApprovalId, ApprovalKind, ApprovalOrigin, ApprovalStore, ChainFacts, CodeKind,
    RiskLevel, SimNoneReason, SimVerdict, SimulationBinding, TokenMeta, Warning,
    build_evm_tx_request,
};
use yw_core::bip32::path::AccountIndex;
use yw_core::evm::abi::{
    AbiValue, SEL_APPROVE, SEL_SET_APPROVAL_FOR_ALL, TOPIC_APPROVAL, TOPIC_APPROVAL_FOR_ALL,
    TOPIC_PERMIT2_APPROVAL, TOPIC_PERMIT2_LOCKDOWN, TOPIC_TRANSFER, TOPIC_TRANSFER_BATCH,
    TOPIC_TRANSFER_SINGLE, TOPIC_WETH_DEPOSIT, TOPIC_WETH_WITHDRAWAL, encode_call, encode_params,
    pad_address,
};
use yw_core::evm::address::Address;
use yw_core::evm::amount::{Delta, U256};
use yw_core::evm::chain::{ChainInfo, SimulationSupport, UserChainInput, sepolia, user_chain_info};
use yw_core::evm::decode::{DecodedTx, decode_call};
use yw_core::evm::fee::{FeeCaps, Fees, GasEstimate, plan_gas_limit};
use yw_core::evm::risk::{self, request_risk};
use yw_core::evm::simulate::{
    ApprovalKindEvm, AssetId, EIP7708_SYSTEM, ERC7528_NATIVE, SimBlock, SimCall, SimCallError,
    SimLog, SimOutcome, SimResult, SimStatus, TransportKind, interpret, simulate_request,
};
use yw_core::evm::tx::{AccessListItem, Eip1559Tx};
use yw_core::vault::EvmKeySource;

const USER: Address = Address::from_bytes([0x01; 20]);
const OTHER: Address = Address::from_bytes([0x02; 20]);
const SPENDER: Address = Address::from_bytes([0x03; 20]);
const TOKEN: Address = Address::from_bytes([0x10; 20]);
const NFT: Address = Address::from_bytes([0x20; 20]);
const MULTI: Address = Address::from_bytes([0x30; 20]);
const TIMESTAMP: u64 = 1_791_381_216;
const NOW: u64 = TIMESTAMP * 1_000;

fn word(value: U256) -> [u8; 32] {
    value.to_be_bytes()
}

fn uword(value: u64) -> [u8; 32] {
    U256::from_u64(value).to_be_bytes()
}

fn log(address: Address, topics: Vec<[u8; 32]>, data: Vec<u8>) -> SimLog {
    SimLog {
        address,
        topics,
        data,
    }
}

fn transfer(token: Address, from: Address, to: Address, amount: U256) -> SimLog {
    log(
        token,
        vec![TOPIC_TRANSFER, pad_address(&from), pad_address(&to)],
        word(amount).to_vec(),
    )
}

fn native(emitter: Address, from: Address, to: Address, amount: u64) -> SimLog {
    log(
        emitter,
        vec![TOPIC_TRANSFER, pad_address(&from), pad_address(&to)],
        uword(amount).to_vec(),
    )
}

fn block(
    status: SimStatus,
    gas_used: u64,
    logs: Vec<SimLog>,
    error: Option<SimCallError>,
) -> SimBlock {
    SimBlock {
        number: 100,
        parent_hash: [7; 32],
        timestamp: TIMESTAMP,
        base_fee_per_gas: U256::from_u64(1_000_000_000),
        call: SimCall {
            status,
            gas_used,
            max_used_gas: None,
            return_data: Vec::new(),
            logs,
            error,
        },
    }
}

fn ok(logs: Vec<SimLog>) -> SimOutcome {
    SimOutcome::Block(block(SimStatus::Success, 50_000, logs, None))
}

fn tx(to: Address, value: u64, data: Vec<u8>) -> Eip1559Tx {
    Eip1559Tx {
        chain_id: 11_155_111,
        nonce: 0,
        max_priority_fee_per_gas: U256::from_u64(100_000_000),
        max_fee_per_gas: U256::from_u64(2_000_000_000),
        gas_limit: 100_000,
        to,
        value: U256::from_u64(value),
        data,
        access_list: Vec::new(),
    }
}

fn simulated(
    result: &SimResult,
) -> (
    SimVerdict,
    &yw_core::evm::simulate::SimulationDiff,
    &[Warning],
) {
    match result {
        SimResult::Simulated {
            verdict,
            diff,
            warnings,
        } => (*verdict, diff, warnings),
        SimResult::Unavailable { .. } => unreachable!("expected a simulated result: {result:?}"),
    }
}

#[test]
#[expect(clippy::too_many_lines, reason = "table-driven test")]
fn v09_diff_classes() {
    let chain = sepolia();
    let weth = chain.weth().unwrap().address;
    let permit2 = chain
        .contract_with_role(yw_core::evm::chain::ContractRole::Permit2)
        .unwrap()
        .address;
    let token2 = Address::from_bytes([0x11; 20]);
    let batch_data = encode_params(&[
        AbiValue::Array(vec![
            AbiValue::Uint(U256::from_u64(8)),
            AbiValue::Uint(U256::from_u64(9)),
        ]),
        AbiValue::Array(vec![
            AbiValue::Uint(U256::from_u64(1)),
            AbiValue::Uint(U256::from_u64(2)),
        ]),
    ]);
    let mut permit2_data = word(U256::MAX_U160).to_vec();
    permit2_data.extend_from_slice(&uword(123));
    let mut lockdown_data = pad_address(&token2).to_vec();
    lockdown_data.extend_from_slice(&pad_address(&SPENDER));
    let mut single_data = uword(7).to_vec();
    single_data.extend_from_slice(&uword(3));
    let logs = vec![
        transfer(TOKEN, USER, OTHER, U256::from_u64(100)),
        transfer(TOKEN, OTHER, USER, U256::from_u64(30)),
        log(
            NFT,
            vec![
                TOPIC_TRANSFER,
                pad_address(&USER),
                pad_address(&OTHER),
                uword(5),
            ],
            vec![],
        ),
        log(
            MULTI,
            vec![
                TOPIC_TRANSFER_SINGLE,
                pad_address(&SPENDER),
                pad_address(&OTHER),
                pad_address(&USER),
            ],
            single_data,
        ),
        log(
            MULTI,
            vec![
                TOPIC_TRANSFER_BATCH,
                pad_address(&SPENDER),
                pad_address(&USER),
                pad_address(&OTHER),
            ],
            batch_data,
        ),
        log(
            weth,
            vec![TOPIC_WETH_DEPOSIT, pad_address(&USER)],
            uword(10).to_vec(),
        ),
        log(
            weth,
            vec![TOPIC_WETH_WITHDRAWAL, pad_address(&USER)],
            uword(4).to_vec(),
        ),
        log(
            TOKEN,
            vec![TOPIC_APPROVAL, pad_address(&USER), pad_address(&SPENDER)],
            uword(50).to_vec(),
        ),
        log(
            TOKEN,
            vec![TOPIC_APPROVAL, pad_address(&USER), pad_address(&SPENDER)],
            uword(60).to_vec(),
        ),
        log(
            NFT,
            vec![TOPIC_APPROVAL, pad_address(&USER), [0; 32], uword(5)],
            vec![],
        ),
        log(
            NFT,
            vec![
                TOPIC_APPROVAL_FOR_ALL,
                pad_address(&USER),
                pad_address(&SPENDER),
            ],
            uword(1).to_vec(),
        ),
        log(
            permit2,
            vec![
                TOPIC_PERMIT2_APPROVAL,
                pad_address(&USER),
                pad_address(&TOKEN),
                pad_address(&SPENDER),
            ],
            permit2_data,
        ),
        log(
            permit2,
            vec![TOPIC_PERMIT2_LOCKDOWN, pad_address(&USER)],
            lockdown_data,
        ),
        // "기타": unrelated transfer, unknown topic, someone else's approval, WETH from a fake emitter.
        transfer(TOKEN, OTHER, SPENDER, U256::from_u64(1)),
        log(TOKEN, vec![[0x99; 32]], vec![]),
        log(
            TOKEN,
            vec![TOPIC_APPROVAL, pad_address(&OTHER), pad_address(&SPENDER)],
            uword(1).to_vec(),
        ),
        log(
            TOKEN,
            vec![TOPIC_WETH_DEPOSIT, pad_address(&USER)],
            uword(10).to_vec(),
        ),
    ];
    let result = interpret(
        &chain,
        &tx(TOKEN, 0, vec![1, 2, 3, 4]),
        &USER,
        &ok(logs),
        NOW,
    );
    let (verdict, diff, warnings) = simulated(&result);
    assert_eq!(verdict, SimVerdict::Ok, "{warnings:?}");
    assert_eq!(diff.other_events, 4);
    let delta = |asset: AssetId, id: Option<u64>| {
        diff.changes
            .iter()
            .find(|change| change.asset == asset && change.token_id == id.map(U256::from_u64))
            .and_then(|change| change.delta)
    };
    assert_eq!(
        delta(AssetId::Token(TOKEN), None),
        Some(Delta::Out(U256::from_u64(70)))
    );
    assert_eq!(
        delta(AssetId::Token(NFT), Some(5)),
        Some(Delta::Out(U256::ONE))
    );
    assert_eq!(
        delta(AssetId::Token(MULTI), Some(7)),
        Some(Delta::In(U256::from_u64(3)))
    );
    assert_eq!(
        delta(AssetId::Token(MULTI), Some(8)),
        Some(Delta::Out(U256::ONE))
    );
    assert_eq!(
        delta(AssetId::Token(MULTI), Some(9)),
        Some(Delta::Out(U256::from_u64(2)))
    );
    assert_eq!(
        delta(AssetId::Token(weth), None),
        Some(Delta::In(U256::from_u64(6)))
    );
    // Sends come before receipts.
    let first_in = diff
        .changes
        .iter()
        .position(|c| matches!(c.delta, Some(Delta::In(_))))
        .unwrap();
    assert!(
        diff.changes[..first_in]
            .iter()
            .all(|c| matches!(c.delta, Some(Delta::Out(_))))
    );
    let kinds: Vec<ApprovalKindEvm> = diff.approvals.iter().map(|change| change.kind).collect();
    assert_eq!(
        kinds,
        vec![
            ApprovalKindEvm::Erc20 {
                amount: U256::from_u64(60)
            },
            ApprovalKindEvm::Erc721 {
                token_id: U256::from_u64(5),
                revoked: true
            },
            ApprovalKindEvm::ForAll { approved: true },
            ApprovalKindEvm::Permit2 {
                amount: U256::MAX_U160,
                expiration: 123
            },
            ApprovalKindEvm::Permit2Lockdown,
        ]
    );
    assert_eq!(diff.approvals[3].asset, TOKEN);
    assert_eq!(diff.approvals[4].asset, token2);
}

#[test]
fn e08_row_limit_and_e09_overflow() {
    let chain = sepolia();
    let logs: Vec<SimLog> = (0..65_u8)
        .map(|index| {
            transfer(
                Address::from_bytes([index.wrapping_add(0x40); 20]),
                OTHER,
                USER,
                U256::ONE,
            )
        })
        .collect();
    let result = interpret(&chain, &tx(OTHER, 0, vec![]), &USER, &ok(logs), NOW);
    let (verdict, diff, warnings) = simulated(&result);
    assert_eq!(verdict, SimVerdict::Incomplete);
    assert_eq!(diff.changes.len(), 64);
    assert_eq!(diff.omitted_rows, 1);
    assert_eq!(warnings[0].rule, risk::E08);
    assert!(
        warnings[0]
            .text
            .ends_with("표시 한도를 넘어 1행을 생략했습니다")
    );

    let logs = vec![
        transfer(TOKEN, OTHER, USER, U256::MAX),
        transfer(TOKEN, OTHER, USER, U256::ONE),
    ];
    let result = interpret(&chain, &tx(OTHER, 0, vec![]), &USER, &ok(logs), NOW);
    let (verdict, diff, warnings) = simulated(&result);
    assert_eq!(verdict, SimVerdict::Incomplete);
    assert_eq!(diff.changes[0].delta, None);
    assert_eq!(warnings[0].rule, risk::E09);
}

#[test]
fn native_log_shape_violation_is_malformed() {
    let chain = sepolia();
    let bad = log(
        EIP7708_SYSTEM,
        vec![TOPIC_TRANSFER, pad_address(&USER)],
        uword(1).to_vec(),
    );
    let result = interpret(&chain, &tx(OTHER, 1, vec![]), &USER, &ok(vec![bad]), NOW);
    assert_eq!(
        result.binding(),
        SimulationBinding::None {
            reason: SimNoneReason::Malformed
        }
    );
    let dirty = log(
        ERC7528_NATIVE,
        vec![TOPIC_TRANSFER, [0xff; 32], pad_address(&OTHER)],
        uword(1).to_vec(),
    );
    let result = interpret(&chain, &tx(OTHER, 1, vec![]), &USER, &ok(vec![dirty]), NOW);
    assert_eq!(
        result.binding(),
        SimulationBinding::None {
            reason: SimNoneReason::Malformed
        }
    );
}

fn facts() -> ChainFacts {
    ChainFacts {
        account_code: CodeKind::Eoa,
        code: vec![(SPENDER, CodeKind::Contract)],
        tokens: vec![(
            TOKEN,
            TokenMeta {
                symbol: Some("TT".to_owned()),
                decimals: Some(18),
                registered: false,
            },
        )],
        balances: vec![(TOKEN, U256::from_u64(10))],
        address_book: Vec::new(),
    }
}

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

fn try_request(
    chain: &ChainInfo,
    tx: &Eip1559Tx,
    outcome: &SimOutcome,
    origin: ApprovalOrigin,
    facts: &ChainFacts,
    pre: Vec<Warning>,
) -> Fallible<ApprovalDraft> {
    let sim = interpret(chain, tx, &USER, outcome, NOW);
    Ok(build_evm_tx_request(
        ApprovalId([1; 16]),
        origin,
        EvmKeySource::Derived(AccountIndex::ZERO),
        USER,
        ApprovalKind::EvmTransaction,
        chain,
        &DecodedTx {
            tx: tx.clone(),
            call: decode_call(chain, &tx.to, &tx.data),
        },
        &sim,
        facts,
        pre,
        NOW,
    )?)
}

fn labels(draft: &ApprovalDraft) -> Vec<String> {
    draft
        .display
        .warnings
        .iter()
        .map(|w| w.rule.label())
        .collect()
}

/// EVM-V17: each §6.3 row → its rule and binding, high risk, never blocked, approvable.
#[test]
#[expect(clippy::too_many_lines, reason = "table-driven test")]
fn v17_every_simulation_row_is_high_risk_and_approvable() {
    let chain = sepolia();
    let value_tx = tx(OTHER, 5, vec![]);
    let rows: Vec<(SimOutcome, &str, SimulationBinding, &str)> = vec![
        (
            SimOutcome::Unsupported,
            "E36",
            SimulationBinding::None {
                reason: SimNoneReason::Unsupported,
            },
            "실제 효과를 확인할 수 없습니다",
        ),
        (
            SimOutcome::Transport(TransportKind::Other),
            "E01",
            SimulationBinding::None {
                reason: SimNoneReason::Transport,
            },
            "시뮬레이션 RPC에 연결할 수 없습니다",
        ),
        (
            SimOutcome::Transport(TransportKind::Timeout),
            "E01",
            SimulationBinding::None {
                reason: SimNoneReason::Timeout,
            },
            "시뮬레이션 응답이 없습니다(10초)",
        ),
        (
            SimOutcome::Transport(TransportKind::RateLimited),
            "E01",
            SimulationBinding::None {
                reason: SimNoneReason::RateLimited,
            },
            "RPC 요청 한도를 넘었습니다",
        ),
        (
            SimOutcome::RpcError { code: 429 },
            "E01",
            SimulationBinding::None {
                reason: SimNoneReason::RateLimited,
            },
            "RPC 요청 한도를 넘었습니다",
        ),
        (
            SimOutcome::TooLarge,
            "E01",
            SimulationBinding::None {
                reason: SimNoneReason::TooLarge,
            },
            "시뮬레이션 응답이 너무 큽니다",
        ),
        (
            SimOutcome::Malformed,
            "E01",
            SimulationBinding::None {
                reason: SimNoneReason::Malformed,
            },
            "시뮬레이션 응답 형식이 올바르지 않습니다",
        ),
        (
            SimOutcome::RpcError { code: -32_601 },
            "E01",
            SimulationBinding::None {
                reason: SimNoneReason::RpcError,
            },
            "RPC가 eth_simulateV1을 지원하지 않습니다(체인 설정에서 시뮬레이션을 \"미지원\"으로 바꿀 수 있습니다)",
        ),
        (
            SimOutcome::RpcError { code: -38_010 },
            "E01",
            SimulationBinding::None {
                reason: SimNoneReason::RpcError,
            },
            "nonce가 이미 사용되었습니다. 다른 곳에서 이 계정으로 거래가 전송되었을 수 있습니다",
        ),
        (
            SimOutcome::RpcError { code: -38_011 },
            "E01",
            SimulationBinding::None {
                reason: SimNoneReason::RpcError,
            },
            "앞선 거래가 아직 처리되지 않았습니다",
        ),
        (
            SimOutcome::RpcError { code: -38_012 },
            "E01",
            SimulationBinding::None {
                reason: SimNoneReason::RpcError,
            },
            "최대 수수료가 현재 기본 수수료보다 낮습니다",
        ),
        (
            SimOutcome::RpcError { code: -32_005 },
            "E01",
            SimulationBinding::None {
                reason: SimNoneReason::RpcError,
            },
            "최대 수수료가 현재 기본 수수료보다 낮습니다",
        ),
        (
            SimOutcome::RpcError { code: -38_013 },
            "E01",
            SimulationBinding::None {
                reason: SimNoneReason::RpcError,
            },
            "가스 한도가 최소 필요량보다 작습니다",
        ),
        (
            SimOutcome::RpcError { code: -38_014 },
            "E01",
            SimulationBinding::None {
                reason: SimNoneReason::RpcError,
            },
            "잔액이 보낼 금액과 최대 수수료의 합보다 적습니다",
        ),
        (
            SimOutcome::RpcError { code: -32_003 },
            "E01",
            SimulationBinding::None {
                reason: SimNoneReason::RpcError,
            },
            "잔액이 보낼 금액과 최대 수수료의 합보다 적습니다",
        ),
        (
            SimOutcome::RpcError { code: -38_015 },
            "E01",
            SimulationBinding::None {
                reason: SimNoneReason::RpcError,
            },
            "가스 한도가 블록 가스 한도를 넘습니다",
        ),
        (
            SimOutcome::RpcError { code: -38_020 },
            "E01",
            SimulationBinding::None {
                reason: SimNoneReason::RpcError,
            },
            "시뮬레이션 노드 오류(코드 -38020)",
        ),
        (
            SimOutcome::RpcError { code: -32_602 },
            "E01",
            SimulationBinding::None {
                reason: SimNoneReason::RpcError,
            },
            "시뮬레이션 노드 오류(코드 -32602)",
        ),
    ];
    for (outcome, rule, binding, cause) in rows {
        let draft = try_request(
            &chain,
            &value_tx,
            &outcome,
            ApprovalOrigin::App,
            &facts(),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(draft.simulation, binding, "{rule} {cause}");
        let first = &draft.display.warnings[0];
        assert_eq!(first.rule.label(), rule, "{cause}");
        assert!(first.text.ends_with(cause), "{:?}", first.text);
        assert_eq!(draft.display.risk, RiskLevel::High, "{cause}");
        assert!(draft.display.ack_required);
        let mut store = ApprovalStore::new();
        let issued = store.issue(draft, 0, NOW).unwrap();
        assert!(
            store.consume(issued.id, issued.digest, 1).is_ok(),
            "{cause}"
        );
    }
    // The unsupported chain never uses the outcome, even a well-formed block.
    let user_chain = user_chain_info(
        &UserChainInput {
            chain_id: 8_453,
            name: "Test L2".to_owned(),
            native_symbol: "ETH".to_owned(),
            native_decimals: 18,
            explorer: None,
            simulation: SimulationSupport::Unsupported,
        },
        [1; 32],
    );
    let mut l2_tx = value_tx.clone();
    l2_tx.chain_id = 8_453;
    let draft = try_request(
        &user_chain,
        &l2_tx,
        &ok(vec![]),
        ApprovalOrigin::App,
        &facts(),
        Vec::new(),
    )
    .unwrap();
    assert_eq!(
        draft.simulation,
        SimulationBinding::None {
            reason: SimNoneReason::Unsupported
        }
    );
    assert_eq!(labels(&draft)[0], "E36");

    // Reverted (code 3 and others), E03, E04, E07.
    let reverted = SimOutcome::Block(block(
        SimStatus::Failure,
        30_000,
        vec![],
        Some(SimCallError {
            code: 3,
            data: Some(vec![0xde, 0xad, 0xbe, 0xef]),
        }),
    ));
    let draft = try_request(
        &chain,
        &value_tx,
        &reverted,
        ApprovalOrigin::App,
        &facts(),
        Vec::new(),
    )
    .unwrap();
    assert!(matches!(
        draft.simulation,
        SimulationBinding::Simulated {
            verdict: SimVerdict::Reverted,
            ..
        }
    ));
    assert_eq!(labels(&draft)[0], "E02");
    let other_error = SimOutcome::Block(block(
        SimStatus::Failure,
        30_000,
        vec![],
        Some(SimCallError {
            code: -32_000,
            data: None,
        }),
    ));
    let draft = try_request(
        &chain,
        &value_tx,
        &other_error,
        ApprovalOrigin::App,
        &facts(),
        Vec::new(),
    )
    .unwrap();
    assert!(
        draft.display.warnings[0]
            .text
            .ends_with("이유: 실행 오류(가스 부족 등, 코드 -32000)")
    );
    let over_gas = SimOutcome::Block(block(
        SimStatus::Success,
        100_001,
        vec![native(ERC7528_NATIVE, USER, OTHER, 5)],
        None,
    ));
    assert_eq!(
        labels(
            &try_request(
                &chain,
                &value_tx,
                &over_gas,
                ApprovalOrigin::App,
                &facts(),
                Vec::new()
            )
            .unwrap()
        )[0],
        "E03"
    );
    let no_native = ok(vec![]);
    assert_eq!(
        labels(
            &try_request(
                &chain,
                &value_tx,
                &no_native,
                ApprovalOrigin::App,
                &facts(),
                Vec::new()
            )
            .unwrap()
        )[0],
        "E04"
    );
    let mut stale = block(
        SimStatus::Success,
        50_000,
        vec![native(ERC7528_NATIVE, USER, OTHER, 5)],
        None,
    );
    stale.timestamp = TIMESTAMP - 301;
    let draft = try_request(
        &chain,
        &value_tx,
        &SimOutcome::Block(stale),
        ApprovalOrigin::App,
        &facts(),
        Vec::new(),
    )
    .unwrap();
    assert_eq!(labels(&draft)[0], "E07");
    assert!(
        draft
            .display
            .warnings
            .iter()
            .all(|w| w.level != RiskLevel::Blocked)
    );
}

#[test]
fn v17_e12_with_e01_single_acknowledgement_and_order() {
    let chain = sepolia();
    let unknown = tx(OTHER, 0, vec![0xde, 0xad, 0xbe, 0xef, 0]);
    let gas_failure = plan_gas_limit(
        GasEstimate::Failed { revert_data: None },
        None,
        &Fees {
            max_priority_fee_per_gas: U256::ONE,
            max_fee_per_gas: U256::from_u64(2_000_000_000),
            base_fee_next: U256::ONE,
        },
        &chain.default_caps,
        &chain,
    );
    let draft = try_request(
        &chain,
        &unknown,
        &SimOutcome::Transport(TransportKind::Timeout),
        ApprovalOrigin::App,
        &facts(),
        gas_failure.warnings,
    )
    .unwrap();
    // Simulation-status rules (E01, E37) lead the high-risk group, then E12.
    assert_eq!(labels(&draft)[..3], ["E01", "E37", "E12"]);
    let (risk, ack) = request_risk(&draft.display.warnings);
    assert_eq!((risk, ack), (RiskLevel::High, true));
}

#[test]
#[expect(clippy::too_many_lines, reason = "table-driven test")]
fn v17_r8_unlimited_approval_without_logs() {
    let chain = sepolia();
    let approve = tx(
        TOKEN,
        0,
        encode_call(
            SEL_APPROVE,
            &[AbiValue::Address(SPENDER), AbiValue::Uint(U256::MAX)],
        ),
    );
    let draft = try_request(
        &chain,
        &approve,
        &SimOutcome::Transport(TransportKind::Other),
        ApprovalOrigin::App,
        &facts(),
        Vec::new(),
    )
    .unwrap();
    let labels = labels(&draft);
    assert!(labels.contains(&"E14".to_owned()), "{labels:?}");
    assert!(labels.contains(&"E21".to_owned()), "{labels:?}");
    // With logs: an unlimited approval log raises E14, and R4/R6 confirm the call.
    let approval_log = log(
        TOKEN,
        vec![TOPIC_APPROVAL, pad_address(&USER), pad_address(&SPENDER)],
        word(U256::MAX).to_vec(),
    );
    let draft = try_request(
        &chain,
        &approve,
        &ok(vec![approval_log]),
        ApprovalOrigin::App,
        &facts(),
        Vec::new(),
    )
    .unwrap();
    let labels = self::labels(&draft);
    assert!(labels.contains(&"E14".to_owned()), "{labels:?}");
    assert!(!labels.contains(&"E13".to_owned()), "{labels:?}");
    // Finite approval above the balance: E20 with the balance note.
    let finite = tx(
        TOKEN,
        0,
        encode_call(
            SEL_APPROVE,
            &[
                AbiValue::Address(SPENDER),
                AbiValue::Uint(U256::from_u64(11)),
            ],
        ),
    );
    let finite_log = log(
        TOKEN,
        vec![TOPIC_APPROVAL, pad_address(&USER), pad_address(&SPENDER)],
        uword(11).to_vec(),
    );
    let draft = try_request(
        &chain,
        &finite,
        &ok(vec![finite_log]),
        ApprovalOrigin::App,
        &facts(),
        Vec::new(),
    )
    .unwrap();
    let e20 = draft
        .display
        .warnings
        .iter()
        .find(|w| w.rule == risk::E20)
        .unwrap();
    assert!(e20.text.ends_with("잔액보다 큰 승인"));
    // Revocation: E30 (info). ApprovalForAll(true): E15. EOA operator: E16.
    let revoke = tx(
        TOKEN,
        0,
        encode_call(
            SEL_APPROVE,
            &[AbiValue::Address(SPENDER), AbiValue::Uint(U256::ZERO)],
        ),
    );
    assert!(
        self::labels(
            &try_request(
                &chain,
                &revoke,
                &SimOutcome::Malformed,
                ApprovalOrigin::App,
                &facts(),
                Vec::new()
            )
            .unwrap()
        )
        .contains(&"E30".to_owned())
    );
    let for_all = tx(
        NFT,
        0,
        encode_call(
            SEL_SET_APPROVAL_FOR_ALL,
            &[AbiValue::Address(OTHER), AbiValue::Bool(true)],
        ),
    );
    let eoa = ChainFacts {
        code: vec![(OTHER, CodeKind::Eoa)],
        ..facts()
    };
    let labels = self::labels(
        &try_request(
            &chain,
            &for_all,
            &SimOutcome::Malformed,
            ApprovalOrigin::App,
            &eoa,
            Vec::new(),
        )
        .unwrap(),
    );
    assert!(
        labels.contains(&"E15".to_owned()) && labels.contains(&"E16".to_owned()),
        "{labels:?}"
    );
}

#[test]
#[expect(clippy::too_many_lines, reason = "table-driven test")]
fn transaction_rules_e17_to_e29() {
    let chain = sepolia();
    let pay = tx(OTHER, 5, vec![]);
    let paid = ok(vec![native(ERC7528_NATIVE, USER, OTHER, 5)]);
    // E28: wallet send to an address outside the address book (info); E29: recipient contract.
    let contract_recipient = ChainFacts {
        code: vec![(OTHER, CodeKind::Contract)],
        ..facts()
    };
    let labels = labels(
        &try_request(
            &chain,
            &pay,
            &paid,
            ApprovalOrigin::App,
            &contract_recipient,
            Vec::new(),
        )
        .unwrap(),
    );
    assert_eq!(labels, ["E28", "E29"]);
    let booked = ChainFacts {
        address_book: vec![(OTHER, "친구".to_owned())],
        ..facts()
    };
    assert!(
        self::labels(
            &try_request(
                &chain,
                &pay,
                &paid,
                ApprovalOrigin::App,
                &booked,
                Vec::new()
            )
            .unwrap()
        )
        .is_empty()
    );
    // E17: the signing account has code.
    let delegated = ChainFacts {
        account_code: CodeKind::Delegated7702 { target: SPENDER },
        ..booked.clone()
    };
    assert!(
        self::labels(
            &try_request(
                &chain,
                &pay,
                &paid,
                ApprovalOrigin::App,
                &delegated,
                Vec::new()
            )
            .unwrap()
        )
        .contains(&"E17".to_owned())
    );
    // E18: native value to the zero address.
    let zero = Address::from_bytes([0; 20]);
    let burn = tx(zero, 5, vec![]);
    let burned = ok(vec![native(ERC7528_NATIVE, USER, zero, 5)]);
    assert!(
        self::labels(
            &try_request(
                &chain,
                &burn,
                &burned,
                ApprovalOrigin::App,
                &facts(),
                Vec::new()
            )
            .unwrap()
        )
        .contains(&"E18".to_owned())
    );
    // E23: a site request that only sends.
    let site =
        ApprovalOrigin::Site(yw_core::policy::BrowserOrigin::parse("https://app.example").unwrap());
    assert!(
        self::labels(
            &try_request(&chain, &pay, &paid, site.clone(), &facts(), Vec::new()).unwrap()
        )
        .contains(&"E23".to_owned())
    );
    // E24: call to oneself with data.
    let self_call = tx(USER, 0, vec![1, 2, 3, 4]);
    assert!(
        self::labels(
            &try_request(&chain, &self_call, &ok(vec![]), site, &facts(), Vec::new()).unwrap()
        )
        .contains(&"E24".to_owned())
    );
    // E19/E25/E26/E33 for an unregistered token claiming a known symbol without decimals.
    let fake = ChainFacts {
        tokens: vec![(
            TOKEN,
            TokenMeta {
                symbol: Some("weth".to_owned()),
                decimals: None,
                registered: false,
            },
        )],
        ..facts()
    };
    let send_token = tx(
        TOKEN,
        0,
        yw_core::evm::abi::erc20_transfer_data(&OTHER, &U256::ONE),
    );
    let labels = self::labels(
        &try_request(
            &chain,
            &send_token,
            &ok(vec![transfer(TOKEN, USER, OTHER, U256::ONE)]),
            ApprovalOrigin::App,
            &fake,
            Vec::new(),
        )
        .unwrap(),
    );
    for rule in ["E19", "E25", "E33"] {
        assert!(labels.contains(&rule.to_owned()), "{rule}: {labels:?}");
    }
    let unknown_symbol = ChainFacts {
        tokens: vec![(
            TOKEN,
            TokenMeta {
                symbol: None,
                decimals: Some(6),
                registered: false,
            },
        )],
        ..facts()
    };
    assert!(
        self::labels(
            &try_request(
                &chain,
                &send_token,
                &ok(vec![transfer(TOKEN, USER, OTHER, U256::ONE)]),
                ApprovalOrigin::App,
                &unknown_symbol,
                Vec::new()
            )
            .unwrap()
        )
        .contains(&"E26".to_owned())
    );
    // E32: other events count.
    let noisy = ok(vec![
        native(ERC7528_NATIVE, USER, OTHER, 5),
        log(TOKEN, vec![[0x99; 32]], vec![]),
    ]);
    let draft = try_request(
        &chain,
        &pay,
        &noisy,
        ApprovalOrigin::App,
        &booked,
        Vec::new(),
    )
    .unwrap();
    assert_eq!(draft.display.warnings[0].text, "기타 이벤트 1개");
}

#[test]
fn simulate_request_shape() {
    let mut tx = tx(OTHER, 5, vec![0xab]);
    tx.access_list = vec![AccessListItem {
        address: SPENDER,
        storage_keys: vec![[0; 32]],
    }];
    let bytes = simulate_request(7, &tx, &USER, true);
    let value = yw_json::parse(&bytes, &yw_json::Limits::REQUEST).unwrap();
    let object = value.as_object().unwrap();
    assert_eq!(
        object.get("method").unwrap().as_str(),
        Some("eth_simulateV1")
    );
    let params = object.get("params").unwrap().as_array().unwrap();
    assert_eq!(params[1].as_str(), Some("latest"));
    let options = params[0].as_object().unwrap();
    assert_eq!(options.get("traceTransfers").unwrap().as_bool(), Some(true));
    assert_eq!(options.get("validation").unwrap().as_bool(), Some(true));
    assert!(options.get("stateOverrides").is_none());
    let call = options.get("blockStateCalls").unwrap().as_array().unwrap()[0]
        .as_object()
        .unwrap()
        .get("calls")
        .unwrap()
        .as_array()
        .unwrap()[0]
        .as_object()
        .unwrap();
    let keys: Vec<&str> = call.keys().collect();
    assert_eq!(
        keys,
        [
            "from",
            "to",
            "value",
            "input",
            "nonce",
            "gas",
            "maxFeePerGas",
            "maxPriorityFeePerGas",
            "chainId",
            "type",
            "accessList"
        ]
    );
    assert_eq!(
        call.get("from").unwrap().as_str(),
        Some("0x0101010101010101010101010101010101010101")
    );
    assert_eq!(call.get("value").unwrap().as_str(), Some("0x5"));
    assert_eq!(call.get("input").unwrap().as_str(), Some("0xab"));
    assert_eq!(call.get("gas").unwrap().as_str(), Some("0x186a0"));
    assert_eq!(call.get("chainId").unwrap().as_str(), Some("0xaa36a7"));
    let plain = simulate_request(1, &self::tx(OTHER, 0, vec![]), &USER, false);
    let text = String::from_utf8(plain).unwrap();
    assert!(!text.contains("chainId") && !text.contains("accessList"));
    assert!(text.contains("\"input\":\"0x\""));
    let _: FeeCaps = chain_caps();
}

fn chain_caps() -> FeeCaps {
    sepolia().default_caps
}

#[test]
fn x4_dapp_fee_fields_are_ignored_with_e31() {
    // browser::params (M5) drops dApp fee fields and passes E31; the transaction keeps the
    // wallet-computed fees.
    let chain = sepolia();
    let wallet_tx = tx(OTHER, 5, vec![]);
    let site =
        ApprovalOrigin::Site(yw_core::policy::BrowserOrigin::parse("https://app.example").unwrap());
    let draft = try_request(
        &chain,
        &wallet_tx,
        &ok(vec![native(ERC7528_NATIVE, USER, OTHER, 5)]),
        site,
        &facts(),
        vec![risk::warning(risk::E31, None)],
    )
    .unwrap();
    let e31 = draft
        .display
        .warnings
        .iter()
        .find(|w| w.rule == risk::E31)
        .unwrap();
    assert_eq!(e31.level, RiskLevel::Info);
    assert_eq!(
        draft.payload,
        yw_core::approval::SigningPayload::EvmTx(wallet_tx)
    );
}

#[test]
fn x13_uninterpreted_with_successful_simulation() {
    let chain = sepolia();
    let unknown = tx(OTHER, 0, vec![0xde, 0xad, 0xbe, 0xef]);
    let draft = try_request(
        &chain,
        &unknown,
        &ok(vec![]),
        ApprovalOrigin::App,
        &facts(),
        Vec::new(),
    )
    .unwrap();
    assert_eq!(labels(&draft)[0], "E12");
    assert_eq!(draft.display.risk, RiskLevel::High);
    assert!(draft.display.ack_required);
}

#[test]
fn x20_token_symbol_is_escaped() {
    let chain = sepolia();
    let symbol = format!("US{}DC", char::from_u32(0x202e).unwrap());
    let sneaky = ChainFacts {
        tokens: vec![(
            TOKEN,
            TokenMeta {
                symbol: Some(symbol),
                decimals: Some(6),
                registered: false,
            },
        )],
        ..facts()
    };
    let send = tx(
        TOKEN,
        0,
        yw_core::evm::abi::erc20_transfer_data(&OTHER, &U256::from_u64(1_000_000)),
    );
    let draft = try_request(
        &chain,
        &send,
        &ok(vec![transfer(
            TOKEN,
            USER,
            OTHER,
            U256::from_u64(1_000_000),
        )]),
        ApprovalOrigin::App,
        &sneaky,
        Vec::new(),
    )
    .unwrap();
    assert!(draft.display.validate().is_ok());
    assert!(
        draft.display.title.contains("1 US[U+202E]DC (미확인)"),
        "{}",
        draft.display.title
    );
}
