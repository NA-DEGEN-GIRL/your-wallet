//! Approval digest, one-shot consumption and replacement (spec/03 §11.3–§11.5, EVM-V14 cases,
//! spec/09 X-14, X-15). The single-bit digest table follows
//! `archive/spec-v2.4:crates/wallet-protocol/src/approval.rs:708-765` with the v3 transcript.

use yw_core::approval::{
    AccountRef, ApprovalDisplay, ApprovalDraft, ApprovalError, ApprovalId, ApprovalKind,
    ApprovalOrigin, ApprovalState, ApprovalStore, ChainRef, DisplayError, DisplayField, FieldKey,
    RiskLevel, Signer, SigningPayload, SimBinding, SimNoneReason, SimVerdict, SimulationBinding,
    Warning, approval_digest,
};
use yw_core::bip32::path::AccountIndex;
use yw_core::evm::address::Address;
use yw_core::evm::amount::U256;
use yw_core::evm::chain::SEPOLIA_GENESIS;
use yw_core::evm::risk::{E01, E05, warning};
use yw_core::evm::simulate::{SIM_FRESHNESS_MS, needs_resimulation};
use yw_core::evm::tx::Eip1559Tx;
use yw_core::policy::BrowserOrigin;
use yw_core::vault::EvmKeySource;

const EXPIRES: u64 = 1_791_381_336_000;

fn tx() -> Eip1559Tx {
    Eip1559Tx {
        chain_id: 11_155_111,
        nonce: 3,
        max_priority_fee_per_gas: U256::from_u64(1),
        max_fee_per_gas: U256::from_u64(2),
        gas_limit: 21_000,
        to: Address::from_bytes([0x22; 20]),
        value: U256::from_u64(5),
        data: Vec::new(),
        access_list: Vec::new(),
    }
}

fn try_display(value: &str, warnings: Vec<Warning>) -> Result<ApprovalDisplay, DisplayError> {
    ApprovalDisplay::new(
        yw_core::lang::Lang::Ko,
        "[Sepolia 테스트넷] 테스트".to_owned(),
        vec![
            DisplayField::new(FieldKey::TO, "", value)?,
            DisplayField::new(FieldKey::EXPECTED_FEE, "", "알 수 없음")?,
        ],
        warnings,
    )
}

fn display(value: &str, warnings: Vec<Warning>) -> ApprovalDisplay {
    match try_display(value, warnings) {
        Ok(display) => display,
        Err(_) => ApprovalDisplay {
            lang: yw_core::lang::Lang::Ko,
            title: String::new(),
            fields: Vec::new(),
            warnings: Vec::new(),
            risk: RiskLevel::Blocked,
            ack_required: false,
        },
    }
}

fn block() -> SimBinding {
    SimBinding {
        number: 0x9a_0000,
        parent_hash: [0xb0; 32],
        timestamp: 0x6ac6_4ee0,
        base_fee: U256::from_u64(1_000_000_000),
        sim_digest: [0x5d; 32],
    }
}

fn draft() -> ApprovalDraft {
    ApprovalDraft {
        id: ApprovalId([0; 16]),
        origin: ApprovalOrigin::App,
        chain: ChainRef::Evm {
            chain_id: 11_155_111,
            genesis: SEPOLIA_GENESIS,
        },
        account: AccountRef::Evm(Address::from_bytes([0x11; 20])),
        signer: Signer::Evm(EvmKeySource::Derived(AccountIndex::ZERO)),
        kind: ApprovalKind::EvmTransaction,
        payload: SigningPayload::EvmTx(tx()),
        display: display("a", Vec::new()),
        simulation: SimulationBinding::Simulated {
            verdict: SimVerdict::Ok,
            block: block(),
        },
    }
}

#[test]
#[expect(clippy::too_many_lines, reason = "one case per digest input")]
fn x15_every_digest_input_changes_the_digest() {
    let original = draft();
    let expected = approval_digest(&original, EXPIRES).unwrap();
    let mut cases: Vec<(&str, ApprovalDraft, u64)> = Vec::new();
    let mut push = |name, change: &dyn Fn(&mut ApprovalDraft), expires| {
        let mut changed = draft();
        change(&mut changed);
        cases.push((name, changed, expires));
    };
    push("id", &|d| d.id.0[15] ^= 1, EXPIRES);
    push("kind", &|d| d.kind = ApprovalKind::EvmSpeedUp, EXPIRES);
    push(
        "origin",
        &|d| d.origin = ApprovalOrigin::Site(BrowserOrigin::parse("https://app.example").unwrap()),
        EXPIRES,
    );
    push(
        "chain id",
        &|d| {
            d.chain = ChainRef::Evm {
                chain_id: 11_155_110,
                genesis: SEPOLIA_GENESIS,
            };
        },
        EXPIRES,
    );
    push(
        "genesis",
        &|d| {
            let mut genesis = SEPOLIA_GENESIS;
            genesis[0] ^= 1;
            d.chain = ChainRef::Evm {
                chain_id: 11_155_111,
                genesis,
            };
        },
        EXPIRES,
    );
    push(
        "account",
        &|d| {
            let mut bytes = [0x11; 20];
            bytes[19] ^= 1;
            d.account = AccountRef::Evm(Address::from_bytes(bytes));
        },
        EXPIRES,
    );
    push(
        "payload",
        &|d| {
            let mut changed = tx();
            changed.nonce ^= 1;
            d.payload = SigningPayload::EvmTx(changed);
        },
        EXPIRES,
    );
    push(
        "display",
        &|d| d.display = display("c", Vec::new()),
        EXPIRES,
    );
    push(
        "verdict",
        &|d| {
            d.simulation = SimulationBinding::Simulated {
                verdict: SimVerdict::Incomplete,
                block: block(),
            };
        },
        EXPIRES,
    );
    push(
        "parent hash",
        &|d| {
            let mut changed = block();
            changed.parent_hash[31] ^= 1;
            d.simulation = SimulationBinding::Simulated {
                verdict: SimVerdict::Ok,
                block: changed,
            };
        },
        EXPIRES,
    );
    push(
        "sim digest",
        &|d| {
            let mut changed = block();
            changed.sim_digest[0] ^= 1;
            d.simulation = SimulationBinding::Simulated {
                verdict: SimVerdict::Ok,
                block: changed,
            };
        },
        EXPIRES,
    );
    push(
        "base fee",
        &|d| {
            let mut changed = block();
            changed.base_fee = U256::from_u64(1_000_000_001);
            d.simulation = SimulationBinding::Simulated {
                verdict: SimVerdict::Ok,
                block: changed,
            };
        },
        EXPIRES,
    );
    push(
        "sim absent",
        &|d| {
            d.simulation = SimulationBinding::None {
                reason: SimNoneReason::RpcError,
            };
        },
        EXPIRES,
    );
    push("expiry", &|_| {}, EXPIRES ^ 1);
    for (name, changed, expires) in &cases {
        assert_ne!(
            approval_digest(changed, *expires).unwrap(),
            expected,
            "{name}"
        );
    }
    // Reason byte and tag are bound too.
    let mut none_a = draft();
    none_a.simulation = SimulationBinding::None {
        reason: SimNoneReason::Transport,
    };
    let mut none_b = draft();
    none_b.simulation = SimulationBinding::None {
        reason: SimNoneReason::Timeout,
    };
    assert_ne!(
        approval_digest(&none_a, EXPIRES).unwrap(),
        approval_digest(&none_b, EXPIRES).unwrap()
    );
}

#[test]
fn x14_one_shot_consumption() {
    let mut store = ApprovalStore::new();
    let request = store.issue(draft(), 1_000, 1_791_381_216_000).unwrap();
    assert_eq!(request.expires_unix_ms, EXPIRES);
    assert_eq!(request.digest, approval_digest(&draft(), EXPIRES).unwrap());
    let approved = store
        .consume(request.id, request.digest, 1_000 + 119_999)
        .unwrap();
    assert_eq!(approved.digest(), request.digest);
    assert_eq!(
        store.consume(request.id, request.digest, 1_500),
        Err(ApprovalError::NotPending(ApprovalState::Consumed))
    );

    let mut mismatch = draft();
    mismatch.id = ApprovalId([1; 16]);
    let request = store.issue(mismatch, 1_000, 1_791_381_216_000).unwrap();
    let mut shown = request.digest;
    shown[0] ^= 1;
    assert_eq!(
        store.consume(request.id, shown, 1_500),
        Err(ApprovalError::DigestMismatch)
    );
    assert_eq!(store.state(request.id), Some(ApprovalState::Invalidated));
    assert_eq!(
        store.consume(request.id, request.digest, 1_500),
        Err(ApprovalError::NotPending(ApprovalState::Invalidated))
    );

    let mut late = draft();
    late.id = ApprovalId([2; 16]);
    let request = store.issue(late, 1_000, 1_791_381_216_000).unwrap();
    assert_eq!(
        store.consume(request.id, request.digest, 1_000 + 120_000),
        Err(ApprovalError::Expired)
    );
    assert_eq!(store.state(request.id), Some(ApprovalState::Expired));

    let mut locked = draft();
    locked.id = ApprovalId([3; 16]);
    let request = store.issue(locked, 1_000, 1_791_381_216_000).unwrap();
    store.invalidate_all();
    assert_eq!(
        store.consume(request.id, request.digest, 1_500),
        Err(ApprovalError::NotPending(ApprovalState::Invalidated))
    );

    let mut rejected = draft();
    rejected.id = ApprovalId([4; 16]);
    let request = store.issue(rejected, 1_000, 1_791_381_216_000).unwrap();
    store.reject(request.id);
    assert_eq!(store.state(request.id), Some(ApprovalState::Rejected));

    let mut due = draft();
    due.id = ApprovalId([5; 16]);
    let request = store.issue(due, 1_000, 1_791_381_216_000).unwrap();
    assert!(store.expire_due(120_999).is_empty());
    assert_eq!(store.expire_due(121_000), vec![request.id]);
    assert_eq!(
        store.consume(ApprovalId([9; 16]), [0; 32], 0).unwrap_err(),
        ApprovalError::UnknownId
    );
}

#[test]
fn issue_checks() {
    let mut store = ApprovalStore::new();
    store.issue(draft(), 0, 0).unwrap();
    assert_eq!(
        store.issue(draft(), 0, 0).unwrap_err(),
        ApprovalError::DuplicateId
    );
    // EVM transaction kinds need Simulated/None; messages need NotApplicable.
    let mut tx_without_binding = draft();
    tx_without_binding.id = ApprovalId([1; 16]);
    tx_without_binding.simulation = SimulationBinding::NotApplicable;
    assert_eq!(
        store.issue(tx_without_binding, 0, 0).unwrap_err(),
        ApprovalError::SimulationBindingMismatch
    );
    let mut message_with_sim = draft();
    message_with_sim.id = ApprovalId([2; 16]);
    message_with_sim.kind = ApprovalKind::EvmPersonalSign;
    message_with_sim.payload =
        SigningPayload::EvmPersonal(b"\x19Ethereum Signed Message:\n1a".to_vec());
    assert_eq!(
        store.issue(message_with_sim.clone(), 0, 0).unwrap_err(),
        ApprovalError::SimulationBindingMismatch
    );
    message_with_sim.simulation = SimulationBinding::NotApplicable;
    assert!(store.issue(message_with_sim, 0, 0).is_ok());
    let mut wrong_payload = draft();
    wrong_payload.id = ApprovalId([3; 16]);
    wrong_payload.payload = SigningPayload::EvmTypedData([0; 66]);
    assert_eq!(
        store.issue(wrong_payload, 0, 0).unwrap_err(),
        ApprovalError::PayloadMismatch
    );
    assert_eq!(
        store
            .issue(
                ApprovalDraft {
                    id: ApprovalId([4; 16]),
                    ..draft()
                },
                u64::MAX,
                0
            )
            .unwrap_err(),
        ApprovalError::Overflow
    );
}

#[test]
fn blocked_requests_cannot_be_consumed_and_high_risk_can() {
    let mut store = ApprovalStore::new();
    let mut blocked = draft();
    blocked.display = display(
        "a",
        vec![warning(
            yw_core::lang::Lang::Ko,
            E05,
            Some("최대 수수료 > 상한"),
        )],
    );
    assert_eq!(blocked.display.risk, RiskLevel::Blocked);
    assert!(!blocked.display.ack_required);
    let request = store.issue(blocked, 0, 0).unwrap();
    assert_eq!(
        store.consume(request.id, request.digest, 1),
        Err(ApprovalError::Blocked)
    );
    let mut high = draft();
    high.id = ApprovalId([1; 16]);
    high.display = display(
        "a",
        vec![warning(yw_core::lang::Lang::Ko, E01, Some("원인"))],
    );
    assert_eq!(high.display.risk, RiskLevel::High);
    assert!(high.display.ack_required);
    let request = store.issue(high, 0, 0).unwrap();
    assert!(store.consume(request.id, request.digest, 1).is_ok());
}

#[test]
fn replace_keeps_times_and_requires_the_shown_digest() {
    let mut store = ApprovalStore::new();
    let request = store.issue(draft(), 10_000, 1_791_381_216_000).unwrap();
    // Re-simulation: only parentHash changed → same display, new digest.
    let mut fresh = draft();
    fresh.simulation = SimulationBinding::Simulated {
        verdict: SimVerdict::Ok,
        block: SimBinding {
            parent_hash: [0xb9; 32],
            ..block()
        },
    };
    assert_eq!(
        fresh.display.stable_bytes().unwrap(),
        request.display.stable_bytes().unwrap()
    );
    let mut stale = request.digest;
    stale[3] ^= 1;
    assert_eq!(
        store.replace(request.id, stale, fresh.clone()).unwrap_err(),
        ApprovalError::DigestMismatch
    );
    let mut other_id = fresh.clone();
    other_id.id = ApprovalId([9; 16]);
    assert_eq!(
        store
            .replace(request.id, request.digest, other_id)
            .unwrap_err(),
        ApprovalError::ReplaceMismatch
    );
    // spec/03 §11.5 (2026-11-14): a re-simulation never switches the display language.
    let mut other_language = fresh.clone();
    other_language.display.lang = yw_core::lang::Lang::En;
    assert_eq!(
        store
            .replace(request.id, request.digest, other_language)
            .unwrap_err(),
        ApprovalError::ReplaceMismatch
    );
    let replaced = store.replace(request.id, request.digest, fresh).unwrap();
    assert_ne!(replaced.digest, request.digest);
    assert_eq!(replaced.created_unix_ms, request.created_unix_ms);
    assert_eq!(replaced.expires_unix_ms, request.expires_unix_ms);
    // The old digest no longer consumes; the deadline is the original one.
    assert_eq!(
        store.consume(request.id, request.digest, 10_001),
        Err(ApprovalError::DigestMismatch)
    );
    let mut again = draft();
    again.id = ApprovalId([1; 16]);
    let request = store
        .issue(again.clone(), 10_000, 1_791_381_216_000)
        .unwrap();
    // A failed re-simulation replaces the binding with None (spec/03 §6.6-3).
    let mut none = again;
    none.simulation = SimulationBinding::None {
        reason: SimNoneReason::Timeout,
    };
    none.display = display(
        "a",
        vec![warning(
            yw_core::lang::Lang::Ko,
            E01,
            Some("시뮬레이션 응답이 없습니다(10초)"),
        )],
    );
    let replaced = store.replace(request.id, request.digest, none).unwrap();
    assert_eq!(
        store.consume(request.id, replaced.digest, 10_000 + 120_000),
        Err(ApprovalError::Expired)
    );
}

#[test]
fn v17_resimulation_freshness() {
    let simulated = SimulationBinding::Simulated {
        verdict: SimVerdict::Ok,
        block: block(),
    };
    assert!(!needs_resimulation(
        &simulated,
        1_000,
        1_000 + SIM_FRESHNESS_MS
    ));
    assert!(needs_resimulation(
        &simulated,
        1_000,
        1_000 + SIM_FRESHNESS_MS + 1
    ));
    for reason in [
        SimNoneReason::Unsupported,
        SimNoneReason::Timeout,
        SimNoneReason::RpcError,
    ] {
        let none = SimulationBinding::None { reason };
        assert!(!needs_resimulation(&none, 1_000, 1_000 + 61_000));
    }
    assert!(!needs_resimulation(
        &SimulationBinding::NotApplicable,
        0,
        u64::MAX
    ));
}

#[test]
fn message_drafts_need_exact_eip191_and_eip712_prefixes() {
    let mut store = ApprovalStore::new();
    let message = |id: u8, kind: ApprovalKind, payload: SigningPayload| ApprovalDraft {
        id: ApprovalId([id; 16]),
        kind,
        payload,
        simulation: SimulationBinding::NotApplicable,
        ..draft()
    };
    let personal = yw_core::evm::eip191::personal_preimage(b"hello");
    assert!(
        store
            .issue(
                message(
                    1,
                    ApprovalKind::EvmPersonalSign,
                    SigningPayload::EvmPersonal(personal)
                ),
                0,
                0
            )
            .is_ok()
    );
    for (id, bad) in [
        (2, vec![0xab; 32]),
        (3, b"\x19Ethereum Signed Message:\n4hello".to_vec()),
        (4, b"\x19Ethereum Signed Message:\n05hello".to_vec()),
        (5, b"\x19Bitcoin Signed Message:\n5hello".to_vec()),
    ] {
        assert_eq!(
            store
                .issue(
                    message(
                        id,
                        ApprovalKind::EvmPersonalSign,
                        SigningPayload::EvmPersonal(bad)
                    ),
                    0,
                    0
                )
                .unwrap_err(),
            ApprovalError::PayloadMismatch,
            "personal draft {id}"
        );
    }
    let mut typed = [0_u8; 66];
    typed[0] = 0x19;
    typed[1] = 0x01;
    assert!(
        store
            .issue(
                message(
                    6,
                    ApprovalKind::EvmTypedData,
                    SigningPayload::EvmTypedData(typed)
                ),
                0,
                0
            )
            .is_ok()
    );
    typed[1] = 0x45;
    assert_eq!(
        store
            .issue(
                message(
                    7,
                    ApprovalKind::EvmTypedData,
                    SigningPayload::EvmTypedData(typed)
                ),
                0,
                0
            )
            .unwrap_err(),
        ApprovalError::PayloadMismatch
    );
}
