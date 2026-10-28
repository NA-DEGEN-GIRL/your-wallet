//! spec/08 §8, §10, §11.3, §13 through the public API: fee units (`fee_units_btc_per_kvb`), the
//! floor and source rules (`fee_floor_raises_estimate`), caps and the typed override
//! (`fee_caps_and_typed_override`), the ratio confirmation (`fee_ratio_confirm`), the `B01`–`B08`
//! levels and texts, the `reject-reason` and RPC tables, the `testmempoolaccept` comparison
//! (`testmempoolaccept_mismatch_rejects`) and the `sendrawtransaction` outcome mapping, and
//! BTC-N5 (fee caps blocked).
#![allow(
    clippy::unwrap_used,
    reason = "fixture helpers outside #[test] functions panic on broken fixtures"
)]

mod btc_common;

use btc_common::{NET, RECIPIENT, SEED, TIP, account, plan, rate, utxo};
use yw_core::approval::{ApprovalId, ApprovalStore, RiskLevel};
use yw_core::bip32::path::BtcChain;
use yw_core::btc::amount::{AmountError, Sats};
use yw_core::btc::display::{BtcSendFacts, build_btc_request, plan_warnings};
use yw_core::btc::fee::{
    FeeChoice, FeeError, FeeRate, FeeSelection, FeeSource, check_fee, choose_fee_rate, fee_floor,
    fee_for, fee_rate_from_btc_per_kvb, incremental_or_default, maxfeerate_literal,
    parse_user_sat_per_vb, rate_kvb,
};
use yw_core::btc::policy::{
    B01, B02, B03, B04, B05, B06, B07, B08, BroadcastOutcome, BtcWarning, LocalTx, MempoolAccept,
    PrecheckOutcome, REJECT_TOKENS, SendRawResult, broadcast_outcome, check_mempool_accept,
    known_reject_token, level_of, reject_reason_text, rpc_error_text, texts,
};
use yw_core::btc::select::{SendAmount, SendRequest, plan_send};
use yw_core::btc::tx::Txid;

fn sats(value: u64) -> Sats {
    Sats::new(value).unwrap()
}

fn kvb(value: u64) -> FeeRate {
    FeeRate::from_sat_per_kvb(value)
}

/// spec/08 §14.2 `fee_units_btc_per_kvb`.
#[test]
fn fee_units_btc_per_kvb() {
    assert_eq!(fee_rate_from_btc_per_kvb("0.00001000"), Ok(kvb(1_000)));
    assert_eq!(fee_rate_from_btc_per_kvb("0.00000474"), Ok(kvb(474)));
    assert_eq!(fee_rate_from_btc_per_kvb("0.00000100"), Ok(kvb(100)));
    assert_eq!(fee_rate_from_btc_per_kvb("0.0001"), Ok(kvb(10_000)));
    assert_eq!(fee_rate_from_btc_per_kvb("0"), Ok(kvb(0)));
    for bad in [
        "1e-05",
        "-0.1",
        "0.000010000",
        "+0.1",
        "0.1e1",
        ".1",
        "1.",
        "00.1",
        "0,1",
        " 0.1",
        "",
        "NaN",
    ] {
        assert_eq!(
            fee_rate_from_btc_per_kvb(bad),
            Err(AmountError::InvalidFormat),
            "{bad}"
        );
    }
    // Manual sat/vB: ^[0-9]{1,6}(\.[0-9]{1,3})?$
    assert_eq!(parse_user_sat_per_vb("1"), Ok(kvb(1_000)));
    assert_eq!(parse_user_sat_per_vb("10.2"), Ok(kvb(10_200)));
    assert_eq!(parse_user_sat_per_vb("0.474"), Ok(kvb(474)));
    assert_eq!(parse_user_sat_per_vb("999999.999"), Ok(kvb(999_999_999)));
    assert_eq!(parse_user_sat_per_vb("007"), Ok(kvb(7_000)));
    for bad in [
        "", "1.", ".5", "1.0001", "1234567", "-1", "1e3", "1,5", " 1", "1 ",
    ] {
        assert_eq!(
            parse_user_sat_per_vb(bad),
            Err(AmountError::InvalidFormat),
            "{bad}"
        );
    }
    // Display: X.XXX sat/vB, trailing zeros trimmed.
    assert_eq!(kvb(1_000).to_string(), "1 sat/vB");
    assert_eq!(kvb(10_200).to_string(), "10.2 sat/vB");
    assert_eq!(kvb(474).to_string(), "0.474 sat/vB");
    assert_eq!(kvb(1_050).to_string(), "1.05 sat/vB");
    assert_eq!(kvb(0).to_string(), "0 sat/vB");
    // fee = ceil(rate × vsize / 1000), rate_kvb = ceil(fee × 1000 / vsize).
    assert_eq!(fee_for(kvb(1_000), 141), Some(sats(141)));
    assert_eq!(fee_for(kvb(1_001), 141), Some(sats(142)));
    assert_eq!(fee_for(kvb(474), 110), Some(sats(53)));
    assert_eq!(fee_for(kvb(u64::MAX), 2), None);
    assert_eq!(rate_kvb(sats(141), 141), Some(1_000));
    assert_eq!(rate_kvb(sats(142), 141), Some(1_008));
    assert_eq!(rate_kvb(sats(1), 0), None);
    // maxfeerate: ceil(rate/1000)+1 sat/vB as BTC/kvB.
    assert_eq!(maxfeerate_literal(10_200).as_deref(), Some("0.00012000"));
    assert_eq!(maxfeerate_literal(1_000).as_deref(), Some("0.00002000"));
    assert_eq!(maxfeerate_literal(474).as_deref(), Some("0.00002000"));
    assert_eq!(maxfeerate_literal(500_000).as_deref(), Some("0.00501000"));
    assert_eq!(incremental_or_default(None), kvb(1_000));
    assert_eq!(incremental_or_default(Some(kvb(100))), kvb(100));
}

/// spec/08 §14.2 `fee_floor_raises_estimate` (live 2026-10-27: Core 31 floor fields 100 sat/kvB,
/// mainnet estimate 474 sat/kvB, testnet4 no estimate).
#[test]
fn fee_floor_raises_estimate() {
    let floor = fee_floor(Some(kvb(100)), Some(kvb(100)));
    assert_eq!(floor, kvb(1_000));
    assert_eq!(fee_floor(None, None), kvb(1_000));
    assert_eq!(fee_floor(Some(kvb(2_500)), Some(kvb(1_500))), kvb(2_500));
    let raised = choose_fee_rate(
        FeeSelection::Estimate {
            target: 6,
            estimate: Some(kvb(474)),
        },
        floor,
    )
    .unwrap();
    assert_eq!(
        raised,
        FeeChoice {
            rate: kvb(1_000),
            source: FeeSource::Floor
        }
    );
    assert_eq!(raised.source.text(), "하한 적용");
    let estimate = choose_fee_rate(
        FeeSelection::Estimate {
            target: 2,
            estimate: Some(kvb(3_210)),
        },
        floor,
    )
    .unwrap();
    assert_eq!(estimate.rate, kvb(3_210));
    assert_eq!(estimate.source.text(), "노드 추정(빠름, 2블록 목표)");
    assert_eq!(
        FeeSource::Estimate { target: 6 }.text(),
        "노드 추정(보통, 6블록 목표)"
    );
    assert_eq!(
        FeeSource::Estimate { target: 24 }.text(),
        "노드 추정(느림, 24블록 목표)"
    );
    assert_eq!(
        FeeSource::Estimate { target: 3 }.text(),
        "노드 추정(3블록 목표)"
    );
    assert_eq!(
        choose_fee_rate(
            FeeSelection::Estimate {
                target: 6,
                estimate: None
            },
            floor
        ),
        Err(FeeError::NoEstimate)
    );
    assert_eq!(
        choose_fee_rate(FeeSelection::Manual(kvb(999)), floor),
        Err(FeeError::ManualBelowFloor { floor })
    );
    assert_eq!(
        FeeError::ManualBelowFloor { floor }.to_string(),
        "수수료율이 노드 하한(1 sat/vB)보다 낮습니다"
    );
    assert_eq!(
        choose_fee_rate(FeeSelection::Manual(kvb(1_000)), floor),
        Ok(FeeChoice {
            rate: kvb(1_000),
            source: FeeSource::Manual
        })
    );
    assert_eq!(
        choose_fee_rate(FeeSelection::Floor, kvb(2_000)),
        Ok(FeeChoice {
            rate: kvb(2_000),
            source: FeeSource::Floor
        })
    );
    // The floor is what a plan uses: 474 sat/kvB would give 67 sats for 141 vB.
    let plan = plan(
        &[utxo(50_000, TIP - 1, 1, 0)],
        RECIPIENT,
        SendAmount::Exact(sats(20_000)),
        raised,
        SEED,
    )
    .unwrap();
    assert_eq!(plan.fee(), sats(141));
    assert_eq!(plan.fee_source(), FeeSource::Floor);
}

fn warnings_of(plan: &yw_core::btc::select::SendPlan) -> Vec<yw_core::approval::RuleId> {
    plan_warnings(plan, &BtcSendFacts::default())
        .iter()
        .map(|warning| warning.rule)
        .collect()
}

fn plan_typed(
    candidates: &[yw_core::btc::select::Utxo],
    amount: SendAmount,
    fee: FeeChoice,
    typed: Option<Sats>,
) -> yw_core::btc::select::SendPlan {
    let account = account();
    plan_send(&SendRequest {
        network: NET,
        account: &account,
        recipient: RECIPIENT,
        amount,
        fee,
        candidates,
        tip_height: TIP,
        change_next: 0,
        layout_seed: SEED,
        typed_fee_override: typed,
        conflicts: &[],
    })
    .unwrap()
}

/// spec/08 §14.2 `fee_caps_and_typed_override` and BTC-N5 (fee caps blocked): the rate cap
/// (500 sat/vB) and the absolute cap (0.005 BTC) block (B02) unless the send form's exact typed
/// fee lifts them (B03, high); 10,000 sat/vB (B01) is never lifted.
#[test]
fn fee_caps_and_typed_override() {
    let big = [utxo(2_000_000, TIP - 1, 1, 0)];
    let amount = SendAmount::Exact(sats(100_000));
    // At the cap: nothing.
    let at_cap = plan_typed(&big, amount, rate(500), None);
    let check = at_cap.fee_check().unwrap();
    assert_eq!(check.rate_kvb, 500_000);
    assert!(!check.over_cap && !at_cap.needs_typed_override());
    assert!(!warnings_of(&at_cap).contains(&B02));
    // Over the rate cap: B02 without, B03 with the exact typed fee.
    let over = plan_typed(&big, amount, rate(501), None);
    assert!(over.fee_check().unwrap().over_cap);
    assert!(over.needs_typed_override());
    assert_eq!(warnings_of(&over), vec![B02, B04]);
    let wrong = plan_typed(&big, amount, rate(501), Some(sats(over.fee().get() - 1)));
    assert!(!wrong.fee_override_typed());
    assert!(warnings_of(&wrong).contains(&B02));
    let typed = plan_typed(&big, amount, rate(501), Some(over.fee()));
    assert!(typed.fee_override_typed() && !typed.needs_typed_override());
    assert_eq!(warnings_of(&typed), vec![B03, B04]);
    // A typed value below the cap changes nothing.
    let low = plan_typed(&big, amount, rate(2), Some(sats(282)));
    assert!(!low.fee_override_typed());
    // Absolute cap at a legal rate: 100 inputs at 100 sat/vB = 681,700 sats.
    let many: Vec<_> = (0..100_u8)
        .map(|tag| utxo(10_000, TIP - 1, tag, u32::from(tag)))
        .collect();
    let absolute = plan_typed(&many, SendAmount::Max, rate(100), None);
    assert_eq!(absolute.inputs().len(), 100);
    assert_eq!(absolute.fee(), sats(681_700));
    let check = absolute.fee_check().unwrap();
    assert!(check.rate_kvb <= 500_000 && check.over_cap);
    assert!(warnings_of(&absolute).contains(&B02));
    // 10,000 sat/vB and above: B01 even with the typed fee.
    let huge = plan_typed(&big, SendAmount::Exact(sats(500_000)), rate(10_001), None);
    assert!(huge.fee_check().unwrap().unoverridable);
    let huge_typed = plan_typed(
        &big,
        SendAmount::Exact(sats(500_000)),
        rate(10_001),
        Some(huge.fee()),
    );
    assert!(huge_typed.fee_override_typed());
    assert_eq!(warnings_of(&huge_typed), vec![B01, B04]);
    // Blocked requests are issued but cannot be consumed (no approve button).
    let draft = build_btc_request(
        ApprovalId([3; 16]),
        &over,
        &account(),
        &BtcSendFacts::default(),
    )
    .unwrap();
    assert_eq!(draft.display.risk, RiskLevel::Blocked);
    let mut store = ApprovalStore::new();
    let request = store.issue(draft, 1, 1).unwrap();
    assert_eq!(
        store.consume(request.id, request.digest, 2),
        Err(yw_core::approval::ApprovalError::Blocked)
    );
    let draft = build_btc_request(
        ApprovalId([4; 16]),
        &typed,
        &account(),
        &BtcSendFacts::default(),
    )
    .unwrap();
    assert_eq!(draft.display.risk, RiskLevel::High);
    assert!(draft.display.ack_required);
}

/// spec/08 §14.2 `fee_ratio_confirm`: high risk exactly when `fee × 50 > amount`.
#[test]
fn fee_ratio_confirm() {
    assert!(!check_fee(sats(200), 141, sats(10_000)).unwrap().ratio_high);
    assert!(check_fee(sats(201), 141, sats(10_000)).unwrap().ratio_high);
    let small = plan(
        &[utxo(50_000, TIP - 1, 1, 0)],
        RECIPIENT,
        SendAmount::Exact(sats(7_050)),
        rate(1),
        SEED,
    )
    .unwrap();
    assert_eq!(small.fee(), sats(141));
    assert!(
        !warnings_of(&small).contains(&B04),
        "141 × 50 = 7,050 is not above"
    );
    let smaller = plan(
        &[utxo(50_000, TIP - 1, 1, 0)],
        RECIPIENT,
        SendAmount::Exact(sats(7_049)),
        rate(1),
        SEED,
    )
    .unwrap();
    assert_eq!(warnings_of(&smaller), vec![B04]);
    let draft = build_btc_request(
        ApprovalId([5; 16]),
        &smaller,
        &account(),
        &BtcSendFacts::default(),
    )
    .unwrap();
    assert_eq!(draft.display.risk, RiskLevel::High);
    assert_eq!(draft.display.warnings[0].text, texts::FEE_RATIO);
}

/// The §10 table: rule ids, levels and fixed texts.
#[test]
fn b_rule_levels_and_texts() {
    let table = [
        (B01, RiskLevel::Blocked, 1),
        (B02, RiskLevel::Blocked, 2),
        (B03, RiskLevel::High, 3),
        (B04, RiskLevel::High, 4),
        (B05, RiskLevel::Caution, 5),
        (B06, RiskLevel::Caution, 6),
        (B07, RiskLevel::Info, 7),
        (B08, RiskLevel::Info, 8),
    ];
    for (rule, level, number) in table {
        assert_eq!(rule.family(), b'B');
        assert_eq!(rule.number(), number);
        assert_eq!(level_of(rule), Some(level));
        assert_eq!(rule.label(), format!("B0{number}"));
    }
    assert_eq!(level_of(yw_core::approval::RuleId::new(b'B', 9)), None);
    assert_eq!(
        BtcWarning::UtxosExcluded { count: 3 }.text(),
        "UTXO 3개는 포함되지 않음(입력 최대 100개)"
    );
    assert_eq!(
        BtcWarning::OwnAddress {
            coin: 1,
            chain: BtcChain::Change,
            index: 4
        }
        .text(),
        "이 지갑의 주소입니다 (m/84'/1'/0'/1/4)"
    );
    for warning in [
        BtcWarning::FeeUnoverridable,
        BtcWarning::FeeCapBlocked,
        BtcWarning::FeeCapOverridden,
        BtcWarning::FeeRatio,
        BtcWarning::FirstTimeRecipient,
        BtcWarning::RecipientDecreased,
        BtcWarning::UtxosExcluded { count: 1 },
        BtcWarning::OwnAddress {
            coin: 0,
            chain: BtcChain::Receive,
            index: 0,
        },
        BtcWarning::LegacyRecipient,
        BtcWarning::ScriptRecipient,
    ] {
        let shown = warning.warning();
        assert_eq!(shown.rule, warning.rule());
        assert_eq!(Some(shown.level), level_of(shown.rule));
        assert!(yw_core::approval::is_valid_display_text(
            &shown.text,
            1_000,
            false
        ));
    }
}

/// spec/08 §13: exact `reject-reason` tokens only; RPC codes; no server text passes through.
#[test]
fn reject_reason_and_rpc_tables() {
    let table = [
        (
            "min relay fee not met",
            "수수료율이 노드 최소값보다 낮습니다",
        ),
        (
            "mempool min fee not met",
            "수수료율이 노드 최소값보다 낮습니다",
        ),
        ("insufficient fee", "교체 수수료가 부족합니다"),
        ("txn-mempool-conflict", "다른 미확정 거래와 충돌합니다"),
        ("missing-inputs", "입력이 없거나 이미 사용되었습니다"),
        (
            "bad-txns-inputs-missingorspent",
            "입력이 없거나 이미 사용되었습니다",
        ),
        (
            "non-final",
            "잠금 시간이 아직 지나지 않았습니다(노드 높이 확인)",
        ),
        ("dust", "먼지 출력이 있습니다"),
        ("max-fee-exceeded", "수수료 상한을 넘었습니다"),
        ("txn-already-in-mempool", "이미 전송된 거래입니다"),
        ("txn-already-known", "이미 전송된 거래입니다"),
    ];
    for (token, text) in table {
        assert_eq!(reject_reason_text(token), text);
    }
    for unknown in [
        "Dust",
        "dust ",
        "min relay fee not met, 100 < 141",
        "<script>",
        "",
        "insufficient fee, rejecting replacement",
    ] {
        assert_eq!(reject_reason_text(unknown), "알 수 없는 거부 사유");
    }
    assert_eq!(rpc_error_text(-25), "입력이 없거나 이미 사용되었습니다");
    assert_eq!(rpc_error_text(-26), "노드가 거래를 거부했습니다");
    assert_eq!(rpc_error_text(-8), "RPC 오류(코드 -8)");
}

fn local() -> LocalTx {
    LocalTx {
        txid: Txid::from_bytes([1; 32]),
        wtxid: [2; 32],
        vsize: 141,
        fee: sats(141),
    }
}

fn accepted() -> MempoolAccept {
    MempoolAccept {
        txid: Txid::from_bytes([1; 32]),
        wtxid: [2; 32],
        allowed: true,
        vsize: Some(141),
        fee_base: Some(sats(141)),
        reject_reason: None,
    }
}

/// spec/08 §14.2 `testmempoolaccept_mismatch_rejects`.
#[test]
fn testmempoolaccept_mismatch_rejects() {
    let local = local();
    assert_eq!(
        check_mempool_accept(&accepted(), &local),
        PrecheckOutcome::Accepted
    );
    let mismatch = PrecheckOutcome::Rejected {
        text: "노드 검사 결과가 로컬 계산과 다릅니다",
    };
    let mut cases = Vec::new();
    let mut answer = accepted();
    answer.fee_base = Some(sats(142));
    cases.push(answer);
    let mut answer = accepted();
    answer.fee_base = None;
    cases.push(answer);
    let mut answer = accepted();
    answer.vsize = Some(140);
    cases.push(answer);
    let mut answer = accepted();
    answer.vsize = None;
    cases.push(answer);
    let mut answer = accepted();
    answer.txid = Txid::from_bytes([3; 32]);
    cases.push(answer);
    let mut answer = accepted();
    answer.wtxid = [3; 32];
    cases.push(answer);
    for answer in cases {
        assert_eq!(
            check_mempool_accept(&answer, &local),
            mismatch,
            "{answer:?}"
        );
    }
    let mut refused = accepted();
    refused.allowed = false;
    refused.reject_reason = Some("insufficient fee".to_owned());
    assert_eq!(
        check_mempool_accept(&refused, &local),
        PrecheckOutcome::Rejected {
            text: "교체 수수료가 부족합니다"
        }
    );
    refused.reject_reason = Some("server says: send to bc1q...".to_owned());
    assert_eq!(
        check_mempool_accept(&refused, &local),
        PrecheckOutcome::Rejected {
            text: "알 수 없는 거부 사유"
        }
    );
    refused.reject_reason = None;
    assert_eq!(
        check_mempool_accept(&refused, &local),
        PrecheckOutcome::Rejected {
            text: "알 수 없는 거부 사유"
        }
    );
}

/// Review fix (spec/08 §11.3): `allowed == false` because the node already has our transaction
/// (`txn-already-in-mempool` / `txn-already-known`) is never `Rejected`; the same tokens about
/// another txid or wtxid are a mismatch.
#[test]
fn already_known_precheck_is_not_rejected() {
    let local = local();
    for token in ["txn-already-in-mempool", "txn-already-known"] {
        let mut answer = accepted();
        answer.allowed = false;
        answer.vsize = None;
        answer.fee_base = None;
        answer.reject_reason = Some(token.to_owned());
        assert_eq!(
            check_mempool_accept(&answer, &local),
            PrecheckOutcome::AlreadyKnown {
                text: "이미 전송된 거래입니다"
            },
            "{token}"
        );
        for (other_txid, other_wtxid) in [(true, false), (false, true)] {
            let mut other = answer.clone();
            if other_txid {
                other.txid = Txid::from_bytes([3; 32]);
            }
            if other_wtxid {
                other.wtxid = [3; 32];
            }
            assert_eq!(
                check_mempool_accept(&other, &local),
                PrecheckOutcome::Rejected {
                    text: "노드 검사 결과가 로컬 계산과 다릅니다"
                },
                "{token}"
            );
        }
    }
    // Other refusals stay `Rejected`.
    let mut refused = accepted();
    refused.allowed = false;
    refused.reject_reason = Some("txn-mempool-conflict".to_owned());
    assert_eq!(
        check_mempool_accept(&refused, &local),
        PrecheckOutcome::Rejected {
            text: "다른 미확정 거래와 충돌합니다"
        }
    );
}

/// spec/08 §11.3 `sendrawtransaction` outcomes.
#[test]
fn sendrawtransaction_outcomes() {
    let ours = Txid::from_bytes([1; 32]);
    assert_eq!(
        broadcast_outcome(&SendRawResult::Txid(ours), &ours),
        BroadcastOutcome::Submitted
    );
    assert_eq!(
        broadcast_outcome(&SendRawResult::Txid(Txid::from_bytes([2; 32])), &ours),
        BroadcastOutcome::BroadcastUnknown {
            text: Some("응답 txid 불일치".to_owned()),
            comm_failure: false
        }
    );
    assert_eq!(
        broadcast_outcome(&SendRawResult::RpcError { code: -27 }, &ours),
        BroadcastOutcome::Submitted
    );
    assert_eq!(
        broadcast_outcome(&SendRawResult::RpcError { code: -26 }, &ours),
        BroadcastOutcome::Rejected {
            text: "노드가 거래를 거부했습니다".to_owned()
        }
    );
    assert_eq!(
        broadcast_outcome(&SendRawResult::RpcError { code: -25 }, &ours),
        BroadcastOutcome::Rejected {
            text: "입력이 없거나 이미 사용되었습니다".to_owned()
        }
    );
    assert_eq!(
        broadcast_outcome(&SendRawResult::RpcError { code: -32603 }, &ours),
        BroadcastOutcome::BroadcastUnknown {
            text: Some("RPC 오류(코드 -32603)".to_owned()),
            comm_failure: false
        }
    );
    for result in [SendRawResult::Timeout, SendRawResult::Transport] {
        assert_eq!(
            broadcast_outcome(&result, &ours),
            BroadcastOutcome::BroadcastUnknown {
                text: None,
                comm_failure: true
            }
        );
    }
    assert_eq!(
        broadcast_outcome(&SendRawResult::NotTxid, &ours),
        BroadcastOutcome::BroadcastUnknown {
            text: Some("응답 txid 불일치".to_owned()),
            comm_failure: false
        }
    );
    assert_eq!(
        broadcast_outcome(&SendRawResult::Refused, &ours),
        BroadcastOutcome::BroadcastUnknown {
            text: None,
            comm_failure: false
        }
    );
    assert_eq!(known_reject_token("dust"), Some("dust"));
    assert_eq!(known_reject_token("Dust"), None);
    for token in REJECT_TOKENS {
        assert_ne!(reject_reason_text(token), "알 수 없는 거부 사유");
    }
}
