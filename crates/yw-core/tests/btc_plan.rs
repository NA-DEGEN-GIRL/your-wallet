//! spec/08 §7, §9, §10 through the public API with fixed seeds: `selection_single_then_fewest`,
//! `change_fold_below_294`, `send_max_dust`, `recipient_dust_by_type`, `rbf_rules`, the layout
//! (Fisher–Yates and change position from the seed), the byte layout of `btc_payload`, and the
//! approval display fields and warnings.
#![allow(
    clippy::unwrap_used,
    reason = "fixture helpers outside #[test] functions panic on broken fixtures"
)]

mod btc_common;

use btc_common::{
    NET, RECIPIENT, SEED, TIP, account, kinds, plan, rate, record, simple_plan, utxo,
};
use sha2::{Digest, Sha256};
use yw_core::approval::{ApprovalId, ApprovalKind, FieldKey, RiskLevel, SigningPayload};
use yw_core::bip32::path::BtcChain;
use yw_core::btc::address::{ScriptKind, encode_address, script_pubkey};
use yw_core::btc::amount::Sats;
use yw_core::btc::display::{BtcSendFacts, btc_payload, build_btc_request, payload_header};
use yw_core::btc::fee::{FeeChoice, FeeRate};
use yw_core::btc::policy::{B05, B06, B07, B08, texts};
use yw_core::btc::select::{
    BumpRequest, BumpSource, PlanError, SendAmount, SendPlan, Utxo, bump_fee_ok, plan_fee_bump,
};
use yw_core::btc::tx::{OutPoint, Txid, estimate_vsize, serialize};
use yw_core::btc::{BTC_SEQUENCE, BTC_TX_VERSION};
use yw_core::journal::btc::BtcTxState;
use yw_core::lang::Lang;

fn sats(value: u64) -> Sats {
    Sats::new(value).unwrap()
}

fn exact(value: u64) -> SendAmount {
    SendAmount::Exact(sats(value))
}

fn outpoints(plan: &SendPlan) -> Vec<OutPoint> {
    let mut out: Vec<OutPoint> = plan.inputs().iter().map(|input| input.outpoint).collect();
    out.sort();
    out
}

fn op(tag: u8, vout: u32) -> OutPoint {
    OutPoint {
        txid: Txid::from_bytes([tag; 32]),
        vout,
    }
}

/// Every plan's fixed fields (spec/08 §7.1) and internal consistency.
fn check_fixed(plan: &SendPlan) {
    let tx = plan.tx();
    assert_eq!(tx.version, BTC_TX_VERSION);
    assert_eq!(tx.lock_time, plan.lock_time());
    for (input, planned) in tx.inputs.iter().zip(plan.inputs()) {
        assert_eq!(input.sequence, BTC_SEQUENCE);
        assert!(input.script_sig.is_empty() && input.witness.is_empty());
        assert_eq!(input.prevout, planned.outpoint);
    }
    let recipient = &tx.outputs[usize::try_from(plan.recipient_vout()).unwrap()];
    assert_eq!(recipient.script_pubkey, script_pubkey(&plan.recipient()));
    assert_eq!(recipient.value, plan.amount());
    let outputs: u64 = tx.outputs.iter().map(|output| output.value.get()).sum();
    assert_eq!(
        plan.input_total().unwrap().get() - outputs,
        plan.fee().get(),
        "fee = Σin − Σout"
    );
    let lens: Vec<usize> = tx.outputs.iter().map(|o| o.script_pubkey.len()).collect();
    assert_eq!(
        estimate_vsize(tx.inputs.len(), &lens).unwrap(),
        u64::from(plan.planned_vsize())
    );
    match plan.change() {
        Some(change) => {
            assert_eq!(tx.outputs.len(), 2);
            assert!(change.value.get() >= 294);
            assert_eq!(
                tx.outputs[usize::try_from(change.vout).unwrap()].value,
                change.value
            );
        }
        None => assert_eq!(tx.outputs.len(), 1),
    }
}

/// spec/08 §14.2 `selection_single_then_fewest` (§7.4 steps 1–3, sort keys, candidate rules).
#[test]
fn selection_single_then_fewest() {
    let candidates = [
        utxo(10_000, TIP - 1, 1, 0),
        utxo(25_000, TIP - 2, 2, 0),
        utxo(60_000, TIP - 3, 3, 0),
        utxo(200_000, TIP - 4, 4, 0),
    ];
    // Step 1: the smallest single input that is feasible (not the largest).
    let one = plan(&candidates, RECIPIENT, exact(20_000), rate(1), SEED).unwrap();
    check_fixed(&one);
    assert_eq!(outpoints(&one), vec![op(2, 0)]);
    assert_eq!(one.fee(), sats(141));
    assert_eq!(one.change().unwrap().value, sats(4_859));
    assert_eq!(one.change().unwrap().index, 3, "change_next");
    // Step 2: fewest inputs by value descending.
    let two = plan(&candidates, RECIPIENT, exact(240_000), rate(1), SEED).unwrap();
    check_fixed(&two);
    assert_eq!(outpoints(&two), vec![op(3, 0), op(4, 0)]);
    assert_eq!(two.fee(), sats(208));
    assert_eq!(two.change().unwrap().value, sats(19_792));
    let four = plan(&candidates, RECIPIENT, exact(290_000), rate(1), SEED).unwrap();
    check_fixed(&four);
    assert_eq!(four.inputs().len(), 4);
    assert_eq!(four.fee(), sats(344));
    assert_eq!(four.change().unwrap().value, sats(4_656));
    // Step 3.
    assert_eq!(
        plan(&candidates, RECIPIENT, exact(300_000), rate(1), SEED),
        Err(PlanError::InsufficientFunds {
            available: sats(295_000),
            needed: sats(300_313),
        })
    );
    assert_eq!(
        PlanError::InsufficientFunds {
            available: sats(295_000),
            needed: sats(300_313),
        }
        .to_string(),
        "잔액이 부족합니다(필요 300,313 sats, 사용 가능 295,000 sats)"
    );
    // Ties: height ascending, then txid (display order), then vout.
    let ties = [
        utxo(25_000, TIP - 2, 2, 0),
        utxo(25_000, TIP - 9, 9, 0),
        utxo(25_000, TIP - 9, 8, 1),
        utxo(25_000, TIP - 9, 8, 0),
    ];
    let tie = plan(&ties, RECIPIENT, exact(20_000), rate(1), SEED).unwrap();
    assert_eq!(outpoints(&tie), vec![op(8, 0)]);
    // Unconfirmed, immature coinbase and zero-value candidates are never used.
    let mut coinbase = utxo(500_000, TIP - 98, 5, 0);
    coinbase.is_coinbase = true;
    let unconfirmed = utxo(400_000, TIP + 1, 6, 0);
    assert_eq!(
        plan(
            &[coinbase, unconfirmed],
            RECIPIENT,
            exact(20_000),
            rate(1),
            SEED
        ),
        Err(PlanError::InsufficientFunds {
            available: Sats::ZERO,
            needed: sats(20_110),
        })
    );
    let mut mature = coinbase;
    mature.height = TIP - 99;
    let spent = plan(
        &[mature, unconfirmed],
        RECIPIENT,
        exact(20_000),
        rate(1),
        SEED,
    )
    .unwrap();
    assert_eq!(outpoints(&spent), vec![op(5, 0)]);
    // Duplicate candidates count once.
    let duplicated = [utxo(15_000, TIP - 1, 7, 0), utxo(15_000, TIP - 1, 7, 0)];
    assert!(matches!(
        plan(&duplicated, RECIPIENT, exact(20_000), rate(1), SEED),
        Err(PlanError::InsufficientFunds { available, .. }) if available == sats(15_000)
    ));
    // Deterministic for a fixed seed; the set does not depend on the seed.
    let again = plan(&candidates, RECIPIENT, exact(290_000), rate(1), SEED).unwrap();
    assert_eq!(again, four);
    let other = plan(&candidates, RECIPIENT, exact(290_000), rate(1), [1; 32]).unwrap();
    assert_eq!(outpoints(&other), outpoints(&four));
}

/// spec/08 §7.5: input order by Fisher–Yates over the selection order and the change position,
/// both from the seed.
#[test]
fn layout_from_seed() {
    let candidates: Vec<Utxo> = (1..=6_u8)
        .map(|tag| utxo(10_000 * u64::from(tag), TIP - 1, tag, 0))
        .collect();
    for seed_byte in 0..8_u8 {
        let seed = [seed_byte; 32];
        let plan = plan(&candidates, RECIPIENT, exact(205_000), rate(1), seed).unwrap();
        // Selection order: value descending (all six).
        let mut expected: Vec<OutPoint> = (1..=6_u8).rev().map(|tag| op(tag, 0)).collect();
        for i in (1..expected.len()).rev() {
            let mut hasher = Sha256::new();
            hasher.update(seed);
            hasher.update(b"yw-btc-in");
            hasher.update(u32::try_from(i).unwrap().to_be_bytes());
            let digest = hasher.finalize();
            let word = u64::from_be_bytes(digest[..8].try_into().unwrap());
            let j = usize::try_from(word % u64::try_from(i + 1).unwrap()).unwrap();
            expected.swap(i, j);
        }
        let actual: Vec<OutPoint> = plan.inputs().iter().map(|input| input.outpoint).collect();
        assert_eq!(actual, expected, "seed {seed_byte}");
        let first = Sha256::new()
            .chain_update(seed)
            .chain_update(b"yw-btc-chg")
            .finalize()[0]
            & 1
            == 0;
        let change = plan.change().unwrap();
        assert_eq!(change.vout, u32::from(!first), "seed {seed_byte}");
        assert_eq!(plan.recipient_vout(), 1 - change.vout);
    }
}

/// A change script equal to the recipient script moves the change to `change_next + 1`.
#[test]
fn change_skips_recipient_script() {
    let account = account();
    let program =
        yw_core::btc::address::p2wpkh_program(account.xpub().unwrap(), BtcChain::Change, 3)
            .unwrap();
    let to_change = plan(
        &[utxo(50_000, TIP - 1, 1, 0)],
        ScriptKind::P2wpkh(program),
        exact(20_000),
        rate(1),
        SEED,
    )
    .unwrap();
    assert_eq!(to_change.change().unwrap().index, 4);
}

/// spec/08 §14.2 `change_fold_below_294`.
#[test]
fn change_fold_below_294() {
    let single = [utxo(25_000, TIP - 1, 2, 0)];
    let folded = plan(&single, RECIPIENT, exact(24_566), rate(1), SEED).unwrap();
    check_fixed(&folded);
    assert_eq!(folded.change(), None);
    assert_eq!(folded.fee(), sats(434));
    assert_eq!(folded.change_folded(), sats(324));
    assert_eq!(folded.planned_vsize(), 110);
    let draft = build_btc_request(
        Lang::Ko,
        ApprovalId([1; 16]),
        &folded,
        &account(),
        &BtcSendFacts::default(),
    )
    .unwrap();
    let change_field = draft
        .display
        .fields
        .iter()
        .find(|field| field.key == FieldKey::BTC_CHANGE)
        .unwrap();
    assert_eq!(change_field.value, "잔돈 없음: 324 sats 수수료에 추가");
    let kept = plan(&single, RECIPIENT, exact(24_565), rate(1), SEED).unwrap();
    check_fixed(&kept);
    assert_eq!(kept.change().unwrap().value, sats(294));
    assert_eq!(kept.fee(), sats(141));
    assert_eq!(kept.change_folded(), Sats::ZERO);
    // Exactly enough without change: everything above the amount is fee.
    let exact_fit = plan(&single, RECIPIENT, exact(24_890), rate(1), SEED).unwrap();
    assert_eq!(exact_fit.fee(), sats(110));
    assert_eq!(exact_fit.change_folded(), Sats::ZERO);
    assert!(plan(&single, RECIPIENT, exact(24_891), rate(1), SEED).is_err());
}

/// spec/08 §14.2 `send_max_dust` (§7.6).
#[test]
fn send_max_dust() {
    assert_eq!(
        plan(
            &[utxo(403, TIP - 1, 1, 0)],
            RECIPIENT,
            SendAmount::Max,
            rate(1),
            SEED
        ),
        Err(PlanError::DustAmount {
            threshold: sats(294)
        })
    );
    let minimal = plan(
        &[utxo(404, TIP - 1, 1, 0)],
        RECIPIENT,
        SendAmount::Max,
        rate(1),
        SEED,
    )
    .unwrap();
    check_fixed(&minimal);
    assert!(minimal.send_max());
    assert_eq!(minimal.amount(), sats(294));
    assert_eq!(minimal.fee(), sats(110));
    assert_eq!(
        plan(
            &[utxo(100, TIP - 1, 1, 0)],
            RECIPIENT,
            SendAmount::Max,
            rate(1),
            SEED
        ),
        Err(PlanError::DustAmount {
            threshold: sats(294)
        })
    );
    assert_eq!(
        PlanError::DustAmount {
            threshold: sats(294)
        }
        .to_string(),
        "받는 금액이 최소값(294 sats) 미만입니다"
    );
    assert_eq!(
        plan(&[], RECIPIENT, SendAmount::Max, rate(1), SEED),
        Err(PlanError::InsufficientFunds {
            available: Sats::ZERO,
            needed: sats(404),
        })
    );
    // More than 100 candidates: the 100 largest, the rest reported (B06).
    let mut many: Vec<Utxo> = (0..100_u8)
        .map(|tag| utxo(1_000, TIP - 1, tag, 0))
        .collect();
    many.push(utxo(999, TIP - 1, 200, 0));
    let max = plan(&many, RECIPIENT, SendAmount::Max, rate(1), SEED).unwrap();
    check_fixed(&max);
    assert_eq!(max.inputs().len(), 100);
    assert!(!outpoints(&max).contains(&op(200, 0)));
    assert_eq!(max.excluded_utxos(), 1);
    assert_eq!(max.fee(), sats(6_817));
    assert_eq!(max.amount(), sats(100_000 - 6_817));
    let draft = build_btc_request(
        Lang::Ko,
        ApprovalId([2; 16]),
        &max,
        &account(),
        &BtcSendFacts::default(),
    )
    .unwrap();
    assert!(
        draft
            .display
            .warnings
            .iter()
            .any(|w| w.rule == B06 && w.text == "UTXO 1개는 포함되지 않음(입력 최대 100개)")
    );
}

/// spec/08 §14.2 `recipient_dust_by_type`: 546 / 540 / 294 / 330 / 330.
#[test]
fn recipient_dust_by_type() {
    let thresholds = [546_u64, 540, 294, 330, 330];
    let candidates = [utxo(100_000, TIP - 1, 1, 0)];
    for (kind, threshold) in kinds().into_iter().zip(thresholds) {
        assert_eq!(
            plan(&candidates, kind, exact(threshold - 1), rate(1), SEED),
            Err(PlanError::DustAmount {
                threshold: sats(threshold)
            }),
            "{kind:?}"
        );
        let ok = plan(&candidates, kind, exact(threshold), rate(1), SEED).unwrap();
        check_fixed(&ok);
        assert_eq!(ok.recipient(), kind);
    }
    assert!(matches!(
        plan(&candidates, RECIPIENT, exact(0), rate(1), SEED),
        Err(PlanError::DustAmount { .. })
    ));
}

fn bump(
    source: &BumpSource,
    fee: FeeChoice,
    incremental: Option<FeeRate>,
    extras: &[Utxo],
) -> Result<SendPlan, PlanError> {
    let account = account();
    plan_fee_bump(&BumpRequest {
        source,
        account: &account,
        fee,
        incremental,
        candidates: extras,
        tip_height: TIP + 3,
        change_next: 7,
        layout_seed: [0x77; 32],
        typed_fee_override: None,
    })
}

fn source_of(plan: &SendPlan) -> BumpSource {
    record(plan, BtcTxState::Submitted, 1_000)
        .bump_source(&account())
        .unwrap()
}

/// spec/08 §14.2 `rbf_rules` (§9): fee increase rules, same recipient, change index kept or
/// dropped, inputs added with a new change index, send-max decrease (B06) and its dust limit,
/// new layout and lock time.
#[test]
#[expect(clippy::too_many_lines, reason = "one block per spec/08 §9 rule")]
fn rbf_rules() {
    let original = plan(
        &[utxo(25_000, TIP - 1, 2, 0)],
        RECIPIENT,
        exact(20_000),
        rate(1),
        SEED,
    )
    .unwrap();
    let source = source_of(&original);
    assert_eq!(source.txid, original.txid());
    assert_eq!((source.fee, source.vsize), (sats(141), 141));
    assert_eq!(source.change_index, Some(3));
    // Same rate: the BIP125 minimum applies (old fee + incremental × new vsize).
    let same = bump(&source, rate(1), None, &[]).unwrap();
    check_fixed(&same);
    assert_eq!(same.kind(), ApprovalKind::BtcFeeBump);
    assert_eq!(same.replaces(), Some(original.txid()));
    assert_eq!(same.fee(), sats(282));
    assert!(same.bump().unwrap().min_applied);
    assert_eq!(same.amount(), original.amount());
    assert_eq!(same.recipient(), original.recipient());
    assert_eq!(same.change().unwrap().index, 3);
    assert_eq!(same.change().unwrap().value, sats(4_718));
    assert_eq!(same.lock_time(), TIP + 3);
    assert_eq!(outpoints(&same), outpoints(&original));
    assert_eq!(same.new_input_total(), Sats::ZERO);
    assert!(!same.recipient_decreased());
    assert!(bump_fee_ok(sats(141), 141, same.fee(), 141, None));
    assert!(!bump_fee_ok(sats(141), 141, sats(281), 141, None));
    assert!(!bump_fee_ok(
        sats(141),
        141,
        sats(141),
        141,
        Some(FeeRate::from_sat_per_kvb(0))
    ));
    // A higher rate: no minimum needed.
    let faster = bump(&source, rate(5), None, &[]).unwrap();
    assert_eq!(faster.fee(), sats(705));
    assert!(!faster.bump().unwrap().min_applied);
    // Core 31 incrementalrelayfee 100 sat/kvB: old + ceil(0.1 × 141) = 156 (> strictly higher
    // rate minimum 142).
    let core31 = bump(&source, rate(1), Some(FeeRate::from_sat_per_kvb(100)), &[]).unwrap();
    assert_eq!(core31.fee(), sats(156));
    assert!(bump_fee_ok(
        sats(141),
        141,
        core31.fee(),
        141,
        Some(FeeRate::from_sat_per_kvb(100))
    ));
    // Change below 294 after the increase: dropped and added to the fee.
    let small_change = plan(
        &[utxo(20_700, TIP - 1, 2, 0)],
        RECIPIENT,
        exact(20_000),
        rate(1),
        SEED,
    )
    .unwrap();
    assert_eq!(small_change.change().unwrap().value, sats(559));
    let dropped = bump(&source_of(&small_change), rate(3), None, &[]).unwrap();
    check_fixed(&dropped);
    assert_eq!(dropped.change(), None);
    assert_eq!(dropped.fee(), sats(700));
    assert_eq!(dropped.change_folded(), sats(370));
    // No change and not enough: an extra input (largest first) and change at change_next.
    let no_change = plan(
        &[utxo(20_300, TIP - 1, 2, 0)],
        RECIPIENT,
        exact(20_000),
        rate(1),
        SEED,
    )
    .unwrap();
    assert_eq!((no_change.change(), no_change.fee()), (None, sats(300)));
    let extras = [utxo(5_000, TIP - 1, 9, 0), utxo(50_000, TIP - 1, 8, 0)];
    let added = bump(&source_of(&no_change), rate(10), None, &extras).unwrap();
    check_fixed(&added);
    assert_eq!(outpoints(&added), vec![op(2, 0), op(8, 0)]);
    assert_eq!(added.fee(), sats(2_080));
    assert_eq!(added.change().unwrap().index, 7);
    assert_eq!(added.change().unwrap().value, sats(48_220));
    assert_eq!(added.new_input_total(), sats(50_000));
    assert_eq!(
        bump(&source_of(&no_change), rate(10), None, &[]),
        Err(PlanError::InsufficientFunds {
            available: sats(20_300),
            needed: sats(21_100),
        })
    );
    // A candidate that is already an input of the source is not added twice.
    let reused = [utxo(20_300, TIP - 1, 2, 0)];
    assert!(bump(&source_of(&no_change), rate(10), None, &reused).is_err());
    // Send-max: the recipient amount drops by the fee increase (B06), down to dust.
    let max = plan(
        &[utxo(30_000, TIP - 1, 3, 0), utxo(20_000, TIP - 1, 4, 0)],
        RECIPIENT,
        SendAmount::Max,
        rate(1),
        SEED,
    )
    .unwrap();
    assert_eq!((max.fee(), max.amount()), (sats(177), sats(49_823)));
    let reduced = bump(&source_of(&max), rate(2), None, &[]).unwrap();
    check_fixed(&reduced);
    assert!(reduced.send_max() && reduced.recipient_decreased());
    assert_eq!((reduced.fee(), reduced.amount()), (sats(354), sats(49_646)));
    let draft = build_btc_request(
        Lang::Ko,
        ApprovalId([3; 16]),
        &reduced,
        &account(),
        &BtcSendFacts::default(),
    )
    .unwrap();
    assert_eq!(draft.display.title, "[Bitcoin testnet4] 수수료 올리기");
    assert!(
        draft
            .display
            .warnings
            .iter()
            .any(|w| w.rule == B06 && w.text == texts::RECIPIENT_DECREASED.get(Lang::Ko))
    );
    let replaces = draft
        .display
        .fields
        .iter()
        .find(|field| field.key == FieldKey::BTC_REPLACES)
        .unwrap();
    assert_eq!(
        replaces.value,
        format!(
            "교체 대상 {}\n수수료 177 → 354 sats (+177)\n수신 금액 감소(B06): 49,823 → 49,646 sats",
            max.txid()
        )
    );
    let tiny = plan(
        &[utxo(600, TIP - 1, 3, 0)],
        RECIPIENT,
        SendAmount::Max,
        rate(1),
        SEED,
    )
    .unwrap();
    assert_eq!(tiny.amount(), sats(490));
    assert_eq!(
        bump(&source_of(&tiny), rate(2), None, &[])
            .unwrap()
            .amount(),
        sats(380)
    );
    assert_eq!(
        bump(&source_of(&tiny), rate(3), None, &[]),
        Err(PlanError::DustAmount {
            threshold: sats(294)
        })
    );
    // Only bumpable states with keys of this account.
    let mut confirmed = record(&original, BtcTxState::Confirmed, 1_000);
    assert!(confirmed.bump_source(&account()).is_none());
    confirmed.state = BtcTxState::InMempool;
    confirmed.confirmed_height = None;
    assert!(confirmed.bump_source(&account()).is_some());
    confirmed.inputs[0].index += 1;
    assert!(
        confirmed.bump_source(&account()).is_none(),
        "path ≠ witness key"
    );
    // The bump approval: 0x0609 after the balance, payload with replaces.
    let draft = build_btc_request(
        Lang::Ko,
        ApprovalId([4; 16]),
        &same,
        &account(),
        &BtcSendFacts::default(),
    )
    .unwrap();
    assert_eq!(draft.kind, ApprovalKind::BtcFeeBump);
    let keys: Vec<u16> = draft
        .display
        .fields
        .iter()
        .map(|field| field.key.0)
        .collect();
    assert_eq!(
        keys,
        vec![
            0x0001, 0x0002, 0x0003, 0x0601, 0x0602, 0x0603, 0x0604, 0x0605, 0x0606, 0x0607, 0x0608,
            0x0609, 0x0640
        ]
    );
    let replaces = draft
        .display
        .fields
        .iter()
        .find(|field| field.key == FieldKey::BTC_REPLACES)
        .unwrap();
    assert_eq!(
        replaces.value,
        format!(
            "교체 대상 {}\n수수료 141 → 282 sats (+141)\n수신자 변경 없음\n교체 최소 수수료(BIP125)를 적용함",
            original.txid()
        )
    );
    let payload = btc_payload(&same);
    assert_eq!(draft.payload, SigningPayload::Btc(payload.clone()));
    assert_eq!(
        payload_header(&payload).map(|header| (header.network, header.has_replaces)),
        Some((2, true))
    );
}

fn be32(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

/// spec/08 §10 `btc_payload` byte layout, rebuilt independently.
#[test]
fn payload_byte_layout() {
    let send = simple_plan(2, 20_000);
    let unsigned = serialize(send.tx(), false);
    let mut expected = vec![2_u8];
    expected.extend_from_slice(&be32(u32::try_from(unsigned.len()).unwrap()));
    expected.extend_from_slice(&unsigned);
    expected.extend_from_slice(&1_u16.to_be_bytes());
    expected.extend_from_slice(&100_000_u64.to_be_bytes());
    expected.push(0);
    expected.extend_from_slice(&be32(2));
    let change = send.change().unwrap();
    expected.push(1);
    expected.extend_from_slice(&be32(change.vout));
    expected.extend_from_slice(&be32(3));
    expected.extend_from_slice(&141_u64.to_be_bytes());
    expected.extend_from_slice(&be32(141));
    expected.push(0);
    expected.push(0);
    assert_eq!(btc_payload(&send), expected);
    assert_eq!(
        payload_header(&expected).map(|header| (header.network, header.has_replaces)),
        Some((2, false))
    );
    for cut in 0..expected.len() {
        assert_eq!(payload_header(&expected[..cut]), None, "cut {cut}");
    }
    let mut trailing = expected.clone();
    trailing.push(0);
    assert_eq!(payload_header(&trailing), None);
    let mut bad_flag = expected.clone();
    let last = bad_flag.len() - 1;
    bad_flag[last] = 2;
    assert_eq!(payload_header(&bad_flag), None);

    let bumped = bump(&source_of(&send), rate(1), None, &[]).unwrap();
    let payload = btc_payload(&bumped);
    let tail = &payload[payload.len() - 34..];
    assert_eq!(tail[0], 1);
    assert_eq!(&tail[1..33], send.txid().as_bytes());
    assert_eq!(tail[33], 0);
}

fn field(draft: &yw_core::approval::ApprovalDraft, key: FieldKey) -> String {
    draft
        .display
        .fields
        .iter()
        .find(|field| field.key == key)
        .map(|field| field.value.clone())
        .unwrap()
}

/// spec/08 §10 field texts and warnings B05/B07/B08.
#[test]
#[expect(clippy::too_many_lines, reason = "every spec/08 §10 field")]
fn display_fields_and_warnings() {
    let send = simple_plan(2, 20_000);
    let facts = BtcSendFacts {
        verified_balance: sats(100_000),
        min_confirmations: Some(3),
        first_time_recipient: true,
        own_recipient: None,
    };
    let draft =
        build_btc_request(Lang::Ko, ApprovalId([6; 16]), &send, &account(), &facts).unwrap();
    assert_eq!(
        draft.display.title,
        "[Bitcoin testnet4] 보내기: 0.00020000 BTC"
    );
    assert_eq!(field(&draft, FieldKey::ORIGIN), "Your Wallet 앱");
    assert_eq!(
        field(&draft, FieldKey::NETWORK),
        "BITCOIN TESTNET4 — 가치 없음"
    );
    assert_eq!(
        field(&draft, FieldKey::ACCOUNT),
        "Bitcoin 네이티브 세그윗 계정 0 (m/84'/1'/0')"
    );
    assert_eq!(
        field(&draft, FieldKey::BTC_TO),
        encode_address(&RECIPIENT, NET)
    );
    assert_eq!(field(&draft, FieldKey::BTC_TYPE), "P2WPKH");
    assert_eq!(
        field(&draft, FieldKey::BTC_AMOUNT),
        "0.00020000 BTC (20,000 sats)"
    );
    assert_eq!(
        field(&draft, FieldKey::BTC_CHANGE),
        "0.00079859 BTC — 이 지갑으로 돌아옴 m/84'/1'/0'/1/3"
    );
    assert_eq!(
        field(&draft, FieldKey::BTC_INPUTS),
        "1개, 합계 0.00100000 BTC (100,000 sats)\n모든 입력 금액은 이전 거래 해시로 검증됨\n최소 확인 수 3 (서버 기준)"
    );
    assert_eq!(
        field(&draft, FieldKey::BTC_FEE),
        "0.00000141 BTC (141 sats)\n1 sat/vB (계획 vsize 141 vB 기준, 서명 후 실제 값은 같거나 높음)\n보내는 금액의 0.71%\n출처: 직접 입력"
    );
    assert_eq!(
        field(&draft, FieldKey::BTC_TOTAL),
        "0.00020141 BTC (20,141 sats)"
    );
    assert_eq!(
        field(&draft, FieldKey::BTC_BALANCE),
        "0.00079859 BTC (79,859 sats) (검증 잔액 0.00100000 BTC 기준)"
    );
    assert_eq!(
        field(&draft, FieldKey::BTC_ADVANCED),
        format!(
            "version 2\nnLockTime 200000 (= 블록 높이 200000)\nRBF 가능 (sequence 0xFFFFFFFD)\n입력 형식 P2WPKH\nvsize 141 vB · weight 561 WU (서명 전 추정)\ntxid {}",
            send.txid()
        )
    );
    let rules: Vec<_> = draft.display.warnings.iter().map(|w| w.rule).collect();
    assert_eq!(rules, vec![B05]);
    assert_eq!(draft.display.risk, RiskLevel::Caution);
    assert!(!draft.display.ack_required);
    // Own address (B07, info) and recipient kinds (B08).
    let own = BtcSendFacts {
        own_recipient: Some((BtcChain::Receive, 4)),
        ..BtcSendFacts::default()
    };
    let draft = build_btc_request(Lang::Ko, ApprovalId([7; 16]), &send, &account(), &own).unwrap();
    assert_eq!(draft.display.warnings[0].rule, B07);
    assert_eq!(
        draft.display.warnings[0].text,
        "이 지갑의 주소입니다 (m/84'/1'/0'/0/4)"
    );
    assert_eq!(draft.display.risk, RiskLevel::Info);
    let candidates = [utxo(100_000, TIP - 1, 2, 0)];
    let [legacy, script_hash, _, witness_script, taproot] = kinds();
    for (kind, text, label) in [
        (
            legacy,
            Some(texts::LEGACY_RECIPIENT.get(Lang::Ko)),
            "P2PKH(레거시)",
        ),
        (
            script_hash,
            Some(texts::SCRIPT_RECIPIENT.get(Lang::Ko)),
            "P2SH(스크립트)",
        ),
        (
            witness_script,
            Some(texts::SCRIPT_RECIPIENT.get(Lang::Ko)),
            "P2WSH(스크립트)",
        ),
        (taproot, None, "P2TR"),
    ] {
        let plan = plan(&candidates, kind, exact(20_000), rate(1), SEED).unwrap();
        let draft = build_btc_request(
            Lang::Ko,
            ApprovalId([8; 16]),
            &plan,
            &account(),
            &BtcSendFacts::default(),
        )
        .unwrap();
        let b08: Vec<&str> = draft
            .display
            .warnings
            .iter()
            .filter(|w| w.rule == B08)
            .map(|w| w.text.as_str())
            .collect();
        assert_eq!(b08, text.into_iter().collect::<Vec<_>>());
        assert_eq!(field(&draft, FieldKey::BTC_TYPE), label);
        assert_eq!(field(&draft, FieldKey::BTC_TO), encode_address(&kind, NET));
    }
    // Mainnet titles and account path.
    let mut mainnet_source = source_of(&send);
    mainnet_source.network = yw_core::btc::BtcNetwork::Mainnet;
    let mainnet = bump(&mainnet_source, rate(1), None, &[]).unwrap();
    let draft = build_btc_request(
        Lang::Ko,
        ApprovalId([9; 16]),
        &mainnet,
        &account(),
        &BtcSendFacts::default(),
    )
    .unwrap();
    assert_eq!(draft.display.title, "[Bitcoin 메인넷] 수수료 올리기");
    assert_eq!(field(&draft, FieldKey::NETWORK), "BITCOIN MAINNET");
    assert_eq!(
        field(&draft, FieldKey::ACCOUNT),
        "Bitcoin 네이티브 세그윗 계정 0 (m/84'/0'/0')"
    );
}

/// spec/14: a send-max fee bump (B06, field `0x0609`) and the send it replaces, built in English
/// with every fact set (B05, B07): no Hangul in the title, any field or any warning, and the same
/// fields and rules as the Korean draft.
#[test]
fn english_send_and_bump_display() {
    use yw_core::lang::has_hangul;
    let max = plan(
        &[utxo(30_000, TIP - 1, 3, 0), utxo(20_000, TIP - 1, 4, 0)],
        RECIPIENT,
        SendAmount::Max,
        rate(1),
        SEED,
    )
    .unwrap();
    let reduced = bump(&source_of(&max), rate(2), None, &[]).unwrap();
    let facts = BtcSendFacts {
        verified_balance: sats(50_000),
        min_confirmations: Some(3),
        first_time_recipient: true,
        own_recipient: Some((BtcChain::Change, 4)),
    };
    for plan in [&max, &reduced] {
        let build = |lang| build_btc_request(lang, ApprovalId([9; 16]), plan, &account(), &facts);
        let (en, ko) = (build(Lang::En).unwrap(), build(Lang::Ko).unwrap());
        assert_eq!((en.display.lang, ko.display.lang), (Lang::En, Lang::Ko));
        assert!(!has_hangul(&en.display.title), "{}", en.display.title);
        for field in &en.display.fields {
            assert!(!has_hangul(&field.value), "{:?}", field.value);
            assert!(!has_hangul(&field.sub_label), "{:?}", field.sub_label);
        }
        for warning in &en.display.warnings {
            assert!(!has_hangul(&warning.text), "{:?}", warning.text);
        }
        let keys = |draft: &yw_core::approval::ApprovalDraft| {
            let fields: Vec<_> = draft.display.fields.iter().map(|f| f.key).collect();
            let rules: Vec<_> = draft.display.warnings.iter().map(|w| w.rule).collect();
            (fields, rules)
        };
        assert_eq!(keys(&en), keys(&ko));
        assert!(
            en.display
                .fields
                .iter()
                .any(|f| f.key == FieldKey::BTC_BALANCE)
        );
    }
    let bump_title = build_btc_request(Lang::En, ApprovalId([9; 16]), &reduced, &account(), &facts)
        .unwrap()
        .display
        .title;
    assert_eq!(bump_title, "[Bitcoin testnet4] Bump fee");
}
