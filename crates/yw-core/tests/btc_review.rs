//! Review fixes of the BTC send path (public API): txid uniqueness and entry-keyed transitions
//! (H1), the abandon rule (M1: indexer-unconfirmed counts as "in a mempool", the next send must
//! conflict with a live abandoned transaction), the lock-time / tip bounds (M2), discovery and
//! issuance caps, the RBF minimum under Core's truncated rates, reorgs of shallow confirmations,
//! the end of a replacement chain that was abandoned, the bump target by journal order, the
//! persisted communication-failure flag and the change index of a rejected send.
#![allow(
    clippy::unwrap_used,
    reason = "fixture helpers outside #[test] functions panic on broken fixtures"
)]

mod btc_common;

use btc_common::{NET, RECIPIENT, SEED, TIP, account, rate, record, simple_plan, utxo, xpub};
use yw_core::btc::amount::Sats;
use yw_core::btc::fee::FeeRate;
use yw_core::btc::meta::{BtcMeta, Discovery, MetaError};
use yw_core::btc::select::{
    PlanError, SendAmount, SendPlan, SendRequest, Utxo, bump_fee_ok, plan_send,
};
use yw_core::btc::tx::{OutPoint, Txid};
use yw_core::btc::{BTC_DISCOVERY_MAX_SCAN, BTC_LOCKTIME_THRESHOLD, BTC_MAX_ADDRESS_INDEX};
use yw_core::journal::btc::{
    BTC_ABANDON_WINDOW_SECS, BtcEntries, BtcPushError, BtcRecord, BtcTxState, TrackObservation,
    TransitionError, abandoned_conflicts, apply_observation, bump_target,
    check_abandoned_conflicts, check_can_send, current_record, finished_rows, in_flight_outpoints,
    is_finished, push_record, refresh_keep_outpoints, set_last_send_comm_failure, set_state,
    set_state_entry, take_finished_duplicates,
};
use yw_core::journal::{Entry, EntryKind, JournalPlain};

fn op(tag: u8) -> OutPoint {
    OutPoint {
        txid: Txid::from_bytes([tag; 32]),
        vout: 0,
    }
}

fn records_of(journal: &JournalPlain) -> Vec<BtcRecord> {
    BtcEntries::from_plain(journal).records()
}

fn with_id(mut record: BtcRecord, id: u8) -> BtcRecord {
    record.entry_id = [id; 16];
    record
}

/// A journal written before the uniqueness rule: the entries are added without the check.
fn legacy_plain(records: &[BtcRecord]) -> JournalPlain {
    let mut journal = JournalPlain::default();
    for record in records {
        journal.entries.push(Entry {
            kind: EntryKind::Btc,
            body: record.encode().unwrap(),
        });
    }
    journal
}

fn send_request<'a>(
    candidates: &'a [Utxo],
    amount: SendAmount,
    conflicts: &'a [Vec<OutPoint>],
    tip_height: u32,
    change_next: u32,
    account: &'a yw_core::btc::account::BtcAccountKey,
) -> SendRequest<'a> {
    SendRequest {
        network: NET,
        account,
        recipient: RECIPIENT,
        amount,
        fee: rate(1),
        candidates,
        tip_height,
        change_next,
        layout_seed: SEED,
        typed_fee_override: None,
        conflicts,
    }
}

fn spent(plan: &SendPlan) -> Vec<OutPoint> {
    let mut out: Vec<OutPoint> = plan.inputs().iter().map(|input| input.outpoint).collect();
    out.sort_by_key(|outpoint| outpoint.txid.to_bytes());
    out
}

/// H1: signing the same transaction again (same txid) after a finished record moves the old
/// record to activity and replaces it; a tracked one refuses the new record; transitions address
/// the current record (also in a journal that already holds both).
#[test]
fn resigned_identical_transaction() {
    let plan = simple_plan(2, 20_000);
    let txid = plan.txid();
    let old = with_id(record(&plan, BtcTxState::Rejected, 1), 1);
    let new = with_id(record(&plan, BtcTxState::Signed, 5), 2);
    let mut journal = JournalPlain::default();
    push_record(&mut journal, &old).unwrap();
    assert_eq!(
        push_record(&mut journal, &new),
        Err(BtcPushError::Duplicate)
    );
    let rows =
        take_finished_duplicates(yw_core::lang::Lang::Ko, &mut journal, &new, TIP, 10, 99).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, "rejected");
    assert_eq!(rows[0].tx_id, txid.to_display_hex());
    push_record(&mut journal, &new).unwrap();
    assert_eq!(records_of(&journal).len(), 1);
    assert_eq!(
        set_state(&mut journal, NET, &txid, BtcTxState::Broadcasting, 11)
            .unwrap()
            .changed,
        vec![(txid, BtcTxState::Broadcasting)]
    );
    // A tracked record with the same txid refuses the new one; nothing changes.
    let tracked = journal.clone();
    let again = with_id(record(&plan, BtcTxState::Signed, 6), 3);
    let mut trial = tracked.clone();
    assert_eq!(
        take_finished_duplicates(yw_core::lang::Lang::Ko, &mut trial, &again, TIP, 12, 99),
        Err(BtcPushError::Duplicate)
    );
    assert_eq!(trial, tracked);

    // A journal written before the rule: the finished old record and a later `Signed` one.
    let mut legacy = legacy_plain(&[old.clone(), new.clone()]);
    let records = records_of(&legacy);
    assert_eq!(
        current_record(&records, NET, &txid).unwrap().entry_id,
        [2; 16]
    );
    assert_eq!(check_can_send(&records, NET), Err(PlanError::InFlight));
    // The transition reaches the `Signed` record (it used to hit the `Rejected` one and stay
    // stuck, blocking every send).
    set_state(&mut legacy, NET, &txid, BtcTxState::Broadcasting, 20).unwrap();
    set_state_entry(&mut legacy, NET, &[2; 16], BtcTxState::Submitted, 21).unwrap();
    let records = records_of(&legacy);
    assert_eq!(records[0].state, BtcTxState::Rejected);
    assert_eq!(records[1].state, BtcTxState::Submitted);
    apply_observation(
        &mut legacy,
        NET,
        &txid,
        TrackObservation::Confirmed { height: TIP },
        TIP,
        22,
    )
    .unwrap();
    let records = records_of(&legacy);
    assert_eq!(records[1].state, BtcTxState::Confirmed);
    assert_eq!(check_can_send(&records, NET), Ok(()));
    // Only the current record produces the activity row of the txid.
    let rows = finished_rows(yw_core::lang::Lang::Ko, &legacy, NET, TIP + 10, 30, 1);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, "succeeded");
    assert_eq!(
        set_state_entry(&mut legacy, NET, &[9; 16], BtcTxState::Abandoned, 23),
        Err(TransitionError::UnknownTx)
    );
    // An abandoned transaction signed again byte for byte is superseded (same transaction).
    let mut abandoned = with_id(record(&plan, BtcTxState::Abandoned, 1), 1);
    abandoned.not_found_count = 10;
    let mut journal = legacy_plain(&[abandoned]);
    let rows =
        take_finished_duplicates(yw_core::lang::Lang::Ko, &mut journal, &new, TIP, 10, 99).unwrap();
    assert_eq!(rows[0].status, "abandoned");
    push_record(&mut journal, &new).unwrap();
    assert_eq!(records_of(&journal).len(), 1);
}

/// W-ADDR-3 for Bitcoin: equal leading plus trailing characters after the fixed prefix total at
/// least 5, in any split (the bold `bc1q`+2 … last 6 included).
#[test]
fn look_alike_addresses() {
    use yw_core::btc::address::{is_look_alike, look_alike_ends};
    let a = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    assert!(is_look_alike(
        a,
        "tb1qw508zzqejxtdg4y5r3zarvary0c5xw7kxpjzsx"
    ));
    assert!(is_look_alike(
        a,
        "TB1QW508ZZQEJXTDG4Y5R3ZARVARY0C5XW7KXPJZSX"
    ));
    assert!(!is_look_alike(a, a), "the same address");
    // Any split of 5: 2+3, 0+5 (only the tail), 5+0 (only the head).
    assert_eq!(
        look_alike_ends(a, "tb1qw5z8d6qejxtdg4y5r3zarvary0c5xw7kxpqzsx"),
        Some((2, 3))
    );
    assert_eq!(
        look_alike_ends(a, "tb1qx508d6qejxtdg4y5r3zarvary0c5xw7kqpjzsx"),
        Some((0, 5))
    );
    assert_eq!(
        look_alike_ends(a, "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsy"),
        Some((37, 0))
    );
    // Four in total (2+2) is not flagged.
    assert!(!is_look_alike(
        a,
        "tb1qw5z8d6qejxtdg4y5r3zarvary0c5xw7kxpjqsx"
    ));
    // base58: the version character is the prefix.
    let p2pkh = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn";
    assert!(is_look_alike(p2pkh, "mipcBzzzzzzzzzzzzzzzzzzzzzzzzZJRfn"));
    assert!(!is_look_alike(p2pkh, "mipzBbFg9gMiCh81Kj8tqqdgoZub1ZJRzn"));
    assert!(!is_look_alike("bc1q", "bc1q"));
    assert!(!is_look_alike("tb1qabc", "tb1qabd"), "too short");
}

/// The bump target is the last bumpable record in journal order, not the newest wall-clock
/// `created_at` (the clock may go backwards).
#[test]
fn bump_target_follows_journal_order() {
    let first = simple_plan(2, 20_000);
    let second = simple_plan(3, 20_000);
    let records = vec![
        record(&first, BtcTxState::InMempool, 500),
        record(&second, BtcTxState::BroadcastUnknown, 100),
    ];
    assert_eq!(
        bump_target(&records, NET).map(|record| record.txid),
        Some(second.txid())
    );
}

/// M1: the next send must spend an input of a live abandoned transaction; the planner forces
/// one, the pre-sign check refuses a plan without; a confirmation of either side conflicts the
/// other.
#[test]
#[expect(clippy::too_many_lines, reason = "the whole abandon flow")]
fn abandoned_transaction_must_be_conflicted() {
    let account = account();
    let abandoned_plan = simple_plan(1, 20_000);
    let mut abandoned = record(&abandoned_plan, BtcTxState::Abandoned, 1_000);
    // [취소] of a never-sent `Signed` record: nothing to conflict with.
    assert!(abandoned_conflicts(&[abandoned.clone()], NET, 1_000).is_empty());
    // [포기] of a `BroadcastUnknown` record (10 not-found rounds): live for 30 days.
    abandoned.not_found_count = 10;
    let records = vec![abandoned.clone()];
    assert_eq!(abandoned_conflicts(&records, NET, 1_000), vec![vec![op(1)]]);
    assert!(
        abandoned_conflicts(&records, NET, 1_001 + BTC_ABANDON_WINDOW_SECS).is_empty(),
        "window over"
    );
    // Its inputs stay in `verified` although the indexer hides them, and stay spendable.
    assert_eq!(refresh_keep_outpoints(&records, NET, 1_000), vec![op(1)]);
    assert!(in_flight_outpoints(&records, NET).is_empty());
    // The planner spends one of them first.
    let candidates = [
        utxo(100_000, TIP - 10, 1, 0),
        utxo(50_000, TIP - 10, 2, 0),
        utxo(300_000, TIP - 10, 3, 0),
    ];
    let conflicts = abandoned_conflicts(&records, NET, 1_000);
    let free = plan_send(&send_request(
        &candidates,
        SendAmount::Exact(Sats::new(20_000).unwrap()),
        &[],
        TIP,
        3,
        &account,
    ))
    .unwrap();
    assert_eq!(spent(&free), vec![op(2)], "smallest single input otherwise");
    assert_eq!(
        check_abandoned_conflicts(&records, &free, 1_000),
        Err(PlanError::AbandonedNotConflicted)
    );
    let forced = plan_send(&send_request(
        &candidates,
        SendAmount::Exact(Sats::new(20_000).unwrap()),
        &conflicts,
        TIP,
        3,
        &account,
    ))
    .unwrap();
    assert_eq!(spent(&forced), vec![op(1)]);
    assert_eq!(check_abandoned_conflicts(&records, &forced, 1_000), Ok(()));
    // The forced input plus the fewest others by descending value.
    let bigger = plan_send(&send_request(
        &candidates,
        SendAmount::Exact(Sats::new(150_000).unwrap()),
        &conflicts,
        TIP,
        3,
        &account,
    ))
    .unwrap();
    assert_eq!(spent(&bigger), vec![op(1), op(3)]);
    let max = plan_send(&send_request(
        &candidates,
        SendAmount::Max,
        &conflicts,
        TIP,
        3,
        &account,
    ))
    .unwrap();
    assert_eq!(spent(&max), vec![op(1), op(2), op(3)]);
    // No spendable input of the abandoned transaction (frozen, gone): refused.
    assert_eq!(
        plan_send(&send_request(
            &candidates[1..],
            SendAmount::Exact(Sats::new(20_000).unwrap()),
            &conflicts,
            TIP,
            3,
            &account,
        )),
        Err(PlanError::AbandonedNotConflicted)
    );
    // The new send confirms first: the abandoned transaction can never confirm.
    let new = with_id(record(&forced, BtcTxState::Submitted, 2_000), 7);
    let mut journal = legacy_plain(&[with_id(abandoned.clone(), 6), new.clone()]);
    let change = apply_observation(
        &mut journal,
        NET,
        &forced.txid(),
        TrackObservation::Confirmed { height: TIP },
        TIP,
        2_100,
    )
    .unwrap();
    assert!(
        change
            .changed
            .contains(&(forced.txid(), BtcTxState::Confirmed))
    );
    assert!(
        change
            .changed
            .contains(&(abandoned_plan.txid(), BtcTxState::Conflicted))
    );
    let records = records_of(&journal);
    assert!(abandoned_conflicts(&records, NET, 2_100).is_empty());
    assert!(is_finished(&records[0], &records, Some(TIP), 2_100));
    // The abandoned one confirms first (it had propagated): the new send is conflicted.
    let mut journal = legacy_plain(&[with_id(abandoned, 6), new]);
    let change = apply_observation(
        &mut journal,
        NET,
        &abandoned_plan.txid(),
        TrackObservation::Confirmed { height: TIP },
        TIP,
        2_100,
    )
    .unwrap();
    assert!(
        change
            .changed
            .contains(&(forced.txid(), BtcTxState::Conflicted))
    );
    assert_eq!(check_can_send(&records_of(&journal), NET), Ok(()));
}

/// M2: a Core tip at or above 500,000,000 is never a lock time and never stored; a wrong high
/// tip stored earlier can be reset.
#[test]
fn tip_bounds_and_reset() {
    let account = account();
    let candidates = [utxo(100_000, TIP - 10, 1, 0)];
    let request = |tip| {
        plan_send(&send_request(
            &candidates,
            SendAmount::Exact(Sats::new(20_000).unwrap()),
            &[],
            tip,
            3,
            &account,
        ))
    };
    assert!(request(BTC_LOCKTIME_THRESHOLD - 1).is_ok());
    assert_eq!(
        request(BTC_LOCKTIME_THRESHOLD),
        Err(PlanError::TipImplausible)
    );
    let mut meta = BtcMeta::new(NET, *account.xpub().unwrap());
    assert_eq!(
        meta.observe_tip(BTC_LOCKTIME_THRESHOLD),
        Err(MetaError::TipImplausible)
    );
    assert_eq!(meta.max_tip_seen(), 0);
    assert_eq!(meta.observe_tip(4_000_000), Ok(true));
    assert!(matches!(
        meta.observe_tip(TIP),
        Err(MetaError::TipRegression { .. })
    ));
    assert!(meta.reset_max_tip());
    assert!(!meta.reset_max_tip());
    assert_eq!(meta.observe_tip(TIP), Ok(true));
}

/// Discovery of an indexer reporting history everywhere stops after 1,000 addresses per chain;
/// issuance stops at `BTC_MAX_ADDRESS_INDEX`; the change chain too.
#[test]
fn discovery_and_issuance_caps() {
    let mut meta = BtcMeta::new(NET, xpub());
    let mut discovery = Discovery::full();
    let mut requests = 0_u32;
    while discovery.next_request().is_some() {
        discovery.observe(1);
        requests += 1;
        assert!(requests <= 2 * BTC_DISCOVERY_MAX_SCAN, "unbounded");
    }
    assert_eq!(requests, 2 * BTC_DISCOVERY_MAX_SCAN);
    discovery.apply(&mut meta).unwrap();
    assert_eq!(meta.receive_next(), BTC_DISCOVERY_MAX_SCAN);
    assert_eq!(meta.change_next(), BTC_DISCOVERY_MAX_SCAN);
    // "더 찾기" is bounded the same way.
    let mut more = Discovery::more(&meta);
    let mut extra = 0_u32;
    while more.next_request().is_some() {
        more.observe(1);
        extra += 1;
    }
    assert_eq!(extra, 2 * BTC_DISCOVERY_MAX_SCAN);
    // Issuance at the cap.
    // HD mode (issuance; a fixed-address account always shows `/0/0`).
    let mut hd = BtcMeta::new(NET, xpub());
    assert_eq!(hd.set_single_address(false), Ok(true));
    let text = String::from_utf8(yw_json::to_vec(&hd.to_json())).unwrap();
    let capped = text
        .replace(
            "\"receive_next\":0",
            &format!("\"receive_next\":{BTC_MAX_ADDRESS_INDEX}"),
        )
        .replace(
            "\"last_used_receive\":null",
            &format!("\"last_used_receive\":{}", BTC_MAX_ADDRESS_INDEX - 1),
        );
    assert_ne!(capped, text);
    let value = yw_json::parse(capped.as_bytes(), &yw_json::Limits::RESPONSE).unwrap();
    let mut full = BtcMeta::from_json(&value).unwrap();
    assert_eq!(full.receive_address(), Err(MetaError::IndexExhausted));
    assert_eq!(
        full.on_broadcasting(Some(BTC_MAX_ADDRESS_INDEX)),
        Err(MetaError::IndexExhausted)
    );
    assert!(
        full.watch_set().unwrap().len() <= usize::try_from(BTC_MAX_ADDRESS_INDEX).unwrap(),
        "watch set bounded"
    );
    // A plan needing change at the cap is refused.
    let account = account();
    let candidates = [utxo(100_000, TIP - 10, 1, 0)];
    assert_eq!(
        plan_send(&send_request(
            &candidates,
            SendAmount::Exact(Sats::new(20_000).unwrap()),
            &[],
            TIP,
            BTC_MAX_ADDRESS_INDEX,
            &account,
        )),
        Err(PlanError::ChangeIndexExhausted)
    );
}

/// The RBF minimum also holds after Core truncates both rates to sat/kvB.
#[test]
fn bump_minimum_under_truncated_rates() {
    let zero = Some(FeeRate::from_sat_per_kvb(0));
    let old = Sats::new(1_000).unwrap();
    // 1000 / 141 vB = 7092.19 sat/kvB; 14,185 / 2,000 vB = 7092.5: higher exactly, equal
    // after truncation (Core refuses it).
    assert!(!bump_fee_ok(
        old,
        141,
        Sats::new(14_185).unwrap(),
        2_000,
        zero
    ));
    assert!(bump_fee_ok(
        old,
        141,
        Sats::new(14_186).unwrap(),
        2_000,
        zero
    ));
}

/// The core transition table for a `Confirmed` record that is observed back in the mempool or
/// missing (kept for completeness): in flight again, or `BroadcastUnknown` after 10 rounds.
/// Tracking never feeds a `Confirmed` record any more — one confirmation is final and its
/// tracking ends (spec.md D32) — so the app does not reach this path.
#[test]
fn reorg_of_a_shallow_confirmation() {
    let plan = simple_plan(2, 20_000);
    let txid = plan.txid();
    let mut journal = legacy_plain(&[record(&plan, BtcTxState::Confirmed, 1)]);
    let records = records_of(&journal);
    let change = records[0].change_outpoint().unwrap();
    assert!(!in_flight_outpoints(&records, NET).contains(&change));
    let moved = apply_observation(
        &mut journal,
        NET,
        &txid,
        TrackObservation::InMempool,
        TIP,
        5,
    )
    .unwrap();
    assert_eq!(moved.changed, vec![(txid, BtcTxState::InMempool)]);
    let records = records_of(&journal);
    assert_eq!(records[0].confirmed_height, None);
    assert!(in_flight_outpoints(&records, NET).contains(&change));
    assert_eq!(check_can_send(&records, NET), Err(PlanError::InFlight));
    // Confirmed again, then gone for 10 rounds.
    apply_observation(
        &mut journal,
        NET,
        &txid,
        TrackObservation::Confirmed { height: TIP },
        TIP,
        6,
    )
    .unwrap();
    for round in 0..9_u64 {
        let change = apply_observation(
            &mut journal,
            NET,
            &txid,
            TrackObservation::NotFound,
            TIP,
            7 + round,
        )
        .unwrap();
        assert!(change.is_empty());
    }
    assert_eq!(records_of(&journal)[0].state, BtcTxState::Confirmed);
    let change = apply_observation(
        &mut journal,
        NET,
        &txid,
        TrackObservation::NotFound,
        TIP,
        20,
    )
    .unwrap();
    assert_eq!(change.changed, vec![(txid, BtcTxState::BroadcastUnknown)]);
    // Through `set_state` a confirmation is never undone.
    let mut confirmed = legacy_plain(&[record(&plan, BtcTxState::Confirmed, 1)]);
    assert!(set_state(&mut confirmed, NET, &txid, BtcTxState::BroadcastUnknown, 2).is_err());
}

/// A `Replaced` original whose replacement was abandoned is finished after the replacement's
/// 30-day window (it used to be tracked forever).
#[test]
fn replaced_by_an_abandoned_replacement_finishes() {
    let original = simple_plan(2, 20_000);
    let mut replaced = record(&original, BtcTxState::Replaced, 1);
    let replacement_plan = simple_plan(3, 20_000);
    replaced.replaced_by = Some(replacement_plan.txid());
    let mut replacement = record(&replacement_plan, BtcTxState::Abandoned, 2);
    replacement.updated_at_unix = 100;
    let records = vec![replaced, replacement];
    assert!(!is_finished(
        &records[0],
        &records,
        Some(TIP),
        100 + BTC_ABANDON_WINDOW_SECS
    ));
    assert!(is_finished(
        &records[0],
        &records,
        Some(TIP),
        101 + BTC_ABANDON_WINDOW_SECS
    ));
}

/// The communication-failure flag of the last send survives the journal round trip.
#[test]
fn last_send_comm_failure_is_persisted() {
    let plan = simple_plan(2, 20_000);
    let record = with_id(record(&plan, BtcTxState::BroadcastUnknown, 1), 4);
    let mut journal = legacy_plain(&[record]);
    assert!(!records_of(&journal)[0].last_send_comm_failure);
    assert_eq!(
        set_last_send_comm_failure(&mut journal, NET, &[4; 16], true),
        Ok(true)
    );
    assert_eq!(
        set_last_send_comm_failure(&mut journal, NET, &[4; 16], true),
        Ok(false)
    );
    let reloaded = JournalPlain::decode(&journal.encode().unwrap()).unwrap();
    assert!(records_of(&reloaded)[0].last_send_comm_failure);
    assert_eq!(
        set_last_send_comm_failure(&mut journal, NET, &[5; 16], true),
        Err(TransitionError::UnknownTx)
    );
}

/// A send the node refused without relaying gives its change index back.
#[test]
fn rejected_send_gives_the_change_index_back() {
    let mut meta = BtcMeta::new(NET, xpub());
    assert_eq!(meta.on_broadcasting(Some(0)), Ok(true));
    assert_eq!(meta.change_next(), 1);
    assert!(!meta.on_send_rejected(Some(5)), "not the latest index");
    assert!(meta.on_send_rejected(Some(0)));
    assert_eq!(meta.change_next(), 0);
    assert!(!meta.on_send_rejected(None));
}

/// Security review (hostile RPC double payment): a record whose bytes were handed to the RPC
/// (flags bit7) and then ended `Rejected` (pre-check or send refusal) or was cancelled from
/// `Signed` constrains the next send like a live abandoned one for 30 days; an undisclosed
/// `Rejected` / cancelled record constrains nothing.
#[test]
#[expect(clippy::too_many_lines, reason = "the whole disclosed-record flow")]
fn disclosed_rejected_or_cancelled_must_be_conflicted() {
    use yw_core::journal::btc::{
        TrackMode, disclosed_duplicate, set_disclosed, set_state_entry, track_mode,
    };
    let account = account();
    let first_plan = simple_plan(1, 20_000);
    // Undisclosed: final at once, no constraint, not tracked (existing behaviour).
    let undisclosed_rejected = record(&first_plan, BtcTxState::Rejected, 1_000);
    let undisclosed_cancelled = record(&first_plan, BtcTxState::Abandoned, 1_000);
    for record in [&undisclosed_rejected, &undisclosed_cancelled] {
        let records = vec![record.clone()];
        assert!(abandoned_conflicts(&records, NET, 1_000).is_empty());
        assert!(refresh_keep_outpoints(&records, NET, 1_000).is_empty());
    }
    assert!(is_finished(
        &undisclosed_rejected,
        std::slice::from_ref(&undisclosed_rejected),
        Some(TIP),
        1_000
    ));
    assert_eq!(
        track_mode(&undisclosed_rejected, &[], TIP, 1_000),
        TrackMode::None
    );

    // The flag is written through the journal (never cleared) and survives a reload.
    let mut journal = legacy_plain(&[with_id(record(&first_plan, BtcTxState::Signed, 1_000), 6)]);
    assert_eq!(set_disclosed(&mut journal, NET, &[6; 16]), Ok(true));
    assert_eq!(set_disclosed(&mut journal, NET, &[6; 16]), Ok(false));
    assert_eq!(
        set_disclosed(&mut journal, NET, &[9; 16]),
        Err(TransitionError::UnknownTx)
    );
    let reloaded = JournalPlain::decode(&journal.encode().unwrap()).unwrap();
    assert!(records_of(&reloaded)[0].disclosed);
    // A hostile RPC answers "rejected" after receiving the bytes.
    set_state_entry(&mut journal, NET, &[6; 16], BtcTxState::Rejected, 1_000).unwrap();
    let rejected = records_of(&journal)[0].clone();
    assert!(rejected.disclosed);
    // [취소] after a failed pre-check (communication error: still `Signed`, but disclosed).
    let mut cancelled = record(&first_plan, BtcTxState::Abandoned, 1_000);
    cancelled.disclosed = true;
    assert_eq!(cancelled.not_found_count, 0);

    let candidates = [
        utxo(100_000, TIP - 10, 1, 0),
        utxo(50_000, TIP - 10, 2, 0),
        utxo(300_000, TIP - 10, 3, 0),
    ];
    for given_up in [rejected.clone(), cancelled] {
        let records = vec![given_up.clone()];
        assert_eq!(abandoned_conflicts(&records, NET, 1_000), vec![vec![op(1)]]);
        assert_eq!(refresh_keep_outpoints(&records, NET, 1_000), vec![op(1)]);
        assert!(in_flight_outpoints(&records, NET).is_empty());
        assert_eq!(check_can_send(&records, NET), Ok(()), "not in flight");
        assert!(!is_finished(&given_up, &records, Some(TIP), 1_000));
        assert_eq!(
            track_mode(&given_up, &records, TIP, 1_000),
            TrackMode::ConfirmationOnly
        );
        // The next send with another amount (and another fee) must spend op(1).
        let conflicts = abandoned_conflicts(&records, NET, 1_000);
        let free = plan_send(&send_request(
            &candidates,
            SendAmount::Exact(Sats::new(30_000).unwrap()),
            &[],
            TIP,
            3,
            &account,
        ))
        .unwrap();
        assert_eq!(spent(&free), vec![op(2)]);
        assert_eq!(
            check_abandoned_conflicts(&records, &free, 1_000),
            Err(PlanError::AbandonedNotConflicted)
        );
        let mut request = send_request(
            &candidates,
            SendAmount::Exact(Sats::new(30_000).unwrap()),
            &conflicts,
            TIP,
            3,
            &account,
        );
        request.fee = rate(3);
        let forced = plan_send(&request).unwrap();
        assert_eq!(spent(&forced), vec![op(1)]);
        assert_ne!(forced.txid(), first_plan.txid());
        assert_eq!(check_abandoned_conflicts(&records, &forced, 1_000), Ok(()));
        // The 30-day window ends: no constraint, finished.
        let after = 1_001 + BTC_ABANDON_WINDOW_SECS;
        assert!(abandoned_conflicts(&records, NET, after).is_empty());
        assert!(is_finished(&given_up, &records, Some(TIP), after));

        // The new send confirms first: the given-up transaction can never confirm (cleared).
        let new = with_id(record(&forced, BtcTxState::Submitted, 2_000), 7);
        let mut journal = legacy_plain(&[with_id(given_up.clone(), 6), new.clone()]);
        let change = apply_observation(
            &mut journal,
            NET,
            &forced.txid(),
            TrackObservation::Confirmed { height: TIP },
            TIP,
            2_100,
        )
        .unwrap();
        assert!(
            change
                .changed
                .contains(&(first_plan.txid(), BtcTxState::Conflicted)),
            "{change:?}"
        );
        let records = records_of(&journal);
        assert!(abandoned_conflicts(&records, NET, 2_100).is_empty());
        assert!(is_finished(&records[0], &records, Some(TIP), 2_100));
        // Or the hostile RPC relayed it and it confirms: recorded, the new send conflicted.
        let mut journal = legacy_plain(&[with_id(given_up, 6), new]);
        let change = apply_observation(
            &mut journal,
            NET,
            &first_plan.txid(),
            TrackObservation::Confirmed { height: TIP },
            TIP,
            2_100,
        )
        .unwrap();
        assert!(
            change
                .changed
                .contains(&(first_plan.txid(), BtcTxState::Confirmed))
        );
        assert!(
            change
                .changed
                .contains(&(forced.txid(), BtcTxState::Conflicted))
        );
    }

    // An undisclosed `Rejected` record is final: neither a confirmation of a send sharing its
    // input nor an observation moves it.
    let forced = simple_plan(1, 30_000);
    let mut journal = legacy_plain(&[
        with_id(undisclosed_rejected.clone(), 6),
        with_id(record(&forced, BtcTxState::Submitted, 2_000), 7),
    ]);
    apply_observation(
        &mut journal,
        NET,
        &forced.txid(),
        TrackObservation::Confirmed { height: TIP },
        TIP,
        2_100,
    )
    .unwrap();
    apply_observation(
        &mut journal,
        NET,
        &first_plan.txid(),
        TrackObservation::Confirmed { height: TIP },
        TIP,
        2_100,
    )
    .unwrap();
    assert_eq!(records_of(&journal)[0].state, BtcTxState::Rejected);

    // The same transaction signed again supersedes the disclosed `Rejected` record and is
    // disclosed from the start (a [취소] of it still constrains the next send).
    let mut journal = legacy_plain(&[with_id(rejected, 6)]);
    let again = with_id(record(&first_plan, BtcTxState::Signed, 3_000), 8);
    assert!(disclosed_duplicate(&journal, &again));
    let rows = take_finished_duplicates(
        yw_core::lang::Lang::Ko,
        &mut journal,
        &again,
        TIP,
        3_000,
        99,
    )
    .unwrap();
    assert_eq!(rows[0].status, "rejected");
    push_record(&mut journal, &again).unwrap();
    assert_eq!(records_of(&journal).len(), 1);
    let fresh = legacy_plain(&[with_id(undisclosed_rejected, 6)]);
    assert!(!disclosed_duplicate(&fresh, &again));
}

/// Security review (double payment across account identities, spec/08 §12.1): a disclosed
/// `Abandoned` record of an imported key that was removed and imported again (a new vault record
/// id, so a new account identity) still constrains the next send of the new identity: records are
/// matched by the scripts their inputs spend (and by outpoint), not by account id. The HD account
/// holding the same address covers it too; another address or address type does not. While the
/// record may still confirm, the key may not be removed.
#[test]
fn reimported_key_inherits_the_abandon_rule() {
    use yw_core::bip32::path::BtcChain;
    use yw_core::btc::account::{BtcAccountId, BtcAccountKey, BtcPubKey, ScriptType};
    use yw_core::journal::btc::{AccountScope, input_scripts, of_account, related_records};
    let plan = simple_plan(1, 20_000);
    let input = plan.inputs()[0];
    let key = btc_common::pubkey(input.chain, input.index);
    let mut given_up = record(&plan, BtcTxState::Abandoned, 1_000);
    given_up.disclosed = true;
    given_up.account = BtcAccountId::Imported { id: [0xa1; 16] };
    let records = records_of(&legacy_plain(&[given_up.clone()]));
    assert_eq!(records, vec![given_up.clone()]);
    // The witness shows the key: the script is known without the removed account.
    let single = |id: u8, script_type: ScriptType, public: [u8; 33]| {
        BtcAccountKey::single([id; 16], script_type, BtcPubKey::Compressed(public)).unwrap()
    };
    let new_key = single(0xb2, ScriptType::P2wpkh, key);
    assert_eq!(
        input_scripts(&given_up, None),
        vec![Some(new_key.script(BtcChain::Receive, 0).unwrap())]
    );
    // By account id the new identity sees nothing (the old rule): unconstrained.
    assert!(of_account(&records, NET, new_key.id()).is_empty());
    let scope = AccountScope::of(&BtcMeta::with_key(NET, new_key)).unwrap();
    let related = related_records(&records, &scope, &[new_key]);
    assert_eq!(related, records);
    assert_eq!(abandoned_conflicts(&related, NET, 1_000), vec![vec![op(1)]]);
    assert_eq!(refresh_keep_outpoints(&related, NET, 1_000), vec![op(1)]);
    // The next send of the new identity must spend op(1).
    let account = account();
    let candidates = [utxo(100_000, TIP - 10, 1, 0), utxo(50_000, TIP - 10, 2, 0)];
    let free = plan_send(&send_request(
        &candidates,
        SendAmount::Exact(Sats::new(30_000).unwrap()),
        &[],
        TIP,
        3,
        &account,
    ))
    .unwrap();
    assert_eq!(spent(&free), vec![op(2)]);
    assert_eq!(
        check_abandoned_conflicts(&related, &free, 1_000),
        Err(PlanError::AbandonedNotConflicted)
    );
    let conflicts = abandoned_conflicts(&related, NET, 1_000);
    let forced = plan_send(&send_request(
        &candidates,
        SendAmount::Exact(Sats::new(30_000).unwrap()),
        &conflicts,
        TIP,
        3,
        &account,
    ))
    .unwrap();
    assert_eq!(spent(&forced), vec![op(1)]);
    assert_eq!(check_abandoned_conflicts(&related, &forced, 1_000), Ok(()));
    // The HD account with the same address (an alias) covers it as well.
    let hd = AccountScope::of(&BtcMeta::new(NET, xpub())).unwrap();
    assert_eq!(related_records(&records, &hd, &[]), records);
    // Another key, or the same key as another address type: unrelated.
    let other = single(
        0xc3,
        ScriptType::P2wpkh,
        btc_common::pubkey(BtcChain::Receive, 5),
    );
    let other_scope = AccountScope::of(&BtcMeta::with_key(NET, other)).unwrap();
    assert!(related_records(&records, &other_scope, &[]).is_empty());
    let taproot = single(0xd4, ScriptType::P2tr, key);
    let taproot_scope = AccountScope::of(&BtcMeta::with_key(NET, taproot)).unwrap();
    assert!(related_records(&records, &taproot_scope, &[]).is_empty());
    // Removal block (spec/04 §2.18): may still confirm inside the window, not after.
    assert!(given_up.may_still_confirm(1_000));
    assert!(!given_up.may_still_confirm(1_001 + BTC_ABANDON_WINDOW_SECS));
    let mut cancelled = given_up.clone();
    cancelled.disclosed = false;
    assert!(!cancelled.is_live_conflict(1_000));
    assert!(
        cancelled.may_still_confirm(1_000),
        "every abandoned record of the window"
    );
    let mut confirmed = record(&plan, BtcTxState::Confirmed, 1_000);
    assert!(!confirmed.may_still_confirm(1_000));
    confirmed.state = BtcTxState::Replaced;
    confirmed.confirmed_height = None;
    assert!(confirmed.may_still_confirm(1_000 + 2 * BTC_ABANDON_WINDOW_SECS));
}

/// Review fix (spec/08 §12.1, §4.7-6): the inputs of a confirmed send are gone for good. A
/// later send that still spends one of them (a stale `verified` entry) and that the node refuses
/// after seeing its bytes (disclosed `Rejected`), or that is given up, ends `Conflicted` at once:
/// never a live conflict that would force every next send onto the spent output for 30 days. A
/// journal written before this rule is fixed at startup; balances and plans leave the inputs out.
#[test]
fn spent_by_a_confirmed_send_is_never_a_live_conflict() {
    use yw_core::journal::btc::{confirmed_inputs, normalize_on_startup, unspendable_outpoints};
    let first = simple_plan(1, 20_000);
    let again = simple_plan(1, 30_000);
    let confirmed = with_id(record(&first, BtcTxState::Confirmed, 1_000), 6);
    let alone = [confirmed.clone()];
    assert_eq!(confirmed_inputs(&alone, NET), vec![op(1)]);
    assert_eq!(unspendable_outpoints(&alone, NET), vec![op(1)]);
    assert!(in_flight_outpoints(&alone, NET).is_empty());
    // Refused by the node that saw the bytes.
    let mut doomed = with_id(record(&again, BtcTxState::Signed, 2_000), 7);
    doomed.disclosed = true;
    let mut journal = legacy_plain(&[confirmed.clone(), doomed]);
    let change = set_state_entry(&mut journal, NET, &[7; 16], BtcTxState::Rejected, 2_100).unwrap();
    assert_eq!(
        change.changed,
        vec![
            (again.txid(), BtcTxState::Rejected),
            (again.txid(), BtcTxState::Conflicted)
        ]
    );
    let records = records_of(&journal);
    assert!(abandoned_conflicts(&records, NET, 2_100).is_empty());
    assert!(refresh_keep_outpoints(&records, NET, 2_100).is_empty());
    // [포기] after 10 not-found rounds: conflicted as well.
    let mut unknown = with_id(record(&again, BtcTxState::BroadcastUnknown, 2_000), 7);
    unknown.not_found_count = 10;
    let mut journal = legacy_plain(&[confirmed.clone(), unknown]);
    set_state_entry(&mut journal, NET, &[7; 16], BtcTxState::Abandoned, 2_100).unwrap();
    assert_eq!(records_of(&journal)[1].state, BtcTxState::Conflicted);
    // Written before this rule: the startup pass conflicts it.
    let mut stuck = with_id(record(&again, BtcTxState::Rejected, 2_000), 7);
    stuck.disclosed = true;
    let mut journal = legacy_plain(&[confirmed, stuck]);
    let change = normalize_on_startup(&mut journal, 2_200).unwrap();
    assert_eq!(change.changed, vec![(again.txid(), BtcTxState::Conflicted)]);
    assert!(abandoned_conflicts(&records_of(&journal), NET, 2_200).is_empty());
}
