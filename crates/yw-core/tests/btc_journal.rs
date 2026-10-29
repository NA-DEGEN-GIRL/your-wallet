//! spec/08 §12 through the public API: `journal_codec_roundtrip_and_truncation` (every truncation
//! and every bit flip of a checked field rejected), the state table, startup normalization,
//! the §12.2 tracking decisions (`esplora_tx_status_ambiguous` decision part), replacement
//! bookkeeping, `inflight_blocks_new_send` / `rbf_allowed_while_inflight` (D20, BTC-N5),
//! `journal_btc_prune`, the pre-add room check (`JournalError::Full`), activity rows and the
//! `change_next` floor.
#![allow(
    clippy::unwrap_used,
    reason = "fixture helpers outside #[test] functions panic on broken fixtures"
)]

mod btc_common;

use btc_common::{NET, RECIPIENT, SEED, TIP, account, plan, rate, record, simple_plan, utxo, xpub};
use yw_core::btc::amount::Sats;
use yw_core::btc::select::{BumpRequest, PlanError, SendAmount, SendPlan, plan_fee_bump};
use yw_core::btc::tx::{OutPoint, Txid};
use yw_core::journal::btc::{
    BTC_ABANDON_WINDOW_SECS, BTC_JOURNAL_HEADER_LEN, BTC_JOURNAL_INPUT_LEN, BTC_JOURNAL_MAX_BODY,
    BtcEntries, BtcPushError, BtcRecord, BtcRecordError, BtcTxState, RecordChange, TrackInput,
    TrackMode, TrackObservation, TransitionError, TxSeen, activity_row, apply_observation,
    bump_target, change_next_floor, check_can_send, check_plan_allowed, finished_rows, has_room,
    hold_confirmation, in_flight, in_flight_outpoints, in_flight_replacements, is_finished,
    make_room, normalize_on_startup, observe, own_outputs, prune_finished, push_record,
    recorded_amounts, replacement_ancestors, set_state, track_mode,
};
use yw_core::journal::{Entry, EntryKind, JournalError, JournalPlain, MAX_BODY};

const ALL_STATES: [BtcTxState; 10] = [
    BtcTxState::Signed,
    BtcTxState::Rejected,
    BtcTxState::Broadcasting,
    BtcTxState::Submitted,
    BtcTxState::BroadcastUnknown,
    BtcTxState::InMempool,
    BtcTxState::Confirmed,
    BtcTxState::Replaced,
    BtcTxState::Conflicted,
    BtcTxState::Abandoned,
];

fn sats(value: u64) -> Sats {
    Sats::new(value).unwrap()
}

fn bump_of(original: &SendPlan, sat_per_vb: u64) -> SendPlan {
    let source = record(original, BtcTxState::Submitted, 1)
        .bump_source(&account())
        .unwrap();
    let account = account();
    plan_fee_bump(&BumpRequest {
        source: &source,
        account: &account,
        fee: rate(sat_per_vb),
        incremental: None,
        candidates: &[],
        tip_height: TIP + 1,
        change_next: 9,
        layout_seed: [0x31; 32],
        typed_fee_override: None,
    })
    .unwrap()
}

fn plain_of(records: &[BtcRecord]) -> JournalPlain {
    let mut plain = JournalPlain::default();
    for record in records {
        push_record(&mut plain, record).unwrap();
    }
    plain
}

fn records_of(plain: &JournalPlain) -> Vec<BtcRecord> {
    BtcEntries::from_plain(plain).records()
}

fn state_of(plain: &JournalPlain, txid: &Txid) -> BtcTxState {
    records_of(plain)
        .into_iter()
        .find(|record| record.txid == *txid)
        .unwrap()
        .state
}

/// Header positions a bit flip may leave decodable (not derivable from the raw transaction):
/// state, the send-max and typed-override flags, ids, times, digest, counter, optional values
/// and input paths.
fn free_position(record: &BtcRecord, position: usize, bit: u8) -> bool {
    let inputs_end = BTC_JOURNAL_HEADER_LEN + BTC_JOURNAL_INPUT_LEN * record.inputs.len();
    match position {
        2 | 4..36 | 100..132 | 148..152 => true,
        3 => !(2..6).contains(&bit),
        152..184 => record.replaces.is_some(),
        184..216 => record.replaced_by.is_some(),
        216..220 => record.confirmed_height.is_some(),
        220..224 => record.change.is_some(),
        p if (BTC_JOURNAL_HEADER_LEN..inputs_end).contains(&p) => {
            (p - BTC_JOURNAL_HEADER_LEN) % BTC_JOURNAL_INPUT_LEN >= 44
        }
        _ => false,
    }
}

/// spec/08 §14.2 `journal_codec_roundtrip_and_truncation`.
#[test]
#[expect(clippy::too_many_lines, reason = "every record shape, cut and flip")]
fn journal_codec_roundtrip_and_truncation() {
    let send = simple_plan(2, 20_000);
    let max = plan(
        &[utxo(30_000, TIP - 1, 3, 0), utxo(20_000, TIP - 1, 4, 1)],
        RECIPIENT,
        SendAmount::Max,
        rate(1),
        SEED,
    )
    .unwrap();
    let bumped = bump_of(&send, 3);
    let typed_source = [utxo(2_000_000, TIP - 1, 5, 0)];
    let account = account();
    let over = yw_core::btc::select::plan_send(&yw_core::btc::select::SendRequest {
        network: NET,
        account: &account,
        recipient: RECIPIENT,
        amount: SendAmount::Exact(sats(100_000)),
        fee: rate(501),
        candidates: &typed_source,
        tip_height: TIP,
        change_next: 0,
        layout_seed: SEED,
        typed_fee_override: None,
        conflicts: &[],
    })
    .unwrap();
    let typed = yw_core::btc::select::plan_send(&yw_core::btc::select::SendRequest {
        network: NET,
        account: &account,
        recipient: RECIPIENT,
        amount: SendAmount::Exact(sats(100_000)),
        fee: rate(501),
        candidates: &typed_source,
        tip_height: TIP,
        change_next: 0,
        layout_seed: SEED,
        typed_fee_override: Some(over.fee()),
        conflicts: &[],
    })
    .unwrap();
    assert!(typed.fee_override_typed());
    let mut replaced = record(&send, BtcTxState::Replaced, 10);
    replaced.replaced_by = Some(bumped.txid());
    let records = [
        record(&send, BtcTxState::Signed, 1),
        record(&max, BtcTxState::Submitted, 2),
        record(&bumped, BtcTxState::InMempool, 3),
        record(&send, BtcTxState::Confirmed, 4),
        replaced,
        record(&typed, BtcTxState::Abandoned, 5),
    ];
    for original in &records {
        let body = original.encode().unwrap();
        assert_eq!(
            body.len(),
            BTC_JOURNAL_HEADER_LEN
                + BTC_JOURNAL_INPUT_LEN * original.inputs.len()
                + original.raw.len()
        );
        assert_eq!(BtcRecord::decode(&body).as_ref(), Ok(original));
        // Layout spot checks.
        assert_eq!(body[0], 1);
        assert_eq!(body[1], 2);
        assert_eq!(body[2], original.state.code());
        assert_eq!(&body[36..68], original.txid.as_bytes());
        assert_eq!(&body[132..140], &original.fee.get().to_be_bytes());
        assert_eq!(
            &body[232..234],
            &u16::try_from(original.inputs.len()).unwrap().to_be_bytes()
        );
        assert_eq!(
            &body[234..238],
            &u32::try_from(original.raw.len()).unwrap().to_be_bytes()
        );
        assert_eq!(
            &body[body.len() - original.raw.len()..],
            original.raw.as_slice()
        );
        let flags = body[3];
        assert_eq!(flags & 1 != 0, original.send_max);
        assert_eq!(flags & 2 != 0, original.fee_override_typed);
        assert_eq!(flags & 4 != 0, original.change.is_some());
        assert_eq!(flags & 8 != 0, original.replaces.is_some());
        assert_eq!(flags & 16 != 0, original.replaced_by.is_some());
        assert_eq!(flags & 32 != 0, original.confirmed_height.is_some());
        if original.change.is_none() {
            assert_eq!(&body[220..228], &[0xff; 8]);
        }
        // Every truncation and an extra byte.
        for cut in 0..body.len() {
            assert!(BtcRecord::decode(&body[..cut]).is_err(), "cut {cut}");
        }
        let mut longer = body.clone();
        longer.push(0);
        assert_eq!(BtcRecord::decode(&longer), Err(BtcRecordError::Length));
        // Every bit flip: rejected unless the field is free (not derivable from the raw bytes).
        let mut rejected = 0_usize;
        for position in 0..body.len() {
            for bit in 0..8_u8 {
                let mut changed = body.clone();
                changed[position] ^= 1 << bit;
                match BtcRecord::decode(&changed) {
                    Err(_) => rejected += 1,
                    Ok(decoded) => {
                        assert!(
                            free_position(original, position, bit),
                            "flip at {position} bit {bit} accepted ({:?})",
                            original.state
                        );
                        assert_eq!(decoded.encode().unwrap(), changed);
                    }
                }
            }
        }
        assert!(rejected > body.len() * 5, "{rejected}");
    }
    // Specific rejections.
    let body = records[0].encode().unwrap();
    let mut version = body.clone();
    version[0] = 3;
    assert_eq!(BtcRecord::decode(&version), Err(BtcRecordError::Version));
    // Version 2 needs the 18-byte account block after the header.
    version[0] = 2;
    assert_eq!(BtcRecord::decode(&version), Err(BtcRecordError::Length));
    // bit7: the bytes were handed to the RPC (disclosed). A body written before the bit reads
    // as not disclosed; the bit round-trips.
    assert!(!BtcRecord::decode(&body).unwrap().disclosed);
    let mut disclosed = body.clone();
    disclosed[3] |= 0x80;
    let decoded = BtcRecord::decode(&disclosed).unwrap();
    assert!(decoded.disclosed);
    assert_eq!(decoded.encode().unwrap(), disclosed);
    // bit6: the last send was a communication failure (kept across restarts).
    let mut comm = body.clone();
    comm[3] |= 0x40;
    let decoded = BtcRecord::decode(&comm).unwrap();
    assert!(decoded.last_send_comm_failure);
    assert_eq!(decoded.encode().unwrap(), comm);
    let mut state = body.clone();
    state[2] = 11;
    assert_eq!(BtcRecord::decode(&state), Err(BtcRecordError::Value));
    let mut zero_id = body.clone();
    zero_id[4..20].fill(0);
    assert_eq!(BtcRecord::decode(&zero_id), Err(BtcRecordError::Value));
    let mut wtxid = body.clone();
    wtxid[68] ^= 1;
    assert_eq!(BtcRecord::decode(&wtxid), Err(BtcRecordError::Hash));
    let mut no_inputs = records[0].clone();
    no_inputs.inputs.clear();
    assert_eq!(no_inputs.encode(), Err(BtcRecordError::Length));
    let mut wrong_fee = records[0].clone();
    wrong_fee.fee = sats(1);
    assert_eq!(wrong_fee.encode(), Err(BtcRecordError::Outputs));
    let mut confirmed_without_height = records[3].clone();
    confirmed_without_height.confirmed_height = None;
    assert_eq!(
        confirmed_without_height.encode(),
        Err(BtcRecordError::Flags)
    );
    let mut replaced_without_by = records[4].clone();
    replaced_without_by.replaced_by = None;
    assert_eq!(replaced_without_by.encode(), Err(BtcRecordError::Flags));
    let mut unsigned = records[0].clone();
    unsigned.raw = yw_core::btc::tx::serialize(send.tx(), false);
    assert_eq!(unsigned.encode(), Err(BtcRecordError::Raw));
    assert_eq!(
        yw_core::journal::EntryKind::Btc.max_body(),
        BTC_JOURNAL_MAX_BODY
    );
    assert_eq!(BTC_JOURNAL_MAX_BODY, 238 + 18 + 49 * 100 + 32_768);
}

/// spec/08 §12.1 transitions (with `Conflicted` from the broadcast states and `Replaced`).
#[test]
#[expect(clippy::too_many_lines, reason = "the whole spec/08 §12.1 table")]
fn state_table() {
    use BtcTxState::{
        Abandoned, BroadcastUnknown, Broadcasting, Confirmed, Conflicted, InMempool, Rejected,
        Replaced, Signed, Submitted,
    };
    let allowed: [(BtcTxState, &[BtcTxState]); 10] = [
        (Signed, &[Broadcasting, Rejected, Abandoned]),
        // Only a disclosed `Rejected` record leaves the state (tracking and its cascade).
        (Rejected, &[Confirmed, Conflicted]),
        (Broadcasting, &[Submitted, BroadcastUnknown, Rejected]),
        (
            Submitted,
            &[InMempool, Confirmed, Replaced, BroadcastUnknown, Conflicted],
        ),
        (
            BroadcastUnknown,
            &[InMempool, Confirmed, Replaced, Abandoned, Conflicted],
        ),
        (
            InMempool,
            &[Confirmed, Replaced, BroadcastUnknown, Conflicted],
        ),
        (Confirmed, &[InMempool, BroadcastUnknown]),
        (Replaced, &[Confirmed, Conflicted]),
        (Conflicted, &[]),
        (Abandoned, &[Confirmed, Conflicted]),
    ];
    for (from, targets) in allowed {
        for to in ALL_STATES {
            assert_eq!(
                from.can_transition_to(to),
                targets.contains(&to),
                "{} → {}",
                from.name(),
                to.name()
            );
        }
    }
    for (code, state) in (1_u8..=10).zip(ALL_STATES) {
        assert_eq!(BtcTxState::from_code(code), Some(state));
        assert_eq!(state.code(), code);
    }
    assert_eq!(BtcTxState::from_code(0), None);
    assert_eq!(BtcTxState::from_code(11), None);
    let in_flight: Vec<_> = ALL_STATES
        .into_iter()
        .filter(|s| s.is_in_flight())
        .collect();
    assert_eq!(
        in_flight,
        vec![Signed, Broadcasting, Submitted, BroadcastUnknown, InMempool]
    );
    let bumpable: Vec<_> = ALL_STATES.into_iter().filter(|s| s.can_bump()).collect();
    assert_eq!(bumpable, vec![Submitted, BroadcastUnknown, InMempool]);
    assert_eq!(Confirmed.activity_status(), Some("succeeded"));
    assert_eq!(Rejected.activity_status(), Some("rejected"));
    assert_eq!(Replaced.activity_status(), Some("replaced"));
    assert_eq!(Conflicted.activity_status(), Some("conflicted"));
    assert_eq!(Abandoned.activity_status(), Some("abandoned"));
    assert_eq!(Submitted.activity_status(), None);
    // set_state through the table; unknown and cascade-only targets refused.
    let send = simple_plan(2, 20_000);
    let txid = send.txid();
    let mut plain = plain_of(&[record(&send, BtcTxState::Signed, 1)]);
    assert_eq!(
        set_state(&mut plain, NET, &txid, BtcTxState::Submitted, 2),
        Err(TransitionError::NotAllowed {
            from: Signed,
            to: Submitted
        })
    );
    for target in [Confirmed, Replaced, Conflicted] {
        assert!(set_state(&mut plain, NET, &txid, target, 2).is_err());
    }
    assert_eq!(
        set_state(&mut plain, NET, &Txid::from_bytes([1; 32]), Broadcasting, 2),
        Err(TransitionError::UnknownTx)
    );
    assert_eq!(
        set_state(
            &mut plain,
            yw_core::btc::BtcNetwork::Mainnet,
            &txid,
            Broadcasting,
            2
        ),
        Err(TransitionError::UnknownTx)
    );
    let change = set_state(&mut plain, NET, &txid, Broadcasting, 2).unwrap();
    assert_eq!(change.changed, vec![(txid, Broadcasting)]);
    // Startup: Broadcasting → BroadcastUnknown; Signed is left for the user.
    let other = simple_plan(3, 20_000);
    push_record(&mut plain, &record(&other, Signed, 3)).unwrap();
    let change = normalize_on_startup(&mut plain, 9).unwrap();
    assert_eq!(change.changed, vec![(txid, BroadcastUnknown)]);
    assert_eq!(state_of(&plain, &txid), BroadcastUnknown);
    assert_eq!(state_of(&plain, &other.txid()), Signed);
    assert!(normalize_on_startup(&mut plain, 10).unwrap().is_empty());
    // [포기]: BroadcastUnknown → Abandoned once not found 10 times; [취소]: Signed → Abandoned.
    for _ in 0..10 {
        apply_observation(&mut plain, NET, &txid, TrackObservation::NotFound, TIP, 10).unwrap();
    }
    set_state(&mut plain, NET, &txid, Abandoned, 11).unwrap();
    set_state(&mut plain, NET, &other.txid(), Abandoned, 11).unwrap();
    assert!(
        records_of(&plain)
            .iter()
            .all(|r| r.state == Abandoned && r.updated_at_unix == 11)
    );
}

/// spec/08 §12.2 decisions (`getmempoolentry`, indexer `TxStatus`, the Esplora `TxRaw` probe).
#[test]
#[expect(clippy::too_many_lines, reason = "every spec/08 §12.2 decision")]
fn tracking_decisions() {
    use TrackObservation::{Confirmed, InMempool, NeedRawProbe, NotFound};
    let confirmed = TxSeen::Confirmed { height: 7 };
    assert_eq!(observe(TrackInput::MempoolEntry), InMempool);
    // Review fix M1: Core's mempool lacks it, but an indexer that still sees it unconfirmed (or
    // knows its raw bytes after an ambiguous Esplora status) keeps it "in a mempool": the round
    // does not count towards [포기].
    for (seen, raw_found, expected) in [
        (confirmed, None, Confirmed { height: 7 }),
        (TxSeen::Unconfirmed, None, InMempool),
        (TxSeen::NotFound, None, NotFound),
        (TxSeen::UnconfirmedOrUnknown, None, NeedRawProbe),
        (TxSeen::UnconfirmedOrUnknown, Some(true), InMempool),
        (TxSeen::UnconfirmedOrUnknown, Some(false), NotFound),
    ] {
        assert_eq!(
            observe(TrackInput::NotInMempool {
                indexer: seen,
                raw_found
            }),
            expected
        );
    }
    for (seen, raw_found, expected) in [
        (confirmed, None, Confirmed { height: 7 }),
        (TxSeen::Unconfirmed, None, InMempool),
        (TxSeen::NotFound, None, NotFound),
        (TxSeen::UnconfirmedOrUnknown, None, NeedRawProbe),
        (TxSeen::UnconfirmedOrUnknown, Some(true), InMempool),
        (TxSeen::UnconfirmedOrUnknown, Some(false), NotFound),
    ] {
        assert_eq!(
            observe(TrackInput::NoMempoolRpc {
                indexer: seen,
                raw_found
            }),
            expected
        );
    }
    // not_found_count → BroadcastUnknown at 10; InMempool resets it.
    let send = simple_plan(2, 20_000);
    let txid = send.txid();
    let mut plain = plain_of(&[record(&send, BtcTxState::Submitted, 1)]);
    for round in 1..10_u64 {
        let change = apply_observation(&mut plain, NET, &txid, NotFound, TIP, 100 + round).unwrap();
        assert!(change.is_empty(), "count only");
    }
    assert_eq!(records_of(&plain)[0].not_found_count, 9);
    assert_eq!(state_of(&plain, &txid), BtcTxState::Submitted);
    let change = apply_observation(&mut plain, NET, &txid, NotFound, TIP, 200).unwrap();
    assert_eq!(change.changed, vec![(txid, BtcTxState::BroadcastUnknown)]);
    apply_observation(&mut plain, NET, &txid, NotFound, TIP, 201).unwrap();
    assert_eq!(records_of(&plain)[0].not_found_count, 11);
    let change = apply_observation(&mut plain, NET, &txid, InMempool, TIP, 202).unwrap();
    assert_eq!(change.changed, vec![(txid, BtcTxState::InMempool)]);
    assert_eq!(records_of(&plain)[0].not_found_count, 0);
    // A height above the Core tip is not a confirmation yet.
    let change = apply_observation(
        &mut plain,
        NET,
        &txid,
        Confirmed { height: TIP + 1 },
        TIP,
        203,
    )
    .unwrap();
    assert!(change.is_empty());
    let change =
        apply_observation(&mut plain, NET, &txid, Confirmed { height: TIP }, TIP, 204).unwrap();
    assert_eq!(change.changed, vec![(txid, BtcTxState::Confirmed)]);
    let records = records_of(&plain);
    assert_eq!(records[0].confirmed_height, Some(TIP));
    assert_eq!(
        track_mode(&records[0], &records, TIP + 4, 205),
        TrackMode::ConfirmationOnly
    );
    assert_eq!(
        track_mode(&records[0], &records, TIP + 5, 205),
        TrackMode::None
    );
    // Re-org: the height follows the indexer.
    apply_observation(
        &mut plain,
        NET,
        &txid,
        Confirmed { height: TIP - 1 },
        TIP,
        206,
    )
    .unwrap();
    assert_eq!(records_of(&plain)[0].confirmed_height, Some(TIP - 1));
    // Abandoned: confirmed within 30 days only.
    let late = simple_plan(3, 20_000);
    let mut abandoned = record(&late, BtcTxState::Abandoned, 1_000);
    abandoned.updated_at_unix = 1_000;
    let mut plain = plain_of(&[abandoned.clone()]);
    let records = records_of(&plain);
    assert_eq!(
        track_mode(&records[0], &records, TIP, 1_000 + BTC_ABANDON_WINDOW_SECS),
        TrackMode::ConfirmationOnly
    );
    assert_eq!(
        track_mode(&records[0], &records, TIP, 1_001 + BTC_ABANDON_WINDOW_SECS),
        TrackMode::None
    );
    let after = 1_001 + BTC_ABANDON_WINDOW_SECS;
    assert!(
        apply_observation(
            &mut plain,
            NET,
            &late.txid(),
            Confirmed { height: TIP },
            TIP,
            after
        )
        .unwrap()
        .is_empty()
    );
    let within = 1_000 + BTC_ABANDON_WINDOW_SECS;
    let change = apply_observation(
        &mut plain,
        NET,
        &late.txid(),
        Confirmed { height: TIP },
        TIP,
        within,
    )
    .unwrap();
    assert_eq!(change.changed, vec![(late.txid(), BtcTxState::Confirmed)]);
    // Modes of the other states.
    let modes = [
        (BtcTxState::Signed, TrackMode::None),
        (BtcTxState::Broadcasting, TrackMode::None),
        (BtcTxState::Submitted, TrackMode::Full),
        (BtcTxState::BroadcastUnknown, TrackMode::Full),
        (BtcTxState::InMempool, TrackMode::Full),
        (BtcTxState::Rejected, TrackMode::None),
    ];
    for (state, mode) in modes {
        let record = record(&late, state, 1);
        assert_eq!(track_mode(&record, &[], TIP, 2), mode, "{}", state.name());
    }
}

/// spec/08 §9 bookkeeping: a submitted replacement replaces the original; if the original
/// confirms first the replacement is `Conflicted`; otherwise the original is finished once the
/// replacement has 6 confirmations.
#[test]
fn replacement_bookkeeping() {
    let original = simple_plan(2, 20_000);
    let replacement = bump_of(&original, 2);
    let second = bump_of(&replacement, 4);
    let t0 = original.txid();
    let t1 = replacement.txid();
    let t2 = second.txid();
    let mut plain = plain_of(&[
        record(&original, BtcTxState::Submitted, 1),
        record(&replacement, BtcTxState::Signed, 2),
    ]);
    set_state(&mut plain, NET, &t1, BtcTxState::Broadcasting, 3).unwrap();
    let change = set_state(&mut plain, NET, &t1, BtcTxState::Submitted, 4).unwrap();
    assert_eq!(
        change.changed,
        vec![(t1, BtcTxState::Submitted), (t0, BtcTxState::Replaced)]
    );
    let records = records_of(&plain);
    assert_eq!(records[0].replaced_by, Some(t1));
    assert_eq!(bump_target(&records, NET).map(|r| r.txid), Some(t1));
    // The original confirms first: the replacement conflicts.
    let mut first_wins = plain.clone();
    let change = apply_observation(
        &mut first_wins,
        NET,
        &t0,
        TrackObservation::Confirmed { height: TIP },
        TIP,
        5,
    )
    .unwrap();
    assert_eq!(
        change.changed,
        vec![(t0, BtcTxState::Confirmed), (t1, BtcTxState::Conflicted)]
    );
    let records = records_of(&first_wins);
    assert!(is_finished(&records[1], &records, Some(TIP), 6));
    assert_eq!(activity_row(&records[1], 7).unwrap().status, "conflicted");
    // A chain of two replacements; the last one confirms.
    push_record(&mut plain, &record(&second, BtcTxState::Signed, 5)).unwrap();
    set_state(&mut plain, NET, &t2, BtcTxState::Broadcasting, 6).unwrap();
    // BroadcastUnknown does not replace yet; InMempool does.
    let change = set_state(&mut plain, NET, &t2, BtcTxState::BroadcastUnknown, 7).unwrap();
    assert_eq!(change.changed, vec![(t2, BtcTxState::BroadcastUnknown)]);
    let change =
        apply_observation(&mut plain, NET, &t2, TrackObservation::InMempool, TIP, 8).unwrap();
    assert_eq!(
        change.changed,
        vec![(t2, BtcTxState::InMempool), (t1, BtcTxState::Replaced)]
    );
    let change = apply_observation(
        &mut plain,
        NET,
        &t2,
        TrackObservation::Confirmed { height: TIP },
        TIP,
        9,
    )
    .unwrap();
    assert_eq!(change.changed, vec![(t2, BtcTxState::Confirmed)]);
    let records = records_of(&plain);
    assert_eq!(
        records.iter().map(|r| r.state).collect::<Vec<_>>(),
        vec![
            BtcTxState::Replaced,
            BtcTxState::Replaced,
            BtcTxState::Confirmed
        ]
    );
    for tip in [TIP, TIP + 4] {
        assert!(!is_finished(&records[0], &records, Some(tip), 10));
        assert_eq!(
            track_mode(&records[0], &records, tip, 10),
            TrackMode::ConfirmationOnly
        );
    }
    assert!(is_finished(&records[0], &records, Some(TIP + 5), 10));
    assert!(is_finished(&records[1], &records, Some(TIP + 5), 10));
    let rows = finished_rows(&plain, NET, TIP + 5, 10, 77);
    let statuses: Vec<_> = rows.iter().map(|row| row.status).collect();
    assert_eq!(statuses, vec!["replaced", "replaced", "succeeded"]);
    assert_eq!(rows[1].title, "[Bitcoin testnet4] 수수료 올리기");
    assert_eq!(rows[0].title, "[Bitcoin testnet4] 보내기: 0.00020000 BTC");
    assert_eq!(rows[2].time_unix_ms, 77);
    // A replaced record whose replacement is gone from the journal is finished.
    let lonely = &records[0];
    assert!(is_finished(
        lonely,
        std::slice::from_ref(lonely),
        Some(TIP),
        10
    ));
}

/// spec/08 §14.2 `inflight_blocks_new_send` (D20, §12.1; BTC-N5 "진행 중 두 번째 송금").
#[test]
fn inflight_blocks_new_send() {
    let first = simple_plan(2, 20_000);
    let second = simple_plan(3, 30_000);
    let records = vec![record(&first, BtcTxState::Submitted, 1)];
    assert!(in_flight(&records, NET));
    assert!(!in_flight(&records, yw_core::btc::BtcNetwork::Mainnet));
    assert_eq!(check_can_send(&records, NET), Err(PlanError::InFlight));
    assert_eq!(
        check_plan_allowed(&records, &second),
        Err(PlanError::InFlight)
    );
    assert_eq!(
        PlanError::InFlight.to_string(),
        "진행 중인 Bitcoin 거래가 확인된 뒤 보낼 수 있습니다. 수수료 올리기는 가능합니다"
    );
    let bump = bump_of(&first, 3);
    // Every in-flight state blocks; finished ones do not.
    for state in [
        BtcTxState::Signed,
        BtcTxState::Broadcasting,
        BtcTxState::Submitted,
        BtcTxState::BroadcastUnknown,
        BtcTxState::InMempool,
    ] {
        let records = vec![record(&first, state, 1)];
        assert_eq!(check_can_send(&records, NET), Err(PlanError::InFlight));
        // Its inputs, and its own (unconfirmed) change output.
        assert_eq!(
            in_flight_outpoints(&records, NET),
            vec![
                first.inputs()[0].outpoint,
                records[0].change_outpoint().unwrap()
            ]
        );
    }
    for state in [
        BtcTxState::Rejected,
        BtcTxState::Confirmed,
        BtcTxState::Replaced,
        BtcTxState::Conflicted,
        BtcTxState::Abandoned,
    ] {
        let mut record = record(&first, state, 1);
        if state == BtcTxState::Replaced {
            record.replaced_by = Some(Txid::from_bytes([5; 32]));
        }
        let records = vec![record];
        assert_eq!(check_can_send(&records, NET), Ok(()), "{}", state.name());
        assert!(in_flight_outpoints(&records, NET).is_empty());
        assert_eq!(check_plan_allowed(&records, &second), Ok(()));
        assert_eq!(
            check_plan_allowed(&records, &bump),
            Err(PlanError::NotBumpable)
        );
    }
    // Bump target: the newest bumpable record.
    let newer = record(&second, BtcTxState::InMempool, 9);
    let both = vec![record(&first, BtcTxState::Submitted, 1), newer];
    assert_eq!(bump_target(&both, NET).map(|r| r.txid), Some(second.txid()));
    // Recorded amounts, own outputs and the change_next floor.
    let amounts = recorded_amounts(&both, NET);
    assert_eq!(amounts.len(), 2);
    assert_eq!(own_outputs(&both, NET).len(), 2);
    assert_eq!(
        own_outputs(&both, NET)[0],
        OutPoint {
            txid: first.txid(),
            vout: first.change().unwrap().vout
        }
    );
    assert_eq!(change_next_floor(&both, NET), Some(4));
    let signed_only = vec![record(&first, BtcTxState::Signed, 1)];
    assert_eq!(change_next_floor(&signed_only, NET), None);
    assert_eq!(
        change_next_floor(&both, yw_core::btc::BtcNetwork::Mainnet),
        None
    );
}

/// spec/08 §14.2 `rbf_allowed_while_inflight` (§9, §12.1): the fee bump of the current
/// in-flight target is allowed; other targets and inputs of other in-flight records are not.
#[test]
fn rbf_allowed_while_inflight() {
    let first = simple_plan(2, 20_000);
    let second = simple_plan(3, 30_000);
    let bump = bump_of(&first, 3);
    for state in [
        BtcTxState::Submitted,
        BtcTxState::BroadcastUnknown,
        BtcTxState::InMempool,
    ] {
        let records = vec![record(&first, state, 1)];
        assert_eq!(check_can_send(&records, NET), Err(PlanError::InFlight));
        assert_eq!(
            check_plan_allowed(&records, &bump),
            Ok(()),
            "{}",
            state.name()
        );
        assert!(records[0].bump_source(&account()).is_some());
    }
    // Not yet sent: nothing to replace.
    for state in [BtcTxState::Signed, BtcTxState::Broadcasting] {
        let records = vec![record(&first, state, 1)];
        assert_eq!(
            check_plan_allowed(&records, &bump),
            Err(PlanError::NotBumpable)
        );
    }
    let records = vec![record(&first, BtcTxState::Submitted, 1)];
    // Only the current target may be replaced.
    let stale = bump_of(&second, 3);
    assert_eq!(
        check_plan_allowed(&records, &stale),
        Err(PlanError::NotBumpable)
    );
    // Inputs of another in-flight record are refused.
    let mut other = record(&second, BtcTxState::Signed, 2);
    other.inputs.clone_from(&first.inputs().to_vec());
    let mut with_other = records.clone();
    with_other.push(other);
    assert_eq!(
        check_plan_allowed(&with_other, &bump),
        Err(PlanError::InputInFlight)
    );
    // A replacement of the replacement: the newest bumpable record is the target.
    let mut chain = vec![record(&first, BtcTxState::Replaced, 1)];
    chain[0].replaced_by = Some(bump.txid());
    chain.push(record(&bump, BtcTxState::Submitted, 2));
    assert_eq!(bump_target(&chain, NET).map(|r| r.txid), Some(bump.txid()));
    let again = bump_of(&bump, 6);
    assert_eq!(check_plan_allowed(&chain, &again), Ok(()));
    assert_eq!(
        check_plan_allowed(&chain, &bump),
        Err(PlanError::NotBumpable),
        "the replaced original is no longer the target"
    );
}

/// spec/09 BTC-N5: fee rate and absolute caps (blocked without the typed fee), a dust output
/// and a second send while one is in flight are all refused.
#[test]
fn btc_n5_blocked() {
    use yw_core::approval::{ApprovalId, RiskLevel};
    use yw_core::btc::display::{BtcSendFacts, build_btc_request};
    let blocked = |plan: &SendPlan| {
        build_btc_request(
            ApprovalId([1; 16]),
            plan,
            &account(),
            &BtcSendFacts::default(),
        )
        .unwrap()
        .display
        .risk
    };
    let rate_cap = plan(
        &[utxo(2_000_000, TIP - 1, 1, 0)],
        RECIPIENT,
        SendAmount::Exact(sats(100_000)),
        rate(501),
        SEED,
    )
    .unwrap();
    assert!(rate_cap.needs_typed_override());
    assert_eq!(blocked(&rate_cap), RiskLevel::Blocked);
    let many: Vec<_> = (0..100_u8)
        .map(|tag| utxo(10_000, TIP - 1, tag, u32::from(tag)))
        .collect();
    let absolute = plan(&many, RECIPIENT, SendAmount::Max, rate(100), SEED).unwrap();
    assert!(absolute.fee().get() > 500_000);
    assert_eq!(blocked(&absolute), RiskLevel::Blocked);
    assert_eq!(
        plan(
            &[utxo(100_000, TIP - 1, 1, 0)],
            RECIPIENT,
            SendAmount::Exact(sats(293)),
            rate(1),
            SEED
        ),
        Err(PlanError::DustAmount {
            threshold: sats(294)
        })
    );
    let first = simple_plan(2, 20_000);
    let records = vec![record(&first, BtcTxState::BroadcastUnknown, 1)];
    assert_eq!(
        check_plan_allowed(&records, &simple_plan(3, 20_000)),
        Err(PlanError::InFlight)
    );
}

fn rejected_plans(count: u8) -> Vec<SendPlan> {
    (0..count)
        .map(|n| simple_plan(n, 20_000 + u64::from(n)))
        .collect()
}

/// spec/08 §14.2 `journal_btc_prune`: the 65th finished record moves the oldest finished one to
/// activity and out of the journal; tracked records stay.
#[test]
fn journal_btc_prune() {
    let plans = rejected_plans(66);
    let mut records: Vec<BtcRecord> = plans[1..]
        .iter()
        .zip(1_u64..)
        .map(|(plan, created)| record(plan, BtcTxState::Rejected, 1_000 + created))
        .collect();
    let tracked = record(&plans[0], BtcTxState::Submitted, 500);
    records.insert(0, tracked.clone());
    let mut plain = plain_of(&records[..65]);
    assert!(
        prune_finished(&mut plain, NET, TIP, 2_000, 1).is_empty(),
        "64 finished kept"
    );
    push_record(&mut plain, &records[65]).unwrap();
    let rows = prune_finished(&mut plain, NET, TIP, 2_000, 1);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].tx_id, plans[1].txid().to_display_hex());
    assert_eq!(rows[0].status, "rejected");
    assert_eq!(rows[0].amount, "20001");
    let left = records_of(&plain);
    assert_eq!(left.len(), 65);
    assert!(left.iter().any(|r| r.txid == tracked.txid));
    assert!(!left.iter().any(|r| r.txid == plans[1].txid()));
    // Finished rows cover every finished record (written to meta before deleting).
    assert_eq!(finished_rows(&plain, NET, TIP, 2_000, 1).len(), 64);
    // Undecodable BTC entries are never touched.
    plain.entries.push(Entry {
        kind: EntryKind::Btc,
        body: vec![9; 300],
    });
    let entries = BtcEntries::from_plain(&plain);
    assert_eq!(entries.corrupt, 1);
    push_record(
        &mut plain,
        &record(&rejected_plans(67)[66], BtcTxState::Rejected, 5_000),
    )
    .unwrap();
    prune_finished(&mut plain, NET, TIP, 6_000, 1);
    assert!(plain.entries.iter().any(|entry| entry.body == vec![9; 300]));
    assert_eq!(BtcEntries::from_plain(&plain).records.len(), 65);
}

/// spec/02 §5.4 pre-add check: 256 entries or 16 MiB; finished BTC records make room oldest
/// first, otherwise `JournalError::Full`.
#[test]
fn room_and_full() {
    let plans = rejected_plans(6);
    let finished: Vec<BtcRecord> = plans
        .iter()
        .zip(1_u64..)
        .map(|(plan, created)| record(plan, BtcTxState::Rejected, created))
        .collect();
    let mut plain = JournalPlain::default();
    for _ in 0..250 {
        plain.entries.push(Entry {
            kind: EntryKind::Evm,
            body: vec![1],
        });
    }
    for record in &finished {
        push_record(&mut plain, record).unwrap();
    }
    assert_eq!(plain.entries.len(), 256);
    assert!(!has_room(&plain));
    assert_eq!(
        push_record(&mut plain, &finished[0]),
        Err(BtcPushError::Full)
    );
    let rows = make_room(&mut plain, NET, TIP, 10, 1).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].tx_id, plans[0].txid().to_display_hex());
    assert!(has_room(&plain));
    assert!(make_room(&mut plain, NET, TIP, 10, 1).unwrap().is_empty());
    // Only tracked BTC records: Full, nothing removed.
    let mut tracked_only = JournalPlain::default();
    for _ in 0..255 {
        tracked_only.entries.push(Entry {
            kind: EntryKind::Sol,
            body: vec![2],
        });
    }
    push_record(
        &mut tracked_only,
        &record(&plans[1], BtcTxState::Submitted, 1),
    )
    .unwrap();
    let before = tracked_only.clone();
    assert_eq!(
        make_room(&mut tracked_only, NET, TIP, 10, 1),
        Err(JournalError::Full)
    );
    assert_eq!(tracked_only, before);
    // The size bound (16 MiB plaintext).
    let mut big = JournalPlain::default();
    for _ in 0..15 {
        big.entries.push(Entry {
            kind: EntryKind::Evm,
            body: vec![0; MAX_BODY],
        });
    }
    push_record(&mut big, &finished[2]).unwrap();
    let filler = 16_777_216 - big.plaintext_len() - 5 - 5 - BTC_JOURNAL_MAX_BODY + 1;
    big.entries.push(Entry {
        kind: EntryKind::Evm,
        body: vec![0; filler],
    });
    assert!(big.within_bounds());
    assert!(!has_room(&big));
    let rows = make_room(&mut big, NET, TIP, 10, 1).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(has_room(&big));
}

/// Review fix (spec/08 §12.1, §12.2-3): [포기] of a `BroadcastUnknown` record only after
/// tracking did not find it 10 times in a row; right after a send timeout, transport error or
/// txid mismatch it is refused (the journal is unchanged).
#[test]
fn abandon_only_after_not_found_limit() {
    let send = simple_plan(2, 20_000);
    let txid = send.txid();
    // Send timeout / transport error / txid mismatch: Broadcasting → BroadcastUnknown.
    let mut plain = plain_of(&[record(&send, BtcTxState::Broadcasting, 1)]);
    set_state(&mut plain, NET, &txid, BtcTxState::BroadcastUnknown, 2).unwrap();
    assert!(!records_of(&plain)[0].can_abandon());
    let refused = Err(TransitionError::NotAllowed {
        from: BtcTxState::BroadcastUnknown,
        to: BtcTxState::Abandoned,
    });
    let before = plain.clone();
    assert_eq!(
        set_state(&mut plain, NET, &txid, BtcTxState::Abandoned, 3),
        refused
    );
    assert_eq!(plain, before);
    for round in 1..10_u64 {
        apply_observation(
            &mut plain,
            NET,
            &txid,
            TrackObservation::NotFound,
            TIP,
            3 + round,
        )
        .unwrap();
        assert!(!records_of(&plain)[0].can_abandon(), "round {round}");
        assert_eq!(
            set_state(&mut plain, NET, &txid, BtcTxState::Abandoned, 20),
            refused
        );
    }
    // Seen in the mempool meanwhile: not abandonable (and no longer BroadcastUnknown).
    let mut seen = plain.clone();
    apply_observation(&mut seen, NET, &txid, TrackObservation::InMempool, TIP, 21).unwrap();
    assert!(!records_of(&seen)[0].can_abandon());
    assert!(set_state(&mut seen, NET, &txid, BtcTxState::Abandoned, 22).is_err());
    // The 10th miss: neither in the mempool nor confirmed → [포기] allowed.
    apply_observation(&mut plain, NET, &txid, TrackObservation::NotFound, TIP, 30).unwrap();
    assert_eq!(records_of(&plain)[0].not_found_count, 10);
    assert!(records_of(&plain)[0].can_abandon());
    let change = set_state(&mut plain, NET, &txid, BtcTxState::Abandoned, 31).unwrap();
    assert_eq!(change.changed, vec![(txid, BtcTxState::Abandoned)]);
    // InMempool that disappeared (10 misses) is abandonable right away.
    let mut vanished = plain_of(&[record(&send, BtcTxState::InMempool, 1)]);
    for round in 0..10_u64 {
        apply_observation(
            &mut vanished,
            NET,
            &txid,
            TrackObservation::NotFound,
            TIP,
            round,
        )
        .unwrap();
    }
    assert_eq!(state_of(&vanished, &txid), BtcTxState::BroadcastUnknown);
    assert!(set_state(&mut vanished, NET, &txid, BtcTxState::Abandoned, 11).is_ok());
    // [취소] of a Signed record stays allowed; other states never.
    assert!(record(&send, BtcTxState::Signed, 1).can_abandon());
    for state in [
        BtcTxState::Broadcasting,
        BtcTxState::Submitted,
        BtcTxState::InMempool,
        BtcTxState::Rejected,
        BtcTxState::Confirmed,
        BtcTxState::Conflicted,
        BtcTxState::Abandoned,
    ] {
        let mut record = record(&send, state, 1);
        record.not_found_count = 10;
        assert!(!record.can_abandon(), "{}", state.name());
    }
}

/// Review fix (spec/08 §9, §5): `T` stays `InMempool` while its bump `R1` ended
/// `BroadcastUnknown`; bumping `R1` again may spend `T`'s inputs (the target's chain), and once
/// that replacement reaches the node every still-bumpable original of the chain is `Replaced`.
#[test]
fn bump_of_unknown_replacement_while_original_in_mempool() {
    let original = simple_plan(2, 20_000);
    let first = bump_of(&original, 3);
    let second = bump_of(&first, 6);
    let (t, r1, r2) = (original.txid(), first.txid(), second.txid());
    let records = vec![
        record(&original, BtcTxState::InMempool, 1),
        record(&first, BtcTxState::BroadcastUnknown, 2),
    ];
    assert_eq!(bump_target(&records, NET).map(|r| r.txid), Some(r1));
    assert_eq!(replacement_ancestors(&records, NET, &r1), vec![t]);
    assert!(replacement_ancestors(&records, NET, &t).is_empty());
    assert_eq!(check_plan_allowed(&records, &second), Ok(()));
    // Still refused: a replacement of the target already under way (D20: one chain) and the
    // inputs of an unrelated in-flight record.
    let pending = bump_of(&first, 4);
    let mut with_pending = records.clone();
    with_pending.push(record(&pending, BtcTxState::Signed, 3));
    assert_eq!(
        check_plan_allowed(&with_pending, &second),
        Err(PlanError::InputInFlight)
    );
    let mut stranger = record(&simple_plan(5, 20_000), BtcTxState::Signed, 3);
    stranger.inputs.clone_from(&original.inputs().to_vec());
    let mut with_stranger = records.clone();
    with_stranger.push(stranger);
    assert_eq!(
        check_plan_allowed(&with_stranger, &second),
        Err(PlanError::InputInFlight)
    );
    // R2 reaches the node: R1 and T are both replaced; only R2 stays in flight.
    let mut plain = plain_of(&records);
    push_record(&mut plain, &record(&second, BtcTxState::Signed, 4)).unwrap();
    set_state(&mut plain, NET, &r2, BtcTxState::Broadcasting, 5).unwrap();
    let change = set_state(&mut plain, NET, &r2, BtcTxState::Submitted, 6).unwrap();
    assert_eq!(
        change.changed,
        vec![
            (r2, BtcTxState::Submitted),
            (r1, BtcTxState::Replaced),
            (t, BtcTxState::Replaced)
        ]
    );
    let after = records_of(&plain);
    assert_eq!(after[0].replaced_by, Some(r1));
    assert_eq!(after[1].replaced_by, Some(r2));
    assert_eq!(
        in_flight_outpoints(&after, NET),
        second
            .inputs()
            .iter()
            .map(|input| input.outpoint)
            .chain(after[2].change_outpoint())
            .collect::<Vec<_>>()
    );
    apply_observation(
        &mut plain,
        NET,
        &r2,
        TrackObservation::Confirmed { height: TIP },
        TIP,
        7,
    )
    .unwrap();
    let after = records_of(&plain);
    assert_eq!(check_can_send(&after, NET), Ok(()));
    assert!(is_finished(&after[0], &after, Some(TIP + 5), 8));
}

/// Review fix (spec/08 §12.2): an indexer `Confirmed` of a record with an in-flight
/// replacement is held back while Core still has that replacement in its mempool.
#[test]
fn confirmation_held_for_in_flight_replacement() {
    let original = simple_plan(2, 20_000);
    let first = bump_of(&original, 3);
    let second = bump_of(&first, 6);
    let (t, r1, r2) = (original.txid(), first.txid(), second.txid());
    let mut replaced = record(&original, BtcTxState::Replaced, 1);
    replaced.replaced_by = Some(r1);
    let records = vec![replaced.clone(), record(&first, BtcTxState::InMempool, 2)];
    assert_eq!(in_flight_replacements(&records, NET, &t), vec![r1]);
    assert!(in_flight_replacements(&records, NET, &r1).is_empty());
    // Through a replaced intermediate replacement.
    let mut middle = record(&first, BtcTxState::Replaced, 2);
    middle.replaced_by = Some(r2);
    let chain = vec![replaced, middle, record(&second, BtcTxState::Submitted, 3)];
    assert_eq!(in_flight_replacements(&chain, NET, &t), vec![r2]);
    assert_eq!(in_flight_replacements(&chain, NET, &r1), vec![r2]);
    assert!(in_flight_replacements(&chain, yw_core::btc::BtcNetwork::Mainnet, &t).is_empty());
    // The guard.
    let confirmed = TrackObservation::Confirmed { height: TIP };
    assert_eq!(
        hold_confirmation(confirmed, true),
        TrackObservation::Deferred
    );
    assert_eq!(hold_confirmation(confirmed, false), confirmed);
    for other in [
        TrackObservation::InMempool,
        TrackObservation::NotFound,
        TrackObservation::NeedRawProbe,
    ] {
        assert_eq!(hold_confirmation(other, true), other);
    }
    // A held confirmation changes nothing; the replacement stays in flight.
    let mut plain = plain_of(&records);
    let before = plain.clone();
    let change =
        apply_observation(&mut plain, NET, &t, TrackObservation::Deferred, TIP, 5).unwrap();
    assert!(change.is_empty());
    assert_eq!(plain, before);
    assert_eq!(state_of(&plain, &r1), BtcTxState::InMempool);
}

/// Review fix (spec/08 §12.2-5): our change is inserted only when its output pays the P2WPKH
/// script of `(Change, index)` under this session's account.
#[test]
fn own_change_needs_the_account_script() {
    let send = simple_plan(2, 20_000);
    let change = send.change().unwrap();
    let confirmed = record(&send, BtcTxState::Confirmed, 1);
    let own = confirmed.own_change_utxo(&account()).unwrap();
    assert_eq!(own.chain, yw_core::bip32::path::BtcChain::Change);
    assert_eq!(own.index, change.index);
    assert_eq!(own.value, change.value);
    assert_eq!(own.height, TIP);
    assert!(own.own);
    // Another account (e.g. an alt-passphrase session sharing the journal): skipped.
    let other = yw_core::bip32::derive_public_child(&xpub(), 7).unwrap();
    assert_eq!(
        confirmed.own_change_utxo(&yw_core::btc::account::BtcAccountKey::primary(other)),
        None
    );
    // A recorded change index that does not derive the output's script: skipped.
    let mut wrong_index = confirmed.clone();
    wrong_index.change = Some(RecordChange {
        index: change.index + 1,
        vout: change.vout,
    });
    assert_eq!(wrong_index.own_change_utxo(&account()), None);
    // Not confirmed: nothing.
    assert_eq!(
        record(&send, BtcTxState::InMempool, 1).own_change_utxo(&account()),
        None
    );
}
