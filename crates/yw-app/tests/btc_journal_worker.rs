//! The key worker's Bitcoin journal and meta path on real files (spec/08 §3.2, §11.1–§12.4): a
//! throwaway vault in a temp folder (BIP-39 test vector `abandon … about`, testnet4, never a real
//! seed). `BtcMeta` changes are on disk before they are reported; the `Signed` record is on disk
//! before the transaction is returned; `Broadcasting` raises `change_next` (meta written first);
//! at startup `Broadcasting` becomes `BroadcastUnknown` and `change_next` is reconciled with the
//! journal; `Signed` records stay for [전송 계속] / [취소]; a damaged BTC entry stops BTC signing.

use std::path::PathBuf;

use yw_app::events::KeyOutcome;
use yw_app::meta;
use yw_app::store::{FileStorage, LockedSlotBox};
use yw_app::workers::journal::JournalState;
use yw_app::workers::journal::btc::{
    BtcJournalDone, BtcJournalOp, BtcKeyError, BtcMetaDone, BtcMetaOp, BtcRefreshUpdate,
    BtcSignFailure,
};
use yw_core::approval::{ApprovalId, ApprovalStore, Approved};
use yw_core::bip32::path::BtcChain;
use yw_core::btc::fee::{FeeChoice, FeeRate, FeeSource};
use yw_core::btc::meta::{ListedUtxo, VerifiedUtxo};
use yw_core::btc::policy::{BroadcastOutcome, MempoolAccept, SendRawResult};
use yw_core::btc::{
    BtcMeta, BtcNetwork, OutPoint, Sats, SendAmount, SendPlan, SendRequest, Txid,
    build_btc_request, parse_address, plan_send,
};
use yw_core::journal::btc::{BtcTxState, TrackObservation, TransitionError};
use yw_core::journal::{Entry, EntryKind, JournalPlain};
use yw_core::password::VaultPassword;
use yw_core::vault::{FileKind, Vault};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const RECIPIENT: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
const TIP: u32 = 157_717;
const NOW_MS: u64 = 1_793_074_713_000;

struct Fixture {
    dir: PathBuf,
    vault: Vault,
    state: JournalState,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Distinct temp folder per call (pid + counter: two tests in the same millisecond never share one).
static NEXT_DIR: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn fixture(tag: &str) -> TestResult<Fixture> {
    let dir = std::env::temp_dir().join(format!(
        "yw-app-btc-journal-{tag}-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    // A folder left by an earlier run whose pid was the same starts empty again.
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let mut vault = Vault::load(Box::new(
        FileStorage::open(&dir).map_err(|error| format!("{error:?}"))?,
    ))?;
    let password = VaultPassword::new(b"m8-journal-test!").map_err(|error| format!("{error:?}"))?;
    let slot = Box::new(LockedSlotBox::new().map_err(|error| format!("{error:?}"))?);
    vault.import_mnemonic(&password, ABANDON, None, slot, 1_793_000_000)?;
    let mut state = JournalState::default();
    state.set_btc_meta(None, yw_core::btc::BtcAccounts::default());
    Ok(Fixture { dir, vault, state })
}

fn meta_on_disk(vault: &Vault) -> TestResult<Option<BtcMeta>> {
    let Some((_, plaintext)) = vault.open_sidecar(FileKind::Meta)? else {
        return Ok(None);
    };
    let document = meta::parse(plaintext.expose())
        .map_err(|_| "meta parse")?
        .meta;
    Ok(document.btc.map(|btc| *btc))
}

fn meta_op(fixture: &mut Fixture, op: BtcMetaOp) -> TestResult<BtcMetaDone> {
    let outcomes = fixture.state.btc_meta_op(&mut fixture.vault, op, false);
    match outcomes.into_iter().next() {
        Some(KeyOutcome::BtcMeta(Ok(update))) => Ok(update.done),
        Some(KeyOutcome::BtcMeta(Err(error))) => Err(format!("{error:?}").into()),
        _ => Err("no outcome".into()),
    }
}

/// Creates the testnet4 `BtcMeta` and adds one verified 100,000-sat output at 0/0.
fn funded(fixture: &mut Fixture) -> TestResult<OutPoint> {
    meta_op(
        fixture,
        BtcMetaOp::Create {
            network: BtcNetwork::Testnet4,
        },
    )?;
    let outpoint = OutPoint {
        txid: Txid::from_bytes([0x44; 32]),
        vout: 0,
    };
    let done = meta_op(
        fixture,
        BtcMetaOp::Refreshed {
            network: BtcNetwork::Testnet4,
            account: yw_core::btc::BtcAccountId::PRIMARY,
            update: Box::new(BtcRefreshUpdate {
                listed: vec![ListedUtxo {
                    outpoint,
                    chain: BtcChain::Receive,
                    index: 0,
                    height: TIP - 10,
                }],
                newly: vec![VerifiedUtxo {
                    outpoint,
                    value: Sats::new(100_000).ok_or("sats")?,
                    chain: BtcChain::Receive,
                    index: 0,
                    height: TIP - 10,
                    is_coinbase: false,
                    own: false,
                }],
                history: vec![(BtcChain::Receive, 0, 1)],
                max_tip_seen: TIP,
                now_unix: 1_000,
            }),
        },
    )?;
    assert!(matches!(done, BtcMetaDone::Refreshed(report) if report.inserted == 1));
    Ok(outpoint)
}

fn plan(meta: &BtcMeta, seed: u8) -> TestResult<SendPlan> {
    let recipient =
        parse_address(RECIPIENT, BtcNetwork::Testnet4).map_err(|error| format!("{error:?}"))?;
    let candidates = meta.spendable(TIP, &[]);
    Ok(plan_send(&SendRequest {
        network: BtcNetwork::Testnet4,
        account: meta.account(),
        recipient,
        amount: SendAmount::Exact(Sats::new(30_000).ok_or("sats")?),
        fee: FeeChoice {
            rate: FeeRate::from_sat_per_kvb(2_000),
            source: FeeSource::Manual,
        },
        candidates: &candidates,
        tip_height: TIP,
        change_next: meta.change_next(),
        layout_seed: [seed; 32],
        typed_fee_override: None,
        conflicts: &[],
    })
    .map_err(|error| format!("{error:?}"))?)
}

fn approve(meta: &BtcMeta, plan: &SendPlan) -> TestResult<Approved> {
    let facts = meta
        .send_facts(plan, TIP, &[])
        .map_err(|error| format!("{error:?}"))?;
    let draft = build_btc_request(ApprovalId::random()?, plan, meta.account(), &facts)
        .map_err(|error| format!("{error:?}"))?;
    let mut store = ApprovalStore::new();
    let request = store.issue(draft, 1, NOW_MS)?;
    Ok(store.consume(request.id, request.digest, 2)?)
}

/// Signs `plan`; returns the txid of the committed `Signed` record.
fn sign(fixture: &mut Fixture, plan: &SendPlan) -> TestResult<Txid> {
    let meta = fixture.state.btc_meta().ok_or("meta")?.clone();
    let approved = approve(&meta, plan)?;
    let outcomes = fixture.state.sign_btc(
        &mut fixture.vault,
        Box::new(approved),
        plan,
        TIP,
        NOW_MS,
        false,
    );
    match outcomes.first() {
        Some(KeyOutcome::SignedBtc(Ok(summary))) => {
            assert_eq!(summary.network, BtcNetwork::Testnet4);
            assert_eq!(
                summary.change_index,
                plan.change().map(|change| change.index)
            );
            Ok(summary.tx.txid)
        }
        Some(KeyOutcome::SignedBtc(Err(failure))) => Err(format!("{failure:?}").into()),
        _ => Err("no signing outcome".into()),
    }
}

fn reload(fixture: &Fixture) -> TestResult<Vec<yw_core::journal::btc::BtcRecord>> {
    let mut reader = JournalState::default();
    Ok(reader.load(&fixture.vault)?.btc_records)
}

fn accept_for(fixture: &Fixture, txid: &Txid) -> TestResult<MempoolAccept> {
    let record = reload(fixture)?
        .into_iter()
        .find(|record| record.txid == *txid)
        .ok_or("record")?;
    Ok(MempoolAccept {
        txid: record.txid,
        wtxid: record.wtxid,
        allowed: true,
        vsize: Some(u64::from(record.vsize)),
        fee_base: Some(record.fee),
        reject_reason: None,
    })
}

#[test]
fn meta_changes_are_persisted_before_they_are_reported() -> TestResult {
    let mut fixture = fixture("meta")?;
    assert!(meta_on_disk(&fixture.vault)?.is_none());
    funded(&mut fixture)?;
    let stored = meta_on_disk(&fixture.vault)?.ok_or("btc meta on disk")?;
    assert_eq!(Some(&stored), fixture.state.btc_meta());
    assert_eq!(stored.verified().len(), 1);
    // Receive address: nothing issued yet (history only marks issued indices) → index 0 is
    // issued, and `receive_next` is on disk before the outcome is reported.
    let done = meta_op(
        &mut fixture,
        BtcMetaOp::ReceiveAddress {
            network: BtcNetwork::Testnet4,
            account: yw_core::btc::BtcAccountId::PRIMARY,
        },
    )?;
    assert_eq!(
        done,
        BtcMetaDone::Receive {
            index: 0,
            issued: true
        }
    );
    assert_eq!(
        meta_on_disk(&fixture.vault)?.ok_or("meta")?.receive_next(),
        1
    );
    // Shown again: the same unused index, no new issue.
    let done = meta_op(
        &mut fixture,
        BtcMetaOp::ReceiveAddress {
            network: BtcNetwork::Testnet4,
            account: yw_core::btc::BtcAccountId::PRIMARY,
        },
    )?;
    assert_eq!(
        done,
        BtcMetaDone::Receive {
            index: 0,
            issued: false
        }
    );
    let done = meta_op(
        &mut fixture,
        BtcMetaOp::NewReceiveAddress {
            network: BtcNetwork::Testnet4,
            account: yw_core::btc::BtcAccountId::PRIMARY,
            gap_confirmed: false,
        },
    )?;
    assert_eq!(
        done,
        BtcMetaDone::Receive {
            index: 1,
            issued: true
        }
    );
    assert_eq!(
        meta_on_disk(&fixture.vault)?.ok_or("meta")?.receive_next(),
        2
    );
    // A different network refuses every change.
    assert!(
        meta_op(
            &mut fixture,
            BtcMetaOp::ReceiveAddress {
                network: BtcNetwork::Mainnet,
                account: yw_core::btc::BtcAccountId::PRIMARY,
            }
        )
        .is_err()
    );
    // Every meta document the UI saves gets the worker's copy.
    let mut document = meta::Meta::default();
    fixture.state.merge_overlay(&mut document);
    assert_eq!(document.btc.as_deref(), fixture.state.btc_meta());
    Ok(())
}

#[test]
fn startup_broadcasting_becomes_broadcast_unknown() -> TestResult {
    let mut fixture = fixture("startup")?;
    funded(&mut fixture)?;
    let before = fixture.state.btc_meta().ok_or("meta")?.clone();
    let plan = plan(&before, 3)?;
    assert_eq!(plan.change().map(|change| change.index), Some(0));
    let txid = sign(&mut fixture, &plan)?;
    // On disk before the summary was returned.
    let records = reload(&fixture)?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].state, BtcTxState::Signed);
    assert_eq!(records[0].txid, txid);
    // Pre-check accepted: meta change_next first, then Broadcasting.
    let accept = accept_for(&fixture, &txid)?;
    let outcomes = fixture.state.btc_journal(
        &mut fixture.vault,
        BtcJournalOp::Precheck {
            network: BtcNetwork::Testnet4,
            txid,
            accept,
        },
        NOW_MS,
        false,
    );
    assert!(matches!(
        outcomes.first(),
        Some(KeyOutcome::BtcMeta(Ok(update))) if update.done == BtcMetaDone::ChangeNext
    ));
    assert!(matches!(
        outcomes.last(),
        Some(KeyOutcome::BtcJournal(Ok(BtcJournalDone::Broadcasting { tx, .. }))) if tx.txid == txid
    ));
    assert_eq!(
        meta_on_disk(&fixture.vault)?.ok_or("meta")?.change_next(),
        1
    );
    assert_eq!(reload(&fixture)?[0].state, BtcTxState::Broadcasting);

    // Crash after the commit (`btc.after_broadcasting`) with a meta that still had
    // change_next 0: the restart normalizes the record and reconciles change_next.
    let mut restarted = JournalState::default();
    restarted.set_btc_meta(Some(before), yw_core::btc::BtcAccounts::default());
    restarted.load(&fixture.vault)?;
    let outcomes = restarted.btc_startup(&mut fixture.vault, NOW_MS / 1_000 + 60, false);
    assert!(outcomes.iter().any(|outcome| matches!(
        outcome,
        KeyOutcome::BtcMeta(Ok(update)) if update.done == BtcMetaDone::ChangeNext
    )));
    let view = outcomes
        .iter()
        .find_map(|outcome| match outcome {
            KeyOutcome::Journal(Ok(view)) => Some(view.clone()),
            _ => None,
        })
        .ok_or("journal view")?;
    assert_eq!(view.btc_records[0].state, BtcTxState::BroadcastUnknown);
    assert_eq!(reload(&fixture)?[0].state, BtcTxState::BroadcastUnknown);
    assert_eq!(restarted.btc_meta().ok_or("meta")?.change_next(), 1);
    assert_eq!(
        meta_on_disk(&fixture.vault)?.ok_or("meta")?.change_next(),
        1
    );
    Ok(())
}

#[test]
fn signed_record_kept_at_startup_then_cancelled() -> TestResult {
    let mut fixture = fixture("signed")?;
    funded(&mut fixture)?;
    let meta = fixture.state.btc_meta().ok_or("meta")?.clone();
    let txid = sign(&mut fixture, &plan(&meta, 5)?)?;
    let mut restarted = JournalState::default();
    restarted.set_btc_meta(
        meta_on_disk(&fixture.vault)?,
        yw_core::btc::BtcAccounts::default(),
    );
    restarted.load(&fixture.vault)?;
    let outcomes = restarted.btc_startup(&mut fixture.vault, NOW_MS / 1_000, false);
    // Nothing to normalize: `Signed` stays for [전송 계속] / [취소].
    assert!(outcomes.is_empty());
    assert_eq!(reload(&fixture)?[0].state, BtcTxState::Signed);
    // In flight: a second send is refused before any key use.
    let second = plan(&meta, 6)?;
    let approved = approve(&meta, &second)?;
    let refused = restarted.sign_btc(
        &mut fixture.vault,
        Box::new(approved),
        &second,
        TIP,
        NOW_MS,
        false,
    );
    assert!(matches!(
        refused.first(),
        Some(KeyOutcome::SignedBtc(Err(BtcSignFailure::Plan(
            yw_core::btc::PlanError::InFlight
        ))))
    ));
    assert_eq!(reload(&fixture)?.len(), 1);
    // [취소].
    let outcomes = restarted.btc_journal(
        &mut fixture.vault,
        BtcJournalOp::Abandon {
            network: BtcNetwork::Testnet4,
            txid,
        },
        NOW_MS,
        false,
    );
    assert!(matches!(
        outcomes.last(),
        Some(KeyOutcome::BtcJournal(Ok(BtcJournalDone::Abandoned { .. })))
    ));
    assert_eq!(reload(&fixture)?[0].state, BtcTxState::Abandoned);
    // change_next untouched (never Broadcasting).
    assert_eq!(
        meta_on_disk(&fixture.vault)?.ok_or("meta")?.change_next(),
        0
    );
    Ok(())
}

#[test]
fn damaged_btc_entry_stops_btc_signing_only() -> TestResult {
    let mut fixture = fixture("damaged")?;
    funded(&mut fixture)?;
    let mut damaged = JournalPlain::default();
    damaged.entries.push(Entry {
        kind: EntryKind::Btc,
        body: vec![1, 2, 3],
    });
    let bytes = damaged.encode().map_err(|error| format!("{error:?}"))?;
    fixture.vault.save_sidecar(FileKind::Journal, &bytes)?;
    let mut state = JournalState::default();
    state.set_btc_meta(
        fixture.state.btc_meta().cloned(),
        yw_core::btc::BtcAccounts::default(),
    );
    let view = state.load(&fixture.vault)?;
    assert_eq!(view.btc_corrupt, 1);
    assert!(view.btc_records.is_empty());
    let meta = state.btc_meta().ok_or("meta")?.clone();
    let plan = plan(&meta, 7)?;
    let approved = approve(&meta, &plan)?;
    let outcomes = state.sign_btc(
        &mut fixture.vault,
        Box::new(approved),
        &plan,
        TIP,
        NOW_MS,
        false,
    );
    assert!(matches!(
        outcomes.first(),
        Some(KeyOutcome::SignedBtc(Err(BtcSignFailure::JournalDamaged)))
    ));
    // The damaged bytes are kept.
    let (_, disk) = fixture
        .vault
        .open_sidecar(FileKind::Journal)?
        .ok_or("journal")?;
    assert_eq!(JournalPlain::decode(disk.expose())?, damaged);
    Ok(())
}

fn journal(fixture: &mut Fixture, op: BtcJournalOp) -> Result<BtcJournalDone, BtcKeyError> {
    let outcomes = fixture
        .state
        .btc_journal(&mut fixture.vault, op, NOW_MS, false);
    match outcomes.into_iter().last() {
        Some(KeyOutcome::BtcJournal(result)) => result,
        _ => Err(BtcKeyError::Internal),
    }
}

fn tracked(txid: Txid, observation: TrackObservation) -> BtcJournalOp {
    BtcJournalOp::Tracked {
        network: BtcNetwork::Testnet4,
        tip_height: TIP,
        max_tip_seen: None,
        observations: vec![(txid, observation)],
    }
}

/// Signs and pre-checks a send of `seed` (`Broadcasting` committed).
fn broadcasting(fixture: &mut Fixture, seed: u8) -> TestResult<(SendPlan, Txid)> {
    let meta = fixture.state.btc_meta().ok_or("meta")?.clone();
    let plan = plan(&meta, seed)?;
    let txid = sign(fixture, &plan)?;
    let accept = accept_for(fixture, &txid)?;
    let done = journal(
        fixture,
        BtcJournalOp::Precheck {
            network: BtcNetwork::Testnet4,
            txid,
            accept,
        },
    )
    .map_err(|error| format!("{error:?}"))?;
    assert!(matches!(done, BtcJournalDone::Broadcasting { .. }));
    Ok((plan, txid))
}

/// Review fix (spec/08 §12.1, §12.2-3): [포기] of a `BroadcastUnknown` record right after a send
/// timeout is refused by the key worker; it is allowed once tracking did not find the
/// transaction 10 times.
#[test]
fn abandon_refused_until_not_found_limit() -> TestResult {
    let mut fixture = fixture("abandon")?;
    funded(&mut fixture)?;
    let (_, txid) = broadcasting(&mut fixture, 9)?;
    let done = journal(
        &mut fixture,
        BtcJournalOp::Sent {
            network: BtcNetwork::Testnet4,
            txid,
            result: SendRawResult::Timeout,
        },
    )
    .map_err(|error| format!("{error:?}"))?;
    assert!(matches!(
        done,
        BtcJournalDone::Sent {
            outcome: BroadcastOutcome::BroadcastUnknown { .. },
            ..
        }
    ));
    assert_eq!(reload(&fixture)?[0].state, BtcTxState::BroadcastUnknown);
    let abandon = BtcJournalOp::Abandon {
        network: BtcNetwork::Testnet4,
        txid,
    };
    for round in 0..10 {
        assert_eq!(
            journal(&mut fixture, abandon.clone()),
            Err(BtcKeyError::Journal(TransitionError::NotAllowed {
                from: BtcTxState::BroadcastUnknown,
                to: BtcTxState::Abandoned,
            })),
            "round {round}"
        );
        assert_eq!(reload(&fixture)?[0].state, BtcTxState::BroadcastUnknown);
        journal(&mut fixture, tracked(txid, TrackObservation::NotFound))
            .map_err(|error| format!("{error:?}"))?;
    }
    assert_eq!(reload(&fixture)?[0].not_found_count, 10);
    assert_eq!(
        journal(&mut fixture, abandon),
        Ok(BtcJournalDone::Abandoned { txid })
    );
    assert_eq!(reload(&fixture)?[0].state, BtcTxState::Abandoned);
    Ok(())
}

/// Review fix (spec/08 §11.3): a pre-check answering `txn-already-in-mempool` for our own
/// transaction is not `Rejected`: `change_next` is raised, the record goes through
/// `Broadcasting` to `BroadcastUnknown` without a send, and tracking moves it on.
#[test]
fn precheck_already_known_is_tracked_not_rejected() -> TestResult {
    let mut fixture = fixture("known")?;
    funded(&mut fixture)?;
    let meta = fixture.state.btc_meta().ok_or("meta")?.clone();
    let txid = sign(&mut fixture, &plan(&meta, 11)?)?;
    let mut accept = accept_for(&fixture, &txid)?;
    accept.allowed = false;
    accept.vsize = None;
    accept.fee_base = None;
    accept.reject_reason = Some("txn-already-in-mempool".to_owned());
    let outcomes = fixture.state.btc_journal(
        &mut fixture.vault,
        BtcJournalOp::Precheck {
            network: BtcNetwork::Testnet4,
            txid,
            accept,
        },
        NOW_MS,
        false,
    );
    assert!(matches!(
        outcomes.first(),
        Some(KeyOutcome::BtcMeta(Ok(update))) if update.done == BtcMetaDone::ChangeNext
    ));
    assert!(matches!(
        outcomes.last(),
        Some(KeyOutcome::BtcJournal(Ok(BtcJournalDone::PrecheckKnown { txid: known, text })))
            if *known == txid && *text == "이미 전송된 거래입니다"
    ));
    let record = reload(&fixture)?.remove(0);
    assert_eq!(record.state, BtcTxState::BroadcastUnknown);
    assert!(!record.can_abandon());
    assert_eq!(
        meta_on_disk(&fixture.vault)?.ok_or("meta")?.change_next(),
        1
    );
    // Its inputs stay in flight (never freed by `Rejected`).
    assert_eq!(
        yw_core::journal::btc::check_can_send(&reload(&fixture)?, BtcNetwork::Testnet4),
        Err(yw_core::btc::PlanError::InFlight)
    );
    journal(&mut fixture, tracked(txid, TrackObservation::InMempool))
        .map_err(|error| format!("{error:?}"))?;
    assert_eq!(reload(&fixture)?[0].state, BtcTxState::InMempool);
    Ok(())
}

/// Review fix (spec/08 §12.2-5): a confirmed record's change is inserted into `verified` only
/// by a session whose account derives the change script (not by an alt-passphrase session
/// sharing the journal).
#[test]
fn own_change_inserted_only_for_its_account() -> TestResult {
    let mut fixture = fixture("ownchange")?;
    funded(&mut fixture)?;
    let (plan, txid) = broadcasting(&mut fixture, 13)?;
    let change = plan.change().ok_or("change")?;
    journal(
        &mut fixture,
        BtcJournalOp::Sent {
            network: BtcNetwork::Testnet4,
            txid,
            result: SendRawResult::Txid(txid),
        },
    )
    .map_err(|error| format!("{error:?}"))?;
    let outpoint = OutPoint {
        txid,
        vout: change.vout,
    };
    let confirmed = TrackObservation::Confirmed { height: TIP - 1 };
    // Another account on the same journal (alt passphrase: meta in memory only).
    let main = fixture.state.btc_meta().ok_or("meta")?.clone();
    let other = yw_core::bip32::derive_public_child(main.account().xpub().ok_or("xpub")?, 9)
        .map_err(|error| format!("{error:?}"))?;
    let mut alt = JournalState::default();
    alt.set_btc_meta(
        Some(BtcMeta::new(BtcNetwork::Testnet4, other)),
        yw_core::btc::BtcAccounts::default(),
    );
    alt.load(&fixture.vault)?;
    let outcomes = alt.btc_journal(&mut fixture.vault, tracked(txid, confirmed), NOW_MS, true);
    assert!(matches!(
        outcomes.last(),
        Some(KeyOutcome::BtcJournal(Ok(BtcJournalDone::Tracked { changed })))
            if changed.contains(&(txid, BtcTxState::Confirmed))
    ));
    let alt_meta = alt.btc_meta().ok_or("alt meta")?;
    assert!(
        alt_meta
            .verified()
            .iter()
            .all(|utxo| utxo.outpoint != outpoint)
    );
    // The session of this account inserts it as its own change.
    journal(&mut fixture, tracked(txid, confirmed)).map_err(|error| format!("{error:?}"))?;
    let stored = meta_on_disk(&fixture.vault)?.ok_or("meta")?;
    let own = stored
        .verified()
        .iter()
        .find(|utxo| utxo.outpoint == outpoint)
        .ok_or("own change")?;
    assert!(own.own);
    assert_eq!(own.chain, BtcChain::Change);
    assert_eq!(own.index, change.index);
    assert_eq!(own.value, change.value);
    Ok(())
}

/// The meta `btc_accounts` document on disk.
fn accounts_on_disk(vault: &Vault) -> TestResult<yw_core::btc::BtcAccounts> {
    let Some((_, plaintext)) = vault.open_sidecar(FileKind::Meta)? else {
        return Ok(yw_core::btc::BtcAccounts::default());
    };
    Ok(meta::parse(plaintext.expose())
        .map_err(|_| "meta parse")?
        .meta
        .btc_accounts)
}

/// spec/08 §3, §12.3a: `계정 추가` (HD) and an imported key's account on the key worker: stored in
/// meta `btc_accounts` (BIP84 account 0 untouched) and selected before they are reported;
/// selection switches; a refresh of another account changes only that account; a duplicate add
/// is refused; signing for an imported account whose vault record does not exist (public data
/// only here: the record would be vault tag 4) stops with `RecordNotFound` and nothing journaled.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the account ops in order on one vault"
)]
fn accounts_are_stored_selected_and_imported_keys_need_their_record() -> TestResult {
    use yw_core::btc::{BtcAccountId, BtcAccountKey, BtcPubKey, ScriptType, SignError};
    let mut fixture = fixture("accounts")?;
    funded(&mut fixture)?;
    let primary = meta_on_disk(&fixture.vault)?.ok_or("primary")?;
    let done = meta_op(
        &mut fixture,
        BtcMetaOp::AddAccount {
            network: BtcNetwork::Testnet4,
            script_type: ScriptType::P2shP2wpkh,
        },
    )?;
    let nested = BtcAccountId::Hd {
        script_type: ScriptType::P2shP2wpkh,
        account: 0,
    };
    assert_eq!(done, BtcMetaDone::AccountAdded(nested));
    let stored = accounts_on_disk(&fixture.vault)?;
    assert_eq!(stored.selected, Some(nested));
    let added = stored
        .get(BtcNetwork::Testnet4, nested)
        .ok_or("nested account")?;
    assert!(!added.discovery_done());
    assert_eq!(
        added.account().node_text(BtcNetwork::Testnet4),
        "m/49'/1'/0'"
    );
    assert_eq!(meta_on_disk(&fixture.vault)?, Some(primary.clone()));
    // The same type again gets the next account number; the list never holds a duplicate.
    let done = meta_op(
        &mut fixture,
        BtcMetaOp::AddAccount {
            network: BtcNetwork::Testnet4,
            script_type: ScriptType::P2shP2wpkh,
        },
    )?;
    assert_eq!(
        done,
        BtcMetaDone::AccountAdded(BtcAccountId::Hd {
            script_type: ScriptType::P2shP2wpkh,
            account: 1,
        })
    );
    // A refresh of the nested account changes it only.
    let outpoint = OutPoint {
        txid: Txid::from_bytes([0x55; 32]),
        vout: 1,
    };
    meta_op(
        &mut fixture,
        BtcMetaOp::Refreshed {
            network: BtcNetwork::Testnet4,
            account: nested,
            update: Box::new(BtcRefreshUpdate {
                listed: vec![ListedUtxo {
                    outpoint,
                    chain: BtcChain::Receive,
                    index: 0,
                    height: TIP - 3,
                }],
                newly: vec![VerifiedUtxo {
                    outpoint,
                    value: Sats::new(42_000).ok_or("sats")?,
                    chain: BtcChain::Receive,
                    index: 0,
                    height: TIP - 3,
                    is_coinbase: false,
                    own: false,
                }],
                history: Vec::new(),
                max_tip_seen: TIP,
                now_unix: 1_000,
            }),
        },
    )?;
    let stored = accounts_on_disk(&fixture.vault)?;
    let nested_meta = stored.get(BtcNetwork::Testnet4, nested).ok_or("nested")?;
    // Receive 0 was never issued: the listing is applied, history ignored.
    assert_eq!(nested_meta.verified().len(), 1);
    assert_eq!(
        meta_on_disk(&fixture.vault)?.ok_or("primary")?.verified(),
        primary.verified()
    );
    // Select back.
    let done = meta_op(
        &mut fixture,
        BtcMetaOp::Select {
            network: BtcNetwork::Testnet4,
            account: BtcAccountId::PRIMARY,
        },
    )?;
    assert_eq!(done, BtcMetaDone::Selected(BtcAccountId::PRIMARY));
    assert_eq!(accounts_on_disk(&fixture.vault)?.selected, None);
    // An imported key (public data only; the secret would be vault tag 4).
    let public = yw_core::hex::decode_array::<33>(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )?;
    let key = BtcAccountKey::single([0x77; 16], ScriptType::P2tr, BtcPubKey::Compressed(public))
        .map_err(|error| format!("{error:?}"))?;
    let done = meta_op(
        &mut fixture,
        BtcMetaOp::AddImported {
            network: BtcNetwork::Testnet4,
            key,
        },
    )?;
    assert_eq!(done, BtcMetaDone::AccountAdded(key.id()));
    assert!(
        meta_op(
            &mut fixture,
            BtcMetaOp::AddImported {
                network: BtcNetwork::Testnet4,
                key,
            },
        )
        .is_err()
    );
    let stored = accounts_on_disk(&fixture.vault)?;
    let single = stored
        .get(BtcNetwork::Testnet4, key.id())
        .ok_or("imported account")?
        .clone();
    assert!(single.discovery_done() && single.is_single());
    assert_eq!(single.receive_next(), 1);
    // Fund its one address and try to sign: no vault record [0x77; 16], nothing is journaled.
    let imported_outpoint = OutPoint {
        txid: Txid::from_bytes([0x66; 32]),
        vout: 0,
    };
    meta_op(
        &mut fixture,
        BtcMetaOp::Refreshed {
            network: BtcNetwork::Testnet4,
            account: key.id(),
            update: Box::new(BtcRefreshUpdate {
                listed: vec![ListedUtxo {
                    outpoint: imported_outpoint,
                    chain: BtcChain::Receive,
                    index: 0,
                    height: TIP - 3,
                }],
                newly: vec![VerifiedUtxo {
                    outpoint: imported_outpoint,
                    value: Sats::new(80_000).ok_or("sats")?,
                    chain: BtcChain::Receive,
                    index: 0,
                    height: TIP - 3,
                    is_coinbase: false,
                    own: false,
                }],
                history: vec![(BtcChain::Receive, 0, 1)],
                max_tip_seen: TIP,
                now_unix: 1_000,
            }),
        },
    )?;
    let single = accounts_on_disk(&fixture.vault)?
        .get(BtcNetwork::Testnet4, key.id())
        .ok_or("imported account")?
        .clone();
    let plan = plan(&single, 3)?;
    assert_eq!(plan.change().map(|change| change.index), Some(0));
    let approved = approve(&single, &plan)?;
    let before = reload(&fixture)?.len();
    let outcomes = fixture.state.sign_btc(
        &mut fixture.vault,
        Box::new(approved),
        &plan,
        TIP,
        NOW_MS,
        false,
    );
    assert!(matches!(
        outcomes.first(),
        Some(KeyOutcome::SignedBtc(Err(BtcSignFailure::Sign(
            SignError::Vault(yw_core::error::VaultError::RecordNotFound)
        ))))
    ));
    assert_eq!(reload(&fixture)?.len(), before);
    Ok(())
}
