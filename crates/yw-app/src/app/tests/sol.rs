//! The tests of `app_sol.rs` that build an `App` (2026-11-21, S4 W0, spec/09 §2.1),
//! moved unchanged from its inline `mod tests` (where every test builds an `App`).
//! It was a `#[cfg(test)] #[path]` child of `crate::app_sol`, not of `app::tests`, to keep the
//! access of the inline module, so no production item of that file was widened. 2026-11-22 (S4d
//! E0c, spec/09 §2.1): a child of `app::tests` (that file moves to yw-engine at S4d E1 and these
//! tests need `App`); what it reaches is `pub(crate)` now (test-only use):
//! `Wallet::on_sol_tracked`.

use yw_core::bip32::path::AccountIndex;
use yw_core::journal::sol::{SolRecord, SolTxState};
use yw_core::slip10::SolKeySource;
use yw_core::sol::broadcast::{LoopState, Outcome};
use yw_core::sol::message::{assemble_transaction, encode_message};
use yw_core::sol::recipient::KnownKind;
use yw_core::sol::{SolAddress, SolAsset, SolCluster, SolTransferCore};

use crate::app::{App, Paths};
use yw_engine::apikeys::ApiKeys;
use yw_engine::errors::ErrorCode;
use yw_engine::events::{JournalView, SolKeysPurpose};
use yw_engine::meta::{Account, ActivityEntry, Meta, Tab};
use yw_engine::settings::Settings;
use yw_engine::sol::flow::TrackResult;
use yw_engine::wallet::app_sol::{
    ReviewRefusal, SOL_APPLY_RETRY_MS, SOL_REVIEW_CHANGED_TEXT, SOL_SAVE_FAILED_TEXT,
    SOL_SAVING_TEXT, SOL_SCAN_RECONFIRM_TEXT, ScanStage, SolHalt,
};
use yw_engine::wallet::{AppMode, Screen};

const OWN: [u8; 32] = [200; 32];
const TO_A: &str = "Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb";
const TO_B: &str = "7WktogJEd2wQ9eH2oWusmcoFTgeYi6rS632UviTBJ2jm";

/// An unlocked wallet with Solana account 0 on the send screen (mainnet, empty journal).
fn app() -> App {
    let dir = std::env::temp_dir().join(format!("yw-app-sol-ui-{}", std::process::id()));
    let mut app = App::new(
        Paths {
            data: dir.clone(),
            logs: dir.join("logs"),
        },
        true,
        Settings::default(),
        ApiKeys::default(),
    );
    app.mode = AppMode::Unlocked {
        alt_passphrase: false,
    };
    let mut meta = Meta {
        sol_accounts: vec![Account {
            index: 0,
            label: "Solana 1".to_owned(),
            address: SolAddress::from_bytes(OWN).to_base58(),
            hidden: false,
        }],
        ..Meta::default()
    };
    meta.prefs.tab = Tab::Sol;
    app.meta = Some(meta);
    app.evm.journal = Some(JournalView::default());
    app.screen = Screen::SolSend;
    app
}

fn addr(text: &str) -> SolAddress {
    SolAddress::parse(text).unwrap()
}

/// A journal record of a `T_SOL` transfer from account 0 (fake signature `[sig; 64]`).
fn record(cluster: SolCluster, state: SolTxState, to: &str, sig: u8) -> SolRecord {
    let core = SolTransferCore {
        from: SolAddress::from_bytes(OWN),
        to: addr(to),
        asset: SolAsset::Sol,
        amount: 1_000_000,
        cu_limit: 600,
        cu_price_micro: 0,
    };
    SolRecord {
        state,
        cluster,
        source: SolKeySource::Standard(AccountIndex::ZERO),
        intent_id: [sig; 16],
        intent_hash: [sig; 32],
        signed_at_ms: 1,
        last_valid_block_height: 1_150,
        terminal_slot: 0,
        terminal_err: 0,
        tx: assemble_transaction(&[sig; 64], &encode_message(&core, &[7; 32])),
        dapp: None,
    }
}

/// `app()` with one `Pending` mainnet record being tracked.
fn tracking_app() -> (App, [u8; 64]) {
    let mut app = app();
    let pending = record(SolCluster::Mainnet, SolTxState::Pending, TO_A, 0x5a);
    let signature = pending.signature();
    app.evm.journal = Some(JournalView {
        sol_records: vec![pending],
        ..JournalView::default()
    });
    app.sol_schedule_tracking();
    (app, signature)
}

fn round(signature: [u8; 64], generation: u64, outcome: Outcome) -> TrackResult {
    TrackResult {
        signature,
        state: LoopState::default(),
        outcome: Ok(outcome),
        genesis_ok: Some(true),
        sends: 0,
        generation,
    }
}

#[test]
fn a_round_from_before_a_url_change_cannot_set_or_clear_the_genesis_flag() {
    let (mut app, signature) = tracking_app();
    // A round with the genesis check runs (generation 0) when the URL changes.
    app.sol.tracking.get_mut(&signature).unwrap().busy = true;
    app.sol_url_changed(yw_engine::network::SolCluster::Mainnet);
    let state = app.sol.tracking[&signature];
    assert_eq!(state.generation, 1);
    assert!(!state.genesis_checked);
    // Its completion is stale: "checked" is not set for the new URL, nothing terminal is
    // applied, and the next round starts at once.
    app.on_sol_tracked(&round(signature, 0, Outcome::Landed { slot: 9 }));
    let state = app.sol.tracking[&signature];
    assert!(!state.busy);
    assert!(!state.genesis_checked);
    assert_eq!(state.halt, None);
    // A stale mismatch cannot halt the new URL either.
    let mut mismatch = round(signature, 0, Outcome::Pending { notice: false });
    mismatch.genesis_ok = Some(false);
    app.on_sol_tracked(&mismatch);
    assert_eq!(app.sol.tracking[&signature].halt, None);
    // The new generation's own check counts.
    app.on_sol_tracked(&round(signature, 1, Outcome::Pending { notice: false }));
    assert!(app.sol.tracking[&signature].genesis_checked);
    mismatch.generation = 1;
    app.on_sol_tracked(&mismatch);
    assert_eq!(
        app.sol.tracking[&signature].halt,
        Some(SolHalt::ClusterMismatch)
    );
    let pending = app.sol_records().remove(0);
    assert!(
        app.sol_record_status(&pending)
            .contains(ErrorCode::Rpc006.text_in(yw_core::lang::Lang::Ko).as_str())
    );
    // A URL change lifts the mismatch halt.
    app.sol_url_changed(yw_engine::network::SolCluster::Mainnet);
    assert_eq!(app.sol.tracking[&signature].halt, None);
}

#[test]
fn a_final_state_not_saved_shows_the_save_texts_not_the_cluster_text() {
    let (mut app, signature) = tracking_app();
    app.on_sol_tracked(&round(signature, 0, Outcome::Landed { slot: 9 }));
    let state = app.sol.tracking[&signature];
    assert!(matches!(state.halt, Some(SolHalt::Saving { .. })));
    let pending = app.sol_records().remove(0);
    let text = app.sol_record_status(&pending);
    assert!(text.contains(SOL_SAVING_TEXT), "{text}");
    assert!(
        !text.contains(ErrorCode::Rpc006.text_in(yw_core::lang::Lang::Ko).as_str()),
        "{text}"
    );
    // Still `Pending` in the journal long after `SolApply`: the write failed. The loop
    // resumes (to observe and save again) and says so.
    let later = app.clock.now_ms().saturating_add(SOL_APPLY_RETRY_MS);
    app.sol_tick_tracking(later);
    let state = app.sol.tracking[&signature];
    assert_eq!(state.halt, None);
    assert!(state.save_failed);
    let text = app.sol_record_status(&pending);
    assert!(text.contains(SOL_SAVE_FAILED_TEXT), "{text}");
    assert!(
        !text.contains(ErrorCode::Rpc006.text_in(yw_core::lang::Lang::Ko).as_str()),
        "{text}"
    );
    // Once the journal has the final state, the record leaves tracking.
    app.evm.journal = Some(JournalView {
        sol_records: vec![record(SolCluster::Mainnet, SolTxState::Landed, TO_A, 0x5a)],
        ..JournalView::default()
    });
    app.sol_schedule_tracking();
    assert!(app.sol.tracking.is_empty());
}

#[test]
fn only_successful_sends_on_this_cluster_make_a_recipient_known() {
    const TO_C: &str = "GjJyeC1r2RgkuoCWMyPYkCWSGSGLcz266EaAkLA27AhL";
    const TO_D: &str = "ANf3TEKFL6jPWjzkndo4CbnNdUNkBk4KHPggJs2nu8Xi";
    const TO_E: &str = "D2PPQSYFe83nDzk96FqGumVU8JA7J8vj2Rhjc2oXzEi5";
    let mut app = app();
    let row = |to: &str, status: &str, sig: u8| ActivityEntry {
        account: SolAddress::from_bytes(OWN).to_base58(),
        tx_id: SolAddress::from_bytes([sig; 32]).to_base58(),
        title: "SOL 전송".to_owned(),
        asset: "native".to_owned(),
        amount: "1".to_owned(),
        counterparty: to.to_owned(),
        status: status.to_owned(),
        time_unix_ms: u64::from(sig),
    };
    let mainnet = SolCluster::Mainnet.network_id();
    let devnet = SolCluster::Devnet.network_id();
    {
        let meta = app.meta.as_mut().unwrap();
        meta.upsert_activity(mainnet, &row(TO_A, "expired", 1));
        meta.upsert_activity(mainnet, &row(TO_B, "failed", 2));
        meta.upsert_activity(devnet, &row(TO_C, "succeeded", 3));
    }
    app.evm.journal = Some(JournalView {
        sol_records: vec![
            record(SolCluster::Mainnet, SolTxState::Pending, TO_D, 4),
            record(SolCluster::Devnet, SolTxState::Landed, TO_E, 5),
        ],
        ..JournalView::default()
    });
    let first_time = |app: &mut App, to: &str| {
        app.sol.send.to_text = to.to_owned();
        app.sol_validate_send();
        app.sol.send.check.as_ref().unwrap().first_time
    };
    // Expired, failed, pending, or a success on the other cluster: still a first time.
    for to in [TO_A, TO_B, TO_C, TO_D, TO_E] {
        assert!(first_time(&mut app, to), "{to}");
    }
    assert_eq!(
        app.sol_known()
            .iter()
            .filter(|known| known.kind == KnownKind::History)
            .count(),
        5
    );
    // A success on this cluster makes it known (activity, or a `Landed` journal record).
    app.meta
        .as_mut()
        .unwrap()
        .upsert_activity(mainnet, &row(TO_A, "succeeded", 6));
    assert!(!first_time(&mut app, TO_A));
    app.evm.journal = Some(JournalView {
        sol_records: vec![record(SolCluster::Mainnet, SolTxState::Landed, TO_D, 4)],
        ..JournalView::default()
    });
    assert!(!first_time(&mut app, TO_D));
    // On devnet the devnet successes are the known ones.
    app.settings.solana.cluster = yw_engine::network::SolCluster::Devnet;
    assert!(!first_time(&mut app, TO_C));
    assert!(first_time(&mut app, TO_A));
}

#[test]
fn the_scan_runs_only_for_the_cluster_whose_notice_was_confirmed() {
    let _ = std::fs::create_dir_all(
        std::env::temp_dir().join(format!("yw-app-sol-ui-{}", std::process::id())),
    );
    let mut app = app();
    let url = yw_platform::http::HttpsUrl::parse("https://rpc.example.test/v1").unwrap();
    for cluster in [
        yw_engine::network::SolCluster::Mainnet,
        yw_engine::network::SolCluster::Devnet,
    ] {
        app.apikeys
            .set_rpc(yw_engine::network::NetworkId::Solana(cluster), &url);
    }
    app.sol_open_scan();
    app.sol_start_scan();
    assert_eq!(app.sol.scan.stage, ScanStage::Deriving);
    assert_eq!(app.sol.scan.cluster, Some(SolCluster::Mainnet));
    // The cluster is switched while the keys are derived: back to the notice, and the keys
    // that arrive afterwards query nothing.
    assert!(app.on_sol_command(crate::ui::screens_sol::ids::CLUSTER_DEVNET));
    assert_eq!(app.sol_cluster(), SolCluster::Devnet);
    assert_eq!(app.sol.scan.stage, ScanStage::Notice);
    app.on_sol_keys(SolKeysPurpose::Scan, Ok(Vec::new()));
    assert_eq!(app.sol.scan.stage, ScanStage::Notice);
    assert_eq!(app.sol.scan.job, 0);
    // Confirmed for devnet, then the selection changes without a reset: confirm again.
    app.sol_start_scan();
    assert_eq!(app.sol.scan.cluster, Some(SolCluster::Devnet));
    app.settings.solana.cluster = yw_engine::network::SolCluster::Mainnet;
    app.on_sol_keys(SolKeysPurpose::Scan, Ok(Vec::new()));
    assert_eq!(app.sol.scan.stage, ScanStage::Notice);
    assert_eq!(
        app.sol.scan.message.as_deref(),
        Some(SOL_SCAN_RECONFIRM_TEXT)
    );
    assert_eq!(app.sol.scan.job, 0);
    // Confirmed for the selected cluster: the scan runs there.
    app.sol_start_scan();
    app.on_sol_keys(SolKeysPurpose::Scan, Ok(Vec::new()));
    assert_eq!(app.sol.scan.stage, ScanStage::Running);
    assert_eq!(app.sol.scan.cluster, Some(SolCluster::Mainnet));
    assert_ne!(app.sol.scan.job, 0);
    // A second confirmation click while it runs starts nothing.
    let job = app.sol.scan.job;
    app.sol_start_scan();
    assert_eq!(app.sol.scan.stage, ScanStage::Running);
    assert_eq!(app.sol.scan.job, job);
}

#[test]
fn review_uses_a_fresh_validation_and_refuses_a_changed_input() {
    let mut app = app();
    app.sol.send.to_text = TO_A.to_owned();
    app.sol.send.amount_text = "1".to_owned();
    app.sol_validate_send();
    assert_eq!(app.sol.send.check.as_ref().unwrap().to, addr(TO_A));
    assert_eq!(app.sol_review_blocker(), None);
    // Edits inside the debounce: the shown validation still says A / 1 SOL.
    app.sol.send.to_text = TO_B.to_owned();
    app.sol.send.dirty_ms = Some(1);
    assert_eq!(app.sol_review_item().unwrap_err(), ReviewRefusal::Changed);
    assert_eq!(app.sol.send.check.as_ref().unwrap().to, addr(TO_B));
    assert_eq!(app.sol.send.dirty_ms, None);
    // The fresh validation is now on screen: the item is built from it.
    let item = app.sol_review_item().unwrap();
    assert_eq!(item.recipient.to, addr(TO_B));
    assert_eq!(item.amount, Some(1_000_000_000));
    // The amount too.
    app.sol.send.amount_text = "2".to_owned();
    assert_eq!(app.sol_review_item().unwrap_err(), ReviewRefusal::Changed);
    assert_eq!(app.sol_review_item().unwrap().amount, Some(2_000_000_000));
    // And the asset (a token of another cluster falls back to SOL on validation).
    let devnet_usdc = yw_core::sol::template::spl_entries(yw_core::sol::SolCluster::Devnet)
        .next()
        .unwrap();
    app.sol.send.token = Some(devnet_usdc);
    assert_eq!(app.sol_review_item().unwrap_err(), ReviewRefusal::Changed);
    assert_eq!(app.sol.send.token, None);
    // `검토` itself: the fixed text, nothing queued.
    app.sol.send.to_text = TO_A.to_owned();
    app.sol_review();
    assert_eq!(app.sol.send.info.as_deref(), Some(SOL_REVIEW_CHANGED_TEXT));
    assert!(app.sol.slot.is_none());
    assert_eq!(app.sol.send.check.as_ref().unwrap().to, addr(TO_A));
    // Not reviewable (input error) is not a change.
    app.sol.send.amount_text = "x".to_owned();
    app.sol_validate_send();
    assert_eq!(app.sol_review_item().unwrap_err(), ReviewRefusal::NotReady);
}

/// spec/07 §20.9, Q6: dApp sends of account 0 are tracked side by side (one round each, with
/// its own preflight options) and never hold the send form: the one-pending rule of
/// spec/07 §1 counts wallet sends only.
#[test]
fn dapp_sends_are_tracked_together_and_do_not_hold_the_send_form() {
    use yw_core::journal::sol::{SolDappMeta, dapp_flags};

    use yw_engine::workers::rpc::RpcJob;
    let mut app = app();
    let dapp = |sig: u8, flags: u8| {
        let mut pending = record(SolCluster::Mainnet, SolTxState::Pending, TO_A, sig);
        pending.dapp = Some(SolDappMeta {
            public: OWN,
            signer_slot: 0,
            flags,
            origin: "https://app.example".to_owned(),
        });
        pending
    };
    let plain = dapp(0x61, dapp_flags::BROADCAST);
    let skip = dapp(0x62, dapp_flags::BROADCAST | dapp_flags::SKIP_PREFLIGHT);
    let (plain_id, skip_id) = (plain.signature(), skip.signature());
    app.evm.journal = Some(JournalView {
        sol_records: vec![plain, skip],
        ..JournalView::default()
    });
    app.sol_schedule_tracking();
    assert_eq!(app.sol.tracking.len(), 2);
    let (rpc, jobs) = std::sync::mpsc::channel();
    app.rpc_tx = Some(rpc);
    let url = yw_platform::http::HttpsUrl::parse("https://sol.example.test/").unwrap();
    app.apikeys.set_rpc(
        yw_engine::network::NetworkId::Solana(yw_engine::network::SolCluster::Mainnet),
        &url,
    );
    let now = app.clock.now_ms();
    app.sol_tick_tracking(now);
    let mut sent: Vec<([u8; 64], bool)> = jobs
        .try_iter()
        .filter_map(|job| match job {
            RpcJob::SolTrack(job) => Some((job.signature, job.send.skip_preflight)),
            _ => None,
        })
        .collect();
    sent.sort_unstable();
    assert_eq!(sent, vec![(plain_id, false), (skip_id, true)]);
    assert!(
        app.sol_pending(SolCluster::Mainnet, &SolAddress::from_bytes(OWN))
            .is_none()
    );
    assert_ne!(
        app.sol_review_blocker(),
        Some(yw_engine::wallet::app_sol::ReviewBlocker::InFlight)
    );
    // A wallet transfer of the account does hold it.
    let mut records = app.sol_records();
    records.push(record(SolCluster::Mainnet, SolTxState::Pending, TO_B, 0x63));
    app.evm.journal = Some(JournalView {
        sol_records: records,
        ..JournalView::default()
    });
    assert_eq!(
        app.sol_review_blocker(),
        Some(yw_engine::wallet::app_sol::ReviewBlocker::InFlight)
    );
}
