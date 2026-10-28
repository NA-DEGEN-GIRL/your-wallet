//! The key worker's journal path on real files (spec/03 §5.3–§5.4, spec/02 §5.4): a throwaway
//! vault in a temp folder (BIP-39 test vector `abandon … about`, never a real seed) signs an
//! approved Sepolia transfer prepared through the fake transport; the `Signed` record is on disk
//! before the summary is returned, survives a reload, follows Broadcast → Included → Finalized
//! and moves to meta `activity` after the 7-day retention.

mod common;

use std::path::PathBuf;

use common::evm::{S2_UNIX_MS, TestResult, USER, address, fake, job, ready, send_intent, world};
use common::{Answer, FakeClock};
use yw_app::events::{EvmSigned, KeyOutcome, SignFailure, SignInfo, SignTicket};
use yw_app::flow::evm::ChainCache;
use yw_app::flow::evm::prepare::prepare;
use yw_app::meta;
use yw_app::store::{FileStorage, LockedSlotBox};
use yw_app::workers::journal::JournalState;
use yw_core::approval::ApprovalStore;
use yw_core::codec::keccak256;
use yw_core::evm::chain::{SEPOLIA_GENESIS, sepolia};
use yw_core::evm::sign::SignError;
use yw_core::journal::evm::{Role, Transition, TxState};
use yw_core::password::VaultPassword;
use yw_core::vault::{FileKind, Vault};

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const DAY_MS: u64 = 86_400_000;

fn temp_dir(tag: &str) -> TestResult<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "yw-app-journal-{tag}-{}-{}",
        std::process::id(),
        yw_win::time::monotonic_ms()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn vault(dir: &std::path::Path) -> TestResult<Vault> {
    let mut vault = Vault::load(Box::new(
        FileStorage::open(dir).map_err(|error| format!("{error:?}"))?,
    ))?;
    let password = VaultPassword::new(b"m4-journal-test!").map_err(|error| format!("{error:?}"))?;
    let slot = Box::new(LockedSlotBox::new().map_err(|error| format!("{error:?}"))?);
    vault.import_mnemonic(&password, ABANDON, None, slot, 1_800_000_000)?;
    Ok(vault)
}

#[test]
#[expect(clippy::too_many_lines, reason = "one end-to-end journal scenario")]
fn signed_record_is_committed_then_tracked_and_moved_to_activity() -> TestResult {
    let dir = temp_dir("signed")?;
    let mut vault = vault(&dir)?;
    // Prepare and approve (fake RPC), as the UI would.
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
    let request = store.issue(prepared.draft.clone(), 1, S2_UNIX_MS)?;
    let approved = store.consume(request.id, request.digest, 2)?;
    let info = SignInfo {
        origin: "yw-app".to_owned(),
        label: request.display.title.clone(),
        role: Role::Original,
        now_unix_ms: S2_UNIX_MS,
    };
    let mut state = JournalState::default();
    let outcomes = state.sign(&mut vault, SignTicket(1), Box::new(approved), &info, false);
    let Some(KeyOutcome::SignedEvm(EvmSigned {
        ticket: SignTicket(1),
        result: Ok(summary),
    })) = outcomes.first()
    else {
        return Err(format!("not signed: {:?}", outcomes.first().map(|_| "other")).into());
    };
    assert_eq!((summary.chain_id, summary.nonce), (11_155_111, 5));
    assert_eq!(summary.account, address(USER)?);
    assert_eq!(summary.tx_hash, keccak256(&summary.raw));
    let raw = summary.raw.clone();
    let hash = summary.tx_hash;
    // The Signed record is already on disk: a fresh state reading the file sees it.
    let mut reloaded = JournalState::default();
    let view = reloaded.load(&vault)?;
    assert_eq!(view.records.len(), 1);
    let record = &view.records[0];
    assert_eq!(record.state, TxState::Signed);
    assert_eq!(record.tx_hash, hash);
    assert_eq!(record.raw, raw);
    assert_eq!(record.approval_digest, request.digest);
    assert_eq!(view.corrupt, 0);
    assert!(view.room);
    // Broadcast → Included, each committed.
    let at = S2_UNIX_MS + 1_000;
    for transition in [
        Transition::Broadcast {
            tx_hash: hash,
            at_unix_ms: at,
        },
        Transition::Included {
            tx_hash: hash,
            block_number: 100,
            block_hash: [0x5b; 32],
            success: true,
            at_unix_ms: at + 12_000,
        },
    ] {
        let outcomes = reloaded.apply(&mut vault, &[transition], at + 12_000, false);
        assert!(matches!(outcomes.first(), Some(KeyOutcome::Journal(Ok(_)))));
    }
    let view = JournalState::default().load(&vault)?;
    assert_eq!(view.records[0].state, TxState::Included);
    // An unknown hash changes nothing (no write).
    let outcomes = reloaded.apply(
        &mut vault,
        &[Transition::Broadcast {
            tx_hash: [0xaa; 32],
            at_unix_ms: at,
        }],
        at,
        false,
    );
    assert_eq!(outcomes.len(), 1);
    // Finalized, committed six days later: kept (retention counts from the terminal time).
    let finalized_at = at + 900_000;
    let outcomes = reloaded.apply(
        &mut vault,
        &[Transition::Finalized {
            tx_hash: hash,
            at_unix_ms: finalized_at,
        }],
        finalized_at + 6 * DAY_MS,
        false,
    );
    assert_eq!(outcomes.len(), 1);
    assert_eq!(
        JournalState::default().load(&vault)?.records[0].state,
        TxState::Finalized
    );
    // Signing the next transaction seven days after the terminal time first moves the group to
    // meta activity (meta first, then the journal, spec/03 §5.4-4).
    let next_at = finalized_at + 7 * DAY_MS;
    let rpc = fake(world(
        11_155_111,
        SEPOLIA_GENESIS,
        vec![(
            "eth_getTransactionCount",
            Answer::Result("\"0x6\"".to_owned()),
        )],
    ));
    let mut job = job;
    job.id = yw_core::approval::ApprovalId([8; 16]);
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
    let request = store.issue(prepared.draft.clone(), 10, S2_UNIX_MS)?;
    let approved = store.consume(request.id, request.digest, 11)?;
    let mut later = JournalState::default();
    let outcomes = later.sign(
        &mut vault,
        SignTicket(2),
        Box::new(approved),
        &SignInfo {
            now_unix_ms: next_at,
            ..info
        },
        false,
    );
    assert!(
        matches!(outcomes.first(), Some(KeyOutcome::SignedEvm(EvmSigned { ticket: SignTicket(2), result: Ok(summary) })) if summary.nonce == 6)
    );
    let moved = outcomes.iter().find_map(|outcome| match outcome {
        KeyOutcome::ActivityMoved(rows) => Some(rows.len()),
        _ => None,
    });
    assert_eq!(moved, Some(1));
    let Some((_, sidecar)) = vault.open_sidecar(FileKind::Meta)? else {
        return Err("meta".into());
    };
    let document = meta::parse(&sidecar).map_err(|_| "meta parse")?.meta;
    let activity = document.activity_of("eip155:11155111");
    assert_eq!(activity.len(), 1);
    assert_eq!(activity[0].status, "succeeded");
    assert_eq!(
        activity[0].tx_id,
        format!("0x{}", yw_core::hex::encode(&hash))
    );
    let view = JournalState::default().load(&vault)?;
    assert_eq!(view.records.len(), 1);
    assert_eq!(view.records[0].nonce, 6);
    assert_eq!(later.overlay().len(), 1);
    drop(vault);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// X-17: an approval whose account is not the signer's address fails the post-sign check
/// (`PostSignVerification`, E-TX-003) and nothing reaches the journal (so nothing is sent).
#[test]
fn post_sign_verification_failure_stores_nothing() -> TestResult {
    let dir = temp_dir("x17")?;
    let mut vault = vault(&dir)?;
    let other = address("0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb")?;
    let rpc = fake(world(11_155_111, SEPOLIA_GENESIS, Vec::new()));
    let clock = FakeClock::at(S2_UNIX_MS);
    // The account is another address while the key is account 0 of the vault.
    let job = job(sepolia(), other, send_intent()?);
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
    let request = store.issue(prepared.draft, 1, S2_UNIX_MS)?;
    let approved = store.consume(request.id, request.digest, 2)?;
    let info = SignInfo {
        origin: "yw-app".to_owned(),
        label: request.display.title.clone(),
        role: Role::Original,
        now_unix_ms: S2_UNIX_MS,
    };
    let outcomes =
        JournalState::default().sign(&mut vault, SignTicket(3), Box::new(approved), &info, false);
    assert!(matches!(
        outcomes.first(),
        Some(KeyOutcome::SignedEvm(EvmSigned {
            ticket: SignTicket(3),
            result: Err(SignFailure::Sign(SignError::PostSignVerification))
        }))
    ));
    assert_eq!(outcomes.len(), 1, "no journal view: nothing was written");
    assert!(JournalState::default().load(&vault)?.records.is_empty());
    drop(vault);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// spec/04 §1.2 with signing tickets: `Lock` cancels queued signing jobs and each answers its own
/// ticket (the UI matches waiters by ticket, never by queue order).
#[test]
fn lock_cancelled_signing_jobs_report_their_tickets() -> TestResult {
    use yw_app::events::{
        KeyJob, KeyQueue, KeyResult, LockSignal, MessageSignFailure, MessageSigned,
    };
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
    let first = store.issue(prepared.draft.clone(), 1, S2_UNIX_MS)?;
    let first = store.consume(first.id, first.digest, 2)?;
    let mut draft = prepared.draft;
    draft.id = yw_core::approval::ApprovalId([8; 16]);
    let second = store.issue(draft, 3, S2_UNIX_MS)?;
    let second = store.consume(second.id, second.digest, 4)?;
    let info = SignInfo {
        origin: "https://app.example".to_owned(),
        label: "x".to_owned(),
        role: Role::Original,
        now_unix_ms: S2_UNIX_MS,
    };
    let queue = KeyQueue::default();
    queue.push(
        1,
        KeyJob::SignEvm {
            ticket: SignTicket(11),
            approved: Box::new(first),
            info,
        },
    );
    queue.push(
        1,
        KeyJob::SignMessage {
            ticket: SignTicket(12),
            approved: Box::new(second),
            typed: false,
        },
    );
    queue.push(2, KeyJob::Lock);
    queue.push(2, KeyJob::Shutdown);
    let dir = temp_dir("lock-tickets")?;
    let results: std::sync::Mutex<Vec<KeyResult>> = std::sync::Mutex::new(Vec::new());
    yw_app::workers::key::run(
        yw_app::workers::key::KeyWorker::new(&dir),
        &queue,
        &|result| {
            if let Ok(mut list) = results.lock() {
                list.push(result);
            }
        },
        &LockSignal::default(),
    );
    let results = results.into_inner().map_err(|_| "poisoned")?;
    assert!(matches!(
        results.first().map(|result| &result.outcome),
        Some(KeyOutcome::SignedEvm(EvmSigned {
            ticket: SignTicket(11),
            result: Err(SignFailure::Locked)
        }))
    ));
    assert!(matches!(
        results.get(1).map(|result| &result.outcome),
        Some(KeyOutcome::SignedMessage(MessageSigned {
            ticket: SignTicket(12),
            result: Err(MessageSignFailure::Locked)
        }))
    ));
    assert!(matches!(
        results.get(2).map(|result| &result.outcome),
        Some(KeyOutcome::LockDone)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
