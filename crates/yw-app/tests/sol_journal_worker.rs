//! The key worker's SOL journal path on real files (spec/07 §13.1 steps 6–7, §14.1): a throwaway
//! vault in a temp folder (BIP-39 test vector `abandon`×11 `about`, never a real seed) signs an
//! approved devnet transfer; the `Pending` record is on disk before the transaction is returned,
//! the same intent cannot be signed twice (`AlreadySigned`), a late approval is refused before
//! any key use, and a `Landed` transition moves the record to meta `activity`. The v1.1 case
//! signs a devnet USDC transfer (`T_SPL`, 526-byte body) and checks the activity `asset` = mint.
//! The dApp case (spec/07 §20.8–§20.9) journals a site's send (version 3) before returning it,
//! reuses the record of the same bytes, and refuses the 17th pending send of the account.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use yw_app::events::{KeyOutcome, SignTicket, SolDappSigned, SolDappSignedSummary, SolSignFailure};
use yw_app::meta;
use yw_app::store::{FileStorage, LockedSlotBox};
use yw_app::workers::journal::{JournalState, SolDappSignJob, SolSignTimes};
use yw_core::approval::{ApprovalId, ApprovalStore, Approved};
use yw_core::bip32::path::AccountIndex;
use yw_core::error::StorageError;
use yw_core::journal::sol::{SolTransition, SolTxState};
use yw_core::password::VaultPassword;
use yw_core::policy::BrowserOrigin;
use yw_core::slip10::SolKeySource;
use yw_core::sol::dapp::{
    PreSignCheck, SolSendOptions, SolTxFacts, SolTxItemFacts, SolTxMode, SolTxRequest,
    SolTxSignError, build_sol_tx_request,
};
use yw_core::sol::display::{
    SimSummary, SolPreviewFacts, SplPreviewFacts, build_sol_transfer_request,
};
use yw_core::sol::intent::{SolTransferIntent, flags};
use yw_core::sol::message::parse_transaction;
use yw_core::sol::recipient::{AccountClass, check_recipient};
use yw_core::sol::{SolAddress, SolAsset, SolCluster, SolSignError, SolTransferCore};
use yw_core::vault::{FileKind, Vault, VaultStorage};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const FROM: &str = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
const TO: &str = "Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb";
const NOW: u64 = 1_800_000_000_000;

/// Distinct temp folder per call (pid + counter: two tests in the same millisecond never share one).
static NEXT_DIR: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn temp_dir(tag: &str) -> TestResult<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "yw-app-sol-journal-{tag}-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    // A folder left by an earlier run whose pid was the same starts empty again.
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn vault(dir: &std::path::Path) -> TestResult<Vault> {
    let mut vault = Vault::load(Box::new(
        FileStorage::open(dir).map_err(|error| format!("{error:?}"))?,
    ))?;
    let password = VaultPassword::new(b"m7-journal-test!").map_err(|error| format!("{error:?}"))?;
    let slot = Box::new(LockedSlotBox::new().map_err(|error| format!("{error:?}"))?);
    vault.import_mnemonic(&password, ABANDON, None, slot, 1_800_000_000)?;
    Ok(vault)
}

fn addr(text: &str) -> TestResult<SolAddress> {
    SolAddress::parse(text).map_err(|error| format!("{error:?}").into())
}

fn intent() -> TestResult<SolTransferIntent> {
    Ok(SolTransferIntent {
        id: [0x42; 16],
        cluster: SolCluster::Devnet,
        source: SolKeySource::Standard(AccountIndex::ZERO),
        core: SolTransferCore {
            from: addr(FROM)?,
            to: addr(TO)?,
            asset: SolAsset::Sol,
            amount: 1_000_000,
            cu_limit: 600,
            cu_price_micro: 0,
        },
        max_fee_lamports: 5_000,
        fee_cap_lamports: 100_000,
        flags: flags::FIRST_TIME,
        created_at_ms: NOW,
    })
}

fn approve(intent: &SolTransferIntent) -> TestResult<Approved> {
    let facts = SolPreviewFacts {
        account_label: "Solana 1".to_owned(),
        recipient: check_recipient(TO, &intent.core.from, &[])
            .map_err(|error| format!("{error:?}"))?,
        recipient_account: AccountClass::Missing,
        balance: 10_000_000_000,
        rent0: 890_880,
        rpc_fee: Some(5_000),
        simulation: SimSummary::Ok { units: 450 },
        spl: intent.core.asset.spl().map(|_| SplPreviewFacts {
            token_balance: Some(5_000_000),
            to_ata_exists: false,
            rent165: 2_039_280,
        }),
        blocks: Vec::new(),
    };
    let draft = build_sol_transfer_request(intent, &intent.cluster.genesis(), &facts)
        .map_err(|error| format!("{error:?}"))?;
    let mut store = ApprovalStore::new();
    let request = store.issue(draft, 1, NOW)?;
    Ok(store.consume(request.id, request.digest, 2)?)
}

fn times(consumed_at_ms: u64) -> SolSignTimes {
    SolSignTimes {
        consumed_at_ms,
        blockhash: [7; 32],
        last_valid_block_height: 1_150,
        now_unix_ms: NOW,
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one record's life: pending, every refusal while it is pending, activity"
)]
fn pending_record_first_then_already_signed_then_activity() -> TestResult {
    let dir = temp_dir("pending")?;
    let mut vault = vault(&dir)?;
    let mut state = JournalState::default();
    let now = yw_win::time::monotonic_ms();
    let outcomes = state.sign_sol(
        &mut vault,
        Box::new(approve(&intent()?)?),
        times(now),
        false,
    );
    let Some(KeyOutcome::SignedSol(Ok(summary))) = outcomes.first() else {
        return Err("not signed".into());
    };
    assert_eq!(summary.cluster, SolCluster::Devnet);
    assert_eq!(summary.from, addr(FROM)?);
    assert_eq!(summary.tx.len(), 267);
    let (core, blockhash, signature) =
        parse_transaction(&summary.tx, SolCluster::Devnet).map_err(|error| format!("{error:?}"))?;
    assert_eq!(
        (core, blockhash, signature),
        (intent()?.core, [7; 32], summary.signature)
    );
    // On disk before the summary was returned.
    let mut reloaded = JournalState::default();
    let view = reloaded.load(&vault)?;
    assert_eq!(view.sol_records.len(), 1);
    assert_eq!(view.sol_corrupt, 0);
    let record = view.sol_records.first().ok_or("no record")?;
    assert_eq!(record.state, SolTxState::Pending);
    assert_eq!(record.intent_hash, intent()?.intent_hash());
    assert_eq!(record.last_valid_block_height, 1_150);
    assert_eq!(record.tx, summary.tx);
    // ⑤ the same intent again: AlreadySigned, nothing signed or written.
    let before = std::fs::read(dir.join("journal.ywj"))?;
    let again = state.sign_sol(
        &mut vault,
        Box::new(approve(&intent()?)?),
        times(now),
        false,
    );
    assert!(matches!(
        again.first(),
        Some(KeyOutcome::SignedSol(Err(SolSignFailure::AlreadySigned)))
    ));
    assert_eq!(std::fs::read(dir.join("journal.ywj"))?, before);
    // One `Pending` per (cluster, account), checked again on the journal before signing: another
    // approved transfer of the same account is refused, nothing signed or written.
    let mut other = intent()?;
    other.id = [0x43; 16];
    let second = state.sign_sol(
        &mut vault,
        Box::new(approve(&other)?),
        times(yw_win::time::monotonic_ms()),
        false,
    );
    assert!(matches!(
        second.first(),
        Some(KeyOutcome::SignedSol(Err(SolSignFailure::Sign(
            SolSignError::PendingExists
        ))))
    ));
    assert_eq!(std::fs::read(dir.join("journal.ywj"))?, before);
    // The same account on the other cluster is not blocked by it (refused here only for the
    // deadline: ④ more than 20 s after consume, before any key use or write).
    let mut mainnet = other;
    mainnet.id = [0x45; 16];
    mainnet.cluster = SolCluster::Mainnet;
    let late = state.sign_sol(
        &mut vault,
        Box::new(approve(&mainnet)?),
        times(now.saturating_sub(20_001)),
        false,
    );
    assert!(matches!(
        late.first(),
        Some(KeyOutcome::SignedSol(Err(SolSignFailure::Sign(
            SolSignError::DeadlineExceeded
        ))))
    ));
    assert_eq!(std::fs::read(dir.join("journal.ywj"))?, before);
    // Landed: moved to meta activity (solana:devnet) and removed from the journal.
    let moved = state.apply_sol(
        &mut vault,
        &SolTransition::Landed {
            signature: summary.signature,
            slot: 77,
        },
        NOW + 5_000,
        false,
    );
    let Some(KeyOutcome::Journal(Ok(view))) = moved.first() else {
        return Err("no journal view".into());
    };
    assert!(view.sol_records.is_empty());
    let Some(KeyOutcome::ActivityMoved(rows)) = moved.get(1) else {
        return Err("no activity".into());
    };
    let (network, entry) = rows.first().ok_or("empty activity")?;
    assert_eq!(network.to_string(), "solana:devnet");
    assert_eq!(entry.status, "succeeded");
    assert_eq!(entry.account, FROM);
    assert_eq!(entry.counterparty, TO);
    assert_eq!(entry.amount, "1000000");
    assert_eq!(entry.asset, "native");
    assert_eq!(
        entry.tx_id,
        yw_core::codec::base58::base58_encode(&summary.signature)
    );
    assert_eq!(
        entry.title,
        "[Solana devnet (테스트)] SOL 전송: 0.001000000 SOL"
    );
    let (_, plaintext) = vault.open_sidecar(FileKind::Meta)?.ok_or("meta missing")?;
    let document = meta::parse(plaintext.expose())
        .map_err(|_| "meta parse")?
        .meta;
    assert_eq!(document.activity_of("solana:devnet").len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Storage whose next journal commit fails: `Some(true)` after the bytes reached the disk,
/// `Some(false)` without writing.
struct FlakyJournal {
    inner: FileStorage,
    next: Arc<Mutex<Option<bool>>>,
}

impl VaultStorage for FlakyJournal {
    fn load(&self, kind: FileKind) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.load(kind)
    }

    fn load_prev(&self, kind: FileKind) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.load_prev(kind)
    }

    fn commit(
        &mut self,
        kind: FileKind,
        expected_generation: Option<u64>,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        let fail = if kind == FileKind::Journal {
            self.next.lock().map_or(None, |mut next| next.take())
        } else {
            None
        };
        match fail {
            None => self.inner.commit(kind, expected_generation, bytes),
            Some(false) => Err(StorageError::Io(5)),
            Some(true) => {
                self.inner.commit(kind, expected_generation, bytes)?;
                Err(StorageError::Io(1_117))
            }
        }
    }

    fn quarantine(&mut self, kind: FileKind, now_unix: u64) -> Result<(), StorageError> {
        self.inner.quarantine(kind, now_unix)
    }
}

/// spec/07 §13.1-7: a journal write that failed leaves nothing and returns no transaction; one
/// that reached the disk but reported a failure is read back and tracked as written (it would be
/// resumed after a restart, so it must never be reported as "not sent").
#[test]
fn pending_write_reported_failed_but_on_disk_is_tracked() -> TestResult {
    let dir = temp_dir("flaky")?;
    let next = Arc::new(Mutex::new(None));
    let mut vault = Vault::load(Box::new(FlakyJournal {
        inner: FileStorage::open(&dir).map_err(|error| format!("{error:?}"))?,
        next: Arc::clone(&next),
    }))?;
    let password = VaultPassword::new(b"m7-journal-test!").map_err(|error| format!("{error:?}"))?;
    let slot = Box::new(LockedSlotBox::new().map_err(|error| format!("{error:?}"))?);
    vault.import_mnemonic(&password, ABANDON, None, slot, 1_800_000_000)?;
    let mut state = JournalState::default();
    // Really failed: no transaction, nothing on disk.
    *next.lock().map_err(|_| "lock")? = Some(false);
    let failed = state.sign_sol(
        &mut vault,
        Box::new(approve(&intent()?)?),
        times(yw_win::time::monotonic_ms()),
        false,
    );
    assert!(matches!(
        failed.first(),
        Some(KeyOutcome::SignedSol(Err(SolSignFailure::JournalWrite(_))))
    ));
    assert!(JournalState::default().load(&vault)?.sol_records.is_empty());
    // Written, but reported failed: tracked as written.
    *next.lock().map_err(|_| "lock")? = Some(true);
    let mut landed_anyway = intent()?;
    landed_anyway.id = [0x44; 16];
    let outcomes = state.sign_sol(
        &mut vault,
        Box::new(approve(&landed_anyway)?),
        times(yw_win::time::monotonic_ms()),
        false,
    );
    let Some(KeyOutcome::SignedSol(Ok(summary))) = outcomes.first() else {
        return Err(format!("not tracked: {:?}", outcomes.first()).into());
    };
    let Some(KeyOutcome::Journal(Ok(view))) = outcomes.get(1) else {
        return Err("no journal view".into());
    };
    assert_eq!(view.sol_records.len(), 1);
    let on_disk = JournalState::default().load(&vault)?;
    let record = on_disk.sol_records.first().ok_or("no record on disk")?;
    assert_eq!(record.state, SolTxState::Pending);
    assert_eq!(record.signature(), summary.signature);
    assert_eq!(record.intent_hash, landed_anyway.intent_hash());
    // Later writes still work (the generation was re-read with the journal).
    let moved = state.apply_sol(
        &mut vault,
        &SolTransition::Landed {
            signature: summary.signature,
            slot: 9,
        },
        NOW + 5_000,
        false,
    );
    assert!(
        matches!(moved.first(), Some(KeyOutcome::Journal(Ok(view))) if view.sol_records.is_empty())
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// v1.1: a devnet USDC transfer through the key worker — `T_SPL` (437 bytes) journaled as a
/// 526-byte body, then `FailedOnChain` → activity with `asset` = the devnet USDC mint.
#[test]
fn spl_transfer_is_journaled_and_its_activity_names_the_mint() -> TestResult {
    let dir = temp_dir("spl")?;
    let mut vault = vault(&dir)?;
    let mut state = JournalState::default();
    let entry = yw_core::sol::template::spl_entries(SolCluster::Devnet)
        .next()
        .ok_or("no devnet token")?;
    let mut spl = intent()?;
    spl.id = [0x55; 16];
    spl.core.asset = SolAsset::Spl(entry);
    spl.core.amount = 2_500_000;
    spl.core.cu_limit = yw_core::sol::fee::SPL_TRANSFER_CU_LIMIT;
    spl.max_fee_lamports = 5_000;
    let outcomes = state.sign_sol(
        &mut vault,
        Box::new(approve(&spl)?),
        times(yw_win::time::monotonic_ms()),
        false,
    );
    let Some(KeyOutcome::SignedSol(Ok(summary))) = outcomes.first() else {
        return Err("not signed".into());
    };
    assert_eq!(summary.tx.len(), 437);
    let (core, _, _) =
        parse_transaction(&summary.tx, SolCluster::Devnet).map_err(|error| format!("{error:?}"))?;
    assert_eq!(core, spl.core);
    let mut reloaded = JournalState::default();
    let view = reloaded.load(&vault)?;
    let record = view.sol_records.first().ok_or("no record")?;
    assert_eq!(record.encode().map_err(|_| "encode")?.len(), 526);
    let moved = state.apply_sol(
        &mut vault,
        &SolTransition::FailedOnChain {
            signature: summary.signature,
            slot: 78,
            err: yw_core::sol::broadcast::err::TOKEN_INSTRUCTION,
        },
        NOW + 5_000,
        false,
    );
    let Some(KeyOutcome::ActivityMoved(rows)) = moved.get(1) else {
        return Err("no activity".into());
    };
    let (network, activity) = rows.first().ok_or("empty activity")?;
    assert_eq!(network.to_string(), "solana:devnet");
    assert_eq!(activity.status, "failed");
    assert_eq!(
        activity.asset,
        "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
    );
    assert_eq!(activity.amount, "2500000");
    assert_eq!(activity.counterparty, TO);
    assert_eq!(
        activity.title,
        "[Solana devnet (테스트)] 토큰 전송: 2.500000 USDC"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// A legacy dApp transaction account 0 signs and pays for: one unknown-program instruction
/// with data `[tag]` (blockhash `[7; 32]`).
fn dapp_tx(tag: u8) -> TestResult<Vec<u8>> {
    let mut out = vec![1_u8];
    out.extend_from_slice(&[0; 64]);
    out.extend_from_slice(&[1, 0, 1, 2]);
    out.extend_from_slice(&addr(FROM)?.to_bytes());
    out.extend_from_slice(&[5; 32]);
    out.extend_from_slice(&[7; 32]);
    out.extend_from_slice(&[1, 1, 1, 0, 1, tag]);
    Ok(out)
}

/// An approved `sol_signAndSendTransaction` of [`dapp_tx`]`(tag)` (approval id `[id; 16]`).
fn approve_send(tag: u8, id: u8) -> TestResult<Approved> {
    let request = SolTxRequest {
        id: ApprovalId([id; 16]),
        origin: BrowserOrigin::parse("https://app.example").ok_or("origin")?,
        cluster: SolCluster::Devnet,
        source: SolKeySource::Standard(AccountIndex::ZERO),
        public: addr(FROM)?.to_bytes(),
        label: "Solana 1".to_owned(),
        mode: SolTxMode::SignAndSend,
        options: SolSendOptions {
            skip_preflight: true,
            preflight_commitment: None,
            min_context_slot: Some(77),
        },
        txs: vec![dapp_tx(tag)?],
    };
    let facts = SolTxFacts {
        items: vec![SolTxItemFacts {
            tables: Ok((0, Vec::new())),
            pre: Vec::new(),
            post: None,
            sim: SimSummary::NoResult,
            sim_replaced_blockhash: false,
            rpc_fee: Some(5_000),
            blockhash_valid: Some(true),
        }],
        mints: Vec::new(),
        unread_mints: Vec::new(),
        known: Vec::new(),
        fee_cap: 100_000,
    };
    let draft = build_sol_tx_request(&request, &facts).map_err(|error| format!("{error:?}"))?;
    let mut store = ApprovalStore::new();
    let issued = store.issue(draft, 1, NOW)?;
    Ok(store.consume(issued.id, issued.digest, 2)?)
}

/// The pre-sign part of a send job: the check found blockhash `[7; 32]` valid just now.
fn dapp_job(ticket: u64, consumed_at_ms: u64) -> SolDappSignJob {
    SolDappSignJob {
        ticket: SignTicket(ticket),
        consumed_at_ms,
        last_valid_block_height: 1_150,
        now_unix_ms: NOW,
        check: PreSignCheck {
            blockhash: [7; 32],
            loaded: None,
        },
        origin: "https://app.example".to_owned(),
    }
}

/// `sign_sol_dapp` of [`dapp_tx`]`(tag)` approved as `id`.
fn sign_dapp(
    state: &mut JournalState,
    vault: &mut Vault,
    tag: u8,
    id: u8,
    consumed_at_ms: u64,
) -> TestResult<Vec<KeyOutcome>> {
    Ok(state.sign_sol_dapp(
        vault,
        Box::new(approve_send(tag, id)?),
        dapp_job(u64::from(id), consumed_at_ms),
        false,
    ))
}

/// spec/07 §20.8, §20.9: a dApp send is journaled (version 3) before it is returned — next to
/// a wallet transfer of the same account still pending (the one-pending rule is the wallet's
/// own) — with the dApp's origin and options; the same bytes approved again write nothing and
/// return the same transaction id; a late signing is refused before any key use; the 17th
/// pending send of the account is -32002 (`TooManyPending`); a landed send moves to activity
/// as a site transaction.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one account's dApp sends: pending, reuse, refusals, activity"
)]
fn dapp_send_is_journaled_first_reused_and_capped() -> TestResult {
    let dir = temp_dir("dapp")?;
    let mut vault = vault(&dir)?;
    let mut state = JournalState::default();
    let transfer = state.sign_sol(
        &mut vault,
        Box::new(approve(&intent()?)?),
        times(yw_win::time::monotonic_ms()),
        false,
    );
    assert!(matches!(
        transfer.first(),
        Some(KeyOutcome::SignedSol(Ok(_)))
    ));
    let outcomes = sign_dapp(&mut state, &mut vault, 1, 1, yw_win::time::monotonic_ms())?;
    let Some(KeyOutcome::SignedSolDapp(SolDappSigned {
        ticket: SignTicket(1),
        result: Ok(summary),
    })) = outcomes.first()
    else {
        return Err(format!("not signed: {outcomes:?}").into());
    };
    assert!(!summary.reused);
    assert_eq!(summary.cluster, SolCluster::Devnet);
    assert_eq!(summary.min_context_slot, Some(77));
    // The wallet pays: signature 0 is ours and the transaction id.
    assert_eq!(summary.tx_id, summary.own_signature);
    let message = summary.tx.get(65..).ok_or("message")?;
    assert_eq!(Some(message), dapp_tx(1)?.get(65..));
    assert!(yw_core::sol::keys::verify_strict(
        &addr(FROM)?.to_bytes(),
        message,
        &summary.tx_id
    ));
    // On disk before the summary was returned.
    let view = JournalState::default().load(&vault)?;
    assert_eq!(view.sol_corrupt, 0);
    let record = view
        .sol_records
        .iter()
        .find(|record| record.dapp.is_some())
        .ok_or("no dApp record")?;
    assert_eq!(record.state, SolTxState::Pending);
    assert_eq!(record.signature(), summary.tx_id);
    assert_eq!(record.tx, summary.tx);
    assert_eq!(record.last_valid_block_height, 1_150);
    assert_eq!(
        record.dapp.as_ref().map(|dapp| dapp.origin.as_str()),
        Some("https://app.example")
    );
    assert_eq!(
        record.send_flags(),
        Some((true, yw_core::sol::dapp::SolCommitment::Confirmed))
    );
    assert!(record.core().is_none());
    // The same bytes approved again: the same id, nothing written.
    let before = std::fs::read(dir.join("journal.ywj"))?;
    let again = sign_dapp(&mut state, &mut vault, 1, 2, yw_win::time::monotonic_ms())?;
    let Some(KeyOutcome::SignedSolDapp(SolDappSigned {
        result: Ok(repeat), ..
    })) = again.first()
    else {
        return Err(format!("not reused: {again:?}").into());
    };
    assert!(repeat.reused);
    assert_eq!(repeat.tx_id, summary.tx_id);
    assert_eq!(std::fs::read(dir.join("journal.ywj"))?, before);
    // More than 20 s after the pre-sign answer: refused before any key use or write.
    let late = sign_dapp(
        &mut state,
        &mut vault,
        2,
        3,
        yw_win::time::monotonic_ms().saturating_sub(20_001),
    )?;
    assert!(matches!(
        late.first(),
        Some(KeyOutcome::SignedSolDapp(SolDappSigned {
            result: Err(SolSignFailure::DappSign(SolTxSignError::DeadlineExceeded)),
            ..
        }))
    ));
    assert_eq!(std::fs::read(dir.join("journal.ywj"))?, before);
    // Up to 16 pending sends of the account; the 17th is refused.
    for tag in 2..=16 {
        let signed = sign_dapp(
            &mut state,
            &mut vault,
            tag,
            tag + 10,
            yw_win::time::monotonic_ms(),
        )?;
        assert!(
            matches!(
                signed.first(),
                Some(KeyOutcome::SignedSolDapp(SolDappSigned {
                    result: Ok(SolDappSignedSummary { reused: false, .. }),
                    ..
                }))
            ),
            "send {tag}"
        );
    }
    let before = std::fs::read(dir.join("journal.ywj"))?;
    let refused = sign_dapp(&mut state, &mut vault, 17, 40, yw_win::time::monotonic_ms())?;
    assert!(matches!(
        refused.first(),
        Some(KeyOutcome::SignedSolDapp(SolDappSigned {
            result: Err(SolSignFailure::TooManyPending),
            ..
        }))
    ));
    assert_eq!(std::fs::read(dir.join("journal.ywj"))?, before);
    let view = JournalState::default().load(&vault)?;
    assert_eq!(
        view.sol_records
            .iter()
            .filter(|record| record.dapp.is_some())
            .count(),
        16
    );
    // Landed: a site transaction in activity.
    let moved = state.apply_sol(
        &mut vault,
        &SolTransition::Landed {
            signature: summary.tx_id,
            slot: 77,
        },
        NOW + 5_000,
        false,
    );
    let Some(KeyOutcome::ActivityMoved(rows)) = moved.get(1) else {
        return Err("no activity".into());
    };
    let (network, entry) = rows.first().ok_or("empty activity")?;
    assert_eq!(network.to_string(), "solana:devnet");
    assert_eq!(entry.status, "succeeded");
    assert_eq!(entry.account, FROM);
    assert_eq!(entry.counterparty, "");
    assert_eq!(
        entry.tx_id,
        yw_core::codec::base58::base58_encode(&summary.tx_id)
    );
    assert!(
        entry.title.contains("사이트 거래 · https://app.example"),
        "{}",
        entry.title
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
