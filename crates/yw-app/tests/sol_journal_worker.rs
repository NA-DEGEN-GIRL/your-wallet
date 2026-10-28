//! The key worker's SOL journal path on real files (spec/07 §13.1 steps 6–7, §14.1): a throwaway
//! vault in a temp folder (BIP-39 test vector `abandon`×11 `about`, never a real seed) signs an
//! approved devnet transfer; the `Pending` record is on disk before the transaction is returned,
//! the same intent cannot be signed twice (`AlreadySigned`), a late approval is refused before
//! any key use, and a `Landed` transition moves the record to meta `activity`. The v1.1 case
//! signs a devnet USDC transfer (`T_SPL`, 526-byte body) and checks the activity `asset` = mint.

use std::path::PathBuf;

use yw_app::events::{KeyOutcome, SolSignFailure};
use yw_app::meta;
use yw_app::store::{FileStorage, LockedSlotBox};
use yw_app::workers::journal::{JournalState, SolSignTimes};
use yw_core::approval::{ApprovalStore, Approved};
use yw_core::bip32::path::AccountIndex;
use yw_core::journal::sol::{SolTransition, SolTxState};
use yw_core::password::VaultPassword;
use yw_core::slip10::SolKeySource;
use yw_core::sol::display::{
    SimSummary, SolPreviewFacts, SplPreviewFacts, build_sol_transfer_request,
};
use yw_core::sol::intent::{SolTransferIntent, flags};
use yw_core::sol::message::parse_transaction;
use yw_core::sol::recipient::{AccountClass, check_recipient};
use yw_core::sol::{SolAddress, SolAsset, SolCluster, SolSignError, SolTransferCore};
use yw_core::vault::{FileKind, Vault};

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
    let draft = build_sol_transfer_request(intent, &SolCluster::Devnet.genesis(), &facts)
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
    // ④ more than 20 s after consume: refused before any key use or write.
    let mut other = intent()?;
    other.id = [0x43; 16];
    let late = state.sign_sol(
        &mut vault,
        Box::new(approve(&other)?),
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
