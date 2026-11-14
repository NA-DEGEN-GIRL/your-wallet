//! Imported keys through the key worker on real files (spec/02 §8.4–§8.5, spec/04 §2.18,
//! spec/07 §3.4): "개인키로 시작하기" builds a key-only vault (no recovery words) from a Solana
//! keypair, takes EVM and Bitcoin keys, reopens straight to `Unlocked`, reveals and removes them
//! (never the last one); and an imported Solana key in a mnemonic wallet goes through the SOL
//! send pipeline — preview over the scripted RPC, approval, signing in the key worker with the
//! `Pending` record on disk. Public test vectors only (RFC 8032 test 1, spec/07 §17.1, BIP84).

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use common::{Answer, FakeRpc, url};
use yw_app::events::{ImportedAccount, KeyJob, KeyOutcome, RevealWhat};
use yw_app::sol::flow::{PreviewJob, PreviewOutcome, SolEndpoint, preview};
use yw_app::store::{FileStorage, LockedSlotBox};
use yw_app::workers::journal::btc::BtcMetaDone;
use yw_app::workers::journal::{JournalState, SolSignTimes};
use yw_app::workers::key::KeyWorker;
use yw_core::approval::ApprovalStore;
use yw_core::bip32::path::BtcChain;
use yw_core::btc::{BtcAccountId, BtcNetwork, ScriptType};
use yw_core::codec::base58;
use yw_core::error::{KeyError, VaultError};
use yw_core::keyimport::{ImportKey, ImportPreview, ImportSpec};
use yw_core::password::VaultPassword;
use yw_core::secret::Zeroizing;
use yw_core::slip10::SolKeySource;
use yw_core::sol::display::build_sol_transfer_request;
use yw_core::sol::keys::verify_strict;
use yw_core::sol::message::parse_transaction;
use yw_core::sol::recipient::check_recipient;
use yw_core::sol::{SolAddress, SolAsset, SolCluster};
use yw_core::vault::{Vault, VaultStatus};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const PASSWORD: &[u8] = b"key-import test password";
const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// spec/07 §17.1: abandon `m/44'/501'/0'/0'`.
const ABANDON_SOL_SEED: &str = "37df573b3ac4ad5b522e064e25b63ea16bcbe79d449e81a0268d1047948bb445";
const ABANDON_SOL_ADDRESS: &str = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
/// RFC 8032 test 1.
const RFC8032_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const RFC8032_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
/// BIP84 test vector (abandon `m/84'/0'/0'/0/0`).
const BIP84_WIF: &str = "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d";
const BIP84_ADDRESS: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
const DEVNET_GENESIS: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
const TO: &str = "Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb";
const BLOCKHASH: &str = "US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx";

static NEXT_DIR: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn temp_dir(tag: &str) -> TestResult<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "yw-app-keys-{tag}-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn keypair(seed_hex: &str, public: &[u8; 32]) -> TestResult<String> {
    let mut pair = yw_core::hex::decode(seed_hex).map_err(|error| format!("{error:?}"))?;
    pair.extend_from_slice(public);
    Ok(base58::encode(&pair))
}

fn abandon_keypair() -> TestResult<String> {
    keypair(
        ABANDON_SOL_SEED,
        &base58::base58_decode_32(ABANDON_SOL_ADDRESS).map_err(|error| format!("{error:?}"))?,
    )
}

fn bytes(text: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(text.as_bytes().to_vec())
}

/// Runs one job and returns its only outcome.
fn one(worker: &mut KeyWorker, job: KeyJob) -> TestResult<KeyOutcome> {
    let mut outcomes = worker.handle(job);
    if outcomes.len() != 1 {
        return Err(format!("{} outcomes", outcomes.len()).into());
    }
    outcomes.pop().ok_or_else(|| "no outcome".into())
}

fn imported(outcome: KeyOutcome) -> TestResult<ImportedAccount> {
    match outcome {
        KeyOutcome::KeyImported(Ok(account)) => Ok(account),
        KeyOutcome::KeyImported(Err(error)) => Err(format!("import refused: {error:?}").into()),
        _ => Err("not an import outcome".into()),
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one key-only wallet: create, import, reopen, reveal, remove"
)]
fn key_only_vault_through_the_key_worker() -> TestResult {
    let dir = temp_dir("keyonly")?;
    let mut worker = KeyWorker::new(&dir);
    assert!(matches!(
        one(&mut worker, KeyJob::Load)?,
        KeyOutcome::Loaded {
            status: VaultStatus::NoVault,
            ..
        }
    ));
    // Nothing to commit before a preview.
    assert!(matches!(
        one(&mut worker, KeyJob::CommitKeyStart)?,
        KeyOutcome::KeyStartCommitted(Err(VaultError::InvalidState))
    ));
    // First a Bitcoin WIF as taproot (S19 shows a bc1p address), then "다릅니다".
    let KeyOutcome::KeyStartPreview(Ok(ImportPreview::Btc(info))) = one(
        &mut worker,
        KeyJob::PreviewKeyStart {
            password: Some(Zeroizing::new(PASSWORD.to_vec())),
            spec: ImportSpec::Btc(ScriptType::P2tr),
            key: bytes(BIP84_WIF),
        },
    )?
    else {
        return Err("no taproot preview".into());
    };
    assert!(info.address.starts_with("bc1p"));
    one(
        &mut worker,
        KeyJob::DiscardKeyStart {
            keep_password: true,
        },
    )?;
    // An address pasted instead of a key: E-INP-021, the password stays held.
    assert!(matches!(
        one(
            &mut worker,
            KeyJob::PreviewKeyStart {
                password: None,
                spec: ImportSpec::Sol,
                key: bytes(ABANDON_SOL_ADDRESS),
            },
        )?,
        KeyOutcome::KeyStartPreview(Err(KeyError::SolKeyIsAddress))
    ));
    let KeyOutcome::KeyStartPreview(Ok(ImportPreview::Sol(address))) = one(
        &mut worker,
        KeyJob::PreviewKeyStart {
            password: None,
            spec: ImportSpec::Sol,
            key: bytes(&abandon_keypair()?),
        },
    )?
    else {
        return Err("no Solana preview".into());
    };
    assert_eq!(address.to_base58(), ABANDON_SOL_ADDRESS);
    assert!(matches!(
        one(&mut worker, KeyJob::CommitKeyStart)?,
        KeyOutcome::KeyStartCommitted(Ok(()))
    ));
    // The default meta of a key-only wallet.
    let KeyOutcome::Meta(Ok(loaded)) = one(&mut worker, KeyJob::LoadMeta)? else {
        return Err("meta".into());
    };
    assert!(!loaded.has_mnemonic);
    assert!(loaded.meta.evm_accounts.is_empty() && loaded.meta.sol_accounts.is_empty());
    assert_eq!(loaded.meta.sol_raw_accounts.len(), 1);
    assert_eq!(
        loaded.meta.sol_raw_selected,
        loaded
            .meta
            .sol_raw_accounts
            .first()
            .map(|raw| raw.record_id)
    );
    assert!(!loaded.mismatch, "the written meta matches the vault");
    // EVM and Bitcoin keys join; a duplicate Solana key is refused.
    let ImportedAccount::Evm(evm_id, evm_address) = imported(one(
        &mut worker,
        KeyJob::ImportKey {
            spec: ImportSpec::Evm,
            key: bytes(&format!("0x{}1", "0".repeat(63))),
        },
    )?)?
    else {
        return Err("not EVM".into());
    };
    assert_eq!(
        evm_address.to_checksum(),
        "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
    );
    let ImportedAccount::Btc(btc_id, btc_info) = imported(one(
        &mut worker,
        KeyJob::ImportKey {
            spec: ImportSpec::Btc(ScriptType::P2wpkh),
            key: bytes(BIP84_WIF),
        },
    )?)?
    else {
        return Err("not Bitcoin".into());
    };
    assert_eq!(btc_info.address, BIP84_ADDRESS);
    // Its Bitcoin account (the UI sends `AddImported` with it; meta load adds a missing one).
    let btc_account = btc_info
        .account_key(*btc_id.as_bytes())
        .map_err(|error| format!("{error:?}"))?;
    assert_eq!(
        btc_account
            .address(BtcNetwork::Mainnet, BtcChain::Receive, 0)?
            .as_str(),
        BIP84_ADDRESS
    );
    assert!(matches!(
        one(
            &mut worker,
            KeyJob::ImportKey {
                spec: ImportSpec::Sol,
                key: bytes(&abandon_keypair()?),
            },
        )?,
        KeyOutcome::KeyImported(Err(VaultError::DuplicateKey))
    ));
    // Lock, reload, unlock: straight to `Unlocked`; meta lists all three keys.
    one(&mut worker, KeyJob::Lock)?;
    assert!(matches!(
        one(&mut worker, KeyJob::Load)?,
        KeyOutcome::Loaded {
            status: VaultStatus::Locked,
            ..
        }
    ));
    assert!(matches!(
        one(
            &mut worker,
            KeyJob::Unlock {
                password: Zeroizing::new(PASSWORD.to_vec())
            }
        )?,
        KeyOutcome::Status(Ok(VaultStatus::Unlocked {
            alt_passphrase: false
        }))
    ));
    let KeyOutcome::Meta(Ok(loaded)) = one(&mut worker, KeyJob::LoadMeta)? else {
        return Err("meta".into());
    };
    assert!(!loaded.has_mnemonic);
    // The tag-4 record had no account yet (no `AddImported` in this test): meta load adds it.
    assert!(loaded.mismatch);
    assert_eq!(
        (
            loaded.meta.evm_raw_accounts.len(),
            loaded.meta.sol_raw_accounts.len(),
            loaded.meta.btc_accounts.accounts.len()
        ),
        (1, 1, 1)
    );
    assert_eq!(
        loaded
            .meta
            .btc_accounts
            .get(BtcNetwork::Mainnet, btc_account.id())
            .map(|meta| *meta.account()),
        Some(btc_account)
    );
    // Written back: the next load matches.
    let KeyOutcome::Meta(Ok(again)) = one(&mut worker, KeyJob::LoadMeta)? else {
        return Err("meta".into());
    };
    assert!(!again.mismatch);
    // Reveal gives the WIF back.
    let KeyOutcome::Revealed(Ok((_, wif, None))) = one(
        &mut worker,
        KeyJob::Reveal {
            password: Zeroizing::new(PASSWORD.to_vec()),
            what: RevealWhat::ImportedKey(btc_id),
        },
    )?
    else {
        return Err("reveal".into());
    };
    assert_eq!(wif.expose(), BIP84_WIF);
    // Removal: the password is checked; the last key stays.
    assert!(matches!(
        one(
            &mut worker,
            KeyJob::RemoveImportedKey {
                password: Zeroizing::new(b"wrong password 123".to_vec()),
                id: evm_id,
            },
        )?,
        KeyOutcome::ImportedKeyRemoved(Err(VaultError::UnlockFailed))
    ));
    assert!(matches!(
        one(
            &mut worker,
            KeyJob::RemoveImportedKey {
                password: Zeroizing::new(PASSWORD.to_vec()),
                id: evm_id,
            },
        )?,
        KeyOutcome::ImportedKeyRemoved(Ok(_))
    ));
    // The Bitcoin key: the vault record, then its account in meta `btc_accounts`.
    let outcomes = worker.handle(KeyJob::RemoveImportedKey {
        password: Zeroizing::new(PASSWORD.to_vec()),
        id: btc_id,
    });
    assert!(matches!(
        outcomes.first(),
        Some(KeyOutcome::ImportedKeyRemoved(Ok(_)))
    ));
    let Some(KeyOutcome::BtcMeta(Ok(update))) = outcomes.get(1) else {
        return Err("no BtcMeta outcome after removing the Bitcoin key".into());
    };
    assert_eq!(
        update.done,
        BtcMetaDone::Removed(BtcAccountId::Imported {
            id: *btc_id.as_bytes()
        })
    );
    assert!(update.accounts.accounts.is_empty());
    let KeyOutcome::Meta(Ok(loaded_after)) = one(&mut worker, KeyJob::LoadMeta)? else {
        return Err("meta".into());
    };
    // The worker already wrote meta without the Bitcoin account (the EVM key's list entry is
    // the UI's to drop, so this load reconciles that one).
    assert!(loaded_after.meta.btc_accounts.accounts.is_empty());
    assert!(loaded_after.meta.evm_raw_accounts.is_empty());
    let sol_id = loaded
        .meta
        .sol_raw_accounts
        .first()
        .map(|raw| yw_core::vault::RecordId::from_bytes(raw.record_id))
        .ok_or("no Solana record")?;
    assert!(matches!(
        one(
            &mut worker,
            KeyJob::RemoveImportedKey {
                password: Zeroizing::new(PASSWORD.to_vec()),
                id: sol_id,
            },
        )?,
        KeyOutcome::ImportedKeyRemoved(Err(VaultError::LastKey))
    ));
    worker.lock();
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

fn devnet_answer(method: &str) -> Answer {
    let ctx =
        |value: &str| Answer::Result(format!("{{\"context\":{{\"slot\":7}},\"value\":{value}}}"));
    match method {
        "getGenesisHash" => Answer::Result(format!("\"{DEVNET_GENESIS}\"")),
        "getBalance" => ctx("10000000000"),
        "getAccountInfo" => ctx("null"),
        "getMinimumBalanceForRentExemption" => Answer::Result("890880".to_owned()),
        "getRecentPrioritizationFees" => Answer::Result(
            "[{\"slot\":1,\"prioritizationFee\":0},{\"slot\":2,\"prioritizationFee\":0}]"
                .to_owned(),
        ),
        "getLatestBlockhash" => ctx(&format!(
            "{{\"blockhash\":\"{BLOCKHASH}\",\"lastValidBlockHeight\":1150}}"
        )),
        "getFeeForMessage" => ctx("5000"),
        "simulateTransaction" => ctx(
            "{\"err\":null,\"logs\":[],\"accounts\":null,\"unitsConsumed\":450,\"returnData\":null}",
        ),
        _ => Answer::Error(-32_601, None),
    }
}

#[test]
fn imported_sol_key_prepares_and_signs_a_devnet_transfer() -> TestResult {
    let dir = temp_dir("solsend")?;
    let mut vault = Vault::load(Box::new(
        FileStorage::open(&dir).map_err(|error| format!("{error:?}"))?,
    ))?;
    let password = VaultPassword::new(PASSWORD).map_err(|error| format!("{error:?}"))?;
    let slot = Box::new(LockedSlotBox::new().map_err(|error| format!("{error:?}"))?);
    vault.import_mnemonic(&password, ABANDON, None, slot, 1_800_000_000)?;
    let public: [u8; 32] =
        yw_core::hex::decode_array(RFC8032_PUBLIC).map_err(|error| format!("{error:?}"))?;
    let key = ImportKey::parse(ImportSpec::Sol, &keypair(RFC8032_SEED, &public)?)?;
    vault.import_key(key, 1_800_000_001)?;
    let from = SolAddress::from_bytes(public);
    // Step 2: the preview with an imported source (no non-standard flag, normal fee rules).
    let rpc = FakeRpc::new(|method, _| devnet_answer(method));
    let job = PreviewJob {
        job: 1,
        endpoint: SolEndpoint {
            cluster: SolCluster::Devnet,
            url: url(),
        },
        source: SolKeySource::Imported,
        from,
        account_label: "가져온 Solana 1".to_owned(),
        recipient: check_recipient(TO, &from, &[]).map_err(|error| format!("{error:?}"))?,
        asset: SolAsset::Sol,
        amount: Some(1_000_000),
        fee_cap: 100_000,
        max_cu_price: 1_000_000,
        pending_exists: false,
        journal_room: true,
    };
    let prepared = match preview(&*Arc::clone(&rpc), &job).outcome {
        PreviewOutcome::Ready(prepared) => *prepared,
        PreviewOutcome::Failed { code, .. } => return Err(code.code().into()),
    };
    assert_eq!(prepared.source, SolKeySource::Imported);
    assert_eq!(prepared.core.from, from);
    assert_eq!(
        prepared.flags & yw_core::sol::intent::flags::NON_STANDARD_PATH,
        0
    );
    // Steps 3–7: approval, then the key worker's journal path signs with the imported key.
    let intent = prepared.intent([0x51; 16], 1_800_000_000_000);
    let draft = build_sol_transfer_request(
        yw_core::lang::Lang::Ko,
        &intent,
        &prepared.genesis,
        &prepared.facts,
    )
    .map_err(|error| format!("{error:?}"))?;
    let mut store = ApprovalStore::new();
    let request = store.issue(draft, 1, intent.created_at_ms)?;
    let approved = store.consume(request.id, request.digest, 2)?;
    let mut state = JournalState::default();
    let now = yw_win::time::monotonic_ms();
    let outcomes = state.sign_sol(
        &mut vault,
        Box::new(approved),
        SolSignTimes {
            consumed_at_ms: now,
            blockhash: [7; 32],
            last_valid_block_height: 1_150,
            now_unix_ms: 1_800_000_000_000,
        },
        false,
    );
    let Some(KeyOutcome::SignedSol(Ok(summary))) = outcomes.first() else {
        return Err("not signed".into());
    };
    assert_eq!(summary.from, from);
    let (core, _, signature) =
        parse_transaction(&summary.tx, SolCluster::Devnet).map_err(|error| format!("{error:?}"))?;
    assert_eq!(core, intent.core);
    let message = yw_core::sol::message::encode_message(&core, &[7; 32]);
    assert!(verify_strict(&public, &message, &signature));
    // The `Pending` record (source tag 6) is on disk.
    let view = JournalState::default().load(&vault)?;
    assert_eq!(view.sol_records.len(), 1);
    assert_eq!(
        view.sol_records.first().map(|record| record.source),
        Some(SolKeySource::Imported)
    );
    vault.lock();
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
