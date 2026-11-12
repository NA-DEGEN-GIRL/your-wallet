//! Solana dApp transactions end to end without a window (spec/07 §20, spec/05 §3.6): the
//! dispatcher's params check → the preview over the scripted RPC (spec/07 §20.7) → the core
//! request builder → one approval issued and consumed → the key worker's sign-only route
//! (`SignChainMessage`, spec/07 §20.8) → the dApp answer (`chain_answer_value`). A throwaway
//! vault in a temp folder (BIP-39 test vector `abandon`×11 `about`, never a real seed); no
//! network, nothing sent.
//!
//! Cases: a transaction whose fee payer is another account that signed first keeps that
//! signature and gets ours in its own slot only, both verifying; a `signAll` of three answers
//! three signed transactions in order; a forged site signature is X01 Blocked and cannot be
//! consumed. A send (spec/07 §20.8–§20.10) runs the pre-sign check over the scripted RPC, is
//! signed and journaled by the key worker (`SignSolDapp`), and its first broadcast round decides
//! the answer: the transaction id, or -32603 after a deterministic preflight error; an expired
//! blockhash stops it at pre-sign.

mod common;

use std::path::PathBuf;

use common::{Answer, FakeClock, FakeRpc, url};
use yw_app::app_chain_sites::{ChainAnswer, chain_answer_value};
use yw_app::browser::params::{Validated, validate};
use yw_app::events::{
    ChainMessageSigned, ChainSignature, KeyJob, KeyOutcome, SignTicket, SolDappSigned,
    SolKeysPurpose,
};
use yw_app::sol::flow::{DappPreviewJob, SolEndpoint, dapp_preview};
use yw_app::workers::key::KeyWorker;
use yw_core::approval::{ApprovalId, ApprovalStore, RiskLevel};
use yw_core::bip32::path::AccountIndex;
use yw_core::policy::{BrowserOrigin, Method};
use yw_core::secret::Zeroizing;
use yw_core::slip10::SolKeySource;
use yw_core::sol::dapp::{SolTxMode, SolTxRequest, build_sol_tx_request};
use yw_core::sol::{SolAddress, SolCluster};
use yw_json::{Limits, Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const DEVNET: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
const NOW: u64 = 1_800_000_000_000;
/// An unknown program (X02: raw instruction, High, never Blocked).
const PROGRAM: [u8; 32] = [5; 32];

/// Distinct temp folder per call.
static NEXT_DIR: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn temp_dir(tag: &str) -> TestResult<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "yw-app-sol-dapp-{tag}-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// A key worker with the `abandon` wallet imported, and the public keys of standard Solana
/// accounts 0 and 1.
fn worker(dir: &std::path::Path) -> TestResult<(KeyWorker, [u8; 32], [u8; 32])> {
    let mut worker = KeyWorker::new(dir);
    let _ = worker.handle(KeyJob::Load);
    let preview = worker.handle(KeyJob::PreviewImport {
        password: Some(Zeroizing::new(b"sol dapp flow password".to_vec())),
        phrase: Zeroizing::new(ABANDON.as_bytes().to_vec()),
        passphrase: None,
    });
    if !matches!(preview.first(), Some(KeyOutcome::Preview(Ok(_)))) {
        return Err("preview".into());
    }
    if !matches!(
        worker.handle(KeyJob::CommitImport).first(),
        Some(KeyOutcome::Imported(Ok(())))
    ) {
        return Err("import".into());
    }
    let keys = worker.handle(KeyJob::SolKeys {
        purpose: SolKeysPurpose::Scan,
        sources: vec![
            SolKeySource::Standard(AccountIndex::ZERO),
            SolKeySource::Standard(AccountIndex::new(1)?),
        ],
    });
    let Some(KeyOutcome::SolKeys(_, Ok(keys))) = keys.first() else {
        return Err("keys".into());
    };
    let [(_, first), (_, second)] = keys.as_slice() else {
        return Err("two keys".into());
    };
    // Account 0 of the vector (spec/07 §3 test vector).
    assert_eq!(
        first.to_base58(),
        "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"
    );
    Ok((worker, first.to_bytes(), second.to_bytes()))
}

fn len_u8(len: usize) -> u8 {
    u8::try_from(len).unwrap_or(u8::MAX)
}

/// A legacy transaction with `required` zero signature slots over `keys` (the last key
/// read-only unsigned): one instruction of the last key with the signers as accounts.
fn legacy(keys: &[[u8; 32]], required: u8, tag: u8) -> Vec<u8> {
    let mut out = vec![required];
    out.extend(std::iter::repeat_n(0_u8, 64 * usize::from(required)));
    out.extend_from_slice(&[required, 0, 1, len_u8(keys.len())]);
    for key in keys {
        out.extend_from_slice(key);
    }
    out.extend_from_slice(&[7; 32]);
    let accounts: Vec<u8> = (0..required).collect();
    out.extend_from_slice(&[1, len_u8(keys.len() - 1), len_u8(accounts.len())]);
    out.extend_from_slice(&accounts);
    out.extend_from_slice(&[1, tag]);
    out
}

fn ctx(value: &str) -> Answer {
    Answer::Result(format!("{{\"context\":{{\"slot\":7}},\"value\":{value}}}"))
}

/// A healthy devnet where every account is missing and the simulation succeeds.
fn rpc() -> std::sync::Arc<FakeRpc> {
    FakeRpc::new(|method, params| {
        let nulls = |list: Option<&Value>| {
            let count = list.and_then(Value::as_array).map_or(0, <[Value]>::len);
            format!("[{}]", vec!["null"; count].join(","))
        };
        let config = params
            .as_array()
            .and_then(|items| items.get(1))
            .and_then(Value::as_object);
        match method {
            "getGenesisHash" => Answer::Result(format!("\"{DEVNET}\"")),
            "getMultipleAccounts" => ctx(&nulls(params.as_array().and_then(|items| items.first()))),
            "isBlockhashValid" => ctx("true"),
            "getFeeForMessage" => ctx("5000"),
            "simulateTransaction" => {
                let addresses = config
                    .and_then(|object| object.get("accounts"))
                    .and_then(Value::as_object)
                    .and_then(|object| object.get("addresses"));
                ctx(&format!(
                    "{{\"err\":null,\"logs\":[],\"accounts\":{},\"unitsConsumed\":1200}}",
                    nulls(addresses)
                ))
            }
            _ => Answer::Error(-32_601, None),
        }
    })
}

fn origin() -> TestResult<BrowserOrigin> {
    BrowserOrigin::parse("https://app.example").ok_or_else(|| "origin".into())
}

/// The dApp's params as the dispatcher validates them: `(transactions, list)`.
fn params(method: Method, public: &[u8; 32], txs: &[Vec<u8>]) -> TestResult<(Vec<Vec<u8>>, bool)> {
    let key = SolAddress::from_bytes(*public).to_base58();
    let hex: Vec<String> = txs
        .iter()
        .map(|tx| format!("\"{}\"", yw_core::hex::encode(tx)))
        .collect();
    let text = if method == Method::SolSignAllTransactions {
        format!(
            r#"[{{"publicKey":"{key}","transactions":[{}],"chain":"solana:devnet"}}]"#,
            hex.join(",")
        )
    } else {
        format!(
            r#"[{{"publicKey":"{key}","transaction":{}}}]"#,
            hex.join(",")
        )
    };
    let value = yw_json::parse(text.as_bytes(), &Limits::REQUEST)?;
    match validate(method, &value) {
        Ok(Validated::SolTx {
            public: checked,
            txs,
            batch,
            ..
        }) if checked == *public => Ok((txs, batch)),
        other => Err(format!("params: {other:?}").into()),
    }
}

/// [`approve_as`] of a sign-only request.
fn approve(
    public: [u8; 32],
    source: SolKeySource,
    txs: Vec<Vec<u8>>,
    id: u8,
) -> TestResult<(
    RiskLevel,
    Result<yw_core::approval::Approved, yw_core::approval::ApprovalError>,
)> {
    approve_as(public, source, txs, id, SolTxMode::SignOnly)
}

/// Preview → draft → one approval (the window's part), for `public` of `source`.
fn approve_as(
    public: [u8; 32],
    source: SolKeySource,
    txs: Vec<Vec<u8>>,
    id: u8,
    mode: SolTxMode,
) -> TestResult<(
    RiskLevel,
    Result<yw_core::approval::Approved, yw_core::approval::ApprovalError>,
)> {
    let rpc = rpc();
    let preview = dapp_preview(
        &*rpc,
        &DappPreviewJob {
            job: 1,
            endpoint: SolEndpoint {
                cluster: SolCluster::Devnet,
                url: url(),
            },
            wallet: SolAddress::from_bytes(public),
            txs: txs.clone(),
        },
        &FakeClock::at(NOW),
    )
    .map_err(|code| format!("preview {code:?}"))?;
    let request = SolTxRequest {
        id: ApprovalId([id; 16]),
        origin: origin()?,
        cluster: SolCluster::Devnet,
        source,
        public,
        label: "Solana 1".to_owned(),
        mode,
        options: yw_core::sol::dapp::SolSendOptions::default(),
        txs,
    };
    let draft = build_sol_tx_request(&request, &preview.into_facts(Vec::new(), 100_000))
        .map_err(|error| format!("draft {error:?}"))?;
    let risk = draft.display.risk;
    let mut store = ApprovalStore::new();
    let issued = store.issue(draft, 1, NOW)?;
    Ok((risk, store.consume(issued.id, issued.digest, 2)))
}

/// The key worker's sign-only route; the signed transactions.
fn sign(worker: &mut KeyWorker, approved: yw_core::approval::Approved) -> TestResult<Vec<Vec<u8>>> {
    let outcome = worker.handle(KeyJob::SignChainMessage {
        ticket: SignTicket(1),
        approved: Box::new(approved),
    });
    match outcome.as_slice() {
        [
            KeyOutcome::SignedChainMessage(ChainMessageSigned {
                result: Ok(ChainSignature::SolTxs(list)),
                ..
            }),
        ] => Ok(list.clone()),
        other => Err(format!("signed: {other:?}").into()),
    }
}

/// The dApp's answer as JSON text.
fn answer(public: [u8; 32], batch: bool, signed: Vec<Vec<u8>>) -> TestResult<Value> {
    let value = chain_answer_value(
        &ChainAnswer::SolTx {
            public,
            origin: origin()?,
            batch,
            send: false,
        },
        &ChainSignature::SolTxs(signed),
    )
    .ok_or("answer")?;
    Ok(value)
}

fn slot(tx: &[u8], index: usize) -> TestResult<[u8; 64]> {
    let start = 1 + 64 * index;
    Ok(tx.get(start..start + 64).ok_or("slot")?.try_into()?)
}

/// spec/07 §20.5, §20.8: another account pays and signs first (slot 0, through its own
/// approval); the wallet's approval then fills slot 1 only — the site signature and every
/// message byte are kept, both signatures verify, and the answer is `{publicKey,
/// signedTransaction}`.
#[test]
fn partial_signature_is_kept_and_only_our_slot_changes() -> TestResult {
    let dir = temp_dir("partial")?;
    let (mut worker, wallet, payer) = worker(&dir)?;
    let tx = legacy(&[payer, wallet, PROGRAM], 2, 1);
    let message = tx.get(1 + 128..).ok_or("message")?.to_vec();
    // The other account signs first (in a real dApp: the site's own key).
    let (txs, _) = params(Method::SolSignTransaction, &payer, &[tx])?;
    let (_, approved) = approve(payer, SolKeySource::Standard(AccountIndex::new(1)?), txs, 1)?;
    let [cosigned] = <[Vec<u8>; 1]>::try_from(sign(&mut worker, approved?)?).map_err(|_| "one")?;
    assert_eq!(slot(&cosigned, 1)?, [0; 64]);
    // The wallet's request.
    let (txs, batch) = params(
        Method::SolSignTransaction,
        &wallet,
        std::slice::from_ref(&cosigned),
    )?;
    assert!(!batch);
    let (risk, approved) = approve(wallet, SolKeySource::Standard(AccountIndex::ZERO), txs, 2)?;
    assert!(risk < RiskLevel::Blocked, "{risk:?}");
    let signed = sign(&mut worker, approved?)?;
    let value = answer(wallet, false, signed)?;
    let object = value.as_object().ok_or("object")?;
    assert_eq!(
        object.get("publicKey").and_then(Value::as_str),
        Some(SolAddress::from_bytes(wallet).to_base58().as_str())
    );
    let returned = yw_core::hex::decode(
        object
            .get("signedTransaction")
            .and_then(Value::as_str)
            .ok_or("signedTransaction")?,
    )?;
    assert_eq!(returned.len(), cosigned.len());
    assert_eq!(
        slot(&returned, 0)?,
        slot(&cosigned, 0)?,
        "site signature kept"
    );
    assert_eq!(returned.get(1 + 128..), Some(message.as_slice()));
    let changed: Vec<usize> = returned
        .iter()
        .zip(&cosigned)
        .enumerate()
        .filter(|(_, (a, b))| a != b)
        .map(|(index, _)| index)
        .collect();
    assert!(changed.iter().all(|index| (65..129).contains(index)));
    assert!(yw_core::sol::keys::verify_strict(
        &payer,
        &message,
        &slot(&returned, 0)?
    ));
    assert!(yw_core::sol::keys::verify_strict(
        &wallet,
        &message,
        &slot(&returned, 1)?
    ));
    // A forged site signature: X01 Blocked, never consumable.
    let mut forged = cosigned;
    *forged.get_mut(1).ok_or("byte")? ^= 1;
    let (txs, _) = params(Method::SolSignTransaction, &wallet, &[forged])?;
    let (risk, approved) = approve(wallet, SolKeySource::Standard(AccountIndex::ZERO), txs, 3)?;
    assert_eq!(risk, RiskLevel::Blocked);
    assert!(matches!(
        approved,
        Err(yw_core::approval::ApprovalError::Blocked)
    ));
    drop(worker);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// spec/05 §3.6: `sol_signAllTransactions` of three is one approval and answers
/// `signedTransactions` in request order, each signed in our slot.
#[test]
fn sign_all_answers_every_transaction_in_order() -> TestResult {
    let dir = temp_dir("all")?;
    let (mut worker, wallet, _) = worker(&dir)?;
    let sent: Vec<Vec<u8>> = (1..=3)
        .map(|tag| legacy(&[wallet, PROGRAM], 1, tag))
        .collect();
    let (txs, batch) = params(Method::SolSignAllTransactions, &wallet, &sent)?;
    assert!(batch);
    let (_, approved) = approve(wallet, SolKeySource::Standard(AccountIndex::ZERO), txs, 4)?;
    let value = answer(wallet, true, sign(&mut worker, approved?)?)?;
    let list = value
        .as_object()
        .and_then(|object| object.get("signedTransactions"))
        .and_then(Value::as_array)
        .ok_or("signedTransactions")?;
    assert_eq!(list.len(), 3);
    for (item, original) in list.iter().zip(&sent) {
        let returned = yw_core::hex::decode(item.as_str().ok_or("hex")?)?;
        let message = original.get(65..).ok_or("message")?;
        assert_eq!(returned.get(65..), Some(message));
        assert!(yw_core::sol::keys::verify_strict(
            &wallet,
            message,
            &slot(&returned, 0)?
        ));
    }
    drop(worker);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// What the scripted devnet answers to a send: whether the blockhash is still valid, the
/// `sendTransaction` answer, and the signature an accepting node returns.
struct SendWorld {
    valid: bool,
    send: Option<Answer>,
    signature: String,
}

fn send_rpc(world: &std::sync::Arc<std::sync::Mutex<SendWorld>>) -> std::sync::Arc<FakeRpc> {
    let world = std::sync::Arc::clone(world);
    FakeRpc::new(move |method, _| {
        let Ok(world) = world.lock() else {
            return Answer::Error(-32_603, None);
        };
        match method {
            "getGenesisHash" => Answer::Result(format!("\"{DEVNET}\"")),
            "isBlockhashValid" => ctx(if world.valid { "true" } else { "false" }),
            "getLatestBlockhash" => ctx(&format!(
                "{{\"blockhash\":\"{}\",\"lastValidBlockHeight\":1150}}",
                SolAddress::from_bytes([7; 32]).to_base58()
            )),
            "getBlockHeight" => Answer::Result("1000".to_owned()),
            "getSignatureStatuses" => ctx("[null]"),
            "sendTransaction" => world
                .send
                .clone()
                .unwrap_or_else(|| Answer::Result(format!("\"{}\"", world.signature))),
            _ => Answer::Error(-32_601, None),
        }
    })
}

/// A preflight failure of the instruction itself (spec/07 §15.3 code 9, deterministic).
fn program_failed() -> Answer {
    Answer::Envelope(
        concat!(
            r#"{"jsonrpc":"2.0","id":0,"error":{"code":-32002,"message":"Transaction "#,
            r#"simulation failed: x","data":{"err":{"InstructionError":[0,{"Custom":1}]},"#,
            r#""logs":[],"accounts":null,"unitsConsumed":0}}}"#
        )
        .as_bytes()
        .to_vec(),
    )
}

/// spec/07 §20.8–§20.10, spec/05 §3.6, §5: `sol_signAndSendTransaction` end to end — the
/// pre-sign check binds `lastValidBlockHeight` at `processed`, `SignSolDapp` journals the
/// transaction before returning it (only our slot changed), and the first broadcast round
/// sends those exact bytes and answers `{publicKey, signature}` with the transaction id. A
/// deterministic preflight failure (code 9) stops the re-sends and answers -32603; an expired
/// blockhash stops the send at pre-sign, before any key use.
#[test]
#[expect(clippy::too_many_lines, reason = "one send from params to answer")]
fn send_is_checked_journaled_and_answered_after_the_first_round() -> TestResult {
    use yw_app::app_sol_dapp::{sol_round_failed, sol_send_answer};
    use yw_app::sol::flow::{PreSignError, TrackJob, pre_sign_dapp, track_round};
    use yw_app::sol::rpc::SendConfig;
    use yw_core::sol::broadcast::{LoopState, PendingTx};

    let dir = temp_dir("send")?;
    let (mut worker, wallet, _) = worker(&dir)?;
    let world = std::sync::Arc::new(std::sync::Mutex::new(SendWorld {
        valid: true,
        send: None,
        signature: String::new(),
    }));
    let rpc = send_rpc(&world);
    let endpoint = SolEndpoint {
        cluster: SolCluster::Devnet,
        url: url(),
    };
    let sent = legacy(&[wallet, PROGRAM], 1, 1);
    let (txs, batch) = params(
        Method::SolSignAndSendTransaction,
        &wallet,
        std::slice::from_ref(&sent),
    )?;
    assert!(!batch);
    let (risk, approved) = approve_as(
        wallet,
        SolKeySource::Standard(AccountIndex::ZERO),
        txs,
        5,
        SolTxMode::SignAndSend,
    )?;
    assert!(risk < RiskLevel::Blocked, "{risk:?}");
    let approved = approved?;
    let message = yw_core::sol::dapp::parse_wire_tx(&sent)?.message;
    let (last_valid, check) =
        pre_sign_dapp(&*rpc, &endpoint, &message).map_err(|error| format!("{error:?}"))?;
    assert_eq!(last_valid, 1_150);
    let outcomes = worker.handle(KeyJob::SignSolDapp {
        ticket: SignTicket(5),
        approved: Box::new(approved),
        consumed_at_ms: yw_win::time::monotonic_ms(),
        now_unix_ms: NOW,
        last_valid_block_height: last_valid,
        check,
        origin: "https://app.example".to_owned(),
    });
    let Some(KeyOutcome::SignedSolDapp(SolDappSigned {
        ticket: SignTicket(5),
        result: Ok(summary),
    })) = outcomes.first()
    else {
        return Err(format!("not signed: {outcomes:?}").into());
    };
    // Journaled before it was returned: the view that follows holds the record.
    assert!(outcomes.iter().any(|outcome| matches!(
        outcome,
        KeyOutcome::Journal(Ok(view))
            if view.sol_records.iter().any(|record| record.signature() == summary.tx_id)
    )));
    assert_eq!(
        summary.tx.get(65..),
        sent.get(65..),
        "only our slot changed"
    );
    if let Ok(mut world) = world.lock() {
        world.signature = yw_core::codec::base58::base58_encode(&summary.tx_id);
    }
    let round = |state: LoopState| TrackJob {
        endpoint: endpoint.clone(),
        signature: summary.tx_id,
        tx: summary.tx.clone(),
        pending: PendingTx {
            signed_at_ms: summary.signed_at_ms,
            last_valid_block_height: summary.last_valid_block_height,
        },
        state,
        check_genesis: false,
        generation: 0,
        send: SendConfig::default(),
    };
    let clock = FakeClock::at(NOW + 1_000);
    let first = track_round(&*rpc, &round(LoopState::default()), &clock);
    assert_eq!(first.sends, 1);
    assert!(!sol_round_failed(&first), "{first:?}");
    let sends = rpc.params_of("sendTransaction");
    assert!(
        sends
            .first()
            .is_some_and(|params| params.contains(&yw_core::codec::base64::encode(&summary.tx))),
        "the journaled bytes are sent"
    );
    let answer = sol_send_answer(&wallet, &first.signature);
    assert_eq!(
        String::from_utf8(yw_json::to_vec(&answer))?,
        format!(
            r#"{{"publicKey":"{}","signature":"{}"}}"#,
            SolAddress::from_bytes(wallet).to_base58(),
            yw_core::hex::encode(&summary.tx_id)
        )
    );
    // The program fails in preflight (code 9): the re-sends stop, the dApp gets -32603.
    if let Ok(mut world) = world.lock() {
        world.send = Some(program_failed());
    }
    let failed = track_round(&*rpc, &round(LoopState::default()), &clock);
    assert_eq!(failed.state.preflight_err, Some(9));
    assert!(sol_round_failed(&failed));
    // An expired blockhash stops the send at pre-sign: nothing is signed.
    if let Ok(mut world) = world.lock() {
        world.valid = false;
    }
    assert!(matches!(
        pre_sign_dapp(&*rpc, &endpoint, &message),
        Err(PreSignError::BlockhashExpired)
    ));
    drop(worker);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
