//! Solana pipelines over the scripted transport (spec/07 §13–§15, spec/09 §4.4): the step-2
//! preview with its call order, `L01` blocks and flags; the step-5 lookup and its range check;
//! the broadcast round state machine against a fake RPC and a manual clock (SOL-N1: the same
//! signed bytes are re-sent, never re-signed, and "지금 다시 전송" re-sends them at once;
//! `Expired` — which allows a new signature — after one round with a confirmed `getEpochInfo`
//! height above `lastValidBlockHeight` and a history `null` answered at or after that view's
//! slot, with no clock minimum; never while the height is at or below it);
//! balances and the recovery scan with the genesis pin; dApp transactions (spec/07 §20.7,
//! §20.10): the preview's call order and config, lookup-table failures kept per transaction, the
//! stale-blockhash simulation retry, the reference budget, the pre-sign check at `processed`, a
//! dApp record's send options, and the exact dApp RPC requests.

mod common;

use std::sync::{Arc, Mutex};

use common::{Answer, FakeClock, FakeRpc, url};
use yw_app::errors::ErrorCode;
use yw_app::flow::evm::Clock as _;
use yw_app::rpc::{RpcClient, RpcFailure};
use yw_app::sol::flow::{
    DappPreviewJob, PreSignError, PreviewJob, PreviewOutcome, SolEndpoint, SolPrepared, TrackJob,
    balances, dapp_preview, pre_sign, pre_sign_dapp, preview, track_round,
};
use yw_app::sol::rpc::{self as sol, SendConfig};
use yw_app::sol::scan::{SOL_SCAN_GAP, scan, scan_sources};
use yw_core::approval::{ApprovalId, SigningPayload};
use yw_core::bip32::path::AccountIndex;
use yw_core::codec::base58::base58_encode;
use yw_core::policy::BrowserOrigin;
use yw_core::slip10::SolKeySource;
use yw_core::sol::address::{ADDRESS_LOOKUP_TABLE_PROGRAM, SYSTEM_PROGRAM, TOKEN_PROGRAM};
use yw_core::sol::broadcast::{LoopState, Outcome, PendingTx, err};
use yw_core::sol::dapp::{
    AltError, PreSignCheck, ResolvedKeys, SolSendOptions, SolTxMessage, SolTxMode, SolTxRequest,
    build_sol_tx_request, parse_wire_tx,
};
use yw_core::sol::display::{SimSummary, SolBlock};
use yw_core::sol::fee::{FeeError, SOL_TRANSFER_CU_LIMIT};
use yw_core::sol::intent::flags;
use yw_core::sol::recipient::check_recipient;
use yw_core::sol::rent::RentError;
use yw_core::sol::{SolAddress, SolAsset, SolCluster};
use yw_json::{Limits, Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const DEVNET: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
const MAINNET: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
const FROM: &str = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
const TO: &str = "Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb";
const BLOCKHASH: &str = "US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx";
const RENT0: u64 = 890_880;
const SOL: u64 = 1_000_000_000;

fn endpoint() -> SolEndpoint {
    SolEndpoint {
        cluster: SolCluster::Devnet,
        url: url(),
    }
}

fn ctx(value: &str) -> Answer {
    Answer::Result(format!("{{\"context\":{{\"slot\":7}},\"value\":{value}}}"))
}

/// A healthy devnet: 10 SOL sender, missing recipient, rent 890,880, fees 0, fee 5,000.
#[derive(Clone)]
struct World {
    genesis: &'static str,
    balance: u64,
    account: &'static str,
    rent0: u64,
    fees: &'static str,
    fee: &'static str,
    simulate: &'static str,
}

impl Default for World {
    fn default() -> Self {
        Self {
            genesis: DEVNET,
            balance: 10 * SOL,
            account: "null",
            rent0: RENT0,
            fees: "[{\"slot\":1,\"prioritizationFee\":0},{\"slot\":2,\"prioritizationFee\":0}]",
            fee: "5000",
            simulate: "{\"err\":null,\"logs\":[],\"accounts\":null,\"unitsConsumed\":450,\"returnData\":null}",
        }
    }
}

fn answer(world: &World, method: &str) -> Answer {
    match method {
        "getGenesisHash" => Answer::Result(format!("\"{}\"", world.genesis)),
        "getBalance" => ctx(&world.balance.to_string()),
        "getAccountInfo" => ctx(world.account),
        "getMinimumBalanceForRentExemption" => Answer::Result(world.rent0.to_string()),
        "getRecentPrioritizationFees" => Answer::Result(world.fees.to_owned()),
        "getLatestBlockhash" => ctx(&format!(
            "{{\"blockhash\":\"{BLOCKHASH}\",\"lastValidBlockHeight\":1150}}"
        )),
        "getFeeForMessage" => ctx(world.fee),
        "simulateTransaction" => ctx(world.simulate),
        "getBlockHeight" => Answer::Result("1000".to_owned()),
        _ => Answer::Error(-32_601, None),
    }
}

fn fake(world: World) -> Arc<FakeRpc> {
    FakeRpc::new(move |method, _| answer(&world, method))
}

fn addr(text: &str) -> SolAddress {
    SolAddress::parse(text).unwrap_or(SolAddress::from_bytes([9; 32]))
}

fn job(amount: Option<u64>) -> TestResult<PreviewJob> {
    Ok(PreviewJob {
        job: 1,
        endpoint: endpoint(),
        source: SolKeySource::Standard(AccountIndex::ZERO),
        from: addr(FROM),
        account_label: "Solana 1".to_owned(),
        recipient: check_recipient(TO, &addr(FROM), &[]).map_err(|error| format!("{error:?}"))?,
        asset: SolAsset::Sol,
        amount,
        fee_cap: 100_000,
        max_cu_price: 1_000_000,
        pending_exists: false,
        journal_room: true,
    })
}

fn ready(outcome: PreviewOutcome) -> TestResult<SolPrepared> {
    match outcome {
        PreviewOutcome::Ready(prepared) => Ok(*prepared),
        PreviewOutcome::Failed { code, .. } => Err(format!("failed {}", code.code()).into()),
    }
}

#[test]
fn preview_calls_in_spec_order_and_builds_the_core() -> TestResult {
    let rpc = fake(World::default());
    let prepared = ready(preview(&*rpc, &job(Some(SOL))?).outcome)?;
    assert_eq!(
        rpc.methods(),
        [
            "getGenesisHash",
            "getBalance",
            "getAccountInfo",
            "getMinimumBalanceForRentExemption",
            "getRecentPrioritizationFees",
            "getLatestBlockhash",
            "getFeeForMessage",
            "simulateTransaction",
        ]
    );
    assert!(
        prepared.facts.blocks.is_empty(),
        "{:?}",
        prepared.facts.blocks
    );
    assert_eq!(prepared.core.amount, SOL);
    assert_eq!(prepared.core.cu_limit, SOL_TRANSFER_CU_LIMIT);
    assert_eq!(prepared.core.cu_price_micro, 0);
    assert_eq!(prepared.max_fee, 5_000);
    assert_eq!(prepared.facts.simulation, SimSummary::Ok { units: 450 });
    assert_eq!(prepared.flags, flags::FIRST_TIME);
    let params = rpc.params_of("getAccountInfo").join("");
    assert!(params.contains("\"dataSlice\":{\"offset\":0,\"length\":0}"));
    assert!(params.contains("\"commitment\":\"confirmed\""));
    let simulate = rpc.params_of("simulateTransaction").join("");
    assert!(simulate.contains("\"sigVerify\":false"));
    assert!(simulate.contains("\"replaceRecentBlockhash\":true"));
    Ok(())
}

#[test]
fn preview_price_is_the_clamped_p75() -> TestResult {
    let world = World {
        fees: "[{\"slot\":1,\"prioritizationFee\":100},{\"slot\":2,\"prioritizationFee\":200},{\"slot\":3,\"prioritizationFee\":300},{\"slot\":4,\"prioritizationFee\":4000}]",
        fee: "5003",
        ..World::default()
    };
    let rpc = fake(world);
    let prepared = ready(preview(&*rpc, &job(Some(SOL))?).outcome)?;
    assert_eq!(prepared.core.cu_price_micro, 4_000);
    assert_eq!(prepared.max_fee, 5_003);
    assert!(prepared.facts.blocks.is_empty());
    Ok(())
}

#[test]
fn genesis_mismatch_stops_the_preview() -> TestResult {
    let rpc = fake(World {
        genesis: MAINNET,
        ..World::default()
    });
    let prepared = ready(preview(&*rpc, &job(Some(SOL))?).outcome)?;
    assert_eq!(prepared.facts.blocks, [SolBlock::ClusterMismatch]);
    assert_eq!(rpc.methods(), ["getGenesisHash"]);
    Ok(())
}

#[test]
fn rent_fee_and_recipient_blocks() -> TestResult {
    let blocks = |world: World, amount: Option<u64>| -> TestResult<Vec<SolBlock>> {
        Ok(ready(preview(&*fake(world), &job(amount)?).outcome)?
            .facts
            .blocks)
    };
    // New account below rent0, exactly rent0.
    assert_eq!(
        blocks(World::default(), Some(RENT0 - 1))?,
        [SolBlock::Rent(RentError::BelowRentForNewAccount {
            rent0: RENT0
        })]
    );
    assert!(blocks(World::default(), Some(RENT0))?.is_empty());
    // Sender dust: r = rent0 − 1.
    let world = World {
        balance: 2 * RENT0 + 5_000 - 1,
        ..World::default()
    };
    assert_eq!(
        blocks(world, Some(RENT0))?,
        [SolBlock::Rent(RentError::SenderDust { rent0: RENT0 })]
    );
    // Insufficient balance.
    assert_eq!(
        blocks(World::default(), Some(20 * SOL))?,
        [SolBlock::Rent(RentError::InsufficientBalance)]
    );
    // RPC fee higher → FeeFormulaChanged; lower → allowed (normal) / refused (send max).
    let higher = World {
        fee: "5001",
        ..World::default()
    };
    assert_eq!(
        blocks(higher, Some(SOL))?,
        [SolBlock::Fee(FeeError::FeeFormulaChanged)]
    );
    let lower = World {
        fee: "4999",
        ..World::default()
    };
    assert!(blocks(lower.clone(), Some(SOL))?.is_empty());
    assert_eq!(
        blocks(lower, None)?,
        [SolBlock::Fee(FeeError::FeeFormulaChanged)]
    );
    // null twice → FeeQueryFailed after a second preview blockhash.
    let rpc = fake(World {
        fee: "null",
        ..World::default()
    });
    let prepared = ready(preview(&*rpc, &job(Some(SOL))?).outcome)?;
    assert_eq!(
        prepared.facts.blocks,
        [SolBlock::Fee(FeeError::FeeQueryFailed)]
    );
    assert_eq!(rpc.count("getLatestBlockhash"), 2);
    assert_eq!(rpc.count("getFeeForMessage"), 2);
    // Rent outside 1..=2,000,000.
    for rent0 in [0, 2_000_001] {
        let found = blocks(
            World {
                rent0,
                ..World::default()
            },
            Some(SOL),
        )?;
        assert_eq!(found, [SolBlock::RpcAnomaly], "{rent0}");
    }
    Ok(())
}

#[test]
fn rent_rule_uses_the_recipient_lamports_and_r0_is_send_max() -> TestResult {
    let blocks = |world: World, amount: Option<u64>| -> TestResult<Vec<SolBlock>> {
        Ok(ready(preview(&*fake(world), &job(amount)?).outcome)?
            .facts
            .blocks)
    };
    // An existing system account below rent0 must end at rent0 or above.
    let low = World {
        account: "{\"data\":[\"\",\"base64\"],\"executable\":false,\"lamports\":890000,\"owner\":\"11111111111111111111111111111111\",\"rentEpoch\":0,\"space\":0}",
        ..World::default()
    };
    assert_eq!(
        blocks(low.clone(), Some(RENT0 - 890_000 - 1))?,
        [SolBlock::Rent(RentError::RecipientBelowRent {
            needed: RENT0 - 890_000,
            rent0: RENT0
        })]
    );
    assert!(blocks(low, Some(RENT0 - 890_000))?.is_empty());
    // An account reported with 0 lamports is treated as new.
    let zero = World {
        account: "{\"data\":[\"\",\"base64\"],\"executable\":false,\"lamports\":0,\"owner\":\"11111111111111111111111111111111\",\"rentEpoch\":0,\"space\":0}",
        ..World::default()
    };
    assert_eq!(
        blocks(zero, Some(RENT0 - 1))?,
        [SolBlock::Rent(RentError::BelowRentForNewAccount {
            rent0: RENT0
        })]
    );
    // A typed amount that leaves the sender exactly 0 is a send max for the fee cross-check: a
    // lower RPC fee is refused (it would leave dust); one lamport less to send is a normal send.
    let lower = World {
        fee: "4999",
        ..World::default()
    };
    let everything = 10 * SOL - 5_000;
    assert_eq!(
        blocks(lower.clone(), Some(everything))?,
        [SolBlock::Fee(FeeError::FeeFormulaChanged)]
    );
    let prepared = ready(preview(&*fake(lower.clone()), &job(Some(everything))?).outcome)?;
    assert_eq!(
        prepared.flags & flags::SEND_MAX,
        0,
        "the typed amount is not flagged"
    );
    // Leaving rent0 behind instead: allowed with the lower RPC estimate.
    assert!(blocks(lower, Some(everything - RENT0))?.is_empty());
    Ok(())
}

#[test]
fn recipient_account_and_pending_blocks() -> TestResult {
    let blocks = |world: World, amount: Option<u64>| -> TestResult<Vec<SolBlock>> {
        Ok(ready(preview(&*fake(world), &job(amount)?).outcome)?
            .facts
            .blocks)
    };
    // Token account / executable / program-owned recipients.
    let token = "{\"data\":[\"\",\"base64\"],\"executable\":false,\"lamports\":2039280,\"owner\":\"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA\",\"rentEpoch\":18446744073709551615,\"space\":165}";
    assert_eq!(
        blocks(
            World {
                account: token,
                ..World::default()
            },
            Some(SOL)
        )?,
        [SolBlock::RecipientIsTokenAccount]
    );
    let program = "{\"data\":[\"\",\"base64\"],\"executable\":true,\"lamports\":1,\"owner\":\"BPFLoaderUpgradeab1e11111111111111111111111\",\"rentEpoch\":0,\"space\":36}";
    assert_eq!(
        blocks(
            World {
                account: program,
                ..World::default()
            },
            Some(SOL)
        )?,
        [SolBlock::RecipientIsProgram]
    );
    let owned = "{\"data\":[\"\",\"base64\"],\"executable\":false,\"lamports\":1000000,\"owner\":\"Stake11111111111111111111111111111111111111\",\"rentEpoch\":0,\"space\":200}";
    let prepared = ready(
        preview(
            &*fake(World {
                account: owned,
                ..World::default()
            }),
            &job(Some(1))?,
        )
        .outcome,
    )?;
    assert!(prepared.facts.blocks.is_empty());
    assert_ne!(prepared.flags & flags::PROGRAM_OWNED, 0);
    // Pending transfer and journal room.
    let mut pending = job(Some(SOL))?;
    pending.pending_exists = true;
    pending.journal_room = false;
    assert_eq!(
        ready(preview(&*fake(World::default()), &pending).outcome)?
            .facts
            .blocks,
        [SolBlock::PendingExists, SolBlock::JournalFull]
    );
    Ok(())
}

#[test]
fn send_max_and_simulation_warning() -> TestResult {
    let world = World {
        balance: 2 * SOL,
        account: "{\"data\":[\"\",\"base64\"],\"executable\":false,\"lamports\":5,\"owner\":\"11111111111111111111111111111111\",\"rentEpoch\":0,\"space\":0}",
        simulate: "{\"err\":{\"InstructionError\":[2,{\"Custom\":1}]},\"logs\":[],\"accounts\":null,\"unitsConsumed\":300,\"returnData\":null}",
        ..World::default()
    };
    let prepared = ready(preview(&*fake(world), &job(None)?).outcome)?;
    assert!(prepared.facts.blocks.is_empty());
    assert_eq!(prepared.core.amount, 2 * SOL - 5_000);
    assert_ne!(prepared.flags & flags::SEND_MAX, 0);
    assert_ne!(prepared.flags & flags::SIM_WARNING, 0);
    assert_eq!(
        prepared.facts.simulation,
        SimSummary::Failed {
            err: err::SYSTEM_INSTRUCTION,
            units: Some(300)
        }
    );
    // Nothing to send: InsufficientBalance, amount 0 (blocked).
    let empty = ready(
        preview(
            &*fake(World {
                balance: 5_000,
                ..World::default()
            }),
            &job(None)?,
        )
        .outcome,
    )?;
    assert_eq!(
        empty.facts.blocks,
        [SolBlock::Rent(RentError::InsufficientBalance)]
    );
    Ok(())
}

#[test]
fn transport_failures_fail_the_preview() -> TestResult {
    let rpc = FakeRpc::new(|method, _| match method {
        "getGenesisHash" => Answer::Result(format!("\"{DEVNET}\"")),
        _ => Answer::Transport(yw_win::http::HttpError::Timeout),
    });
    match preview(&*rpc, &job(Some(SOL))?).outcome {
        PreviewOutcome::Failed { code, retryable } => {
            assert_eq!(code.code(), "E-RPC-002");
            assert!(retryable);
        }
        PreviewOutcome::Ready(_) => return Err("expected failure".into()),
    }
    let malformed = FakeRpc::new(|method, _| match method {
        "getGenesisHash" => Answer::Result("\"not-base58-0OIl\"".to_owned()),
        _ => Answer::Error(-32_601, None),
    });
    assert!(matches!(
        preview(&*malformed, &job(Some(SOL))?).outcome,
        PreviewOutcome::Failed {
            retryable: false,
            ..
        }
    ));
    Ok(())
}

#[test]
fn pre_sign_lookup_and_range_check() {
    let lookup = |height: u64, last_valid: u64, genesis: &'static str| {
        let rpc = FakeRpc::new(move |method, _| match method {
            "getGenesisHash" => Answer::Result(format!("\"{genesis}\"")),
            "getLatestBlockhash" => ctx(&format!(
                "{{\"blockhash\":\"{BLOCKHASH}\",\"lastValidBlockHeight\":{last_valid}}}"
            )),
            "getBlockHeight" => Answer::Result(height.to_string()),
            _ => Answer::Error(-32_601, None),
        });
        let result = pre_sign(&*rpc, &endpoint());
        (result, rpc.methods())
    };
    let (ok, methods) = lookup(1_000, 1_150, DEVNET);
    assert_eq!(ok, Ok(([7; 32], 1_150)));
    assert_eq!(
        methods,
        ["getGenesisHash", "getLatestBlockhash", "getBlockHeight"]
    );
    // lvbh = blockhash height + 150 ≤ h + 150; below h + 100 is implausible (it would let the
    // expiry proof start early), above h + 300 too.
    assert!(lookup(1_000, 1_100, DEVNET).0.is_ok());
    assert!(lookup(1_000, 1_300, DEVNET).0.is_ok());
    assert_eq!(
        lookup(1_000, 1_099, DEVNET).0,
        Err(PreSignError::RpcAnomaly)
    );
    assert_eq!(
        lookup(1_000, 1_000, DEVNET).0,
        Err(PreSignError::RpcAnomaly)
    );
    assert_eq!(lookup(1_000, 999, DEVNET).0, Err(PreSignError::RpcAnomaly));
    assert_eq!(
        lookup(1_000, 1_301, DEVNET).0,
        Err(PreSignError::RpcAnomaly)
    );
    let (mismatch, methods) = lookup(1_000, 1_150, MAINNET);
    assert_eq!(mismatch, Err(PreSignError::ClusterMismatch));
    assert_eq!(methods, ["getGenesisHash"]);
}

// ----- broadcast loop (SOL-N1) ----------------------------------------------------------------

/// The fake network of one signature: status (history off/on, the history answer's
/// `context.slot`), the `getEpochInfo` view (height and slot), send behaviour.
#[derive(Clone, Debug)]
struct Net {
    status: &'static str,
    history: &'static str,
    height: u64,
    send: Answer,
    view_slot: u64,
    history_slot: u64,
}

impl Net {
    /// A consistent RPC: the history is answered at the slot of the height view.
    fn new(status: &'static str, history: &'static str, height: u64, send: Answer) -> Self {
        Self {
            status,
            history,
            height,
            send,
            view_slot: 4_000,
            history_slot: 4_000,
        }
    }
}

fn ctx_at(value: &str, slot: u64) -> Answer {
    Answer::Result(format!(
        "{{\"context\":{{\"slot\":{slot}}},\"value\":{value}}}"
    ))
}

const NULL_STATUS: &str = "[null]";
const PROCESSED: &str = "[{\"slot\":9,\"confirmations\":0,\"err\":null,\"status\":{\"Ok\":null},\"confirmationStatus\":\"processed\"}]";
const CONFIRMED: &str = "[{\"slot\":9,\"confirmations\":1,\"err\":null,\"status\":{\"Ok\":null},\"confirmationStatus\":\"confirmed\"}]";
const LANDED: &str = "[{\"slot\":9,\"confirmations\":null,\"err\":null,\"status\":{\"Ok\":null},\"confirmationStatus\":\"finalized\"}]";
const FAILED: &str = "[{\"slot\":9,\"confirmations\":null,\"err\":{\"InstructionError\":[2,{\"Custom\":1}]},\"status\":{\"Err\":{}},\"confirmationStatus\":\"finalized\"}]";

fn net_rpc(net: &Arc<Mutex<Net>>) -> Arc<FakeRpc> {
    let net = Arc::clone(net);
    FakeRpc::new(move |method, params| {
        let Ok(net) = net.lock() else {
            return Answer::Error(-32_603, None);
        };
        match method {
            "getGenesisHash" => Answer::Result(format!("\"{DEVNET}\"")),
            "getSignatureStatuses" => {
                let history = params
                    .as_array()
                    .and_then(|items| items.get(1))
                    .and_then(Value::as_object)
                    .and_then(|object| object.get("searchTransactionHistory"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if history {
                    ctx_at(net.history, net.history_slot)
                } else {
                    ctx_at(net.status, net.view_slot)
                }
            }
            "getEpochInfo" => Answer::Result(format!(
                "{{\"absoluteSlot\":{},\"blockHeight\":{},\"epoch\":900,\"slotIndex\":1,\"slotsInEpoch\":432000,\"transactionCount\":null}}",
                net.view_slot, net.height
            )),
            "sendTransaction" => net.send.clone(),
            _ => Answer::Error(-32_601, None),
        }
    })
}

const SIGNATURE: [u8; 64] = [0x5a; 64];
const SIGNED_AT: u64 = 1_800_000_000_000;

/// A round of the record signed at `SIGNED_AT`.
fn track(state: LoopState) -> TrackJob {
    TrackJob {
        endpoint: endpoint(),
        signature: SIGNATURE,
        tx: vec![1, 2, 3, 4, 5],
        pending: PendingTx {
            signed_at_ms: SIGNED_AT,
            last_valid_block_height: 1_150,
        },
        state,
        check_genesis: false,
        generation: 0,
        send: SendConfig::default(),
    }
}

fn local_signature() -> String {
    base58_encode(&SIGNATURE)
}

fn accepted() -> Answer {
    Answer::Result(format!("\"{}\"", local_signature()))
}

/// Runs `rounds` rounds 1 s apart; returns the last outcome and the final state.
fn run(
    rpc: &FakeRpc,
    clock: &FakeClock,
    rounds: u32,
    mut state: LoopState,
) -> (Result<Outcome, String>, LoopState) {
    let mut outcome = Ok(Outcome::Pending { notice: false });
    for _ in 0..rounds {
        let result = track_round(rpc, &track(state), clock);
        state = result.state;
        outcome = result.outcome.map_err(|code| code.code().to_owned());
        if !matches!(outcome, Ok(Outcome::Pending { .. })) {
            break;
        }
        clock.advance(1_000);
    }
    (outcome, state)
}

#[test]
fn sol_n1_unseen_transaction_is_resent_unchanged_never_resigned() {
    // ① status null, height ≤ lvbh: only the same bytes are re-sent, every 2.5 s.
    let net = Arc::new(Mutex::new(Net::new(
        NULL_STATUS,
        NULL_STATUS,
        1_100,
        accepted(),
    )));
    let rpc = net_rpc(&net);
    let clock = FakeClock::at(SIGNED_AT + 10_000);
    let (outcome, _) = run(&rpc, &clock, 30, LoopState::default());
    assert!(matches!(outcome, Ok(Outcome::Pending { .. })));
    let sends = rpc.params_of("sendTransaction");
    assert!(sends.len() >= 10 && sends.len() <= 13, "{}", sends.len());
    assert!(
        sends.iter().all(|params| params == &sends[0]),
        "same bytes and parameters"
    );
    assert!(sends[0].contains("\"skipPreflight\":false"));
    assert!(sends[0].contains("\"maxRetries\":0"));
    assert!(sends[0].contains("\"preflightCommitment\":\"confirmed\""));
    assert!(sends[0].contains("AQIDBAU="), "base64 of the signed bytes");
    assert_eq!(
        rpc.count("getSignatureStatuses"),
        30,
        "no history lookup below lvbh"
    );
}

#[test]
fn sol_resign_allowed_as_soon_as_the_rpc_height_passes_lvbh() {
    // Confirmed height 1,151 > lvbh 1,150 and the history search shows nothing: the very first
    // round proves expiry, 1 s after signing — no wall-clock or monotonic minimum, no second
    // round. `Expired` frees the account (D20) for a new review, approval and signature.
    let net = Arc::new(Mutex::new(Net::new(
        NULL_STATUS,
        NULL_STATUS,
        1_151,
        accepted(),
    )));
    let rpc = net_rpc(&net);
    let clock = FakeClock::at(SIGNED_AT + 1_000);
    let result = track_round(&*rpc, &track(LoopState::default()), &clock);
    assert_eq!(
        result.outcome.map_err(ErrorCode::code),
        Ok(Outcome::Expired)
    );
    // The height and slot come from one confirmed getEpochInfo answer; getBlockHeight is not
    // asked; the history lookup follows the height.
    let epoch = rpc.params_of("getEpochInfo");
    assert_eq!(epoch.len(), 1);
    assert!(epoch[0].contains("\"commitment\":\"confirmed\""));
    assert_eq!(rpc.count("getBlockHeight"), 0);
    let history = rpc
        .params_of("getSignatureStatuses")
        .into_iter()
        .filter(|params| params.contains("\"searchTransactionHistory\":true"))
        .count();
    assert_eq!(history, 1);
    // The same holds with a wall clock behind the signing time (no clock is consulted).
    let rpc = net_rpc(&net);
    let (outcome, _) = run(
        &rpc,
        &FakeClock::at(SIGNED_AT - 60_000),
        1,
        LoopState::default(),
    );
    assert_eq!(outcome, Ok(Outcome::Expired));
}

#[test]
fn sol_resign_refused_while_the_rpc_height_is_at_or_below_lvbh() {
    // Height = lvbh: the blockhash can still land the transaction, so the record stays
    // `Pending` (D20 keeps the account busy; "다시 보내기" with a new signature is not offered)
    // however long it takes, and only the same bytes are re-sent.
    for height in [1_000, 1_150] {
        let net = Arc::new(Mutex::new(Net::new(
            NULL_STATUS,
            NULL_STATUS,
            height,
            accepted(),
        )));
        let rpc = net_rpc(&net);
        let clock = FakeClock::at(SIGNED_AT + 600_000);
        let (outcome, _) = run(&rpc, &clock, 20, LoopState::default());
        assert_eq!(outcome, Ok(Outcome::Pending { notice: true }), "{height}");
        assert!(
            rpc.params_of("getSignatureStatuses")
                .iter()
                .all(|params| params.contains("\"searchTransactionHistory\":false")),
            "no history lookup at or below lvbh"
        );
        let sends = rpc.params_of("sendTransaction");
        assert!(sends.len() >= 7);
        assert!(sends.iter().all(|params| params == &sends[0]));
    }
}

#[test]
fn sol_rebroadcast_the_same_tx_now_before_expiry() {
    // Before expiry the user can re-send the same signed bytes at once instead of waiting for
    // the 2.5 s period: one more `sendTransaction` with identical parameters, still `Pending`.
    let net = Arc::new(Mutex::new(Net::new(
        NULL_STATUS,
        NULL_STATUS,
        1_100,
        accepted(),
    )));
    let rpc = net_rpc(&net);
    let clock = FakeClock::at(SIGNED_AT);
    let first = track_round(&*rpc, &track(LoopState::default()), &clock);
    assert_eq!(first.sends, 1);
    clock.advance(500);
    let waiting = track_round(&*rpc, &track(first.state), &clock);
    assert_eq!(waiting.sends, 0, "the period has not passed");
    let mut state = waiting.state;
    state.send_now();
    let now = track_round(&*rpc, &track(state), &clock);
    assert_eq!(now.sends, 1);
    assert!(matches!(now.outcome, Ok(Outcome::Pending { .. })));
    let sends = rpc.params_of("sendTransaction");
    assert_eq!(sends.len(), 2);
    assert_eq!(sends[0], sends[1], "same bytes, same signature");
    assert!(sends[1].contains("AQIDBAU="));
    // After a deterministic preflight error stopped the automatic re-sends, "지금 다시 전송"
    // still sends the same bytes once.
    let net = Arc::new(Mutex::new(Net::new(
        NULL_STATUS,
        NULL_STATUS,
        1_100,
        preflight("\"InsufficientFundsForFee\""),
    )));
    let rpc = net_rpc(&net);
    let (_, mut state) = run(&rpc, &clock, 6, LoopState::default());
    assert!(state.stop_rebroadcast);
    assert_eq!(rpc.count("sendTransaction"), 1);
    state.send_now();
    let again = track_round(&*rpc, &track(state), &clock);
    assert_eq!(again.sends, 1);
    assert_eq!(rpc.count("sendTransaction"), 2);
    let sends = rpc.params_of("sendTransaction");
    assert_eq!(sends[0], sends[1]);
}

#[test]
fn sol_n1_expiry_needs_one_consistent_view() {
    // The history `null` is answered at a slot behind the height view: never Expired.
    let mut behind = Net::new(NULL_STATUS, NULL_STATUS, 1_151, accepted());
    behind.history_slot = behind.view_slot - 1;
    let rpc = net_rpc(&Arc::new(Mutex::new(behind)));
    let (outcome, _) = run(
        &rpc,
        &FakeClock::at(SIGNED_AT + 600_000),
        20,
        LoopState::default(),
    );
    assert!(matches!(outcome, Ok(Outcome::Pending { notice: true })));
    // A history answer ahead of the view is fine.
    let mut ahead = Net::new(NULL_STATUS, NULL_STATUS, 1_151, accepted());
    ahead.history_slot = ahead.view_slot + 50;
    let rpc = net_rpc(&Arc::new(Mutex::new(ahead)));
    let (outcome, _) = run(
        &rpc,
        &FakeClock::at(SIGNED_AT + 1_000),
        1,
        LoopState::default(),
    );
    assert_eq!(outcome, Ok(Outcome::Expired));
    // A malformed getEpochInfo (no absoluteSlot) is no height observation.
    let rpc = FakeRpc::new(|method, _| match method {
        "getEpochInfo" => Answer::Result("{\"blockHeight\":2000}".to_owned()),
        "getSignatureStatuses" => ctx_at(NULL_STATUS, 9_999),
        "sendTransaction" => accepted(),
        _ => Answer::Error(-32_601, None),
    });
    let (outcome, _) = run(
        &rpc,
        &FakeClock::at(SIGNED_AT + 600_000),
        20,
        LoopState::default(),
    );
    assert!(matches!(outcome, Ok(Outcome::Pending { .. })));
}

#[test]
fn sol_n1_late_landing_found_by_history_wins() {
    // ⑥ the history search finds it: Landed / FailedOnChain, not Expired.
    for (history, expected) in [
        (LANDED, Outcome::Landed { slot: 9 }),
        (
            FAILED,
            Outcome::FailedOnChain {
                slot: 9,
                err: err::SYSTEM_INSTRUCTION,
            },
        ),
    ] {
        let net = Arc::new(Mutex::new(Net::new(
            NULL_STATUS,
            history,
            2_000,
            accepted(),
        )));
        let rpc = net_rpc(&net);
        let clock = FakeClock::at(SIGNED_AT + 600_000);
        let (outcome, _) = run(&rpc, &clock, 3, LoopState::default());
        assert_eq!(outcome, Ok(expected));
    }
    // A confirmed (one confirmation is final) or finalized status without history (only the
    // session's first send happened): Landed at once.
    for status in [CONFIRMED, LANDED] {
        let net = Arc::new(Mutex::new(Net::new(status, NULL_STATUS, 1_000, accepted())));
        let rpc = net_rpc(&net);
        let (outcome, _) = run(&rpc, &FakeClock::at(SIGNED_AT), 1, LoopState::default());
        assert_eq!(outcome, Ok(Outcome::Landed { slot: 9 }));
        assert_eq!(rpc.count("sendTransaction"), 1);
    }
    // processed: no re-send after the first, not final yet.
    let net = Arc::new(Mutex::new(Net::new(
        PROCESSED,
        NULL_STATUS,
        1_000,
        accepted(),
    )));
    let rpc = net_rpc(&net);
    let (outcome, state) = run(&rpc, &FakeClock::at(SIGNED_AT), 10, LoopState::default());
    assert!(matches!(outcome, Ok(Outcome::Pending { .. })));
    assert!(state.processing);
    assert_eq!(rpc.count("sendTransaction"), 1);
}

#[test]
fn first_send_goes_out_even_when_the_status_lookup_fails() {
    // The status lookup times out: the first round of the session still sends the signed bytes
    // first, records that send (no immediate repeat), and reports the lookup failure.
    let rpc = FakeRpc::new(|method, _| match method {
        "getSignatureStatuses" => Answer::Transport(yw_win::http::HttpError::Timeout),
        "sendTransaction" => accepted(),
        _ => Answer::Error(-32_601, None),
    });
    let clock = FakeClock::at(SIGNED_AT);
    let result = track_round(&*rpc, &track(LoopState::default()), &clock);
    assert_eq!(rpc.methods(), ["sendTransaction", "getSignatureStatuses"]);
    assert_eq!(result.sends, 1);
    assert_eq!(result.outcome.map_err(ErrorCode::code), Err("E-RPC-002"));
    assert_eq!(result.state.last_round_ms, Some(clock.now_ms()));
    // The next rounds are status first; the next send waits for the status and the period.
    clock.advance(1_000);
    let again = track_round(&*rpc, &track(result.state), &clock);
    assert_eq!(again.sends, 0);
    assert_eq!(rpc.count("sendTransaction"), 1);
    // A deterministic preflight error of that first send is kept even though the lookup failed.
    let rpc = FakeRpc::new(|method, _| match method {
        "getSignatureStatuses" => Answer::Transport(yw_win::http::HttpError::Timeout),
        "sendTransaction" => preflight("\"InsufficientFundsForFee\""),
        _ => Answer::Error(-32_601, None),
    });
    let result = track_round(&*rpc, &track(LoopState::default()), &clock);
    assert!(result.state.stop_rebroadcast);
    assert_eq!(
        result.state.preflight_err,
        Some(err::INSUFFICIENT_FUNDS_FOR_FEE)
    );
}

fn preflight(err: &str) -> Answer {
    Answer::Envelope(
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":0,\"error\":{{\"code\":-32002,\"message\":\"Transaction simulation failed: x\",\"data\":{{\"err\":{err},\"logs\":[],\"accounts\":null,\"unitsConsumed\":0}}}}}}"
        )
        .into_bytes(),
    )
}

#[test]
fn sol_n1_deterministic_preflight_stops_resending_but_keeps_pending() {
    // ⑦ InsufficientFundsForFee: re-sending stops (memory flag), the record stays Pending, the
    // height is still checked for the expiry proof.
    let net = Arc::new(Mutex::new(Net::new(
        NULL_STATUS,
        NULL_STATUS,
        1_000,
        preflight("\"InsufficientFundsForFee\""),
    )));
    let rpc = net_rpc(&net);
    let clock = FakeClock::at(SIGNED_AT + 1_000);
    let (outcome, state) = run(&rpc, &clock, 12, LoopState::default());
    assert!(matches!(outcome, Ok(Outcome::Pending { .. })));
    assert!(state.stop_rebroadcast);
    assert_eq!(state.preflight_err, Some(err::INSUFFICIENT_FUNDS_FOR_FEE));
    assert_eq!(rpc.count("sendTransaction"), 1);
    assert!(rpc.count("getEpochInfo") >= 4);
    // A transient preflight error (BlockhashNotFound) keeps re-sending.
    let net = Arc::new(Mutex::new(Net::new(
        NULL_STATUS,
        NULL_STATUS,
        1_000,
        preflight("\"BlockhashNotFound\""),
    )));
    let rpc = net_rpc(&net);
    let (_, state) = run(&rpc, &FakeClock::at(SIGNED_AT), 12, LoopState::default());
    assert!(!state.stop_rebroadcast);
    assert!(rpc.count("sendTransaction") >= 4);
    // Transport errors too.
    let net = Arc::new(Mutex::new(Net::new(
        NULL_STATUS,
        NULL_STATUS,
        1_000,
        Answer::Transport(yw_win::http::HttpError::Timeout),
    )));
    let rpc = net_rpc(&net);
    let (_, state) = run(&rpc, &FakeClock::at(SIGNED_AT), 12, LoopState::default());
    assert!(!state.stop_rebroadcast);
    assert!(rpc.count("sendTransaction") >= 4);
}

#[test]
fn sol_n1_other_signature_is_an_anomaly() {
    // ⑧ the RPC answers with another signature: RpcAnomaly, state unchanged (still Pending).
    let net = Arc::new(Mutex::new(Net::new(
        NULL_STATUS,
        NULL_STATUS,
        1_000,
        Answer::Result(format!("\"{}\"", base58_encode(&[0x11; 64]))),
    )));
    let rpc = net_rpc(&net);
    let (outcome, state) = run(&rpc, &FakeClock::at(SIGNED_AT), 3, LoopState::default());
    assert!(matches!(outcome, Ok(Outcome::Pending { .. })));
    assert!(state.anomaly);
}

#[test]
fn resume_checks_the_genesis_first() {
    let rpc = FakeRpc::new(|method, _| match method {
        "getGenesisHash" => Answer::Result(format!("\"{MAINNET}\"")),
        _ => Answer::Error(-32_601, None),
    });
    let mut job = track(LoopState::default());
    job.check_genesis = true;
    job.generation = 7;
    let result = track_round(&*rpc, &job, &FakeClock::at(SIGNED_AT));
    assert_eq!(result.generation, 7, "the UI drops results of an older URL");
    assert_eq!(result.genesis_ok, Some(false));
    assert!(result.outcome.is_err());
    assert_eq!(rpc.methods(), ["getGenesisHash"]);
    assert_eq!(result.sends, 0);
}

#[test]
fn balances_and_scan_pin_the_genesis() -> TestResult {
    let rpc = fake(World::default());
    let list = balances(&*rpc, &endpoint(), &[addr(FROM), addr(TO)])
        .map_err(|code| code.code().to_owned())?;
    let lamports: Vec<(SolAddress, u64)> =
        list.iter().map(|row| (row.address, row.lamports)).collect();
    assert_eq!(lamports, [(addr(FROM), 10 * SOL), (addr(TO), 10 * SOL)]);
    // Devnet: exactly the one allowlisted token per account, missing ATA (getAccountInfo null).
    for row in &list {
        assert_eq!(row.tokens.len(), 1);
        assert_eq!(row.tokens[0].1, yw_core::sol::token::TokenHolding::Missing);
    }
    let wrong = fake(World {
        genesis: MAINNET,
        ..World::default()
    });
    assert_eq!(
        balances(&*wrong, &endpoint(), &[addr(FROM)]).map_err(ErrorCode::code),
        Err("E-RPC-006")
    );
    assert_eq!(wrong.count("getBalance"), 0);
    // Scan: funded standard 0 and 2, empty elsewhere → tag 1 stops after 5 empties past 2.
    let funded = [addr(FROM).to_base58(), addr(TO).to_base58()];
    let rpc = FakeRpc::new(move |method, params| match method {
        "getGenesisHash" => Answer::Result(format!("\"{DEVNET}\"")),
        "getBalance" => {
            let address = params
                .as_array()
                .and_then(|items| items.first())
                .and_then(Value::as_str)
                .unwrap_or("");
            ctx(if funded.iter().any(|known| known == address) {
                "42"
            } else {
                "0"
            })
        }
        "getAccountInfo" => ctx("null"),
        _ => Answer::Error(-32_601, None),
    });
    let sources = scan_sources();
    let keys: Vec<(SolKeySource, SolAddress)> = sources
        .iter()
        .enumerate()
        .map(|(position, source)| {
            let address = match position {
                0 => addr(FROM),
                2 => addr(TO),
                other => SolAddress::from_bytes([u8::try_from(other).unwrap_or(0); 32]),
            };
            (*source, address)
        })
        .collect();
    let rows = scan(&*rpc, &endpoint(), &keys).map_err(|code| code.code().to_owned())?;
    let standard = rows.iter().filter(|row| row.source.tag() == 1).count();
    assert_eq!(standard, 3 + usize::try_from(SOL_SCAN_GAP).unwrap_or(5));
    let bip44 = rows.iter().filter(|row| row.source.tag() == 2).count();
    assert_eq!(bip44, usize::try_from(SOL_SCAN_GAP).unwrap_or(5));
    assert_eq!(rows.iter().filter(|row| row.source.tag() >= 3).count(), 2);
    assert_eq!(rows.iter().filter(|row| row.balance == 42).count(), 2);
    Ok(())
}

// ----- dApp transactions (spec/07 §20.7, §20.10) ----------------------------------------------

const TABLE: [u8; 32] = [0x71; 32];
const LOADED_W: [u8; 32] = [0x72; 32];
const LOADED_R: [u8; 32] = [0x73; 32];
const PROGRAM: [u8; 32] = [0x74; 32];
const MINT: [u8; 32] = [0x75; 32];
const NONCE: [u8; 32] = [0x76; 32];
const COSIGNER: [u8; 32] = [0x77; 32];
const DAPP_BLOCKHASH: [u8; 32] = [7; 32];

fn b58(bytes: &[u8; 32]) -> String {
    SolAddress::from_bytes(*bytes).to_base58()
}

fn wallet_bytes() -> [u8; 32] {
    addr(FROM).to_bytes()
}

fn len_u8(len: usize) -> u8 {
    u8::try_from(len).unwrap_or(u8::MAX)
}

/// One compiled instruction: program index, account indices, data.
type CompiledIx<'a> = (u8, &'a [u8], &'a [u8]);
/// One lookup: table, writable indices, read-only indices.
type Lookup<'a> = ([u8; 32], &'a [u8], &'a [u8]);

/// A legacy (`lookups == None`) or v0 message; every length here is below 128 (one shortvec
/// byte).
fn message(
    header: [u8; 3],
    keys: &[[u8; 32]],
    ixs: &[CompiledIx<'_>],
    lookups: Option<&[Lookup<'_>]>,
) -> Vec<u8> {
    let mut out = Vec::new();
    if lookups.is_some() {
        out.push(0x80);
    }
    out.extend_from_slice(&header);
    out.push(len_u8(keys.len()));
    for key in keys {
        out.extend_from_slice(key);
    }
    out.extend_from_slice(&DAPP_BLOCKHASH);
    out.push(len_u8(ixs.len()));
    for (program, accounts, data) in ixs {
        out.push(*program);
        out.push(len_u8(accounts.len()));
        out.extend_from_slice(accounts);
        out.push(len_u8(data.len()));
        out.extend_from_slice(data);
    }
    if let Some(lookups) = lookups {
        out.push(len_u8(lookups.len()));
        for (table, writable, readonly) in lookups {
            out.extend_from_slice(table);
            out.push(len_u8(writable.len()));
            out.extend_from_slice(writable);
            out.push(len_u8(readonly.len()));
            out.extend_from_slice(readonly);
        }
    }
    out
}

/// `shortvec(n) ‖ signatures ‖ message`.
fn wire(signatures: &[[u8; 64]], message: &[u8]) -> Vec<u8> {
    let mut out = vec![len_u8(signatures.len())];
    for signature in signatures {
        out.extend_from_slice(signature);
    }
    out.extend_from_slice(message);
    out
}

/// v0: the wallet signs and pays; an unknown program gets the wallet, a loaded writable token
/// account and a loaded read-only account.
fn alt_tx() -> Vec<u8> {
    wire(
        &[[0; 64]],
        &message(
            [1, 0, 1],
            &[wallet_bytes(), PROGRAM],
            &[(1, &[0, 2, 3], &[1, 2, 3])],
            Some(&[(TABLE, &[0], &[1])]),
        ),
    )
}

/// Legacy without lookups: the wallet calls an unknown program.
fn legacy_tx() -> Vec<u8> {
    wire(
        &[[0; 64]],
        &message(
            [1, 0, 1],
            &[wallet_bytes(), PROGRAM],
            &[(1, &[0], &[9])],
            None,
        ),
    )
}

/// Legacy durable nonce: System `AdvanceNonceAccount` first, on a writable nonce account.
fn nonce_tx() -> Vec<u8> {
    let system = yw_core::sol::address::SYSTEM_PROGRAM.to_bytes();
    wire(
        &[[0; 64]],
        &message(
            [1, 0, 1],
            &[wallet_bytes(), NONCE, system],
            &[(2, &[1, 0], &[4, 0, 0, 0])],
            None,
        ),
    )
}

/// Legacy with two signers: a co-signer pays (slot 0, signed), the wallet signs slot 1.
fn cosigned_tx() -> Vec<u8> {
    wire(
        &[[0x33; 64], [0x44; 64]],
        &message(
            [2, 0, 1],
            &[COSIGNER, wallet_bytes(), PROGRAM],
            &[(2, &[0, 1], &[7])],
            None,
        ),
    )
}

fn table_data(addresses: &[[u8; 32]], last_extended_slot: u64, start: u8) -> Vec<u8> {
    let mut data = vec![0_u8; 56];
    data[0..4].copy_from_slice(&1_u32.to_le_bytes());
    data[4..12].copy_from_slice(&u64::MAX.to_le_bytes());
    data[12..20].copy_from_slice(&last_extended_slot.to_le_bytes());
    data[20] = start;
    for address in addresses {
        data.extend_from_slice(address);
    }
    data
}

fn token_data(mint: &[u8; 32], owner: &[u8; 32], amount: u64) -> Vec<u8> {
    let mut data = vec![0_u8; 165];
    data[0..32].copy_from_slice(mint);
    data[32..64].copy_from_slice(owner);
    data[64..72].copy_from_slice(&amount.to_le_bytes());
    data[108] = 1;
    data
}

fn mint_data(decimals: u8) -> Vec<u8> {
    let mut data = vec![0_u8; 82];
    data[0] = 1;
    data[44] = decimals;
    data[45] = 1;
    data
}

fn account_json(owner: &SolAddress, lamports: u64, data: &[u8]) -> String {
    format!(
        "{{\"data\":[\"{}\",\"base64\"],\"executable\":false,\"lamports\":{lamports},\"owner\":\"{}\",\"rentEpoch\":0,\"space\":{}}}",
        sol::base64(data),
        owner.to_base58(),
        data.len()
    )
}

/// A healthy devnet for dApp transactions: accounts by base58 address (pre-state, and the
/// simulated post-state over it), the blockhash check, the simulation behaviour.
#[derive(Clone)]
struct DappWorld {
    genesis: &'static str,
    accounts: Vec<(String, String)>,
    post: Vec<(String, String)>,
    slot: u64,
    blockhash_valid: bool,
    stale_simulation: bool,
    last_valid: u64,
}

impl Default for DappWorld {
    fn default() -> Self {
        let wallet = wallet_bytes();
        Self {
            genesis: DEVNET,
            accounts: vec![
                (
                    b58(&TABLE),
                    account_json(
                        &ADDRESS_LOOKUP_TABLE_PROGRAM,
                        1,
                        &table_data(&[LOADED_W, LOADED_R], 5, 0),
                    ),
                ),
                (b58(&wallet), account_json(&SYSTEM_PROGRAM, 10 * SOL, &[])),
                (
                    b58(&LOADED_W),
                    account_json(&TOKEN_PROGRAM, 2_039_280, &token_data(&MINT, &wallet, 500)),
                ),
                (b58(&MINT), account_json(&TOKEN_PROGRAM, 1, &mint_data(6))),
            ],
            post: vec![
                (
                    b58(&wallet),
                    account_json(&SYSTEM_PROGRAM, 10 * SOL - 5_000, &[]),
                ),
                (
                    b58(&LOADED_W),
                    account_json(&TOKEN_PROGRAM, 2_039_280, &token_data(&MINT, &wallet, 400)),
                ),
            ],
            slot: 7,
            blockhash_valid: true,
            stale_simulation: false,
            last_valid: 1_150,
        }
    }
}

fn param(params: &Value, index: usize) -> Option<&Value> {
    params.as_array().and_then(|items| items.get(index))
}

fn config_of<'a>(params: &'a Value, key: &str) -> Option<&'a Value> {
    param(params, 1)
        .and_then(Value::as_object)
        .and_then(|object| object.get(key))
}

fn listed<'a>(table: &'a [(String, String)], address: &str) -> Option<&'a str> {
    table
        .iter()
        .find(|(known, _)| known == address)
        .map(|(_, json)| json.as_str())
}

fn dapp_answer(world: &DappWorld, method: &str, params: &Value) -> Answer {
    match method {
        "getGenesisHash" => Answer::Result(format!("\"{}\"", world.genesis)),
        "getMultipleAccounts" => {
            let entries: Vec<&str> = param(params, 0)
                .and_then(Value::as_array)
                .map(|keys| {
                    keys.iter()
                        .map(|key| {
                            listed(&world.accounts, key.as_str().unwrap_or("")).unwrap_or("null")
                        })
                        .collect()
                })
                .unwrap_or_default();
            ctx_at(&format!("[{}]", entries.join(",")), world.slot)
        }
        "isBlockhashValid" => ctx_at(&world.blockhash_valid.to_string(), 9),
        "getLatestBlockhash" => ctx(&format!(
            "{{\"blockhash\":\"{BLOCKHASH}\",\"lastValidBlockHeight\":{}}}",
            world.last_valid
        )),
        "getBlockHeight" => Answer::Result("1000".to_owned()),
        "getFeeForMessage" => ctx("5000"),
        "simulateTransaction" => {
            let replace = config_of(params, "replaceRecentBlockhash").and_then(Value::as_bool);
            if world.stale_simulation && replace == Some(false) {
                return ctx(
                    "{\"err\":\"BlockhashNotFound\",\"logs\":[],\"accounts\":null,\"unitsConsumed\":0}",
                );
            }
            let addresses: Vec<&str> = config_of(params, "accounts")
                .and_then(Value::as_object)
                .and_then(|object| object.get("addresses"))
                .and_then(Value::as_array)
                .map(|keys| {
                    keys.iter()
                        .map(|key| {
                            let key = key.as_str().unwrap_or("");
                            listed(&world.post, key)
                                .or_else(|| listed(&world.accounts, key))
                                .unwrap_or("null")
                        })
                        .collect()
                })
                .unwrap_or_default();
            ctx(&format!(
                "{{\"err\":null,\"logs\":[\"ignored\"],\"accounts\":[{}],\"unitsConsumed\":1200}}",
                addresses.join(",")
            ))
        }
        _ => Answer::Error(-32_601, None),
    }
}

fn dapp_fake(world: DappWorld) -> Arc<FakeRpc> {
    FakeRpc::new(move |method, params| dapp_answer(&world, method, params))
}

fn dapp_job(txs: Vec<Vec<u8>>) -> DappPreviewJob {
    DappPreviewJob {
        job: 3,
        endpoint: endpoint(),
        wallet: addr(FROM),
        txs,
    }
}

/// The addresses of a recorded `getMultipleAccounts` call.
fn keys_param(params: &str) -> Vec<String> {
    let value = yw_json::parse(params.as_bytes(), &Limits::RESPONSE).unwrap_or(Value::Null);
    param(&value, 0)
        .and_then(Value::as_array)
        .map(|keys| {
            keys.iter()
                .filter_map(|key| key.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn resolved() -> ResolvedKeys {
    ResolvedKeys {
        writable: vec![SolAddress::from_bytes(LOADED_W)],
        readonly: vec![SolAddress::from_bytes(LOADED_R)],
    }
}

#[test]
fn dapp_preview_calls_in_order_with_the_spec_config() -> TestResult {
    let rpc = dapp_fake(DappWorld::default());
    let clock = FakeClock::at(SIGNED_AT);
    let preview = dapp_preview(&*rpc, &dapp_job(vec![alt_tx()]), &clock)
        .map_err(|code| code.code().to_owned())?;
    assert_eq!(
        rpc.methods(),
        [
            "getGenesisHash",
            "getMultipleAccounts",
            "getMultipleAccounts",
            "getMultipleAccounts",
            "isBlockhashValid",
            "getFeeForMessage",
            "simulateTransaction",
        ]
    );
    // Tables whole, then the writable accounts' first 166 bytes, then the mints whole.
    let multiple = rpc.params_of("getMultipleAccounts");
    assert_eq!(keys_param(&multiple[0]), [b58(&TABLE)]);
    assert!(!multiple[0].contains("dataSlice"));
    assert_eq!(
        keys_param(&multiple[1]),
        [b58(&wallet_bytes()), b58(&LOADED_W)]
    );
    assert!(multiple[1].contains("\"dataSlice\":{\"offset\":0,\"length\":166}"));
    assert!(multiple[1].contains("\"commitment\":\"confirmed\""));
    assert_eq!(keys_param(&multiple[2]), [b58(&MINT)]);
    assert!(rpc.params_of("isBlockhashValid")[0].contains("\"commitment\":\"processed\""));
    let simulate = &rpc.params_of("simulateTransaction")[0];
    for part in [
        "\"sigVerify\":false",
        "\"replaceRecentBlockhash\":false",
        "\"commitment\":\"confirmed\"",
        "\"innerInstructions\":false",
    ] {
        assert!(simulate.contains(part), "{part}");
    }
    // The watched accounts are keys of the transaction itself: the wallet and its token account.
    assert!(simulate.contains(&format!(
        "\"addresses\":[\"{}\",\"{}\"]",
        b58(&wallet_bytes()),
        b58(&LOADED_W)
    )));
    let [item] = preview.items.as_slice() else {
        return Err("one item".into());
    };
    let (slot, tables) = item.tables.as_ref().map_err(ToString::to_string)?;
    assert_eq!(*slot, 7);
    assert_eq!(tables.len(), 1);
    assert_eq!(
        tables[0].1.addresses,
        [
            SolAddress::from_bytes(LOADED_W),
            SolAddress::from_bytes(LOADED_R)
        ]
    );
    assert_eq!(item.pre.len(), 2);
    assert!(item.pre.iter().all(|(_, snapshot)| snapshot.is_some()));
    let post = item.post.as_ref().ok_or("post-state")?;
    assert_eq!(post.len(), 2);
    assert_eq!(
        post[0].1.as_ref().map(|account| account.lamports),
        Some(10 * SOL - 5_000)
    );
    assert_eq!(item.sim, SimSummary::Ok { units: 1_200 });
    assert!(!item.sim_replaced_blockhash);
    assert_eq!(item.rpc_fee, Some(5_000));
    assert_eq!(item.blockhash_valid, Some(true));
    assert_eq!(preview.mints.len(), 1);
    assert_eq!(preview.mints[0].0, SolAddress::from_bytes(MINT));
    assert_eq!(preview.mints[0].1.decimals, 6);
    // The builder accepts the facts and binds the resolved addresses in the payload.
    let request = SolTxRequest {
        id: ApprovalId([5; 16]),
        origin: BrowserOrigin::parse("https://dapp.example").ok_or("origin")?,
        cluster: SolCluster::Devnet,
        source: SolKeySource::Standard(AccountIndex::ZERO),
        public: wallet_bytes(),
        label: "Solana 1".to_owned(),
        mode: SolTxMode::SignOnly,
        options: SolSendOptions::default(),
        txs: vec![alt_tx()],
    };
    let draft = build_sol_tx_request(&request, &preview.into_facts(Vec::new(), 100_000))
        .map_err(|error| format!("{error:?}"))?;
    let SigningPayload::SolTx(payload) = &draft.payload else {
        return Err("payload".into());
    };
    assert_eq!(payload.items[0].loaded, Some(resolved()));
    // A genesis mismatch stops before anything else.
    let rpc = dapp_fake(DappWorld {
        genesis: MAINNET,
        ..DappWorld::default()
    });
    assert_eq!(
        dapp_preview(&*rpc, &dapp_job(vec![alt_tx()]), &clock),
        Err(ErrorCode::Rpc006)
    );
    assert_eq!(rpc.methods(), ["getGenesisHash"]);
    Ok(())
}

#[test]
fn dapp_preview_table_failures_stay_with_their_transaction() -> TestResult {
    let clock = FakeClock::at(SIGNED_AT);
    // The table account is missing: the v0 item keeps the error (X01 in the builder), the
    // legacy item next to it is unaffected, and the preview still answers.
    let mut world = DappWorld::default();
    world
        .accounts
        .retain(|(address, _)| *address != b58(&TABLE));
    let rpc = dapp_fake(world);
    let preview = dapp_preview(&*rpc, &dapp_job(vec![legacy_tx(), alt_tx()]), &clock)
        .map_err(|code| code.code().to_owned())?;
    assert_eq!(preview.items.len(), 2);
    assert_eq!(preview.items[0].tables, Ok((7, Vec::new())));
    assert_eq!(
        preview.items[1].tables,
        Err(AltError::Missing(SolAddress::from_bytes(TABLE)))
    );
    // Without the loaded keys only the static writable key (the wallet) has a pre-state.
    assert_eq!(preview.items[1].pre.len(), 1);
    assert_eq!(rpc.count("simulateTransaction"), 2);
    // An account of another owner is not a table.
    let mut world = DappWorld::default();
    world.accounts[0].1 =
        account_json(&SYSTEM_PROGRAM, 1, &table_data(&[LOADED_W, LOADED_R], 5, 0));
    let preview = dapp_preview(&*dapp_fake(world), &dapp_job(vec![alt_tx()]), &clock)
        .map_err(|code| code.code().to_owned())?;
    assert_eq!(
        preview.items[0].tables,
        Err(AltError::NotTable(SolAddress::from_bytes(TABLE)))
    );
    // Addresses added in the slot being read are not usable yet (Agave): the table is read, the
    // index fails at resolution and only the static keys remain.
    let mut world = DappWorld::default();
    world.accounts[0].1 = account_json(
        &ADDRESS_LOOKUP_TABLE_PROGRAM,
        1,
        &table_data(&[LOADED_W, LOADED_R], 7, 1),
    );
    let preview = dapp_preview(&*dapp_fake(world), &dapp_job(vec![alt_tx()]), &clock)
        .map_err(|code| code.code().to_owned())?;
    assert!(preview.items[0].tables.is_ok());
    assert_eq!(preview.items[0].pre.len(), 1);
    // A failing required read fails the preview.
    let rpc = FakeRpc::new(|method, _| match method {
        "getGenesisHash" => Answer::Result(format!("\"{DEVNET}\"")),
        _ => Answer::Status(503),
    });
    assert!(dapp_preview(&*rpc, &dapp_job(vec![alt_tx()]), &clock).is_err());
    Ok(())
}

#[test]
fn dapp_preview_retries_a_stale_blockhash_simulation_with_replacement() -> TestResult {
    let clock = FakeClock::at(SIGNED_AT);
    let world = DappWorld {
        stale_simulation: true,
        ..DappWorld::default()
    };
    let rpc = dapp_fake(world.clone());
    let preview = dapp_preview(&*rpc, &dapp_job(vec![legacy_tx()]), &clock)
        .map_err(|code| code.code().to_owned())?;
    let simulate = rpc.params_of("simulateTransaction");
    assert_eq!(simulate.len(), 2);
    assert!(simulate[0].contains("\"replaceRecentBlockhash\":false"));
    assert!(simulate[1].contains("\"replaceRecentBlockhash\":true"));
    assert_eq!(preview.items[0].sim, SimSummary::Ok { units: 1_200 });
    assert!(preview.items[0].sim_replaced_blockhash);
    // A durable nonce is never simulated with another blockhash and its blockhash (the nonce
    // value) is not checked: the stale answer stays (X09).
    let rpc = dapp_fake(world);
    let preview = dapp_preview(&*rpc, &dapp_job(vec![nonce_tx()]), &clock)
        .map_err(|code| code.code().to_owned())?;
    assert_eq!(rpc.count("simulateTransaction"), 1);
    assert_eq!(rpc.count("isBlockhashValid"), 0);
    assert_eq!(preview.items[0].blockhash_valid, None);
    assert_eq!(
        preview.items[0].sim,
        SimSummary::Failed {
            err: err::BLOCKHASH_NOT_FOUND,
            units: Some(0)
        }
    );
    assert!(!preview.items[0].sim_replaced_blockhash);
    assert_eq!(preview.items[0].post, None);
    Ok(())
}

#[test]
fn dapp_preview_reference_calls_stop_at_the_budget() -> TestResult {
    // Every simulation takes 20 s: the first two transactions are simulated, the third keeps
    // no result (X09) and no fee; the shared blockhash is asked once.
    let clock = Arc::new(FakeClock::at(SIGNED_AT));
    let world = DappWorld::default();
    let timer = Arc::clone(&clock);
    let rpc = FakeRpc::new(move |method, params| {
        if method == "simulateTransaction" {
            timer.advance(20_000);
        }
        dapp_answer(&world, method, params)
    });
    let preview = dapp_preview(
        &*rpc,
        &dapp_job(vec![legacy_tx(), legacy_tx(), legacy_tx()]),
        &*clock,
    )
    .map_err(|code| code.code().to_owned())?;
    assert_eq!(rpc.count("isBlockhashValid"), 1);
    assert_eq!(rpc.count("getFeeForMessage"), 2);
    assert_eq!(rpc.count("simulateTransaction"), 2);
    assert_eq!(preview.items[1].sim, SimSummary::Ok { units: 1_200 });
    assert_eq!(preview.items[2].sim, SimSummary::NoResult);
    assert_eq!(preview.items[2].rpc_fee, None);
    assert_eq!(preview.items[2].post, None);
    assert_eq!(preview.items[2].blockhash_valid, Some(true));
    assert_eq!(preview.items[2].pre.len(), 1, "required reads are not cut");
    Ok(())
}

#[test]
fn pre_sign_dapp_checks_the_blockhash_at_processed_and_the_tables_again() -> TestResult {
    let message = |tx: &[u8]| -> TestResult<SolTxMessage> {
        Ok(parse_wire_tx(tx)
            .map_err(|error| error.to_string())?
            .message)
    };
    let alt = message(&alt_tx())?;
    let rpc = dapp_fake(DappWorld::default());
    let (last_valid, check) =
        pre_sign_dapp(&*rpc, &endpoint(), &alt).map_err(|error| format!("{error:?}"))?;
    assert_eq!(last_valid, 1_150);
    assert_eq!(
        check,
        PreSignCheck {
            blockhash: DAPP_BLOCKHASH,
            loaded: Some(resolved()),
        }
    );
    assert_eq!(
        rpc.methods(),
        [
            "getGenesisHash",
            "isBlockhashValid",
            "getMultipleAccounts",
            "getLatestBlockhash",
            "getBlockHeight",
        ]
    );
    // Both blockhash calls at `processed`; the latest one no older than the validity answer.
    assert_eq!(
        rpc.params_of("isBlockhashValid"),
        [format!(
            "[\"{}\",{{\"commitment\":\"processed\"}}]",
            b58(&DAPP_BLOCKHASH)
        )]
    );
    assert_eq!(
        rpc.params_of("getLatestBlockhash"),
        ["[{\"commitment\":\"processed\",\"minContextSlot\":9}]"]
    );
    // Without lookups: no table read, `None`.
    let rpc = dapp_fake(DappWorld::default());
    let (_, check) = pre_sign_dapp(&*rpc, &endpoint(), &message(&legacy_tx())?)
        .map_err(|error| format!("{error:?}"))?;
    assert_eq!(check.loaded, None);
    assert_eq!(rpc.count("getMultipleAccounts"), 0);
    // An expired blockhash stops before the tables and the latest blockhash.
    let rpc = dapp_fake(DappWorld {
        blockhash_valid: false,
        ..DappWorld::default()
    });
    assert_eq!(
        pre_sign_dapp(&*rpc, &endpoint(), &alt),
        Err(PreSignError::BlockhashExpired)
    );
    assert_eq!(rpc.methods(), ["getGenesisHash", "isBlockhashValid"]);
    // The range check of the wallet's own lookup.
    let rpc = dapp_fake(DappWorld {
        last_valid: 1_099,
        ..DappWorld::default()
    });
    assert_eq!(
        pre_sign_dapp(&*rpc, &endpoint(), &alt),
        Err(PreSignError::RpcAnomaly)
    );
    // The table is gone, or no longer holds the indices.
    let mut gone = DappWorld::default();
    gone.accounts.retain(|(address, _)| *address != b58(&TABLE));
    let mut shrunk = DappWorld::default();
    shrunk.accounts[0].1 = account_json(
        &ADDRESS_LOOKUP_TABLE_PROGRAM,
        1,
        &table_data(&[LOADED_W], 5, 0),
    );
    for world in [gone, shrunk] {
        assert_eq!(
            pre_sign_dapp(&*dapp_fake(world), &endpoint(), &alt),
            Err(PreSignError::TablesChanged)
        );
    }
    // Other addresses still resolve: the core signer compares them with the approval.
    let mut changed = DappWorld::default();
    changed.accounts[0].1 = account_json(
        &ADDRESS_LOOKUP_TABLE_PROGRAM,
        1,
        &table_data(&[LOADED_R, LOADED_W], 5, 0),
    );
    let (_, check) = pre_sign_dapp(&*dapp_fake(changed), &endpoint(), &alt)
        .map_err(|error| format!("{error:?}"))?;
    assert!(check.loaded.is_some_and(|keys| keys != resolved()));
    let rpc = dapp_fake(DappWorld {
        genesis: MAINNET,
        ..DappWorld::default()
    });
    assert_eq!(
        pre_sign_dapp(&*rpc, &endpoint(), &alt),
        Err(PreSignError::ClusterMismatch)
    );
    Ok(())
}

#[test]
fn dapp_record_rounds_resend_the_same_bytes_with_its_options() {
    // A co-signed dApp transaction: every send carries the exact signed bytes (both signatures,
    // never re-signed) and the record's options; `minContextSlot` only when given.
    let tx = cosigned_tx();
    let net = Arc::new(Mutex::new(Net::new(
        NULL_STATUS,
        NULL_STATUS,
        1_100,
        Answer::Result(format!("\"{}\"", base58_encode(&[0x33; 64]))),
    )));
    let rpc = net_rpc(&net);
    let clock = FakeClock::at(SIGNED_AT);
    let mut state = LoopState::default();
    for min_context_slot in [Some(42), None, None] {
        let job = TrackJob {
            signature: [0x33; 64],
            tx: tx.clone(),
            send: SendConfig {
                skip_preflight: true,
                preflight_commitment: "processed",
                min_context_slot,
            },
            ..track(state)
        };
        let result = track_round(&*rpc, &job, &clock);
        assert!(result.sends <= 1);
        state = result.state;
        clock.advance(2_500);
    }
    let sends = rpc.params_of("sendTransaction");
    assert!(sends.len() >= 2, "{}", sends.len());
    let base = sol::base64(&tx);
    assert_eq!(
        sends[0],
        format!(
            "[\"{base}\",{{\"encoding\":\"base64\",\"skipPreflight\":true,\"preflightCommitment\":\"processed\",\"maxRetries\":0,\"minContextSlot\":42}}]"
        )
    );
    for later in &sends[1..] {
        assert_eq!(
            *later,
            format!(
                "[\"{base}\",{{\"encoding\":\"base64\",\"skipPreflight\":true,\"preflightCommitment\":\"processed\",\"maxRetries\":0}}]"
            )
        );
    }
    // A failing instruction of another program (code 9) is deterministic: re-sending stops.
    let net = Arc::new(Mutex::new(Net::new(
        NULL_STATUS,
        NULL_STATUS,
        1_000,
        preflight("{\"InstructionError\":[0,{\"Custom\":6001}]}"),
    )));
    let rpc = net_rpc(&net);
    let job = TrackJob {
        signature: [0x33; 64],
        tx,
        ..track(LoopState::default())
    };
    let result = track_round(&*rpc, &job, &clock);
    assert!(result.state.stop_rebroadcast);
    assert_eq!(result.state.preflight_err, Some(err::PROGRAM_INSTRUCTION));
}

#[test]
fn dapp_rpc_requests_are_exact() -> TestResult {
    let rpc = dapp_fake(DappWorld::default());
    let client = RpcClient::new(&*rpc);
    let url = url();
    // The wallet's own requests are unchanged.
    sol::latest_blockhash(&client, &url).map_err(|error| format!("{error:?}"))?;
    let _ = sol::send_transaction(&client, &url, &[1, 2, 3], "x");
    assert_eq!(
        rpc.params_of("getLatestBlockhash"),
        ["[{\"commitment\":\"confirmed\"}]"]
    );
    assert_eq!(
        rpc.params_of("sendTransaction"),
        [
            "[\"AQID\",{\"encoding\":\"base64\",\"skipPreflight\":false,\"preflightCommitment\":\"confirmed\",\"maxRetries\":0}]"
        ]
    );
    let _ = sol::send_transaction_opts(
        &client,
        &url,
        &[1, 2, 3],
        "x",
        &SendConfig {
            skip_preflight: true,
            preflight_commitment: "finalized",
            min_context_slot: Some(5),
        },
    );
    assert_eq!(
        rpc.params_of("sendTransaction")[1],
        "[\"AQID\",{\"encoding\":\"base64\",\"skipPreflight\":true,\"preflightCommitment\":\"finalized\",\"maxRetries\":0,\"minContextSlot\":5}]"
    );
    sol::latest_blockhash_at(&client, &url, "processed", Some(9))
        .map_err(|error| format!("{error:?}"))?;
    assert_eq!(
        rpc.params_of("getLatestBlockhash")[1],
        "[{\"commitment\":\"processed\",\"minContextSlot\":9}]"
    );
    assert_eq!(
        sol::blockhash_valid(&client, &url, &DAPP_BLOCKHASH),
        Ok((true, 9))
    );
    // 150 unknown addresses but one: two calls (100 + 50), one entry per address in order.
    let mut wanted: Vec<SolAddress> = (0..150_u8)
        .map(|index| {
            let mut bytes = [0xe0; 32];
            bytes[0] = index;
            SolAddress::from_bytes(bytes)
        })
        .collect();
    wanted[120] = SolAddress::from_bytes(MINT);
    let (slot, accounts) =
        sol::multiple_accounts(&client, &url, &wanted, 82, Some((0, 166)), Some(3))
            .map_err(|error| format!("{error:?}"))?;
    assert_eq!(slot, 7);
    assert_eq!(accounts.len(), 150);
    assert_eq!(
        accounts
            .iter()
            .position(Option::is_some)
            .map(|index| (index, accounts.iter().flatten().count())),
        Some((120, 1))
    );
    let multiple = rpc.params_of("getMultipleAccounts");
    assert_eq!(multiple.len(), 2);
    assert_eq!(keys_param(&multiple[0]).len(), 100);
    assert_eq!(keys_param(&multiple[1]).len(), 50);
    assert!(multiple[0].ends_with(
        "{\"encoding\":\"base64\",\"commitment\":\"confirmed\",\"dataSlice\":{\"offset\":0,\"length\":166},\"minContextSlot\":3}]"
    ));
    // Longer data than the bound is left out and marked.
    let (_, accounts) = sol::multiple_accounts(
        &client,
        &url,
        &[SolAddress::from_bytes(LOADED_W)],
        82,
        None,
        None,
    )
    .map_err(|error| format!("{error:?}"))?;
    let account = accounts[0].as_ref().ok_or("account")?;
    assert!(account.truncated && account.data.is_empty());
    assert_eq!(account.lamports, 2_039_280);
    let sim = sol::simulate_dapp(&client, &url, &[1, 2, 3], &[addr(FROM)], true);
    assert_eq!(sim.summary, SimSummary::Ok { units: 1_200 });
    assert_eq!(sim.accounts.map(|list| list.len()), Some(1));
    assert_eq!(
        rpc.params_of("simulateTransaction")[0],
        format!(
            "[\"AQID\",{{\"encoding\":\"base64\",\"sigVerify\":false,\"replaceRecentBlockhash\":true,\"commitment\":\"confirmed\",\"innerInstructions\":false,\"accounts\":{{\"encoding\":\"base64\",\"addresses\":[\"{FROM}\"]}}}}]"
        )
    );
    // An answer with another number of entries is malformed (simulation: no accounts).
    let short = FakeRpc::new(|_, _| ctx_at("[null]", 1));
    let short_client = RpcClient::new(&*short);
    assert_eq!(
        sol::multiple_accounts(&short_client, &url, &[addr(FROM), addr(TO)], 82, None, None),
        Err(RpcFailure::Malformed)
    );
    let odd =
        FakeRpc::new(|_, _| ctx("{\"err\":null,\"accounts\":[null,null],\"unitsConsumed\":5}"));
    let sim = sol::simulate_dapp(&RpcClient::new(&*odd), &url, &[1], &[addr(FROM)], false);
    assert_eq!(sim.summary, SimSummary::Ok { units: 5 });
    assert_eq!(sim.accounts, None);
    Ok(())
}
