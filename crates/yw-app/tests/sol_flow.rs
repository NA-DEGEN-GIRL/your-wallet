//! Solana pipelines over the scripted transport (spec/07 §13–§15, spec/09 §4.4): the step-2
//! preview with its call order, `L01` blocks and flags; the step-5 lookup and its range check;
//! the broadcast round state machine against a fake RPC and a manual clock (SOL-N1: the same
//! signed bytes are re-sent, never re-signed; `Expired` only after two height rounds, each with a
//! `getEpochInfo` height above `lastValidBlockHeight`, a history `null` answered at or after that
//! view's slot, and 90 s of both the wall and the monotonic clock);
//! balances and the recovery scan with the genesis pin.

mod common;

use std::sync::{Arc, Mutex};

use common::{Answer, FakeClock, FakeRpc, url};
use yw_app::errors::ErrorCode;
use yw_app::flow::evm::Clock as _;
use yw_app::sol::flow::{
    PreSignError, PreviewJob, PreviewOutcome, SolEndpoint, SolPrepared, TrackJob, balances,
    pre_sign, preview, track_round,
};
use yw_app::sol::scan::{SOL_SCAN_GAP, scan, scan_sources};
use yw_core::bip32::path::AccountIndex;
use yw_core::codec::base58::base58_encode;
use yw_core::slip10::SolKeySource;
use yw_core::sol::broadcast::{LoopState, Outcome, PendingTx, err};
use yw_core::sol::display::{SimSummary, SolBlock};
use yw_core::sol::fee::{FeeError, SOL_TRANSFER_CU_LIMIT};
use yw_core::sol::intent::flags;
use yw_core::sol::recipient::check_recipient;
use yw_core::sol::rent::RentError;
use yw_core::sol::{SolAddress, SolAsset, SolCluster};
use yw_json::Value;

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
    assert!(params.contains("\"commitment\":\"finalized\""));
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
const PROCESSED: &str = "[{\"slot\":9,\"confirmations\":0,\"err\":null,\"status\":{\"Ok\":null},\"confirmationStatus\":\"confirmed\"}]";
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

/// A round of the record signed at `SIGNED_AT`, tracked since monotonic `since`.
fn track_since(state: LoopState, since: u64) -> TrackJob {
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
        tracked_since_ms: since,
        generation: 0,
    }
}

fn track(state: LoopState) -> TrackJob {
    track_since(state, 0)
}

/// Monotonic ms of the signing when it happened in this session (both clocks agree).
fn signed_in_session(clock: &FakeClock) -> u64 {
    clock
        .now_ms()
        .saturating_sub(clock.now_unix_ms().saturating_sub(SIGNED_AT))
}

fn local_signature() -> String {
    base58_encode(&SIGNATURE)
}

fn accepted() -> Answer {
    Answer::Result(format!("\"{}\"", local_signature()))
}

/// Runs `rounds` rounds 1 s apart (a record signed in this session); returns the last outcome
/// and the final state.
fn run(
    rpc: &FakeRpc,
    clock: &FakeClock,
    rounds: u32,
    state: LoopState,
) -> (Result<Outcome, String>, LoopState) {
    run_since(rpc, clock, rounds, state, signed_in_session(clock))
}

/// [`run`] for a record tracked since monotonic `since`.
fn run_since(
    rpc: &FakeRpc,
    clock: &FakeClock,
    rounds: u32,
    mut state: LoopState,
    since: u64,
) -> (Result<Outcome, String>, LoopState) {
    let mut outcome = Ok(Outcome::Pending { notice: false });
    for _ in 0..rounds {
        let result = track_round(rpc, &track_since(state, since), clock);
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
    assert!(sends[0].contains("\"preflightCommitment\":\"finalized\""));
    assert!(sends[0].contains("AQIDBAU="), "base64 of the signed bytes");
    assert_eq!(
        rpc.count("getSignatureStatuses"),
        30,
        "no history lookup below lvbh"
    );
}

#[test]
fn sol_n1_expiry_needs_height_history_and_90_seconds() {
    // ② height > lvbh and history null but < 90 s since signing: still Pending.
    let net = Arc::new(Mutex::new(Net::new(
        NULL_STATUS,
        NULL_STATUS,
        1_151,
        accepted(),
    )));
    let rpc = net_rpc(&net);
    let clock = FakeClock::at(SIGNED_AT + 30_000);
    let (outcome, state) = run(&rpc, &clock, 50, LoopState::default());
    assert!(matches!(outcome, Ok(Outcome::Pending { .. })));
    assert!(
        rpc.count("getSignatureStatuses") > 50,
        "history asked after the height"
    );
    assert!(state.last_round_ms.is_some());
    // Height and slot come from one getEpochInfo answer; getBlockHeight is not asked.
    assert!(rpc.count("getEpochInfo") >= 16);
    assert_eq!(rpc.count("getBlockHeight"), 0);
    let history = rpc
        .params_of("getSignatureStatuses")
        .into_iter()
        .filter(|params| params.contains("\"searchTransactionHistory\":true"))
        .count();
    assert_eq!(history, rpc.count("getEpochInfo"));
    // ③ every condition in two height rounds (2.5 s apart): Expired; a new send needs a new
    // intent and approval (nothing here re-signs). Height rounds at 89 s (too early), 92 s
    // (first proof round) and 95 s (second).
    let rpc = net_rpc(&net);
    let clock = FakeClock::at(SIGNED_AT + 89_000);
    let (outcome, state) = run(&rpc, &clock, 10, LoopState::default());
    assert_eq!(outcome, Ok(Outcome::Expired), "{state:?}");
    assert_eq!(rpc.count("getEpochInfo"), 3);
    assert_eq!(clock.now_unix_ms(), SIGNED_AT + 95_000);
}

#[test]
fn sol_n1_expiry_needs_one_consistent_view_and_the_monotonic_clock() {
    // The history `null` is answered at a slot behind the height view: never Expired.
    let mut behind = Net::new(NULL_STATUS, NULL_STATUS, 1_151, accepted());
    behind.history_slot = behind.view_slot - 1;
    let rpc = net_rpc(&Arc::new(Mutex::new(behind)));
    let (outcome, state) = run(
        &rpc,
        &FakeClock::at(SIGNED_AT + 600_000),
        20,
        LoopState::default(),
    );
    assert!(matches!(outcome, Ok(Outcome::Pending { notice: true })));
    assert_eq!(state.expiry_rounds, 0);
    // A history answer ahead of the view is fine.
    let mut ahead = Net::new(NULL_STATUS, NULL_STATUS, 1_151, accepted());
    ahead.history_slot = ahead.view_slot + 50;
    let rpc = net_rpc(&Arc::new(Mutex::new(ahead)));
    let (outcome, _) = run(
        &rpc,
        &FakeClock::at(SIGNED_AT + 600_000),
        20,
        LoopState::default(),
    );
    assert_eq!(outcome, Ok(Outcome::Expired));
    // The wall clock says 10 minutes, but this session started tracking (restart, unlock) just
    // now: 90 s of monotonic time are still needed.
    let net = Arc::new(Mutex::new(Net::new(
        NULL_STATUS,
        NULL_STATUS,
        1_151,
        accepted(),
    )));
    let rpc = net_rpc(&net);
    let clock = FakeClock::at(SIGNED_AT + 600_000);
    let since = clock.now_ms();
    let (outcome, state) = run_since(&rpc, &clock, 85, LoopState::default(), since);
    assert!(matches!(outcome, Ok(Outcome::Pending { .. })));
    assert_eq!(state.expiry_rounds, 0);
    let (outcome, _) = run_since(&rpc, &clock, 15, state, since);
    assert_eq!(outcome, Ok(Outcome::Expired));
    // A malformed getEpochInfo (no absoluteSlot) is no height observation.
    let rpc = FakeRpc::new(|method, _| match method {
        "getEpochInfo" => Answer::Result("{\"blockHeight\":2000}".to_owned()),
        "getSignatureStatuses" => ctx_at(NULL_STATUS, 9_999),
        "sendTransaction" => accepted(),
        _ => Answer::Error(-32_601, None),
    });
    let (outcome, state) = run(
        &rpc,
        &FakeClock::at(SIGNED_AT + 600_000),
        20,
        LoopState::default(),
    );
    assert!(matches!(outcome, Ok(Outcome::Pending { .. })));
    assert_eq!(state.expiry_rounds, 0);
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
    // A finalized status without history (only the session's first send happened).
    let net = Arc::new(Mutex::new(Net::new(LANDED, NULL_STATUS, 1_000, accepted())));
    let rpc = net_rpc(&net);
    let (outcome, _) = run(&rpc, &FakeClock::at(SIGNED_AT), 1, LoopState::default());
    assert_eq!(outcome, Ok(Outcome::Landed { slot: 9 }));
    assert_eq!(rpc.count("sendTransaction"), 1);
    // processed/confirmed: no re-send after the first, not success.
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
