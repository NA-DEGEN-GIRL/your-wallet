//! v1.1 SPL pipelines over the scripted transport (spec/07 §11, §13.1, §15.2–§15.4, spec/09
//! §4.4): the step-2 preview of an allowlisted token (call order, raw account data, the pinned
//! decimals that a lying RPC cannot change, rent display values and blocks), balances that only
//! ever ask for the derived ATAs of the allowlist (unknown tokens hidden), the broadcast round's
//! token error class, and the recovery scan's "empty" rule.

mod common;

use std::sync::Arc;

use common::{Answer, FakeClock, FakeRpc, url};
use yw_app::sol::flow::{
    PreviewJob, PreviewOutcome, SolEndpoint, SolPrepared, TrackJob, balances, preview, track_round,
};
use yw_app::sol::rpc::{SendConfig, base64};
use yw_app::sol::scan::{SOL_SCAN_GAP, scan, scan_sources};
use yw_core::bip32::path::AccountIndex;
use yw_core::codec::base58::base58_encode;
use yw_core::slip10::SolKeySource;
use yw_core::sol::broadcast::{LoopState, Outcome, PendingTx, err};
use yw_core::sol::display::{SimSummary, SolBlock, SplPreviewFacts, build_sol_transfer_request};
use yw_core::sol::fee::SPL_TRANSFER_CU_LIMIT;
use yw_core::sol::intent::flags;
use yw_core::sol::message::{assemble_transaction, encode_message, parse_message};
use yw_core::sol::pda::associated_token_address;
use yw_core::sol::recipient::check_recipient_for;
use yw_core::sol::rent::RentError;
use yw_core::sol::template::{SPL_ALLOWLIST, SplAllowEntry, spl_entries};
use yw_core::sol::token::TokenHolding;
use yw_core::sol::{SolAddress, SolAsset, SolCluster, SolTransferCore};
use yw_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const DEVNET: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
const FROM: &str = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
const TO: &str = "Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb";
const BLOCKHASH: &str = "US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx";
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const RENT0: u64 = 890_880;
const RENT165: u64 = 2_039_280;
const SOL: u64 = 1_000_000_000;

fn addr(text: &str) -> SolAddress {
    SolAddress::parse(text).unwrap_or(SolAddress::from_bytes([9; 32]))
}

fn devnet_usdc() -> &'static SplAllowEntry {
    spl_entries(SolCluster::Devnet)
        .next()
        .unwrap_or(&SPL_ALLOWLIST[2])
}

fn ata(wallet: &str) -> SolAddress {
    let entry = devnet_usdc();
    associated_token_address(&addr(wallet), &entry.token_program, &entry.mint)
        .map_or(SolAddress::from_bytes([0; 32]), |(address, _)| address)
}

fn ctx(value: &str) -> Answer {
    Answer::Result(format!("{{\"context\":{{\"slot\":7}},\"value\":{value}}}"))
}

fn account(owner: &str, data: &[u8]) -> String {
    format!(
        "{{\"data\":[\"{}\",\"base64\"],\"executable\":false,\"lamports\":2039280,\"owner\":\"{owner}\",\"rentEpoch\":18446744073709551615,\"space\":{}}}",
        base64(data),
        data.len()
    )
}

fn mint_data(decimals: u8) -> Vec<u8> {
    let mut data = vec![0_u8; 82];
    data[0] = 1;
    data[36..44].copy_from_slice(&1_000_000_000_000_u64.to_le_bytes());
    data[44] = decimals;
    data[45] = 1;
    data
}

fn token_data(mint: &SolAddress, owner: &SolAddress, amount: u64, state: u8) -> Vec<u8> {
    let mut data = vec![0_u8; 165];
    data[0..32].copy_from_slice(mint.as_bytes());
    data[32..64].copy_from_slice(owner.as_bytes());
    data[64..72].copy_from_slice(&amount.to_le_bytes());
    data[108] = state;
    data
}

/// A devnet where `FROM` has SOL and USDC, `TO` is a missing wallet without a USDC ATA.
#[derive(Clone)]
struct World {
    balance: u64,
    recipient: String,
    mint: String,
    from_ata: String,
    to_ata: String,
    rent0: u64,
    rent165: u64,
    fee: &'static str,
    simulate: &'static str,
}

impl Default for World {
    fn default() -> Self {
        let mint = devnet_usdc().mint;
        Self {
            balance: SOL,
            recipient: "null".to_owned(),
            mint: account(TOKEN, &mint_data(6)),
            from_ata: account(TOKEN, &token_data(&mint, &addr(FROM), 5_000_000, 1)),
            to_ata: "null".to_owned(),
            rent0: RENT0,
            rent165: RENT165,
            fee: "5000",
            simulate: "{\"err\":null,\"logs\":[],\"accounts\":null,\"unitsConsumed\":27000,\"returnData\":null}",
        }
    }
}

fn first_param(params: &Value) -> String {
    params
        .as_array()
        .and_then(|items| items.first())
        .map(|value| match value {
            Value::String(text) => text.clone(),
            Value::Number(number) => number.as_u64().map_or_else(String::new, |n| n.to_string()),
            _ => String::new(),
        })
        .unwrap_or_default()
}

fn answer(world: &World, method: &str, params: &Value) -> Answer {
    let first = first_param(params);
    match method {
        "getGenesisHash" => Answer::Result(format!("\"{DEVNET}\"")),
        "getBalance" => ctx(&world.balance.to_string()),
        "getAccountInfo" => {
            if first == devnet_usdc().mint.to_base58() {
                ctx(&world.mint)
            } else if first == ata(FROM).to_base58() {
                ctx(&world.from_ata)
            } else if first == ata(TO).to_base58() {
                ctx(&world.to_ata)
            } else {
                ctx(&world.recipient)
            }
        }
        "getMinimumBalanceForRentExemption" => Answer::Result(if first == "165" {
            world.rent165.to_string()
        } else {
            world.rent0.to_string()
        }),
        "getRecentPrioritizationFees" => {
            Answer::Result("[{\"slot\":1,\"prioritizationFee\":0}]".to_owned())
        }
        "getLatestBlockhash" => ctx(&format!(
            "{{\"blockhash\":\"{BLOCKHASH}\",\"lastValidBlockHeight\":1150}}"
        )),
        "getFeeForMessage" => ctx(world.fee),
        "simulateTransaction" => ctx(world.simulate),
        _ => Answer::Error(-32_601, None),
    }
}

fn fake(world: World) -> Arc<FakeRpc> {
    FakeRpc::new(move |method, params| answer(&world, method, params))
}

fn endpoint() -> SolEndpoint {
    SolEndpoint {
        cluster: SolCluster::Devnet,
        url: url(),
    }
}

fn job(amount: Option<u64>) -> TestResult<PreviewJob> {
    let asset = SolAsset::Spl(devnet_usdc());
    Ok(PreviewJob {
        job: 1,
        endpoint: endpoint(),
        source: SolKeySource::Standard(AccountIndex::ZERO),
        from: addr(FROM),
        account_label: "Solana 1".to_owned(),
        recipient: check_recipient_for(TO, &addr(FROM), &[], asset)
            .map_err(|error| format!("{error:?}"))?,
        asset,
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

fn blocks(world: World, amount: Option<u64>) -> TestResult<Vec<SolBlock>> {
    Ok(ready(preview(&*fake(world), &job(amount)?).outcome)?
        .facts
        .blocks)
}

#[test]
fn spl_preview_calls_in_spec_order_and_builds_the_core() -> TestResult {
    let rpc = fake(World::default());
    let prepared = ready(preview(&*rpc, &job(Some(1_500_000))?).outcome)?;
    assert_eq!(
        rpc.methods(),
        [
            "getGenesisHash",
            "getBalance",
            "getAccountInfo",
            "getAccountInfo",
            "getAccountInfo",
            "getAccountInfo",
            "getMinimumBalanceForRentExemption",
            "getMinimumBalanceForRentExemption",
            "getRecentPrioritizationFees",
            "getLatestBlockhash",
            "getFeeForMessage",
            "simulateTransaction",
        ]
    );
    // getAccountInfo: recipient (dataSlice 0/0), then mint, from_ata, to_ata with full data.
    let infos = rpc.params_of("getAccountInfo");
    assert!(infos[0].contains(TO) && infos[0].contains("\"dataSlice\""));
    for (params, address) in infos[1..].iter().zip([
        devnet_usdc().mint.to_base58(),
        ata(FROM).to_base58(),
        ata(TO).to_base58(),
    ]) {
        assert!(params.contains(&address), "{params}");
        assert!(!params.contains("dataSlice"), "{params}");
        assert!(params.contains("\"encoding\":\"base64\""));
        assert!(!params.contains("jsonParsed"));
    }
    let rents = rpc.params_of("getMinimumBalanceForRentExemption");
    assert!(
        rents[0].starts_with("[0,") && rents[1].starts_with("[165,"),
        "{rents:?}"
    );
    let fees = rpc.params_of("getRecentPrioritizationFees").join("");
    for writable in [FROM.to_owned(), ata(FROM).to_base58(), ata(TO).to_base58()] {
        assert!(fees.contains(&writable));
    }
    assert!(
        prepared.facts.blocks.is_empty(),
        "{:?}",
        prepared.facts.blocks
    );
    assert_eq!(
        prepared.core,
        SolTransferCore {
            from: addr(FROM),
            to: addr(TO),
            asset: SolAsset::Spl(devnet_usdc()),
            amount: 1_500_000,
            cu_limit: SPL_TRANSFER_CU_LIMIT,
            cu_price_micro: 0,
        }
    );
    assert_eq!(prepared.max_fee, 5_000);
    assert_eq!(
        prepared.facts.spl,
        Some(SplPreviewFacts {
            token_balance: Some(5_000_000),
            to_ata_exists: false,
            rent165: RENT165,
        })
    );
    assert_eq!(prepared.facts.simulation, SimSummary::Ok { units: 27_000 });
    assert_eq!(prepared.flags, flags::FIRST_TIME);
    // The approval draft: 0x0503 shows the rent the sender pays.
    let intent = prepared.intent([1; 16], 1_800_000_000_000);
    let draft = build_sol_transfer_request(&intent, &prepared.genesis, &prepared.facts)
        .map_err(|error| format!("{error:?}"))?;
    let ata_field = draft
        .display
        .fields
        .iter()
        .find(|field| field.key.0 == 0x0503)
        .ok_or("no 0x0503")?;
    assert!(ata_field.value.contains("2,039,280 lamports"));
    assert_eq!(
        draft.display.title,
        "[Solana devnet (테스트)] 토큰 전송: 1.500000 USDC"
    );
    Ok(())
}

/// Decimals pinning: an RPC that reports 9 decimals for the mint (or a foreign account at the
/// mint address) blocks the request; the message still carries the pinned 6.
#[test]
fn spl_rpc_decimals_lie_blocks_and_never_changes_the_message() -> TestResult {
    let lying = World {
        mint: account(TOKEN, &mint_data(9)),
        ..World::default()
    };
    let prepared = ready(preview(&*fake(lying), &job(Some(1_000_000))?).outcome)?;
    assert_eq!(prepared.facts.blocks, [SolBlock::RpcAnomaly]);
    assert_eq!(prepared.core.asset, SolAsset::Spl(devnet_usdc()));
    let message = encode_message(&prepared.core, &[7; 32]);
    assert_eq!(
        message.last(),
        Some(&6),
        "TransferChecked decimals stay pinned"
    );
    assert_eq!(
        parse_message(&message, SolCluster::Devnet)
            .map_err(|error| format!("{error:?}"))?
            .0,
        prepared.core
    );
    for mint in [
        "null".to_owned(),
        account("11111111111111111111111111111111", &mint_data(6)),
        account(TOKEN, &mint_data(6)[..81]),
    ] {
        assert_eq!(
            blocks(
                World {
                    mint,
                    ..World::default()
                },
                Some(1)
            )?,
            [SolBlock::RpcAnomaly]
        );
    }
    Ok(())
}

#[test]
fn spl_token_and_sol_rules_block() -> TestResult {
    let mint = devnet_usdc().mint;
    // No sender ATA.
    assert_eq!(
        blocks(
            World {
                from_ata: "null".to_owned(),
                ..World::default()
            },
            Some(1)
        )?,
        [SolBlock::Rent(RentError::NoTokenAccount)]
    );
    // More than the token balance; exactly the balance passes.
    assert_eq!(
        blocks(World::default(), Some(5_000_001))?,
        [SolBlock::Rent(RentError::InsufficientTokens)]
    );
    assert!(blocks(World::default(), Some(5_000_000))?.is_empty());
    // SOL reserve: fee + rent165 + rent0 exactly passes, one lamport less blocks.
    let needed = 5_000 + RENT165 + RENT0;
    assert!(
        blocks(
            World {
                balance: needed,
                ..World::default()
            },
            Some(1)
        )?
        .is_empty()
    );
    assert_eq!(
        blocks(
            World {
                balance: needed - 1,
                ..World::default()
            },
            Some(1)
        )?,
        [SolBlock::Rent(RentError::SolReserve {
            needed,
            rent0: RENT0
        })]
    );
    // An existing destination ATA needs no rent.
    let existing = World {
        balance: 5_000 + RENT0,
        to_ata: account(TOKEN, &token_data(&mint, &addr(TO), 0, 1)),
        ..World::default()
    };
    let prepared = ready(preview(&*fake(existing), &job(Some(1))?).outcome)?;
    assert!(prepared.facts.blocks.is_empty());
    assert_eq!(prepared.facts.spl.map(|spl| spl.to_ata_exists), Some(true));
    // Frozen accounts; a foreign account at the sender's ATA address; rent165 out of range.
    assert_eq!(
        blocks(
            World {
                from_ata: account(TOKEN, &token_data(&mint, &addr(FROM), 5_000_000, 2)),
                ..World::default()
            },
            Some(1)
        )?,
        [SolBlock::TokenAccountFrozen]
    );
    assert_eq!(
        blocks(
            World {
                to_ata: account(TOKEN, &token_data(&mint, &addr(TO), 0, 2)),
                ..World::default()
            },
            Some(1)
        )?,
        [SolBlock::RecipientTokenAccountUnusable]
    );
    assert_eq!(
        blocks(
            World {
                from_ata: account(TOKEN, &token_data(&mint, &addr(TO), 5_000_000, 1)),
                ..World::default()
            },
            Some(1)
        )?,
        [
            SolBlock::RpcAnomaly,
            SolBlock::Rent(RentError::NoTokenAccount)
        ]
    );
    for rent165 in [0, 5_000_001] {
        assert_eq!(
            blocks(
                World {
                    rent165,
                    ..World::default()
                },
                Some(1)
            )?,
            [SolBlock::RpcAnomaly],
            "{rent165}"
        );
    }
    Ok(())
}

#[test]
fn spl_send_max_is_the_whole_token_balance() -> TestResult {
    // A lower RPC fee estimate does not refuse SPL "send max" (the SOL account is not emptied).
    let lower = World {
        fee: "4999",
        ..World::default()
    };
    let prepared = ready(preview(&*fake(lower), &job(None)?).outcome)?;
    assert!(
        prepared.facts.blocks.is_empty(),
        "{:?}",
        prepared.facts.blocks
    );
    assert_eq!(prepared.core.amount, 5_000_000);
    assert_ne!(prepared.flags & flags::SEND_MAX, 0);
    // Zero tokens: nothing to send.
    let mint = devnet_usdc().mint;
    assert_eq!(
        blocks(
            World {
                from_ata: account(TOKEN, &token_data(&mint, &addr(FROM), 0, 1)),
                ..World::default()
            },
            None
        )?,
        [SolBlock::Rent(RentError::InsufficientTokens)]
    );
    Ok(())
}

/// Balances only ever ask for the derived ATA of each allowlisted token: an unknown token in
/// the wallet is never fetched, and a foreign account at the ATA address is not shown.
#[test]
fn spl_balances_read_only_the_allowlisted_atas() -> TestResult {
    let mint = devnet_usdc().mint;
    let data = account(TOKEN, &token_data(&mint, &addr(FROM), 1_234_567, 1));
    let foreign = account(
        TOKEN,
        &token_data(&SolAddress::from_bytes([0x66; 32]), &addr(TO), 99, 1),
    );
    let (from_ata, to_ata) = (ata(FROM).to_base58(), ata(TO).to_base58());
    let rpc = FakeRpc::new(move |method, params| {
        let first = first_param(params);
        match method {
            "getGenesisHash" => Answer::Result(format!("\"{DEVNET}\"")),
            "getBalance" => ctx("7"),
            "getAccountInfo" if first == from_ata => ctx(&data),
            "getAccountInfo" if first == to_ata => ctx(&foreign),
            _ => Answer::Error(-32_601, None),
        }
    });
    let rows = balances(&*rpc, &endpoint(), &[addr(FROM), addr(TO)])
        .map_err(|code| code.code().to_owned())?;
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[0].tokens,
        [(devnet_usdc(), TokenHolding::Active(1_234_567))]
    );
    assert_eq!(rows[1].tokens, [(devnet_usdc(), TokenHolding::Invalid)]);
    assert_eq!(
        rpc.methods(),
        [
            "getGenesisHash",
            "getBalance",
            "getAccountInfo",
            "getBalance",
            "getAccountInfo"
        ]
    );
    // Mainnet asks for both allowlisted tokens and nothing else; the USDC ATA of HAgk14… is
    // the spec/07 §17.3 vector.
    let mainnet = FakeRpc::new(|method, _| match method {
        "getGenesisHash" => {
            Answer::Result("\"5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d\"".to_owned())
        }
        "getBalance" => ctx("7"),
        "getAccountInfo" => ctx("null"),
        _ => Answer::Error(-32_601, None),
    });
    let endpoint = SolEndpoint {
        cluster: SolCluster::Mainnet,
        url: url(),
    };
    let rows =
        balances(&*mainnet, &endpoint, &[addr(FROM)]).map_err(|code| code.code().to_owned())?;
    let symbols: Vec<&str> = rows[0]
        .tokens
        .iter()
        .map(|(entry, _)| entry.symbol)
        .collect();
    assert_eq!(symbols, ["USDC", "USDT"]);
    let asked = mainnet.params_of("getAccountInfo");
    assert_eq!(asked.len(), 2);
    assert!(asked[0].contains("5N3f1tj9v1vc5TUZ8S7mCAnVmjVKrfnzXWhxLaxyZAgt"));
    Ok(())
}

/// The broadcast round classifies `InstructionError` of the token instructions as code 5.
#[test]
fn spl_track_round_classifies_token_errors() {
    let core = SolTransferCore {
        from: addr(FROM),
        to: addr(TO),
        asset: SolAsset::Spl(devnet_usdc()),
        amount: 1,
        cu_limit: SPL_TRANSFER_CU_LIMIT,
        cu_price_micro: 0,
    };
    let signature = [0x5a; 64];
    let tx = assemble_transaction(&signature, &encode_message(&core, &[7; 32]));
    let rpc = FakeRpc::new(|method, _| match method {
        "getSignatureStatuses" => ctx(
            "[{\"slot\":9,\"confirmations\":null,\"err\":{\"InstructionError\":[3,{\"Custom\":1}]},\"status\":{\"Err\":{}},\"confirmationStatus\":\"finalized\"}]",
        ),
        _ => Answer::Error(-32_601, None),
    });
    let job = TrackJob {
        endpoint: endpoint(),
        signature,
        tx,
        pending: PendingTx {
            signed_at_ms: 1_800_000_000_000,
            last_valid_block_height: 1_150,
        },
        state: LoopState::default(),
        check_genesis: false,
        generation: 0,
        send: SendConfig::default(),
    };
    let result = track_round(&*rpc, &job, &FakeClock::at(1_800_000_001_000));
    assert_eq!(
        result.outcome,
        Ok(Outcome::FailedOnChain {
            slot: 9,
            err: err::TOKEN_INSTRUCTION
        })
    );
    assert_eq!(base58_encode(&result.signature), base58_encode(&signature));
}

/// Recovery scan (spec/07 §3.3): an account holding only USDC is not "empty".
#[test]
fn spl_scan_counts_token_only_accounts() -> TestResult {
    let mint = devnet_usdc().mint;
    // Standard 0..=3 are empty, 4 holds USDC only, the rest empty.
    let keys: Vec<(SolKeySource, SolAddress)> = scan_sources()
        .iter()
        .enumerate()
        .map(|(position, source)| {
            let address = match position {
                4 => addr(FROM),
                other => SolAddress::from_bytes([u8::try_from(other).unwrap_or(0); 32]),
            };
            (*source, address)
        })
        .collect();
    let data = account(TOKEN, &token_data(&mint, &addr(FROM), 3, 1));
    let from_ata = ata(FROM).to_base58();
    let rpc = FakeRpc::new(move |method, params| match method {
        "getGenesisHash" => Answer::Result(format!("\"{DEVNET}\"")),
        "getBalance" => ctx("0"),
        "getAccountInfo" if first_param(params) == from_ata => ctx(&data),
        "getAccountInfo" => ctx("null"),
        _ => Answer::Error(-32_601, None),
    });
    let rows = scan(&*rpc, &endpoint(), &keys).map_err(|code| code.code().to_owned())?;
    let standard: Vec<_> = rows.iter().filter(|row| row.source.tag() == 1).collect();
    // Without the token, the gap rule would stop after 5 (indices 0..=4).
    assert_eq!(
        standard.len(),
        5 + usize::try_from(SOL_SCAN_GAP).unwrap_or(5)
    );
    let funded: Vec<_> = rows.iter().filter(|row| row.has_funds()).collect();
    assert_eq!(funded.len(), 1);
    assert_eq!(funded[0].address, addr(FROM));
    assert_eq!(funded[0].tokens, [(devnet_usdc(), TokenHolding::Active(3))]);
    Ok(())
}
