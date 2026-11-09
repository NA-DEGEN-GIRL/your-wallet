//! EVM worlds for the flow tests: a chain answering like Sepolia through [`FakeRpc`], send
//! jobs and small accessors.

use std::collections::HashMap;
use std::sync::Arc;

use super::{Answer, FakeRpc, Script, hex, url};
use yw_app::flow::evm::prepare::{PrepareJob, PrepareOutcome, Prepared, SendIntent};
use yw_app::flow::evm::{ChainJob, Limits};
use yw_core::approval::{ApprovalId, ApprovalOrigin};
use yw_core::bip32::path::AccountIndex;
use yw_core::evm::address::{Address, parse_address};
use yw_core::evm::amount::U256;
use yw_core::evm::chain::{ChainInfo, SimulationSupport, UserChainInput, user_chain_info};
use yw_core::vault::EvmKeySource;

/// Test result.
pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The S2 sender (abandon … about, account 0).
pub const USER: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
/// The S2 recipient.
pub const NEW: &str = "0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb";
/// The S2 block time.
pub const S2_UNIX_MS: u64 = 0x6ac6_4ee0 * 1_000;

/// An `eth_simulateV1` fixture envelope.
pub fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/eth_simulateV1")
        .join(format!("{name}.response.json"));
    std::fs::read(path).unwrap_or_default()
}

pub fn limits() -> Limits {
    Limits {
        sim_wait_ms: 3_000,
        budget_ms: 30_000,
        retry_delay_ms: 0,
        broadcast_retry_ms: [0, 0],
    }
}

pub fn fee_history() -> String {
    let base = ["\"0x3b9aca00\""; 11].join(",");
    let ratios = ["0.5"; 10].join(",");
    let rewards = ["[\"0x5f5e100\"]"; 10].join(",");
    format!(
        "{{\"oldestBlock\":\"0x1\",\"baseFeePerGas\":[{base}],\"gasUsedRatio\":[{ratios}],\"reward\":[{rewards}]}}"
    )
}

pub fn block(hash: &[u8; 32], number: u64) -> String {
    format!("{{\"number\":\"0x{number:x}\",\"hash\":\"{}\"}}", hex(hash))
}

/// A chain that answers like Sepolia (genesis constant, nonce 5, 1 gwei base fee, 204,600 gas).
pub fn world(chain_id: u64, genesis: [u8; 32], overrides: Vec<(&str, Answer)>) -> Script {
    let mut answers: HashMap<String, Answer> = HashMap::new();
    answers.insert(
        "eth_chainId".to_owned(),
        Answer::Result(format!("\"0x{chain_id:x}\"")),
    );
    answers.insert(
        "eth_getBlockByNumber".to_owned(),
        Answer::Result(block(&genesis, 0)),
    );
    answers.insert(
        "eth_getCode".to_owned(),
        Answer::Result("\"0x\"".to_owned()),
    );
    answers.insert(
        "eth_getTransactionCount".to_owned(),
        Answer::Result("\"0x5\"".to_owned()),
    );
    answers.insert("eth_feeHistory".to_owned(), Answer::Result(fee_history()));
    answers.insert(
        "eth_estimateGas".to_owned(),
        Answer::Result("\"0x31f38\"".to_owned()),
    );
    answers.insert("eth_simulateV1".to_owned(), Answer::Envelope(fixture("S2")));
    answers.insert(
        "eth_getTransactionReceipt".to_owned(),
        Answer::Result("null".to_owned()),
    );
    answers.insert(
        "eth_getTransactionByHash".to_owned(),
        Answer::Result("null".to_owned()),
    );
    for (method, answer) in overrides {
        answers.insert(method.to_owned(), answer);
    }
    Script { answers }
}

pub fn fake(script: Script) -> Arc<FakeRpc> {
    FakeRpc::new(move |method, _params| script.get(method))
}

pub fn address(text: &str) -> TestResult<Address> {
    Ok(parse_address(text)?)
}

pub fn send_intent() -> TestResult<SendIntent> {
    Ok(SendIntent {
        to: address(NEW)?,
        value: U256::from_u64(0x0023_86f2_6fc1_0000),
        data: Vec::new(),
        access_list: Vec::new(),
        dapp_gas: None,
        dapp_nonce: None,
    })
}

pub fn job(chain: ChainInfo, account: Address, intent: SendIntent) -> PrepareJob {
    PrepareJob {
        job: 1,
        chain: ChainJob {
            caps: chain.default_caps,
            info: chain,
            url: url(),
        },
        id: ApprovalId([9; 16]),
        origin: ApprovalOrigin::App,
        account,
        signer: EvmKeySource::Derived(AccountIndex::ZERO),
        intent,
        replace: None,
        records: Vec::new(),
        journal_room: true,
        address_book: Vec::new(),
        own_accounts: Vec::new(),
        known: Vec::new(),
        extra_warnings: Vec::new(),
        limits: limits(),
    }
}

pub fn ready(outcome: PrepareOutcome) -> TestResult<Prepared> {
    match outcome {
        PrepareOutcome::Ready(prepared) => Ok(*prepared),
        PrepareOutcome::Failed(failure) => Err(format!("failed: {}", failure.message()).into()),
    }
}

pub fn rules(prepared: &Prepared) -> Vec<String> {
    prepared
        .draft
        .display
        .warnings
        .iter()
        .map(|warning| warning.rule.label())
        .collect()
}

pub fn user_chain(chain_id: u64, genesis: [u8; 32], simulation: SimulationSupport) -> ChainInfo {
    user_chain_info(
        &UserChainInput {
            chain_id,
            name: "Test Chain".to_owned(),
            native_symbol: "TST".to_owned(),
            native_decimals: 18,
            explorer: None,
            simulation,
        },
        genesis,
    )
}
