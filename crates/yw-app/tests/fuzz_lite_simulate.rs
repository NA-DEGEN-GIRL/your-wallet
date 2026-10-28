//! spec/09 §2.4 fallback for the `simulate` fuzz target (M2-3): the yw-app `eth_simulateV1`
//! response parser feeding yw-core `evm::simulate` interpretation and the approval builder, over
//! 1,000,000 xorshift64* mutations of the S1–S16 fixtures. Invariants: no panic; the result is a
//! diff or the §3.8 warnings; response bytes alone never make the request blocked (D15, D16).
//! Run with `cargo test --release -p yw-app --test fuzz_lite_simulate -- --ignored`.

use yw_app::rpc::evm::parse_simulate_response;
use yw_core::approval::{
    ApprovalId, ApprovalKind, ApprovalOrigin, ChainFacts, RiskLevel, build_evm_tx_request,
};
use yw_core::bip32::path::AccountIndex;
use yw_core::evm::address::Address;
use yw_core::evm::amount::U256;
use yw_core::evm::chain::sepolia;
use yw_core::evm::decode::{DecodedTx, decode_call};
use yw_core::evm::simulate::{SimResult, interpret};
use yw_core::evm::tx::Eip1559Tx;
use yw_core::vault::EvmKeySource;

struct Mutator {
    state: u64,
}

impl Mutator {
    fn below(&mut self, bound: usize) -> usize {
        self.state ^= self.state >> 12;
        self.state ^= self.state << 25;
        self.state ^= self.state >> 27;
        let value = self.state.wrapping_mul(0x2545_f491_4f6c_dd1d);
        let bound = u64::try_from(bound.max(1)).unwrap_or(u64::MAX);
        usize::try_from(value % bound).unwrap_or(0)
    }

    fn mutate(&mut self, seeds: &[&[u8]]) -> Vec<u8> {
        let mut input = seeds
            .get(self.below(seeds.len()))
            .map(|seed| seed.to_vec())
            .unwrap_or_default();
        for _ in 0..=self.below(4) {
            match self.below(4) {
                0 if !input.is_empty() => {
                    let at = self.below(input.len());
                    let bit = self.below(8);
                    if let Some(byte) = input.get_mut(at) {
                        *byte ^= 1 << bit;
                    }
                }
                1 if input.len() < 65_536 => {
                    let at = self.below(input.len() + 1);
                    let value = u8::try_from(self.below(256)).unwrap_or(0);
                    input.insert(at, value);
                }
                2 if !input.is_empty() => {
                    let at = self.below(input.len());
                    input.remove(at);
                }
                3 => {
                    let length = self.below(input.len() + 1);
                    input.truncate(length);
                }
                _ => {}
            }
        }
        input
    }
}

macro_rules! fixtures {
    ($($name:literal),*) => {
        [$(include_bytes!(concat!("fixtures/eth_simulateV1/", $name, ".response.json")).as_slice()),*]
    };
}

/// Iterations per target: `YW_FUZZ_RUNS` when set to a positive number (the short smoke run of
/// `scripts/check.ps1`), otherwise 1,000,000 (spec/09 §2.4).
fn runs() -> u32 {
    std::env::var("YW_FUZZ_RUNS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|&runs| runs > 0)
        .unwrap_or(1_000_000)
}

#[test]
#[ignore = "fuzz-lite (spec/09 §2.4 fallback)"]
fn fuzz_lite_simulate() {
    let seeds = fixtures!(
        "S1", "S1h", "S2", "S3", "S3b", "S3c", "S4", "S4h", "S5", "S6", "S7", "S7b", "S8", "S8b",
        "S9a", "S9b", "S9c", "S9d", "S9e", "S9f", "S9g", "S9h", "S9i", "S10", "S10b", "S11", "S14",
        "S16"
    );
    let chain = sepolia();
    let user = Address::from_bytes([
        0x98, 0x58, 0xef, 0xfd, 0x23, 0x2b, 0x40, 0x33, 0xe4, 0x7d, 0x90, 0x00, 0x3d, 0x41, 0xec,
        0x34, 0xec, 0xae, 0xda, 0x94,
    ]);
    let tx = Eip1559Tx {
        chain_id: 11_155_111,
        nonce: 0,
        max_priority_fee_per_gas: U256::from_u64(100_000_000),
        max_fee_per_gas: U256::from_u64(2_000_000_000),
        gas_limit: 245_520,
        to: Address::from_bytes([0x11; 20]),
        value: U256::from_u64(10_000_000_000_000_000),
        data: Vec::new(),
        access_list: Vec::new(),
    };
    let decoded = DecodedTx {
        call: decode_call(&chain, &tx.to, &tx.data),
        tx: tx.clone(),
    };
    let mut mutator = Mutator {
        state: 0x7369_6d75_6c61_7465,
    };
    let mut simulated = 0_u32;
    for _ in 0..runs() {
        let input = mutator.mutate(&seeds);
        let outcome = parse_simulate_response(&input, 1);
        let sim = interpret(&chain, &tx, &user, &outcome, 1_791_381_228_000);
        assert!(sim.warnings().iter().all(|w| w.level == RiskLevel::High));
        if let SimResult::Simulated { .. } = sim {
            simulated += 1;
        }
        let draft = build_evm_tx_request(
            ApprovalId([1; 16]),
            ApprovalOrigin::App,
            EvmKeySource::Derived(AccountIndex::ZERO),
            user,
            ApprovalKind::EvmTransaction,
            &chain,
            &decoded,
            &sim,
            &ChainFacts::default(),
            Vec::new(),
            1_791_381_228_000,
        )
        .unwrap();
        assert_ne!(draft.display.risk, RiskLevel::Blocked);
    }
    assert!(simulated > 0);
}
