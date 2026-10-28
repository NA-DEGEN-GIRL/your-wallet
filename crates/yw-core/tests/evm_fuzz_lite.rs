//! spec/09 §2.4 fallback for the M2 fuzz targets owned by yw-core (`rlp`, `signed_tx`, `abi`,
//! `eip712`, `siwe`): cargo-fuzz/nightly are not installed (offline), so each target's invariant
//! runs here over 1,000,000 xorshift64* mutations (bit flip, insert, delete, truncate) of its
//! seeds. Run with `cargo test --release -p yw-core --test evm_fuzz_lite -- --ignored`.

use yw_core::evm::abi::{
    AbiValue, SEL_APPROVE, SEL_MULTICALL, SEL_PERMIT2_APPROVE, SEL_PERMIT2_LOCKDOWN,
    SEL_SAFE_BATCH_TRANSFER_FROM_1155, SEL_SAFE_TRANSFER_FROM_721_DATA, SEL_TRANSFER, encode_call,
};
use yw_core::evm::address::Address;
use yw_core::evm::amount::U256;
use yw_core::evm::chain::sepolia;
use yw_core::evm::decode::{DecodedCall, decode_call};
use yw_core::evm::eip712::{eip712_digest, validate_typed_data_v4};
use yw_core::evm::rlp::{decode_exact, encode_item};
use yw_core::evm::sign::recover_address;
use yw_core::evm::siwe::{SiweParse, parse_siwe};
use yw_core::evm::tx::{AccessListItem, Eip1559Tx, decode_signed};
use yw_core::hex;

/// Iterations per target: `YW_FUZZ_RUNS` when set to a positive number (the short smoke run of
/// `scripts/check.ps1`), otherwise 1,000,000 (spec/09 §2.4).
#[expect(
    clippy::disallowed_methods,
    reason = "the iteration count of a test tool; yw-core itself never reads the environment"
)]
fn runs() -> u32 {
    std::env::var("YW_FUZZ_RUNS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|&runs| runs > 0)
        .unwrap_or(1_000_000)
}

/// xorshift64* with a fixed seed (recorded in docs/acceptance/m2-20261027.md).
struct Mutator {
    state: u64,
    max_len: usize,
}

impl Mutator {
    const fn new(seed: u64, max_len: usize) -> Self {
        Self {
            state: seed,
            max_len,
        }
    }

    fn below(&mut self, bound: usize) -> usize {
        self.state ^= self.state >> 12;
        self.state ^= self.state << 25;
        self.state ^= self.state >> 27;
        let value = self.state.wrapping_mul(0x2545_f491_4f6c_dd1d);
        let bound = u64::try_from(bound.max(1)).unwrap_or(u64::MAX);
        usize::try_from(value % bound).unwrap_or(0)
    }

    fn mutate(&mut self, seeds: &[Vec<u8>]) -> Vec<u8> {
        let mut input = seeds
            .get(self.below(seeds.len()))
            .cloned()
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
                1 if input.len() < self.max_len => {
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

const BESU: &str = "02f86e048203338301284d8301d97c828ae094000000000000000000000000000000000000aaaa8402933bc980c080a00f924cb68412c8f1cfd74d9b581c71eeaf94fff6abdde3e5b02ca6b2931dcf47a07dd1c50027c3e31f8b565e25ce68a5072110f61fce5eee81b195dd51273c2f83";
const EIP155: &str = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";

fn signed_seed() -> Vec<u8> {
    Eip1559Tx {
        chain_id: 11_155_111,
        nonce: 5,
        max_priority_fee_per_gas: U256::from_u64(100),
        max_fee_per_gas: U256::from_u64(1_000),
        gas_limit: 60_000,
        to: Address::from_bytes([0x22; 20]),
        value: U256::from_u64(1),
        data: vec![0xa9, 0x05, 0x9c, 0xbb, 0, 1, 2],
        access_list: vec![AccessListItem {
            address: Address::from_bytes([0x33; 20]),
            storage_keys: vec![[0x44; 32]],
        }],
    }
    .encode_signed(1, &[0x0f; 32], &[0x1e; 32])
}

#[test]
#[ignore = "fuzz-lite (spec/09 §2.4 fallback)"]
fn fuzz_lite_rlp() {
    let besu = hex::decode(BESU).unwrap();
    let seeds = vec![
        hex::decode(EIP155).unwrap(),
        besu[1..].to_vec(),
        signed_seed()[1..].to_vec(),
        vec![0xc4, 0xc3, 0xc2, 0xc1, 0xc0],
    ];
    let mut mutator = Mutator::new(0x726c_7066_757a_7a31, 4_096);
    let mut accepted = 0_u32;
    for _ in 0..runs() {
        let input = mutator.mutate(&seeds);
        if let Ok(item) = decode_exact(&input) {
            assert_eq!(encode_item(&item), input);
            accepted += 1;
        }
    }
    assert!(accepted > 0 && accepted < runs());
}

#[test]
#[ignore = "fuzz-lite (spec/09 §2.4 fallback)"]
fn fuzz_lite_signed_tx() {
    let seeds = vec![hex::decode(BESU).unwrap(), signed_seed()];
    let mut mutator = Mutator::new(0x7369_676e_6564_7478, 4_096);
    let mut accepted = 0_u32;
    for _ in 0..runs() {
        let input = mutator.mutate(&seeds);
        if let Ok(decoded) = decode_signed(&input) {
            assert_eq!(decoded.encode(), input);
            let mut compact = [0_u8; 64];
            compact[..32].copy_from_slice(&decoded.r);
            compact[32..].copy_from_slice(&decoded.s);
            let hash = decoded.tx.signing_hash();
            assert_eq!(
                recover_address(hash, decoded.y_parity, &compact),
                recover_address(hash, decoded.y_parity, &compact)
            );
            accepted += 1;
        }
    }
    assert!(accepted > 0 && accepted < runs());
}

#[test]
#[ignore = "fuzz-lite (spec/09 §2.4 fallback)"]
fn fuzz_lite_abi() {
    let chain = sepolia();
    let permit2 = chain
        .contract_with_role(yw_core::evm::chain::ContractRole::Permit2)
        .unwrap()
        .address;
    let weth = chain.weth().unwrap().address;
    let address = |byte| AbiValue::Address(Address::from_bytes([byte; 20]));
    let uint = |value| AbiValue::Uint(U256::from_u64(value));
    let transfer = encode_call(SEL_TRANSFER, &[address(2), uint(5)]);
    let seeds = vec![
        transfer.clone(),
        encode_call(SEL_APPROVE, &[address(2), AbiValue::Uint(U256::MAX)]),
        encode_call(
            SEL_SAFE_TRANSFER_FROM_721_DATA,
            &[
                address(1),
                address(2),
                uint(7),
                AbiValue::Bytes(vec![1, 2, 3]),
            ],
        ),
        encode_call(
            SEL_SAFE_BATCH_TRANSFER_FROM_1155,
            &[
                address(1),
                address(2),
                AbiValue::Array(vec![uint(1)]),
                AbiValue::Array(vec![uint(2)]),
                AbiValue::Bytes(vec![]),
            ],
        ),
        encode_call(
            SEL_PERMIT2_APPROVE,
            &[address(3), address(2), uint(5), uint(6)],
        ),
        encode_call(
            SEL_PERMIT2_LOCKDOWN,
            &[AbiValue::Array(vec![AbiValue::Tuple(vec![
                address(3),
                address(2),
            ])])],
        ),
        encode_call(
            SEL_MULTICALL,
            &[AbiValue::Array(vec![AbiValue::Bytes(transfer)])],
        ),
        vec![0xd0, 0xe3, 0x0d, 0xb0],
    ];
    let mut mutator = Mutator::new(0x6162_6966_757a_7a31, 8_192);
    let mut known = 0_u32;
    for _ in 0..runs() {
        let input = mutator.mutate(&seeds);
        let to = match input.first().map(|byte| byte % 3) {
            Some(0) => permit2,
            Some(1) => weth,
            _ => Address::from_bytes([0x77; 20]),
        };
        let call = decode_call(&chain, &to, &input);
        if let DecodedCall::Known { kind, args, .. } = &call
            && !matches!(*kind, "erc2612_permit_submit" | "dai_permit_submit")
        {
            let values: Vec<AbiValue> = args.iter().map(|(_, value)| value.clone()).collect();
            let mut selector = [0_u8; 4];
            selector.copy_from_slice(&input[..4]);
            assert_eq!(encode_call(selector, &values), input, "{kind}");
            known += 1;
        }
    }
    assert!(known > 0);
}

const ETHER_MAIL: &str = r#"{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallet","type":"address"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person"},{"name":"contents","type":"string"}]},"primaryType":"Mail","domain":{"name":"Ether Mail","version":"1","chainId":11155111,"verifyingContract":"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},"message":{"from":{"name":"Cow","wallet":"0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},"to":{"name":"Bob","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},"contents":"Hello, Bob!"}}"#;
const PERMIT_SINGLE: &str = r#"{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"PermitDetails":[{"name":"token","type":"address"},{"name":"amount","type":"uint160"},{"name":"expiration","type":"uint48"},{"name":"nonce","type":"uint48"}],"PermitSingle":[{"name":"details","type":"PermitDetails"},{"name":"spender","type":"address"},{"name":"sigDeadline","type":"uint256"}]},"primaryType":"PermitSingle","domain":{"name":"Permit2","chainId":11155111,"verifyingContract":"0x000000000022D473030F116dDEE9F6B43aC78BA3"},"message":{"details":{"token":"0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238","amount":"5","expiration":"1791381216","nonce":"0"},"spender":"0x2222222222222222222222222222222222222222","sigDeadline":"1791381816"}}"#;

#[test]
#[ignore = "fuzz-lite (spec/09 §2.4 fallback)"]
fn fuzz_lite_eip712() {
    let seeds = vec![
        ETHER_MAIL.as_bytes().to_vec(),
        PERMIT_SINGLE.as_bytes().to_vec(),
    ];
    let mut mutator = Mutator::new(0x6569_7037_3132_6631, 131_072);
    let mut accepted = 0_u32;
    for _ in 0..runs() {
        let input = mutator.mutate(&seeds);
        let Ok(value) = yw_json::parse(&input, &yw_json::Limits::REQUEST) else {
            continue;
        };
        if let Ok(typed) = validate_typed_data_v4(&input, &value, 11_155_111) {
            assert_eq!(eip712_digest(&typed), eip712_digest(&typed));
            accepted += 1;
        }
    }
    assert!(accepted > 0);
}

#[test]
#[ignore = "fuzz-lite (spec/09 §2.4 fallback)"]
fn fuzz_lite_siwe() {
    let base = "app.example wants you to sign in with your Ethereum account:\n0x9858EfFD232B4033E47d90003D41EC34EcaEda94\n\nSign in to Example.\n\nURI: https://app.example/login\nVersion: 1\nChain ID: 11155111\nNonce: 32891756\nIssued At: 2026-10-25T23:59:00Z";
    let full = format!(
        "https://{base}\nExpiration Time: 2099-01-01T00:00:00Z\nNot Before: 2026-10-25T00:00:00Z\nRequest ID: abc\nResources:\n- https://app.example/a"
    );
    let seeds = vec![base.as_bytes().to_vec(), full.into_bytes()];
    let mut mutator = Mutator::new(0x7369_7765_6675_7a7a, 4_096);
    let mut accepted = 0_u32;
    for _ in 0..runs() {
        let input = mutator.mutate(&seeds);
        let Ok(text) = core::str::from_utf8(&input) else {
            continue;
        };
        if let SiweParse::Message(message) = parse_siwe(text) {
            assert_eq!(message.to_text(), text);
            accepted += 1;
        }
    }
    assert!(accepted > 0 && accepted < runs());
}
