//! spec/09 §2.4 fallback for the M7 fuzz targets (`sol_base58`, `sol_shortvec`, `sol_tx`,
//! `sol_journal`; seeds `T_SOL` and, since v1.1, `T_SPL`; since M7.2 `sol_dapp_tx` with a v0
//! message over two lookup tables, and version 3 dApp-send journal bodies): cargo-fuzz/nightly
//! are not installed (offline), so each
//! target's invariant runs here over 1,000,000 xorshift64* mutations (bit flip, insert, delete,
//! truncate) of its seeds.
//! Run with `cargo test --release -p yw-core --test sol_fuzz_lite -- --ignored`.

use yw_core::codec::base58::{base58_decode_32, base58_decode_64, base58_encode};
use yw_core::hex;
use yw_core::journal::sol::SolRecord;
use yw_core::sol::dapp::{encode_message_any, parse_message_any, parse_wire_tx};
use yw_core::sol::message::{assemble_transaction, encode_message, parse_transaction};
use yw_core::sol::msgsign::looks_like_transaction;
use yw_core::sol::shortvec;
use yw_core::sol::template::SPL_ALLOWLIST;
use yw_core::sol::{SolAddress, SolAsset, SolCluster, SolTransferCore};

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

/// xorshift64* with a fixed seed (recorded in docs/acceptance/m7-20261027.md).
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

/// The spec/07 §17.3 `T_SOL` golden message (202 bytes).
const T_SOL_MESSAGE: &str = concat!(
    "01000204",
    "f036276246a75b9de3349ed42b15e232f6518fc20f5fcd4f1d64e81f9bd258f7",
    "f8029acf5cbcbdd5ac46ec147f3b78a3df6e5022ef0411db2bab650d329a4cd4",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000",
    "0707070707070707070707070707070707070707070707070707070707070707",
    "03",
    "03000502c2010000",
    "03000903e803000000000000",
    "020200010c0200000040420f0000000000",
);
/// Its signature (spec/07 §17.3).
const T_SOL_SIGNATURE: &str =
    "5DpEKELbVjwDHeTJzKG8EoYQdahDegeR6onWnyBqhTBiz4b1k1YMEKutLioNjVgc1Z1wTZuFLDLW2Y6vU4cu2k2u";

fn golden_tx() -> Vec<u8> {
    assemble_transaction(
        &base58_decode_64(T_SOL_SIGNATURE).unwrap_or([0; 64]),
        &hex::decode(T_SOL_MESSAGE).unwrap_or_default(),
    )
}

/// The spec/07 §17.3 `T_SPL` golden message (372 bytes, mainnet USDC), built by the public
/// encoder and pinned by its SHA-256.
fn spl_message() -> Vec<u8> {
    let addr = |text: &str| SolAddress::parse(text).unwrap_or(SolAddress::from_bytes([0; 32]));
    let core = SolTransferCore {
        from: addr("HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"),
        to: addr("Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb"),
        asset: SolAsset::Spl(&SPL_ALLOWLIST[0]),
        amount: 1_000_000,
        cu_limit: 40_000,
        cu_price_micro: 1_000,
    };
    encode_message(&core, &[7; 32])
}

/// Its signature (spec/07 §17.3).
const T_SPL_SIGNATURE: &str =
    "5iVhrE6aU2jjv4CyoJKYkqAd3xpPcdPynaGWW32yt6daMUZm1jAdVWq4aSyFNpB4eyU2SGhB6p7tB8eLrMdoGt8L";

fn spl_tx() -> Vec<u8> {
    assemble_transaction(
        &base58_decode_64(T_SPL_SIGNATURE).unwrap_or([0; 64]),
        &spl_message(),
    )
}

/// A v0 message (spec/07 §20.2) with two signers, two lookup tables (writable and read-only
/// loads), a Memo instruction over static and loaded accounts and a System transfer.
fn v0_message() -> Vec<u8> {
    let mut out = vec![0x80, 2, 1, 2, 4];
    for key in [0x11_u8, 0x12, 0x00, 0x05] {
        out.extend_from_slice(&[key; 32]);
    }
    out.extend_from_slice(&[7; 32]);
    out.push(2);
    out.extend_from_slice(&[3, 3, 0, 4, 6, 2, b'h', b'i']);
    out.extend_from_slice(&[2, 2, 0, 5, 12, 2, 0, 0, 0]);
    out.extend_from_slice(&1_000_u64.to_le_bytes());
    out.push(2);
    out.extend_from_slice(&[0xa1; 32]);
    out.extend_from_slice(&[1, 5, 1, 0]);
    out.extend_from_slice(&[0xa2; 32]);
    out.extend_from_slice(&[1, 1, 0]);
    out
}

/// The v0 message as a partially signed transaction (slot 1 still empty).
fn v0_tx() -> Vec<u8> {
    let mut out = vec![2];
    out.extend_from_slice(&[0x44; 64]);
    out.extend_from_slice(&[0; 64]);
    out.extend_from_slice(&v0_message());
    out
}

/// A devnet body around the golden `T_SOL` transaction (spec/07 §14.1 layout).
fn golden_body(state: u8) -> Vec<u8> {
    body_of(state, 2, &golden_tx())
}

/// A body of `tx` on `cluster` in `state`.
fn body_of(state: u8, cluster: u8, tx: &[u8]) -> Vec<u8> {
    let mut body = vec![0x02, 1, state, cluster, 1];
    body.extend_from_slice(&[0; 8]);
    body.extend_from_slice(&[0x42; 16]);
    body.extend_from_slice(&[0x24; 32]);
    body.extend_from_slice(&1_790_000_000_000_u64.to_be_bytes());
    body.extend_from_slice(&1_234_u64.to_be_bytes());
    let (slot, err): (u64, u16) = if state == 3 { (9, 4) } else { (0, 0) };
    body.extend_from_slice(&slot.to_be_bytes());
    body.extend_from_slice(&err.to_be_bytes());
    body.extend_from_slice(&u16::try_from(tx.len()).unwrap_or(0).to_be_bytes());
    body.extend_from_slice(tx);
    body
}

/// A version 3 (dApp send, spec/07 §14.1) devnet body: a one-signer legacy transaction with one
/// instruction of an unknown program, signed by a fixed key, from `https://dapp.example`.
fn v3_body(state: u8) -> Vec<u8> {
    use ed25519_dalek::{Signer as _, SigningKey};
    let key = SigningKey::from_bytes(&[0x11; 32]);
    let public = key.verifying_key().to_bytes();
    let mut message = vec![1, 0, 1, 2];
    message.extend_from_slice(&public);
    message.extend_from_slice(&[0x05; 32]);
    message.extend_from_slice(&[7; 32]);
    message.extend_from_slice(&[1, 1, 1, 0, 2, b'g', b'm']);
    let mut tx = vec![1];
    tx.extend_from_slice(&key.sign(&message).to_bytes());
    tx.extend_from_slice(&message);
    let origin = b"https://dapp.example";
    let mut dapp = public.to_vec();
    dapp.extend_from_slice(&[0, 0x03]);
    dapp.extend_from_slice(&u16::try_from(origin.len()).unwrap_or(0).to_be_bytes());
    dapp.extend_from_slice(origin);
    let mut body = body_of(state, 2, &tx);
    if let Some(version) = body.get_mut(1) {
        *version = 3;
    }
    body.splice(89..89, dapp);
    body
}

#[test]
fn seeds_are_valid() {
    assert!(parse_transaction(&golden_tx(), SolCluster::Mainnet).is_ok());
    assert_eq!(
        hex::encode(&yw_core::codec::sha256(&spl_message())),
        "db305edc2a3c1a3bcde2ac525684340d7a56a8e816c41e86d8231f795ca6d9e8"
    );
    assert!(parse_transaction(&spl_tx(), SolCluster::Mainnet).is_ok());
    for tx in [golden_tx(), spl_tx(), v0_tx()] {
        assert_eq!(parse_wire_tx(&tx).unwrap().to_bytes(), tx);
        assert!(looks_like_transaction(&tx));
    }
    let v0 = parse_message_any(&v0_message()).unwrap();
    assert_eq!(v0.lookups.len(), 2);
    assert_eq!(v0.account_count(), 7);
    for state in 1..=4 {
        assert!(SolRecord::decode(&golden_body(state)).is_ok(), "{state}");
        assert!(
            SolRecord::decode(&body_of(state, 1, &spl_tx())).is_ok(),
            "{state}"
        );
        let v3 = v3_body(state);
        let record = SolRecord::decode(&v3).unwrap();
        assert!(record.dapp.is_some() && record.core().is_none());
        assert_eq!(record.encode().unwrap(), v3);
    }
}

#[test]
#[ignore = "fuzz-lite (spec/09 §2.4 fallback)"]
fn fuzz_lite_sol_base58() {
    let seeds: Vec<Vec<u8>> = [
        "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk",
        "11111111111111111111111111111111",
        "JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG",
        "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM",
        "14uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofL",
    ]
    .iter()
    .map(|text| text.as_bytes().to_vec())
    .collect();
    let mut mutator = Mutator::new(0x736f_6c62_3538_3332, 64);
    let mut accepted = 0_u32;
    for _ in 0..runs() {
        let input = mutator.mutate(&seeds);
        let Ok(text) = core::str::from_utf8(&input) else {
            continue;
        };
        if let Ok(bytes) = base58_decode_32(text) {
            assert_eq!(base58_encode(&bytes), text);
            accepted += 1;
        }
    }
    assert!(accepted > 0 && accepted < runs());
}

#[test]
#[ignore = "fuzz-lite (spec/09 §2.4 fallback)"]
fn fuzz_lite_sol_shortvec() {
    let seeds: Vec<Vec<u8>> = [
        0_u16, 0x7f, 0x80, 0xff, 0x100, 0x3fff, 0x4000, 0x7fff, 0xffff,
    ]
    .iter()
    .map(|value| shortvec::encode(*value))
    .collect();
    let mut mutator = Mutator::new(0x7368_6f72_7476_6563, 8);
    let mut accepted = 0_u32;
    for _ in 0..runs() {
        let input = mutator.mutate(&seeds);
        if let Ok((value, used)) = shortvec::decode(&input) {
            assert_eq!(shortvec::encode(value), input[..used]);
            accepted += 1;
        }
    }
    assert!(accepted > 0 && accepted < runs());
}

#[test]
#[ignore = "fuzz-lite (spec/09 §2.4 fallback)"]
fn fuzz_lite_sol_tx() {
    let seeds = vec![
        golden_tx(),
        hex::decode(T_SOL_MESSAGE).unwrap(),
        spl_tx(),
        spl_message(),
    ];
    let mut mutator = Mutator::new(0x736f_6c5f_7478_2121, 1_232);
    let mut accepted = 0_u32;
    for _ in 0..runs() {
        let input = mutator.mutate(&seeds);
        if let Ok((core, blockhash, signature)) = parse_transaction(&input, SolCluster::Mainnet) {
            assert_eq!(
                assemble_transaction(&signature, &encode_message(&core, &blockhash)),
                input
            );
            accepted += 1;
        }
    }
    assert!(accepted > 0 && accepted < runs());
}

#[test]
#[ignore = "fuzz-lite (spec/09 §2.4 fallback)"]
fn fuzz_lite_sol_journal() {
    let mut seeds: Vec<Vec<u8>> = (1..=4).map(golden_body).collect();
    seeds.extend((1..=4).map(|state| body_of(state, 1, &spl_tx())));
    seeds.extend((1..=4).map(v3_body));
    let mut mutator = Mutator::new(0x736f_6c6a_726e_6c21, 2_048);
    let mut accepted = 0_u32;
    for _ in 0..runs() {
        let input = mutator.mutate(&seeds);
        if let Ok(record) = SolRecord::decode(&input) {
            assert_eq!(record.encode().unwrap(), input);
            accepted += 1;
        }
    }
    assert!(accepted > 0 && accepted < runs());
}

/// `sol_dapp_tx` (spec/07 §20.2): an accepted transaction or message re-encodes to exactly the
/// input, and the message signer would block it (M01).
#[test]
#[ignore = "fuzz-lite (spec/09 §2.4 fallback)"]
fn fuzz_lite_sol_dapp_tx() {
    let seeds = vec![
        v0_tx(),
        v0_message(),
        golden_tx(),
        hex::decode(T_SOL_MESSAGE).unwrap(),
        spl_tx(),
        spl_message(),
    ];
    let mut mutator = Mutator::new(0x736f_6c64_6170_7074, 1_232);
    let mut accepted = 0_u32;
    for _ in 0..runs() {
        let input = mutator.mutate(&seeds);
        if let Ok(tx) = parse_wire_tx(&input) {
            assert_eq!(tx.to_bytes(), input);
            assert_eq!(encode_message_any(&tx.message), tx.message_bytes);
            assert!(looks_like_transaction(&input));
            accepted += 1;
        }
        if let Ok(message) = parse_message_any(&input) {
            assert_eq!(encode_message_any(&message), input);
            assert!(looks_like_transaction(&input));
            accepted += 1;
        }
    }
    assert!(accepted > 0 && accepted < runs());
}
