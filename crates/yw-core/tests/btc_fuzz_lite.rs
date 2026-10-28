//! spec/09 §2.4 fallback for the M8 fuzz targets (`btc_tx`, `btc_address`, `btc_journal`):
//! cargo-fuzz/nightly are not installed (offline), so each target's invariant runs here over
//! 1,000,000 xorshift64* mutations (bit flip, insert, delete, truncate) of its seeds. Run with
//! `cargo test --release -p yw-core --test btc_fuzz_lite -- --ignored`.
//!
//! `parser_random_bytes_no_panic` (spec/08 §14.2) is the always-on part: 100,000 fixed-seed random
//! and mutated inputs through the transaction parser, previous-output verification and the
//! address parser; `journal_body_mutations_no_panic` runs 20,000 journal body mutations.
#![allow(
    clippy::unwrap_used,
    reason = "fixture helpers outside #[test] functions panic on broken fixtures"
)]

mod btc_common;

use yw_core::btc::address::{ScriptKind, encode_address, parse_address};
use yw_core::btc::amount::Sats;
use yw_core::btc::network::BtcNetwork;
use yw_core::btc::prevtx::verify_prev_output;
use yw_core::btc::script::p2wpkh_script_pubkey;
use yw_core::btc::select::SendAmount;
use yw_core::btc::tx::{Txid, parse_transaction, serialize, txid, vsize, weight};
use yw_core::hex;
use yw_core::journal::btc::{BTC_JOURNAL_MAX_BODY, BtcRecord, BtcTxState};
use yw_json::{Limits, Value};

const RUNS: u32 = 1_000_000;
const ALWAYS_ON_RUNS: u32 = 100_000;
const TX_MAX_LEN: usize = 65_536;
const ADDRESS_MAX_LEN: usize = 128;
const JOURNAL_ALWAYS_ON_RUNS: u32 = 20_000;

const TX_VALID: &str = include_str!("vectors/btc/tx_valid.json");
const KEY_IO_VALID: &str = include_str!("vectors/btc/key_io_valid.json");
const KEY_IO_INVALID: &str = include_str!("vectors/btc/key_io_invalid.json");
const TESTNET4_TX_HEX_HTTP: &[u8] = include_bytes!("vectors/btc/esplora/testnet4-tx-hex.http");
const BIP143_UNSIGNED: &str = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";
const BIP143_SIGNED: &str = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000";

/// xorshift64* with a fixed seed per target.
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

    fn next(&mut self) -> u64 {
        self.state ^= self.state >> 12;
        self.state ^= self.state << 25;
        self.state ^= self.state >> 27;
        self.state.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: usize) -> usize {
        let bound = u64::try_from(bound.max(1)).unwrap_or(u64::MAX);
        usize::try_from(self.next() % bound).unwrap_or(0)
    }

    fn random_bytes(&mut self, max: usize) -> Vec<u8> {
        let length = self.below(max + 1);
        (0..length)
            .map(|_| u8::try_from(self.below(256)).unwrap_or(0))
            .collect()
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

fn json_array(text: &str) -> Vec<Value> {
    yw_json::parse(text.as_bytes(), &Limits::RESPONSE)
        .ok()
        .and_then(|root| root.as_array().map(<[Value]>::to_vec))
        .unwrap_or_default()
}

/// BIP143 transactions, the real testnet4 transaction and every Core `tx_valid.json` entry.
fn tx_seeds() -> Vec<Vec<u8>> {
    let mut seeds: Vec<Vec<u8>> = [BIP143_UNSIGNED, BIP143_SIGNED]
        .iter()
        .filter_map(|text| hex::decode(text).ok())
        .collect();
    if let Some(split) = TESTNET4_TX_HEX_HTTP
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        && let Some(body) = TESTNET4_TX_HEX_HTTP.get(split + 4..)
        && let Ok(body) = core::str::from_utf8(body)
        && let Ok(raw) = hex::decode(body)
    {
        seeds.push(raw);
    }
    for entry in json_array(TX_VALID) {
        if let Some(serialized) = entry
            .as_array()
            .and_then(|fields| fields.get(1))
            .and_then(Value::as_str)
            && let Ok(raw) = hex::decode(serialized)
        {
            seeds.push(raw);
        }
    }
    seeds
}

/// BIP173/BIP350 addresses, the spec/08 §14.1 table and every `key_io` string.
fn address_seeds() -> Vec<Vec<u8>> {
    let mut seeds: Vec<Vec<u8>> = [
        "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
        "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
        "BC1SW50QGDZ25J",
        "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
        "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
        "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
        "bc1pfeessrawgf",
        "tb1pfees9rn5nz",
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl",
        "1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i",
        "3CMNFxN1oHBc4R1EpboAL5yzHGgE611Xou",
        "mo9ncXisMeAoXwqcV5EWuyncbmCcQN4rVs",
        "2N2JD6wb56AfK4tfmM6PwdVmoYk2dCKf4Br",
    ]
    .iter()
    .map(|text| text.as_bytes().to_vec())
    .collect();
    for entry in json_array(KEY_IO_VALID)
        .iter()
        .chain(json_array(KEY_IO_INVALID).iter())
    {
        if let Some(text) = entry
            .as_array()
            .and_then(|fields| fields.first())
            .and_then(Value::as_str)
        {
            seeds.push(text.as_bytes().to_vec());
        }
    }
    seeds
}

/// `btc_tx` invariant: Ok → re-serialization == input and the txid is deterministic. Also runs
/// the size functions and previous-output verification on every input. Returns acceptance.
fn check_tx(input: &[u8]) -> bool {
    let script = p2wpkh_script_pubkey(&[0; 20]);
    let _ = verify_prev_output(input, &Txid::from_bytes([0; 32]), 0, &script);
    let Ok(tx) = parse_transaction(input) else {
        return false;
    };
    assert_eq!(serialize(&tx, true), input);
    let id = txid(&tx);
    let again = parse_transaction(input).map(|parsed| txid(&parsed));
    assert_eq!(again, Ok(id));
    let base = u64::try_from(serialize(&tx, false).len()).unwrap_or(u64::MAX);
    let total = u64::try_from(input.len()).unwrap_or(u64::MAX);
    assert_eq!(weight(&tx), 3 * base + total);
    assert_eq!(vsize(&tx), weight(&tx).div_ceil(4));
    // The hash of the original bytes is the computed txid: verification reaches the vout check.
    let verified = verify_prev_output(input, &id, u32::MAX, &script);
    assert_eq!(
        verified,
        Err(yw_core::btc::prevtx::PrevTxError::VoutOutOfRange)
    );
    true
}

/// `btc_address` invariant: Ok → `encode_address` is the canonical text (lowercase for bech32,
/// the trimmed input for base58) and parses back to the same kind. Returns acceptance.
fn check_address(input: &[u8]) -> bool {
    let Ok(text) = core::str::from_utf8(input) else {
        return false;
    };
    let mut accepted = false;
    for net in [BtcNetwork::Mainnet, BtcNetwork::Testnet4] {
        if let Ok(kind) = parse_address(text, net) {
            let encoded = encode_address(&kind, net);
            let trimmed =
                text.trim_matches(|character| matches!(character, ' ' | '\t' | '\r' | '\n'));
            match kind {
                ScriptKind::P2pkh(_) | ScriptKind::P2sh(_) => assert_eq!(encoded, trimmed),
                _ => {
                    assert_eq!(encoded, encoded.to_ascii_lowercase());
                    assert_eq!(encoded, trimmed.to_ascii_lowercase());
                }
            }
            assert_eq!(parse_address(&encoded, net), Ok(kind));
            assert!(parse_address(&encoded, net.other()).is_err());
            accepted = true;
        }
    }
    accepted
}

/// Journal bodies of every shape: send with change, send-max, fee bump (`replaces`), confirmed
/// (`confirmed_height`), replaced (`replaced_by`), a 3-input send.
fn journal_seeds() -> Vec<Vec<u8>> {
    use btc_common::{RECIPIENT, SEED, TIP, plan, rate, record, simple_plan, utxo};
    let send = simple_plan(2, 20_000);
    let max = plan(
        &[utxo(30_000, TIP - 1, 3, 0), utxo(20_000, TIP - 1, 4, 1)],
        RECIPIENT,
        SendAmount::Max,
        rate(1),
        SEED,
    )
    .unwrap();
    let three = plan(
        &[
            utxo(30_000, TIP - 1, 5, 0),
            utxo(20_000, TIP - 1, 6, 1),
            utxo(10_000, TIP - 1, 7, 2),
        ],
        RECIPIENT,
        SendAmount::Exact(Sats::new(55_000).unwrap()),
        rate(2),
        SEED,
    )
    .unwrap();
    let source = record(&send, BtcTxState::Submitted, 1)
        .bump_source(&btc_common::account())
        .unwrap();
    let account = btc_common::account();
    let bump = yw_core::btc::select::plan_fee_bump(&yw_core::btc::select::BumpRequest {
        source: &source,
        account: &account,
        fee: rate(3),
        incremental: None,
        candidates: &[],
        tip_height: TIP,
        change_next: 4,
        layout_seed: [9; 32],
        typed_fee_override: None,
    })
    .unwrap();
    let mut replaced = record(&send, BtcTxState::Replaced, 6);
    replaced.replaced_by = Some(bump.txid());
    [
        record(&send, BtcTxState::Signed, 1),
        record(&max, BtcTxState::Submitted, 2),
        record(&three, BtcTxState::InMempool, 3),
        record(&bump, BtcTxState::BroadcastUnknown, 4),
        record(&send, BtcTxState::Confirmed, 5),
        replaced,
    ]
    .iter()
    .map(|record| record.encode().unwrap())
    .collect()
}

/// `btc_journal` invariant: decode or reject without panic; accepted → re-encoding is identical.
/// Returns acceptance.
fn check_journal(input: &[u8]) -> bool {
    let Ok(record) = BtcRecord::decode(input) else {
        return false;
    };
    assert_eq!(record.encode().as_deref(), Ok(input));
    true
}

#[test]
fn seeds_are_valid() {
    assert!(journal_seeds().iter().all(|seed| check_journal(seed)));
    let tx = tx_seeds();
    assert!(tx.len() > 100);
    assert!(tx.iter().all(|seed| check_tx(seed)));
    let addresses = address_seeds();
    assert!(addresses.len() > 150);
    assert!(addresses.iter().filter(|seed| check_address(seed)).count() > 40);
}

/// spec/08 §14.2: 100,000 fixed-seed random and mutated inputs, no panic.
#[test]
fn parser_random_bytes_no_panic() {
    let tx = tx_seeds();
    let addresses = address_seeds();
    let mut mutator = Mutator::new(0x6274_635f_7261_6e64, TX_MAX_LEN);
    let mut address_mutator = Mutator::new(0x6274_635f_6164_6472, ADDRESS_MAX_LEN);
    let mut accepted = 0_u32;
    for round in 0..ALWAYS_ON_RUNS {
        let input = match round % 4 {
            0 => mutator.random_bytes(300),
            1 => {
                // Random bytes behind a valid version and segwit marker/flag.
                let mut input = vec![2, 0, 0, 0, 0, 1];
                input.extend(mutator.random_bytes(200));
                input
            }
            _ => mutator.mutate(&tx),
        };
        if check_tx(&input) {
            accepted += 1;
        }
        let text = if round % 2 == 0 {
            address_mutator.random_bytes(ADDRESS_MAX_LEN)
        } else {
            address_mutator.mutate(&addresses)
        };
        check_address(&text);
    }
    assert!(accepted > 0 && accepted < ALWAYS_ON_RUNS);
}

/// 20,000 journal body mutations, no panic, accepted bodies re-encode identically.
#[test]
fn journal_body_mutations_no_panic() {
    let seeds = journal_seeds();
    let mut mutator = Mutator::new(0x6274_635f_6a72_6e6c, BTC_JOURNAL_MAX_BODY + 64);
    let mut accepted = 0_u32;
    for _ in 0..JOURNAL_ALWAYS_ON_RUNS {
        if check_journal(&mutator.mutate(&seeds)) {
            accepted += 1;
        }
    }
    assert!(accepted < JOURNAL_ALWAYS_ON_RUNS);
}

#[test]
#[ignore = "fuzz-lite (spec/09 §2.4 fallback)"]
fn fuzz_lite_btc_journal() {
    let seeds = journal_seeds();
    let mut mutator = Mutator::new(0x6274_635f_6a6f_7521, BTC_JOURNAL_MAX_BODY + 64);
    let mut accepted = 0_u32;
    for _ in 0..RUNS {
        if check_journal(&mutator.mutate(&seeds)) {
            accepted += 1;
        }
    }
    assert!(accepted > 0 && accepted < RUNS);
}

#[test]
#[ignore = "fuzz-lite (spec/09 §2.4 fallback)"]
fn fuzz_lite_btc_tx() {
    let seeds = tx_seeds();
    let mut mutator = Mutator::new(0x6274_635f_7478_2121, TX_MAX_LEN);
    let mut accepted = 0_u32;
    for _ in 0..RUNS {
        if check_tx(&mutator.mutate(&seeds)) {
            accepted += 1;
        }
    }
    assert!(accepted > 0 && accepted < RUNS);
}

#[test]
#[ignore = "fuzz-lite (spec/09 §2.4 fallback)"]
fn fuzz_lite_btc_address() {
    let seeds = address_seeds();
    let mut mutator = Mutator::new(0x6274_635f_6164_6421, ADDRESS_MAX_LEN);
    let mut accepted = 0_u32;
    for _ in 0..RUNS {
        if check_address(&mutator.mutate(&seeds)) {
            accepted += 1;
        }
    }
    assert!(accepted > 0 && accepted < RUNS);
}
