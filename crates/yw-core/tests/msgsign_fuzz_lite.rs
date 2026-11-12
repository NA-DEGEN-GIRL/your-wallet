//! spec/09 §2.4 fallback for the dApp message-signing fuzz targets (`sol_msgsign`,
//! `btc_msgsign`, `base64`): cargo-fuzz/nightly are not installed (offline), so each target's
//! invariant runs here over 1,000,000 xorshift64* mutations (bit flip, insert, delete, truncate)
//! of its seeds. `scripts/check.ps1` runs 20,000 of each (well under 2 s in a debug build).
//! Run with `cargo test --release -p yw-core --test msgsign_fuzz_lite -- --ignored`.
#![allow(
    clippy::unwrap_used,
    reason = "fixture helpers outside #[test] functions panic on broken fixtures"
)]

use yw_core::approval::{ApprovalId, RiskLevel};
use yw_core::bip32::path::AccountIndex;
use yw_core::btc::msgsign::{PSBT_MAGIC, looks_like_transaction as btc_looks_like_transaction};
use yw_core::btc::tx::parse_transaction;
use yw_core::codec::base64;
use yw_core::hex;
use yw_core::policy::BrowserOrigin;
use yw_core::slip10::SolKeySource;
use yw_core::sol::SolCluster;
use yw_core::sol::dapp::{parse_message_any, parse_wire_tx};
use yw_core::sol::msgsign::{
    MAX_SOL_MESSAGE_BYTES, OFFCHAIN_DOMAIN, SiwsMessage, SolMessageRequest,
    build_sol_message_request, looks_like_transaction, looks_like_versioned_message,
    parse_offchain, signable,
};

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

/// A legacy Solana message (one signer, three keys, one instruction).
fn legacy_message() -> Vec<u8> {
    let mut out = vec![1, 0, 1, 2];
    out.extend_from_slice(&[0x11; 32]);
    out.extend_from_slice(&[0x22; 32]);
    out.extend_from_slice(&[0x33; 32]);
    out.extend_from_slice(&[1, 1, 1, 0, 4, 2, 0, 0, 0]);
    out
}

fn sol_seeds() -> Vec<Vec<u8>> {
    let legacy = legacy_message();
    let mut v0 = vec![0x80];
    v0.extend_from_slice(&legacy);
    v0.push(0);
    let mut signed = vec![1];
    signed.extend_from_slice(&[0x44; 64]);
    signed.extend_from_slice(&legacy);
    let mut sdk = OFFCHAIN_DOMAIN.to_vec();
    sdk.extend_from_slice(&[0, 0, 5, 0]);
    sdk.extend_from_slice(b"hello");
    let mut proposal = OFFCHAIN_DOMAIN.to_vec();
    proposal.push(0);
    proposal.extend_from_slice(&[0x55; 32]);
    proposal.extend_from_slice(&[1, 1]);
    proposal.extend_from_slice(&[0x66; 32]);
    proposal.extend_from_slice(&[2, 0]);
    proposal.extend_from_slice(b"hi");
    let siws = SiwsMessage {
        domain: "app.example:8443".to_owned(),
        address: "FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z".to_owned(),
        statement: Some("Sign in".to_owned()),
        uri: Some("https://app.example:8443/login".to_owned()),
        version: Some("1".to_owned()),
        chain_id: Some("mainnet".to_owned()),
        nonce: Some("abc123".to_owned()),
        issued_at: Some("2026-10-31T00:00:00Z".to_owned()),
        resources: Some(vec!["https://a.example".to_owned()]),
        ..SiwsMessage::default()
    };
    vec![
        legacy,
        v0,
        signed,
        sdk,
        proposal,
        siws.to_text().into_bytes(),
        "가나다 소유 증명".as_bytes().to_vec(),
        b"Prove you own this account".to_vec(),
        vec![0x81, 0x01, 0x00],
    ]
}

fn sol_request(message: Vec<u8>) -> SolMessageRequest {
    SolMessageRequest {
        id: ApprovalId([3; 16]),
        origin: BrowserOrigin::parse("https://app.example").unwrap(),
        cluster: SolCluster::Mainnet,
        source: SolKeySource::Standard(AccountIndex::new(0).unwrap()),
        public: [7; 32],
        label: "계정 1".to_owned(),
        message,
        sign_in: false,
    }
}

#[test]
#[ignore = "fuzz-lite (spec/09 §2.4 fallback)"]
fn fuzz_lite_sol_msgsign() {
    let seeds = sol_seeds();
    let mut mutator = Mutator::new(0x736f_6c6d_7367_7331, 1_024);
    let (mut blocked, mut allowed, mut siws) = (0_u32, 0_u32, 0_u32);
    for round in 0..runs() {
        let input = mutator.mutate(&seeds);
        let transaction = looks_like_transaction(&input);
        // Whatever the dApp transaction parser accepts is blocked here (spec/07 §20.2, M01).
        if parse_wire_tx(&input).is_ok() || parse_message_any(&input).is_ok() {
            assert!(transaction);
        }
        // A later message version is a transaction too.
        assert!(!looks_like_versioned_message(&input) || transaction);
        // Trailing bytes never unblock a parsed message prefix.
        if transaction && !looks_like_versioned_message(&input) {
            let mut longer = input.clone();
            longer.extend_from_slice(&[0, 0xff, 7]);
            assert!(looks_like_transaction(&longer));
        }
        let offchain = parse_offchain(&input);
        if let Some(parsed) = &offchain {
            assert!(input.starts_with(OFFCHAIN_DOMAIN));
            assert!(!parsed.message.is_empty());
            assert!(input.ends_with(&parsed.message));
        }
        let ok = signable(&input);
        assert_eq!(
            ok,
            input.len() <= MAX_SOL_MESSAGE_BYTES
                && !transaction
                && (!input.starts_with(OFFCHAIN_DOMAIN) || offchain.is_some())
        );
        if ok {
            allowed += 1;
        } else {
            blocked += 1;
        }
        // The approval window blocks exactly what the signer refuses (every 8th input: the
        // display build is the expensive part).
        if round % 8 == 0 {
            let draft = build_sol_message_request(&sol_request(input.clone()), 0).unwrap();
            if !ok {
                assert_eq!(draft.display.risk, RiskLevel::Blocked);
            }
        }
        if let Ok(text) = core::str::from_utf8(&input)
            && let Some(message) = SiwsMessage::parse(text)
        {
            let again = message.to_text();
            assert_eq!(again, text.trim_end_matches('\n'));
            assert_eq!(SiwsMessage::parse(&again), Some(message));
            siws += 1;
        }
    }
    assert!(blocked > 0 && allowed > 0 && siws > 0);
}

/// BIP143 signed transaction (segwit) — a real transaction to hide in messages.
const BIP143_SIGNED: &str = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000";

fn raw_transaction(bytes: &[u8]) -> bool {
    bytes.starts_with(PSBT_MAGIC) || parse_transaction(bytes).is_ok()
}

#[test]
#[ignore = "fuzz-lite (spec/09 §2.4 fallback)"]
fn fuzz_lite_btc_msgsign() {
    let tx = hex::decode(BIP143_SIGNED).unwrap();
    let mut psbt = PSBT_MAGIC.to_vec();
    psbt.extend_from_slice(&[0x01, 0x00, 0x0a, 0x02]);
    let seeds = vec![
        tx.clone(),
        psbt.clone(),
        BIP143_SIGNED.as_bytes().to_vec(),
        format!("0x{BIP143_SIGNED}").into_bytes(),
        base64::encode(&tx).into_bytes(),
        base64::encode(&psbt).into_bytes(),
        b"Hello World, sign to prove you own this address".to_vec(),
    ];
    let mut mutator = Mutator::new(0x6274_636d_7367_7331, 1_024);
    let (mut detected, mut clean) = (0_u32, 0_u32);
    for _ in 0..runs() {
        let input = mutator.mutate(&seeds);
        let found = btc_looks_like_transaction(&input);
        let raw = raw_transaction(&input);
        // Raw bytes are always caught, and so are their hex (with or without 0x) and base64 text
        // once long enough to be plainly an encoding.
        assert!(!raw || found);
        if raw && input.len() >= 12 {
            let text = hex::encode(&input);
            assert!(btc_looks_like_transaction(text.as_bytes()));
            assert!(btc_looks_like_transaction(
                format!(" 0x{text}\n").as_bytes()
            ));
            assert!(btc_looks_like_transaction(
                base64::encode(&input).as_bytes()
            ));
        }
        if found {
            detected += 1;
        } else {
            clean += 1;
        }
    }
    assert!(detected > 0 && clean > 0);
}

#[test]
#[ignore = "fuzz-lite (spec/09 §2.4 fallback)"]
fn fuzz_lite_base64() {
    let seeds = vec![
        b"AA==".to_vec(),
        b"AAE=".to_vec(),
        b"AAEC".to_vec(),
        base64::encode(&[0xff; 65]).into_bytes(),
        base64::encode(b"psbt\xff\x01\x00").into_bytes(),
        Vec::new(),
    ];
    let mut mutator = Mutator::new(0x6261_7365_3634_6631, 256);
    let mut accepted = 0_u32;
    for _ in 0..runs() {
        let input = mutator.mutate(&seeds);
        // Encoding then decoding any bytes is the identity.
        assert_eq!(base64::decode(&base64::encode(&input)), Some(input.clone()));
        // Decoding is canonical: an accepted text is exactly the encoding of its bytes.
        if let Ok(text) = core::str::from_utf8(&input)
            && let Some(bytes) = base64::decode(text)
        {
            assert_eq!(base64::encode(&bytes), text);
            accepted += 1;
        }
    }
    assert!(accepted > 0);
}
