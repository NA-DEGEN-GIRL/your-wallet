//! spec/09 §2.4 `chain_params` target (fallback; cargo-fuzz/nightly are not installed offline):
//! the Solana/Bitcoin dApp parameter rules (`browser::chain_params` through
//! `browser::params::validate`) and the meta `sol_sites`/`btc_sites` entry parsers
//! (`browser::grants::{sol,btc}_site_from_value`) over 1,000,000 xorshift64* mutations of JSON
//! seeds. Invariants: no panic; accepted params respect their limits (message sizes, SIWS fields
//! without control characters, valid purposes); an accepted grant entry round-trips.
//! `scripts/check.ps1` runs 20,000 (well under 2 s in a debug build).
//! Run with `cargo test --release -p yw-app --test fuzz_lite_chain_params -- --ignored`.

use yw_app::browser::grants::{
    btc_site_from_value, btc_site_to_value, sol_site_from_value, sol_site_to_value,
};
use yw_app::browser::params::{Validated, validate};
use yw_core::btc::msgsign::MAX_BTC_MESSAGE_BYTES;
use yw_core::policy::{Method, btc_purposes_valid};
use yw_core::sol::msgsign::{
    MAX_SIWS_FIELD_BYTES, MAX_SIWS_RESOURCES, MAX_SOL_MESSAGE_BYTES, SIWS_MARKER, SiwsMessage,
};
use yw_json::{Limits, Value};

const SOL_KEY: &str = "FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z";

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

    fn mutate(&mut self, seeds: &[String]) -> Vec<u8> {
        let mut input = seeds
            .get(self.below(seeds.len()))
            .map(|seed| seed.as_bytes().to_vec())
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
                1 if input.len() < 4_096 => {
                    let at = self.below(input.len() + 1);
                    // Mostly JSON punctuation and letters, so mutants stay parsable often.
                    let alphabet = b"{}[]\":,0123456789abcdefnrtu \\";
                    let value = alphabet.get(self.below(alphabet.len())).copied();
                    input.insert(at, value.unwrap_or(b' '));
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

/// Iterations per target: `YW_FUZZ_RUNS` when set to a positive number (the short smoke run of
/// `scripts/check.ps1`), otherwise 1,000,000 (spec/09 §2.4).
fn runs() -> u32 {
    std::env::var("YW_FUZZ_RUNS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|&runs| runs > 0)
        .unwrap_or(1_000_000)
}

fn seeds() -> Vec<String> {
    vec![
        "[]".to_owned(),
        r#"[{"onlyIfTrusted":true}]"#.to_owned(),
        format!(r#"[{{"publicKey":"{SOL_KEY}","message":"48656c6c6f"}}]"#),
        format!(
            r#"[{{"publicKey":"{SOL_KEY}","input":{{"domain":"app.example","statement":"Sign in","uri":"https://app.example","version":"1","chainId":"mainnet","nonce":"n1","issuedAt":"2026-10-31T00:00:00Z","resources":["https://a.example"]}}}}]"#
        ),
        r#"[{"purposes":["payment","ordinals"]}]"#.to_owned(),
        r#"[{"purposes":["any"]}]"#.to_owned(),
        r#"[{"address":"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4","message":"hi","protocol":"bip322"}]"#
            .to_owned(),
        format!(
            r#"{{"origin":"https://app.example","public_key":"{SOL_KEY}","granted_at_unix_ms":5}}"#
        ),
        r#"{"origin":"https://app.example:8443","network":0,"addresses":[{"purpose":"payment","address":"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4","public_key":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","script_type":"p2wpkh"}],"granted_at_unix_ms":9}"#
            .to_owned(),
    ]
}

fn siws_field_ok(text: &str) -> bool {
    !text.is_empty() && text.len() <= MAX_SIWS_FIELD_BYTES && !text.chars().any(char::is_control)
}

fn check_siws(input: &SiwsMessage) {
    for text in [
        &input.statement,
        &input.uri,
        &input.version,
        &input.chain_id,
        &input.nonce,
        &input.issued_at,
        &input.expiration_time,
        &input.not_before,
        &input.request_id,
    ]
    .into_iter()
    .flatten()
    {
        assert!(siws_field_ok(text), "{text:?}");
    }
    for text in [&input.domain, &input.address] {
        assert!(text.is_empty() || siws_field_ok(text));
    }
    if let Some(resources) = &input.resources {
        assert!(resources.len() <= MAX_SIWS_RESOURCES);
        assert!(resources.iter().all(|item| siws_field_ok(item)));
    }
    // No field can add a line: the first line is always `domain` + the marker.
    let text = input.to_text();
    assert_eq!(
        text.split('\n').next(),
        Some(format!("{}{SIWS_MARKER}", input.domain).as_str())
    );
}

fn check_params(value: &Value) -> u32 {
    let mut accepted = 0;
    for method in [
        Method::SolConnect,
        Method::SolSignMessage,
        Method::SolSignIn,
        Method::BtcRequestAccounts,
        Method::BtcSignMessage,
    ] {
        let Ok(validated) = validate(method, value) else {
            continue;
        };
        accepted += 1;
        let known = match validated {
            Validated::SolConnect { .. } => method == Method::SolConnect,
            Validated::SolSignMessage { message, .. } => {
                message.len() <= MAX_SOL_MESSAGE_BYTES && method == Method::SolSignMessage
            }
            Validated::SolSignIn { input, .. } => {
                check_siws(&input);
                method == Method::SolSignIn
            }
            Validated::BtcRequestAccounts(purposes) => btc_purposes_valid(&purposes),
            Validated::BtcSignMessage {
                address, message, ..
            } => {
                (1..=100).contains(&address.len())
                    && address.is_ascii()
                    && message.len() <= MAX_BTC_MESSAGE_BYTES
                    && core::str::from_utf8(&message).is_ok()
            }
            _ => false,
        };
        assert!(known, "{method:?}");
    }
    accepted
}

#[test]
#[ignore = "fuzz-lite (spec/09 §2.4 fallback)"]
fn fuzz_lite_chain_params() {
    let seeds = seeds();
    let mut mutator = Mutator {
        state: 0x6368_6169_6e70_6172,
    };
    let (mut params, mut grants) = (0_u32, 0_u32);
    for _ in 0..runs() {
        let input = mutator.mutate(&seeds);
        let Ok(value) = yw_json::parse(&input, &Limits::REQUEST) else {
            continue;
        };
        params += check_params(&value);
        if let Some(grant) = sol_site_from_value(&value) {
            assert_eq!(sol_site_from_value(&sol_site_to_value(&grant)), Some(grant));
            grants += 1;
        }
        if let Some(grant) = btc_site_from_value(&value) {
            assert!(!grant.addresses.is_empty());
            assert_eq!(btc_site_from_value(&btc_site_to_value(&grant)), Some(grant));
            grants += 1;
        }
    }
    assert!(params > 0 && grants > 0);
}
