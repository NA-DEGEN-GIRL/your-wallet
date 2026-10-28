//! spec/09 §2.4 `envelope` target (M5-14 fallback; cargo-fuzz/nightly are not installed
//! offline): `browser::envelope::parse_inbound` over 1,000,000 xorshift64* mutations of the
//! spec/05 §10.3 request and cancel goldens. Invariants: no panic; an accepted request or cancel
//! re-encoded in the golden key order parses back to the same value.
//! Run with `cargo test --release -p yw-app --test fuzz_lite_envelope -- --ignored`.

mod common;

use common::browser::GOLDEN_ID;
use yw_app::browser::envelope::{Inbound, parse_inbound};
use yw_json::{Number, Value};

const REQUEST: &[u8] = include_bytes!("../../../extension/native-host/v1-request.golden.json");
const CANCEL: &[u8] = include_bytes!("../../../extension/native-host/v1-cancel.golden.json");

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
                1 if input.len() < 8_192 => {
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

fn s(text: &str) -> Value {
    Value::String(text.to_owned())
}

fn n(value: u64) -> Value {
    Value::Number(Number::from_u64(value))
}

fn object(pairs: Vec<(&str, Value)>) -> Value {
    yw_app::text::json_object(pairs)
}

fn encode(inbound: &Inbound) -> Vec<u8> {
    let value = match inbound {
        Inbound::Request(request) => object(vec![
            ("namespace", s("your-wallet")),
            ("version", n(1)),
            ("role", s("extension")),
            ("kind", s("request")),
            ("sessionId", s(&request.correlation.session_id.hex())),
            ("sequence", n(request.correlation.sequence)),
            ("deadlineUnixMs", n(request.deadline_unix_ms)),
            ("profileInstallId", s(&request.profile_install_id.hex())),
            (
                "activationNonce",
                s(&request.correlation.activation_nonce.hex()),
            ),
            ("requestId", s(&request.correlation.request_id.hex())),
            ("method", s(&request.method)),
            ("params", request.params.clone()),
            ("route", s(request.route.as_str())),
            ("context", {
                let mut context = vec![
                    ("browserFamily", s("chrome")),
                    ("extensionId", s(GOLDEN_ID)),
                    ("tabId", n(request.context.tab_id)),
                    ("frameId", n(0)),
                    ("documentId", s(&request.context.document_id)),
                    ("topOrigin", s(request.context.origin.as_str())),
                    ("frameOrigin", s(request.context.origin.as_str())),
                    ("documentLifecycle", s("active")),
                    ("channelNonce", s(&request.context.channel_nonce.hex())),
                ];
                if let Some(mode) = request.context.compat_mode {
                    context.push(("compatMode", s(mode.as_str())));
                }
                object(context)
            }),
        ]),
        Inbound::Cancel(cancel) => object(vec![
            ("namespace", s("your-wallet")),
            ("version", n(1)),
            ("role", s("extension")),
            ("kind", s("cancel")),
            ("sessionId", s(&cancel.session_id.hex())),
            ("sequence", n(cancel.sequence)),
            ("activationNonce", s(&cancel.activation_nonce.hex())),
            ("requestId", s(&cancel.request_id.hex())),
            ("requestSequence", n(cancel.request_sequence)),
            ("reason", s(&cancel.reason)),
        ]),
    };
    yw_json::to_vec(&value)
}

#[test]
#[ignore = "fuzz-lite (spec/09 §2.4 fallback)"]
fn fuzz_lite_envelope() {
    let seeds: [&[u8]; 2] = [REQUEST, CANCEL];
    let mut mutator = Mutator {
        state: 0x656e_7665_6c6f_7065,
    };
    let mut accepted = 0_u32;
    for _ in 0..1_000_000 {
        let input = mutator.mutate(&seeds);
        if let Ok(inbound) = parse_inbound(&input, GOLDEN_ID, true) {
            let again = parse_inbound(&encode(&inbound), GOLDEN_ID, true);
            assert_eq!(again.as_ref(), Ok(&inbound));
            accepted += 1;
        }
    }
    assert!(accepted > 0);
}
