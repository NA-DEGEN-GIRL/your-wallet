//! spec/09 §2.4 fallback for the `json` fuzz target (M2-3): cargo-fuzz/nightly are not
//! installed (offline), so `parse(b, &Limits::REQUEST)` runs over 1,000,000 xorshift64*
//! mutations of the seeds. Invariant: no panic; `Ok` → `to_vec` → `parse` gives the same value.
//! Run with `cargo test --release -p yw-json --test fuzz_lite -- --ignored`.

use yw_json::{Limits, parse, to_vec};

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

#[test]
#[ignore = "fuzz-lite (spec/09 §2.4 fallback)"]
fn fuzz_lite_json() {
    let seeds: [&[u8]; 4] = [
        br#"{"jsonrpc":"2.0","id":1,"result":[{"number":"0x1","calls":[{"status":"0x1","logs":[]}]}]}"#,
        br#"{"a":[1,-0.5e+3,true,false,null,"x\"\\\/\b\f\n\r\t\u0041"],"b":{},"c":[]}"#,
        br#"[[[[1]]],{"k":{"k":{"k":"v"}}},"A",0,-0,1e9]"#,
        br#""plain""#,
    ];
    let mut mutator = Mutator {
        state: 0x6a73_6f6e_6675_7a31,
    };
    let mut accepted = 0_u32;
    for _ in 0..1_000_000 {
        let input = mutator.mutate(&seeds);
        if let Ok(value) = parse(&input, &Limits::REQUEST) {
            let written = to_vec(&value);
            assert_eq!(parse(&written, &Limits::REQUEST), Ok(value));
            accepted += 1;
        }
    }
    assert!(accepted > 0);
}
