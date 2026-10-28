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
    for _ in 0..runs() {
        let input = mutator.mutate(&seeds);
        if let Ok(value) = parse(&input, &Limits::REQUEST) {
            let written = to_vec(&value);
            assert_eq!(parse(&written, &Limits::REQUEST), Ok(value));
            accepted += 1;
        }
    }
    assert!(accepted > 0);
}

/// spec/09 §2.4 `frame` target (M5-14 fallback): `read_frame` over a cursor until EOF on
/// 1,000,000 mutations. Invariants: no panic; a frame read back with `write_frame` equals the
/// input bytes it was read from; a length of 0 or > 1 MiB is `Oversized` before any payload byte
/// is read.
#[test]
#[ignore = "fuzz-lite (spec/09 §2.4 fallback)"]
fn fuzz_lite_frame() {
    use std::io::{Cursor, Read};
    use yw_json::frame::{FrameError, MAX_FRAME_BYTES, read_frame, write_frame};

    struct Counting<'a> {
        inner: Cursor<&'a [u8]>,
        read: usize,
    }
    impl Read for Counting<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let count = self.inner.read(buf)?;
            self.read += count;
            Ok(count)
        }
    }

    let seeds: [&[u8]; 4] = [
        b"\x02\x00\x00\x00{}",
        b"\x02\x00\x00\x00{}\x05\x00\x00\x00[1,2]",
        b"\x00\x00\x00\x00",
        b"\x01\x00\x10\x00x",
    ];
    let mut mutator = Mutator {
        state: 0x6672_616d_6566_7a31,
    };
    let mut frames = 0_u32;
    for _ in 0..runs() {
        let input = mutator.mutate(&seeds);
        let mut reader = Counting {
            inner: Cursor::new(&input),
            read: 0,
        };
        loop {
            let before = reader.read;
            let length = input
                .get(before..before.saturating_add(4))
                .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                .map(u32::from_le_bytes);
            match read_frame(&mut reader, MAX_FRAME_BYTES) {
                Ok(Some(frame)) => {
                    let mut written = Vec::new();
                    write_frame(&mut written, &frame, MAX_FRAME_BYTES).unwrap();
                    assert_eq!(Some(written.as_slice()), input.get(before..reader.read));
                    frames += 1;
                }
                Err(FrameError::Oversized) => {
                    let length = usize::try_from(length.unwrap_or(0)).unwrap_or(usize::MAX);
                    assert!(length == 0 || length > MAX_FRAME_BYTES);
                    assert_eq!(reader.read, before + 4, "payload read before Oversized");
                    break;
                }
                Ok(None) | Err(_) => break,
            }
        }
    }
    assert!(frames > 0);
}
