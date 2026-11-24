//! spec/09 §2.4 `android_input` target (2026-11-25 A2-6, spec/15 §3.2, §18 8): the Android wire's
//! input decoder over xorshift64* mutations of every input kind, and the decoded inputs applied to
//! a wallet with a drawn model. Invariants: no panic; a press reaches the logic only when it
//! names the model drawn last and a slot whose control takes a press, and an edit only for a
//! plain, writable edit; no input of another revision is ever taken.
//! Run with `cargo test --release -p yw-engine --test fuzz_lite_android_input -- --ignored`.

mod wire_support;

use wire_support::{Facts, first_run_wallet, take_all};
use yw_engine::screen::model::{Act, CtlKind};
use yw_engine::wire::{Input, InputOutcome, decode_input};

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

    fn mutate(&mut self, seeds: &[Vec<u8>]) -> Vec<u8> {
        let mut input = seeds
            .get(self.below(seeds.len()))
            .cloned()
            .unwrap_or_default();
        for _ in 0..=self.below(4) {
            match self.below(5) {
                0 if !input.is_empty() => {
                    let at = self.below(input.len());
                    let bit = self.below(8);
                    if let Some(byte) = input.get_mut(at) {
                        *byte ^= 1 << bit;
                    }
                }
                1 if input.len() < 8_192 => {
                    let at = self.below(input.len() + 1);
                    let value = b"0123456789\"{}:,-.e"
                        .get(self.below(18))
                        .copied()
                        .unwrap_or(b'0');
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

/// Iterations: `YW_FUZZ_RUNS` when set to a positive number (the short smoke run of
/// `scripts/check.ps1`), otherwise 1,000,000 (spec/09 §2.4).
#[expect(
    clippy::disallowed_methods,
    reason = "the iteration count of a test tool; yw-engine itself never reads the environment"
)]
fn runs() -> u32 {
    std::env::var("YW_FUZZ_RUNS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|&runs| runs > 0)
        .unwrap_or(1_000_000)
}

fn seeds() -> Vec<Vec<u8>> {
    [
        r#"{"t":"press","rev":1,"slot":3}"#,
        r#"{"t":"press","rev":2,"slot":0}"#,
        r#"{"t":"edit","rev":1,"slot":2,"text":"abc"}"#,
        r#"{"t":"rendered","rev":1,"focus":null,"of":null}"#,
        r#"{"t":"rendered","rev":2,"focus":4,"of":1}"#,
        r#"{"t":"life","e":"back"}"#,
        r#"{"t":"life","e":"front"}"#,
        r#"{"t":"tick"}"#,
        r#"{"t":"timer","id":"send_check"}"#,
        r#"{"t":"copied","id":3,"ok":false}"#,
    ]
    .into_iter()
    .map(|seed| seed.as_bytes().to_vec())
    .collect()
}

#[test]
#[ignore = "fuzz-lite: run with --ignored (scripts/check.ps1 runs it with YW_FUZZ_RUNS)"]
fn fuzz_lite_android_input() {
    let seeds = seeds();
    let mut mutator = Mutator {
        state: 0x9e37_79b9_7f4a_7c15,
    };
    let mut wallet = first_run_wallet();
    let _ = wallet.draw(&Facts);
    let mut taken = 0_u32;
    for run in 0..runs() {
        // Every fourth input names the model drawn now (the seeds' revisions soon go stale), at
        // a slot that may be past its controls.
        let bytes = if run % 4 == 0 {
            let rev = wallet.drawn().map_or(0, yw_engine::wire::Drawn::rev);
            let slot = mutator.below(48);
            let kind = if mutator.below(3) == 0 {
                format!(r#"{{"t":"edit","rev":{rev},"slot":{slot},"text":"x"}}"#)
            } else {
                format!(r#"{{"t":"press","rev":{rev},"slot":{slot}}}"#)
            };
            kind.into_bytes()
        } else {
            mutator.mutate(&seeds)
        };
        let Ok(input) = decode_input(&bytes) else {
            continue;
        };
        // What the input names in the model drawn now (before it is applied).
        let drawn = wallet.drawn().cloned();
        let named = match &input {
            Input::Press { rev, slot } | Input::Edit { rev, slot, .. } => Some((*rev, *slot)),
            _ => None,
        };
        let is_press = matches!(input, Input::Press { .. });
        let outcome = wallet.on_input(input, &Facts);
        if outcome == InputOutcome::Done
            && let Some((rev, slot)) = named
        {
            let drawn = drawn.unwrap_or_else(|| unreachable!("taken without a model"));
            assert_eq!(rev, drawn.rev(), "{bytes:?}");
            let info = drawn
                .slot(slot)
                .unwrap_or_else(|| unreachable!("taken without a slot"));
            assert!(info.enabled, "{bytes:?}");
            if is_press {
                assert!(matches!(info.act, Act::Press(_)), "{bytes:?}");
                assert!(!matches!(info.kind, CtlKind::Edit { .. }), "{bytes:?}");
            } else {
                assert!(matches!(info.act, Act::Field(_)), "{bytes:?}");
                assert!(
                    matches!(
                        info.kind,
                        CtlKind::Edit {
                            readonly: false,
                            ..
                        }
                    ),
                    "{bytes:?}"
                );
            }
            taken = taken.saturating_add(1);
        }
        // The shell takes what the input queued and draws again when asked to.
        if take_all(&mut wallet)
            .iter()
            .any(|effect| matches!(effect, yw_engine::effect::Effect::Render))
        {
            let _ = wallet.draw(&Facts);
        }
    }
    // The seeds name real slots of the first model: some inputs are taken, so the invariants
    // above were exercised (a run of 20 000 takes many).
    assert!(runs() < 1_000 || taken > 0, "no input was taken");
}
