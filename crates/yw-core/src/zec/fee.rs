//! ZIP 317 conventional fee for transparent transactions (spec/12 §7).
//!
//! `logical_actions = max(⌈tx_in_total_size / 150⌉, ⌈tx_out_total_size / 34⌉)` (no shielded
//! actions here) and `conventional_fee = 5000 × max(2, logical_actions)` zatoshis, where the
//! sizes are the serialized sizes of all `tx_in` and all `tx_out` fields.
#![deny(clippy::indexing_slicing)]

use super::tx::ZecTx;

/// ZIP 317 `marginal_fee` (zatoshis per logical action).
pub const MARGINAL_FEE: u64 = 5_000;
/// ZIP 317 `grace_actions`.
pub const GRACE_ACTIONS: u64 = 2;
/// ZIP 317 `p2pkh_standard_input_size`.
pub const P2PKH_STANDARD_INPUT_SIZE: u64 = 150;
/// ZIP 317 `p2pkh_standard_output_size`.
pub const P2PKH_STANDARD_OUTPUT_SIZE: u64 = 34;
/// Upper bound of one signed P2PKH input with a compressed key (36 + 1 + (1 + 73 + 1 + 33) + 4 =
/// 149 bytes, the 73 being a ≤ 72-byte card DER plus the hash type): never above the standard
/// size, so `n` inputs never count for more than `n` actions.
pub const MAX_P2PKH_INPUT_SIZE: u64 = 149;

/// `⌈a / b⌉` for `b > 0`.
const fn div_ceil(a: u64, b: u64) -> u64 {
    a.div_ceil(b)
}

/// ZIP 317 logical actions of a transparent-only transaction with these field sizes.
#[must_use]
pub const fn logical_actions(tx_in_total_size: u64, tx_out_total_size: u64) -> u64 {
    let inputs = div_ceil(tx_in_total_size, P2PKH_STANDARD_INPUT_SIZE);
    let outputs = div_ceil(tx_out_total_size, P2PKH_STANDARD_OUTPUT_SIZE);
    if inputs > outputs { inputs } else { outputs }
}

/// ZIP 317 conventional fee for `logical_actions`.
#[must_use]
pub const fn conventional_fee(logical_actions: u64) -> u64 {
    let actions = if logical_actions > GRACE_ACTIONS {
        logical_actions
    } else {
        GRACE_ACTIONS
    };
    MARGINAL_FEE.saturating_mul(actions)
}

/// Serialized size of one output with a `spk_len`-byte script (8 + `CompactSize` + script).
#[must_use]
pub const fn output_size(spk_len: usize) -> u64 {
    let len = spk_len as u64;
    8 + if len < 0xfd { 1 } else { 3 } + len
}

/// The fee of a planned transaction before signing: every input counted at
/// [`MAX_P2PKH_INPUT_SIZE`], outputs exactly.
#[must_use]
pub fn planned_fee(inputs: usize, output_spk_lens: &[usize]) -> u64 {
    let in_size = (inputs as u64).saturating_mul(MAX_P2PKH_INPUT_SIZE);
    let out_size = output_spk_lens
        .iter()
        .map(|len| output_size(*len))
        .fold(0_u64, u64::saturating_add);
    conventional_fee(logical_actions(in_size, out_size))
}

/// The ZIP 317 conventional fee of an actual (signed) transaction, from its serialized sizes.
#[must_use]
pub fn tx_conventional_fee(tx: &ZecTx) -> u64 {
    let in_size = tx
        .inputs
        .iter()
        .map(|input| {
            let script = input.script_sig.len() as u64;
            36 + if script < 0xfd { 1 } else { 3 } + script + 4
        })
        .fold(0_u64, u64::saturating_add);
    let out_size = tx
        .outputs
        .iter()
        .map(|output| output_size(output.script_pubkey.len()))
        .fold(0_u64, u64::saturating_add);
    conventional_fee(logical_actions(in_size, out_size))
}

#[cfg(test)]
mod tests {
    use super::{conventional_fee, logical_actions, planned_fee};

    /// ZIP 317 examples: a 1-in/2-out P2PKH transaction pays the 2-action minimum (10,000 zats);
    /// 3 inputs and 2 outputs pay 15,000.
    #[test]
    fn zip317_examples() {
        assert_eq!(conventional_fee(0), 10_000);
        assert_eq!(conventional_fee(2), 10_000);
        assert_eq!(conventional_fee(3), 15_000);
        assert_eq!(logical_actions(150, 68), 2);
        assert_eq!(logical_actions(151, 34), 2);
        assert_eq!(planned_fee(1, &[25, 25]), 10_000);
        assert_eq!(planned_fee(3, &[25, 25]), 15_000);
        assert_eq!(planned_fee(1, &[23]), 10_000);
        assert_eq!(planned_fee(10, &[25]), 50_000);
    }
}
