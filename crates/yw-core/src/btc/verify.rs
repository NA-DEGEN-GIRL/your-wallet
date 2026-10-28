//! Post-sign verification (spec/08 §11.2): every check is mandatory and any failure discards the
//! signed bytes. The raw transaction is re-parsed and compared with the approved unsigned
//! transaction, each witness is checked strictly against a sighash recomputed with the verified
//! amount and the key derived from the cached account node, the change is re-derived, and the
//! fee, caps, dust and sizes are recomputed.
#![deny(clippy::indexing_slicing)]

use core::fmt;

use super::address::{hash160, kind_from_script, p2wpkh_program};
use super::amount::Sats;
use super::fee::{check_fee, maxfeerate_literal, rate_kvb};
use super::policy::LocalTx;
use super::script::{dust_threshold, p2wpkh_script_pubkey};
use super::select::SendPlan;
use super::sighash::bip143_sighash_p2wpkh;
use super::sign::{PUBKEY_LEN, WitnessSigError, check_witness_signature_with};
use super::tx::{Transaction, Txid, parse_transaction, serialize, txid, vsize, weight, wtxid};
use crate::bip32::AccountXpub;
use crate::bip32::path::BtcChain;
use crate::entropy::{OsRandom, secp_context};

/// Standard transaction weight limit.
pub const MAX_STANDARD_TX_WEIGHT: u64 = 400_000;

/// A signed transaction that passed every §11.2 check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSignedTx {
    pub(crate) raw: Vec<u8>,
    pub(crate) txid: Txid,
    pub(crate) wtxid: [u8; 32],
    pub(crate) weight: u64,
    pub(crate) vsize: u64,
    pub(crate) fee: Sats,
}

impl VerifiedSignedTx {
    /// The signed bytes (with witnesses).
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Lowercase hex of the signed bytes (`testmempoolaccept`/`sendrawtransaction`).
    #[must_use]
    pub fn raw_hex(&self) -> String {
        crate::hex::encode(&self.raw)
    }

    /// txid (internal order; display with `Display`/`to_display_hex`).
    #[must_use]
    pub const fn txid(&self) -> Txid {
        self.txid
    }

    /// wtxid (internal order).
    #[must_use]
    pub const fn wtxid(&self) -> [u8; 32] {
        self.wtxid
    }

    /// Actual weight.
    #[must_use]
    pub const fn weight(&self) -> u64 {
        self.weight
    }

    /// Actual vsize (≤ planned).
    #[must_use]
    pub const fn vsize(&self) -> u64 {
        self.vsize
    }

    /// Fee (`Σ verified inputs − Σ outputs`).
    #[must_use]
    pub const fn fee(&self) -> Sats {
        self.fee
    }

    /// The values the node's `testmempoolaccept` answer must match (spec/08 §11.3).
    #[must_use]
    pub const fn local(&self) -> LocalTx {
        LocalTx {
            txid: self.txid,
            wtxid: self.wtxid,
            vsize: self.vsize,
            fee: self.fee,
        }
    }

    /// The `maxfeerate` literal of the actual rate (spec/08 §8.3): `ceil(rate/1000)+1` sat/vB as
    /// BTC/kvB with 8 decimals.
    #[must_use]
    pub fn maxfeerate(&self) -> Option<String> {
        maxfeerate_literal(rate_kvb(self.fee, self.vsize)?)
    }
}

/// Which §11.2 check failed (the bytes must be discarded).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PostSignError {
    /// 1: the bytes do not parse.
    Parse,
    /// 1: re-serialization differs from the bytes.
    Reserialize,
    /// 2: the non-witness serialization is not the approved unsigned transaction.
    UnsignedMismatch,
    /// The plan itself is inconsistent (inputs vs transaction).
    PlanInconsistent,
    /// 3: input `input` does not have exactly 2 witness items.
    WitnessShape {
        /// Input index.
        input: usize,
    },
    /// 3/5: strict signature rules or verification failed.
    Signature {
        /// Input index.
        input: usize,
        /// The failing rule.
        reason: WitnessSigError,
    },
    /// 4: `HASH160(pubkey)` is not the program of the input's `(chain, index)`.
    KeyMismatch {
        /// Input index.
        input: usize,
    },
    /// 6: the change output is not our re-derived script or value, or an extra output exists.
    Outputs,
    /// 7: the fee differs from the approved fee.
    FeeMismatch,
    /// 7: the fee exceeds the §8.3 caps.
    FeeCap,
    /// 7: an output is below its dust threshold, not a sendable script, or above `MAX_MONEY`.
    Dust,
    /// 8: weight above 400,000.
    Weight,
    /// 8: actual vsize above the planned vsize.
    Vsize,
    /// Key derivation or randomness failed while checking.
    Derivation,
}

impl fmt::Display for PostSignError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(super::policy::texts::POST_SIGN)
    }
}

impl std::error::Error for PostSignError {}

/// Verifies `raw` against the approved plan (spec/08 §11.2 items 1–8).
///
/// # Errors
///
/// The first failing check's [`PostSignError`].
pub fn verify_signed(
    raw: &[u8],
    plan: &SendPlan,
    acct: &AccountXpub,
) -> Result<VerifiedSignedTx, PostSignError> {
    // 1. Strict parse and identical re-serialization.
    let parsed = parse_transaction(raw).map_err(|_| PostSignError::Parse)?;
    if serialize(&parsed, true) != raw {
        return Err(PostSignError::Reserialize);
    }
    // 2. The non-witness serialization is the approved unsigned transaction.
    if serialize(&parsed, false) != serialize(plan.tx(), false) {
        return Err(PostSignError::UnsignedMismatch);
    }
    let inputs = plan.inputs();
    if inputs.len() != parsed.inputs.len()
        || inputs
            .iter()
            .zip(&parsed.inputs)
            .any(|(planned, input)| planned.outpoint != input.prevout)
    {
        return Err(PostSignError::PlanInconsistent);
    }
    check_witnesses(&parsed, plan, acct)?;
    check_outputs(&parsed, plan, acct)?;
    // 7. Fee from the verified inputs, caps, dust.
    let input_total = plan.input_total().ok_or(PostSignError::FeeMismatch)?;
    let output_total = Sats::checked_sum(parsed.outputs.iter().map(|output| output.value))
        .ok_or(PostSignError::Dust)?;
    let fee = input_total
        .checked_sub(output_total)
        .ok_or(PostSignError::FeeMismatch)?;
    if fee != plan.fee() {
        return Err(PostSignError::FeeMismatch);
    }
    let check = check_fee(fee, u64::from(plan.planned_vsize()), plan.amount())
        .ok_or(PostSignError::FeeCap)?;
    if check.unoverridable || (check.over_cap && !plan.fee_override_typed()) {
        return Err(PostSignError::FeeCap);
    }
    for output in &parsed.outputs {
        let kind = kind_from_script(&output.script_pubkey).ok_or(PostSignError::Dust)?;
        if output.value < dust_threshold(&kind) {
            return Err(PostSignError::Dust);
        }
    }
    // 8. Sizes.
    let actual_weight = weight(&parsed);
    if actual_weight > MAX_STANDARD_TX_WEIGHT {
        return Err(PostSignError::Weight);
    }
    let actual_vsize = vsize(&parsed);
    if actual_vsize > u64::from(plan.planned_vsize()) {
        return Err(PostSignError::Vsize);
    }
    Ok(VerifiedSignedTx {
        raw: raw.to_vec(),
        txid: txid(&parsed),
        wtxid: wtxid(&parsed),
        weight: actual_weight,
        vsize: actual_vsize,
        fee,
    })
}

/// Checks 3–5 for every input.
fn check_witnesses(
    parsed: &Transaction,
    plan: &SendPlan,
    acct: &AccountXpub,
) -> Result<(), PostSignError> {
    let ctx = secp_context(&mut OsRandom).map_err(|_| PostSignError::Derivation)?;
    for (position, (planned, input)) in plan.inputs().iter().zip(&parsed.inputs).enumerate() {
        // 3. Exactly two items: `DER ‖ 0x01` and a compressed key.
        let [sig_item, key_item] = input.witness.as_slice() else {
            return Err(PostSignError::WitnessShape { input: position });
        };
        if key_item.len() != PUBKEY_LEN {
            return Err(PostSignError::Signature {
                input: position,
                reason: WitnessSigError::PublicKey,
            });
        }
        // 4. The key hashes to the program of (chain, index) from the cached account node.
        let program = p2wpkh_program(acct, planned.chain, planned.index)
            .map_err(|_| PostSignError::Derivation)?;
        if hash160(key_item) != program {
            return Err(PostSignError::KeyMismatch { input: position });
        }
        // 5. BIP143 with the verified amount, strict DER/low-R/low-S and verify.
        let sighash = bip143_sighash_p2wpkh(parsed, position, &program, planned.value)
            .ok_or(PostSignError::PlanInconsistent)?;
        check_witness_signature_with(&ctx, sig_item, key_item, &sighash).map_err(|reason| {
            PostSignError::Signature {
                input: position,
                reason,
            }
        })?;
    }
    Ok(())
}

/// Check 6: the recipient output, the re-derived change and nothing else.
fn check_outputs(
    parsed: &Transaction,
    plan: &SendPlan,
    acct: &AccountXpub,
) -> Result<(), PostSignError> {
    let expected_outputs = 1_usize.saturating_add(usize::from(plan.change().is_some()));
    if parsed.outputs.len() != expected_outputs {
        return Err(PostSignError::Outputs);
    }
    if let Some(change) = plan.change() {
        let script = p2wpkh_script_pubkey(
            &p2wpkh_program(acct, BtcChain::Change, change.index)
                .map_err(|_| PostSignError::Derivation)?,
        );
        let output = usize::try_from(change.vout)
            .ok()
            .and_then(|vout| parsed.outputs.get(vout))
            .ok_or(PostSignError::Outputs)?;
        if output.script_pubkey.as_slice() != script.as_slice()
            || output.value != change.value
            || change.vout == plan.recipient_vout()
        {
            return Err(PostSignError::Outputs);
        }
    }
    let recipient = usize::try_from(plan.recipient_vout())
        .ok()
        .and_then(|vout| parsed.outputs.get(vout))
        .ok_or(PostSignError::Outputs)?;
    if recipient.script_pubkey != plan.recipient_script() || recipient.value != plan.amount() {
        return Err(PostSignError::Outputs);
    }
    Ok(())
}
