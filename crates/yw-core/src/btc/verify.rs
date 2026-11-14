//! Post-sign verification (spec/08 §11.2): every check is mandatory and any failure discards the
//! signed bytes. The raw transaction is re-parsed and compared with the approved unsigned
//! transaction, each witness is checked strictly against a sighash recomputed with the verified
//! amount(s) and the key the account derives for each input (ECDSA witness or scriptSig, or the
//! Taproot key-path signature under the derived output key), the change is re-derived, and the
//! fee, caps, dust and sizes are recomputed.
#![deny(clippy::indexing_slicing)]

use core::fmt;

use super::SIGHASH_ALL;
use super::account::{BtcAccountKey, ScriptType};
use super::address::{ScriptKind, hash160, kind_from_script, script_pubkey};
use super::amount::Sats;
use super::fee::{check_fee, maxfeerate_literal, rate_kvb};
use super::policy::LocalTx;
use super::script::{dust_threshold, split_p2pkh_script_sig};
use super::select::SendPlan;
use super::sighash::{bip143_sighash_p2wpkh, legacy_sighash};
use super::sign::{
    PUBKEY_LEN, WitnessSigError, check_card_signature_with, check_p2pkh_signature_with,
    check_witness_signature_with, expected_inputs, plan_prevouts,
};
use super::taproot::{TaprootSigError, check_key_path_witness, sighash_default};
use super::tx::{Transaction, Txid, parse_transaction, serialize, txid, vsize, weight, wtxid};
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
    /// 3/5: the Taproot key-path signature failed.
    Taproot {
        /// Input index.
        input: usize,
        /// The failing rule.
        reason: TaprootSigError,
    },
    /// 4: the key is not the account's key of the input's `(chain, index)`.
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

impl PostSignError {
    /// The fixed text in `lang` (`Display` is the Korean one).
    #[must_use]
    #[expect(
        clippy::unused_self,
        reason = "every check failure has the same fixed text"
    )]
    pub const fn text_in(self, lang: crate::lang::Lang) -> &'static str {
        super::policy::texts::POST_SIGN.get(lang)
    }
}

impl fmt::Display for PostSignError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.text_in(crate::lang::Lang::Ko))
    }
}

impl std::error::Error for PostSignError {}

/// The transaction as approved: witnesses removed and, for a P2PKH account, the signature
/// scriptSigs emptied (the plan carries every other scriptSig: empty, or the P2SH-P2WPKH
/// redeem-script push).
fn as_unsigned(parsed: &Transaction, script_type: ScriptType) -> Transaction {
    let mut out = parsed.clone();
    for input in &mut out.inputs {
        input.witness.clear();
        if script_type == ScriptType::P2pkh {
            input.script_sig.clear();
        }
    }
    out
}

/// Verifies `raw` against the approved plan of `account` (spec/08 §11.2 items 1–8).
///
/// # Errors
///
/// The first failing check's [`PostSignError`].
pub fn verify_signed(
    raw: &[u8],
    plan: &SendPlan,
    account: &BtcAccountKey,
) -> Result<VerifiedSignedTx, PostSignError> {
    if plan.account() != account {
        return Err(PostSignError::PlanInconsistent);
    }
    // 1. Strict parse and identical re-serialization.
    let parsed = parse_transaction(raw).map_err(|_| PostSignError::Parse)?;
    if serialize(&parsed, true) != raw {
        return Err(PostSignError::Reserialize);
    }
    // 2. The transaction without signatures is the approved unsigned transaction.
    if serialize(&as_unsigned(&parsed, account.script_type()), false) != serialize(plan.tx(), false)
    {
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
    check_witnesses(&parsed, plan, account)?;
    check_outputs(&parsed, plan, account)?;
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

/// Checks 3–5 for every input, by account type:
///
/// (A `YubiKey` account's ECDSA items are checked with the relaxed card rules instead,
/// `sign::check_card_signature`.)
///
/// - P2WPKH / P2SH-P2WPKH: exactly `[DER ‖ 0x01, K]` (the P2SH scriptSig was compared in check
///   2), `K` is the account key of `(chain, index)`, BIP143 with the verified amount;
/// - P2PKH: no witness, scriptSig exactly `<DER ‖ 0x01> <K>` with the account key (33 or 65
///   bytes), the legacy sighash;
/// - P2TR: exactly one 64-byte Schnorr signature valid under the derived output key for the
///   BIP341 sighash over every input's verified amount and script.
fn check_witnesses(
    parsed: &Transaction,
    plan: &SendPlan,
    account: &BtcAccountKey,
) -> Result<(), PostSignError> {
    let expected = expected_inputs(plan, account).map_err(|_| PostSignError::Derivation)?;
    let prevouts = plan_prevouts(plan, &expected);
    let ctx = secp_context(&mut OsRandom).map_err(|_| PostSignError::Derivation)?;
    let script_type = account.script_type();
    // A YubiKey account's inputs are card signatures: the relaxed card rules (high-R allowed,
    // DER ≤ 72, spec/10 §6.3); every other account keeps the strict low-R rules.
    let card = account.is_hardware();
    for (position, ((planned, input), (pubkey, kind))) in plan
        .inputs()
        .iter()
        .zip(&parsed.inputs)
        .zip(&expected)
        .enumerate()
    {
        let signature_error = |reason| PostSignError::Signature {
            input: position,
            reason,
        };
        match script_type {
            ScriptType::P2wpkh | ScriptType::P2shP2wpkh => {
                // 3. Exactly two items: `DER ‖ 0x01` and a compressed key.
                let [sig_item, key_item] = input.witness.as_slice() else {
                    return Err(PostSignError::WitnessShape { input: position });
                };
                if key_item.len() != PUBKEY_LEN {
                    return Err(signature_error(WitnessSigError::PublicKey));
                }
                // 4. The key is the account's key of (chain, index).
                if key_item.as_slice() != pubkey.as_bytes() {
                    return Err(PostSignError::KeyMismatch { input: position });
                }
                // 5. BIP143 with the verified amount, strict DER/low-R/low-S and verify.
                let sighash =
                    bip143_sighash_p2wpkh(parsed, position, &hash160(key_item), planned.value)
                        .ok_or(PostSignError::PlanInconsistent)?;
                if card {
                    check_card_signature_with(&ctx, sig_item, key_item, &sighash)
                } else {
                    check_witness_signature_with(&ctx, sig_item, key_item, &sighash)
                }
                .map_err(signature_error)?;
            }
            ScriptType::P2pkh => {
                if !input.witness.is_empty() {
                    return Err(PostSignError::WitnessShape { input: position });
                }
                let (sig_item, key_item) = split_p2pkh_script_sig(&input.script_sig)
                    .ok_or(PostSignError::WitnessShape { input: position })?;
                if key_item != pubkey.as_bytes() {
                    return Err(PostSignError::KeyMismatch { input: position });
                }
                let sighash = legacy_sighash(
                    parsed,
                    position,
                    &script_pubkey(kind),
                    u32::from(SIGHASH_ALL),
                )
                .ok_or(PostSignError::PlanInconsistent)?;
                if card {
                    check_card_signature_with(&ctx, sig_item, key_item, &sighash)
                } else {
                    check_p2pkh_signature_with(&ctx, sig_item, key_item, &sighash)
                }
                .map_err(signature_error)?;
            }
            ScriptType::P2tr => {
                let ScriptKind::P2tr(output) = kind else {
                    return Err(PostSignError::Derivation);
                };
                let sighash = sighash_default(parsed, position, &prevouts)
                    .ok_or(PostSignError::PlanInconsistent)?;
                check_key_path_witness(&ctx, &input.witness, output, &sighash).map_err(
                    |reason| match reason {
                        TaprootSigError::Shape => PostSignError::WitnessShape { input: position },
                        other => PostSignError::Taproot {
                            input: position,
                            reason: other,
                        },
                    },
                )?;
            }
        }
    }
    Ok(())
}

/// Check 6: the recipient output, the re-derived change and nothing else.
fn check_outputs(
    parsed: &Transaction,
    plan: &SendPlan,
    account: &BtcAccountKey,
) -> Result<(), PostSignError> {
    let expected_outputs = 1_usize.saturating_add(usize::from(plan.change().is_some()));
    if parsed.outputs.len() != expected_outputs {
        return Err(PostSignError::Outputs);
    }
    if let Some(change) = plan.change() {
        let (chain, index) = account.change_path(change.index);
        let script = account
            .script(chain, index)
            .map_err(|_| PostSignError::Derivation)?;
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
