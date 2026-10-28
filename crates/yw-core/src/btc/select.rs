//! Coin selection and transaction planning (spec/08 §7, §9): eligible candidates, the
//! single-input-then-fewest-inputs selection, change at 294 sats or folded into the fee,
//! send-max, the layout seed (Fisher–Yates input order and change position), the fixed fields
//! (version 2, sequence `0xFFFFFFFD`, empty scriptSig, `lock_time = tip_height`), and RBF fee
//! bumps with the BIP125 minimum. Every amount is a checked [`Sats`] operation; plans are
//! deterministic for a fixed `layout_seed`.
//!
//! A [`SendPlan`] carries everything the approval payload (`display::btc_payload`), signing
//! (`sign::sign_plan`), post-sign verification (`verify::verify_signed`) and the journal record
//! need. Its fields are crate-private: callers read them through accessors and cannot change a
//! plan after it was shown.
#![deny(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

use core::cmp::Ordering;
use core::fmt;

use sha2::{Digest, Sha256};

use super::address::{ScriptKind, p2wpkh_program, script_pubkey};
use super::amount::{Sats, format_sats_grouped};
use super::fee::{
    FeeCheck, FeeChoice, FeeRate, FeeSource, check_fee, fee_for, incremental_or_default,
};
use super::network::BtcNetwork;
use super::script::{P2WPKH_SPK_LEN, dust_threshold, p2wpkh_script_pubkey, spk_len};
use super::tx::{OutPoint, Transaction, TxIn, TxOut, Txid, estimate_weight};
use super::{
    BTC_CHANGE_DUST, BTC_COINBASE_MATURITY, BTC_MAX_INPUTS, BTC_MIN_CONF, BTC_SEQUENCE,
    BTC_TX_VERSION, conf,
};
use crate::approval::ApprovalKind;
use crate::bip32::path::BtcChain;
use crate::bip32::{AccountXpub, HARDENED};
use crate::error::KeyError;

/// Input-order domain of the layout seed (spec/08 §7.5).
const LAYOUT_INPUT_TAG: &[u8] = b"yw-btc-in";
/// Change-position domain of the layout seed.
const LAYOUT_CHANGE_TAG: &[u8] = b"yw-btc-chg";
const CHANGE_DUST: Sats = match Sats::new(BTC_CHANGE_DUST) {
    Some(value) => value,
    None => Sats::ZERO,
};

/// A spendable candidate: a verified (spec/08 §5) output of ours with its server height.
/// [`crate::btc::meta::BtcMeta::spendable`] builds the list (confirmed, mature, not frozen, not
/// used by an in-flight journal entry); planning re-checks the confirmation rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Utxo {
    /// Outpoint.
    pub outpoint: OutPoint,
    /// Verified value.
    pub value: Sats,
    /// Our chain (receive / change).
    pub chain: BtcChain,
    /// Our index (`< 2^31`).
    pub index: u32,
    /// Block height reported by the indexer.
    pub height: u32,
    /// Coinbase output (100 confirmations needed).
    pub is_coinbase: bool,
}

/// One input of a plan in transaction order: the outpoint, its verified value and our path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PlanInput {
    /// Outpoint.
    pub outpoint: OutPoint,
    /// Verified value (the BIP143 amount).
    pub value: Sats,
    /// Chain of the key.
    pub chain: BtcChain,
    /// Index of the key.
    pub index: u32,
}

impl From<&Utxo> for PlanInput {
    fn from(utxo: &Utxo) -> Self {
        Self {
            outpoint: utxo.outpoint,
            value: utxo.value,
            chain: utxo.chain,
            index: utxo.index,
        }
    }
}

/// The change output of a plan (P2WPKH at `m/84'/{coin}'/0'/1/index`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PlanChange {
    /// Output index.
    pub vout: u32,
    /// Change chain index.
    pub index: u32,
    /// Value (≥ 294 sats).
    pub value: Sats,
}

/// What a fee bump replaced (spec/08 §9, field `0x0609`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BumpInfo {
    /// The replaced transaction.
    pub replaces: Txid,
    /// Its fee.
    pub old_fee: Sats,
    /// Its recipient amount.
    pub old_amount: Sats,
    /// The BIP125 minimum (incremental relay fee / strictly higher rate) raised the fee above
    /// the chosen rate.
    pub min_applied: bool,
}

/// Planning failure (nothing is shown or signed; spec/08 §10: blocked in the send form).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanError {
    /// The recipient amount is below the recipient kind's dust threshold.
    DustAmount {
        /// The threshold (`{n}` of the §13 text).
        threshold: Sats,
    },
    /// The candidates cannot pay amount and fee.
    InsufficientFunds {
        /// Σ of the candidates considered (at most 100).
        available: Sats,
        /// Amount + no-change fee at the largest input count tried.
        needed: Sats,
    },
    /// A BTC transaction of this account is in flight (D20, spec/08 §12.1).
    InFlight,
    /// The plan spends an outpoint used by an in-flight journal entry (spec/08 §5).
    InputInFlight,
    /// The fee-bump source is not a replaceable transaction of ours.
    NotBumpable,
    /// Change key derivation failed.
    Key(KeyError),
    /// Size or amount arithmetic overflow.
    Overflow,
}

impl fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        use super::policy::texts;
        match self {
            Self::DustAmount { threshold } => write!(
                formatter,
                "받는 금액이 최소값({} sats) 미만입니다",
                format_sats_grouped(threshold.get())
            ),
            Self::InsufficientFunds { available, needed } => write!(
                formatter,
                "잔액이 부족합니다(필요 {} sats, 사용 가능 {} sats)",
                format_sats_grouped(needed.get()),
                format_sats_grouped(available.get())
            ),
            Self::InFlight => formatter.write_str(texts::IN_FLIGHT),
            Self::InputInFlight => formatter.write_str(texts::INPUT_IN_FLIGHT),
            Self::NotBumpable => formatter.write_str(texts::NOT_BUMPABLE),
            Self::Key(_) => formatter.write_str(texts::DERIVATION_FAILED),
            Self::Overflow => formatter.write_str(texts::PLAN_OVERFLOW),
        }
    }
}

impl std::error::Error for PlanError {}

impl From<KeyError> for PlanError {
    fn from(error: KeyError) -> Self {
        Self::Key(error)
    }
}

/// A complete unsigned transaction plan (spec/08 §7, §9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendPlan {
    pub(crate) network: BtcNetwork,
    pub(crate) tx: Transaction,
    pub(crate) inputs: Vec<PlanInput>,
    pub(crate) recipient: ScriptKind,
    pub(crate) recipient_vout: u32,
    pub(crate) amount: Sats,
    pub(crate) change: Option<PlanChange>,
    pub(crate) fee: Sats,
    pub(crate) change_folded: Sats,
    pub(crate) planned_vsize: u32,
    pub(crate) planned_weight: u64,
    pub(crate) send_max: bool,
    pub(crate) fee_override_typed: bool,
    pub(crate) rate: FeeRate,
    pub(crate) fee_source: FeeSource,
    pub(crate) excluded_utxos: u32,
    pub(crate) recipient_decreased: bool,
    pub(crate) bump: Option<BumpInfo>,
    pub(crate) new_input_total: Sats,
}

impl SendPlan {
    /// Network.
    #[must_use]
    pub const fn network(&self) -> BtcNetwork {
        self.network
    }

    /// The unsigned transaction (empty scriptSigs and witnesses).
    #[must_use]
    pub const fn tx(&self) -> &Transaction {
        &self.tx
    }

    /// Inputs in transaction order.
    #[must_use]
    pub fn inputs(&self) -> &[PlanInput] {
        &self.inputs
    }

    /// Recipient script kind.
    #[must_use]
    pub const fn recipient(&self) -> ScriptKind {
        self.recipient
    }

    /// Recipient scriptPubKey.
    #[must_use]
    pub fn recipient_script(&self) -> Vec<u8> {
        script_pubkey(&self.recipient)
    }

    /// Recipient output index.
    #[must_use]
    pub const fn recipient_vout(&self) -> u32 {
        self.recipient_vout
    }

    /// Recipient amount.
    #[must_use]
    pub const fn amount(&self) -> Sats {
        self.amount
    }

    /// Change output, if any.
    #[must_use]
    pub const fn change(&self) -> Option<PlanChange> {
        self.change
    }

    /// Fee (`Σ inputs − Σ outputs`).
    #[must_use]
    pub const fn fee(&self) -> Sats {
        self.fee
    }

    /// Sats added to the fee because the change would have been below 294 (`0x0604`).
    #[must_use]
    pub const fn change_folded(&self) -> Sats {
        self.change_folded
    }

    /// Planned (pre-signing estimate) vsize; the signed size is never larger.
    #[must_use]
    pub const fn planned_vsize(&self) -> u32 {
        self.planned_vsize
    }

    /// Planned weight.
    #[must_use]
    pub const fn planned_weight(&self) -> u64 {
        self.planned_weight
    }

    /// Send-max plan (one output, everything minus the fee).
    #[must_use]
    pub const fn send_max(&self) -> bool {
        self.send_max
    }

    /// The cap was lifted by the send form's exact typed fee (B03, journal flag).
    #[must_use]
    pub const fn fee_override_typed(&self) -> bool {
        self.fee_override_typed
    }

    /// The chosen fee rate.
    #[must_use]
    pub const fn rate(&self) -> FeeRate {
        self.rate
    }

    /// Where the rate came from.
    #[must_use]
    pub const fn fee_source(&self) -> FeeSource {
        self.fee_source
    }

    /// Candidates left out of a send-max because of the 100-input limit (B06).
    #[must_use]
    pub const fn excluded_utxos(&self) -> u32 {
        self.excluded_utxos
    }

    /// A send-max bump reduced the recipient amount (B06).
    #[must_use]
    pub const fn recipient_decreased(&self) -> bool {
        self.recipient_decreased
    }

    /// The replaced transaction of a fee bump.
    #[must_use]
    pub const fn bump(&self) -> Option<BumpInfo> {
        self.bump
    }

    /// The replaced txid of a fee bump.
    #[must_use]
    pub fn replaces(&self) -> Option<Txid> {
        self.bump.map(|bump| bump.replaces)
    }

    /// Σ of the inputs that were not already spent by the replaced transaction (all inputs of a
    /// send): what leaves the spendable balance.
    #[must_use]
    pub const fn new_input_total(&self) -> Sats {
        self.new_input_total
    }

    /// `BtcSend` or `BtcFeeBump`.
    #[must_use]
    pub const fn kind(&self) -> ApprovalKind {
        if self.bump.is_some() {
            ApprovalKind::BtcFeeBump
        } else {
            ApprovalKind::BtcSend
        }
    }

    /// Lock time (= the tip height at planning).
    #[must_use]
    pub const fn lock_time(&self) -> u32 {
        self.tx.lock_time
    }

    /// Σ of the input values.
    #[must_use]
    pub fn input_total(&self) -> Option<Sats> {
        Sats::checked_sum(self.inputs.iter().map(|input| input.value))
    }

    /// The §8.3 checks over the planned vsize.
    #[must_use]
    pub fn fee_check(&self) -> Option<FeeCheck> {
        check_fee(self.fee, u64::from(self.planned_vsize), self.amount)
    }

    /// The send form must ask for the exact fee (B02 otherwise): the cap is exceeded and no
    /// matching typed override was given. B01 (`unoverridable`) can never be lifted.
    #[must_use]
    pub fn needs_typed_override(&self) -> bool {
        self.fee_check()
            .is_some_and(|check| check.over_cap && !self.fee_override_typed)
    }

    /// The txid of the unsigned transaction (final: no witness data in it).
    #[must_use]
    pub fn txid(&self) -> Txid {
        super::tx::txid(&self.tx)
    }
}

/// The amount of a send.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SendAmount {
    /// This amount to the recipient.
    Exact(Sats),
    /// Everything minus the fee (spec/08 §7.6).
    Max,
}

/// Inputs of [`plan_send`].
#[derive(Clone, Copy, Debug)]
pub struct SendRequest<'a> {
    /// Wallet network.
    pub network: BtcNetwork,
    /// Cached account node (`BtcMeta` account key).
    pub account: &'a AccountXpub,
    /// Parsed recipient.
    pub recipient: ScriptKind,
    /// Amount or send-max.
    pub amount: SendAmount,
    /// Rate and source (`fee::choose_fee_rate`).
    pub fee: FeeChoice,
    /// Spendable candidates (`BtcMeta::spendable`).
    pub candidates: &'a [Utxo],
    /// Core tip height (`getblockchaininfo.blocks`): confirmations and `lock_time`.
    pub tip_height: u32,
    /// `BtcMeta.change_next` (reconciled with the journal).
    pub change_next: u32,
    /// Random 32 bytes (getrandom; fixed in tests).
    pub layout_seed: [u8; 32],
    /// The send form's "exact fee" input that lifts the cap (B03) when equal to the plan fee.
    pub typed_fee_override: Option<Sats>,
}

/// The transaction a fee bump replaces (from `journal::btc::BtcRecord::bump_source`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BumpSource {
    /// Network.
    pub network: BtcNetwork,
    /// The replaced transaction.
    pub txid: Txid,
    /// Its inputs with their recorded values and paths.
    pub inputs: Vec<PlanInput>,
    /// Its recipient.
    pub recipient: ScriptKind,
    /// Its recipient amount.
    pub amount: Sats,
    /// Its change index, if it had change.
    pub change_index: Option<u32>,
    /// Its fee.
    pub fee: Sats,
    /// Its actual vsize.
    pub vsize: u64,
    /// It was a send-max.
    pub send_max: bool,
}

/// Inputs of [`plan_fee_bump`].
#[derive(Clone, Copy, Debug)]
pub struct BumpRequest<'a> {
    /// The replaced transaction.
    pub source: &'a BumpSource,
    /// Cached account node.
    pub account: &'a AccountXpub,
    /// The new rate (raised to the BIP125 minimum when needed).
    pub fee: FeeChoice,
    /// `getmempoolinfo.incrementalrelayfee` (1,000 sat/kvB when missing).
    pub incremental: Option<FeeRate>,
    /// Spendable candidates for extra inputs (not in flight).
    pub candidates: &'a [Utxo],
    /// Current Core tip height (new `lock_time`).
    pub tip_height: u32,
    /// `BtcMeta.change_next` (used when inputs are added to a change-less transaction).
    pub change_next: u32,
    /// A new random layout seed.
    pub layout_seed: [u8; 32],
    /// The bump form's exact typed fee (B03).
    pub typed_fee_override: Option<Sats>,
}

fn display_txid(txid: &Txid) -> [u8; 32] {
    let mut bytes = txid.to_bytes();
    bytes.reverse();
    bytes
}

fn tie_break(a: &Utxo, b: &Utxo) -> Ordering {
    a.height
        .cmp(&b.height)
        .then_with(|| display_txid(&a.outpoint.txid).cmp(&display_txid(&b.outpoint.txid)))
        .then_with(|| a.outpoint.vout.cmp(&b.outpoint.vout))
}

/// Step 1 order: value ascending, height ascending, txid (display order), vout.
fn ascending(a: &Utxo, b: &Utxo) -> Ordering {
    a.value.cmp(&b.value).then_with(|| tie_break(a, b))
}

/// Step 2 / send-max / extra-input order: value descending, then as [`ascending`].
fn descending(a: &Utxo, b: &Utxo) -> Ordering {
    b.value.cmp(&a.value).then_with(|| tie_break(a, b))
}

/// Candidates that may be spent at `tip_height`: confirmed (coinbase: mature), non-zero, a
/// non-hardened index, first occurrence of each outpoint.
fn eligible(candidates: &[Utxo], tip_height: u32) -> Vec<Utxo> {
    let mut out: Vec<Utxo> = Vec::with_capacity(candidates.len());
    for utxo in candidates {
        let confirmations = conf(utxo.height, tip_height);
        let mature = confirmations >= BTC_MIN_CONF
            && (!utxo.is_coinbase || confirmations >= BTC_COINBASE_MATURITY);
        if mature
            && utxo.value > Sats::ZERO
            && utxo.index & HARDENED == 0
            && !out.iter().any(|seen| seen.outpoint == utxo.outpoint)
        {
            out.push(*utxo);
        }
    }
    out
}

#[derive(Clone, Copy, Debug)]
struct Shape {
    vsize: u64,
    weight: u64,
}

fn shape(inputs: usize, outputs: &[usize]) -> Result<Shape, PlanError> {
    let weight = estimate_weight(inputs, outputs).ok_or(PlanError::Overflow)?;
    Ok(Shape {
        vsize: weight.div_ceil(4),
        weight,
    })
}

#[derive(Clone, Copy, Debug)]
struct BumpMin {
    old_fee: Sats,
    old_vsize: u64,
    incremental: FeeRate,
}

impl BumpMin {
    /// The smallest fee of a replacement of `new_vsize` (spec/08 §9): at least
    /// `old_fee + ceil(incremental × new_vsize / 1000)` and a strictly higher rate
    /// (`new_fee × old_vsize > old_fee × new_vsize`).
    fn required(self, new_vsize: u64) -> Result<Sats, PlanError> {
        let increment = fee_for(self.incremental, new_vsize).ok_or(PlanError::Overflow)?;
        let by_increment = self
            .old_fee
            .checked_add(increment)
            .ok_or(PlanError::Overflow)?;
        let product = u128::from(self.old_fee.get())
            .checked_mul(u128::from(new_vsize))
            .ok_or(PlanError::Overflow)?;
        let by_rate = product
            .checked_div(u128::from(self.old_vsize))
            .and_then(|quotient| quotient.checked_add(1))
            .and_then(|value| u64::try_from(value).ok())
            .and_then(Sats::new)
            .ok_or(PlanError::Overflow)?;
        Ok(by_increment.max(by_rate))
    }
}

/// Whether a replacement fee satisfies both spec/08 §9 rules.
#[must_use]
pub fn bump_fee_ok(
    old_fee: Sats,
    old_vsize: u64,
    new_fee: Sats,
    new_vsize: u64,
    incremental: Option<FeeRate>,
) -> bool {
    let increment = fee_for(incremental_or_default(incremental), new_vsize);
    let Some(minimum) = increment.and_then(|increment| old_fee.checked_add(increment)) else {
        return false;
    };
    let new_side = u128::from(new_fee.get()).checked_mul(u128::from(old_vsize));
    let old_side = u128::from(old_fee.get()).checked_mul(u128::from(new_vsize));
    match (new_side, old_side) {
        (Some(new_side), Some(old_side)) => new_fee >= minimum && new_side > old_side,
        _ => false,
    }
}

#[derive(Clone, Copy, Debug)]
struct FeeRule {
    rate: FeeRate,
    bump: Option<BumpMin>,
}

impl FeeRule {
    /// The fee for `vsize` and whether the bump minimum raised it.
    fn fee(self, vsize: u64) -> Result<(Sats, bool), PlanError> {
        let by_rate = fee_for(self.rate, vsize).ok_or(PlanError::Overflow)?;
        match self.bump {
            None => Ok((by_rate, false)),
            Some(minimum) => {
                let required = minimum.required(vsize)?;
                Ok(if required > by_rate {
                    (required, true)
                } else {
                    (by_rate, false)
                })
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Fit {
    change: Option<Sats>,
    fee: Sats,
    folded: Sats,
    shape: Shape,
    min_applied: bool,
}

/// The feasibility rule of spec/08 §7.4 for `inputs` worth `total`.
fn fit(
    total: Sats,
    amount: Sats,
    inputs: usize,
    recipient_len: usize,
    rule: FeeRule,
    allow_change: bool,
) -> Result<Option<Fit>, PlanError> {
    if allow_change {
        let with_change = shape(inputs, &[recipient_len, P2WPKH_SPK_LEN])?;
        let (fee, min_applied) = rule.fee(with_change.vsize)?;
        let needed = amount
            .checked_add(fee)
            .and_then(|sum| sum.checked_add(CHANGE_DUST));
        if needed.is_some_and(|needed| total >= needed) {
            let change = total
                .checked_sub(amount)
                .and_then(|rest| rest.checked_sub(fee))
                .ok_or(PlanError::Overflow)?;
            return Ok(Some(Fit {
                change: Some(change),
                fee,
                folded: Sats::ZERO,
                shape: with_change,
                min_applied,
            }));
        }
    }
    let without = shape(inputs, &[recipient_len])?;
    let (base, min_applied) = rule.fee(without.vsize)?;
    if amount
        .checked_add(base)
        .is_some_and(|needed| total >= needed)
    {
        let fee = total.checked_sub(amount).ok_or(PlanError::Overflow)?;
        let folded = fee.checked_sub(base).ok_or(PlanError::Overflow)?;
        return Ok(Some(Fit {
            change: None,
            fee,
            folded,
            shape: without,
            min_applied,
        }));
    }
    Ok(None)
}

fn sum_values<'a>(utxos: impl IntoIterator<Item = &'a Utxo>) -> Result<Sats, PlanError> {
    Sats::checked_sum(utxos.into_iter().map(|utxo| utxo.value)).ok_or(PlanError::Overflow)
}

fn seed_hash(seed: &[u8; 32], tag: &[u8], suffix: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(seed);
    hasher.update(tag);
    hasher.update(suffix);
    hasher.finalize().into()
}

/// Fisher–Yates with `j = u64_be(SHA256(seed ‖ "yw-btc-in" ‖ u32_be(i))[0..8]) mod (i + 1)`
/// for `i = n-1..=1` (spec/08 §7.5).
fn shuffle_inputs(inputs: &mut [PlanInput], seed: &[u8; 32]) -> Result<(), PlanError> {
    let mut i = inputs.len().saturating_sub(1);
    while i >= 1 {
        let tag = u32::try_from(i).map_err(|_| PlanError::Overflow)?;
        let digest = seed_hash(seed, LAYOUT_INPUT_TAG, &tag.to_be_bytes());
        let mut word = [0_u8; 8];
        for (slot, byte) in word.iter_mut().zip(digest.iter()) {
            *slot = *byte;
        }
        let bound = u64::try_from(i)
            .ok()
            .and_then(|i| i.checked_add(1))
            .ok_or(PlanError::Overflow)?;
        let j = u64::from_be_bytes(word)
            .checked_rem(bound)
            .and_then(|j| usize::try_from(j).ok())
            .ok_or(PlanError::Overflow)?;
        inputs.swap(i, j);
        i = i.checked_sub(1).ok_or(PlanError::Overflow)?;
    }
    Ok(())
}

/// Change first when `SHA256(seed ‖ "yw-btc-chg")[0] & 1 == 0`.
fn change_first(seed: &[u8; 32]) -> bool {
    seed_hash(seed, LAYOUT_CHANGE_TAG, &[])
        .first()
        .is_some_and(|byte| byte & 1 == 0)
}

struct Assembly<'a> {
    network: BtcNetwork,
    account: &'a AccountXpub,
    recipient: ScriptKind,
    inputs: Vec<PlanInput>,
    amount: Sats,
    fit: Fit,
    change_index: u32,
    tip_height: u32,
    seed: [u8; 32],
    fee: FeeChoice,
    typed: Option<Sats>,
    send_max: bool,
    excluded: usize,
    recipient_decreased: bool,
    bump: Option<BumpInfo>,
    new_input_total: Sats,
}

fn change_script(
    account: &AccountXpub,
    index: u32,
    recipient: &[u8],
) -> Result<(u32, [u8; P2WPKH_SPK_LEN]), PlanError> {
    let script = p2wpkh_script_pubkey(&p2wpkh_program(account, BtcChain::Change, index)?);
    if script.as_slice() != recipient {
        return Ok((index, script));
    }
    let next = index.checked_add(1).ok_or(PlanError::Overflow)?;
    let script = p2wpkh_script_pubkey(&p2wpkh_program(account, BtcChain::Change, next)?);
    Ok((next, script))
}

fn assemble(mut parts: Assembly<'_>) -> Result<SendPlan, PlanError> {
    if parts.inputs.is_empty() || parts.inputs.len() > BTC_MAX_INPUTS {
        return Err(PlanError::Overflow);
    }
    shuffle_inputs(&mut parts.inputs, &parts.seed)?;
    let recipient_script = script_pubkey(&parts.recipient);
    let recipient_output = TxOut {
        value: parts.amount,
        script_pubkey: recipient_script.clone(),
    };
    let (outputs, recipient_vout, change) = match parts.fit.change {
        None => (vec![recipient_output], 0, None),
        Some(value) => {
            let (index, script) =
                change_script(parts.account, parts.change_index, &recipient_script)?;
            let change_output = TxOut {
                value,
                script_pubkey: script.to_vec(),
            };
            let (outputs, recipient_vout, change_vout) = if change_first(&parts.seed) {
                (vec![change_output, recipient_output], 1, 0)
            } else {
                (vec![recipient_output, change_output], 0, 1)
            };
            (
                outputs,
                recipient_vout,
                Some(PlanChange {
                    vout: change_vout,
                    index,
                    value,
                }),
            )
        }
    };
    let tx = Transaction {
        version: BTC_TX_VERSION,
        inputs: parts
            .inputs
            .iter()
            .map(|input| TxIn {
                prevout: input.outpoint,
                script_sig: Vec::new(),
                sequence: BTC_SEQUENCE,
                witness: Vec::new(),
            })
            .collect(),
        outputs,
        lock_time: parts.tip_height,
    };
    let planned_vsize = u32::try_from(parts.fit.shape.vsize).map_err(|_| PlanError::Overflow)?;
    let check =
        check_fee(parts.fit.fee, parts.fit.shape.vsize, parts.amount).ok_or(PlanError::Overflow)?;
    let fee_override_typed = check.over_cap && parts.typed == Some(parts.fit.fee);
    let bump = parts.bump.map(|bump| BumpInfo {
        min_applied: parts.fit.min_applied,
        ..bump
    });
    Ok(SendPlan {
        network: parts.network,
        tx,
        inputs: parts.inputs,
        recipient: parts.recipient,
        recipient_vout,
        amount: parts.amount,
        change,
        fee: parts.fit.fee,
        change_folded: parts.fit.folded,
        planned_vsize,
        planned_weight: parts.fit.shape.weight,
        send_max: parts.send_max,
        fee_override_typed,
        rate: parts.fee.rate,
        fee_source: parts.fee.source,
        excluded_utxos: u32::try_from(parts.excluded).map_err(|_| PlanError::Overflow)?,
        recipient_decreased: parts.recipient_decreased,
        bump,
        new_input_total: parts.new_input_total,
    })
}

/// Plans a send (spec/08 §7): eligible candidates, selection (§7.4) or send-max (§7.6), change or
/// fold, layout (§7.5) and fixed fields (§7.1).
///
/// # Errors
///
/// [`PlanError::DustAmount`] (amount, or send-max remainder, below the recipient dust),
/// [`PlanError::InsufficientFunds`], [`PlanError::Key`] (change derivation),
/// [`PlanError::Overflow`].
pub fn plan_send(req: &SendRequest<'_>) -> Result<SendPlan, PlanError> {
    let dust = dust_threshold(&req.recipient);
    let recipient_len = spk_len(&req.recipient);
    let rule = FeeRule {
        rate: req.fee.rate,
        bump: None,
    };
    let candidates = eligible(req.candidates, req.tip_height);
    let mut desc = candidates.clone();
    desc.sort_by(descending);
    let largest = desc.len().min(BTC_MAX_INPUTS);
    let (chosen, amount, fit, send_max, excluded) = match req.amount {
        SendAmount::Max => {
            let chosen = desc.get(..largest).unwrap_or_default().to_vec();
            if chosen.is_empty() {
                let (fee, _) = rule.fee(shape(1, &[recipient_len])?.vsize)?;
                return Err(PlanError::InsufficientFunds {
                    available: Sats::ZERO,
                    needed: dust.checked_add(fee).ok_or(PlanError::Overflow)?,
                });
            }
            let total = sum_values(&chosen)?;
            let without = shape(chosen.len(), &[recipient_len])?;
            let (fee, _) = rule.fee(without.vsize)?;
            let amount = total
                .checked_sub(fee)
                .filter(|amount| *amount >= dust)
                .ok_or(PlanError::DustAmount { threshold: dust })?;
            let fit = Fit {
                change: None,
                fee,
                folded: Sats::ZERO,
                shape: without,
                min_applied: false,
            };
            let excluded = desc.len().saturating_sub(largest);
            (chosen, amount, fit, true, excluded)
        }
        SendAmount::Exact(amount) => {
            if amount < dust {
                return Err(PlanError::DustAmount { threshold: dust });
            }
            let (chosen, fit) = select(&candidates, &desc, amount, recipient_len, rule)?;
            (chosen, amount, fit, false, 0)
        }
    };
    let new_input_total = sum_values(&chosen)?;
    assemble(Assembly {
        network: req.network,
        account: req.account,
        recipient: req.recipient,
        inputs: chosen.iter().map(PlanInput::from).collect(),
        amount,
        fit,
        change_index: req.change_next,
        tip_height: req.tip_height,
        seed: req.layout_seed,
        fee: req.fee,
        typed: req.typed_fee_override,
        send_max,
        excluded,
        recipient_decreased: false,
        bump: None,
        new_input_total,
    })
}

/// Selection steps 1–3 of spec/08 §7.4.
fn select(
    candidates: &[Utxo],
    desc: &[Utxo],
    amount: Sats,
    recipient_len: usize,
    rule: FeeRule,
) -> Result<(Vec<Utxo>, Fit), PlanError> {
    let mut asc = candidates.to_vec();
    asc.sort_by(ascending);
    for utxo in &asc {
        if let Some(fit) = fit(utxo.value, amount, 1, recipient_len, rule, true)? {
            return Ok((vec![*utxo], fit));
        }
    }
    let largest = desc.len().min(BTC_MAX_INPUTS);
    let mut total = desc.first().map_or(Sats::ZERO, |first| first.value);
    for (position, utxo) in desc.iter().enumerate().take(largest).skip(1) {
        total = total.checked_add(utxo.value).ok_or(PlanError::Overflow)?;
        let count = position.checked_add(1).ok_or(PlanError::Overflow)?;
        if let Some(fit) = fit(total, amount, count, recipient_len, rule, true)? {
            return Ok((desc.get(..count).unwrap_or_default().to_vec(), fit));
        }
    }
    let available = sum_values(desc.iter().take(largest))?;
    let (fee, _) = rule.fee(shape(largest.max(1), &[recipient_len])?.vsize)?;
    Err(PlanError::InsufficientFunds {
        available,
        needed: amount.checked_add(fee).ok_or(PlanError::Overflow)?,
    })
}

/// Plans an RBF replacement of `req.source` (spec/08 §9): all original inputs plus, if needed,
/// extra candidates by descending value (fewest), the same recipient script and amount (a
/// send-max loses the fee increase instead), the same change index (dropped below 294;
/// `change_next` when inputs were added to a change-less transaction), the BIP125 minimum fee,
/// a new layout and `lock_time = tip_height`.
///
/// # Errors
///
/// [`PlanError::NotBumpable`] for an empty or oversized source, [`PlanError::DustAmount`] when a
/// send-max recipient would fall below dust, [`PlanError::InsufficientFunds`],
/// [`PlanError::Key`], [`PlanError::Overflow`].
pub fn plan_fee_bump(req: &BumpRequest<'_>) -> Result<SendPlan, PlanError> {
    let source = req.source;
    if source.inputs.is_empty() || source.inputs.len() > BTC_MAX_INPUTS || source.vsize == 0 {
        return Err(PlanError::NotBumpable);
    }
    let rule = FeeRule {
        rate: req.fee.rate,
        bump: Some(BumpMin {
            old_fee: source.fee,
            old_vsize: source.vsize,
            incremental: incremental_or_default(req.incremental),
        }),
    };
    let dust = dust_threshold(&source.recipient);
    let recipient_len = spk_len(&source.recipient);
    let base_total = Sats::checked_sum(source.inputs.iter().map(|input| input.value))
        .ok_or(PlanError::Overflow)?;
    let info = BumpInfo {
        replaces: source.txid,
        old_fee: source.fee,
        old_amount: source.amount,
        min_applied: false,
    };
    let (inputs, amount, fit, added_total) = if source.send_max {
        let without = shape(source.inputs.len(), &[recipient_len])?;
        let (fee, min_applied) = rule.fee(without.vsize)?;
        let amount = base_total
            .checked_sub(fee)
            .filter(|amount| *amount >= dust)
            .ok_or(PlanError::DustAmount { threshold: dust })?;
        let fit = Fit {
            change: None,
            fee,
            folded: Sats::ZERO,
            shape: without,
            min_applied,
        };
        (source.inputs.clone(), amount, fit, Sats::ZERO)
    } else {
        let mut extras: Vec<Utxo> = eligible(req.candidates, req.tip_height)
            .into_iter()
            .filter(|utxo| {
                !source
                    .inputs
                    .iter()
                    .any(|input| input.outpoint == utxo.outpoint)
            })
            .collect();
        extras.sort_by(descending);
        let (count, fit) = bump_select(source, &extras, base_total, recipient_len, rule)?;
        let added = extras.get(..count).unwrap_or_default();
        let mut inputs = source.inputs.clone();
        inputs.extend(added.iter().map(PlanInput::from));
        (inputs, source.amount, fit, sum_values(added)?)
    };
    let new_fee = fit.fee;
    if !bump_fee_ok(
        source.fee,
        source.vsize,
        new_fee,
        fit.shape.vsize,
        req.incremental,
    ) {
        return Err(PlanError::Overflow);
    }
    assemble(Assembly {
        network: source.network,
        account: req.account,
        recipient: source.recipient,
        inputs,
        amount,
        fit,
        change_index: source.change_index.unwrap_or(req.change_next),
        tip_height: req.tip_height,
        seed: req.layout_seed,
        fee: req.fee,
        typed: req.typed_fee_override,
        send_max: source.send_max,
        excluded: 0,
        recipient_decreased: amount < source.amount,
        bump: Some(info),
        new_input_total: added_total,
    })
}

/// The fewest extra inputs (in `extras` order) that make the replacement feasible.
fn bump_select(
    source: &BumpSource,
    extras: &[Utxo],
    base_total: Sats,
    recipient_len: usize,
    rule: FeeRule,
) -> Result<(usize, Fit), PlanError> {
    let room = BTC_MAX_INPUTS.saturating_sub(source.inputs.len());
    let mut total = base_total;
    let mut last_count = source.inputs.len();
    for added in 0..=extras.len().min(room) {
        if added > 0 {
            let extra = extras
                .get(added.saturating_sub(1))
                .ok_or(PlanError::Overflow)?;
            total = total.checked_add(extra.value).ok_or(PlanError::Overflow)?;
        }
        let count = source
            .inputs
            .len()
            .checked_add(added)
            .ok_or(PlanError::Overflow)?;
        last_count = count;
        let allow_change = source.change_index.is_some() || added > 0;
        if let Some(fit) = fit(
            total,
            source.amount,
            count,
            recipient_len,
            rule,
            allow_change,
        )? {
            return Ok((added, fit));
        }
    }
    let (fee, _) = rule.fee(shape(last_count, &[recipient_len])?.vsize)?;
    Err(PlanError::InsufficientFunds {
        available: total,
        needed: source.amount.checked_add(fee).ok_or(PlanError::Overflow)?,
    })
}
