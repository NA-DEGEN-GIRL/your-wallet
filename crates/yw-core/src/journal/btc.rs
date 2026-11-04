//! BTC journal records (spec/08 §12.1–§12.4, `kind 0x03` entries of spec/02 §5.4): the binary
//! body codec with every load check (exact length, strict transaction parse, recomputed txid and
//! wtxid, input list in transaction order, output indices, flags against zero fields, no unknown
//! state), the state table with its transitions, startup normalization, the D20
//! in-flight rule, replacement bookkeeping, the §12.2 tracking decisions as pure functions,
//! finished-record clean-up and the pre-add room check, the `ActivityEntry` mapping, and the
//! `change_next` floor. A body the decoder rejects stops BTC sending only; its bytes are kept.
//!
//! Body layout (big-endian; the raw transaction bytes as they are), 238-byte fixed header:
//!
//! ```text
//! [0] record_version u8 = 1   [1] network u8   [2] state u8   [3] flags u8 (bits 0–7)
//! [4] entry_id [16]   [20] created_at_unix u64   [28] updated_at_unix u64
//! [36] txid [32]   [68] wtxid [32]   [100] approval_digest [32]
//! [132] fee_sats u64   [140] vsize u32   [144] lock_time u32   [148] not_found_count u32
//! [152] replaces_txid [32]   [184] replaced_by_txid [32]   [216] confirmed_height u32
//! [220] change_index u32   [224] change_vout u32   [228] recipient_vout u32
//! [232] input_count u16   [234] raw_len u32
//! [238] input_count × 49: txid[32] vout u32 value u64 chain u8 index u32
//! [238 + 49n] raw_len bytes: the signed transaction
//! ```
//!
//! Records of BIP84 account 0 keep exactly this layout (`record_version = 1`). Every other account
//! (another address type or account number, or an imported key) writes `record_version = 2`:
//! the same 238-byte header, an 18-byte account block at `[238]` (`source u8` 1 HD / 2
//! imported / 3 EVM account key, `script_type u8`, then the HD account `u32` and 12 zero bytes,
//! the 16-byte record id, or the EVM account index `u32` and 12 zero bytes), then the inputs at
//! `[256]` and the raw bytes. A P2PKH account's raw transaction has no witness.
//!
//! A record's change index does not say which chain it is on: an HD account in fixed-address
//! mode (spec/08 §3.5) sends change to `(Receive, 0)` and records index 0. The change output's
//! script decides ([`BtcRecord::hd_change_index`], [`BtcRecord::own_change_utxo`]), so records
//! written before the account's mode was switched stay correct.
#![deny(clippy::indexing_slicing)]

use core::fmt;

use super::{
    ENTRY_HEADER_LEN, Entry, EntryKind, JournalError, JournalPlain, MAX_ENTRIES, MAX_PLAINTEXT,
};
use crate::bip32::HARDENED;
use crate::bip32::path::BtcChain;
use crate::btc::account::{BtcAccountId, BtcAccountKey, ScriptType};
use crate::btc::address::{ScriptKind, encode_address, hash160, kind_from_script, script_pubkey};
use crate::btc::amount::Sats;
use crate::btc::display::btc_title;
use crate::btc::meta::{BtcMeta, VerifiedUtxo};
use crate::btc::network::BtcNetwork;
use crate::btc::script::{
    p2pkh_script_pubkey, p2sh_p2wpkh_redeem_script, p2sh_script_pubkey, p2wpkh_script_pubkey,
    split_p2pkh_script_sig,
};
use crate::btc::select::{BumpSource, PlanError, PlanInput, SendPlan};
use crate::btc::sign::SignedTx;
use crate::btc::taproot::{Prevout, check_key_path_witness, sighash_default};
use crate::btc::tx::{
    OutPoint, Transaction, TxIn, Txid, parse_transaction, serialize, txid, vsize, wtxid,
};
use crate::btc::verify::VerifiedSignedTx;
use crate::btc::{
    BTC_JOURNAL_FINAL_KEEP, BTC_MAX_INPUTS, BTC_MAX_JOURNAL_RAW, BTC_NOT_FOUND_LIMIT, conf,
};
use crate::error::KeyError;

/// `record_version` of BIP84 account 0 records (unchanged layout).
pub const BTC_RECORD_VERSION: u8 = 1;
/// `record_version` of every other account's records: the version 1 header, then an 18-byte
/// account block, then inputs and raw bytes.
pub const BTC_RECORD_VERSION_V2: u8 = 2;
/// Fixed header length.
pub const BTC_JOURNAL_HEADER_LEN: usize = 238;
/// The version 2 account block: `source u8 (1 HD, 2 imported, 3 EVM key) ‖ script_type u8 ‖ (HD:
/// account u32 ‖ 0^12 | imported: record id 16 | EVM key: EVM account index u32 ‖ 0^12)`.
pub const BTC_JOURNAL_ACCOUNT_LEN: usize = 18;
/// Bytes per input record.
pub const BTC_JOURNAL_INPUT_LEN: usize = 49;
/// Largest BTC body: 238 + 18 + 49 × 100 + 32,768 = 37,924 (spec/02 §5.4; version 1 bodies are
/// at most 37,906).
pub const BTC_JOURNAL_MAX_BODY: usize = 37_924;
/// Confirmations at which a transaction is final and tracking stops (spec/08 §12.2-4): one.
/// The configured Core RPC and indexer are trusted (spec.md §2.2); a reorg of a one-confirmation
/// transaction is out of scope.
pub const BTC_FINAL_CONFIRMATIONS: u32 = 1;
/// `Abandoned` records may still become `Confirmed` within this window, and are finished after
/// it (30 days, seconds).
pub const BTC_ABANDON_WINDOW_SECS: u64 = 30 * 86_400;

/// Flag bits (`[3] flags`).
pub mod flags {
    /// bit0: send-max.
    pub const SEND_MAX: u8 = 1 << 0;
    /// bit1: fee cap lifted by the typed override.
    pub const FEE_OVERRIDE_TYPED: u8 = 1 << 1;
    /// bit2: has change.
    pub const HAS_CHANGE: u8 = 1 << 2;
    /// bit3: has `replaces_txid`.
    pub const HAS_REPLACES: u8 = 1 << 3;
    /// bit4: has `replaced_by_txid`.
    pub const HAS_REPLACED_BY: u8 = 1 << 4;
    /// bit5: has `confirmed_height`.
    pub const HAS_CONFIRMED_HEIGHT: u8 = 1 << 5;
    /// bit6: the last Core `sendrawtransaction` of this record was a communication failure
    /// (spec/08 §11.3 manual Esplora broadcast condition; kept across restarts).
    pub const LAST_SEND_COMM_FAILURE: u8 = 1 << 6;
    /// bit7: the signed bytes were handed to the RPC (`testmempoolaccept` or
    /// `sendrawtransaction` attempted; written to the journal before the call). A hostile RPC
    /// may relay them, so a later `Rejected` or [취소] of this record still constrains the next
    /// send (spec/08 §12.1 "공개된 거래"). Records written before this bit read as not disclosed.
    pub const DISCLOSED: u8 = 1 << 7;
    /// Every defined bit (all eight are in use).
    pub const ALL: u8 = 0xff;
}

const NO_INDEX: u32 = 0xFFFF_FFFF;

/// Record state (spec/08 §12.1 codes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BtcTxState {
    /// Signed and journaled, not yet sent (in flight).
    Signed = 1,
    /// Refused by the node (finished).
    Rejected = 2,
    /// `testmempoolaccept` passed, `sendrawtransaction` under way (in flight).
    Broadcasting = 3,
    /// The node accepted it (in flight).
    Submitted = 4,
    /// Outcome unknown (in flight).
    BroadcastUnknown = 5,
    /// Seen in the mempool (in flight).
    InMempool = 6,
    /// Confirmed: final at one confirmation (not tracked further).
    Confirmed = 7,
    /// Replaced by a fee bump (tracked until the replacement confirms).
    Replaced = 8,
    /// The replaced original confirmed first (finished).
    Conflicted = 9,
    /// Given up by the user (may still confirm within 30 days).
    Abandoned = 10,
}

impl BtcTxState {
    /// The state code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Parses a state code.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::Signed,
            2 => Self::Rejected,
            3 => Self::Broadcasting,
            4 => Self::Submitted,
            5 => Self::BroadcastUnknown,
            6 => Self::InMempool,
            7 => Self::Confirmed,
            8 => Self::Replaced,
            9 => Self::Conflicted,
            10 => Self::Abandoned,
            _ => return None,
        })
    }

    /// Fixed name (logs).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Signed => "Signed",
            Self::Rejected => "Rejected",
            Self::Broadcasting => "Broadcasting",
            Self::Submitted => "Submitted",
            Self::BroadcastUnknown => "BroadcastUnknown",
            Self::InMempool => "InMempool",
            Self::Confirmed => "Confirmed",
            Self::Replaced => "Replaced",
            Self::Conflicted => "Conflicted",
            Self::Abandoned => "Abandoned",
        }
    }

    /// "진행 중" states 1, 3, 4, 5, 6 (D20: one replacement chain per account).
    #[must_use]
    pub const fn is_in_flight(self) -> bool {
        matches!(
            self,
            Self::Signed
                | Self::Broadcasting
                | Self::Submitted
                | Self::BroadcastUnknown
                | Self::InMempool
        )
    }

    /// RBF targets (spec/08 §9): `Submitted`, `BroadcastUnknown`, `InMempool`.
    #[must_use]
    pub const fn can_bump(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::BroadcastUnknown | Self::InMempool
        )
    }

    /// The §12.1 transition table (with `Conflicted` reachable from the broadcast states and
    /// `Replaced` when an original confirms first). `BroadcastUnknown → Abandoned` additionally
    /// needs the record's [`BtcRecord::can_abandon`] (checked by [`set_state`]). The table keeps
    /// `Confirmed → InMempool / BroadcastUnknown` (a reorg seen by tracking), but a `Confirmed`
    /// record is final at one confirmation and no longer tracked, so tracking never feeds it.
    /// An `Abandoned` record becomes `Conflicted` when a transaction spending one of its inputs
    /// confirms (one confirmation).
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        match self {
            Self::Signed => matches!(next, Self::Broadcasting | Self::Rejected | Self::Abandoned),
            // Only a disclosed record (flags bit7) leaves `Rejected` (checked by the working
            // copy): the RPC had its bytes, so it may confirm, or a send spending one of its
            // inputs may confirm first.
            Self::Rejected => matches!(next, Self::Confirmed | Self::Conflicted),
            Self::Broadcasting => matches!(
                next,
                Self::Submitted | Self::BroadcastUnknown | Self::Rejected
            ),
            Self::Submitted => matches!(
                next,
                Self::InMempool
                    | Self::Confirmed
                    | Self::Replaced
                    | Self::BroadcastUnknown
                    | Self::Conflicted
            ),
            Self::BroadcastUnknown => matches!(
                next,
                Self::InMempool
                    | Self::Confirmed
                    | Self::Replaced
                    | Self::Abandoned
                    | Self::Conflicted
            ),
            Self::InMempool => matches!(
                next,
                Self::Confirmed | Self::Replaced | Self::BroadcastUnknown | Self::Conflicted
            ),
            Self::Replaced => matches!(next, Self::Confirmed | Self::Conflicted),
            Self::Abandoned => matches!(next, Self::Confirmed | Self::Conflicted),
            Self::Confirmed => matches!(next, Self::InMempool | Self::BroadcastUnknown),
            Self::Conflicted => false,
        }
    }

    /// The `ActivityEntry.status` (spec/08 §12.3, spec/02 §5.3): `Confirmed` → `succeeded`,
    /// others their lowercase name; `None` for states that never produce a row.
    #[must_use]
    pub const fn activity_status(self) -> Option<&'static str> {
        match self {
            Self::Confirmed => Some("succeeded"),
            Self::Rejected => Some("rejected"),
            Self::Replaced => Some("replaced"),
            Self::Conflicted => Some("conflicted"),
            Self::Abandoned => Some("abandoned"),
            Self::Signed
            | Self::Broadcasting
            | Self::Submitted
            | Self::BroadcastUnknown
            | Self::InMempool => None,
        }
    }
}

/// A body the BTC decoder rejects ("저널 손상", E-VLT-006: BTC sending stops, bytes kept).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BtcRecordError {
    /// Length, `input_count` or `raw_len` out of bounds, or the length is not exact.
    Length,
    /// `record_version != 1`.
    Version,
    /// Unknown network or state, zero `entry_id`, or an out-of-range value.
    Value,
    /// Flags and the optional fields disagree.
    Flags,
    /// An input record is invalid or differs from the transaction's input order.
    Inputs,
    /// The raw transaction does not parse strictly or re-serializes differently.
    Raw,
    /// txid or wtxid differ from the recomputed values.
    Hash,
    /// `recipient_vout`/`change_vout` out of range, or vsize, lock time or fee inconsistent.
    Outputs,
}

impl fmt::Display for BtcRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("저널 손상")
    }
}

impl std::error::Error for BtcRecordError {}

/// The change of a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RecordChange {
    /// Change chain index.
    pub index: u32,
    /// Output index.
    pub vout: u32,
}

/// One BTC journal record (spec/08 §12.4).
#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent persisted flag bits of one record (spec/08 §12.4)"
)]
pub struct BtcRecord {
    /// Network.
    pub network: BtcNetwork,
    /// The spending account.
    pub account: BtcAccountId,
    /// Its address type (of every input and of the change; P2WPKH for version 1 records).
    pub script_type: ScriptType,
    /// State.
    pub state: BtcTxState,
    /// Send-max.
    pub send_max: bool,
    /// Fee cap lifted by the typed override.
    pub fee_override_typed: bool,
    /// Non-zero identifier (the approval id).
    pub entry_id: [u8; 16],
    /// Creation time (Unix seconds).
    pub created_at_unix: u64,
    /// Last change (Unix seconds).
    pub updated_at_unix: u64,
    /// txid (internal order).
    pub txid: Txid,
    /// wtxid (internal order).
    pub wtxid: [u8; 32],
    /// Approval digest.
    pub approval_digest: [u8; 32],
    /// Fee.
    pub fee: Sats,
    /// Actual vsize.
    pub vsize: u32,
    /// Lock time.
    pub lock_time: u32,
    /// Consecutive not-found observations (spec/08 §12.2).
    pub not_found_count: u32,
    /// The last Core `sendrawtransaction` was a communication failure (flags bit6).
    pub last_send_comm_failure: bool,
    /// The signed bytes were handed to the RPC (flags bit7, [`flags::DISCLOSED`]).
    pub disclosed: bool,
    /// The transaction this one replaces (fee bump).
    pub replaces: Option<Txid>,
    /// The replacement that replaced this one.
    pub replaced_by: Option<Txid>,
    /// Confirmation height (`Confirmed` only).
    pub confirmed_height: Option<u32>,
    /// Change, if any.
    pub change: Option<RecordChange>,
    /// Recipient output index.
    pub recipient_vout: u32,
    /// Inputs in transaction order with their verified values and paths.
    pub inputs: Vec<PlanInput>,
    /// The signed transaction.
    pub raw: Vec<u8>,
}

struct Reader<'a> {
    body: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn take(&mut self, count: usize) -> Result<&[u8], BtcRecordError> {
        let end = self.at.checked_add(count).ok_or(BtcRecordError::Length)?;
        let slice = self.body.get(self.at..end).ok_or(BtcRecordError::Length)?;
        self.at = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], BtcRecordError> {
        self.take(N)?.try_into().map_err(|_| BtcRecordError::Length)
    }

    fn u8(&mut self) -> Result<u8, BtcRecordError> {
        Ok(u8::from_be_bytes(self.array::<1>()?))
    }

    fn u16(&mut self) -> Result<u16, BtcRecordError> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    fn u32(&mut self) -> Result<u32, BtcRecordError> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, BtcRecordError> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }
}

fn optional_hash(present: bool, bytes: [u8; 32]) -> Result<Option<Txid>, BtcRecordError> {
    match (present, bytes == [0; 32]) {
        (true, false) => Ok(Some(Txid::from_bytes(bytes))),
        (false, true) => Ok(None),
        _ => Err(BtcRecordError::Flags),
    }
}

fn chain_from_code(code: u8) -> Option<BtcChain> {
    match code {
        0 => Some(BtcChain::Receive),
        1 => Some(BtcChain::Change),
        _ => None,
    }
}

/// `count` input records (49 bytes each).
fn read_inputs(reader: &mut Reader<'_>, count: usize) -> Result<Vec<PlanInput>, BtcRecordError> {
    let mut inputs = Vec::with_capacity(count);
    for _ in 0..count {
        let outpoint = OutPoint {
            txid: Txid::from_bytes(reader.array::<32>()?),
            vout: reader.u32()?,
        };
        let value = Sats::new(reader.u64()?).ok_or(BtcRecordError::Inputs)?;
        let chain = chain_from_code(reader.u8()?).ok_or(BtcRecordError::Inputs)?;
        let index = reader.u32()?;
        inputs.push(PlanInput {
            outpoint,
            value,
            chain,
            index,
        });
    }
    Ok(inputs)
}

/// The version 2 account block: a known source and type, zero padding after an HD account
/// number, a non-zero imported id, and never BIP84 account 0 (that is version 1).
fn decode_account_block(
    block: &[u8; BTC_JOURNAL_ACCOUNT_LEN],
) -> Result<(BtcAccountId, ScriptType), BtcRecordError> {
    let [source, code, rest @ ..] = block;
    let script_type = ScriptType::from_code(*code).ok_or(BtcRecordError::Value)?;
    let id = <[u8; 16]>::try_from(rest.as_slice()).map_err(|_| BtcRecordError::Length)?;
    let account = match source {
        1 => {
            let (number, padding) = id.split_first_chunk::<4>().ok_or(BtcRecordError::Length)?;
            let account = u32::from_be_bytes(*number);
            if padding.iter().any(|byte| *byte != 0) || account & HARDENED != 0 {
                return Err(BtcRecordError::Value);
            }
            BtcAccountId::Hd {
                script_type,
                account,
            }
        }
        2 if id != [0; 16] => BtcAccountId::Imported { id },
        3 => {
            let (number, padding) = id.split_first_chunk::<4>().ok_or(BtcRecordError::Length)?;
            let evm_index = u32::from_be_bytes(*number);
            if padding.iter().any(|byte| *byte != 0)
                || crate::bip32::path::AccountIndex::new(evm_index).is_err()
            {
                return Err(BtcRecordError::Value);
            }
            BtcAccountId::EvmShared {
                evm_index,
                script_type,
            }
        }
        _ => return Err(BtcRecordError::Value),
    };
    if account == BtcAccountId::PRIMARY {
        return Err(BtcRecordError::Version);
    }
    Ok((account, script_type))
}

/// Checks the record against its parsed transaction (shared by `decode` and `encode`).
fn check_against_raw(record: &BtcRecord) -> Result<Transaction, BtcRecordError> {
    if record.raw.is_empty() || record.raw.len() > BTC_MAX_JOURNAL_RAW {
        return Err(BtcRecordError::Length);
    }
    if record.inputs.is_empty() || record.inputs.len() > BTC_MAX_INPUTS {
        return Err(BtcRecordError::Length);
    }
    if matches!(record.account, BtcAccountId::Hd { script_type, .. } | BtcAccountId::EvmShared { script_type, .. } if script_type != record.script_type)
    {
        return Err(BtcRecordError::Value);
    }
    let parsed = parse_transaction(&record.raw).map_err(|_| BtcRecordError::Raw)?;
    if parsed.has_witness() != record.script_type.is_segwit()
        || serialize(&parsed, true) != record.raw
    {
        return Err(BtcRecordError::Raw);
    }
    if txid(&parsed) != record.txid || wtxid(&parsed) != record.wtxid {
        return Err(BtcRecordError::Hash);
    }
    if record.inputs.len() != parsed.inputs.len()
        || record
            .inputs
            .iter()
            .zip(&parsed.inputs)
            .any(|(input, tx_input)| input.outpoint != tx_input.prevout)
        || record
            .inputs
            .iter()
            .any(|input| input.index & HARDENED != 0 || input.value == Sats::ZERO)
    {
        return Err(BtcRecordError::Inputs);
    }
    let outputs = parsed.outputs.len();
    let in_range = |vout: u32| usize::try_from(vout).is_ok_and(|vout| vout < outputs);
    let recipient_ok = in_range(record.recipient_vout)
        && usize::try_from(record.recipient_vout)
            .ok()
            .and_then(|vout| parsed.outputs.get(vout))
            .is_some_and(|output| kind_from_script(&output.script_pubkey).is_some());
    let change_ok = record.change.is_none_or(|change| {
        in_range(change.vout)
            && change.vout != record.recipient_vout
            && change.index & HARDENED == 0
    });
    let input_total = Sats::checked_sum(record.inputs.iter().map(|input| input.value));
    let output_total = Sats::checked_sum(parsed.outputs.iter().map(|output| output.value));
    let fee_ok = input_total
        .zip(output_total)
        .and_then(|(inputs, outputs)| inputs.checked_sub(outputs))
        == Some(record.fee);
    if !recipient_ok
        || !change_ok
        || !fee_ok
        || u64::from(record.vsize) != vsize(&parsed)
        || record.lock_time != parsed.lock_time
    {
        return Err(BtcRecordError::Outputs);
    }
    Ok(parsed)
}

fn check_flags(record: &BtcRecord) -> Result<(), BtcRecordError> {
    if record.entry_id == [0; 16] {
        return Err(BtcRecordError::Value);
    }
    let confirmed = record.state == BtcTxState::Confirmed;
    if confirmed != record.confirmed_height.is_some()
        || record.confirmed_height == Some(0)
        || (record.state == BtcTxState::Replaced && record.replaced_by.is_none())
        || record.replaces == Some(Txid::from_bytes([0; 32]))
        || record.replaced_by == Some(Txid::from_bytes([0; 32]))
    {
        return Err(BtcRecordError::Flags);
    }
    Ok(())
}

impl BtcRecord {
    /// The `Signed` record of a verified signed plan (spec/08 §11.1): `entry_id` is the approval
    /// id, `vsize` the actual size.
    ///
    /// # Errors
    ///
    /// [`BtcRecordError`] when `signed` and `verified` are different transactions, the approval
    /// id is zero, or the record would not pass its own load checks.
    pub fn new_signed(
        plan: &SendPlan,
        signed: &SignedTx,
        verified: &VerifiedSignedTx,
        now_unix: u64,
    ) -> Result<Self, BtcRecordError> {
        if signed.raw != verified.raw() {
            return Err(BtcRecordError::Raw);
        }
        let record = Self {
            network: plan.network(),
            account: plan.account().id(),
            script_type: plan.account().script_type(),
            state: BtcTxState::Signed,
            send_max: plan.send_max(),
            fee_override_typed: plan.fee_override_typed(),
            entry_id: signed.approval_id.0,
            created_at_unix: now_unix,
            updated_at_unix: now_unix,
            txid: verified.txid(),
            wtxid: verified.wtxid(),
            approval_digest: signed.approval_digest,
            fee: verified.fee(),
            vsize: u32::try_from(verified.vsize()).map_err(|_| BtcRecordError::Outputs)?,
            lock_time: plan.lock_time(),
            not_found_count: 0,
            last_send_comm_failure: false,
            disclosed: false,
            replaces: plan.replaces(),
            replaced_by: None,
            confirmed_height: None,
            change: plan.change().map(|change| RecordChange {
                index: change.index,
                vout: change.vout,
            }),
            recipient_vout: plan.recipient_vout(),
            inputs: plan.inputs().to_vec(),
            raw: signed.raw.clone(),
        };
        check_flags(&record)?;
        check_against_raw(&record)?;
        Ok(record)
    }

    const fn flags(&self) -> u8 {
        let mut out = 0;
        if self.send_max {
            out |= flags::SEND_MAX;
        }
        if self.fee_override_typed {
            out |= flags::FEE_OVERRIDE_TYPED;
        }
        if self.change.is_some() {
            out |= flags::HAS_CHANGE;
        }
        if self.replaces.is_some() {
            out |= flags::HAS_REPLACES;
        }
        if self.replaced_by.is_some() {
            out |= flags::HAS_REPLACED_BY;
        }
        if self.confirmed_height.is_some() {
            out |= flags::HAS_CONFIRMED_HEIGHT;
        }
        if self.last_send_comm_failure {
            out |= flags::LAST_SEND_COMM_FAILURE;
        }
        if self.disclosed {
            out |= flags::DISCLOSED;
        }
        out
    }

    /// Whether this record keeps the version 1 layout (BIP84 account 0).
    fn is_v1(&self) -> bool {
        self.account == BtcAccountId::PRIMARY
    }

    /// The version 2 account block.
    fn account_block(&self) -> [u8; BTC_JOURNAL_ACCOUNT_LEN] {
        let mut out = [0_u8; BTC_JOURNAL_ACCOUNT_LEN];
        let (source, body) = match self.account {
            BtcAccountId::Hd { account, .. } => {
                let mut body = [0_u8; 16];
                for (slot, byte) in body.iter_mut().zip(account.to_be_bytes()) {
                    *slot = byte;
                }
                (1_u8, body)
            }
            BtcAccountId::Imported { id } => (2_u8, id),
            BtcAccountId::EvmShared { evm_index, .. } => {
                let mut body = [0_u8; 16];
                for (slot, byte) in body.iter_mut().zip(evm_index.to_be_bytes()) {
                    *slot = byte;
                }
                (3_u8, body)
            }
        };
        for (slot, byte) in out
            .iter_mut()
            .zip([source, self.script_type.code()].iter().chain(body.iter()))
        {
            *slot = *byte;
        }
        out
    }

    /// Encodes the body (`238 + 49 × inputs + raw_len` bytes; version 2 adds the 18-byte account
    /// block after the header).
    ///
    /// # Errors
    ///
    /// [`BtcRecordError`] when the record would not pass [`BtcRecord::decode`].
    pub fn encode(&self) -> Result<Vec<u8>, BtcRecordError> {
        check_flags(self)?;
        check_against_raw(self)?;
        let count = u16::try_from(self.inputs.len()).map_err(|_| BtcRecordError::Length)?;
        let raw_len = u32::try_from(self.raw.len()).map_err(|_| BtcRecordError::Length)?;
        let mut out = Vec::with_capacity(
            BTC_JOURNAL_MAX_BODY.min(
                BTC_JOURNAL_HEADER_LEN
                    .saturating_add(BTC_JOURNAL_ACCOUNT_LEN)
                    .saturating_add(BTC_JOURNAL_INPUT_LEN.saturating_mul(self.inputs.len()))
                    .saturating_add(self.raw.len()),
            ),
        );
        out.push(if self.is_v1() {
            BTC_RECORD_VERSION
        } else {
            BTC_RECORD_VERSION_V2
        });
        out.push(self.network.id());
        out.push(self.state.code());
        out.push(self.flags());
        out.extend_from_slice(&self.entry_id);
        out.extend_from_slice(&self.created_at_unix.to_be_bytes());
        out.extend_from_slice(&self.updated_at_unix.to_be_bytes());
        out.extend_from_slice(self.txid.as_bytes());
        out.extend_from_slice(&self.wtxid);
        out.extend_from_slice(&self.approval_digest);
        out.extend_from_slice(&self.fee.get().to_be_bytes());
        out.extend_from_slice(&self.vsize.to_be_bytes());
        out.extend_from_slice(&self.lock_time.to_be_bytes());
        out.extend_from_slice(&self.not_found_count.to_be_bytes());
        out.extend_from_slice(&self.replaces.map_or([0; 32], Txid::to_bytes));
        out.extend_from_slice(&self.replaced_by.map_or([0; 32], Txid::to_bytes));
        out.extend_from_slice(&self.confirmed_height.unwrap_or(0).to_be_bytes());
        out.extend_from_slice(&self.change.map_or(NO_INDEX, |c| c.index).to_be_bytes());
        out.extend_from_slice(&self.change.map_or(NO_INDEX, |c| c.vout).to_be_bytes());
        out.extend_from_slice(&self.recipient_vout.to_be_bytes());
        out.extend_from_slice(&count.to_be_bytes());
        out.extend_from_slice(&raw_len.to_be_bytes());
        if !self.is_v1() {
            out.extend_from_slice(&self.account_block());
        }
        for input in &self.inputs {
            out.extend_from_slice(input.outpoint.txid.as_bytes());
            out.extend_from_slice(&input.outpoint.vout.to_be_bytes());
            out.extend_from_slice(&input.value.get().to_be_bytes());
            out.push(u8::try_from(input.chain.index()).unwrap_or(u8::MAX));
            out.extend_from_slice(&input.index.to_be_bytes());
        }
        out.extend_from_slice(&self.raw);
        Ok(out)
    }

    /// Decodes and fully validates a body (spec/08 §12.4 load checks).
    ///
    /// # Errors
    ///
    /// [`BtcRecordError`].
    pub fn decode(body: &[u8]) -> Result<Self, BtcRecordError> {
        if body.len() < BTC_JOURNAL_HEADER_LEN || body.len() > BTC_JOURNAL_MAX_BODY {
            return Err(BtcRecordError::Length);
        }
        let mut reader = Reader { body, at: 0 };
        let v2 = match reader.u8()? {
            BTC_RECORD_VERSION => false,
            BTC_RECORD_VERSION_V2 => true,
            _ => return Err(BtcRecordError::Version),
        };
        let network = BtcNetwork::from_id(reader.u8()?).ok_or(BtcRecordError::Value)?;
        let state = BtcTxState::from_code(reader.u8()?).ok_or(BtcRecordError::Value)?;
        // Every flag bit is defined (`flags::ALL == 0xff`): no unknown bit to refuse.
        let flag_bits = reader.u8()?;
        let has = |bit: u8| flag_bits & bit != 0;
        let entry_id = reader.array::<16>()?;
        let created_at_unix = reader.u64()?;
        let updated_at_unix = reader.u64()?;
        let txid_bytes = reader.array::<32>()?;
        let wtxid_bytes = reader.array::<32>()?;
        let approval_digest = reader.array::<32>()?;
        let fee = Sats::new(reader.u64()?).ok_or(BtcRecordError::Value)?;
        let vsize_field = reader.u32()?;
        let lock_time = reader.u32()?;
        let not_found_count = reader.u32()?;
        let replaces = optional_hash(has(flags::HAS_REPLACES), reader.array::<32>()?)?;
        let replaced_by = optional_hash(has(flags::HAS_REPLACED_BY), reader.array::<32>()?)?;
        let height = reader.u32()?;
        let confirmed_height = match (has(flags::HAS_CONFIRMED_HEIGHT), height) {
            (true, 0) | (false, 1..) => return Err(BtcRecordError::Flags),
            (true, height) => Some(height),
            (false, _) => None,
        };
        let change_index = reader.u32()?;
        let change_vout = reader.u32()?;
        let change = match (has(flags::HAS_CHANGE), change_index, change_vout) {
            (false, NO_INDEX, NO_INDEX) => None,
            (true, index, vout) if index != NO_INDEX && vout != NO_INDEX => {
                Some(RecordChange { index, vout })
            }
            _ => return Err(BtcRecordError::Flags),
        };
        let recipient_vout = reader.u32()?;
        let count = usize::from(reader.u16()?);
        let raw_len = usize::try_from(reader.u32()?).map_err(|_| BtcRecordError::Length)?;
        if count == 0 || count > BTC_MAX_INPUTS || raw_len == 0 || raw_len > BTC_MAX_JOURNAL_RAW {
            return Err(BtcRecordError::Length);
        }
        let expected = BTC_JOURNAL_INPUT_LEN
            .checked_mul(count)
            .and_then(|inputs| inputs.checked_add(BTC_JOURNAL_HEADER_LEN))
            .and_then(|fixed| fixed.checked_add(if v2 { BTC_JOURNAL_ACCOUNT_LEN } else { 0 }))
            .and_then(|fixed| fixed.checked_add(raw_len))
            .ok_or(BtcRecordError::Length)?;
        if body.len() != expected {
            return Err(BtcRecordError::Length);
        }
        let (account, script_type) = if v2 {
            let block = reader.array::<BTC_JOURNAL_ACCOUNT_LEN>()?;
            decode_account_block(&block)?
        } else {
            (BtcAccountId::PRIMARY, ScriptType::P2wpkh)
        };
        let inputs = read_inputs(&mut reader, count)?;
        let raw = reader.take(raw_len)?.to_vec();
        let record = Self {
            network,
            account,
            script_type,
            state,
            send_max: has(flags::SEND_MAX),
            fee_override_typed: has(flags::FEE_OVERRIDE_TYPED),
            entry_id,
            created_at_unix,
            updated_at_unix,
            txid: Txid::from_bytes(txid_bytes),
            wtxid: wtxid_bytes,
            approval_digest,
            fee,
            vsize: vsize_field,
            lock_time,
            not_found_count,
            last_send_comm_failure: has(flags::LAST_SEND_COMM_FAILURE),
            disclosed: has(flags::DISCLOSED),
            replaces,
            replaced_by,
            confirmed_height,
            change,
            recipient_vout,
            inputs,
            raw,
        };
        check_flags(&record)?;
        check_against_raw(&record)?;
        Ok(record)
    }

    /// The signed transaction (always `Some` for a decoded record).
    #[must_use]
    pub fn transaction(&self) -> Option<Transaction> {
        parse_transaction(&self.raw).ok()
    }

    /// Lowercase hex of the signed bytes (re-broadcast of the same bytes).
    #[must_use]
    pub fn raw_hex(&self) -> String {
        crate::hex::encode(&self.raw)
    }

    fn recipient_output(&self) -> Option<(Vec<u8>, Sats)> {
        let tx = self.transaction()?;
        let output = tx
            .outputs
            .into_iter()
            .nth(usize::try_from(self.recipient_vout).ok()?)?;
        Some((output.script_pubkey, output.value))
    }

    /// Recipient scriptPubKey.
    #[must_use]
    pub fn recipient_script(&self) -> Option<Vec<u8>> {
        self.recipient_output().map(|(script, _)| script)
    }

    /// Recipient kind.
    #[must_use]
    pub fn recipient_kind(&self) -> Option<ScriptKind> {
        kind_from_script(&self.recipient_script()?)
    }

    /// Recipient amount.
    #[must_use]
    pub fn recipient_amount(&self) -> Option<Sats> {
        self.recipient_output().map(|(_, value)| value)
    }

    /// Recipient address (canonical re-encoding).
    #[must_use]
    pub fn recipient_address(&self) -> Option<String> {
        Some(encode_address(&self.recipient_kind()?, self.network))
    }

    /// The approval title rebuilt from the record (spec/08 §10).
    #[must_use]
    pub fn title(&self) -> String {
        btc_title(
            self.network,
            self.replaces.is_some(),
            self.recipient_amount().unwrap_or(Sats::ZERO),
        )
    }

    /// Whether the record may become `Abandoned` (spec/08 §12.1, §12.2-3): [취소] of a `Signed`
    /// record, or [포기] of a `BroadcastUnknown` record that tracking did not find
    /// `BTC_NOT_FOUND_LIMIT` (10) times in a row (neither in the mempool nor confirmed). A
    /// `BroadcastUnknown` right after a send timeout, transport error or txid mismatch is not
    /// abandonable yet.
    #[must_use]
    pub const fn can_abandon(&self) -> bool {
        match self.state {
            BtcTxState::Signed => true,
            BtcTxState::BroadcastUnknown => self.not_found_count >= BTC_NOT_FOUND_LIMIT,
            _ => false,
        }
    }

    /// A given-up or refused record whose transaction may still confirm, within the 30-day
    /// window: an `Abandoned` record that reached the network ([포기] of a `BroadcastUnknown`
    /// record needs `not_found_count >= 10`, kept by the transition) or whose bytes the RPC
    /// received ([`flags::DISCLOSED`], e.g. [취소] after a pre-check attempt), and a disclosed
    /// `Rejected` record (an RPC that answered "rejected" may still have relayed it). [취소] of a
    /// `Signed` record whose bytes never left the app is not live. Every new send must spend one
    /// of its inputs so that at most one of the two can confirm (spec/08 §12.1 "포기 뒤 다시
    /// 보내기", "공개된 거래").
    #[must_use]
    pub const fn is_live_conflict(&self, now_unix: u64) -> bool {
        let may_confirm = match self.state {
            BtcTxState::Abandoned => self.disclosed || self.not_found_count >= BTC_NOT_FOUND_LIMIT,
            BtcTxState::Rejected => self.disclosed,
            _ => false,
        };
        may_confirm && now_unix.saturating_sub(self.updated_at_unix) <= BTC_ABANDON_WINDOW_SECS
    }

    /// Whether this record's transaction may still confirm (spec/04 §2.18: an imported key is
    /// not removed then): in flight, `Replaced` (tracked until its replacement confirms), a live
    /// given-up or refused record ([`BtcRecord::is_live_conflict`]), or any `Abandoned` record
    /// inside the 30-day window (records written before [`flags::DISCLOSED`] existed may have
    /// reached the RPC without saying so).
    #[must_use]
    pub const fn may_still_confirm(&self, now_unix: u64) -> bool {
        let in_window = now_unix.saturating_sub(self.updated_at_unix) <= BTC_ABANDON_WINDOW_SECS;
        self.state.is_in_flight()
            || matches!(self.state, BtcTxState::Replaced)
            || self.is_live_conflict(now_unix)
            || (matches!(self.state, BtcTxState::Abandoned) && in_window)
    }

    /// Whether `other` spends one of this record's inputs.
    #[must_use]
    pub fn shares_input(&self, other: &Self) -> bool {
        self.inputs
            .iter()
            .any(|input| other.inputs.iter().any(|o| o.outpoint == input.outpoint))
    }

    /// Confirmations at `tip_height` (0 unless `Confirmed`).
    #[must_use]
    pub fn confirmations(&self, tip_height: u32) -> u32 {
        self.confirmed_height
            .map_or(0, |height| conf(height, tip_height))
    }

    /// The RBF source of this record (spec/08 §9), `None` unless it is bumpable and every input's
    /// witness key hashes to the program of its recorded `(chain, index)` under `account` (the
    /// journal paths are re-signed by the replacement, so they are checked here).
    #[must_use]
    pub fn bump_source(&self, account: &BtcAccountKey) -> Option<BumpSource> {
        if !self.state.can_bump()
            || self.account != account.id()
            || self.script_type != account.script_type()
        {
            return None;
        }
        let tx = self.transaction()?;
        if !inputs_signed_by(self, &tx, account) {
            return None;
        }
        Some(BumpSource {
            network: self.network,
            txid: self.txid,
            inputs: self.inputs.clone(),
            recipient: self.recipient_kind()?,
            amount: self.recipient_amount()?,
            change_index: self.change.map(|change| change.index),
            fee: self.fee,
            vsize: u64::from(self.vsize),
            send_max: self.send_max,
        })
    }

    /// The change index of this record on `account`'s change chain (spec/08 §3.2): `None` when
    /// there is no change or the change went to the fixed address `(Receive, 0)` (fixed-address
    /// mode and one-key accounts never move `change_next`). A record whose bytes cannot be
    /// checked keeps its index (raising `change_next` is harmless).
    #[must_use]
    pub fn hd_change_index(&self, account: &BtcAccountKey) -> Option<u32> {
        let change = self.change?;
        if account.is_single() {
            return None;
        }
        let fixed = account.script(BtcChain::Receive, 0).ok();
        let paid = self
            .transaction()
            .and_then(|tx| {
                tx.outputs
                    .into_iter()
                    .nth(usize::try_from(change.vout).ok()?)
            })
            .map(|output| output.script_pubkey);
        match (fixed, paid) {
            (Some(fixed), Some(paid)) if fixed == paid => None,
            _ => Some(change.index),
        }
    }

    /// The change outpoint, if any.
    #[must_use]
    pub const fn change_outpoint(&self) -> Option<OutPoint> {
        match self.change {
            Some(change) => Some(OutPoint {
                txid: self.txid,
                vout: change.vout,
            }),
            None => None,
        }
    }

    /// Our change as a verified output once `Confirmed` (spec/08 §12.2-5), from the local bytes.
    /// `None` unless the output's scriptPubKey is the P2WPKH script of `(Change, index)` derived
    /// from `account` (a record of another account, e.g. an alt-passphrase session sharing the
    /// journal, is never inserted into that account's `verified`).
    #[must_use]
    pub fn own_change_utxo(&self, account: &BtcAccountKey) -> Option<VerifiedUtxo> {
        if self.account != account.id() {
            return None;
        }
        let height = self.confirmed_height?;
        let change = self.change?;
        let output = self
            .transaction()?
            .outputs
            .into_iter()
            .nth(usize::try_from(change.vout).ok()?)?;
        // The change chain or the fixed address, whichever the output pays (an HD account's mode
        // may have been switched since the record was written).
        let (chain, index) =
            account
                .change_candidates(change.index)
                .into_iter()
                .find(|(chain, index)| {
                    account
                        .script(*chain, *index)
                        .is_ok_and(|script| script == output.script_pubkey)
                })?;
        Some(VerifiedUtxo {
            outpoint: OutPoint {
                txid: self.txid,
                vout: change.vout,
            },
            value: output.value,
            chain,
            index,
            height,
            is_coinbase: false,
            own: true,
        })
    }
}

/// Whether every input of `tx` (the record's signed bytes) carries the key or signature of the
/// record's `(chain, index)` under `account` (the replacement re-signs these paths): the
/// witness or scriptSig key for ECDSA types, a valid key-path signature for P2TR.
fn inputs_signed_by(record: &BtcRecord, tx: &Transaction, account: &BtcAccountKey) -> bool {
    let Ok(deriver) = account.deriver() else {
        return false;
    };
    let mut prevouts = Vec::with_capacity(record.inputs.len());
    let mut keys = Vec::with_capacity(record.inputs.len());
    for input in &record.inputs {
        let (Ok(key), Ok(kind)) = (
            deriver.pubkey(input.chain, input.index),
            deriver.kind(input.chain, input.index),
        ) else {
            return false;
        };
        prevouts.push(Prevout {
            value: input.value,
            script_pubkey: script_pubkey(&kind),
        });
        keys.push((key, kind));
    }
    record
        .inputs
        .iter()
        .zip(&tx.inputs)
        .zip(&keys)
        .enumerate()
        .all(|(position, ((_, tx_input), (key, kind)))| {
            match account.script_type() {
                ScriptType::P2wpkh | ScriptType::P2shP2wpkh => {
                    matches!(tx_input.witness.as_slice(), [_, item] if item.as_slice() == key.as_bytes())
                }
                ScriptType::P2pkh => split_p2pkh_script_sig(&tx_input.script_sig)
                    .is_some_and(|(_, item)| item == key.as_bytes()),
                ScriptType::P2tr => {
                    let ScriptKind::P2tr(output) = kind else {
                        return false;
                    };
                    sighash_default(tx, position, &prevouts).is_some_and(|sighash| {
                        check_key_path_witness(deriver.ctx(), &tx_input.witness, output, &sighash)
                            .is_ok()
                    })
                }
            }
        })
}

/// The BTC entries of a journal with their entry indices.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BtcEntries {
    /// `(entry index, record)` for every decodable BTC entry.
    pub records: Vec<(usize, BtcRecord)>,
    /// BTC entries the decoder rejected (BTC sending stops while any exist).
    pub corrupt: usize,
}

impl BtcEntries {
    /// Decodes every BTC entry of `plain`.
    #[must_use]
    pub fn from_plain(plain: &JournalPlain) -> Self {
        let mut out = Self::default();
        for (index, entry) in plain.entries.iter().enumerate() {
            if entry.kind != EntryKind::Btc {
                continue;
            }
            match BtcRecord::decode(&entry.body) {
                Ok(record) => out.records.push((index, record)),
                Err(_) => out.corrupt = out.corrupt.saturating_add(1),
            }
        }
        out
    }

    /// The records only.
    #[must_use]
    pub fn records(&self) -> Vec<BtcRecord> {
        self.records
            .iter()
            .map(|(_, record)| record.clone())
            .collect()
    }
}

fn of_network(records: &[BtcRecord], network: BtcNetwork) -> impl Iterator<Item = &BtcRecord> {
    records
        .iter()
        .filter(move |record| record.network == network)
}

/// The records of `account` on `network`. The per-account rules (D20 in-flight, input reuse,
/// abandoned conflicts, recorded amounts, own change, `change_next` floor, bump target) take
/// these: the functions below filter by network only, so the caller passes one account's
/// records.
#[must_use]
pub fn of_account(
    records: &[BtcRecord],
    network: BtcNetwork,
    account: BtcAccountId,
) -> Vec<BtcRecord> {
    of_network(records, network)
        .filter(|record| record.account == account)
        .cloned()
        .collect()
}

/// The scriptPubKey an input spends as its signed bytes show it: the public key of a P2WPKH or
/// P2SH-P2WPKH witness, or of a P2PKH scriptSig. A key-path P2TR input shows no key.
fn revealed_script(script_type: ScriptType, input: &TxIn) -> Option<Vec<u8>> {
    match script_type {
        ScriptType::P2wpkh => match input.witness.as_slice() {
            [_, key] => Some(p2wpkh_script_pubkey(&hash160(key)).to_vec()),
            _ => None,
        },
        ScriptType::P2shP2wpkh => match input.witness.as_slice() {
            [_, key] => {
                let redeem = p2sh_p2wpkh_redeem_script(&hash160(key));
                Some(p2sh_script_pubkey(&hash160(&redeem)).to_vec())
            }
            _ => None,
        },
        ScriptType::P2pkh => split_p2pkh_script_sig(&input.script_sig)
            .map(|(_, key)| p2pkh_script_pubkey(&hash160(key)).to_vec()),
        ScriptType::P2tr => None,
    }
}

/// The scriptPubKey each input of `record` spends, in input order (spec/08 §12.1 "같은 주소의
/// 다른 계정"): read from the signed bytes for the ECDSA types (the public key of the witness or
/// scriptSig); for key-path P2TR, derived at the recorded `(chain, index)` from `own` — the
/// record's own account key when the session has it — once every input carries a valid
/// signature of that key, else `None`.
#[must_use]
pub fn input_scripts(record: &BtcRecord, own: Option<&BtcAccountKey>) -> Vec<Option<Vec<u8>>> {
    let Some(tx) = record.transaction() else {
        return vec![None; record.inputs.len()];
    };
    if record.script_type != ScriptType::P2tr {
        return tx
            .inputs
            .iter()
            .map(|input| revealed_script(record.script_type, input))
            .collect();
    }
    let derived = own
        .filter(|key| key.id() == record.account && key.script_type() == record.script_type)
        .filter(|key| inputs_signed_by(record, &tx, key))
        .and_then(|key| key.deriver().ok());
    record
        .inputs
        .iter()
        .map(|input| {
            derived
                .as_ref()
                .and_then(|deriver| deriver.script(input.chain, input.index).ok())
        })
        .collect()
}

/// One account's footprint for the cross-identity journal rules (spec/08 §12.1 "같은 주소의 다른
/// 계정"): its identity and key, its scripts ([`BtcMeta::owned_scripts`]) and its verified
/// outpoints. A record belongs to the account when it is the account's own (same identity) or
/// spends one of these scripts or outpoints, whatever account identity it was written under.
#[derive(Clone, Debug)]
pub struct AccountScope {
    network: BtcNetwork,
    key: BtcAccountKey,
    scripts: Vec<Vec<u8>>,
    outpoints: Vec<OutPoint>,
}

impl AccountScope {
    /// The scope of `meta`'s account.
    ///
    /// # Errors
    ///
    /// [`KeyError`] (derivation of the account's scripts).
    pub fn of(meta: &BtcMeta) -> Result<Self, KeyError> {
        Ok(Self {
            network: meta.network(),
            key: *meta.account(),
            scripts: meta.owned_scripts()?,
            outpoints: meta.verified().iter().map(|utxo| utxo.outpoint).collect(),
        })
    }

    /// Whether `record` spends an output of this account: the same identity, an input outpoint
    /// among its verified outputs, an input script among its scripts ([`input_scripts`] with
    /// `own`, the record's own account key when the session has it), or (key-path P2TR inputs
    /// whose script is unknown, e.g. a removed imported key imported again under a new record
    /// id) valid signatures of this account's keys at the recorded paths.
    #[must_use]
    pub fn covers(&self, record: &BtcRecord, own: Option<&BtcAccountKey>) -> bool {
        if record.network != self.network {
            return false;
        }
        if record.account == self.key.id()
            || record
                .inputs
                .iter()
                .any(|input| self.outpoints.contains(&input.outpoint))
        {
            return true;
        }
        // Each address type has its own script form: other types never share a script.
        if record.script_type != self.key.script_type() {
            return false;
        }
        let scripts = input_scripts(record, own);
        if scripts
            .iter()
            .flatten()
            .any(|script| self.scripts.contains(script))
        {
            return true;
        }
        record.script_type == ScriptType::P2tr
            && scripts.iter().any(Option::is_none)
            && record
                .transaction()
                .is_some_and(|tx| inputs_signed_by(record, &tx, &self.key))
    }
}

/// The records of `scope`'s network that touch its account ([`AccountScope::covers`]): its own
/// records and every record of another identity spending one of its outputs: an imported key
/// removed and imported again (a new vault record id), or another account with the same address.
/// `keys` are the session's account keys (a record's own key, when present, gives the scripts of
/// its key-path P2TR inputs). D20, the abandon rule and the kept outpoints use these, so a new
/// identity inherits every constraint of the old one (spec/08 §12.1).
#[must_use]
pub fn related_records(
    records: &[BtcRecord],
    scope: &AccountScope,
    keys: &[BtcAccountKey],
) -> Vec<BtcRecord> {
    records
        .iter()
        .filter(|record| {
            let own = keys.iter().find(|key| key.id() == record.account);
            scope.covers(record, own)
        })
        .cloned()
        .collect()
}

/// Whether a transaction of `network`'s account is in flight (D20).
#[must_use]
pub fn in_flight(records: &[BtcRecord], network: BtcNetwork) -> bool {
    of_network(records, network).any(|record| record.state.is_in_flight())
}

/// The outpoints spent by in-flight records, and the change outputs of in-flight records
/// (unconfirmed again after a reorg, spec/08 §12.2-5): excluded from candidates and balance;
/// kept in `verified` by `BtcMeta::apply_refresh`.
#[must_use]
pub fn in_flight_outpoints(records: &[BtcRecord], network: BtcNetwork) -> Vec<OutPoint> {
    let mut out: Vec<OutPoint> = Vec::new();
    for record in of_network(records, network).filter(|record| record.state.is_in_flight()) {
        for outpoint in record
            .inputs
            .iter()
            .map(|input| input.outpoint)
            .chain(record.change_outpoint())
        {
            if !out.contains(&outpoint) {
                out.push(outpoint);
            }
        }
    }
    out
}

/// The input sets of the live `Abandoned` and disclosed `Rejected` records of `network`
/// ([`BtcRecord::is_live_conflict`]): a new send must spend at least one outpoint of every set
/// (`SendRequest::conflicts`), so the given-up transaction and the new one can never both
/// confirm (spec/08 §12.1).
#[must_use]
pub fn abandoned_conflicts(
    records: &[BtcRecord],
    network: BtcNetwork,
    now_unix: u64,
) -> Vec<Vec<OutPoint>> {
    of_network(records, network)
        .filter(|record| record.is_live_conflict(now_unix))
        .map(|record| record.inputs.iter().map(|input| input.outpoint).collect())
        .collect()
}

/// The outpoints `BtcMeta::apply_refresh` keeps although the indexer no longer lists them:
/// [`in_flight_outpoints`] and the inputs of live `Abandoned` / disclosed `Rejected` records
/// ([`abandoned_conflicts`]: an indexer that saw the given-up transaction hides its inputs; the
/// next send must still be able to spend one).
#[must_use]
pub fn refresh_keep_outpoints(
    records: &[BtcRecord],
    network: BtcNetwork,
    now_unix: u64,
) -> Vec<OutPoint> {
    let mut out = in_flight_outpoints(records, network);
    for outpoint in abandoned_conflicts(records, network, now_unix)
        .into_iter()
        .flatten()
    {
        if !out.contains(&outpoint) {
            out.push(outpoint);
        }
    }
    out
}

/// Every recorded `outpoint → value` of `network`'s records (for `check_recorded_amounts`).
#[must_use]
pub fn recorded_amounts(records: &[BtcRecord], network: BtcNetwork) -> Vec<(OutPoint, Sats)> {
    of_network(records, network)
        .flat_map(|record| {
            record
                .inputs
                .iter()
                .map(|input| (input.outpoint, input.value))
        })
        .collect()
}

/// Change outpoints of `network`'s records (our own outputs, never auto-frozen).
#[must_use]
pub fn own_outputs(records: &[BtcRecord], network: BtcNetwork) -> Vec<OutPoint> {
    of_network(records, network)
        .filter_map(BtcRecord::change_outpoint)
        .collect()
}

/// D20 (spec/08 §12.1): a new send is refused while any record of the account is in flight.
///
/// # Errors
///
/// [`PlanError::InFlight`].
pub fn check_can_send(records: &[BtcRecord], network: BtcNetwork) -> Result<(), PlanError> {
    if in_flight(records, network) {
        Err(PlanError::InFlight)
    } else {
        Ok(())
    }
}

/// The current RBF target of `network` (spec/08 §9: always the latest replacement): the last
/// record in journal order (records are appended, so a replacement always follows its
/// original; the wall clock is not used) in `Submitted`/`BroadcastUnknown`/`InMempool`.
#[must_use]
pub fn bump_target(records: &[BtcRecord], network: BtcNetwork) -> Option<&BtcRecord> {
    of_network(records, network)
        .filter(|record| record.state.can_bump())
        .last()
}

/// The current record of `txid` on `network`: the last one in journal order. A txid is unique
/// in the journal ([`push_record`] refuses a second record), but a journal written before that
/// rule may hold a finished record and a later one with the same txid; transitions and
/// observations always address the later one.
#[must_use]
pub fn current_record<'a>(
    records: &'a [BtcRecord],
    network: BtcNetwork,
    txid: &Txid,
) -> Option<&'a BtcRecord> {
    records
        .iter()
        .rev()
        .find(|record| record.network == network && record.txid == *txid)
}

fn find<'a>(records: &'a [BtcRecord], network: BtcNetwork, txid: &Txid) -> Option<&'a BtcRecord> {
    current_record(records, network, txid)
}

/// Whether `record` is the current record of its txid ([`current_record`]): a superseded
/// duplicate of an old journal produces no activity row.
fn is_current(record: &BtcRecord, records: &[BtcRecord]) -> bool {
    current_record(records, record.network, &record.txid)
        .is_some_and(|current| current.entry_id == record.entry_id)
}

/// The originals `txid` replaces on `network`, nearest first: its `replaces`, that record's
/// `replaces`, and so on while the journal has them (spec/08 §9 replacement chain).
#[must_use]
pub fn replacement_ancestors(records: &[BtcRecord], network: BtcNetwork, txid: &Txid) -> Vec<Txid> {
    let mut out: Vec<Txid> = Vec::new();
    let mut current = find(records, network, txid).and_then(|record| record.replaces);
    while let Some(original) = current {
        if original == *txid || out.contains(&original) {
            break;
        }
        out.push(original);
        current = find(records, network, &original).and_then(|record| record.replaces);
    }
    out
}

/// The in-flight replacements of `txid` on `network` (spec/08 §9, §12.2): every record that
/// replaces it directly or through other replacements and is in an in-flight state (§12.1:
/// `Signed`, `Broadcasting`, `Submitted`, `BroadcastUnknown`, `InMempool`). An indexer
/// `Confirmed` of `txid` would conflict them, so tracking applies it only when Core's
/// `getmempoolentry` answers `-5` for each of them ([`hold_confirmation`]).
#[must_use]
pub fn in_flight_replacements(
    records: &[BtcRecord],
    network: BtcNetwork,
    txid: &Txid,
) -> Vec<Txid> {
    let mut visited = vec![*txid];
    let mut frontier = vec![*txid];
    let mut out = Vec::new();
    while let Some(parent) = frontier.pop() {
        for record in of_network(records, network) {
            if record.replaces == Some(parent) && !visited.contains(&record.txid) {
                visited.push(record.txid);
                frontier.push(record.txid);
                if record.state.is_in_flight() {
                    out.push(record.txid);
                }
            }
        }
    }
    out
}

/// The pre-sign re-check of spec/08 §11.1 ("in-flight 재확인", §5 "같은 outpoint 재서명 거부"): a
/// send needs no in-flight record; a fee bump must replace the current bump target and may only
/// spend outpoints of that chain or free ones. The chain is the target and the originals it
/// replaces ([`replacement_ancestors`]): an original may still be in flight (e.g. `T` in
/// `InMempool` while its replacement `R1` ended `BroadcastUnknown`), and a bump of `R1` spends
/// `T`'s inputs by design (§9). Other in-flight records, including a `Signed`/`Broadcasting`
/// replacement of the target still under way, keep their inputs (D20: one chain).
///
/// # Errors
///
/// [`PlanError::InFlight`], [`PlanError::NotBumpable`], [`PlanError::InputInFlight`].
pub fn check_plan_allowed(records: &[BtcRecord], plan: &SendPlan) -> Result<(), PlanError> {
    let network = plan.network();
    let Some(replaces) = plan.replaces() else {
        check_can_send(records, network)?;
        let used = in_flight_outpoints(records, network);
        if plan
            .inputs()
            .iter()
            .any(|input| used.contains(&input.outpoint))
        {
            return Err(PlanError::InputInFlight);
        }
        return Ok(());
    };
    if bump_target(records, network).map(|record| record.txid) != Some(replaces) {
        return Err(PlanError::NotBumpable);
    }
    let mut chain = replacement_ancestors(records, network, &replaces);
    chain.push(replaces);
    let others: Vec<OutPoint> = of_network(records, network)
        .filter(|record| record.state.is_in_flight() && !chain.contains(&record.txid))
        .flat_map(|record| record.inputs.iter().map(|input| input.outpoint))
        .collect();
    if plan
        .inputs()
        .iter()
        .any(|input| others.contains(&input.outpoint))
    {
        return Err(PlanError::InputInFlight);
    }
    Ok(())
}

/// The pre-sign re-check of the abandon rule (spec/08 §12.1): a new send (not a fee bump) must
/// spend at least one input of every live `Abandoned` and disclosed `Rejected` record
/// ([`abandoned_conflicts`]), else both transactions could confirm and pay twice.
///
/// # Errors
///
/// [`PlanError::AbandonedNotConflicted`].
pub fn check_abandoned_conflicts(
    records: &[BtcRecord],
    plan: &SendPlan,
    now_unix: u64,
) -> Result<(), PlanError> {
    if plan.replaces().is_some() {
        return Ok(());
    }
    let spent: Vec<OutPoint> = plan.inputs().iter().map(|input| input.outpoint).collect();
    if abandoned_conflicts(records, plan.network(), now_unix)
        .iter()
        .all(|group| group.iter().any(|outpoint| spent.contains(outpoint)))
    {
        Ok(())
    } else {
        Err(PlanError::AbandonedNotConflicted)
    }
}

/// The startup floor of `change_next` (spec/08 §3.2): `max(change_index + 1)` over records of
/// `network` that reached `Broadcasting` or a later state, counting only change on `account`'s
/// change chain ([`BtcRecord::hd_change_index`]: change to the fixed address does not count).
#[must_use]
pub fn change_next_floor(
    records: &[BtcRecord],
    network: BtcNetwork,
    account: &BtcAccountKey,
) -> Option<u32> {
    of_network(records, network)
        .filter(|record| !matches!(record.state, BtcTxState::Signed | BtcTxState::Rejected))
        .filter_map(|record| record.hd_change_index(account))
        .filter_map(|index| index.checked_add(1))
        .max()
}

/// A transition the table refuses, or a missing record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TransitionError {
    /// No decodable BTC record with this txid on this network.
    UnknownTx,
    /// `from → to` is not in the §12.1 table.
    NotAllowed {
        /// Current state.
        from: BtcTxState,
        /// Requested state.
        to: BtcTxState,
    },
    /// The re-encoded record failed its own checks (never written).
    Encode(BtcRecordError),
}

impl fmt::Display for TransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnknownTx => "저널에 없는 거래입니다",
            Self::NotAllowed { .. } => "허용되지 않는 거래 상태 변경입니다",
            Self::Encode(_) => "저널 손상",
        })
    }
}

impl std::error::Error for TransitionError {}

/// Records whose state changed (the cascade included), in order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StateChange {
    /// `(txid, new state)`.
    pub changed: Vec<(Txid, BtcTxState)>,
}

impl StateChange {
    /// Whether anything changed (persist the journal).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.changed.is_empty()
    }
}

/// The working copy of a journal's BTC records.
struct Working {
    records: Vec<(usize, BtcRecord)>,
    dirty: Vec<bool>,
    change: StateChange,
}

impl Working {
    fn load(plain: &JournalPlain) -> Self {
        let records = BtcEntries::from_plain(plain).records;
        let dirty = vec![false; records.len()];
        Self {
            records,
            dirty,
            change: StateChange::default(),
        }
    }

    /// The current record of `txid` (the last in journal order, [`current_record`]).
    fn position(&self, network: BtcNetwork, txid: &Txid) -> Option<usize> {
        self.records
            .iter()
            .rposition(|(_, record)| record.network == network && record.txid == *txid)
    }

    /// The record with `entry_id` (unique: the approval id).
    fn position_entry(&self, network: BtcNetwork, entry_id: &[u8; 16]) -> Option<usize> {
        self.records
            .iter()
            .position(|(_, record)| record.network == network && record.entry_id == *entry_id)
    }

    fn mark_dirty(&mut self, position: usize) {
        if let Some(flag) = self.dirty.get_mut(position) {
            *flag = true;
        }
    }

    fn set(&mut self, position: usize, next: BtcTxState, now_unix: u64) -> bool {
        let Some((_, record)) = self.records.get_mut(position) else {
            return false;
        };
        // A `Rejected` record whose bytes the RPC never saw is final.
        if !record.state.can_transition_to(next)
            || (record.state == BtcTxState::Rejected && !record.disclosed)
        {
            return false;
        }
        record.state = next;
        record.updated_at_unix = now_unix;
        if next != BtcTxState::Confirmed {
            record.confirmed_height = None;
        }
        if let Some(flag) = self.dirty.get_mut(position) {
            *flag = true;
        }
        self.change.changed.push((record.txid, next));
        true
    }

    /// Side effects of `position` entering its current state: a replacement that reached the
    /// node replaces its original, and every earlier original of the chain that is still
    /// bumpable (an intermediate replacement may never have reached the node, so its original
    /// stayed in flight; spec/08 §9); a confirmed record conflicts every replacement of it.
    fn cascade(&mut self, position: usize, now_unix: u64) {
        let Some((_, record)) = self.records.get(position) else {
            return;
        };
        let (network, own_txid, state, replaces) =
            (record.network, record.txid, record.state, record.replaces);
        if matches!(
            state,
            BtcTxState::Submitted | BtcTxState::InMempool | BtcTxState::Confirmed
        ) {
            let mut child = own_txid;
            let mut current = replaces;
            let mut steps = self.records.len();
            while let Some(original) = current
                && steps > 0
            {
                steps = steps.saturating_sub(1);
                let Some(original_position) = self.position(network, &original) else {
                    break;
                };
                let (bumpable, next) = self
                    .records
                    .get(original_position)
                    .map_or((false, None), |(_, record)| {
                        (record.state.can_bump(), record.replaces)
                    });
                if bumpable
                    && self.set(original_position, BtcTxState::Replaced, now_unix)
                    && let Some((_, record)) = self.records.get_mut(original_position)
                {
                    record.replaced_by = Some(child);
                }
                child = original;
                current = next;
            }
        }
        if state == BtcTxState::Confirmed {
            let mut frontier = vec![own_txid];
            let mut visited = vec![own_txid];
            while let Some(parent) = frontier.pop() {
                let children: Vec<usize> = self
                    .records
                    .iter()
                    .enumerate()
                    .filter(|(_, (_, record))| {
                        record.network == network
                            && record.replaces == Some(parent)
                            && !visited.contains(&record.txid)
                    })
                    .map(|(child, _)| child)
                    .collect();
                for child in children {
                    let Some(txid) = self.records.get(child).map(|(_, record)| record.txid) else {
                        continue;
                    };
                    visited.push(txid);
                    frontier.push(txid);
                    self.set(child, BtcTxState::Conflicted, now_unix);
                }
            }
            // Any other record spending one of the confirmed inputs can never confirm now: an
            // abandoned (or disclosed rejected) transaction a later send conflicted with, or
            // that later send when the abandoned one confirmed first (spec/08 §12.1). Originals
            // of the confirmed record are `Replaced` already (above) and stay so.
            let conflicting: Vec<usize> =
                self.records
                    .get(position)
                    .map_or_else(Vec::new, |(_, confirmed)| {
                        self.records
                            .iter()
                            .enumerate()
                            .filter(|(other, (_, record))| {
                                *other != position
                                    && record.network == network
                                    && (matches!(
                                        record.state,
                                        BtcTxState::Abandoned
                                            | BtcTxState::Submitted
                                            | BtcTxState::BroadcastUnknown
                                            | BtcTxState::InMempool
                                    ) || (record.state == BtcTxState::Rejected
                                        && record.disclosed))
                                    && record.shares_input(confirmed)
                            })
                            .map(|(other, _)| other)
                            .collect()
                    });
            for other in conflicting {
                self.set(other, BtcTxState::Conflicted, now_unix);
            }
        }
    }

    fn commit(self, plain: &mut JournalPlain) -> Result<StateChange, TransitionError> {
        let mut bodies = Vec::new();
        for ((entry_index, record), dirty) in self.records.iter().zip(&self.dirty) {
            if *dirty {
                bodies.push((
                    *entry_index,
                    record.encode().map_err(TransitionError::Encode)?,
                ));
            }
        }
        for (entry_index, body) in bodies {
            if let Some(entry) = plain.entries.get_mut(entry_index) {
                entry.body = body;
            }
        }
        Ok(self.change)
    }
}

/// Moves the record `txid` of `network` to `next` (spec/08 §12.1 table) and applies the
/// replacement bookkeeping: a replacement entering `Submitted`/`InMempool`/`Confirmed` turns
/// its original (and every earlier original of its chain still in a bumpable state) into
/// `Replaced{by}`; a record entering `Confirmed` turns its replacements into
/// `Conflicted`. `Confirmed` needs [`apply_observation`] (it carries the height); `Replaced` and
/// `Conflicted` only result from that bookkeeping. `Abandoned` also needs
/// [`BtcRecord::can_abandon`] (a `BroadcastUnknown` record only after `not_found_count >= 10`).
///
/// # Errors
///
/// [`TransitionError`]; `plain` is unchanged on error.
pub fn set_state(
    plain: &mut JournalPlain,
    network: BtcNetwork,
    txid: &Txid,
    next: BtcTxState,
    now_unix: u64,
) -> Result<StateChange, TransitionError> {
    let working = Working::load(plain);
    let position = working
        .position(network, txid)
        .ok_or(TransitionError::UnknownTx)?;
    transition(plain, working, position, next, now_unix)
}

/// [`set_state`] of the record with `entry_id` (the approval id; unique in the journal). The
/// key worker resolves a step's record once and addresses it by `entry_id` from then on, so a
/// check and its transition always concern the same record.
///
/// # Errors
///
/// As [`set_state`] (`UnknownTx` for an unknown `entry_id`).
pub fn set_state_entry(
    plain: &mut JournalPlain,
    network: BtcNetwork,
    entry_id: &[u8; 16],
    next: BtcTxState,
    now_unix: u64,
) -> Result<StateChange, TransitionError> {
    let working = Working::load(plain);
    let position = working
        .position_entry(network, entry_id)
        .ok_or(TransitionError::UnknownTx)?;
    transition(plain, working, position, next, now_unix)
}

fn transition(
    plain: &mut JournalPlain,
    mut working: Working,
    position: usize,
    next: BtcTxState,
    now_unix: u64,
) -> Result<StateChange, TransitionError> {
    let (from, abandonable) = working
        .records
        .get(position)
        .map(|(_, record)| (record.state, record.can_abandon()))
        .ok_or(TransitionError::UnknownTx)?;
    let cascade_only = matches!(
        next,
        BtcTxState::Confirmed | BtcTxState::Replaced | BtcTxState::Conflicted
    ) || (from == BtcTxState::Confirmed);
    let refused_abandon = next == BtcTxState::Abandoned && !abandonable;
    if cascade_only || refused_abandon || !working.set(position, next, now_unix) {
        return Err(TransitionError::NotAllowed { from, to: next });
    }
    working.cascade(position, now_unix);
    working.commit(plain)
}

/// Startup normalization (spec/08 §12.1): every `Broadcasting` record becomes
/// `BroadcastUnknown`. (`Signed` records are offered [전송 계속] / [취소] by the app.)
///
/// # Errors
///
/// [`TransitionError::Encode`] (defensive).
pub fn normalize_on_startup(
    plain: &mut JournalPlain,
    now_unix: u64,
) -> Result<StateChange, TransitionError> {
    let mut working = Working::load(plain);
    for position in 0..working.records.len() {
        if working
            .records
            .get(position)
            .is_some_and(|(_, record)| record.state == BtcTxState::Broadcasting)
        {
            working.set(position, BtcTxState::BroadcastUnknown, now_unix);
        }
    }
    working.commit(plain)
}

/// The indexer `TxStatus` result (spec/08 §4.3 `TxSeen`), mapped by the app's indexer parser.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TxSeen {
    /// Confirmed at `height`.
    Confirmed {
        /// Block height.
        height: u32,
    },
    /// Unconfirmed (Blockbook `confirmations == 0`).
    Unconfirmed,
    /// Not found (404, Blockbook not-found error).
    NotFound,
    /// Esplora `{"confirmed":false}`: also returned for unknown txids.
    UnconfirmedOrUnknown,
}

/// One tracking round's raw inputs (spec/08 §12.2 steps 1–2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TrackInput {
    /// Step 1: `getmempoolentry` returned an object.
    MempoolEntry,
    /// Step 1 returned `-5` (or the record is tracked by step 2 only); step 2's indexer
    /// `TxStatus`, plus the Esplora `TxRaw` probe when the status was ambiguous.
    NotInMempool {
        /// `TxStatus`.
        indexer: TxSeen,
        /// `TxRaw` probe result, if made.
        raw_found: Option<bool>,
    },
    /// The endpoint has no `getmempoolentry` (§4.5 C2): step 2 only, plus the Esplora `TxRaw`
    /// probe (`Some(true)` = 200, `Some(false)` = 404) when the status was ambiguous.
    NoMempoolRpc {
        /// `TxStatus`.
        indexer: TxSeen,
        /// `TxRaw` probe result, if made.
        raw_found: Option<bool>,
    },
}

/// What a tracking round observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TrackObservation {
    /// In the mempool (server based).
    InMempool,
    /// Confirmed at `height`.
    Confirmed {
        /// Block height.
        height: u32,
    },
    /// Not found: `not_found_count + 1`.
    NotFound,
    /// Ambiguous Esplora status without `getmempoolentry`: make the `TxRaw` probe and call
    /// [`observe`] again with `raw_found`.
    NeedRawProbe,
    /// An indexer `Confirmed` held back this round because Core still has an in-flight
    /// replacement of the record in its mempool ([`hold_confirmation`]): changes nothing.
    Deferred,
}

/// The §12.2 decision of one round. An indexer that still sees the transaction unconfirmed
/// (Blockbook `confirmations == 0`, or an ambiguous Esplora `{"confirmed":false}` whose `TxRaw`
/// probe answers 200) counts as "in a mempool" even when Core's mempool lacks it: the
/// transaction is still propagating somewhere, so the round must not count towards [포기].
#[must_use]
pub const fn observe(input: TrackInput) -> TrackObservation {
    let (indexer, raw_found) = match input {
        TrackInput::MempoolEntry => return TrackObservation::InMempool,
        TrackInput::NotInMempool { indexer, raw_found }
        | TrackInput::NoMempoolRpc { indexer, raw_found } => (indexer, raw_found),
    };
    match (indexer, raw_found) {
        (TxSeen::Confirmed { height }, _) => TrackObservation::Confirmed { height },
        (TxSeen::Unconfirmed, _) | (TxSeen::UnconfirmedOrUnknown, Some(true)) => {
            TrackObservation::InMempool
        }
        (TxSeen::NotFound, _) | (TxSeen::UnconfirmedOrUnknown, Some(false)) => {
            TrackObservation::NotFound
        }
        (TxSeen::UnconfirmedOrUnknown, None) => TrackObservation::NeedRawProbe,
    }
}

/// The replacement guard of spec/08 §12.2: confirming a record conflicts its in-flight
/// replacements ([`in_flight_replacements`]), so an indexer `Confirmed` is applied only when
/// Core's `getmempoolentry` answered `-5` for each of them. When one is still in the Core
/// mempool (`replacement_in_mempool`) the confirmation is held back this round
/// ([`TrackObservation::Deferred`]); every other observation passes unchanged. (Without
/// `getmempoolentry`, §4.5 C2, there is no Core answer and tracking stays server based.)
#[must_use]
pub const fn hold_confirmation(
    observation: TrackObservation,
    replacement_in_mempool: bool,
) -> TrackObservation {
    match observation {
        TrackObservation::Confirmed { .. } if replacement_in_mempool => TrackObservation::Deferred,
        other => other,
    }
}

/// How a record is tracked now (spec/08 §12.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TrackMode {
    /// Steps 1–2 every 60 s (`Submitted`, `BroadcastUnknown`, `InMempool`).
    Full,
    /// Step 2 only (`Replaced` until its replacement confirms, `Abandoned` and disclosed
    /// `Rejected` within 30 days).
    ConfirmationOnly,
    /// Not tracked.
    None,
}

fn chain_end_finished(
    record: &BtcRecord,
    records: &[BtcRecord],
    tip_height: Option<u32>,
    now_unix: u64,
) -> bool {
    let mut current = record.replaced_by;
    for _ in 0..records.len().saturating_add(1) {
        let Some(txid) = current else {
            return true;
        };
        let Some(next) = find(records, record.network, &txid) else {
            return true;
        };
        match next.state {
            BtcTxState::Confirmed => {
                return tip_height
                    .is_none_or(|tip| next.confirmations(tip) >= BTC_FINAL_CONFIRMATIONS);
            }
            BtcTxState::Replaced => current = next.replaced_by,
            // A replacement that was given up: the original may still confirm within the
            // replacement's 30-day window, not longer.
            BtcTxState::Abandoned => {
                return now_unix.saturating_sub(next.updated_at_unix) > BTC_ABANDON_WINDOW_SECS;
            }
            BtcTxState::Rejected | BtcTxState::Conflicted => return true,
            BtcTxState::Signed
            | BtcTxState::Broadcasting
            | BtcTxState::Submitted
            | BtcTxState::BroadcastUnknown
            | BtcTxState::InMempool => return false,
        }
    }
    true
}

/// Whether tracking of `record` is over (spec/08 §12.4 "추적이 끝난 항목"): `Rejected` (a
/// disclosed one only after 30 days, like `Abandoned`), `Conflicted`, `Confirmed` (one
/// confirmation is final, [`BTC_FINAL_CONFIRMATIONS`]), `Replaced` whose replacement chain ends
/// confirmed, rejected, conflicted, missing, or abandoned more than 30 days ago, `Abandoned`
/// older than 30 days. `tip_height` is `None` for records of another network (not queried any
/// more: `Confirmed` counts as finished); a tip below the confirmation height (a lagging or
/// garbage tip) does not finish a `Confirmed` record.
#[must_use]
pub fn is_finished(
    record: &BtcRecord,
    records: &[BtcRecord],
    tip_height: Option<u32>,
    now_unix: u64,
) -> bool {
    match record.state {
        BtcTxState::Conflicted => true,
        BtcTxState::Confirmed => {
            tip_height.is_none_or(|tip| record.confirmations(tip) >= BTC_FINAL_CONFIRMATIONS)
        }
        BtcTxState::Replaced => chain_end_finished(record, records, tip_height, now_unix),
        BtcTxState::Rejected if !record.disclosed => true,
        BtcTxState::Rejected | BtcTxState::Abandoned => {
            now_unix.saturating_sub(record.updated_at_unix) > BTC_ABANDON_WINDOW_SECS
        }
        BtcTxState::Signed
        | BtcTxState::Broadcasting
        | BtcTxState::Submitted
        | BtcTxState::BroadcastUnknown
        | BtcTxState::InMempool => false,
    }
}

/// The tracking mode of `record` at `tip_height`.
#[must_use]
pub fn track_mode(
    record: &BtcRecord,
    records: &[BtcRecord],
    tip_height: u32,
    now_unix: u64,
) -> TrackMode {
    if is_finished(record, records, Some(tip_height), now_unix) {
        return TrackMode::None;
    }
    match record.state {
        BtcTxState::Submitted | BtcTxState::BroadcastUnknown | BtcTxState::InMempool => {
            TrackMode::Full
        }
        // A `Rejected` record that is not finished is a disclosed one within 30 days.
        BtcTxState::Confirmed
        | BtcTxState::Replaced
        | BtcTxState::Abandoned
        | BtcTxState::Rejected => TrackMode::ConfirmationOnly,
        BtcTxState::Signed | BtcTxState::Broadcasting | BtcTxState::Conflicted => TrackMode::None,
    }
}

/// Applies one tracking observation to record `txid` (spec/08 §12.2): `InMempool` moves
/// `Submitted`/`BroadcastUnknown` to `InMempool` and resets `not_found_count`, and moves a
/// `Confirmed` record back to `InMempool` (only reachable if a caller still tracks one; tracking
/// stops at the first confirmation); `Confirmed` (with at least 1 confirmation at
/// `tip_height`) confirms `Submitted`/`BroadcastUnknown`/`InMempool`/`Replaced`, an `Abandoned`
/// or disclosed `Rejected` record within 30 days, or updates a `Confirmed` height, conflicting every replacement and
/// every other record spending one of its inputs; `NotFound` increments `not_found_count` of a
/// `Submitted`/`InMempool`/`BroadcastUnknown`/`Confirmed` record and turns it into
/// `BroadcastUnknown` at 10 (a `Confirmed` record that vanished was reorganized out).
/// `Deferred` and other combinations change nothing. (The caller passes a `Confirmed` of a
/// record with in-flight replacements through [`hold_confirmation`] first.)
///
/// # Errors
///
/// [`TransitionError::UnknownTx`], [`TransitionError::Encode`].
pub fn apply_observation(
    plain: &mut JournalPlain,
    network: BtcNetwork,
    txid: &Txid,
    observation: TrackObservation,
    tip_height: u32,
    now_unix: u64,
) -> Result<StateChange, TransitionError> {
    let mut working = Working::load(plain);
    let position = working
        .position(network, txid)
        .ok_or(TransitionError::UnknownTx)?;
    let Some((_, record)) = working.records.get_mut(position) else {
        return Err(TransitionError::UnknownTx);
    };
    let state = record.state;
    match observation {
        TrackObservation::InMempool => {
            if matches!(
                state,
                BtcTxState::Submitted
                    | BtcTxState::BroadcastUnknown
                    | BtcTxState::InMempool
                    | BtcTxState::Confirmed
            ) && record.not_found_count != 0
            {
                record.not_found_count = 0;
                record.updated_at_unix = now_unix;
                working.mark_dirty(position);
            }
            if matches!(
                state,
                BtcTxState::Submitted | BtcTxState::BroadcastUnknown | BtcTxState::Confirmed
            ) && working.set(position, BtcTxState::InMempool, now_unix)
            {
                working.cascade(position, now_unix);
            }
        }
        TrackObservation::Confirmed { height } => {
            if height == 0 || conf(height, tip_height) == 0 {
                return working.commit(plain);
            }
            let within_window =
                now_unix.saturating_sub(record.updated_at_unix) <= BTC_ABANDON_WINDOW_SECS;
            match state {
                BtcTxState::Confirmed => {
                    if record.confirmed_height != Some(height) || record.not_found_count != 0 {
                        record.confirmed_height = Some(height);
                        record.not_found_count = 0;
                        record.updated_at_unix = now_unix;
                        working.mark_dirty(position);
                    }
                }
                BtcTxState::Abandoned if !within_window => {}
                BtcTxState::Rejected if !within_window || !record.disclosed => {}
                _ => {
                    if working.set(position, BtcTxState::Confirmed, now_unix) {
                        if let Some((_, record)) = working.records.get_mut(position) {
                            record.confirmed_height = Some(height);
                            record.not_found_count = 0;
                        }
                        working.cascade(position, now_unix);
                    }
                }
            }
        }
        TrackObservation::NotFound => {
            if matches!(
                state,
                BtcTxState::Submitted
                    | BtcTxState::InMempool
                    | BtcTxState::BroadcastUnknown
                    | BtcTxState::Confirmed
            ) {
                record.not_found_count = record.not_found_count.saturating_add(1);
                record.updated_at_unix = now_unix;
                let limit = record.not_found_count >= BTC_NOT_FOUND_LIMIT;
                working.mark_dirty(position);
                if limit && state != BtcTxState::BroadcastUnknown {
                    working.set(position, BtcTxState::BroadcastUnknown, now_unix);
                }
            }
        }
        TrackObservation::NeedRawProbe | TrackObservation::Deferred => {}
    }
    working.commit(plain)
}

/// A finished record as an `ActivityEntry` (spec/08 §12.3, spec/02 §5.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcActivityRow {
    /// Network (`activity["bitcoin:<net>"]`).
    pub network: BtcNetwork,
    /// `BtcAccountId::activity_tag`: `""` for BIP84 account 0, `p2tr/0`-style for other HD
    /// accounts, `imported/<id hex>` for imported keys.
    pub account: String,
    /// Display-order lowercase txid.
    pub tx_id: String,
    /// The approval title rebuilt from the record.
    pub title: String,
    /// `"native"`.
    pub asset: String,
    /// Recipient sats, decimal.
    pub amount: String,
    /// Recipient address (canonical).
    pub counterparty: String,
    /// `succeeded` / `rejected` / `replaced` / `conflicted` / `abandoned`.
    pub status: &'static str,
    /// Observation time of the end of tracking.
    pub time_unix_ms: u64,
}

/// The activity row of a record in a row-producing state.
#[must_use]
pub fn activity_row(record: &BtcRecord, time_unix_ms: u64) -> Option<BtcActivityRow> {
    Some(BtcActivityRow {
        network: record.network,
        account: record.account.activity_tag(),
        tx_id: record.txid.to_display_hex(),
        title: record.title(),
        asset: "native".to_owned(),
        amount: record.recipient_amount()?.get().to_string(),
        counterparty: record.recipient_address()?,
        status: record.state.activity_status()?,
        time_unix_ms,
    })
}

fn tip_for(record: &BtcRecord, network: BtcNetwork, tip_height: u32) -> Option<u32> {
    (record.network == network).then_some(tip_height)
}

/// Activity rows of every finished BTC record (write them to meta, overwriting by `tx_id`,
/// when they finish; spec/08 §12.4). `tip_height` is the current network's tip. A superseded
/// duplicate of an old journal ([`current_record`]) produces no row.
#[must_use]
pub fn finished_rows(
    plain: &JournalPlain,
    network: BtcNetwork,
    tip_height: u32,
    now_unix: u64,
    time_unix_ms: u64,
) -> Vec<BtcActivityRow> {
    let records = BtcEntries::from_plain(plain).records();
    records
        .iter()
        .filter(|record| {
            is_current(record, &records)
                && is_finished(
                    record,
                    &records,
                    tip_for(record, network, tip_height),
                    now_unix,
                )
        })
        .filter_map(|record| activity_row(record, time_unix_ms))
        .collect()
}

/// The activity row of a removed finished record, `None` for a superseded duplicate.
fn removed_row(
    record: &BtcRecord,
    records: &[BtcRecord],
    time_unix_ms: u64,
) -> Option<BtcActivityRow> {
    if is_current(record, records) {
        activity_row(record, time_unix_ms)
    } else {
        None
    }
}

/// Finished records, oldest first (`created_at_unix`, `updated_at_unix`, `entry_id`).
fn finished_oldest_first(
    plain: &JournalPlain,
    network: BtcNetwork,
    tip_height: u32,
    now_unix: u64,
) -> Vec<BtcRecord> {
    let records = BtcEntries::from_plain(plain).records();
    let mut finished: Vec<BtcRecord> = records
        .iter()
        .filter(|record| {
            is_finished(
                record,
                &records,
                tip_for(record, network, tip_height),
                now_unix,
            )
        })
        .cloned()
        .collect();
    finished.sort_by_key(|record| {
        (
            record.created_at_unix,
            record.updated_at_unix,
            record.entry_id,
        )
    });
    finished
}

fn remove_record(plain: &mut JournalPlain, record: &BtcRecord) -> bool {
    let mut removed = false;
    plain.entries.retain(|entry| {
        if removed || entry.kind != EntryKind::Btc {
            return true;
        }
        match BtcRecord::decode(&entry.body) {
            Ok(decoded) if decoded.entry_id == record.entry_id && decoded.txid == record.txid => {
                removed = true;
                false
            }
            _ => true,
        }
    });
    removed
}

/// Keeps at most `BTC_JOURNAL_FINAL_KEEP` (64) finished BTC records: removes the oldest beyond
/// that and returns their activity rows. The caller writes the rows to meta first, then
/// commits the journal (meta write → journal delete). Tracked records are never removed;
/// undecodable entries are kept.
pub fn prune_finished(
    plain: &mut JournalPlain,
    network: BtcNetwork,
    tip_height: u32,
    now_unix: u64,
    time_unix_ms: u64,
) -> Vec<BtcActivityRow> {
    let records = BtcEntries::from_plain(plain).records();
    let finished = finished_oldest_first(plain, network, tip_height, now_unix);
    let excess = finished.len().saturating_sub(BTC_JOURNAL_FINAL_KEEP);
    let mut rows = Vec::new();
    for record in finished.iter().take(excess) {
        if remove_record(plain, record)
            && let Some(row) = removed_row(record, &records, time_unix_ms)
        {
            rows.push(row);
        }
    }
    rows
}

/// The pre-add check for a new `Signed` record (spec/02 §5.4): `entry_count + 1 <= 256` and
/// `plaintext + 5 + 37,924 <= 16 MiB`.
#[must_use]
pub fn has_room(plain: &JournalPlain) -> bool {
    plain.entries.len() < MAX_ENTRIES
        && plain
            .plaintext_len()
            .saturating_add(ENTRY_HEADER_LEN)
            .saturating_add(BTC_JOURNAL_MAX_BODY)
            <= MAX_PLAINTEXT
}

/// The pre-add clean-up: without room, removes finished BTC records oldest first until there
/// is room, returning their activity rows (write them to meta before committing). Other
/// chains' entries and tracked records are never removed.
///
/// # Errors
///
/// [`JournalError::Full`] when even every finished BTC record is not enough (`plain`
/// unchanged): no signing, no sending.
pub fn make_room(
    plain: &mut JournalPlain,
    network: BtcNetwork,
    tip_height: u32,
    now_unix: u64,
    time_unix_ms: u64,
) -> Result<Vec<BtcActivityRow>, JournalError> {
    if has_room(plain) {
        return Ok(Vec::new());
    }
    let records = BtcEntries::from_plain(plain).records();
    let mut trial = plain.clone();
    let mut rows = Vec::new();
    for record in finished_oldest_first(&trial, network, tip_height, now_unix) {
        if remove_record(&mut trial, &record)
            && let Some(row) = removed_row(&record, &records, time_unix_ms)
        {
            rows.push(row);
        }
        if has_room(&trial) {
            *plain = trial;
            return Ok(rows);
        }
    }
    Err(JournalError::Full)
}

/// Why a new record was not added.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BtcPushError {
    /// No room ([`JournalError::Full`]), or the record does not encode.
    Full,
    /// A record with the same txid exists on the network and is still tracked (or, for
    /// [`push_record`], exists at all: call [`take_finished_duplicates`] first).
    Duplicate,
}

impl fmt::Display for BtcPushError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Full => "거래 저널 공간이 부족합니다",
            Self::Duplicate => "같은 거래가 이미 저널에 있습니다. 그 거래의 상태를 확인하세요",
        })
    }
}

impl std::error::Error for BtcPushError {}

impl From<JournalError> for BtcPushError {
    fn from(error: JournalError) -> Self {
        match error {
            JournalError::Full => Self::Full,
        }
    }
}

/// Before adding `record` (spec/08 §12.4 "txid 중복"): finished records with the same txid on
/// its network (e.g. a pre-check `Rejected` transaction signed again byte for byte: same
/// inputs, outputs and lock time) and `Abandoned` or disclosed `Rejected` ones (the new record
/// tracks the same transaction; [`disclosed_duplicate`] says whether to mark it disclosed) are
/// removed from `plain` and their activity rows returned (write them to meta
/// before committing the journal). Any other tracked one (in flight, `Confirmed` above the tip,
/// `Replaced`) refuses the new record and leaves `plain` unchanged.
///
/// # Errors
///
/// [`BtcPushError::Duplicate`].
pub fn take_finished_duplicates(
    plain: &mut JournalPlain,
    record: &BtcRecord,
    tip_height: u32,
    now_unix: u64,
    time_unix_ms: u64,
) -> Result<Vec<BtcActivityRow>, BtcPushError> {
    let records = BtcEntries::from_plain(plain).records();
    let same: Vec<&BtcRecord> = records
        .iter()
        .filter(|old| old.network == record.network && old.txid == record.txid)
        .collect();
    // An `Abandoned` or (disclosed) `Rejected` record is superseded too: the new record tracks
    // the very same transaction (same txid, same inputs), so nothing can confirm twice.
    if same.iter().any(|old| {
        !matches!(old.state, BtcTxState::Abandoned | BtcTxState::Rejected)
            && !is_finished(old, &records, Some(tip_height), now_unix)
    }) {
        return Err(BtcPushError::Duplicate);
    }
    let mut trial = plain.clone();
    let mut rows = Vec::new();
    for old in same {
        if remove_record(&mut trial, old)
            && let Some(row) = removed_row(old, &records, time_unix_ms)
        {
            rows.push(row);
        }
    }
    *plain = trial;
    Ok(rows)
}

/// Whether a record with `record`'s txid on its network already had its bytes handed to the
/// RPC ([`flags::DISCLOSED`]) or reached the network: the same transaction signed again is
/// disclosed from the start, so cancelling it still constrains the next send. Call before
/// [`take_finished_duplicates`] removes the old record.
#[must_use]
pub fn disclosed_duplicate(plain: &JournalPlain, record: &BtcRecord) -> bool {
    BtcEntries::from_plain(plain)
        .records
        .iter()
        .any(|(_, old)| {
            old.network == record.network
                && old.txid == record.txid
                && (old.disclosed
                    || match old.state {
                        BtcTxState::Signed | BtcTxState::Rejected => false,
                        BtcTxState::Abandoned => old.not_found_count >= BTC_NOT_FOUND_LIMIT,
                        BtcTxState::Broadcasting
                        | BtcTxState::Submitted
                        | BtcTxState::BroadcastUnknown
                        | BtcTxState::InMempool
                        | BtcTxState::Confirmed
                        | BtcTxState::Replaced
                        | BtcTxState::Conflicted => true,
                    })
        })
}

/// Adds a record as a new BTC entry. A txid is unique per network in the journal: transitions
/// and observations address a record by it.
///
/// # Errors
///
/// [`BtcPushError::Full`] when it does not fit (call [`make_room`] first) or does not encode,
/// [`BtcPushError::Duplicate`] when a record with the same txid exists (call
/// [`take_finished_duplicates`] first).
pub fn push_record(plain: &mut JournalPlain, record: &BtcRecord) -> Result<(), BtcPushError> {
    if !has_room(plain) {
        return Err(BtcPushError::Full);
    }
    if BtcEntries::from_plain(plain)
        .records
        .iter()
        .any(|(_, old)| old.network == record.network && old.txid == record.txid)
    {
        return Err(BtcPushError::Duplicate);
    }
    let body = record.encode().map_err(|_| BtcPushError::Full)?;
    plain.entries.push(Entry {
        kind: EntryKind::Btc,
        body,
    });
    Ok(())
}

/// Records the outcome class of the last Core `sendrawtransaction` of the record `entry_id`
/// (flags bit6): `true` after a communication failure (timeout, transport, HTTP 5xx, 429
/// abort), `false` after any answer of the node. Kept across restarts so the manual Esplora
/// broadcast (spec/08 §11.3) stays offered. Returns whether the journal changed.
///
/// # Errors
///
/// [`TransitionError::UnknownTx`], [`TransitionError::Encode`].
pub fn set_last_send_comm_failure(
    plain: &mut JournalPlain,
    network: BtcNetwork,
    entry_id: &[u8; 16],
    comm_failure: bool,
) -> Result<bool, TransitionError> {
    let mut working = Working::load(plain);
    let position = working
        .position_entry(network, entry_id)
        .ok_or(TransitionError::UnknownTx)?;
    let Some((_, record)) = working.records.get_mut(position) else {
        return Err(TransitionError::UnknownTx);
    };
    if record.last_send_comm_failure == comm_failure {
        return Ok(false);
    }
    record.last_send_comm_failure = comm_failure;
    working.mark_dirty(position);
    working.commit(plain).map(|_| true)
}

/// Marks the record `entry_id` as disclosed (flags bit7): written to the journal before the
/// first `testmempoolaccept` / `sendrawtransaction` of its bytes, so a crash, a `Rejected`
/// answer or a later [취소] still knows the RPC may have them (spec/08 §11.3, §12.1). Never
/// cleared. Returns whether the journal changed.
///
/// # Errors
///
/// [`TransitionError::UnknownTx`], [`TransitionError::Encode`].
pub fn set_disclosed(
    plain: &mut JournalPlain,
    network: BtcNetwork,
    entry_id: &[u8; 16],
) -> Result<bool, TransitionError> {
    let mut working = Working::load(plain);
    let position = working
        .position_entry(network, entry_id)
        .ok_or(TransitionError::UnknownTx)?;
    let Some((_, record)) = working.records.get_mut(position) else {
        return Err(TransitionError::UnknownTx);
    };
    if record.disclosed {
        return Ok(false);
    }
    record.disclosed = true;
    working.mark_dirty(position);
    working.commit(plain).map(|_| true)
}
