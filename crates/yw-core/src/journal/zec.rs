//! ZEC journal records (spec/12 §12, `kind 0x04` entries of spec/02 §5.4): "record first, send
//! later", the one-in-flight rule per account and the disclosed-transaction rule (inputs of a
//! transaction that was handed to a node stay reserved until it is mined or provably expired).
//!
//! Zcash transactions carry `nExpiryHeight`: once the tip is above it and the transaction is not
//! mined, it can never be mined (ZIP 203). That is the only way a disclosed record ends without
//! confirming, so there is no "abandon" action as in Bitcoin.
#![deny(clippy::indexing_slicing)]

use core::fmt;

use super::{
    ENTRY_HEADER_LEN, Entry, EntryKind, JournalError, JournalPlain, MAX_ENTRIES, MAX_PLAINTEXT,
};
use crate::lang::Lang;
use crate::zec::account::{ZecAccount, ZecKeySource};
use crate::zec::address::ZecDest;
use crate::zec::network::ZecNetwork;
use crate::zec::plan::{ZecPlan, ZecUtxo};
use crate::zec::sign::ZecSignedTx;
use crate::zec::tx::{ZecOutPoint, ZecTx, parse_tx, txid, txid_display};
use crate::zec::{ZEC_JOURNAL_FINAL_KEEP, ZEC_MAX_INPUTS, ZEC_MAX_JOURNAL_RAW};

/// `record_kind` (fixed).
pub const RECORD_KIND: u8 = 0x04;
/// `record_version` of every record whose key is not an added mnemonic's (unchanged layout).
pub const RECORD_VERSION: u8 = 1;
/// `record_version` of an added mnemonic's account (source code 5, spec/02 §8.6): the version 1
/// header, then the 16-byte mnemonic record id, then the transaction. Earlier builds treat it as
/// a damaged body (ZEC sending stops, the bytes are kept; spec/04 §6.6).
pub const RECORD_VERSION_V2: u8 = 2;
/// Fixed header length.
pub const ZEC_JOURNAL_HEADER_LEN: usize = 135;
/// The mnemonic record id of a version 2 record.
pub const ZEC_JOURNAL_MNEMONIC_LEN: usize = 16;
/// Largest ZEC body (version 2).
pub const ZEC_JOURNAL_MAX_BODY: usize =
    ZEC_JOURNAL_HEADER_LEN + ZEC_JOURNAL_MNEMONIC_LEN + ZEC_MAX_JOURNAL_RAW;
/// ZEC records in the journal.
pub const ZEC_JOURNAL_MAX_RECORDS: usize = 80;

/// Record state (spec/12 §12.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ZecTxState {
    /// Signed and journaled, not yet handed to a node.
    Signed = 1,
    /// Handed to the node (`sendrawtransaction` accepted, or the answer was lost).
    Broadcast = 2,
    /// Mined (terminal).
    Confirmed = 3,
    /// The tip passed `nExpiryHeight` without the transaction being mined (terminal).
    Expired = 4,
    /// The node refused it (`-25`/`-26`): not relayed by that node, but disclosed, so it stays
    /// "may still confirm" until it expires.
    Rejected = 5,
    /// Never handed to any node and discarded (terminal; e.g. the send was cancelled after
    /// signing because the node check failed).
    Discarded = 6,
    /// Past the expiry margin the node does not know it, but none of its inputs is unspent any
    /// more: it may have been mined (a node without that transaction indexed) or the inputs went
    /// elsewhere (terminal, no resend; its inputs stay reserved — spec/12 §12.2).
    InputsSpent = 7,
}

impl ZecTxState {
    /// Parses the state byte.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::Signed,
            2 => Self::Broadcast,
            3 => Self::Confirmed,
            4 => Self::Expired,
            5 => Self::Rejected,
            6 => Self::Discarded,
            7 => Self::InputsSpent,
            _ => return None,
        })
    }

    /// Terminal: nothing about this record can change any more.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Confirmed | Self::Expired | Self::Discarded | Self::InputsSpent
        )
    }

    /// Display label in `lang`.
    #[must_use]
    pub const fn label_in(self, lang: Lang) -> &'static str {
        match self {
            Self::Signed => text::STATE_SIGNED,
            Self::Broadcast => text::STATE_BROADCAST,
            Self::Confirmed => text::STATE_CONFIRMED,
            Self::Expired => text::STATE_EXPIRED,
            Self::Rejected => text::STATE_REJECTED,
            Self::Discarded => text::STATE_DISCARDED,
            Self::InputsSpent => text::STATE_INPUTS_SPENT,
        }
        .get(lang)
    }

    /// Fixed name for logs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Signed => "Signed",
            Self::Broadcast => "Broadcast",
            Self::Confirmed => "Confirmed",
            Self::Expired => "Expired",
            Self::Rejected => "Rejected",
            Self::Discarded => "Discarded",
            Self::InputsSpent => "InputsSpent",
        }
    }
}

/// The fixed texts of ZEC journal records (spec/12, spec/14).
pub mod text {
    crate::texts! {
        /// `ZecTxState::label_in`.
        STATE_SIGNED = "서명됨 (전송 전)" / "Signed (not sent yet)";
        STATE_BROADCAST = "전송됨 (확인 대기)" / "Sent (awaiting confirmation)";
        STATE_CONFIRMED = "확인됨" / "Confirmed";
        STATE_EXPIRED = "만료됨 (포함되지 않음)" / "Expired (not included)";
        STATE_REJECTED = "노드가 거부함 (만료까지 대기)" / "Rejected by the node (waiting for expiry)";
        STATE_DISCARDED = "폐기됨 (전송 안 함)" / "Discarded (not sent)";
        STATE_INPUTS_SPENT = "입력이 사용됨 — 포함되었을 수 있음"
            / "Inputs spent — it may have been included";
        /// `ZecRecordError`.
        CORRUPT = "저널 손상" / "Journal damaged";
        /// `ZecJournalBlock::text_in`.
        BLOCK_CORRUPT = "Zcash 거래 저널이 손상되어 보내기를 막았습니다."
            / "The Zcash transaction journal is damaged, so sending is blocked.";
        BLOCK_IN_FLIGHT = "이 계정의 이전 Zcash 거래가 아직 확인되지 않았습니다. 확인되거나 만료된 뒤에 다시 보내세요."
            / "A previous Zcash transaction from this account is not confirmed yet. Send again after it confirms or expires.";
        BLOCK_FULL = "거래 저널 공간이 부족합니다." / "The transaction journal is full.";
    }
}

/// A body the ZEC decoder rejects ("저널 손상": ZEC sending stops, the bytes are kept).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZecRecordError {
    /// Lengths.
    Length,
    /// `record_kind` / `record_version`.
    Header,
    /// Unknown state, network or source.
    Value,
    /// The transaction does not parse, or is not this record's (key, expiry, amounts).
    Tx,
}

impl ZecRecordError {
    /// The fixed text in `lang` (`Display` is the Korean one).
    #[must_use]
    #[expect(
        clippy::unused_self,
        reason = "every damaged ZEC record shows the same text"
    )]
    pub const fn text_in(self, lang: Lang) -> &'static str {
        text::CORRUPT.get(lang)
    }
}

impl fmt::Display for ZecRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.text_in(Lang::Ko))
    }
}

impl std::error::Error for ZecRecordError {}

/// One ZEC journal record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZecRecord {
    /// State.
    pub state: ZecTxState,
    /// Account (network, key source, public key).
    pub account: ZecAccount,
    /// Consumed approval id.
    pub approval_id: [u8; 16],
    /// Consumed approval digest.
    pub approval_digest: [u8; 32],
    /// Wall-clock Unix ms of signing.
    pub signed_at_ms: u64,
    /// The transaction was handed to a node at least once (possibly lost answer).
    pub disclosed: bool,
    /// Mined height (0 unless `Confirmed`).
    pub mined_height: u32,
    /// Consecutive "not found" answers while `Broadcast`.
    pub not_found: u16,
    /// Amount to the recipient (zatoshis).
    pub amount: u64,
    /// Fee (zatoshis).
    pub fee: u64,
    /// Sum of the inputs (zatoshis).
    pub input_total: u64,
    /// Signed transaction bytes.
    pub raw: Vec<u8>,
}

fn be_u16(body: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(array::<2>(body, at)?))
}

fn be_u32(body: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(array::<4>(body, at)?))
}

fn be_u64(body: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_be_bytes(array::<8>(body, at)?))
}

fn array<const N: usize>(body: &[u8], at: usize) -> Option<[u8; N]> {
    let end = at.checked_add(N)?;
    body.get(at..end)?.try_into().ok()
}

impl ZecRecord {
    /// The `Signed` record of a freshly signed, verified plan.
    #[must_use]
    pub fn new_signed(plan: &ZecPlan, signed: &ZecSignedTx, signed_at_ms: u64) -> Self {
        Self {
            state: ZecTxState::Signed,
            account: plan.account,
            approval_id: signed.approval_id.0,
            approval_digest: signed.approval_digest,
            signed_at_ms,
            disclosed: false,
            mined_height: 0,
            not_found: 0,
            amount: plan.amount,
            fee: plan.fee,
            input_total: plan.input_total(),
            raw: signed.raw.clone(),
        }
    }

    /// The parsed transaction (always `Ok` for a decoded record).
    ///
    /// # Errors
    ///
    /// [`ZecRecordError::Tx`].
    pub fn tx(&self) -> Result<ZecTx, ZecRecordError> {
        parse_tx(&self.raw).map_err(|_| ZecRecordError::Tx)
    }

    /// The txid (internal order).
    #[must_use]
    pub fn txid(&self) -> [u8; 32] {
        self.tx().map_or([0; 32], |tx| txid(&tx))
    }

    /// The txid as display hex.
    #[must_use]
    pub fn txid_hex(&self) -> String {
        txid_display(&self.txid())
    }

    /// `nExpiryHeight`.
    #[must_use]
    pub fn expiry_height(&self) -> u32 {
        self.tx().map_or(0, |tx| tx.expiry_height)
    }

    /// The outpoints this record spends.
    #[must_use]
    pub fn inputs(&self) -> Vec<ZecOutPoint> {
        self.tx()
            .map(|tx| tx.inputs.iter().map(|input| input.prevout).collect())
            .unwrap_or_default()
    }

    /// The recipient (first output).
    #[must_use]
    pub fn recipient(&self) -> Option<ZecDest> {
        let tx = self.tx().ok()?;
        ZecDest::from_script_pubkey(&tx.outputs.first()?.script_pubkey)
    }

    /// The change value (second output), 0 when none.
    #[must_use]
    pub fn change(&self) -> u64 {
        self.tx()
            .ok()
            .and_then(|tx| tx.outputs.get(1).map(|output| output.value))
            .unwrap_or(0)
    }

    /// Whether this record may still be mined (its inputs stay reserved): every non-terminal
    /// state (a `Signed` record could have been sent by a crash between send and state write).
    #[must_use]
    pub const fn may_still_confirm(&self) -> bool {
        !self.state.is_terminal()
    }

    /// Whether this record's inputs are never selected again: every record that may still
    /// confirm, and an [`ZecTxState::InputsSpent`] one (it may be in the chain).
    #[must_use]
    pub const fn reserves_inputs(&self) -> bool {
        self.may_still_confirm() || matches!(self.state, ZecTxState::InputsSpent)
    }

    /// Whether this record's inputs are not ours to send from: reserved
    /// ([`ZecRecord::reserves_inputs`]) or spent by this very transaction (`Confirmed`).
    #[must_use]
    pub const fn uses_inputs(&self) -> bool {
        self.reserves_inputs() || matches!(self.state, ZecTxState::Confirmed)
    }

    /// The change of a mined record as an output of its account (the second output, paying the
    /// account's own script, at the mined height); `None` before `Confirmed` or without change.
    #[must_use]
    pub fn mined_change(&self) -> Option<ZecUtxo> {
        if self.state != ZecTxState::Confirmed || self.mined_height == 0 {
            return None;
        }
        let tx = self.tx().ok()?;
        let output = tx.outputs.get(1)?;
        if output.value == 0 || output.script_pubkey != self.account.script_pubkey() {
            return None;
        }
        Some(ZecUtxo {
            outpoint: ZecOutPoint {
                txid: txid(&tx),
                index: 1,
            },
            value: output.value,
            height: Some(self.mined_height),
            coinbase: false,
        })
    }

    /// Encodes the body.
    ///
    /// # Errors
    ///
    /// [`ZecRecordError::Length`].
    pub fn encode(&self) -> Result<Vec<u8>, ZecRecordError> {
        if self.raw.is_empty() || self.raw.len() > ZEC_MAX_JOURNAL_RAW {
            return Err(ZecRecordError::Length);
        }
        let raw_len = u16::try_from(self.raw.len()).map_err(|_| ZecRecordError::Length)?;
        let (a, b) = self.account.source.params();
        let mnemonic = self.account.source.mnemonic();
        let mut out =
            Vec::with_capacity(ZEC_JOURNAL_HEADER_LEN + ZEC_JOURNAL_MNEMONIC_LEN + self.raw.len());
        out.push(RECORD_KIND);
        out.push(if mnemonic.is_some() {
            RECORD_VERSION_V2
        } else {
            RECORD_VERSION
        });
        out.push(self.state as u8);
        out.push(self.account.network.id());
        out.push(self.account.source.code());
        out.extend_from_slice(&a.to_be_bytes());
        out.extend_from_slice(&b.to_be_bytes());
        out.extend_from_slice(&self.account.pubkey);
        out.extend_from_slice(&self.approval_id);
        out.extend_from_slice(&self.approval_digest);
        out.extend_from_slice(&self.signed_at_ms.to_be_bytes());
        out.push(u8::from(self.disclosed));
        out.extend_from_slice(&self.mined_height.to_be_bytes());
        out.extend_from_slice(&self.not_found.to_be_bytes());
        out.extend_from_slice(&self.amount.to_be_bytes());
        out.extend_from_slice(&self.fee.to_be_bytes());
        out.extend_from_slice(&self.input_total.to_be_bytes());
        out.extend_from_slice(&raw_len.to_be_bytes());
        debug_assert_eq!(out.len(), ZEC_JOURNAL_HEADER_LEN);
        if let Some(id) = mnemonic {
            out.extend_from_slice(id.as_bytes());
        }
        out.extend_from_slice(&self.raw);
        Ok(out)
    }

    /// Decodes and validates a body: header, values, strict transaction parse, every scriptSig
    /// ends with this record's public key, outputs + fee = input total, amount = first output.
    ///
    /// # Errors
    ///
    /// [`ZecRecordError`].
    pub fn decode(body: &[u8]) -> Result<Self, ZecRecordError> {
        let len = ZecRecordError::Length;
        if body.len() < ZEC_JOURNAL_HEADER_LEN {
            return Err(len);
        }
        let v2 = match (body.first(), body.get(1)) {
            (Some(&RECORD_KIND), Some(&RECORD_VERSION)) => false,
            (Some(&RECORD_KIND), Some(&RECORD_VERSION_V2)) => true,
            _ => return Err(ZecRecordError::Header),
        };
        let raw_at = if v2 {
            ZEC_JOURNAL_HEADER_LEN + ZEC_JOURNAL_MNEMONIC_LEN
        } else {
            ZEC_JOURNAL_HEADER_LEN
        };
        let byte = |at: usize| body.get(at).copied().ok_or(len);
        let state = ZecTxState::from_code(byte(2)?).ok_or(ZecRecordError::Value)?;
        let network = ZecNetwork::from_id(byte(3)?).ok_or(ZecRecordError::Value)?;
        let a = be_u32(body, 5).ok_or(len)?;
        let b = be_u32(body, 9).ok_or(len)?;
        // Code 5 (an added mnemonic) exactly in version 2, with its record id after the header.
        let source = match (v2, byte(4)?) {
            (true, 5) => ZecKeySource::from_mnemonic_parts(
                array::<16>(body, ZEC_JOURNAL_HEADER_LEN).ok_or(len)?,
                a,
                b,
            ),
            (false, code) if code != 5 => ZecKeySource::from_parts(code, a, b),
            _ => return Err(ZecRecordError::Header),
        }
        .ok_or(ZecRecordError::Value)?;
        let pubkey = array::<33>(body, 13).ok_or(len)?;
        let approval_id = array::<16>(body, 46).ok_or(len)?;
        let approval_digest = array::<32>(body, 62).ok_or(len)?;
        let signed_at_ms = be_u64(body, 94).ok_or(len)?;
        let disclosed = match byte(102)? {
            0 => false,
            1 => true,
            _ => return Err(ZecRecordError::Value),
        };
        let mined_height = be_u32(body, 103).ok_or(len)?;
        let not_found = be_u16(body, 107).ok_or(len)?;
        let amount = be_u64(body, 109).ok_or(len)?;
        let fee = be_u64(body, 117).ok_or(len)?;
        let input_total = be_u64(body, 125).ok_or(len)?;
        let raw_len = usize::from(be_u16(body, 133).ok_or(len)?);
        if raw_len == 0
            || raw_len > ZEC_MAX_JOURNAL_RAW
            || body.len() != raw_at.saturating_add(raw_len)
        {
            return Err(len);
        }
        let raw = body.get(raw_at..).ok_or(len)?.to_vec();
        let record = Self {
            state,
            account: ZecAccount {
                network,
                source,
                pubkey,
            },
            approval_id,
            approval_digest,
            signed_at_ms,
            disclosed,
            mined_height,
            not_found,
            amount,
            fee,
            input_total,
            raw,
        };
        record.check_tx()?;
        if (state == ZecTxState::Confirmed) != (mined_height > 0) {
            return Err(ZecRecordError::Value);
        }
        Ok(record)
    }

    fn check_tx(&self) -> Result<(), ZecRecordError> {
        let tx = self.tx()?;
        let outputs = tx
            .outputs
            .iter()
            .map(|output| output.value)
            .fold(0_u64, u64::saturating_add);
        let key_ok = tx.inputs.iter().all(|input| {
            crate::btc::script::split_p2pkh_script_sig(&input.script_sig)
                .is_some_and(|(_, key)| key == self.account.pubkey)
        });
        let first = tx.outputs.first().map(|output| output.value);
        if tx.inputs.is_empty()
            || !key_ok
            || first != Some(self.amount)
            || outputs.checked_add(self.fee) != Some(self.input_total)
        {
            return Err(ZecRecordError::Tx);
        }
        Ok(())
    }

    /// Terminal.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }
}

/// The ZEC entries of a journal with their entry indices.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ZecEntries {
    /// `(entry index, record)` for every decodable ZEC entry.
    pub records: Vec<(usize, ZecRecord)>,
    /// ZEC entries the decoder rejected (ZEC sending stops while any exist).
    pub corrupt: usize,
}

impl ZecEntries {
    /// Decodes every ZEC entry of `plain`.
    #[must_use]
    pub fn from_plain(plain: &JournalPlain) -> Self {
        let mut out = Self::default();
        for (index, entry) in plain.entries.iter().enumerate() {
            if entry.kind != EntryKind::Zec {
                continue;
            }
            match ZecRecord::decode(&entry.body) {
                Ok(record) => out.records.push((index, record)),
                Err(_) => out.corrupt = out.corrupt.saturating_add(1),
            }
        }
        out
    }

    /// The records only.
    #[must_use]
    pub fn records(&self) -> Vec<ZecRecord> {
        self.records
            .iter()
            .map(|(_, record)| record.clone())
            .collect()
    }
}

/// Why a new send is not allowed now (spec/12 §12.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZecJournalBlock {
    /// A ZEC entry could not be decoded ("저널 손상").
    Corrupt,
    /// A record of this account may still confirm (one in flight, D20).
    InFlight,
    /// The journal has no room.
    Full,
}

impl ZecJournalBlock {
    /// The fixed text in `lang`.
    #[must_use]
    pub const fn text_in(self, lang: Lang) -> &'static str {
        match self {
            Self::Corrupt => text::BLOCK_CORRUPT,
            Self::InFlight => text::BLOCK_IN_FLIGHT,
            Self::Full => text::BLOCK_FULL,
        }
        .get(lang)
    }
}

/// The pre-sign check: no corrupt ZEC entry, no record of `account` (same network and public
/// key) that may still confirm, and room for one more record.
///
/// # Errors
///
/// [`ZecJournalBlock`].
pub fn check_plan_allowed(
    plain: &JournalPlain,
    account: &ZecAccount,
) -> Result<(), ZecJournalBlock> {
    let entries = ZecEntries::from_plain(plain);
    if entries.corrupt > 0 {
        return Err(ZecJournalBlock::Corrupt);
    }
    if entries.records.iter().any(|(_, record)| {
        record.may_still_confirm()
            && record.account.network == account.network
            && record.account.pubkey == account.pubkey
    }) {
        return Err(ZecJournalBlock::InFlight);
    }
    if !has_room(plain) && !terminal_removable(plain) {
        return Err(ZecJournalBlock::Full);
    }
    Ok(())
}

/// Outpoints reserved by records of `network` that may still confirm (never selected again,
/// spec/12 §12.2 disclosed-transaction rule).
#[must_use]
pub fn reserved_inputs(plain: &JournalPlain, network: ZecNetwork) -> Vec<ZecOutPoint> {
    ZecEntries::from_plain(plain)
        .records
        .iter()
        .filter(|(_, record)| record.reserves_inputs() && record.account.network == network)
        .flat_map(|(_, record)| record.inputs())
        .collect()
}

/// What a refresh still sends from when the address answer is over its limits (spec/12 §4.3):
/// `known` (the largest outputs of the last answer) plus the change of every mined record of
/// `records` (the account's records; a change paid while over the limits is never listed),
/// without any input of a record that spent or holds it ([`ZecRecord::uses_inputs`]: without
/// `gettxout` nothing else would drop an output our own confirmed send spent), largest first, at
/// most [`ZEC_MAX_INPUTS`]. `gettxout`, when the node has it, prunes the rest.
#[must_use]
pub fn over_limit_known(known: &[ZecUtxo], records: &[ZecRecord]) -> Vec<ZecUtxo> {
    let used: std::collections::BTreeSet<ZecOutPoint> = records
        .iter()
        .filter(|record| record.uses_inputs())
        .flat_map(ZecRecord::inputs)
        .collect();
    let mut out: Vec<ZecUtxo> = known
        .iter()
        .filter(|utxo| !used.contains(&utxo.outpoint))
        .copied()
        .collect();
    for change in records.iter().filter_map(ZecRecord::mined_change) {
        if !used.contains(&change.outpoint)
            && !out.iter().any(|kept| kept.outpoint == change.outpoint)
        {
            out.push(change);
        }
    }
    out.sort_by(|a, b| b.value.cmp(&a.value).then(a.outpoint.cmp(&b.outpoint)));
    out.truncate(ZEC_MAX_INPUTS);
    out
}

fn zec_entries(plain: &JournalPlain) -> usize {
    plain
        .entries
        .iter()
        .filter(|entry| entry.kind == EntryKind::Zec)
        .count()
}

/// The pre-add check for a new record.
#[must_use]
pub fn has_room(plain: &JournalPlain) -> bool {
    plain.entries.len() < MAX_ENTRIES
        && zec_entries(plain) < ZEC_JOURNAL_MAX_RECORDS
        && plain
            .plaintext_len()
            .saturating_add(ENTRY_HEADER_LEN)
            .saturating_add(ZEC_JOURNAL_MAX_BODY)
            <= MAX_PLAINTEXT
}

fn terminal_removable(plain: &JournalPlain) -> bool {
    ZecEntries::from_plain(plain)
        .records
        .iter()
        .any(|(_, record)| record.is_terminal())
}

/// Adds a record, first removing the oldest terminal ZEC records beyond
/// [`ZEC_JOURNAL_FINAL_KEEP`] or as needed for room. Other chains' entries are never removed.
///
/// # Errors
///
/// [`JournalError::Full`] (`plain` unchanged).
pub fn push_record(plain: &mut JournalPlain, record: &ZecRecord) -> Result<(), JournalError> {
    let body = record.encode().map_err(|_| JournalError::Full)?;
    let mut trial = plain.clone();
    let mut terminal: Vec<(u64, [u8; 32])> = ZecEntries::from_plain(&trial)
        .records
        .iter()
        .filter(|(_, known)| known.is_terminal())
        .map(|(_, known)| (known.signed_at_ms, known.txid()))
        .collect();
    terminal.sort_by_key(|(signed_at, _)| *signed_at);
    let mut excess = terminal.len().saturating_sub(ZEC_JOURNAL_FINAL_KEEP);
    for (_, id) in terminal {
        if excess == 0 && has_room(&trial) {
            break;
        }
        remove_txid(&mut trial, &id);
        excess = excess.saturating_sub(1);
    }
    if !has_room(&trial) {
        return Err(JournalError::Full);
    }
    trial.entries.push(Entry {
        kind: EntryKind::Zec,
        body,
    });
    *plain = trial;
    Ok(())
}

fn remove_txid(plain: &mut JournalPlain, id: &[u8; 32]) {
    let mut removed = false;
    plain.entries.retain(|entry| {
        if removed || entry.kind != EntryKind::Zec {
            return true;
        }
        match ZecRecord::decode(&entry.body) {
            Ok(record) if record.is_terminal() && record.txid() == *id => {
                removed = true;
                false
            }
            _ => true,
        }
    });
}

/// A change observed by the tracking loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZecTransition {
    /// About to be handed to a node (set before any RPC sees the bytes).
    Disclose,
    /// The node accepted it (or the answer was lost: `disclosed` either way).
    Broadcast,
    /// The node refused it (`-25`/`-26`, disclosed).
    Rejected,
    /// Never handed to a node and dropped.
    Discarded,
    /// Seen in a block at this height.
    Mined(u32),
    /// The node no longer has it in its mempool (count towards `ZEC_NOT_FOUND_LIMIT`).
    NotFound,
    /// Seen again in the mempool (resets the not-found count).
    InMempool,
    /// The tip passed the expiry height and it is not mined (at least one input still unspent).
    Expired,
    /// The tip passed the expiry height, the node does not know it and every input is spent.
    InputsSpent,
}

/// Applies `transition` to the record with `txid` (internal order); returns the new state if a
/// record changed. Terminal records never change; `Expired` needs a non-terminal record. A
/// transition that changes nothing (the same state, `disclosed` and `not_found`, e.g. the node
/// refusing a re-sent `Rejected` record again) returns `None`: nothing to write.
pub fn apply(
    plain: &mut JournalPlain,
    id: &[u8; 32],
    transition: ZecTransition,
) -> Option<ZecTxState> {
    for entry in &mut plain.entries {
        if entry.kind != EntryKind::Zec {
            continue;
        }
        let Ok(mut record) = ZecRecord::decode(&entry.body) else {
            continue;
        };
        if record.txid() != *id || record.is_terminal() {
            continue;
        }
        let before = record.clone();
        match transition {
            ZecTransition::Disclose => {
                if record.disclosed {
                    return None;
                }
                record.disclosed = true;
            }
            ZecTransition::Broadcast => {
                record.state = ZecTxState::Broadcast;
                record.disclosed = true;
                record.not_found = 0;
            }
            ZecTransition::Rejected => {
                record.state = ZecTxState::Rejected;
                record.disclosed = true;
            }
            ZecTransition::Discarded => {
                if record.disclosed {
                    return None;
                }
                record.state = ZecTxState::Discarded;
            }
            ZecTransition::Mined(height) if height > 0 => {
                record.state = ZecTxState::Confirmed;
                record.mined_height = height;
            }
            ZecTransition::Mined(_) => return None,
            ZecTransition::NotFound => record.not_found = record.not_found.saturating_add(1),
            ZecTransition::InMempool => record.not_found = 0,
            ZecTransition::Expired => record.state = ZecTxState::Expired,
            ZecTransition::InputsSpent => record.state = ZecTxState::InputsSpent,
        }
        if record == before {
            return None;
        }
        let state = record.state;
        let body = record.encode().ok()?;
        entry.body = body;
        return Some(state);
    }
    None
}
