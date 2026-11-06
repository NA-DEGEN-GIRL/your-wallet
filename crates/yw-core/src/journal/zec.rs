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
use crate::zec::account::{ZecAccount, ZecKeySource};
use crate::zec::address::ZecDest;
use crate::zec::network::ZecNetwork;
use crate::zec::plan::ZecPlan;
use crate::zec::sign::ZecSignedTx;
use crate::zec::tx::{ZecOutPoint, ZecTx, parse_tx, txid, txid_display};
use crate::zec::{ZEC_JOURNAL_FINAL_KEEP, ZEC_MAX_JOURNAL_RAW};

/// `record_kind` (fixed).
pub const RECORD_KIND: u8 = 0x04;
/// `record_version`.
pub const RECORD_VERSION: u8 = 1;
/// Fixed header length.
pub const ZEC_JOURNAL_HEADER_LEN: usize = 135;
/// Largest ZEC body.
pub const ZEC_JOURNAL_MAX_BODY: usize = ZEC_JOURNAL_HEADER_LEN + ZEC_MAX_JOURNAL_RAW;
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
            _ => return None,
        })
    }

    /// Terminal: nothing about this record can change any more.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Confirmed | Self::Expired | Self::Discarded)
    }

    /// Display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Signed => "서명됨 (전송 전)",
            Self::Broadcast => "전송됨 (확인 대기)",
            Self::Confirmed => "확인됨",
            Self::Expired => "만료됨 (포함되지 않음)",
            Self::Rejected => "노드가 거부함 (만료까지 대기)",
            Self::Discarded => "폐기됨 (전송 안 함)",
        }
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
        }
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

impl fmt::Display for ZecRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("저널 손상")
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
        let mut out = Vec::with_capacity(ZEC_JOURNAL_HEADER_LEN + self.raw.len());
        out.push(RECORD_KIND);
        out.push(RECORD_VERSION);
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
        if body.first() != Some(&RECORD_KIND) || body.get(1) != Some(&RECORD_VERSION) {
            return Err(ZecRecordError::Header);
        }
        let byte = |at: usize| body.get(at).copied().ok_or(len);
        let state = ZecTxState::from_code(byte(2)?).ok_or(ZecRecordError::Value)?;
        let network = ZecNetwork::from_id(byte(3)?).ok_or(ZecRecordError::Value)?;
        let a = be_u32(body, 5).ok_or(len)?;
        let b = be_u32(body, 9).ok_or(len)?;
        let source = ZecKeySource::from_parts(byte(4)?, a, b).ok_or(ZecRecordError::Value)?;
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
            || body.len() != ZEC_JOURNAL_HEADER_LEN.saturating_add(raw_len)
        {
            return Err(len);
        }
        let raw = body.get(ZEC_JOURNAL_HEADER_LEN..).ok_or(len)?.to_vec();
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
    /// The fixed Korean text.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::Corrupt => "Zcash 거래 저널이 손상되어 보내기를 막았습니다.",
            Self::InFlight => {
                "이 계정의 이전 Zcash 거래가 아직 확인되지 않았습니다. 확인되거나 만료된 뒤에 다시 보내세요."
            }
            Self::Full => "거래 저널 공간이 부족합니다.",
        }
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
        .filter(|(_, record)| record.may_still_confirm() && record.account.network == network)
        .flat_map(|(_, record)| record.inputs())
        .collect()
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
    /// The tip passed the expiry height and it is not mined.
    Expired,
}

/// Applies `transition` to the record with `txid` (internal order); returns the new state if a
/// record changed. Terminal records never change; `Expired` needs a non-terminal record.
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
        match transition {
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
        }
        let state = record.state;
        let body = record.encode().ok()?;
        entry.body = body;
        return Some(state);
    }
    None
}
