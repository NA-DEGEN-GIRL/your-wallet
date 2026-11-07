//! SOL journal records (spec/07 §14.1–§14.2, `kind 0x02` entries of spec/02 §5.4): the binary
//! body codec with its full load-time validation (header, strict transaction parse, re-encoding
//! identity, `verify_strict`), state transitions, the pre-add room check with terminal clean-up,
//! and the `ActivityEntry` mapping. A body the decoder rejects stops SOL sending only; its bytes
//! are kept verbatim and never broadcast.
//!
//! Pattern: "record first, send later" of
//! `archive/spec-v2.4:crates/key-agent/src/durable.rs:725-806,1100-1129`, with 4 states.
#![deny(clippy::indexing_slicing)]

use core::fmt;

use super::{
    ENTRY_HEADER_LEN, Entry, EntryKind, JournalError, JournalPlain, MAX_ENTRIES, MAX_PLAINTEXT,
};
use crate::codec::base58::base58_encode;
use crate::slip10::SolKeySource;
use crate::sol::display::transfer_title;
use crate::sol::intent::SolTransferIntent;
use crate::sol::keys::verify_strict;
use crate::sol::message::{SolParseError, encode_message, parse_transaction};
use crate::sol::template::{SOL_MAX_TX_BYTES, SolAsset, SolTransferCore};
use crate::sol::{SignedSolTransfer, SolAddress, SolCluster};

/// `record_kind` (fixed).
pub const RECORD_KIND: u8 = 0x02;
/// `record_version` of every record whose source is not an added mnemonic's (unchanged layout).
pub const RECORD_VERSION: u8 = 1;
/// `record_version` of a record of an added mnemonic's account (source tag 8, spec/02 §8.6): the
/// version 1 header, then the 16-byte mnemonic record id, then the transaction. Earlier builds
/// treat it as a damaged body (SOL sending stops, the bytes are kept; spec/04 §6.6).
pub const RECORD_VERSION_V2: u8 = 2;
/// Fixed header length H (offsets 0..=88).
pub const SOL_JOURNAL_HEADER_LEN: usize = 89;
/// The mnemonic record id of a version 2 record.
pub const SOL_JOURNAL_MNEMONIC_LEN: usize = 16;
/// Largest SOL body: 89 + 16 + 1,232 = 1,337 (spec/02 §5.4; version 1 bodies are at most
/// 1,321).
pub const SOL_JOURNAL_MAX_BODY: usize =
    SOL_JOURNAL_HEADER_LEN + SOL_JOURNAL_MNEMONIC_LEN + SOL_MAX_TX_BYTES;
/// SOL records in the journal.
pub const SOL_JOURNAL_MAX_RECORDS: usize = 64;
const MIN_TX_LEN: usize = 65;

/// Record state (spec/07 §14.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SolTxState {
    /// Signed and journaled; being (re)broadcast.
    Pending = 1,
    /// Finalized with `err: null` (terminal).
    Landed = 2,
    /// Finalized with an error; the fee was charged (terminal).
    FailedOnChain = 3,
    /// Expiry proven; never sent (terminal).
    Expired = 4,
}

impl SolTxState {
    /// Parses the state byte.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::Pending,
            2 => Self::Landed,
            3 => Self::FailedOnChain,
            4 => Self::Expired,
            _ => return None,
        })
    }

    /// Terminal states 2–4.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Pending)
    }

    /// The `ActivityEntry.status` of a terminal state.
    #[must_use]
    pub const fn activity_status(self) -> Option<&'static str> {
        match self {
            Self::Pending => None,
            Self::Landed => Some("succeeded"),
            Self::FailedOnChain => Some("failed"),
            Self::Expired => Some("expired"),
        }
    }

    /// Fixed name for logs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Landed => "Landed",
            Self::FailedOnChain => "FailedOnChain",
            Self::Expired => "Expired",
        }
    }
}

/// A body the SOL decoder rejects ("저널 손상": SOL sending stops, the bytes are kept).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolRecordError {
    /// Body shorter than the header, `tx_len` outside 65..=1232, or `body_len != 89 + tx_len`.
    Length,
    /// `record_kind != 0x02`, an unknown `record_version`, or a version that does not match the
    /// source (version 2 exactly for tag 8).
    Header,
    /// Unknown state or cluster.
    Value,
    /// Source tag or its parameters invalid.
    Source,
    /// `Pending`/`Expired` with a terminal slot or error.
    Terminal,
    /// The transaction does not parse as a template.
    Tx(SolParseError),
    /// The message does not re-encode to the same bytes.
    Identity,
    /// `verify_strict(from)` failed.
    Signature,
}

impl fmt::Display for SolRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("저널 손상")
    }
}

impl std::error::Error for SolRecordError {}

/// One SOL journal record (spec/07 §14.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolRecord {
    /// State.
    pub state: SolTxState,
    /// Cluster.
    pub cluster: SolCluster,
    /// Key source of the sender.
    pub source: SolKeySource,
    /// Intent / approval id.
    pub intent_id: [u8; 16],
    /// `intent_hash`.
    pub intent_hash: [u8; 32],
    /// Wall-clock Unix ms of signing.
    pub signed_at_ms: u64,
    /// `lastValidBlockHeight` of the signed blockhash.
    pub last_valid_block_height: u64,
    /// Finalized slot (0 if none).
    pub terminal_slot: u64,
    /// spec/07 §15.3 code (0 if none).
    pub terminal_err: u16,
    /// The signed transaction.
    pub tx: Vec<u8>,
}

fn be_u16(body: &[u8], at: usize) -> Option<u16> {
    let end = at.checked_add(2)?;
    Some(u16::from_be_bytes(body.get(at..end)?.try_into().ok()?))
}

fn be_u32(body: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    Some(u32::from_be_bytes(body.get(at..end)?.try_into().ok()?))
}

fn be_u64(body: &[u8], at: usize) -> Option<u64> {
    let end = at.checked_add(8)?;
    Some(u64::from_be_bytes(body.get(at..end)?.try_into().ok()?))
}

fn array<const N: usize>(body: &[u8], at: usize) -> Option<[u8; N]> {
    let end = at.checked_add(N)?;
    body.get(at..end)?.try_into().ok()
}

impl SolRecord {
    /// The `Pending` record of a freshly signed transfer.
    #[must_use]
    pub fn new_pending(
        intent: &SolTransferIntent,
        signed: &SignedSolTransfer,
        signed_at_ms: u64,
        last_valid_block_height: u64,
    ) -> Self {
        Self {
            state: SolTxState::Pending,
            cluster: intent.cluster,
            source: intent.source,
            intent_id: intent.id,
            intent_hash: intent.intent_hash(),
            signed_at_ms,
            last_valid_block_height,
            terminal_slot: 0,
            terminal_err: 0,
            tx: signed.tx.clone(),
        }
    }

    /// Encodes the body (`89 + tx_len` bytes).
    ///
    /// # Errors
    ///
    /// [`SolRecordError::Length`] for a transaction outside 65..=1232 bytes.
    pub fn encode(&self) -> Result<Vec<u8>, SolRecordError> {
        if !(MIN_TX_LEN..=SOL_MAX_TX_BYTES).contains(&self.tx.len()) {
            return Err(SolRecordError::Length);
        }
        let tx_len = u16::try_from(self.tx.len()).map_err(|_| SolRecordError::Length)?;
        let (a, b) = self.source.params();
        let mnemonic = self.source.mnemonic();
        let mut out = Vec::with_capacity(SOL_JOURNAL_MAX_BODY);
        out.push(RECORD_KIND);
        out.push(if mnemonic.is_some() {
            RECORD_VERSION_V2
        } else {
            RECORD_VERSION
        });
        out.push(self.state as u8);
        out.push(self.cluster.code());
        out.push(self.source.tag());
        out.extend_from_slice(&a.to_be_bytes());
        out.extend_from_slice(&b.to_be_bytes());
        out.extend_from_slice(&self.intent_id);
        out.extend_from_slice(&self.intent_hash);
        out.extend_from_slice(&self.signed_at_ms.to_be_bytes());
        out.extend_from_slice(&self.last_valid_block_height.to_be_bytes());
        out.extend_from_slice(&self.terminal_slot.to_be_bytes());
        out.extend_from_slice(&self.terminal_err.to_be_bytes());
        out.extend_from_slice(&tx_len.to_be_bytes());
        if let Some(id) = mnemonic {
            out.extend_from_slice(id.as_bytes());
        }
        out.extend_from_slice(&self.tx);
        Ok(out)
    }

    /// Decodes and fully validates a body (spec/07 §14.1 load checks).
    ///
    /// # Errors
    ///
    /// [`SolRecordError`].
    pub fn decode(body: &[u8]) -> Result<Self, SolRecordError> {
        if body.len() < SOL_JOURNAL_HEADER_LEN {
            return Err(SolRecordError::Length);
        }
        let byte = |at: usize| body.get(at).copied().ok_or(SolRecordError::Length);
        let v2 = match (byte(0)?, byte(1)?) {
            (RECORD_KIND, RECORD_VERSION) => false,
            (RECORD_KIND, RECORD_VERSION_V2) => true,
            _ => return Err(SolRecordError::Header),
        };
        let state = SolTxState::from_code(byte(2)?).ok_or(SolRecordError::Value)?;
        let cluster = SolCluster::from_code(byte(3)?).ok_or(SolRecordError::Value)?;
        let a = be_u32(body, 5).ok_or(SolRecordError::Length)?;
        let b = be_u32(body, 9).ok_or(SolRecordError::Length)?;
        let tx_at = if v2 {
            SOL_JOURNAL_HEADER_LEN + SOL_JOURNAL_MNEMONIC_LEN
        } else {
            SOL_JOURNAL_HEADER_LEN
        };
        let source = match (v2, byte(4)?) {
            (true, 8) => {
                let id = array::<16>(body, SOL_JOURNAL_HEADER_LEN).ok_or(SolRecordError::Length)?;
                SolKeySource::from_mnemonic_parts(id, a, b).map_err(|_| SolRecordError::Source)?
            }
            // Tag 8 in version 1 is refused by `from_parts` (it needs the record id).
            (false, tag) => {
                SolKeySource::from_parts(tag, a, b).map_err(|_| SolRecordError::Source)?
            }
            (true, _) => return Err(SolRecordError::Header),
        };
        let intent_id = array::<16>(body, 13).ok_or(SolRecordError::Length)?;
        let intent_hash = array::<32>(body, 29).ok_or(SolRecordError::Length)?;
        let signed_at_ms = be_u64(body, 61).ok_or(SolRecordError::Length)?;
        let last_valid_block_height = be_u64(body, 69).ok_or(SolRecordError::Length)?;
        let terminal_slot = be_u64(body, 77).ok_or(SolRecordError::Length)?;
        let terminal_err = be_u16(body, 85).ok_or(SolRecordError::Length)?;
        let tx_len = usize::from(be_u16(body, 87).ok_or(SolRecordError::Length)?);
        if !(MIN_TX_LEN..=SOL_MAX_TX_BYTES).contains(&tx_len)
            || body.len() != tx_at.saturating_add(tx_len)
        {
            return Err(SolRecordError::Length);
        }
        if matches!(state, SolTxState::Pending | SolTxState::Expired)
            && (terminal_slot != 0 || terminal_err != 0)
        {
            return Err(SolRecordError::Terminal);
        }
        let tx = body.get(tx_at..).ok_or(SolRecordError::Length)?.to_vec();
        let (core, blockhash, signature) =
            parse_transaction(&tx, cluster).map_err(SolRecordError::Tx)?;
        let message = tx.get(MIN_TX_LEN..).ok_or(SolRecordError::Length)?;
        if encode_message(&core, &blockhash) != message {
            return Err(SolRecordError::Identity);
        }
        if !verify_strict(core.from.as_bytes(), message, &signature) {
            return Err(SolRecordError::Signature);
        }
        Ok(Self {
            state,
            cluster,
            source,
            intent_id,
            intent_hash,
            signed_at_ms,
            last_valid_block_height,
            terminal_slot,
            terminal_err,
            tx,
        })
    }

    /// The parsed transaction content (always `Some` for a decoded record).
    #[must_use]
    pub fn core(&self) -> Option<SolTransferCore> {
        parse_transaction(&self.tx, self.cluster)
            .ok()
            .map(|(core, _, _)| core)
    }

    /// The signature (`tx[1..65]`).
    #[must_use]
    pub fn signature(&self) -> [u8; 64] {
        array::<64>(&self.tx, 1).unwrap_or([0; 64])
    }

    /// The transaction id (`base58(signature)`).
    #[must_use]
    pub fn tx_id(&self) -> String {
        base58_encode(&self.signature())
    }

    /// Terminal (states 2–4).
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }
}

/// The SOL entries of a journal with their entry indices.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SolEntries {
    /// `(entry index, record)` for every decodable SOL entry.
    pub records: Vec<(usize, SolRecord)>,
    /// SOL entries the decoder rejected (SOL sending stops while any exist).
    pub corrupt: usize,
}

impl SolEntries {
    /// Decodes every SOL entry of `plain`.
    #[must_use]
    pub fn from_plain(plain: &JournalPlain) -> Self {
        let mut out = Self::default();
        for (index, entry) in plain.entries.iter().enumerate() {
            if entry.kind != EntryKind::Sol {
                continue;
            }
            match SolRecord::decode(&entry.body) {
                Ok(record) => out.records.push((index, record)),
                Err(_) => out.corrupt = out.corrupt.saturating_add(1),
            }
        }
        out
    }

    /// The records only.
    #[must_use]
    pub fn records(&self) -> Vec<SolRecord> {
        self.records
            .iter()
            .map(|(_, record)| record.clone())
            .collect()
    }
}

/// Whether any SOL entry (decodable or not) carries `intent_hash` (`AlreadySigned`).
#[must_use]
pub fn has_intent(plain: &JournalPlain, intent_hash: &[u8; 32]) -> bool {
    plain.entries.iter().any(|entry| {
        entry.kind == EntryKind::Sol && entry.body.get(29..61) == Some(intent_hash.as_slice())
    })
}

/// The `Pending` record of `(cluster, from)`, if any (one transfer in flight, spec/07 §1).
#[must_use]
pub fn pending_for<'a>(
    records: &'a [SolRecord],
    cluster: SolCluster,
    from: &SolAddress,
) -> Option<&'a SolRecord> {
    records.iter().find(|record| {
        record.state == SolTxState::Pending
            && record.cluster == cluster
            && record.core().is_some_and(|core| core.from == *from)
    })
}

fn sol_entries(plain: &JournalPlain) -> usize {
    plain
        .entries
        .iter()
        .filter(|entry| entry.kind == EntryKind::Sol)
        .count()
}

/// The pre-add check for a new `Pending` record (spec/07 §14.1, spec/02 §5.4).
#[must_use]
pub fn has_room(plain: &JournalPlain) -> bool {
    plain.entries.len() < MAX_ENTRIES
        && sol_entries(plain) < SOL_JOURNAL_MAX_RECORDS
        && plain
            .plaintext_len()
            .saturating_add(ENTRY_HEADER_LEN)
            .saturating_add(SOL_JOURNAL_MAX_BODY)
            <= MAX_PLAINTEXT
}

/// A terminal record as an `ActivityEntry` (spec/07 §14.1 table).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolActivityRow {
    /// Cluster (`solana:<cluster>` network).
    pub cluster: SolCluster,
    /// Sender (base58).
    pub account: String,
    /// `base58(signature)`.
    pub tx_id: String,
    /// The approval title rebuilt from the transaction.
    pub title: String,
    /// `"native"` (SOL) or the SPL mint (base58).
    pub asset: String,
    /// Lamports or raw token units, decimal.
    pub amount: String,
    /// Recipient wallet (base58).
    pub counterparty: String,
    /// `succeeded` / `failed` / `expired`.
    pub status: &'static str,
    /// Terminal observation time.
    pub time_unix_ms: u64,
}

/// The activity row of a terminal record (`None` for `Pending`).
#[must_use]
pub fn activity_row(record: &SolRecord, time_unix_ms: u64) -> Option<SolActivityRow> {
    let status = record.state.activity_status()?;
    let core = record.core()?;
    Some(SolActivityRow {
        cluster: record.cluster,
        account: core.from.to_base58(),
        tx_id: record.tx_id(),
        title: transfer_title(record.cluster, &core),
        asset: match core.asset {
            SolAsset::Sol => "native".to_owned(),
            SolAsset::Spl(entry) => entry.mint.to_base58(),
        },
        amount: core.amount.to_string(),
        counterparty: core.to.to_base58(),
        status,
        time_unix_ms,
    })
}

/// A state change observed by the broadcast loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolTransition {
    /// Finalized, `err: null`.
    Landed {
        /// Signature.
        signature: [u8; 64],
        /// Slot.
        slot: u64,
    },
    /// Finalized with an error.
    FailedOnChain {
        /// Signature.
        signature: [u8; 64],
        /// Slot.
        slot: u64,
        /// spec/07 §15.3 code.
        err: u16,
    },
    /// Expiry proven.
    Expired {
        /// Signature.
        signature: [u8; 64],
    },
}

impl SolTransition {
    const fn signature(&self) -> &[u8; 64] {
        match self {
            Self::Landed { signature, .. }
            | Self::FailedOnChain { signature, .. }
            | Self::Expired { signature } => signature,
        }
    }

    /// Fixed name for logs.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Landed { .. } => "Landed",
            Self::FailedOnChain { .. } => "FailedOnChain",
            Self::Expired { .. } => "Expired",
        }
    }
}

/// Applies a transition to the matching `Pending` record (only `Pending` moves); returns whether
/// a record changed. Undecodable entries are never touched.
pub fn apply(plain: &mut JournalPlain, transition: &SolTransition) -> bool {
    for entry in &mut plain.entries {
        if entry.kind != EntryKind::Sol {
            continue;
        }
        let Ok(mut record) = SolRecord::decode(&entry.body) else {
            continue;
        };
        if record.signature() != *transition.signature() || record.state != SolTxState::Pending {
            continue;
        }
        match *transition {
            SolTransition::Landed { slot, .. } => {
                record.state = SolTxState::Landed;
                record.terminal_slot = slot;
            }
            SolTransition::FailedOnChain { slot, err, .. } => {
                record.state = SolTxState::FailedOnChain;
                record.terminal_slot = slot;
                record.terminal_err = err;
            }
            SolTransition::Expired { .. } => record.state = SolTxState::Expired,
        }
        if let Ok(body) = record.encode() {
            entry.body = body;
            return true;
        }
    }
    false
}

/// Removes every decodable terminal SOL record and returns their activity rows (moved to meta
/// first by the caller, then committed without them).
pub fn take_terminal(plain: &mut JournalPlain, time_unix_ms: u64) -> Vec<SolActivityRow> {
    let mut rows = Vec::new();
    plain.entries.retain(|entry| {
        if entry.kind != EntryKind::Sol {
            return true;
        }
        match SolRecord::decode(&entry.body) {
            Ok(record) if record.is_terminal() => {
                if let Some(row) = activity_row(&record, time_unix_ms) {
                    rows.push(row);
                }
                false
            }
            _ => true,
        }
    });
    rows
}

/// The pre-add clean-up: when there is no room, removes terminal SOL records oldest first
/// (`signed_at_ms` ascending) until there is, returning their activity rows. Other chains'
/// entries are never removed.
///
/// # Errors
///
/// [`JournalError::Full`] when even all terminal SOL records are not enough (`plain` unchanged).
pub fn make_room(
    plain: &mut JournalPlain,
    time_unix_ms: u64,
) -> Result<Vec<SolActivityRow>, JournalError> {
    if has_room(plain) {
        return Ok(Vec::new());
    }
    let mut trial = plain.clone();
    let mut terminal: Vec<(u64, [u8; 64])> = SolEntries::from_plain(&trial)
        .records
        .iter()
        .filter(|(_, record)| record.is_terminal())
        .map(|(_, record)| (record.signed_at_ms, record.signature()))
        .collect();
    terminal.sort_by_key(|(signed_at, _)| *signed_at);
    let mut rows = Vec::new();
    for (_, signature) in terminal {
        let mut removed = None;
        trial.entries.retain(|entry| {
            if removed.is_some() || entry.kind != EntryKind::Sol {
                return true;
            }
            match SolRecord::decode(&entry.body) {
                Ok(record) if record.signature() == signature => {
                    removed = Some(record);
                    false
                }
                _ => true,
            }
        });
        if let Some(record) = removed
            && let Some(row) = activity_row(&record, time_unix_ms)
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

/// Adds a record as a new SOL entry.
///
/// # Errors
///
/// [`JournalError::Full`] when it does not fit (call [`make_room`] first).
pub fn push_record(plain: &mut JournalPlain, record: &SolRecord) -> Result<(), JournalError> {
    if !has_room(plain) {
        return Err(JournalError::Full);
    }
    let body = record.encode().map_err(|_| JournalError::Full)?;
    plain.entries.push(Entry {
        kind: EntryKind::Sol,
        body,
    });
    Ok(())
}
