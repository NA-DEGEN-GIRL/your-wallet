//! EVM journal records (spec/03 §5): the big-endian record body (`kind 0x01` entries), its strict
//! decoder, the candidate state machine (§5.2), the one-in-flight nonce rule (§3.6, D20), the
//! terminal-record clean-up with its activity mapping (§5.4) and the pre-add room check
//! (spec/02 §5.4).
//!
//! Ported patterns: the nonce-slot lifecycle of
//! `archive/spec-v2.4:crates/wallet-protocol/src/nonce.rs:20-65` (one candidate set per
//! `(chain, account, nonce)`, inclusion separate from finality) and the "signed record before
//! broadcast, never re-sign" rule of `archive/spec-v2.4:crates/key-agent/src/durable.rs:725-806`.
#![deny(clippy::indexing_slicing)]

use core::fmt;

use super::{
    ENTRY_HEADER_LEN, Entry, EntryKind, JournalError, JournalPlain, MAX_ENTRIES, MAX_PLAINTEXT,
};
use crate::approval::Warning;
use crate::evm::abi::{SEL_TRANSFER, address_word};
use crate::evm::address::Address;
use crate::evm::amount::U256;
use crate::evm::risk::{E06, warning_text};
use crate::evm::sign::recover_address;
use crate::evm::tx::{Eip1559Tx, MAX_SIGNED_TX_BYTES, SignedEip1559, decode_signed, tx_hash};

/// `record_kind` (fixed).
pub const RECORD_KIND: u8 = 0x01;
/// `record_version`.
pub const RECORD_VERSION: u8 = 0x01;
/// Bytes before `origin` (offsets 0..172).
pub const FIXED_LEN: usize = 172;
/// Largest `origin`.
pub const MAX_ORIGIN: usize = 255;
/// Largest `label` (approval title).
pub const MAX_LABEL: usize = 256;
/// Smallest signed transaction.
pub const MIN_RAW: usize = 2;
/// Largest EVM body (172 + 255 + 2 + 256 + 4 + 131,072).
pub const MAX_BODY: usize = 131_761;
/// Terminal records move to activity this long after becoming terminal (7 days).
pub const RETENTION_MS: u64 = 604_800_000;
/// Candidates per nonce: the original plus 8 replacements.
pub const MAX_CANDIDATES: usize = 9;
/// Two `latest nonce > nonce` observations at least this far apart drop a group.
pub const DROP_CONFIRM_MS: u64 = 30_000;
/// Automatic re-broadcast at most once per this interval.
pub const REBROADCAST_INTERVAL_MS: u64 = 60_000;
/// `flags` bit 0: the RPC returned another transaction hash (no automatic re-broadcast).
pub const FLAG_RPC_HASH_MISMATCH: u8 = 0x01;
/// `flags` bit 1: the user discarded the candidate set.
pub const FLAG_USER_DISCARDED: u8 = 0x02;
/// `flags` bit 2: the broadcast was refused for good (unknown to the node, or the chain no longer
/// matched) and the dApp was told it failed — no automatic re-broadcast, only the user's `재전송`
/// (spec/03 §4.4, §5.4-3). Records without it decode as before.
pub const FLAG_MANUAL_RESEND: u8 = 0x04;
const KNOWN_FLAGS: u8 = FLAG_RPC_HASH_MISMATCH | FLAG_USER_DISCARDED | FLAG_MANUAL_RESEND;

/// Candidate state (§5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TxState {
    /// Signed and journaled, not known to the network.
    Signed = 1,
    /// Known to the network.
    Broadcast = 2,
    /// A receipt exists.
    Included = 3,
    /// Finalized (terminal).
    Finalized = 4,
    /// Another transaction used the nonce, or the user discarded it (terminal).
    Dropped = 5,
    /// Another candidate of the same nonce was included (terminal).
    Replaced = 6,
}

impl TxState {
    /// The state byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Parses a state byte.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::Signed,
            2 => Self::Broadcast,
            3 => Self::Included,
            4 => Self::Finalized,
            5 => Self::Dropped,
            6 => Self::Replaced,
            _ => return None,
        })
    }

    /// `Finalized`, `Dropped` or `Replaced`.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Finalized | Self::Dropped | Self::Replaced)
    }

    /// Fixed name for logs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Signed => "Signed",
            Self::Broadcast => "Broadcast",
            Self::Included => "Included",
            Self::Finalized => "Finalized",
            Self::Dropped => "Dropped",
            Self::Replaced => "Replaced",
        }
    }
}

/// Candidate role (§4.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Role {
    /// The original transaction.
    Original = 0,
    /// A speed-up replacement.
    SpeedUp = 1,
    /// A cancel replacement.
    Cancel = 2,
}

impl Role {
    /// The role byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Parses a role byte.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::Original,
            1 => Self::SpeedUp,
            2 => Self::Cancel,
            _ => return None,
        })
    }
}

/// Receipt status (§5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ReceiptStatus {
    /// No receipt.
    None = 0,
    /// `status 0x1`.
    Success = 1,
    /// `status 0x0`.
    Failure = 2,
}

impl ReceiptStatus {
    /// Parses a status byte.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::None,
            1 => Self::Success,
            2 => Self::Failure,
            _ => return None,
        })
    }
}

/// A record body that the EVM decoder rejects ("저널 손상": EVM sending stops, bytes are kept).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// Body length differs from the sum of its fields or a length field is out of range.
    Length,
    /// `record_kind` or `record_version` is not 1.
    Header,
    /// Unknown state, role or receipt status.
    Value,
    /// Unused flag bits are set.
    Flags,
    /// `origin` or `label` is not UTF-8.
    Text,
    /// `raw` is not a strictly decodable signed type-2 transaction.
    Raw,
    /// `keccak256(raw) != tx_hash`.
    Hash,
    /// The decoded `chain_id` or `nonce` differs from the record.
    Mismatch,
    /// The recovered signer is not `account`.
    Signer,
}

impl fmt::Display for RecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("저널 손상")
    }
}

impl std::error::Error for RecordError {}

/// One EVM journal record (spec/03 §5.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvmRecord {
    /// Chain id.
    pub chain_id: u64,
    /// Signing account.
    pub account: Address,
    /// Nonce.
    pub nonce: u64,
    /// State.
    pub state: TxState,
    /// Role.
    pub role: Role,
    /// Receipt status.
    pub receipt_status: ReceiptStatus,
    /// Flags (`FLAG_*`).
    pub flags: u8,
    /// Creation (Unix ms).
    pub created_unix_ms: u64,
    /// Last state change (Unix ms).
    pub updated_unix_ms: u64,
    /// Last broadcast (Unix ms), 0 = never.
    pub last_broadcast_unix_ms: u64,
    /// `keccak256(raw)`.
    pub tx_hash: [u8; 32],
    /// Approval digest (spec/03 §11.4).
    pub approval_digest: [u8; 32],
    /// Including block, 0 = none.
    pub included_block_number: u64,
    /// Including block hash, zero = none.
    pub included_block_hash: [u8; 32],
    /// `"yw-app"` or a serialized origin.
    pub origin: String,
    /// The approval title.
    pub label: String,
    /// Signed transaction `0x02 ‖ rlp`.
    pub raw: Vec<u8>,
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], RecordError> {
        let end = self.at.checked_add(len).ok_or(RecordError::Length)?;
        let slice = self.bytes.get(self.at..end).ok_or(RecordError::Length)?;
        self.at = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RecordError> {
        self.take(N)?.try_into().map_err(|_| RecordError::Length)
    }

    fn u8(&mut self) -> Result<u8, RecordError> {
        Ok(u8::from_be_bytes(self.array::<1>()?))
    }

    fn u16(&mut self) -> Result<u16, RecordError> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    fn u32(&mut self) -> Result<u32, RecordError> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, RecordError> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }

    fn text(&mut self, len: usize) -> Result<String, RecordError> {
        let bytes = self.take(len)?;
        core::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| RecordError::Text)
    }
}

impl EvmRecord {
    /// A new `Signed` record (role `Original`, `SpeedUp` or `Cancel`) for a verified signed
    /// transaction.
    ///
    /// # Errors
    ///
    /// [`RecordError`] when the fields break §5.1 (lengths, hash, decoding, signer).
    #[expect(
        clippy::too_many_arguments,
        reason = "one argument per non-default field of spec/03 §5.1"
    )]
    pub fn new_signed(
        chain_id: u64,
        account: Address,
        nonce: u64,
        role: Role,
        now_unix_ms: u64,
        approval_digest: [u8; 32],
        origin: &str,
        label: &str,
        raw: Vec<u8>,
    ) -> Result<Self, RecordError> {
        let record = Self {
            chain_id,
            account,
            nonce,
            state: TxState::Signed,
            role,
            receipt_status: ReceiptStatus::None,
            flags: 0,
            created_unix_ms: now_unix_ms,
            updated_unix_ms: now_unix_ms,
            last_broadcast_unix_ms: 0,
            tx_hash: tx_hash(&raw),
            approval_digest,
            included_block_number: 0,
            included_block_hash: [0; 32],
            origin: origin.to_owned(),
            label: label.to_owned(),
            raw,
        };
        Self::decode(&record.encode()?)?;
        Ok(record)
    }

    /// Encodes the body.
    ///
    /// # Errors
    ///
    /// [`RecordError::Length`] when `origin`, `label` or `raw` is out of range.
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let origin_len = u16::try_from(self.origin.len())
            .ok()
            .filter(|len| usize::from(*len) <= MAX_ORIGIN)
            .ok_or(RecordError::Length)?;
        let label_len = u16::try_from(self.label.len())
            .ok()
            .filter(|len| usize::from(*len) <= MAX_LABEL)
            .ok_or(RecordError::Length)?;
        let raw_len = u32::try_from(self.raw.len())
            .ok()
            .filter(|_| (MIN_RAW..=MAX_SIGNED_TX_BYTES).contains(&self.raw.len()))
            .ok_or(RecordError::Length)?;
        let mut out = Vec::with_capacity(
            FIXED_LEN
                .saturating_add(self.origin.len())
                .saturating_add(self.label.len())
                .saturating_add(self.raw.len())
                .saturating_add(6),
        );
        out.push(RECORD_KIND);
        out.push(RECORD_VERSION);
        out.extend_from_slice(&self.chain_id.to_be_bytes());
        out.extend_from_slice(self.account.as_bytes());
        out.extend_from_slice(&self.nonce.to_be_bytes());
        out.push(self.state.code());
        out.push(self.role.code());
        out.push(self.receipt_status as u8);
        out.push(self.flags);
        out.extend_from_slice(&self.created_unix_ms.to_be_bytes());
        out.extend_from_slice(&self.updated_unix_ms.to_be_bytes());
        out.extend_from_slice(&self.last_broadcast_unix_ms.to_be_bytes());
        out.extend_from_slice(&self.tx_hash);
        out.extend_from_slice(&self.approval_digest);
        out.extend_from_slice(&self.included_block_number.to_be_bytes());
        out.extend_from_slice(&self.included_block_hash);
        out.extend_from_slice(&origin_len.to_be_bytes());
        out.extend_from_slice(self.origin.as_bytes());
        out.extend_from_slice(&label_len.to_be_bytes());
        out.extend_from_slice(self.label.as_bytes());
        out.extend_from_slice(&raw_len.to_be_bytes());
        out.extend_from_slice(&self.raw);
        Ok(out)
    }

    /// Strictly decodes a body (§5.1 read checks): exact length, known kind, version and enum
    /// values, unused flag bits zero, `keccak256(raw) == tx_hash`, `raw` decodes, its chain id
    /// and nonce match, and the recovered signer is `account`.
    ///
    /// # Errors
    ///
    /// [`RecordError`].
    pub fn decode(body: &[u8]) -> Result<Self, RecordError> {
        if body.len() > MAX_BODY {
            return Err(RecordError::Length);
        }
        let mut reader = Reader { bytes: body, at: 0 };
        if reader.u8()? != RECORD_KIND || reader.u8()? != RECORD_VERSION {
            return Err(RecordError::Header);
        }
        let chain_id = reader.u64()?;
        let account = Address::from_bytes(reader.array::<20>()?);
        let nonce = reader.u64()?;
        let state = TxState::from_code(reader.u8()?).ok_or(RecordError::Value)?;
        let role = Role::from_code(reader.u8()?).ok_or(RecordError::Value)?;
        let receipt_status = ReceiptStatus::from_code(reader.u8()?).ok_or(RecordError::Value)?;
        let flags = reader.u8()?;
        if flags & !KNOWN_FLAGS != 0 {
            return Err(RecordError::Flags);
        }
        let created_unix_ms = reader.u64()?;
        let updated_unix_ms = reader.u64()?;
        let last_broadcast_unix_ms = reader.u64()?;
        let hash = reader.array::<32>()?;
        let approval_digest = reader.array::<32>()?;
        let included_block_number = reader.u64()?;
        let included_block_hash = reader.array::<32>()?;
        let origin_len = usize::from(reader.u16()?);
        if origin_len > MAX_ORIGIN {
            return Err(RecordError::Length);
        }
        let origin = reader.text(origin_len)?;
        let label_len = usize::from(reader.u16()?);
        if label_len > MAX_LABEL {
            return Err(RecordError::Length);
        }
        let label = reader.text(label_len)?;
        let raw_len = usize::try_from(reader.u32()?).map_err(|_| RecordError::Length)?;
        if !(MIN_RAW..=MAX_SIGNED_TX_BYTES).contains(&raw_len) {
            return Err(RecordError::Length);
        }
        let raw = reader.take(raw_len)?.to_vec();
        if reader.at != body.len() {
            return Err(RecordError::Length);
        }
        if tx_hash(&raw) != hash {
            return Err(RecordError::Hash);
        }
        let signed = decode_signed(&raw).map_err(|_| RecordError::Raw)?;
        if signed.tx.chain_id != chain_id || signed.tx.nonce != nonce {
            return Err(RecordError::Mismatch);
        }
        if signer_of(&signed) != Some(account) {
            return Err(RecordError::Signer);
        }
        Ok(Self {
            chain_id,
            account,
            nonce,
            state,
            role,
            receipt_status,
            flags,
            created_unix_ms,
            updated_unix_ms,
            last_broadcast_unix_ms,
            tx_hash: hash,
            approval_digest,
            included_block_number,
            included_block_hash,
            origin,
            label,
            raw,
        })
    }

    /// Whether the record is terminal.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    /// The decoded signed transaction.
    #[must_use]
    pub fn signed(&self) -> Option<SignedEip1559> {
        decode_signed(&self.raw).ok()
    }

    /// The transaction fields.
    #[must_use]
    pub fn tx(&self) -> Option<Eip1559Tx> {
        self.signed().map(|signed| signed.tx)
    }

    /// The nonce group key.
    #[must_use]
    pub const fn key(&self) -> GroupKey {
        GroupKey {
            chain_id: self.chain_id,
            account: self.account,
            nonce: self.nonce,
        }
    }

    /// Whether `flag` is set.
    #[must_use]
    pub const fn has_flag(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}

fn signer_of(signed: &SignedEip1559) -> Option<Address> {
    let mut compact = [0_u8; 64];
    let (r, s) = compact.split_at_mut(32);
    r.copy_from_slice(&signed.r);
    s.copy_from_slice(&signed.s);
    recover_address(signed.tx.signing_hash(), signed.y_parity, &compact)
}

/// A nonce group: `(chain, account, nonce)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GroupKey {
    /// Chain id.
    pub chain_id: u64,
    /// Account.
    pub account: Address,
    /// Nonce.
    pub nonce: u64,
}

/// The EVM records of a journal with their entry indices.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EvmEntries {
    /// `(entry index, record)` for every decodable EVM entry.
    pub records: Vec<(usize, EvmRecord)>,
    /// EVM entries the decoder rejected (bytes kept; EVM sending stops while any exist).
    pub corrupt: usize,
}

impl EvmEntries {
    /// Decodes every EVM entry of `plain`.
    #[must_use]
    pub fn from_plain(plain: &JournalPlain) -> Self {
        let mut out = Self::default();
        for (index, entry) in plain.entries.iter().enumerate() {
            if entry.kind != EntryKind::Evm {
                continue;
            }
            match EvmRecord::decode(&entry.body) {
                Ok(record) => out.records.push((index, record)),
                Err(_) => out.corrupt = out.corrupt.saturating_add(1),
            }
        }
        out
    }

    /// The records only.
    #[must_use]
    pub fn records(&self) -> Vec<EvmRecord> {
        self.records
            .iter()
            .map(|(_, record)| record.clone())
            .collect()
    }
}

/// Groups records by nonce key (key order), each group sorted by creation time.
#[must_use]
pub fn groups(records: &[EvmRecord]) -> Vec<(GroupKey, Vec<&EvmRecord>)> {
    let mut out: Vec<(GroupKey, Vec<&EvmRecord>)> = Vec::new();
    for record in records {
        let key = record.key();
        match out.iter_mut().find(|(known, _)| *known == key) {
            Some((_, members)) => members.push(record),
            None => out.push((key, vec![record])),
        }
    }
    out.sort_by_key(|(key, _)| *key);
    for (_, members) in &mut out {
        members.sort_by_key(|record| record.created_unix_ms);
    }
    out
}

/// The lowest nonce of a non-terminal record of `(chain_id, account)`, if any (§3.6).
#[must_use]
pub fn in_flight(records: &[EvmRecord], chain_id: u64, account: &Address) -> Option<u64> {
    records
        .iter()
        .filter(|record| {
            record.chain_id == chain_id && record.account == *account && !record.is_terminal()
        })
        .map(|record| record.nonce)
        .min()
}

/// The newest non-terminal candidate of a group (re-broadcast and replacement base).
#[must_use]
pub fn latest_candidate<'a>(group: &[&'a EvmRecord]) -> Option<&'a EvmRecord> {
    group
        .iter()
        .copied()
        .filter(|record| matches!(record.state, TxState::Signed | TxState::Broadcast))
        .max_by_key(|record| record.created_unix_ms)
}

/// Why a new transaction may not take a nonce (E06, blocked).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonceBlock {
    /// The journal has a non-terminal record for the account.
    InFlight {
        /// Its nonce.
        nonce: u64,
    },
    /// `pending != latest`: a transaction sent elsewhere is pending.
    ExternalPending,
}

impl NonceBlock {
    /// The E06 warning.
    #[must_use]
    pub fn warning(self) -> Warning {
        match self {
            Self::InFlight { nonce } => {
                warning_text(E06, format!("진행 중인 거래가 있습니다 (nonce {nonce})"))
            }
            Self::ExternalPending => warning_text(
                E06,
                "이 계정에서 다른 곳으로 보낸 대기 중 거래가 있습니다".to_owned(),
            ),
        }
    }
}

/// The E06 "journal full" warning (§5.4-4).
#[must_use]
pub fn journal_full_warning() -> Warning {
    warning_text(E06, "거래 저널 공간이 부족합니다".to_owned())
}

/// The nonce of a new transaction (§3.6): blocked by an in-flight record or by `pending !=
/// latest`, otherwise `latest`.
///
/// # Errors
///
/// [`NonceBlock`].
pub const fn plan_nonce(
    in_flight: Option<u64>,
    latest: u64,
    pending: u64,
) -> Result<u64, NonceBlock> {
    if let Some(nonce) = in_flight {
        return Err(NonceBlock::InFlight { nonce });
    }
    if pending != latest {
        return Err(NonceBlock::ExternalPending);
    }
    Ok(latest)
}

/// A state change (§5.2), applied by the key worker and committed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Transition {
    /// The RPC returned the same hash, or `eth_getTransactionByHash` found it:
    /// `Signed → Broadcast` (also clears `rpc_hash_mismatch`).
    Broadcast {
        /// Candidate.
        tx_hash: [u8; 32],
        /// Observation time.
        at_unix_ms: u64,
    },
    /// The same bytes were sent again (records `last_broadcast_unix_ms`).
    Rebroadcast {
        /// Candidate.
        tx_hash: [u8; 32],
        /// Send time.
        at_unix_ms: u64,
    },
    /// The RPC returned another hash: stays `Signed` with `rpc_hash_mismatch`.
    HashMismatch {
        /// Candidate.
        tx_hash: [u8; 32],
        /// Observation time.
        at_unix_ms: u64,
    },
    /// The broadcast was refused for good: stays `Signed` with `manual_resend` (no automatic
    /// re-broadcast; cleared by a later `Broadcast`).
    ManualResend {
        /// Candidate.
        tx_hash: [u8; 32],
        /// Observation time.
        at_unix_ms: u64,
    },
    /// A valid receipt: `Included`; other non-terminal candidates of the nonce → `Replaced`.
    Included {
        /// Candidate.
        tx_hash: [u8; 32],
        /// Block number.
        block_number: u64,
        /// Block hash.
        block_hash: [u8; 32],
        /// `status 0x1`.
        success: bool,
        /// Observation time.
        at_unix_ms: u64,
    },
    /// Finalized block ≥ inclusion and the block hash matches: `Included → Finalized`.
    Finalized {
        /// Candidate.
        tx_hash: [u8; 32],
        /// Observation time.
        at_unix_ms: u64,
    },
    /// The block hash at the inclusion height changed: `Included → Broadcast`, inclusion cleared.
    Reorged {
        /// Candidate.
        tx_hash: [u8; 32],
        /// Observation time.
        at_unix_ms: u64,
    },
    /// No receipt and `latest nonce > nonce` twice ≥ 30 s apart: all candidates `Dropped`.
    Dropped {
        /// Group.
        key: GroupKey,
        /// Observation time.
        at_unix_ms: u64,
    },
    /// User discard: all candidates `Dropped` with `user_discarded`.
    Discarded {
        /// Group.
        key: GroupKey,
        /// Time.
        at_unix_ms: u64,
    },
}

impl Transition {
    /// Fixed name for logs.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Broadcast { .. } => "Broadcast",
            Self::Rebroadcast { .. } => "Rebroadcast",
            Self::HashMismatch { .. } => "HashMismatch",
            Self::ManualResend { .. } => "ManualResend",
            Self::Included { .. } => "Included",
            Self::Finalized { .. } => "Finalized",
            Self::Reorged { .. } => "Reorged",
            Self::Dropped { .. } => "Dropped",
            Self::Discarded { .. } => "Discarded",
        }
    }
}

const fn open(state: TxState) -> bool {
    matches!(state, TxState::Signed | TxState::Broadcast)
}

/// Applies one transition (§5.2 table); returns the indices of changed records. Transitions that
/// the table does not allow from the current state change nothing.
#[expect(
    clippy::too_many_lines,
    reason = "one arm per row of the spec/03 §5.2 table"
)]
pub fn apply(records: &mut [EvmRecord], transition: &Transition) -> Vec<usize> {
    let mut changed = Vec::new();
    let position = |records: &[EvmRecord], hash: &[u8; 32]| {
        records.iter().position(|record| record.tx_hash == *hash)
    };
    match *transition {
        Transition::Broadcast {
            tx_hash,
            at_unix_ms,
        } => {
            if let Some(index) = position(records, &tx_hash)
                && let Some(record) = records.get_mut(index)
                && record.state == TxState::Signed
            {
                record.state = TxState::Broadcast;
                record.flags &= !(FLAG_RPC_HASH_MISMATCH | FLAG_MANUAL_RESEND);
                record.updated_unix_ms = at_unix_ms;
                if record.last_broadcast_unix_ms == 0 {
                    record.last_broadcast_unix_ms = at_unix_ms;
                }
                changed.push(index);
            }
        }
        Transition::Rebroadcast {
            tx_hash,
            at_unix_ms,
        } => {
            if let Some(index) = position(records, &tx_hash)
                && let Some(record) = records.get_mut(index)
                && open(record.state)
            {
                record.last_broadcast_unix_ms = at_unix_ms;
                changed.push(index);
            }
        }
        Transition::HashMismatch {
            tx_hash,
            at_unix_ms,
        } => {
            if let Some(index) = position(records, &tx_hash)
                && let Some(record) = records.get_mut(index)
                && record.state == TxState::Signed
            {
                record.flags |= FLAG_RPC_HASH_MISMATCH;
                record.updated_unix_ms = at_unix_ms;
                record.last_broadcast_unix_ms = at_unix_ms;
                changed.push(index);
            }
        }
        Transition::ManualResend {
            tx_hash,
            at_unix_ms,
        } => {
            if let Some(index) = position(records, &tx_hash)
                && let Some(record) = records.get_mut(index)
                && record.state == TxState::Signed
                && !record.has_flag(FLAG_MANUAL_RESEND)
            {
                record.flags |= FLAG_MANUAL_RESEND;
                record.updated_unix_ms = at_unix_ms;
                changed.push(index);
            }
        }
        Transition::Included {
            tx_hash,
            block_number,
            block_hash,
            success,
            at_unix_ms,
        } => {
            let Some(index) = position(records, &tx_hash) else {
                return changed;
            };
            let Some(key) = records
                .get(index)
                .filter(|record| open(record.state))
                .map(EvmRecord::key)
            else {
                return changed;
            };
            for (other, record) in records.iter_mut().enumerate() {
                if other == index {
                    record.state = TxState::Included;
                    record.receipt_status = if success {
                        ReceiptStatus::Success
                    } else {
                        ReceiptStatus::Failure
                    };
                    record.included_block_number = block_number;
                    record.included_block_hash = block_hash;
                    record.updated_unix_ms = at_unix_ms;
                    changed.push(other);
                } else if record.key() == key && open(record.state) {
                    record.state = TxState::Replaced;
                    record.updated_unix_ms = at_unix_ms;
                    changed.push(other);
                }
            }
        }
        Transition::Finalized {
            tx_hash,
            at_unix_ms,
        } => {
            if let Some(index) = position(records, &tx_hash)
                && let Some(record) = records.get_mut(index)
                && record.state == TxState::Included
            {
                record.state = TxState::Finalized;
                record.updated_unix_ms = at_unix_ms;
                changed.push(index);
            }
        }
        Transition::Reorged {
            tx_hash,
            at_unix_ms,
        } => {
            if let Some(index) = position(records, &tx_hash)
                && let Some(record) = records.get_mut(index)
                && record.state == TxState::Included
            {
                record.state = TxState::Broadcast;
                record.receipt_status = ReceiptStatus::None;
                record.included_block_number = 0;
                record.included_block_hash = [0; 32];
                record.updated_unix_ms = at_unix_ms;
                changed.push(index);
            }
        }
        Transition::Dropped { key, at_unix_ms } | Transition::Discarded { key, at_unix_ms } => {
            let discard = matches!(transition, Transition::Discarded { .. });
            for (index, record) in records.iter_mut().enumerate() {
                if record.key() == key && open(record.state) {
                    record.state = TxState::Dropped;
                    if discard {
                        record.flags |= FLAG_USER_DISCARDED;
                    }
                    record.updated_unix_ms = at_unix_ms;
                    changed.push(index);
                }
            }
        }
    }
    changed
}

/// Applies `transitions` to the EVM entries of `plain` (re-encoding changed records in place;
/// other entries keep their bytes). Returns the number of changed records.
pub fn apply_to_plain(plain: &mut JournalPlain, transitions: &[Transition]) -> usize {
    let entries = EvmEntries::from_plain(plain);
    let (indices, mut records): (Vec<usize>, Vec<EvmRecord>) = entries.records.into_iter().unzip();
    let mut changed: Vec<usize> = Vec::new();
    for transition in transitions {
        for index in apply(&mut records, transition) {
            if !changed.contains(&index) {
                changed.push(index);
            }
        }
    }
    let mut written = 0_usize;
    for index in changed {
        if let (Some(entry_index), Some(record)) = (indices.get(index), records.get(index))
            && let Ok(body) = record.encode()
            && let Some(entry) = plain.entries.get_mut(*entry_index)
        {
            entry.body = body;
            written = written.saturating_add(1);
        }
    }
    written
}

/// Activity status of a finished EVM transaction (spec/02 §5.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivityStatus {
    /// Finalized with receipt status 1.
    Succeeded,
    /// Finalized with receipt status 0.
    Failed,
    /// Dropped (user discard included).
    Dropped,
    /// Replaced by a cancel.
    Replaced,
}

impl ActivityStatus {
    /// The meta string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Dropped => "dropped",
            Self::Replaced => "replaced",
        }
    }
}

/// One activity row (spec/02 §5.3 `ActivityEntry`, EVM mapping of spec/03 §5.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivityRow {
    /// `eip155:<chainId>` network of the row.
    pub chain_id: u64,
    /// Lowercase `0x` account.
    pub account: String,
    /// `0x` + tx hash.
    pub tx_id: String,
    /// Approval title at signing time.
    pub title: String,
    /// `"native"` or the token address.
    pub asset: String,
    /// Smallest-unit decimal amount.
    pub amount: String,
    /// Recipient (lowercase `0x`).
    pub counterparty: String,
    /// Status.
    pub status: ActivityStatus,
    /// Terminal observation time.
    pub time_unix_ms: u64,
}

/// `(asset, amount, counterparty)` of a transaction: an ERC-20 `transfer` → token, amount,
/// recipient; otherwise native value to `to`.
#[must_use]
pub fn transfer_summary(tx: &Eip1559Tx) -> (String, String, String) {
    if tx.data.len() == 68 && tx.data.get(..4) == Some(SEL_TRANSFER.as_slice()) {
        let recipient = tx
            .data
            .get(4..36)
            .and_then(|word| <[u8; 32]>::try_from(word).ok())
            .and_then(|word| address_word(&word));
        let amount = tx
            .data
            .get(36..68)
            .and_then(|word| <[u8; 32]>::try_from(word).ok())
            .map(U256::from_be_bytes);
        if let (Some(recipient), Some(amount)) = (recipient, amount) {
            return (
                tx.to.to_lower_hex(),
                amount.to_decimal_string(),
                recipient.to_lower_hex(),
            );
        }
    }
    (
        "native".to_owned(),
        tx.value.to_decimal_string(),
        tx.to.to_lower_hex(),
    )
}

fn row(
    record: &EvmRecord,
    title: &str,
    status: ActivityStatus,
    time_unix_ms: u64,
) -> Option<ActivityRow> {
    let tx = record.tx()?;
    let (asset, amount, counterparty) = transfer_summary(&tx);
    let title = if title.len() > MAX_LABEL {
        record.label.clone()
    } else {
        title.to_owned()
    };
    Some(ActivityRow {
        chain_id: record.chain_id,
        account: record.account.to_lower_hex(),
        tx_id: format!("0x{}", crate::hex::encode(&record.tx_hash)),
        title,
        asset,
        amount,
        counterparty,
        status,
        time_unix_ms,
    })
}

/// Activity rows of a fully terminal nonce group (§5.4): a speed-up shares the original's row
/// (hash of the confirmed candidate); a confirmed cancel turns the original row `replaced` and
/// adds a "거래 취소" row. `None` when some record is not terminal.
#[must_use]
pub fn group_activity(group: &[&EvmRecord]) -> Option<Vec<ActivityRow>> {
    if group.is_empty() || group.iter().any(|record| !record.is_terminal()) {
        return None;
    }
    let time = group
        .iter()
        .map(|record| record.updated_unix_ms)
        .max()
        .unwrap_or(0);
    let title = group
        .iter()
        .find(|record| record.role == Role::Original)
        .or_else(|| group.first())
        .map_or("", |record| record.label.as_str());
    let finalized = group
        .iter()
        .find(|record| record.state == TxState::Finalized)
        .copied();
    let newest_non_cancel = group
        .iter()
        .filter(|record| record.role != Role::Cancel)
        .max_by_key(|record| record.created_unix_ms)
        .copied();
    let receipt = |record: &EvmRecord| {
        if record.receipt_status == ReceiptStatus::Success {
            ActivityStatus::Succeeded
        } else {
            ActivityStatus::Failed
        }
    };
    let mut rows = Vec::new();
    match finalized {
        Some(record) if record.role == Role::Cancel => {
            if let Some(original) = newest_non_cancel {
                rows.extend(row(original, title, ActivityStatus::Replaced, time));
            }
            rows.extend(row(record, "거래 취소", receipt(record), time));
        }
        Some(record) => rows.extend(row(record, title, receipt(record), time)),
        None => {
            let newest = group
                .iter()
                .max_by_key(|record| record.created_unix_ms)
                .copied()?;
            rows.extend(row(newest, title, ActivityStatus::Dropped, time));
        }
    }
    Some(rows)
}

/// Removes the entries of the given groups from `plain` and returns their activity rows.
fn remove_groups(plain: &mut JournalPlain, keys: &[GroupKey]) -> Vec<ActivityRow> {
    let entries = EvmEntries::from_plain(plain);
    let records = entries.records();
    let mut rows = Vec::new();
    for (key, members) in groups(&records) {
        if keys.contains(&key) {
            rows.extend(group_activity(&members).unwrap_or_default());
        }
    }
    let remove: Vec<usize> = entries
        .records
        .iter()
        .filter(|(_, record)| keys.contains(&record.key()))
        .map(|(index, _)| *index)
        .collect();
    let mut index = 0_usize;
    plain.entries.retain(|_: &Entry| {
        let keep = !remove.contains(&index);
        index = index.saturating_add(1);
        keep
    });
    rows
}

/// Fully terminal groups with their terminal time, oldest first.
fn terminal_groups(records: &[EvmRecord]) -> Vec<(GroupKey, u64)> {
    let mut out: Vec<(GroupKey, u64)> = groups(records)
        .into_iter()
        .filter(|(_, members)| members.iter().all(|record| record.is_terminal()))
        .map(|(key, members)| {
            let time = members
                .iter()
                .map(|record| record.updated_unix_ms)
                .max()
                .unwrap_or(0);
            (key, time)
        })
        .collect();
    out.sort_by_key(|(key, time)| (*time, *key));
    out
}

/// Takes out the groups terminal for 7 days or longer (done before every journal write, §5.4-4).
#[must_use]
pub fn take_expired(plain: &mut JournalPlain, now_unix_ms: u64) -> Vec<ActivityRow> {
    let records = EvmEntries::from_plain(plain).records();
    let expired: Vec<GroupKey> = terminal_groups(&records)
        .into_iter()
        .filter(|(_, time)| now_unix_ms.saturating_sub(*time) >= RETENTION_MS)
        .map(|(key, _)| key)
        .collect();
    if expired.is_empty() {
        return Vec::new();
    }
    remove_groups(plain, &expired)
}

/// The terminal groups whose removal makes room for one more EVM entry, oldest first; `None`
/// when even all of them are not enough.
fn groups_to_free(plain: &JournalPlain) -> Option<Vec<GroupKey>> {
    if plain.has_room_for(EntryKind::Evm) {
        return Some(Vec::new());
    }
    let entries = EvmEntries::from_plain(plain);
    let records = entries.records();
    let mut count = plain.entries.len();
    let mut length = plain.plaintext_len();
    let mut chosen = Vec::new();
    for (key, _) in terminal_groups(&records) {
        for (index, record) in &entries.records {
            if record.key() == key {
                let size = plain
                    .entries
                    .get(*index)
                    .map_or(0, |entry| entry.body.len().saturating_add(ENTRY_HEADER_LEN));
                count = count.saturating_sub(1);
                length = length.saturating_sub(size);
            }
        }
        chosen.push(key);
        if count < MAX_ENTRIES
            && length
                .saturating_add(ENTRY_HEADER_LEN)
                .saturating_add(MAX_BODY)
                <= MAX_PLAINTEXT
        {
            return Some(chosen);
        }
    }
    None
}

/// The pre-add check for a new EVM record (spec/02 §5.4): when there is no room, removes terminal
/// EVM groups oldest first (returning their activity rows) until there is.
///
/// # Errors
///
/// [`JournalError::Full`] when even all terminal EVM groups are not enough (`plain` unchanged).
pub fn make_room(plain: &mut JournalPlain) -> Result<Vec<ActivityRow>, JournalError> {
    let keys = groups_to_free(plain).ok_or(JournalError::Full)?;
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    Ok(remove_groups(plain, &keys))
}

/// Whether a new EVM record would fit after the clean-up of [`make_room`] (prepare step 4).
#[must_use]
pub fn room_after_cleanup(plain: &JournalPlain) -> bool {
    groups_to_free(plain).is_some()
}

/// Adds an encoded record as a new EVM entry.
///
/// # Errors
///
/// [`JournalError::Full`] when it does not fit (call [`make_room`] first).
pub fn push_record(plain: &mut JournalPlain, record: &EvmRecord) -> Result<(), JournalError> {
    if !plain.has_room_for(EntryKind::Evm) {
        return Err(JournalError::Full);
    }
    let body = record.encode().map_err(|_| JournalError::Full)?;
    plain.entries.push(Entry {
        kind: EntryKind::Evm,
        body,
    });
    Ok(())
}
