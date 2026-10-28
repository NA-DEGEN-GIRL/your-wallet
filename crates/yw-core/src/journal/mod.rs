//! Transaction journal plaintext (spec/02 §5.4, M4): the chain-independent binary container
//! `"YWJPL003" ‖ entry_count u16 ‖ reserved[6] ‖ entries` with
//! `entry = kind u8 ‖ body_len u32 BE ‖ body`, its count and size bounds, and
//! [`JournalError::Full`]. Chain record bodies live in the chain submodules (`journal::evm` at M4,
//! `journal::sol` at M7, `journal::btc` at M8).
//!
//! Patterns from `archive/spec-v2.4:crates/key-agent/src/durable.rs:725-806,1100-1129`
//! (signed-before-broadcast records, interrupted-broadcast recovery) re-specified for v3: the
//! container is sealed by the vault's journal sidecar (spec/02 §5.2) and framing errors are
//! `VaultError::SidecarCorrupt(Journal)`.
#![deny(clippy::indexing_slicing)]

pub mod btc;
pub mod evm;
pub mod sol;

#[cfg(test)]
mod tests;

use core::fmt;

use crate::error::VaultError;
use crate::vault::FileKind;

/// Plaintext magic.
pub const PLAIN_MAGIC: [u8; 8] = *b"YWJPL003";
/// Header length (magic, count, reserved).
pub const HEADER_LEN: usize = 16;
/// Per-entry framing (`kind` + `body_len`).
pub const ENTRY_HEADER_LEN: usize = 5;
/// Entries in the whole journal (all chains).
pub const MAX_ENTRIES: usize = 256;
/// Plaintext bound (16 MiB, spec/02 §5.2).
pub const MAX_PLAINTEXT: usize = 16_777_216;
/// Largest `body_len` the framing accepts.
pub const MAX_BODY: usize = 1_048_576;

/// The chain discriminator of an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EntryKind {
    /// EVM record (spec/03 §5.1).
    Evm = 1,
    /// Solana record (spec/07 §14.1, M7).
    Sol = 2,
    /// Bitcoin record (spec/08 §12.4, M8).
    Btc = 3,
}

impl EntryKind {
    /// The `kind` byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Parses a `kind` byte.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Evm),
            2 => Some(Self::Sol),
            3 => Some(Self::Btc),
            _ => None,
        }
    }

    /// The largest body of this chain (spec/02 §5.4: EVM 131,761, SOL 1,321, BTC 37,924).
    #[must_use]
    pub const fn max_body(self) -> usize {
        match self {
            Self::Evm => evm::MAX_BODY,
            Self::Sol => sol::SOL_JOURNAL_MAX_BODY,
            Self::Btc => btc::BTC_JOURNAL_MAX_BODY,
        }
    }
}

/// One entry: chain kind and its record body bytes (kept verbatim, also when a chain decoder
/// rejects them).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Chain.
    pub kind: EntryKind,
    /// Record body.
    pub body: Vec<u8>,
}

/// Journal failure that blocks signing (spec/02 §10.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalError {
    /// No room for a new record even after removing terminal records: no signing, no sending.
    Full,
}

impl fmt::Display for JournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Full => "거래 저널 공간이 부족합니다",
        })
    }
}

impl std::error::Error for JournalError {}

const CORRUPT: VaultError = VaultError::SidecarCorrupt(FileKind::Journal);

/// The decoded journal plaintext: entries in insertion order (the order has no meaning).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JournalPlain {
    /// Entries.
    pub entries: Vec<Entry>,
}

fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    let slice: [u8; 4] = bytes.get(at..end)?.try_into().ok()?;
    Some(u32::from_be_bytes(slice))
}

impl JournalPlain {
    /// Decodes the plaintext. A missing journal file is an empty journal (the caller passes no
    /// bytes then).
    ///
    /// # Errors
    ///
    /// `VaultError::SidecarCorrupt(Journal)` for any framing error: magic, `entry_count` above
    /// 256, reserved bytes ≠ 0, an unknown `kind`, `body_len` 0 or above 1 MiB or past the end,
    /// trailing bytes, or a plaintext above 16 MiB.
    pub fn decode(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() > MAX_PLAINTEXT || bytes.get(..8) != Some(PLAIN_MAGIC.as_slice()) {
            return Err(CORRUPT);
        }
        let count = bytes
            .get(8..10)
            .and_then(|slice| <[u8; 2]>::try_from(slice).ok())
            .map(u16::from_be_bytes)
            .ok_or(CORRUPT)?;
        let count = usize::from(count);
        if count > MAX_ENTRIES
            || bytes
                .get(10..HEADER_LEN)
                .is_none_or(|reserved| reserved.iter().any(|byte| *byte != 0))
        {
            return Err(CORRUPT);
        }
        let mut at = HEADER_LEN;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let kind = bytes
                .get(at)
                .copied()
                .and_then(EntryKind::from_code)
                .ok_or(CORRUPT)?;
            let body_len = read_u32(bytes, at.checked_add(1).ok_or(CORRUPT)?)
                .and_then(|len| usize::try_from(len).ok())
                .ok_or(CORRUPT)?;
            if body_len == 0 || body_len > MAX_BODY {
                return Err(CORRUPT);
            }
            let start = at.checked_add(ENTRY_HEADER_LEN).ok_or(CORRUPT)?;
            let end = start.checked_add(body_len).ok_or(CORRUPT)?;
            let body = bytes.get(start..end).ok_or(CORRUPT)?;
            entries.push(Entry {
                kind,
                body: body.to_vec(),
            });
            at = end;
        }
        if at != bytes.len() {
            return Err(CORRUPT);
        }
        Ok(Self { entries })
    }

    /// Plaintext length of the current entries.
    #[must_use]
    pub fn plaintext_len(&self) -> usize {
        self.entries.iter().fold(HEADER_LEN, |total, entry| {
            total
                .saturating_add(ENTRY_HEADER_LEN)
                .saturating_add(entry.body.len())
        })
    }

    /// Whether the journal is within its count and size bounds.
    #[must_use]
    pub fn within_bounds(&self) -> bool {
        self.entries.len() <= MAX_ENTRIES
            && self.plaintext_len() <= MAX_PLAINTEXT
            && self
                .entries
                .iter()
                .all(|entry| (1..=MAX_BODY).contains(&entry.body.len()))
    }

    /// The pre-add check (spec/02 §5.4): one more entry of `kind` fits in count and size.
    #[must_use]
    pub fn has_room_for(&self, kind: EntryKind) -> bool {
        self.entries.len() < MAX_ENTRIES
            && self
                .plaintext_len()
                .saturating_add(ENTRY_HEADER_LEN)
                .saturating_add(kind.max_body())
                <= MAX_PLAINTEXT
    }

    /// Encodes the plaintext.
    ///
    /// # Errors
    ///
    /// [`JournalError::Full`] when the entries exceed the count or size bounds (never written).
    pub fn encode(&self) -> Result<Vec<u8>, JournalError> {
        if !self.within_bounds() {
            return Err(JournalError::Full);
        }
        let count = u16::try_from(self.entries.len()).map_err(|_| JournalError::Full)?;
        let mut out = Vec::with_capacity(self.plaintext_len());
        out.extend_from_slice(&PLAIN_MAGIC);
        out.extend_from_slice(&count.to_be_bytes());
        out.extend_from_slice(&[0; 6]);
        for entry in &self.entries {
            let len = u32::try_from(entry.body.len()).map_err(|_| JournalError::Full)?;
            out.push(entry.kind.code());
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&entry.body);
        }
        Ok(out)
    }
}
