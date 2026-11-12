//! Address lookup tables (spec/07 §20.3): the table account layout and the resolution of a v0
//! message's lookups into loaded addresses, in Agave's load order. Table contents come from the
//! RPC (X10); the resolved addresses are bound into the approval digest.
#![deny(clippy::indexing_slicing)]

use core::fmt;
use std::collections::HashSet;

use super::parse::SolTxMessage;
use crate::sol::address::{ADDRESS_LOOKUP_TABLE_PROGRAM, SolAddress};

/// Bytes before the first address (`LOOKUP_TABLE_META_SIZE`).
pub const LOOKUP_TABLE_META_SIZE: usize = 56;
/// Most addresses in one table.
pub const LOOKUP_TABLE_MAX_ADDRESSES: usize = 256;
/// Largest table account (`56 + 256 × 32`).
pub const LOOKUP_TABLE_MAX_DATA: usize = 8_248;
/// Most distinct tables read for one request.
pub const SOL_DAPP_MAX_TABLES: usize = 100;
/// `ProgramState::LookupTable` (u32 LE; 0 is an uninitialized account).
const LOOKUP_TABLE_DISCRIMINATOR: u32 = 1;

/// A parsed lookup table account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupTable {
    /// `u64::MAX` while active.
    pub deactivation_slot: u64,
    /// Slot of the last extension.
    pub last_extended_slot: u64,
    /// Table length before that extension.
    pub last_extended_start: u8,
    /// Who may extend or close the table (`None`: frozen).
    pub authority: Option<SolAddress>,
    /// The addresses.
    pub addresses: Vec<SolAddress>,
}

impl LookupTable {
    /// Whether deactivation has started (the table still resolves until it is closed).
    #[must_use]
    pub const fn is_deactivated(&self) -> bool {
        self.deactivation_slot != u64::MAX
    }

    /// Addresses a transaction may use at `current_slot`: those added in the current slot are
    /// not usable yet (Agave `get_active_addresses_len`).
    #[must_use]
    pub fn usable_len(&self, current_slot: u64) -> usize {
        if self.last_extended_slot == current_slot {
            usize::from(self.last_extended_start).min(self.addresses.len())
        } else {
            self.addresses.len()
        }
    }
}

fn le_u64(data: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        data.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}

/// Parses a table account owned by `owner`: owner = ALT program, discriminator 1, a 56-byte
/// header (4 deactivation slot, 12 last extended slot, 20 its start index, 21 authority option
/// tag 0/1, 22..54 the authority, 54..56 padding) and at most 256 addresses after it. With tag 0
/// the authority bytes are ignored (the program leaves stale bytes there when freezing).
#[must_use]
pub fn parse_lookup_table(owner: &SolAddress, data: &[u8]) -> Option<LookupTable> {
    if *owner != ADDRESS_LOOKUP_TABLE_PROGRAM || data.len() > LOOKUP_TABLE_MAX_DATA {
        return None;
    }
    let body = data.get(LOOKUP_TABLE_META_SIZE..)?;
    if body.len() % 32 != 0 {
        return None;
    }
    let discriminator = u32::from_le_bytes(data.get(..4)?.try_into().ok()?);
    if discriminator != LOOKUP_TABLE_DISCRIMINATOR {
        return None;
    }
    let authority = match *data.get(21)? {
        0 => None,
        1 => Some(SolAddress::from_bytes(data.get(22..54)?.try_into().ok()?)),
        _ => return None,
    };
    let addresses: Vec<SolAddress> = body
        .chunks_exact(32)
        .filter_map(|chunk| <[u8; 32]>::try_from(chunk).ok())
        .map(SolAddress::from_bytes)
        .collect();
    if addresses.len() > LOOKUP_TABLE_MAX_ADDRESSES {
        return None;
    }
    Some(LookupTable {
        deactivation_slot: le_u64(data, 4)?,
        last_extended_slot: le_u64(data, 12)?,
        last_extended_start: *data.get(20)?,
        authority,
        addresses,
    })
}

/// The addresses a v0 message loads, in load order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResolvedKeys {
    /// Every writable lookup, in lookup order.
    pub writable: Vec<SolAddress>,
    /// Then every read-only lookup, in lookup order.
    pub readonly: Vec<SolAddress>,
}

/// Why a message's lookups cannot be resolved (X01 for that transaction).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AltError {
    /// The table account does not exist.
    Missing(SolAddress),
    /// The account is not a lookup table (owner, layout).
    NotTable(SolAddress),
    /// An index is past the table's usable length.
    Index,
    /// A loaded address equals a static key or another loaded address.
    Duplicate,
}

impl fmt::Display for AltError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(table) => write!(formatter, "조회 테이블이 없습니다: {table}"),
            Self::NotTable(table) => write!(formatter, "조회 테이블이 아닙니다: {table}"),
            Self::Index => formatter.write_str("조회 테이블 인덱스가 범위 밖입니다"),
            Self::Duplicate => formatter.write_str("조회한 주소가 다른 계정 키와 겹칩니다"),
        }
    }
}

impl std::error::Error for AltError {}

/// The distinct tables a message looks up, in first-use order.
#[must_use]
pub fn lookup_tables(message: &SolTxMessage) -> Vec<SolAddress> {
    let mut out: Vec<SolAddress> = Vec::new();
    for lookup in &message.lookups {
        if !out.contains(&lookup.table) {
            out.push(lookup.table);
        }
    }
    out
}

/// Resolves the lookups of `message` against `tables` read at `current_slot`. A legacy message
/// resolves to no addresses. A deactivated table still resolves (display adds a cause).
///
/// # Errors
///
/// [`AltError::Missing`] for a table not in `tables`, [`AltError::Index`],
/// [`AltError::Duplicate`].
pub fn resolve(
    message: &SolTxMessage,
    tables: &[(SolAddress, LookupTable)],
    current_slot: u64,
) -> Result<ResolvedKeys, AltError> {
    let mut resolved = ResolvedKeys::default();
    for lookup in &message.lookups {
        let table = tables
            .iter()
            .find(|(address, _)| *address == lookup.table)
            .map(|(_, table)| table)
            .ok_or(AltError::Missing(lookup.table))?;
        let usable = table
            .addresses
            .get(..table.usable_len(current_slot))
            .unwrap_or(&[]);
        let pick = |index: &u8| {
            usable
                .get(usize::from(*index))
                .copied()
                .ok_or(AltError::Index)
        };
        for index in &lookup.writable {
            resolved.writable.push(pick(index)?);
        }
        for index in &lookup.readonly {
            resolved.readonly.push(pick(index)?);
        }
    }
    let mut seen: HashSet<SolAddress> = HashSet::with_capacity(message.account_count());
    let all = message
        .static_keys
        .iter()
        .chain(&resolved.writable)
        .chain(&resolved.readonly);
    for key in all {
        if !seen.insert(*key) {
            return Err(AltError::Duplicate);
        }
    }
    Ok(resolved)
}

/// What one account key is in a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyRole {
    /// Signs the transaction.
    pub signer: bool,
    /// Writable by the header rule or the load order (before runtime demotion).
    pub writable: bool,
    /// The lookup table it was loaded from (`None` for a static key).
    pub table: Option<SolAddress>,
}

/// Every account key in runtime order with its role: static keys, then the loaded writable,
/// then the loaded read-only ones. Without `loaded` (or with counts that do not match the
/// message) only the static keys are listed.
#[must_use]
pub fn full_keys(
    message: &SolTxMessage,
    loaded: Option<&ResolvedKeys>,
) -> Vec<(SolAddress, KeyRole)> {
    let mut out: Vec<(SolAddress, KeyRole)> = message
        .static_keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            (
                *key,
                KeyRole {
                    signer: message.is_signer(index),
                    writable: message.is_writable_static(index),
                    table: None,
                },
            )
        })
        .collect();
    let Some(loaded) = loaded else {
        return out;
    };
    if message.loaded_counts() != (loaded.writable.len(), loaded.readonly.len()) {
        return out;
    }
    let writable_tables = message
        .lookups
        .iter()
        .flat_map(|lookup| lookup.writable.iter().map(|_| lookup.table));
    for (key, table) in loaded.writable.iter().zip(writable_tables) {
        out.push((
            *key,
            KeyRole {
                signer: false,
                writable: true,
                table: Some(table),
            },
        ));
    }
    let readonly_tables = message
        .lookups
        .iter()
        .flat_map(|lookup| lookup.readonly.iter().map(|_| lookup.table));
    for (key, table) in loaded.readonly.iter().zip(readonly_tables) {
        out.push((
            *key,
            KeyRole {
                signer: false,
                writable: false,
                table: Some(table),
            },
        ));
    }
    out
}
