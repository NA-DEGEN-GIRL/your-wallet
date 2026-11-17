//! `sol::scan` (spec/07 §3.3): the read-only recovery scan of other derivation paths. Public keys
//! come from one `Vault::sol_public_keys` call on the key worker (102 sources: tags 1–2 for
//! `i = 0..=49`, tags 3–4 once; Sollet legacy is not implemented); this module only asks
//! balances by address after the genesis check — SOL and (v1.1) the derived ATA of each
//! allowlisted token — stopping each indexed path after `SOL_SCAN_GAP` consecutive empty
//! accounts ("empty" = 0 lamports and no allowlisted ATA).

use yw_core::bip32::path::AccountIndex;
use yw_core::slip10::SolKeySource;
use yw_core::sol::token::TokenHolding;
use yw_core::sol::{SolAddress, SplAllowEntry};

use super::flow::{SolEndpoint, check_genesis, token_holdings};
use super::rpc as sol_rpc;
use crate::errors::ErrorCode;
use crate::rpc::{RpcClient, Transport, classify};

/// Consecutive empty accounts that end an indexed path.
pub const SOL_SCAN_GAP: u32 = 5;
/// Highest scanned index.
pub const SOL_SCAN_MAX_INDEX: u32 = 49;

/// The sources of one scan in a fixed order: `Standard(0..=49)`, `Bip44Account(0..=49)`,
/// `Bip44Root`, `RawSeed` (102 ≤ the 128 bound of `sol_public_keys`).
#[must_use]
pub fn scan_sources() -> Vec<SolKeySource> {
    let indices = || (0..=SOL_SCAN_MAX_INDEX).filter_map(|i| AccountIndex::new(i).ok());
    let mut out: Vec<SolKeySource> = indices().map(SolKeySource::Standard).collect();
    out.extend(indices().map(SolKeySource::Bip44Account));
    out.push(SolKeySource::Bip44Root);
    out.push(SolKeySource::RawSeed);
    out
}

/// One queried account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanRow {
    /// Source.
    pub source: SolKeySource,
    /// Address.
    pub address: SolAddress,
    /// Lamports (reference).
    pub balance: u64,
    /// Allowlisted token holdings of the cluster (reference).
    pub tokens: Vec<(&'static SplAllowEntry, TokenHolding)>,
}

impl ScanRow {
    /// spec/07 §3.3 "empty": no lamports and every allowlisted ATA missing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.balance == 0
            && self
                .tokens
                .iter()
                .all(|(_, holding)| *holding == TokenHolding::Missing)
    }

    /// Something worth showing: lamports or a positive token balance.
    #[must_use]
    pub fn has_funds(&self) -> bool {
        self.balance > 0
            || self
                .tokens
                .iter()
                .any(|(_, holding)| holding.balance().is_some_and(|amount| amount > 0))
    }
}

fn row(
    client: &RpcClient<'_>,
    endpoint: &SolEndpoint,
    source: SolKeySource,
    address: SolAddress,
) -> Result<ScanRow, ErrorCode> {
    let balance = sol_rpc::balance(client, &endpoint.url, &address).map_err(classify)?;
    let tokens =
        token_holdings(client, &endpoint.url, endpoint.cluster, &address).map_err(classify)?;
    Ok(ScanRow {
        source,
        address,
        balance,
        tokens,
    })
}

/// Runs the scan over `keys` (as produced for [`scan_sources`]).
///
/// # Errors
///
/// The classified failure, or E-RPC-006 for a genesis mismatch.
pub fn scan(
    transport: &dyn Transport,
    endpoint: &SolEndpoint,
    keys: &[(SolKeySource, SolAddress)],
) -> Result<Vec<ScanRow>, ErrorCode> {
    let client = RpcClient::new(transport);
    if !check_genesis(&client, endpoint)? {
        return Err(ErrorCode::Rpc006);
    }
    let mut rows = Vec::new();
    for tag in [1_u8, 2] {
        let mut empty_run = 0_u32;
        for (source, address) in keys.iter().filter(|(source, _)| source.tag() == tag) {
            let found = row(&client, endpoint, *source, *address)?;
            let empty = found.is_empty();
            rows.push(found);
            if empty {
                empty_run = empty_run.saturating_add(1);
                if empty_run >= SOL_SCAN_GAP {
                    break;
                }
            } else {
                empty_run = 0;
            }
        }
    }
    for (source, address) in keys
        .iter()
        .filter(|(source, _)| matches!(source.tag(), 3 | 4))
    {
        rows.push(row(&client, endpoint, *source, *address)?);
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use yw_core::sol::SolAddress;
    use yw_core::sol::template::SPL_ALLOWLIST;
    use yw_core::sol::token::TokenHolding;

    use super::{ScanRow, scan_sources};

    #[test]
    fn sources_fit_one_public_key_call() {
        let sources = scan_sources();
        assert_eq!(sources.len(), 102);
        assert!(sources.len() <= 128);
        assert_eq!(
            sources.iter().filter(|source| source.tag() == 1).count(),
            50
        );
        assert_eq!(
            sources.iter().filter(|source| source.tag() == 2).count(),
            50
        );
    }

    #[test]
    fn empty_means_no_lamports_and_no_allowlisted_ata() {
        let base = ScanRow {
            source: scan_sources()[0],
            address: SolAddress::from_bytes([3; 32]),
            balance: 0,
            tokens: vec![(&SPL_ALLOWLIST[0], TokenHolding::Missing)],
        };
        assert!(base.is_empty() && !base.has_funds());
        let zero_ata = ScanRow {
            tokens: vec![(&SPL_ALLOWLIST[0], TokenHolding::Active(0))],
            ..base.clone()
        };
        assert!(!zero_ata.is_empty() && !zero_ata.has_funds());
        let tokens = ScanRow {
            tokens: vec![(&SPL_ALLOWLIST[0], TokenHolding::Active(5))],
            ..base.clone()
        };
        assert!(!tokens.is_empty() && tokens.has_funds());
        let lamports = ScanRow { balance: 1, ..base };
        assert!(!lamports.is_empty() && lamports.has_funds());
    }
}
