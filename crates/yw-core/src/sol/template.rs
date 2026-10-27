//! Instruction templates (spec/07 §8): the fixed `T_SOL` transfer of v1 and the SPL allowlist
//! (the allowlisted mints are already blocked as recipients; `T_SPL` itself is v1.1).

use super::address::{SolAddress, SolCluster};

/// Largest serialized transaction (spec/07 §7).
pub const SOL_MAX_TX_BYTES: usize = 1_232;
/// `T_SOL` message length.
pub const T_SOL_MESSAGE_LEN: usize = 202;
/// `T_SOL` transaction length (`01 ‖ signature ‖ message`).
pub const T_SOL_TX_LEN: usize = 267;
/// Largest compute-unit limit of a transaction.
pub const SOL_MAX_COMPUTE_UNITS: u32 = 1_400_000;
/// `T_SOL` header `[num_required_signatures, num_readonly_signed, num_readonly_unsigned]`.
pub const T_SOL_HEADER: [u8; 3] = [1, 0, 2];
/// `T_SPL` header (v1.1; rejected as an unknown template in v1).
pub const T_SPL_HEADER: [u8; 3] = [1, 0, 6];
/// Lamports per SOL.
pub const LAMPORTS_PER_SOL: u64 = 1_000_000_000;
/// SOL decimals.
pub const SOL_DECIMALS: u8 = 9;

/// The asset of a transfer (v1: SOL only; `Spl` arrives with v1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SolAsset {
    /// Native SOL (lamports).
    Sol,
}

impl SolAsset {
    /// Intent transcript `asset_tag` (1 = SOL, 2 = SPL).
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Sol => 1,
        }
    }
}

/// Everything the message bytes decide except the blockhash (spec/07 §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SolTransferCore {
    /// Sender (fee payer, only signer).
    pub from: SolAddress,
    /// Recipient wallet.
    pub to: SolAddress,
    /// Asset.
    pub asset: SolAsset,
    /// Lamports (SOL).
    pub amount: u64,
    /// `SetComputeUnitLimit` units.
    pub cu_limit: u32,
    /// `SetComputeUnitPrice` micro-lamports per CU.
    pub cu_price_micro: u64,
}

/// An allowlisted SPL token (spec/07 §8.3; identified by mint only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SplAllowEntry {
    /// Cluster.
    pub cluster: SolCluster,
    /// Symbol shown.
    pub symbol: &'static str,
    /// Mint (base58).
    pub mint: &'static str,
    /// Fixed decimals.
    pub decimals: u8,
}

/// The SPL allowlist (classic Token program only). Devnet USDC is Circle's devnet mint, checked
/// with `getAccountInfo` (owner = Token, decimals = 6) on 2026-10-27
/// (`docs/acceptance/m7-live-20261027.md`).
pub const SPL_ALLOWLIST: [SplAllowEntry; 3] = [
    SplAllowEntry {
        cluster: SolCluster::Mainnet,
        symbol: "USDC",
        mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        decimals: 6,
    },
    SplAllowEntry {
        cluster: SolCluster::Mainnet,
        symbol: "USDT",
        mint: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
        decimals: 6,
    },
    SplAllowEntry {
        cluster: SolCluster::Devnet,
        symbol: "USDC",
        mint: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
        decimals: 6,
    },
];

/// `SetComputeUnitLimit` data: `02 ‖ u32 LE`.
#[must_use]
pub fn set_compute_unit_limit_data(units: u32) -> Vec<u8> {
    let mut data = Vec::with_capacity(5);
    data.push(0x02);
    data.extend_from_slice(&units.to_le_bytes());
    data
}

/// `SetComputeUnitPrice` data: `03 ‖ u64 LE`.
#[must_use]
pub fn set_compute_unit_price_data(micro_lamports: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(9);
    data.push(0x03);
    data.extend_from_slice(&micro_lamports.to_le_bytes());
    data
}

/// System `Transfer` data: `u32 LE 2 ‖ u64 LE lamports`.
#[must_use]
pub fn system_transfer_data(lamports: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2_u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    data
}

#[cfg(test)]
mod tests {
    use super::{SPL_ALLOWLIST, system_transfer_data};
    use crate::sol::address::SolAddress;

    #[test]
    fn system_transfer_42_lamports() {
        assert_eq!(
            system_transfer_data(42),
            [0x02, 0, 0, 0, 0x2a, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn allowlist_mints_decode() {
        for entry in SPL_ALLOWLIST {
            assert!(SolAddress::parse(entry.mint).is_ok(), "{}", entry.mint);
            assert_eq!(entry.decimals, 6);
        }
    }
}
