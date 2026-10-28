//! Instruction templates (spec/07 §8): the fixed `T_SOL` transfer (v1), the SPL allowlist with
//! pinned decimals and token program, and the `T_SPL` instruction data (v1.1: ATA
//! `CreateIdempotent` + Token `TransferChecked`).

use super::address::{SolAddress, SolCluster, TOKEN_PROGRAM};
use super::pda::associated_token_address;

/// Largest serialized transaction (spec/07 §7).
pub const SOL_MAX_TX_BYTES: usize = 1_232;
/// `T_SOL` message length.
pub const T_SOL_MESSAGE_LEN: usize = 202;
/// `T_SOL` transaction length (`01 ‖ signature ‖ message`).
pub const T_SOL_TX_LEN: usize = 267;
/// `T_SPL` message length (v1.1).
pub const T_SPL_MESSAGE_LEN: usize = 372;
/// `T_SPL` transaction length (v1.1).
pub const T_SPL_TX_LEN: usize = 437;
/// Largest compute-unit limit of a transaction.
pub const SOL_MAX_COMPUTE_UNITS: u32 = 1_400_000;
/// `T_SOL` header `[num_required_signatures, num_readonly_signed, num_readonly_unsigned]`.
pub const T_SOL_HEADER: [u8; 3] = [1, 0, 2];
/// `T_SPL` header: one writable signer, two writable token accounts, six readonly keys.
pub const T_SPL_HEADER: [u8; 3] = [1, 0, 6];
/// Lamports per SOL.
pub const LAMPORTS_PER_SOL: u64 = 1_000_000_000;
/// SOL decimals.
pub const SOL_DECIMALS: u8 = 9;
/// Size of an SPL token account (`getMinimumBalanceForRentExemption(165)`, spec/07 §11).
pub const TOKEN_ACCOUNT_LEN: usize = 165;
/// Size of an SPL mint account.
pub const MINT_LEN: usize = 82;

/// An allowlisted SPL token (spec/07 §8.3). Identified by mint only; decimals and token program
/// are pinned here and never taken from RPC or on-chain metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SplAllowEntry {
    /// Cluster.
    pub cluster: SolCluster,
    /// Symbol shown (fixed here, not read from chain).
    pub symbol: &'static str,
    /// Mint.
    pub mint: SolAddress,
    /// Pinned decimals (`TransferChecked` data, amount parsing and display).
    pub decimals: u8,
    /// Pinned token program (classic `Tokenkeg…` only).
    pub token_program: SolAddress,
}

/// The SPL allowlist (classic Token program only). Mints and decimals were checked with
/// `getAccountInfo` (owner = Token, 82 bytes, decimals 6, initialized) on 2026-10-27 and again
/// for v1.1 on 2026-10-28 (`docs/acceptance/m7-live-20261027.md`, `m7-spl-20261028.md`).
pub static SPL_ALLOWLIST: [SplAllowEntry; 3] = [
    // EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v
    SplAllowEntry {
        cluster: SolCluster::Mainnet,
        symbol: "USDC",
        mint: SolAddress::from_bytes([
            0xc6, 0xfa, 0x7a, 0xf3, 0xbe, 0xdb, 0xad, 0x3a, 0x3d, 0x65, 0xf3, 0x6a, 0xab, 0xc9,
            0x74, 0x31, 0xb1, 0xbb, 0xe4, 0xc2, 0xd2, 0xf6, 0xe0, 0xe4, 0x7c, 0xa6, 0x02, 0x03,
            0x45, 0x2f, 0x5d, 0x61,
        ]),
        decimals: 6,
        token_program: TOKEN_PROGRAM,
    },
    // Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB
    SplAllowEntry {
        cluster: SolCluster::Mainnet,
        symbol: "USDT",
        mint: SolAddress::from_bytes([
            0xce, 0x01, 0x0e, 0x60, 0xaf, 0xed, 0xb2, 0x27, 0x17, 0xbd, 0x63, 0x19, 0x2f, 0x54,
            0x14, 0x5a, 0x3f, 0x96, 0x5a, 0x33, 0xbb, 0x82, 0xd2, 0xc7, 0x02, 0x9e, 0xb2, 0xce,
            0x1e, 0x20, 0x82, 0x64,
        ]),
        decimals: 6,
        token_program: TOKEN_PROGRAM,
    },
    // 4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU (Circle devnet USDC)
    SplAllowEntry {
        cluster: SolCluster::Devnet,
        symbol: "USDC",
        mint: SolAddress::from_bytes([
            0x3b, 0x44, 0x2c, 0xb3, 0x91, 0x21, 0x57, 0xf1, 0x3a, 0x93, 0x3d, 0x01, 0x34, 0x28,
            0x2d, 0x03, 0x2b, 0x5f, 0xfe, 0xcd, 0x01, 0xa2, 0xdb, 0xf1, 0xb7, 0x79, 0x06, 0x08,
            0xdf, 0x00, 0x2e, 0xa7,
        ]),
        decimals: 6,
        token_program: TOKEN_PROGRAM,
    },
];

/// The allowlist entries of a cluster, in table order.
pub fn spl_entries(cluster: SolCluster) -> impl Iterator<Item = &'static SplAllowEntry> {
    SPL_ALLOWLIST
        .iter()
        .filter(move |entry| entry.cluster == cluster)
}

/// The allowlist entry of `mint` on `cluster` (`None`: not allowlisted there).
#[must_use]
pub fn spl_entry(cluster: SolCluster, mint: &SolAddress) -> Option<&'static SplAllowEntry> {
    spl_entries(cluster).find(|entry| entry.mint == *mint)
}

/// Whether `address` is an allowlisted mint of any cluster (blocked as a recipient).
#[must_use]
pub fn is_allowlisted_mint(address: &SolAddress) -> bool {
    SPL_ALLOWLIST.iter().any(|entry| entry.mint == *address)
}

/// The asset of a transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SolAsset {
    /// Native SOL (lamports).
    Sol,
    /// An allowlisted SPL token (raw units; v1.1).
    Spl(&'static SplAllowEntry),
}

impl SolAsset {
    /// Intent transcript `asset_tag` (1 = SOL, 2 = SPL).
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Sol => 1,
            Self::Spl(_) => 2,
        }
    }

    /// Decimals of the raw amount (SOL 9; SPL the pinned value).
    #[must_use]
    pub const fn decimals(self) -> u8 {
        match self {
            Self::Sol => SOL_DECIMALS,
            Self::Spl(entry) => entry.decimals,
        }
    }

    /// Symbol shown (`SOL`, or the allowlist symbol).
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::Sol => "SOL",
            Self::Spl(entry) => entry.symbol,
        }
    }

    /// The SPL entry, if any.
    #[must_use]
    pub const fn spl(self) -> Option<&'static SplAllowEntry> {
        match self {
            Self::Sol => None,
            Self::Spl(entry) => Some(entry),
        }
    }
}

/// Everything the message bytes decide except the blockhash (spec/07 §2). For SPL the token
/// accounts are derived from `from`/`to` and the entry ([`SplAccounts::of`]), never stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SolTransferCore {
    /// Sender (fee payer, only signer, token owner).
    pub from: SolAddress,
    /// Recipient wallet (for SPL: the owner of the destination ATA).
    pub to: SolAddress,
    /// Asset.
    pub asset: SolAsset,
    /// Lamports (SOL) or raw token units (SPL).
    pub amount: u64,
    /// `SetComputeUnitLimit` units.
    pub cu_limit: u32,
    /// `SetComputeUnitPrice` micro-lamports per CU.
    pub cu_price_micro: u64,
}

/// The derived accounts of an SPL transfer (spec/07 §8.3–§8.4): both ATAs are computed locally
/// with the pinned token program, never taken from RPC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SplAccounts {
    /// The allowlist entry.
    pub entry: &'static SplAllowEntry,
    /// `ATA(from, token_program, mint)`.
    pub from_ata: SolAddress,
    /// `ATA(to, token_program, mint)`.
    pub to_ata: SolAddress,
}

impl SplAccounts {
    /// The accounts of an SPL core; `None` for SOL (or the practically impossible case that no
    /// bump yields a PDA, which then fails closed everywhere).
    #[must_use]
    pub fn of(core: &SolTransferCore) -> Option<Self> {
        let entry = core.asset.spl()?;
        let (from_ata, _) =
            associated_token_address(&core.from, &entry.token_program, &entry.mint).ok()?;
        let (to_ata, _) =
            associated_token_address(&core.to, &entry.token_program, &entry.mint).ok()?;
        Some(Self {
            entry,
            from_ata,
            to_ata,
        })
    }
}

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

/// ATA `CreateIdempotent` data: `01` (spl-associated-token-account `instruction.rs`).
pub const ATA_CREATE_IDEMPOTENT: [u8; 1] = [0x01];
/// Token `TransferChecked` instruction tag.
pub const TOKEN_TRANSFER_CHECKED_TAG: u8 = 0x0c;

/// Token `TransferChecked` data: `0c ‖ u64 LE amount ‖ u8 decimals`.
#[must_use]
pub fn transfer_checked_data(amount: u64, decimals: u8) -> Vec<u8> {
    let mut data = Vec::with_capacity(10);
    data.push(TOKEN_TRANSFER_CHECKED_TAG);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    data
}

#[cfg(test)]
mod tests {
    use super::{
        SPL_ALLOWLIST, SolAsset, is_allowlisted_mint, spl_entries, spl_entry, system_transfer_data,
        transfer_checked_data,
    };
    use crate::sol::address::{SolAddress, SolCluster, TOKEN_PROGRAM};

    #[test]
    fn system_transfer_42_lamports() {
        assert_eq!(
            system_transfer_data(42),
            [0x02, 0, 0, 0, 0x2a, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn transfer_checked_layout() {
        assert_eq!(
            transfer_checked_data(1_000_000, 6),
            [0x0c, 0x40, 0x42, 0x0f, 0, 0, 0, 0, 0, 0x06]
        );
    }

    #[test]
    fn allowlist_mints_are_the_spec_table() {
        let texts: Vec<(SolCluster, &str, String)> = SPL_ALLOWLIST
            .iter()
            .map(|entry| (entry.cluster, entry.symbol, entry.mint.to_base58()))
            .collect();
        assert_eq!(
            texts,
            [
                (
                    SolCluster::Mainnet,
                    "USDC",
                    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_owned()
                ),
                (
                    SolCluster::Mainnet,
                    "USDT",
                    "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB".to_owned()
                ),
                (
                    SolCluster::Devnet,
                    "USDC",
                    "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU".to_owned()
                ),
            ]
        );
        for entry in &SPL_ALLOWLIST {
            assert_eq!(entry.decimals, 6);
            assert_eq!(entry.token_program, TOKEN_PROGRAM);
            assert!(is_allowlisted_mint(&entry.mint));
        }
        assert_eq!(spl_entries(SolCluster::Mainnet).count(), 2);
        assert_eq!(spl_entries(SolCluster::Devnet).count(), 1);
        let mainnet_usdc = SPL_ALLOWLIST[0].mint;
        assert!(spl_entry(SolCluster::Mainnet, &mainnet_usdc).is_some());
        assert!(spl_entry(SolCluster::Devnet, &mainnet_usdc).is_none());
        assert!(!is_allowlisted_mint(&SolAddress::from_bytes([5; 32])));
        let usdc = SolAsset::Spl(&SPL_ALLOWLIST[0]);
        assert_eq!((usdc.tag(), usdc.decimals(), usdc.symbol()), (2, 6, "USDC"));
        assert_eq!(
            (
                SolAsset::Sol.tag(),
                SolAsset::Sol.decimals(),
                SolAsset::Sol.symbol()
            ),
            (1, 9, "SOL")
        );
    }
}
