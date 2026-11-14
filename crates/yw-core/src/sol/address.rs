//! Solana addresses, clusters and curve classification (spec/07 §2, §5, §8.1, §12.1, §15.1).

use core::fmt;

use curve25519_dalek::edwards::CompressedEdwardsY;

use crate::codec::base58::{Base58Error, base58_decode_32, base58_encode};

/// A 32-byte Solana address (Ed25519 public key or program-derived address).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SolAddress([u8; 32]);

impl SolAddress {
    /// Wraps raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The raw bytes by value.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Strict base58 → 32 bytes (spec/07 §5): no trimming, no URI.
    ///
    /// # Errors
    ///
    /// The strict [`Base58Error`] variants.
    pub fn parse(text: &str) -> Result<Self, Base58Error> {
        base58_decode_32(text).map(Self)
    }

    /// UI input: only leading/trailing ASCII space, TAB, LF and CR are removed before the strict
    /// parser (spec/07 §5). Inner whitespace, `solana:` URIs and queries are errors.
    ///
    /// # Errors
    ///
    /// The strict [`Base58Error`] variants.
    pub fn parse_input(text: &str) -> Result<Self, Base58Error> {
        let trimmed = text.trim_matches(|character| matches!(character, ' ' | '\t' | '\n' | '\r'));
        Self::parse(trimmed)
    }

    /// The base58 text.
    #[must_use]
    pub fn to_base58(self) -> String {
        base58_encode(&self.0)
    }
}

impl fmt::Debug for SolAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SolAddress({})", self.to_base58())
    }
}

impl fmt::Display for SolAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_base58())
    }
}

/// The address split into 4-character groups separated by one space (spec/07 §12.3: the full
/// address, never shortened; spaces only widen the drawing).
#[must_use]
pub fn grouped(address: &SolAddress) -> String {
    let text = address.to_base58();
    let characters: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len().saturating_add(12));
    for (index, chunk) in characters.chunks(4).enumerate() {
        if index != 0 {
            out.push(' ');
        }
        out.extend(chunk.iter());
    }
    out
}

/// System program `11111111111111111111111111111111`.
pub const SYSTEM_PROGRAM: SolAddress = SolAddress([0; 32]);
/// `ComputeBudget111111111111111111111111111111`.
pub const COMPUTE_BUDGET_PROGRAM: SolAddress = SolAddress([
    0x03, 0x06, 0x46, 0x6f, 0xe5, 0x21, 0x17, 0x32, 0xff, 0xec, 0xad, 0xba, 0x72, 0xc3, 0x9b, 0xe7,
    0xbc, 0x8c, 0xe5, 0xbb, 0xc5, 0xf7, 0x12, 0x6b, 0x2c, 0x43, 0x9b, 0x3a, 0x40, 0x00, 0x00, 0x00,
]);
/// Classic SPL Token program `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`.
pub const TOKEN_PROGRAM: SolAddress = SolAddress([
    0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93, 0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac,
    0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91, 0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9,
]);
/// Associated Token Account program `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`.
pub const ATA_PROGRAM: SolAddress = SolAddress([
    0x8c, 0x97, 0x25, 0x8f, 0x4e, 0x24, 0x89, 0xf1, 0xbb, 0x3d, 0x10, 0x29, 0x14, 0x8e, 0x0d, 0x83,
    0x0b, 0x5a, 0x13, 0x99, 0xda, 0xff, 0x10, 0x84, 0x04, 0x8e, 0x7b, 0xd8, 0xdb, 0xe9, 0xf8, 0x59,
]);
/// Token-2022 program `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`.
pub const TOKEN_2022_PROGRAM: SolAddress = SolAddress([
    0x06, 0xdd, 0xf6, 0xe1, 0xee, 0x75, 0x8f, 0xde, 0x18, 0x42, 0x5d, 0xbc, 0xe4, 0x6c, 0xcd, 0xda,
    0xb6, 0x1a, 0xfc, 0x4d, 0x83, 0xb9, 0x0d, 0x27, 0xfe, 0xbd, 0xf9, 0x28, 0xd8, 0xa1, 0x8b, 0xfc,
]);
/// Memo program v1 `Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo`.
pub const MEMO_PROGRAM_V1: SolAddress = SolAddress([
    0x05, 0x4a, 0x53, 0x50, 0xf8, 0x5d, 0xc8, 0x82, 0xd6, 0x14, 0xa5, 0x56, 0x72, 0x78, 0x8a, 0x29,
    0x6d, 0xdf, 0x1e, 0xab, 0xab, 0xd0, 0xa6, 0x06, 0x78, 0x88, 0x49, 0x32, 0xf4, 0xee, 0xf6, 0xa0,
]);
/// Memo program v2 `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`.
pub const MEMO_PROGRAM_V2: SolAddress = SolAddress([
    0x05, 0x4a, 0x53, 0x5a, 0x99, 0x29, 0x21, 0x06, 0x4d, 0x24, 0xe8, 0x71, 0x60, 0xda, 0x38, 0x7c,
    0x7c, 0x35, 0xb5, 0xdd, 0xbc, 0x92, 0xbb, 0x81, 0xe4, 0x1f, 0xa8, 0x40, 0x41, 0x05, 0x44, 0x8d,
]);
/// Address lookup table program `AddressLookupTab1e1111111111111111111111111`.
pub const ADDRESS_LOOKUP_TABLE_PROGRAM: SolAddress = SolAddress([
    0x02, 0x77, 0xa6, 0xaf, 0x97, 0x33, 0x9b, 0x7a, 0xc8, 0x8d, 0x18, 0x92, 0xc9, 0x04, 0x46, 0xf5,
    0x00, 0x02, 0x30, 0x92, 0x66, 0xf6, 0x2e, 0x53, 0xc1, 0x18, 0x24, 0x49, 0x82, 0x00, 0x00, 0x00,
]);
/// Stake program `Stake11111111111111111111111111111111111111`.
pub const STAKE_PROGRAM: SolAddress = SolAddress([
    0x06, 0xa1, 0xd8, 0x17, 0x91, 0x37, 0x54, 0x2a, 0x98, 0x34, 0x37, 0xbd, 0xfe, 0x2a, 0x7a, 0xb2,
    0x55, 0x7f, 0x53, 0x5c, 0x8a, 0x78, 0x72, 0x2b, 0x68, 0xa4, 0x9d, 0xc0, 0x00, 0x00, 0x00, 0x00,
]);
/// Vote program `Vote111111111111111111111111111111111111111`.
pub const VOTE_PROGRAM: SolAddress = SolAddress([
    0x07, 0x61, 0x48, 0x1d, 0x35, 0x74, 0x74, 0xbb, 0x7c, 0x4d, 0x76, 0x24, 0xeb, 0xd3, 0xbd, 0xb3,
    0xd8, 0x35, 0x5e, 0x73, 0xd1, 0x10, 0x43, 0xfc, 0x0d, 0xa3, 0x53, 0x80, 0x00, 0x00, 0x00, 0x00,
]);
/// Config program `Config1111111111111111111111111111111111111`.
pub const CONFIG_PROGRAM: SolAddress = SolAddress([
    0x03, 0x06, 0x4a, 0xa3, 0x00, 0x2f, 0x74, 0xdc, 0xc8, 0x6e, 0x43, 0x31, 0x0f, 0x0c, 0x05, 0x2a,
    0xf8, 0xc5, 0xda, 0x27, 0xf6, 0x10, 0x40, 0x19, 0xa3, 0x23, 0xef, 0xa0, 0x00, 0x00, 0x00, 0x00,
]);
/// BPF loader v2 `BPFLoader2111111111111111111111111111111111`.
pub const BPF_LOADER: SolAddress = SolAddress([
    0x02, 0xa8, 0xf6, 0x91, 0x4e, 0x88, 0xa1, 0x6e, 0x39, 0x5a, 0xe1, 0x28, 0x94, 0x8f, 0xfa, 0x69,
    0x56, 0x93, 0x37, 0x68, 0x18, 0xdd, 0x47, 0x43, 0x52, 0x21, 0xf3, 0xc6, 0x00, 0x00, 0x00, 0x00,
]);
/// Deprecated BPF loader (v1) `BPFLoader1111111111111111111111111111111111`.
pub const BPF_LOADER_DEPRECATED: SolAddress = SolAddress([
    0x02, 0xa8, 0xf6, 0x91, 0x4e, 0x88, 0xa1, 0x6b, 0xbd, 0x23, 0x95, 0x85, 0x5f, 0x64, 0x04, 0xd9,
    0xb4, 0xf4, 0x56, 0xb7, 0x82, 0x1b, 0xb0, 0x14, 0x57, 0x49, 0x42, 0x8c, 0x00, 0x00, 0x00, 0x00,
]);
/// Upgradeable BPF loader (v3) `BPFLoaderUpgradeab1e11111111111111111111111`.
pub const BPF_LOADER_UPGRADEABLE: SolAddress = SolAddress([
    0x02, 0xa8, 0xf6, 0x91, 0x4e, 0x88, 0xa1, 0xb0, 0xe2, 0x10, 0x15, 0x3e, 0xf7, 0x63, 0xae, 0x2b,
    0x00, 0xc2, 0xb9, 0x3d, 0x16, 0xc1, 0x24, 0xd2, 0xc0, 0x53, 0x7a, 0x10, 0x04, 0x80, 0x00, 0x00,
]);
/// Ed25519 signature-verify precompile `Ed25519SigVerify111111111111111111111111111`.
pub const ED25519_PRECOMPILE: SolAddress = SolAddress([
    0x03, 0x7d, 0x46, 0xd6, 0x7c, 0x93, 0xfb, 0xbe, 0x12, 0xf9, 0x42, 0x8f, 0x83, 0x8d, 0x40, 0xff,
    0x05, 0x70, 0x74, 0x49, 0x27, 0xf4, 0x8a, 0x64, 0xfc, 0xca, 0x70, 0x44, 0x80, 0x00, 0x00, 0x00,
]);
/// Secp256k1 (Keccak) signature-verify precompile `KeccakSecp256k11111111111111111111111111111`.
pub const SECP256K1_PRECOMPILE: SolAddress = SolAddress([
    0x04, 0xc6, 0xfc, 0x20, 0xf0, 0x50, 0xcc, 0xf0, 0x55, 0x84, 0xd7, 0x21, 0x1c, 0x9f, 0x8c, 0xf5,
    0x9e, 0xc1, 0x47, 0x85, 0xbb, 0x16, 0x6a, 0x1e, 0x28, 0x30, 0xe8, 0x12, 0x20, 0x00, 0x00, 0x00,
]);
/// Secp256r1 signature-verify precompile `Secp256r1SigVerify1111111111111111111111111`.
pub const SECP256R1_PRECOMPILE: SolAddress = SolAddress([
    0x06, 0x92, 0x0d, 0xec, 0x2f, 0xea, 0x71, 0xb5, 0xb7, 0x23, 0x81, 0x4d, 0x74, 0x2d, 0xa9, 0x03,
    0x1c, 0x83, 0xe7, 0x5f, 0xdb, 0x79, 0x5d, 0x56, 0x8e, 0x75, 0x47, 0x80, 0x20, 0x00, 0x00, 0x00,
]);
/// Rent sysvar `SysvarRent111111111111111111111111111111111`.
pub const SYSVAR_RENT: SolAddress = SolAddress([
    0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2c, 0x5c, 0x51, 0x21, 0x8c, 0xc9, 0x4c, 0x3d, 0x4a, 0xf1, 0x7f,
    0x58, 0xda, 0xee, 0x08, 0x9b, 0xa1, 0xfd, 0x44, 0xe3, 0xdb, 0xd9, 0x8a, 0x00, 0x00, 0x00, 0x00,
]);
/// Clock sysvar `SysvarC1ock11111111111111111111111111111111`.
pub const SYSVAR_CLOCK: SolAddress = SolAddress([
    0x06, 0xa7, 0xd5, 0x17, 0x18, 0xc7, 0x74, 0xc9, 0x28, 0x56, 0x63, 0x98, 0x69, 0x1d, 0x5e, 0xb6,
    0x8b, 0x5e, 0xb8, 0xa3, 0x9b, 0x4b, 0x6d, 0x5c, 0x73, 0x55, 0x5b, 0x21, 0x00, 0x00, 0x00, 0x00,
]);
/// Instructions sysvar `Sysvar1nstructions1111111111111111111111111`.
pub const SYSVAR_INSTRUCTIONS: SolAddress = SolAddress([
    0x06, 0xa7, 0xd5, 0x17, 0x18, 0x7b, 0xd1, 0x66, 0x35, 0xda, 0xd4, 0x04, 0x55, 0xfd, 0xc2, 0xc0,
    0xc1, 0x24, 0xc6, 0x8f, 0x21, 0x56, 0x75, 0xa5, 0xdb, 0xba, 0xcb, 0x5f, 0x08, 0x00, 0x00, 0x00,
]);
/// Recent blockhashes sysvar (durable nonce instructions) `SysvarRecentB1ockHashes11111111111111111111`.
pub const SYSVAR_RECENT_BLOCKHASHES: SolAddress = SolAddress([
    0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2c, 0x56, 0x8e, 0xe0, 0x8a, 0x84, 0x5f, 0x73, 0xd2, 0x97, 0x88,
    0xcf, 0x03, 0x5c, 0x31, 0x45, 0xb2, 0x1a, 0xb3, 0x44, 0xd8, 0x06, 0x2e, 0xa9, 0x40, 0x00, 0x00,
]);
/// Wrapped SOL mint `So11111111111111111111111111111111111111112`.
pub const WSOL_MINT: SolAddress = SolAddress([
    0x06, 0x9b, 0x88, 0x57, 0xfe, 0xab, 0x81, 0x84, 0xfb, 0x68, 0x7f, 0x63, 0x46, 0x18, 0xc0, 0x35,
    0xda, 0xc4, 0x39, 0xdc, 0x1a, 0xeb, 0x3b, 0x55, 0x98, 0xa0, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x01,
]);

/// The display name of a well-known program (spec/07 §20.4): the programs the dApp decoder
/// interprets, and those it only names (Stake, Vote, Config, the loaders, ALT) while still
/// showing their instructions raw. `None` for every other address.
#[must_use]
pub fn program_name(program: &SolAddress) -> Option<&'static str> {
    const NAMES: [(SolAddress, &str); 17] = [
        (SYSTEM_PROGRAM, "System"),
        (TOKEN_PROGRAM, "Token"),
        (TOKEN_2022_PROGRAM, "Token-2022"),
        (ATA_PROGRAM, "Associated Token Account"),
        (COMPUTE_BUDGET_PROGRAM, "Compute Budget"),
        (MEMO_PROGRAM_V1, "Memo v1"),
        (MEMO_PROGRAM_V2, "Memo"),
        (ADDRESS_LOOKUP_TABLE_PROGRAM, "Address Lookup Table"),
        (STAKE_PROGRAM, "Stake"),
        (VOTE_PROGRAM, "Vote"),
        (CONFIG_PROGRAM, "Config"),
        (BPF_LOADER, "BPF Loader 2"),
        (BPF_LOADER_DEPRECATED, "BPF Loader (deprecated)"),
        (BPF_LOADER_UPGRADEABLE, "BPF Upgradeable Loader"),
        (ED25519_PRECOMPILE, "Ed25519 SigVerify"),
        (SECP256K1_PRECOMPILE, "Secp256k1 SigVerify"),
        (SECP256R1_PRECOMPILE, "Secp256r1 SigVerify"),
    ];
    NAMES
        .iter()
        .find(|(address, _)| address == program)
        .map(|(_, name)| *name)
}

/// Solana mainnet genesis hash `5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d` (spec/07 §15.1).
pub const MAINNET_GENESIS: [u8; 32] = [
    0x45, 0x29, 0x69, 0x98, 0xa6, 0xf8, 0xe2, 0xa7, 0x84, 0xdb, 0x5d, 0x9f, 0x95, 0xe1, 0x8f, 0xc2,
    0x3f, 0x70, 0x44, 0x1a, 0x10, 0x39, 0x44, 0x68, 0x01, 0x08, 0x98, 0x79, 0xb0, 0x8c, 0x7e, 0xf0,
];
/// Solana devnet genesis hash `EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG`.
pub const DEVNET_GENESIS: [u8; 32] = [
    0xce, 0x59, 0xdb, 0x50, 0x80, 0xfc, 0x2c, 0x6d, 0x3b, 0xcf, 0x7c, 0xa9, 0x07, 0x12, 0xd3, 0xc2,
    0xe5, 0xe6, 0xc2, 0x8f, 0x27, 0xf0, 0xdf, 0xbb, 0x99, 0x53, 0xbd, 0xb0, 0x89, 0x4c, 0x03, 0xab,
];

/// Solana cluster (spec/07 §2; digest/journal byte 1 mainnet, 2 devnet).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SolCluster {
    /// `solana:mainnet`.
    Mainnet = 1,
    /// `solana:devnet`.
    Devnet = 2,
}

impl SolCluster {
    /// The byte code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Parses the byte code.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Mainnet),
            2 => Some(Self::Devnet),
            _ => None,
        }
    }

    /// The pinned genesis hash (spec/07 §15.1).
    #[must_use]
    pub const fn genesis(self) -> [u8; 32] {
        match self {
            Self::Mainnet => MAINNET_GENESIS,
            Self::Devnet => DEVNET_GENESIS,
        }
    }

    /// The display name used in titles and the network field in `lang` (devnet marked as a test
    /// network; spec/14). 2026-11-14 (Step 3): the Korean-only `display_name` is gone.
    #[must_use]
    pub const fn display_name_in(self, lang: crate::lang::Lang) -> &'static str {
        match self {
            Self::Mainnet => "Solana mainnet",
            Self::Devnet => super::text::CLUSTER_DEVNET.get(lang),
        }
    }

    /// `solana:mainnet` / `solana:devnet` (spec/02 §5.3 `NetworkId`).
    #[must_use]
    pub const fn network_id(self) -> &'static str {
        match self {
            Self::Mainnet => "solana:mainnet",
            Self::Devnet => "solana:devnet",
        }
    }
}

/// `CompressedEdwardsY::from_slice(b).decompress().is_some()` — the same notion of "on curve" as
/// Solana's `bytes_are_curve_point` (spec/07 §8.4).
#[must_use]
pub fn is_on_curve_solana(bytes: &[u8; 32]) -> bool {
    CompressedEdwardsY::from_slice(bytes)
        .ok()
        .and_then(|compressed| compressed.decompress())
        .is_some()
}

/// Curve class of a 32-byte address (spec/07 §12.1 checks 3 and 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CurveClass {
    /// A canonical point of large order: a normal wallet key.
    OnCurve,
    /// Not a curve point: a program-derived address or other off-curve key.
    OffCurve,
    /// A small-order point (no usable private key; the System ID is one).
    SmallOrder,
    /// Decompresses but re-compresses to other bytes (non-canonical y).
    NonCanonical,
}

/// Classifies `bytes`.
#[must_use]
pub fn curve_class(bytes: &[u8; 32]) -> CurveClass {
    let Some(point) = CompressedEdwardsY::from_slice(bytes)
        .ok()
        .and_then(|compressed| compressed.decompress())
    else {
        return CurveClass::OffCurve;
    };
    if point.is_small_order() {
        CurveClass::SmallOrder
    } else if point.compress().to_bytes() != *bytes {
        CurveClass::NonCanonical
    } else {
        CurveClass::OnCurve
    }
}

/// Program and sysvar addresses that are never valid recipients (spec/07 §12.1 check 2).
pub const SOL_BLOCKED_RECIPIENTS: [&str; 27] = [
    "11111111111111111111111111111111",
    "ComputeBudget111111111111111111111111111111",
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
    "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
    "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo",
    "So11111111111111111111111111111111111111112",
    "Stake11111111111111111111111111111111111111",
    "Vote111111111111111111111111111111111111111",
    "BPFLoaderUpgradeab1e11111111111111111111111",
    "BPFLoader2111111111111111111111111111111111",
    "BPFLoader1111111111111111111111111111111111",
    "NativeLoader1111111111111111111111111111111",
    "Config1111111111111111111111111111111111111",
    "AddressLookupTab1e1111111111111111111111111",
    "Sysvar1111111111111111111111111111111111111",
    "SysvarRent111111111111111111111111111111111",
    "SysvarC1ock11111111111111111111111111111111",
    "SysvarRecentB1ockHashes11111111111111111111",
    "SysvarEpochSchedu1e111111111111111111111111",
    "SysvarFees111111111111111111111111111111111",
    "Sysvar1nstructions1111111111111111111111111",
    "SysvarS1otHashes111111111111111111111111111",
    "SysvarStakeHistory1111111111111111111111111",
    "Ed25519SigVerify111111111111111111111111111",
    "KeccakSecp256k11111111111111111111111111111",
];

/// Whether `address` is a blocked program/sysvar or an allowlisted SPL mint of any cluster.
#[must_use]
pub fn is_blocked_recipient(address: &SolAddress) -> bool {
    let text = address.to_base58();
    SOL_BLOCKED_RECIPIENTS.contains(&text.as_str())
        || crate::sol::template::is_allowlisted_mint(address)
}

/// The runtime's reserved account keys among `SOL_BLOCKED_RECIPIENTS` (the builtins, loaders,
/// precompiles and sysvars, not the SPL programs or the wSOL mint): a transaction can mark them
/// writable, but the runtime loads them read-only (spec/07 §20.6 `0x0513`). A key missing here
/// is only shown writable, never the other way round.
pub const SOL_RESERVED_KEYS: [&str; 21] = [
    "11111111111111111111111111111111",
    "ComputeBudget111111111111111111111111111111",
    "Stake11111111111111111111111111111111111111",
    "Vote111111111111111111111111111111111111111",
    "BPFLoaderUpgradeab1e11111111111111111111111",
    "BPFLoader2111111111111111111111111111111111",
    "BPFLoader1111111111111111111111111111111111",
    "NativeLoader1111111111111111111111111111111",
    "Config1111111111111111111111111111111111111",
    "AddressLookupTab1e1111111111111111111111111",
    "Sysvar1111111111111111111111111111111111111",
    "SysvarRent111111111111111111111111111111111",
    "SysvarC1ock11111111111111111111111111111111",
    "SysvarRecentB1ockHashes11111111111111111111",
    "SysvarEpochSchedu1e111111111111111111111111",
    "SysvarFees111111111111111111111111111111111",
    "Sysvar1nstructions1111111111111111111111111",
    "SysvarS1otHashes111111111111111111111111111",
    "SysvarStakeHistory1111111111111111111111111",
    "Ed25519SigVerify111111111111111111111111111",
    "KeccakSecp256k11111111111111111111111111111",
];

/// Whether `address` is exactly one of `SOL_RESERVED_KEYS`.
#[must_use]
pub fn is_reserved_key(address: &SolAddress) -> bool {
    SOL_RESERVED_KEYS.contains(&address.to_base58().as_str())
}

#[cfg(test)]
mod tests {
    use super::{
        ADDRESS_LOOKUP_TABLE_PROGRAM, ATA_PROGRAM, BPF_LOADER, BPF_LOADER_DEPRECATED,
        BPF_LOADER_UPGRADEABLE, COMPUTE_BUDGET_PROGRAM, CONFIG_PROGRAM, CurveClass, DEVNET_GENESIS,
        ED25519_PRECOMPILE, MAINNET_GENESIS, MEMO_PROGRAM_V1, MEMO_PROGRAM_V2,
        SECP256K1_PRECOMPILE, SECP256R1_PRECOMPILE, SOL_BLOCKED_RECIPIENTS, SOL_RESERVED_KEYS,
        STAKE_PROGRAM, SYSTEM_PROGRAM, SYSVAR_CLOCK, SYSVAR_INSTRUCTIONS,
        SYSVAR_RECENT_BLOCKHASHES, SYSVAR_RENT, SolAddress, SolCluster, TOKEN_2022_PROGRAM,
        TOKEN_PROGRAM, VOTE_PROGRAM, WSOL_MINT, curve_class, grouped, is_on_curve_solana,
        is_reserved_key, program_name,
    };

    /// Every named constant with its base58 text (spec/07 §20.4 names in `program_name`).
    const NAMED: [(SolAddress, &str); 22] = [
        (SYSTEM_PROGRAM, "11111111111111111111111111111111"),
        (
            COMPUTE_BUDGET_PROGRAM,
            "ComputeBudget111111111111111111111111111111",
        ),
        (TOKEN_PROGRAM, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
        (ATA_PROGRAM, "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"),
        (
            TOKEN_2022_PROGRAM,
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
        ),
        (
            MEMO_PROGRAM_V1,
            "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo",
        ),
        (
            MEMO_PROGRAM_V2,
            "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
        ),
        (
            ADDRESS_LOOKUP_TABLE_PROGRAM,
            "AddressLookupTab1e1111111111111111111111111",
        ),
        (STAKE_PROGRAM, "Stake11111111111111111111111111111111111111"),
        (VOTE_PROGRAM, "Vote111111111111111111111111111111111111111"),
        (
            CONFIG_PROGRAM,
            "Config1111111111111111111111111111111111111",
        ),
        (BPF_LOADER, "BPFLoader2111111111111111111111111111111111"),
        (
            BPF_LOADER_DEPRECATED,
            "BPFLoader1111111111111111111111111111111111",
        ),
        (
            BPF_LOADER_UPGRADEABLE,
            "BPFLoaderUpgradeab1e11111111111111111111111",
        ),
        (
            ED25519_PRECOMPILE,
            "Ed25519SigVerify111111111111111111111111111",
        ),
        (
            SECP256K1_PRECOMPILE,
            "KeccakSecp256k11111111111111111111111111111",
        ),
        (
            SECP256R1_PRECOMPILE,
            "Secp256r1SigVerify1111111111111111111111111",
        ),
        (SYSVAR_RENT, "SysvarRent111111111111111111111111111111111"),
        (SYSVAR_CLOCK, "SysvarC1ock11111111111111111111111111111111"),
        (
            SYSVAR_INSTRUCTIONS,
            "Sysvar1nstructions1111111111111111111111111",
        ),
        (
            SYSVAR_RECENT_BLOCKHASHES,
            "SysvarRecentB1ockHashes11111111111111111111",
        ),
        (WSOL_MINT, "So11111111111111111111111111111111111111112"),
    ];

    #[test]
    fn constants_decode_and_round_trip() {
        assert_eq!(
            SolAddress::parse("ComputeBudget111111111111111111111111111111").unwrap(),
            COMPUTE_BUDGET_PROGRAM
        );
        assert_eq!(
            SolAddress::parse("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap(),
            TOKEN_PROGRAM
        );
        assert_eq!(
            SolAddress::parse("5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d")
                .unwrap()
                .to_bytes(),
            MAINNET_GENESIS
        );
        assert_eq!(
            SolAddress::parse("EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG")
                .unwrap()
                .to_bytes(),
            DEVNET_GENESIS
        );
        let mut seen = std::collections::HashSet::new();
        for text in SOL_BLOCKED_RECIPIENTS {
            let address = SolAddress::parse(text).unwrap();
            assert_eq!(address.to_base58(), text);
            assert!(seen.insert(address), "{text}");
        }
        assert_eq!(SolCluster::from_code(2), Some(SolCluster::Devnet));
        assert_eq!(SolCluster::from_code(3), None);
        let mut named = std::collections::HashSet::new();
        for (constant, text) in NAMED {
            assert_eq!(constant.to_base58(), text);
            assert_eq!(SolAddress::parse(text).unwrap(), constant);
            assert!(named.insert(constant), "{text}");
        }
        // Every named constant the blocked-recipient table lists is the same address there.
        for text in SOL_BLOCKED_RECIPIENTS {
            if let Some((constant, _)) = NAMED.iter().find(|(_, named)| *named == text) {
                assert_eq!(SolAddress::parse(text).unwrap(), *constant);
            }
        }
        // Only the Secp256r1 precompile is newer than the blocked-recipient table.
        let unlisted: Vec<&str> = NAMED
            .iter()
            .map(|(_, text)| *text)
            .filter(|text| !SOL_BLOCKED_RECIPIENTS.contains(text))
            .collect();
        assert_eq!(unlisted, ["Secp256r1SigVerify1111111111111111111111111"]);
    }

    #[test]
    fn program_names() {
        for (constant, text) in NAMED {
            let sysvar_or_mint = text.starts_with("Sysvar") || constant == WSOL_MINT;
            assert_eq!(program_name(&constant).is_some(), !sysvar_or_mint, "{text}");
        }
        assert_eq!(program_name(&TOKEN_2022_PROGRAM), Some("Token-2022"));
        assert_eq!(program_name(&STAKE_PROGRAM), Some("Stake"));
        assert_eq!(program_name(&SolAddress::from_bytes([9; 32])), None);
    }

    #[test]
    fn reserved_keys_are_the_blocked_list_without_spl() {
        let spl = [
            TOKEN_PROGRAM,
            TOKEN_2022_PROGRAM,
            ATA_PROGRAM,
            MEMO_PROGRAM_V1,
            MEMO_PROGRAM_V2,
            WSOL_MINT,
        ];
        for text in SOL_BLOCKED_RECIPIENTS {
            let address = SolAddress::parse(text).unwrap();
            assert_eq!(is_reserved_key(&address), !spl.contains(&address), "{text}");
        }
        for text in SOL_RESERVED_KEYS {
            assert!(SOL_BLOCKED_RECIPIENTS.contains(&text), "{text}");
        }
        // Exact addresses only: a vanity key with a sysvar's prefix is not reserved.
        let vanity = SolAddress::parse("SysvarRent111111111111111111111111111111112").unwrap();
        assert!(!is_reserved_key(&vanity));
        assert!(is_reserved_key(&SYSVAR_RENT));
    }

    #[test]
    fn parse_input_trims_only_ascii_edges() {
        let text = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
        assert!(SolAddress::parse_input(&format!(" \t{text}\r\n")).is_ok());
        assert!(SolAddress::parse_input(&format!("\u{3000}{text}")).is_err());
        assert!(SolAddress::parse_input(&format!("solana:{text}")).is_err());
        assert!(SolAddress::parse_input("HAgk14JpMQLgt6rV gv7cBQFJWFto5Dqxi472uT3DKpqk").is_err());
        assert_eq!(
            grouped(&SolAddress::parse(text).unwrap()),
            "HAgk 14Jp MQLg t6rV gv7c BQFJ WFto 5Dqx i472 uT3D Kpqk"
        );
    }

    #[test]
    fn curve_classes() {
        let key = SolAddress::parse("HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk").unwrap();
        assert_eq!(curve_class(key.as_bytes()), CurveClass::OnCurve);
        assert_eq!(curve_class(&[0; 32]), CurveClass::SmallOrder);
        assert_eq!(
            curve_class(COMPUTE_BUDGET_PROGRAM.as_bytes()),
            CurveClass::OffCurve
        );
        assert!(is_on_curve_solana(TOKEN_PROGRAM.as_bytes()));
        assert!(!is_on_curve_solana(COMPUTE_BUDGET_PROGRAM.as_bytes()));
        // y + p for a small y: decompresses (reduced mod p) but re-compresses to y itself.
        let mut found = false;
        for small in 2_u8..19 {
            let mut bytes = [0xff_u8; 32];
            bytes[0] = 0xed_u8.wrapping_add(small);
            bytes[31] = 0x7f;
            if curve_class(&bytes) == CurveClass::NonCanonical {
                found = true;
            }
            assert_ne!(curve_class(&bytes), CurveClass::OnCurve);
        }
        assert!(found);
    }
}
