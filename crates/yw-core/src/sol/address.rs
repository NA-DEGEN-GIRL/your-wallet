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

    /// The display name used in titles and the network field (devnet marked as a test network).
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Mainnet => "Solana mainnet",
            Self::Devnet => "Solana devnet (테스트)",
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

#[cfg(test)]
mod tests {
    use super::{
        COMPUTE_BUDGET_PROGRAM, CurveClass, DEVNET_GENESIS, MAINNET_GENESIS,
        SOL_BLOCKED_RECIPIENTS, SolAddress, SolCluster, TOKEN_PROGRAM, curve_class, grouped,
        is_on_curve_solana,
    };

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
