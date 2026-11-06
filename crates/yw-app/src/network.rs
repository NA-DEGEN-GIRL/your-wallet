//! `NetworkId` (spec/02 §5.3): `eip155:<chainId>`, `solana:<cluster>`, `bitcoin:<net>`.
//! Logs and screens refer to RPC endpoints only by this identifier (D13).

use core::fmt;

use yw_core::evm::chain::{
    ARBITRUM_ONE, BASE_MAINNET, BSC_MAINNET, ETHEREUM_MAINNET, HYPEREVM_MAINNET, ROBINHOOD_MAINNET,
    SEPOLIA,
};

/// Built-in EVM chains in table order (spec/03 §1.1).
pub const BUILTIN_EVM: [u64; 7] = [
    ETHEREUM_MAINNET,
    SEPOLIA,
    HYPEREVM_MAINNET,
    ARBITRUM_ONE,
    BASE_MAINNET,
    BSC_MAINNET,
    ROBINHOOD_MAINNET,
];

/// Solana cluster.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SolCluster {
    /// `mainnet`.
    Mainnet,
    /// `devnet`.
    Devnet,
}

impl SolCluster {
    /// Settings / id string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Devnet => "devnet",
        }
    }

    /// Parses `mainnet` / `devnet`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "mainnet" => Some(Self::Mainnet),
            "devnet" => Some(Self::Devnet),
            _ => None,
        }
    }
}

/// Bitcoin network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BtcNet {
    /// `mainnet`.
    Mainnet,
    /// `testnet4`.
    Testnet4,
}

impl BtcNet {
    /// Settings / id string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet4 => "testnet4",
        }
    }

    /// Parses `mainnet` / `testnet4`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "mainnet" => Some(Self::Mainnet),
            "testnet4" => Some(Self::Testnet4),
            _ => None,
        }
    }
}

/// A network identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NetworkId {
    /// `eip155:<chainId>` (1..=2^64−1).
    Eip155(u64),
    /// `solana:<cluster>`.
    Solana(SolCluster),
    /// `bitcoin:<net>`.
    Bitcoin(BtcNet),
}

/// Strict decimal: digits only, no leading zero, 1..=`u64::MAX`.
#[must_use]
pub fn parse_decimal_u64(text: &str) -> Option<u64> {
    if text.is_empty()
        || text.len() > 20
        || text.starts_with('0')
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    text.parse().ok()
}

impl NetworkId {
    /// Parses the canonical text form.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        if let Some(id) = text.strip_prefix("eip155:") {
            return parse_decimal_u64(id).map(Self::Eip155);
        }
        if let Some(cluster) = text.strip_prefix("solana:") {
            return SolCluster::parse(cluster).map(Self::Solana);
        }
        if let Some(net) = text.strip_prefix("bitcoin:") {
            return BtcNet::parse(net).map(Self::Bitcoin);
        }
        None
    }

    /// Whether this is a built-in EVM chain.
    #[must_use]
    pub fn is_builtin_evm(self) -> bool {
        matches!(self, Self::Eip155(id) if BUILTIN_EVM.contains(&id))
    }
}

impl fmt::Display for NetworkId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eip155(id) => write!(formatter, "eip155:{id}"),
            Self::Solana(cluster) => write!(formatter, "solana:{}", cluster.as_str()),
            Self::Bitcoin(net) => write!(formatter, "bitcoin:{}", net.as_str()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BtcNet, NetworkId, SolCluster};

    #[test]
    fn parse_and_display_round_trip() {
        for text in [
            "eip155:1",
            "eip155:11155111",
            "eip155:18446744073709551615",
            "solana:devnet",
            "bitcoin:testnet4",
        ] {
            assert_eq!(NetworkId::parse(text).unwrap().to_string(), text);
        }
        assert_eq!(
            NetworkId::parse("solana:mainnet"),
            Some(NetworkId::Solana(SolCluster::Mainnet))
        );
        assert_eq!(
            NetworkId::parse("bitcoin:mainnet"),
            Some(NetworkId::Bitcoin(BtcNet::Mainnet))
        );
        for bad in [
            "eip155:01",
            "eip155:0",
            "eip155:",
            "eip155:18446744073709551616",
            "eip155:+1",
            "solana:testnet",
            "bitcoin:testnet3",
            "EIP155:1",
        ] {
            assert_eq!(NetworkId::parse(bad), None, "{bad}");
        }
    }
}
