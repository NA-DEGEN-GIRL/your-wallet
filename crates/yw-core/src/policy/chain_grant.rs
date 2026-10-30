//! Solana and Bitcoin connection grants (spec/05 §4.9; meta `sol_sites`/`btc_sites`, spec/02
//! §5.3): one grant per origin per chain, separate from the EVM `connected_sites`. A dApp
//! connection only proves account ownership (connect + message signing, spec.md D25–D27), so a
//! grant holds exactly one Solana account, or one Bitcoin address per purpose — the stable
//! receive index 0 address of an account, or an imported key's address.

use super::BrowserOrigin;
use crate::btc::{BtcNetwork, BtcPubKey, ScriptType};

/// Most grants per chain (like `connected_sites`).
pub const MAX_CHAIN_GRANTS: usize = 256;

/// A Solana grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolGrant {
    /// Origin (key).
    pub origin: BrowserOrigin,
    /// The connected account's public key.
    pub public: [u8; 32],
    /// When the connection was approved (Unix ms).
    pub granted_at_unix_ms: u64,
}

/// What a Bitcoin address is for (sats-connect `AddressPurpose`; `Any` = the single `UniSat`
/// address, of any type).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BtcPurpose {
    /// Payment: a P2WPKH or P2SH-P2WPKH address.
    Payment,
    /// Ordinals: a P2TR address.
    Ordinals,
    /// One address of any type (`UniSat`).
    Any,
}

impl BtcPurpose {
    /// Wire and meta label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Payment => "payment",
            Self::Ordinals => "ordinals",
            Self::Any => "any",
        }
    }

    /// Parses the exact label.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "payment" => Some(Self::Payment),
            "ordinals" => Some(Self::Ordinals),
            "any" => Some(Self::Any),
            _ => None,
        }
    }

    /// Whether an address type may serve this purpose.
    #[must_use]
    pub const fn accepts(self, script_type: ScriptType) -> bool {
        match self {
            Self::Payment => matches!(script_type, ScriptType::P2wpkh | ScriptType::P2shP2wpkh),
            Self::Ordinals => matches!(script_type, ScriptType::P2tr),
            Self::Any => true,
        }
    }

    /// The connect-window heading.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Payment => "결제용 주소 (payment: P2WPKH·P2SH-P2WPKH)",
            Self::Ordinals => "오디널스용 주소 (ordinals: P2TR)",
            Self::Any => "연결할 주소",
        }
    }
}

/// A requested purpose list: 1–2 distinct purposes, `Any` only alone.
#[must_use]
pub fn btc_purposes_valid(purposes: &[BtcPurpose]) -> bool {
    match purposes {
        [_] => true,
        [a, b] => a != b && *a != BtcPurpose::Any && *b != BtcPurpose::Any,
        _ => false,
    }
}

/// sats-connect `AddressType` of an address type.
#[must_use]
pub const fn btc_address_type(script_type: ScriptType) -> &'static str {
    match script_type {
        ScriptType::P2pkh => "p2pkh",
        ScriptType::P2shP2wpkh => "p2sh",
        ScriptType::P2wpkh => "p2wpkh",
        ScriptType::P2tr => "p2tr",
    }
}

/// One granted Bitcoin address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcGrantAddress {
    /// Purpose.
    pub purpose: BtcPurpose,
    /// The address as encoded.
    pub address: String,
    /// Its public key.
    pub pubkey: BtcPubKey,
    /// Its address type.
    pub script_type: ScriptType,
}

/// A Bitcoin grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcGrant {
    /// Origin (key).
    pub origin: BrowserOrigin,
    /// The network the addresses belong to (a grant of another network is not used).
    pub network: BtcNetwork,
    /// 1–2 addresses with distinct, valid purposes.
    pub addresses: Vec<BtcGrantAddress>,
    /// When the connection was approved (Unix ms).
    pub granted_at_unix_ms: u64,
}

impl BtcGrant {
    /// A grant, or `None` when the purposes are invalid or an address does not fit its purpose.
    #[must_use]
    pub fn new(
        origin: BrowserOrigin,
        network: BtcNetwork,
        addresses: Vec<BtcGrantAddress>,
        granted_at_unix_ms: u64,
    ) -> Option<Self> {
        let purposes: Vec<BtcPurpose> = addresses.iter().map(|entry| entry.purpose).collect();
        (btc_purposes_valid(&purposes)
            && addresses
                .iter()
                .all(|entry| entry.purpose.accepts(entry.script_type)))
        .then_some(Self {
            origin,
            network,
            addresses,
            granted_at_unix_ms,
        })
    }

    /// The granted entry of `address`.
    #[must_use]
    pub fn entry(&self, address: &str) -> Option<&BtcGrantAddress> {
        self.addresses.iter().find(|entry| entry.address == address)
    }
}

#[cfg(test)]
mod tests {
    use super::{BtcGrant, BtcGrantAddress, BtcPurpose, btc_purposes_valid};
    use crate::btc::{BtcNetwork, BtcPubKey, ScriptType};
    use crate::policy::BrowserOrigin;

    #[test]
    fn purposes_and_types() {
        use BtcPurpose::{Any, Ordinals, Payment};
        assert!(btc_purposes_valid(&[Payment]));
        assert!(btc_purposes_valid(&[Payment, Ordinals]));
        assert!(btc_purposes_valid(&[Any]));
        assert!(!btc_purposes_valid(&[]));
        assert!(!btc_purposes_valid(&[Payment, Payment]));
        assert!(!btc_purposes_valid(&[Any, Payment]));
        assert!(!btc_purposes_valid(&[Payment, Ordinals, Any]));
        assert!(Payment.accepts(ScriptType::P2shP2wpkh));
        assert!(!Payment.accepts(ScriptType::P2tr));
        assert!(Ordinals.accepts(ScriptType::P2tr));
        assert!(Any.accepts(ScriptType::P2pkh));
        for purpose in [Payment, Ordinals, Any] {
            assert_eq!(BtcPurpose::parse(purpose.as_str()), Some(purpose));
        }
        let origin = BrowserOrigin::parse("https://app.example").unwrap();
        let entry = |purpose, script_type| BtcGrantAddress {
            purpose,
            address: "a".to_owned(),
            pubkey: BtcPubKey::Compressed([2; 33]),
            script_type,
        };
        assert!(
            BtcGrant::new(
                origin.clone(),
                BtcNetwork::Mainnet,
                vec![entry(Payment, ScriptType::P2wpkh)],
                0
            )
            .is_some()
        );
        assert!(
            BtcGrant::new(
                origin,
                BtcNetwork::Mainnet,
                vec![entry(Ordinals, ScriptType::P2wpkh)],
                0
            )
            .is_none()
        );
    }
}
