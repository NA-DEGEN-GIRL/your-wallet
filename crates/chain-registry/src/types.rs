use core::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;

/// A full-width EIP-155 chain identifier.
///
/// The identifier is stored as a 256-bit big-endian integer so callers never
/// silently truncate a chain identifier to a platform integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainId([u8; 32]);

impl ChainId {
    /// The zero identifier, which is rejected for user-defined chains.
    pub const ZERO: Self = Self([0; 32]);

    /// Constructs an identifier from a `u64` without narrowing the public type.
    #[must_use]
    pub const fn from_u64(value: u64) -> Self {
        let mut bytes = [0_u8; 32];
        let value_bytes = value.to_be_bytes();
        let mut index = 0;
        while index < value_bytes.len() {
            bytes[24 + index] = value_bytes[index];
            index += 1;
        }
        Self(bytes)
    }

    /// Constructs an identifier from its full big-endian representation.
    #[must_use]
    pub const fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the full big-endian representation.
    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Returns `true` when this is the reserved zero identifier.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        let mut index = 0;
        while index < self.0.len() {
            if self.0[index] != 0 {
                return false;
            }
            index += 1;
        }
        true
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("0x")?;
        let first_nonzero = self.0.iter().position(|byte| *byte != 0);
        let Some(first_nonzero) = first_nonzero else {
            return formatter.write_str("0");
        };
        write!(formatter, "{:x}", self.0[first_nonzero])?;
        for byte in &self.0[first_nonzero + 1..] {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for ChainId {
    type Err = ChainIdParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let digits = input
            .strip_prefix("0x")
            .or_else(|| input.strip_prefix("0X"))
            .ok_or(ChainIdParseError::MissingPrefix)?;
        if digits.is_empty() {
            return Err(ChainIdParseError::Empty);
        }
        if digits.len() > 64 {
            return Err(ChainIdParseError::TooWide);
        }
        let mut bytes = [0_u8; 32];
        let mut output_index = 32 - digits.len().div_ceil(2);
        let mut input_index = 0;
        if digits.len() % 2 == 1 {
            bytes[output_index] = decode_nibble(digits.as_bytes()[0])?;
            output_index += 1;
            input_index = 1;
        }
        while input_index < digits.len() {
            let high = decode_nibble(digits.as_bytes()[input_index])?;
            let low = decode_nibble(digits.as_bytes()[input_index + 1])?;
            bytes[output_index] = (high << 4) | low;
            output_index += 1;
            input_index += 2;
        }
        Ok(Self(bytes))
    }
}

const fn decode_nibble(value: u8) -> Result<u8, ChainIdParseError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(ChainIdParseError::InvalidHex),
    }
}

impl Serialize for ChainId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ChainId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ChainIdVisitor;

        impl de::Visitor<'_> for ChainIdVisitor {
            type Value = ChainId;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a 0x-prefixed, at-most-256-bit chain identifier")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                value.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_str(ChainIdVisitor)
    }
}

/// Failure to parse a full-width EIP-155 chain identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ChainIdParseError {
    /// The required hexadecimal prefix was absent.
    #[error("chain identifier must use a 0x prefix")]
    MissingPrefix,
    /// No hexadecimal digits followed the prefix.
    #[error("chain identifier is empty")]
    Empty,
    /// More than 256 bits were supplied.
    #[error("chain identifier exceeds 256 bits")]
    TooWide,
    /// A non-hexadecimal character was supplied.
    #[error("chain identifier contains a non-hexadecimal digit")]
    InvalidHex,
}

/// A 32-byte block hash used as a chain-identity anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockHash([u8; 32]);

impl BlockHash {
    /// Constructs a block hash from exact bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact block-hash bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Compile-time implementation family selected by trusted wallet code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Adapter {
    /// Ethereum proof-of-stake rules.
    EthereumPoS,
    /// BNB Smart Chain Parlia rules.
    BscParlia,
    /// Polygon `PoS` rules.
    PolygonPoS,
    /// Avalanche C-Chain rules.
    AvalancheC,
    /// OP Stack rollup rules.
    OpStack,
    /// Arbitrum Nitro rollup rules.
    ArbitrumNitro,
    /// Conservative standard EIP-155 behavior for user-defined chains.
    GenericEvm155,
}

/// Whether a registry entry is production or test infrastructure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkKind {
    /// A value-bearing production chain.
    Mainnet,
    /// An officially maintained public test chain.
    Testnet,
}

/// Transaction envelopes implemented by the initial signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum TransactionEnvelope {
    /// EIP-155 replay-protected legacy transactions, type byte `0` by policy.
    LegacyEip155 = 0,
    /// EIP-2930 access-list transactions.
    AccessListEip2930 = 1,
    /// EIP-1559 dynamic-fee transactions.
    DynamicFeeEip1559 = 2,
}

/// Compact allowlist of transaction envelope types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeSet(u8);

impl EnvelopeSet {
    /// No envelope types.
    pub const NONE: Self = Self(0);
    /// The initial wallet's standard type-0, type-1, and type-2 set.
    pub const STANDARD: Self = Self(0b0000_0111);

    /// Returns whether the set contains a particular envelope.
    #[must_use]
    pub const fn contains(self, envelope: TransactionEnvelope) -> bool {
        self.0 & (1 << envelope as u8) != 0
    }

    /// Returns whether no envelope was selected.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub(crate) fn from_type_bytes(types: &[u8]) -> Result<Self, u8> {
        let mut bits = 0_u8;
        for transaction_type in types {
            if *transaction_type > TransactionEnvelope::DynamicFeeEip1559 as u8 {
                return Err(*transaction_type);
            }
            let bit = 1_u8 << transaction_type;
            if bits & bit != 0 {
                return Err(*transaction_type);
            }
            bits |= bit;
        }
        Ok(Self(bits))
    }
}

/// Native currency metadata used only for display and amount scaling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeCurrency {
    /// Human-readable currency name.
    pub name: &'static str,
    /// Short display symbol.
    pub symbol: &'static str,
    /// Base-10 decimal places.
    pub decimals: u8,
}

/// How an RPC observation can be bound to a known network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityFingerprint {
    /// An execution-layer genesis block hash from an official configuration.
    PinnedGenesis(BlockHash),
    /// No immutable official fingerprint has yet been incorporated.
    Missing {
        /// Why the entry cannot currently authenticate the network.
        reason: &'static str,
    },
}

/// Wallet review coverage for consensus and transaction-signing rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleCoverage {
    /// The adapter and registry were reviewed against the named rule revision.
    Verified {
        /// Immutable source revision or release identifier.
        revision: &'static str,
    },
    /// A complete rule review has not been recorded.
    Unknown {
        /// The concrete missing review work.
        reason: &'static str,
    },
}

/// The protocol family whose finality must be tracked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalityModel {
    /// Execution RPC `safe` and `finalized` tags backed by Ethereum consensus.
    EthereumRpcTags,
    /// Chain-specific finality that requires its compiled adapter.
    AdapterSpecific,
    /// Local L2 inclusion and parent-chain settlement are distinct axes.
    OptimisticRollup {
        /// Parent chain on which the rollup settles.
        parent_chain_id: ChainId,
        /// Compiled rollup implementation family.
        stack: RollupStack,
    },
    /// No finality statement is made, as required for custom chains.
    NoClaim,
}

/// Compiled optimistic-rollup implementation families.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollupStack {
    /// OP Stack.
    OpStack,
    /// Arbitrum Nitro.
    ArbitrumNitro,
}

/// A finality model together with its release-review state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalityPolicy {
    /// The monitoring axes the wallet must preserve.
    pub model: FinalityModel,
    /// Whether the model is covered by the current rules review.
    pub coverage: RuleCoverage,
}

/// Time boundary for a registry security review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReviewWindow {
    /// UTC Unix time at which sources were reviewed.
    pub reviewed_at_unix: u64,
    /// UTC Unix time after which another review is mandatory.
    pub expires_at_unix: u64,
}

/// Kind of fact established by an official source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceClaim {
    /// Chain identifier and active/deprecated network status.
    ChainIdAndLifecycle,
    /// Immutable execution-layer genesis identity.
    GenesisIdentity,
    /// Protocol architecture or finality semantics.
    ProtocolModel,
}

/// An official primary-source reference embedded for review provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceReference {
    /// Short source title.
    pub title: &'static str,
    /// Public primary-source URL without credentials or query parameters.
    pub url: &'static str,
    /// The fact this source is used to establish.
    pub claim: SourceClaim,
}

/// One inert built-in network definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainDefinition {
    /// Stable internal identifier.
    pub slug: &'static str,
    /// User-facing network name.
    pub display_name: &'static str,
    /// Full-width EIP-155 identifier.
    pub chain_id: ChainId,
    /// Production or test classification.
    pub network_kind: NetworkKind,
    /// Compile-time adapter selection.
    pub adapter: Adapter,
    /// Native display currency.
    pub native_currency: NativeCurrency,
    /// Candidate transaction envelope implementation set.
    pub transaction_envelopes: EnvelopeSet,
    /// Immutable chain-identity anchor, or an explicit gap.
    pub identity: IdentityFingerprint,
    /// Transaction and consensus rule coverage.
    pub rules: RuleCoverage,
    /// Finality monitoring policy.
    pub finality: FinalityPolicy,
    /// Review freshness window.
    pub review: ReviewWindow,
    /// Official sources used for the entry.
    pub sources: &'static [SourceReference],
}

/// Chain identity returned by a selected RPC endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    /// Result of `eth_chainId` parsed without integer truncation.
    pub chain_id: ChainId,
    /// Hash of execution block zero, if the endpoint returned it.
    pub genesis_block_hash: Option<BlockHash>,
}

/// Security validity of a chain and rule-set observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolValidity {
    /// Identity, rules, finality policy, and review freshness all passed.
    Verified,
    /// The underlying review expired and must be refreshed.
    ExpiredReview,
    /// Identity, rules, or finality review coverage is incomplete.
    RuleCoverageUnknown,
    /// An observed value contradicted the compiled registry.
    Invalid,
}

/// Result of the release signing gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseGate {
    /// Signing may proceed under the reviewed built-in adapter.
    Eligible,
    /// Signing must not proceed.
    Denied(ReleaseGateDenial),
}

/// Fail-closed reason emitted by the release signing gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseGateDenial {
    /// The observed chain ID or pinned genesis hash did not match.
    InvalidIdentityObservation,
    /// No immutable identity anchor is compiled into the entry.
    MissingIdentityFingerprint,
    /// Transaction, consensus, or finality rule coverage is incomplete.
    RuleCoverageUnknown,
    /// The security review freshness window elapsed.
    ReviewExpired,
}

/// Evaluates an RPC observation against a built-in definition.
#[must_use]
pub fn protocol_validity(
    definition: &ChainDefinition,
    observation: Observation,
    now_unix: u64,
) -> ProtocolValidity {
    if observation.chain_id != definition.chain_id {
        return ProtocolValidity::Invalid;
    }
    match definition.identity {
        IdentityFingerprint::PinnedGenesis(expected) => {
            if observation.genesis_block_hash != Some(expected) {
                return ProtocolValidity::Invalid;
            }
        }
        IdentityFingerprint::Missing { .. } => return ProtocolValidity::RuleCoverageUnknown,
    }
    if matches!(definition.rules, RuleCoverage::Unknown { .. })
        || matches!(definition.finality.coverage, RuleCoverage::Unknown { .. })
    {
        return ProtocolValidity::RuleCoverageUnknown;
    }
    if now_unix > definition.review.expires_at_unix {
        return ProtocolValidity::ExpiredReview;
    }
    ProtocolValidity::Verified
}

/// Applies the fail-closed built-in release signing gate.
///
/// Unknown or expired entries are deliberately not converted into warning-only
/// results by this crate. A user-defined custom chain follows the separate,
/// always-warning path in [`crate::validate_custom_chain`].
#[must_use]
pub fn release_signing_gate(
    definition: &ChainDefinition,
    observation: Observation,
    now_unix: u64,
) -> ReleaseGate {
    match protocol_validity(definition, observation, now_unix) {
        ProtocolValidity::Verified => ReleaseGate::Eligible,
        ProtocolValidity::Invalid => {
            ReleaseGate::Denied(ReleaseGateDenial::InvalidIdentityObservation)
        }
        ProtocolValidity::ExpiredReview => ReleaseGate::Denied(ReleaseGateDenial::ReviewExpired),
        ProtocolValidity::RuleCoverageUnknown => match definition.identity {
            IdentityFingerprint::Missing { .. } => {
                ReleaseGate::Denied(ReleaseGateDenial::MissingIdentityFingerprint)
            }
            IdentityFingerprint::PinnedGenesis(_) => {
                ReleaseGate::Denied(ReleaseGateDenial::RuleCoverageUnknown)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{ChainId, ChainIdParseError};

    #[test]
    fn full_width_chain_id_round_trips() {
        let parsed =
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".parse::<ChainId>();
        assert!(parsed.is_ok());
        if let Ok(chain_id) = parsed {
            assert_eq!(
                chain_id.to_string(),
                "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            );
        }
    }

    #[test]
    fn chain_id_parser_rejects_oversize_and_non_hex() {
        let oversize = format!("0x1{}", "0".repeat(64));
        assert_eq!(oversize.parse::<ChainId>(), Err(ChainIdParseError::TooWide));
        assert_eq!(
            "0xgg".parse::<ChainId>(),
            Err(ChainIdParseError::InvalidHex)
        );
    }

    #[test]
    fn small_chain_id_has_canonical_hex_display() {
        assert_eq!(ChainId::from_u64(1).to_string(), "0x1");
        assert_eq!(ChainId::ZERO.to_string(), "0x0");
    }
}
