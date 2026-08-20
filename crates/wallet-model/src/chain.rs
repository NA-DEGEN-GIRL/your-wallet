use crate::{CanonicalEncode, CodecError, Hash32, Transcript, U256};

/// Consensus and transaction-rule adapter selected for a chain.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum AdapterKind {
    /// Ethereum proof-of-stake rules.
    EthereumPos = 1,
    /// BNB Smart Chain Parlia rules.
    BscParlia = 2,
    /// Polygon proof-of-stake rules.
    PolygonPos = 3,
    /// Avalanche C-Chain rules.
    AvalancheC = 4,
    /// OP Stack rules.
    OpStack = 5,
    /// Arbitrum Nitro rules.
    ArbitrumNitro = 6,
    /// Conservative standard EVM EIP-155/type-1/type-2 behavior.
    GenericEvm155 = 7,
}

impl CanonicalEncode for AdapterKind {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        transcript.push_u8(*self as u8);
        Ok(())
    }
}

/// A chain fingerprint bound into every approval.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ChainIdentity {
    chain_id: U256,
    genesis_hash: Hash32,
    adapter: AdapterKind,
    registry_revision: Hash32,
}

impl ChainIdentity {
    /// Constructs a fully fingerprinted identity.
    #[must_use]
    pub const fn new(
        chain_id: U256,
        genesis_hash: Hash32,
        adapter: AdapterKind,
        registry_revision: Hash32,
    ) -> Self {
        Self {
            chain_id,
            genesis_hash,
            adapter,
            registry_revision,
        }
    }

    /// Returns the EIP-155 chain ID.
    #[must_use]
    pub const fn chain_id(&self) -> U256 {
        self.chain_id
    }

    /// Returns the expected genesis block hash.
    #[must_use]
    pub const fn genesis_hash(&self) -> Hash32 {
        self.genesis_hash
    }

    /// Returns the consensus adapter.
    #[must_use]
    pub const fn adapter(&self) -> AdapterKind {
        self.adapter
    }

    /// Returns the signed registry revision digest.
    #[must_use]
    pub const fn registry_revision(&self) -> Hash32 {
        self.registry_revision
    }
}

impl CanonicalEncode for ChainIdentity {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        self.chain_id.encode(transcript)?;
        self.genesis_hash.encode(transcript)?;
        self.adapter.encode(transcript)?;
        self.registry_revision.encode(transcript)
    }
}

/// A canonical block observation anchor.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BlockAnchor {
    /// Block number.
    pub number: U256,
    /// Block hash.
    pub hash: Hash32,
}

impl CanonicalEncode for BlockAnchor {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        self.number.encode(transcript)?;
        self.hash.encode(transcript)
    }
}

/// Stable, non-secret identifier for the RPC source configuration.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RpcSourceId(pub Hash32);

impl CanonicalEncode for RpcSourceId {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        self.0.encode(transcript)
    }
}

/// How much corroboration an RPC observation received.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ObservationConfidence {
    /// Exactly one endpoint produced the observation.
    SingleSource = 1,
    /// Multiple independent endpoints agreed.
    Corroborated = 2,
    /// The value was computed locally from verified inputs.
    LocallyDerived = 3,
}

impl CanonicalEncode for ObservationConfidence {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        transcript.push_u8(*self as u8);
        Ok(())
    }
}

/// A value paired with the provenance needed to bind it into approval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpcObservation<T> {
    /// Observed value.
    pub value: T,
    /// Sanitized endpoint-configuration digest.
    pub source: RpcSourceId,
    /// Local monotonic-wall-clock correlation timestamp in Unix milliseconds.
    pub observed_at_ms: u64,
    /// Block against which the value was observed, when applicable.
    pub block: Option<BlockAnchor>,
    /// Source corroboration level.
    pub confidence: ObservationConfidence,
}

impl<T: CanonicalEncode> CanonicalEncode for RpcObservation<T> {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        self.value.encode(transcript)?;
        self.source.encode(transcript)?;
        transcript.push_u64(self.observed_at_ms);
        transcript.push_optional(self.block.as_ref())?;
        self.confidence.encode(transcript)
    }
}
