use thiserror::Error;

use crate::{BlockHash, ChainDefinition, ChainId, IdentityFingerprint, Observation, chain_by_id};

/// Failure to turn an RPC observation into opaque built-in-chain evidence.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EvidenceError {
    /// No immutable built-in definition has this full-width chain identifier.
    #[error("unknown built-in chain")]
    UnknownChain,
    /// The built-in entry has no immutable genesis identity anchor.
    #[error("built-in chain identity is incomplete")]
    MissingIdentity,
    /// The observed chain identifier or genesis hash contradicted the built-in entry.
    #[error("chain observation does not match the built-in identity")]
    ObservationMismatch,
}

/// Opaque evidence produced only by checking an RPC observation against a
/// compile-time built-in entry.
///
/// Callers can inspect the assessed facts but cannot construct this capability
/// from a public `ChainDefinition` or a caller-selected validity enum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuiltInChainEvidence {
    definition: &'static ChainDefinition,
    genesis_hash: BlockHash,
}

impl BuiltInChainEvidence {
    /// Returns the compile-time entry that was actually assessed.
    #[must_use]
    pub const fn definition(&self) -> &'static ChainDefinition {
        self.definition
    }

    /// Returns the authenticated genesis hash observed at the endpoint.
    #[must_use]
    pub const fn genesis_hash(&self) -> BlockHash {
        self.genesis_hash
    }
}

/// Assesses an exact observation against the matching compile-time entry and
/// returns an unforgeable-in-safe-Rust evidence value.
///
/// Missing identity anchors and mismatches are hard errors. Incomplete rule or
/// finality review remains explicit in the evidence so the authorization layer
/// can permit only its private-canary warning-and-hold policy.
///
/// # Errors
///
/// Returns an error if the chain is not a compile-time entry, its immutable
/// identity is incomplete, or the observed chain ID/genesis hash mismatches.
pub fn assess_builtin_chain(
    requested_chain_id: ChainId,
    observation: Observation,
) -> Result<BuiltInChainEvidence, EvidenceError> {
    let definition = chain_by_id(requested_chain_id).ok_or(EvidenceError::UnknownChain)?;
    let genesis_hash = match definition.identity {
        IdentityFingerprint::PinnedGenesis(expected) => expected,
        IdentityFingerprint::Missing { .. } => return Err(EvidenceError::MissingIdentity),
    };
    if observation.chain_id != definition.chain_id
        || observation.genesis_block_hash != Some(genesis_hash)
    {
        return Err(EvidenceError::ObservationMismatch);
    }
    Ok(BuiltInChainEvidence {
        definition,
        genesis_hash,
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        BlockHash, ChainId, EvidenceError, IdentityFingerprint, Observation, assess_builtin_chain,
        chain_by_id,
    };

    #[test]
    fn evidence_requires_the_pinned_builtin_genesis() -> Result<(), EvidenceError> {
        let chain_id = ChainId::from_u64(1);
        let definition = chain_by_id(chain_id).ok_or(EvidenceError::UnknownChain)?;
        let expected = match definition.identity {
            IdentityFingerprint::PinnedGenesis(value) => value,
            IdentityFingerprint::Missing { .. } => return Err(EvidenceError::MissingIdentity),
        };
        let evidence = assess_builtin_chain(
            chain_id,
            Observation {
                chain_id,
                genesis_block_hash: Some(expected),
            },
        )?;
        assert_eq!(evidence.definition(), definition);
        assert_eq!(evidence.genesis_hash(), expected);
        Ok(())
    }

    #[test]
    fn mismatch_and_missing_identity_never_produce_evidence() {
        let chain_id = ChainId::from_u64(1);
        assert_eq!(
            assess_builtin_chain(
                chain_id,
                Observation {
                    chain_id,
                    genesis_block_hash: Some(BlockHash::new([0xff; 32])),
                },
            ),
            Err(EvidenceError::ObservationMismatch)
        );

        let missing = ChainId::from_u64(56);
        assert_eq!(
            assess_builtin_chain(
                missing,
                Observation {
                    chain_id: missing,
                    genesis_block_hash: None,
                },
            ),
            Err(EvidenceError::MissingIdentity)
        );
    }
}
