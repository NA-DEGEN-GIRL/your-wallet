use crate::{
    Adapter, BlockHash, ChainDefinition, ChainId, EnvelopeSet, FinalityModel, FinalityPolicy,
    IdentityFingerprint, NativeCurrency, NetworkKind, ReviewWindow, RollupStack, RuleCoverage,
    SourceClaim, SourceReference,
};

const REVIEW: ReviewWindow = ReviewWindow {
    reviewed_at_unix: 1_786_579_200,
    expires_at_unix: 1_789_171_200,
};

const RULES_NOT_RELEASE_BOUND: RuleCoverage = RuleCoverage::Unknown {
    reason: "current fork rules have not yet been bound to an immutable wallet release artifact",
};

const IDENTITY_NOT_PINNED: IdentityFingerprint = IdentityFingerprint::Missing {
    reason: "official chain ID is verified, but no immutable genesis or equivalent fingerprint is pinned",
};

const ETHEREUM_MAINNET_GENESIS: BlockHash = BlockHash::new([
    0xd4, 0xe5, 0x67, 0x40, 0xf8, 0x76, 0xae, 0xf8, 0xc0, 0x10, 0xb8, 0x6a, 0x40, 0xd5, 0xf5, 0x67,
    0x45, 0xa1, 0x18, 0xd0, 0x90, 0x6a, 0x34, 0xe6, 0x9a, 0xec, 0x8c, 0x0d, 0xb1, 0xcb, 0x8f, 0xa3,
]);

const SEPOLIA_GENESIS: BlockHash = BlockHash::new([
    0x25, 0xa5, 0xcc, 0x10, 0x6e, 0xea, 0x71, 0x38, 0xac, 0xab, 0x33, 0x23, 0x1d, 0x71, 0x60, 0xd6,
    0x9c, 0xb7, 0x77, 0xee, 0x0c, 0x2c, 0x55, 0x3f, 0xcd, 0xdf, 0x51, 0x38, 0x99, 0x3e, 0x6d, 0xd9,
]);

const HOODI_GENESIS: BlockHash = BlockHash::new([
    0xbb, 0xe3, 0x12, 0x86, 0x8b, 0x37, 0x6a, 0x30, 0x01, 0x69, 0x2a, 0x64, 0x6d, 0xd2, 0xd7, 0xd1,
    0xe4, 0x40, 0x63, 0x80, 0xdf, 0xd8, 0x6b, 0x98, 0xaa, 0x8a, 0x34, 0xd1, 0x55, 0x7c, 0x97, 0x1b,
]);

const ETH_MAIN_SOURCES: &[SourceReference] = &[
    SourceReference {
        title: "Ethereum Mainnet cross-client configuration",
        url: "https://github.com/eth-clients/mainnet",
        claim: SourceClaim::GenesisIdentity,
    },
    SourceReference {
        title: "go-ethereum built-in mainnet configuration",
        url: "https://github.com/ethereum/go-ethereum/tree/master/params",
        claim: SourceClaim::ChainIdAndLifecycle,
    },
];

const SEPOLIA_SOURCES: &[SourceReference] = &[
    SourceReference {
        title: "Sepolia cross-client configuration",
        url: "https://github.com/eth-clients/sepolia",
        claim: SourceClaim::GenesisIdentity,
    },
    SourceReference {
        title: "Ethereum networks",
        url: "https://ethereum.org/developers/docs/networks/",
        claim: SourceClaim::ChainIdAndLifecycle,
    },
];

const HOODI_SOURCES: &[SourceReference] = &[
    SourceReference {
        title: "Hoodi cross-client configuration",
        url: "https://github.com/eth-clients/hoodi",
        claim: SourceClaim::GenesisIdentity,
    },
    SourceReference {
        title: "Ethereum networks",
        url: "https://ethereum.org/developers/docs/networks/",
        claim: SourceClaim::ChainIdAndLifecycle,
    },
];

const BSC_SOURCES: &[SourceReference] = &[SourceReference {
    title: "BNB Smart Chain JSON-RPC endpoints",
    url: "https://docs.bnbchain.org/bnb-smart-chain/developers/json_rpc/json-rpc-endpoint/",
    claim: SourceClaim::ChainIdAndLifecycle,
}];

const POLYGON_SOURCES: &[SourceReference] = &[SourceReference {
    title: "Polygon PoS network details",
    url: "https://docs.polygon.technology/pos/reference/rpc-endpoints/",
    claim: SourceClaim::ChainIdAndLifecycle,
}];

const AVALANCHE_SOURCES: &[SourceReference] = &[
    SourceReference {
        title: "Avalanche Primary Network",
        url: "https://build.avax.network/docs/primary-network",
        claim: SourceClaim::ChainIdAndLifecycle,
    },
    SourceReference {
        title: "Avalanche C-Chain RPC",
        url: "https://build.avax.network/docs/rpcs/c-chain",
        claim: SourceClaim::ProtocolModel,
    },
];

const ARBITRUM_SOURCES: &[SourceReference] = &[SourceReference {
    title: "Arbitrum chain information",
    url: "https://docs.arbitrum.io/for-devs/dev-tools-and-resources/chain-info",
    claim: SourceClaim::ChainIdAndLifecycle,
}];

const OPTIMISM_SOURCES: &[SourceReference] = &[SourceReference {
    title: "Connecting to OP Mainnet and OP Sepolia",
    url: "https://docs.optimism.io/op-mainnet/network-information/connecting-to-op",
    claim: SourceClaim::ChainIdAndLifecycle,
}];

const BASE_SOURCES: &[SourceReference] = &[SourceReference {
    title: "Base RPC overview",
    url: "https://docs.base.org/base-chain/api-reference/rpc-overview",
    claim: SourceClaim::ChainIdAndLifecycle,
}];

const ROBINHOOD_SOURCES: &[SourceReference] = &[
    SourceReference {
        title: "Connecting to Robinhood Chain",
        url: "https://docs.robinhood.com/chain/connecting/",
        claim: SourceClaim::ChainIdAndLifecycle,
    },
    SourceReference {
        title: "Running a Robinhood Chain full node",
        url: "https://docs.robinhood.com/chain/run-a-full-node/",
        claim: SourceClaim::ProtocolModel,
    },
];

const ETH: NativeCurrency = NativeCurrency {
    name: "Ether",
    symbol: "ETH",
    decimals: 18,
};

const BNB: NativeCurrency = NativeCurrency {
    name: "BNB",
    symbol: "BNB",
    decimals: 18,
};

const POL: NativeCurrency = NativeCurrency {
    name: "POL",
    symbol: "POL",
    decimals: 18,
};

const AVAX: NativeCurrency = NativeCurrency {
    name: "AVAX",
    symbol: "AVAX",
    decimals: 18,
};

const ETHEREUM_FINALITY: FinalityPolicy = FinalityPolicy {
    model: FinalityModel::EthereumRpcTags,
    coverage: RULES_NOT_RELEASE_BOUND,
};

const ADAPTER_FINALITY: FinalityPolicy = FinalityPolicy {
    model: FinalityModel::AdapterSpecific,
    coverage: RULES_NOT_RELEASE_BOUND,
};

const OP_MAINNET_FINALITY: FinalityPolicy = FinalityPolicy {
    model: FinalityModel::OptimisticRollup {
        parent_chain_id: ChainId::from_u64(1),
        stack: RollupStack::OpStack,
    },
    coverage: RULES_NOT_RELEASE_BOUND,
};

const OP_SEPOLIA_FINALITY: FinalityPolicy = FinalityPolicy {
    model: FinalityModel::OptimisticRollup {
        parent_chain_id: ChainId::from_u64(11_155_111),
        stack: RollupStack::OpStack,
    },
    coverage: RULES_NOT_RELEASE_BOUND,
};

const ARBITRUM_MAINNET_FINALITY: FinalityPolicy = FinalityPolicy {
    model: FinalityModel::OptimisticRollup {
        parent_chain_id: ChainId::from_u64(1),
        stack: RollupStack::ArbitrumNitro,
    },
    coverage: RULES_NOT_RELEASE_BOUND,
};

const ARBITRUM_SEPOLIA_FINALITY: FinalityPolicy = FinalityPolicy {
    model: FinalityModel::OptimisticRollup {
        parent_chain_id: ChainId::from_u64(11_155_111),
        stack: RollupStack::ArbitrumNitro,
    },
    coverage: RULES_NOT_RELEASE_BOUND,
};

macro_rules! chain {
    (
        $slug:expr,
        $display_name:expr,
        $chain_id:expr,
        $network_kind:expr,
        $adapter:expr,
        $native_currency:expr,
        $identity:expr,
        $finality:expr,
        $sources:expr $(,)?
    ) => {
        ChainDefinition {
            slug: $slug,
            display_name: $display_name,
            chain_id: ChainId::from_u64($chain_id),
            network_kind: $network_kind,
            adapter: $adapter,
            native_currency: $native_currency,
            transaction_envelopes: EnvelopeSet::STANDARD,
            identity: $identity,
            rules: RULES_NOT_RELEASE_BOUND,
            finality: $finality,
            review: REVIEW,
            sources: $sources,
        }
    };
}

/// All built-in networks covered by the private-canary integration matrix.
///
/// Entries with incomplete fingerprints or rule reviews intentionally remain
/// signing-ineligible until those release artifacts are supplied.
pub static ALL_CHAINS: [ChainDefinition; 17] = [
    chain!(
        "ethereum-mainnet",
        "Ethereum Mainnet",
        1,
        NetworkKind::Mainnet,
        Adapter::EthereumPoS,
        ETH,
        IdentityFingerprint::PinnedGenesis(ETHEREUM_MAINNET_GENESIS),
        ETHEREUM_FINALITY,
        ETH_MAIN_SOURCES,
    ),
    chain!(
        "ethereum-sepolia",
        "Ethereum Sepolia",
        11_155_111,
        NetworkKind::Testnet,
        Adapter::EthereumPoS,
        ETH,
        IdentityFingerprint::PinnedGenesis(SEPOLIA_GENESIS),
        ETHEREUM_FINALITY,
        SEPOLIA_SOURCES,
    ),
    chain!(
        "ethereum-hoodi",
        "Ethereum Hoodi",
        560_048,
        NetworkKind::Testnet,
        Adapter::EthereumPoS,
        ETH,
        IdentityFingerprint::PinnedGenesis(HOODI_GENESIS),
        ETHEREUM_FINALITY,
        HOODI_SOURCES,
    ),
    chain!(
        "bsc-mainnet",
        "BNB Smart Chain",
        56,
        NetworkKind::Mainnet,
        Adapter::BscParlia,
        BNB,
        IDENTITY_NOT_PINNED,
        ADAPTER_FINALITY,
        BSC_SOURCES,
    ),
    chain!(
        "bsc-testnet",
        "BNB Smart Chain Testnet",
        97,
        NetworkKind::Testnet,
        Adapter::BscParlia,
        BNB,
        IDENTITY_NOT_PINNED,
        ADAPTER_FINALITY,
        BSC_SOURCES,
    ),
    chain!(
        "polygon-pos-mainnet",
        "Polygon PoS",
        137,
        NetworkKind::Mainnet,
        Adapter::PolygonPoS,
        POL,
        IDENTITY_NOT_PINNED,
        ADAPTER_FINALITY,
        POLYGON_SOURCES,
    ),
    chain!(
        "polygon-pos-amoy",
        "Polygon Amoy",
        80_002,
        NetworkKind::Testnet,
        Adapter::PolygonPoS,
        POL,
        IDENTITY_NOT_PINNED,
        ADAPTER_FINALITY,
        POLYGON_SOURCES,
    ),
    chain!(
        "avalanche-c-mainnet",
        "Avalanche C-Chain",
        43_114,
        NetworkKind::Mainnet,
        Adapter::AvalancheC,
        AVAX,
        IDENTITY_NOT_PINNED,
        ADAPTER_FINALITY,
        AVALANCHE_SOURCES,
    ),
    chain!(
        "avalanche-c-fuji",
        "Avalanche Fuji C-Chain",
        43_113,
        NetworkKind::Testnet,
        Adapter::AvalancheC,
        AVAX,
        IDENTITY_NOT_PINNED,
        ADAPTER_FINALITY,
        AVALANCHE_SOURCES,
    ),
    chain!(
        "arbitrum-one",
        "Arbitrum One",
        42_161,
        NetworkKind::Mainnet,
        Adapter::ArbitrumNitro,
        ETH,
        IDENTITY_NOT_PINNED,
        ARBITRUM_MAINNET_FINALITY,
        ARBITRUM_SOURCES,
    ),
    chain!(
        "arbitrum-sepolia",
        "Arbitrum Sepolia",
        421_614,
        NetworkKind::Testnet,
        Adapter::ArbitrumNitro,
        ETH,
        IDENTITY_NOT_PINNED,
        ARBITRUM_SEPOLIA_FINALITY,
        ARBITRUM_SOURCES,
    ),
    chain!(
        "op-mainnet",
        "OP Mainnet",
        10,
        NetworkKind::Mainnet,
        Adapter::OpStack,
        ETH,
        IDENTITY_NOT_PINNED,
        OP_MAINNET_FINALITY,
        OPTIMISM_SOURCES,
    ),
    chain!(
        "op-sepolia",
        "OP Sepolia",
        11_155_420,
        NetworkKind::Testnet,
        Adapter::OpStack,
        ETH,
        IDENTITY_NOT_PINNED,
        OP_SEPOLIA_FINALITY,
        OPTIMISM_SOURCES,
    ),
    chain!(
        "base-mainnet",
        "Base",
        8_453,
        NetworkKind::Mainnet,
        Adapter::OpStack,
        ETH,
        IDENTITY_NOT_PINNED,
        OP_MAINNET_FINALITY,
        BASE_SOURCES,
    ),
    chain!(
        "base-sepolia",
        "Base Sepolia",
        84_532,
        NetworkKind::Testnet,
        Adapter::OpStack,
        ETH,
        IDENTITY_NOT_PINNED,
        OP_SEPOLIA_FINALITY,
        BASE_SOURCES,
    ),
    chain!(
        "robinhood-chain-mainnet",
        "Robinhood Chain",
        4_663,
        NetworkKind::Mainnet,
        Adapter::ArbitrumNitro,
        ETH,
        IDENTITY_NOT_PINNED,
        ADAPTER_FINALITY,
        ROBINHOOD_SOURCES,
    ),
    chain!(
        "robinhood-chain-testnet",
        "Robinhood Chain Testnet",
        46_630,
        NetworkKind::Testnet,
        Adapter::ArbitrumNitro,
        ETH,
        IDENTITY_NOT_PINNED,
        ADAPTER_FINALITY,
        ROBINHOOD_SOURCES,
    ),
];

/// Returns all immutable built-in chain definitions.
#[must_use]
pub fn all_chains() -> &'static [ChainDefinition] {
    &ALL_CHAINS
}

/// Looks up a built-in definition by its full-width chain identifier.
#[must_use]
pub fn chain_by_id(chain_id: ChainId) -> Option<&'static ChainDefinition> {
    ALL_CHAINS.iter().find(|chain| chain.chain_id == chain_id)
}

/// Looks up a built-in definition by stable slug.
#[must_use]
pub fn chain_by_slug(slug: &str) -> Option<&'static ChainDefinition> {
    ALL_CHAINS.iter().find(|chain| chain.slug == slug)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::{
        Adapter, BlockHash, ChainDefinition, ChainId, EnvelopeSet, FinalityModel, FinalityPolicy,
        IdentityFingerprint, NativeCurrency, NetworkKind, Observation, ProtocolValidity,
        ReleaseGate, ReleaseGateDenial, ReviewWindow, RuleCoverage, SourceClaim, SourceReference,
        all_chains, chain_by_id, chain_by_slug, protocol_validity, release_signing_gate,
    };

    const NOW: u64 = 1_786_579_200;

    #[test]
    fn registry_has_exact_expected_matrix() {
        assert_eq!(all_chains().len(), 17);
        let mainnets = all_chains()
            .iter()
            .filter(|chain| chain.network_kind == NetworkKind::Mainnet)
            .count();
        let testnets = all_chains()
            .iter()
            .filter(|chain| chain.network_kind == NetworkKind::Testnet)
            .count();
        assert_eq!(mainnets, 8);
        assert_eq!(testnets, 9);
    }

    #[test]
    fn identifiers_names_and_slugs_are_unique() {
        let mut identifiers = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut slugs = BTreeSet::new();
        for chain in all_chains() {
            assert!(identifiers.insert(chain.chain_id));
            assert!(names.insert(chain.display_name));
            assert!(slugs.insert(chain.slug));
            assert!(!chain.sources.is_empty());
            assert!(
                chain
                    .transaction_envelopes
                    .contains(crate::TransactionEnvelope::LegacyEip155)
            );
            assert!(
                chain
                    .transaction_envelopes
                    .contains(crate::TransactionEnvelope::AccessListEip2930)
            );
            assert!(
                chain
                    .transaction_envelopes
                    .contains(crate::TransactionEnvelope::DynamicFeeEip1559)
            );
        }
    }

    #[test]
    fn every_definition_round_trips_through_both_lookups() {
        for expected in all_chains() {
            assert_eq!(chain_by_id(expected.chain_id), Some(expected));
            assert_eq!(chain_by_slug(expected.slug), Some(expected));
        }
        assert_eq!(chain_by_id(ChainId::ZERO), None);
        assert_eq!(chain_by_slug("not-a-chain"), None);
    }

    #[test]
    fn no_unreviewed_builtin_is_release_signing_eligible() {
        for definition in all_chains() {
            let observed_hash = match definition.identity {
                IdentityFingerprint::PinnedGenesis(hash) => Some(hash),
                IdentityFingerprint::Missing { .. } => None,
            };
            let observation = Observation {
                chain_id: definition.chain_id,
                genesis_block_hash: observed_hash,
            };
            assert_ne!(
                release_signing_gate(definition, observation, NOW),
                ReleaseGate::Eligible
            );
        }
    }

    #[test]
    fn missing_fingerprint_and_unknown_rules_have_distinct_denials() {
        let bsc = chain_by_slug("bsc-mainnet");
        assert!(bsc.is_some());
        if let Some(bsc) = bsc {
            let gate = release_signing_gate(
                bsc,
                Observation {
                    chain_id: bsc.chain_id,
                    genesis_block_hash: None,
                },
                NOW,
            );
            assert_eq!(
                gate,
                ReleaseGate::Denied(ReleaseGateDenial::MissingIdentityFingerprint)
            );
        }

        let ethereum = chain_by_slug("ethereum-mainnet");
        assert!(ethereum.is_some());
        if let Some(ethereum) = ethereum {
            let IdentityFingerprint::PinnedGenesis(genesis) = ethereum.identity else {
                return;
            };
            let gate = release_signing_gate(
                ethereum,
                Observation {
                    chain_id: ethereum.chain_id,
                    genesis_block_hash: Some(genesis),
                },
                NOW,
            );
            assert_eq!(
                gate,
                ReleaseGate::Denied(ReleaseGateDenial::RuleCoverageUnknown)
            );
        }
    }

    #[test]
    fn mismatched_observation_is_always_invalid() {
        let ethereum = chain_by_slug("ethereum-mainnet");
        assert!(ethereum.is_some());
        if let Some(ethereum) = ethereum {
            let observation = Observation {
                chain_id: ChainId::from_u64(56),
                genesis_block_hash: None,
            };
            assert_eq!(
                protocol_validity(ethereum, observation, NOW),
                ProtocolValidity::Invalid
            );
            assert_eq!(
                release_signing_gate(ethereum, observation, NOW),
                ReleaseGate::Denied(ReleaseGateDenial::InvalidIdentityObservation)
            );
        }
    }

    #[test]
    fn verified_and_expired_paths_are_covered() {
        const HASH: BlockHash = BlockHash::new([7; 32]);
        const SOURCES: &[SourceReference] = &[SourceReference {
            title: "test source",
            url: "https://example.invalid/source",
            claim: SourceClaim::GenesisIdentity,
        }];
        let definition = ChainDefinition {
            slug: "test-only",
            display_name: "Test Only",
            chain_id: ChainId::from_u64(999),
            network_kind: NetworkKind::Testnet,
            adapter: Adapter::EthereumPoS,
            native_currency: NativeCurrency {
                name: "Test Ether",
                symbol: "TETH",
                decimals: 18,
            },
            transaction_envelopes: EnvelopeSet::STANDARD,
            identity: IdentityFingerprint::PinnedGenesis(HASH),
            rules: RuleCoverage::Verified { revision: "test" },
            finality: FinalityPolicy {
                model: FinalityModel::EthereumRpcTags,
                coverage: RuleCoverage::Verified { revision: "test" },
            },
            review: ReviewWindow {
                reviewed_at_unix: 10,
                expires_at_unix: 20,
            },
            sources: SOURCES,
        };
        let observation = Observation {
            chain_id: definition.chain_id,
            genesis_block_hash: Some(HASH),
        };
        assert_eq!(
            protocol_validity(&definition, observation, 20),
            ProtocolValidity::Verified
        );
        assert_eq!(
            release_signing_gate(&definition, observation, 20),
            ReleaseGate::Eligible
        );
        assert_eq!(
            protocol_validity(&definition, observation, 21),
            ProtocolValidity::ExpiredReview
        );
    }

    #[test]
    fn known_rollup_testnets_track_sepolia_as_a_separate_finality_axis() {
        for slug in ["arbitrum-sepolia", "op-sepolia", "base-sepolia"] {
            let definition = chain_by_slug(slug);
            assert!(definition.is_some());
            if let Some(definition) = definition {
                assert!(matches!(
                    definition.finality.model,
                    FinalityModel::OptimisticRollup { .. }
                ));
                if let FinalityModel::OptimisticRollup {
                    parent_chain_id, ..
                } = definition.finality.model
                {
                    assert_eq!(parent_chain_id, ChainId::from_u64(11_155_111));
                }
            }
        }
    }
}
