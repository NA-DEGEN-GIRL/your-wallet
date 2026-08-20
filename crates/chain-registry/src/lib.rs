//! Inert, compile-time EVM chain metadata and fail-closed signing policy.
//!
//! This crate never performs network I/O and never loads executable behavior from
//! registry data. A [`ChainDefinition`] can select only an adapter compiled into
//! this crate. Missing identity anchors or transaction-rule reviews remain
//! explicit and make a built-in chain ineligible for release signing.

mod custom;
mod evidence;
mod registry;
mod rpc;
mod types;

pub use custom::{
    CustomChainError, CustomChainProposal, CustomSigningPolicy, CustomWarning,
    ValidatedCustomChain, validate_custom_chain,
};
pub use evidence::{BuiltInChainEvidence, EvidenceError, assess_builtin_chain};
pub use registry::{ALL_CHAINS, all_chains, chain_by_id, chain_by_slug};
pub use rpc::{RpcEndpointClass, RpcUrlError, classify_rpc_endpoint, validate_resolved_peer};
pub use types::{
    Adapter, BlockHash, ChainDefinition, ChainId, ChainIdParseError, EnvelopeSet, FinalityModel,
    FinalityPolicy, IdentityFingerprint, NativeCurrency, NetworkKind, Observation,
    ProtocolValidity, ReleaseGate, ReleaseGateDenial, ReviewWindow, RollupStack, RuleCoverage,
    SourceClaim, SourceReference, TransactionEnvelope, protocol_validity, release_signing_gate,
};
