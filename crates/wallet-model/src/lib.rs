//! Secret-free value types shared across wallet trust boundaries.
//!
//! This crate deliberately contains no private-key operations and no permissive
//! JSON deserialization. Untrusted wire values must be converted into the
//! canonical types exposed here by `wallet-protocol`.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]

mod bounded;
mod chain;
mod codec;
mod context;
mod operation;

pub use bounded::{Address20, BoundedBytes, BoundedText, Hash32, ParseValueError, U256};
pub use chain::{
    AdapterKind, BlockAnchor, ChainIdentity, ObservationConfidence, RpcObservation, RpcSourceId,
};
pub use codec::{CanonicalEncode, CodecError, Transcript};
pub use context::{
    ActivationNonce, BrowserContext, BrowserContextError, BrowserFamily, BrowserOrigin,
    BrowserProvenance, ChannelNonce, DocumentId, DocumentLifecycle, ExtensionId, NonceLeaseId,
    ProfileInstallId, RequestId, SessionId, SimulationEngine, SimulationProvenance,
};
pub use operation::{
    AccessListEntry, AccessListTransaction, CanonicalOperation, DynamicFeeTransaction,
    LegacyTransaction, MAX_ACCESS_LIST_ENTRIES, MAX_CALLDATA_BYTES, MAX_MESSAGE_BYTES,
    MAX_STORAGE_KEYS_PER_ENTRY, PersonalMessage, TransactionTarget, TypedDataV4,
    UntrustedAccessListEntry, UntrustedOperation, UntrustedTransaction, UntrustedTypedDataV4,
};
