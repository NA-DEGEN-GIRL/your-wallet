//! Validation and state machines between untrusted wallet inputs and signing.
//!
//! The APIs in this crate are intentionally narrow: callers cannot construct a
//! signer-ready operation without passing strict validation, approvals are bound
//! to deterministic transcripts, and a nonce is never automatically reusable
//! after signing might have occurred.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]

mod approval;
mod authorization;
mod error;
mod nonce;
mod policy;
mod validation;

pub use approval::{
    APPROVAL_TTL_MAX_MS, ApprovalDecision, ApprovalNonce, ApprovalSessionState, display_digest,
};
pub use authorization::{
    AuthorizationOperation, AuthorizationRequest, AuthorizedOperation, AuthorizedOperationRef,
    PreparedAuthorization, prepare_authorization,
};
pub use error::{ErrorField, ProtocolError, ProtocolErrorKind, ProviderError};
pub use nonce::{
    CandidateId, CandidateLifecycle, FinalityState, InclusionState, NonceCandidate, NonceLease,
    NonceLedger, NonceSlot, ReleasedNonce,
};
pub use policy::{InvalidProtocolReason, ProtocolDisposition, ProtocolValidity, ReleaseChannel};
pub use validation::{OperationValidator, SignedSchemaAllowlist, ValidatedOperation};
