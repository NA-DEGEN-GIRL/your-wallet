//! Windows-only trust-boundary primitives for the wallet native processes.
//!
//! The recovery launch facade is deliberately not public. External callers
//! cannot obtain its raw pipes, requests, or one-shot stage receipts:
//!
//! ```compile_fail
//! use platform_windows::recovery_channel::launch_recovery_display_frontend;
//! ```
//!
//! ```compile_fail
//! use platform_windows::pipe::PrivateSecretInputPipes;
//! ```
//!
//! The exact Key Agent process-activation proof is likewise a dormant,
//! supervisor-internal capability. External crates cannot construct or resume
//! it. All creator-thread-bound debug operations finish on one fresh worker;
//! only the proven detached-and-suspended capability crosses that join:
//!
//! ```compile_fail
//! use platform_windows::key_agent_activation::HeldKeyAgentActivation;
//! ```
//!
//! ```compile_fail
//! use platform_windows::key_agent_activation::activate_key_agent;
//! ```
//!
//! The fully bound dormant supervisor aggregate is private as well. External
//! crates cannot obtain its Job, parent pipe endpoints, startup lease, or held
//! process, and there is no resume operation:
//!
//! ```compile_fail
//! use platform_windows::key_agent_supervisor::BoundDormantKeyAgent;
//! ```
//!
//! ```compile_fail
//! use platform_windows::key_agent_supervisor::bind_dormant_key_agent;
//! ```
//!
//! The public one-shot helper launcher also rejects the manifest-derived Key
//! Agent role; an allowlisted Key Agent cannot use that resumed-process path.

#![cfg_attr(not(windows), allow(dead_code))]

#[allow(dead_code)]
mod anchor_registry;
mod approval_channel;
pub mod attestation;
pub mod helper;
// Exact image-file authentication and suspended-process ownership remain
// crate-private until the supervisor can bind the resulting capability to the
// private Broker channel and protected-settings lease.
#[cfg(windows)]
mod key_agent_activation;
#[cfg(windows)]
mod key_agent_root_job;
// The startup lease, private parent channel, root Job, and exact-image
// activation are one dormant aggregate with no resume path. Protected-settings
// authorization, the Broker protocol, and a distinct Key Agent LPAC/storage
// policy remain intentionally unbound and release-blocking.
#[cfg(windows)]
mod key_agent_supervisor;
pub mod launch;
pub mod pipe;
// Recovery display/confirmation remain dormant until the Key Agent adapter can
// bind requests to a live protected-settings lease. Keeping the entire facade
// crate-private prevents arbitrary anti-phishing phrase provenance.
#[allow(dead_code)]
mod recovery_channel;
// The authenticated Secret Input arming seam is intentionally crate-private
// and dormant until a Key Agent leaf adapter can mint live protected-state
// authorization. Keeping it compiled and tested without exporting a raw UI
// launcher is the desired fail-closed state.
#[allow(dead_code)]
mod secret_channel;
pub mod storage;
pub use approval_channel::{
    ApprovalChannelError, ApprovalLaunchError, VerifiedApprovalDecision, VerifiedApprovalResponse,
};
#[cfg(windows)]
pub use approval_channel::{PendingApproval, launch_approval_frontend};
pub use secret_channel::{SecretInputChannelError, SecretInputValue, VerifiedSecretInput};
