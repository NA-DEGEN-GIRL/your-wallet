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
//! The release-bound Broker artifact admission is also private and dormant. It
//! cannot be constructed or used as an external launch surface:
//!
//! ```compile_fail
//! use platform_windows::broker_artifact::PreflightBrokerArtifact;
//! ```
//!
//! ```compile_fail
//! use platform_windows::broker_artifact::preflight_broker_artifact;
//! ```
//!
//! The resulting release supervisor and exact-image activation core remain
//! private and dormant too. The supervisor retains the admitted file and its
//! opaque Windows file identity through exact child cleanup; there is no
//! external launch or resource accessor surface:
//!
//! ```compile_fail
//! use platform_windows::broker_artifact::broker_supervisor::PreparedReleaseBrokerSupervisor;
//! ```
//!
//! ```compile_fail
//! use platform_windows::broker_artifact::prepare_release_broker_supervisor;
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
// This pure admission seam checks Broker role, complete release evidence, its
// distinct manifest allowlist, absolute verified path, and same-handle
// FILE_ID_INFO before its private child supervisor may allocate activation
// resources. Nesting gives only the admission module prepared-state minting
// authority.
#[allow(dead_code)]
mod broker_artifact;
// This persistent secretless native-host/Broker transport is composed by the
// private prepared-value activation core. Only the Windows debug feature adds
// cross-crate payload-only `broker::ipc` adapters. Chrome-launched native-host
// provenance, signed immutable installation/registration, stable extension
// identity, global launch coordination, and release attestation remain
// blocking; default and release entrypoints cannot reach either composition.
#[cfg(windows)]
#[allow(dead_code)]
mod broker_channel;
// The opaque same-handle identity query and mapped-image comparator serve the
// private release-prepared core. Only the sibling path-opening image wrapper is
// item-gated by the exact debug hook inside this private module.
#[cfg(windows)]
#[allow(dead_code)]
mod exact_image;
// All Rust `bInheritHandles=TRUE` process creation is sealed behind this one
// process-wide, thread-bound permit. Callers acquire it before creating any
// ephemeral inheritable handle and release it immediately after creation.
#[cfg(windows)]
mod inheritable_handle_launch;
// Exact image-file authentication and suspended-process ownership remain
// crate-private until the supervisor can bind the resulting capability to the
// private Broker channel and protected-settings lease.
#[cfg(windows)]
mod key_agent_activation;
#[cfg(windows)]
mod key_agent_child_bootstrap;
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
// Restricted helpers and the Key Agent share one immutable, OS-derived launch
// context so neither inherits the supervisor's environment or working folder.
#[cfg(windows)]
mod restricted_process_context;
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
#[cfg(all(
    windows,
    feature = "broker-channel-contract-test-hook",
    debug_assertions
))]
pub use broker_artifact::broker_supervisor::{
    DormantBrokerError, DormantBrokerPayloadChannel, connect_inherited_native_host_channel,
    launch_dormant_broker_channel,
};
#[cfg(windows)]
pub use key_agent_child_bootstrap::{
    KeyAgentChildBootstrapError, SealedKeyAgentStdio, seal_inherited_key_agent_stdio,
};
pub use secret_channel::{SecretInputChannelError, SecretInputValue, VerifiedSecretInput};
