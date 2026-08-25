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
//! The exact Key Agent process-activation proof is likewise a
//! supervisor-internal capability. External crates cannot construct or resume
//! it. All creator-thread-bound debug operations finish on one fresh worker;
//! internally, the detached-and-suspended proof has only one consuming
//! transition into the fixed storage-startup exchange:
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
//! crates cannot obtain its Job, parent pipe endpoints, startup lease, held
//! process, or fixed resume transition:
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
//! The crate-private one-shot helper launcher also rejects the manifest-derived
//! Key Agent role; an allowlisted Key Agent cannot use that resumed-process path.
//! The crate-private legacy Approval entry point returns
//! `LogicalParentUnavailable` before allocation and cannot return a held
//! process. `LaunchedHelper` is separately crate-private for other internal paths:
//!
//! ```compile_fail
//! use platform_windows::launch_approval_frontend;
//! ```
//!
//! ```compile_fail
//! use platform_windows::launch::LaunchedHelper;
//! ```

#![cfg_attr(not(windows), allow(dead_code))]

#[allow(dead_code)]
mod anchor_registry;
#[cfg(windows)]
mod appcontainer_profile_api;
#[allow(dead_code)]
mod approval_channel;
// One platform-issued monotonic Approval lifetime splits into move-only
// authorization and transport halves. Only the matching authorization half can
// bind the single-use transport half to one canonical request; the resulting
// carrier exposes its request and exact original deadline only inside this
// crate. It has no response or signing conversion.
#[allow(dead_code)]
mod approval_transport;
// The production-compiled Approval activation first creates the complete
// parent-bound process suspended. One sealed consuming transition writes its
// five-object parent hello, resumes exactly once, and authenticates the child
// hello. A second sealed transition accepts no raw request or deadline: it
// consumes that opaque bootstrap, opens its one-shot bound transport carrier
// internally, and applies the exact original monotonic deadline to
// finish/request EOF, response/EOF, and natural child exit code zero. After the
// post-exit Key Agent revalidation it observes that deadline once more, then the
// terminal retains the carrier. The
// `VerifiedParentBoundApprovalExchange` has zero production callers and no
// public response or signing conversion. Its final Key Agent check is only
// point-in-time evidence; any future authorization edge must revalidate the
// retained exact Key Agent immediately before use.
#[cfg(windows)]
#[allow(dead_code)]
mod approval_activation;
// Approval release admission and parent binding remain deliberately dormant.
// They retain the verified pinned artifact, whole-release/file identities, and
// exact Key Agent logical-parent proof without exposing raw constituents. The
// sealed full exchange above still does not prove the mapped Approval image,
// process-object DACL/principal split, or complete runtime/signing composition.
// The platform-issued non-Clone authorization/transport halves now preserve one
// exact monotonic issuance identity through request binding, dormant activation,
// bootstrap, full exchange, and terminal retention.
#[cfg(windows)]
#[allow(dead_code)]
mod approval_parent;
#[cfg(windows)]
#[allow(dead_code)]
mod approval_supervisor;
pub mod attestation;
pub mod helper;
// This dormant admission seam checks Broker role, complete release evidence, its
// distinct manifest allowlist, and absolute verified path, then retains the
// opaque whole-release identity through same-handle FILE_ID_INFO preparation.
// The release, manifest, and exact file-object proofs remain separate before
// its private child supervisor may allocate activation resources. Nesting gives
// only the admission module prepared-state minting authority. It creates no
// Broker/Key Agent same-release aggregate, authenticated topology, single-instance
// proof, or runtime/signing authority, and no production caller exists.
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
// The fixed-name SCM host is an inert, debug-only Phase 1 feasibility fixture.
// It owns no wallet state, IPC endpoint, user token, helper, or signing path.
// Default and release callers receive only a fail-closed unavailable result.
mod key_agent_service;
// Held existing-install adoption bookends the pure authenticated-snapshot
// matcher with exact root/profile-binding revalidation. Its compiled dormant
// binding separately matches the journal's whole-release ArtifactDigest to the
// attested release while retaining helper-manifest and file-object proofs. It
// remains production-unreachable: there is no authoritative profile observer
// or production caller for the dormant existing-root opener, nor any installer
// key/checkpoint or journal I/O backend, exclusive installer lease, binding
// caller, recovery/upgrade path, or release activation yet.
#[cfg(windows)]
#[allow(dead_code)]
mod key_agent_install_adoption;
// Pure, sealed install-state classification is compiled for review and tests.
// Its snapshot matcher has only the dormant held-object adoption consumer; the
// journal validator still has no production evidence source or I/O backend.
// Fresh OS objects remain non-launchable until a future installer-owned
// authenticated provenance and authoritative-reread ceremony exists.
#[cfg(windows)]
#[allow(dead_code)]
mod key_agent_install_provenance;
// Fixed, zero-capability Key Agent LPAC provisioning and suspended-token proof
// remain private to the dormant activation boundary. No caller can select a
// profile name, SID, capability, or raw token attribute.
#[cfg(windows)]
mod key_agent_lpac;
#[cfg(windows)]
mod key_agent_root_job;
// Fresh fixed-profile/root creation yields only non-launchable pending objects.
// A dormant zero-caller existing-root opener rebinds a fixed canonical path to
// the same retained identity, but supplies no higher-level install authority.
// The startup path accepts a separately prepared supervisor-held proof; the
// child independently path-opens and retains that same object while the parent
// retains and revalidates its peer handle.
#[cfg(windows)]
mod key_agent_storage;
// The fixed startup transcript binds the supervisor's nonce and suspended
// process instance to the root identity independently reopened by the child.
// It remains crate-private and carries no signing or general IPC authority.
#[cfg(windows)]
mod key_agent_startup;
// The startup lease, private parent channel, root Job, exact-image activation,
// and child-opened root evidence form one private one-shot transition. No
// generic runtime or signing operation is exposed; protected-settings
// authorization and the Broker/topology protocol remain release-blocking.
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
pub use approval_transport::{
    ApprovalAuthorizationWindow, ApprovalSessionWindowError, ApprovalTransportWindow,
    BoundApprovalTransport, IssuedApprovalSessionWindow,
};
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
    KeyAgentChildBootstrapError, serve_inherited_key_agent_storage_startup,
};
pub use key_agent_service::{
    KEY_AGENT_SERVICE_NAME, KeyAgentServiceFixtureError, run_inert_key_agent_service_fixture,
};
pub use secret_channel::{SecretInputChannelError, SecretInputValue, VerifiedSecretInput};
