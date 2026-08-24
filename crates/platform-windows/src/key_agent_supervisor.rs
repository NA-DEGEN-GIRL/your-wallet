//! Supervisor-owned dormant and storage-proven Key Agent bootstrap states.
//!
//! This module contains exactly one consuming resume transition for the fixed
//! storage-startup exchange and no general runtime operation. Its nonce,
//! process-instance binding, root identity, and monotonic deadline remain
//! separate from the Key Agent's protected-settings lease, which may be issued
//! only after later authenticated settings and topology boundaries exist.

#![allow(dead_code)]

use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;
use std::os::windows::io::BorrowedHandle;
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::approval_activation::ApprovalActivationSeal;
#[cfg(test)]
use crate::attestation::ReleaseAttestation;
#[cfg(test)]
use crate::helper::VerifiedHelper;
#[cfg(test)]
use crate::key_agent_activation::activate_preflighted_key_agent_on_fresh_worker_for_kernel_test;
#[cfg(test)]
use crate::key_agent_activation::preflight_key_agent_activation;
use crate::key_agent_activation::{
    HeldKeyAgentActivation, KeyAgentActivationError, PreparedApprovalParentProcess,
    RunningKeyAgentActivation, activate_preflighted_key_agent_on_fresh_worker,
    prepare_approval_parent_process, run_on_fresh_key_agent_debug_thread,
};
#[cfg(test)]
use crate::key_agent_install_adoption::verified_install_continuity_for_supervisor_test;
use crate::key_agent_install_adoption::{
    ArtifactBoundExistingKeyAgentInstall, VerifiedKeyAgentInstallContinuity,
    consume_artifact_bound_existing_key_agent_install,
};
use crate::key_agent_lpac::{
    KeyAgentLpacError, PendingKeyAgentProvisioning, PreparedKeyAgentProvisioning,
};
use crate::key_agent_root_job::{KeyAgentRootJob, KeyAgentRootJobError};
use crate::key_agent_startup::{
    KEY_AGENT_STARTUP_REQUEST_BYTES, KEY_AGENT_STARTUP_RESPONSE_BYTES, KeyAgentStartupCodecError,
    KeyAgentStartupRequest, KeyAgentStartupResponse,
};
use crate::launch::{ApprovalLogicalParentInjectionSeal, InjectedApprovalLogicalParent};
use crate::pipe::{
    KeyAgentStartupRequestWriter, KeyAgentStartupResponseReader, PipeError, PrivateKeyAgentPipes,
};

const ACTIVATION_NONCE_BYTES: usize = 32;
const STARTUP_TRANSCRIPT_BYTES: usize = 32;
const STARTUP_TRANSCRIPT_DOMAIN: &[u8] = b"your-wallet/key-agent-storage-startup/v1\0";

/// Unforgeable permission for the adoption module's sole supervisor split.
///
/// The private field means only this module can mint the value. Architecture
/// checks fix its one construction inside [`bind_dormant_key_agent`].
pub(crate) struct KeyAgentSupervisorBindingSeal {
    _private: (),
}
const MAX_STARTUP_LIFETIME: Duration = Duration::from_mins(2);
const RANDOMNESS_ATTEMPTS: usize = 4;

#[derive(Clone, Copy)]
enum StartupResponseTransport {
    Exact,
    #[cfg(test)]
    PinnedLibtestTerse,
}

/// Stable failures while minting a supervisor-only startup lease.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum KeyAgentSupervisorError {
    /// The caller requested an empty startup interval.
    #[error("Key Agent startup lifetime is invalid")]
    InvalidLifetime,
    /// The trusted monotonic deadline could not be represented.
    #[error("Key Agent startup deadline is unavailable")]
    DeadlineUnavailable,
    /// The operating system did not provide a nonzero activation nonce.
    #[error("Key Agent activation randomness is unavailable")]
    RandomnessUnavailable,
    /// The child did not echo the exact one-attempt activation nonce.
    #[error("Key Agent startup binding is invalid")]
    BindingMismatch,
    /// The child response arrived at or after the trusted monotonic deadline.
    #[error("Key Agent startup deadline expired")]
    Expired,
    /// The release-gated exact-image activation proof failed closed.
    #[error("Key Agent dormant activation failed")]
    Activation,
    /// The private parent/child channel could not be created exactly.
    #[error("Key Agent private channel is unavailable")]
    PrivateChannel,
    /// The root Job policy could not be created or revalidated exactly.
    #[error("Key Agent root Job policy is unavailable")]
    RootJobPolicy,
    /// The pending or independently verified fixed profile/storage state failed.
    #[error("Key Agent profile/storage provisioning is unavailable")]
    Provisioning,
    /// The exact fixed startup frame or returned identity proof was invalid.
    #[error("Key Agent storage-startup protocol failed")]
    StartupProtocol,
}

impl From<KeyAgentActivationError> for KeyAgentSupervisorError {
    fn from(_error: KeyAgentActivationError) -> Self {
        Self::Activation
    }
}

impl From<PipeError> for KeyAgentSupervisorError {
    fn from(_error: PipeError) -> Self {
        Self::PrivateChannel
    }
}

impl From<KeyAgentRootJobError> for KeyAgentSupervisorError {
    fn from(_error: KeyAgentRootJobError) -> Self {
        Self::RootJobPolicy
    }
}

impl From<KeyAgentLpacError> for KeyAgentSupervisorError {
    fn from(_error: KeyAgentLpacError) -> Self {
        Self::Provisioning
    }
}

impl From<KeyAgentStartupCodecError> for KeyAgentSupervisorError {
    fn from(_error: KeyAgentStartupCodecError) -> Self {
        Self::StartupProtocol
    }
}

/// Non-cloneable supervisor authority for one startup attempt.
///
/// This nonce is a channel/replay binding, not a settings or signing
/// capability. It must never be used as a substitute for the Key Agent's
/// internally minted protected-settings lease.
struct SupervisorActivationLease {
    nonce: Zeroizing<[u8; ACTIVATION_NONCE_BYTES]>,
    expires_at: Instant,
}

impl SupervisorActivationLease {
    /// Mints one fresh lease and clamps the requested lifetime to two minutes.
    fn issue(requested_lifetime: Duration) -> Result<Self, KeyAgentSupervisorError> {
        if requested_lifetime.is_zero() {
            return Err(KeyAgentSupervisorError::InvalidLifetime);
        }
        let effective_lifetime = requested_lifetime.min(MAX_STARTUP_LIFETIME);
        let expires_at = Instant::now()
            .checked_add(effective_lifetime)
            .ok_or(KeyAgentSupervisorError::DeadlineUnavailable)?;

        let mut nonce = Zeroizing::new([0_u8; ACTIVATION_NONCE_BYTES]);
        for _ in 0..RANDOMNESS_ATTEMPTS {
            getrandom::fill(nonce.as_mut())
                .map_err(|_| KeyAgentSupervisorError::RandomnessUnavailable)?;
            if nonce
                .as_ref()
                .ct_eq(&[0_u8; ACTIVATION_NONCE_BYTES])
                .unwrap_u8()
                == 0
            {
                return Ok(Self { nonce, expires_at });
            }
        }
        Err(KeyAgentSupervisorError::RandomnessUnavailable)
    }

    /// Returns the exact nonce for the one authenticated child request.
    fn nonce_for_child(&self) -> &[u8; ACTIVATION_NONCE_BYTES] {
        &self.nonce
    }

    /// Rechecks the internally sampled monotonic deadline without accepting a
    /// caller-provided clock value.
    fn ensure_live(&self) -> Result<(), KeyAgentSupervisorError> {
        (Instant::now() < self.expires_at)
            .then_some(())
            .ok_or(KeyAgentSupervisorError::Expired)
    }

    fn expires_at(&self) -> Instant {
        self.expires_at
    }

    #[cfg(test)]
    fn ensure_live_at_for_test(&self, now: Instant) -> Result<(), KeyAgentSupervisorError> {
        (now < self.expires_at)
            .then_some(())
            .ok_or(KeyAgentSupervisorError::Expired)
    }

    /// Consumes this attempt while checking the exact echoed nonce and trusted
    /// monotonic deadline. The returned transcript proof remains private to
    /// this module and grants no protected-settings or runtime authority.
    fn verify_and_consume(
        self,
        candidate: &[u8; ACTIVATION_NONCE_BYTES],
        transcript_commitment: [u8; STARTUP_TRANSCRIPT_BYTES],
    ) -> Result<VerifiedSupervisorHandshake, KeyAgentSupervisorError> {
        self.ensure_live()?;
        if self.nonce.as_ref().ct_eq(candidate).unwrap_u8() == 0 {
            return Err(KeyAgentSupervisorError::BindingMismatch);
        }
        Ok(VerifiedSupervisorHandshake {
            nonce: self.nonce,
            expires_at: self.expires_at,
            transcript_commitment: Zeroizing::new(transcript_commitment),
        })
    }

    #[cfg(test)]
    fn verify_and_consume_at_for_test(
        self,
        candidate: &[u8; ACTIVATION_NONCE_BYTES],
        now: Instant,
        transcript_commitment: [u8; STARTUP_TRANSCRIPT_BYTES],
    ) -> Result<VerifiedSupervisorHandshake, KeyAgentSupervisorError> {
        self.ensure_live_at_for_test(now)?;
        if self.nonce.as_ref().ct_eq(candidate).unwrap_u8() == 0 {
            return Err(KeyAgentSupervisorError::BindingMismatch);
        }
        Ok(VerifiedSupervisorHandshake {
            nonce: self.nonce,
            expires_at: self.expires_at,
            transcript_commitment: Zeroizing::new(transcript_commitment),
        })
    }

    #[cfg(test)]
    fn with_test_parts(nonce: [u8; ACTIVATION_NONCE_BYTES], expires_at: Instant) -> Self {
        Self {
            nonce: Zeroizing::new(nonce),
            expires_at,
        }
    }
}

impl fmt::Debug for SupervisorActivationLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SupervisorActivationLease")
            .field("nonce", &"[REDACTED]")
            .field("expires_at", &"[TRUSTED MONOTONIC DEADLINE]")
            .finish()
    }
}

/// Opaque evidence that the exact child response consumed one live lease.
struct VerifiedSupervisorHandshake {
    nonce: Zeroizing<[u8; ACTIVATION_NONCE_BYTES]>,
    expires_at: Instant,
    transcript_commitment: Zeroizing<[u8; STARTUP_TRANSCRIPT_BYTES]>,
}

impl VerifiedSupervisorHandshake {
    /// Reports whether the completed startup proof remains inside its lease.
    fn is_live(&self) -> bool {
        Instant::now() < self.expires_at
    }
}

impl fmt::Debug for VerifiedSupervisorHandshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedSupervisorHandshake")
            .field("nonce", &"[REDACTED]")
            .field("expires_at", &"[TRUSTED MONOTONIC DEADLINE]")
            .field("transcript_commitment", &"[REDACTED SHA-256]")
            .finish()
    }
}

/// One exact Key Agent activation bound to all supervisor-owned resources.
///
/// This capability is crate-private, non-cloneable, and deliberately `!Sync`.
/// It owns the detached-and-suspended exact-image proof, the two-process
/// kill-on-close root Job, both unique parent pipe endpoints, and the one-shot
/// startup lease, authenticated install/release continuity, and the
/// independently verified profile/storage proof. The short-lived inheritable
/// child handles and creation attributes have already been dropped before this
/// value can cross the fresh worker join.
///
/// Field order is security-significant: Drop first releases the exact suspended
/// activation, then the retained root Job, before closing the parent channel
/// endpoints, zeroizing the startup nonce, and finally closing the no-delete-
/// share storage-root handle. Those process owners attempt bounded synchronous
/// cleanup, but Drop cannot report failure and retained kill-on-close Job closure
/// remains the fallback. No raw handle, path, SID, pipe name, debugger operation,
/// or generic resume operation is exposed.
#[must_use = "dropping this state attempts bounded Key Agent cleanup before kill-on-close fallback"]
pub(crate) struct BoundDormantKeyAgent {
    activation: HeldKeyAgentActivation,
    root_job: KeyAgentRootJob,
    request_writer: KeyAgentStartupRequestWriter,
    response_reader: KeyAgentStartupResponseReader,
    startup_lease: SupervisorActivationLease,
    install_continuity: VerifiedKeyAgentInstallContinuity,
    not_sync: PhantomData<Cell<()>>,
    provisioning: PreparedKeyAgentProvisioning,
}

impl fmt::Debug for BoundDormantKeyAgent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundDormantKeyAgent")
            .field("activation", &"[DETACHED SUSPENDED KEY AGENT]")
            .field("root_job", &"[TWO-PROCESS KILL-ON-CLOSE ROOT JOB]")
            .field("request_writer", &"[UNIQUE STARTUP REQUEST HANDLE]")
            .field("response_reader", &"[UNIQUE STARTUP RESPONSE HANDLE]")
            .field("startup_lease", &"[ONE-SHOT NONCE AND MONOTONIC DEADLINE]")
            .field(
                "install_continuity",
                &"[AUTHENTICATED INSTALL/RELEASE CONTINUITY]",
            )
            .field("provisioning", &"[VERIFIED PROFILE AND HELD STORAGE ROOT]")
            .finish_non_exhaustive()
    }
}

/// One exact Key Agent whose sole permitted user-mode step proved that it
/// reopened the supervisor-held storage root and observed the same process
/// instance and startup nonce.
///
/// Both startup connection epochs have ended in exact EOF before this private
/// capability is minted, and it exposes no runtime request operation or signing
/// authority. Field order is security-significant: Drop first releases the
/// running activation and then the retained root Job before transcript proof,
/// install/release continuity, or held provisioning state. Those owners attempt
/// bounded synchronous cleanup, but Drop cannot report failure and retained
/// kill-on-close Job closure remains the fallback. This does not prove a child
/// key bundle, rollback anchor, protected settings state, or runtime/signing
/// authority.
#[must_use = "dropping this state attempts bounded Key Agent cleanup before kill-on-close fallback"]
pub(crate) struct BoundStorageProvenKeyAgent {
    activation: RunningKeyAgentActivation,
    root_job: KeyAgentRootJob,
    handshake: VerifiedSupervisorHandshake,
    install_continuity: VerifiedKeyAgentInstallContinuity,
    not_sync: PhantomData<Cell<()>>,
    provisioning: PreparedKeyAgentProvisioning,
}

impl fmt::Debug for BoundStorageProvenKeyAgent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundStorageProvenKeyAgent")
            .field("activation", &"[DETACHED RUNNING KEY AGENT]")
            .field("root_job", &"[TWO-PROCESS KILL-ON-CLOSE ROOT JOB]")
            .field("startup_streams", &"[EXACT EOF; NO RETAINED ENDPOINTS]")
            .field("handshake", &"[VERIFIED STORAGE-STARTUP TRANSCRIPT]")
            .field(
                "install_continuity",
                &"[AUTHENTICATED INSTALL/RELEASE CONTINUITY]",
            )
            .field("provisioning", &"[VERIFIED PROFILE AND HELD STORAGE ROOT]")
            .finish_non_exhaustive()
    }
}

/// One intact storage-proven Key Agent plus a least-authority proof source for
/// a future Approval parent binding.
///
/// The aggregate is non-cloneable and exposes neither its process capability
/// nor any retained proof. The exact Key Agent remains owned first so Drop or
/// unwind attempts bounded cleanup and releases its retained kill-on-close Job
/// before the narrow duplicate handle and all later-held evidence. Drop cannot
/// report synchronous cleanup failure. This state does not prove that an
/// Approval LPAC can use the handle or that a process DACL, distinct supervisor
/// principal, mapped image, or endpoint topology exists.
#[must_use = "dropping this state attempts bounded Key Agent cleanup before kill-on-close fallback"]
pub(crate) struct ApprovalParentSourcePreparedKeyAgent {
    storage_proven: BoundStorageProvenKeyAgent,
    parent_process: PreparedApprovalParentProcess,
    response_transport: StartupResponseTransport,
}

impl fmt::Debug for ApprovalParentSourcePreparedKeyAgent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "ApprovalParentSourcePreparedKeyAgent([STORAGE-PROVEN KEY AGENT; EXACT QLI+SYNCHRONIZE PARENT SOURCE])",
        )
    }
}

impl ApprovalParentSourcePreparedKeyAgent {
    /// Revalidates the complete exact Key Agent parent source while the sole
    /// Approval activation authority is live.
    pub(crate) fn revalidate_for_approval_activation(
        &self,
        _seal: &ApprovalActivationSeal,
    ) -> Result<(), KeyAgentSupervisorError> {
        self.revalidate_parent_source()
    }

    /// Injects the exact narrow Key Agent process handle into one still-
    /// suspended Approval child without exposing the source handle.
    pub(crate) fn inject_into_suspended_approval(
        &self,
        suspended_child: BorrowedHandle<'_>,
        seal: &ApprovalLogicalParentInjectionSeal,
    ) -> Result<InjectedApprovalLogicalParent, KeyAgentSupervisorError> {
        self.revalidate_parent_source()?;
        let injected = self
            .parent_process
            .duplicate_into_suspended_approval(suspended_child, seal)?;
        self.revalidate_parent_source()?;
        Ok(injected)
    }

    fn revalidate_parent_source(&self) -> Result<(), KeyAgentSupervisorError> {
        revalidate_post_startup_state(
            &self.storage_proven.provisioning,
            &self.storage_proven.root_job,
            &self.storage_proven.activation,
            self.response_transport,
        )?;
        self.parent_process.revalidate().map_err(Into::into)
    }
}

#[cfg(test)]
impl ApprovalParentSourcePreparedKeyAgent {
    pub(crate) fn revalidate_for_lpac_probe(&self) -> Result<(), KeyAgentSupervisorError> {
        self.revalidate_parent_source()
    }
}

/// Consumes the complete storage-proven aggregate and mints one exact,
/// non-inheritable `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE` duplicate.
///
/// All resident, storage, root-Job membership, limit, and topology checks run
/// both before and after duplication. No PID reopen, raw handle, launch state,
/// or general desired-access argument crosses this boundary.
pub(crate) fn prepare_approval_parent_source(
    storage_proven: BoundStorageProvenKeyAgent,
) -> Result<ApprovalParentSourcePreparedKeyAgent, KeyAgentSupervisorError> {
    prepare_approval_parent_source_with_transport(storage_proven, StartupResponseTransport::Exact)
}

#[cfg(test)]
pub(crate) fn prepare_approval_parent_source_for_kernel_test(
    storage_proven: BoundStorageProvenKeyAgent,
) -> Result<ApprovalParentSourcePreparedKeyAgent, KeyAgentSupervisorError> {
    prepare_approval_parent_source_with_transport(
        storage_proven,
        StartupResponseTransport::PinnedLibtestTerse,
    )
}

fn prepare_approval_parent_source_with_transport(
    storage_proven: BoundStorageProvenKeyAgent,
    response_transport: StartupResponseTransport,
) -> Result<ApprovalParentSourcePreparedKeyAgent, KeyAgentSupervisorError> {
    revalidate_post_startup_state(
        &storage_proven.provisioning,
        &storage_proven.root_job,
        &storage_proven.activation,
        response_transport,
    )?;
    let parent_process = prepare_approval_parent_process(&storage_proven.activation)?;
    revalidate_post_startup_state(
        &storage_proven.provisioning,
        &storage_proven.root_job,
        &storage_proven.activation,
        response_transport,
    )?;
    parent_process.revalidate()?;
    Ok(ApprovalParentSourcePreparedKeyAgent {
        storage_proven,
        parent_process,
        response_transport,
    })
}

/// Performs the one-time fresh profile and fixed storage-root ceremony.
///
/// An already-existing profile or root fails closed. This seam deliberately
/// does not adopt, repair, or delete persistent `AppContainer` state; a future
/// trusted installer must supply durable provenance for that separate path.
/// The result cannot be passed to [`bind_dormant_key_agent`]: fresh objects do
/// not become launch authority before an independently authenticated committed
/// provenance record is authoritatively reread and matched.
pub(crate) fn provision_fresh_key_agent_boundary()
-> Result<PendingKeyAgentProvisioning, KeyAgentSupervisorError> {
    PendingKeyAgentProvisioning::provision_fresh().map_err(Into::into)
}

/// Binds one release-preflighted exact Key Agent without executing user code.
///
/// Release, manifest-role, allowlist, and path checks happen before the worker
/// or any Job/pipe resource exists. The internally sampled startup deadline
/// therefore covers worker creation and the complete dormant binding. Inside
/// the activation-owned fresh worker, lifetime-bound Job and inherited-handle
/// attributes cannot escape the exact `CreateProcessW` call. The child remains
/// detached with one proven suspend count when the aggregate returns.
///
/// The input has already bound durable installer provenance to the exact
/// preflighted whole-release identity and pinned Key Agent artifact. This
/// function then configures and proves the fixed zero-capability Key Agent LPAC
/// plus one verified supervisor-held storage root, but stops before the sibling
/// one-shot storage-startup transition. Protected settings, child-side
/// key/anchor authority, and authenticated topology remain absent, so the
/// returned state is not runtime-ready or signing-capable.
pub(crate) fn bind_dormant_key_agent(
    bound: ArtifactBoundExistingKeyAgentInstall,
) -> Result<BoundDormantKeyAgent, KeyAgentSupervisorError> {
    let (preflighted, provisioning, install_continuity) =
        consume_artifact_bound_existing_key_agent_install(
            bound,
            KeyAgentSupervisorBindingSeal { _private: () },
        );
    provisioning.revalidate()?;
    let startup_lease = SupervisorActivationLease::issue(MAX_STARTUP_LIFETIME)?;

    run_on_fresh_key_agent_debug_thread(move |fresh_thread| {
        startup_lease.ensure_live()?;
        provisioning.revalidate()?;
        let root_job = KeyAgentRootJob::create()?;
        let pipes = PrivateKeyAgentPipes::create()?;
        let root_job_attribute = root_job.creation_attribute()?;

        let activation = activate_preflighted_key_agent_on_fresh_worker(
            fresh_thread,
            preflighted,
            &provisioning,
            &pipes,
            &root_job,
            &root_job_attribute,
            startup_lease.expires_at(),
        )?;

        // The Job attribute is creation-only. The activation leaf has already
        // closed all three inheritable handles and released the process-wide
        // launch flight immediately after `CreateProcessW` returned.
        drop(root_job_attribute);

        root_job.recheck_supervisor_context()?;
        root_job.verify_effective_limits()?;
        if root_job.active_process_count()? != 1 {
            return Err(KeyAgentSupervisorError::RootJobPolicy);
        }

        let (request_writer, response_reader) = pipes.into_parent();
        provisioning.revalidate()?;
        startup_lease.ensure_live()?;
        Ok(BoundDormantKeyAgent {
            activation,
            root_job,
            request_writer,
            response_reader,
            startup_lease,
            install_continuity,
            not_sync: PhantomData,
            provisioning,
        })
    })
}

/// Executes only the fixed storage-startup probe for a dormant production Key
/// Agent and returns a private, non-operational proof aggregate.
///
/// The request is written while the child is still suspended. Exactly one
/// verified suspend count is then released; the child must reopen the fixed
/// root by path and echo the nonce, process instance, creation time, and full
/// `FILE_ID_INFO` identity before the deadline. No general request/response
/// operation becomes available after this transition.
pub(crate) fn bind_key_agent_storage_startup(
    bound: BoundDormantKeyAgent,
) -> Result<BoundStorageProvenKeyAgent, KeyAgentSupervisorError> {
    let request = KeyAgentStartupRequest::new(
        bound.startup_lease.nonce_for_child(),
        bound.activation.process_id(),
        bound.activation.creation_time(),
        bound.provisioning.storage_root_identity(),
    )?;
    bind_key_agent_storage_startup_with_request(bound, &request, StartupResponseTransport::Exact)
}

#[cfg(test)]
fn bind_key_agent_storage_startup_for_kernel_test(
    bound: BoundDormantKeyAgent,
) -> Result<BoundStorageProvenKeyAgent, KeyAgentSupervisorError> {
    let storage_leaf = bound
        .provisioning
        .storage_root_path_for_test()
        .file_name()
        .and_then(|leaf| leaf.to_str())
        .ok_or(KeyAgentSupervisorError::StartupProtocol)?;
    let request = KeyAgentStartupRequest::new_for_test(
        bound.startup_lease.nonce_for_child(),
        bound.activation.process_id(),
        bound.activation.creation_time(),
        bound.provisioning.storage_root_identity(),
        storage_leaf,
    )?;
    bind_key_agent_storage_startup_with_request(
        bound,
        &request,
        StartupResponseTransport::PinnedLibtestTerse,
    )
}

fn bind_key_agent_storage_startup_with_request(
    bound: BoundDormantKeyAgent,
    request: &KeyAgentStartupRequest,
    response_transport: StartupResponseTransport,
) -> Result<BoundStorageProvenKeyAgent, KeyAgentSupervisorError> {
    bound.startup_lease.ensure_live()?;
    bound.provisioning.revalidate()?;
    if bound
        .startup_lease
        .nonce_for_child()
        .ct_eq(request.nonce())
        .unwrap_u8()
        == 0
        || request.expected_process_id() != bound.activation.process_id()
        || request.expected_creation_time() != bound.activation.creation_time()
        || request.storage_root_identity() != bound.provisioning.storage_root_identity()
    {
        return Err(KeyAgentSupervisorError::StartupProtocol);
    }

    let request_frame = request.encode()?;
    let deadline = bound.startup_lease.expires_at();
    let artifact_identity = bound.activation.artifact_identity();
    let BoundDormantKeyAgent {
        activation,
        root_job,
        request_writer,
        response_reader,
        startup_lease,
        install_continuity,
        not_sync: _,
        provisioning,
    } = bound;

    match request_writer.send(request_frame.as_bytes(), deadline) {
        Ok(()) => {}
        Err(error) => {
            drop(activation);
            return Err(error.into());
        }
    }
    if let Err(error) = startup_lease.ensure_live() {
        drop(activation);
        return Err(error);
    }
    if let Err(error) = provisioning.revalidate() {
        drop(activation);
        return Err(error.into());
    }

    let activation = activation.resume_for_storage_startup()?;
    let response_result =
        receive_storage_startup_response(response_reader, deadline, response_transport);
    let response_frame = match response_result {
        Ok(response) => response,
        Err(error) => {
            drop(activation);
            return Err(error.into());
        }
    };
    let response = match KeyAgentStartupResponse::decode(response_frame.as_slice()) {
        Ok(response) => response,
        Err(_error) => {
            drop(activation);
            return Err(KeyAgentSupervisorError::StartupProtocol);
        }
    };

    if let Err(error) = validate_storage_startup_response(request, &response) {
        drop(activation);
        return Err(error);
    }
    if let Err(error) =
        revalidate_post_startup_state(&provisioning, &root_job, &activation, response_transport)
    {
        drop(activation);
        return Err(error);
    }

    let transcript_commitment = startup_transcript_commitment(
        artifact_identity.encode_be(),
        request_frame.as_bytes(),
        &response_frame,
    );
    let handshake =
        match startup_lease.verify_and_consume(response.echoed_nonce(), transcript_commitment) {
            Ok(handshake) => handshake,
            Err(error) => {
                drop(activation);
                return Err(error);
            }
        };
    if let Err(error) =
        revalidate_post_startup_state(&provisioning, &root_job, &activation, response_transport)
    {
        drop(activation);
        return Err(error);
    }

    Ok(BoundStorageProvenKeyAgent {
        activation,
        root_job,
        handshake,
        install_continuity,
        not_sync: PhantomData,
        provisioning,
    })
}

fn receive_storage_startup_response(
    response_reader: KeyAgentStartupResponseReader,
    deadline: Instant,
    response_transport: StartupResponseTransport,
) -> Result<Zeroizing<[u8; KEY_AGENT_STARTUP_RESPONSE_BYTES]>, PipeError> {
    match response_transport {
        StartupResponseTransport::Exact => response_reader.receive(deadline),
        #[cfg(test)]
        StartupResponseTransport::PinnedLibtestTerse => {
            response_reader.receive_after_exact_libtest_terse_preamble_for_test(deadline)
        }
    }
}

fn validate_storage_startup_response(
    request: &KeyAgentStartupRequest,
    response: &KeyAgentStartupResponse,
) -> Result<(), KeyAgentSupervisorError> {
    if request.nonce().ct_eq(response.echoed_nonce()).unwrap_u8() == 0 {
        return Err(KeyAgentSupervisorError::BindingMismatch);
    }
    if response.actual_process_id() != request.expected_process_id()
        || response.actual_creation_time() != request.expected_creation_time()
        || response.storage_root_identity() != request.storage_root_identity()
    {
        return Err(KeyAgentSupervisorError::StartupProtocol);
    }
    Ok(())
}

fn revalidate_post_startup_state(
    provisioning: &PreparedKeyAgentProvisioning,
    root_job: &KeyAgentRootJob,
    #[cfg_attr(not(test), allow(unused_variables))] activation: &RunningKeyAgentActivation,
    response_transport: StartupResponseTransport,
) -> Result<(), KeyAgentSupervisorError> {
    activation.revalidate_resident_process()?;
    provisioning.revalidate()?;
    root_job.recheck_supervisor_context()?;
    root_job.verify_effective_limits()?;
    if !activation.is_member_of_root_job(root_job)? {
        return Err(KeyAgentSupervisorError::RootJobPolicy);
    }
    let topology_is_valid = match response_transport {
        StartupResponseTransport::Exact => root_job.active_process_count().map(|count| count == 1),
        #[cfg(test)]
        StartupResponseTransport::PinnedLibtestTerse => {
            root_job.verify_kernel_fixture_topology_for_test(activation.process_id())
        }
    }?;
    topology_is_valid
        .then_some(())
        .ok_or(KeyAgentSupervisorError::RootJobPolicy)?;
    activation.revalidate_resident_process().map_err(Into::into)
}

fn startup_transcript_commitment(
    artifact_identity: [u8; 24],
    request_frame: &[u8; KEY_AGENT_STARTUP_REQUEST_BYTES],
    response_frame: &[u8; KEY_AGENT_STARTUP_RESPONSE_BYTES],
) -> [u8; STARTUP_TRANSCRIPT_BYTES] {
    let mut transcript = Sha256::new();
    transcript.update(STARTUP_TRANSCRIPT_DOMAIN);
    transcript.update(artifact_identity);
    transcript.update(request_frame);
    transcript.update(response_frame);
    transcript.finalize().into()
}

/// Test-harness equivalent of [`bind_dormant_key_agent`] for kernel-positive
/// coverage when the Rust test runner is itself Job-contained.
///
/// This path differs only in using the root Job's explicit `cfg(test)` outer
/// runner-context bypass. It proves exact image/attribute/pipe/Job ownership
/// and cleanup, but is not evidence for the production supervisor-context
/// checks or post-return supervisor process ACL.
#[cfg(test)]
fn bind_dormant_key_agent_for_kernel_test(
    attestation: ReleaseAttestation,
    artifact: VerifiedHelper,
    provisioning: PreparedKeyAgentProvisioning,
) -> Result<BoundDormantKeyAgent, KeyAgentSupervisorError> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt as _;

    const STORAGE_STARTUP_CHILD_FIXTURE: &str =
        "key_agent_child_bootstrap::tests::storage_startup_child_fixture";
    let command_line = format!(
        "\"{}\" --exact {STORAGE_STARTUP_CHILD_FIXTURE} --ignored --test-threads=1 --quiet",
        artifact.path().display()
    );
    let mut command_line = OsStr::new(&command_line)
        .encode_wide()
        .chain(core::iter::once(0))
        .collect::<Vec<_>>();
    let preflighted = preflight_key_agent_activation(attestation, artifact)?;
    let install_continuity = verified_install_continuity_for_supervisor_test();
    provisioning.revalidate()?;
    let startup_lease = SupervisorActivationLease::issue(MAX_STARTUP_LIFETIME)?;

    run_on_fresh_key_agent_debug_thread(move |fresh_thread| {
        startup_lease.ensure_live()?;
        provisioning.revalidate()?;
        let root_job = KeyAgentRootJob::create_for_kernel_test()?;
        let pipes = PrivateKeyAgentPipes::create()?;
        let root_job_attribute = root_job.creation_attribute()?;
        let activation = activate_preflighted_key_agent_on_fresh_worker_for_kernel_test(
            fresh_thread,
            preflighted,
            &provisioning,
            &pipes,
            &root_job,
            &root_job_attribute,
            startup_lease.expires_at(),
            &mut command_line,
        )?;
        drop(root_job_attribute);

        root_job.verify_effective_limits()?;
        if root_job.active_process_count()? != 1 {
            return Err(KeyAgentSupervisorError::RootJobPolicy);
        }
        let (request_writer, response_reader) = pipes.into_parent();
        provisioning.revalidate()?;
        startup_lease.ensure_live()?;
        Ok(BoundDormantKeyAgent {
            activation,
            root_job,
            request_writer,
            response_reader,
            startup_lease,
            install_continuity,
            not_sync: PhantomData,
            provisioning,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::{
        ACTIVATION_NONCE_BYTES, ApprovalParentSourcePreparedKeyAgent, BoundDormantKeyAgent,
        BoundStorageProvenKeyAgent, KeyAgentStartupCodecError, KeyAgentSupervisorError,
        MAX_STARTUP_LIFETIME, STARTUP_TRANSCRIPT_BYTES, SupervisorActivationLease,
        bind_dormant_key_agent_for_kernel_test, bind_key_agent_storage_startup_for_kernel_test,
        prepare_approval_parent_source_for_kernel_test, startup_transcript_commitment,
    };
    use crate::approval_activation::bind_dormant_parent_bound_approval;
    use crate::approval_parent::{
        bind_release_approval_parent_for_kernel_test,
        verify_parent_bound_approval_lpac_for_kernel_test,
    };
    use crate::approval_supervisor::{
        preflight_approval_artifact, prepare_release_approval_supervisor,
    };
    use crate::approval_transport::bound_approval_transport_for_test;
    use crate::attestation::{ArtifactDigest, ReleaseAttestation};
    use crate::helper::VerifiedHelper;
    use crate::key_agent_activation::{KeyAgentActivationError, PreparedApprovalParentProcess};
    use crate::key_agent_lpac::{KeyAgentLpacError, PreparedKeyAgentProvisioning};
    use crate::key_agent_root_job::{KeyAgentRootJob, KeyAgentRootJobError};
    use crate::key_agent_startup::{
        KEY_AGENT_STARTUP_REQUEST_BYTES, KEY_AGENT_STARTUP_RESPONSE_BYTES,
    };
    use crate::launch::ApprovalLpacKernelTestFixture;
    use crate::pipe::{PipeError, key_agent_startup_parent_endpoints_are_noninheritable_for_test};
    use std::time::{Duration, Instant};

    const REJECTED_PROCESS_EXIT_CODE: u32 = 0xE0A0_0001;
    const APPROVAL_MANIFEST: [u8; 32] = [0x71; 32];

    trait AmbiguousIfSync<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfSync<()> for T {}
    impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for T {}

    trait AmbiguousIfClone<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    impl<T: Clone> AmbiguousIfClone<u8> for T {}

    trait AmbiguousIfCopy<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfCopy<()> for T {}
    impl<T: Copy> AmbiguousIfCopy<u8> for T {}

    fn attestation_for(artifact: &VerifiedHelper) -> ReleaseAttestation {
        ReleaseAttestation::with_helper_manifests_for_test(
            ArtifactDigest::for_test([23; 32]),
            [artifact.manifest_digest(), [25; 32], [26; 32]],
        )
    }

    #[test]
    fn lease_is_fresh_nonzero_and_one_attempt_specific() -> Result<(), KeyAgentSupervisorError> {
        let first = SupervisorActivationLease::issue(Duration::from_secs(30))?;
        let second = SupervisorActivationLease::issue(Duration::from_secs(30))?;

        assert_ne!(first.nonce_for_child(), &[0; ACTIVATION_NONCE_BYTES]);
        assert_ne!(first.nonce_for_child(), second.nonce_for_child());
        let echoed = *first.nonce_for_child();
        let handshake = first.verify_and_consume(&echoed, [3; STARTUP_TRANSCRIPT_BYTES])?;
        assert!(handshake.is_live());
        assert_eq!(
            handshake.transcript_commitment.as_ref(),
            &[3; STARTUP_TRANSCRIPT_BYTES]
        );
        Ok(())
    }

    #[test]
    fn transcript_commitment_binds_artifact_request_and_response_bytes() {
        let artifact = [1_u8; 24];
        let request = [2_u8; KEY_AGENT_STARTUP_REQUEST_BYTES];
        let response = [3_u8; KEY_AGENT_STARTUP_RESPONSE_BYTES];
        let commitment = startup_transcript_commitment(artifact, &request, &response);
        assert_ne!(commitment, [0; STARTUP_TRANSCRIPT_BYTES]);

        let mut changed_artifact = artifact;
        changed_artifact[23] ^= 1;
        assert_ne!(
            commitment,
            startup_transcript_commitment(changed_artifact, &request, &response)
        );
        let mut changed_request = request;
        changed_request[KEY_AGENT_STARTUP_REQUEST_BYTES - 1] ^= 1;
        assert_ne!(
            commitment,
            startup_transcript_commitment(artifact, &changed_request, &response)
        );
        let mut changed_response = response;
        changed_response[KEY_AGENT_STARTUP_RESPONSE_BYTES - 1] ^= 1;
        assert_ne!(
            commitment,
            startup_transcript_commitment(artifact, &request, &changed_response)
        );
    }

    #[test]
    fn lifetime_is_clamped_and_expiry_is_inclusive() -> Result<(), KeyAgentSupervisorError> {
        let now = Instant::now();
        let lease = SupervisorActivationLease::with_test_parts(
            [1; ACTIVATION_NONCE_BYTES],
            now + MAX_STARTUP_LIFETIME,
        );
        let exact_expiry = now + MAX_STARTUP_LIFETIME;
        let echoed = *lease.nonce_for_child();

        assert!(
            lease
                .verify_and_consume_at_for_test(
                    &echoed,
                    exact_expiry
                        .checked_sub(Duration::from_nanos(1))
                        .ok_or(KeyAgentSupervisorError::DeadlineUnavailable,)?,
                    [4; STARTUP_TRANSCRIPT_BYTES],
                )
                .is_ok()
        );
        let expired =
            SupervisorActivationLease::with_test_parts([1; ACTIVATION_NONCE_BYTES], exact_expiry);
        assert!(matches!(
            expired.verify_and_consume_at_for_test(
                &[1; ACTIVATION_NONCE_BYTES],
                exact_expiry,
                [4; STARTUP_TRANSCRIPT_BYTES],
            ),
            Err(KeyAgentSupervisorError::Expired)
        ));
        Ok(())
    }

    #[test]
    fn wrong_nonce_consumes_attempt_and_fails_closed() {
        let now = Instant::now();
        let lease = SupervisorActivationLease::with_test_parts(
            [1; ACTIVATION_NONCE_BYTES],
            now + Duration::from_secs(1),
        );
        assert!(matches!(
            lease.verify_and_consume_at_for_test(
                &[2; ACTIVATION_NONCE_BYTES],
                now,
                [5; STARTUP_TRANSCRIPT_BYTES],
            ),
            Err(KeyAgentSupervisorError::BindingMismatch)
        ));
    }

    #[test]
    fn dormant_binding_deadline_recheck_is_inclusive_and_test_clock_only()
    -> Result<(), KeyAgentSupervisorError> {
        let now = Instant::now();
        let expires_at = now
            .checked_add(Duration::from_secs(1))
            .ok_or(KeyAgentSupervisorError::DeadlineUnavailable)?;
        let immediately_before = expires_at
            .checked_sub(Duration::from_nanos(1))
            .ok_or(KeyAgentSupervisorError::DeadlineUnavailable)?;
        let live =
            SupervisorActivationLease::with_test_parts([1; ACTIVATION_NONCE_BYTES], expires_at);
        assert!(live.ensure_live_at_for_test(immediately_before).is_ok());
        assert_eq!(
            live.ensure_live_at_for_test(expires_at),
            Err(KeyAgentSupervisorError::Expired)
        );
        Ok(())
    }

    #[test]
    fn empty_lifetime_fails_before_randomness() {
        assert!(matches!(
            SupervisorActivationLease::issue(Duration::ZERO),
            Err(KeyAgentSupervisorError::InvalidLifetime)
        ));
    }

    #[test]
    fn debug_is_stable_and_redacted() -> Result<(), KeyAgentSupervisorError> {
        let lease = SupervisorActivationLease::issue(Duration::from_secs(1))?;
        assert_eq!(
            format!("{lease:?}"),
            "SupervisorActivationLease { nonce: \"[REDACTED]\", expires_at: \"[TRUSTED MONOTONIC DEADLINE]\" }"
        );
        Ok(())
    }

    #[test]
    fn dormant_aggregate_can_cross_only_by_unique_ownership() {
        fn assert_send<T: Send>() {}
        assert_send::<BoundDormantKeyAgent>();
        assert_send::<BoundStorageProvenKeyAgent>();
        assert_send::<ApprovalParentSourcePreparedKeyAgent>();
        let _ = <BoundDormantKeyAgent as AmbiguousIfSync<_>>::marker;
        let _ = <BoundDormantKeyAgent as AmbiguousIfClone<_>>::marker;
        let _ = <BoundDormantKeyAgent as AmbiguousIfCopy<_>>::marker;
        let _ = <BoundStorageProvenKeyAgent as AmbiguousIfSync<_>>::marker;
        let _ = <BoundStorageProvenKeyAgent as AmbiguousIfClone<_>>::marker;
        let _ = <BoundStorageProvenKeyAgent as AmbiguousIfCopy<_>>::marker;
        let _ = <ApprovalParentSourcePreparedKeyAgent as AmbiguousIfSync<_>>::marker;
        let _ = <ApprovalParentSourcePreparedKeyAgent as AmbiguousIfClone<_>>::marker;
        let _ = <ApprovalParentSourcePreparedKeyAgent as AmbiguousIfCopy<_>>::marker;
    }

    #[test]
    fn resource_failures_collapse_to_stable_supervisor_categories() {
        assert_eq!(
            KeyAgentSupervisorError::from(KeyAgentActivationError::WrongRole),
            KeyAgentSupervisorError::Activation
        );
        assert_eq!(
            KeyAgentSupervisorError::from(PipeError::OperatingSystem),
            KeyAgentSupervisorError::PrivateChannel
        );
        assert_eq!(
            KeyAgentSupervisorError::from(KeyAgentRootJobError::UnsupportedSupervisorContext),
            KeyAgentSupervisorError::RootJobPolicy
        );
        assert_eq!(
            KeyAgentSupervisorError::from(KeyAgentLpacError::Provisioning),
            KeyAgentSupervisorError::Provisioning
        );
        assert_eq!(
            KeyAgentSupervisorError::from(KeyAgentStartupCodecError::InvalidResponse),
            KeyAgentSupervisorError::StartupProtocol
        );
    }

    #[test]
    fn integrated_kernel_binding_owns_one_member_and_no_inheritable_parent_handles()
    -> Result<(), Box<dyn std::error::Error>> {
        let artifact = VerifiedHelper::for_key_agent_activation_test()?;
        let attestation = attestation_for(&artifact);
        let provisioning = PreparedKeyAgentProvisioning::prepare_for_kernel_test()?;
        let storage_root = provisioning.storage_root_path_for_test().to_path_buf();
        let bound = bind_dormant_key_agent_for_kernel_test(attestation, artifact, provisioning)?;

        assert!(bound.activation.is_detached_and_suspended());
        assert!(
            bound
                .activation
                .is_member_of_root_job_for_test(&bound.root_job)?
        );
        assert_eq!(bound.root_job.active_process_count()?, 1);
        assert!(bound.root_job.verify_effective_limits().is_ok());
        assert!(
            key_agent_startup_parent_endpoints_are_noninheritable_for_test(
                &bound.request_writer,
                &bound.response_reader,
            )?
        );

        let process_id = bound.activation.process_id();
        let creation_time = bound.activation.creation_time();
        let rendered = format!("{bound:?}");
        assert!(rendered.contains("BoundDormantKeyAgent"));
        assert!(rendered.contains("VERIFIED PROFILE AND HELD STORAGE ROOT"));
        assert!(!rendered.contains(&process_id.to_string()));
        assert!(!rendered.contains(&creation_time.to_string()));
        assert!(storage_root.is_dir());

        let observation = bound.activation.duplicate_process_observation()?;
        drop(bound);
        assert!(!storage_root.exists());
        assert_eq!(
            observation.rejected_exit_code()?,
            REJECTED_PROCESS_EXIT_CODE
        );
        Ok(())
    }

    #[test]
    fn dormant_aggregate_unwind_synchronously_aborts_the_exact_process()
    -> Result<(), Box<dyn std::error::Error>> {
        let artifact = VerifiedHelper::for_key_agent_activation_test()?;
        let attestation = attestation_for(&artifact);
        let provisioning = PreparedKeyAgentProvisioning::prepare_for_kernel_test()?;
        let storage_root = provisioning.storage_root_path_for_test().to_path_buf();
        let bound = bind_dormant_key_agent_for_kernel_test(attestation, artifact, provisioning)?;
        let observation = bound.activation.duplicate_process_observation()?;

        let worker = std::thread::spawn(move || {
            let _dormant_cleanup_guard = bound;
            std::panic::resume_unwind(Box::new("intentional dormant aggregate unwind test"));
        });
        assert!(worker.join().is_err());
        assert!(!storage_root.exists());
        assert_eq!(
            observation.rejected_exit_code()?,
            REJECTED_PROCESS_EXIT_CODE
        );
        Ok(())
    }

    #[test]
    fn integrated_storage_startup_binds_child_process_and_full_root_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let artifact = VerifiedHelper::for_key_agent_activation_test()?;
        let attestation = attestation_for(&artifact);
        let provisioning = PreparedKeyAgentProvisioning::prepare_for_kernel_test()?;
        let storage_root = provisioning.storage_root_path_for_test().to_path_buf();
        let dormant = bind_dormant_key_agent_for_kernel_test(attestation, artifact, provisioning)?;
        let bound = bind_key_agent_storage_startup_for_kernel_test(dormant)?;

        assert!(bound.activation.is_detached_and_running());
        assert!(
            bound
                .activation
                .is_member_of_root_job_for_test(&bound.root_job)?
        );
        let unrelated_root_job = KeyAgentRootJob::create_for_kernel_test()?;
        assert!(
            !bound
                .activation
                .is_member_of_root_job_for_test(&unrelated_root_job)?
        );
        assert!(
            bound
                .root_job
                .verify_kernel_fixture_topology_for_test(bound.activation.process_id())?
        );
        assert!(bound.root_job.verify_effective_limits().is_ok());
        assert!(bound.provisioning.revalidate().is_ok());
        assert!(bound.activation.revalidate_resident_process().is_ok());
        assert!(bound.handshake.is_live());
        assert!(
            bound
                .handshake
                .transcript_commitment
                .iter()
                .any(|byte| *byte != 0)
        );

        let process_id = bound.activation.process_id();
        let creation_time = bound.activation.creation_time();
        let rendered = format!("{bound:?}");
        assert!(rendered.contains("BoundStorageProvenKeyAgent"));
        assert!(rendered.contains("VERIFIED STORAGE-STARTUP TRANSCRIPT"));
        assert!(rendered.contains("EXACT EOF; NO RETAINED ENDPOINTS"));
        assert!(!rendered.contains(&process_id.to_string()));
        assert!(!rendered.contains(&creation_time.to_string()));
        assert!(storage_root.is_dir());

        let observation = bound.activation.duplicate_process_observation()?;
        drop(bound);
        assert!(!storage_root.exists());
        assert_eq!(
            observation.rejected_exit_code()?,
            REJECTED_PROCESS_EXIT_CODE
        );
        Ok(())
    }

    #[test]
    fn approval_parent_source_retains_the_complete_storage_proof_and_exact_narrow_process()
    -> Result<(), Box<dyn std::error::Error>> {
        let artifact = VerifiedHelper::for_key_agent_activation_test()?;
        let attestation = attestation_for(&artifact);
        let provisioning = PreparedKeyAgentProvisioning::prepare_for_kernel_test()?;
        let storage_root = provisioning.storage_root_path_for_test().to_path_buf();
        let dormant = bind_dormant_key_agent_for_kernel_test(attestation, artifact, provisioning)?;
        let storage_proven = bind_key_agent_storage_startup_for_kernel_test(dormant)?;
        let process_id = storage_proven.activation.process_id();
        let creation_time = storage_proven.activation.creation_time();
        let observation = storage_proven.activation.duplicate_process_observation()?;

        let prepared = prepare_approval_parent_source_for_kernel_test(storage_proven)?;
        assert_eq!(
            PreparedApprovalParentProcess::access_mask_for_test(),
            0x0010_1000
        );
        prepared.parent_process.revalidate()?;
        prepared
            .storage_proven
            .activation
            .revalidate_resident_process()?;
        assert!(prepared.storage_proven.provisioning.revalidate().is_ok());
        assert!(prepared.storage_proven.handshake.is_live());
        assert!(
            prepared
                .storage_proven
                .root_job
                .verify_kernel_fixture_topology_for_test(process_id)?
        );
        let rendered = format!("{prepared:?}");
        assert!(rendered.contains("ApprovalParentSourcePreparedKeyAgent"));
        assert!(rendered.contains("EXACT QLI+SYNCHRONIZE PARENT SOURCE"));
        assert!(!rendered.contains(&process_id.to_string()));
        assert!(!rendered.contains(&creation_time.to_string()));

        drop(prepared);
        assert!(!storage_root.exists());
        assert_eq!(
            observation.rejected_exit_code()?,
            REJECTED_PROCESS_EXIT_CODE
        );
        Ok(())
    }

    #[test]
    fn release_approval_and_exact_key_agent_parent_form_only_one_dormant_owned_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let key_agent_artifact = VerifiedHelper::for_key_agent_activation_test()?;
        let key_agent_attestation = attestation_for(&key_agent_artifact);
        let provisioning = PreparedKeyAgentProvisioning::prepare_for_kernel_test()?;
        let storage_root = provisioning.storage_root_path_for_test().to_path_buf();
        let dormant = bind_dormant_key_agent_for_kernel_test(
            key_agent_attestation,
            key_agent_artifact,
            provisioning,
        )?;
        let storage_proven = bind_key_agent_storage_startup_for_kernel_test(dormant)?;
        let process_id = storage_proven.activation.process_id();
        let creation_time = storage_proven.activation.creation_time();
        let observation = storage_proven.activation.duplicate_process_observation()?;

        let approval_artifact = VerifiedHelper::for_approval_artifact_test(
            std::env::current_exe()?,
            APPROVAL_MANIFEST,
            true,
        )?;
        let approval_attestation = ReleaseAttestation::with_helper_manifests_for_test(
            ArtifactDigest::for_test([0x70; 32]),
            [APPROVAL_MANIFEST, [0x72; 32], [0x73; 32]],
        );
        let approval = prepare_release_approval_supervisor(preflight_approval_artifact(
            approval_attestation,
            approval_artifact,
        )?)?;

        let bound = bind_release_approval_parent_for_kernel_test(approval, storage_proven)?;
        let rendered = format!("{bound:?}");
        assert_eq!(
            rendered,
            "ParentBoundReleaseApprovalSupervisor([HELD APPROVAL; STORAGE-PROVEN EXACT KEY AGENT PARENT SOURCE])"
        );
        assert!(!rendered.contains(&process_id.to_string()));
        assert!(!rendered.contains(&creation_time.to_string()));

        drop(bound);
        assert!(!storage_root.exists());
        assert_eq!(
            observation.rejected_exit_code()?,
            REJECTED_PROCESS_EXIT_CODE
        );
        Ok(())
    }

    #[test]
    fn parent_bound_approval_is_live_in_job_and_drop_cleans_both_process_trees()
    -> Result<(), Box<dyn std::error::Error>> {
        let key_agent_artifact = VerifiedHelper::for_key_agent_activation_test()?;
        let key_agent_attestation = attestation_for(&key_agent_artifact);
        let provisioning = PreparedKeyAgentProvisioning::prepare_for_kernel_test()?;
        let storage_root = provisioning.storage_root_path_for_test().to_path_buf();
        let dormant = bind_dormant_key_agent_for_kernel_test(
            key_agent_attestation,
            key_agent_artifact,
            provisioning,
        )?;
        let storage_proven = bind_key_agent_storage_startup_for_kernel_test(dormant)?;
        let process_id = storage_proven.activation.process_id();
        let creation_time = storage_proven.activation.creation_time();
        let observation = storage_proven.activation.duplicate_process_observation()?;

        let approval_fixture = ApprovalLpacKernelTestFixture::create()?;
        let approval_executable = approval_fixture.path().to_path_buf();
        let approval_directory = approval_executable
            .parent()
            .ok_or_else(|| std::io::Error::other("fixture executable has no parent"))?
            .to_path_buf();
        let approval_artifact = VerifiedHelper::for_approval_artifact_test(
            approval_executable.clone(),
            APPROVAL_MANIFEST,
            true,
        )?;
        let approval_attestation = ReleaseAttestation::with_helper_manifests_for_test(
            ArtifactDigest::for_test([0x70; 32]),
            [APPROVAL_MANIFEST, [0x72; 32], [0x73; 32]],
        );
        let approval = prepare_release_approval_supervisor(preflight_approval_artifact(
            approval_attestation,
            approval_artifact,
        )?)?;
        let bound = bind_release_approval_parent_for_kernel_test(approval, storage_proven)?;

        let transport = bound_approval_transport_for_test()?;
        let dormant_approval = bind_dormant_parent_bound_approval(bound, transport)?;
        assert!(dormant_approval.is_live_in_job_for_test()?);
        let rendered = format!("{dormant_approval:?}");
        assert_eq!(
            rendered,
            "BoundDormantApproval([SUSPENDED APPROVAL; PRIVATE ENDPOINTS; PARENT-BOUND KEY AGENT; BOUND TRANSPORT])"
        );
        assert!(!rendered.contains(&process_id.to_string()));
        assert!(!rendered.contains(&creation_time.to_string()));
        assert!(storage_root.is_dir());
        assert!(approval_executable.is_file());

        drop(dormant_approval);
        assert!(!storage_root.exists());
        assert_eq!(
            observation.rejected_exit_code()?,
            REJECTED_PROCESS_EXIT_CODE
        );
        approval_fixture.cleanup()?;
        assert!(!approval_executable.exists());
        assert!(!approval_directory.exists());
        Ok(())
    }

    #[test]
    fn actual_approval_lpac_can_query_exact_key_agent_parent_without_amplification()
    -> Result<(), Box<dyn std::error::Error>> {
        let key_agent_artifact = VerifiedHelper::for_key_agent_activation_test()?;
        let key_agent_attestation = attestation_for(&key_agent_artifact);
        let provisioning = PreparedKeyAgentProvisioning::prepare_for_kernel_test()?;
        let storage_root = provisioning.storage_root_path_for_test().to_path_buf();
        let dormant = bind_dormant_key_agent_for_kernel_test(
            key_agent_attestation,
            key_agent_artifact,
            provisioning,
        )?;
        let storage_proven = bind_key_agent_storage_startup_for_kernel_test(dormant)?;
        let observation = storage_proven.activation.duplicate_process_observation()?;

        let approval_fixture = ApprovalLpacKernelTestFixture::create()?;
        let approval_executable = approval_fixture.path().to_path_buf();
        let approval_directory = approval_executable
            .parent()
            .ok_or_else(|| std::io::Error::other("fixture executable has no parent"))?
            .to_path_buf();
        let approval_artifact = VerifiedHelper::for_approval_artifact_test(
            approval_executable.clone(),
            APPROVAL_MANIFEST,
            true,
        )?;
        let approval_attestation = ReleaseAttestation::with_helper_manifests_for_test(
            ArtifactDigest::for_test([0x70; 32]),
            [APPROVAL_MANIFEST, [0x72; 32], [0x73; 32]],
        );
        let approval = prepare_release_approval_supervisor(preflight_approval_artifact(
            approval_attestation,
            approval_artifact,
        )?)?;
        let bound = bind_release_approval_parent_for_kernel_test(approval, storage_proven)?;

        verify_parent_bound_approval_lpac_for_kernel_test(&bound)?;
        assert!(storage_root.is_dir());

        drop(bound);
        assert!(!storage_root.exists());
        assert_eq!(
            observation.rejected_exit_code()?,
            REJECTED_PROCESS_EXIT_CODE
        );
        approval_fixture.cleanup()?;
        assert!(!approval_executable.exists());
        assert!(!approval_directory.exists());
        Ok(())
    }

    #[test]
    fn resident_revalidation_rejects_the_exact_process_after_exit()
    -> Result<(), Box<dyn std::error::Error>> {
        let artifact = VerifiedHelper::for_key_agent_activation_test()?;
        let attestation = attestation_for(&artifact);
        let provisioning = PreparedKeyAgentProvisioning::prepare_for_kernel_test()?;
        let storage_root = provisioning.storage_root_path_for_test().to_path_buf();
        let dormant = bind_dormant_key_agent_for_kernel_test(attestation, artifact, provisioning)?;
        let bound = bind_key_agent_storage_startup_for_kernel_test(dormant)?;
        let observation = bound.activation.duplicate_process_observation()?;

        observation.terminate_for_resident_revalidation_test()?;
        assert!(matches!(
            bound.activation.revalidate_resident_process(),
            Err(KeyAgentActivationError::ResidentState)
        ));
        assert_eq!(
            observation.rejected_exit_code()?,
            REJECTED_PROCESS_EXIT_CODE
        );

        drop(bound);
        assert!(!storage_root.exists());
        Ok(())
    }

    #[test]
    fn storage_proven_aggregate_unwind_synchronously_aborts_the_exact_process()
    -> Result<(), Box<dyn std::error::Error>> {
        let artifact = VerifiedHelper::for_key_agent_activation_test()?;
        let attestation = attestation_for(&artifact);
        let provisioning = PreparedKeyAgentProvisioning::prepare_for_kernel_test()?;
        let storage_root = provisioning.storage_root_path_for_test().to_path_buf();
        let dormant = bind_dormant_key_agent_for_kernel_test(attestation, artifact, provisioning)?;
        let bound = bind_key_agent_storage_startup_for_kernel_test(dormant)?;
        let observation = bound.activation.duplicate_process_observation()?;

        let worker = std::thread::spawn(move || {
            let _resident_cleanup_guard = bound;
            std::panic::resume_unwind(Box::new("intentional storage-proven aggregate unwind test"));
        });
        assert!(worker.join().is_err());
        assert!(!storage_root.exists());
        assert_eq!(
            observation.rejected_exit_code()?,
            REJECTED_PROCESS_EXIT_CODE
        );
        Ok(())
    }
}
