//! Authenticated, one-shot approval-response verification.
//!
//! The internal channel deliberately has no public constructor.
//! [`launch_approval_frontend`] is a crate-private legacy seam retained only to
//! reject calls before nonce, pipe, or process allocation. It cannot provide the
//! separate logical Key Agent capability required by bootstrap v2. The sealed
//! parent-bound activation module owns the sole hello resume and full-exchange
//! edges; neither edge is composed into production orchestration.

use core::fmt;
use std::time::{Duration, Instant};

use approval_wire::{
    ApprovalChildHello, ApprovalParentHello, ApprovalRequest, Decision, RESPONSE_BYTES,
    decode_response, request_hash,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

#[cfg(windows)]
use crate::{
    approval_activation::ApprovalActivationSeal,
    helper::VerifiedHelper,
    launch::{LaunchError, LaunchedHelper, RestrictedLauncher},
    pipe::{ApprovalResponseReader, PipeError},
};
use crate::{helper::FileIdentity, launch::HeldProcessIdentity};

const TRANSCRIPT_DOMAIN: &[u8] = b"your-wallet/approval-child-transcript/v3";
const BOOTSTRAP_NONCE_BYTES: usize = 32;
const TRANSCRIPT_SALT_BYTES: usize = 32;
const TERMINATION_GRACE: Duration = Duration::from_secs(5);

/// Decision decoded from the fixed approval-helper wire format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifiedApprovalDecision {
    /// The user completed the frontend's required confirmation gesture.
    Approve,
    /// The user rejected or cancelled the request.
    Reject,
}

/// Failure while consuming the authenticated one-shot approval channel.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ApprovalChannelError {
    /// The held process does not match the identity branded into the channel.
    #[error("approval channel helper identity mismatch")]
    IdentityMismatch,
    /// The response was not the one exact fixed-width approval-wire frame.
    #[error("malformed approval response")]
    MalformedResponse,
    /// The response did not echo the exact request digest and nonce.
    #[error("approval response binding mismatch")]
    BindingMismatch,
    /// The trusted monotonic response deadline elapsed.
    #[error("approval response deadline elapsed")]
    DeadlineElapsed,
    /// The private channel could not produce one complete response.
    #[error("private approval response channel failed")]
    ChannelFailure,
    /// Secure parent-local transcript-salt generation or transcript
    /// construction failed closed.
    #[error("approval channel transcript construction failed")]
    TranscriptFailure,
}

/// Failure before a one-shot approval helper/channel is fully armed.
#[derive(Debug, Error)]
pub enum ApprovalLaunchError {
    /// The verified manifest belonged to another helper role.
    #[error("verified helper is not the approval frontend")]
    WrongHelperRole,
    /// The restricted helper launch failed closed.
    #[error("approval frontend launch failed")]
    Launch(#[source] LaunchError),
    /// Private endpoint construction or request transfer failed.
    #[error("approval private-pipe setup failed")]
    Pipe(#[source] PipeError),
    /// The trusted monotonic approval deadline elapsed during setup.
    #[error("approval setup deadline elapsed")]
    DeadlineElapsed,
    /// Secure parent-local transcript-salt generation or channel arming failed
    /// closed.
    #[error("approval response channel could not be armed")]
    Channel(#[source] ApprovalChannelError),
    /// The legacy launcher has no exact logical Key Agent parent aggregate.
    #[error("approval logical parent is unavailable on the legacy launch path")]
    LogicalParentUnavailable,
}

/// Rejects the legacy Approval launch path before allocating any resource.
///
/// Bootstrap v2 requires an ordinary channel-supervisor proof and a separately
/// injected logical Key Agent process capability. A [`RestrictedLauncher`] has
/// no complete parent-bound aggregate, so fabricating placeholder coordinates
/// here would weaken the child proof. Wrong roles retain their distinct error;
/// the correct role then fails closed without sampling a nonce, creating a pipe,
/// or starting a process.
///
/// # Errors
///
/// Returns [`ApprovalLaunchError::WrongHelperRole`] for a wrong helper role and
/// [`ApprovalLaunchError::LogicalParentUnavailable`] otherwise.
#[cfg(windows)]
pub(crate) fn launch_approval_frontend(
    launcher: RestrictedLauncher,
    helper: &VerifiedHelper,
    request: &ApprovalRequest,
) -> Result<PendingApproval, ApprovalLaunchError> {
    if !helper.is_approval_frontend() {
        return Err(ApprovalLaunchError::WrongHelperRole);
    }
    let _ = (launcher, request);
    Err(ApprovalLaunchError::LogicalParentUnavailable)
}

#[cfg(windows)]
fn matches_verified_approval_helper(
    verified_helper: &VerifiedHelper,
    helper_file: FileIdentity,
    helper_manifest_digest: [u8; 32],
    is_held_in_job: bool,
) -> bool {
    verified_helper.is_approval_frontend()
        && helper_file == verified_helper.identity()
        && helper_manifest_digest == verified_helper.manifest_digest()
        && is_held_in_job
}

/// A held approval frontend plus its exact branded one-shot response channel.
///
/// This type is non-cloneable. Receiving consumes both the helper/job handles
/// and the channel, so neither a response nor its process identity can be reused.
#[cfg(windows)]
pub(crate) struct PendingApproval {
    helper: LaunchedHelper,
    channel: ApprovalResponseChannel,
}

#[cfg(windows)]
impl PendingApproval {
    /// Consumes the held helper and channel into one verified response.
    ///
    /// # Errors
    ///
    /// Fails closed on timeout, cancellation, malformed or trailing bytes,
    /// request mismatch, channel failure, or held-identity mismatch.
    ///
    /// Consuming the private pending state makes reuse impossible in safe Rust.
    pub(crate) fn receive(self) -> Result<VerifiedApprovalResponse, ApprovalChannelError> {
        self.channel.receive(self.helper)
    }
}

#[cfg(windows)]
impl fmt::Debug for PendingApproval {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingApproval")
            .field("helper", &"[HELD PROCESS AND JOB]")
            .field("channel", &self.channel)
            .finish()
    }
}

/// Proof that one exact response arrived over verified one-shot helper transport.
///
/// The transport is bound to ordinary channel-supervisor evidence; it does not
/// attribute endpoint ownership or writes to the separately proven logical Key
/// Agent. This value is non-cloneable and can be consumed only once. No
/// production constructor currently reaches this state, so safe Rust callers
/// cannot fabricate approval digest/nonce bytes and reach signing.
#[derive(Eq, PartialEq)]
pub struct VerifiedApprovalResponse {
    decision: VerifiedApprovalDecision,
    approval_digest: [u8; 32],
    challenge_nonce: [u8; 32],
    child_transcript: [u8; 32],
    request_hash: [u8; 32],
}

impl fmt::Debug for VerifiedApprovalResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedApprovalResponse([REDACTED ONE-SHOT PROOF])")
    }
}

impl VerifiedApprovalResponse {
    /// Consumes the one-shot proof into its transcript-bound response parts.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        VerifiedApprovalDecision,
        [u8; 32],
        [u8; 32],
        [u8; 32],
        [u8; 32],
    ) {
        (
            self.decision,
            self.approval_digest,
            self.challenge_nonce,
            self.child_transcript,
            self.request_hash,
        )
    }
}

/// Internal pair of authenticated, nonzero bootstrap nonces.
///
/// Copyability is confined to this private transcript helper and does not mint
/// a response capability or expose either nonce outside this module.
#[derive(Clone, Copy, Eq, PartialEq)]
struct BootstrapNonces {
    parent: [u8; BOOTSTRAP_NONCE_BYTES],
    child: [u8; BOOTSTRAP_NONCE_BYTES],
}

impl BootstrapNonces {
    fn from_hellos(
        expected_parent: [u8; BOOTSTRAP_NONCE_BYTES],
        parent_hello: &ApprovalParentHello,
        child_hello: &ApprovalChildHello,
    ) -> Result<Self, ApprovalChannelError> {
        let nonces = Self::new(parent_hello.parent_nonce(), child_hello.child_nonce())?;
        if nonces.parent != expected_parent {
            return Err(ApprovalChannelError::TranscriptFailure);
        }
        Ok(nonces)
    }

    fn new(
        parent: [u8; BOOTSTRAP_NONCE_BYTES],
        child: [u8; BOOTSTRAP_NONCE_BYTES],
    ) -> Result<Self, ApprovalChannelError> {
        if is_all_zero(&parent) || is_all_zero(&child) {
            return Err(ApprovalChannelError::TranscriptFailure);
        }
        Ok(Self { parent, child })
    }
}

/// One exact parent-bound response verifier armed before parent finish/EOF.
///
/// The concrete pipe reader, request binding, launcher identity, bootstrap
/// nonces, deadline, and fresh parent-local transcript salt remain sealed. The
/// salt is never sent to the child and is not a challenge-response primitive.
#[cfg(windows)]
pub(crate) struct ArmedParentBoundApprovalResponse {
    channel: ApprovalResponseChannel,
}

#[cfg(windows)]
impl fmt::Debug for ArmedParentBoundApprovalResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.channel;
        formatter.write_str("ArmedParentBoundApprovalResponse([SEALED])")
    }
}

/// Response bytes verified against the armed channel but not yet authorized as
/// a completed exchange because natural child success is still outstanding.
#[cfg(windows)]
pub(crate) struct ExitPendingParentBoundApprovalResponse {
    parts: VerifiedResponseParts,
}

#[cfg(windows)]
impl fmt::Debug for ExitPendingParentBoundApprovalResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.parts;
        formatter.write_str("ExitPendingParentBoundApprovalResponse([SEALED])")
    }
}

/// Opaque response evidence minted only after natural child success and final
/// logical Key Agent revalidation by the activation-sealed transition.
///
/// This value has no accessors or conversion into the public response/signing
/// capability. It is deliberately non-cloneable and non-copyable.
#[cfg(windows)]
pub(crate) struct ParentBoundApprovalResponseEvidence {
    parts: VerifiedResponseParts,
}

#[cfg(windows)]
impl fmt::Debug for ParentBoundApprovalResponseEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.parts;
        formatter.write_str("ParentBoundApprovalResponseEvidence([SEALED])")
    }
}

/// Arms the existing fixed-response verifier from activation-owned resources.
#[cfg(windows)]
pub(crate) fn arm_parent_bound_approval_response(
    bound_identity: HeldProcessIdentity,
    parent_hello: &ApprovalParentHello,
    child_hello: &ApprovalChildHello,
    request: &ApprovalRequest,
    expires_at: Instant,
    reader: ApprovalResponseReader,
    _seal: &ApprovalActivationSeal,
) -> Result<ArmedParentBoundApprovalResponse, ApprovalChannelError> {
    let bootstrap_nonces =
        BootstrapNonces::from_hellos(parent_hello.parent_nonce(), parent_hello, child_hello)?;
    let channel = ApprovalResponseChannel::arm_from_branded_reader(
        bound_identity,
        request,
        expires_at,
        bootstrap_nonces,
        Box::new(PlatformResponseReader(reader)),
    )?;
    Ok(ArmedParentBoundApprovalResponse { channel })
}

/// Consumes the exact response pipe and verifies one fixed frame plus EOF.
///
/// The result remains exit-pending and cannot yet become completed evidence.
#[cfg(windows)]
pub(crate) fn verify_parent_bound_approval_response(
    armed: ArmedParentBoundApprovalResponse,
    actual_identity: HeldProcessIdentity,
    _seal: &ApprovalActivationSeal,
) -> Result<ExitPendingParentBoundApprovalResponse, ApprovalChannelError> {
    let parts = armed
        .channel
        .verify_for_identity(TranscriptIdentity::from_held(actual_identity))?;
    Ok(ExitPendingParentBoundApprovalResponse { parts })
}

/// Mints sealed evidence after the activation module has consumed the child
/// into exit-code-zero success and revalidated the intact Key Agent aggregate.
#[cfg(windows)]
pub(crate) fn seal_successful_parent_bound_approval_response(
    pending: ExitPendingParentBoundApprovalResponse,
    _seal: &ApprovalActivationSeal,
) -> ParentBoundApprovalResponseEvidence {
    ParentBoundApprovalResponseEvidence {
        parts: pending.parts,
    }
}

/// Opaque, non-cloneable verifier state for one response from one held helper.
///
/// There is intentionally no public constructor. The activation-sealed
/// transition alone arms its concrete deadline-capable reader from the exact
/// launcher-owned response endpoint and held process identity, and that
/// transition has no orchestration caller. Accepting an arbitrary file, raw
/// handle, PID, or byte slice here would invalidate the authentication claim.
struct ApprovalResponseChannel {
    bound_identity: TranscriptIdentity,
    expected_digest: [u8; 32],
    expected_nonce: [u8; 32],
    expected_request_hash: [u8; 32],
    expires_at: Instant,
    transcript_salt: Zeroizing<[u8; TRANSCRIPT_SALT_BYTES]>,
    parent_bootstrap_nonce: Zeroizing<[u8; BOOTSTRAP_NONCE_BYTES]>,
    child_bootstrap_nonce: Zeroizing<[u8; BOOTSTRAP_NONCE_BYTES]>,
    reader: Box<dyn OneShotResponseReader>,
}

impl ApprovalResponseChannel {
    /// Consumes both the branded channel and the held helper process to produce
    /// one verified response.
    ///
    /// The helper's live process and kill-on-close job handles remain owned for
    /// the entire read and verification. Its PID is only one transcript field;
    /// it is never treated as sufficient authentication.
    ///
    /// # Errors
    ///
    /// Fails closed on an identity mismatch, timeout, channel failure, malformed
    /// frame, request-binding mismatch, or zero transcript.
    #[cfg(windows)]
    fn receive(
        self,
        helper: LaunchedHelper,
    ) -> Result<VerifiedApprovalResponse, ApprovalChannelError> {
        let actual_identity = TranscriptIdentity::from_held(helper.identity());
        let parts = helper
            .revalidate_held_process()
            .map_err(|_| ApprovalChannelError::IdentityMismatch)
            .and_then(|()| self.verify_for_identity(actual_identity));
        // Keep both exact handles alive through response verification, then
        // terminate the one-process Job and synchronously reap the held process
        // before releasing any approval capability. Cleanup is attempted even
        // when live-object revalidation or response verification failed.
        let termination =
            helper
                .terminate_and_wait(cleanup_deadline())
                .map_err(|error| match error {
                    LaunchError::TerminationDeadlineElapsed => {
                        ApprovalChannelError::DeadlineElapsed
                    }
                    _ => ApprovalChannelError::ChannelFailure,
                });
        let parts = parts?;
        termination?;
        Ok(VerifiedApprovalResponse {
            decision: parts.decision,
            approval_digest: parts.approval_digest,
            challenge_nonce: parts.challenge_nonce,
            child_transcript: parts.child_transcript,
            request_hash: parts.request_hash,
        })
    }

    /// Arms a channel only after the held process still matches the verified
    /// Approval helper artifact and its kill-on-close job remains live.
    #[cfg(windows)]
    fn arm_from_held_helper(
        verified_helper: &VerifiedHelper,
        launched_helper: &LaunchedHelper,
        request: &ApprovalRequest,
        expires_at: Instant,
        bootstrap_nonces: BootstrapNonces,
        reader: Box<dyn OneShotResponseReader>,
    ) -> Result<Self, ApprovalChannelError> {
        let identity = launched_helper.identity();
        if !matches_verified_approval_helper(
            verified_helper,
            identity.helper_file(),
            identity.helper_manifest_digest(),
            launched_helper.is_held_in_job(),
        ) {
            return Err(ApprovalChannelError::IdentityMismatch);
        }
        Self::arm_from_branded_reader(identity, request, expires_at, bootstrap_nonces, reader)
    }

    /// Arms a channel from already branded launcher-owned resources.
    ///
    /// The sole production-compiled caller is the activation-sealed parent-
    /// bound transition; it remains unreachable from orchestration. Legacy
    /// launch still rejects before allocation.
    fn arm_from_branded_reader(
        bound_identity: HeldProcessIdentity,
        request: &ApprovalRequest,
        expires_at: Instant,
        bootstrap_nonces: BootstrapNonces,
        reader: Box<dyn OneShotResponseReader>,
    ) -> Result<Self, ApprovalChannelError> {
        let bootstrap_nonces =
            BootstrapNonces::new(bootstrap_nonces.parent, bootstrap_nonces.child)?;
        let mut transcript_salt = Zeroizing::new([0_u8; TRANSCRIPT_SALT_BYTES]);
        getrandom::fill(&mut *transcript_salt)
            .map_err(|_| ApprovalChannelError::TranscriptFailure)?;
        if is_all_zero(&*transcript_salt) {
            return Err(ApprovalChannelError::TranscriptFailure);
        }
        if deadline_elapsed(expires_at) {
            return Err(ApprovalChannelError::DeadlineElapsed);
        }
        Ok(Self {
            bound_identity: TranscriptIdentity::from_held(bound_identity),
            expected_digest: *request.digest(),
            expected_nonce: *request.approval_nonce(),
            expected_request_hash: request_hash(request),
            expires_at,
            transcript_salt,
            parent_bootstrap_nonce: Zeroizing::new(bootstrap_nonces.parent),
            child_bootstrap_nonce: Zeroizing::new(bootstrap_nonces.child),
            reader,
        })
    }

    fn verify_for_identity(
        self,
        actual_identity: TranscriptIdentity,
    ) -> Result<VerifiedResponseParts, ApprovalChannelError> {
        if actual_identity != self.bound_identity {
            return Err(ApprovalChannelError::IdentityMismatch);
        }
        if is_all_zero(&*self.transcript_salt)
            || is_all_zero(&*self.parent_bootstrap_nonce)
            || is_all_zero(&*self.child_bootstrap_nonce)
        {
            return Err(ApprovalChannelError::TranscriptFailure);
        }
        if deadline_elapsed(self.expires_at) {
            return Err(ApprovalChannelError::DeadlineElapsed);
        }

        let response_bytes = self.reader.read_once(self.expires_at)?;
        if deadline_elapsed(self.expires_at) {
            return Err(ApprovalChannelError::DeadlineElapsed);
        }
        if response_bytes.len() != RESPONSE_BYTES {
            return Err(ApprovalChannelError::MalformedResponse);
        }
        let response = decode_response(&response_bytes)
            .map_err(|_| ApprovalChannelError::MalformedResponse)?;
        if response.digest() != &self.expected_digest
            || response.approval_nonce() != &self.expected_nonce
        {
            return Err(ApprovalChannelError::BindingMismatch);
        }

        let bootstrap_nonces =
            BootstrapNonces::new(*self.parent_bootstrap_nonce, *self.child_bootstrap_nonce)?;
        let child_transcript = transcript_hash(
            self.bound_identity,
            self.expected_digest,
            self.expected_nonce,
            self.expected_request_hash,
            &response_bytes,
            &self.transcript_salt,
            bootstrap_nonces,
        )?;
        let decision = match response.decision() {
            Decision::Approve => VerifiedApprovalDecision::Approve,
            Decision::Reject => VerifiedApprovalDecision::Reject,
        };
        Ok(VerifiedResponseParts {
            decision,
            approval_digest: self.expected_digest,
            challenge_nonce: self.expected_nonce,
            child_transcript,
            request_hash: self.expected_request_hash,
        })
    }
}

#[derive(Eq, PartialEq)]
struct VerifiedResponseParts {
    decision: VerifiedApprovalDecision,
    approval_digest: [u8; 32],
    challenge_nonce: [u8; 32],
    child_transcript: [u8; 32],
    request_hash: [u8; 32],
}

impl fmt::Debug for VerifiedResponseParts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedResponseParts([REDACTED])")
    }
}

impl fmt::Debug for ApprovalResponseChannel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalResponseChannel")
            .field("bound_identity", &"[REDACTED]")
            .field("expected_digest", &"[SHA-256]")
            .field("expected_nonce", &"[NONCE]")
            .field("expected_request_hash", &"[SHA-256]")
            .field("expires_at", &"[MONOTONIC DEADLINE]")
            .field("transcript_salt", &"[REDACTED PARENT-LOCAL SALT]")
            .field("parent_bootstrap_nonce", &"[REDACTED]")
            .field("child_bootstrap_nonce", &"[REDACTED]")
            .field("reader", &"[ONE-SHOT PRIVATE PIPE]")
            .finish()
    }
}

/// A read capability that can return at most one complete frame before the
/// supplied trusted monotonic deadline.
///
/// The trait is private: accepting caller-defined readers would turn arbitrary
/// bytes into an authenticated-helper claim. Its concrete Windows adapter is
/// armed only by the activation-sealed parent-bound transition.
trait OneShotResponseReader {
    fn read_once(self: Box<Self>, deadline: Instant) -> Result<Vec<u8>, ApprovalChannelError>;
}

#[cfg(windows)]
struct PlatformResponseReader(ApprovalResponseReader);

#[cfg(windows)]
impl OneShotResponseReader for PlatformResponseReader {
    fn read_once(self: Box<Self>, deadline: Instant) -> Result<Vec<u8>, ApprovalChannelError> {
        self.0
            .read_exact_frame(RESPONSE_BYTES, deadline)
            .map_err(|error| match error {
                PipeError::DeadlineElapsed => ApprovalChannelError::DeadlineElapsed,
                PipeError::UnexpectedEnd | PipeError::TrailingData => {
                    ApprovalChannelError::MalformedResponse
                }
                _ => ApprovalChannelError::ChannelFailure,
            })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct TranscriptIdentity {
    process_id: u32,
    helper_file: FileIdentity,
    helper_manifest_digest: [u8; 32],
    profile_revision: u32,
}

impl fmt::Debug for TranscriptIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TranscriptIdentity")
            .field("process_id", &"[REDACTED]")
            .field("helper_file", &"[REDACTED]")
            .field("helper_manifest_digest", &"[REDACTED]")
            .field("profile_revision", &"[REDACTED]")
            .finish()
    }
}

impl TranscriptIdentity {
    const fn from_held(identity: HeldProcessIdentity) -> Self {
        Self {
            process_id: identity.process_id(),
            helper_file: identity.helper_file(),
            helper_manifest_digest: identity.helper_manifest_digest(),
            profile_revision: identity.profile_revision(),
        }
    }
}

fn transcript_hash(
    identity: TranscriptIdentity,
    request_digest: [u8; 32],
    request_nonce: [u8; 32],
    request_hash: [u8; 32],
    response_bytes: &[u8],
    transcript_salt: &[u8; TRANSCRIPT_SALT_BYTES],
    bootstrap_nonces: BootstrapNonces,
) -> Result<[u8; 32], ApprovalChannelError> {
    if response_bytes.len() != RESPONSE_BYTES
        || is_all_zero(transcript_salt)
        || is_all_zero(&bootstrap_nonces.parent)
        || is_all_zero(&bootstrap_nonces.child)
    {
        return Err(ApprovalChannelError::TranscriptFailure);
    }
    let mut transcript = Sha256::new();
    transcript.update(
        u32::try_from(TRANSCRIPT_DOMAIN.len())
            .map_err(|_| ApprovalChannelError::TranscriptFailure)?
            .to_be_bytes(),
    );
    transcript.update(TRANSCRIPT_DOMAIN);
    transcript.update(identity.process_id.to_be_bytes());
    transcript.update(identity.helper_file.volume_serial_number.to_be_bytes());
    transcript.update(identity.helper_file.file_index.to_be_bytes());
    transcript.update(identity.helper_file.file_size.to_be_bytes());
    transcript.update(identity.helper_manifest_digest);
    transcript.update(identity.profile_revision.to_be_bytes());
    transcript.update(request_digest);
    transcript.update(request_nonce);
    transcript.update(request_hash);
    transcript.update(response_bytes);
    // This fresh value is parent-local transcript salt. It is never transmitted
    // and therefore must not be described as child challenge-response proof.
    transcript.update(transcript_salt);
    transcript.update(bootstrap_nonces.parent);
    transcript.update(bootstrap_nonces.child);
    let digest: [u8; 32] = transcript.finalize().into();
    if is_all_zero(&digest) {
        Err(ApprovalChannelError::TranscriptFailure)
    } else {
        Ok(digest)
    }
}

fn deadline_elapsed(expires_at: Instant) -> bool {
    Instant::now().checked_duration_since(expires_at).is_some()
}

fn cleanup_deadline() -> Instant {
    Instant::now()
        .checked_add(TERMINATION_GRACE)
        .unwrap_or_else(Instant::now)
}

fn is_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use approval_wire::{
        ApprovalChildHello, ApprovalDisplay, ApprovalParentHello, ApprovalRequest,
        ApprovalResponse, Decision, DisplayField, FieldSemantic, OperationKind, RiskLevel,
        SimulationStatus, encode_response, request_hash,
    };
    use zeroize::Zeroizing;

    use super::{
        ApprovalChannelError, ApprovalResponseChannel, BOOTSTRAP_NONCE_BYTES, BootstrapNonces,
        OneShotResponseReader, TRANSCRIPT_SALT_BYTES, TranscriptIdentity, VerifiedApprovalDecision,
    };
    #[cfg(windows)]
    use super::{
        ApprovalLaunchError, ArmedParentBoundApprovalResponse,
        ExitPendingParentBoundApprovalResponse, ParentBoundApprovalResponseEvidence,
        launch_approval_frontend, matches_verified_approval_helper,
    };
    use crate::helper::FileIdentity;
    #[cfg(windows)]
    use crate::{
        attestation::ReleaseAttestation,
        helper::VerifiedHelper,
        launch::{NoNetworkLpacProfile, RestrictedLauncher},
    };

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

    #[derive(Debug)]
    struct MemoryReader {
        bytes: Vec<u8>,
        fail: bool,
    }

    impl OneShotResponseReader for MemoryReader {
        fn read_once(self: Box<Self>, _deadline: Instant) -> Result<Vec<u8>, ApprovalChannelError> {
            if self.fail {
                Err(ApprovalChannelError::ChannelFailure)
            } else {
                Ok(self.bytes)
            }
        }
    }

    fn field(
        semantic: FieldSemantic,
        value: &str,
    ) -> Result<DisplayField, Box<dyn std::error::Error>> {
        Ok(DisplayField::new(
            semantic,
            value,
            semantic != FieldSemantic::SimulationEngine,
        )?)
    }

    fn request() -> Result<ApprovalRequest, Box<dyn std::error::Error>> {
        let display = ApprovalDisplay::new(
            RiskLevel::High,
            vec![
                field(FieldSemantic::Origin, "https://example.test")?,
                field(
                    FieldSemantic::OriginProvenance,
                    "Browser-reported; not independently verified",
                )?,
                field(
                    FieldSemantic::Account,
                    "0x1111111111111111111111111111111111111111",
                )?,
                field(FieldSemantic::NetworkName, "Ethereum")?,
                field(FieldSemantic::ChainId, "1")?,
                field(
                    FieldSemantic::GenesisHash,
                    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )?,
                field(
                    FieldSemantic::RulesetRevision,
                    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                )?,
                field(
                    FieldSemantic::RpcObservationsDigest,
                    "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                )?,
                field(
                    FieldSemantic::OperationKind,
                    OperationKind::PersonalMessage.value(),
                )?,
                field(FieldSemantic::PersonalMessageBytes, "0x0102")?,
                field(
                    FieldSemantic::SimulationStatus,
                    SimulationStatus::NotPerformed.value(),
                )?,
                field(
                    FieldSemantic::OriginWarning,
                    "Browser origin is not independently attested.",
                )?,
                field(
                    FieldSemantic::PersonalMessageWarning,
                    "Personal signatures can be reused by protocols.",
                )?,
                field(
                    FieldSemantic::NoSimulationWarning,
                    "No simulation was performed.",
                )?,
            ],
        )?;
        Ok(ApprovalRequest::new(
            [7; 32],
            [9; 32],
            120_000,
            "blue comet",
            display,
        )?)
    }

    const fn identity() -> TranscriptIdentity {
        TranscriptIdentity {
            process_id: 41,
            helper_file: FileIdentity {
                volume_serial_number: 42,
                file_index: 43,
                file_size: 44,
            },
            helper_manifest_digest: [45; 32],
            profile_revision: 1,
        }
    }

    fn channel(
        bytes: Vec<u8>,
        bound_identity: TranscriptIdentity,
        salt_byte: u8,
        expires_at: Instant,
    ) -> Result<ApprovalResponseChannel, Box<dyn std::error::Error>> {
        channel_with_bootstrap(
            bytes,
            bound_identity,
            salt_byte,
            [60; BOOTSTRAP_NONCE_BYTES],
            [70; BOOTSTRAP_NONCE_BYTES],
            expires_at,
        )
    }

    fn channel_with_bootstrap(
        bytes: Vec<u8>,
        bound_identity: TranscriptIdentity,
        salt_byte: u8,
        parent_bootstrap_nonce: [u8; BOOTSTRAP_NONCE_BYTES],
        child_bootstrap_nonce: [u8; BOOTSTRAP_NONCE_BYTES],
        expires_at: Instant,
    ) -> Result<ApprovalResponseChannel, Box<dyn std::error::Error>> {
        let request = request()?;
        Ok(ApprovalResponseChannel {
            bound_identity,
            expected_digest: *request.digest(),
            expected_nonce: *request.approval_nonce(),
            expected_request_hash: request_hash(&request),
            expires_at,
            transcript_salt: Zeroizing::new([salt_byte; TRANSCRIPT_SALT_BYTES]),
            parent_bootstrap_nonce: Zeroizing::new(parent_bootstrap_nonce),
            child_bootstrap_nonce: Zeroizing::new(child_bootstrap_nonce),
            reader: Box::new(MemoryReader { bytes, fail: false }),
        })
    }

    fn valid_bytes(decision: Decision) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let request = request()?;
        Ok(encode_response(ApprovalResponse::for_request(decision, &request)).to_vec())
    }

    fn future_deadline() -> Result<Instant, Box<dyn std::error::Error>> {
        Instant::now()
            .checked_add(Duration::from_mins(1))
            .ok_or_else(|| "monotonic deadline overflow".into())
    }

    #[cfg(windows)]
    #[test]
    fn parent_bound_response_typestates_are_move_only() {
        let _ = <ArmedParentBoundApprovalResponse as AmbiguousIfClone<_>>::marker;
        let _ = <ArmedParentBoundApprovalResponse as AmbiguousIfCopy<_>>::marker;
        let _ = <ExitPendingParentBoundApprovalResponse as AmbiguousIfClone<_>>::marker;
        let _ = <ExitPendingParentBoundApprovalResponse as AmbiguousIfCopy<_>>::marker;
        let _ = <ParentBoundApprovalResponseEvidence as AmbiguousIfClone<_>>::marker;
        let _ = <ParentBoundApprovalResponseEvidence as AmbiguousIfCopy<_>>::marker;
    }

    #[test]
    fn exact_response_produces_nonzero_identity_bound_transcript()
    -> Result<(), Box<dyn std::error::Error>> {
        let verified = channel(
            valid_bytes(Decision::Approve)?,
            identity(),
            50,
            future_deadline()?,
        )?
        .verify_for_identity(identity())?;
        assert_eq!(verified.decision, VerifiedApprovalDecision::Approve);
        assert_eq!(verified.approval_digest, [7; 32]);
        assert_eq!(verified.challenge_nonce, [9; 32]);
        assert!(verified.child_transcript.iter().any(|byte| *byte != 0));
        Ok(())
    }

    #[test]
    fn bootstrap_nonce_validation_rejects_zero_and_parent_substitution()
    -> Result<(), Box<dyn std::error::Error>> {
        let parent_nonce = [60; BOOTSTRAP_NONCE_BYTES];
        let child_nonce = [70; BOOTSTRAP_NONCE_BYTES];
        let parent_hello = ApprovalParentHello::new(41, 42, 43, 44, 45, parent_nonce)?;
        let child_hello = ApprovalChildHello::new(child_nonce)?;

        let validated = BootstrapNonces::from_hellos(parent_nonce, &parent_hello, &child_hello)?;
        assert_eq!(validated.parent, parent_nonce);
        assert_eq!(validated.child, child_nonce);
        assert!(matches!(
            BootstrapNonces::from_hellos([61; BOOTSTRAP_NONCE_BYTES], &parent_hello, &child_hello),
            Err(ApprovalChannelError::TranscriptFailure)
        ));
        assert!(matches!(
            BootstrapNonces::new([0; BOOTSTRAP_NONCE_BYTES], child_nonce),
            Err(ApprovalChannelError::TranscriptFailure)
        ));
        assert!(matches!(
            BootstrapNonces::new(parent_nonce, [0; BOOTSTRAP_NONCE_BYTES]),
            Err(ApprovalChannelError::TranscriptFailure)
        ));
        Ok(())
    }

    #[test]
    fn reject_is_valid_but_never_aliases_approve() -> Result<(), Box<dyn std::error::Error>> {
        let approve = channel(
            valid_bytes(Decision::Approve)?,
            identity(),
            50,
            future_deadline()?,
        )?
        .verify_for_identity(identity())?;
        let reject = channel(
            valid_bytes(Decision::Reject)?,
            identity(),
            50,
            future_deadline()?,
        )?
        .verify_for_identity(identity())?;
        assert_eq!(reject.decision, VerifiedApprovalDecision::Reject);
        assert_ne!(approve.child_transcript, reject.child_transcript);
        Ok(())
    }

    #[test]
    fn protocol_bit_changes_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        for index in [0_usize, 8, 11, 42, 43, 74] {
            let mut changed = valid_bytes(Decision::Approve)?;
            changed[index] ^= 1;
            let error = channel(changed, identity(), 50, future_deadline()?)?
                .verify_for_identity(identity());
            assert!(matches!(
                error,
                Err(ApprovalChannelError::MalformedResponse | ApprovalChannelError::BindingMismatch)
            ));
        }
        Ok(())
    }

    #[test]
    fn every_truncation_and_trailing_bytes_are_rejected() -> Result<(), Box<dyn std::error::Error>>
    {
        let bytes = valid_bytes(Decision::Approve)?;
        for length in 0..bytes.len() {
            let error = channel(bytes[..length].to_vec(), identity(), 50, future_deadline()?)?
                .verify_for_identity(identity());
            assert_eq!(error, Err(ApprovalChannelError::MalformedResponse));
        }
        let mut trailing = bytes;
        trailing.push(0);
        let error =
            channel(trailing, identity(), 50, future_deadline()?)?.verify_for_identity(identity());
        assert_eq!(error, Err(ApprovalChannelError::MalformedResponse));
        Ok(())
    }

    #[test]
    fn expired_monotonic_deadline_fails_before_read() -> Result<(), Box<dyn std::error::Error>> {
        let past = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .ok_or("monotonic clock cannot represent the test deadline")?;
        let error = channel(valid_bytes(Decision::Approve)?, identity(), 50, past)?
            .verify_for_identity(identity());
        assert_eq!(error, Err(ApprovalChannelError::DeadlineElapsed));
        Ok(())
    }

    #[test]
    fn wrong_digest_and_nonce_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let mut wrong_digest = valid_bytes(Decision::Approve)?;
        wrong_digest[11] ^= 1;
        assert_eq!(
            channel(wrong_digest, identity(), 50, future_deadline()?)?
                .verify_for_identity(identity()),
            Err(ApprovalChannelError::BindingMismatch)
        );

        let mut wrong_nonce = valid_bytes(Decision::Approve)?;
        wrong_nonce[43] ^= 1;
        assert_eq!(
            channel(wrong_nonce, identity(), 50, future_deadline()?)?
                .verify_for_identity(identity()),
            Err(ApprovalChannelError::BindingMismatch)
        );
        Ok(())
    }

    #[test]
    fn every_held_identity_component_is_bound() -> Result<(), Box<dyn std::error::Error>> {
        let expected = identity();
        let mut mutations = [expected; 6];
        mutations[0].process_id ^= 1;
        mutations[1].helper_file.volume_serial_number ^= 1;
        mutations[2].helper_file.file_index ^= 1;
        mutations[3].helper_file.file_size ^= 1;
        mutations[4].helper_manifest_digest[0] ^= 1;
        mutations[5].profile_revision ^= 1;
        for actual in mutations {
            assert_eq!(
                channel(
                    valid_bytes(Decision::Approve)?,
                    expected,
                    50,
                    future_deadline()?
                )?
                .verify_for_identity(actual),
                Err(ApprovalChannelError::IdentityMismatch)
            );
        }
        Ok(())
    }

    #[test]
    fn direct_response_replay_and_nonce_substitution_produce_distinct_transcripts()
    -> Result<(), Box<dyn std::error::Error>> {
        let bytes = valid_bytes(Decision::Approve)?;
        let first = channel_with_bootstrap(
            bytes.clone(),
            identity(),
            50,
            [60; BOOTSTRAP_NONCE_BYTES],
            [70; BOOTSTRAP_NONCE_BYTES],
            future_deadline()?,
        )?
        .verify_for_identity(identity())?;
        let substituted_parent = channel_with_bootstrap(
            bytes.clone(),
            identity(),
            50,
            [61; BOOTSTRAP_NONCE_BYTES],
            [70; BOOTSTRAP_NONCE_BYTES],
            future_deadline()?,
        )?
        .verify_for_identity(identity())?;
        let substituted_child = channel_with_bootstrap(
            bytes,
            identity(),
            50,
            [60; BOOTSTRAP_NONCE_BYTES],
            [71; BOOTSTRAP_NONCE_BYTES],
            future_deadline()?,
        )?
        .verify_for_identity(identity())?;
        assert_ne!(first.child_transcript, substituted_parent.child_transcript);
        assert_ne!(first.child_transcript, substituted_child.child_transcript);
        assert_ne!(
            substituted_parent.child_transcript,
            substituted_child.child_transcript
        );
        Ok(())
    }

    #[test]
    fn capability_retains_exact_request_hash_across_response_delay()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = request()?;
        let expected = request_hash(&request);
        let verified = channel(
            valid_bytes(Decision::Approve)?,
            identity(),
            50,
            future_deadline()?,
        )?
        .verify_for_identity(identity())?;
        assert_eq!(verified.request_hash, expected);
        Ok(())
    }

    #[test]
    fn approval_channel_debug_redacts_bound_transcript_material()
    -> Result<(), Box<dyn std::error::Error>> {
        let response_channel = channel(
            valid_bytes(Decision::Approve)?,
            identity(),
            50,
            future_deadline()?,
        )?;
        let rendered = format!("{response_channel:?}");
        assert!(rendered.contains("ApprovalResponseChannel"));
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("process_id: 41"));
        assert!(!rendered.contains("volume_serial_number: 42"));
        assert!(!rendered.contains("45, 45"));
        Ok(())
    }

    #[test]
    fn zero_salt_and_reader_failure_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let zero_salt = channel(
            valid_bytes(Decision::Approve)?,
            identity(),
            0,
            future_deadline()?,
        )?
        .verify_for_identity(identity());
        assert_eq!(zero_salt, Err(ApprovalChannelError::TranscriptFailure));

        let zero_parent = channel_with_bootstrap(
            valid_bytes(Decision::Approve)?,
            identity(),
            50,
            [0; BOOTSTRAP_NONCE_BYTES],
            [70; BOOTSTRAP_NONCE_BYTES],
            future_deadline()?,
        )?
        .verify_for_identity(identity());
        assert_eq!(zero_parent, Err(ApprovalChannelError::TranscriptFailure));

        let zero_child = channel_with_bootstrap(
            valid_bytes(Decision::Approve)?,
            identity(),
            50,
            [60; BOOTSTRAP_NONCE_BYTES],
            [0; BOOTSTRAP_NONCE_BYTES],
            future_deadline()?,
        )?
        .verify_for_identity(identity());
        assert_eq!(zero_child, Err(ApprovalChannelError::TranscriptFailure));

        let request = request()?;
        let failed_reader = ApprovalResponseChannel {
            bound_identity: identity(),
            expected_digest: *request.digest(),
            expected_nonce: *request.approval_nonce(),
            expected_request_hash: request_hash(&request),
            expires_at: future_deadline()?,
            transcript_salt: Zeroizing::new([50; TRANSCRIPT_SALT_BYTES]),
            parent_bootstrap_nonce: Zeroizing::new([60; BOOTSTRAP_NONCE_BYTES]),
            child_bootstrap_nonce: Zeroizing::new([70; BOOTSTRAP_NONCE_BYTES]),
            reader: Box::new(MemoryReader {
                bytes: Vec::new(),
                fail: true,
            }),
        };
        assert_eq!(
            failed_reader.verify_for_identity(identity()),
            Err(ApprovalChannelError::ChannelFailure)
        );
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn arming_rejects_verified_artifact_role_identity_digest_or_job_mismatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let approval = VerifiedHelper::for_approval_channel_test(true)?;
        let other_role = VerifiedHelper::for_approval_channel_test(false)?;
        let expected_identity = approval.identity();
        let expected_digest = approval.manifest_digest();
        assert!(matches_verified_approval_helper(
            &approval,
            expected_identity,
            expected_digest,
            true
        ));

        let mut substituted_identity = expected_identity;
        substituted_identity.file_index ^= 1;
        assert!(!matches_verified_approval_helper(
            &approval,
            substituted_identity,
            expected_digest,
            true
        ));

        let mut substituted_digest = expected_digest;
        substituted_digest[0] ^= 1;
        assert!(!matches_verified_approval_helper(
            &approval,
            expected_identity,
            substituted_digest,
            true
        ));
        assert!(!matches_verified_approval_helper(
            &other_role,
            expected_identity,
            expected_digest,
            true
        ));
        assert!(!matches_verified_approval_helper(
            &approval,
            expected_identity,
            expected_digest,
            false
        ));
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn high_level_launch_rejects_wrong_role_before_pipe_or_process_side_effects()
    -> Result<(), Box<dyn std::error::Error>> {
        let wrong_role = VerifiedHelper::for_approval_channel_test(false)?;
        let launcher =
            RestrictedLauncher::new(ReleaseAttestation::default(), NoNetworkLpacProfile::v1());
        assert!(matches!(
            launch_approval_frontend(launcher, &wrong_role, &request()?),
            Err(ApprovalLaunchError::WrongHelperRole)
        ));
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn high_level_launch_rejects_missing_logical_parent_before_bootstrap_resources()
    -> Result<(), Box<dyn std::error::Error>> {
        let approval_frontend = VerifiedHelper::for_approval_channel_test(true)?;
        let launcher =
            RestrictedLauncher::new(ReleaseAttestation::default(), NoNetworkLpacProfile::v1());
        assert!(matches!(
            launch_approval_frontend(launcher, &approval_frontend, &request()?),
            Err(ApprovalLaunchError::LogicalParentUnavailable)
        ));
        Ok(())
    }
}
