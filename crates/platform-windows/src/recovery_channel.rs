//! Authenticated parent-side channel for the two-process recovery ceremony.
//!
//! Display and confirmation deliberately use different launch functions,
//! bootstrap domains, retained request types, and one-shot capabilities.  This
//! module remains crate-private until a Key Agent adapter can supply a live
//! protected-settings lease for the anti-phishing phrase.  Development builds
//! also retain the compiled release policy at `None`, so the restricted launcher
//! fails before a recovery frontend can be started.

use core::fmt;
use std::time::{Duration, Instant};

use secret_input_ui::{
    SecretInputError,
    bootstrap::{
        CHILD_HELLO_BYTES, MAX_AUTHENTICATED_RECOVERY_RESPONSE_BYTES, NONCE_BYTES, ParentHello,
        RecoverySessionKind, decode_authenticated_recovery_outcome, decode_recovery_child_hello,
        encode_recovery_parent_finish, encode_recovery_parent_hello,
    },
    recovery::{
        RecoveryCeremonyId, RecoveryConfirmRequest, RecoveryConfirmationInput,
        RecoveryDisplayRequest, RecoveryOutcome, RecoveryRequest, encode_request,
    },
};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{helper::FileIdentity, launch::HeldProcessIdentity};
#[cfg(windows)]
use crate::{
    helper::VerifiedHelper,
    launch::{InheritedStdio, LaunchError, LaunchedHelper, RestrictedLauncher},
    pipe::{PipeError, PrivateSecretInputPipes, SecretResponseReader},
};

const DISPLAY_REQUEST_DOMAIN: &[u8] = b"your-wallet/platform-recovery-display-request/v1\0";
const CONFIRM_REQUEST_DOMAIN: &[u8] = b"your-wallet/platform-recovery-confirm-request/v1\0";
const DISPLAY_TRANSCRIPT_DOMAIN: &[u8] = b"your-wallet/platform-recovery-display-transcript/v1\0";
const CONFIRM_TRANSCRIPT_DOMAIN: &[u8] = b"your-wallet/platform-recovery-confirm-transcript/v1\0";
const MAX_RECOVERY_UI_DURATION: Duration = Duration::from_mins(2);

/// Failure while consuming one authenticated recovery response.
///
/// Variants intentionally contain no path, phrase, answer, nonce, or operating
/// system text and are therefore safe to format at the non-secret boundary.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum RecoveryChannelError {
    /// A held process or release artifact differed from the bound identity.
    #[error("recovery frontend identity mismatch")]
    IdentityMismatch,
    /// The retained request no longer matched the request bound at launch.
    #[error("recovery request binding mismatch")]
    RequestBindingMismatch,
    /// A response was malformed, cross-stage, truncated, oversized, or trailing.
    #[error("malformed authenticated recovery response")]
    MalformedResponse,
    /// The one monotonic ceremony deadline elapsed.
    #[error("recovery frontend deadline elapsed")]
    DeadlineElapsed,
    /// The private response endpoint failed without disclosing platform detail.
    #[error("private recovery response channel failed")]
    ChannelFailure,
    /// Fresh challenge generation or transcript construction failed closed.
    #[error("recovery channel transcript construction failed")]
    TranscriptFailure,
}

/// Failure before a concrete recovery helper and channel have been armed.
#[cfg(windows)]
#[derive(Debug, Error)]
pub(crate) enum RecoveryLaunchError {
    /// The manifest-derived role was not exactly Secret Input Frontend.
    #[error("verified helper is not the recovery frontend")]
    WrongHelperRole,
    /// A typed recovery request failed canonical validation.
    #[error("recovery request is invalid")]
    InvalidRequest,
    /// A confirmation did not consume a receipt from the same artifact/profile.
    #[error("recovery display receipt does not match the confirmation ceremony or helper")]
    DisplayReceiptMismatch,
    /// The restricted, release-attested helper launch failed closed.
    #[error("recovery frontend launch failed")]
    Launch(#[source] LaunchError),
    /// Private endpoint setup or request transfer failed.
    #[error("recovery private-pipe setup failed")]
    Pipe(#[source] PipeError),
    /// The clamped monotonic deadline was already elapsed or unrepresentable.
    #[error("recovery setup deadline elapsed")]
    DeadlineElapsed,
    /// Held identity or transcript binding failed while arming the channel.
    #[error("recovery response channel could not be armed")]
    Channel(#[source] RecoveryChannelError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryStage {
    Display,
    Confirm,
}

impl RecoveryStage {
    const fn session_kind(self) -> RecoverySessionKind {
        match self {
            Self::Display => RecoverySessionKind::Display,
            Self::Confirm => RecoverySessionKind::Confirm,
        }
    }

    const fn request_domain(self) -> &'static [u8] {
        match self {
            Self::Display => DISPLAY_REQUEST_DOMAIN,
            Self::Confirm => CONFIRM_REQUEST_DOMAIN,
        }
    }

    const fn transcript_domain(self) -> &'static [u8] {
        match self {
            Self::Display => DISPLAY_TRANSCRIPT_DOMAIN,
            Self::Confirm => CONFIRM_TRANSCRIPT_DOMAIN,
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Display => 1,
            Self::Confirm => 2,
        }
    }
}

/// Result of the display process after its held process and kill-on-close job
/// have been consumed.
pub(crate) enum RecoveryDisplayResult {
    /// The user deliberately acknowledged the displayed recovery material.
    Acknowledged(RecoveryDisplayAcknowledgement),
    /// The user cancelled or closed the display process.
    Cancelled,
}

impl fmt::Debug for RecoveryDisplayResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Acknowledged(_) => "RecoveryDisplayResult::Acknowledged([REDACTED RECEIPT])",
            Self::Cancelled => "RecoveryDisplayResult::Cancelled",
        })
    }
}

/// Non-cloneable transition receipt required to launch confirmation.
///
/// It contains only the opaque ceremony identifier, original monotonic expiry,
/// hashes, and held identity metadata. The mnemonic and first address from the
/// display request are dropped and zeroized before this value can be returned.
pub(crate) struct RecoveryDisplayAcknowledgement {
    link: DisplayLink,
}

impl fmt::Debug for RecoveryDisplayAcknowledgement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryDisplayAcknowledgement([REDACTED ONE-SHOT RECEIPT])")
    }
}

/// Result of the confirmation process after its held process and job have been
/// consumed.
pub(crate) enum RecoveryConfirmResult {
    /// Four zeroizing words plus the independently entered first address.
    Confirmed(Box<VerifiedRecoveryConfirmation>),
    /// The user cancelled or closed the confirmation process.
    Cancelled,
}

impl fmt::Debug for RecoveryConfirmResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Confirmed(_) => "RecoveryConfirmResult::Confirmed([REDACTED RECEIPT])",
            Self::Cancelled => "RecoveryConfirmResult::Cancelled",
        })
    }
}

/// Opaque, non-cloneable proof of one exact authenticated confirmation result.
pub(crate) struct VerifiedRecoveryConfirmation {
    input: RecoveryConfirmationInput,
    request_hash: [u8; 32],
    transcript: [u8; 32],
    display_transcript: [u8; 32],
    expires_at: Instant,
}

impl VerifiedRecoveryConfirmation {
    /// Consumes the one-shot proof into zeroizing words and the submitted
    /// address, provided the original monotonic deadline has not elapsed.
    pub(crate) fn into_parts(
        self,
    ) -> Result<([Zeroizing<String>; 4], [u8; 20]), RecoveryChannelError> {
        if deadline_elapsed(self.expires_at) {
            return Err(RecoveryChannelError::DeadlineElapsed);
        }
        if is_all_zero(&self.request_hash)
            || is_all_zero(&self.transcript)
            || is_all_zero(&self.display_transcript)
        {
            return Err(RecoveryChannelError::TranscriptFailure);
        }
        Ok(self.input.into_parts())
    }
}

impl fmt::Debug for VerifiedRecoveryConfirmation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedRecoveryConfirmation([REDACTED ONE-SHOT PROOF])")
    }
}

/// Held display frontend plus its exact concrete response endpoint.
#[cfg(windows)]
pub(crate) struct PendingRecoveryDisplay {
    ceremony_id: RecoveryCeremonyId,
    helper: LaunchedHelper,
    response_reader: SecretResponseReader,
    binding: RecoveryResponseBinding,
}

#[cfg(windows)]
impl PendingRecoveryDisplay {
    /// Consumes the display helper and returns only acknowledgement or cancel.
    /// The exact helper is explicitly terminated and awaited before an
    /// acknowledgement receipt is constructed and made available to the caller.
    pub(crate) fn receive(self) -> Result<RecoveryDisplayResult, RecoveryChannelError> {
        let Self {
            ceremony_id,
            helper,
            response_reader,
            binding,
        } = self;
        if !helper.is_held_in_job() {
            return Err(RecoveryChannelError::IdentityMismatch);
        }
        let actual_identity = TranscriptIdentity::from_held(helper.identity());
        let expires_at = binding.expires_at;
        let decoded = binding.receive_from_concrete(response_reader, actual_identity);
        let terminated = helper
            .terminate_and_wait(expires_at)
            .map_err(map_termination_error);
        // No confirmation-enabling receipt exists until both response
        // authentication and exact held-process termination have succeeded.
        terminated?;
        match decoded? {
            DecodedRecovery::DisplayAcknowledged(evidence) => Ok(
                RecoveryDisplayResult::Acknowledged(RecoveryDisplayAcknowledgement {
                    link: DisplayLink {
                        ceremony_id,
                        identity: evidence.identity,
                        request_hash: evidence.request_hash,
                        transcript: evidence.transcript,
                        expires_at,
                    },
                }),
            ),
            DecodedRecovery::DisplayCancelled => Ok(RecoveryDisplayResult::Cancelled),
            DecodedRecovery::Confirmed { .. } | DecodedRecovery::ConfirmCancelled => {
                Err(RecoveryChannelError::MalformedResponse)
            }
        }
    }
}

#[cfg(windows)]
impl fmt::Debug for PendingRecoveryDisplay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingRecoveryDisplay")
            .field("ceremony_id", &"[REDACTED]")
            .field("helper", &"[HELD PROCESS AND JOB]")
            .field("response_reader", &"[CONCRETE PRIVATE PIPE]")
            .field("binding", &self.binding)
            .finish()
    }
}

/// Held confirmation frontend plus its exact concrete response endpoint.
#[cfg(windows)]
pub(crate) struct PendingRecoveryConfirm {
    helper: LaunchedHelper,
    response_reader: SecretResponseReader,
    binding: RecoveryResponseBinding,
}

#[cfg(windows)]
impl PendingRecoveryConfirm {
    /// Consumes the confirmation helper into one authenticated typed result.
    pub(crate) fn receive(self) -> Result<RecoveryConfirmResult, RecoveryChannelError> {
        let Self {
            helper,
            response_reader,
            binding,
        } = self;
        if !helper.is_held_in_job() {
            return Err(RecoveryChannelError::IdentityMismatch);
        }
        let actual_identity = TranscriptIdentity::from_held(helper.identity());
        let expires_at = binding.expires_at;
        let decoded = binding.receive_from_concrete(response_reader, actual_identity);
        let terminated = helper
            .terminate_and_wait(expires_at)
            .map_err(map_termination_error);
        // The secret-bearing result is not returned while the exact child is live.
        terminated?;
        match decoded? {
            DecodedRecovery::Confirmed {
                input,
                request_hash,
                transcript,
                display_transcript,
                expires_at,
            } => Ok(RecoveryConfirmResult::Confirmed(Box::new(
                VerifiedRecoveryConfirmation {
                    input,
                    request_hash,
                    transcript,
                    display_transcript,
                    expires_at,
                },
            ))),
            DecodedRecovery::ConfirmCancelled => Ok(RecoveryConfirmResult::Cancelled),
            DecodedRecovery::DisplayAcknowledged(_) | DecodedRecovery::DisplayCancelled => {
                Err(RecoveryChannelError::MalformedResponse)
            }
        }
    }
}

#[cfg(windows)]
impl fmt::Debug for PendingRecoveryConfirm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingRecoveryConfirm")
            .field("helper", &"[HELD PROCESS AND JOB]")
            .field("response_reader", &"[CONCRETE PRIVATE PIPE]")
            .field("binding", &self.binding)
            .finish()
    }
}

/// Launches one isolated recovery-display process.
///
/// This facade intentionally stays crate-private: no caller can currently
/// provide an arbitrary anti-phishing phrase or bypass the future Key Agent
/// protected-settings lease adapter.
#[cfg(windows)]
pub(crate) fn launch_recovery_display_frontend(
    launcher: RestrictedLauncher,
    helper: &VerifiedHelper,
    ceremony_id: RecoveryCeremonyId,
    request: RecoveryDisplayRequest,
    requested_duration: Duration,
) -> Result<PendingRecoveryDisplay, RecoveryLaunchError> {
    if !request.matches_ceremony(&ceremony_id) {
        return Err(RecoveryLaunchError::InvalidRequest);
    }
    let request = RecoveryRequest::Display(request);
    let expires_at = clamped_deadline(requested_duration)?;
    let (helper, response_reader, binding) = launch_recovery_stage(
        launcher,
        helper,
        request,
        RecoveryStage::Display,
        None,
        expires_at,
    )?;
    Ok(PendingRecoveryDisplay {
        ceremony_id,
        helper,
        response_reader,
        binding,
    })
}

/// Launches one isolated recovery-confirmation process after consuming the
/// non-cloneable acknowledgement from the terminated display process.
#[cfg(windows)]
pub(crate) fn launch_recovery_confirm_frontend(
    acknowledgement: RecoveryDisplayAcknowledgement,
    launcher: RestrictedLauncher,
    helper: &VerifiedHelper,
    request: RecoveryConfirmRequest,
    requested_duration: Duration,
) -> Result<PendingRecoveryConfirm, RecoveryLaunchError> {
    require_recovery_frontend(helper)?;
    let display_link = acknowledgement.link;
    if !display_link.identity.same_artifact_as_verified(helper) {
        return Err(RecoveryLaunchError::DisplayReceiptMismatch);
    }
    if !request.matches_ceremony(&display_link.ceremony_id) {
        return Err(RecoveryLaunchError::DisplayReceiptMismatch);
    }
    let request = RecoveryRequest::Confirm(request);
    let expires_at = clamped_deadline_capped(requested_duration, display_link.expires_at)?;
    let (helper, response_reader, binding) = launch_recovery_stage(
        launcher,
        helper,
        request,
        RecoveryStage::Confirm,
        Some(display_link),
        expires_at,
    )?;
    Ok(PendingRecoveryConfirm {
        helper,
        response_reader,
        binding,
    })
}

#[cfg(windows)]
fn launch_recovery_stage(
    launcher: RestrictedLauncher,
    helper: &VerifiedHelper,
    request: RecoveryRequest,
    stage: RecoveryStage,
    display_link: Option<DisplayLink>,
    expires_at: Instant,
) -> Result<
    (
        LaunchedHelper,
        SecretResponseReader,
        RecoveryResponseBinding,
    ),
    RecoveryLaunchError,
> {
    require_recovery_frontend(helper)?;
    validate_request_stage(&request, stage).map_err(|_| RecoveryLaunchError::InvalidRequest)?;
    let _validated_request =
        encode_request(&request).map_err(|_| RecoveryLaunchError::InvalidRequest)?;

    let mut parent_nonce = Zeroizing::new([0_u8; NONCE_BYTES]);
    getrandom::fill(&mut *parent_nonce)
        .map_err(|_| RecoveryLaunchError::Channel(RecoveryChannelError::TranscriptFailure))?;
    if is_all_zero(&*parent_nonce) {
        return Err(RecoveryLaunchError::Channel(
            RecoveryChannelError::TranscriptFailure,
        ));
    }

    let pipes = PrivateSecretInputPipes::create().map_err(map_setup_pipe_error)?;
    let held_process = {
        let inherited = InheritedStdio::for_child_pipe_servers(
            pipes.child_input(),
            pipes.child_output(),
            pipes.child_output(),
        )
        .map_err(RecoveryLaunchError::Launch)?;
        launcher
            .spawn_secret_input(helper, &inherited)
            .map_err(RecoveryLaunchError::Launch)?
    };
    let proof = held_process
        .parent_proof()
        .ok_or(RecoveryLaunchError::Channel(
            RecoveryChannelError::IdentityMismatch,
        ))?;
    let parent_hello = ParentHello::new(
        proof.process_id(),
        proof.process_handle(),
        proof.image_handle(),
        *parent_nonce,
    )
    .map_err(|_| RecoveryLaunchError::Channel(RecoveryChannelError::TranscriptFailure))?;
    let hello = encode_recovery_parent_hello(stage.session_kind(), &parent_hello);
    let (mut writer, response_reader) = pipes.into_parent();
    writer
        .write_bytes(&hello, expires_at)
        .map_err(map_setup_pipe_error)?;
    let child_hello_bytes = response_reader
        .read_exact(CHILD_HELLO_BYTES, expires_at)
        .map_err(map_setup_pipe_error)?;
    let child_hello =
        decode_recovery_child_hello(stage.session_kind(), &parent_hello, &child_hello_bytes)
            .map_err(|_| RecoveryLaunchError::Channel(RecoveryChannelError::TranscriptFailure))?;
    let child_nonce = child_hello.child_nonce();
    let finish = encode_recovery_parent_finish(&request, &parent_nonce, &child_nonce)
        .map_err(|_| RecoveryLaunchError::InvalidRequest)?;
    let binding = RecoveryResponseBinding::arm_from_held_helper(
        helper,
        &held_process,
        request,
        stage,
        display_link,
        expires_at,
        *parent_nonce,
        child_nonce,
    )
    .map_err(|error| match error {
        RecoveryChannelError::DeadlineElapsed => RecoveryLaunchError::DeadlineElapsed,
        _ => RecoveryLaunchError::Channel(error),
    })?;
    writer
        .write_all(&finish, expires_at)
        .map_err(map_setup_pipe_error)?;
    Ok((held_process, response_reader, binding))
}

#[cfg(windows)]
fn require_recovery_frontend(helper: &VerifiedHelper) -> Result<(), RecoveryLaunchError> {
    if helper.is_secret_input_frontend() {
        Ok(())
    } else {
        Err(RecoveryLaunchError::WrongHelperRole)
    }
}

#[cfg(windows)]
fn map_setup_pipe_error(error: PipeError) -> RecoveryLaunchError {
    if matches!(error, PipeError::DeadlineElapsed) {
        RecoveryLaunchError::DeadlineElapsed
    } else {
        RecoveryLaunchError::Pipe(error)
    }
}

#[cfg(windows)]
fn clamped_deadline(requested: Duration) -> Result<Instant, RecoveryLaunchError> {
    if requested.is_zero() {
        return Err(RecoveryLaunchError::DeadlineElapsed);
    }
    Instant::now()
        .checked_add(requested.min(MAX_RECOVERY_UI_DURATION))
        .ok_or(RecoveryLaunchError::DeadlineElapsed)
}

#[cfg(windows)]
fn clamped_deadline_capped(
    requested: Duration,
    original_display_expiry: Instant,
) -> Result<Instant, RecoveryLaunchError> {
    if deadline_elapsed(original_display_expiry) {
        return Err(RecoveryLaunchError::DeadlineElapsed);
    }
    let requested_expiry = clamped_deadline(requested)?;
    Ok(requested_expiry.min(original_display_expiry))
}

struct RecoveryResponseBinding {
    bound_identity: TranscriptIdentity,
    request: RecoveryRequest,
    stage: RecoveryStage,
    expected_request_hash: [u8; 32],
    display_link: Option<DisplayLink>,
    expires_at: Instant,
    parent_nonce: Zeroizing<[u8; NONCE_BYTES]>,
    child_nonce: Zeroizing<[u8; NONCE_BYTES]>,
}

impl RecoveryResponseBinding {
    #[cfg(windows)]
    #[allow(clippy::too_many_arguments)]
    fn arm_from_held_helper(
        verified_helper: &VerifiedHelper,
        launched_helper: &LaunchedHelper,
        request: RecoveryRequest,
        stage: RecoveryStage,
        display_link: Option<DisplayLink>,
        expires_at: Instant,
        parent_nonce: [u8; NONCE_BYTES],
        child_nonce: [u8; NONCE_BYTES],
    ) -> Result<Self, RecoveryChannelError> {
        if !verified_helper.is_secret_input_frontend() {
            return Err(RecoveryChannelError::IdentityMismatch);
        }
        let identity = launched_helper.identity();
        if identity.helper_file() != verified_helper.identity()
            || identity.helper_manifest_digest() != verified_helper.manifest_digest()
            || !launched_helper.is_held_in_job()
        {
            return Err(RecoveryChannelError::IdentityMismatch);
        }
        Self::arm_with_challenges(
            TranscriptIdentity::from_held(identity),
            request,
            stage,
            display_link,
            expires_at,
            parent_nonce,
            child_nonce,
        )
    }

    #[cfg(test)]
    fn arm(
        bound_identity: TranscriptIdentity,
        request: RecoveryRequest,
        stage: RecoveryStage,
        display_link: Option<DisplayLink>,
        expires_at: Instant,
    ) -> Result<Self, RecoveryChannelError> {
        let mut parent_nonce = Zeroizing::new([0_u8; NONCE_BYTES]);
        getrandom::fill(&mut *parent_nonce).map_err(|_| RecoveryChannelError::TranscriptFailure)?;
        let mut child_nonce = Zeroizing::new([0_u8; NONCE_BYTES]);
        getrandom::fill(&mut *child_nonce).map_err(|_| RecoveryChannelError::TranscriptFailure)?;
        Self::arm_with_challenges(
            bound_identity,
            request,
            stage,
            display_link,
            expires_at,
            *parent_nonce,
            *child_nonce,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn arm_with_challenges(
        bound_identity: TranscriptIdentity,
        request: RecoveryRequest,
        stage: RecoveryStage,
        display_link: Option<DisplayLink>,
        expires_at: Instant,
        parent_nonce: [u8; NONCE_BYTES],
        child_nonce: [u8; NONCE_BYTES],
    ) -> Result<Self, RecoveryChannelError> {
        validate_request_stage(&request, stage)?;
        validate_display_link(
            stage,
            &bound_identity,
            &request,
            display_link.as_ref(),
            expires_at,
        )?;
        if deadline_elapsed(expires_at) {
            return Err(RecoveryChannelError::DeadlineElapsed);
        }
        if is_all_zero(&parent_nonce) || is_all_zero(&child_nonce) {
            return Err(RecoveryChannelError::TranscriptFailure);
        }
        let expected_request_hash = request_hash(&request, stage)?;
        Ok(Self {
            bound_identity,
            request,
            stage,
            expected_request_hash,
            display_link,
            expires_at,
            parent_nonce: Zeroizing::new(parent_nonce),
            child_nonce: Zeroizing::new(child_nonce),
        })
    }

    #[cfg(windows)]
    fn receive_from_concrete(
        self,
        response_reader: SecretResponseReader,
        actual_identity: TranscriptIdentity,
    ) -> Result<DecodedRecovery, RecoveryChannelError> {
        self.preflight(actual_identity)?;
        let response = response_reader
            .read_bounded_to_end(MAX_AUTHENTICATED_RECOVERY_RESPONSE_BYTES, self.expires_at)
            .map_err(map_response_pipe_error)?;
        self.finish(response)
    }

    fn preflight(&self, actual_identity: TranscriptIdentity) -> Result<(), RecoveryChannelError> {
        if actual_identity != self.bound_identity {
            return Err(RecoveryChannelError::IdentityMismatch);
        }
        if deadline_elapsed(self.expires_at) {
            return Err(RecoveryChannelError::DeadlineElapsed);
        }
        if is_all_zero(&*self.parent_nonce) || is_all_zero(&*self.child_nonce) {
            return Err(RecoveryChannelError::TranscriptFailure);
        }
        validate_display_link(
            self.stage,
            &self.bound_identity,
            &self.request,
            self.display_link.as_ref(),
            self.expires_at,
        )?;
        let retained_hash = request_hash(&self.request, self.stage)?;
        if !bool::from(retained_hash.ct_eq(&self.expected_request_hash)) {
            return Err(RecoveryChannelError::RequestBindingMismatch);
        }
        Ok(())
    }

    fn finish(self, response: Zeroizing<Vec<u8>>) -> Result<DecodedRecovery, RecoveryChannelError> {
        if deadline_elapsed(self.expires_at) {
            return Err(RecoveryChannelError::DeadlineElapsed);
        }
        let response_length = response.len();
        let outcome = decode_authenticated_recovery_outcome(
            &self.request,
            &self.parent_nonce,
            &self.child_nonce,
            response,
        )
        .map_err(map_decode_error)?;
        if deadline_elapsed(self.expires_at) {
            return Err(RecoveryChannelError::DeadlineElapsed);
        }
        let disposition = match &outcome {
            RecoveryOutcome::DisplayCancelled | RecoveryOutcome::ConfirmCancelled => 0,
            RecoveryOutcome::DisplayAcknowledged | RecoveryOutcome::Confirmed(_) => 1,
        };
        let transcript = transcript_hash(
            self.stage,
            self.bound_identity,
            &self.request,
            self.expected_request_hash,
            self.display_link.as_ref(),
            self.expires_at,
            disposition,
            response_length,
            &self.parent_nonce,
            &self.child_nonce,
        )?;
        match (self.stage, outcome, self.display_link) {
            (RecoveryStage::Display, RecoveryOutcome::DisplayAcknowledged, None) => {
                Ok(DecodedRecovery::DisplayAcknowledged(DisplayEvidence {
                    identity: self.bound_identity,
                    request_hash: self.expected_request_hash,
                    transcript,
                }))
            }
            (RecoveryStage::Display, RecoveryOutcome::DisplayCancelled, None) => {
                Ok(DecodedRecovery::DisplayCancelled)
            }
            (RecoveryStage::Confirm, RecoveryOutcome::Confirmed(input), Some(display_link)) => {
                Ok(DecodedRecovery::Confirmed {
                    input,
                    request_hash: self.expected_request_hash,
                    transcript,
                    display_transcript: display_link.transcript,
                    expires_at: self.expires_at,
                })
            }
            (RecoveryStage::Confirm, RecoveryOutcome::ConfirmCancelled, Some(_)) => {
                Ok(DecodedRecovery::ConfirmCancelled)
            }
            _ => Err(RecoveryChannelError::MalformedResponse),
        }
    }
}

impl fmt::Debug for RecoveryResponseBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryResponseBinding")
            .field("bound_identity", &"[REDACTED]")
            .field("request", &"[REDACTED TYPED REQUEST]")
            .field("stage", &self.stage)
            .field("expected_request_hash", &"[SHA-256]")
            .field("display_link", &"[REDACTED OPTIONAL RECEIPT]")
            .field("expires_at", &"[MONOTONIC DEADLINE]")
            .field("parent_nonce", &"[REDACTED]")
            .field("child_nonce", &"[REDACTED]")
            .finish()
    }
}

enum DecodedRecovery {
    DisplayAcknowledged(DisplayEvidence),
    DisplayCancelled,
    Confirmed {
        input: RecoveryConfirmationInput,
        request_hash: [u8; 32],
        transcript: [u8; 32],
        display_transcript: [u8; 32],
        expires_at: Instant,
    },
    ConfirmCancelled,
}

struct DisplayEvidence {
    identity: TranscriptIdentity,
    request_hash: [u8; 32],
    transcript: [u8; 32],
}

struct DisplayLink {
    ceremony_id: RecoveryCeremonyId,
    identity: TranscriptIdentity,
    request_hash: [u8; 32],
    transcript: [u8; 32],
    expires_at: Instant,
}

impl fmt::Debug for DisplayLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DisplayLink([REDACTED ONE-SHOT LINK])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct TranscriptIdentity {
    process_id: u32,
    helper_file: FileIdentity,
    helper_manifest_digest: [u8; 32],
    profile_revision: u32,
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

    #[cfg(windows)]
    fn same_artifact_as_verified(self, helper: &VerifiedHelper) -> bool {
        self.helper_file == helper.identity()
            && self.helper_manifest_digest == helper.manifest_digest()
    }

    fn same_artifact_and_profile(self, other: Self) -> bool {
        self.helper_file == other.helper_file
            && self.helper_manifest_digest == other.helper_manifest_digest
            && self.profile_revision == other.profile_revision
    }
}

impl fmt::Debug for TranscriptIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TranscriptIdentity([REDACTED HELD PROCESS/IMAGE/PROFILE])")
    }
}

fn validate_request_stage(
    request: &RecoveryRequest,
    stage: RecoveryStage,
) -> Result<(), RecoveryChannelError> {
    if matches!(
        (request, stage),
        (RecoveryRequest::Display(_), RecoveryStage::Display)
            | (RecoveryRequest::Confirm(_), RecoveryStage::Confirm)
    ) {
        Ok(())
    } else {
        Err(RecoveryChannelError::RequestBindingMismatch)
    }
}

fn validate_display_link(
    stage: RecoveryStage,
    identity: &TranscriptIdentity,
    request: &RecoveryRequest,
    display_link: Option<&DisplayLink>,
    expires_at: Instant,
) -> Result<(), RecoveryChannelError> {
    if let (RecoveryStage::Confirm, Some(link)) = (stage, display_link)
        && (deadline_elapsed(link.expires_at) || expires_at > link.expires_at)
    {
        return Err(RecoveryChannelError::DeadlineElapsed);
    }
    match (stage, display_link) {
        (RecoveryStage::Display, None) => Ok(()),
        (RecoveryStage::Confirm, Some(link))
            if link.identity.same_artifact_and_profile(*identity)
                && request_matches_ceremony(request, &link.ceremony_id)
                && !is_all_zero(&link.request_hash)
                && !is_all_zero(&link.transcript) =>
        {
            Ok(())
        }
        _ => Err(RecoveryChannelError::IdentityMismatch),
    }
}

fn request_matches_ceremony(request: &RecoveryRequest, expected: &RecoveryCeremonyId) -> bool {
    match request {
        RecoveryRequest::Display(request) => request.matches_ceremony(expected),
        RecoveryRequest::Confirm(request) => request.matches_ceremony(expected),
    }
}

fn request_hash(
    request: &RecoveryRequest,
    stage: RecoveryStage,
) -> Result<[u8; 32], RecoveryChannelError> {
    validate_request_stage(request, stage)?;
    let encoded = encode_request(request).map_err(map_decode_error)?;
    let mut hash = Sha256::new();
    hash.update(stage.request_domain());
    hash.update([stage.tag()]);
    hash.update(
        u32::try_from(encoded.len())
            .map_err(|_| RecoveryChannelError::TranscriptFailure)?
            .to_be_bytes(),
    );
    hash.update(&*encoded);
    let digest: [u8; 32] = hash.finalize().into();
    if is_all_zero(&digest) {
        Err(RecoveryChannelError::TranscriptFailure)
    } else {
        Ok(digest)
    }
}

#[allow(clippy::too_many_arguments)]
fn transcript_hash(
    stage: RecoveryStage,
    identity: TranscriptIdentity,
    request: &RecoveryRequest,
    request_hash: [u8; 32],
    display_link: Option<&DisplayLink>,
    expires_at: Instant,
    disposition: u8,
    response_length: usize,
    parent_nonce: &[u8; NONCE_BYTES],
    child_nonce: &[u8; NONCE_BYTES],
) -> Result<[u8; 32], RecoveryChannelError> {
    if !matches!(disposition, 0 | 1)
        || is_all_zero(&request_hash)
        || is_all_zero(parent_nonce)
        || is_all_zero(child_nonce)
    {
        return Err(RecoveryChannelError::TranscriptFailure);
    }
    validate_display_link(stage, &identity, request, display_link, expires_at)?;
    let mut hash = Sha256::new();
    hash.update(stage.transcript_domain());
    hash.update([stage.tag()]);
    hash.update(identity.process_id.to_be_bytes());
    hash.update(identity.helper_file.volume_serial_number.to_be_bytes());
    hash.update(identity.helper_file.file_index.to_be_bytes());
    hash.update(identity.helper_file.file_size.to_be_bytes());
    hash.update(identity.helper_manifest_digest);
    hash.update(identity.profile_revision.to_be_bytes());
    hash.update(request_hash);
    if let Some(link) = display_link {
        hash.update([1]);
        hash.update(link.request_hash);
        hash.update(link.transcript);
    } else {
        hash.update([0]);
        hash.update([0_u8; 64]);
    }
    hash.update([disposition]);
    hash.update(
        u32::try_from(response_length)
            .map_err(|_| RecoveryChannelError::TranscriptFailure)?
            .to_be_bytes(),
    );
    hash.update(parent_nonce);
    hash.update(child_nonce);
    let digest: [u8; 32] = hash.finalize().into();
    if is_all_zero(&digest) {
        Err(RecoveryChannelError::TranscriptFailure)
    } else {
        Ok(digest)
    }
}

fn map_decode_error(_error: SecretInputError) -> RecoveryChannelError {
    RecoveryChannelError::MalformedResponse
}

#[cfg(windows)]
fn map_response_pipe_error(error: PipeError) -> RecoveryChannelError {
    match error {
        PipeError::DeadlineElapsed => RecoveryChannelError::DeadlineElapsed,
        PipeError::UnexpectedEnd | PipeError::TrailingData | PipeError::FrameTooLarge => {
            RecoveryChannelError::MalformedResponse
        }
        _ => RecoveryChannelError::ChannelFailure,
    }
}

#[cfg(windows)]
fn map_termination_error(error: LaunchError) -> RecoveryChannelError {
    if matches!(error, LaunchError::TerminationDeadlineElapsed) {
        RecoveryChannelError::DeadlineElapsed
    } else {
        RecoveryChannelError::ChannelFailure
    }
}

fn deadline_elapsed(expires_at: Instant) -> bool {
    Instant::now().checked_duration_since(expires_at).is_some()
}

fn is_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use secret_input_ui::{
        bootstrap::NONCE_BYTES,
        recovery::{
            RecoveryCeremonyId, RecoveryConfirmRequest, RecoveryConfirmationInput,
            RecoveryDisplayRequest, RecoveryOutcome, RecoveryRequest, RecoveryWordCount,
            encode_outcome, encode_request,
        },
    };
    use sha2::{Digest as _, Sha256};
    use zeroize::Zeroizing;

    use super::{
        DecodedRecovery, DisplayLink, RecoveryChannelError, RecoveryResponseBinding, RecoveryStage,
        TranscriptIdentity, VerifiedRecoveryConfirmation,
    };
    #[cfg(windows)]
    use super::{
        MAX_RECOVERY_UI_DURATION, RecoveryDisplayAcknowledgement, RecoveryLaunchError,
        clamped_deadline, clamped_deadline_capped, launch_recovery_confirm_frontend,
        launch_recovery_display_frontend,
    };
    use crate::helper::FileIdentity;
    #[cfg(windows)]
    use crate::{
        attestation::ReleaseAttestation,
        helper::VerifiedHelper,
        launch::{LaunchError, NoNetworkLpacProfile, RestrictedLauncher},
    };

    const TEST_PARENT_NONCE: [u8; NONCE_BYTES] = [0x31; NONCE_BYTES];
    const TEST_CHILD_NONCE: [u8; NONCE_BYTES] = [0x52; NONCE_BYTES];

    fn future_deadline() -> Result<Instant, Box<dyn std::error::Error>> {
        Instant::now()
            .checked_add(Duration::from_secs(30))
            .ok_or_else(|| "monotonic deadline overflow".into())
    }

    const fn identity(process_id: u32) -> TranscriptIdentity {
        TranscriptIdentity {
            process_id,
            helper_file: FileIdentity {
                volume_serial_number: 81,
                file_index: 82,
                file_size: 83,
            },
            helper_manifest_digest: [84; 32],
            profile_revision: 1,
        }
    }

    fn ceremony_id() -> Result<RecoveryCeremonyId, RecoveryChannelError> {
        RecoveryCeremonyId::generate().map_err(|_| RecoveryChannelError::TranscriptFailure)
    }

    fn different_ceremony_id(
        other: &RecoveryCeremonyId,
    ) -> Result<RecoveryCeremonyId, RecoveryChannelError> {
        loop {
            let candidate = ceremony_id()?;
            if !candidate.matches(other) {
                return Ok(candidate);
            }
        }
    }

    fn display_request_for(
        ceremony_id: &RecoveryCeremonyId,
    ) -> Result<RecoveryRequest, RecoveryChannelError> {
        RecoveryDisplayRequest::new(
            ceremony_id,
            Zeroizing::new("amber cedar moon river sage".to_owned()),
            RecoveryWordCount::Twelve,
            [0xa5; 20],
            Zeroizing::new(["abandon"; 12].join(" ")),
        )
        .map(RecoveryRequest::Display)
        .map_err(|_| RecoveryChannelError::MalformedResponse)
    }

    fn display_request() -> Result<RecoveryRequest, RecoveryChannelError> {
        let ceremony_id = ceremony_id()?;
        display_request_for(&ceremony_id)
    }

    fn confirm_request_for(
        ceremony_id: &RecoveryCeremonyId,
        positions: [u8; 4],
    ) -> Result<RecoveryRequest, RecoveryChannelError> {
        RecoveryConfirmRequest::new(
            ceremony_id,
            Zeroizing::new("amber cedar moon river sage".to_owned()),
            RecoveryWordCount::Twelve,
            positions,
        )
        .map(RecoveryRequest::Confirm)
        .map_err(|_| RecoveryChannelError::MalformedResponse)
    }

    fn confirm_request(positions: [u8; 4]) -> Result<RecoveryRequest, RecoveryChannelError> {
        let ceremony_id = ceremony_id()?;
        confirm_request_for(&ceremony_id, positions)
    }

    fn confirmation_input() -> Result<RecoveryConfirmationInput, RecoveryChannelError> {
        RecoveryConfirmationInput::new(
            [
                Zeroizing::new("abandon".to_owned()),
                Zeroizing::new("ability".to_owned()),
                Zeroizing::new("able".to_owned()),
                Zeroizing::new("about".to_owned()),
            ],
            [0xb6; 20],
        )
        .map_err(|_| RecoveryChannelError::MalformedResponse)
    }

    fn display_link(ceremony_id: RecoveryCeremonyId, expires_at: Instant) -> DisplayLink {
        DisplayLink {
            ceremony_id,
            identity: identity(101),
            request_hash: [0xc1; 32],
            transcript: [0xd2; 32],
            expires_at,
        }
    }

    fn bootstrap_request_hash(stage: RecoveryStage, request_bytes: &[u8]) -> [u8; 32] {
        let domain: &[u8] = match stage {
            RecoveryStage::Display => b"your-wallet/recovery-display-bootstrap-request/v1\0",
            RecoveryStage::Confirm => b"your-wallet/recovery-confirm-bootstrap-request/v1\0",
        };
        let mut hash = Sha256::new();
        hash.update(domain);
        hash.update(
            u32::try_from(request_bytes.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        hash.update(request_bytes);
        hash.finalize().into()
    }

    fn authenticated_response(
        request: &RecoveryRequest,
        stage: RecoveryStage,
        parent_nonce: &[u8; NONCE_BYTES],
        child_nonce: &[u8; NONCE_BYTES],
        outcome: &RecoveryOutcome,
    ) -> Result<Zeroizing<Vec<u8>>, RecoveryChannelError> {
        let inner = encode_outcome(request, outcome)
            .map_err(|_| RecoveryChannelError::MalformedResponse)?;
        let request_bytes =
            encode_request(request).map_err(|_| RecoveryChannelError::MalformedResponse)?;
        let total = 110_usize
            .checked_add(inner.len())
            .ok_or(RecoveryChannelError::TranscriptFailure)?;
        let mut output = Zeroizing::new(Vec::with_capacity(total));
        output.extend_from_slice(match stage {
            RecoveryStage::Display => b"YWRDOR01",
            RecoveryStage::Confirm => b"YWRCOR01",
        });
        output.extend_from_slice(&1_u16.to_be_bytes());
        output.extend_from_slice(parent_nonce);
        output.extend_from_slice(child_nonce);
        output.extend_from_slice(&bootstrap_request_hash(stage, &request_bytes));
        output.extend_from_slice(
            &u32::try_from(inner.len())
                .map_err(|_| RecoveryChannelError::TranscriptFailure)?
                .to_be_bytes(),
        );
        output.extend_from_slice(&inner);
        Ok(output)
    }

    fn binding(
        request: RecoveryRequest,
        stage: RecoveryStage,
        link: Option<DisplayLink>,
        parent_nonce: [u8; NONCE_BYTES],
        child_nonce: [u8; NONCE_BYTES],
        expires_at: Instant,
    ) -> Result<RecoveryResponseBinding, RecoveryChannelError> {
        RecoveryResponseBinding::arm_with_challenges(
            identity(102),
            request,
            stage,
            link,
            expires_at,
            parent_nonce,
            child_nonce,
        )
    }

    #[test]
    fn display_and_confirm_use_fresh_nonzero_challenges_and_distinct_transcripts()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = RecoveryResponseBinding::arm(
            identity(102),
            display_request()?,
            RecoveryStage::Display,
            None,
            future_deadline()?,
        )?;
        let second = RecoveryResponseBinding::arm(
            identity(102),
            display_request()?,
            RecoveryStage::Display,
            None,
            future_deadline()?,
        )?;
        assert!(first.parent_nonce.iter().any(|byte| *byte != 0));
        assert!(first.child_nonce.iter().any(|byte| *byte != 0));
        assert_ne!(*first.parent_nonce, *second.parent_nonce);
        assert_ne!(*first.child_nonce, *second.child_nonce);

        let first_response = authenticated_response(
            &first.request,
            RecoveryStage::Display,
            &first.parent_nonce,
            &first.child_nonce,
            &RecoveryOutcome::DisplayAcknowledged,
        )?;
        let second_response = authenticated_response(
            &second.request,
            RecoveryStage::Display,
            &second.parent_nonce,
            &second.child_nonce,
            &RecoveryOutcome::DisplayAcknowledged,
        )?;
        first.preflight(identity(102))?;
        second.preflight(identity(102))?;
        let DecodedRecovery::DisplayAcknowledged(first_link) = first.finish(first_response)? else {
            return Err("display acknowledgement changed stage".into());
        };
        let DecodedRecovery::DisplayAcknowledged(second_link) = second.finish(second_response)?
        else {
            return Err("display acknowledgement changed stage".into());
        };
        assert_ne!(first_link.transcript, second_link.transcript);
        Ok(())
    }

    #[test]
    fn exact_stage_request_nonce_and_eof_binding_rejects_swaps_and_replay()
    -> Result<(), Box<dyn std::error::Error>> {
        let original_id = ceremony_id()?;
        let original = confirm_request_for(&original_id, [1, 4, 8, 12])?;
        let changed = confirm_request_for(&original_id, [2, 5, 9, 11])?;
        let valid = authenticated_response(
            &original,
            RecoveryStage::Confirm,
            &TEST_PARENT_NONCE,
            &TEST_CHILD_NONCE,
            &RecoveryOutcome::Confirmed(confirmation_input()?),
        )?;

        let changed_expiry = future_deadline()?;
        let changed_request = binding(
            changed,
            RecoveryStage::Confirm,
            Some(display_link(original_id, changed_expiry)),
            TEST_PARENT_NONCE,
            TEST_CHILD_NONCE,
            changed_expiry,
        )?;
        changed_request.preflight(identity(102))?;
        assert!(matches!(
            changed_request.finish(Zeroizing::new(valid.to_vec())),
            Err(RecoveryChannelError::MalformedResponse)
        ));

        let replay_request = display_request()?;
        let replay_bytes = authenticated_response(
            &replay_request,
            RecoveryStage::Display,
            &TEST_PARENT_NONCE,
            &TEST_CHILD_NONCE,
            &RecoveryOutcome::DisplayAcknowledged,
        )?;
        let replay = binding(
            replay_request,
            RecoveryStage::Display,
            None,
            [0x72; NONCE_BYTES],
            TEST_CHILD_NONCE,
            future_deadline()?,
        )?;
        replay.preflight(identity(102))?;
        assert!(matches!(
            replay.finish(replay_bytes),
            Err(RecoveryChannelError::MalformedResponse)
        ));

        let trailing_id = ceremony_id()?;
        let trailing_request = confirm_request_for(&trailing_id, [1, 4, 8, 12])?;
        let mut trailing = authenticated_response(
            &trailing_request,
            RecoveryStage::Confirm,
            &TEST_PARENT_NONCE,
            &TEST_CHILD_NONCE,
            &RecoveryOutcome::Confirmed(confirmation_input()?),
        )?
        .to_vec();
        trailing.push(0);
        let trailing_expiry = future_deadline()?;
        let trailing_binding = binding(
            trailing_request,
            RecoveryStage::Confirm,
            Some(display_link(trailing_id, trailing_expiry)),
            TEST_PARENT_NONCE,
            TEST_CHILD_NONCE,
            trailing_expiry,
        )?;
        trailing_binding.preflight(identity(102))?;
        assert!(matches!(
            trailing_binding.finish(Zeroizing::new(trailing)),
            Err(RecoveryChannelError::MalformedResponse)
        ));
        Ok(())
    }

    #[test]
    fn cross_stage_response_and_missing_display_receipt_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let display = display_request()?;
        let display_bytes = authenticated_response(
            &display,
            RecoveryStage::Display,
            &TEST_PARENT_NONCE,
            &TEST_CHILD_NONCE,
            &RecoveryOutcome::DisplayAcknowledged,
        )?;
        let confirm_id = ceremony_id()?;
        let staged_confirm_request = confirm_request_for(&confirm_id, [1, 4, 8, 12])?;
        let confirm_expiry = future_deadline()?;
        let confirm = binding(
            staged_confirm_request,
            RecoveryStage::Confirm,
            Some(display_link(confirm_id, confirm_expiry)),
            TEST_PARENT_NONCE,
            TEST_CHILD_NONCE,
            confirm_expiry,
        )?;
        confirm.preflight(identity(102))?;
        assert!(matches!(
            confirm.finish(display_bytes),
            Err(RecoveryChannelError::MalformedResponse)
        ));

        assert!(matches!(
            binding(
                confirm_request([1, 4, 8, 12])?,
                RecoveryStage::Confirm,
                None,
                TEST_PARENT_NONCE,
                TEST_CHILD_NONCE,
                future_deadline()?
            ),
            Err(RecoveryChannelError::IdentityMismatch)
        ));
        let impossible_link_id = ceremony_id()?;
        assert!(matches!(
            binding(
                display_request()?,
                RecoveryStage::Display,
                Some(display_link(impossible_link_id, future_deadline()?)),
                TEST_PARENT_NONCE,
                TEST_CHILD_NONCE,
                future_deadline()?
            ),
            Err(RecoveryChannelError::IdentityMismatch)
        ));
        Ok(())
    }

    #[test]
    fn identity_and_profile_mismatch_are_rejected_before_response_decode()
    -> Result<(), Box<dyn std::error::Error>> {
        let channel = binding(
            display_request()?,
            RecoveryStage::Display,
            None,
            TEST_PARENT_NONCE,
            TEST_CHILD_NONCE,
            future_deadline()?,
        )?;
        assert_eq!(
            channel.preflight(identity(999)),
            Err(RecoveryChannelError::IdentityMismatch)
        );

        let wrong_profile_id = ceremony_id()?;
        let wrong_profile_request = confirm_request_for(&wrong_profile_id, [1, 4, 8, 12])?;
        let wrong_profile_expiry = future_deadline()?;
        let mut wrong_profile_link = display_link(wrong_profile_id, wrong_profile_expiry);
        wrong_profile_link.identity.profile_revision = 2;
        assert!(matches!(
            binding(
                wrong_profile_request,
                RecoveryStage::Confirm,
                Some(wrong_profile_link),
                TEST_PARENT_NONCE,
                TEST_CHILD_NONCE,
                wrong_profile_expiry
            ),
            Err(RecoveryChannelError::IdentityMismatch)
        ));
        Ok(())
    }

    #[test]
    fn deadline_is_checked_before_and_after_response_read() -> Result<(), Box<dyn std::error::Error>>
    {
        let expired = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .ok_or("monotonic clock cannot represent expired test deadline")?;
        assert!(matches!(
            binding(
                display_request()?,
                RecoveryStage::Display,
                None,
                TEST_PARENT_NONCE,
                TEST_CHILD_NONCE,
                expired
            ),
            Err(RecoveryChannelError::DeadlineElapsed)
        ));

        let short = Instant::now()
            .checked_add(Duration::from_millis(5))
            .ok_or("monotonic clock cannot represent short test deadline")?;
        let request = display_request()?;
        let response = authenticated_response(
            &request,
            RecoveryStage::Display,
            &TEST_PARENT_NONCE,
            &TEST_CHILD_NONCE,
            &RecoveryOutcome::DisplayCancelled,
        )?;
        let channel = binding(
            request,
            RecoveryStage::Display,
            None,
            TEST_PARENT_NONCE,
            TEST_CHILD_NONCE,
            short,
        )?;
        channel.preflight(identity(102))?;
        std::thread::sleep(Duration::from_millis(10));
        assert!(matches!(
            channel.finish(response),
            Err(RecoveryChannelError::DeadlineElapsed)
        ));
        Ok(())
    }

    #[test]
    fn confirmed_value_is_zeroizing_one_shot_and_debug_redacted()
    -> Result<(), Box<dyn std::error::Error>> {
        let proof = VerifiedRecoveryConfirmation {
            input: confirmation_input()?,
            request_hash: [0x11; 32],
            transcript: [0x22; 32],
            display_transcript: [0x33; 32],
            expires_at: future_deadline()?,
        };
        assert_eq!(
            format!("{proof:?}"),
            "VerifiedRecoveryConfirmation([REDACTED ONE-SHOT PROOF])"
        );
        let (words, address) = proof.into_parts()?;
        assert_eq!(words[0].as_str(), "abandon");
        assert_eq!(address, [0xb6; 20]);
        Ok(())
    }

    #[test]
    fn confirmation_request_never_carries_display_mnemonic_or_expected_address()
    -> Result<(), Box<dyn std::error::Error>> {
        let encoded = encode_request(&confirm_request([1, 4, 8, 12])?)
            .map_err(|_| RecoveryChannelError::MalformedResponse)?;
        assert!(
            !encoded
                .windows(b"abandon".len())
                .any(|part| part == b"abandon")
        );
        assert!(!encoded.windows(20).any(|part| part == [0xa5; 20]));
        Ok(())
    }

    #[test]
    fn binding_debug_contains_no_request_nonce_or_identity_material()
    -> Result<(), Box<dyn std::error::Error>> {
        let binding = binding(
            display_request()?,
            RecoveryStage::Display,
            None,
            TEST_PARENT_NONCE,
            TEST_CHILD_NONCE,
            future_deadline()?,
        )?;
        let debug = format!("{binding:?}");
        assert!(debug.contains("[REDACTED"));
        assert!(!debug.contains("amber cedar"));
        assert!(!debug.contains("49, 49"));
        assert!(!debug.contains("82, 82"));
        assert!(!debug.contains("process_id: 102"));
        Ok(())
    }

    #[cfg(windows)]
    fn display_dto() -> Result<(RecoveryCeremonyId, RecoveryDisplayRequest), RecoveryChannelError> {
        let ceremony_id = ceremony_id()?;
        match display_request_for(&ceremony_id)? {
            RecoveryRequest::Display(request) => Ok((ceremony_id, request)),
            RecoveryRequest::Confirm(_) => Err(RecoveryChannelError::MalformedResponse),
        }
    }

    #[cfg(windows)]
    fn confirm_dto_for(
        ceremony_id: &RecoveryCeremonyId,
    ) -> Result<RecoveryConfirmRequest, RecoveryChannelError> {
        match confirm_request_for(ceremony_id, [1, 4, 8, 12])? {
            RecoveryRequest::Confirm(request) => Ok(request),
            RecoveryRequest::Display(_) => Err(RecoveryChannelError::MalformedResponse),
        }
    }

    #[cfg(windows)]
    fn acknowledgement(
        helper: &VerifiedHelper,
        ceremony_id: RecoveryCeremonyId,
        expires_at: Instant,
    ) -> RecoveryDisplayAcknowledgement {
        RecoveryDisplayAcknowledgement {
            link: DisplayLink {
                ceremony_id,
                identity: TranscriptIdentity {
                    process_id: 91,
                    helper_file: helper.identity(),
                    helper_manifest_digest: helper.manifest_digest(),
                    profile_revision: NoNetworkLpacProfile::v1().revision(),
                },
                request_hash: [0x44; 32],
                transcript: [0x55; 32],
                expires_at,
            },
        }
    }

    #[cfg(windows)]
    #[test]
    fn clamped_deadline_never_exceeds_the_two_minute_ui_window()
    -> Result<(), Box<dyn std::error::Error>> {
        let deadline = clamped_deadline(Duration::from_hours(24))?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("deadline unexpectedly elapsed")?;
        assert!(remaining <= MAX_RECOVERY_UI_DURATION);
        assert!(remaining > Duration::from_secs(119));
        assert!(matches!(
            clamped_deadline(Duration::ZERO),
            Err(RecoveryLaunchError::DeadlineElapsed)
        ));

        let original = Instant::now()
            .checked_add(Duration::from_millis(50))
            .ok_or("deadline unexpectedly overflowed")?;
        let capped = clamped_deadline_capped(Duration::from_hours(24), original)?;
        assert_eq!(capped, original);

        let receipt_expiry = Instant::now()
            .checked_add(Duration::from_secs(30))
            .ok_or("deadline unexpectedly overflowed")?;
        let extended_expiry = receipt_expiry
            .checked_add(Duration::from_secs(1))
            .ok_or("deadline unexpectedly overflowed")?;
        let confirm_id = ceremony_id()?;
        let confirm = confirm_request_for(&confirm_id, [1, 4, 8, 12])?;
        assert!(matches!(
            binding(
                confirm,
                RecoveryStage::Confirm,
                Some(display_link(confirm_id, receipt_expiry)),
                TEST_PARENT_NONCE,
                TEST_CHILD_NONCE,
                extended_expiry
            ),
            Err(RecoveryChannelError::DeadlineElapsed)
        ));
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn high_level_display_rejects_wrong_role_without_launching_a_process()
    -> Result<(), Box<dyn std::error::Error>> {
        let wrong_role = VerifiedHelper::for_approval_channel_test(true)?;
        let launcher =
            RestrictedLauncher::new(ReleaseAttestation::default(), NoNetworkLpacProfile::v1());
        let (ceremony_id, request) = display_dto()?;
        assert!(matches!(
            launch_recovery_display_frontend(
                launcher,
                &wrong_role,
                ceremony_id,
                request,
                Duration::from_secs(30)
            ),
            Err(RecoveryLaunchError::WrongHelperRole)
        ));
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn display_and_confirmation_reject_cross_ceremony_ids_before_launch()
    -> Result<(), Box<dyn std::error::Error>> {
        let helper = VerifiedHelper::for_secret_input_channel_test()?;
        let launcher =
            RestrictedLauncher::new(ReleaseAttestation::default(), NoNetworkLpacProfile::v1());

        let supplied_display_id = ceremony_id()?;
        let request_display_id = different_ceremony_id(&supplied_display_id)?;
        let display_request = match display_request_for(&request_display_id)? {
            RecoveryRequest::Display(request) => request,
            RecoveryRequest::Confirm(_) => return Err("display fixture changed stage".into()),
        };
        assert!(matches!(
            launch_recovery_display_frontend(
                launcher,
                &helper,
                supplied_display_id,
                display_request,
                Duration::from_secs(30)
            ),
            Err(RecoveryLaunchError::InvalidRequest)
        ));

        let display_id = ceremony_id()?;
        let confirmation_id = different_ceremony_id(&display_id)?;
        let confirmation_request = confirm_dto_for(&confirmation_id)?;
        let receipt = acknowledgement(&helper, display_id, future_deadline()?);
        assert!(matches!(
            launch_recovery_confirm_frontend(
                receipt,
                launcher,
                &helper,
                confirmation_request,
                Duration::from_secs(30)
            ),
            Err(RecoveryLaunchError::DisplayReceiptMismatch)
        ));
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn stale_display_receipt_is_rejected_before_confirmation_launch()
    -> Result<(), Box<dyn std::error::Error>> {
        let helper = VerifiedHelper::for_secret_input_channel_test()?;
        let launcher =
            RestrictedLauncher::new(ReleaseAttestation::default(), NoNetworkLpacProfile::v1());
        let ceremony_id = ceremony_id()?;
        let confirmation_request = confirm_dto_for(&ceremony_id)?;
        let expired = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .ok_or("monotonic clock cannot represent expired test deadline")?;
        let receipt = acknowledgement(&helper, ceremony_id, expired);
        assert!(matches!(
            launch_recovery_confirm_frontend(
                receipt,
                launcher,
                &helper,
                confirmation_request,
                Duration::from_secs(30)
            ),
            Err(RecoveryLaunchError::DeadlineElapsed)
        ));
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn compiled_release_gate_keeps_both_recovery_launches_headless_and_disabled()
    -> Result<(), Box<dyn std::error::Error>> {
        let helper = VerifiedHelper::for_secret_input_channel_test()?;
        let launcher =
            RestrictedLauncher::new(ReleaseAttestation::default(), NoNetworkLpacProfile::v1());
        let (display_id, display_request) = display_dto()?;
        assert!(matches!(
            launch_recovery_display_frontend(
                launcher,
                &helper,
                display_id,
                display_request,
                Duration::from_secs(30)
            ),
            Err(RecoveryLaunchError::Launch(LaunchError::ReleaseNotAttested))
        ));

        let confirm_id = ceremony_id()?;
        let confirm_request = confirm_dto_for(&confirm_id)?;
        let acknowledgement = acknowledgement(&helper, confirm_id, future_deadline()?);
        assert!(matches!(
            launch_recovery_confirm_frontend(
                acknowledgement,
                launcher,
                &helper,
                confirm_request,
                Duration::from_secs(30)
            ),
            Err(RecoveryLaunchError::Launch(LaunchError::ReleaseNotAttested))
        ));
        Ok(())
    }
}
