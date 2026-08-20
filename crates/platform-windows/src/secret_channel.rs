//! Authenticated, one-shot parent-side Secret Input response channel.
//!
//! The channel binds one validated [`SecretPrompt`] to one held, release-bound
//! Secret Input Frontend process and the exact private pipe ends it inherited.
//! The integrated high-level launcher requires the release-attested restricted
//! launcher and the exact manifest-derived Secret Input role. Callers cannot
//! supply readers, handles, process identifiers, or response bytes. Ordinary
//! builds remain unreachable because no compiled release policy exists.

use core::fmt;
use std::time::{Duration, Instant};

use secret_input_ui::{
    PromptKind, SecretInputError, SecretOutcome, SecretPrompt,
    bootstrap::{
        CHILD_HELLO_BYTES, MAX_AUTHENTICATED_RESPONSE_BYTES, NONCE_BYTES, ParentHello,
        decode_authenticated_outcome, decode_child_hello, encode_parent_finish,
        encode_parent_hello,
    },
    encode_prompt,
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

const PROMPT_DOMAIN: &[u8] = b"your-wallet/secret-input-prompt/v1";
const TRANSCRIPT_DOMAIN: &[u8] = b"your-wallet/secret-input-child-transcript/v1";
const CHANNEL_CHALLENGE_BYTES: usize = NONCE_BYTES;
const MAX_SECRET_INPUT_DURATION: Duration = Duration::from_mins(2);

/// Failure while arming or consuming the authenticated Secret Input channel.
///
/// Error variants deliberately contain no OS message, path, prompt phrase, or
/// secret-derived bytes, so formatting an error cannot disclose private input.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SecretInputChannelError {
    /// The verified manifest belongs to another helper role.
    #[error("verified helper is not the secret-input frontend")]
    WrongHelperRole,
    /// The held process does not match the identity branded into the channel.
    #[error("secret-input channel helper identity mismatch")]
    IdentityMismatch,
    /// The prompt cannot be encoded under the fixed Secret Input contract.
    #[error("secret-input prompt is invalid")]
    InvalidPrompt,
    /// The retained prompt no longer matches the exact prompt bound at arming.
    #[error("secret-input prompt binding mismatch")]
    PromptBindingMismatch,
    /// The response was not one exact bounded frame followed by EOF.
    #[error("malformed secret-input response")]
    MalformedResponse,
    /// Accepted input violates the exact minimum/maximum prompt bounds.
    #[error("secret input violates the bound prompt length")]
    PromptBoundsViolation,
    /// The trusted monotonic response deadline elapsed.
    #[error("secret-input response deadline elapsed")]
    DeadlineElapsed,
    /// The private response channel failed without exposing platform details.
    #[error("private secret-input response channel failed")]
    ChannelFailure,
    /// Secure challenge generation or transcript construction failed closed.
    #[error("secret-input channel transcript construction failed")]
    TranscriptFailure,
}

/// Failure before a concrete one-shot Secret Input helper/channel is armed.
///
#[cfg(windows)]
#[derive(Debug, Error)]
pub(crate) enum SecretInputLaunchError {
    /// The manifest-derived role was not exactly Secret Input Frontend.
    #[error("verified helper is not the secret-input frontend")]
    WrongHelperRole,
    /// The prompt did not satisfy the canonical Secret Input contract.
    #[error("secret-input prompt is invalid")]
    InvalidPrompt,
    /// The restricted release-attested helper launch failed closed.
    #[error("secret-input frontend launch failed")]
    Launch(#[source] LaunchError),
    /// Private endpoint creation or the complete request transfer failed.
    #[error("secret-input private-pipe setup failed")]
    Pipe(#[source] PipeError),
    /// The trusted monotonic setup deadline elapsed.
    #[error("secret-input setup deadline elapsed")]
    DeadlineElapsed,
    /// The caller supplied a deadline outside the short trusted UI window.
    #[error("secret-input setup deadline exceeds the maximum duration")]
    DeadlineTooFar,
    /// Held identity or transcript binding failed while arming the channel.
    #[error("secret-input response channel could not be armed")]
    Channel(#[source] SecretInputChannelError),
}

/// Launches the exact verified Secret Input Frontend with two private one-shot
/// pipe directions and returns the held process plus its concrete response end.
///
/// This is the only public arming API. It creates both endpoints, includes only
/// child stdin/stdout/stderr in the restricted launcher's handle list, closes
/// the parent's copies of those child ends, transfers the complete canonical
/// prompt before the supplied monotonic deadline, and closes the request writer
/// to deliver EOF. Any failure drops the pipe owners and, after process
/// creation, the kill-on-close held job.
///
/// # Errors
///
/// Fails closed for a wrong manifest role, invalid prompt, expired deadline,
/// release-attestation or restricted-launch failure, private-pipe failure, or
/// held helper identity mismatch.
#[cfg(windows)]
pub(crate) fn launch_secret_input_frontend(
    launcher: RestrictedLauncher,
    helper: &VerifiedHelper,
    prompt: &SecretPrompt,
    expires_at: Instant,
) -> Result<PendingSecretInput, SecretInputLaunchError> {
    if !helper.is_secret_input_frontend() {
        return Err(SecretInputLaunchError::WrongHelperRole);
    }
    let _validated_prompt =
        Zeroizing::new(encode_prompt(prompt).map_err(|_| SecretInputLaunchError::InvalidPrompt)?);
    validate_launch_deadline(expires_at)?;
    let mut parent_nonce = Zeroizing::new([0_u8; CHANNEL_CHALLENGE_BYTES]);
    getrandom::fill(&mut *parent_nonce)
        .map_err(|_| SecretInputLaunchError::Channel(SecretInputChannelError::TranscriptFailure))?;
    if is_all_zero(&*parent_nonce) {
        return Err(SecretInputLaunchError::Channel(
            SecretInputChannelError::TranscriptFailure,
        ));
    }

    let pipes = PrivateSecretInputPipes::create().map_err(map_setup_pipe_error)?;
    let held_process = {
        let inherited = InheritedStdio::for_secret_input_servers(
            pipes.child_input(),
            pipes.child_output(),
            pipes.child_output(),
        )
        .map_err(SecretInputLaunchError::Launch)?;
        launcher
            .spawn_secret_input(helper, &inherited)
            .map_err(SecretInputLaunchError::Launch)?
    };
    let proof = held_process
        .parent_proof()
        .ok_or(SecretInputLaunchError::Channel(
            SecretInputChannelError::IdentityMismatch,
        ))?;
    let parent_hello = ParentHello::new(
        proof.process_id(),
        proof.process_handle(),
        proof.image_handle(),
        *parent_nonce,
    )
    .map_err(|_| SecretInputLaunchError::Channel(SecretInputChannelError::TranscriptFailure))?;
    let encoded_hello = encode_parent_hello(&parent_hello);
    let (mut writer, response_reader) = pipes.into_parent();
    writer
        .write_bytes(&encoded_hello, expires_at)
        .map_err(map_setup_pipe_error)?;
    let child_hello_bytes = response_reader
        .read_exact(CHILD_HELLO_BYTES, expires_at)
        .map_err(map_setup_pipe_error)?;
    let child_hello = decode_child_hello(&parent_hello, &child_hello_bytes)
        .map_err(|_| SecretInputLaunchError::Channel(SecretInputChannelError::TranscriptFailure))?;
    let child_nonce = child_hello.child_nonce();
    let binding = SecretResponseBinding::arm_from_held_helper(
        helper,
        &held_process,
        prompt.clone(),
        expires_at,
        *parent_nonce,
        child_nonce,
    )
    .map_err(|error| match error {
        SecretInputChannelError::DeadlineElapsed => SecretInputLaunchError::DeadlineElapsed,
        _ => SecretInputLaunchError::Channel(error),
    })?;
    let finish = encode_parent_finish(prompt, &parent_nonce, &child_nonce)
        .map_err(|_| SecretInputLaunchError::InvalidPrompt)?;
    writer
        .write_all(&finish, expires_at)
        .map_err(map_setup_pipe_error)?;
    Ok(PendingSecretInput {
        helper: held_process,
        response_reader,
        binding,
    })
}

#[cfg(windows)]
fn validate_launch_deadline(expires_at: Instant) -> Result<(), SecretInputLaunchError> {
    let remaining = expires_at
        .checked_duration_since(Instant::now())
        .ok_or(SecretInputLaunchError::DeadlineElapsed)?;
    if remaining > MAX_SECRET_INPUT_DURATION {
        return Err(SecretInputLaunchError::DeadlineTooFar);
    }
    Ok(())
}

#[cfg(windows)]
fn map_setup_pipe_error(error: PipeError) -> SecretInputLaunchError {
    if matches!(error, PipeError::DeadlineElapsed) {
        SecretInputLaunchError::DeadlineElapsed
    } else {
        SecretInputLaunchError::Pipe(error)
    }
}

/// Result obtained after consuming an authenticated Secret Input proof.
///
/// This enum is intentionally not itself an authentication capability. Callers
/// receive it only by consuming [`VerifiedSecretInput`]. Accepted bytes always
/// remain in a zeroizing allocation.
pub enum SecretInputValue {
    /// One accepted, prompt-bounded UTF-8 secret.
    Accepted(Zeroizing<Vec<u8>>),
    /// The user cancelled or closed the trusted native prompt.
    Cancelled,
}

impl fmt::Debug for SecretInputValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accepted(_) => formatter.write_str("SecretInputValue::Accepted([REDACTED])"),
            Self::Cancelled => formatter.write_str("SecretInputValue::Cancelled"),
        }
    }
}

/// Opaque proof that one result came from the exact held Secret Input helper.
///
/// This proof is non-cloneable and has no public constructor. Its private
/// transcript binds the helper file, process, sandbox profile, exact prompt,
/// response disposition, response length, and a fresh OS-CSPRNG challenge. The
/// transcript never hashes the secret bytes, avoiding a password-verification
/// oracle.
///
/// ```compile_fail
/// use platform_windows::VerifiedSecretInput;
///
/// fn cannot_clone(value: VerifiedSecretInput) {
///     let _copy = value.clone();
/// }
/// ```
///
/// ```compile_fail
/// use platform_windows::VerifiedSecretInput;
///
/// fn cannot_consume_twice(value: VerifiedSecretInput) {
///     # use secret_input_ui::{PromptKind, SecretPrompt};
///     # let Ok(prompt) = SecretPrompt::new(PromptKind::UnlockPassword, "local phrase".to_owned()) else { return; };
///     let _first = value.into_value_for(&prompt);
///     let _second = value.into_value_for(&prompt);
/// }
/// ```
///
/// ```compile_fail
/// use platform_windows::VerifiedSecretInput;
///
/// fn cannot_extract_transcript(value: &VerifiedSecretInput) {
///     let _ = value.child_transcript();
/// }
/// ```
///
/// ```compile_fail
/// use platform_windows::VerifiedSecretInput;
///
/// fn cannot_borrow_secret(value: &VerifiedSecretInput) {
///     let _ = value.secret();
/// }
/// ```
pub struct VerifiedSecretInput {
    outcome: SecretOutcome,
    prompt_kind: PromptKind,
    prompt_hash: [u8; 32],
    child_transcript: [u8; 32],
    expires_at: Instant,
}

impl VerifiedSecretInput {
    /// Consumes the one-shot proof only for the exact prompt originally bound
    /// into its authenticated child transcript.
    ///
    /// # Errors
    ///
    /// Returns [`SecretInputChannelError::PromptBindingMismatch`] when the
    /// caller attempts to consume the result for any other prompt. The proof is
    /// consumed on failure, so a swap attempt cannot be retried elsewhere.
    pub fn into_value_for(
        self,
        expected_prompt: &SecretPrompt,
    ) -> Result<SecretInputValue, SecretInputChannelError> {
        if deadline_elapsed(self.expires_at) {
            return Err(SecretInputChannelError::DeadlineElapsed);
        }
        let recomputed = prompt_hash(expected_prompt)?;
        if self.prompt_kind != expected_prompt.kind()
            || !bool::from(self.prompt_hash.ct_eq(&recomputed))
        {
            return Err(SecretInputChannelError::PromptBindingMismatch);
        }
        match self.outcome {
            SecretOutcome::Accepted(secret) => Ok(SecretInputValue::Accepted(secret)),
            SecretOutcome::Cancelled => Ok(SecretInputValue::Cancelled),
        }
    }
}

impl fmt::Debug for VerifiedSecretInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted = if is_all_zero(&self.prompt_hash) || is_all_zero(&self.child_transcript) {
            "VerifiedSecretInput([INVALID REDACTED PROOF])"
        } else {
            "VerifiedSecretInput([REDACTED ONE-SHOT PROOF])"
        };
        formatter.write_str(redacted)
    }
}

/// A held Secret Input Frontend plus its exact concrete response endpoint.
///
/// There is no public constructor. [`launch_secret_input_frontend`] is the only
/// arming path and requires the release-attested restricted launcher plus the
/// exact verified Secret Input helper role.
#[cfg(windows)]
pub(crate) struct PendingSecretInput {
    helper: LaunchedHelper,
    response_reader: SecretResponseReader,
    binding: SecretResponseBinding,
}

#[cfg(windows)]
impl PendingSecretInput {
    /// Consumes the held helper and channel into one authenticated result.
    ///
    /// # Errors
    ///
    /// Fails closed on held-identity mismatch, timeout, malformed/trailing
    /// response data, prompt mismatch, prompt-bound violation, or pipe failure.
    ///
    /// ```compile_fail
    /// use platform_windows::PendingSecretInput;
    ///
    /// fn cannot_receive_twice(pending: PendingSecretInput) {
    ///     let _first = pending.receive();
    ///     let _second = pending.receive();
    /// }
    /// ```
    pub(crate) fn receive(self) -> Result<VerifiedSecretInput, SecretInputChannelError> {
        let Self {
            helper,
            response_reader,
            binding,
        } = self;
        if !helper.is_held_in_job() {
            return Err(SecretInputChannelError::IdentityMismatch);
        }
        let actual_identity = TranscriptIdentity::from_held(helper.identity());
        let result = binding.receive_from_concrete(response_reader, actual_identity);
        // Preserve both held process and kill-on-close job handles until after
        // response read, identity verification, and transcript construction.
        drop(helper);
        result
    }
}

#[cfg(windows)]
impl fmt::Debug for PendingSecretInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingSecretInput")
            .field("helper", &"[HELD PROCESS AND JOB]")
            .field("response_reader", &"[CONCRETE PRIVATE PIPE]")
            .field("binding", &self.binding)
            .finish()
    }
}

/// Opaque binding for one complete response from the concrete inherited pipe.
struct SecretResponseBinding {
    bound_identity: TranscriptIdentity,
    prompt: SecretPrompt,
    expected_prompt_hash: [u8; 32],
    expires_at: Instant,
    channel_challenge: Zeroizing<[u8; CHANNEL_CHALLENGE_BYTES]>,
    child_challenge: Zeroizing<[u8; CHANNEL_CHALLENGE_BYTES]>,
}

impl SecretResponseBinding {
    /// Binds a role-verified held process to the exact retained prompt.
    #[cfg(windows)]
    fn arm_from_held_helper(
        verified_helper: &VerifiedHelper,
        launched_helper: &LaunchedHelper,
        prompt: SecretPrompt,
        expires_at: Instant,
        parent_challenge: [u8; CHANNEL_CHALLENGE_BYTES],
        child_challenge: [u8; CHANNEL_CHALLENGE_BYTES],
    ) -> Result<Self, SecretInputChannelError> {
        require_secret_input_frontend(verified_helper)?;
        let identity = launched_helper.identity();
        if identity.helper_file() != verified_helper.identity()
            || identity.helper_manifest_digest() != verified_helper.manifest_digest()
            || !launched_helper.is_held_in_job()
        {
            return Err(SecretInputChannelError::IdentityMismatch);
        }
        Self::arm_with_challenges(
            TranscriptIdentity::from_held(identity),
            prompt,
            expires_at,
            parent_challenge,
            child_challenge,
        )
    }

    fn arm(
        bound_identity: TranscriptIdentity,
        prompt: SecretPrompt,
        expires_at: Instant,
    ) -> Result<Self, SecretInputChannelError> {
        let mut challenge = Zeroizing::new([0_u8; CHANNEL_CHALLENGE_BYTES]);
        getrandom::fill(&mut *challenge).map_err(|_| SecretInputChannelError::TranscriptFailure)?;
        let mut child_challenge = Zeroizing::new([0_u8; CHANNEL_CHALLENGE_BYTES]);
        getrandom::fill(&mut *child_challenge)
            .map_err(|_| SecretInputChannelError::TranscriptFailure)?;
        Self::arm_with_challenges(
            bound_identity,
            prompt,
            expires_at,
            *challenge,
            *child_challenge,
        )
    }

    fn arm_with_challenges(
        bound_identity: TranscriptIdentity,
        prompt: SecretPrompt,
        expires_at: Instant,
        parent_challenge: [u8; CHANNEL_CHALLENGE_BYTES],
        child_challenge: [u8; CHANNEL_CHALLENGE_BYTES],
    ) -> Result<Self, SecretInputChannelError> {
        let expected_prompt_hash = prompt_hash(&prompt)?;
        if is_all_zero(&parent_challenge) || is_all_zero(&child_challenge) {
            return Err(SecretInputChannelError::TranscriptFailure);
        }
        if deadline_elapsed(expires_at) {
            return Err(SecretInputChannelError::DeadlineElapsed);
        }
        Ok(Self {
            bound_identity,
            prompt,
            expected_prompt_hash,
            expires_at,
            channel_challenge: Zeroizing::new(parent_challenge),
            child_challenge: Zeroizing::new(child_challenge),
        })
    }

    #[cfg(windows)]
    fn receive_from_concrete(
        self,
        response_reader: SecretResponseReader,
        actual_identity: TranscriptIdentity,
    ) -> Result<VerifiedSecretInput, SecretInputChannelError> {
        self.preflight(actual_identity)?;
        let response_bytes = response_reader
            .read_bounded_to_end(MAX_AUTHENTICATED_RESPONSE_BYTES, self.expires_at)
            .map_err(map_response_pipe_error)?;
        self.finish(response_bytes)
    }

    fn preflight(
        &self,
        actual_identity: TranscriptIdentity,
    ) -> Result<(), SecretInputChannelError> {
        if actual_identity != self.bound_identity {
            return Err(SecretInputChannelError::IdentityMismatch);
        }
        if deadline_elapsed(self.expires_at) {
            return Err(SecretInputChannelError::DeadlineElapsed);
        }
        if is_all_zero(&*self.channel_challenge) || is_all_zero(&*self.child_challenge) {
            return Err(SecretInputChannelError::TranscriptFailure);
        }
        let retained_prompt_hash = prompt_hash(&self.prompt)?;
        if !bool::from(retained_prompt_hash.ct_eq(&self.expected_prompt_hash)) {
            return Err(SecretInputChannelError::PromptBindingMismatch);
        }
        Ok(())
    }

    fn finish(
        self,
        response_bytes: Zeroizing<Vec<u8>>,
    ) -> Result<VerifiedSecretInput, SecretInputChannelError> {
        if deadline_elapsed(self.expires_at) {
            return Err(SecretInputChannelError::DeadlineElapsed);
        }
        let outcome = decode_authenticated_outcome(
            &self.prompt,
            &self.channel_challenge,
            &self.child_challenge,
            response_bytes,
        )
        .map_err(|error| map_decode_error(&error))?;
        if deadline_elapsed(self.expires_at) {
            return Err(SecretInputChannelError::DeadlineElapsed);
        }
        let (disposition, secret_length) = match &outcome {
            SecretOutcome::Accepted(secret) => (1_u8, secret.len()),
            SecretOutcome::Cancelled => (0_u8, 0),
        };
        let child_transcript = transcript_hash(
            self.bound_identity,
            self.expected_prompt_hash,
            disposition,
            secret_length,
            &self.channel_challenge,
            &self.child_challenge,
        )?;
        Ok(VerifiedSecretInput {
            outcome,
            prompt_kind: self.prompt.kind(),
            prompt_hash: self.expected_prompt_hash,
            child_transcript,
            expires_at: self.expires_at,
        })
    }
}

impl fmt::Debug for SecretResponseBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretResponseBinding")
            .field("bound_identity", &"[REDACTED]")
            .field("prompt", &"[REDACTED FIXED PROMPT]")
            .field("expected_prompt_hash", &"[SHA-256]")
            .field("expires_at", &"[MONOTONIC DEADLINE]")
            .field("channel_challenge", &"[REDACTED]")
            .field("child_challenge", &"[REDACTED]")
            .finish()
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

#[cfg(windows)]
fn require_secret_input_frontend(helper: &VerifiedHelper) -> Result<(), SecretInputChannelError> {
    if helper.is_secret_input_frontend() {
        Ok(())
    } else {
        Err(SecretInputChannelError::WrongHelperRole)
    }
}

fn prompt_hash(prompt: &SecretPrompt) -> Result<[u8; 32], SecretInputChannelError> {
    let encoded = encode_prompt(prompt).map_err(|_| SecretInputChannelError::InvalidPrompt)?;
    let mut hash = Sha256::new();
    hash.update(PROMPT_DOMAIN);
    hash.update(
        u32::try_from(encoded.len())
            .map_err(|_| SecretInputChannelError::InvalidPrompt)?
            .to_be_bytes(),
    );
    hash.update(encoded);
    let digest: [u8; 32] = hash.finalize().into();
    if is_all_zero(&digest) {
        Err(SecretInputChannelError::PromptBindingMismatch)
    } else {
        Ok(digest)
    }
}

fn transcript_hash(
    identity: TranscriptIdentity,
    prompt_hash: [u8; 32],
    disposition: u8,
    secret_length: usize,
    channel_challenge: &[u8; CHANNEL_CHALLENGE_BYTES],
    child_challenge: &[u8; CHANNEL_CHALLENGE_BYTES],
) -> Result<[u8; 32], SecretInputChannelError> {
    if !matches!(disposition, 0 | 1)
        || is_all_zero(channel_challenge)
        || is_all_zero(child_challenge)
    {
        return Err(SecretInputChannelError::TranscriptFailure);
    }
    let mut transcript = Sha256::new();
    transcript.update(TRANSCRIPT_DOMAIN);
    transcript.update(identity.process_id.to_be_bytes());
    transcript.update(identity.helper_file.volume_serial_number.to_be_bytes());
    transcript.update(identity.helper_file.file_index.to_be_bytes());
    transcript.update(identity.helper_file.file_size.to_be_bytes());
    transcript.update(identity.helper_manifest_digest);
    transcript.update(identity.profile_revision.to_be_bytes());
    transcript.update(prompt_hash);
    transcript.update([disposition]);
    transcript.update(
        u32::try_from(secret_length)
            .map_err(|_| SecretInputChannelError::TranscriptFailure)?
            .to_be_bytes(),
    );
    transcript.update(channel_challenge);
    transcript.update(child_challenge);
    let digest: [u8; 32] = transcript.finalize().into();
    if is_all_zero(&digest) {
        Err(SecretInputChannelError::TranscriptFailure)
    } else {
        Ok(digest)
    }
}

fn map_decode_error(error: &SecretInputError) -> SecretInputChannelError {
    match error {
        SecretInputError::Malformed => SecretInputChannelError::MalformedResponse,
        SecretInputError::InvalidLength => SecretInputChannelError::PromptBoundsViolation,
        SecretInputError::Io(_) | SecretInputError::NativeFailure => {
            SecretInputChannelError::ChannelFailure
        }
    }
}

#[cfg(windows)]
fn map_response_pipe_error(error: PipeError) -> SecretInputChannelError {
    match error {
        PipeError::DeadlineElapsed => SecretInputChannelError::DeadlineElapsed,
        PipeError::UnexpectedEnd | PipeError::TrailingData | PipeError::FrameTooLarge => {
            SecretInputChannelError::MalformedResponse
        }
        _ => SecretInputChannelError::ChannelFailure,
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
    use core::fmt;
    use std::time::{Duration, Instant};

    use secret_input_ui::{
        MAX_RESPONSE_BYTES, PromptKind, SecretOutcome, SecretPrompt, encode_prompt, write_outcome,
    };
    use sha2::{Digest as _, Sha256};
    use zeroize::Zeroizing;

    use super::{
        CHANNEL_CHALLENGE_BYTES, SecretInputChannelError, SecretInputValue, SecretResponseBinding,
        TranscriptIdentity, VerifiedSecretInput, prompt_hash,
    };
    #[cfg(windows)]
    use super::{
        SecretInputLaunchError, launch_secret_input_frontend, require_secret_input_frontend,
    };
    use crate::helper::FileIdentity;
    #[cfg(windows)]
    use crate::helper::VerifiedHelper;
    #[cfg(windows)]
    use crate::{
        attestation::ReleaseAttestation,
        launch::{LaunchError, NoNetworkLpacProfile, RestrictedLauncher},
    };

    struct MemoryReader {
        bytes: Zeroizing<Vec<u8>>,
        failure: Option<SecretInputChannelError>,
        wait_until_deadline: bool,
    }

    impl fmt::Debug for MemoryReader {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("MemoryReader([REDACTED TEST RESPONSE])")
        }
    }

    impl MemoryReader {
        fn read_once(
            self,
            deadline: Instant,
        ) -> Result<Zeroizing<Vec<u8>>, SecretInputChannelError> {
            if self.wait_until_deadline {
                while !super::deadline_elapsed(deadline) {
                    std::hint::spin_loop();
                }
            }
            if let Some(error) = self.failure {
                Err(error)
            } else {
                Ok(self.bytes)
            }
        }
    }

    #[derive(Debug)]
    struct TestSecretResponseChannel {
        binding: SecretResponseBinding,
        reader: MemoryReader,
    }

    impl TestSecretResponseChannel {
        fn verify_for_identity(
            self,
            actual_identity: TranscriptIdentity,
        ) -> Result<VerifiedSecretInput, SecretInputChannelError> {
            let Self { binding, reader } = self;
            binding.preflight(actual_identity)?;
            let response = reader.read_once(binding.expires_at)?;
            binding.finish(response)
        }
    }

    fn prompt(minimum: u16, maximum: u16) -> SecretPrompt {
        assert_eq!((minimum, maximum), (12, 64));
        SecretPrompt::new(PromptKind::UnlockPassword, "blue comet".to_owned())
            .unwrap_or_else(|_| unreachable!("test prompt is canonical"))
    }

    const fn identity() -> TranscriptIdentity {
        TranscriptIdentity {
            process_id: 71,
            helper_file: FileIdentity {
                volume_serial_number: 72,
                file_index: 73,
                file_size: 74,
            },
            helper_manifest_digest: [75; 32],
            profile_revision: 1,
        }
    }

    const TEST_PARENT_CHALLENGE: [u8; CHANNEL_CHALLENGE_BYTES] = [91; CHANNEL_CHALLENGE_BYTES];
    const TEST_CHILD_CHALLENGE: [u8; CHANNEL_CHALLENGE_BYTES] = [37; CHANNEL_CHALLENGE_BYTES];

    fn authenticated_bytes_for(
        prompt: &SecretPrompt,
        parent_challenge: &[u8; CHANNEL_CHALLENGE_BYTES],
        child_challenge: &[u8; CHANNEL_CHALLENGE_BYTES],
        outcome: SecretOutcome,
    ) -> Result<Zeroizing<Vec<u8>>, SecretInputChannelError> {
        let mut inner = Zeroizing::new(Vec::new());
        write_outcome(&mut *inner, outcome).map_err(|error| super::map_decode_error(&error))?;
        let encoded_prompt =
            encode_prompt(prompt).map_err(|error| super::map_decode_error(&error))?;
        let mut hash = Sha256::new();
        hash.update(b"your-wallet/secret-input-bootstrap-prompt/v1\0");
        hash.update(
            u32::try_from(encoded_prompt.len())
                .map_err(|_| SecretInputChannelError::TranscriptFailure)?
                .to_be_bytes(),
        );
        hash.update(encoded_prompt);
        let prompt_digest: [u8; 32] = hash.finalize().into();
        let inner_length =
            u32::try_from(inner.len()).map_err(|_| SecretInputChannelError::TranscriptFailure)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.extend_from_slice(b"YWSBOR01");
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(parent_challenge);
        bytes.extend_from_slice(child_challenge);
        bytes.extend_from_slice(&prompt_digest);
        bytes.extend_from_slice(&inner_length.to_be_bytes());
        bytes.extend_from_slice(&inner);
        Ok(bytes)
    }

    fn accepted_bytes(secret: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecretInputChannelError> {
        authenticated_bytes_for(
            &prompt(12, 64),
            &TEST_PARENT_CHALLENGE,
            &TEST_CHILD_CHALLENGE,
            SecretOutcome::Accepted(Zeroizing::new(secret.to_vec())),
        )
    }

    fn cancelled_bytes() -> Result<Zeroizing<Vec<u8>>, SecretInputChannelError> {
        authenticated_bytes_for(
            &prompt(12, 64),
            &TEST_PARENT_CHALLENGE,
            &TEST_CHILD_CHALLENGE,
            SecretOutcome::Cancelled,
        )
    }

    fn future_deadline() -> Result<Instant, Box<dyn std::error::Error>> {
        Instant::now()
            .checked_add(Duration::from_mins(1))
            .ok_or_else(|| "monotonic deadline overflow".into())
    }

    fn channel(
        bytes: Zeroizing<Vec<u8>>,
        expected_prompt: SecretPrompt,
        expected_identity: TranscriptIdentity,
        expires_at: Instant,
    ) -> Result<TestSecretResponseChannel, Box<dyn std::error::Error>> {
        let expected_prompt_hash = prompt_hash(&expected_prompt)?;
        Ok(TestSecretResponseChannel {
            binding: SecretResponseBinding {
                bound_identity: expected_identity,
                prompt: expected_prompt,
                expected_prompt_hash,
                expires_at,
                channel_challenge: Zeroizing::new(TEST_PARENT_CHALLENGE),
                child_challenge: Zeroizing::new(TEST_CHILD_CHALLENGE),
            },
            reader: MemoryReader {
                bytes,
                failure: None,
                wait_until_deadline: false,
            },
        })
    }

    fn memory_reader(bytes: Zeroizing<Vec<u8>>) -> MemoryReader {
        MemoryReader {
            bytes,
            failure: None,
            wait_until_deadline: false,
        }
    }

    #[test]
    fn arming_uses_fresh_nonzero_os_challenges_and_rejects_invalid_prompt()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = SecretResponseBinding::arm(identity(), prompt(12, 64), future_deadline()?)?;
        let second = SecretResponseBinding::arm(identity(), prompt(12, 64), future_deadline()?)?;
        assert!(first.channel_challenge.iter().any(|byte| *byte != 0));
        assert!(second.channel_challenge.iter().any(|byte| *byte != 0));
        assert_ne!(*first.channel_challenge, *second.channel_challenge);
        let first_response = authenticated_bytes_for(
            &first.prompt,
            &first.channel_challenge,
            &first.child_challenge,
            SecretOutcome::Cancelled,
        )?;
        let second_response = authenticated_bytes_for(
            &second.prompt,
            &second.channel_challenge,
            &second.child_challenge,
            SecretOutcome::Cancelled,
        )?;
        let first_verified = TestSecretResponseChannel {
            binding: first,
            reader: memory_reader(first_response),
        }
        .verify_for_identity(identity())?;
        let second_verified = TestSecretResponseChannel {
            binding: second,
            reader: memory_reader(second_response),
        }
        .verify_for_identity(identity())?;
        assert_ne!(
            first_verified.child_transcript,
            second_verified.child_transcript
        );

        let invalid = SecretPrompt::new(PromptKind::UnlockPassword, String::new());
        assert!(matches!(
            invalid,
            Err(secret_input_ui::SecretInputError::Malformed)
        ));
        Ok(())
    }

    #[test]
    fn accepted_secret_stays_zeroizing_and_debug_is_redacted()
    -> Result<(), Box<dyn std::error::Error>> {
        let verified = channel(
            accepted_bytes(b"bounded secret")?,
            prompt(12, 64),
            identity(),
            future_deadline()?,
        )?
        .verify_for_identity(identity())?;
        let proof_debug = format!("{verified:?}");
        assert_eq!(
            proof_debug,
            "VerifiedSecretInput([REDACTED ONE-SHOT PROOF])"
        );
        assert!(!proof_debug.contains("bounded secret"));
        let exact_prompt = prompt(12, 64);
        match verified.into_value_for(&exact_prompt)? {
            SecretInputValue::Accepted(secret) => {
                assert_eq!(secret.as_slice(), b"bounded secret");
                assert_eq!(
                    format!("{:?}", SecretInputValue::Accepted(secret)),
                    "SecretInputValue::Accepted([REDACTED])"
                );
            }
            SecretInputValue::Cancelled => return Err("accepted input became cancellation".into()),
        }
        Ok(())
    }

    #[test]
    fn cancellation_is_distinct_and_contains_no_secret() -> Result<(), Box<dyn std::error::Error>> {
        let verified = channel(
            cancelled_bytes()?,
            prompt(12, 64),
            identity(),
            future_deadline()?,
        )?
        .verify_for_identity(identity())?;
        let exact_prompt = prompt(12, 64);
        assert!(matches!(
            verified.into_value_for(&exact_prompt)?,
            SecretInputValue::Cancelled
        ));
        Ok(())
    }

    #[test]
    fn verified_result_cannot_be_consumed_after_its_deadline()
    -> Result<(), Box<dyn std::error::Error>> {
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(50))
            .ok_or("monotonic clock cannot represent short deadline")?;
        let exact_prompt = prompt(12, 64);
        let verified = channel(
            cancelled_bytes()?,
            exact_prompt.clone(),
            identity(),
            deadline,
        )?
        .verify_for_identity(identity())?;
        std::thread::sleep(Duration::from_millis(60));
        assert!(matches!(
            verified.into_value_for(&exact_prompt),
            Err(SecretInputChannelError::DeadlineElapsed)
        ));
        Ok(())
    }

    #[test]
    fn proof_consumption_requires_the_exact_prompt_not_a_same_length_swap()
    -> Result<(), Box<dyn std::error::Error>> {
        let original = SecretPrompt::new(PromptKind::UnlockPassword, "blue comet".to_owned())
            .unwrap_or_else(|_| unreachable!("test prompt is canonical"));
        let swapped = SecretPrompt::new(PromptKind::NewVaultPassword, "green moon".to_owned())
            .unwrap_or_else(|_| unreachable!("test prompt is canonical"));
        let rejected = channel(
            accepted_bytes(b"bounded secret")?,
            original.clone(),
            identity(),
            future_deadline()?,
        )?
        .verify_for_identity(identity())?;
        assert!(matches!(
            rejected.into_value_for(&swapped),
            Err(SecretInputChannelError::PromptBindingMismatch)
        ));

        let phrase_swapped = SecretPrompt::new(PromptKind::UnlockPassword, "green moon".to_owned())
            .unwrap_or_else(|_| unreachable!("test prompt is canonical"));
        let rejected = channel(
            accepted_bytes(b"bounded secret")?,
            original.clone(),
            identity(),
            future_deadline()?,
        )?
        .verify_for_identity(identity())?;
        assert!(matches!(
            rejected.into_value_for(&phrase_swapped),
            Err(SecretInputChannelError::PromptBindingMismatch)
        ));

        let accepted = channel(
            accepted_bytes(b"bounded secret")?,
            original.clone(),
            identity(),
            future_deadline()?,
        )?
        .verify_for_identity(identity())?;
        assert!(matches!(
            accepted.into_value_for(&original)?,
            SecretInputValue::Accepted(_)
        ));
        Ok(())
    }

    #[test]
    fn exact_prompt_is_bound_and_bounds_are_enforced() -> Result<(), Box<dyn std::error::Error>> {
        let expected_prompt = prompt(12, 64);
        let mut wrong_binding = channel(
            accepted_bytes(b"bounded secret")?,
            expected_prompt.clone(),
            identity(),
            future_deadline()?,
        )?;
        wrong_binding.binding.expected_prompt_hash[0] ^= 1;
        assert!(matches!(
            wrong_binding.verify_for_identity(identity()),
            Err(SecretInputChannelError::PromptBindingMismatch)
        ));

        let too_short = channel(
            accepted_bytes(b"short")?,
            expected_prompt,
            identity(),
            future_deadline()?,
        )?
        .verify_for_identity(identity());
        assert!(matches!(
            too_short,
            Err(SecretInputChannelError::PromptBoundsViolation)
        ));
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
            assert!(matches!(
                channel(
                    accepted_bytes(b"bounded secret")?,
                    prompt(12, 64),
                    expected,
                    future_deadline()?,
                )?
                .verify_for_identity(actual),
                Err(SecretInputChannelError::IdentityMismatch)
            ));
        }
        Ok(())
    }

    #[test]
    fn every_truncation_and_trailing_byte_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let exact = accepted_bytes(b"bounded secret")?;
        for length in 0..exact.len() {
            let truncated = Zeroizing::new(exact[..length].to_vec());
            assert!(matches!(
                channel(truncated, prompt(12, 64), identity(), future_deadline()?)?
                    .verify_for_identity(identity()),
                Err(SecretInputChannelError::MalformedResponse)
            ));
        }
        let mut trailing = Zeroizing::new(exact.to_vec());
        trailing.push(0);
        assert!(matches!(
            channel(trailing, prompt(12, 64), identity(), future_deadline()?)?
                .verify_for_identity(identity()),
            Err(SecretInputChannelError::MalformedResponse)
        ));
        Ok(())
    }

    #[test]
    fn oversized_and_non_utf8_responses_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let oversized = Zeroizing::new(vec![0; MAX_RESPONSE_BYTES + 1]);
        assert!(matches!(
            channel(oversized, prompt(12, 64), identity(), future_deadline()?,)?
                .verify_for_identity(identity()),
            Err(SecretInputChannelError::MalformedResponse)
        ));

        let mut non_utf8 = accepted_bytes(b"bounded secret")?;
        if let Some(last) = non_utf8.last_mut() {
            *last = 0xff;
        } else {
            return Err("encoded accepted frame was empty".into());
        }
        assert!(matches!(
            channel(non_utf8, prompt(12, 64), identity(), future_deadline()?,)?
                .verify_for_identity(identity()),
            Err(SecretInputChannelError::MalformedResponse)
        ));
        Ok(())
    }

    #[test]
    fn deadline_is_checked_before_and_after_response_read() -> Result<(), Box<dyn std::error::Error>>
    {
        let past = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .ok_or("monotonic clock cannot represent past deadline")?;
        assert!(matches!(
            channel(
                accepted_bytes(b"bounded secret")?,
                prompt(12, 64),
                identity(),
                past,
            )?
            .verify_for_identity(identity()),
            Err(SecretInputChannelError::DeadlineElapsed)
        ));

        let deadline = Instant::now()
            .checked_add(Duration::from_millis(2))
            .ok_or("monotonic clock cannot represent short deadline")?;
        let expected_prompt = prompt(12, 64);
        let delayed = TestSecretResponseChannel {
            binding: SecretResponseBinding {
                bound_identity: identity(),
                expected_prompt_hash: prompt_hash(&expected_prompt)?,
                prompt: expected_prompt,
                expires_at: deadline,
                channel_challenge: Zeroizing::new([91; CHANNEL_CHALLENGE_BYTES]),
                child_challenge: Zeroizing::new([37; CHANNEL_CHALLENGE_BYTES]),
            },
            reader: MemoryReader {
                bytes: accepted_bytes(b"bounded secret")?,
                failure: None,
                wait_until_deadline: true,
            },
        };
        assert!(matches!(
            delayed.verify_for_identity(identity()),
            Err(SecretInputChannelError::DeadlineElapsed)
        ));
        Ok(())
    }

    #[test]
    fn reader_failure_and_zero_challenge_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let expected_prompt = prompt(12, 64);
        let failed = TestSecretResponseChannel {
            binding: SecretResponseBinding {
                bound_identity: identity(),
                expected_prompt_hash: prompt_hash(&expected_prompt)?,
                prompt: expected_prompt,
                expires_at: future_deadline()?,
                channel_challenge: Zeroizing::new([91; CHANNEL_CHALLENGE_BYTES]),
                child_challenge: Zeroizing::new([37; CHANNEL_CHALLENGE_BYTES]),
            },
            reader: MemoryReader {
                bytes: Zeroizing::new(Vec::new()),
                failure: Some(SecretInputChannelError::ChannelFailure),
                wait_until_deadline: false,
            },
        };
        assert!(matches!(
            failed.verify_for_identity(identity()),
            Err(SecretInputChannelError::ChannelFailure)
        ));

        let expected_prompt = prompt(12, 64);
        let zero_challenge = TestSecretResponseChannel {
            binding: SecretResponseBinding {
                bound_identity: identity(),
                expected_prompt_hash: prompt_hash(&expected_prompt)?,
                prompt: expected_prompt,
                expires_at: future_deadline()?,
                channel_challenge: Zeroizing::new([0; CHANNEL_CHALLENGE_BYTES]),
                child_challenge: Zeroizing::new([37; CHANNEL_CHALLENGE_BYTES]),
            },
            reader: MemoryReader {
                bytes: accepted_bytes(b"bounded secret")?,
                failure: None,
                wait_until_deadline: false,
            },
        };
        assert!(matches!(
            zero_challenge.verify_for_identity(identity()),
            Err(SecretInputChannelError::TranscriptFailure)
        ));
        Ok(())
    }

    #[test]
    fn transcript_binds_prompt_disposition_and_fresh_challenge_without_secret_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = channel(
            accepted_bytes(b"bounded secret")?,
            prompt(12, 64),
            identity(),
            future_deadline()?,
        )?
        .verify_for_identity(identity())?;
        let second = channel(
            cancelled_bytes()?,
            prompt(12, 64),
            identity(),
            future_deadline()?,
        )?
        .verify_for_identity(identity())?;
        assert_eq!(first.prompt_hash, second.prompt_hash);
        assert_ne!(first.child_transcript, second.child_transcript);
        assert!(first.child_transcript.iter().any(|byte| *byte != 0));
        Ok(())
    }

    #[test]
    fn debug_never_exposes_prompt_identity_or_challenge() -> Result<(), Box<dyn std::error::Error>>
    {
        let response_channel = channel(
            accepted_bytes(b"bounded secret")?,
            prompt(12, 64),
            identity(),
            future_deadline()?,
        )?;
        let rendered = format!("{response_channel:?}");
        assert!(rendered.contains("TestSecretResponseChannel"));
        assert!(rendered.contains("[REDACTED"));
        assert!(!rendered.contains("blue comet"));
        assert!(!rendered.contains("bounded secret"));
        assert!(!rendered.contains("process_id: 71"));
        assert!(!rendered.contains("91, 91"));
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn exact_secret_input_role_is_required() -> Result<(), Box<dyn std::error::Error>> {
        let secret_helper = VerifiedHelper::for_secret_input_channel_test()?;
        let approval_helper = VerifiedHelper::for_approval_channel_test(true)?;
        assert_eq!(require_secret_input_frontend(&secret_helper), Ok(()));
        assert_eq!(
            require_secret_input_frontend(&approval_helper),
            Err(SecretInputChannelError::WrongHelperRole)
        );
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn high_level_launch_rejects_wrong_role_before_pipe_or_process_side_effects()
    -> Result<(), Box<dyn std::error::Error>> {
        let wrong_role = VerifiedHelper::for_approval_channel_test(true)?;
        let launcher =
            RestrictedLauncher::new(ReleaseAttestation::default(), NoNetworkLpacProfile::v1());
        assert!(matches!(
            launch_secret_input_frontend(
                launcher,
                &wrong_role,
                &prompt(12, 64),
                future_deadline()?,
            ),
            Err(SecretInputLaunchError::WrongHelperRole)
        ));
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn high_level_launch_cleans_private_pipes_when_release_gate_is_disabled()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret_frontend = VerifiedHelper::for_secret_input_channel_test()?;
        for _ in 0..32 {
            let launcher =
                RestrictedLauncher::new(ReleaseAttestation::default(), NoNetworkLpacProfile::v1());
            let launch = launch_secret_input_frontend(
                launcher,
                &secret_frontend,
                &prompt(12, 64),
                future_deadline()?,
            );
            assert!(
                matches!(
                    &launch,
                    Err(SecretInputLaunchError::Launch(
                        LaunchError::ReleaseNotAttested
                    ))
                ),
                "unexpected fail-closed result: {launch:?}"
            );
        }
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn high_level_launch_rejects_expired_deadline_before_pipe_creation()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret_frontend = VerifiedHelper::for_secret_input_channel_test()?;
        let launcher =
            RestrictedLauncher::new(ReleaseAttestation::default(), NoNetworkLpacProfile::v1());
        let expired = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .ok_or("monotonic clock cannot represent test deadline")?;
        assert!(matches!(
            launch_secret_input_frontend(launcher, &secret_frontend, &prompt(12, 64), expired,),
            Err(SecretInputLaunchError::DeadlineElapsed)
        ));
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn high_level_launch_rejects_deadline_beyond_ui_window()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret_frontend = VerifiedHelper::for_secret_input_channel_test()?;
        let launcher =
            RestrictedLauncher::new(ReleaseAttestation::default(), NoNetworkLpacProfile::v1());
        let too_far = Instant::now()
            .checked_add(Duration::from_mins(3))
            .ok_or("monotonic clock cannot represent test deadline")?;
        assert!(matches!(
            launch_secret_input_frontend(launcher, &secret_frontend, &prompt(12, 64), too_far),
            Err(SecretInputLaunchError::DeadlineTooFar)
        ));
        Ok(())
    }

    #[test]
    fn public_proof_has_no_clone_and_no_secret_bearing_debug_derives() {
        fn assert_debug<T: fmt::Debug>() {}
        assert_debug::<VerifiedSecretInput>();
    }
}
