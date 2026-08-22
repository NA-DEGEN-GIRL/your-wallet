//! Dormant supervisor-owned bootstrap state for the Key Agent.
//!
//! This module deliberately contains no process-resume operation. The startup
//! nonce and monotonic deadline belong to the external supervisor boundary;
//! they are separate from the Key Agent's protected-settings lease, which may
//! be issued only after the Key Agent has started and revalidated its own
//! authenticated settings state.

#![allow(dead_code)]

use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;
use std::time::{Duration, Instant};

use subtle::ConstantTimeEq as _;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::attestation::ReleaseAttestation;
use crate::helper::VerifiedHelper;
use crate::key_agent_activation::{
    HeldKeyAgentActivation, KeyAgentActivationError,
    activate_preflighted_key_agent_on_fresh_worker, preflight_key_agent_activation,
    run_on_fresh_key_agent_debug_thread,
};
use crate::key_agent_root_job::{KeyAgentRootJob, KeyAgentRootJobError};
use crate::pipe::{KeyAgentRequestWriter, KeyAgentResponseReader, PipeError, PrivateKeyAgentPipes};

const ACTIVATION_NONCE_BYTES: usize = 32;
const MAX_STARTUP_LIFETIME: Duration = Duration::from_mins(2);
const RANDOMNESS_ATTEMPTS: usize = 4;

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
    /// monotonic deadline. The returned proof remains private to this module;
    /// a future resume path must consume it and recheck the deadline itself.
    fn verify_and_consume(
        self,
        candidate: &[u8; ACTIVATION_NONCE_BYTES],
    ) -> Result<VerifiedSupervisorHandshake, KeyAgentSupervisorError> {
        self.ensure_live()?;
        if self.nonce.as_ref().ct_eq(candidate).unwrap_u8() == 0 {
            return Err(KeyAgentSupervisorError::BindingMismatch);
        }
        Ok(VerifiedSupervisorHandshake {
            nonce: self.nonce,
            expires_at: self.expires_at,
        })
    }

    #[cfg(test)]
    fn verify_and_consume_at_for_test(
        self,
        candidate: &[u8; ACTIVATION_NONCE_BYTES],
        now: Instant,
    ) -> Result<VerifiedSupervisorHandshake, KeyAgentSupervisorError> {
        self.ensure_live_at_for_test(now)?;
        if self.nonce.as_ref().ct_eq(candidate).unwrap_u8() == 0 {
            return Err(KeyAgentSupervisorError::BindingMismatch);
        }
        Ok(VerifiedSupervisorHandshake {
            nonce: self.nonce,
            expires_at: self.expires_at,
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
}

impl VerifiedSupervisorHandshake {
    /// Final in-module deadline check for the future no-gap resume boundary.
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
            .finish()
    }
}

/// One exact Key Agent activation bound to all supervisor-owned resources.
///
/// This capability is crate-private, non-cloneable, and deliberately `!Sync`.
/// It owns the detached-and-suspended exact-image proof, the two-process
/// kill-on-close root Job, both unique parent pipe endpoints, and the one-shot
/// startup lease. The short-lived inheritable child handles and creation
/// attributes have already been dropped before this value can cross the fresh
/// worker join.
///
/// Field order is security-significant: dropping this value first aborts the
/// exact suspended process, then terminates the root Job, then closes the
/// parent channel endpoints, and finally zeroizes the startup nonce. No raw
/// handle, pipe name, debugger operation, or resume operation is exposed.
#[must_use = "dropping the dormant Key Agent capability aborts its suspended process tree"]
pub(crate) struct BoundDormantKeyAgent {
    activation: HeldKeyAgentActivation,
    root_job: KeyAgentRootJob,
    request_writer: KeyAgentRequestWriter,
    response_reader: KeyAgentResponseReader,
    startup_lease: SupervisorActivationLease,
    not_sync: PhantomData<Cell<()>>,
}

impl fmt::Debug for BoundDormantKeyAgent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundDormantKeyAgent")
            .field("activation", &"[DETACHED SUSPENDED KEY AGENT]")
            .field("root_job", &"[TWO-PROCESS KILL-ON-CLOSE ROOT JOB]")
            .field("request_writer", &"[UNIQUE PARENT REQUEST HANDLE]")
            .field("response_reader", &"[UNIQUE PARENT RESPONSE HANDLE]")
            .field("startup_lease", &"[ONE-SHOT NONCE AND MONOTONIC DEADLINE]")
            .finish_non_exhaustive()
    }
}

/// Preflights and binds one exact Key Agent without executing its user code.
///
/// Release, manifest-role, allowlist, and path checks happen before the worker
/// or any Job/pipe resource exists. The internally sampled startup deadline
/// therefore covers worker creation and the complete dormant binding. Inside
/// the activation-owned fresh worker, lifetime-bound Job and inherited-handle
/// attributes cannot escape the exact `CreateProcessW` call. The child remains
/// detached with one proven suspend count when the aggregate returns.
///
/// This function does not configure a Key Agent LPAC and cannot resume or arm
/// the process. Production remains fail-closed while release evidence is
/// absent and the Key Agent-only profile/storage policy is STOP-SHIP.
pub(crate) fn bind_dormant_key_agent(
    attestation: ReleaseAttestation,
    artifact: VerifiedHelper,
) -> Result<BoundDormantKeyAgent, KeyAgentSupervisorError> {
    let preflighted = preflight_key_agent_activation(attestation, artifact)?;
    let startup_lease = SupervisorActivationLease::issue(MAX_STARTUP_LIFETIME)?;

    run_on_fresh_key_agent_debug_thread(move |fresh_thread| {
        startup_lease.ensure_live()?;
        let root_job = KeyAgentRootJob::create()?;
        let pipes = PrivateKeyAgentPipes::create()?;
        let root_job_attribute = root_job.creation_attribute()?;

        let activation = activate_preflighted_key_agent_on_fresh_worker(
            fresh_thread,
            preflighted,
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
        startup_lease.ensure_live()?;
        Ok(BoundDormantKeyAgent {
            activation,
            root_job,
            request_writer,
            response_reader,
            startup_lease,
            not_sync: PhantomData,
        })
    })
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
) -> Result<BoundDormantKeyAgent, KeyAgentSupervisorError> {
    let preflighted = preflight_key_agent_activation(attestation, artifact)?;
    let startup_lease = SupervisorActivationLease::issue(MAX_STARTUP_LIFETIME)?;

    run_on_fresh_key_agent_debug_thread(move |fresh_thread| {
        startup_lease.ensure_live()?;
        let root_job = KeyAgentRootJob::create_for_kernel_test()?;
        let pipes = PrivateKeyAgentPipes::create()?;
        let root_job_attribute = root_job.creation_attribute()?;
        let activation = activate_preflighted_key_agent_on_fresh_worker(
            fresh_thread,
            preflighted,
            &pipes,
            &root_job,
            &root_job_attribute,
            startup_lease.expires_at(),
        )?;
        drop(root_job_attribute);

        root_job.verify_effective_limits()?;
        if root_job.active_process_count()? != 1 {
            return Err(KeyAgentSupervisorError::RootJobPolicy);
        }
        let (request_writer, response_reader) = pipes.into_parent();
        startup_lease.ensure_live()?;
        Ok(BoundDormantKeyAgent {
            activation,
            root_job,
            request_writer,
            response_reader,
            startup_lease,
            not_sync: PhantomData,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::{
        ACTIVATION_NONCE_BYTES, BoundDormantKeyAgent, KeyAgentSupervisorError,
        MAX_STARTUP_LIFETIME, SupervisorActivationLease, bind_dormant_key_agent_for_kernel_test,
    };
    use crate::attestation::ReleaseAttestation;
    use crate::helper::VerifiedHelper;
    use crate::key_agent_activation::KeyAgentActivationError;
    use crate::key_agent_root_job::KeyAgentRootJobError;
    use crate::pipe::{PipeError, key_agent_parent_endpoints_are_noninheritable_for_test};
    use std::time::{Duration, Instant};

    const REJECTED_PROCESS_EXIT_CODE: u32 = 0xE0A0_0001;

    fn attestation_for(artifact: &VerifiedHelper) -> ReleaseAttestation {
        ReleaseAttestation::with_helper_manifests_for_test([
            artifact.manifest_digest(),
            [25; 32],
            [26; 32],
        ])
    }

    #[test]
    fn lease_is_fresh_nonzero_and_one_attempt_specific() -> Result<(), KeyAgentSupervisorError> {
        let first = SupervisorActivationLease::issue(Duration::from_secs(30))?;
        let second = SupervisorActivationLease::issue(Duration::from_secs(30))?;

        assert_ne!(first.nonce_for_child(), &[0; ACTIVATION_NONCE_BYTES]);
        assert_ne!(first.nonce_for_child(), second.nonce_for_child());
        let echoed = *first.nonce_for_child();
        assert!(first.verify_and_consume(&echoed)?.is_live());
        Ok(())
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
                        .ok_or(KeyAgentSupervisorError::DeadlineUnavailable,)?
                )
                .is_ok()
        );
        let expired =
            SupervisorActivationLease::with_test_parts([1; ACTIVATION_NONCE_BYTES], exact_expiry);
        assert!(matches!(
            expired.verify_and_consume_at_for_test(&[1; ACTIVATION_NONCE_BYTES], exact_expiry),
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
            lease.verify_and_consume_at_for_test(&[2; ACTIVATION_NONCE_BYTES], now),
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
    }

    #[test]
    fn integrated_kernel_binding_owns_one_member_and_no_inheritable_parent_handles()
    -> Result<(), Box<dyn std::error::Error>> {
        let artifact = VerifiedHelper::for_key_agent_activation_test()?;
        let attestation = attestation_for(&artifact);
        let bound = bind_dormant_key_agent_for_kernel_test(attestation, artifact)?;

        assert!(bound.activation.is_detached_and_suspended());
        assert!(
            bound
                .activation
                .is_member_of_root_job_for_test(&bound.root_job)?
        );
        assert_eq!(bound.root_job.active_process_count()?, 1);
        assert!(bound.root_job.verify_effective_limits().is_ok());
        assert!(key_agent_parent_endpoints_are_noninheritable_for_test(
            &bound.request_writer,
            &bound.response_reader,
        )?);

        let process_id = bound.activation.process_id();
        let creation_time = bound.activation.creation_time();
        let rendered = format!("{bound:?}");
        assert!(rendered.contains("BoundDormantKeyAgent"));
        assert!(!rendered.contains(&process_id.to_string()));
        assert!(!rendered.contains(&creation_time.to_string()));

        let observation = bound.activation.duplicate_process_observation()?;
        drop(bound);
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
        let bound = bind_dormant_key_agent_for_kernel_test(attestation, artifact)?;
        let observation = bound.activation.duplicate_process_observation()?;

        let worker = std::thread::spawn(move || {
            let _dormant_cleanup_guard = bound;
            std::panic::resume_unwind(Box::new("intentional dormant aggregate unwind test"));
        });
        assert!(worker.join().is_err());
        assert_eq!(
            observation.rejected_exit_code()?,
            REJECTED_PROCESS_EXIT_CODE
        );
        Ok(())
    }
}
