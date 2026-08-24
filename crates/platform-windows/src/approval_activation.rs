//! Sealed Approval activation bound to one exact Key Agent.
//!
//! This module advances the private release typestate through one authenticated
//! bootstrap and a separate consuming full-exchange transition. The terminal
//! exchange remains opaque, has no production caller, and exposes no response,
//! signing, raw-handle, PID, path, profile, policy, or caller-directed resume
//! operation. The existing channel-supervisor proof remains distinct from the
//! separately injected logical Key Agent capability.

use core::fmt;
use std::time::{Duration, Instant};

use approval_wire::{
    ApprovalChildHello, ApprovalParentHello, ApprovalRequest, CHILD_HELLO_BYTES,
    MAX_EXPIRY_MILLISECONDS, decode_child_hello, encode_parent_finish, encode_parent_hello,
};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::approval_channel::{
    ApprovalChannelError, ParentBoundApprovalResponseEvidence, arm_parent_bound_approval_response,
    seal_successful_parent_bound_approval_response, verify_parent_bound_approval_response,
};
use crate::approval_parent::{
    ParentBoundReleaseApprovalSupervisor, prepare_parent_bound_approval_activation,
    revalidate_parent_bound_approval_state,
};
use crate::launch::{
    HeldExitedApproval, HeldRunningApproval, HeldSuspendedApproval, InheritedStdio, LaunchError,
};
use crate::pipe::{ApprovalRequestWriter, ApprovalResponseReader, PipeError, PrivateApprovalPipes};

const APPROVAL_CLEANUP_GRACE: Duration = Duration::from_secs(5);
const APPROVAL_BOOTSTRAP_GRACE: Duration = Duration::from_secs(5);
const APPROVAL_NONCE_BYTES: usize = 32;

/// Unforgeable permission for the sealed parent-bound Approval transitions.
///
/// The field is private to this module. Other crate modules may accept a borrow
/// only while this module is executing one of its consuming transitions.
pub(crate) struct ApprovalActivationSeal {
    _private: (),
}

/// Stable failures from dormant parent-bound Approval preparation.
///
/// Raw operating-system, pipe, process, path, and identity details are
/// intentionally collapsed at this boundary.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum ApprovalActivationError {
    /// The exact storage-proven Key Agent or its logical-parent proof changed.
    #[error("Approval logical parent state is unavailable")]
    ParentState,
    /// The two private one-shot Approval pipes could not be created exactly.
    #[error("Approval private channel preparation failed")]
    PrivateChannel,
    /// The suspended zero-capability Approval process could not be prepared.
    #[error("dormant Approval activation failed")]
    Activation,
    /// The sealed parent/child hello exchange could not be authenticated.
    #[error("Approval bootstrap authentication failed")]
    Bootstrap,
    /// The sealed finish/request/response exchange could not be completed and
    /// authenticated before its request-derived monotonic deadline.
    #[error("Approval full exchange authentication failed")]
    Exchange,
    /// Explicit rejection cleanup could not synchronously reap an Approval
    /// process. Drop-only cleanup failures cannot be represented here and retain
    /// the kill-on-close fallback.
    #[error("Approval cleanup failed")]
    Cleanup,
}

impl From<PipeError> for ApprovalActivationError {
    fn from(_error: PipeError) -> Self {
        Self::PrivateChannel
    }
}

impl From<LaunchError> for ApprovalActivationError {
    fn from(error: LaunchError) -> Self {
        match error {
            LaunchError::Cleanup => Self::Cleanup,
            _ => Self::Activation,
        }
    }
}

/// One exact Approval process held before its first user-mode instruction.
///
/// The value is non-cloneable and deliberately exposes no operation. Its
/// supervisor-side endpoints are retained only for the sealed bootstrap and
/// full-exchange transitions. Field order is security-significant: explicit
/// `Drop` first takes the Approval child and makes its bounded synchronous
/// terminate/reap attempt;
/// the retained kill-on-close Job/process ownership then closes before the
/// endpoints and complete parent-bound Key Agent aggregate. A Drop-only cleanup
/// error cannot be returned.
#[must_use = "dropping dormant Approval only attempts bounded cleanup before kill-on-close fallback"]
pub(crate) struct BoundDormantApproval {
    activation: Option<HeldApprovalActivation>,
    request_writer: Option<ApprovalRequestWriter>,
    response_reader: Option<ApprovalResponseReader>,
    bound: Option<ParentBoundReleaseApprovalSupervisor>,
}

impl fmt::Debug for BoundDormantApproval {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.activation,
            &self.request_writer,
            &self.response_reader,
            &self.bound,
        );
        formatter.write_str(
            "BoundDormantApproval([SUSPENDED APPROVAL; PRIVATE ENDPOINTS; PARENT-BOUND KEY AGENT])",
        )
    }
}

#[cfg(test)]
impl BoundDormantApproval {
    /// Observes only that the exact suspended child remains live in its retained
    /// one-process Job. No process identifier, handle, thread, resume, protocol,
    /// or constituent capability is exposed to the test caller.
    pub(crate) fn is_live_in_job_for_test(&self) -> Result<bool, LaunchError> {
        self.activation
            .as_ref()
            .ok_or(LaunchError::OperatingSystem)?
            .is_live_in_job_for_test()
    }
}

impl Drop for BoundDormantApproval {
    fn drop(&mut self) {
        if let Some(activation) = self.activation.take() {
            let _ = terminate_held_approval(activation);
        }
    }
}

enum HeldApprovalActivation {
    Suspended(HeldSuspendedApproval),
    Running(HeldRunningApproval),
}

impl HeldApprovalActivation {
    #[cfg(test)]
    fn is_live_in_job_for_test(&self) -> Result<bool, LaunchError> {
        match self {
            Self::Suspended(activation) => activation.is_live_in_job_for_test(),
            Self::Running(activation) => activation.is_live_in_job_for_test(),
        }
    }

    fn terminate_and_wait(self, deadline: Instant) -> Result<(), LaunchError> {
        match self {
            Self::Suspended(activation) => activation.terminate_and_wait(deadline),
            Self::Running(activation) => activation.terminate_and_wait(deadline),
        }
    }
}

impl fmt::Debug for HeldApprovalActivation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Suspended(_) => formatter.write_str("HeldApprovalActivation([SUSPENDED])"),
            Self::Running(_) => formatter.write_str("HeldApprovalActivation([RUNNING])"),
        }
    }
}

/// One exact running Approval held after its authenticated child hello.
///
/// The value is opaque, non-cloneable, and has no methods. Only the separate
/// activation-sealed consuming full-exchange function can provide its request;
/// no response, signing, raw resource, or partial protocol capability escapes.
/// Until consumed, the child remains blocked waiting for the missing finish.
/// Field order is security-significant: dropping `dormant` first makes its
/// bounded synchronous terminate/reap attempt and closes child Job/process
/// ownership before its endpoints and complete Key Agent aggregate close;
/// transcript material is released only afterward.
#[must_use = "dropping authenticated Approval only attempts bounded cleanup before kill-on-close fallback"]
pub(crate) struct AuthenticatedApprovalBootstrap {
    dormant: BoundDormantApproval,
    parent_hello: ApprovalParentHello,
    child_hello: ApprovalChildHello,
}

impl fmt::Debug for AuthenticatedApprovalBootstrap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.dormant, &self.parent_hello, &self.child_hello);
        formatter.write_str(
            "AuthenticatedApprovalBootstrap([RUNNING HELD APPROVAL; PRIVATE ENDPOINTS; PARENT-BOUND KEY AGENT; REDACTED HELLOS])",
        )
    }
}

/// Terminal, parent-bound Approval exchange evidence with no outward surface.
///
/// The exact exited child objects, intact Key Agent aggregate, both bootstrap
/// hellos, and sealed response evidence remain co-owned. This type has no
/// methods or conversions into [`crate::approval_channel::VerifiedApprovalResponse`]
/// or signing authority and is deliberately non-cloneable and non-copyable.
#[must_use = "retain the complete parent-bound Approval exchange evidence"]
pub(crate) struct VerifiedParentBoundApprovalExchange {
    exited_child: HeldExitedApproval,
    bound: ParentBoundReleaseApprovalSupervisor,
    parent_hello: ApprovalParentHello,
    child_hello: ApprovalChildHello,
    response_evidence: ParentBoundApprovalResponseEvidence,
}

impl fmt::Debug for VerifiedParentBoundApprovalExchange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.exited_child,
            &self.bound,
            &self.parent_hello,
            &self.child_hello,
            &self.response_evidence,
        );
        formatter.write_str("VerifiedParentBoundApprovalExchange([SEALED COMPLETE EVIDENCE])")
    }
}

/// Consumes the complete parent-bound aggregate into suspended dormant state.
///
/// The fixed Approval LPAC revision is selected only inside the sealed launch
/// leaf. This transition accepts no request, response, deadline, path, PID,
/// profile, attestation, command line, or generic launcher input and never
/// resumes the child.
pub(crate) fn bind_dormant_parent_bound_approval(
    bound: ParentBoundReleaseApprovalSupervisor,
) -> Result<BoundDormantApproval, ApprovalActivationError> {
    let pipes = PrivateApprovalPipes::create()?;
    let inherited = InheritedStdio::for_child_pipe_servers(
        pipes.child_input(),
        pipes.child_output(),
        pipes.child_output(),
    )?;
    let seal = ApprovalActivationSeal { _private: () };
    let activation = prepare_parent_bound_approval_activation(&bound, &inherited, &seal)?;
    let (request_writer, response_reader) = pipes.into_parent();

    Ok(BoundDormantApproval {
        activation: Some(HeldApprovalActivation::Suspended(activation)),
        request_writer: Some(request_writer),
        response_reader: Some(response_reader),
        bound: Some(bound),
    })
}

/// Consumes dormant state into one authenticated, hello-only bootstrap.
///
/// The transition samples its own fixed monotonic deadline and fresh nonzero
/// nonce. It writes the complete five-object parent hello while the child is
/// still suspended, resumes only the retained primary thread through this
/// module's seal, reads one exact child hello, and revalidates both the running
/// process and intact parent-bound aggregate. No caller supplies protocol,
/// identity, resource, policy, timing, or signing input.
///
/// Every rejection makes a synchronous terminate/reap attempt for the already-
/// created child with a fresh bounded cleanup deadline. Cleanup failure takes
/// precedence over the bootstrap failure; kill-on-close ownership remains the
/// final fallback before endpoint and Key Agent aggregate release.
pub(crate) fn authenticate_parent_bound_approval_bootstrap(
    mut dormant: BoundDormantApproval,
) -> Result<AuthenticatedApprovalBootstrap, ApprovalActivationError> {
    let bootstrap = (|| {
        let deadline = Instant::now()
            .checked_add(APPROVAL_BOOTSTRAP_GRACE)
            .ok_or(ApprovalActivationError::Bootstrap)?;
        let mut parent_nonce = Zeroizing::new([0_u8; APPROVAL_NONCE_BYTES]);
        getrandom::fill(&mut *parent_nonce).map_err(|_| ApprovalActivationError::Bootstrap)?;
        if is_all_zero(parent_nonce.as_slice()) {
            return Err(ApprovalActivationError::Bootstrap);
        }

        let seal = ApprovalActivationSeal { _private: () };
        revalidate_parent_bound_approval_state(
            dormant
                .bound
                .as_ref()
                .ok_or(ApprovalActivationError::ParentState)?,
            &seal,
        )?;
        let parent_hello = match dormant.activation.as_ref() {
            Some(HeldApprovalActivation::Suspended(activation)) => {
                activation.parent_hello_for_bootstrap(*parent_nonce, &seal)?
            }
            Some(HeldApprovalActivation::Running(_)) | None => {
                return Err(ApprovalActivationError::Activation);
            }
        };
        let encoded_parent_hello = Zeroizing::new(encode_parent_hello(&parent_hello));
        dormant
            .request_writer
            .as_mut()
            .ok_or(ApprovalActivationError::Activation)?
            .write_bytes(encoded_parent_hello.as_slice(), deadline)
            .map_err(|_| ApprovalActivationError::Bootstrap)?;

        // The complete hello must be committed to the pipe before this sole
        // production resume edge can execute.
        revalidate_parent_bound_approval_state(
            dormant
                .bound
                .as_ref()
                .ok_or(ApprovalActivationError::ParentState)?,
            &seal,
        )?;
        let suspended = match dormant.activation.take() {
            Some(HeldApprovalActivation::Suspended(activation)) => activation,
            Some(HeldApprovalActivation::Running(activation)) => {
                dormant.activation = Some(HeldApprovalActivation::Running(activation));
                return Err(ApprovalActivationError::Activation);
            }
            None => return Err(ApprovalActivationError::Activation),
        };
        let running = suspended.resume_for_bootstrap(&seal)?;
        dormant.activation = Some(HeldApprovalActivation::Running(running));

        let child_hello_bytes = dormant
            .response_reader
            .as_ref()
            .ok_or(ApprovalActivationError::Activation)?
            .read_exact(CHILD_HELLO_BYTES, deadline)
            .map_err(|_| ApprovalActivationError::Bootstrap)?;
        let child_hello = decode_child_hello(&parent_hello, &child_hello_bytes)
            .map_err(|_| ApprovalActivationError::Bootstrap)?;
        match dormant.activation.as_ref() {
            Some(HeldApprovalActivation::Running(activation)) => {
                activation.revalidate_for_bootstrap(&seal)?;
            }
            Some(HeldApprovalActivation::Suspended(_)) | None => {
                return Err(ApprovalActivationError::Activation);
            }
        }
        revalidate_parent_bound_approval_state(
            dormant
                .bound
                .as_ref()
                .ok_or(ApprovalActivationError::ParentState)?,
            &seal,
        )?;

        Ok((parent_hello, child_hello))
    })();

    match bootstrap {
        Ok((parent_hello, child_hello)) => Ok(AuthenticatedApprovalBootstrap {
            dormant,
            parent_hello,
            child_hello,
        }),
        Err(error) => {
            if let Some(activation) = dormant.activation.take() {
                terminate_held_approval(activation)?;
            }
            Err(error)
        }
    }
}

/// Consumes one authenticated bootstrap and request into terminal sealed
/// parent-bound exchange evidence.
///
/// A single monotonic deadline is sampled internally from the validated
/// request lifetime and shared by arming, finish/request transfer, fixed
/// response+EOF verification, and natural child exit. The parent-local
/// transcript salt is freshly sampled while arming and is never sent to the
/// child. The exact operation order is fail-closed: pre-arm child/Job and Key
/// Agent revalidation; arm; consuming finish write and EOF; pre-read child/Job
/// and Key Agent revalidation; fixed response and transcript verification;
/// consuming natural exit-code-zero wait; final Key Agent revalidation; final
/// observation of the same deadline; then evidence minting.
///
/// Rejections before the natural-exit transition use the outer retained child
/// for a fresh bounded terminate/reap attempt. Wait or exit-code rejection owns
/// its own bounded cleanup. In both cases cleanup failure takes precedence.
/// There is intentionally no production caller and the terminal value exposes
/// no response/signing conversion.
#[allow(clippy::too_many_lines)] // Keep the security-significant protocol and cleanup order linear.
pub(crate) fn complete_parent_bound_approval_exchange(
    authenticated: AuthenticatedApprovalBootstrap,
    request: &ApprovalRequest,
) -> Result<VerifiedParentBoundApprovalExchange, ApprovalActivationError> {
    let AuthenticatedApprovalBootstrap {
        mut dormant,
        parent_hello,
        child_hello,
    } = authenticated;
    let mut parent_hello = Some(parent_hello);
    let mut child_hello = Some(child_hello);
    let exchange = (|| {
        let expiry_milliseconds = request.expires_after_milliseconds();
        if !(1..=MAX_EXPIRY_MILLISECONDS).contains(&expiry_milliseconds) {
            return Err(ApprovalActivationError::Exchange);
        }
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(u64::from(expiry_milliseconds)))
            .ok_or(ApprovalActivationError::Exchange)?;
        let seal = ApprovalActivationSeal { _private: () };

        let pre_arm_identity = match dormant.activation.as_ref() {
            Some(HeldApprovalActivation::Running(activation)) => activation
                .revalidated_identity_for_exchange(&seal)
                .map_err(map_exchange_launch_error)?,
            Some(HeldApprovalActivation::Suspended(_)) | None => {
                return Err(ApprovalActivationError::Activation);
            }
        };
        revalidate_parent_bound_approval_state(
            dormant
                .bound
                .as_ref()
                .ok_or(ApprovalActivationError::ParentState)?,
            &seal,
        )?;

        let response_reader = dormant
            .response_reader
            .take()
            .ok_or(ApprovalActivationError::Activation)?;
        let armed_response = arm_parent_bound_approval_response(
            pre_arm_identity,
            parent_hello
                .as_ref()
                .ok_or(ApprovalActivationError::Exchange)?,
            child_hello
                .as_ref()
                .ok_or(ApprovalActivationError::Exchange)?,
            request,
            deadline,
            response_reader,
            &seal,
        )
        .map_err(map_exchange_channel_error)?;

        let encoded_finish = Zeroizing::new(encode_parent_finish(
            parent_hello
                .as_ref()
                .ok_or(ApprovalActivationError::Exchange)?,
            child_hello
                .as_ref()
                .ok_or(ApprovalActivationError::Exchange)?,
            request,
        ));
        let request_writer = dormant
            .request_writer
            .take()
            .ok_or(ApprovalActivationError::Activation)?;
        // Consuming the endpoint closes it immediately after the exact finish
        // (which contains the canonical request) is written, giving the child
        // the required unambiguous EOF boundary.
        request_writer
            .write_all(encoded_finish.as_slice(), deadline)
            .map_err(|_| ApprovalActivationError::Exchange)?;

        let pre_read_identity = match dormant.activation.as_ref() {
            Some(HeldApprovalActivation::Running(activation)) => activation
                .revalidated_identity_for_exchange(&seal)
                .map_err(map_exchange_launch_error)?,
            Some(HeldApprovalActivation::Suspended(_)) | None => {
                return Err(ApprovalActivationError::Activation);
            }
        };
        revalidate_parent_bound_approval_state(
            dormant
                .bound
                .as_ref()
                .ok_or(ApprovalActivationError::ParentState)?,
            &seal,
        )?;

        let exit_pending_response =
            verify_parent_bound_approval_response(armed_response, pre_read_identity, &seal)
                .map_err(map_exchange_channel_error)?;

        // EOF and response authentication do not prove successful child exit.
        // Consume the running typestate so a second wait or cleanup owner cannot
        // exist in safe Rust. This transition performs cleanup itself on error.
        let running = match dormant.activation.take() {
            Some(HeldApprovalActivation::Running(activation)) => activation,
            Some(HeldApprovalActivation::Suspended(activation)) => {
                dormant.activation = Some(HeldApprovalActivation::Suspended(activation));
                return Err(ApprovalActivationError::Activation);
            }
            None => return Err(ApprovalActivationError::Activation),
        };
        let exited_child = running
            .wait_for_success_for_exchange(deadline, &seal)
            .map_err(map_exchange_launch_error)?;

        // This is point-in-time terminal evidence, not a durable liveness
        // claim. The result has no consumer; any future authorization edge must
        // revalidate the retained exact Key Agent again immediately before use.
        revalidate_parent_bound_approval_state(
            dormant
                .bound
                .as_ref()
                .ok_or(ApprovalActivationError::ParentState)?,
            &seal,
        )?;
        if deadline_elapsed(deadline) {
            return Err(ApprovalActivationError::Exchange);
        }
        let bound = dormant
            .bound
            .take()
            .ok_or(ApprovalActivationError::ParentState)?;
        let parent_hello = parent_hello
            .take()
            .ok_or(ApprovalActivationError::Exchange)?;
        let child_hello = child_hello
            .take()
            .ok_or(ApprovalActivationError::Exchange)?;
        // No fallible operation remains after evidence minting. All exact
        // ownership required by the terminal aggregate is already local.
        let response_evidence =
            seal_successful_parent_bound_approval_response(exit_pending_response, &seal);
        Ok(VerifiedParentBoundApprovalExchange {
            exited_child,
            bound,
            parent_hello,
            child_hello,
            response_evidence,
        })
    })();

    // Earlier failures still retain the running activation here. Natural-exit
    // success or wait rejection consumed it and already proved or cleaned the
    // exact process. Any explicit cleanup failure overrides the exchange error.
    let cleanup = match dormant.activation.take() {
        Some(activation) => terminate_held_approval(activation),
        None => Ok(()),
    };
    resolve_after_cleanup(exchange, cleanup)
}

const fn map_exchange_channel_error(_error: ApprovalChannelError) -> ApprovalActivationError {
    ApprovalActivationError::Exchange
}

const fn map_exchange_launch_error(error: LaunchError) -> ApprovalActivationError {
    if matches!(error, LaunchError::Cleanup) {
        ApprovalActivationError::Cleanup
    } else {
        ApprovalActivationError::Exchange
    }
}

fn resolve_after_cleanup<T>(
    exchange: Result<T, ApprovalActivationError>,
    cleanup: Result<(), ApprovalActivationError>,
) -> Result<T, ApprovalActivationError> {
    cleanup?;
    exchange
}

/// Synchronously terminates one rejected suspended Approval and waits at most
/// five seconds for the exact process object to become signalled.
pub(crate) fn terminate_suspended_approval(
    activation: HeldSuspendedApproval,
) -> Result<(), ApprovalActivationError> {
    let deadline = Instant::now()
        .checked_add(APPROVAL_CLEANUP_GRACE)
        .ok_or(ApprovalActivationError::Cleanup)?;
    activation
        .terminate_and_wait(deadline)
        .map_err(|_| ApprovalActivationError::Cleanup)
}

fn terminate_held_approval(
    activation: HeldApprovalActivation,
) -> Result<(), ApprovalActivationError> {
    let deadline = Instant::now()
        .checked_add(APPROVAL_CLEANUP_GRACE)
        .ok_or(ApprovalActivationError::Cleanup)?;
    activation
        .terminate_and_wait(deadline)
        .map_err(|_| ApprovalActivationError::Cleanup)
}

fn is_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn deadline_elapsed(deadline: Instant) -> bool {
    Instant::now().checked_duration_since(deadline).is_some()
}

#[cfg(test)]
mod tests {
    use approval_wire::ApprovalRequest;

    use super::{
        APPROVAL_NONCE_BYTES, ApprovalActivationError, ApprovalActivationSeal,
        AuthenticatedApprovalBootstrap, BoundDormantApproval, HeldApprovalActivation,
        VerifiedParentBoundApprovalExchange, authenticate_parent_bound_approval_bootstrap,
        complete_parent_bound_approval_exchange, is_all_zero, resolve_after_cleanup,
    };
    use crate::launch::{HeldExitedApproval, HeldRunningApproval, LaunchError};
    use crate::pipe::PipeError;

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

    #[test]
    fn dormant_activation_authority_and_state_are_move_only() {
        let _ = <ApprovalActivationSeal as AmbiguousIfClone<_>>::marker;
        let _ = <ApprovalActivationSeal as AmbiguousIfCopy<_>>::marker;
        let _ = <BoundDormantApproval as AmbiguousIfClone<_>>::marker;
        let _ = <BoundDormantApproval as AmbiguousIfCopy<_>>::marker;
        let _ = <HeldApprovalActivation as AmbiguousIfClone<_>>::marker;
        let _ = <HeldApprovalActivation as AmbiguousIfCopy<_>>::marker;
        let _ = <HeldRunningApproval as AmbiguousIfClone<_>>::marker;
        let _ = <HeldRunningApproval as AmbiguousIfCopy<_>>::marker;
        let _ = <AuthenticatedApprovalBootstrap as AmbiguousIfClone<_>>::marker;
        let _ = <AuthenticatedApprovalBootstrap as AmbiguousIfCopy<_>>::marker;
        let _ = <HeldExitedApproval as AmbiguousIfClone<_>>::marker;
        let _ = <HeldExitedApproval as AmbiguousIfCopy<_>>::marker;
        let _ = <VerifiedParentBoundApprovalExchange as AmbiguousIfClone<_>>::marker;
        let _ = <VerifiedParentBoundApprovalExchange as AmbiguousIfCopy<_>>::marker;
        let _: fn(
            BoundDormantApproval,
        ) -> Result<AuthenticatedApprovalBootstrap, ApprovalActivationError> =
            authenticate_parent_bound_approval_bootstrap;
        let _: fn(
            AuthenticatedApprovalBootstrap,
            &ApprovalRequest,
        ) -> Result<VerifiedParentBoundApprovalExchange, ApprovalActivationError> =
            complete_parent_bound_approval_exchange;
    }

    #[test]
    fn outer_errors_collapse_private_channel_and_launch_details() {
        assert_eq!(
            ApprovalActivationError::from(PipeError::OperatingSystem),
            ApprovalActivationError::PrivateChannel
        );
        assert_eq!(
            ApprovalActivationError::from(LaunchError::SandboxVerification),
            ApprovalActivationError::Activation
        );
        assert_eq!(
            ApprovalActivationError::from(LaunchError::Cleanup),
            ApprovalActivationError::Cleanup
        );
    }

    #[test]
    fn bootstrap_nonce_must_be_nonzero() {
        assert!(is_all_zero(&[0; APPROVAL_NONCE_BYTES]));
        assert!(!is_all_zero(&[1; APPROVAL_NONCE_BYTES]));
    }

    #[test]
    fn explicit_cleanup_failure_precedes_exchange_failure() {
        let result: Result<(), ApprovalActivationError> = resolve_after_cleanup(
            Err(ApprovalActivationError::Exchange),
            Err(ApprovalActivationError::Cleanup),
        );
        assert_eq!(result, Err(ApprovalActivationError::Cleanup));
        assert_eq!(
            resolve_after_cleanup::<()>(Err(ApprovalActivationError::Exchange), Ok(())),
            Err(ApprovalActivationError::Exchange)
        );
    }
}
