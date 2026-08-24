//! Dormant suspended Approval activation bound to one exact Key Agent.
//!
//! This module advances the private release typestate only as far as a held,
//! still-suspended Approval process. It exposes no request, response, resume,
//! signing, raw-handle, PID, path, profile, or policy-selection operation. The
//! existing channel-supervisor proof remains distinct from the separately
//! injected logical Key Agent parent capability.

use core::fmt;
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::approval_parent::{
    ParentBoundReleaseApprovalSupervisor, prepare_parent_bound_approval_activation,
};
use crate::launch::{HeldSuspendedApproval, InheritedStdio, LaunchError};
use crate::pipe::{ApprovalRequestWriter, ApprovalResponseReader, PipeError, PrivateApprovalPipes};

const APPROVAL_CLEANUP_GRACE: Duration = Duration::from_secs(5);

/// Unforgeable permission for the one parent-bound Approval activation leaf.
///
/// The field is private to this module. Other crate modules may accept a borrow
/// only while this module is executing its single consuming transition.
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
    /// A rejected or dropped Approval process could not be synchronously reaped.
    #[error("dormant Approval cleanup failed")]
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
/// supervisor-side endpoints are retained only for a future consuming protocol
/// transition. Field order is security-significant: explicit `Drop` first takes
/// and reaps the Approval child; the endpoints then close before the complete
/// parent-bound aggregate terminates the Key Agent and releases the pinned
/// Approval artifact.
#[must_use = "dropping dormant Approval state terminates its suspended process"]
pub(crate) struct BoundDormantApproval {
    activation: Option<HeldSuspendedApproval>,
    request_writer: ApprovalRequestWriter,
    response_reader: ApprovalResponseReader,
    bound: ParentBoundReleaseApprovalSupervisor,
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
            let _ = terminate_suspended_approval(activation);
        }
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
        activation: Some(activation),
        request_writer,
        response_reader,
        bound,
    })
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

#[cfg(test)]
mod tests {
    use super::{ApprovalActivationError, ApprovalActivationSeal, BoundDormantApproval};
    use crate::launch::LaunchError;
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
}
