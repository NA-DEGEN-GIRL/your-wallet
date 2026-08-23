//! Dormant binding between one release-prepared Approval artifact and the
//! exact storage-proven Key Agent selected as its future logical parent.
//!
//! This module allocates only one narrow process-handle duplicate inside the
//! Key Agent supervisor transition. It creates no process, thread, Job, pipe,
//! channel, token object, attribute list, or launch state, retains no token
//! handle, and exposes no production activation operation. A `cfg(test)`-only
//! transition now proves narrow logical-parent handle/token usability in an
//! actual Approval LPAC. The resulting private typestate remains non-runtime-
//! ready: mapped-image provenance, a separate supervisor principal,
//! process/thread creation-time DACLs, endpoint topology, production cleanup,
//! and orchestration remain unproved.

use core::fmt;

use thiserror::Error;

use crate::approval_supervisor::PreparedReleaseApprovalSupervisor;
#[cfg(test)]
use crate::key_agent_supervisor::prepare_approval_parent_source_for_kernel_test;
use crate::key_agent_supervisor::{
    ApprovalParentSourcePreparedKeyAgent, BoundStorageProvenKeyAgent, KeyAgentSupervisorError,
    prepare_approval_parent_source,
};
#[cfg(test)]
use crate::launch::prove_approval_parent_in_lpac_for_kernel_test;

/// Stable failure at the dormant Approval/Key Agent parent-binding boundary.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum ApprovalParentBindingError {
    /// The exact storage-proven Key Agent could not mint or retain the narrow
    /// logical-parent process capability.
    #[error("Approval parent source is unavailable")]
    ParentSourceUnavailable,
}

impl From<KeyAgentSupervisorError> for ApprovalParentBindingError {
    fn from(_error: KeyAgentSupervisorError) -> Self {
        Self::ParentSourceUnavailable
    }
}

/// One dormant release-prepared Approval artifact bound by ownership to one
/// exact storage-proven Key Agent logical-parent source.
///
/// The non-cloneable value exposes no constituent, identity, process handle,
/// PID, path, launch, or resource accessor. Field order is security-significant:
/// drop and unwind terminate the Key Agent process tree before releasing the
/// held Approval file. This ownership binding alone does not prove that an
/// production Approval process exists or can use the retained least-authority
/// handle; that narrower fact is covered only by a repo-local kernel test.
#[must_use = "dropping the parent-bound Approval supervisor terminates its exact Key Agent tree"]
pub(crate) struct ParentBoundReleaseApprovalSupervisor {
    parent_source: ApprovalParentSourcePreparedKeyAgent,
    approval: PreparedReleaseApprovalSupervisor,
}

impl fmt::Debug for ParentBoundReleaseApprovalSupervisor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "ParentBoundReleaseApprovalSupervisor([HELD APPROVAL; STORAGE-PROVEN EXACT KEY AGENT PARENT SOURCE])",
        )
    }
}

/// Consumes both complete proof aggregates into one dormant ownership binding.
///
/// The Key Agent transition performs all pre/post liveness, storage, Job, and
/// topology revalidation while minting its exact non-inheritable
/// `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE` duplicate. This function
/// has no production caller until the remaining Approval isolation proofs are
/// implemented.
pub(crate) fn bind_release_approval_parent(
    approval: PreparedReleaseApprovalSupervisor,
    storage_proven: BoundStorageProvenKeyAgent,
) -> Result<ParentBoundReleaseApprovalSupervisor, ApprovalParentBindingError> {
    let parent_source = prepare_approval_parent_source(storage_proven)?;
    Ok(ParentBoundReleaseApprovalSupervisor {
        parent_source,
        approval,
    })
}

/// Test-runner equivalent that admits only the pinned libtest topology already
/// used by the integrated Key Agent kernel fixture.
#[cfg(test)]
pub(crate) fn bind_release_approval_parent_for_kernel_test(
    approval: PreparedReleaseApprovalSupervisor,
    storage_proven: BoundStorageProvenKeyAgent,
) -> Result<ParentBoundReleaseApprovalSupervisor, ApprovalParentBindingError> {
    let parent_source = prepare_approval_parent_source_for_kernel_test(storage_proven)?;
    Ok(ParentBoundReleaseApprovalSupervisor {
        parent_source,
        approval,
    })
}

/// Executes the test-only real Approval LPAC proof without exposing either
/// aggregate constituent or enabling a production launch path.
#[cfg(test)]
pub(crate) fn verify_parent_bound_approval_lpac_for_kernel_test(
    bound: &ParentBoundReleaseApprovalSupervisor,
) -> Result<(), crate::launch::ApprovalParentProbeError> {
    bound
        .parent_source
        .revalidate_for_lpac_probe()
        .map_err(|_| crate::launch::ApprovalParentProbeError::ParentState)?;
    prove_approval_parent_in_lpac_for_kernel_test(
        bound.approval.artifact_for_parent_probe(),
        bound.parent_source.parent_process_for_lpac_probe(),
    )?;
    bound
        .parent_source
        .revalidate_for_lpac_probe()
        .map_err(|_| crate::launch::ApprovalParentProbeError::ParentState)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ApprovalParentBindingError, ParentBoundReleaseApprovalSupervisor};
    use crate::key_agent_supervisor::KeyAgentSupervisorError;

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
    fn parent_binding_is_unique_and_collapses_internal_failures() {
        let _ = <ParentBoundReleaseApprovalSupervisor as AmbiguousIfClone<_>>::marker;
        let _ = <ParentBoundReleaseApprovalSupervisor as AmbiguousIfCopy<_>>::marker;
        assert_eq!(
            ApprovalParentBindingError::from(KeyAgentSupervisorError::Activation),
            ApprovalParentBindingError::ParentSourceUnavailable
        );
    }
}
