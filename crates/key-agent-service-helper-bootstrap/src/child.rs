//! Child-side capture and adoption of debugger-injected service channels.

#![deny(unsafe_code)]

use core::fmt;
use core::marker::PhantomData;
use std::rc::Rc;

use crate::wire::HelperBootstrapRole;

#[allow(unsafe_code)]
mod windows;

/// Opaque ownership of the adopted request-input and response-output pipes.
///
/// The value exposes neither raw handles nor I/O. It is move-only and bound to
/// the capturing thread so a later protocol transition must consume it in the
/// same child-side bootstrap sequence.
#[must_use = "adopted injected channels must remain owned through bootstrap"]
pub struct AdoptedInjectedChannels {
    inner: windows::AdoptedInjectedChannels,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl fmt::Debug for AdoptedInjectedChannels {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdoptedInjectedChannels([SEALED PIPE HANDLES])")
    }
}

/// Opaque channels after service identity, deadline, acknowledgement, and the
/// adoption-complete debugger gate have all succeeded.
///
/// The value remains move-only and thread-bound. It exposes neither raw handles
/// nor I/O. It privately retains the zeroizing bootstrap correlation key and
/// absolute deadline for a later reviewed `HelperReady` transition; neither is
/// cloneable or exposed through a raw accessor.
#[must_use = "bootstrapped injected channels must remain owned through helper startup"]
pub struct BootstrappedInjectedChannels {
    _inner: windows::BootstrappedInjectedChannels,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl fmt::Debug for BootstrappedInjectedChannels {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BootstrappedInjectedChannels([SEALED PIPE HANDLES])")
    }
}

/// Captures and adopts the two debugger-injected channel candidates.
///
/// The fixed gate writes `r10` and `r11` into valid stack storage after the
/// debugger continues its authenticated breakpoint. Adoption then rejects
/// invalid, pseudo, standard-stream, aliased, inheritable, or non-pipe handles;
/// requests exact role-specific access masks for fresh non-inheritable
/// duplicates; closes both injected candidates; and revalidates the retained
/// duplicates. This feasibility layer does not claim that supported Win32
/// queries prove the source handles' granted access or pipe direction.
///
/// This function executes an `INT3` and is only for the dedicated helper
/// bootstrap while the expected parent debugger is attached. Calling it as a
/// general probe or without that debugger is expected to terminate the child;
/// there is no recoverable "debugger absent" result.
///
/// # Process termination
///
/// Every capture, validation, duplication, candidate-close, and final
/// revalidation failure aborts the child process immediately. No recoverable
/// error path may leave injected candidates in a continuing process. The
/// service-side parent must observe termination and reap the child.
pub fn capture_and_adopt_injected_channels() -> AdoptedInjectedChannels {
    let Ok(inner) = windows::capture_and_adopt_injected_channels() else {
        std::process::abort();
    };
    AdoptedInjectedChannels {
        inner,
        _not_send_or_sync: PhantomData,
    }
}

/// Consumes adopted channels, authenticates the service peer and bounded hello,
/// emits one exact adoption acknowledgement, and enters the independent
/// adoption-complete debugger gate before returning bootstrapped ownership.
/// `expected_role` must be fixed by the signed helper entrypoint; a canonical
/// hello for any other role is rejected before identity queries or an ACK.
/// The exact 100-byte canonical frame is read at the trusted service-owned
/// single-writer bootstrap boundary. The minimum-rights request handle is not
/// broadened merely to query or attribute subsequently queued bytes.
///
/// # Process termination
///
/// Every read, framing, role, identity, deadline, peer-process, and write
/// failure aborts the child immediately. Calling the second gate without the
/// expected parent debugger is likewise process-terminal. No recoverable path
/// may expose a partially bootstrapped helper channel.
pub fn complete_injected_channel_bootstrap(
    channels: AdoptedInjectedChannels,
    expected_role: HelperBootstrapRole,
) -> BootstrappedInjectedChannels {
    let Ok(inner) = windows::complete_injected_channel_bootstrap(channels.inner, expected_role)
    else {
        std::process::abort();
    };
    BootstrappedInjectedChannels {
        _inner: inner,
        _not_send_or_sync: PhantomData,
    }
}

/// Consumes bootstrapped channels, performs the fixed authenticated version-2
/// `HelperReady` RPC round trip, emits one exactly correlated confirmation,
/// closes the response pipe, and waits on the request pipe until the service
/// terminates the admitted helper.
///
/// `expected_role` must again be fixed by the signed helper entrypoint. It is
/// checked against the privately retained bootstrap correlation before any RPC
/// or pipe operation. The role is correlation evidence only: it is never sent
/// over RPC and cannot replace the service's expected-peer classification.
///
/// # Process termination
///
/// Every deadline, binding, authentication, RPC, acknowledgement, correlation,
/// confirmation-write, or response-close failure aborts the child. After a
/// successful confirmation, any request-pipe read completion is likewise
/// process-terminal. The function therefore never returns.
#[cfg(all(
    target_env = "msvc",
    feature = "helper-ready-rpc-feasibility-test-hook"
))]
pub fn complete_helper_ready_rpc_probe(
    channels: BootstrappedInjectedChannels,
    expected_role: HelperBootstrapRole,
) -> ! {
    let BootstrappedInjectedChannels {
        _inner: inner,
        _not_send_or_sync: _,
    } = channels;
    windows::complete_helper_ready_rpc_probe(inner, expected_role)
}

/// One canonical Approval request retained with its authenticated debug channels.
///
/// This move-only, thread-bound value is transport state, not approval or signing
/// authority. No handles, raw I/O, request replacement, or caller deadline escape.
#[cfg(all(
    target_env = "msvc",
    feature = "approval-exchange-feasibility-test-hook"
))]
#[must_use = "the one-shot service request must remain owned through presentation"]
pub struct ServiceApprovalRequest {
    inner: windows::ServiceApprovalRequest,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

#[cfg(all(
    target_env = "msvc",
    feature = "approval-exchange-feasibility-test-hook"
))]
impl fmt::Debug for ServiceApprovalRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServiceApprovalRequest([REDACTED])")
    }
}

#[cfg(all(
    target_env = "msvc",
    feature = "approval-exchange-feasibility-test-hook"
))]
impl ServiceApprovalRequest {
    /// Presents and binds exactly one decision, then awaits service termination.
    ///
    /// The original absolute bootstrap deadline is checked before and after the
    /// callback and every write. A presenter's relative UI timer cannot extend
    /// that deadline; the parent must enforce it while this thread is blocked.
    ///
    /// # Process termination
    /// A failed/late callback, I/O, or close aborts. After response EOF, any input
    /// completion also aborts; the parent owns final cancellation and reaping.
    pub fn present_and_respond(
        self,
        presenter: impl FnOnce(&approval_wire::ApprovalRequest) -> Option<approval_wire::Decision>,
    ) -> ! {
        self.inner.present_and_respond(presenter)
    }
}

/// Consumes the bootstrap, completes fixed-role Approval `HelperReady`, and reads
/// exactly one bounded length-prefixed canonical request on the retained pipe.
///
/// # Process termination
/// Every role, authentication, deadline, framing, and read failure aborts. This
/// debug feasibility transition never creates production authorization evidence.
#[cfg(all(
    target_env = "msvc",
    feature = "approval-exchange-feasibility-test-hook"
))]
pub fn receive_service_approval_request(
    channels: BootstrappedInjectedChannels,
) -> ServiceApprovalRequest {
    let BootstrappedInjectedChannels {
        _inner: inner,
        _not_send_or_sync: _,
    } = channels;
    let Ok(inner) = windows::receive_service_approval_request(inner) else {
        std::process::abort();
    };
    ServiceApprovalRequest {
        inner,
        _not_send_or_sync: PhantomData,
    }
}

#[cfg(test)]
mod tests {
    use core::fmt::Debug;

    #[cfg(all(
        target_env = "msvc",
        feature = "helper-ready-rpc-feasibility-test-hook"
    ))]
    use super::complete_helper_ready_rpc_probe;
    use super::{
        AdoptedInjectedChannels, BootstrappedInjectedChannels, capture_and_adopt_injected_channels,
        complete_injected_channel_bootstrap,
    };

    struct Invalid;

    trait AmbiguousIfSend<Marker> {
        fn probe() {}
    }

    impl<Type: ?Sized> AmbiguousIfSend<()> for Type {}
    impl<Type: ?Sized + Send> AmbiguousIfSend<Invalid> for Type {}

    trait AmbiguousIfSync<Marker> {
        fn probe() {}
    }

    impl<Type: ?Sized> AmbiguousIfSync<()> for Type {}
    impl<Type: ?Sized + Sync> AmbiguousIfSync<Invalid> for Type {}

    #[test]
    fn public_capture_signature_has_no_recoverable_error_channel() {
        fn require_signature(_capture: fn() -> AdoptedInjectedChannels) {}

        require_signature(capture_and_adopt_injected_channels);
    }

    #[test]
    fn public_completion_signature_has_no_recoverable_error_channel() {
        fn require_signature(
            _complete: fn(
                AdoptedInjectedChannels,
                crate::HelperBootstrapRole,
            ) -> BootstrappedInjectedChannels,
        ) {
        }

        require_signature(complete_injected_channel_bootstrap);
    }

    #[cfg(all(
        target_env = "msvc",
        feature = "helper-ready-rpc-feasibility-test-hook"
    ))]
    #[test]
    fn public_helper_ready_signature_consumes_bootstrap_and_never_returns() {
        fn require_signature(
            _complete: fn(BootstrappedInjectedChannels, crate::HelperBootstrapRole) -> !,
        ) {
        }

        require_signature(complete_helper_ready_rpc_probe);
    }

    #[test]
    fn opaque_channel_states_are_debuggable_but_thread_bound() {
        fn require_debug<Type: Debug>() {}

        require_debug::<AdoptedInjectedChannels>();
        require_debug::<BootstrappedInjectedChannels>();
        let _ = <AdoptedInjectedChannels as AmbiguousIfSend<_>>::probe;
        let _ = <AdoptedInjectedChannels as AmbiguousIfSync<_>>::probe;
        let _ = <BootstrappedInjectedChannels as AmbiguousIfSend<_>>::probe;
        let _ = <BootstrappedInjectedChannels as AmbiguousIfSync<_>>::probe;
    }

    #[cfg(all(
        target_env = "msvc",
        feature = "approval-exchange-feasibility-test-hook"
    ))]
    #[test]
    fn service_approval_request_is_thread_bound_and_consumes_the_bootstrap() {
        fn require_debug<Type: Debug>() {}
        type Presenter = fn(&approval_wire::ApprovalRequest) -> Option<approval_wire::Decision>;

        require_debug::<super::ServiceApprovalRequest>();
        let _: fn(BootstrappedInjectedChannels) -> super::ServiceApprovalRequest =
            super::receive_service_approval_request;
        let _: fn(super::ServiceApprovalRequest, Presenter) -> ! =
            super::ServiceApprovalRequest::present_and_respond;
        let _ = <super::ServiceApprovalRequest as AmbiguousIfSend<_>>::probe;
        let _ = <super::ServiceApprovalRequest as AmbiguousIfSync<_>>::probe;
    }
}
