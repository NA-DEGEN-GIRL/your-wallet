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

#[cfg(test)]
mod tests {
    use core::fmt::Debug;

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
}
