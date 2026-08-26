//! Child-side capture and adoption of debugger-injected service channels.

#![deny(unsafe_code)]

use core::fmt;
use core::marker::PhantomData;
use std::rc::Rc;

#[allow(unsafe_code)]
mod windows;

/// Public structural marker placed in `r10` at the authenticated capture gate.
pub const REQUEST_INPUT_MARKER: u64 = 0xA1D7_5E02_9C4B_63F8;

/// Public structural marker placed in `r11` at the authenticated capture gate.
pub const RESPONSE_OUTPUT_MARKER: u64 = 0x6C39_B4E1_27FA_805D;

/// Opaque ownership of the adopted request-input and response-output pipes.
///
/// The value exposes neither raw handles nor I/O. It is move-only and bound to
/// the capturing thread so a later protocol transition must consume it in the
/// same child-side bootstrap sequence.
#[must_use = "adopted injected channels must remain owned through bootstrap"]
pub struct AdoptedInjectedChannels {
    _inner: windows::AdoptedInjectedChannels,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl fmt::Debug for AdoptedInjectedChannels {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdoptedInjectedChannels([SEALED PIPE HANDLES])")
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
        _inner: inner,
        _not_send_or_sync: PhantomData,
    }
}

#[cfg(test)]
mod tests {
    use super::{AdoptedInjectedChannels, capture_and_adopt_injected_channels};

    #[test]
    fn public_capture_signature_has_no_recoverable_error_channel() {
        fn require_signature(_capture: fn() -> AdoptedInjectedChannels) {}

        require_signature(capture_and_adopt_injected_channels);
    }
}
