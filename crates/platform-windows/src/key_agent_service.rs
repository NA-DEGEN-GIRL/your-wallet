//! Fixed-name, inert Windows SCM feasibility host.
//!
//! This module deliberately contains no wallet state, secret, IPC endpoint,
//! token derivation, child-process creation, or signing transition. The real
//! dispatcher is compiled only for Windows debug builds with the explicit
//! feasibility feature. Every other build fails closed before touching SCM.

use thiserror::Error;

/// Fixed SCM service name selected by ADR 0001.
pub const KEY_AGENT_SERVICE_NAME: &str = "YourWalletKeyAgent";

/// Failure returned by the inert SCM feasibility facade.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum KeyAgentServiceFixtureError {
    /// The feasibility dispatcher is absent from this build.
    #[error("key agent service fixture is unavailable")]
    Unavailable,
    /// Windows rejected or could not complete the fixed SCM lifecycle.
    #[error("key agent service fixture crossed an unavailable operating-system boundary")]
    OperatingSystemBoundary,
}

/// Runs the fixed-name inert SCM lifecycle when the debug feasibility hook is enabled.
///
/// Default builds, release builds, and non-Windows builds always return
/// [`KeyAgentServiceFixtureError::Unavailable`]. The enabled Windows fixture
/// accepts only SCM lifecycle controls and exposes no wallet operation.
///
/// # Errors
///
/// Returns [`KeyAgentServiceFixtureError::Unavailable`] outside the exact debug
/// feasibility build, or [`KeyAgentServiceFixtureError::OperatingSystemBoundary`]
/// when Windows rejects the fixed dispatcher lifecycle.
pub fn run_inert_key_agent_service_fixture() -> Result<(), KeyAgentServiceFixtureError> {
    #[cfg(all(
        windows,
        feature = "key-agent-service-scm-feasibility-test-hook",
        debug_assertions
    ))]
    {
        sys::run_dispatcher()
    }

    #[cfg(not(all(
        windows,
        feature = "key-agent-service-scm-feasibility-test-hook",
        debug_assertions
    )))]
    {
        Err(KeyAgentServiceFixtureError::Unavailable)
    }
}

#[cfg(all(
    windows,
    feature = "key-agent-service-scm-feasibility-test-hook",
    debug_assertions
))]
mod sys {
    #![allow(unsafe_code)]

    use core::ffi::c_void;
    use core::ptr;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::{Mutex, MutexGuard, PoisonError};

    use windows::Win32::Foundation::{
        CloseHandle, ERROR_CALL_NOT_IMPLEMENTED, ERROR_SERVICE_SPECIFIC_ERROR, HANDLE,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows::Win32::System::Services::{
        RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
        SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
        SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE,
        SERVICE_STATUS_HANDLE, SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW,
        SERVICE_WIN32_OWN_PROCESS, SetServiceStatus, StartServiceCtrlDispatcherW,
    };
    use windows::Win32::System::Threading::{CreateEventW, SetEvent, WaitForSingleObject};
    use windows::core::{PCWSTR, PWSTR};

    use super::KeyAgentServiceFixtureError;

    const SERVICE_NAME_WIDE: [u16; 19] = [
        89, 111, 117, 114, 87, 97, 108, 108, 101, 116, 75, 101, 121, 65, 103, 101, 110, 116, 0,
    ];
    const INITIALIZATION_FAILURE: u32 = 1;
    const WAIT_FAILURE: u32 = 2;
    const CONTROL_FAILURE: u32 = 3;
    const STATUS_FAILURE: u32 = 4;
    const START_WAIT_HINT_MILLISECONDS: u32 = 3_000;
    const STOP_WAIT_HINT_MILLISECONDS: u32 = 3_000;
    const CONTROL_POLL_MILLISECONDS: u32 = 250;

    const OUTCOME_NOT_STARTED: u32 = 0;
    const OUTCOME_CALLBACK_ACTIVE: u32 = 1;
    const OUTCOME_SUCCESS: u32 = 2;
    const OUTCOME_FAILURE: u32 = 3;

    static DISPATCH_CLAIMED: AtomicBool = AtomicBool::new(false);
    static DISPATCH_OUTCOME: AtomicU32 = AtomicU32::new(OUTCOME_NOT_STARTED);

    #[derive(Clone, Copy, Debug)]
    struct PublishedControlContext {
        status_handle: usize,
        stop_event: usize,
        status: SERVICE_STATUS,
        stop_requested: bool,
        control_error: bool,
        finishing: bool,
    }

    impl PublishedControlContext {
        const fn empty() -> Self {
            Self {
                status_handle: 0,
                stop_event: 0,
                status: status_value(SERVICE_STOPPED, 0, 0, 0, 0),
                stop_requested: false,
                control_error: false,
                finishing: true,
            }
        }

        fn reset_for_dispatch(&mut self) {
            *self = Self {
                finishing: false,
                ..Self::empty()
            };
        }

        fn latch_stop(&mut self) {
            self.stop_requested = true;
        }

        fn publish_stop_event(&mut self, event: HANDLE) -> bool {
            self.stop_event = event.0 as usize;
            self.stop_requested
        }

        fn unpublish_stop_event(&mut self) {
            self.stop_event = 0;
        }
    }

    static CONTROL_CONTEXT: Mutex<PublishedControlContext> =
        Mutex::new(PublishedControlContext::empty());

    struct OwnedEvent(HANDLE);

    impl OwnedEvent {
        fn create() -> Result<Self, KeyAgentServiceFixtureError> {
            // SAFETY: no security descriptor or name is supplied. The returned
            // manual-reset event is process-private and owned by this value.
            let handle = unsafe { CreateEventW(None, true, false, None) }
                .map_err(|_| KeyAgentServiceFixtureError::OperatingSystemBoundary)?;
            Ok(Self(handle))
        }

        const fn raw(&self) -> HANDLE {
            self.0
        }

        fn close(mut self) -> Result<(), KeyAgentServiceFixtureError> {
            // SAFETY: this value exclusively owns the unpublished event handle.
            unsafe { CloseHandle(self.0) }
                .map_err(|_| KeyAgentServiceFixtureError::OperatingSystemBoundary)?;
            self.0 = HANDLE::default();
            Ok(())
        }
    }

    impl Drop for OwnedEvent {
        fn drop(&mut self) {
            if self.0.is_invalid() {
                return;
            }
            // SAFETY: finalization first unpublishes this exact handle while
            // holding the handler context lock. This is only the fail-closed
            // fallback after an explicit close did not complete.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    enum WaitOutcome {
        Stop,
        BoundaryFailure,
    }

    pub(super) fn run_dispatcher() -> Result<(), KeyAgentServiceFixtureError> {
        if DISPATCH_CLAIMED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(KeyAgentServiceFixtureError::OperatingSystemBoundary);
        }
        DISPATCH_OUTCOME.store(OUTCOME_NOT_STARTED, Ordering::Release);
        lock_context().reset_for_dispatch();

        let mut service_name = SERVICE_NAME_WIDE;
        let entries = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: PWSTR(service_name.as_mut_ptr()),
                lpServiceProc: Some(service_main),
            },
            SERVICE_TABLE_ENTRYW::default(),
        ];
        // SAFETY: `entries` contains one fixed callback followed by the required
        // null terminator and remains live until the dispatcher returns.
        unsafe { StartServiceCtrlDispatcherW(entries.as_ptr()) }
            .map_err(|_| KeyAgentServiceFixtureError::OperatingSystemBoundary)?;

        if DISPATCH_OUTCOME.load(Ordering::Acquire) == OUTCOME_SUCCESS {
            Ok(())
        } else {
            Err(KeyAgentServiceFixtureError::OperatingSystemBoundary)
        }
    }

    unsafe extern "system" fn service_main(_argument_count: u32, _arguments: *mut PWSTR) {
        DISPATCH_OUTCOME.store(OUTCOME_CALLBACK_ACTIVE, Ordering::Release);

        // SAFETY: SCM invokes this callback for the fixed service table entry.
        let Ok(status_handle) = (unsafe {
            RegisterServiceCtrlHandlerExW(
                PCWSTR(SERVICE_NAME_WIDE.as_ptr()),
                Some(control_handler),
                None,
            )
        }) else {
            DISPATCH_OUTCOME.store(OUTCOME_FAILURE, Ordering::Release);
            return;
        };

        let start_status_failed = {
            let mut context = lock_context();
            context.status_handle = status_handle.0 as usize;
            publish_status(
                &mut context,
                SERVICE_START_PENDING,
                0,
                1,
                START_WAIT_HINT_MILLISECONDS,
            )
            .is_err()
        };
        if start_status_failed {
            finish_service(status_handle, None, Some(STATUS_FAILURE));
            return;
        }

        let Ok(stop_event) = OwnedEvent::create() else {
            finish_service(status_handle, None, Some(INITIALIZATION_FAILURE));
            return;
        };

        let startup_failed = {
            let mut context = lock_context();
            let stop_requested = context.publish_stop_event(stop_event.raw());
            if stop_requested {
                // SAFETY: service main retains the event and the context lock
                // prevents concurrent unpublish/drop during this signal.
                if unsafe { SetEvent(stop_event.raw()) }.is_err() {
                    context.control_error = true;
                }
            }

            let state = if stop_requested {
                SERVICE_STOP_PENDING
            } else {
                SERVICE_RUNNING
            };
            let checkpoint = u32::from(stop_requested);
            let wait_hint = if stop_requested {
                STOP_WAIT_HINT_MILLISECONDS
            } else {
                0
            };
            if publish_status(&mut context, state, 0, checkpoint, wait_hint).is_err() {
                context.control_error = true;
            }
            context.control_error
        };
        if startup_failed {
            finish_service(status_handle, Some(stop_event), Some(CONTROL_FAILURE));
            return;
        }

        let wait_outcome = wait_for_stop(&stop_event);
        let failure = match wait_outcome {
            WaitOutcome::Stop => None,
            WaitOutcome::BoundaryFailure => Some(WAIT_FAILURE),
        };
        finish_service(status_handle, Some(stop_event), failure);
    }

    unsafe extern "system" fn control_handler(
        control: u32,
        _event_type: u32,
        _event_data: *mut c_void,
        _context: *mut c_void,
    ) -> u32 {
        let mut context = lock_context();
        match control {
            SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
                if context.finishing {
                    return 0;
                }
                context.latch_stop();
                if context.status_handle != 0
                    && context.status.dwCurrentState != SERVICE_STOP_PENDING
                    && publish_status(
                        &mut context,
                        SERVICE_STOP_PENDING,
                        0,
                        1,
                        STOP_WAIT_HINT_MILLISECONDS,
                    )
                    .is_err()
                {
                    context.control_error = true;
                }
                if context.stop_event != 0 {
                    // SAFETY: the context lock prevents service main from
                    // unpublishing and dropping this event during the signal.
                    if unsafe { SetEvent(HANDLE(context.stop_event as *mut c_void)) }.is_err() {
                        context.control_error = true;
                    }
                }
                0
            }
            SERVICE_CONTROL_INTERROGATE => {
                if context.status_handle != 0
                    && send_status(
                        SERVICE_STATUS_HANDLE(context.status_handle as *mut c_void),
                        &context.status,
                    )
                    .is_err()
                    && !context.finishing
                {
                    context.control_error = true;
                }
                0
            }
            _ => ERROR_CALL_NOT_IMPLEMENTED.0,
        }
    }

    fn wait_for_stop(stop_event: &OwnedEvent) -> WaitOutcome {
        loop {
            // SAFETY: service main retains the event for the complete bounded
            // wait and finalization owns the only close transition.
            let wait = unsafe { WaitForSingleObject(stop_event.raw(), CONTROL_POLL_MILLISECONDS) };
            let context = lock_context();
            if context.control_error {
                return WaitOutcome::BoundaryFailure;
            }
            if context.stop_requested {
                return WaitOutcome::Stop;
            }
            if wait != WAIT_TIMEOUT && wait != WAIT_OBJECT_0 {
                return WaitOutcome::BoundaryFailure;
            }
            if wait == WAIT_OBJECT_0 {
                return WaitOutcome::BoundaryFailure;
            }
        }
    }

    fn finish_service(
        status_handle: SERVICE_STATUS_HANDLE,
        stop_event: Option<OwnedEvent>,
        mut failure: Option<u32>,
    ) {
        {
            let mut context = lock_context();
            context.finishing = true;
            if context.status.dwCurrentState == SERVICE_RUNNING
                && publish_status(
                    &mut context,
                    SERVICE_STOP_PENDING,
                    0,
                    1,
                    STOP_WAIT_HINT_MILLISECONDS,
                )
                .is_err()
                && failure.is_none()
            {
                failure = Some(STATUS_FAILURE);
            }
            context.unpublish_stop_event();
        }

        // All owned runtime resources must close before SERVICE_STOPPED. A
        // failed explicit close omits the terminal status so process exit, not
        // a false clean-stop claim, remains the authoritative cleanup.
        if let Some(event) = stop_event
            && event.close().is_err()
        {
            let mut context = lock_context();
            context.status_handle = 0;
            context.stop_event = 0;
            context.finishing = true;
            DISPATCH_OUTCOME.store(OUTCOME_FAILURE, Ordering::Release);
            return;
        }

        let final_status = if let Some(detail) = failure {
            status_value(
                SERVICE_STOPPED,
                ERROR_SERVICE_SPECIFIC_ERROR.0,
                detail,
                0,
                0,
            )
        } else {
            status_value(SERVICE_STOPPED, 0, 0, 0, 0)
        };

        {
            let mut context = lock_context();
            context.status_handle = 0;
            context.stop_event = 0;
            context.status = final_status;
            context.finishing = true;
        }

        let intended_outcome = if failure.is_none() {
            OUTCOME_SUCCESS
        } else {
            OUTCOME_FAILURE
        };
        DISPATCH_OUTCOME.store(intended_outcome, Ordering::Release);

        // This is the last successful service operation. If it succeeds, the
        // callback returns immediately without touching shared state again.
        if send_status(status_handle, &final_status).is_err() {
            DISPATCH_OUTCOME.store(OUTCOME_FAILURE, Ordering::Release);
        }
    }

    fn publish_status(
        context: &mut PublishedControlContext,
        state: SERVICE_STATUS_CURRENT_STATE,
        win32_exit: u32,
        checkpoint: u32,
        wait_hint: u32,
    ) -> windows::core::Result<()> {
        if context.status_handle == 0 {
            return Err(windows::core::Error::from_win32());
        }
        let status = status_value(state, win32_exit, 0, checkpoint, wait_hint);
        send_status(
            SERVICE_STATUS_HANDLE(context.status_handle as *mut c_void),
            &status,
        )?;
        context.status = status;
        Ok(())
    }

    fn send_status(
        status_handle: SERVICE_STATUS_HANDLE,
        status: &SERVICE_STATUS,
    ) -> windows::core::Result<()> {
        // SAFETY: status_handle is the value returned for this ServiceMain
        // invocation and the complete status remains live for the call.
        unsafe { SetServiceStatus(status_handle, ptr::from_ref(status)) }
    }

    const fn status_value(
        state: SERVICE_STATUS_CURRENT_STATE,
        win32_exit: u32,
        service_specific_exit: u32,
        checkpoint: u32,
        wait_hint: u32,
    ) -> SERVICE_STATUS {
        SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: if state.0 == SERVICE_RUNNING.0 {
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
            } else {
                0
            },
            dwWin32ExitCode: win32_exit,
            dwServiceSpecificExitCode: service_specific_exit,
            dwCheckPoint: checkpoint,
            dwWaitHint: wait_hint,
        }
    }

    fn lock_context() -> MutexGuard<'static, PublishedControlContext> {
        CONTROL_CONTEXT
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn service_name_is_fixed_and_nul_terminated() {
            let expected: Vec<u16> = super::super::KEY_AGENT_SERVICE_NAME
                .encode_utf16()
                .chain(core::iter::once(0))
                .collect();
            assert_eq!(SERVICE_NAME_WIDE, expected.as_slice());
        }

        #[test]
        fn status_contract_preserves_pending_checkpoint_on_interrogate() {
            let pending = status_value(SERVICE_STOP_PENDING, 0, 0, 1, STOP_WAIT_HINT_MILLISECONDS);
            assert_eq!(pending.dwServiceType, SERVICE_WIN32_OWN_PROCESS);
            assert_eq!(pending.dwControlsAccepted, 0);
            assert_eq!(pending.dwCheckPoint, 1);
            assert_eq!(pending.dwWaitHint, STOP_WAIT_HINT_MILLISECONDS);

            let running = status_value(SERVICE_RUNNING, 0, 0, 0, 0);
            assert_eq!(
                running.dwControlsAccepted,
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
            );
        }

        #[test]
        fn stop_before_event_publication_is_latched_and_rundown_is_explicit() {
            let mut context = PublishedControlContext::empty();
            context.reset_for_dispatch();
            context.latch_stop();

            assert!(context.publish_stop_event(HANDLE(7_usize as *mut c_void)));
            assert_ne!(context.stop_event, 0);

            context.unpublish_stop_event();
            assert_eq!(context.stop_event, 0);
            assert!(context.stop_requested);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_service_name_is_stable_ascii() {
        assert_eq!(KEY_AGENT_SERVICE_NAME, "YourWalletKeyAgent");
        assert!(KEY_AGENT_SERVICE_NAME.is_ascii());
    }

    #[cfg(not(all(
        windows,
        feature = "key-agent-service-scm-feasibility-test-hook",
        debug_assertions
    )))]
    #[test]
    fn fixture_is_unavailable_outside_the_exact_debug_build() {
        assert_eq!(
            run_inert_key_agent_service_fixture(),
            Err(KeyAgentServiceFixtureError::Unavailable)
        );
    }
}
