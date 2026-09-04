//! Fixed-name dormant Windows SCM host and feasibility entrypoints.
//!
//! This module deliberately contains no wallet state, secret, or signing
//! transition. The SCM/status mechanics are Windows production-compiled for a
//! sealed lifecycle-effect adapter with no executable caller. Inert lifecycle,
//! restricted-token, and helper-launch dispatchers remain available only to
//! their exact debug features; default and release entrypoints fail closed
//! before touching SCM. Those probes remain feasibility evidence, not
//! production authorization or installer provenance.

use thiserror::Error;

// Production-compiled private lifecycle, durable-run-state, provisioning,
// lease-first runtime-boot, held run-state-root, and dormant Windows lifecycle
// composition models through Phase 2I. They have no executable/top-level
// caller, production key source, or installer authority mint in this module.
#[allow(dead_code)]
mod durable_run_state;

#[allow(dead_code)]
mod lifecycle_core;

#[cfg(windows)]
#[allow(dead_code)]
mod windows_lifecycle;

#[cfg(windows)]
#[allow(dead_code)]
mod windows_session_events;

#[cfg(windows)]
#[allow(dead_code)]
mod run_state_root;

/// Fixed SCM service name selected by ADR 0001.
pub const KEY_AGENT_SERVICE_NAME: &str = "YourWalletKeyAgent";

#[cfg(windows)]
#[cfg_attr(test, allow(unused_imports))]
pub(in crate::key_agent_service) use sys::WindowsScmStatusAuthority;

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

/// Runs the fixed-name restricted-service-token fixture when explicitly enabled.
///
/// Default builds, release builds, and non-Windows builds always return
/// [`KeyAgentServiceFixtureError::Unavailable`]. The enabled fixture verifies
/// the current process token before publishing `SERVICE_RUNNING`; its opaque
/// proof deliberately does not claim final SCM configuration, integrity, or
/// helper-launch feasibility.
///
/// # Errors
///
/// Returns [`KeyAgentServiceFixtureError::Unavailable`] outside the exact debug
/// feasibility build, or [`KeyAgentServiceFixtureError::OperatingSystemBoundary`]
/// when Windows rejects the SCM lifecycle or the current token does not match
/// the documented feasibility policy.
pub fn run_service_token_key_agent_service_fixture() -> Result<(), KeyAgentServiceFixtureError> {
    #[cfg(all(
        windows,
        feature = "key-agent-service-token-feasibility-test-hook",
        debug_assertions
    ))]
    {
        sys::run_service_token_dispatcher()
    }

    #[cfg(not(all(
        windows,
        feature = "key-agent-service-token-feasibility-test-hook",
        debug_assertions
    )))]
    {
        Err(KeyAgentServiceFixtureError::Unavailable)
    }
}

/// Runs the fixed-name, no-secret local-RPC status fixture when explicitly enabled.
///
/// Default builds, release builds, and non-Windows builds always return
/// [`KeyAgentServiceFixtureError::Unavailable`]. The enabled fixture exposes
/// only the bounded `OpenEpoch` and `Status -> Unavailable` protocol and is not
/// production Broker or helper authorization.
///
/// # Errors
///
/// Returns [`KeyAgentServiceFixtureError::Unavailable`] outside the exact debug
/// feasibility build, or [`KeyAgentServiceFixtureError::OperatingSystemBoundary`]
/// when Windows rejects the SCM or local-RPC lifecycle.
pub fn run_status_rpc_key_agent_service_fixture() -> Result<(), KeyAgentServiceFixtureError> {
    #[cfg(all(
        windows,
        feature = "key-agent-service-rpc-status-feasibility-test-hook",
        debug_assertions
    ))]
    {
        sys::run_status_rpc_dispatcher()
    }

    #[cfg(not(all(
        windows,
        feature = "key-agent-service-rpc-status-feasibility-test-hook",
        debug_assertions
    )))]
    {
        Err(KeyAgentServiceFixtureError::Unavailable)
    }
}

/// Runs the debug-only restricted-service LPAC/helper RPC probe fixture.
///
/// This composes the retained service-token proof, role-aware V2 RPC manager,
/// one-at-a-time launch coordinator, fixed sibling Approval/Secret Input helper
/// entrypoints, expected-peer admission, confirmation, and terminal cleanup.
/// It remains no-secret feasibility evidence and is unavailable in every
/// default, release, non-Windows, or feature-disabled build.
///
/// # Errors
///
/// Returns [`KeyAgentServiceFixtureError::Unavailable`] outside the exact debug
/// feasibility build, or [`KeyAgentServiceFixtureError::OperatingSystemBoundary`]
/// when SCM, token, RPC, helper, or cleanup composition fails closed.
pub fn run_lpac_rpc_probe_key_agent_service_fixture() -> Result<(), KeyAgentServiceFixtureError> {
    #[cfg(all(
        windows,
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    {
        sys::run_lpac_rpc_probe_dispatcher()
    }

    #[cfg(not(all(
        windows,
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    )))]
    {
        Err(KeyAgentServiceFixtureError::Unavailable)
    }
}

#[cfg(windows)]
#[allow(dead_code, unsafe_code)]
mod sys {
    use core::ffi::c_void;
    use core::ptr;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
    use std::sync::{Mutex, MutexGuard, PoisonError};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

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
    const STOP_PROGRESS_MILLISECONDS: u64 = 500;
    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    const STOP_DEADLINE_MILLISECONDS: u64 =
        crate::key_agent_service_launch::SERVICE_RPC_PROBE_STOP_DEADLINE_MILLISECONDS;
    #[cfg(not(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    )))]
    const STOP_DEADLINE_MILLISECONDS: u64 = 15_000;

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

    enum StartupState {
        Run,
        Stop,
        BoundaryFailure,
    }

    #[derive(Clone, Copy)]
    enum AuthoritativeStatus {
        Running,
        Stopped,
    }

    /// Move-only authority for publishing this registered service invocation's
    /// lifecycle status through SCM.
    ///
    /// The registration handle is private to this native boundary. Diagnostics
    /// never expose it, and `bind_registered_status` is the sole mint.
    #[must_use = "the SCM status authority must remain attached to its lifecycle effects"]
    pub(in crate::key_agent_service) struct WindowsScmStatusAuthority {
        status_handle: usize,
    }

    impl WindowsScmStatusAuthority {
        fn bind_registered_status(status_handle: SERVICE_STATUS_HANDLE) -> Self {
            Self {
                status_handle: status_handle.0 as usize,
            }
        }

        /// Publishes `SERVICE_RUNNING` for the exact registered service invocation.
        pub(in crate::key_agent_service) fn publish_running(&mut self) -> bool {
            publish_authoritative_status(self.status_handle, AuthoritativeStatus::Running)
        }

        /// Runs one admission-open transition only while this exact invocation
        /// remains authoritatively running and no stop or failure is latched.
        pub(in crate::key_agent_service) fn with_running_admission_gate<R>(
            &mut self,
            operation: impl FnOnce() -> R,
        ) -> Option<R> {
            with_authoritative_running_admission_gate(self.status_handle, operation)
        }

        /// Publishes `SERVICE_STOPPED` for the exact registered service invocation.
        pub(in crate::key_agent_service) fn publish_stopped(&mut self) -> bool {
            let published =
                publish_authoritative_status(self.status_handle, AuthoritativeStatus::Stopped);
            if published {
                self.status_handle = 0;
            }
            published
        }
    }

    impl core::fmt::Debug for WindowsScmStatusAuthority {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("WindowsScmStatusAuthority([REDACTED])")
        }
    }

    trait ScmWorker: Sized {
        type AdmissionClosed: AdmissionClosedScmWorker;

        fn start() -> Result<Self, WorkerStartFailure>;

        fn begin_accepting(&mut self) -> Result<(), KeyAgentServiceFixtureError>;

        fn close_admission(self) -> Self::AdmissionClosed;
    }

    trait AdmissionClosedScmWorker: Sized {
        fn drain(self) -> Result<(), KeyAgentServiceFixtureError>;
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum WorkerStartFailure {
        Boundary,
        #[cfg(feature = "key-agent-service-rpc-status-feasibility-test-hook")]
        RuntimeStateRetained,
    }

    struct StopProgressReporter {
        complete: SyncSender<()>,
        thread: JoinHandle<()>,
    }

    impl StopProgressReporter {
        fn start() -> Result<Self, ()> {
            let (complete, receiver) = sync_channel(1);
            let thread = thread::Builder::new()
                .name("key-agent-service-stop-progress".to_owned())
                .spawn(move || report_stop_progress_until_complete(&receiver))
                .map_err(|_| ())?;
            Ok(Self { complete, thread })
        }

        fn finish(self) -> Result<(), ()> {
            let sent = self.complete.send(()).is_ok();
            let joined = self.thread.join().is_ok();
            if sent && joined { Ok(()) } else { Err(()) }
        }
    }

    impl WorkerStartFailure {
        const fn permits_stopped_status(self) -> bool {
            matches!(self, Self::Boundary)
        }
    }

    struct InertWorker;

    struct AdmissionClosedInertWorker;

    impl ScmWorker for InertWorker {
        type AdmissionClosed = AdmissionClosedInertWorker;

        fn start() -> Result<Self, WorkerStartFailure> {
            Ok(Self)
        }

        fn begin_accepting(&mut self) -> Result<(), KeyAgentServiceFixtureError> {
            Ok(())
        }

        fn close_admission(self) -> Self::AdmissionClosed {
            AdmissionClosedInertWorker
        }
    }

    impl AdmissionClosedScmWorker for AdmissionClosedInertWorker {
        fn drain(self) -> Result<(), KeyAgentServiceFixtureError> {
            Ok(())
        }
    }

    #[cfg(all(
        feature = "key-agent-service-token-feasibility-test-hook",
        debug_assertions
    ))]
    struct ServiceTokenWorker {
        proof: crate::key_agent_service_token::ServiceTokenFixtureProof,
    }

    #[cfg(all(
        feature = "key-agent-service-token-feasibility-test-hook",
        debug_assertions
    ))]
    struct AdmissionClosedServiceTokenWorker {
        proof: crate::key_agent_service_token::ServiceTokenFixtureProof,
    }

    #[cfg(all(
        feature = "key-agent-service-token-feasibility-test-hook",
        debug_assertions
    ))]
    impl ScmWorker for ServiceTokenWorker {
        type AdmissionClosed = AdmissionClosedServiceTokenWorker;

        fn start() -> Result<Self, WorkerStartFailure> {
            crate::key_agent_service_token::verify_current_key_agent_service_token_fixture()
                .map(|proof| Self { proof })
                .map_err(|_| WorkerStartFailure::Boundary)
        }

        fn begin_accepting(&mut self) -> Result<(), KeyAgentServiceFixtureError> {
            Ok(())
        }

        fn close_admission(self) -> Self::AdmissionClosed {
            AdmissionClosedServiceTokenWorker { proof: self.proof }
        }
    }

    #[cfg(all(
        feature = "key-agent-service-token-feasibility-test-hook",
        debug_assertions
    ))]
    impl AdmissionClosedScmWorker for AdmissionClosedServiceTokenWorker {
        fn drain(self) -> Result<(), KeyAgentServiceFixtureError> {
            Ok(())
        }
    }

    #[cfg(feature = "key-agent-service-rpc-status-feasibility-test-hook")]
    struct StatusRpcWorker(crate::key_agent_service_rpc::StatusRpcWorker);

    #[cfg(feature = "key-agent-service-rpc-status-feasibility-test-hook")]
    struct AdmissionClosedStatusRpcWorker(
        crate::key_agent_service_rpc::AdmissionClosedStatusRpcWorker,
    );

    #[cfg(feature = "key-agent-service-rpc-status-feasibility-test-hook")]
    impl ScmWorker for StatusRpcWorker {
        type AdmissionClosed = AdmissionClosedStatusRpcWorker;

        fn start() -> Result<Self, WorkerStartFailure> {
            match crate::key_agent_service_rpc::StatusRpcWorker::start() {
                Ok(worker) => Ok(Self(worker)),
                Err(crate::key_agent_service_rpc::StatusRpcWorkerError::Unavailable) => {
                    Err(WorkerStartFailure::Boundary)
                }
                Err(crate::key_agent_service_rpc::StatusRpcWorkerError::RuntimeStateRetained) => {
                    Err(WorkerStartFailure::RuntimeStateRetained)
                }
            }
        }

        fn begin_accepting(&mut self) -> Result<(), KeyAgentServiceFixtureError> {
            self.0
                .begin_accepting()
                .map_err(|_| KeyAgentServiceFixtureError::OperatingSystemBoundary)
        }

        fn close_admission(self) -> Self::AdmissionClosed {
            AdmissionClosedStatusRpcWorker(self.0.close_admission())
        }
    }

    #[cfg(feature = "key-agent-service-rpc-status-feasibility-test-hook")]
    impl AdmissionClosedScmWorker for AdmissionClosedStatusRpcWorker {
        fn drain(self) -> Result<(), KeyAgentServiceFixtureError> {
            self.0
                .drain()
                .map_err(|_| KeyAgentServiceFixtureError::OperatingSystemBoundary)
        }
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    struct LpacRpcProbeWorker(crate::key_agent_service_rpc::StatusRpcWorker);

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    struct AdmissionClosedLpacRpcProbeWorker(
        crate::key_agent_service_rpc::AdmissionClosedStatusRpcWorker,
    );

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    impl ScmWorker for LpacRpcProbeWorker {
        type AdmissionClosed = AdmissionClosedLpacRpcProbeWorker;

        fn start() -> Result<Self, WorkerStartFailure> {
            let service_token =
                crate::key_agent_service_token::verify_current_key_agent_service_token_fixture()
                    .map_err(|_| WorkerStartFailure::Boundary)?;
            match crate::key_agent_service_rpc::StatusRpcWorker::start_lpac_rpc_probe(service_token)
            {
                Ok(worker) => Ok(Self(worker)),
                Err(crate::key_agent_service_rpc::StatusRpcWorkerError::Unavailable) => {
                    Err(WorkerStartFailure::Boundary)
                }
                Err(crate::key_agent_service_rpc::StatusRpcWorkerError::RuntimeStateRetained) => {
                    Err(WorkerStartFailure::RuntimeStateRetained)
                }
            }
        }

        fn begin_accepting(&mut self) -> Result<(), KeyAgentServiceFixtureError> {
            self.0
                .begin_accepting()
                .map_err(|_| KeyAgentServiceFixtureError::OperatingSystemBoundary)
        }

        fn close_admission(self) -> Self::AdmissionClosed {
            AdmissionClosedLpacRpcProbeWorker(self.0.close_admission())
        }
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    impl AdmissionClosedScmWorker for AdmissionClosedLpacRpcProbeWorker {
        fn drain(self) -> Result<(), KeyAgentServiceFixtureError> {
            self.0
                .drain()
                .map_err(|_| KeyAgentServiceFixtureError::OperatingSystemBoundary)
        }
    }

    pub(super) fn run_dispatcher() -> Result<(), KeyAgentServiceFixtureError> {
        run_dispatcher_with(service_main)
    }

    #[cfg(all(
        feature = "key-agent-service-token-feasibility-test-hook",
        debug_assertions
    ))]
    pub(super) fn run_service_token_dispatcher() -> Result<(), KeyAgentServiceFixtureError> {
        run_dispatcher_with(service_token_service_main)
    }

    #[cfg(feature = "key-agent-service-rpc-status-feasibility-test-hook")]
    pub(super) fn run_status_rpc_dispatcher() -> Result<(), KeyAgentServiceFixtureError> {
        run_dispatcher_with(status_rpc_service_main)
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    pub(super) fn run_lpac_rpc_probe_dispatcher() -> Result<(), KeyAgentServiceFixtureError> {
        run_dispatcher_with(lpac_rpc_probe_service_main)
    }

    fn run_dispatcher_with(
        service_proc: unsafe extern "system" fn(u32, *mut PWSTR),
    ) -> Result<(), KeyAgentServiceFixtureError> {
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
                lpServiceProc: Some(service_proc),
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
        service_main_impl::<InertWorker>();
    }

    #[cfg(all(
        feature = "key-agent-service-token-feasibility-test-hook",
        debug_assertions
    ))]
    unsafe extern "system" fn service_token_service_main(
        _argument_count: u32,
        _arguments: *mut PWSTR,
    ) {
        service_main_impl::<ServiceTokenWorker>();
    }

    #[cfg(feature = "key-agent-service-rpc-status-feasibility-test-hook")]
    unsafe extern "system" fn status_rpc_service_main(
        _argument_count: u32,
        _arguments: *mut PWSTR,
    ) {
        service_main_impl::<StatusRpcWorker>();
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    unsafe extern "system" fn lpac_rpc_probe_service_main(
        _argument_count: u32,
        _arguments: *mut PWSTR,
    ) {
        service_main_impl::<LpacRpcProbeWorker>();
    }

    fn service_main_impl<W: ScmWorker>() {
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
            finish_service::<W>(status_handle, None, None, Some(STATUS_FAILURE));
            return;
        }

        let Ok(stop_event) = OwnedEvent::create() else {
            finish_service::<W>(status_handle, None, None, Some(INITIALIZATION_FAILURE));
            return;
        };

        let initial_state = publish_stop_event_and_select_startup(&stop_event);
        match initial_state {
            StartupState::BoundaryFailure => {
                finish_service::<W>(status_handle, Some(stop_event), None, Some(CONTROL_FAILURE));
                return;
            }
            StartupState::Stop => {
                finish_service::<W>(status_handle, Some(stop_event), None, None);
                return;
            }
            StartupState::Run => {}
        }

        let mut worker = match W::start() {
            Ok(worker) => worker,
            Err(failure) => {
                if failure.permits_stopped_status() {
                    finish_service::<W>(
                        status_handle,
                        Some(stop_event),
                        None,
                        Some(INITIALIZATION_FAILURE),
                    );
                } else {
                    abandon_service_with_retained_runtime(stop_event);
                }
                return;
            }
        };

        let running_state = publish_running_or_select_stop(&mut worker);
        match running_state {
            StartupState::BoundaryFailure => {
                finish_service(
                    status_handle,
                    Some(stop_event),
                    Some(worker),
                    Some(CONTROL_FAILURE),
                );
                return;
            }
            StartupState::Stop => {
                finish_service(status_handle, Some(stop_event), Some(worker), None);
                return;
            }
            StartupState::Run => {}
        }

        let wait_outcome = wait_for_stop(&stop_event);
        let failure = match wait_outcome {
            WaitOutcome::Stop => None,
            WaitOutcome::BoundaryFailure => Some(WAIT_FAILURE),
        };
        finish_service(status_handle, Some(stop_event), Some(worker), failure);
    }

    fn publish_stop_event_and_select_startup(stop_event: &OwnedEvent) -> StartupState {
        let mut context = lock_context();
        let stop_requested = context.publish_stop_event(stop_event.raw());
        if stop_requested {
            // SAFETY: service main retains the event and the context lock
            // prevents concurrent unpublish/drop during this signal.
            if unsafe { SetEvent(stop_event.raw()) }.is_err() {
                context.control_error = true;
            }
        }

        if context.control_error {
            return StartupState::BoundaryFailure;
        }
        if !stop_requested {
            return StartupState::Run;
        }
        if publish_status(
            &mut context,
            SERVICE_STOP_PENDING,
            0,
            1,
            STOP_WAIT_HINT_MILLISECONDS,
        )
        .is_err()
        {
            context.control_error = true;
            StartupState::BoundaryFailure
        } else {
            StartupState::Stop
        }
    }

    fn publish_running_or_select_stop<W: ScmWorker>(worker: &mut W) -> StartupState {
        let mut context = lock_context();
        if context.control_error {
            return StartupState::BoundaryFailure;
        }
        if context.stop_requested {
            if context.status.dwCurrentState != SERVICE_STOP_PENDING
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
                return StartupState::BoundaryFailure;
            }
            return StartupState::Stop;
        }
        if publish_status(&mut context, SERVICE_RUNNING, 0, 0, 0).is_err()
            || worker.begin_accepting().is_err()
        {
            context.control_error = true;
            StartupState::BoundaryFailure
        } else {
            StartupState::Run
        }
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

    fn finish_service<W: ScmWorker>(
        status_handle: SERVICE_STATUS_HANDLE,
        stop_event: Option<OwnedEvent>,
        worker: Option<W>,
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

        // Admission is closed by a consuming transition before the progress
        // reporter or any potentially blocking drain begins. The live worker
        // can never be recovered after this point.
        let admission_closed_worker = worker.map(ScmWorker::close_admission);
        let (drain_failed, progress_failed) = match admission_closed_worker {
            None => (false, false),
            Some(worker) => {
                if let Ok(reporter) = StopProgressReporter::start() {
                    let drain_failed = worker.drain().is_err();
                    let progress_failed = reporter.finish().is_err();
                    (drain_failed, progress_failed)
                } else {
                    // Dropping an admission-closed RPC worker retains its
                    // runtime-owned state. Without a progress/deadline thread
                    // a clean drain cannot be claimed.
                    drop(worker);
                    (true, true)
                }
            }
        };
        if drain_failed && failure.is_none() {
            failure = Some(CONTROL_FAILURE);
        }

        // All owned runtime resources must close before SERVICE_STOPPED. A
        // failed worker drain or explicit close omits the terminal status so
        // process exit, not a false clean-stop claim, remains authoritative.
        let event_close_failed = stop_event
            .map(OwnedEvent::close)
            .is_some_and(|result| result.is_err());
        if drain_failed || progress_failed || event_close_failed {
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

    fn abandon_service_with_retained_runtime(stop_event: OwnedEvent) {
        {
            let mut context = lock_context();
            context.finishing = true;
            context.unpublish_stop_event();
        }

        // RPC state intentionally remains retained, but the SCM wakeup event
        // is no longer published and can be closed without a handler race.
        let _ = stop_event.close();
        {
            let mut context = lock_context();
            context.status_handle = 0;
            context.stop_event = 0;
            context.finishing = true;
        }
        // Never publish SERVICE_STOPPED: process exit is the only authoritative
        // cleanup for the uncertain RPC runtime state.
        DISPATCH_OUTCOME.store(OUTCOME_FAILURE, Ordering::Release);
    }

    fn report_stop_progress_until_complete(receiver: &Receiver<()>) {
        let Some(deadline) =
            Instant::now().checked_add(Duration::from_millis(STOP_DEADLINE_MILLISECONDS))
        else {
            std::process::abort();
        };
        let mut checkpoint = 1_u32;
        loop {
            match receiver.recv_timeout(Duration::from_millis(STOP_PROGRESS_MILLISECONDS)) {
                Ok(()) => return,
                Err(RecvTimeoutError::Disconnected) => std::process::abort(),
                Err(RecvTimeoutError::Timeout) => {}
            }
            if Instant::now() >= deadline {
                std::process::abort();
            }
            let Some(next_checkpoint) = checkpoint.checked_add(1) else {
                std::process::abort();
            };
            checkpoint = next_checkpoint;
            let mut context = lock_context();
            if !context.finishing
                || context.status_handle == 0
                || publish_status(
                    &mut context,
                    SERVICE_STOP_PENDING,
                    0,
                    checkpoint,
                    STOP_WAIT_HINT_MILLISECONDS,
                )
                .is_err()
            {
                std::process::abort();
            }
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

    fn publish_authoritative_status(
        expected_status_handle: usize,
        status: AuthoritativeStatus,
    ) -> bool {
        let mut context = lock_context();
        if expected_status_handle == 0
            || context.status_handle != expected_status_handle
            || !authoritative_status_predecessor_is_exact(&context, status)
        {
            return false;
        }

        match status {
            AuthoritativeStatus::Running => {
                if publish_status(&mut context, SERVICE_RUNNING, 0, 0, 0).is_err() {
                    context.control_error = true;
                    false
                } else {
                    true
                }
            }
            AuthoritativeStatus::Stopped => {
                let final_status = status_value(SERVICE_STOPPED, 0, 0, 0, 0);
                let status_handle = SERVICE_STATUS_HANDLE(context.status_handle as *mut c_void);

                // Terminalize under the same lock before the final native send
                // so a concurrent control callback cannot publish STOP_PENDING
                // after the authoritative STOPPED transition begins.
                context.status_handle = 0;
                context.stop_event = 0;
                context.status = final_status;
                context.finishing = true;

                if send_status(status_handle, &final_status).is_err() {
                    context.control_error = true;
                    false
                } else {
                    true
                }
            }
        }
    }

    fn authoritative_status_predecessor_is_exact(
        context: &PublishedControlContext,
        status: AuthoritativeStatus,
    ) -> bool {
        match status {
            AuthoritativeStatus::Running => {
                context.status.dwCurrentState == SERVICE_START_PENDING
                    && !context.finishing
                    && !context.control_error
                    && !context.stop_requested
            }
            AuthoritativeStatus::Stopped => {
                context.status.dwCurrentState == SERVICE_STOP_PENDING
                    && !context.control_error
                    && (context.stop_requested || context.finishing)
            }
        }
    }

    fn with_authoritative_running_admission_gate<R>(
        expected_status_handle: usize,
        operation: impl FnOnce() -> R,
    ) -> Option<R> {
        let context = lock_context();
        if !running_admission_gate_is_exact(&context, expected_status_handle) {
            return None;
        }

        let result = operation();
        drop(context);
        Some(result)
    }

    fn running_admission_gate_is_exact(
        context: &PublishedControlContext,
        expected_status_handle: usize,
    ) -> bool {
        expected_status_handle != 0
            && context.status_handle == expected_status_handle
            && context.status.dwCurrentState == SERVICE_RUNNING
            && !context.stop_requested
            && !context.control_error
            && !context.finishing
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

        #[test]
        fn retained_runtime_start_failure_forbids_stopped_status() {
            assert!(WorkerStartFailure::Boundary.permits_stopped_status());
            #[cfg(feature = "key-agent-service-rpc-status-feasibility-test-hook")]
            assert!(!WorkerStartFailure::RuntimeStateRetained.permits_stopped_status());
        }

        #[test]
        fn authoritative_status_rejects_wrong_predecessors_and_stop_latched_running() {
            let mut context = PublishedControlContext {
                status_handle: 7,
                stop_event: 11,
                status: status_value(SERVICE_START_PENDING, 0, 0, 1, 1),
                stop_requested: false,
                control_error: false,
                finishing: false,
            };
            assert!(authoritative_status_predecessor_is_exact(
                &context,
                AuthoritativeStatus::Running
            ));

            context.stop_requested = true;
            assert!(!authoritative_status_predecessor_is_exact(
                &context,
                AuthoritativeStatus::Running
            ));
            context.stop_requested = false;
            context.status = status_value(SERVICE_RUNNING, 0, 0, 0, 0);
            assert!(!authoritative_status_predecessor_is_exact(
                &context,
                AuthoritativeStatus::Running
            ));

            context.status = status_value(SERVICE_STOP_PENDING, 0, 0, 1, 1);
            assert!(!authoritative_status_predecessor_is_exact(
                &context,
                AuthoritativeStatus::Stopped
            ));
            context.finishing = true;
            assert!(authoritative_status_predecessor_is_exact(
                &context,
                AuthoritativeStatus::Stopped
            ));
            context.control_error = true;
            assert!(!authoritative_status_predecessor_is_exact(
                &context,
                AuthoritativeStatus::Stopped
            ));
        }

        #[test]
        fn running_admission_gate_requires_exact_live_unlatched_context() {
            let mut context = PublishedControlContext {
                status_handle: 7,
                stop_event: 11,
                status: status_value(SERVICE_RUNNING, 0, 0, 0, 0),
                stop_requested: false,
                control_error: false,
                finishing: false,
            };
            assert!(running_admission_gate_is_exact(&context, 7));
            assert!(!running_admission_gate_is_exact(&context, 0));
            assert!(!running_admission_gate_is_exact(&context, 8));

            context.stop_requested = true;
            assert!(!running_admission_gate_is_exact(&context, 7));
            context.stop_requested = false;
            context.control_error = true;
            assert!(!running_admission_gate_is_exact(&context, 7));
            context.control_error = false;
            context.finishing = true;
            assert!(!running_admission_gate_is_exact(&context, 7));
            context.finishing = false;
            context.status = status_value(SERVICE_START_PENDING, 0, 0, 1, 1);
            assert!(!running_admission_gate_is_exact(&context, 7));
        }

        #[test]
        fn scm_status_authority_is_sys_sealed_single_mint_and_debug_redacted()
        -> Result<(), &'static str> {
            let authority = WindowsScmStatusAuthority::bind_registered_status(
                SERVICE_STATUS_HANDLE(7_usize as *mut c_void),
            );
            assert_eq!(
                format!("{authority:?}"),
                "WindowsScmStatusAuthority([REDACTED])"
            );

            let source = include_str!("key_agent_service.rs");
            let (parent_source, sys_source) = source
                .split_once("mod sys {")
                .ok_or("Windows sys module must remain explicit")?;
            assert!(parent_source.contains("use sys::WindowsScmStatusAuthority;"));
            assert!(!parent_source.contains("struct WindowsScmStatusAuthority"));
            let production_sys = sys_source
                .split_once("    #[cfg(test)]")
                .map_or(sys_source, |(production, _tests)| production);
            assert_eq!(
                production_sys
                    .matches("struct WindowsScmStatusAuthority")
                    .count(),
                1
            );
            assert_eq!(
                production_sys.matches("fn bind_registered_status(").count(),
                1
            );
            let (_, authority_body) = production_sys
                .split_once("struct WindowsScmStatusAuthority {")
                .ok_or("sealed authority declaration must remain in sys")?;
            let (authority_fields, _) = authority_body
                .split_once('}')
                .ok_or("sealed authority declaration must remain bounded")?;
            assert_eq!(authority_fields.trim(), "status_handle: usize,");
            Ok(())
        }

        #[test]
        fn stop_progress_reporter_can_complete_without_a_checkpoint() {
            assert!(STOP_PROGRESS_MILLISECONDS < u64::from(STOP_WAIT_HINT_MILLISECONDS));
            assert!(u64::from(STOP_WAIT_HINT_MILLISECONDS) < STOP_DEADLINE_MILLISECONDS);

            let reporter = StopProgressReporter::start();
            assert!(reporter.is_ok());
            if let Ok(reporter) = reporter {
                assert!(reporter.finish().is_ok());
            }
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

    #[cfg(not(all(
        windows,
        feature = "key-agent-service-rpc-status-feasibility-test-hook",
        debug_assertions
    )))]
    #[test]
    fn rpc_status_fixture_is_unavailable_outside_the_exact_debug_build() {
        assert_eq!(
            run_status_rpc_key_agent_service_fixture(),
            Err(KeyAgentServiceFixtureError::Unavailable)
        );
    }

    #[cfg(not(all(
        windows,
        feature = "key-agent-service-token-feasibility-test-hook",
        debug_assertions
    )))]
    #[test]
    fn service_token_fixture_is_unavailable_outside_the_exact_debug_build() {
        assert_eq!(
            run_service_token_key_agent_service_fixture(),
            Err(KeyAgentServiceFixtureError::Unavailable)
        );
    }

    #[cfg(not(all(
        windows,
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    )))]
    #[test]
    fn lpac_rpc_probe_fixture_is_unavailable_outside_the_exact_debug_build() {
        assert_eq!(
            run_lpac_rpc_probe_key_agent_service_fixture(),
            Err(KeyAgentServiceFixtureError::Unavailable)
        );
    }
}
