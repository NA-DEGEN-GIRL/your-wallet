//! Dormant authenticated local-RPC status mechanics and helper-probe service.
//!
//! Status RPC is Windows production-compiled for the sealed lifecycle-effect
//! adapter, while every executable probe remains debug-feature-only. The
//! fixtures prove bounded V1/V2 transport, fresh per-call Windows desktop
//! identity, and expected service-created LPAC helper correlation. They do not
//! prove an enrolled Broker, signed immutable helpers, complete service mutual
//! identity, supported-build coverage, or any wallet/signing authority.

#![allow(unsafe_code)]

mod auth;
#[cfg(all(
    target_arch = "x86_64",
    target_env = "msvc",
    feature = "key-agent-service-desktop-rpc-probe-feasibility-test-hook",
    debug_assertions
))]
mod client_binding;
#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
mod coordinator;
#[cfg(all(
    target_arch = "x86_64",
    target_env = "msvc",
    feature = "key-agent-service-desktop-rpc-probe-feasibility-test-hook",
    debug_assertions
))]
pub(crate) mod desktop_probe;
mod dispatch;
mod epoch;
#[allow(dead_code)]
// Coordinator-only guards remain dormant after the feature-gated router wiring.
mod expected_peer;
mod lifecycle;
#[allow(dead_code)]
// Approval request ordering remains dormant until a production UI compositor exists.
mod request_lifecycle;
#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
mod router;
#[allow(dead_code)]
// Secret Input ordering remains dormant until a production UI compositor exists.
mod secret_input_lifecycle;

use core::{ffi::c_void, fmt};
#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
use std::sync::atomic::AtomicU32;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use key_agent_service_rpc_sys::{
    CallBinding, InterfaceSpec, ManagerError, RpcFrame, install_server_handler,
    server_interface_spec,
};
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::System::Rpc::{
    RPC_STATUS, RpcMgmtStopServerListening, RpcMgmtWaitServerListen, RpcServerListen,
    RpcServerRegisterAuthInfoW, RpcServerRegisterIf3, RpcServerUnregisterIf,
    RpcServerUseProtseqEpW,
};
use windows::core::PCWSTR;

#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
use crate::key_agent_service_launch::ServiceHelperAdmission;
#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
use crate::key_agent_service_launch::{
    FixedLpacRpcEndpointProfileSids, derive_fixed_lpac_rpc_endpoint_profile_sids,
};
#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
use crate::key_agent_service_token::ServiceTokenFixtureProof;

#[cfg(not(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
)))]
use self::auth::AuthenticatedRpcClient;
#[cfg(test)]
use self::auth::RpcAuthError;
#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
pub(crate) use self::auth::{
    AuthenticatedDesktopImpersonation, AuthenticatedRpcClient, CreatedDesktopProcess,
    DESKTOP_PROCESS_CLEANUP_WAIT_MILLISECONDS, DetachedDesktopProcess,
    PendingDebuggerExitProcessCleanup, PendingDebuggerExitProcessSuccess,
    PreparedDebuggerExitProcessSuccess, ServiceCreatedLpacCandidate,
};
#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
use self::coordinator::{ServiceProbeCoordinator, ServiceProbeCoordinatorClient};
#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
use self::dispatch::DispatchError;
use self::dispatch::{AuthenticationFailure, DispatchEngine};
use self::epoch::SystemMonotonicClock;
#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
pub(crate) use self::expected_peer::{
    EXPECTED_HELPER_QUIESCENCE_MILLISECONDS, ExpectedHelperAdmission, ExpectedHelperLease,
    ExpectedHelperPeer, ExpectedHelperRole, ExpectedPeerKey, ExpectedPeerRegistryError,
    ExpectedPeerVerificationError,
};
use self::lifecycle::{
    AdmissionClosedStatusRpcServer, LifecycleHooks, ListeningStatusRpcServer,
    PreparedStatusRpcServer, RpcOps,
};
#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
use self::router::{RoleAwareCallbackPeer, RoleAwareManagerDispatch, RoleAwareManagerPeer};

const RPC_S_OK: i32 = 0;
const RPC_S_ACCESS_DENIED: i32 = 5;
static LOCAL_RPC_PROTOCOL_SEQUENCE_WIDE: [u16; 8] = [110, 99, 97, 108, 114, 112, 99, 0];
const STATUS_RPC_SECURITY_DESCRIPTOR_SDDL: &str = "D:P(A;;GA;;;AU)(A;;GA;;;SY)S:(ML;;NW;;;ME)";
#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
const RPC_ENDPOINT_CONNECT_ACCESS: &str = "0x1";
#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
const RPC_INTERFACE_CALL_ACCESS: &str = "GA";
#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
const LPAC_RPC_LOW_MANDATORY_LABEL: &str = "S:(ML;;NW;;;LW)";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RpcSecurityProfile {
    StatusOnly,
    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    LpacProbe,
}

#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
const fn lpac_probe_security_profile() -> RpcSecurityProfile {
    RpcSecurityProfile::LpacProbe
}

const _: () = assert!(
    lifecycle::STATUS_RPC_MAX_RPC_SIZE as usize == key_agent_service_rpc_sys::RPC_FRAME_SIZE
);

/// Data-free failure of the dormant status worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StatusRpcWorkerError {
    /// A required local-RPC, authentication, epoch, or synchronization boundary failed.
    Unavailable,
    /// RPC-referenced runtime state could not be proven released and remains
    /// retained until process exit.
    RuntimeStateRetained,
}

impl fmt::Display for StatusRpcWorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("key agent status RPC fixture is unavailable")
    }
}

impl std::error::Error for StatusRpcWorkerError {}

/// Closed startup locations; no native error or runtime identity is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RpcStartupStage {
    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    Coordinator,
    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    Context,
    SecurityDescriptor,
    InterfaceSpec,
    PublishContext,
    RegisterAuthentication,
    BindEndpoint,
    InstallHandler,
    RegisterInterface,
    Listen,
}

impl From<lifecycle::StartStage> for RpcStartupStage {
    fn from(stage: lifecycle::StartStage) -> Self {
        match stage {
            lifecycle::StartStage::RegisterAuthentication => Self::RegisterAuthentication,
            lifecycle::StartStage::BindEndpoint => Self::BindEndpoint,
            lifecycle::StartStage::InstallHandler => Self::InstallHandler,
            lifecycle::StartStage::RegisterInterface => Self::RegisterInterface,
            lifecycle::StartStage::Listen => Self::Listen,
        }
    }
}

#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
impl RpcStartupStage {
    pub(super) const fn startup_diagnostic_code(self) -> u32 {
        match self {
            Self::Coordinator => 0x2301,
            Self::Context => 0x2302,
            Self::SecurityDescriptor => 0x2303,
            Self::InterfaceSpec => 0x2304,
            Self::PublishContext => 0x2305,
            Self::RegisterAuthentication => 0x2311,
            Self::BindEndpoint => 0x2312,
            Self::InstallHandler => 0x2313,
            Self::RegisterInterface => 0x2314,
            Self::Listen => 0x2315,
        }
    }
}

/// Separate startup-only transport so status callers keep their existing error contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RpcWorkerStartupError {
    Boundary(RpcStartupStage),
    RuntimeStateRetained,
}

impl RpcWorkerStartupError {
    const fn into_status_error(self) -> StatusRpcWorkerError {
        match self {
            Self::Boundary(_) => StatusRpcWorkerError::Unavailable,
            Self::RuntimeStateRetained => StatusRpcWorkerError::RuntimeStateRetained,
        }
    }
}

impl fmt::Display for RpcWorkerStartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("key agent status RPC fixture is unavailable")
    }
}

impl std::error::Error for RpcWorkerStartupError {}

#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
#[derive(Clone, Copy)]
enum AuthDiagnosticOrigin {
    Callback,
    Manager,
}

/// Closed, data-free diagnostic for this debug service invocation only.
#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AuthStopDiagnostic(u32);

#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
impl AuthStopDiagnostic {
    fn new(origin: AuthDiagnosticOrigin, stage: u32) -> Option<Self> {
        if !(1..=15).contains(&stage) {
            return None;
        }
        Some(Self(match origin {
            AuthDiagnosticOrigin::Callback => 0x6000 + stage,
            AuthDiagnosticOrigin::Manager => 0x6100 + stage,
        }))
    }

    pub(super) const fn code(self) -> u32 {
        self.0
    }
}

/// Constructed only after RPC, coordinator, helper, and context rundown.
#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
pub(super) enum DiagnosticDrainOutcome {
    Complete,
    AuthFailure(AuthStopDiagnostic),
}

struct ServerContext {
    admission: AtomicBool,
    fatal: AtomicBool,
    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    auth_diagnostic: AtomicU32,
    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    other_fatal: AtomicBool,
    callback_auth_inflight: AtomicUsize,
    dispatch: DispatchEngine<AuthenticatedRpcClient, SystemMonotonicClock>,
    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    helpers: ServiceHelperAdmission,
    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    probe_coordinator_client: Option<ServiceProbeCoordinatorClient>,
    // The join owner must share the globally published context lifetime. An
    // RPC rundown failure retains this mutex and the helper registry together.
    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    probe_coordinator_owner: Mutex<Option<ServiceProbeCoordinator>>,
}

impl ServerContext {
    fn new() -> Result<Self, StatusRpcWorkerError> {
        let dispatch = DispatchEngine::new().map_err(|_| StatusRpcWorkerError::Unavailable)?;
        Ok(Self {
            admission: AtomicBool::new(false),
            fatal: AtomicBool::new(false),
            #[cfg(all(
                feature = "key-agent-service-lpac-launch-feasibility-test-hook",
                debug_assertions
            ))]
            auth_diagnostic: AtomicU32::new(0),
            #[cfg(all(
                feature = "key-agent-service-lpac-launch-feasibility-test-hook",
                debug_assertions
            ))]
            other_fatal: AtomicBool::new(false),
            callback_auth_inflight: AtomicUsize::new(0),
            dispatch,
            #[cfg(all(
                feature = "key-agent-service-lpac-launch-feasibility-test-hook",
                debug_assertions
            ))]
            helpers: ServiceHelperAdmission::new(),
            #[cfg(all(
                feature = "key-agent-service-lpac-launch-feasibility-test-hook",
                debug_assertions
            ))]
            probe_coordinator_client: None,
            #[cfg(all(
                feature = "key-agent-service-lpac-launch-feasibility-test-hook",
                debug_assertions
            ))]
            probe_coordinator_owner: Mutex::new(None),
        })
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    fn new_with_probe_coordinator(
        helpers: ServiceHelperAdmission,
        probe_coordinator: ServiceProbeCoordinator,
    ) -> Result<Self, StatusRpcWorkerError> {
        let dispatch = DispatchEngine::new().map_err(|_| StatusRpcWorkerError::Unavailable)?;
        let probe_coordinator_client = probe_coordinator.client();
        Ok(Self {
            admission: AtomicBool::new(false),
            fatal: AtomicBool::new(false),
            auth_diagnostic: AtomicU32::new(0),
            other_fatal: AtomicBool::new(false),
            callback_auth_inflight: AtomicUsize::new(0),
            dispatch,
            helpers,
            probe_coordinator_client: Some(probe_coordinator_client),
            probe_coordinator_owner: Mutex::new(Some(probe_coordinator)),
        })
    }

    fn try_callback_auth_permit(&self) -> Option<CallbackAuthPermit<'_>> {
        if self.fatal.load(Ordering::Acquire) || !self.admission.load(Ordering::Acquire) {
            return None;
        }
        #[cfg(all(
            feature = "key-agent-service-lpac-launch-feasibility-test-hook",
            debug_assertions
        ))]
        if self.probe_coordinator_has_failed() {
            self.latch_fatal_runtime();
            return None;
        }
        self.callback_auth_inflight
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < lifecycle::STATUS_RPC_MAX_CALLS as usize).then_some(current + 1)
            })
            .ok()?;
        Some(CallbackAuthPermit { context: self })
    }

    fn exchange<'call>(
        &self,
        binding: CallBinding<'call>,
        request: &'call RpcFrame,
    ) -> Result<RpcFrame, ManagerError> {
        if self.fatal.load(Ordering::Acquire) {
            return Err(ManagerError::CallFailed);
        }
        #[cfg(all(
            feature = "key-agent-service-lpac-launch-feasibility-test-hook",
            debug_assertions
        ))]
        if self.probe_coordinator_has_failed() {
            self.latch_fatal_runtime();
            return Err(ManagerError::CallFailed);
        }
        if !self.admission.load(Ordering::Acquire) {
            return Err(ManagerError::ServerUnavailable);
        }

        #[cfg(not(all(
            feature = "key-agent-service-lpac-launch-feasibility-test-hook",
            debug_assertions
        )))]
        {
            self.dispatch
                .exchange_with(request, move || {
                    auth::authenticate_call(binding).map_err(AuthenticationFailure::from)
                })
                .map_err(ManagerError::from)
        }

        #[cfg(all(
            feature = "key-agent-service-lpac-launch-feasibility-test-hook",
            debug_assertions
        ))]
        {
            let auth_failure_observed = core::cell::Cell::new(false);
            let observed = &auth_failure_observed;
            let routed = router::route_manager(&self.dispatch, &self.helpers, request, move || {
                let peer = auth::authenticate_role_aware_call(binding).map_err(|failure| {
                    observed.set(true);
                    self.latch_auth_diagnostic(AuthDiagnosticOrigin::Manager, failure.code());
                    AuthenticationFailure::from(failure.error())
                })?;
                Ok(match peer {
                    auth::AuthenticatedManagerPeer::Desktop(desktop) => {
                        RoleAwareManagerPeer::Desktop(desktop)
                    }
                    auth::AuthenticatedManagerPeer::ServiceCreatedLpac(helper) => {
                        RoleAwareManagerPeer::Helper(helper)
                    }
                })
            });
            let routed = self.map_lpac_auth_dispatch_result(routed, auth_failure_observed.get())?;

            match routed {
                RoleAwareManagerDispatch::Immediate(response) => Ok(response),
                RoleAwareManagerDispatch::Launch(launch) => {
                    if let Some(coordinator) = &self.probe_coordinator_client {
                        let response = coordinator.complete_launch(launch);
                        if coordinator.has_failed() {
                            self.latch_fatal_runtime();
                        }
                        self.map_lpac_dispatch_result(response)
                    } else {
                        let (authenticated_desktop, completion) = launch.into_parts();
                        let response = completion
                            .complete(key_agent_service_wire::debug_v2::DesktopResult::Unavailable);
                        drop(authenticated_desktop);
                        self.map_lpac_dispatch_result(response)
                    }
                }
            }
        }
    }

    fn invalidate_epochs(&self) {
        let dispatch_failed = self.dispatch.stop().is_err();
        #[cfg(all(
            feature = "key-agent-service-lpac-launch-feasibility-test-hook",
            debug_assertions
        ))]
        if let Some(coordinator) = &self.probe_coordinator_client {
            coordinator.begin_stop();
        }

        if dispatch_failed {
            self.latch_fatal_runtime();
        }
    }

    fn latch_fatal_runtime(&self) {
        #[cfg(all(
            feature = "key-agent-service-lpac-launch-feasibility-test-hook",
            debug_assertions
        ))]
        self.other_fatal.store(true, Ordering::Release);
        self.close_for_fatal_runtime();
    }

    fn close_for_fatal_runtime(&self) {
        self.admission.store(false, Ordering::Release);
        self.fatal.store(true, Ordering::Release);
        #[cfg(all(
            feature = "key-agent-service-lpac-launch-feasibility-test-hook",
            debug_assertions
        ))]
        if let Some(coordinator) = &self.probe_coordinator_client {
            coordinator.begin_stop();
        }
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    fn latch_auth_diagnostic(&self, origin: AuthDiagnosticOrigin, stage: u32) {
        let Some(diagnostic) = AuthStopDiagnostic::new(origin, stage) else {
            self.latch_fatal_runtime();
            return;
        };
        let _ = self.auth_diagnostic.compare_exchange(
            0,
            diagnostic.code(),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        self.close_for_fatal_runtime();
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    fn auth_diagnostic(&self) -> Option<AuthStopDiagnostic> {
        match self.auth_diagnostic.load(Ordering::Acquire) {
            code @ (0x6001..=0x600f | 0x6101..=0x610f) => Some(AuthStopDiagnostic(code)),
            _ => None,
        }
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    fn diagnostic_after_clean_drain(&self) -> Result<DiagnosticDrainOutcome, StatusRpcWorkerError> {
        if self.other_fatal.load(Ordering::Acquire) {
            return Err(StatusRpcWorkerError::Unavailable);
        }
        if let Some(diagnostic) = self.auth_diagnostic() {
            return Ok(DiagnosticDrainOutcome::AuthFailure(diagnostic));
        }
        if self.fatal.load(Ordering::Acquire) {
            return Err(StatusRpcWorkerError::Unavailable);
        }
        Ok(DiagnosticDrainOutcome::Complete)
    }

    fn legacy_after_clean_drain(&self) -> Result<(), StatusRpcWorkerError> {
        if self.fatal.load(Ordering::Acquire) {
            Err(StatusRpcWorkerError::Unavailable)
        } else {
            Ok(())
        }
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    fn probe_coordinator_has_failed(&self) -> bool {
        self.probe_coordinator_client
            .as_ref()
            .is_some_and(ServiceProbeCoordinatorClient::has_failed)
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    fn map_lpac_dispatch_result<T>(
        &self,
        result: Result<T, DispatchError>,
    ) -> Result<T, ManagerError> {
        self.map_lpac_auth_dispatch_result(result, false)
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    fn map_lpac_auth_dispatch_result<T>(
        &self,
        result: Result<T, DispatchError>,
        auth_failure_observed: bool,
    ) -> Result<T, ManagerError> {
        result.map_err(|error| {
            // Only this call's early-returned native auth failure is tagged.
            // A global diagnostic latch never excuses another internal error.
            if error == DispatchError::Internal && !auth_failure_observed {
                self.latch_fatal_runtime();
            }
            ManagerError::from(error)
        })
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    fn stop_probe_coordinator_and_helpers(&self) -> Result<(), StatusRpcWorkerError> {
        // Take the join owner under the mutex, but never hold the mutex across
        // the bounded coordinator join or helper process cleanup.
        let coordinator = match self.probe_coordinator_owner.lock() {
            Ok(mut owner) => match (self.probe_coordinator_client.is_some(), owner.is_some()) {
                (false, false) => Ok(None),
                (true, true) => Ok(owner.take()),
                (false, true) | (true, false) => Err(()),
            },
            Err(_) => Err(()),
        };

        let coordinator_failed = match coordinator {
            Ok(Some(coordinator)) => coordinator.stop_and_drain().is_err(),
            Ok(None) => false,
            Err(()) => true,
        };
        let coordinator_reported_failure = self.probe_coordinator_has_failed();
        let helpers_failed = self.helpers.stop().is_err();
        if coordinator_failed || coordinator_reported_failure || helpers_failed {
            self.latch_fatal_runtime();
            Err(StatusRpcWorkerError::Unavailable)
        } else {
            Ok(())
        }
    }
}

struct CallbackAuthPermit<'context> {
    context: &'context ServerContext,
}

impl Drop for CallbackAuthPermit<'_> {
    fn drop(&mut self) {
        let previous = self
            .context
            .callback_auth_inflight
            .fetch_sub(1, Ordering::AcqRel);
        if previous == 0 {
            std::process::abort();
        }
    }
}

impl fmt::Debug for ServerContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServerContext([REDACTED])")
    }
}

#[derive(Clone)]
struct ServerHooks {
    context: Arc<ServerContext>,
}

impl LifecycleHooks for ServerHooks {
    fn set_admission(&mut self, accepting: bool) {
        self.context.admission.store(accepting, Ordering::Release);
    }

    fn invalidate_epochs(&mut self) {
        self.context.invalidate_epochs();
    }
}

impl fmt::Debug for ServerHooks {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServerHooks([REDACTED])")
    }
}

static SERVER_CONTEXT: Mutex<Option<Arc<ServerContext>>> = Mutex::new(None);

type LiveStatusServer = ListeningStatusRpcServer<WindowsRpcOps, ServerHooks>;
type AdmissionClosedLiveStatusServer = AdmissionClosedStatusRpcServer<WindowsRpcOps, ServerHooks>;

/// SCM-owned worker for one process-lifetime status RPC fixture.
pub(super) struct StatusRpcWorker {
    server: LiveStatusServer,
    context: Arc<ServerContext>,
}

/// SCM-owned status RPC worker whose admission gate is irreversibly closed.
#[must_use = "closed status RPC worker must be drained or deliberately retained"]
pub(super) struct AdmissionClosedStatusRpcWorker {
    server: AdmissionClosedLiveStatusServer,
    context: Arc<ServerContext>,
}

impl StatusRpcWorker {
    pub(super) fn start() -> Result<Self, StatusRpcWorkerError> {
        let context = Arc::new(ServerContext::new()?);
        let (server, context) = start_status_rpc_server(context, RpcSecurityProfile::StatusOnly)
            .map_err(RpcWorkerStartupError::into_status_error)?;
        Ok(Self { server, context })
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    pub(super) fn start_lpac_rpc_probe(
        service_token: ServiceTokenFixtureProof,
    ) -> Result<Self, RpcWorkerStartupError> {
        let helpers = ServiceHelperAdmission::new();
        let probe_coordinator = ServiceProbeCoordinator::start(service_token, helpers.clone())
            .map_err(|_| RpcWorkerStartupError::Boundary(RpcStartupStage::Coordinator))?;
        let context = Arc::new(
            ServerContext::new_with_probe_coordinator(helpers, probe_coordinator)
                .map_err(|_| RpcWorkerStartupError::Boundary(RpcStartupStage::Context))?,
        );
        let (server, context) = start_status_rpc_server(context, lpac_probe_security_profile())?;
        Ok(Self { server, context })
    }

    pub(super) fn begin_accepting(&mut self) -> Result<(), StatusRpcWorkerError> {
        if self.context.fatal.load(Ordering::Acquire) {
            return Err(StatusRpcWorkerError::Unavailable);
        }
        #[cfg(all(
            feature = "key-agent-service-lpac-launch-feasibility-test-hook",
            debug_assertions
        ))]
        if self.context.probe_coordinator_has_failed() {
            self.context.latch_fatal_runtime();
            return Err(StatusRpcWorkerError::Unavailable);
        }
        self.server.enable_admission_after_scm_running();
        if !self.server.is_admitting() || !self.context.admission.load(Ordering::Acquire) {
            return Err(StatusRpcWorkerError::Unavailable);
        }
        Ok(())
    }

    pub(super) fn close_admission(self) -> AdmissionClosedStatusRpcWorker {
        let Self { server, context } = self;
        AdmissionClosedStatusRpcWorker {
            server: server.close_admission(),
            context,
        }
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    pub(super) fn auth_diagnostic_stop_requested(&self) -> bool {
        self.context.auth_diagnostic().is_some()
    }
}

impl AdmissionClosedStatusRpcWorker {
    pub(super) fn drain(self) -> Result<(), StatusRpcWorkerError> {
        let context = self.drain_resources()?;
        context.legacy_after_clean_drain()
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    pub(super) fn drain_for_auth_diagnostic(
        self,
    ) -> Result<DiagnosticDrainOutcome, StatusRpcWorkerError> {
        diagnostic_from_drain_result(self.drain_resources())
    }

    fn drain_resources(self) -> Result<Arc<ServerContext>, StatusRpcWorkerError> {
        let Self { server, context } = self;
        if let Err(failure) = server.drain() {
            let report = failure.report();
            let _ = (report.stage(), report.error(), report.secondary());
            debug_assert!(failure.resources_are_retained());
            return Err(StatusRpcWorkerError::RuntimeStateRetained);
        }
        #[cfg(all(
            feature = "key-agent-service-lpac-launch-feasibility-test-hook",
            debug_assertions
        ))]
        context.stop_probe_coordinator_and_helpers()?;
        clear_context(&context)?;
        Ok(context)
    }
}

#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
fn diagnostic_from_drain_result(
    drained: Result<Arc<ServerContext>, StatusRpcWorkerError>,
) -> Result<DiagnosticDrainOutcome, StatusRpcWorkerError> {
    drained?.diagnostic_after_clean_drain()
}

fn start_status_rpc_server(
    context: Arc<ServerContext>,
    security_profile: RpcSecurityProfile,
) -> Result<(LiveStatusServer, Arc<ServerContext>), RpcWorkerStartupError> {
    let security_descriptor = OwnedSecurityDescriptor::new(security_profile)
        .map_err(|_| RpcWorkerStartupError::Boundary(RpcStartupStage::SecurityDescriptor))?;
    let interface_spec = server_interface_spec().ok_or(RpcWorkerStartupError::Boundary(
        RpcStartupStage::InterfaceSpec,
    ))?;
    publish_context(Arc::clone(&context))
        .map_err(|_| RpcWorkerStartupError::Boundary(RpcStartupStage::PublishContext))?;

    let prepared = PreparedStatusRpcServer::new(
        WindowsRpcOps,
        interface_spec,
        security_descriptor,
        ServerHooks {
            context: Arc::clone(&context),
        },
    );
    match prepared.start() {
        Ok(server) => Ok((server, context)),
        Err(failure) => {
            let _ = (failure.stage(), failure.error());
            if let Some(cleanup) = failure.cleanup_failure() {
                let _ = (cleanup.stage(), cleanup.error(), cleanup.secondary());
            }
            if failure.resources_are_retained() {
                return Err(RpcWorkerStartupError::RuntimeStateRetained);
            }
            #[cfg(all(
                feature = "key-agent-service-lpac-launch-feasibility-test-hook",
                debug_assertions
            ))]
            if context.stop_probe_coordinator_and_helpers().is_err() {
                // The published context and uncertain terminal owners must stay
                // retained, and SCM must not classify this as a clean boundary
                // failure that permits SERVICE_STOPPED.
                return Err(RpcWorkerStartupError::RuntimeStateRetained);
            }
            if clear_context(&context).is_err() {
                return Err(RpcWorkerStartupError::RuntimeStateRetained);
            }
            Err(RpcWorkerStartupError::Boundary(failure.stage().into()))
        }
    }
}

impl fmt::Debug for StatusRpcWorker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StatusRpcWorker([REDACTED])")
    }
}

impl fmt::Debug for AdmissionClosedStatusRpcWorker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdmissionClosedStatusRpcWorker([REDACTED])")
    }
}

fn publish_context(context: Arc<ServerContext>) -> Result<(), StatusRpcWorkerError> {
    let mut slot = SERVER_CONTEXT
        .lock()
        .map_err(|_| StatusRpcWorkerError::Unavailable)?;
    if slot.is_some() {
        return Err(StatusRpcWorkerError::Unavailable);
    }
    *slot = Some(context);
    Ok(())
}

fn current_context() -> Result<Arc<ServerContext>, ManagerError> {
    SERVER_CONTEXT
        .lock()
        .map_err(|_| ManagerError::CallFailed)?
        .as_ref()
        .cloned()
        .ok_or(ManagerError::ServerUnavailable)
}

fn clear_context(expected: &Arc<ServerContext>) -> Result<(), StatusRpcWorkerError> {
    let mut slot = SERVER_CONTEXT
        .lock()
        .map_err(|_| StatusRpcWorkerError::Unavailable)?;
    let Some(current) = slot.as_ref() else {
        return Err(StatusRpcWorkerError::Unavailable);
    };
    if !Arc::ptr_eq(current, expected) {
        return Err(StatusRpcWorkerError::Unavailable);
    }
    *slot = None;
    Ok(())
}

fn exchange_handler<'call>(
    binding: CallBinding<'call>,
    request: &'call RpcFrame,
) -> Result<RpcFrame, ManagerError> {
    current_context()?.exchange(binding, request)
}

unsafe extern "system" fn interface_security_callback(
    _interface_uuid: *const c_void,
    call_context: *const c_void,
) -> RPC_STATUS {
    let Ok(context) = current_context() else {
        return RPC_STATUS(RPC_S_ACCESS_DENIED);
    };
    let Some(_permit) = context.try_callback_auth_permit() else {
        return RPC_STATUS(RPC_S_ACCESS_DENIED);
    };
    #[cfg(not(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    )))]
    // SAFETY: Rpcrt4 supplies the synchronous call binding as callback context;
    // the authentication helper neither retains nor frees it.
    let authorization = unsafe { auth::authenticate_callback_context(call_context) }.map(|_| ());

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    let auth_failure_observed = core::cell::Cell::new(false);

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    let authorization = router::authorize_callback(&context.helpers, || {
        // SAFETY: Rpcrt4 supplies the synchronous call binding as callback
        // context; the authentication helper neither retains nor frees it.
        let peer = unsafe { auth::authenticate_role_aware_callback_context(call_context) }
            .map_err(|failure| {
                auth_failure_observed.set(true);
                context.latch_auth_diagnostic(AuthDiagnosticOrigin::Callback, failure.code());
                AuthenticationFailure::from(failure.error())
            })?;
        Ok(match peer {
            auth::AuthenticatedCallbackPeer::Desktop(desktop) => {
                RoleAwareCallbackPeer::Desktop(desktop)
            }
            auth::AuthenticatedCallbackPeer::ServiceCreatedLpac(helper) => {
                RoleAwareCallbackPeer::Helper(helper)
            }
        })
    });

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    if matches!(authorization, Err(DispatchError::Internal)) && !auth_failure_observed.get() {
        context.latch_fatal_runtime();
    }

    match authorization {
        Ok(()) => RPC_STATUS(RPC_S_OK),
        // The RPC runtime exposes every non-OK If3 callback result to the
        // client as access denied, so both closed auth categories intentionally
        // collapse here. The manager still authenticates independently.
        Err(_) => RPC_STATUS(RPC_S_ACCESS_DENIED),
    }
}

struct OwnedSecurityDescriptor {
    endpoint: OwnedLocalSecurityDescriptor,
    // Status-only preserves its historical one-descriptor contract. The LPAC
    // probe uses a connect-only endpoint DACL and a separate interface DACL,
    // both bound to the same exact package identities.
    interface: Option<OwnedLocalSecurityDescriptor>,
}

impl OwnedSecurityDescriptor {
    fn new(profile: RpcSecurityProfile) -> Result<Self, StatusRpcWorkerError> {
        match profile {
            RpcSecurityProfile::StatusOnly => Ok(Self {
                endpoint: OwnedLocalSecurityDescriptor::from_sddl(
                    STATUS_RPC_SECURITY_DESCRIPTOR_SDDL,
                )?,
                interface: None,
            }),
            #[cfg(all(
                feature = "key-agent-service-lpac-launch-feasibility-test-hook",
                debug_assertions
            ))]
            RpcSecurityProfile::LpacProbe => {
                let profile_sids = derive_fixed_lpac_rpc_endpoint_profile_sids()
                    .map_err(|_| StatusRpcWorkerError::Unavailable)?;
                let policy = LpacRpcSecuritySddl::new(&profile_sids)?;
                Ok(Self {
                    endpoint: OwnedLocalSecurityDescriptor::from_sddl(&policy.endpoint)?,
                    interface: Some(OwnedLocalSecurityDescriptor::from_sddl(&policy.interface)?),
                })
            }
        }
    }

    const fn endpoint_raw(&self) -> *const c_void {
        self.endpoint.as_raw()
    }

    fn interface_raw(&self) -> *const c_void {
        self.interface.as_ref().map_or_else(
            || self.endpoint.as_raw(),
            OwnedLocalSecurityDescriptor::as_raw,
        )
    }
}

impl fmt::Debug for OwnedSecurityDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OwnedSecurityDescriptor([REDACTED])")
    }
}

struct OwnedLocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl OwnedLocalSecurityDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self, StatusRpcWorkerError> {
        if sddl.is_empty() || sddl.contains('\0') {
            return Err(StatusRpcWorkerError::Unavailable);
        }
        let wide: Vec<u16> = sddl.encode_utf16().chain(core::iter::once(0)).collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `wide` is a live NUL-terminated SDDL string. Success returns
        // one self-relative LocalAlloc descriptor owned by this wrapper.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &raw mut descriptor,
                None,
            )
        }
        .map_err(|_| StatusRpcWorkerError::Unavailable)?;
        if descriptor.0.is_null() {
            return Err(StatusRpcWorkerError::Unavailable);
        }
        Ok(Self(descriptor))
    }

    const fn as_raw(&self) -> *const c_void {
        self.0.0.cast_const()
    }
}

impl fmt::Debug for OwnedLocalSecurityDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OwnedLocalSecurityDescriptor([REDACTED])")
    }
}

impl Drop for OwnedLocalSecurityDescriptor {
    fn drop(&mut self) {
        if self.0.0.is_null() {
            return;
        }
        // SAFETY: this is the exact LocalAlloc-family pointer returned by the
        // SDDL converter and lifecycle rundown proved Rpcrt4 no longer uses it.
        let remainder = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
        if !remainder.0.is_null() {
            std::process::abort();
        }
        self.0 = PSECURITY_DESCRIPTOR::default();
    }
}

#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
struct LpacRpcSecuritySddl {
    endpoint: String,
    interface: String,
}

#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
impl LpacRpcSecuritySddl {
    fn new(profile_sids: &FixedLpacRpcEndpointProfileSids) -> Result<Self, StatusRpcWorkerError> {
        let expected_sids = profile_sids.as_ordered_pair();
        if expected_sids[0] == expected_sids[1] {
            return Err(StatusRpcWorkerError::Unavailable);
        }
        let policy = Self {
            endpoint: lpac_rpc_sddl(RPC_ENDPOINT_CONNECT_ACCESS, expected_sids),
            interface: lpac_rpc_sddl(RPC_INTERFACE_CALL_ACCESS, expected_sids),
        };
        if !policy.is_exact_for(expected_sids) {
            return Err(StatusRpcWorkerError::Unavailable);
        }
        Ok(policy)
    }

    fn is_exact_for(&self, expected_sids: [&str; 2]) -> bool {
        expected_sids[0] != expected_sids[1]
            && self.endpoint == lpac_rpc_sddl(RPC_ENDPOINT_CONNECT_ACCESS, expected_sids)
            && self.interface == lpac_rpc_sddl(RPC_INTERFACE_CALL_ACCESS, expected_sids)
    }
}

#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
impl fmt::Debug for LpacRpcSecuritySddl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LpacRpcSecuritySddl([REDACTED])")
    }
}

#[cfg(all(
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
fn lpac_rpc_sddl(access: &str, expected_sids: [&str; 2]) -> String {
    let [approval, secret_input] = expected_sids;
    format!(
        "D:P(A;;{access};;;AU)(A;;{access};;;SY)(A;;{access};;;{approval})(A;;{access};;;{secret_input}){LPAC_RPC_LOW_MANDATORY_LABEL}"
    )
}

#[derive(Clone, Copy, Debug, Default)]
struct WindowsRpcOps;

impl RpcOps for WindowsRpcOps {
    type Error = RpcRuntimeError;
    type InterfaceSpec = InterfaceSpec;
    type EndpointSecurityDescriptor = OwnedSecurityDescriptor;

    fn register_auth_info_without_principal(
        &mut self,
        authentication_service: u32,
    ) -> Result<(), Self::Error> {
        // SAFETY: null principal selects the fixed WINNT service credentials;
        // no custom key callback or argument is supplied.
        rpc_result(unsafe {
            RpcServerRegisterAuthInfoW(PCWSTR::null(), authentication_service, None, None)
        })
    }

    fn use_protocol_sequence_endpoint(
        &mut self,
        protocol_sequence: &'static str,
        max_calls: u32,
        endpoint: &'static str,
        security_descriptor: &Self::EndpointSecurityDescriptor,
    ) -> Result<(), Self::Error> {
        if protocol_sequence != lifecycle::LOCAL_RPC_PROTOCOL_SEQUENCE
            || endpoint != key_agent_service_rpc_sys::LOCAL_RPC_ENDPOINT
        {
            return Err(RpcRuntimeError);
        }
        // SAFETY: both fixed wide strings are NUL-terminated and the immutable
        // descriptor is retained through complete RPC rundown.
        rpc_result(unsafe {
            RpcServerUseProtseqEpW(
                PCWSTR(LOCAL_RPC_PROTOCOL_SEQUENCE_WIDE.as_ptr()),
                max_calls,
                PCWSTR(key_agent_service_rpc_sys::LOCAL_RPC_ENDPOINT_WIDE.as_ptr()),
                Some(security_descriptor.endpoint_raw()),
            )
        })
    }

    fn install_process_lifetime_handler(&mut self) -> Result<(), Self::Error> {
        install_server_handler(exchange_handler).map_err(|_| RpcRuntimeError)
    }

    fn register_interface3(
        &mut self,
        interface_spec: Self::InterfaceSpec,
        flags: u32,
        max_calls: u32,
        max_rpc_size: u32,
        security_descriptor: &Self::EndpointSecurityDescriptor,
    ) -> Result<(), Self::Error> {
        // SAFETY: the generated ifspec and immutable descriptor are retained
        // until exact unregister-and-wait rundown completes.
        rpc_result(unsafe {
            RpcServerRegisterIf3(
                interface_spec.as_raw().cast_const(),
                None,
                None,
                flags,
                max_calls,
                max_rpc_size,
                Some(interface_security_callback),
                Some(security_descriptor.interface_raw()),
            )
        })
    }

    fn listen(
        &mut self,
        minimum_call_threads: u32,
        max_calls: u32,
        dont_wait: u32,
    ) -> Result<(), Self::Error> {
        // SAFETY: registration and the fixed endpoint precede this call.
        rpc_result(unsafe { RpcServerListen(minimum_call_threads, max_calls, dont_wait) })
    }

    fn stop_server_listening(&mut self) -> Result<(), Self::Error> {
        // SAFETY: NULL selects this process's server as required by the fixed
        // consume-only shutdown sequence.
        rpc_result(unsafe { RpcMgmtStopServerListening(None) })
    }

    fn unregister_interface_waiting(
        &mut self,
        interface_spec: Self::InterfaceSpec,
        wait_for_calls_to_complete: bool,
    ) -> Result<(), Self::Error> {
        if !wait_for_calls_to_complete {
            return Err(RpcRuntimeError);
        }
        // SAFETY: this is the exact generated ifspec registered above; TRUE
        // requires all active manager calls to finish before return.
        rpc_result(unsafe {
            RpcServerUnregisterIf(Some(interface_spec.as_raw().cast_const()), None, 1)
        })
    }

    fn wait_server_listen(&mut self) -> Result<(), Self::Error> {
        // SAFETY: StopServerListening already succeeded on this path.
        rpc_result(unsafe { RpcMgmtWaitServerListen() })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct RpcRuntimeError;

impl fmt::Debug for RpcRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RpcRuntimeError([REDACTED])")
    }
}

fn rpc_result(status: RPC_STATUS) -> Result<(), RpcRuntimeError> {
    if status.0 == RPC_S_OK {
        Ok(())
    } else {
        Err(RpcRuntimeError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use key_agent_service_rpc_sys::{BindingHandle, exchange};
    use key_agent_service_wire::{
        OpenEpochRequest, ServiceCommand, ServiceCommandRequest, ServiceRequest, ServiceRequestId,
        ServiceResponse, ServiceStatus, decode_response, encode_request,
    };
    use windows::Win32::System::Rpc::{
        RpcBindingFree, RpcBindingFromStringBindingW, RpcBindingSetAuthInfoW,
        RpcStringBindingComposeW, RpcStringFreeW,
    };
    use windows::core::PWSTR;

    const TEST_RPC_AUTHN_LEVEL_PACKET_PRIVACY: u32 = 6;
    const TEST_RPC_AUTHN_SERVICE_WINNT: u32 = 10;
    const TEST_RPC_AUTHZ_SERVICE_NONE: u32 = 0;

    #[test]
    fn startup_stages_preserve_the_status_only_error_contract() {
        for stage in [
            RpcStartupStage::SecurityDescriptor,
            RpcStartupStage::InterfaceSpec,
            RpcStartupStage::PublishContext,
            RpcStartupStage::RegisterAuthentication,
            RpcStartupStage::BindEndpoint,
            RpcStartupStage::InstallHandler,
            RpcStartupStage::RegisterInterface,
            RpcStartupStage::Listen,
        ] {
            assert_eq!(
                RpcWorkerStartupError::Boundary(stage).into_status_error(),
                StatusRpcWorkerError::Unavailable
            );
        }
        assert_eq!(
            RpcWorkerStartupError::RuntimeStateRetained.into_status_error(),
            StatusRpcWorkerError::RuntimeStateRetained
        );
    }

    #[test]
    fn startup_lifecycle_stage_mapping_is_exact_and_data_free() {
        for (stage, expected) in [
            (
                lifecycle::StartStage::RegisterAuthentication,
                RpcStartupStage::RegisterAuthentication,
            ),
            (
                lifecycle::StartStage::BindEndpoint,
                RpcStartupStage::BindEndpoint,
            ),
            (
                lifecycle::StartStage::InstallHandler,
                RpcStartupStage::InstallHandler,
            ),
            (
                lifecycle::StartStage::RegisterInterface,
                RpcStartupStage::RegisterInterface,
            ),
            (lifecycle::StartStage::Listen, RpcStartupStage::Listen),
        ] {
            assert_eq!(RpcStartupStage::from(stage), expected);
        }
        assert_eq!(
            RpcWorkerStartupError::RuntimeStateRetained.to_string(),
            "key agent status RPC fixture is unavailable"
        );
        assert_eq!(
            format!("{:?}", RpcWorkerStartupError::RuntimeStateRetained),
            "RuntimeStateRetained"
        );
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    #[test]
    fn lpac_startup_codes_are_closed_unique_and_redacted() {
        let cases = [
            (RpcStartupStage::Coordinator, 0x2301, "Coordinator"),
            (RpcStartupStage::Context, 0x2302, "Context"),
            (
                RpcStartupStage::SecurityDescriptor,
                0x2303,
                "SecurityDescriptor",
            ),
            (RpcStartupStage::InterfaceSpec, 0x2304, "InterfaceSpec"),
            (RpcStartupStage::PublishContext, 0x2305, "PublishContext"),
            (
                RpcStartupStage::RegisterAuthentication,
                0x2311,
                "RegisterAuthentication",
            ),
            (RpcStartupStage::BindEndpoint, 0x2312, "BindEndpoint"),
            (RpcStartupStage::InstallHandler, 0x2313, "InstallHandler"),
            (
                RpcStartupStage::RegisterInterface,
                0x2314,
                "RegisterInterface",
            ),
            (RpcStartupStage::Listen, 0x2315, "Listen"),
        ];
        let mut codes = std::collections::BTreeSet::new();
        for (stage, code, name) in cases {
            assert_eq!(stage.startup_diagnostic_code(), code);
            assert!(codes.insert(code));
            let error = RpcWorkerStartupError::Boundary(stage);
            assert_eq!(error.into_status_error(), StatusRpcWorkerError::Unavailable);
            assert_eq!(
                error.to_string(),
                "key agent status RPC fixture is unavailable"
            );
            assert_eq!(format!("{error:?}"), format!("Boundary({name})"));
        }
        assert_eq!(codes.len(), 10);
    }

    struct OwnedTestBinding(*mut c_void);

    impl OwnedTestBinding {
        fn connect() -> Result<Self, &'static str> {
            let mut string_binding = PWSTR::null();
            // SAFETY: every input is a fixed NUL-terminated string and the RPC
            // runtime returns one string owner through the live output slot.
            let compose_status = unsafe {
                RpcStringBindingComposeW(
                    PCWSTR::null(),
                    PCWSTR(LOCAL_RPC_PROTOCOL_SEQUENCE_WIDE.as_ptr()),
                    PCWSTR::null(),
                    PCWSTR(key_agent_service_rpc_sys::LOCAL_RPC_ENDPOINT_WIDE.as_ptr()),
                    PCWSTR::null(),
                    Some(&raw mut string_binding),
                )
            };
            let string_binding = OwnedRpcString(string_binding);
            rpc_result(compose_status).map_err(|_| "compose binding")?;
            if string_binding.0.is_null() {
                return Err("composed binding is null");
            }

            let mut binding = core::ptr::null_mut::<c_void>();
            // SAFETY: the composed string owner remains live through the
            // conversion and receives one independent binding owner.
            let binding_status = unsafe {
                RpcBindingFromStringBindingW(
                    PCWSTR(string_binding.0.0.cast_const()),
                    &raw mut binding,
                )
            };
            let binding = Self(binding);
            rpc_result(binding_status).map_err(|_| "convert binding")?;
            if binding.0.is_null() {
                return Err("converted binding is null");
            }

            // SAFETY: the binding is live; implicit credentials are restricted
            // to exact WINNT packet-privacy authentication for this probe.
            rpc_result(unsafe {
                RpcBindingSetAuthInfoW(
                    binding.0.cast_const(),
                    PCWSTR::null(),
                    TEST_RPC_AUTHN_LEVEL_PACKET_PRIVACY,
                    TEST_RPC_AUTHN_SERVICE_WINNT,
                    None,
                    TEST_RPC_AUTHZ_SERVICE_NONE,
                )
            })
            .map_err(|_| "set binding authentication")?;
            Ok(binding)
        }

        fn call(&self, request: &ServiceRequest) -> Result<ServiceResponse, &'static str> {
            // SAFETY: this owner stays live until the synchronous generated
            // client call and never transfers or frees the borrowed handle.
            let binding = unsafe { BindingHandle::from_raw(self.0) }.ok_or("borrow binding")?;
            let frame =
                RpcFrame::from_payload(&encode_request(request)).map_err(|_| "frame request")?;
            let response = exchange(&binding, &frame).map_err(|status| match status.code() {
                5 => "exchange access denied",
                87 => "exchange invalid argument",
                1_723 => "exchange server too busy",
                1_722 => "exchange server unavailable",
                1_726 => "exchange call failed",
                _ => "exchange failed",
            })?;
            decode_response(response.payload()).map_err(|_| "decode response")
        }
    }

    impl Drop for OwnedTestBinding {
        fn drop(&mut self) {
            if self.0.is_null() {
                return;
            }
            // SAFETY: this is the exact binding owner returned by Rpcrt4.
            let status = unsafe { RpcBindingFree(&raw mut self.0) };
            if status.0 != RPC_S_OK || !self.0.is_null() {
                std::process::abort();
            }
        }
    }

    struct OwnedRpcString(PWSTR);

    impl Drop for OwnedRpcString {
        fn drop(&mut self) {
            if self.0.0.is_null() {
                return;
            }
            // SAFETY: this is the exact string owner returned by Rpcrt4.
            let status = unsafe { RpcStringFreeW(&raw mut self.0) };
            if status.0 != RPC_S_OK || !self.0.0.is_null() {
                std::process::abort();
            }
        }
    }

    #[test]
    fn constants_bind_generated_frame_and_endpoint() {
        assert_eq!(
            lifecycle::STATUS_RPC_MAX_RPC_SIZE as usize,
            key_agent_service_rpc_sys::RPC_FRAME_SIZE
        );
        assert_eq!(
            lifecycle::STATUS_RPC_ENDPOINT,
            key_agent_service_rpc_sys::LOCAL_RPC_ENDPOINT
        );
    }

    #[test]
    fn status_only_security_profile_preserves_the_existing_descriptor_contract()
    -> Result<(), StatusRpcWorkerError> {
        assert_eq!(
            STATUS_RPC_SECURITY_DESCRIPTOR_SDDL,
            "D:P(A;;GA;;;AU)(A;;GA;;;SY)S:(ML;;NW;;;ME)"
        );
        let descriptor = OwnedSecurityDescriptor::new(RpcSecurityProfile::StatusOnly)?;
        assert!(descriptor.interface.is_none());
        assert_eq!(
            format!("{descriptor:?}"),
            "OwnedSecurityDescriptor([REDACTED])"
        );
        Ok(())
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    #[test]
    fn lpac_probe_security_profile_is_debug_only() {
        assert_eq!(lpac_probe_security_profile(), RpcSecurityProfile::LpacProbe);
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    #[test]
    fn lpac_probe_sddl_binds_exact_connect_and_interface_aces() -> Result<(), StatusRpcWorkerError>
    {
        const APPROVAL_SID: &str = "S-1-15-2-1-2-3-4-5-6-7";
        const SECRET_INPUT_SID: &str = "S-1-15-2-8-9-10-11-12-13-14";
        let expected_sids = [APPROVAL_SID, SECRET_INPUT_SID];
        let policy = LpacRpcSecuritySddl {
            endpoint: lpac_rpc_sddl(RPC_ENDPOINT_CONNECT_ACCESS, expected_sids),
            interface: lpac_rpc_sddl(RPC_INTERFACE_CALL_ACCESS, expected_sids),
        };

        assert!(policy.is_exact_for(expected_sids));
        assert!(
            policy.endpoint
                == "D:P(A;;0x1;;;AU)(A;;0x1;;;SY)(A;;0x1;;;S-1-15-2-1-2-3-4-5-6-7)(A;;0x1;;;S-1-15-2-8-9-10-11-12-13-14)S:(ML;;NW;;;LW)"
        );
        assert!(
            policy.interface
                == "D:P(A;;GA;;;AU)(A;;GA;;;SY)(A;;GA;;;S-1-15-2-1-2-3-4-5-6-7)(A;;GA;;;S-1-15-2-8-9-10-11-12-13-14)S:(ML;;NW;;;LW)"
        );
        assert_eq!(format!("{policy:?}"), "LpacRpcSecuritySddl([REDACTED])");
        let endpoint = OwnedLocalSecurityDescriptor::from_sddl(&policy.endpoint)?;
        let interface = OwnedLocalSecurityDescriptor::from_sddl(&policy.interface)?;
        assert!(!endpoint.as_raw().is_null());
        assert!(!interface.as_raw().is_null());
        Ok(())
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    #[test]
    fn lpac_probe_descriptor_reaches_os_derivation_and_owns_distinct_descriptors()
    -> Result<(), &'static str> {
        let profile_sids = derive_fixed_lpac_rpc_endpoint_profile_sids()
            .map_err(|_| "derive fixed profile identities")?;
        let policy = LpacRpcSecuritySddl::new(&profile_sids).map_err(|_| "compose exact policy")?;
        let endpoint = OwnedLocalSecurityDescriptor::from_sddl(&policy.endpoint)
            .map_err(|_| "parse endpoint descriptor")?;
        let interface = OwnedLocalSecurityDescriptor::from_sddl(&policy.interface)
            .map_err(|_| "parse interface descriptor")?;
        assert!(endpoint.as_raw() != interface.as_raw());

        let descriptor = OwnedSecurityDescriptor::new(RpcSecurityProfile::LpacProbe)
            .map_err(|_| "construct retained descriptors")?;
        assert!(descriptor.interface.is_some());
        assert!(descriptor.endpoint_raw() != descriptor.interface_raw());
        assert_eq!(
            format!("{descriptor:?}"),
            "OwnedSecurityDescriptor([REDACTED])"
        );
        Ok(())
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    #[test]
    fn lpac_probe_sddl_rejects_wrong_missing_duplicate_and_relaxed_policy() {
        const APPROVAL_SID: &str = "S-1-15-2-1-2-3-4-5-6-7";
        const SECRET_INPUT_SID: &str = "S-1-15-2-8-9-10-11-12-13-14";
        const WRONG_SID: &str = "S-1-15-2-15-16-17-18-19-20-21";
        let expected_sids = [APPROVAL_SID, SECRET_INPUT_SID];
        let endpoint = lpac_rpc_sddl(RPC_ENDPOINT_CONNECT_ACCESS, expected_sids);
        let interface = lpac_rpc_sddl(RPC_INTERFACE_CALL_ACCESS, expected_sids);

        let candidates = [
            LpacRpcSecuritySddl {
                endpoint: endpoint.replace(SECRET_INPUT_SID, WRONG_SID),
                interface: interface.clone(),
            },
            LpacRpcSecuritySddl {
                endpoint: endpoint.replace(&format!("(A;;0x1;;;{SECRET_INPUT_SID})"), ""),
                interface: interface.clone(),
            },
            LpacRpcSecuritySddl {
                endpoint: endpoint.clone(),
                interface: interface.replace(SECRET_INPUT_SID, APPROVAL_SID),
            },
            LpacRpcSecuritySddl {
                endpoint: endpoint.replacen("D:P", "D:", 1),
                interface: interface.clone(),
            },
            LpacRpcSecuritySddl {
                endpoint: endpoint.replacen("0x1", "GA", 1),
                interface: interface.clone(),
            },
            LpacRpcSecuritySddl {
                endpoint: endpoint.replace("S:(ML;;NW;;;LW)", "S:(ML;;NW;;;ME)"),
                interface: interface.clone(),
            },
            LpacRpcSecuritySddl {
                endpoint: endpoint.replace("S:(ML;;NW;;;LW)", "S:(ML;;;;;LW)"),
                interface,
            },
        ];

        for candidate in candidates {
            assert!(!candidate.is_exact_for(expected_sids));
        }
        let exact = LpacRpcSecuritySddl {
            endpoint: lpac_rpc_sddl(RPC_ENDPOINT_CONNECT_ACCESS, expected_sids),
            interface: lpac_rpc_sddl(RPC_INTERFACE_CALL_ACCESS, expected_sids),
        };
        assert!(!exact.is_exact_for([APPROVAL_SID, APPROVAL_SID]));
    }

    #[test]
    fn errors_and_context_debug_are_data_free() -> Result<(), StatusRpcWorkerError> {
        let context = ServerContext::new()?;
        assert_eq!(format!("{context:?}"), "ServerContext([REDACTED])");
        assert_eq!(
            format!("{:?}", StatusRpcWorkerError::Unavailable),
            "Unavailable"
        );
        assert_eq!(
            RpcAuthError::AccessDenied.manager_error(),
            ManagerError::AccessDenied
        );
        Ok(())
    }

    #[test]
    fn callback_authentication_has_an_application_level_concurrency_cap()
    -> Result<(), StatusRpcWorkerError> {
        let context = ServerContext::new()?;
        context.admission.store(true, Ordering::Release);
        let permits: Vec<_> = (0..lifecycle::STATUS_RPC_MAX_CALLS)
            .map(|_| context.try_callback_auth_permit())
            .collect();
        assert!(permits.iter().all(Option::is_some));
        assert!(context.try_callback_auth_permit().is_none());
        drop(permits);
        assert!(context.try_callback_auth_permit().is_some());
        Ok(())
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    #[test]
    fn invalidation_defers_expected_helper_stop_until_post_rpc_cleanup()
    -> Result<(), StatusRpcWorkerError> {
        let context = ServerContext::new()?;
        context.invalidate_epochs();

        context.stop_probe_coordinator_and_helpers()?;
        assert_eq!(
            context.helpers.stop(),
            Err(ExpectedPeerRegistryError::Stopping)
        );
        assert!(!context.fatal.load(Ordering::Acquire));
        Ok(())
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    #[test]
    fn auth_stop_diagnostic_codes_are_closed_and_origin_separated() {
        for stage in 1..=15 {
            assert_eq!(
                AuthStopDiagnostic::new(AuthDiagnosticOrigin::Callback, stage)
                    .map(AuthStopDiagnostic::code),
                Some(0x6000 + stage)
            );
            assert_eq!(
                AuthStopDiagnostic::new(AuthDiagnosticOrigin::Manager, stage)
                    .map(AuthStopDiagnostic::code),
                Some(0x6100 + stage)
            );
        }
        for stage in [0, 16, 17, 0x6001, u32::MAX] {
            assert_eq!(
                AuthStopDiagnostic::new(AuthDiagnosticOrigin::Callback, stage),
                None
            );
            assert_eq!(
                AuthStopDiagnostic::new(AuthDiagnosticOrigin::Manager, stage),
                None
            );
        }
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    #[test]
    fn auth_stop_diagnostic_is_first_wins_and_preserves_legacy_fatal_rejection()
    -> Result<(), StatusRpcWorkerError> {
        for (first, second, expected) in [
            (
                AuthDiagnosticOrigin::Callback,
                AuthDiagnosticOrigin::Manager,
                0x6001,
            ),
            (
                AuthDiagnosticOrigin::Manager,
                AuthDiagnosticOrigin::Callback,
                0x6101,
            ),
        ] {
            let context = ServerContext::new()?;
            context.admission.store(true, Ordering::Release);
            assert!(context.auth_diagnostic().is_none());
            assert!(matches!(
                context.diagnostic_after_clean_drain(),
                Ok(DiagnosticDrainOutcome::Complete)
            ));
            context.latch_auth_diagnostic(first, 1);
            context.latch_auth_diagnostic(second, 15);
            assert_eq!(
                context.auth_diagnostic().map(AuthStopDiagnostic::code),
                Some(expected)
            );
            assert!(context.fatal.load(Ordering::Acquire));
            assert!(!context.other_fatal.load(Ordering::Acquire));
            assert!(!context.admission.load(Ordering::Acquire));
            assert!(context.try_callback_auth_permit().is_none());
            assert_eq!(
                context.legacy_after_clean_drain(),
                Err(StatusRpcWorkerError::Unavailable)
            );
            assert!(
                matches!(context.diagnostic_after_clean_drain(), Ok(DiagnosticDrainOutcome::AuthFailure(diagnostic)) if diagnostic.code() == expected)
            );
        }
        Ok(())
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    #[test]
    fn auth_stop_diagnostic_never_excuses_another_calls_internal_failure()
    -> Result<(), StatusRpcWorkerError> {
        for (auth_error, manager_error) in [
            (DispatchError::Authentication, ManagerError::AccessDenied),
            (DispatchError::Internal, ManagerError::CallFailed),
        ] {
            let context = ServerContext::new()?;
            context.latch_auth_diagnostic(AuthDiagnosticOrigin::Manager, 5);
            assert_eq!(
                context.map_lpac_auth_dispatch_result::<()>(Err(auth_error), true),
                Err(manager_error)
            );
            assert!(!context.other_fatal.load(Ordering::Acquire));
            assert!(matches!(
                context.diagnostic_after_clean_drain(),
                Ok(DiagnosticDrainOutcome::AuthFailure(_))
            ));
            assert_eq!(
                context.map_lpac_dispatch_result::<()>(Err(DispatchError::Internal)),
                Err(ManagerError::CallFailed)
            );
            assert!(context.other_fatal.load(Ordering::Acquire));
            assert!(matches!(
                context.diagnostic_after_clean_drain(),
                Err(StatusRpcWorkerError::Unavailable)
            ));
        }
        Ok(())
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    #[test]
    fn concurrent_other_fatal_always_suppresses_auth_stop_diagnostic()
    -> Result<(), StatusRpcWorkerError> {
        for _ in 0..16 {
            let context = ServerContext::new()?;
            std::thread::scope(|scope| {
                scope.spawn(|| context.latch_auth_diagnostic(AuthDiagnosticOrigin::Callback, 5));
                scope.spawn(|| context.latch_auth_diagnostic(AuthDiagnosticOrigin::Manager, 9));
                scope.spawn(|| context.latch_fatal_runtime());
            });
            assert!(matches!(
                context.auth_diagnostic().map(AuthStopDiagnostic::code),
                Some(0x6005 | 0x6109)
            ));
            assert!(context.fatal.load(Ordering::Acquire));
            assert!(context.other_fatal.load(Ordering::Acquire));
            assert!(matches!(
                context.diagnostic_after_clean_drain(),
                Err(StatusRpcWorkerError::Unavailable)
            ));
        }
        Ok(())
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    #[test]
    fn an_earlier_other_fatal_is_never_downgraded_by_auth_diagnostic()
    -> Result<(), StatusRpcWorkerError> {
        let context = ServerContext::new()?;
        context.latch_fatal_runtime();
        context.latch_auth_diagnostic(AuthDiagnosticOrigin::Callback, 5);
        assert_eq!(
            context.auth_diagnostic().map(AuthStopDiagnostic::code),
            Some(0x6005)
        );
        assert!(context.other_fatal.load(Ordering::Acquire));
        assert_eq!(
            context.legacy_after_clean_drain(),
            Err(StatusRpcWorkerError::Unavailable)
        );
        assert!(matches!(
            context.diagnostic_after_clean_drain(),
            Err(StatusRpcWorkerError::Unavailable)
        ));
        Ok(())
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    #[test]
    fn unknown_auth_stage_and_unclassified_fatal_never_become_diagnostics()
    -> Result<(), StatusRpcWorkerError> {
        for stage in [0, 16, u32::MAX] {
            let context = ServerContext::new()?;
            context.latch_auth_diagnostic(AuthDiagnosticOrigin::Callback, stage);
            assert!(context.auth_diagnostic().is_none());
            assert!(context.other_fatal.load(Ordering::Acquire));
            assert!(matches!(
                context.diagnostic_after_clean_drain(),
                Err(StatusRpcWorkerError::Unavailable)
            ));
        }
        let context = ServerContext::new()?;
        context.fatal.store(true, Ordering::Release);
        assert!(context.auth_diagnostic().is_none());
        assert!(matches!(
            context.diagnostic_after_clean_drain(),
            Err(StatusRpcWorkerError::Unavailable)
        ));
        Ok(())
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    #[test]
    fn every_failed_resource_drain_suppresses_auth_diagnostic_output()
    -> Result<(), StatusRpcWorkerError> {
        for failure in [
            StatusRpcWorkerError::Unavailable,
            StatusRpcWorkerError::RuntimeStateRetained,
        ] {
            assert!(
                matches!(diagnostic_from_drain_result(Err(failure)), Err(actual) if actual == failure)
            );
        }
        let context = Arc::new(ServerContext::new()?);
        context.latch_auth_diagnostic(AuthDiagnosticOrigin::Callback, 5);
        assert!(
            matches!(diagnostic_from_drain_result(Ok(context)), Ok(DiagnosticDrainOutcome::AuthFailure(diagnostic)) if diagnostic.code() == 0x6005)
        );
        Ok(())
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    #[test]
    fn coordinator_cleanup_failure_dominates_an_auth_diagnostic() -> Result<(), StatusRpcWorkerError>
    {
        let context = ServerContext::new()?;
        context.latch_auth_diagnostic(AuthDiagnosticOrigin::Callback, 5);
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let Ok(_owner) = context.probe_coordinator_owner.lock() else {
                return;
            };
            std::panic::resume_unwind(Box::new(()));
        }));
        assert!(poisoned.is_err());
        assert_eq!(
            context.stop_probe_coordinator_and_helpers(),
            Err(StatusRpcWorkerError::Unavailable)
        );
        assert!(context.other_fatal.load(Ordering::Acquire));
        assert!(matches!(
            context.diagnostic_after_clean_drain(),
            Err(StatusRpcWorkerError::Unavailable)
        ));
        assert_eq!(
            context.helpers.stop(),
            Err(ExpectedPeerRegistryError::Stopping)
        );
        Ok(())
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    #[test]
    fn only_internal_dispatch_failure_latches_fatal_and_closes_admission()
    -> Result<(), StatusRpcWorkerError> {
        let context = ServerContext::new()?;
        context.admission.store(true, Ordering::Release);

        for error in [
            DispatchError::Malformed,
            DispatchError::Authentication,
            DispatchError::Epoch,
            DispatchError::Full,
            DispatchError::Stopping,
        ] {
            assert!(context.map_lpac_dispatch_result::<()>(Err(error)).is_err());
            assert!(!context.fatal.load(Ordering::Acquire));
            assert!(context.admission.load(Ordering::Acquire));
        }

        assert_eq!(
            context.map_lpac_dispatch_result::<()>(Err(DispatchError::Internal)),
            Err(ManagerError::CallFailed)
        );
        assert!(context.fatal.load(Ordering::Acquire));
        assert!(!context.admission.load(Ordering::Acquire));
        Ok(())
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    #[test]
    fn fatal_health_latch_preserves_an_already_completed_response()
    -> Result<(), StatusRpcWorkerError> {
        let context = ServerContext::new()?;
        context.latch_fatal_runtime();

        assert_eq!(context.map_lpac_dispatch_result::<u32>(Ok(7)), Ok(7));
        assert!(context.fatal.load(Ordering::Acquire));
        assert!(!context.admission.load(Ordering::Acquire));
        Ok(())
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    #[test]
    fn coordinator_owner_invariant_failure_is_fatal_but_still_stops_helpers()
    -> Result<(), StatusRpcWorkerError> {
        let context = ServerContext::new()?;
        context.admission.store(true, Ordering::Release);
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let Ok(_owner) = context.probe_coordinator_owner.lock() else {
                return;
            };
            std::panic::resume_unwind(Box::new(()));
        }));
        assert!(poisoned.is_err());

        assert_eq!(
            context.stop_probe_coordinator_and_helpers(),
            Err(StatusRpcWorkerError::Unavailable)
        );
        assert!(context.fatal.load(Ordering::Acquire));
        assert!(!context.admission.load(Ordering::Acquire));
        assert_eq!(
            context.helpers.stop(),
            Err(ExpectedPeerRegistryError::Stopping)
        );
        Ok(())
    }

    #[test]
    fn runtime_error_never_exposes_status_details() {
        assert_eq!(
            format!("{RpcRuntimeError:?}"),
            "RpcRuntimeError([REDACTED])"
        );
        assert_eq!(rpc_result(RPC_STATUS(5)), Err(RpcRuntimeError));
    }

    #[test]
    #[ignore = "requires an interactive medium-integrity Windows desktop token and a free fixed endpoint"]
    fn live_authenticated_local_rpc_status_round_trip() -> Result<(), &'static str> {
        let mut worker = StatusRpcWorker::start().map_err(|_| "start worker")?;
        worker.begin_accepting().map_err(|_| "open admission")?;

        let exchange_result = (|| {
            let binding = OwnedTestBinding::connect()?;
            let open = ServiceRequest::OpenEpoch(OpenEpochRequest::new());
            let nonce = match binding.call(&open)? {
                ServiceResponse::OpenEpoch(ack) => ack.epoch_nonce(),
                ServiceResponse::Status(_) => return Err("unexpected open response"),
            };

            let request_id =
                ServiceRequestId::new([0xA5; 16]).map_err(|_| "construct request id")?;
            let status = ServiceRequest::Command(ServiceCommandRequest::new(
                nonce,
                request_id,
                ServiceCommand::Status,
            ));
            match binding.call(&status)? {
                ServiceResponse::Status(response)
                    if response.status() == ServiceStatus::Unavailable
                        && response.epoch_nonce() == nonce
                        && response.request_id() == request_id =>
                {
                    Ok(())
                }
                ServiceResponse::OpenEpoch(_) | ServiceResponse::Status(_) => {
                    Err("unexpected status response")
                }
            }
        })();

        let stop_result = worker.close_admission().drain().map_err(|_| "drain worker");
        exchange_result?;
        stop_result
    }
}
