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
    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
    debug_assertions
))]
mod coordinator;
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

use core::{ffi::c_void, fmt};
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

struct ServerContext {
    admission: AtomicBool,
    fatal: AtomicBool,
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
            let routed = self.map_lpac_dispatch_result(router::route_manager(
                &self.dispatch,
                &self.helpers,
                request,
                move || {
                    let peer = auth::authenticate_role_aware_call(binding)
                        .map_err(AuthenticationFailure::from)?;
                    Ok(match peer {
                        auth::AuthenticatedManagerPeer::Desktop(desktop) => {
                            RoleAwareManagerPeer::Desktop(desktop)
                        }
                        auth::AuthenticatedManagerPeer::ServiceCreatedLpac(helper) => {
                            RoleAwareManagerPeer::Helper(helper)
                        }
                    })
                },
            ))?;

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
        result.map_err(|error| {
            if error == DispatchError::Internal {
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
        let (server, context) = start_status_rpc_server(context, RpcSecurityProfile::StatusOnly)?;
        Ok(Self { server, context })
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    pub(super) fn start_lpac_rpc_probe(
        service_token: ServiceTokenFixtureProof,
    ) -> Result<Self, StatusRpcWorkerError> {
        let helpers = ServiceHelperAdmission::new();
        let probe_coordinator = ServiceProbeCoordinator::start(service_token, helpers.clone())
            .map_err(|_| StatusRpcWorkerError::Unavailable)?;
        let context = Arc::new(ServerContext::new_with_probe_coordinator(
            helpers,
            probe_coordinator,
        )?);
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
}

impl AdmissionClosedStatusRpcWorker {
    pub(super) fn drain(self) -> Result<(), StatusRpcWorkerError> {
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
        if context.fatal.load(Ordering::Acquire) {
            return Err(StatusRpcWorkerError::Unavailable);
        }
        Ok(())
    }
}

fn start_status_rpc_server(
    context: Arc<ServerContext>,
    security_profile: RpcSecurityProfile,
) -> Result<(LiveStatusServer, Arc<ServerContext>), StatusRpcWorkerError> {
    let security_descriptor = OwnedSecurityDescriptor::new(security_profile)?;
    let interface_spec = server_interface_spec().ok_or(StatusRpcWorkerError::Unavailable)?;
    publish_context(Arc::clone(&context))?;

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
                return Err(StatusRpcWorkerError::RuntimeStateRetained);
            }
            #[cfg(all(
                feature = "key-agent-service-lpac-launch-feasibility-test-hook",
                debug_assertions
            ))]
            if context.stop_probe_coordinator_and_helpers().is_err() {
                // The published context and uncertain terminal owners must stay
                // retained, and SCM must not classify this as a clean boundary
                // failure that permits SERVICE_STOPPED.
                return Err(StatusRpcWorkerError::RuntimeStateRetained);
            }
            if clear_context(&context).is_err() {
                return Err(StatusRpcWorkerError::RuntimeStateRetained);
            }
            Err(StatusRpcWorkerError::Unavailable)
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
    let authorization = router::authorize_callback(&context.helpers, || {
        // SAFETY: Rpcrt4 supplies the synchronous call binding as callback
        // context; the authentication helper neither retains nor frees it.
        let peer = unsafe { auth::authenticate_role_aware_callback_context(call_context) }
            .map_err(AuthenticationFailure::from)?;
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
    if matches!(authorization, Err(DispatchError::Internal)) {
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
