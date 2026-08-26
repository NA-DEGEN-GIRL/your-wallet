//! Debug-only authenticated local-RPC Status/Unavailable service.
//!
//! This fixture proves a bounded transport and fresh per-call Windows desktop
//! identity. It deliberately does not prove an enrolled Broker image, helper
//! role, service mutual identity, or any wallet/signing authority.

#![allow(unsafe_code)]

mod auth;
mod dispatch;
mod epoch;
mod lifecycle;

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
use windows::core::{PCWSTR, w};

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
    DetachedDesktopProcess, PendingDebuggerExitProcessCleanup, PendingDebuggerExitProcessSuccess,
    PreparedDebuggerExitProcessSuccess,
};
use self::dispatch::{AuthenticationFailure, DispatchEngine};
use self::epoch::SystemMonotonicClock;
use self::lifecycle::{LifecycleHooks, ListeningStatusRpcServer, PreparedStatusRpcServer, RpcOps};

const RPC_S_OK: i32 = 0;
const RPC_S_ACCESS_DENIED: i32 = 5;
static LOCAL_RPC_PROTOCOL_SEQUENCE_WIDE: [u16; 8] = [110, 99, 97, 108, 114, 112, 99, 0];
const STATUS_RPC_SECURITY_DESCRIPTOR: PCWSTR = w!("D:P(A;;GA;;;AU)(A;;GA;;;SY)S:(ML;;NW;;;ME)");

const _: () = assert!(
    lifecycle::STATUS_RPC_MAX_RPC_SIZE as usize == key_agent_service_rpc_sys::RPC_FRAME_SIZE
);

/// Data-free failure of the debug-only status worker.
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
    dispatch: Mutex<DispatchEngine<AuthenticatedRpcClient, SystemMonotonicClock>>,
}

impl ServerContext {
    fn new() -> Result<Self, StatusRpcWorkerError> {
        let dispatch = DispatchEngine::new().map_err(|_| StatusRpcWorkerError::Unavailable)?;
        Ok(Self {
            admission: AtomicBool::new(false),
            fatal: AtomicBool::new(false),
            callback_auth_inflight: AtomicUsize::new(0),
            dispatch: Mutex::new(dispatch),
        })
    }

    fn try_callback_auth_permit(&self) -> Option<CallbackAuthPermit<'_>> {
        if self.fatal.load(Ordering::Acquire) || !self.admission.load(Ordering::Acquire) {
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
        if !self.admission.load(Ordering::Acquire) {
            return Err(ManagerError::ServerUnavailable);
        }

        let dispatch = self.dispatch.lock().map_err(|_| ManagerError::CallFailed)?;
        if self.fatal.load(Ordering::Acquire) {
            return Err(ManagerError::CallFailed);
        }
        if !self.admission.load(Ordering::Acquire) {
            return Err(ManagerError::ServerUnavailable);
        }

        dispatch
            .exchange_with(request, move || {
                auth::authenticate_call(binding).map_err(AuthenticationFailure::from)
            })
            .map_err(ManagerError::from)
    }

    fn invalidate_epochs(&self) {
        let result = self
            .dispatch
            .lock()
            .map_err(|_| ())
            .and_then(|dispatch| dispatch.stop().map_err(|_| ()));
        if result.is_err() {
            self.fatal.store(true, Ordering::Release);
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

/// SCM-owned worker for one process-lifetime status RPC fixture.
pub(super) struct StatusRpcWorker {
    server: LiveStatusServer,
    context: Arc<ServerContext>,
}

impl StatusRpcWorker {
    pub(super) fn start() -> Result<Self, StatusRpcWorkerError> {
        let context = Arc::new(ServerContext::new()?);
        let security_descriptor = OwnedSecurityDescriptor::new()?;
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
            Ok(server) => Ok(Self { server, context }),
            Err(failure) => {
                let _ = (failure.stage(), failure.error());
                if let Some(cleanup) = failure.cleanup_failure() {
                    let _ = (cleanup.stage(), cleanup.error(), cleanup.secondary());
                }
                if failure.resources_are_retained() {
                    return Err(StatusRpcWorkerError::RuntimeStateRetained);
                }
                clear_context(&context)?;
                Err(StatusRpcWorkerError::Unavailable)
            }
        }
    }

    pub(super) fn begin_accepting(&mut self) -> Result<(), StatusRpcWorkerError> {
        if self.context.fatal.load(Ordering::Acquire) {
            return Err(StatusRpcWorkerError::Unavailable);
        }
        self.server.enable_admission_after_scm_running();
        if !self.server.is_admitting() || !self.context.admission.load(Ordering::Acquire) {
            return Err(StatusRpcWorkerError::Unavailable);
        }
        Ok(())
    }

    pub(super) fn stop_and_drain(self) -> Result<(), StatusRpcWorkerError> {
        let Self { server, context } = self;
        if let Err(failure) = server.stop_and_drain() {
            let report = failure.report();
            let _ = (report.stage(), report.error(), report.secondary());
            debug_assert!(failure.resources_are_retained());
            return Err(StatusRpcWorkerError::RuntimeStateRetained);
        }
        clear_context(&context)?;
        if context.fatal.load(Ordering::Acquire) {
            return Err(StatusRpcWorkerError::Unavailable);
        }
        Ok(())
    }
}

impl fmt::Debug for StatusRpcWorker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StatusRpcWorker([REDACTED])")
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
    // SAFETY: Rpcrt4 supplies the synchronous call binding as callback context;
    // the authentication helper neither retains nor frees it.
    match unsafe { auth::authenticate_callback_context(call_context) } {
        Ok(_) => RPC_STATUS(RPC_S_OK),
        // The RPC runtime exposes every non-OK If3 callback result to the
        // client as access denied, so both closed auth categories intentionally
        // collapse here. The manager still authenticates independently.
        Err(_) => RPC_STATUS(RPC_S_ACCESS_DENIED),
    }
}

struct OwnedSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl OwnedSecurityDescriptor {
    fn new() -> Result<Self, StatusRpcWorkerError> {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: the fixed SDDL is NUL-terminated; the API allocates one
        // self-relative descriptor which this owner releases with LocalFree.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                STATUS_RPC_SECURITY_DESCRIPTOR,
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

impl fmt::Debug for OwnedSecurityDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OwnedSecurityDescriptor([REDACTED])")
    }
}

impl Drop for OwnedSecurityDescriptor {
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
                Some(security_descriptor.as_raw()),
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
                Some(security_descriptor.as_raw()),
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

        let stop_result = worker.stop_and_drain().map_err(|_| "drain worker");
        exchange_result?;
        stop_result
    }
}
