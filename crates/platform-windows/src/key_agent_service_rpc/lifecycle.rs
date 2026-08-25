//! Fail-closed lifecycle for the debug-only Key Agent status RPC server.
//!
//! This module owns ordering and lifetime only. Authentication decisions,
//! epoch contents, request dispatch, and the concrete Windows calls remain in
//! sibling modules. Once an interface may be reachable, an abandoned or
//! failed lifecycle intentionally retains its RPC context and endpoint
//! security descriptor until process exit.

#![deny(unsafe_code)]

use core::{fmt, mem::ManuallyDrop};

pub(crate) const LOCAL_RPC_PROTOCOL_SEQUENCE: &str = "ncalrpc";
pub(crate) const STATUS_RPC_ENDPOINT: &str = "YourWallet.KeyAgentService.v1";
pub(crate) const RPC_C_AUTHN_WINNT: u32 = 10;
pub(crate) const RPC_IF_ALLOW_SECURE_ONLY: u32 = 0x0000_0008;
pub(crate) const RPC_IF_ALLOW_LOCAL_ONLY: u32 = 0x0000_0020;
pub(crate) const RPC_IF_SEC_NO_CACHE: u32 = 0x0000_0040;
pub(crate) const STATUS_RPC_INTERFACE_FLAGS: u32 =
    RPC_IF_ALLOW_LOCAL_ONLY | RPC_IF_ALLOW_SECURE_ONLY | RPC_IF_SEC_NO_CACHE;
pub(crate) const STATUS_RPC_MIN_CALL_THREADS: u32 = 1;
/// Runtime registration/listen hint. The server context separately enforces
/// this number as an application-level cap on concurrent callback auth work.
pub(crate) const STATUS_RPC_MAX_CALLS: u32 = 8;
/// Registration hint for transports that honor it. The generated fixed MIDL
/// frame and canonical Rust decoder are the actual local-RPC size boundary.
pub(crate) const STATUS_RPC_MAX_RPC_SIZE: u32 = 76;
pub(crate) const RPC_LISTEN_DONT_WAIT: u32 = 1;

const RPC_IF_AUTOLISTEN: u32 = 0x0000_0001;
const RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH: u32 = 0x0000_0010;

const _: () = assert!(STATUS_RPC_INTERFACE_FLAGS == 0x0000_0068);
const _: () = assert!(STATUS_RPC_MAX_RPC_SIZE == 76);
const _: () = assert!(STATUS_RPC_INTERFACE_FLAGS & RPC_IF_AUTOLISTEN == 0);
const _: () = assert!(STATUS_RPC_INTERFACE_FLAGS & RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH == 0);

/// Narrow operating-system surface required by the status RPC lifecycle.
///
/// The real adapter must map each method one-for-one to the named classic RPC
/// operation. In particular, `stop_server_listening` always targets the whole
/// server (`NULL`) and `unregister_interface_waiting` must pass the exact
/// interface specification with `WaitForCallsToComplete = TRUE`.
pub(crate) trait RpcOps {
    type Error;
    type InterfaceSpec: Copy;
    type EndpointSecurityDescriptor;

    fn register_auth_info_without_principal(
        &mut self,
        authentication_service: u32,
    ) -> Result<(), Self::Error>;

    fn use_protocol_sequence_endpoint(
        &mut self,
        protocol_sequence: &'static str,
        max_calls: u32,
        endpoint: &'static str,
        security_descriptor: &Self::EndpointSecurityDescriptor,
    ) -> Result<(), Self::Error>;

    fn install_process_lifetime_handler(&mut self) -> Result<(), Self::Error>;

    fn register_interface3(
        &mut self,
        interface_spec: Self::InterfaceSpec,
        flags: u32,
        max_calls: u32,
        max_rpc_size: u32,
        security_descriptor: &Self::EndpointSecurityDescriptor,
    ) -> Result<(), Self::Error>;

    fn listen(
        &mut self,
        minimum_call_threads: u32,
        max_calls: u32,
        dont_wait: u32,
    ) -> Result<(), Self::Error>;

    fn stop_server_listening(&mut self) -> Result<(), Self::Error>;

    fn unregister_interface_waiting(
        &mut self,
        interface_spec: Self::InterfaceSpec,
        wait_for_calls_to_complete: bool,
    ) -> Result<(), Self::Error>;

    fn wait_server_listen(&mut self) -> Result<(), Self::Error>;
}

/// Infallible, authority-free lifecycle callbacks owned by the RPC context.
pub(crate) trait LifecycleHooks {
    fn set_admission(&mut self, accepting: bool);
    fn invalidate_epochs(&mut self);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StartStage {
    RegisterAuthentication,
    BindEndpoint,
    InstallHandler,
    RegisterInterface,
    Listen,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DrainStage {
    StopListening,
    UnregisterInterface,
    WaitForListen,
}

struct RpcResources<O, H>
where
    O: RpcOps,
    H: LifecycleHooks,
{
    ops: O,
    interface_spec: O::InterfaceSpec,
    endpoint_security_descriptor: O::EndpointSecurityDescriptor,
    hooks: H,
}

impl<O, H> fmt::Debug for RpcResources<O, H>
where
    O: RpcOps,
    H: LifecycleHooks,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RpcResources(..)")
    }
}

/// Resources whose safe rundown could not be proven.
///
/// Dropping this owner deliberately does not run destructors for the RPC
/// context, endpoint security descriptor, or OS adapter. The service host must
/// treat the containing failure as terminal and exit the process.
struct RetainedRpcResources<O, H>
where
    O: RpcOps,
    H: LifecycleHooks,
{
    resources: ManuallyDrop<RpcResources<O, H>>,
}

impl<O, H> RetainedRpcResources<O, H>
where
    O: RpcOps,
    H: LifecycleHooks,
{
    fn new(resources: RpcResources<O, H>) -> Self {
        Self {
            resources: ManuallyDrop::new(resources),
        }
    }
}

impl<O, H> fmt::Debug for RetainedRpcResources<O, H>
where
    O: RpcOps,
    H: LifecycleHooks,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("RetainedRpcResources")
            .field(&self.resources)
            .finish()
    }
}

pub(crate) struct DrainFailureReport<E> {
    stage: DrainStage,
    error: E,
    secondary: Option<(DrainStage, E)>,
}

impl<E> DrainFailureReport<E> {
    #[must_use]
    pub(crate) const fn stage(&self) -> DrainStage {
        self.stage
    }

    #[must_use]
    pub(crate) const fn error(&self) -> &E {
        &self.error
    }

    #[must_use]
    pub(crate) fn secondary(&self) -> Option<(DrainStage, &E)> {
        self.secondary
            .as_ref()
            .map(|(stage, error)| (*stage, error))
    }
}

impl<E> fmt::Debug for DrainFailureReport<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DrainFailureReport")
            .field("stage", &self.stage)
            .field("has_secondary", &self.secondary.is_some())
            .finish_non_exhaustive()
    }
}

/// Startup failure, optionally carrying resources retained after an uncertain
/// rollback of a failed listen transition.
#[must_use]
pub(crate) struct StartFailure<O, H>
where
    O: RpcOps,
    H: LifecycleHooks,
{
    stage: StartStage,
    error: O::Error,
    cleanup_failure: Option<DrainFailureReport<O::Error>>,
    retained_resources: Option<RetainedRpcResources<O, H>>,
}

impl<O, H> StartFailure<O, H>
where
    O: RpcOps,
    H: LifecycleHooks,
{
    fn released(stage: StartStage, error: O::Error, resources: RpcResources<O, H>) -> Self {
        release_resources(resources);
        Self {
            stage,
            error,
            cleanup_failure: None,
            retained_resources: None,
        }
    }

    fn after_uncertain_cleanup(
        stage: StartStage,
        error: O::Error,
        cleanup_failure: DrainFailureReport<O::Error>,
        retained_resources: RetainedRpcResources<O, H>,
    ) -> Self {
        Self {
            stage,
            error,
            cleanup_failure: Some(cleanup_failure),
            retained_resources: Some(retained_resources),
        }
    }

    #[must_use]
    pub(crate) const fn stage(&self) -> StartStage {
        self.stage
    }

    #[must_use]
    pub(crate) const fn error(&self) -> &O::Error {
        &self.error
    }

    #[must_use]
    pub(crate) const fn cleanup_failure(&self) -> Option<&DrainFailureReport<O::Error>> {
        self.cleanup_failure.as_ref()
    }

    #[must_use]
    pub(crate) const fn resources_are_retained(&self) -> bool {
        self.retained_resources.is_some()
    }
}

impl<O, H> fmt::Debug for StartFailure<O, H>
where
    O: RpcOps,
    H: LifecycleHooks,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StartFailure")
            .field("stage", &self.stage)
            .field("has_cleanup_failure", &self.cleanup_failure.is_some())
            .field("resources_retained", &self.retained_resources.is_some())
            .finish_non_exhaustive()
    }
}

/// Stop failure that keeps all potentially referenced resources alive.
#[must_use]
pub(crate) struct StopFailure<O, H>
where
    O: RpcOps,
    H: LifecycleHooks,
{
    report: DrainFailureReport<O::Error>,
    retained_resources: RetainedRpcResources<O, H>,
}

impl<O, H> StopFailure<O, H>
where
    O: RpcOps,
    H: LifecycleHooks,
{
    #[must_use]
    pub(crate) const fn report(&self) -> &DrainFailureReport<O::Error> {
        &self.report
    }

    #[must_use]
    pub(crate) const fn resources_are_retained(&self) -> bool {
        let _ = &self.retained_resources;
        true
    }
}

impl<O, H> fmt::Debug for StopFailure<O, H>
where
    O: RpcOps,
    H: LifecycleHooks,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StopFailure")
            .field("report", &self.report)
            .field("resources_retained", &true)
            .finish_non_exhaustive()
    }
}

/// Prepared status server. Construction closes admission before any RPC API is
/// allowed to run.
#[must_use]
pub(crate) struct PreparedStatusRpcServer<O, H>
where
    O: RpcOps,
    H: LifecycleHooks,
{
    resources: RpcResources<O, H>,
}

impl<O, H> PreparedStatusRpcServer<O, H>
where
    O: RpcOps,
    H: LifecycleHooks,
{
    pub(crate) fn new(
        ops: O,
        interface_spec: O::InterfaceSpec,
        endpoint_security_descriptor: O::EndpointSecurityDescriptor,
        mut hooks: H,
    ) -> Self {
        hooks.set_admission(false);
        Self {
            resources: RpcResources {
                ops,
                interface_spec,
                endpoint_security_descriptor,
                hooks,
            },
        }
    }

    pub(crate) fn start(mut self) -> Result<ListeningStatusRpcServer<O, H>, StartFailure<O, H>> {
        if let Err(error) = self
            .resources
            .ops
            .register_auth_info_without_principal(RPC_C_AUTHN_WINNT)
        {
            return Err(StartFailure::released(
                StartStage::RegisterAuthentication,
                error,
                self.resources,
            ));
        }

        if let Err(error) = self.resources.ops.use_protocol_sequence_endpoint(
            LOCAL_RPC_PROTOCOL_SEQUENCE,
            STATUS_RPC_MAX_CALLS,
            STATUS_RPC_ENDPOINT,
            &self.resources.endpoint_security_descriptor,
        ) {
            return Err(StartFailure::released(
                StartStage::BindEndpoint,
                error,
                self.resources,
            ));
        }

        if let Err(error) = self.resources.ops.install_process_lifetime_handler() {
            return Err(StartFailure::released(
                StartStage::InstallHandler,
                error,
                self.resources,
            ));
        }

        if let Err(error) = self.resources.ops.register_interface3(
            self.resources.interface_spec,
            STATUS_RPC_INTERFACE_FLAGS,
            STATUS_RPC_MAX_CALLS,
            STATUS_RPC_MAX_RPC_SIZE,
            &self.resources.endpoint_security_descriptor,
        ) {
            return Err(StartFailure::released(
                StartStage::RegisterInterface,
                error,
                self.resources,
            ));
        }

        if let Err(error) = self.resources.ops.listen(
            STATUS_RPC_MIN_CALL_THREADS,
            STATUS_RPC_MAX_CALLS,
            RPC_LISTEN_DONT_WAIT,
        ) {
            return match drain_resources(self.resources) {
                Ok(()) => Err(StartFailure {
                    stage: StartStage::Listen,
                    error,
                    cleanup_failure: None,
                    retained_resources: None,
                }),
                Err((cleanup_failure, retained_resources)) => {
                    Err(StartFailure::after_uncertain_cleanup(
                        StartStage::Listen,
                        error,
                        cleanup_failure,
                        retained_resources,
                    ))
                }
            };
        }

        Ok(ListeningStatusRpcServer {
            resources: Some(ManuallyDrop::new(self.resources)),
            admission_open: false,
        })
    }
}

impl<O, H> fmt::Debug for PreparedStatusRpcServer<O, H>
where
    O: RpcOps,
    H: LifecycleHooks,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedStatusRpcServer(..)")
    }
}

/// Listening status server whose admission gate remains closed until the SCM
/// owner has successfully published `SERVICE_RUNNING`.
#[must_use]
pub(crate) struct ListeningStatusRpcServer<O, H>
where
    O: RpcOps,
    H: LifecycleHooks,
{
    resources: Option<ManuallyDrop<RpcResources<O, H>>>,
    admission_open: bool,
}

impl<O, H> ListeningStatusRpcServer<O, H>
where
    O: RpcOps,
    H: LifecycleHooks,
{
    pub(crate) fn enable_admission_after_scm_running(&mut self) {
        if self.admission_open {
            return;
        }
        if let Some(resources) = self.resources.as_mut() {
            resources.hooks.set_admission(true);
            self.admission_open = true;
        }
    }

    #[must_use]
    pub(crate) const fn is_admitting(&self) -> bool {
        self.admission_open
    }

    pub(crate) fn stop_and_drain(mut self) -> Result<(), StopFailure<O, H>> {
        let resources = match self.resources.take() {
            Some(resources) => ManuallyDrop::into_inner(resources),
            None => std::process::abort(),
        };
        self.admission_open = false;

        match drain_resources(resources) {
            Ok(()) => Ok(()),
            Err((report, retained_resources)) => Err(StopFailure {
                report,
                retained_resources,
            }),
        }
    }
}

impl<O, H> fmt::Debug for ListeningStatusRpcServer<O, H>
where
    O: RpcOps,
    H: LifecycleHooks,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListeningStatusRpcServer")
            .field("admission_open", &self.admission_open)
            .finish_non_exhaustive()
    }
}

impl<O, H> Drop for ListeningStatusRpcServer<O, H>
where
    O: RpcOps,
    H: LifecycleHooks,
{
    fn drop(&mut self) {
        let Some(resources) = self.resources.as_mut() else {
            return;
        };
        resources.hooks.set_admission(false);
        resources.hooks.invalidate_epochs();
        self.admission_open = false;
        // The `ManuallyDrop` deliberately retains every RPC-owned resource.
    }
}

type DrainResult<O, H> = Result<
    (),
    (
        DrainFailureReport<<O as RpcOps>::Error>,
        RetainedRpcResources<O, H>,
    ),
>;

fn drain_resources<O, H>(mut resources: RpcResources<O, H>) -> DrainResult<O, H>
where
    O: RpcOps,
    H: LifecycleHooks,
{
    resources.hooks.set_admission(false);
    resources.hooks.invalidate_epochs();

    if let Err(error) = resources.ops.stop_server_listening() {
        let secondary = resources
            .ops
            .unregister_interface_waiting(resources.interface_spec, true)
            .err()
            .map(|secondary_error| (DrainStage::UnregisterInterface, secondary_error));
        let report = DrainFailureReport {
            stage: DrainStage::StopListening,
            error,
            secondary,
        };
        return Err((report, RetainedRpcResources::new(resources)));
    }

    let unregister_error = resources
        .ops
        .unregister_interface_waiting(resources.interface_spec, true)
        .err();
    let wait_error = resources.ops.wait_server_listen().err();

    if let Some(error) = unregister_error {
        let secondary =
            wait_error.map(|secondary_error| (DrainStage::WaitForListen, secondary_error));
        let report = DrainFailureReport {
            stage: DrainStage::UnregisterInterface,
            error,
            secondary,
        };
        return Err((report, RetainedRpcResources::new(resources)));
    }
    if let Some(error) = wait_error {
        let report = DrainFailureReport {
            stage: DrainStage::WaitForListen,
            error,
            secondary: None,
        };
        return Err((report, RetainedRpcResources::new(resources)));
    }

    release_resources(resources);
    Ok(())
}

fn release_resources<O, H>(resources: RpcResources<O, H>)
where
    O: RpcOps,
    H: LifecycleHooks,
{
    let RpcResources {
        ops,
        interface_spec: _,
        endpoint_security_descriptor,
        hooks,
    } = resources;
    drop(hooks);
    drop(endpoint_security_descriptor);
    drop(ops);
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use super::*;

    type EventLog = Rc<RefCell<Vec<Event>>>;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FailurePoint {
        RegisterAuthentication,
        BindEndpoint,
        InstallHandler,
        RegisterInterface,
        Listen,
        StopListening,
        UnregisterInterface,
        WaitForListen,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FakeError(FailurePoint);

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Event {
        Admission(bool),
        InvalidateEpochs,
        RegisterAuthentication(u32),
        BindEndpoint {
            protocol_sequence: &'static str,
            max_calls: u32,
            endpoint: &'static str,
            descriptor: &'static str,
        },
        InstallHandler,
        RegisterInterface {
            interface_spec: FakeInterfaceSpec,
            flags: u32,
            max_calls: u32,
            max_rpc_size: u32,
            descriptor: &'static str,
        },
        Listen {
            minimum_call_threads: u32,
            max_calls: u32,
            dont_wait: u32,
        },
        StopListeningNone,
        UnregisterInterface {
            interface_spec: FakeInterfaceSpec,
            wait_for_calls: bool,
        },
        WaitForListen,
        Drop(&'static str),
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FakeInterfaceSpec(u32);

    struct DropProbe {
        name: &'static str,
        log: EventLog,
    }

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.log.borrow_mut().push(Event::Drop(self.name));
        }
    }

    struct FakeOps {
        log: EventLog,
        failures: Vec<FailurePoint>,
    }

    impl FakeOps {
        fn result(&self, point: FailurePoint) -> Result<(), FakeError> {
            if self.failures.contains(&point) {
                Err(FakeError(point))
            } else {
                Ok(())
            }
        }
    }

    impl Drop for FakeOps {
        fn drop(&mut self) {
            self.log.borrow_mut().push(Event::Drop("ops"));
        }
    }

    impl RpcOps for FakeOps {
        type Error = FakeError;
        type InterfaceSpec = FakeInterfaceSpec;
        type EndpointSecurityDescriptor = DropProbe;

        fn register_auth_info_without_principal(
            &mut self,
            authentication_service: u32,
        ) -> Result<(), Self::Error> {
            self.log
                .borrow_mut()
                .push(Event::RegisterAuthentication(authentication_service));
            self.result(FailurePoint::RegisterAuthentication)
        }

        fn use_protocol_sequence_endpoint(
            &mut self,
            protocol_sequence: &'static str,
            max_calls: u32,
            endpoint: &'static str,
            security_descriptor: &Self::EndpointSecurityDescriptor,
        ) -> Result<(), Self::Error> {
            self.log.borrow_mut().push(Event::BindEndpoint {
                protocol_sequence,
                max_calls,
                endpoint,
                descriptor: security_descriptor.name,
            });
            self.result(FailurePoint::BindEndpoint)
        }

        fn install_process_lifetime_handler(&mut self) -> Result<(), Self::Error> {
            self.log.borrow_mut().push(Event::InstallHandler);
            self.result(FailurePoint::InstallHandler)
        }

        fn register_interface3(
            &mut self,
            interface_spec: Self::InterfaceSpec,
            flags: u32,
            max_calls: u32,
            max_rpc_size: u32,
            security_descriptor: &Self::EndpointSecurityDescriptor,
        ) -> Result<(), Self::Error> {
            self.log.borrow_mut().push(Event::RegisterInterface {
                interface_spec,
                flags,
                max_calls,
                max_rpc_size,
                descriptor: security_descriptor.name,
            });
            self.result(FailurePoint::RegisterInterface)
        }

        fn listen(
            &mut self,
            minimum_call_threads: u32,
            max_calls: u32,
            dont_wait: u32,
        ) -> Result<(), Self::Error> {
            self.log.borrow_mut().push(Event::Listen {
                minimum_call_threads,
                max_calls,
                dont_wait,
            });
            self.result(FailurePoint::Listen)
        }

        fn stop_server_listening(&mut self) -> Result<(), Self::Error> {
            self.log.borrow_mut().push(Event::StopListeningNone);
            self.result(FailurePoint::StopListening)
        }

        fn unregister_interface_waiting(
            &mut self,
            interface_spec: Self::InterfaceSpec,
            wait_for_calls_to_complete: bool,
        ) -> Result<(), Self::Error> {
            self.log.borrow_mut().push(Event::UnregisterInterface {
                interface_spec,
                wait_for_calls: wait_for_calls_to_complete,
            });
            self.result(FailurePoint::UnregisterInterface)
        }

        fn wait_server_listen(&mut self) -> Result<(), Self::Error> {
            self.log.borrow_mut().push(Event::WaitForListen);
            self.result(FailurePoint::WaitForListen)
        }
    }

    struct FakeHooks {
        log: EventLog,
    }

    impl LifecycleHooks for FakeHooks {
        fn set_admission(&mut self, accepting: bool) {
            self.log.borrow_mut().push(Event::Admission(accepting));
        }

        fn invalidate_epochs(&mut self) {
            self.log.borrow_mut().push(Event::InvalidateEpochs);
        }
    }

    impl Drop for FakeHooks {
        fn drop(&mut self) {
            self.log.borrow_mut().push(Event::Drop("hooks"));
        }
    }

    fn prepared(
        failures: &[FailurePoint],
    ) -> (PreparedStatusRpcServer<FakeOps, FakeHooks>, EventLog) {
        let log = Rc::new(RefCell::new(Vec::new()));
        let ops = FakeOps {
            log: Rc::clone(&log),
            failures: failures.to_vec(),
        };
        let security_descriptor = DropProbe {
            name: "endpoint-sd",
            log: Rc::clone(&log),
        };
        let hooks = FakeHooks {
            log: Rc::clone(&log),
        };
        (
            PreparedStatusRpcServer::new(ops, FakeInterfaceSpec(0x51), security_descriptor, hooks),
            log,
        )
    }

    fn take_start_error(
        result: Result<
            ListeningStatusRpcServer<FakeOps, FakeHooks>,
            StartFailure<FakeOps, FakeHooks>,
        >,
    ) -> StartFailure<FakeOps, FakeHooks> {
        match result {
            Err(error) => error,
            Ok(server) => {
                drop(server);
                unreachable!("failure injection unexpectedly started the server")
            }
        }
    }

    fn take_stop_error(
        result: Result<(), StopFailure<FakeOps, FakeHooks>>,
    ) -> StopFailure<FakeOps, FakeHooks> {
        match result {
            Err(error) => error,
            Ok(()) => unreachable!("failure injection unexpectedly drained the server"),
        }
    }

    #[test]
    fn constants_are_exact_and_exclude_unsafe_registration_modes() {
        assert_eq!(LOCAL_RPC_PROTOCOL_SEQUENCE, "ncalrpc");
        assert_eq!(STATUS_RPC_ENDPOINT, "YourWallet.KeyAgentService.v1");
        assert_eq!(RPC_C_AUTHN_WINNT, 10);
        assert_eq!(STATUS_RPC_INTERFACE_FLAGS, 0x68);
        assert_eq!(STATUS_RPC_INTERFACE_FLAGS & RPC_IF_AUTOLISTEN, 0);
        assert_eq!(
            STATUS_RPC_INTERFACE_FLAGS & RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH,
            0
        );
        assert_eq!(STATUS_RPC_MIN_CALL_THREADS, 1);
        assert_eq!(STATUS_RPC_MAX_CALLS, 8);
        assert_eq!(STATUS_RPC_MAX_RPC_SIZE, 76);
        assert_eq!(RPC_LISTEN_DONT_WAIT, 1);
    }

    #[test]
    fn successful_lifecycle_has_exact_order_and_drops_only_after_wait() {
        let (prepared, log) = prepared(&[]);
        let Ok(mut server) = prepared.start() else {
            unreachable!("success fixture must start")
        };
        assert!(!server.is_admitting());
        assert_eq!(
            *log.borrow(),
            [
                Event::Admission(false),
                Event::RegisterAuthentication(10),
                Event::BindEndpoint {
                    protocol_sequence: "ncalrpc",
                    max_calls: 8,
                    endpoint: "YourWallet.KeyAgentService.v1",
                    descriptor: "endpoint-sd",
                },
                Event::InstallHandler,
                Event::RegisterInterface {
                    interface_spec: FakeInterfaceSpec(0x51),
                    flags: 0x68,
                    max_calls: 8,
                    max_rpc_size: 76,
                    descriptor: "endpoint-sd",
                },
                Event::Listen {
                    minimum_call_threads: 1,
                    max_calls: 8,
                    dont_wait: 1,
                },
            ]
        );

        server.enable_admission_after_scm_running();
        server.enable_admission_after_scm_running();
        assert!(server.is_admitting());
        assert!(server.stop_and_drain().is_ok());
        assert_eq!(
            &log.borrow()[6..],
            [
                Event::Admission(true),
                Event::Admission(false),
                Event::InvalidateEpochs,
                Event::StopListeningNone,
                Event::UnregisterInterface {
                    interface_spec: FakeInterfaceSpec(0x51),
                    wait_for_calls: true,
                },
                Event::WaitForListen,
                Event::Drop("hooks"),
                Event::Drop("endpoint-sd"),
                Event::Drop("ops"),
            ]
        );
    }

    #[test]
    fn every_start_operation_failure_releases_without_opening_admission() {
        let cases = [
            (
                FailurePoint::RegisterAuthentication,
                StartStage::RegisterAuthentication,
            ),
            (FailurePoint::BindEndpoint, StartStage::BindEndpoint),
            (FailurePoint::InstallHandler, StartStage::InstallHandler),
            (
                FailurePoint::RegisterInterface,
                StartStage::RegisterInterface,
            ),
            (FailurePoint::Listen, StartStage::Listen),
        ];

        for (failure, stage) in cases {
            let (prepared, log) = prepared(&[failure]);
            let error = take_start_error(prepared.start());
            assert_eq!(error.stage(), stage);
            assert_eq!(error.error(), &FakeError(failure));
            assert!(error.cleanup_failure().is_none());
            assert!(!error.resources_are_retained());
            let events = log.borrow();
            assert!(!events.contains(&Event::Admission(true)));
            let (expected_count, terminal_operation) = match failure {
                FailurePoint::RegisterAuthentication => {
                    (5, Event::RegisterAuthentication(RPC_C_AUTHN_WINNT))
                }
                FailurePoint::BindEndpoint => (
                    6,
                    Event::BindEndpoint {
                        protocol_sequence: LOCAL_RPC_PROTOCOL_SEQUENCE,
                        max_calls: STATUS_RPC_MAX_CALLS,
                        endpoint: STATUS_RPC_ENDPOINT,
                        descriptor: "endpoint-sd",
                    },
                ),
                FailurePoint::InstallHandler => (7, Event::InstallHandler),
                FailurePoint::RegisterInterface => (
                    8,
                    Event::RegisterInterface {
                        interface_spec: FakeInterfaceSpec(0x51),
                        flags: STATUS_RPC_INTERFACE_FLAGS,
                        max_calls: STATUS_RPC_MAX_CALLS,
                        max_rpc_size: STATUS_RPC_MAX_RPC_SIZE,
                        descriptor: "endpoint-sd",
                    },
                ),
                FailurePoint::Listen => (14, Event::WaitForListen),
                FailurePoint::StopListening
                | FailurePoint::UnregisterInterface
                | FailurePoint::WaitForListen => {
                    unreachable!("not a startup operation")
                }
            };
            assert_eq!(events.len(), expected_count);
            assert_eq!(events[events.len() - 4], terminal_operation);
            assert_eq!(
                &events[events.len() - 3..],
                [
                    Event::Drop("hooks"),
                    Event::Drop("endpoint-sd"),
                    Event::Drop("ops"),
                ]
            );
        }
    }

    #[test]
    fn failed_listen_cleanup_edges_retain_resources_and_never_claim_success() {
        let cases = [
            (FailurePoint::StopListening, DrainStage::StopListening),
            (
                FailurePoint::UnregisterInterface,
                DrainStage::UnregisterInterface,
            ),
            (FailurePoint::WaitForListen, DrainStage::WaitForListen),
        ];

        for (cleanup_failure, expected_stage) in cases {
            let (prepared, log) = prepared(&[FailurePoint::Listen, cleanup_failure]);
            let error = take_start_error(prepared.start());
            assert_eq!(error.stage(), StartStage::Listen);
            assert!(error.resources_are_retained());
            let Some(report) = error.cleanup_failure() else {
                unreachable!("failed cleanup must have a report")
            };
            assert_eq!(report.stage(), expected_stage);
            assert_eq!(report.error(), &FakeError(cleanup_failure));
            drop(error);
            assert!(
                !log.borrow()
                    .iter()
                    .any(|event| matches!(event, Event::Drop(_)))
            );
        }
    }

    #[test]
    fn stop_listening_failure_best_effort_unregisters_but_never_waits() {
        let (prepared, log) = prepared(&[
            FailurePoint::StopListening,
            FailurePoint::UnregisterInterface,
        ]);
        let Ok(server) = prepared.start() else {
            unreachable!("stop failure fixture must start")
        };
        let error = take_stop_error(server.stop_and_drain());
        assert_eq!(error.report().stage(), DrainStage::StopListening);
        assert_eq!(
            error.report().secondary(),
            Some((
                DrainStage::UnregisterInterface,
                &FakeError(FailurePoint::UnregisterInterface)
            ))
        );
        assert!(error.resources_are_retained());
        assert_eq!(
            &log.borrow()[6..],
            [
                Event::Admission(false),
                Event::InvalidateEpochs,
                Event::StopListeningNone,
                Event::UnregisterInterface {
                    interface_spec: FakeInterfaceSpec(0x51),
                    wait_for_calls: true,
                },
            ]
        );
        drop(error);
        assert!(
            !log.borrow()
                .iter()
                .any(|event| matches!(event, Event::Drop(_)))
        );
    }

    #[test]
    fn unregister_and_wait_failures_never_return_clean_stop() {
        for (failure, expected_stage) in [
            (
                FailurePoint::UnregisterInterface,
                DrainStage::UnregisterInterface,
            ),
            (FailurePoint::WaitForListen, DrainStage::WaitForListen),
        ] {
            let (prepared, log) = prepared(&[failure]);
            let Ok(mut server) = prepared.start() else {
                unreachable!("drain failure fixture must start")
            };
            server.enable_admission_after_scm_running();
            let error = take_stop_error(server.stop_and_drain());
            assert_eq!(error.report().stage(), expected_stage);
            assert_eq!(error.report().error(), &FakeError(failure));
            assert!(error.resources_are_retained());
            assert_eq!(
                &log.borrow()[6..],
                [
                    Event::Admission(true),
                    Event::Admission(false),
                    Event::InvalidateEpochs,
                    Event::StopListeningNone,
                    Event::UnregisterInterface {
                        interface_spec: FakeInterfaceSpec(0x51),
                        wait_for_calls: true,
                    },
                    Event::WaitForListen,
                ]
            );
            drop(error);
            assert!(
                !log.borrow()
                    .iter()
                    .any(|event| matches!(event, Event::Drop(_)))
            );
        }
    }

    #[test]
    fn unregister_and_wait_double_failure_preserves_secondary_error() {
        let (prepared, _log) = prepared(&[
            FailurePoint::UnregisterInterface,
            FailurePoint::WaitForListen,
        ]);
        let Ok(server) = prepared.start() else {
            unreachable!("double drain failure fixture must start")
        };
        let error = take_stop_error(server.stop_and_drain());
        assert_eq!(error.report().stage(), DrainStage::UnregisterInterface);
        assert_eq!(
            error.report().secondary(),
            Some((
                DrainStage::WaitForListen,
                &FakeError(FailurePoint::WaitForListen)
            ))
        );
    }

    #[test]
    fn dropping_live_server_closes_admission_invalidates_and_retains_resources() {
        let (prepared, log) = prepared(&[]);
        let Ok(mut server) = prepared.start() else {
            unreachable!("drop fixture must start")
        };
        server.enable_admission_after_scm_running();
        drop(server);
        let events = log.borrow();
        assert_eq!(
            &events[events.len() - 2..],
            [Event::Admission(false), Event::InvalidateEpochs]
        );
        assert!(!events.iter().any(|event| matches!(event, Event::Drop(_))));
    }
}
