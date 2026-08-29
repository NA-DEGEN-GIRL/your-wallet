//! Pure role-aware routing for the debug-only service RPC fixture.
//!
//! Manager authentication is consumed before this module examines any frame.
//! Desktop peers retain the immutable V1 behavior or enter the explicit V2
//! desktop dispatcher. A service-created helper candidate can present only one
//! canonical V2 `HelperReady`; malformed or role-inappropriate input is
//! terminally rejected through the expected-peer admission boundary.

#![deny(unsafe_code)]

use core::fmt;

use key_agent_service_rpc_sys::RpcFrame;
use key_agent_service_wire::{PROTOCOL_MAGIC as V1_PROTOCOL_MAGIC, debug_v2};
use zeroize::Zeroizing;

use super::dispatch::{
    AuthenticationFailure, DesktopV2Dispatch, DesktopV2Launch, DispatchEngine, DispatchError,
};
use super::epoch::{ExactEpochPeer, MonotonicClock};
use super::expected_peer::{
    ExpectedHelperAdmission, ExpectedHelperCandidate, ExpectedHelperPeer, ExpectedHelperRole,
    ExpectedPeerKey, ExpectedPeerRegistryError,
};

/// Authenticated manager peer kind with authority retained in the exact branch.
#[must_use = "authenticated manager authority must be routed exactly once"]
pub(super) enum RoleAwareManagerPeer<D, H> {
    /// A desktop Broker peer that may own one epoch or launch action.
    Desktop(D),
    /// A service-created LPAC candidate awaiting expected-peer correlation.
    Helper(H),
}

impl<D, H> fmt::Debug for RoleAwareManagerPeer<D, H> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Desktop(_) => formatter.write_str("RoleAwareManagerPeer::Desktop([REDACTED])"),
            Self::Helper(_) => formatter.write_str("RoleAwareManagerPeer::Helper([REDACTED])"),
        }
    }
}

/// Independently authenticated callback peer kind.
#[must_use = "authenticated callback identity must be observed exactly once"]
pub(super) enum RoleAwareCallbackPeer<D, H> {
    /// A desktop callback, which carries no manager launch authority.
    Desktop(D),
    /// A service-created LPAC candidate that may only be observed.
    Helper(H),
}

impl<D, H> fmt::Debug for RoleAwareCallbackPeer<D, H> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Desktop(_) => formatter.write_str("RoleAwareCallbackPeer::Desktop([REDACTED])"),
            Self::Helper(_) => formatter.write_str("RoleAwareCallbackPeer::Helper([REDACTED])"),
        }
    }
}

/// Role-aware manager result returned without waiting under a dispatcher lock.
#[must_use = "routing outcomes may own authenticated launch authority"]
pub(super) enum RoleAwareManagerDispatch<D> {
    /// A complete response that can be returned by the RPC manager now.
    Immediate(RpcFrame),
    /// Move-only desktop launch work for the bounded launch coordinator.
    Launch(DesktopV2Launch<D>),
}

impl<D> fmt::Debug for RoleAwareManagerDispatch<D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Immediate(_) => {
                formatter.write_str("RoleAwareManagerDispatch::Immediate([REDACTED])")
            }
            Self::Launch(_) => formatter.write_str("RoleAwareManagerDispatch::Launch([REDACTED])"),
        }
    }
}

/// Narrow expected-helper boundary used by manager and callback routing.
///
/// The manager consumes or rejects; the security callback can only observe.
/// Keeping these operations on one injected port makes the sequencing testable
/// without weakening the concrete registry's move-only ownership rules.
pub(super) trait HelperAdmissionPort<C> {
    /// Consumes the exact expected helper and returns its server-derived role.
    fn consume_manager(
        &self,
        key: ExpectedPeerKey,
        candidate: &C,
    ) -> Result<ExpectedHelperRole, ExpectedPeerRegistryError>;

    /// Terminally rejects the candidate when no trustworthy helper key exists.
    fn reject_manager_candidate(&self, candidate: &C) -> Result<(), ExpectedPeerRegistryError>;

    /// Observes an exact expected helper without consuming its manager state.
    fn observe_callback(
        &self,
        candidate: &C,
    ) -> Result<ExpectedHelperRole, ExpectedPeerRegistryError>;
}

impl<P, C> HelperAdmissionPort<C> for ExpectedHelperAdmission<P, C>
where
    C: ExpectedHelperCandidate,
    P: ExpectedHelperPeer<C>,
{
    fn consume_manager(
        &self,
        key: ExpectedPeerKey,
        candidate: &C,
    ) -> Result<ExpectedHelperRole, ExpectedPeerRegistryError> {
        ExpectedHelperAdmission::consume_manager(self, key, candidate)
    }

    fn reject_manager_candidate(&self, candidate: &C) -> Result<(), ExpectedPeerRegistryError> {
        ExpectedHelperAdmission::reject_manager_candidate(self, candidate)
    }

    fn observe_callback(
        &self,
        candidate: &C,
    ) -> Result<ExpectedHelperRole, ExpectedPeerRegistryError> {
        ExpectedHelperAdmission::observe_callback(self, candidate)
    }
}

/// Authenticates and routes exactly one manager call.
///
/// `authenticate` is invoked once before canonicality, magic, version, kind, or
/// payload bytes are inspected. Helper admission can emit an ACK only after a
/// successful exact manager consume.
pub(super) fn route_manager<D, H, C, A, F>(
    dispatch: &DispatchEngine<D, C>,
    helpers: &A,
    request_frame: &RpcFrame,
    authenticate: F,
) -> Result<RoleAwareManagerDispatch<D>, DispatchError>
where
    D: ExactEpochPeer,
    C: MonotonicClock,
    A: HelperAdmissionPort<H>,
    F: FnOnce() -> Result<RoleAwareManagerPeer<D, H>, AuthenticationFailure>,
{
    route_manager_with_ack(
        dispatch,
        helpers,
        request_frame,
        authenticate,
        encode_helper_ready_ack,
    )
}

fn route_manager_with_ack<D, H, C, A, F, E>(
    dispatch: &DispatchEngine<D, C>,
    helpers: &A,
    request_frame: &RpcFrame,
    authenticate: F,
    encode_ack: E,
) -> Result<RoleAwareManagerDispatch<D>, DispatchError>
where
    D: ExactEpochPeer,
    C: MonotonicClock,
    A: HelperAdmissionPort<H>,
    F: FnOnce() -> Result<RoleAwareManagerPeer<D, H>, AuthenticationFailure>,
    E: FnOnce(&debug_v2::HelperReadyRequest, ExpectedHelperRole) -> Result<RpcFrame, DispatchError>,
{
    let peer = authenticate().map_err(map_authentication_failure)?;
    match peer {
        RoleAwareManagerPeer::Desktop(desktop) => route_desktop(dispatch, request_frame, desktop),
        RoleAwareManagerPeer::Helper(helper) => {
            route_helper_with_ack(helpers, request_frame, &helper, encode_ack)
                .map(RoleAwareManagerDispatch::Immediate)
        }
    }
}

fn route_desktop<D, C>(
    dispatch: &DispatchEngine<D, C>,
    request_frame: &RpcFrame,
    desktop: D,
) -> Result<RoleAwareManagerDispatch<D>, DispatchError>
where
    D: ExactEpochPeer,
    C: MonotonicClock,
{
    if !request_frame.is_canonical() {
        return Err(DispatchError::Malformed);
    }

    if request_frame.payload().get(..V1_PROTOCOL_MAGIC.len()) == Some(V1_PROTOCOL_MAGIC.as_slice())
    {
        return dispatch
            .exchange_authenticated_v1(request_frame, desktop)
            .map(RoleAwareManagerDispatch::Immediate);
    }

    match dispatch.exchange_authenticated_v2_desktop(request_frame, desktop)? {
        DesktopV2Dispatch::Immediate(response) => Ok(RoleAwareManagerDispatch::Immediate(response)),
        DesktopV2Dispatch::Launch(launch) => Ok(RoleAwareManagerDispatch::Launch(launch)),
    }
}

fn route_helper_with_ack<H, A, E>(
    helpers: &A,
    request_frame: &RpcFrame,
    helper: &H,
    encode_ack: E,
) -> Result<RpcFrame, DispatchError>
where
    A: HelperAdmissionPort<H>,
    E: FnOnce(&debug_v2::HelperReadyRequest, ExpectedHelperRole) -> Result<RpcFrame, DispatchError>,
{
    if !request_frame.is_canonical() {
        return reject_helper(helpers, helper, DispatchError::Malformed);
    }

    let Ok(request) = debug_v2::decode_request(request_frame.payload()) else {
        return reject_helper(helpers, helper, DispatchError::Malformed);
    };
    let debug_v2::ServiceRequest::HelperReady(ready) = request else {
        return reject_helper(helpers, helper, DispatchError::Authentication);
    };

    let key = ExpectedPeerKey::new(ready.epoch_nonce(), ready.request_id());
    let role = match helpers.consume_manager(key, helper) {
        Ok(role) => role,
        Err(consume_error) => {
            let failure = match helpers.reject_manager_candidate(helper) {
                Ok(()) => consume_error,
                Err(rejection_error) => more_severe_registry_error(consume_error, rejection_error),
            };
            return Err(map_registry_error(failure));
        }
    };
    encode_ack(&ready, role)
}

fn reject_helper<H, A>(
    helpers: &A,
    helper: &H,
    rejected_as: DispatchError,
) -> Result<RpcFrame, DispatchError>
where
    A: HelperAdmissionPort<H>,
{
    helpers
        .reject_manager_candidate(helper)
        .map_err(map_registry_error)?;
    Err(rejected_as)
}

fn encode_helper_ready_ack(
    request: &debug_v2::HelperReadyRequest,
    _server_role: ExpectedHelperRole,
) -> Result<RpcFrame, DispatchError> {
    let response = debug_v2::ServiceResponse::HelperReady(debug_v2::HelperReadyAck::new(
        request.epoch_nonce(),
        request.request_id(),
    ));
    response
        .ensure_correlates_with(&debug_v2::ServiceRequest::HelperReady(*request))
        .map_err(|_| DispatchError::Internal)?;
    let encoded = Zeroizing::new(debug_v2::encode_response(&response));
    RpcFrame::from_payload(encoded.as_slice()).map_err(|_| DispatchError::Internal)
}

/// Authenticates and authorizes one independent RPC security callback.
///
/// Desktop callback authentication carries no manager authority. A helper
/// callback performs only exact observation; manager consume remains reserved
/// for a later independently authenticated manager invocation.
pub(super) fn authorize_callback<D, H, A, F>(
    helpers: &A,
    authenticate: F,
) -> Result<(), DispatchError>
where
    A: HelperAdmissionPort<H>,
    F: FnOnce() -> Result<RoleAwareCallbackPeer<D, H>, AuthenticationFailure>,
{
    match authenticate().map_err(map_authentication_failure)? {
        RoleAwareCallbackPeer::Desktop(_) => Ok(()),
        RoleAwareCallbackPeer::Helper(helper) => helpers
            .observe_callback(&helper)
            .map(|_| ())
            .map_err(map_registry_error),
    }
}

const fn map_authentication_failure(error: AuthenticationFailure) -> DispatchError {
    match error {
        AuthenticationFailure::Denied => DispatchError::Authentication,
        AuthenticationFailure::Internal => DispatchError::Internal,
    }
}

const fn map_registry_error(error: ExpectedPeerRegistryError) -> DispatchError {
    match error {
        ExpectedPeerRegistryError::Denied => DispatchError::Authentication,
        ExpectedPeerRegistryError::Full => DispatchError::Full,
        ExpectedPeerRegistryError::Stopping => DispatchError::Stopping,
        ExpectedPeerRegistryError::Internal => DispatchError::Internal,
    }
}

/// Preserves the manager consume failure unless terminal rejection discovers
/// a stronger fail-closed service state. Concrete rejection cannot report
/// `Full`, but keeping all registry categories ordered makes injected ports
/// deterministic and prevents cleanup `Internal` failures from being hidden.
const fn more_severe_registry_error(
    primary: ExpectedPeerRegistryError,
    secondary: ExpectedPeerRegistryError,
) -> ExpectedPeerRegistryError {
    use ExpectedPeerRegistryError::{Denied, Full, Internal, Stopping};

    match (primary, secondary) {
        (Internal, _) | (_, Internal) => Internal,
        (Stopping, _) | (_, Stopping) => Stopping,
        (Full, _) | (_, Full) => Full,
        (Denied, Denied) => Denied,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use key_agent_service_wire::{
        OpenEpochRequest, ServiceCommand, ServiceCommandRequest, ServiceRequest, ServiceRequestId,
        ServiceResponse, ServiceStatus, decode_response, encode_request,
    };

    use super::*;
    use crate::key_agent_service_rpc::epoch::{PeerRevalidationError, sealed};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FakeDesktop(u64);

    impl sealed::Sealed for FakeDesktop {}

    impl ExactEpochPeer for FakeDesktop {
        fn exactly_matches(&self, current: &Self) -> Result<bool, PeerRevalidationError> {
            Ok(self == current)
        }

        fn revalidate(&self) -> Result<(), PeerRevalidationError> {
            Ok(())
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FakeHelper(u64);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum AdmissionEvent {
        Consume(ExpectedHelperRole),
        ConsumeFailure(ExpectedPeerRegistryError),
        Reject,
        Observe(ExpectedHelperRole),
        Encode(ExpectedHelperRole),
    }

    struct FakeAdmission {
        events: Arc<Mutex<Vec<AdmissionEvent>>>,
        consume: Result<ExpectedHelperRole, ExpectedPeerRegistryError>,
        reject: Result<(), ExpectedPeerRegistryError>,
        observe: Result<ExpectedHelperRole, ExpectedPeerRegistryError>,
    }

    impl FakeAdmission {
        fn allowing(role: ExpectedHelperRole) -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
                consume: Ok(role),
                reject: Ok(()),
                observe: Ok(role),
            }
        }

        fn events(&self) -> Result<Vec<AdmissionEvent>, &'static str> {
            self.events
                .lock()
                .map(|events| events.clone())
                .map_err(|_| "event lock")
        }
    }

    impl HelperAdmissionPort<FakeHelper> for FakeAdmission {
        fn consume_manager(
            &self,
            _key: ExpectedPeerKey,
            _candidate: &FakeHelper,
        ) -> Result<ExpectedHelperRole, ExpectedPeerRegistryError> {
            let event = match self.consume {
                Ok(role) => AdmissionEvent::Consume(role),
                Err(error) => AdmissionEvent::ConsumeFailure(error),
            };
            self.events
                .lock()
                .map_err(|_| ExpectedPeerRegistryError::Internal)?
                .push(event);
            self.consume
        }

        fn reject_manager_candidate(
            &self,
            _candidate: &FakeHelper,
        ) -> Result<(), ExpectedPeerRegistryError> {
            self.events
                .lock()
                .map_err(|_| ExpectedPeerRegistryError::Internal)?
                .push(AdmissionEvent::Reject);
            self.reject
        }

        fn observe_callback(
            &self,
            _candidate: &FakeHelper,
        ) -> Result<ExpectedHelperRole, ExpectedPeerRegistryError> {
            if let Ok(role) = self.observe {
                self.events
                    .lock()
                    .map_err(|_| ExpectedPeerRegistryError::Internal)?
                    .push(AdmissionEvent::Observe(role));
            }
            self.observe
        }
    }

    fn frame(payload: &[u8]) -> Result<RpcFrame, &'static str> {
        RpcFrame::from_payload(payload).map_err(|_| "frame")
    }

    fn request_id() -> Result<ServiceRequestId, &'static str> {
        ServiceRequestId::new([0xA5; 16]).map_err(|_| "request id")
    }

    fn helper_ready_frame() -> Result<RpcFrame, &'static str> {
        let epoch =
            key_agent_service_wire::EpochNonce::new([0x5A; 32]).map_err(|_| "epoch nonce")?;
        frame(&debug_v2::encode_request(
            &debug_v2::ServiceRequest::HelperReady(debug_v2::HelperReadyRequest::new(
                epoch,
                request_id()?,
            )),
        ))
    }

    fn new_dispatch() -> Result<DispatchEngine<FakeDesktop>, &'static str> {
        DispatchEngine::new().map_err(|_| "dispatch")
    }

    #[test]
    fn authentication_runs_once_before_malformed_input_is_examined() -> Result<(), &'static str> {
        let dispatch = new_dispatch()?;
        let admission = FakeAdmission::allowing(ExpectedHelperRole::Approval);
        let calls = Arc::new(Mutex::new(0_usize));
        let call_counter = Arc::clone(&calls);
        let result = route_manager(&dispatch, &admission, &RpcFrame::empty(), move || {
            let mut count = call_counter
                .lock()
                .map_err(|_| AuthenticationFailure::Internal)?;
            *count += 1;
            Ok(RoleAwareManagerPeer::Helper(FakeHelper(7)))
        });

        assert!(matches!(result, Err(DispatchError::Malformed)));
        assert_eq!(*calls.lock().map_err(|_| "call lock")?, 1);
        assert_eq!(admission.events()?, vec![AdmissionEvent::Reject]);
        Ok(())
    }

    #[test]
    fn authentication_failure_precedes_parsing_and_helper_admission() -> Result<(), &'static str> {
        let dispatch = new_dispatch()?;
        let admission = FakeAdmission::allowing(ExpectedHelperRole::Approval);
        let calls = Arc::new(Mutex::new(0_usize));
        let call_counter = Arc::clone(&calls);
        let result = route_manager::<FakeDesktop, FakeHelper, _, _, _>(
            &dispatch,
            &admission,
            &RpcFrame::empty(),
            move || {
                let mut count = call_counter
                    .lock()
                    .map_err(|_| AuthenticationFailure::Internal)?;
                *count += 1;
                Err(AuthenticationFailure::Denied)
            },
        );

        assert!(matches!(result, Err(DispatchError::Authentication)));
        assert_eq!(*calls.lock().map_err(|_| "call lock")?, 1);
        assert!(admission.events()?.is_empty());
        Ok(())
    }

    #[test]
    fn authentication_and_admission_errors_have_closed_dispatch_categories() {
        assert_eq!(
            map_authentication_failure(AuthenticationFailure::Denied),
            DispatchError::Authentication
        );
        assert_eq!(
            map_authentication_failure(AuthenticationFailure::Internal),
            DispatchError::Internal
        );
        assert_eq!(
            map_registry_error(ExpectedPeerRegistryError::Denied),
            DispatchError::Authentication
        );
        assert_eq!(
            map_registry_error(ExpectedPeerRegistryError::Full),
            DispatchError::Full
        );
        assert_eq!(
            map_registry_error(ExpectedPeerRegistryError::Stopping),
            DispatchError::Stopping
        );
        assert_eq!(
            map_registry_error(ExpectedPeerRegistryError::Internal),
            DispatchError::Internal
        );
    }

    #[test]
    fn desktop_v1_behavior_remains_open_then_status_unavailable() -> Result<(), &'static str> {
        let dispatch = new_dispatch()?;
        let admission = FakeAdmission::allowing(ExpectedHelperRole::Approval);
        let open = frame(&encode_request(&ServiceRequest::OpenEpoch(
            OpenEpochRequest::new(),
        )))?;
        let RoleAwareManagerDispatch::Immediate(open_response) =
            route_manager(&dispatch, &admission, &open, || {
                Ok(RoleAwareManagerPeer::Desktop(FakeDesktop(1)))
            })
            .map_err(|_| "route open")?
        else {
            return Err("v1 open launched");
        };
        let nonce = match decode_response(open_response.payload()).map_err(|_| "decode open")? {
            ServiceResponse::OpenEpoch(ack) => ack.epoch_nonce(),
            ServiceResponse::Status(_) => return Err("wrong open response"),
        };
        let status = frame(&encode_request(&ServiceRequest::Command(
            ServiceCommandRequest::new(nonce, request_id()?, ServiceCommand::Status),
        )))?;
        let RoleAwareManagerDispatch::Immediate(status_response) =
            route_manager(&dispatch, &admission, &status, || {
                Ok(RoleAwareManagerPeer::Desktop(FakeDesktop(1)))
            })
            .map_err(|_| "route status")?
        else {
            return Err("v1 status launched");
        };
        match decode_response(status_response.payload()).map_err(|_| "decode status")? {
            ServiceResponse::Status(response)
                if response.status() == ServiceStatus::Unavailable
                    && response.epoch_nonce() == nonce =>
            {
                Ok(())
            }
            ServiceResponse::OpenEpoch(_) | ServiceResponse::Status(_) => {
                Err("wrong status response")
            }
        }
    }

    #[test]
    fn desktop_v2_returns_immediate_status_or_move_only_launch() -> Result<(), &'static str> {
        let dispatch = new_dispatch()?;
        let admission = FakeAdmission::allowing(ExpectedHelperRole::Approval);
        let open = frame(&debug_v2::encode_request(
            &debug_v2::ServiceRequest::OpenEpoch(debug_v2::OpenEpochRequest::new()),
        ))?;
        let RoleAwareManagerDispatch::Immediate(open_response) =
            route_manager(&dispatch, &admission, &open, || {
                Ok(RoleAwareManagerPeer::Desktop(FakeDesktop(2)))
            })
            .map_err(|_| "route v2 open")?
        else {
            return Err("v2 open launched");
        };
        let nonce = match debug_v2::decode_response(open_response.payload())
            .map_err(|_| "decode v2 open")?
        {
            debug_v2::ServiceResponse::OpenEpoch(ack) => ack.epoch_nonce(),
            debug_v2::ServiceResponse::DesktopCommand(_)
            | debug_v2::ServiceResponse::HelperReady(_) => return Err("wrong v2 open response"),
        };

        let status_request = debug_v2::DesktopCommandRequest::new(
            nonce,
            request_id()?,
            debug_v2::DesktopCommand::Status,
        );
        let status = frame(&debug_v2::encode_request(
            &debug_v2::ServiceRequest::DesktopCommand(status_request),
        ))?;
        let RoleAwareManagerDispatch::Immediate(status_response) =
            route_manager(&dispatch, &admission, &status, || {
                Ok(RoleAwareManagerPeer::Desktop(FakeDesktop(2)))
            })
            .map_err(|_| "route v2 status")?
        else {
            return Err("v2 status launched");
        };
        match debug_v2::decode_response(status_response.payload())
            .map_err(|_| "decode v2 status")?
        {
            debug_v2::ServiceResponse::DesktopCommand(response)
                if response.result() == debug_v2::DesktopResult::Unavailable => {}
            debug_v2::ServiceResponse::OpenEpoch(_)
            | debug_v2::ServiceResponse::DesktopCommand(_)
            | debug_v2::ServiceResponse::HelperReady(_) => return Err("wrong v2 status response"),
        }

        let second_open = frame(&debug_v2::encode_request(
            &debug_v2::ServiceRequest::OpenEpoch(debug_v2::OpenEpochRequest::new()),
        ))?;
        let RoleAwareManagerDispatch::Immediate(second_open_response) =
            route_manager(&dispatch, &admission, &second_open, || {
                Ok(RoleAwareManagerPeer::Desktop(FakeDesktop(2)))
            })
            .map_err(|_| "route second v2 open")?
        else {
            return Err("second v2 open launched");
        };
        let second_nonce = match debug_v2::decode_response(second_open_response.payload())
            .map_err(|_| "decode second v2 open")?
        {
            debug_v2::ServiceResponse::OpenEpoch(ack) => ack.epoch_nonce(),
            debug_v2::ServiceResponse::DesktopCommand(_)
            | debug_v2::ServiceResponse::HelperReady(_) => {
                return Err("wrong second v2 open response");
            }
        };
        let launch_request = debug_v2::DesktopCommandRequest::new(
            second_nonce,
            request_id()?,
            debug_v2::DesktopCommand::LaunchApprovalRpcProbe,
        );
        let launch_frame = frame(&debug_v2::encode_request(
            &debug_v2::ServiceRequest::DesktopCommand(launch_request),
        ))?;
        let RoleAwareManagerDispatch::Launch(launch) =
            route_manager(&dispatch, &admission, &launch_frame, || {
                Ok(RoleAwareManagerPeer::Desktop(FakeDesktop(2)))
            })
            .map_err(|_| "route v2 launch")?
        else {
            return Err("v2 launch returned immediate");
        };
        let (peer, completion) = launch.into_parts();
        assert_eq!(peer, FakeDesktop(2));
        assert_eq!(completion.request(), &launch_request);
        let completed = completion
            .complete(debug_v2::DesktopResult::ApprovalRpcProbeCompleted)
            .map_err(|_| "complete launch")?;
        assert!(matches!(
            debug_v2::decode_response(completed.payload()),
            Ok(debug_v2::ServiceResponse::DesktopCommand(response))
                if response.result() == debug_v2::DesktopResult::ApprovalRpcProbeCompleted
        ));
        Ok(())
    }

    #[test]
    fn helper_ready_is_consumed_before_exact_ack_encoding() -> Result<(), &'static str> {
        let dispatch = new_dispatch()?;
        let admission = FakeAdmission::allowing(ExpectedHelperRole::SecretInput);
        let events = Arc::clone(&admission.events);
        let request = helper_ready_frame()?;
        let RoleAwareManagerDispatch::Immediate(response) = route_manager_with_ack(
            &dispatch,
            &admission,
            &request,
            || Ok(RoleAwareManagerPeer::Helper(FakeHelper(9))),
            move |ready, role| {
                events
                    .lock()
                    .map_err(|_| DispatchError::Internal)?
                    .push(AdmissionEvent::Encode(role));
                encode_helper_ready_ack(ready, role)
            },
        )
        .map_err(|_| "route helper ready")?
        else {
            return Err("helper ready launched");
        };

        assert_eq!(
            admission.events()?,
            vec![
                AdmissionEvent::Consume(ExpectedHelperRole::SecretInput),
                AdmissionEvent::Encode(ExpectedHelperRole::SecretInput),
            ]
        );
        assert!(matches!(
            debug_v2::decode_response(response.payload()),
            Ok(debug_v2::ServiceResponse::HelperReady(_))
        ));
        Ok(())
    }

    #[test]
    fn helper_non_ready_and_malformed_frames_are_terminally_rejected() -> Result<(), &'static str> {
        let dispatch = new_dispatch()?;
        let admission = FakeAdmission::allowing(ExpectedHelperRole::Approval);
        let open = frame(&debug_v2::encode_request(
            &debug_v2::ServiceRequest::OpenEpoch(debug_v2::OpenEpochRequest::new()),
        ))?;
        assert!(matches!(
            route_manager(&dispatch, &admission, &open, || {
                Ok(RoleAwareManagerPeer::Helper(FakeHelper(10)))
            }),
            Err(DispatchError::Authentication)
        ));
        assert!(matches!(
            route_manager(&dispatch, &admission, &RpcFrame::empty(), || {
                Ok(RoleAwareManagerPeer::Helper(FakeHelper(10)))
            }),
            Err(DispatchError::Malformed)
        ));
        assert_eq!(
            admission.events()?,
            vec![AdmissionEvent::Reject, AdmissionEvent::Reject]
        );
        Ok(())
    }

    #[test]
    fn helper_rejection_failure_dominates_the_wire_category() -> Result<(), &'static str> {
        let dispatch = new_dispatch()?;
        let admission = FakeAdmission {
            events: Arc::new(Mutex::new(Vec::new())),
            consume: Ok(ExpectedHelperRole::Approval),
            reject: Err(ExpectedPeerRegistryError::Internal),
            observe: Ok(ExpectedHelperRole::Approval),
        };
        assert!(matches!(
            route_manager(&dispatch, &admission, &RpcFrame::empty(), || {
                Ok(RoleAwareManagerPeer::Helper(FakeHelper(15)))
            }),
            Err(DispatchError::Internal)
        ));
        assert_eq!(admission.events()?, vec![AdmissionEvent::Reject]);
        Ok(())
    }

    #[test]
    fn helper_consume_failure_never_encodes_an_ack() -> Result<(), &'static str> {
        let dispatch = new_dispatch()?;
        let admission = FakeAdmission {
            events: Arc::new(Mutex::new(Vec::new())),
            consume: Err(ExpectedPeerRegistryError::Denied),
            reject: Ok(()),
            observe: Ok(ExpectedHelperRole::Approval),
        };
        let encoded = Arc::new(Mutex::new(false));
        let encoded_marker = Arc::clone(&encoded);
        let result = route_manager_with_ack(
            &dispatch,
            &admission,
            &helper_ready_frame()?,
            || Ok(RoleAwareManagerPeer::Helper(FakeHelper(11))),
            move |ready, role| {
                *encoded_marker.lock().map_err(|_| DispatchError::Internal)? = true;
                encode_helper_ready_ack(ready, role)
            },
        );

        assert!(matches!(result, Err(DispatchError::Authentication)));
        assert!(!*encoded.lock().map_err(|_| "encoded lock")?);
        assert_eq!(
            admission.events()?,
            vec![
                AdmissionEvent::ConsumeFailure(ExpectedPeerRegistryError::Denied),
                AdmissionEvent::Reject,
            ]
        );
        Ok(())
    }

    #[test]
    fn helper_rejection_cleanup_failure_dominates_consume_denial_without_ack()
    -> Result<(), &'static str> {
        let dispatch = new_dispatch()?;
        let admission = FakeAdmission {
            events: Arc::new(Mutex::new(Vec::new())),
            consume: Err(ExpectedPeerRegistryError::Denied),
            reject: Err(ExpectedPeerRegistryError::Internal),
            observe: Ok(ExpectedHelperRole::Approval),
        };
        let encoded = Arc::new(Mutex::new(false));
        let encoded_marker = Arc::clone(&encoded);
        let result = route_manager_with_ack(
            &dispatch,
            &admission,
            &helper_ready_frame()?,
            || Ok(RoleAwareManagerPeer::Helper(FakeHelper(16))),
            move |ready, role| {
                *encoded_marker.lock().map_err(|_| DispatchError::Internal)? = true;
                encode_helper_ready_ack(ready, role)
            },
        );

        assert!(matches!(result, Err(DispatchError::Internal)));
        assert!(!*encoded.lock().map_err(|_| "encoded lock")?);
        assert_eq!(
            admission.events()?,
            vec![
                AdmissionEvent::ConsumeFailure(ExpectedPeerRegistryError::Denied),
                AdmissionEvent::Reject,
            ]
        );
        Ok(())
    }

    #[test]
    fn desktop_can_never_present_helper_ready() -> Result<(), &'static str> {
        let dispatch = new_dispatch()?;
        let admission = FakeAdmission::allowing(ExpectedHelperRole::Approval);
        assert!(matches!(
            route_manager(&dispatch, &admission, &helper_ready_frame()?, || {
                Ok(RoleAwareManagerPeer::Desktop(FakeDesktop(12)))
            }),
            Err(DispatchError::Authentication)
        ));
        assert!(admission.events()?.is_empty());
        Ok(())
    }

    #[test]
    fn helper_callback_observes_without_manager_consume_or_reject() -> Result<(), &'static str> {
        let admission = FakeAdmission::allowing(ExpectedHelperRole::SecretInput);
        let calls = Arc::new(Mutex::new(0_usize));
        let call_counter = Arc::clone(&calls);
        authorize_callback::<(), _, _, _>(&admission, move || {
            let mut count = call_counter
                .lock()
                .map_err(|_| AuthenticationFailure::Internal)?;
            *count += 1;
            Ok(RoleAwareCallbackPeer::Helper(FakeHelper(13)))
        })
        .map_err(|_| "authorize callback")?;

        assert_eq!(*calls.lock().map_err(|_| "call lock")?, 1);
        assert_eq!(
            admission.events()?,
            vec![AdmissionEvent::Observe(ExpectedHelperRole::SecretInput)]
        );
        Ok(())
    }

    #[test]
    fn desktop_callback_does_not_touch_helper_admission() -> Result<(), &'static str> {
        let admission = FakeAdmission::allowing(ExpectedHelperRole::Approval);
        authorize_callback::<_, FakeHelper, _, _>(&admission, || {
            Ok(RoleAwareCallbackPeer::Desktop(()))
        })
        .map_err(|_| "authorize desktop callback")?;
        assert!(admission.events()?.is_empty());
        Ok(())
    }

    #[test]
    fn callback_observation_failure_is_closed_without_a_consume() -> Result<(), &'static str> {
        let admission = FakeAdmission {
            events: Arc::new(Mutex::new(Vec::new())),
            consume: Ok(ExpectedHelperRole::Approval),
            reject: Ok(()),
            observe: Err(ExpectedPeerRegistryError::Internal),
        };
        assert!(matches!(
            authorize_callback::<(), _, _, _>(&admission, || {
                Ok(RoleAwareCallbackPeer::Helper(FakeHelper(14)))
            }),
            Err(DispatchError::Internal)
        ));
        assert!(admission.events()?.is_empty());
        Ok(())
    }

    #[test]
    fn callback_authentication_failure_precedes_helper_observation() -> Result<(), &'static str> {
        let admission = FakeAdmission::allowing(ExpectedHelperRole::Approval);
        assert!(matches!(
            authorize_callback::<(), FakeHelper, _, _>(&admission, || {
                Err(AuthenticationFailure::Denied)
            }),
            Err(DispatchError::Authentication)
        ));
        assert!(admission.events()?.is_empty());
        Ok(())
    }

    #[test]
    fn route_debug_output_is_data_free() {
        assert_eq!(
            format!(
                "{:?}",
                RoleAwareManagerPeer::<_, FakeHelper>::Desktop(FakeDesktop(1))
            ),
            "RoleAwareManagerPeer::Desktop([REDACTED])"
        );
        assert_eq!(
            format!(
                "{:?}",
                RoleAwareCallbackPeer::<(), _>::Helper(FakeHelper(1))
            ),
            "RoleAwareCallbackPeer::Helper([REDACTED])"
        );
    }
}
