//! Authenticated wire dispatch for the debug-only status RPC fixture.
//!
//! Every manager call authenticates exactly once through a consuming callback.
//! The separately registered RPC security callback performs its own independent
//! check before the manager is entered; that lifecycle boundary is intentionally
//! outside this pure dispatcher.

#![deny(unsafe_code)]

use std::fmt;

use key_agent_service_rpc_sys::{ManagerError, RpcFrame};
#[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
use key_agent_service_wire::debug_v2::{
    self, DesktopCommand, DesktopCommandRequest, DesktopCommandResponse, DesktopResult,
};
use key_agent_service_wire::{
    OpenEpochAck, ServiceCommand, ServiceRequest, ServiceResponse, ServiceStatus,
    ServiceStatusResponse, decode_request, encode_response,
};
use zeroize::Zeroizing;

#[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
use super::epoch::ProtocolVersion;
use super::epoch::{EpochError, EpochTable, ExactEpochPeer, MonotonicClock, SystemMonotonicClock};

/// Stable result of manager-side call authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AuthenticationFailure {
    /// The call did not satisfy the complete local RPC peer policy.
    Denied,
    /// The operating system could not produce an unambiguous safe result.
    Internal,
}

/// Closed dispatch outcomes mapped to the five RPC manager categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DispatchError {
    /// The fixed outer frame or versioned wire payload was noncanonical.
    Malformed,
    /// Manager-side call authentication rejected the peer.
    Authentication,
    /// Epoch authentication, binding, expiry, or replay validation failed.
    Epoch,
    /// All fixed live epoch slots were occupied.
    Full,
    /// The worker is stopping and accepts no new work.
    Stopping,
    /// An OS query, clock, counter, HMAC, or invariant failed closed.
    Internal,
}

impl From<DispatchError> for ManagerError {
    fn from(error: DispatchError) -> Self {
        match error {
            DispatchError::Malformed => Self::InvalidArgument,
            DispatchError::Authentication | DispatchError::Epoch => Self::AccessDenied,
            DispatchError::Full => Self::ServerTooBusy,
            DispatchError::Stopping => Self::ServerUnavailable,
            DispatchError::Internal => Self::CallFailed,
        }
    }
}

/// Pure version-2 desktop dispatch result.
///
/// Launch work remains an owned action so this dispatcher never waits for a
/// helper or holds a launch coordinator lock.
#[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
#[must_use = "dispatch outcomes may own authenticated launch authority"]
#[allow(
    dead_code,
    reason = "runtime role-aware manager wiring follows this pure V2 dispatch slice"
)]
pub(super) enum DesktopV2Dispatch<P> {
    /// A complete response that can be returned immediately.
    Immediate(RpcFrame),
    /// A freshly authenticated desktop peer and its consumed launch request.
    Launch(DesktopV2Launch<P>),
}

#[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
impl<P> fmt::Debug for DesktopV2Dispatch<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Immediate(_) => formatter.write_str("DesktopV2Dispatch::Immediate([REDACTED])"),
            Self::Launch(_) => formatter.write_str("DesktopV2Dispatch::Launch([REDACTED])"),
        }
    }
}

/// One authenticated version-2 desktop launch action.
#[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
#[must_use = "launch actions own authenticated peer authority until consumed"]
#[allow(
    dead_code,
    reason = "runtime role-aware manager wiring follows this pure V2 dispatch slice"
)]
pub(super) struct DesktopV2Launch<P> {
    current_peer: P,
    pending_completion: DesktopV2PendingCompletion,
}

#[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
#[allow(
    dead_code,
    reason = "runtime role-aware manager wiring follows this pure V2 dispatch slice"
)]
impl<P> DesktopV2Launch<P> {
    /// Separates the move-only peer authority from its one-shot completion.
    #[must_use = "the returned tuple owns authenticated peer authority"]
    pub(super) fn into_parts(self) -> (P, DesktopV2PendingCompletion) {
        (self.current_peer, self.pending_completion)
    }
}

#[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
impl<P> fmt::Debug for DesktopV2Launch<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DesktopV2Launch([REDACTED])")
    }
}

/// One-shot right to complete an already-consumed version-2 desktop launch.
///
/// Only [`DesktopV2Launch`] can issue this non-`Clone`, non-`Copy` capability.
/// Borrowing the request supports launch correlation, while producing the RPC
/// response consumes the capability so a coordinator cannot report completion
/// twice for one launch action.
#[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
#[must_use = "pending launch completion must be settled exactly once"]
#[allow(
    dead_code,
    reason = "runtime role-aware manager wiring follows this pure V2 dispatch slice"
)]
pub(super) struct DesktopV2PendingCompletion {
    request: DesktopCommandRequest,
}

#[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
#[allow(
    dead_code,
    reason = "runtime role-aware manager wiring follows this pure V2 dispatch slice"
)]
impl DesktopV2PendingCompletion {
    /// Borrows the exact request for launch-side role and correlation checks.
    #[must_use]
    pub(super) const fn request(&self) -> &DesktopCommandRequest {
        &self.request
    }

    /// Consumes the one-shot capability and encodes its correlated result.
    pub(super) fn complete(self, result: DesktopResult) -> Result<RpcFrame, DispatchError> {
        if !matches!(
            self.request.command(),
            DesktopCommand::LaunchApprovalRpcProbe | DesktopCommand::LaunchSecretInputRpcProbe
        ) {
            return Err(DispatchError::Internal);
        }

        let response = DesktopCommandResponse::new(
            self.request.epoch_nonce(),
            self.request.request_id(),
            result,
        );
        response
            .ensure_correlates_with(&self.request)
            .map_err(|_| DispatchError::Internal)?;
        encode_v2_response(&debug_v2::ServiceResponse::DesktopCommand(response))
    }
}

#[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
impl fmt::Debug for DesktopV2PendingCompletion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DesktopV2PendingCompletion([REDACTED])")
    }
}

/// Pure authenticated dispatcher owned by one status RPC worker.
pub(super) struct DispatchEngine<P, C = SystemMonotonicClock>
where
    P: ExactEpochPeer,
    C: MonotonicClock,
{
    epochs: EpochTable<P, C>,
}

impl<P> DispatchEngine<P, SystemMonotonicClock>
where
    P: ExactEpochPeer,
{
    /// Starts a dispatcher with a fresh per-worker random epoch seed.
    pub(super) fn new() -> Result<Self, DispatchError> {
        EpochTable::new(SystemMonotonicClock)
            .map(|epochs| Self { epochs })
            .map_err(map_epoch_error)
    }
}

impl<P, C> DispatchEngine<P, C>
where
    P: ExactEpochPeer,
    C: MonotonicClock,
{
    #[cfg(test)]
    fn new_for_test(clock: C, seed: Zeroizing<[u8; 32]>) -> Result<Self, DispatchError> {
        EpochTable::new_for_test(clock, seed)
            .map(|epochs| Self { epochs })
            .map_err(map_epoch_error)
    }

    /// Authenticates and dispatches exactly one canonical manager call.
    ///
    /// `authenticate` must consume the call-scoped RPC binding in production.
    /// It is invoked exactly once, before any wire parsing, so every manager
    /// entry independently authenticates even malformed input.
    pub(super) fn exchange_with<F>(
        &self,
        request_frame: &RpcFrame,
        authenticate: F,
    ) -> Result<RpcFrame, DispatchError>
    where
        F: FnOnce() -> Result<P, AuthenticationFailure>,
    {
        let current_peer = authenticate().map_err(map_authentication_failure)?;
        self.exchange_authenticated_v1(request_frame, current_peer)
    }

    /// Dispatches one version-1 call after its peer was authenticated.
    ///
    /// This split preserves the immutable version-1 behavior while allowing a
    /// role-aware manager to authenticate before selecting a protocol path.
    pub(super) fn exchange_authenticated_v1(
        &self,
        request_frame: &RpcFrame,
        current_peer: P,
    ) -> Result<RpcFrame, DispatchError> {
        if !request_frame.is_canonical() {
            return Err(DispatchError::Malformed);
        }
        let request =
            decode_request(request_frame.payload()).map_err(|_| DispatchError::Malformed)?;

        let response = match request {
            ServiceRequest::OpenEpoch(_) => {
                let nonce = self.epochs.issue(current_peer).map_err(map_epoch_error)?;
                ServiceResponse::OpenEpoch(OpenEpochAck::new(nonce))
            }
            ServiceRequest::Command(command) => {
                self.epochs
                    .consume(command.epoch_nonce(), &current_peer)
                    .map_err(map_epoch_error)?;
                match command.command() {
                    ServiceCommand::Status => ServiceResponse::Status(ServiceStatusResponse::new(
                        command.epoch_nonce(),
                        command.request_id(),
                        ServiceStatus::Unavailable,
                    )),
                }
            }
        };

        response
            .ensure_correlates_with(&request)
            .map_err(|_| DispatchError::Internal)?;
        let encoded = Zeroizing::new(encode_response(&response));
        RpcFrame::from_payload(encoded.as_slice()).map_err(|_| DispatchError::Internal)
    }

    /// Authenticates and dispatches one debug-only version-2 desktop call.
    #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
    #[allow(
        dead_code,
        reason = "runtime role-aware manager wiring follows this pure V2 dispatch slice"
    )]
    pub(super) fn exchange_v2_desktop_with<F>(
        &self,
        request_frame: &RpcFrame,
        authenticate: F,
    ) -> Result<DesktopV2Dispatch<P>, DispatchError>
    where
        F: FnOnce() -> Result<P, AuthenticationFailure>,
    {
        let current_peer = authenticate().map_err(map_authentication_failure)?;
        self.exchange_authenticated_v2_desktop(request_frame, current_peer)
    }

    /// Dispatches one debug-only version-2 call for an authenticated desktop.
    ///
    /// Helper-ready belongs exclusively to a matched service-created helper.
    /// This desktop path rejects it before looking up or consuming an epoch.
    #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
    #[allow(
        dead_code,
        reason = "runtime role-aware manager wiring follows this pure V2 dispatch slice"
    )]
    pub(super) fn exchange_authenticated_v2_desktop(
        &self,
        request_frame: &RpcFrame,
        current_peer: P,
    ) -> Result<DesktopV2Dispatch<P>, DispatchError> {
        if !request_frame.is_canonical() {
            return Err(DispatchError::Malformed);
        }
        let request = debug_v2::decode_request(request_frame.payload())
            .map_err(|_| DispatchError::Malformed)?;

        match request {
            debug_v2::ServiceRequest::OpenEpoch(_) => {
                let nonce = self
                    .epochs
                    .issue_for_version(current_peer, ProtocolVersion::V2)
                    .map_err(map_epoch_error)?;
                let response =
                    debug_v2::ServiceResponse::OpenEpoch(debug_v2::OpenEpochAck::new(nonce));
                response
                    .ensure_correlates_with(&request)
                    .map_err(|_| DispatchError::Internal)?;
                encode_v2_response(&response).map(DesktopV2Dispatch::Immediate)
            }
            debug_v2::ServiceRequest::DesktopCommand(command) => {
                self.epochs
                    .consume_for_version(command.epoch_nonce(), &current_peer, ProtocolVersion::V2)
                    .map_err(map_epoch_error)?;
                match command.command() {
                    DesktopCommand::Status => {
                        let response =
                            debug_v2::ServiceResponse::DesktopCommand(DesktopCommandResponse::new(
                                command.epoch_nonce(),
                                command.request_id(),
                                DesktopResult::Unavailable,
                            ));
                        response
                            .ensure_correlates_with(&request)
                            .map_err(|_| DispatchError::Internal)?;
                        encode_v2_response(&response).map(DesktopV2Dispatch::Immediate)
                    }
                    DesktopCommand::LaunchApprovalRpcProbe
                    | DesktopCommand::LaunchSecretInputRpcProbe => {
                        Ok(DesktopV2Dispatch::Launch(DesktopV2Launch {
                            current_peer,
                            pending_completion: DesktopV2PendingCompletion { request: command },
                        }))
                    }
                }
            }
            debug_v2::ServiceRequest::HelperReady(_) => Err(DispatchError::Authentication),
        }
    }

    /// Stops this dispatcher and invalidates every outstanding epoch.
    pub(super) fn stop(&self) -> Result<(), DispatchError> {
        self.epochs.stop().map_err(map_epoch_error)
    }
}

#[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
#[allow(
    dead_code,
    reason = "runtime role-aware manager wiring follows this pure V2 dispatch slice"
)]
fn encode_v2_response(response: &debug_v2::ServiceResponse) -> Result<RpcFrame, DispatchError> {
    let encoded = Zeroizing::new(debug_v2::encode_response(response));
    RpcFrame::from_payload(encoded.as_slice()).map_err(|_| DispatchError::Internal)
}

impl<P, C> fmt::Debug for DispatchEngine<P, C>
where
    P: ExactEpochPeer,
    C: MonotonicClock,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DispatchEngine([REDACTED])")
    }
}

const fn map_authentication_failure(error: AuthenticationFailure) -> DispatchError {
    match error {
        AuthenticationFailure::Denied => DispatchError::Authentication,
        AuthenticationFailure::Internal => DispatchError::Internal,
    }
}

const fn map_epoch_error(error: EpochError) -> DispatchError {
    match error {
        EpochError::Denied => DispatchError::Epoch,
        EpochError::Full => DispatchError::Full,
        EpochError::Stopping => DispatchError::Stopping,
        EpochError::Internal => DispatchError::Internal,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicU64, AtomicUsize, Ordering},
        },
        time::Duration,
    };

    #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
    use key_agent_service_wire::debug_v2 as wire_v2;
    use key_agent_service_wire::{
        EpochNonce, OpenEpochRequest, ServiceCommandRequest, ServiceRequestId, WireError,
        decode_response, encode_request,
    };

    use super::*;
    use crate::key_agent_service_rpc::epoch::{PeerRevalidationError, sealed};

    const TEST_SEED: [u8; 32] = [0x6D; 32];

    #[derive(Clone, Debug)]
    struct TestClock(Arc<AtomicU64>);

    impl TestClock {
        fn at(millis: u64) -> Self {
            Self(Arc::new(AtomicU64::new(millis)))
        }
    }

    impl MonotonicClock for TestClock {
        type Instant = u64;

        fn now(&self) -> Option<Self::Instant> {
            Some(self.0.load(Ordering::SeqCst))
        }

        fn checked_add(&self, instant: Self::Instant, duration: Duration) -> Option<Self::Instant> {
            instant.checked_add(u64::try_from(duration.as_millis()).ok()?)
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct TestPeer {
        identity: u64,
        revalidation: Result<(), PeerRevalidationError>,
    }

    impl TestPeer {
        const fn allowed(identity: u64) -> Self {
            Self {
                identity,
                revalidation: Ok(()),
            }
        }

        const fn internally_ambiguous(identity: u64) -> Self {
            Self {
                identity,
                revalidation: Err(PeerRevalidationError::Internal),
            }
        }
    }

    impl sealed::Sealed for TestPeer {}

    impl ExactEpochPeer for TestPeer {
        fn exactly_matches(&self, current: &Self) -> Result<bool, PeerRevalidationError> {
            Ok(self.identity == current.identity)
        }

        fn revalidate(&self) -> Result<(), PeerRevalidationError> {
            self.revalidation
        }
    }

    fn engine() -> Result<DispatchEngine<TestPeer, TestClock>, DispatchError> {
        DispatchEngine::new_for_test(TestClock::at(0), Zeroizing::new(TEST_SEED))
    }

    fn request_frame(request: &ServiceRequest) -> Result<RpcFrame, DispatchError> {
        RpcFrame::from_payload(&encode_request(request)).map_err(|_| DispatchError::Internal)
    }

    fn response(frame: &RpcFrame) -> Result<ServiceResponse, DispatchError> {
        decode_response(frame.payload()).map_err(|_| DispatchError::Internal)
    }

    #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
    fn request_frame_v2(request: &wire_v2::ServiceRequest) -> Result<RpcFrame, DispatchError> {
        RpcFrame::from_payload(&wire_v2::encode_request(request))
            .map_err(|_| DispatchError::Internal)
    }

    #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
    fn response_v2(frame: &RpcFrame) -> Result<wire_v2::ServiceResponse, DispatchError> {
        wire_v2::decode_response(frame.payload()).map_err(|_| DispatchError::Internal)
    }

    #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
    fn immediate_v2(outcome: &DesktopV2Dispatch<TestPeer>) -> Result<RpcFrame, DispatchError> {
        match outcome {
            DesktopV2Dispatch::Immediate(frame) => Ok(*frame),
            DesktopV2Dispatch::Launch(_) => Err(DispatchError::Internal),
        }
    }

    fn open_epoch(
        engine: &DispatchEngine<TestPeer, TestClock>,
        peer: TestPeer,
        calls: &AtomicUsize,
    ) -> Result<EpochNonce, DispatchError> {
        let request = ServiceRequest::OpenEpoch(OpenEpochRequest::new());
        let frame = request_frame(&request)?;
        let response_frame = engine.exchange_with(&frame, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(peer)
        })?;
        match response(&response_frame)? {
            ServiceResponse::OpenEpoch(ack) => Ok(ack.epoch_nonce()),
            ServiceResponse::Status(_) => Err(DispatchError::Internal),
        }
    }

    #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
    fn open_epoch_v2(
        engine: &DispatchEngine<TestPeer, TestClock>,
        peer: TestPeer,
        calls: &AtomicUsize,
    ) -> Result<EpochNonce, DispatchError> {
        let request = wire_v2::ServiceRequest::OpenEpoch(wire_v2::OpenEpochRequest::new());
        let frame = request_frame_v2(&request)?;
        let outcome = engine.exchange_v2_desktop_with(&frame, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(peer)
        })?;
        match response_v2(&immediate_v2(&outcome)?)? {
            wire_v2::ServiceResponse::OpenEpoch(ack) => Ok(ack.epoch_nonce()),
            wire_v2::ServiceResponse::DesktopCommand(_)
            | wire_v2::ServiceResponse::HelperReady(_) => Err(DispatchError::Internal),
        }
    }

    #[test]
    fn open_and_status_are_the_only_successful_dispatches() -> Result<(), DispatchError> {
        let engine = engine()?;
        let calls = AtomicUsize::new(0);
        let nonce = open_epoch(&engine, TestPeer::allowed(7), &calls)?;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let request_id = ServiceRequestId::new([0x3C; 16]).map_err(|_| DispatchError::Internal)?;
        let command = ServiceCommandRequest::new(nonce, request_id, ServiceCommand::Status);
        let request = ServiceRequest::Command(command);
        let frame = request_frame(&request)?;
        let response_frame = engine.exchange_with(&frame, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(TestPeer::allowed(7))
        })?;
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let decoded = response(&response_frame)?;
        decoded
            .ensure_correlates_with(&request)
            .map_err(|_| DispatchError::Internal)?;
        match decoded {
            ServiceResponse::Status(status) => {
                assert_eq!(status.status(), ServiceStatus::Unavailable);
                assert_eq!(status.epoch_nonce(), nonce);
                assert_eq!(status.request_id(), request_id);
            }
            ServiceResponse::OpenEpoch(_) => return Err(DispatchError::Internal),
        }
        Ok(())
    }

    #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
    #[test]
    fn v2_open_and_status_return_only_correlated_immediate_frames() -> Result<(), DispatchError> {
        let engine = engine()?;
        let calls = AtomicUsize::new(0);
        let nonce = open_epoch_v2(&engine, TestPeer::allowed(70), &calls)?;
        let request_id = ServiceRequestId::new([0x71; 16]).map_err(|_| DispatchError::Internal)?;
        let command =
            wire_v2::DesktopCommandRequest::new(nonce, request_id, wire_v2::DesktopCommand::Status);
        let request = wire_v2::ServiceRequest::DesktopCommand(command);
        let frame = request_frame_v2(&request)?;
        let outcome = engine.exchange_v2_desktop_with(&frame, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(TestPeer::allowed(70))
        })?;
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let decoded = response_v2(&immediate_v2(&outcome)?)?;
        decoded
            .ensure_correlates_with(&request)
            .map_err(|_| DispatchError::Internal)?;
        match decoded {
            wire_v2::ServiceResponse::DesktopCommand(response) => {
                assert_eq!(response.result(), wire_v2::DesktopResult::Unavailable);
                assert_eq!(response.epoch_nonce(), nonce);
                assert_eq!(response.request_id(), request_id);
            }
            wire_v2::ServiceResponse::OpenEpoch(_) | wire_v2::ServiceResponse::HelperReady(_) => {
                return Err(DispatchError::Internal);
            }
        }
        Ok(())
    }

    #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
    #[test]
    fn both_v2_launch_actions_own_the_freshly_authenticated_peer() -> Result<(), DispatchError> {
        let engine = engine()?;
        let calls = AtomicUsize::new(0);
        let cases = [
            (81, wire_v2::DesktopCommand::LaunchApprovalRpcProbe),
            (82, wire_v2::DesktopCommand::LaunchSecretInputRpcProbe),
        ];

        for (identity, command) in cases {
            let nonce = open_epoch_v2(&engine, TestPeer::allowed(identity), &calls)?;
            let request_id = ServiceRequestId::new(
                [u8::try_from(identity).map_err(|_| DispatchError::Internal)?; 16],
            )
            .map_err(|_| DispatchError::Internal)?;
            let request = wire_v2::DesktopCommandRequest::new(nonce, request_id, command);
            let frame = request_frame_v2(&wire_v2::ServiceRequest::DesktopCommand(request))?;
            let outcome = engine.exchange_v2_desktop_with(&frame, || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(TestPeer::allowed(identity))
            })?;
            let DesktopV2Dispatch::Launch(action) = outcome else {
                return Err(DispatchError::Internal);
            };
            let (current_peer, pending_completion) = action.into_parts();
            assert_eq!(current_peer, TestPeer::allowed(identity));
            assert_eq!(pending_completion.request(), &request);
            let response = pending_completion.complete(wire_v2::DesktopResult::Unavailable)?;
            response_v2(&response)?
                .ensure_correlates_with(&wire_v2::ServiceRequest::DesktopCommand(request))
                .map_err(|_| DispatchError::Internal)?;
        }
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        Ok(())
    }

    #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
    #[test]
    fn desktop_helper_ready_is_authentication_denied_before_epoch_consumption()
    -> Result<(), DispatchError> {
        let engine = engine()?;
        let calls = AtomicUsize::new(0);
        let nonce = open_epoch_v2(&engine, TestPeer::allowed(91), &calls)?;
        let helper_request_id =
            ServiceRequestId::new([0x92; 16]).map_err(|_| DispatchError::Internal)?;
        let helper = wire_v2::ServiceRequest::HelperReady(wire_v2::HelperReadyRequest::new(
            nonce,
            helper_request_id,
        ));
        let helper_frame = request_frame_v2(&helper)?;
        assert!(matches!(
            engine.exchange_v2_desktop_with(&helper_frame, || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(TestPeer::allowed(91))
            }),
            Err(DispatchError::Authentication)
        ));

        let status_request_id =
            ServiceRequestId::new([0x93; 16]).map_err(|_| DispatchError::Internal)?;
        let status = wire_v2::ServiceRequest::DesktopCommand(wire_v2::DesktopCommandRequest::new(
            nonce,
            status_request_id,
            wire_v2::DesktopCommand::Status,
        ));
        let status_frame = request_frame_v2(&status)?;
        let outcome = engine.exchange_v2_desktop_with(&status_frame, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(TestPeer::allowed(91))
        })?;
        let decoded = response_v2(&immediate_v2(&outcome)?)?;
        decoded
            .ensure_correlates_with(&status)
            .map_err(|_| DispatchError::Internal)?;
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        Ok(())
    }

    #[test]
    fn manager_authenticates_exactly_once_before_parsing() -> Result<(), DispatchError> {
        let engine = engine()?;
        let calls = AtomicUsize::new(0);
        let malformed =
            RpcFrame::from_payload(b"not a wire frame").map_err(|_| DispatchError::Internal)?;
        assert_eq!(
            engine.exchange_with(&malformed, || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(TestPeer::allowed(1))
            }),
            Err(DispatchError::Malformed)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        assert_eq!(
            engine.exchange_with(&malformed, || {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(AuthenticationFailure::Denied)
            }),
            Err(DispatchError::Authentication)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
    #[test]
    fn malformed_v2_input_authenticates_once_and_yields_no_action() -> Result<(), DispatchError> {
        let engine = engine()?;
        let calls = AtomicUsize::new(0);
        let malformed = RpcFrame::from_payload(b"YWKASV02").map_err(|_| DispatchError::Internal)?;
        assert!(matches!(
            engine.exchange_v2_desktop_with(&malformed, || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(TestPeer::allowed(101))
            }),
            Err(DispatchError::Malformed)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        assert!(matches!(
            engine.exchange_v2_desktop_with(&malformed, || {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(AuthenticationFailure::Denied)
            }),
            Err(DispatchError::Authentication)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
    #[test]
    fn cross_version_epoch_attempts_are_terminal_in_both_directions() -> Result<(), DispatchError> {
        let engine = engine()?;
        let calls = AtomicUsize::new(0);

        let v1_nonce = open_epoch(&engine, TestPeer::allowed(111), &calls)?;
        let v2_request_id =
            ServiceRequestId::new([0x70; 16]).map_err(|_| DispatchError::Internal)?;
        let v2_with_v1_nonce =
            wire_v2::ServiceRequest::DesktopCommand(wire_v2::DesktopCommandRequest::new(
                v1_nonce,
                v2_request_id,
                wire_v2::DesktopCommand::Status,
            ));
        let v2_frame = request_frame_v2(&v2_with_v1_nonce)?;
        assert!(matches!(
            engine.exchange_v2_desktop_with(&v2_frame, || Ok(TestPeer::allowed(111))),
            Err(DispatchError::Epoch)
        ));

        let v1_request_id =
            ServiceRequestId::new([0x71; 16]).map_err(|_| DispatchError::Internal)?;
        let v1_with_v1_nonce = ServiceRequest::Command(ServiceCommandRequest::new(
            v1_nonce,
            v1_request_id,
            ServiceCommand::Status,
        ));
        assert_eq!(
            engine.exchange_with(&request_frame(&v1_with_v1_nonce)?, || {
                Ok(TestPeer::allowed(111))
            }),
            Err(DispatchError::Epoch)
        );

        let v2_nonce = open_epoch_v2(&engine, TestPeer::allowed(112), &calls)?;
        let v1_with_v2_nonce = ServiceRequest::Command(ServiceCommandRequest::new(
            v2_nonce,
            v1_request_id,
            ServiceCommand::Status,
        ));
        assert_eq!(
            engine.exchange_with(&request_frame(&v1_with_v2_nonce)?, || {
                Ok(TestPeer::allowed(112))
            }),
            Err(DispatchError::Epoch)
        );

        let v2_with_v2_nonce =
            wire_v2::ServiceRequest::DesktopCommand(wire_v2::DesktopCommandRequest::new(
                v2_nonce,
                v2_request_id,
                wire_v2::DesktopCommand::Status,
            ));
        assert!(matches!(
            engine.exchange_v2_desktop_with(&request_frame_v2(&v2_with_v2_nonce)?, || Ok(
                TestPeer::allowed(112)
            )),
            Err(DispatchError::Epoch)
        ));
        Ok(())
    }

    #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
    #[test]
    fn launch_completion_is_exactly_correlated_and_role_closed() -> Result<(), DispatchError> {
        fn require_consuming_completion_signature(
            _: fn(
                DesktopV2PendingCompletion,
                wire_v2::DesktopResult,
            ) -> Result<RpcFrame, DispatchError>,
        ) {
        }
        require_consuming_completion_signature(DesktopV2PendingCompletion::complete);

        let nonce = EpochNonce::new([0xB1; 32]).map_err(|_| DispatchError::Internal)?;
        let request_id = ServiceRequestId::new([0xB2; 16]).map_err(|_| DispatchError::Internal)?;
        let approval = wire_v2::DesktopCommandRequest::new(
            nonce,
            request_id,
            wire_v2::DesktopCommand::LaunchApprovalRpcProbe,
        );
        let secret_input = wire_v2::DesktopCommandRequest::new(
            nonce,
            request_id,
            wire_v2::DesktopCommand::LaunchSecretInputRpcProbe,
        );

        for request in [approval, secret_input] {
            let unavailable = DesktopV2PendingCompletion { request }
                .complete(wire_v2::DesktopResult::Unavailable)?;
            let response = response_v2(&unavailable)?;
            response
                .ensure_correlates_with(&wire_v2::ServiceRequest::DesktopCommand(request))
                .map_err(|_| DispatchError::Internal)?;
        }

        let approval_complete = DesktopV2PendingCompletion { request: approval }
            .complete(wire_v2::DesktopResult::ApprovalRpcProbeCompleted)?;
        response_v2(&approval_complete)?
            .ensure_correlates_with(&wire_v2::ServiceRequest::DesktopCommand(approval))
            .map_err(|_| DispatchError::Internal)?;
        let secret_complete = DesktopV2PendingCompletion {
            request: secret_input,
        }
        .complete(wire_v2::DesktopResult::SecretInputRpcProbeCompleted)?;
        response_v2(&secret_complete)?
            .ensure_correlates_with(&wire_v2::ServiceRequest::DesktopCommand(secret_input))
            .map_err(|_| DispatchError::Internal)?;

        assert_eq!(
            DesktopV2PendingCompletion { request: approval }
                .complete(wire_v2::DesktopResult::SecretInputRpcProbeCompleted),
            Err(DispatchError::Internal)
        );
        assert_eq!(
            DesktopV2PendingCompletion {
                request: secret_input,
            }
            .complete(wire_v2::DesktopResult::ApprovalRpcProbeCompleted),
            Err(DispatchError::Internal)
        );
        let status =
            wire_v2::DesktopCommandRequest::new(nonce, request_id, wire_v2::DesktopCommand::Status);
        assert_eq!(
            DesktopV2PendingCompletion { request: status }
                .complete(wire_v2::DesktopResult::Unavailable),
            Err(DispatchError::Internal)
        );
        Ok(())
    }

    #[test]
    fn wrong_peer_and_replay_map_only_to_epoch_denial() -> Result<(), DispatchError> {
        let engine = engine()?;
        let calls = AtomicUsize::new(0);
        let nonce = open_epoch(&engine, TestPeer::allowed(1), &calls)?;
        let request_id = ServiceRequestId::new([0x4D; 16]).map_err(|_| DispatchError::Internal)?;
        let request = ServiceRequest::Command(ServiceCommandRequest::new(
            nonce,
            request_id,
            ServiceCommand::Status,
        ));
        let frame = request_frame(&request)?;
        assert_eq!(
            engine.exchange_with(&frame, || Ok(TestPeer::allowed(2))),
            Err(DispatchError::Epoch)
        );
        assert_eq!(
            engine.exchange_with(&frame, || Ok(TestPeer::allowed(1))),
            Err(DispatchError::Epoch)
        );
        Ok(())
    }

    #[test]
    fn current_peer_revalidation_failure_is_internal_and_terminal() -> Result<(), DispatchError> {
        let engine = engine()?;
        let calls = AtomicUsize::new(0);
        let nonce = open_epoch(&engine, TestPeer::allowed(8), &calls)?;
        let request_id = ServiceRequestId::new([0x5E; 16]).map_err(|_| DispatchError::Internal)?;
        let frame = request_frame(&ServiceRequest::Command(ServiceCommandRequest::new(
            nonce,
            request_id,
            ServiceCommand::Status,
        )))?;
        assert_eq!(
            engine.exchange_with(&frame, || Ok(TestPeer::internally_ambiguous(8))),
            Err(DispatchError::Internal)
        );
        assert_eq!(
            engine.exchange_with(&frame, || Ok(TestPeer::allowed(8))),
            Err(DispatchError::Epoch)
        );
        Ok(())
    }

    #[test]
    fn fixed_full_and_stopping_categories_are_preserved() -> Result<(), DispatchError> {
        let engine = engine()?;
        let calls = AtomicUsize::new(0);
        for identity in 0..super::super::epoch::EPOCH_CAPACITY {
            let identity = u64::try_from(identity).map_err(|_| DispatchError::Internal)?;
            let _nonce = open_epoch(&engine, TestPeer::allowed(identity), &calls)?;
        }
        let open = request_frame(&ServiceRequest::OpenEpoch(OpenEpochRequest::new()))?;
        assert_eq!(
            engine.exchange_with(&open, || Ok(TestPeer::allowed(99))),
            Err(DispatchError::Full)
        );

        engine.stop()?;
        assert_eq!(
            engine.exchange_with(&open, || Ok(TestPeer::allowed(100))),
            Err(DispatchError::Stopping)
        );
        Ok(())
    }

    #[test]
    fn every_dispatch_category_has_one_closed_manager_mapping() {
        let mappings = [
            (DispatchError::Malformed, ManagerError::InvalidArgument),
            (DispatchError::Authentication, ManagerError::AccessDenied),
            (DispatchError::Epoch, ManagerError::AccessDenied),
            (DispatchError::Full, ManagerError::ServerTooBusy),
            (DispatchError::Stopping, ManagerError::ServerUnavailable),
            (DispatchError::Internal, ManagerError::CallFailed),
        ];
        for (dispatch, manager) in mappings {
            assert_eq!(ManagerError::from(dispatch), manager);
        }

        assert_eq!(
            map_authentication_failure(AuthenticationFailure::Internal),
            DispatchError::Internal
        );
        assert_eq!(
            map_authentication_failure(AuthenticationFailure::Denied),
            DispatchError::Authentication
        );
    }

    #[test]
    fn debug_output_contains_no_seed_peer_nonce_or_request_bytes() -> Result<(), DispatchError> {
        let engine = engine()?;
        let calls = AtomicUsize::new(0);
        let _nonce = open_epoch(&engine, TestPeer::allowed(0x6D6D), &calls)?;
        let debug = format!("{engine:?}");
        assert_eq!(debug, "DispatchEngine([REDACTED])");
        assert!(!debug.contains("109"));
        assert!(!debug.contains("28013"));
        Ok(())
    }

    #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
    #[test]
    fn v2_outcome_debug_redacts_peer_and_wire_bindings() -> Result<(), DispatchError> {
        let nonce = EpochNonce::new([0xC1; 32]).map_err(|_| DispatchError::Internal)?;
        let request_id = ServiceRequestId::new([0xC2; 16]).map_err(|_| DispatchError::Internal)?;
        let request = wire_v2::DesktopCommandRequest::new(
            nonce,
            request_id,
            wire_v2::DesktopCommand::LaunchApprovalRpcProbe,
        );
        let action = DesktopV2Launch {
            current_peer: TestPeer::allowed(49_345),
            pending_completion: DesktopV2PendingCompletion { request },
        };
        let action_debug = format!("{action:?}");
        assert_eq!(action_debug, "DesktopV2Launch([REDACTED])");
        assert!(!action_debug.contains("49345"));
        assert!(!action_debug.contains("193"));
        assert!(!action_debug.contains("194"));

        let launch_debug = format!("{:?}", DesktopV2Dispatch::Launch(action));
        assert_eq!(launch_debug, "DesktopV2Dispatch::Launch([REDACTED])");
        assert!(!launch_debug.contains("49345"));

        let pending = DesktopV2PendingCompletion { request };
        let pending_debug = format!("{pending:?}");
        assert_eq!(pending_debug, "DesktopV2PendingCompletion([REDACTED])");
        assert!(!pending_debug.contains("193"));
        assert!(!pending_debug.contains("194"));

        let response =
            wire_v2::ServiceResponse::DesktopCommand(wire_v2::DesktopCommandResponse::new(
                nonce,
                request_id,
                wire_v2::DesktopResult::Unavailable,
            ));
        let immediate = DesktopV2Dispatch::<TestPeer>::Immediate(encode_v2_response(&response)?);
        let immediate_debug = format!("{immediate:?}");
        assert_eq!(immediate_debug, "DesktopV2Dispatch::Immediate([REDACTED])");
        assert!(!immediate_debug.contains("193"));
        assert!(!immediate_debug.contains("194"));
        Ok(())
    }

    #[test]
    fn wire_error_categories_cannot_escape_dispatch() -> Result<(), DispatchError> {
        let engine = engine()?;
        let frame = RpcFrame::from_payload(&[0_u8; 20]).map_err(|_| DispatchError::Internal)?;
        assert_eq!(
            engine.exchange_with(&frame, || Ok(TestPeer::allowed(1))),
            Err(DispatchError::Malformed)
        );
        assert_eq!(
            WireError::InvalidMagic,
            key_agent_service_wire::decode_request(frame.payload())
                .err()
                .ok_or(DispatchError::Internal)?
        );
        Ok(())
    }
}
