//! Authenticated wire dispatch for the debug-only status RPC fixture.
//!
//! Every manager call authenticates exactly once through a consuming callback.
//! The separately registered RPC security callback performs its own independent
//! check before the manager is entered; that lifecycle boundary is intentionally
//! outside this pure dispatcher.

#![deny(unsafe_code)]

use std::fmt;

use key_agent_service_rpc_sys::{ManagerError, RpcFrame};
use key_agent_service_wire::{
    OpenEpochAck, ServiceCommand, ServiceRequest, ServiceResponse, ServiceStatus,
    ServiceStatusResponse, decode_request, encode_response,
};
use zeroize::Zeroizing;

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

    /// Stops this dispatcher and invalidates every outstanding epoch.
    pub(super) fn stop(&self) -> Result<(), DispatchError> {
        self.epochs.stop().map_err(map_epoch_error)
    }
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
