//! One bounded desktop V2 Approval transport probe, with no wallet authority.
//!
//! Only the explicit Windows x64 MSVC debug feature reaches this module. The
//! caller supplies no endpoint, epoch, request identifier, role, payload, or
//! timeout. A successful result describes a non-signing service transport test,
//! not an enrolled Broker, installed-service identity, or approval to sign.

#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use key_agent_service_rpc_sys::RpcFrame;
use key_agent_service_wire::ServiceRequestId;
use key_agent_service_wire::debug_v2::{
    self as wire, DesktopCommand, DesktopCommandRequest, DesktopResult, OpenEpochRequest,
    ServiceRequest, ServiceResponse,
};
use thiserror::Error;

use super::auth::preflight_current_desktop_probe;
use super::client_binding::{ClientBindingError, FixedDesktopRpcBinding};

const PROBE_LIFETIME: Duration = Duration::from_secs(25);
const OPEN_EPOCH_LIFETIME: Duration = Duration::from_secs(5);
const REQUEST_ID_BYTES: usize = 16;

/// Closed, data-free failure of the non-signing desktop transport probe.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DesktopRpcProbeError {
    /// The peer returned only the correlated unavailable result.
    #[error("non-signing service transport is unavailable")]
    Unavailable,
    /// The current token or thread is not an admissible desktop environment.
    #[error("non-signing service transport requires an admissible desktop")]
    Environment,
    /// OS randomness did not produce a usable public request identifier.
    #[error("non-signing service transport request identity is unavailable")]
    Randomness,
    /// The original monotonic deadline has expired or cannot be represented.
    #[error("non-signing service transport deadline expired")]
    Deadline,
    /// The fixed authenticated local-RPC binding or exchange failed.
    #[error("non-signing service transport exchange failed")]
    Transport,
    /// The response was malformed, miscorrelated, or not the exact completion.
    #[error("non-signing service transport response was rejected")]
    Protocol,
}

/// Runs exactly one fresh `OpenEpoch` followed by one Approval probe command.
///
/// This sends no wallet data and returns no user decision or signing authority.
/// The same process and binding perform both calls. No command is retried: the
/// service epoch is single-use even when a request fails or a reply is lost.
///
/// A synchronous local RPC call can block despite its absolute result deadline.
/// Only the standalone debug executable's process watchdog bounds that wait;
/// this library function does not terminate its caller process.
///
/// # Errors
///
/// Returns a data-free category on local preflight, randomness, fixed binding,
/// original deadline, canonical response, or exact correlation failure.
pub fn run_non_signing_service_approval_probe() -> Result<(), DesktopRpcProbeError> {
    run_with_operations(&mut WindowsDesktopProbeOperations)
}

trait DesktopProbeOperations {
    type Binding;

    fn now(&mut self) -> Result<Instant, DesktopRpcProbeError>;
    fn fill_request_id(
        &mut self,
        bytes: &mut [u8; REQUEST_ID_BYTES],
    ) -> Result<(), DesktopRpcProbeError>;
    fn preflight(&mut self) -> Result<(), DesktopRpcProbeError>;
    fn connect(&mut self) -> Result<Self::Binding, DesktopRpcProbeError>;
    fn exchange(
        &mut self,
        binding: &mut Self::Binding,
        request: &RpcFrame,
        deadline: Instant,
    ) -> Result<RpcFrame, DesktopRpcProbeError>;
}

struct WindowsDesktopProbeOperations;

impl DesktopProbeOperations for WindowsDesktopProbeOperations {
    type Binding = FixedDesktopRpcBinding;

    fn now(&mut self) -> Result<Instant, DesktopRpcProbeError> {
        Ok(Instant::now())
    }

    fn fill_request_id(
        &mut self,
        bytes: &mut [u8; REQUEST_ID_BYTES],
    ) -> Result<(), DesktopRpcProbeError> {
        getrandom::fill(bytes).map_err(|_| DesktopRpcProbeError::Randomness)
    }

    fn preflight(&mut self) -> Result<(), DesktopRpcProbeError> {
        preflight_current_desktop_probe().map_err(|_| DesktopRpcProbeError::Environment)
    }

    fn connect(&mut self) -> Result<Self::Binding, DesktopRpcProbeError> {
        FixedDesktopRpcBinding::connect().map_err(map_binding_error)
    }

    fn exchange(
        &mut self,
        binding: &mut Self::Binding,
        request: &RpcFrame,
        deadline: Instant,
    ) -> Result<RpcFrame, DesktopRpcProbeError> {
        binding
            .exchange(request, deadline)
            .map_err(map_binding_error)
    }
}

fn map_binding_error(error: ClientBindingError) -> DesktopRpcProbeError {
    match error {
        ClientBindingError::Unavailable => DesktopRpcProbeError::Transport,
        ClientBindingError::Deadline => DesktopRpcProbeError::Deadline,
    }
}

fn run_with_operations<Operations: DesktopProbeOperations>(
    operations: &mut Operations,
) -> Result<(), DesktopRpcProbeError> {
    let start = operations.now()?;
    let deadline = start
        .checked_add(PROBE_LIFETIME)
        .ok_or(DesktopRpcProbeError::Deadline)?;
    let open_deadline = start
        .checked_add(OPEN_EPOCH_LIFETIME)
        .ok_or(DesktopRpcProbeError::Deadline)?;
    // This is a public correlation value, not a seed, key, or wallet fixture.
    // Produce it before acquiring the service's short-lived single-use epoch.
    let mut bytes = [0_u8; REQUEST_ID_BYTES];
    operations.fill_request_id(&mut bytes)?;
    let request_id = ServiceRequestId::new(bytes).map_err(|_| DesktopRpcProbeError::Randomness)?;
    operations.preflight()?;
    require_live_deadline(operations, open_deadline)?;
    let mut binding = operations.connect()?;
    let result = run_bound_probe(
        operations,
        &mut binding,
        request_id,
        open_deadline,
        deadline,
    );
    // RAII also closes on every earlier error or unwind. On the successful edge
    // finish this synchronous binding cleanup before the final deadline read.
    drop(binding);
    result?;
    require_live_deadline(operations, deadline)
}

fn run_bound_probe<Operations: DesktopProbeOperations>(
    operations: &mut Operations,
    binding: &mut Operations::Binding,
    request_id: ServiceRequestId,
    open_deadline: Instant,
    deadline: Instant,
) -> Result<(), DesktopRpcProbeError> {
    let open = ServiceRequest::OpenEpoch(OpenEpochRequest::new());
    let epoch_nonce = match exchange_checked(operations, binding, &open, open_deadline)? {
        ServiceResponse::OpenEpoch(ack) => ack.epoch_nonce(),
        ServiceResponse::DesktopCommand(_) | ServiceResponse::HelperReady(_) => {
            return Err(DesktopRpcProbeError::Protocol);
        }
    };

    operations.preflight()?;
    // Conservatively finish launch admission within the original opening
    // window too. No delay or fresh lifetime is inserted after the epoch ACK.
    require_live_deadline(operations, open_deadline)?;
    let command = ServiceRequest::DesktopCommand(DesktopCommandRequest::new(
        epoch_nonce,
        request_id,
        DesktopCommand::LaunchApprovalRpcProbe,
    ));
    match exchange_checked(operations, binding, &command, deadline)? {
        ServiceResponse::DesktopCommand(response) => match response.result() {
            DesktopResult::ApprovalRpcProbeCompleted => Ok(()),
            DesktopResult::Unavailable => Err(DesktopRpcProbeError::Unavailable),
            DesktopResult::SecretInputRpcProbeCompleted => Err(DesktopRpcProbeError::Protocol),
        },
        ServiceResponse::OpenEpoch(_) | ServiceResponse::HelperReady(_) => {
            Err(DesktopRpcProbeError::Protocol)
        }
    }
}

fn exchange_checked<Operations: DesktopProbeOperations>(
    operations: &mut Operations,
    binding: &mut Operations::Binding,
    request: &ServiceRequest,
    deadline: Instant,
) -> Result<ServiceResponse, DesktopRpcProbeError> {
    let frame = RpcFrame::from_payload(&wire::encode_request(request))
        .map_err(|_| DesktopRpcProbeError::Protocol)?;
    require_live_deadline(operations, deadline)?;
    let result = operations.exchange(binding, &frame, deadline);
    // Check even failed exchanges so a late response cannot escape through an
    // alternate result path. Native RPC faults never cross the existing shim.
    require_live_deadline(operations, deadline)?;
    let frame = result?;
    if !frame.is_canonical() {
        return Err(DesktopRpcProbeError::Protocol);
    }
    let response =
        wire::decode_response(frame.payload()).map_err(|_| DesktopRpcProbeError::Protocol)?;
    response
        .ensure_correlates_with(request)
        .map_err(|_| DesktopRpcProbeError::Protocol)?;
    Ok(response)
}

fn require_live_deadline<Operations: DesktopProbeOperations>(
    operations: &mut Operations,
    deadline: Instant,
) -> Result<(), DesktopRpcProbeError> {
    if operations.now()? >= deadline {
        return Err(DesktopRpcProbeError::Deadline);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use key_agent_service_wire::EpochNonce;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;
    use wire::{DesktopCommandResponse, HelperReadyAck, OpenEpochAck};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        Now,
        Random,
        Preflight,
        Connect,
        Open,
        Launch,
        Drop,
    }

    struct FakeBinding {
        events: Rc<RefCell<Vec<Event>>>,
    }

    impl Drop for FakeBinding {
        fn drop(&mut self) {
            self.events.borrow_mut().push(Event::Drop);
        }
    }

    #[derive(Clone, Copy)]
    enum Reply {
        Canonical,
        Unavailable,
        WrongEpoch,
        WrongRequest,
        WrongCompletion,
        OpenReplay,
        HelperReady,
        Empty,
        Truncated,
        Trailing,
        Corrupt,
        Transport,
    }

    struct FakeOperations {
        start: Instant,
        clock: Cell<Instant>,
        events: Rc<RefCell<Vec<Event>>>,
        requests: Vec<(ServiceRequest, Instant)>,
        replies: [Reply; 2],
        zero_random: bool,
        fail_at: Option<usize>,
        panic_at: Option<usize>,
        advance_at: Option<(usize, Duration)>,
    }

    impl FakeOperations {
        fn new() -> Self {
            let start = Instant::now();
            Self {
                start,
                clock: Cell::new(start),
                events: Rc::new(RefCell::new(Vec::new())),
                requests: Vec::new(),
                replies: [Reply::Canonical; 2],
                zero_random: false,
                fail_at: None,
                panic_at: None,
                advance_at: None,
            }
        }

        fn step(
            &self,
            event: Event,
            error: DesktopRpcProbeError,
        ) -> Result<(), DesktopRpcProbeError> {
            let index = self.events.borrow().len();
            self.events.borrow_mut().push(event);
            if let Some((at, elapsed)) = self.advance_at
                && at == index
            {
                self.clock.set(self.start + elapsed);
            }
            if self.panic_at == Some(index) {
                std::panic::resume_unwind(Box::new(()));
            }
            if self.fail_at == Some(index) {
                return Err(error);
            }
            Ok(())
        }

        fn events(&self) -> Vec<Event> {
            self.events.borrow().clone()
        }

        fn drops(&self) -> usize {
            self.events
                .borrow()
                .iter()
                .filter(|event| **event == Event::Drop)
                .count()
        }
    }

    fn epoch() -> Result<EpochNonce, DesktopRpcProbeError> {
        EpochNonce::new([0x31; 32]).map_err(|_| DesktopRpcProbeError::Protocol)
    }

    fn public_request_id() -> Result<ServiceRequestId, DesktopRpcProbeError> {
        ServiceRequestId::new([0x71; REQUEST_ID_BYTES]).map_err(|_| DesktopRpcProbeError::Protocol)
    }

    fn response_frame(
        request: &ServiceRequest,
        reply: Reply,
    ) -> Result<RpcFrame, DesktopRpcProbeError> {
        if matches!(reply, Reply::Transport) {
            return Err(DesktopRpcProbeError::Transport);
        }
        let response = match request {
            ServiceRequest::OpenEpoch(_) => ServiceResponse::OpenEpoch(OpenEpochAck::new(epoch()?)),
            ServiceRequest::DesktopCommand(command) => {
                let epoch_nonce = if matches!(reply, Reply::WrongEpoch) {
                    EpochNonce::new([0x32; 32]).map_err(|_| DesktopRpcProbeError::Protocol)?
                } else {
                    command.epoch_nonce()
                };
                let request_id = if matches!(reply, Reply::WrongRequest) {
                    ServiceRequestId::new([0x72; REQUEST_ID_BYTES])
                        .map_err(|_| DesktopRpcProbeError::Protocol)?
                } else {
                    command.request_id()
                };
                let result = match reply {
                    Reply::Unavailable => DesktopResult::Unavailable,
                    Reply::WrongCompletion => DesktopResult::SecretInputRpcProbeCompleted,
                    _ => DesktopResult::ApprovalRpcProbeCompleted,
                };
                ServiceResponse::DesktopCommand(DesktopCommandResponse::new(
                    epoch_nonce,
                    request_id,
                    result,
                ))
            }
            ServiceRequest::HelperReady(_) => return Err(DesktopRpcProbeError::Protocol),
        };
        let response = match reply {
            Reply::OpenReplay => ServiceResponse::OpenEpoch(OpenEpochAck::new(epoch()?)),
            Reply::HelperReady => {
                ServiceResponse::HelperReady(HelperReadyAck::new(epoch()?, public_request_id()?))
            }
            _ => response,
        };
        let mut bytes = wire::encode_response(&response);
        match reply {
            Reply::Empty => bytes.clear(),
            Reply::Truncated => {
                bytes.pop();
            }
            Reply::Trailing => bytes.push(0),
            Reply::Corrupt => bytes[0] ^= 1,
            _ => {}
        }
        // A 73-byte launch response is rejected by the outer frame before it
        // could become an RPC result; the 53-byte open trailing case exercises
        // the canonical V2 decoder itself.
        RpcFrame::from_payload(&bytes).map_err(|_| DesktopRpcProbeError::Protocol)
    }

    impl DesktopProbeOperations for FakeOperations {
        type Binding = FakeBinding;

        fn now(&mut self) -> Result<Instant, DesktopRpcProbeError> {
            self.step(Event::Now, DesktopRpcProbeError::Deadline)?;
            Ok(self.clock.get())
        }

        fn fill_request_id(
            &mut self,
            bytes: &mut [u8; REQUEST_ID_BYTES],
        ) -> Result<(), DesktopRpcProbeError> {
            self.step(Event::Random, DesktopRpcProbeError::Randomness)?;
            bytes.fill(if self.zero_random { 0 } else { 0x71 });
            Ok(())
        }

        fn preflight(&mut self) -> Result<(), DesktopRpcProbeError> {
            self.step(Event::Preflight, DesktopRpcProbeError::Environment)
        }

        fn connect(&mut self) -> Result<Self::Binding, DesktopRpcProbeError> {
            self.step(Event::Connect, DesktopRpcProbeError::Transport)?;
            Ok(FakeBinding {
                events: Rc::clone(&self.events),
            })
        }

        fn exchange(
            &mut self,
            _binding: &mut Self::Binding,
            request: &RpcFrame,
            deadline: Instant,
        ) -> Result<RpcFrame, DesktopRpcProbeError> {
            assert!(request.is_canonical());
            let request = wire::decode_request(request.payload())
                .map_err(|_| DesktopRpcProbeError::Protocol)?;
            let index = self.requests.len();
            let event = match request {
                ServiceRequest::OpenEpoch(_) => Event::Open,
                ServiceRequest::DesktopCommand(command) => {
                    assert_eq!(command.command(), DesktopCommand::LaunchApprovalRpcProbe);
                    Event::Launch
                }
                ServiceRequest::HelperReady(_) => return Err(DesktopRpcProbeError::Protocol),
            };
            self.requests.push((request, deadline));
            self.step(event, DesktopRpcProbeError::Transport)?;
            let reply = *self
                .replies
                .get(index)
                .ok_or(DesktopRpcProbeError::Protocol)?;
            response_frame(&request, reply)
        }
    }

    fn successful_events() -> Vec<Event> {
        vec![
            Event::Now,
            Event::Random,
            Event::Preflight,
            Event::Now,
            Event::Connect,
            Event::Now,
            Event::Open,
            Event::Now,
            Event::Preflight,
            Event::Now,
            Event::Now,
            Event::Launch,
            Event::Now,
            Event::Drop,
            Event::Now,
        ]
    }

    #[test]
    fn probe_has_one_fixed_non_signing_command_and_original_deadlines()
    -> Result<(), DesktopRpcProbeError> {
        let mut operations = FakeOperations::new();
        run_with_operations(&mut operations)?;
        assert_eq!(operations.events(), successful_events());
        assert_eq!(operations.requests.len(), 2);
        assert_eq!(
            operations.requests[0].1,
            operations.start + OPEN_EPOCH_LIFETIME
        );
        assert_eq!(operations.requests[1].1, operations.start + PROBE_LIFETIME);
        assert_eq!(
            operations.requests[0].0,
            ServiceRequest::OpenEpoch(OpenEpochRequest::new())
        );
        assert_eq!(
            operations.requests[1].0,
            ServiceRequest::DesktopCommand(DesktopCommandRequest::new(
                epoch()?,
                public_request_id()?,
                DesktopCommand::LaunchApprovalRpcProbe
            ))
        );
        assert_eq!(operations.drops(), 1);
        assert_eq!(PROBE_LIFETIME, Duration::from_secs(25));
        assert_eq!(OPEN_EPOCH_LIFETIME, Duration::from_secs(5));
        Ok(())
    }

    #[test]
    fn zero_random_request_id_fails_before_preflight_or_binding() {
        let mut operations = FakeOperations::new();
        operations.zero_random = true;
        assert_eq!(
            run_with_operations(&mut operations),
            Err(DesktopRpcProbeError::Randomness)
        );
        assert_eq!(operations.events(), vec![Event::Now, Event::Random]);
        assert_eq!(operations.drops(), 0);
    }

    #[test]
    fn every_fallible_operation_fails_closed_without_retry_and_drops_owned_binding() {
        for (index, event) in successful_events().into_iter().enumerate() {
            if event == Event::Drop {
                continue;
            }
            let mut operations = FakeOperations::new();
            operations.fail_at = Some(index);
            assert!(run_with_operations(&mut operations).is_err());
            assert_eq!(operations.drops(), usize::from(index > 4));
            assert!(operations.requests.len() <= 2);
            let actual = operations.events();
            let expected = successful_events();
            let prefix_len = index + 1;
            assert_eq!(actual[..prefix_len], expected[..prefix_len]);
            // exchange errors still observe the original deadline once before
            // unwinding; no second request or preflight follows the failure.
            let suffix = &actual[prefix_len..];
            assert!(
                suffix
                    .iter()
                    .all(|event| matches!(event, Event::Now | Event::Drop))
            );
        }
    }

    #[test]
    fn unwind_at_every_fallible_operation_still_drops_owned_binding() {
        for (index, event) in successful_events().into_iter().enumerate() {
            if event == Event::Drop {
                continue;
            }
            let mut operations = FakeOperations::new();
            operations.panic_at = Some(index);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_with_operations(&mut operations)
            }));
            assert!(result.is_err());
            assert_eq!(operations.drops(), usize::from(index > 4));
            assert!(operations.requests.len() <= 2);
        }
    }

    #[test]
    fn both_preflights_precede_their_call_and_failure_never_launches() {
        for index in [2, 8] {
            let mut operations = FakeOperations::new();
            operations.fail_at = Some(index);
            assert_eq!(
                run_with_operations(&mut operations),
                Err(DesktopRpcProbeError::Environment)
            );
            assert!(!operations.events().contains(&Event::Launch));
            assert_eq!(operations.requests.len(), usize::from(index == 8));
        }
    }

    #[test]
    fn every_original_deadline_edge_rejects_equality_and_lateness() {
        for (index, lifetime) in [
            (3, OPEN_EPOCH_LIFETIME),
            (5, OPEN_EPOCH_LIFETIME),
            (7, OPEN_EPOCH_LIFETIME),
            (9, OPEN_EPOCH_LIFETIME),
            (10, PROBE_LIFETIME),
            (12, PROBE_LIFETIME),
            (14, PROBE_LIFETIME),
        ] {
            for extra in [Duration::ZERO, Duration::from_millis(1)] {
                let mut operations = FakeOperations::new();
                operations.advance_at = Some((index, lifetime + extra));
                assert_eq!(
                    run_with_operations(&mut operations),
                    Err(DesktopRpcProbeError::Deadline)
                );
                assert_eq!(operations.drops(), usize::from(index > 4));
            }
        }
    }

    #[test]
    fn time_spent_in_preflight_and_connect_never_restarts_opening_window() {
        for index in [2, 4, 8] {
            let mut operations = FakeOperations::new();
            operations.advance_at = Some((index, OPEN_EPOCH_LIFETIME));
            assert_eq!(
                run_with_operations(&mut operations),
                Err(DesktopRpcProbeError::Deadline)
            );
            assert!(!operations.events().contains(&Event::Launch));
        }
    }

    #[test]
    fn timely_completion_must_still_pass_the_post_cleanup_deadline()
    -> Result<(), DesktopRpcProbeError> {
        let mut operations = FakeOperations::new();
        let timely = PROBE_LIFETIME
            .checked_sub(Duration::from_millis(1))
            .ok_or(DesktopRpcProbeError::Deadline)?;
        operations.advance_at = Some((12, timely));
        assert_eq!(run_with_operations(&mut operations), Ok(()));
        assert_eq!(operations.events().last(), Some(&Event::Now));
        assert_eq!(operations.drops(), 1);

        let mut operations = FakeOperations::new();
        operations.advance_at = Some((14, PROBE_LIFETIME));
        assert_eq!(
            run_with_operations(&mut operations),
            Err(DesktopRpcProbeError::Deadline)
        );
        assert_eq!(operations.drops(), 1);
        Ok(())
    }

    #[test]
    fn malformed_opening_responses_never_reach_the_launch() {
        for reply in [
            Reply::HelperReady,
            Reply::Empty,
            Reply::Truncated,
            Reply::Trailing,
            Reply::Corrupt,
        ] {
            let mut operations = FakeOperations::new();
            operations.replies[0] = reply;
            assert_eq!(
                run_with_operations(&mut operations),
                Err(DesktopRpcProbeError::Protocol)
            );
            assert_eq!(operations.requests.len(), 1);
            assert_eq!(operations.drops(), 1);
        }
    }

    #[test]
    fn launch_rejects_replay_wrong_bindings_variants_and_noncanonical_frames() {
        for reply in [
            Reply::WrongEpoch,
            Reply::WrongRequest,
            Reply::WrongCompletion,
            Reply::OpenReplay,
            Reply::HelperReady,
            Reply::Empty,
            Reply::Truncated,
            Reply::Trailing,
            Reply::Corrupt,
        ] {
            let mut operations = FakeOperations::new();
            operations.replies[1] = reply;
            assert_eq!(
                run_with_operations(&mut operations),
                Err(DesktopRpcProbeError::Protocol)
            );
            assert_eq!(operations.requests.len(), 2);
            assert_eq!(operations.drops(), 1);
        }
    }

    #[test]
    fn correlated_unavailable_and_transport_failure_never_become_success_or_retry() {
        let mut unavailable = FakeOperations::new();
        unavailable.replies[1] = Reply::Unavailable;
        assert_eq!(
            run_with_operations(&mut unavailable),
            Err(DesktopRpcProbeError::Unavailable)
        );
        assert_eq!(unavailable.requests.len(), 2);
        assert_eq!(unavailable.drops(), 1);
        for index in 0..2 {
            let mut operations = FakeOperations::new();
            operations.replies[index] = Reply::Transport;
            assert_eq!(
                run_with_operations(&mut operations),
                Err(DesktopRpcProbeError::Transport)
            );
            assert_eq!(operations.requests.len(), index + 1);
            assert_eq!(operations.drops(), 1);
        }
    }

    #[test]
    fn late_transport_errors_still_observe_original_deadline() {
        for (reply_index, now_index, lifetime) in
            [(0, 7, OPEN_EPOCH_LIFETIME), (1, 12, PROBE_LIFETIME)]
        {
            let mut operations = FakeOperations::new();
            operations.replies[reply_index] = Reply::Transport;
            operations.advance_at = Some((now_index, lifetime));
            assert_eq!(
                run_with_operations(&mut operations),
                Err(DesktopRpcProbeError::Deadline)
            );
            assert_eq!(operations.drops(), 1);
        }
    }

    #[test]
    fn public_errors_and_native_mapping_are_data_free() {
        for error in [
            DesktopRpcProbeError::Unavailable,
            DesktopRpcProbeError::Environment,
            DesktopRpcProbeError::Randomness,
            DesktopRpcProbeError::Deadline,
            DesktopRpcProbeError::Transport,
            DesktopRpcProbeError::Protocol,
        ] {
            assert!(
                error
                    .to_string()
                    .starts_with("non-signing service transport")
            );
            assert!(!format!("{error:?}").contains('('));
        }
        assert_eq!(
            map_binding_error(ClientBindingError::Unavailable),
            DesktopRpcProbeError::Transport
        );
        assert_eq!(
            map_binding_error(ClientBindingError::Deadline),
            DesktopRpcProbeError::Deadline
        );
    }
}
