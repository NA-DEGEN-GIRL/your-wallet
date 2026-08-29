//! Bounded one-at-a-time launch coordinator for the debug-only V2 probes.
//!
//! RPC manager threads never hold dispatcher or expected-peer locks while a
//! helper runs. One dedicated worker owns the restricted-service-token proof,
//! admits one occupied launch across its worker and one-slot transport, accepts
//! no queued launch behind that occupied attempt, and settles every accepted
//! completion exactly once as either the matching probe result or correlated
//! `Unavailable`.

#![forbid(unsafe_code)]

use core::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc::{Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError, sync_channel},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use key_agent_service_rpc_sys::RpcFrame;
use key_agent_service_wire::debug_v2::{DesktopCommandRequest, DesktopResult};
use thiserror::Error;

use super::auth::AuthenticatedRpcClient;
use super::dispatch::{DesktopV2Launch, DesktopV2PendingCompletion, DispatchError};
use crate::key_agent_service_launch::{ServiceHelperAdmission, run_service_helper_rpc_probe};
use crate::key_agent_service_token::ServiceTokenFixtureProof;

// The separate occupied CAS prevents this slot from queuing behind active work.
const COORDINATOR_QUEUE_CAPACITY: usize = 1;
const COORDINATOR_RESPONSE_TIMEOUT: Duration = Duration::from_secs(20);
const COORDINATOR_RESPONSE_POLL_INTERVAL: Duration = Duration::from_millis(50);
const COORDINATOR_THREAD_NAME: &str = "yw-key-agent-service-launch";

/// Data-free coordinator lifecycle failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(super) enum ServiceProbeCoordinatorError {
    #[error("service probe coordinator thread is unavailable")]
    Thread,
}

enum CoordinatorCommand {
    Launch(Box<CoordinatorLaunch>),
    Stop,
}

struct CoordinatorLaunch {
    desktop: AuthenticatedRpcClient,
    request: DesktopCommandRequest,
    reply: SyncSender<DesktopResult>,
    occupancy: LaunchOccupancy,
}

/// Cloneable RPC-side submission edge with shared fail-closed stop state.
#[derive(Clone)]
pub(super) struct ServiceProbeCoordinatorClient {
    sender: SyncSender<CoordinatorCommand>,
    stopping: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    occupied: Arc<AtomicBool>,
}

impl ServiceProbeCoordinatorClient {
    /// Submits one move-only launch without ever waiting for queue capacity.
    ///
    /// The manager thread retains the one-shot completion capability. Only the
    /// authenticated desktop authority and an exact copy of its already-bound
    /// request cross the queue. Stop, timeout, disconnect, and worker failure
    /// therefore all settle the same local capability as correlated
    /// `Unavailable`; no worker can emit a second wire response.
    pub(super) fn complete_launch(
        &self,
        launch: DesktopV2Launch<AuthenticatedRpcClient>,
    ) -> Result<RpcFrame, DispatchError> {
        let (desktop, completion) = launch.into_parts();
        let request = *completion.request();
        let Some(occupancy) = self.try_reserve_launch() else {
            drop(desktop);
            return self.complete_locally(completion, DesktopResult::Unavailable);
        };

        let (reply, response) = sync_channel(1);
        let command = CoordinatorCommand::Launch(Box::new(CoordinatorLaunch {
            desktop,
            request,
            reply,
            occupancy,
        }));
        let result = match self.sender.try_send(command) {
            Ok(()) => self.wait_for_result(&response),
            Err(TrySendError::Full(command)) => reject_unsent(command),
            Err(TrySendError::Disconnected(command)) => {
                self.failed.store(true, Ordering::Release);
                reject_unsent(command)
            }
        };
        let result = if self.stopping.load(Ordering::Acquire) || self.failed.load(Ordering::Acquire)
        {
            DesktopResult::Unavailable
        } else {
            result
        };
        self.complete_locally(completion, result)
    }

    /// Closes admission before RPC rundown and wakes an idle coordinator.
    pub(super) fn begin_stop(&self) {
        if self.stopping.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = self.sender.try_send(CoordinatorCommand::Stop);
    }

    #[must_use]
    pub(super) fn has_failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    fn wait_for_result(&self, response: &Receiver<DesktopResult>) -> DesktopResult {
        let Some(deadline) = Instant::now().checked_add(COORDINATOR_RESPONSE_TIMEOUT) else {
            self.failed.store(true, Ordering::Release);
            return DesktopResult::Unavailable;
        };
        self.wait_for_result_until(response, deadline)
    }

    fn wait_for_result_until(
        &self,
        response: &Receiver<DesktopResult>,
        deadline: Instant,
    ) -> DesktopResult {
        loop {
            if self.stopping.load(Ordering::Acquire) {
                return DesktopResult::Unavailable;
            }
            if self.failed.load(Ordering::Acquire) {
                return DesktopResult::Unavailable;
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return DesktopResult::Unavailable;
            };
            let slice = remaining.min(COORDINATOR_RESPONSE_POLL_INTERVAL);
            match response.recv_timeout(slice) {
                Ok(result)
                    if !self.stopping.load(Ordering::Acquire)
                        && !self.failed.load(Ordering::Acquire) =>
                {
                    return result;
                }
                Ok(_) => return DesktopResult::Unavailable,
                Err(RecvTimeoutError::Timeout) => {
                    if remaining.is_zero() {
                        return DesktopResult::Unavailable;
                    }
                }
                Err(RecvTimeoutError::Disconnected) => {
                    self.failed.store(true, Ordering::Release);
                    return DesktopResult::Unavailable;
                }
            }
        }
    }

    fn try_reserve_launch(&self) -> Option<LaunchOccupancy> {
        if self.stopping.load(Ordering::Acquire) || self.failed.load(Ordering::Acquire) {
            return None;
        }
        self.occupied
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        let occupancy = LaunchOccupancy::new(Arc::clone(&self.occupied));
        if self.stopping.load(Ordering::Acquire) || self.failed.load(Ordering::Acquire) {
            drop(occupancy);
            return None;
        }
        Some(occupancy)
    }

    fn complete_locally(
        &self,
        completion: DesktopV2PendingCompletion,
        result: DesktopResult,
    ) -> Result<RpcFrame, DispatchError> {
        let completed = completion.complete(result);
        if completed.is_err() {
            self.failed.store(true, Ordering::Release);
        }
        completed
    }
}

struct LaunchOccupancy {
    occupied: Arc<AtomicBool>,
}

impl LaunchOccupancy {
    fn new(occupied: Arc<AtomicBool>) -> Self {
        Self { occupied }
    }
}

impl Drop for LaunchOccupancy {
    fn drop(&mut self) {
        if !self.occupied.swap(false, Ordering::AcqRel) {
            std::process::abort();
        }
    }
}

impl fmt::Debug for ServiceProbeCoordinatorClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServiceProbeCoordinatorClient([REDACTED])")
    }
}

/// Server-context-owned coordinator thread and token proof.
pub(super) struct ServiceProbeCoordinator {
    client: ServiceProbeCoordinatorClient,
    thread: Option<JoinHandle<()>>,
}

impl ServiceProbeCoordinator {
    pub(super) fn start(
        service_token: ServiceTokenFixtureProof,
        admission: ServiceHelperAdmission,
    ) -> Result<Self, ServiceProbeCoordinatorError> {
        let (sender, receiver) = sync_channel(COORDINATOR_QUEUE_CAPACITY);
        let stopping = Arc::new(AtomicBool::new(false));
        let failed = Arc::new(AtomicBool::new(false));
        let occupied = Arc::new(AtomicBool::new(false));
        let worker_stopping = Arc::clone(&stopping);
        let worker_failed = Arc::clone(&failed);
        let thread = thread::Builder::new()
            .name(COORDINATOR_THREAD_NAME.to_owned())
            .spawn(move || {
                let mut failure_latch = CoordinatorFailureLatch::new(&worker_failed);
                coordinator_loop(
                    service_token,
                    &admission,
                    &receiver,
                    &worker_stopping,
                    &worker_failed,
                );
                failure_latch.disarm();
            })
            .map_err(|_| ServiceProbeCoordinatorError::Thread)?;
        Ok(Self {
            client: ServiceProbeCoordinatorClient {
                sender,
                stopping,
                failed,
                occupied,
            },
            thread: Some(thread),
        })
    }

    pub(super) fn client(&self) -> ServiceProbeCoordinatorClient {
        self.client.clone()
    }

    pub(super) fn stop_and_drain(mut self) -> Result<(), ServiceProbeCoordinatorError> {
        self.client.begin_stop();
        self.join()
    }

    fn join(&mut self) -> Result<(), ServiceProbeCoordinatorError> {
        let Some(thread) = self.thread.take() else {
            return Err(ServiceProbeCoordinatorError::Thread);
        };
        thread
            .join()
            .map_err(|_| ServiceProbeCoordinatorError::Thread)
    }
}

struct CoordinatorFailureLatch<'flag> {
    failed: &'flag AtomicBool,
    armed: bool,
}

impl<'flag> CoordinatorFailureLatch<'flag> {
    const fn new(failed: &'flag AtomicBool) -> Self {
        Self {
            failed,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CoordinatorFailureLatch<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.failed.store(true, Ordering::Release);
        }
    }
}

impl fmt::Debug for ServiceProbeCoordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServiceProbeCoordinator([REDACTED])")
    }
}

impl Drop for ServiceProbeCoordinator {
    fn drop(&mut self) {
        if self.thread.is_none() {
            return;
        }
        self.client.begin_stop();
        if self.join().is_err() {
            std::process::abort();
        }
    }
}

fn coordinator_loop(
    mut service_token: ServiceTokenFixtureProof,
    admission: &ServiceHelperAdmission,
    receiver: &Receiver<CoordinatorCommand>,
    stopping: &AtomicBool,
    failed: &AtomicBool,
) {
    loop {
        if stopping.load(Ordering::Acquire) || failed.load(Ordering::Acquire) {
            drain_unavailable(receiver);
            return;
        }
        let command = match receiver.recv_timeout(COORDINATOR_RESPONSE_POLL_INTERVAL) {
            Ok(command) => command,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        match command {
            CoordinatorCommand::Stop => {
                drain_unavailable(receiver);
                return;
            }
            launch @ CoordinatorCommand::Launch(_) => {
                if stopping.load(Ordering::Acquire) || failed.load(Ordering::Acquire) {
                    reply_command_unavailable(launch);
                } else {
                    complete_command(launch, &mut service_token, admission, stopping, failed);
                }
            }
        }
        if stopping.load(Ordering::Acquire) || failed.load(Ordering::Acquire) {
            drain_unavailable(receiver);
            return;
        }
    }
}

fn complete_command(
    command: CoordinatorCommand,
    service_token: &mut ServiceTokenFixtureProof,
    admission: &ServiceHelperAdmission,
    stopping: &AtomicBool,
    failed: &AtomicBool,
) {
    let CoordinatorCommand::Launch(launch) = command else {
        return;
    };
    let CoordinatorLaunch {
        desktop,
        request,
        reply,
        occupancy: _occupancy,
    } = *launch;
    let result = match run_service_helper_rpc_probe(service_token, desktop, request, admission) {
        Ok(result) if !stopping.load(Ordering::Acquire) => result,
        Ok(_) => DesktopResult::Unavailable,
        Err(error) => {
            if error.is_fatal() {
                failed.store(true, Ordering::Release);
            }
            DesktopResult::Unavailable
        }
    };
    let _ = reply.send(result);
}

fn drain_unavailable(receiver: &Receiver<CoordinatorCommand>) {
    loop {
        match receiver.try_recv() {
            Ok(command) => {
                reply_command_unavailable(command);
            }
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => return,
        }
    }
}

fn reply_command_unavailable(command: CoordinatorCommand) {
    match command {
        CoordinatorCommand::Launch(launch) => {
            let CoordinatorLaunch {
                desktop,
                reply,
                request: _,
                occupancy: _occupancy,
            } = *launch;
            drop(desktop);
            let _ = reply.send(DesktopResult::Unavailable);
        }
        CoordinatorCommand::Stop => {}
    }
}

fn reject_unsent(command: CoordinatorCommand) -> DesktopResult {
    match command {
        CoordinatorCommand::Launch(launch) => {
            let CoordinatorLaunch {
                desktop,
                request: _,
                reply: _,
                occupancy: _occupancy,
            } = *launch;
            drop(desktop);
            DesktopResult::Unavailable
        }
        CoordinatorCommand::Stop => DesktopResult::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_client() -> (ServiceProbeCoordinatorClient, Receiver<CoordinatorCommand>) {
        let (sender, receiver) = sync_channel(COORDINATOR_QUEUE_CAPACITY);
        (
            ServiceProbeCoordinatorClient {
                sender,
                stopping: Arc::new(AtomicBool::new(false)),
                failed: Arc::new(AtomicBool::new(false)),
                occupied: Arc::new(AtomicBool::new(false)),
            },
            receiver,
        )
    }

    #[test]
    fn queue_and_reply_bounds_are_fixed() {
        assert_eq!(COORDINATOR_QUEUE_CAPACITY, 1);
        assert_eq!(COORDINATOR_RESPONSE_TIMEOUT, Duration::from_secs(20));
        assert_eq!(
            COORDINATOR_RESPONSE_POLL_INTERVAL,
            Duration::from_millis(50)
        );
    }

    #[test]
    fn failure_latch_marks_only_an_unwound_worker() {
        let (client, receiver) = test_client();
        let failed = Arc::clone(&client.failed);
        let unwound = std::panic::catch_unwind(|| {
            let _latch = CoordinatorFailureLatch::new(failed.as_ref());
            std::panic::resume_unwind(Box::new(()));
        });
        assert!(unwound.is_err());
        assert!(client.has_failed());
        assert!(client.try_reserve_launch().is_none());
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));

        failed.store(false, Ordering::Release);
        {
            let mut latch = CoordinatorFailureLatch::new(failed.as_ref());
            latch.disarm();
        }
        assert!(!failed.load(Ordering::Acquire));
    }

    #[test]
    fn stop_wins_over_a_ready_success_result() {
        let (client, _receiver) = test_client();
        client.stopping.store(true, Ordering::Release);
        let (reply, response) = sync_channel(1);
        assert!(reply.send(DesktopResult::ApprovalRpcProbeCompleted).is_ok());

        assert_eq!(
            client.wait_for_result(&response),
            DesktopResult::Unavailable
        );
    }

    #[test]
    fn expired_deadline_returns_unavailable_without_latching_worker_failure() {
        let (client, _receiver) = test_client();
        let (_reply, response) = sync_channel(1);

        assert_eq!(
            client.wait_for_result_until(&response, Instant::now()),
            DesktopResult::Unavailable
        );
        assert!(!client.has_failed());
    }

    #[test]
    fn disconnected_worker_reply_latches_failure() {
        let (client, _receiver) = test_client();
        let (reply, response) = sync_channel(1);
        drop(reply);

        assert_eq!(
            client.wait_for_result_until(
                &response,
                Instant::now() + COORDINATOR_RESPONSE_POLL_INTERVAL
            ),
            DesktopResult::Unavailable
        );
        assert!(client.has_failed());
    }

    #[test]
    fn one_occupied_attempt_blocks_a_second_without_queuing_it() -> Result<(), &'static str> {
        let (client, receiver) = test_client();
        let first = client
            .try_reserve_launch()
            .ok_or("the first launch did not own occupancy")?;

        assert!(client.try_reserve_launch().is_none());
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));

        drop(first);
        let next = client
            .try_reserve_launch()
            .ok_or("dropping the attempt owner did not release occupancy")?;
        drop(next);
        Ok(())
    }

    #[test]
    fn stop_closes_admission_before_waking_the_worker_and_is_idempotent() -> Result<(), &'static str>
    {
        let (client, receiver) = test_client();
        let active = client
            .try_reserve_launch()
            .ok_or("the active launch did not own occupancy")?;

        client.begin_stop();

        assert!(client.stopping.load(Ordering::Acquire));
        assert!(client.try_reserve_launch().is_none());
        assert!(matches!(receiver.try_recv(), Ok(CoordinatorCommand::Stop)));

        client.begin_stop();
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
        drop(active);
        assert!(!client.occupied.load(Ordering::Acquire));
        Ok(())
    }

    #[test]
    fn coordinator_errors_and_debug_are_data_free() {
        assert_eq!(
            format!("{:?}", ServiceProbeCoordinatorError::Thread),
            "Thread"
        );
        assert_eq!(
            ServiceProbeCoordinatorError::Thread.to_string(),
            "service probe coordinator thread is unavailable"
        );
    }
}
