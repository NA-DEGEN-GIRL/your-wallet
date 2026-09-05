//! Fixed-capacity expected-helper admission for the dormant RPC fixture.
//!
//! The launch side supplies one move-only peer carrying server-derived role and
//! exact process/token/image evidence. Registration happens while that peer is
//! suspended; only a successful registered revalidation may perform its sole
//! resume. The RPC security callback observes without consuming, while the
//! manager spends the expected state exactly once. Retired slots are never
//! reused during one server lifetime, deliberately limiting that lifetime to
//! eight registrations so replay-resistant evidence cannot be recycled.

#![deny(unsafe_code)]

use core::fmt;
use core::num::NonZeroU32;
use std::array;
use std::marker::PhantomData;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use key_agent_service_wire::{EpochNonce, ServiceRequestId};

pub(crate) const EXPECTED_HELPER_CAPACITY: usize = 8;
pub(crate) const EXPECTED_HELPER_SESSION_QUARANTINE_CAPACITY: usize = 64;
pub(crate) const EXPECTED_HELPER_QUIESCENCE_MILLISECONDS: u64 = 5_000;
pub(crate) const EXPECTED_HELPER_QUIESCENCE_TIMEOUT: Duration =
    Duration::from_millis(EXPECTED_HELPER_QUIESCENCE_MILLISECONDS);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExpectedHelperRole {
    Approval,
    SecretInput,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct ExpectedPeerKey {
    epoch_nonce: EpochNonce,
    request_id: ServiceRequestId,
}

impl ExpectedPeerKey {
    pub(crate) const fn new(epoch_nonce: EpochNonce, request_id: ServiceRequestId) -> Self {
        Self {
            epoch_nonce,
            request_id,
        }
    }
}

impl fmt::Debug for ExpectedPeerKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExpectedPeerKey([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExpectedPeerVerificationError {
    Denied,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExpectedPeerRegistryError {
    Denied,
    Full,
    Stopping,
    Internal,
}

pub(crate) trait ExpectedHelperCandidate {
    fn revalidate(&self) -> Result<(), ExpectedPeerVerificationError>;
}

/// Move-only launch proof retained by the registry for the helper lifetime.
///
/// Every method except `resume_once` can perform bounded operating-system work
/// and is called only while the peer is owned outside the registry mutex.
/// `resume_once` is the deliberately tiny exception: the exact primary-thread
/// resume and `ExpectedRunning` publication share one mutex critical section,
/// so a newly runnable helper cannot observe an intermediate `InFlight` slot.
/// `cancel` must prove terminal reap before reporting success; dropping the
/// peer remains a process-terminal last line of defense.
pub(crate) trait ExpectedHelperPeer<C>: Send
where
    C: ExpectedHelperCandidate,
{
    fn key(&self) -> ExpectedPeerKey;
    fn session_id(&self) -> NonZeroU32;
    fn role(&self) -> ExpectedHelperRole;
    fn revalidate_suspended(&self) -> Result<(), ExpectedPeerVerificationError>;
    fn resume_once(&mut self) -> Result<(), ExpectedPeerVerificationError>;
    fn exactly_matches(&self, candidate: &C) -> Result<bool, ExpectedPeerVerificationError>;
    fn revalidate_running(&self) -> Result<(), ExpectedPeerVerificationError>;
    fn cancel(&mut self) -> Result<(), ExpectedPeerVerificationError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PeerPhase {
    RegisteredSuspended,
    ExpectedRunning,
    Admitted,
}

#[derive(Clone, Copy)]
enum SelectiveCancellationSettlementPolicy {
    PreservePlannedPhases,
    RollBackUnaffectedToOriginalPhase,
}

enum ExpectedPeerSlot<P> {
    Vacant,
    Live {
        key: ExpectedPeerKey,
        session_id: NonZeroU32,
        phase: PeerPhase,
        peer: P,
    },
    InFlight {
        key: ExpectedPeerKey,
        session_id: NonZeroU32,
        phase: PeerPhase,
        generation: u64,
        cancel_requested: bool,
        global_cancel_requested: bool,
        settlement: Arc<InFlightSettlement>,
    },
    Retired(ExpectedPeerKey),
}

struct InFlightSettlement {
    key: ExpectedPeerKey,
    generation: u64,
    result: Mutex<Option<Result<(), ExpectedPeerRegistryError>>>,
    completed: Condvar,
}

impl InFlightSettlement {
    fn new(key: ExpectedPeerKey, generation: u64) -> Self {
        Self {
            key,
            generation,
            result: Mutex::new(None),
            completed: Condvar::new(),
        }
    }

    fn complete(&self, result: Result<(), ExpectedPeerRegistryError>) {
        let mut settled = match self.result.lock() {
            Ok(settled) => settled,
            Err(poisoned) => poisoned.into_inner(),
        };
        if settled.is_none() {
            *settled = Some(result);
        } else {
            *settled = Some(Err(ExpectedPeerRegistryError::Internal));
        }
        self.result.clear_poison();
        self.completed.notify_all();
    }

    fn wait_until(&self, deadline: Instant) -> Result<(), ExpectedPeerRegistryError> {
        let mut settled = self
            .result
            .lock()
            .map_err(|_| ExpectedPeerRegistryError::Internal)?;
        loop {
            if let Some(result) = *settled {
                return result;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ExpectedPeerRegistryError::Internal);
            }
            let (next, timeout) = self
                .completed
                .wait_timeout(settled, remaining)
                .map_err(|_| ExpectedPeerRegistryError::Internal)?;
            settled = next;
            if timeout.timed_out() && settled.is_none() {
                return Err(ExpectedPeerRegistryError::Internal);
            }
        }
    }
}

struct InFlightSettlementGuard {
    settlement: Arc<InFlightSettlement>,
    completed: bool,
}

impl InFlightSettlementGuard {
    fn complete(&mut self, result: Result<(), ExpectedPeerRegistryError>) {
        if !self.completed {
            self.settlement.complete(result);
            self.completed = true;
        }
    }
}

impl Drop for InFlightSettlementGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.settlement
                .complete(Err(ExpectedPeerRegistryError::Internal));
        }
    }
}

struct InFlightCancellation {
    key: ExpectedPeerKey,
    generation: u64,
    settlement: Arc<InFlightSettlement>,
}

impl InFlightCancellation {
    fn wait_until(&self, deadline: Instant) -> Result<(), ExpectedPeerRegistryError> {
        if self.settlement.key != self.key || self.settlement.generation != self.generation {
            return Err(ExpectedPeerRegistryError::Internal);
        }
        self.settlement.wait_until(deadline)
    }
}

struct GuardOperation<T> {
    result: Result<T, ExpectedPeerRegistryError>,
    delegated: bool,
}

impl<T> GuardOperation<T> {
    const fn direct(result: Result<T, ExpectedPeerRegistryError>) -> Self {
        Self {
            result,
            delegated: false,
        }
    }

    const fn delegated(result: Result<T, ExpectedPeerRegistryError>) -> Self {
        Self {
            result,
            delegated: true,
        }
    }
}

struct ExpectedPeerState<P> {
    stopping: bool,
    next_generation: u64,
    quarantined_sessions: [Option<NonZeroU32>; EXPECTED_HELPER_SESSION_QUARANTINE_CAPACITY],
    slots: [ExpectedPeerSlot<P>; EXPECTED_HELPER_CAPACITY],
}

impl<P> ExpectedPeerState<P> {
    fn new() -> Self {
        Self {
            stopping: false,
            next_generation: 1,
            quarantined_sessions: [None; EXPECTED_HELPER_SESSION_QUARANTINE_CAPACITY],
            slots: array::from_fn(|_| ExpectedPeerSlot::Vacant),
        }
    }

    fn generation(&mut self) -> Result<u64, ExpectedPeerRegistryError> {
        let generation = self.next_generation;
        self.next_generation = generation
            .checked_add(1)
            .ok_or(ExpectedPeerRegistryError::Internal)?;
        Ok(generation)
    }
}

struct ExpectedPeerInner<P, C>
where
    C: ExpectedHelperCandidate,
    P: ExpectedHelperPeer<C>,
{
    state: Mutex<ExpectedPeerState<P>>,
    _candidate: PhantomData<fn(&C)>,
}

struct LocalPeer<P> {
    index: usize,
    key: ExpectedPeerKey,
    session_id: NonZeroU32,
    generation: u64,
    original_phase: PeerPhase,
    next_phase: Option<PeerPhase>,
    peer: P,
    settlement: InFlightSettlementGuard,
}

pub(crate) struct ExpectedHelperAdmission<P, C>
where
    C: ExpectedHelperCandidate,
    P: ExpectedHelperPeer<C>,
{
    inner: Arc<ExpectedPeerInner<P, C>>,
}

impl<P, C> Clone for ExpectedHelperAdmission<P, C>
where
    C: ExpectedHelperCandidate,
    P: ExpectedHelperPeer<C>,
{
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<P, C> ExpectedHelperAdmission<P, C>
where
    C: ExpectedHelperCandidate,
    P: ExpectedHelperPeer<C>,
{
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(ExpectedPeerInner {
                state: Mutex::new(ExpectedPeerState::new()),
                _candidate: PhantomData,
            }),
        }
    }

    pub(crate) fn register_suspended(
        &self,
        mut peer: P,
    ) -> Result<RegisteredExpectedHelper<P, C>, ExpectedPeerRegistryError> {
        let key = peer.key();
        let session_id = peer.session_id();
        let mut state = match lock_expected_state(&self.inner) {
            Ok(state) => state,
            Err(error) => {
                let cleanup = cleanup_peer(&mut peer);
                drop(peer);
                return cleanup.and(Err(error));
            }
        };
        let rejected = if state.stopping {
            Some(ExpectedPeerRegistryError::Stopping)
        } else if quarantine_contains(&state.quarantined_sessions, session_id)
            || state.slots.iter().any(|slot| slot_key(slot) == Some(key))
        {
            Some(ExpectedPeerRegistryError::Denied)
        } else {
            None
        };
        if let Some(error) = rejected {
            drop(state);
            let cleanup = cleanup_peer(&mut peer);
            drop(peer);
            return cleanup.and(Err(error));
        }
        let Some(index) = state
            .slots
            .iter()
            .position(|slot| matches!(slot, ExpectedPeerSlot::Vacant))
        else {
            drop(state);
            let cleanup = cleanup_peer(&mut peer);
            drop(peer);
            return cleanup.and(Err(ExpectedPeerRegistryError::Full));
        };
        state.slots[index] = ExpectedPeerSlot::Live {
            key,
            session_id,
            phase: PeerPhase::RegisteredSuspended,
            peer,
        };
        Ok(RegisteredExpectedHelper {
            inner: Arc::clone(&self.inner),
            key,
            index,
            armed: true,
        })
    }

    /// Callback-only exact observation. Candidate authentication failure is
    /// non-consuming because no key-bearing manager authority was presented.
    pub(crate) fn observe_callback(
        &self,
        candidate: &C,
    ) -> Result<ExpectedHelperRole, ExpectedPeerRegistryError> {
        candidate.revalidate().map_err(map_verification_error)?;
        let mut peers = self.begin_exclusive_scan(None)?;
        let observation = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut matched = Vec::with_capacity(2);
            let mut failure = None;
            for (position, local) in peers.iter_mut().enumerate() {
                match local.peer.exactly_matches(candidate) {
                    Ok(false) => {}
                    Ok(true) if local.original_phase == PeerPhase::ExpectedRunning => {
                        matched.push(position);
                    }
                    Ok(true) => {
                        local.next_phase = None;
                        failure.get_or_insert(ExpectedPeerRegistryError::Denied);
                    }
                    Err(error) => {
                        local.next_phase = None;
                        failure.get_or_insert(map_verification_error(error));
                    }
                }
            }
            if matched.len() > 1 {
                failure = Some(ExpectedPeerRegistryError::Internal);
            }
            if let Some(error) = failure {
                // A successful exact match is related to the failed/ambiguous
                // observation and cannot remain trusted. Definite non-matches
                // keep their phase, so replay for A cannot kill unrelated B.
                for position in matched {
                    peers[position].next_phase = None;
                }
                return Err(error);
            }
            let [position] = matched.as_slice() else {
                return Err(ExpectedPeerRegistryError::Denied);
            };
            let position = *position;
            let role = peers[position].peer.role();
            if let Err(error) = peers[position].peer.revalidate_running() {
                peers[position].next_phase = None;
                return Err(map_verification_error(error));
            }
            Ok(role)
        }));
        let result = match observation {
            Ok(result) => result,
            Err(payload) => {
                retire_all(&mut peers);
                let _ = self.settle_scan(
                    peers,
                    SelectiveCancellationSettlementPolicy::PreservePlannedPhases,
                );
                std::panic::resume_unwind(payload);
            }
        };
        let policy = if result.is_ok() {
            SelectiveCancellationSettlementPolicy::RollBackUnaffectedToOriginalPhase
        } else {
            SelectiveCancellationSettlementPolicy::PreservePlannedPhases
        };
        resolve_scan_result(self.settle_scan(peers, policy), result)
    }

    /// Manager-only exact consume. All live slots are moved outside the mutex
    /// and compared. Commit succeeds only when exactly one peer matches and it
    /// is the key-selected expected-running slot. A concurrent registration is
    /// detected at the atomic commit check and terminally retires every related
    /// peer rather than admitting an ambiguous identity.
    pub(crate) fn consume_manager(
        &self,
        key: ExpectedPeerKey,
        candidate: &C,
    ) -> Result<ExpectedHelperRole, ExpectedPeerRegistryError> {
        let mut peers = self.begin_exclusive_scan(Some(key))?;
        let Some(selected) = peers.iter().position(|local| local.key == key) else {
            retire_all(&mut peers);
            return self
                .settle_scan(
                    peers,
                    SelectiveCancellationSettlementPolicy::PreservePlannedPhases,
                )
                .map(|_| ())
                .and(Err(ExpectedPeerRegistryError::Internal));
        };
        if peers[selected].original_phase != PeerPhase::ExpectedRunning {
            retire_all(&mut peers);
            return self
                .settle_scan(
                    peers,
                    SelectiveCancellationSettlementPolicy::PreservePlannedPhases,
                )
                .map(|_| ())
                .and(Err(ExpectedPeerRegistryError::Denied));
        }
        let observation = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if let Err(error) = candidate.revalidate() {
                retire_all(&mut peers);
                return Err(map_verification_error(error));
            }

            let mut matched = None;
            let mut failure = None;
            for (position, local) in peers.iter().enumerate() {
                match local.peer.exactly_matches(candidate) {
                    Ok(false) => {}
                    Ok(true) => {
                        if matched.replace(position).is_some() {
                            failure = Some(ExpectedPeerRegistryError::Internal);
                            break;
                        }
                    }
                    Err(error) => {
                        failure = Some(map_verification_error(error));
                        break;
                    }
                }
            }
            if failure.is_none() && matched != Some(selected) {
                failure = Some(ExpectedPeerRegistryError::Denied);
            }
            if let Some(error) = failure {
                retire_all(&mut peers);
                return Err(error);
            }
            if let Err(error) = peers[selected].peer.revalidate_running() {
                retire_all(&mut peers);
                return Err(map_verification_error(error));
            }
            let role = peers[selected].peer.role();
            peers[selected].next_phase = Some(PeerPhase::Admitted);
            Ok(role)
        }));
        let result = match observation {
            Ok(result) => result,
            Err(payload) => {
                retire_all(&mut peers);
                let _ = self.settle_scan(
                    peers,
                    SelectiveCancellationSettlementPolicy::PreservePlannedPhases,
                );
                std::panic::resume_unwind(payload);
            }
        };
        let policy = if result.is_ok() {
            SelectiveCancellationSettlementPolicy::RollBackUnaffectedToOriginalPhase
        } else {
            SelectiveCancellationSettlementPolicy::PreservePlannedPhases
        };
        resolve_scan_result(self.settle_scan(peers, policy), result)
    }

    /// Manager-side terminal rejection when a malformed helper frame did not
    /// yield a trustworthy key. Candidate and peer comparisons run with every
    /// live peer outside the registry mutex. Exactly matching peers and peers
    /// whose relationship cannot be determined are retired; definite
    /// non-matches remain live. A failed candidate revalidation is still
    /// followed by exact comparison so its related launch cannot be retried.
    pub(crate) fn reject_manager_candidate(
        &self,
        candidate: &C,
    ) -> Result<(), ExpectedPeerRegistryError> {
        let mut peers = self.begin_exclusive_scan(None)?;
        let rejection = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut failure = candidate.revalidate().err().map(map_verification_error);
            let mut matched = Vec::with_capacity(2);

            for (position, local) in peers.iter_mut().enumerate() {
                match local.peer.exactly_matches(candidate) {
                    Ok(false) => {}
                    Ok(true) => matched.push(position),
                    Err(error) => {
                        // A failed identity query cannot prove this peer is
                        // unrelated, so terminal ownership is the only safe
                        // result for that slot.
                        local.next_phase = None;
                        let error = map_verification_error(error);
                        failure = Some(
                            if failure == Some(ExpectedPeerRegistryError::Internal)
                                || error == ExpectedPeerRegistryError::Internal
                            {
                                ExpectedPeerRegistryError::Internal
                            } else {
                                error
                            },
                        );
                    }
                }
            }

            for position in &matched {
                peers[*position].next_phase = None;
            }
            if matched.len() > 1 {
                failure = Some(ExpectedPeerRegistryError::Internal);
            } else if matched.is_empty() && failure.is_none() {
                failure = Some(ExpectedPeerRegistryError::Denied);
            }

            failure.map_or(Ok(()), Err)
        }));
        let result = match rejection {
            Ok(result) => result,
            Err(payload) => {
                // A panic leaves the remaining comparisons indeterminate.
                // Preserve the existing guard contract by retiring every
                // extracted owner before propagating the panic.
                retire_all(&mut peers);
                let _ = self.settle_scan(
                    peers,
                    SelectiveCancellationSettlementPolicy::PreservePlannedPhases,
                );
                std::panic::resume_unwind(payload);
            }
        };
        resolve_scan_result(
            self.settle_scan(
                peers,
                SelectiveCancellationSettlementPolicy::PreservePlannedPhases,
            ),
            result,
        )
    }

    #[expect(
        dead_code,
        reason = "the live router rejects malformed peers by candidate, not by decoded key alone"
    )]
    pub(crate) fn reject_manager(
        &self,
        key: ExpectedPeerKey,
    ) -> Result<(), ExpectedPeerRegistryError> {
        self.cancel_key(key, ExpectedPeerRegistryError::Denied)
            .result
    }

    /// Quarantines one server-derived logon session and terminally reaps only
    /// helpers owned by that session. The quarantine is committed before any
    /// matching owner can be extracted or asked to settle. Process cleanup and
    /// the bounded settlement wait run only after the registry mutex is free.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "dormant until the SCM session-change callback owns a bounded dispatch queue"
        )
    )]
    pub(crate) fn invalidate_session(
        &self,
        session_id: NonZeroU32,
    ) -> Result<(), ExpectedPeerRegistryError> {
        let mut state = lock_expected_state(&self.inner)?;
        if state.stopping {
            return Err(ExpectedPeerRegistryError::Stopping);
        }
        if !quarantine_insert(&mut state.quarantined_sessions, session_id) {
            state.stopping = true;
            let (cleanup, in_flight) = request_selected_session_cancellation_and_retire_live(
                &mut state.slots,
                |_| true,
                true,
            );
            drop(state);
            return settle_invalidated_owners::<P, C>(cleanup, in_flight)
                .and(Err(ExpectedPeerRegistryError::Stopping));
        }
        let (cleanup, in_flight) = request_selected_session_cancellation_and_retire_live(
            &mut state.slots,
            |candidate| candidate == session_id,
            false,
        );
        drop(state);
        settle_invalidated_owners::<P, C>(cleanup, in_flight)
    }

    /// Atomically quarantines the departing session and every session observed
    /// in the active helper topology, then terminally reaps every current
    /// owner. A quarantine-capacity failure instead transitions the whole
    /// registry to stopping and still reaps all current owners.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "dormant until the SCM session-change callback owns a bounded dispatch queue"
        )
    )]
    pub(crate) fn invalidate_active_sessions(
        &self,
        departing_session: NonZeroU32,
    ) -> Result<(), ExpectedPeerRegistryError> {
        let mut state = lock_expected_state(&self.inner)?;
        if state.stopping {
            return Err(ExpectedPeerRegistryError::Stopping);
        }

        let mut quarantined = state.quarantined_sessions;
        let mut fits = quarantine_insert(&mut quarantined, departing_session);
        if fits {
            for session_id in state.slots.iter().filter_map(slot_session_id) {
                if !quarantine_insert(&mut quarantined, session_id) {
                    fits = false;
                    break;
                }
            }
        }
        if fits {
            state.quarantined_sessions = quarantined;
        } else {
            state.stopping = true;
        }

        let (cleanup, in_flight) = request_selected_session_cancellation_and_retire_live(
            &mut state.slots,
            |_| true,
            !fits,
        );
        drop(state);
        let settled = settle_invalidated_owners::<P, C>(cleanup, in_flight);
        if fits {
            settled
        } else {
            settled.and(Err(ExpectedPeerRegistryError::Stopping))
        }
    }

    /// Closes registration, terminally cancels resident peers, and waits a
    /// bounded interval for every exact in-flight owner to finish delegated
    /// cleanup. No operating-system cleanup or condition-variable wait runs
    /// while the registry mutex is held.
    pub(crate) fn stop(&self) -> Result<(), ExpectedPeerRegistryError> {
        self.stop_with_timeout(EXPECTED_HELPER_QUIESCENCE_TIMEOUT)
    }

    fn stop_with_timeout(&self, timeout: Duration) -> Result<(), ExpectedPeerRegistryError> {
        let mut state = lock_expected_state(&self.inner)?;
        if state.stopping {
            return Err(ExpectedPeerRegistryError::Stopping);
        }
        state.stopping = true;
        let mut cleanup = Vec::with_capacity(EXPECTED_HELPER_CAPACITY);
        let mut in_flight = Vec::with_capacity(EXPECTED_HELPER_CAPACITY);
        for slot in &mut state.slots {
            match slot {
                ExpectedPeerSlot::InFlight {
                    key,
                    generation,
                    cancel_requested,
                    global_cancel_requested,
                    settlement,
                    ..
                } => {
                    request_global_cancellation(cancel_requested, global_cancel_requested);
                    in_flight.push(InFlightCancellation {
                        key: *key,
                        generation: *generation,
                        settlement: Arc::clone(settlement),
                    });
                }
                ExpectedPeerSlot::Live { .. } => {
                    if let Some(peer) = retire_live_slot(slot) {
                        cleanup.push(peer);
                    }
                }
                ExpectedPeerSlot::Vacant | ExpectedPeerSlot::Retired(_) => {}
            }
        }
        drop(state);
        let cleanup = cleanup_peers(cleanup);
        let settled = wait_for_cancellations(in_flight, timeout);
        cleanup.and(settled)
    }

    fn begin_single_registered(
        &self,
        index: usize,
        key: ExpectedPeerKey,
    ) -> Result<LocalPeer<P>, ExpectedPeerRegistryError> {
        let mut state = lock_expected_state(&self.inner)?;
        if state.stopping || index >= state.slots.len() {
            return Err(ExpectedPeerRegistryError::Stopping);
        }
        if state
            .slots
            .iter()
            .any(|slot| matches!(slot, ExpectedPeerSlot::InFlight { .. }))
        {
            let cleanup = request_in_flight_cancellation_and_retire_live(&mut state.slots);
            drop(state);
            return cleanup_peers(cleanup).and(Err(ExpectedPeerRegistryError::Internal));
        }
        let generation = state.generation()?;
        let local = extract_live_slot(&mut state.slots[index], index, generation)?;
        if local.key == key && local.original_phase == PeerPhase::RegisteredSuspended {
            Ok(local)
        } else {
            let mut local = local;
            local.next_phase = None;
            drop(state);
            let _ = self.finish_single(local, None);
            Err(ExpectedPeerRegistryError::Denied)
        }
    }

    fn begin_exclusive_scan(
        &self,
        required_key: Option<ExpectedPeerKey>,
    ) -> Result<Vec<LocalPeer<P>>, ExpectedPeerRegistryError> {
        let mut state = lock_expected_state(&self.inner)?;
        if state.stopping {
            return Err(ExpectedPeerRegistryError::Stopping);
        }
        if let Some(key) = required_key {
            let selected = state
                .slots
                .iter()
                .position(|slot| slot_key(slot) == Some(key));
            match selected.map(|index| (index, &state.slots[index])) {
                Some((
                    _,
                    ExpectedPeerSlot::Live {
                        phase: PeerPhase::ExpectedRunning,
                        ..
                    }
                    | ExpectedPeerSlot::InFlight { .. },
                )) => {}
                Some((index, ExpectedPeerSlot::Live { .. })) => {
                    let cleanup = retire_live_slot(&mut state.slots[index]);
                    drop(state);
                    return cleanup
                        .map_or(Ok(()), |mut peer| {
                            let result = cleanup_peer::<P, C>(&mut peer);
                            drop(peer);
                            result
                        })
                        .and(Err(ExpectedPeerRegistryError::Denied));
                }
                Some((_, ExpectedPeerSlot::Retired(_))) | None => {
                    return Err(ExpectedPeerRegistryError::Denied);
                }
                Some((_, ExpectedPeerSlot::Vacant)) => {
                    return Err(ExpectedPeerRegistryError::Internal);
                }
            }
        }
        if state
            .slots
            .iter()
            .any(|slot| matches!(slot, ExpectedPeerSlot::InFlight { .. }))
        {
            let cleanup = request_in_flight_cancellation_and_retire_live(&mut state.slots);
            drop(state);
            return cleanup_peers(cleanup).and(Err(ExpectedPeerRegistryError::Internal));
        }
        let live_count = state
            .slots
            .iter()
            .filter(|slot| matches!(slot, ExpectedPeerSlot::Live { .. }))
            .count();
        let generation = state.next_generation;
        state.next_generation = generation
            .checked_add(
                u64::try_from(live_count).map_err(|_| ExpectedPeerRegistryError::Internal)?,
            )
            .ok_or(ExpectedPeerRegistryError::Internal)?;
        let mut ordinal = 0_u64;
        let mut peers: Vec<LocalPeer<P>> = Vec::with_capacity(EXPECTED_HELPER_CAPACITY);
        for index in 0..state.slots.len() {
            if matches!(state.slots[index], ExpectedPeerSlot::Live { .. }) {
                let local =
                    match extract_live_slot(&mut state.slots[index], index, generation + ordinal) {
                        Ok(local) => local,
                        Err(error) => {
                            let mut resident = Vec::with_capacity(EXPECTED_HELPER_CAPACITY);
                            for local in &peers {
                                if let Some(ExpectedPeerSlot::InFlight {
                                    generation,
                                    cancel_requested,
                                    global_cancel_requested,
                                    ..
                                }) = state.slots.get_mut(local.index)
                                    && *generation == local.generation
                                {
                                    request_global_cancellation(
                                        cancel_requested,
                                        global_cancel_requested,
                                    );
                                }
                            }
                            for slot in &mut state.slots {
                                if let Some(peer) = retire_live_slot(slot) {
                                    resident.push(peer);
                                }
                            }
                            drop(state);
                            retire_all(&mut peers);
                            let cleanup = self
                                .cleanup_local_peers(peers)
                                .and(cleanup_peers::<P, C>(resident));
                            return cleanup.and(Err(error));
                        }
                    };
                ordinal += 1;
                peers.push(local);
            }
        }
        Ok(peers)
    }

    /// Settles one structurally exact multi-peer scan. An exact per-slot
    /// cancellation is not a registry corruption: only that local owner is
    /// retired, while unaffected locals are restored. Callers explicitly
    /// choose whether an otherwise-successful state transition rolls back to
    /// original phases or preserves planned terminal-rejection cleanup. The
    /// returned flag makes callers discard that otherwise-successful result.
    fn settle_scan(
        &self,
        mut peers: Vec<LocalPeer<P>>,
        policy: SelectiveCancellationSettlementPolicy,
    ) -> Result<bool, ExpectedPeerRegistryError> {
        let mut state = match lock_expected_state(&self.inner) {
            Ok(state) => state,
            Err(error) => {
                retire_all(&mut peers);
                let cleanup = self.cleanup_local_peers(peers);
                return cleanup.and(Err(error));
            }
        };
        let concurrent_live = state
            .slots
            .iter()
            .any(|slot| matches!(slot, ExpectedPeerSlot::Live { .. }));
        let exact_slots = scan_slots_are_structurally_exact(&state.slots, &peers);
        let global_cancellation = scan_has_global_cancellation(&state.slots, &peers);
        if state.stopping || concurrent_live || !exact_slots || global_cancellation {
            let stopping = state.stopping;
            let mut concurrent = Vec::with_capacity(EXPECTED_HELPER_CAPACITY);
            for slot in &mut state.slots {
                match slot {
                    ExpectedPeerSlot::Live { .. } => {
                        if let Some(peer) = retire_live_slot(slot) {
                            concurrent.push(peer);
                        }
                    }
                    ExpectedPeerSlot::InFlight {
                        cancel_requested,
                        global_cancel_requested,
                        ..
                    } => request_global_cancellation(cancel_requested, global_cancel_requested),
                    ExpectedPeerSlot::Vacant | ExpectedPeerSlot::Retired(_) => {}
                }
            }
            drop(state);
            retire_all(&mut peers);
            let cleanup = self
                .cleanup_local_peers(peers)
                .and(cleanup_peers(concurrent));
            return cleanup.and(Err(if stopping {
                ExpectedPeerRegistryError::Stopping
            } else {
                ExpectedPeerRegistryError::Internal
            }));
        }

        let targeted_cancellation = peers
            .iter()
            .any(|local| local_has_selective_session_cancellation(&state.slots, local));
        let mut cleanup = Vec::new();
        for local in peers {
            let cancelled = local_has_selective_session_cancellation(&state.slots, &local);
            let restored_phase = if targeted_cancellation
                && matches!(
                    policy,
                    SelectiveCancellationSettlementPolicy::RollBackUnaffectedToOriginalPhase
                ) {
                Some(local.original_phase)
            } else {
                local.next_phase
            };
            if !cancelled && let Some(phase) = restored_phase {
                let LocalPeer {
                    index,
                    key,
                    session_id,
                    peer,
                    mut settlement,
                    ..
                } = local;
                state.slots[index] = ExpectedPeerSlot::Live {
                    key,
                    session_id,
                    phase,
                    peer,
                };
                settlement.complete(Ok(()));
            } else {
                if !cancelled
                    && let Some(ExpectedPeerSlot::InFlight {
                        generation,
                        cancel_requested,
                        global_cancel_requested,
                        ..
                    }) = state.slots.get_mut(local.index)
                    && *generation == local.generation
                {
                    request_global_cancellation(cancel_requested, global_cancel_requested);
                }
                cleanup.push(local);
            }
        }
        drop(state);
        self.cleanup_local_peers(cleanup)
            .map(|()| targeted_cancellation)
    }

    fn finish_single(
        &self,
        local: LocalPeer<P>,
        next_phase: Option<PeerPhase>,
    ) -> Result<(), ExpectedPeerRegistryError> {
        let mut state = match lock_expected_state(&self.inner) {
            Ok(state) => state,
            Err(error) => {
                let cleanup = self.cleanup_local_peers(vec![local]);
                return cleanup.and(Err(error));
            }
        };
        let exact = matches!(
            state.slots.get(local.index),
            Some(ExpectedPeerSlot::InFlight {
                key,
                session_id,
                phase,
                generation,
                cancel_requested: false,
                global_cancel_requested: false,
                ..
            }) if *key == local.key
                && *session_id == local.session_id
                && *phase == local.original_phase
                && *generation == local.generation
        );
        let stopping = state.stopping;
        if exact && !stopping {
            if let Some(phase) = next_phase {
                let LocalPeer {
                    index,
                    key,
                    session_id,
                    peer,
                    mut settlement,
                    ..
                } = local;
                state.slots[index] = ExpectedPeerSlot::Live {
                    key,
                    session_id,
                    phase,
                    peer,
                };
                settlement.complete(Ok(()));
                return Ok(());
            }
            if let Some(ExpectedPeerSlot::InFlight {
                generation,
                cancel_requested,
                global_cancel_requested,
                ..
            }) = state.slots.get_mut(local.index)
                && *generation == local.generation
            {
                request_global_cancellation(cancel_requested, global_cancel_requested);
            }
            drop(state);
            let cleanup = self.cleanup_local_peers(vec![local]);
            return cleanup;
        }
        if let Some(ExpectedPeerSlot::InFlight {
            generation,
            cancel_requested,
            global_cancel_requested,
            ..
        }) = state.slots.get_mut(local.index)
            && *generation == local.generation
        {
            request_global_cancellation(cancel_requested, global_cancel_requested);
        }
        drop(state);
        let cleanup = self.cleanup_local_peers(vec![local]);
        cleanup.and(Err(if stopping {
            ExpectedPeerRegistryError::Stopping
        } else {
            ExpectedPeerRegistryError::Internal
        }))
    }

    /// Revalidates while the mutex is free, then performs only the exact
    /// primary-thread resume while holding the slot lock. Any callback begun by
    /// the resumed child blocks on this mutex until `ExpectedRunning` is
    /// published, establishing the required happens-before edge without a
    /// second child bootstrap gate.
    fn resume_and_publish(&self, mut local: LocalPeer<P>) -> Result<(), ExpectedPeerRegistryError> {
        let mut state = match lock_expected_state(&self.inner) {
            Ok(state) => state,
            Err(error) => {
                let cleanup = self.cleanup_local_peers(vec![local]);
                return cleanup.and(Err(error));
            }
        };
        let exact = matches!(
            state.slots.get(local.index),
            Some(ExpectedPeerSlot::InFlight {
                key,
                session_id,
                phase: PeerPhase::RegisteredSuspended,
                generation,
                cancel_requested: false,
                global_cancel_requested: false,
                ..
            }) if *key == local.key
                && *session_id == local.session_id
                && *generation == local.generation
        );
        if state.stopping || !exact {
            let stopping = state.stopping;
            if let Some(ExpectedPeerSlot::InFlight {
                generation,
                cancel_requested,
                global_cancel_requested,
                ..
            }) = state.slots.get_mut(local.index)
                && *generation == local.generation
            {
                request_global_cancellation(cancel_requested, global_cancel_requested);
            }
            drop(state);
            local.next_phase = None;
            let cleanup = self.cleanup_local_peers(vec![local]);
            return cleanup.and(Err(if stopping {
                ExpectedPeerRegistryError::Stopping
            } else {
                ExpectedPeerRegistryError::Internal
            }));
        }

        let resume =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| local.peer.resume_once()));
        let resume = match resume {
            Ok(resume) => resume,
            Err(payload) => {
                if let ExpectedPeerSlot::InFlight {
                    cancel_requested,
                    global_cancel_requested,
                    ..
                } = &mut state.slots[local.index]
                {
                    request_global_cancellation(cancel_requested, global_cancel_requested);
                }
                drop(state);
                local.next_phase = None;
                let _ = self.cleanup_local_peers(vec![local]);
                std::panic::resume_unwind(payload);
            }
        };
        if let Err(error) = resume {
            if let ExpectedPeerSlot::InFlight {
                cancel_requested,
                global_cancel_requested,
                ..
            } = &mut state.slots[local.index]
            {
                request_global_cancellation(cancel_requested, global_cancel_requested);
            }
            drop(state);
            local.next_phase = None;
            let cleanup = self.cleanup_local_peers(vec![local]);
            return cleanup.and(Err(map_verification_error(error)));
        }
        let LocalPeer {
            index,
            key,
            session_id,
            peer,
            mut settlement,
            ..
        } = local;
        state.slots[index] = ExpectedPeerSlot::Live {
            key,
            session_id,
            phase: PeerPhase::ExpectedRunning,
            peer,
        };
        settlement.complete(Ok(()));
        Ok(())
    }

    /// Runs terminal peer cleanup first, then retires the exact key/generation
    /// and only afterward wakes cancellation waiters. Keeping the slot
    /// `InFlight` until this point prevents stop or a second guard from
    /// mistaking delegated-but-still-running cleanup for quiescence.
    fn cleanup_local_peers(
        &self,
        peers: Vec<LocalPeer<P>>,
    ) -> Result<(), ExpectedPeerRegistryError> {
        let mut cleanup_result = Ok(());
        let mut completed = Vec::with_capacity(peers.len());
        for local in peers {
            let LocalPeer {
                index,
                key,
                session_id,
                generation,
                mut peer,
                settlement,
                ..
            } = local;
            let cleanup = cleanup_peer::<P, C>(&mut peer);
            drop(peer);
            cleanup_result = cleanup_result.and(cleanup);
            completed.push((index, key, session_id, generation, settlement, cleanup));
        }

        if completed.is_empty() {
            return cleanup_result;
        }

        let (mut state, poisoned) = match self.inner.state.lock() {
            Ok(state) => (state, false),
            Err(poisoned) => (poisoned.into_inner(), true),
        };
        let mut resident = Vec::with_capacity(EXPECTED_HELPER_CAPACITY);
        if poisoned {
            state.stopping = true;
            for slot in &mut state.slots {
                match slot {
                    ExpectedPeerSlot::Live { .. } => {
                        if let Some(peer) = retire_live_slot(slot) {
                            resident.push(peer);
                        }
                    }
                    ExpectedPeerSlot::InFlight {
                        cancel_requested,
                        global_cancel_requested,
                        ..
                    } => request_global_cancellation(cancel_requested, global_cancel_requested),
                    ExpectedPeerSlot::Vacant | ExpectedPeerSlot::Retired(_) => {}
                }
            }
        }
        let poison_result = if poisoned {
            Err(ExpectedPeerRegistryError::Internal)
        } else {
            Ok(())
        };
        let mut registry_result = poison_result;
        let mut signals = Vec::with_capacity(completed.len());
        for (index, key, session_id, generation, settlement, cleanup) in completed {
            let exact = matches!(
                state.slots.get(index),
                Some(ExpectedPeerSlot::InFlight {
                    key: current_key,
                    session_id: current_session_id,
                    generation: current_generation,
                    ..
                }) if *current_key == key
                    && *current_session_id == session_id
                    && *current_generation == generation
            );
            let slot_result = if exact {
                state.slots[index] = ExpectedPeerSlot::Retired(key);
                Ok(())
            } else {
                Err(ExpectedPeerRegistryError::Internal)
            };
            registry_result = registry_result.and(slot_result);
            signals.push((settlement, cleanup.and(slot_result).and(poison_result)));
        }
        if poisoned {
            self.inner.state.clear_poison();
        }
        drop(state);
        let resident_cleanup = cleanup_peers::<P, C>(resident);
        for (mut settlement, result) in signals {
            settlement.complete(result);
        }
        cleanup_result.and(resident_cleanup).and(registry_result)
    }

    fn cancel_key(
        &self,
        key: ExpectedPeerKey,
        absent: ExpectedPeerRegistryError,
    ) -> GuardOperation<()> {
        self.cancel_key_with_timeout(key, absent, EXPECTED_HELPER_QUIESCENCE_TIMEOUT)
    }

    fn cancel_key_with_timeout(
        &self,
        key: ExpectedPeerKey,
        absent: ExpectedPeerRegistryError,
        timeout: Duration,
    ) -> GuardOperation<()> {
        let mut state = match lock_expected_state(&self.inner) {
            Ok(state) => state,
            Err(error) => return GuardOperation::direct(Err(error)),
        };
        let Some(index) = state
            .slots
            .iter()
            .position(|slot| slot_key(slot) == Some(key))
        else {
            return GuardOperation::direct(Err(absent));
        };
        let mut in_flight = None;
        let cleanup = match &mut state.slots[index] {
            ExpectedPeerSlot::Live { .. } => retire_live_slot(&mut state.slots[index]),
            ExpectedPeerSlot::InFlight {
                key,
                generation,
                cancel_requested,
                global_cancel_requested,
                settlement,
                ..
            } => {
                request_global_cancellation(cancel_requested, global_cancel_requested);
                in_flight = Some(InFlightCancellation {
                    key: *key,
                    generation: *generation,
                    settlement: Arc::clone(settlement),
                });
                None
            }
            ExpectedPeerSlot::Retired(_) => return GuardOperation::direct(Err(absent)),
            ExpectedPeerSlot::Vacant => {
                return GuardOperation::direct(Err(ExpectedPeerRegistryError::Internal));
            }
        };
        drop(state);
        if let Some(in_flight) = in_flight {
            let result =
                deadline_after(timeout).and_then(|deadline| in_flight.wait_until(deadline));
            return GuardOperation::delegated(result);
        }
        let cleanup = cleanup.map_or(Ok(()), |mut peer| {
            let result = cleanup_peer(&mut peer);
            drop(peer);
            result
        });
        GuardOperation::direct(cleanup)
    }

    fn finish_admitted_key(&self, key: ExpectedPeerKey) -> GuardOperation<ExpectedHelperRole> {
        self.finish_admitted_key_with_timeout(key, EXPECTED_HELPER_QUIESCENCE_TIMEOUT)
    }

    fn finish_admitted_key_with_timeout(
        &self,
        key: ExpectedPeerKey,
        timeout: Duration,
    ) -> GuardOperation<ExpectedHelperRole> {
        let mut state = match lock_expected_state(&self.inner) {
            Ok(state) => state,
            Err(error) => return GuardOperation::direct(Err(error)),
        };
        let Some(index) = state
            .slots
            .iter()
            .position(|slot| slot_key(slot) == Some(key))
        else {
            return GuardOperation::direct(Err(ExpectedPeerRegistryError::Denied));
        };
        let mut in_flight = None;
        let phase = match &mut state.slots[index] {
            ExpectedPeerSlot::Live { phase, .. } => *phase,
            ExpectedPeerSlot::InFlight {
                key,
                generation,
                cancel_requested,
                global_cancel_requested,
                settlement,
                ..
            } => {
                request_global_cancellation(cancel_requested, global_cancel_requested);
                in_flight = Some(InFlightCancellation {
                    key: *key,
                    generation: *generation,
                    settlement: Arc::clone(settlement),
                });
                PeerPhase::ExpectedRunning
            }
            ExpectedPeerSlot::Retired(_) => {
                return GuardOperation::direct(Err(ExpectedPeerRegistryError::Denied));
            }
            ExpectedPeerSlot::Vacant => {
                return GuardOperation::direct(Err(ExpectedPeerRegistryError::Internal));
            }
        };
        if let Some(in_flight) = in_flight {
            drop(state);
            let _settled =
                deadline_after(timeout).and_then(|deadline| in_flight.wait_until(deadline));
            return GuardOperation::delegated(Err(ExpectedPeerRegistryError::Internal));
        }
        let Some(mut peer) = retire_live_slot(&mut state.slots[index]) else {
            return GuardOperation::direct(Err(ExpectedPeerRegistryError::Internal));
        };
        drop(state);

        if phase != PeerPhase::Admitted {
            let cleanup = cleanup_peer::<P, C>(&mut peer);
            drop(peer);
            return GuardOperation::direct(cleanup.and(Err(ExpectedPeerRegistryError::Denied)));
        }

        // Admission is historical evidence. Revalidate the exact still-owned
        // process immediately before extracting its role and terminal cleanup;
        // a helper that died or changed since admission cannot finish positively.
        // Keep both observations in the unwind boundary so cleanup also runs
        // when an implementation panics instead of returning a rejection.
        let role = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            peer.revalidate_running().map_err(map_verification_error)?;
            Ok(peer.role())
        }));
        let cleanup = cleanup_peer::<P, C>(&mut peer);
        drop(peer);
        let result = match role {
            Ok(role) => cleanup.and(role),
            Err(payload) => {
                let _ = cleanup;
                std::panic::resume_unwind(payload);
            }
        };
        GuardOperation::direct(result)
    }
}

impl<P, C> fmt::Debug for ExpectedHelperAdmission<P, C>
where
    C: ExpectedHelperCandidate,
    P: ExpectedHelperPeer<C>,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExpectedHelperAdmission([REDACTED])")
    }
}

#[must_use = "registered suspended helper must activate or cancel"]
pub(crate) struct RegisteredExpectedHelper<P, C>
where
    C: ExpectedHelperCandidate,
    P: ExpectedHelperPeer<C>,
{
    inner: Arc<ExpectedPeerInner<P, C>>,
    key: ExpectedPeerKey,
    index: usize,
    armed: bool,
}

impl<P, C> RegisteredExpectedHelper<P, C>
where
    C: ExpectedHelperCandidate,
    P: ExpectedHelperPeer<C>,
{
    pub(crate) fn revalidate_and_resume_once(
        mut self,
    ) -> Result<ExpectedHelperLease<P, C>, ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission {
            inner: Arc::clone(&self.inner),
        };
        let local = admission.begin_single_registered(self.index, self.key)?;
        let suspended = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            local.peer.revalidate_suspended()
        }));
        let suspended = match suspended {
            Ok(suspended) => suspended,
            Err(payload) => {
                let _ = admission.finish_single(local, None);
                self.armed = false;
                std::panic::resume_unwind(payload);
            }
        };
        if let Err(error) = suspended {
            let settled = admission.finish_single(local, None);
            self.armed = false;
            return settled.and(Err(map_verification_error(error)));
        }
        let activated = admission.resume_and_publish(local);
        self.armed = false;
        activated?;
        Ok(ExpectedHelperLease {
            inner: Arc::clone(&self.inner),
            key: self.key,
            armed: true,
        })
    }
}

impl<P, C> Drop for RegisteredExpectedHelper<P, C>
where
    C: ExpectedHelperCandidate,
    P: ExpectedHelperPeer<C>,
{
    fn drop(&mut self) {
        if self.armed {
            let admission = ExpectedHelperAdmission {
                inner: Arc::clone(&self.inner),
            };
            let outcome = admission.cancel_key(self.key, ExpectedPeerRegistryError::Denied);
            if !outcome.delegated {
                enforce_guard_drop_cleanup(outcome.result);
            }
        }
    }
}

impl<P, C> fmt::Debug for RegisteredExpectedHelper<P, C>
where
    C: ExpectedHelperCandidate,
    P: ExpectedHelperPeer<C>,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RegisteredExpectedHelper([REDACTED])")
    }
}

#[must_use = "expected helper lease must remain live or cancel the helper"]
pub(crate) struct ExpectedHelperLease<P, C>
where
    C: ExpectedHelperCandidate,
    P: ExpectedHelperPeer<C>,
{
    inner: Arc<ExpectedPeerInner<P, C>>,
    key: ExpectedPeerKey,
    armed: bool,
}

impl<P, C> ExpectedHelperLease<P, C>
where
    C: ExpectedHelperCandidate,
    P: ExpectedHelperPeer<C>,
{
    pub(crate) fn cancel(&mut self) -> Result<(), ExpectedPeerRegistryError> {
        self.cancel_with_timeout(EXPECTED_HELPER_QUIESCENCE_TIMEOUT)
    }

    fn cancel_with_timeout(&mut self, timeout: Duration) -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission {
            inner: Arc::clone(&self.inner),
        };
        let outcome =
            admission.cancel_key_with_timeout(self.key, ExpectedPeerRegistryError::Denied, timeout);
        if outcome.result.is_ok() || outcome.delegated {
            self.armed = false;
        }
        outcome.result
    }

    /// Completes a server-admitted helper and terminally reaps its process.
    ///
    /// The role comes from the registry-owned launch proof. A live slot in any
    /// phase other than `Admitted` is still terminally retired, but can never
    /// produce a successful completion. The exact admitted peer must pass a
    /// fresh running revalidation before its role is extracted; cleanup still
    /// runs if that observation rejects or panics.
    pub(crate) fn finish_admitted_and_cancel(
        &mut self,
    ) -> Result<ExpectedHelperRole, ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission {
            inner: Arc::clone(&self.inner),
        };
        let outcome = admission.finish_admitted_key(self.key);
        if outcome.result.is_ok() || outcome.delegated {
            self.armed = false;
        }
        outcome.result
    }
}

impl<P, C> Drop for ExpectedHelperLease<P, C>
where
    C: ExpectedHelperCandidate,
    P: ExpectedHelperPeer<C>,
{
    fn drop(&mut self) {
        if self.armed {
            let admission = ExpectedHelperAdmission {
                inner: Arc::clone(&self.inner),
            };
            let outcome = admission.cancel_key(self.key, ExpectedPeerRegistryError::Denied);
            if !outcome.delegated {
                enforce_guard_drop_cleanup(outcome.result);
            }
        }
    }
}

impl<P, C> fmt::Debug for ExpectedHelperLease<P, C>
where
    C: ExpectedHelperCandidate,
    P: ExpectedHelperPeer<C>,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExpectedHelperLease([REDACTED])")
    }
}

fn scan_slots_are_structurally_exact<P>(
    slots: &[ExpectedPeerSlot<P>],
    peers: &[LocalPeer<P>],
) -> bool {
    peers.iter().all(|local| {
        matches!(
            slots.get(local.index),
            Some(ExpectedPeerSlot::InFlight {
                key,
                session_id,
                phase,
                generation,
                ..
            }) if *key == local.key
                && *session_id == local.session_id
                && *phase == local.original_phase
                && *generation == local.generation
        )
    })
}

fn scan_has_global_cancellation<P>(slots: &[ExpectedPeerSlot<P>], peers: &[LocalPeer<P>]) -> bool {
    peers.iter().any(|local| {
        matches!(
            slots.get(local.index),
            Some(ExpectedPeerSlot::InFlight {
                generation,
                global_cancel_requested: true,
                ..
            }) if *generation == local.generation
        )
    })
}

fn local_has_selective_session_cancellation<P>(
    slots: &[ExpectedPeerSlot<P>],
    local: &LocalPeer<P>,
) -> bool {
    matches!(
        slots.get(local.index),
        Some(ExpectedPeerSlot::InFlight {
            generation,
            cancel_requested: true,
            global_cancel_requested: false,
            ..
        }) if *generation == local.generation
    )
}

fn resolve_scan_result<T>(
    settlement: Result<bool, ExpectedPeerRegistryError>,
    operation: Result<T, ExpectedPeerRegistryError>,
) -> Result<T, ExpectedPeerRegistryError> {
    let targeted_cancellation = settlement?;
    if targeted_cancellation && operation.is_ok() {
        Err(ExpectedPeerRegistryError::Denied)
    } else {
        operation
    }
}

fn extract_live_slot<P>(
    slot: &mut ExpectedPeerSlot<P>,
    index: usize,
    generation: u64,
) -> Result<LocalPeer<P>, ExpectedPeerRegistryError> {
    let previous = core::mem::replace(slot, ExpectedPeerSlot::Vacant);
    let ExpectedPeerSlot::Live {
        key,
        session_id,
        phase,
        peer,
    } = previous
    else {
        *slot = previous;
        return Err(ExpectedPeerRegistryError::Internal);
    };
    let settlement = Arc::new(InFlightSettlement::new(key, generation));
    *slot = ExpectedPeerSlot::InFlight {
        key,
        session_id,
        phase,
        generation,
        cancel_requested: false,
        global_cancel_requested: false,
        settlement: Arc::clone(&settlement),
    };
    Ok(LocalPeer {
        index,
        key,
        session_id,
        generation,
        original_phase: phase,
        next_phase: Some(phase),
        peer,
        settlement: InFlightSettlementGuard {
            settlement,
            completed: false,
        },
    })
}

fn retire_live_slot<P>(slot: &mut ExpectedPeerSlot<P>) -> Option<P> {
    let previous = core::mem::replace(slot, ExpectedPeerSlot::Vacant);
    match previous {
        ExpectedPeerSlot::Live { key, peer, .. } => {
            *slot = ExpectedPeerSlot::Retired(key);
            Some(peer)
        }
        other => {
            *slot = other;
            None
        }
    }
}

fn request_global_cancellation(cancel_requested: &mut bool, global_cancel_requested: &mut bool) {
    *cancel_requested = true;
    *global_cancel_requested = true;
}

fn request_selective_session_cancellation(cancel_requested: &mut bool) {
    *cancel_requested = true;
}

fn request_in_flight_cancellation_and_retire_live<P>(slots: &mut [ExpectedPeerSlot<P>]) -> Vec<P> {
    let mut cleanup = Vec::with_capacity(EXPECTED_HELPER_CAPACITY);
    for slot in slots {
        match slot {
            ExpectedPeerSlot::InFlight {
                cancel_requested,
                global_cancel_requested,
                ..
            } => request_global_cancellation(cancel_requested, global_cancel_requested),
            ExpectedPeerSlot::Live { .. } => {
                if let Some(peer) = retire_live_slot(slot) {
                    cleanup.push(peer);
                }
            }
            ExpectedPeerSlot::Vacant | ExpectedPeerSlot::Retired(_) => {}
        }
    }
    cleanup
}

fn request_selected_session_cancellation_and_retire_live<P, F>(
    slots: &mut [ExpectedPeerSlot<P>],
    selected: F,
    global: bool,
) -> (Vec<P>, Vec<InFlightCancellation>)
where
    F: Fn(NonZeroU32) -> bool,
{
    let mut cleanup = Vec::with_capacity(EXPECTED_HELPER_CAPACITY);
    let mut in_flight = Vec::with_capacity(EXPECTED_HELPER_CAPACITY);
    for slot in slots {
        let selected_session = match slot_session_id(slot) {
            Some(session_id) => selected(session_id),
            None => false,
        };
        if !selected_session {
            continue;
        }
        match slot {
            ExpectedPeerSlot::InFlight {
                key,
                generation,
                cancel_requested,
                global_cancel_requested,
                settlement,
                ..
            } => {
                if global {
                    request_global_cancellation(cancel_requested, global_cancel_requested);
                } else {
                    request_selective_session_cancellation(cancel_requested);
                }
                in_flight.push(InFlightCancellation {
                    key: *key,
                    generation: *generation,
                    settlement: Arc::clone(settlement),
                });
            }
            ExpectedPeerSlot::Live { .. } => {
                if let Some(peer) = retire_live_slot(slot) {
                    cleanup.push(peer);
                }
            }
            ExpectedPeerSlot::Vacant | ExpectedPeerSlot::Retired(_) => {}
        }
    }
    (cleanup, in_flight)
}

fn settle_invalidated_owners<P, C>(
    cleanup: Vec<P>,
    in_flight: Vec<InFlightCancellation>,
) -> Result<(), ExpectedPeerRegistryError>
where
    C: ExpectedHelperCandidate,
    P: ExpectedHelperPeer<C>,
{
    let cleanup = cleanup_peers::<P, C>(cleanup);
    let settled = wait_for_cancellations(in_flight, EXPECTED_HELPER_QUIESCENCE_TIMEOUT);
    cleanup.and(settled)
}

fn quarantine_contains(
    quarantined: &[Option<NonZeroU32>; EXPECTED_HELPER_SESSION_QUARANTINE_CAPACITY],
    session_id: NonZeroU32,
) -> bool {
    quarantined.contains(&Some(session_id))
}

fn quarantine_insert(
    quarantined: &mut [Option<NonZeroU32>; EXPECTED_HELPER_SESSION_QUARANTINE_CAPACITY],
    session_id: NonZeroU32,
) -> bool {
    if quarantine_contains(quarantined, session_id) {
        return true;
    }
    let Some(vacant) = quarantined.iter_mut().find(|entry| entry.is_none()) else {
        return false;
    };
    *vacant = Some(session_id);
    true
}

fn slot_key<P>(slot: &ExpectedPeerSlot<P>) -> Option<ExpectedPeerKey> {
    match slot {
        ExpectedPeerSlot::Live { key, .. }
        | ExpectedPeerSlot::InFlight { key, .. }
        | ExpectedPeerSlot::Retired(key) => Some(*key),
        ExpectedPeerSlot::Vacant => None,
    }
}

fn slot_session_id<P>(slot: &ExpectedPeerSlot<P>) -> Option<NonZeroU32> {
    match slot {
        ExpectedPeerSlot::Live { session_id, .. }
        | ExpectedPeerSlot::InFlight { session_id, .. } => Some(*session_id),
        ExpectedPeerSlot::Vacant | ExpectedPeerSlot::Retired(_) => None,
    }
}

fn retire_all<P>(peers: &mut [LocalPeer<P>]) {
    for local in peers {
        local.next_phase = None;
    }
}

fn deadline_after(timeout: Duration) -> Result<Instant, ExpectedPeerRegistryError> {
    Instant::now()
        .checked_add(timeout)
        .ok_or(ExpectedPeerRegistryError::Internal)
}

fn wait_for_cancellations(
    cancellations: Vec<InFlightCancellation>,
    timeout: Duration,
) -> Result<(), ExpectedPeerRegistryError> {
    if cancellations.is_empty() {
        return Ok(());
    }
    let deadline = deadline_after(timeout)?;
    let mut result = Ok(());
    for cancellation in cancellations {
        result = result.and(cancellation.wait_until(deadline));
    }
    result
}

fn cleanup_peer<P, C>(peer: &mut P) -> Result<(), ExpectedPeerRegistryError>
where
    C: ExpectedHelperCandidate,
    P: ExpectedHelperPeer<C>,
{
    peer.cancel().map_err(map_verification_error)
}

fn cleanup_peers<P, C>(peers: Vec<P>) -> Result<(), ExpectedPeerRegistryError>
where
    C: ExpectedHelperCandidate,
    P: ExpectedHelperPeer<C>,
{
    let mut result = Ok(());
    for mut peer in peers {
        result = result.and(cleanup_peer::<P, C>(&mut peer));
        drop(peer);
    }
    result
}

fn lock_expected_state<P, C>(
    inner: &ExpectedPeerInner<P, C>,
) -> Result<MutexGuard<'_, ExpectedPeerState<P>>, ExpectedPeerRegistryError>
where
    C: ExpectedHelperCandidate,
    P: ExpectedHelperPeer<C>,
{
    match inner.state.lock() {
        Ok(state) => Ok(state),
        Err(poisoned) => {
            let mut state = poisoned.into_inner();
            state.stopping = true;
            let mut cleanup = Vec::with_capacity(EXPECTED_HELPER_CAPACITY);
            for slot in &mut state.slots {
                match slot {
                    ExpectedPeerSlot::Live { .. } => {
                        if let Some(peer) = retire_live_slot(slot) {
                            cleanup.push(peer);
                        }
                    }
                    ExpectedPeerSlot::InFlight {
                        cancel_requested,
                        global_cancel_requested,
                        ..
                    } => request_global_cancellation(cancel_requested, global_cancel_requested),
                    ExpectedPeerSlot::Vacant | ExpectedPeerSlot::Retired(_) => {}
                }
            }
            drop(state);
            let _ = cleanup_peers::<P, C>(cleanup);
            // Resident peers were terminally extracted. Clear the poison so a
            // surviving guard can observe its Retired slot instead of treating
            // already-completed cleanup as an unresolved in-flight owner.
            inner.state.clear_poison();
            Err(ExpectedPeerRegistryError::Internal)
        }
    }
}

const fn map_verification_error(error: ExpectedPeerVerificationError) -> ExpectedPeerRegistryError {
    match error {
        ExpectedPeerVerificationError::Denied => ExpectedPeerRegistryError::Denied,
        ExpectedPeerVerificationError::Internal => ExpectedPeerRegistryError::Internal,
    }
}

fn enforce_guard_drop_cleanup(result: Result<(), ExpectedPeerRegistryError>) {
    if matches!(
        result,
        Err(ExpectedPeerRegistryError::Internal | ExpectedPeerRegistryError::Stopping)
    ) {
        // A guard may observe `Denied` after its fixed slot was terminally
        // retired by manager admission or concurrent cleanup. `Internal` or
        // `Stopping` cannot prove that, so Drop must never claim quiet success.
        fail_fast_unsettled_guard();
    }
}

#[cfg(not(test))]
fn fail_fast_unsettled_guard() -> ! {
    std::process::abort()
}

#[cfg(test)]
#[allow(clippy::panic)]
fn fail_fast_unsettled_guard() -> ! {
    panic!("expected-helper guard dropped before terminal cleanup")
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Barrier, mpsc};
    use std::thread;
    use std::time::Duration;

    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        Candidate,
        Suspended,
        Resume,
        Match,
        Running,
        Cancel,
        Drop,
    }

    #[derive(Clone)]
    struct Trace(Arc<Mutex<Vec<Event>>>);

    impl Trace {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(Vec::new())))
        }

        fn push(&self, event: Event) {
            if let Ok(mut events) = self.0.lock() {
                events.push(event);
            }
        }
    }

    struct FakeCandidate {
        identity: u8,
        valid: bool,
        trace: Trace,
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum TerminalFinishPanic {
        Running,
        Role,
    }

    impl ExpectedHelperCandidate for FakeCandidate {
        fn revalidate(&self) -> Result<(), ExpectedPeerVerificationError> {
            self.trace.push(Event::Candidate);
            self.valid
                .then_some(())
                .ok_or(ExpectedPeerVerificationError::Denied)
        }
    }

    struct FakePeer {
        key: ExpectedPeerKey,
        session_id: NonZeroU32,
        identity: u8,
        role: ExpectedHelperRole,
        fail: Option<Event>,
        resumed: bool,
        trace: Trace,
        drops: Arc<AtomicU32>,
        match_pause: Option<Arc<Barrier>>,
        suspended_pause: Option<Arc<Barrier>>,
        resume_pause: Option<Arc<Barrier>>,
        cancel_pause: Option<Arc<Barrier>>,
        panic_on_match: bool,
        finish_panic: Option<TerminalFinishPanic>,
    }

    impl Drop for FakePeer {
        fn drop(&mut self) {
            self.trace.push(Event::Drop);
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl ExpectedHelperPeer<FakeCandidate> for FakePeer {
        fn key(&self) -> ExpectedPeerKey {
            self.key
        }

        fn session_id(&self) -> NonZeroU32 {
            self.session_id
        }

        fn role(&self) -> ExpectedHelperRole {
            assert!(
                self.finish_panic != Some(TerminalFinishPanic::Role),
                "peer role panic for terminal-finish test"
            );
            self.role
        }

        fn revalidate_suspended(&self) -> Result<(), ExpectedPeerVerificationError> {
            self.trace.push(Event::Suspended);
            if let Some(pause) = &self.suspended_pause {
                pause.wait();
                pause.wait();
            }
            (self.fail != Some(Event::Suspended))
                .then_some(())
                .ok_or(ExpectedPeerVerificationError::Denied)
        }

        fn resume_once(&mut self) -> Result<(), ExpectedPeerVerificationError> {
            self.trace.push(Event::Resume);
            if let Some(pause) = &self.resume_pause {
                pause.wait();
                pause.wait();
            }
            if self.resumed || self.fail == Some(Event::Resume) {
                return Err(ExpectedPeerVerificationError::Denied);
            }
            self.resumed = true;
            Ok(())
        }

        fn exactly_matches(
            &self,
            candidate: &FakeCandidate,
        ) -> Result<bool, ExpectedPeerVerificationError> {
            self.trace.push(Event::Match);
            assert!(
                !self.panic_on_match,
                "peer match panic for terminal-drop test"
            );
            if let Some(pause) = &self.match_pause {
                pause.wait();
                pause.wait();
            }
            if self.fail == Some(Event::Match) {
                Err(ExpectedPeerVerificationError::Internal)
            } else {
                Ok(self.identity == candidate.identity)
            }
        }

        fn revalidate_running(&self) -> Result<(), ExpectedPeerVerificationError> {
            self.trace.push(Event::Running);
            assert!(
                self.finish_panic != Some(TerminalFinishPanic::Running),
                "peer running panic for terminal-finish test"
            );
            (self.resumed && self.fail != Some(Event::Running))
                .then_some(())
                .ok_or(ExpectedPeerVerificationError::Denied)
        }

        fn cancel(&mut self) -> Result<(), ExpectedPeerVerificationError> {
            self.trace.push(Event::Cancel);
            if let Some(pause) = &self.cancel_pause {
                pause.wait();
                pause.wait();
            }
            (self.fail != Some(Event::Cancel))
                .then_some(())
                .ok_or(ExpectedPeerVerificationError::Internal)
        }
    }

    fn key(marker: u8) -> Result<ExpectedPeerKey, ExpectedPeerRegistryError> {
        Ok(ExpectedPeerKey::new(
            EpochNonce::new([marker; 32]).map_err(|_| ExpectedPeerRegistryError::Internal)?,
            ServiceRequestId::new([marker; 16]).map_err(|_| ExpectedPeerRegistryError::Internal)?,
        ))
    }

    fn session_id(value: u32) -> Result<NonZeroU32, ExpectedPeerRegistryError> {
        NonZeroU32::new(value).ok_or(ExpectedPeerRegistryError::Internal)
    }

    fn peer(
        marker: u8,
        identity: u8,
        role: ExpectedHelperRole,
        trace: &Trace,
        drops: &Arc<AtomicU32>,
    ) -> Result<FakePeer, ExpectedPeerRegistryError> {
        Ok(FakePeer {
            key: key(marker)?,
            session_id: NonZeroU32::new(u32::from(identity))
                .ok_or(ExpectedPeerRegistryError::Internal)?,
            identity,
            role,
            fail: None,
            resumed: false,
            trace: trace.clone(),
            drops: Arc::clone(drops),
            match_pause: None,
            suspended_pause: None,
            resume_pause: None,
            cancel_pause: None,
            panic_on_match: false,
            finish_panic: None,
        })
    }

    fn mutate_admitted_peer(
        admission: &ExpectedHelperAdmission<FakePeer, FakeCandidate>,
        expected_key: ExpectedPeerKey,
        mutation: impl FnOnce(&mut FakePeer),
    ) -> Result<(), ExpectedPeerRegistryError> {
        let mut state = admission
            .inner
            .state
            .lock()
            .map_err(|_| ExpectedPeerRegistryError::Internal)?;
        let selected = state
            .slots
            .iter_mut()
            .find(|slot| slot_key(slot) == Some(expected_key));
        let Some(ExpectedPeerSlot::Live {
            peer,
            phase: PeerPhase::Admitted,
            ..
        }) = selected
        else {
            return Err(ExpectedPeerRegistryError::Internal);
        };
        mutation(peer);
        Ok(())
    }

    fn candidate(marker: u8, valid: bool, trace: &Trace) -> FakeCandidate {
        FakeCandidate {
            identity: marker,
            valid,
            trace: trace.clone(),
        }
    }

    fn wait_for_cancel_request(
        admission: &ExpectedHelperAdmission<FakePeer, FakeCandidate>,
        expected_key: ExpectedPeerKey,
    ) -> Result<(), ExpectedPeerRegistryError> {
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(1))
            .ok_or(ExpectedPeerRegistryError::Internal)?;
        loop {
            let state = admission
                .inner
                .state
                .lock()
                .map_err(|_| ExpectedPeerRegistryError::Internal)?;
            let requested = state.slots.iter().any(|slot| {
                matches!(
                    slot,
                    ExpectedPeerSlot::InFlight {
                        key,
                        cancel_requested: true,
                        ..
                    } if *key == expected_key
                )
            });
            drop(state);
            if requested {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(ExpectedPeerRegistryError::Internal);
            }
            thread::yield_now();
        }
    }

    fn is_in_flight(
        admission: &ExpectedHelperAdmission<FakePeer, FakeCandidate>,
        expected_key: ExpectedPeerKey,
    ) -> Result<bool, ExpectedPeerRegistryError> {
        let state = admission
            .inner
            .state
            .lock()
            .map_err(|_| ExpectedPeerRegistryError::Internal)?;
        Ok(state.slots.iter().any(|slot| {
            matches!(
                slot,
                ExpectedPeerSlot::InFlight { key, .. } if *key == expected_key
            )
        }))
    }

    fn in_flight_cancellation_scope(
        admission: &ExpectedHelperAdmission<FakePeer, FakeCandidate>,
        expected_key: ExpectedPeerKey,
        expected_session: NonZeroU32,
    ) -> Result<Option<(bool, bool)>, ExpectedPeerRegistryError> {
        let state = admission
            .inner
            .state
            .lock()
            .map_err(|_| ExpectedPeerRegistryError::Internal)?;
        Ok(state.slots.iter().find_map(|slot| match slot {
            ExpectedPeerSlot::InFlight {
                key,
                session_id,
                cancel_requested,
                global_cancel_requested,
                ..
            } if *key == expected_key && *session_id == expected_session => {
                Some((*cancel_requested, *global_cancel_requested))
            }
            _ => None,
        }))
    }

    fn live_phase(
        admission: &ExpectedHelperAdmission<FakePeer, FakeCandidate>,
        expected_key: ExpectedPeerKey,
        expected_session: NonZeroU32,
    ) -> Result<Option<PeerPhase>, ExpectedPeerRegistryError> {
        let state = admission
            .inner
            .state
            .lock()
            .map_err(|_| ExpectedPeerRegistryError::Internal)?;
        Ok(state.slots.iter().find_map(|slot| match slot {
            ExpectedPeerSlot::Live {
                key,
                session_id,
                phase,
                ..
            } if *key == expected_key && *session_id == expected_session => Some(*phase),
            _ => None,
        }))
    }

    fn assert_selective_invalidation_preserves_terminal_rejection()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let scan_pause = Arc::new(Barrier::new(2));
        let mut invalidated = peer(15, 15, ExpectedHelperRole::Approval, &trace, &drops)?;
        invalidated.session_id = session_id(81)?;
        invalidated.match_pause = Some(Arc::clone(&scan_pause));
        let invalidated = admission
            .register_suspended(invalidated)?
            .revalidate_and_resume_once()?;
        let mut malformed = peer(16, 16, ExpectedHelperRole::SecretInput, &trace, &drops)?;
        malformed.session_id = session_id(82)?;
        let malformed = admission
            .register_suspended(malformed)?
            .revalidate_and_resume_once()?;

        let rejection_admission = admission.clone();
        let rejection_trace = trace.clone();
        let rejection = thread::spawn(move || {
            rejection_admission.reject_manager_candidate(&candidate(16, true, &rejection_trace))
        });
        scan_pause.wait();
        let invalidation_admission = admission.clone();
        let invalidated_session = session_id(81)?;
        let invalidation =
            thread::spawn(move || invalidation_admission.invalidate_session(invalidated_session));
        wait_for_cancel_request(&admission, key(15)?)?;
        scan_pause.wait();

        assert_eq!(
            rejection
                .join()
                .map_err(|_| ExpectedPeerRegistryError::Internal)?,
            Err(ExpectedPeerRegistryError::Denied)
        );
        assert_eq!(
            invalidation
                .join()
                .map_err(|_| ExpectedPeerRegistryError::Internal)?,
            Ok(())
        );
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        assert_eq!(
            admission.observe_callback(&candidate(16, true, &trace)),
            Err(ExpectedPeerRegistryError::Denied)
        );
        drop(invalidated);
        drop(malformed);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[test]
    fn callback_is_non_consuming_and_manager_is_exactly_once()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let lease = admission
            .register_suspended(peer(1, 1, ExpectedHelperRole::Approval, &trace, &drops)?)?
            .revalidate_and_resume_once()?;
        let observed = candidate(1, true, &trace);
        assert_eq!(
            admission.observe_callback(&observed),
            Ok(ExpectedHelperRole::Approval)
        );
        assert_eq!(
            admission.observe_callback(&observed),
            Ok(ExpectedHelperRole::Approval)
        );
        assert_eq!(
            admission.consume_manager(key(1)?, &observed),
            Ok(ExpectedHelperRole::Approval)
        );
        assert_eq!(
            admission.consume_manager(key(1)?, &observed),
            Err(ExpectedPeerRegistryError::Denied)
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        drop(lease);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn admitted_finish_returns_server_role_and_is_exactly_once()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let mut lease = admission
            .register_suspended(peer(
                21,
                21,
                ExpectedHelperRole::SecretInput,
                &trace,
                &drops,
            )?)?
            .revalidate_and_resume_once()?;

        assert_eq!(
            admission.consume_manager(key(21)?, &candidate(21, true, &trace)),
            Ok(ExpectedHelperRole::SecretInput)
        );
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert_eq!(
            lease.finish_admitted_and_cancel(),
            Ok(ExpectedHelperRole::SecretInput)
        );
        assert_eq!(
            lease.finish_admitted_and_cancel(),
            Err(ExpectedPeerRegistryError::Denied)
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        let cancel_count = trace
            .0
            .lock()
            .map_err(|_| ExpectedPeerRegistryError::Internal)?
            .iter()
            .filter(|event| **event == Event::Cancel)
            .count();
        assert_eq!(cancel_count, 1);
        drop(lease);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn finish_before_manager_admission_is_denied_and_terminal()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let mut lease = admission
            .register_suspended(peer(22, 22, ExpectedHelperRole::Approval, &trace, &drops)?)?
            .revalidate_and_resume_once()?;

        assert_eq!(
            lease.finish_admitted_and_cancel(),
            Err(ExpectedPeerRegistryError::Denied)
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(
            admission.consume_manager(key(22)?, &candidate(22, true, &trace)),
            Err(ExpectedPeerRegistryError::Denied)
        );
        drop(lease);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn registered_phase_cannot_be_finished_as_admitted() -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let registered = admission.register_suspended(peer(
            23,
            23,
            ExpectedHelperRole::SecretInput,
            &trace,
            &drops,
        )?)?;
        let mut lease = ExpectedHelperLease {
            inner: Arc::clone(&admission.inner),
            key: key(23)?,
            armed: true,
        };

        assert_eq!(
            lease.finish_admitted_and_cancel(),
            Err(ExpectedPeerRegistryError::Denied)
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        drop(lease);
        drop(registered);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn admitted_finish_cleanup_error_dominates_role_success()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let mut failing = peer(24, 24, ExpectedHelperRole::Approval, &trace, &drops)?;
        failing.fail = Some(Event::Cancel);
        let mut lease = admission
            .register_suspended(failing)?
            .revalidate_and_resume_once()?;
        assert_eq!(
            admission.consume_manager(key(24)?, &candidate(24, true, &trace)),
            Ok(ExpectedHelperRole::Approval)
        );

        assert_eq!(
            lease.finish_admitted_and_cancel(),
            Err(ExpectedPeerRegistryError::Internal)
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        drop(lease);
        Ok(())
    }

    #[test]
    fn admitted_finish_revalidates_fresh_peer_before_terminal_cleanup()
    -> Result<(), ExpectedPeerRegistryError> {
        for role in [
            ExpectedHelperRole::Approval,
            ExpectedHelperRole::SecretInput,
        ] {
            let admission = ExpectedHelperAdmission::new();
            let trace = Trace::new();
            let drops = Arc::new(AtomicU32::new(0));
            let mut lease = admission
                .register_suspended(peer(24, 24, role, &trace, &drops)?)?
                .revalidate_and_resume_once()?;
            assert_eq!(
                admission.consume_manager(key(24)?, &candidate(24, true, &trace)),
                Ok(role)
            );
            trace
                .0
                .lock()
                .map_err(|_| ExpectedPeerRegistryError::Internal)?
                .clear();

            assert_eq!(lease.finish_admitted_and_cancel(), Ok(role));
            assert_eq!(
                *trace
                    .0
                    .lock()
                    .map_err(|_| ExpectedPeerRegistryError::Internal)?,
                [Event::Running, Event::Cancel, Event::Drop]
            );
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            drop(lease);
        }
        Ok(())
    }

    #[test]
    fn admitted_finish_rejects_stale_or_dead_peer_and_never_extracts_role()
    -> Result<(), ExpectedPeerRegistryError> {
        for dead in [false, true] {
            let admission = ExpectedHelperAdmission::new();
            let trace = Trace::new();
            let drops = Arc::new(AtomicU32::new(0));
            let mut lease = admission
                .register_suspended(peer(24, 24, ExpectedHelperRole::Approval, &trace, &drops)?)?
                .revalidate_and_resume_once()?;
            assert_eq!(
                admission.consume_manager(key(24)?, &candidate(24, true, &trace)),
                Ok(ExpectedHelperRole::Approval)
            );
            mutate_admitted_peer(&admission, key(24)?, |peer| {
                if dead {
                    peer.resumed = false;
                } else {
                    peer.fail = Some(Event::Running);
                }
                peer.finish_panic = Some(TerminalFinishPanic::Role);
            })?;
            trace
                .0
                .lock()
                .map_err(|_| ExpectedPeerRegistryError::Internal)?
                .clear();

            assert_eq!(
                lease.finish_admitted_and_cancel(),
                Err(ExpectedPeerRegistryError::Denied)
            );
            assert_eq!(
                *trace
                    .0
                    .lock()
                    .map_err(|_| ExpectedPeerRegistryError::Internal)?,
                [Event::Running, Event::Cancel, Event::Drop]
            );
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(
                admission.consume_manager(key(24)?, &candidate(24, true, &trace)),
                Err(ExpectedPeerRegistryError::Denied)
            );
            drop(lease);
        }
        Ok(())
    }

    #[test]
    fn admitted_finish_cleanup_error_dominates_failed_fresh_revalidation()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let mut lease = admission
            .register_suspended(peer(24, 24, ExpectedHelperRole::Approval, &trace, &drops)?)?
            .revalidate_and_resume_once()?;
        assert_eq!(
            admission.consume_manager(key(24)?, &candidate(24, true, &trace)),
            Ok(ExpectedHelperRole::Approval)
        );
        mutate_admitted_peer(&admission, key(24)?, |peer| {
            peer.resumed = false;
            peer.fail = Some(Event::Cancel);
            peer.finish_panic = Some(TerminalFinishPanic::Role);
        })?;
        trace
            .0
            .lock()
            .map_err(|_| ExpectedPeerRegistryError::Internal)?
            .clear();

        assert_eq!(
            lease.finish_admitted_and_cancel(),
            Err(ExpectedPeerRegistryError::Internal)
        );
        assert_eq!(
            *trace
                .0
                .lock()
                .map_err(|_| ExpectedPeerRegistryError::Internal)?,
            [Event::Running, Event::Cancel, Event::Drop]
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        drop(lease);
        Ok(())
    }

    #[test]
    fn admitted_finish_revalidation_or_role_panic_still_cleans_up()
    -> Result<(), ExpectedPeerRegistryError> {
        for panic_on_running in [true, false] {
            let admission = ExpectedHelperAdmission::new();
            let trace = Trace::new();
            let drops = Arc::new(AtomicU32::new(0));
            let mut lease = admission
                .register_suspended(peer(24, 24, ExpectedHelperRole::Approval, &trace, &drops)?)?
                .revalidate_and_resume_once()?;
            assert_eq!(
                admission.consume_manager(key(24)?, &candidate(24, true, &trace)),
                Ok(ExpectedHelperRole::Approval)
            );
            mutate_admitted_peer(&admission, key(24)?, |peer| {
                peer.finish_panic = Some(if panic_on_running {
                    TerminalFinishPanic::Running
                } else {
                    TerminalFinishPanic::Role
                });
            })?;
            trace
                .0
                .lock()
                .map_err(|_| ExpectedPeerRegistryError::Internal)?
                .clear();

            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    lease.finish_admitted_and_cancel()
                }))
                .is_err()
            );
            assert_eq!(
                *trace
                    .0
                    .lock()
                    .map_err(|_| ExpectedPeerRegistryError::Internal)?,
                [Event::Running, Event::Cancel, Event::Drop]
            );
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(
                admission.consume_manager(key(24)?, &candidate(24, true, &trace)),
                Err(ExpectedPeerRegistryError::Denied)
            );
            drop(lease);
        }
        Ok(())
    }

    #[test]
    fn in_flight_finish_is_not_success_and_requests_terminal_cleanup()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let pause = Arc::new(Barrier::new(2));
        let mut helper = peer(25, 25, ExpectedHelperRole::Approval, &trace, &drops)?;
        helper.match_pause = Some(Arc::clone(&pause));
        let mut lease = admission
            .register_suspended(helper)?
            .revalidate_and_resume_once()?;
        let worker_admission = admission.clone();
        let worker_trace = trace.clone();
        let worker = thread::spawn(move || {
            worker_admission.consume_manager(key(25)?, &candidate(25, true, &worker_trace))
        });

        pause.wait();
        let (finish_sent, finish_received) = mpsc::channel();
        let finish = thread::spawn(move || {
            let result = lease.finish_admitted_and_cancel();
            let dropped =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(lease))).is_ok();
            let _ = finish_sent.send((result, dropped));
        });
        wait_for_cancel_request(&admission, key(25)?)?;
        let expected_key = key(25)?;
        let state = admission
            .inner
            .state
            .lock()
            .map_err(|_| ExpectedPeerRegistryError::Internal)?;
        assert!(state.slots.iter().any(|slot| {
            matches!(
                slot,
                ExpectedPeerSlot::InFlight {
                    key: stored_key,
                    cancel_requested: true,
                    global_cancel_requested: true,
                    ..
                } if *stored_key == expected_key
            )
        }));
        drop(state);
        assert!(
            finish_received
                .recv_timeout(Duration::from_millis(25))
                .is_err()
        );
        pause.wait();
        assert_eq!(
            worker
                .join()
                .map_err(|_| ExpectedPeerRegistryError::Internal)?,
            Err(ExpectedPeerRegistryError::Internal)
        );
        assert_eq!(
            finish_received
                .recv_timeout(Duration::from_secs(1))
                .map_err(|_| ExpectedPeerRegistryError::Internal)?,
            (Err(ExpectedPeerRegistryError::Internal), true)
        );
        finish
            .join()
            .map_err(|_| ExpectedPeerRegistryError::Internal)?;
        assert!(!is_in_flight(&admission, key(25)?)?);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn admitted_finish_cancels_outside_registry_mutex() -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let pause = Arc::new(Barrier::new(2));
        let mut helper = peer(26, 26, ExpectedHelperRole::Approval, &trace, &drops)?;
        helper.cancel_pause = Some(Arc::clone(&pause));
        let mut lease = admission
            .register_suspended(helper)?
            .revalidate_and_resume_once()?;
        assert_eq!(
            admission.consume_manager(key(26)?, &candidate(26, true, &trace)),
            Ok(ExpectedHelperRole::Approval)
        );

        let (finish_sent, finish_received) = mpsc::channel();
        let finish = thread::spawn(move || {
            let result = lease.finish_admitted_and_cancel();
            let _ = finish_sent.send(result);
        });
        pause.wait();

        let registration_admission = admission.clone();
        let registration_trace = trace.clone();
        let registration_drops = Arc::clone(&drops);
        let (registration_sent, registration_received) = mpsc::channel();
        let registration = thread::spawn(move || {
            let result = peer(
                27,
                27,
                ExpectedHelperRole::SecretInput,
                &registration_trace,
                &registration_drops,
            )
            .and_then(|peer| registration_admission.register_suspended(peer));
            let _ = registration_sent.send(result);
        });
        let early_registration = registration_received.recv_timeout(Duration::from_millis(25));
        let completed_while_cancel_blocked = early_registration.is_ok();
        pause.wait();
        let registered = match early_registration {
            Ok(result) => result?,
            Err(mpsc::RecvTimeoutError::Timeout) => registration_received
                .recv_timeout(Duration::from_secs(1))
                .map_err(|_| ExpectedPeerRegistryError::Internal)??,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(ExpectedPeerRegistryError::Internal);
            }
        };
        assert!(completed_while_cancel_blocked);
        assert_eq!(
            finish_received
                .recv_timeout(Duration::from_secs(1))
                .map_err(|_| ExpectedPeerRegistryError::Internal)?,
            Ok(ExpectedHelperRole::Approval)
        );
        finish
            .join()
            .map_err(|_| ExpectedPeerRegistryError::Internal)?;
        registration
            .join()
            .map_err(|_| ExpectedPeerRegistryError::Internal)?;
        drop(registered);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[test]
    fn activation_and_candidate_failures_are_terminal_where_required()
    -> Result<(), ExpectedPeerRegistryError> {
        for failure in [Event::Suspended, Event::Resume] {
            let admission = ExpectedHelperAdmission::new();
            let trace = Trace::new();
            let drops = Arc::new(AtomicU32::new(0));
            let mut failing = peer(2, 2, ExpectedHelperRole::SecretInput, &trace, &drops)?;
            failing.fail = Some(failure);
            let registered = admission.register_suspended(failing)?;
            assert_eq!(
                registered.revalidate_and_resume_once().map(|_| ()),
                Err(ExpectedPeerRegistryError::Denied)
            );
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        }

        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let lease = admission
            .register_suspended(peer(3, 3, ExpectedHelperRole::Approval, &trace, &drops)?)?
            .revalidate_and_resume_once()?;
        assert_eq!(
            admission.observe_callback(&candidate(3, false, &trace)),
            Err(ExpectedPeerRegistryError::Denied)
        );
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert_eq!(
            admission.consume_manager(key(3)?, &candidate(3, false, &trace)),
            Err(ExpectedPeerRegistryError::Denied)
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        drop(lease);
        Ok(())
    }

    #[test]
    fn manager_candidate_rejection_retires_one_exact_running_peer()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let lease = admission
            .register_suspended(peer(12, 12, ExpectedHelperRole::Approval, &trace, &drops)?)?
            .revalidate_and_resume_once()?;

        assert_eq!(
            admission.reject_manager_candidate(&candidate(12, true, &trace)),
            Ok(())
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        drop(lease);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn manager_candidate_rejection_no_match_preserves_unrelated_peer()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let lease = admission
            .register_suspended(peer(
                13,
                13,
                ExpectedHelperRole::SecretInput,
                &trace,
                &drops,
            )?)?
            .revalidate_and_resume_once()?;

        assert_eq!(
            admission.reject_manager_candidate(&candidate(14, true, &trace)),
            Err(ExpectedPeerRegistryError::Denied)
        );
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert_eq!(
            admission.consume_manager(key(13)?, &candidate(13, true, &trace)),
            Ok(ExpectedHelperRole::SecretInput)
        );
        drop(lease);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn manager_candidate_revalidation_failure_still_retires_exact_peer()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let lease = admission
            .register_suspended(peer(15, 15, ExpectedHelperRole::Approval, &trace, &drops)?)?
            .revalidate_and_resume_once()?;

        assert_eq!(
            admission.reject_manager_candidate(&candidate(15, false, &trace)),
            Err(ExpectedPeerRegistryError::Denied)
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        drop(lease);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn manager_candidate_rejection_retires_ambiguous_matches()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let first = admission
            .register_suspended(peer(16, 18, ExpectedHelperRole::Approval, &trace, &drops)?)?
            .revalidate_and_resume_once()?;
        let second = admission
            .register_suspended(peer(
                17,
                18,
                ExpectedHelperRole::SecretInput,
                &trace,
                &drops,
            )?)?
            .revalidate_and_resume_once()?;

        assert_eq!(
            admission.reject_manager_candidate(&candidate(18, true, &trace)),
            Err(ExpectedPeerRegistryError::Internal)
        );
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        drop(first);
        drop(second);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[test]
    fn manager_candidate_rejection_retires_query_failure_and_preserves_nonmatch()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let mut failing = peer(19, 19, ExpectedHelperRole::Approval, &trace, &drops)?;
        failing.fail = Some(Event::Match);
        let failing_lease = admission
            .register_suspended(failing)?
            .revalidate_and_resume_once()?;
        let unrelated_lease = admission
            .register_suspended(peer(
                20,
                20,
                ExpectedHelperRole::SecretInput,
                &trace,
                &drops,
            )?)?
            .revalidate_and_resume_once()?;

        assert_eq!(
            admission.reject_manager_candidate(&candidate(19, true, &trace)),
            Err(ExpectedPeerRegistryError::Internal)
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(
            admission.consume_manager(key(20)?, &candidate(20, true, &trace)),
            Ok(ExpectedHelperRole::SecretInput)
        );
        drop(failing_lease);
        drop(unrelated_lease);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[test]
    fn manager_candidate_rejection_cleanup_error_dominates_success()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let mut failing = peer(21, 21, ExpectedHelperRole::Approval, &trace, &drops)?;
        failing.fail = Some(Event::Cancel);
        let lease = admission
            .register_suspended(failing)?
            .revalidate_and_resume_once()?;

        assert_eq!(
            admission.reject_manager_candidate(&candidate(21, true, &trace)),
            Err(ExpectedPeerRegistryError::Internal)
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        drop(lease);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn manager_candidate_rejection_panic_retires_indeterminate_peers()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let mut panicking = peer(22, 22, ExpectedHelperRole::Approval, &trace, &drops)?;
        panicking.panic_on_match = true;
        let panicking_lease = admission
            .register_suspended(panicking)?
            .revalidate_and_resume_once()?;
        let other_lease = admission
            .register_suspended(peer(
                23,
                23,
                ExpectedHelperRole::SecretInput,
                &trace,
                &drops,
            )?)?
            .revalidate_and_resume_once()?;

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = admission.reject_manager_candidate(&candidate(22, true, &trace));
        }));
        assert!(outcome.is_err());
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        assert_eq!(admission.stop(), Ok(()));
        drop(panicking_lease);
        drop(other_lease);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[test]
    fn manager_candidate_rejection_registration_race_retires_every_owner()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let pause = Arc::new(Barrier::new(2));
        let mut slow = peer(24, 24, ExpectedHelperRole::Approval, &trace, &drops)?;
        slow.match_pause = Some(Arc::clone(&pause));
        let lease = admission
            .register_suspended(slow)?
            .revalidate_and_resume_once()?;
        let worker_admission = admission.clone();
        let worker_trace = trace.clone();
        let worker = thread::spawn(move || {
            worker_admission.reject_manager_candidate(&candidate(24, true, &worker_trace))
        });

        pause.wait();
        let raced = admission.register_suspended(peer(
            25,
            25,
            ExpectedHelperRole::SecretInput,
            &trace,
            &drops,
        )?)?;
        pause.wait();
        assert_eq!(
            worker
                .join()
                .map_err(|_| ExpectedPeerRegistryError::Internal)?,
            Err(ExpectedPeerRegistryError::Internal)
        );
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        drop(raced);
        drop(lease);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[test]
    fn retired_replay_preserves_unrelated_expected_running_peer()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let first_lease = admission
            .register_suspended(peer(1, 1, ExpectedHelperRole::Approval, &trace, &drops)?)?
            .revalidate_and_resume_once()?;
        let first_candidate = candidate(1, true, &trace);
        assert_eq!(
            admission.consume_manager(key(1)?, &first_candidate),
            Ok(ExpectedHelperRole::Approval)
        );
        assert_eq!(
            admission.consume_manager(key(1)?, &first_candidate),
            Err(ExpectedPeerRegistryError::Denied)
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);

        let second_lease = admission
            .register_suspended(peer(2, 2, ExpectedHelperRole::SecretInput, &trace, &drops)?)?
            .revalidate_and_resume_once()?;
        assert_eq!(
            admission.consume_manager(key(1)?, &first_candidate),
            Err(ExpectedPeerRegistryError::Denied)
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(
            admission.observe_callback(&candidate(2, true, &trace)),
            Ok(ExpectedHelperRole::SecretInput)
        );
        assert_eq!(
            admission.consume_manager(key(2)?, &candidate(2, true, &trace)),
            Ok(ExpectedHelperRole::SecretInput)
        );
        drop(first_lease);
        drop(second_lease);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[test]
    fn callback_replay_retires_only_related_admitted_peer() -> Result<(), ExpectedPeerRegistryError>
    {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let first_lease = admission
            .register_suspended(peer(1, 1, ExpectedHelperRole::Approval, &trace, &drops)?)?
            .revalidate_and_resume_once()?;
        let second_lease = admission
            .register_suspended(peer(2, 2, ExpectedHelperRole::SecretInput, &trace, &drops)?)?
            .revalidate_and_resume_once()?;

        assert_eq!(
            admission.consume_manager(key(1)?, &candidate(1, true, &trace)),
            Ok(ExpectedHelperRole::Approval)
        );
        assert_eq!(
            admission.observe_callback(&candidate(1, true, &trace)),
            Err(ExpectedPeerRegistryError::Denied)
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(
            admission.observe_callback(&candidate(2, true, &trace)),
            Ok(ExpectedHelperRole::SecretInput)
        );
        assert_eq!(
            admission.consume_manager(key(2)?, &candidate(2, true, &trace)),
            Ok(ExpectedHelperRole::SecretInput)
        );
        drop(first_lease);
        drop(second_lease);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[test]
    fn every_match_and_running_failure_cleans_all_observed_authority()
    -> Result<(), ExpectedPeerRegistryError> {
        for failure in [Event::Match, Event::Running] {
            let admission = ExpectedHelperAdmission::new();
            let trace = Trace::new();
            let drops = Arc::new(AtomicU32::new(0));
            let mut failing = peer(4, 4, ExpectedHelperRole::Approval, &trace, &drops)?;
            failing.fail = Some(failure);
            let lease = admission
                .register_suspended(failing)?
                .revalidate_and_resume_once()?;
            assert!(
                admission
                    .consume_manager(key(4)?, &candidate(4, true, &trace))
                    .is_err()
            );
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            drop(lease);
        }

        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let mut failing_cancel = peer(4, 4, ExpectedHelperRole::Approval, &trace, &drops)?;
        failing_cancel.fail = Some(Event::Cancel);
        let lease = admission
            .register_suspended(failing_cancel)?
            .revalidate_and_resume_once()?;
        assert_eq!(
            admission.consume_manager(key(4)?, &candidate(4, true, &trace)),
            Ok(ExpectedHelperRole::Approval)
        );
        assert_eq!(
            admission.consume_manager(key(4)?, &candidate(4, true, &trace)),
            Err(ExpectedPeerRegistryError::Internal)
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        drop(lease);
        Ok(())
    }

    #[test]
    fn duplicate_full_stop_and_retired_slots_are_closed() -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let first = admission.register_suspended(peer(
            1,
            1,
            ExpectedHelperRole::Approval,
            &trace,
            &drops,
        )?)?;
        assert!(matches!(
            admission.register_suspended(peer(
                1,
                9,
                ExpectedHelperRole::SecretInput,
                &trace,
                &drops,
            )?),
            Err(ExpectedPeerRegistryError::Denied)
        ));
        drop(first);
        for marker in 2..=u8::try_from(EXPECTED_HELPER_CAPACITY)
            .map_err(|_| ExpectedPeerRegistryError::Internal)?
        {
            let registered = admission.register_suspended(peer(
                marker,
                marker,
                ExpectedHelperRole::Approval,
                &trace,
                &drops,
            )?)?;
            drop(registered);
        }
        assert!(matches!(
            admission
                .register_suspended(peer(9, 9, ExpectedHelperRole::Approval, &trace, &drops,)?),
            Err(ExpectedPeerRegistryError::Full)
        ));
        admission.stop()?;
        assert_eq!(admission.stop(), Err(ExpectedPeerRegistryError::Stopping));
        Ok(())
    }

    #[test]
    fn manager_detects_same_process_different_key_role_registration_race()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let pause = Arc::new(Barrier::new(2));
        let mut first = peer(5, 7, ExpectedHelperRole::Approval, &trace, &drops)?;
        first.match_pause = Some(Arc::clone(&pause));
        let lease = admission
            .register_suspended(first)?
            .revalidate_and_resume_once()?;
        let worker_admission = admission.clone();
        let worker_trace = trace.clone();
        let first_key = key(5)?;
        let worker = thread::spawn(move || {
            worker_admission.consume_manager(first_key, &candidate(7, true, &worker_trace))
        });
        pause.wait();
        let raced = admission.register_suspended(peer(
            6,
            7,
            ExpectedHelperRole::SecretInput,
            &trace,
            &drops,
        )?)?;
        pause.wait();
        assert_eq!(
            worker
                .join()
                .map_err(|_| ExpectedPeerRegistryError::Internal)?,
            Err(ExpectedPeerRegistryError::Internal)
        );
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        drop(raced);
        drop(lease);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[test]
    fn stop_waits_for_in_flight_cleanup_without_holding_registry_mutex()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let pause = Arc::new(Barrier::new(2));
        let mut slow = peer(7, 7, ExpectedHelperRole::Approval, &trace, &drops)?;
        slow.suspended_pause = Some(Arc::clone(&pause));
        let registered = admission.register_suspended(slow)?;
        let (sent, received) = mpsc::channel();
        let worker = thread::spawn(move || {
            let result = registered.revalidate_and_resume_once().map(|_| ());
            let _ = sent.send(result);
        });
        pause.wait();
        let stop_admission = admission.clone();
        let (stop_sent, stop_received) = mpsc::channel();
        let stop = thread::spawn(move || {
            let result = stop_admission.stop();
            let _ = stop_sent.send(result);
        });
        wait_for_cancel_request(&admission, key(7)?)?;
        assert!(
            stop_received
                .recv_timeout(Duration::from_millis(25))
                .is_err()
        );
        assert!(received.recv_timeout(Duration::from_millis(25)).is_err());
        pause.wait();
        assert!(
            received
                .recv_timeout(Duration::from_secs(1))
                .map_err(|_| ExpectedPeerRegistryError::Internal)?
                .is_err()
        );
        assert_eq!(
            stop_received
                .recv_timeout(Duration::from_secs(1))
                .map_err(|_| ExpectedPeerRegistryError::Internal)?,
            Ok(())
        );
        worker
            .join()
            .map_err(|_| ExpectedPeerRegistryError::Internal)?;
        stop.join()
            .map_err(|_| ExpectedPeerRegistryError::Internal)?;
        assert!(!is_in_flight(&admission, key(7)?)?);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn resume_and_expected_running_publication_precede_callback_observation()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let pause = Arc::new(Barrier::new(2));
        let mut helper = peer(10, 10, ExpectedHelperRole::Approval, &trace, &drops)?;
        helper.resume_pause = Some(Arc::clone(&pause));
        let registered = admission.register_suspended(helper)?;
        let (activation_sent, activation_received) = mpsc::channel();
        let activation = thread::spawn(move || {
            let _ = activation_sent.send(registered.revalidate_and_resume_once());
        });

        pause.wait();
        let callback_admission = admission.clone();
        let callback_trace = trace.clone();
        let (callback_sent, callback_received) = mpsc::channel();
        let callback = thread::spawn(move || {
            let result = callback_admission.observe_callback(&candidate(10, true, &callback_trace));
            let _ = callback_sent.send(result);
        });
        assert!(
            callback_received
                .recv_timeout(Duration::from_millis(25))
                .is_err()
        );
        pause.wait();

        let lease = activation_received
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| ExpectedPeerRegistryError::Internal)??;
        assert_eq!(
            callback_received
                .recv_timeout(Duration::from_secs(1))
                .map_err(|_| ExpectedPeerRegistryError::Internal)?,
            Ok(ExpectedHelperRole::Approval)
        );
        activation
            .join()
            .map_err(|_| ExpectedPeerRegistryError::Internal)?;
        callback
            .join()
            .map_err(|_| ExpectedPeerRegistryError::Internal)?;
        drop(lease);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn in_flight_cancel_waits_for_observer_cleanup_and_guard_drop_is_quiet()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let pause = Arc::new(Barrier::new(2));
        let mut helper = peer(11, 11, ExpectedHelperRole::Approval, &trace, &drops)?;
        helper.match_pause = Some(Arc::clone(&pause));
        let mut lease = admission
            .register_suspended(helper)?
            .revalidate_and_resume_once()?;
        let worker_admission = admission.clone();
        let worker_trace = trace.clone();
        let worker = thread::spawn(move || {
            worker_admission.observe_callback(&candidate(11, true, &worker_trace))
        });
        pause.wait();
        let (cancel_sent, cancel_received) = mpsc::channel();
        let cancel = thread::spawn(move || {
            let result = lease.cancel();
            let dropped =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(lease))).is_ok();
            let _ = cancel_sent.send((result, dropped));
        });
        wait_for_cancel_request(&admission, key(11)?)?;
        assert!(
            cancel_received
                .recv_timeout(Duration::from_millis(25))
                .is_err()
        );
        pause.wait();
        assert!(
            worker
                .join()
                .map_err(|_| ExpectedPeerRegistryError::Internal)?
                .is_err()
        );
        assert_eq!(
            cancel_received
                .recv_timeout(Duration::from_secs(1))
                .map_err(|_| ExpectedPeerRegistryError::Internal)?,
            (Ok(()), true)
        );
        cancel
            .join()
            .map_err(|_| ExpectedPeerRegistryError::Internal)?;
        assert!(!is_in_flight(&admission, key(11)?)?);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn in_flight_cancel_timeout_delegates_cleanup_without_guard_abort()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let pause = Arc::new(Barrier::new(2));
        let mut helper = peer(12, 12, ExpectedHelperRole::Approval, &trace, &drops)?;
        helper.match_pause = Some(Arc::clone(&pause));
        let mut lease = admission
            .register_suspended(helper)?
            .revalidate_and_resume_once()?;
        let worker_admission = admission.clone();
        let worker_trace = trace.clone();
        let worker = thread::spawn(move || {
            worker_admission.observe_callback(&candidate(12, true, &worker_trace))
        });

        pause.wait();
        assert_eq!(
            lease.cancel_with_timeout(Duration::ZERO),
            Err(ExpectedPeerRegistryError::Internal)
        );
        let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(lease)));
        assert!(dropped.is_ok());
        assert!(is_in_flight(&admission, key(12)?)?);
        pause.wait();
        assert!(
            worker
                .join()
                .map_err(|_| ExpectedPeerRegistryError::Internal)?
                .is_err()
        );
        assert!(!is_in_flight(&admission, key(12)?)?);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn delegated_cleanup_error_is_returned_without_second_guard_cleanup()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let pause = Arc::new(Barrier::new(2));
        let mut helper = peer(13, 13, ExpectedHelperRole::Approval, &trace, &drops)?;
        helper.match_pause = Some(Arc::clone(&pause));
        helper.fail = Some(Event::Cancel);
        let mut lease = admission
            .register_suspended(helper)?
            .revalidate_and_resume_once()?;
        let worker_admission = admission.clone();
        let worker_trace = trace.clone();
        let worker = thread::spawn(move || {
            worker_admission.observe_callback(&candidate(13, true, &worker_trace))
        });
        pause.wait();

        let (cancel_sent, cancel_received) = mpsc::channel();
        let cancel = thread::spawn(move || {
            let result = lease.cancel();
            let dropped =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(lease))).is_ok();
            let _ = cancel_sent.send((result, dropped));
        });
        wait_for_cancel_request(&admission, key(13)?)?;
        pause.wait();
        assert_eq!(
            worker
                .join()
                .map_err(|_| ExpectedPeerRegistryError::Internal)?,
            Err(ExpectedPeerRegistryError::Internal)
        );
        assert_eq!(
            cancel_received
                .recv_timeout(Duration::from_secs(1))
                .map_err(|_| ExpectedPeerRegistryError::Internal)?,
            (Err(ExpectedPeerRegistryError::Internal), true)
        );
        cancel
            .join()
            .map_err(|_| ExpectedPeerRegistryError::Internal)?;
        assert!(!is_in_flight(&admission, key(13)?)?);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn peer_panic_drops_terminal_owner_without_poisoning_registry()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let mut panicking = peer(8, 8, ExpectedHelperRole::Approval, &trace, &drops)?;
        panicking.panic_on_match = true;
        let lease = admission
            .register_suspended(panicking)?
            .revalidate_and_resume_once()?;
        let panicking_key = key(8)?;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = admission.consume_manager(panicking_key, &candidate(8, true, &trace));
        }));
        assert!(outcome.is_err());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(admission.stop(), Ok(()));
        drop(lease);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    #[allow(clippy::panic)]
    fn poisoned_registry_extracts_and_drops_live_peer_outside_lock()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let registered = admission.register_suspended(peer(
            9,
            9,
            ExpectedHelperRole::Approval,
            &trace,
            &drops,
        )?)?;
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _state = admission
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            panic!("poison registry for recovery test");
        }));
        assert!(poisoned.is_err());
        assert_eq!(admission.stop(), Err(ExpectedPeerRegistryError::Internal));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        drop(registered);
        Ok(())
    }

    #[test]
    fn registration_records_server_derived_nonzero_session_without_wire_authority()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let mut helper = peer(1, 1, ExpectedHelperRole::Approval, &trace, &drops)?;
        helper.session_id = session_id(41)?;
        let registered = admission.register_suspended(helper)?;

        let state = admission
            .inner
            .state
            .lock()
            .map_err(|_| ExpectedPeerRegistryError::Internal)?;
        assert!(matches!(
            state.slots.get(registered.index),
            Some(ExpectedPeerSlot::Live {
                key: stored_key,
                session_id: stored_session,
                phase: PeerPhase::RegisteredSuspended,
                ..
            }) if *stored_key == key(1)? && *stored_session == session_id(41)?
        ));
        assert!(!quarantine_contains(
            &state.quarantined_sessions,
            session_id(41)?
        ));
        drop(state);

        drop(registered);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn invalidated_session_rejects_and_cancels_future_registration()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        admission.invalidate_session(session_id(21)?)?;

        let mut blocked = peer(2, 2, ExpectedHelperRole::Approval, &trace, &drops)?;
        blocked.session_id = session_id(21)?;
        assert!(matches!(
            admission.register_suspended(blocked),
            Err(ExpectedPeerRegistryError::Denied)
        ));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        let events = trace
            .0
            .lock()
            .map_err(|_| ExpectedPeerRegistryError::Internal)?;
        assert_eq!(
            events
                .iter()
                .filter(|event| **event == Event::Cancel)
                .count(),
            1
        );
        drop(events);

        let mut allowed = peer(3, 3, ExpectedHelperRole::Approval, &trace, &drops)?;
        allowed.session_id = session_id(22)?;
        let allowed = admission.register_suspended(allowed)?;
        drop(allowed);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[test]
    fn session_invalidation_cancels_only_matching_live_peers_outside_registry_mutex()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let cancel_pause = Arc::new(Barrier::new(2));

        let mut matching = peer(4, 4, ExpectedHelperRole::Approval, &trace, &drops)?;
        matching.session_id = session_id(31)?;
        matching.cancel_pause = Some(Arc::clone(&cancel_pause));
        let matching = admission.register_suspended(matching)?;
        let mut unrelated = peer(5, 5, ExpectedHelperRole::SecretInput, &trace, &drops)?;
        unrelated.session_id = session_id(32)?;
        let unrelated = admission.register_suspended(unrelated)?;

        let worker_admission = admission.clone();
        let invalidated_session = session_id(31)?;
        let (sent, received) = mpsc::channel();
        let worker = thread::spawn(move || {
            let result = worker_admission.invalidate_session(invalidated_session);
            let _ = sent.send(result);
        });
        cancel_pause.wait();
        let state = admission
            .inner
            .state
            .try_lock()
            .map_err(|_| ExpectedPeerRegistryError::Internal)?;
        assert!(matches!(
            state.slots.get(matching.index),
            Some(ExpectedPeerSlot::Retired(stored_key)) if *stored_key == key(4)?
        ));
        assert!(matches!(
            state.slots.get(unrelated.index),
            Some(ExpectedPeerSlot::Live {
                session_id: stored_session,
                ..
            }) if *stored_session == session_id(32)?
        ));
        drop(state);
        assert!(received.recv_timeout(Duration::from_millis(25)).is_err());
        cancel_pause.wait();
        assert_eq!(
            received
                .recv_timeout(Duration::from_secs(1))
                .map_err(|_| ExpectedPeerRegistryError::Internal)?,
            Ok(())
        );
        worker
            .join()
            .map_err(|_| ExpectedPeerRegistryError::Internal)?;
        assert_eq!(drops.load(Ordering::SeqCst), 1);

        drop(matching);
        drop(unrelated);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[test]
    fn session_invalidation_requests_matching_in_flight_cancel_and_waits_for_settlement()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let suspended_pause = Arc::new(Barrier::new(2));
        let mut helper = peer(6, 6, ExpectedHelperRole::Approval, &trace, &drops)?;
        helper.session_id = session_id(41)?;
        helper.suspended_pause = Some(Arc::clone(&suspended_pause));
        let registered = admission.register_suspended(helper)?;
        let helper_worker =
            thread::spawn(move || registered.revalidate_and_resume_once().map(|_| ()));
        suspended_pause.wait();

        let invalidation_admission = admission.clone();
        let invalidated_session = session_id(41)?;
        let (sent, received) = mpsc::channel();
        let invalidation = thread::spawn(move || {
            let result = invalidation_admission.invalidate_session(invalidated_session);
            let _ = sent.send(result);
        });
        wait_for_cancel_request(&admission, key(6)?)?;
        assert!(received.recv_timeout(Duration::from_millis(25)).is_err());
        suspended_pause.wait();
        assert!(
            helper_worker
                .join()
                .map_err(|_| ExpectedPeerRegistryError::Internal)?
                .is_err()
        );
        assert_eq!(
            received
                .recv_timeout(Duration::from_secs(1))
                .map_err(|_| ExpectedPeerRegistryError::Internal)?,
            Ok(())
        );
        invalidation
            .join()
            .map_err(|_| ExpectedPeerRegistryError::Internal)?;
        assert!(!is_in_flight(&admission, key(6)?)?);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn session_invalidation_preserves_unrelated_live_and_in_flight_peers()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let scan_pause = Arc::new(Barrier::new(2));
        let mut target = peer(7, 7, ExpectedHelperRole::Approval, &trace, &drops)?;
        target.session_id = session_id(51)?;
        target.match_pause = Some(Arc::clone(&scan_pause));
        let target = admission
            .register_suspended(target)?
            .revalidate_and_resume_once()?;
        let mut unrelated_live = peer(8, 8, ExpectedHelperRole::SecretInput, &trace, &drops)?;
        unrelated_live.session_id = session_id(52)?;
        let unrelated = admission
            .register_suspended(unrelated_live)?
            .revalidate_and_resume_once()?;

        let manager_admission = admission.clone();
        let manager_trace = trace.clone();
        let selected_key = key(8)?;
        let manager = thread::spawn(move || {
            manager_admission.consume_manager(selected_key, &candidate(8, true, &manager_trace))
        });
        scan_pause.wait();

        let invalidation_admission = admission.clone();
        let invalidated_session = session_id(51)?;
        let (sent, received) = mpsc::channel();
        let invalidation = thread::spawn(move || {
            let result = invalidation_admission.invalidate_session(invalidated_session);
            let _ = sent.send(result);
        });
        wait_for_cancel_request(&admission, key(7)?)?;
        let expected_target_key = key(7)?;
        let expected_target_session = session_id(51)?;
        let expected_unrelated_key = key(8)?;
        let expected_unrelated_session = session_id(52)?;
        assert_eq!(
            in_flight_cancellation_scope(&admission, expected_target_key, expected_target_session)?,
            Some((true, false))
        );
        assert_eq!(
            in_flight_cancellation_scope(
                &admission,
                expected_unrelated_key,
                expected_unrelated_session
            )?,
            Some((false, false))
        );
        assert!(received.recv_timeout(Duration::from_millis(25)).is_err());
        scan_pause.wait();
        assert_eq!(
            manager
                .join()
                .map_err(|_| ExpectedPeerRegistryError::Internal)?,
            Err(ExpectedPeerRegistryError::Denied)
        );
        assert_eq!(
            received
                .recv_timeout(Duration::from_secs(1))
                .map_err(|_| ExpectedPeerRegistryError::Internal)?,
            Ok(())
        );
        invalidation
            .join()
            .map_err(|_| ExpectedPeerRegistryError::Internal)?;
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(
            live_phase(
                &admission,
                expected_unrelated_key,
                expected_unrelated_session
            )?,
            Some(PeerPhase::ExpectedRunning)
        );
        assert_eq!(
            admission.consume_manager(key(8)?, &candidate(8, true, &trace)),
            Ok(ExpectedHelperRole::SecretInput)
        );
        drop(target);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        drop(unrelated);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        assert_selective_invalidation_preserves_terminal_rejection()?;
        Ok(())
    }

    #[test]
    fn active_session_invalidation_quarantines_all_observed_sessions_and_departing_session()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        let mut first = peer(10, 10, ExpectedHelperRole::Approval, &trace, &drops)?;
        first.session_id = session_id(61)?;
        let first = admission.register_suspended(first)?;
        let suspended_pause = Arc::new(Barrier::new(2));
        let mut second = peer(11, 11, ExpectedHelperRole::SecretInput, &trace, &drops)?;
        second.session_id = session_id(62)?;
        second.suspended_pause = Some(Arc::clone(&suspended_pause));
        let second = admission.register_suspended(second)?;
        let helper_worker = thread::spawn(move || second.revalidate_and_resume_once().map(|_| ()));
        suspended_pause.wait();

        let invalidation_admission = admission.clone();
        let departing_session = session_id(63)?;
        let (sent, received) = mpsc::channel();
        let invalidation = thread::spawn(move || {
            let result = invalidation_admission.invalidate_active_sessions(departing_session);
            let _ = sent.send(result);
        });
        wait_for_cancel_request(&admission, key(11)?)?;
        let expected_in_flight_key = key(11)?;
        let expected_in_flight_session = session_id(62)?;
        let expected_retired_key = key(10)?;
        let state = admission
            .inner
            .state
            .lock()
            .map_err(|_| ExpectedPeerRegistryError::Internal)?;
        assert_eq!(
            state
                .quarantined_sessions
                .iter()
                .filter(|entry| entry.is_some())
                .count(),
            3
        );
        for expected in [session_id(61)?, session_id(62)?, session_id(63)?] {
            assert!(quarantine_contains(&state.quarantined_sessions, expected));
        }
        assert!(state.slots.iter().any(|slot| {
            matches!(
                slot,
                ExpectedPeerSlot::InFlight {
                    key: stored_key,
                    session_id: stored_session,
                    cancel_requested: true,
                    ..
                } if *stored_key == expected_in_flight_key
                    && *stored_session == expected_in_flight_session
            )
        }));
        assert!(state.slots.iter().any(|slot| {
            matches!(slot, ExpectedPeerSlot::Retired(stored_key)
                if *stored_key == expected_retired_key)
        }));
        drop(state);
        assert!(received.recv_timeout(Duration::from_millis(25)).is_err());
        suspended_pause.wait();
        assert!(
            helper_worker
                .join()
                .map_err(|_| ExpectedPeerRegistryError::Internal)?
                .is_err()
        );
        assert_eq!(
            received
                .recv_timeout(Duration::from_secs(1))
                .map_err(|_| ExpectedPeerRegistryError::Internal)?,
            Ok(())
        );
        invalidation
            .join()
            .map_err(|_| ExpectedPeerRegistryError::Internal)?;
        drop(first);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[test]
    fn session_quarantine_exhaustion_fail_closes_and_reaps_every_owner()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        for value in 1..=u32::try_from(EXPECTED_HELPER_SESSION_QUARANTINE_CAPACITY)
            .map_err(|_| ExpectedPeerRegistryError::Internal)?
        {
            admission.invalidate_session(session_id(value)?)?;
        }

        let mut live = peer(12, 12, ExpectedHelperRole::Approval, &trace, &drops)?;
        live.session_id = session_id(65)?;
        let live = admission.register_suspended(live)?;
        let suspended_pause = Arc::new(Barrier::new(2));
        let mut in_flight = peer(13, 13, ExpectedHelperRole::SecretInput, &trace, &drops)?;
        in_flight.session_id = session_id(66)?;
        in_flight.suspended_pause = Some(Arc::clone(&suspended_pause));
        let in_flight = admission.register_suspended(in_flight)?;
        let helper_worker =
            thread::spawn(move || in_flight.revalidate_and_resume_once().map(|_| ()));
        suspended_pause.wait();

        let overflow_admission = admission.clone();
        let overflow_session = session_id(67)?;
        let (sent, received) = mpsc::channel();
        let overflow = thread::spawn(move || {
            let result = overflow_admission.invalidate_session(overflow_session);
            let _ = sent.send(result);
        });
        wait_for_cancel_request(&admission, key(13)?)?;
        assert!(received.recv_timeout(Duration::from_millis(25)).is_err());
        suspended_pause.wait();
        assert!(
            helper_worker
                .join()
                .map_err(|_| ExpectedPeerRegistryError::Internal)?
                .is_err()
        );
        assert_eq!(
            received
                .recv_timeout(Duration::from_secs(1))
                .map_err(|_| ExpectedPeerRegistryError::Internal)?,
            Err(ExpectedPeerRegistryError::Stopping)
        );
        overflow
            .join()
            .map_err(|_| ExpectedPeerRegistryError::Internal)?;
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        assert_eq!(
            admission.invalidate_session(session_id(68)?),
            Err(ExpectedPeerRegistryError::Stopping)
        );
        drop(live);
        Ok(())
    }

    #[test]
    fn session_invalidation_failure_and_debug_are_data_free()
    -> Result<(), ExpectedPeerRegistryError> {
        let admission = ExpectedHelperAdmission::new();
        let trace = Trace::new();
        let drops = Arc::new(AtomicU32::new(0));
        for value in 1..=u32::try_from(EXPECTED_HELPER_SESSION_QUARANTINE_CAPACITY)
            .map_err(|_| ExpectedPeerRegistryError::Internal)?
        {
            admission.invalidate_session(session_id(value)?)?;
        }
        let mut helper = peer(14, 14, ExpectedHelperRole::Approval, &trace, &drops)?;
        helper.session_id = session_id(71)?;
        helper.fail = Some(Event::Cancel);
        let registered = admission.register_suspended(helper)?;

        let Err(error) = admission.invalidate_session(session_id(72)?) else {
            return Err(ExpectedPeerRegistryError::Internal);
        };
        assert_eq!(error, ExpectedPeerRegistryError::Internal);
        assert_eq!(format!("{error:?}"), "Internal");
        let empty: ExpectedHelperAdmission<FakePeer, FakeCandidate> =
            ExpectedHelperAdmission::new();
        assert_eq!(format!("{admission:?}"), format!("{empty:?}"));
        assert!(!format!("{admission:?}").contains(&session_id(71)?.get().to_string()));
        drop(registered);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn debug_is_data_free() -> Result<(), ExpectedPeerRegistryError> {
        let admission: ExpectedHelperAdmission<FakePeer, FakeCandidate> =
            ExpectedHelperAdmission::new();
        assert_eq!(
            format!("{admission:?}"),
            "ExpectedHelperAdmission([REDACTED])"
        );
        assert_eq!(format!("{:?}", key(1)?), "ExpectedPeerKey([REDACTED])");
        Ok(())
    }
}
