//! Fixed-capacity expected-helper admission for the dormant RPC fixture.
//!
//! The launch side supplies one move-only peer carrying server-derived role and
//! exact process/token/image evidence. Registration happens while that peer is
//! suspended; only a successful registered revalidation may perform its sole
//! resume. The RPC security callback observes without consuming, while the
//! manager spends the expected state exactly once. Retired slots are never
//! reused during one server lifetime.

#![deny(unsafe_code)]

use core::fmt;
use std::array;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex, MutexGuard};

use key_agent_service_wire::{EpochNonce, ServiceRequestId};

pub(crate) const EXPECTED_HELPER_CAPACITY: usize = 8;

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

enum ExpectedPeerSlot<P> {
    Vacant,
    Live {
        key: ExpectedPeerKey,
        phase: PeerPhase,
        peer: P,
    },
    InFlight {
        key: ExpectedPeerKey,
        phase: PeerPhase,
        generation: u64,
        cancel_requested: bool,
    },
    Retired(ExpectedPeerKey),
}

struct ExpectedPeerState<P> {
    stopping: bool,
    next_generation: u64,
    slots: [ExpectedPeerSlot<P>; EXPECTED_HELPER_CAPACITY],
}

impl<P> ExpectedPeerState<P> {
    fn new() -> Self {
        Self {
            stopping: false,
            next_generation: 1,
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
    generation: u64,
    original_phase: PeerPhase,
    next_phase: Option<PeerPhase>,
    peer: P,
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
        } else if state.slots.iter().any(|slot| slot_key(slot) == Some(key)) {
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
                let _ = self.settle_scan(peers);
                std::panic::resume_unwind(payload);
            }
        };
        self.settle_scan(peers).and(result)
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
                .settle_scan(peers)
                .and(Err(ExpectedPeerRegistryError::Internal));
        };
        if peers[selected].original_phase != PeerPhase::ExpectedRunning {
            retire_all(&mut peers);
            return self
                .settle_scan(peers)
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
                let _ = self.settle_scan(peers);
                std::panic::resume_unwind(payload);
            }
        };
        self.settle_scan(peers).and(result)
    }

    /// Manager-side terminal rejection when a malformed helper frame did not
    /// yield a trustworthy key. Candidate and peer comparisons run with every
    /// live peer outside the registry mutex. Exactly matching peers and peers
    /// whose relationship cannot be determined are retired; definite
    /// non-matches remain live. A failed candidate revalidation is still
    /// followed by exact comparison so its related launch cannot be retried.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "dormant malformed-helper manager integration follows this foundation"
        )
    )]
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
                let _ = self.settle_scan(peers);
                std::panic::resume_unwind(payload);
            }
        };
        self.settle_scan(peers).and(result)
    }

    #[expect(
        dead_code,
        reason = "dormant role-aware manager integration follows this foundation"
    )]
    pub(crate) fn reject_manager(
        &self,
        key: ExpectedPeerKey,
    ) -> Result<(), ExpectedPeerRegistryError> {
        self.cancel_key(key, ExpectedPeerRegistryError::Denied)
    }

    /// Stop never waits for an in-flight OS observation. Peers resident in the
    /// registry are extracted and cancelled outside the mutex; an operation
    /// already holding a peer sees `cancel_requested` before any reinsert and
    /// terminally drops its owner.
    pub(crate) fn stop(&self) -> Result<(), ExpectedPeerRegistryError> {
        let mut state = lock_expected_state(&self.inner)?;
        if state.stopping {
            return Err(ExpectedPeerRegistryError::Stopping);
        }
        state.stopping = true;
        let mut cleanup = Vec::with_capacity(EXPECTED_HELPER_CAPACITY);
        let mut in_flight = false;
        for slot in &mut state.slots {
            match slot {
                ExpectedPeerSlot::InFlight {
                    cancel_requested, ..
                } => {
                    *cancel_requested = true;
                    in_flight = true;
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
        if in_flight {
            cleanup.and(Err(ExpectedPeerRegistryError::Internal))
        } else {
            cleanup
        }
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
            let mut cleanup = Vec::with_capacity(EXPECTED_HELPER_CAPACITY);
            for slot in &mut state.slots {
                match slot {
                    ExpectedPeerSlot::InFlight {
                        cancel_requested, ..
                    } => *cancel_requested = true,
                    ExpectedPeerSlot::Live { .. } => {
                        if let Some(peer) = retire_live_slot(slot) {
                            cleanup.push(peer);
                        }
                    }
                    ExpectedPeerSlot::Vacant | ExpectedPeerSlot::Retired(_) => {}
                }
            }
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
            let mut cleanup = Vec::with_capacity(EXPECTED_HELPER_CAPACITY);
            for slot in &mut state.slots {
                match slot {
                    ExpectedPeerSlot::InFlight {
                        cancel_requested, ..
                    } => *cancel_requested = true,
                    ExpectedPeerSlot::Live { .. } => {
                        if let Some(peer) = retire_live_slot(slot) {
                            cleanup.push(peer);
                        }
                    }
                    ExpectedPeerSlot::Vacant | ExpectedPeerSlot::Retired(_) => {}
                }
            }
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
                                state.slots[local.index] = ExpectedPeerSlot::Retired(local.key);
                            }
                            for slot in &mut state.slots {
                                if let Some(peer) = retire_live_slot(slot) {
                                    resident.push(peer);
                                }
                            }
                            drop(state);
                            retire_all(&mut peers);
                            let cleanup =
                                cleanup_local_peers::<P, C>(peers)
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

    fn settle_scan(&self, mut peers: Vec<LocalPeer<P>>) -> Result<(), ExpectedPeerRegistryError> {
        let mut state = match lock_expected_state(&self.inner) {
            Ok(state) => state,
            Err(error) => {
                retire_all(&mut peers);
                let cleanup = cleanup_local_peers(peers);
                return cleanup.and(Err(error));
            }
        };
        let concurrent_live = state
            .slots
            .iter()
            .any(|slot| matches!(slot, ExpectedPeerSlot::Live { .. }));
        let exact_slots = peers.iter().all(|local| {
            matches!(
                state.slots.get(local.index),
                Some(ExpectedPeerSlot::InFlight {
                    key,
                    phase,
                    generation,
                    cancel_requested: false,
                }) if *key == local.key
                    && *phase == local.original_phase
                    && *generation == local.generation
            )
        });
        if state.stopping || concurrent_live || !exact_slots {
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
                        cancel_requested, ..
                    } => *cancel_requested = true,
                    ExpectedPeerSlot::Vacant | ExpectedPeerSlot::Retired(_) => {}
                }
            }
            for local in &peers {
                if matches!(
                    state.slots.get(local.index),
                    Some(ExpectedPeerSlot::InFlight { generation, .. })
                        if *generation == local.generation
                ) {
                    state.slots[local.index] = ExpectedPeerSlot::Retired(local.key);
                }
            }
            drop(state);
            retire_all(&mut peers);
            let cleanup = cleanup_local_peers(peers).and(cleanup_peers(concurrent));
            return cleanup.and(Err(if stopping {
                ExpectedPeerRegistryError::Stopping
            } else {
                ExpectedPeerRegistryError::Internal
            }));
        }

        let mut cleanup = Vec::new();
        for local in peers {
            let LocalPeer {
                index,
                key,
                next_phase,
                peer,
                ..
            } = local;
            if let Some(phase) = next_phase {
                state.slots[index] = ExpectedPeerSlot::Live { key, phase, peer };
            } else {
                state.slots[index] = ExpectedPeerSlot::Retired(key);
                cleanup.push(peer);
            }
        }
        drop(state);
        cleanup_peers(cleanup)
    }

    fn finish_single(
        &self,
        local: LocalPeer<P>,
        next_phase: Option<PeerPhase>,
    ) -> Result<(), ExpectedPeerRegistryError> {
        let mut state = match lock_expected_state(&self.inner) {
            Ok(state) => state,
            Err(error) => {
                let cleanup = cleanup_local_peers::<P, C>(vec![local]);
                return cleanup.and(Err(error));
            }
        };
        let exact = matches!(
            state.slots.get(local.index),
            Some(ExpectedPeerSlot::InFlight {
                key,
                phase,
                generation,
                cancel_requested: false,
            }) if *key == local.key
                && *phase == local.original_phase
                && *generation == local.generation
        );
        let stopping = state.stopping;
        if exact && !stopping {
            let LocalPeer {
                index, key, peer, ..
            } = local;
            if let Some(phase) = next_phase {
                state.slots[index] = ExpectedPeerSlot::Live { key, phase, peer };
                return Ok(());
            }
            state.slots[index] = ExpectedPeerSlot::Retired(key);
            drop(state);
            let cleanup = cleanup_peers::<P, C>(vec![peer]);
            return cleanup;
        }
        if matches!(
            state.slots.get(local.index),
            Some(ExpectedPeerSlot::InFlight { generation, .. })
                if *generation == local.generation
        ) {
            state.slots[local.index] = ExpectedPeerSlot::Retired(local.key);
        }
        drop(state);
        let cleanup = cleanup_local_peers::<P, C>(vec![local]);
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
                let cleanup = cleanup_local_peers::<P, C>(vec![local]);
                return cleanup.and(Err(error));
            }
        };
        let exact = matches!(
            state.slots.get(local.index),
            Some(ExpectedPeerSlot::InFlight {
                key,
                phase: PeerPhase::RegisteredSuspended,
                generation,
                cancel_requested: false,
            }) if *key == local.key && *generation == local.generation
        );
        if state.stopping || !exact {
            let stopping = state.stopping;
            if matches!(
                state.slots.get(local.index),
                Some(ExpectedPeerSlot::InFlight { generation, .. })
                    if *generation == local.generation
            ) {
                state.slots[local.index] = ExpectedPeerSlot::Retired(local.key);
            }
            drop(state);
            local.next_phase = None;
            let cleanup = cleanup_local_peers::<P, C>(vec![local]);
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
                state.slots[local.index] = ExpectedPeerSlot::Retired(local.key);
                drop(state);
                local.next_phase = None;
                let _ = cleanup_local_peers::<P, C>(vec![local]);
                std::panic::resume_unwind(payload);
            }
        };
        if let Err(error) = resume {
            state.slots[local.index] = ExpectedPeerSlot::Retired(local.key);
            drop(state);
            local.next_phase = None;
            let cleanup = cleanup_local_peers::<P, C>(vec![local]);
            return cleanup.and(Err(map_verification_error(error)));
        }
        let LocalPeer {
            index, key, peer, ..
        } = local;
        state.slots[index] = ExpectedPeerSlot::Live {
            key,
            phase: PeerPhase::ExpectedRunning,
            peer,
        };
        Ok(())
    }

    fn cancel_key(
        &self,
        key: ExpectedPeerKey,
        absent: ExpectedPeerRegistryError,
    ) -> Result<(), ExpectedPeerRegistryError> {
        let mut state = lock_expected_state(&self.inner)?;
        let Some(index) = state
            .slots
            .iter()
            .position(|slot| slot_key(slot) == Some(key))
        else {
            return Err(absent);
        };
        let mut in_flight = false;
        let cleanup = match &mut state.slots[index] {
            ExpectedPeerSlot::Live { .. } => retire_live_slot(&mut state.slots[index]),
            ExpectedPeerSlot::InFlight {
                cancel_requested, ..
            } => {
                *cancel_requested = true;
                in_flight = true;
                None
            }
            ExpectedPeerSlot::Retired(_) => return Err(absent),
            ExpectedPeerSlot::Vacant => return Err(ExpectedPeerRegistryError::Internal),
        };
        drop(state);
        let cleanup = cleanup.map_or(Ok(()), |mut peer| {
            let result = cleanup_peer(&mut peer);
            drop(peer);
            result
        });
        if in_flight {
            cleanup.and(Err(ExpectedPeerRegistryError::Internal))
        } else {
            cleanup
        }
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
            enforce_guard_drop_cleanup(
                admission.cancel_key(self.key, ExpectedPeerRegistryError::Denied),
            );
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
        let admission = ExpectedHelperAdmission {
            inner: Arc::clone(&self.inner),
        };
        let result = admission.cancel_key(self.key, ExpectedPeerRegistryError::Denied);
        if result.is_ok() {
            self.armed = false;
        }
        result
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
            enforce_guard_drop_cleanup(
                admission.cancel_key(self.key, ExpectedPeerRegistryError::Denied),
            );
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

fn extract_live_slot<P>(
    slot: &mut ExpectedPeerSlot<P>,
    index: usize,
    generation: u64,
) -> Result<LocalPeer<P>, ExpectedPeerRegistryError> {
    let previous = core::mem::replace(slot, ExpectedPeerSlot::Vacant);
    let ExpectedPeerSlot::Live { key, phase, peer } = previous else {
        *slot = previous;
        return Err(ExpectedPeerRegistryError::Internal);
    };
    *slot = ExpectedPeerSlot::InFlight {
        key,
        phase,
        generation,
        cancel_requested: false,
    };
    Ok(LocalPeer {
        index,
        key,
        generation,
        original_phase: phase,
        next_phase: Some(phase),
        peer,
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

fn slot_key<P>(slot: &ExpectedPeerSlot<P>) -> Option<ExpectedPeerKey> {
    match slot {
        ExpectedPeerSlot::Live { key, .. }
        | ExpectedPeerSlot::InFlight { key, .. }
        | ExpectedPeerSlot::Retired(key) => Some(*key),
        ExpectedPeerSlot::Vacant => None,
    }
}

fn retire_all<P>(peers: &mut [LocalPeer<P>]) {
    for local in peers {
        local.next_phase = None;
    }
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

fn cleanup_local_peers<P, C>(peers: Vec<LocalPeer<P>>) -> Result<(), ExpectedPeerRegistryError>
where
    C: ExpectedHelperCandidate,
    P: ExpectedHelperPeer<C>,
{
    cleanup_peers::<P, C>(peers.into_iter().map(|local| local.peer).collect())
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
                        cancel_requested, ..
                    } => *cancel_requested = true,
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
        identity: u8,
        role: ExpectedHelperRole,
        fail: Option<Event>,
        resumed: bool,
        trace: Trace,
        drops: Arc<AtomicU32>,
        match_pause: Option<Arc<Barrier>>,
        suspended_pause: Option<Arc<Barrier>>,
        resume_pause: Option<Arc<Barrier>>,
        panic_on_match: bool,
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

        fn role(&self) -> ExpectedHelperRole {
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
            (self.resumed && self.fail != Some(Event::Running))
                .then_some(())
                .ok_or(ExpectedPeerVerificationError::Denied)
        }

        fn cancel(&mut self) -> Result<(), ExpectedPeerVerificationError> {
            self.trace.push(Event::Cancel);
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

    fn peer(
        marker: u8,
        identity: u8,
        role: ExpectedHelperRole,
        trace: &Trace,
        drops: &Arc<AtomicU32>,
    ) -> Result<FakePeer, ExpectedPeerRegistryError> {
        Ok(FakePeer {
            key: key(marker)?,
            identity,
            role,
            fail: None,
            resumed: false,
            trace: trace.clone(),
            drops: Arc::clone(drops),
            match_pause: None,
            suspended_pause: None,
            resume_pause: None,
            panic_on_match: false,
        })
    }

    fn candidate(marker: u8, valid: bool, trace: &Trace) -> FakeCandidate {
        FakeCandidate {
            identity: marker,
            valid,
            trace: trace.clone(),
        }
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
            core::mem::forget(registered);
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
    fn slow_os_observation_never_holds_registry_mutex() -> Result<(), ExpectedPeerRegistryError> {
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
        assert_eq!(admission.stop(), Err(ExpectedPeerRegistryError::Internal));
        assert!(received.recv_timeout(Duration::from_millis(25)).is_err());
        pause.wait();
        assert!(
            received
                .recv_timeout(Duration::from_secs(1))
                .map_err(|_| ExpectedPeerRegistryError::Internal)?
                .is_err()
        );
        worker
            .join()
            .map_err(|_| ExpectedPeerRegistryError::Internal)?;
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
    fn in_flight_cancel_is_not_success_and_guard_drop_fails_fast()
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
        assert_eq!(lease.cancel(), Err(ExpectedPeerRegistryError::Internal));
        let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(lease)));
        assert!(dropped.is_err());
        pause.wait();
        assert!(
            worker
                .join()
                .map_err(|_| ExpectedPeerRegistryError::Internal)?
                .is_err()
        );
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
