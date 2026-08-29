//! Fixed-capacity, one-shot epochs for the debug-only local RPC fixture.
//!
//! The table deliberately owns the retained peer capability associated with
//! each epoch. A command removes that capability before checking time, peer
//! identity, or fresh process state, so every attempted use is terminal.

#![deny(unsafe_code)]

use std::{
    fmt,
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};

use hmac::{Hmac, Mac as _};
use key_agent_service_wire::EpochNonce;
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

type EpochHmacSha256 = Hmac<Sha256>;

/// Maximum number of simultaneously live authenticated epochs.
pub(super) const EPOCH_CAPACITY: usize = 16;
/// Exact lifetime of an authenticated epoch.
pub(super) const EPOCH_LIFETIME: Duration = Duration::from_secs(5);

const EPOCH_SEED_BYTES: usize = 32;
#[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
const EPOCH_NONCE_DOMAIN_V2: &[u8] = b"your-wallet.key-agent-service.epoch.v2\0";

/// Wire generation permanently bound to an issued epoch.
#[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProtocolVersion {
    V1,
    V2,
}
const EPOCH_NONCE_DOMAIN_V1: &[u8] = b"YourWallet.KeyAgentService.EpochNonce.v1\0";

/// Sealing marker kept visible only inside the service RPC module.
pub(super) mod sealed {
    pub(crate) trait Sealed {}
}

/// A retained, exact authenticated client process.
///
/// Production implementations own the OS objects needed to distinguish a
/// process instance and re-query its current state. Implementations must treat
/// `exactly_matches` as an equivalence relation. No raw handle crosses this
/// seam, and implementations are sealed to this crate.
pub(super) trait ExactEpochPeer: sealed::Sealed + Send + 'static {
    /// Tests whether `current` is the same exact process instance as `self`.
    fn exactly_matches(&self, current: &Self) -> Result<bool, PeerRevalidationError>;

    /// Revalidates this retained process against current operating-system
    /// state immediately before an epoch is accepted.
    fn revalidate(&self) -> Result<(), PeerRevalidationError>;
}

/// Stable, data-free result of freshly revalidating a retained peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PeerRevalidationError {
    /// The retained process no longer satisfies the authentication policy.
    Denied,
    /// The operating system could not produce an unambiguous safe result.
    Internal,
}

/// Monotonic clock seam used by the production worker and deterministic tests.
pub(super) trait MonotonicClock: Send + Sync + 'static {
    /// Opaque, totally ordered monotonic instant.
    type Instant: Copy + Ord + Send + 'static;

    /// Reads the current monotonic instant, or fails closed.
    fn now(&self) -> Option<Self::Instant>;

    /// Computes a deadline without wrapping the monotonic domain.
    fn checked_add(&self, instant: Self::Instant, duration: Duration) -> Option<Self::Instant>;
}

/// Process monotonic clock used by the Windows service worker.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct SystemMonotonicClock;

impl MonotonicClock for SystemMonotonicClock {
    type Instant = Instant;

    fn now(&self) -> Option<Self::Instant> {
        Some(Instant::now())
    }

    fn checked_add(&self, instant: Self::Instant, duration: Duration) -> Option<Self::Instant> {
        instant.checked_add(duration)
    }
}

/// Closed, data-free epoch-table outcome categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum EpochError {
    /// An epoch was missing, expired, reused, duplicated, or bound elsewhere.
    Denied,
    /// Every one of the fixed live slots was occupied.
    Full,
    /// The worker is stopping and accepts no issue or consume operation.
    Stopping,
    /// Randomness, monotonic time, counter, HMAC, or synchronization failed.
    Internal,
}

struct EpochSlot<P, I> {
    nonce: Zeroizing<[u8; 32]>,
    #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
    protocol_version: ProtocolVersion,
    peer: P,
    deadline: I,
}

struct EpochState<P, I> {
    seed: Zeroizing<[u8; EPOCH_SEED_BYTES]>,
    counter: u64,
    stopped: bool,
    slots: [Option<EpochSlot<P, I>>; EPOCH_CAPACITY],
}

/// Synchronized, fixed-slot epoch table owned by one RPC worker.
pub(super) struct EpochTable<P, C>
where
    P: ExactEpochPeer,
    C: MonotonicClock,
{
    clock: C,
    state: Mutex<EpochState<P, C::Instant>>,
}

impl<P, C> EpochTable<P, C>
where
    P: ExactEpochPeer,
    C: MonotonicClock,
{
    /// Starts a fresh table with a nonzero, per-worker OS-random seed.
    pub(super) fn new(clock: C) -> Result<Self, EpochError> {
        let mut seed = Zeroizing::new([0_u8; EPOCH_SEED_BYTES]);
        getrandom::fill(seed.as_mut()).map_err(|_| EpochError::Internal)?;
        Self::from_seed(clock, seed)
    }

    #[cfg(test)]
    pub(super) fn new_for_test(
        clock: C,
        seed: Zeroizing<[u8; EPOCH_SEED_BYTES]>,
    ) -> Result<Self, EpochError> {
        Self::from_seed(clock, seed)
    }

    fn from_seed(clock: C, seed: Zeroizing<[u8; EPOCH_SEED_BYTES]>) -> Result<Self, EpochError> {
        if seed.iter().all(|byte| *byte == 0) {
            return Err(EpochError::Internal);
        }

        Ok(Self {
            clock,
            state: Mutex::new(EpochState {
                seed,
                counter: 0,
                stopped: false,
                slots: std::array::from_fn(|_| None),
            }),
        })
    }

    /// Issues one live epoch for an exact peer, without eviction.
    pub(super) fn issue(&self, peer: P) -> Result<EpochNonce, EpochError> {
        #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
        let result = self.issue_inner(peer, ProtocolVersion::V1);
        #[cfg(not(feature = "key-agent-service-lpac-launch-feasibility-test-hook"))]
        let result = self.issue_inner(peer);
        result
    }

    /// Issues one live epoch permanently bound to `protocol_version`.
    #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
    pub(super) fn issue_for_version(
        &self,
        peer: P,
        protocol_version: ProtocolVersion,
    ) -> Result<EpochNonce, EpochError> {
        self.issue_inner(peer, protocol_version)
    }

    fn issue_inner(
        &self,
        peer: P,
        #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
        protocol_version: ProtocolVersion,
    ) -> Result<EpochNonce, EpochError> {
        let mut state = self.lock_state()?;
        if state.stopped {
            return Err(EpochError::Stopping);
        }

        let now = self.clock.now().ok_or(EpochError::Internal)?;
        for slot in &mut state.slots {
            if slot
                .as_ref()
                .is_some_and(|existing| now >= existing.deadline)
            {
                *slot = None;
            }
        }

        for existing in state.slots.iter().flatten() {
            if existing
                .peer
                .exactly_matches(&peer)
                .map_err(map_revalidation_error)?
            {
                return Err(EpochError::Denied);
            }
        }

        let slot_index = state
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(EpochError::Full)?;
        let deadline = self
            .clock
            .checked_add(now, EPOCH_LIFETIME)
            .ok_or(EpochError::Internal)?;
        let next_counter = state.counter.checked_add(1).ok_or(EpochError::Internal)?;
        state.counter = next_counter;
        #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
        let nonce_bytes = derive_nonce(&state.seed, next_counter, protocol_version)?;
        #[cfg(not(feature = "key-agent-service-lpac-launch-feasibility-test-hook"))]
        let nonce_bytes = derive_nonce(&state.seed, next_counter)?;

        if state
            .slots
            .iter()
            .flatten()
            .any(|existing| nonce_bytes_match(&existing.nonce, &nonce_bytes))
        {
            return Err(EpochError::Internal);
        }

        let nonce = EpochNonce::new(*nonce_bytes).map_err(|_| EpochError::Internal)?;

        state.slots[slot_index] = Some(EpochSlot {
            nonce: nonce_bytes,
            #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
            protocol_version,
            peer,
            deadline,
        });
        Ok(nonce)
    }

    /// Spends an epoch exactly once and freshly validates both retained peers.
    ///
    /// The matching slot is removed while holding the table lock before the
    /// expiry, peer, or OS-state checks below. Every failure therefore consumes
    /// the nonce and cannot be retried as an oracle.
    pub(super) fn consume(&self, nonce: EpochNonce, current_peer: &P) -> Result<(), EpochError> {
        #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
        let result = self.consume_inner(nonce, current_peer, ProtocolVersion::V1);
        #[cfg(not(feature = "key-agent-service-lpac-launch-feasibility-test-hook"))]
        let result = self.consume_inner(nonce, current_peer);
        result
    }

    /// Spends an epoch exactly once under its bound protocol generation.
    ///
    /// A matching nonce is removed before the version check. Presenting an
    /// epoch through the wrong protocol generation is therefore terminal and
    /// cannot be retried through the generation that issued it.
    #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
    pub(super) fn consume_for_version(
        &self,
        nonce: EpochNonce,
        current_peer: &P,
        protocol_version: ProtocolVersion,
    ) -> Result<(), EpochError> {
        self.consume_inner(nonce, current_peer, protocol_version)
    }

    fn consume_inner(
        &self,
        nonce: EpochNonce,
        current_peer: &P,
        #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
        protocol_version: ProtocolVersion,
    ) -> Result<(), EpochError> {
        let slot = {
            let mut state = self.lock_state()?;
            if state.stopped {
                return Err(EpochError::Stopping);
            }
            let slot_index = state
                .slots
                .iter()
                .position(|candidate| {
                    candidate.as_ref().is_some_and(|candidate| {
                        nonce_bytes_match(&candidate.nonce, nonce.as_bytes())
                    })
                })
                .ok_or(EpochError::Denied)?;
            state.slots[slot_index].take().ok_or(EpochError::Internal)?
        };

        #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
        if slot.protocol_version != protocol_version {
            return Err(EpochError::Denied);
        }
        let now = self.clock.now().ok_or(EpochError::Internal)?;
        if now >= slot.deadline {
            return Err(EpochError::Denied);
        }
        if !slot
            .peer
            .exactly_matches(current_peer)
            .map_err(map_revalidation_error)?
        {
            return Err(EpochError::Denied);
        }
        slot.peer.revalidate().map_err(map_revalidation_error)?;
        current_peer.revalidate().map_err(map_revalidation_error)?;

        if self.lock_state()?.stopped {
            return Err(EpochError::Stopping);
        }
        Ok(())
    }

    /// Irreversibly stops this worker table and invalidates every live epoch.
    pub(super) fn stop(&self) -> Result<(), EpochError> {
        let mut state = self.lock_state()?;
        state.stopped = true;
        for slot in &mut state.slots {
            *slot = None;
        }
        Ok(())
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, EpochState<P, C::Instant>>, EpochError> {
        self.state.lock().map_err(|_| EpochError::Internal)
    }
}

impl<P, C> fmt::Debug for EpochTable<P, C>
where
    P: ExactEpochPeer,
    C: MonotonicClock,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EpochTable([REDACTED])")
    }
}

fn derive_nonce(
    seed: &[u8; EPOCH_SEED_BYTES],
    counter: u64,
    #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
    protocol_version: ProtocolVersion,
) -> Result<Zeroizing<[u8; 32]>, EpochError> {
    let mut mac = EpochHmacSha256::new_from_slice(seed).map_err(|_| EpochError::Internal)?;
    #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
    mac.update(match protocol_version {
        ProtocolVersion::V1 => EPOCH_NONCE_DOMAIN_V1,
        ProtocolVersion::V2 => EPOCH_NONCE_DOMAIN_V2,
    });
    #[cfg(not(feature = "key-agent-service-lpac-launch-feasibility-test-hook"))]
    mac.update(EPOCH_NONCE_DOMAIN_V1);
    mac.update(&counter.to_be_bytes());
    let nonce_bytes: [u8; 32] = mac.finalize().into_bytes().into();
    if nonce_bytes.iter().all(|byte| *byte == 0) {
        return Err(EpochError::Internal);
    }
    Ok(Zeroizing::new(nonce_bytes))
}

fn nonce_bytes_match(left: &[u8; 32], right: &[u8; 32]) -> bool {
    bool::from(left.ct_eq(right))
}

const fn map_revalidation_error(error: PeerRevalidationError) -> EpochError {
    match error {
        PeerRevalidationError::Denied => EpochError::Denied,
        PeerRevalidationError::Internal => EpochError::Internal,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc, Barrier,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        thread,
    };

    use super::*;

    const TEST_SEED: [u8; EPOCH_SEED_BYTES] = [0xA7; EPOCH_SEED_BYTES];

    #[derive(Clone, Debug)]
    struct TestClock {
        now_millis: Arc<AtomicU64>,
        fail_now: Arc<AtomicBool>,
        fail_deadline: Arc<AtomicBool>,
    }

    impl TestClock {
        fn at(now_millis: u64) -> Self {
            Self {
                now_millis: Arc::new(AtomicU64::new(now_millis)),
                fail_now: Arc::new(AtomicBool::new(false)),
                fail_deadline: Arc::new(AtomicBool::new(false)),
            }
        }

        fn advance(&self, millis: u64) {
            self.now_millis.fetch_add(millis, Ordering::SeqCst);
        }
    }

    impl MonotonicClock for TestClock {
        type Instant = u64;

        fn now(&self) -> Option<Self::Instant> {
            (!self.fail_now.load(Ordering::SeqCst)).then(|| self.now_millis.load(Ordering::SeqCst))
        }

        fn checked_add(&self, instant: Self::Instant, duration: Duration) -> Option<Self::Instant> {
            if self.fail_deadline.load(Ordering::SeqCst) {
                return None;
            }
            let millis = u64::try_from(duration.as_millis()).ok()?;
            instant.checked_add(millis)
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct TestPeer {
        identity: u64,
        revalidation: PeerRevalidationError,
    }

    impl TestPeer {
        const fn valid(identity: u64) -> Self {
            Self {
                identity,
                revalidation: PeerRevalidationError::Denied,
            }
        }

        const fn allowed(identity: u64) -> Self {
            Self {
                identity,
                revalidation: PeerRevalidationError::Internal,
            }
        }
    }

    impl sealed::Sealed for TestPeer {}

    impl ExactEpochPeer for TestPeer {
        fn exactly_matches(&self, current: &Self) -> Result<bool, PeerRevalidationError> {
            Ok(self.identity == current.identity)
        }

        fn revalidate(&self) -> Result<(), PeerRevalidationError> {
            match self.revalidation {
                PeerRevalidationError::Denied if self.identity != u64::MAX => Ok(()),
                PeerRevalidationError::Internal if self.identity != u64::MAX - 1 => Ok(()),
                error => Err(error),
            }
        }
    }

    fn table(clock: TestClock) -> Result<EpochTable<TestPeer, TestClock>, EpochError> {
        EpochTable::new_for_test(clock, Zeroizing::new(TEST_SEED))
    }

    #[test]
    fn zero_seed_is_rejected_and_debug_is_fully_redacted() -> Result<(), EpochError> {
        assert!(matches!(
            EpochTable::<TestPeer, _>::new_for_test(
                TestClock::at(0),
                Zeroizing::new([0; EPOCH_SEED_BYTES])
            ),
            Err(EpochError::Internal)
        ));

        let table = table(TestClock::at(0))?;
        let _nonce = table.issue(TestPeer::allowed(0xA7A7))?;
        let debug = format!("{table:?}");
        assert_eq!(debug, "EpochTable([REDACTED])");
        assert!(!debug.contains("167"));
        assert!(!debug.contains("42919"));
        Ok(())
    }

    #[test]
    fn same_exact_peer_has_only_one_live_epoch() -> Result<(), EpochError> {
        let table = table(TestClock::at(1_000))?;
        let _nonce = table.issue(TestPeer::allowed(7))?;
        assert_eq!(table.issue(TestPeer::allowed(7)), Err(EpochError::Denied));
        Ok(())
    }

    #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
    #[test]
    fn same_exact_peer_cannot_open_parallel_epochs_across_versions() -> Result<(), EpochError> {
        let table = table(TestClock::at(1_000))?;
        let _nonce = table.issue_for_version(TestPeer::allowed(7), ProtocolVersion::V2)?;
        assert_eq!(table.issue(TestPeer::allowed(7)), Err(EpochError::Denied));
        Ok(())
    }

    #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
    #[test]
    fn protocol_versions_use_distinct_nonce_domains() -> Result<(), EpochError> {
        let v1_table = table(TestClock::at(1_000))?;
        let v2_table = table(TestClock::at(1_000))?;
        let v1_nonce = v1_table.issue(TestPeer::allowed(7))?;
        let v2_nonce = v2_table.issue_for_version(TestPeer::allowed(7), ProtocolVersion::V2)?;
        assert_ne!(v1_nonce, v2_nonce);
        Ok(())
    }

    #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
    #[test]
    fn cross_version_attempt_is_terminal_before_matching_version_replay() -> Result<(), EpochError>
    {
        let table = table(TestClock::at(1_000))?;

        let v1_nonce = table.issue(TestPeer::allowed(1))?;
        assert_eq!(
            table.consume_for_version(v1_nonce, &TestPeer::allowed(1), ProtocolVersion::V2),
            Err(EpochError::Denied)
        );
        assert_eq!(
            table.consume(v1_nonce, &TestPeer::allowed(1)),
            Err(EpochError::Denied)
        );

        let v2_nonce = table.issue_for_version(TestPeer::allowed(2), ProtocolVersion::V2)?;
        assert_eq!(
            table.consume(v2_nonce, &TestPeer::allowed(2)),
            Err(EpochError::Denied)
        );
        assert_eq!(
            table.consume_for_version(v2_nonce, &TestPeer::allowed(2), ProtocolVersion::V2),
            Err(EpochError::Denied)
        );
        Ok(())
    }

    #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
    #[test]
    fn matching_v2_epoch_is_consumed_exactly_once() -> Result<(), EpochError> {
        let table = table(TestClock::at(1_000))?;
        let nonce = table.issue_for_version(TestPeer::allowed(7), ProtocolVersion::V2)?;
        table.consume_for_version(nonce, &TestPeer::allowed(7), ProtocolVersion::V2)?;
        assert_eq!(
            table.consume_for_version(nonce, &TestPeer::allowed(7), ProtocolVersion::V2),
            Err(EpochError::Denied)
        );
        Ok(())
    }

    #[test]
    fn concurrent_issue_for_same_peer_has_exactly_one_winner() -> Result<(), EpochError> {
        let table = Arc::new(table(TestClock::at(1_000))?);
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let worker_table = Arc::clone(&table);
            let worker_barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                worker_barrier.wait();
                worker_table.issue(TestPeer::allowed(9))
            }));
        }
        barrier.wait();

        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().map_err(|_| EpochError::Internal))
            .collect::<Result<_, _>>()?;
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err(EpochError::Denied))
                .count(),
            1
        );
        Ok(())
    }

    #[test]
    fn fixed_capacity_never_evicts_a_live_epoch() -> Result<(), EpochError> {
        let table = table(TestClock::at(1_000))?;
        let mut first_nonce = None;
        for identity in 0..EPOCH_CAPACITY {
            let identity = u64::try_from(identity).map_err(|_| EpochError::Internal)?;
            let nonce = table.issue(TestPeer::allowed(identity))?;
            if first_nonce.is_none() {
                first_nonce = Some(nonce);
            }
        }
        assert_eq!(table.issue(TestPeer::allowed(99)), Err(EpochError::Full));
        table.consume(
            first_nonce.ok_or(EpochError::Internal)?,
            &TestPeer::allowed(0),
        )?;
        let _replacement = table.issue(TestPeer::allowed(99))?;
        Ok(())
    }

    #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
    #[test]
    fn fixed_capacity_is_shared_across_protocol_versions() -> Result<(), EpochError> {
        let table = table(TestClock::at(1_000))?;
        let mut first_v2_nonce = None;
        for identity in 0..EPOCH_CAPACITY {
            let identity = u64::try_from(identity).map_err(|_| EpochError::Internal)?;
            let protocol_version = if identity % 2 == 0 {
                ProtocolVersion::V1
            } else {
                ProtocolVersion::V2
            };
            let nonce = table.issue_for_version(TestPeer::allowed(identity), protocol_version)?;
            if protocol_version == ProtocolVersion::V2 && first_v2_nonce.is_none() {
                first_v2_nonce = Some((nonce, identity));
            }
        }
        assert_eq!(
            table.issue_for_version(TestPeer::allowed(99), ProtocolVersion::V2),
            Err(EpochError::Full)
        );

        let (nonce, identity) = first_v2_nonce.ok_or(EpochError::Internal)?;
        table.consume_for_version(nonce, &TestPeer::allowed(identity), ProtocolVersion::V2)?;
        let _replacement = table.issue(TestPeer::allowed(99))?;
        Ok(())
    }

    #[test]
    fn expiry_is_inclusive_at_exactly_five_seconds() -> Result<(), EpochError> {
        let clock = TestClock::at(1_000);
        let table = table(clock.clone())?;
        let nonce = table.issue(TestPeer::allowed(3))?;
        clock.advance(4_999);
        table.consume(nonce, &TestPeer::allowed(3))?;

        let nonce = table.issue(TestPeer::allowed(3))?;
        clock.advance(5_000);
        assert_eq!(
            table.consume(nonce, &TestPeer::allowed(3)),
            Err(EpochError::Denied)
        );
        Ok(())
    }

    #[cfg(feature = "key-agent-service-lpac-launch-feasibility-test-hook")]
    #[test]
    fn expiry_cleanup_releases_peer_and_capacity_across_versions() -> Result<(), EpochError> {
        let clock = TestClock::at(1_000);
        let table = table(clock.clone())?;
        let expired_v2 = table.issue_for_version(TestPeer::allowed(3), ProtocolVersion::V2)?;
        clock.advance(5_000);

        let replacement_v1 = table.issue(TestPeer::allowed(3))?;
        assert_eq!(
            table.consume_for_version(expired_v2, &TestPeer::allowed(3), ProtocolVersion::V2),
            Err(EpochError::Denied)
        );
        table.consume(replacement_v1, &TestPeer::allowed(3))?;
        Ok(())
    }

    #[test]
    fn wrong_peer_spends_the_epoch_before_identity_check() -> Result<(), EpochError> {
        let table = table(TestClock::at(0))?;
        let nonce = table.issue(TestPeer::allowed(1))?;
        assert_eq!(
            table.consume(nonce, &TestPeer::allowed(2)),
            Err(EpochError::Denied)
        );
        assert_eq!(
            table.consume(nonce, &TestPeer::allowed(1)),
            Err(EpochError::Denied)
        );
        Ok(())
    }

    #[test]
    fn both_retained_and_current_peer_are_revalidated() -> Result<(), EpochError> {
        let table = table(TestClock::at(0))?;
        let stored_failure = table.issue(TestPeer::valid(u64::MAX))?;
        assert_eq!(
            table.consume(stored_failure, &TestPeer::allowed(u64::MAX)),
            Err(EpochError::Denied)
        );

        let current_failure = table.issue(TestPeer::valid(u64::MAX - 1))?;
        assert_eq!(
            table.consume(current_failure, &TestPeer::allowed(u64::MAX - 1)),
            Err(EpochError::Internal)
        );
        Ok(())
    }

    #[test]
    fn same_nonce_has_exactly_one_concurrent_consumer() -> Result<(), EpochError> {
        let table = Arc::new(table(TestClock::at(0))?);
        let nonce = table.issue(TestPeer::allowed(41))?;
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let worker_table = Arc::clone(&table);
            let worker_barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                worker_barrier.wait();
                worker_table.consume(nonce, &TestPeer::allowed(41))
            }));
        }
        barrier.wait();

        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().map_err(|_| EpochError::Internal))
            .collect::<Result<_, _>>()?;
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err(EpochError::Denied))
                .count(),
            1
        );
        Ok(())
    }

    #[test]
    fn stop_invalidates_all_epochs_and_restart_requires_a_new_table() -> Result<(), EpochError> {
        let clock = TestClock::at(0);
        let table = table(clock.clone())?;
        let old_nonce = table.issue(TestPeer::allowed(5))?;
        table.stop()?;
        assert_eq!(table.issue(TestPeer::allowed(6)), Err(EpochError::Stopping));
        assert_eq!(
            table.consume(old_nonce, &TestPeer::allowed(5)),
            Err(EpochError::Stopping)
        );

        let restarted = EpochTable::new_for_test(clock, Zeroizing::new([0xB8; 32]))?;
        assert_eq!(
            restarted.consume(old_nonce, &TestPeer::allowed(5)),
            Err(EpochError::Denied)
        );
        let _new_nonce = restarted.issue(TestPeer::allowed(5))?;
        Ok(())
    }

    #[test]
    fn counter_and_deadline_failures_are_internal_and_insert_nothing() -> Result<(), EpochError> {
        let clock = TestClock::at(0);
        let counter_table = table(clock.clone())?;
        {
            let mut state = counter_table.lock_state()?;
            state.counter = u64::MAX;
        }
        assert_eq!(
            counter_table.issue(TestPeer::allowed(1)),
            Err(EpochError::Internal)
        );

        let deadline_table = table(clock.clone())?;
        clock.fail_deadline.store(true, Ordering::SeqCst);
        assert_eq!(
            deadline_table.issue(TestPeer::allowed(2)),
            Err(EpochError::Internal)
        );
        clock.fail_deadline.store(false, Ordering::SeqCst);
        let _nonce = deadline_table.issue(TestPeer::allowed(2))?;
        Ok(())
    }

    #[test]
    fn failed_time_read_after_take_cannot_be_replayed() -> Result<(), EpochError> {
        let clock = TestClock::at(0);
        let table = table(clock.clone())?;
        let nonce = table.issue(TestPeer::allowed(1))?;
        clock.fail_now.store(true, Ordering::SeqCst);
        assert_eq!(
            table.consume(nonce, &TestPeer::allowed(1)),
            Err(EpochError::Internal)
        );
        clock.fail_now.store(false, Ordering::SeqCst);
        assert_eq!(
            table.consume(nonce, &TestPeer::allowed(1)),
            Err(EpochError::Denied)
        );
        Ok(())
    }

    #[test]
    fn poisoned_table_cannot_report_a_clean_stop() -> Result<(), EpochError> {
        let table = Arc::new(table(TestClock::at(0))?);
        let worker_table = Arc::clone(&table);
        let worker = thread::spawn(move || {
            if let Ok(_guard) = worker_table.state.lock() {
                assert!(std::hint::black_box(false));
            }
        });
        assert!(worker.join().is_err());
        assert_eq!(table.stop(), Err(EpochError::Internal));
        assert_eq!(table.issue(TestPeer::allowed(1)), Err(EpochError::Internal));
        Ok(())
    }
}
