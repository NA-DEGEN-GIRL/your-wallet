//! Dormant, no-authority Secret Input request ordering policy.
//!
//! This private, production-compiled typestate models only the ordering between
//! an admitted Secret Input request, UI startup, UI authentication, and one UI
//! completion. It carries no process, pipe, token, lease, cleanup, vault,
//! signing, wallet, private-key, secret-value, or durable-completion authority.
//!
//! No production constructor exists. Test-only seeds and observations exercise
//! the policy until a future composition owns an authenticated source.

#![forbid(unsafe_code)]

use core::{fmt, num::NonZeroU32};

use super::{
    epoch::MonotonicClock,
    expected_peer::{ExpectedHelperRole, ExpectedPeerKey},
};

/// Data-free reason that a Secret Input policy reached terminal rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SecretInputPolicyRejectionCause {
    ClockUnavailable,
    DeadlineExpired,
    InvalidObservation,
    Cancelled,
    SessionInvalidated,
    ActiveSessionsInvalidated,
}

struct MoveOnly;

/// Move-only binding supplied by a future authenticated composition.
///
/// Its only constructor is test-only. This token proves no operating-system
/// ownership, cleanup obligation, or secret-input authority.
#[must_use = "a Secret Input seed must be admitted or rejected exactly once"]
pub(super) struct SecretInputPolicySeed<C>
where
    C: MonotonicClock,
{
    clock: C,
    key: ExpectedPeerKey,
    session_id: NonZeroU32,
    role: ExpectedHelperRole,
    original_deadline: C::Instant,
    _move_only: MoveOnly,
}

#[cfg(test)]
impl<C> SecretInputPolicySeed<C>
where
    C: MonotonicClock,
{
    fn new_for_test(
        clock: C,
        key: ExpectedPeerKey,
        session_id: NonZeroU32,
        role: ExpectedHelperRole,
        original_deadline: C::Instant,
    ) -> Self {
        Self {
            clock,
            key,
            session_id,
            role,
            original_deadline,
            _move_only: MoveOnly,
        }
    }
}

impl<C> fmt::Debug for SecretInputPolicySeed<C>
where
    C: MonotonicClock,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretInputPolicySeed([REDACTED])")
    }
}

/// One move-only Secret Input policy observation.
///
/// The pure policy can recheck only the bound clock's original inclusive
/// deadline and equality with this observation. It does not prove process or
/// expected-peer liveness. A future production mint must consume fresh,
/// authenticated Secret Input UI and expected-peer liveness proofs before
/// constructing each one-shot observation. Construction remains test-only.
pub(super) struct SecretInputPolicyObservation {
    key: ExpectedPeerKey,
    session_id: NonZeroU32,
    role: ExpectedHelperRole,
    _move_only: MoveOnly,
}

#[cfg(test)]
impl SecretInputPolicyObservation {
    const fn new_for_test(
        key: ExpectedPeerKey,
        session_id: NonZeroU32,
        role: ExpectedHelperRole,
    ) -> Self {
        Self {
            key,
            session_id,
            role,
            _move_only: MoveOnly,
        }
    }
}

impl fmt::Debug for SecretInputPolicyObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretInputPolicyObservation([REDACTED])")
    }
}

#[derive(Clone, Copy)]
enum SecretInputDecision {
    Accept,
    Cancel,
}

/// One authenticated UI completion observation.
///
/// It carries no input value, transcript, vault material, wallet material,
/// signing material, private key, or cleanup evidence. Constructors are
/// test-only.
pub(super) struct SecretInputCompletionObservation {
    peer: SecretInputPolicyObservation,
    decision: SecretInputDecision,
}

#[cfg(test)]
impl SecretInputCompletionObservation {
    const fn accepted_for_test(peer: SecretInputPolicyObservation) -> Self {
        Self {
            peer,
            decision: SecretInputDecision::Accept,
        }
    }

    const fn cancelled_for_test(peer: SecretInputPolicyObservation) -> Self {
        Self {
            peer,
            decision: SecretInputDecision::Cancel,
        }
    }
}

impl fmt::Debug for SecretInputCompletionObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretInputCompletionObservation([REDACTED])")
    }
}

struct SecretInputBinding<C>
where
    C: MonotonicClock,
{
    clock: C,
    key: ExpectedPeerKey,
    session_id: NonZeroU32,
    role: ExpectedHelperRole,
    original_deadline: C::Instant,
    _move_only: MoveOnly,
}

impl<C> SecretInputBinding<C>
where
    C: MonotonicClock,
{
    #[allow(clippy::needless_pass_by_value)] // A fresh observation is a one-shot policy input.
    fn validate(
        &self,
        observation: SecretInputPolicyObservation,
    ) -> Result<(), SecretInputPolicyRejectionCause> {
        let SecretInputPolicyObservation {
            key,
            session_id,
            role,
            _move_only: _,
        } = observation;
        let now = self
            .clock
            .now()
            .ok_or(SecretInputPolicyRejectionCause::ClockUnavailable)?;
        if now >= self.original_deadline {
            return Err(SecretInputPolicyRejectionCause::DeadlineExpired);
        }
        if self.role != ExpectedHelperRole::SecretInput
            || role != ExpectedHelperRole::SecretInput
            || key != self.key
            || session_id != self.session_id
        {
            return Err(SecretInputPolicyRejectionCause::InvalidObservation);
        }
        Ok(())
    }
}

impl<C> fmt::Debug for SecretInputBinding<C>
where
    C: MonotonicClock,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretInputBinding([REDACTED])")
    }
}

/// A Secret Input request admitted into the pure-policy ordering model.
#[must_use = "an admitted Secret Input request must advance or terminate"]
pub(super) struct AdmittedSecretInputPolicy<C>
where
    C: MonotonicClock,
{
    binding: SecretInputBinding<C>,
}

impl<C> AdmittedSecretInputPolicy<C>
where
    C: MonotonicClock,
{
    #[cfg(test)]
    fn admit_for_test(
        seed: SecretInputPolicySeed<C>,
        observation: SecretInputPolicyObservation,
    ) -> Result<Self, RejectedSecretInputPolicy> {
        let SecretInputPolicySeed {
            clock,
            key,
            session_id,
            role,
            original_deadline,
            _move_only: _,
        } = seed;
        let binding = SecretInputBinding {
            clock,
            key,
            session_id,
            role,
            original_deadline,
            _move_only: MoveOnly,
        };
        match binding.validate(observation) {
            Ok(()) => Ok(Self { binding }),
            Err(cause) => Err(reject_binding(binding, cause)),
        }
    }

    pub(super) fn begin_ui(
        self,
        observation: SecretInputPolicyObservation,
    ) -> Result<SecretInputUiStartingPolicy<C>, RejectedSecretInputPolicy> {
        match self.binding.validate(observation) {
            Ok(()) => Ok(SecretInputUiStartingPolicy {
                binding: self.binding,
            }),
            Err(cause) => Err(reject_binding(self.binding, cause)),
        }
    }

    pub(super) fn recheck_liveness(
        self,
        observation: SecretInputPolicyObservation,
    ) -> Result<Self, RejectedSecretInputPolicy> {
        match self.binding.validate(observation) {
            Ok(()) => Ok(self),
            Err(cause) => Err(reject_binding(self.binding, cause)),
        }
    }

    pub(super) fn cancel(self) -> RejectedSecretInputPolicy {
        reject_binding(self.binding, SecretInputPolicyRejectionCause::Cancelled)
    }

    pub(super) fn invalidate_session(
        self,
        session_id: NonZeroU32,
    ) -> Result<Self, RejectedSecretInputPolicy> {
        if self.binding.session_id == session_id {
            Err(reject_binding(
                self.binding,
                SecretInputPolicyRejectionCause::SessionInvalidated,
            ))
        } else {
            Ok(self)
        }
    }

    pub(super) fn invalidate_active_sessions(self) -> RejectedSecretInputPolicy {
        reject_binding(
            self.binding,
            SecretInputPolicyRejectionCause::ActiveSessionsInvalidated,
        )
    }
}

impl<C> fmt::Debug for AdmittedSecretInputPolicy<C>
where
    C: MonotonicClock,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdmittedSecretInputPolicy([REDACTED])")
    }
}

/// A Secret Input UI whose start was accepted but is not authenticated.
#[must_use = "a starting Secret Input UI must authenticate or terminate"]
pub(super) struct SecretInputUiStartingPolicy<C>
where
    C: MonotonicClock,
{
    binding: SecretInputBinding<C>,
}

impl<C> SecretInputUiStartingPolicy<C>
where
    C: MonotonicClock,
{
    pub(super) fn authenticate_ui(
        self,
        observation: SecretInputPolicyObservation,
    ) -> Result<SecretInputUiAuthenticatedPolicy<C>, RejectedSecretInputPolicy> {
        match self.binding.validate(observation) {
            Ok(()) => Ok(SecretInputUiAuthenticatedPolicy {
                binding: self.binding,
            }),
            Err(cause) => Err(reject_binding(self.binding, cause)),
        }
    }

    pub(super) fn recheck_liveness(
        self,
        observation: SecretInputPolicyObservation,
    ) -> Result<Self, RejectedSecretInputPolicy> {
        match self.binding.validate(observation) {
            Ok(()) => Ok(self),
            Err(cause) => Err(reject_binding(self.binding, cause)),
        }
    }

    pub(super) fn cancel(self) -> RejectedSecretInputPolicy {
        reject_binding(self.binding, SecretInputPolicyRejectionCause::Cancelled)
    }

    pub(super) fn invalidate_session(
        self,
        session_id: NonZeroU32,
    ) -> Result<Self, RejectedSecretInputPolicy> {
        if self.binding.session_id == session_id {
            Err(reject_binding(
                self.binding,
                SecretInputPolicyRejectionCause::SessionInvalidated,
            ))
        } else {
            Ok(self)
        }
    }

    pub(super) fn invalidate_active_sessions(self) -> RejectedSecretInputPolicy {
        reject_binding(
            self.binding,
            SecretInputPolicyRejectionCause::ActiveSessionsInvalidated,
        )
    }
}

impl<C> fmt::Debug for SecretInputUiStartingPolicy<C>
where
    C: MonotonicClock,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretInputUiStartingPolicy([REDACTED])")
    }
}

/// An exact Secret Input UI authenticated immediately before one completion.
#[must_use = "an authenticated Secret Input UI must complete or terminate"]
pub(super) struct SecretInputUiAuthenticatedPolicy<C>
where
    C: MonotonicClock,
{
    binding: SecretInputBinding<C>,
}

impl<C> SecretInputUiAuthenticatedPolicy<C>
where
    C: MonotonicClock,
{
    pub(super) fn complete(
        self,
        observation: SecretInputCompletionObservation,
    ) -> Result<SecretInputCompletion<C>, RejectedSecretInputPolicy> {
        let SecretInputCompletionObservation { peer, decision } = observation;
        if let Err(cause) = self.binding.validate(peer) {
            return Err(reject_binding(self.binding, cause));
        }
        match decision {
            SecretInputDecision::Accept => {
                Ok(SecretInputCompletion::Accepted(AcceptedSecretInputPolicy {
                    binding: self.binding,
                }))
            }
            SecretInputDecision::Cancel => Ok(SecretInputCompletion::Cancelled(
                complete_cancelled_binding(self.binding),
            )),
        }
    }

    pub(super) fn recheck_liveness(
        self,
        observation: SecretInputPolicyObservation,
    ) -> Result<Self, RejectedSecretInputPolicy> {
        match self.binding.validate(observation) {
            Ok(()) => Ok(self),
            Err(cause) => Err(reject_binding(self.binding, cause)),
        }
    }

    pub(super) fn cancel(self) -> RejectedSecretInputPolicy {
        reject_binding(self.binding, SecretInputPolicyRejectionCause::Cancelled)
    }

    pub(super) fn invalidate_session(
        self,
        session_id: NonZeroU32,
    ) -> Result<Self, RejectedSecretInputPolicy> {
        if self.binding.session_id == session_id {
            Err(reject_binding(
                self.binding,
                SecretInputPolicyRejectionCause::SessionInvalidated,
            ))
        } else {
            Ok(self)
        }
    }

    pub(super) fn invalidate_active_sessions(self) -> RejectedSecretInputPolicy {
        reject_binding(
            self.binding,
            SecretInputPolicyRejectionCause::ActiveSessionsInvalidated,
        )
    }
}

impl<C> fmt::Debug for SecretInputUiAuthenticatedPolicy<C>
where
    C: MonotonicClock,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretInputUiAuthenticatedPolicy([REDACTED])")
    }
}

/// The exact one-shot outcome of an authenticated Secret Input UI completion.
#[must_use = "a Secret Input completion must be consumed exactly once"]
pub(super) enum SecretInputCompletion<C>
where
    C: MonotonicClock,
{
    Accepted(AcceptedSecretInputPolicy<C>),
    Cancelled(CancelledSecretInputPolicy),
}

impl<C> fmt::Debug for SecretInputCompletion<C>
where
    C: MonotonicClock,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretInputCompletion([REDACTED])")
    }
}

/// A non-durable acceptance observation with no secret or downstream authority.
///
/// Acceptance remains live-bound, expiring, cancellable, and invalidatable.
/// This type exposes no accessor or conversion into an input value, vault,
/// transcript, wallet, signing operation, private key, or cleanup receipt.
#[must_use = "Secret Input acceptance must remain live or terminate"]
pub(super) struct AcceptedSecretInputPolicy<C>
where
    C: MonotonicClock,
{
    binding: SecretInputBinding<C>,
}

impl<C> AcceptedSecretInputPolicy<C>
where
    C: MonotonicClock,
{
    pub(super) fn recheck_liveness(
        self,
        observation: SecretInputPolicyObservation,
    ) -> Result<Self, RejectedSecretInputPolicy> {
        match self.binding.validate(observation) {
            Ok(()) => Ok(self),
            Err(cause) => Err(reject_binding(self.binding, cause)),
        }
    }

    pub(super) fn cancel(self) -> RejectedSecretInputPolicy {
        reject_binding(self.binding, SecretInputPolicyRejectionCause::Cancelled)
    }

    pub(super) fn invalidate_session(
        self,
        session_id: NonZeroU32,
    ) -> Result<Self, RejectedSecretInputPolicy> {
        if self.binding.session_id == session_id {
            Err(reject_binding(
                self.binding,
                SecretInputPolicyRejectionCause::SessionInvalidated,
            ))
        } else {
            Ok(self)
        }
    }

    pub(super) fn invalidate_active_sessions(self) -> RejectedSecretInputPolicy {
        reject_binding(
            self.binding,
            SecretInputPolicyRejectionCause::ActiveSessionsInvalidated,
        )
    }
}

impl<C> fmt::Debug for AcceptedSecretInputPolicy<C>
where
    C: MonotonicClock,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AcceptedSecretInputPolicy([REDACTED])")
    }
}

/// Terminal, data-free cancellation completed by an authenticated Secret Input UI.
#[must_use = "terminal cancellation must be observed"]
pub(super) struct CancelledSecretInputPolicy {
    _move_only: MoveOnly,
}

impl fmt::Debug for CancelledSecretInputPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CancelledSecretInputPolicy")
    }
}

/// Terminal, data-free Secret Input policy rejection.
#[must_use = "terminal rejection must be observed"]
pub(super) struct RejectedSecretInputPolicy {
    cause: SecretInputPolicyRejectionCause,
    _move_only: MoveOnly,
}

impl fmt::Debug for RejectedSecretInputPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RejectedSecretInputPolicy")
            .field("cause", &self.cause)
            .finish_non_exhaustive()
    }
}

fn complete_cancelled_binding<C>(_binding: SecretInputBinding<C>) -> CancelledSecretInputPolicy
where
    C: MonotonicClock,
{
    CancelledSecretInputPolicy {
        _move_only: MoveOnly,
    }
}

fn reject_binding<C>(
    _binding: SecretInputBinding<C>,
    cause: SecretInputPolicyRejectionCause,
) -> RejectedSecretInputPolicy
where
    C: MonotonicClock,
{
    RejectedSecretInputPolicy {
        cause,
        _move_only: MoveOnly,
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU32;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    };
    use std::time::Duration;

    use key_agent_service_wire::{EpochNonce, ServiceRequestId};

    use super::*;

    const VALID_MARKER: u8 = 0x31;
    const OTHER_MARKER: u8 = 0x52;
    const VALID_SESSION: u32 = 7;
    const OTHER_SESSION: u32 = 9;
    const VALID_DEADLINE: u64 = 100;

    #[derive(Clone, Debug)]
    struct TestClock {
        state: Arc<TestClockState>,
    }

    #[derive(Debug)]
    struct TestClockState {
        now: AtomicU64,
        fail: AtomicBool,
        reads: AtomicU64,
    }

    impl TestClock {
        fn new(now: u64) -> Self {
            Self {
                state: Arc::new(TestClockState {
                    now: AtomicU64::new(now),
                    fail: AtomicBool::new(false),
                    reads: AtomicU64::new(0),
                }),
            }
        }

        fn set_now(&self, now: u64) {
            self.state.now.store(now, Ordering::Relaxed);
        }

        fn set_failure(&self, fail: bool) {
            self.state.fail.store(fail, Ordering::Relaxed);
        }

        fn reads(&self) -> u64 {
            self.state.reads.load(Ordering::Relaxed)
        }
    }

    impl MonotonicClock for TestClock {
        type Instant = u64;

        fn now(&self) -> Option<Self::Instant> {
            self.state.reads.fetch_add(1, Ordering::Relaxed);
            if self.state.fail.load(Ordering::Relaxed) {
                None
            } else {
                Some(self.state.now.load(Ordering::Relaxed))
            }
        }

        fn checked_add(&self, instant: Self::Instant, duration: Duration) -> Option<Self::Instant> {
            u64::try_from(duration.as_millis())
                .ok()
                .and_then(|increment| instant.checked_add(increment))
        }
    }

    fn key(marker: u8) -> Result<ExpectedPeerKey, &'static str> {
        let epoch = EpochNonce::new([marker; 32]).map_err(|_| "epoch marker was invalid")?;
        let request =
            ServiceRequestId::new([marker; 16]).map_err(|_| "request marker was invalid")?;
        Ok(ExpectedPeerKey::new(epoch, request))
    }

    fn session(value: u32) -> Result<NonZeroU32, &'static str> {
        NonZeroU32::new(value).ok_or("session must be nonzero")
    }

    fn observation(
        marker: u8,
        session_id: u32,
        role: ExpectedHelperRole,
    ) -> Result<SecretInputPolicyObservation, &'static str> {
        Ok(SecretInputPolicyObservation::new_for_test(
            key(marker)?,
            session(session_id)?,
            role,
        ))
    }

    fn seed(
        clock: TestClock,
        marker: u8,
        session_id: u32,
        role: ExpectedHelperRole,
        original_deadline: u64,
    ) -> Result<SecretInputPolicySeed<TestClock>, &'static str> {
        Ok(SecretInputPolicySeed::new_for_test(
            clock,
            key(marker)?,
            session(session_id)?,
            role,
            original_deadline,
        ))
    }

    fn valid_observation() -> Result<SecretInputPolicyObservation, &'static str> {
        observation(VALID_MARKER, VALID_SESSION, ExpectedHelperRole::SecretInput)
    }

    fn admitted(clock: &TestClock) -> Result<AdmittedSecretInputPolicy<TestClock>, &'static str> {
        AdmittedSecretInputPolicy::admit_for_test(
            seed(
                clock.clone(),
                VALID_MARKER,
                VALID_SESSION,
                ExpectedHelperRole::SecretInput,
                VALID_DEADLINE,
            )?,
            valid_observation()?,
        )
        .map_err(|_| "valid admission was rejected")
    }

    fn starting(clock: &TestClock) -> Result<SecretInputUiStartingPolicy<TestClock>, &'static str> {
        admitted(clock)?
            .begin_ui(valid_observation()?)
            .map_err(|_| "valid UI start was rejected")
    }

    fn authenticated(
        clock: &TestClock,
    ) -> Result<SecretInputUiAuthenticatedPolicy<TestClock>, &'static str> {
        starting(clock)?
            .authenticate_ui(valid_observation()?)
            .map_err(|_| "valid UI authentication was rejected")
    }

    fn accepted(clock: &TestClock) -> Result<AcceptedSecretInputPolicy<TestClock>, &'static str> {
        match authenticated(clock)?.complete(SecretInputCompletionObservation::accepted_for_test(
            valid_observation()?,
        )) {
            Ok(SecretInputCompletion::Accepted(accepted)) => Ok(accepted),
            Ok(SecretInputCompletion::Cancelled(_)) => Err("valid acceptance was cancelled"),
            Err(_) => Err("valid acceptance was rejected"),
        }
    }

    fn require_rejection<T>(
        result: Result<T, RejectedSecretInputPolicy>,
        expected: SecretInputPolicyRejectionCause,
    ) -> Result<(), &'static str> {
        match result {
            Err(rejected) if rejected.cause == expected => Ok(()),
            Err(_) => Err("request was rejected for the wrong reason"),
            Ok(_) => Err("request unexpectedly remained live"),
        }
    }

    #[allow(clippy::needless_pass_by_value)] // The helper fixes consuming terminal semantics.
    fn require_rejected(
        rejected: RejectedSecretInputPolicy,
        expected: SecretInputPolicyRejectionCause,
    ) -> Result<(), &'static str> {
        let RejectedSecretInputPolicy {
            cause,
            _move_only: _,
        } = rejected;
        (cause == expected)
            .then_some(())
            .ok_or("terminal rejection used the wrong cause")
    }

    #[allow(clippy::needless_pass_by_value)] // The helper fixes consuming terminal semantics.
    fn require_cancelled(cancelled: CancelledSecretInputPolicy) {
        let CancelledSecretInputPolicy { _move_only: _ } = cancelled;
    }

    fn assert_exact_binding(
        binding: &SecretInputBinding<TestClock>,
        expected_key: ExpectedPeerKey,
        expected_session: NonZeroU32,
        expected_deadline: u64,
    ) -> Result<(), &'static str> {
        if binding.key != expected_key
            || binding.session_id != expected_session
            || binding.role != ExpectedHelperRole::SecretInput
            || binding.original_deadline != expected_deadline
        {
            return Err("Secret Input binding changed");
        }
        Ok(())
    }

    fn assert_same_clock_source(
        binding: &SecretInputBinding<TestClock>,
        expected: &TestClock,
    ) -> Result<(), &'static str> {
        Arc::ptr_eq(&binding.clock.state, &expected.state)
            .then_some(())
            .ok_or("Secret Input clock source changed")
    }

    fn assert_bound(
        binding: &SecretInputBinding<TestClock>,
        clock: &TestClock,
    ) -> Result<(), &'static str> {
        assert_exact_binding(
            binding,
            key(VALID_MARKER)?,
            session(VALID_SESSION)?,
            VALID_DEADLINE,
        )?;
        assert_same_clock_source(binding, clock)
    }

    #[test]
    fn policy_types_are_move_only_and_transition_methods_consume_self() -> Result<(), &'static str>
    {
        trait AmbiguousIfClone<A> {
            fn marker() {}
        }
        impl<T> AmbiguousIfClone<()> for T {}
        impl<T: Clone> AmbiguousIfClone<u8> for T {}

        trait AmbiguousIfCopy<A> {
            fn marker() {}
        }
        impl<T> AmbiguousIfCopy<()> for T {}
        impl<T: Copy> AmbiguousIfCopy<u8> for T {}

        type StartResult =
            Result<SecretInputUiStartingPolicy<TestClock>, RejectedSecretInputPolicy>;
        type AuthenticateResult =
            Result<SecretInputUiAuthenticatedPolicy<TestClock>, RejectedSecretInputPolicy>;
        type CompletionResult = Result<SecretInputCompletion<TestClock>, RejectedSecretInputPolicy>;

        let _ = <SecretInputPolicySeed<TestClock> as AmbiguousIfClone<_>>::marker;
        let _ = <SecretInputPolicyObservation as AmbiguousIfClone<_>>::marker;
        let _ = <SecretInputCompletionObservation as AmbiguousIfClone<_>>::marker;
        let _ = <SecretInputBinding<TestClock> as AmbiguousIfClone<_>>::marker;
        let _ = <AdmittedSecretInputPolicy<TestClock> as AmbiguousIfClone<_>>::marker;
        let _ = <SecretInputUiStartingPolicy<TestClock> as AmbiguousIfClone<_>>::marker;
        let _ = <SecretInputUiAuthenticatedPolicy<TestClock> as AmbiguousIfClone<_>>::marker;
        let _ = <AcceptedSecretInputPolicy<TestClock> as AmbiguousIfClone<_>>::marker;
        let _ = <SecretInputCompletion<TestClock> as AmbiguousIfClone<_>>::marker;
        let _ = <CancelledSecretInputPolicy as AmbiguousIfClone<_>>::marker;
        let _ = <RejectedSecretInputPolicy as AmbiguousIfClone<_>>::marker;
        let _ = <SecretInputPolicySeed<TestClock> as AmbiguousIfCopy<_>>::marker;
        let _ = <SecretInputPolicyObservation as AmbiguousIfCopy<_>>::marker;
        let _ = <SecretInputCompletionObservation as AmbiguousIfCopy<_>>::marker;
        let _ = <SecretInputBinding<TestClock> as AmbiguousIfCopy<_>>::marker;
        let _ = <AdmittedSecretInputPolicy<TestClock> as AmbiguousIfCopy<_>>::marker;
        let _ = <SecretInputUiStartingPolicy<TestClock> as AmbiguousIfCopy<_>>::marker;
        let _ = <SecretInputUiAuthenticatedPolicy<TestClock> as AmbiguousIfCopy<_>>::marker;
        let _ = <AcceptedSecretInputPolicy<TestClock> as AmbiguousIfCopy<_>>::marker;
        let _ = <SecretInputCompletion<TestClock> as AmbiguousIfCopy<_>>::marker;
        let _ = <CancelledSecretInputPolicy as AmbiguousIfCopy<_>>::marker;
        let _ = <RejectedSecretInputPolicy as AmbiguousIfCopy<_>>::marker;

        let _: fn(
            AdmittedSecretInputPolicy<TestClock>,
            SecretInputPolicyObservation,
        ) -> StartResult = AdmittedSecretInputPolicy::<TestClock>::begin_ui;
        let _: fn(
            SecretInputUiStartingPolicy<TestClock>,
            SecretInputPolicyObservation,
        ) -> AuthenticateResult = SecretInputUiStartingPolicy::<TestClock>::authenticate_ui;
        let _: fn(
            SecretInputUiAuthenticatedPolicy<TestClock>,
            SecretInputCompletionObservation,
        ) -> CompletionResult = SecretInputUiAuthenticatedPolicy::<TestClock>::complete;
        let _: fn(AdmittedSecretInputPolicy<TestClock>) -> RejectedSecretInputPolicy =
            AdmittedSecretInputPolicy::<TestClock>::cancel;
        let _: fn(SecretInputUiStartingPolicy<TestClock>) -> RejectedSecretInputPolicy =
            SecretInputUiStartingPolicy::<TestClock>::cancel;
        let _: fn(SecretInputUiAuthenticatedPolicy<TestClock>) -> RejectedSecretInputPolicy =
            SecretInputUiAuthenticatedPolicy::<TestClock>::cancel;
        let _: fn(AcceptedSecretInputPolicy<TestClock>) -> RejectedSecretInputPolicy =
            AcceptedSecretInputPolicy::<TestClock>::cancel;

        require_rejected(
            accepted(&TestClock::new(1))?.cancel(),
            SecretInputPolicyRejectionCause::Cancelled,
        )
    }

    #[test]
    fn admission_requires_strict_future_exact_correlation_and_secret_input_role()
    -> Result<(), &'static str> {
        let clock = TestClock::new(10);
        for deadline in [9, 10] {
            require_rejection(
                AdmittedSecretInputPolicy::admit_for_test(
                    seed(
                        clock.clone(),
                        VALID_MARKER,
                        VALID_SESSION,
                        ExpectedHelperRole::SecretInput,
                        deadline,
                    )?,
                    valid_observation()?,
                ),
                SecretInputPolicyRejectionCause::DeadlineExpired,
            )?;
        }

        let live = AdmittedSecretInputPolicy::admit_for_test(
            seed(
                clock.clone(),
                VALID_MARKER,
                VALID_SESSION,
                ExpectedHelperRole::SecretInput,
                11,
            )?,
            valid_observation()?,
        )
        .map_err(|_| "strictly future admission was rejected")?;
        assert_exact_binding(
            &live.binding,
            key(VALID_MARKER)?,
            session(VALID_SESSION)?,
            11,
        )?;
        assert_same_clock_source(&live.binding, &clock)?;

        for invalid in [
            observation(OTHER_MARKER, VALID_SESSION, ExpectedHelperRole::SecretInput)?,
            observation(VALID_MARKER, OTHER_SESSION, ExpectedHelperRole::SecretInput)?,
            observation(VALID_MARKER, VALID_SESSION, ExpectedHelperRole::Approval)?,
        ] {
            require_rejection(
                AdmittedSecretInputPolicy::admit_for_test(
                    seed(
                        clock.clone(),
                        VALID_MARKER,
                        VALID_SESSION,
                        ExpectedHelperRole::SecretInput,
                        11,
                    )?,
                    invalid,
                ),
                SecretInputPolicyRejectionCause::InvalidObservation,
            )?;
        }

        require_rejection(
            AdmittedSecretInputPolicy::admit_for_test(
                seed(
                    clock,
                    VALID_MARKER,
                    VALID_SESSION,
                    ExpectedHelperRole::Approval,
                    11,
                )?,
                observation(VALID_MARKER, VALID_SESSION, ExpectedHelperRole::Approval)?,
            ),
            SecretInputPolicyRejectionCause::InvalidObservation,
        )
    }

    #[test]
    fn ui_start_requires_exact_key_session_and_secret_input_role() -> Result<(), &'static str> {
        let clock = TestClock::new(1);
        for invalid in [
            observation(OTHER_MARKER, VALID_SESSION, ExpectedHelperRole::SecretInput)?,
            observation(VALID_MARKER, OTHER_SESSION, ExpectedHelperRole::SecretInput)?,
            observation(VALID_MARKER, VALID_SESSION, ExpectedHelperRole::Approval)?,
        ] {
            require_rejection(
                admitted(&clock)?.begin_ui(invalid),
                SecretInputPolicyRejectionCause::InvalidObservation,
            )?;
        }

        let live = starting(&clock)?;
        assert_bound(&live.binding, &clock)
    }

    #[test]
    fn ui_authentication_rechecks_exact_key_session_and_secret_input_role()
    -> Result<(), &'static str> {
        let clock = TestClock::new(1);
        for invalid in [
            observation(OTHER_MARKER, VALID_SESSION, ExpectedHelperRole::SecretInput)?,
            observation(VALID_MARKER, OTHER_SESSION, ExpectedHelperRole::SecretInput)?,
            observation(VALID_MARKER, VALID_SESSION, ExpectedHelperRole::Approval)?,
        ] {
            require_rejection(
                starting(&clock)?.authenticate_ui(invalid),
                SecretInputPolicyRejectionCause::InvalidObservation,
            )?;
        }

        let live = authenticated(&clock)?;
        assert_bound(&live.binding, &clock)
    }

    #[test]
    fn completion_rechecks_binding_and_branches_accepted_or_cancelled_once()
    -> Result<(), &'static str> {
        let clock = TestClock::new(1);
        for invalid in [
            observation(OTHER_MARKER, VALID_SESSION, ExpectedHelperRole::SecretInput)?,
            observation(VALID_MARKER, OTHER_SESSION, ExpectedHelperRole::SecretInput)?,
            observation(VALID_MARKER, VALID_SESSION, ExpectedHelperRole::Approval)?,
        ] {
            require_rejection(
                authenticated(&clock)?
                    .complete(SecretInputCompletionObservation::accepted_for_test(invalid)),
                SecretInputPolicyRejectionCause::InvalidObservation,
            )?;
        }

        let accepted_reads = clock.reads();
        let accepted = authenticated(&clock)?;
        let reads_before_completion = clock.reads();
        let accepted = match accepted.complete(SecretInputCompletionObservation::accepted_for_test(
            valid_observation()?,
        )) {
            Ok(SecretInputCompletion::Accepted(accepted)) => accepted,
            Ok(SecretInputCompletion::Cancelled(_)) => return Err("acceptance branch cancelled"),
            Err(_) => return Err("acceptance branch rejected"),
        };
        if clock.reads() - reads_before_completion != 1 || clock.reads() <= accepted_reads {
            return Err("acceptance did not consume exactly one fresh observation read");
        }
        assert_bound(&accepted.binding, &clock)?;

        let authenticated = authenticated(&clock)?;
        let reads_before_completion = clock.reads();
        match authenticated.complete(SecretInputCompletionObservation::cancelled_for_test(
            valid_observation()?,
        )) {
            Ok(SecretInputCompletion::Cancelled(cancelled)) => require_cancelled(cancelled),
            Ok(SecretInputCompletion::Accepted(_)) => return Err("cancellation branch accepted"),
            Err(_) => return Err("cancellation branch rejected"),
        }
        if clock.reads() - reads_before_completion != 1 {
            return Err("cancellation did not consume exactly one fresh observation read");
        }
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One matrix fixes every clocked edge and live recheck.
    fn every_positive_edge_uses_original_inclusive_deadline_and_fresh_clock_read()
    -> Result<(), &'static str> {
        let clock = TestClock::new(1);
        let admitted_live = admitted(&clock)?;
        assert_bound(&admitted_live.binding, &clock)?;
        let starting_live = admitted_live
            .begin_ui(valid_observation()?)
            .map_err(|_| "UI start before deadline failed")?;
        assert_bound(&starting_live.binding, &clock)?;
        let authenticated_live = starting_live
            .authenticate_ui(valid_observation()?)
            .map_err(|_| "UI authentication before deadline failed")?;
        assert_bound(&authenticated_live.binding, &clock)?;
        let accepted_live = match authenticated_live.complete(
            SecretInputCompletionObservation::accepted_for_test(valid_observation()?),
        ) {
            Ok(SecretInputCompletion::Accepted(accepted)) => accepted,
            Ok(SecretInputCompletion::Cancelled(_)) => return Err("positive edge cancelled"),
            Err(_) => return Err("positive edge rejected"),
        };
        assert_bound(&accepted_live.binding, &clock)?;
        let accepted_live = accepted_live
            .recheck_liveness(valid_observation()?)
            .map_err(|_| "accepted liveness before deadline failed")?;
        assert_bound(&accepted_live.binding, &clock)?;

        let admitted_checked = admitted(&clock)?
            .recheck_liveness(valid_observation()?)
            .map_err(|_| "admitted liveness before deadline failed")?;
        assert_bound(&admitted_checked.binding, &clock)?;
        let starting_checked = starting(&clock)?
            .recheck_liveness(valid_observation()?)
            .map_err(|_| "starting liveness before deadline failed")?;
        assert_bound(&starting_checked.binding, &clock)?;
        let authenticated_checked = authenticated(&clock)?
            .recheck_liveness(valid_observation()?)
            .map_err(|_| "authenticated liveness before deadline failed")?;
        assert_bound(&authenticated_checked.binding, &clock)?;

        let admitted_at_boundary = admitted(&clock)?;
        let starting_at_boundary = starting(&clock)?;
        let authenticated_at_boundary = authenticated(&clock)?;
        let accepted_at_boundary = accepted(&clock)?;
        let admitted_liveness_boundary = admitted(&clock)?;
        let starting_liveness_boundary = starting(&clock)?;
        let authenticated_liveness_boundary = authenticated(&clock)?;
        clock.set_now(VALID_DEADLINE);
        require_rejection(
            admitted_at_boundary.begin_ui(valid_observation()?),
            SecretInputPolicyRejectionCause::DeadlineExpired,
        )?;
        require_rejection(
            starting_at_boundary.authenticate_ui(valid_observation()?),
            SecretInputPolicyRejectionCause::DeadlineExpired,
        )?;
        require_rejection(
            authenticated_at_boundary.complete(
                SecretInputCompletionObservation::accepted_for_test(valid_observation()?),
            ),
            SecretInputPolicyRejectionCause::DeadlineExpired,
        )?;
        require_rejection(
            accepted_at_boundary.recheck_liveness(valid_observation()?),
            SecretInputPolicyRejectionCause::DeadlineExpired,
        )?;
        require_rejection(
            admitted_liveness_boundary.recheck_liveness(valid_observation()?),
            SecretInputPolicyRejectionCause::DeadlineExpired,
        )?;
        require_rejection(
            starting_liveness_boundary.recheck_liveness(valid_observation()?),
            SecretInputPolicyRejectionCause::DeadlineExpired,
        )?;
        require_rejection(
            authenticated_liveness_boundary.recheck_liveness(valid_observation()?),
            SecretInputPolicyRejectionCause::DeadlineExpired,
        )?;

        clock.set_now(1);
        let admitted_at_failure = admitted(&clock)?;
        let starting_at_failure = starting(&clock)?;
        let authenticated_at_failure = authenticated(&clock)?;
        let accepted_at_failure = accepted(&clock)?;
        let admitted_liveness_failure = admitted(&clock)?;
        let starting_liveness_failure = starting(&clock)?;
        let authenticated_liveness_failure = authenticated(&clock)?;
        clock.set_failure(true);
        let reads_before = clock.reads();
        require_rejection(
            AdmittedSecretInputPolicy::admit_for_test(
                seed(
                    clock.clone(),
                    VALID_MARKER,
                    VALID_SESSION,
                    ExpectedHelperRole::SecretInput,
                    VALID_DEADLINE,
                )?,
                valid_observation()?,
            ),
            SecretInputPolicyRejectionCause::ClockUnavailable,
        )?;
        require_rejection(
            admitted_at_failure.begin_ui(valid_observation()?),
            SecretInputPolicyRejectionCause::ClockUnavailable,
        )?;
        require_rejection(
            starting_at_failure.authenticate_ui(valid_observation()?),
            SecretInputPolicyRejectionCause::ClockUnavailable,
        )?;
        require_rejection(
            authenticated_at_failure.complete(SecretInputCompletionObservation::accepted_for_test(
                valid_observation()?,
            )),
            SecretInputPolicyRejectionCause::ClockUnavailable,
        )?;
        require_rejection(
            accepted_at_failure.recheck_liveness(valid_observation()?),
            SecretInputPolicyRejectionCause::ClockUnavailable,
        )?;
        require_rejection(
            admitted_liveness_failure.recheck_liveness(valid_observation()?),
            SecretInputPolicyRejectionCause::ClockUnavailable,
        )?;
        require_rejection(
            starting_liveness_failure.recheck_liveness(valid_observation()?),
            SecretInputPolicyRejectionCause::ClockUnavailable,
        )?;
        require_rejection(
            authenticated_liveness_failure.recheck_liveness(valid_observation()?),
            SecretInputPolicyRejectionCause::ClockUnavailable,
        )?;
        if clock.reads() - reads_before != 8 {
            return Err("not every positive edge performed one fresh clock read");
        }
        Ok(())
    }

    #[test]
    fn lifecycle_cancellation_rejects_every_live_stage_and_ui_cancel_is_distinct()
    -> Result<(), &'static str> {
        let clock = TestClock::new(1);
        for rejected in [
            admitted(&clock)?.cancel(),
            starting(&clock)?.cancel(),
            authenticated(&clock)?.cancel(),
            accepted(&clock)?.cancel(),
        ] {
            require_rejected(rejected, SecretInputPolicyRejectionCause::Cancelled)?;
        }

        match authenticated(&clock)?.complete(SecretInputCompletionObservation::cancelled_for_test(
            valid_observation()?,
        )) {
            Ok(SecretInputCompletion::Cancelled(cancelled)) => require_cancelled(cancelled),
            Ok(SecretInputCompletion::Accepted(_)) => {
                return Err("authenticated UI cancellation was accepted");
            }
            Err(_) => return Err("authenticated UI cancellation was rejected"),
        }
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Four stages fix matching and unrelated session behavior.
    fn targeted_invalidation_rejects_matching_and_preserves_unrelated_session()
    -> Result<(), &'static str> {
        let clock = TestClock::new(1);
        let matching = session(VALID_SESSION)?;
        let unrelated = session(OTHER_SESSION)?;

        require_rejection(
            admitted(&clock)?.invalidate_session(matching),
            SecretInputPolicyRejectionCause::SessionInvalidated,
        )?;
        require_rejection(
            starting(&clock)?.invalidate_session(matching),
            SecretInputPolicyRejectionCause::SessionInvalidated,
        )?;
        require_rejection(
            authenticated(&clock)?.invalidate_session(matching),
            SecretInputPolicyRejectionCause::SessionInvalidated,
        )?;
        require_rejection(
            accepted(&clock)?.invalidate_session(matching),
            SecretInputPolicyRejectionCause::SessionInvalidated,
        )?;

        let admitted_live = admitted(&clock)?
            .invalidate_session(unrelated)
            .map_err(|_| "unrelated session rejected admitted state")?;
        assert_bound(&admitted_live.binding, &clock)?;
        let starting_live = starting(&clock)?
            .invalidate_session(unrelated)
            .map_err(|_| "unrelated session rejected starting state")?;
        assert_bound(&starting_live.binding, &clock)?;
        let authenticated_live = authenticated(&clock)?
            .invalidate_session(unrelated)
            .map_err(|_| "unrelated session rejected authenticated state")?;
        assert_bound(&authenticated_live.binding, &clock)?;
        let accepted_live = accepted(&clock)?
            .invalidate_session(unrelated)
            .map_err(|_| "unrelated session rejected accepted state")?;
        assert_bound(&accepted_live.binding, &clock)
    }

    #[test]
    fn active_invalidation_terminates_every_live_stage() -> Result<(), &'static str> {
        let clock = TestClock::new(1);
        for rejected in [
            admitted(&clock)?.invalidate_active_sessions(),
            starting(&clock)?.invalidate_active_sessions(),
            authenticated(&clock)?.invalidate_active_sessions(),
            accepted(&clock)?.invalidate_active_sessions(),
        ] {
            require_rejected(
                rejected,
                SecretInputPolicyRejectionCause::ActiveSessionsInvalidated,
            )?;
        }
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Exact strings cover every policy-bearing Debug surface.
    fn terminal_and_debug_surfaces_are_data_free() -> Result<(), &'static str> {
        let clock = TestClock::new(1);
        let seed_debug = format!(
            "{:?}",
            seed(
                clock.clone(),
                VALID_MARKER,
                VALID_SESSION,
                ExpectedHelperRole::SecretInput,
                VALID_DEADLINE,
            )?
        );
        let observation_debug = format!("{:?}", valid_observation()?);
        let completion_observation_debug = format!(
            "{:?}",
            SecretInputCompletionObservation::accepted_for_test(valid_observation()?)
        );
        let binding_debug = format!("{:?}", admitted(&clock)?.binding);
        if seed_debug != "SecretInputPolicySeed([REDACTED])"
            || observation_debug != "SecretInputPolicyObservation([REDACTED])"
            || completion_observation_debug != "SecretInputCompletionObservation([REDACTED])"
            || binding_debug != "SecretInputBinding([REDACTED])"
            || format!("{:?}", admitted(&clock)?) != "AdmittedSecretInputPolicy([REDACTED])"
            || format!("{:?}", starting(&clock)?) != "SecretInputUiStartingPolicy([REDACTED])"
            || format!("{:?}", authenticated(&clock)?)
                != "SecretInputUiAuthenticatedPolicy([REDACTED])"
            || format!("{:?}", accepted(&clock)?) != "AcceptedSecretInputPolicy([REDACTED])"
        {
            return Err("a live Secret Input Debug surface was not exactly redacted");
        }

        let accepted_completion = authenticated(&clock)?
            .complete(SecretInputCompletionObservation::accepted_for_test(
                valid_observation()?,
            ))
            .map_err(|_| "accepted completion was rejected")?;
        let cancelled_completion = authenticated(&clock)?
            .complete(SecretInputCompletionObservation::cancelled_for_test(
                valid_observation()?,
            ))
            .map_err(|_| "cancelled completion was rejected")?;
        if format!("{accepted_completion:?}") != "SecretInputCompletion([REDACTED])"
            || format!("{cancelled_completion:?}") != "SecretInputCompletion([REDACTED])"
        {
            return Err("completion Debug exposed branch or request data");
        }
        let cancelled = match cancelled_completion {
            SecretInputCompletion::Cancelled(cancelled) => cancelled,
            SecretInputCompletion::Accepted(_) => return Err("cancelled completion was accepted"),
        };
        match accepted_completion {
            SecretInputCompletion::Accepted(_) => {}
            SecretInputCompletion::Cancelled(_) => return Err("accepted completion was cancelled"),
        }
        if format!("{cancelled:?}") != "CancelledSecretInputPolicy" {
            return Err("authenticated UI cancellation Debug exposed request data");
        }
        let lifecycle_cancel = admitted(&clock)?.cancel();
        if format!("{lifecycle_cancel:?}") != "RejectedSecretInputPolicy { cause: Cancelled, .. }" {
            return Err("lifecycle cancellation was confused with UI completion cancellation");
        }

        let causes = [
            SecretInputPolicyRejectionCause::ClockUnavailable,
            SecretInputPolicyRejectionCause::DeadlineExpired,
            SecretInputPolicyRejectionCause::InvalidObservation,
            SecretInputPolicyRejectionCause::Cancelled,
            SecretInputPolicyRejectionCause::SessionInvalidated,
            SecretInputPolicyRejectionCause::ActiveSessionsInvalidated,
        ];
        for cause in causes {
            let rejected = reject_binding(admitted(&clock)?.binding, cause);
            let expected = format!("RejectedSecretInputPolicy {{ cause: {cause:?}, .. }}");
            if format!("{rejected:?}") != expected {
                return Err("terminal rejection Debug exposed request data");
            }
        }
        Ok(())
    }
}
