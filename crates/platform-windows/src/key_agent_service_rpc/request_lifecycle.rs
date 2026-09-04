//! Dormant, no-authority Approval request ordering policy.
//!
//! This private, production-compiled typestate models only the ordering between
//! an admitted Approval request, UI startup, UI authentication, and one UI
//! decision. `AdmittedRequestPolicy` is deliberately separate from
//! `expected_peer::PeerPhase::Admitted`: that phase follows `HelperReady`
//! manager admission, while this module carries no process, pipe, token, lease,
//! cleanup, signing, wallet, secret, or durable-decision authority.
//!
//! No production constructor exists. Test-only seeds and observations exercise
//! the policy until a future composition owns an authenticated source.

#![forbid(unsafe_code)]

use core::{fmt, num::NonZeroU32};

use super::{
    epoch::MonotonicClock,
    expected_peer::{ExpectedHelperRole, ExpectedPeerKey},
};

/// Data-free reason that a request policy reached its terminal rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RequestPolicyRejectionCause {
    ClockUnavailable,
    DeadlineExpired,
    InvalidObservation,
    Cancelled,
    SessionInvalidated,
    ActiveSessionsInvalidated,
    UserRejected,
}

struct MoveOnly;

/// Move-only binding supplied by a future authenticated composition.
///
/// Its only constructor is test-only. In particular, this token does not prove
/// that an operating-system owner or cleanup obligation exists.
#[must_use = "a request seed must be admitted or rejected exactly once"]
pub(super) struct RequestPolicySeed<C>
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
impl<C> RequestPolicySeed<C>
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

impl<C> fmt::Debug for RequestPolicySeed<C>
where
    C: MonotonicClock,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestPolicySeed([REDACTED])")
    }
}

/// One move-only request-policy observation.
///
/// The pure policy can recheck only the bound clock's original inclusive
/// deadline and equality with this observation. It does not prove process or
/// expected-peer liveness. A future production mint must consume fresh
/// authenticated Approval UI and expected-peer liveness proofs before
/// constructing each one-shot observation. Construction remains test-only
/// here; callers cannot nominate a key, session, or role through a production
/// request-policy API.
pub(super) struct RequestPolicyObservation {
    key: ExpectedPeerKey,
    session_id: NonZeroU32,
    role: ExpectedHelperRole,
    _move_only: MoveOnly,
}

#[cfg(test)]
impl RequestPolicyObservation {
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

impl fmt::Debug for RequestPolicyObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestPolicyObservation([REDACTED])")
    }
}

#[derive(Clone, Copy)]
enum UiDecision {
    Approve,
    Reject,
}

/// One authenticated UI decision observation.
///
/// It deliberately carries no transcript, intent, signature, wallet material,
/// or cleanup evidence. Its constructors are test-only.
pub(super) struct UiDecisionObservation {
    peer: RequestPolicyObservation,
    decision: UiDecision,
}

#[cfg(test)]
impl UiDecisionObservation {
    const fn approve_for_test(peer: RequestPolicyObservation) -> Self {
        Self {
            peer,
            decision: UiDecision::Approve,
        }
    }

    const fn reject_for_test(peer: RequestPolicyObservation) -> Self {
        Self {
            peer,
            decision: UiDecision::Reject,
        }
    }
}

impl fmt::Debug for UiDecisionObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UiDecisionObservation([REDACTED])")
    }
}

struct RequestBinding<C>
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

impl<C> RequestBinding<C>
where
    C: MonotonicClock,
{
    #[allow(clippy::needless_pass_by_value)] // A fresh observation is a one-shot policy input.
    fn validate(
        &self,
        observation: RequestPolicyObservation,
    ) -> Result<(), RequestPolicyRejectionCause> {
        let RequestPolicyObservation {
            key,
            session_id,
            role,
            _move_only: _,
        } = observation;
        let now = self
            .clock
            .now()
            .ok_or(RequestPolicyRejectionCause::ClockUnavailable)?;
        if now >= self.original_deadline {
            return Err(RequestPolicyRejectionCause::DeadlineExpired);
        }
        if self.role != ExpectedHelperRole::Approval
            || role != ExpectedHelperRole::Approval
            || key != self.key
            || session_id != self.session_id
        {
            return Err(RequestPolicyRejectionCause::InvalidObservation);
        }
        Ok(())
    }
}

impl<C> fmt::Debug for RequestBinding<C>
where
    C: MonotonicClock,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestBinding([REDACTED])")
    }
}

/// An Approval request admitted into the pure-policy ordering model.
#[must_use = "an admitted request remains non-durable and must advance or reject"]
pub(super) struct AdmittedRequestPolicy<C>
where
    C: MonotonicClock,
{
    binding: RequestBinding<C>,
}

impl<C> AdmittedRequestPolicy<C>
where
    C: MonotonicClock,
{
    #[cfg(test)]
    fn admit_for_test(
        seed: RequestPolicySeed<C>,
        observation: RequestPolicyObservation,
    ) -> Result<Self, RejectedRequestPolicy> {
        let RequestPolicySeed {
            clock,
            key,
            session_id,
            role,
            original_deadline,
            _move_only: _,
        } = seed;
        let binding = RequestBinding {
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
        observation: RequestPolicyObservation,
    ) -> Result<UiStartingRequestPolicy<C>, RejectedRequestPolicy> {
        match self.binding.validate(observation) {
            Ok(()) => Ok(UiStartingRequestPolicy {
                binding: self.binding,
            }),
            Err(cause) => Err(reject_binding(self.binding, cause)),
        }
    }

    pub(super) fn recheck_liveness(
        self,
        observation: RequestPolicyObservation,
    ) -> Result<Self, RejectedRequestPolicy> {
        match self.binding.validate(observation) {
            Ok(()) => Ok(self),
            Err(cause) => Err(reject_binding(self.binding, cause)),
        }
    }

    pub(super) fn cancel(self) -> RejectedRequestPolicy {
        reject_binding(self.binding, RequestPolicyRejectionCause::Cancelled)
    }

    pub(super) fn invalidate_session(
        self,
        session_id: NonZeroU32,
    ) -> Result<Self, RejectedRequestPolicy> {
        if self.binding.session_id == session_id {
            Err(reject_binding(
                self.binding,
                RequestPolicyRejectionCause::SessionInvalidated,
            ))
        } else {
            Ok(self)
        }
    }

    pub(super) fn invalidate_active_sessions(self) -> RejectedRequestPolicy {
        reject_binding(
            self.binding,
            RequestPolicyRejectionCause::ActiveSessionsInvalidated,
        )
    }
}

impl<C> fmt::Debug for AdmittedRequestPolicy<C>
where
    C: MonotonicClock,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdmittedRequestPolicy([REDACTED])")
    }
}

/// An Approval UI whose start was accepted but is not yet authenticated.
#[must_use = "a starting UI remains non-durable and must authenticate or reject"]
pub(super) struct UiStartingRequestPolicy<C>
where
    C: MonotonicClock,
{
    binding: RequestBinding<C>,
}

impl<C> UiStartingRequestPolicy<C>
where
    C: MonotonicClock,
{
    pub(super) fn authenticate_ui(
        self,
        observation: RequestPolicyObservation,
    ) -> Result<UiAuthenticatedRequestPolicy<C>, RejectedRequestPolicy> {
        match self.binding.validate(observation) {
            Ok(()) => Ok(UiAuthenticatedRequestPolicy {
                binding: self.binding,
            }),
            Err(cause) => Err(reject_binding(self.binding, cause)),
        }
    }

    pub(super) fn recheck_liveness(
        self,
        observation: RequestPolicyObservation,
    ) -> Result<Self, RejectedRequestPolicy> {
        match self.binding.validate(observation) {
            Ok(()) => Ok(self),
            Err(cause) => Err(reject_binding(self.binding, cause)),
        }
    }

    pub(super) fn cancel(self) -> RejectedRequestPolicy {
        reject_binding(self.binding, RequestPolicyRejectionCause::Cancelled)
    }

    pub(super) fn invalidate_session(
        self,
        session_id: NonZeroU32,
    ) -> Result<Self, RejectedRequestPolicy> {
        if self.binding.session_id == session_id {
            Err(reject_binding(
                self.binding,
                RequestPolicyRejectionCause::SessionInvalidated,
            ))
        } else {
            Ok(self)
        }
    }

    pub(super) fn invalidate_active_sessions(self) -> RejectedRequestPolicy {
        reject_binding(
            self.binding,
            RequestPolicyRejectionCause::ActiveSessionsInvalidated,
        )
    }
}

impl<C> fmt::Debug for UiStartingRequestPolicy<C>
where
    C: MonotonicClock,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UiStartingRequestPolicy([REDACTED])")
    }
}

/// An exact Approval UI authenticated immediately before its one decision.
#[must_use = "an authenticated UI remains non-durable and must decide or reject"]
pub(super) struct UiAuthenticatedRequestPolicy<C>
where
    C: MonotonicClock,
{
    binding: RequestBinding<C>,
}

impl<C> UiAuthenticatedRequestPolicy<C>
where
    C: MonotonicClock,
{
    pub(super) fn decide(
        self,
        observation: UiDecisionObservation,
    ) -> Result<ApprovedRequestPolicy<C>, RejectedRequestPolicy> {
        let UiDecisionObservation { peer, decision } = observation;
        if let Err(cause) = self.binding.validate(peer) {
            return Err(reject_binding(self.binding, cause));
        }
        match decision {
            UiDecision::Approve => Ok(ApprovedRequestPolicy {
                binding: self.binding,
            }),
            UiDecision::Reject => Err(reject_binding(
                self.binding,
                RequestPolicyRejectionCause::UserRejected,
            )),
        }
    }

    pub(super) fn recheck_liveness(
        self,
        observation: RequestPolicyObservation,
    ) -> Result<Self, RejectedRequestPolicy> {
        match self.binding.validate(observation) {
            Ok(()) => Ok(self),
            Err(cause) => Err(reject_binding(self.binding, cause)),
        }
    }

    pub(super) fn cancel(self) -> RejectedRequestPolicy {
        reject_binding(self.binding, RequestPolicyRejectionCause::Cancelled)
    }

    pub(super) fn invalidate_session(
        self,
        session_id: NonZeroU32,
    ) -> Result<Self, RejectedRequestPolicy> {
        if self.binding.session_id == session_id {
            Err(reject_binding(
                self.binding,
                RequestPolicyRejectionCause::SessionInvalidated,
            ))
        } else {
            Ok(self)
        }
    }

    pub(super) fn invalidate_active_sessions(self) -> RejectedRequestPolicy {
        reject_binding(
            self.binding,
            RequestPolicyRejectionCause::ActiveSessionsInvalidated,
        )
    }
}

impl<C> fmt::Debug for UiAuthenticatedRequestPolicy<C>
where
    C: MonotonicClock,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UiAuthenticatedRequestPolicy([REDACTED])")
    }
}

/// A non-durable Approval observation with no signing or cleanup authority.
///
/// Approval remains live-bound, expiring, cancellable, and invalidatable. This
/// type intentionally exposes no accessor or conversion into an intent,
/// transcript, wallet, signing operation, private key, or cleanup receipt.
#[must_use = "approval is non-durable and must remain live or reject"]
pub(super) struct ApprovedRequestPolicy<C>
where
    C: MonotonicClock,
{
    binding: RequestBinding<C>,
}

impl<C> ApprovedRequestPolicy<C>
where
    C: MonotonicClock,
{
    pub(super) fn recheck_liveness(
        self,
        observation: RequestPolicyObservation,
    ) -> Result<Self, RejectedRequestPolicy> {
        match self.binding.validate(observation) {
            Ok(()) => Ok(self),
            Err(cause) => Err(reject_binding(self.binding, cause)),
        }
    }

    pub(super) fn cancel(self) -> RejectedRequestPolicy {
        reject_binding(self.binding, RequestPolicyRejectionCause::Cancelled)
    }

    pub(super) fn invalidate_session(
        self,
        session_id: NonZeroU32,
    ) -> Result<Self, RejectedRequestPolicy> {
        if self.binding.session_id == session_id {
            Err(reject_binding(
                self.binding,
                RequestPolicyRejectionCause::SessionInvalidated,
            ))
        } else {
            Ok(self)
        }
    }

    pub(super) fn invalidate_active_sessions(self) -> RejectedRequestPolicy {
        reject_binding(
            self.binding,
            RequestPolicyRejectionCause::ActiveSessionsInvalidated,
        )
    }
}

impl<C> fmt::Debug for ApprovedRequestPolicy<C>
where
    C: MonotonicClock,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApprovedRequestPolicy([REDACTED])")
    }
}

/// Terminal, data-free request-policy rejection.
#[must_use = "terminal rejection must be observed"]
pub(super) struct RejectedRequestPolicy {
    cause: RequestPolicyRejectionCause,
    _move_only: MoveOnly,
}

impl fmt::Debug for RejectedRequestPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RejectedRequestPolicy")
            .field("cause", &self.cause)
            .finish_non_exhaustive()
    }
}

fn reject_binding<C>(
    _binding: RequestBinding<C>,
    cause: RequestPolicyRejectionCause,
) -> RejectedRequestPolicy
where
    C: MonotonicClock,
{
    RejectedRequestPolicy {
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
    ) -> Result<RequestPolicyObservation, &'static str> {
        Ok(RequestPolicyObservation::new_for_test(
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
    ) -> Result<RequestPolicySeed<TestClock>, &'static str> {
        Ok(RequestPolicySeed::new_for_test(
            clock,
            key(marker)?,
            session(session_id)?,
            role,
            original_deadline,
        ))
    }

    fn admitted(clock: &TestClock) -> Result<AdmittedRequestPolicy<TestClock>, &'static str> {
        AdmittedRequestPolicy::admit_for_test(
            seed(
                clock.clone(),
                VALID_MARKER,
                VALID_SESSION,
                ExpectedHelperRole::Approval,
                VALID_DEADLINE,
            )?,
            observation(VALID_MARKER, VALID_SESSION, ExpectedHelperRole::Approval)?,
        )
        .map_err(|_| "valid admission was rejected")
    }

    fn starting(clock: &TestClock) -> Result<UiStartingRequestPolicy<TestClock>, &'static str> {
        admitted(clock)?
            .begin_ui(observation(
                VALID_MARKER,
                VALID_SESSION,
                ExpectedHelperRole::Approval,
            )?)
            .map_err(|_| "valid UI start was rejected")
    }

    fn authenticated(
        clock: &TestClock,
    ) -> Result<UiAuthenticatedRequestPolicy<TestClock>, &'static str> {
        starting(clock)?
            .authenticate_ui(observation(
                VALID_MARKER,
                VALID_SESSION,
                ExpectedHelperRole::Approval,
            )?)
            .map_err(|_| "valid UI authentication was rejected")
    }

    fn approved(clock: &TestClock) -> Result<ApprovedRequestPolicy<TestClock>, &'static str> {
        authenticated(clock)?
            .decide(UiDecisionObservation::approve_for_test(observation(
                VALID_MARKER,
                VALID_SESSION,
                ExpectedHelperRole::Approval,
            )?))
            .map_err(|_| "valid approval was rejected")
    }

    fn valid_observation() -> Result<RequestPolicyObservation, &'static str> {
        observation(VALID_MARKER, VALID_SESSION, ExpectedHelperRole::Approval)
    }

    fn require_rejection<T>(
        result: Result<T, RejectedRequestPolicy>,
        expected: RequestPolicyRejectionCause,
    ) -> Result<(), &'static str> {
        match result {
            Err(rejected) if rejected.cause == expected => Ok(()),
            Err(_) => Err("request was rejected for the wrong reason"),
            Ok(_) => Err("request unexpectedly remained live"),
        }
    }

    #[allow(clippy::needless_pass_by_value)] // The test fixes terminal-token consuming semantics.
    fn require_terminal_cause(
        rejected: RejectedRequestPolicy,
        expected: RequestPolicyRejectionCause,
    ) -> Result<(), &'static str> {
        let RejectedRequestPolicy {
            cause,
            _move_only: _,
        } = rejected;
        if cause == expected {
            Ok(())
        } else {
            Err("terminal rejection used the wrong cause")
        }
    }

    fn assert_exact_binding(
        binding: &RequestBinding<TestClock>,
        expected_key: ExpectedPeerKey,
        expected_session: NonZeroU32,
        expected_deadline: u64,
    ) -> Result<(), &'static str> {
        if binding.key != expected_key
            || binding.session_id != expected_session
            || binding.role != ExpectedHelperRole::Approval
            || binding.original_deadline != expected_deadline
        {
            return Err("request binding changed");
        }
        Ok(())
    }

    fn assert_same_clock_source(
        binding: &RequestBinding<TestClock>,
        expected: &TestClock,
    ) -> Result<(), &'static str> {
        if Arc::ptr_eq(&binding.clock.state, &expected.state) {
            Ok(())
        } else {
            Err("request clock source changed")
        }
    }

    #[test]
    fn request_policy_types_are_move_only_and_transition_methods_consume_self()
    -> Result<(), &'static str> {
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

        type StartResult = Result<UiStartingRequestPolicy<TestClock>, RejectedRequestPolicy>;
        type AuthenticateResult =
            Result<UiAuthenticatedRequestPolicy<TestClock>, RejectedRequestPolicy>;
        type DecisionResult = Result<ApprovedRequestPolicy<TestClock>, RejectedRequestPolicy>;

        let _ = <AdmittedRequestPolicy<TestClock> as AmbiguousIfClone<_>>::marker;
        let _ = <UiStartingRequestPolicy<TestClock> as AmbiguousIfClone<_>>::marker;
        let _ = <UiAuthenticatedRequestPolicy<TestClock> as AmbiguousIfClone<_>>::marker;
        let _ = <ApprovedRequestPolicy<TestClock> as AmbiguousIfClone<_>>::marker;
        let _ = <RejectedRequestPolicy as AmbiguousIfClone<_>>::marker;
        let _ = <RequestPolicySeed<TestClock> as AmbiguousIfClone<_>>::marker;
        let _ = <RequestPolicyObservation as AmbiguousIfClone<_>>::marker;
        let _ = <UiDecisionObservation as AmbiguousIfClone<_>>::marker;
        let _ = <RequestBinding<TestClock> as AmbiguousIfClone<_>>::marker;
        let _ = <AdmittedRequestPolicy<TestClock> as AmbiguousIfCopy<_>>::marker;
        let _ = <UiStartingRequestPolicy<TestClock> as AmbiguousIfCopy<_>>::marker;
        let _ = <UiAuthenticatedRequestPolicy<TestClock> as AmbiguousIfCopy<_>>::marker;
        let _ = <ApprovedRequestPolicy<TestClock> as AmbiguousIfCopy<_>>::marker;
        let _ = <RejectedRequestPolicy as AmbiguousIfCopy<_>>::marker;
        let _ = <RequestPolicySeed<TestClock> as AmbiguousIfCopy<_>>::marker;
        let _ = <RequestPolicyObservation as AmbiguousIfCopy<_>>::marker;
        let _ = <UiDecisionObservation as AmbiguousIfCopy<_>>::marker;
        let _ = <RequestBinding<TestClock> as AmbiguousIfCopy<_>>::marker;

        let _: fn(AdmittedRequestPolicy<TestClock>, RequestPolicyObservation) -> StartResult =
            AdmittedRequestPolicy::<TestClock>::begin_ui;
        let _: fn(
            UiStartingRequestPolicy<TestClock>,
            RequestPolicyObservation,
        ) -> AuthenticateResult = UiStartingRequestPolicy::<TestClock>::authenticate_ui;
        let _: fn(
            UiAuthenticatedRequestPolicy<TestClock>,
            UiDecisionObservation,
        ) -> DecisionResult = UiAuthenticatedRequestPolicy::<TestClock>::decide;
        let _: fn(AdmittedRequestPolicy<TestClock>) -> RejectedRequestPolicy =
            AdmittedRequestPolicy::<TestClock>::cancel;
        let _: fn(UiStartingRequestPolicy<TestClock>) -> RejectedRequestPolicy =
            UiStartingRequestPolicy::<TestClock>::cancel;
        let _: fn(UiAuthenticatedRequestPolicy<TestClock>) -> RejectedRequestPolicy =
            UiAuthenticatedRequestPolicy::<TestClock>::cancel;
        let _: fn(ApprovedRequestPolicy<TestClock>) -> RejectedRequestPolicy =
            ApprovedRequestPolicy::<TestClock>::cancel;
        let _: fn(AdmittedRequestPolicy<TestClock>) -> RejectedRequestPolicy =
            AdmittedRequestPolicy::<TestClock>::invalidate_active_sessions;
        let _: fn(UiStartingRequestPolicy<TestClock>) -> RejectedRequestPolicy =
            UiStartingRequestPolicy::<TestClock>::invalidate_active_sessions;
        let _: fn(UiAuthenticatedRequestPolicy<TestClock>) -> RejectedRequestPolicy =
            UiAuthenticatedRequestPolicy::<TestClock>::invalidate_active_sessions;
        let _: fn(ApprovedRequestPolicy<TestClock>) -> RejectedRequestPolicy =
            ApprovedRequestPolicy::<TestClock>::invalidate_active_sessions;

        let clock = TestClock::new(1);
        let rejected = approved(&clock)?.cancel();
        require_terminal_cause(rejected, RequestPolicyRejectionCause::Cancelled)
    }

    #[test]
    fn admission_requires_a_strict_future_deadline() -> Result<(), &'static str> {
        let clock = TestClock::new(10);
        for deadline in [9, 10] {
            require_rejection(
                AdmittedRequestPolicy::admit_for_test(
                    seed(
                        clock.clone(),
                        VALID_MARKER,
                        VALID_SESSION,
                        ExpectedHelperRole::Approval,
                        deadline,
                    )?,
                    observation(VALID_MARKER, VALID_SESSION, ExpectedHelperRole::Approval)?,
                ),
                RequestPolicyRejectionCause::DeadlineExpired,
            )?;
        }

        let live = AdmittedRequestPolicy::admit_for_test(
            seed(
                clock.clone(),
                VALID_MARKER,
                VALID_SESSION,
                ExpectedHelperRole::Approval,
                11,
            )?,
            observation(VALID_MARKER, VALID_SESSION, ExpectedHelperRole::Approval)?,
        )
        .map_err(|_| "strictly future admission was rejected")?;
        assert_exact_binding(
            &live.binding,
            key(VALID_MARKER)?,
            session(VALID_SESSION)?,
            11,
        )?;

        for invalid in [
            observation(OTHER_MARKER, VALID_SESSION, ExpectedHelperRole::Approval)?,
            observation(VALID_MARKER, OTHER_SESSION, ExpectedHelperRole::Approval)?,
        ] {
            require_rejection(
                AdmittedRequestPolicy::admit_for_test(
                    seed(
                        clock.clone(),
                        VALID_MARKER,
                        VALID_SESSION,
                        ExpectedHelperRole::Approval,
                        11,
                    )?,
                    invalid,
                ),
                RequestPolicyRejectionCause::InvalidObservation,
            )?;
        }

        require_rejection(
            AdmittedRequestPolicy::admit_for_test(
                seed(
                    clock.clone(),
                    VALID_MARKER,
                    VALID_SESSION,
                    ExpectedHelperRole::SecretInput,
                    11,
                )?,
                observation(VALID_MARKER, VALID_SESSION, ExpectedHelperRole::SecretInput)?,
            ),
            RequestPolicyRejectionCause::InvalidObservation,
        )
    }

    #[test]
    fn ui_start_requires_exact_key_session_and_approval_role() -> Result<(), &'static str> {
        let clock = TestClock::new(1);
        for invalid in [
            observation(OTHER_MARKER, VALID_SESSION, ExpectedHelperRole::Approval)?,
            observation(VALID_MARKER, OTHER_SESSION, ExpectedHelperRole::Approval)?,
            observation(VALID_MARKER, VALID_SESSION, ExpectedHelperRole::SecretInput)?,
        ] {
            require_rejection(
                admitted(&clock)?.begin_ui(invalid),
                RequestPolicyRejectionCause::InvalidObservation,
            )?;
        }

        let live = starting(&clock)?;
        assert_exact_binding(
            &live.binding,
            key(VALID_MARKER)?,
            session(VALID_SESSION)?,
            VALID_DEADLINE,
        )
    }

    #[test]
    fn ui_authentication_rechecks_exact_key_session_and_approval_role() -> Result<(), &'static str>
    {
        let clock = TestClock::new(1);
        for invalid in [
            observation(OTHER_MARKER, VALID_SESSION, ExpectedHelperRole::Approval)?,
            observation(VALID_MARKER, OTHER_SESSION, ExpectedHelperRole::Approval)?,
            observation(VALID_MARKER, VALID_SESSION, ExpectedHelperRole::SecretInput)?,
        ] {
            require_rejection(
                starting(&clock)?.authenticate_ui(invalid),
                RequestPolicyRejectionCause::InvalidObservation,
            )?;
        }

        let live = authenticated(&clock)?;
        assert_exact_binding(
            &live.binding,
            key(VALID_MARKER)?,
            session(VALID_SESSION)?,
            VALID_DEADLINE,
        )
    }

    #[test]
    fn ui_decision_rechecks_binding_and_branches_exactly_once() -> Result<(), &'static str> {
        let clock = TestClock::new(1);
        for invalid in [
            observation(OTHER_MARKER, VALID_SESSION, ExpectedHelperRole::Approval)?,
            observation(VALID_MARKER, OTHER_SESSION, ExpectedHelperRole::Approval)?,
            observation(VALID_MARKER, VALID_SESSION, ExpectedHelperRole::SecretInput)?,
        ] {
            require_rejection(
                authenticated(&clock)?.decide(UiDecisionObservation::approve_for_test(invalid)),
                RequestPolicyRejectionCause::InvalidObservation,
            )?;
        }

        let rejected = authenticated(&clock)?.decide(UiDecisionObservation::reject_for_test(
            observation(VALID_MARKER, VALID_SESSION, ExpectedHelperRole::Approval)?,
        ));
        require_rejection(rejected, RequestPolicyRejectionCause::UserRejected)?;

        let live = approved(&clock)?;
        assert_exact_binding(
            &live.binding,
            key(VALID_MARKER)?,
            session(VALID_SESSION)?,
            VALID_DEADLINE,
        )
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One matrix proves every clocked edge uses one immutable deadline.
    fn every_positive_edge_uses_the_original_inclusive_deadline() -> Result<(), &'static str> {
        let clock = TestClock::new(1);
        let admitted_live = admitted(&clock)?;
        assert_exact_binding(
            &admitted_live.binding,
            key(VALID_MARKER)?,
            session(VALID_SESSION)?,
            VALID_DEADLINE,
        )?;
        let starting_live = admitted_live
            .begin_ui(observation(
                VALID_MARKER,
                VALID_SESSION,
                ExpectedHelperRole::Approval,
            )?)
            .map_err(|_| "UI start before the deadline failed")?;
        assert_exact_binding(
            &starting_live.binding,
            key(VALID_MARKER)?,
            session(VALID_SESSION)?,
            VALID_DEADLINE,
        )?;
        let authenticated_live = starting_live
            .authenticate_ui(observation(
                VALID_MARKER,
                VALID_SESSION,
                ExpectedHelperRole::Approval,
            )?)
            .map_err(|_| "UI authentication before the deadline failed")?;
        assert_exact_binding(
            &authenticated_live.binding,
            key(VALID_MARKER)?,
            session(VALID_SESSION)?,
            VALID_DEADLINE,
        )?;
        let approved_live = authenticated_live
            .decide(UiDecisionObservation::approve_for_test(observation(
                VALID_MARKER,
                VALID_SESSION,
                ExpectedHelperRole::Approval,
            )?))
            .map_err(|_| "UI decision before the deadline failed")?;
        assert_exact_binding(
            &approved_live.binding,
            key(VALID_MARKER)?,
            session(VALID_SESSION)?,
            VALID_DEADLINE,
        )?;
        let approved_live = approved_live
            .recheck_liveness(observation(
                VALID_MARKER,
                VALID_SESSION,
                ExpectedHelperRole::Approval,
            )?)
            .map_err(|_| "approved liveness before the deadline failed")?;
        assert_exact_binding(
            &approved_live.binding,
            key(VALID_MARKER)?,
            session(VALID_SESSION)?,
            VALID_DEADLINE,
        )?;

        let admitted_checked = admitted(&clock)?
            .recheck_liveness(valid_observation()?)
            .map_err(|_| "admitted liveness before the deadline failed")?;
        assert_exact_binding(
            &admitted_checked.binding,
            key(VALID_MARKER)?,
            session(VALID_SESSION)?,
            VALID_DEADLINE,
        )?;
        let starting_checked = starting(&clock)?
            .recheck_liveness(valid_observation()?)
            .map_err(|_| "starting liveness before the deadline failed")?;
        assert_exact_binding(
            &starting_checked.binding,
            key(VALID_MARKER)?,
            session(VALID_SESSION)?,
            VALID_DEADLINE,
        )?;
        let authenticated_checked = authenticated(&clock)?
            .recheck_liveness(valid_observation()?)
            .map_err(|_| "authenticated liveness before the deadline failed")?;
        assert_exact_binding(
            &authenticated_checked.binding,
            key(VALID_MARKER)?,
            session(VALID_SESSION)?,
            VALID_DEADLINE,
        )?;

        let admitted_at_boundary = admitted(&clock)?;
        let starting_at_boundary = starting(&clock)?;
        let authenticated_at_boundary = authenticated(&clock)?;
        let approved_at_boundary = approved(&clock)?;
        let admitted_liveness_boundary = admitted(&clock)?;
        let starting_liveness_boundary = starting(&clock)?;
        let authenticated_liveness_boundary = authenticated(&clock)?;
        clock.set_now(VALID_DEADLINE);
        require_rejection(
            admitted_at_boundary.begin_ui(observation(
                VALID_MARKER,
                VALID_SESSION,
                ExpectedHelperRole::Approval,
            )?),
            RequestPolicyRejectionCause::DeadlineExpired,
        )?;
        require_rejection(
            starting_at_boundary.authenticate_ui(observation(
                VALID_MARKER,
                VALID_SESSION,
                ExpectedHelperRole::Approval,
            )?),
            RequestPolicyRejectionCause::DeadlineExpired,
        )?;
        require_rejection(
            authenticated_at_boundary.decide(UiDecisionObservation::approve_for_test(observation(
                VALID_MARKER,
                VALID_SESSION,
                ExpectedHelperRole::Approval,
            )?)),
            RequestPolicyRejectionCause::DeadlineExpired,
        )?;
        require_rejection(
            approved_at_boundary.recheck_liveness(observation(
                VALID_MARKER,
                VALID_SESSION,
                ExpectedHelperRole::Approval,
            )?),
            RequestPolicyRejectionCause::DeadlineExpired,
        )?;
        require_rejection(
            admitted_liveness_boundary.recheck_liveness(valid_observation()?),
            RequestPolicyRejectionCause::DeadlineExpired,
        )?;
        require_rejection(
            starting_liveness_boundary.recheck_liveness(valid_observation()?),
            RequestPolicyRejectionCause::DeadlineExpired,
        )?;
        require_rejection(
            authenticated_liveness_boundary.recheck_liveness(valid_observation()?),
            RequestPolicyRejectionCause::DeadlineExpired,
        )?;

        clock.set_now(1);
        let admitted_at_failure = admitted(&clock)?;
        let starting_at_failure = starting(&clock)?;
        let authenticated_at_failure = authenticated(&clock)?;
        let approved_at_failure = approved(&clock)?;
        let admitted_liveness_failure = admitted(&clock)?;
        let starting_liveness_failure = starting(&clock)?;
        let authenticated_liveness_failure = authenticated(&clock)?;
        clock.set_failure(true);
        let reads_before = clock.reads();
        require_rejection(
            AdmittedRequestPolicy::admit_for_test(
                seed(
                    clock.clone(),
                    VALID_MARKER,
                    VALID_SESSION,
                    ExpectedHelperRole::Approval,
                    VALID_DEADLINE,
                )?,
                observation(VALID_MARKER, VALID_SESSION, ExpectedHelperRole::Approval)?,
            ),
            RequestPolicyRejectionCause::ClockUnavailable,
        )?;
        require_rejection(
            admitted_at_failure.begin_ui(observation(
                VALID_MARKER,
                VALID_SESSION,
                ExpectedHelperRole::Approval,
            )?),
            RequestPolicyRejectionCause::ClockUnavailable,
        )?;
        require_rejection(
            starting_at_failure.authenticate_ui(observation(
                VALID_MARKER,
                VALID_SESSION,
                ExpectedHelperRole::Approval,
            )?),
            RequestPolicyRejectionCause::ClockUnavailable,
        )?;
        require_rejection(
            authenticated_at_failure.decide(UiDecisionObservation::approve_for_test(observation(
                VALID_MARKER,
                VALID_SESSION,
                ExpectedHelperRole::Approval,
            )?)),
            RequestPolicyRejectionCause::ClockUnavailable,
        )?;
        require_rejection(
            approved_at_failure.recheck_liveness(observation(
                VALID_MARKER,
                VALID_SESSION,
                ExpectedHelperRole::Approval,
            )?),
            RequestPolicyRejectionCause::ClockUnavailable,
        )?;
        require_rejection(
            admitted_liveness_failure.recheck_liveness(valid_observation()?),
            RequestPolicyRejectionCause::ClockUnavailable,
        )?;
        require_rejection(
            starting_liveness_failure.recheck_liveness(valid_observation()?),
            RequestPolicyRejectionCause::ClockUnavailable,
        )?;
        require_rejection(
            authenticated_liveness_failure.recheck_liveness(valid_observation()?),
            RequestPolicyRejectionCause::ClockUnavailable,
        )?;
        if clock.reads() - reads_before != 8 {
            return Err("not every positive edge performed a fresh clock read");
        }
        Ok(())
    }

    #[test]
    fn cancellation_rejects_every_non_durable_stage_including_approved() -> Result<(), &'static str>
    {
        let clock = TestClock::new(1);
        for rejected in [
            admitted(&clock)?.cancel(),
            starting(&clock)?.cancel(),
            authenticated(&clock)?.cancel(),
            approved(&clock)?.cancel(),
        ] {
            require_terminal_cause(rejected, RequestPolicyRejectionCause::Cancelled)?;
        }
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)] // The four-stage matrix fixes both sides of targeted invalidation.
    fn targeted_invalidation_rejects_only_the_matching_session_at_every_stage()
    -> Result<(), &'static str> {
        let clock = TestClock::new(1);
        let matching = session(VALID_SESSION)?;
        let unrelated = session(OTHER_SESSION)?;

        require_rejection(
            admitted(&clock)?.invalidate_session(matching),
            RequestPolicyRejectionCause::SessionInvalidated,
        )?;
        require_rejection(
            starting(&clock)?.invalidate_session(matching),
            RequestPolicyRejectionCause::SessionInvalidated,
        )?;
        require_rejection(
            authenticated(&clock)?.invalidate_session(matching),
            RequestPolicyRejectionCause::SessionInvalidated,
        )?;
        require_rejection(
            approved(&clock)?.invalidate_session(matching),
            RequestPolicyRejectionCause::SessionInvalidated,
        )?;

        let admitted_live = admitted(&clock)?
            .invalidate_session(unrelated)
            .map_err(|_| "unrelated session rejected admitted state")?;
        assert_exact_binding(
            &admitted_live.binding,
            key(VALID_MARKER)?,
            matching,
            VALID_DEADLINE,
        )?;
        assert_same_clock_source(&admitted_live.binding, &clock)?;
        let starting_live = starting(&clock)?
            .invalidate_session(unrelated)
            .map_err(|_| "unrelated session rejected starting state")?;
        assert_exact_binding(
            &starting_live.binding,
            key(VALID_MARKER)?,
            matching,
            VALID_DEADLINE,
        )?;
        assert_same_clock_source(&starting_live.binding, &clock)?;
        let authenticated_live = authenticated(&clock)?
            .invalidate_session(unrelated)
            .map_err(|_| "unrelated session rejected authenticated state")?;
        assert_exact_binding(
            &authenticated_live.binding,
            key(VALID_MARKER)?,
            matching,
            VALID_DEADLINE,
        )?;
        assert_same_clock_source(&authenticated_live.binding, &clock)?;
        let approved_live = approved(&clock)?
            .invalidate_session(unrelated)
            .map_err(|_| "unrelated session rejected approved state")?;
        assert_exact_binding(
            &approved_live.binding,
            key(VALID_MARKER)?,
            matching,
            VALID_DEADLINE,
        )?;
        assert_same_clock_source(&approved_live.binding, &clock)
    }

    #[test]
    fn active_session_invalidation_rejects_every_non_durable_stage() -> Result<(), &'static str> {
        let clock = TestClock::new(1);
        for rejected in [
            admitted(&clock)?.invalidate_active_sessions(),
            starting(&clock)?.invalidate_active_sessions(),
            authenticated(&clock)?.invalidate_active_sessions(),
            approved(&clock)?.invalidate_active_sessions(),
        ] {
            require_terminal_cause(
                rejected,
                RequestPolicyRejectionCause::ActiveSessionsInvalidated,
            )?;
        }
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Exact strings cover every policy-bearing Debug surface.
    fn terminal_causes_and_all_debug_surfaces_are_data_free() -> Result<(), &'static str> {
        let clock = TestClock::new(1);
        let seed_debug = format!(
            "{:?}",
            seed(
                clock.clone(),
                VALID_MARKER,
                VALID_SESSION,
                ExpectedHelperRole::Approval,
                VALID_DEADLINE,
            )?
        );
        let observation_debug = format!(
            "{:?}",
            observation(VALID_MARKER, VALID_SESSION, ExpectedHelperRole::Approval,)?
        );
        let decision_debug = format!(
            "{:?}",
            UiDecisionObservation::approve_for_test(observation(
                VALID_MARKER,
                VALID_SESSION,
                ExpectedHelperRole::Approval,
            )?)
        );
        let binding_debug = format!("{:?}", admitted(&clock)?.binding);
        if seed_debug != "RequestPolicySeed([REDACTED])"
            || observation_debug != "RequestPolicyObservation([REDACTED])"
            || decision_debug != "UiDecisionObservation([REDACTED])"
            || binding_debug != "RequestBinding([REDACTED])"
            || format!("{:?}", admitted(&clock)?) != "AdmittedRequestPolicy([REDACTED])"
            || format!("{:?}", starting(&clock)?) != "UiStartingRequestPolicy([REDACTED])"
            || format!("{:?}", authenticated(&clock)?) != "UiAuthenticatedRequestPolicy([REDACTED])"
            || format!("{:?}", approved(&clock)?) != "ApprovedRequestPolicy([REDACTED])"
        {
            return Err("a live request Debug surface was not exactly redacted");
        }

        let causes = [
            RequestPolicyRejectionCause::ClockUnavailable,
            RequestPolicyRejectionCause::DeadlineExpired,
            RequestPolicyRejectionCause::InvalidObservation,
            RequestPolicyRejectionCause::Cancelled,
            RequestPolicyRejectionCause::SessionInvalidated,
            RequestPolicyRejectionCause::ActiveSessionsInvalidated,
            RequestPolicyRejectionCause::UserRejected,
        ];
        for cause in causes {
            let rejected = reject_binding(admitted(&clock)?.binding, cause);
            let expected = format!("RejectedRequestPolicy {{ cause: {cause:?}, .. }}");
            if format!("{rejected:?}") != expected {
                return Err("terminal rejection Debug exposed request data");
            }
        }
        Ok(())
    }
}
