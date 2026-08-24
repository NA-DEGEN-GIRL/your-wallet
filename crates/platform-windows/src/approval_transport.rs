//! Opaque monotonic lifetime capabilities for one Approval session.

use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use approval_wire::{ApprovalRequest, MAX_EXPIRY_MILLISECONDS};
use thiserror::Error;

const APPROVAL_BOOTSTRAP_GRACE: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct SharedApprovalSessionWindow {
    expires_at: Instant,
}

/// Failure while issuing or consuming an Approval session lifetime capability.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ApprovalSessionWindowError {
    /// The requested lifetime was zero or exceeded the wire-protocol maximum.
    #[error("approval session lifetime is outside the allowed range")]
    InvalidLifetime,
    /// The monotonic deadline could not be represented.
    #[error("approval session deadline overflowed")]
    DeadlineOverflow,
    /// The original monotonic session deadline elapsed.
    #[error("approval session deadline elapsed")]
    Expired,
    /// The authorization and transport halves came from different issuances.
    #[error("approval session lifetime halves do not match")]
    WindowMismatch,
    /// The bound request carried an invalid relative lifetime.
    #[error("approval request lifetime is outside the allowed range")]
    InvalidRequestLifetime,
}

/// A freshly issued, unsplit Approval session lifetime.
///
/// The capability intentionally implements neither [`Clone`] nor [`Copy`].
/// Splitting consumes it and produces the only authorization and transport
/// halves for this issuance.
#[must_use = "the Approval session window must be split and retained"]
pub struct IssuedApprovalSessionWindow {
    shared: Arc<SharedApprovalSessionWindow>,
}

impl fmt::Debug for IssuedApprovalSessionWindow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedApprovalSessionWindow")
            .field("expires_at", &"[REDACTED]")
            .finish()
    }
}

impl IssuedApprovalSessionWindow {
    /// Issues one session window from a bounded relative lifetime.
    ///
    /// This is the only public mint. It samples the monotonic clock internally;
    /// callers cannot supply or replace the resulting deadline.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalSessionWindowError::InvalidLifetime`] for a zero or
    /// out-of-range lifetime, and
    /// [`ApprovalSessionWindowError::DeadlineOverflow`] if the deadline cannot
    /// be represented.
    pub fn issue(ttl_milliseconds: u64) -> Result<Self, ApprovalSessionWindowError> {
        if !(1..=u64::from(MAX_EXPIRY_MILLISECONDS)).contains(&ttl_milliseconds) {
            return Err(ApprovalSessionWindowError::InvalidLifetime);
        }

        let issued_at = Instant::now();
        let expires_at = checked_deadline(issued_at, Duration::from_millis(ttl_milliseconds))?;
        Ok(Self {
            shared: Arc::new(SharedApprovalSessionWindow { expires_at }),
        })
    }

    /// Consumes this issuance into its exact authorization and transport halves.
    pub fn into_parts(self) -> (ApprovalAuthorizationWindow, ApprovalTransportWindow) {
        let transport_shared = Arc::clone(&self.shared);
        (
            ApprovalAuthorizationWindow {
                shared: self.shared,
            },
            ApprovalTransportWindow {
                shared: transport_shared,
            },
        )
    }
}

/// The authorization-side half of one monotonic Approval session lifetime.
///
/// This move-only capability remains with the authorization state machine. It
/// exposes only fail-closed time checks, never the raw monotonic deadline.
#[must_use = "the authorization window must remain with its Approval session"]
pub struct ApprovalAuthorizationWindow {
    shared: Arc<SharedApprovalSessionWindow>,
}

impl fmt::Debug for ApprovalAuthorizationWindow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalAuthorizationWindow")
            .field("expires_at", &"[REDACTED]")
            .finish()
    }
}

impl ApprovalAuthorizationWindow {
    /// Returns the remaining whole-millisecond lifetime for a canonical wire
    /// request, bounded by the Approval protocol maximum.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalSessionWindowError::Expired`] once less than one whole
    /// millisecond remains. An invariant violation fails closed as
    /// [`ApprovalSessionWindowError::InvalidLifetime`].
    pub fn remaining_milliseconds(&self) -> Result<u32, ApprovalSessionWindowError> {
        let remaining = self
            .shared
            .expires_at
            .saturating_duration_since(Instant::now());
        let milliseconds = u32::try_from(remaining.as_millis())
            .map_err(|_| ApprovalSessionWindowError::InvalidLifetime)?;
        if milliseconds == 0 || milliseconds > MAX_EXPIRY_MILLISECONDS {
            Err(if milliseconds == 0 {
                ApprovalSessionWindowError::Expired
            } else {
                ApprovalSessionWindowError::InvalidLifetime
            })
        } else {
            Ok(milliseconds)
        }
    }

    /// Requires the original monotonic session deadline to remain live.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalSessionWindowError::Expired`] at or after the original
    /// deadline.
    pub fn ensure_unexpired(&self) -> Result<(), ApprovalSessionWindowError> {
        ensure_deadline_unexpired(self.shared.expires_at)
    }

    /// Consumes the matching transport half and binds it once to one exact
    /// canonical Approval request.
    ///
    /// The original session deadline remains authoritative. The request's
    /// relative lifetime is validated, but is not compared with a newly sampled
    /// remaining value because millisecond rounding would create a race.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalSessionWindowError::Expired`] if the original deadline
    /// elapsed, [`ApprovalSessionWindowError::WindowMismatch`] if the halves
    /// came from different issuances, or
    /// [`ApprovalSessionWindowError::InvalidRequestLifetime`] for an invalid
    /// wire lifetime.
    pub fn bind_transport(
        &self,
        transport: ApprovalTransportWindow,
        request: ApprovalRequest,
    ) -> Result<BoundApprovalTransport, ApprovalSessionWindowError> {
        self.ensure_unexpired()?;
        if !Arc::ptr_eq(&self.shared, &transport.shared) {
            return Err(ApprovalSessionWindowError::WindowMismatch);
        }
        if !(1..=MAX_EXPIRY_MILLISECONDS).contains(&request.expires_after_milliseconds()) {
            return Err(ApprovalSessionWindowError::InvalidRequestLifetime);
        }

        Ok(BoundApprovalTransport {
            shared: transport.shared,
            request,
        })
    }
}

/// The single-use transport-side half of one monotonic Approval session.
///
/// It has no public behavior of its own. The matching authorization half must
/// consume it through [`ApprovalAuthorizationWindow::bind_transport`].
#[must_use = "the transport window must be bound once to its exact Approval request"]
pub struct ApprovalTransportWindow {
    shared: Arc<SharedApprovalSessionWindow>,
}

impl fmt::Debug for ApprovalTransportWindow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalTransportWindow")
            .field("expires_at", &"[REDACTED]")
            .finish()
    }
}

/// One exact Approval request bound to its original monotonic transport cap.
///
/// This move-only carrier exposes neither its request nor its deadline outside
/// `platform-windows`. A later crate-internal activation transition must retain
/// the carrier through terminal response verification.
#[must_use = "the bound Approval transport must reach its consuming exchange"]
pub struct BoundApprovalTransport {
    shared: Arc<SharedApprovalSessionWindow>,
    request: ApprovalRequest,
}

impl fmt::Debug for BoundApprovalTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundApprovalTransport")
            .field("request", &"[REDACTED]")
            .field("expires_at", &"[REDACTED]")
            .finish()
    }
}

impl BoundApprovalTransport {
    pub(crate) fn request(&self) -> &ApprovalRequest {
        &self.request
    }

    pub(crate) fn deadline(&self) -> Instant {
        self.shared.expires_at
    }

    pub(crate) fn bootstrap_deadline(&self) -> Result<Instant, ApprovalSessionWindowError> {
        let now = Instant::now();
        if now >= self.shared.expires_at {
            return Err(ApprovalSessionWindowError::Expired);
        }
        let grace_deadline = checked_deadline(now, APPROVAL_BOOTSTRAP_GRACE)?;
        Ok(self.shared.expires_at.min(grace_deadline))
    }
}

fn checked_deadline(
    issued_at: Instant,
    lifetime: Duration,
) -> Result<Instant, ApprovalSessionWindowError> {
    issued_at
        .checked_add(lifetime)
        .ok_or(ApprovalSessionWindowError::DeadlineOverflow)
}

fn ensure_deadline_unexpired(deadline: Instant) -> Result<(), ApprovalSessionWindowError> {
    (Instant::now() < deadline)
        .then_some(())
        .ok_or(ApprovalSessionWindowError::Expired)
}

#[cfg(test)]
pub(crate) fn bound_approval_transport_for_test()
-> Result<BoundApprovalTransport, Box<dyn std::error::Error>> {
    let (authorization, transport) = IssuedApprovalSessionWindow::issue(120_000)?.into_parts();
    Ok(authorization.bind_transport(transport, tests::request()?)?)
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, thread, time::Duration};

    use approval_wire::{
        ApprovalDisplay, ApprovalRequest, DisplayField, FieldSemantic, OperationKind, RiskLevel,
        SimulationStatus,
    };

    use super::{
        ApprovalAuthorizationWindow, ApprovalSessionWindowError, ApprovalTransportWindow,
        BoundApprovalTransport, IssuedApprovalSessionWindow, checked_deadline,
    };

    trait AmbiguousIfClone<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    impl<T: Clone> AmbiguousIfClone<u8> for T {}

    trait AmbiguousIfCopy<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfCopy<()> for T {}
    impl<T: Copy> AmbiguousIfCopy<u8> for T {}

    fn field(
        semantic: FieldSemantic,
        value: &str,
    ) -> Result<DisplayField, Box<dyn std::error::Error>> {
        Ok(DisplayField::new(
            semantic,
            value,
            semantic != FieldSemantic::SimulationEngine,
        )?)
    }

    pub(super) fn request() -> Result<ApprovalRequest, Box<dyn std::error::Error>> {
        let display = ApprovalDisplay::new(
            RiskLevel::High,
            vec![
                field(FieldSemantic::Origin, "https://example.test")?,
                field(
                    FieldSemantic::OriginProvenance,
                    "Browser-reported; not independently verified",
                )?,
                field(
                    FieldSemantic::Account,
                    "0x1111111111111111111111111111111111111111",
                )?,
                field(FieldSemantic::NetworkName, "Ethereum")?,
                field(FieldSemantic::ChainId, "1")?,
                field(
                    FieldSemantic::GenesisHash,
                    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )?,
                field(
                    FieldSemantic::RulesetRevision,
                    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                )?,
                field(
                    FieldSemantic::RpcObservationsDigest,
                    "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                )?,
                field(
                    FieldSemantic::OperationKind,
                    OperationKind::PersonalMessage.value(),
                )?,
                field(FieldSemantic::PersonalMessageBytes, "0x0102")?,
                field(
                    FieldSemantic::SimulationStatus,
                    SimulationStatus::NotPerformed.value(),
                )?,
                field(
                    FieldSemantic::OriginWarning,
                    "Browser origin is not independently attested.",
                )?,
                field(
                    FieldSemantic::PersonalMessageWarning,
                    "Personal signatures can be reused by protocols.",
                )?,
                field(
                    FieldSemantic::NoSimulationWarning,
                    "No simulation was performed.",
                )?,
            ],
        )?;
        Ok(ApprovalRequest::new(
            [7; 32],
            [9; 32],
            120_000,
            "blue comet",
            display,
        )?)
    }

    #[test]
    fn issued_halves_share_exact_deadline_and_identity() -> Result<(), ApprovalSessionWindowError> {
        let issued = IssuedApprovalSessionWindow::issue(120_000)?;
        let (authorization, transport) = issued.into_parts();

        assert_eq!(authorization.shared.expires_at, transport.shared.expires_at);
        assert!(Arc::ptr_eq(&authorization.shared, &transport.shared));
        Ok(())
    }

    #[test]
    fn exact_request_binding_preserves_original_window() -> Result<(), Box<dyn std::error::Error>> {
        let (authorization, transport) = IssuedApprovalSessionWindow::issue(120_000)?.into_parts();
        let expected = request()?;
        let bound = authorization.bind_transport(transport, expected.clone())?;

        assert!(Arc::ptr_eq(&authorization.shared, &bound.shared));
        assert_eq!(authorization.shared.expires_at, bound.deadline());
        assert_eq!(bound.request(), &expected);
        Ok(())
    }

    #[test]
    fn mixed_issuances_cannot_be_bound() -> Result<(), Box<dyn std::error::Error>> {
        let (authorization, _) = IssuedApprovalSessionWindow::issue(120_000)?.into_parts();
        let (_, transport) = IssuedApprovalSessionWindow::issue(120_000)?.into_parts();

        assert!(matches!(
            authorization.bind_transport(transport, request()?),
            Err(ApprovalSessionWindowError::WindowMismatch)
        ));
        Ok(())
    }

    #[test]
    fn expired_window_rejects_checks_and_binding() -> Result<(), Box<dyn std::error::Error>> {
        let (authorization, transport) = IssuedApprovalSessionWindow::issue(1)?.into_parts();
        thread::sleep(Duration::from_millis(10));

        assert_eq!(
            authorization.ensure_unexpired(),
            Err(ApprovalSessionWindowError::Expired)
        );
        assert_eq!(
            authorization.remaining_milliseconds(),
            Err(ApprovalSessionWindowError::Expired)
        );
        assert!(matches!(
            authorization.bind_transport(transport, request()?),
            Err(ApprovalSessionWindowError::Expired)
        ));
        Ok(())
    }

    #[test]
    fn invalid_lifetimes_and_deadline_overflow_fail_closed() {
        assert!(matches!(
            IssuedApprovalSessionWindow::issue(0),
            Err(ApprovalSessionWindowError::InvalidLifetime)
        ));
        assert!(matches!(
            IssuedApprovalSessionWindow::issue(
                u64::from(approval_wire::MAX_EXPIRY_MILLISECONDS) + 1
            ),
            Err(ApprovalSessionWindowError::InvalidLifetime)
        ));
        assert!(matches!(
            checked_deadline(std::time::Instant::now(), Duration::MAX),
            Err(ApprovalSessionWindowError::DeadlineOverflow)
        ));
    }

    #[test]
    fn bootstrap_deadline_is_capped_by_original_window() -> Result<(), Box<dyn std::error::Error>> {
        let (authorization, transport) = IssuedApprovalSessionWindow::issue(100)?.into_parts();
        let bound = authorization.bind_transport(transport, request()?)?;

        assert!(bound.bootstrap_deadline()? <= bound.deadline());
        Ok(())
    }

    #[test]
    fn bound_transport_expiry_rejects_bootstrap_before_use()
    -> Result<(), Box<dyn std::error::Error>> {
        let (authorization, transport) = IssuedApprovalSessionWindow::issue(1)?.into_parts();
        let bound = authorization.bind_transport(transport, request()?)?;
        thread::sleep(Duration::from_millis(10));

        assert_eq!(
            bound.bootstrap_deadline(),
            Err(ApprovalSessionWindowError::Expired)
        );
        Ok(())
    }

    #[test]
    fn approval_lifetime_typestates_are_move_only() {
        let _ = <IssuedApprovalSessionWindow as AmbiguousIfClone<_>>::marker;
        let _ = <IssuedApprovalSessionWindow as AmbiguousIfCopy<_>>::marker;
        let _ = <ApprovalAuthorizationWindow as AmbiguousIfClone<_>>::marker;
        let _ = <ApprovalAuthorizationWindow as AmbiguousIfCopy<_>>::marker;
        let _ = <ApprovalTransportWindow as AmbiguousIfClone<_>>::marker;
        let _ = <ApprovalTransportWindow as AmbiguousIfCopy<_>>::marker;
        let _ = <BoundApprovalTransport as AmbiguousIfClone<_>>::marker;
        let _ = <BoundApprovalTransport as AmbiguousIfCopy<_>>::marker;
    }
}
