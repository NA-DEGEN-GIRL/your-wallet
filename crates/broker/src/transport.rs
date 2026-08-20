//! Typed adapter between the public native-host envelope and broker policy.

use core::fmt;
use std::time::{Duration, Instant};

use serde_json::Value;
#[cfg(any(test, all(feature = "ipc-contract-test-hook", debug_assertions)))]
use wallet_model::SessionId;
use wallet_model::{ActivationNonce, Address20, BrowserContext, U256};

#[cfg(any(test, all(feature = "ipc-contract-test-hook", debug_assertions)))]
use crate::BrowserDocumentKey;
use crate::{
    Admission, BrokerError, PermissionKey, PermissionStore, ProviderMethod, ProviderRoute,
    SessionRouter,
};

/// A fully parsed version-1 extension request.
#[derive(Clone)]
pub struct TransportRequest {
    context: BrowserContext,
    method_name: String,
    params: Value,
    route: ProviderRoute,
}

impl fmt::Debug for TransportRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportRequest")
            .field("context", &"[VALIDATED BROWSER CONTEXT]")
            .field("method_name", &self.method_name)
            .field("params", &"[BOUNDED JSON REDACTED]")
            .field("route", &self.route)
            .finish()
    }
}

impl TransportRequest {
    /// Construct a request only after its browser fields were parsed into model types.
    ///
    /// # Errors
    ///
    /// Returns a stable malformed error when the context, method, parameters, or
    /// extension-asserted route do not agree.
    pub fn new(
        context: BrowserContext,
        method_name: String,
        params: Value,
        route: ProviderRoute,
    ) -> Result<Self, BrokerError> {
        context.validate().map_err(|_| BrokerError::Malformed)?;
        let method = crate::validate_public_request(&method_name, &params)?;
        if method.route() != route {
            return Err(BrokerError::Malformed);
        }
        Ok(Self {
            context,
            method_name,
            params,
            route,
        })
    }

    /// Return the exact browser context reconstructed from the wire envelope.
    #[must_use]
    pub const fn context(&self) -> &BrowserContext {
        &self.context
    }

    /// Return the validated method name.
    #[must_use]
    pub fn method_name(&self) -> &str {
        &self.method_name
    }

    /// Return the bounded method parameters.
    #[must_use]
    pub const fn params(&self) -> &Value {
        &self.params
    }

    /// Return the independently verified route.
    #[must_use]
    pub const fn route(&self) -> ProviderRoute {
        self.route
    }
}

/// Exact cancellation binding supplied by the extension.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TransportCancellation {
    /// Extension/native session identifier.
    pub session_id: [u8; 32],
    /// Monotonic transport sequence of the cancellation itself.
    pub sequence: u64,
    /// Activation lifetime that owns the request.
    pub activation_nonce: ActivationNonce,
    /// End-to-end request identifier.
    pub request_id: [u8; 16],
    /// Original request transport sequence.
    pub request_sequence: u64,
}

/// Correlation-only completion for a request deliberately unavailable at the
/// debug native-host boundary.
///
/// No JSON parameters, message bytes, account, address, origin, or arbitrary
/// method string can be represented by this type.
#[derive(Clone, Copy)]
#[cfg(any(test, all(feature = "ipc-contract-test-hook", debug_assertions)))]
pub(crate) struct TransportUnavailable {
    session_id: [u8; 32],
    sequence: u64,
    activation_nonce: ActivationNonce,
    request_id: [u8; 16],
    method: ProviderMethod,
}

#[cfg(any(test, all(feature = "ipc-contract-test-hook", debug_assertions)))]
impl fmt::Debug for TransportUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportUnavailable")
            .field("session_id", &"[REDACTED]")
            .field("sequence", &"[REDACTED]")
            .field("activation_nonce", &"[REDACTED]")
            .field("request_id", &"[REDACTED]")
            .field("method", &self.method)
            .finish()
    }
}

#[cfg(any(test, all(feature = "ipc-contract-test-hook", debug_assertions)))]
impl TransportUnavailable {
    pub(crate) const fn new(
        session_id: [u8; 32],
        sequence: u64,
        activation_nonce: ActivationNonce,
        request_id: [u8; 16],
        method: ProviderMethod,
    ) -> Self {
        Self {
            session_id,
            sequence,
            activation_nonce,
            request_id,
            method,
        }
    }

    pub(crate) const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }
}

/// Result of consuming one exactly bound transport cancellation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportCancellationOutcome {
    /// A still-pending request was cancelled.
    Cancelled,
    /// The exact request had already completed; the late cancellation was
    /// consumed idempotently and did not affect another request.
    AlreadyCompleted,
}

/// Broker-owned output of the deliberately tiny secretless local subset.
#[cfg(any(test, all(feature = "ipc-contract-test-hook", debug_assertions)))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SecretlessLocalOutcome {
    /// The Broker-selected chain identifier.
    ChainId(U256),
}

impl fmt::Debug for TransportCancellation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportCancellation")
            .field("session_id", &"[REDACTED]")
            .field("sequence", &"[REDACTED]")
            .field("activation_nonce", &"[REDACTED]")
            .field("request_id", &"[REDACTED]")
            .field("request_sequence", &"[REDACTED]")
            .finish()
    }
}

/// Downstream class selected only after method, context, and permission checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerTarget {
    /// Operation must be handled inside the broker or by a fresh permission UI.
    LocalPermission,
    /// Read-only RPC adapter.
    ReadRpc,
    /// Private approval/signing pipeline.
    SigningPipeline,
}

/// Owned components of one admitted request.
///
/// The tuple is returned only by consuming [`AuthorizedDispatch`]. Keeping the
/// browser context and bounded JSON together prevents a downstream adapter from
/// fetching or reparsing mutable public-boundary state after admission.
pub type AuthorizedDispatchParts = (
    BrowserContext,
    Value,
    ProviderMethod,
    BrokerTarget,
    [u8; 16],
    u64,
);

/// Non-forgeable admission result consumed by a downstream adapter.
pub struct AuthorizedDispatch {
    context: BrowserContext,
    params: Value,
    method: ProviderMethod,
    target: BrokerTarget,
    request_id: [u8; 16],
    request_sequence: u64,
}

impl AuthorizedDispatch {
    /// Return the complete browser-owned context admitted by the broker.
    #[must_use]
    pub const fn context(&self) -> &BrowserContext {
        &self.context
    }

    /// Return the exact bounded parameters admitted by the broker.
    #[must_use]
    pub const fn params(&self) -> &Value {
        &self.params
    }

    /// Return the exact validated provider method.
    #[must_use]
    pub const fn method(&self) -> ProviderMethod {
        self.method
    }

    /// Return the only downstream class allowed for the method.
    #[must_use]
    pub const fn target(&self) -> BrokerTarget {
        self.target
    }

    /// Return the request identifier bound to this admission.
    #[must_use]
    pub const fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }

    /// Return the original request's transport sequence.
    #[must_use]
    pub const fn request_sequence(&self) -> u64 {
        self.request_sequence
    }

    /// Consume this admission into the exact values checked by the broker.
    ///
    /// No downstream component needs to fetch or reparse extension-owned state.
    #[must_use]
    pub fn into_parts(self) -> AuthorizedDispatchParts {
        (
            self.context,
            self.params,
            self.method,
            self.target,
            self.request_id,
            self.request_sequence,
        )
    }
}

impl fmt::Debug for AuthorizedDispatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedDispatch")
            .field("context", &"[VALIDATED BROWSER CONTEXT]")
            .field("params", &"[BOUNDED JSON REDACTED]")
            .field("method", &self.method)
            .field("target", &self.target)
            .field("request_id", &"[REDACTED]")
            .field("request_sequence", &"[REDACTED]")
            .finish()
    }
}

/// Stateful broker-side transport admission gate.
pub struct TransportBroker {
    router: SessionRouter,
    permissions: PermissionStore,
    active_account: Address20,
    active_chain: U256,
    session_id: Option<[u8; 32]>,
    next_wire_sequence: u64,
}

impl fmt::Debug for TransportBroker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportBroker")
            .field("router", &self.router)
            .field("permissions", &self.permissions)
            .field("active_account", &"[REDACTED]")
            .field("active_chain", &"[REDACTED]")
            .field("session_id", &"[REDACTED]")
            .field("next_wire_sequence", &"[REDACTED]")
            .finish()
    }
}

impl TransportBroker {
    /// Create a dispatcher for one active account and chain.
    #[must_use]
    pub fn new(
        permissions: PermissionStore,
        active_account: Address20,
        active_chain: U256,
    ) -> Self {
        Self {
            router: SessionRouter::default(),
            permissions,
            active_account,
            active_chain,
            session_id: None,
            next_wire_sequence: 1,
        }
    }

    /// Begin a new native connection, invalidating every pending old-session request.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Malformed`] for the reserved all-zero identifier.
    pub fn begin_session(&mut self, session_id: [u8; 32]) -> Result<(), BrokerError> {
        self.router.begin_session(session_id)?;
        self.session_id = Some(session_id);
        self.next_wire_sequence = 1;
        Ok(())
    }

    /// Admit one request after the single request/cancellation sequence and
    /// origin/account/chain permission have been verified.
    ///
    /// # Errors
    ///
    /// Returns a stable broker boundary error and consumes the wire sequence on
    /// every structurally valid attempt, preventing replay after policy denial.
    pub fn admit(
        &mut self,
        request: &TransportRequest,
        now: Instant,
        now_unix_ms: u64,
    ) -> Result<AuthorizedDispatch, BrokerError> {
        self.consume_wire_sequence(
            *request.context.session_id.as_bytes(),
            request.context.sequence,
        )?;

        let remaining_ms = request
            .context
            .deadline_ms
            .checked_sub(now_unix_ms)
            .ok_or(BrokerError::DeadlineExceeded)?;
        if remaining_ms == 0 || remaining_ms > 120_000 {
            return Err(BrokerError::DeadlineExceeded);
        }
        let method = crate::validate_public_request(request.method_name(), request.params())?;
        if method.route() != request.route {
            return Err(BrokerError::Malformed);
        }
        self.require_transport_permission(request, method)?;
        self.router.admit_presequenced(
            Admission {
                context: &request.context,
                method_name: request.method_name(),
                params: request.params(),
                relative_deadline: Duration::from_millis(remaining_ms),
            },
            now,
        )?;
        let target = match method.route() {
            ProviderRoute::Permission => BrokerTarget::LocalPermission,
            ProviderRoute::Read => BrokerTarget::ReadRpc,
            ProviderRoute::Signing => BrokerTarget::SigningPipeline,
        };
        Ok(AuthorizedDispatch {
            context: request.context.clone(),
            params: request.params.clone(),
            method,
            target,
            request_id: *request.context.request_id.as_bytes(),
            request_sequence: request.context.sequence,
        })
    }

    /// Apply an exactly bound cancellation. A mismatch does not cancel another request.
    ///
    /// # Errors
    ///
    /// Returns replay/context errors for the wrong session, wire sequence, or
    /// request lifetime.
    pub fn cancel(
        &mut self,
        cancellation: TransportCancellation,
    ) -> Result<TransportCancellationOutcome, BrokerError> {
        self.consume_wire_sequence(cancellation.session_id, cancellation.sequence)?;
        self.router
            .cancel_bound(
                cancellation.request_id,
                cancellation.request_sequence,
                cancellation.activation_nonce,
            )
            .ok_or(BrokerError::ContextChanged)
    }

    /// Consume and remember one correlation-only debug-unavailable request.
    ///
    /// This keeps every extension request and cancellation on the same strict
    /// sequence even when no operation is admitted and no raw parameters cross
    /// the subprocess contract hook.
    ///
    /// # Errors
    ///
    /// Returns a replay, context, capacity, or malformed error for a mismatched
    /// session/sequence, reused request identifier, or `eth_chainId`, which must
    /// use the typed local execution path instead.
    #[cfg(any(test, all(feature = "ipc-contract-test-hook", debug_assertions)))]
    pub(crate) fn complete_unavailable(
        &mut self,
        unavailable: TransportUnavailable,
    ) -> Result<(), BrokerError> {
        if unavailable.method == ProviderMethod::ChainId {
            return Err(BrokerError::Malformed);
        }
        self.consume_wire_sequence(unavailable.session_id, unavailable.sequence)?;
        self.router.remember_unavailable(
            SessionId::new(unavailable.session_id),
            unavailable.activation_nonce,
            unavailable.request_id,
            unavailable.sequence,
        )
    }

    /// Execute the deliberately tiny, secret-free local provider subset.
    ///
    /// The response is owned by the Broker so an external executor cannot turn
    /// a locally admitted permission route into account disclosure. This first
    /// bridge slice implements only `eth_chainId`; it performs no network,
    /// signing, permission mutation, or Key Agent operation. Every admitted
    /// request is completed before this method returns, including unsupported
    /// local methods.
    ///
    /// # Errors
    ///
    /// Returns the normal admission/completion error, or
    /// [`BrokerError::UnsupportedMethod`] for every method except
    /// `eth_chainId`.
    #[cfg(any(test, all(feature = "ipc-contract-test-hook", debug_assertions)))]
    pub(crate) fn execute_secretless_local(
        &mut self,
        request: &TransportRequest,
        admitted_at: Instant,
        completed_at: Instant,
        now_unix_ms: u64,
    ) -> Result<SecretlessLocalOutcome, BrokerError> {
        let admission = self.admit(request, admitted_at, now_unix_ms)?;
        let document = BrowserDocumentKey::from_context(admission.context())?;
        let request_id = *admission.request_id();
        let admitted_method = admission.method();
        let admitted_target = admission.target();
        let result = if admitted_target == BrokerTarget::LocalPermission
            && admitted_method == ProviderMethod::ChainId
        {
            Ok(SecretlessLocalOutcome::ChainId(self.active_chain))
        } else {
            Err(BrokerError::UnsupportedMethod)
        };

        let completed_method = self.router.complete(request_id, &document, completed_at)?;
        if completed_method != admitted_method {
            return Err(BrokerError::ContextChanged);
        }
        result
    }

    /// Return the number of requests still pending in this transport session.
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.router.pending_len()
    }

    /// Grant the exact active account/chain to a validated document origin.
    ///
    /// This is intended to be called only after a separately verified permission
    /// approval has completed.
    ///
    /// # Errors
    ///
    /// Returns a stable context or capacity failure.
    pub fn grant_active_permission(
        &mut self,
        context: &BrowserContext,
    ) -> Result<bool, BrokerError> {
        let key = PermissionKey::from_context(context, self.active_account, self.active_chain)?;
        self.permissions.grant(key)
    }

    fn consume_wire_sequence(
        &mut self,
        session_id: [u8; 32],
        sequence: u64,
    ) -> Result<(), BrokerError> {
        if self.session_id != Some(session_id) || sequence != self.next_wire_sequence {
            return Err(BrokerError::Replay);
        }
        self.next_wire_sequence = self
            .next_wire_sequence
            .checked_add(1)
            .ok_or(BrokerError::Replay)?;
        Ok(())
    }

    fn require_transport_permission(
        &self,
        request: &TransportRequest,
        method: ProviderMethod,
    ) -> Result<(), BrokerError> {
        if method.route() == ProviderRoute::Permission {
            return Ok(());
        }
        let key =
            PermissionKey::from_context(request.context(), self.active_account, self.active_chain)?;
        if !self.permissions.contains(&key) {
            return Err(BrokerError::Unauthorized);
        }
        if method.route() == ProviderRoute::Signing {
            let claimed_account = signing_account(method, request.params())?;
            if claimed_account != self.active_account {
                return Err(BrokerError::Unauthorized);
            }
        }
        Ok(())
    }
}

fn signing_account(method: ProviderMethod, params: &Value) -> Result<Address20, BrokerError> {
    let values = params.as_array().ok_or(BrokerError::Malformed)?;
    let value = match method {
        ProviderMethod::SendTransaction => values
            .first()
            .and_then(Value::as_object)
            .and_then(|transaction| transaction.get("from")),
        ProviderMethod::PersonalSign => values.get(1),
        ProviderMethod::SignTypedDataV4 => values.first(),
        _ => return Err(BrokerError::Malformed),
    }
    .and_then(Value::as_str)
    .ok_or(BrokerError::Malformed)?;
    Address20::from_fixed_hex(value).map_err(|_| BrokerError::Malformed)
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use serde_json::json;
    use wallet_model::{
        ActivationNonce, Address20, BrowserContext, BrowserFamily, BrowserOrigin,
        BrowserProvenance, ChannelNonce, DocumentId, DocumentLifecycle, ExtensionId,
        ProfileInstallId, RequestId, SessionId, U256,
    };

    use super::{
        BrokerTarget, SecretlessLocalOutcome, TransportBroker, TransportCancellation,
        TransportCancellationOutcome, TransportRequest, TransportUnavailable,
    };
    use crate::{BrokerError, PermissionStore, ProviderMethod, ProviderRoute};

    fn context(sequence: u64, request: u8) -> Result<BrowserContext, Box<dyn std::error::Error>> {
        Ok(BrowserContext {
            browser_family: BrowserFamily::Chrome,
            profile_install_id: ProfileInstallId::new([1; 32]),
            extension_id: ExtensionId::new("abcdefghijklmnopabcdefghijklmnop")?,
            tab_id: 17,
            frame_id: 0,
            document_id: DocumentId::new("document-17")?,
            activation_nonce: ActivationNonce::new([3; 32]),
            top_origin: BrowserOrigin::new("https://dapp.example")?,
            frame_origin: BrowserOrigin::new("https://dapp.example")?,
            document_lifecycle: DocumentLifecycle::Active,
            channel_nonce: ChannelNonce::new([4; 32]),
            provenance: BrowserProvenance::BrowserReportedUnverified,
            session_id: SessionId::new([2; 32]),
            sequence,
            deadline_ms: 1_700_000_120_000,
            request_id: RequestId::new([request; 16]),
        })
    }

    #[test]
    fn transport_debug_redacts_context_params_accounts_and_identifiers()
    -> Result<(), Box<dyn std::error::Error>> {
        let request_context = context(1, 0x5a)?;
        let request = TransportRequest::new(
            request_context.clone(),
            "personal_sign".to_owned(),
            json!(["0xdeadbeef", "0x1111111111111111111111111111111111111111"]),
            ProviderRoute::Signing,
        )?;
        let cancellation = TransportCancellation {
            session_id: [0xa5; 32],
            sequence: 2,
            activation_nonce: request_context.activation_nonce,
            request_id: [0x5a; 16],
            request_sequence: 1,
        };
        let mut broker = TransportBroker::new(
            PermissionStore::default(),
            Address20::new([0x11; 20]),
            U256::from_u64(1),
        );
        assert!(broker.grant_active_permission(&request_context)?);

        let rendered = format!("{request:?} {cancellation:?} {broker:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("dapp.example"));
        assert!(!rendered.contains("deadbeef"));
        assert!(!rendered.contains("1111111111111111111111111111111111111111"));
        assert!(!rendered.contains("165, 165, 165"));
        assert!(!rendered.contains("90, 90, 90"));
        Ok(())
    }

    #[test]
    fn read_and_signing_routes_require_exact_origin_account_chain_grant()
    -> Result<(), Box<dyn std::error::Error>> {
        let account = Address20::new([0x11; 20]);
        let mut broker =
            TransportBroker::new(PermissionStore::default(), account, U256::from_u64(1));
        broker.begin_session([2; 32])?;
        let read_context = context(1, 1)?;
        let read = TransportRequest::new(
            read_context.clone(),
            "eth_blockNumber".to_owned(),
            json!([]),
            ProviderRoute::Read,
        )?;
        assert!(matches!(
            broker.admit(&read, Instant::now(), 1_700_000_000_000),
            Err(BrokerError::Unauthorized)
        ));

        let mut grant_context = read_context;
        grant_context.sequence = 2;
        grant_context.request_id = RequestId::new([2; 16]);
        assert!(broker.grant_active_permission(&grant_context)?);
        let read = TransportRequest::new(
            grant_context,
            "eth_blockNumber".to_owned(),
            json!([]),
            ProviderRoute::Read,
        )?;
        assert_eq!(
            broker
                .admit(&read, Instant::now(), 1_700_000_000_000)?
                .target(),
            BrokerTarget::ReadRpc
        );
        Ok(())
    }

    #[test]
    fn cancellation_uses_the_shared_wire_sequence_and_exact_activation()
    -> Result<(), Box<dyn std::error::Error>> {
        let account = Address20::new([0x11; 20]);
        let mut broker =
            TransportBroker::new(PermissionStore::default(), account, U256::from_u64(1));
        broker.begin_session([2; 32])?;
        let request_context = context(1, 7)?;
        let request = TransportRequest::new(
            request_context,
            "eth_chainId".to_owned(),
            json!([]),
            ProviderRoute::Permission,
        )?;
        broker.admit(&request, Instant::now(), 1_700_000_000_000)?;
        assert_eq!(
            broker.cancel(TransportCancellation {
                session_id: [2; 32],
                sequence: 2,
                activation_nonce: ActivationNonce::new([9; 32]),
                request_id: [7; 16],
                request_sequence: 1,
            }),
            Err(BrokerError::ContextChanged)
        );
        Ok(())
    }

    #[test]
    fn secretless_local_chain_id_completes_before_return_and_late_cancel_is_idempotent()
    -> Result<(), Box<dyn std::error::Error>> {
        let account = Address20::new([0x11; 20]);
        let mut broker = TransportBroker::new(
            PermissionStore::default(),
            account,
            U256::from_u64(11_155_111),
        );
        broker.begin_session([2; 32])?;
        let request_context = context(1, 7)?;
        let request = TransportRequest::new(
            request_context.clone(),
            "eth_chainId".to_owned(),
            json!([]),
            ProviderRoute::Permission,
        )?;
        let now = Instant::now();
        assert_eq!(
            broker.execute_secretless_local(&request, now, now, 1_700_000_000_000,)?,
            SecretlessLocalOutcome::ChainId(U256::from_u64(11_155_111))
        );
        assert_eq!(broker.pending_len(), 0);
        assert_eq!(
            broker.cancel(TransportCancellation {
                session_id: [2; 32],
                sequence: 2,
                activation_nonce: request_context.activation_nonce,
                request_id: [7; 16],
                request_sequence: 1,
            })?,
            TransportCancellationOutcome::AlreadyCompleted
        );
        assert_eq!(broker.pending_len(), 0);
        Ok(())
    }

    #[test]
    fn unavailable_completion_consumes_sequence_and_binds_late_cancel() -> Result<(), BrokerError> {
        let mut broker = TransportBroker::new(
            PermissionStore::default(),
            Address20::new([0x11; 20]),
            U256::from_u64(11_155_111),
        );
        broker.begin_session([2; 32])?;
        broker.complete_unavailable(TransportUnavailable::new(
            [2; 32],
            1,
            ActivationNonce::new([3; 32]),
            [7; 16],
            ProviderMethod::PersonalSign,
        ))?;
        assert_eq!(broker.pending_len(), 0);
        assert_eq!(
            broker.cancel(TransportCancellation {
                session_id: [2; 32],
                sequence: 2,
                activation_nonce: ActivationNonce::new([3; 32]),
                request_id: [7; 16],
                request_sequence: 1,
            })?,
            TransportCancellationOutcome::AlreadyCompleted
        );
        assert_eq!(
            broker.complete_unavailable(TransportUnavailable::new(
                [2; 32],
                3,
                ActivationNonce::new([3; 32]),
                [7; 16],
                ProviderMethod::PersonalSign,
            )),
            Err(BrokerError::Replay)
        );
        Ok(())
    }

    #[test]
    fn unavailable_completion_cannot_replace_typed_chain_id_execution()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut broker = TransportBroker::new(
            PermissionStore::default(),
            Address20::new([0x11; 20]),
            U256::from_u64(11_155_111),
        );
        broker.begin_session([2; 32])?;
        assert_eq!(
            broker.complete_unavailable(TransportUnavailable::new(
                [2; 32],
                1,
                ActivationNonce::new([3; 32]),
                [7; 16],
                ProviderMethod::ChainId,
            )),
            Err(BrokerError::Malformed)
        );
        let request = TransportRequest::new(
            context(1, 7)?,
            "eth_chainId".to_owned(),
            json!([]),
            ProviderRoute::Permission,
        )?;
        let now = Instant::now();
        assert_eq!(
            broker.execute_secretless_local(&request, now, now, 1_700_000_000_000)?,
            SecretlessLocalOutcome::ChainId(U256::from_u64(11_155_111))
        );
        Ok(())
    }

    #[test]
    fn secretless_local_rejects_account_queries_without_leaking_pending_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut broker = TransportBroker::new(
            PermissionStore::default(),
            Address20::new([0x11; 20]),
            U256::from_u64(11_155_111),
        );
        broker.begin_session([2; 32])?;
        let request = TransportRequest::new(
            context(1, 8)?,
            "eth_accounts".to_owned(),
            json!([]),
            ProviderRoute::Permission,
        )?;
        let now = Instant::now();
        assert_eq!(
            broker.execute_secretless_local(&request, now, now, 1_700_000_000_000),
            Err(crate::BrokerError::UnsupportedMethod)
        );
        assert_eq!(broker.pending_len(), 0);
        Ok(())
    }

    #[test]
    fn extension_route_is_recomputed() -> Result<(), Box<dyn std::error::Error>> {
        assert!(matches!(
            TransportRequest::new(
                context(1, 1)?,
                "eth_sendTransaction".to_owned(),
                json!([{
                    "from": "0x1111111111111111111111111111111111111111",
                    "to": "0x2222222222222222222222222222222222222222"
                }]),
                ProviderRoute::Read,
            ),
            Err(BrokerError::Malformed)
        ));
        Ok(())
    }

    #[test]
    fn admission_owns_exact_context_params_and_cannot_be_cancel_mixed()
    -> Result<(), Box<dyn std::error::Error>> {
        let account = Address20::new([0x11; 20]);
        let mut broker =
            TransportBroker::new(PermissionStore::default(), account, U256::from_u64(1));
        broker.begin_session([2; 32])?;
        let admitted_context = context(1, 7)?;
        assert!(broker.grant_active_permission(&admitted_context)?);
        let mut request = TransportRequest::new(
            admitted_context,
            "personal_sign".to_owned(),
            json!(["0x00", "0x1111111111111111111111111111111111111111"]),
            ProviderRoute::Signing,
        )?;
        let dispatch = broker.admit(&request, Instant::now(), 1_700_000_000_000)?;

        // Flip public-boundary values after admission. The capability owns the
        // exact values already checked, rather than retaining a mutable source.
        request.params[0] = json!("0x01");
        request.context.activation_nonce = ActivationNonce::new([2; 32]);
        request.context.request_id = RequestId::new([8; 16]);
        assert_eq!(
            broker.cancel(TransportCancellation {
                session_id: [2; 32],
                sequence: 2,
                activation_nonce: request.context.activation_nonce,
                request_id: *request.context.request_id.as_bytes(),
                request_sequence: request.context.sequence,
            }),
            Err(BrokerError::ContextChanged)
        );

        assert_eq!(
            dispatch.context().activation_nonce,
            ActivationNonce::new([3; 32])
        );
        assert_eq!(dispatch.params()[0], json!("0x00"));
        assert_eq!(dispatch.method(), crate::ProviderMethod::PersonalSign);
        assert_eq!(dispatch.target(), BrokerTarget::SigningPipeline);
        assert_eq!(dispatch.request_id(), &[7; 16]);
        assert_eq!(dispatch.request_sequence(), 1);
        let debug = format!("{dispatch:?}");
        assert!(!debug.contains("0x00"));
        assert!(!debug.contains("dapp.example"));

        let (owned_context, owned_params, method, target, request_id, sequence) =
            dispatch.into_parts();
        assert_eq!(
            owned_context.activation_nonce,
            ActivationNonce::new([3; 32])
        );
        assert_eq!(owned_params[0], json!("0x00"));
        assert_eq!(method, crate::ProviderMethod::PersonalSign);
        assert_eq!(target, BrokerTarget::SigningPipeline);
        assert_eq!(request_id, [7; 16]);
        assert_eq!(sequence, 1);
        Ok(())
    }
}
