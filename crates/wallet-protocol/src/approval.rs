use approval_wire::{ApprovalDisplay, ApprovalRequest, RiskLevel};
use core::fmt;
use platform_windows::{
    ApprovalAuthorizationWindow, ApprovalSessionWindowError, ApprovalTransportWindow,
    BoundApprovalTransport, IssuedApprovalSessionWindow,
};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use wallet_model::{
    Address20, BrowserContext, CanonicalEncode, CanonicalOperation, ChainIdentity, CodecError,
    Hash32, NonceLeaseId, SimulationProvenance, Transcript, U256,
};

use crate::{ErrorField, ProtocolError, ProtocolErrorKind, ProtocolValidity, ReleaseChannel};

const APPROVAL_DOMAIN: &str = "your-wallet/approval-binding";
const DISPLAY_DOMAIN: &str = "your-wallet/canonical-display";
const APPROVAL_VERSION: u16 = 2;
const DISPLAY_VERSION: u16 = 2;

/// Maximum lifetime of an approval challenge.
pub const APPROVAL_TTL_MAX_MS: u64 = 120_000;

/// Nonce reservation details bound to a transaction approval.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct NonceLeaseBinding {
    /// Random reservation identifier.
    pub(crate) lease_id: NonceLeaseId,
    /// Exact transaction nonce.
    pub(crate) nonce: U256,
}

impl fmt::Debug for NonceLeaseBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NonceLeaseBinding")
            .field("lease_id", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .finish()
    }
}

impl NonceLeaseBinding {
    /// Returns the durable reservation identifier after authorization.
    #[must_use]
    pub const fn lease_id(self) -> NonceLeaseId {
        self.lease_id
    }

    /// Returns the exact reserved transaction nonce after authorization.
    #[must_use]
    pub const fn nonce(self) -> U256 {
        self.nonce
    }
}

impl CanonicalEncode for NonceLeaseBinding {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        self.lease_id.encode(transcript)?;
        self.nonce.encode(transcript)
    }
}

/// Exact operation, provenance, display, and policy state approved by the user.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ApprovalBinding {
    /// Validated operation.
    pub(crate) operation: CanonicalOperation,
    /// Signing account.
    pub(crate) account: Address20,
    /// Full chain fingerprint and registry revision.
    pub(crate) chain: ChainIdentity,
    /// Signed chain-rule-set digest.
    pub(crate) ruleset_revision: Hash32,
    /// Durable nonce lease for transaction operations.
    pub(crate) nonce_lease: Option<NonceLeaseBinding>,
    /// Browser origin/document/session/request provenance.
    pub(crate) browser: BrowserContext,
    /// Exact one-shot UI model.
    pub(crate) display: ApprovalDisplay,
    /// Simulation result provenance.
    pub(crate) simulation: SimulationProvenance,
    /// Digest of canonical RPC observations used to fill request fields.
    pub(crate) rpc_observations_digest: Hash32,
    /// Protocol registry/rule coverage status displayed to the user.
    pub(crate) protocol_validity: ProtocolValidity,
}

impl fmt::Debug for ApprovalBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalBinding")
            .field("operation", &"[REDACTED]")
            .field("account", &"[REDACTED]")
            .field("chain", &"[REDACTED]")
            .field("ruleset_revision", &"[REDACTED]")
            .field("nonce_lease", &"[REDACTED]")
            .field("browser", &"[REDACTED]")
            .field("display", &"[REDACTED]")
            .field("simulation", &self.simulation)
            .field("rpc_observations_digest", &"[REDACTED]")
            .field("protocol_validity", &self.protocol_validity)
            .finish()
    }
}

impl ApprovalBinding {
    /// Checks cross-field invariants before a challenge can be issued.
    pub fn validate(&self, channel: ReleaseChannel) -> Result<(), ProtocolError> {
        self.browser.validate().map_err(|_| {
            ProtocolError::at(
                ProtocolErrorKind::InvalidBrowserContext,
                ErrorField::BrowserContext,
            )
        })?;
        if let Some(operation_chain_id) = self.operation.chain_id()
            && operation_chain_id != self.chain.chain_id()
        {
            return Err(ProtocolError::at(
                ProtocolErrorKind::ChainMismatch,
                ErrorField::ChainId,
            ));
        }

        let transaction_nonce = operation_nonce(&self.operation);
        match (transaction_nonce, self.nonce_lease) {
            (Some(expected_nonce), Some(lease)) if expected_nonce == lease.nonce => {}
            (Some(_), Some(_)) => {
                return Err(ProtocolError::at(
                    ProtocolErrorKind::InvalidNumericInvariant,
                    ErrorField::Nonce,
                ));
            }
            (Some(_), None) => {
                return Err(ProtocolError::at(
                    ProtocolErrorKind::MissingField,
                    ErrorField::Nonce,
                ));
            }
            (None, Some(_)) => {
                return Err(ProtocolError::at(
                    ProtocolErrorKind::ConflictingFields,
                    ErrorField::Nonce,
                ));
            }
            (None, None) => {}
        }

        if self.protocol_validity.disposition(channel) == crate::ProtocolDisposition::Deny {
            return Err(ProtocolError::new(ProtocolErrorKind::ProtocolInvalid));
        }
        if self.protocol_validity.disposition(channel) == crate::ProtocolDisposition::WarnAndHold
            && self.display.risk() != RiskLevel::High
        {
            return Err(ProtocolError::at(
                ProtocolErrorKind::InvalidBrowserContext,
                ErrorField::Approval,
            ));
        }
        Ok(())
    }

    fn encode_for_approval(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        self.operation.encode(transcript)?;
        self.account.encode(transcript)?;
        self.chain.encode(transcript)?;
        self.ruleset_revision.encode(transcript)?;
        transcript.push_optional(self.nonce_lease.as_ref())?;
        self.browser.encode(transcript)?;
        display_digest(&self.display)?.encode(transcript)?;
        self.simulation.encode(transcript)?;
        self.rpc_observations_digest.encode(transcript)?;
        self.protocol_validity.encode(transcript)
    }
}

/// Computes the versioned SHA-256 digest of exactly what the trusted UI renders.
pub fn display_digest(display: &ApprovalDisplay) -> Result<Hash32, CodecError> {
    let mut transcript = Transcript::start_domain(DISPLAY_DOMAIN, DISPLAY_VERSION)?;
    transcript.push_bytes(&display.canonical_bytes())?;
    Ok(sha256(transcript.as_bytes()))
}

/// Computes the versioned, domain-separated approval binding digest.
pub(crate) fn approval_digest(binding: &ApprovalBinding) -> Result<Hash32, CodecError> {
    let mut transcript = Transcript::start_domain(APPROVAL_DOMAIN, APPROVAL_VERSION)?;
    binding.encode_for_approval(&mut transcript)?;
    Ok(sha256(transcript.as_bytes()))
}

fn sha256(bytes: &[u8]) -> Hash32 {
    let digest = Sha256::digest(bytes);
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    Hash32::new(output)
}

fn operation_nonce(operation: &CanonicalOperation) -> Option<U256> {
    match operation {
        CanonicalOperation::LegacyEip155(transaction) => Some(transaction.nonce),
        CanonicalOperation::AccessListEip2930(transaction) => Some(transaction.nonce),
        CanonicalOperation::DynamicFeeEip1559(transaction) => Some(transaction.nonce),
        CanonicalOperation::PersonalMessage(_) | CanonicalOperation::TypedDataV4(_) => None,
    }
}

/// Random one-shot nonce generated by the key agent.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ApprovalNonce([u8; 32]);

impl fmt::Debug for ApprovalNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApprovalNonce([REDACTED])")
    }
}

impl ApprovalNonce {
    /// Wraps CSPRNG output generated inside the authorization TCB.
    #[must_use]
    pub(crate) const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact nonce bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Trusted UI decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalDecision {
    /// Authorize this exact digest once.
    Approve,
    /// Reject this exact digest.
    Reject,
}

/// Minimal response accepted from the one-shot approval frontend.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct ApprovalResponse {
    /// User decision.
    pub decision: ApprovalDecision,
    /// Digest displayed by the frontend.
    pub approval_digest: Hash32,
    /// One-time challenge nonce.
    pub nonce: ApprovalNonce,
}

impl fmt::Debug for ApprovalResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalResponse")
            .field("decision", &self.decision)
            .field("approval_digest", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .finish()
    }
}

/// Observable state of a non-cloneable approval session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalSessionState {
    /// Challenge may be consumed once before its deadline.
    Pending,
    /// A matching approval or rejection was consumed.
    Consumed,
    /// A mismatch or external state change invalidated the challenge.
    Invalidated,
    /// Deadline passed before consumption.
    Expired,
}

/// In-memory one-shot approval challenge.
pub(crate) struct ApprovalSession {
    expected_digest: Hash32,
    nonce: ApprovalNonce,
    expires_at_ms: u64,
    authorization_window: ApprovalAuthorizationWindow,
    transport_window: Option<ApprovalTransportWindow>,
    state: ApprovalSessionState,
}

impl fmt::Debug for ApprovalSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalSession")
            .field("expected_digest", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("expires_at_ms", &"[REDACTED]")
            .field("authorization_window", &"[REDACTED]")
            .field("transport_window", &"[REDACTED]")
            .field("state", &self.state)
            .finish()
    }
}

impl ApprovalSession {
    /// Issues a challenge for at most 120 seconds.
    pub fn issue(
        binding: &ApprovalBinding,
        nonce: ApprovalNonce,
        ttl_ms: u64,
        channel: ReleaseChannel,
    ) -> Result<Self, ProtocolError> {
        binding.validate(channel)?;
        if ttl_ms == 0 || ttl_ms > APPROVAL_TTL_MAX_MS {
            return Err(ProtocolError::at(
                ProtocolErrorKind::InvalidNumericInvariant,
                ErrorField::Approval,
            ));
        }
        let issued_at_ms = current_unix_ms()?;
        let browser_remaining_ms = binding
            .browser
            .deadline_ms
            .checked_sub(issued_at_ms)
            .filter(|remaining| *remaining != 0)
            .ok_or_else(|| {
                ProtocolError::at(
                    ProtocolErrorKind::InvalidBrowserContext,
                    ErrorField::BrowserContext,
                )
            })?;
        let effective_ttl_ms = ttl_ms.min(browser_remaining_ms);
        let expires_at_ms = issued_at_ms.checked_add(effective_ttl_ms).ok_or_else(|| {
            ProtocolError::at(
                ProtocolErrorKind::InvalidNumericInvariant,
                ErrorField::Approval,
            )
        })?;
        let issued_window = IssuedApprovalSessionWindow::issue(effective_ttl_ms).map_err(|_| {
            ProtocolError::at(
                ProtocolErrorKind::InvalidNumericInvariant,
                ErrorField::Approval,
            )
        })?;
        let (authorization_window, transport_window) = issued_window.into_parts();
        let expected_digest = approval_digest(binding).map_err(|_| {
            ProtocolError::at(ProtocolErrorKind::BoundsExceeded, ErrorField::Approval)
        })?;
        Ok(Self {
            expected_digest,
            nonce,
            expires_at_ms,
            authorization_window,
            transport_window: Some(transport_window),
            state: ApprovalSessionState::Pending,
        })
    }

    /// Returns the expected digest to send to the trusted frontend.
    #[must_use]
    pub const fn expected_digest(&self) -> Hash32 {
        self.expected_digest
    }

    /// Returns the one-time nonce to send to the trusted frontend.
    #[must_use]
    pub const fn nonce(&self) -> ApprovalNonce {
        self.nonce
    }

    /// Returns the absolute expiration deadline.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Returns the remaining trusted monotonic lifetime, rounded down to
    /// milliseconds and bounded by the protocol maximum.
    pub fn remaining_milliseconds(&self) -> Result<u32, ProtocolError> {
        self.authorization_window
            .remaining_milliseconds()
            .map_err(map_window_check_error)
    }

    /// Returns current terminal/pending state.
    #[must_use]
    #[cfg(test)]
    pub const fn state(&self) -> ApprovalSessionState {
        self.state
    }

    /// Invalidates a pending challenge after any bound state changes.
    pub fn invalidate(&mut self) {
        self.transport_window.take();
        if self.state == ApprovalSessionState::Pending {
            self.state = ApprovalSessionState::Invalidated;
        }
    }

    /// Consumes the transport half once and binds it to the exact request
    /// derived from this session's immutable authorization binding.
    pub fn bind_transport(
        &mut self,
        binding: &ApprovalBinding,
        request: ApprovalRequest,
    ) -> Result<BoundApprovalTransport, ProtocolError> {
        match self.state {
            ApprovalSessionState::Consumed => {
                return Err(ProtocolError::new(ProtocolErrorKind::ApprovalConsumed));
            }
            ApprovalSessionState::Invalidated => {
                return Err(ProtocolError::new(ProtocolErrorKind::ApprovalInvalidated));
            }
            ApprovalSessionState::Expired => {
                return Err(ProtocolError::new(ProtocolErrorKind::ApprovalExpired));
            }
            ApprovalSessionState::Pending => {}
        }

        let Some(transport_window) = self.transport_window.take() else {
            self.state = ApprovalSessionState::Invalidated;
            return Err(ProtocolError::new(ProtocolErrorKind::ApprovalInvalidated));
        };
        let current_digest = approval_digest(binding).map_err(|_| {
            self.state = ApprovalSessionState::Invalidated;
            ProtocolError::new(ProtocolErrorKind::ApprovalInvalidated)
        })?;
        if !constant_time_equal(self.expected_digest.as_bytes(), current_digest.as_bytes())
            || !constant_time_equal(request.digest(), current_digest.as_bytes())
            || !constant_time_equal(request.approval_nonce(), self.nonce.as_bytes())
            || request.display() != &binding.display
        {
            self.state = ApprovalSessionState::Invalidated;
            return Err(ProtocolError::new(ProtocolErrorKind::ApprovalMismatch));
        }

        self.authorization_window
            .bind_transport(transport_window, request)
            .map_err(|error| {
                let protocol_error = map_window_check_error(error);
                self.state = if error == ApprovalSessionWindowError::Expired {
                    ApprovalSessionState::Expired
                } else {
                    ApprovalSessionState::Invalidated
                };
                protocol_error
            })
    }

    /// Requires the one transport half to have been successfully bound before
    /// a verified response can enter the public authorization transition.
    pub(crate) fn ensure_transport_bound(&mut self) -> Result<(), ProtocolError> {
        match self.state {
            ApprovalSessionState::Consumed => {
                Err(ProtocolError::new(ProtocolErrorKind::ApprovalConsumed))
            }
            ApprovalSessionState::Invalidated => {
                Err(ProtocolError::new(ProtocolErrorKind::ApprovalInvalidated))
            }
            ApprovalSessionState::Expired => {
                Err(ProtocolError::new(ProtocolErrorKind::ApprovalExpired))
            }
            ApprovalSessionState::Pending if self.transport_window.is_none() => Ok(()),
            ApprovalSessionState::Pending => {
                self.transport_window.take();
                self.state = ApprovalSessionState::Invalidated;
                Err(ProtocolError::new(ProtocolErrorKind::ApprovalInvalidated))
            }
        }
    }

    /// Consumes one exact response. Any mismatch terminally invalidates the session.
    pub fn consume(
        &mut self,
        response: ApprovalResponse,
        current_digest: Hash32,
    ) -> Result<ApprovalDecision, ProtocolError> {
        match self.state {
            ApprovalSessionState::Consumed => {
                return Err(ProtocolError::new(ProtocolErrorKind::ApprovalConsumed));
            }
            ApprovalSessionState::Invalidated => {
                return Err(ProtocolError::new(ProtocolErrorKind::ApprovalInvalidated));
            }
            ApprovalSessionState::Expired => {
                return Err(ProtocolError::new(ProtocolErrorKind::ApprovalExpired));
            }
            ApprovalSessionState::Pending => {}
        }
        self.authorization_window
            .ensure_unexpired()
            .map_err(|error| {
                let protocol_error = map_window_check_error(error);
                self.state = if error == ApprovalSessionWindowError::Expired {
                    ApprovalSessionState::Expired
                } else {
                    ApprovalSessionState::Invalidated
                };
                protocol_error
            })?;
        if !constant_time_equal(self.expected_digest.as_bytes(), current_digest.as_bytes())
            || !constant_time_equal(
                self.expected_digest.as_bytes(),
                response.approval_digest.as_bytes(),
            )
            || !constant_time_equal(self.nonce.as_bytes(), response.nonce.as_bytes())
        {
            self.state = ApprovalSessionState::Invalidated;
            return Err(ProtocolError::new(ProtocolErrorKind::ApprovalMismatch));
        }
        self.state = ApprovalSessionState::Consumed;
        Ok(response.decision)
    }
}

fn map_window_check_error(error: ApprovalSessionWindowError) -> ProtocolError {
    if error == ApprovalSessionWindowError::Expired {
        ProtocolError::new(ProtocolErrorKind::ApprovalExpired)
    } else {
        ProtocolError::new(ProtocolErrorKind::ApprovalInvalidated)
    }
}

fn current_unix_ms() -> Result<u64, ProtocolError> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
        ProtocolError::at(
            ProtocolErrorKind::InvalidNumericInvariant,
            ErrorField::Approval,
        )
    })?;
    u64::try_from(duration.as_millis()).map_err(|_| {
        ProtocolError::at(
            ProtocolErrorKind::InvalidNumericInvariant,
            ErrorField::Approval,
        )
    })
}

fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let difference = left
        .iter()
        .zip(right)
        .fold(0_u8, |accumulator, (left_byte, right_byte)| {
            accumulator | (left_byte ^ right_byte)
        });
    difference == 0
}

#[cfg(test)]
mod tests {
    use approval_wire::{
        ApprovalDisplay, ApprovalRequest, DisplayField, FieldSemantic, OperationKind, RiskLevel,
        SimulationStatus,
    };
    use wallet_model::{
        ActivationNonce, AdapterKind, Address20, BoundedBytes, BrowserContext, BrowserFamily,
        BrowserOrigin, BrowserProvenance, CanonicalOperation, ChainIdentity, ChannelNonce,
        DocumentId, DocumentLifecycle, ExtensionId, Hash32, LegacyTransaction, NonceLeaseId,
        ProfileInstallId, RequestId, SessionId, SimulationProvenance, TransactionTarget, U256,
    };

    use super::{
        APPROVAL_TTL_MAX_MS, ApprovalBinding, ApprovalDecision, ApprovalNonce, ApprovalResponse,
        ApprovalSession, ApprovalSessionState, NonceLeaseBinding, approval_digest, display_digest,
    };
    use crate::{ProtocolError, ProtocolErrorKind, ProtocolValidity, ReleaseChannel};

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

    fn binding() -> Result<ApprovalBinding, Box<dyn std::error::Error>> {
        let display = binding_display()?;
        Ok(ApprovalBinding {
            operation: CanonicalOperation::LegacyEip155(LegacyTransaction {
                chain_id: U256::from(1),
                nonce: U256::from(4),
                gas_price: U256::from(10),
                gas_limit: U256::from(21_000),
                target: TransactionTarget::Call(Address20::new([1; 20])),
                value: U256::from(5),
                data: BoundedBytes::new(Vec::new())?,
            }),
            account: Address20::new([2; 20]),
            chain: ChainIdentity::new(
                U256::from(1),
                Hash32::new([3; 32]),
                AdapterKind::EthereumPos,
                Hash32::new([4; 32]),
            ),
            ruleset_revision: Hash32::new([5; 32]),
            nonce_lease: Some(NonceLeaseBinding {
                lease_id: NonceLeaseId::new([6; 16]),
                nonce: U256::from(4),
            }),
            browser: BrowserContext {
                browser_family: BrowserFamily::Chrome,
                profile_install_id: ProfileInstallId::new([13; 32]),
                extension_id: ExtensionId::new("abcdefghijklmnopabcdefghijklmnop")?,
                tab_id: 7,
                frame_id: 0,
                document_id: DocumentId::new("document-a")?,
                activation_nonce: ActivationNonce::new([14; 32]),
                top_origin: BrowserOrigin::new("https://example.test")?,
                frame_origin: BrowserOrigin::new("https://example.test")?,
                document_lifecycle: DocumentLifecycle::Active,
                channel_nonce: ChannelNonce::new([15; 32]),
                provenance: BrowserProvenance::BrowserReportedUnverified,
                session_id: SessionId::new([8; 32]),
                sequence: 9,
                deadline_ms: u64::MAX,
                request_id: RequestId::new([10; 16]),
            },
            display,
            simulation: SimulationProvenance::NotPerformed,
            rpc_observations_digest: Hash32::new([11; 32]),
            protocol_validity: ProtocolValidity::Verified,
        })
    }

    fn binding_display() -> Result<ApprovalDisplay, approval_wire::WireError> {
        ApprovalDisplay::new(
            RiskLevel::High,
            vec![
                display_field(FieldSemantic::Origin, "https://example.test")?,
                display_field(
                    FieldSemantic::OriginProvenance,
                    "Browser-reported; not independently verified",
                )?,
                display_field(
                    FieldSemantic::Account,
                    "0x0202020202020202020202020202020202020202",
                )?,
                display_field(FieldSemantic::NetworkName, "Ethereum")?,
                display_field(FieldSemantic::ChainId, "1")?,
                display_field(
                    FieldSemantic::GenesisHash,
                    "0x0303030303030303030303030303030303030303030303030303030303030303",
                )?,
                display_field(
                    FieldSemantic::RulesetRevision,
                    "0x0505050505050505050505050505050505050505050505050505050505050505",
                )?,
                display_field(
                    FieldSemantic::RpcObservationsDigest,
                    "0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                )?,
                display_field(
                    FieldSemantic::OperationKind,
                    OperationKind::LegacyEip155.value(),
                )?,
                display_field(FieldSemantic::EnvelopeType, "0")?,
                display_field(FieldSemantic::Nonce, "0x4")?,
                display_field(
                    FieldSemantic::Target,
                    "0x0101010101010101010101010101010101010101",
                )?,
                display_field(FieldSemantic::NativeValue, "0x5")?,
                display_field(FieldSemantic::GasLimit, "0x5208")?,
                display_field(FieldSemantic::GasPrice, "0xa")?,
                display_field(FieldSemantic::MaximumNetworkFee, "0x33450")?,
                display_field(FieldSemantic::Calldata, "0x")?,
                display_field(
                    FieldSemantic::CalldataKeccak256,
                    "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                )?,
                display_field(
                    FieldSemantic::SimulationStatus,
                    SimulationStatus::NotPerformed.value(),
                )?,
                display_field(
                    FieldSemantic::OriginWarning,
                    "Browser origin is not independently attested.",
                )?,
                display_field(
                    FieldSemantic::NoSimulationWarning,
                    "No simulation was performed.",
                )?,
            ],
        )
    }

    fn display_field(
        semantic: FieldSemantic,
        value: &str,
    ) -> Result<DisplayField, approval_wire::WireError> {
        DisplayField::new(semantic, value, semantic != FieldSemantic::SimulationEngine)
    }

    fn request_for_session(
        binding: &ApprovalBinding,
        session: &ApprovalSession,
        expires_after_milliseconds: u32,
    ) -> Result<ApprovalRequest, approval_wire::WireError> {
        ApprovalRequest::new(
            *session.expected_digest().as_bytes(),
            *session.nonce().as_bytes(),
            expires_after_milliseconds,
            "blue comet",
            binding.display.clone(),
        )
    }

    #[test]
    fn any_single_bit_change_changes_approval_digest() -> Result<(), Box<dyn std::error::Error>> {
        let original = binding()?;
        let expected = approval_digest(&original)?;

        let mut cases = Vec::new();
        let mut account = original.clone();
        account.account = Address20::new([0; 20]);
        cases.push(account);
        let mut sequence = original.clone();
        sequence.browser.sequence ^= 1;
        cases.push(sequence);
        let mut profile = original.clone();
        profile.browser.profile_install_id = ProfileInstallId::new([12; 32]);
        cases.push(profile);
        let mut extension = original.clone();
        extension.browser.extension_id = ExtensionId::new("bbcdefghijklmnopabcdefghijklmnop")?;
        cases.push(extension);
        let mut document = original.clone();
        document.browser.document_id = DocumentId::new("document-b")?;
        cases.push(document);
        let mut activation = original.clone();
        activation.browser.activation_nonce = ActivationNonce::new([16; 32]);
        cases.push(activation);
        let mut channel = original.clone();
        channel.browser.channel_nonce = ChannelNonce::new([17; 32]);
        cases.push(channel);
        let mut origin = original.clone();
        origin.browser.top_origin = BrowserOrigin::new("https://changed.test")?;
        cases.push(origin);
        let mut rpc = original.clone();
        rpc.rpc_observations_digest = Hash32::new([10; 32]);
        cases.push(rpc);
        let mut display = original.clone();
        let changed_fields = display
            .display
            .fields()
            .iter()
            .map(|field| {
                if field.semantic() == FieldSemantic::Account {
                    display_field(
                        FieldSemantic::Account,
                        "0x0303030303030303030303030303030303030303",
                    )
                } else {
                    Ok(field.clone())
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        display.display = ApprovalDisplay::new(RiskLevel::High, changed_fields)?;
        cases.push(display);

        for changed in cases {
            assert_ne!(approval_digest(&changed)?, expected);
        }
        Ok(())
    }

    #[test]
    fn display_digest_is_semantic_and_value_sensitive() -> Result<(), Box<dyn std::error::Error>> {
        let original = binding()?.display;
        let changed_fields = original
            .fields()
            .iter()
            .map(|field| {
                if field.semantic() == FieldSemantic::Account {
                    display_field(
                        FieldSemantic::Account,
                        "0x0303030303030303030303030303030303030303",
                    )
                } else {
                    Ok(field.clone())
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        let changed = ApprovalDisplay::new(RiskLevel::High, changed_fields)?;
        assert_ne!(display_digest(&original)?, display_digest(&changed)?);
        Ok(())
    }

    #[test]
    fn approval_is_one_shot_and_bound_to_current_state() -> Result<(), Box<dyn std::error::Error>> {
        let binding = binding()?;
        let mut session = ApprovalSession::issue(
            &binding,
            ApprovalNonce::new([12; 32]),
            10_000,
            ReleaseChannel::PrivateCanary,
        )?;
        let response = ApprovalResponse {
            decision: ApprovalDecision::Approve,
            approval_digest: session.expected_digest(),
            nonce: session.nonce(),
        };
        assert_eq!(
            session.consume(response, session.expected_digest())?,
            ApprovalDecision::Approve
        );
        assert_eq!(session.state(), ApprovalSessionState::Consumed);
        assert_eq!(
            session.consume(response, session.expected_digest()),
            Err(ProtocolError::new(ProtocolErrorKind::ApprovalConsumed))
        );
        Ok(())
    }

    #[test]
    fn mismatch_terminally_invalidates_challenge() -> Result<(), Box<dyn std::error::Error>> {
        let binding = binding()?;
        let mut session = ApprovalSession::issue(
            &binding,
            ApprovalNonce::new([12; 32]),
            10_000,
            ReleaseChannel::PrivateCanary,
        )?;
        let response = ApprovalResponse {
            decision: ApprovalDecision::Approve,
            approval_digest: Hash32::ZERO,
            nonce: session.nonce(),
        };
        assert_eq!(
            session.consume(response, session.expected_digest()),
            Err(ProtocolError::new(ProtocolErrorKind::ApprovalMismatch))
        );
        assert_eq!(session.state(), ApprovalSessionState::Invalidated);
        Ok(())
    }

    #[test]
    fn approval_transport_binding_is_one_attempt() -> Result<(), Box<dyn std::error::Error>> {
        let binding = binding()?;
        let mut session = ApprovalSession::issue(
            &binding,
            ApprovalNonce::new([12; 32]),
            10_000,
            ReleaseChannel::PrivateCanary,
        )?;
        let request = request_for_session(&binding, &session, 10_000)?;
        let retry = request.clone();

        let _bound = session.bind_transport(&binding, request)?;
        assert_eq!(session.state(), ApprovalSessionState::Pending);
        assert!(matches!(
            session.bind_transport(&binding, retry),
            Err(error) if error == ProtocolError::new(ProtocolErrorKind::ApprovalInvalidated)
        ));
        assert_eq!(session.state(), ApprovalSessionState::Invalidated);
        Ok(())
    }

    #[test]
    fn authorization_requires_successfully_bound_transport()
    -> Result<(), Box<dyn std::error::Error>> {
        let binding = binding()?;
        let mut unbound = ApprovalSession::issue(
            &binding,
            ApprovalNonce::new([12; 32]),
            10_000,
            ReleaseChannel::PrivateCanary,
        )?;
        assert_eq!(
            unbound.ensure_transport_bound(),
            Err(ProtocolError::new(ProtocolErrorKind::ApprovalInvalidated))
        );
        assert_eq!(unbound.state(), ApprovalSessionState::Invalidated);

        let mut bound = ApprovalSession::issue(
            &binding,
            ApprovalNonce::new([12; 32]),
            10_000,
            ReleaseChannel::PrivateCanary,
        )?;
        let request = request_for_session(&binding, &bound, 10_000)?;
        let _transport = bound.bind_transport(&binding, request)?;
        assert_eq!(bound.ensure_transport_bound(), Ok(()));
        assert_eq!(bound.state(), ApprovalSessionState::Pending);
        Ok(())
    }

    #[test]
    fn approval_transport_substitution_terminally_invalidates_session()
    -> Result<(), Box<dyn std::error::Error>> {
        let binding = binding()?;

        let mut digest_session = ApprovalSession::issue(
            &binding,
            ApprovalNonce::new([12; 32]),
            10_000,
            ReleaseChannel::PrivateCanary,
        )?;
        let changed_digest = ApprovalRequest::new(
            [13; 32],
            *digest_session.nonce().as_bytes(),
            10_000,
            "blue comet",
            binding.display.clone(),
        )?;
        assert!(matches!(
            digest_session.bind_transport(&binding, changed_digest),
            Err(error) if error == ProtocolError::new(ProtocolErrorKind::ApprovalMismatch)
        ));
        assert_eq!(digest_session.state(), ApprovalSessionState::Invalidated);

        let mut nonce_session = ApprovalSession::issue(
            &binding,
            ApprovalNonce::new([12; 32]),
            10_000,
            ReleaseChannel::PrivateCanary,
        )?;
        let changed_nonce = ApprovalRequest::new(
            *nonce_session.expected_digest().as_bytes(),
            [13; 32],
            10_000,
            "blue comet",
            binding.display.clone(),
        )?;
        assert!(matches!(
            nonce_session.bind_transport(&binding, changed_nonce),
            Err(error) if error == ProtocolError::new(ProtocolErrorKind::ApprovalMismatch)
        ));
        assert_eq!(nonce_session.state(), ApprovalSessionState::Invalidated);

        let mut display_session = ApprovalSession::issue(
            &binding,
            ApprovalNonce::new([12; 32]),
            10_000,
            ReleaseChannel::PrivateCanary,
        )?;
        let mut changed_fields = binding.display.fields().to_vec();
        let account_field = changed_fields
            .iter_mut()
            .find(|field| field.semantic() == FieldSemantic::Account)
            .ok_or("missing account display field")?;
        *account_field = display_field(
            FieldSemantic::Account,
            "0x0303030303030303030303030303030303030303",
        )?;
        let changed_display = ApprovalDisplay::new(binding.display.risk(), changed_fields)?;
        let substituted_display = ApprovalRequest::new(
            *display_session.expected_digest().as_bytes(),
            *display_session.nonce().as_bytes(),
            10_000,
            "blue comet",
            changed_display,
        )?;
        assert!(matches!(
            display_session.bind_transport(&binding, substituted_display),
            Err(error) if error == ProtocolError::new(ProtocolErrorKind::ApprovalMismatch)
        ));
        assert_eq!(display_session.state(), ApprovalSessionState::Invalidated);
        Ok(())
    }

    #[test]
    fn approval_transport_binding_obeys_original_monotonic_expiry()
    -> Result<(), Box<dyn std::error::Error>> {
        let binding = binding()?;
        let mut session = ApprovalSession::issue(
            &binding,
            ApprovalNonce::new([12; 32]),
            10,
            ReleaseChannel::PrivateCanary,
        )?;
        let request = request_for_session(&binding, &session, u32::try_from(APPROVAL_TTL_MAX_MS)?)?;

        std::thread::sleep(std::time::Duration::from_millis(25));

        assert!(matches!(
            session.bind_transport(&binding, request),
            Err(error) if error == ProtocolError::new(ProtocolErrorKind::ApprovalExpired)
        ));
        assert_eq!(session.state(), ApprovalSessionState::Expired);
        Ok(())
    }

    #[test]
    fn approval_session_is_move_only() {
        let _ = <ApprovalSession as AmbiguousIfClone<_>>::marker;
        let _ = <ApprovalSession as AmbiguousIfCopy<_>>::marker;
    }

    #[test]
    fn deadline_is_inclusive_and_capped() -> Result<(), Box<dyn std::error::Error>> {
        let binding = binding()?;
        let mut session = ApprovalSession::issue(
            &binding,
            ApprovalNonce::new([12; 32]),
            1,
            ReleaseChannel::PrivateCanary,
        )?;
        let response = ApprovalResponse {
            decision: ApprovalDecision::Reject,
            approval_digest: session.expected_digest(),
            nonce: session.nonce(),
        };
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert_eq!(
            session.consume(response, session.expected_digest()),
            Err(ProtocolError::new(ProtocolErrorKind::ApprovalExpired))
        );
        assert!(
            ApprovalSession::issue(
                &binding,
                ApprovalNonce::new([1; 32]),
                120_001,
                ReleaseChannel::PrivateCanary,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn delayed_preparation_clamps_to_browser_deadline() -> Result<(), Box<dyn std::error::Error>> {
        let mut binding = binding()?;
        binding.browser.deadline_ms = super::current_unix_ms()?.saturating_add(500);
        let session = ApprovalSession::issue(
            &binding,
            ApprovalNonce::new([12; 32]),
            APPROVAL_TTL_MAX_MS,
            ReleaseChannel::PrivateCanary,
        )?;
        assert_eq!(session.expires_at_ms(), binding.browser.deadline_ms);
        assert!(session.remaining_milliseconds()? <= 500);

        binding.browser.deadline_ms = super::current_unix_ms()?;
        let expired = ApprovalSession::issue(
            &binding,
            ApprovalNonce::new([12; 32]),
            APPROVAL_TTL_MAX_MS,
            ReleaseChannel::PrivateCanary,
        );
        assert!(matches!(
            expired,
            Err(error)
                if error
                    == ProtocolError::at(
                        ProtocolErrorKind::InvalidBrowserContext,
                        crate::ErrorField::BrowserContext,
                    )
        ));
        Ok(())
    }
}
