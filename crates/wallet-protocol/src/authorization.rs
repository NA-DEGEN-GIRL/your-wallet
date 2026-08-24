use approval_wire::{
    ApprovalDisplay, ApprovalRequest, DisplayField, FieldSemantic, OperationKind, RiskLevel,
    SimulationStatus,
};
use chain_registry::{
    Adapter, BuiltInChainEvidence, ChainDefinition, FinalityModel, NetworkKind, RuleCoverage,
    SourceClaim, TransactionEnvelope,
};
use platform_windows::{
    BoundApprovalTransport, VerifiedApprovalDecision, VerifiedApprovalResponse,
};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;
use std::time::{SystemTime, UNIX_EPOCH};
use wallet_eip712::ValidatedTypedDataV4;
use wallet_model::{
    AdapterKind, Address20, BrowserContext, CanonicalOperation, ChainIdentity, Hash32,
    SimulationEngine, SimulationProvenance, TransactionTarget, U256, UntrustedOperation,
    UntrustedTransaction,
};

use crate::{
    ApprovalDecision, ApprovalNonce, ErrorField, NonceLease, OperationValidator,
    ProtocolDisposition, ProtocolError, ProtocolErrorKind, ProtocolValidity, ReleaseChannel,
    SignedSchemaAllowlist,
    approval::{
        ApprovalBinding, ApprovalResponse, ApprovalSession, NonceLeaseBinding, approval_digest,
    },
};

const MAX_EXACT_DISPLAY_PAYLOAD_BYTES: usize = 512;
const MAX_EXACT_PERSONAL_MESSAGE_BYTES: usize = 1_023;
const COMPILED_RELEASE_CHANNEL: ReleaseChannel = ReleaseChannel::PrivateCanary;
const APPROVAL_TTL_MS: u64 = 120_000;

/// Untrusted operation supplied to the authorization TCB.
#[derive(Clone, Eq, PartialEq)]
pub enum AuthorizationOperation {
    /// Browser/RPC transaction fields requiring normalization and validation.
    Transaction(UntrustedTransaction),
    /// Exact EIP-191 message bytes.
    PersonalMessage(Vec<u8>),
    /// Opaque result of strict parsing and hashing of exact EIP-712 source bytes.
    TypedDataV4(ValidatedTypedDataV4),
}

impl core::fmt::Debug for AuthorizationOperation {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transaction(_) => {
                formatter.write_str("AuthorizationOperation::Transaction([REDACTED])")
            }
            Self::PersonalMessage(message) => formatter
                .debug_struct("AuthorizationOperation::PersonalMessage")
                .field("message", &"[REDACTED]")
                .field("bytes", &message.len())
                .finish(),
            Self::TypedDataV4(_) => {
                formatter.write_str("AuthorizationOperation::TypedDataV4([REDACTED])")
            }
        }
    }
}

/// Untrusted request facts plus opaque chain evidence used to prepare approval.
pub struct AuthorizationRequest {
    /// Operation to validate and display.
    pub operation: AuthorizationOperation,
    /// Account selected by the user before the dApp request.
    pub account: Address20,
    /// Opaque assessment of an observed built-in chain.
    pub chain_evidence: BuiltInChainEvidence,
    /// Durable nonce reservation for transaction operations.
    pub nonce_lease: Option<NonceLease>,
    /// Browser-owned document/session provenance reported by the extension.
    pub browser: BrowserContext,
    /// Simulation evidence, including an explicit not-performed state.
    pub simulation: SimulationProvenance,
    /// Digest of canonical RPC observations used to prepare transaction fields.
    pub rpc_observations_digest: Hash32,
}

impl core::fmt::Debug for AuthorizationRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AuthorizationRequest")
            .field("operation", &self.operation)
            .field("account", &"[REDACTED]")
            .field("chain_evidence", &"[REDACTED]")
            .field("nonce_lease", &"[REDACTED]")
            .field("browser", &"[REDACTED]")
            .field("simulation", &self.simulation)
            .field("rpc_observations_digest", &"[REDACTED]")
            .finish()
    }
}

/// One pending, non-cloneable approval prepared entirely inside the
/// authorization TCB.
pub struct PreparedAuthorization {
    binding: ApprovalBinding,
    session: ApprovalSession,
}

impl core::fmt::Debug for PreparedAuthorization {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PreparedAuthorization([REDACTED BINDING AND SESSION])")
    }
}

impl PreparedAuthorization {
    /// Returns the exact trusted display model bound into the challenge digest.
    #[must_use]
    pub const fn display(&self) -> &ApprovalDisplay {
        &self.binding.display
    }

    /// Returns the remaining trusted approval lifetime for the Key Agent's
    /// private helper request.
    ///
    /// The authorization TCB deliberately does not accept or serialize an
    /// anti-phishing phrase. That locally protected setting belongs to the Key
    /// Agent and must not be caller-injected through this public API.
    pub fn remaining_milliseconds(&self) -> Result<u32, ProtocolError> {
        self.session.remaining_milliseconds()
    }

    /// Returns the exact digest the trusted frontend must echo.
    #[must_use]
    pub const fn approval_digest(&self) -> Hash32 {
        self.session.expected_digest()
    }

    /// Returns the one-time random nonce the trusted frontend must echo.
    #[must_use]
    pub const fn approval_nonce(&self) -> ApprovalNonce {
        self.session.nonce()
    }

    /// Returns the wall-clock deadline used for external display and bookkeeping.
    /// Authorization expiry is enforced by the opaque monotonic session window.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.session.expires_at_ms()
    }

    /// Consumes this session's transport half once and binds it to the exact
    /// Key-Agent request derived from this immutable authorization.
    ///
    /// A substituted digest, nonce, or canonical display terminally invalidates
    /// the session. Neither the request nor its original monotonic deadline is
    /// exposed by the returned opaque transport capability.
    pub fn bind_approval_transport(
        &mut self,
        request: ApprovalRequest,
    ) -> Result<BoundApprovalTransport, ProtocolError> {
        self.session.bind_transport(&self.binding, request)
    }

    /// Invalidates this challenge after lock, suspend, navigation, chain change,
    /// process restart, or any other bound state change.
    pub fn invalidate(&mut self) {
        self.session.invalidate();
    }

    /// Consumes one exact approval into an opaque signer capability.
    // Consuming the non-Clone response is a security property: a verified
    // one-shot UI result must not remain reusable after authorization.
    #[allow(clippy::needless_pass_by_value)]
    pub fn authorize(
        mut self,
        expected_request_hash: [u8; 32],
        verified_response: VerifiedApprovalResponse,
    ) -> Result<AuthorizedOperation, ProtocolError> {
        self.session.ensure_transport_bound()?;
        let (decision, approval_digest, challenge_nonce, child_transcript, displayed_request_hash) =
            verified_response.into_parts();
        if child_transcript.iter().all(|byte| *byte == 0)
            || expected_request_hash.iter().all(|byte| *byte == 0)
            || displayed_request_hash != expected_request_hash
        {
            return Err(ProtocolError::new(ProtocolErrorKind::ApprovalMismatch));
        }
        let response = ApprovalResponse {
            decision: match decision {
                VerifiedApprovalDecision::Approve => ApprovalDecision::Approve,
                VerifiedApprovalDecision::Reject => ApprovalDecision::Reject,
            },
            approval_digest: Hash32::new(approval_digest),
            nonce: ApprovalNonce::new(challenge_nonce),
        };
        self.authorize_inner(response)
    }

    fn authorize_inner(
        mut self,
        response: ApprovalResponse,
    ) -> Result<AuthorizedOperation, ProtocolError> {
        let digest = approval_digest(&self.binding).map_err(|_| {
            ProtocolError::at(ProtocolErrorKind::BoundsExceeded, ErrorField::Approval)
        })?;
        if self.session.consume(response, digest)? != ApprovalDecision::Approve {
            return Err(ProtocolError::new(ProtocolErrorKind::UserRejected));
        }
        Ok(AuthorizedOperation {
            binding: self.binding,
            approval_digest: digest,
        })
    }
}

/// Opaque, non-cloneable capability proving one exact operation was displayed
/// and approved through a live one-shot session.
pub struct AuthorizedOperation {
    binding: ApprovalBinding,
    approval_digest: Hash32,
}

impl core::fmt::Debug for AuthorizedOperation {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AuthorizedOperation([REDACTED BINDING])")
    }
}

/// Exact operation view available only after one-shot authorization.
#[derive(Clone, Copy)]
pub enum AuthorizedOperationRef<'a> {
    /// EIP-155 legacy transaction.
    Legacy(&'a wallet_model::LegacyTransaction),
    /// EIP-2930 access-list transaction.
    AccessList(&'a wallet_model::AccessListTransaction),
    /// EIP-1559 dynamic-fee transaction.
    DynamicFee(&'a wallet_model::DynamicFeeTransaction),
    /// EIP-191 personal message.
    PersonalMessage(&'a wallet_model::PersonalMessage),
    /// Strictly parsed EIP-712 v4 value.
    TypedDataV4(&'a wallet_model::TypedDataV4),
}

impl core::fmt::Debug for AuthorizedOperationRef<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Legacy(_) => "AuthorizedOperationRef::Legacy([REDACTED])",
            Self::AccessList(_) => "AuthorizedOperationRef::AccessList([REDACTED])",
            Self::DynamicFee(_) => "AuthorizedOperationRef::DynamicFee([REDACTED])",
            Self::PersonalMessage(_) => "AuthorizedOperationRef::PersonalMessage([REDACTED])",
            Self::TypedDataV4(_) => "AuthorizedOperationRef::TypedDataV4([REDACTED])",
        })
    }
}

impl AuthorizedOperation {
    /// Borrows the exact validated operation. No owned re-wrap API is exposed.
    #[must_use]
    pub const fn operation(&self) -> AuthorizedOperationRef<'_> {
        match &self.binding.operation {
            CanonicalOperation::LegacyEip155(value) => AuthorizedOperationRef::Legacy(value),
            CanonicalOperation::AccessListEip2930(value) => {
                AuthorizedOperationRef::AccessList(value)
            }
            CanonicalOperation::DynamicFeeEip1559(value) => {
                AuthorizedOperationRef::DynamicFee(value)
            }
            CanonicalOperation::PersonalMessage(value) => {
                AuthorizedOperationRef::PersonalMessage(value)
            }
            CanonicalOperation::TypedDataV4(value) => AuthorizedOperationRef::TypedDataV4(value),
        }
    }

    /// Returns the approved account.
    #[must_use]
    pub const fn account(&self) -> Address20 {
        self.binding.account
    }

    /// Returns the full approved chain fingerprint.
    #[must_use]
    pub const fn chain(&self) -> ChainIdentity {
        self.binding.chain
    }

    /// Returns the durable nonce reservation, if this is a transaction.
    #[must_use]
    pub const fn nonce_lease(&self) -> Option<NonceLeaseBinding> {
        self.binding.nonce_lease
    }

    /// Returns the exact consumed approval digest.
    #[must_use]
    pub const fn approval_digest(&self) -> Hash32 {
        self.approval_digest
    }

    /// Consumes the one-shot capability and returns its immutable canonical
    /// operation to the secret-core signer. Callers cannot create another
    /// capability from the returned value.
    #[must_use]
    pub fn into_canonical(self) -> CanonicalOperation {
        self.binding.operation
    }
}

/// Validates untrusted fields, derives a fixed-semantic display model, binds all
/// provenance, and issues a one-shot challenge using this artifact's fixed
/// release policy and a fresh operating-system CSPRNG nonce.
pub fn prepare_authorization(
    mut request: AuthorizationRequest,
) -> Result<PreparedAuthorization, ProtocolError> {
    let mut nonce_bytes = [0_u8; 32];
    getrandom::fill(&mut nonce_bytes).map_err(|_| {
        ProtocolError::at(
            ProtocolErrorKind::InvalidNumericInvariant,
            ErrorField::Approval,
        )
    })?;
    let nonce_lease = request.nonce_lease.take().map(NonceLease::into_binding);
    prepare_authorization_with_policy(
        request,
        nonce_lease,
        ApprovalNonce::new(nonce_bytes),
        APPROVAL_TTL_MS,
        COMPILED_RELEASE_CHANNEL,
    )
}

fn prepare_authorization_with_policy(
    request: AuthorizationRequest,
    nonce_lease: Option<NonceLeaseBinding>,
    nonce: ApprovalNonce,
    ttl_ms: u64,
    channel: ReleaseChannel,
) -> Result<PreparedAuthorization, ProtocolError> {
    request.browser.validate().map_err(|_| {
        ProtocolError::at(
            ProtocolErrorKind::InvalidBrowserContext,
            ErrorField::BrowserContext,
        )
    })?;

    let definition = request.chain_evidence.definition();
    let chain = chain_identity(request.chain_evidence)?;
    let protocol_validity = protocol_validity(request.chain_evidence, current_unix_seconds()?)?;
    if protocol_validity.disposition(channel) == ProtocolDisposition::Deny {
        return Err(ProtocolError::new(ProtocolErrorKind::ProtocolInvalid));
    }

    let validator = OperationValidator::new(chain, SignedSchemaAllowlist::default());
    let validated = match request.operation {
        AuthorizationOperation::Transaction(transaction) => {
            validator.validate(UntrustedOperation::Transaction(transaction))?
        }
        AuthorizationOperation::PersonalMessage(message) => {
            validator.validate(UntrustedOperation::PersonalMessage(message))?
        }
        AuthorizationOperation::TypedDataV4(typed_data) => {
            validator.validate_eip712(&typed_data)?
        }
    };
    let operation = validated.into_canonical();
    let ruleset_revision = ruleset_digest(definition);
    let display = derive_display(
        &operation,
        DisplayContext {
            account: request.account,
            definition,
            browser: &request.browser,
            simulation: request.simulation,
            rpc_observations_digest: request.rpc_observations_digest,
            validity: protocol_validity,
            ruleset_revision,
        },
    )?;
    let binding = ApprovalBinding {
        operation,
        account: request.account,
        chain,
        ruleset_revision,
        nonce_lease,
        browser: request.browser,
        display,
        simulation: request.simulation,
        rpc_observations_digest: request.rpc_observations_digest,
        protocol_validity,
    };
    let session = ApprovalSession::issue(&binding, nonce, ttl_ms, channel)?;
    Ok(PreparedAuthorization { binding, session })
}

fn chain_identity(evidence: BuiltInChainEvidence) -> Result<ChainIdentity, ProtocolError> {
    let definition = evidence.definition();
    let chain_id = U256::from_be_bytes(definition.chain_id.to_be_bytes());
    if chain_id.is_zero() {
        return Err(ProtocolError::at(
            ProtocolErrorKind::ChainMismatch,
            ErrorField::ChainId,
        ));
    }
    Ok(ChainIdentity::new(
        chain_id,
        Hash32::new(evidence.genesis_hash().into_bytes()),
        adapter_kind(definition.adapter),
        registry_digest(definition),
    ))
}

const fn adapter_kind(adapter: Adapter) -> AdapterKind {
    match adapter {
        Adapter::EthereumPoS => AdapterKind::EthereumPos,
        Adapter::BscParlia => AdapterKind::BscParlia,
        Adapter::PolygonPoS => AdapterKind::PolygonPos,
        Adapter::AvalancheC => AdapterKind::AvalancheC,
        Adapter::OpStack => AdapterKind::OpStack,
        Adapter::ArbitrumNitro => AdapterKind::ArbitrumNitro,
        Adapter::GenericEvm155 => AdapterKind::GenericEvm155,
    }
}

fn protocol_validity(
    evidence: BuiltInChainEvidence,
    now_unix: u64,
) -> Result<ProtocolValidity, ProtocolError> {
    let definition = evidence.definition();
    if matches!(definition.rules, RuleCoverage::Unknown { .. })
        || matches!(definition.finality.coverage, RuleCoverage::Unknown { .. })
    {
        return Ok(ProtocolValidity::RuleCoverageUnknown {
            rule_id: ruleset_digest(definition),
        });
    }
    if now_unix > definition.review.expires_at_unix {
        let expired_at_ms = definition
            .review
            .expires_at_unix
            .checked_mul(1_000)
            .ok_or_else(|| {
                ProtocolError::at(
                    ProtocolErrorKind::InvalidNumericInvariant,
                    ErrorField::Approval,
                )
            })?;
        return Ok(ProtocolValidity::ExpiredReview { expired_at_ms });
    }
    Ok(ProtocolValidity::Verified)
}

fn current_unix_seconds() -> Result<u64, ProtocolError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| {
            ProtocolError::at(
                ProtocolErrorKind::InvalidNumericInvariant,
                ErrorField::Approval,
            )
        })
}

#[derive(Clone, Copy)]
struct DisplayContext<'a> {
    account: Address20,
    definition: &'a ChainDefinition,
    browser: &'a BrowserContext,
    simulation: SimulationProvenance,
    rpc_observations_digest: Hash32,
    validity: ProtocolValidity,
    ruleset_revision: Hash32,
}

#[allow(clippy::too_many_lines)]
fn derive_display(
    operation: &CanonicalOperation,
    context: DisplayContext<'_>,
) -> Result<ApprovalDisplay, ProtocolError> {
    let mut fields = vec![
        trusted_field(FieldSemantic::Origin, context.browser.top_origin.as_str())?,
        trusted_field(
            FieldSemantic::OriginProvenance,
            "Browser-reported; not independently verified",
        )?,
        trusted_field(FieldSemantic::Account, eip55(context.account))?,
        trusted_field(FieldSemantic::NetworkName, context.definition.display_name)?,
        trusted_field(
            FieldSemantic::ChainId,
            context.definition.chain_id.to_string(),
        )?,
        trusted_field(
            FieldSemantic::GenesisHash,
            chain_genesis(context.definition)?,
        )?,
        trusted_field(
            FieldSemantic::RulesetRevision,
            context.ruleset_revision.to_fixed_hex(),
        )?,
        trusted_field(
            FieldSemantic::RpcObservationsDigest,
            context.rpc_observations_digest.to_fixed_hex(),
        )?,
        trusted_field(
            FieldSemantic::OriginWarning,
            "The requesting origin is reported by the browser extension and is not independently attested.",
        )?,
    ];
    let mut high_risk = false;

    match operation {
        CanonicalOperation::LegacyEip155(transaction) => {
            fields.push(trusted_field(
                FieldSemantic::OperationKind,
                OperationKind::LegacyEip155.value(),
            )?);
            fields.push(trusted_field(
                FieldSemantic::GasPrice,
                transaction.gas_price.to_canonical_quantity(),
            )?);
            let maximum_fee = checked_fee(
                transaction.gas_limit,
                transaction.gas_price,
                ErrorField::GasPrice,
            )?;
            transaction_display_fields(
                &mut fields,
                transaction.nonce,
                transaction.target,
                transaction.value,
                transaction.gas_limit,
                maximum_fee,
                transaction.data.as_slice(),
                0,
                None,
                &mut high_risk,
            )?;
        }
        CanonicalOperation::AccessListEip2930(transaction) => {
            fields.push(trusted_field(
                FieldSemantic::OperationKind,
                OperationKind::AccessListEip2930.value(),
            )?);
            fields.push(trusted_field(
                FieldSemantic::GasPrice,
                transaction.gas_price.to_canonical_quantity(),
            )?);
            let maximum_fee = checked_fee(
                transaction.gas_limit,
                transaction.gas_price,
                ErrorField::GasPrice,
            )?;
            transaction_display_fields(
                &mut fields,
                transaction.nonce,
                transaction.target,
                transaction.value,
                transaction.gas_limit,
                maximum_fee,
                transaction.data.as_slice(),
                1,
                Some(&transaction.access_list),
                &mut high_risk,
            )?;
        }
        CanonicalOperation::DynamicFeeEip1559(transaction) => {
            fields.push(trusted_field(
                FieldSemantic::OperationKind,
                OperationKind::DynamicFeeEip1559.value(),
            )?);
            fields.push(trusted_field(
                FieldSemantic::MaxPriorityFeePerGas,
                transaction.max_priority_fee_per_gas.to_canonical_quantity(),
            )?);
            fields.push(trusted_field(
                FieldSemantic::MaxFeePerGas,
                transaction.max_fee_per_gas.to_canonical_quantity(),
            )?);
            let maximum_fee = checked_fee(
                transaction.gas_limit,
                transaction.max_fee_per_gas,
                ErrorField::MaxFeePerGas,
            )?;
            transaction_display_fields(
                &mut fields,
                transaction.nonce,
                transaction.target,
                transaction.value,
                transaction.gas_limit,
                maximum_fee,
                transaction.data.as_slice(),
                2,
                Some(&transaction.access_list),
                &mut high_risk,
            )?;
        }
        CanonicalOperation::PersonalMessage(message) => {
            if message.message.len() > MAX_EXACT_PERSONAL_MESSAGE_BYTES {
                return Err(ProtocolError::at(
                    ProtocolErrorKind::BoundsExceeded,
                    ErrorField::Payload,
                ));
            }
            fields.push(trusted_field(
                FieldSemantic::OperationKind,
                OperationKind::PersonalMessage.value(),
            )?);
            fields.push(trusted_field(
                FieldSemantic::PersonalMessageBytes,
                fixed_hex(message.message.as_slice()),
            )?);
            fields.push(trusted_field(
                FieldSemantic::PersonalMessageWarning,
                "A personal signature can be reused by protocols; approve only exact bytes you understand.",
            )?);
            high_risk = true;
        }
        CanonicalOperation::TypedDataV4(_) => {
            return Err(ProtocolError::at(
                ProtocolErrorKind::ProtocolInvalid,
                ErrorField::TypedDataDomain,
            ));
        }
    }

    match context.simulation {
        SimulationProvenance::NotPerformed => {
            fields.push(trusted_field(
                FieldSemantic::SimulationStatus,
                SimulationStatus::NotPerformed.value(),
            )?);
            fields.push(trusted_field(
                FieldSemantic::NoSimulationWarning,
                "No transaction simulation was performed.",
            )?);
            high_risk = true;
        }
        SimulationProvenance::Performed {
            engine,
            result_digest,
            input_digest,
        } => {
            fields.push(trusted_field(
                FieldSemantic::SimulationStatus,
                SimulationStatus::Performed.value(),
            )?);
            fields.push(trusted_field(
                FieldSemantic::SimulationEngine,
                simulation_engine(engine),
            )?);
            fields.push(trusted_field(
                FieldSemantic::SimulationResultDigest,
                result_digest.to_fixed_hex(),
            )?);
            fields.push(trusted_field(
                FieldSemantic::SimulationInputDigest,
                input_digest.to_fixed_hex(),
            )?);
        }
    }

    if context.validity.disposition(ReleaseChannel::PrivateCanary)
        == ProtocolDisposition::WarnAndHold
    {
        fields.push(trusted_field(
            FieldSemantic::ProtocolCoverageWarning,
            "Protocol or finality rule coverage is incomplete; private-canary use only.",
        )?);
        high_risk = true;
    }
    ApprovalDisplay::new(
        if high_risk {
            RiskLevel::High
        } else {
            RiskLevel::Standard
        },
        fields,
    )
    .map_err(|_| ProtocolError::at(ProtocolErrorKind::BoundsExceeded, ErrorField::Approval))
}

fn checked_fee(
    gas_limit: U256,
    fee_per_gas: U256,
    error_field: ErrorField,
) -> Result<U256, ProtocolError> {
    gas_limit
        .checked_mul(fee_per_gas)
        .ok_or_else(|| ProtocolError::at(ProtocolErrorKind::InvalidNumericInvariant, error_field))
}

#[allow(clippy::too_many_arguments)]
fn transaction_display_fields(
    fields: &mut Vec<DisplayField>,
    nonce: U256,
    target: TransactionTarget,
    value: U256,
    gas_limit: U256,
    maximum_fee: U256,
    data: &[u8],
    envelope: u8,
    access_list: Option<&[wallet_model::AccessListEntry]>,
    high_risk: &mut bool,
) -> Result<(), ProtocolError> {
    fields.push(trusted_field(
        FieldSemantic::EnvelopeType,
        envelope.to_string(),
    )?);
    fields.push(trusted_field(
        FieldSemantic::Nonce,
        nonce.to_canonical_quantity(),
    )?);
    fields.push(trusted_field(
        FieldSemantic::Target,
        display_target(target),
    )?);
    fields.push(trusted_field(
        FieldSemantic::NativeValue,
        value.to_canonical_quantity(),
    )?);
    fields.push(trusted_field(
        FieldSemantic::GasLimit,
        gas_limit.to_canonical_quantity(),
    )?);
    fields.push(trusted_field(
        FieldSemantic::MaximumNetworkFee,
        maximum_fee.to_canonical_quantity(),
    )?);
    if data.len() > MAX_EXACT_DISPLAY_PAYLOAD_BYTES {
        return Err(ProtocolError::at(
            ProtocolErrorKind::BoundsExceeded,
            ErrorField::Payload,
        ));
    }
    fields.push(trusted_field(FieldSemantic::Calldata, fixed_hex(data))?);
    fields.push(trusted_field(
        FieldSemantic::CalldataKeccak256,
        keccak(data).to_fixed_hex(),
    )?);
    if !data.is_empty() {
        fields.push(trusted_field(
            FieldSemantic::UnknownCalldataWarning,
            "Calldata semantics are unrecognized; verify the exact bytes before approval.",
        )?);
        *high_risk = true;
    }
    if let Some(entries) = access_list {
        fields.push(trusted_field(
            FieldSemantic::AccessList,
            display_access_list(entries),
        )?);
    }
    Ok(())
}

fn trusted_field(
    semantic: FieldSemantic,
    value: impl Into<String>,
) -> Result<DisplayField, ProtocolError> {
    DisplayField::new(semantic, value, semantic != FieldSemantic::SimulationEngine)
        .map_err(|_| ProtocolError::at(ProtocolErrorKind::BoundsExceeded, ErrorField::Approval))
}

const fn simulation_engine(engine: SimulationEngine) -> &'static str {
    match engine {
        SimulationEngine::LocalEvm => "Deterministic local EVM",
        SimulationEngine::RpcTrace => "RPC trace with bound provenance",
    }
}

fn display_access_list(entries: &[wallet_model::AccessListEntry]) -> String {
    let mut output = String::from("[");
    for (entry_index, entry) in entries.iter().enumerate() {
        if entry_index != 0 {
            output.push(',');
        }
        output.push_str("{\"address\":\"");
        output.push_str(&eip55(entry.address()));
        output.push_str("\",\"storageKeys\":[");
        for (key_index, key) in entry.storage_keys().iter().enumerate() {
            if key_index != 0 {
                output.push(',');
            }
            output.push('"');
            output.push_str(&key.to_fixed_hex());
            output.push('"');
        }
        output.push_str("]}");
    }
    output.push(']');
    output
}

fn display_target(target: TransactionTarget) -> String {
    match target {
        TransactionTarget::Create => "Contract creation".to_owned(),
        TransactionTarget::Call(address) => eip55(address),
    }
}

fn chain_genesis(definition: &ChainDefinition) -> Result<String, ProtocolError> {
    match definition.identity {
        chain_registry::IdentityFingerprint::PinnedGenesis(hash) => {
            Ok(Hash32::new(hash.into_bytes()).to_fixed_hex())
        }
        chain_registry::IdentityFingerprint::Missing { .. } => {
            Err(ProtocolError::new(ProtocolErrorKind::ProtocolInvalid))
        }
    }
}

fn fixed_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2).saturating_add(2));
    output.push_str("0x");
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn eip55(address: Address20) -> String {
    let lower = fixed_hex(address.as_bytes());
    let digits = &lower[2..];
    let digest = Keccak256::digest(digits.as_bytes());
    let mut output = String::with_capacity(42);
    output.push_str("0x");
    for (index, byte) in digits.bytes().enumerate() {
        let nibble = if index % 2 == 0 {
            digest[index / 2] >> 4
        } else {
            digest[index / 2] & 0x0f
        };
        output.push(if byte.is_ascii_alphabetic() && nibble >= 8 {
            char::from(byte.to_ascii_uppercase())
        } else {
            char::from(byte)
        });
    }
    output
}

fn keccak(bytes: &[u8]) -> Hash32 {
    let digest = Keccak256::digest(bytes);
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    Hash32::new(output)
}

fn registry_digest(definition: &ChainDefinition) -> Hash32 {
    let mut digest = Sha256::new();
    hash_text(&mut digest, "your-wallet/builtin-chain-registry/v1");
    hash_text(&mut digest, definition.slug);
    hash_text(&mut digest, definition.display_name);
    digest.update(definition.chain_id.to_be_bytes());
    digest.update([
        network_tag(definition.network_kind),
        adapter_tag(definition.adapter),
    ]);
    digest.update([definition.native_currency.decimals]);
    hash_text(&mut digest, definition.native_currency.name);
    hash_text(&mut digest, definition.native_currency.symbol);
    digest.update(definition.review.reviewed_at_unix.to_be_bytes());
    digest.update(definition.review.expires_at_unix.to_be_bytes());
    for envelope in [
        TransactionEnvelope::LegacyEip155,
        TransactionEnvelope::AccessListEip2930,
        TransactionEnvelope::DynamicFeeEip1559,
    ] {
        digest.update([u8::from(
            definition.transaction_envelopes.contains(envelope),
        )]);
    }
    digest.update(ruleset_digest(definition).as_bytes());
    for source in definition.sources {
        hash_text(&mut digest, source.title);
        hash_text(&mut digest, source.url);
        digest.update([source_claim_tag(source.claim)]);
    }
    finalize_sha256(digest)
}

fn ruleset_digest(definition: &ChainDefinition) -> Hash32 {
    let mut digest = Sha256::new();
    hash_text(&mut digest, "your-wallet/builtin-chain-rules/v1");
    hash_text(&mut digest, definition.slug);
    digest.update([adapter_tag(definition.adapter)]);
    hash_rule_coverage(&mut digest, definition.rules);
    match definition.finality.model {
        FinalityModel::EthereumRpcTags => digest.update([1]),
        FinalityModel::AdapterSpecific => digest.update([2]),
        FinalityModel::OptimisticRollup {
            parent_chain_id,
            stack,
        } => {
            digest.update([3]);
            digest.update(parent_chain_id.to_be_bytes());
            digest.update([match stack {
                chain_registry::RollupStack::OpStack => 1,
                chain_registry::RollupStack::ArbitrumNitro => 2,
            }]);
        }
        FinalityModel::NoClaim => digest.update([4]),
    }
    hash_rule_coverage(&mut digest, definition.finality.coverage);
    finalize_sha256(digest)
}

fn hash_rule_coverage(digest: &mut Sha256, coverage: RuleCoverage) {
    match coverage {
        RuleCoverage::Verified { revision } => {
            digest.update([1]);
            hash_text(digest, revision);
        }
        RuleCoverage::Unknown { reason } => {
            digest.update([2]);
            hash_text(digest, reason);
        }
    }
}

fn hash_text(digest: &mut Sha256, value: &str) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value.as_bytes());
}

fn finalize_sha256(digest: Sha256) -> Hash32 {
    let bytes = digest.finalize();
    let mut output = [0_u8; 32];
    output.copy_from_slice(&bytes);
    Hash32::new(output)
}

const fn adapter_tag(adapter: Adapter) -> u8 {
    match adapter {
        Adapter::EthereumPoS => 1,
        Adapter::BscParlia => 2,
        Adapter::PolygonPoS => 3,
        Adapter::AvalancheC => 4,
        Adapter::OpStack => 5,
        Adapter::ArbitrumNitro => 6,
        Adapter::GenericEvm155 => 7,
    }
}

const fn network_tag(kind: NetworkKind) -> u8 {
    match kind {
        NetworkKind::Mainnet => 1,
        NetworkKind::Testnet => 2,
    }
}

const fn source_claim_tag(claim: SourceClaim) -> u8 {
    match claim {
        SourceClaim::ChainIdAndLifecycle => 1,
        SourceClaim::GenesisIdentity => 2,
        SourceClaim::ProtocolModel => 3,
    }
}

#[cfg(test)]
mod tests {
    use approval_wire::FieldSemantic;
    use chain_registry::{
        ChainId, EvidenceError, IdentityFingerprint, Observation, assess_builtin_chain, chain_by_id,
    };
    use wallet_model::{
        ActivationNonce, Address20, BrowserContext, BrowserFamily, BrowserOrigin,
        BrowserProvenance, ChannelNonce, DocumentId, DocumentLifecycle, ExtensionId, Hash32,
        NonceLeaseId, ProfileInstallId, RequestId, SessionId, SimulationProvenance,
        TransactionTarget, U256, UntrustedAccessListEntry, UntrustedTransaction,
    };

    use super::{
        ApprovalDecision, ApprovalNonce, ApprovalResponse, AuthorizationOperation,
        AuthorizationRequest, PreparedAuthorization, ReleaseChannel,
        prepare_authorization_with_policy,
    };
    use crate::{CandidateId, NonceCandidate, NonceLedger};

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

    fn evidence() -> Result<chain_registry::BuiltInChainEvidence, EvidenceError> {
        let chain_id = ChainId::from_u64(1);
        let definition = chain_by_id(chain_id).ok_or(EvidenceError::UnknownChain)?;
        let genesis = match definition.identity {
            IdentityFingerprint::PinnedGenesis(value) => value,
            IdentityFingerprint::Missing { .. } => return Err(EvidenceError::MissingIdentity),
        };
        assess_builtin_chain(
            chain_id,
            Observation {
                chain_id,
                genesis_block_hash: Some(genesis),
            },
        )
    }

    fn browser() -> Result<BrowserContext, Box<dyn std::error::Error>> {
        let origin = BrowserOrigin::new("https://example.test")?;
        Ok(BrowserContext {
            browser_family: BrowserFamily::Chrome,
            profile_install_id: ProfileInstallId::new([1; 32]),
            extension_id: ExtensionId::new("abcdefghijklmnopabcdefghijklmnop")?,
            tab_id: 1,
            frame_id: 0,
            document_id: DocumentId::new("document")?,
            activation_nonce: ActivationNonce::new([2; 32]),
            top_origin: origin.clone(),
            frame_origin: origin,
            document_lifecycle: DocumentLifecycle::Active,
            channel_nonce: ChannelNonce::new([3; 32]),
            provenance: BrowserProvenance::BrowserReportedUnverified,
            session_id: SessionId::new([4; 32]),
            sequence: 1,
            deadline_ms: u64::MAX,
            request_id: RequestId::new([5; 16]),
        })
    }

    fn request(
        value: u64,
    ) -> Result<(AuthorizationRequest, super::NonceLeaseBinding), Box<dyn std::error::Error>> {
        let chain_evidence = evidence()?;
        let chain = super::chain_identity(chain_evidence)?;
        let lease_id = NonceLeaseId::new([6; 16]);
        let mut ledger = NonceLedger::new();
        ledger.reserve(NonceCandidate::reserve(
            Address20::new([0x22; 20]),
            chain,
            U256::from_u64(7),
            lease_id,
            CandidateId(Hash32::new([0x44; 32])),
        ))?;
        let lease = ledger
            .issue_lease(
                Address20::new([0x22; 20]),
                chain,
                U256::from_u64(7),
                lease_id,
            )?
            .into_binding();
        Ok((
            AuthorizationRequest {
                operation: AuthorizationOperation::Transaction(UntrustedTransaction {
                    envelope_type: Some(2),
                    chain_id: Some(U256::from_u64(1)),
                    nonce: Some(U256::from_u64(7)),
                    gas_limit: Some(U256::from_u64(21_000)),
                    gas_price: None,
                    max_priority_fee_per_gas: Some(U256::from_u64(1)),
                    max_fee_per_gas: Some(U256::from_u64(2)),
                    target: Some(TransactionTarget::Call(Address20::new([0x11; 20]))),
                    value: Some(U256::from_u64(value)),
                    data: Vec::new(),
                    access_list: Some(Vec::new()),
                }),
                account: Address20::new([0x22; 20]),
                chain_evidence,
                nonce_lease: None,
                browser: browser()?,
                simulation: SimulationProvenance::NotPerformed,
                rpc_observations_digest: Hash32::new([7; 32]),
            },
            lease,
        ))
    }

    #[test]
    fn authorization_debug_redacts_request_and_approval_bindings()
    -> Result<(), Box<dyn std::error::Error>> {
        let (request, lease) = request(54_321)?;
        let response = ApprovalResponse {
            decision: ApprovalDecision::Approve,
            approval_digest: Hash32::new([0x7b; 32]),
            nonce: ApprovalNonce::new([0x7c; 32]),
        };

        let rendered = format!("{request:?} {lease:?} {response:?}");
        assert!(rendered.contains("AuthorizationOperation::Transaction"));
        assert!(rendered.contains("Approve"));
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("example.test"));
        assert!(!rendered.contains("212, 49"));
        assert!(!rendered.contains("34, 34, 34"));
        assert!(!rendered.contains("123, 123, 123"));
        assert!(!rendered.contains("124, 124, 124"));
        Ok(())
    }

    #[test]
    fn prepared_authorization_is_move_only() {
        let _ = <PreparedAuthorization as AmbiguousIfClone<_>>::marker;
        let _ = <PreparedAuthorization as AmbiguousIfCopy<_>>::marker;
    }

    #[test]
    fn exact_operation_change_changes_derived_digest() -> Result<(), Box<dyn std::error::Error>> {
        let (first_request, first_lease) = request(1)?;
        let first = prepare_authorization_with_policy(
            first_request,
            Some(first_lease),
            ApprovalNonce::new([8; 32]),
            1_000,
            ReleaseChannel::PrivateCanary,
        )?;
        let (second_request, second_lease) = request(2)?;
        let second = prepare_authorization_with_policy(
            second_request,
            Some(second_lease),
            ApprovalNonce::new([8; 32]),
            1_000,
            ReleaseChannel::PrivateCanary,
        )?;
        assert_ne!(
            first.display().canonical_bytes(),
            second.display().canonical_bytes()
        );
        assert_eq!(
            first
                .display()
                .field(FieldSemantic::NativeValue)
                .map(approval_wire::DisplayField::value),
            Some("0x1")
        );
        assert_eq!(
            second
                .display()
                .field(FieldSemantic::NativeValue)
                .map(approval_wire::DisplayField::value),
            Some("0x2")
        );
        assert_ne!(first.approval_digest(), second.approval_digest());
        assert!(first.remaining_milliseconds()? > 0);
        Ok(())
    }

    #[test]
    fn only_matching_one_shot_response_produces_capability()
    -> Result<(), Box<dyn std::error::Error>> {
        let (request, lease) = request(1)?;
        let prepared = prepare_authorization_with_policy(
            request,
            Some(lease),
            ApprovalNonce::new([8; 32]),
            1_000,
            ReleaseChannel::PrivateCanary,
        )?;
        let response = ApprovalResponse {
            decision: ApprovalDecision::Approve,
            approval_digest: prepared.approval_digest(),
            nonce: prepared.approval_nonce(),
        };
        let authorized = prepared.authorize_inner(response)?;
        assert_eq!(authorized.account(), Address20::new([0x22; 20]));
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn every_supported_operation_projects_exact_semantic_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut legacy_request, legacy_lease) = request(3)?;
        legacy_request.operation = AuthorizationOperation::Transaction(UntrustedTransaction {
            envelope_type: Some(0),
            chain_id: Some(U256::from_u64(1)),
            nonce: Some(U256::from_u64(7)),
            gas_limit: Some(U256::from_u64(21_000)),
            gas_price: Some(U256::from_u64(4)),
            max_priority_fee_per_gas: None,
            max_fee_per_gas: None,
            target: Some(TransactionTarget::Call(Address20::new([0x11; 20]))),
            value: Some(U256::from_u64(3)),
            data: vec![0xab, 0xcd],
            access_list: None,
        });
        let legacy = prepare_authorization_with_policy(
            legacy_request,
            Some(legacy_lease),
            ApprovalNonce::new([8; 32]),
            1_000,
            ReleaseChannel::PrivateCanary,
        )?;
        assert_fields(
            legacy.display(),
            &[
                (FieldSemantic::OperationKind, "Legacy EIP-155 transaction"),
                (FieldSemantic::EnvelopeType, "0"),
                (FieldSemantic::Nonce, "0x7"),
                (FieldSemantic::NativeValue, "0x3"),
                (FieldSemantic::GasLimit, "0x5208"),
                (FieldSemantic::GasPrice, "0x4"),
                (FieldSemantic::MaximumNetworkFee, "0x14820"),
                (FieldSemantic::Calldata, "0xabcd"),
            ],
        );
        assert!(
            legacy
                .display()
                .field(FieldSemantic::CalldataKeccak256)
                .is_some()
        );
        assert!(
            legacy
                .display()
                .field(FieldSemantic::UnknownCalldataWarning)
                .is_some()
        );

        let (mut type_one_request, type_one_lease) = request(4)?;
        type_one_request.operation = AuthorizationOperation::Transaction(UntrustedTransaction {
            envelope_type: Some(1),
            chain_id: Some(U256::from_u64(1)),
            nonce: Some(U256::from_u64(7)),
            gas_limit: Some(U256::from_u64(30_000)),
            gas_price: Some(U256::from_u64(5)),
            max_priority_fee_per_gas: None,
            max_fee_per_gas: None,
            target: Some(TransactionTarget::Create),
            value: Some(U256::from_u64(4)),
            data: Vec::new(),
            access_list: Some(vec![UntrustedAccessListEntry {
                address: Address20::new([0x33; 20]),
                storage_keys: vec![Hash32::new([0x44; 32])],
            }]),
        });
        let type_one = prepare_authorization_with_policy(
            type_one_request,
            Some(type_one_lease),
            ApprovalNonce::new([8; 32]),
            1_000,
            ReleaseChannel::PrivateCanary,
        )?;
        assert_fields(
            type_one.display(),
            &[
                (
                    FieldSemantic::OperationKind,
                    "EIP-2930 access-list transaction",
                ),
                (FieldSemantic::EnvelopeType, "1"),
                (FieldSemantic::Target, "Contract creation"),
                (FieldSemantic::GasPrice, "0x5"),
                (FieldSemantic::MaximumNetworkFee, "0x249f0"),
                (FieldSemantic::Calldata, "0x"),
            ],
        );
        let access_list = type_one
            .display()
            .field(FieldSemantic::AccessList)
            .map(approval_wire::DisplayField::value)
            .unwrap_or_default();
        assert!(access_list.contains("0x3333333333333333333333333333333333333333"));
        assert!(
            access_list
                .contains("0x4444444444444444444444444444444444444444444444444444444444444444")
        );

        let (type_two_request, type_two_lease) = request(5)?;
        let type_two = prepare_authorization_with_policy(
            type_two_request,
            Some(type_two_lease),
            ApprovalNonce::new([8; 32]),
            1_000,
            ReleaseChannel::PrivateCanary,
        )?;
        assert_fields(
            type_two.display(),
            &[
                (
                    FieldSemantic::OperationKind,
                    "EIP-1559 dynamic-fee transaction",
                ),
                (FieldSemantic::EnvelopeType, "2"),
                (FieldSemantic::MaxPriorityFeePerGas, "0x1"),
                (FieldSemantic::MaxFeePerGas, "0x2"),
                (FieldSemantic::MaximumNetworkFee, "0xa410"),
                (FieldSemantic::AccessList, "[]"),
            ],
        );

        let personal_request = AuthorizationRequest {
            operation: AuthorizationOperation::PersonalMessage(vec![0, 1, 0xfe, 0xff]),
            account: Address20::new([0x22; 20]),
            chain_evidence: evidence()?,
            nonce_lease: None,
            browser: browser()?,
            simulation: SimulationProvenance::NotPerformed,
            rpc_observations_digest: Hash32::new([7; 32]),
        };
        let personal = prepare_authorization_with_policy(
            personal_request,
            None,
            ApprovalNonce::new([8; 32]),
            1_000,
            ReleaseChannel::PrivateCanary,
        )?;
        assert_fields(
            personal.display(),
            &[
                (FieldSemantic::OperationKind, "EIP-191 personal message"),
                (FieldSemantic::PersonalMessageBytes, "0x0001feff"),
            ],
        );
        assert!(
            personal
                .display()
                .field(FieldSemantic::PersonalMessageWarning)
                .is_some()
        );
        Ok(())
    }

    #[test]
    fn typed_data_remains_denied_until_exact_structured_ui_exists()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = br#"{
          "types": {
            "EIP712Domain": [
              {"name":"chainId","type":"uint256"},
              {"name":"verifyingContract","type":"address"}
            ],
            "Message": [{"name":"contents","type":"string"}]
          },
          "primaryType":"Message",
          "domain":{"chainId":1,"verifyingContract":"0x1111111111111111111111111111111111111111"},
          "message":{"contents":"hello"}
        }"#;
        let typed = wallet_eip712::validate_typed_data_v4(source, U256::from_u64(1))?;
        let request = AuthorizationRequest {
            operation: AuthorizationOperation::TypedDataV4(typed),
            account: Address20::new([0x22; 20]),
            chain_evidence: evidence()?,
            nonce_lease: None,
            browser: browser()?,
            simulation: SimulationProvenance::NotPerformed,
            rpc_observations_digest: Hash32::new([7; 32]),
        };
        assert!(
            prepare_authorization_with_policy(
                request,
                None,
                ApprovalNonce::new([8; 32]),
                1_000,
                ReleaseChannel::PrivateCanary,
            )
            .is_err()
        );
        Ok(())
    }

    fn assert_fields(display: &approval_wire::ApprovalDisplay, expected: &[(FieldSemantic, &str)]) {
        for (semantic, value) in expected {
            assert_eq!(
                display
                    .field(*semantic)
                    .map(approval_wire::DisplayField::value),
                Some(*value)
            );
        }
    }
}
