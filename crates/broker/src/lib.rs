//! Untrusted-client broker boundary.
//!
//! The broker owns public permissions, RPC policy and pending request routing.
//! It has no vault or secret-core dependency and cannot issue an unbound sign.

mod params;
mod transport;

#[cfg(any(test, all(feature = "ipc-contract-test-hook", debug_assertions)))]
pub mod ipc;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chain_registry::{ChainDefinition, Observation, ReleaseGate, release_signing_gate};
use serde_json::Value;
use thiserror::Error;
use wallet_model::{
    ActivationNonce, Address20, BrowserContext, BrowserOrigin, ChannelNonce, DocumentId,
    ExtensionId, ProfileInstallId, SessionId, U256,
};

/// Hard cap shared with Native Messaging in either direction.
pub const MAX_PUBLIC_MESSAGE_BYTES: usize = 1_048_576;
/// Maximum request identifiers retained for replay defense in one session.
pub const MAX_TRACKED_REQUESTS_PER_SESSION: usize = 4_096;
/// Maximum requests concurrently pending in one session.
pub const MAX_PENDING_REQUESTS: usize = 256;
/// Maximum concurrent requests from one profile/extension/origin.
pub const MAX_PENDING_PER_ORIGIN: usize = 64;
/// Maximum concurrent requests bound to one browser document.
pub const MAX_PENDING_PER_DOCUMENT: usize = 32;
/// Maximum origins represented by pending requests in one session.
pub const MAX_PENDING_ORIGINS: usize = 64;
/// Maximum documents represented by pending requests in one session.
pub const MAX_PENDING_DOCUMENTS: usize = 128;
/// Maximum persistent permission grants.
pub const MAX_PERMISSION_GRANTS: usize = 1_024;
/// Maximum permission grants for one profile/extension/origin.
pub const MAX_PERMISSION_GRANTS_PER_ORIGIN: usize = 64;
/// Maximum origins represented in the permission store.
pub const MAX_PERMISSION_ORIGINS: usize = 256;

pub use transport::{
    AuthorizedDispatch, BrokerTarget, TransportBroker, TransportCancellation,
    TransportCancellationOutcome, TransportRequest,
};

/// Route asserted by the extension and independently recomputed by the broker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderRoute {
    /// Locally handled permission or provider-state operation.
    Permission,
    /// Operation that may enter the approval/signing pipeline.
    Signing,
    /// Read-only operation that may reach the configured RPC endpoint.
    Read,
}

impl ProviderRoute {
    /// Parse the exact lowercase version-1 route label.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "permission" => Some(Self::Permission),
            "signing" => Some(Self::Signing),
            "read" => Some(Self::Read),
            _ => None,
        }
    }
}

/// Exact dApp methods accepted by both the extension and v1 broker firewall.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProviderMethod {
    /// EIP-1102 connection prompt.
    RequestAccounts,
    /// Return only accounts connected to this site.
    Accounts,
    /// Current chain identifier.
    ChainId,
    /// Legacy decimal network version.
    NetVersion,
    /// Current block number.
    BlockNumber,
    /// Read-only account balance.
    GetBalance,
    /// Read-only bytecode query.
    GetCode,
    /// Read-only storage slot query.
    GetStorageAt,
    /// Read-only nonce observation.
    GetTransactionCount,
    /// Read-only call.
    Call,
    /// Read-only gas estimate.
    EstimateGas,
    /// Read-only gas price.
    GasPrice,
    /// Read-only fee history.
    FeeHistory,
    /// Read-only priority-fee estimate.
    MaxPriorityFeePerGas,
    /// Read-only block query.
    GetBlockByHash,
    /// Read-only block query.
    GetBlockByNumber,
    /// Read-only transaction query.
    GetTransactionByHash,
    /// Read-only receipt query.
    GetTransactionReceipt,
    /// Bounded log query.
    GetLogs,
    /// Fresh transaction approval and internal broadcast.
    SendTransaction,
    /// EIP-191 personal signature.
    PersonalSign,
    /// EIP-712 v4 typed signature.
    SignTypedDataV4,
    /// User-mediated network metadata proposal.
    AddEthereumChain,
    /// User-mediated active-chain change.
    SwitchEthereumChain,
    /// User-mediated ERC-20 watch request.
    WatchAsset,
    /// Return actual method capabilities.
    GetCapabilities,
    /// Request site permissions.
    RequestPermissions,
    /// Return site permissions.
    GetPermissions,
}

impl ProviderMethod {
    /// Parse an exact method name. Unknown and dangerous methods never reach RPC.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "eth_requestAccounts" => Some(Self::RequestAccounts),
            "eth_accounts" => Some(Self::Accounts),
            "eth_chainId" => Some(Self::ChainId),
            "net_version" => Some(Self::NetVersion),
            "eth_blockNumber" => Some(Self::BlockNumber),
            "eth_getBalance" => Some(Self::GetBalance),
            "eth_getCode" => Some(Self::GetCode),
            "eth_getStorageAt" => Some(Self::GetStorageAt),
            "eth_getTransactionCount" => Some(Self::GetTransactionCount),
            "eth_call" => Some(Self::Call),
            "eth_estimateGas" => Some(Self::EstimateGas),
            "eth_gasPrice" => Some(Self::GasPrice),
            "eth_feeHistory" => Some(Self::FeeHistory),
            "eth_maxPriorityFeePerGas" => Some(Self::MaxPriorityFeePerGas),
            "eth_getBlockByHash" => Some(Self::GetBlockByHash),
            "eth_getBlockByNumber" => Some(Self::GetBlockByNumber),
            "eth_getTransactionByHash" => Some(Self::GetTransactionByHash),
            "eth_getTransactionReceipt" => Some(Self::GetTransactionReceipt),
            "eth_getLogs" => Some(Self::GetLogs),
            "eth_sendTransaction" => Some(Self::SendTransaction),
            "personal_sign" => Some(Self::PersonalSign),
            "eth_signTypedData_v4" => Some(Self::SignTypedDataV4),
            "wallet_addEthereumChain" => Some(Self::AddEthereumChain),
            "wallet_switchEthereumChain" => Some(Self::SwitchEthereumChain),
            "wallet_watchAsset" => Some(Self::WatchAsset),
            "wallet_getCapabilities" => Some(Self::GetCapabilities),
            "wallet_requestPermissions" => Some(Self::RequestPermissions),
            "wallet_getPermissions" => Some(Self::GetPermissions),
            _ => None,
        }
    }

    /// Whether this method requires a fresh native authorization every time.
    #[must_use]
    pub const fn requires_fresh_approval(self) -> bool {
        matches!(
            self,
            Self::RequestAccounts
                | Self::SendTransaction
                | Self::PersonalSign
                | Self::SignTypedDataV4
                | Self::AddEthereumChain
                | Self::SwitchEthereumChain
                | Self::WatchAsset
                | Self::RequestPermissions
        )
    }

    /// Whether the provider may send this exact method to an RPC read endpoint.
    #[must_use]
    pub const fn is_read_only_rpc(self) -> bool {
        matches!(
            self,
            Self::BlockNumber
                | Self::GetBalance
                | Self::GetCode
                | Self::GetStorageAt
                | Self::GetTransactionCount
                | Self::Call
                | Self::EstimateGas
                | Self::GasPrice
                | Self::FeeHistory
                | Self::MaxPriorityFeePerGas
                | Self::GetBlockByHash
                | Self::GetBlockByNumber
                | Self::GetTransactionByHash
                | Self::GetTransactionReceipt
                | Self::GetLogs
        )
    }

    /// Return the only extension route allowed for this method.
    #[must_use]
    pub const fn route(self) -> ProviderRoute {
        if self.is_read_only_rpc() {
            ProviderRoute::Read
        } else if matches!(
            self,
            Self::SendTransaction | Self::PersonalSign | Self::SignTypedDataV4
        ) {
            ProviderRoute::Signing
        } else {
            ProviderRoute::Permission
        }
    }
}

/// Stable public-boundary failures.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum BrokerError {
    /// Message or a public collection exceeded a wire-data bound.
    #[error("LimitExceeded")]
    LimitExceeded,
    /// A bounded in-memory state table cannot safely accept another entry.
    #[error("StateCapacityExceeded")]
    StateCapacityExceeded,
    /// Exact method is absent from the firewall.
    #[error("UnsupportedMethod")]
    UnsupportedMethod,
    /// Site/account/chain permission is absent.
    #[error("Unauthorized")]
    Unauthorized,
    /// Browser document/session/lifetime changed.
    #[error("ContextChanged")]
    ContextChanged,
    /// Request identifier or sequence was already consumed.
    #[error("Replay")]
    Replay,
    /// Relative deadline elapsed.
    #[error("DeadlineExceeded")]
    DeadlineExceeded,
    /// Public schema is malformed.
    #[error("Malformed")]
    Malformed,
    /// Signing is disabled until local release evidence is attested.
    #[error("CanaryGateNotAttested")]
    CanaryGateNotAttested,
}

/// Require an explicitly release-eligible chain before any signing request can
/// be forwarded to the private Key Agent channel.
///
/// # Errors
///
/// Returns [`BrokerError::CanaryGateNotAttested`] unless identity, rules,
/// finality, and review freshness are all release eligible.
pub fn require_chain_signing_eligibility(
    chain: &ChainDefinition,
    observation: Observation,
) -> Result<(), BrokerError> {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BrokerError::CanaryGateNotAttested)?
        .as_secs();
    if release_signing_gate(chain, observation, now_unix) == ReleaseGate::Eligible {
        Ok(())
    } else {
        Err(BrokerError::CanaryGateNotAttested)
    }
}

/// Validated browser-owned document and activation lifetime projection.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct BrowserDocumentKey {
    profile_install_id: ProfileInstallId,
    extension_id: ExtensionId,
    tab_id: u64,
    document_id: DocumentId,
    activation_nonce: ActivationNonce,
    origin: BrowserOrigin,
    channel_nonce: ChannelNonce,
    session_id: SessionId,
}

impl fmt::Debug for BrowserDocumentKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserDocumentKey")
            .field("profile_install_id", &"[REDACTED]")
            .field("extension_id", &"[REDACTED]")
            .field("tab_id", &"[REDACTED]")
            .field("document_id", &"[REDACTED]")
            .field("activation_nonce", &"[REDACTED]")
            .field("origin", &"[REDACTED]")
            .field("channel_nonce", &"[REDACTED]")
            .field("session_id", &"[REDACTED]")
            .finish()
    }
}

impl BrowserDocumentKey {
    /// Derives a document key only from a fully validated browser context.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Malformed`] if the context is not a top-level,
    /// active Chrome HTTPS context with canonical typed fields.
    pub fn from_context(context: &BrowserContext) -> Result<Self, BrokerError> {
        context.validate().map_err(|_| BrokerError::Malformed)?;
        Ok(Self {
            profile_install_id: context.profile_install_id,
            extension_id: context.extension_id.clone(),
            tab_id: context.tab_id,
            document_id: context.document_id.clone(),
            activation_nonce: context.activation_nonce,
            origin: context.top_origin.clone(),
            channel_nonce: context.channel_nonce,
            session_id: context.session_id,
        })
    }

    /// Returns the exact parsed origin.
    #[must_use]
    pub const fn origin(&self) -> &BrowserOrigin {
        &self.origin
    }

    fn origin_scope(&self) -> OriginScope {
        OriginScope {
            profile_install_id: self.profile_install_id,
            extension_id: self.extension_id.clone(),
            origin: self.origin.clone(),
        }
    }

    fn document_scope(&self) -> DocumentScope {
        DocumentScope {
            origin: self.origin_scope(),
            tab_id: self.tab_id,
            document_id: self.document_id.clone(),
        }
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct OriginScope {
    profile_install_id: ProfileInstallId,
    extension_id: ExtensionId,
    origin: BrowserOrigin,
}

impl fmt::Debug for OriginScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OriginScope")
            .field("profile_install_id", &"[REDACTED]")
            .field("extension_id", &"[REDACTED]")
            .field("origin", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct DocumentScope {
    origin: OriginScope,
    tab_id: u64,
    document_id: DocumentId,
}

impl fmt::Debug for DocumentScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DocumentScope")
            .field("origin", &"[REDACTED]")
            .field("tab_id", &"[REDACTED]")
            .field("document_id", &"[REDACTED]")
            .finish()
    }
}

/// Site permission scope stored only by the broker.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct PermissionKey {
    origin: OriginScope,
    account: Address20,
    chain_id: U256,
}

impl fmt::Debug for PermissionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PermissionKey")
            .field("origin", &"[REDACTED]")
            .field("account", &"[REDACTED]")
            .field("chain_id", &"[REDACTED]")
            .finish()
    }
}

impl PermissionKey {
    /// Derives a permission key from a validated browser context.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Malformed`] for a context not eligible for the
    /// version-1 secure top-level origin policy.
    pub fn from_context(
        context: &BrowserContext,
        account: Address20,
        chain_id: U256,
    ) -> Result<Self, BrokerError> {
        context.validate().map_err(|_| BrokerError::Malformed)?;
        Ok(Self {
            origin: OriginScope {
                profile_install_id: context.profile_install_id,
                extension_id: context.extension_id.clone(),
                origin: context.top_origin.clone(),
            },
            account,
            chain_id,
        })
    }

    /// Returns the exact parsed origin used by this grant.
    #[must_use]
    pub const fn origin(&self) -> &BrowserOrigin {
        &self.origin.origin
    }
}

/// Bounded in-memory permission state.
#[derive(Default)]
pub struct PermissionStore {
    grants: BTreeSet<PermissionKey>,
    per_origin: BTreeMap<OriginScope, usize>,
}

impl fmt::Debug for PermissionStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PermissionStore")
            .field("grants", &"[REDACTED]")
            .field("grant_count", &self.grants.len())
            .field("per_origin", &"[REDACTED]")
            .field("origin_count", &self.per_origin.len())
            .finish()
    }
}

impl PermissionStore {
    /// Adds an exact permission grant, returning `false` for an existing grant.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::StateCapacityExceeded`] before either the global,
    /// per-origin, or distinct-origin bound could be exceeded.
    pub fn grant(&mut self, key: PermissionKey) -> Result<bool, BrokerError> {
        if self.grants.contains(&key) {
            return Ok(false);
        }
        let current_for_origin = self.per_origin.get(&key.origin).copied().unwrap_or(0);
        let is_new_origin = current_for_origin == 0;
        if self.grants.len() >= MAX_PERMISSION_GRANTS
            || current_for_origin >= MAX_PERMISSION_GRANTS_PER_ORIGIN
            || is_new_origin && self.per_origin.len() >= MAX_PERMISSION_ORIGINS
        {
            return Err(BrokerError::StateCapacityExceeded);
        }
        self.per_origin
            .insert(key.origin.clone(), current_for_origin.saturating_add(1));
        self.grants.insert(key);
        Ok(true)
    }

    /// Removes one exact permission grant.
    pub fn revoke(&mut self, key: &PermissionKey) -> bool {
        if !self.grants.remove(key) {
            return false;
        }
        decrement_count(&mut self.per_origin, &key.origin);
        true
    }

    /// Returns whether the exact origin/account/chain grant exists.
    #[must_use]
    pub fn contains(&self, key: &PermissionKey) -> bool {
        self.grants.contains(key)
    }

    /// Returns the number of grants without exposing the backing collection.
    #[must_use]
    pub fn len(&self) -> usize {
        self.grants.len()
    }

    /// Returns whether there are no grants.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }
}

/// One request whose response must remain bound to the same live document.
#[derive(Clone)]
struct PendingRequest {
    document: BrowserDocumentKey,
    deadline: Instant,
    method: ProviderMethod,
    request_sequence: u64,
}

#[derive(Clone)]
struct CompletedRequest {
    session_id: SessionId,
    activation_nonce: ActivationNonce,
    request_sequence: u64,
}

impl fmt::Debug for PendingRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingRequest")
            .field("document", &"[REDACTED]")
            .field("deadline", &"[REDACTED]")
            .field("method", &self.method)
            .field("request_sequence", &"[REDACTED]")
            .finish()
    }
}

/// Complete request admission data bound to one typed browser context.
#[derive(Clone, Copy)]
pub struct Admission<'a> {
    /// Fully parsed and validated by the model layer at admission.
    pub context: &'a BrowserContext,
    /// Exact provider method name.
    pub method_name: &'a str,
    /// Parsed JSON-RPC parameters; the broker applies a method-specific schema.
    pub params: &'a Value,
    /// Bounded relative request lifetime.
    pub relative_deadline: Duration,
}

impl fmt::Debug for Admission<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Admission")
            .field("context", &"[REDACTED]")
            .field("method_name", &self.method_name)
            .field("params", &"[REDACTED]")
            .field("relative_deadline", &"[REDACTED]")
            .finish()
    }
}

/// In-memory session router. Durable grants belong in a separate encrypted/public store.
#[derive(Default)]
pub struct SessionRouter {
    session_id: Option<[u8; 32]>,
    next_sequence: u64,
    pending: BTreeMap<[u8; 16], PendingRequest>,
    completed: BTreeMap<[u8; 16], CompletedRequest>,
    pending_by_origin: BTreeMap<OriginScope, usize>,
    pending_by_document: BTreeMap<DocumentScope, usize>,
}

impl fmt::Debug for SessionRouter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionRouter")
            .field("session_id", &"[REDACTED]")
            .field("next_sequence", &"[REDACTED]")
            .field("pending", &"[REDACTED]")
            .field("pending_count", &self.pending.len())
            .field("completed", &"[REDACTED]")
            .field("completed_count", &self.completed.len())
            .field("pending_by_origin", &"[REDACTED]")
            .field("pending_origin_count", &self.pending_by_origin.len())
            .field("pending_by_document", &"[REDACTED]")
            .field("pending_document_count", &self.pending_by_document.len())
            .finish()
    }
}

impl SessionRouter {
    /// Begin a new extension-worker/native connection and cancel all uncertainty.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Malformed`] rather than accepting the reserved
    /// all-zero session identifier.
    pub fn begin_session(&mut self, session_id: [u8; 32]) -> Result<(), BrokerError> {
        if session_id.iter().all(|byte| *byte == 0) {
            return Err(BrokerError::Malformed);
        }
        self.pending.clear();
        self.completed.clear();
        self.pending_by_origin.clear();
        self.pending_by_document.clear();
        self.session_id = Some(session_id);
        self.next_sequence = 1;
        Ok(())
    }

    /// Admit one exact request once.
    ///
    /// # Errors
    ///
    /// Returns an error for replay, malformed context/parameters, unsupported
    /// method, deadline violations, or any bounded state-table exhaustion.
    pub fn admit(
        &mut self,
        admission: Admission<'_>,
        now: Instant,
    ) -> Result<ProviderMethod, BrokerError> {
        let session_id = *admission.context.session_id.as_bytes();
        let request_id = *admission.context.request_id.as_bytes();
        if request_id.iter().all(|byte| *byte == 0) {
            return Err(BrokerError::Malformed);
        }
        if self.session_id != Some(session_id)
            || admission.context.sequence != self.next_sequence
            || self.completed.contains_key(&request_id)
            || self.pending.contains_key(&request_id)
        {
            return Err(BrokerError::Replay);
        }
        let document = BrowserDocumentKey::from_context(admission.context)?;
        if admission.relative_deadline.is_zero()
            || admission.relative_deadline > Duration::from_mins(2)
            || admission.context.deadline_ms == 0
        {
            return Err(BrokerError::DeadlineExceeded);
        }
        let deadline = now
            .checked_add(admission.relative_deadline)
            .ok_or(BrokerError::DeadlineExceeded)?;
        let method = validate_public_request(admission.method_name, admission.params)?;

        self.ensure_capacity(&document)?;
        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(BrokerError::Replay)?;
        let origin_scope = document.origin_scope();
        let document_scope = document.document_scope();
        increment_count(&mut self.pending_by_origin, origin_scope)?;
        if let Err(error) = increment_count(&mut self.pending_by_document, document_scope) {
            decrement_count(&mut self.pending_by_origin, &document.origin_scope());
            return Err(error);
        }
        self.pending.insert(
            request_id,
            PendingRequest {
                document,
                deadline,
                method,
                request_sequence: admission.context.sequence,
            },
        );
        self.next_sequence = next_sequence;
        Ok(method)
    }

    fn ensure_capacity(&self, document: &BrowserDocumentKey) -> Result<(), BrokerError> {
        let tracked = self
            .pending
            .len()
            .checked_add(self.completed.len())
            .ok_or(BrokerError::StateCapacityExceeded)?;
        let origin_scope = document.origin_scope();
        let document_scope = document.document_scope();
        let per_origin = self
            .pending_by_origin
            .get(&origin_scope)
            .copied()
            .unwrap_or(0);
        let per_document = self
            .pending_by_document
            .get(&document_scope)
            .copied()
            .unwrap_or(0);
        if tracked >= MAX_TRACKED_REQUESTS_PER_SESSION
            || self.pending.len() >= MAX_PENDING_REQUESTS
            || per_origin >= MAX_PENDING_PER_ORIGIN
            || per_document >= MAX_PENDING_PER_DOCUMENT
            || per_origin == 0 && self.pending_by_origin.len() >= MAX_PENDING_ORIGINS
            || per_document == 0 && self.pending_by_document.len() >= MAX_PENDING_DOCUMENTS
        {
            return Err(BrokerError::StateCapacityExceeded);
        }
        Ok(())
    }

    /// Cancel one request. A later backend response will be discarded.
    pub fn cancel(&mut self, request_id: [u8; 16]) {
        if let Some(pending) = self.take_pending(request_id) {
            self.remember_completed(request_id, &pending);
        }
    }

    fn admit_presequenced(
        &mut self,
        admission: Admission<'_>,
        now: Instant,
    ) -> Result<ProviderMethod, BrokerError> {
        let session_id = *admission.context.session_id.as_bytes();
        let request_id = *admission.context.request_id.as_bytes();
        if request_id.iter().all(|byte| *byte == 0) || self.session_id != Some(session_id) {
            return Err(BrokerError::Malformed);
        }
        if self.completed.contains_key(&request_id) || self.pending.contains_key(&request_id) {
            return Err(BrokerError::Replay);
        }
        let document = BrowserDocumentKey::from_context(admission.context)?;
        if admission.relative_deadline.is_zero()
            || admission.relative_deadline > Duration::from_mins(2)
            || admission.context.deadline_ms == 0
        {
            return Err(BrokerError::DeadlineExceeded);
        }
        let deadline = now
            .checked_add(admission.relative_deadline)
            .ok_or(BrokerError::DeadlineExceeded)?;
        let method = validate_public_request(admission.method_name, admission.params)?;

        self.ensure_capacity(&document)?;
        let origin_scope = document.origin_scope();
        let document_scope = document.document_scope();
        increment_count(&mut self.pending_by_origin, origin_scope)?;
        if let Err(error) = increment_count(&mut self.pending_by_document, document_scope) {
            decrement_count(&mut self.pending_by_origin, &document.origin_scope());
            return Err(error);
        }
        self.pending.insert(
            request_id,
            PendingRequest {
                document,
                deadline,
                method,
                request_sequence: admission.context.sequence,
            },
        );
        Ok(method)
    }

    fn cancel_bound(
        &mut self,
        request_id: [u8; 16],
        request_sequence: u64,
        activation_nonce: ActivationNonce,
    ) -> Option<TransportCancellationOutcome> {
        if self.pending.get(&request_id).is_some_and(|pending| {
            self.matches_cancellation(pending, request_sequence, activation_nonce)
        }) {
            self.cancel(request_id);
            return Some(TransportCancellationOutcome::Cancelled);
        }
        self.completed.get(&request_id).and_then(|completed| {
            (completed.activation_nonce == activation_nonce
                && self
                    .session_id
                    .is_some_and(|session| completed.session_id == SessionId::new(session))
                && completed.request_sequence == request_sequence)
                .then_some(TransportCancellationOutcome::AlreadyCompleted)
        })
    }

    #[cfg(any(test, all(feature = "ipc-contract-test-hook", debug_assertions)))]
    fn remember_unavailable(
        &mut self,
        session_id: SessionId,
        activation_nonce: ActivationNonce,
        request_id: [u8; 16],
        request_sequence: u64,
    ) -> Result<(), BrokerError> {
        if request_id.iter().all(|byte| *byte == 0)
            || activation_nonce.as_bytes().iter().all(|byte| *byte == 0)
            || self.session_id != Some(*session_id.as_bytes())
        {
            return Err(BrokerError::Malformed);
        }
        if self.completed.contains_key(&request_id) || self.pending.contains_key(&request_id) {
            return Err(BrokerError::Replay);
        }
        let tracked = self
            .pending
            .len()
            .checked_add(self.completed.len())
            .ok_or(BrokerError::StateCapacityExceeded)?;
        if tracked >= MAX_TRACKED_REQUESTS_PER_SESSION {
            return Err(BrokerError::StateCapacityExceeded);
        }
        self.completed.insert(
            request_id,
            CompletedRequest {
                session_id,
                activation_nonce,
                request_sequence,
            },
        );
        Ok(())
    }

    /// Cancel every request tied to an exact document/activation lifetime.
    pub fn cancel_document(&mut self, document: &BrowserDocumentKey) {
        let identifiers: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(identifier, pending)| {
                (pending.document == *document).then_some(*identifier)
            })
            .collect();
        for identifier in identifiers {
            self.cancel(identifier);
        }
    }

    /// Consume at most one response after a final same-document check.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::ContextChanged`] for an unknown, completed,
    /// expired, or no-longer-current request/document pair.
    pub fn complete(
        &mut self,
        request_id: [u8; 16],
        current_document: &BrowserDocumentKey,
        now: Instant,
    ) -> Result<ProviderMethod, BrokerError> {
        let pending = self
            .take_pending(request_id)
            .ok_or(BrokerError::ContextChanged)?;
        self.remember_completed(request_id, &pending);
        if pending.deadline <= now || pending.document != *current_document {
            return Err(BrokerError::ContextChanged);
        }
        Ok(pending.method)
    }

    fn take_pending(&mut self, request_id: [u8; 16]) -> Option<PendingRequest> {
        let pending = self.pending.remove(&request_id)?;
        decrement_count(
            &mut self.pending_by_origin,
            &pending.document.origin_scope(),
        );
        decrement_count(
            &mut self.pending_by_document,
            &pending.document.document_scope(),
        );
        Some(pending)
    }

    fn matches_cancellation(
        &self,
        pending: &PendingRequest,
        request_sequence: u64,
        activation_nonce: ActivationNonce,
    ) -> bool {
        pending.document.activation_nonce == activation_nonce
            && self
                .session_id
                .is_some_and(|session| pending.document.session_id == SessionId::new(session))
            && pending.request_sequence == request_sequence
    }

    fn remember_completed(&mut self, request_id: [u8; 16], pending: &PendingRequest) {
        self.completed.insert(
            request_id,
            CompletedRequest {
                session_id: pending.document.session_id,
                activation_nonce: pending.document.activation_nonce,
                request_sequence: pending.request_sequence,
            },
        );
    }

    /// Returns the number of currently pending requests.
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

fn increment_count<K: Ord>(counts: &mut BTreeMap<K, usize>, key: K) -> Result<(), BrokerError> {
    let next = counts
        .get(&key)
        .copied()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(BrokerError::StateCapacityExceeded)?;
    counts.insert(key, next);
    Ok(())
}

fn decrement_count<K: Ord>(counts: &mut BTreeMap<K, usize>, key: &K) {
    let remove = if let Some(count) = counts.get_mut(key) {
        *count = count.saturating_sub(1);
        *count == 0
    } else {
        false
    };
    if remove {
        counts.remove(key);
    }
}

/// Reject public raw-broadcast methods and validate exact per-method schemas.
///
/// The size is computed from the locally serialized method and parameter value;
/// no caller-supplied encoded-length claim is trusted.
///
/// # Errors
///
/// Returns a stable error for an unsupported method, malformed/cross-schema
/// parameters, or any wire/aggregate bound violation.
pub fn validate_public_request(
    method: &str,
    params: &Value,
) -> Result<ProviderMethod, BrokerError> {
    params::validate(method, params)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use serde_json::json;
    use wallet_model::{
        ActivationNonce, Address20, BrowserContext, BrowserContextError, BrowserFamily,
        BrowserOrigin, BrowserProvenance, ChannelNonce, DocumentId, DocumentLifecycle, ExtensionId,
        ProfileInstallId, RequestId, SessionId, U256,
    };

    use super::{
        Admission, BrokerError, BrowserDocumentKey, MAX_PENDING_PER_DOCUMENT,
        MAX_PERMISSION_GRANTS_PER_ORIGIN, PermissionKey, PermissionStore, ProviderMethod,
        SessionRouter, validate_public_request,
    };

    fn context(
        sequence: u64,
        request: u8,
        activation: u8,
        origin: &str,
    ) -> Result<BrowserContext, BrowserContextError> {
        Ok(BrowserContext {
            browser_family: BrowserFamily::Chrome,
            profile_install_id: ProfileInstallId::new([1; 32]),
            extension_id: ExtensionId::new("abcdefghijklmnopabcdefghijklmnop")?,
            tab_id: 7,
            frame_id: 0,
            document_id: DocumentId::new("browser-document")?,
            activation_nonce: ActivationNonce::new([activation; 32]),
            top_origin: BrowserOrigin::new(origin)?,
            frame_origin: BrowserOrigin::new(origin)?,
            document_lifecycle: DocumentLifecycle::Active,
            channel_nonce: ChannelNonce::new([2; 32]),
            provenance: BrowserProvenance::BrowserReportedUnverified,
            session_id: SessionId::new([4; 32]),
            sequence,
            deadline_ms: 1_000,
            request_id: RequestId::new([request; 16]),
        })
    }

    fn admit_accounts(
        router: &mut SessionRouter,
        context: &BrowserContext,
        now: Instant,
    ) -> Result<ProviderMethod, BrokerError> {
        router.admit(
            Admission {
                context,
                method_name: "eth_accounts",
                params: &json!([]),
                relative_deadline: Duration::from_secs(30),
            },
            now,
        )
    }

    #[test]
    fn dangerous_and_extension_absent_methods_are_not_in_firewall() {
        for method in [
            "eth_sign",
            "eth_signTransaction",
            "eth_sendRawTransaction",
            "debug_traceTransaction",
            "wallet_sendCalls",
            "wallet_revokePermissions",
        ] {
            assert_eq!(
                validate_public_request(method, &json!([])),
                Err(BrokerError::UnsupportedMethod)
            );
        }
        assert_eq!(
            validate_public_request("eth_blockNumber", &json!([])),
            Ok(ProviderMethod::BlockNumber)
        );
    }

    #[test]
    fn request_accounts_always_requires_fresh_approval() {
        assert!(ProviderMethod::RequestAccounts.requires_fresh_approval());
        assert!(ProviderMethod::RequestPermissions.requires_fresh_approval());
        assert!(!ProviderMethod::Accounts.requires_fresh_approval());
    }

    #[test]
    fn only_exact_read_methods_can_reach_rpc() {
        assert!(
            ProviderMethod::parse("eth_getBalance").is_some_and(ProviderMethod::is_read_only_rpc)
        );
        assert!(
            ProviderMethod::parse("eth_sendTransaction")
                .is_some_and(|method| !method.is_read_only_rpc())
        );
    }

    #[test]
    fn navigation_discards_late_response() -> Result<(), Box<dyn std::error::Error>> {
        let now = Instant::now();
        let mut router = SessionRouter::default();
        router.begin_session([4; 32])?;
        let admitted = context(1, 8, 1, "https://example.invalid")?;
        admit_accounts(&mut router, &admitted, now)?;
        let navigated = context(2, 9, 2, "https://example.invalid")?;
        let navigated_key = BrowserDocumentKey::from_context(&navigated)?;
        assert_eq!(
            router.complete([8; 16], &navigated_key, now),
            Err(BrokerError::ContextChanged)
        );
        let original_key = BrowserDocumentKey::from_context(&admitted)?;
        assert_eq!(
            router.complete([8; 16], &original_key, now),
            Err(BrokerError::ContextChanged)
        );
        Ok(())
    }

    #[test]
    fn worker_restart_cancels_old_session() -> Result<(), Box<dyn std::error::Error>> {
        let now = Instant::now();
        let mut router = SessionRouter::default();
        router.begin_session([4; 32])?;
        let admitted = context(1, 1, 1, "https://example.invalid")?;
        admit_accounts(&mut router, &admitted, now)?;
        router.begin_session([5; 32])?;
        let document = BrowserDocumentKey::from_context(&admitted)?;
        assert_eq!(
            router.complete([1; 16], &document, now),
            Err(BrokerError::ContextChanged)
        );
        Ok(())
    }

    #[test]
    fn zero_session_and_request_identifiers_fail_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let now = Instant::now();
        let mut router = SessionRouter::default();
        assert_eq!(router.begin_session([0; 32]), Err(BrokerError::Malformed));
        router.begin_session([4; 32])?;
        let zero_request = context(1, 0, 1, "https://example.invalid")?;
        assert_eq!(
            admit_accounts(&mut router, &zero_request, now),
            Err(BrokerError::Malformed)
        );
        Ok(())
    }

    #[test]
    fn malformed_origins_cannot_alias_permission_keys() -> Result<(), Box<dyn std::error::Error>> {
        let account = Address20::new([1; 20]);
        let chain = U256::from_u64(1);
        let trusted = PermissionKey::from_context(
            &context(1, 1, 1, "https://example.invalid")?,
            account,
            chain,
        )?;
        let sibling = PermissionKey::from_context(
            &context(1, 1, 1, "https://example.invalid.evil.test")?,
            account,
            chain,
        )?;
        assert_ne!(trusted, sibling);

        for origin in ["https://example.invalid/path", "https://EXAMPLE.invalid"] {
            assert!(context(1, 1, 1, origin).is_err());
        }
        let insecure = context(1, 1, 1, "http://example.invalid")?;
        assert_eq!(
            PermissionKey::from_context(&insecure, account, chain),
            Err(BrokerError::Malformed)
        );
        Ok(())
    }

    #[test]
    fn pending_per_document_bound_fails_closed_and_recovers_after_cancel()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = Instant::now();
        let mut router = SessionRouter::default();
        router.begin_session([4; 32])?;
        for sequence in 1..=MAX_PENDING_PER_DOCUMENT {
            let request = u8::try_from(sequence)?;
            let request_context = context(
                u64::try_from(sequence)?,
                request,
                request,
                "https://example.invalid",
            )?;
            admit_accounts(&mut router, &request_context, now)?;
        }
        let overflow_sequence = MAX_PENDING_PER_DOCUMENT.saturating_add(1);
        let overflow = context(
            u64::try_from(overflow_sequence)?,
            u8::try_from(overflow_sequence)?,
            u8::try_from(overflow_sequence)?,
            "https://example.invalid",
        )?;
        assert_eq!(
            admit_accounts(&mut router, &overflow, now),
            Err(BrokerError::StateCapacityExceeded)
        );
        router.cancel([1; 16]);
        assert_eq!(
            admit_accounts(&mut router, &overflow, now),
            Ok(ProviderMethod::Accounts)
        );
        assert_eq!(router.pending_len(), MAX_PENDING_PER_DOCUMENT);
        Ok(())
    }

    #[test]
    fn pending_per_origin_bound_counts_distinct_documents() -> Result<(), Box<dyn std::error::Error>>
    {
        let now = Instant::now();
        let mut router = SessionRouter::default();
        router.begin_session([4; 32])?;
        for sequence in 1..=super::MAX_PENDING_PER_ORIGIN {
            let request = u8::try_from(sequence)?;
            let mut request_context = context(
                u64::try_from(sequence)?,
                request,
                request,
                "https://example.invalid",
            )?;
            request_context.document_id = DocumentId::new(format!("document-{sequence}"))?;
            admit_accounts(&mut router, &request_context, now)?;
        }
        let overflow_sequence = super::MAX_PENDING_PER_ORIGIN.saturating_add(1);
        let mut overflow = context(
            u64::try_from(overflow_sequence)?,
            u8::try_from(overflow_sequence)?,
            u8::try_from(overflow_sequence)?,
            "https://example.invalid",
        )?;
        overflow.document_id = DocumentId::new("overflow-document")?;
        assert_eq!(
            admit_accounts(&mut router, &overflow, now),
            Err(BrokerError::StateCapacityExceeded)
        );
        Ok(())
    }

    #[test]
    fn permission_store_enforces_per_origin_bound() -> Result<(), Box<dyn std::error::Error>> {
        let request_context = context(1, 1, 1, "https://example.invalid")?;
        let mut store = PermissionStore::default();
        for index in 0..MAX_PERMISSION_GRANTS_PER_ORIGIN {
            let byte = u8::try_from(index)?;
            let key = PermissionKey::from_context(
                &request_context,
                Address20::new([byte; 20]),
                U256::from_u64(1),
            )?;
            assert!(store.grant(key)?);
        }
        let overflow = PermissionKey::from_context(
            &request_context,
            Address20::new([0xff; 20]),
            U256::from_u64(1),
        )?;
        assert_eq!(
            store.grant(overflow.clone()),
            Err(BrokerError::StateCapacityExceeded)
        );
        let first = PermissionKey::from_context(
            &request_context,
            Address20::new([0; 20]),
            U256::from_u64(1),
        )?;
        assert!(store.revoke(&first));
        assert!(store.grant(overflow.clone())?);
        assert!(store.contains(&overflow));
        Ok(())
    }
}
