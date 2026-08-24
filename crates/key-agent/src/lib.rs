//! Isolated signer orchestration.
//!
//! This crate deliberately exposes no raw hash-signing API. Callers must supply
//! an opaque [`wallet_protocol::PreparedAuthorization`] produced from strict
//! validation and internally derived display data. Transaction bytes are
//! decoded and the sender is recovered before any artifact is returned.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

pub mod durable;
/// Fail-closed key-bundle/envelope model; production PCP and anchor adapters are absent.
pub(crate) mod key_material;
/// Fail-closed dispatcher for the bounded offline lifecycle channel.
pub(crate) mod offline_controller;
pub(crate) mod offline_service;
/// Strict binary protocol for the inherited offline lifecycle channel.
pub(crate) mod offline_wire;
pub(crate) mod settings;
pub(crate) mod vault_session;

use std::fmt;

use approval_wire::ApprovalRequest;
use platform_windows::{BoundApprovalTransport, VerifiedApprovalResponse};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, Secp256k1};
use secret_core::{CanonicalSignature, RawPrivateKey, SecretError};
use sha3::{Digest as _, Keccak256};
use thiserror::Error;
use wallet_model::{
    AccessListEntry, Address20, CanonicalOperation, ChainIdentity, CodecError, Hash32,
    LegacyTransaction, NonceLeaseId, TransactionTarget, U256,
};
use wallet_protocol::{AuthorizedOperationRef, PreparedAuthorization, ProtocolError};
use zeroize::Zeroize;

const MAX_SIGNED_TRANSACTION_BYTES: usize = 1_200_000;
const MAX_RLP_DEPTH: usize = 4;

enum SigningPlan {
    Transaction(SigningIntent),
    Message([u8; 32]),
}

/// Opaque one-shot prompt retaining the exact request hash and its bound
/// transport capability across the complete UI interaction. Authorization and
/// transport share one original monotonic expiry, while the wall-clock expiry
/// remains part of the authorization session's external bookkeeping.
/// Authorization never rebuilds a different request after a hold.
/// Its non-clone settings lease binds the authenticated settings generation,
/// phrase revision, exact record digest, exclusive owner, process instance, and
/// a fresh one-time nonce.
#[allow(dead_code)]
pub(crate) struct PreparedApprovalPrompt {
    prepared: PreparedAuthorization,
    transport: BoundApprovalTransport,
    request_hash: [u8; 32],
    settings_lease: settings::LiveSettingsLease,
    settings_binding: [u8; 32],
}

impl fmt::Debug for PreparedApprovalPrompt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedApprovalPrompt([REDACTED REQUEST AND AUTHORIZATION])")
    }
}

/// Prepares the exact shared v2 prompt for the authenticated private approval
/// channel. All field semantics and values were derived by the authorization
/// TCB. The anti-phishing cue and its live epoch are issued only by freshly
/// revalidated Key-Agent protected settings; no caller can inject a string.
#[allow(dead_code)]
pub(crate) fn prepare_approval_prompt<S: settings::SettingsStore>(
    mut prepared: PreparedAuthorization,
    protected_settings: &mut settings::ProtectedLocalSettings<S>,
) -> Result<PreparedApprovalPrompt, SignerError> {
    let material = protected_settings
        .issue_approval_material()
        .map_err(|_| SignerError::Settings)?;
    let (anti_phishing_phrase, settings_lease) = material.into_parts();
    let expires_after_milliseconds = match prepared.remaining_milliseconds() {
        Ok(milliseconds) => milliseconds,
        Err(error) => {
            protected_settings.lock();
            return Err(error.into());
        }
    };
    let request = ApprovalRequest::new(
        *prepared.approval_digest().as_bytes(),
        *prepared.approval_nonce().as_bytes(),
        expires_after_milliseconds,
        anti_phishing_phrase,
        prepared.display().clone(),
    )
    .map_err(|_| {
        protected_settings.lock();
        ProtocolError::new(wallet_protocol::ProtocolErrorKind::BoundsExceeded)
    })?;
    let request_hash = approval_wire::request_hash(&request);
    let transport = match prepared.bind_approval_transport(request) {
        Ok(transport) => transport,
        Err(error) => {
            protected_settings.lock();
            return Err(error.into());
        }
    };
    let settings_binding = settings_lease.bind_request(request_hash);
    Ok(PreparedApprovalPrompt {
        prepared,
        transport,
        request_hash,
        settings_lease,
        settings_binding,
    })
}

/// Errors intentionally safe to map to stable outer codes without raw payloads.
#[derive(Debug, Error)]
pub enum SignerError {
    /// Approval binding, state, or response was invalid.
    #[error("approval rejected by signer policy")]
    Protocol(#[from] ProtocolError),
    /// Protected local settings were stale, unconfirmed, or unavailable.
    #[error("protected local settings rejected signing")]
    Settings,
    /// Canonical transcript encoding failed a hard bound.
    #[error("canonical transcript encoding failed")]
    Codec(#[from] CodecError),
    /// Secret-key operation failed its invariant.
    #[error("cryptographic operation failed")]
    Secret(#[from] SecretError),
    /// User explicitly rejected the request.
    #[error("user rejected approval")]
    UserRejected,
    /// The selected key does not own the bound account.
    #[error("selected key does not match approved account")]
    AccountMismatch,
    /// Durable signed-candidate storage failed. The nonce remains quarantined.
    #[error("signed-candidate journal failed")]
    Journal,
    /// Transaction encoding or post-sign decode was not canonical and exact.
    #[error("signed transaction self-check failed")]
    SignedEncoding,
    /// Public-key recovery did not reproduce the approved sender.
    #[error("signature sender recovery failed")]
    SenderRecovery,
    /// A 256-bit signing field overflowed.
    #[error("transaction numeric invariant failed")]
    NumericOverflow,
    /// A signing operation violated an internal type invariant.
    #[error("signing invariant failed")]
    Invariant,
}

/// Record written and flushed before the private-key operation begins.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SigningIntent {
    /// Exact approval digest.
    pub approval_digest: Hash32,
    /// Full chain fingerprint.
    pub chain: ChainIdentity,
    /// Approved sender.
    pub account: Address20,
    /// Durable reservation identifier.
    pub lease_id: NonceLeaseId,
    /// Exact candidate nonce.
    pub nonce: U256,
}

impl fmt::Debug for SigningIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigningIntent")
            .field("approval_digest", &"[REDACTED]")
            .field("chain", &"[REDACTED]")
            .field("account", &"[REDACTED]")
            .field("lease_id", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .finish()
    }
}

/// Signed candidate that must be encrypted and flushed before return/broadcast.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct SignedTransactionRecord {
    /// Intent that was already durably marked potentially signed.
    intent: SigningIntent,
    /// Locally computed EIP-2718 transaction hash.
    transaction_hash: Hash32,
    /// Exact signed wire bytes. These can spend funds and must not be logged.
    signed_bytes: Vec<u8>,
}

impl fmt::Debug for SignedTransactionRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedTransactionRecord")
            .field("intent", &"[REDACTED]")
            .field("transaction_hash", &"[REDACTED]")
            .field("signed_bytes", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SignedTransactionRecord {
    fn drop(&mut self) {
        self.signed_bytes.zeroize();
    }
}

/// Opaque transaction result released after signing and durable journal ingest.
///
/// Exact wire bytes remain private to the durable journal. They become
/// available only through a consumed `durable::BroadcastLease` after the
/// journal has committed the `Broadcasting` transition.
///
/// ```compile_fail
/// fn leak_bytes(artifact: key_agent::SignedTransactionArtifact) {
///     let _ = artifact.signed_bytes;
/// }
/// ```
#[derive(Eq, PartialEq)]
pub struct SignedTransactionArtifact {
    transaction_hash: Hash32,
    sender: Address20,
}

impl SignedTransactionArtifact {
    /// Locally computed EIP-2718 transaction hash.
    #[must_use]
    pub const fn transaction_hash(&self) -> Hash32 {
        self.transaction_hash
    }

    /// Sender recovered from the exact signature.
    #[must_use]
    pub const fn sender(&self) -> Address20 {
        self.sender
    }
}

impl fmt::Debug for SignedTransactionArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedTransactionArtifact")
            .field("transaction_hash", &"[REDACTED]")
            .field("sender", &"[REDACTED]")
            .field("signed_bytes", &"[JOURNAL OWNED]")
            .finish()
    }
}

/// Artifact released only after approval, journal, decode, and recovery checks.
#[derive(Eq, PartialEq)]
pub enum SignedArtifact {
    /// Fully checked transaction metadata. Signed bytes remain journal-owned.
    Transaction(SignedTransactionArtifact),
    /// Provider-compatible `r || s || v`, where `v` is 27 or 28.
    MessageSignature([u8; 65]),
}

impl fmt::Debug for SignedArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transaction(transaction) => transaction.fmt(formatter),
            Self::MessageSignature(_) => {
                formatter.write_str("SignedArtifact::MessageSignature([REDACTED])")
            }
        }
    }
}

/// Consume a matching one-shot approval and sign exactly its bound operation.
///
/// Transaction intent is flushed before signing and signed bytes are ingested
/// by the concrete durable journal before return. If either journal step fails,
/// no artifact is released. Transaction bytes are never present in the returned
/// artifact and can reach RPC only through a committed broadcast lease.
#[allow(dead_code)]
pub(crate) fn approve_and_sign<J: durable::GenerationStore, S: settings::SettingsStore>(
    protected_settings: &mut settings::ProtectedLocalSettings<S>,
    prompt: PreparedApprovalPrompt,
    verified_response: VerifiedApprovalResponse,
    key: &RawPrivateKey,
    journal: &mut durable::DurableKeyAgentJournal<J>,
) -> Result<SignedArtifact, SignerError> {
    let PreparedApprovalPrompt {
        prepared,
        transport: _,
        request_hash,
        settings_lease,
        settings_binding,
    } = prompt;
    protected_settings
        .revalidate_and_consume_approval(settings_lease, request_hash, settings_binding)
        .map_err(|_| SignerError::Settings)?;
    let authorized = prepared.authorize(request_hash, verified_response)?;
    let account = authorized.account();
    verify_key_account(key, account)?;

    let plan = match authorized.operation() {
        AuthorizedOperationRef::Legacy(_)
        | AuthorizedOperationRef::AccessList(_)
        | AuthorizedOperationRef::DynamicFee(_) => {
            let lease = authorized.nonce_lease().ok_or(SignerError::Invariant)?;
            let intent = SigningIntent {
                approval_digest: authorized.approval_digest(),
                chain: authorized.chain(),
                account,
                lease_id: lease.lease_id(),
                nonce: lease.nonce(),
            };
            journal.record_signing_intent(intent)?;
            SigningPlan::Transaction(intent)
        }
        AuthorizedOperationRef::PersonalMessage(message) => {
            SigningPlan::Message(keccak_array(&message.eip191_preimage()))
        }
        AuthorizedOperationRef::TypedDataV4(typed_data) => {
            SigningPlan::Message(keccak_array(&typed_data.eip712_preimage()))
        }
    };

    let signed = key.sign_authorized_operation(authorized)?;
    let (signature, operation) = signed.into_parts();
    match plan {
        SigningPlan::Transaction(intent) => {
            let prehash = keccak_array(&encode_unsigned_transaction(&operation)?);
            if signature.signing_prehash() != &prehash {
                return Err(SignerError::SignedEncoding);
            }
            let signed_bytes = encode_signed_transaction(&operation, &signature)?;
            if signed_bytes.len() > MAX_SIGNED_TRANSACTION_BYTES {
                return Err(SignerError::SignedEncoding);
            }
            validate_signed_transaction(&operation, &signature, &signed_bytes)?;
            let sender = recover_sender(prehash, &signature)?;
            if sender != account {
                return Err(SignerError::SenderRecovery);
            }
            let transaction_hash = keccak_hash(&signed_bytes);
            let record = SignedTransactionRecord {
                intent,
                transaction_hash,
                signed_bytes,
            };
            journal.record_signed_transaction(&record)?;
            Ok(SignedArtifact::Transaction(SignedTransactionArtifact {
                transaction_hash,
                sender,
            }))
        }
        SigningPlan::Message(expected_prehash) => {
            sign_message(signature, expected_prehash, account)
        }
    }
}

fn verify_key_account(key: &RawPrivateKey, approved: Address20) -> Result<(), SignerError> {
    let actual = key.ethereum_address()?;
    if actual.as_bytes() != approved.as_bytes() {
        return Err(SignerError::AccountMismatch);
    }
    Ok(())
}

fn sign_message(
    signature: CanonicalSignature,
    expected_prehash: [u8; 32],
    approved: Address20,
) -> Result<SignedArtifact, SignerError> {
    if signature.signing_prehash() != &expected_prehash {
        return Err(SignerError::SignedEncoding);
    }
    let recovery_id = signature.recovery_id();
    if recovery_id > 1 {
        return Err(SignerError::SenderRecovery);
    }
    if recover_sender(expected_prehash, &signature)? != approved {
        return Err(SignerError::SenderRecovery);
    }
    let mut provider = [0_u8; 65];
    provider[..64].copy_from_slice(signature.compact());
    provider[64] = recovery_id
        .checked_add(27)
        .ok_or(SignerError::NumericOverflow)?;
    Ok(SignedArtifact::MessageSignature(provider))
}

fn encode_unsigned_transaction(operation: &CanonicalOperation) -> Result<Vec<u8>, SignerError> {
    match operation {
        CanonicalOperation::LegacyEip155(transaction) => Ok(rlp_list(&[
            rlp_u256(transaction.nonce),
            rlp_u256(transaction.gas_price),
            rlp_u256(transaction.gas_limit),
            rlp_target(transaction.target),
            rlp_u256(transaction.value),
            rlp_bytes(transaction.data.as_slice()),
            rlp_u256(transaction.chain_id),
            rlp_bytes(&[]),
            rlp_bytes(&[]),
        ])),
        CanonicalOperation::AccessListEip2930(transaction) => {
            let payload = rlp_list(&[
                rlp_u256(transaction.chain_id),
                rlp_u256(transaction.nonce),
                rlp_u256(transaction.gas_price),
                rlp_u256(transaction.gas_limit),
                rlp_target(transaction.target),
                rlp_u256(transaction.value),
                rlp_bytes(transaction.data.as_slice()),
                rlp_access_list(&transaction.access_list),
            ]);
            Ok(typed_envelope(1, payload))
        }
        CanonicalOperation::DynamicFeeEip1559(transaction) => {
            let payload = rlp_list(&[
                rlp_u256(transaction.chain_id),
                rlp_u256(transaction.nonce),
                rlp_u256(transaction.max_priority_fee_per_gas),
                rlp_u256(transaction.max_fee_per_gas),
                rlp_u256(transaction.gas_limit),
                rlp_target(transaction.target),
                rlp_u256(transaction.value),
                rlp_bytes(transaction.data.as_slice()),
                rlp_access_list(&transaction.access_list),
            ]);
            Ok(typed_envelope(2, payload))
        }
        CanonicalOperation::PersonalMessage(_) | CanonicalOperation::TypedDataV4(_) => {
            Err(SignerError::Invariant)
        }
    }
}

fn encode_signed_transaction(
    operation: &CanonicalOperation,
    signature: &CanonicalSignature,
) -> Result<Vec<u8>, SignerError> {
    let (r, s) = signature.compact().split_at(32);
    match operation {
        CanonicalOperation::LegacyEip155(transaction) => {
            encode_legacy_signed_parts(transaction, signature.recovery_id(), r, s)
        }
        CanonicalOperation::AccessListEip2930(transaction) => {
            let payload = rlp_list(&[
                rlp_u256(transaction.chain_id),
                rlp_u256(transaction.nonce),
                rlp_u256(transaction.gas_price),
                rlp_u256(transaction.gas_limit),
                rlp_target(transaction.target),
                rlp_u256(transaction.value),
                rlp_bytes(transaction.data.as_slice()),
                rlp_access_list(&transaction.access_list),
                rlp_u64(u64::from(signature.recovery_id())),
                rlp_integer_bytes(r),
                rlp_integer_bytes(s),
            ]);
            Ok(typed_envelope(1, payload))
        }
        CanonicalOperation::DynamicFeeEip1559(transaction) => {
            let payload = rlp_list(&[
                rlp_u256(transaction.chain_id),
                rlp_u256(transaction.nonce),
                rlp_u256(transaction.max_priority_fee_per_gas),
                rlp_u256(transaction.max_fee_per_gas),
                rlp_u256(transaction.gas_limit),
                rlp_target(transaction.target),
                rlp_u256(transaction.value),
                rlp_bytes(transaction.data.as_slice()),
                rlp_access_list(&transaction.access_list),
                rlp_u64(u64::from(signature.recovery_id())),
                rlp_integer_bytes(r),
                rlp_integer_bytes(s),
            ]);
            Ok(typed_envelope(2, payload))
        }
        CanonicalOperation::PersonalMessage(_) | CanonicalOperation::TypedDataV4(_) => {
            Err(SignerError::Invariant)
        }
    }
}

fn encode_legacy_signed_parts(
    transaction: &LegacyTransaction,
    recovery_id: u8,
    r: &[u8],
    s: &[u8],
) -> Result<Vec<u8>, SignerError> {
    let v = legacy_v(transaction.chain_id, recovery_id)?;
    Ok(rlp_list(&[
        rlp_u256(transaction.nonce),
        rlp_u256(transaction.gas_price),
        rlp_u256(transaction.gas_limit),
        rlp_target(transaction.target),
        rlp_u256(transaction.value),
        rlp_bytes(transaction.data.as_slice()),
        rlp_u256(v),
        rlp_integer_bytes(r),
        rlp_integer_bytes(s),
    ]))
}

fn typed_envelope(kind: u8, mut payload: Vec<u8>) -> Vec<u8> {
    payload.insert(0, kind);
    payload
}

fn rlp_target(target: TransactionTarget) -> Vec<u8> {
    match target {
        TransactionTarget::Create => rlp_bytes(&[]),
        TransactionTarget::Call(address) => rlp_bytes(address.as_bytes()),
    }
}

fn rlp_access_list(entries: &[AccessListEntry]) -> Vec<u8> {
    let encoded: Vec<_> = entries
        .iter()
        .map(|entry| {
            let keys: Vec<_> = entry
                .storage_keys()
                .iter()
                .map(|key| rlp_bytes(key.as_bytes()))
                .collect();
            rlp_list(&[rlp_bytes(entry.address().as_bytes()), rlp_list(&keys)])
        })
        .collect();
    rlp_list(&encoded)
}

fn rlp_u256(value: U256) -> Vec<u8> {
    rlp_integer_bytes(value.as_be_bytes())
}

fn rlp_u64(value: u64) -> Vec<u8> {
    rlp_integer_bytes(&value.to_be_bytes())
}

fn rlp_integer_bytes(bytes: &[u8]) -> Vec<u8> {
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    rlp_bytes(&bytes[first..])
}

fn rlp_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        return vec![bytes[0]];
    }
    let mut output = Vec::new();
    encode_length(0x80, 0xb7, bytes.len(), &mut output);
    output.extend_from_slice(bytes);
    output
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload_length = items
        .iter()
        .fold(0_usize, |total, item| total.saturating_add(item.len()));
    let mut output = Vec::new();
    encode_length(0xc0, 0xf7, payload_length, &mut output);
    for item in items {
        output.extend_from_slice(item);
    }
    output
}

fn encode_length(short_base: u8, long_base: u8, length: usize, output: &mut Vec<u8>) {
    if length <= 55 {
        output.push(short_base.saturating_add(u8::try_from(length).unwrap_or(55)));
        return;
    }
    let bytes = length.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    let significant = &bytes[first..];
    output.push(long_base.saturating_add(u8::try_from(significant.len()).unwrap_or(8)));
    output.extend_from_slice(significant);
}

fn legacy_v(chain_id: U256, y_parity: u8) -> Result<U256, SignerError> {
    if y_parity > 1 {
        return Err(SignerError::Invariant);
    }
    let mut output = [0_u8; 32];
    let mut carry = u16::from(35_u8.saturating_add(y_parity));
    for (source, target) in chain_id
        .as_be_bytes()
        .iter()
        .rev()
        .zip(output.iter_mut().rev())
    {
        let value = u16::from(*source).saturating_mul(2).saturating_add(carry);
        *target = u8::try_from(value & 0xff).map_err(|_| SignerError::NumericOverflow)?;
        carry = value >> 8;
    }
    if carry != 0 {
        return Err(SignerError::NumericOverflow);
    }
    Ok(U256::from_be_bytes(output))
}

fn validate_signed_transaction(
    operation: &CanonicalOperation,
    signature: &CanonicalSignature,
    bytes: &[u8],
) -> Result<(), SignerError> {
    let (envelope, payload) = match operation {
        CanonicalOperation::LegacyEip155(_) => (None, bytes),
        CanonicalOperation::AccessListEip2930(_) => {
            let (kind, payload) = bytes.split_first().ok_or(SignerError::SignedEncoding)?;
            if *kind != 1 {
                return Err(SignerError::SignedEncoding);
            }
            (Some(1), payload)
        }
        CanonicalOperation::DynamicFeeEip1559(_) => {
            let (kind, payload) = bytes.split_first().ok_or(SignerError::SignedEncoding)?;
            if *kind != 2 {
                return Err(SignerError::SignedEncoding);
            }
            (Some(2), payload)
        }
        CanonicalOperation::PersonalMessage(_) | CanonicalOperation::TypedDataV4(_) => {
            return Err(SignerError::Invariant);
        }
    };
    let parsed = parse_rlp_exact(payload)?;
    validate_signed_fields(operation, signature, envelope, &parsed)
}

fn validate_signed_fields(
    operation: &CanonicalOperation,
    signature: &CanonicalSignature,
    envelope: Option<u8>,
    parsed: &RlpValue<'_>,
) -> Result<(), SignerError> {
    let fields = parsed.as_list()?;
    let (r, s) = signature.compact().split_at(32);
    match operation {
        CanonicalOperation::LegacyEip155(transaction) => {
            require_envelope(envelope, None)?;
            require_count(fields, 9)?;
            require_integer(fields[0].as_bytes()?, transaction.nonce)?;
            require_integer(fields[1].as_bytes()?, transaction.gas_price)?;
            require_integer(fields[2].as_bytes()?, transaction.gas_limit)?;
            require_target(fields[3].as_bytes()?, transaction.target)?;
            require_integer(fields[4].as_bytes()?, transaction.value)?;
            require_bytes(fields[5].as_bytes()?, transaction.data.as_slice())?;
            require_integer(
                fields[6].as_bytes()?,
                legacy_v(transaction.chain_id, signature.recovery_id())?,
            )?;
            require_integer_slice(fields[7].as_bytes()?, r)?;
            require_integer_slice(fields[8].as_bytes()?, s)
        }
        CanonicalOperation::AccessListEip2930(transaction) => {
            require_envelope(envelope, Some(1))?;
            require_count(fields, 11)?;
            require_integer(fields[0].as_bytes()?, transaction.chain_id)?;
            require_integer(fields[1].as_bytes()?, transaction.nonce)?;
            require_integer(fields[2].as_bytes()?, transaction.gas_price)?;
            require_integer(fields[3].as_bytes()?, transaction.gas_limit)?;
            require_target(fields[4].as_bytes()?, transaction.target)?;
            require_integer(fields[5].as_bytes()?, transaction.value)?;
            require_bytes(fields[6].as_bytes()?, transaction.data.as_slice())?;
            require_access_list(&fields[7], &transaction.access_list)?;
            require_integer(
                fields[8].as_bytes()?,
                U256::from_u64(u64::from(signature.recovery_id())),
            )?;
            require_integer_slice(fields[9].as_bytes()?, r)?;
            require_integer_slice(fields[10].as_bytes()?, s)
        }
        CanonicalOperation::DynamicFeeEip1559(transaction) => {
            require_envelope(envelope, Some(2))?;
            require_count(fields, 12)?;
            require_integer(fields[0].as_bytes()?, transaction.chain_id)?;
            require_integer(fields[1].as_bytes()?, transaction.nonce)?;
            require_integer(fields[2].as_bytes()?, transaction.max_priority_fee_per_gas)?;
            require_integer(fields[3].as_bytes()?, transaction.max_fee_per_gas)?;
            require_integer(fields[4].as_bytes()?, transaction.gas_limit)?;
            require_target(fields[5].as_bytes()?, transaction.target)?;
            require_integer(fields[6].as_bytes()?, transaction.value)?;
            require_bytes(fields[7].as_bytes()?, transaction.data.as_slice())?;
            require_access_list(&fields[8], &transaction.access_list)?;
            require_integer(
                fields[9].as_bytes()?,
                U256::from_u64(u64::from(signature.recovery_id())),
            )?;
            require_integer_slice(fields[10].as_bytes()?, r)?;
            require_integer_slice(fields[11].as_bytes()?, s)
        }
        CanonicalOperation::PersonalMessage(_) | CanonicalOperation::TypedDataV4(_) => {
            Err(SignerError::Invariant)
        }
    }
}

fn require_envelope(actual: Option<u8>, expected: Option<u8>) -> Result<(), SignerError> {
    if actual == expected {
        Ok(())
    } else {
        Err(SignerError::SignedEncoding)
    }
}

fn require_count(fields: &[RlpValue<'_>], expected: usize) -> Result<(), SignerError> {
    if fields.len() == expected {
        Ok(())
    } else {
        Err(SignerError::SignedEncoding)
    }
}

fn require_integer(actual: &[u8], expected: U256) -> Result<(), SignerError> {
    require_integer_slice(actual, expected.as_be_bytes())
}

fn require_integer_slice(actual: &[u8], expected: &[u8]) -> Result<(), SignerError> {
    let first = expected
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(expected.len());
    require_bytes(actual, &expected[first..])
}

fn require_target(actual: &[u8], expected: TransactionTarget) -> Result<(), SignerError> {
    match expected {
        TransactionTarget::Create => require_bytes(actual, &[]),
        TransactionTarget::Call(address) => require_bytes(actual, address.as_bytes()),
    }
}

fn require_bytes(actual: &[u8], expected: &[u8]) -> Result<(), SignerError> {
    if actual == expected {
        Ok(())
    } else {
        Err(SignerError::SignedEncoding)
    }
}

fn require_access_list(
    actual: &RlpValue<'_>,
    expected: &[AccessListEntry],
) -> Result<(), SignerError> {
    let entries = actual.as_list()?;
    if entries.len() != expected.len() {
        return Err(SignerError::SignedEncoding);
    }
    for (entry, expected_entry) in entries.iter().zip(expected) {
        let fields = entry.as_list()?;
        require_count(fields, 2)?;
        require_bytes(fields[0].as_bytes()?, expected_entry.address().as_bytes())?;
        let keys = fields[1].as_list()?;
        if keys.len() != expected_entry.storage_keys().len() {
            return Err(SignerError::SignedEncoding);
        }
        for (key, expected_key) in keys.iter().zip(expected_entry.storage_keys()) {
            require_bytes(key.as_bytes()?, expected_key.as_bytes())?;
        }
    }
    Ok(())
}

fn recover_sender(
    prehash: [u8; 32],
    signature: &CanonicalSignature,
) -> Result<Address20, SignerError> {
    let recovery = RecoveryId::try_from(i32::from(signature.recovery_id()))
        .map_err(|_| SignerError::SenderRecovery)?;
    let recoverable = RecoverableSignature::from_compact(signature.compact(), recovery)
        .map_err(|_| SignerError::SenderRecovery)?;
    let public = Secp256k1::new()
        .recover_ecdsa(Message::from_digest(prehash), &recoverable)
        .map_err(|_| SignerError::SenderRecovery)?;
    let serialized = public.serialize_uncompressed();
    let digest = Keccak256::digest(&serialized[1..]);
    let mut address = [0_u8; 20];
    address.copy_from_slice(&digest[12..]);
    Ok(Address20::new(address))
}

fn keccak_array(bytes: &[u8]) -> [u8; 32] {
    let digest = Keccak256::digest(bytes);
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    output
}

fn keccak_hash(bytes: &[u8]) -> Hash32 {
    Hash32::new(keccak_array(bytes))
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RlpValue<'a> {
    Bytes(&'a [u8]),
    List(Vec<Self>),
}

impl<'a> RlpValue<'a> {
    fn as_bytes(&self) -> Result<&'a [u8], SignerError> {
        match self {
            Self::Bytes(bytes) => Ok(bytes),
            Self::List(_) => Err(SignerError::SignedEncoding),
        }
    }

    fn as_list(&self) -> Result<&[Self], SignerError> {
        match self {
            Self::List(items) => Ok(items),
            Self::Bytes(_) => Err(SignerError::SignedEncoding),
        }
    }
}

fn parse_rlp_exact(bytes: &[u8]) -> Result<RlpValue<'_>, SignerError> {
    let (value, remaining) = parse_rlp(bytes, 0)?;
    if remaining.is_empty() {
        Ok(value)
    } else {
        Err(SignerError::SignedEncoding)
    }
}

fn parse_rlp(bytes: &[u8], depth: usize) -> Result<(RlpValue<'_>, &[u8]), SignerError> {
    if depth > MAX_RLP_DEPTH {
        return Err(SignerError::SignedEncoding);
    }
    let (&prefix, tail) = bytes.split_first().ok_or(SignerError::SignedEncoding)?;
    match prefix {
        0x00..=0x7f => Ok((RlpValue::Bytes(&bytes[..1]), tail)),
        0x80..=0xb7 => {
            let length = usize::from(prefix - 0x80);
            let (payload, remaining) = split_payload(tail, length)?;
            if length == 1 && payload[0] < 0x80 {
                return Err(SignerError::SignedEncoding);
            }
            Ok((RlpValue::Bytes(payload), remaining))
        }
        0xb8..=0xbf => {
            let length_of_length = usize::from(prefix - 0xb7);
            let (length_bytes, tail) = split_payload(tail, length_of_length)?;
            let length = parse_long_length(length_bytes)?;
            if length < 56 {
                return Err(SignerError::SignedEncoding);
            }
            let (payload, remaining) = split_payload(tail, length)?;
            Ok((RlpValue::Bytes(payload), remaining))
        }
        0xc0..=0xf7 => parse_rlp_list(tail, usize::from(prefix - 0xc0), depth),
        0xf8..=0xff => {
            let length_of_length = usize::from(prefix - 0xf7);
            let (length_bytes, tail) = split_payload(tail, length_of_length)?;
            let length = parse_long_length(length_bytes)?;
            if length < 56 {
                return Err(SignerError::SignedEncoding);
            }
            parse_rlp_list(tail, length, depth)
        }
    }
}

fn parse_rlp_list(
    tail: &[u8],
    length: usize,
    depth: usize,
) -> Result<(RlpValue<'_>, &[u8]), SignerError> {
    let (mut payload, remaining) = split_payload(tail, length)?;
    let mut items = Vec::new();
    while !payload.is_empty() {
        let (item, rest) = parse_rlp(payload, depth.saturating_add(1))?;
        if rest.len() >= payload.len() {
            return Err(SignerError::SignedEncoding);
        }
        items.push(item);
        payload = rest;
    }
    Ok((RlpValue::List(items), remaining))
}

fn split_payload(bytes: &[u8], length: usize) -> Result<(&[u8], &[u8]), SignerError> {
    if bytes.len() < length {
        return Err(SignerError::SignedEncoding);
    }
    Ok(bytes.split_at(length))
}

fn parse_long_length(bytes: &[u8]) -> Result<usize, SignerError> {
    if bytes.is_empty() || bytes[0] == 0 || bytes.len() > std::mem::size_of::<usize>() {
        return Err(SignerError::SignedEncoding);
    }
    let mut length = 0_usize;
    for byte in bytes {
        length = length
            .checked_mul(256)
            .and_then(|value| value.checked_add(usize::from(*byte)))
            .ok_or(SignerError::SignedEncoding)?;
    }
    Ok(length)
}

#[cfg(test)]
mod tests {
    use wallet_model::{
        Address20, BoundedBytes, CanonicalOperation, DynamicFeeTransaction, Hash32,
        LegacyTransaction, TransactionTarget, U256,
    };

    use super::{
        RlpValue, SignerError, encode_legacy_signed_parts, encode_unsigned_transaction,
        keccak_array, legacy_v, parse_rlp_exact,
    };

    fn legacy() -> Result<CanonicalOperation, wallet_model::ParseValueError> {
        Ok(CanonicalOperation::LegacyEip155(LegacyTransaction {
            chain_id: U256::from_u64(1),
            nonce: U256::from_u64(9),
            gas_price: U256::from_u64(20_000_000_000),
            gas_limit: U256::from_u64(21_000),
            target: TransactionTarget::Call(wallet_model::Address20::new([0x35; 20])),
            value: U256::from_u64(1_000),
            data: BoundedBytes::new(Vec::new())?,
        }))
    }

    #[test]
    fn legacy_v_matches_eip155_formula() -> Result<(), SignerError> {
        assert_eq!(legacy_v(U256::from_u64(1), 0)?, U256::from_u64(37));
        assert_eq!(legacy_v(U256::from_u64(1), 1)?, U256::from_u64(38));
        Ok(())
    }

    #[test]
    fn all_supported_envelopes_are_domain_separated() -> Result<(), Box<dyn std::error::Error>> {
        let legacy_operation = legacy()?;
        let type_two = CanonicalOperation::DynamicFeeEip1559(DynamicFeeTransaction {
            chain_id: U256::from_u64(1),
            nonce: U256::from_u64(9),
            max_priority_fee_per_gas: U256::from_u64(1),
            max_fee_per_gas: U256::from_u64(2),
            gas_limit: U256::from_u64(21_000),
            target: TransactionTarget::Create,
            value: U256::ZERO,
            data: BoundedBytes::new(Vec::new())?,
            access_list: Vec::new(),
        });
        let legacy_unsigned = encode_unsigned_transaction(&legacy_operation)?;
        let typed_unsigned = encode_unsigned_transaction(&type_two)?;
        assert_ne!(legacy_unsigned.first(), Some(&2));
        assert_eq!(typed_unsigned.first(), Some(&2));
        Ok(())
    }

    #[test]
    fn strict_rlp_rejects_noncanonical_and_trailing_data() {
        assert!(parse_rlp_exact(&[0x81, 0x01]).is_err());
        assert!(parse_rlp_exact(&[0x01, 0x02]).is_err());
        assert!(parse_rlp_exact(&[0xb8, 0x01, 0x80]).is_err());
    }

    #[test]
    fn canonical_legacy_unsigned_encoding_is_a_list() -> Result<(), Box<dyn std::error::Error>> {
        let unsigned = encode_unsigned_transaction(&legacy()?)?;
        assert!(matches!(parse_rlp_exact(&unsigned)?, RlpValue::List(_)));
        Ok(())
    }

    #[test]
    fn official_eip155_vector_matches_preimage_hash_and_signed_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        // https://eips.ethereum.org/EIPS/eip-155#example
        let transaction = LegacyTransaction {
            chain_id: U256::from_u64(1),
            nonce: U256::from_u64(9),
            gas_price: U256::from_u64(20_000_000_000),
            gas_limit: U256::from_u64(21_000),
            target: TransactionTarget::Call(Address20::from_fixed_hex(
                "0x3535353535353535353535353535353535353535",
            )?),
            value: U256::from_u64(1_000_000_000_000_000_000),
            data: BoundedBytes::new(Vec::new())?,
        };
        let operation = CanonicalOperation::LegacyEip155(transaction.clone());
        let unsigned = encode_unsigned_transaction(&operation)?;
        assert_eq!(
            unsigned,
            decode_hex(
                "ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080"
            )?
        );
        assert_eq!(
            Hash32::new(keccak_array(&unsigned)),
            Hash32::from_fixed_hex(
                "0xdaf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
            )?
        );
        let r = decode_hex("28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276")?;
        let s = decode_hex("67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83")?;
        assert_eq!(
            encode_legacy_signed_parts(&transaction, 0, &r, &s)?,
            decode_hex(
                "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
            )?
        );
        Ok(())
    }

    #[test]
    fn official_signed_vector_rejects_every_truncation_and_trailing_byte() -> Result<(), SignerError>
    {
        let signed = decode_hex(
            "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83",
        )?;
        assert!(parse_rlp_exact(&signed).is_ok());
        for length in 0..signed.len() {
            assert!(parse_rlp_exact(&signed[..length]).is_err());
        }
        let mut trailing = signed;
        trailing.push(0);
        assert!(parse_rlp_exact(&trailing).is_err());
        Ok(())
    }

    fn decode_hex(value: &str) -> Result<Vec<u8>, SignerError> {
        if !value.len().is_multiple_of(2) {
            return Err(SignerError::SignedEncoding);
        }
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = decode_nibble(pair[0])?;
                let low = decode_nibble(pair[1])?;
                Ok((high << 4) | low)
            })
            .collect()
    }

    const fn decode_nibble(value: u8) -> Result<u8, SignerError> {
        match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            _ => Err(SignerError::SignedEncoding),
        }
    }
}
