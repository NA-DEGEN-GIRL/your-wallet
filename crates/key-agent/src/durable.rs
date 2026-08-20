//! Application-encrypted durable nonce and signed-candidate state.
//!
//! The generation store authenticates filesystem metadata, while this module
//! independently encrypts the complete Key Agent state. A store error is
//! ambiguous: the next generation may already be durable. Callers must reload
//! before retrying, and every ambiguous state keeps the nonce quarantined.
//!
//! Plaintext v2 is exactly `YWKAST02 || version:u16be || flags:u16be ||
//! ledger_len:u32be || pending_count:u32be || signed_count:u32be || ledger ||
//! pending_intents || signed_records`. Intents are fixed-width; signed records
//! add a fixed hash and bounded length-prefixed wire bytes. The AEAD associated
//! data is exactly the ASCII `AAD_DOMAIN`, followed by the v2 `u16be`, record
//! class byte `3`, and the durable generation as `u64be`.

use std::fmt;
use std::sync::Mutex;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use platform_windows::storage::{
    CiphertextFormat, CommitReceipt, EncryptedPayload, RecordClass, StoreError,
    WindowsGenerationStore,
};
use secret_core::{AtomicVaultStorage, StorageError, VaultBlob};
use sha3::{Digest as _, Keccak256};
use thiserror::Error;
use wallet_model::{AdapterKind, Address20, ChainIdentity, Hash32, NonceLeaseId, U256};
use wallet_protocol::{CandidateLifecycle, NonceCandidate, NonceLease, NonceLedger, ProtocolError};
use zeroize::{Zeroize, Zeroizing};

use crate::{MAX_SIGNED_TRANSACTION_BYTES, SignedTransactionRecord, SignerError, SigningIntent};

const STATE_MAGIC: &[u8; 8] = b"YWKAST02";
const STATE_VERSION: u16 = 2;
const STATE_FLAGS: u16 = 0;
const STATE_HEADER_BYTES: usize = 24;
const INTENT_BYTES: usize = 197;
const JOURNAL_RECORD_CLASS_TAG: u8 = 3;
const AEAD_TAG_BYTES: usize = 16;
const MAX_CIPHERTEXT_BYTES: usize = 16 * 1024 * 1024;
const MAX_STATE_PLAINTEXT_BYTES: usize = MAX_CIPHERTEXT_BYTES - AEAD_TAG_BYTES;
const MAX_PENDING_INTENTS: usize = 4_096;
const MAX_SIGNED_RECORDS: usize = 4_096;
const AAD_DOMAIN: &[u8] = b"your-wallet/key-agent/durable-state/xchacha20poly1305";

/// Stable, path-free errors for the encrypted Key Agent state boundary.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum DurableJournalError {
    /// The independent journal encryption key is invalid.
    #[error("journal encryption key is invalid")]
    InvalidKey,
    /// Operating-system cryptographic randomness was unavailable.
    #[error("operating-system randomness is unavailable")]
    RandomnessUnavailable,
    /// No committed Key Agent state exists.
    #[error("durable Key Agent state does not exist")]
    NotFound,
    /// A state already exists where a new one was requested.
    #[error("durable Key Agent state already exists")]
    AlreadyExists,
    /// The encrypted generation envelope was malformed or exceeded a bound.
    #[error("encrypted Key Agent state envelope is invalid")]
    InvalidEnvelope,
    /// AEAD authentication failed. Wrong keys and tampering are indistinguishable.
    #[error("encrypted Key Agent state did not authenticate")]
    AuthenticationFailed,
    /// Authenticated plaintext was malformed, duplicated, or inconsistent.
    #[error("authenticated Key Agent state is invalid")]
    CorruptState,
    /// A fixed state or signed-transaction bound was exceeded.
    #[error("durable Key Agent state exceeds its fixed bound")]
    BoundsExceeded,
    /// The requested nonce transition did not exactly match durable state.
    #[error("durable nonce transition is invalid")]
    InvalidTransition,
    /// The generation store could not prove a complete durable commit.
    #[error("durable generation store failed")]
    StoreFailure,
    /// A prior ambiguous commit must be resolved by reloading before retry.
    #[error("durable Key Agent state must be reloaded before retry")]
    ReloadRequired,
}

/// Result returned by the single raw-transaction RPC attempt.
///
/// Every non-matching or non-hash outcome is conservatively journaled as
/// `BroadcastUnknown`. Only an exact returned transaction hash may advance to
/// `Submitted`.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum RpcBroadcastOutcome {
    /// The endpoint returned a transaction hash.
    ReturnedHash(Hash32),
    /// The endpoint timed out after the request may have crossed the boundary.
    Timeout,
    /// The transport failed after send status became ambiguous.
    TransportError,
    /// The endpoint returned an error or rejection.
    RpcError,
}

impl fmt::Debug for RpcBroadcastOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReturnedHash(_) => formatter.write_str("ReturnedHash([REDACTED])"),
            Self::Timeout => formatter.write_str("Timeout"),
            Self::TransportError => formatter.write_str("TransportError"),
            Self::RpcError => formatter.write_str("RpcError"),
        }
    }
}

/// Exact report produced by a raw-transaction RPC adapter.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RpcBroadcastReport {
    local_transaction_hash: Hash32,
    outcome: RpcBroadcastOutcome,
}

/// Result of consuming a broadcast lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BroadcastResolution {
    /// Exact local and RPC-returned hashes matched and `Submitted` committed.
    Submitted(Hash32),
    /// The attempt was durably quarantined as `BroadcastUnknown`.
    Unknown,
    /// A hash mismatch was durably quarantined as `BroadcastUnknown`.
    HashMismatch,
}

impl RpcBroadcastReport {
    /// Bind the adapter's local hash calculation to the endpoint outcome.
    #[must_use]
    pub const fn new(local_transaction_hash: Hash32, outcome: RpcBroadcastOutcome) -> Self {
        Self {
            local_transaction_hash,
            outcome,
        }
    }
}

impl fmt::Debug for RpcBroadcastReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RpcBroadcastReport")
            .field("local_transaction_hash", &"[REDACTED]")
            .field("outcome", &self.outcome)
            .finish()
    }
}

/// RPC boundary that can receive signed bytes only from a committed lease.
pub trait RawTransactionRpc {
    /// Attempt exactly one `eth_sendRawTransaction` and report both the local
    /// hash associated with the submitted bytes and the endpoint outcome.
    fn send_raw_transaction(&mut self, signed_bytes: &[u8]) -> RpcBroadcastReport;
}

impl From<ProtocolError> for DurableJournalError {
    fn from(_: ProtocolError) -> Self {
        Self::InvalidTransition
    }
}

/// Independent application-layer XChaCha20-Poly1305 key.
///
/// This key must be provisioned independently from the vault key and the
/// generation store's HMAC key. This repository intentionally does not yet
/// provide a production key-provisioning or rotation mechanism.
pub struct JournalEncryptionKey {
    bytes: Zeroizing<[u8; 32]>,
}

impl JournalEncryptionKey {
    /// Imports an independently provisioned journal key.
    ///
    /// # Errors
    ///
    /// The all-zero sentinel is rejected.
    pub fn new(bytes: [u8; 32]) -> Result<Self, DurableJournalError> {
        if bytes == [0; 32] {
            return Err(DurableJournalError::InvalidKey);
        }
        Ok(Self {
            bytes: Zeroizing::new(bytes),
        })
    }

    fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl fmt::Debug for JournalEncryptionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JournalEncryptionKey([REDACTED])")
    }
}

/// One authenticated application-encrypted store generation.
#[derive(Clone, Eq, PartialEq)]
pub struct EncryptedGeneration {
    generation: u64,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

impl EncryptedGeneration {
    /// Validates an encrypted generation returned by a store implementation.
    ///
    /// # Errors
    ///
    /// Rejects generation zero, an all-zero nonce, and invalid ciphertext bounds.
    pub fn new(
        generation: u64,
        nonce: [u8; 24],
        ciphertext: Vec<u8>,
    ) -> Result<Self, DurableJournalError> {
        if generation == 0
            || nonce == [0; 24]
            || !(AEAD_TAG_BYTES..=MAX_CIPHERTEXT_BYTES).contains(&ciphertext.len())
        {
            return Err(DurableJournalError::InvalidEnvelope);
        }
        Ok(Self {
            generation,
            nonce,
            ciphertext,
        })
    }

    /// Returns the authenticated generation number.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the external `XChaCha20` nonce.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; 24] {
        &self.nonce
    }

    /// Returns application ciphertext plus its Poly1305 tag.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl fmt::Debug for EncryptedGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedGeneration")
            .field("generation", &self.generation)
            .field("nonce", &"[REDACTED]")
            .field("ciphertext", &"[REDACTED]")
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

/// Minimal atomic generation-store contract used by the Key Agent journal.
///
/// Implementations must provide exclusive-writer CAS semantics. An error from
/// `commit` may mean the new generation is already durable; callers therefore
/// enter reload-required state after every commit error.
pub trait GenerationStore: fmt::Debug + sealed::GenerationStoreSealed {
    /// Loads the latest authenticated generation, or `None` for an empty store.
    fn load(&mut self) -> Result<Option<EncryptedGeneration>, DurableJournalError>;

    /// Atomically commits the next generation and returns its durable number.
    fn commit(
        &mut self,
        expected_generation: Option<u64>,
        nonce: [u8; 24],
        ciphertext: Vec<u8>,
    ) -> Result<u64, DurableJournalError>;
}

mod sealed {
    pub trait GenerationStoreSealed {}
}

/// Adapter from the hardened Windows generation store to [`GenerationStore`].
pub struct WindowsJournalStore {
    inner: WindowsGenerationStore,
}

impl WindowsJournalStore {
    /// Wraps a store configured for `SignedCandidateJournal` records.
    #[must_use]
    pub const fn new(inner: WindowsGenerationStore) -> Self {
        Self { inner }
    }

    /// Consumes the adapter and returns the platform store.
    #[must_use]
    pub fn into_inner(self) -> WindowsGenerationStore {
        self.inner
    }
}

impl fmt::Debug for WindowsJournalStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsJournalStore")
            .field("inner", &"[AUTHENTICATED GENERATION STORE]")
            .finish()
    }
}

impl sealed::GenerationStoreSealed for WindowsJournalStore {}

impl GenerationStore for WindowsJournalStore {
    fn load(&mut self) -> Result<Option<EncryptedGeneration>, DurableJournalError> {
        let record = match self.inner.load() {
            Ok(record) => record,
            Err(StoreError::NotFound) => return Ok(None),
            Err(_) => return Err(DurableJournalError::StoreFailure),
        };
        let payload = record.payload();
        if payload.class() != RecordClass::SignedCandidateJournal
            || payload.format() != CiphertextFormat::XChaCha20Poly1305V1
        {
            return Err(DurableJournalError::InvalidEnvelope);
        }
        EncryptedGeneration::new(
            record.generation(),
            *payload.nonce(),
            payload.ciphertext().to_vec(),
        )
        .map(Some)
    }

    fn commit(
        &mut self,
        expected_generation: Option<u64>,
        nonce: [u8; 24],
        ciphertext: Vec<u8>,
    ) -> Result<u64, DurableJournalError> {
        let payload = EncryptedPayload::xchacha20poly1305_v1(
            RecordClass::SignedCandidateJournal,
            nonce,
            ciphertext,
        )
        .map_err(|_| DurableJournalError::InvalidEnvelope)?;
        self.inner
            .commit(expected_generation, &payload)
            .map(CommitReceipt::generation)
            .map_err(|_| DurableJournalError::StoreFailure)
    }
}

/// Vault adapter for a Windows generation store configured as `Vault`.
///
/// A mutex bridges `AtomicVaultStorage::load(&self)` to the platform store's
/// recovery-capable mutable load. The platform still deliberately lacks a
/// production rollback anchor, so constructing this adapter does not make a
/// release-ready vault store.
pub struct WindowsVaultStorage {
    inner: Mutex<WindowsGenerationStore>,
}

impl WindowsVaultStorage {
    /// Wraps a Windows store configured for canonical vault-v1 blobs.
    #[must_use]
    pub const fn new(inner: WindowsGenerationStore) -> Self {
        Self {
            inner: Mutex::new(inner),
        }
    }

    /// Consumes the adapter and returns the platform store.
    ///
    /// # Errors
    ///
    /// Fails if a previous holder poisoned the recovery mutex.
    pub fn into_inner(self) -> Result<WindowsGenerationStore, StorageError> {
        self.inner
            .into_inner()
            .map_err(|_| StorageError::DurabilityFailure)
    }
}

impl fmt::Debug for WindowsVaultStorage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsVaultStorage")
            .field("inner", &"[AUTHENTICATED GENERATION STORE]")
            .finish()
    }
}

impl AtomicVaultStorage for WindowsVaultStorage {
    fn load(&self) -> Result<Vec<u8>, StorageError> {
        let mut store = self
            .inner
            .lock()
            .map_err(|_| StorageError::DurabilityFailure)?;
        let record = store.load().map_err(map_vault_store_error)?;
        if record.payload().class() != RecordClass::Vault
            || record.payload().format() != CiphertextFormat::VaultV1
        {
            return Err(StorageError::DurabilityFailure);
        }
        validate_loaded_vault(record.generation(), record.payload().ciphertext())
    }

    fn commit(
        &mut self,
        expected_generation: Option<u64>,
        blob: &VaultBlob,
    ) -> Result<(), StorageError> {
        let expected = validate_vault_commit_generation(expected_generation, blob)?;
        let payload =
            EncryptedPayload::vault_v1(blob.as_bytes().to_vec()).map_err(map_vault_store_error)?;
        let store = self
            .inner
            .get_mut()
            .map_err(|_| StorageError::DurabilityFailure)?;
        let receipt = store
            .commit(expected_generation, &payload)
            .map_err(map_vault_store_error)?;
        if receipt.generation() != expected {
            return Err(StorageError::DurabilityFailure);
        }
        Ok(())
    }
}

fn validate_vault_commit_generation(
    expected_generation: Option<u64>,
    blob: &VaultBlob,
) -> Result<u64, StorageError> {
    let next =
        next_generation(expected_generation).map_err(|_| StorageError::GenerationConflict)?;
    if blob.header().generation() != next {
        return Err(StorageError::GenerationConflict);
    }
    Ok(next)
}

fn validate_loaded_vault(store_generation: u64, bytes: &[u8]) -> Result<Vec<u8>, StorageError> {
    let blob = VaultBlob::parse(bytes).map_err(|_| StorageError::DurabilityFailure)?;
    if blob.header().generation() != store_generation {
        return Err(StorageError::DurabilityFailure);
    }
    Ok(bytes.to_vec())
}

fn map_vault_store_error(error: StoreError) -> StorageError {
    match error {
        StoreError::NotFound => StorageError::NotFound,
        StoreError::GenerationConflict | StoreError::AnchorConflict => {
            StorageError::GenerationConflict
        }
        StoreError::BoundsExceeded => StorageError::BoundsExceeded,
        _ => StorageError::DurabilityFailure,
    }
}

#[derive(Clone, Eq, PartialEq)]
struct JournalState {
    ledger: NonceLedger,
    pending_intents: Vec<SigningIntent>,
    signed_records: Vec<SignedTransactionRecord>,
}

impl JournalState {
    fn new(ledger: NonceLedger) -> Self {
        Self {
            ledger,
            pending_intents: Vec::new(),
            signed_records: Vec::new(),
        }
    }

    fn validate(&self) -> Result<(), DurableJournalError> {
        self.ledger
            .encode_durable()
            .map_err(|_| DurableJournalError::CorruptState)?;
        if self.pending_intents.len() > MAX_PENDING_INTENTS
            || self.signed_records.len() > MAX_SIGNED_RECORDS
        {
            return Err(DurableJournalError::BoundsExceeded);
        }

        for (index, intent) in self.pending_intents.iter().enumerate() {
            if intent.approval_digest == Hash32::ZERO
                || self.pending_intents[..index]
                    .iter()
                    .any(|prior| same_candidate_binding(prior, intent))
                || self
                    .signed_records
                    .iter()
                    .any(|record| same_candidate_binding(&record.intent, intent))
            {
                return Err(DurableJournalError::CorruptState);
            }
            require_unique_candidate(&self.ledger, intent, CandidateLifecycle::PotentiallySigned)?;
        }

        for (index, record) in self.signed_records.iter().enumerate() {
            if record.intent.approval_digest == Hash32::ZERO
                || record.signed_bytes.is_empty()
                || record.signed_bytes.len() > MAX_SIGNED_TRANSACTION_BYTES
                || Hash32::new(Keccak256::digest(&record.signed_bytes).into())
                    != record.transaction_hash
                || self.signed_records[..index].iter().any(|prior| {
                    same_candidate_binding(&prior.intent, &record.intent)
                        || prior.transaction_hash == record.transaction_hash
                })
            {
                return Err(DurableJournalError::CorruptState);
            }
            let candidate = require_unique_signed_candidate(&self.ledger, &record.intent)?;
            if candidate.signed_transaction_hash() != Some(record.transaction_hash) {
                return Err(DurableJournalError::CorruptState);
            }
        }

        for slot in self.ledger.slots() {
            for candidate in slot.candidates() {
                match candidate.lifecycle() {
                    CandidateLifecycle::PotentiallySigned => {
                        if count_matching_intents(&self.pending_intents, candidate) != 1 {
                            return Err(DurableJournalError::CorruptState);
                        }
                    }
                    CandidateLifecycle::SignedUnbroadcast
                    | CandidateLifecycle::Broadcasting
                    | CandidateLifecycle::BroadcastUnknown
                    | CandidateLifecycle::Submitted => {
                        if count_matching_signed_records(&self.signed_records, candidate) != 1 {
                            return Err(DurableJournalError::CorruptState);
                        }
                    }
                    CandidateLifecycle::Reserved | CandidateLifecycle::ApprovalPending => {}
                }
            }
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, DurableJournalError> {
        self.validate()?;
        self.encode_unchecked()
    }

    fn encode_unchecked(&self) -> Result<Vec<u8>, DurableJournalError> {
        let ledger = self
            .ledger
            .encode_durable()
            .map_err(|_| DurableJournalError::CorruptState)?;
        let ledger_len =
            u32::try_from(ledger.len()).map_err(|_| DurableJournalError::BoundsExceeded)?;
        let pending_count = u32::try_from(self.pending_intents.len())
            .map_err(|_| DurableJournalError::BoundsExceeded)?;
        let signed_count = u32::try_from(self.signed_records.len())
            .map_err(|_| DurableJournalError::BoundsExceeded)?;
        let mut output = Vec::new();
        output.extend_from_slice(STATE_MAGIC);
        output.extend_from_slice(&STATE_VERSION.to_be_bytes());
        output.extend_from_slice(&STATE_FLAGS.to_be_bytes());
        output.extend_from_slice(&ledger_len.to_be_bytes());
        output.extend_from_slice(&pending_count.to_be_bytes());
        output.extend_from_slice(&signed_count.to_be_bytes());
        output.extend_from_slice(&ledger);
        for intent in &self.pending_intents {
            encode_intent(&mut output, *intent);
        }
        for record in &self.signed_records {
            encode_intent(&mut output, record.intent);
            output.extend_from_slice(record.transaction_hash.as_bytes());
            let length = u32::try_from(record.signed_bytes.len())
                .map_err(|_| DurableJournalError::BoundsExceeded)?;
            output.extend_from_slice(&length.to_be_bytes());
            output.extend_from_slice(&record.signed_bytes);
        }
        if output.len() > MAX_STATE_PLAINTEXT_BYTES {
            output.zeroize();
            return Err(DurableJournalError::BoundsExceeded);
        }
        Ok(output)
    }

    fn decode(bytes: &[u8]) -> Result<Self, DurableJournalError> {
        if bytes.len() < STATE_HEADER_BYTES {
            return Err(DurableJournalError::CorruptState);
        }
        if bytes.len() > MAX_STATE_PLAINTEXT_BYTES {
            return Err(DurableJournalError::BoundsExceeded);
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take::<8>()? != *STATE_MAGIC
            || cursor.read_u16()? != STATE_VERSION
            || cursor.read_u16()? != STATE_FLAGS
        {
            return Err(DurableJournalError::CorruptState);
        }
        let ledger_len =
            usize::try_from(cursor.read_u32()?).map_err(|_| DurableJournalError::BoundsExceeded)?;
        let pending_count =
            usize::try_from(cursor.read_u32()?).map_err(|_| DurableJournalError::BoundsExceeded)?;
        let signed_count =
            usize::try_from(cursor.read_u32()?).map_err(|_| DurableJournalError::BoundsExceeded)?;
        if pending_count > MAX_PENDING_INTENTS || signed_count > MAX_SIGNED_RECORDS {
            return Err(DurableJournalError::BoundsExceeded);
        }
        let minimum = ledger_len
            .checked_add(
                pending_count
                    .checked_mul(INTENT_BYTES)
                    .ok_or(DurableJournalError::BoundsExceeded)?,
            )
            .and_then(|value| value.checked_add(signed_count.checked_mul(INTENT_BYTES + 36)?))
            .ok_or(DurableJournalError::BoundsExceeded)?;
        if cursor.remaining() < minimum {
            return Err(DurableJournalError::CorruptState);
        }
        let ledger = NonceLedger::decode_durable(cursor.take_slice(ledger_len)?)
            .map_err(|_| DurableJournalError::CorruptState)?;
        let mut pending_intents = Vec::with_capacity(pending_count);
        for _ in 0..pending_count {
            pending_intents.push(decode_intent(&mut cursor)?);
        }
        let mut signed_records = SignedRecordDecodeGuard::new(signed_count);
        for _ in 0..signed_count {
            let intent = decode_intent(&mut cursor)?;
            let transaction_hash = Hash32::new(cursor.take::<32>()?);
            let length = usize::try_from(cursor.read_u32()?)
                .map_err(|_| DurableJournalError::BoundsExceeded)?;
            if length == 0 || length > MAX_SIGNED_TRANSACTION_BYTES {
                return Err(DurableJournalError::BoundsExceeded);
            }
            let signed_bytes = cursor.take_slice(length)?.to_vec();
            signed_records.push(SignedTransactionRecord {
                intent,
                transaction_hash,
                signed_bytes,
            });
        }
        if !cursor.is_finished() {
            return Err(DurableJournalError::CorruptState);
        }
        let state = Self {
            ledger,
            pending_intents,
            signed_records: signed_records.into_records(),
        };
        state.validate()?;
        Ok(state)
    }
}

impl Drop for JournalState {
    fn drop(&mut self) {
        wipe_signed_records(&mut self.signed_records);
    }
}

struct SignedRecordDecodeGuard {
    records: Option<Vec<SignedTransactionRecord>>,
}

impl SignedRecordDecodeGuard {
    fn new(capacity: usize) -> Self {
        Self {
            records: Some(Vec::with_capacity(capacity)),
        }
    }

    fn push(&mut self, record: SignedTransactionRecord) {
        if let Some(records) = self.records.as_mut() {
            records.push(record);
        }
    }

    fn into_records(mut self) -> Vec<SignedTransactionRecord> {
        self.records.take().unwrap_or_default()
    }
}

impl Drop for SignedRecordDecodeGuard {
    fn drop(&mut self) {
        if let Some(records) = self.records.as_mut() {
            wipe_signed_records(records);
        }
    }
}

fn wipe_signed_records(records: &mut [SignedTransactionRecord]) {
    for record in records {
        record.signed_bytes.zeroize();
    }
}

impl fmt::Debug for JournalState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JournalState")
            .field("nonce_slots", &self.ledger.slots().len())
            .field("pending_intents", &self.pending_intents.len())
            .field("signed_records", &self.signed_records.len())
            .field("signed_bytes", &"[REDACTED]")
            .finish()
    }
}

/// Opaque, non-clone authority to submit one exact journaled transaction.
///
/// The only constructor is [`DurableKeyAgentJournal::begin_broadcast`], which
/// returns this value only after the exact candidate's `Broadcasting` state is
/// durably committed. Dropping an unresolved lease attempts to durably mark the
/// outcome unknown; an ambiguous store failure instead puts the journal into
/// reload-required state.
///
/// ```compile_fail
/// use key_agent::durable::{BroadcastLease, GenerationStore};
///
/// fn leak_bytes<S: GenerationStore>(lease: &BroadcastLease<'_, S>) {
///     let _ = lease.rpc_wire_bytes();
/// }
/// ```
pub struct BroadcastLease<'journal, S: GenerationStore> {
    journal: &'journal mut DurableKeyAgentJournal<S>,
    intent: SigningIntent,
    transaction_hash: Hash32,
    signed_bytes: Zeroizing<Vec<u8>>,
    settled: bool,
}

impl<S: GenerationStore> BroadcastLease<'_, S> {
    /// Locally computed hash of the journal-owned RPC wire bytes.
    #[must_use]
    pub const fn local_transaction_hash(&self) -> Hash32 {
        self.transaction_hash
    }

    /// Consume this lease for exactly one RPC attempt, then durably quarantine
    /// or submit the candidate.
    ///
    /// `local_transaction_hash` must be the hash the RPC adapter associated with
    /// its outcome. `Submitted` is committed only when that hash, the capability
    /// hash, and the RPC-returned hash are identical. Every timeout, error, or
    /// mismatch is committed as `BroadcastUnknown`. A commit failure is
    /// ambiguous and leaves the journal reload-required.
    pub fn submit(
        mut self,
        rpc: &mut impl RawTransactionRpc,
    ) -> Result<BroadcastResolution, DurableJournalError> {
        let report = rpc.send_raw_transaction(self.signed_bytes.as_slice());
        let local_transaction_hash = report.local_transaction_hash;
        let outcome = report.outcome;
        let local_matches = local_transaction_hash == self.transaction_hash;
        let returned_matches = matches!(
            outcome,
            RpcBroadcastOutcome::ReturnedHash(returned) if returned == self.transaction_hash
        );
        let target = if local_matches && returned_matches {
            CandidateLifecycle::Submitted
        } else {
            CandidateLifecycle::BroadcastUnknown
        };
        let result = self
            .journal
            .finish_broadcast(self.intent, self.transaction_hash, target);
        self.settled = result.is_ok() || self.journal.reload_required();
        result?;

        if !local_matches
            || matches!(outcome, RpcBroadcastOutcome::ReturnedHash(_)) && !returned_matches
        {
            return Ok(BroadcastResolution::HashMismatch);
        }
        if !returned_matches {
            return Ok(BroadcastResolution::Unknown);
        }
        Ok(BroadcastResolution::Submitted(self.transaction_hash))
    }
}

impl<S: GenerationStore> fmt::Debug for BroadcastLease<'_, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BroadcastLease")
            .field("candidate", &"[REDACTED]")
            .field("transaction_hash", &"[REDACTED]")
            .field("signed_bytes", &"[REDACTED]")
            .field("settled", &self.settled)
            .finish()
    }
}

impl<S: GenerationStore> Drop for BroadcastLease<'_, S> {
    fn drop(&mut self) {
        if !self.settled && !self.journal.reload_required() {
            let result = self.journal.finish_broadcast(
                self.intent,
                self.transaction_hash,
                CandidateLifecycle::BroadcastUnknown,
            );
            self.settled = result.is_ok() || self.journal.reload_required();
        }
    }
}

/// Durable Key Agent state machine backed by an authenticated generation store.
pub struct DurableKeyAgentJournal<S: GenerationStore> {
    store: S,
    key: JournalEncryptionKey,
    generation: Option<u64>,
    state: JournalState,
    reload_required: bool,
}

impl<S: GenerationStore> DurableKeyAgentJournal<S> {
    /// Creates generation one from a validated nonce ledger.
    ///
    /// # Errors
    ///
    /// Fails if a generation already exists. A commit error is ambiguous; the
    /// caller must reconstruct the store, reprovision the exact same key, and
    /// attempt [`Self::open`] before creating or reserving again. This API
    /// consumes both values specifically so an uncertain in-memory state cannot
    /// continue after the first commit reports an error.
    pub fn create(
        mut store: S,
        key: JournalEncryptionKey,
        ledger: NonceLedger,
    ) -> Result<Self, DurableJournalError> {
        if store.load()?.is_some() {
            return Err(DurableJournalError::AlreadyExists);
        }
        let mut journal = Self {
            store,
            key,
            generation: None,
            state: JournalState::new(NonceLedger::new()),
            reload_required: false,
        };
        journal.commit_state(JournalState::new(ledger))?;
        Ok(journal)
    }

    /// Opens and authenticates an existing durable state.
    pub fn open(mut store: S, key: JournalEncryptionKey) -> Result<Self, DurableJournalError> {
        let snapshot = store.load()?.ok_or(DurableJournalError::NotFound)?;
        let generation = snapshot.generation();
        let state = decrypt_state(&key, &snapshot)?;
        let mut journal = Self {
            store,
            key,
            generation: Some(generation),
            state,
            reload_required: false,
        };
        journal.recover_interrupted_broadcasts()?;
        Ok(journal)
    }

    /// Reloads after a possibly committed store error and resolves ambiguity.
    ///
    /// No signing or reservation retry is accepted while reload is required.
    pub fn reload(&mut self) -> Result<(), DurableJournalError> {
        let snapshot = self.store.load()?.ok_or(DurableJournalError::NotFound)?;
        let state = decrypt_state(&self.key, &snapshot)?;
        self.generation = Some(snapshot.generation());
        self.state = state;
        self.reload_required = false;
        self.recover_interrupted_broadcasts()
    }

    /// Returns the current authenticated durable nonce ledger.
    #[must_use]
    pub const fn nonce_ledger(&self) -> &NonceLedger {
        &self.state.ledger
    }

    /// Returns the last successfully loaded or committed generation.
    #[must_use]
    pub const fn committed_generation(&self) -> Option<u64> {
        self.generation
    }

    /// Reports whether an ambiguous commit requires reload before retry.
    #[must_use]
    pub const fn reload_required(&self) -> bool {
        self.reload_required
    }

    /// Commits a new nonce in `Reserved` state without issuing authority.
    ///
    /// A failed commit returns no capability and requires reload before any
    /// retry because the reservation may already be durable.
    pub fn reserve_nonce(&mut self, candidate: NonceCandidate) -> Result<(), DurableJournalError> {
        self.require_ready()?;
        let mut next = self.state.clone();
        next.ledger.reserve(candidate)?;
        self.commit_state(next)
    }

    /// Issues an approval lease only after the exact `ApprovalPending`
    /// transition is durably committed.
    ///
    /// The returned opaque, non-clone [`NonceLease`] is the value callers put
    /// in `wallet_protocol::AuthorizationRequest::nonce_lease` before invoking
    /// `wallet_protocol::prepare_authorization`. A failed commit never returns
    /// the lease and requires reload; if the transition committed, reload shows
    /// `ApprovalPending`, so no second lease can be issued automatically.
    pub fn issue_approval_lease(
        &mut self,
        account: Address20,
        chain: ChainIdentity,
        nonce: U256,
        lease_id: NonceLeaseId,
    ) -> Result<NonceLease, DurableJournalError> {
        self.require_ready()?;
        let mut next = self.state.clone();
        let lease = next.ledger.issue_lease(account, chain, nonce, lease_id)?;
        self.commit_state(next)?;
        Ok(lease)
    }

    /// Reserves a new nonce candidate and returns its approval lease only after
    /// the combined `Reserved` → `ApprovalPending` generation is durable.
    ///
    /// Prefer [`Self::reserve_nonce`] followed by [`Self::issue_approval_lease`]
    /// when the pre-approval reservation must itself survive independently.
    pub fn reserve_for_approval(
        &mut self,
        candidate: NonceCandidate,
    ) -> Result<NonceLease, DurableJournalError> {
        self.require_ready()?;
        let account = candidate.account();
        let chain = candidate.chain();
        let nonce = candidate.nonce();
        let lease_id = candidate.lease_id();
        let mut next = self.state.clone();
        next.ledger.reserve(candidate)?;
        let lease = next.ledger.issue_lease(account, chain, nonce, lease_id)?;
        self.commit_state(next)?;
        Ok(lease)
    }

    fn record_intent(&mut self, intent: SigningIntent) -> Result<(), DurableJournalError> {
        self.require_ready()?;
        if intent.approval_digest == Hash32::ZERO {
            return Err(DurableJournalError::InvalidTransition);
        }
        let mut next = self.state.clone();
        if next
            .pending_intents
            .iter()
            .any(|prior| same_candidate_binding(prior, &intent))
            || next
                .signed_records
                .iter()
                .any(|record| same_candidate_binding(&record.intent, &intent))
        {
            return Err(DurableJournalError::InvalidTransition);
        }
        let candidate_id =
            require_unique_candidate(&next.ledger, &intent, CandidateLifecycle::ApprovalPending)?
                .candidate_id();
        next.ledger
            .slot_mut(intent.account, intent.chain, intent.nonce)
            .and_then(|slot| slot.candidate_mut(candidate_id))
            .ok_or(DurableJournalError::InvalidTransition)?
            .mark_signing_intent()?;
        next.pending_intents.push(intent);
        self.commit_state(next)
    }

    fn record_signed(
        &mut self,
        record: &SignedTransactionRecord,
    ) -> Result<(), DurableJournalError> {
        self.require_ready()?;
        if record.signed_bytes.is_empty()
            || record.signed_bytes.len() > MAX_SIGNED_TRANSACTION_BYTES
            || Hash32::new(Keccak256::digest(&record.signed_bytes).into())
                != record.transaction_hash
        {
            return Err(DurableJournalError::InvalidTransition);
        }
        let mut next = self.state.clone();
        let matching: Vec<_> = next
            .pending_intents
            .iter()
            .enumerate()
            .filter(|(_, intent)| **intent == record.intent)
            .map(|(index, _)| index)
            .collect();
        let [pending_index] = matching.as_slice() else {
            return Err(DurableJournalError::InvalidTransition);
        };
        let candidate_id = require_unique_candidate(
            &next.ledger,
            &record.intent,
            CandidateLifecycle::PotentiallySigned,
        )?
        .candidate_id();
        next.ledger
            .slot_mut(
                record.intent.account,
                record.intent.chain,
                record.intent.nonce,
            )
            .and_then(|slot| slot.candidate_mut(candidate_id))
            .ok_or(DurableJournalError::InvalidTransition)?
            .record_signed(record.transaction_hash)?;
        next.pending_intents.remove(*pending_index);
        next.signed_records.push(record.clone());
        self.commit_state(next)
    }

    pub(crate) fn record_signing_intent(
        &mut self,
        intent: SigningIntent,
    ) -> Result<(), SignerError> {
        self.record_intent(intent).map_err(|_| SignerError::Journal)
    }

    pub(crate) fn record_signed_transaction(
        &mut self,
        record: &SignedTransactionRecord,
    ) -> Result<(), SignerError> {
        self.record_signed(record).map_err(|_| SignerError::Journal)
    }

    /// Durably enters `Broadcasting` and only then releases exact wire bytes.
    ///
    /// The returned [`BroadcastLease`] is opaque and non-clone. RPC submission
    /// code should accept the lease's bytes and resolve the same lease with its
    /// local transaction hash plus the endpoint outcome.
    pub fn begin_broadcast(
        &mut self,
        transaction_hash: Hash32,
    ) -> Result<BroadcastLease<'_, S>, DurableJournalError> {
        self.require_ready()?;
        let record = require_unique_signed_record(&self.state, transaction_hash)?;
        let intent = record.intent;
        let signed_bytes = Zeroizing::new(record.signed_bytes.clone());
        let mut next = self.state.clone();
        let candidate = require_unique_signed_candidate(&next.ledger, &intent)?;
        if candidate.signed_transaction_hash() != Some(transaction_hash) {
            return Err(DurableJournalError::InvalidTransition);
        }
        let candidate_id = candidate.candidate_id();
        next.ledger
            .slot_mut(intent.account, intent.chain, intent.nonce)
            .and_then(|slot| slot.candidate_mut(candidate_id))
            .ok_or(DurableJournalError::InvalidTransition)?
            .begin_broadcast()?;
        self.commit_state(next)?;
        Ok(BroadcastLease {
            journal: self,
            intent,
            transaction_hash,
            signed_bytes,
            settled: false,
        })
    }

    fn finish_broadcast(
        &mut self,
        intent: SigningIntent,
        transaction_hash: Hash32,
        target: CandidateLifecycle,
    ) -> Result<(), DurableJournalError> {
        self.require_ready()?;
        if !matches!(
            target,
            CandidateLifecycle::Submitted | CandidateLifecycle::BroadcastUnknown
        ) {
            return Err(DurableJournalError::InvalidTransition);
        }
        let mut next = self.state.clone();
        let record = require_unique_signed_record(&next, transaction_hash)?;
        if record.intent != intent {
            return Err(DurableJournalError::InvalidTransition);
        }
        let candidate_id =
            require_unique_candidate(&next.ledger, &intent, CandidateLifecycle::Broadcasting)?
                .candidate_id();
        let candidate = next
            .ledger
            .slot_mut(intent.account, intent.chain, intent.nonce)
            .and_then(|slot| slot.candidate_mut(candidate_id))
            .ok_or(DurableJournalError::InvalidTransition)?;
        match target {
            CandidateLifecycle::Submitted => candidate.mark_submitted()?,
            CandidateLifecycle::BroadcastUnknown => candidate.mark_broadcast_unknown()?,
            _ => return Err(DurableJournalError::InvalidTransition),
        }
        self.commit_state(next)
    }

    fn recover_interrupted_broadcasts(&mut self) -> Result<(), DurableJournalError> {
        self.require_ready()?;
        let mut next = self.state.clone();
        let bindings: Vec<_> = next
            .signed_records
            .iter()
            .map(|record| (record.intent, record.transaction_hash))
            .collect();
        let mut changed = false;
        for (intent, transaction_hash) in bindings {
            let candidate = require_unique_signed_candidate(&next.ledger, &intent)?;
            if candidate.lifecycle() != CandidateLifecycle::Broadcasting {
                continue;
            }
            if candidate.signed_transaction_hash() != Some(transaction_hash) {
                return Err(DurableJournalError::CorruptState);
            }
            let candidate_id = candidate.candidate_id();
            next.ledger
                .slot_mut(intent.account, intent.chain, intent.nonce)
                .and_then(|slot| slot.candidate_mut(candidate_id))
                .ok_or(DurableJournalError::CorruptState)?
                .mark_broadcast_unknown()?;
            changed = true;
        }
        if changed {
            self.commit_state(next)?;
        }
        Ok(())
    }

    fn require_ready(&self) -> Result<(), DurableJournalError> {
        if self.reload_required {
            Err(DurableJournalError::ReloadRequired)
        } else {
            Ok(())
        }
    }

    fn commit_state(&mut self, next: JournalState) -> Result<(), DurableJournalError> {
        self.require_ready()?;
        let generation = next_generation(self.generation)?;
        let plaintext = Zeroizing::new(next.encode()?);
        let nonce = random_nonzero_nonce()?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(self.key.bytes()));
        let aad = generation_aad(generation);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_| DurableJournalError::InvalidEnvelope)?;
        if ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err(DurableJournalError::BoundsExceeded);
        }
        let committed = self
            .store
            .commit(self.generation, nonce, ciphertext)
            .inspect_err(|_| self.reload_required = true)?;
        if committed != generation {
            self.reload_required = true;
            return Err(DurableJournalError::StoreFailure);
        }
        self.generation = Some(generation);
        self.state = next;
        Ok(())
    }
}

impl<S: GenerationStore> fmt::Debug for DurableKeyAgentJournal<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableKeyAgentJournal")
            .field("store", &"[AUTHENTICATED GENERATION STORE]")
            .field("key", &"[REDACTED]")
            .field("generation", &self.generation)
            .field("state", &self.state)
            .field("reload_required", &self.reload_required)
            .finish()
    }
}

fn decrypt_state(
    key: &JournalEncryptionKey,
    snapshot: &EncryptedGeneration,
) -> Result<JournalState, DurableJournalError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.bytes()));
    let aad = generation_aad(snapshot.generation());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(snapshot.nonce()),
            Payload {
                msg: snapshot.ciphertext(),
                aad: &aad,
            },
        )
        .map_err(|_| DurableJournalError::AuthenticationFailed)?;
    let plaintext = Zeroizing::new(plaintext);
    JournalState::decode(plaintext.as_slice())
}

fn random_nonzero_nonce() -> Result<[u8; 24], DurableJournalError> {
    for _ in 0..4 {
        let mut nonce = [0; 24];
        getrandom::fill(&mut nonce).map_err(|_| DurableJournalError::RandomnessUnavailable)?;
        if nonce != [0; 24] {
            return Ok(nonce);
        }
    }
    Err(DurableJournalError::RandomnessUnavailable)
}

fn generation_aad(generation: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + 11);
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(&STATE_VERSION.to_be_bytes());
    aad.push(JOURNAL_RECORD_CLASS_TAG);
    aad.extend_from_slice(&generation.to_be_bytes());
    aad
}

fn next_generation(current: Option<u64>) -> Result<u64, DurableJournalError> {
    match current {
        None => Ok(1),
        Some(value) => value
            .checked_add(1)
            .ok_or(DurableJournalError::BoundsExceeded),
    }
}

fn same_candidate_binding(left: &SigningIntent, right: &SigningIntent) -> bool {
    left.account == right.account
        && left.chain == right.chain
        && left.nonce == right.nonce
        && left.lease_id == right.lease_id
}

fn candidate_matches_intent(
    candidate: &NonceCandidate,
    intent: &SigningIntent,
    lifecycle: CandidateLifecycle,
) -> bool {
    candidate.account() == intent.account
        && candidate.chain() == intent.chain
        && candidate.nonce() == intent.nonce
        && candidate.lease_id() == intent.lease_id
        && candidate.lifecycle() == lifecycle
}

fn require_unique_candidate<'a>(
    ledger: &'a NonceLedger,
    intent: &SigningIntent,
    lifecycle: CandidateLifecycle,
) -> Result<&'a NonceCandidate, DurableJournalError> {
    let slot = ledger
        .slot(intent.account, intent.chain, intent.nonce)
        .ok_or(DurableJournalError::InvalidTransition)?;
    let mut matches = slot
        .candidates()
        .iter()
        .filter(|candidate| candidate_matches_intent(candidate, intent, lifecycle));
    let candidate = matches
        .next()
        .ok_or(DurableJournalError::InvalidTransition)?;
    if matches.next().is_some() {
        return Err(DurableJournalError::InvalidTransition);
    }
    Ok(candidate)
}

fn require_unique_signed_candidate<'a>(
    ledger: &'a NonceLedger,
    intent: &SigningIntent,
) -> Result<&'a NonceCandidate, DurableJournalError> {
    let slot = ledger
        .slot(intent.account, intent.chain, intent.nonce)
        .ok_or(DurableJournalError::CorruptState)?;
    let mut matches = slot.candidates().iter().filter(|candidate| {
        candidate.account() == intent.account
            && candidate.chain() == intent.chain
            && candidate.nonce() == intent.nonce
            && candidate.lease_id() == intent.lease_id
            && matches!(
                candidate.lifecycle(),
                CandidateLifecycle::SignedUnbroadcast
                    | CandidateLifecycle::Broadcasting
                    | CandidateLifecycle::BroadcastUnknown
                    | CandidateLifecycle::Submitted
            )
    });
    let candidate = matches.next().ok_or(DurableJournalError::CorruptState)?;
    if matches.next().is_some() {
        return Err(DurableJournalError::CorruptState);
    }
    Ok(candidate)
}

fn require_unique_signed_record(
    state: &JournalState,
    transaction_hash: Hash32,
) -> Result<&SignedTransactionRecord, DurableJournalError> {
    let mut matches = state
        .signed_records
        .iter()
        .filter(|record| record.transaction_hash == transaction_hash);
    let record = matches
        .next()
        .ok_or(DurableJournalError::InvalidTransition)?;
    if matches.next().is_some()
        || Hash32::new(Keccak256::digest(&record.signed_bytes).into()) != transaction_hash
    {
        return Err(DurableJournalError::InvalidTransition);
    }
    Ok(record)
}

fn count_matching_intents(intents: &[SigningIntent], candidate: &NonceCandidate) -> usize {
    intents
        .iter()
        .filter(|intent| {
            candidate.account() == intent.account
                && candidate.chain() == intent.chain
                && candidate.nonce() == intent.nonce
                && candidate.lease_id() == intent.lease_id
        })
        .count()
}

fn count_matching_signed_records(
    records: &[SignedTransactionRecord],
    candidate: &NonceCandidate,
) -> usize {
    records
        .iter()
        .filter(|record| {
            candidate.account() == record.intent.account
                && candidate.chain() == record.intent.chain
                && candidate.nonce() == record.intent.nonce
                && candidate.lease_id() == record.intent.lease_id
                && candidate.signed_transaction_hash() == Some(record.transaction_hash)
        })
        .count()
}

fn encode_intent(output: &mut Vec<u8>, intent: SigningIntent) {
    output.extend_from_slice(intent.approval_digest.as_bytes());
    output.extend_from_slice(intent.account.as_bytes());
    encode_chain(output, intent.chain);
    output.extend_from_slice(intent.nonce.as_be_bytes());
    output.extend_from_slice(intent.lease_id.as_bytes());
}

fn decode_intent(cursor: &mut Cursor<'_>) -> Result<SigningIntent, DurableJournalError> {
    let approval_digest = Hash32::new(cursor.take::<32>()?);
    let account = Address20::new(cursor.take::<20>()?);
    let chain = decode_chain(cursor)?;
    let nonce = U256::from_be_bytes(cursor.take::<32>()?);
    let lease_id = NonceLeaseId::new(cursor.take::<16>()?);
    Ok(SigningIntent {
        approval_digest,
        chain,
        account,
        lease_id,
        nonce,
    })
}

fn encode_chain(output: &mut Vec<u8>, chain: ChainIdentity) {
    output.extend_from_slice(chain.chain_id().as_be_bytes());
    output.extend_from_slice(chain.genesis_hash().as_bytes());
    output.push(chain.adapter() as u8);
    output.extend_from_slice(chain.registry_revision().as_bytes());
}

fn decode_chain(cursor: &mut Cursor<'_>) -> Result<ChainIdentity, DurableJournalError> {
    let chain_id = U256::from_be_bytes(cursor.take::<32>()?);
    let genesis_hash = Hash32::new(cursor.take::<32>()?);
    let adapter = match cursor.read_u8()? {
        1 => AdapterKind::EthereumPos,
        2 => AdapterKind::BscParlia,
        3 => AdapterKind::PolygonPos,
        4 => AdapterKind::AvalancheC,
        5 => AdapterKind::OpStack,
        6 => AdapterKind::ArbitrumNitro,
        7 => AdapterKind::GenericEvm155,
        _ => return Err(DurableJournalError::CorruptState),
    };
    let registry_revision = Hash32::new(cursor.take::<32>()?);
    Ok(ChainIdentity::new(
        chain_id,
        genesis_hash,
        adapter,
        registry_revision,
    ))
}

#[derive(Clone, Copy, Debug)]
struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], DurableJournalError> {
        let slice = self.take_slice(LENGTH)?;
        slice
            .try_into()
            .map_err(|_| DurableJournalError::CorruptState)
    }

    fn take_slice(&mut self, length: usize) -> Result<&'a [u8], DurableJournalError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(DurableJournalError::BoundsExceeded)?;
        let output = self
            .bytes
            .get(self.position..end)
            .ok_or(DurableJournalError::CorruptState)?;
        self.position = end;
        Ok(output)
    }

    fn read_u16(&mut self) -> Result<u16, DurableJournalError> {
        Ok(u16::from_be_bytes(self.take()?))
    }

    fn read_u8(&mut self) -> Result<u8, DurableJournalError> {
        Ok(self.take::<1>()?[0])
    }

    fn read_u32(&mut self) -> Result<u32, DurableJournalError> {
        Ok(u32::from_be_bytes(self.take()?))
    }

    fn remaining(self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn is_finished(self) -> bool {
        self.position == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use chain_registry::{
        ChainId, EvidenceError, IdentityFingerprint, Observation, assess_builtin_chain, chain_by_id,
    };
    use wallet_model::{
        ActivationNonce, BrowserContext, BrowserFamily, BrowserOrigin, BrowserProvenance,
        ChannelNonce, DocumentId, DocumentLifecycle, ExtensionId, ProfileInstallId, RequestId,
        SessionId, SimulationProvenance, TransactionTarget, UntrustedTransaction,
    };
    use wallet_protocol::{
        AuthorizationOperation, AuthorizationRequest, CandidateId, prepare_authorization,
    };

    use super::*;

    const TEST_KEY: [u8; 32] = [0x31; 32];

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum CommitMode {
        Success,
        FailBefore,
        FailAfter,
    }

    struct MemoryBackend {
        snapshot: Option<EncryptedGeneration>,
        mode: CommitMode,
    }

    #[derive(Clone)]
    struct MemoryStore {
        backend: Rc<RefCell<MemoryBackend>>,
    }

    impl MemoryStore {
        fn new() -> Self {
            Self {
                backend: Rc::new(RefCell::new(MemoryBackend {
                    snapshot: None,
                    mode: CommitMode::Success,
                })),
            }
        }

        fn set_mode(&self, mode: CommitMode) {
            self.backend.borrow_mut().mode = mode;
        }

        fn tamper_ciphertext(&self) {
            let mut backend = self.backend.borrow_mut();
            if let Some(snapshot) = backend.snapshot.as_mut()
                && let Some(byte) = snapshot.ciphertext.last_mut()
            {
                *byte ^= 1;
            }
        }
    }

    impl fmt::Debug for MemoryStore {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("MemoryStore([REDACTED])")
        }
    }

    impl sealed::GenerationStoreSealed for MemoryStore {}

    impl GenerationStore for MemoryStore {
        fn load(&mut self) -> Result<Option<EncryptedGeneration>, DurableJournalError> {
            Ok(self.backend.borrow().snapshot.clone())
        }

        fn commit(
            &mut self,
            expected_generation: Option<u64>,
            nonce: [u8; 24],
            ciphertext: Vec<u8>,
        ) -> Result<u64, DurableJournalError> {
            let mut backend = self.backend.borrow_mut();
            let actual = backend
                .snapshot
                .as_ref()
                .map(EncryptedGeneration::generation);
            if actual != expected_generation {
                return Err(DurableJournalError::StoreFailure);
            }
            if backend.mode == CommitMode::FailBefore {
                backend.mode = CommitMode::Success;
                return Err(DurableJournalError::StoreFailure);
            }
            let generation = next_generation(actual)?;
            backend.snapshot = Some(EncryptedGeneration::new(generation, nonce, ciphertext)?);
            if backend.mode == CommitMode::FailAfter {
                backend.mode = CommitMode::Success;
                return Err(DurableJournalError::StoreFailure);
            }
            Ok(generation)
        }
    }

    fn chain() -> ChainIdentity {
        ChainIdentity::new(
            U256::from(1),
            Hash32::new([2; 32]),
            AdapterKind::EthereumPos,
            Hash32::new([3; 32]),
        )
    }

    fn candidate() -> NonceCandidate {
        NonceCandidate::reserve(
            Address20::new([4; 20]),
            chain(),
            U256::from(5),
            NonceLeaseId::new([6; 16]),
            CandidateId(Hash32::new([7; 32])),
        )
    }

    fn pending_ledger() -> Result<NonceLedger, DurableJournalError> {
        let candidate = candidate();
        let mut ledger = NonceLedger::new();
        ledger.reserve(candidate.clone())?;
        let _lease = ledger.issue_lease(
            candidate.account(),
            candidate.chain(),
            candidate.nonce(),
            candidate.lease_id(),
        )?;
        Ok(ledger)
    }

    fn intent() -> SigningIntent {
        let candidate = candidate();
        SigningIntent {
            approval_digest: Hash32::new([8; 32]),
            chain: candidate.chain(),
            account: candidate.account(),
            lease_id: candidate.lease_id(),
            nonce: candidate.nonce(),
        }
    }

    fn signed_record() -> SignedTransactionRecord {
        let signed_bytes = vec![0x02, 0xc0];
        SignedTransactionRecord {
            intent: intent(),
            transaction_hash: Hash32::new(Keccak256::digest(&signed_bytes).into()),
            signed_bytes,
        }
    }

    fn signed_journal(
        store: MemoryStore,
    ) -> Result<DurableKeyAgentJournal<MemoryStore>, DurableJournalError> {
        let mut journal = DurableKeyAgentJournal::create(store, key()?, pending_ledger()?)?;
        journal.record_intent(intent())?;
        journal.record_signed(&signed_record())?;
        Ok(journal)
    }

    fn candidate_lifecycle(
        journal: &DurableKeyAgentJournal<MemoryStore>,
    ) -> Result<CandidateLifecycle, DurableJournalError> {
        journal
            .nonce_ledger()
            .slot(intent().account, intent().chain, intent().nonce)
            .and_then(|slot| slot.candidates().first())
            .map(NonceCandidate::lifecycle)
            .ok_or(DurableJournalError::CorruptState)
    }

    struct TestRpc {
        report: RpcBroadcastReport,
        observed_bytes: Vec<u8>,
        calls: usize,
    }

    impl TestRpc {
        const fn new(report: RpcBroadcastReport) -> Self {
            Self {
                report,
                observed_bytes: Vec::new(),
                calls: 0,
            }
        }
    }

    impl RawTransactionRpc for TestRpc {
        fn send_raw_transaction(&mut self, signed_bytes: &[u8]) -> RpcBroadcastReport {
            self.calls = self.calls.saturating_add(1);
            self.observed_bytes = signed_bytes.to_vec();
            self.report
        }
    }

    fn key() -> Result<JournalEncryptionKey, DurableJournalError> {
        JournalEncryptionKey::new(TEST_KEY)
    }

    fn chain_evidence() -> Result<chain_registry::BuiltInChainEvidence, EvidenceError> {
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

    fn browser_context() -> Result<BrowserContext, Box<dyn std::error::Error>> {
        let origin = BrowserOrigin::new("https://example.test")?;
        Ok(BrowserContext {
            browser_family: BrowserFamily::Chrome,
            profile_install_id: ProfileInstallId::new([12; 32]),
            extension_id: ExtensionId::new("abcdefghijklmnopabcdefghijklmnop")?,
            tab_id: 1,
            frame_id: 0,
            document_id: DocumentId::new("durable-journal-test")?,
            activation_nonce: ActivationNonce::new([13; 32]),
            top_origin: origin.clone(),
            frame_origin: origin,
            document_lifecycle: DocumentLifecycle::Active,
            channel_nonce: ChannelNonce::new([14; 32]),
            provenance: BrowserProvenance::BrowserReportedUnverified,
            session_id: SessionId::new([15; 32]),
            sequence: 1,
            deadline_ms: u64::MAX,
            request_id: RequestId::new([16; 16]),
        })
    }

    fn synthetic_vault_blob(generation: u64) -> Result<VaultBlob, StorageError> {
        const HEADER_BYTES: usize = 112;
        const CIPHERTEXT_BYTES: usize = 16;
        let mut bytes = vec![0_u8; HEADER_BYTES + CIPHERTEXT_BYTES];
        bytes[0..8].copy_from_slice(b"YWRVLT01");
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10..12].copy_from_slice(&112_u16.to_be_bytes());
        bytes[12..28].copy_from_slice(&[1; 16]);
        bytes[28..36].copy_from_slice(&generation.to_be_bytes());
        bytes[36..38].copy_from_slice(&1_u16.to_be_bytes());
        bytes[38..40].copy_from_slice(&1_u16.to_be_bytes());
        bytes[40..42].copy_from_slice(&1_u16.to_be_bytes());
        bytes[42..44].copy_from_slice(&1_u16.to_be_bytes());
        bytes[44..48].copy_from_slice(&262_144_u32.to_be_bytes());
        bytes[48..52].copy_from_slice(&3_u32.to_be_bytes());
        bytes[52..56].copy_from_slice(&4_u32.to_be_bytes());
        bytes[56..72].copy_from_slice(&[2; 16]);
        bytes[72..96].copy_from_slice(&[3; 24]);
        bytes[96..100].copy_from_slice(&16_u32.to_be_bytes());
        bytes[HEADER_BYTES..].copy_from_slice(&[4; CIPHERTEXT_BYTES]);
        VaultBlob::parse(&bytes).map_err(|_| StorageError::DurabilityFailure)
    }

    #[test]
    fn key_and_debug_views_are_redacted() -> Result<(), DurableJournalError> {
        assert_eq!(format!("{:?}", key()?), "JournalEncryptionKey([REDACTED])");
        let store = MemoryStore::new();
        let journal = DurableKeyAgentJournal::create(store, key()?, pending_ledger()?)?;
        let debug = format!("{journal:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("0202"));
        let intent_debug = format!("{:?}", intent());
        let record_debug = format!("{:?}", signed_record());
        assert!(intent_debug.contains("[REDACTED]"));
        assert!(record_debug.contains("[REDACTED]"));
        assert!(!intent_debug.contains("08080808"));
        assert!(!record_debug.contains("02c0"));
        Ok(())
    }

    #[test]
    fn create_reopen_and_exact_transitions_round_trip() -> Result<(), DurableJournalError> {
        let store = MemoryStore::new();
        let mut journal = DurableKeyAgentJournal::create(store.clone(), key()?, pending_ledger()?)?;
        assert_eq!(journal.committed_generation(), Some(1));
        journal.record_intent(intent())?;
        assert_eq!(journal.committed_generation(), Some(2));
        journal.record_signed(&signed_record())?;
        assert_eq!(journal.committed_generation(), Some(3));
        let reopened = DurableKeyAgentJournal::open(store, key()?)?;
        let stored = reopened
            .nonce_ledger()
            .slot(intent().account, intent().chain, intent().nonce)
            .and_then(|slot| slot.candidates().first())
            .ok_or(DurableJournalError::CorruptState)?;
        assert_eq!(stored.lifecycle(), CandidateLifecycle::SignedUnbroadcast);
        assert_eq!(
            stored.signed_transaction_hash(),
            Some(signed_record().transaction_hash)
        );
        assert_eq!(reopened.state.signed_records.len(), 1);
        assert_eq!(
            reopened.state.signed_records[0].signed_bytes,
            vec![0x02, 0xc0]
        );
        Ok(())
    }

    #[test]
    fn broadcast_bytes_are_released_only_after_broadcasting_commit()
    -> Result<(), DurableJournalError> {
        let store = MemoryStore::new();
        let mut journal = signed_journal(store.clone())?;
        let record = signed_record();
        let lease = journal.begin_broadcast(record.transaction_hash)?;
        assert_eq!(lease.local_transaction_hash(), record.transaction_hash);
        assert!(!format!("{lease:?}").contains("02c0"));

        let snapshot = store
            .backend
            .borrow()
            .snapshot
            .clone()
            .ok_or(DurableJournalError::NotFound)?;
        assert_eq!(snapshot.generation(), 4);
        let committed = decrypt_state(&key()?, &snapshot)?;
        let candidate = require_unique_signed_candidate(&committed.ledger, &intent())?;
        assert_eq!(candidate.lifecycle(), CandidateLifecycle::Broadcasting);

        let mut rpc = TestRpc::new(RpcBroadcastReport::new(
            record.transaction_hash,
            RpcBroadcastOutcome::ReturnedHash(record.transaction_hash),
        ));
        assert_eq!(
            lease.submit(&mut rpc)?,
            BroadcastResolution::Submitted(record.transaction_hash)
        );
        assert_eq!(rpc.calls, 1);
        assert_eq!(rpc.observed_bytes, record.signed_bytes);
        assert_eq!(
            candidate_lifecycle(&journal)?,
            CandidateLifecycle::Submitted
        );
        assert_eq!(journal.committed_generation(), Some(5));
        Ok(())
    }

    #[test]
    fn timeout_transport_and_rpc_errors_are_durably_unknown() -> Result<(), DurableJournalError> {
        for outcome in [
            RpcBroadcastOutcome::Timeout,
            RpcBroadcastOutcome::TransportError,
            RpcBroadcastOutcome::RpcError,
        ] {
            let store = MemoryStore::new();
            let mut journal = signed_journal(store.clone())?;
            let hash = signed_record().transaction_hash;
            let lease = journal.begin_broadcast(hash)?;
            let mut rpc = TestRpc::new(RpcBroadcastReport::new(hash, outcome));
            assert_eq!(lease.submit(&mut rpc)?, BroadcastResolution::Unknown);
            assert_eq!(
                candidate_lifecycle(&journal)?,
                CandidateLifecycle::BroadcastUnknown
            );
            let reopened = DurableKeyAgentJournal::open(store, key()?)?;
            assert_eq!(
                candidate_lifecycle(&reopened)?,
                CandidateLifecycle::BroadcastUnknown
            );
            assert!(
                !reopened
                    .nonce_ledger()
                    .slot(intent().account, intent().chain, intent().nonce)
                    .ok_or(DurableJournalError::CorruptState)?
                    .automatic_reuse_permitted()
            );
        }
        Ok(())
    }

    #[test]
    fn either_local_or_returned_hash_mismatch_is_durably_unknown() -> Result<(), DurableJournalError>
    {
        let exact = signed_record().transaction_hash;
        for (local, outcome) in [
            (
                exact,
                RpcBroadcastOutcome::ReturnedHash(Hash32::new([0x91; 32])),
            ),
            (
                Hash32::new([0x92; 32]),
                RpcBroadcastOutcome::ReturnedHash(exact),
            ),
        ] {
            let store = MemoryStore::new();
            let mut journal = signed_journal(store.clone())?;
            let lease = journal.begin_broadcast(exact)?;
            let mut rpc = TestRpc::new(RpcBroadcastReport::new(local, outcome));
            assert_eq!(lease.submit(&mut rpc)?, BroadcastResolution::HashMismatch);
            assert_eq!(
                candidate_lifecycle(&journal)?,
                CandidateLifecycle::BroadcastUnknown
            );
            let reopened = DurableKeyAgentJournal::open(store, key()?)?;
            assert_eq!(
                candidate_lifecycle(&reopened)?,
                CandidateLifecycle::BroadcastUnknown
            );
        }
        Ok(())
    }

    #[test]
    fn dropping_or_crashing_with_a_lease_never_leaves_a_reusable_nonce()
    -> Result<(), DurableJournalError> {
        let store = MemoryStore::new();
        let mut journal = signed_journal(store.clone())?;
        let hash = signed_record().transaction_hash;
        drop(journal.begin_broadcast(hash)?);
        assert_eq!(
            candidate_lifecycle(&journal)?,
            CandidateLifecycle::BroadcastUnknown
        );

        let retry = journal.begin_broadcast(hash)?;
        core::mem::forget(retry);
        drop(journal);
        let reopened = DurableKeyAgentJournal::open(store, key()?)?;
        assert_eq!(
            candidate_lifecycle(&reopened)?,
            CandidateLifecycle::BroadcastUnknown
        );
        Ok(())
    }

    #[test]
    fn broadcast_commit_ambiguity_reloads_without_releasing_bytes()
    -> Result<(), DurableJournalError> {
        for mode in [CommitMode::FailBefore, CommitMode::FailAfter] {
            let store = MemoryStore::new();
            let mut journal = signed_journal(store.clone())?;
            store.set_mode(mode);
            assert_eq!(
                journal
                    .begin_broadcast(signed_record().transaction_hash)
                    .err(),
                Some(DurableJournalError::StoreFailure)
            );
            assert!(journal.reload_required());
            journal.reload()?;
            let expected = if mode == CommitMode::FailBefore {
                CandidateLifecycle::SignedUnbroadcast
            } else {
                CandidateLifecycle::BroadcastUnknown
            };
            assert_eq!(candidate_lifecycle(&journal)?, expected);
        }
        Ok(())
    }

    #[test]
    fn outcome_commit_ambiguity_requires_reload_and_recovers_safely()
    -> Result<(), DurableJournalError> {
        for mode in [CommitMode::FailBefore, CommitMode::FailAfter] {
            let store = MemoryStore::new();
            let mut journal = signed_journal(store.clone())?;
            let hash = signed_record().transaction_hash;
            let lease = journal.begin_broadcast(hash)?;
            store.set_mode(mode);
            let mut rpc = TestRpc::new(RpcBroadcastReport::new(
                hash,
                RpcBroadcastOutcome::ReturnedHash(hash),
            ));
            assert_eq!(
                lease.submit(&mut rpc),
                Err(DurableJournalError::StoreFailure)
            );
            assert!(journal.reload_required());
            journal.reload()?;
            let expected = if mode == CommitMode::FailBefore {
                CandidateLifecycle::BroadcastUnknown
            } else {
                CandidateLifecycle::Submitted
            };
            assert_eq!(candidate_lifecycle(&journal)?, expected);
        }
        Ok(())
    }

    #[test]
    fn legacy_state_v1_is_rejected_instead_of_silently_reinterpreted()
    -> Result<(), DurableJournalError> {
        let mut encoded = JournalState::new(pending_ledger()?).encode()?;
        encoded[..8].copy_from_slice(b"YWKAST01");
        encoded[8..10].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            JournalState::decode(&encoded).err(),
            Some(DurableJournalError::CorruptState)
        );
        Ok(())
    }

    #[test]
    fn reservation_returns_lease_only_after_durable_approval_pending()
    -> Result<(), DurableJournalError> {
        let store = MemoryStore::new();
        let mut journal =
            DurableKeyAgentJournal::create(store.clone(), key()?, NonceLedger::new())?;
        let lease = journal.reserve_for_approval(candidate())?;
        assert_eq!(journal.committed_generation(), Some(2));
        let _ = lease;
        let reopened = DurableKeyAgentJournal::open(store, key()?)?;
        let stored = reopened
            .nonce_ledger()
            .slot(intent().account, intent().chain, intent().nonce)
            .and_then(|slot| slot.candidates().first())
            .ok_or(DurableJournalError::CorruptState)?;
        assert_eq!(stored.lifecycle(), CandidateLifecycle::ApprovalPending);
        Ok(())
    }

    #[test]
    fn separate_reserve_and_issue_commit_before_capability_return()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = MemoryStore::new();
        let mut journal =
            DurableKeyAgentJournal::create(store.clone(), key()?, NonceLedger::new())?;
        journal.reserve_nonce(candidate())?;
        assert_eq!(journal.committed_generation(), Some(2));
        let reserved = journal
            .nonce_ledger()
            .slot(intent().account, intent().chain, intent().nonce)
            .and_then(|slot| slot.candidates().first())
            .ok_or(DurableJournalError::CorruptState)?;
        assert_eq!(reserved.lifecycle(), CandidateLifecycle::Reserved);

        let lease = journal.issue_approval_lease(
            intent().account,
            intent().chain,
            intent().nonce,
            intent().lease_id,
        )?;
        let prepared = prepare_authorization(AuthorizationRequest {
            operation: AuthorizationOperation::Transaction(UntrustedTransaction {
                envelope_type: Some(2),
                chain_id: Some(U256::from(1)),
                nonce: Some(intent().nonce),
                gas_limit: Some(U256::from(21_000)),
                gas_price: None,
                max_priority_fee_per_gas: Some(U256::from(1)),
                max_fee_per_gas: Some(U256::from(2)),
                target: Some(TransactionTarget::Call(Address20::new([17; 20]))),
                value: Some(U256::from(1)),
                data: Vec::new(),
                access_list: Some(Vec::new()),
            }),
            account: intent().account,
            chain_evidence: chain_evidence()?,
            nonce_lease: Some(lease),
            browser: browser_context()?,
            simulation: SimulationProvenance::NotPerformed,
            rpc_observations_digest: Hash32::new([18; 32]),
        })?;
        assert_ne!(prepared.approval_digest(), Hash32::ZERO);
        assert_eq!(journal.committed_generation(), Some(3));
        let reopened = DurableKeyAgentJournal::open(store, key()?)?;
        let pending = reopened
            .nonce_ledger()
            .slot(intent().account, intent().chain, intent().nonce)
            .and_then(|slot| slot.candidates().first())
            .ok_or(DurableJournalError::CorruptState)?;
        assert_eq!(pending.lifecycle(), CandidateLifecycle::ApprovalPending);
        Ok(())
    }

    #[test]
    fn issue_lease_commit_failure_returns_no_capability_and_requires_reload()
    -> Result<(), DurableJournalError> {
        let store = MemoryStore::new();
        let mut journal =
            DurableKeyAgentJournal::create(store.clone(), key()?, NonceLedger::new())?;
        journal.reserve_nonce(candidate())?;
        store.set_mode(CommitMode::FailAfter);
        let result = journal.issue_approval_lease(
            intent().account,
            intent().chain,
            intent().nonce,
            intent().lease_id,
        );
        assert_eq!(result.err(), Some(DurableJournalError::StoreFailure));
        assert!(journal.reload_required());
        journal.reload()?;
        let pending = journal
            .nonce_ledger()
            .slot(intent().account, intent().chain, intent().nonce)
            .and_then(|slot| slot.candidates().first())
            .ok_or(DurableJournalError::CorruptState)?;
        assert_eq!(pending.lifecycle(), CandidateLifecycle::ApprovalPending);
        assert_eq!(
            journal
                .issue_approval_lease(
                    intent().account,
                    intent().chain,
                    intent().nonce,
                    intent().lease_id,
                )
                .err(),
            Some(DurableJournalError::InvalidTransition)
        );
        Ok(())
    }

    #[test]
    fn wrong_intent_or_signed_digest_never_advances_state() -> Result<(), DurableJournalError> {
        let store = MemoryStore::new();
        let mut journal = DurableKeyAgentJournal::create(store, key()?, pending_ledger()?)?;
        let mut wrong = intent();
        wrong.approval_digest = Hash32::new([9; 32]);
        wrong.lease_id = NonceLeaseId::new([10; 16]);
        assert_eq!(
            journal.record_intent(wrong),
            Err(DurableJournalError::InvalidTransition)
        );
        assert_eq!(journal.committed_generation(), Some(1));
        journal.record_intent(intent())?;
        let mut record = signed_record();
        record.transaction_hash = Hash32::new([11; 32]);
        assert_eq!(
            journal.record_signed(&record),
            Err(DurableJournalError::InvalidTransition)
        );
        assert_eq!(journal.committed_generation(), Some(2));
        Ok(())
    }

    #[test]
    fn tamper_and_wrong_key_fail_authentication() -> Result<(), DurableJournalError> {
        let store = MemoryStore::new();
        let _journal = DurableKeyAgentJournal::create(store.clone(), key()?, pending_ledger()?)?;
        assert_eq!(
            DurableKeyAgentJournal::open(store.clone(), JournalEncryptionKey::new([0x41; 32])?)
                .err(),
            Some(DurableJournalError::AuthenticationFailed)
        );
        store.tamper_ciphertext();
        assert_eq!(
            DurableKeyAgentJournal::open(store, key()?).err(),
            Some(DurableJournalError::AuthenticationFailed)
        );
        Ok(())
    }

    #[test]
    fn every_plaintext_truncation_and_trailing_bytes_are_rejected()
    -> Result<(), DurableJournalError> {
        let state = JournalState::new(pending_ledger()?);
        let encoded = state.encode()?;
        for length in 0..encoded.len() {
            assert!(JournalState::decode(&encoded[..length]).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            JournalState::decode(&trailing).err(),
            Some(DurableJournalError::CorruptState)
        );
        assert!(JournalState::decode(&encoded).is_ok());
        Ok(())
    }

    #[test]
    fn duplicate_and_excess_counts_are_rejected() -> Result<(), DurableJournalError> {
        let mut state = JournalState::new(pending_ledger()?);
        let candidate_id = require_unique_candidate(
            &state.ledger,
            &intent(),
            CandidateLifecycle::ApprovalPending,
        )?
        .candidate_id();
        state
            .ledger
            .slot_mut(intent().account, intent().chain, intent().nonce)
            .and_then(|slot| slot.candidate_mut(candidate_id))
            .ok_or(DurableJournalError::CorruptState)?
            .mark_signing_intent()?;
        state.pending_intents.push(intent());
        state.pending_intents.push(intent());
        let duplicate = state.encode_unchecked()?;
        assert_eq!(
            JournalState::decode(&duplicate).err(),
            Some(DurableJournalError::CorruptState)
        );

        let mut excess = JournalState::new(NonceLedger::new()).encode_unchecked()?;
        excess[16..20].copy_from_slice(
            &u32::try_from(MAX_PENDING_INTENTS + 1)
                .map_err(|_| DurableJournalError::BoundsExceeded)?
                .to_be_bytes(),
        );
        assert_eq!(
            JournalState::decode(&excess).err(),
            Some(DurableJournalError::BoundsExceeded)
        );
        Ok(())
    }

    #[test]
    fn failed_commit_requires_reload_and_preserves_quarantine() -> Result<(), DurableJournalError> {
        let store = MemoryStore::new();
        let mut journal = DurableKeyAgentJournal::create(store.clone(), key()?, pending_ledger()?)?;
        store.set_mode(CommitMode::FailAfter);
        assert_eq!(
            journal.record_intent(intent()),
            Err(DurableJournalError::StoreFailure)
        );
        assert!(journal.reload_required());
        assert_eq!(
            journal.record_intent(intent()),
            Err(DurableJournalError::ReloadRequired)
        );
        journal.reload()?;
        let stored = journal
            .nonce_ledger()
            .slot(intent().account, intent().chain, intent().nonce)
            .and_then(|slot| slot.candidates().first())
            .ok_or(DurableJournalError::CorruptState)?;
        assert_eq!(stored.lifecycle(), CandidateLifecycle::PotentiallySigned);
        assert_eq!(
            journal.record_intent(intent()),
            Err(DurableJournalError::InvalidTransition)
        );
        Ok(())
    }

    #[test]
    fn signed_commit_crash_reloads_committed_bytes_without_reporting_success()
    -> Result<(), DurableJournalError> {
        let store = MemoryStore::new();
        let mut journal = DurableKeyAgentJournal::create(store.clone(), key()?, pending_ledger()?)?;
        journal.record_intent(intent())?;
        store.set_mode(CommitMode::FailAfter);
        assert_eq!(
            journal.record_signed(&signed_record()),
            Err(DurableJournalError::StoreFailure)
        );
        assert!(journal.reload_required());
        journal.reload()?;
        assert_eq!(journal.state.signed_records.len(), 1);
        let stored = journal
            .nonce_ledger()
            .slot(intent().account, intent().chain, intent().nonce)
            .and_then(|slot| slot.candidates().first())
            .ok_or(DurableJournalError::CorruptState)?;
        assert_eq!(stored.lifecycle(), CandidateLifecycle::SignedUnbroadcast);
        Ok(())
    }

    #[test]
    fn failed_before_commit_can_only_retry_after_reload() -> Result<(), DurableJournalError> {
        let store = MemoryStore::new();
        let mut journal = DurableKeyAgentJournal::create(store.clone(), key()?, pending_ledger()?)?;
        store.set_mode(CommitMode::FailBefore);
        assert_eq!(
            journal.record_intent(intent()),
            Err(DurableJournalError::StoreFailure)
        );
        assert!(journal.reload_required());
        journal.reload()?;
        journal.record_intent(intent())?;
        assert_eq!(journal.committed_generation(), Some(2));
        Ok(())
    }

    #[test]
    fn all_zero_keys_and_invalid_envelopes_are_rejected() {
        assert_eq!(
            JournalEncryptionKey::new([0; 32]).err(),
            Some(DurableJournalError::InvalidKey)
        );
        assert_eq!(
            EncryptedGeneration::new(0, [1; 24], vec![0; 16]).err(),
            Some(DurableJournalError::InvalidEnvelope)
        );
        assert_eq!(
            EncryptedGeneration::new(1, [0; 24], vec![0; 16]).err(),
            Some(DurableJournalError::InvalidEnvelope)
        );
    }

    #[test]
    fn vault_commit_generation_must_match_initial_and_later_store_generation()
    -> Result<(), StorageError> {
        let generation_one = synthetic_vault_blob(1)?;
        let generation_two = synthetic_vault_blob(2)?;
        let generation_three = synthetic_vault_blob(3)?;
        assert_eq!(
            validate_vault_commit_generation(None, &generation_one),
            Ok(1)
        );
        assert_eq!(
            validate_vault_commit_generation(None, &generation_two),
            Err(StorageError::GenerationConflict)
        );
        assert_eq!(
            validate_vault_commit_generation(Some(1), &generation_two),
            Ok(2)
        );
        assert_eq!(
            validate_vault_commit_generation(Some(1), &generation_one),
            Err(StorageError::GenerationConflict)
        );
        assert_eq!(
            validate_vault_commit_generation(Some(1), &generation_three),
            Err(StorageError::GenerationConflict)
        );
        Ok(())
    }

    #[test]
    fn vault_load_rejects_envelope_store_generation_divergence() -> Result<(), StorageError> {
        let generation_two = synthetic_vault_blob(2)?;
        assert_eq!(
            validate_loaded_vault(1, generation_two.as_bytes()),
            Err(StorageError::DurabilityFailure)
        );
        assert_eq!(
            validate_loaded_vault(2, generation_two.as_bytes())?,
            generation_two.as_bytes()
        );
        Ok(())
    }
}
