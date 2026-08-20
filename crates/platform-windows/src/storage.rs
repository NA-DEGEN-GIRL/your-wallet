//! Authenticated, bounded, crash-consistent Windows generation storage.
//!
//! The store deliberately accepts only caller-encrypted payloads. Its HMAC
//! authenticates storage metadata and ciphertext; it provides no confidentiality.
//! Full-store rollback detection additionally requires the crate's independently
//! verified monotonic anchor. A normal file, registry value, or DPAPI blob stored
//! beside this directory is not an independent rollback anchor.

use core::fmt;
use std::path::PathBuf;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

pub use crate::anchor_registry::BoundRollbackAnchor;

type HmacSha256 = Hmac<Sha256>;

const RECORD_MAGIC: [u8; 4] = *b"YWGR";
const MANIFEST_MAGIC: [u8; 4] = *b"YWGM";
const FORMAT_VERSION: u16 = 1;
const RECORD_MAC_DOMAIN: &[u8] = b"your-wallet/generation-record/v1\0";
const MANIFEST_MAC_DOMAIN: &[u8] = b"your-wallet/generation-manifest/v1\0";
const STORE_ID_DOMAIN: &[u8] = b"your-wallet/generation-store-id/v1\0";
const RECORD_FIXED_BYTES: usize = 150;
const MANIFEST_BODY_BYTES: usize = 122;
const MAC_BYTES: usize = 32;
const MANIFEST_BYTES: usize = MANIFEST_BODY_BYTES + MAC_BYTES;
const MAX_CIPHERTEXT_BYTES: usize = 16 * 1024 * 1024;
const XCHACHA_TAG_BYTES: usize = 16;
const VAULT_HEADER_BYTES: usize = 112;
const VAULT_MAGIC: &[u8; 8] = b"YWRVLT01";

/// Logical ciphertext class bound into every record and manifest MAC.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RecordClass {
    /// A `secret-core` encrypted vault blob.
    Vault = 1,
    /// An application-encrypted durable nonce ledger.
    NonceLedger = 2,
    /// An application-encrypted signing-intent and signed-candidate journal.
    SignedCandidateJournal = 3,
    /// Application-encrypted Key Agent local settings.
    LocalSettings = 4,
}

impl RecordClass {
    fn from_byte(value: u8) -> Result<Self, StoreError> {
        match value {
            1 => Ok(Self::Vault),
            2 => Ok(Self::NonceLedger),
            3 => Ok(Self::SignedCandidateJournal),
            4 => Ok(Self::LocalSettings),
            _ => Err(StoreError::IntegrityFailure),
        }
    }
}

/// Ciphertext envelope format. The storage MAC is not one of these algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CiphertextFormat {
    /// The self-contained `secret-core` vault-v1 envelope.
    VaultV1 = 1,
    /// A caller-created XChaCha20-Poly1305 ciphertext and tag with a separate nonce.
    XChaCha20Poly1305V1 = 2,
}

impl CiphertextFormat {
    fn from_byte(value: u8) -> Result<Self, StoreError> {
        match value {
            1 => Ok(Self::VaultV1),
            2 => Ok(Self::XChaCha20Poly1305V1),
            _ => Err(StoreError::IntegrityFailure),
        }
    }
}

/// Opaque caller-encrypted bytes accepted by the durable store.
///
/// There is intentionally no plaintext constructor. For nonce, journal, and
/// local-settings records, callers must pass the output of an application-layer
/// XChaCha20-Poly1305 encryption step; passing plaintext bytes violates this
/// API's security contract even if those bytes happen to satisfy length checks.
#[derive(Clone, Eq, PartialEq)]
pub struct EncryptedPayload {
    class: RecordClass,
    format: CiphertextFormat,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

impl EncryptedPayload {
    /// Validates and wraps a self-contained encrypted vault-v1 blob.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidCiphertextEnvelope`] for a wrong magic or
    /// an envelope too short to contain the authenticated vault header and tag.
    pub fn vault_v1(blob: Vec<u8>) -> Result<Self, StoreError> {
        if blob.len() < VAULT_HEADER_BYTES + XCHACHA_TAG_BYTES
            || blob.get(..VAULT_MAGIC.len()) != Some(VAULT_MAGIC)
        {
            return Err(StoreError::InvalidCiphertextEnvelope);
        }
        Ok(Self {
            class: RecordClass::Vault,
            format: CiphertextFormat::VaultV1,
            nonce: [0; 24],
            ciphertext: blob,
        })
    }

    /// Wraps application-layer XChaCha20-Poly1305 ciphertext plus its tag.
    ///
    /// This constructor refuses vault records so vaults retain their canonical
    /// self-contained format. The `ciphertext_and_tag` argument must be the
    /// direct output of authenticated encryption, never plaintext application
    /// state.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidCiphertextEnvelope`] for an all-zero nonce,
    /// a missing authentication tag, or the wrong record class.
    pub fn xchacha20poly1305_v1(
        class: RecordClass,
        nonce: [u8; 24],
        ciphertext_and_tag: Vec<u8>,
    ) -> Result<Self, StoreError> {
        if class == RecordClass::Vault
            || nonce == [0; 24]
            || ciphertext_and_tag.len() < XCHACHA_TAG_BYTES
        {
            return Err(StoreError::InvalidCiphertextEnvelope);
        }
        Ok(Self {
            class,
            format: CiphertextFormat::XChaCha20Poly1305V1,
            nonce,
            ciphertext: ciphertext_and_tag,
        })
    }

    /// Returns the logical encrypted record class.
    #[must_use]
    pub const fn class(&self) -> RecordClass {
        self.class
    }

    /// Returns the caller-declared AEAD envelope format.
    #[must_use]
    pub const fn format(&self) -> CiphertextFormat {
        self.format
    }

    /// Returns the external nonce for application-encrypted records.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; 24] {
        &self.nonce
    }

    /// Returns ciphertext bytes. These bytes must still be treated as sensitive.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl fmt::Debug for EncryptedPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedPayload")
            .field("class", &self.class)
            .field("format", &self.format)
            .field("nonce", &"[REDACTED]")
            .field("ciphertext", &"[REDACTED]")
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

/// HMAC-SHA256 key used only for durable storage authentication.
///
/// This key must be independent from all vault and journal encryption keys.
pub struct StorageAuthenticationKey([u8; 32]);

impl StorageAuthenticationKey {
    /// Creates a storage authentication key.
    ///
    /// # Errors
    ///
    /// Rejects the all-zero value, which normally indicates missing key setup.
    pub fn new(bytes: [u8; 32]) -> Result<Self, StoreError> {
        if bytes == [0; 32] {
            return Err(StoreError::InvalidAuthenticationKey);
        }
        Ok(Self(bytes))
    }

    fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for StorageAuthenticationKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for StorageAuthenticationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StorageAuthenticationKey([REDACTED])")
    }
}

/// Immutable store configuration.
#[derive(Clone, Eq, PartialEq)]
pub struct StoreConfig {
    root: PathBuf,
    namespace: String,
    class: RecordClass,
    max_ciphertext_bytes: usize,
}

impl fmt::Debug for StoreConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoreConfig")
            .field("root", &"[REDACTED LOCAL PATH]")
            .field("namespace", &"[REDACTED]")
            .field("class", &self.class)
            .field("max_ciphertext_bytes", &self.max_ciphertext_bytes)
            .finish()
    }
}

impl StoreConfig {
    /// Creates a bounded store configuration.
    ///
    /// The root is validated as an absolute local Windows path when opened. The
    /// final directory may be created, but its parent must already exist.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidConfiguration`] for an unsafe namespace or
    /// a zero/excessive payload bound.
    pub fn new(
        root: PathBuf,
        namespace: &str,
        class: RecordClass,
        max_ciphertext_bytes: usize,
    ) -> Result<Self, StoreError> {
        if namespace.is_empty()
            || namespace.len() > 48
            || !namespace
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || !(XCHACHA_TAG_BYTES..=MAX_CIPHERTEXT_BYTES).contains(&max_ciphertext_bytes)
        {
            return Err(StoreError::InvalidConfiguration);
        }
        Ok(Self {
            root,
            namespace: namespace.to_owned(),
            class,
            max_ciphertext_bytes,
        })
    }

    fn store_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(STORE_ID_DOMAIN);
        hasher.update([self.class as u8]);
        hasher.update(
            u16::try_from(self.namespace.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        hasher.update(self.namespace.as_bytes());
        hasher.finalize().into()
    }
}

/// Value held by a monotonic rollback anchor outside this file store.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AnchorValue {
    generation: u64,
    record_digest: [u8; 32],
    manifest_digest: [u8; 32],
}

impl AnchorValue {
    /// Reconstructs a value only after an authenticated registry has validated
    /// the generation and both digests.
    pub(crate) fn from_authenticated_parts(
        generation: u64,
        record_digest: [u8; 32],
        manifest_digest: [u8; 32],
    ) -> Result<Self, AnchorError> {
        if generation == 0 || record_digest == [0; 32] || manifest_digest == [0; 32] {
            return Err(AnchorError::Rollback);
        }
        Ok(Self {
            generation,
            record_digest,
            manifest_digest,
        })
    }

    /// Returns the committed generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the digest of the authenticated active slot record.
    #[must_use]
    pub const fn record_digest(self) -> [u8; 32] {
        self.record_digest
    }

    /// Returns the digest of the authenticated manifest.
    #[must_use]
    pub const fn manifest_digest(self) -> [u8; 32] {
        self.manifest_digest
    }
}

impl fmt::Debug for AnchorValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnchorValue")
            .field("generation", &self.generation)
            .field("record_digest", &"[SHA-256]")
            .field("manifest_digest", &"[SHA-256]")
            .finish()
    }
}

/// Errors returned by an independent monotonic rollback anchor.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AnchorError {
    /// The anchor cannot currently prove its durable state.
    #[error("rollback anchor unavailable")]
    Unavailable,
    /// The compare-and-advance expectation no longer matches.
    #[error("rollback anchor generation conflict")]
    Conflict,
    /// The requested value would regress or rewrite anchored history.
    #[error("rollback anchor rejected a rollback")]
    Rollback,
}

/// Independent monotonic state required for full-store rollback detection.
///
/// A release implementation must be non-rollbackable relative to the data
/// directory, perform a durable compare-and-advance, and scope values by the
/// supplied store identifier. An ordinary file, adjacent registry value, or
/// DPAPI blob does not meet this contract. This crate intentionally provides no
/// production implementation until a TPM-backed policy is independently tested.
pub(crate) trait RollbackAnchor: fmt::Debug {
    /// Loads the currently anchored value for `store_id`.
    ///
    /// # Errors
    ///
    /// Returns an anchor error unless the absence or value is authoritative.
    fn load(&self, store_id: [u8; 32]) -> Result<Option<AnchorValue>, AnchorError>;

    /// Durably advances from `expected` to `next` without permitting rewrites.
    ///
    /// # Errors
    ///
    /// Returns [`AnchorError::Conflict`] when another writer advanced first and
    /// [`AnchorError::Rollback`] for a non-monotonic transition.
    fn compare_and_advance(
        &self,
        store_id: [u8; 32],
        expected: Option<AnchorValue>,
        next: AnchorValue,
    ) -> Result<(), AnchorError>;
}

/// Stable, path-free storage errors suitable for security-boundary reporting.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum StoreError {
    /// Store configuration is outside its fixed grammar or bounds.
    #[error("durable store configuration is invalid")]
    InvalidConfiguration,
    /// The storage authentication key is an invalid sentinel value.
    #[error("durable store authentication key is invalid")]
    InvalidAuthenticationKey,
    /// Bytes did not form a supported caller-encrypted envelope.
    #[error("encrypted payload envelope is invalid")]
    InvalidCiphertextEnvelope,
    /// Payload class did not match the store's immutable class.
    #[error("encrypted payload class does not match durable store")]
    RecordClassMismatch,
    /// Payload or file bytes exceeded a configured hard bound.
    #[error("durable store bound exceeded")]
    BoundsExceeded,
    /// No committed record exists.
    #[error("durable record does not exist")]
    NotFound,
    /// The expected generation does not match the committed generation.
    #[error("durable store generation conflict")]
    GenerationConflict,
    /// An authenticated file was corrupt, truncated, swapped, or inconsistent.
    #[error("durable store integrity verification failed")]
    IntegrityFailure,
    /// The filesystem generation is older or inconsistent with the anchor.
    #[error("durable store rollback detected")]
    RollbackDetected,
    /// The independent rollback anchor could not prove its state.
    #[error("durable store rollback anchor unavailable")]
    AnchorUnavailable,
    /// A concurrent writer changed the rollback anchor.
    #[error("durable store rollback anchor conflict")]
    AnchorConflict,
    /// File data, atomic replacement, metadata flush, or ACL proof failed.
    #[error("durable atomic storage operation failed")]
    DurabilityFailure,
    /// A path component was non-local, relative, or a reparse point.
    #[error("durable store path is unsafe")]
    UnsafePath,
    /// A required file or directory did not have the exact protected stable-user DACL and owner.
    #[error("durable store permissions are unsafe")]
    InsecurePermissions,
    /// The DACL allowed inheritance instead of being protected.
    #[error("durable store DACL is not protected")]
    UnprotectedDacl,
    /// The DACL contained rights or entries outside the exact release policy.
    #[error("durable store DACL entry is unsafe")]
    UnexpectedAccessControlEntry,
    /// The owner or sole access entry did not name this process's stable `TokenUser` SID.
    #[error("durable store owner or DACL principal is unsafe")]
    WrongStoragePrincipal,
    /// Required Windows storage semantics are unavailable on this platform.
    #[error("Windows durable storage is unavailable on this platform")]
    UnsupportedPlatform,
    #[cfg(test)]
    /// Test-only simulated interruption at a named commit boundary.
    #[error("simulated process interruption")]
    InjectedCrash,
}

impl From<AnchorError> for StoreError {
    fn from(error: AnchorError) -> Self {
        match error {
            AnchorError::Unavailable => Self::AnchorUnavailable,
            AnchorError::Conflict => Self::AnchorConflict,
            AnchorError::Rollback => Self::RollbackDetected,
        }
    }
}

/// Authenticated committed ciphertext plus generation metadata.
#[derive(Clone, Eq, PartialEq)]
pub struct StoredCiphertext {
    generation: u64,
    record_digest: [u8; 32],
    payload: EncryptedPayload,
    slot: u8,
    previous_generation: u64,
    previous_digest: [u8; 32],
}

impl StoredCiphertext {
    /// Returns the committed generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the authenticated record digest.
    #[must_use]
    pub const fn record_digest(&self) -> [u8; 32] {
        self.record_digest
    }

    /// Returns caller-encrypted bytes and envelope metadata.
    #[must_use]
    pub const fn payload(&self) -> &EncryptedPayload {
        &self.payload
    }

    /// Consumes the record and returns caller-encrypted bytes.
    #[must_use]
    pub fn into_payload(self) -> EncryptedPayload {
        self.payload
    }
}

impl fmt::Debug for StoredCiphertext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredCiphertext")
            .field("generation", &self.generation)
            .field("record_digest", &"[SHA-256]")
            .field("payload", &self.payload)
            .finish_non_exhaustive()
    }
}

/// Receipt returned only after slot, manifest, directory metadata, and rollback
/// anchor advancement have all completed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitReceipt {
    anchor: AnchorValue,
}

impl CommitReceipt {
    /// Returns the durably committed generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.anchor.generation
    }

    /// Returns the value that was committed to the independent anchor.
    #[must_use]
    pub const fn anchor(self) -> AnchorValue {
        self.anchor
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileRole {
    Slot(u8),
    Manifest,
}

trait FaultControl {
    fn hit(&mut self, point: FaultPoint) -> Result<(), StoreError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FaultPoint {
    SlotTempCreated,
    SlotTempWritten,
    SlotTempFlushed,
    SlotReplaced,
    SlotDirectoryFlushed,
    ManifestTempCreated,
    ManifestTempWritten,
    ManifestTempFlushed,
    ManifestReplaced,
    ManifestDirectoryFlushed,
    BeforeAnchorAdvance,
    AfterAnchorAdvance,
}

#[derive(Debug)]
struct NoFault;

impl FaultControl for NoFault {
    fn hit(&mut self, _point: FaultPoint) -> Result<(), StoreError> {
        Ok(())
    }
}

trait DurableBackend: fmt::Debug {
    fn read(&self, role: FileRole, max_bytes: usize) -> Result<Option<Vec<u8>>, StoreError>;
    fn atomic_write(
        &mut self,
        role: FileRole,
        bytes: &[u8],
        fault: &mut dyn FaultControl,
    ) -> Result<(), StoreError>;
}

struct StoreCore<B, A> {
    backend: B,
    anchor: A,
    config: StoreConfig,
    key: StorageAuthenticationKey,
    store_id: [u8; 32],
}

impl<B, A> fmt::Debug for StoreCore<B, A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoreCore")
            .field("backend", &"[REDACTED]")
            .field("anchor", &"[REDACTED]")
            .field("config", &self.config)
            .field("key", &"[REDACTED]")
            .field("store_id", &"[REDACTED]")
            .finish()
    }
}

impl<B: DurableBackend, A: RollbackAnchor> StoreCore<B, A> {
    fn new(backend: B, anchor: A, config: StoreConfig, key: StorageAuthenticationKey) -> Self {
        let store_id = config.store_id();
        Self {
            backend,
            anchor,
            config,
            key,
            store_id,
        }
    }

    fn load(&mut self) -> Result<StoredCiphertext, StoreError> {
        self.recover_optional()?.ok_or(StoreError::NotFound)
    }

    fn commit(
        &mut self,
        expected_generation: Option<u64>,
        payload: &EncryptedPayload,
    ) -> Result<CommitReceipt, StoreError> {
        let mut no_fault = NoFault;
        self.commit_with_fault(expected_generation, payload, &mut no_fault)
    }

    fn commit_with_fault(
        &mut self,
        expected_generation: Option<u64>,
        payload: &EncryptedPayload,
        fault: &mut dyn FaultControl,
    ) -> Result<CommitReceipt, StoreError> {
        if payload.class != self.config.class {
            return Err(StoreError::RecordClassMismatch);
        }
        if payload.ciphertext.len() > self.config.max_ciphertext_bytes {
            return Err(StoreError::BoundsExceeded);
        }
        validate_payload(payload)?;

        let current = self.recover_optional()?;
        let actual_generation = current.as_ref().map(StoredCiphertext::generation);
        if expected_generation != actual_generation {
            return Err(StoreError::GenerationConflict);
        }

        let generation = actual_generation
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(StoreError::BoundsExceeded)?;
        let previous_generation = actual_generation.unwrap_or(0);
        let previous_digest = current
            .as_ref()
            .map_or([0; 32], StoredCiphertext::record_digest);
        let slot = current.as_ref().map_or(0, |record| record.slot ^ 1);
        let record_bytes = encode_record(
            self.store_id,
            slot,
            generation,
            previous_generation,
            previous_digest,
            payload,
            &self.key,
        )?;
        let record_digest = sha256(&record_bytes);
        self.backend
            .atomic_write(FileRole::Slot(slot), &record_bytes, fault)?;

        let manifest_bytes = encode_manifest(
            ManifestDescriptor {
                store_id: self.store_id,
                class: self.config.class,
                active_slot: slot,
                generation,
                previous_generation,
                record_digest,
                previous_digest,
            },
            &self.key,
        )?;
        self.backend
            .atomic_write(FileRole::Manifest, &manifest_bytes, fault)?;

        let next_anchor = AnchorValue {
            generation,
            record_digest,
            manifest_digest: sha256(&manifest_bytes),
        };
        let expected_anchor = current
            .as_ref()
            .map(|record| anchor_for_record(self.store_id, self.config.class, record, &self.key))
            .transpose()?;
        fault.hit(FaultPoint::BeforeAnchorAdvance)?;
        self.anchor
            .compare_and_advance(self.store_id, expected_anchor, next_anchor)?;
        fault.hit(FaultPoint::AfterAnchorAdvance)?;
        Ok(CommitReceipt {
            anchor: next_anchor,
        })
    }

    fn recover_optional(&mut self) -> Result<Option<StoredCiphertext>, StoreError> {
        let max_record_bytes = RECORD_FIXED_BYTES
            .checked_add(self.config.max_ciphertext_bytes)
            .and_then(|value| value.checked_add(MAC_BYTES))
            .ok_or(StoreError::BoundsExceeded)?;
        let slot_zero = self.read_record(0, max_record_bytes);
        let slot_one = self.read_record(1, max_record_bytes);
        let manifest = self.read_manifest();
        reject_nonrecoverable_read_error(&slot_zero)?;
        reject_nonrecoverable_read_error(&slot_one)?;
        reject_nonrecoverable_read_error(&manifest)?;
        let anchor = self.anchor.load(self.store_id)?;

        let records = [slot_zero, slot_one];
        if let Ok(ref manifest) = manifest
            && let Some(record) = matching_manifest_record(manifest, &records)
        {
            return self.reconcile_manifest(record.clone(), manifest, anchor);
        }

        self.recover_from_anchor(anchor, &records, &manifest)
    }

    fn read_record(&self, slot: u8, max_bytes: usize) -> Result<StoredCiphertext, StoreError> {
        let bytes = self
            .backend
            .read(FileRole::Slot(slot), max_bytes)?
            .ok_or(StoreError::NotFound)?;
        decode_record(
            &bytes,
            self.store_id,
            self.config.class,
            slot,
            self.config.max_ciphertext_bytes,
            &self.key,
        )
    }

    fn read_manifest(&self) -> Result<Manifest, StoreError> {
        let bytes = self
            .backend
            .read(FileRole::Manifest, MANIFEST_BYTES)?
            .ok_or(StoreError::NotFound)?;
        decode_manifest(&bytes, self.store_id, self.config.class, &self.key)
    }

    fn reconcile_manifest(
        &self,
        record: StoredCiphertext,
        manifest: &Manifest,
        anchor: Option<AnchorValue>,
    ) -> Result<Option<StoredCiphertext>, StoreError> {
        let next = manifest.anchor();
        match anchor {
            Some(current) if current == next => Ok(Some(record)),
            Some(current)
                if next.generation == current.generation.saturating_add(1)
                    && manifest.previous_generation == current.generation
                    && manifest.previous_digest == current.record_digest =>
            {
                self.anchor
                    .compare_and_advance(self.store_id, Some(current), next)?;
                Ok(Some(record))
            }
            None if next.generation == 1
                && manifest.previous_generation == 0
                && manifest.previous_digest == [0; 32] =>
            {
                self.anchor.compare_and_advance(self.store_id, None, next)?;
                Ok(Some(record))
            }
            Some(current) if next.generation < current.generation => {
                Err(StoreError::RollbackDetected)
            }
            Some(current)
                if next.generation == current.generation
                    && (next.record_digest != current.record_digest
                        || next.manifest_digest != current.manifest_digest) =>
            {
                Err(StoreError::RollbackDetected)
            }
            _ => Err(StoreError::RollbackDetected),
        }
    }

    fn recover_from_anchor(
        &mut self,
        anchor: Option<AnchorValue>,
        records: &[Result<StoredCiphertext, StoreError>; 2],
        manifest: &Result<Manifest, StoreError>,
    ) -> Result<Option<StoredCiphertext>, StoreError> {
        let Some(anchor) = anchor else {
            if records
                .iter()
                .all(|record| matches!(record, Err(StoreError::NotFound)))
                && matches!(manifest, Err(StoreError::NotFound))
            {
                return Ok(None);
            }

            if let Some(error) = records
                .iter()
                .filter_map(|record| record.as_ref().err())
                .chain(manifest.as_ref().err())
                .find(|error| **error != StoreError::NotFound)
            {
                return Err(*error);
            }
            return Err(StoreError::IntegrityFailure);
        };

        let record = records
            .iter()
            .filter_map(|candidate| candidate.as_ref().ok())
            .find(|candidate| {
                candidate.generation == anchor.generation
                    && candidate.record_digest == anchor.record_digest
            })
            .cloned()
            .ok_or(StoreError::RollbackDetected)?;
        let manifest_bytes =
            manifest_for_record(self.store_id, self.config.class, &record, &self.key)?;
        if sha256(&manifest_bytes) != anchor.manifest_digest {
            return Err(StoreError::RollbackDetected);
        }
        let mut no_fault = NoFault;
        self.backend
            .atomic_write(FileRole::Manifest, &manifest_bytes, &mut no_fault)?;
        Ok(Some(record))
    }
}

fn reject_nonrecoverable_read_error<T>(result: &Result<T, StoreError>) -> Result<(), StoreError> {
    match result {
        Ok(_) | Err(StoreError::NotFound | StoreError::IntegrityFailure) => Ok(()),
        Err(error) => Err(*error),
    }
}

fn matching_manifest_record<'a>(
    manifest: &Manifest,
    records: &'a [Result<StoredCiphertext, StoreError>; 2],
) -> Option<&'a StoredCiphertext> {
    records
        .get(usize::from(manifest.active_slot))?
        .as_ref()
        .ok()
        .filter(|record| {
            record.generation == manifest.generation
                && record.record_digest == manifest.record_digest
                && record.previous_generation == manifest.previous_generation
                && record.previous_digest == manifest.previous_digest
        })
}

fn validate_payload(payload: &EncryptedPayload) -> Result<(), StoreError> {
    match (payload.class, payload.format) {
        (RecordClass::Vault, CiphertextFormat::VaultV1)
            if payload.nonce == [0; 24]
                && payload.ciphertext.len() >= VAULT_HEADER_BYTES + XCHACHA_TAG_BYTES
                && payload.ciphertext.get(..VAULT_MAGIC.len()) == Some(VAULT_MAGIC) =>
        {
            Ok(())
        }
        (
            RecordClass::NonceLedger
            | RecordClass::SignedCandidateJournal
            | RecordClass::LocalSettings,
            CiphertextFormat::XChaCha20Poly1305V1,
        ) if payload.nonce != [0; 24] && payload.ciphertext.len() >= XCHACHA_TAG_BYTES => Ok(()),
        _ => Err(StoreError::InvalidCiphertextEnvelope),
    }
}

fn encode_record(
    store_id: [u8; 32],
    slot: u8,
    generation: u64,
    previous_generation: u64,
    previous_digest: [u8; 32],
    payload: &EncryptedPayload,
    key: &StorageAuthenticationKey,
) -> Result<Vec<u8>, StoreError> {
    let payload_len =
        u32::try_from(payload.ciphertext.len()).map_err(|_| StoreError::BoundsExceeded)?;
    let capacity = RECORD_FIXED_BYTES
        .checked_add(payload.ciphertext.len())
        .and_then(|value| value.checked_add(MAC_BYTES))
        .ok_or(StoreError::BoundsExceeded)?;
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(&RECORD_MAGIC);
    output.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    output.extend_from_slice(&store_id);
    output.push(payload.class as u8);
    output.push(slot);
    output.push(payload.format as u8);
    output.push(0);
    output.extend_from_slice(&generation.to_be_bytes());
    output.extend_from_slice(&previous_generation.to_be_bytes());
    output.extend_from_slice(&previous_digest);
    output.extend_from_slice(&payload.nonce);
    output.extend_from_slice(&payload_len.to_be_bytes());
    output.extend_from_slice(&sha256(&payload.ciphertext));
    debug_assert_eq!(output.len(), RECORD_FIXED_BYTES);
    output.extend_from_slice(&payload.ciphertext);
    let tag = hmac_tag(key, RECORD_MAC_DOMAIN, &output)?;
    output.extend_from_slice(&tag);
    Ok(output)
}

fn decode_record(
    bytes: &[u8],
    expected_store_id: [u8; 32],
    expected_class: RecordClass,
    expected_slot: u8,
    max_ciphertext_bytes: usize,
    key: &StorageAuthenticationKey,
) -> Result<StoredCiphertext, StoreError> {
    if bytes.len() < RECORD_FIXED_BYTES + MAC_BYTES {
        return Err(StoreError::IntegrityFailure);
    }
    let (body, tag) = bytes.split_at(bytes.len() - MAC_BYTES);
    verify_hmac(key, RECORD_MAC_DOMAIN, body, tag)?;
    let mut cursor = Cursor::new(body);
    if cursor.take::<4>()? != RECORD_MAGIC || cursor.read_u16()? != FORMAT_VERSION {
        return Err(StoreError::IntegrityFailure);
    }
    if cursor.take::<32>()? != expected_store_id {
        return Err(StoreError::IntegrityFailure);
    }
    let class = RecordClass::from_byte(cursor.read_u8()?)?;
    let slot = cursor.read_u8()?;
    let format = CiphertextFormat::from_byte(cursor.read_u8()?)?;
    if cursor.read_u8()? != 0 || class != expected_class || slot != expected_slot || slot > 1 {
        return Err(StoreError::IntegrityFailure);
    }
    let generation = cursor.read_u64()?;
    let previous_generation = cursor.read_u64()?;
    let previous_digest = cursor.take::<32>()?;
    let nonce = cursor.take::<24>()?;
    let payload_length =
        usize::try_from(cursor.read_u32()?).map_err(|_| StoreError::BoundsExceeded)?;
    let payload_digest = cursor.take::<32>()?;
    if payload_length > max_ciphertext_bytes || cursor.remaining() != payload_length {
        return Err(StoreError::BoundsExceeded);
    }
    let ciphertext = cursor.take_slice(payload_length)?.to_vec();
    if sha256(&ciphertext) != payload_digest
        || generation == 0
        || (generation == 1 && (previous_generation != 0 || previous_digest != [0; 32]))
        || (generation > 1 && previous_generation != generation - 1)
    {
        return Err(StoreError::IntegrityFailure);
    }
    let payload = EncryptedPayload {
        class,
        format,
        nonce,
        ciphertext,
    };
    validate_payload(&payload)?;
    Ok(StoredCiphertext {
        generation,
        record_digest: sha256(bytes),
        payload,
        slot,
        previous_generation,
        previous_digest,
    })
}

#[derive(Clone, Eq, PartialEq)]
struct Manifest {
    active_slot: u8,
    generation: u64,
    previous_generation: u64,
    record_digest: [u8; 32],
    previous_digest: [u8; 32],
    authenticated_digest: [u8; 32],
}

impl fmt::Debug for Manifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Manifest")
            .field("active_slot", &self.active_slot)
            .field("generation", &self.generation)
            .field("previous_generation", &self.previous_generation)
            .field("record_digest", &"[REDACTED]")
            .field("previous_digest", &"[REDACTED]")
            .field("authenticated_digest", &"[REDACTED]")
            .finish()
    }
}

impl Manifest {
    const fn anchor(&self) -> AnchorValue {
        AnchorValue {
            generation: self.generation,
            record_digest: self.record_digest,
            manifest_digest: self.authenticated_digest,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ManifestDescriptor {
    store_id: [u8; 32],
    class: RecordClass,
    active_slot: u8,
    generation: u64,
    previous_generation: u64,
    record_digest: [u8; 32],
    previous_digest: [u8; 32],
}

fn encode_manifest(
    descriptor: ManifestDescriptor,
    key: &StorageAuthenticationKey,
) -> Result<Vec<u8>, StoreError> {
    let mut output = Vec::with_capacity(MANIFEST_BYTES);
    output.extend_from_slice(&MANIFEST_MAGIC);
    output.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    output.extend_from_slice(&descriptor.store_id);
    output.push(descriptor.class as u8);
    output.push(descriptor.active_slot);
    output.extend_from_slice(&[0, 0]);
    output.extend_from_slice(&descriptor.generation.to_be_bytes());
    output.extend_from_slice(&descriptor.previous_generation.to_be_bytes());
    output.extend_from_slice(&descriptor.record_digest);
    output.extend_from_slice(&descriptor.previous_digest);
    debug_assert_eq!(output.len(), MANIFEST_BODY_BYTES);
    let tag = hmac_tag(key, MANIFEST_MAC_DOMAIN, &output)?;
    output.extend_from_slice(&tag);
    Ok(output)
}

fn decode_manifest(
    bytes: &[u8],
    expected_store_id: [u8; 32],
    expected_class: RecordClass,
    key: &StorageAuthenticationKey,
) -> Result<Manifest, StoreError> {
    if bytes.len() != MANIFEST_BYTES {
        return Err(StoreError::IntegrityFailure);
    }
    let (body, tag) = bytes.split_at(MANIFEST_BODY_BYTES);
    verify_hmac(key, MANIFEST_MAC_DOMAIN, body, tag)?;
    let mut cursor = Cursor::new(body);
    if cursor.take::<4>()? != MANIFEST_MAGIC || cursor.read_u16()? != FORMAT_VERSION {
        return Err(StoreError::IntegrityFailure);
    }
    if cursor.take::<32>()? != expected_store_id {
        return Err(StoreError::IntegrityFailure);
    }
    let class = RecordClass::from_byte(cursor.read_u8()?)?;
    let active_slot = cursor.read_u8()?;
    if cursor.take::<2>()? != [0, 0] || class != expected_class || active_slot > 1 {
        return Err(StoreError::IntegrityFailure);
    }
    let generation = cursor.read_u64()?;
    let previous_generation = cursor.read_u64()?;
    let record_digest = cursor.take::<32>()?;
    let previous_digest = cursor.take::<32>()?;
    if cursor.remaining() != 0
        || generation == 0
        || (generation == 1 && (previous_generation != 0 || previous_digest != [0; 32]))
        || (generation > 1 && previous_generation != generation - 1)
    {
        return Err(StoreError::IntegrityFailure);
    }
    Ok(Manifest {
        active_slot,
        generation,
        previous_generation,
        record_digest,
        previous_digest,
        authenticated_digest: sha256(bytes),
    })
}

fn manifest_for_record(
    store_id: [u8; 32],
    class: RecordClass,
    record: &StoredCiphertext,
    key: &StorageAuthenticationKey,
) -> Result<Vec<u8>, StoreError> {
    encode_manifest(
        ManifestDescriptor {
            store_id,
            class,
            active_slot: record.slot,
            generation: record.generation,
            previous_generation: record.previous_generation,
            record_digest: record.record_digest,
            previous_digest: record.previous_digest,
        },
        key,
    )
}

fn anchor_for_record(
    store_id: [u8; 32],
    class: RecordClass,
    record: &StoredCiphertext,
    key: &StorageAuthenticationKey,
) -> Result<AnchorValue, StoreError> {
    let manifest = manifest_for_record(store_id, class, record, key)?;
    Ok(AnchorValue {
        generation: record.generation,
        record_digest: record.record_digest,
        manifest_digest: sha256(&manifest),
    })
}

fn hmac_tag(
    key: &StorageAuthenticationKey,
    domain: &[u8],
    bytes: &[u8],
) -> Result<[u8; 32], StoreError> {
    let mut mac = HmacSha256::new_from_slice(key.bytes())
        .map_err(|_| StoreError::InvalidAuthenticationKey)?;
    mac.update(domain);
    mac.update(bytes);
    Ok(mac.finalize().into_bytes().into())
}

fn verify_hmac(
    key: &StorageAuthenticationKey,
    domain: &[u8],
    body: &[u8],
    tag: &[u8],
) -> Result<(), StoreError> {
    let mut mac = HmacSha256::new_from_slice(key.bytes())
        .map_err(|_| StoreError::InvalidAuthenticationKey)?;
    mac.update(domain);
    mac.update(body);
    mac.verify_slice(tag)
        .map_err(|_| StoreError::IntegrityFailure)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[derive(Clone, Copy)]
struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], StoreError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(StoreError::IntegrityFailure)?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(StoreError::IntegrityFailure)?;
        let mut output = [0; N];
        output.copy_from_slice(slice);
        self.position = end;
        Ok(output)
    }

    fn take_slice(&mut self, length: usize) -> Result<&'a [u8], StoreError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(StoreError::IntegrityFailure)?;
        let output = self
            .bytes
            .get(self.position..end)
            .ok_or(StoreError::IntegrityFailure)?;
        self.position = end;
        Ok(output)
    }

    fn read_u8(&mut self) -> Result<u8, StoreError> {
        Ok(self.take::<1>()?[0])
    }

    fn read_u16(&mut self) -> Result<u16, StoreError> {
        Ok(u16::from_be_bytes(self.take()?))
    }

    fn read_u32(&mut self) -> Result<u32, StoreError> {
        Ok(u32::from_be_bytes(self.take()?))
    }

    fn read_u64(&mut self) -> Result<u64, StoreError> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    fn remaining(self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }
}

/// Windows-backed authenticated generation store.
///
/// The root and every file are owned by the stable current `TokenUser` SID and
/// have a protected DACL containing exactly one full-control ACE for that SID.
/// Per-logon SIDs are intentionally reserved for session IPC and are never used
/// as persistent-storage principals.
/// Only held-handle-proven fixed local NTFS volumes are accepted. Directory
/// handles are held without delete sharing, temporary files live in the same
/// directory, and commit uses write-through file handles, explicit
/// `FlushFileBuffers`, atomic replace/move, exact installed byte/hash/identity
/// readback, and a directory-handle flush.
///
/// The production type is deliberately not generic over an application-supplied
/// anchor. Its only constructor consumes an opaque [`BoundRollbackAnchor`] that
/// external crates can neither construct nor clone.
///
/// ```compile_fail
/// use platform_windows::storage::RollbackAnchor;
/// // The rollback-anchor implementation contract is crate-private.
/// ```
///
/// ```compile_fail
/// use platform_windows::storage::WindowsGenerationStore;
/// struct ApplicationAnchor;
/// // Production storage cannot be specialized with an application anchor.
/// let _ = core::mem::size_of::<WindowsGenerationStore<ApplicationAnchor>>();
/// ```
pub struct WindowsGenerationStore {
    #[cfg(windows)]
    inner: StoreCore<sys::WindowsBackend, BoundRollbackAnchor>,
    #[cfg(not(windows))]
    marker: core::marker::PhantomData<BoundRollbackAnchor>,
}

impl WindowsGenerationStore {
    /// Opens or creates the dedicated store root and verifies its Windows
    /// reparse, identity, and DACL invariants.
    ///
    /// # Errors
    ///
    /// Fails closed when any required Windows guarantee cannot be proven.
    pub fn open(
        config: StoreConfig,
        key: StorageAuthenticationKey,
        anchor: BoundRollbackAnchor,
    ) -> Result<Self, StoreError> {
        #[cfg(windows)]
        {
            let backend = sys::WindowsBackend::open(&config)?;
            Ok(Self {
                inner: StoreCore::new(backend, anchor, config, key),
            })
        }

        #[cfg(not(windows))]
        {
            let _ = (config, key, anchor);
            Err(StoreError::UnsupportedPlatform)
        }
    }

    /// Loads and authenticates the latest anchored ciphertext generation.
    ///
    /// This also completes deterministic recovery of an anchored manifest or
    /// the one-generation commit window between manifest and anchor advancement.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] for an empty store and fails closed for
    /// corruption, rollback, unsafe paths, or unprovable durability.
    pub fn load(&mut self) -> Result<StoredCiphertext, StoreError> {
        #[cfg(windows)]
        {
            self.inner.load()
        }

        #[cfg(not(windows))]
        {
            Err(StoreError::UnsupportedPlatform)
        }
    }

    /// Atomically commits the next encrypted generation using optimistic CAS.
    ///
    /// A successful receipt means file bytes, the active manifest, directory
    /// metadata, and the independent rollback anchor all completed. An error may
    /// leave a recoverable future slot/manifest, so callers must reload before
    /// retrying and must never reuse a potentially signed nonce based on an error.
    ///
    /// # Errors
    ///
    /// Returns a stable error without exposing paths or ciphertext.
    pub fn commit(
        &mut self,
        expected_generation: Option<u64>,
        payload: &EncryptedPayload,
    ) -> Result<CommitReceipt, StoreError> {
        #[cfg(windows)]
        {
            self.inner.commit(expected_generation, payload)
        }

        #[cfg(not(windows))]
        {
            let _ = (expected_generation, payload);
            Err(StoreError::UnsupportedPlatform)
        }
    }
}

impl fmt::Debug for WindowsGenerationStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsGenerationStore")
            .field("root", &"[HELD SECURE DIRECTORY]")
            .field("authentication_key", &"[REDACTED]")
            .field("anchor", &"[ROLLBACK ANCHOR]")
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
mod sys;

#[cfg(test)]
mod tests;
