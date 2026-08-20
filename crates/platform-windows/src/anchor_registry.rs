//! Global rollback-anchor registry state machine.
//!
//! This module deliberately contains no file, registry, DPAPI, or TPM calls.
//! It models authenticated bytes and the exact ordering required of future
//! reviewed backends. The backend traits are sealed, and this crate provides no
//! production implementation, so ordinary local storage cannot accidentally be
//! treated as a non-rollbackable anchor.

use core::fmt;
use std::sync::{Arc, Mutex};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::storage::{AnchorError, AnchorValue, RollbackAnchor};

type HmacSha256 = Hmac<Sha256>;

const SLOT_MAGIC: [u8; 8] = *b"YWARSL01";
const MANIFEST_MAGIC: [u8; 8] = *b"YWARMA01";
const FORMAT_VERSION: u16 = 1;
const ENTRY_COUNT: usize = 4;
const DIGEST_BYTES: usize = 32;
const MAC_BYTES: usize = 32;
const ENTRY_BYTES: usize = 108;
const SLOT_BODY_BYTES: usize = 136 + ENTRY_COUNT * ENTRY_BYTES;
const SLOT_BYTES: usize = SLOT_BODY_BYTES + MAC_BYTES;
const MANIFEST_BODY_BYTES: usize = 136;
const MANIFEST_BYTES: usize = MANIFEST_BODY_BYTES + MAC_BYTES;
const SLOT_MAC_DOMAIN: &[u8] = b"your-wallet/global-anchor-registry/slot/v1\0";
const MANIFEST_MAC_DOMAIN: &[u8] = b"your-wallet/global-anchor-registry/manifest/v1\0";
const ZERO_DIGEST: [u8; DIGEST_BYTES] = [0; DIGEST_BYTES];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum RegistryStore {
    Vault = 1,
    NonceLedger = 2,
    SignedCandidateJournal = 3,
    LocalSettings = 4,
}

impl RegistryStore {
    const ALL: [Self; ENTRY_COUNT] = [
        Self::Vault,
        Self::NonceLedger,
        Self::SignedCandidateJournal,
        Self::LocalSettings,
    ];

    const fn index(self) -> usize {
        (self as u8 - 1) as usize
    }

    fn from_byte(value: u8) -> Result<Self, RegistryError> {
        match value {
            1 => Ok(Self::Vault),
            2 => Ok(Self::NonceLedger),
            3 => Ok(Self::SignedCandidateJournal),
            4 => Ok(Self::LocalSettings),
            _ => Err(RegistryError::IntegrityFailure),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RegistrySlot {
    A,
    B,
}

impl RegistrySlot {
    const fn byte(self) -> u8 {
        match self {
            Self::A => 0,
            Self::B => 1,
        }
    }

    const fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }

    fn from_byte(value: u8) -> Result<Self, RegistryError> {
        match value {
            0 => Ok(Self::A),
            1 => Ok(Self::B),
            _ => Err(RegistryError::IntegrityFailure),
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum RegistryError {
    #[error("rollback registry identity is invalid")]
    InvalidIdentity,
    #[error("rollback registry authentication key is invalid")]
    InvalidAuthenticationKey,
    #[error("rollback registry backend is unavailable")]
    BackendUnavailable,
    #[error("monotonic counter is unavailable")]
    CounterUnavailable,
    #[error("rollback registry is missing")]
    MissingRegistry,
    #[error("rollback registry integrity verification failed")]
    IntegrityFailure,
    #[error("rollback registry contains same-counter equivocation")]
    SameCounterEquivocation,
    #[error("rollback registry counter or sequence has an invalid gap")]
    GapDetected,
    #[error("rollback registry rollback was detected")]
    RollbackDetected,
    #[error("rollback registry generation expectation conflicts")]
    Conflict,
    #[error("rollback registry counter or sequence overflowed")]
    Overflow,
    #[error("rollback registry is already provisioned")]
    AlreadyProvisioned,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum CounterBackendError {
    #[error("monotonic counter operation is unavailable")]
    Unavailable,
    #[error("monotonic counter increment outcome is ambiguous")]
    Ambiguous,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum RegistryBackendError {
    #[error("registry persistence operation is unavailable")]
    Unavailable,
    #[error("registry persistence read exceeded its exact bound")]
    BoundsExceeded,
}

pub(crate) mod sealed {
    pub trait CounterBackendSealed {}
    pub trait RegistryBackendSealed {}
}

pub(crate) trait CounterBackend: sealed::CounterBackendSealed + fmt::Debug + Send {
    /// Returns the immutable identity of the physical monotonic counter.
    fn identity(&mut self) -> Result<[u8; 32], CounterBackendError>;
    fn read(&mut self) -> Result<u64, CounterBackendError>;
    fn increment_once(&mut self) -> Result<(), CounterBackendError>;
    /// Atomically authenticates the one-time provisioning proof and increments
    /// the counter once. If the counter does not advance, the proof must remain
    /// reusable; an ambiguous response is resolved only by an authoritative
    /// [`CounterBackend::read`].
    fn increment_once_for_provisioning(
        &mut self,
        evidence: &ProvisioningEvidence,
    ) -> Result<(), CounterBackendError>;
}

pub(crate) trait RegistryBackend: sealed::RegistryBackendSealed + fmt::Debug + Send {
    fn read_slot(
        &mut self,
        slot: RegistrySlot,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, RegistryBackendError>;
    fn write_slot_durable(
        &mut self,
        slot: RegistrySlot,
        bytes: &[u8],
    ) -> Result<(), RegistryBackendError>;
    fn read_manifest(&mut self, max_bytes: usize) -> Result<Option<Vec<u8>>, RegistryBackendError>;
    fn write_manifest_durable(&mut self, bytes: &[u8]) -> Result<(), RegistryBackendError>;
}

pub(crate) struct RegistryAuthenticationKey(Zeroizing<[u8; 32]>);

impl RegistryAuthenticationKey {
    fn new(bytes: [u8; 32]) -> Result<Self, RegistryError> {
        if bytes == [0; 32] {
            return Err(RegistryError::InvalidAuthenticationKey);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RegistryAuthenticationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RegistryAuthenticationKey([REDACTED])")
    }
}

/// Opaque authorization for the only permitted fresh-registry initialization.
///
/// A future reviewed counter backend must mint this from a non-rollbackable,
/// one-time hardware provisioning ceremony. There is deliberately no
/// production constructor in this crate. The proof is bound to one
/// installation, key epoch, immutable counter identity, and counter baseline;
/// deleting the registry bytes cannot recreate or retarget it.
pub(crate) struct ProvisioningEvidence {
    installation_id: [u8; 32],
    key_epoch: u64,
    counter_identity: [u8; 32],
    baseline_counter: u64,
    one_time_proof: Zeroizing<[u8; 32]>,
}

impl ProvisioningEvidence {
    fn validate(
        &self,
        identity: RegistryIdentity,
        counter_identity: [u8; 32],
        observed_counter: u64,
    ) -> Result<(), RegistryError> {
        if self.installation_id != identity.installation_id
            || self.key_epoch != identity.key_epoch
            || self.counter_identity != identity.counter_identity
            || self.counter_identity != counter_identity
            || self.baseline_counter != observed_counter
            || *self.one_time_proof == [0; 32]
        {
            return Err(RegistryError::InvalidIdentity);
        }
        Ok(())
    }
}

impl fmt::Debug for ProvisioningEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisioningEvidence")
            .field("installation_id", &"[REDACTED]")
            .field("key_epoch", &self.key_epoch)
            .field("counter_identity", &"[REDACTED]")
            .field("baseline_counter", &self.baseline_counter)
            .field("one_time_proof", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct RegistryStoreIds([[u8; 32]; ENTRY_COUNT]);

impl RegistryStoreIds {
    fn new(ids: [[u8; 32]; ENTRY_COUNT]) -> Result<Self, RegistryError> {
        if ids.contains(&[0; 32]) {
            return Err(RegistryError::InvalidIdentity);
        }
        for (index, id) in ids.iter().enumerate() {
            if ids[..index].contains(id) {
                return Err(RegistryError::InvalidIdentity);
            }
        }
        Ok(Self(ids))
    }

    const fn get(self, store: RegistryStore) -> [u8; 32] {
        self.0[store.index()]
    }
}

impl fmt::Debug for RegistryStoreIds {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RegistryStoreIds([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct RegistryIdentity {
    installation_id: [u8; 32],
    key_epoch: u64,
    counter_identity: [u8; 32],
    store_ids: RegistryStoreIds,
}

impl RegistryIdentity {
    fn new(
        installation_id: [u8; 32],
        key_epoch: u64,
        counter_identity: [u8; 32],
        store_ids: RegistryStoreIds,
    ) -> Result<Self, RegistryError> {
        if installation_id == [0; 32] || key_epoch == 0 || counter_identity == [0; 32] {
            return Err(RegistryError::InvalidIdentity);
        }
        Ok(Self {
            installation_id,
            key_epoch,
            counter_identity,
            store_ids,
        })
    }
}

impl fmt::Debug for RegistryIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryIdentity")
            .field("installation_id", &"[REDACTED]")
            .field("key_epoch", &self.key_epoch)
            .field("counter_identity", &"[REDACTED]")
            .field("store_ids", &self.store_ids)
            .finish()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct RegistryEntry {
    store: RegistryStore,
    store_id: [u8; 32],
    present: bool,
    generation: u64,
    record_digest: [u8; 32],
    manifest_digest: [u8; 32],
}

impl RegistryEntry {
    const fn absent(store: RegistryStore, store_id: [u8; 32]) -> Self {
        Self {
            store,
            store_id,
            present: false,
            generation: 0,
            record_digest: ZERO_DIGEST,
            manifest_digest: ZERO_DIGEST,
        }
    }

    fn validate(
        self,
        expected_store: RegistryStore,
        expected_id: [u8; 32],
    ) -> Result<(), RegistryError> {
        if self.store != expected_store || self.store_id != expected_id {
            return Err(RegistryError::RollbackDetected);
        }
        if self.present {
            if self.generation == 0
                || self.record_digest == ZERO_DIGEST
                || self.manifest_digest == ZERO_DIGEST
            {
                return Err(RegistryError::IntegrityFailure);
            }
        } else if self.generation != 0
            || self.record_digest != ZERO_DIGEST
            || self.manifest_digest != ZERO_DIGEST
        {
            return Err(RegistryError::IntegrityFailure);
        }
        Ok(())
    }

    fn anchor(self) -> Result<Option<AnchorValue>, RegistryError> {
        if !self.present {
            return Ok(None);
        }
        AnchorValue::from_authenticated_parts(
            self.generation,
            self.record_digest,
            self.manifest_digest,
        )
        .map(Some)
        .map_err(|_| RegistryError::IntegrityFailure)
    }
}

impl fmt::Debug for RegistryEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryEntry")
            .field("store", &self.store)
            .field("store_id", &"[REDACTED]")
            .field("present", &self.present)
            .field("generation", &self.generation)
            .field("record_digest", &"[SHA-256]")
            .field("manifest_digest", &"[SHA-256]")
            .finish()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct RegistryState {
    installation_id: [u8; 32],
    key_epoch: u64,
    counter_identity: [u8; 32],
    physical_counter: u64,
    global_sequence: u64,
    previous_registry_digest: [u8; 32],
    entries: [RegistryEntry; ENTRY_COUNT],
}

impl RegistryState {
    fn genesis(identity: RegistryIdentity, physical_counter: u64) -> Self {
        Self {
            installation_id: identity.installation_id,
            key_epoch: identity.key_epoch,
            counter_identity: identity.counter_identity,
            physical_counter,
            global_sequence: 1,
            previous_registry_digest: ZERO_DIGEST,
            entries: RegistryStore::ALL
                .map(|store| RegistryEntry::absent(store, identity.store_ids.get(store))),
        }
    }

    fn validate(self, identity: RegistryIdentity) -> Result<(), RegistryError> {
        if self.installation_id != identity.installation_id
            || self.key_epoch != identity.key_epoch
            || self.counter_identity != identity.counter_identity
            || self.global_sequence == 0
        {
            return Err(RegistryError::RollbackDetected);
        }
        for store in RegistryStore::ALL {
            self.entries[store.index()].validate(store, identity.store_ids.get(store))?;
        }
        Ok(())
    }
}

impl fmt::Debug for RegistryState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryState")
            .field("installation_id", &"[REDACTED]")
            .field("key_epoch", &self.key_epoch)
            .field("counter_identity", &"[REDACTED]")
            .field("physical_counter", &self.physical_counter)
            .field("global_sequence", &self.global_sequence)
            .field("previous_registry_digest", &"[SHA-256]")
            .field("entries", &self.entries)
            .finish()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct DecodedSlot {
    slot: RegistrySlot,
    state: RegistryState,
    digest: [u8; 32],
}

impl fmt::Debug for DecodedSlot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecodedSlot")
            .field("slot", &self.slot)
            .field("state", &self.state)
            .field("digest", &"[SHA-256]")
            .finish()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct RegistryManifest {
    active_slot: RegistrySlot,
    installation_id: [u8; 32],
    key_epoch: u64,
    counter_identity: [u8; 32],
    physical_counter: u64,
    global_sequence: u64,
    registry_digest: [u8; 32],
}

impl fmt::Debug for RegistryManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryManifest")
            .field("active_slot", &self.active_slot)
            .field("installation_id", &"[REDACTED]")
            .field("key_epoch", &self.key_epoch)
            .field("counter_identity", &"[REDACTED]")
            .field("physical_counter", &self.physical_counter)
            .field("global_sequence", &self.global_sequence)
            .field("registry_digest", &"[SHA-256]")
            .finish()
    }
}

struct RegistryCoordinator {
    backend: Box<dyn RegistryBackend>,
    counter: Box<dyn CounterBackend>,
    identity: RegistryIdentity,
    key: RegistryAuthenticationKey,
}

impl fmt::Debug for RegistryCoordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryCoordinator")
            .field("backend", &"[REDACTED BACKEND]")
            .field("counter", &"[REDACTED COUNTER]")
            .field("identity", &self.identity)
            .field("key", &self.key)
            .finish()
    }
}

impl RegistryCoordinator {
    fn provision(
        mut backend: Box<dyn RegistryBackend>,
        mut counter: Box<dyn CounterBackend>,
        identity: RegistryIdentity,
        key: RegistryAuthenticationKey,
        evidence: &ProvisioningEvidence,
    ) -> Result<Self, RegistryError> {
        let slot_a = backend
            .read_slot(RegistrySlot::A, SLOT_BYTES)
            .map_err(map_backend)?;
        let slot_b = backend
            .read_slot(RegistrySlot::B, SLOT_BYTES)
            .map_err(map_backend)?;
        let saved_manifest = backend.read_manifest(MANIFEST_BYTES).map_err(map_backend)?;
        let counter_identity = counter.identity().map_err(map_counter)?;
        let counter_value = counter.read().map_err(map_counter)?;
        evidence.validate(identity, counter_identity, counter_value)?;
        let target_counter = counter_value
            .checked_add(1)
            .ok_or(RegistryError::Overflow)?;
        let state = RegistryState::genesis(identity, target_counter);
        let slot_bytes = encode_slot(RegistrySlot::A, &state, &key)?;
        let registry_digest = sha256(&slot_bytes);
        match (
            slot_a.as_deref(),
            slot_b.as_deref(),
            saved_manifest.as_deref(),
        ) {
            (None, None, None) => backend
                .write_slot_durable(RegistrySlot::A, &slot_bytes)
                .map_err(map_backend)?,
            (Some(prepared), None, None) if prepared == slot_bytes => {}
            _ => return Err(RegistryError::AlreadyProvisioned),
        }

        let _increment_result = counter.increment_once_for_provisioning(evidence);
        // Provisioning has the same ambiguous-outcome rule as normal commits:
        // never retry here, and trust only the authoritative counter reread.
        let observed_counter = counter.read().map_err(map_counter)?;
        if observed_counter < counter_value {
            return Err(RegistryError::RollbackDetected);
        }
        if observed_counter == counter_value {
            return Err(RegistryError::CounterUnavailable);
        }
        if observed_counter != target_counter {
            return Err(RegistryError::GapDetected);
        }
        let manifest = manifest_for(RegistrySlot::A, &state, registry_digest);
        let manifest_bytes = encode_manifest(manifest, &key)?;
        backend
            .write_manifest_durable(&manifest_bytes)
            .map_err(map_backend)?;
        Ok(Self {
            backend,
            counter,
            identity,
            key,
        })
    }

    fn open(
        backend: Box<dyn RegistryBackend>,
        counter: Box<dyn CounterBackend>,
        identity: RegistryIdentity,
        key: RegistryAuthenticationKey,
    ) -> Result<Self, RegistryError> {
        let mut coordinator = Self {
            backend,
            counter,
            identity,
            key,
        };
        coordinator.load_current()?;
        Ok(coordinator)
    }

    fn load_current(&mut self) -> Result<DecodedSlot, RegistryError> {
        if self.counter.identity().map_err(map_counter)? != self.identity.counter_identity {
            return Err(RegistryError::RollbackDetected);
        }
        let counter_value = self.counter.read().map_err(map_counter)?;
        let slots = [
            self.read_decoded_slot(RegistrySlot::A)?,
            self.read_decoded_slot(RegistrySlot::B)?,
        ];
        let manifest = self
            .backend
            .read_manifest(MANIFEST_BYTES)
            .map_err(map_backend)?
            .map(|bytes| decode_manifest(&bytes, self.identity, &self.key))
            .transpose()?;
        let selected = select_slot(counter_value, &slots, manifest)?;
        let expected_manifest = manifest_for(selected.slot, &selected.state, selected.digest);
        if manifest != Some(expected_manifest) {
            let bytes = encode_manifest(expected_manifest, &self.key)?;
            self.backend
                .write_manifest_durable(&bytes)
                .map_err(map_backend)?;
        }
        Ok(selected)
    }

    fn read_decoded_slot(
        &mut self,
        slot: RegistrySlot,
    ) -> Result<Option<DecodedSlot>, RegistryError> {
        self.backend
            .read_slot(slot, SLOT_BYTES)
            .map_err(map_backend)?
            .map(|bytes| decode_slot(&bytes, slot, self.identity, &self.key))
            .transpose()
    }

    fn load_entry(
        &mut self,
        store: RegistryStore,
        store_id: [u8; 32],
    ) -> Result<Option<AnchorValue>, RegistryError> {
        self.ensure_bound(store, store_id)?;
        self.load_current()?.state.entries[store.index()].anchor()
    }

    fn compare_and_advance(
        &mut self,
        store: RegistryStore,
        store_id: [u8; 32],
        expected: Option<AnchorValue>,
        next: AnchorValue,
    ) -> Result<(), RegistryError> {
        self.ensure_bound(store, store_id)?;
        let current = self.load_current()?;
        let old_entry = current.state.entries[store.index()];
        if old_entry.anchor()? != expected {
            return Err(RegistryError::Conflict);
        }

        let expected_generation = old_entry
            .generation
            .checked_add(1)
            .ok_or(RegistryError::Overflow)?;
        if next.generation() != expected_generation
            || next.record_digest() == ZERO_DIGEST
            || next.manifest_digest() == ZERO_DIGEST
        {
            return Err(RegistryError::RollbackDetected);
        }

        let target_counter = current
            .state
            .physical_counter
            .checked_add(1)
            .ok_or(RegistryError::Overflow)?;
        let target_sequence = current
            .state
            .global_sequence
            .checked_add(1)
            .ok_or(RegistryError::Overflow)?;
        let mut next_state = current.state;
        next_state.physical_counter = target_counter;
        next_state.global_sequence = target_sequence;
        next_state.previous_registry_digest = current.digest;
        next_state.entries[store.index()] = RegistryEntry {
            store,
            store_id,
            present: true,
            generation: next.generation(),
            record_digest: next.record_digest(),
            manifest_digest: next.manifest_digest(),
        };

        let target_slot = current.slot.other();
        let slot_bytes = encode_slot(target_slot, &next_state, &self.key)?;
        let target_digest = sha256(&slot_bytes);
        self.backend
            .write_slot_durable(target_slot, &slot_bytes)
            .map_err(map_backend)?;

        let _increment_result = self.counter.increment_once();
        // Never retry an increment here. Even an error may mean the physical
        // device advanced before its response was lost; this authoritative
        // reread resolves that ambiguity.
        let observed_counter = self.counter.read().map_err(map_counter)?;
        if observed_counter < current.state.physical_counter {
            return Err(RegistryError::RollbackDetected);
        }
        if observed_counter == current.state.physical_counter {
            return Err(RegistryError::CounterUnavailable);
        }
        if observed_counter != target_counter {
            return Err(RegistryError::GapDetected);
        }

        let manifest = manifest_for(target_slot, &next_state, target_digest);
        let manifest_bytes = encode_manifest(manifest, &self.key)?;
        self.backend
            .write_manifest_durable(&manifest_bytes)
            .map_err(map_backend)
    }

    fn ensure_bound(&self, store: RegistryStore, store_id: [u8; 32]) -> Result<(), RegistryError> {
        if self.identity.store_ids.get(store) != store_id {
            return Err(RegistryError::RollbackDetected);
        }
        Ok(())
    }
}

struct RegistryAnchorSet {
    coordinator: Arc<Mutex<RegistryCoordinator>>,
}

impl RegistryAnchorSet {
    fn provision(
        backend: Box<dyn RegistryBackend>,
        counter: Box<dyn CounterBackend>,
        identity: RegistryIdentity,
        key: RegistryAuthenticationKey,
        evidence: &ProvisioningEvidence,
    ) -> Result<Self, RegistryError> {
        Ok(Self {
            coordinator: Arc::new(Mutex::new(RegistryCoordinator::provision(
                backend, counter, identity, key, evidence,
            )?)),
        })
    }

    fn open(
        backend: Box<dyn RegistryBackend>,
        counter: Box<dyn CounterBackend>,
        identity: RegistryIdentity,
        key: RegistryAuthenticationKey,
    ) -> Result<Self, RegistryError> {
        Ok(Self {
            coordinator: Arc::new(Mutex::new(RegistryCoordinator::open(
                backend, counter, identity, key,
            )?)),
        })
    }

    fn bind(
        &self,
        store: RegistryStore,
        store_id: [u8; 32],
    ) -> Result<BoundRollbackAnchor, RegistryError> {
        let coordinator = self
            .coordinator
            .lock()
            .map_err(|_| RegistryError::BackendUnavailable)?;
        coordinator.ensure_bound(store, store_id)?;
        drop(coordinator);
        Ok(BoundRollbackAnchor {
            coordinator: Arc::clone(&self.coordinator),
            store,
            store_id,
        })
    }
}

impl fmt::Debug for RegistryAnchorSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RegistryAnchorSet([REDACTED])")
    }
}

/// A rollback anchor permanently restricted to one fixed registry store ID.
///
/// There is intentionally no public constructor. A future reviewed
/// platform-specific provisioner inside this crate must create the shared
/// global registry and bind each durable store to its one configured ID.
///
/// ```compile_fail
/// use platform_windows::storage::BoundRollbackAnchor;
/// // All fields are private and no public constructor or Default exists.
/// let _anchor = BoundRollbackAnchor {};
/// ```
///
/// ```compile_fail
/// use platform_windows::storage::BoundRollbackAnchor;
/// fn duplicate(anchor: &BoundRollbackAnchor) -> BoundRollbackAnchor {
///     Clone::clone(anchor)
/// }
/// ```
pub struct BoundRollbackAnchor {
    coordinator: Arc<Mutex<RegistryCoordinator>>,
    store: RegistryStore,
    store_id: [u8; 32],
}

impl fmt::Debug for BoundRollbackAnchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundRollbackAnchor")
            .field("coordinator", &"[REDACTED]")
            .field("store", &self.store)
            .field("store_id", &"[REDACTED]")
            .finish()
    }
}

impl RollbackAnchor for BoundRollbackAnchor {
    fn load(&self, store_id: [u8; 32]) -> Result<Option<AnchorValue>, AnchorError> {
        if store_id != self.store_id {
            return Err(AnchorError::Rollback);
        }
        self.coordinator
            .lock()
            .map_err(|_| AnchorError::Unavailable)?
            .load_entry(self.store, self.store_id)
            .map_err(map_anchor_error)
    }

    fn compare_and_advance(
        &self,
        store_id: [u8; 32],
        expected: Option<AnchorValue>,
        next: AnchorValue,
    ) -> Result<(), AnchorError> {
        if store_id != self.store_id {
            return Err(AnchorError::Rollback);
        }
        self.coordinator
            .lock()
            .map_err(|_| AnchorError::Unavailable)?
            .compare_and_advance(self.store, self.store_id, expected, next)
            .map_err(map_anchor_error)
    }
}

fn select_slot(
    counter: u64,
    slots: &[Option<DecodedSlot>; 2],
    manifest: Option<RegistryManifest>,
) -> Result<DecodedSlot, RegistryError> {
    let mut current = None;
    let mut previous = None;
    let mut future = None;

    for decoded in slots.iter().flatten().copied() {
        match decoded.state.physical_counter.cmp(&counter) {
            core::cmp::Ordering::Equal => {
                if current.replace(decoded).is_some() {
                    return Err(RegistryError::SameCounterEquivocation);
                }
            }
            core::cmp::Ordering::Less => {
                if counter - decoded.state.physical_counter > 1 {
                    return Err(RegistryError::GapDetected);
                }
                if previous.is_none_or(|candidate: DecodedSlot| {
                    decoded.state.physical_counter > candidate.state.physical_counter
                }) {
                    previous = Some(decoded);
                }
            }
            core::cmp::Ordering::Greater => {
                let distance = decoded.state.physical_counter - counter;
                if distance != 1 || future.replace(decoded).is_some() {
                    return Err(RegistryError::GapDetected);
                }
            }
        }
    }

    let selected = current.ok_or_else(|| {
        if previous.is_some() || future.is_some() {
            RegistryError::RollbackDetected
        } else {
            RegistryError::MissingRegistry
        }
    })?;

    if let Some(prepared) = future {
        validate_successor(&selected, &prepared)?;
    }

    if let Some(old) = previous {
        validate_successor(&old, &selected)?;
    } else if future.is_none()
        && (selected.state.global_sequence != 1
            || selected.state.previous_registry_digest != ZERO_DIGEST)
    {
        // With only one surviving slot there is no authenticated predecessor or
        // successor proving that a non-genesis state belongs to this history.
        return Err(RegistryError::RollbackDetected);
    }

    if let Some(saved_manifest) = manifest {
        if saved_manifest.physical_counter > counter {
            return Err(RegistryError::RollbackDetected);
        }
        let gap = counter - saved_manifest.physical_counter;
        if gap > 1 {
            return Err(RegistryError::GapDetected);
        }
        if gap == 0 {
            if !manifest_matches(saved_manifest, &selected) {
                return Err(RegistryError::SameCounterEquivocation);
            }
        } else {
            let old = previous.ok_or(RegistryError::RollbackDetected)?;
            if !manifest_matches(saved_manifest, &old) {
                return Err(RegistryError::RollbackDetected);
            }
        }
    }
    Ok(selected)
}

fn validate_successor(old: &DecodedSlot, new: &DecodedSlot) -> Result<(), RegistryError> {
    if old.state.installation_id != new.state.installation_id
        || old.state.key_epoch != new.state.key_epoch
        || old.state.counter_identity != new.state.counter_identity
    {
        return Err(RegistryError::RollbackDetected);
    }
    if old.state.physical_counter.checked_add(1) != Some(new.state.physical_counter)
        || old.state.global_sequence.checked_add(1) != Some(new.state.global_sequence)
    {
        return Err(RegistryError::GapDetected);
    }
    if new.state.previous_registry_digest != old.digest {
        return Err(RegistryError::RollbackDetected);
    }
    let mut changed_entry = None;
    for store in RegistryStore::ALL {
        let old_entry = old.state.entries[store.index()];
        let new_entry = new.state.entries[store.index()];
        if old_entry == new_entry {
            continue;
        }
        if changed_entry.replace(store).is_some()
            || new_entry.store != old_entry.store
            || new_entry.store_id != old_entry.store_id
            || !new_entry.present
            || new_entry.generation != old_entry.generation.checked_add(1).unwrap_or(0)
            || new_entry.record_digest == ZERO_DIGEST
            || new_entry.manifest_digest == ZERO_DIGEST
        {
            return Err(RegistryError::RollbackDetected);
        }
    }
    if changed_entry.is_none() {
        return Err(RegistryError::RollbackDetected);
    }
    Ok(())
}

fn manifest_matches(manifest: RegistryManifest, slot: &DecodedSlot) -> bool {
    manifest.active_slot == slot.slot
        && manifest.installation_id == slot.state.installation_id
        && manifest.key_epoch == slot.state.key_epoch
        && manifest.counter_identity == slot.state.counter_identity
        && manifest.physical_counter == slot.state.physical_counter
        && manifest.global_sequence == slot.state.global_sequence
        && manifest.registry_digest == slot.digest
}

const fn manifest_for(
    active_slot: RegistrySlot,
    state: &RegistryState,
    registry_digest: [u8; 32],
) -> RegistryManifest {
    RegistryManifest {
        active_slot,
        installation_id: state.installation_id,
        key_epoch: state.key_epoch,
        counter_identity: state.counter_identity,
        physical_counter: state.physical_counter,
        global_sequence: state.global_sequence,
        registry_digest,
    }
}

fn encode_slot(
    slot: RegistrySlot,
    state: &RegistryState,
    key: &RegistryAuthenticationKey,
) -> Result<[u8; SLOT_BYTES], RegistryError> {
    let mut bytes = [0_u8; SLOT_BYTES];
    let mut cursor = 0;
    put(&mut bytes[..SLOT_BODY_BYTES], &mut cursor, &SLOT_MAGIC)?;
    put(
        &mut bytes[..SLOT_BODY_BYTES],
        &mut cursor,
        &FORMAT_VERSION.to_be_bytes(),
    )?;
    put(&mut bytes[..SLOT_BODY_BYTES], &mut cursor, &[slot.byte()])?;
    put(
        &mut bytes[..SLOT_BODY_BYTES],
        &mut cursor,
        &[u8::try_from(ENTRY_COUNT).map_err(|_| RegistryError::Overflow)?],
    )?;
    put(&mut bytes[..SLOT_BODY_BYTES], &mut cursor, &[0; 4])?;
    put(
        &mut bytes[..SLOT_BODY_BYTES],
        &mut cursor,
        &state.installation_id,
    )?;
    put(
        &mut bytes[..SLOT_BODY_BYTES],
        &mut cursor,
        &state.key_epoch.to_be_bytes(),
    )?;
    put(
        &mut bytes[..SLOT_BODY_BYTES],
        &mut cursor,
        &state.counter_identity,
    )?;
    put(
        &mut bytes[..SLOT_BODY_BYTES],
        &mut cursor,
        &state.physical_counter.to_be_bytes(),
    )?;
    put(
        &mut bytes[..SLOT_BODY_BYTES],
        &mut cursor,
        &state.global_sequence.to_be_bytes(),
    )?;
    put(
        &mut bytes[..SLOT_BODY_BYTES],
        &mut cursor,
        &state.previous_registry_digest,
    )?;
    for entry in state.entries {
        put(
            &mut bytes[..SLOT_BODY_BYTES],
            &mut cursor,
            &[entry.store as u8, u8::from(entry.present), 0, 0],
        )?;
        put(&mut bytes[..SLOT_BODY_BYTES], &mut cursor, &entry.store_id)?;
        put(
            &mut bytes[..SLOT_BODY_BYTES],
            &mut cursor,
            &entry.generation.to_be_bytes(),
        )?;
        put(
            &mut bytes[..SLOT_BODY_BYTES],
            &mut cursor,
            &entry.record_digest,
        )?;
        put(
            &mut bytes[..SLOT_BODY_BYTES],
            &mut cursor,
            &entry.manifest_digest,
        )?;
    }
    if cursor != SLOT_BODY_BYTES {
        return Err(RegistryError::IntegrityFailure);
    }
    let tag = authenticate(SLOT_MAC_DOMAIN, &bytes[..SLOT_BODY_BYTES], key)?;
    bytes[SLOT_BODY_BYTES..].copy_from_slice(&tag);
    Ok(bytes)
}

fn decode_slot(
    bytes: &[u8],
    expected_slot: RegistrySlot,
    identity: RegistryIdentity,
    key: &RegistryAuthenticationKey,
) -> Result<DecodedSlot, RegistryError> {
    if bytes.len() != SLOT_BYTES {
        return Err(RegistryError::IntegrityFailure);
    }
    verify_mac(
        SLOT_MAC_DOMAIN,
        &bytes[..SLOT_BODY_BYTES],
        &bytes[SLOT_BODY_BYTES..],
        key,
    )?;
    let mut cursor = 0;
    if take::<8>(bytes, &mut cursor)? != SLOT_MAGIC
        || u16::from_be_bytes(take::<2>(bytes, &mut cursor)?) != FORMAT_VERSION
        || RegistrySlot::from_byte(take::<1>(bytes, &mut cursor)?[0])? != expected_slot
        || usize::from(take::<1>(bytes, &mut cursor)?[0]) != ENTRY_COUNT
        || take::<4>(bytes, &mut cursor)? != [0; 4]
    {
        return Err(RegistryError::IntegrityFailure);
    }
    let installation_id = take::<32>(bytes, &mut cursor)?;
    let key_epoch = u64::from_be_bytes(take::<8>(bytes, &mut cursor)?);
    let counter_identity = take::<32>(bytes, &mut cursor)?;
    let physical_counter = u64::from_be_bytes(take::<8>(bytes, &mut cursor)?);
    let global_sequence = u64::from_be_bytes(take::<8>(bytes, &mut cursor)?);
    let previous_registry_digest = take::<32>(bytes, &mut cursor)?;
    let mut entries = RegistryStore::ALL.map(|store| RegistryEntry::absent(store, [0; 32]));
    for entry in &mut entries {
        let header = take::<4>(bytes, &mut cursor)?;
        if header[1] > 1 || header[2..] != [0; 2] {
            return Err(RegistryError::IntegrityFailure);
        }
        *entry = RegistryEntry {
            store: RegistryStore::from_byte(header[0])?,
            present: header[1] == 1,
            store_id: take::<32>(bytes, &mut cursor)?,
            generation: u64::from_be_bytes(take::<8>(bytes, &mut cursor)?),
            record_digest: take::<32>(bytes, &mut cursor)?,
            manifest_digest: take::<32>(bytes, &mut cursor)?,
        };
    }
    if cursor != SLOT_BODY_BYTES {
        return Err(RegistryError::IntegrityFailure);
    }
    let state = RegistryState {
        installation_id,
        key_epoch,
        counter_identity,
        physical_counter,
        global_sequence,
        previous_registry_digest,
        entries,
    };
    state.validate(identity)?;
    Ok(DecodedSlot {
        slot: expected_slot,
        state,
        digest: sha256(bytes),
    })
}

fn encode_manifest(
    manifest: RegistryManifest,
    key: &RegistryAuthenticationKey,
) -> Result<[u8; MANIFEST_BYTES], RegistryError> {
    let mut bytes = [0_u8; MANIFEST_BYTES];
    let mut cursor = 0;
    put(
        &mut bytes[..MANIFEST_BODY_BYTES],
        &mut cursor,
        &MANIFEST_MAGIC,
    )?;
    put(
        &mut bytes[..MANIFEST_BODY_BYTES],
        &mut cursor,
        &FORMAT_VERSION.to_be_bytes(),
    )?;
    put(
        &mut bytes[..MANIFEST_BODY_BYTES],
        &mut cursor,
        &[manifest.active_slot.byte()],
    )?;
    put(&mut bytes[..MANIFEST_BODY_BYTES], &mut cursor, &[0; 5])?;
    put(
        &mut bytes[..MANIFEST_BODY_BYTES],
        &mut cursor,
        &manifest.installation_id,
    )?;
    put(
        &mut bytes[..MANIFEST_BODY_BYTES],
        &mut cursor,
        &manifest.key_epoch.to_be_bytes(),
    )?;
    put(
        &mut bytes[..MANIFEST_BODY_BYTES],
        &mut cursor,
        &manifest.counter_identity,
    )?;
    put(
        &mut bytes[..MANIFEST_BODY_BYTES],
        &mut cursor,
        &manifest.physical_counter.to_be_bytes(),
    )?;
    put(
        &mut bytes[..MANIFEST_BODY_BYTES],
        &mut cursor,
        &manifest.global_sequence.to_be_bytes(),
    )?;
    put(
        &mut bytes[..MANIFEST_BODY_BYTES],
        &mut cursor,
        &manifest.registry_digest,
    )?;
    if cursor != MANIFEST_BODY_BYTES {
        return Err(RegistryError::IntegrityFailure);
    }
    let tag = authenticate(MANIFEST_MAC_DOMAIN, &bytes[..MANIFEST_BODY_BYTES], key)?;
    bytes[MANIFEST_BODY_BYTES..].copy_from_slice(&tag);
    Ok(bytes)
}

fn decode_manifest(
    bytes: &[u8],
    identity: RegistryIdentity,
    key: &RegistryAuthenticationKey,
) -> Result<RegistryManifest, RegistryError> {
    if bytes.len() != MANIFEST_BYTES {
        return Err(RegistryError::IntegrityFailure);
    }
    verify_mac(
        MANIFEST_MAC_DOMAIN,
        &bytes[..MANIFEST_BODY_BYTES],
        &bytes[MANIFEST_BODY_BYTES..],
        key,
    )?;
    let mut cursor = 0;
    if take::<8>(bytes, &mut cursor)? != MANIFEST_MAGIC
        || u16::from_be_bytes(take::<2>(bytes, &mut cursor)?) != FORMAT_VERSION
    {
        return Err(RegistryError::IntegrityFailure);
    }
    let active_slot = RegistrySlot::from_byte(take::<1>(bytes, &mut cursor)?[0])?;
    if take::<5>(bytes, &mut cursor)? != [0; 5] {
        return Err(RegistryError::IntegrityFailure);
    }
    let manifest = RegistryManifest {
        active_slot,
        installation_id: take::<32>(bytes, &mut cursor)?,
        key_epoch: u64::from_be_bytes(take::<8>(bytes, &mut cursor)?),
        counter_identity: take::<32>(bytes, &mut cursor)?,
        physical_counter: u64::from_be_bytes(take::<8>(bytes, &mut cursor)?),
        global_sequence: u64::from_be_bytes(take::<8>(bytes, &mut cursor)?),
        registry_digest: take::<32>(bytes, &mut cursor)?,
    };
    if cursor != MANIFEST_BODY_BYTES
        || manifest.installation_id != identity.installation_id
        || manifest.key_epoch != identity.key_epoch
        || manifest.counter_identity != identity.counter_identity
        || manifest.global_sequence == 0
        || manifest.registry_digest == ZERO_DIGEST
    {
        return Err(RegistryError::RollbackDetected);
    }
    Ok(manifest)
}

fn authenticate(
    domain: &[u8],
    bytes: &[u8],
    key: &RegistryAuthenticationKey,
) -> Result<[u8; MAC_BYTES], RegistryError> {
    let mut mac = HmacSha256::new_from_slice(key.bytes())
        .map_err(|_| RegistryError::InvalidAuthenticationKey)?;
    mac.update(domain);
    mac.update(bytes);
    Ok(mac.finalize().into_bytes().into())
}

fn verify_mac(
    domain: &[u8],
    bytes: &[u8],
    tag: &[u8],
    key: &RegistryAuthenticationKey,
) -> Result<(), RegistryError> {
    let mut mac = HmacSha256::new_from_slice(key.bytes())
        .map_err(|_| RegistryError::InvalidAuthenticationKey)?;
    mac.update(domain);
    mac.update(bytes);
    mac.verify_slice(tag)
        .map_err(|_| RegistryError::IntegrityFailure)
}

fn sha256(bytes: &[u8]) -> [u8; DIGEST_BYTES] {
    Sha256::digest(bytes).into()
}

fn put(target: &mut [u8], cursor: &mut usize, value: &[u8]) -> Result<(), RegistryError> {
    let end = cursor
        .checked_add(value.len())
        .ok_or(RegistryError::Overflow)?;
    let destination = target
        .get_mut(*cursor..end)
        .ok_or(RegistryError::IntegrityFailure)?;
    destination.copy_from_slice(value);
    *cursor = end;
    Ok(())
}

fn take<const LENGTH: usize>(
    source: &[u8],
    cursor: &mut usize,
) -> Result<[u8; LENGTH], RegistryError> {
    let end = cursor.checked_add(LENGTH).ok_or(RegistryError::Overflow)?;
    let source = source
        .get(*cursor..end)
        .ok_or(RegistryError::IntegrityFailure)?;
    let mut value = [0_u8; LENGTH];
    value.copy_from_slice(source);
    *cursor = end;
    Ok(value)
}

const fn map_backend(error: RegistryBackendError) -> RegistryError {
    match error {
        RegistryBackendError::Unavailable => RegistryError::BackendUnavailable,
        RegistryBackendError::BoundsExceeded => RegistryError::IntegrityFailure,
    }
}

const fn map_counter(_: CounterBackendError) -> RegistryError {
    RegistryError::CounterUnavailable
}

const fn map_anchor_error(error: RegistryError) -> AnchorError {
    match error {
        RegistryError::Conflict => AnchorError::Conflict,
        RegistryError::BackendUnavailable | RegistryError::CounterUnavailable => {
            AnchorError::Unavailable
        }
        RegistryError::InvalidIdentity
        | RegistryError::InvalidAuthenticationKey
        | RegistryError::MissingRegistry
        | RegistryError::IntegrityFailure
        | RegistryError::SameCounterEquivocation
        | RegistryError::GapDetected
        | RegistryError::RollbackDetected
        | RegistryError::Overflow
        | RegistryError::AlreadyProvisioned => AnchorError::Rollback,
    }
}

#[cfg(test)]
mod tests;
