//! Rollback-bound local Key Agent settings.
//!
//! This module intentionally has no production [`SettingsStore`] or trusted
//! ceremony implementation. The executable therefore remains fail-closed until
//! a release-reviewed Windows store can prove all of the following together:
//!
//! - the expected installation, store, and record-class identity;
//! - an exclusive process/session owner generation;
//! - authenticated empty or exact record bytes and their digest;
//! - previous-record and non-rollbackable high-water evidence; and
//! - an exact-byte, next-generation durable commit.
//!
//! A generated or rotated anti-phishing phrase is persisted as pending first.
//! It cannot be used in a prompt until a trusted surface presents the exact
//! enrollment or old-to-new rotation ceremony and returns an exact confirmation.

#![cfg_attr(not(test), allow(dead_code))]

use core::fmt;

use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use zeroize::{Zeroize as _, Zeroizing};

const SETTINGS_MAGIC: &[u8; 8] = b"YWSET002";
const SETTINGS_VERSION: u16 = 2;
const SETTINGS_SCHEMA: &[u8; 16] = b"anti-phish-v2\0\0\0";
const SETTINGS_DOMAIN: &[u8] = b"your-wallet/key-agent/local-settings/v2\0";
const SETTINGS_RECORD_CLASS: &[u8; 16] = b"yw-settings-v1\0\0";
const APPROVAL_LEASE_DOMAIN: &[u8] = b"your-wallet/key-agent/settings-approval-lease/v1\0";
const RESERVED_BYTES: usize = 3;
const PHRASE_WORD_COUNT: usize = 5;
const MAX_PHRASE_BYTES: usize = 64;
const SETTINGS_HEADER_BYTES: usize = 82;
const MAX_SETTINGS_BYTES: usize = SETTINGS_HEADER_BYTES + (MAX_PHRASE_BYTES * 2);
const RANDOM_ATTEMPTS: usize = 16;
const STATUS_PENDING_ENROLLMENT: u8 = 1;
const STATUS_READY: u8 = 2;
const STATUS_PENDING_ROTATION: u8 = 3;

// Sixty-four fixed ASCII words give each independently sampled word six bits.
// Five distinct words provide a recognizable local cue while remaining within
// every currently specified helper bound.
const PHRASE_WORDS: [&str; 64] = [
    "amber", "anchor", "apple", "ash", "atlas", "autumn", "bamboo", "beacon", "birch", "breeze",
    "brook", "canyon", "cedar", "cherry", "cloud", "coast", "coral", "crane", "dawn", "delta",
    "dune", "eagle", "elm", "ember", "fern", "field", "finch", "flame", "forest", "frost",
    "garden", "grove", "harbor", "hazel", "heron", "hill", "iris", "island", "jade", "lake",
    "lantern", "leaf", "lemon", "lily", "maple", "meadow", "mint", "moon", "moss", "ocean",
    "olive", "orchid", "otter", "pearl", "pine", "plum", "rain", "raven", "reed", "river", "robin",
    "rose", "sage", "shore",
];

/// A locally generated anti-phishing cue available only inside the Key Agent.
///
/// The type is non-`Clone`, has no externally reachable constructor or raw
/// accessor, and redacts its `Debug` representation.
pub(crate) struct LocalAntiPhishingPhrase(Zeroizing<String>);

impl fmt::Debug for LocalAntiPhishingPhrase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalAntiPhishingPhrase([REDACTED])")
    }
}

impl LocalAntiPhishingPhrase {
    fn from_canonical(value: &str) -> Result<Self, SettingsError> {
        if !is_canonical_phrase(value) {
            return Err(SettingsError::InvalidRecord);
        }
        let mut owned = String::with_capacity(value.len());
        owned.push_str(value);
        Ok(Self(Zeroizing::new(owned)))
    }

    fn generate() -> Result<Self, SettingsError> {
        for _ in 0..RANDOM_ATTEMPTS {
            let mut random = [0_u8; PHRASE_WORD_COUNT];
            getrandom::fill(&mut random).map_err(|_| SettingsError::RandomnessUnavailable)?;
            let indices = random.map(|byte| usize::from(byte & 0x3f));
            random.zeroize();
            if !all_distinct(&indices) {
                continue;
            }

            let phrase_length = indices
                .iter()
                .map(|index| PHRASE_WORDS[*index].len())
                .sum::<usize>()
                .saturating_add(PHRASE_WORD_COUNT - 1);
            if phrase_length > MAX_PHRASE_BYTES {
                return Err(SettingsError::InvalidRecord);
            }
            let mut phrase = String::with_capacity(phrase_length);
            for (position, index) in indices.into_iter().enumerate() {
                if position != 0 {
                    phrase.push(' ');
                }
                phrase.push_str(PHRASE_WORDS[index]);
            }
            if phrase.len() != phrase_length || phrase.capacity() != phrase_length {
                return Err(SettingsError::InvalidRecord);
            }
            if !is_canonical_phrase(&phrase) {
                return Err(SettingsError::InvalidRecord);
            }
            return Ok(Self(Zeroizing::new(phrase)));
        }
        Err(SettingsError::RandomnessUnavailable)
    }

    fn copy_for_prompt(&self) -> String {
        let mut output = String::with_capacity(self.0.len());
        output.push_str(self.0.as_str());
        output
    }

    fn exact_eq(&self, other: &str) -> bool {
        self.0.len() == other.len() && self.0.as_bytes().ct_eq(other.as_bytes()).unwrap_u8() == 1
    }
}

/// Stable, content-free protected-settings failures.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum SettingsError {
    /// Authenticated bytes or their typed evidence were not canonical.
    #[error("local settings record is invalid")]
    InvalidRecord,
    /// A lower generation or authenticated empty state followed an observation.
    #[error("local settings rollback was detected")]
    RollbackDetected,
    /// Two authenticated records claimed the same generation with different bytes.
    #[error("local settings equivocation was detected")]
    EquivocationDetected,
    /// The expected store, installation, or record class changed.
    #[error("local settings store identity changed")]
    StoreIdentityChanged,
    /// The exclusive process/session owner proof changed.
    #[error("local settings owner changed")]
    OwnerChanged,
    /// The settings lifecycle is locked.
    #[error("local settings are locked")]
    Locked,
    /// A phrase has not completed its trusted confirmation ceremony.
    #[error("local settings confirmation is required")]
    ConfirmationRequired,
    /// The trusted surface canceled or did not confirm the exact phrase.
    #[error("local settings confirmation was rejected")]
    ConfirmationRejected,
    /// An approval used an expired, foreign, or already consumed lease.
    #[error("local settings lease is stale")]
    StaleLease,
    /// The operating-system CSPRNG was unavailable.
    #[error("local settings randomness is unavailable")]
    RandomnessUnavailable,
    /// The sealed store could not prove a complete current-state reload.
    #[error("local settings store is unavailable")]
    StoreUnavailable,
    /// A store write may or may not have committed and requires reload.
    #[error("local settings commit outcome is ambiguous")]
    CommitAmbiguous,
}

/// Content-free failures from a sealed authenticated settings store.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum SettingsStoreError {
    /// Stored bytes or authenticated metadata failed verification.
    #[error("settings store integrity verification failed")]
    IntegrityFailure,
    /// The rollback anchor rejected or exposed an older generation.
    #[error("settings store rollback detected")]
    RollbackDetected,
    /// Another writer advanced the authenticated generation.
    #[error("settings store generation conflict")]
    GenerationConflict,
    /// A commit returned after durability became uncertain.
    #[error("settings store commit outcome is ambiguous")]
    CommitAmbiguous,
    /// The exclusive settings owner proof is no longer current.
    #[error("settings store owner changed")]
    OwnerChanged,
    /// Required storage, identity, or anchor evidence was unavailable.
    #[error("settings store is unavailable")]
    Unavailable,
}

/// Exact installation/store/class identity authenticated by the store.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct SettingsStoreIdentity {
    installation_id: [u8; 32],
    store_id: [u8; 32],
    record_class: [u8; 16],
}

impl fmt::Debug for SettingsStoreIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SettingsStoreIdentity([REDACTED])")
    }
}

impl SettingsStoreIdentity {
    #[cfg(test)]
    const fn for_test(installation_id: [u8; 32], store_id: [u8; 32]) -> Self {
        Self {
            installation_id,
            store_id,
            record_class: *SETTINGS_RECORD_CLASS,
        }
    }

    fn is_canonical(self) -> bool {
        self.record_class == *SETTINGS_RECORD_CLASS
            && self.installation_id != [0_u8; 32]
            && self.store_id != [0_u8; 32]
    }
}

/// Exclusive single-process/session ownership authenticated by the store.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct SettingsOwnerEvidence {
    generation: u64,
    nonce: [u8; 32],
}

impl fmt::Debug for SettingsOwnerEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SettingsOwnerEvidence")
            .field("generation", &self.generation)
            .field("nonce", &"[REDACTED]")
            .finish()
    }
}

impl SettingsOwnerEvidence {
    fn is_canonical(self) -> bool {
        self.generation != 0 && self.nonce != [0_u8; 32]
    }
}

/// Previous-record and high-water evidence authenticated with a snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SettingsAnchorEvidence {
    high_water_generation: u64,
    previous_generation: Option<u64>,
    previous_record_digest: Option<[u8; 32]>,
}

impl SettingsAnchorEvidence {
    fn validate_empty(self) -> Result<(), SettingsError> {
        if self.high_water_generation == 0
            && self.previous_generation.is_none()
            && self.previous_record_digest.is_none()
        {
            Ok(())
        } else {
            Err(SettingsError::RollbackDetected)
        }
    }

    fn validate_record(self, generation: u64) -> Result<(), SettingsError> {
        if generation == 0 || self.high_water_generation != generation {
            return Err(SettingsError::RollbackDetected);
        }
        if generation == 1 {
            if self.previous_generation.is_none() && self.previous_record_digest.is_none() {
                return Ok(());
            }
        } else if self.previous_generation == generation.checked_sub(1)
            && self.previous_record_digest.is_some()
        {
            return Ok(());
        }
        Err(SettingsError::InvalidRecord)
    }
}

enum AuthenticatedSettingsPayload {
    Empty,
    Record {
        generation: u64,
        record_digest: [u8; 32],
        bytes: Zeroizing<Vec<u8>>,
    },
}

/// One complete, authenticated, freshly loaded settings snapshot.
pub(crate) struct AuthenticatedSettingsSnapshot {
    identity: SettingsStoreIdentity,
    owner: SettingsOwnerEvidence,
    anchor: SettingsAnchorEvidence,
    payload: AuthenticatedSettingsPayload,
}

impl fmt::Debug for AuthenticatedSettingsSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedSettingsSnapshot")
            .field("identity", &"[REDACTED]")
            .field("owner", &"[REDACTED]")
            .field("anchor", &"[REDACTED]")
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

impl AuthenticatedSettingsSnapshot {
    #[cfg(test)]
    const fn authenticated_empty(
        identity: SettingsStoreIdentity,
        owner: SettingsOwnerEvidence,
        anchor: SettingsAnchorEvidence,
    ) -> Self {
        Self {
            identity,
            owner,
            anchor,
            payload: AuthenticatedSettingsPayload::Empty,
        }
    }

    #[cfg(test)]
    const fn authenticated_record(
        identity: SettingsStoreIdentity,
        owner: SettingsOwnerEvidence,
        anchor: SettingsAnchorEvidence,
        generation: u64,
        record_digest: [u8; 32],
        bytes: Zeroizing<Vec<u8>>,
    ) -> Self {
        Self {
            identity,
            owner,
            anchor,
            payload: AuthenticatedSettingsPayload::Record {
                generation,
                record_digest,
                bytes,
            },
        }
    }
}

/// Exact-byte compare-and-swap request passed to the sealed store.
pub(crate) struct SettingsCommitRequest {
    identity: SettingsStoreIdentity,
    owner: SettingsOwnerEvidence,
    expected_generation: Option<u64>,
    expected_record_digest: Option<[u8; 32]>,
    next_generation: u64,
    record_digest: [u8; 32],
    bytes: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for SettingsCommitRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SettingsCommitRequest([REDACTED EXACT BYTES AND EVIDENCE])")
    }
}

/// Evidence returned only after exact bytes and the next high-water generation
/// are durably committed by the authenticated store.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct SettingsCommitEvidence {
    identity: SettingsStoreIdentity,
    owner: SettingsOwnerEvidence,
    previous_generation: Option<u64>,
    previous_record_digest: Option<[u8; 32]>,
    generation: u64,
    record_digest: [u8; 32],
    high_water_generation: u64,
}

impl fmt::Debug for SettingsCommitEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SettingsCommitEvidence([REDACTED])")
    }
}

/// Authentication, exclusive-owner, freshness, and rollback boundary.
///
/// `load` is deliberately a freshness operation, not a cache accessor. Every
/// lease issue and every lease consumption reloads through this seam. A future
/// implementation must reject a caller whose owner generation is no longer the
/// store's exclusive current owner.
pub(crate) trait SettingsStore: fmt::Debug + sealed::SettingsStoreSealed {
    fn load(&mut self) -> Result<AuthenticatedSettingsSnapshot, SettingsStoreError>;

    fn commit(
        &mut self,
        request: SettingsCommitRequest,
    ) -> Result<SettingsCommitEvidence, SettingsStoreError>;
}

pub(crate) mod sealed {
    pub trait SettingsStoreSealed {}
    pub trait TrustedSettingsPresenterSealed {}
}

/// Which trusted phrase ceremony is being shown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SettingsCeremonyKind {
    Enrollment,
    Rotation,
}

/// Borrowed, exact ceremony data for a trusted Key Agent-owned surface.
#[allow(dead_code)]
pub(crate) struct TrustedSettingsPrompt<'a> {
    kind: SettingsCeremonyKind,
    generation: u64,
    revision: u64,
    record_digest: [u8; 32],
    ceremony_nonce: [u8; 32],
    current_phrase: Option<&'a str>,
    proposed_phrase: &'a str,
}

impl fmt::Debug for TrustedSettingsPrompt<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TrustedSettingsPrompt([REDACTED CEREMONY])")
    }
}

impl<'a> TrustedSettingsPrompt<'a> {
    pub(crate) const fn kind(&self) -> SettingsCeremonyKind {
        self.kind
    }

    pub(crate) const fn current_phrase(&self) -> Option<&'a str> {
        self.current_phrase
    }

    pub(crate) const fn proposed_phrase(&self) -> &'a str {
        self.proposed_phrase
    }
}

/// Exact user-entered confirmation returned by a trusted surface.
///
/// It is non-`Clone`, transcript-bound, zeroized on drop, and constructible only
/// within this crate's sealed trusted-presenter boundary.
pub(crate) struct TrustedSettingsConfirmation {
    kind: SettingsCeremonyKind,
    record_digest: [u8; 32],
    ceremony_nonce: [u8; 32],
    exact_phrase: Zeroizing<String>,
}

impl fmt::Debug for TrustedSettingsConfirmation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TrustedSettingsConfirmation([REDACTED])")
    }
}

impl TrustedSettingsConfirmation {
    pub(crate) fn from_user_input(
        prompt: &TrustedSettingsPrompt<'_>,
        exact_phrase: Zeroizing<String>,
    ) -> Self {
        Self {
            kind: prompt.kind,
            record_digest: prompt.record_digest,
            ceremony_nonce: prompt.ceremony_nonce,
            exact_phrase,
        }
    }
}

/// Stable trusted-surface failure without phrase contents.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("trusted settings ceremony did not complete")]
pub(crate) struct TrustedSettingsPresenterError;

/// Internal trusted UI seam. There is intentionally no production implementor.
pub(crate) trait TrustedSettingsPresenter:
    fmt::Debug + sealed::TrustedSettingsPresenterSealed
{
    fn present_and_confirm(
        &mut self,
        prompt: &TrustedSettingsPrompt<'_>,
    ) -> Result<TrustedSettingsConfirmation, TrustedSettingsPresenterError>;
}

/// User-visible lifecycle without exposing either phrase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProtectedSettingsStatus {
    Locked,
    PendingEnrollment,
    PendingRotation,
    Ready,
}

struct SettingsEpoch {
    generation: u64,
    revision: u64,
    record_digest: [u8; 32],
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct EpochBinding {
    generation: u64,
    revision: u64,
    record_digest: [u8; 32],
}

impl SettingsEpoch {
    const fn binding(&self) -> EpochBinding {
        EpochBinding {
            generation: self.generation,
            revision: self.revision,
            record_digest: self.record_digest,
        }
    }
}

enum SettingsState {
    Invalid,
    PendingEnrollment {
        epoch: SettingsEpoch,
        proposed: LocalAntiPhishingPhrase,
    },
    Ready {
        epoch: SettingsEpoch,
        phrase: LocalAntiPhishingPhrase,
    },
    PendingRotation {
        epoch: SettingsEpoch,
        current: LocalAntiPhishingPhrase,
        proposed: LocalAntiPhishingPhrase,
    },
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ObservedRecord {
    generation: u64,
    digest: [u8; 32],
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ActiveLeaseBinding {
    generation: u64,
    revision: u64,
    record_digest: [u8; 32],
    owner_generation: u64,
    owner_nonce: [u8; 32],
    instance_nonce: [u8; 32],
    lease_nonce: [u8; 32],
    serial: u64,
}

/// Non-clone, one-shot settings epoch carried by an approval prompt.
pub(super) struct LiveSettingsLease {
    generation: u64,
    revision: u64,
    record_digest: [u8; 32],
    owner_generation: u64,
    owner_nonce: [u8; 32],
    instance_nonce: [u8; 32],
    lease_nonce: [u8; 32],
    serial: u64,
}

impl fmt::Debug for LiveSettingsLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LiveSettingsLease([REDACTED ONE-SHOT EPOCH])")
    }
}

impl LiveSettingsLease {
    pub(super) fn bind_request(&self, request_hash: [u8; 32]) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(APPROVAL_LEASE_DOMAIN);
        hash.update(self.generation.to_be_bytes());
        hash.update(self.revision.to_be_bytes());
        hash.update(self.record_digest);
        hash.update(self.owner_generation.to_be_bytes());
        hash.update(self.owner_nonce);
        hash.update(self.instance_nonce);
        hash.update(self.lease_nonce);
        hash.update(self.serial.to_be_bytes());
        hash.update(request_hash);
        digest_array(hash.finalize().as_slice())
    }

    fn matches_active(&self, active: ActiveLeaseBinding) -> bool {
        self.generation == active.generation
            && self.revision == active.revision
            && self.owner_generation == active.owner_generation
            && self.serial == active.serial
            && ct_array_eq(&self.record_digest, &active.record_digest)
            && ct_array_eq(&self.owner_nonce, &active.owner_nonce)
            && ct_array_eq(&self.instance_nonce, &active.instance_nonce)
            && ct_array_eq(&self.lease_nonce, &active.lease_nonce)
    }

    #[cfg(test)]
    fn duplicate_for_test(&self) -> Self {
        Self {
            generation: self.generation,
            revision: self.revision,
            record_digest: self.record_digest,
            owner_generation: self.owner_generation,
            owner_nonce: self.owner_nonce,
            instance_nonce: self.instance_nonce,
            lease_nonce: self.lease_nonce,
            serial: self.serial,
        }
    }
}

impl Drop for LiveSettingsLease {
    fn drop(&mut self) {
        self.generation.zeroize();
        self.revision.zeroize();
        self.record_digest.zeroize();
        self.owner_generation.zeroize();
        self.owner_nonce.zeroize();
        self.instance_nonce.zeroize();
        self.lease_nonce.zeroize();
        self.serial.zeroize();
    }
}

/// Phrase copy needed by the bounded wire request plus its one-shot epoch.
pub(super) struct ApprovalSettingsMaterial {
    phrase: String,
    lease: LiveSettingsLease,
}

impl fmt::Debug for ApprovalSettingsMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApprovalSettingsMaterial([REDACTED])")
    }
}

impl ApprovalSettingsMaterial {
    pub(super) fn into_parts(self) -> (String, LiveSettingsLease) {
        (self.phrase, self.lease)
    }
}

/// Key Agent-owned protected settings lifecycle.
pub(crate) struct ProtectedLocalSettings<S> {
    store: S,
    expected_identity: SettingsStoreIdentity,
    owner: Option<SettingsOwnerEvidence>,
    state: SettingsState,
    highest_authenticated_generation: Option<u64>,
    observed_record: Option<ObservedRecord>,
    instance_nonce: [u8; 32],
    next_lease_serial: u64,
    active_lease: Option<ActiveLeaseBinding>,
}

impl<S> fmt::Debug for ProtectedLocalSettings<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedLocalSettings")
            .field("store", &"[SEALED AUTHENTICATED STORE]")
            .field("state", &self.status())
            .field("identity", &"[REDACTED]")
            .field("owner", &"[REDACTED]")
            .field(
                "highest_authenticated_generation",
                &self.highest_authenticated_generation,
            )
            .field("active_lease", &self.active_lease.is_some())
            .finish_non_exhaustive()
    }
}

impl<S> ProtectedLocalSettings<S> {
    /// Starts locked and generates a process-instance nonce used by every lease.
    pub(crate) fn new(
        store: S,
        expected_identity: SettingsStoreIdentity,
    ) -> Result<Self, SettingsError> {
        if !expected_identity.is_canonical() {
            return Err(SettingsError::StoreIdentityChanged);
        }
        Ok(Self {
            store,
            expected_identity,
            owner: None,
            state: SettingsState::Invalid,
            highest_authenticated_generation: None,
            observed_record: None,
            instance_nonce: fresh_nonce()?,
            next_lease_serial: 0,
            active_lease: None,
        })
    }

    #[must_use]
    pub(crate) const fn status(&self) -> ProtectedSettingsStatus {
        match self.state {
            SettingsState::Invalid => ProtectedSettingsStatus::Locked,
            SettingsState::PendingEnrollment { .. } => ProtectedSettingsStatus::PendingEnrollment,
            SettingsState::Ready { .. } => ProtectedSettingsStatus::Ready,
            SettingsState::PendingRotation { .. } => ProtectedSettingsStatus::PendingRotation,
        }
    }

    /// Explicitly invalidates the phrase and every issued lease.
    pub(crate) fn lock(&mut self) {
        self.active_lease = None;
        self.state = SettingsState::Invalid;
    }

    #[must_use]
    pub(crate) fn into_store(mut self) -> S {
        self.lock();
        self.store
    }

    fn current_epoch_binding(&self) -> Result<EpochBinding, SettingsError> {
        match &self.state {
            SettingsState::Invalid => Err(SettingsError::Locked),
            SettingsState::PendingEnrollment { epoch, .. }
            | SettingsState::Ready { epoch, .. }
            | SettingsState::PendingRotation { epoch, .. } => Ok(epoch.binding()),
        }
    }
}

impl<S: SettingsStore> ProtectedLocalSettings<S> {
    /// Freshly loads the authenticated state, or durably begins enrollment when
    /// the store proves canonical empty state. No generated phrase is exposed.
    pub(crate) fn load_or_begin_enrollment(
        &mut self,
    ) -> Result<ProtectedSettingsStatus, SettingsError> {
        self.lock();
        let snapshot = self.store.load().map_err(map_load_error)?;
        match self.verify_snapshot(snapshot)? {
            VerifiedSnapshot::Empty => self.begin_enrollment()?,
            VerifiedSnapshot::Record { epoch, record } => {
                self.state = state_from_decoded(epoch, record);
            }
        }
        Ok(self.status())
    }

    /// Persists a pending old-to-new rotation. Both the old and new cue remain
    /// unavailable to ordinary prompts until the trusted ceremony completes.
    pub(crate) fn begin_rotation(&mut self) -> Result<ProtectedSettingsStatus, SettingsError> {
        self.revalidate_current_or_lock()?;
        self.active_lease = None;
        let previous = core::mem::replace(&mut self.state, SettingsState::Invalid);
        let (epoch, current) = match previous {
            SettingsState::Ready { epoch, phrase } => (epoch, phrase),
            other => {
                self.state = other;
                return Err(match self.state {
                    SettingsState::PendingEnrollment { .. }
                    | SettingsState::PendingRotation { .. } => SettingsError::ConfirmationRequired,
                    SettingsState::Invalid => SettingsError::Locked,
                    SettingsState::Ready { .. } => SettingsError::InvalidRecord,
                });
            }
        };
        let revision = epoch
            .revision
            .checked_add(1)
            .ok_or(SettingsError::InvalidRecord)?;
        let proposed = generate_distinct_phrase(&current)?;
        let bytes = encode_settings(
            epoch
                .generation
                .checked_add(1)
                .ok_or(SettingsError::InvalidRecord)?,
            revision,
            RecordRef::PendingRotation {
                current: &current,
                proposed: &proposed,
            },
        )?;
        let next_epoch = self.commit_record(Some(epoch.binding()), revision, bytes)?;
        self.state = SettingsState::PendingRotation {
            epoch: next_epoch,
            current,
            proposed,
        };
        Ok(self.status())
    }

    /// Runs the internal trusted confirmation seam and, only after an exact
    /// transcript-bound phrase match, commits the ready state at the next
    /// generation.
    pub(crate) fn confirm_pending<P: TrustedSettingsPresenter>(
        &mut self,
        presenter: &mut P,
    ) -> Result<ProtectedSettingsStatus, SettingsError> {
        self.revalidate_current_or_lock()?;
        self.active_lease = None;
        let ceremony_nonce = fresh_nonce()?;
        let confirmation = {
            let prompt = match &self.state {
                SettingsState::PendingEnrollment { epoch, proposed } => TrustedSettingsPrompt {
                    kind: SettingsCeremonyKind::Enrollment,
                    generation: epoch.generation,
                    revision: epoch.revision,
                    record_digest: epoch.record_digest,
                    ceremony_nonce,
                    current_phrase: None,
                    proposed_phrase: proposed.0.as_str(),
                },
                SettingsState::PendingRotation {
                    epoch,
                    current,
                    proposed,
                } => TrustedSettingsPrompt {
                    kind: SettingsCeremonyKind::Rotation,
                    generation: epoch.generation,
                    revision: epoch.revision,
                    record_digest: epoch.record_digest,
                    ceremony_nonce,
                    current_phrase: Some(current.0.as_str()),
                    proposed_phrase: proposed.0.as_str(),
                },
                SettingsState::Ready { .. } => return Ok(ProtectedSettingsStatus::Ready),
                SettingsState::Invalid => return Err(SettingsError::Locked),
            };
            presenter.present_and_confirm(&prompt)
        };
        let Ok(confirmation) = confirmation else {
            self.lock();
            return Err(SettingsError::ConfirmationRejected);
        };
        if !self.confirmation_matches(&confirmation, ceremony_nonce) {
            self.lock();
            return Err(SettingsError::ConfirmationRejected);
        }

        let previous = core::mem::replace(&mut self.state, SettingsState::Invalid);
        let (SettingsState::PendingEnrollment {
            epoch,
            proposed: ready_phrase,
        }
        | SettingsState::PendingRotation {
            epoch,
            current: _,
            proposed: ready_phrase,
        }) = previous
        else {
            return Err(SettingsError::InvalidRecord);
        };
        let generation = epoch
            .generation
            .checked_add(1)
            .ok_or(SettingsError::InvalidRecord)?;
        let bytes = encode_settings(generation, epoch.revision, RecordRef::Ready(&ready_phrase))?;
        let next_epoch = self.commit_record(Some(epoch.binding()), epoch.revision, bytes)?;
        self.state = SettingsState::Ready {
            epoch: next_epoch,
            phrase: ready_phrase,
        };
        Ok(self.status())
    }

    /// Freshly revalidates ready settings, invalidates any older lease, and
    /// issues one new non-clone approval material object.
    pub(super) fn issue_approval_material(
        &mut self,
    ) -> Result<ApprovalSettingsMaterial, SettingsError> {
        self.revalidate_current_or_lock()?;
        // Beginning a replacement issuance irrevocably retires any older
        // prompt. In particular, RNG failure or serial exhaustion below must
        // not leave the previous approval lease usable.
        self.active_lease = None;
        let (epoch, phrase) = match &self.state {
            SettingsState::Ready { epoch, phrase } => (epoch.binding(), phrase.copy_for_prompt()),
            SettingsState::PendingEnrollment { .. } | SettingsState::PendingRotation { .. } => {
                return Err(SettingsError::ConfirmationRequired);
            }
            SettingsState::Invalid => return Err(SettingsError::Locked),
        };
        let owner = self.owner.ok_or(SettingsError::StoreUnavailable)?;
        let lease_nonce = fresh_nonce()?;
        let serial = self
            .next_lease_serial
            .checked_add(1)
            .ok_or(SettingsError::InvalidRecord)?;
        self.next_lease_serial = serial;
        let active = ActiveLeaseBinding {
            generation: epoch.generation,
            revision: epoch.revision,
            record_digest: epoch.record_digest,
            owner_generation: owner.generation,
            owner_nonce: owner.nonce,
            instance_nonce: self.instance_nonce,
            lease_nonce,
            serial,
        };
        self.active_lease = Some(active);
        Ok(ApprovalSettingsMaterial {
            phrase,
            lease: LiveSettingsLease {
                generation: active.generation,
                revision: active.revision,
                record_digest: active.record_digest,
                owner_generation: active.owner_generation,
                owner_nonce: active.owner_nonce,
                instance_nonce: active.instance_nonce,
                lease_nonce: active.lease_nonce,
                serial: active.serial,
            },
        })
    }

    /// Consumes exactly one live lease after a fresh authenticated store reload.
    /// This is called immediately before authorization and private-key use.
    pub(super) fn revalidate_and_consume_approval(
        &mut self,
        lease: LiveSettingsLease,
        request_hash: [u8; 32],
        settings_binding: [u8; 32],
    ) -> Result<(), SettingsError> {
        let Some(active) = self.active_lease.take() else {
            self.lock();
            return Err(SettingsError::StaleLease);
        };
        let expected_binding = lease.bind_request(request_hash);
        if !lease.matches_active(active) || !ct_array_eq(&expected_binding, &settings_binding) {
            self.lock();
            return Err(SettingsError::StaleLease);
        }

        self.revalidate_current_or_lock()?;
        let current = match &self.state {
            SettingsState::Ready { epoch, .. } => epoch.binding(),
            SettingsState::PendingEnrollment { .. } | SettingsState::PendingRotation { .. } => {
                self.lock();
                return Err(SettingsError::ConfirmationRequired);
            }
            SettingsState::Invalid => return Err(SettingsError::Locked),
        };
        let owner = self.owner.ok_or(SettingsError::StoreUnavailable)?;
        if current.generation != lease.generation
            || current.revision != lease.revision
            || owner.generation != lease.owner_generation
            || !ct_array_eq(&current.record_digest, &lease.record_digest)
            || !ct_array_eq(&owner.nonce, &lease.owner_nonce)
            || !ct_array_eq(&self.instance_nonce, &lease.instance_nonce)
        {
            self.lock();
            return Err(SettingsError::StaleLease);
        }
        // Explicit move-and-drop documents the one-shot capability boundary.
        drop(lease);
        Ok(())
    }

    fn begin_enrollment(&mut self) -> Result<(), SettingsError> {
        let proposed = LocalAntiPhishingPhrase::generate()?;
        let bytes = encode_settings(1, 1, RecordRef::PendingEnrollment(&proposed))?;
        let epoch = self.commit_record(None, 1, bytes)?;
        self.state = SettingsState::PendingEnrollment { epoch, proposed };
        Ok(())
    }

    fn confirmation_matches(
        &self,
        confirmation: &TrustedSettingsConfirmation,
        expected_ceremony_nonce: [u8; 32],
    ) -> bool {
        (match &self.state {
            SettingsState::PendingEnrollment { epoch, proposed } => {
                confirmation.kind == SettingsCeremonyKind::Enrollment
                    && ct_array_eq(&confirmation.record_digest, &epoch.record_digest)
                    && proposed.exact_eq(confirmation.exact_phrase.as_str())
            }
            SettingsState::PendingRotation {
                epoch, proposed, ..
            } => {
                confirmation.kind == SettingsCeremonyKind::Rotation
                    && ct_array_eq(&confirmation.record_digest, &epoch.record_digest)
                    && proposed.exact_eq(confirmation.exact_phrase.as_str())
            }
            SettingsState::Invalid | SettingsState::Ready { .. } => false,
        }) && ct_array_eq(&confirmation.ceremony_nonce, &expected_ceremony_nonce)
    }

    fn revalidate_current_or_lock(&mut self) -> Result<(), SettingsError> {
        let expected = self.current_epoch_binding()?;
        let expected_status = self.status();
        let result = match self.store.load().map_err(map_load_error) {
            Ok(snapshot) => self.verify_snapshot(snapshot),
            Err(error) => Err(error),
        };
        match result {
            Ok(VerifiedSnapshot::Record { epoch, record })
                if epoch.binding() == expected && decoded_status(&record) == expected_status =>
            {
                Ok(())
            }
            Ok(VerifiedSnapshot::Empty | VerifiedSnapshot::Record { .. }) => {
                self.lock();
                Err(SettingsError::StaleLease)
            }
            Err(error) => {
                self.lock();
                Err(error)
            }
        }
    }

    fn verify_snapshot(
        &mut self,
        snapshot: AuthenticatedSettingsSnapshot,
    ) -> Result<VerifiedSnapshot, SettingsError> {
        let AuthenticatedSettingsSnapshot {
            identity,
            owner,
            anchor,
            payload,
        } = snapshot;
        if identity != self.expected_identity || !identity.is_canonical() {
            return Err(SettingsError::StoreIdentityChanged);
        }
        if !owner.is_canonical() {
            return Err(SettingsError::InvalidRecord);
        }
        if self.owner.is_some_and(|expected| expected != owner) {
            return Err(SettingsError::OwnerChanged);
        }

        let verified = match payload {
            AuthenticatedSettingsPayload::Empty => {
                anchor.validate_empty()?;
                if self.highest_authenticated_generation.is_some() || self.observed_record.is_some()
                {
                    return Err(SettingsError::RollbackDetected);
                }
                VerifiedSnapshot::Empty
            }
            AuthenticatedSettingsPayload::Record {
                generation,
                record_digest,
                bytes,
            } => {
                anchor.validate_record(generation)?;
                let exact_digest = sha256_array(bytes.as_slice());
                if !ct_array_eq(&record_digest, &exact_digest) {
                    return Err(SettingsError::InvalidRecord);
                }
                let record = decode_settings(bytes.as_slice(), generation)?;
                self.validate_observation(generation, record_digest, anchor)?;
                self.highest_authenticated_generation = Some(generation);
                self.observed_record = Some(ObservedRecord {
                    generation,
                    digest: record_digest,
                });
                VerifiedSnapshot::Record {
                    epoch: SettingsEpoch {
                        generation,
                        revision: record.revision,
                        record_digest,
                    },
                    record,
                }
            }
        };
        self.owner = Some(owner);
        Ok(verified)
    }

    fn validate_observation(
        &self,
        generation: u64,
        digest: [u8; 32],
        anchor: SettingsAnchorEvidence,
    ) -> Result<(), SettingsError> {
        if self
            .highest_authenticated_generation
            .is_some_and(|highest| generation < highest)
        {
            return Err(SettingsError::RollbackDetected);
        }
        let Some(observed) = self.observed_record else {
            return Ok(());
        };
        if generation < observed.generation {
            return Err(SettingsError::RollbackDetected);
        }
        if generation == observed.generation {
            return if ct_array_eq(&digest, &observed.digest) {
                Ok(())
            } else {
                Err(SettingsError::EquivocationDetected)
            };
        }
        let expected_next = observed
            .generation
            .checked_add(1)
            .ok_or(SettingsError::InvalidRecord)?;
        if generation != expected_next
            || anchor.previous_generation != Some(observed.generation)
            || anchor.previous_record_digest != Some(observed.digest)
        {
            return Err(SettingsError::InvalidRecord);
        }
        Ok(())
    }

    fn commit_record(
        &mut self,
        expected: Option<EpochBinding>,
        revision: u64,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<SettingsEpoch, SettingsError> {
        let owner = self.owner.ok_or(SettingsError::StoreUnavailable)?;
        let expected_generation = expected.map(|value| value.generation);
        let expected_record_digest = expected.map(|value| value.record_digest);
        let next_generation = expected_generation
            .map_or(Some(1), |value| value.checked_add(1))
            .ok_or(SettingsError::InvalidRecord)?;
        let record_digest = sha256_array(bytes.as_slice());
        let request = SettingsCommitRequest {
            identity: self.expected_identity,
            owner,
            expected_generation,
            expected_record_digest,
            next_generation,
            record_digest,
            bytes,
        };
        let evidence = self.store.commit(request).map_err(map_commit_error)?;
        if evidence.identity != self.expected_identity
            || evidence.owner != owner
            || evidence.previous_generation != expected_generation
            || evidence.previous_record_digest != expected_record_digest
            || evidence.generation != next_generation
            || evidence.high_water_generation != next_generation
            || !ct_array_eq(&evidence.record_digest, &record_digest)
        {
            return Err(SettingsError::CommitAmbiguous);
        }
        self.highest_authenticated_generation = Some(next_generation);
        self.observed_record = Some(ObservedRecord {
            generation: next_generation,
            digest: record_digest,
        });
        Ok(SettingsEpoch {
            generation: next_generation,
            revision,
            record_digest,
        })
    }
}

enum VerifiedSnapshot {
    Empty,
    Record {
        epoch: SettingsEpoch,
        record: DecodedSettings,
    },
}

#[derive(Clone, Copy)]
enum RecordRef<'a> {
    PendingEnrollment(&'a LocalAntiPhishingPhrase),
    Ready(&'a LocalAntiPhishingPhrase),
    PendingRotation {
        current: &'a LocalAntiPhishingPhrase,
        proposed: &'a LocalAntiPhishingPhrase,
    },
}

enum DecodedSettingsState {
    PendingEnrollment(LocalAntiPhishingPhrase),
    Ready(LocalAntiPhishingPhrase),
    PendingRotation {
        current: LocalAntiPhishingPhrase,
        proposed: LocalAntiPhishingPhrase,
    },
}

struct DecodedSettings {
    revision: u64,
    state: DecodedSettingsState,
}

fn state_from_decoded(epoch: SettingsEpoch, record: DecodedSettings) -> SettingsState {
    match record.state {
        DecodedSettingsState::PendingEnrollment(proposed) => {
            SettingsState::PendingEnrollment { epoch, proposed }
        }
        DecodedSettingsState::Ready(phrase) => SettingsState::Ready { epoch, phrase },
        DecodedSettingsState::PendingRotation { current, proposed } => {
            SettingsState::PendingRotation {
                epoch,
                current,
                proposed,
            }
        }
    }
}

const fn decoded_status(record: &DecodedSettings) -> ProtectedSettingsStatus {
    match &record.state {
        DecodedSettingsState::PendingEnrollment(_) => ProtectedSettingsStatus::PendingEnrollment,
        DecodedSettingsState::Ready(_) => ProtectedSettingsStatus::Ready,
        DecodedSettingsState::PendingRotation { .. } => ProtectedSettingsStatus::PendingRotation,
    }
}

fn encode_settings(
    generation: u64,
    revision: u64,
    record: RecordRef<'_>,
) -> Result<Zeroizing<Vec<u8>>, SettingsError> {
    if generation == 0 || revision == 0 || revision > generation {
        return Err(SettingsError::InvalidRecord);
    }
    let (status, primary, secondary) = match record {
        RecordRef::PendingEnrollment(proposed) if generation == 1 && revision == 1 => {
            (STATUS_PENDING_ENROLLMENT, proposed.0.as_str(), "")
        }
        RecordRef::Ready(phrase) if is_ready_generation(generation, revision) => {
            (STATUS_READY, phrase.0.as_str(), "")
        }
        RecordRef::PendingRotation { current, proposed }
            if is_pending_rotation_generation(generation, revision)
                && !current.exact_eq(proposed.0.as_str()) =>
        {
            (
                STATUS_PENDING_ROTATION,
                current.0.as_str(),
                proposed.0.as_str(),
            )
        }
        RecordRef::PendingEnrollment(_) | RecordRef::PendingRotation { .. } => {
            return Err(SettingsError::InvalidRecord);
        }
        RecordRef::Ready(_) => return Err(SettingsError::InvalidRecord),
    };
    if !is_canonical_phrase(primary) || (!secondary.is_empty() && !is_canonical_phrase(secondary)) {
        return Err(SettingsError::InvalidRecord);
    }
    let primary_length = u16::try_from(primary.len()).map_err(|_| SettingsError::InvalidRecord)?;
    let secondary_length =
        u16::try_from(secondary.len()).map_err(|_| SettingsError::InvalidRecord)?;
    let exact_length = SETTINGS_HEADER_BYTES
        .checked_add(primary.len())
        .and_then(|value| value.checked_add(secondary.len()))
        .ok_or(SettingsError::InvalidRecord)?;
    if exact_length > MAX_SETTINGS_BYTES {
        return Err(SettingsError::InvalidRecord);
    }

    let mut bytes = Zeroizing::new(Vec::with_capacity(exact_length));
    bytes.extend_from_slice(SETTINGS_MAGIC);
    bytes.extend_from_slice(&SETTINGS_VERSION.to_be_bytes());
    bytes.extend_from_slice(SETTINGS_SCHEMA);
    bytes.extend_from_slice(&Sha256::digest(SETTINGS_DOMAIN));
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes.extend_from_slice(&revision.to_be_bytes());
    bytes.push(status);
    bytes.extend_from_slice(&[0_u8; RESERVED_BYTES]);
    bytes.extend_from_slice(&primary_length.to_be_bytes());
    bytes.extend_from_slice(&secondary_length.to_be_bytes());
    if bytes.len() != SETTINGS_HEADER_BYTES {
        return Err(SettingsError::InvalidRecord);
    }
    bytes.extend_from_slice(primary.as_bytes());
    bytes.extend_from_slice(secondary.as_bytes());
    if bytes.len() != exact_length || bytes.capacity() != exact_length {
        return Err(SettingsError::InvalidRecord);
    }
    Ok(bytes)
}

fn decode_settings(
    bytes: &[u8],
    evidence_generation: u64,
) -> Result<DecodedSettings, SettingsError> {
    if bytes.len() < SETTINGS_HEADER_BYTES || bytes.len() > MAX_SETTINGS_BYTES {
        return Err(SettingsError::InvalidRecord);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take::<8>()? != *SETTINGS_MAGIC
        || cursor.read_u16()? != SETTINGS_VERSION
        || cursor.take::<16>()? != *SETTINGS_SCHEMA
        || cursor.take::<32>()? != Sha256::digest(SETTINGS_DOMAIN).as_slice()
    {
        return Err(SettingsError::InvalidRecord);
    }
    let generation = cursor.read_u64()?;
    let revision = cursor.read_u64()?;
    let status = cursor.read_u8()?;
    if cursor.take::<RESERVED_BYTES>()? != [0_u8; RESERVED_BYTES]
        || generation == 0
        || generation != evidence_generation
        || revision == 0
        || revision > generation
    {
        return Err(SettingsError::InvalidRecord);
    }
    let primary_length = usize::from(cursor.read_u16()?);
    let secondary_length = usize::from(cursor.read_u16()?);
    if primary_length == 0
        || primary_length > MAX_PHRASE_BYTES
        || secondary_length > MAX_PHRASE_BYTES
        || cursor.remaining()
            != primary_length
                .checked_add(secondary_length)
                .ok_or(SettingsError::InvalidRecord)?
    {
        return Err(SettingsError::InvalidRecord);
    }
    let primary = core::str::from_utf8(cursor.take_slice(primary_length)?)
        .map_err(|_| SettingsError::InvalidRecord)?;
    let secondary = core::str::from_utf8(cursor.take_slice(secondary_length)?)
        .map_err(|_| SettingsError::InvalidRecord)?;
    if cursor.remaining() != 0 {
        return Err(SettingsError::InvalidRecord);
    }

    let state = match status {
        STATUS_PENDING_ENROLLMENT if generation == 1 && revision == 1 && secondary.is_empty() => {
            DecodedSettingsState::PendingEnrollment(LocalAntiPhishingPhrase::from_canonical(
                primary,
            )?)
        }
        STATUS_READY if secondary.is_empty() && is_ready_generation(generation, revision) => {
            DecodedSettingsState::Ready(LocalAntiPhishingPhrase::from_canonical(primary)?)
        }
        STATUS_PENDING_ROTATION
            if is_pending_rotation_generation(generation, revision) && !secondary.is_empty() =>
        {
            let current = LocalAntiPhishingPhrase::from_canonical(primary)?;
            let proposed = LocalAntiPhishingPhrase::from_canonical(secondary)?;
            if current.exact_eq(proposed.0.as_str()) {
                return Err(SettingsError::InvalidRecord);
            }
            DecodedSettingsState::PendingRotation { current, proposed }
        }
        _ => return Err(SettingsError::InvalidRecord),
    };
    Ok(DecodedSettings { revision, state })
}

fn is_ready_generation(generation: u64, revision: u64) -> bool {
    revision
        .checked_mul(2)
        .is_some_and(|expected| generation == expected)
}

fn is_pending_rotation_generation(generation: u64, revision: u64) -> bool {
    revision >= 2
        && revision
            .checked_mul(2)
            .and_then(|value| value.checked_sub(1))
            .is_some_and(|expected| generation == expected)
}

fn is_canonical_phrase(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_PHRASE_BYTES || !value.is_ascii() {
        return false;
    }
    let mut words = [""; PHRASE_WORD_COUNT];
    let mut count = 0_usize;
    for word in value.split(' ') {
        if count == PHRASE_WORD_COUNT || word.is_empty() || !PHRASE_WORDS.contains(&word) {
            return false;
        }
        words[count] = word;
        count += 1;
    }
    count == PHRASE_WORD_COUNT && all_distinct_words(&words)
}

fn all_distinct(indices: &[usize; PHRASE_WORD_COUNT]) -> bool {
    indices
        .iter()
        .enumerate()
        .all(|(position, value)| !indices[..position].contains(value))
}

fn all_distinct_words(words: &[&str; PHRASE_WORD_COUNT]) -> bool {
    words
        .iter()
        .enumerate()
        .all(|(position, value)| !words[..position].contains(value))
}

fn generate_distinct_phrase(
    current: &LocalAntiPhishingPhrase,
) -> Result<LocalAntiPhishingPhrase, SettingsError> {
    for _ in 0..RANDOM_ATTEMPTS {
        let proposed = LocalAntiPhishingPhrase::generate()?;
        if !current.exact_eq(proposed.0.as_str()) {
            return Ok(proposed);
        }
    }
    Err(SettingsError::RandomnessUnavailable)
}

fn fresh_nonce() -> Result<[u8; 32], SettingsError> {
    for _ in 0..RANDOM_ATTEMPTS {
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| SettingsError::RandomnessUnavailable)?;
        if nonce != [0_u8; 32] {
            return Ok(nonce);
        }
    }
    Err(SettingsError::RandomnessUnavailable)
}

fn sha256_array(bytes: &[u8]) -> [u8; 32] {
    digest_array(Sha256::digest(bytes).as_slice())
}

fn digest_array(bytes: &[u8]) -> [u8; 32] {
    let mut output = [0_u8; 32];
    output.copy_from_slice(bytes);
    output
}

fn ct_array_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.ct_eq(right).unwrap_u8() == 1
}

fn map_load_error(error: SettingsStoreError) -> SettingsError {
    match error {
        SettingsStoreError::RollbackDetected => SettingsError::RollbackDetected,
        SettingsStoreError::IntegrityFailure => SettingsError::InvalidRecord,
        SettingsStoreError::OwnerChanged => SettingsError::OwnerChanged,
        SettingsStoreError::GenerationConflict
        | SettingsStoreError::CommitAmbiguous
        | SettingsStoreError::Unavailable => SettingsError::StoreUnavailable,
    }
}

const fn map_commit_error(_error: SettingsStoreError) -> SettingsError {
    SettingsError::CommitAmbiguous
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

    fn take<const N: usize>(&mut self) -> Result<[u8; N], SettingsError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(SettingsError::InvalidRecord)?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(SettingsError::InvalidRecord)?;
        let mut output = [0_u8; N];
        output.copy_from_slice(slice);
        self.position = end;
        Ok(output)
    }

    fn take_slice(&mut self, length: usize) -> Result<&'a [u8], SettingsError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(SettingsError::InvalidRecord)?;
        let output = self
            .bytes
            .get(self.position..end)
            .ok_or(SettingsError::InvalidRecord)?;
        self.position = end;
        Ok(output)
    }

    fn read_u8(&mut self) -> Result<u8, SettingsError> {
        Ok(self.take::<1>()?[0])
    }

    fn read_u16(&mut self) -> Result<u16, SettingsError> {
        Ok(u16::from_be_bytes(self.take()?))
    }

    fn read_u64(&mut self) -> Result<u64, SettingsError> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    fn remaining(self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use zeroize::Zeroizing;

    use super::*;

    const FIRST_PHRASE: &str = "amber cedar moon river sage";
    const OTHER_PHRASE: &str = "anchor cloud pine raven shore";

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum CommitMode {
        Normal,
        PersistThenAmbiguous,
        Reject,
        WrongDigestEvidence,
    }

    struct DiskRecord {
        generation: u64,
        digest: [u8; 32],
        bytes: Vec<u8>,
        previous_generation: Option<u64>,
        previous_digest: Option<[u8; 32]>,
    }

    struct FakeDisk {
        identity: SettingsStoreIdentity,
        owner: SettingsOwnerEvidence,
        record: Option<DiskRecord>,
        high_water_generation: u64,
        load_error: Option<SettingsStoreError>,
        commit_mode: CommitMode,
    }

    #[derive(Clone)]
    struct FakeStore {
        disk: Rc<RefCell<FakeDisk>>,
    }

    impl FakeStore {
        fn new() -> Self {
            Self {
                disk: Rc::new(RefCell::new(FakeDisk {
                    identity: identity(),
                    owner: SettingsOwnerEvidence {
                        generation: 1,
                        nonce: [0x31; 32],
                    },
                    record: None,
                    high_water_generation: 0,
                    load_error: None,
                    commit_mode: CommitMode::Normal,
                })),
            }
        }

        fn take_over(&self) -> Result<Self, SettingsError> {
            let mut disk = self.disk.borrow_mut();
            disk.owner.generation = disk
                .owner
                .generation
                .checked_add(1)
                .ok_or(SettingsError::InvalidRecord)?;
            let byte = u8::try_from(disk.owner.generation).unwrap_or(0xa5);
            disk.owner.nonce = [byte; 32];
            Ok(self.clone())
        }

        fn clear_record_but_keep_anchor(&self) {
            self.disk.borrow_mut().record = None;
        }

        fn equivocate_same_generation(&self) -> Result<(), SettingsError> {
            let phrase = LocalAntiPhishingPhrase::from_canonical(OTHER_PHRASE)?;
            let mut disk = self.disk.borrow_mut();
            let record = disk
                .record
                .as_mut()
                .ok_or(SettingsError::StoreUnavailable)?;
            let revision = decode_settings(&record.bytes, record.generation)?.revision;
            let bytes = encode_settings(record.generation, revision, RecordRef::Ready(&phrase))?;
            record.digest = sha256_array(bytes.as_slice());
            record.bytes = bytes.to_vec();
            Ok(())
        }

        fn corrupt_record_digest(&self) {
            if let Some(record) = self.disk.borrow_mut().record.as_mut() {
                record.digest[0] ^= 1;
            }
        }
    }

    impl Default for FakeStore {
        fn default() -> Self {
            Self::new()
        }
    }

    impl fmt::Debug for FakeStore {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("FakeStore([REDACTED])")
        }
    }

    impl sealed::SettingsStoreSealed for FakeStore {}

    impl SettingsStore for FakeStore {
        fn load(&mut self) -> Result<AuthenticatedSettingsSnapshot, SettingsStoreError> {
            let disk = self.disk.borrow();
            if let Some(error) = disk.load_error {
                return Err(error);
            }
            match &disk.record {
                Some(record) => Ok(AuthenticatedSettingsSnapshot::authenticated_record(
                    disk.identity,
                    disk.owner,
                    SettingsAnchorEvidence {
                        high_water_generation: disk.high_water_generation,
                        previous_generation: record.previous_generation,
                        previous_record_digest: record.previous_digest,
                    },
                    record.generation,
                    record.digest,
                    Zeroizing::new(record.bytes.clone()),
                )),
                None => Ok(AuthenticatedSettingsSnapshot::authenticated_empty(
                    disk.identity,
                    disk.owner,
                    SettingsAnchorEvidence {
                        high_water_generation: disk.high_water_generation,
                        previous_generation: None,
                        previous_record_digest: None,
                    },
                )),
            }
        }

        fn commit(
            &mut self,
            request: SettingsCommitRequest,
        ) -> Result<SettingsCommitEvidence, SettingsStoreError> {
            let mut disk = self.disk.borrow_mut();
            if request.identity != disk.identity || request.owner != disk.owner {
                return Err(SettingsStoreError::OwnerChanged);
            }
            let actual_generation = disk.record.as_ref().map(|record| record.generation);
            let actual_digest = disk.record.as_ref().map(|record| record.digest);
            if actual_generation != request.expected_generation
                || actual_digest != request.expected_record_digest
                || request.next_generation
                    != actual_generation
                        .map_or(Some(1), |value| value.checked_add(1))
                        .ok_or(SettingsStoreError::GenerationConflict)?
                || request.record_digest != sha256_array(request.bytes.as_slice())
            {
                return Err(SettingsStoreError::GenerationConflict);
            }
            if disk.commit_mode == CommitMode::Reject {
                return Err(SettingsStoreError::CommitAmbiguous);
            }
            disk.record = Some(DiskRecord {
                generation: request.next_generation,
                digest: request.record_digest,
                bytes: request.bytes.to_vec(),
                previous_generation: actual_generation,
                previous_digest: actual_digest,
            });
            disk.high_water_generation = request.next_generation;
            if disk.commit_mode == CommitMode::PersistThenAmbiguous {
                return Err(SettingsStoreError::CommitAmbiguous);
            }
            let evidence_digest = if disk.commit_mode == CommitMode::WrongDigestEvidence {
                let mut wrong = request.record_digest;
                wrong[0] ^= 1;
                wrong
            } else {
                request.record_digest
            };
            Ok(SettingsCommitEvidence {
                identity: disk.identity,
                owner: disk.owner,
                previous_generation: actual_generation,
                previous_record_digest: actual_digest,
                generation: request.next_generation,
                record_digest: evidence_digest,
                high_water_generation: disk.high_water_generation,
            })
        }
    }

    #[derive(Debug)]
    struct FakePresenter {
        mode: PresenterMode,
        last_kind: Option<SettingsCeremonyKind>,
        last_current: Option<String>,
        last_proposed: Option<String>,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum PresenterMode {
        Exact,
        Wrong,
        Cancel,
    }

    impl FakePresenter {
        const fn exact() -> Self {
            Self {
                mode: PresenterMode::Exact,
                last_kind: None,
                last_current: None,
                last_proposed: None,
            }
        }

        const fn wrong() -> Self {
            Self {
                mode: PresenterMode::Wrong,
                last_kind: None,
                last_current: None,
                last_proposed: None,
            }
        }
    }

    impl sealed::TrustedSettingsPresenterSealed for FakePresenter {}

    impl TrustedSettingsPresenter for FakePresenter {
        fn present_and_confirm(
            &mut self,
            prompt: &TrustedSettingsPrompt<'_>,
        ) -> Result<TrustedSettingsConfirmation, TrustedSettingsPresenterError> {
            self.last_kind = Some(prompt.kind());
            self.last_current = prompt.current_phrase().map(str::to_owned);
            self.last_proposed = Some(prompt.proposed_phrase().to_owned());
            match self.mode {
                PresenterMode::Exact => Ok(TrustedSettingsConfirmation::from_user_input(
                    prompt,
                    Zeroizing::new(prompt.proposed_phrase().to_owned()),
                )),
                PresenterMode::Wrong => Ok(TrustedSettingsConfirmation::from_user_input(
                    prompt,
                    Zeroizing::new(FIRST_PHRASE.to_owned()),
                )),
                PresenterMode::Cancel => Err(TrustedSettingsPresenterError),
            }
        }
    }

    fn identity() -> SettingsStoreIdentity {
        SettingsStoreIdentity::for_test([0x11; 32], [0x22; 32])
    }

    fn confirmed_settings(
        store: FakeStore,
    ) -> Result<ProtectedLocalSettings<FakeStore>, SettingsError> {
        let mut settings = ProtectedLocalSettings::new(store, identity())?;
        assert_eq!(
            settings.load_or_begin_enrollment()?,
            ProtectedSettingsStatus::PendingEnrollment
        );
        assert_eq!(
            settings.confirm_pending(&mut FakePresenter::exact())?,
            ProtectedSettingsStatus::Ready
        );
        Ok(settings)
    }

    #[test]
    fn enrollment_is_persisted_pending_and_unavailable_until_exact_confirmation()
    -> Result<(), SettingsError> {
        let store = FakeStore::new();
        let mut settings = ProtectedLocalSettings::new(store.clone(), identity())?;
        assert_eq!(
            settings.load_or_begin_enrollment()?,
            ProtectedSettingsStatus::PendingEnrollment
        );
        assert!(matches!(
            settings.issue_approval_material(),
            Err(SettingsError::ConfirmationRequired)
        ));
        assert_eq!(store.disk.borrow().high_water_generation, 1);

        let mut presenter = FakePresenter::exact();
        assert_eq!(
            settings.confirm_pending(&mut presenter)?,
            ProtectedSettingsStatus::Ready
        );
        assert_eq!(presenter.last_kind, Some(SettingsCeremonyKind::Enrollment));
        assert!(presenter.last_current.is_none());
        let (phrase, _) = settings.issue_approval_material()?.into_parts();
        assert!(is_canonical_phrase(&phrase));
        assert_eq!(store.disk.borrow().high_water_generation, 2);

        let mut restarted = ProtectedLocalSettings::new(store, identity())?;
        assert_eq!(
            restarted.load_or_begin_enrollment()?,
            ProtectedSettingsStatus::Ready
        );
        Ok(())
    }

    #[test]
    fn pending_enrollment_survives_reload_and_wrong_confirmation_locks() -> Result<(), SettingsError>
    {
        let store = FakeStore::new();
        let mut first = ProtectedLocalSettings::new(store.clone(), identity())?;
        let _ = first.load_or_begin_enrollment()?;

        let mut restarted = ProtectedLocalSettings::new(store.clone(), identity())?;
        assert_eq!(
            restarted.load_or_begin_enrollment()?,
            ProtectedSettingsStatus::PendingEnrollment
        );
        assert!(matches!(
            restarted.confirm_pending(&mut FakePresenter::wrong()),
            Err(SettingsError::ConfirmationRejected)
        ));
        assert_eq!(restarted.status(), ProtectedSettingsStatus::Locked);

        let mut recovered = ProtectedLocalSettings::new(store, identity())?;
        let _ = recovered.load_or_begin_enrollment()?;
        assert_eq!(
            recovered.confirm_pending(&mut FakePresenter::exact())?,
            ProtectedSettingsStatus::Ready
        );
        Ok(())
    }

    #[test]
    fn rotation_is_a_persisted_old_to_new_confirmation_ceremony() -> Result<(), SettingsError> {
        let store = FakeStore::new();
        let mut settings = confirmed_settings(store.clone())?;
        let (old_phrase, _) = settings.issue_approval_material()?.into_parts();
        assert_eq!(
            settings.begin_rotation()?,
            ProtectedSettingsStatus::PendingRotation
        );
        assert!(matches!(
            settings.issue_approval_material(),
            Err(SettingsError::ConfirmationRequired)
        ));
        assert_eq!(store.disk.borrow().high_water_generation, 3);

        let mut presenter = FakePresenter::exact();
        assert_eq!(
            settings.confirm_pending(&mut presenter)?,
            ProtectedSettingsStatus::Ready
        );
        assert_eq!(presenter.last_kind, Some(SettingsCeremonyKind::Rotation));
        assert_eq!(presenter.last_current.as_deref(), Some(old_phrase.as_str()));
        assert_ne!(
            presenter.last_proposed.as_deref(),
            Some(old_phrase.as_str())
        );
        let (new_phrase, _) = settings.issue_approval_material()?.into_parts();
        assert_eq!(
            presenter.last_proposed.as_deref(),
            Some(new_phrase.as_str())
        );
        assert_eq!(store.disk.borrow().high_water_generation, 4);
        Ok(())
    }

    #[test]
    fn lock_and_rotation_invalidate_prepared_approval_leases() -> Result<(), SettingsError> {
        let store = FakeStore::new();
        let mut settings = confirmed_settings(store)?;
        let (_, lease) = settings.issue_approval_material()?.into_parts();
        let stale_after_lock = lease.duplicate_for_test();
        let request_hash = [0x41; 32];
        let binding = lease.bind_request(request_hash);
        settings.lock();
        assert!(matches!(
            settings.revalidate_and_consume_approval(stale_after_lock, request_hash, binding),
            Err(SettingsError::StaleLease)
        ));

        let _ = settings.load_or_begin_enrollment()?;
        let (_, lease) = settings.issue_approval_material()?.into_parts();
        let stale_after_rotation = lease.duplicate_for_test();
        let binding = lease.bind_request(request_hash);
        let _ = settings.begin_rotation()?;
        assert!(matches!(
            settings.revalidate_and_consume_approval(stale_after_rotation, request_hash, binding),
            Err(SettingsError::StaleLease)
        ));
        Ok(())
    }

    #[test]
    fn failed_replacement_issuance_invalidates_the_older_lease() -> Result<(), SettingsError> {
        let store = FakeStore::new();
        let mut settings = confirmed_settings(store)?;
        let (_, older_lease) = settings.issue_approval_material()?.into_parts();
        let request_hash = [0x49; 32];
        let binding = older_lease.bind_request(request_hash);

        settings.next_lease_serial = u64::MAX;
        assert!(matches!(
            settings.issue_approval_material(),
            Err(SettingsError::InvalidRecord)
        ));
        assert!(matches!(
            settings.revalidate_and_consume_approval(older_lease, request_hash, binding),
            Err(SettingsError::StaleLease)
        ));
        Ok(())
    }

    #[test]
    fn approval_lease_is_one_shot_and_bound_to_request_hash() -> Result<(), SettingsError> {
        let store = FakeStore::new();
        let mut settings = confirmed_settings(store)?;
        let (_, lease) = settings.issue_approval_material()?.into_parts();
        let replay = lease.duplicate_for_test();
        let request_hash = [0x51; 32];
        let binding = lease.bind_request(request_hash);
        settings.revalidate_and_consume_approval(lease, request_hash, binding)?;
        assert!(matches!(
            settings.revalidate_and_consume_approval(replay, request_hash, binding),
            Err(SettingsError::StaleLease)
        ));
        Ok(())
    }

    #[test]
    fn owner_takeover_and_cross_instance_prompt_use_fail_closed() -> Result<(), SettingsError> {
        let store = FakeStore::new();
        let mut first = confirmed_settings(store.clone())?;
        let (_, lease) = first.issue_approval_material()?.into_parts();
        let cross_instance = lease.duplicate_for_test();
        let request_hash = [0x61; 32];
        let binding = lease.bind_request(request_hash);

        let mut peer = ProtectedLocalSettings::new(store.clone(), identity())?;
        assert_eq!(
            peer.load_or_begin_enrollment()?,
            ProtectedSettingsStatus::Ready
        );
        assert!(matches!(
            peer.revalidate_and_consume_approval(cross_instance, request_hash, binding),
            Err(SettingsError::StaleLease)
        ));

        let restarted_store = store.take_over()?;
        let mut restarted = ProtectedLocalSettings::new(restarted_store, identity())?;
        assert_eq!(
            restarted.load_or_begin_enrollment()?,
            ProtectedSettingsStatus::Ready
        );
        assert!(matches!(
            first.revalidate_and_consume_approval(lease, request_hash, binding),
            Err(SettingsError::OwnerChanged)
        ));
        assert_eq!(first.status(), ProtectedSettingsStatus::Locked);
        Ok(())
    }

    #[test]
    fn same_generation_equivocation_and_empty_after_observed_are_rejected()
    -> Result<(), SettingsError> {
        let store = FakeStore::new();
        let mut settings = confirmed_settings(store.clone())?;
        store.equivocate_same_generation()?;
        assert!(matches!(
            settings.load_or_begin_enrollment(),
            Err(SettingsError::EquivocationDetected)
        ));

        let store = FakeStore::new();
        let mut settings = confirmed_settings(store.clone())?;
        store.clear_record_but_keep_anchor();
        assert!(matches!(
            settings.load_or_begin_enrollment(),
            Err(SettingsError::RollbackDetected)
        ));
        Ok(())
    }

    #[test]
    fn exact_record_digest_and_commit_evidence_are_mandatory() -> Result<(), SettingsError> {
        let store = FakeStore::new();
        let mut settings = confirmed_settings(store.clone())?;
        store.corrupt_record_digest();
        assert!(matches!(
            settings.load_or_begin_enrollment(),
            Err(SettingsError::InvalidRecord)
        ));

        let store = FakeStore::new();
        store.disk.borrow_mut().commit_mode = CommitMode::WrongDigestEvidence;
        let mut settings = ProtectedLocalSettings::new(store, identity())?;
        assert!(matches!(
            settings.load_or_begin_enrollment(),
            Err(SettingsError::CommitAmbiguous)
        ));
        assert_eq!(settings.status(), ProtectedSettingsStatus::Locked);
        Ok(())
    }

    #[test]
    fn ambiguous_commit_never_exposes_phrase_until_authenticated_reload()
    -> Result<(), SettingsError> {
        let store = FakeStore::new();
        store.disk.borrow_mut().commit_mode = CommitMode::PersistThenAmbiguous;
        let mut settings = ProtectedLocalSettings::new(store.clone(), identity())?;
        assert!(matches!(
            settings.load_or_begin_enrollment(),
            Err(SettingsError::CommitAmbiguous)
        ));
        assert_eq!(settings.status(), ProtectedSettingsStatus::Locked);
        assert_eq!(store.disk.borrow().high_water_generation, 1);

        store.disk.borrow_mut().commit_mode = CommitMode::Normal;
        assert_eq!(
            settings.load_or_begin_enrollment()?,
            ProtectedSettingsStatus::PendingEnrollment
        );
        Ok(())
    }

    #[test]
    fn strict_codec_rejects_unknown_fields_and_trailing_bytes() -> Result<(), SettingsError> {
        let phrase = LocalAntiPhishingPhrase::from_canonical(FIRST_PHRASE)?;
        let canonical = encode_settings(2, 1, RecordRef::Ready(&phrase))?;
        let mut cases = Vec::new();

        let mut forged_ready_without_confirmation =
            encode_settings(1, 1, RecordRef::PendingEnrollment(&phrase))?.to_vec();
        forged_ready_without_confirmation[74] = STATUS_READY;
        assert!(matches!(
            decode_settings(&forged_ready_without_confirmation, 1),
            Err(SettingsError::InvalidRecord)
        ));

        let mut wrong_generation_schedule = canonical.to_vec();
        wrong_generation_schedule[58..66].copy_from_slice(&3_u64.to_be_bytes());
        assert!(matches!(
            decode_settings(&wrong_generation_schedule, 3),
            Err(SettingsError::InvalidRecord)
        ));

        let mut unknown_version = canonical.to_vec();
        unknown_version[8..10].copy_from_slice(&SETTINGS_VERSION.saturating_add(1).to_be_bytes());
        cases.push(unknown_version);

        let mut unknown_schema = canonical.to_vec();
        unknown_schema[10] ^= 1;
        cases.push(unknown_schema);

        let mut wrong_domain = canonical.to_vec();
        wrong_domain[26] ^= 1;
        cases.push(wrong_domain);

        let mut reserved = canonical.to_vec();
        reserved[75] = 1;
        cases.push(reserved);

        let mut trailing = canonical.to_vec();
        trailing.push(0);
        cases.push(trailing);

        for bytes in cases {
            assert!(matches!(
                decode_settings(&bytes, 2),
                Err(SettingsError::InvalidRecord)
            ));
        }
        Ok(())
    }

    #[test]
    fn debug_outputs_never_include_phrase_or_authenticated_identifiers() -> Result<(), SettingsError>
    {
        let phrase = LocalAntiPhishingPhrase::from_canonical(FIRST_PHRASE)?;
        assert_eq!(format!("{phrase:?}"), "LocalAntiPhishingPhrase([REDACTED])");
        let settings = ProtectedLocalSettings::new(FakeStore::new(), identity())?;
        let debug = format!("{settings:?}");
        assert!(!debug.contains(FIRST_PHRASE));
        assert!(debug.contains("[SEALED AUTHENTICATED STORE]"));
        let _store = settings.into_store();
        Ok(())
    }

    #[test]
    fn store_errors_and_canceled_ceremony_remain_locked() -> Result<(), SettingsError> {
        for (store_error, expected) in [
            (
                SettingsStoreError::IntegrityFailure,
                SettingsError::InvalidRecord,
            ),
            (
                SettingsStoreError::RollbackDetected,
                SettingsError::RollbackDetected,
            ),
            (
                SettingsStoreError::OwnerChanged,
                SettingsError::OwnerChanged,
            ),
            (
                SettingsStoreError::Unavailable,
                SettingsError::StoreUnavailable,
            ),
        ] {
            let store = FakeStore::new();
            store.disk.borrow_mut().load_error = Some(store_error);
            let mut settings = ProtectedLocalSettings::new(store, identity())?;
            assert!(
                matches!(settings.load_or_begin_enrollment(), Err(actual) if actual == expected)
            );
            assert_eq!(settings.status(), ProtectedSettingsStatus::Locked);
        }

        let store = FakeStore::new();
        let mut settings = ProtectedLocalSettings::new(store, identity())?;
        let _ = settings.load_or_begin_enrollment()?;
        let mut presenter = FakePresenter {
            mode: PresenterMode::Cancel,
            last_kind: None,
            last_current: None,
            last_proposed: None,
        };
        assert!(matches!(
            settings.confirm_pending(&mut presenter),
            Err(SettingsError::ConfirmationRejected)
        ));
        assert_eq!(settings.status(), ProtectedSettingsStatus::Locked);
        Ok(())
    }
}
