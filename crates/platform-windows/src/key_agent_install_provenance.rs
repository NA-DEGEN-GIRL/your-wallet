//! Fail-closed model for trusted Key Agent installation provenance.
//!
//! This module is deliberately pure: it performs no profile, filesystem,
//! registry, cryptographic-provider, or serialization I/O. It defines the
//! canonical authenticated-journal codec and validates an independently
//! authenticated checkpoint. Its internal observation is constructed only
//! from the typed, authority-free snapshot copied by the LPAC held-object
//! boundary. Production currently has no key, checkpoint, journal, or held OS
//! observation source. Journal absence/read failure,
//! malformed bytes, authentication failure, rollback, gaps, or equivocation
//! therefore cannot mint classifier inputs. Until a future installer-owned
//! adapter supplies those sealed facts, there is no production adoption path.

use core::fmt;
use core::marker::PhantomData;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::key_agent_lpac::{KEY_AGENT_PROFILE_V1_NAME, KeyAgentHeldInstallObservation};
use crate::key_agent_storage::KeyAgentStorageRootIdentity;

const INSTALL_JOURNAL_SCHEMA_V1: u16 = 1;
// Policy v1 means the compiled fixed profile name and derived SID, compiled
// fixed storage leaf, stable TokenUser owner, exact dual-principal protected
// DACL, inherited Low/NW label, local fixed NTFS volume, full FILE_ID_INFO, and
// selector-free held-object observation rules. A future adapter must satisfy the
// whole policy before sealing an observation; this pure model cannot prove it.
const INSTALL_POLICY_V1: u16 = 1;
const MAX_PROFILE_NAME_BYTES: usize = 64;
const IDENTITY_BYTES: usize = 32;
const MAX_CANONICAL_SID_BYTES: usize = 68;
const INSTALL_JOURNAL_DIGEST_BYTES: usize = 32;
const INSTALL_JOURNAL_MAC_BYTES: usize = 32;
const INSTALL_JOURNAL_AUTHENTICATION_KEY_BYTES: usize = 32;
const COMMITTED_JOURNAL_GENERATION_V1: u64 = 4;
const INSTALL_JOURNAL_RECORD_MAGIC_V1: [u8; 8] = *b"YWKAIJ01";
const INSTALL_JOURNAL_RECORD_DIGEST_DOMAIN_V1: &[u8] =
    b"your-wallet/key-agent-install/record-digest/v1\0";
const INSTALL_JOURNAL_RECORD_MAC_DOMAIN_V1: &[u8] =
    b"your-wallet/key-agent-install/record-mac/v1\0";
const INSTALL_CHECKPOINT_COMMITMENT_DOMAIN_V1: &[u8] =
    b"your-wallet/key-agent-install/checkpoint/v1\0";

const RECORD_MAGIC_OFFSET: usize = 0;
const RECORD_SCHEMA_OFFSET: usize = 8;
const RECORD_POLICY_OFFSET: usize = 10;
const RECORD_STATE_OFFSET: usize = 12;
const RECORD_HEADER_RESERVED_OFFSET: usize = 13;
const RECORD_HEADER_RESERVED_BYTES: usize = 3;
const RECORD_GENERATION_OFFSET: usize = 16;
const RECORD_TRANSACTION_ID_OFFSET: usize = 24;
const RECORD_INSTALLATION_ID_OFFSET: usize = 56;
const RECORD_RELEASE_IDENTITY_OFFSET: usize = 88;
const RECORD_PREDECESSOR_DIGEST_OFFSET: usize = 120;
const RECORD_PROFILE_NAME_LEN_OFFSET: usize = 152;
const RECORD_PROFILE_NAME_OFFSET: usize = 153;
const RECORD_PROFILE_SID_LEN_OFFSET: usize = 217;
const RECORD_PROFILE_SID_OFFSET: usize = 218;
const RECORD_STABLE_USER_SID_LEN_OFFSET: usize = 286;
const RECORD_STABLE_USER_SID_OFFSET: usize = 287;
const RECORD_ROOT_IDENTITY_OFFSET: usize = 355;
const RECORD_TAIL_RESERVED_OFFSET: usize = 379;
const RECORD_TAIL_RESERVED_BYTES: usize = 5;
const INSTALL_JOURNAL_RECORD_BODY_BYTES: usize = 384;
const INSTALL_JOURNAL_RECORD_BYTES: usize =
    INSTALL_JOURNAL_RECORD_BODY_BYTES + INSTALL_JOURNAL_MAC_BYTES;
const RECORD_MAC_OFFSET: usize = INSTALL_JOURNAL_RECORD_BODY_BYTES;
const PROFILE_PAYLOAD_OFFSET: usize = RECORD_PROFILE_NAME_LEN_OFFSET;
const PROFILE_PAYLOAD_BYTES: usize =
    RECORD_STABLE_USER_SID_LEN_OFFSET - RECORD_PROFILE_NAME_LEN_OFFSET;
const ROOT_PAYLOAD_OFFSET: usize = RECORD_STABLE_USER_SID_LEN_OFFSET;
const ROOT_PAYLOAD_BYTES: usize = RECORD_TAIL_RESERVED_OFFSET - RECORD_STABLE_USER_SID_LEN_OFFSET;

type InstallerJournalHmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyAgentInstallTransactionState {
    Prepared,
    ProfileCreated,
    RootCreated,
    Committed,
}

struct KeyAgentInstallCommonRecord {
    schema_version: u16,
    policy_version: u16,
    journal_generation: u64,
    transaction_id: [u8; IDENTITY_BYTES],
    installation_id: [u8; IDENTITY_BYTES],
    release_identity: [u8; IDENTITY_BYTES],
    predecessor_digest: [u8; INSTALL_JOURNAL_DIGEST_BYTES],
}

struct KeyAgentInstallProfileEvidence {
    name_len: u8,
    name: [u8; MAX_PROFILE_NAME_BYTES],
    sid: CanonicalSidEvidence,
}

struct KeyAgentInstallRootEvidence {
    stable_user_sid: CanonicalSidEvidence,
    root_identity: KeyAgentStorageRootIdentity,
}

enum KeyAgentInstallRecord {
    Prepared {
        common: KeyAgentInstallCommonRecord,
    },
    ProfileCreated {
        common: KeyAgentInstallCommonRecord,
        profile: KeyAgentInstallProfileEvidence,
    },
    RootCreated {
        common: KeyAgentInstallCommonRecord,
        profile: KeyAgentInstallProfileEvidence,
        root: KeyAgentInstallRootEvidence,
    },
    Committed {
        common: KeyAgentInstallCommonRecord,
        profile: KeyAgentInstallProfileEvidence,
        root: KeyAgentInstallRootEvidence,
    },
}

#[derive(Eq, PartialEq)]
struct CanonicalSidEvidence {
    len: u8,
    bytes: [u8; MAX_CANONICAL_SID_BYTES],
}

struct ObservedKeyAgentProfile {
    name_len: u8,
    name: [u8; MAX_PROFILE_NAME_BYTES],
    sid: CanonicalSidEvidence,
}

struct ObservedKeyAgentStorageRoot {
    identity: KeyAgentStorageRootIdentity,
    stable_user_sid: CanonicalSidEvidence,
    profile_sid: CanonicalSidEvidence,
}

struct JournalEvidenceSeal;
struct ExpectedIdentitySeal;
struct OsObservationSeal;
struct CheckpointEvidenceSeal;
struct InstallerJournalAuthenticationKeySeal;

enum KeyAgentInstallJournalValidationError {
    InvalidAuthenticationKey,
    Authentication,
    Encoding,
    History,
    Checkpoint,
}

/// Installer-owned journal authentication material.
///
/// The key is zeroized on drop, thread-affine, and has no production
/// constructor. A future protected installer backend must mint it without
/// exposing raw key bytes or permitting caller-selected authentication.
struct InstallerJournalAuthenticationKey {
    bytes: Zeroizing<[u8; INSTALL_JOURNAL_AUTHENTICATION_KEY_BYTES]>,
    _seal: InstallerJournalAuthenticationKeySeal,
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl fmt::Debug for InstallerJournalAuthenticationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InstallerJournalAuthenticationKey([REDACTED])")
    }
}

/// Independently authenticated rollback checkpoint for the installer journal.
///
/// The commitment binds the high-water generation, current authenticated
/// record digest, and independently expected installation/release identities.
/// The type has no production constructor or persistence backend.
struct AuthenticatedKeyAgentInstallCheckpoint {
    high_water_generation: u64,
    current_record_digest: [u8; INSTALL_JOURNAL_DIGEST_BYTES],
    installation_id: [u8; IDENTITY_BYTES],
    release_identity: [u8; IDENTITY_BYTES],
    commitment: [u8; INSTALL_JOURNAL_DIGEST_BYTES],
    _seal: CheckpointEvidenceSeal,
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl fmt::Debug for AuthenticatedKeyAgentInstallCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedKeyAgentInstallCheckpoint([REDACTED])")
    }
}

/// Authenticated observation of the installer-owned provenance journal.
///
/// Private fields and the unnameable seal prevent sibling modules from
/// asserting that arbitrary bytes were authenticated. The pure decoder can
/// mint this only after the complete MAC, history, and checkpoint validation;
/// production has no key/checkpoint constructor or journal reader for it.
pub(crate) struct AuthenticatedKeyAgentInstallJournal {
    authenticated_generation: u64,
    record: Option<KeyAgentInstallRecord>,
    _seal: JournalEvidenceSeal,
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl fmt::Debug for AuthenticatedKeyAgentInstallJournal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedKeyAgentInstallJournal([REDACTED])")
    }
}

/// One complete journal/checkpoint validation result.
///
/// The current authenticated record digest is retained so an independently
/// reread snapshot can be compared after the held OS observation. Production
/// has no reader capable of constructing this value.
pub(crate) struct AuthenticatedKeyAgentInstallSnapshot {
    journal: AuthenticatedKeyAgentInstallJournal,
    expected: ExpectedKeyAgentInstallIdentities,
    current_record_digest: [u8; INSTALL_JOURNAL_DIGEST_BYTES],
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl fmt::Debug for AuthenticatedKeyAgentInstallSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedKeyAgentInstallSnapshot([REDACTED])")
    }
}

/// Installation and release identities from trust domains independent of the journal.
///
/// This distinct sealed input prevents the pure classifier contract from
/// treating journal-derived identifiers as independently expected. Production
/// has no source for it.
pub(crate) struct ExpectedKeyAgentInstallIdentities {
    installation_id: [u8; IDENTITY_BYTES],
    release_identity: [u8; IDENTITY_BYTES],
    _seal: ExpectedIdentitySeal,
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl fmt::Debug for ExpectedKeyAgentInstallIdentities {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExpectedKeyAgentInstallIdentities([REDACTED])")
    }
}

/// Internal fixed-profile-binding and held-root observation record.
///
/// The type alone does not prove an OS-registered profile, exact root security,
/// local NTFS, or a retained no-delete-share handle. Its sole compiled
/// constructor consumes authority-free evidence copied from the typed held
/// aggregate. Production has no authoritative profile-registration observer or
/// constructor for that aggregate, and the dormant existing-root opener has no
/// production caller.
pub(crate) struct ObservedKeyAgentInstallObjects {
    profile: Option<ObservedKeyAgentProfile>,
    root: Option<ObservedKeyAgentStorageRoot>,
    _seal: OsObservationSeal,
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl fmt::Debug for ObservedKeyAgentInstallObjects {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ObservedKeyAgentInstallObjects([REDACTED])")
    }
}

/// Non-authoritative evidence that no installation objects were observed.
///
/// This candidate does not authorize object creation. A future trusted
/// installer must independently serialize and anchor its own fresh transaction.
pub(crate) struct UninitializedKeyAgentInstallCandidate {
    installation_id: [u8; IDENTITY_BYTES],
    release_identity: [u8; IDENTITY_BYTES],
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl fmt::Debug for UninitializedKeyAgentInstallCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.installation_id, &self.release_identity);
        formatter.write_str("UninitializedKeyAgentInstallCandidate([REDACTED])")
    }
}

/// Non-authoritative consistency result for one existing installation.
///
/// This candidate proves only consistency among the sealed facts supplied to
/// this pure model. It is not an adoption or launch capability, and no
/// direct production conversion to `PreparedKeyAgentProvisioning` exists. In
/// particular, it retains no root handle and cannot cross an observation/open
/// race as authority.
pub(crate) struct ConsistentExistingKeyAgentInstallCandidate {
    installation_id: [u8; IDENTITY_BYTES],
    release_identity: [u8; IDENTITY_BYTES],
    root_identity: KeyAgentStorageRootIdentity,
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl fmt::Debug for ConsistentExistingKeyAgentInstallCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.installation_id,
            &self.release_identity,
            &self.root_identity,
        );
        formatter.write_str("ConsistentExistingKeyAgentInstallCandidate([REDACTED])")
    }
}

/// Closed result of the trusted installation-provenance classifier.
pub(crate) enum KeyAgentInstallDisposition {
    /// No journal, profile, or root exists under independently expected IDs.
    Uninitialized(UninitializedKeyAgentInstallCandidate),
    /// A committed journal and both live objects were internally consistent.
    ConsistentExisting(ConsistentExistingKeyAgentInstallCandidate),
    /// Any partial, stale, malformed, mismatched, or pending state.
    RecoveryRequired,
}

impl fmt::Debug for KeyAgentInstallDisposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uninitialized(_) => {
                formatter.write_str("KeyAgentInstallDisposition::Uninitialized([REDACTED])")
            }
            Self::ConsistentExisting(_) => {
                formatter.write_str("KeyAgentInstallDisposition::ConsistentExisting([REDACTED])")
            }
            Self::RecoveryRequired => {
                formatter.write_str("KeyAgentInstallDisposition::RecoveryRequired")
            }
        }
    }
}

/// Classifies one authenticated journal observation and one sealed live snapshot.
///
/// Only an authenticated absence with no surviving objects yields an
/// uninitialized candidate. An exact committed record with both matching
/// objects is only a consistent candidate. Neither grants adoption authority.
/// Every other state requires a separate trusted recovery ceremony; this
/// function never repairs, deletes, creates, opens, or mutates anything.
// All three sealed observations are intentionally consumed. Accepting a borrow
// would permit an authority-bearing observation to be classified more than once.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn classify_key_agent_install(
    journal: AuthenticatedKeyAgentInstallJournal,
    expected: ExpectedKeyAgentInstallIdentities,
    objects: ObservedKeyAgentInstallObjects,
) -> KeyAgentInstallDisposition {
    let expected_installation_id = expected.installation_id;
    let expected_release_identity = expected.release_identity;
    if !valid_identity(&expected_installation_id)
        || !valid_identity(&expected_release_identity)
        || expected_installation_id == expected_release_identity
    {
        return KeyAgentInstallDisposition::RecoveryRequired;
    }

    match (journal.record, objects.profile, objects.root) {
        (None, None, None) if journal.authenticated_generation == 0 => {
            KeyAgentInstallDisposition::Uninitialized(UninitializedKeyAgentInstallCandidate {
                installation_id: expected_installation_id,
                release_identity: expected_release_identity,
                _not_send_or_sync: PhantomData,
            })
        }
        (Some(record), Some(profile), Some(root))
            if journal.authenticated_generation == record_common(&record).journal_generation
                && exact_committed_match(
                    &record,
                    &profile,
                    &root,
                    &expected_installation_id,
                    &expected_release_identity,
                ) =>
        {
            match record {
                KeyAgentInstallRecord::Committed {
                    common,
                    root: journal_root,
                    ..
                } => KeyAgentInstallDisposition::ConsistentExisting(
                    ConsistentExistingKeyAgentInstallCandidate {
                        installation_id: common.installation_id,
                        release_identity: common.release_identity,
                        root_identity: journal_root.root_identity,
                        _not_send_or_sync: PhantomData,
                    },
                ),
                _ => KeyAgentInstallDisposition::RecoveryRequired,
            }
        }
        _ => KeyAgentInstallDisposition::RecoveryRequired,
    }
}

/// Pure proof that two independently authenticated snapshots and one supplied
/// authority-free OS observation describe the same committed installation.
///
/// This value retains no profile, root handle, path, or launch authority. Only
/// the sibling adoption module can combine it with the still-held OS objects.
#[must_use = "stable existing-install evidence must remain bound to held objects"]
pub(crate) struct StableExistingKeyAgentInstallEvidence {
    installation_id: [u8; IDENTITY_BYTES],
    release_identity: [u8; IDENTITY_BYTES],
    root_identity: KeyAgentStorageRootIdentity,
    journal_generation: u64,
    journal_record_digest: [u8; INSTALL_JOURNAL_DIGEST_BYTES],
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl fmt::Debug for StableExistingKeyAgentInstallEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StableExistingKeyAgentInstallEvidence([REDACTED])")
    }
}

/// Consumes the handle-free proof into the exact fields retained by the
/// adoption aggregate. The root identity remains intentionally unexported: it
/// was already bound to the consumed held observation by the verifier.
/// Passing by value is intentional so the sealed evidence remains one-shot.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn consume_stable_existing_key_agent_install_evidence(
    evidence: StableExistingKeyAgentInstallEvidence,
) -> (
    [u8; IDENTITY_BYTES],
    [u8; IDENTITY_BYTES],
    u64,
    [u8; INSTALL_JOURNAL_DIGEST_BYTES],
) {
    (
        evidence.installation_id,
        evidence.release_identity,
        evidence.journal_generation,
        evidence.journal_record_digest,
    )
}

/// Compares the initial and post-observation authenticated snapshots, then
/// runs the exact committed classifier over canonical held-object evidence.
///
/// The function is pure and consumes both one-shot snapshots. Its sole
/// production caller is the private adoption transition, which must retain and
/// revalidate the corresponding OS capabilities around this call.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn verify_existing_key_agent_install_snapshots(
    initial: AuthenticatedKeyAgentInstallSnapshot,
    reread: AuthenticatedKeyAgentInstallSnapshot,
    observation: KeyAgentHeldInstallObservation,
) -> Option<StableExistingKeyAgentInstallEvidence> {
    let journal_generation = initial.journal.authenticated_generation;
    let journal_record_digest = initial.current_record_digest;
    let installation_id = initial.expected.installation_id;
    let release_identity = initial.expected.release_identity;
    if journal_generation != COMMITTED_JOURNAL_GENERATION_V1
        || !valid_digest(&journal_record_digest)
        || !same_authenticated_install_snapshot(&initial, &reread)
    {
        return None;
    }

    let root_identity = observation.storage_root_identity();
    let objects = observed_install_objects_from_canonical(&observation)?;
    let disposition = classify_key_agent_install(initial.journal, initial.expected, objects);
    let KeyAgentInstallDisposition::ConsistentExisting(candidate) = disposition else {
        return None;
    };
    if candidate.installation_id != installation_id
        || candidate.release_identity != release_identity
        || candidate.root_identity != root_identity
    {
        return None;
    }

    Some(StableExistingKeyAgentInstallEvidence {
        installation_id,
        release_identity,
        root_identity,
        journal_generation,
        journal_record_digest,
        _not_send_or_sync: PhantomData,
    })
}

fn same_authenticated_install_snapshot(
    initial: &AuthenticatedKeyAgentInstallSnapshot,
    reread: &AuthenticatedKeyAgentInstallSnapshot,
) -> bool {
    initial.journal.authenticated_generation == reread.journal.authenticated_generation
        && initial.current_record_digest == reread.current_record_digest
        && initial.expected.installation_id == reread.expected.installation_id
        && initial.expected.release_identity == reread.expected.release_identity
}

fn observed_install_objects_from_canonical(
    observation: &KeyAgentHeldInstallObservation,
) -> Option<ObservedKeyAgentInstallObjects> {
    let fixed_name = KEY_AGENT_PROFILE_V1_NAME.as_bytes();
    let name_len = u8::try_from(fixed_name.len()).ok()?;
    let mut name = [0_u8; MAX_PROFILE_NAME_BYTES];
    name.get_mut(..fixed_name.len())?
        .copy_from_slice(fixed_name);
    Some(ObservedKeyAgentInstallObjects {
        profile: Some(ObservedKeyAgentProfile {
            name_len,
            name,
            sid: canonical_observed_sid(observation.profile_sid())?,
        }),
        root: Some(ObservedKeyAgentStorageRoot {
            identity: observation.storage_root_identity(),
            stable_user_sid: canonical_observed_sid(observation.stable_user_sid())?,
            profile_sid: canonical_observed_sid(observation.storage_profile_sid())?,
        }),
        _seal: OsObservationSeal,
        _not_send_or_sync: PhantomData,
    })
}

fn canonical_observed_sid(observed: &[u8]) -> Option<CanonicalSidEvidence> {
    let len = u8::try_from(observed.len()).ok()?;
    let mut bytes = [0_u8; MAX_CANONICAL_SID_BYTES];
    bytes.get_mut(..observed.len())?.copy_from_slice(observed);
    let sid = CanonicalSidEvidence { len, bytes };
    if !valid_canonical_sid(&sid) {
        return None;
    }
    Some(sid)
}

fn exact_committed_match(
    record: &KeyAgentInstallRecord,
    profile: &ObservedKeyAgentProfile,
    root: &ObservedKeyAgentStorageRoot,
    expected_installation_id: &[u8; IDENTITY_BYTES],
    expected_release_identity: &[u8; IDENTITY_BYTES],
) -> bool {
    let KeyAgentInstallRecord::Committed {
        common,
        profile: record_profile,
        root: record_root,
    } = record
    else {
        return false;
    };

    valid_install_record(record)
        && common.installation_id == *expected_installation_id
        && common.release_identity == *expected_release_identity
        && exact_fixed_profile_name(record_profile.name_len, &record_profile.name)
        && exact_fixed_profile_name(profile.name_len, &profile.name)
        && profile.sid == record_profile.sid
        && root.identity == record_root.root_identity
        && root.stable_user_sid == record_root.stable_user_sid
        && root.profile_sid == record_profile.sid
}

fn record_common(record: &KeyAgentInstallRecord) -> &KeyAgentInstallCommonRecord {
    match record {
        KeyAgentInstallRecord::Prepared { common }
        | KeyAgentInstallRecord::ProfileCreated { common, .. }
        | KeyAgentInstallRecord::RootCreated { common, .. }
        | KeyAgentInstallRecord::Committed { common, .. } => common,
    }
}

fn record_profile(record: &KeyAgentInstallRecord) -> Option<&KeyAgentInstallProfileEvidence> {
    match record {
        KeyAgentInstallRecord::Prepared { .. } => None,
        KeyAgentInstallRecord::ProfileCreated { profile, .. }
        | KeyAgentInstallRecord::RootCreated { profile, .. }
        | KeyAgentInstallRecord::Committed { profile, .. } => Some(profile),
    }
}

fn record_root(record: &KeyAgentInstallRecord) -> Option<&KeyAgentInstallRootEvidence> {
    match record {
        KeyAgentInstallRecord::Prepared { .. } | KeyAgentInstallRecord::ProfileCreated { .. } => {
            None
        }
        KeyAgentInstallRecord::RootCreated { root, .. }
        | KeyAgentInstallRecord::Committed { root, .. } => Some(root),
    }
}

const fn record_state(record: &KeyAgentInstallRecord) -> KeyAgentInstallTransactionState {
    match record {
        KeyAgentInstallRecord::Prepared { .. } => KeyAgentInstallTransactionState::Prepared,
        KeyAgentInstallRecord::ProfileCreated { .. } => {
            KeyAgentInstallTransactionState::ProfileCreated
        }
        KeyAgentInstallRecord::RootCreated { .. } => KeyAgentInstallTransactionState::RootCreated,
        KeyAgentInstallRecord::Committed { .. } => KeyAgentInstallTransactionState::Committed,
    }
}

fn valid_install_record(record: &KeyAgentInstallRecord) -> bool {
    let state = record_state(record);
    let common = record_common(record);
    if common.schema_version != INSTALL_JOURNAL_SCHEMA_V1
        || common.policy_version != INSTALL_POLICY_V1
        || common.journal_generation != transaction_generation(state)
        || !valid_identity(&common.transaction_id)
        || !valid_identity(&common.installation_id)
        || !valid_identity(&common.release_identity)
        || common.transaction_id == common.installation_id
        || common.transaction_id == common.release_identity
        || common.installation_id == common.release_identity
        || (state == KeyAgentInstallTransactionState::Prepared
            && common.predecessor_digest != [0; INSTALL_JOURNAL_DIGEST_BYTES])
        || (state != KeyAgentInstallTransactionState::Prepared
            && !valid_digest(&common.predecessor_digest))
    {
        return false;
    }

    let profile_valid = record_profile(record).is_none_or(|profile| {
        exact_fixed_profile_name(profile.name_len, &profile.name)
            && valid_canonical_sid(&profile.sid)
    });
    let root_valid = record_root(record).is_none_or(|root| {
        valid_canonical_sid(&root.stable_user_sid)
            && record_profile(record).is_some_and(|profile| root.stable_user_sid != profile.sid)
    });
    profile_valid && root_valid
}

fn encode_install_journal_record_body(
    record: &KeyAgentInstallRecord,
) -> Result<[u8; INSTALL_JOURNAL_RECORD_BODY_BYTES], KeyAgentInstallJournalValidationError> {
    if !valid_install_record(record) {
        return Err(KeyAgentInstallJournalValidationError::Encoding);
    }

    let mut encoded = [0_u8; INSTALL_JOURNAL_RECORD_BODY_BYTES];
    let common = record_common(record);
    encoded[RECORD_MAGIC_OFFSET..RECORD_SCHEMA_OFFSET]
        .copy_from_slice(&INSTALL_JOURNAL_RECORD_MAGIC_V1);
    encoded[RECORD_SCHEMA_OFFSET..RECORD_POLICY_OFFSET]
        .copy_from_slice(&common.schema_version.to_be_bytes());
    encoded[RECORD_POLICY_OFFSET..RECORD_STATE_OFFSET]
        .copy_from_slice(&common.policy_version.to_be_bytes());
    encoded[RECORD_STATE_OFFSET] = transaction_state_tag(record_state(record));
    encoded[RECORD_GENERATION_OFFSET..RECORD_TRANSACTION_ID_OFFSET]
        .copy_from_slice(&common.journal_generation.to_be_bytes());
    encoded[RECORD_TRANSACTION_ID_OFFSET..RECORD_INSTALLATION_ID_OFFSET]
        .copy_from_slice(&common.transaction_id);
    encoded[RECORD_INSTALLATION_ID_OFFSET..RECORD_RELEASE_IDENTITY_OFFSET]
        .copy_from_slice(&common.installation_id);
    encoded[RECORD_RELEASE_IDENTITY_OFFSET..RECORD_PREDECESSOR_DIGEST_OFFSET]
        .copy_from_slice(&common.release_identity);
    encoded[RECORD_PREDECESSOR_DIGEST_OFFSET..RECORD_PROFILE_NAME_LEN_OFFSET]
        .copy_from_slice(&common.predecessor_digest);

    if let Some(profile) = record_profile(record) {
        encoded[RECORD_PROFILE_NAME_LEN_OFFSET] = profile.name_len;
        encoded[RECORD_PROFILE_NAME_OFFSET..RECORD_PROFILE_SID_LEN_OFFSET]
            .copy_from_slice(&profile.name);
        encoded[RECORD_PROFILE_SID_LEN_OFFSET] = profile.sid.len;
        encoded[RECORD_PROFILE_SID_OFFSET..RECORD_STABLE_USER_SID_LEN_OFFSET]
            .copy_from_slice(&profile.sid.bytes);
    }
    if let Some(root) = record_root(record) {
        encoded[RECORD_STABLE_USER_SID_LEN_OFFSET] = root.stable_user_sid.len;
        encoded[RECORD_STABLE_USER_SID_OFFSET..RECORD_ROOT_IDENTITY_OFFSET]
            .copy_from_slice(&root.stable_user_sid.bytes);
        encoded[RECORD_ROOT_IDENTITY_OFFSET..RECORD_TAIL_RESERVED_OFFSET]
            .copy_from_slice(&root.root_identity.encode_be());
    }
    Ok(encoded)
}

fn decode_install_journal_common(
    encoded: &[u8; INSTALL_JOURNAL_RECORD_BODY_BYTES],
) -> Result<
    (KeyAgentInstallCommonRecord, KeyAgentInstallTransactionState),
    KeyAgentInstallJournalValidationError,
> {
    let schema_version = u16::from_be_bytes([
        encoded[RECORD_SCHEMA_OFFSET],
        encoded[RECORD_SCHEMA_OFFSET + 1],
    ]);
    let policy_version = u16::from_be_bytes([
        encoded[RECORD_POLICY_OFFSET],
        encoded[RECORD_POLICY_OFFSET + 1],
    ]);
    let transaction_state = decode_transaction_state_tag(encoded[RECORD_STATE_OFFSET])?;
    let journal_generation = u64::from_be_bytes([
        encoded[RECORD_GENERATION_OFFSET],
        encoded[RECORD_GENERATION_OFFSET + 1],
        encoded[RECORD_GENERATION_OFFSET + 2],
        encoded[RECORD_GENERATION_OFFSET + 3],
        encoded[RECORD_GENERATION_OFFSET + 4],
        encoded[RECORD_GENERATION_OFFSET + 5],
        encoded[RECORD_GENERATION_OFFSET + 6],
        encoded[RECORD_GENERATION_OFFSET + 7],
    ]);
    let mut transaction_id = [0_u8; IDENTITY_BYTES];
    transaction_id
        .copy_from_slice(&encoded[RECORD_TRANSACTION_ID_OFFSET..RECORD_INSTALLATION_ID_OFFSET]);
    let mut installation_id = [0_u8; IDENTITY_BYTES];
    installation_id
        .copy_from_slice(&encoded[RECORD_INSTALLATION_ID_OFFSET..RECORD_RELEASE_IDENTITY_OFFSET]);
    let mut release_identity = [0_u8; IDENTITY_BYTES];
    release_identity.copy_from_slice(
        &encoded[RECORD_RELEASE_IDENTITY_OFFSET..RECORD_PREDECESSOR_DIGEST_OFFSET],
    );
    let mut predecessor_digest = [0_u8; INSTALL_JOURNAL_DIGEST_BYTES];
    predecessor_digest.copy_from_slice(
        &encoded[RECORD_PREDECESSOR_DIGEST_OFFSET..RECORD_PROFILE_NAME_LEN_OFFSET],
    );
    let common = KeyAgentInstallCommonRecord {
        schema_version,
        policy_version,
        journal_generation,
        transaction_id,
        installation_id,
        release_identity,
        predecessor_digest,
    };
    Ok((common, transaction_state))
}

fn decode_install_journal_profile(
    encoded: &[u8; INSTALL_JOURNAL_RECORD_BODY_BYTES],
) -> KeyAgentInstallProfileEvidence {
    let mut profile_name = [0_u8; MAX_PROFILE_NAME_BYTES];
    profile_name
        .copy_from_slice(&encoded[RECORD_PROFILE_NAME_OFFSET..RECORD_PROFILE_SID_LEN_OFFSET]);
    let mut profile_sid_bytes = [0_u8; MAX_CANONICAL_SID_BYTES];
    profile_sid_bytes
        .copy_from_slice(&encoded[RECORD_PROFILE_SID_OFFSET..RECORD_STABLE_USER_SID_LEN_OFFSET]);
    KeyAgentInstallProfileEvidence {
        name_len: encoded[RECORD_PROFILE_NAME_LEN_OFFSET],
        name: profile_name,
        sid: CanonicalSidEvidence {
            len: encoded[RECORD_PROFILE_SID_LEN_OFFSET],
            bytes: profile_sid_bytes,
        },
    }
}

fn decode_install_journal_root(
    encoded: &[u8; INSTALL_JOURNAL_RECORD_BODY_BYTES],
) -> Result<KeyAgentInstallRootEvidence, KeyAgentInstallJournalValidationError> {
    let mut stable_user_sid_bytes = [0_u8; MAX_CANONICAL_SID_BYTES];
    stable_user_sid_bytes
        .copy_from_slice(&encoded[RECORD_STABLE_USER_SID_OFFSET..RECORD_ROOT_IDENTITY_OFFSET]);
    let mut root_identity = [0_u8; 24];
    root_identity
        .copy_from_slice(&encoded[RECORD_ROOT_IDENTITY_OFFSET..RECORD_TAIL_RESERVED_OFFSET]);
    Ok(KeyAgentInstallRootEvidence {
        stable_user_sid: CanonicalSidEvidence {
            len: encoded[RECORD_STABLE_USER_SID_LEN_OFFSET],
            bytes: stable_user_sid_bytes,
        },
        root_identity: KeyAgentStorageRootIdentity::decode_be(root_identity)
            .map_err(|_| KeyAgentInstallJournalValidationError::Encoding)?,
    })
}

fn decode_install_journal_record_body(
    encoded: &[u8; INSTALL_JOURNAL_RECORD_BODY_BYTES],
) -> Result<KeyAgentInstallRecord, KeyAgentInstallJournalValidationError> {
    if encoded[RECORD_MAGIC_OFFSET..RECORD_SCHEMA_OFFSET] != INSTALL_JOURNAL_RECORD_MAGIC_V1
        || encoded[RECORD_HEADER_RESERVED_OFFSET
            ..RECORD_HEADER_RESERVED_OFFSET + RECORD_HEADER_RESERVED_BYTES]
            != [0; RECORD_HEADER_RESERVED_BYTES]
        || encoded
            [RECORD_TAIL_RESERVED_OFFSET..RECORD_TAIL_RESERVED_OFFSET + RECORD_TAIL_RESERVED_BYTES]
            != [0; RECORD_TAIL_RESERVED_BYTES]
    {
        return Err(KeyAgentInstallJournalValidationError::Encoding);
    }

    let (common, transaction_state) = decode_install_journal_common(encoded)?;
    let record = match transaction_state {
        KeyAgentInstallTransactionState::Prepared => KeyAgentInstallRecord::Prepared { common },
        KeyAgentInstallTransactionState::ProfileCreated => KeyAgentInstallRecord::ProfileCreated {
            common,
            profile: decode_install_journal_profile(encoded),
        },
        KeyAgentInstallTransactionState::RootCreated => KeyAgentInstallRecord::RootCreated {
            common,
            profile: decode_install_journal_profile(encoded),
            root: decode_install_journal_root(encoded)?,
        },
        KeyAgentInstallTransactionState::Committed => KeyAgentInstallRecord::Committed {
            common,
            profile: decode_install_journal_profile(encoded),
            root: decode_install_journal_root(encoded)?,
        },
    };

    let canonical = encode_install_journal_record_body(&record)?;
    if canonical != *encoded {
        return Err(KeyAgentInstallJournalValidationError::Encoding);
    }
    Ok(record)
}

fn verify_install_journal_record_mac(
    body: &[u8; INSTALL_JOURNAL_RECORD_BODY_BYTES],
    tag: &[u8],
    key: &[u8; INSTALL_JOURNAL_AUTHENTICATION_KEY_BYTES],
) -> Result<(), KeyAgentInstallJournalValidationError> {
    let mut mac = InstallerJournalHmacSha256::new_from_slice(key)
        .map_err(|_| KeyAgentInstallJournalValidationError::InvalidAuthenticationKey)?;
    mac.update(INSTALL_JOURNAL_RECORD_MAC_DOMAIN_V1);
    mac.update(body);
    mac.verify_slice(tag)
        .map_err(|_| KeyAgentInstallJournalValidationError::Authentication)
}

fn decode_authenticated_install_journal_record(
    encoded: &[u8; INSTALL_JOURNAL_RECORD_BYTES],
    key: &[u8; INSTALL_JOURNAL_AUTHENTICATION_KEY_BYTES],
) -> Result<KeyAgentInstallRecord, KeyAgentInstallJournalValidationError> {
    let mut body = [0_u8; INSTALL_JOURNAL_RECORD_BODY_BYTES];
    body.copy_from_slice(&encoded[..RECORD_MAC_OFFSET]);
    verify_install_journal_record_mac(&body, &encoded[RECORD_MAC_OFFSET..], key)?;
    decode_install_journal_record_body(&body)
}

fn authenticated_install_journal_record_digest(
    encoded: &[u8; INSTALL_JOURNAL_RECORD_BYTES],
) -> [u8; INSTALL_JOURNAL_DIGEST_BYTES] {
    let mut digest = Sha256::new();
    digest.update(INSTALL_JOURNAL_RECORD_DIGEST_DOMAIN_V1);
    digest.update(encoded);
    digest.finalize().into()
}

fn install_checkpoint_commitment(
    high_water_generation: u64,
    current_record_digest: &[u8; INSTALL_JOURNAL_DIGEST_BYTES],
    installation_id: &[u8; IDENTITY_BYTES],
    release_identity: &[u8; IDENTITY_BYTES],
) -> [u8; INSTALL_JOURNAL_DIGEST_BYTES] {
    let mut digest = Sha256::new();
    digest.update(INSTALL_CHECKPOINT_COMMITMENT_DOMAIN_V1);
    digest.update(INSTALL_JOURNAL_SCHEMA_V1.to_be_bytes());
    digest.update(INSTALL_POLICY_V1.to_be_bytes());
    digest.update(high_water_generation.to_be_bytes());
    digest.update(current_record_digest);
    digest.update(installation_id);
    digest.update(release_identity);
    digest.finalize().into()
}

fn bind_install_journal_phase_payload(
    index: usize,
    body: &[u8],
    profile_payload: &mut Option<[u8; PROFILE_PAYLOAD_BYTES]>,
    root_payload: &mut Option<[u8; ROOT_PAYLOAD_BYTES]>,
) -> Result<(), KeyAgentInstallJournalValidationError> {
    if index >= 1 {
        let mut current = [0_u8; PROFILE_PAYLOAD_BYTES];
        current.copy_from_slice(
            &body[PROFILE_PAYLOAD_OFFSET..PROFILE_PAYLOAD_OFFSET + PROFILE_PAYLOAD_BYTES],
        );
        if profile_payload.is_some_and(|first| current != first) {
            return Err(KeyAgentInstallJournalValidationError::History);
        }
        if profile_payload.is_none() {
            *profile_payload = Some(current);
        }
    }
    if index >= 2 {
        let mut current = [0_u8; ROOT_PAYLOAD_BYTES];
        current
            .copy_from_slice(&body[ROOT_PAYLOAD_OFFSET..ROOT_PAYLOAD_OFFSET + ROOT_PAYLOAD_BYTES]);
        if root_payload.is_some_and(|first| current != first) {
            return Err(KeyAgentInstallJournalValidationError::History);
        }
        if root_payload.is_none() {
            *root_payload = Some(current);
        }
    }
    Ok(())
}

fn validate_nonempty_install_journal_history(
    encoded_journal: &[u8],
    authentication_key: &[u8; INSTALL_JOURNAL_AUTHENTICATION_KEY_BYTES],
    high_water_generation: u64,
    current_record_digest: &[u8; INSTALL_JOURNAL_DIGEST_BYTES],
    installation_id: &[u8; IDENTITY_BYTES],
    release_identity: &[u8; IDENTITY_BYTES],
) -> Result<KeyAgentInstallRecord, KeyAgentInstallJournalValidationError> {
    let record_count = usize::try_from(high_water_generation)
        .map_err(|_| KeyAgentInstallJournalValidationError::Checkpoint)?;
    let expected_bytes = record_count
        .checked_mul(INSTALL_JOURNAL_RECORD_BYTES)
        .ok_or(KeyAgentInstallJournalValidationError::Checkpoint)?;
    if encoded_journal.len() != expected_bytes {
        return Err(KeyAgentInstallJournalValidationError::History);
    }

    let mut previous_digest = [0_u8; INSTALL_JOURNAL_DIGEST_BYTES];
    let mut transaction_id = None;
    let mut profile_payload = None;
    let mut root_payload = None;
    let mut current_record = None;
    for index in 0..record_count {
        let offset = index * INSTALL_JOURNAL_RECORD_BYTES;
        let mut encoded_record = [0_u8; INSTALL_JOURNAL_RECORD_BYTES];
        encoded_record
            .copy_from_slice(&encoded_journal[offset..offset + INSTALL_JOURNAL_RECORD_BYTES]);
        let record =
            decode_authenticated_install_journal_record(&encoded_record, authentication_key)?;
        let expected_state = transaction_state_for_index(index)
            .ok_or(KeyAgentInstallJournalValidationError::History)?;
        let common = record_common(&record);
        if record_state(&record) != expected_state
            || common.journal_generation
                != u64::try_from(index + 1)
                    .map_err(|_| KeyAgentInstallJournalValidationError::History)?
            || common.installation_id != *installation_id
            || common.release_identity != *release_identity
            || common
                .predecessor_digest
                .ct_eq(&previous_digest)
                .unwrap_u8()
                == 0
        {
            return Err(KeyAgentInstallJournalValidationError::History);
        }
        if let Some(first_transaction_id) = transaction_id {
            if common.transaction_id != first_transaction_id {
                return Err(KeyAgentInstallJournalValidationError::History);
            }
        } else {
            transaction_id = Some(common.transaction_id);
        }

        bind_install_journal_phase_payload(
            index,
            &encoded_record[..INSTALL_JOURNAL_RECORD_BODY_BYTES],
            &mut profile_payload,
            &mut root_payload,
        )?;

        previous_digest = authenticated_install_journal_record_digest(&encoded_record);
        current_record = Some(record);
    }

    if previous_digest.ct_eq(current_record_digest).unwrap_u8() == 0 {
        return Err(KeyAgentInstallJournalValidationError::Checkpoint);
    }
    current_record.ok_or(KeyAgentInstallJournalValidationError::History)
}

fn validate_authenticated_install_journal(
    encoded_journal: &[u8],
    authentication_key: InstallerJournalAuthenticationKey,
    checkpoint: AuthenticatedKeyAgentInstallCheckpoint,
) -> Result<AuthenticatedKeyAgentInstallSnapshot, KeyAgentInstallJournalValidationError> {
    let InstallerJournalAuthenticationKey { bytes: key, .. } = authentication_key;
    let AuthenticatedKeyAgentInstallCheckpoint {
        high_water_generation,
        current_record_digest,
        installation_id,
        release_identity,
        commitment,
        _seal: _checkpoint_seal,
        _not_send_or_sync: _checkpoint_thread_affinity,
    } = checkpoint;
    if !valid_authentication_key(&key) {
        return Err(KeyAgentInstallJournalValidationError::InvalidAuthenticationKey);
    }
    if !valid_identity(&installation_id)
        || !valid_identity(&release_identity)
        || installation_id == release_identity
    {
        return Err(KeyAgentInstallJournalValidationError::Checkpoint);
    }
    let expected_commitment = install_checkpoint_commitment(
        high_water_generation,
        &current_record_digest,
        &installation_id,
        &release_identity,
    );
    if expected_commitment.ct_eq(&commitment).unwrap_u8() == 0 {
        return Err(KeyAgentInstallJournalValidationError::Checkpoint);
    }

    let record = if encoded_journal.is_empty() {
        if high_water_generation != 0 || current_record_digest != [0; INSTALL_JOURNAL_DIGEST_BYTES]
        {
            return Err(KeyAgentInstallJournalValidationError::Checkpoint);
        }
        None
    } else {
        if !(1..=COMMITTED_JOURNAL_GENERATION_V1).contains(&high_water_generation)
            || !valid_digest(&current_record_digest)
        {
            return Err(KeyAgentInstallJournalValidationError::Checkpoint);
        }
        Some(validate_nonempty_install_journal_history(
            encoded_journal,
            &key,
            high_water_generation,
            &current_record_digest,
            &installation_id,
            &release_identity,
        )?)
    };

    Ok(AuthenticatedKeyAgentInstallSnapshot {
        journal: AuthenticatedKeyAgentInstallJournal {
            authenticated_generation: high_water_generation,
            record,
            _seal: JournalEvidenceSeal,
            _not_send_or_sync: PhantomData,
        },
        expected: ExpectedKeyAgentInstallIdentities {
            installation_id,
            release_identity,
            _seal: ExpectedIdentitySeal,
            _not_send_or_sync: PhantomData,
        },
        current_record_digest,
        _not_send_or_sync: PhantomData,
    })
}

#[cfg(test)]
fn installer_journal_authentication_key_for_test(
    bytes: [u8; INSTALL_JOURNAL_AUTHENTICATION_KEY_BYTES],
) -> InstallerJournalAuthenticationKey {
    InstallerJournalAuthenticationKey {
        bytes: Zeroizing::new(bytes),
        _seal: InstallerJournalAuthenticationKeySeal,
        _not_send_or_sync: PhantomData,
    }
}

#[cfg(test)]
fn authenticated_install_checkpoint_for_test(
    high_water_generation: u64,
    current_record_digest: [u8; INSTALL_JOURNAL_DIGEST_BYTES],
    installation_id: [u8; IDENTITY_BYTES],
    release_identity: [u8; IDENTITY_BYTES],
) -> AuthenticatedKeyAgentInstallCheckpoint {
    let commitment = install_checkpoint_commitment(
        high_water_generation,
        &current_record_digest,
        &installation_id,
        &release_identity,
    );
    AuthenticatedKeyAgentInstallCheckpoint {
        high_water_generation,
        current_record_digest,
        installation_id,
        release_identity,
        commitment,
        _seal: CheckpointEvidenceSeal,
        _not_send_or_sync: PhantomData,
    }
}

#[cfg(test)]
fn encode_authenticated_install_journal_record_for_test(
    record: &KeyAgentInstallRecord,
    key: &InstallerJournalAuthenticationKey,
) -> Result<[u8; INSTALL_JOURNAL_RECORD_BYTES], KeyAgentInstallJournalValidationError> {
    let body = encode_install_journal_record_body(record)?;
    let mut mac = InstallerJournalHmacSha256::new_from_slice(key.bytes.as_ref())
        .map_err(|_| KeyAgentInstallJournalValidationError::InvalidAuthenticationKey)?;
    mac.update(INSTALL_JOURNAL_RECORD_MAC_DOMAIN_V1);
    mac.update(&body);
    let tag: [u8; INSTALL_JOURNAL_MAC_BYTES] = mac.finalize().into_bytes().into();
    let mut encoded = [0_u8; INSTALL_JOURNAL_RECORD_BYTES];
    encoded[..RECORD_MAC_OFFSET].copy_from_slice(&body);
    encoded[RECORD_MAC_OFFSET..].copy_from_slice(&tag);
    Ok(encoded)
}

#[cfg(test)]
fn retag_authenticated_install_journal_record_for_test(
    encoded: &mut [u8; INSTALL_JOURNAL_RECORD_BYTES],
    key: &InstallerJournalAuthenticationKey,
) -> Result<(), KeyAgentInstallJournalValidationError> {
    let mut mac = InstallerJournalHmacSha256::new_from_slice(key.bytes.as_ref())
        .map_err(|_| KeyAgentInstallJournalValidationError::InvalidAuthenticationKey)?;
    mac.update(INSTALL_JOURNAL_RECORD_MAC_DOMAIN_V1);
    mac.update(&encoded[..RECORD_MAC_OFFSET]);
    let tag: [u8; INSTALL_JOURNAL_MAC_BYTES] = mac.finalize().into_bytes().into();
    encoded[RECORD_MAC_OFFSET..].copy_from_slice(&tag);
    Ok(())
}

/// Builds two independently validated snapshots for the held-adoption kernel
/// tests without exposing any production journal/key/checkpoint constructor.
#[cfg(test)]
pub(crate) fn authenticated_install_snapshot_pair_for_test(
    profile_sid: &[u8],
    stable_user_sid: &[u8],
    root_identity: KeyAgentStorageRootIdentity,
    installation_id: [u8; IDENTITY_BYTES],
    release_identity: [u8; IDENTITY_BYTES],
    record_count: usize,
) -> Option<(
    AuthenticatedKeyAgentInstallSnapshot,
    AuthenticatedKeyAgentInstallSnapshot,
)> {
    let states = [
        KeyAgentInstallTransactionState::Prepared,
        KeyAgentInstallTransactionState::ProfileCreated,
        KeyAgentInstallTransactionState::RootCreated,
        KeyAgentInstallTransactionState::Committed,
    ];
    if record_count > states.len() {
        return None;
    }
    let transaction_id = [0x11_u8; IDENTITY_BYTES];
    let key_bytes = [0xa5_u8; INSTALL_JOURNAL_AUTHENTICATION_KEY_BYTES];
    let mut journal = Vec::with_capacity(record_count * INSTALL_JOURNAL_RECORD_BYTES);
    let mut predecessor_digest = [0_u8; INSTALL_JOURNAL_DIGEST_BYTES];
    for state in states.into_iter().take(record_count) {
        let common = KeyAgentInstallCommonRecord {
            schema_version: INSTALL_JOURNAL_SCHEMA_V1,
            policy_version: INSTALL_POLICY_V1,
            journal_generation: transaction_generation(state),
            transaction_id,
            installation_id,
            release_identity,
            predecessor_digest,
        };
        let profile = KeyAgentInstallProfileEvidence {
            name_len: u8::try_from(KEY_AGENT_PROFILE_V1_NAME.len()).ok()?,
            name: padded_fixed_profile_name_for_test()?,
            sid: canonical_observed_sid(profile_sid)?,
        };
        let root = KeyAgentInstallRootEvidence {
            stable_user_sid: canonical_observed_sid(stable_user_sid)?,
            root_identity,
        };
        let record = match state {
            KeyAgentInstallTransactionState::Prepared => KeyAgentInstallRecord::Prepared { common },
            KeyAgentInstallTransactionState::ProfileCreated => {
                KeyAgentInstallRecord::ProfileCreated { common, profile }
            }
            KeyAgentInstallTransactionState::RootCreated => KeyAgentInstallRecord::RootCreated {
                common,
                profile,
                root,
            },
            KeyAgentInstallTransactionState::Committed => KeyAgentInstallRecord::Committed {
                common,
                profile,
                root,
            },
        };
        let key = installer_journal_authentication_key_for_test(key_bytes);
        let encoded = encode_authenticated_install_journal_record_for_test(&record, &key).ok()?;
        predecessor_digest = authenticated_install_journal_record_digest(&encoded);
        journal.extend_from_slice(&encoded);
    }

    let generation = u64::try_from(record_count).ok()?;
    let initial = validate_authenticated_install_journal(
        &journal,
        installer_journal_authentication_key_for_test(key_bytes),
        authenticated_install_checkpoint_for_test(
            generation,
            predecessor_digest,
            installation_id,
            release_identity,
        ),
    )
    .ok()?;
    let reread = validate_authenticated_install_journal(
        &journal,
        installer_journal_authentication_key_for_test(key_bytes),
        authenticated_install_checkpoint_for_test(
            generation,
            predecessor_digest,
            installation_id,
            release_identity,
        ),
    )
    .ok()?;
    Some((initial, reread))
}

#[cfg(test)]
fn padded_fixed_profile_name_for_test() -> Option<[u8; MAX_PROFILE_NAME_BYTES]> {
    let fixed = KEY_AGENT_PROFILE_V1_NAME.as_bytes();
    let mut name = [0_u8; MAX_PROFILE_NAME_BYTES];
    name.get_mut(..fixed.len())?.copy_from_slice(fixed);
    Some(name)
}

fn valid_identity(value: &[u8; IDENTITY_BYTES]) -> bool {
    *value != [0; IDENTITY_BYTES] && *value != [u8::MAX; IDENTITY_BYTES]
}

fn valid_digest(value: &[u8; INSTALL_JOURNAL_DIGEST_BYTES]) -> bool {
    *value != [0; INSTALL_JOURNAL_DIGEST_BYTES] && *value != [u8::MAX; INSTALL_JOURNAL_DIGEST_BYTES]
}

fn valid_authentication_key(value: &[u8; INSTALL_JOURNAL_AUTHENTICATION_KEY_BYTES]) -> bool {
    *value != [0; INSTALL_JOURNAL_AUTHENTICATION_KEY_BYTES]
        && *value != [u8::MAX; INSTALL_JOURNAL_AUTHENTICATION_KEY_BYTES]
}

const fn transaction_generation(state: KeyAgentInstallTransactionState) -> u64 {
    match state {
        KeyAgentInstallTransactionState::Prepared => 1,
        KeyAgentInstallTransactionState::ProfileCreated => 2,
        KeyAgentInstallTransactionState::RootCreated => 3,
        KeyAgentInstallTransactionState::Committed => COMMITTED_JOURNAL_GENERATION_V1,
    }
}

const fn transaction_state_tag(state: KeyAgentInstallTransactionState) -> u8 {
    match state {
        KeyAgentInstallTransactionState::Prepared => 1,
        KeyAgentInstallTransactionState::ProfileCreated => 2,
        KeyAgentInstallTransactionState::RootCreated => 3,
        KeyAgentInstallTransactionState::Committed => 4,
    }
}

fn decode_transaction_state_tag(
    tag: u8,
) -> Result<KeyAgentInstallTransactionState, KeyAgentInstallJournalValidationError> {
    match tag {
        1 => Ok(KeyAgentInstallTransactionState::Prepared),
        2 => Ok(KeyAgentInstallTransactionState::ProfileCreated),
        3 => Ok(KeyAgentInstallTransactionState::RootCreated),
        4 => Ok(KeyAgentInstallTransactionState::Committed),
        _ => Err(KeyAgentInstallJournalValidationError::Encoding),
    }
}

const fn transaction_state_for_index(index: usize) -> Option<KeyAgentInstallTransactionState> {
    match index {
        0 => Some(KeyAgentInstallTransactionState::Prepared),
        1 => Some(KeyAgentInstallTransactionState::ProfileCreated),
        2 => Some(KeyAgentInstallTransactionState::RootCreated),
        3 => Some(KeyAgentInstallTransactionState::Committed),
        _ => None,
    }
}

fn exact_fixed_profile_name(len: u8, padded: &[u8; MAX_PROFILE_NAME_BYTES]) -> bool {
    let fixed_name = KEY_AGENT_PROFILE_V1_NAME.as_bytes();
    usize::from(len) == fixed_name.len()
        && padded[..fixed_name.len()] == *fixed_name
        && padded[fixed_name.len()..].iter().all(|byte| *byte == 0)
}

fn valid_canonical_sid(sid: &CanonicalSidEvidence) -> bool {
    let len = usize::from(sid.len);
    if !(12..=MAX_CANONICAL_SID_BYTES).contains(&len)
        || sid.bytes[0] != 1
        || usize::from(sid.bytes[1]) > 15
        || len != 8 + usize::from(sid.bytes[1]) * 4
        || sid.bytes[2..8].iter().all(|byte| *byte == 0)
    {
        return false;
    }
    sid.bytes[len..].iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use core::marker::PhantomData;

    use crate::key_agent_storage::KeyAgentStorageError;

    use super::{
        AuthenticatedKeyAgentInstallCheckpoint, AuthenticatedKeyAgentInstallJournal,
        AuthenticatedKeyAgentInstallSnapshot, COMMITTED_JOURNAL_GENERATION_V1,
        CanonicalSidEvidence, ConsistentExistingKeyAgentInstallCandidate, ExpectedIdentitySeal,
        ExpectedKeyAgentInstallIdentities, IDENTITY_BYTES,
        INSTALL_JOURNAL_AUTHENTICATION_KEY_BYTES, INSTALL_JOURNAL_DIGEST_BYTES,
        INSTALL_JOURNAL_RECORD_BODY_BYTES, INSTALL_JOURNAL_RECORD_BYTES, INSTALL_JOURNAL_SCHEMA_V1,
        INSTALL_POLICY_V1, InstallerJournalAuthenticationKey, JournalEvidenceSeal,
        KeyAgentInstallCommonRecord, KeyAgentInstallDisposition, KeyAgentInstallProfileEvidence,
        KeyAgentInstallRecord, KeyAgentInstallRootEvidence, KeyAgentInstallTransactionState,
        MAX_CANONICAL_SID_BYTES, MAX_PROFILE_NAME_BYTES, ObservedKeyAgentInstallObjects,
        ObservedKeyAgentProfile, ObservedKeyAgentStorageRoot, OsObservationSeal,
        RECORD_GENERATION_OFFSET, RECORD_HEADER_RESERVED_OFFSET, RECORD_INSTALLATION_ID_OFFSET,
        RECORD_PREDECESSOR_DIGEST_OFFSET, RECORD_PROFILE_NAME_LEN_OFFSET,
        RECORD_PROFILE_NAME_OFFSET, RECORD_PROFILE_SID_LEN_OFFSET, RECORD_PROFILE_SID_OFFSET,
        RECORD_RELEASE_IDENTITY_OFFSET, RECORD_ROOT_IDENTITY_OFFSET,
        RECORD_STABLE_USER_SID_LEN_OFFSET, RECORD_STABLE_USER_SID_OFFSET, RECORD_STATE_OFFSET,
        RECORD_TAIL_RESERVED_OFFSET, RECORD_TRANSACTION_ID_OFFSET,
        StableExistingKeyAgentInstallEvidence, UninitializedKeyAgentInstallCandidate,
        authenticated_install_checkpoint_for_test, authenticated_install_journal_record_digest,
        classify_key_agent_install as classify_model, decode_authenticated_install_journal_record,
        encode_authenticated_install_journal_record_for_test,
        installer_journal_authentication_key_for_test, record_common,
        retag_authenticated_install_journal_record_for_test, transaction_generation,
        validate_authenticated_install_journal,
    };
    use crate::key_agent_lpac::KEY_AGENT_PROFILE_V1_NAME;

    const TRANSACTION_ID: [u8; IDENTITY_BYTES] = [0x11; IDENTITY_BYTES];
    const INSTALLATION_ID: [u8; IDENTITY_BYTES] = [0x22; IDENTITY_BYTES];
    const RELEASE_IDENTITY: [u8; IDENTITY_BYTES] = [0x33; IDENTITY_BYTES];
    const AUTHENTICATION_KEY: [u8; INSTALL_JOURNAL_AUTHENTICATION_KEY_BYTES] =
        [0xa5; INSTALL_JOURNAL_AUTHENTICATION_KEY_BYTES];

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

    trait AmbiguousIfSend<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfSend<()> for T {}
    impl<T: ?Sized + Send> AmbiguousIfSend<u8> for T {}

    trait AmbiguousIfSync<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfSync<()> for T {}
    impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for T {}

    fn padded_profile_name() -> (u8, [u8; MAX_PROFILE_NAME_BYTES]) {
        let mut name = [0_u8; MAX_PROFILE_NAME_BYTES];
        let fixed_name = KEY_AGENT_PROFILE_V1_NAME.as_bytes();
        name[..fixed_name.len()].copy_from_slice(fixed_name);
        (u8::try_from(fixed_name.len()).unwrap_or_default(), name)
    }

    fn canonical_sid(marker: u32) -> CanonicalSidEvidence {
        let mut bytes = [0_u8; MAX_CANONICAL_SID_BYTES];
        bytes[0] = 1;
        bytes[1] = 1;
        bytes[7] = 5;
        bytes[8..12].copy_from_slice(&marker.to_le_bytes());
        CanonicalSidEvidence { len: 12, bytes }
    }

    fn malformed_sid(case: u8) -> CanonicalSidEvidence {
        let mut sid = canonical_sid(0x44);
        match case {
            0 => sid.bytes[0] = 2,
            1 => sid.bytes[1] = 16,
            2 => sid.len = 16,
            3 => sid.bytes[2..8].fill(0),
            4 => sid.bytes[12] = 1,
            _ => sid.len = 0,
        }
        sid
    }

    fn root_identity(
        marker: u8,
    ) -> Result<super::KeyAgentStorageRootIdentity, KeyAgentStorageError> {
        let mut encoded = [0_u8; 24];
        encoded[..8].copy_from_slice(&u64::from(marker).to_be_bytes());
        encoded[8..].fill(marker);
        super::KeyAgentStorageRootIdentity::decode_be(encoded)
    }

    fn record(
        transaction_state: KeyAgentInstallTransactionState,
    ) -> Result<KeyAgentInstallRecord, KeyAgentStorageError> {
        let predecessor_digest = if transaction_state == KeyAgentInstallTransactionState::Prepared {
            [0; INSTALL_JOURNAL_DIGEST_BYTES]
        } else {
            [0x77; INSTALL_JOURNAL_DIGEST_BYTES]
        };
        record_with_predecessor(transaction_state, predecessor_digest)
    }

    fn record_with_predecessor(
        transaction_state: KeyAgentInstallTransactionState,
        predecessor_digest: [u8; INSTALL_JOURNAL_DIGEST_BYTES],
    ) -> Result<KeyAgentInstallRecord, KeyAgentStorageError> {
        let (profile_name_len, profile_name) = padded_profile_name();
        let common = KeyAgentInstallCommonRecord {
            schema_version: INSTALL_JOURNAL_SCHEMA_V1,
            policy_version: INSTALL_POLICY_V1,
            journal_generation: transaction_generation(transaction_state),
            transaction_id: TRANSACTION_ID,
            installation_id: INSTALLATION_ID,
            release_identity: RELEASE_IDENTITY,
            predecessor_digest,
        };
        let profile = KeyAgentInstallProfileEvidence {
            name_len: profile_name_len,
            name: profile_name,
            sid: canonical_sid(0x55),
        };
        let root = KeyAgentInstallRootEvidence {
            stable_user_sid: canonical_sid(0x44),
            root_identity: root_identity(0x66)?,
        };
        Ok(match transaction_state {
            KeyAgentInstallTransactionState::Prepared => KeyAgentInstallRecord::Prepared { common },
            KeyAgentInstallTransactionState::ProfileCreated => {
                KeyAgentInstallRecord::ProfileCreated { common, profile }
            }
            KeyAgentInstallTransactionState::RootCreated => KeyAgentInstallRecord::RootCreated {
                common,
                profile,
                root,
            },
            KeyAgentInstallTransactionState::Committed => KeyAgentInstallRecord::Committed {
                common,
                profile,
                root,
            },
        })
    }

    fn common_mut(record: &mut KeyAgentInstallRecord) -> &mut KeyAgentInstallCommonRecord {
        match record {
            KeyAgentInstallRecord::Prepared { common }
            | KeyAgentInstallRecord::ProfileCreated { common, .. }
            | KeyAgentInstallRecord::RootCreated { common, .. }
            | KeyAgentInstallRecord::Committed { common, .. } => common,
        }
    }

    fn profile_mut(
        record: &mut KeyAgentInstallRecord,
    ) -> Option<&mut KeyAgentInstallProfileEvidence> {
        match record {
            KeyAgentInstallRecord::Prepared { .. } => None,
            KeyAgentInstallRecord::ProfileCreated { profile, .. }
            | KeyAgentInstallRecord::RootCreated { profile, .. }
            | KeyAgentInstallRecord::Committed { profile, .. } => Some(profile),
        }
    }

    fn root_mut(record: &mut KeyAgentInstallRecord) -> Option<&mut KeyAgentInstallRootEvidence> {
        match record {
            KeyAgentInstallRecord::Prepared { .. }
            | KeyAgentInstallRecord::ProfileCreated { .. } => None,
            KeyAgentInstallRecord::RootCreated { root, .. }
            | KeyAgentInstallRecord::Committed { root, .. } => Some(root),
        }
    }

    fn journal(saved: Option<KeyAgentInstallRecord>) -> AuthenticatedKeyAgentInstallJournal {
        let authenticated_generation = saved
            .as_ref()
            .map_or(0, |record| record_common(record).journal_generation);
        AuthenticatedKeyAgentInstallJournal {
            authenticated_generation,
            record: saved,
            _seal: JournalEvidenceSeal,
            _not_send_or_sync: PhantomData,
        }
    }

    fn expected() -> ExpectedKeyAgentInstallIdentities {
        ExpectedKeyAgentInstallIdentities {
            installation_id: INSTALLATION_ID,
            release_identity: RELEASE_IDENTITY,
            _seal: ExpectedIdentitySeal,
            _not_send_or_sync: PhantomData,
        }
    }

    fn authentication_key() -> InstallerJournalAuthenticationKey {
        installer_journal_authentication_key_for_test(AUTHENTICATION_KEY)
    }

    fn encoded_record(
        record: &KeyAgentInstallRecord,
        key: &InstallerJournalAuthenticationKey,
    ) -> [u8; INSTALL_JOURNAL_RECORD_BYTES] {
        let result = encode_authenticated_install_journal_record_for_test(record, key);
        assert!(result.is_ok(), "test record must encode");
        result.unwrap_or([0; INSTALL_JOURNAL_RECORD_BYTES])
    }

    fn decoded_record(
        encoded: &[u8; INSTALL_JOURNAL_RECORD_BYTES],
        key: &InstallerJournalAuthenticationKey,
    ) -> Option<KeyAgentInstallRecord> {
        decode_authenticated_install_journal_record(encoded, &key.bytes).ok()
    }

    fn canonical_journal(
        record_count: usize,
    ) -> Result<(Vec<u8>, [u8; INSTALL_JOURNAL_DIGEST_BYTES]), KeyAgentStorageError> {
        let key = authentication_key();
        let mut journal = Vec::with_capacity(record_count * INSTALL_JOURNAL_RECORD_BYTES);
        let mut predecessor_digest = [0_u8; INSTALL_JOURNAL_DIGEST_BYTES];
        let states = [
            KeyAgentInstallTransactionState::Prepared,
            KeyAgentInstallTransactionState::ProfileCreated,
            KeyAgentInstallTransactionState::RootCreated,
            KeyAgentInstallTransactionState::Committed,
        ];
        assert!(record_count <= states.len());
        for state in states.into_iter().take(record_count) {
            let saved = record_with_predecessor(state, predecessor_digest)?;
            let encoded = encoded_record(&saved, &key);
            predecessor_digest = authenticated_install_journal_record_digest(&encoded);
            journal.extend_from_slice(&encoded);
        }
        Ok((journal, predecessor_digest))
    }

    fn checkpoint(
        high_water_generation: u64,
        current_record_digest: [u8; INSTALL_JOURNAL_DIGEST_BYTES],
    ) -> AuthenticatedKeyAgentInstallCheckpoint {
        authenticated_install_checkpoint_for_test(
            high_water_generation,
            current_record_digest,
            INSTALLATION_ID,
            RELEASE_IDENTITY,
        )
    }

    fn validate_journal(
        encoded: &[u8],
        high_water_generation: u64,
        current_record_digest: [u8; INSTALL_JOURNAL_DIGEST_BYTES],
    ) -> Option<super::AuthenticatedKeyAgentInstallSnapshot> {
        validate_authenticated_install_journal(
            encoded,
            authentication_key(),
            checkpoint(high_water_generation, current_record_digest),
        )
        .ok()
    }

    fn retag_last_record_after_mutation(
        journal: &mut [u8],
        body_offset: usize,
        replacement: u8,
    ) -> [u8; INSTALL_JOURNAL_DIGEST_BYTES] {
        let start = journal.len() - INSTALL_JOURNAL_RECORD_BYTES;
        let mut encoded = [0_u8; INSTALL_JOURNAL_RECORD_BYTES];
        encoded.copy_from_slice(&journal[start..]);
        encoded[body_offset] = replacement;
        let result = retag_authenticated_install_journal_record_for_test(
            &mut encoded,
            &authentication_key(),
        );
        assert!(result.is_ok(), "test record must retag");
        journal[start..].copy_from_slice(&encoded);
        authenticated_install_journal_record_digest(&encoded)
    }

    fn objects(
        profile_present: bool,
        root_present: bool,
    ) -> Result<ObservedKeyAgentInstallObjects, KeyAgentStorageError> {
        let (name_len, name) = padded_profile_name();
        Ok(ObservedKeyAgentInstallObjects {
            profile: profile_present.then_some(ObservedKeyAgentProfile {
                name_len,
                name,
                sid: canonical_sid(0x55),
            }),
            root: root_present.then_some(ObservedKeyAgentStorageRoot {
                identity: root_identity(0x66)?,
                stable_user_sid: canonical_sid(0x44),
                profile_sid: canonical_sid(0x55),
            }),
            _seal: OsObservationSeal,
            _not_send_or_sync: PhantomData,
        })
    }

    fn classify_key_agent_install(
        journal: AuthenticatedKeyAgentInstallJournal,
        objects: ObservedKeyAgentInstallObjects,
    ) -> KeyAgentInstallDisposition {
        classify_model(journal, expected(), objects)
    }

    // Tests consume each one-shot disposition even when only its variant matters.
    #[allow(clippy::needless_pass_by_value)]
    fn is_recovery(disposition: KeyAgentInstallDisposition) -> bool {
        matches!(disposition, KeyAgentInstallDisposition::RecoveryRequired)
    }

    #[test]
    fn full_presence_and_transaction_truth_table_is_fail_closed() -> Result<(), KeyAgentStorageError>
    {
        for profile_present in [false, true] {
            for root_present in [false, true] {
                let disposition = classify_key_agent_install(
                    journal(None),
                    objects(profile_present, root_present)?,
                );
                if profile_present || root_present {
                    assert!(is_recovery(disposition));
                } else {
                    assert!(matches!(
                        disposition,
                        KeyAgentInstallDisposition::Uninitialized(_)
                    ));
                }

                for state in [
                    KeyAgentInstallTransactionState::Prepared,
                    KeyAgentInstallTransactionState::ProfileCreated,
                    KeyAgentInstallTransactionState::RootCreated,
                    KeyAgentInstallTransactionState::Committed,
                ] {
                    let disposition = classify_key_agent_install(
                        journal(Some(record(state)?)),
                        objects(profile_present, root_present)?,
                    );
                    if state == KeyAgentInstallTransactionState::Committed
                        && profile_present
                        && root_present
                    {
                        assert!(matches!(
                            disposition,
                            KeyAgentInstallDisposition::ConsistentExisting(_)
                        ));
                    } else {
                        assert!(is_recovery(disposition));
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn deterministic_profile_squatting_without_a_record_requires_recovery()
    -> Result<(), KeyAgentStorageError> {
        assert!(is_recovery(classify_key_agent_install(
            journal(None),
            objects(true, false)?,
        )));
        assert!(is_recovery(classify_key_agent_install(
            journal(None),
            objects(true, true)?,
        )));
        Ok(())
    }

    #[test]
    fn every_record_binding_mismatch_requires_recovery() -> Result<(), KeyAgentStorageError> {
        let mut cases = Vec::new();

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        common_mut(&mut value).schema_version = INSTALL_JOURNAL_SCHEMA_V1.saturating_add(1);
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        common_mut(&mut value).policy_version = INSTALL_POLICY_V1.saturating_add(1);
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        common_mut(&mut value).transaction_id = [0; IDENTITY_BYTES];
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        common_mut(&mut value).transaction_id = [u8::MAX; IDENTITY_BYTES];
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        common_mut(&mut value).installation_id = [0; IDENTITY_BYTES];
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        common_mut(&mut value).installation_id = [u8::MAX; IDENTITY_BYTES];
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        common_mut(&mut value).release_identity = [0; IDENTITY_BYTES];
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        common_mut(&mut value).release_identity = [u8::MAX; IDENTITY_BYTES];
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        common_mut(&mut value).installation_id[0] ^= 1;
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        common_mut(&mut value).release_identity[0] ^= 1;
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        if let Some(profile) = profile_mut(&mut value) {
            profile.name[0] ^= 1;
        }
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        if let Some(profile) = profile_mut(&mut value) {
            profile.name_len = profile.name_len.saturating_sub(1);
        }
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        if let Some(profile) = profile_mut(&mut value) {
            profile.name[MAX_PROFILE_NAME_BYTES - 1] = 1;
        }
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        common_mut(&mut value).transaction_id = INSTALLATION_ID;
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        common_mut(&mut value).transaction_id = RELEASE_IDENTITY;
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        common_mut(&mut value).release_identity = INSTALLATION_ID;
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        if let Some(root) = root_mut(&mut value) {
            root.stable_user_sid.bytes[11] ^= 1;
        }
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        if let Some(profile) = profile_mut(&mut value) {
            profile.sid.bytes[11] ^= 1;
        }
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        if let Some(root) = root_mut(&mut value) {
            root.root_identity = root_identity(0x67)?;
        }
        cases.push(value);

        for value in cases {
            assert!(is_recovery(classify_key_agent_install(
                journal(Some(value)),
                objects(true, true)?,
            )));
        }
        Ok(())
    }

    #[test]
    fn every_live_observation_or_expected_identity_mismatch_requires_recovery()
    -> Result<(), KeyAgentStorageError> {
        let mut expected_identities = expected();
        expected_identities.installation_id[0] ^= 1;
        assert!(is_recovery(classify_model(
            journal(Some(record(KeyAgentInstallTransactionState::Committed)?)),
            expected_identities,
            objects(true, true)?,
        )));

        let mut expected_identities = expected();
        expected_identities.release_identity = INSTALLATION_ID;
        assert!(is_recovery(classify_model(
            journal(Some(record(KeyAgentInstallTransactionState::Committed)?)),
            expected_identities,
            objects(true, true)?,
        )));

        let mut expected_identities = expected();
        expected_identities.release_identity[0] ^= 1;
        assert!(is_recovery(classify_model(
            journal(Some(record(KeyAgentInstallTransactionState::Committed)?)),
            expected_identities,
            objects(true, true)?,
        )));

        let mut value = objects(true, true)?;
        if let Some(profile) = value.profile.as_mut() {
            profile.name[0] ^= 1;
        }
        assert!(is_recovery(classify_key_agent_install(
            journal(Some(record(KeyAgentInstallTransactionState::Committed)?)),
            value,
        )));

        let mut value = objects(true, true)?;
        if let Some(profile) = value.profile.as_mut() {
            profile.name_len = profile.name_len.saturating_sub(1);
        }
        assert!(is_recovery(classify_key_agent_install(
            journal(Some(record(KeyAgentInstallTransactionState::Committed)?)),
            value,
        )));

        let mut value = objects(true, true)?;
        if let Some(profile) = value.profile.as_mut() {
            profile.name[MAX_PROFILE_NAME_BYTES - 1] = 1;
        }
        assert!(is_recovery(classify_key_agent_install(
            journal(Some(record(KeyAgentInstallTransactionState::Committed)?)),
            value,
        )));

        let mut value = objects(true, true)?;
        if let Some(profile) = value.profile.as_mut() {
            profile.sid.bytes[11] ^= 1;
        }
        assert!(is_recovery(classify_key_agent_install(
            journal(Some(record(KeyAgentInstallTransactionState::Committed)?)),
            value,
        )));

        let mut value = objects(true, true)?;
        if let Some(root) = value.root.as_mut() {
            root.identity = root_identity(0x67)?;
        }
        assert!(is_recovery(classify_key_agent_install(
            journal(Some(record(KeyAgentInstallTransactionState::Committed)?)),
            value,
        )));

        let mut value = objects(true, true)?;
        if let Some(root) = value.root.as_mut() {
            root.stable_user_sid.bytes[11] ^= 1;
        }
        assert!(is_recovery(classify_key_agent_install(
            journal(Some(record(KeyAgentInstallTransactionState::Committed)?)),
            value,
        )));

        let mut value = objects(true, true)?;
        if let Some(root) = value.root.as_mut() {
            root.profile_sid.bytes[11] ^= 1;
        }
        assert!(is_recovery(classify_key_agent_install(
            journal(Some(record(KeyAgentInstallTransactionState::Committed)?)),
            value,
        )));
        Ok(())
    }

    #[test]
    fn malformed_or_aliased_canonical_sids_require_recovery() -> Result<(), KeyAgentStorageError> {
        for case in 0..=5 {
            let mut saved_record = record(KeyAgentInstallTransactionState::Committed)?;
            if let Some(root) = root_mut(&mut saved_record) {
                root.stable_user_sid = malformed_sid(case);
            }
            let mut observed = objects(true, true)?;
            if let Some(root) = observed.root.as_mut() {
                root.stable_user_sid = malformed_sid(case);
            }
            assert!(is_recovery(classify_key_agent_install(
                journal(Some(saved_record)),
                observed,
            )));

            let mut saved_record = record(KeyAgentInstallTransactionState::Committed)?;
            if let Some(profile) = profile_mut(&mut saved_record) {
                profile.sid = malformed_sid(case);
            }
            let mut observed = objects(true, true)?;
            if let Some(profile) = observed.profile.as_mut() {
                profile.sid = malformed_sid(case);
            }
            if let Some(root) = observed.root.as_mut() {
                root.profile_sid = malformed_sid(case);
            }
            assert!(is_recovery(classify_key_agent_install(
                journal(Some(saved_record)),
                observed,
            )));
        }

        let mut saved_record = record(KeyAgentInstallTransactionState::Committed)?;
        if let Some(root) = root_mut(&mut saved_record) {
            root.stable_user_sid = canonical_sid(0x55);
        }
        let mut observed = objects(true, true)?;
        if let Some(root) = observed.root.as_mut() {
            root.stable_user_sid = canonical_sid(0x55);
        }
        assert!(is_recovery(classify_key_agent_install(
            journal(Some(saved_record)),
            observed,
        )));
        Ok(())
    }

    #[test]
    fn sentinel_expected_identities_and_invalid_journal_generation_require_recovery()
    -> Result<(), KeyAgentStorageError> {
        for sentinel in [[0; IDENTITY_BYTES], [u8::MAX; IDENTITY_BYTES]] {
            let mut expected_identities = expected();
            expected_identities.installation_id = sentinel;
            assert!(is_recovery(classify_model(
                journal(None),
                expected_identities,
                objects(false, false)?,
            )));

            let mut expected_identities = expected();
            expected_identities.release_identity = sentinel;
            assert!(is_recovery(classify_model(
                journal(None),
                expected_identities,
                objects(false, false)?,
            )));
        }

        let mut saved = journal(Some(record(KeyAgentInstallTransactionState::Committed)?));
        saved.authenticated_generation = 0;
        assert!(is_recovery(classify_key_agent_install(
            saved,
            objects(true, true)?,
        )));

        for wrong_generation in [0, 3, 5] {
            let mut saved_record = record(KeyAgentInstallTransactionState::Committed)?;
            common_mut(&mut saved_record).journal_generation = wrong_generation;
            assert!(is_recovery(classify_key_agent_install(
                journal(Some(saved_record)),
                objects(true, true)?,
            )));
        }

        let mut mismatched = journal(Some(record(KeyAgentInstallTransactionState::Committed)?));
        mismatched.authenticated_generation = COMMITTED_JOURNAL_GENERATION_V1 + 1;
        assert!(is_recovery(classify_key_agent_install(
            mismatched,
            objects(true, true)?,
        )));

        let mut absent = journal(None);
        absent.authenticated_generation = 1;
        assert!(is_recovery(classify_key_agent_install(
            absent,
            objects(false, false)?,
        )));
        Ok(())
    }

    #[test]
    fn canonical_authenticated_codec_round_trips_all_phase_prefixes()
    -> Result<(), KeyAgentStorageError> {
        for record_count in 0..=usize::try_from(COMMITTED_JOURNAL_GENERATION_V1).unwrap_or_default()
        {
            let (encoded_journal, current_digest) = canonical_journal(record_count)?;
            let validated = validate_journal(
                &encoded_journal,
                u64::try_from(record_count).unwrap_or_default(),
                current_digest,
            );
            assert!(validated.is_some(), "canonical prefix must validate");
            let Some(snapshot) = validated else {
                continue;
            };
            assert_eq!(
                snapshot.journal.authenticated_generation,
                u64::try_from(record_count).unwrap_or_default()
            );
            assert_eq!(snapshot.expected.installation_id, INSTALLATION_ID);
            assert_eq!(snapshot.expected.release_identity, RELEASE_IDENTITY);
            assert_eq!(snapshot.current_record_digest, current_digest);

            let disposition = classify_model(
                snapshot.journal,
                snapshot.expected,
                if record_count == 0 {
                    objects(false, false)?
                } else {
                    objects(true, true)?
                },
            );
            match record_count {
                0 => assert!(matches!(
                    disposition,
                    KeyAgentInstallDisposition::Uninitialized(_)
                )),
                4 => assert!(matches!(
                    disposition,
                    KeyAgentInstallDisposition::ConsistentExisting(_)
                )),
                _ => assert!(is_recovery(disposition)),
            }

            let key = authentication_key();
            for encoded_chunk in encoded_journal.chunks_exact(INSTALL_JOURNAL_RECORD_BYTES) {
                let mut encoded = [0_u8; INSTALL_JOURNAL_RECORD_BYTES];
                encoded.copy_from_slice(encoded_chunk);
                let decoded = decoded_record(&encoded, &key);
                assert!(decoded.is_some());
                if let Some(decoded) = decoded {
                    assert_eq!(encoded_record(&decoded, &key), encoded);
                }
            }
        }
        Ok(())
    }

    #[test]
    fn codec_rejects_truncation_trailing_authentication_reserved_and_unused_bytes()
    -> Result<(), KeyAgentStorageError> {
        let (encoded_journal, current_digest) = canonical_journal(4)?;

        let mut truncated = encoded_journal.clone();
        let _ = truncated.pop();
        assert!(validate_journal(&truncated, 4, current_digest).is_none());

        let mut trailing = encoded_journal.clone();
        trailing.push(0);
        assert!(validate_journal(&trailing, 4, current_digest).is_none());

        let mut body_tampered = encoded_journal.clone();
        body_tampered[0] ^= 1;
        assert!(validate_journal(&body_tampered, 4, current_digest).is_none());

        let mut tag_tampered = encoded_journal.clone();
        tag_tampered[INSTALL_JOURNAL_RECORD_BODY_BYTES] ^= 1;
        assert!(validate_journal(&tag_tampered, 4, current_digest).is_none());

        let wrong_key = installer_journal_authentication_key_for_test(
            [0xb6; INSTALL_JOURNAL_AUTHENTICATION_KEY_BYTES],
        );
        assert!(
            validate_authenticated_install_journal(
                &encoded_journal,
                wrong_key,
                checkpoint(4, current_digest),
            )
            .is_err()
        );
        for sentinel in [
            [0; INSTALL_JOURNAL_AUTHENTICATION_KEY_BYTES],
            [u8::MAX; INSTALL_JOURNAL_AUTHENTICATION_KEY_BYTES],
        ] {
            assert!(
                validate_authenticated_install_journal(
                    &encoded_journal,
                    installer_journal_authentication_key_for_test(sentinel),
                    checkpoint(4, current_digest),
                )
                .is_err()
            );
        }

        for unused_offset in [
            RECORD_HEADER_RESERVED_OFFSET,
            RECORD_PROFILE_NAME_LEN_OFFSET,
            RECORD_PROFILE_NAME_OFFSET,
            RECORD_PROFILE_SID_LEN_OFFSET,
            RECORD_PROFILE_SID_OFFSET,
            RECORD_STABLE_USER_SID_LEN_OFFSET,
            RECORD_STABLE_USER_SID_OFFSET,
            RECORD_ROOT_IDENTITY_OFFSET,
            RECORD_TAIL_RESERVED_OFFSET,
        ] {
            let (mut prepared, _) = canonical_journal(1)?;
            let digest = retag_last_record_after_mutation(&mut prepared, unused_offset, 1);
            assert!(validate_journal(&prepared, 1, digest).is_none());
        }
        for unused_offset in [
            RECORD_STABLE_USER_SID_LEN_OFFSET,
            RECORD_STABLE_USER_SID_OFFSET,
            RECORD_ROOT_IDENTITY_OFFSET,
        ] {
            let (mut profile_created, _) = canonical_journal(2)?;
            let digest = retag_last_record_after_mutation(&mut profile_created, unused_offset, 1);
            assert!(validate_journal(&profile_created, 2, digest).is_none());
        }
        Ok(())
    }

    #[test]
    fn exact_history_rejects_gap_order_id_payload_and_predecessor_drift()
    -> Result<(), KeyAgentStorageError> {
        for (offset, replacement) in [
            (RECORD_GENERATION_OFFSET + 7, 3),
            (RECORD_STATE_OFFSET, 3),
            (RECORD_TRANSACTION_ID_OFFSET, TRANSACTION_ID[0] ^ 1),
            (RECORD_INSTALLATION_ID_OFFSET, INSTALLATION_ID[0] ^ 1),
            (RECORD_RELEASE_IDENTITY_OFFSET, RELEASE_IDENTITY[0] ^ 1),
        ] {
            let (mut drifted, _) = canonical_journal(2)?;
            let digest = retag_last_record_after_mutation(&mut drifted, offset, replacement);
            assert!(validate_journal(&drifted, 2, digest).is_none());
        }

        let (mut predecessor_drifted, _) = canonical_journal(2)?;
        let last = predecessor_drifted.len() - INSTALL_JOURNAL_RECORD_BYTES;
        let replacement = predecessor_drifted[last + RECORD_PREDECESSOR_DIGEST_OFFSET] ^ 1;
        let digest = retag_last_record_after_mutation(
            &mut predecessor_drifted,
            RECORD_PREDECESSOR_DIGEST_OFFSET,
            replacement,
        );
        assert!(validate_journal(&predecessor_drifted, 2, digest).is_none());

        let (mut profile_drifted, _) = canonical_journal(3)?;
        let last = profile_drifted.len() - INSTALL_JOURNAL_RECORD_BYTES;
        let profile_marker = RECORD_PROFILE_SID_OFFSET + 11;
        let replacement = profile_drifted[last + profile_marker] ^ 1;
        let digest =
            retag_last_record_after_mutation(&mut profile_drifted, profile_marker, replacement);
        assert!(validate_journal(&profile_drifted, 3, digest).is_none());

        for root_payload_offset in [
            RECORD_STABLE_USER_SID_OFFSET + 11,
            RECORD_ROOT_IDENTITY_OFFSET + 23,
        ] {
            let (mut root_drifted, _) = canonical_journal(4)?;
            let last = root_drifted.len() - INSTALL_JOURNAL_RECORD_BYTES;
            let replacement = root_drifted[last + root_payload_offset] ^ 1;
            let digest = retag_last_record_after_mutation(
                &mut root_drifted,
                root_payload_offset,
                replacement,
            );
            assert!(validate_journal(&root_drifted, 4, digest).is_none());
        }
        Ok(())
    }

    #[test]
    fn checkpoint_rejects_rollback_equivocation_digest_and_empty_mismatches()
    -> Result<(), KeyAgentStorageError> {
        let (encoded_journal, current_digest) = canonical_journal(4)?;
        let mut third_record = [0_u8; INSTALL_JOURNAL_RECORD_BYTES];
        let third_offset = 2 * INSTALL_JOURNAL_RECORD_BYTES;
        third_record.copy_from_slice(
            &encoded_journal[third_offset..third_offset + INSTALL_JOURNAL_RECORD_BYTES],
        );
        let third_digest = authenticated_install_journal_record_digest(&third_record);
        assert!(
            validate_authenticated_install_journal(
                &encoded_journal,
                authentication_key(),
                checkpoint(3, third_digest),
            )
            .is_err()
        );
        assert!(
            validate_authenticated_install_journal(
                &encoded_journal,
                authentication_key(),
                checkpoint(5, current_digest),
            )
            .is_err()
        );

        let mut equivocated = checkpoint(4, current_digest);
        equivocated.installation_id[0] ^= 1;
        assert!(
            validate_authenticated_install_journal(
                &encoded_journal,
                authentication_key(),
                equivocated,
            )
            .is_err()
        );

        let mut wrong_current_digest = current_digest;
        wrong_current_digest[0] ^= 1;
        assert!(
            validate_authenticated_install_journal(
                &encoded_journal,
                authentication_key(),
                checkpoint(4, wrong_current_digest),
            )
            .is_err()
        );

        let mut wrong_commitment = checkpoint(4, current_digest);
        wrong_commitment.commitment[0] ^= 1;
        assert!(
            validate_authenticated_install_journal(
                &encoded_journal,
                authentication_key(),
                wrong_commitment,
            )
            .is_err()
        );

        assert!(validate_journal(&[], 0, [0; INSTALL_JOURNAL_DIGEST_BYTES]).is_some());
        assert!(validate_journal(&[], 1, current_digest).is_none());
        assert!(validate_journal(&[], 0, current_digest).is_none());
        assert!(
            validate_journal(
                &encoded_journal[..INSTALL_JOURNAL_RECORD_BYTES],
                0,
                [0; INSTALL_JOURNAL_DIGEST_BYTES],
            )
            .is_none()
        );
        Ok(())
    }

    #[test]
    fn authority_is_one_shot_thread_affine_and_debug_redacted() -> Result<(), KeyAgentStorageError>
    {
        let _ = <AuthenticatedKeyAgentInstallJournal as AmbiguousIfClone<_>>::marker;
        let _ = <AuthenticatedKeyAgentInstallJournal as AmbiguousIfCopy<_>>::marker;
        let _ = <AuthenticatedKeyAgentInstallJournal as AmbiguousIfSend<_>>::marker;
        let _ = <AuthenticatedKeyAgentInstallJournal as AmbiguousIfSync<_>>::marker;
        let _ = <ExpectedKeyAgentInstallIdentities as AmbiguousIfClone<_>>::marker;
        let _ = <ExpectedKeyAgentInstallIdentities as AmbiguousIfCopy<_>>::marker;
        let _ = <ExpectedKeyAgentInstallIdentities as AmbiguousIfSend<_>>::marker;
        let _ = <ExpectedKeyAgentInstallIdentities as AmbiguousIfSync<_>>::marker;
        let _ = <ObservedKeyAgentInstallObjects as AmbiguousIfClone<_>>::marker;
        let _ = <ObservedKeyAgentInstallObjects as AmbiguousIfCopy<_>>::marker;
        let _ = <ObservedKeyAgentInstallObjects as AmbiguousIfSend<_>>::marker;
        let _ = <ObservedKeyAgentInstallObjects as AmbiguousIfSync<_>>::marker;
        let _ = <UninitializedKeyAgentInstallCandidate as AmbiguousIfClone<_>>::marker;
        let _ = <UninitializedKeyAgentInstallCandidate as AmbiguousIfCopy<_>>::marker;
        let _ = <UninitializedKeyAgentInstallCandidate as AmbiguousIfSend<_>>::marker;
        let _ = <UninitializedKeyAgentInstallCandidate as AmbiguousIfSync<_>>::marker;
        let _ = <ConsistentExistingKeyAgentInstallCandidate as AmbiguousIfClone<_>>::marker;
        let _ = <ConsistentExistingKeyAgentInstallCandidate as AmbiguousIfCopy<_>>::marker;
        let _ = <ConsistentExistingKeyAgentInstallCandidate as AmbiguousIfSend<_>>::marker;
        let _ = <ConsistentExistingKeyAgentInstallCandidate as AmbiguousIfSync<_>>::marker;
        let _ = <KeyAgentInstallDisposition as AmbiguousIfClone<_>>::marker;
        let _ = <KeyAgentInstallDisposition as AmbiguousIfCopy<_>>::marker;
        let _ = <KeyAgentInstallDisposition as AmbiguousIfSend<_>>::marker;
        let _ = <KeyAgentInstallDisposition as AmbiguousIfSync<_>>::marker;
        let _ = <InstallerJournalAuthenticationKey as AmbiguousIfClone<_>>::marker;
        let _ = <InstallerJournalAuthenticationKey as AmbiguousIfCopy<_>>::marker;
        let _ = <InstallerJournalAuthenticationKey as AmbiguousIfSend<_>>::marker;
        let _ = <InstallerJournalAuthenticationKey as AmbiguousIfSync<_>>::marker;
        let _ = <AuthenticatedKeyAgentInstallCheckpoint as AmbiguousIfClone<_>>::marker;
        let _ = <AuthenticatedKeyAgentInstallCheckpoint as AmbiguousIfCopy<_>>::marker;
        let _ = <AuthenticatedKeyAgentInstallCheckpoint as AmbiguousIfSend<_>>::marker;
        let _ = <AuthenticatedKeyAgentInstallCheckpoint as AmbiguousIfSync<_>>::marker;
        let _ = <AuthenticatedKeyAgentInstallSnapshot as AmbiguousIfClone<_>>::marker;
        let _ = <AuthenticatedKeyAgentInstallSnapshot as AmbiguousIfCopy<_>>::marker;
        let _ = <AuthenticatedKeyAgentInstallSnapshot as AmbiguousIfSend<_>>::marker;
        let _ = <AuthenticatedKeyAgentInstallSnapshot as AmbiguousIfSync<_>>::marker;
        let _ = <StableExistingKeyAgentInstallEvidence as AmbiguousIfClone<_>>::marker;
        let _ = <StableExistingKeyAgentInstallEvidence as AmbiguousIfCopy<_>>::marker;
        let _ = <StableExistingKeyAgentInstallEvidence as AmbiguousIfSend<_>>::marker;
        let _ = <StableExistingKeyAgentInstallEvidence as AmbiguousIfSync<_>>::marker;

        let uninitialized = classify_key_agent_install(journal(None), objects(false, false)?);
        assert_eq!(
            format!("{uninitialized:?}"),
            "KeyAgentInstallDisposition::Uninitialized([REDACTED])"
        );
        let consistent = classify_key_agent_install(
            journal(Some(record(KeyAgentInstallTransactionState::Committed)?)),
            objects(true, true)?,
        );
        assert_eq!(
            format!("{consistent:?}"),
            "KeyAgentInstallDisposition::ConsistentExisting([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", journal(None)),
            "AuthenticatedKeyAgentInstallJournal([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", expected()),
            "ExpectedKeyAgentInstallIdentities([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", objects(false, false)?),
            "ObservedKeyAgentInstallObjects([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", authentication_key()),
            "InstallerJournalAuthenticationKey([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", checkpoint(0, [0; INSTALL_JOURNAL_DIGEST_BYTES])),
            "AuthenticatedKeyAgentInstallCheckpoint([REDACTED])"
        );
        let empty_snapshot = validate_journal(&[], 0, [0; INSTALL_JOURNAL_DIGEST_BYTES]);
        assert!(empty_snapshot.is_some());
        if let Some(empty_snapshot) = empty_snapshot {
            assert_eq!(
                format!("{empty_snapshot:?}"),
                "AuthenticatedKeyAgentInstallSnapshot([REDACTED])"
            );
        }
        Ok(())
    }
}
