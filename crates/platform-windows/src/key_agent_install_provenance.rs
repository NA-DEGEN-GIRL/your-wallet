//! Fail-closed model for trusted Key Agent installation provenance.
//!
//! This module is deliberately pure: it performs no profile, filesystem,
//! registry, cryptographic-provider, or serialization I/O. Its inputs can be
//! constructed only inside this module, and production currently has no source
//! for them. A future installer-owned adapter must authenticate and
//! authoritatively reread the durable journal and live OS observations before
//! it may call this classifier. Journal absence/read failure, malformed bytes,
//! authentication failure, rollback, gaps, or equivocation must prevent the
//! authenticated input from being minted and fail closed in that adapter.
//! Until then there is no production adoption path.

use core::fmt;
use core::marker::PhantomData;

use crate::key_agent_lpac::KEY_AGENT_PROFILE_V1_NAME;
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
const COMMITTED_JOURNAL_GENERATION_V1: u64 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyAgentInstallTransactionState {
    Prepared,
    ProfileCreated,
    RootCreated,
    Committed,
}

struct KeyAgentInstallRecord {
    schema_version: u16,
    policy_version: u16,
    transaction_state: KeyAgentInstallTransactionState,
    journal_generation: u64,
    transaction_id: [u8; IDENTITY_BYTES],
    installation_id: [u8; IDENTITY_BYTES],
    release_identity: [u8; IDENTITY_BYTES],
    profile_name_len: u8,
    profile_name: [u8; MAX_PROFILE_NAME_BYTES],
    stable_user_sid: CanonicalSidEvidence,
    profile_sid: CanonicalSidEvidence,
    root_identity: KeyAgentStorageRootIdentity,
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

/// Authenticated observation of the installer-owned provenance journal.
///
/// Private fields and the unnameable seal prevent sibling modules from
/// asserting that arbitrary bytes were authenticated. Production has no
/// constructor, decoder, reader, or authentication implementation for it.
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

/// Live fixed-profile and held storage-root observations.
///
/// The type alone does not prove an OS-registered profile, exact root security,
/// local NTFS, or a retained no-delete-share handle. A future constructor must
/// remain fused to those selector-free checks. Production has no OS observer.
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
/// production conversion to `PreparedKeyAgentProvisioning` exists. In
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
            if journal.authenticated_generation == record.journal_generation
                && exact_committed_match(
                    &record,
                    &profile,
                    &root,
                    &expected_installation_id,
                    &expected_release_identity,
                ) =>
        {
            KeyAgentInstallDisposition::ConsistentExisting(
                ConsistentExistingKeyAgentInstallCandidate {
                    installation_id: record.installation_id,
                    release_identity: record.release_identity,
                    root_identity: record.root_identity,
                    _not_send_or_sync: PhantomData,
                },
            )
        }
        _ => KeyAgentInstallDisposition::RecoveryRequired,
    }
}

fn exact_committed_match(
    record: &KeyAgentInstallRecord,
    profile: &ObservedKeyAgentProfile,
    root: &ObservedKeyAgentStorageRoot,
    expected_installation_id: &[u8; IDENTITY_BYTES],
    expected_release_identity: &[u8; IDENTITY_BYTES],
) -> bool {
    record.schema_version == INSTALL_JOURNAL_SCHEMA_V1
        && record.policy_version == INSTALL_POLICY_V1
        && record.transaction_state == KeyAgentInstallTransactionState::Committed
        && record.journal_generation == transaction_generation(record.transaction_state)
        && valid_identity(&record.transaction_id)
        && valid_identity(&record.installation_id)
        && valid_identity(&record.release_identity)
        && record.transaction_id != record.installation_id
        && record.transaction_id != record.release_identity
        && record.installation_id != record.release_identity
        && record.installation_id == *expected_installation_id
        && record.release_identity == *expected_release_identity
        && exact_fixed_profile_name(record.profile_name_len, &record.profile_name)
        && exact_fixed_profile_name(profile.name_len, &profile.name)
        && valid_canonical_sid(&record.stable_user_sid)
        && valid_canonical_sid(&record.profile_sid)
        && record.stable_user_sid != record.profile_sid
        && profile.sid == record.profile_sid
        && root.identity == record.root_identity
        && root.stable_user_sid == record.stable_user_sid
        && root.profile_sid == record.profile_sid
}

fn valid_identity(value: &[u8; IDENTITY_BYTES]) -> bool {
    *value != [0; IDENTITY_BYTES] && *value != [u8::MAX; IDENTITY_BYTES]
}

const fn transaction_generation(state: KeyAgentInstallTransactionState) -> u64 {
    match state {
        KeyAgentInstallTransactionState::Prepared => 1,
        KeyAgentInstallTransactionState::ProfileCreated => 2,
        KeyAgentInstallTransactionState::RootCreated => 3,
        KeyAgentInstallTransactionState::Committed => COMMITTED_JOURNAL_GENERATION_V1,
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
        AuthenticatedKeyAgentInstallJournal, COMMITTED_JOURNAL_GENERATION_V1, CanonicalSidEvidence,
        ConsistentExistingKeyAgentInstallCandidate, ExpectedIdentitySeal,
        ExpectedKeyAgentInstallIdentities, IDENTITY_BYTES, INSTALL_JOURNAL_SCHEMA_V1,
        INSTALL_POLICY_V1, JournalEvidenceSeal, KeyAgentInstallDisposition, KeyAgentInstallRecord,
        KeyAgentInstallTransactionState, MAX_CANONICAL_SID_BYTES, MAX_PROFILE_NAME_BYTES,
        ObservedKeyAgentInstallObjects, ObservedKeyAgentProfile, ObservedKeyAgentStorageRoot,
        OsObservationSeal, UninitializedKeyAgentInstallCandidate,
        classify_key_agent_install as classify_model, transaction_generation,
    };
    use crate::key_agent_lpac::KEY_AGENT_PROFILE_V1_NAME;

    const TRANSACTION_ID: [u8; IDENTITY_BYTES] = [0x11; IDENTITY_BYTES];
    const INSTALLATION_ID: [u8; IDENTITY_BYTES] = [0x22; IDENTITY_BYTES];
    const RELEASE_IDENTITY: [u8; IDENTITY_BYTES] = [0x33; IDENTITY_BYTES];

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
        let (profile_name_len, profile_name) = padded_profile_name();
        Ok(KeyAgentInstallRecord {
            schema_version: INSTALL_JOURNAL_SCHEMA_V1,
            policy_version: INSTALL_POLICY_V1,
            transaction_state,
            journal_generation: transaction_generation(transaction_state),
            transaction_id: TRANSACTION_ID,
            installation_id: INSTALLATION_ID,
            release_identity: RELEASE_IDENTITY,
            profile_name_len,
            profile_name,
            stable_user_sid: canonical_sid(0x44),
            profile_sid: canonical_sid(0x55),
            root_identity: root_identity(0x66)?,
        })
    }

    fn journal(saved: Option<KeyAgentInstallRecord>) -> AuthenticatedKeyAgentInstallJournal {
        let authenticated_generation = saved.as_ref().map_or(0, |record| record.journal_generation);
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
        value.schema_version = value.schema_version.saturating_add(1);
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        value.policy_version = value.policy_version.saturating_add(1);
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        value.transaction_id = [0; IDENTITY_BYTES];
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        value.transaction_id = [u8::MAX; IDENTITY_BYTES];
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        value.installation_id = [0; IDENTITY_BYTES];
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        value.installation_id = [u8::MAX; IDENTITY_BYTES];
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        value.release_identity = [0; IDENTITY_BYTES];
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        value.release_identity = [u8::MAX; IDENTITY_BYTES];
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        value.installation_id[0] ^= 1;
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        value.release_identity[0] ^= 1;
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        value.profile_name[0] ^= 1;
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        value.profile_name_len = value.profile_name_len.saturating_sub(1);
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        value.profile_name[MAX_PROFILE_NAME_BYTES - 1] = 1;
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        value.transaction_id = INSTALLATION_ID;
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        value.transaction_id = RELEASE_IDENTITY;
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        value.release_identity = INSTALLATION_ID;
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        value.stable_user_sid.bytes[11] ^= 1;
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        value.profile_sid.bytes[11] ^= 1;
        cases.push(value);

        let mut value = record(KeyAgentInstallTransactionState::Committed)?;
        value.root_identity = root_identity(0x67)?;
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
            saved_record.stable_user_sid = malformed_sid(case);
            let mut observed = objects(true, true)?;
            if let Some(root) = observed.root.as_mut() {
                root.stable_user_sid = malformed_sid(case);
            }
            assert!(is_recovery(classify_key_agent_install(
                journal(Some(saved_record)),
                observed,
            )));

            let mut saved_record = record(KeyAgentInstallTransactionState::Committed)?;
            saved_record.profile_sid = malformed_sid(case);
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
        saved_record.stable_user_sid = canonical_sid(0x55);
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
            saved_record.journal_generation = wrong_generation;
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
        Ok(())
    }
}
