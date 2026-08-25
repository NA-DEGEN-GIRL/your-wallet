//! Debug-only restricted-service token feasibility policy.
//!
//! This module proves only facts that Windows documents independently of the
//! still-unverified helper-launch composition. In particular, the candidate
//! privilege *set* is exact, but privilege enablement, restricting-SID
//! attributes, and the final integrity policy remain explicitly unverified
//! until a real SCM/kernel matrix fixes their expected values.

#![deny(unsafe_code)]

use core::fmt;

use zeroize::Zeroize as _;

mod sys;

/// Fixed virtual service-account name selected by ADR 0001.
pub(crate) const KEY_AGENT_VIRTUAL_SERVICE_ACCOUNT: &str = "NT SERVICE\\YourWalletKeyAgent";

/// Candidate privileges retained by the no-secret Phase 1 fixture.
///
/// `SeChangeNotifyPrivilege` is retained by SCM for compatibility even when it
/// is not listed in `SERVICE_REQUIRED_PRIVILEGES_INFO`. The other three names
/// are the complete feasibility candidates accepted by the Design Brief. This
/// is not the final privilege policy: later kernel calls must remove every
/// candidate they do not actually require.
pub(crate) const KEY_AGENT_SERVICE_FIXTURE_PRIVILEGES: [&str; 4] = [
    "SeChangeNotifyPrivilege",
    "SeImpersonatePrivilege",
    "SeIncreaseQuotaPrivilege",
    "SeAssignPrimaryTokenPrivilege",
];

/// Privileges forbidden by the accepted service design.
pub(crate) const KEY_AGENT_SERVICE_FORBIDDEN_PRIVILEGES: [&str; 4] = [
    "SeTcbPrivilege",
    "SeDebugPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeRestorePrivilege",
];

const WORLD_SID: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
const LOCAL_SID: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0];
const WRITE_RESTRICTED_SID: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 33, 0, 0, 0];

const GROUP_MANDATORY: u32 = 0x0000_0001;
const GROUP_ENABLED_BY_DEFAULT: u32 = 0x0000_0002;
const GROUP_ENABLED: u32 = 0x0000_0004;
const GROUP_OWNER: u32 = 0x0000_0008;
const GROUP_LOGON_ID: u32 = 0xC000_0000;

// SERVICE_SID_INFO documents these exact normal-group attributes.
const SERVICE_SID_GROUP_ATTRIBUTES: u32 = GROUP_ENABLED_BY_DEFAULT | GROUP_OWNER;
const SERVICE_LOGON_GROUP_ATTRIBUTES: u32 =
    GROUP_MANDATORY | GROUP_ENABLED_BY_DEFAULT | GROUP_ENABLED | GROUP_LOGON_ID;
const LOCAL_GROUP_ATTRIBUTES: u32 = GROUP_MANDATORY | GROUP_ENABLED_BY_DEFAULT | GROUP_ENABLED;

const PRIVILEGE_ENABLED_BY_DEFAULT: u32 = 0x0000_0001;
const PRIVILEGE_ENABLED: u32 = 0x0000_0002;
const PRIVILEGE_REMOVED: u32 = 0x0000_0004;
const PRIVILEGE_USED_FOR_ACCESS: u32 = 0x8000_0000;
const VALID_PRIVILEGE_ATTRIBUTES: u32 = PRIVILEGE_ENABLED_BY_DEFAULT
    | PRIVILEGE_ENABLED
    | PRIVILEGE_REMOVED
    | PRIVILEGE_USED_FOR_ACCESS;

/// Completeness of the current no-secret service-token fixture policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ServiceTokenPolicyCompleteness {
    /// Kernel evidence has not fixed every attribute-level expectation yet.
    Unverified,
}

/// The current policy deliberately cannot be promoted to production evidence.
pub(crate) const SERVICE_TOKEN_POLICY_COMPLETENESS: ServiceTokenPolicyCompleteness =
    ServiceTokenPolicyCompleteness::Unverified;

/// Opaque proof that the current process matched the documented fixture policy.
///
/// A value of this type does **not** prove the final service-token policy. It
/// preserves explicit `Unverified` markers for restricting-SID attributes,
/// privilege enablement/use state, integrity, and SCM configuration readback.
#[must_use = "discarding the fixture proof must not be confused with production evidence"]
pub(crate) struct ServiceTokenFixtureProof {
    completeness: ServiceTokenPolicyCompleteness,
    _restricted_sid_attributes: UnverifiedRestrictedSidAttributes,
    _privilege_state: UnverifiedPrivilegeState,
    _integrity_policy: UnverifiedIntegrityPolicy,
    _scm_configuration: UnverifiedScmConfiguration,
}

impl fmt::Debug for ServiceTokenFixtureProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.completeness {
            ServiceTokenPolicyCompleteness::Unverified => {
                formatter.write_str("ServiceTokenFixtureProof([REDACTED])")
            }
        }
    }
}

struct UnverifiedRestrictedSidAttributes;
struct UnverifiedPrivilegeState;
struct UnverifiedIntegrityPolicy;
struct UnverifiedScmConfiguration;

/// Fail-closed service-token observation or policy failure.
pub(crate) struct ServiceTokenFixtureError {
    _kind: ServiceTokenFixtureErrorKind,
}

enum ServiceTokenFixtureErrorKind {
    OperatingSystem,
    Policy,
}

impl ServiceTokenFixtureError {
    const fn operating_system() -> Self {
        Self {
            _kind: ServiceTokenFixtureErrorKind::OperatingSystem,
        }
    }

    const fn policy() -> Self {
        Self {
            _kind: ServiceTokenFixtureErrorKind::Policy,
        }
    }
}

impl fmt::Debug for ServiceTokenFixtureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServiceTokenFixtureError([REDACTED])")
    }
}

impl fmt::Display for ServiceTokenFixtureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("key agent service-token fixture is unavailable")
    }
}

impl std::error::Error for ServiceTokenFixtureError {}

/// Verifies the current process primary token against the no-secret fixture policy.
///
/// This entry point is intended to run synchronously from the fixed SCM service
/// main before `SERVICE_RUNNING` is published. It performs no token, account, or
/// SCM mutation and emits no token values.
///
/// # Errors
///
/// Returns a redacted error if any Windows observation is incomplete or any
/// documented fixture predicate does not match exactly.
pub(crate) fn verify_current_key_agent_service_token_fixture()
-> Result<ServiceTokenFixtureProof, ServiceTokenFixtureError> {
    let captured = sys::capture_current_service_token()?;
    verify_fixture_policy(&captured.observation, &captured.catalog)
        .map_err(|_| ServiceTokenFixtureError::policy())
}

#[derive(Eq, PartialEq)]
#[cfg_attr(test, derive(Clone))]
struct SidBytes(Vec<u8>);

impl SidBytes {
    fn has_canonical_shape(&self) -> bool {
        let Some((&revision, remainder)) = self.0.split_first() else {
            return false;
        };
        let Some((&sub_authority_count, _)) = remainder.split_first() else {
            return false;
        };
        revision == 1
            && usize::from(sub_authority_count) <= 15
            && usize::from(sub_authority_count)
                .checked_mul(core::mem::size_of::<u32>())
                .and_then(|sub_authorities| 8_usize.checked_add(sub_authorities))
                == Some(self.0.len())
    }
}

impl fmt::Debug for SidBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SidBytes([REDACTED])")
    }
}

impl Drop for SidBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct LuidValue {
    low_part: u32,
    high_part: i32,
}

impl fmt::Debug for LuidValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LuidValue([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixturePrivilege {
    ChangeNotify,
    Impersonate,
    IncreaseQuota,
    AssignPrimaryToken,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ForbiddenPrivilege {
    TrustedComputingBase,
    Debug,
    TakeOwnership,
    Restore,
}

#[derive(Clone, Copy)]
struct ExpectedPrivilege {
    kind: FixturePrivilege,
    luid: LuidValue,
}

#[derive(Clone, Copy)]
struct ForbiddenPrivilegeLuid {
    kind: ForbiddenPrivilege,
    luid: LuidValue,
}

#[derive(Clone, Copy)]
struct PrivilegeCatalog {
    expected: [ExpectedPrivilege; KEY_AGENT_SERVICE_FIXTURE_PRIVILEGES.len()],
    forbidden: [ForbiddenPrivilegeLuid; KEY_AGENT_SERVICE_FORBIDDEN_PRIVILEGES.len()],
}

#[cfg_attr(test, derive(Clone))]
struct SidEntry {
    sid: SidBytes,
    attributes: u32,
}

#[derive(Clone, Copy)]
struct PrivilegeEntry {
    luid: LuidValue,
    attributes: u32,
}

#[cfg_attr(test, derive(Clone))]
#[allow(clippy::struct_excessive_bools)] // Each Boolean is one independent token query.
struct ServiceTokenObservation {
    token_is_primary: bool,
    session_id: u32,
    app_container: bool,
    ui_access: bool,
    has_restrictions: bool,
    user_sid: SidBytes,
    groups: Vec<SidEntry>,
    restricted_sids: Vec<SidEntry>,
    privileges: Vec<PrivilegeEntry>,
}

struct CapturedServiceToken {
    observation: ServiceTokenObservation,
    catalog: PrivilegeCatalog,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PolicyRejection {
    TokenShape,
    ServiceIdentity,
    ServiceGroups,
    RestrictedSidSet,
    Privileges,
}

fn verify_fixture_policy(
    token: &ServiceTokenObservation,
    catalog: &PrivilegeCatalog,
) -> Result<ServiceTokenFixtureProof, PolicyRejection> {
    if !token.token_is_primary
        || token.session_id != 0
        || token.app_container
        || token.ui_access
        || !token.has_restrictions
        || !token.user_sid.has_canonical_shape()
    {
        return Err(PolicyRejection::TokenShape);
    }

    let service_sid = &token.user_sid;
    let service_group =
        exactly_one_group(&token.groups, &service_sid.0).ok_or(PolicyRejection::ServiceIdentity)?;
    if service_group.attributes != SERVICE_SID_GROUP_ATTRIBUTES {
        return Err(PolicyRejection::ServiceIdentity);
    }

    let local_group =
        exactly_one_group(&token.groups, LOCAL_SID).ok_or(PolicyRejection::ServiceGroups)?;
    if local_group.attributes != LOCAL_GROUP_ATTRIBUTES {
        return Err(PolicyRejection::ServiceGroups);
    }

    let logon_group = exactly_one_group_with_flag(&token.groups, GROUP_LOGON_ID)
        .ok_or(PolicyRejection::ServiceGroups)?;
    if logon_group.attributes != SERVICE_LOGON_GROUP_ATTRIBUTES
        || !logon_group.sid.has_canonical_shape()
    {
        return Err(PolicyRejection::ServiceGroups);
    }

    let expected_restricted = [
        service_sid.0.as_slice(),
        WORLD_SID,
        logon_group.sid.0.as_slice(),
        WRITE_RESTRICTED_SID,
    ];
    if !contains_exact_sid_set(&token.restricted_sids, &expected_restricted) {
        return Err(PolicyRejection::RestrictedSidSet);
    }

    validate_privileges(&token.privileges, catalog)?;

    Ok(ServiceTokenFixtureProof {
        completeness: SERVICE_TOKEN_POLICY_COMPLETENESS,
        _restricted_sid_attributes: UnverifiedRestrictedSidAttributes,
        _privilege_state: UnverifiedPrivilegeState,
        _integrity_policy: UnverifiedIntegrityPolicy,
        _scm_configuration: UnverifiedScmConfiguration,
    })
}

fn exactly_one_group<'entry>(groups: &'entry [SidEntry], sid: &[u8]) -> Option<&'entry SidEntry> {
    let mut matches = groups.iter().filter(|entry| entry.sid.0 == sid);
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

fn exactly_one_group_with_flag(groups: &[SidEntry], required_flag: u32) -> Option<&SidEntry> {
    let mut matches = groups
        .iter()
        .filter(|entry| entry.attributes & required_flag == required_flag);
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

fn contains_exact_sid_set(entries: &[SidEntry], expected: &[&[u8]]) -> bool {
    entries.len() == expected.len()
        && entries.iter().all(|entry| entry.sid.has_canonical_shape())
        && expected.iter().all(|sid| {
            entries
                .iter()
                .filter(|entry| entry.sid.0.as_slice() == *sid)
                .count()
                == 1
        })
}

fn validate_privileges(
    privileges: &[PrivilegeEntry],
    catalog: &PrivilegeCatalog,
) -> Result<(), PolicyRejection> {
    if catalog.expected.map(|entry| entry.kind)
        != [
            FixturePrivilege::ChangeNotify,
            FixturePrivilege::Impersonate,
            FixturePrivilege::IncreaseQuota,
            FixturePrivilege::AssignPrimaryToken,
        ]
        || catalog.forbidden.map(|entry| entry.kind)
            != [
                ForbiddenPrivilege::TrustedComputingBase,
                ForbiddenPrivilege::Debug,
                ForbiddenPrivilege::TakeOwnership,
                ForbiddenPrivilege::Restore,
            ]
    {
        return Err(PolicyRejection::Privileges);
    }

    let catalog_luids: Vec<LuidValue> = catalog
        .expected
        .iter()
        .map(|entry| entry.luid)
        .chain(catalog.forbidden.iter().map(|entry| entry.luid))
        .collect();
    if catalog_luids
        .iter()
        .enumerate()
        .any(|(index, luid)| catalog_luids[index + 1..].contains(luid))
        || privileges.len() != catalog.expected.len()
    {
        return Err(PolicyRejection::Privileges);
    }

    if privileges.iter().any(|entry| {
        entry.attributes & !VALID_PRIVILEGE_ATTRIBUTES != 0
            || entry.attributes & PRIVILEGE_REMOVED != 0
            || catalog
                .forbidden
                .iter()
                .any(|forbidden| forbidden.luid == entry.luid)
    }) {
        return Err(PolicyRejection::Privileges);
    }

    for expected in catalog.expected {
        if privileges
            .iter()
            .filter(|entry| entry.luid == expected.luid)
            .count()
            != 1
        {
            return Err(PolicyRejection::Privileges);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(authority: u64, sub_authorities: &[u32]) -> SidBytes {
        assert!(authority <= 0x0000_FFFF_FFFF_FFFF);
        assert!(sub_authorities.len() <= 15);
        let mut bytes = Vec::with_capacity(8 + sub_authorities.len() * 4);
        bytes.push(1);
        bytes.push(u8::try_from(sub_authorities.len()).unwrap_or_default());
        bytes.extend_from_slice(&authority.to_be_bytes()[2..]);
        for sub_authority in sub_authorities {
            bytes.extend_from_slice(&sub_authority.to_le_bytes());
        }
        let sid = SidBytes(bytes);
        assert!(sid.has_canonical_shape());
        sid
    }

    fn service_sid() -> SidBytes {
        sid(5, &[80, 1, 2, 3, 4, 5])
    }

    fn logon_sid() -> SidBytes {
        sid(5, &[5, 10, 20])
    }

    const fn luid(value: u32) -> LuidValue {
        LuidValue {
            low_part: value,
            high_part: 0,
        }
    }

    fn catalog() -> PrivilegeCatalog {
        PrivilegeCatalog {
            expected: [
                ExpectedPrivilege {
                    kind: FixturePrivilege::ChangeNotify,
                    luid: luid(1),
                },
                ExpectedPrivilege {
                    kind: FixturePrivilege::Impersonate,
                    luid: luid(2),
                },
                ExpectedPrivilege {
                    kind: FixturePrivilege::IncreaseQuota,
                    luid: luid(3),
                },
                ExpectedPrivilege {
                    kind: FixturePrivilege::AssignPrimaryToken,
                    luid: luid(4),
                },
            ],
            forbidden: [
                ForbiddenPrivilegeLuid {
                    kind: ForbiddenPrivilege::TrustedComputingBase,
                    luid: luid(5),
                },
                ForbiddenPrivilegeLuid {
                    kind: ForbiddenPrivilege::Debug,
                    luid: luid(6),
                },
                ForbiddenPrivilegeLuid {
                    kind: ForbiddenPrivilege::TakeOwnership,
                    luid: luid(7),
                },
                ForbiddenPrivilegeLuid {
                    kind: ForbiddenPrivilege::Restore,
                    luid: luid(8),
                },
            ],
        }
    }

    fn observation() -> ServiceTokenObservation {
        ServiceTokenObservation {
            token_is_primary: true,
            session_id: 0,
            app_container: false,
            ui_access: false,
            has_restrictions: true,
            user_sid: service_sid(),
            groups: vec![
                SidEntry {
                    sid: service_sid(),
                    attributes: SERVICE_SID_GROUP_ATTRIBUTES,
                },
                SidEntry {
                    sid: SidBytes(LOCAL_SID.to_vec()),
                    attributes: LOCAL_GROUP_ATTRIBUTES,
                },
                SidEntry {
                    sid: logon_sid(),
                    attributes: SERVICE_LOGON_GROUP_ATTRIBUTES,
                },
                SidEntry {
                    sid: sid(5, &[11]),
                    attributes: GROUP_ENABLED,
                },
            ],
            restricted_sids: vec![
                SidEntry {
                    sid: service_sid(),
                    attributes: 0,
                },
                SidEntry {
                    sid: SidBytes(WORLD_SID.to_vec()),
                    attributes: GROUP_ENABLED,
                },
                SidEntry {
                    sid: logon_sid(),
                    attributes: GROUP_OWNER,
                },
                SidEntry {
                    sid: SidBytes(WRITE_RESTRICTED_SID.to_vec()),
                    attributes: u32::MAX,
                },
            ],
            privileges: vec![
                PrivilegeEntry {
                    luid: luid(1),
                    attributes: PRIVILEGE_ENABLED_BY_DEFAULT | PRIVILEGE_ENABLED,
                },
                PrivilegeEntry {
                    luid: luid(2),
                    attributes: PRIVILEGE_ENABLED,
                },
                PrivilegeEntry {
                    luid: luid(3),
                    attributes: 0,
                },
                PrivilegeEntry {
                    luid: luid(4),
                    attributes: PRIVILEGE_USED_FOR_ACCESS,
                },
            ],
        }
    }

    #[test]
    fn documented_fixture_policy_passes_but_remains_unverified() {
        let result = verify_fixture_policy(&observation(), &catalog());
        assert!(result.is_ok());
        if let Ok(proof) = result {
            assert_eq!(
                proof.completeness,
                ServiceTokenPolicyCompleteness::Unverified
            );
            assert_eq!(format!("{proof:?}"), "ServiceTokenFixtureProof([REDACTED])");
        }
    }

    #[test]
    fn every_scalar_and_service_group_policy_mutation_is_rejected() {
        let mut rejected = Vec::new();

        let mut value = observation();
        value.token_is_primary = false;
        rejected.push(value);
        let mut value = observation();
        value.session_id = 1;
        rejected.push(value);
        let mut value = observation();
        value.app_container = true;
        rejected.push(value);
        let mut value = observation();
        value.ui_access = true;
        rejected.push(value);
        let mut value = observation();
        value.has_restrictions = false;
        rejected.push(value);
        let mut value = observation();
        value.user_sid = sid(5, &[80, 9, 9, 9, 9, 9]);
        rejected.push(value);
        let mut value = observation();
        value.user_sid.0[0] = 2;
        rejected.push(value);

        for group_index in 0..3 {
            let mut value = observation();
            value.groups.remove(group_index);
            rejected.push(value);
        }
        for group_index in 0..3 {
            let mut value = observation();
            let duplicate = value.groups[group_index].clone();
            value.groups.push(duplicate);
            rejected.push(value);
        }
        for group_index in 0..3 {
            let mut value = observation();
            value.groups[group_index].attributes ^= GROUP_ENABLED;
            rejected.push(value);
        }
        let mut value = observation();
        value.groups.push(SidEntry {
            sid: sid(5, &[5, 30, 40]),
            attributes: GROUP_LOGON_ID,
        });
        rejected.push(value);

        assert!(
            rejected
                .iter()
                .all(|value| verify_fixture_policy(value, &catalog()).is_err())
        );
    }

    #[test]
    fn exact_documented_restricted_sid_quartet_rejects_every_set_mutation() {
        let mut rejected = Vec::new();
        for index in 0..4 {
            let mut value = observation();
            value.restricted_sids.remove(index);
            rejected.push(value);
        }
        for index in 0..4 {
            let mut value = observation();
            let duplicate = value.restricted_sids[index].clone();
            value.restricted_sids.push(duplicate);
            rejected.push(value);
        }
        let mut value = observation();
        value.restricted_sids[2].sid = sid(5, &[5, 10, 21]);
        rejected.push(value);
        let mut value = observation();
        value.restricted_sids[0].sid = sid(5, &[80, 6, 7, 8, 9, 10]);
        rejected.push(value);
        let mut value = observation();
        value.restricted_sids[1].sid.0[1] = 2;
        rejected.push(value);

        assert!(
            rejected
                .iter()
                .all(|value| verify_fixture_policy(value, &catalog()).is_err())
        );
    }

    #[test]
    fn candidate_privileges_are_an_exact_presence_set_with_bounded_attributes() {
        let fixture_catalog = catalog();
        let mut rejected = Vec::new();

        for index in 0..fixture_catalog.expected.len() {
            let mut value = observation();
            value.privileges.remove(index);
            rejected.push(value);
        }
        for forbidden in fixture_catalog.forbidden {
            let mut value = observation();
            value.privileges[0] = PrivilegeEntry {
                luid: forbidden.luid,
                attributes: 0,
            };
            rejected.push(value);
        }
        let mut value = observation();
        value.privileges[0].luid = luid(99);
        rejected.push(value);
        let mut value = observation();
        value.privileges[0].attributes = PRIVILEGE_REMOVED;
        rejected.push(value);
        let mut value = observation();
        value.privileges[0].attributes = 0x0000_0100;
        rejected.push(value);

        assert!(
            rejected
                .iter()
                .all(|value| verify_fixture_policy(value, &fixture_catalog).is_err())
        );

        let mut colliding = fixture_catalog;
        colliding.forbidden[0].luid = colliding.expected[0].luid;
        assert!(verify_fixture_policy(&observation(), &colliding).is_err());
    }

    #[test]
    fn redacted_public_errors_never_expose_policy_details() {
        for error in [
            ServiceTokenFixtureError::operating_system(),
            ServiceTokenFixtureError::policy(),
        ] {
            assert_eq!(format!("{error:?}"), "ServiceTokenFixtureError([REDACTED])");
            assert_eq!(
                error.to_string(),
                "key agent service-token fixture is unavailable"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires execution inside the installed restricted YourWalletKeyAgent SCM service context"]
    fn installed_service_context_matches_documented_fixture_policy()
    -> Result<(), ServiceTokenFixtureError> {
        verify_current_key_agent_service_token_fixture().map(|_proof| ())
    }
}
