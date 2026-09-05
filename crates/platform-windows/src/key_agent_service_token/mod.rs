//! Debug-only restricted-service token feasibility policy.
//!
//! This module checks documented token facts and narrowly scoped observed
//! fixture representations, not the still-unverified helper-launch composition.
//! In particular, the candidate
//! privilege *set* is exact, but privilege enablement, restricting-SID
//! attributes, and the final integrity policy remain explicitly unverified
//! until a real SCM/kernel matrix fixes their expected values.

#![deny(unsafe_code)]

use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;
use std::os::windows::io::BorrowedHandle;

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

// SERVICE_SID_INFO documents these attributes if a separate normal-group
// service SID is present. TokenUser is already the OS-resolved fixed virtual
// account; TOKEN_OWNER permits that user SID without a redundant group entry.
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
    retained_token: sys::OwnedToken,
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "debug-only Phase 1 service probe is gated out of ordinary builds"
        )
    )]
    baseline: ServiceTokenBaseline,
    completeness: ServiceTokenPolicyCompleteness,
    _restricted_sid_attributes: UnverifiedRestrictedSidAttributes,
    _privilege_state: UnverifiedPrivilegeState,
    _integrity_policy: UnverifiedIntegrityPolicy,
    _scm_configuration: UnverifiedScmConfiguration,
    _not_sync: PhantomData<Cell<()>>,
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

impl ServiceTokenFixtureProof {
    fn revalidate_creation_token(&mut self) -> Result<(), ServiceTokenFixtureError> {
        let mut recaptured = sys::recapture_current_service_token(&self.retained_token)?;
        canonicalize_service_token_baseline(&mut recaptured.captured.baseline);
        verify_creation_token_revalidation(
            &self.baseline,
            &recaptured.captured.baseline,
            recaptured.retained_handle_flags,
            recaptured.same_token_object,
        )
        .map_err(|reason| {
            ServiceTokenFixtureError::policy_rejection_for_baseline(
                reason,
                &recaptured.captured.baseline,
            )
        })
    }

    /// Freshly revalidates the retained service token before lending it to the
    /// sibling creation-security seam.
    ///
    /// The exclusive borrow prevents another revalidation or handle borrow
    /// until the returned marker has been consumed and dropped.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "debug-only Phase 1 service probe is gated out of ordinary builds"
        )
    )]
    pub(crate) fn creation_token(
        &mut self,
    ) -> Result<VerifiedServiceCreationToken<'_>, ServiceTokenFixtureError> {
        self.revalidate_creation_token()?;

        Ok(VerifiedServiceCreationToken {
            proof: self,
            _not_sync: PhantomData,
        })
    }
}

/// Fresh, lifetime-bound authority to borrow the retained service token for
/// the sibling creation-security seam.
///
/// This marker owns no identity, SID, PID, or raw-handle data. It is move-only,
/// is not `Sync`, and keeps an exclusive borrow of the complete fixture proof
/// until the creation-security operation has finished its readback.
#[must_use = "the freshly revalidated creation-token authority must stay live through readback"]
pub(crate) struct VerifiedServiceCreationToken<'proof> {
    proof: &'proof mut ServiceTokenFixtureProof,
    _not_sync: PhantomData<Cell<()>>,
}

impl VerifiedServiceCreationToken<'_> {
    pub(crate) fn borrowed_handle(&self) -> BorrowedHandle<'_> {
        self.proof.retained_token.borrowed_handle()
    }

    /// Confirms that descriptor construction copied the exact retained token
    /// owner and primary-group SIDs without exporting either principal.
    pub(crate) fn verify_creation_principals(
        &self,
        owner: &[u8],
        primary_group: &[u8],
    ) -> Result<(), ServiceTokenFixtureError> {
        let observation = &self.proof.baseline.observation;
        if owner != observation.owner_sid.0.as_slice()
            || primary_group != observation.primary_group_sid.0.as_slice()
        {
            return Err(ServiceTokenFixtureError::policy()
                .at_stage(ServiceTokenCaptureStage::CreationPrincipals));
        }
        Ok(())
    }

    /// Repeats the complete retained/fresh-token and policy continuity check.
    pub(crate) fn revalidate(&mut self) -> Result<(), ServiceTokenFixtureError> {
        self.proof.revalidate_creation_token()
    }
}

impl fmt::Debug for VerifiedServiceCreationToken<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedServiceCreationToken([REDACTED])")
    }
}

struct UnverifiedRestrictedSidAttributes;
struct UnverifiedPrivilegeState;
struct UnverifiedIntegrityPolicy;
struct UnverifiedScmConfiguration;

/// Fail-closed service-token observation or policy failure.
#[cfg_attr(
    not(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    )),
    allow(
        dead_code,
        reason = "closed diagnostics have no default or release consumer"
    )
)]
pub(crate) struct ServiceTokenFixtureError {
    kind: ServiceTokenFixtureErrorKind,
    stage: ServiceTokenCaptureStage,
    policy_rejection: Option<PolicyRejection>,
    policy_detail: Option<ServiceTokenPolicyDetail>,
    remaining_policy_failures: Option<ServiceTokenRemainingPolicyFailures>,
}

enum ServiceTokenFixtureErrorKind {
    OperatingSystem,
    Policy,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ServiceTokenPolicyDetail {
    OwnerMismatch,
    ServiceGroupMultiplicity,
    ServiceGroupAttributes,
}

// Only fixed predicate outcomes from the already captured baseline, never raw
// token values. Missing/duplicate Local or logon entries make their dependent
// checks unavailable; the corresponding multiplicity bit tells the decoder.
#[cfg_attr(
    not(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    )),
    allow(
        dead_code,
        reason = "closed diagnostics have no default or release consumer"
    )
)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent closed failure predicates, not state-machine flags"
)]
struct ServiceTokenRemainingPolicyFailures {
    primary_group: bool,
    local_group: bool,
    local_attributes: bool,
    logon_group: bool,
    logon_attributes: bool,
    restricted_sids: bool,
    privileges: bool,
    logon_attribute_detail: Option<ServiceTokenLogonAttributeFailures>,
}

impl ServiceTokenRemainingPolicyFailures {
    fn from_baseline(baseline: &ServiceTokenBaseline) -> Self {
        let token = &baseline.observation;
        let local = exactly_one_group(&token.groups, LOCAL_SID);
        let logon = exactly_one_group_with_flag(&token.groups, GROUP_LOGON_ID);
        Self {
            primary_group: !primary_group_is_bound(
                &token.primary_group_sid,
                &token.user_sid,
                &token.groups,
            ),
            local_group: local.is_none(),
            local_attributes: local.is_some_and(|group| group.attributes != LOCAL_GROUP_ATTRIBUTES),
            logon_group: logon.is_none(),
            logon_attributes: logon.is_some_and(|group| {
                !service_logon_group_attributes_are_supported(group.attributes)
                    || !group.sid.has_canonical_shape()
            }),
            restricted_sids: logon.is_some_and(|group| {
                !contains_exact_sid_set(
                    &token.restricted_sids,
                    &[
                        token.user_sid.0.as_slice(),
                        WORLD_SID,
                        group.sid.0.as_slice(),
                        WRITE_RESTRICTED_SID,
                    ],
                )
            }),
            privileges: validate_privileges(&token.privileges, &baseline.catalog).is_err(),
            logon_attribute_detail: logon
                .filter(|group| !service_logon_group_attributes_are_supported(group.attributes))
                .map(|group| ServiceTokenLogonAttributeFailures::from_attributes(group.attributes)),
        }
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    const fn service_specific_code(&self) -> Option<u32> {
        let mut code = 0x4000;
        if self.primary_group {
            code |= 0x01;
        }
        if self.local_group {
            code |= 0x02;
        }
        if self.local_attributes {
            code |= 0x04;
        }
        if self.logon_group {
            code |= 0x08;
        }
        if self.logon_attributes {
            code |= 0x10;
        }
        if self.restricted_sids {
            code |= 0x20;
        }
        if self.privileges {
            code |= 0x40;
        }
        // Only this sole failure can be refined: every other aggregate check
        // passed. Mixed failures retain the complete original aggregate code.
        if code == 0x4010
            && let Some(detail) = &self.logon_attribute_detail
            && let Some(refined) = detail.diagnostic_code()
        {
            return Some(refined);
        }
        // A report with no failed predicate never disguises the original error.
        if code == 0x4000 { None } else { Some(code) }
    }
}

// Semantic differences only, never a retained or emitted native attribute mask.
// Both LOGON_ID bits are already required by the unique-group selector.
#[cfg_attr(
    not(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    )),
    allow(
        dead_code,
        reason = "closed diagnostics have no default or release consumer"
    )
)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent closed failure predicates, not state-machine flags"
)]
struct ServiceTokenLogonAttributeFailures {
    missing_mandatory: bool,
    missing_enabled_by_default: bool,
    missing_enabled: bool,
    extra_owner: bool,
    extra_deny_only: bool,
    extra_integrity: bool,
    extra_integrity_enabled: bool,
    extra_resource: bool,
    unknown_bits: bool,
}

impl ServiceTokenLogonAttributeFailures {
    fn from_attributes(attributes: u32) -> Self {
        Self {
            missing_mandatory: attributes & GROUP_MANDATORY == 0,
            missing_enabled_by_default: attributes & GROUP_ENABLED_BY_DEFAULT == 0,
            missing_enabled: attributes & GROUP_ENABLED == 0,
            extra_owner: attributes & GROUP_OWNER != 0,
            extra_deny_only: attributes & 0x0000_0010 != 0,
            extra_integrity: attributes & 0x0000_0020 != 0,
            extra_integrity_enabled: attributes & 0x0000_0040 != 0,
            extra_resource: attributes & 0x2000_0000 != 0,
            unknown_bits: attributes & !0xE000_007F != 0,
        }
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    const fn diagnostic_code(&self) -> Option<u32> {
        let mut code = 0x5000;
        if self.missing_mandatory {
            code |= 0x001;
        }
        if self.missing_enabled_by_default {
            code |= 0x002;
        }
        if self.missing_enabled {
            code |= 0x004;
        }
        if self.extra_owner {
            code |= 0x008;
        }
        if self.extra_deny_only {
            code |= 0x010;
        }
        if self.extra_integrity {
            code |= 0x020;
        }
        if self.extra_integrity_enabled {
            code |= 0x040;
        }
        if self.extra_resource {
            code |= 0x080;
        }
        if self.unknown_bits {
            code |= 0x100;
        }
        if code == 0x5000 { None } else { Some(code) }
    }
}

// Closed, data-free capture boundaries. These labels never contain a native
// error, token value, account, SID, PID, handle, or privilege value.
#[derive(Clone, Copy, Eq, PartialEq)]
enum ServiceTokenCaptureStage {
    Unspecified,
    ThreadBefore,
    TokenOpen,
    HandleFlags,
    ServiceSid,
    PrivilegeCatalog,
    IdentityBefore,
    TokenType,
    Session,
    AppContainer,
    UiAccess,
    Restrictions,
    UserSid,
    UserIdentity,
    OwnerSid,
    PrimaryGroupSid,
    Groups,
    RestrictedSids,
    Privileges,
    IdentityAfter,
    IdentityContinuity,
    ThreadAfter,
    RetainedHandleFlags,
    FreshIdentity,
    RecaptureIdentityContinuity,
    CreationPrincipals,
}

impl ServiceTokenFixtureError {
    const fn operating_system() -> Self {
        Self {
            kind: ServiceTokenFixtureErrorKind::OperatingSystem,
            stage: ServiceTokenCaptureStage::Unspecified,
            policy_rejection: None,
            policy_detail: None,
            remaining_policy_failures: None,
        }
    }

    const fn policy() -> Self {
        Self {
            kind: ServiceTokenFixtureErrorKind::Policy,
            stage: ServiceTokenCaptureStage::Unspecified,
            policy_rejection: None,
            policy_detail: None,
            remaining_policy_failures: None,
        }
    }

    const fn at_stage(mut self, stage: ServiceTokenCaptureStage) -> Self {
        self.stage = stage;
        self
    }

    const fn policy_rejection(reason: PolicyRejection) -> Self {
        Self {
            kind: ServiceTokenFixtureErrorKind::Policy,
            stage: ServiceTokenCaptureStage::Unspecified,
            policy_rejection: Some(reason),
            policy_detail: None,
            remaining_policy_failures: None,
        }
    }

    fn policy_rejection_for_baseline(
        reason: PolicyRejection,
        baseline: &ServiceTokenBaseline,
    ) -> Self {
        let mut error = Self::policy_rejection(reason);
        // Classify the already rejected baseline with the same identity rule.
        // This does not query another token or convert a rejection to success.
        if reason == PolicyRejection::ServiceIdentity {
            error.policy_detail = service_identity_rejection(&baseline.observation);
        }
        if reason == PolicyRejection::ServiceGroups
            || reason == PolicyRejection::RestrictedSidSet
            || reason == PolicyRejection::Privileges
        {
            error.remaining_policy_failures =
                Some(ServiceTokenRemainingPolicyFailures::from_baseline(baseline));
        }
        error
    }

    /// Returns only a closed debug SCM diagnostic category, never native data.
    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    pub(crate) const fn startup_diagnostic_code(&self) -> u32 {
        if let Some(failures) = &self.remaining_policy_failures
            && let Some(code) = failures.service_specific_code()
        {
            return code;
        }
        if let Some(reason) = self.policy_rejection {
            if let Some(detail) = self.policy_detail {
                return match detail {
                    ServiceTokenPolicyDetail::OwnerMismatch => 0x2191,
                    ServiceTokenPolicyDetail::ServiceGroupMultiplicity => 0x2192,
                    ServiceTokenPolicyDetail::ServiceGroupAttributes => 0x2193,
                };
            }
            return match reason {
                PolicyRejection::HandleContinuity => 0x2181,
                PolicyRejection::TokenShape => 0x2182,
                PolicyRejection::ServiceIdentity => 0x2183,
                PolicyRejection::ServiceGroups => 0x2184,
                PolicyRejection::RestrictedSidSet => 0x2185,
                PolicyRejection::Privileges => 0x2186,
                PolicyRejection::BaselineContinuity => 0x2187,
            };
        }
        match self.stage {
            ServiceTokenCaptureStage::Unspecified => match self.kind {
                ServiceTokenFixtureErrorKind::OperatingSystem => 0x2100,
                ServiceTokenFixtureErrorKind::Policy => 0x2180,
            },
            ServiceTokenCaptureStage::ThreadBefore => 0x2101,
            ServiceTokenCaptureStage::TokenOpen => 0x2102,
            ServiceTokenCaptureStage::HandleFlags => 0x2103,
            ServiceTokenCaptureStage::ServiceSid => 0x2104,
            ServiceTokenCaptureStage::PrivilegeCatalog => 0x2105,
            ServiceTokenCaptureStage::IdentityBefore => 0x2106,
            ServiceTokenCaptureStage::TokenType => 0x2107,
            ServiceTokenCaptureStage::Session => 0x2108,
            ServiceTokenCaptureStage::AppContainer => 0x2109,
            ServiceTokenCaptureStage::UiAccess => 0x210a,
            ServiceTokenCaptureStage::Restrictions => 0x210b,
            ServiceTokenCaptureStage::UserSid => 0x210c,
            ServiceTokenCaptureStage::UserIdentity => 0x210d,
            ServiceTokenCaptureStage::OwnerSid => 0x210e,
            ServiceTokenCaptureStage::PrimaryGroupSid => 0x210f,
            ServiceTokenCaptureStage::Groups => 0x2110,
            ServiceTokenCaptureStage::RestrictedSids => 0x2111,
            ServiceTokenCaptureStage::Privileges => 0x2112,
            ServiceTokenCaptureStage::IdentityAfter => 0x2113,
            ServiceTokenCaptureStage::IdentityContinuity => 0x2114,
            ServiceTokenCaptureStage::ThreadAfter => 0x2115,
            ServiceTokenCaptureStage::RetainedHandleFlags => 0x2116,
            ServiceTokenCaptureStage::FreshIdentity => 0x2117,
            ServiceTokenCaptureStage::RecaptureIdentityContinuity => 0x2118,
            ServiceTokenCaptureStage::CreationPrincipals => 0x2119,
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
    let mut captured = sys::capture_current_service_token()?;
    canonicalize_service_token_baseline(&mut captured.baseline);
    verify_fixture_baseline(&captured.baseline).map_err(|reason| {
        ServiceTokenFixtureError::policy_rejection_for_baseline(reason, &captured.baseline)
    })?;
    Ok(ServiceTokenFixtureProof {
        retained_token: captured.token,
        baseline: captured.baseline,
        completeness: SERVICE_TOKEN_POLICY_COMPLETENESS,
        _restricted_sid_attributes: UnverifiedRestrictedSidAttributes,
        _privilege_state: UnverifiedPrivilegeState,
        _integrity_policy: UnverifiedIntegrityPolicy,
        _scm_configuration: UnverifiedScmConfiguration,
        _not_sync: PhantomData,
    })
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

impl LuidValue {
    fn zeroize(&mut self) {
        self.low_part.zeroize();
        self.high_part.zeroize();
    }
}

#[derive(Eq, PartialEq)]
#[cfg_attr(test, derive(Clone))]
struct TokenIdentityBaseline {
    token_id: LuidValue,
    modified_id: LuidValue,
}

impl Drop for TokenIdentityBaseline {
    fn drop(&mut self) {
        self.token_id.zeroize();
        self.modified_id.zeroize();
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

#[derive(Clone, Copy, Eq, PartialEq)]
struct ExpectedPrivilege {
    kind: FixturePrivilege,
    luid: LuidValue,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ForbiddenPrivilegeLuid {
    kind: ForbiddenPrivilege,
    luid: LuidValue,
}

#[derive(Eq, PartialEq)]
#[cfg_attr(test, derive(Clone))]
struct PrivilegeCatalog {
    expected: [ExpectedPrivilege; KEY_AGENT_SERVICE_FIXTURE_PRIVILEGES.len()],
    forbidden: [ForbiddenPrivilegeLuid; KEY_AGENT_SERVICE_FORBIDDEN_PRIVILEGES.len()],
}

impl Drop for PrivilegeCatalog {
    fn drop(&mut self) {
        for entry in &mut self.expected {
            entry.luid.zeroize();
        }
        for entry in &mut self.forbidden {
            entry.luid.zeroize();
        }
    }
}

#[derive(Eq, PartialEq)]
#[cfg_attr(test, derive(Clone))]
struct SidEntry {
    sid: SidBytes,
    attributes: u32,
}

impl Drop for SidEntry {
    fn drop(&mut self) {
        self.attributes.zeroize();
    }
}

#[derive(Eq, PartialEq)]
#[cfg_attr(test, derive(Clone))]
struct PrivilegeEntry {
    luid: LuidValue,
    attributes: u32,
}

impl Drop for PrivilegeEntry {
    fn drop(&mut self) {
        self.luid.zeroize();
        self.attributes.zeroize();
    }
}

#[derive(Eq, PartialEq)]
#[cfg_attr(test, derive(Clone))]
#[allow(clippy::struct_excessive_bools)] // Each Boolean is one independent token query.
struct ServiceTokenObservation {
    identity: TokenIdentityBaseline,
    token_is_primary: bool,
    session_id: u32,
    app_container: bool,
    ui_access: bool,
    has_restrictions: bool,
    user_sid: SidBytes,
    owner_sid: SidBytes,
    primary_group_sid: SidBytes,
    groups: Vec<SidEntry>,
    restricted_sids: Vec<SidEntry>,
    privileges: Vec<PrivilegeEntry>,
}

impl Drop for ServiceTokenObservation {
    fn drop(&mut self) {
        self.token_is_primary.zeroize();
        self.session_id.zeroize();
        self.app_container.zeroize();
        self.ui_access.zeroize();
        self.has_restrictions.zeroize();
    }
}

#[derive(Eq, PartialEq)]
#[cfg_attr(test, derive(Clone))]
struct ServiceTokenBaseline {
    token_handle_flags: u32,
    observation: ServiceTokenObservation,
    catalog: PrivilegeCatalog,
}

impl Drop for ServiceTokenBaseline {
    fn drop(&mut self) {
        self.token_handle_flags.zeroize();
    }
}

struct CapturedServiceToken {
    token: sys::OwnedToken,
    baseline: ServiceTokenBaseline,
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "debug-only Phase 1 service probe is gated out of ordinary builds"
    )
)]
struct RecapturedServiceToken {
    captured: CapturedServiceToken,
    retained_handle_flags: u32,
    same_token_object: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PolicyRejection {
    HandleContinuity,
    TokenShape,
    ServiceIdentity,
    ServiceGroups,
    RestrictedSidSet,
    Privileges,
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "debug-only Phase 1 service probe is gated out of ordinary builds"
        )
    )]
    BaselineContinuity,
}

fn verify_fixture_baseline(baseline: &ServiceTokenBaseline) -> Result<(), PolicyRejection> {
    if baseline.token_handle_flags != 0 {
        return Err(PolicyRejection::HandleContinuity);
    }
    verify_fixture_policy(&baseline.observation, &baseline.catalog)
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "debug-only Phase 1 service probe is gated out of ordinary builds"
    )
)]
fn verify_creation_token_revalidation(
    baseline: &ServiceTokenBaseline,
    fresh: &ServiceTokenBaseline,
    retained_handle_flags: u32,
    same_token_object: bool,
) -> Result<(), PolicyRejection> {
    if retained_handle_flags != 0 || !same_token_object {
        return Err(PolicyRejection::HandleContinuity);
    }
    verify_fixture_baseline(fresh)?;
    if fresh != baseline {
        return Err(PolicyRejection::BaselineContinuity);
    }
    Ok(())
}

fn canonicalize_service_token_baseline(baseline: &mut ServiceTokenBaseline) {
    baseline.observation.groups.sort_by(|left, right| {
        left.sid
            .0
            .cmp(&right.sid.0)
            .then(left.attributes.cmp(&right.attributes))
    });
    baseline.observation.restricted_sids.sort_by(|left, right| {
        left.sid
            .0
            .cmp(&right.sid.0)
            .then(left.attributes.cmp(&right.attributes))
    });
    baseline.observation.privileges.sort_by(|left, right| {
        left.luid
            .high_part
            .cmp(&right.luid.high_part)
            .then(left.luid.low_part.cmp(&right.luid.low_part))
            .then(left.attributes.cmp(&right.attributes))
    });
}

fn verify_fixture_policy(
    token: &ServiceTokenObservation,
    catalog: &PrivilegeCatalog,
) -> Result<(), PolicyRejection> {
    if !token.token_is_primary
        || token.session_id != 0
        || token.app_container
        || token.ui_access
        || !token.has_restrictions
        || !token.user_sid.has_canonical_shape()
        || !token.owner_sid.has_canonical_shape()
        || !token.primary_group_sid.has_canonical_shape()
    {
        return Err(PolicyRejection::TokenShape);
    }

    let service_sid = &token.user_sid;
    if service_identity_rejection(token).is_some() {
        return Err(PolicyRejection::ServiceIdentity);
    }
    if !primary_group_is_bound(&token.primary_group_sid, service_sid, &token.groups) {
        return Err(PolicyRejection::ServiceGroups);
    }

    let local_group =
        exactly_one_group(&token.groups, LOCAL_SID).ok_or(PolicyRejection::ServiceGroups)?;
    if local_group.attributes != LOCAL_GROUP_ATTRIBUTES {
        return Err(PolicyRejection::ServiceGroups);
    }

    let logon_group = exactly_one_group_with_flag(&token.groups, GROUP_LOGON_ID)
        .ok_or(PolicyRejection::ServiceGroups)?;
    if !service_logon_group_attributes_are_supported(logon_group.attributes)
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

    Ok(())
}

fn service_logon_group_attributes_are_supported(attributes: u32) -> bool {
    // Retain the documented SCM form and the exact OWNER-capable form observed
    // in this host's installed fixture. OWNER eligibility does not select the
    // actual TokenOwner: that remains the fixed service user, sealed separately.
    // Do not strip attributes; full baseline continuity binds the complete value.
    attributes == SERVICE_LOGON_GROUP_ATTRIBUTES
        || attributes == (SERVICE_LOGON_GROUP_ATTRIBUTES | GROUP_OWNER)
}

fn primary_group_is_bound(primary: &SidBytes, user: &SidBytes, groups: &[SidEntry]) -> bool {
    // LSA logon-token construction permits primary-group metadata independent
    // of assigned groups. Support the observed primary==user form, while still
    // requiring exactly one normal entry for any other primary principal.
    // The caller already verified fixed TokenUser and rejected duplicate or
    // invalid service-group entries; full baseline continuity binds this value.
    primary == user || exactly_one_group(groups, &primary.0).is_some()
}

fn service_identity_rejection(token: &ServiceTokenObservation) -> Option<ServiceTokenPolicyDetail> {
    // capture_service_token_baseline already binds TokenUser to the exact
    // OS-resolved virtual service account. That principal may own objects as
    // TokenUser; it need not also be represented in TokenGroups. Keep owner
    // equality, and validate rather than ignore any separately present group.
    if token.owner_sid != token.user_sid {
        return Some(ServiceTokenPolicyDetail::OwnerMismatch);
    }
    let mut service_groups = token
        .groups
        .iter()
        .filter(|entry| entry.sid == token.user_sid);
    let first = service_groups.next();
    if service_groups.next().is_some() {
        return Some(ServiceTokenPolicyDetail::ServiceGroupMultiplicity);
    }
    match first {
        Some(group) if group.attributes != SERVICE_SID_GROUP_ATTRIBUTES => {
            Some(ServiceTokenPolicyDetail::ServiceGroupAttributes)
        }
        Some(_) | None => None,
    }
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
            identity: TokenIdentityBaseline {
                token_id: luid(9),
                modified_id: luid(10),
            },
            token_is_primary: true,
            session_id: 0,
            app_container: false,
            ui_access: false,
            has_restrictions: true,
            user_sid: service_sid(),
            owner_sid: service_sid(),
            primary_group_sid: SidBytes(LOCAL_SID.to_vec()),
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

    fn baseline() -> ServiceTokenBaseline {
        let mut baseline = ServiceTokenBaseline {
            token_handle_flags: 0,
            observation: observation(),
            catalog: catalog(),
        };
        canonicalize_service_token_baseline(&mut baseline);
        baseline
    }

    fn fixture_proof() -> ServiceTokenFixtureProof {
        ServiceTokenFixtureProof {
            retained_token: sys::OwnedToken::invalid_for_test(),
            baseline: baseline(),
            completeness: SERVICE_TOKEN_POLICY_COMPLETENESS,
            _restricted_sid_attributes: UnverifiedRestrictedSidAttributes,
            _privilege_state: UnverifiedPrivilegeState,
            _integrity_policy: UnverifiedIntegrityPolicy,
            _scm_configuration: UnverifiedScmConfiguration,
            _not_sync: PhantomData,
        }
    }

    #[test]
    fn documented_fixture_policy_passes_but_remains_unverified() {
        let result = verify_fixture_policy(&observation(), &catalog());
        assert_eq!(result, Ok(()));
        assert_eq!(verify_fixture_baseline(&baseline()), Ok(()));

        let proof = fixture_proof();
        assert_eq!(
            proof.completeness,
            ServiceTokenPolicyCompleteness::Unverified
        );
        assert_eq!(format!("{proof:?}"), "ServiceTokenFixtureProof([REDACTED])");
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
        let mut value = observation();
        value.owner_sid = sid(5, &[80, 9, 9, 9, 9, 9]);
        rejected.push(value);
        let mut value = observation();
        value.primary_group_sid = sid(5, &[32, 999]);
        rejected.push(value);
        let mut value = observation();
        value.primary_group_sid.0[0] = 2;
        rejected.push(value);

        // The virtual-account user need not be repeated as normal group 0.
        for group_index in 1..3 {
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
    fn virtual_account_user_identity_accepts_zero_or_one_exact_service_group() {
        for separate_group in [false, true] {
            let mut value = baseline();
            if !separate_group {
                value
                    .observation
                    .groups
                    .retain(|group| group.sid != service_sid());
            }
            assert!(service_identity_rejection(&value.observation).is_none());
            assert_eq!(verify_fixture_baseline(&value), Ok(()));
            assert_eq!(
                verify_creation_token_revalidation(&value, &value, 0, true),
                Ok(())
            );
            let diagnostic = ServiceTokenFixtureError::policy_rejection_for_baseline(
                PolicyRejection::ServiceIdentity,
                &value,
            );
            assert!(diagnostic.policy_detail.is_none());
        }
        assert_eq!(
            SERVICE_TOKEN_POLICY_COMPLETENESS,
            ServiceTokenPolicyCompleteness::Unverified
        );
    }

    #[test]
    fn optional_service_group_still_rejects_duplicates_and_every_attribute_bit_change() {
        for bit in 0..32 {
            let mut value = observation();
            value.groups[0].attributes ^= 1_u32 << bit;
            assert!(matches!(
                service_identity_rejection(&value),
                Some(ServiceTokenPolicyDetail::ServiceGroupAttributes)
            ));
            assert_eq!(
                verify_fixture_policy(&value, &catalog()),
                Err(PolicyRejection::ServiceIdentity)
            );
            value.groups.push(SidEntry {
                sid: service_sid(),
                attributes: SERVICE_SID_GROUP_ATTRIBUTES,
            });
            assert!(matches!(
                service_identity_rejection(&value),
                Some(ServiceTokenPolicyDetail::ServiceGroupMultiplicity)
            ));
            assert_eq!(
                verify_fixture_policy(&value, &catalog()),
                Err(PolicyRejection::ServiceIdentity)
            );
        }
    }

    #[test]
    fn absent_service_group_preserves_all_other_token_policy_requirements() {
        for primary_is_user in [false, true] {
            let mut expected = observation();
            expected.groups.retain(|group| group.sid != service_sid());
            if primary_is_user {
                expected.primary_group_sid = expected.user_sid.clone();
            }
            assert_eq!(verify_fixture_policy(&expected, &catalog()), Ok(()));
            let mutations: [fn(&mut ServiceTokenObservation); 18] = [
                |token| token.token_is_primary = false,
                |token| token.session_id = 1,
                |token| token.app_container = true,
                |token| token.ui_access = true,
                |token| token.has_restrictions = false,
                |token| token.user_sid = sid(5, &[80, 9, 9, 9, 9, 9]),
                |token| token.user_sid.0[0] = 2,
                |token| token.owner_sid = SidBytes(WORLD_SID.to_vec()),
                |token| token.owner_sid.0[0] = 2,
                |token| token.primary_group_sid = SidBytes(WORLD_SID.to_vec()),
                |token| token.primary_group_sid.0[0] = 2,
                |token| {
                    token.groups.remove(0);
                },
                |token| {
                    token.groups.remove(1);
                },
                |token| token.groups.push(token.groups[0].clone()),
                |token| token.groups.push(token.groups[1].clone()),
                |token| token.groups[0].attributes ^= GROUP_ENABLED,
                |token| token.groups[1].attributes ^= GROUP_ENABLED,
                |token| {
                    token.groups.push(SidEntry {
                        sid: sid(5, &[5, 30, 40]),
                        attributes: GROUP_LOGON_ID,
                    });
                },
            ];
            for mutate in mutations {
                let mut rejected = expected.clone();
                mutate(&mut rejected);
                assert!(verify_fixture_policy(&rejected, &catalog()).is_err());
            }
            for index in 0..4 {
                let mut missing = expected.clone();
                missing.restricted_sids.remove(index);
                assert_eq!(
                    verify_fixture_policy(&missing, &catalog()),
                    Err(PolicyRejection::RestrictedSidSet)
                );
                let mut duplicate = expected.clone();
                duplicate
                    .restricted_sids
                    .push(duplicate.restricted_sids[index].clone());
                assert_eq!(
                    verify_fixture_policy(&duplicate, &catalog()),
                    Err(PolicyRejection::RestrictedSidSet)
                );
                let mut malformed = expected.clone();
                malformed.restricted_sids[index].sid.0[0] = 2;
                assert_eq!(
                    verify_fixture_policy(&malformed, &catalog()),
                    Err(PolicyRejection::RestrictedSidSet)
                );
                let mut missing_privilege = expected.clone();
                missing_privilege.privileges.remove(index);
                assert_eq!(
                    verify_fixture_policy(&missing_privilege, &catalog()),
                    Err(PolicyRejection::Privileges)
                );
                for attributes in [PRIVILEGE_REMOVED, 0x0000_0100] {
                    let mut invalid_privilege = expected.clone();
                    invalid_privilege.privileges[index].attributes = attributes;
                    assert_eq!(
                        verify_fixture_policy(&invalid_privilege, &catalog()),
                        Err(PolicyRejection::Privileges)
                    );
                }
            }
            for forbidden in catalog().forbidden {
                let mut rejected = expected.clone();
                rejected.privileges[0].luid = forbidden.luid;
                assert_eq!(
                    verify_fixture_policy(&rejected, &catalog()),
                    Err(PolicyRejection::Privileges)
                );
            }
        }
    }

    #[test]
    fn primary_user_binding_preserves_duplicates_and_full_principal_continuity() {
        for separate_group in [false, true] {
            let mut original = baseline();
            if !separate_group {
                original
                    .observation
                    .groups
                    .retain(|group| group.sid != service_sid());
            }
            let mut user_primary = original.clone();
            user_primary.observation.primary_group_sid = user_primary.observation.user_sid.clone();
            assert_eq!(verify_fixture_baseline(&original), Ok(()));
            assert_eq!(verify_fixture_baseline(&user_primary), Ok(()));
            for (before, after) in [(&original, &user_primary), (&user_primary, &original)] {
                assert_eq!(
                    verify_creation_token_revalidation(before, after, 0, true),
                    Err(PolicyRejection::BaselineContinuity)
                );
            }
            let mut duplicates = user_primary.clone();
            duplicates.observation.groups.push(SidEntry {
                sid: service_sid(),
                attributes: SERVICE_SID_GROUP_ATTRIBUTES,
            });
            duplicates.observation.groups.push(SidEntry {
                sid: service_sid(),
                attributes: SERVICE_SID_GROUP_ATTRIBUTES,
            });
            assert_eq!(
                verify_fixture_baseline(&duplicates),
                Err(PolicyRejection::ServiceIdentity)
            );
            let mut foreign = user_primary.clone();
            foreign.observation.primary_group_sid = SidBytes(WORLD_SID.to_vec());
            assert_eq!(
                verify_fixture_baseline(&foreign),
                Err(PolicyRejection::ServiceGroups)
            );
            foreign.observation.groups.push(SidEntry {
                sid: SidBytes(WORLD_SID.to_vec()),
                attributes: GROUP_ENABLED,
            });
            assert_eq!(verify_fixture_baseline(&foreign), Ok(()));
            foreign.observation.groups.push(SidEntry {
                sid: SidBytes(WORLD_SID.to_vec()),
                attributes: GROUP_ENABLED,
            });
            assert_eq!(
                verify_fixture_baseline(&foreign),
                Err(PolicyRejection::ServiceGroups)
            );
            let mut proof = fixture_proof();
            proof.baseline = user_primary;
            let principal = proof.baseline.observation.user_sid.0.clone();
            let token = VerifiedServiceCreationToken {
                proof: &mut proof,
                _not_sync: PhantomData,
            };
            assert!(
                token
                    .verify_creation_principals(&principal, &principal)
                    .is_ok()
            );
            assert!(
                token
                    .verify_creation_principals(WORLD_SID, &principal)
                    .is_err()
            );
            assert!(
                token
                    .verify_creation_principals(&principal, WORLD_SID)
                    .is_err()
            );
        }
    }

    #[test]
    fn optional_service_group_cannot_bypass_handle_or_complete_baseline_continuity() {
        let present = baseline();
        let mut absent = present.clone();
        absent
            .observation
            .groups
            .retain(|group| group.sid != service_sid());
        for (original, fresh) in [(&present, &absent), (&absent, &present)] {
            assert_eq!(verify_fixture_baseline(original), Ok(()));
            assert_eq!(verify_fixture_baseline(fresh), Ok(()));
            assert_eq!(
                verify_creation_token_revalidation(original, fresh, 0, true),
                Err(PolicyRejection::BaselineContinuity)
            );
        }
        assert_eq!(
            verify_creation_token_revalidation(&absent, &absent, 1, true),
            Err(PolicyRejection::HandleContinuity)
        );
        assert_eq!(
            verify_creation_token_revalidation(&absent, &absent, 0, false),
            Err(PolicyRejection::HandleContinuity)
        );
        let mut inheritable = absent.clone();
        inheritable.token_handle_flags = 1;
        assert_eq!(
            verify_fixture_baseline(&inheritable),
            Err(PolicyRejection::HandleContinuity)
        );
        let mut drifted = absent.clone();
        drifted.observation.identity.modified_id.low_part ^= 1;
        assert_eq!(
            verify_creation_token_revalidation(&absent, &drifted, 0, true),
            Err(PolicyRejection::BaselineContinuity)
        );
        let mut proof = fixture_proof();
        proof.baseline = absent;
        let owner = proof.baseline.observation.owner_sid.0.clone();
        let primary_group = proof.baseline.observation.primary_group_sid.0.clone();
        let token = VerifiedServiceCreationToken {
            proof: &mut proof,
            _not_sync: PhantomData,
        };
        assert!(
            token
                .verify_creation_principals(&owner, &primary_group)
                .is_ok()
        );
        assert!(
            token
                .verify_creation_principals(WORLD_SID, &primary_group)
                .is_err()
        );
        assert!(token.verify_creation_principals(&owner, WORLD_SID).is_err());
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
    fn creation_token_revalidation_rejects_handle_flags_and_wrong_object() {
        let expected = baseline();
        assert_eq!(
            verify_creation_token_revalidation(&expected, &expected, 0, true),
            Ok(())
        );

        let mut inheritable_fresh = expected.clone();
        inheritable_fresh.token_handle_flags = 1;
        assert_eq!(
            verify_creation_token_revalidation(&expected, &inheritable_fresh, 0, true),
            Err(PolicyRejection::HandleContinuity)
        );
        assert_eq!(
            verify_creation_token_revalidation(&expected, &expected, 1, true),
            Err(PolicyRejection::HandleContinuity)
        );
        assert_eq!(
            verify_creation_token_revalidation(&expected, &expected, 0, false),
            Err(PolicyRejection::HandleContinuity)
        );
    }

    #[test]
    fn creation_token_revalidation_rejects_complete_baseline_and_catalog_drift() {
        let expected = baseline();
        let mut drifted = Vec::new();

        let mut value = expected.clone();
        value.observation.identity.modified_id = luid(11);
        drifted.push(value);

        let mut value = expected.clone();
        let old_service_sid = value.observation.user_sid.clone();
        let new_service_sid = sid(5, &[80, 11, 12, 13, 14, 15]);
        value.observation.user_sid = new_service_sid.clone();
        value.observation.owner_sid = new_service_sid.clone();
        let mut replaced_service_group = false;
        for entry in &mut value.observation.groups {
            if entry.sid == old_service_sid {
                entry.sid = new_service_sid.clone();
                replaced_service_group = true;
            }
        }
        let mut replaced_restricted_service_sid = false;
        for entry in &mut value.observation.restricted_sids {
            if entry.sid == old_service_sid {
                entry.sid = new_service_sid.clone();
                replaced_restricted_service_sid = true;
            }
        }
        assert!(replaced_service_group);
        assert!(replaced_restricted_service_sid);
        drifted.push(value);

        let mut value = expected.clone();
        value.observation.primary_group_sid = value.observation.user_sid.clone();
        drifted.push(value);

        let mut value = expected.clone();
        value.observation.restricted_sids[0].attributes ^= GROUP_ENABLED;
        drifted.push(value);

        let mut value = expected.clone();
        value.observation.privileges[0].attributes ^= PRIVILEGE_ENABLED;
        drifted.push(value);

        let mut value = expected.clone();
        let old_luid = value.catalog.expected[0].luid;
        let new_luid = luid(101);
        value.catalog.expected[0].luid = new_luid;
        if let Some(privilege) = value
            .observation
            .privileges
            .iter_mut()
            .find(|entry| entry.luid == old_luid)
        {
            privilege.luid = new_luid;
        }
        drifted.push(value);

        let mut value = expected.clone();
        value.observation.groups.push(SidEntry {
            sid: sid(5, &[12]),
            attributes: GROUP_ENABLED,
        });
        drifted.push(value);

        for value in &mut drifted {
            canonicalize_service_token_baseline(value);
            assert!(verify_fixture_baseline(value).is_ok());
            assert_eq!(
                verify_creation_token_revalidation(&expected, value, 0, true),
                Err(PolicyRejection::BaselineContinuity)
            );
        }

        let mut reordered = expected.clone();
        reordered.observation.groups.reverse();
        reordered.observation.restricted_sids.reverse();
        reordered.observation.privileges.reverse();
        canonicalize_service_token_baseline(&mut reordered);
        assert_eq!(
            verify_creation_token_revalidation(&expected, &reordered, 0, true),
            Ok(())
        );
    }

    trait AmbiguousIfSync<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfSync<()> for T {}
    impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for T {}

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

    fn assert_send<T: Send>() {}

    #[test]
    fn proof_and_creation_token_are_move_only_send_and_not_sync() {
        assert_send::<ServiceTokenFixtureProof>();
        assert_send::<VerifiedServiceCreationToken<'static>>();
        let _ = <ServiceTokenFixtureProof as AmbiguousIfSync<_>>::marker;
        let _ = <ServiceTokenFixtureProof as AmbiguousIfClone<_>>::marker;
        let _ = <ServiceTokenFixtureProof as AmbiguousIfCopy<_>>::marker;
        let _ = <VerifiedServiceCreationToken<'static> as AmbiguousIfSync<_>>::marker;
        let _ = <VerifiedServiceCreationToken<'static> as AmbiguousIfClone<_>>::marker;
        let _ = <VerifiedServiceCreationToken<'static> as AmbiguousIfCopy<_>>::marker;
    }

    #[test]
    fn creation_token_debug_is_data_free() {
        let mut proof = fixture_proof();
        let owner = proof.baseline.observation.owner_sid.0.clone();
        let primary_group = proof.baseline.observation.primary_group_sid.0.clone();
        let token = VerifiedServiceCreationToken {
            proof: &mut proof,
            _not_sync: PhantomData,
        };
        assert_eq!(
            format!("{token:?}"),
            "VerifiedServiceCreationToken([REDACTED])"
        );
        assert!(
            token
                .verify_creation_principals(&owner, &primary_group)
                .is_ok()
        );
        assert!(
            token
                .verify_creation_principals(WORLD_SID, &primary_group)
                .is_err()
        );
        assert!(token.verify_creation_principals(&owner, WORLD_SID).is_err());
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

    fn capture_diagnostic_cases() -> [(ServiceTokenCaptureStage, u32); 25] {
        [
            (ServiceTokenCaptureStage::ThreadBefore, 0x2101),
            (ServiceTokenCaptureStage::TokenOpen, 0x2102),
            (ServiceTokenCaptureStage::HandleFlags, 0x2103),
            (ServiceTokenCaptureStage::ServiceSid, 0x2104),
            (ServiceTokenCaptureStage::PrivilegeCatalog, 0x2105),
            (ServiceTokenCaptureStage::IdentityBefore, 0x2106),
            (ServiceTokenCaptureStage::TokenType, 0x2107),
            (ServiceTokenCaptureStage::Session, 0x2108),
            (ServiceTokenCaptureStage::AppContainer, 0x2109),
            (ServiceTokenCaptureStage::UiAccess, 0x210a),
            (ServiceTokenCaptureStage::Restrictions, 0x210b),
            (ServiceTokenCaptureStage::UserSid, 0x210c),
            (ServiceTokenCaptureStage::UserIdentity, 0x210d),
            (ServiceTokenCaptureStage::OwnerSid, 0x210e),
            (ServiceTokenCaptureStage::PrimaryGroupSid, 0x210f),
            (ServiceTokenCaptureStage::Groups, 0x2110),
            (ServiceTokenCaptureStage::RestrictedSids, 0x2111),
            (ServiceTokenCaptureStage::Privileges, 0x2112),
            (ServiceTokenCaptureStage::IdentityAfter, 0x2113),
            (ServiceTokenCaptureStage::IdentityContinuity, 0x2114),
            (ServiceTokenCaptureStage::ThreadAfter, 0x2115),
            (ServiceTokenCaptureStage::RetainedHandleFlags, 0x2116),
            (ServiceTokenCaptureStage::FreshIdentity, 0x2117),
            (
                ServiceTokenCaptureStage::RecaptureIdentityContinuity,
                0x2118,
            ),
            (ServiceTokenCaptureStage::CreationPrincipals, 0x2119),
        ]
    }

    fn policy_diagnostic_cases() -> [(PolicyRejection, u32); 7] {
        [
            (PolicyRejection::HandleContinuity, 0x2181),
            (PolicyRejection::TokenShape, 0x2182),
            (PolicyRejection::ServiceIdentity, 0x2183),
            (PolicyRejection::ServiceGroups, 0x2184),
            (PolicyRejection::RestrictedSidSet, 0x2185),
            (PolicyRejection::Privileges, 0x2186),
            (PolicyRejection::BaselineContinuity, 0x2187),
        ]
    }

    #[test]
    fn tagged_errors_keep_existing_redacted_facade_and_fail_closed_results() {
        let mut errors = Vec::new();
        for (stage, _) in capture_diagnostic_cases() {
            errors.push(ServiceTokenFixtureError::operating_system().at_stage(stage));
            errors.push(ServiceTokenFixtureError::policy().at_stage(stage));
        }
        for (reason, _) in policy_diagnostic_cases() {
            let rejected: Result<(), PolicyRejection> = Err(reason);
            let mapped = rejected.map_err(ServiceTokenFixtureError::policy_rejection);
            assert!(mapped.is_err());
            if let Err(error) = mapped {
                assert!(matches!(error.kind, ServiceTokenFixtureErrorKind::Policy));
                assert_eq!(error.policy_rejection, Some(reason));
                errors.push(error);
            }
        }
        for error in errors {
            assert_eq!(format!("{error:?}"), "ServiceTokenFixtureError([REDACTED])");
            assert_eq!(
                error.to_string(),
                "key agent service-token fixture is unavailable"
            );
            assert!(std::error::Error::source(&error).is_none());
        }
        let accepted: Result<(), PolicyRejection> = Ok(());
        assert!(
            accepted
                .map_err(ServiceTokenFixtureError::policy_rejection)
                .is_ok()
        );
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    #[test]
    fn startup_diagnostic_capture_codes_are_exact_and_unique() {
        assert_eq!(
            ServiceTokenFixtureError::operating_system().startup_diagnostic_code(),
            0x2100
        );
        assert_eq!(
            ServiceTokenFixtureError::policy().startup_diagnostic_code(),
            0x2180
        );
        let mut seen = std::collections::BTreeSet::from([0x2100, 0x2180]);
        for (stage, expected) in capture_diagnostic_cases() {
            assert!(seen.insert(expected));
            for error in [
                ServiceTokenFixtureError::operating_system(),
                ServiceTokenFixtureError::policy(),
            ] {
                assert_eq!(error.at_stage(stage).startup_diagnostic_code(), expected);
            }
        }
        for (reason, expected) in policy_diagnostic_cases() {
            assert!(seen.insert(expected));
            for (stage, _) in capture_diagnostic_cases() {
                assert_eq!(
                    ServiceTokenFixtureError::policy_rejection(reason)
                        .at_stage(stage)
                        .startup_diagnostic_code(),
                    expected
                );
            }
        }
        for expected in [0x2191, 0x2192, 0x2193] {
            assert!(seen.insert(expected));
        }
        assert_eq!(seen.len(), 37);
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    #[test]
    fn startup_diagnostic_policy_codes_match_real_rejections() {
        let mut cases = Vec::new();
        let mut value = baseline();
        value.token_handle_flags = 1;
        cases.push((value, PolicyRejection::HandleContinuity, 0x2181));
        let mut value = baseline();
        value.observation.session_id = 1;
        cases.push((value, PolicyRejection::TokenShape, 0x2182));
        let mut value = baseline();
        value.observation.owner_sid = SidBytes(WORLD_SID.to_vec());
        cases.push((value, PolicyRejection::ServiceIdentity, 0x2183));
        let mut value = baseline();
        value.observation.primary_group_sid = SidBytes(WORLD_SID.to_vec());
        cases.push((value, PolicyRejection::ServiceGroups, 0x2184));
        let mut value = baseline();
        value.observation.restricted_sids.pop();
        cases.push((value, PolicyRejection::RestrictedSidSet, 0x2185));
        let mut value = baseline();
        value.observation.privileges.pop();
        cases.push((value, PolicyRejection::Privileges, 0x2186));
        for (value, expected_reason, expected_code) in cases {
            let rejected = verify_fixture_baseline(&value);
            assert_eq!(rejected, Err(expected_reason));
            let mapped = rejected.map_err(ServiceTokenFixtureError::policy_rejection);
            assert!(mapped.is_err());
            if let Err(error) = mapped {
                assert_eq!(error.startup_diagnostic_code(), expected_code);
            }
        }
        let original = baseline();
        let mut fresh = baseline();
        fresh.observation.identity.modified_id.low_part ^= 1;
        let rejected = verify_creation_token_revalidation(&original, &fresh, 0, true);
        assert_eq!(rejected, Err(PolicyRejection::BaselineContinuity));
        let mapped = rejected.map_err(ServiceTokenFixtureError::policy_rejection);
        assert!(mapped.is_err());
        if let Err(error) = mapped {
            assert_eq!(error.startup_diagnostic_code(), 0x2187);
        }
        assert!(
            verify_fixture_baseline(&original)
                .map_err(ServiceTokenFixtureError::policy_rejection)
                .is_ok()
        );
    }

    #[test]
    fn startup_service_identity_details_remain_rejected_and_redacted() {
        let mut cases = Vec::new();
        let mut value = baseline();
        value.observation.owner_sid = SidBytes(WORLD_SID.to_vec());
        cases.push((value, ServiceTokenPolicyDetail::OwnerMismatch, 0x2191));
        let mut value = baseline();
        value.observation.groups.push(SidEntry {
            sid: service_sid(),
            attributes: SERVICE_SID_GROUP_ATTRIBUTES,
        });
        cases.push((
            value,
            ServiceTokenPolicyDetail::ServiceGroupMultiplicity,
            0x2192,
        ));
        let mut value = baseline();
        for group in &mut value.observation.groups {
            if group.sid == service_sid() {
                group.attributes ^= GROUP_ENABLED;
            }
        }
        cases.push((
            value,
            ServiceTokenPolicyDetail::ServiceGroupAttributes,
            0x2193,
        ));
        for (value, expected_detail, expected_code) in cases {
            let rejected = verify_fixture_baseline(&value);
            assert_eq!(rejected, Err(PolicyRejection::ServiceIdentity));
            let mapped = rejected.map_err(|reason| {
                ServiceTokenFixtureError::policy_rejection_for_baseline(reason, &value)
            });
            assert!(mapped.is_err());
            if let Err(error) = mapped {
                assert_eq!(
                    error.policy_rejection,
                    Some(PolicyRejection::ServiceIdentity)
                );
                assert!(error.policy_detail == Some(expected_detail));
                assert_eq!(format!("{error:?}"), "ServiceTokenFixtureError([REDACTED])");
                assert_eq!(
                    error.to_string(),
                    "key agent service-token fixture is unavailable"
                );
                assert!(std::error::Error::source(&error).is_none());
                #[cfg(all(
                    feature = "key-agent-service-lpac-launch-feasibility-test-hook",
                    debug_assertions
                ))]
                assert_eq!(error.startup_diagnostic_code(), expected_code);
                let _ = expected_code;
            }
            let other = ServiceTokenFixtureError::policy_rejection_for_baseline(
                PolicyRejection::Privileges,
                &value,
            );
            assert!(other.policy_detail.is_none());
            assert_eq!(other.policy_rejection, Some(PolicyRejection::Privileges));
        }
        let accepted = baseline();
        assert!(
            verify_fixture_baseline(&accepted)
                .map_err(
                    |reason| ServiceTokenFixtureError::policy_rejection_for_baseline(
                        reason, &accepted
                    )
                )
                .is_ok()
        );
        let fallback = ServiceTokenFixtureError::policy_rejection_for_baseline(
            PolicyRejection::ServiceIdentity,
            &accepted,
        );
        assert!(fallback.policy_detail.is_none());
        #[cfg(all(
            feature = "key-agent-service-lpac-launch-feasibility-test-hook",
            debug_assertions
        ))]
        assert_eq!(fallback.startup_diagnostic_code(), 0x2183);
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    #[test]
    fn remaining_policy_failure_codes_are_closed_and_exhaustive() {
        let mut seen = std::collections::BTreeSet::new();
        for mask in 0_u32..128 {
            let failures = ServiceTokenRemainingPolicyFailures {
                primary_group: mask & 0x01 != 0,
                local_group: mask & 0x02 != 0,
                local_attributes: mask & 0x04 != 0,
                logon_group: mask & 0x08 != 0,
                logon_attributes: mask & 0x10 != 0,
                restricted_sids: mask & 0x20 != 0,
                privileges: mask & 0x40 != 0,
                logon_attribute_detail: None,
            };
            if mask == 0 {
                assert_eq!(failures.service_specific_code(), None);
            } else {
                assert_eq!(failures.service_specific_code(), Some(0x4000 | mask));
                assert!(seen.insert(0x4000 | mask));
            }
        }
        assert_eq!(seen.len(), 127);
        assert_eq!(seen.first(), Some(&0x4001));
        assert_eq!(seen.last(), Some(&0x407f));
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    #[test]
    fn remaining_policy_report_collects_independent_failures_without_accepting_them() {
        let mutations: [fn(&mut ServiceTokenBaseline); 7] = [
            |value| value.observation.primary_group_sid = SidBytes(WORLD_SID.to_vec()),
            |value| {
                value
                    .observation
                    .groups
                    .retain(|group| group.sid.0 != LOCAL_SID);
            },
            |value| {
                for group in &mut value.observation.groups {
                    if group.sid.0 == LOCAL_SID {
                        group.attributes ^= GROUP_ENABLED;
                    }
                }
            },
            |value| {
                value
                    .observation
                    .groups
                    .retain(|group| group.sid != logon_sid());
            },
            |value| {
                for group in &mut value.observation.groups {
                    if group.sid == logon_sid() {
                        group.attributes ^= GROUP_ENABLED;
                    }
                }
            },
            |value| {
                value.observation.restricted_sids.pop();
            },
            |value| {
                value.observation.privileges.pop();
            },
        ];
        for (index, mutate) in mutations.into_iter().enumerate() {
            let mut value = baseline();
            // The new primary-user representation must retain every other check.
            value.observation.primary_group_sid = service_sid();
            value
                .observation
                .groups
                .retain(|group| group.sid != service_sid());
            mutate(&mut value);
            let expected_reason = match index {
                0..=4 => PolicyRejection::ServiceGroups,
                5 => PolicyRejection::RestrictedSidSet,
                _ => PolicyRejection::Privileges,
            };
            let rejected = verify_fixture_baseline(&value);
            assert_eq!(rejected, Err(expected_reason));
            let mapped = rejected.map_err(|reason| {
                ServiceTokenFixtureError::policy_rejection_for_baseline(reason, &value)
            });
            assert!(mapped.is_err());
            if let Err(error) = mapped {
                assert_eq!(error.policy_rejection, Some(expected_reason));
                let expected_code = if index == 4 {
                    0x5004
                } else {
                    0x4000 | (1 << index)
                };
                assert_eq!(error.startup_diagnostic_code(), expected_code);
                assert_eq!(format!("{error:?}"), "ServiceTokenFixtureError([REDACTED])");
                assert_eq!(
                    error.to_string(),
                    "key agent service-token fixture is unavailable"
                );
                assert!(std::error::Error::source(&error).is_none());
            }
        }

        let mut value = baseline();
        for index in [0, 2, 4, 5, 6] {
            mutations[index](&mut value);
        }
        assert_eq!(
            verify_fixture_baseline(&value),
            Err(PolicyRejection::ServiceGroups)
        );
        let error = ServiceTokenFixtureError::policy_rejection_for_baseline(
            PolicyRejection::ServiceGroups,
            &value,
        );
        assert_eq!(error.startup_diagnostic_code(), 0x4075);
        assert_eq!(error.policy_rejection, Some(PolicyRejection::ServiceGroups));
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    #[test]
    fn remaining_policy_report_marks_missing_dependencies_unavailable_and_keeps_fallback() {
        for duplicate in [false, true] {
            let mut value = baseline();
            value.observation.primary_group_sid = service_sid();
            if duplicate {
                value.observation.groups.push(SidEntry {
                    sid: SidBytes(LOCAL_SID.to_vec()),
                    attributes: LOCAL_GROUP_ATTRIBUTES,
                });
                value.observation.groups.push(SidEntry {
                    sid: logon_sid(),
                    attributes: SERVICE_LOGON_GROUP_ATTRIBUTES,
                });
            } else {
                value
                    .observation
                    .groups
                    .retain(|group| group.sid.0 != LOCAL_SID && group.sid != logon_sid());
            }
            value.observation.restricted_sids.clear();
            value.observation.privileges.clear();
            let failures = ServiceTokenRemainingPolicyFailures::from_baseline(&value);
            assert!(failures.local_group);
            assert!(!failures.local_attributes);
            assert!(failures.logon_group);
            assert!(!failures.logon_attributes);
            assert!(!failures.restricted_sids);
            assert!(failures.privileges);
            assert_eq!(failures.service_specific_code(), Some(0x404a));
            assert_eq!(
                verify_fixture_baseline(&value),
                Err(PolicyRejection::ServiceGroups)
            );
        }

        let accepted = baseline();
        assert_eq!(
            ServiceTokenRemainingPolicyFailures::from_baseline(&accepted).service_specific_code(),
            None
        );
        assert!(
            verify_fixture_baseline(&accepted)
                .map_err(|reason| {
                    ServiceTokenFixtureError::policy_rejection_for_baseline(reason, &accepted)
                })
                .is_ok()
        );
        for (reason, fallback_code) in policy_diagnostic_cases() {
            let error = ServiceTokenFixtureError::policy_rejection_for_baseline(reason, &accepted);
            assert_eq!(error.startup_diagnostic_code(), fallback_code);
            assert_eq!(error.policy_rejection, Some(reason));
            assert_eq!(
                error.remaining_policy_failures.is_some(),
                matches!(
                    reason,
                    PolicyRejection::ServiceGroups
                        | PolicyRejection::RestrictedSidSet
                        | PolicyRejection::Privileges
                )
            );
        }
        assert!(
            ServiceTokenFixtureError::operating_system()
                .remaining_policy_failures
                .is_none()
        );
        assert!(
            ServiceTokenFixtureError::policy()
                .remaining_policy_failures
                .is_none()
        );
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    #[test]
    fn logon_attribute_diagnostics_exhaust_every_known_and_unknown_difference() {
        let mut seen = std::collections::BTreeSet::new();
        for mask in 0_u32..512 {
            let mut attributes = SERVICE_LOGON_GROUP_ATTRIBUTES ^ (mask & 7);
            for (semantic_bit, native_bit) in [
                (0x008, GROUP_OWNER),
                (0x010, 0x10),
                (0x020, 0x20),
                (0x040, 0x40),
                (0x080, 0x2000_0000),
                (0x100, 0x80),
            ] {
                if mask & semantic_bit != 0 {
                    attributes |= native_bit;
                }
            }
            let detail = ServiceTokenLogonAttributeFailures::from_attributes(attributes);
            assert_eq!(detail.missing_mandatory, mask & 0x001 != 0);
            assert_eq!(detail.missing_enabled_by_default, mask & 0x002 != 0);
            assert_eq!(detail.missing_enabled, mask & 0x004 != 0);
            assert_eq!(detail.extra_owner, mask & 0x008 != 0);
            assert_eq!(detail.extra_deny_only, mask & 0x010 != 0);
            assert_eq!(detail.extra_integrity, mask & 0x020 != 0);
            assert_eq!(detail.extra_integrity_enabled, mask & 0x040 != 0);
            assert_eq!(detail.extra_resource, mask & 0x080 != 0);
            assert_eq!(detail.unknown_bits, mask & 0x100 != 0);
            let expected_code = if mask == 0 { None } else { Some(0x5000 | mask) };
            assert_eq!(detail.diagnostic_code(), expected_code);
            let mut value = baseline();
            for group in &mut value.observation.groups {
                if group.sid == logon_sid() {
                    group.attributes = attributes;
                }
            }
            let checked = verify_fixture_baseline(&value);
            if mask == 0 || mask == 0x008 {
                assert_eq!(checked, Ok(()));
                assert!(
                    ServiceTokenRemainingPolicyFailures::from_baseline(&value)
                        .logon_attribute_detail
                        .is_none()
                );
            } else {
                assert!(seen.insert(0x5000 | mask));
                assert_eq!(checked, Err(PolicyRejection::ServiceGroups));
                let mapped = checked.map_err(|reason| {
                    ServiceTokenFixtureError::policy_rejection_for_baseline(reason, &value)
                });
                assert!(mapped.is_err());
                if let Err(error) = mapped {
                    assert_eq!(Some(error.startup_diagnostic_code()), expected_code);
                    assert_eq!(format!("{error:?}"), "ServiceTokenFixtureError([REDACTED])");
                    assert_eq!(
                        error.to_string(),
                        "key agent service-token fixture is unavailable"
                    );
                    assert!(std::error::Error::source(&error).is_none());
                }
            }
        }
        assert_eq!(seen.len(), 510);
        assert_eq!(seen.first(), Some(&0x5001));
        assert_eq!(seen.last(), Some(&0x51ff));
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    #[test]
    fn logon_attribute_details_preserve_all_aggregate_codes_and_missing_dependencies() {
        for mask in 0_u32..128 {
            let mut failures = ServiceTokenRemainingPolicyFailures {
                primary_group: mask & 0x01 != 0,
                local_group: mask & 0x02 != 0,
                local_attributes: mask & 0x04 != 0,
                logon_group: mask & 0x08 != 0,
                logon_attributes: mask & 0x10 != 0,
                restricted_sids: mask & 0x20 != 0,
                privileges: mask & 0x40 != 0,
                logon_attribute_detail: Some(ServiceTokenLogonAttributeFailures::from_attributes(
                    SERVICE_LOGON_GROUP_ATTRIBUTES | GROUP_OWNER,
                )),
            };
            let original = if mask == 0 { None } else { Some(0x4000 | mask) };
            let expected = if mask == 0x10 { Some(0x5008) } else { original };
            assert_eq!(failures.service_specific_code(), expected);
            failures.logon_attribute_detail = Some(
                ServiceTokenLogonAttributeFailures::from_attributes(SERVICE_LOGON_GROUP_ATTRIBUTES),
            );
            assert_eq!(failures.service_specific_code(), original);
            failures.logon_attribute_detail = None;
            assert_eq!(failures.service_specific_code(), original);
        }
        for duplicate in [false, true] {
            let mut value = baseline();
            value.observation.primary_group_sid = service_sid();
            if duplicate {
                value.observation.groups.push(SidEntry {
                    sid: logon_sid(),
                    attributes: SERVICE_LOGON_GROUP_ATTRIBUTES | GROUP_OWNER,
                });
            } else {
                value
                    .observation
                    .groups
                    .retain(|group| group.sid != logon_sid());
            }
            let failures = ServiceTokenRemainingPolicyFailures::from_baseline(&value);
            assert!(failures.logon_attribute_detail.is_none());
            assert_eq!(failures.service_specific_code(), Some(0x4008));
            assert_eq!(
                verify_fixture_baseline(&value),
                Err(PolicyRejection::ServiceGroups)
            );
        }
        // Attribute-exact but malformed SID data cannot produce a refined code.
        let mut value = baseline();
        value.observation.primary_group_sid = service_sid();
        for group in &mut value.observation.groups {
            if group.sid == logon_sid() {
                group.sid.0[0] = 2;
            }
        }
        let failures = ServiceTokenRemainingPolicyFailures::from_baseline(&value);
        assert!(failures.logon_attribute_detail.is_none());
        assert_eq!(failures.service_specific_code(), Some(0x4030));
        assert!(verify_fixture_baseline(&value).is_err());
    }

    #[cfg(all(
        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
        debug_assertions
    ))]
    #[test]
    fn logon_attribute_details_leave_early_rejections_and_policy_unchanged() {
        assert_eq!(SERVICE_LOGON_GROUP_ATTRIBUTES, 0xC000_0007);
        for bit in 0_u32..32 {
            let mut value = baseline();
            for group in &mut value.observation.groups {
                if group.sid == logon_sid() {
                    group.attributes ^= 1_u32 << bit;
                }
            }
            let report = ServiceTokenRemainingPolicyFailures::from_baseline(&value);
            if bit == 3 {
                assert_eq!(verify_fixture_baseline(&value), Ok(()));
                assert!(report.logon_attribute_detail.is_none());
                assert_eq!(report.service_specific_code(), None);
                continue;
            }
            assert_eq!(
                verify_fixture_baseline(&value),
                Err(PolicyRejection::ServiceGroups)
            );
            if bit >= 30 {
                assert!(report.logon_attribute_detail.is_none());
                assert_eq!(report.service_specific_code(), Some(0x4008));
            } else if (7..29).contains(&bit) {
                // Every unknown bit collapses into one fixed category.
                assert_eq!(report.service_specific_code(), Some(0x5100));
            }
        }
        let mutations: [fn(&mut ServiceTokenBaseline); 3] = [
            |value| value.token_handle_flags = 1,
            |value| value.observation.session_id = 1,
            |value| value.observation.owner_sid = SidBytes(WORLD_SID.to_vec()),
        ];
        for (mutate, reason, code) in [
            (mutations[0], PolicyRejection::HandleContinuity, 0x2181),
            (mutations[1], PolicyRejection::TokenShape, 0x2182),
            (mutations[2], PolicyRejection::ServiceIdentity, 0x2191),
        ] {
            let mut value = baseline();
            for group in &mut value.observation.groups {
                if group.sid == logon_sid() {
                    group.attributes |= GROUP_OWNER;
                }
            }
            mutate(&mut value);
            assert_eq!(verify_fixture_baseline(&value), Err(reason));
            let error = ServiceTokenFixtureError::policy_rejection_for_baseline(reason, &value);
            assert!(error.remaining_policy_failures.is_none());
            assert_eq!(error.startup_diagnostic_code(), code);
        }
    }

    #[test]
    fn service_logon_owner_attribute_accepts_only_two_exact_forms() {
        for attributes in [
            SERVICE_LOGON_GROUP_ATTRIBUTES,
            SERVICE_LOGON_GROUP_ATTRIBUTES | GROUP_OWNER,
        ] {
            for separate_service_group in [false, true] {
                for primary_is_user in [false, true] {
                    let mut value = baseline();
                    if !separate_service_group {
                        value
                            .observation
                            .groups
                            .retain(|group| group.sid != service_sid());
                    }
                    if primary_is_user {
                        value.observation.primary_group_sid = service_sid();
                    }
                    for group in &mut value.observation.groups {
                        if group.sid == logon_sid() {
                            group.attributes = attributes;
                        }
                    }
                    assert_eq!(verify_fixture_baseline(&value), Ok(()));
                    assert!(
                        verify_fixture_baseline(&value)
                            .map_err(|reason| {
                                ServiceTokenFixtureError::policy_rejection_for_baseline(
                                    reason, &value,
                                )
                            })
                            .is_ok()
                    );
                    let report = ServiceTokenRemainingPolicyFailures::from_baseline(&value);
                    assert!(!report.logon_attributes);
                    assert!(report.logon_attribute_detail.is_none());
                    #[cfg(all(
                        feature = "key-agent-service-lpac-launch-feasibility-test-hook",
                        debug_assertions
                    ))]
                    assert_eq!(report.service_specific_code(), None);
                    for bit in 0_u32..32 {
                        let mut changed = value.clone();
                        for group in &mut changed.observation.groups {
                            if group.sid == logon_sid() {
                                group.attributes ^= 1_u32 << bit;
                            }
                        }
                        let expected = if bit == 3 {
                            Ok(())
                        } else {
                            Err(PolicyRejection::ServiceGroups)
                        };
                        assert_eq!(verify_fixture_baseline(&changed), expected);
                    }
                }
            }
        }
        assert!(!service_logon_group_attributes_are_supported(0));
        assert!(!service_logon_group_attributes_are_supported(u32::MAX));
    }

    #[test]
    fn owner_capable_logon_group_preserves_other_policy_requirements() {
        let mut original = baseline();
        original.observation.primary_group_sid = service_sid();
        original
            .observation
            .groups
            .retain(|group| group.sid != service_sid());
        for group in &mut original.observation.groups {
            if group.sid == logon_sid() {
                group.attributes |= GROUP_OWNER;
            }
        }
        assert_eq!(verify_fixture_baseline(&original), Ok(()));
        let mutations: [fn(&mut ServiceTokenBaseline); 15] = [
            |value| value.token_handle_flags = 1,
            |value| value.observation.token_is_primary = false,
            |value| value.observation.session_id = 1,
            |value| value.observation.app_container = true,
            |value| value.observation.ui_access = true,
            |value| value.observation.has_restrictions = false,
            |value| value.observation.user_sid.0[0] = 2,
            |value| value.observation.owner_sid = logon_sid(),
            |value| value.observation.owner_sid.0[0] = 2,
            |value| value.observation.primary_group_sid = SidBytes(WORLD_SID.to_vec()),
            |value| value.observation.primary_group_sid.0[0] = 2,
            |value| {
                value
                    .observation
                    .groups
                    .retain(|group| group.sid.0 != LOCAL_SID);
            },
            |value| {
                value
                    .observation
                    .groups
                    .retain(|group| group.sid != logon_sid());
            },
            |value| {
                for group in &mut value.observation.groups {
                    if group.sid.0 == LOCAL_SID {
                        group.attributes ^= GROUP_ENABLED;
                    }
                }
            },
            |value| {
                value.observation.groups.push(SidEntry {
                    sid: service_sid(),
                    attributes: 0,
                });
            },
        ];
        for mutate in mutations {
            let mut changed = original.clone();
            mutate(&mut changed);
            assert!(verify_fixture_baseline(&changed).is_err());
        }
        for (sid, attributes) in [
            (SidBytes(LOCAL_SID.to_vec()), LOCAL_GROUP_ATTRIBUTES),
            (logon_sid(), SERVICE_LOGON_GROUP_ATTRIBUTES),
            (logon_sid(), SERVICE_LOGON_GROUP_ATTRIBUTES | GROUP_OWNER),
        ] {
            let mut changed = original.clone();
            changed
                .observation
                .groups
                .push(SidEntry { sid, attributes });
            assert_eq!(
                verify_fixture_baseline(&changed),
                Err(PolicyRejection::ServiceGroups)
            );
        }
    }

    #[test]
    fn owner_capable_logon_group_preserves_restricted_and_privilege_policy() {
        let mut original = baseline();
        original.observation.primary_group_sid = service_sid();
        original
            .observation
            .groups
            .retain(|group| group.sid != service_sid());
        for group in &mut original.observation.groups {
            if group.sid == logon_sid() {
                group.attributes |= GROUP_OWNER;
            }
        }
        assert_eq!(verify_fixture_baseline(&original), Ok(()));
        for index in 0..4 {
            let mut missing = original.clone();
            missing.observation.restricted_sids.remove(index);
            assert_eq!(
                verify_fixture_baseline(&missing),
                Err(PolicyRejection::RestrictedSidSet)
            );
            let mut duplicate = original.clone();
            duplicate
                .observation
                .restricted_sids
                .push(original.observation.restricted_sids[index].clone());
            assert_eq!(
                verify_fixture_baseline(&duplicate),
                Err(PolicyRejection::RestrictedSidSet)
            );
            let mut malformed = original.clone();
            malformed.observation.restricted_sids[index].sid.0[0] = 2;
            assert_eq!(
                verify_fixture_baseline(&malformed),
                Err(PolicyRejection::RestrictedSidSet)
            );
            let mut missing_privilege = original.clone();
            missing_privilege.observation.privileges.remove(index);
            assert_eq!(
                verify_fixture_baseline(&missing_privilege),
                Err(PolicyRejection::Privileges)
            );
            for attributes in [PRIVILEGE_REMOVED, 0x0000_0100] {
                let mut invalid = original.clone();
                invalid.observation.privileges[index].attributes = attributes;
                assert_eq!(
                    verify_fixture_baseline(&invalid),
                    Err(PolicyRejection::Privileges)
                );
            }
        }
        for forbidden in catalog().forbidden {
            let mut changed = original.clone();
            changed.observation.privileges.push(PrivilegeEntry {
                luid: forbidden.luid,
                attributes: 0,
            });
            assert_eq!(
                verify_fixture_baseline(&changed),
                Err(PolicyRejection::Privileges)
            );
        }
    }

    #[test]
    fn logon_owner_attribute_drift_preserves_baseline_and_creation_principals() {
        let original = baseline();
        let mut owner_capable = original.clone();
        for group in &mut owner_capable.observation.groups {
            if group.sid == logon_sid() {
                group.attributes |= GROUP_OWNER;
            }
        }
        for (before, after) in [(&original, &owner_capable), (&owner_capable, &original)] {
            assert_eq!(verify_fixture_baseline(before), Ok(()));
            assert_eq!(verify_fixture_baseline(after), Ok(()));
            assert_eq!(
                verify_creation_token_revalidation(before, after, 0, true),
                Err(PolicyRejection::BaselineContinuity)
            );
        }
        assert_eq!(
            verify_creation_token_revalidation(&owner_capable, &owner_capable, 1, true),
            Err(PolicyRejection::HandleContinuity)
        );
        assert_eq!(
            verify_creation_token_revalidation(&owner_capable, &owner_capable, 0, false),
            Err(PolicyRejection::HandleContinuity)
        );
        let mut wrong_owner = owner_capable.clone();
        wrong_owner.observation.owner_sid = logon_sid();
        assert_eq!(
            verify_fixture_baseline(&wrong_owner),
            Err(PolicyRejection::ServiceIdentity)
        );
        let mut proof = fixture_proof();
        proof.baseline = owner_capable;
        let owner = proof.baseline.observation.owner_sid.0.clone();
        let primary = proof.baseline.observation.primary_group_sid.0.clone();
        let token = VerifiedServiceCreationToken {
            proof: &mut proof,
            _not_sync: PhantomData,
        };
        assert!(token.verify_creation_principals(&owner, &primary).is_ok());
        assert!(
            token
                .verify_creation_principals(&logon_sid().0, &primary)
                .is_err()
        );
        assert!(
            token
                .verify_creation_principals(&owner, &logon_sid().0)
                .is_err()
        );
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires execution inside the installed restricted YourWalletKeyAgent SCM service context"]
    fn installed_service_context_matches_documented_fixture_policy()
    -> Result<(), ServiceTokenFixtureError> {
        let mut proof = verify_current_key_agent_service_token_fixture()?;
        let owner = proof.baseline.observation.owner_sid.0.clone();
        let primary_group = proof.baseline.observation.primary_group_sid.0.clone();
        let mut creation_token = proof.creation_token()?;
        creation_token.verify_creation_principals(&owner, &primary_group)?;
        creation_token.revalidate()?;
        let _borrowed = creation_token.borrowed_handle();
        Ok(())
    }
}
