//! Target-user, zero-capability LPAC inputs for the service launch probe.
//!
//! The two constructors are fixed to the Approval and Secret Input helper
//! profiles. Profile creation and observation run only while the calling
//! thread impersonates the exact authenticated desktop client. No SID, path,
//! token, or role selector is exposed to a future launch caller.

#![deny(unsafe_code)]

use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;
use core::mem::size_of;
use core::num::NonZeroU32;
use core::ptr;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::BorrowedHandle;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use thiserror::Error;
use windows::Win32::Security::{PSID, SECURITY_CAPABILITIES};
use windows::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST;

use crate::appcontainer_profile_api::{
    TargetAppContainerProfileApiGuard, acquire_target_appcontainer_profile_api,
};
use crate::key_agent_service_rpc::AuthenticatedRpcClient;
use crate::restricted_process_context::RestrictedProcessContext;

use super::FixedLpacRpcEndpointProfileSidError;

const CAPABILITY_COUNT: u32 = 0;
const MAX_ENVIRONMENT_UNITS: usize = 32_767;
const SID_REVISION: u8 = 1;
const MAX_SID_SUBAUTHORITIES: usize = 15;
const MIN_BINARY_SID_BYTES: usize = 8;
const MAX_BINARY_SID_BYTES: usize =
    MIN_BINARY_SID_BYTES + size_of::<u32>() * MAX_SID_SUBAUTHORITIES;
const APPROVAL_PROFILE_V1_NAME: &str = "YourWallet.ApprovalFrontend.LPAC.v1";
const APPROVAL_PROFILE_DISPLAY_NAME: &str = "Your Wallet approval frontend";
const APPROVAL_PROFILE_DESCRIPTION: &str =
    "Persistent no-network LPAC identity for Your Wallet approval prompts";
const SECRET_INPUT_PROFILE_V1_NAME: &str = "YourWallet.SecretInputFrontend.LPAC.v1";
const SECRET_INPUT_PROFILE_DISPLAY_NAME: &str = "Your Wallet secret input frontend";
const SECRET_INPUT_PROFILE_DESCRIPTION: &str =
    "Persistent no-network LPAC identity for Your Wallet secret input";
const PACKAGE_SID_HASH_COMPONENTS: usize = 7;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetProfileRole {
    Approval,
    SecretInput,
}

#[derive(Clone, Copy)]
struct ProfileMetadata {
    role: TargetProfileRole,
    name: &'static str,
    display_name: &'static str,
    description: &'static str,
}

const APPROVAL_PROFILE: ProfileMetadata = ProfileMetadata {
    role: TargetProfileRole::Approval,
    name: APPROVAL_PROFILE_V1_NAME,
    display_name: APPROVAL_PROFILE_DISPLAY_NAME,
    description: APPROVAL_PROFILE_DESCRIPTION,
};

const SECRET_INPUT_PROFILE: ProfileMetadata = ProfileMetadata {
    role: TargetProfileRole::SecretInput,
    name: SECRET_INPUT_PROFILE_V1_NAME,
    display_name: SECRET_INPUT_PROFILE_DISPLAY_NAME,
    description: SECRET_INPUT_PROFILE_DESCRIPTION,
};

/// Canonical package SID strings for the two fixed service-helper profiles.
///
/// The fields stay sealed so the RPC endpoint policy can only consume the
/// identities derived here from the same monikers used for process creation.
pub(crate) struct FixedLpacRpcEndpointProfileSids {
    approval: String,
    secret_input: String,
}

impl fmt::Debug for FixedLpacRpcEndpointProfileSids {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FixedLpacRpcEndpointProfileSids([REDACTED])")
    }
}

impl FixedLpacRpcEndpointProfileSids {
    /// Returns Approval then Secret Input in the fixed endpoint-ACE order.
    pub(crate) fn as_ordered_pair(&self) -> [&str; 2] {
        [&self.approval, &self.secret_input]
    }
}

/// Derives and canonicalizes the two package SIDs used by the debug-only RPC
/// helper endpoint.
///
/// Each OS allocation is immediately transferred to a `FreeSid` owner. The
/// temporary SID-string allocation is separately released with `LocalFree`
/// before the package SID owners leave this function.
pub(crate) fn derive_fixed_lpac_rpc_endpoint_profile_sids()
-> Result<FixedLpacRpcEndpointProfileSids, FixedLpacRpcEndpointProfileSidError> {
    derive_fixed_lpac_rpc_endpoint_profile_sids_with(|profile_name| {
        let sid = sys::derive_profile(&wide_nul(profile_name))?;
        let wide = sys::sid_string(sid.raw())?;
        let Some((&0, body)) = wide.split_last() else {
            return Err(TargetUserLpacError::Verification);
        };
        if body.is_empty() || body.contains(&0) {
            return Err(TargetUserLpacError::Verification);
        }
        String::from_utf16(body).map_err(|_| TargetUserLpacError::Verification)
    })
    .map_err(|_| FixedLpacRpcEndpointProfileSidError)
}

fn derive_fixed_lpac_rpc_endpoint_profile_sids_with<F>(
    mut derive: F,
) -> Result<FixedLpacRpcEndpointProfileSids, TargetUserLpacError>
where
    F: FnMut(&'static str) -> Result<String, TargetUserLpacError>,
{
    let approval = derive(APPROVAL_PROFILE_V1_NAME)?;
    let secret_input = derive(SECRET_INPUT_PROFILE_V1_NAME)?;
    if !is_canonical_package_sid_string(&approval)
        || !is_canonical_package_sid_string(&secret_input)
        || approval == secret_input
    {
        return Err(TargetUserLpacError::Verification);
    }
    Ok(FixedLpacRpcEndpointProfileSids {
        approval,
        secret_input,
    })
}

fn is_canonical_package_sid_string(value: &str) -> bool {
    let Some(hash) = value.strip_prefix("S-1-15-2-") else {
        return false;
    };
    let mut count = 0_usize;
    for component in hash.split('-') {
        let Ok(parsed) = component.parse::<u32>() else {
            return false;
        };
        if parsed.to_string() != component {
            return false;
        }
        count += 1;
    }
    count == PACKAGE_SID_HASH_COMPONENTS
}

/// Data-free failures from target-user profile preparation and revalidation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(super) enum TargetUserLpacError {
    /// The authenticated desktop identity or its retained process changed.
    #[error("target-user LPAC authentication is unavailable")]
    Authentication,
    /// The process-wide profile API or target impersonation gate failed.
    #[error("target-user LPAC profile coordination is unavailable")]
    Coordination,
    /// Windows could not create, derive, or observe the fixed profile.
    #[error("target-user LPAC profile is unavailable")]
    Profile,
    /// The returned SID or target-user profile path did not match the policy.
    #[error("target-user LPAC profile verification failed")]
    Verification,
    /// The restricted process context changed or was malformed.
    #[error("target-user LPAC process context is unavailable")]
    ProcessContext,
    /// Stable attribute storage could not be installed into a live list.
    #[error("target-user LPAC creation attributes are unavailable")]
    AttributeInstallation,
}

/// Fixed target-user LPAC profile, minimal environment, and stable attributes.
///
/// The retained authenticated client binds every later revalidation to the
/// same desktop process and primary token. This owner is move-only and
/// deliberately `!Send + !Sync`; target impersonation and launch preparation
/// must remain on one dedicated service thread.
#[must_use = "target-user LPAC inputs must remain live through child creation"]
pub(super) struct PreparedTargetUserLpac<'client> {
    client: &'client AuthenticatedRpcClient,
    metadata: ProfileMetadata,
    environment: Box<[u16]>,
    profile_folder: PathBuf,
    security_capabilities: Box<SECURITY_CAPABILITIES>,
    all_application_packages_policy: Box<u32>,
    profile_sid: OwnedAppContainerSid,
    _thread_bound: PhantomData<Rc<Cell<()>>>,
}

/// Exact created-process and primary-token continuity for one verified target
/// LPAC child.
///
/// This proof owns only down-scoped process/token handles and an independent
/// sealed copy of the expected profile identity. It borrows neither the
/// `PreparedTargetUserLpac` nor the source process handle, so a suspended
/// process owner may store all three values without a self-reference.
#[must_use = "the verified target LPAC proof must remain bound to the suspended child"]
pub(super) struct VerifiedCreatedTargetLpac<'client> {
    // Drop the token and process evidence before releasing its expected SID.
    token: sys::OwnedChildToken,
    process_query: sys::OwnedProcessQuery,
    expected: SealedExpectedTargetProfile<'client>,
    _thread_bound: PhantomData<Rc<Cell<()>>>,
}

/// Independent exact helper identity minted only from a fully revalidated
/// service-created target LPAC proof.
///
/// It retains the exact process and primary-token objects, sealed profile SID,
/// authenticated desktop session, and service-selected profile role. It does
/// not retain target impersonation or desktop launch authority and is safe to
/// move across the debugger-thread join boundary.
#[must_use = "expected service-created LPAC identity must remain process-bound"]
pub(super) struct ExpectedServiceCreatedLpac {
    token: sys::OwnedChildToken,
    process_query: sys::OwnedProcessQuery,
    profile_sid: sys::OwnedAlignedSidCopy,
    session_id: NonZeroU32,
    role: TargetProfileRole,
}

struct SealedExpectedTargetProfile<'client> {
    client: &'client AuthenticatedRpcClient,
    profile_sid: sys::OwnedAlignedSidCopy,
    role: TargetProfileRole,
    _thread_bound: PhantomData<Rc<Cell<()>>>,
}

impl fmt::Debug for VerifiedCreatedTargetLpac<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedCreatedTargetLpac([REDACTED])")
    }
}

impl fmt::Debug for ExpectedServiceCreatedLpac {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExpectedServiceCreatedLpac([REDACTED])")
    }
}

impl VerifiedCreatedTargetLpac<'_> {
    /// Irreversibly removes desktop-thread authority after one final complete
    /// created-child revalidation by the caller.
    pub(super) fn into_expected_service_created(
        self,
    ) -> Result<ExpectedServiceCreatedLpac, TargetUserLpacError> {
        let Self {
            token,
            process_query,
            expected,
            _thread_bound: _,
        } = self;
        let observed = sys::observe_child_token(&token, expected.profile_sid.as_psid())?;
        expected
            .client
            .require_desktop_session(observed.session_id)
            .map_err(|_| TargetUserLpacError::Authentication)?;
        let session_id = observed.session_id;
        validate_created_child_token_policy(&observed.with_session_match())?;
        let SealedExpectedTargetProfile {
            client: _,
            profile_sid,
            role,
            _thread_bound: _,
        } = expected;
        let independent = ExpectedServiceCreatedLpac {
            token,
            process_query,
            profile_sid,
            session_id,
            role,
        };
        independent.revalidate()?;
        Ok(independent)
    }
}

impl ExpectedServiceCreatedLpac {
    /// Returns the authenticated desktop session retained by the
    /// service-created token proof.
    pub(super) const fn session_id(&self) -> NonZeroU32 {
        self.session_id
    }

    pub(super) fn revalidate_for_process(
        &self,
        process: BorrowedHandle<'_>,
    ) -> Result<(), TargetUserLpacError> {
        sys::require_same_process(process, &self.process_query)?;
        self.revalidate()
    }

    pub(super) const fn is_approval(&self) -> bool {
        matches!(self.role, TargetProfileRole::Approval)
    }

    pub(super) const fn is_secret_input(&self) -> bool {
        matches!(self.role, TargetProfileRole::SecretInput)
    }

    fn revalidate(&self) -> Result<(), TargetUserLpacError> {
        sys::require_process_flags_zero(&self.process_query)?;
        sys::require_process_live(&self.process_query)?;
        self.revalidate_token(&self.token)?;
        let fresh = sys::open_child_token(&self.process_query)?;
        sys::require_token_flags_zero(&fresh)?;
        sys::require_same_token(&self.token, &fresh)?;
        self.revalidate_token(&fresh)
    }

    fn revalidate_token(&self, token: &sys::OwnedChildToken) -> Result<(), TargetUserLpacError> {
        sys::require_token_flags_zero(token)?;
        let observed = sys::observe_child_token(token, self.profile_sid.as_psid())?;
        if observed.session_id != self.session_id {
            return Err(TargetUserLpacError::Verification);
        }
        validate_created_child_token_policy(&observed.with_session_match())
    }
}

impl<'client> PreparedTargetUserLpac<'client> {
    /// Prepares the fixed Approval helper profile for the authenticated user.
    pub(super) fn prepare_approval(
        client: &'client AuthenticatedRpcClient,
        context: &RestrictedProcessContext,
    ) -> Result<Self, TargetUserLpacError> {
        Self::prepare(client, context, APPROVAL_PROFILE)
    }

    /// Prepares the fixed Secret Input helper profile for the authenticated
    /// user.
    pub(super) fn prepare_secret_input(
        client: &'client AuthenticatedRpcClient,
        context: &RestrictedProcessContext,
    ) -> Result<Self, TargetUserLpacError> {
        Self::prepare(client, context, SECRET_INPUT_PROFILE)
    }

    fn prepare(
        client: &'client AuthenticatedRpcClient,
        context: &RestrictedProcessContext,
        metadata: ProfileMetadata,
    ) -> Result<Self, TargetUserLpacError> {
        context
            .recheck_thread()
            .map_err(|_| TargetUserLpacError::ProcessContext)?;
        let observed = observe_profile(client, metadata, ProfileObservation::CreateOrOpen)?;
        context
            .recheck_thread()
            .map_err(|_| TargetUserLpacError::ProcessContext)?;
        let environment =
            environment_for_folder(&observed.folder, metadata.name, context.environment())?;
        let security_capabilities = Box::new(SECURITY_CAPABILITIES {
            AppContainerSid: observed.sid.raw(),
            Capabilities: ptr::null_mut(),
            CapabilityCount: CAPABILITY_COUNT,
            Reserved: 0,
        });
        let prepared = Self {
            client,
            metadata,
            environment,
            profile_folder: observed.folder,
            security_capabilities,
            all_application_packages_policy: Box::new(sys::all_application_packages_opt_out()),
            profile_sid: observed.sid,
            _thread_bound: PhantomData,
        };
        prepared.verify_stable_attributes()?;
        Ok(prepared)
    }

    /// Returns only the stable, lifetime-bound attribute installers.
    pub(super) fn creation_attributes(&self) -> PreparedTargetLpacAttributes<'_> {
        PreparedTargetLpacAttributes {
            security_capabilities: &self.security_capabilities,
            all_application_packages_policy: &self.all_application_packages_policy,
            _owner: PhantomData,
        }
    }

    /// Returns the exact three-entry, double-NUL target process environment.
    pub(super) fn environment(&self) -> &[u16] {
        &self.environment
    }

    /// Re-observes the fixed SID and folder under a fresh target impersonation
    /// and proves that the minimal environment and backing pointers are stable.
    pub(super) fn revalidate(
        &self,
        context: &RestrictedProcessContext,
    ) -> Result<(), TargetUserLpacError> {
        context
            .recheck_thread()
            .map_err(|_| TargetUserLpacError::ProcessContext)?;
        self.client
            .revalidate()
            .map_err(|_| TargetUserLpacError::Authentication)?;
        let observed = observe_profile(self.client, self.metadata, ProfileObservation::DeriveOnly)?;
        verify_fresh_observation(
            &WindowsProfileObservationOps,
            &self.profile_sid,
            &self.profile_folder,
            &self.environment,
            self.metadata,
            context.environment(),
            &observed,
        )?;
        self.verify_stable_attributes()?;
        context
            .recheck_thread()
            .map_err(|_| TargetUserLpacError::ProcessContext)
    }

    /// Verifies the exact still-live child process and token twice, retaining
    /// independent process/token object continuity without borrowing `self` or
    /// the caller's process owner in the returned proof.
    pub(super) fn verify_created_process(
        &self,
        process: BorrowedHandle<'_>,
        context: &RestrictedProcessContext,
    ) -> Result<VerifiedCreatedTargetLpac<'client>, TargetUserLpacError> {
        let ops = WindowsCreatedChildVerificationOps {
            prepared: self,
            process,
            context,
        };
        let VerifiedCreatedChildOwners {
            token,
            process_query,
            expected,
        } = verify_created_child_with(&ops)?;
        Ok(VerifiedCreatedTargetLpac {
            token,
            process_query,
            expected,
            _thread_bound: PhantomData,
        })
    }

    /// Revalidates one stored child proof against the original process owner
    /// immediately before any post-create injection or execution transition.
    pub(super) fn revalidate_created_process(
        &self,
        proof: &VerifiedCreatedTargetLpac<'client>,
        process: BorrowedHandle<'_>,
        context: &RestrictedProcessContext,
    ) -> Result<(), TargetUserLpacError> {
        let ops = WindowsCreatedChildVerificationOps {
            prepared: self,
            process,
            context,
        };
        revalidate_created_child_with(&ops, &proof.process_query, &proof.token, &proof.expected)
    }

    fn seal_expected_profile(
        &self,
        context: &RestrictedProcessContext,
    ) -> Result<SealedExpectedTargetProfile<'client>, TargetUserLpacError> {
        self.revalidate(context)?;
        let expected = SealedExpectedTargetProfile {
            client: self.client,
            profile_sid: sys::copy_sid(self.profile_sid.raw())?,
            role: self.metadata.role,
            _thread_bound: PhantomData,
        };
        self.require_expected_profile(&expected, context)?;
        Ok(expected)
    }

    fn require_expected_profile(
        &self,
        expected: &SealedExpectedTargetProfile<'client>,
        context: &RestrictedProcessContext,
    ) -> Result<(), TargetUserLpacError> {
        self.revalidate(context)?;
        expected
            .client
            .revalidate()
            .map_err(|_| TargetUserLpacError::Authentication)?;
        if !core::ptr::eq(self.client, expected.client)
            || self.metadata.role != expected.role
            || !sys::equal_sid(self.profile_sid.raw(), expected.profile_sid.as_psid())?
        {
            return Err(TargetUserLpacError::Verification);
        }
        self.verify_stable_attributes()
    }

    fn verify_stable_attributes(&self) -> Result<(), TargetUserLpacError> {
        if !stable_attribute_backing_is_exact(
            &self.security_capabilities,
            *self.all_application_packages_policy,
            self.profile_sid.raw(),
        ) {
            return Err(TargetUserLpacError::Verification);
        }
        Ok(())
    }
}

impl fmt::Debug for PreparedTargetUserLpac<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedTargetUserLpac([REDACTED])")
    }
}

/// Borrowed installers for the exact zero-capability and AAP opt-out values.
#[must_use = "attribute backing must remain borrowed through list deletion"]
pub(super) struct PreparedTargetLpacAttributes<'owner> {
    security_capabilities: &'owner SECURITY_CAPABILITIES,
    all_application_packages_policy: &'owner u32,
    _owner: PhantomData<&'owner ()>,
}

impl PreparedTargetLpacAttributes<'_> {
    /// Installs the zero-capability `AppContainer` SID into one free list slot.
    ///
    /// # Safety
    ///
    /// `attribute_list` must be initialized with a free slot and deleted before
    /// this borrowed value or its `PreparedTargetUserLpac` owner is released.
    #[allow(unsafe_code)]
    pub(super) unsafe fn install_security_capabilities_into(
        &self,
        attribute_list: LPPROC_THREAD_ATTRIBUTE_LIST,
    ) -> Result<(), TargetUserLpacError> {
        // SAFETY: the caller owns the list; this view keeps heap-backed values
        // and the AppContainer SID live for the complete list lifetime.
        unsafe { sys::install_security_capabilities(attribute_list, self.security_capabilities) }
    }

    /// Installs the exact all-application-packages opt-out value.
    ///
    /// # Safety
    ///
    /// The same list and owner lifetime contract as
    /// `install_security_capabilities_into` applies.
    #[allow(unsafe_code)]
    pub(super) unsafe fn install_all_application_packages_opt_out_into(
        &self,
        attribute_list: LPPROC_THREAD_ATTRIBUTE_LIST,
    ) -> Result<(), TargetUserLpacError> {
        // SAFETY: the caller owns the list and this view retains stable boxed
        // storage until list deletion.
        unsafe {
            sys::install_all_application_packages_policy(
                attribute_list,
                self.all_application_packages_policy,
            )
        }
    }
}

impl fmt::Debug for PreparedTargetLpacAttributes<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedTargetLpacAttributes([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExactTokenDword {
    value: u32,
    returned_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AppContainerMembershipEvidence {
    Lpac,
    RegularAppContainer,
    Neither,
    Inverted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AppContainerSidEvidence {
    Exact,
    Invalid,
    Mismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CreatedChildTokenPolicyEvidence {
    token_is_primary: bool,
    token_type_bytes: usize,
    session_id: Option<NonZeroU32>,
    session_bytes: usize,
    session_matches: bool,
    is_appcontainer: ExactTokenDword,
    is_lpac: ExactTokenDword,
    appcontainer_sid_bytes: usize,
    appcontainer_sid: AppContainerSidEvidence,
    capability_bytes: usize,
    capability_count: u32,
    membership: AppContainerMembershipEvidence,
}

fn validate_created_child_token_policy(
    evidence: &CreatedChildTokenPolicyEvidence,
) -> Result<(), TargetUserLpacError> {
    if !evidence.token_is_primary
        || evidence.token_type_bytes != size_of::<windows::Win32::Security::TOKEN_TYPE>()
        || evidence.session_id.is_none()
        || evidence.session_bytes != size_of::<u32>()
        || !evidence.session_matches
        || evidence.is_appcontainer.value != 1
        || evidence.is_appcontainer.returned_bytes != size_of::<u32>()
        || evidence.is_lpac.value != 1
        || evidence.is_lpac.returned_bytes != size_of::<u32>()
        || evidence.appcontainer_sid_bytes
            < size_of::<windows::Win32::Security::TOKEN_APPCONTAINER_INFORMATION>()
        || evidence.appcontainer_sid != AppContainerSidEvidence::Exact
        || evidence.capability_bytes < size_of::<u32>()
        || evidence.capability_count != CAPABILITY_COUNT
        || evidence.membership != AppContainerMembershipEvidence::Lpac
    {
        return Err(TargetUserLpacError::Verification);
    }
    Ok(())
}

struct VerifiedCreatedChildOwners<ProcessQuery, Token, Expected> {
    token: Token,
    process_query: ProcessQuery,
    expected: Expected,
}

type VerifiedCreatedChildOwnersFor<O> = VerifiedCreatedChildOwners<
    <O as CreatedChildVerificationOps>::ProcessQuery,
    <O as CreatedChildVerificationOps>::Token,
    <O as CreatedChildVerificationOps>::Expected,
>;

trait CreatedChildVerificationOps {
    type ProcessQuery;
    type Token;
    type Expected;

    fn seal_expected(&self) -> Result<Self::Expected, TargetUserLpacError>;

    fn duplicate_process(&self) -> Result<Self::ProcessQuery, TargetUserLpacError>;

    fn source_matches_process(
        &self,
        process: &Self::ProcessQuery,
    ) -> Result<(), TargetUserLpacError>;

    fn process_flags_are_zero(
        &self,
        process: &Self::ProcessQuery,
    ) -> Result<(), TargetUserLpacError>;

    fn process_is_live(&self, process: &Self::ProcessQuery) -> Result<(), TargetUserLpacError>;

    fn open_token(&self, process: &Self::ProcessQuery) -> Result<Self::Token, TargetUserLpacError>;

    fn token_flags_are_zero(&self, token: &Self::Token) -> Result<(), TargetUserLpacError>;

    fn token_identity_is_desktop(
        &self,
        token: &Self::Token,
        expected: &Self::Expected,
    ) -> Result<(), TargetUserLpacError>;

    fn observe_token(
        &self,
        token: &Self::Token,
        expected: &Self::Expected,
    ) -> Result<CreatedChildTokenPolicyEvidence, TargetUserLpacError>;

    fn same_token(
        &self,
        retained: &Self::Token,
        fresh: &Self::Token,
    ) -> Result<(), TargetUserLpacError>;

    fn expected_is_current(&self, expected: &Self::Expected) -> Result<(), TargetUserLpacError>;
}

fn verify_created_child_with<O>(
    ops: &O,
) -> Result<VerifiedCreatedChildOwnersFor<O>, TargetUserLpacError>
where
    O: CreatedChildVerificationOps,
{
    let expected = ops.seal_expected()?;
    let process_query = ops.duplicate_process()?;
    ops.source_matches_process(&process_query)?;
    ops.process_flags_are_zero(&process_query)?;
    ops.process_is_live(&process_query)?;

    let token = ops.open_token(&process_query)?;
    ops.token_flags_are_zero(&token)?;
    ops.token_identity_is_desktop(&token, &expected)?;
    validate_created_child_token_policy(&ops.observe_token(&token, &expected)?)?;
    ops.expected_is_current(&expected)?;

    ops.source_matches_process(&process_query)?;
    ops.process_is_live(&process_query)?;
    let fresh = ops.open_token(&process_query)?;
    ops.token_flags_are_zero(&fresh)?;
    ops.same_token(&token, &fresh)?;
    ops.token_identity_is_desktop(&fresh, &expected)?;
    validate_created_child_token_policy(&ops.observe_token(&fresh, &expected)?)?;
    ops.expected_is_current(&expected)?;
    ops.source_matches_process(&process_query)?;
    ops.process_is_live(&process_query)?;

    Ok(VerifiedCreatedChildOwners {
        token,
        process_query,
        expected,
    })
}

fn revalidate_created_child_with<O>(
    ops: &O,
    process_query: &O::ProcessQuery,
    retained_token: &O::Token,
    expected: &O::Expected,
) -> Result<(), TargetUserLpacError>
where
    O: CreatedChildVerificationOps,
{
    ops.expected_is_current(expected)?;
    ops.source_matches_process(process_query)?;
    ops.process_flags_are_zero(process_query)?;
    ops.process_is_live(process_query)?;
    ops.token_flags_are_zero(retained_token)?;
    ops.token_identity_is_desktop(retained_token, expected)?;
    validate_created_child_token_policy(&ops.observe_token(retained_token, expected)?)?;
    ops.expected_is_current(expected)?;
    ops.source_matches_process(process_query)?;
    ops.process_is_live(process_query)?;

    let fresh = ops.open_token(process_query)?;
    ops.token_flags_are_zero(&fresh)?;
    ops.same_token(retained_token, &fresh)?;
    ops.token_identity_is_desktop(&fresh, expected)?;
    validate_created_child_token_policy(&ops.observe_token(&fresh, expected)?)?;

    ops.expected_is_current(expected)?;
    ops.source_matches_process(process_query)?;
    ops.process_is_live(process_query)
}

struct WindowsCreatedChildVerificationOps<'prepared, 'client, 'process, 'context> {
    prepared: &'prepared PreparedTargetUserLpac<'client>,
    process: BorrowedHandle<'process>,
    context: &'context RestrictedProcessContext,
}

impl<'client> CreatedChildVerificationOps
    for WindowsCreatedChildVerificationOps<'_, 'client, '_, '_>
{
    type ProcessQuery = sys::OwnedProcessQuery;
    type Token = sys::OwnedChildToken;
    type Expected = SealedExpectedTargetProfile<'client>;

    fn seal_expected(&self) -> Result<Self::Expected, TargetUserLpacError> {
        self.prepared.seal_expected_profile(self.context)
    }

    fn duplicate_process(&self) -> Result<Self::ProcessQuery, TargetUserLpacError> {
        sys::duplicate_process_query(self.process)
    }

    fn source_matches_process(
        &self,
        process: &Self::ProcessQuery,
    ) -> Result<(), TargetUserLpacError> {
        sys::require_same_process(self.process, process)
    }

    fn process_flags_are_zero(
        &self,
        process: &Self::ProcessQuery,
    ) -> Result<(), TargetUserLpacError> {
        sys::require_process_flags_zero(process)
    }

    fn process_is_live(&self, process: &Self::ProcessQuery) -> Result<(), TargetUserLpacError> {
        sys::require_process_live(process)
    }

    fn open_token(&self, process: &Self::ProcessQuery) -> Result<Self::Token, TargetUserLpacError> {
        sys::open_child_token(process)
    }

    fn token_flags_are_zero(&self, token: &Self::Token) -> Result<(), TargetUserLpacError> {
        sys::require_token_flags_zero(token)
    }

    fn token_identity_is_desktop(
        &self,
        token: &Self::Token,
        expected: &Self::Expected,
    ) -> Result<(), TargetUserLpacError> {
        expected
            .client
            .require_desktop_child_identity(token.borrowed_handle())
            .map_err(|_| TargetUserLpacError::Authentication)
    }

    fn observe_token(
        &self,
        token: &Self::Token,
        expected: &Self::Expected,
    ) -> Result<CreatedChildTokenPolicyEvidence, TargetUserLpacError> {
        let observed = sys::observe_child_token(token, expected.profile_sid.as_psid())?;
        expected
            .client
            .require_desktop_session(observed.session_id)
            .map_err(|_| TargetUserLpacError::Authentication)?;
        Ok(observed.with_session_match())
    }

    fn same_token(
        &self,
        retained: &Self::Token,
        fresh: &Self::Token,
    ) -> Result<(), TargetUserLpacError> {
        sys::require_same_token(retained, fresh)
    }

    fn expected_is_current(&self, expected: &Self::Expected) -> Result<(), TargetUserLpacError> {
        self.prepared
            .require_expected_profile(expected, self.context)
    }
}

#[derive(Clone, Copy)]
enum ProfileObservation {
    CreateOrOpen,
    DeriveOnly,
}

struct ObservedProfile<Sid> {
    sid: Sid,
    folder: PathBuf,
}

enum CreateProfileOutcome<Sid> {
    Created(Sid),
    AlreadyExists,
}

/// Private safe seam that makes the complete target-profile observation
/// protocol exhaustively testable without forging an authenticated RPC client
/// or invoking profile APIs outside the target-impersonation guard.
trait ProfileObservationGuard {
    fn recheck_target(&self) -> Result<(), TargetUserLpacError>;
}

trait ProfileObservationOps {
    type Sid;

    fn create_profile(
        &self,
        metadata: ProfileMetadata,
    ) -> Result<CreateProfileOutcome<Self::Sid>, TargetUserLpacError>;

    fn derive_profile(&self, name: &str) -> Result<Self::Sid, TargetUserLpacError>;

    fn equal_sid(&self, left: &Self::Sid, right: &Self::Sid) -> Result<bool, TargetUserLpacError>;

    fn appcontainer_folder(&self, sid: &Self::Sid) -> Result<PathBuf, TargetUserLpacError>;

    fn validate_profile_folder(&self, folder: &Path) -> Result<bool, TargetUserLpacError>;
}

struct WindowsProfileObservationOps;

impl ProfileObservationGuard for TargetAppContainerProfileApiGuard<'_> {
    fn recheck_target(&self) -> Result<(), TargetUserLpacError> {
        TargetAppContainerProfileApiGuard::recheck_target(self)
            .map_err(|_| TargetUserLpacError::Authentication)
    }
}

impl ProfileObservationOps for WindowsProfileObservationOps {
    type Sid = OwnedAppContainerSid;

    fn create_profile(
        &self,
        metadata: ProfileMetadata,
    ) -> Result<CreateProfileOutcome<Self::Sid>, TargetUserLpacError> {
        let name = wide_nul(metadata.name);
        let display = wide_nul(metadata.display_name);
        let description = wide_nul(metadata.description);
        sys::create_profile(&name, &display, &description).map(|created| match created {
            Some(sid) => CreateProfileOutcome::Created(sid),
            None => CreateProfileOutcome::AlreadyExists,
        })
    }

    fn derive_profile(&self, name: &str) -> Result<Self::Sid, TargetUserLpacError> {
        sys::derive_profile(&wide_nul(name))
    }

    fn equal_sid(&self, left: &Self::Sid, right: &Self::Sid) -> Result<bool, TargetUserLpacError> {
        sys::equal_sid(left.raw(), right.raw())
    }

    fn appcontainer_folder(&self, sid: &Self::Sid) -> Result<PathBuf, TargetUserLpacError> {
        sys::appcontainer_folder(sid.raw())
    }

    fn validate_profile_folder(&self, folder: &Path) -> Result<bool, TargetUserLpacError> {
        Ok(folder.is_absolute() && folder.is_dir())
    }
}

fn observe_profile(
    client: &AuthenticatedRpcClient,
    metadata: ProfileMetadata,
    mode: ProfileObservation,
) -> Result<ObservedProfile<OwnedAppContainerSid>, TargetUserLpacError> {
    let guard = acquire_target_appcontainer_profile_api(client)
        .map_err(|_| TargetUserLpacError::Coordination)?;
    let observed =
        observe_profile_under_guard(&guard, &WindowsProfileObservationOps, metadata, mode);
    let finished = guard
        .finish()
        .map_err(|_| TargetUserLpacError::Authentication);
    match (observed, finished) {
        (Ok(observed), Ok(())) => Ok(observed),
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
    }
}

fn observe_profile_under_guard<G, O>(
    guard: &G,
    ops: &O,
    metadata: ProfileMetadata,
    mode: ProfileObservation,
) -> Result<ObservedProfile<O::Sid>, TargetUserLpacError>
where
    G: ProfileObservationGuard,
    O: ProfileObservationOps,
{
    let sid = match mode {
        ProfileObservation::CreateOrOpen => {
            let created = bookended(guard, || ops.create_profile(metadata))?;
            match created {
                CreateProfileOutcome::Created(created) => {
                    let derived = derive_profile_under_guard(guard, ops, metadata.name)?;
                    let same_sid = bookended(guard, || ops.equal_sid(&created, &derived))?;
                    if !same_sid {
                        return Err(TargetUserLpacError::Verification);
                    }
                    derived
                }
                CreateProfileOutcome::AlreadyExists => {
                    derive_profile_under_guard(guard, ops, metadata.name)?
                }
            }
        }
        ProfileObservation::DeriveOnly => derive_profile_under_guard(guard, ops, metadata.name)?,
    };

    let folder = bookended(guard, || ops.appcontainer_folder(&sid))?;
    let folder_is_valid = bookended(guard, || ops.validate_profile_folder(&folder))?;
    if !folder_is_valid {
        return Err(TargetUserLpacError::Verification);
    }
    Ok(ObservedProfile { sid, folder })
}

fn derive_profile_under_guard<G, O>(
    guard: &G,
    ops: &O,
    name: &str,
) -> Result<O::Sid, TargetUserLpacError>
where
    G: ProfileObservationGuard,
    O: ProfileObservationOps,
{
    bookended(guard, || ops.derive_profile(name))
}

fn bookended<G, T>(
    guard: &G,
    call: impl FnOnce() -> Result<T, TargetUserLpacError>,
) -> Result<T, TargetUserLpacError>
where
    G: ProfileObservationGuard,
{
    guard.recheck_target()?;
    let result = call();
    guard.recheck_target()?;
    result
}

fn verify_fresh_observation<O>(
    ops: &O,
    retained_sid: &O::Sid,
    retained_folder: &Path,
    retained_environment: &[u16],
    metadata: ProfileMetadata,
    base_environment: &[u16],
    observed: &ObservedProfile<O::Sid>,
) -> Result<(), TargetUserLpacError>
where
    O: ProfileObservationOps,
{
    if !ops.equal_sid(retained_sid, &observed.sid)? || retained_folder != observed.folder {
        return Err(TargetUserLpacError::Verification);
    }
    let expected = environment_for_folder(&observed.folder, metadata.name, base_environment)?;
    if retained_environment != expected.as_ref() {
        return Err(TargetUserLpacError::Verification);
    }
    Ok(())
}

fn stable_attribute_backing_is_exact(
    capabilities: &SECURITY_CAPABILITIES,
    policy: u32,
    expected_sid: PSID,
) -> bool {
    capabilities.AppContainerSid == expected_sid
        && capabilities.Capabilities.is_null()
        && capabilities.CapabilityCount == CAPABILITY_COUNT
        && capabilities.Reserved == 0
        && policy == sys::all_application_packages_opt_out()
}

fn environment_for_folder(
    appcontainer_local_data: &Path,
    expected_profile_name: &str,
    base_environment: &[u16],
) -> Result<Box<[u16]>, TargetUserLpacError> {
    let local_folder_name = appcontainer_local_data
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(TargetUserLpacError::Verification)?;
    let profile_folder = appcontainer_local_data
        .parent()
        .ok_or(TargetUserLpacError::Verification)?;
    let profile_name = profile_folder
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(TargetUserLpacError::Verification)?;
    let packages = profile_folder
        .parent()
        .ok_or(TargetUserLpacError::Verification)?;
    let packages_name = packages
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(TargetUserLpacError::Verification)?;
    if !local_folder_name.eq_ignore_ascii_case("AC")
        || !profile_name.eq_ignore_ascii_case(expected_profile_name)
        || !packages_name.eq_ignore_ascii_case("Packages")
        || !appcontainer_local_data.is_absolute()
        || !base_environment_is_exact(base_environment)
    {
        return Err(TargetUserLpacError::Verification);
    }

    let local_value: Vec<u16> = appcontainer_local_data.as_os_str().encode_wide().collect();
    if local_value.is_empty() || local_value.contains(&0) {
        return Err(TargetUserLpacError::Verification);
    }
    let mut environment = Vec::with_capacity(
        "LOCALAPPDATA="
            .encode_utf16()
            .count()
            .checked_add(local_value.len())
            .and_then(|length| length.checked_add(base_environment.len() + 1))
            .ok_or(TargetUserLpacError::Verification)?,
    );
    environment.extend("LOCALAPPDATA=".encode_utf16());
    environment.extend_from_slice(&local_value);
    environment.push(0);
    environment.extend_from_slice(base_environment);
    if environment.len() > MAX_ENVIRONMENT_UNITS || !environment.ends_with(&[0, 0]) {
        return Err(TargetUserLpacError::Verification);
    }
    Ok(environment.into_boxed_slice())
}

fn base_environment_is_exact(environment: &[u16]) -> bool {
    if !environment.ends_with(&[0, 0]) {
        return false;
    }
    let mut entries = environment[..environment.len() - 1].split(|unit| *unit == 0);
    let Some(system_root) = entries.next() else {
        return false;
    };
    let Some(windir) = entries.next() else {
        return false;
    };
    let Some(final_empty) = entries.next() else {
        return false;
    };
    entries.next().is_none()
        && final_empty.is_empty()
        && starts_with_utf16(system_root, "SystemRoot=")
        && starts_with_utf16(windir, "WINDIR=")
        && system_root.len() > "SystemRoot=".encode_utf16().count()
        && windir.len() > "WINDIR=".encode_utf16().count()
}

fn starts_with_utf16(value: &[u16], prefix: &str) -> bool {
    value.starts_with(&prefix.encode_utf16().collect::<Vec<_>>())
}

fn wide_nul(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(core::iter::once(0)).collect()
}

fn bounded_sid_length(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < MIN_BINARY_SID_BYTES
        || bytes[0] != SID_REVISION
        || usize::from(bytes[1]) > MAX_SID_SUBAUTHORITIES
    {
        return None;
    }
    let length = MIN_BINARY_SID_BYTES.checked_add(size_of::<u32>() * usize::from(bytes[1]))?;
    (length <= bytes.len() && length <= MAX_BINARY_SID_BYTES).then_some(length)
}

struct OwnedAppContainerSid(PSID);

impl OwnedAppContainerSid {
    fn from_profile_api(raw: PSID) -> Result<Self, TargetUserLpacError> {
        if raw.is_invalid() || !sys::is_valid_sid(raw) {
            if !raw.is_invalid() {
                sys::free_sid(raw);
            }
            return Err(TargetUserLpacError::Verification);
        }
        Ok(Self(raw))
    }

    const fn raw(&self) -> PSID {
        self.0
    }
}

impl Drop for OwnedAppContainerSid {
    fn drop(&mut self) {
        sys::free_sid(self.0);
    }
}

mod sys {
    #![allow(unsafe_code)]

    use core::ffi::c_void;
    use core::fmt;
    use core::mem::size_of;
    use core::num::NonZeroU32;
    use core::ptr;
    use core::slice;
    use std::os::windows::io::{AsRawHandle as _, BorrowedHandle};
    use std::path::PathBuf;

    use windows::Win32::Foundation::{
        CloseHandle, CompareObjectHandles, DUPLICATE_HANDLE_OPTIONS, DuplicateHandle,
        ERROR_ALREADY_EXISTS, ERROR_INSUFFICIENT_BUFFER, GetHandleInformation, HANDLE, HLOCAL,
        LocalFree, WAIT_TIMEOUT,
    };
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::Isolation::{
        CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
        GetAppContainerFolderPath,
    };
    use windows::Win32::Security::{
        CheckTokenMembershipEx, CopySid, DuplicateTokenEx, EqualSid, FreeSid, GetLengthSid,
        GetTokenInformation, IsValidSid, PSID, SECURITY_CAPABILITIES, SecurityIdentification,
        TOKEN_APPCONTAINER_INFORMATION, TOKEN_DUPLICATE, TOKEN_INFORMATION_CLASS, TOKEN_QUERY,
        TOKEN_TYPE, TOKEN_USER, TokenAppContainerSid, TokenCapabilities, TokenImpersonation,
        TokenIsAppContainer, TokenIsLessPrivilegedAppContainer, TokenPrimary, TokenSessionId,
        TokenType, TokenUser,
    };
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::System::SystemServices::{CTMF_INCLUDE_APPCONTAINER, CTMF_INCLUDE_LPAC};
    use windows::Win32::System::Threading::{
        GetCurrentProcess, LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcessToken,
        PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_ACCESS_RIGHTS,
        PROCESS_QUERY_LIMITED_INFORMATION, UpdateProcThreadAttribute, WaitForSingleObject,
    };
    use windows::Win32::System::WindowsProgramming::PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
    use windows::core::{BOOL, PCWSTR, PWSTR};

    use super::{
        AppContainerMembershipEvidence, AppContainerSidEvidence, CreatedChildTokenPolicyEvidence,
        ExactTokenDword, MAX_BINARY_SID_BYTES, MIN_BINARY_SID_BYTES, OwnedAppContainerSid,
        TargetUserLpacError, bounded_sid_length,
    };

    const MAX_TOKEN_INFORMATION_BYTES: usize = 64 * 1024;
    const PROCESS_SYNCHRONIZE: PROCESS_ACCESS_RIGHTS = PROCESS_ACCESS_RIGHTS(0x0010_0000);

    /// A real, non-inheritable duplicate with only query and synchronize access.
    pub(super) struct OwnedProcessQuery(HANDLE);

    /// A real, non-inheritable query/duplicate handle for the child's primary token.
    pub(super) struct OwnedChildToken(HANDLE);

    // SAFETY: these owners contain only non-inheritable process-wide kernel
    // handles used by synchronous query/object-comparison operations. Neither
    // handle carries impersonation, RPC-binding, or creator-thread affinity;
    // moving unique ownership across the completed debugger-thread join still
    // closes each handle exactly once.
    unsafe impl Send for OwnedProcessQuery {}
    // SAFETY: `OwnedChildToken` has the same non-inheritable, process-wide,
    // uniquely owned kernel-handle contract described immediately above.
    unsafe impl Send for OwnedChildToken {}

    struct OwnedMembershipToken(HANDLE);

    /// Aligned, independently owned copy of one validated `AppContainer` SID.
    pub(super) struct OwnedAlignedSidCopy {
        words: Box<[usize]>,
    }

    pub(super) struct ObservedChildToken {
        pub(super) session_id: NonZeroU32,
        evidence: CreatedChildTokenPolicyEvidence,
    }

    struct TokenInformation {
        words: Box<[usize]>,
        returned_bytes: usize,
    }

    impl fmt::Debug for OwnedProcessQuery {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("OwnedProcessQuery([REDACTED])")
        }
    }

    impl fmt::Debug for OwnedChildToken {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("OwnedChildToken([REDACTED])")
        }
    }

    impl fmt::Debug for OwnedAlignedSidCopy {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("OwnedAlignedSidCopy([REDACTED])")
        }
    }

    impl OwnedProcessQuery {
        const fn raw(&self) -> HANDLE {
            self.0
        }
    }

    impl OwnedChildToken {
        const fn raw(&self) -> HANDLE {
            self.0
        }

        pub(super) fn borrowed_handle(&self) -> BorrowedHandle<'_> {
            // SAFETY: the borrow cannot outlive this owner and exposes no close
            // authority. The retained token remains live for the auth query.
            unsafe { BorrowedHandle::borrow_raw(self.0.0) }
        }
    }

    impl OwnedMembershipToken {
        const fn raw(&self) -> HANDLE {
            self.0
        }
    }

    impl OwnedAlignedSidCopy {
        pub(super) fn as_psid(&self) -> PSID {
            PSID(self.words.as_ptr().cast_mut().cast::<c_void>())
        }
    }

    impl ObservedChildToken {
        pub(super) fn with_session_match(mut self) -> CreatedChildTokenPolicyEvidence {
            self.evidence.session_matches = true;
            self.evidence
        }
    }

    impl TokenInformation {
        fn bytes(&self) -> &[u8] {
            // SAFETY: `words` is live, aligned storage and `returned_bytes` was
            // bounded to the allocation's initialized API output.
            unsafe { slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.returned_bytes) }
        }

        fn prefix<T: Copy>(&self) -> Option<T> {
            (self.returned_bytes >= size_of::<T>()).then(|| {
                // SAFETY: the byte count was checked and the aligned allocation
                // remains live. Unaligned read also supports ABI structs whose
                // natural alignment is less than `usize`.
                unsafe { ptr::read_unaligned(self.words.as_ptr().cast::<T>()) }
            })
        }

        fn contained_sid(&self, sid: PSID) -> Result<PSID, TargetUserLpacError> {
            if sid.is_invalid() {
                return Err(TargetUserLpacError::Verification);
            }
            let base = self.words.as_ptr().cast::<u8>().addr();
            let end = base
                .checked_add(self.returned_bytes)
                .ok_or(TargetUserLpacError::Verification)?;
            let address = sid.0.cast::<u8>().addr();
            let offset = address
                .checked_sub(base)
                .filter(|_| address < end)
                .ok_or(TargetUserLpacError::Verification)?;
            let bytes = self
                .bytes()
                .get(offset..)
                .ok_or(TargetUserLpacError::Verification)?;
            let declared = bounded_sid_length(bytes).ok_or(TargetUserLpacError::Verification)?;
            if !is_valid_sid(sid)
                // SAFETY: pointer containment and the complete bounded SID
                // representation were established before querying its length.
                || usize::try_from(unsafe { GetLengthSid(sid) }).ok() != Some(declared)
            {
                return Err(TargetUserLpacError::Verification);
            }
            Ok(sid)
        }
    }

    impl Drop for OwnedProcessQuery {
        fn drop(&mut self) {
            close_handle(self.0);
        }
    }

    impl Drop for OwnedChildToken {
        fn drop(&mut self) {
            close_handle(self.0);
        }
    }

    impl Drop for OwnedMembershipToken {
        fn drop(&mut self) {
            close_handle(self.0);
        }
    }

    fn close_handle(handle: HANDLE) {
        if !handle.is_invalid() {
            // SAFETY: every wrapper accepts exactly one successful owned handle.
            unsafe {
                let _ = CloseHandle(handle);
            }
        }
    }

    pub(super) fn copy_sid(source: PSID) -> Result<OwnedAlignedSidCopy, TargetUserLpacError> {
        if !is_valid_sid(source) {
            return Err(TargetUserLpacError::Verification);
        }
        // SAFETY: `source` was validated and is retained by its live owner.
        let byte_len = usize::try_from(unsafe { GetLengthSid(source) })
            .map_err(|_| TargetUserLpacError::Verification)?;
        if !(MIN_BINARY_SID_BYTES..=MAX_BINARY_SID_BYTES).contains(&byte_len) {
            return Err(TargetUserLpacError::Verification);
        }
        let word_bytes = size_of::<usize>();
        let word_count = byte_len
            .checked_add(word_bytes - 1)
            .and_then(|rounded| rounded.checked_div(word_bytes))
            .ok_or(TargetUserLpacError::Verification)?;
        let mut words = vec![0_usize; word_count].into_boxed_slice();
        let destination = PSID(words.as_mut_ptr().cast::<c_void>());
        // SAFETY: the destination is aligned writable storage of at least the
        // validated source length; both allocations remain live for the call.
        unsafe {
            CopySid(
                u32::try_from(byte_len).map_err(|_| TargetUserLpacError::Verification)?,
                destination,
                source,
            )
        }
        .map_err(|_| TargetUserLpacError::Verification)?;
        let owned = OwnedAlignedSidCopy { words };
        if !is_valid_sid(owned.as_psid())
            // SAFETY: `owned` retains a successful complete CopySid result.
            || usize::try_from(unsafe { GetLengthSid(owned.as_psid()) }).ok() != Some(byte_len)
            || !equal_sid(source, owned.as_psid())?
        {
            return Err(TargetUserLpacError::Verification);
        }
        Ok(owned)
    }

    pub(super) fn duplicate_process_query(
        source: BorrowedHandle<'_>,
    ) -> Result<OwnedProcessQuery, TargetUserLpacError> {
        let source = HANDLE(source.as_raw_handle());
        // SAFETY: the current-process pseudo handle denotes the source and
        // target handle table. `source` is borrowed for the complete call.
        let current_process = unsafe { GetCurrentProcess() };
        let mut duplicate = HANDLE::default();
        // SAFETY: output is exclusive, and the requested mask is exactly the
        // non-mutating process query/liveness access required by this proof.
        unsafe {
            DuplicateHandle(
                current_process,
                source,
                current_process,
                &raw mut duplicate,
                (PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE).0,
                false,
                DUPLICATE_HANDLE_OPTIONS(0),
            )
        }
        .map_err(|_| TargetUserLpacError::Verification)?;
        if duplicate.is_invalid() {
            return Err(TargetUserLpacError::Verification);
        }
        Ok(OwnedProcessQuery(duplicate))
    }

    pub(super) fn require_same_process(
        source: BorrowedHandle<'_>,
        duplicate: &OwnedProcessQuery,
    ) -> Result<(), TargetUserLpacError> {
        let source = HANDLE(source.as_raw_handle());
        require_handle_flags_zero(source)?;
        // SAFETY: both process handles are borrowed and live for the comparison.
        unsafe { CompareObjectHandles(source, duplicate.raw()) }
            .as_bool()
            .then_some(())
            .ok_or(TargetUserLpacError::Verification)
    }

    pub(super) fn require_process_flags_zero(
        process: &OwnedProcessQuery,
    ) -> Result<(), TargetUserLpacError> {
        require_handle_flags_zero(process.raw())
    }

    pub(super) fn require_process_live(
        process: &OwnedProcessQuery,
    ) -> Result<(), TargetUserLpacError> {
        // SAFETY: the retained process handle owns SYNCHRONIZE access; a
        // zero-duration wait only observes whether it has been signalled.
        (unsafe { WaitForSingleObject(process.raw(), 0) } == WAIT_TIMEOUT)
            .then_some(())
            .ok_or(TargetUserLpacError::Verification)
    }

    pub(super) fn open_child_token(
        process: &OwnedProcessQuery,
    ) -> Result<OwnedChildToken, TargetUserLpacError> {
        let mut token = HANDLE::default();
        // SAFETY: process has query access and remains live; output is exclusive.
        unsafe { OpenProcessToken(process.raw(), TOKEN_QUERY | TOKEN_DUPLICATE, &raw mut token) }
            .map_err(|_| TargetUserLpacError::Verification)?;
        if token.is_invalid() {
            return Err(TargetUserLpacError::Verification);
        }
        Ok(OwnedChildToken(token))
    }

    pub(super) fn require_token_flags_zero(
        token: &OwnedChildToken,
    ) -> Result<(), TargetUserLpacError> {
        require_handle_flags_zero(token.raw())
    }

    pub(super) fn require_same_token(
        retained: &OwnedChildToken,
        fresh: &OwnedChildToken,
    ) -> Result<(), TargetUserLpacError> {
        // SAFETY: both owned token handles remain live for the comparison.
        unsafe { CompareObjectHandles(retained.raw(), fresh.raw()) }
            .as_bool()
            .then_some(())
            .ok_or(TargetUserLpacError::Verification)
    }

    pub(super) fn observe_child_token(
        token: &OwnedChildToken,
        expected_sid: PSID,
    ) -> Result<ObservedChildToken, TargetUserLpacError> {
        if !is_valid_sid(expected_sid) {
            return Err(TargetUserLpacError::Verification);
        }

        let mut token_type = TOKEN_TYPE::default();
        let token_type_bytes = query_token_fixed(token.raw(), TokenType, &mut token_type)?;
        let session = query_token_dword(token.raw(), TokenSessionId)?;
        let session_id = NonZeroU32::new(session.value).ok_or(TargetUserLpacError::Verification)?;
        let is_appcontainer = query_token_dword(token.raw(), TokenIsAppContainer)?;
        // There is intentionally no ERROR_INVALID_PARAMETER fallback: an OS
        // without the authoritative LPAC token class cannot produce a proof.
        let is_lpac = query_token_dword(token.raw(), TokenIsLessPrivilegedAppContainer)?;

        let appcontainer = query_token_information(token.raw(), TokenAppContainerSid)?;
        let container = appcontainer
            .prefix::<TOKEN_APPCONTAINER_INFORMATION>()
            .ok_or(TargetUserLpacError::Verification)?;
        let observed_sid = appcontainer.contained_sid(container.TokenAppContainer)?;
        let appcontainer_sid_matches = equal_sid(observed_sid, expected_sid)?;

        let capabilities = query_token_information(token.raw(), TokenCapabilities)?;
        let capability_count = capabilities
            .bytes()
            .get(..size_of::<u32>())
            .and_then(|bytes| <[u8; size_of::<u32>()]>::try_from(bytes).ok())
            .map(u32::from_ne_bytes)
            .ok_or(TargetUserLpacError::Verification)?;
        let membership = observe_appcontainer_membership(token)?;

        Ok(ObservedChildToken {
            session_id,
            evidence: CreatedChildTokenPolicyEvidence {
                token_is_primary: token_type == TokenPrimary,
                token_type_bytes,
                session_id: Some(session_id),
                session_bytes: session.returned_bytes,
                session_matches: false,
                is_appcontainer,
                is_lpac,
                appcontainer_sid_bytes: appcontainer.returned_bytes,
                appcontainer_sid: if appcontainer_sid_matches {
                    AppContainerSidEvidence::Exact
                } else {
                    AppContainerSidEvidence::Mismatch
                },
                capability_bytes: capabilities.returned_bytes,
                capability_count,
                membership,
            },
        })
    }

    fn query_token_fixed<T>(
        token: HANDLE,
        class: TOKEN_INFORMATION_CLASS,
        output: &mut T,
    ) -> Result<usize, TargetUserLpacError> {
        let mut returned = 0_u32;
        // SAFETY: `output` is writable for its exact ABI size; the token is
        // live and query-authorized. The caller validates the returned size.
        unsafe {
            GetTokenInformation(
                token,
                class,
                Some(ptr::from_mut(output).cast::<c_void>()),
                u32::try_from(size_of::<T>()).map_err(|_| TargetUserLpacError::Verification)?,
                &raw mut returned,
            )
        }
        .map_err(|_| TargetUserLpacError::Verification)?;
        usize::try_from(returned).map_err(|_| TargetUserLpacError::Verification)
    }

    fn query_token_dword(
        token: HANDLE,
        class: TOKEN_INFORMATION_CLASS,
    ) -> Result<ExactTokenDword, TargetUserLpacError> {
        let mut value = 0_u32;
        let returned_bytes = query_token_fixed(token, class, &mut value)?;
        Ok(ExactTokenDword {
            value,
            returned_bytes,
        })
    }

    fn query_token_information(
        token: HANDLE,
        class: TOKEN_INFORMATION_CLASS,
    ) -> Result<TokenInformation, TargetUserLpacError> {
        let mut required = 0_u32;
        // SAFETY: documented sizing call; no output buffer is supplied.
        match unsafe { GetTokenInformation(token, class, None, 0, &raw mut required) } {
            Err(error) if error.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult() => {}
            _ => return Err(TargetUserLpacError::Verification),
        }
        let required = usize::try_from(required).map_err(|_| TargetUserLpacError::Verification)?;
        if required == 0 || required > MAX_TOKEN_INFORMATION_BYTES {
            return Err(TargetUserLpacError::Verification);
        }
        let word_bytes = size_of::<usize>();
        let word_count = required
            .checked_add(word_bytes - 1)
            .and_then(|rounded| rounded.checked_div(word_bytes))
            .ok_or(TargetUserLpacError::Verification)?;
        let mut words = vec![0_usize; word_count].into_boxed_slice();
        let mut returned = 0_u32;
        // SAFETY: the aligned allocation has at least `required` writable
        // bytes and remains owned through all parsing of its interior pointers.
        unsafe {
            GetTokenInformation(
                token,
                class,
                Some(words.as_mut_ptr().cast::<c_void>()),
                u32::try_from(required).map_err(|_| TargetUserLpacError::Verification)?,
                &raw mut returned,
            )
        }
        .map_err(|_| TargetUserLpacError::Verification)?;
        let returned_bytes =
            usize::try_from(returned).map_err(|_| TargetUserLpacError::Verification)?;
        if returned_bytes == 0 || returned_bytes > required {
            return Err(TargetUserLpacError::Verification);
        }
        Ok(TokenInformation {
            words,
            returned_bytes,
        })
    }

    fn observe_appcontainer_membership(
        token: &OwnedChildToken,
    ) -> Result<AppContainerMembershipEvidence, TargetUserLpacError> {
        let user_information = query_token_information(token.raw(), TokenUser)?;
        let user = user_information
            .prefix::<TOKEN_USER>()
            .ok_or(TargetUserLpacError::Verification)?;
        let user_sid = user_information.contained_sid(user.User.Sid)?;

        let mut impersonation = HANDLE::default();
        // SAFETY: the child token is live and has TOKEN_DUPLICATE; output is
        // exclusive and requests only query access at identification level.
        unsafe {
            DuplicateTokenEx(
                token.raw(),
                TOKEN_QUERY,
                None,
                SecurityIdentification,
                TokenImpersonation,
                &raw mut impersonation,
            )
        }
        .map_err(|_| TargetUserLpacError::Verification)?;
        if impersonation.is_invalid() {
            return Err(TargetUserLpacError::Verification);
        }
        let impersonation = OwnedMembershipToken(impersonation);
        require_handle_flags_zero(impersonation.raw())?;

        let check = |flags| -> Result<bool, TargetUserLpacError> {
            let mut member = BOOL(0);
            // SAFETY: the identification token and contained user SID remain
            // live for this non-mutating AppContainer-aware membership query.
            unsafe {
                CheckTokenMembershipEx(Some(impersonation.raw()), user_sid, flags, &raw mut member)
            }
            .map_err(|_| TargetUserLpacError::Verification)?;
            Ok(member.as_bool())
        };
        let regular = check(CTMF_INCLUDE_APPCONTAINER)?;
        let lpac = check(CTMF_INCLUDE_APPCONTAINER | CTMF_INCLUDE_LPAC)?;
        Ok(match (regular, lpac) {
            (false, true) => AppContainerMembershipEvidence::Lpac,
            (true, true) => AppContainerMembershipEvidence::RegularAppContainer,
            (false, false) => AppContainerMembershipEvidence::Neither,
            (true, false) => AppContainerMembershipEvidence::Inverted,
        })
    }

    fn require_handle_flags_zero(handle: HANDLE) -> Result<(), TargetUserLpacError> {
        let mut flags = u32::MAX;
        // SAFETY: the caller retains the live owned handle for this scalar query.
        unsafe { GetHandleInformation(handle, &raw mut flags) }
            .map_err(|_| TargetUserLpacError::Verification)?;
        (flags == 0)
            .then_some(())
            .ok_or(TargetUserLpacError::Verification)
    }

    pub(super) const fn all_application_packages_opt_out() -> u32 {
        PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT
    }

    pub(super) fn create_profile(
        name: &[u16],
        display_name: &[u16],
        description: &[u16],
    ) -> Result<Option<OwnedAppContainerSid>, TargetUserLpacError> {
        // SAFETY: every slice is NUL terminated, remains live for the call, and
        // no capability array is supplied. A success SID is FreeSid-owned.
        match unsafe {
            CreateAppContainerProfile(
                PCWSTR(name.as_ptr()),
                PCWSTR(display_name.as_ptr()),
                PCWSTR(description.as_ptr()),
                None,
            )
        } {
            Ok(raw) => OwnedAppContainerSid::from_profile_api(raw).map(Some),
            Err(error) if error.code() == ERROR_ALREADY_EXISTS.to_hresult() => Ok(None),
            Err(_) => Err(TargetUserLpacError::Profile),
        }
    }

    pub(super) fn derive_profile(
        name: &[u16],
    ) -> Result<OwnedAppContainerSid, TargetUserLpacError> {
        // SAFETY: `name` is a live NUL-terminated fixed profile name. A success
        // SID is transferred immediately into its FreeSid owner.
        let raw = unsafe { DeriveAppContainerSidFromAppContainerName(PCWSTR(name.as_ptr())) }
            .map_err(|_| TargetUserLpacError::Profile)?;
        OwnedAppContainerSid::from_profile_api(raw)
    }

    pub(super) fn equal_sid(left: PSID, right: PSID) -> Result<bool, TargetUserLpacError> {
        if !is_valid_sid(left) || !is_valid_sid(right) {
            return Err(TargetUserLpacError::Verification);
        }
        // SAFETY: both SIDs are validated and retained by live owners.
        Ok(unsafe { EqualSid(left, right) }.is_ok())
    }

    pub(super) fn appcontainer_folder(sid: PSID) -> Result<PathBuf, TargetUserLpacError> {
        let sid_text = sid_string(sid)?;
        // SAFETY: the canonical SID string is NUL terminated and remains live;
        // a success path is CoTaskMem-owned until the conversion completes.
        let raw = unsafe { GetAppContainerFolderPath(PCWSTR(sid_text.as_ptr())) }
            .map_err(|_| TargetUserLpacError::Profile)?;
        let owned = OwnedCoTaskMemWide(raw);
        owned.to_path()
    }

    pub(super) fn sid_string(sid: PSID) -> Result<Vec<u16>, TargetUserLpacError> {
        if !is_valid_sid(sid) {
            return Err(TargetUserLpacError::Verification);
        }
        let mut raw = PWSTR::null();
        // SAFETY: the SID is valid and retained; success returns LocalAlloc
        // storage owned by `OwnedLocalWide`.
        unsafe { ConvertSidToStringSidW(sid, &raw mut raw) }
            .map_err(|_| TargetUserLpacError::Profile)?;
        let owned = OwnedLocalWide(raw);
        owned.to_wide_nul()
    }

    pub(super) fn is_valid_sid(sid: PSID) -> bool {
        // SAFETY: callers use this as the validation boundary for an opaque
        // pointer returned by a profile API or retained by a validated owner.
        !sid.is_invalid() && unsafe { IsValidSid(sid) }.as_bool()
    }

    pub(super) fn free_sid(sid: PSID) {
        if !sid.is_invalid() {
            // SAFETY: callers transfer exactly one profile-API SID allocation.
            let remainder = unsafe { FreeSid(sid) };
            if !remainder.is_null() {
                std::process::abort();
            }
        }
    }

    pub(super) unsafe fn install_security_capabilities(
        list: LPPROC_THREAD_ATTRIBUTE_LIST,
        capabilities: &SECURITY_CAPABILITIES,
    ) -> Result<(), TargetUserLpacError> {
        // SAFETY: the caller guarantees a live initialized list and retains
        // this stable backing plus the referenced SID through list deletion.
        unsafe {
            update(
                list,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                ptr::from_ref(capabilities).cast::<c_void>(),
                size_of::<SECURITY_CAPABILITIES>(),
            )
        }
    }

    pub(super) unsafe fn install_all_application_packages_policy(
        list: LPPROC_THREAD_ATTRIBUTE_LIST,
        policy: &u32,
    ) -> Result<(), TargetUserLpacError> {
        // SAFETY: the caller guarantees a live initialized list and retains
        // this stable policy value through list deletion.
        unsafe {
            update(
                list,
                PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                ptr::from_ref(policy).cast::<c_void>(),
                size_of::<u32>(),
            )
        }
    }

    unsafe fn update(
        list: LPPROC_THREAD_ATTRIBUTE_LIST,
        attribute: u32,
        value: *const c_void,
        value_bytes: usize,
    ) -> Result<(), TargetUserLpacError> {
        // SAFETY: forwarded from the two lifetime-bound installers above.
        unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                usize::try_from(attribute)
                    .map_err(|_| TargetUserLpacError::AttributeInstallation)?,
                Some(value),
                value_bytes,
                None,
                None,
            )
        }
        .map_err(|_| TargetUserLpacError::AttributeInstallation)
    }

    struct OwnedLocalWide(PWSTR);

    impl OwnedLocalWide {
        fn to_wide_nul(&self) -> Result<Vec<u16>, TargetUserLpacError> {
            if self.0.is_null() {
                return Err(TargetUserLpacError::Profile);
            }
            // SAFETY: successful conversion returned one NUL-terminated string
            // which remains live through this conversion.
            let value = unsafe { self.0.to_string() }.map_err(|_| TargetUserLpacError::Profile)?;
            Ok(value.encode_utf16().chain(core::iter::once(0)).collect())
        }
    }

    impl Drop for OwnedLocalWide {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: ConvertSidToStringSidW returns LocalAlloc storage.
                let remainder = unsafe { LocalFree(Some(HLOCAL(self.0.0.cast::<c_void>()))) };
                if !remainder.0.is_null() {
                    std::process::abort();
                }
                self.0 = PWSTR::null();
            }
        }
    }

    struct OwnedCoTaskMemWide(PWSTR);

    impl OwnedCoTaskMemWide {
        fn to_path(&self) -> Result<PathBuf, TargetUserLpacError> {
            if self.0.is_null() {
                return Err(TargetUserLpacError::Profile);
            }
            // SAFETY: a successful GetAppContainerFolderPath result is live and
            // NUL terminated until this owner drops.
            unsafe { self.0.to_string() }
                .map(PathBuf::from)
                .map_err(|_| TargetUserLpacError::Profile)
        }
    }

    impl Drop for OwnedCoTaskMemWide {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: GetAppContainerFolderPath allocates with CoTaskMem.
                unsafe { CoTaskMemFree(Some(self.0.0.cast::<c_void>())) };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;
    use core::ffi::c_void;
    use core::mem::size_of;
    use core::num::NonZeroU32;
    use std::cell::RefCell;
    use std::os::windows::ffi::OsStrExt as _;
    use std::path::{Path, PathBuf};
    use std::rc::Rc;

    use windows::Win32::Security::{PSID, SECURITY_CAPABILITIES};

    use super::{
        APPROVAL_PROFILE, APPROVAL_PROFILE_V1_NAME, AppContainerMembershipEvidence,
        AppContainerSidEvidence, CAPABILITY_COUNT, CreateProfileOutcome,
        CreatedChildTokenPolicyEvidence, CreatedChildVerificationOps, ExactTokenDword,
        ObservedProfile, PreparedTargetUserLpac, ProfileMetadata, ProfileObservation,
        ProfileObservationGuard, ProfileObservationOps, SECRET_INPUT_PROFILE,
        SECRET_INPUT_PROFILE_V1_NAME, TargetUserLpacError, VerifiedCreatedTargetLpac,
        base_environment_is_exact, bounded_sid_length,
        derive_fixed_lpac_rpc_endpoint_profile_sids_with, environment_for_folder,
        observe_profile_under_guard, revalidate_created_child_with,
        stable_attribute_backing_is_exact, validate_created_child_token_policy,
        verify_created_child_with, verify_fresh_observation,
    };

    const CREATED_TRACE: [&str; 15] = [
        "check",
        "create",
        "check",
        "check",
        "derive",
        "check",
        "check",
        "equal",
        "check",
        "check",
        "folder",
        "check",
        "check",
        "filesystem",
        "check",
    ];
    const ALREADY_EXISTS_TRACE: [&str; 12] = [
        "check",
        "create",
        "check",
        "check",
        "derive",
        "check",
        "check",
        "folder",
        "check",
        "check",
        "filesystem",
        "check",
    ];
    const DERIVE_ONLY_TRACE: [&str; 9] = [
        "check",
        "derive",
        "check",
        "check",
        "folder",
        "check",
        "check",
        "filesystem",
        "check",
    ];

    #[derive(Clone, Copy)]
    enum FakeCreate {
        Created(u8),
        AlreadyExists,
    }

    struct FakeControl {
        trace: RefCell<Vec<&'static str>>,
        event_index: Cell<usize>,
        fail_at: Option<usize>,
    }

    impl FakeControl {
        fn new(fail_at: Option<usize>) -> Self {
            Self {
                trace: RefCell::new(Vec::new()),
                event_index: Cell::new(0),
                fail_at,
            }
        }

        fn event(&self, label: &'static str) -> Result<(), TargetUserLpacError> {
            self.trace.borrow_mut().push(label);
            let index = self.event_index.get();
            self.event_index.set(index.saturating_add(1));
            if self.fail_at == Some(index) {
                return if label == "check" {
                    Err(TargetUserLpacError::Authentication)
                } else {
                    Err(TargetUserLpacError::Profile)
                };
            }
            Ok(())
        }

        fn observed_trace(&self) -> Vec<&'static str> {
            self.trace.borrow().clone()
        }
    }

    struct FakeSid {
        id: u8,
        drops: Rc<RefCell<Vec<u8>>>,
    }

    impl FakeSid {
        fn new(id: u8, drops: &Rc<RefCell<Vec<u8>>>) -> Self {
            Self {
                id,
                drops: Rc::clone(drops),
            }
        }
    }

    impl Drop for FakeSid {
        fn drop(&mut self) {
            self.drops.borrow_mut().push(self.id);
        }
    }

    struct FakeGuard {
        control: Rc<FakeControl>,
    }

    impl ProfileObservationGuard for FakeGuard {
        fn recheck_target(&self) -> Result<(), TargetUserLpacError> {
            self.control.event("check")
        }
    }

    struct FakeOps {
        control: Rc<FakeControl>,
        drops: Rc<RefCell<Vec<u8>>>,
        create: FakeCreate,
        derived_id: u8,
        folder: PathBuf,
        folder_valid: bool,
    }

    impl ProfileObservationOps for FakeOps {
        type Sid = FakeSid;

        fn create_profile(
            &self,
            _metadata: ProfileMetadata,
        ) -> Result<CreateProfileOutcome<Self::Sid>, TargetUserLpacError> {
            self.control.event("create")?;
            Ok(match self.create {
                FakeCreate::Created(id) => {
                    CreateProfileOutcome::Created(FakeSid::new(id, &self.drops))
                }
                FakeCreate::AlreadyExists => CreateProfileOutcome::AlreadyExists,
            })
        }

        fn derive_profile(&self, _name: &str) -> Result<Self::Sid, TargetUserLpacError> {
            self.control.event("derive")?;
            Ok(FakeSid::new(self.derived_id, &self.drops))
        }

        fn equal_sid(
            &self,
            left: &Self::Sid,
            right: &Self::Sid,
        ) -> Result<bool, TargetUserLpacError> {
            self.control.event("equal")?;
            Ok(left.id == right.id)
        }

        fn appcontainer_folder(&self, _sid: &Self::Sid) -> Result<PathBuf, TargetUserLpacError> {
            self.control.event("folder")?;
            Ok(self.folder.clone())
        }

        fn validate_profile_folder(&self, _folder: &Path) -> Result<bool, TargetUserLpacError> {
            self.control.event("filesystem")?;
            Ok(self.folder_valid)
        }
    }

    struct FakeSetup {
        guard: FakeGuard,
        ops: FakeOps,
        control: Rc<FakeControl>,
        drops: Rc<RefCell<Vec<u8>>>,
    }

    impl FakeSetup {
        fn new(
            fail_at: Option<usize>,
            create: FakeCreate,
            derived_id: u8,
            folder_valid: bool,
        ) -> Self {
            let control = Rc::new(FakeControl::new(fail_at));
            let drops = Rc::new(RefCell::new(Vec::new()));
            let folder = approval_folder();
            Self {
                guard: FakeGuard {
                    control: Rc::clone(&control),
                },
                ops: FakeOps {
                    control: Rc::clone(&control),
                    drops: Rc::clone(&drops),
                    create,
                    derived_id,
                    folder,
                    folder_valid,
                },
                control,
                drops,
            }
        }
    }

    fn approval_folder() -> PathBuf {
        PathBuf::from(
            r"C:\ProfileRoot\AppData\Local\Packages\YourWallet.ApprovalFrontend.LPAC.v1\AC",
        )
    }

    fn drop_count(drops: &[u8], id: u8) -> usize {
        drops
            .iter()
            .fold(0, |count, observed| count + usize::from(*observed == id))
    }

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

    trait AmbiguousIfClone<A> {
        fn marker() {}
    }
    impl<T: Clone> AmbiguousIfClone<u8> for T {}
    impl<T: ?Sized> AmbiguousIfClone<()> for T {}

    trait AmbiguousIfCopy<A> {
        fn marker() {}
    }
    impl<T: Copy> AmbiguousIfCopy<u8> for T {}
    impl<T: ?Sized> AmbiguousIfCopy<()> for T {}

    const VERIFY_CHILD_TRACE: [&str; 20] = [
        "seal_expected",
        "duplicate_process",
        "source_matches_process",
        "process_flags_are_zero",
        "process_is_live",
        "open_token",
        "token_flags_are_zero",
        "token_identity_is_desktop",
        "observe_token",
        "expected_is_current",
        "source_matches_process",
        "process_is_live",
        "open_token",
        "token_flags_are_zero",
        "same_token",
        "token_identity_is_desktop",
        "observe_token",
        "expected_is_current",
        "source_matches_process",
        "process_is_live",
    ];

    const REVALIDATE_CHILD_TRACE: [&str; 18] = [
        "expected_is_current",
        "source_matches_process",
        "process_flags_are_zero",
        "process_is_live",
        "token_flags_are_zero",
        "token_identity_is_desktop",
        "observe_token",
        "expected_is_current",
        "source_matches_process",
        "process_is_live",
        "open_token",
        "token_flags_are_zero",
        "same_token",
        "token_identity_is_desktop",
        "observe_token",
        "expected_is_current",
        "source_matches_process",
        "process_is_live",
    ];

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FakeExpectedState {
        Current,
        WrongSid,
        WrongFolder,
        WrongEnvironment,
        WrongRole,
        WrongClient,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FakeChildIdentityState {
        Exact,
        WrongUserSid,
        WrongLogonSid,
        WrongAuthenticationId,
        WrongSession,
        WrongTokenShape,
    }

    struct FakeChildControl {
        trace: RefCell<Vec<&'static str>>,
        event_index: Cell<usize>,
        fail_at: Option<usize>,
    }

    impl FakeChildControl {
        fn new(fail_at: Option<usize>) -> Self {
            Self {
                trace: RefCell::new(Vec::new()),
                event_index: Cell::new(0),
                fail_at,
            }
        }

        fn event(&self, name: &'static str) -> Result<(), TargetUserLpacError> {
            self.trace.borrow_mut().push(name);
            let index = self.event_index.get();
            self.event_index.set(index.saturating_add(1));
            if self.fail_at == Some(index) {
                return Err(TargetUserLpacError::Verification);
            }
            Ok(())
        }

        fn reset_trace(&self) {
            self.trace.borrow_mut().clear();
            self.event_index.set(0);
        }
    }

    struct FakeChildOwner {
        id: u8,
        drops: Rc<RefCell<Vec<u8>>>,
    }

    impl FakeChildOwner {
        fn new(id: u8, drops: &Rc<RefCell<Vec<u8>>>) -> Self {
            Self {
                id,
                drops: Rc::clone(drops),
            }
        }
    }

    impl Drop for FakeChildOwner {
        fn drop(&mut self) {
            self.drops.borrow_mut().push(self.id);
        }
    }

    struct FakeChildOps {
        control: Rc<FakeChildControl>,
        drops: Rc<RefCell<Vec<u8>>>,
        next_token: Cell<u8>,
        evidence: Cell<CreatedChildTokenPolicyEvidence>,
        expected_state: Cell<FakeExpectedState>,
        child_identity: Cell<FakeChildIdentityState>,
        source_matches: Cell<bool>,
        process_live: Cell<bool>,
        token_continuity: Cell<bool>,
    }

    impl FakeChildOps {
        fn new(fail_at: Option<usize>) -> Self {
            Self {
                control: Rc::new(FakeChildControl::new(fail_at)),
                drops: Rc::new(RefCell::new(Vec::new())),
                next_token: Cell::new(10),
                evidence: Cell::new(valid_child_evidence()),
                expected_state: Cell::new(FakeExpectedState::Current),
                child_identity: Cell::new(FakeChildIdentityState::Exact),
                source_matches: Cell::new(true),
                process_live: Cell::new(true),
                token_continuity: Cell::new(true),
            }
        }

        fn owner(&self, id: u8) -> FakeChildOwner {
            FakeChildOwner::new(id, &self.drops)
        }

        fn trace(&self) -> Vec<&'static str> {
            self.control.trace.borrow().clone()
        }
    }

    impl CreatedChildVerificationOps for FakeChildOps {
        type ProcessQuery = FakeChildOwner;
        type Token = FakeChildOwner;
        type Expected = FakeChildOwner;

        fn seal_expected(&self) -> Result<Self::Expected, TargetUserLpacError> {
            self.control.event("seal_expected")?;
            Ok(self.owner(1))
        }

        fn duplicate_process(&self) -> Result<Self::ProcessQuery, TargetUserLpacError> {
            self.control.event("duplicate_process")?;
            Ok(self.owner(2))
        }

        fn source_matches_process(
            &self,
            _process: &Self::ProcessQuery,
        ) -> Result<(), TargetUserLpacError> {
            self.control.event("source_matches_process")?;
            self.source_matches
                .get()
                .then_some(())
                .ok_or(TargetUserLpacError::Verification)
        }

        fn process_flags_are_zero(
            &self,
            _process: &Self::ProcessQuery,
        ) -> Result<(), TargetUserLpacError> {
            self.control.event("process_flags_are_zero")
        }

        fn process_is_live(
            &self,
            _process: &Self::ProcessQuery,
        ) -> Result<(), TargetUserLpacError> {
            self.control.event("process_is_live")?;
            self.process_live
                .get()
                .then_some(())
                .ok_or(TargetUserLpacError::Verification)
        }

        fn open_token(
            &self,
            _process: &Self::ProcessQuery,
        ) -> Result<Self::Token, TargetUserLpacError> {
            self.control.event("open_token")?;
            let id = self.next_token.get();
            self.next_token.set(id.saturating_add(1));
            Ok(self.owner(id))
        }

        fn token_flags_are_zero(&self, _token: &Self::Token) -> Result<(), TargetUserLpacError> {
            self.control.event("token_flags_are_zero")
        }

        fn token_identity_is_desktop(
            &self,
            _token: &Self::Token,
            _expected: &Self::Expected,
        ) -> Result<(), TargetUserLpacError> {
            self.control.event("token_identity_is_desktop")?;
            (self.child_identity.get() == FakeChildIdentityState::Exact)
                .then_some(())
                .ok_or(TargetUserLpacError::Authentication)
        }

        fn observe_token(
            &self,
            _token: &Self::Token,
            _expected: &Self::Expected,
        ) -> Result<CreatedChildTokenPolicyEvidence, TargetUserLpacError> {
            self.control.event("observe_token")?;
            Ok(self.evidence.get())
        }

        fn same_token(
            &self,
            _retained: &Self::Token,
            _fresh: &Self::Token,
        ) -> Result<(), TargetUserLpacError> {
            self.control.event("same_token")?;
            self.token_continuity
                .get()
                .then_some(())
                .ok_or(TargetUserLpacError::Verification)
        }

        fn expected_is_current(
            &self,
            _expected: &Self::Expected,
        ) -> Result<(), TargetUserLpacError> {
            self.control.event("expected_is_current")?;
            (self.expected_state.get() == FakeExpectedState::Current)
                .then_some(())
                .ok_or(TargetUserLpacError::Verification)
        }
    }

    fn valid_child_evidence() -> CreatedChildTokenPolicyEvidence {
        CreatedChildTokenPolicyEvidence {
            token_is_primary: true,
            token_type_bytes: size_of::<windows::Win32::Security::TOKEN_TYPE>(),
            session_id: NonZeroU32::new(7),
            session_bytes: size_of::<u32>(),
            session_matches: true,
            is_appcontainer: ExactTokenDword {
                value: 1,
                returned_bytes: size_of::<u32>(),
            },
            is_lpac: ExactTokenDword {
                value: 1,
                returned_bytes: size_of::<u32>(),
            },
            appcontainer_sid_bytes: size_of::<
                windows::Win32::Security::TOKEN_APPCONTAINER_INFORMATION,
            >(),
            appcontainer_sid: AppContainerSidEvidence::Exact,
            capability_bytes: size_of::<u32>(),
            capability_count: CAPABILITY_COUNT,
            membership: AppContainerMembershipEvidence::Lpac,
        }
    }

    fn encode_base(system_root: &str, windir: &str) -> Vec<u16> {
        let mut environment: Vec<u16> =
            format!("SystemRoot={system_root}").encode_utf16().collect();
        environment.push(0);
        environment.extend(format!("WINDIR={windir}").encode_utf16());
        environment.extend([0, 0]);
        environment
    }

    #[test]
    fn create_success_is_fully_bookended_and_releases_each_sid_once() {
        let setup = FakeSetup::new(None, FakeCreate::Created(7), 7, true);
        let observed = observe_profile_under_guard(
            &setup.guard,
            &setup.ops,
            APPROVAL_PROFILE,
            ProfileObservation::CreateOrOpen,
        );
        assert!(observed.is_ok());
        assert_eq!(setup.control.observed_trace(), CREATED_TRACE);
        assert_eq!(drop_count(&setup.drops.borrow(), 7), 1);

        drop(observed);
        assert_eq!(drop_count(&setup.drops.borrow(), 7), 2);
    }

    #[test]
    fn already_existing_profile_skips_created_sid_equality() {
        let setup = FakeSetup::new(None, FakeCreate::AlreadyExists, 9, true);
        let observed = observe_profile_under_guard(
            &setup.guard,
            &setup.ops,
            APPROVAL_PROFILE,
            ProfileObservation::CreateOrOpen,
        );
        assert!(observed.is_ok());
        assert_eq!(setup.control.observed_trace(), ALREADY_EXISTS_TRACE);
        assert!(setup.drops.borrow().is_empty());

        drop(observed);
        assert_eq!(setup.drops.borrow().as_slice(), &[9]);
    }

    #[test]
    fn created_and_derived_sid_mismatch_fails_and_frees_both_once() {
        let setup = FakeSetup::new(None, FakeCreate::Created(3), 4, true);
        let observed = observe_profile_under_guard(
            &setup.guard,
            &setup.ops,
            APPROVAL_PROFILE,
            ProfileObservation::CreateOrOpen,
        );
        assert!(matches!(observed, Err(TargetUserLpacError::Verification)));
        assert_eq!(setup.control.observed_trace(), CREATED_TRACE[..9]);
        let drops = setup.drops.borrow();
        assert_eq!(drop_count(&drops, 3), 1);
        assert_eq!(drop_count(&drops, 4), 1);
        assert_eq!(drops.len(), 2);
    }

    #[test]
    fn every_observation_failure_has_the_exact_completed_bookend_prefix() {
        const CALL_EVENTS: [usize; 5] = [1, 4, 7, 10, 13];

        for fail_at in 0..CREATED_TRACE.len() {
            let setup = FakeSetup::new(Some(fail_at), FakeCreate::Created(11), 11, true);
            let observed = observe_profile_under_guard(
                &setup.guard,
                &setup.ops,
                APPROVAL_PROFILE,
                ProfileObservation::CreateOrOpen,
            );
            assert!(observed.is_err(), "failure event {fail_at} was accepted");

            let trace_end = if CALL_EVENTS.contains(&fail_at) {
                fail_at + 2
            } else {
                fail_at + 1
            };
            assert_eq!(
                setup.control.observed_trace(),
                CREATED_TRACE[..trace_end],
                "wrong completed prefix for event {fail_at}"
            );

            let drops = setup.drops.borrow();
            let expected_created = usize::from(fail_at >= 2);
            let expected_derived = usize::from(fail_at >= 5);
            assert_eq!(
                drop_count(&drops, 11),
                expected_created + expected_derived,
                "wrong SID release count for event {fail_at}"
            );
            assert_eq!(drops.len(), expected_created + expected_derived);
        }
    }

    #[test]
    fn filesystem_rejection_occurs_after_its_complete_bookend() {
        let setup = FakeSetup::new(None, FakeCreate::AlreadyExists, 12, false);
        let observed = observe_profile_under_guard(
            &setup.guard,
            &setup.ops,
            APPROVAL_PROFILE,
            ProfileObservation::CreateOrOpen,
        );
        assert!(matches!(observed, Err(TargetUserLpacError::Verification)));
        assert_eq!(setup.control.observed_trace(), ALREADY_EXISTS_TRACE);
        assert_eq!(setup.drops.borrow().as_slice(), &[12]);
    }

    #[test]
    fn derive_only_fresh_observation_has_no_create_or_equality_call() {
        let setup = FakeSetup::new(None, FakeCreate::Created(13), 13, true);
        let observed = observe_profile_under_guard(
            &setup.guard,
            &setup.ops,
            SECRET_INPUT_PROFILE,
            ProfileObservation::DeriveOnly,
        );
        assert!(observed.is_ok());
        assert_eq!(setup.control.observed_trace(), DERIVE_ONLY_TRACE);
        assert!(setup.drops.borrow().is_empty());

        drop(observed);
        assert_eq!(setup.drops.borrow().as_slice(), &[13]);
    }

    #[test]
    fn fresh_revalidation_rejects_wrong_sid_folder_and_environment()
    -> Result<(), TargetUserLpacError> {
        let base = encode_base(r"C:\Windows", r"C:\Windows");
        let folder = approval_folder();
        let retained_environment =
            environment_for_folder(&folder, APPROVAL_PROFILE_V1_NAME, &base)?;

        let setup = FakeSetup::new(None, FakeCreate::AlreadyExists, 1, true);
        let retained_sid = FakeSid::new(1, &setup.drops);
        let wrong_sid = ObservedProfile {
            sid: FakeSid::new(2, &setup.drops),
            folder: folder.clone(),
        };
        assert_eq!(
            verify_fresh_observation(
                &setup.ops,
                &retained_sid,
                &folder,
                &retained_environment,
                APPROVAL_PROFILE,
                &base,
                &wrong_sid,
            ),
            Err(TargetUserLpacError::Verification)
        );

        let wrong_folder = ObservedProfile {
            sid: FakeSid::new(1, &setup.drops),
            folder: PathBuf::from(
                r"C:\ProfileRoot\AppData\Local\Packages\YourWallet.SecretInputFrontend.LPAC.v1\AC",
            ),
        };
        assert_eq!(
            verify_fresh_observation(
                &setup.ops,
                &retained_sid,
                &folder,
                &retained_environment,
                APPROVAL_PROFILE,
                &base,
                &wrong_folder,
            ),
            Err(TargetUserLpacError::Verification)
        );

        let matching = ObservedProfile {
            sid: FakeSid::new(1, &setup.drops),
            folder: folder.clone(),
        };
        let mut wrong_environment = retained_environment.to_vec();
        if let Some(first) = wrong_environment.first_mut() {
            *first ^= 1;
        }
        assert_eq!(
            verify_fresh_observation(
                &setup.ops,
                &retained_sid,
                &folder,
                &wrong_environment,
                APPROVAL_PROFILE,
                &base,
                &matching,
            ),
            Err(TargetUserLpacError::Verification)
        );
        assert_eq!(
            verify_fresh_observation(
                &setup.ops,
                &retained_sid,
                &folder,
                &retained_environment,
                APPROVAL_PROFILE,
                &base,
                &matching,
            ),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn stable_attribute_backing_is_exact_zero_capability_aap_opt_out() {
        let mut sid_storage = [0_u8; 1];
        let mut other_sid_storage = [0_u8; 1];
        let sid = PSID(sid_storage.as_mut_ptr().cast::<c_void>());
        let other_sid = PSID(other_sid_storage.as_mut_ptr().cast::<c_void>());
        let exact = SECURITY_CAPABILITIES {
            AppContainerSid: sid,
            Capabilities: core::ptr::null_mut(),
            CapabilityCount: CAPABILITY_COUNT,
            Reserved: 0,
        };
        assert!(stable_attribute_backing_is_exact(
            &exact,
            super::sys::all_application_packages_opt_out(),
            sid,
        ));

        let wrong_sid = SECURITY_CAPABILITIES {
            AppContainerSid: other_sid,
            ..exact
        };
        let nonzero_capability_count = SECURITY_CAPABILITIES {
            CapabilityCount: 1,
            ..exact
        };
        let nonnull_capabilities = SECURITY_CAPABILITIES {
            Capabilities: core::ptr::dangling_mut(),
            ..exact
        };
        let nonzero_reserved = SECURITY_CAPABILITIES {
            Reserved: 1,
            ..exact
        };
        for mutation in [
            wrong_sid,
            nonzero_capability_count,
            nonnull_capabilities,
            nonzero_reserved,
        ] {
            assert!(!stable_attribute_backing_is_exact(
                &mutation,
                super::sys::all_application_packages_opt_out(),
                sid,
            ));
        }
        assert!(!stable_attribute_backing_is_exact(
            &exact,
            super::sys::all_application_packages_opt_out() ^ 1,
            sid,
        ));
    }

    #[test]
    fn created_child_verification_observes_full_policy_twice_and_owns_exact_evidence()
    -> Result<(), TargetUserLpacError> {
        let ops = FakeChildOps::new(None);
        let owners = verify_created_child_with(&ops)?;
        assert_eq!(ops.trace(), VERIFY_CHILD_TRACE);
        assert_eq!(ops.drops.borrow().as_slice(), &[11]);

        drop(owners);
        assert_eq!(ops.drops.borrow().as_slice(), &[11, 10, 2, 1]);
        Ok(())
    }

    #[test]
    fn every_created_child_failure_stops_at_the_exact_prefix_and_drops_each_owner_once() {
        for fail_at in 0..VERIFY_CHILD_TRACE.len() {
            let ops = FakeChildOps::new(Some(fail_at));
            let result = verify_created_child_with(&ops);
            assert!(result.is_err(), "failure event {fail_at} was accepted");
            assert_eq!(
                ops.trace(),
                VERIFY_CHILD_TRACE[..=fail_at],
                "wrong prefix for failure event {fail_at}"
            );

            let drops = ops.drops.borrow();
            for id in [1_u8, 2, 10, 11] {
                assert!(
                    drop_count(&drops, id) <= 1,
                    "owner {id} was released more than once at event {fail_at}"
                );
            }
            assert_eq!(drop_count(&drops, 1), usize::from(fail_at >= 1));
            assert_eq!(drop_count(&drops, 2), usize::from(fail_at >= 2));
            assert_eq!(drop_count(&drops, 10), usize::from(fail_at >= 6));
            assert_eq!(drop_count(&drops, 11), usize::from(fail_at >= 13));
        }
    }

    #[test]
    fn exact_child_token_policy_rejects_every_scalar_and_membership_mutation() {
        let exact = valid_child_evidence();
        assert_eq!(validate_created_child_token_policy(&exact), Ok(()));

        let mut mutations = Vec::new();
        let mut value = exact;
        value.token_is_primary = false;
        mutations.push(value);
        let mut value = exact;
        value.token_type_bytes = 0;
        mutations.push(value);
        let mut value = exact;
        value.session_id = None;
        mutations.push(value);
        let mut value = exact;
        value.session_bytes = 0;
        mutations.push(value);
        let mut value = exact;
        value.session_matches = false;
        mutations.push(value);
        let mut value = exact;
        value.is_appcontainer.value = 0;
        mutations.push(value);
        let mut value = exact;
        value.is_appcontainer.returned_bytes = 0;
        mutations.push(value);
        let mut value = exact;
        value.is_lpac.value = 0;
        mutations.push(value);
        let mut value = exact;
        value.is_lpac.returned_bytes = 0;
        mutations.push(value);
        let mut value = exact;
        value.appcontainer_sid_bytes = 0;
        mutations.push(value);
        let mut value = exact;
        value.appcontainer_sid = AppContainerSidEvidence::Invalid;
        mutations.push(value);
        let mut value = exact;
        value.appcontainer_sid = AppContainerSidEvidence::Mismatch;
        mutations.push(value);
        let mut value = exact;
        value.capability_bytes = 0;
        mutations.push(value);
        let mut value = exact;
        value.capability_count = 1;
        mutations.push(value);
        for membership in [
            AppContainerMembershipEvidence::RegularAppContainer,
            AppContainerMembershipEvidence::Neither,
            AppContainerMembershipEvidence::Inverted,
        ] {
            let mut value = exact;
            value.membership = membership;
            mutations.push(value);
        }

        for mutation in mutations {
            assert_eq!(
                validate_created_child_token_policy(&mutation),
                Err(TargetUserLpacError::Verification)
            );
        }
    }

    #[test]
    fn created_child_revalidation_rechecks_policy_twice_and_rejects_substitution()
    -> Result<(), TargetUserLpacError> {
        let ops = FakeChildOps::new(None);
        let owners = verify_created_child_with(&ops)?;
        ops.control.reset_trace();
        revalidate_created_child_with(
            &ops,
            &owners.process_query,
            &owners.token,
            &owners.expected,
        )?;
        assert_eq!(ops.trace(), REVALIDATE_CHILD_TRACE);

        ops.control.reset_trace();
        ops.token_continuity.set(false);
        assert_eq!(
            revalidate_created_child_with(
                &ops,
                &owners.process_query,
                &owners.token,
                &owners.expected,
            ),
            Err(TargetUserLpacError::Verification)
        );
        assert_eq!(ops.trace(), REVALIDATE_CHILD_TRACE[..13]);
        Ok(())
    }

    #[test]
    fn every_created_child_revalidation_failure_stops_at_the_exact_prefix() {
        for fail_at in 0..REVALIDATE_CHILD_TRACE.len() {
            let ops = FakeChildOps::new(Some(fail_at));
            ops.next_token.set(11);
            let process = ops.owner(2);
            let retained = ops.owner(10);
            let expected = ops.owner(1);
            let result = revalidate_created_child_with(&ops, &process, &retained, &expected);
            assert!(result.is_err(), "failure event {fail_at} was accepted");
            assert_eq!(
                ops.trace(),
                REVALIDATE_CHILD_TRACE[..=fail_at],
                "wrong revalidation prefix for event {fail_at}"
            );

            drop((retained, process, expected));
            let drops = ops.drops.borrow();
            for id in [1_u8, 2, 10, 11] {
                assert!(
                    drop_count(&drops, id) <= 1,
                    "owner {id} was released more than once at event {fail_at}"
                );
            }
            assert_eq!(drop_count(&drops, 1), 1);
            assert_eq!(drop_count(&drops, 2), 1);
            assert_eq!(drop_count(&drops, 10), 1);
            assert_eq!(drop_count(&drops, 11), usize::from(fail_at >= 11));
        }
    }

    #[test]
    fn created_child_revalidation_rejects_fresh_expected_profile_mutations()
    -> Result<(), TargetUserLpacError> {
        for mutation in [
            FakeExpectedState::WrongSid,
            FakeExpectedState::WrongFolder,
            FakeExpectedState::WrongEnvironment,
            FakeExpectedState::WrongRole,
            FakeExpectedState::WrongClient,
        ] {
            let ops = FakeChildOps::new(None);
            let owners = verify_created_child_with(&ops)?;
            ops.control.reset_trace();
            ops.expected_state.set(mutation);
            assert_eq!(
                revalidate_created_child_with(
                    &ops,
                    &owners.process_query,
                    &owners.token,
                    &owners.expected,
                ),
                Err(TargetUserLpacError::Verification),
                "fresh expected mutation {mutation:?} was accepted"
            );
            assert_eq!(ops.trace(), ["expected_is_current"]);
        }
        Ok(())
    }

    #[test]
    fn created_child_revalidation_rejects_every_desktop_identity_substitution()
    -> Result<(), TargetUserLpacError> {
        for mutation in [
            FakeChildIdentityState::WrongUserSid,
            FakeChildIdentityState::WrongLogonSid,
            FakeChildIdentityState::WrongAuthenticationId,
            FakeChildIdentityState::WrongSession,
            FakeChildIdentityState::WrongTokenShape,
        ] {
            let ops = FakeChildOps::new(None);
            let owners = verify_created_child_with(&ops)?;
            ops.control.reset_trace();
            ops.child_identity.set(mutation);
            assert_eq!(
                revalidate_created_child_with(
                    &ops,
                    &owners.process_query,
                    &owners.token,
                    &owners.expected,
                ),
                Err(TargetUserLpacError::Authentication),
                "desktop identity mutation {mutation:?} was accepted"
            );
            assert_eq!(ops.trace(), REVALIDATE_CHILD_TRACE[..6]);
        }
        Ok(())
    }

    #[test]
    fn created_child_revalidation_rejects_process_identity_liveness_and_policy_drift()
    -> Result<(), TargetUserLpacError> {
        let assert_rejected = |mutate: fn(&FakeChildOps),
                               expected_prefix: &[&'static str]|
         -> Result<(), TargetUserLpacError> {
            let ops = FakeChildOps::new(None);
            let owners = verify_created_child_with(&ops)?;
            ops.control.reset_trace();
            mutate(&ops);
            assert_eq!(
                revalidate_created_child_with(
                    &ops,
                    &owners.process_query,
                    &owners.token,
                    &owners.expected,
                ),
                Err(TargetUserLpacError::Verification)
            );
            assert_eq!(ops.trace(), expected_prefix);
            Ok(())
        };

        assert_rejected(
            |ops| ops.source_matches.set(false),
            &REVALIDATE_CHILD_TRACE[..2],
        )?;
        assert_rejected(
            |ops| ops.process_live.set(false),
            &REVALIDATE_CHILD_TRACE[..4],
        )?;
        assert_rejected(
            |ops| {
                let mut evidence = ops.evidence.get();
                evidence.session_matches = false;
                ops.evidence.set(evidence);
            },
            &REVALIDATE_CHILD_TRACE[..7],
        )?;
        Ok(())
    }

    #[test]
    fn bounded_sid_parser_rejects_short_wrong_revision_excess_and_truncation() {
        let mut one_subauthority = [0_u8; 12];
        one_subauthority[0] = 1;
        one_subauthority[1] = 1;
        assert_eq!(bounded_sid_length(&one_subauthority), Some(12));
        assert_eq!(bounded_sid_length(&one_subauthority[..7]), None);

        let mut wrong_revision = one_subauthority;
        wrong_revision[0] = 2;
        assert_eq!(bounded_sid_length(&wrong_revision), None);

        let mut excessive = one_subauthority;
        excessive[1] = 16;
        assert_eq!(bounded_sid_length(&excessive), None);

        let mut truncated = one_subauthority;
        truncated[1] = 2;
        assert_eq!(bounded_sid_length(&truncated), None);
    }

    #[test]
    fn verified_child_proof_is_opaque_move_only_thread_affine_and_owner_compatible() {
        fn owner_shape_compiles<'client>(
            target_process_owner: usize,
            prepared: PreparedTargetUserLpac<'client>,
            proof: VerifiedCreatedTargetLpac<'client>,
        ) {
            struct SuspendedOwner<'client> {
                target_process_owner: usize,
                prepared: PreparedTargetUserLpac<'client>,
                proof: VerifiedCreatedTargetLpac<'client>,
            }
            let owner = SuspendedOwner {
                target_process_owner,
                prepared,
                proof,
            };
            let SuspendedOwner {
                target_process_owner,
                prepared,
                proof,
            } = owner;
            drop((target_process_owner, prepared, proof));
        }

        fn assert_debug<T: core::fmt::Debug>() {}
        let _ = owner_shape_compiles;
        assert_debug::<VerifiedCreatedTargetLpac<'static>>();
        let _ = <VerifiedCreatedTargetLpac<'static> as AmbiguousIfSend<_>>::marker;
        let _ = <VerifiedCreatedTargetLpac<'static> as AmbiguousIfSync<_>>::marker;
        let _ = <VerifiedCreatedTargetLpac<'static> as AmbiguousIfClone<_>>::marker;
        let _ = <VerifiedCreatedTargetLpac<'static> as AmbiguousIfCopy<_>>::marker;
    }

    #[test]
    fn fixed_profiles_are_distinct_and_versioned() {
        assert_ne!(APPROVAL_PROFILE_V1_NAME, SECRET_INPUT_PROFILE_V1_NAME);
        assert!(APPROVAL_PROFILE_V1_NAME.ends_with(".LPAC.v1"));
        assert!(SECRET_INPUT_PROFILE_V1_NAME.ends_with(".LPAC.v1"));
    }

    #[test]
    fn rpc_endpoint_sid_derivation_is_bound_to_exact_fixed_profile_monikers()
    -> Result<(), TargetUserLpacError> {
        const APPROVAL_SID: &str = "S-1-15-2-1-2-3-4-5-6-7";
        const SECRET_INPUT_SID: &str = "S-1-15-2-8-9-10-11-12-13-14";
        let mut observed_names = Vec::new();
        let identities = derive_fixed_lpac_rpc_endpoint_profile_sids_with(|name| {
            observed_names.push(name);
            match name {
                APPROVAL_PROFILE_V1_NAME => Ok(APPROVAL_SID.to_owned()),
                SECRET_INPUT_PROFILE_V1_NAME => Ok(SECRET_INPUT_SID.to_owned()),
                _ => Err(TargetUserLpacError::Verification),
            }
        })?;

        assert_eq!(
            observed_names,
            [APPROVAL_PROFILE_V1_NAME, SECRET_INPUT_PROFILE_V1_NAME]
        );
        assert!(identities.as_ordered_pair() == [APPROVAL_SID, SECRET_INPUT_SID]);
        assert_eq!(
            format!("{identities:?}"),
            "FixedLpacRpcEndpointProfileSids([REDACTED])"
        );
        Ok(())
    }

    #[test]
    fn rpc_endpoint_sid_derivation_rejects_non_package_and_duplicate_sids() {
        const PACKAGE_SID: &str = "S-1-15-2-1-2-3-4-5-6-7";
        for malformed in [
            "",
            "S-1-5-18",
            "S-1-15-2-1",
            "S-1-15-2-01-2-3-4-5-6-7",
            "S-1-15-2-1-2-3-4-5-6-not-a-number",
        ] {
            assert!(matches!(
                derive_fixed_lpac_rpc_endpoint_profile_sids_with(|name| {
                    if name == APPROVAL_PROFILE_V1_NAME {
                        Ok(malformed.to_owned())
                    } else {
                        Ok("S-1-15-2-8-9-10-11-12-13-14".to_owned())
                    }
                }),
                Err(TargetUserLpacError::Verification)
            ));
        }

        assert!(matches!(
            derive_fixed_lpac_rpc_endpoint_profile_sids_with(|_| Ok(PACKAGE_SID.to_owned())),
            Err(TargetUserLpacError::Verification)
        ));
    }

    #[test]
    fn environment_is_exact_and_target_profile_bound() -> Result<(), TargetUserLpacError> {
        let base = encode_base(r"C:\Windows", r"C:\Windows");
        let folder = Path::new(
            r"C:\ProfileRoot\AppData\Local\Packages\YourWallet.ApprovalFrontend.LPAC.v1\AC",
        );
        let environment = environment_for_folder(folder, APPROVAL_PROFILE_V1_NAME, &base)?;
        assert!(environment.ends_with(&[0, 0]));
        assert_eq!(environment.iter().filter(|unit| **unit == 0).count(), 4);
        let first_entry = environment
            .split(|unit| *unit == 0)
            .next()
            .ok_or(TargetUserLpacError::Verification)?;
        let mut expected: Vec<u16> = "LOCALAPPDATA=".encode_utf16().collect();
        expected.extend(folder.as_os_str().encode_wide());
        assert_eq!(first_entry, expected.as_slice());
        assert_eq!(
            environment_for_folder(folder, SECRET_INPUT_PROFILE_V1_NAME, &base),
            Err(TargetUserLpacError::Verification)
        );
        Ok(())
    }

    #[test]
    fn environment_rejects_shape_and_base_mutations() {
        let base = encode_base(r"C:\Windows", r"C:\Windows");
        let wrong_leaf = Path::new(
            r"C:\ProfileRoot\AppData\Local\Packages\YourWallet.ApprovalFrontend.LPAC.v1\Temp",
        );
        assert_eq!(
            environment_for_folder(wrong_leaf, APPROVAL_PROFILE_V1_NAME, &base),
            Err(TargetUserLpacError::Verification)
        );

        let mut malformed_base = base.clone();
        malformed_base.pop();
        let valid_folder = Path::new(
            r"C:\ProfileRoot\AppData\Local\Packages\YourWallet.ApprovalFrontend.LPAC.v1\AC",
        );
        assert_eq!(
            environment_for_folder(valid_folder, APPROVAL_PROFILE_V1_NAME, &malformed_base),
            Err(TargetUserLpacError::Verification)
        );
        assert!(!base_environment_is_exact(&malformed_base));
    }

    #[test]
    fn errors_are_data_free_in_debug() {
        assert_eq!(
            format!("{:?}", TargetUserLpacError::Authentication),
            "Authentication"
        );
        let _ = <PreparedTargetUserLpac<'static> as AmbiguousIfSend<_>>::marker;
        let _ = <PreparedTargetUserLpac<'static> as AmbiguousIfSync<_>>::marker;
        let _ = <PreparedTargetUserLpac<'static> as AmbiguousIfClone<_>>::marker;
        let _ = <PreparedTargetUserLpac<'static> as AmbiguousIfCopy<_>>::marker;
    }
}
