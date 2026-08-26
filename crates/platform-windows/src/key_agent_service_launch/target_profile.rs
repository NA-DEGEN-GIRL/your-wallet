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
use core::ptr;
use std::os::windows::ffi::OsStrExt as _;
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

const CAPABILITY_COUNT: u32 = 0;
const MAX_ENVIRONMENT_UNITS: usize = 32_767;
const APPROVAL_PROFILE_V1_NAME: &str = "YourWallet.ApprovalFrontend.LPAC.v1";
const APPROVAL_PROFILE_DISPLAY_NAME: &str = "Your Wallet approval frontend";
const APPROVAL_PROFILE_DESCRIPTION: &str =
    "Persistent no-network LPAC identity for Your Wallet approval prompts";
const SECRET_INPUT_PROFILE_V1_NAME: &str = "YourWallet.SecretInputFrontend.LPAC.v1";
const SECRET_INPUT_PROFILE_DISPLAY_NAME: &str = "Your Wallet secret input frontend";
const SECRET_INPUT_PROFILE_DESCRIPTION: &str =
    "Persistent no-network LPAC identity for Your Wallet secret input";

#[derive(Clone, Copy)]
struct ProfileMetadata {
    name: &'static str,
    display_name: &'static str,
    description: &'static str,
}

const APPROVAL_PROFILE: ProfileMetadata = ProfileMetadata {
    name: APPROVAL_PROFILE_V1_NAME,
    display_name: APPROVAL_PROFILE_DISPLAY_NAME,
    description: APPROVAL_PROFILE_DESCRIPTION,
};

const SECRET_INPUT_PROFILE: ProfileMetadata = ProfileMetadata {
    name: SECRET_INPUT_PROFILE_V1_NAME,
    display_name: SECRET_INPUT_PROFILE_DISPLAY_NAME,
    description: SECRET_INPUT_PROFILE_DESCRIPTION,
};

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
    use core::mem::size_of;
    use core::ptr;
    use std::path::PathBuf;

    use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::Isolation::{
        CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
        GetAppContainerFolderPath,
    };
    use windows::Win32::Security::{EqualSid, FreeSid, IsValidSid, PSID, SECURITY_CAPABILITIES};
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::System::Threading::{
        LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, UpdateProcThreadAttribute,
    };
    use windows::Win32::System::WindowsProgramming::PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
    use windows::core::{PCWSTR, PWSTR};

    use super::{OwnedAppContainerSid, TargetUserLpacError};

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

    fn sid_string(sid: PSID) -> Result<Vec<u16>, TargetUserLpacError> {
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
            unsafe {
                let _ = FreeSid(sid);
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
                unsafe {
                    let _ = LocalFree(Some(HLOCAL(self.0.0.cast::<c_void>())));
                }
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
    use std::cell::RefCell;
    use std::os::windows::ffi::OsStrExt as _;
    use std::path::{Path, PathBuf};
    use std::rc::Rc;

    use windows::Win32::Security::{PSID, SECURITY_CAPABILITIES};

    use super::{
        APPROVAL_PROFILE, APPROVAL_PROFILE_V1_NAME, CAPABILITY_COUNT, CreateProfileOutcome,
        ObservedProfile, PreparedTargetUserLpac, ProfileMetadata, ProfileObservation,
        ProfileObservationGuard, ProfileObservationOps, SECRET_INPUT_PROFILE,
        SECRET_INPUT_PROFILE_V1_NAME, TargetUserLpacError, base_environment_is_exact,
        environment_for_folder, observe_profile_under_guard, stable_attribute_backing_is_exact,
        verify_fresh_observation,
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
    fn fixed_profiles_are_distinct_and_versioned() {
        assert_ne!(APPROVAL_PROFILE_V1_NAME, SECRET_INPUT_PROFILE_V1_NAME);
        assert!(APPROVAL_PROFILE_V1_NAME.ends_with(".LPAC.v1"));
        assert!(SECRET_INPUT_PROFILE_V1_NAME.ends_with(".LPAC.v1"));
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
