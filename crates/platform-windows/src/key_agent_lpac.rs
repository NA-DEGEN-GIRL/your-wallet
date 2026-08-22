//! Fixed, zero-capability LPAC policy for the dormant Key Agent.
//!
//! The profile identity is compiled into this private module. Callers can
//! neither select an `AppContainer` name nor obtain its SID. A prepared value
//! owns every pointer installed into a process-creation attribute list and is
//! consumed only after the suspended child token has been checked.

#![allow(unsafe_code)]

use core::ffi::c_void;
use core::fmt;
use core::mem::size_of;
use core::ptr;
use std::cell::Cell;
use std::marker::PhantomData;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{AsRawHandle as _, BorrowedHandle};
use std::path::PathBuf;
use std::rc::Rc;
#[cfg(test)]
use std::{
    fs::{File, OpenOptions},
    io,
    path::Path,
};

#[cfg(test)]
use windows::Win32::Foundation::ERROR_ALREADY_EXISTS;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_INVALID_PARAMETER, HANDLE, INVALID_HANDLE_VALUE,
};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
#[cfg(test)]
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::Isolation::GetAppContainerFolderPath;
use windows::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows::Win32::Security::{
    CheckTokenMembershipEx, DuplicateToken, EqualSid, FreeSid, GetLengthSid, GetTokenInformation,
    IsValidSid, PSID, SECURITY_CAPABILITIES, SecurityIdentification,
    TOKEN_APPCONTAINER_INFORMATION, TOKEN_DUPLICATE, TOKEN_QUERY, TOKEN_USER, TokenAppContainerSid,
    TokenCapabilities, TokenIsAppContainer, TokenIsLessPrivilegedAppContainer, TokenUser,
};
#[cfg(test)]
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, IsValidSecurityDescriptor, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, SetFileSecurityW,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::SystemServices::{CTMF_INCLUDE_APPCONTAINER, CTMF_INCLUDE_LPAC};
#[cfg(test)]
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::Win32::System::Threading::{
    LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcessToken,
    PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, UpdateProcThreadAttribute,
};
use windows::Win32::System::WindowsProgramming::PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
use windows::core::{BOOL, PCWSTR};
use windows::{
    Win32::Foundation::{HLOCAL, LocalFree},
    core::PWSTR,
};

use crate::appcontainer_profile_api::{
    AppContainerProfileApiGuard, acquire_appcontainer_profile_api,
};
use crate::key_agent_install_adoption::ExistingInstallAdoptionSeal;
#[cfg(test)]
use crate::key_agent_storage::create_unique_key_agent_storage_root_for_test;
use crate::key_agent_storage::{
    HeldKeyAgentStorageRoot, KeyAgentHeldRootObservation, KeyAgentStorageRootIdentity,
    create_fixed_key_agent_storage_root,
};

pub(crate) const KEY_AGENT_PROFILE_V1_NAME: &str = "YourWallet.KeyAgent.LPAC.v1";
const KEY_AGENT_PROFILE_DISPLAY_NAME: &str = "Your Wallet Key Agent";
const KEY_AGENT_PROFILE_DESCRIPTION: &str =
    "Persistent zero-capability LPAC identity for Your Wallet Key Agent";
const CAPABILITY_COUNT: u32 = 0;
const MAX_TOKEN_INFORMATION_BYTES: usize = 64 * 1024;
const MAX_INSTALL_SID_BYTES: usize = 68;
/// Stable, non-diagnostic failures from the private Key Agent LPAC boundary.
#[derive(Eq, PartialEq)]
pub(crate) enum KeyAgentLpacError {
    /// The fixed profile could not be created, derived, or validated.
    Profile,
    /// The exact process-creation attributes could not be installed.
    Attribute,
    /// Fresh profile-bound storage provisioning or revalidation failed.
    Provisioning,
    /// The suspended child token did not match the fixed LPAC policy.
    Token,
}

impl fmt::Display for KeyAgentLpacError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Profile => "Key Agent LPAC profile policy failed",
            Self::Attribute => "Key Agent LPAC creation-attribute policy failed",
            Self::Provisioning => "Key Agent LPAC storage provisioning policy failed",
            Self::Token => "Key Agent LPAC token policy failed",
        })
    }
}

impl ::std::error::Error for KeyAgentLpacError {}

impl fmt::Debug for KeyAgentLpacError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyAgentLpacError([REDACTED])")
    }
}

/// Freshly created Key Agent objects that are not yet authorized for launch.
///
/// The trusted installer must durably commit and authoritatively reread an exact
/// provenance record before these objects may ever become a
/// [`PreparedKeyAgentProvisioning`]. There is deliberately no direct
/// Pending-to-Prepared production transition. Dropping this value does not
/// delete or repair either durable object; a later trusted recovery ceremony
/// must classify the partial state.
#[must_use = "fresh Key Agent objects require a durable provenance ceremony"]
pub(crate) struct PendingKeyAgentProvisioning {
    profile: PreparedKeyAgentProfile,
    storage_root: HeldKeyAgentStorageRoot,
}

impl PendingKeyAgentProvisioning {
    /// Creates the fixed profile and storage root but grants no launch authority.
    pub(crate) fn provision_fresh() -> Result<Self, KeyAgentLpacError> {
        let profile = PreparedKeyAgentProfile::provision_fresh()?;
        // SAFETY: the private profile owner retains this exact validated SID for
        // the complete call. The storage constructor copies it immediately.
        let storage_root = unsafe {
            create_fixed_key_agent_storage_root(
                &profile.appcontainer_local_data,
                profile.profile_sid.as_psid(),
            )
        }
        .map_err(|_| KeyAgentLpacError::Provisioning)?;
        Ok(Self {
            profile,
            storage_root,
        })
    }

    #[cfg(test)]
    fn prepare_for_kernel_test() -> Result<Self, KeyAgentLpacError> {
        let profile = PreparedKeyAgentProfile::open_or_create()?;
        // SAFETY: the test seam retains the exact SID owner while the storage
        // helper copies it and chooses a private CSPRNG-named empty leaf.
        let storage_root = unsafe {
            create_unique_key_agent_storage_root_for_test(
                &profile.appcontainer_local_data,
                profile.profile_sid.as_psid(),
            )
        }
        .map_err(|_| KeyAgentLpacError::Provisioning)?;
        Ok(Self {
            profile,
            storage_root,
        })
    }
}

impl fmt::Debug for PendingKeyAgentProvisioning {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.profile, &self.storage_root);
        formatter.write_str("PendingKeyAgentProvisioning([NON-LAUNCHABLE FRESH OBJECTS; REDACTED])")
    }
}

/// Fixed-profile binding and held storage-root object awaiting adoption.
///
/// This type has no production constructor. In particular, merely deriving the
/// deterministic profile SID or finding its folder is not authoritative proof
/// that the per-user profile is registered. A future installer-owned observer
/// must provide that proof, open the fixed root without repair, and retain the
/// same no-delete-share handle before constructing this aggregate.
#[must_use = "held existing Key Agent objects require authenticated adoption"]
pub(crate) struct HeldExistingKeyAgentInstallObjects {
    profile: PreparedKeyAgentProfile,
    storage_root: HeldKeyAgentStorageRoot,
}

impl HeldExistingKeyAgentInstallObjects {
    /// Creates real held objects only under the bounded kernel-test seam.
    #[cfg(test)]
    pub(crate) fn for_kernel_test() -> Result<Self, KeyAgentLpacError> {
        let PendingKeyAgentProvisioning {
            profile,
            storage_root,
        } = PendingKeyAgentProvisioning::prepare_for_kernel_test()?;
        let held = Self {
            profile,
            storage_root,
        };
        held.revalidate()?;
        Ok(held)
    }

    /// Revalidates both the deterministic fixed-profile binding and the exact
    /// retained storage-root object without reopening either authority.
    pub(crate) fn revalidate(&self) -> Result<(), KeyAgentLpacError> {
        self.profile.revalidate()?;
        self.storage_root
            .revalidate()
            .map_err(|_| KeyAgentLpacError::Provisioning)
    }

    /// Copies only path-free, handle-free evidence for provenance matching.
    pub(crate) fn install_observation(
        &self,
    ) -> Result<KeyAgentHeldInstallObservation, KeyAgentLpacError> {
        let (profile_sid_len, profile_sid) = self.profile.profile_sid.canonical_bytes()?;
        let root = self
            .storage_root
            .install_observation()
            .map_err(|_| KeyAgentLpacError::Provisioning)?;
        Ok(KeyAgentHeldInstallObservation {
            profile_sid_len,
            profile_sid,
            root,
        })
    }

    /// Converts the held objects only after the adoption module supplies its
    /// unforgeable seal. No other module can mint that seal.
    pub(crate) fn into_prepared(
        self,
        _seal: ExistingInstallAdoptionSeal,
    ) -> PreparedKeyAgentProvisioning {
        PreparedKeyAgentProvisioning {
            profile: self.profile,
            storage_root: self.storage_root,
        }
    }
}

impl fmt::Debug for HeldExistingKeyAgentInstallObjects {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "HeldExistingKeyAgentInstallObjects([PROFILE BINDING AND HELD ROOT; REDACTED])",
        )
    }
}

/// Authority-free profile and root evidence copied from held OS objects.
pub(crate) struct KeyAgentHeldInstallObservation {
    profile_sid_len: u8,
    profile_sid: [u8; MAX_INSTALL_SID_BYTES],
    root: KeyAgentHeldRootObservation,
}

impl KeyAgentHeldInstallObservation {
    pub(crate) fn profile_sid(&self) -> &[u8] {
        &self.profile_sid[..usize::from(self.profile_sid_len)]
    }

    pub(crate) fn stable_user_sid(&self) -> &[u8] {
        self.root.stable_user_sid()
    }

    pub(crate) fn storage_profile_sid(&self) -> &[u8] {
        self.root.profile_sid()
    }

    pub(crate) const fn storage_root_identity(&self) -> KeyAgentStorageRootIdentity {
        self.root.root_identity()
    }
}

impl fmt::Debug for KeyAgentHeldInstallObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyAgentHeldInstallObservation([REDACTED IDENTITIES])")
    }
}

/// Supervisor-held proof of an independently verified Key Agent installation.
///
/// There is no reachable or unsealed production constructor. The sole compiled
/// existing-install mint is the private dormant adoption transition, which
/// authenticates matching committed snapshots and bookends the exact held root
/// and profile binding with revalidation. Its test-only input constructors do
/// not make production adoption reachable.
#[must_use = "the Key Agent provisioning proof must remain bound to its activation"]
pub(crate) struct PreparedKeyAgentProvisioning {
    profile: PreparedKeyAgentProfile,
    storage_root: HeldKeyAgentStorageRoot,
}

impl PreparedKeyAgentProvisioning {
    /// Reuses the fixed persistent profile only for bounded kernel tests and
    /// creates a CSPRNG-named empty root that is removed non-recursively on drop.
    #[cfg(test)]
    pub(crate) fn prepare_for_kernel_test() -> Result<Self, KeyAgentLpacError> {
        let profile = PreparedKeyAgentProfile::open_or_create()?;
        // SAFETY: identical to the production ownership argument; the test seam
        // chooses the leaf internally and retains no borrowed pointer.
        let storage_root = unsafe {
            create_unique_key_agent_storage_root_for_test(
                &profile.appcontainer_local_data,
                profile.profile_sid.as_psid(),
            )
        }
        .map_err(|_| KeyAgentLpacError::Provisioning)?;
        Ok(Self {
            profile,
            storage_root,
        })
    }

    pub(crate) fn revalidate(&self) -> Result<(), KeyAgentLpacError> {
        self.profile.revalidate()?;
        self.storage_root
            .revalidate()
            .map_err(|_| KeyAgentLpacError::Provisioning)
    }

    pub(crate) fn prepare_lpac(&self) -> Result<PreparedKeyAgentLpac, KeyAgentLpacError> {
        self.profile.prepare_lpac()
    }

    pub(crate) fn storage_root_identity(&self) -> KeyAgentStorageRootIdentity {
        self.storage_root.identity()
    }

    #[cfg(test)]
    pub(crate) fn storage_root_path_for_test(&self) -> &Path {
        self.storage_root.path_for_test()
    }
}

impl fmt::Debug for PreparedKeyAgentProvisioning {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "PreparedKeyAgentProvisioning([VERIFIED PROFILE AND HELD STORAGE ROOT; REDACTED])",
        )
    }
}

/// Supervisor-owned preparation of the one fixed Key Agent profile identity.
///
/// Fresh provisioning can place this value only inside a non-launchable pending
/// aggregate. The existing-install path can retain it only inside the private
/// dormant held-object adoption boundary; production still has no authoritative
/// profile-registration observer. The value owns an aligned copy of the fixed
/// profile SID and the exact OS-reported local-data folder; neither is exposed
/// to callers.
#[must_use = "the prepared Key Agent profile must remain bound to its activation"]
struct PreparedKeyAgentProfile {
    profile_sid: OwnedAppContainerSid,
    appcontainer_local_data: PathBuf,
    _not_sync: PhantomData<Cell<()>>,
}

impl PreparedKeyAgentProfile {
    /// Creates the fixed profile and rejects an already-existing profile.
    ///
    /// This is intentionally not a normal startup operation. A future trusted
    /// installer/supervisor ceremony must call it once and preserve durable
    /// provenance before any later process may adopt the persistent profile.
    fn provision_fresh() -> Result<Self, KeyAgentLpacError> {
        let profile_sid = OwnedAppContainerSid::create_fresh()?;
        Self::from_profile_sid(profile_sid)
    }

    #[cfg(test)]
    fn open_or_create() -> Result<Self, KeyAgentLpacError> {
        let profile_sid = OwnedAppContainerSid::open_or_create()?;
        Self::from_profile_sid(profile_sid)
    }

    fn from_profile_sid(profile_sid: OwnedAppContainerSid) -> Result<Self, KeyAgentLpacError> {
        let appcontainer_local_data = validated_appcontainer_folder(&profile_sid)?;
        Ok(Self {
            profile_sid,
            appcontainer_local_data,
            _not_sync: PhantomData,
        })
    }

    fn revalidate(&self) -> Result<(), KeyAgentLpacError> {
        let derived = OwnedAppContainerSid::derive_fixed()?;
        require_created_sid_matches_derived(&self.profile_sid, &derived)?;
        let current_folder = validated_appcontainer_folder(&derived)?;
        if current_folder != self.appcontainer_local_data {
            return Err(KeyAgentLpacError::Profile);
        }
        Ok(())
    }

    fn prepare_lpac(&self) -> Result<PreparedKeyAgentLpac, KeyAgentLpacError> {
        PreparedKeyAgentLpac::from_profile(self)
    }
}

impl fmt::Debug for PreparedKeyAgentProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedKeyAgentProfile([FIXED PROFILE; REDACTED])")
    }
}

/// Opaque ownership of the fixed Key Agent profile SID and stable attribute
/// values required by one process-creation attempt.
///
/// This value is deliberately non-cloneable and thread-affine. Production can
/// derive it only from a held [`PreparedKeyAgentProvisioning`]; the zero-input
/// constructor below is compiled for tests only.
pub(crate) struct PreparedKeyAgentLpac {
    // Drop the pointer-bearing value record before freeing its target SID.
    values: Box<KeyAgentLpacAttributeValues>,
    profile_sid: OwnedAppContainerSid,
    appcontainer_local_data: PathBuf,
    _same_thread: PhantomData<Rc<()>>,
}

impl PreparedKeyAgentLpac {
    /// Test-only compatibility path that creates or opens the fixed profile
    /// before preparing its exact zero-capability LPAC attribute values.
    #[cfg(test)]
    pub(crate) fn prepare() -> Result<Self, KeyAgentLpacError> {
        PreparedKeyAgentProfile::open_or_create()?.prepare_lpac()
    }

    /// Extends the trusted two-name process context with the OS-derived user
    /// local-data base that Windows rebases to this exact `AppContainer`'s `AC`
    /// folder during process creation.
    pub(crate) fn environment_with_local_app_data(
        &self,
        base_environment: &[u16],
    ) -> Result<Box<[u16]>, KeyAgentLpacError> {
        let appcontainer_local_data = &self.appcontainer_local_data;
        let local_folder_name = appcontainer_local_data
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(KeyAgentLpacError::Profile)?;
        let profile_folder = appcontainer_local_data
            .parent()
            .ok_or(KeyAgentLpacError::Profile)?;
        let profile_name = profile_folder
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(KeyAgentLpacError::Profile)?;
        let packages = profile_folder.parent().ok_or(KeyAgentLpacError::Profile)?;
        let packages_name = packages
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(KeyAgentLpacError::Profile)?;
        let packages_parent = packages.parent().ok_or(KeyAgentLpacError::Profile)?;
        if !local_folder_name.eq_ignore_ascii_case("AC")
            || !profile_name.eq_ignore_ascii_case(KEY_AGENT_PROFILE_V1_NAME)
            || !packages_name.eq_ignore_ascii_case("Packages")
            || !appcontainer_local_data.is_absolute()
            || !packages_parent.is_absolute()
            || !base_environment_is_exact(base_environment)
        {
            return Err(KeyAgentLpacError::Profile);
        }
        let local_value: Vec<u16> = packages_parent.as_os_str().encode_wide().collect();
        if local_value.is_empty() || local_value.contains(&0) {
            return Err(KeyAgentLpacError::Profile);
        }
        let mut environment = Vec::with_capacity(
            "LOCALAPPDATA="
                .encode_utf16()
                .count()
                .checked_add(local_value.len())
                .and_then(|length| length.checked_add(base_environment.len() + 1))
                .ok_or(KeyAgentLpacError::Profile)?,
        );
        environment.extend("LOCALAPPDATA=".encode_utf16());
        environment.extend_from_slice(&local_value);
        environment.push(0);
        environment.extend_from_slice(base_environment);
        if environment.len() > 32_767 || !environment.ends_with(&[0, 0]) {
            return Err(KeyAgentLpacError::Profile);
        }
        Ok(environment.into_boxed_slice())
    }

    fn from_profile(profile: &PreparedKeyAgentProfile) -> Result<Self, KeyAgentLpacError> {
        let profile_sid = profile.profile_sid.duplicate()?;
        let values = Box::new(KeyAgentLpacAttributeValues {
            security_capabilities: SECURITY_CAPABILITIES {
                AppContainerSid: profile_sid.as_psid(),
                Capabilities: ptr::null_mut(),
                CapabilityCount: CAPABILITY_COUNT,
                Reserved: 0,
            },
            all_application_packages_policy: PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT,
        });
        Ok(Self {
            values,
            profile_sid,
            appcontainer_local_data: profile.appcontainer_local_data.clone(),
            _same_thread: PhantomData,
        })
    }

    /// Installs exactly `SECURITY_CAPABILITIES` and the LPAC
    /// `ALL_APPLICATION_PACKAGES` opt-out into a caller-owned attribute list.
    ///
    /// # Safety
    ///
    /// `attribute_list` must be a live initialized list with two unused slots.
    /// The caller must retain `self` until it deletes that list with
    /// `DeleteProcThreadAttributeList`, including every partial-failure path.
    pub(crate) unsafe fn install_into(
        &self,
        attribute_list: LPPROC_THREAD_ATTRIBUTE_LIST,
    ) -> Result<(), KeyAgentLpacError> {
        // SAFETY: the caller establishes the native list lifetime. Both values
        // are heap-stable and borrow the still-owned profile SID.
        unsafe {
            update_attribute(
                attribute_list,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                ptr::from_ref(&self.values.security_capabilities).cast::<c_void>(),
                size_of::<SECURITY_CAPABILITIES>(),
            )?;
            update_attribute(
                attribute_list,
                PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                ptr::from_ref(&self.values.all_application_packages_policy).cast::<c_void>(),
                size_of::<u32>(),
            )
        }
    }

    /// Consumes this prepared identity after proving that the exact suspended
    /// process has the expected zero-capability LPAC token.
    pub(crate) fn verify_suspended_process(
        self,
        process: BorrowedHandle<'_>,
    ) -> Result<VerifiedKeyAgentLpac, KeyAgentLpacError> {
        verify_process_token(process, self.profile_sid.as_psid())?;
        Ok(VerifiedKeyAgentLpac { _private: () })
    }
}

impl fmt::Debug for PreparedKeyAgentLpac {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedKeyAgentLpac([OPAQUE KEY AGENT LPAC])")
    }
}

/// Opaque proof that one suspended process passed the exact Key Agent LPAC
/// token checks. It carries no profile selector, SID, or process handle.
pub(crate) struct VerifiedKeyAgentLpac {
    _private: (),
}

impl fmt::Debug for VerifiedKeyAgentLpac {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedKeyAgentLpac([VERIFIED])")
    }
}

/// Test-owned executable copy placed beneath the fixed profile's OS-managed
/// `AppContainer` folder.
///
/// This is only launchability scaffolding for kernel tests. It does not claim
/// production install-root, signed-artifact, or Key Agent storage ACL evidence.
#[cfg(test)]
pub(crate) struct KeyAgentLpacKernelTestFixture {
    directory: PathBuf,
    executable: PathBuf,
}

#[cfg(test)]
impl KeyAgentLpacKernelTestFixture {
    /// Copies the current test image to one CSPRNG-named profile-private path.
    pub(crate) fn create() -> Result<Self, KeyAgentLpacError> {
        let profile_sid = OwnedAppContainerSid::open_or_create()?;
        let profile_folder = appcontainer_folder(&profile_sid)?;
        if !profile_folder.is_absolute() || !profile_folder.is_dir() {
            return Err(KeyAgentLpacError::Profile);
        }

        let directory = create_unique_fixture_directory(&profile_folder)?;
        let executable = directory.join("key-agent-kernel-test.exe");
        let result = apply_exact_fixture_dacl(&directory, profile_sid.as_psid())
            .and_then(|()| copy_current_test_image(&executable))
            .and_then(|()| apply_exact_fixture_dacl(&executable, profile_sid.as_psid()));
        if let Err(error) = result {
            let _ = std::fs::remove_file(&executable);
            let _ = std::fs::remove_dir(&directory);
            return Err(error);
        }
        Ok(Self {
            directory,
            executable,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.executable
    }
}

#[cfg(test)]
impl Drop for KeyAgentLpacKernelTestFixture {
    fn drop(&mut self) {
        // The targets are exact CSPRNG-named children created by `create`; no
        // recursive or profile-wide cleanup is ever attempted.
        let _ = std::fs::remove_file(&self.executable);
        let _ = std::fs::remove_dir(&self.directory);
    }
}

#[cfg(test)]
impl fmt::Debug for KeyAgentLpacKernelTestFixture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyAgentLpacKernelTestFixture([REDACTED PATH])")
    }
}

struct KeyAgentLpacAttributeValues {
    security_capabilities: SECURITY_CAPABILITIES,
    all_application_packages_policy: u32,
}

struct OwnedAppContainerSid {
    words: Box<[usize]>,
    byte_len: usize,
}

impl OwnedAppContainerSid {
    fn create_fresh() -> Result<Self, KeyAgentLpacError> {
        let name = wide_nul_str(KEY_AGENT_PROFILE_V1_NAME)?;
        let display_name = wide_nul_str(KEY_AGENT_PROFILE_DISPLAY_NAME)?;
        let description = wide_nul_str(KEY_AGENT_PROFILE_DESCRIPTION)?;
        let profile_api =
            acquire_appcontainer_profile_api().map_err(|_| KeyAgentLpacError::Profile)?;

        // SAFETY: all strings are NUL terminated and there are deliberately no
        // capability SIDs. Only a newly-created profile may mint this proof;
        // ERROR_ALREADY_EXISTS and every other failure remain fail-closed.
        let created_sid = unsafe {
            CreateAppContainerProfile(
                PCWSTR(name.as_ptr()),
                PCWSTR(display_name.as_ptr()),
                PCWSTR(description.as_ptr()),
                None,
            )
        }
        .map_err(|_| KeyAgentLpacError::Profile)?;
        let created = Self::from_profile_api(created_sid)?;
        let derived = Self::derive_under_guard(&profile_api, &name)?;
        require_created_sid_matches_derived(&created, &derived)?;
        Ok(derived)
    }

    #[cfg(test)]
    fn open_or_create() -> Result<Self, KeyAgentLpacError> {
        let name = wide_nul_str(KEY_AGENT_PROFILE_V1_NAME)?;
        let display_name = wide_nul_str(KEY_AGENT_PROFILE_DISPLAY_NAME)?;
        let description = wide_nul_str(KEY_AGENT_PROFILE_DESCRIPTION)?;
        let profile_api =
            acquire_appcontainer_profile_api().map_err(|_| KeyAgentLpacError::Profile)?;

        // SAFETY: all strings are NUL terminated and there are deliberately no
        // capability SIDs. A successful returned SID belongs to the caller.
        let created = unsafe {
            CreateAppContainerProfile(
                PCWSTR(name.as_ptr()),
                PCWSTR(display_name.as_ptr()),
                PCWSTR(description.as_ptr()),
                None,
            )
        };
        match created {
            Ok(created_sid) => {
                let created = Self::from_profile_api(created_sid)?;
                let derived = Self::derive_under_guard(&profile_api, &name)?;
                require_created_sid_matches_derived(&created, &derived)?;
                Ok(derived)
            }
            Err(error) if error.code() == ERROR_ALREADY_EXISTS.to_hresult() => {
                Self::derive_under_guard(&profile_api, &name)
            }
            Err(_) => Err(KeyAgentLpacError::Profile),
        }
    }

    #[cfg(test)]
    fn derive(name: &[u16]) -> Result<Self, KeyAgentLpacError> {
        let profile_api =
            acquire_appcontainer_profile_api().map_err(|_| KeyAgentLpacError::Profile)?;
        Self::derive_under_guard(&profile_api, name)
    }

    fn derive_fixed() -> Result<Self, KeyAgentLpacError> {
        let name = wide_nul_str(KEY_AGENT_PROFILE_V1_NAME)?;
        let profile_api =
            acquire_appcontainer_profile_api().map_err(|_| KeyAgentLpacError::Profile)?;
        Self::derive_under_guard(&profile_api, &name)
    }

    fn derive_under_guard(
        _profile_api: &AppContainerProfileApiGuard,
        name: &[u16],
    ) -> Result<Self, KeyAgentLpacError> {
        // SAFETY: callers pass a live NUL-terminated profile name.
        let sid = unsafe { DeriveAppContainerSidFromAppContainerName(PCWSTR(name.as_ptr())) }
            .map_err(|_| KeyAgentLpacError::Profile)?;
        Self::from_profile_api(sid)
    }

    fn from_profile_api(sid: PSID) -> Result<Self, KeyAgentLpacError> {
        // SAFETY: the SID came from a successful AppContainer profile API.
        if sid.is_invalid() || !unsafe { IsValidSid(sid) }.as_bool() {
            if !sid.is_invalid() {
                // SAFETY: every non-null result from these profile APIs must be
                // released with FreeSid, including a malformed result.
                unsafe {
                    let _ = FreeSid(sid);
                }
            }
            return Err(KeyAgentLpacError::Profile);
        }
        let copied = Self::copy_from(sid);
        // SAFETY: every valid non-null result from an AppContainer profile API
        // is released exactly once after its bytes have been copied.
        unsafe {
            let _ = FreeSid(sid);
        }
        copied
    }

    fn copy_from(sid: PSID) -> Result<Self, KeyAgentLpacError> {
        // SAFETY: callers supply a valid live SID returned by a profile API or
        // retained in another owned aligned SID buffer.
        if sid.is_invalid() || !unsafe { IsValidSid(sid) }.as_bool() {
            return Err(KeyAgentLpacError::Profile);
        }
        // SAFETY: validation accepted the complete SID before its declared
        // length is queried.
        let byte_len = usize::try_from(unsafe { GetLengthSid(sid) })
            .map_err(|_| KeyAgentLpacError::Profile)?;
        if !(8..=256).contains(&byte_len) {
            return Err(KeyAgentLpacError::Profile);
        }
        let word_bytes = size_of::<usize>();
        let word_count = byte_len
            .checked_add(word_bytes - 1)
            .and_then(|rounded| rounded.checked_div(word_bytes))
            .ok_or(KeyAgentLpacError::Profile)?;
        let mut words = ::std::vec![0_usize; word_count].into_boxed_slice();
        // SAFETY: the source contains the validated SID's complete reported
        // byte length and the aligned destination allocation is at least that
        // large. The allocations do not overlap.
        unsafe {
            ptr::copy_nonoverlapping(
                sid.0.cast::<u8>(),
                words.as_mut_ptr().cast::<u8>(),
                byte_len,
            );
        }
        let owned = Self { words, byte_len };
        // SAFETY: the owned aligned buffer contains the exact copied SID bytes.
        if !unsafe { IsValidSid(owned.as_psid()) }.as_bool() {
            return Err(KeyAgentLpacError::Profile);
        }
        // SAFETY: IsValidSid just accepted the complete owned aligned buffer.
        let copied_byte_len = usize::try_from(unsafe { GetLengthSid(owned.as_psid()) })
            .map_err(|_| KeyAgentLpacError::Profile)?;
        if copied_byte_len != owned.byte_len {
            return Err(KeyAgentLpacError::Profile);
        }
        Ok(owned)
    }

    fn duplicate(&self) -> Result<Self, KeyAgentLpacError> {
        Self::copy_from(self.as_psid())
    }

    fn as_psid(&self) -> PSID {
        PSID(self.words.as_ptr().cast_mut().cast::<c_void>())
    }

    fn canonical_bytes(&self) -> Result<(u8, [u8; MAX_INSTALL_SID_BYTES]), KeyAgentLpacError> {
        let byte_len = u8::try_from(self.byte_len).map_err(|_| KeyAgentLpacError::Profile)?;
        if !(8..=MAX_INSTALL_SID_BYTES).contains(&self.byte_len) {
            return Err(KeyAgentLpacError::Profile);
        }
        let mut encoded = [0_u8; MAX_INSTALL_SID_BYTES];
        // SAFETY: construction validated the SID length against the owned,
        // aligned allocation. The immutable view cannot outlive `self`.
        let bytes =
            unsafe { core::slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.byte_len) };
        encoded[..self.byte_len].copy_from_slice(bytes);
        Ok((byte_len, encoded))
    }
}

impl Drop for OwnedAppContainerSid {
    fn drop(&mut self) {
        for word in &mut self.words {
            *word = 0;
        }
        self.byte_len = 0;
    }
}

impl fmt::Debug for OwnedAppContainerSid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OwnedAppContainerSid([SID])")
    }
}

fn require_created_sid_matches_derived(
    created: &OwnedAppContainerSid,
    derived: &OwnedAppContainerSid,
) -> Result<(), KeyAgentLpacError> {
    // SAFETY: both owners contain valid live profile SIDs.
    unsafe { EqualSid(created.as_psid(), derived.as_psid()) }
        .map_err(|_| KeyAgentLpacError::Profile)
}

struct OwnedToken(HANDLE);

impl OwnedToken {
    fn new(handle: HANDLE) -> Result<Self, KeyAgentLpacError> {
        if invalid_handle(handle) {
            return Err(KeyAgentLpacError::Token);
        }
        Ok(Self(handle))
    }
}

impl Drop for OwnedToken {
    fn drop(&mut self) {
        if !invalid_handle(self.0) {
            // SAFETY: this wrapper owns the successful OpenProcessToken result.
            unsafe {
                let _ = CloseHandle(self.0);
            }
            self.0 = HANDLE::default();
        }
    }
}

impl fmt::Debug for OwnedToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OwnedToken([HANDLE])")
    }
}

struct TokenDword {
    value: u32,
    returned_bytes: usize,
}

struct TokenInformation {
    words: Vec<usize>,
    returned_bytes: usize,
}

struct TokenPolicyEvidence {
    is_appcontainer: TokenDword,
    is_lpac: Option<TokenDword>,
    membership: AppContainerMembershipEvidence,
    appcontainer_sid_bytes: usize,
    appcontainer_sid_valid: bool,
    appcontainer_sid_matches: bool,
    capability_bytes: usize,
    capability_count: u32,
}

fn verify_process_token(
    process: BorrowedHandle<'_>,
    expected_sid: PSID,
) -> Result<(), KeyAgentLpacError> {
    let mut raw_token = HANDLE::default();
    // SAFETY: `process` is a live suspended-process borrow and the output
    // receives one exclusively owned token handle.
    unsafe {
        OpenProcessToken(
            HANDLE(process.as_raw_handle()),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &raw mut raw_token,
        )
    }
    .map_err(|_| KeyAgentLpacError::Token)?;
    let token = OwnedToken::new(raw_token)?;

    let is_appcontainer = token_dword(token.0, TokenIsAppContainer)?;
    let is_lpac = less_privileged_appcontainer_dword(token.0)?;

    let sid_information = token_information(token.0, TokenAppContainerSid)?;
    if sid_information.returned_bytes < size_of::<TOKEN_APPCONTAINER_INFORMATION>() {
        return Err(KeyAgentLpacError::Token);
    }
    // SAFETY: the aligned allocation contains at least the returned structure
    // prefix, and remains live while its interior SID pointer is inspected.
    let container = unsafe {
        ptr::read_unaligned(
            sid_information
                .words
                .as_ptr()
                .cast::<TOKEN_APPCONTAINER_INFORMATION>(),
        )
    };
    let appcontainer_sid_valid = !container.TokenAppContainer.is_invalid()
        // SAFETY: a successful token query returned this pointer inside the
        // still-live information buffer.
        && unsafe { IsValidSid(container.TokenAppContainer) }.as_bool();
    let appcontainer_sid_matches = appcontainer_sid_valid
        // SAFETY: the token SID and prepared expected SID are both valid and
        // remain live throughout the comparison.
        && unsafe { EqualSid(container.TokenAppContainer, expected_sid) }.is_ok();

    let capability_information = token_information(token.0, TokenCapabilities)?;
    if capability_information.returned_bytes < size_of::<u32>() {
        return Err(KeyAgentLpacError::Token);
    }
    // SAFETY: aligned word storage contains the returned leading GroupCount.
    let capability_count =
        unsafe { ptr::read_unaligned(capability_information.words.as_ptr().cast::<u32>()) };

    let membership = appcontainer_membership_evidence(token.0)?;

    let evidence = TokenPolicyEvidence {
        is_appcontainer,
        is_lpac,
        membership,
        appcontainer_sid_bytes: sid_information.returned_bytes,
        appcontainer_sid_valid,
        appcontainer_sid_matches,
        capability_bytes: capability_information.returned_bytes,
        capability_count,
    };
    validate_token_policy(&evidence)
}

fn token_dword(
    token: HANDLE,
    class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
) -> Result<TokenDword, KeyAgentLpacError> {
    let mut value = 0_u32;
    let mut returned = 0_u32;
    // SAFETY: the token is live and output points to exact DWORD storage.
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some(ptr::from_mut(&mut value).cast::<c_void>()),
            u32::try_from(size_of::<u32>()).map_err(|_| KeyAgentLpacError::Token)?,
            &raw mut returned,
        )
    }
    .map_err(|_| KeyAgentLpacError::Token)?;
    Ok(TokenDword {
        value,
        returned_bytes: usize::try_from(returned).map_err(|_| KeyAgentLpacError::Token)?,
    })
}

fn less_privileged_appcontainer_dword(
    token: HANDLE,
) -> Result<Option<TokenDword>, KeyAgentLpacError> {
    let mut value = 0_u32;
    let mut returned = 0_u32;
    // SAFETY: the token is live and output points to exact DWORD storage. Some
    // supported Windows builds reject this newer information class with
    // ERROR_INVALID_PARAMETER; only that specific result activates the
    // independent app-container-aware membership proof below.
    match unsafe {
        GetTokenInformation(
            token,
            TokenIsLessPrivilegedAppContainer,
            Some(ptr::from_mut(&mut value).cast::<c_void>()),
            u32::try_from(size_of::<u32>()).map_err(|_| KeyAgentLpacError::Token)?,
            &raw mut returned,
        )
    } {
        Ok(()) => Ok(Some(TokenDword {
            value,
            returned_bytes: usize::try_from(returned).map_err(|_| KeyAgentLpacError::Token)?,
        })),
        Err(error) if error.code() == ERROR_INVALID_PARAMETER.to_hresult() => Ok(None),
        Err(_) => Err(KeyAgentLpacError::Token),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AppContainerMembershipEvidence {
    Lpac,
    RegularAppContainer,
    Neither,
    Inverted,
}

fn appcontainer_membership_evidence(
    token: HANDLE,
) -> Result<AppContainerMembershipEvidence, KeyAgentLpacError> {
    let user_information = token_information(token, TokenUser)?;
    if user_information.returned_bytes < size_of::<TOKEN_USER>() {
        return Err(KeyAgentLpacError::Token);
    }
    // SAFETY: the aligned allocation contains at least the returned TOKEN_USER
    // prefix and remains live for both membership checks.
    let user = unsafe { ptr::read_unaligned(user_information.words.as_ptr().cast::<TOKEN_USER>()) };
    if user.User.Sid.is_invalid()
        // SAFETY: a successful token query populated the SID pointer in the
        // still-live information allocation.
        || !unsafe { IsValidSid(user.User.Sid) }.as_bool()
    {
        return Err(KeyAgentLpacError::Token);
    }

    let mut raw_impersonation_token = HANDLE::default();
    // SAFETY: the source token is live and has TOKEN_DUPLICATE; the output
    // receives one exclusively owned impersonation-token handle.
    unsafe {
        DuplicateToken(
            token,
            SecurityIdentification,
            &raw mut raw_impersonation_token,
        )
    }
    .map_err(|_| KeyAgentLpacError::Token)?;
    let impersonation_token = OwnedToken::new(raw_impersonation_token)?;

    let passes_appcontainer = check_token_membership(
        impersonation_token.0,
        user.User.Sid,
        CTMF_INCLUDE_APPCONTAINER,
    )?;
    let passes_lpac = check_token_membership(
        impersonation_token.0,
        user.User.Sid,
        CTMF_INCLUDE_APPCONTAINER | CTMF_INCLUDE_LPAC,
    )?;
    Ok(match (passes_appcontainer, passes_lpac) {
        (false, true) => AppContainerMembershipEvidence::Lpac,
        (true, true) => AppContainerMembershipEvidence::RegularAppContainer,
        (false, false) => AppContainerMembershipEvidence::Neither,
        (true, false) => AppContainerMembershipEvidence::Inverted,
    })
}

fn check_token_membership(
    impersonation_token: HANDLE,
    sid: PSID,
    flags: u32,
) -> Result<bool, KeyAgentLpacError> {
    let mut is_member = BOOL(0);
    // SAFETY: the duplicated token is an impersonation token, the token-user
    // SID is live and valid, and the output BOOL is writable. The fixed flags
    // ask Windows to perform its AppContainer-aware access-membership check.
    unsafe { CheckTokenMembershipEx(Some(impersonation_token), sid, flags, &raw mut is_member) }
        .map_err(|_| KeyAgentLpacError::Token)?;
    Ok(is_member.as_bool())
}

fn token_information(
    token: HANDLE,
    class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
) -> Result<TokenInformation, KeyAgentLpacError> {
    let mut required = 0_u32;
    // SAFETY: this is the documented sizing call; failure is expected and the
    // returned size is validated before allocation.
    let _ = unsafe { GetTokenInformation(token, class, None, 0, &raw mut required) };
    let required = usize::try_from(required).map_err(|_| KeyAgentLpacError::Token)?;
    if required == 0 || required > MAX_TOKEN_INFORMATION_BYTES {
        return Err(KeyAgentLpacError::Token);
    }
    let word_size = size_of::<usize>();
    let word_count = required
        .checked_add(word_size - 1)
        .and_then(|rounded| rounded.checked_div(word_size))
        .ok_or(KeyAgentLpacError::Token)?;
    let mut words = ::std::vec![0_usize; word_count];
    let mut returned = 0_u32;
    // SAFETY: aligned storage has at least `required` writable bytes.
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some(words.as_mut_ptr().cast::<c_void>()),
            u32::try_from(required).map_err(|_| KeyAgentLpacError::Token)?,
            &raw mut returned,
        )
    }
    .map_err(|_| KeyAgentLpacError::Token)?;
    let returned_bytes = usize::try_from(returned).map_err(|_| KeyAgentLpacError::Token)?;
    if returned_bytes == 0 || returned_bytes > required {
        return Err(KeyAgentLpacError::Token);
    }
    Ok(TokenInformation {
        words,
        returned_bytes,
    })
}

fn validate_token_policy(evidence: &TokenPolicyEvidence) -> Result<(), KeyAgentLpacError> {
    let queried_lpac_is_valid = match evidence.is_lpac.as_ref() {
        Some(is_lpac) => is_lpac.value == 1 && is_lpac.returned_bytes == size_of::<u32>(),
        None => true,
    };
    if evidence.is_appcontainer.value != 1
        || evidence.is_appcontainer.returned_bytes != size_of::<u32>()
        || !queried_lpac_is_valid
        || evidence.membership != AppContainerMembershipEvidence::Lpac
        || evidence.appcontainer_sid_bytes < size_of::<TOKEN_APPCONTAINER_INFORMATION>()
        || !evidence.appcontainer_sid_valid
        || !evidence.appcontainer_sid_matches
        || evidence.capability_bytes < size_of::<u32>()
        || evidence.capability_count != CAPABILITY_COUNT
    {
        return Err(KeyAgentLpacError::Token);
    }
    Ok(())
}

unsafe fn update_attribute(
    attribute_list: LPPROC_THREAD_ATTRIBUTE_LIST,
    attribute: u32,
    value: *const c_void,
    value_bytes: usize,
) -> Result<(), KeyAgentLpacError> {
    // SAFETY: the caller guarantees the initialized list and stable input-value
    // lifetimes required by UpdateProcThreadAttribute.
    unsafe {
        UpdateProcThreadAttribute(
            attribute_list,
            0,
            usize::try_from(attribute).map_err(|_| KeyAgentLpacError::Attribute)?,
            Some(value),
            value_bytes,
            None,
            None,
        )
    }
    .map_err(|_| KeyAgentLpacError::Attribute)
}

fn wide_nul_str(value: &str) -> Result<Vec<u16>, KeyAgentLpacError> {
    let mut wide: Vec<u16> = value.encode_utf16().collect();
    if wide.contains(&0) {
        return Err(KeyAgentLpacError::Profile);
    }
    wide.push(0);
    Ok(wide)
}

fn invalid_handle(handle: HANDLE) -> bool {
    handle.is_invalid() || handle == INVALID_HANDLE_VALUE
}

fn appcontainer_folder(profile_sid: &OwnedAppContainerSid) -> Result<PathBuf, KeyAgentLpacError> {
    let sid_text = wide_nul_str(&sid_string(profile_sid.as_psid())?)?;
    let _profile_api =
        acquire_appcontainer_profile_api().map_err(|_| KeyAgentLpacError::Profile)?;
    // SAFETY: the converted SID string is live and NUL terminated.
    let folder_result = unsafe { GetAppContainerFolderPath(PCWSTR(sid_text.as_ptr())) };
    let folder = folder_result.map_err(|_| KeyAgentLpacError::Profile)?;
    if folder.is_null() {
        return Err(KeyAgentLpacError::Profile);
    }
    // SAFETY: the successful API returned one NUL-terminated CoTaskMem string.
    let path = unsafe { folder.to_string() }
        .map(PathBuf::from)
        .map_err(|_| KeyAgentLpacError::Profile);
    // SAFETY: GetAppContainerFolderPath allocates with CoTaskMemAlloc.
    unsafe { CoTaskMemFree(Some(folder.0.cast::<c_void>())) };
    path
}

fn validated_appcontainer_folder(
    profile_sid: &OwnedAppContainerSid,
) -> Result<PathBuf, KeyAgentLpacError> {
    let appcontainer_local_data = appcontainer_folder(profile_sid)?;
    let local_folder_name = appcontainer_local_data
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(KeyAgentLpacError::Profile)?;
    let profile_folder = appcontainer_local_data
        .parent()
        .ok_or(KeyAgentLpacError::Profile)?;
    let profile_name = profile_folder
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(KeyAgentLpacError::Profile)?;
    let packages = profile_folder.parent().ok_or(KeyAgentLpacError::Profile)?;
    let packages_name = packages
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(KeyAgentLpacError::Profile)?;
    let packages_parent = packages.parent().ok_or(KeyAgentLpacError::Profile)?;
    if !local_folder_name.eq_ignore_ascii_case("AC")
        || !profile_name.eq_ignore_ascii_case(KEY_AGENT_PROFILE_V1_NAME)
        || !packages_name.eq_ignore_ascii_case("Packages")
        || !appcontainer_local_data.is_absolute()
        || !packages_parent.is_absolute()
    {
        return Err(KeyAgentLpacError::Profile);
    }
    Ok(appcontainer_local_data)
}

fn sid_string(sid: PSID) -> Result<String, KeyAgentLpacError> {
    // SAFETY: the pointer is inspected only for validity before conversion.
    if sid.is_invalid() || !unsafe { IsValidSid(sid) }.as_bool() {
        return Err(KeyAgentLpacError::Profile);
    }
    let mut sid_text = PWSTR::null();
    // SAFETY: `sid` is valid and live; the returned LocalAlloc string is freed
    // after conversion on every successful allocation path.
    unsafe { ConvertSidToStringSidW(sid, &raw mut sid_text) }
        .map_err(|_| KeyAgentLpacError::Profile)?;
    // SAFETY: successful conversion returned a NUL-terminated string.
    let result = unsafe { sid_text.to_string() }.map_err(|_| KeyAgentLpacError::Profile);
    // SAFETY: ConvertSidToStringSidW allocated with LocalAlloc.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sid_text.0.cast::<c_void>())));
    }
    result
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
        && system_root.starts_with(&"SystemRoot=".encode_utf16().collect::<Vec<_>>())
        && windir.starts_with(&"WINDIR=".encode_utf16().collect::<Vec<_>>())
        && system_root.len() > "SystemRoot=".encode_utf16().count()
        && windir.len() > "WINDIR=".encode_utf16().count()
}

#[cfg(test)]
fn current_user_sid_string() -> Result<String, KeyAgentLpacError> {
    let mut raw_token = HANDLE::default();
    // SAFETY: the pseudo handle names this process and output receives one
    // exclusively owned query-only token handle.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut raw_token) }
        .map_err(|_| KeyAgentLpacError::Profile)?;
    let token = OwnedToken::new(raw_token)?;
    let information = token_information(token.0, TokenUser)?;
    if information.returned_bytes < size_of::<TOKEN_USER>() {
        return Err(KeyAgentLpacError::Profile);
    }
    // SAFETY: aligned storage contains at least the returned TOKEN_USER prefix.
    let user = unsafe { ptr::read_unaligned(information.words.as_ptr().cast::<TOKEN_USER>()) };
    sid_string(user.User.Sid)
}

#[cfg(test)]
fn apply_exact_fixture_dacl(path: &Path, profile_sid: PSID) -> Result<(), KeyAgentLpacError> {
    let user_sid = current_user_sid_string()?;
    let profile_sid = sid_string(profile_sid)?;
    let sddl = format!("D:P(A;;FA;;;{user_sid})(A;;GRGX;;;{profile_sid})");
    let sddl = wide_nul_str(&sddl)?;
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the SDDL is live and NUL terminated; the output descriptor is
    // LocalAlloc-owned and released below.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &raw mut descriptor,
            None,
        )
    }
    .map_err(|_| KeyAgentLpacError::Profile)?;
    // SAFETY: the conversion succeeded and returned one self-relative
    // descriptor. Validate it before applying only its protected DACL.
    let valid = unsafe { IsValidSecurityDescriptor(descriptor) }.as_bool();
    let path_wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(core::iter::once(0))
        .collect();
    let applied = if valid {
        // SAFETY: both the path and descriptor remain live for this call.
        unsafe {
            SetFileSecurityW(
                PCWSTR(path_wide.as_ptr()),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor,
            )
        }
        .ok()
        .map_err(|_| KeyAgentLpacError::Profile)
    } else {
        Err(KeyAgentLpacError::Profile)
    };
    // SAFETY: the SDDL conversion allocated this descriptor with LocalAlloc.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
    }
    applied
}

#[cfg(test)]
fn create_unique_fixture_directory(root: &Path) -> Result<PathBuf, KeyAgentLpacError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for _ in 0..16 {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_| KeyAgentLpacError::Profile)?;
        let mut suffix = String::with_capacity(random.len() * 2);
        for byte in random {
            suffix.push(char::from(HEX[usize::from(byte >> 4)]));
            suffix.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        let candidate = root.join(format!("your-wallet-key-agent-kernel-{suffix}"));
        match std::fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(KeyAgentLpacError::Profile),
        }
    }
    Err(KeyAgentLpacError::Profile)
}

#[cfg(test)]
fn copy_current_test_image(destination: &Path) -> Result<(), KeyAgentLpacError> {
    let source_path = std::env::current_exe().map_err(|_| KeyAgentLpacError::Profile)?;
    let mut source = File::open(source_path).map_err(|_| KeyAgentLpacError::Profile)?;
    let mut destination_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|_| KeyAgentLpacError::Profile)?;
    let copied =
        io::copy(&mut source, &mut destination_file).and_then(|_| destination_file.sync_all());
    if copied.is_err() {
        drop(destination_file);
        let _ = std::fs::remove_file(destination);
        return Err(KeyAgentLpacError::Profile);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use core::ffi::c_void;
    use core::mem::size_of;
    use core::ptr;
    use std::os::windows::ffi::OsStrExt as _;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0};
    use windows::Win32::Security::{EqualSid, TOKEN_APPCONTAINER_INFORMATION};
    use windows::Win32::Security::{TOKEN_DUPLICATE, TOKEN_QUERY};
    use windows::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
        DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
        InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcessToken,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, STARTUPINFOEXW,
        TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
    };
    use windows::Win32::System::WindowsProgramming::PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
    use windows::core::PCWSTR;

    use super::{
        AppContainerMembershipEvidence, CAPABILITY_COUNT, HeldExistingKeyAgentInstallObjects,
        KEY_AGENT_PROFILE_V1_NAME, KeyAgentLpacError, KeyAgentLpacKernelTestFixture,
        OwnedAppContainerSid, OwnedToken, PendingKeyAgentProvisioning, PreparedKeyAgentLpac,
        PreparedKeyAgentProfile, PreparedKeyAgentProvisioning, TokenDword, TokenPolicyEvidence,
        VerifiedKeyAgentLpac, appcontainer_folder, appcontainer_membership_evidence,
        require_created_sid_matches_derived, validate_token_policy, wide_nul_str,
    };
    use crate::restricted_process_context::RestrictedProcessContext;

    const APPROVAL_PROFILE_V1_NAME: &str = "YourWallet.ApprovalFrontend.LPAC.v1";
    const SECRET_INPUT_PROFILE_V1_NAME: &str = "YourWallet.SecretInputFrontend.LPAC.v1";

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

    trait AmbiguousIfSync<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfSync<()> for T {}
    impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for T {}

    struct TestAttributeList {
        pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
        _words: Vec<usize>,
    }

    impl Drop for TestAttributeList {
        fn drop(&mut self) {
            // SAFETY: construction returns only after this exact list is
            // initialized and its aligned backing allocation stays live.
            unsafe { DeleteProcThreadAttributeList(self.pointer) };
        }
    }

    struct TestSuspendedProcess {
        process: HANDLE,
        thread: HANDLE,
    }

    impl TestSuspendedProcess {
        fn terminate_and_wait(&mut self) -> Result<(), KeyAgentLpacError> {
            if self.process.is_invalid()
                || self.process == INVALID_HANDLE_VALUE
                || self.thread.is_invalid()
                || self.thread == INVALID_HANDLE_VALUE
            {
                return Err(KeyAgentLpacError::Token);
            }
            // SAFETY: both handles are exclusively owned and the process has
            // remained CREATE_SUSPENDED for its entire lifetime.
            unsafe { TerminateProcess(self.process, 0xE0A0_0002) }
                .map_err(|_| KeyAgentLpacError::Token)?;
            // SAFETY: the same live process handle is waited with a finite bound.
            if unsafe { WaitForSingleObject(self.process, 5_000) } != WAIT_OBJECT_0 {
                return Err(KeyAgentLpacError::Token);
            }
            // SAFETY: the waited process and its primary thread are both owned
            // exactly once. Record both close results before returning.
            let thread_closed = unsafe { CloseHandle(self.thread) };
            // SAFETY: same exclusive ownership argument for the process handle.
            let process_closed = unsafe { CloseHandle(self.process) };
            self.thread = HANDLE::default();
            self.process = HANDLE::default();
            thread_closed
                .and(process_closed)
                .map_err(|_| KeyAgentLpacError::Token)
        }
    }

    impl Drop for TestSuspendedProcess {
        fn drop(&mut self) {
            if !self.process.is_invalid() && self.process != INVALID_HANDLE_VALUE {
                // SAFETY: the test owns the still-suspended process and never
                // resumes it; termination precedes the bounded wait and close.
                unsafe {
                    let _ = TerminateProcess(self.process, 0xE0A0_0002);
                    let _ = WaitForSingleObject(self.process, 5_000);
                    let _ = CloseHandle(self.process);
                }
                self.process = HANDLE::default();
            }
            if !self.thread.is_invalid() && self.thread != INVALID_HANDLE_VALUE {
                // SAFETY: this wrapper exclusively owns the returned thread handle.
                unsafe {
                    let _ = CloseHandle(self.thread);
                }
                self.thread = HANDLE::default();
            }
        }
    }

    fn regular_appcontainer_attribute_list(
        prepared: &PreparedKeyAgentLpac,
    ) -> Result<TestAttributeList, KeyAgentLpacError> {
        let mut bytes = 0_usize;
        // SAFETY: documented sizing call with a null list and writable size.
        let _ = unsafe { InitializeProcThreadAttributeList(None, 1, None, &raw mut bytes) };
        if bytes == 0 {
            return Err(KeyAgentLpacError::Attribute);
        }
        let word_size = size_of::<usize>();
        let word_count = bytes
            .checked_add(word_size - 1)
            .and_then(|rounded| rounded.checked_div(word_size))
            .ok_or(KeyAgentLpacError::Attribute)?;
        let mut words = vec![0_usize; word_count];
        let pointer = LPPROC_THREAD_ATTRIBUTE_LIST(words.as_mut_ptr().cast::<c_void>());
        // SAFETY: the aligned allocation has at least the sized byte count and
        // cannot move while the returned owner is live.
        unsafe { InitializeProcThreadAttributeList(Some(pointer), 1, None, &raw mut bytes) }
            .map_err(|_| KeyAgentLpacError::Attribute)?;
        let attributes = TestAttributeList {
            pointer,
            _words: words,
        };
        // SAFETY: the initialized one-slot list and prepared SID/value stay
        // live through CreateProcessW. Deliberately omit only the AAP opt-out.
        unsafe {
            UpdateProcThreadAttribute(
                attributes.pointer,
                0,
                usize::try_from(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES)
                    .map_err(|_| KeyAgentLpacError::Attribute)?,
                Some(ptr::from_ref(&prepared.values.security_capabilities).cast::<c_void>()),
                size_of::<windows::Win32::Security::SECURITY_CAPABILITIES>(),
                None,
                None,
            )
        }
        .map_err(|_| KeyAgentLpacError::Attribute)?;
        Ok(attributes)
    }

    fn create_suspended_regular_appcontainer(
        prepared: &PreparedKeyAgentLpac,
        fixture: &KeyAgentLpacKernelTestFixture,
    ) -> Result<TestSuspendedProcess, KeyAgentLpacError> {
        let context = RestrictedProcessContext::prepare_for_kernel_test()
            .map_err(|_| KeyAgentLpacError::Profile)?;
        let environment = prepared.environment_with_local_app_data(context.environment())?;
        let attributes = regular_appcontainer_attribute_list(prepared)?;
        let application: Vec<u16> = fixture
            .path()
            .as_os_str()
            .encode_wide()
            .chain(core::iter::once(0))
            .collect();
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb =
            u32::try_from(size_of::<STARTUPINFOEXW>()).map_err(|_| KeyAgentLpacError::Profile)?;
        startup.lpAttributeList = attributes.pointer;
        let mut information = PROCESS_INFORMATION::default();
        // SAFETY: all pointer owners remain live for the call. The child gets
        // no inherited handles, an explicit environment/current directory, and
        // CREATE_SUSPENDED; the test never resumes it into user mode.
        unsafe {
            CreateProcessW(
                PCWSTR(application.as_ptr()),
                None,
                None,
                None,
                false,
                CREATE_SUSPENDED
                    | CREATE_NO_WINDOW
                    | CREATE_UNICODE_ENVIRONMENT
                    | EXTENDED_STARTUPINFO_PRESENT,
                Some(environment.as_ptr().cast::<c_void>()),
                PCWSTR(context.current_directory().as_ptr()),
                &raw const startup.StartupInfo,
                &raw mut information,
            )
        }
        .map_err(|_| KeyAgentLpacError::Profile)?;
        if information.hProcess.is_invalid()
            || information.hProcess == INVALID_HANDLE_VALUE
            || information.hThread.is_invalid()
            || information.hThread == INVALID_HANDLE_VALUE
        {
            if !information.hProcess.is_invalid() && information.hProcess != INVALID_HANDLE_VALUE {
                // SAFETY: clean up any valid partial result before rejecting.
                unsafe {
                    let _ = TerminateProcess(information.hProcess, 0xE0A0_0002);
                    let _ = WaitForSingleObject(information.hProcess, 5_000);
                    let _ = CloseHandle(information.hProcess);
                }
            }
            if !information.hThread.is_invalid() && information.hThread != INVALID_HANDLE_VALUE {
                // SAFETY: clean up the independently valid partial thread handle.
                unsafe {
                    let _ = CloseHandle(information.hThread);
                }
            }
            return Err(KeyAgentLpacError::Profile);
        }
        Ok(TestSuspendedProcess {
            process: information.hProcess,
            thread: information.hThread,
        })
    }

    fn valid_policy_evidence() -> TokenPolicyEvidence {
        TokenPolicyEvidence {
            is_appcontainer: TokenDword {
                value: 1,
                returned_bytes: size_of::<u32>(),
            },
            is_lpac: Some(TokenDword {
                value: 1,
                returned_bytes: size_of::<u32>(),
            }),
            membership: AppContainerMembershipEvidence::Lpac,
            appcontainer_sid_bytes: size_of::<TOKEN_APPCONTAINER_INFORMATION>(),
            appcontainer_sid_valid: true,
            appcontainer_sid_matches: true,
            capability_bytes: size_of::<u32>(),
            capability_count: CAPABILITY_COUNT,
        }
    }

    #[test]
    fn prepared_policy_is_fixed_zero_capability_lpac() -> Result<(), KeyAgentLpacError> {
        let sid = OwnedAppContainerSid::derive(&wide_nul_str(KEY_AGENT_PROFILE_V1_NAME)?)?;
        let profile = PreparedKeyAgentProfile::from_profile_sid(sid)?;
        let prepared = profile.prepare_lpac()?;
        assert_eq!(KEY_AGENT_PROFILE_V1_NAME, "YourWallet.KeyAgent.LPAC.v1");
        assert_eq!(prepared.values.security_capabilities.CapabilityCount, 0);
        assert!(prepared.values.security_capabilities.Capabilities.is_null());
        assert_eq!(prepared.values.security_capabilities.Reserved, 0);
        assert_eq!(
            prepared.values.all_application_packages_policy,
            PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT
        );
        assert!(
            // SAFETY: both fields refer to the same live, validated SID allocation.
            unsafe {
                EqualSid(
                    prepared.values.security_capabilities.AppContainerSid,
                    prepared.profile_sid.as_psid(),
                )
            }
            .is_ok()
        );
        assert_eq!(
            format!("{prepared:?}"),
            "PreparedKeyAgentLpac([OPAQUE KEY AGENT LPAC])"
        );
        Ok(())
    }

    #[test]
    fn concurrent_fixed_profile_preparation_is_process_serialized() -> Result<(), KeyAgentLpacError>
    {
        const WORKERS: usize = 16;
        let start = Arc::new(AtomicBool::new(false));
        let mut workers = Vec::with_capacity(WORKERS);
        let mut all_spawned = true;
        for worker_index in 0..WORKERS {
            let start = Arc::clone(&start);
            let worker = std::thread::Builder::new()
                .name(format!("key-agent-lpac-profile-{worker_index}"))
                .spawn(move || {
                    while !start.load(Ordering::Acquire) {
                        std::thread::yield_now();
                    }
                    let prepared = PreparedKeyAgentLpac::prepare()?;
                    let context = RestrictedProcessContext::prepare_for_kernel_test()
                        .map_err(|_| KeyAgentLpacError::Profile)?;
                    let environment =
                        prepared.environment_with_local_app_data(context.environment())?;
                    if !environment.ends_with(&[0, 0]) {
                        return Err(KeyAgentLpacError::Profile);
                    }
                    Ok(())
                });
            if let Ok(worker) = worker {
                workers.push(worker);
            } else {
                all_spawned = false;
                break;
            }
        }
        start.store(true, Ordering::Release);
        let mut all_succeeded = all_spawned;
        for worker in workers {
            if !matches!(worker.join(), Ok(Ok(()))) {
                all_succeeded = false;
            }
        }
        if !all_succeeded {
            return Err(KeyAgentLpacError::Profile);
        }
        Ok(())
    }

    #[test]
    fn regular_appcontainer_negative_control_passes_both_membership_paths()
    -> Result<(), KeyAgentLpacError> {
        let prepared = PreparedKeyAgentLpac::prepare()?;
        let fixture = KeyAgentLpacKernelTestFixture::create()?;
        let mut process = create_suspended_regular_appcontainer(&prepared, &fixture)?;
        let mut raw_token = HANDLE::default();
        // SAFETY: the process handle is live and suspended; output receives one
        // exclusively owned token handle for query and duplication.
        unsafe {
            OpenProcessToken(
                process.process,
                TOKEN_QUERY | TOKEN_DUPLICATE,
                &raw mut raw_token,
            )
        }
        .map_err(|_| KeyAgentLpacError::Token)?;
        let token = OwnedToken::new(raw_token)?;
        let membership = appcontainer_membership_evidence(token.0)?;
        assert_eq!(
            membership,
            AppContainerMembershipEvidence::RegularAppContainer
        );
        process.terminate_and_wait()?;
        Ok(())
    }

    #[test]
    fn token_policy_rejects_each_single_invariant_break() {
        assert_eq!(validate_token_policy(&valid_policy_evidence()), Ok(()));

        let negative_cases = [
            TokenPolicyEvidence {
                is_appcontainer: TokenDword {
                    value: 0,
                    returned_bytes: size_of::<u32>(),
                },
                ..valid_policy_evidence()
            },
            TokenPolicyEvidence {
                is_appcontainer: TokenDword {
                    value: 1,
                    returned_bytes: size_of::<u32>() - 1,
                },
                ..valid_policy_evidence()
            },
            TokenPolicyEvidence {
                is_lpac: Some(TokenDword {
                    value: 0,
                    returned_bytes: size_of::<u32>(),
                }),
                ..valid_policy_evidence()
            },
            TokenPolicyEvidence {
                is_lpac: Some(TokenDword {
                    value: 1,
                    returned_bytes: size_of::<u32>() + 1,
                }),
                ..valid_policy_evidence()
            },
            TokenPolicyEvidence {
                membership: AppContainerMembershipEvidence::RegularAppContainer,
                ..valid_policy_evidence()
            },
            TokenPolicyEvidence {
                membership: AppContainerMembershipEvidence::Neither,
                ..valid_policy_evidence()
            },
            TokenPolicyEvidence {
                membership: AppContainerMembershipEvidence::Inverted,
                ..valid_policy_evidence()
            },
            TokenPolicyEvidence {
                appcontainer_sid_bytes: size_of::<TOKEN_APPCONTAINER_INFORMATION>() - 1,
                ..valid_policy_evidence()
            },
            TokenPolicyEvidence {
                appcontainer_sid_valid: false,
                ..valid_policy_evidence()
            },
            TokenPolicyEvidence {
                appcontainer_sid_matches: false,
                ..valid_policy_evidence()
            },
            TokenPolicyEvidence {
                capability_bytes: size_of::<u32>() - 1,
                ..valid_policy_evidence()
            },
            TokenPolicyEvidence {
                capability_count: 1,
                ..valid_policy_evidence()
            },
        ];
        for evidence in negative_cases {
            assert!(matches!(
                validate_token_policy(&evidence),
                Err(KeyAgentLpacError::Token)
            ));
        }

        let mut fallback_evidence = valid_policy_evidence();
        fallback_evidence.is_lpac = None;
        assert_eq!(validate_token_policy(&fallback_evidence), Ok(()));

        let mut rejected_fallback = valid_policy_evidence();
        rejected_fallback.is_lpac = None;
        rejected_fallback.membership = AppContainerMembershipEvidence::RegularAppContainer;
        assert_eq!(
            validate_token_policy(&rejected_fallback),
            Err(KeyAgentLpacError::Token)
        );
    }

    #[test]
    fn created_profile_sid_mismatch_is_rejected() -> Result<(), KeyAgentLpacError> {
        let key_agent = OwnedAppContainerSid::derive(&wide_nul_str(KEY_AGENT_PROFILE_V1_NAME)?)?;
        let matching = OwnedAppContainerSid::derive(&wide_nul_str(KEY_AGENT_PROFILE_V1_NAME)?)?;
        let other = OwnedAppContainerSid::derive(&wide_nul_str(APPROVAL_PROFILE_V1_NAME)?)?;

        assert_eq!(
            require_created_sid_matches_derived(&key_agent, &matching),
            Ok(())
        );
        assert_eq!(
            require_created_sid_matches_derived(&key_agent, &other),
            Err(KeyAgentLpacError::Profile)
        );
        Ok(())
    }

    #[test]
    fn exact_environment_has_only_three_os_scoped_names() -> Result<(), KeyAgentLpacError> {
        let prepared = PreparedKeyAgentLpac::prepare()?;
        let base: Vec<u16> = "SystemRoot=[ROOT]\0WINDIR=[ROOT]\0\0"
            .encode_utf16()
            .collect();
        let environment = prepared.environment_with_local_app_data(&base)?;
        assert_eq!(environment.iter().filter(|unit| **unit == 0).count(), 4);

        let entries: Vec<&[u16]> = environment[..environment.len() - 1]
            .split(|unit| *unit == 0)
            .collect();
        let mut exact_local_app_data: Vec<u16> = "LOCALAPPDATA=".encode_utf16().collect();
        let appcontainer_local_data = appcontainer_folder(&prepared.profile_sid)?;
        let user_local_data = appcontainer_local_data
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .ok_or(KeyAgentLpacError::Profile)?;
        exact_local_app_data.extend(user_local_data.as_os_str().encode_wide());
        let system_root: Vec<u16> = "SystemRoot=[ROOT]".encode_utf16().collect();
        let windir: Vec<u16> = "WINDIR=[ROOT]".encode_utf16().collect();
        assert_eq!(entries.len(), 4);
        assert!(entries[0] == exact_local_app_data);
        assert!(entries[1] == system_root);
        assert!(entries[2] == windir);
        assert!(entries[3].is_empty());

        let extra: Vec<u16> = "SystemRoot=[ROOT]\0WINDIR=[ROOT]\0PATH=[DENIED]\0\0"
            .encode_utf16()
            .collect();
        assert!(matches!(
            prepared.environment_with_local_app_data(&extra),
            Err(KeyAgentLpacError::Profile)
        ));
        Ok(())
    }

    #[test]
    fn kernel_fixture_is_profile_scoped_redacted_and_exactly_cleaned()
    -> Result<(), KeyAgentLpacError> {
        let profile = OwnedAppContainerSid::open_or_create()?;
        let profile_folder = appcontainer_folder(&profile)?;
        let fixture = KeyAgentLpacKernelTestFixture::create()?;
        let executable = fixture.executable.clone();
        let directory = fixture.directory.clone();

        assert!(executable.starts_with(&profile_folder));
        assert!(executable.is_file());
        assert!(directory.is_dir());
        assert_eq!(
            format!("{fixture:?}"),
            "KeyAgentLpacKernelTestFixture([REDACTED PATH])"
        );

        drop(fixture);
        assert!(!executable.exists());
        assert!(!directory.exists());
        Ok(())
    }

    #[test]
    fn key_agent_sid_is_distinct_from_both_frontend_sids() -> Result<(), KeyAgentLpacError> {
        let key_agent = OwnedAppContainerSid::derive(&wide_nul_str(KEY_AGENT_PROFILE_V1_NAME)?)?;
        let approval = OwnedAppContainerSid::derive(&wide_nul_str(APPROVAL_PROFILE_V1_NAME)?)?;
        let secret_input =
            OwnedAppContainerSid::derive(&wide_nul_str(SECRET_INPUT_PROFILE_V1_NAME)?)?;

        // SAFETY: every wrapper owns one valid, live derived SID.
        assert!(unsafe { EqualSid(key_agent.as_psid(), approval.as_psid()) }.is_err());
        // SAFETY: same ownership and validity argument.
        assert!(unsafe { EqualSid(key_agent.as_psid(), secret_input.as_psid()) }.is_err());
        // SAFETY: the two frontend profiles must also remain distinct.
        assert!(unsafe { EqualSid(approval.as_psid(), secret_input.as_psid()) }.is_err());
        Ok(())
    }

    #[test]
    fn authority_types_are_non_clone_non_copy_and_debug_redacted() {
        fn assert_send<T: Send>() {}

        assert_send::<PendingKeyAgentProvisioning>();
        assert_send::<PreparedKeyAgentProvisioning>();
        assert_send::<HeldExistingKeyAgentInstallObjects>();
        let _ = <PendingKeyAgentProvisioning as AmbiguousIfClone<_>>::marker;
        let _ = <PendingKeyAgentProvisioning as AmbiguousIfCopy<_>>::marker;
        let _ = <PendingKeyAgentProvisioning as AmbiguousIfSync<_>>::marker;
        let _ = <PreparedKeyAgentProvisioning as AmbiguousIfClone<_>>::marker;
        let _ = <PreparedKeyAgentProvisioning as AmbiguousIfCopy<_>>::marker;
        let _ = <PreparedKeyAgentProvisioning as AmbiguousIfSync<_>>::marker;
        let _ = <HeldExistingKeyAgentInstallObjects as AmbiguousIfClone<_>>::marker;
        let _ = <HeldExistingKeyAgentInstallObjects as AmbiguousIfCopy<_>>::marker;
        let _ = <HeldExistingKeyAgentInstallObjects as AmbiguousIfSync<_>>::marker;
        let _ = <PreparedKeyAgentLpac as AmbiguousIfClone<_>>::marker;
        let _ = <PreparedKeyAgentLpac as AmbiguousIfCopy<_>>::marker;
        let _ = <VerifiedKeyAgentLpac as AmbiguousIfClone<_>>::marker;
        let _ = <VerifiedKeyAgentLpac as AmbiguousIfCopy<_>>::marker;

        let verified = VerifiedKeyAgentLpac { _private: () };
        assert_eq!(format!("{verified:?}"), "VerifiedKeyAgentLpac([VERIFIED])");
        assert_eq!(
            format!("{:?}", KeyAgentLpacError::Profile),
            "KeyAgentLpacError([REDACTED])"
        );
    }

    #[test]
    fn held_existing_observation_is_path_free_consistent_and_redacted()
    -> Result<(), KeyAgentLpacError> {
        let held = HeldExistingKeyAgentInstallObjects::for_kernel_test()?;
        let observation = held.install_observation()?;
        assert!(!observation.profile_sid().is_empty());
        assert!(!observation.stable_user_sid().is_empty());
        assert_eq!(observation.profile_sid(), observation.storage_profile_sid());
        assert_eq!(
            format!("{held:?}"),
            "HeldExistingKeyAgentInstallObjects([PROFILE BINDING AND HELD ROOT; REDACTED])"
        );
        assert_eq!(
            format!("{observation:?}"),
            "KeyAgentHeldInstallObservation([REDACTED IDENTITIES])"
        );
        held.revalidate()
    }

    #[test]
    fn provisioning_proof_is_revalidated_redacted_and_exactly_cleaned()
    -> Result<(), KeyAgentLpacError> {
        let provisioning = PreparedKeyAgentProvisioning::prepare_for_kernel_test()?;
        let storage_root = provisioning.storage_root_path_for_test().to_path_buf();
        assert!(storage_root.is_dir());
        provisioning.revalidate()?;
        assert_eq!(
            format!("{provisioning:?}"),
            "PreparedKeyAgentProvisioning([VERIFIED PROFILE AND HELD STORAGE ROOT; REDACTED])"
        );
        drop(provisioning);
        assert!(!storage_root.exists());
        Ok(())
    }

    #[test]
    fn pending_fresh_objects_are_redacted_non_launchable_and_exactly_cleaned()
    -> Result<(), KeyAgentLpacError> {
        let pending = PendingKeyAgentProvisioning::prepare_for_kernel_test()?;
        let storage_root = pending.storage_root.path_for_test().to_path_buf();
        assert!(storage_root.is_dir());
        assert_eq!(
            format!("{pending:?}"),
            "PendingKeyAgentProvisioning([NON-LAUNCHABLE FRESH OBJECTS; REDACTED])"
        );
        drop(pending);
        assert!(!storage_root.exists());
        Ok(())
    }
}
