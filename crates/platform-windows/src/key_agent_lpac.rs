//! Fixed, zero-capability LPAC policy for the dormant Key Agent.
//!
//! The profile identity is compiled into this private module. Callers can
//! neither select an `AppContainer` name nor obtain its SID. A prepared value
//! owns every pointer installed into a process-creation attribute list and is
//! consumed only after the suspended child token has been checked.

#![allow(unsafe_code)]

use core::ffi::c_void;
use core::fmt;
use core::mem::{align_of, size_of};
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
    CloseHandle, CompareObjectHandles, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER,
    GetHandleInformation, HANDLE, HANDLE_FLAGS, INVALID_HANDLE_VALUE,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::Isolation::GetAppContainerFolderPath;
use windows::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
#[cfg(test)]
use windows::Win32::Security::SetFileSecurityW;
use windows::Win32::Security::{
    ACL, ACL_REVISION, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
    GetKernelObjectSecurity, GetSecurityDescriptorLength, IsValidSecurityDescriptor,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SE_DACL_PRESENT, SE_DACL_PROTECTED, SE_SELF_RELATIVE, SECURITY_ATTRIBUTES,
    SetKernelObjectSecurity,
};
use windows::Win32::Security::{
    CheckTokenMembershipEx, DuplicateToken, EqualSid, FreeSid, GetLengthSid, GetTokenInformation,
    IsValidSid, PSID, SECURITY_CAPABILITIES, SecurityIdentification, SetTokenInformation,
    TOKEN_ACCESS_MASK, TOKEN_ADJUST_DEFAULT, TOKEN_ALL_ACCESS, TOKEN_APPCONTAINER_INFORMATION,
    TOKEN_DEFAULT_DACL, TOKEN_DUPLICATE, TOKEN_OWNER, TOKEN_PRIMARY_GROUP, TOKEN_QUERY,
    TOKEN_STATISTICS, TOKEN_USER, TokenAppContainerSid, TokenCapabilities, TokenDefaultDacl,
    TokenIsAppContainer, TokenIsLessPrivilegedAppContainer, TokenOwner, TokenPrimary,
    TokenPrimaryGroup, TokenStatistics, TokenUser,
};
use windows::Win32::Storage::FileSystem::{READ_CONTROL, WRITE_DAC};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, CTMF_INCLUDE_APPCONTAINER, CTMF_INCLUDE_LPAC,
    SECURITY_DESCRIPTOR_REVISION,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcessToken,
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
use crate::key_agent_storage::{
    HeldKeyAgentStorageRoot, KeyAgentHeldRootObservation, KeyAgentStorageRootIdentity,
    create_fixed_key_agent_storage_root,
};
#[cfg(test)]
use crate::key_agent_storage::{
    KeyAgentStorageError, create_unique_key_agent_storage_root_for_test,
    open_existing_key_agent_storage_root_for_test,
};

pub(crate) const KEY_AGENT_PROFILE_V1_NAME: &str = "YourWallet.KeyAgent.LPAC.v1";
const APPROVAL_PROFILE_V1_NAME: &str = "YourWallet.ApprovalFrontend.LPAC.v1";
const KEY_AGENT_PROFILE_DISPLAY_NAME: &str = "Your Wallet Key Agent";
const KEY_AGENT_PROFILE_DESCRIPTION: &str =
    "Persistent zero-capability LPAC identity for Your Wallet Key Agent";
const CAPABILITY_COUNT: u32 = 0;
const MAX_TOKEN_INFORMATION_BYTES: usize = 64 * 1024;
const MAX_TOKEN_SECURITY_DESCRIPTOR_BYTES: usize = 64 * 1024;
const MAX_INSTALL_SID_BYTES: usize = 68;
const SELF_RELATIVE_SECURITY_DESCRIPTOR_BYTES: usize = 20;
const ACL_HEADER_BYTES: usize = 8;
const ACCESS_ALLOWED_ACE_FIXED_BYTES: usize = 8;
const ACCESS_DENIED_ACE_FIXED_BYTES: usize = 8;
const MIN_BINARY_SID_BYTES: usize = 8;
const MAX_CREATION_SECURITY_DESCRIPTOR_BYTES: usize = 256;
const CREATION_SECURITY_DENIED_ACCESS: u32 = 0x000e_0000;
const OWNER_RIGHTS_SID_BYTES: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0];
const EXACT_TOKEN_DEFAULT_DACL_BYTES: usize =
    ACL_HEADER_BYTES + ACCESS_DENIED_ACE_FIXED_BYTES + OWNER_RIGHTS_SID_BYTES.len();
const EXACT_TOKEN_DEFAULT_DACL_WORDS: usize = EXACT_TOKEN_DEFAULT_DACL_BYTES / size_of::<u32>();
const SUPERVISOR_TOKEN_ACCESS: u32 = TOKEN_ALL_ACCESS.0;
const KEY_AGENT_TOKEN_SELF_ACCESS: u32 = TOKEN_QUERY.0 | TOKEN_DUPLICATE.0;
const APPROVAL_PARENT_TOKEN_ACCESS: u32 = TOKEN_QUERY.0;
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

    /// Prepares the exact process and primary-thread security descriptors for
    /// one creation attempt while this verified installation remains held.
    pub(crate) fn prepare_creation_security(
        &self,
    ) -> Result<PreparedKeyAgentCreationSecurity, KeyAgentLpacError> {
        self.revalidate()?;
        PreparedKeyAgentCreationSecurity::prepare()
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

/// Opaque ownership of the exact process and primary-thread creation policy.
///
/// Each `SECURITY_ATTRIBUTES` value is non-inheritable and points into a
/// distinct `LocalAlloc` descriptor retained by this value. No descriptor,
/// token identity, SID, or raw pointer is exposed to callers.
#[must_use = "creation security must remain live through creation and readback"]
pub(crate) struct PreparedKeyAgentCreationSecurity {
    process_attributes: SECURITY_ATTRIBUTES,
    primary_thread_attributes: SECURITY_ATTRIBUTES,
    process_descriptor: OwnedCreationSecurityDescriptor,
    primary_thread_descriptor: OwnedCreationSecurityDescriptor,
    expected_owner_sid: Vec<u8>,
    expected_primary_group_sid: Vec<u8>,
}

impl PreparedKeyAgentCreationSecurity {
    fn prepare() -> Result<Self, KeyAgentLpacError> {
        let token = open_current_process_creation_security_token()?;

        let owner_information = creation_security_token_information(token.0, TokenOwner)?;
        if owner_information.returned_bytes < size_of::<TOKEN_OWNER>() {
            return Err(KeyAgentLpacError::Attribute);
        }
        // SAFETY: aligned storage contains the complete returned TOKEN_OWNER
        // prefix and remains live while its interior SID is validated.
        let owner =
            unsafe { ptr::read_unaligned(owner_information.words.as_ptr().cast::<TOKEN_OWNER>()) };
        let expected_owner_sid = validated_creation_token_sid_bytes(
            &owner_information,
            owner.Owner,
            size_of::<TOKEN_OWNER>(),
        )?;
        let owner_text = creation_security_sid_string(owner.Owner)?;

        let primary_group_information =
            creation_security_token_information(token.0, TokenPrimaryGroup)?;
        if primary_group_information.returned_bytes < size_of::<TOKEN_PRIMARY_GROUP>() {
            return Err(KeyAgentLpacError::Attribute);
        }
        // SAFETY: aligned storage contains the complete returned
        // TOKEN_PRIMARY_GROUP prefix and remains live during SID validation.
        let primary_group = unsafe {
            ptr::read_unaligned(
                primary_group_information
                    .words
                    .as_ptr()
                    .cast::<TOKEN_PRIMARY_GROUP>(),
            )
        };
        let expected_primary_group_sid = validated_creation_token_sid_bytes(
            &primary_group_information,
            primary_group.PrimaryGroup,
            size_of::<TOKEN_PRIMARY_GROUP>(),
        )?;
        let primary_group_text = creation_security_sid_string(primary_group.PrimaryGroup)?;

        let sddl = format!("O:{owner_text}G:{primary_group_text}D:P(D;;0x000e0000;;;OW)");
        let sddl = creation_security_wide_nul(&sddl)?;
        let process_descriptor = OwnedCreationSecurityDescriptor::from_sddl(
            &sddl,
            &expected_owner_sid,
            &expected_primary_group_sid,
        )?;
        let primary_thread_descriptor = OwnedCreationSecurityDescriptor::from_sddl(
            &sddl,
            &expected_owner_sid,
            &expected_primary_group_sid,
        )?;
        if process_descriptor.descriptor == primary_thread_descriptor.descriptor {
            return Err(KeyAgentLpacError::Attribute);
        }

        let attribute_bytes = u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| KeyAgentLpacError::Attribute)?;
        let process_attributes = SECURITY_ATTRIBUTES {
            nLength: attribute_bytes,
            lpSecurityDescriptor: process_descriptor.descriptor.0,
            bInheritHandle: BOOL(0),
        };
        let primary_thread_attributes = SECURITY_ATTRIBUTES {
            nLength: attribute_bytes,
            lpSecurityDescriptor: primary_thread_descriptor.descriptor.0,
            bInheritHandle: BOOL(0),
        };

        Ok(Self {
            process_attributes,
            primary_thread_attributes,
            process_descriptor,
            primary_thread_descriptor,
            expected_owner_sid,
            expected_primary_group_sid,
        })
    }

    /// Borrows both creation attributes as one inseparable process/thread pair.
    pub(crate) fn creation_security(
        &self,
    ) -> crate::inheritable_handle_launch::ProcessThreadCreationSecurity<'_> {
        crate::inheritable_handle_launch::ProcessThreadCreationSecurity::new(
            &self.process_attributes,
            &self.primary_thread_attributes,
        )
    }

    /// Verifies the descriptors installed on the two handles returned by the
    /// successful creation call. The handles must be the creator-owned process
    /// and primary-thread handles, not reopened or pseudo handles.
    pub(crate) fn verify_created_objects(
        &self,
        process: BorrowedHandle<'_>,
        primary_thread: BorrowedHandle<'_>,
    ) -> Result<(), KeyAgentLpacError> {
        verify_created_object_security(
            HANDLE(process.as_raw_handle()),
            &self.expected_owner_sid,
            &self.expected_primary_group_sid,
        )?;
        verify_created_object_security(
            HANDLE(primary_thread.as_raw_handle()),
            &self.expected_owner_sid,
            &self.expected_primary_group_sid,
        )
    }
}

impl fmt::Debug for PreparedKeyAgentCreationSecurity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.process_descriptor, &self.primary_thread_descriptor);
        formatter.write_str("PreparedKeyAgentCreationSecurity([OPAQUE PROCESS/THREAD POLICY])")
    }
}

struct OwnedCreationSecurityDescriptor {
    descriptor: PSECURITY_DESCRIPTOR,
    descriptor_bytes: usize,
}

impl OwnedCreationSecurityDescriptor {
    fn from_sddl(
        sddl: &[u16],
        expected_owner_sid: &[u8],
        expected_primary_group_sid: &[u8],
    ) -> Result<Self, KeyAgentLpacError> {
        if !sddl.ends_with(&[0]) {
            return Err(KeyAgentLpacError::Attribute);
        }
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let mut converted_bytes = 0_u32;
        // SAFETY: the SDDL is live and NUL terminated. On success Windows
        // returns one self-relative LocalAlloc allocation and its byte length.
        let conversion = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &raw mut descriptor,
                Some(&raw mut converted_bytes),
            )
        };
        let owned = Self {
            descriptor,
            descriptor_bytes: usize::try_from(converted_bytes)
                .map_err(|_| KeyAgentLpacError::Attribute)?,
        };
        conversion.map_err(|_| KeyAgentLpacError::Attribute)?;
        if owned.descriptor.0.is_null()
            || owned.descriptor_bytes < SELF_RELATIVE_SECURITY_DESCRIPTOR_BYTES
            || owned.descriptor_bytes > MAX_CREATION_SECURITY_DESCRIPTOR_BYTES
            // SAFETY: the conversion succeeded and returned a live descriptor.
            || !unsafe { IsValidSecurityDescriptor(owned.descriptor) }.as_bool()
        {
            return Err(KeyAgentLpacError::Attribute);
        }
        // SAFETY: IsValidSecurityDescriptor accepted the complete live value.
        let reported_bytes =
            usize::try_from(unsafe { GetSecurityDescriptorLength(owned.descriptor) })
                .map_err(|_| KeyAgentLpacError::Attribute)?;
        if reported_bytes != owned.descriptor_bytes {
            return Err(KeyAgentLpacError::Attribute);
        }
        inspect_exact_creation_security_descriptor(
            owned.bytes(),
            expected_owner_sid,
            expected_primary_group_sid,
        )?;
        Ok(owned)
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: construction retains this LocalAlloc descriptor and records
        // the exact validated allocation length until Drop.
        unsafe {
            core::slice::from_raw_parts(self.descriptor.0.cast::<u8>(), self.descriptor_bytes)
        }
    }
}

impl Drop for OwnedCreationSecurityDescriptor {
    fn drop(&mut self) {
        if !self.descriptor.0.is_null() {
            // SAFETY: this is the one LocalAlloc allocation returned by the
            // successful SDDL conversion and it is released exactly once.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.descriptor.0)));
            }
            self.descriptor = PSECURITY_DESCRIPTOR::default();
            self.descriptor_bytes = 0;
        }
    }
}

impl fmt::Debug for OwnedCreationSecurityDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OwnedCreationSecurityDescriptor([REDACTED])")
    }
}

struct CreationSecurityToken(HANDLE);

impl Drop for CreationSecurityToken {
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

struct CreationSecurityTokenInformation {
    words: Vec<usize>,
    returned_bytes: usize,
}

fn open_current_process_creation_security_token() -> Result<CreationSecurityToken, KeyAgentLpacError>
{
    let mut token = HANDLE::default();
    // SAFETY: GetCurrentProcess is a process-local pseudo handle used only to
    // open one real query handle; output ownership transfers to the guard.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) }
        .map_err(|_| KeyAgentLpacError::Attribute)?;
    if invalid_handle(token) {
        return Err(KeyAgentLpacError::Attribute);
    }
    Ok(CreationSecurityToken(token))
}

fn creation_security_token_information(
    token: HANDLE,
    class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
) -> Result<CreationSecurityTokenInformation, KeyAgentLpacError> {
    let mut first_required = 0_u32;
    // SAFETY: this is the documented sizing call on a live TOKEN_QUERY handle.
    let sizing = unsafe { GetTokenInformation(token, class, None, 0, &raw mut first_required) };
    if !matches!(
        sizing,
        Err(error) if error.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult()
    ) {
        return Err(KeyAgentLpacError::Attribute);
    }
    let required = usize::try_from(first_required).map_err(|_| KeyAgentLpacError::Attribute)?;
    if required == 0 || required > MAX_TOKEN_INFORMATION_BYTES {
        return Err(KeyAgentLpacError::Attribute);
    }
    let word_bytes = size_of::<usize>();
    let word_count = required
        .checked_add(word_bytes.saturating_sub(1))
        .and_then(|rounded| rounded.checked_div(word_bytes))
        .ok_or(KeyAgentLpacError::Attribute)?;
    let mut words = vec![0_usize; word_count];
    let mut second_returned = 0_u32;
    // SAFETY: aligned word storage has at least `first_required` writable
    // bytes and the same real token handle remains live for this exact query.
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some(words.as_mut_ptr().cast::<c_void>()),
            first_required,
            &raw mut second_returned,
        )
    }
    .map_err(|_| KeyAgentLpacError::Attribute)?;
    if second_returned != first_required {
        return Err(KeyAgentLpacError::Attribute);
    }
    Ok(CreationSecurityTokenInformation {
        words,
        returned_bytes: required,
    })
}

fn validated_creation_token_sid_bytes(
    information: &CreationSecurityTokenInformation,
    sid: PSID,
    structure_bytes: usize,
) -> Result<Vec<u8>, KeyAgentLpacError> {
    if sid.0.is_null() || structure_bytes > information.returned_bytes {
        return Err(KeyAgentLpacError::Attribute);
    }
    let base_address = information.words.as_ptr().cast::<u8>() as usize;
    let sid_address = sid.0 as usize;
    let sid_offset = sid_address
        .checked_sub(base_address)
        .ok_or(KeyAgentLpacError::Attribute)?;
    if sid_offset < structure_bytes || sid_offset % size_of::<u32>() != 0 {
        return Err(KeyAgentLpacError::Attribute);
    }
    let information_bytes = {
        // SAFETY: the successful second query initialized exactly
        // `returned_bytes` inside this still-live aligned allocation.
        unsafe {
            core::slice::from_raw_parts(
                information.words.as_ptr().cast::<u8>(),
                information.returned_bytes,
            )
        }
    };
    let minimum_end = sid_offset
        .checked_add(MIN_BINARY_SID_BYTES)
        .ok_or(KeyAgentLpacError::Attribute)?;
    if minimum_end > information_bytes.len() {
        return Err(KeyAgentLpacError::Attribute);
    }
    let sid_bytes = &information_bytes[sid_offset..];
    let declared_bytes = usize::from(sid_bytes[1])
        .checked_mul(size_of::<u32>())
        .and_then(|bytes| bytes.checked_add(MIN_BINARY_SID_BYTES))
        .ok_or(KeyAgentLpacError::Attribute)?;
    if !(MIN_BINARY_SID_BYTES..=MAX_INSTALL_SID_BYTES).contains(&declared_bytes)
        || sid_offset
            .checked_add(declared_bytes)
            .ok_or(KeyAgentLpacError::Attribute)?
            > information_bytes.len()
    {
        return Err(KeyAgentLpacError::Attribute);
    }
    // SAFETY: the complete declared SID lies within the live token buffer.
    if !unsafe { IsValidSid(sid) }.as_bool()
        // SAFETY: IsValidSid accepted this complete bounded SID.
        || usize::try_from(unsafe { GetLengthSid(sid) })
            .map_err(|_| KeyAgentLpacError::Attribute)?
            != declared_bytes
    {
        return Err(KeyAgentLpacError::Attribute);
    }
    Ok(sid_bytes[..declared_bytes].to_vec())
}

fn creation_security_sid_string(sid: PSID) -> Result<String, KeyAgentLpacError> {
    let mut text = PWSTR::null();
    // SAFETY: the caller first bounded and validated this live token SID. The
    // successful output is one LocalAlloc NUL-terminated string.
    unsafe { ConvertSidToStringSidW(sid, &raw mut text) }
        .map_err(|_| KeyAgentLpacError::Attribute)?;
    if text.is_null() {
        return Err(KeyAgentLpacError::Attribute);
    }
    // SAFETY: successful conversion returned a live NUL-terminated string.
    let converted = unsafe { text.to_string() }.map_err(|_| KeyAgentLpacError::Attribute);
    // SAFETY: ConvertSidToStringSidW allocated this result with LocalAlloc.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(text.0.cast::<c_void>())));
    }
    converted
}

fn creation_security_wide_nul(value: &str) -> Result<Vec<u16>, KeyAgentLpacError> {
    let mut wide: Vec<u16> = value.encode_utf16().collect();
    if wide.is_empty() || wide.contains(&0) {
        return Err(KeyAgentLpacError::Attribute);
    }
    wide.push(0);
    Ok(wide)
}

fn verify_created_object_security(
    handle: HANDLE,
    expected_owner_sid: &[u8],
    expected_primary_group_sid: &[u8],
) -> Result<(), KeyAgentLpacError> {
    let descriptor_bytes = created_object_security_descriptor(handle)?;
    inspect_exact_creation_security_descriptor(
        &descriptor_bytes,
        expected_owner_sid,
        expected_primary_group_sid,
    )
}

fn created_object_security_descriptor(handle: HANDLE) -> Result<Vec<u8>, KeyAgentLpacError> {
    if invalid_handle(handle) {
        return Err(KeyAgentLpacError::Attribute);
    }
    let mut raw_handle_flags = u32::MAX;
    // SAFETY: the live creator-owned handle remains borrowed and output points
    // to exact HANDLE_FLAGS storage. No handle flag is permitted.
    unsafe { GetHandleInformation(handle, &raw mut raw_handle_flags) }
        .map_err(|_| KeyAgentLpacError::Attribute)?;
    validate_creation_handle_flags(HANDLE_FLAGS(raw_handle_flags))?;
    let requested_information =
        (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION).0;
    let mut first_required = 0_u32;
    // SAFETY: `handle` is the live creator-owned object handle. The null first
    // pass is the documented security-descriptor size query.
    let sizing = unsafe {
        GetKernelObjectSecurity(
            handle,
            requested_information,
            None,
            0,
            &raw mut first_required,
        )
    };
    if !matches!(
        sizing,
        Err(error) if error.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult()
    ) {
        return Err(KeyAgentLpacError::Attribute);
    }
    let required = usize::try_from(first_required).map_err(|_| KeyAgentLpacError::Attribute)?;
    if !(SELF_RELATIVE_SECURITY_DESCRIPTOR_BYTES..=MAX_CREATION_SECURITY_DESCRIPTOR_BYTES)
        .contains(&required)
    {
        return Err(KeyAgentLpacError::Attribute);
    }
    let word_bytes = size_of::<usize>();
    let word_count = required
        .checked_add(word_bytes.saturating_sub(1))
        .and_then(|rounded| rounded.checked_div(word_bytes))
        .ok_or(KeyAgentLpacError::Attribute)?;
    let mut words = vec![0_usize; word_count];
    let descriptor = PSECURITY_DESCRIPTOR(words.as_mut_ptr().cast::<c_void>());
    let mut second_required = 0_u32;
    // SAFETY: the aligned allocation has at least `first_required` writable
    // bytes and the same live creator handle remains borrowed for this query.
    unsafe {
        GetKernelObjectSecurity(
            handle,
            requested_information,
            Some(descriptor),
            first_required,
            &raw mut second_required,
        )
    }
    .map_err(|_| KeyAgentLpacError::Attribute)?;
    if second_required != first_required
        // SAFETY: the successful second pass initialized a complete descriptor.
        || !unsafe { IsValidSecurityDescriptor(descriptor) }.as_bool()
    {
        return Err(KeyAgentLpacError::Attribute);
    }
    // SAFETY: IsValidSecurityDescriptor accepted the complete live descriptor.
    let reported_length = usize::try_from(unsafe { GetSecurityDescriptorLength(descriptor) })
        .map_err(|_| KeyAgentLpacError::Attribute)?;
    if reported_length != required {
        return Err(KeyAgentLpacError::Attribute);
    }
    // SAFETY: the second pass initialized exactly `required` descriptor bytes.
    let descriptor_bytes =
        unsafe { core::slice::from_raw_parts(words.as_ptr().cast::<u8>(), required) };
    Ok(descriptor_bytes.to_vec())
}

fn validate_creation_handle_flags(handle_flags: HANDLE_FLAGS) -> Result<(), KeyAgentLpacError> {
    if handle_flags.0 == 0 {
        Ok(())
    } else {
        Err(KeyAgentLpacError::Attribute)
    }
}

fn inspect_exact_creation_security_descriptor(
    descriptor: &[u8],
    expected_owner_sid: &[u8],
    expected_primary_group_sid: &[u8],
) -> Result<(), KeyAgentLpacError> {
    validate_creation_security_sid_bytes(expected_owner_sid)?;
    validate_creation_security_sid_bytes(expected_primary_group_sid)?;
    if !(SELF_RELATIVE_SECURITY_DESCRIPTOR_BYTES..=MAX_CREATION_SECURITY_DESCRIPTOR_BYTES)
        .contains(&descriptor.len())
        || descriptor[0] != u8::try_from(SECURITY_DESCRIPTOR_REVISION).unwrap_or(u8::MAX)
        || descriptor[1] != 0
    {
        return Err(KeyAgentLpacError::Attribute);
    }
    let control = read_creation_security_u16_at(descriptor, 2)?;
    let required_control = SE_SELF_RELATIVE.0 | SE_DACL_PRESENT.0 | SE_DACL_PROTECTED.0;
    if control != required_control || read_creation_security_u32_at(descriptor, 12)? != 0 {
        return Err(KeyAgentLpacError::Attribute);
    }
    let owner_offset = usize::try_from(read_creation_security_u32_at(descriptor, 4)?)
        .map_err(|_| KeyAgentLpacError::Attribute)?;
    let primary_group_offset = usize::try_from(read_creation_security_u32_at(descriptor, 8)?)
        .map_err(|_| KeyAgentLpacError::Attribute)?;
    let dacl_offset = usize::try_from(read_creation_security_u32_at(descriptor, 16)?)
        .map_err(|_| KeyAgentLpacError::Attribute)?;
    let (owner_sid, owner_end) = creation_security_sid_component(descriptor, owner_offset)?;
    let (primary_group_sid, primary_group_end) =
        creation_security_sid_component(descriptor, primary_group_offset)?;
    if owner_sid != expected_owner_sid || primary_group_sid != expected_primary_group_sid {
        return Err(KeyAgentLpacError::Attribute);
    }

    let dacl_header_end = dacl_offset
        .checked_add(ACL_HEADER_BYTES)
        .ok_or(KeyAgentLpacError::Attribute)?;
    if dacl_offset < SELF_RELATIVE_SECURITY_DESCRIPTOR_BYTES
        || !dacl_offset.is_multiple_of(size_of::<u32>())
        || dacl_header_end > descriptor.len()
    {
        return Err(KeyAgentLpacError::Attribute);
    }
    let dacl_bytes = usize::from(read_creation_security_u16_at(descriptor, dacl_offset + 2)?);
    let dacl_end = dacl_offset
        .checked_add(dacl_bytes)
        .ok_or(KeyAgentLpacError::Attribute)?;
    if dacl_end > descriptor.len() {
        return Err(KeyAgentLpacError::Attribute);
    }
    let dacl = &descriptor[dacl_offset..dacl_end];
    let expected_acl_bytes = ACL_HEADER_BYTES
        .checked_add(ACCESS_DENIED_ACE_FIXED_BYTES)
        .and_then(|bytes| bytes.checked_add(OWNER_RIGHTS_SID_BYTES.len()))
        .ok_or(KeyAgentLpacError::Attribute)?;
    if dacl_bytes != expected_acl_bytes
        || u32::from(dacl[0]) != ACL_REVISION.0
        || dacl[1] != 0
        || read_creation_security_u16_at(dacl, 4)? != 1
        || read_creation_security_u16_at(dacl, 6)? != 0
    {
        return Err(KeyAgentLpacError::Attribute);
    }
    let ace_offset = ACL_HEADER_BYTES;
    let ace_size = usize::from(read_creation_security_u16_at(dacl, ace_offset + 2)?);
    let required_deny_ace_bytes = ACCESS_DENIED_ACE_FIXED_BYTES
        .checked_add(OWNER_RIGHTS_SID_BYTES.len())
        .ok_or(KeyAgentLpacError::Attribute)?;
    let ace_end = ace_offset
        .checked_add(ace_size)
        .ok_or(KeyAgentLpacError::Attribute)?;
    if dacl[ace_offset] != u8::try_from(ACCESS_DENIED_ACE_TYPE).unwrap_or(u8::MAX)
        || dacl[ace_offset + 1] != 0
        || ace_size != required_deny_ace_bytes
        || ace_end != dacl.len()
        || read_creation_security_u32_at(dacl, ace_offset + 4)? != CREATION_SECURITY_DENIED_ACCESS
    {
        return Err(KeyAgentLpacError::Attribute);
    }
    let owner_rights_sid = &dacl[ace_offset + ACCESS_DENIED_ACE_FIXED_BYTES..ace_end];
    validate_creation_security_sid_bytes(owner_rights_sid)?;
    if owner_rights_sid != OWNER_RIGHTS_SID_BYTES {
        return Err(KeyAgentLpacError::Attribute);
    }

    let mut regions = [
        (owner_offset, owner_end),
        (primary_group_offset, primary_group_end),
        (dacl_offset, dacl_end),
    ];
    regions.sort_unstable_by_key(|region| region.0);
    if regions[0].0 != SELF_RELATIVE_SECURITY_DESCRIPTOR_BYTES
        || regions[0].1 != regions[1].0
        || regions[1].1 != regions[2].0
        || regions[2].1 != descriptor.len()
    {
        return Err(KeyAgentLpacError::Attribute);
    }
    Ok(())
}

fn creation_security_sid_component(
    descriptor: &[u8],
    offset: usize,
) -> Result<(&[u8], usize), KeyAgentLpacError> {
    let minimum_end = offset
        .checked_add(MIN_BINARY_SID_BYTES)
        .ok_or(KeyAgentLpacError::Attribute)?;
    if offset < SELF_RELATIVE_SECURITY_DESCRIPTOR_BYTES
        || !offset.is_multiple_of(size_of::<u32>())
        || minimum_end > descriptor.len()
    {
        return Err(KeyAgentLpacError::Attribute);
    }
    let declared_bytes = usize::from(descriptor[offset + 1])
        .checked_mul(size_of::<u32>())
        .and_then(|bytes| bytes.checked_add(MIN_BINARY_SID_BYTES))
        .ok_or(KeyAgentLpacError::Attribute)?;
    let end = offset
        .checked_add(declared_bytes)
        .ok_or(KeyAgentLpacError::Attribute)?;
    let sid = descriptor
        .get(offset..end)
        .ok_or(KeyAgentLpacError::Attribute)?;
    validate_creation_security_sid_bytes(sid)?;
    Ok((sid, end))
}

fn validate_creation_security_sid_bytes(sid: &[u8]) -> Result<(), KeyAgentLpacError> {
    if !(MIN_BINARY_SID_BYTES..=MAX_INSTALL_SID_BYTES).contains(&sid.len()) || sid[0] != 1 {
        return Err(KeyAgentLpacError::Attribute);
    }
    let declared_bytes = usize::from(sid[1])
        .checked_mul(size_of::<u32>())
        .and_then(|bytes| bytes.checked_add(MIN_BINARY_SID_BYTES))
        .ok_or(KeyAgentLpacError::Attribute)?;
    if declared_bytes != sid.len() {
        return Err(KeyAgentLpacError::Attribute);
    }
    Ok(())
}

fn read_creation_security_u16_at(bytes: &[u8], offset: usize) -> Result<u16, KeyAgentLpacError> {
    let end = offset
        .checked_add(size_of::<u16>())
        .ok_or(KeyAgentLpacError::Attribute)?;
    let encoded: [u8; 2] = bytes
        .get(offset..end)
        .ok_or(KeyAgentLpacError::Attribute)?
        .try_into()
        .map_err(|_| KeyAgentLpacError::Attribute)?;
    Ok(u16::from_le_bytes(encoded))
}

fn read_creation_security_u32_at(bytes: &[u8], offset: usize) -> Result<u32, KeyAgentLpacError> {
    let end = offset
        .checked_add(size_of::<u32>())
        .ok_or(KeyAgentLpacError::Attribute)?;
    let encoded: [u8; 4] = bytes
        .get(offset..end)
        .ok_or(KeyAgentLpacError::Attribute)?
        .try_into()
        .map_err(|_| KeyAgentLpacError::Attribute)?;
    Ok(u32::from_le_bytes(encoded))
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

    /// Verifies the exact suspended zero-capability LPAC and installs only the
    /// protected token-object DACL before the child is allowed to load.
    ///
    /// The returned move-only authority retains a preauthenticated default-DACL
    /// adjustment handle and the final least-authority query handle. It must be
    /// consumed only at the authenticated in-process gate.
    pub(crate) fn prepare_suspended_process_for_gate(
        self,
        process: BorrowedHandle<'_>,
    ) -> Result<PendingKeyAgentLpac, KeyAgentLpacError> {
        verify_process_token(process, self.profile_sid.as_psid())?;
        let PreparedTokenObjectDacl {
            token: write_token,
            adjust_token,
            final_token,
            principals,
            provisional_baseline,
        } = install_approval_token_object_dacl(process, self.profile_sid.as_psid())?;

        // WRITE_DAC is needed only for the already-read-back token-object DACL.
        // Close it before any child code or delayed default-DACL mutation runs.
        write_token.close_checked()?;
        let pending = PendingKeyAgentLpac {
            token: final_token,
            adjust_token,
            profile_sid: self.profile_sid,
            principals,
            provisional_baseline,
            _same_thread: PhantomData,
        };
        pending.revalidate_current_process_token(process)?;
        Ok(pending)
    }
}

impl fmt::Debug for PreparedKeyAgentLpac {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedKeyAgentLpac([OPAQUE KEY AGENT LPAC])")
    }
}

/// Move-only authority prepared before loader execution and consumed at the
/// authenticated Key Agent gate.
///
/// `token` already has only query, duplicate, and read-control rights.
/// `adjust_token` has exactly query and default-adjustment rights and is never
/// exposed. Dropping this value closes both through their RAII owners; a failed
/// checked close during finalization is retried by the same owner on unwind.
pub(crate) struct PendingKeyAgentLpac {
    token: OwnedToken,
    adjust_token: OwnedToken,
    profile_sid: OwnedAppContainerSid,
    principals: ExactTokenDaclPrincipals,
    provisional_baseline: TokenIdentityBaseline,
    _same_thread: PhantomData<Rc<()>>,
}

impl PendingKeyAgentLpac {
    fn revalidate_current_process_token(
        &self,
        process: BorrowedHandle<'_>,
    ) -> Result<(), KeyAgentLpacError> {
        let retained_before = exact_token_statistics_baseline(self.token.0)?;
        require_same_token_identity(&self.provisional_baseline, &retained_before)?;
        verify_token_policy(self.token.0, self.profile_sid.as_psid())?;
        self.principals.verify_readback(self.token.0)?;
        let retained_after = exact_token_statistics_baseline(self.token.0)?;
        require_same_token_identity(&self.provisional_baseline, &retained_after)?;

        let current = open_process_token_with_access(process, TOKEN_QUERY)?;
        let current_proof = (|| {
            require_same_token_object(self.token.0, current.0)?;
            let current_identity = exact_token_statistics_baseline(current.0)?;
            require_same_token_identity(&self.provisional_baseline, &current_identity)
        })();
        let current_closed = current.close_checked();
        current_proof?;
        current_closed
    }

    /// Consumes the only retained default-adjustment authority at the caller's
    /// authenticated gate, installs and reads back the exact deny-only default
    /// DACL, then returns the final least-authority proof.
    pub(crate) fn finalize_after_gate(
        self,
        process: BorrowedHandle<'_>,
    ) -> Result<VerifiedKeyAgentLpac, KeyAgentLpacError> {
        self.revalidate_current_process_token(process)?;
        let Self {
            token,
            adjust_token,
            profile_sid,
            principals,
            provisional_baseline,
            _same_thread: _,
        } = self;

        let mut default_dacl_owner = OwnedExactTokenDefaultDacl::new()?;
        let default_dacl = ExactTokenDefaultDaclEvidence::from_owner(&default_dacl_owner)?;
        install_exact_token_default_dacl(adjust_token.0, &mut default_dacl_owner)?;
        default_dacl.verify_readback(adjust_token.0)?;
        let baseline = exact_token_statistics_baseline(token.0)?;
        require_same_token_id(&provisional_baseline, &baseline)?;

        // No handle with default-adjustment authority survives this point. A
        // CloseHandle failure keeps ownership through close_checked's Drop retry.
        adjust_token.close_checked()?;

        let retained_before = exact_token_statistics_baseline(token.0)?;
        require_same_token_identity(&baseline, &retained_before)?;
        verify_token_policy(token.0, profile_sid.as_psid())?;
        principals.verify_readback(token.0)?;
        default_dacl.verify_readback(token.0)?;
        let retained_after = exact_token_statistics_baseline(token.0)?;
        require_same_token_identity(&baseline, &retained_after)?;

        let current = open_process_token_with_access(process, TOKEN_QUERY)?;
        let current_proof = (|| {
            require_same_token_object(token.0, current.0)?;
            let current_identity = exact_token_statistics_baseline(current.0)?;
            require_same_token_identity(&baseline, &current_identity)
        })();
        let current_closed = current.close_checked();
        current_proof?;
        current_closed?;

        Ok(VerifiedKeyAgentLpac {
            token,
            profile_sid,
            principals,
            default_dacl,
            baseline,
        })
    }
}

impl fmt::Debug for PendingKeyAgentLpac {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingKeyAgentLpac([OPAQUE RETAINED TOKEN AUTHORITIES])")
    }
}

/// Opaque proof bound to the exact primary-token object whose Key Agent LPAC
/// policy, protected token-object DACL, and exact default DACL were verified.
///
/// The retained handle has query, duplicate, and read-control rights but no
/// DACL-writing authority. The value intentionally exposes neither its handle
/// nor its token/profile identities and is move-only.
pub(crate) struct VerifiedKeyAgentLpac {
    token: OwnedToken,
    profile_sid: OwnedAppContainerSid,
    principals: ExactTokenDaclPrincipals,
    default_dacl: ExactTokenDefaultDaclEvidence,
    baseline: TokenIdentityBaseline,
}

impl VerifiedKeyAgentLpac {
    /// Revalidates the retained token and proves that `process` still names
    /// that exact current primary-token object.
    pub(crate) fn revalidate_current_process_token(
        &self,
        process: BorrowedHandle<'_>,
    ) -> Result<(), KeyAgentLpacError> {
        let retained_before = exact_token_statistics_baseline(self.token.0)?;
        require_same_token_identity(&self.baseline, &retained_before)?;
        verify_token_policy(self.token.0, self.profile_sid.as_psid())?;
        self.principals.verify_readback(self.token.0)?;
        self.default_dacl.verify_readback(self.token.0)?;
        let retained_after = exact_token_statistics_baseline(self.token.0)?;
        require_same_token_identity(&self.baseline, &retained_after)?;

        let current = open_process_token_with_access(process, TOKEN_QUERY)?;
        let current_proof = (|| {
            require_same_token_object(self.token.0, current.0)?;
            let current_identity = exact_token_statistics_baseline(current.0)?;
            require_same_token_identity(&self.baseline, &current_identity)
        })();
        let current_closed = current.close_checked();
        current_proof?;
        current_closed
    }
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
        let source = std::env::current_exe().map_err(|_| KeyAgentLpacError::Profile)?;
        Self::create_from_executable(&source)
    }

    /// Copies one exact absolute regular executable into the same private
    /// profile-scoped fixture shape used by `create`.
    pub(crate) fn create_from_executable(source: &Path) -> Result<Self, KeyAgentLpacError> {
        let source_metadata =
            std::fs::symlink_metadata(source).map_err(|_| KeyAgentLpacError::Profile)?;
        if !source.is_absolute() || !source_metadata.file_type().is_file() {
            return Err(KeyAgentLpacError::Profile);
        }
        let profile_sid = OwnedAppContainerSid::open_or_create()?;
        let profile_folder = appcontainer_folder(&profile_sid)?;
        if !profile_folder.is_absolute() || !profile_folder.is_dir() {
            return Err(KeyAgentLpacError::Profile);
        }

        let directory = create_unique_fixture_directory(&profile_folder)?;
        let executable = directory.join("key-agent-kernel-test.exe");
        let result = apply_exact_fixture_dacl(&directory, profile_sid.as_psid())
            .and_then(|()| copy_executable_image(source, &executable))
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

/// Owns one as-yet-untrusted SID returned by a profile API.
///
/// The allocation is retained before the post-call impersonation check and is
/// released even when that check or subsequent SID validation fails.
struct UnvalidatedProfileApiSid {
    raw: Option<PSID>,
}

impl UnvalidatedProfileApiSid {
    const fn new(raw: PSID) -> Self {
        Self { raw: Some(raw) }
    }

    fn into_owned(self) -> Result<OwnedAppContainerSid, KeyAgentLpacError> {
        let raw = self.raw.ok_or(KeyAgentLpacError::Profile)?;
        // SAFETY: the SID came from a successful AppContainer profile API.
        if raw.is_invalid() || !unsafe { IsValidSid(raw) }.as_bool() {
            return Err(KeyAgentLpacError::Profile);
        }
        OwnedAppContainerSid::copy_from(raw)
    }
}

impl Drop for UnvalidatedProfileApiSid {
    fn drop(&mut self) {
        let Some(sid) = self.raw.take() else {
            return;
        };
        if sid.is_invalid() {
            return;
        }
        // SAFETY: every non-null success value remains owned by this guard and
        // must be released with FreeSid exactly once.
        unsafe {
            let _ = FreeSid(sid);
        }
    }
}

/// Owns one as-yet-untrusted `CoTaskMem` path returned by a profile API.
struct UnvalidatedProfileApiFolderPath {
    raw: Option<PWSTR>,
}

impl UnvalidatedProfileApiFolderPath {
    const fn new(raw: PWSTR) -> Self {
        Self { raw: Some(raw) }
    }

    fn to_path(&self) -> Result<PathBuf, KeyAgentLpacError> {
        let folder = self.raw.ok_or(KeyAgentLpacError::Profile)?;
        if folder.is_null() {
            return Err(KeyAgentLpacError::Profile);
        }
        // SAFETY: a successful non-null API result is NUL terminated and stays
        // owned by this wrapper for the complete conversion.
        unsafe { folder.to_string() }
            .map(PathBuf::from)
            .map_err(|_| KeyAgentLpacError::Profile)
    }
}

impl Drop for UnvalidatedProfileApiFolderPath {
    fn drop(&mut self) {
        let Some(folder) = self.raw.take() else {
            return;
        };
        if folder.is_null() {
            return;
        }
        // SAFETY: GetAppContainerFolderPath allocates this result with
        // CoTaskMemAlloc and ownership has not escaped this wrapper.
        unsafe { CoTaskMemFree(Some(folder.0.cast::<c_void>())) };
    }
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

        profile_api
            .recheck_thread()
            .map_err(|_| KeyAgentLpacError::Profile)?;
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
        .map(UnvalidatedProfileApiSid::new);
        profile_api
            .recheck_thread()
            .map_err(|_| KeyAgentLpacError::Profile)?;
        let created_sid = created_sid.map_err(|_| KeyAgentLpacError::Profile)?;
        let created = created_sid.into_owned()?;
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

        profile_api
            .recheck_thread()
            .map_err(|_| KeyAgentLpacError::Profile)?;
        // SAFETY: all strings are NUL terminated and there are deliberately no
        // capability SIDs. A successful returned SID belongs to the caller.
        let created = unsafe {
            CreateAppContainerProfile(
                PCWSTR(name.as_ptr()),
                PCWSTR(display_name.as_ptr()),
                PCWSTR(description.as_ptr()),
                None,
            )
        }
        .map(UnvalidatedProfileApiSid::new);
        profile_api
            .recheck_thread()
            .map_err(|_| KeyAgentLpacError::Profile)?;
        match created {
            Ok(created_sid) => {
                let created = created_sid.into_owned()?;
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
        profile_api: &AppContainerProfileApiGuard,
        name: &[u16],
    ) -> Result<Self, KeyAgentLpacError> {
        profile_api
            .recheck_thread()
            .map_err(|_| KeyAgentLpacError::Profile)?;
        // SAFETY: callers pass a live NUL-terminated profile name.
        let sid = unsafe { DeriveAppContainerSidFromAppContainerName(PCWSTR(name.as_ptr())) }
            .map(UnvalidatedProfileApiSid::new);
        profile_api
            .recheck_thread()
            .map_err(|_| KeyAgentLpacError::Profile)?;
        sid.map_err(|_| KeyAgentLpacError::Profile)?.into_owned()
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

    fn close_checked(mut self) -> Result<(), KeyAgentLpacError> {
        let handle = self.0;
        // SAFETY: this wrapper exclusively owns the live handle. On failure,
        // `self` remains owned and its ordinary Drop retries the close. Only a
        // successful close clears the field before ordinary Drop observes it.
        unsafe { CloseHandle(handle) }.map_err(|_| KeyAgentLpacError::Token)?;
        self.0 = HANDLE::default();
        Ok(())
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

struct ExactTokenDaclPrincipals {
    user: Vec<u8>,
    key_agent: Vec<u8>,
    approval: Vec<u8>,
}

#[repr(transparent)]
struct OwnedExactTokenDefaultDacl {
    words: [u32; EXACT_TOKEN_DEFAULT_DACL_WORDS],
}

impl OwnedExactTokenDefaultDacl {
    fn new() -> Result<Self, KeyAgentLpacError> {
        let mut owner = Self {
            words: [0_u32; EXACT_TOKEN_DEFAULT_DACL_WORDS],
        };
        let bytes = owner.bytes_mut();
        bytes[0] = u8::try_from(ACL_REVISION.0).map_err(|_| KeyAgentLpacError::Token)?;
        bytes[1] = 0;
        bytes[2..4].copy_from_slice(
            &u16::try_from(EXACT_TOKEN_DEFAULT_DACL_BYTES)
                .map_err(|_| KeyAgentLpacError::Token)?
                .to_le_bytes(),
        );
        bytes[4..6].copy_from_slice(&1_u16.to_le_bytes());
        bytes[6..8].copy_from_slice(&0_u16.to_le_bytes());
        bytes[8] = u8::try_from(ACCESS_DENIED_ACE_TYPE).map_err(|_| KeyAgentLpacError::Token)?;
        bytes[9] = 0;
        bytes[10..12].copy_from_slice(
            &u16::try_from(ACCESS_DENIED_ACE_FIXED_BYTES + OWNER_RIGHTS_SID_BYTES.len())
                .map_err(|_| KeyAgentLpacError::Token)?
                .to_le_bytes(),
        );
        bytes[12..16].copy_from_slice(&CREATION_SECURITY_DENIED_ACCESS.to_le_bytes());
        bytes[16..].copy_from_slice(&OWNER_RIGHTS_SID_BYTES);
        inspect_exact_token_default_dacl_bytes(bytes)?;
        Ok(owner)
    }

    fn bytes(&self) -> &[u8; EXACT_TOKEN_DEFAULT_DACL_BYTES] {
        // SAFETY: the `[u32; 7]` backing allocation is initialized, exactly 28
        // bytes long, and every possible byte pattern is valid through `u8`.
        unsafe { &*ptr::from_ref(&self.words).cast::<[u8; EXACT_TOKEN_DEFAULT_DACL_BYTES]>() }
    }

    fn bytes_mut(&mut self) -> &mut [u8; EXACT_TOKEN_DEFAULT_DACL_BYTES] {
        // SAFETY: same exact layout as `bytes`; the exclusive borrow prevents
        // any typed `u32` access while the byte representation is populated.
        unsafe {
            &mut *ptr::from_mut(&mut self.words).cast::<[u8; EXACT_TOKEN_DEFAULT_DACL_BYTES]>()
        }
    }

    fn as_acl_mut_ptr(&mut self) -> *mut ACL {
        self.words.as_mut_ptr().cast::<ACL>()
    }
}

struct ExactTokenDefaultDaclEvidence {
    bytes: [u8; EXACT_TOKEN_DEFAULT_DACL_BYTES],
}

impl ExactTokenDefaultDaclEvidence {
    fn from_owner(owner: &OwnedExactTokenDefaultDacl) -> Result<Self, KeyAgentLpacError> {
        inspect_exact_token_default_dacl_bytes(owner.bytes())?;
        Ok(Self {
            bytes: *owner.bytes(),
        })
    }

    fn verify_readback(&self, token: HANDLE) -> Result<(), KeyAgentLpacError> {
        verify_exact_token_default_dacl_readback(token, &self.bytes)
    }
}

impl fmt::Debug for ExactTokenDefaultDaclEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExactTokenDefaultDaclEvidence([VERIFIED])")
    }
}

impl ExactTokenDaclPrincipals {
    fn verify_readback(&self, token: HANDLE) -> Result<(), KeyAgentLpacError> {
        verify_installed_token_dacl_readback(token, &self.user, &self.key_agent, &self.approval)
    }
}

impl fmt::Debug for ExactTokenDaclPrincipals {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExactTokenDaclPrincipals([REDACTED])")
    }
}

struct TokenLuidBaseline {
    low_part: u32,
    high_part: i32,
}

struct TokenIdentityBaseline {
    token_id: TokenLuidBaseline,
    modified_id: TokenLuidBaseline,
}

impl fmt::Debug for TokenIdentityBaseline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TokenIdentityBaseline([REDACTED])")
    }
}

struct PreparedTokenObjectDacl {
    token: OwnedToken,
    adjust_token: OwnedToken,
    final_token: OwnedToken,
    principals: ExactTokenDaclPrincipals,
    provisional_baseline: TokenIdentityBaseline,
}

fn install_approval_token_object_dacl(
    process: BorrowedHandle<'_>,
    key_agent_sid: PSID,
) -> Result<PreparedTokenObjectDacl, KeyAgentLpacError> {
    let desired = TOKEN_ACCESS_MASK(TOKEN_QUERY.0 | WRITE_DAC.0 | READ_CONTROL.0);
    let token = open_process_token_with_access(process, desired)?;
    let adjust_access = TOKEN_ACCESS_MASK(TOKEN_QUERY.0 | TOKEN_ADJUST_DEFAULT.0);
    let adjust_token = open_process_token_with_access(process, adjust_access)?;
    require_same_token_object(token.0, adjust_token.0)?;
    let final_access = TOKEN_ACCESS_MASK(TOKEN_QUERY.0 | TOKEN_DUPLICATE.0 | READ_CONTROL.0);
    let final_token = open_process_token_with_access(process, final_access)?;
    require_same_token_object(token.0, final_token.0)?;

    let user_information = token_information(token.0, TokenUser)?;
    if user_information.returned_bytes < size_of::<TOKEN_USER>() {
        return Err(KeyAgentLpacError::Token);
    }
    // SAFETY: aligned storage contains the complete returned TOKEN_USER prefix.
    let user = unsafe { ptr::read_unaligned(user_information.words.as_ptr().cast::<TOKEN_USER>()) };
    let approval = OwnedAppContainerSid::derive(&wide_nul_str(APPROVAL_PROFILE_V1_NAME)?)?;
    // SAFETY: both profile SID owners remain live and valid.
    if unsafe { EqualSid(key_agent_sid, approval.as_psid()) }.is_ok() {
        return Err(KeyAgentLpacError::Token);
    }

    let principals = ExactTokenDaclPrincipals {
        user: copied_sid_bytes(user.User.Sid)?,
        key_agent: copied_sid_bytes(key_agent_sid)?,
        approval: copied_sid_bytes(approval.as_psid())?,
    };
    let user_sid = sid_string(user.User.Sid)?;
    let key_agent_sid_string = sid_string(key_agent_sid)?;
    let approval_sid = sid_string(approval.as_psid())?;
    let sddl = wide_nul_str(&format!(
        "D:P(A;;0x{SUPERVISOR_TOKEN_ACCESS:08x};;;{user_sid})(A;;0x{KEY_AGENT_TOKEN_SELF_ACCESS:08x};;;{key_agent_sid_string})(A;;0x{APPROVAL_PARENT_TOKEN_ACCESS:08x};;;{approval_sid})",
    ))?;
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the exact generated SDDL is live and NUL terminated; output
    // receives one LocalAlloc-owned self-relative descriptor.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &raw mut descriptor,
            None,
        )
    }
    .map_err(|_| KeyAgentLpacError::Token)?;
    // SAFETY: the conversion above returned a live descriptor allocation.
    let valid = unsafe { IsValidSecurityDescriptor(descriptor) }.as_bool();
    let applied = if valid {
        // SAFETY: the owned token and validated descriptor remain live. The
        // caller retains the new process stopped; production performs this while
        // the CREATE_PROCESS debug event is still uncontinued.
        unsafe {
            SetKernelObjectSecurity(
                token.0,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor,
            )
        }
        .map_err(|_| KeyAgentLpacError::Token)
    } else {
        Err(KeyAgentLpacError::Token)
    };
    // SAFETY: the SDDL conversion allocated this descriptor with LocalAlloc.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
    }
    applied?;
    principals.verify_readback(token.0)?;
    let provisional_baseline = exact_token_statistics_baseline(final_token.0)?;
    Ok(PreparedTokenObjectDacl {
        token,
        adjust_token,
        final_token,
        principals,
        provisional_baseline,
    })
}

fn install_exact_token_default_dacl(
    token: HANDLE,
    owner: &mut OwnedExactTokenDefaultDacl,
) -> Result<(), KeyAgentLpacError> {
    if size_of::<OwnedExactTokenDefaultDacl>() != EXACT_TOKEN_DEFAULT_DACL_BYTES
        || !(owner.as_acl_mut_ptr() as usize).is_multiple_of(align_of::<ACL>())
    {
        return Err(KeyAgentLpacError::Token);
    }
    inspect_exact_token_default_dacl_bytes(owner.bytes())?;
    let information = TOKEN_DEFAULT_DACL {
        DefaultDacl: owner.as_acl_mut_ptr(),
    };
    // SAFETY: `token` is the separately authenticated live handle with exactly
    // TOKEN_QUERY | TOKEN_ADJUST_DEFAULT. The pointer-bearing wrapper and its
    // exact aligned ACL owner remain live for the complete synchronous call.
    unsafe {
        SetTokenInformation(
            token,
            TokenDefaultDacl,
            ptr::from_ref(&information).cast::<c_void>(),
            u32::try_from(size_of::<TOKEN_DEFAULT_DACL>()).map_err(|_| KeyAgentLpacError::Token)?,
        )
    }
    .map_err(|_| KeyAgentLpacError::Token)
}

/// Independently proves that the current process already carries the exact
/// fixed zero-capability Key Agent LPAC policy before it may enter the debugger
/// gate.
///
/// Ordinary non-AppContainer execution fails this check without executing the
/// intentional breakpoint, preserving the release-disabled binary contract.
/// The query opens only the current process token and checked-closes that fresh
/// handle before returning.
pub(crate) fn verify_current_key_agent_lpac_before_gate() -> Result<(), KeyAgentLpacError> {
    let profile_sid = OwnedAppContainerSid::derive_fixed()?;
    // SAFETY: GetCurrentProcess returns the process-lifetime pseudo handle and
    // this borrow cannot escape the function.
    let process = unsafe { BorrowedHandle::borrow_raw(GetCurrentProcess().0) };
    let token = open_process_token_with_access(process, TOKEN_QUERY | TOKEN_DUPLICATE)?;
    let verified = verify_token_policy(token.0, profile_sid.as_psid());
    let closed = token.close_checked();
    verified?;
    closed
}

/// Independently verifies the exact deny-only default DACL after the Key Agent
/// has crossed its authenticated debugger gate.
///
/// This child-side proof opens a fresh current-process token handle with only
/// `TOKEN_QUERY`; it neither depends on nor can reuse the supervisor's retained
/// adjustment authority.
pub(crate) fn verify_current_key_agent_default_dacl_after_gate() -> Result<(), KeyAgentLpacError> {
    // SAFETY: GetCurrentProcess returns the process-lifetime pseudo handle and
    // this borrow cannot escape the function.
    let process = unsafe { BorrowedHandle::borrow_raw(GetCurrentProcess().0) };
    let token = open_process_token_with_access(process, TOKEN_QUERY)?;
    let owner = OwnedExactTokenDefaultDacl::new()?;
    let evidence = ExactTokenDefaultDaclEvidence::from_owner(&owner)?;
    let verified = evidence.verify_readback(token.0);
    let closed = token.close_checked();
    verified?;
    closed
}

fn copied_sid_bytes(sid: PSID) -> Result<Vec<u8>, KeyAgentLpacError> {
    if sid.0.is_null() {
        return Err(KeyAgentLpacError::Token);
    }
    // SAFETY: the SID pointer comes from one live token-information buffer or
    // one retained profile SID owner.
    if !unsafe { IsValidSid(sid) }.as_bool() {
        return Err(KeyAgentLpacError::Token);
    }
    // SAFETY: IsValidSid accepted this complete live SID.
    let length =
        usize::try_from(unsafe { GetLengthSid(sid) }).map_err(|_| KeyAgentLpacError::Token)?;
    if !(MIN_BINARY_SID_BYTES..=MAX_INSTALL_SID_BYTES).contains(&length) {
        return Err(KeyAgentLpacError::Token);
    }
    // SAFETY: the validated SID reports this exact readable byte length and
    // its backing owner remains live for the complete copy.
    Ok(unsafe { core::slice::from_raw_parts(sid.0.cast::<u8>(), length) }.to_vec())
}

fn verify_installed_token_dacl_readback(
    token: HANDLE,
    expected_user_sid: &[u8],
    expected_key_agent_sid: &[u8],
    expected_approval_sid: &[u8],
) -> Result<(), KeyAgentLpacError> {
    let mut first_required = 0_u32;
    // SAFETY: `token` is live with READ_CONTROL. A null first-pass buffer is
    // the documented bounded-size query contract.
    let size_query = unsafe {
        GetKernelObjectSecurity(
            token,
            DACL_SECURITY_INFORMATION.0,
            None,
            0,
            &raw mut first_required,
        )
    };
    if !matches!(
        size_query,
        Err(error) if error.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult()
    ) {
        return Err(KeyAgentLpacError::Token);
    }
    let required = usize::try_from(first_required).map_err(|_| KeyAgentLpacError::Token)?;
    if required == 0 || required > MAX_TOKEN_SECURITY_DESCRIPTOR_BYTES {
        return Err(KeyAgentLpacError::Token);
    }
    let word_bytes = size_of::<usize>();
    let word_count = required
        .checked_add(word_bytes.saturating_sub(1))
        .ok_or(KeyAgentLpacError::Token)?
        / word_bytes;
    let mut words = vec![0_usize; word_count];
    let descriptor = PSECURITY_DESCRIPTOR(words.as_mut_ptr().cast::<c_void>());
    let mut second_required = 0_u32;
    // SAFETY: the aligned allocation has at least `first_required` writable
    // bytes, and the same queried token handle remains live.
    unsafe {
        GetKernelObjectSecurity(
            token,
            DACL_SECURITY_INFORMATION.0,
            Some(descriptor),
            first_required,
            &raw mut second_required,
        )
    }
    .map_err(|_| KeyAgentLpacError::Token)?;
    if second_required != first_required {
        return Err(KeyAgentLpacError::Token);
    }
    // SAFETY: the second pass initialized a complete descriptor in this live,
    // aligned allocation.
    if !unsafe { IsValidSecurityDescriptor(descriptor) }.as_bool() {
        return Err(KeyAgentLpacError::Token);
    }
    // SAFETY: IsValidSecurityDescriptor accepted the complete live descriptor.
    let reported_length = usize::try_from(unsafe { GetSecurityDescriptorLength(descriptor) })
        .map_err(|_| KeyAgentLpacError::Token)?;
    if reported_length != required {
        return Err(KeyAgentLpacError::Token);
    }
    // SAFETY: the bounded allocation contains exactly `required` initialized
    // descriptor bytes after the successful second pass.
    let descriptor_bytes =
        unsafe { core::slice::from_raw_parts(words.as_ptr().cast::<u8>(), required) };
    inspect_exact_token_dacl_descriptor(
        descriptor_bytes,
        expected_user_sid,
        expected_key_agent_sid,
        expected_approval_sid,
    )
}

fn inspect_exact_token_dacl_descriptor(
    descriptor: &[u8],
    expected_user_sid: &[u8],
    expected_key_agent_sid: &[u8],
    expected_approval_sid: &[u8],
) -> Result<(), KeyAgentLpacError> {
    if descriptor.len() < SELF_RELATIVE_SECURITY_DESCRIPTOR_BYTES
        || descriptor[0] != u8::try_from(SECURITY_DESCRIPTOR_REVISION).unwrap_or(u8::MAX)
        || descriptor[1] != 0
    {
        return Err(KeyAgentLpacError::Token);
    }
    let control = read_u16_at(descriptor, 2)?;
    let required_control = SE_SELF_RELATIVE.0 | SE_DACL_PRESENT.0 | SE_DACL_PROTECTED.0;
    if control != required_control {
        return Err(KeyAgentLpacError::Token);
    }
    if read_u32_at(descriptor, 4)? != 0
        || read_u32_at(descriptor, 8)? != 0
        || read_u32_at(descriptor, 12)? != 0
    {
        return Err(KeyAgentLpacError::Token);
    }
    let dacl_offset =
        usize::try_from(read_u32_at(descriptor, 16)?).map_err(|_| KeyAgentLpacError::Token)?;
    if dacl_offset != SELF_RELATIVE_SECURITY_DESCRIPTOR_BYTES {
        return Err(KeyAgentLpacError::Token);
    }
    let dacl = descriptor
        .get(dacl_offset..)
        .ok_or(KeyAgentLpacError::Token)?;
    if dacl.len() < ACL_HEADER_BYTES
        || u32::from(dacl[0]) != ACL_REVISION.0
        || dacl[1] != 0
        || read_u16_at(dacl, 4)? != 3
        || read_u16_at(dacl, 6)? != 0
    {
        return Err(KeyAgentLpacError::Token);
    }
    let acl_total = usize::from(read_u16_at(dacl, 2)?);
    if acl_total != dacl.len() {
        return Err(KeyAgentLpacError::Token);
    }

    let expected = [
        (expected_user_sid, SUPERVISOR_TOKEN_ACCESS),
        (expected_key_agent_sid, KEY_AGENT_TOKEN_SELF_ACCESS),
        (expected_approval_sid, APPROVAL_PARENT_TOKEN_ACCESS),
    ];
    let mut used = ACL_HEADER_BYTES;
    for (expected_sid, expected_mask) in expected {
        validate_binary_sid_bytes(expected_sid)?;
        let fixed_end = used
            .checked_add(ACCESS_ALLOWED_ACE_FIXED_BYTES)
            .ok_or(KeyAgentLpacError::Token)?;
        if fixed_end > acl_total {
            return Err(KeyAgentLpacError::Token);
        }
        let ace_type = u8::try_from(ACCESS_ALLOWED_ACE_TYPE).unwrap_or(u8::MAX);
        let ace_size = usize::from(read_u16_at(dacl, used + 2)?);
        let ace_end = used.checked_add(ace_size).ok_or(KeyAgentLpacError::Token)?;
        if dacl[used] != ace_type
            || dacl[used + 1] != 0
            || ace_size < ACCESS_ALLOWED_ACE_FIXED_BYTES + MIN_BINARY_SID_BYTES
            || ace_end > acl_total
            || read_u32_at(dacl, used + 4)? != expected_mask
        {
            return Err(KeyAgentLpacError::Token);
        }
        let actual_sid = &dacl[fixed_end..ace_end];
        validate_binary_sid_bytes(actual_sid)?;
        if actual_sid != expected_sid {
            return Err(KeyAgentLpacError::Token);
        }
        used = ace_end;
    }
    let free = acl_total
        .checked_sub(used)
        .ok_or(KeyAgentLpacError::Token)?;
    if used != acl_total || free != 0 {
        return Err(KeyAgentLpacError::Token);
    }
    Ok(())
}

fn validate_binary_sid_bytes(sid: &[u8]) -> Result<(), KeyAgentLpacError> {
    if !(MIN_BINARY_SID_BYTES..=MAX_INSTALL_SID_BYTES).contains(&sid.len()) || sid[0] != 1 {
        return Err(KeyAgentLpacError::Token);
    }
    let declared = usize::from(sid[1])
        .checked_mul(size_of::<u32>())
        .and_then(|bytes| bytes.checked_add(MIN_BINARY_SID_BYTES))
        .ok_or(KeyAgentLpacError::Token)?;
    if declared != sid.len() {
        return Err(KeyAgentLpacError::Token);
    }
    Ok(())
}

fn read_u16_at(bytes: &[u8], offset: usize) -> Result<u16, KeyAgentLpacError> {
    let end = offset
        .checked_add(size_of::<u16>())
        .ok_or(KeyAgentLpacError::Token)?;
    let encoded: [u8; 2] = bytes
        .get(offset..end)
        .ok_or(KeyAgentLpacError::Token)?
        .try_into()
        .map_err(|_| KeyAgentLpacError::Token)?;
    Ok(u16::from_le_bytes(encoded))
}

fn read_u32_at(bytes: &[u8], offset: usize) -> Result<u32, KeyAgentLpacError> {
    let end = offset
        .checked_add(size_of::<u32>())
        .ok_or(KeyAgentLpacError::Token)?;
    let encoded: [u8; 4] = bytes
        .get(offset..end)
        .ok_or(KeyAgentLpacError::Token)?
        .try_into()
        .map_err(|_| KeyAgentLpacError::Token)?;
    Ok(u32::from_le_bytes(encoded))
}

fn open_process_token_with_access(
    process: BorrowedHandle<'_>,
    desired_access: TOKEN_ACCESS_MASK,
) -> Result<OwnedToken, KeyAgentLpacError> {
    let mut raw_token = HANDLE::default();
    // SAFETY: `process` is a live process-handle borrow and output receives one
    // exclusively owned token handle with exactly `desired_access` requested.
    unsafe {
        OpenProcessToken(
            HANDLE(process.as_raw_handle()),
            desired_access,
            &raw mut raw_token,
        )
    }
    .map_err(|_| KeyAgentLpacError::Token)?;
    OwnedToken::new(raw_token)
}

fn token_identity_from_statistics(
    statistics: &TOKEN_STATISTICS,
    returned_bytes: usize,
) -> Result<TokenIdentityBaseline, KeyAgentLpacError> {
    if returned_bytes != size_of::<TOKEN_STATISTICS>() || statistics.TokenType != TokenPrimary {
        return Err(KeyAgentLpacError::Token);
    }
    Ok(TokenIdentityBaseline {
        token_id: TokenLuidBaseline {
            low_part: statistics.TokenId.LowPart,
            high_part: statistics.TokenId.HighPart,
        },
        modified_id: TokenLuidBaseline {
            low_part: statistics.ModifiedId.LowPart,
            high_part: statistics.ModifiedId.HighPart,
        },
    })
}

fn exact_token_statistics_baseline(
    token: HANDLE,
) -> Result<TokenIdentityBaseline, KeyAgentLpacError> {
    let mut statistics = TOKEN_STATISTICS::default();
    let mut returned = 0_u32;
    let exact_bytes =
        u32::try_from(size_of::<TOKEN_STATISTICS>()).map_err(|_| KeyAgentLpacError::Token)?;
    // SAFETY: `token` is live with TOKEN_QUERY and output is exact, aligned
    // TOKEN_STATISTICS storage. The returned byte count is checked exactly.
    unsafe {
        GetTokenInformation(
            token,
            TokenStatistics,
            Some(ptr::from_mut(&mut statistics).cast::<c_void>()),
            exact_bytes,
            &raw mut returned,
        )
    }
    .map_err(|_| KeyAgentLpacError::Token)?;
    token_identity_from_statistics(
        &statistics,
        usize::try_from(returned).map_err(|_| KeyAgentLpacError::Token)?,
    )
}

fn require_same_token_identity(
    expected: &TokenIdentityBaseline,
    observed: &TokenIdentityBaseline,
) -> Result<(), KeyAgentLpacError> {
    if expected.token_id.low_part != observed.token_id.low_part
        || expected.token_id.high_part != observed.token_id.high_part
        || expected.modified_id.low_part != observed.modified_id.low_part
        || expected.modified_id.high_part != observed.modified_id.high_part
    {
        return Err(KeyAgentLpacError::Token);
    }
    Ok(())
}

fn require_same_token_id(
    expected: &TokenIdentityBaseline,
    observed: &TokenIdentityBaseline,
) -> Result<(), KeyAgentLpacError> {
    if expected.token_id.low_part != observed.token_id.low_part
        || expected.token_id.high_part != observed.token_id.high_part
    {
        return Err(KeyAgentLpacError::Token);
    }
    Ok(())
}

fn require_same_token_object(first: HANDLE, second: HANDLE) -> Result<(), KeyAgentLpacError> {
    if invalid_handle(first) || invalid_handle(second) {
        return Err(KeyAgentLpacError::Token);
    }
    // SAFETY: both handles are live for this call. BOOL false rejects either a
    // different kernel object or an inability to establish object continuity.
    if !unsafe { CompareObjectHandles(first, second) }.as_bool() {
        return Err(KeyAgentLpacError::Token);
    }
    Ok(())
}

fn verify_process_token(
    process: BorrowedHandle<'_>,
    expected_sid: PSID,
) -> Result<(), KeyAgentLpacError> {
    let token = open_process_token_with_access(process, TOKEN_QUERY | TOKEN_DUPLICATE)?;
    verify_token_policy(token.0, expected_sid)
}

fn verify_token_policy(token: HANDLE, expected_sid: PSID) -> Result<(), KeyAgentLpacError> {
    let is_appcontainer = token_dword(token, TokenIsAppContainer)?;
    let is_lpac = less_privileged_appcontainer_dword(token)?;

    let sid_information = token_information(token, TokenAppContainerSid)?;
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

    let capability_information = token_information(token, TokenCapabilities)?;
    if capability_information.returned_bytes < size_of::<u32>() {
        return Err(KeyAgentLpacError::Token);
    }
    // SAFETY: aligned word storage contains the returned leading GroupCount.
    let capability_count =
        unsafe { ptr::read_unaligned(capability_information.words.as_ptr().cast::<u32>()) };

    let membership = appcontainer_membership_evidence(token)?;

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

fn verify_exact_token_default_dacl_readback(
    token: HANDLE,
    expected_acl: &[u8; EXACT_TOKEN_DEFAULT_DACL_BYTES],
) -> Result<(), KeyAgentLpacError> {
    let information = token_information(token, TokenDefaultDacl)?;
    inspect_exact_token_default_dacl_information(&information, expected_acl)
}

fn inspect_exact_token_default_dacl_information(
    information: &TokenInformation,
    expected_acl: &[u8; EXACT_TOKEN_DEFAULT_DACL_BYTES],
) -> Result<(), KeyAgentLpacError> {
    let prefix_bytes = size_of::<TOKEN_DEFAULT_DACL>();
    let allocation_bytes = information
        .words
        .len()
        .checked_mul(size_of::<usize>())
        .ok_or(KeyAgentLpacError::Token)?;
    if information.returned_bytes < prefix_bytes
        || information.returned_bytes > allocation_bytes
        || information.words.is_empty()
    {
        return Err(KeyAgentLpacError::Token);
    }

    let buffer_start = information.words.as_ptr() as usize;
    if !buffer_start.is_multiple_of(align_of::<TOKEN_DEFAULT_DACL>()) {
        return Err(KeyAgentLpacError::Token);
    }
    let prefix_end = buffer_start
        .checked_add(prefix_bytes)
        .ok_or(KeyAgentLpacError::Token)?;
    let buffer_end = buffer_start
        .checked_add(information.returned_bytes)
        .ok_or(KeyAgentLpacError::Token)?;
    if prefix_end > buffer_end {
        return Err(KeyAgentLpacError::Token);
    }

    // SAFETY: the allocation and exact returned range were checked above; its
    // `Vec<usize>` backing satisfies TOKEN_DEFAULT_DACL alignment and contains
    // the complete fixed prefix. This reads only the pointer value, not its ACL.
    let default_dacl =
        unsafe { ptr::read(information.words.as_ptr().cast::<TOKEN_DEFAULT_DACL>()) };
    if default_dacl.DefaultDacl.is_null() {
        return Err(KeyAgentLpacError::Token);
    }
    let acl_start = default_dacl.DefaultDacl as usize;
    if !acl_start.is_multiple_of(align_of::<ACL>()) {
        return Err(KeyAgentLpacError::Token);
    }
    let acl_header_end = acl_start
        .checked_add(ACL_HEADER_BYTES)
        .ok_or(KeyAgentLpacError::Token)?;
    if acl_start < prefix_end || acl_header_end > buffer_end {
        return Err(KeyAgentLpacError::Token);
    }

    // SAFETY: only after null, alignment, overflow, and returned-range checks do
    // we inspect the fixed ACL header needed to establish the complete length.
    let acl_header = unsafe {
        core::slice::from_raw_parts(default_dacl.DefaultDacl.cast::<u8>(), ACL_HEADER_BYTES)
    };
    let acl_bytes = usize::from(read_u16_at(acl_header, 2)?);
    if acl_bytes != EXACT_TOKEN_DEFAULT_DACL_BYTES {
        return Err(KeyAgentLpacError::Token);
    }
    let acl_end = acl_start
        .checked_add(acl_bytes)
        .ok_or(KeyAgentLpacError::Token)?;
    if acl_end > buffer_end {
        return Err(KeyAgentLpacError::Token);
    }

    // SAFETY: the validated header declares the exact policy length, and the
    // complete range was independently proven to lie inside returned bytes.
    let acl =
        unsafe { core::slice::from_raw_parts(default_dacl.DefaultDacl.cast::<u8>(), acl_bytes) };
    inspect_exact_token_default_dacl_bytes(acl)?;
    if acl != expected_acl {
        return Err(KeyAgentLpacError::Token);
    }
    Ok(())
}

fn inspect_exact_token_default_dacl_bytes(acl: &[u8]) -> Result<(), KeyAgentLpacError> {
    if acl.len() != EXACT_TOKEN_DEFAULT_DACL_BYTES
        || u32::from(acl[0]) != ACL_REVISION.0
        || acl[1] != 0
        || usize::from(read_u16_at(acl, 2)?) != EXACT_TOKEN_DEFAULT_DACL_BYTES
        || read_u16_at(acl, 4)? != 1
        || read_u16_at(acl, 6)? != 0
    {
        return Err(KeyAgentLpacError::Token);
    }

    let ace_offset = ACL_HEADER_BYTES;
    let ace_size = usize::from(read_u16_at(acl, ace_offset + 2)?);
    let exact_ace_size = ACCESS_DENIED_ACE_FIXED_BYTES
        .checked_add(OWNER_RIGHTS_SID_BYTES.len())
        .ok_or(KeyAgentLpacError::Token)?;
    let ace_end = ace_offset
        .checked_add(ace_size)
        .ok_or(KeyAgentLpacError::Token)?;
    if acl[ace_offset] != u8::try_from(ACCESS_DENIED_ACE_TYPE).unwrap_or(u8::MAX)
        || acl[ace_offset + 1] != 0
        || ace_size != exact_ace_size
        || ace_end != acl.len()
        || read_u32_at(acl, ace_offset + 4)? != CREATION_SECURITY_DENIED_ACCESS
    {
        return Err(KeyAgentLpacError::Token);
    }
    let sid = acl
        .get(ace_offset + ACCESS_DENIED_ACE_FIXED_BYTES..ace_end)
        .ok_or(KeyAgentLpacError::Token)?;
    validate_binary_sid_bytes(sid)?;
    if sid != OWNER_RIGHTS_SID_BYTES {
        return Err(KeyAgentLpacError::Token);
    }
    Ok(())
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
    let profile_api = acquire_appcontainer_profile_api().map_err(|_| KeyAgentLpacError::Profile)?;
    profile_api
        .recheck_thread()
        .map_err(|_| KeyAgentLpacError::Profile)?;
    // SAFETY: the converted SID string is live and NUL terminated.
    let folder = unsafe { GetAppContainerFolderPath(PCWSTR(sid_text.as_ptr())) }
        .map(UnvalidatedProfileApiFolderPath::new);
    profile_api
        .recheck_thread()
        .map_err(|_| KeyAgentLpacError::Profile)?;
    folder.map_err(|_| KeyAgentLpacError::Profile)?.to_path()
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
fn copy_executable_image(source: &Path, destination: &Path) -> Result<(), KeyAgentLpacError> {
    let mut source = File::open(source).map_err(|_| KeyAgentLpacError::Profile)?;
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
    use core::mem::{align_of, offset_of, size_of};
    use core::ptr;
    use std::fs::OpenOptions;
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::BorrowedHandle;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    use windows::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_INVALID_OWNER, ERROR_NO_TOKEN,
        ERROR_SHARING_VIOLATION, FILETIME, GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT,
        HANDLE_FLAGS, INVALID_HANDLE_VALUE, LUID, SetHandleInformation, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    };
    use windows::Win32::Security::{
        ACL, ACL_REVISION, EqualSid, IsValidAcl, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, PSID,
        SE_DACL_AUTO_INHERIT_REQ, SE_DACL_AUTO_INHERITED, SE_DACL_DEFAULTED, SE_DACL_PRESENT,
        SE_DACL_PROTECTED, SE_OWNER_DEFAULTED, SE_PRIVILEGE_ENABLED, SE_SELF_RELATIVE,
        SECURITY_ATTRIBUTES, SID_AND_ATTRIBUTES, SetTokenInformation, TOKEN_ADJUST_DEFAULT,
        TOKEN_APPCONTAINER_INFORMATION, TOKEN_DEFAULT_DACL, TOKEN_GROUPS, TOKEN_OWNER,
        TOKEN_PRIVILEGES, TOKEN_STATISTICS, TOKEN_USER, TokenDefaultDacl, TokenGroups,
        TokenImpersonation, TokenOwner, TokenPrimary, TokenPrivileges, TokenUser,
    };
    use windows::Win32::Security::{TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_QUERY};
    use windows::Win32::Storage::FileSystem::{
        DELETE, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE, READ_CONTROL, ReadFile, WRITE_DAC, WRITE_OWNER, WriteFile,
    };
    use windows::Win32::System::Pipes::{CreatePipe, PeekNamedPipe};
    use windows::Win32::System::SystemServices::{
        ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, SE_GROUP_OWNER,
    };
    use windows::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateEventW,
        CreateProcessW, CreateThread, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
        GetCurrentProcess, GetCurrentThread, GetExitCodeProcess, GetProcessId, GetThreadId,
        GetThreadTimes, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
        OpenProcess, OpenProcessToken, OpenThread, OpenThreadToken,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        PROCESS_ACCESS_RIGHTS, PROCESS_CREATE_PROCESS, PROCESS_CREATE_THREAD, PROCESS_DUP_HANDLE,
        PROCESS_INFORMATION, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SET_INFORMATION, PROCESS_SET_QUOTA, PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE,
        PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, ResumeThread, STARTUPINFOEXW,
        SetEvent, THREAD_ACCESS_RIGHTS, THREAD_CREATION_FLAGS, THREAD_DIRECT_IMPERSONATION,
        THREAD_GET_CONTEXT, THREAD_IMPERSONATE, THREAD_QUERY_INFORMATION,
        THREAD_QUERY_LIMITED_INFORMATION, THREAD_SET_CONTEXT, THREAD_SET_INFORMATION,
        THREAD_SET_LIMITED_INFORMATION, THREAD_SET_THREAD_TOKEN, THREAD_SUSPEND_RESUME,
        THREAD_TERMINATE, TerminateProcess, TerminateThread, UpdateProcThreadAttribute,
        WaitForSingleObject,
    };
    use windows::Win32::System::WindowsProgramming::PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
    use windows::core::{PCWSTR, PWSTR};

    use super::{
        APPROVAL_PARENT_TOKEN_ACCESS, AppContainerMembershipEvidence, CAPABILITY_COUNT,
        CREATION_SECURITY_DENIED_ACCESS, EXACT_TOKEN_DEFAULT_DACL_BYTES,
        HeldExistingKeyAgentInstallObjects, KEY_AGENT_PROFILE_V1_NAME, KEY_AGENT_TOKEN_SELF_ACCESS,
        KeyAgentLpacError, KeyAgentLpacKernelTestFixture, KeyAgentStorageError,
        OWNER_RIGHTS_SID_BYTES, OwnedAppContainerSid, OwnedExactTokenDefaultDacl, OwnedToken,
        PendingKeyAgentLpac, PendingKeyAgentProvisioning, PreparedKeyAgentCreationSecurity,
        PreparedKeyAgentLpac, PreparedKeyAgentProfile, PreparedKeyAgentProvisioning,
        SUPERVISOR_TOKEN_ACCESS, TokenDword, TokenIdentityBaseline, TokenInformation,
        TokenLuidBaseline, TokenPolicyEvidence, VerifiedKeyAgentLpac, appcontainer_folder,
        appcontainer_membership_evidence, create_unique_key_agent_storage_root_for_test,
        created_object_security_descriptor, creation_security_sid_component,
        creation_security_token_information, creation_security_wide_nul,
        exact_token_statistics_baseline, inspect_exact_creation_security_descriptor,
        inspect_exact_token_dacl_descriptor, inspect_exact_token_default_dacl_bytes,
        inspect_exact_token_default_dacl_information, open_current_process_creation_security_token,
        open_existing_key_agent_storage_root_for_test, open_process_token_with_access,
        read_creation_security_u16_at, read_creation_security_u32_at,
        require_created_sid_matches_derived, require_same_token_id, require_same_token_identity,
        require_same_token_object, token_identity_from_statistics, validate_creation_handle_flags,
        validate_token_policy, verify_created_object_security, wide_nul_str,
    };
    use crate::restricted_process_context::RestrictedProcessContext;

    const APPROVAL_PROFILE_V1_NAME: &str = "YourWallet.ApprovalFrontend.LPAC.v1";
    const SECRET_INPUT_PROFILE_V1_NAME: &str = "YourWallet.SecretInputFrontend.LPAC.v1";
    const LPAC_USER_MODE_SMOKE_CHILD_TEST: &str =
        "key_agent_lpac::tests::lpac_user_mode_smoke_child";
    const POST_LOADER_DEFAULT_DACL_CHILD_TEST: &str =
        "key_agent_lpac::tests::post_loader_worker_feasibility_default_dacl_child";
    const TEST_COMMAND_PIPE_ENV: &str = "YW_TEST_COMMAND_PIPE";
    const TEST_STATUS_PIPE_ENV: &str = "YW_TEST_STATUS_PIPE";
    const TEST_STATUS_LOADER_READY: u8 = 0x11;
    const TEST_STATUS_THREAD_READY: u8 = 0x12;
    const TEST_COMMAND_POLICY_INSTALLED: u8 = 0x21;
    const TEST_COMMAND_MATRIX_COMPLETE: u8 = 0x22;
    const TEST_GENERIC_ALL: u32 = 0x1000_0000;
    const TEST_GENERIC_EXECUTE: u32 = 0x2000_0000;
    const TEST_GENERIC_READ: u32 = 0x8000_0000;
    const STATUS_DLL_INIT_FAILED: u32 = 0xc000_0142;
    const MAX_TEST_DEFAULT_DACL_BYTES: usize = 4 * 1024;
    const LOCAL_SYSTEM_SID_BYTES: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];

    fn exact_ignored_child_command_line(
        executable: &Path,
        test_name: &str,
    ) -> Result<Vec<u16>, KeyAgentLpacError> {
        if test_name.is_empty()
            || test_name.contains(char::is_whitespace)
            || test_name.contains('\0')
        {
            return Err(KeyAgentLpacError::Profile);
        }
        let mut command_line = Vec::new();
        command_line.push(u16::from(b'"'));
        command_line.extend(executable.as_os_str().encode_wide());
        command_line.push(u16::from(b'"'));
        command_line
            .extend(format!(" --ignored --exact {test_name} --test-threads=1").encode_utf16());
        if command_line.len() < 3 || command_line.contains(&0) {
            return Err(KeyAgentLpacError::Profile);
        }
        command_line.push(0);
        Ok(command_line)
    }

    struct TestOwnedHandle(HANDLE);

    impl TestOwnedHandle {
        fn new(handle: HANDLE) -> Result<Self, KeyAgentLpacError> {
            if handle.is_invalid() || handle == INVALID_HANDLE_VALUE {
                return Err(KeyAgentLpacError::Attribute);
            }
            Ok(Self(handle))
        }

        fn raw(&self) -> HANDLE {
            self.0
        }

        fn set_inheritable(&self, inheritable: bool) -> Result<(), KeyAgentLpacError> {
            let expected = if inheritable {
                HANDLE_FLAG_INHERIT
            } else {
                HANDLE_FLAGS(0)
            };
            // SAFETY: this owner retains the exact live pipe endpoint through
            // both scalar handle-flag operations.
            unsafe {
                SetHandleInformation(self.0, HANDLE_FLAG_INHERIT.0, expected)
                    .map_err(|_| KeyAgentLpacError::Attribute)?;
            }
            let mut flags = 0_u32;
            // SAFETY: the same live handle is retained and output is one DWORD.
            unsafe { GetHandleInformation(self.0, &raw mut flags) }
                .map_err(|_| KeyAgentLpacError::Attribute)?;
            if flags != expected.0 {
                return Err(KeyAgentLpacError::Attribute);
            }
            Ok(())
        }

        fn close_checked(mut self) -> Result<(), KeyAgentLpacError> {
            // SAFETY: this wrapper exclusively owns the live handle. A failure
            // leaves the field intact so ordinary Drop retries the close.
            unsafe { CloseHandle(self.0) }.map_err(|_| KeyAgentLpacError::Attribute)?;
            self.0 = HANDLE::default();
            Ok(())
        }
    }

    impl Drop for TestOwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_invalid() && self.0 != INVALID_HANDLE_VALUE {
                // SAFETY: this wrapper owns the exact still-live handle.
                unsafe {
                    let _ = CloseHandle(self.0);
                }
                self.0 = HANDLE::default();
            }
        }
    }

    fn anonymous_pipe_for_test() -> Result<(TestOwnedHandle, TestOwnedHandle), KeyAgentLpacError> {
        let mut read = HANDLE::default();
        let mut write = HANDLE::default();
        // SAFETY: both outputs are exact initialized HANDLE storage. Successful
        // results are transferred once into the owners below.
        unsafe { CreatePipe(&raw mut read, &raw mut write, None, 0) }
            .map_err(|_| KeyAgentLpacError::Attribute)?;
        if read.is_invalid()
            || read == INVALID_HANDLE_VALUE
            || write.is_invalid()
            || write == INVALID_HANDLE_VALUE
        {
            for handle in [read, write]
                .into_iter()
                .filter(|handle| !handle.is_invalid() && *handle != INVALID_HANDLE_VALUE)
            {
                // SAFETY: invalid results are rejected; every independently
                // valid fresh endpoint is still owned by this failure branch.
                unsafe {
                    let _ = CloseHandle(handle);
                }
            }
            return Err(KeyAgentLpacError::Attribute);
        }
        Ok((TestOwnedHandle(read), TestOwnedHandle(write)))
    }

    fn read_exact_pipe(handle: HANDLE, bytes: &mut [u8]) -> Result<(), KeyAgentLpacError> {
        let mut offset = 0_usize;
        while offset < bytes.len() {
            let remaining = bytes
                .get_mut(offset..)
                .ok_or(KeyAgentLpacError::Attribute)?;
            let mut transferred = 0_u32;
            // SAFETY: the caller retains a synchronous readable pipe endpoint;
            // this exact writable suffix and count remain live for the call.
            unsafe { ReadFile(handle, Some(remaining), Some(&raw mut transferred), None) }
                .map_err(|_| KeyAgentLpacError::Attribute)?;
            let transferred =
                usize::try_from(transferred).map_err(|_| KeyAgentLpacError::Attribute)?;
            if transferred == 0 || transferred > remaining.len() {
                return Err(KeyAgentLpacError::Attribute);
            }
            offset = offset
                .checked_add(transferred)
                .ok_or(KeyAgentLpacError::Attribute)?;
        }
        Ok(())
    }

    fn write_exact_pipe(handle: HANDLE, bytes: &[u8]) -> Result<(), KeyAgentLpacError> {
        let mut offset = 0_usize;
        while offset < bytes.len() {
            let remaining = bytes.get(offset..).ok_or(KeyAgentLpacError::Attribute)?;
            let mut transferred = 0_u32;
            // SAFETY: the caller retains a synchronous writable pipe endpoint;
            // this exact readable suffix and count remain live for the call.
            unsafe { WriteFile(handle, Some(remaining), Some(&raw mut transferred), None) }
                .map_err(|_| KeyAgentLpacError::Attribute)?;
            let transferred =
                usize::try_from(transferred).map_err(|_| KeyAgentLpacError::Attribute)?;
            if transferred == 0 || transferred > remaining.len() {
                return Err(KeyAgentLpacError::Attribute);
            }
            offset = offset
                .checked_add(transferred)
                .ok_or(KeyAgentLpacError::Attribute)?;
        }
        Ok(())
    }

    struct TestHandshakePipes {
        child_command_read: Option<TestOwnedHandle>,
        parent_command_write: Option<TestOwnedHandle>,
        parent_status_read: Option<TestOwnedHandle>,
        child_status_write: Option<TestOwnedHandle>,
    }

    impl TestHandshakePipes {
        fn create() -> Result<Self, KeyAgentLpacError> {
            let (command_read, command_write) = anonymous_pipe_for_test()?;
            let (status_read, status_write) = anonymous_pipe_for_test()?;
            command_read.set_inheritable(true)?;
            status_write.set_inheritable(true)?;
            command_write.set_inheritable(false)?;
            status_read.set_inheritable(false)?;
            Ok(Self {
                child_command_read: Some(command_read),
                parent_command_write: Some(command_write),
                parent_status_read: Some(status_read),
                child_status_write: Some(status_write),
            })
        }

        fn child_handles(&self) -> Result<[HANDLE; 2], KeyAgentLpacError> {
            let command = self
                .child_command_read
                .as_ref()
                .ok_or(KeyAgentLpacError::Attribute)?
                .raw();
            let status = self
                .child_status_write
                .as_ref()
                .ok_or(KeyAgentLpacError::Attribute)?
                .raw();
            if command == status {
                return Err(KeyAgentLpacError::Attribute);
            }
            Ok([command, status])
        }

        fn child_environment(&self) -> Result<[String; 2], KeyAgentLpacError> {
            let [command, status] = self.child_handles()?;
            Ok([
                format!("{TEST_COMMAND_PIPE_ENV}={:x}", command.0 as usize),
                format!("{TEST_STATUS_PIPE_ENV}={:x}", status.0 as usize),
            ])
        }

        fn seal_parent_after_launch(&mut self) -> Result<(), KeyAgentLpacError> {
            let command = self
                .child_command_read
                .take()
                .ok_or(KeyAgentLpacError::Attribute)?
                .close_checked();
            let status = self
                .child_status_write
                .take()
                .ok_or(KeyAgentLpacError::Attribute)?
                .close_checked();
            command?;
            status
        }

        fn send_command(&self, command: u8) -> Result<(), KeyAgentLpacError> {
            let pipe = self
                .parent_command_write
                .as_ref()
                .ok_or(KeyAgentLpacError::Attribute)?;
            write_exact_pipe(pipe.raw(), &[command])
        }

        fn receive_status<const N: usize>(
            &self,
            process: HANDLE,
        ) -> Result<[u8; N], KeyAgentLpacError> {
            if N == 0 || process.is_invalid() || process == INVALID_HANDLE_VALUE {
                return Err(KeyAgentLpacError::Attribute);
            }
            let pipe = self
                .parent_status_read
                .as_ref()
                .ok_or(KeyAgentLpacError::Attribute)?;
            let deadline = Instant::now()
                .checked_add(Duration::from_secs(10))
                .ok_or(KeyAgentLpacError::Attribute)?;
            loop {
                let mut available = 0_u32;
                // SAFETY: the retained synchronous read endpoint is queried
                // without consuming bytes; the only output is one DWORD.
                unsafe { PeekNamedPipe(pipe.raw(), None, 0, None, Some(&raw mut available), None) }
                    .map_err(|_| KeyAgentLpacError::Attribute)?;
                let available =
                    usize::try_from(available).map_err(|_| KeyAgentLpacError::Attribute)?;
                if available > N {
                    return Err(KeyAgentLpacError::Attribute);
                }
                if available == N {
                    let mut message = [0_u8; N];
                    read_exact_pipe(pipe.raw(), &mut message)?;
                    return Ok(message);
                }
                // SAFETY: the exact child process is retained while polling for
                // either an early exit or more pipe bytes with a finite bound.
                if unsafe { WaitForSingleObject(process, 0) } != WAIT_TIMEOUT {
                    return Err(KeyAgentLpacError::Attribute);
                }
                if Instant::now() >= deadline {
                    return Err(KeyAgentLpacError::Attribute);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        fn close_checked(mut self) -> Result<(), KeyAgentLpacError> {
            if self.child_command_read.is_some() || self.child_status_write.is_some() {
                return Err(KeyAgentLpacError::Attribute);
            }
            let command = self
                .parent_command_write
                .take()
                .ok_or(KeyAgentLpacError::Attribute)?
                .close_checked();
            let status = self
                .parent_status_read
                .take()
                .ok_or(KeyAgentLpacError::Attribute)?
                .close_checked();
            command?;
            status
        }
    }

    struct ChildHandshake {
        command_read: Option<TestOwnedHandle>,
        status_write: Option<TestOwnedHandle>,
    }

    impl ChildHandshake {
        fn from_environment() -> Result<Self, KeyAgentLpacError> {
            fn inherited_handle(name: &str) -> Result<TestOwnedHandle, KeyAgentLpacError> {
                let encoded = std::env::var(name).map_err(|_| KeyAgentLpacError::Attribute)?;
                if encoded.is_empty()
                    || encoded.contains(char::is_whitespace)
                    || encoded.starts_with(['+', '-'])
                {
                    return Err(KeyAgentLpacError::Attribute);
                }
                let raw = usize::from_str_radix(&encoded, 16)
                    .map_err(|_| KeyAgentLpacError::Attribute)?;
                TestOwnedHandle::new(HANDLE(raw as *mut c_void))
            }

            let command_read = inherited_handle(TEST_COMMAND_PIPE_ENV)?;
            let status_write = inherited_handle(TEST_STATUS_PIPE_ENV)?;
            if command_read.raw() == status_write.raw() {
                return Err(KeyAgentLpacError::Attribute);
            }
            command_read.set_inheritable(true)?;
            status_write.set_inheritable(true)?;
            Ok(Self {
                command_read: Some(command_read),
                status_write: Some(status_write),
            })
        }

        fn send_status(&self, status: &[u8]) -> Result<(), KeyAgentLpacError> {
            let pipe = self
                .status_write
                .as_ref()
                .ok_or(KeyAgentLpacError::Attribute)?;
            write_exact_pipe(pipe.raw(), status)
        }

        fn require_command(&self, expected: u8) -> Result<(), KeyAgentLpacError> {
            let pipe = self
                .command_read
                .as_ref()
                .ok_or(KeyAgentLpacError::Attribute)?;
            let mut command = [0_u8; 1];
            read_exact_pipe(pipe.raw(), &mut command)?;
            if command != [expected] {
                return Err(KeyAgentLpacError::Attribute);
            }
            Ok(())
        }

        fn close_checked(mut self) -> Result<(), KeyAgentLpacError> {
            let command = self
                .command_read
                .take()
                .ok_or(KeyAgentLpacError::Attribute)?
                .close_checked();
            let status = self
                .status_write
                .take()
                .ok_or(KeyAgentLpacError::Attribute)?
                .close_checked();
            command?;
            status
        }
    }

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

    fn require_delete_sharing_violation(path: &Path) -> std::io::Result<()> {
        let opened = OpenOptions::new()
            .access_mode(DELETE.0)
            .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE).0)
            .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
            .open(path);
        match opened {
            Err(error) if error.raw_os_error() == i32::try_from(ERROR_SHARING_VIOLATION.0).ok() => {
                Ok(())
            }
            Err(error) => Err(error),
            Ok(unexpected) => {
                drop(unexpected);
                Err(std::io::Error::other(
                    "held Key Agent root unexpectedly granted DELETE access",
                ))
            }
        }
    }

    struct TestAttributeList {
        pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
        _words: Vec<usize>,
        inherited_handles: Option<Box<[HANDLE; 2]>>,
    }

    #[derive(Clone, Copy, Debug)]
    enum CreationDaclAxis {
        DefaultBoth,
        DenyProcessOnly,
        DenyThreadOnly,
        DenyBoth,
    }

    impl CreationDaclAxis {
        const CASES: [Self; 4] = [
            Self::DefaultBoth,
            Self::DenyProcessOnly,
            Self::DenyThreadOnly,
            Self::DenyBoth,
        ];

        fn process_attributes(
            self,
            security: &PreparedKeyAgentCreationSecurity,
        ) -> Option<&SECURITY_ATTRIBUTES> {
            match self {
                Self::DefaultBoth | Self::DenyThreadOnly => None,
                Self::DenyProcessOnly | Self::DenyBoth => Some(&security.process_attributes),
            }
        }

        fn primary_thread_attributes(
            self,
            security: &PreparedKeyAgentCreationSecurity,
        ) -> Option<&SECURITY_ATTRIBUTES> {
            match self {
                Self::DefaultBoth | Self::DenyProcessOnly => None,
                Self::DenyThreadOnly | Self::DenyBoth => Some(&security.primary_thread_attributes),
            }
        }
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
        resumed: bool,
    }

    impl TestSuspendedProcess {
        fn process_handle(&self) -> BorrowedHandle<'_> {
            // SAFETY: this wrapper exclusively owns the live process handle and
            // bounds the returned borrow to `self`.
            unsafe { BorrowedHandle::borrow_raw(self.process.0) }
        }

        fn primary_thread_handle(&self) -> BorrowedHandle<'_> {
            // SAFETY: this wrapper exclusively owns the live primary-thread
            // handle and bounds the returned borrow to `self`.
            unsafe { BorrowedHandle::borrow_raw(self.thread.0) }
        }

        fn raw_process(&self) -> HANDLE {
            self.process
        }

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
            if thread_closed.is_ok() {
                self.thread = HANDLE::default();
            }
            // SAFETY: same exclusive ownership argument for the process handle.
            let process_closed = unsafe { CloseHandle(self.process) };
            if process_closed.is_ok() {
                self.process = HANDLE::default();
            }
            thread_closed
                .and(process_closed)
                .map_err(|_| KeyAgentLpacError::Token)
        }

        fn resume_once(&mut self) -> Result<(), KeyAgentLpacError> {
            if self.process.is_invalid()
                || self.process == INVALID_HANDLE_VALUE
                || self.thread.is_invalid()
                || self.thread == INVALID_HANDLE_VALUE
                || self.resumed
            {
                return Err(KeyAgentLpacError::Token);
            }
            // SAFETY: this is the sole production-shaped resume of the exact
            // CREATE_SUSPENDED primary-thread handle retained by the test.
            if unsafe { ResumeThread(self.thread) } != 1 {
                return Err(KeyAgentLpacError::Token);
            }
            self.resumed = true;
            Ok(())
        }

        fn wait_for_exit_code_and_close(&mut self) -> Result<u32, KeyAgentLpacError> {
            if !self.resumed
                || self.process.is_invalid()
                || self.process == INVALID_HANDLE_VALUE
                || self.thread.is_invalid()
                || self.thread == INVALID_HANDLE_VALUE
            {
                return Err(KeyAgentLpacError::Token);
            }
            // SAFETY: the live child process is given a finite natural-exit bound.
            if unsafe { WaitForSingleObject(self.process, 30_000) } != WAIT_OBJECT_0 {
                return Err(KeyAgentLpacError::Token);
            }
            let mut exit_code = u32::MAX;
            // SAFETY: the process is signaled and output is exact writable DWORD.
            let exit_result = unsafe { GetExitCodeProcess(self.process, &raw mut exit_code) };

            // SAFETY: after process exit both creator handles remain exclusively
            // owned. Attempt each checked close independently before evaluating
            // the exit proof, retaining any failed-close handle for Drop retry.
            let thread_closed = unsafe { CloseHandle(self.thread) };
            if thread_closed.is_ok() {
                self.thread = HANDLE::default();
            }
            // SAFETY: independent exact process-handle close attempt.
            let process_closed = unsafe { CloseHandle(self.process) };
            if process_closed.is_ok() {
                self.process = HANDLE::default();
            }
            exit_result.map_err(|_| KeyAgentLpacError::Token)?;
            if thread_closed.is_err() || process_closed.is_err() {
                return Err(KeyAgentLpacError::Token);
            }
            Ok(exit_code)
        }

        fn wait_for_success_and_close(&mut self) -> Result<(), KeyAgentLpacError> {
            if self.wait_for_exit_code_and_close()? != 0 {
                return Err(KeyAgentLpacError::Token);
            }
            Ok(())
        }

        fn resume_and_wait_for_success(&mut self) -> Result<(), KeyAgentLpacError> {
            self.resume_once()?;
            self.wait_for_success_and_close()
        }
    }

    impl Drop for TestSuspendedProcess {
        fn drop(&mut self) {
            if !self.process.is_invalid() && self.process != INVALID_HANDLE_VALUE {
                // SAFETY: the test owns the process. This handles both a still-
                // suspended child and a resumed child whose natural wait failed;
                // termination precedes the bounded wait and close.
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

    #[derive(Clone, Copy)]
    enum TestDefaultDaclAceKind {
        Deny,
        Allow,
    }

    struct TestDefaultDaclAce<'a> {
        kind: TestDefaultDaclAceKind,
        mask: u32,
        sid: &'a [u8],
    }

    /// Bounded, DWORD-aligned owner for test-only `TokenDefaultDacl` matrices.
    ///
    /// Unlike the product's exact 28-byte owner, this owner deliberately
    /// supports only the small screening ACLs assembled by the kernel test.
    /// No pointer or SID escapes the synchronous `SetTokenInformation` call.
    struct TestOwnedDefaultDacl {
        words: Box<[u32]>,
        byte_len: usize,
    }

    impl TestOwnedDefaultDacl {
        fn from_bytes(bytes: &[u8]) -> Result<Self, KeyAgentLpacError> {
            if !(size_of::<ACL>()..=MAX_TEST_DEFAULT_DACL_BYTES).contains(&bytes.len())
                || bytes.len() < 8
                || usize::from(u16::from_le_bytes(
                    bytes
                        .get(2..4)
                        .ok_or(KeyAgentLpacError::Token)?
                        .try_into()
                        .map_err(|_| KeyAgentLpacError::Token)?,
                )) != bytes.len()
            {
                return Err(KeyAgentLpacError::Token);
            }
            let word_count = bytes
                .len()
                .checked_add(size_of::<u32>() - 1)
                .and_then(|rounded| rounded.checked_div(size_of::<u32>()))
                .ok_or(KeyAgentLpacError::Token)?;
            let mut words = vec![0_u32; word_count].into_boxed_slice();
            // SAFETY: the aligned boxed allocation has at least `bytes.len()`
            // writable bytes and the source is a distinct live slice.
            unsafe {
                ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    words.as_mut_ptr().cast::<u8>(),
                    bytes.len(),
                );
            }
            let mut owner = Self {
                words,
                byte_len: bytes.len(),
            };
            // SAFETY: the pointer addresses the complete bounded, aligned ACL
            // copied above. IsValidAcl reads no bytes beyond its declared size.
            if !unsafe { IsValidAcl(owner.as_acl_mut_ptr()) }.as_bool() {
                return Err(KeyAgentLpacError::Token);
            }
            Ok(owner)
        }

        fn from_aces(aces: &[TestDefaultDaclAce<'_>]) -> Result<Self, KeyAgentLpacError> {
            let mut byte_len = 8_usize;
            for ace in aces {
                validate_test_sid_bytes(ace.sid)?;
                byte_len = byte_len
                    .checked_add(8)
                    .and_then(|value| value.checked_add(ace.sid.len()))
                    .ok_or(KeyAgentLpacError::Token)?;
            }
            if byte_len > MAX_TEST_DEFAULT_DACL_BYTES {
                return Err(KeyAgentLpacError::Token);
            }
            let mut bytes = Vec::with_capacity(byte_len);
            bytes.push(u8::try_from(ACL_REVISION.0).map_err(|_| KeyAgentLpacError::Token)?);
            bytes.push(0);
            bytes.extend_from_slice(
                &u16::try_from(byte_len)
                    .map_err(|_| KeyAgentLpacError::Token)?
                    .to_le_bytes(),
            );
            bytes.extend_from_slice(
                &u16::try_from(aces.len())
                    .map_err(|_| KeyAgentLpacError::Token)?
                    .to_le_bytes(),
            );
            bytes.extend_from_slice(&0_u16.to_le_bytes());
            for ace in aces {
                let ace_type = match ace.kind {
                    TestDefaultDaclAceKind::Deny => ACCESS_DENIED_ACE_TYPE,
                    TestDefaultDaclAceKind::Allow => ACCESS_ALLOWED_ACE_TYPE,
                };
                bytes.push(u8::try_from(ace_type).map_err(|_| KeyAgentLpacError::Token)?);
                bytes.push(0);
                bytes.extend_from_slice(
                    &u16::try_from(8 + ace.sid.len())
                        .map_err(|_| KeyAgentLpacError::Token)?
                        .to_le_bytes(),
                );
                bytes.extend_from_slice(&ace.mask.to_le_bytes());
                bytes.extend_from_slice(ace.sid);
            }
            if bytes.len() != byte_len {
                return Err(KeyAgentLpacError::Token);
            }
            Self::from_bytes(&bytes)
        }

        fn bytes(&self) -> &[u8] {
            // SAFETY: the boxed u32 owner is initialized and retained, and
            // `byte_len` never exceeds its rounded backing allocation.
            unsafe { core::slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.byte_len) }
        }

        fn as_acl_mut_ptr(&mut self) -> *mut ACL {
            self.words.as_mut_ptr().cast::<ACL>()
        }
    }

    impl Drop for TestOwnedDefaultDacl {
        fn drop(&mut self) {
            self.words.fill(0);
            self.byte_len = 0;
        }
    }

    fn validate_test_sid_bytes(sid: &[u8]) -> Result<(), KeyAgentLpacError> {
        if !(8..=super::MAX_INSTALL_SID_BYTES).contains(&sid.len()) || sid[0] != 1 {
            return Err(KeyAgentLpacError::Token);
        }
        let expected = usize::from(sid[1])
            .checked_mul(size_of::<u32>())
            .and_then(|subauthorities| 8_usize.checked_add(subauthorities))
            .ok_or(KeyAgentLpacError::Token)?;
        if sid.len() != expected {
            return Err(KeyAgentLpacError::Token);
        }
        Ok(())
    }

    fn capture_token_default_dacl(
        token: HANDLE,
    ) -> Result<TestOwnedDefaultDacl, KeyAgentLpacError> {
        let information = super::token_information(token, TokenDefaultDacl)?;
        if information.returned_bytes < size_of::<TOKEN_DEFAULT_DACL>() {
            return Err(KeyAgentLpacError::Token);
        }
        // SAFETY: the aligned owner contains the complete returned prefix.
        let default_dacl =
            unsafe { ptr::read_unaligned(information.words.as_ptr().cast::<TOKEN_DEFAULT_DACL>()) };
        if default_dacl.DefaultDacl.is_null() {
            return Err(KeyAgentLpacError::Token);
        }
        let allocation_start = information.words.as_ptr() as usize;
        let allocation_end = allocation_start
            .checked_add(information.returned_bytes)
            .ok_or(KeyAgentLpacError::Token)?;
        let acl_start = default_dacl.DefaultDacl as usize;
        let acl_offset = acl_start
            .checked_sub(allocation_start)
            .ok_or(KeyAgentLpacError::Token)?;
        if !acl_start.is_multiple_of(align_of::<ACL>())
            || acl_offset < size_of::<TOKEN_DEFAULT_DACL>()
            || acl_start
                .checked_add(8)
                .as_ref()
                .is_none_or(|header_end| *header_end > allocation_end)
        {
            return Err(KeyAgentLpacError::Token);
        }
        // SAFETY: `returned_bytes` is bounded by token_information and never
        // exceeds the initialized rounded allocation.
        let returned = unsafe {
            core::slice::from_raw_parts(
                information.words.as_ptr().cast::<u8>(),
                information.returned_bytes,
            )
        };
        let acl_size = usize::from(u16::from_le_bytes(
            returned
                .get(acl_offset + 2..acl_offset + 4)
                .ok_or(KeyAgentLpacError::Token)?
                .try_into()
                .map_err(|_| KeyAgentLpacError::Token)?,
        ));
        let acl_end = acl_offset
            .checked_add(acl_size)
            .filter(|end| *end <= returned.len())
            .ok_or(KeyAgentLpacError::Token)?;
        TestOwnedDefaultDacl::from_bytes(
            returned
                .get(acl_offset..acl_end)
                .ok_or(KeyAgentLpacError::Token)?,
        )
    }

    fn test_token_user_sid(token: HANDLE) -> Result<Vec<u8>, KeyAgentLpacError> {
        let information = super::token_information(token, TokenUser)?;
        if information.returned_bytes < size_of::<TOKEN_USER>() {
            return Err(KeyAgentLpacError::Token);
        }
        // SAFETY: the aligned owner contains the complete returned prefix and
        // stays live while copied_sid_bytes validates and copies the SID.
        let user = unsafe { ptr::read_unaligned(information.words.as_ptr().cast::<TOKEN_USER>()) };
        super::copied_sid_bytes(user.User.Sid)
    }

    fn bounded_token_information_sid_bytes(
        information: &super::TokenInformation,
        sid: PSID,
    ) -> Result<Vec<u8>, KeyAgentLpacError> {
        if sid.0.is_null() {
            return Err(KeyAgentLpacError::Token);
        }
        let allocation_start = information.words.as_ptr() as usize;
        let sid_start = sid.0 as usize;
        let sid_offset = sid_start
            .checked_sub(allocation_start)
            .ok_or(KeyAgentLpacError::Token)?;
        let sid_header_end = sid_offset
            .checked_add(8)
            .filter(|end| *end <= information.returned_bytes)
            .ok_or(KeyAgentLpacError::Token)?;
        // SAFETY: token_information bounds returned_bytes by its initialized
        // rounded owner and the range checks precede every slice operation.
        let returned = unsafe {
            core::slice::from_raw_parts(
                information.words.as_ptr().cast::<u8>(),
                information.returned_bytes,
            )
        };
        let subauthority_count = usize::from(
            *returned
                .get(sid_offset + 1)
                .ok_or(KeyAgentLpacError::Token)?,
        );
        let sid_len = subauthority_count
            .checked_mul(size_of::<u32>())
            .and_then(|subauthorities| 8_usize.checked_add(subauthorities))
            .ok_or(KeyAgentLpacError::Token)?;
        let sid_end = sid_offset
            .checked_add(sid_len)
            .filter(|end| *end <= information.returned_bytes && *end >= sid_header_end)
            .ok_or(KeyAgentLpacError::Token)?;
        let sid_bytes = returned
            .get(sid_offset..sid_end)
            .ok_or(KeyAgentLpacError::Token)?;
        validate_test_sid_bytes(sid_bytes)?;
        Ok(sid_bytes.to_vec())
    }

    fn token_group_attributes_for_sid(
        token: HANDLE,
        expected_sid: &[u8],
    ) -> Result<Option<u32>, KeyAgentLpacError> {
        validate_test_sid_bytes(expected_sid)?;
        let information = super::token_information(token, TokenGroups)?;
        let groups_offset = offset_of!(TOKEN_GROUPS, Groups);
        if information.returned_bytes < groups_offset {
            return Err(KeyAgentLpacError::Token);
        }
        // SAFETY: the returned owner contains the DWORD GroupCount prefix.
        let group_count = usize::try_from(unsafe {
            ptr::read_unaligned(information.words.as_ptr().cast::<TOKEN_GROUPS>()).GroupCount
        })
        .map_err(|_| KeyAgentLpacError::Token)?;
        let _groups_end = group_count
            .checked_mul(size_of::<SID_AND_ATTRIBUTES>())
            .and_then(|bytes| groups_offset.checked_add(bytes))
            .filter(|required| *required <= information.returned_bytes)
            .ok_or(KeyAgentLpacError::Token)?;
        let mut matching_attributes = None;
        for index in 0..group_count {
            let entry_offset = groups_offset
                .checked_add(
                    index
                        .checked_mul(size_of::<SID_AND_ATTRIBUTES>())
                        .ok_or(KeyAgentLpacError::Token)?,
                )
                .ok_or(KeyAgentLpacError::Token)?;
            // SAFETY: the complete variable-length group array was bounded
            // above and this unaligned read selects one exact in-range entry.
            let entry = unsafe {
                ptr::read_unaligned(
                    information
                        .words
                        .as_ptr()
                        .cast::<u8>()
                        .add(entry_offset)
                        .cast::<SID_AND_ATTRIBUTES>(),
                )
            };
            if bounded_token_information_sid_bytes(&information, entry.Sid)? == expected_sid
                && matching_attributes.replace(entry.Attributes).is_some()
            {
                return Err(KeyAgentLpacError::Token);
            }
        }
        Ok(matching_attributes)
    }

    fn token_owner_sid(token: HANDLE) -> Result<Vec<u8>, KeyAgentLpacError> {
        let information = super::token_information(token, TokenOwner)?;
        if information.returned_bytes < size_of::<TOKEN_OWNER>() {
            return Err(KeyAgentLpacError::Token);
        }
        // SAFETY: the aligned owner contains the complete returned prefix.
        let owner =
            unsafe { ptr::read_unaligned(information.words.as_ptr().cast::<TOKEN_OWNER>()) };
        bounded_token_information_sid_bytes(&information, owner.Owner)
    }

    fn package_sid_token_owner_switch_result(
        token: HANDLE,
        package_sid: PSID,
    ) -> Result<Result<(), windows::core::Error>, KeyAgentLpacError> {
        let original_information = super::token_information(token, TokenOwner)?;
        if original_information.returned_bytes < size_of::<TOKEN_OWNER>() {
            return Err(KeyAgentLpacError::Token);
        }
        // SAFETY: the aligned owner contains the complete returned prefix and
        // remains live through a possible exact restoration below.
        let original_owner = unsafe {
            ptr::read_unaligned(original_information.words.as_ptr().cast::<TOKEN_OWNER>())
        };
        let original_sid =
            bounded_token_information_sid_bytes(&original_information, original_owner.Owner)?;
        let package_sid_bytes = super::copied_sid_bytes(package_sid)?;
        let package_owner = TOKEN_OWNER { Owner: package_sid };
        // SAFETY: the caller retains both the adjustable token and package SID
        // owner for the complete synchronous call.
        let switch = unsafe {
            SetTokenInformation(
                token,
                TokenOwner,
                ptr::from_ref(&package_owner).cast::<c_void>(),
                u32::try_from(size_of::<TOKEN_OWNER>()).map_err(|_| KeyAgentLpacError::Token)?,
            )
        };
        if switch.is_ok() {
            if token_owner_sid(token)? != package_sid_bytes {
                return Err(KeyAgentLpacError::Token);
            }
            // SAFETY: the original token-information allocation and pointed-to
            // SID stay live until this exact restoration call completes.
            unsafe {
                SetTokenInformation(
                    token,
                    TokenOwner,
                    ptr::from_ref(&original_owner).cast::<c_void>(),
                    u32::try_from(size_of::<TOKEN_OWNER>())
                        .map_err(|_| KeyAgentLpacError::Token)?,
                )
            }
            .map_err(|_| KeyAgentLpacError::Token)?;
            if token_owner_sid(token)? != original_sid {
                return Err(KeyAgentLpacError::Token);
            }
        }
        Ok(switch)
    }

    fn install_test_token_default_dacl(
        token: HANDLE,
        owner: &mut TestOwnedDefaultDacl,
    ) -> Result<(), KeyAgentLpacError> {
        set_raw_token_default_dacl_for_test(token, owner.as_acl_mut_ptr())
            .map_err(|_| KeyAgentLpacError::Token)?;
        let readback = capture_token_default_dacl(token)?;
        if readback.bytes() != owner.bytes() {
            return Err(KeyAgentLpacError::Token);
        }
        Ok(())
    }

    fn acl_allows_complete_mask_for_sid(acl: &[u8], sid: &[u8], mask: u32) -> bool {
        if acl.len() < 8 {
            return false;
        }
        let Ok(ace_count_bytes) = <[u8; 2]>::try_from(&acl[4..6]) else {
            return false;
        };
        let ace_count = usize::from(u16::from_le_bytes(ace_count_bytes));
        let Ok(allowed_type) = u8::try_from(ACCESS_ALLOWED_ACE_TYPE) else {
            return false;
        };
        let mut cursor = 8_usize;
        for _ in 0..ace_count {
            let Some(header) = acl.get(cursor..cursor.saturating_add(8)) else {
                return false;
            };
            let Ok(ace_size_bytes) = <[u8; 2]>::try_from(&header[2..4]) else {
                return false;
            };
            let ace_size = usize::from(u16::from_le_bytes(ace_size_bytes));
            let Some(ace_end) = cursor.checked_add(ace_size) else {
                return false;
            };
            let Some(ace) = acl.get(cursor..ace_end) else {
                return false;
            };
            if ace[0] == allowed_type && ace_size >= 8 {
                let Ok(ace_mask_bytes) = <[u8; 4]>::try_from(&ace[4..8]) else {
                    return false;
                };
                let ace_mask = u32::from_le_bytes(ace_mask_bytes);
                if &ace[8..] == sid && ace_mask & mask == mask {
                    return true;
                }
            }
            cursor = ace_end;
        }
        false
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum PreResumeDefaultDaclCase {
        UnmodifiedControl,
        OriginalDeepCopyControl,
        DenyOwnerRights,
        DenyOwnerRightsSystem,
        DenyOwnerRightsPackage,
        DenyOwnerRightsSystemPackage,
        DenyOwnerRightsUserPackage,
        DenyOwnerRightsSystemUserPackage,
    }

    impl PreResumeDefaultDaclCase {
        const CASES: [Self; 8] = [
            Self::UnmodifiedControl,
            Self::OriginalDeepCopyControl,
            Self::DenyOwnerRights,
            Self::DenyOwnerRightsSystem,
            Self::DenyOwnerRightsPackage,
            Self::DenyOwnerRightsSystemPackage,
            Self::DenyOwnerRightsUserPackage,
            Self::DenyOwnerRightsSystemUserPackage,
        ];

        fn expected_exit_code(self) -> u32 {
            match self {
                Self::UnmodifiedControl | Self::OriginalDeepCopyControl => 0,
                Self::DenyOwnerRights
                | Self::DenyOwnerRightsSystem
                | Self::DenyOwnerRightsPackage
                | Self::DenyOwnerRightsSystemPackage
                | Self::DenyOwnerRightsUserPackage
                | Self::DenyOwnerRightsSystemUserPackage => STATUS_DLL_INIT_FAILED,
            }
        }

        fn is_explicit_attenuation_candidate(self) -> bool {
            !matches!(
                self,
                Self::UnmodifiedControl | Self::OriginalDeepCopyControl
            )
        }

        fn explicitly_grants_user_generic_all(self) -> bool {
            matches!(
                self,
                Self::DenyOwnerRightsUserPackage | Self::DenyOwnerRightsSystemUserPackage
            )
        }

        fn build(
            self,
            original: &TestOwnedDefaultDacl,
            user_sid: &[u8],
            package_sid: &[u8],
        ) -> Result<Option<TestOwnedDefaultDacl>, KeyAgentLpacError> {
            match self {
                Self::UnmodifiedControl => return Ok(None),
                Self::OriginalDeepCopyControl => {
                    return TestOwnedDefaultDacl::from_bytes(original.bytes()).map(Some);
                }
                _ => {}
            }
            let mut aces = vec![TestDefaultDaclAce {
                kind: TestDefaultDaclAceKind::Deny,
                mask: CREATION_SECURITY_DENIED_ACCESS,
                sid: &OWNER_RIGHTS_SID_BYTES,
            }];
            if matches!(
                self,
                Self::DenyOwnerRightsSystem
                    | Self::DenyOwnerRightsSystemPackage
                    | Self::DenyOwnerRightsSystemUserPackage
            ) {
                aces.push(TestDefaultDaclAce {
                    kind: TestDefaultDaclAceKind::Allow,
                    mask: TEST_GENERIC_ALL,
                    sid: &LOCAL_SYSTEM_SID_BYTES,
                });
            }
            if self.explicitly_grants_user_generic_all() {
                aces.push(TestDefaultDaclAce {
                    kind: TestDefaultDaclAceKind::Allow,
                    mask: TEST_GENERIC_ALL,
                    sid: user_sid,
                });
            }
            if matches!(
                self,
                Self::DenyOwnerRightsPackage
                    | Self::DenyOwnerRightsSystemPackage
                    | Self::DenyOwnerRightsUserPackage
                    | Self::DenyOwnerRightsSystemUserPackage
            ) {
                aces.push(TestDefaultDaclAce {
                    kind: TestDefaultDaclAceKind::Allow,
                    mask: TEST_GENERIC_ALL,
                    sid: package_sid,
                });
            }
            TestOwnedDefaultDacl::from_aces(&aces).map(Some)
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct PreResumeDefaultDaclOutcome {
        case: PreResumeDefaultDaclCase,
        exit_code: u32,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum OwnerRightsDenyMaskCase {
        ReadControl,
        WriteDac,
        WriteOwner,
        WriteDacWriteOwner,
        ReadControlWriteDac,
    }

    impl OwnerRightsDenyMaskCase {
        const CASES: [Self; 5] = [
            Self::ReadControl,
            Self::WriteDac,
            Self::WriteOwner,
            Self::WriteDacWriteOwner,
            Self::ReadControlWriteDac,
        ];

        const fn mask(self) -> u32 {
            match self {
                Self::ReadControl => 0x0002_0000,
                Self::WriteDac => 0x0004_0000,
                Self::WriteOwner => 0x0008_0000,
                Self::WriteDacWriteOwner => 0x000c_0000,
                Self::ReadControlWriteDac => 0x0006_0000,
            }
        }

        fn build(
            self,
            user_sid: &[u8],
            package_sid: &[u8],
        ) -> Result<TestOwnedDefaultDacl, KeyAgentLpacError> {
            TestOwnedDefaultDacl::from_aces(&[
                TestDefaultDaclAce {
                    kind: TestDefaultDaclAceKind::Deny,
                    mask: self.mask(),
                    sid: &OWNER_RIGHTS_SID_BYTES,
                },
                TestDefaultDaclAce {
                    kind: TestDefaultDaclAceKind::Allow,
                    mask: TEST_GENERIC_ALL,
                    sid: &LOCAL_SYSTEM_SID_BYTES,
                },
                TestDefaultDaclAce {
                    kind: TestDefaultDaclAceKind::Allow,
                    mask: TEST_GENERIC_ALL,
                    sid: package_sid,
                },
                TestDefaultDaclAce {
                    kind: TestDefaultDaclAceKind::Allow,
                    mask: TEST_GENERIC_ALL,
                    sid: user_sid,
                },
            ])
        }
    }

    #[derive(Eq, PartialEq)]
    struct OwnerRightsDenyMaskOutcome {
        case: OwnerRightsDenyMaskCase,
        exit_code: u32,
    }

    impl core::fmt::Debug for OwnerRightsDenyMaskOutcome {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(
                formatter,
                "OwnerRightsDenyMaskOutcome({:?}, 0x{:08x})",
                self.case, self.exit_code
            )
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum SanitizedAceKind {
        Allow,
        Deny,
        Other(u8),
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum SanitizedAcePrincipal {
        ChildUser,
        ExactPackage,
        LocalSystem,
        OwnerRights,
        AllApplicationPackages,
        AllRestrictedApplicationPackages,
        AuthenticatedUsers,
        BuiltinAdministrators,
        CreatorOwner,
        LogonSession,
        Other,
        NotApplicable,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SanitizedDefaultDaclAce {
        kind: SanitizedAceKind,
        flags: u8,
        mask: u32,
        principal: SanitizedAcePrincipal,
    }

    fn classify_sanitized_ace_principal(
        sid: &[u8],
        user_sid: &[u8],
        package_sid: &[u8],
    ) -> SanitizedAcePrincipal {
        const AUTHENTICATED_USERS: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0];
        const CREATOR_OWNER: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0];
        const ALL_APPLICATION_PACKAGES: [u8; 16] =
            [1, 2, 0, 0, 0, 0, 0, 15, 2, 0, 0, 0, 1, 0, 0, 0];
        const ALL_RESTRICTED_APPLICATION_PACKAGES: [u8; 16] =
            [1, 2, 0, 0, 0, 0, 0, 15, 2, 0, 0, 0, 2, 0, 0, 0];
        const BUILTIN_ADMINISTRATORS: [u8; 16] = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];

        if sid == user_sid {
            SanitizedAcePrincipal::ChildUser
        } else if sid == package_sid {
            SanitizedAcePrincipal::ExactPackage
        } else if sid == LOCAL_SYSTEM_SID_BYTES {
            SanitizedAcePrincipal::LocalSystem
        } else if sid == OWNER_RIGHTS_SID_BYTES {
            SanitizedAcePrincipal::OwnerRights
        } else if sid == ALL_APPLICATION_PACKAGES {
            SanitizedAcePrincipal::AllApplicationPackages
        } else if sid == ALL_RESTRICTED_APPLICATION_PACKAGES {
            SanitizedAcePrincipal::AllRestrictedApplicationPackages
        } else if sid == AUTHENTICATED_USERS {
            SanitizedAcePrincipal::AuthenticatedUsers
        } else if sid == BUILTIN_ADMINISTRATORS {
            SanitizedAcePrincipal::BuiltinAdministrators
        } else if sid == CREATOR_OWNER {
            SanitizedAcePrincipal::CreatorOwner
        } else if sid.len() == 20
            && sid[..8] == [1, 3, 0, 0, 0, 0, 0, 5]
            && sid[8..12] == [5, 0, 0, 0]
        {
            SanitizedAcePrincipal::LogonSession
        } else {
            SanitizedAcePrincipal::Other
        }
    }

    fn sanitized_default_dacl_classification(
        acl: &[u8],
        user_sid: &[u8],
        package_sid: &[u8],
    ) -> Result<Vec<SanitizedDefaultDaclAce>, KeyAgentLpacError> {
        if acl.len() < 8 {
            return Err(KeyAgentLpacError::Token);
        }
        let ace_count = usize::from(u16::from_le_bytes(
            acl.get(4..6)
                .ok_or(KeyAgentLpacError::Token)?
                .try_into()
                .map_err(|_| KeyAgentLpacError::Token)?,
        ));
        let allow_type =
            u8::try_from(ACCESS_ALLOWED_ACE_TYPE).map_err(|_| KeyAgentLpacError::Token)?;
        let deny_type =
            u8::try_from(ACCESS_DENIED_ACE_TYPE).map_err(|_| KeyAgentLpacError::Token)?;
        let mut report = Vec::with_capacity(ace_count);
        let mut cursor = 8_usize;
        for _ in 0..ace_count {
            let header = acl
                .get(cursor..cursor.checked_add(8).ok_or(KeyAgentLpacError::Token)?)
                .ok_or(KeyAgentLpacError::Token)?;
            let ace_size = usize::from(u16::from_le_bytes(
                header[2..4]
                    .try_into()
                    .map_err(|_| KeyAgentLpacError::Token)?,
            ));
            let ace_end = cursor
                .checked_add(ace_size)
                .ok_or(KeyAgentLpacError::Token)?;
            let ace = acl.get(cursor..ace_end).ok_or(KeyAgentLpacError::Token)?;
            let kind = if ace[0] == allow_type {
                SanitizedAceKind::Allow
            } else if ace[0] == deny_type {
                SanitizedAceKind::Deny
            } else {
                SanitizedAceKind::Other(ace[0])
            };
            let mask =
                u32::from_le_bytes(ace[4..8].try_into().map_err(|_| KeyAgentLpacError::Token)?);
            let principal = if matches!(kind, SanitizedAceKind::Allow | SanitizedAceKind::Deny) {
                let sid = ace.get(8..).ok_or(KeyAgentLpacError::Token)?;
                validate_test_sid_bytes(sid)?;
                classify_sanitized_ace_principal(sid, user_sid, package_sid)
            } else {
                SanitizedAcePrincipal::NotApplicable
            };
            report.push(SanitizedDefaultDaclAce {
                kind,
                flags: ace[1],
                mask,
                principal,
            });
            cursor = ace_end;
        }
        Ok(report)
    }

    const THREAD_PROBE_READY: u32 = 1;
    const THREAD_PROBE_COMPLETE: u32 = 2;
    const THREAD_PROBE_GET_TIMES_FAILED: u32 = 0xe0a0_0101;
    const THREAD_PROBE_TOKEN_RESULT_FAILED: u32 = 0xe0a0_0102;
    const THREAD_PROBE_WAIT_FAILED: u32 = 0xe0a0_0103;

    struct CreationSecurityThreadProbeContext {
        release: HANDLE,
        state: AtomicU32,
    }

    // SAFETY: the unnamed event handle is valid process-wide and Windows
    // permits SetEvent, WaitForSingleObject, and CloseHandle from any thread.
    // `state` provides the only shared mutable data and is atomic.
    unsafe impl Send for CreationSecurityThreadProbeContext {}

    // SAFETY: the same process-wide event guarantee and atomic state make
    // shared references safe across the creator and native probe threads.
    unsafe impl Sync for CreationSecurityThreadProbeContext {}

    impl CreationSecurityThreadProbeContext {
        fn close_checked(mut self) -> Result<(), KeyAgentLpacError> {
            if self.release.is_invalid() || self.release == INVALID_HANDLE_VALUE {
                return Err(KeyAgentLpacError::Attribute);
            }
            // SAFETY: the native thread has been joined and released its Arc;
            // this unique context owner now exclusively owns the event handle.
            unsafe { CloseHandle(self.release) }.map_err(|_| KeyAgentLpacError::Attribute)?;
            self.release = HANDLE::default();
            Ok(())
        }
    }

    impl Drop for CreationSecurityThreadProbeContext {
        fn drop(&mut self) {
            if !self.release.is_invalid() && self.release != INVALID_HANDLE_VALUE {
                // SAFETY: the final Arc owns the unnamed event. A native probe
                // thread retains an Arc for its complete wait, so this cannot
                // close the event while that wait or context access is live.
                unsafe {
                    let _ = CloseHandle(self.release);
                }
                self.release = HANDLE::default();
            }
        }
    }

    struct CreationSecurityThreadProbeHandles {
        thread: HANDLE,
        release: HANDLE,
    }

    impl CreationSecurityThreadProbeHandles {
        fn finish(&mut self) -> Result<(), KeyAgentLpacError> {
            if self.thread.is_invalid()
                || self.thread == INVALID_HANDLE_VALUE
                || self.release.is_invalid()
                || self.release == INVALID_HANDLE_VALUE
            {
                return Err(KeyAgentLpacError::Attribute);
            }
            // SAFETY: the event and thread are exclusively owned and the event
            // is the probe routine's sole bounded release condition.
            let signaled = unsafe { SetEvent(self.release) };
            if signaled.is_err() {
                // SAFETY: deterministic test-only cleanup if signaling the
                // otherwise event-blocked probe unexpectedly fails.
                unsafe {
                    let _ = TerminateThread(self.thread, THREAD_PROBE_WAIT_FAILED);
                }
            }
            // SAFETY: the same live creator-owned thread handle is waited with
            // a finite bound after signal (or forced cleanup) was attempted.
            let mut wait = unsafe { WaitForSingleObject(self.thread, 5_000) };
            if wait != WAIT_OBJECT_0 {
                // SAFETY: this test-only thread executes only this bounded
                // probe. Forced termination is followed by a second join; its
                // Arc-held context/event stays live even if that join fails.
                unsafe {
                    let _ = TerminateThread(self.thread, THREAD_PROBE_WAIT_FAILED);
                    wait = WaitForSingleObject(self.thread, 5_000);
                }
            }
            // SAFETY: the creator handle is exclusively owned. The context's
            // Arc, rather than this guard, owns the release event.
            let thread_closed = unsafe { CloseHandle(self.thread) };
            if thread_closed.is_ok() {
                self.thread = HANDLE::default();
            }
            self.release = HANDLE::default();
            signaled.map_err(|_| KeyAgentLpacError::Attribute)?;
            if wait != WAIT_OBJECT_0 {
                return Err(KeyAgentLpacError::Attribute);
            }
            thread_closed.map_err(|_| KeyAgentLpacError::Attribute)
        }
    }

    impl Drop for CreationSecurityThreadProbeHandles {
        fn drop(&mut self) {
            if !self.thread.is_invalid() && self.thread != INVALID_HANDLE_VALUE {
                // SAFETY: best-effort bounded release of the exact test thread.
                unsafe {
                    if !self.release.is_invalid()
                        && self.release != INVALID_HANDLE_VALUE
                        && SetEvent(self.release).is_err()
                    {
                        let _ = TerminateThread(self.thread, THREAD_PROBE_WAIT_FAILED);
                    }
                    if WaitForSingleObject(self.thread, 5_000) != WAIT_OBJECT_0 {
                        let _ = TerminateThread(self.thread, THREAD_PROBE_WAIT_FAILED);
                        let _ = WaitForSingleObject(self.thread, 5_000);
                    }
                    let _ = CloseHandle(self.thread);
                }
                self.thread = HANDLE::default();
            }
            // The Arc-held context owns the release event and remains live in
            // the native thread until its start routine exits, including every
            // timeout/forced-cleanup path.
            self.release = HANDLE::default();
        }
    }

    unsafe extern "system" fn creation_security_thread_probe_start(parameter: *mut c_void) -> u32 {
        if parameter.is_null() {
            return THREAD_PROBE_GET_TIMES_FAILED;
        }
        // SAFETY: the creator passes exactly one Arc::into_raw strong reference
        // and transfers it to this start routine. Rebuilding the Arc retains
        // both the context and event through every return path.
        let context =
            unsafe { Arc::from_raw(parameter.cast::<CreationSecurityThreadProbeContext>()) };
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: GetCurrentThread returns this routine's pseudo handle and all
        // four outputs are exact writable FILETIME values.
        if unsafe {
            GetThreadTimes(
                GetCurrentThread(),
                &raw mut creation,
                &raw mut exit,
                &raw mut kernel,
                &raw mut user,
            )
        }
        .is_err()
        {
            context
                .state
                .store(THREAD_PROBE_GET_TIMES_FAILED, Ordering::Release);
            return THREAD_PROBE_GET_TIMES_FAILED;
        }

        let mut unexpected_token = HANDLE::default();
        // SAFETY: this is the current-thread pseudo handle. `open_as_self`
        // avoids an access check against a nonexistent impersonation context.
        match unsafe {
            OpenThreadToken(
                GetCurrentThread(),
                TOKEN_QUERY,
                true,
                &raw mut unexpected_token,
            )
        } {
            Err(error) if error.code() == ERROR_NO_TOKEN.to_hresult() => {}
            Ok(()) => {
                if !unexpected_token.is_invalid() && unexpected_token != INVALID_HANDLE_VALUE {
                    // SAFETY: unexpected success returned one owned token.
                    unsafe {
                        let _ = CloseHandle(unexpected_token);
                    }
                }
                context
                    .state
                    .store(THREAD_PROBE_TOKEN_RESULT_FAILED, Ordering::Release);
                return THREAD_PROBE_TOKEN_RESULT_FAILED;
            }
            Err(_) => {
                context
                    .state
                    .store(THREAD_PROBE_TOKEN_RESULT_FAILED, Ordering::Release);
                return THREAD_PROBE_TOKEN_RESULT_FAILED;
            }
        }

        context.state.store(THREAD_PROBE_READY, Ordering::Release);
        // SAFETY: the creator retains this exact event until the routine exits.
        if unsafe { WaitForSingleObject(context.release, 5_000) } != WAIT_OBJECT_0 {
            context
                .state
                .store(THREAD_PROBE_WAIT_FAILED, Ordering::Release);
            return THREAD_PROBE_WAIT_FAILED;
        }
        context
            .state
            .store(THREAD_PROBE_COMPLETE, Ordering::Release);
        0
    }

    fn creation_dacl_probe_privilege_luid(name: &str) -> Result<LUID, KeyAgentLpacError> {
        let name = creation_security_wide_nul(name)?;
        let mut luid = LUID::default();
        // SAFETY: the fixed privilege name is NUL terminated and output is one
        // exact writable LUID. Null system name selects the local system.
        unsafe { LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(name.as_ptr()), &raw mut luid) }
            .map_err(|_| KeyAgentLpacError::Attribute)?;
        Ok(luid)
    }

    fn require_creation_dacl_probe_privileges_disabled() -> Result<(), KeyAgentLpacError> {
        let debug = creation_dacl_probe_privilege_luid("SeDebugPrivilege")?;
        let take_ownership = creation_dacl_probe_privilege_luid("SeTakeOwnershipPrivilege")?;
        let token = open_current_process_creation_security_token()?;
        let information = creation_security_token_information(token.0, TokenPrivileges)?;
        let entries_offset = offset_of!(TOKEN_PRIVILEGES, Privileges);
        if information.returned_bytes < entries_offset {
            return Err(KeyAgentLpacError::Attribute);
        }
        // SAFETY: the exact returned byte count lies within the live aligned
        // allocation and contains at least the leading privilege count.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                information.words.as_ptr().cast::<u8>(),
                information.returned_bytes,
            )
        };
        let count = usize::try_from(u32::from_le_bytes(
            bytes[..size_of::<u32>()]
                .try_into()
                .map_err(|_| KeyAgentLpacError::Attribute)?,
        ))
        .map_err(|_| KeyAgentLpacError::Attribute)?;
        let required = count
            .checked_mul(size_of::<LUID_AND_ATTRIBUTES>())
            .and_then(|entry_bytes| entries_offset.checked_add(entry_bytes))
            .ok_or(KeyAgentLpacError::Attribute)?;
        if required != information.returned_bytes {
            return Err(KeyAgentLpacError::Attribute);
        }
        for index in 0..count {
            let offset = index
                .checked_mul(size_of::<LUID_AND_ATTRIBUTES>())
                .and_then(|entry_bytes| entries_offset.checked_add(entry_bytes))
                .ok_or(KeyAgentLpacError::Attribute)?;
            // SAFETY: the exact flexible-array extent was checked above.
            let entry = unsafe {
                ptr::read_unaligned(bytes.as_ptr().add(offset).cast::<LUID_AND_ATTRIBUTES>())
            };
            let is_guarded_privilege = entry.Luid == debug || entry.Luid == take_ownership;
            if is_guarded_privilege && entry.Attributes.0 & SE_PRIVILEGE_ENABLED.0 != 0 {
                return Err(KeyAgentLpacError::Attribute);
            }
        }
        Ok(())
    }

    fn require_creation_dacl_thread_reopen_denials(
        thread_id: u32,
    ) -> Result<(), KeyAgentLpacError> {
        const THREAD_SYNCHRONIZE: THREAD_ACCESS_RIGHTS = THREAD_ACCESS_RIGHTS(0x0010_0000);
        if thread_id == 0 {
            return Err(KeyAgentLpacError::Attribute);
        }
        for desired_access in [
            THREAD_TERMINATE,
            THREAD_SUSPEND_RESUME,
            THREAD_GET_CONTEXT,
            THREAD_SET_CONTEXT,
            THREAD_SET_INFORMATION,
            THREAD_QUERY_INFORMATION,
            THREAD_SET_THREAD_TOKEN,
            THREAD_IMPERSONATE,
            THREAD_DIRECT_IMPERSONATION,
            THREAD_SET_LIMITED_INFORMATION,
            THREAD_QUERY_LIMITED_INFORMATION,
            THREAD_ACCESS_RIGHTS(DELETE.0),
            THREAD_ACCESS_RIGHTS(READ_CONTROL.0),
            THREAD_ACCESS_RIGHTS(WRITE_DAC.0),
            THREAD_ACCESS_RIGHTS(WRITE_OWNER.0),
            THREAD_SYNCHRONIZE,
        ] {
            if desired_access.0.count_ones() != 1 {
                return Err(KeyAgentLpacError::Attribute);
            }
            // SAFETY: callers retain the exact live blocked or suspended thread
            // while this fresh TID reopen is attempted without inheritance.
            match unsafe { OpenThread(desired_access, false, thread_id) } {
                Err(error) if error.code() == ERROR_ACCESS_DENIED.to_hresult() => {}
                Ok(unexpected) => {
                    if !unexpected.is_invalid() && unexpected != INVALID_HANDLE_VALUE {
                        // SAFETY: unexpected success returned one fresh handle.
                        unsafe {
                            let _ = CloseHandle(unexpected);
                        }
                    }
                    return Err(KeyAgentLpacError::Attribute);
                }
                Err(_) => return Err(KeyAgentLpacError::Attribute),
            }
        }
        Ok(())
    }

    fn require_creation_dacl_thread_default_reopens(
        thread_id: u32,
    ) -> Result<(), KeyAgentLpacError> {
        const THREAD_SYNCHRONIZE: THREAD_ACCESS_RIGHTS = THREAD_ACCESS_RIGHTS(0x0010_0000);
        if thread_id == 0 {
            return Err(KeyAgentLpacError::Attribute);
        }
        for desired_access in [THREAD_QUERY_LIMITED_INFORMATION, THREAD_SYNCHRONIZE] {
            // SAFETY: callers retain the exact live blocked or suspended thread
            // while this fresh TID reopen is attempted without inheritance.
            let reopened = unsafe { OpenThread(desired_access, false, thread_id) }
                .map_err(|_| KeyAgentLpacError::Attribute)?;
            if reopened.is_invalid() || reopened == INVALID_HANDLE_VALUE {
                return Err(KeyAgentLpacError::Attribute);
            }
            // SAFETY: each successful iteration owns one independently opened
            // handle and closes it before requesting the next single right.
            unsafe { CloseHandle(reopened) }.map_err(|_| KeyAgentLpacError::Attribute)?;
        }
        Ok(())
    }

    fn require_creation_dacl_process_reopen_denials(
        process_id: u32,
    ) -> Result<(), KeyAgentLpacError> {
        const PROCESS_SET_LIMITED_INFORMATION: PROCESS_ACCESS_RIGHTS =
            PROCESS_ACCESS_RIGHTS(0x0000_2000);
        const PROCESS_SYNCHRONIZE: PROCESS_ACCESS_RIGHTS = PROCESS_ACCESS_RIGHTS(0x0010_0000);
        if process_id == 0 {
            return Err(KeyAgentLpacError::Attribute);
        }
        for desired_access in [
            PROCESS_TERMINATE,
            PROCESS_CREATE_THREAD,
            PROCESS_VM_OPERATION,
            PROCESS_VM_READ,
            PROCESS_VM_WRITE,
            PROCESS_DUP_HANDLE,
            PROCESS_CREATE_PROCESS,
            PROCESS_SET_QUOTA,
            PROCESS_SET_INFORMATION,
            PROCESS_QUERY_INFORMATION,
            PROCESS_SUSPEND_RESUME,
            PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_SET_LIMITED_INFORMATION,
            PROCESS_ACCESS_RIGHTS(DELETE.0),
            PROCESS_ACCESS_RIGHTS(READ_CONTROL.0),
            PROCESS_ACCESS_RIGHTS(WRITE_DAC.0),
            PROCESS_ACCESS_RIGHTS(WRITE_OWNER.0),
            PROCESS_SYNCHRONIZE,
        ] {
            if desired_access.0.count_ones() != 1 {
                return Err(KeyAgentLpacError::Attribute);
            }
            // SAFETY: callers retain the exact live suspended process while
            // this fresh PID reopen is attempted without inheritance.
            match unsafe { OpenProcess(desired_access, false, process_id) } {
                Ok(unexpected) => {
                    if !unexpected.is_invalid() && unexpected != INVALID_HANDLE_VALUE {
                        // SAFETY: unexpected success returned one fresh handle.
                        unsafe {
                            let _ = CloseHandle(unexpected);
                        }
                    }
                    return Err(KeyAgentLpacError::Attribute);
                }
                Err(error) if error.code() == ERROR_ACCESS_DENIED.to_hresult() => {}
                Err(_) => return Err(KeyAgentLpacError::Attribute),
            }
        }
        Ok(())
    }

    fn require_creation_dacl_process_default_reopens(
        process_id: u32,
    ) -> Result<(), KeyAgentLpacError> {
        const PROCESS_SYNCHRONIZE: PROCESS_ACCESS_RIGHTS = PROCESS_ACCESS_RIGHTS(0x0010_0000);
        if process_id == 0 {
            return Err(KeyAgentLpacError::Attribute);
        }
        for desired_access in [PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE] {
            // SAFETY: callers retain the exact live suspended process while
            // this fresh PID reopen is attempted without inheritance.
            let reopened = unsafe { OpenProcess(desired_access, false, process_id) }
                .map_err(|_| KeyAgentLpacError::Attribute)?;
            if reopened.is_invalid() || reopened == INVALID_HANDLE_VALUE {
                return Err(KeyAgentLpacError::Attribute);
            }
            // SAFETY: each successful iteration owns one independently opened
            // handle and closes it before requesting the next single right.
            unsafe { CloseHandle(reopened) }.map_err(|_| KeyAgentLpacError::Attribute)?;
        }
        Ok(())
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
            inherited_handles: None,
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

    fn exact_key_agent_attribute_list(
        prepared: &PreparedKeyAgentLpac,
    ) -> Result<TestAttributeList, KeyAgentLpacError> {
        exact_key_agent_attribute_list_with_handles(prepared, None)
    }

    fn exact_key_agent_attribute_list_with_handles(
        prepared: &PreparedKeyAgentLpac,
        inherited_handles: Option<[HANDLE; 2]>,
    ) -> Result<TestAttributeList, KeyAgentLpacError> {
        let attribute_count = if inherited_handles.is_some() { 3 } else { 2 };
        let mut bytes = 0_usize;
        // SAFETY: documented sizing call with a null list and writable size.
        let _ = unsafe {
            InitializeProcThreadAttributeList(None, attribute_count, None, &raw mut bytes)
        };
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
        unsafe {
            InitializeProcThreadAttributeList(Some(pointer), attribute_count, None, &raw mut bytes)
        }
        .map_err(|_| KeyAgentLpacError::Attribute)?;
        let attributes = TestAttributeList {
            pointer,
            _words: words,
            inherited_handles: inherited_handles.map(Box::new),
        };
        // SAFETY: the initialized two-slot list and prepared pointer owners
        // remain live through the process-creation call below.
        unsafe { prepared.install_into(attributes.pointer) }?;
        if let Some(handles) = attributes.inherited_handles.as_deref() {
            if handles[0] == handles[1]
                || handles
                    .iter()
                    .any(|handle| handle.is_invalid() || *handle == INVALID_HANDLE_VALUE)
            {
                return Err(KeyAgentLpacError::Attribute);
            }
            // SAFETY: the initialized list has its third slot free. The boxed
            // exact handle pair is stable in `attributes` through CreateProcessW.
            unsafe {
                UpdateProcThreadAttribute(
                    attributes.pointer,
                    0,
                    usize::try_from(PROC_THREAD_ATTRIBUTE_HANDLE_LIST)
                        .map_err(|_| KeyAgentLpacError::Attribute)?,
                    Some(handles.as_ptr().cast::<c_void>()),
                    size_of::<[HANDLE; 2]>(),
                    None,
                    None,
                )
            }
            .map_err(|_| KeyAgentLpacError::Attribute)?;
        }
        Ok(attributes)
    }

    fn create_suspended_regular_appcontainer(
        prepared: &PreparedKeyAgentLpac,
        fixture: &KeyAgentLpacKernelTestFixture,
    ) -> Result<TestSuspendedProcess, KeyAgentLpacError> {
        let attributes = regular_appcontainer_attribute_list(prepared)?;
        create_suspended_appcontainer(prepared, fixture, &attributes, None, None)
    }

    fn create_suspended_key_agent_lpac(
        prepared: &PreparedKeyAgentLpac,
        fixture: &KeyAgentLpacKernelTestFixture,
    ) -> Result<TestSuspendedProcess, KeyAgentLpacError> {
        let attributes = exact_key_agent_attribute_list(prepared)?;
        create_suspended_appcontainer(prepared, fixture, &attributes, None, None)
    }

    fn create_suspended_key_agent_lpac_for_creation_dacl_axis(
        prepared: &PreparedKeyAgentLpac,
        fixture: &KeyAgentLpacKernelTestFixture,
        creation_security: &PreparedKeyAgentCreationSecurity,
        axis: CreationDaclAxis,
    ) -> Result<TestSuspendedProcess, KeyAgentLpacError> {
        let attributes = exact_key_agent_attribute_list(prepared)?;
        create_suspended_appcontainer(
            prepared,
            fixture,
            &attributes,
            axis.process_attributes(creation_security),
            axis.primary_thread_attributes(creation_security),
        )
    }

    fn create_suspended_key_agent_lpac_exact_child(
        prepared: &PreparedKeyAgentLpac,
        fixture: &KeyAgentLpacKernelTestFixture,
        creation_security: &PreparedKeyAgentCreationSecurity,
        command_line: &mut [u16],
    ) -> Result<TestSuspendedProcess, KeyAgentLpacError> {
        let attributes = exact_key_agent_attribute_list(prepared)?;
        create_suspended_appcontainer_with_command_line(
            prepared,
            fixture,
            &attributes,
            TestChildLaunchOptions {
                process_attributes: Some(&creation_security.process_attributes),
                primary_thread_attributes: Some(&creation_security.primary_thread_attributes),
                command_line: Some(command_line),
                inherit_handles: false,
                extra_environment: &[],
            },
        )
    }

    fn create_suspended_key_agent_lpac_handshake_child(
        prepared: &PreparedKeyAgentLpac,
        fixture: &KeyAgentLpacKernelTestFixture,
        creation_security: &PreparedKeyAgentCreationSecurity,
        command_line: &mut [u16],
        pipes: &TestHandshakePipes,
    ) -> Result<TestSuspendedProcess, KeyAgentLpacError> {
        let child_handles = pipes.child_handles()?;
        let attributes =
            exact_key_agent_attribute_list_with_handles(prepared, Some(child_handles))?;
        let environment = pipes.child_environment()?;
        create_suspended_appcontainer_with_command_line(
            prepared,
            fixture,
            &attributes,
            TestChildLaunchOptions {
                process_attributes: Some(&creation_security.process_attributes),
                primary_thread_attributes: Some(&creation_security.primary_thread_attributes),
                command_line: Some(command_line),
                inherit_handles: true,
                extra_environment: &environment,
            },
        )
    }

    fn create_suspended_appcontainer(
        prepared: &PreparedKeyAgentLpac,
        fixture: &KeyAgentLpacKernelTestFixture,
        attributes: &TestAttributeList,
        process_attributes: Option<&SECURITY_ATTRIBUTES>,
        primary_thread_attributes: Option<&SECURITY_ATTRIBUTES>,
    ) -> Result<TestSuspendedProcess, KeyAgentLpacError> {
        create_suspended_appcontainer_with_command_line(
            prepared,
            fixture,
            attributes,
            TestChildLaunchOptions {
                process_attributes,
                primary_thread_attributes,
                command_line: None,
                inherit_handles: false,
                extra_environment: &[],
            },
        )
    }

    struct TestChildLaunchOptions<'a> {
        process_attributes: Option<&'a SECURITY_ATTRIBUTES>,
        primary_thread_attributes: Option<&'a SECURITY_ATTRIBUTES>,
        command_line: Option<&'a mut [u16]>,
        inherit_handles: bool,
        extra_environment: &'a [String],
    }

    fn append_test_environment_entries(
        environment: &mut Vec<u16>,
        entries: &[String],
    ) -> Result<(), KeyAgentLpacError> {
        if entries.is_empty() {
            return Ok(());
        }
        if environment.len() < 2 || !environment.ends_with(&[0, 0]) {
            return Err(KeyAgentLpacError::Profile);
        }
        environment.pop();
        for entry in entries {
            if entry.is_empty()
                || entry.contains('\0')
                || !entry.is_ascii()
                || !entry.contains('=')
                || entry.starts_with('=')
            {
                return Err(KeyAgentLpacError::Profile);
            }
            environment.extend(entry.encode_utf16());
            environment.push(0);
        }
        environment.push(0);
        if environment.len() > 32_767 || !environment.ends_with(&[0, 0]) {
            return Err(KeyAgentLpacError::Profile);
        }
        Ok(())
    }

    fn create_suspended_appcontainer_with_command_line(
        prepared: &PreparedKeyAgentLpac,
        fixture: &KeyAgentLpacKernelTestFixture,
        attributes: &TestAttributeList,
        options: TestChildLaunchOptions<'_>,
    ) -> Result<TestSuspendedProcess, KeyAgentLpacError> {
        let TestChildLaunchOptions {
            process_attributes,
            primary_thread_attributes,
            command_line,
            inherit_handles,
            extra_environment,
        } = options;
        let context = RestrictedProcessContext::prepare_for_kernel_test()
            .map_err(|_| KeyAgentLpacError::Profile)?;
        let mut environment = prepared
            .environment_with_local_app_data(context.environment())?
            .into_vec();
        append_test_environment_entries(&mut environment, extra_environment)?;
        let application: Vec<u16> = fixture
            .path()
            .as_os_str()
            .encode_wide()
            .chain(core::iter::once(0))
            .collect();
        let command_line = match command_line {
            Some(command_line)
                if command_line.last() == Some(&0)
                    && !command_line[..command_line.len().saturating_sub(1)].contains(&0) =>
            {
                Some(PWSTR(command_line.as_mut_ptr()))
            }
            Some(_) => return Err(KeyAgentLpacError::Profile),
            None => None,
        };
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb =
            u32::try_from(size_of::<STARTUPINFOEXW>()).map_err(|_| KeyAgentLpacError::Profile)?;
        startup.lpAttributeList = attributes.pointer;
        let mut information = PROCESS_INFORMATION::default();
        // SAFETY: all pointer owners remain live for the call. The child gets an
        // explicit environment/current directory and CREATE_SUSPENDED. When
        // inheritance is enabled, the exact HANDLE_LIST is the sole allowlist.
        unsafe {
            CreateProcessW(
                PCWSTR(application.as_ptr()),
                command_line,
                process_attributes.map(ptr::from_ref),
                primary_thread_attributes.map(ptr::from_ref),
                inherit_handles,
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
            resumed: false,
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
    fn prepared_creation_security_owns_two_exact_noninheritable_descriptors()
    -> Result<(), KeyAgentLpacError> {
        let prepared = PreparedKeyAgentCreationSecurity::prepare()?;
        let attribute_bytes =
            u32::try_from(size_of::<windows::Win32::Security::SECURITY_ATTRIBUTES>())
                .map_err(|_| KeyAgentLpacError::Attribute)?;
        assert_eq!(prepared.process_attributes.nLength, attribute_bytes);
        assert_eq!(prepared.primary_thread_attributes.nLength, attribute_bytes);
        assert!(!prepared.process_attributes.bInheritHandle.as_bool());
        assert!(!prepared.primary_thread_attributes.bInheritHandle.as_bool());
        assert_eq!(
            prepared.process_attributes.lpSecurityDescriptor,
            prepared.process_descriptor.descriptor.0
        );
        assert_eq!(
            prepared.primary_thread_attributes.lpSecurityDescriptor,
            prepared.primary_thread_descriptor.descriptor.0
        );
        assert_ne!(
            prepared.process_attributes.lpSecurityDescriptor,
            prepared.primary_thread_attributes.lpSecurityDescriptor
        );
        inspect_exact_creation_security_descriptor(
            prepared.process_descriptor.bytes(),
            &prepared.expected_owner_sid,
            &prepared.expected_primary_group_sid,
        )?;
        inspect_exact_creation_security_descriptor(
            prepared.primary_thread_descriptor.bytes(),
            &prepared.expected_owner_sid,
            &prepared.expected_primary_group_sid,
        )?;
        let _paired = prepared.creation_security();
        assert_eq!(
            format!("{prepared:?}"),
            "PreparedKeyAgentCreationSecurity([OPAQUE PROCESS/THREAD POLICY])"
        );
        Ok(())
    }

    #[test]
    fn creation_dacl_process_and_primary_thread_axes_are_independent()
    -> Result<(), KeyAgentLpacError> {
        let creation_security = PreparedKeyAgentCreationSecurity::prepare()?;
        let prepared_lpac = PreparedKeyAgentLpac::prepare()?;
        let fixture = KeyAgentLpacKernelTestFixture::create()?;
        for axis in CreationDaclAxis::CASES {
            require_creation_dacl_probe_privileges_disabled()?;
            let mut process = create_suspended_key_agent_lpac_for_creation_dacl_axis(
                &prepared_lpac,
                &fixture,
                &creation_security,
                axis,
            )?;
            // SAFETY: these are the two still-suspended handles returned by the
            // exact successful CreateProcessW call and retained by the test owner.
            let process_id = unsafe { GetProcessId(process.process) };
            // SAFETY: same argument for the returned primary-thread handle.
            let primary_thread_id = unsafe { GetThreadId(process.thread) };

            match axis {
                CreationDaclAxis::DefaultBoth => {
                    require_creation_dacl_process_default_reopens(process_id)?;
                    require_creation_dacl_thread_default_reopens(primary_thread_id)?;
                }
                CreationDaclAxis::DenyProcessOnly => {
                    verify_created_object_security(
                        process.process,
                        &creation_security.expected_owner_sid,
                        &creation_security.expected_primary_group_sid,
                    )?;
                    require_creation_dacl_process_reopen_denials(process_id)?;
                    require_creation_dacl_thread_default_reopens(primary_thread_id)?;
                }
                CreationDaclAxis::DenyThreadOnly => {
                    verify_created_object_security(
                        process.thread,
                        &creation_security.expected_owner_sid,
                        &creation_security.expected_primary_group_sid,
                    )?;
                    require_creation_dacl_process_default_reopens(process_id)?;
                    require_creation_dacl_thread_reopen_denials(primary_thread_id)?;
                }
                CreationDaclAxis::DenyBoth => {
                    creation_security.verify_created_objects(
                        process.process_handle(),
                        process.primary_thread_handle(),
                    )?;
                    require_creation_dacl_process_reopen_denials(process_id)?;
                    require_creation_dacl_thread_reopen_denials(primary_thread_id)?;
                }
            }
            require_creation_dacl_probe_privileges_disabled()?;
            process.terminate_and_wait()?;
        }
        Ok(())
    }

    fn verify_default_created_thread_security(
        handle: HANDLE,
        expected_owner_sid: &[u8],
        expected_primary_group_sid: &[u8],
    ) -> Result<(), KeyAgentLpacError> {
        let descriptor = created_object_security_descriptor(handle)?;
        inspect_default_created_thread_security_descriptor(
            &descriptor,
            expected_owner_sid,
            expected_primary_group_sid,
        )
    }

    fn inspect_default_created_thread_security_descriptor(
        descriptor: &[u8],
        expected_owner_sid: &[u8],
        expected_primary_group_sid: &[u8],
    ) -> Result<(), KeyAgentLpacError> {
        if descriptor.len() < 20 || descriptor[0] != 1 || descriptor[1] != 0 {
            return Err(KeyAgentLpacError::Attribute);
        }
        let control = read_creation_security_u16_at(descriptor, 2)?;
        let required_control = SE_SELF_RELATIVE.0 | SE_DACL_PRESENT.0;
        if control & required_control != required_control
            || read_creation_security_u32_at(descriptor, 12)? != 0
        {
            return Err(KeyAgentLpacError::Attribute);
        }
        let owner_offset = usize::try_from(read_creation_security_u32_at(descriptor, 4)?)
            .map_err(|_| KeyAgentLpacError::Attribute)?;
        let group_offset = usize::try_from(read_creation_security_u32_at(descriptor, 8)?)
            .map_err(|_| KeyAgentLpacError::Attribute)?;
        let dacl_offset = usize::try_from(read_creation_security_u32_at(descriptor, 16)?)
            .map_err(|_| KeyAgentLpacError::Attribute)?;
        let (owner_sid, owner_end) = creation_security_sid_component(descriptor, owner_offset)?;
        let (group_sid, group_end) = creation_security_sid_component(descriptor, group_offset)?;
        if owner_sid != expected_owner_sid || group_sid != expected_primary_group_sid {
            return Err(KeyAgentLpacError::Attribute);
        }

        let dacl_header_end = dacl_offset
            .checked_add(8)
            .ok_or(KeyAgentLpacError::Attribute)?;
        if dacl_offset < 20
            || !dacl_offset.is_multiple_of(size_of::<u32>())
            || dacl_header_end > descriptor.len()
        {
            return Err(KeyAgentLpacError::Attribute);
        }
        let dacl_bytes = usize::from(read_creation_security_u16_at(descriptor, dacl_offset + 2)?);
        let dacl_end = dacl_offset
            .checked_add(dacl_bytes)
            .ok_or(KeyAgentLpacError::Attribute)?;
        let dacl = descriptor
            .get(dacl_offset..dacl_end)
            .ok_or(KeyAgentLpacError::Attribute)?;
        inspect_exact_token_default_dacl_bytes(dacl).map_err(|_| KeyAgentLpacError::Attribute)?;

        let mut regions = [
            (owner_offset, owner_end),
            (group_offset, group_end),
            (dacl_offset, dacl_end),
        ];
        regions.sort_unstable_by_key(|region| region.0);
        if regions
            .windows(2)
            .any(|adjacent| adjacent[0].1 > adjacent[1].0)
        {
            return Err(KeyAgentLpacError::Attribute);
        }
        Ok(())
    }

    type ThreadSecurityVerifier = fn(HANDLE, &[u8], &[u8]) -> Result<(), KeyAgentLpacError>;

    fn exercise_creation_security_thread_probe(
        security_attributes: Option<&SECURITY_ATTRIBUTES>,
        expected_owner_sid: &[u8],
        expected_primary_group_sid: &[u8],
        verify_security: ThreadSecurityVerifier,
        after_thread_ready: impl FnOnce(u32) -> Result<(), KeyAgentLpacError>,
        privilege_bookends: bool,
    ) -> Result<(), KeyAgentLpacError> {
        if privilege_bookends {
            require_creation_dacl_probe_privileges_disabled()?;
        }
        // SAFETY: default security and no name create one private,
        // non-inheritable manual-reset event owned by this probe.
        let release = unsafe { CreateEventW(None, true, false, None) }
            .map_err(|_| KeyAgentLpacError::Attribute)?;
        if release.is_invalid() || release == INVALID_HANDLE_VALUE {
            return Err(KeyAgentLpacError::Attribute);
        }
        let context = Arc::new(CreationSecurityThreadProbeContext {
            release,
            state: AtomicU32::new(0),
        });
        // The native routine owns a separate Arc strong reference, so every
        // timeout/termination path preserves its context and event even if its
        // destructor cannot run after TerminateThread.
        let native_context = Arc::into_raw(Arc::clone(&context));
        let mut handles = CreationSecurityThreadProbeHandles {
            thread: HANDLE::default(),
            release,
        };
        let mut thread_id = 0_u32;
        // SAFETY: optional attributes, when present, remain live for the call.
        // `native_context` transfers one Arc strong reference to the start
        // routine, which retains the context and event through exit.
        let thread_result = unsafe {
            CreateThread(
                security_attributes.map(ptr::from_ref),
                0,
                Some(creation_security_thread_probe_start),
                Some(native_context.cast::<c_void>()),
                THREAD_CREATION_FLAGS(0),
                Some(&raw mut thread_id),
            )
        };
        let Ok(thread) = thread_result else {
            // SAFETY: CreateThread failed, so the start routine did not consume
            // the one Arc::into_raw strong reference.
            unsafe {
                drop(Arc::from_raw(native_context));
            }
            return Err(KeyAgentLpacError::Attribute);
        };
        if thread.is_invalid() || thread == INVALID_HANDLE_VALUE || thread_id == 0 {
            if !thread.is_invalid() && thread != INVALID_HANDLE_VALUE {
                // SAFETY: reject and close any independently valid partial result.
                unsafe {
                    let _ = CloseHandle(thread);
                }
            }
            return Err(KeyAgentLpacError::Attribute);
        }
        handles.thread = thread;

        let ready_deadline = Instant::now()
            .checked_add(Duration::from_secs(5))
            .ok_or(KeyAgentLpacError::Attribute)?;
        loop {
            match context.state.load(Ordering::Acquire) {
                THREAD_PROBE_READY => break,
                0 => {}
                _ => return Err(KeyAgentLpacError::Attribute),
            }
            // SAFETY: zero-timeout observation uses the same live creator handle.
            if unsafe { WaitForSingleObject(handles.thread, 0) } == WAIT_OBJECT_0
                || Instant::now() >= ready_deadline
            {
                return Err(KeyAgentLpacError::Attribute);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        verify_security(
            handles.thread,
            expected_owner_sid,
            expected_primary_group_sid,
        )?;
        after_thread_ready(thread_id)?;
        // The privilege bookends make debug and take-ownership bypasses
        // (especially WRITE_OWNER) an explicit test failure, not ambiguity.
        require_creation_dacl_thread_reopen_denials(thread_id)?;
        if privilege_bookends {
            require_creation_dacl_probe_privileges_disabled()?;
        }
        handles.finish()?;
        if context.state.load(Ordering::Acquire) != THREAD_PROBE_COMPLETE {
            return Err(KeyAgentLpacError::Attribute);
        }
        let unique_context = Arc::try_unwrap(context).map_err(|_| KeyAgentLpacError::Attribute)?;
        unique_context.close_checked()
    }

    #[test]
    fn created_thread_preserves_self_pseudo_access_and_denies_fresh_owner_reopens()
    -> Result<(), KeyAgentLpacError> {
        let creation_security = PreparedKeyAgentCreationSecurity::prepare()?;
        exercise_creation_security_thread_probe(
            Some(&creation_security.primary_thread_attributes),
            &creation_security.expected_owner_sid,
            &creation_security.expected_primary_group_sid,
            verify_created_object_security,
            |_| Ok(()),
            true,
        )
    }

    #[test]
    #[ignore = "runs only as the post-loader TokenDefaultDacl LPAC child"]
    fn post_loader_worker_feasibility_default_dacl_child() -> Result<(), KeyAgentLpacError> {
        let creation_security = PreparedKeyAgentCreationSecurity::prepare()?;
        let handshake = ChildHandshake::from_environment()?;
        handshake.send_status(&[TEST_STATUS_LOADER_READY])?;
        handshake.require_command(TEST_COMMAND_POLICY_INSTALLED)?;
        super::verify_current_key_agent_default_dacl_after_gate()?;

        exercise_creation_security_thread_probe(
            None,
            &creation_security.expected_owner_sid,
            &creation_security.expected_primary_group_sid,
            verify_default_created_thread_security,
            |thread_id| {
                let mut thread_ready = [0_u8; 5];
                thread_ready[0] = TEST_STATUS_THREAD_READY;
                thread_ready[1..].copy_from_slice(&thread_id.to_le_bytes());
                handshake.send_status(&thread_ready)?;
                handshake.require_command(TEST_COMMAND_MATRIX_COMPLETE)
            },
            false,
        )?;
        handshake.close_checked()
    }

    #[test]
    #[ignore = "runs only as the exact LPAC user-mode smoke child"]
    fn lpac_user_mode_smoke_child() -> Result<(), KeyAgentLpacError> {
        super::verify_current_key_agent_lpac_before_gate()
    }

    #[test]
    fn pre_resume_token_default_dacl_matrix_proves_loader_and_same_user_boundary()
    -> Result<(), KeyAgentLpacError> {
        let fixture = KeyAgentLpacKernelTestFixture::create()?;
        let creation_security = PreparedKeyAgentCreationSecurity::prepare()?;
        let mut outcomes = Vec::with_capacity(PreResumeDefaultDaclCase::CASES.len());

        for case in PreResumeDefaultDaclCase::CASES {
            let prepared = PreparedKeyAgentLpac::prepare()?;
            let mut command_line =
                exact_ignored_child_command_line(fixture.path(), LPAC_USER_MODE_SMOKE_CHILD_TEST)?;
            let mut process = create_suspended_key_agent_lpac_exact_child(
                &prepared,
                &fixture,
                &creation_security,
                &mut command_line,
            )?;
            creation_security.verify_created_objects(
                process.process_handle(),
                process.primary_thread_handle(),
            )?;
            let pending = prepared.prepare_suspended_process_for_gate(process.process_handle())?;
            let original = capture_token_default_dacl(pending.adjust_token.0)?;
            let user_sid = test_token_user_sid(pending.adjust_token.0)?;
            let package_sid = super::copied_sid_bytes(pending.profile_sid.as_psid())?;
            let mut candidate = case.build(&original, &user_sid, &package_sid)?;

            if let Some(candidate) = candidate.as_mut() {
                if case.is_explicit_attenuation_candidate()
                    && acl_allows_complete_mask_for_sid(
                        candidate.bytes(),
                        &user_sid,
                        TEST_GENERIC_ALL,
                    ) != case.explicitly_grants_user_generic_all()
                {
                    return Err(KeyAgentLpacError::Token);
                }
                install_test_token_default_dacl(pending.adjust_token.0, candidate)?;
            }

            // SetTokenInformation copies the ACL synchronously. Close every
            // retained supervisor token handle before any loader instruction.
            drop(candidate);
            drop(pending);
            process.resume_once()?;
            outcomes.push(PreResumeDefaultDaclOutcome {
                case,
                exit_code: process.wait_for_exit_code_and_close()?,
            });
        }

        let expected: Vec<_> = PreResumeDefaultDaclCase::CASES
            .into_iter()
            .map(|case| PreResumeDefaultDaclOutcome {
                case,
                exit_code: case.expected_exit_code(),
            })
            .collect();
        assert_eq!(outcomes, expected);

        // No explicit deny-first candidate reaches user mode. Adding an
        // ordinary-user GENERIC_ALL allow is still structurally unsafe because
        // a normal same-user process is not subject to the LPAC package-side
        // restricted-token check, and it does not overcome the earlier OWNER
        // RIGHTS deny during loader initialization. Those cases are therefore
        // neither secure nor loader-compatible.
        for outcome in &outcomes {
            if outcome.case.is_explicit_attenuation_candidate() {
                assert_eq!(outcome.exit_code, STATUS_DLL_INIT_FAILED);
            }
        }
        assert!(!outcomes.iter().any(|outcome| {
            outcome.case.is_explicit_attenuation_candidate() && outcome.exit_code == 0
        }));
        Ok(())
    }

    #[test]
    fn pre_resume_owner_rights_deny_mask_axis_proves_each_standard_right_breaks_loader()
    -> Result<(), KeyAgentLpacError> {
        let fixture = KeyAgentLpacKernelTestFixture::create()?;
        let creation_security = PreparedKeyAgentCreationSecurity::prepare()?;
        let mut outcomes = Vec::with_capacity(OwnerRightsDenyMaskCase::CASES.len());

        for case in OwnerRightsDenyMaskCase::CASES {
            let prepared = PreparedKeyAgentLpac::prepare()?;
            let mut command_line =
                exact_ignored_child_command_line(fixture.path(), LPAC_USER_MODE_SMOKE_CHILD_TEST)?;
            let mut process = create_suspended_key_agent_lpac_exact_child(
                &prepared,
                &fixture,
                &creation_security,
                &mut command_line,
            )?;
            creation_security.verify_created_objects(
                process.process_handle(),
                process.primary_thread_handle(),
            )?;
            let pending = prepared.prepare_suspended_process_for_gate(process.process_handle())?;
            let user_sid = test_token_user_sid(pending.adjust_token.0)?;
            let package_sid = super::copied_sid_bytes(pending.profile_sid.as_psid())?;
            let mut candidate = case.build(&user_sid, &package_sid)?;
            if !acl_allows_complete_mask_for_sid(candidate.bytes(), &user_sid, TEST_GENERIC_ALL)
                || !acl_allows_complete_mask_for_sid(
                    candidate.bytes(),
                    &package_sid,
                    TEST_GENERIC_ALL,
                )
            {
                return Err(KeyAgentLpacError::Token);
            }
            install_test_token_default_dacl(pending.adjust_token.0, &mut candidate)?;

            drop(candidate);
            drop(pending);
            process.resume_once()?;
            outcomes.push(OwnerRightsDenyMaskOutcome {
                case,
                exit_code: process.wait_for_exit_code_and_close()?,
            });
        }

        let expected: Vec<_> = OwnerRightsDenyMaskCase::CASES
            .into_iter()
            .map(|case| OwnerRightsDenyMaskOutcome {
                case,
                exit_code: STATUS_DLL_INIT_FAILED,
            })
            .collect();
        assert_eq!(outcomes, expected);
        Ok(())
    }

    #[test]
    fn lpac_package_sid_is_absent_from_groups_and_not_token_owner_eligible()
    -> Result<(), KeyAgentLpacError> {
        let prepared = PreparedKeyAgentLpac::prepare()?;
        let fixture = KeyAgentLpacKernelTestFixture::create()?;
        let mut process = create_suspended_key_agent_lpac(&prepared, &fixture)?;
        let pending = prepared.prepare_suspended_process_for_gate(process.process_handle())?;
        let package_sid = super::copied_sid_bytes(pending.profile_sid.as_psid())?;
        let group_attributes =
            token_group_attributes_for_sid(pending.adjust_token.0, &package_sid)?;
        assert_eq!(group_attributes, None);
        assert_eq!(
            group_attributes.unwrap_or(0)
                & u32::try_from(SE_GROUP_OWNER).map_err(|_| KeyAgentLpacError::Token)?,
            0
        );
        assert_ne!(token_owner_sid(pending.adjust_token.0)?, package_sid);

        let switch = package_sid_token_owner_switch_result(
            pending.adjust_token.0,
            pending.profile_sid.as_psid(),
        )?;
        assert!(matches!(
            switch,
            Err(error) if error.code() == ERROR_INVALID_OWNER.to_hresult()
        ));

        // The failed attempt must be side-effect free; the ordinary owner and
        // suspended child remain disposable within this test-only process.
        assert_ne!(token_owner_sid(pending.adjust_token.0)?, package_sid);
        drop(pending);
        process.terminate_and_wait()
    }

    #[test]
    fn original_lpac_default_dacl_has_path_free_structural_classification()
    -> Result<(), KeyAgentLpacError> {
        let prepared = PreparedKeyAgentLpac::prepare()?;
        let fixture = KeyAgentLpacKernelTestFixture::create()?;
        let mut process = create_suspended_key_agent_lpac(&prepared, &fixture)?;
        let pending = prepared.prepare_suspended_process_for_gate(process.process_handle())?;
        let original = capture_token_default_dacl(pending.adjust_token.0)?;
        let user_sid = test_token_user_sid(pending.adjust_token.0)?;
        let package_sid = super::copied_sid_bytes(pending.profile_sid.as_psid())?;
        let report =
            sanitized_default_dacl_classification(original.bytes(), &user_sid, &package_sid)?;
        assert_eq!(
            report,
            vec![
                SanitizedDefaultDaclAce {
                    kind: SanitizedAceKind::Allow,
                    flags: 0,
                    mask: TEST_GENERIC_ALL,
                    principal: SanitizedAcePrincipal::ChildUser,
                },
                SanitizedDefaultDaclAce {
                    kind: SanitizedAceKind::Allow,
                    flags: 0,
                    mask: TEST_GENERIC_ALL,
                    principal: SanitizedAcePrincipal::LocalSystem,
                },
                SanitizedDefaultDaclAce {
                    kind: SanitizedAceKind::Allow,
                    flags: 0,
                    mask: TEST_GENERIC_READ | TEST_GENERIC_EXECUTE,
                    principal: SanitizedAcePrincipal::LogonSession,
                },
                SanitizedDefaultDaclAce {
                    kind: SanitizedAceKind::Allow,
                    flags: 0,
                    mask: TEST_GENERIC_ALL,
                    principal: SanitizedAcePrincipal::ExactPackage,
                },
            ]
        );
        assert!(!format!("{report:?}").contains("S-1-"));

        drop(pending);
        process.terminate_and_wait()
    }

    #[test]
    fn lpac_fixture_child_reaches_user_mode_before_token_hardening() -> Result<(), KeyAgentLpacError>
    {
        let prepared = PreparedKeyAgentLpac::prepare()?;
        let fixture = KeyAgentLpacKernelTestFixture::create()?;
        let creation_security = PreparedKeyAgentCreationSecurity::prepare()?;
        let mut command_line =
            exact_ignored_child_command_line(fixture.path(), LPAC_USER_MODE_SMOKE_CHILD_TEST)?;
        let mut process = create_suspended_key_agent_lpac_exact_child(
            &prepared,
            &fixture,
            &creation_security,
            &mut command_line,
        )?;
        creation_security
            .verify_created_objects(process.process_handle(), process.primary_thread_handle())?;
        process.resume_and_wait_for_success()
    }

    #[test]
    fn post_loader_worker_feasibility_default_dacl_hardens_later_null_security_thread()
    -> Result<(), KeyAgentLpacError> {
        let prepared = PreparedKeyAgentLpac::prepare()?;
        let fixture = KeyAgentLpacKernelTestFixture::create()?;
        let creation_security = PreparedKeyAgentCreationSecurity::prepare()?;
        let mut command_line =
            exact_ignored_child_command_line(fixture.path(), POST_LOADER_DEFAULT_DACL_CHILD_TEST)?;
        let mut pipes = TestHandshakePipes::create()?;
        let mut process = create_suspended_key_agent_lpac_handshake_child(
            &prepared,
            &fixture,
            &creation_security,
            &mut command_line,
            &pipes,
        )?;
        pipes.seal_parent_after_launch()?;
        creation_security
            .verify_created_objects(process.process_handle(), process.primary_thread_handle())?;

        // This prepares only the token-object DACL before loader execution and
        // retains both preauthenticated gate-phase handles in the Pending value.
        let pending = prepared.prepare_suspended_process_for_gate(process.process_handle())?;
        process.resume_once()?;
        if pipes.receive_status::<1>(process.raw_process())? != [TEST_STATUS_LOADER_READY] {
            return Err(KeyAgentLpacError::Attribute);
        }

        // The copied libtest invokes this handshake on a worker rather than the
        // retained primary thread. It proves the delayed-policy mechanics only;
        // production authenticates its separate exact-primary debugger gate.
        let verified = pending.finalize_after_gate(process.process_handle())?;
        verified.revalidate_current_process_token(process.process_handle())?;
        pipes.send_command(TEST_COMMAND_POLICY_INSTALLED)?;

        let thread_ready = pipes.receive_status::<5>(process.raw_process())?;
        if thread_ready[0] != TEST_STATUS_THREAD_READY {
            return Err(KeyAgentLpacError::Attribute);
        }
        let thread_id = u32::from_le_bytes(
            thread_ready[1..]
                .try_into()
                .map_err(|_| KeyAgentLpacError::Attribute)?,
        );
        require_creation_dacl_probe_privileges_disabled()?;
        require_creation_dacl_thread_reopen_denials(thread_id)?;
        require_creation_dacl_probe_privileges_disabled()?;
        pipes.send_command(TEST_COMMAND_MATRIX_COMPLETE)?;

        process.wait_for_success_and_close()?;
        drop(verified);
        pipes.close_checked()
    }

    #[test]
    fn default_created_thread_parser_allows_os_dacl_control_provenance_bits() {
        let owner_sid = synthetic_sid(100);
        let group_sid = synthetic_sid(200);
        let base = exact_creation_security_descriptor(&owner_sid, &group_sid);
        let required = SE_SELF_RELATIVE.0 | SE_DACL_PRESENT.0;
        for optional in [
            0,
            SE_DACL_PROTECTED.0,
            SE_DACL_DEFAULTED.0,
            SE_DACL_PROTECTED.0 | SE_DACL_DEFAULTED.0,
        ] {
            let mut descriptor = base.clone();
            replace_u16(&mut descriptor, 2, required | optional);
            assert_eq!(
                inspect_default_created_thread_security_descriptor(
                    &descriptor,
                    &owner_sid,
                    &group_sid,
                ),
                Ok(())
            );
        }
    }

    #[test]
    fn creation_handle_flags_must_be_exactly_zero() {
        assert_eq!(validate_creation_handle_flags(HANDLE_FLAGS(0)), Ok(()));
        for flags in [HANDLE_FLAGS(1), HANDLE_FLAGS(2), HANDLE_FLAGS(u32::MAX)] {
            assert_eq!(
                validate_creation_handle_flags(flags),
                Err(KeyAgentLpacError::Attribute)
            );
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
    fn verified_token_retains_exact_object_and_revalidates_current_process_token()
    -> Result<(), KeyAgentLpacError> {
        let prepared = PreparedKeyAgentLpac::prepare()?;
        let fixture = KeyAgentLpacKernelTestFixture::create()?;
        let mut process = create_suspended_key_agent_lpac(&prepared, &fixture)?;
        let pending = prepared.prepare_suspended_process_for_gate(process.process_handle())?;
        assert_eq!(
            format!("{pending:?}"),
            "PendingKeyAgentLpac([OPAQUE RETAINED TOKEN AUTHORITIES])"
        );
        let mut exact_owner = OwnedExactTokenDefaultDacl::new()?;
        let exact_default = super::ExactTokenDefaultDaclEvidence::from_owner(&exact_owner)?;
        assert_eq!(
            exact_default.verify_readback(pending.adjust_token.0),
            Err(KeyAgentLpacError::Token)
        );
        assert!(matches!(
            set_token_default_dacl_for_test(pending.token.0, &mut exact_owner),
            Err(error) if error.code() == ERROR_ACCESS_DENIED.to_hresult()
        ));
        let verified = pending.finalize_after_gate(process.process_handle())?;

        assert_eq!(format!("{verified:?}"), "VerifiedKeyAgentLpac([VERIFIED])");
        verified.revalidate_current_process_token(process.process_handle())?;

        let fresh_current = open_process_token_with_access(process.process_handle(), TOKEN_QUERY)?;
        require_same_token_object(verified.token.0, fresh_current.0)?;
        let fresh_identity = exact_token_statistics_baseline(fresh_current.0)?;
        require_same_token_identity(&verified.baseline, &fresh_identity)?;

        // SAFETY: the current-process pseudo handle is valid for this call and
        // the borrow does not escape this test scope.
        let supervisor_process = unsafe { BorrowedHandle::borrow_raw(GetCurrentProcess().0) };
        assert_eq!(
            verified.revalidate_current_process_token(supervisor_process),
            Err(KeyAgentLpacError::Token)
        );

        process.terminate_and_wait()?;
        Ok(())
    }

    #[test]
    fn verified_token_default_dacl_is_exact_and_final_handle_cannot_adjust()
    -> Result<(), KeyAgentLpacError> {
        let prepared = PreparedKeyAgentLpac::prepare()?;
        let fixture = KeyAgentLpacKernelTestFixture::create()?;
        let mut process = create_suspended_key_agent_lpac(&prepared, &fixture)?;
        let pending = prepared.prepare_suspended_process_for_gate(process.process_handle())?;
        let verified = pending.finalize_after_gate(process.process_handle())?;

        verified.default_dacl.verify_readback(verified.token.0)?;
        let mut owner = OwnedExactTokenDefaultDacl::new()?;
        assert!(matches!(
            set_token_default_dacl_for_test(verified.token.0, &mut owner),
            Err(error) if error.code() == ERROR_ACCESS_DENIED.to_hresult()
        ));
        verified.revalidate_current_process_token(process.process_handle())?;

        process.terminate_and_wait()?;
        Ok(())
    }

    #[test]
    fn current_token_revalidation_detects_live_default_dacl_mutation()
    -> Result<(), KeyAgentLpacError> {
        let prepared = PreparedKeyAgentLpac::prepare()?;
        let fixture = KeyAgentLpacKernelTestFixture::create()?;
        let mut process = create_suspended_key_agent_lpac(&prepared, &fixture)?;
        let pending = prepared.prepare_suspended_process_for_gate(process.process_handle())?;
        let verified = pending.finalize_after_gate(process.process_handle())?;
        let adjust = open_process_token_with_access(
            process.process_handle(),
            TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
        )?;
        require_same_token_object(verified.token.0, adjust.0)?;

        let mut changed = OwnedExactTokenDefaultDacl::new()?;
        changed.bytes_mut()[12..16]
            .copy_from_slice(&(CREATION_SECURITY_DENIED_ACCESS ^ 1).to_le_bytes());
        set_token_default_dacl_for_test(adjust.0, &mut changed)
            .map_err(|_| KeyAgentLpacError::Token)?;
        assert_eq!(
            verified.default_dacl.verify_readback(adjust.0),
            Err(KeyAgentLpacError::Token)
        );
        assert_eq!(
            verified.revalidate_current_process_token(process.process_handle()),
            Err(KeyAgentLpacError::Token)
        );

        adjust.close_checked()?;
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

    fn synthetic_token_identity(
        token_low: u32,
        token_high: i32,
        modified_low: u32,
        modified_high: i32,
    ) -> TokenIdentityBaseline {
        TokenIdentityBaseline {
            token_id: TokenLuidBaseline {
                low_part: token_low,
                high_part: token_high,
            },
            modified_id: TokenLuidBaseline {
                low_part: modified_low,
                high_part: modified_high,
            },
        }
    }

    #[test]
    fn token_identity_comparison_rejects_each_luid_part_mutation() {
        let expected = synthetic_token_identity(1, 2, 3, 4);
        assert_eq!(
            require_same_token_identity(&expected, &synthetic_token_identity(1, 2, 3, 4)),
            Ok(())
        );

        for observed in [
            synthetic_token_identity(9, 2, 3, 4),
            synthetic_token_identity(1, 9, 3, 4),
            synthetic_token_identity(1, 2, 9, 4),
            synthetic_token_identity(1, 2, 3, 9),
        ] {
            assert_eq!(
                require_same_token_identity(&expected, &observed),
                Err(KeyAgentLpacError::Token)
            );
        }
        assert_eq!(format!("{expected:?}"), "TokenIdentityBaseline([REDACTED])");
    }

    #[test]
    fn token_id_continuity_allows_only_modified_id_to_advance_between_phases() {
        let expected = synthetic_token_identity(1, 2, 3, 4);
        assert_eq!(
            require_same_token_id(&expected, &synthetic_token_identity(1, 2, 9, 10)),
            Ok(())
        );
        for observed in [
            synthetic_token_identity(9, 2, 3, 4),
            synthetic_token_identity(1, 9, 3, 4),
        ] {
            assert_eq!(
                require_same_token_id(&expected, &observed),
                Err(KeyAgentLpacError::Token)
            );
        }
    }

    #[test]
    fn token_statistics_identity_requires_exact_size_and_primary_type() {
        let statistics = TOKEN_STATISTICS {
            TokenId: LUID {
                LowPart: 1,
                HighPart: 2,
            },
            TokenType: TokenPrimary,
            ModifiedId: LUID {
                LowPart: 3,
                HighPart: 4,
            },
            ..TOKEN_STATISTICS::default()
        };
        assert!(token_identity_from_statistics(&statistics, size_of::<TOKEN_STATISTICS>()).is_ok());
        assert!(matches!(
            token_identity_from_statistics(&statistics, size_of::<TOKEN_STATISTICS>() - 1),
            Err(KeyAgentLpacError::Token)
        ));
        assert!(matches!(
            token_identity_from_statistics(&statistics, size_of::<TOKEN_STATISTICS>() + 1),
            Err(KeyAgentLpacError::Token)
        ));

        let impersonation = TOKEN_STATISTICS {
            TokenType: TokenImpersonation,
            ..statistics
        };
        assert!(matches!(
            token_identity_from_statistics(&impersonation, size_of::<TOKEN_STATISTICS>()),
            Err(KeyAgentLpacError::Token)
        ));
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
    fn key_agent_token_dacl_masks_are_exact_and_role_separated() {
        assert_eq!(SUPERVISOR_TOKEN_ACCESS, TOKEN_ALL_ACCESS.0);
        assert_eq!(
            KEY_AGENT_TOKEN_SELF_ACCESS,
            TOKEN_QUERY.0 | TOKEN_DUPLICATE.0
        );
        assert_eq!(APPROVAL_PARENT_TOKEN_ACCESS, TOKEN_QUERY.0);
        assert_ne!(KEY_AGENT_TOKEN_SELF_ACCESS, APPROVAL_PARENT_TOKEN_ACCESS);
    }

    fn synthetic_sid(sub_authority: u32) -> Vec<u8> {
        let mut sid = vec![1, 1, 0, 0, 0, 0, 0, 5];
        sid.extend_from_slice(&sub_authority.to_le_bytes());
        sid
    }

    fn exact_creation_security_descriptor(owner_sid: &[u8], group_sid: &[u8]) -> Vec<u8> {
        let mut descriptor = Vec::new();
        descriptor.push(1);
        descriptor.push(0);
        let control = SE_SELF_RELATIVE.0 | SE_DACL_PRESENT.0 | SE_DACL_PROTECTED.0;
        descriptor.extend_from_slice(&control.to_le_bytes());
        let owner_offset = 20_u32;
        let group_offset = owner_offset + u32::try_from(owner_sid.len()).unwrap_or(u32::MAX);
        let dacl_offset = group_offset + u32::try_from(group_sid.len()).unwrap_or(u32::MAX);
        descriptor.extend_from_slice(&owner_offset.to_le_bytes());
        descriptor.extend_from_slice(&group_offset.to_le_bytes());
        descriptor.extend_from_slice(&0_u32.to_le_bytes());
        descriptor.extend_from_slice(&dacl_offset.to_le_bytes());
        descriptor.extend_from_slice(owner_sid);
        descriptor.extend_from_slice(group_sid);
        descriptor.push(u8::try_from(ACL_REVISION.0).unwrap_or(u8::MAX));
        descriptor.push(0);
        let acl_bytes = u16::try_from(8 + 8 + OWNER_RIGHTS_SID_BYTES.len()).unwrap_or(u16::MAX);
        descriptor.extend_from_slice(&acl_bytes.to_le_bytes());
        descriptor.extend_from_slice(&1_u16.to_le_bytes());
        descriptor.extend_from_slice(&0_u16.to_le_bytes());
        descriptor.push(1);
        descriptor.push(0);
        let deny_ace_bytes = u16::try_from(8 + OWNER_RIGHTS_SID_BYTES.len()).unwrap_or(u16::MAX);
        descriptor.extend_from_slice(&deny_ace_bytes.to_le_bytes());
        descriptor.extend_from_slice(&CREATION_SECURITY_DENIED_ACCESS.to_le_bytes());
        descriptor.extend_from_slice(&OWNER_RIGHTS_SID_BYTES);
        descriptor
    }

    fn creation_security_parser_result(
        descriptor: &[u8],
        owner_sid: &[u8],
        group_sid: &[u8],
    ) -> Result<(), KeyAgentLpacError> {
        inspect_exact_creation_security_descriptor(descriptor, owner_sid, group_sid)
    }

    fn replace_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn creation_security_parser_accepts_only_owner_group_and_one_owner_rights_deny() {
        let owner_sid = synthetic_sid(100);
        let group_sid = synthetic_sid(200);
        let descriptor = exact_creation_security_descriptor(&owner_sid, &group_sid);
        assert_eq!(
            CREATION_SECURITY_DENIED_ACCESS,
            READ_CONTROL.0 | WRITE_DAC.0 | WRITE_OWNER.0
        );
        assert_eq!(OWNER_RIGHTS_SID_BYTES, [1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0]);
        assert_eq!(
            creation_security_parser_result(&descriptor, &owner_sid, &group_sid),
            Ok(())
        );
    }

    #[test]
    fn creation_security_parser_rejects_each_single_shape_mutation() {
        let owner_sid = synthetic_sid(100);
        let group_sid = synthetic_sid(200);
        let valid = exact_creation_security_descriptor(&owner_sid, &group_sid);
        let mut negative_cases = Vec::new();

        negative_cases.push(("truncated descriptor", valid[..19].to_vec()));
        for (name, index, value) in [
            ("descriptor revision", 0_usize, 2_u8),
            ("descriptor reserved byte", 1, 1),
            ("owner SID revision", 20, 2),
            ("owner SID declared length", 21, 2),
            ("ACL reserved byte", 45, 1),
            ("ACE type", 52, 0),
            ("ACE flags", 53, 1),
        ] {
            let mut changed = valid.clone();
            changed[index] = value;
            negative_cases.push((name, changed));
        }
        for (name, removed) in [
            ("self-relative control", SE_SELF_RELATIVE.0),
            ("DACL-present control", SE_DACL_PRESENT.0),
            ("DACL-protected control", SE_DACL_PROTECTED.0),
        ] {
            let mut changed = valid.clone();
            let control = u16::from_le_bytes([changed[2], changed[3]]) & !removed;
            replace_u16(&mut changed, 2, control);
            negative_cases.push((name, changed));
        }
        let mut changed = valid.clone();
        let control = u16::from_le_bytes([changed[2], changed[3]]) | SE_OWNER_DEFAULTED.0;
        replace_u16(&mut changed, 2, control);
        negative_cases.push(("extra control bit", changed));
        for (name, offset) in [
            ("missing owner", 4_usize),
            ("missing primary group", 8_usize),
            ("missing DACL", 16_usize),
        ] {
            let mut changed = valid.clone();
            replace_u32(&mut changed, offset, 0);
            negative_cases.push((name, changed));
        }
        let mut changed = valid.clone();
        replace_u32(&mut changed, 12, 20);
        negative_cases.push(("unexpected SACL", changed));
        let mut changed = valid.clone();
        replace_u32(&mut changed, 4, 21);
        negative_cases.push(("misaligned owner", changed));
        let mut changed = valid.clone();
        changed[31] ^= 1;
        negative_cases.push(("owner SID bytes", changed));
        let mut changed = valid.clone();
        changed[43] ^= 1;
        negative_cases.push(("primary-group SID bytes", changed));
        let mut changed = valid.clone();
        changed[44] = u8::try_from(ACL_REVISION.0 + 2).unwrap_or(u8::MAX);
        negative_cases.push(("ACL revision", changed));
        let mut changed = valid.clone();
        replace_u16(&mut changed, 46, 27);
        negative_cases.push(("ACL size", changed));
        let mut changed = valid.clone();
        replace_u16(&mut changed, 48, 2);
        negative_cases.push(("ACE count", changed));
        let mut changed = valid.clone();
        replace_u16(&mut changed, 50, 1);
        negative_cases.push(("ACL trailing reserved field", changed));
        let mut changed = valid.clone();
        replace_u16(&mut changed, 54, 19);
        negative_cases.push(("ACE size", changed));
        let mut changed = valid.clone();
        replace_u32(&mut changed, 56, CREATION_SECURITY_DENIED_ACCESS ^ 1);
        negative_cases.push(("ACE mask", changed));
        let mut changed = valid.clone();
        changed[71] ^= 1;
        negative_cases.push(("OWNER RIGHTS SID bytes", changed));
        let mut changed = valid.clone();
        changed.push(0);
        negative_cases.push(("descriptor trailing byte", changed));
        let mut changed = valid.clone();
        changed.splice(44..44, [0, 0, 0, 0]);
        replace_u32(&mut changed, 16, 48);
        negative_cases.push(("component gap", changed));
        let mut changed = valid.clone();
        replace_u32(&mut changed, 16, 40);
        negative_cases.push(("component overlap", changed));
        let mut changed = valid.clone();
        changed.extend_from_slice(&[0, 0, 0, 0]);
        replace_u16(&mut changed, 46, 32);
        negative_cases.push(("ACL slack", changed));

        for (name, descriptor) in negative_cases {
            assert_eq!(
                creation_security_parser_result(&descriptor, &owner_sid, &group_sid),
                Err(KeyAgentLpacError::Attribute),
                "mutation unexpectedly accepted: {name}"
            );
        }
    }

    fn token_default_dacl_information(
        acl: &[u8],
        pointer_gap: usize,
        trailing_bytes: usize,
    ) -> TokenInformation {
        let prefix_bytes = size_of::<TOKEN_DEFAULT_DACL>();
        let returned_bytes = prefix_bytes + pointer_gap + acl.len() + trailing_bytes;
        let word_bytes = size_of::<usize>();
        let word_count = returned_bytes.div_ceil(word_bytes);
        let mut words = vec![0_usize; word_count];
        let base = words.as_mut_ptr();
        let byte_base = base.cast::<u8>();
        let acl_offset = prefix_bytes + pointer_gap;
        // SAFETY: the rounded allocation contains every requested returned byte;
        // both copies are disjoint and the pointer-bearing prefix is aligned by
        // Vec<usize>. The heap allocation remains stable in the returned owner.
        unsafe {
            ptr::copy_nonoverlapping(acl.as_ptr(), byte_base.add(acl_offset), acl.len());
            ptr::write(
                base.cast::<TOKEN_DEFAULT_DACL>(),
                TOKEN_DEFAULT_DACL {
                    DefaultDacl: base.byte_add(acl_offset).cast::<ACL>(),
                },
            );
        }
        TokenInformation {
            words,
            returned_bytes,
        }
    }

    fn set_token_default_dacl_pointer(information: &mut TokenInformation, address: usize) {
        // SAFETY: every test allocation uses aligned, nonempty Vec<usize>
        // storage large enough for the fixed TOKEN_DEFAULT_DACL prefix.
        unsafe {
            ptr::write(
                information.words.as_mut_ptr().cast::<TOKEN_DEFAULT_DACL>(),
                TOKEN_DEFAULT_DACL {
                    DefaultDacl: address as *mut ACL,
                },
            );
        }
    }

    fn set_token_default_dacl_for_test(
        token: HANDLE,
        owner: &mut OwnedExactTokenDefaultDacl,
    ) -> windows::core::Result<()> {
        set_raw_token_default_dacl_for_test(token, owner.as_acl_mut_ptr())
    }

    fn set_raw_token_default_dacl_for_test(
        token: HANDLE,
        default_dacl: *mut ACL,
    ) -> windows::core::Result<()> {
        let information = TOKEN_DEFAULT_DACL {
            DefaultDacl: default_dacl,
        };
        // SAFETY: each caller retains the live ACL owner and supplies one live
        // token handle for the complete synchronous test-only mutation attempt.
        unsafe {
            SetTokenInformation(
                token,
                TokenDefaultDacl,
                ptr::from_ref(&information).cast::<c_void>(),
                u32::try_from(size_of::<TOKEN_DEFAULT_DACL>()).unwrap_or(u32::MAX),
            )
        }
    }

    #[test]
    fn token_default_dacl_owner_is_exact_aligned_and_policy_shaped() -> Result<(), KeyAgentLpacError>
    {
        let mut owner = OwnedExactTokenDefaultDacl::new()?;
        assert_eq!(size_of::<OwnedExactTokenDefaultDacl>(), 28);
        assert_eq!(EXACT_TOKEN_DEFAULT_DACL_BYTES, 28);
        assert_eq!((owner.as_acl_mut_ptr() as usize) % align_of::<ACL>(), 0);
        assert_eq!(owner.bytes().len(), EXACT_TOKEN_DEFAULT_DACL_BYTES);
        inspect_exact_token_default_dacl_bytes(owner.bytes())
    }

    #[test]
    fn token_default_dacl_readback_parser_accepts_bounded_aligned_os_padding()
    -> Result<(), KeyAgentLpacError> {
        let owner = OwnedExactTokenDefaultDacl::new()?;
        let expected = *owner.bytes();
        let exact = token_default_dacl_information(&expected, 0, 0);
        inspect_exact_token_default_dacl_information(&exact, &expected)?;

        let aligned_gap = align_of::<ACL>();
        let padded = token_default_dacl_information(&expected, aligned_gap, 3);
        inspect_exact_token_default_dacl_information(&padded, &expected)
    }

    #[test]
    fn token_default_dacl_readback_parser_rejects_pointer_and_range_mutations()
    -> Result<(), KeyAgentLpacError> {
        let owner = OwnedExactTokenDefaultDacl::new()?;
        let expected = *owner.bytes();

        let mut null = token_default_dacl_information(&expected, 0, 0);
        set_token_default_dacl_pointer(&mut null, 0);
        assert_eq!(
            inspect_exact_token_default_dacl_information(&null, &expected),
            Err(KeyAgentLpacError::Token)
        );

        let mut prefix_overlap = token_default_dacl_information(&expected, 0, 0);
        let prefix_start = prefix_overlap.words.as_ptr() as usize;
        set_token_default_dacl_pointer(&mut prefix_overlap, prefix_start);
        assert_eq!(
            inspect_exact_token_default_dacl_information(&prefix_overlap, &expected),
            Err(KeyAgentLpacError::Token)
        );

        let mut misaligned = token_default_dacl_information(&expected, 0, 0);
        let expected_start = (misaligned.words.as_ptr() as usize) + size_of::<TOKEN_DEFAULT_DACL>();
        set_token_default_dacl_pointer(&mut misaligned, expected_start + 1);
        assert_eq!(
            inspect_exact_token_default_dacl_information(&misaligned, &expected),
            Err(KeyAgentLpacError::Token)
        );

        let mut one_past = token_default_dacl_information(&expected, 0, 0);
        let one_past_address = (one_past.words.as_ptr() as usize) + one_past.returned_bytes;
        set_token_default_dacl_pointer(&mut one_past, one_past_address);
        assert_eq!(
            inspect_exact_token_default_dacl_information(&one_past, &expected),
            Err(KeyAgentLpacError::Token)
        );

        let mut header_crossing = token_default_dacl_information(&expected, 0, 0);
        let buffer_end = (header_crossing.words.as_ptr() as usize) + header_crossing.returned_bytes;
        let header_crossing_address = buffer_end - 6;
        assert_eq!(header_crossing_address % align_of::<ACL>(), 0);
        assert!(header_crossing_address + 8 > buffer_end);
        set_token_default_dacl_pointer(&mut header_crossing, header_crossing_address);
        assert_eq!(
            inspect_exact_token_default_dacl_information(&header_crossing, &expected),
            Err(KeyAgentLpacError::Token)
        );

        let mut acl_crossing = token_default_dacl_information(&expected, align_of::<ACL>(), 0);
        acl_crossing.returned_bytes -= 1;
        let buffer_start = acl_crossing.words.as_ptr() as usize;
        let acl_start = buffer_start + size_of::<TOKEN_DEFAULT_DACL>() + align_of::<ACL>();
        let shortened_end = buffer_start + acl_crossing.returned_bytes;
        assert_eq!(acl_start % align_of::<ACL>(), 0);
        assert!(acl_start + 8 <= shortened_end);
        assert_eq!(
            acl_start + EXACT_TOKEN_DEFAULT_DACL_BYTES,
            shortened_end + 1
        );
        assert_eq!(
            inspect_exact_token_default_dacl_information(&acl_crossing, &expected),
            Err(KeyAgentLpacError::Token)
        );

        let mut overflowing = token_default_dacl_information(&expected, 0, 0);
        let aligned_max = usize::MAX - (usize::MAX % align_of::<ACL>());
        set_token_default_dacl_pointer(&mut overflowing, aligned_max);
        assert_eq!(
            inspect_exact_token_default_dacl_information(&overflowing, &expected),
            Err(KeyAgentLpacError::Token)
        );

        let mut short_prefix = token_default_dacl_information(&expected, 0, 0);
        short_prefix.returned_bytes = size_of::<TOKEN_DEFAULT_DACL>() - 1;
        assert_eq!(
            inspect_exact_token_default_dacl_information(&short_prefix, &expected),
            Err(KeyAgentLpacError::Token)
        );

        let mut beyond_allocation = token_default_dacl_information(&expected, 0, 0);
        beyond_allocation.returned_bytes = beyond_allocation.words.len() * size_of::<usize>() + 1;
        assert_eq!(
            inspect_exact_token_default_dacl_information(&beyond_allocation, &expected),
            Err(KeyAgentLpacError::Token)
        );
        Ok(())
    }

    #[test]
    fn token_default_dacl_parser_rejects_each_single_acl_shape_mutation()
    -> Result<(), KeyAgentLpacError> {
        let owner = OwnedExactTokenDefaultDacl::new()?;
        let valid = owner.bytes().to_vec();
        let mut negative_cases = vec![
            ("truncated ACL", valid[..valid.len() - 1].to_vec()),
            ("ACL trailing slack", {
                let mut changed = valid.clone();
                changed.push(0);
                changed
            }),
        ];
        for (name, index, value) in [
            ("ACL revision", 0_usize, 4_u8),
            ("ACL reserved byte", 1, 1),
            ("ACE type", 8, 0),
            ("ACE flags", 9, 1),
            ("OWNER RIGHTS SID", 27, 1),
        ] {
            let mut changed = valid.clone();
            changed[index] = value;
            negative_cases.push((name, changed));
        }
        for (name, offset, value) in [
            ("ACL size", 2_usize, 27_u16),
            ("ACE count", 4, 2),
            ("ACL second reserved field", 6, 1),
            ("ACE size", 10, 19),
        ] {
            let mut changed = valid.clone();
            replace_u16(&mut changed, offset, value);
            negative_cases.push((name, changed));
        }
        let mut changed = valid.clone();
        replace_u32(&mut changed, 12, CREATION_SECURITY_DENIED_ACCESS ^ 1);
        negative_cases.push(("ACE mask", changed));

        for (name, acl) in negative_cases {
            assert_eq!(
                inspect_exact_token_default_dacl_bytes(&acl),
                Err(KeyAgentLpacError::Token),
                "mutation unexpectedly accepted: {name}"
            );
        }
        Ok(())
    }

    fn push_allow_ace(bytes: &mut Vec<u8>, mask: u32, sid: &[u8]) {
        bytes.push(0);
        bytes.push(0);
        let ace_size = u16::try_from(8 + sid.len()).unwrap_or(u16::MAX);
        bytes.extend_from_slice(&ace_size.to_le_bytes());
        bytes.extend_from_slice(&mask.to_le_bytes());
        bytes.extend_from_slice(sid);
    }

    fn exact_token_dacl_descriptor(
        user_sid: &[u8],
        key_agent_sid: &[u8],
        approval_sid: &[u8],
    ) -> Vec<u8> {
        let mut descriptor = Vec::new();
        descriptor.push(1);
        descriptor.push(0);
        let control = SE_SELF_RELATIVE.0 | SE_DACL_PRESENT.0 | SE_DACL_PROTECTED.0;
        descriptor.extend_from_slice(&control.to_le_bytes());
        descriptor.extend_from_slice(&0_u32.to_le_bytes());
        descriptor.extend_from_slice(&0_u32.to_le_bytes());
        descriptor.extend_from_slice(&0_u32.to_le_bytes());
        descriptor.extend_from_slice(&20_u32.to_le_bytes());
        descriptor.push(u8::try_from(ACL_REVISION.0).unwrap_or(u8::MAX));
        descriptor.push(0);
        let acl_size_offset = descriptor.len();
        descriptor.extend_from_slice(&0_u16.to_le_bytes());
        descriptor.extend_from_slice(&3_u16.to_le_bytes());
        descriptor.extend_from_slice(&0_u16.to_le_bytes());
        push_allow_ace(&mut descriptor, SUPERVISOR_TOKEN_ACCESS, user_sid);
        push_allow_ace(&mut descriptor, KEY_AGENT_TOKEN_SELF_ACCESS, key_agent_sid);
        push_allow_ace(&mut descriptor, APPROVAL_PARENT_TOKEN_ACCESS, approval_sid);
        let acl_size = u16::try_from(descriptor.len() - 20).unwrap_or(u16::MAX);
        descriptor[acl_size_offset..acl_size_offset + 2].copy_from_slice(&acl_size.to_le_bytes());
        descriptor
    }

    fn replace_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn token_dacl_parser_result(
        descriptor: &[u8],
        user_sid: &[u8],
        key_agent_sid: &[u8],
        approval_sid: &[u8],
    ) -> Result<(), KeyAgentLpacError> {
        inspect_exact_token_dacl_descriptor(descriptor, user_sid, key_agent_sid, approval_sid)
    }

    fn token_dacl_header_negative_cases(valid: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
        let mut cases = Vec::new();
        cases.push(("truncated descriptor", valid[..19].to_vec()));
        let mut changed = valid.to_vec();
        changed[0] = 2;
        cases.push(("descriptor revision", changed));
        let mut changed = valid.to_vec();
        changed[1] = 1;
        cases.push(("descriptor reserved byte", changed));
        for (name, removed) in [
            ("self-relative control", SE_SELF_RELATIVE.0),
            ("DACL-present control", SE_DACL_PRESENT.0),
            ("DACL-protected control", SE_DACL_PROTECTED.0),
        ] {
            let mut changed = valid.to_vec();
            let control = u16::from_le_bytes([changed[2], changed[3]]) & !removed;
            replace_u16(&mut changed, 2, control);
            cases.push((name, changed));
        }
        for (name, added) in [
            ("DACL-defaulted control", SE_DACL_DEFAULTED.0),
            (
                "DACL-auto-inherit-request control",
                SE_DACL_AUTO_INHERIT_REQ.0,
            ),
            ("DACL-auto-inherited control", SE_DACL_AUTO_INHERITED.0),
            ("unrequested owner control", SE_OWNER_DEFAULTED.0),
        ] {
            let mut changed = valid.to_vec();
            let control = u16::from_le_bytes([changed[2], changed[3]]) | added;
            replace_u16(&mut changed, 2, control);
            cases.push((name, changed));
        }
        for (name, offset) in [
            ("owner offset", 4_usize),
            ("group offset", 8_usize),
            ("SACL offset", 12_usize),
        ] {
            let mut changed = valid.to_vec();
            changed[offset..offset + 4].copy_from_slice(&20_u32.to_le_bytes());
            cases.push((name, changed));
        }
        let mut changed = valid.to_vec();
        changed[16..20].copy_from_slice(&24_u32.to_le_bytes());
        cases.push(("DACL offset", changed));
        cases
    }

    #[test]
    fn token_dacl_readback_parser_accepts_only_the_exact_three_ace_descriptor() {
        let user_sid = synthetic_sid(100);
        let key_agent_sid = synthetic_sid(200);
        let approval_sid = synthetic_sid(300);
        let descriptor = exact_token_dacl_descriptor(&user_sid, &key_agent_sid, &approval_sid);

        assert_eq!(
            token_dacl_parser_result(&descriptor, &user_sid, &key_agent_sid, &approval_sid),
            Ok(())
        );
    }

    #[test]
    fn token_dacl_readback_parser_rejects_each_single_shape_mutation() {
        let user_sid = synthetic_sid(100);
        let key_agent_sid = synthetic_sid(200);
        let approval_sid = synthetic_sid(300);
        let valid = exact_token_dacl_descriptor(&user_sid, &key_agent_sid, &approval_sid);
        let mut negative_cases = token_dacl_header_negative_cases(&valid);
        let mut changed = valid.clone();
        changed[20] = u8::try_from(ACL_REVISION.0 + 2).unwrap_or(u8::MAX);
        negative_cases.push(("ACL revision", changed));
        let mut changed = valid.clone();
        changed[21] = 1;
        negative_cases.push(("ACL first reserved byte", changed));
        let mut changed = valid.clone();
        changed[26] = 1;
        negative_cases.push(("ACL second reserved field", changed));
        let mut changed = valid.clone();
        let acl_size = u16::from_le_bytes([changed[22], changed[23]]).saturating_sub(1);
        replace_u16(&mut changed, 22, acl_size);
        negative_cases.push(("ACL total bytes", changed));
        let mut changed = valid.clone();
        replace_u16(&mut changed, 24, 2);
        negative_cases.push(("ACE count", changed));
        let mut changed = valid.clone();
        changed[28] = 1;
        negative_cases.push(("ACE type", changed));
        let mut changed = valid.clone();
        changed[49] = 1;
        negative_cases.push(("ACE flags", changed));
        let mut changed = valid.clone();
        changed[72..76].copy_from_slice(&(APPROVAL_PARENT_TOKEN_ACCESS | 2).to_le_bytes());
        negative_cases.push(("ACE mask", changed));
        let mut changed = valid.clone();
        changed[47] ^= 1;
        negative_cases.push(("SID bytes", changed));
        let mut changed = valid.clone();
        let first_sid = changed[36..48].to_vec();
        let second_sid = changed[56..68].to_vec();
        changed[36..48].copy_from_slice(&second_sid);
        changed[56..68].copy_from_slice(&first_sid);
        negative_cases.push(("SID order", changed));
        let mut changed = valid.clone();
        changed[57] = 2;
        negative_cases.push(("SID declared length", changed));
        let mut changed = valid.clone();
        replace_u16(&mut changed, 30, 24);
        negative_cases.push(("ACE SID remainder", changed));
        let mut changed = valid.clone();
        changed.push(0);
        negative_cases.push(("descriptor trailing slack", changed));
        let mut changed = valid.clone();
        changed.extend_from_slice(&[0, 0, 0, 0]);
        let acl_size = u16::try_from(changed.len() - 20).unwrap_or(u16::MAX);
        replace_u16(&mut changed, 22, acl_size);
        negative_cases.push(("ACL free bytes", changed));
        let mut changed = valid.clone();
        push_allow_ace(&mut changed, APPROVAL_PARENT_TOKEN_ACCESS, &approval_sid);
        let acl_size = u16::try_from(changed.len() - 20).unwrap_or(u16::MAX);
        replace_u16(&mut changed, 22, acl_size);
        replace_u16(&mut changed, 24, 4);
        negative_cases.push(("extra ACE", changed));

        for (name, descriptor) in negative_cases {
            assert_eq!(
                token_dacl_parser_result(&descriptor, &user_sid, &key_agent_sid, &approval_sid,),
                Err(KeyAgentLpacError::Token),
                "mutation unexpectedly accepted: {name}"
            );
        }
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
        let source = std::env::current_exe().map_err(|_| KeyAgentLpacError::Profile)?;
        assert!(source.is_absolute());
        assert!(matches!(
            KeyAgentLpacKernelTestFixture::create_from_executable(Path::new("relative.exe")),
            Err(KeyAgentLpacError::Profile)
        ));
        assert!(matches!(
            KeyAgentLpacKernelTestFixture::create_from_executable(&profile_folder),
            Err(KeyAgentLpacError::Profile)
        ));
        let fixture = KeyAgentLpacKernelTestFixture::create_from_executable(&source)?;
        let executable = fixture.executable.clone();
        let directory = fixture.directory.clone();

        assert!(executable.starts_with(&profile_folder));
        assert!(executable.is_file());
        assert!(directory.is_dir());
        assert_eq!(
            std::fs::metadata(&source)
                .map_err(|_| KeyAgentLpacError::Profile)?
                .len(),
            std::fs::metadata(&executable)
                .map_err(|_| KeyAgentLpacError::Profile)?
                .len()
        );
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
        let _ = <PendingKeyAgentLpac as AmbiguousIfClone<_>>::marker;
        let _ = <PendingKeyAgentLpac as AmbiguousIfCopy<_>>::marker;
        let _ = <PendingKeyAgentLpac as AmbiguousIfSync<_>>::marker;
        let _ = <VerifiedKeyAgentLpac as AmbiguousIfClone<_>>::marker;
        let _ = <VerifiedKeyAgentLpac as AmbiguousIfCopy<_>>::marker;

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
    fn existing_storage_root_reopen_retains_identity_path_and_delete_pin()
    -> Result<(), Box<dyn std::error::Error>> {
        let profile = PreparedKeyAgentProfile::open_or_create()?;
        // SAFETY: `profile` retains the exact validated profile SID while the
        // helper copies it and creates one private CSPRNG-named empty leaf.
        let creator = unsafe {
            create_unique_key_agent_storage_root_for_test(
                &profile.appcontainer_local_data,
                profile.profile_sid.as_psid(),
            )
        }?;
        let creator_path = creator.path_for_test().to_path_buf();
        let creator_leaf = creator_path
            .file_name()
            .and_then(|leaf| leaf.to_str())
            .ok_or_else(|| std::io::Error::other("test storage leaf was not canonical UTF-8"))?
            .to_owned();
        let creator_identity = creator.identity();
        assert_eq!(std::fs::canonicalize(&creator_path)?, creator_path);
        creator.revalidate()?;

        // SAFETY: the same validated folder and live profile SID owner remain
        // held, and `creator_leaf` was copied from the CSPRNG creator path.
        let reopened = unsafe {
            open_existing_key_agent_storage_root_for_test(
                &profile.appcontainer_local_data,
                profile.profile_sid.as_psid(),
                &creator_leaf,
            )
        }?;
        assert_eq!(reopened.identity(), creator_identity);
        assert_eq!(reopened.path_for_test(), creator_path);
        assert_eq!(
            std::fs::canonicalize(reopened.path_for_test())?,
            creator_path
        );
        reopened.revalidate()?;

        require_delete_sharing_violation(&creator_path)?;
        let replacement_path = creator_path.with_file_name(format!("{creator_leaf}.replacement"));
        assert!(!replacement_path.exists());
        if std::fs::rename(&creator_path, &replacement_path).is_ok() {
            drop(reopened);
            drop(creator);
            let _ = std::fs::remove_dir(&replacement_path);
            return Err(
                std::io::Error::other("held Key Agent root was unexpectedly replaceable").into(),
            );
        }
        if std::fs::remove_dir(&creator_path).is_ok() {
            drop(reopened);
            drop(creator);
            return Err(
                std::io::Error::other("held Key Agent root was unexpectedly deletable").into(),
            );
        }
        assert!(creator_path.is_dir());
        assert!(!replacement_path.exists());
        assert_eq!(creator.identity(), creator_identity);
        assert_eq!(reopened.identity(), creator_identity);
        creator.revalidate()?;
        reopened.revalidate()?;

        drop(reopened);
        creator.revalidate()?;
        drop(creator);
        assert!(!creator_path.exists());
        assert!(!replacement_path.exists());
        Ok(())
    }

    #[test]
    fn existing_storage_root_opener_does_not_recreate_cleaned_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let profile = PreparedKeyAgentProfile::open_or_create()?;
        // SAFETY: `profile` retains the exact validated profile SID while the
        // helper copies it and creates one private CSPRNG-named empty leaf.
        let creator = unsafe {
            create_unique_key_agent_storage_root_for_test(
                &profile.appcontainer_local_data,
                profile.profile_sid.as_psid(),
            )
        }?;
        let creator_path = creator.path_for_test().to_path_buf();
        let creator_leaf = creator_path
            .file_name()
            .and_then(|leaf| leaf.to_str())
            .ok_or_else(|| std::io::Error::other("test storage leaf was not canonical UTF-8"))?
            .to_owned();
        assert!(creator_path.is_dir());
        drop(creator);
        assert!(!creator_path.exists());

        // SAFETY: the profile SID remains valid, and the leaf was copied from
        // the exact test creator. The opener must only observe; it cannot create
        // or repair.
        let reopened = unsafe {
            open_existing_key_agent_storage_root_for_test(
                &profile.appcontainer_local_data,
                profile.profile_sid.as_psid(),
                &creator_leaf,
            )
        };
        assert!(matches!(reopened, Err(KeyAgentStorageError::Creation)));
        assert!(!creator_path.exists());
        Ok(())
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
