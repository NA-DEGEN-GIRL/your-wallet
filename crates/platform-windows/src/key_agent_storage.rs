//! Supervisor-side provisioning of the fixed Key Agent storage root.
//!
//! Production callers can create exactly one fixed leaf beneath the already
//! validated fixed-profile `AppContainer` folder. Existing roots are never
//! adopted or repaired. The returned capability keeps a no-delete-share
//! directory handle open and retains the exact NTFS file identity and security
//! principals used for handle-based revalidation.

#![allow(unsafe_code)]

use core::ffi::c_void;
use core::fmt;
#[cfg(test)]
use core::fmt::Write as _;
use core::marker::PhantomData;
use core::mem::{offset_of, size_of, size_of_val};
use core::ptr;
use std::fs;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::fs::MetadataExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, RawHandle};
use std::path::{Component, Path, PathBuf, Prefix};
use std::rc::Rc;
use std::sync::Arc;

use thiserror::Error;
use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_TOKEN,
    ERROR_SUCCESS, GENERIC_WRITE, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
};
#[cfg(test)]
use windows::Win32::Foundation::{ERROR_PRIVILEGE_NOT_HELD, ERROR_SHARING_VIOLATION};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, ACL_SIZE_INFORMATION, AclSizeInformation,
    CONTAINER_INHERIT_ACE, CopySid, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
    GetLengthSid, GetSecurityDescriptorControl, GetTokenInformation, INHERITED_ACE, IsValidAcl,
    IsValidSecurityDescriptor, IsValidSid, LABEL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_AUTO_INHERIT_REQ,
    SE_DACL_AUTO_INHERITED, SE_DACL_DEFAULTED, SE_DACL_PRESENT, SE_DACL_PROTECTED,
    SE_OWNER_DEFAULTED, SE_SACL_AUTO_INHERIT_REQ, SE_SACL_DEFAULTED, SE_SACL_PRESENT,
    SE_SELF_RELATIVE, SECURITY_ATTRIBUTES, SYSTEM_MANDATORY_LABEL_ACE,
    TOKEN_APPCONTAINER_INFORMATION, TOKEN_QUERY, TOKEN_USER, TokenAppContainerSid, TokenUser,
};
#[cfg(test)]
use windows::Win32::Security::{
    AccessCheck, DuplicateToken, GENERIC_MAPPING, GROUP_SECURITY_INFORMATION, PRIVILEGE_SET,
    SecurityImpersonation, TOKEN_DUPLICATE,
};
use windows::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_ID_INFO, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_REMOTE_PROTOCOL_INFO,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_EA,
    FileIdInfo, FileRemoteProtocolInfo, GetDriveTypeW, GetFileInformationByHandleEx,
    GetFinalPathNameByHandleW, GetVolumeInformationByHandleW, OPEN_EXISTING, READ_CONTROL,
    SYNCHRONIZE, VOLUME_NAME_GUID,
};
#[cfg(test)]
use windows::Win32::Storage::FileSystem::{
    DELETE, FILE_ALL_ACCESS, FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, WRITE_DAC, WRITE_OWNER,
};
#[cfg(test)]
use windows::Win32::System::SystemServices::ACCESS_SYSTEM_SECURITY;
use windows::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, FILE_PERSISTENT_ACLS, SYSTEM_MANDATORY_LABEL_ACE_TYPE,
    SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};
use windows::Win32::System::WindowsProgramming::DRIVE_FIXED;
#[cfg(test)]
use windows::core::HRESULT;
use windows::core::{BOOL, PCWSTR, PWSTR};

use crate::key_agent_lpac::KEY_AGENT_PROFILE_V1_NAME;

const KEY_AGENT_STORAGE_ROOT_LEAF: &str = "YourWallet.KeyAgent.Storage.v1";
#[cfg(test)]
const KEY_AGENT_STORAGE_TEST_ROOT_LEAF_PREFIX: &str = "YourWallet.KeyAgent.Storage.Test.";
const KEY_AGENT_STORAGE_IDENTITY_BYTES: usize = size_of::<u64>() + 16;
const MIN_BINARY_SID_BYTES: usize = 8;
const MAX_BINARY_SID_BYTES: usize = 68;
const MAX_STORAGE_TOKEN_INFORMATION_BYTES: usize = 1_024;
const MAX_FINAL_PATH_UTF16: usize = 32_768;
const FILESYSTEM_NAME_UTF16: usize = 32;

// The directory access required by the existing generation-store backend:
// list/traverse, create files/subdirectories, and operate on exact child
// handles. It deliberately excludes DELETE_CHILD, WRITE_DAC, and WRITE_OWNER.
// FILE_ADD_SUBDIRECTORY, FILE_WRITE_EA, and FILE_WRITE_ATTRIBUTES are
// unavoidable members of FILE_GENERIC_WRITE, which the held directory handle
// retains for the later generation-store adapter.
const KEY_AGENT_STORAGE_ROOT_ACCESS: u32 = READ_CONTROL.0
    | SYNCHRONIZE.0
    | FILE_LIST_DIRECTORY.0
    | FILE_ADD_FILE.0
    | FILE_ADD_SUBDIRECTORY.0
    | FILE_WRITE_EA.0
    | FILE_TRAVERSE.0
    | FILE_READ_ATTRIBUTES.0
    | FILE_WRITE_ATTRIBUTES.0;

const INHERITED_LOW_LABEL_ACE_FLAGS: u32 =
    OBJECT_INHERIT_ACE.0 | CONTAINER_INHERIT_ACE.0 | INHERITED_ACE.0;

const LOW_MANDATORY_LABEL_SID: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 16, 0, 16, 0, 0];

/// Stable, path-free failures from fixed Key Agent storage provisioning.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum KeyAgentStorageError {
    /// The exact profile-folder binding or supplied integration SID was invalid.
    #[error("Key Agent storage profile binding is invalid")]
    ProfileBinding,
    /// The fixed storage root already exists and cannot be adopted or repaired.
    #[error("Key Agent storage root already exists")]
    AlreadyExists,
    /// The exact storage root could not be freshly created or opened.
    #[error("Key Agent storage root creation failed")]
    Creation,
    /// Owner, protected DACL, or mandatory-label proof failed.
    #[error("Key Agent storage security policy failed")]
    Security,
    /// The held directory was not a supported local NTFS object.
    #[error("Key Agent storage volume policy failed")]
    Volume,
    /// A stable non-sentinel 128-bit file identity could not be proven.
    #[error("Key Agent storage identity policy failed")]
    Identity,
}

/// Opaque held proof of one freshly created fixed Key Agent storage root.
///
/// The value is deliberately non-cloneable. It exposes neither its path nor
/// either SID and keeps the exact directory object open without delete sharing.
#[must_use = "the held Key Agent storage root must outlive every bound activation"]
pub(crate) struct HeldKeyAgentStorageRoot {
    handle: Option<std::fs::File>,
    identity: KeyAgentStorageRootIdentity,
    stable_user_sid: OwnedSid,
    profile_sid: OwnedSid,
    #[cfg(test)]
    path: PathBuf,
    #[cfg(test)]
    cleanup_on_drop: bool,
}

impl HeldKeyAgentStorageRoot {
    /// Returns copyable, path-free identity evidence for startup binding.
    pub(crate) const fn identity(&self) -> KeyAgentStorageRootIdentity {
        self.identity
    }

    /// Revalidates the held object's exact identity, volume, and security policy.
    pub(crate) fn revalidate(&self) -> Result<(), KeyAgentStorageError> {
        let handle = self.handle.as_ref().ok_or(KeyAgentStorageError::Identity)?;
        verify_directory_object(handle)?;
        verify_supported_local_ntfs(handle)?;
        let identity = exact_file_identity(handle)?;
        if identity != self.identity {
            return Err(KeyAgentStorageError::Identity);
        }
        verify_handle_security(handle, &self.stable_user_sid, &self.profile_sid)
    }

    #[cfg(test)]
    pub(crate) fn path_for_test(&self) -> &Path {
        &self.path
    }
}

impl fmt::Debug for HeldKeyAgentStorageRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeldKeyAgentStorageRoot")
            .field("handle", &"[HELD NO-DELETE-SHARE DIRECTORY]")
            .field("identity", &"[FILE_ID_INFO]")
            .field("owner", &"[STABLE TOKEN USER SID]")
            .field("profile", &"[FIXED KEY AGENT PROFILE SID]")
            .field("path", &"[REDACTED LOCAL PATH]")
            .finish_non_exhaustive()
    }
}

impl Drop for HeldKeyAgentStorageRoot {
    fn drop(&mut self) {
        // Close the no-delete-share handle before the test-only exact cleanup.
        drop(self.handle.take());
        #[cfg(test)]
        if self.cleanup_on_drop {
            // The test seam creates this exact CSPRNG-named empty directory.
            // Cleanup is deliberately non-recursive and never targets the
            // persistent profile folder or production fixed leaf.
            let _ = fs::remove_dir(&self.path);
        }
    }
}

/// Stable, path-free identity evidence for one validated storage root.
///
/// This value conveys no handle, path, or principal authority. Decoding accepts
/// only the exact startup-frame representation and rejects every sentinel that
/// the live `FILE_ID_INFO` query rejects.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct KeyAgentStorageRootIdentity {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

impl KeyAgentStorageRootIdentity {
    fn from_parts(
        volume_serial_number: u64,
        file_id: [u8; 16],
    ) -> Result<Self, KeyAgentStorageError> {
        if volume_serial_number == 0 || file_id == [0; 16] || file_id == [u8::MAX; 16] {
            return Err(KeyAgentStorageError::Identity);
        }
        Ok(Self {
            volume_serial_number,
            file_id,
        })
    }

    /// Encodes the identity as volume serial followed by file ID, in network order.
    pub(crate) fn encode_be(self) -> [u8; 24] {
        let mut encoded = [0_u8; KEY_AGENT_STORAGE_IDENTITY_BYTES];
        let (volume, file_id) = encoded.split_at_mut(size_of::<u64>());
        volume.copy_from_slice(&self.volume_serial_number.to_be_bytes());
        file_id.copy_from_slice(&self.file_id);
        encoded
    }

    /// Decodes and validates the exact network-order startup representation.
    pub(crate) fn decode_be(encoded: [u8; 24]) -> Result<Self, KeyAgentStorageError> {
        let (volume, file_id) = encoded.split_at(size_of::<u64>());
        let volume_serial_number = u64::from_be_bytes(
            <[u8; size_of::<u64>()]>::try_from(volume)
                .map_err(|_| KeyAgentStorageError::Identity)?,
        );
        let file_id = <[u8; 16]>::try_from(file_id).map_err(|_| KeyAgentStorageError::Identity)?;
        Self::from_parts(volume_serial_number, file_id)
    }
}

impl fmt::Debug for KeyAgentStorageRootIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyAgentStorageRootIdentity([REDACTED])")
    }
}

/// Opaque child-held proof of the path-opened fixed Key Agent storage root.
///
/// The value is deliberately non-cloneable and exposes no path, SID, or raw
/// handle. Its `File` omits delete sharing for the capability's full lifetime.
#[must_use = "the child must retain its held Key Agent storage root"]
pub(crate) struct HeldChildKeyAgentStorageRoot {
    handle: std::fs::File,
    identity: KeyAgentStorageRootIdentity,
    stable_user_sid: OwnedSid,
    profile_sid: OwnedSid,
    #[allow(dead_code)] // Read only by the dormant fixed generation-store backend seam.
    path: PathBuf,
}

impl HeldChildKeyAgentStorageRoot {
    /// Returns copyable, path-free identity evidence for startup binding.
    pub(crate) const fn identity(&self) -> KeyAgentStorageRootIdentity {
        self.identity
    }

    /// Revalidates the held object's exact identity and security policy.
    ///
    /// The supervisor-owned peer capability proves the local NTFS volume
    /// policy before and after startup. Matching the complete `FILE_ID_INFO`
    /// here binds this child-held handle to that already-proven object without
    /// requiring volume-management queries from inside LPAC.
    pub(crate) fn revalidate(&self) -> Result<(), KeyAgentStorageError> {
        let identity =
            verify_child_open_storage_root(&self.handle, &self.stable_user_sid, &self.profile_sid)?;
        if identity != self.identity {
            return Err(KeyAgentStorageError::Identity);
        }
        Ok(())
    }

    /// Consumes the child-held root into the four fixed generation-store roles.
    ///
    /// No path, principal, namespace, record class, or payload bound enters this
    /// transition. The private aggregate mints each closed role exactly once and
    /// retains this root until the last role binding is dropped.
    pub(crate) fn into_fixed_generation_store_bindings(
        self,
    ) -> Result<FixedKeyAgentGenerationStoreBindings, KeyAgentStorageError> {
        reject_thread_impersonation()?;
        self.revalidate()?;
        reject_thread_impersonation()?;
        Ok(FixedKeyAgentGenerationStoreBindings::from_child_root(self))
    }
}

impl fmt::Debug for HeldChildKeyAgentStorageRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HeldChildKeyAgentStorageRoot([REDACTED HELD DIRECTORY])")
    }
}

/// The four generation-store roles fixed into the Key Agent storage policy.
///
/// This enum carries no authority. A caller cannot supply it to a constructor;
/// only the consuming child-root transition above mints live role bindings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum FixedKeyAgentGenerationStoreRole {
    Vault = 1,
    NonceLedger = 2,
    SignedCandidateJournal = 3,
    LocalSettings = 4,
}

struct KeyAgentGenerationStoreRootAuthority {
    root: HeldChildKeyAgentStorageRoot,
}

impl fmt::Debug for KeyAgentGenerationStoreRootAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyAgentGenerationStoreRootAuthority([REDACTED HELD ROOT])")
    }
}

/// One non-cloneable binding between the held child root and one fixed store role.
///
/// The shared authority is cloned only inside the one-shot aggregate minting
/// transition. The binding exposes no public path, handle, or principal and is
/// deliberately thread-bound even though its underlying kernel handle is owned.
#[must_use = "the fixed Key Agent generation-store binding must remain held"]
#[allow(dead_code)] // Consumed only by the dormant fixed generation-store backend seam.
pub(crate) struct KeyAgentGenerationStoreBinding {
    authority: Arc<KeyAgentGenerationStoreRootAuthority>,
    role: FixedKeyAgentGenerationStoreRole,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

#[allow(dead_code)] // Accessed only by the dormant fixed generation-store backend seam.
impl KeyAgentGenerationStoreBinding {
    fn new(
        authority: Arc<KeyAgentGenerationStoreRootAuthority>,
        role: FixedKeyAgentGenerationStoreRole,
    ) -> Self {
        Self {
            authority,
            role,
            _not_send_or_sync: PhantomData,
        }
    }

    /// Returns the closed role embedded by the one-shot root transition.
    pub(crate) const fn role(&self) -> FixedKeyAgentGenerationStoreRole {
        self.role
    }

    /// Returns the internally retained root path to the Windows backend only.
    ///
    /// No constructor accepts a path and no public API exports this binding.
    pub(crate) fn root_path(&self) -> &Path {
        &self.authority.root.path
    }

    /// Borrows the exact no-delete-share root handle retained by the binding.
    pub(crate) fn root_handle(&self) -> &std::fs::File {
        &self.authority.root.handle
    }

    /// Returns the live stable-user SID retained by the root proof.
    pub(crate) fn stable_user_sid(&self) -> PSID {
        self.authority.root.stable_user_sid.as_psid()
    }

    /// Returns the live fixed-profile SID retained by the root proof.
    pub(crate) fn profile_sid(&self) -> PSID {
        self.authority.root.profile_sid.as_psid()
    }

    /// Returns path-free full `FILE_ID_INFO` evidence for the retained root.
    pub(crate) fn identity(&self) -> KeyAgentStorageRootIdentity {
        self.authority.root.identity
    }

    /// Revalidates the root without trusting an impersonating thread.
    pub(crate) fn revalidate(&self) -> Result<(), KeyAgentStorageError> {
        reject_thread_impersonation()?;
        self.authority.root.revalidate()?;
        reject_thread_impersonation()
    }
}

impl fmt::Debug for KeyAgentGenerationStoreBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyAgentGenerationStoreBinding([REDACTED FIXED ROLE AND ROOT])")
    }
}

/// Exactly one binding for every fixed Key Agent generation-store role.
///
/// The value is non-cloneable, non-transferable, and caller-nonselectable. Its
/// four fields are private so production composition can consume the complete
/// set rather than opening an arbitrary subset or remapping a role.
#[must_use = "the complete fixed Key Agent generation-store binding set must remain held"]
#[allow(dead_code)] // Three roles stay retained while production storage remains dormant.
pub(crate) struct FixedKeyAgentGenerationStoreBindings {
    vault: KeyAgentGenerationStoreBinding,
    nonce_ledger: KeyAgentGenerationStoreBinding,
    signed_candidate_journal: KeyAgentGenerationStoreBinding,
    local_settings: KeyAgentGenerationStoreBinding,
}

#[allow(dead_code)] // `into_parts` is the intentionally dormant production continuation.
impl FixedKeyAgentGenerationStoreBindings {
    fn from_child_root(root: HeldChildKeyAgentStorageRoot) -> Self {
        let authority = Arc::new(KeyAgentGenerationStoreRootAuthority { root });
        Self {
            vault: KeyAgentGenerationStoreBinding::new(
                Arc::clone(&authority),
                FixedKeyAgentGenerationStoreRole::Vault,
            ),
            nonce_ledger: KeyAgentGenerationStoreBinding::new(
                Arc::clone(&authority),
                FixedKeyAgentGenerationStoreRole::NonceLedger,
            ),
            signed_candidate_journal: KeyAgentGenerationStoreBinding::new(
                Arc::clone(&authority),
                FixedKeyAgentGenerationStoreRole::SignedCandidateJournal,
            ),
            local_settings: KeyAgentGenerationStoreBinding::new(
                authority,
                FixedKeyAgentGenerationStoreRole::LocalSettings,
            ),
        }
    }

    /// Returns the path-free full identity shared by all four bindings.
    pub(crate) fn identity(&self) -> KeyAgentStorageRootIdentity {
        self.vault.identity()
    }

    /// Revalidates the one shared root authority.
    pub(crate) fn revalidate(&self) -> Result<(), KeyAgentStorageError> {
        self.vault.revalidate()
    }

    /// Consumes the complete set into the fixed role order.
    pub(crate) fn into_parts(self) -> [KeyAgentGenerationStoreBinding; 4] {
        [
            self.vault,
            self.nonce_ledger,
            self.signed_candidate_journal,
            self.local_settings,
        ]
    }

    /// Mints test-only role bindings backed by the same retained root authority.
    ///
    /// This is intentionally not a `Clone` implementation and is absent from
    /// production. Kernel tests use it to exercise close-and-reopen behavior.
    #[cfg(test)]
    pub(crate) fn bindings_for_test(&self) -> [KeyAgentGenerationStoreBinding; 4] {
        let authority = Arc::clone(&self.vault.authority);
        [
            KeyAgentGenerationStoreBinding::new(
                Arc::clone(&authority),
                FixedKeyAgentGenerationStoreRole::Vault,
            ),
            KeyAgentGenerationStoreBinding::new(
                Arc::clone(&authority),
                FixedKeyAgentGenerationStoreRole::NonceLedger,
            ),
            KeyAgentGenerationStoreBinding::new(
                Arc::clone(&authority),
                FixedKeyAgentGenerationStoreRole::SignedCandidateJournal,
            ),
            KeyAgentGenerationStoreBinding::new(
                authority,
                FixedKeyAgentGenerationStoreRole::LocalSettings,
            ),
        ]
    }

    #[cfg(test)]
    pub(crate) fn verify_forbidden_root_rights_for_test(&self) -> Result<(), KeyAgentStorageError> {
        let identity = self.identity();
        for (access, expected_error) in [
            (DELETE.0, ERROR_SHARING_VIOLATION.to_hresult()),
            (FILE_DELETE_CHILD.0, ERROR_ACCESS_DENIED.to_hresult()),
            (WRITE_DAC.0, ERROR_ACCESS_DENIED.to_hresult()),
            (WRITE_OWNER.0, ERROR_ACCESS_DENIED.to_hresult()),
            (
                ACCESS_SYSTEM_SECURITY,
                ERROR_PRIVILEGE_NOT_HELD.to_hresult(),
            ),
        ] {
            if access == DELETE.0 || access == WRITE_DAC.0 {
                self.revalidate_identity_for_test(identity)?;
                access_check_denies_root_right_for_test(
                    self.vault.root_handle(),
                    &self.vault.authority.root.stable_user_sid,
                    &self.vault.authority.root.profile_sid,
                    access,
                )?;
                self.revalidate_identity_for_test(identity)?;
            }
            self.revalidate_identity_for_test(identity)?;
            require_root_open_error_for_test(self.vault.root_path(), access, expected_error)?;
            self.revalidate_identity_for_test(identity)?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn revalidate_identity_for_test(
        &self,
        expected: KeyAgentStorageRootIdentity,
    ) -> Result<(), KeyAgentStorageError> {
        self.revalidate()?;
        if self.identity() != expected {
            return Err(KeyAgentStorageError::Identity);
        }
        Ok(())
    }
}

impl fmt::Debug for FixedKeyAgentGenerationStoreBindings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .write_str("FixedKeyAgentGenerationStoreBindings([REDACTED FOUR FIXED ROLE BINDINGS])")
    }
}

/// Freshly creates the one fixed Key Agent storage leaf beneath a previously
/// validated fixed-profile `AC` folder.
///
/// Existing roots fail closed and are never inspected, repaired, or adopted.
/// The fixed leaf is compiled into this module and is not caller-selectable.
///
/// # Safety
///
/// `fixed_profile_sid` must point to the live, valid SID owned by the fixed
/// `YourWallet.KeyAgent.LPAC.v1` profile for the complete call. The function
/// copies it before returning and never retains the raw pointer.
pub(crate) unsafe fn create_fixed_key_agent_storage_root(
    validated_ac_folder: &Path,
    fixed_profile_sid: PSID,
) -> Result<HeldKeyAgentStorageRoot, KeyAgentStorageError> {
    // SAFETY: the caller supplies the fixed live profile SID under the contract
    // above; the common constructor copies and validates it immediately.
    unsafe {
        create_storage_root(
            validated_ac_folder,
            fixed_profile_sid,
            KEY_AGENT_STORAGE_ROOT_LEAF,
            false,
        )
    }
}

/// Opens the fixed storage root from the child process's exact environment.
///
/// This function accepts no caller-selected path, leaf, token, or SID. It
/// rejects thread impersonation, validates the process's AppContainer-rebased
/// `LOCALAPPDATA`, and obtains both expected principals from the current
/// process token before path-opening the one compiled-in leaf.
pub(crate) fn open_fixed_key_agent_storage_root_for_child()
-> Result<HeldChildKeyAgentStorageRoot, KeyAgentStorageError> {
    open_child_storage_root(KEY_AGENT_STORAGE_ROOT_LEAF)
}

#[cfg(test)]
pub(crate) fn open_test_key_agent_storage_root_for_child(
    leaf: &str,
) -> Result<HeldChildKeyAgentStorageRoot, KeyAgentStorageError> {
    if !is_exact_test_storage_root_leaf(leaf) {
        return Err(KeyAgentStorageError::ProfileBinding);
    }
    open_child_storage_root(leaf)
}

fn open_child_storage_root(
    leaf: &str,
) -> Result<HeldChildKeyAgentStorageRoot, KeyAgentStorageError> {
    reject_thread_impersonation()?;
    let validated_ac_folder = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or(KeyAgentStorageError::ProfileBinding)?;
    validate_child_profile_folder_shape(&validated_ac_folder)?;

    let token = current_process_token()?;
    let stable_user_sid = token_user_sid(token.0)?;
    let profile_sid = token_appcontainer_sid(token.0)?;
    let path = validated_ac_folder.join(leaf);

    // Recheck immediately before CreateFileW so its access check uses the same
    // non-impersonating process identity whose token supplied both principals.
    reject_thread_impersonation()?;
    let handle = open_storage_root_handle(&path)?;
    let identity = verify_child_open_storage_root(&handle, &stable_user_sid, &profile_sid)?;
    let held = HeldChildKeyAgentStorageRoot {
        handle,
        identity,
        stable_user_sid,
        profile_sid,
        path,
    };

    held.revalidate()?;
    Ok(held)
}

#[cfg(test)]
fn is_exact_test_storage_root_leaf(leaf: &str) -> bool {
    leaf.strip_prefix(KEY_AGENT_STORAGE_TEST_ROOT_LEAF_PREFIX)
        .is_some_and(|suffix| {
            suffix.len() == 32
                && suffix
                    .as_bytes()
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        })
}

unsafe fn create_storage_root(
    validated_ac_folder: &Path,
    fixed_profile_sid: PSID,
    leaf: &str,
    #[cfg_attr(not(test), allow(unused_variables))] cleanup_on_drop: bool,
) -> Result<HeldKeyAgentStorageRoot, KeyAgentStorageError> {
    validate_profile_folder(validated_ac_folder)?;
    if leaf.is_empty() || leaf.encode_utf16().any(|unit| unit == 0) || leaf.contains(['\\', '/']) {
        return Err(KeyAgentStorageError::ProfileBinding);
    }

    // SAFETY: the caller contract guarantees a readable live SID; copy_sid
    // validates it and retains no borrowed pointer.
    let profile_sid = unsafe { OwnedSid::copy_from(fixed_profile_sid) }?;
    let stable_user_sid = current_stable_user_sid()?;
    let descriptor = SecurityDescriptor::for_key_agent_root(&stable_user_sid, &profile_sid)?;
    descriptor.inspect_creation(&stable_user_sid, &profile_sid)?;

    let path = validated_ac_folder.join(leaf);
    let wide = wide_path(&path)?;
    let attributes = descriptor.attributes();
    // SAFETY: the path and security descriptor remain live for the complete
    // call. CreateDirectoryW succeeds only for a newly created directory.
    let created =
        unsafe { CreateDirectoryW(PCWSTR(wide.as_ptr()), Some(ptr::from_ref(&attributes))) };
    if let Err(error) = created {
        return if error.code() == ERROR_ALREADY_EXISTS.to_hresult() {
            Err(KeyAgentStorageError::AlreadyExists)
        } else {
            Err(KeyAgentStorageError::Creation)
        };
    }

    let result = open_and_verify_created_root(&path, stable_user_sid, profile_sid);
    match result {
        Ok(held) => {
            #[cfg(test)]
            let held = {
                let mut held = held;
                held.cleanup_on_drop = cleanup_on_drop;
                held
            };
            Ok(held)
        }
        Err(error) => {
            // This exact leaf was freshly created by the successful call above.
            // Best-effort cleanup is non-recursive; failure leaves a fail-closed
            // existing root for operator review rather than repairing it.
            let _ = fs::remove_dir(&path);
            Err(error)
        }
    }
}

fn open_and_verify_created_root(
    path: &Path,
    stable_user_sid: OwnedSid,
    profile_sid: OwnedSid,
) -> Result<HeldKeyAgentStorageRoot, KeyAgentStorageError> {
    let handle = open_storage_root_handle(path)?;
    let identity = verify_open_storage_root(&handle, &stable_user_sid, &profile_sid)?;

    Ok(HeldKeyAgentStorageRoot {
        handle: Some(handle),
        identity,
        stable_user_sid,
        profile_sid,
        #[cfg(test)]
        path: path.to_path_buf(),
        #[cfg(test)]
        cleanup_on_drop: false,
    })
}

fn open_storage_root_handle(path: &Path) -> Result<std::fs::File, KeyAgentStorageError> {
    let wide = wide_path(path)?;
    // SAFETY: the validated absolute path is NUL terminated. Omitting
    // FILE_SHARE_DELETE pins the opened directory object against replacement.
    let raw = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0 | FILE_LIST_DIRECTORY.0 | READ_CONTROL.0 | GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|error| {
        if error.code() == ERROR_ACCESS_DENIED.to_hresult() {
            KeyAgentStorageError::Security
        } else {
            KeyAgentStorageError::Creation
        }
    })?;
    // SAFETY: transfer the one successful owned Win32 handle to File exactly once.
    Ok(unsafe { std::fs::File::from_raw_handle(raw.0 as RawHandle) })
}

#[cfg(test)]
fn require_root_open_error_for_test(
    path: &Path,
    desired_access: u32,
    expected_error: HRESULT,
) -> Result<(), KeyAgentStorageError> {
    reject_thread_impersonation()?;
    let wide = wide_path(path)?;
    // SAFETY: the retained root supplied this validated NUL-terminated path.
    // Each probe pins the exact kernel result separately from the DACL-only
    // AccessCheck proof used where the retained handle masks DELETE access.
    let result = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    };
    reject_thread_impersonation()?;
    match result {
        Err(error) if error.code() == expected_error => Ok(()),
        Ok(handle) => {
            // SAFETY: a surprising successful open returned one fresh owned
            // handle. Close it exactly once before failing the security proof.
            drop(unsafe { std::fs::File::from_raw_handle(handle.0 as RawHandle) });
            Err(KeyAgentStorageError::Security)
        }
        Err(_) => Err(KeyAgentStorageError::Security),
    }
}

#[cfg(test)]
#[allow(clippy::too_many_lines)] // Keeps the complete kernel-proof lifetime in one test-only scope.
fn access_check_denies_root_right_for_test(
    root: &std::fs::File,
    stable_user_sid: &OwnedSid,
    profile_sid: &OwnedSid,
    desired_access: u32,
) -> Result<(), KeyAgentStorageError> {
    const MAX_PRIVILEGE_SET_BYTES: usize = 64 * 1024;

    reject_thread_impersonation()?;
    let mut owner = PSID::default();
    let mut group = PSID::default();
    let mut dacl = ptr::null_mut::<ACL>();
    let mut raw_descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: every requested output points to initialized writable storage;
    // the held root handle remains live through descriptor inspection.
    let status = unsafe {
        GetSecurityInfo(
            HANDLE(root.as_raw_handle()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | GROUP_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | LABEL_SECURITY_INFORMATION,
            Some(&raw mut owner),
            Some(&raw mut group),
            Some(&raw mut dacl),
            None,
            Some(&raw mut raw_descriptor),
        )
    };
    if raw_descriptor.0.is_null() {
        return Err(KeyAgentStorageError::Security);
    }
    let descriptor = SecurityDescriptor(raw_descriptor);
    let valid_group = status == ERROR_SUCCESS
        && !group.0.is_null()
        // SAFETY: successful GetSecurityInfo placed `group` inside the live
        // self-relative descriptor retained by `descriptor`.
        && unsafe { IsValidSid(group) }.as_bool();
    if status != ERROR_SUCCESS || owner.0.is_null() || !valid_group || dacl.is_null() {
        return Err(KeyAgentStorageError::Security);
    }

    let mut sacl_present = BOOL(0);
    let mut sacl_defaulted = BOOL(0);
    let mut sacl = ptr::null_mut::<ACL>();
    // SAFETY: GetSecurityInfo returned one live self-relative descriptor that
    // includes LABEL_SECURITY_INFORMATION.
    unsafe {
        windows::Win32::Security::GetSecurityDescriptorSacl(
            descriptor.0,
            &raw mut sacl_present,
            &raw mut sacl,
            &raw mut sacl_defaulted,
        )
        .map_err(|_| KeyAgentStorageError::Security)?;
    }
    if !sacl_present.as_bool() || sacl_defaulted.as_bool() || sacl.is_null() {
        return Err(KeyAgentStorageError::Security);
    }
    inspect_handle_security_descriptor(
        descriptor.0,
        owner,
        dacl,
        sacl,
        stable_user_sid,
        profile_sid,
    )?;

    let token = current_process_impersonation_token_for_test()?;
    let mapping = GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ.0,
        GenericWrite: FILE_GENERIC_WRITE.0,
        GenericExecute: FILE_GENERIC_EXECUTE.0,
        GenericAll: FILE_ALL_ACCESS.0,
    };
    let mut privilege_bytes = 0_u32;
    let mut granted_access = u32::MAX;
    let mut access_status = BOOL(1);
    // SAFETY: all scalar outputs and the mapping are live. The first call
    // intentionally supplies no PRIVILEGE_SET so Windows reports its size.
    let size_query = unsafe {
        AccessCheck(
            descriptor.0,
            token.0,
            desired_access,
            ptr::from_ref(&mapping),
            None,
            &raw mut privilege_bytes,
            &raw mut granted_access,
            &raw mut access_status,
        )
    };
    if !matches!(size_query, Err(error) if error.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult()) {
        return Err(KeyAgentStorageError::Security);
    }

    let privilege_bytes =
        usize::try_from(privilege_bytes).map_err(|_| KeyAgentStorageError::Security)?;
    if privilege_bytes < size_of::<PRIVILEGE_SET>() || privilege_bytes > MAX_PRIVILEGE_SET_BYTES {
        return Err(KeyAgentStorageError::Security);
    }
    let alignment = size_of::<usize>();
    let word_count = privilege_bytes
        .checked_add(alignment - 1)
        .and_then(|rounded| rounded.checked_div(alignment))
        .ok_or(KeyAgentStorageError::Security)?;
    let mut privilege_words = vec![0_usize; word_count];
    let capacity = privilege_words
        .len()
        .checked_mul(alignment)
        .ok_or(KeyAgentStorageError::Security)?;
    if capacity < privilege_bytes {
        return Err(KeyAgentStorageError::Security);
    }
    let mut supplied_bytes = u32::try_from(capacity).map_err(|_| KeyAgentStorageError::Security)?;
    granted_access = u32::MAX;
    access_status = BOOL(1);
    // SAFETY: Vec<usize> supplies alignment at least as strict as
    // PRIVILEGE_SET and remains writable for the advertised capacity.
    unsafe {
        AccessCheck(
            descriptor.0,
            token.0,
            desired_access,
            ptr::from_ref(&mapping),
            Some(privilege_words.as_mut_ptr().cast::<PRIVILEGE_SET>()),
            &raw mut supplied_bytes,
            &raw mut granted_access,
            &raw mut access_status,
        )
        .map_err(|_| KeyAgentStorageError::Security)?;
    }
    reject_thread_impersonation()?;
    if usize::try_from(supplied_bytes).map_err(|_| KeyAgentStorageError::Security)? > capacity
        || access_status.as_bool()
        || granted_access != 0
    {
        return Err(KeyAgentStorageError::Security);
    }
    Ok(())
}

#[cfg(test)]
fn current_process_impersonation_token_for_test() -> Result<OwnedHandle, KeyAgentStorageError> {
    reject_thread_impersonation()?;
    let mut primary = HANDLE::default();
    // SAFETY: query/duplicate-only access is requested for the current process
    // token and the output points to initialized writable handle storage.
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &raw mut primary,
        )
        .map_err(|_| KeyAgentStorageError::Security)?;
    }
    if primary.is_invalid() || primary == INVALID_HANDLE_VALUE {
        return Err(KeyAgentStorageError::Security);
    }
    let primary = OwnedHandle(primary);
    let mut impersonation = HANDLE::default();
    // SAFETY: the primary token has TOKEN_DUPLICATE and the output receives one
    // exclusively owned impersonation-token handle for AccessCheck only.
    unsafe { DuplicateToken(primary.0, SecurityImpersonation, &raw mut impersonation) }
        .map_err(|_| KeyAgentStorageError::Security)?;
    if impersonation.is_invalid() || impersonation == INVALID_HANDLE_VALUE {
        return Err(KeyAgentStorageError::Security);
    }
    reject_thread_impersonation()?;
    Ok(OwnedHandle(impersonation))
}

fn verify_open_storage_root(
    handle: &std::fs::File,
    stable_user_sid: &OwnedSid,
    profile_sid: &OwnedSid,
) -> Result<KeyAgentStorageRootIdentity, KeyAgentStorageError> {
    verify_directory_object(handle)?;
    verify_supported_local_ntfs(handle)?;
    verify_handle_security(handle, stable_user_sid, profile_sid)?;
    exact_file_identity(handle)
}

fn verify_child_open_storage_root(
    handle: &std::fs::File,
    stable_user_sid: &OwnedSid,
    profile_sid: &OwnedSid,
) -> Result<KeyAgentStorageRootIdentity, KeyAgentStorageError> {
    verify_directory_object(handle)?;
    verify_handle_security(handle, stable_user_sid, profile_sid)?;
    exact_file_identity(handle)
}

fn validate_profile_folder(path: &Path) -> Result<(), KeyAgentStorageError> {
    if !path.is_absolute()
        || path
            .file_name()
            .and_then(|name| name.to_str())
            .is_none_or(|name| !name.eq_ignore_ascii_case("AC"))
        || path.as_os_str().encode_wide().any(|unit| unit == 0)
    {
        return Err(KeyAgentStorageError::ProfileBinding);
    }
    let ancestors = path.ancestors().collect::<Vec<_>>();
    for ancestor in ancestors.into_iter().rev() {
        let metadata =
            fs::symlink_metadata(ancestor).map_err(|_| KeyAgentStorageError::ProfileBinding)?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            return Err(KeyAgentStorageError::ProfileBinding);
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| KeyAgentStorageError::ProfileBinding)?;
    if !metadata.is_dir() {
        return Err(KeyAgentStorageError::ProfileBinding);
    }
    Ok(())
}

fn validate_child_profile_folder_shape(path: &Path) -> Result<(), KeyAgentStorageError> {
    let mut components = path.components();
    if !matches!(
        (components.next(), components.next()),
        (
            Some(Component::Prefix(prefix)),
            Some(Component::RootDir)
        ) if matches!(prefix.kind(), Prefix::Disk(_))
    ) || components
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(KeyAgentStorageError::ProfileBinding);
    }
    let local_folder_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(KeyAgentStorageError::ProfileBinding)?;
    let profile_folder = path.parent().ok_or(KeyAgentStorageError::ProfileBinding)?;
    let profile_name = profile_folder
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(KeyAgentStorageError::ProfileBinding)?;
    let packages = profile_folder
        .parent()
        .ok_or(KeyAgentStorageError::ProfileBinding)?;
    let packages_name = packages
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(KeyAgentStorageError::ProfileBinding)?;
    let packages_parent = packages
        .parent()
        .ok_or(KeyAgentStorageError::ProfileBinding)?;
    if !path.is_absolute()
        || !packages_parent.is_absolute()
        || !local_folder_name.eq_ignore_ascii_case("AC")
        || !profile_name.eq_ignore_ascii_case(KEY_AGENT_PROFILE_V1_NAME)
        || !packages_name.eq_ignore_ascii_case("Packages")
        || path.as_os_str().encode_wide().any(|unit| unit == 0)
    {
        return Err(KeyAgentStorageError::ProfileBinding);
    }
    Ok(())
}

fn verify_directory_object(directory: &std::fs::File) -> Result<(), KeyAgentStorageError> {
    let metadata = directory
        .metadata()
        .map_err(|_| KeyAgentStorageError::Identity)?;
    let attributes = metadata.file_attributes();
    if !metadata.is_dir()
        || attributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0
        || attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
    {
        return Err(KeyAgentStorageError::Identity);
    }
    Ok(())
}

fn exact_file_identity(
    directory: &std::fs::File,
) -> Result<KeyAgentStorageRootIdentity, KeyAgentStorageError> {
    let mut information = FILE_ID_INFO::default();
    // SAFETY: the held directory handle is live and output has the exact API
    // representation and writable byte length.
    unsafe {
        GetFileInformationByHandleEx(
            HANDLE(directory.as_raw_handle()),
            FileIdInfo,
            ptr::from_mut(&mut information).cast::<c_void>(),
            u32::try_from(size_of_val(&information)).map_err(|_| KeyAgentStorageError::Identity)?,
        )
    }
    .map_err(|_| KeyAgentStorageError::Identity)?;
    KeyAgentStorageRootIdentity::from_parts(
        information.VolumeSerialNumber,
        information.FileId.Identifier,
    )
}

fn verify_supported_local_ntfs(directory: &std::fs::File) -> Result<(), KeyAgentStorageError> {
    let drive_root = drive_root_for_held_handle(directory)?;
    // SAFETY: this is a NUL-terminated volume-GUID root derived from the held
    // directory handle's kernel final path.
    if unsafe { GetDriveTypeW(PCWSTR(drive_root.as_ptr())) } != DRIVE_FIXED {
        return Err(KeyAgentStorageError::Volume);
    }

    let mut remote_protocol = FILE_REMOTE_PROTOCOL_INFO::default();
    // A successful remote-protocol query proves a redirector-backed object.
    // Local handles normally reject this information class; fixed-drive and
    // exact NTFS checks below independently fail closed.
    // SAFETY: the held directory handle is live and the output points to exact
    // initialized writable storage for the documented information class.
    let remote_query_succeeded = unsafe {
        GetFileInformationByHandleEx(
            HANDLE(directory.as_raw_handle()),
            FileRemoteProtocolInfo,
            ptr::from_mut(&mut remote_protocol).cast::<c_void>(),
            u32::try_from(size_of_val(&remote_protocol))
                .map_err(|_| KeyAgentStorageError::Volume)?,
        )
    }
    .is_ok();

    let mut filesystem_flags = 0_u32;
    let mut filesystem_name = [0_u16; FILESYSTEM_NAME_UTF16];
    // SAFETY: outputs are exact initialized storage and the directory handle
    // remains live for the call.
    unsafe {
        GetVolumeInformationByHandleW(
            HANDLE(directory.as_raw_handle()),
            None,
            None,
            None,
            Some(&raw mut filesystem_flags),
            Some(&mut filesystem_name),
        )
    }
    .map_err(|_| KeyAgentStorageError::Volume)?;

    if remote_query_succeeded
        || filesystem_flags & FILE_PERSISTENT_ACLS == 0
        || !is_exact_ntfs_name(&filesystem_name)
    {
        return Err(KeyAgentStorageError::Volume);
    }
    Ok(())
}

fn drive_root_for_held_handle(directory: &std::fs::File) -> Result<Vec<u16>, KeyAgentStorageError> {
    let mut final_path = vec![0_u16; MAX_FINAL_PATH_UTF16];
    // SAFETY: the live handle and complete initialized output buffer are valid.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            HANDLE(directory.as_raw_handle()),
            &mut final_path,
            VOLUME_NAME_GUID,
        )
    };
    let length = usize::try_from(length).map_err(|_| KeyAgentStorageError::Volume)?;
    if length == 0 || length >= final_path.len() {
        return Err(KeyAgentStorageError::Volume);
    }
    volume_guid_root(&final_path[..length])
}

fn volume_guid_root(path: &[u16]) -> Result<Vec<u16>, KeyAgentStorageError> {
    let prefix = "\\\\?\\Volume{".encode_utf16().collect::<Vec<_>>();
    if path.len() <= prefix.len()
        || !path[..prefix.len()]
            .iter()
            .zip(&prefix)
            .all(|(actual, expected)| {
                u8::try_from(*actual)
                    .ok()
                    .zip(u8::try_from(*expected).ok())
                    .is_some_and(|(actual, expected)| actual.eq_ignore_ascii_case(&expected))
            })
    {
        return Err(KeyAgentStorageError::Volume);
    }
    let closing_brace = path[prefix.len()..]
        .iter()
        .position(|unit| *unit == u16::from(b'}'))
        .and_then(|offset| prefix.len().checked_add(offset))
        .ok_or(KeyAgentStorageError::Volume)?;
    if !is_canonical_volume_guid(&path[prefix.len()..closing_brace])
        || path.get(closing_brace + 1) != Some(&u16::from(b'\\'))
    {
        return Err(KeyAgentStorageError::Volume);
    }
    let end = closing_brace
        .checked_add(2)
        .ok_or(KeyAgentStorageError::Volume)?;
    let mut root = path
        .get(..end)
        .ok_or(KeyAgentStorageError::Volume)?
        .to_vec();
    root.push(0);
    Ok(root)
}

fn is_canonical_volume_guid(value: &[u16]) -> bool {
    value.len() == 36
        && value.iter().enumerate().all(|(index, unit)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *unit == u16::from(b'-')
            } else {
                u8::try_from(*unit).is_ok_and(|byte| byte.is_ascii_hexdigit())
            }
        })
}

fn is_exact_ntfs_name(buffer: &[u16]) -> bool {
    let Some(end) = buffer.iter().position(|unit| *unit == 0) else {
        return false;
    };
    buffer[end..].iter().all(|unit| *unit == 0)
        && ascii_utf16_eq_ignore_case(&buffer[..end], b"NTFS")
}

fn ascii_utf16_eq_ignore_case(value: &[u16], expected: &[u8]) -> bool {
    value.len() == expected.len()
        && value.iter().zip(expected).all(|(unit, expected)| {
            u8::try_from(*unit).is_ok_and(|unit| unit.eq_ignore_ascii_case(expected))
        })
}

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    fn for_key_agent_root(
        stable_user_sid: &OwnedSid,
        profile_sid: &OwnedSid,
    ) -> Result<Self, KeyAgentStorageError> {
        let user = sid_to_string(stable_user_sid.as_psid())?;
        let profile = sid_to_string(profile_sid.as_psid())?;
        let sddl = format!(
            "O:{user}D:P(A;;0x{:08x};;;{user})(A;;0x{:08x};;;{profile})",
            windows::Win32::Storage::FileSystem::FILE_ALL_ACCESS.0,
            KEY_AGENT_STORAGE_ROOT_ACCESS,
        );
        Self::from_sddl(&sddl)
    }

    fn from_sddl(sddl: &str) -> Result<Self, KeyAgentStorageError> {
        let wide = wide_nul(sddl)?;
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: the input is NUL terminated and the successful LocalAlloc
        // result is owned by this wrapper.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &raw mut descriptor,
                None,
            )
        }
        .map_err(|_| KeyAgentStorageError::Security)?;
        // SAFETY: the conversion returned a candidate descriptor allocation.
        if descriptor.0.is_null() || !unsafe { IsValidSecurityDescriptor(descriptor) }.as_bool() {
            if !descriptor.0.is_null() {
                // SAFETY: the failed validation still owns the LocalAlloc block.
                unsafe {
                    let _ = LocalFree(Some(HLOCAL(descriptor.0)));
                }
            }
            return Err(KeyAgentStorageError::Security);
        }
        Ok(Self(descriptor))
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
            lpSecurityDescriptor: self.0.0,
            bInheritHandle: BOOL(0),
        }
    }

    fn inspect_creation(
        &self,
        stable_user_sid: &OwnedSid,
        profile_sid: &OwnedSid,
    ) -> Result<(), KeyAgentStorageError> {
        let mut owner = PSID::default();
        let mut owner_defaulted = BOOL(0);
        let mut dacl_present = BOOL(0);
        let mut dacl_defaulted = BOOL(0);
        let mut dacl = ptr::null_mut::<ACL>();
        // SAFETY: the self-relative descriptor remains live and all output
        // locations are exact initialized stack storage.
        unsafe {
            windows::Win32::Security::GetSecurityDescriptorOwner(
                self.0,
                &raw mut owner,
                &raw mut owner_defaulted,
            )
            .map_err(|_| KeyAgentStorageError::Security)?;
            windows::Win32::Security::GetSecurityDescriptorDacl(
                self.0,
                &raw mut dacl_present,
                &raw mut dacl,
                &raw mut dacl_defaulted,
            )
            .map_err(|_| KeyAgentStorageError::Security)?;
        }
        if owner_defaulted.as_bool() || !dacl_present.as_bool() || dacl_defaulted.as_bool() {
            return Err(KeyAgentStorageError::Security);
        }
        inspect_creation_security_descriptor(self.0, owner, dacl, stable_user_sid, profile_sid)
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: this is the one LocalAlloc block returned by SDDL conversion.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.0.0)));
        }
    }
}

impl fmt::Debug for SecurityDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecurityDescriptor([REDACTED KEY AGENT STORAGE POLICY])")
    }
}

fn verify_handle_security(
    directory: &std::fs::File,
    stable_user_sid: &OwnedSid,
    profile_sid: &OwnedSid,
) -> Result<(), KeyAgentStorageError> {
    let mut owner = PSID::default();
    let mut dacl = ptr::null_mut::<ACL>();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // LABEL_SECURITY_INFORMATION queries only the mandatory label and, by the
    // Windows SECURITY_INFORMATION contract, requires READ_CONTROL rather than
    // ACCESS_SYSTEM_SECURITY. The held handle requests READ_CONTROL.
    // SAFETY: every requested output points to initialized writable storage and
    // the held directory handle remains live for the complete query.
    let status = unsafe {
        GetSecurityInfo(
            HANDLE(directory.as_raw_handle()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            Some(&raw mut owner),
            None,
            Some(&raw mut dacl),
            None,
            Some(&raw mut descriptor),
        )
    };
    if status != ERROR_SUCCESS || descriptor.0.is_null() || owner.0.is_null() || dacl.is_null() {
        if !descriptor.0.is_null() {
            // SAFETY: a non-null GetSecurityInfo descriptor uses LocalAlloc.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(descriptor.0)));
            }
        }
        return Err(KeyAgentStorageError::Security);
    }
    let mut sacl_present = BOOL(0);
    let mut sacl_defaulted = BOOL(0);
    let mut sacl = ptr::null_mut::<ACL>();
    // SAFETY: the successful GetSecurityInfo call returned one live descriptor;
    // its label SACL is queried from that descriptor rather than relying on the
    // ppSacl contract, which is documented only for SACL_SECURITY_INFORMATION.
    let sacl_result = unsafe {
        windows::Win32::Security::GetSecurityDescriptorSacl(
            descriptor,
            &raw mut sacl_present,
            &raw mut sacl,
            &raw mut sacl_defaulted,
        )
    };
    if sacl_result.is_err() || !sacl_present.as_bool() || sacl_defaulted.as_bool() || sacl.is_null()
    {
        // SAFETY: GetSecurityInfo allocated this one self-relative descriptor.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        }
        return Err(KeyAgentStorageError::Security);
    }
    let result = inspect_handle_security_descriptor(
        descriptor,
        owner,
        dacl,
        sacl,
        stable_user_sid,
        profile_sid,
    );
    // SAFETY: GetSecurityInfo allocated this one self-relative descriptor.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
    }
    result
}

fn inspect_creation_security_descriptor(
    descriptor: PSECURITY_DESCRIPTOR,
    owner: PSID,
    dacl: *mut ACL,
    stable_user_sid: &OwnedSid,
    profile_sid: &OwnedSid,
) -> Result<(), KeyAgentStorageError> {
    if descriptor.0.is_null() || dacl.is_null() {
        return Err(KeyAgentStorageError::Security);
    }
    let control = inspect_descriptor_control(descriptor)?;
    let required = control_flag(SE_SELF_RELATIVE)
        | control_flag(SE_DACL_PRESENT)
        | control_flag(SE_DACL_PROTECTED);
    let forbidden = control_flag(SE_OWNER_DEFAULTED)
        | control_flag(SE_DACL_DEFAULTED)
        | control_flag(SE_DACL_AUTO_INHERITED)
        | control_flag(SE_DACL_AUTO_INHERIT_REQ)
        | control_flag(SE_SACL_PRESENT)
        | control_flag(SE_SACL_DEFAULTED)
        | control_flag(SE_SACL_AUTO_INHERIT_REQ);
    if control & required != required || control & forbidden != 0 {
        return Err(KeyAgentStorageError::Security);
    }
    inspect_owner_and_dacl(owner, dacl, stable_user_sid, profile_sid)
}

fn inspect_handle_security_descriptor(
    descriptor: PSECURITY_DESCRIPTOR,
    owner: PSID,
    dacl: *mut ACL,
    sacl: *mut ACL,
    stable_user_sid: &OwnedSid,
    profile_sid: &OwnedSid,
) -> Result<(), KeyAgentStorageError> {
    if descriptor.0.is_null() || dacl.is_null() || sacl.is_null() {
        return Err(KeyAgentStorageError::Security);
    }
    let control = inspect_descriptor_control(descriptor)?;
    let required = control_flag(SE_SELF_RELATIVE)
        | control_flag(SE_DACL_PRESENT)
        | control_flag(SE_DACL_PROTECTED)
        | control_flag(SE_SACL_PRESENT);
    let forbidden = control_flag(SE_OWNER_DEFAULTED)
        | control_flag(SE_DACL_DEFAULTED)
        | control_flag(SE_DACL_AUTO_INHERITED)
        | control_flag(SE_DACL_AUTO_INHERIT_REQ)
        | control_flag(SE_SACL_DEFAULTED)
        | control_flag(SE_SACL_AUTO_INHERIT_REQ);
    // An inherited mandatory-label ACE may set SE_SACL_AUTO_INHERITED on the
    // object descriptor. Its exact trust signal is the ACE's OI|CI|ID flags,
    // which are checked below; no broader SACL is accepted.
    if control & required != required || control & forbidden != 0 {
        return Err(KeyAgentStorageError::Security);
    }

    inspect_owner_and_dacl(owner, dacl, stable_user_sid, profile_sid)?;
    inspect_exact_low_label(sacl)
}

fn inspect_descriptor_control(
    descriptor: PSECURITY_DESCRIPTOR,
) -> Result<u16, KeyAgentStorageError> {
    // SAFETY: descriptor is live for this complete inspection.
    if descriptor.0.is_null() || !unsafe { IsValidSecurityDescriptor(descriptor) }.as_bool() {
        return Err(KeyAgentStorageError::Security);
    }
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: outputs are exact initialized scalar storage.
    unsafe {
        GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision)
            .map_err(|_| KeyAgentStorageError::Security)?;
    }
    Ok(control)
}

fn inspect_owner_and_dacl(
    owner: PSID,
    dacl: *mut ACL,
    stable_user_sid: &OwnedSid,
    profile_sid: &OwnedSid,
) -> Result<(), KeyAgentStorageError> {
    if owner.0.is_null() {
        return Err(KeyAgentStorageError::Security);
    }
    // SAFETY: the owner pointer lies inside the live descriptor.
    if !unsafe { IsValidSid(owner) }.as_bool() {
        return Err(KeyAgentStorageError::Security);
    }
    // SAFETY: IsValidSid accepted owner and the expected SID is owned and live.
    if unsafe { EqualSid(owner, stable_user_sid.as_psid()) }.is_err() {
        return Err(KeyAgentStorageError::Security);
    }
    inspect_exact_dacl(dacl, stable_user_sid, profile_sid)
}

fn control_flag(flag: windows::Win32::Security::SECURITY_DESCRIPTOR_CONTROL) -> u16 {
    u16::from_ne_bytes(flag.0.to_ne_bytes())
}

fn inspect_exact_dacl(
    dacl: *mut ACL,
    stable_user_sid: &OwnedSid,
    profile_sid: &OwnedSid,
) -> Result<(), KeyAgentStorageError> {
    let (acl_size, information) = inspect_acl_header(dacl, 2)?;
    let first = ace_at(dacl, 0)?;
    let second = ace_at(dacl, 1)?;
    let first_size = inspect_allow_ace(
        first,
        stable_user_sid,
        windows::Win32::Storage::FileSystem::FILE_ALL_ACCESS.0,
    )?;
    let second_size = inspect_allow_ace(second, profile_sid, KEY_AGENT_STORAGE_ROOT_ACCESS)?;
    let exact_bytes = size_of::<ACL>()
        .checked_add(first_size)
        .and_then(|bytes| bytes.checked_add(second_size))
        .ok_or(KeyAgentStorageError::Security)?;
    require_exact_acl_size(acl_size, &information, exact_bytes)
}

fn inspect_exact_low_label(sacl: *mut ACL) -> Result<(), KeyAgentStorageError> {
    let (acl_size, information) = inspect_acl_header(sacl, 1)?;
    let ace = ace_at(sacl, 0)?;
    // SAFETY: IsValidAcl/GetAce prove the common ACE_HEADER is present.
    let header = unsafe { &*ace.cast::<ACE_HEADER>() };
    let label_type = u8::try_from(SYSTEM_MANDATORY_LABEL_ACE_TYPE).unwrap_or(u8::MAX);
    let sid_offset = offset_of!(SYSTEM_MANDATORY_LABEL_ACE, SidStart);
    if header.AceType != label_type
        || u32::from(header.AceFlags) != INHERITED_LOW_LABEL_ACE_FLAGS
        || usize::from(header.AceSize) < sid_offset.saturating_add(MIN_BINARY_SID_BYTES)
    {
        return Err(KeyAgentStorageError::Security);
    }
    // SAFETY: the exact mandatory-label ACE fixed portion was proven above.
    let label = unsafe { &*ace.cast::<SYSTEM_MANDATORY_LABEL_ACE>() };
    if label.Mask != SYSTEM_MANDATORY_LABEL_NO_WRITE_UP {
        return Err(KeyAgentStorageError::Security);
    }
    let sid_bytes = ptr::addr_of!(label.SidStart).cast::<u8>();
    let available = usize::from(header.AceSize).saturating_sub(sid_offset);
    let sid_length = validate_sid_in_ace(sid_bytes, available)?;
    if sid_length != LOW_MANDATORY_LABEL_SID.len() {
        return Err(KeyAgentStorageError::Security);
    }
    // SAFETY: validate_sid_in_ace proved this complete range belongs to the ACE.
    let actual = unsafe { core::slice::from_raw_parts(sid_bytes, sid_length) };
    if actual != LOW_MANDATORY_LABEL_SID {
        return Err(KeyAgentStorageError::Security);
    }
    let exact_bytes = size_of::<ACL>()
        .checked_add(usize::from(header.AceSize))
        .ok_or(KeyAgentStorageError::Security)?;
    require_exact_acl_size(acl_size, &information, exact_bytes)
}

fn inspect_acl_header(
    acl: *mut ACL,
    expected_ace_count: u32,
) -> Result<(u16, ACL_SIZE_INFORMATION), KeyAgentStorageError> {
    // SAFETY: a non-null pointer lies inside the caller-owned live descriptor.
    if acl.is_null() || !unsafe { IsValidAcl(acl) }.as_bool() {
        return Err(KeyAgentStorageError::Security);
    }
    // SAFETY: IsValidAcl accepted the complete fixed ACL header. Copying its
    // scalar size does not extend a borrow beyond the caller-owned descriptor.
    let acl_ref = unsafe { &*acl };
    if u32::from(acl_ref.AclRevision) != ACL_REVISION.0 || acl_ref.Sbz1 != 0 || acl_ref.Sbz2 != 0 {
        return Err(KeyAgentStorageError::Security);
    }
    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: output is exact and the validated ACL remains live.
    unsafe {
        GetAclInformation(
            acl,
            (&raw mut information).cast::<c_void>(),
            u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).unwrap_or(u32::MAX),
            AclSizeInformation,
        )
    }
    .map_err(|_| KeyAgentStorageError::Security)?;
    if information.AceCount != expected_ace_count {
        return Err(KeyAgentStorageError::Security);
    }
    Ok((acl_ref.AclSize, information))
}

fn ace_at(acl: *mut ACL, index: u32) -> Result<*mut c_void, KeyAgentStorageError> {
    let mut ace = ptr::null_mut::<c_void>();
    // SAFETY: the validated ACL's AceCount is checked before each fixed index.
    unsafe { GetAce(acl, index, &raw mut ace) }.map_err(|_| KeyAgentStorageError::Security)?;
    if ace.is_null() {
        return Err(KeyAgentStorageError::Security);
    }
    Ok(ace)
}

fn inspect_allow_ace(
    ace: *mut c_void,
    expected_sid: &OwnedSid,
    expected_mask: u32,
) -> Result<usize, KeyAgentStorageError> {
    // SAFETY: GetAce proves that the common fixed header is contained in ACL.
    let header = unsafe { &*ace.cast::<ACE_HEADER>() };
    let allow_type = u8::try_from(ACCESS_ALLOWED_ACE_TYPE).unwrap_or(u8::MAX);
    let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    if header.AceType != allow_type
        || header.AceFlags != 0
        || usize::from(header.AceSize) < sid_offset.saturating_add(MIN_BINARY_SID_BYTES)
    {
        return Err(KeyAgentStorageError::Security);
    }
    // SAFETY: accepted type and size prove the standard allow-ACE fixed fields.
    let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
    if allowed.Mask != expected_mask {
        return Err(KeyAgentStorageError::Security);
    }
    let sid_bytes = ptr::addr_of!(allowed.SidStart).cast::<u8>();
    let available = usize::from(header.AceSize).saturating_sub(sid_offset);
    validate_sid_in_ace(sid_bytes, available)?;
    let actual_sid = PSID(sid_bytes.cast_mut().cast::<c_void>());
    // SAFETY: validate_sid_in_ace proved a complete valid SID within this ACE.
    unsafe { EqualSid(actual_sid, expected_sid.as_psid()) }
        .map_err(|_| KeyAgentStorageError::Security)?;
    Ok(usize::from(header.AceSize))
}

fn validate_sid_in_ace(
    sid_bytes: *const u8,
    available: usize,
) -> Result<usize, KeyAgentStorageError> {
    if sid_bytes.is_null() || available < MIN_BINARY_SID_BYTES {
        return Err(KeyAgentStorageError::Security);
    }
    // SAFETY: available includes the complete fixed SID header and count byte.
    let sub_authority_count = usize::from(unsafe { *sid_bytes.add(1) });
    let declared = sub_authority_count
        .checked_mul(size_of::<u32>())
        .and_then(|bytes| bytes.checked_add(MIN_BINARY_SID_BYTES))
        .ok_or(KeyAgentStorageError::Security)?;
    if declared != available || declared > MAX_BINARY_SID_BYTES {
        return Err(KeyAgentStorageError::Security);
    }
    let sid = PSID(sid_bytes.cast_mut().cast::<c_void>());
    // SAFETY: the self-declared SID length was proven to fit the ACE exactly.
    if !unsafe { IsValidSid(sid) }.as_bool() {
        return Err(KeyAgentStorageError::Security);
    }
    // SAFETY: IsValidSid accepted the SID wholly contained by this ACE.
    let reported = usize::try_from(unsafe { GetLengthSid(sid) })
        .map_err(|_| KeyAgentStorageError::Security)?;
    if reported != declared {
        return Err(KeyAgentStorageError::Security);
    }
    Ok(declared)
}

fn require_exact_acl_size(
    acl_size: u16,
    information: &ACL_SIZE_INFORMATION,
    exact_bytes: usize,
) -> Result<(), KeyAgentStorageError> {
    if usize::try_from(information.AclBytesInUse).map_err(|_| KeyAgentStorageError::Security)?
        != exact_bytes
        || information.AclBytesFree != 0
        || usize::from(acl_size) != exact_bytes
    {
        return Err(KeyAgentStorageError::Security);
    }
    Ok(())
}

struct OwnedSid {
    words: Box<[usize]>,
    byte_len: usize,
}

impl OwnedSid {
    unsafe fn copy_from(sid: PSID) -> Result<Self, KeyAgentStorageError> {
        // SAFETY: the caller guarantees a readable live SID pointer.
        if sid.0.is_null() || !unsafe { IsValidSid(sid) }.as_bool() {
            return Err(KeyAgentStorageError::ProfileBinding);
        }
        // SAFETY: IsValidSid accepted the complete input SID.
        let length = usize::try_from(unsafe { GetLengthSid(sid) })
            .map_err(|_| KeyAgentStorageError::ProfileBinding)?;
        if !(MIN_BINARY_SID_BYTES..=MAX_BINARY_SID_BYTES).contains(&length) {
            return Err(KeyAgentStorageError::ProfileBinding);
        }
        let word_size = size_of::<usize>();
        let word_count = length
            .checked_add(word_size - 1)
            .and_then(|bytes| bytes.checked_div(word_size))
            .ok_or(KeyAgentStorageError::ProfileBinding)?;
        let mut words = vec![0_usize; word_count].into_boxed_slice();
        // SAFETY: the usize allocation provides native alignment and owns at
        // least length writable bytes; source is the validated SID of that
        // exact documented length.
        unsafe {
            CopySid(
                u32::try_from(length).map_err(|_| KeyAgentStorageError::ProfileBinding)?,
                PSID(words.as_mut_ptr().cast::<c_void>()),
                sid,
            )
        }
        .map_err(|_| KeyAgentStorageError::ProfileBinding)?;
        Ok(Self {
            words,
            byte_len: length,
        })
    }

    fn as_psid(&self) -> PSID {
        debug_assert!(self.byte_len <= size_of_val(&*self.words));
        PSID(self.words.as_ptr().cast_mut().cast::<c_void>())
    }
}

impl Drop for OwnedSid {
    fn drop(&mut self) {
        self.words.fill(0);
        self.byte_len = 0;
    }
}

impl fmt::Debug for OwnedSid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OwnedSid([REDACTED])")
    }
}

fn current_stable_user_sid() -> Result<OwnedSid, KeyAgentStorageError> {
    let token = current_process_token()?;
    token_user_sid(token.0)
}

fn current_process_token() -> Result<OwnedHandle, KeyAgentStorageError> {
    let mut token = HANDLE::default();
    // SAFETY: query-only current process token output is valid.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) }
        .map_err(|_| KeyAgentStorageError::Security)?;
    if token.is_invalid() || token == INVALID_HANDLE_VALUE {
        return Err(KeyAgentStorageError::Security);
    }
    Ok(OwnedHandle(token))
}

struct TokenInformation {
    words: Vec<usize>,
    returned_bytes: usize,
}

fn token_information(
    token: HANDLE,
    class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
) -> Result<TokenInformation, KeyAgentStorageError> {
    let mut needed = 0_u32;
    // SAFETY: the first call intentionally queries this information class's
    // exact byte length without supplying an output buffer.
    let size_query = unsafe { GetTokenInformation(token, class, None, 0, &raw mut needed) };
    let needed_bytes = usize::try_from(needed).map_err(|_| KeyAgentStorageError::Security)?;
    if !matches!(size_query, Err(error) if error.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult())
        || needed_bytes == 0
        || needed_bytes > MAX_STORAGE_TOKEN_INFORMATION_BYTES
    {
        return Err(KeyAgentStorageError::Security);
    }
    let word_size = size_of::<usize>();
    let words = needed_bytes
        .checked_add(word_size - 1)
        .and_then(|bytes| bytes.checked_div(word_size))
        .ok_or(KeyAgentStorageError::Security)?;
    let mut buffer = vec![0_usize; words];
    let capacity = buffer
        .len()
        .checked_mul(word_size)
        .ok_or(KeyAgentStorageError::Security)?;
    let mut returned = 0_u32;
    // SAFETY: aligned buffer is writable for the queried byte length.
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            needed,
            &raw mut returned,
        )
    }
    .map_err(|_| KeyAgentStorageError::Security)?;
    let returned_bytes = usize::try_from(returned).map_err(|_| KeyAgentStorageError::Security)?;
    if returned_bytes != needed_bytes || returned_bytes > capacity {
        return Err(KeyAgentStorageError::Security);
    }
    Ok(TokenInformation {
        words: buffer,
        returned_bytes,
    })
}

fn token_user_sid(token: HANDLE) -> Result<OwnedSid, KeyAgentStorageError> {
    let information = token_information(token, TokenUser)?;
    if information.returned_bytes < size_of::<TOKEN_USER>() {
        return Err(KeyAgentStorageError::Security);
    }
    // SAFETY: Windows initialized a complete TOKEN_USER in the aligned buffer.
    let user = unsafe { ptr::read_unaligned(information.words.as_ptr().cast::<TOKEN_USER>()) };
    // SAFETY: TokenUser owns a live SID until buffer drop; copy completes first.
    unsafe { OwnedSid::copy_from(user.User.Sid) }.map_err(|_| KeyAgentStorageError::Security)
}

fn token_appcontainer_sid(token: HANDLE) -> Result<OwnedSid, KeyAgentStorageError> {
    let information = token_information(token, TokenAppContainerSid)?;
    if information.returned_bytes < size_of::<TOKEN_APPCONTAINER_INFORMATION>() {
        return Err(KeyAgentStorageError::Security);
    }
    // SAFETY: the aligned token-information allocation contains the complete
    // returned structure and remains live while its interior SID is copied.
    let container = unsafe {
        ptr::read_unaligned(
            information
                .words
                .as_ptr()
                .cast::<TOKEN_APPCONTAINER_INFORMATION>(),
        )
    };
    if container.TokenAppContainer.is_invalid() {
        return Err(KeyAgentStorageError::Security);
    }
    // SAFETY: TokenAppContainerSid returned this non-null SID inside the
    // still-live information allocation; the owned copy completes first.
    unsafe { OwnedSid::copy_from(container.TokenAppContainer) }
        .map_err(|_| KeyAgentStorageError::Security)
}

fn reject_thread_impersonation() -> Result<(), KeyAgentStorageError> {
    let mut token = HANDLE::default();
    // SAFETY: the pseudo-thread handle and output are valid; OpenAsSelf makes
    // the token query independent of the current impersonation level.
    let result = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &raw mut token) };
    match result {
        Ok(()) if token.is_invalid() || token == INVALID_HANDLE_VALUE => {
            Err(KeyAgentStorageError::Security)
        }
        Ok(()) => {
            drop(OwnedHandle(token));
            Err(KeyAgentStorageError::Security)
        }
        Err(error) if error.code() == ERROR_NO_TOKEN.to_hresult() => Ok(()),
        Err(_) => Err(KeyAgentStorageError::Security),
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns exactly one successful Win32 handle.
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

fn sid_to_string(sid: PSID) -> Result<String, KeyAgentStorageError> {
    let mut text = PWSTR::null();
    // SAFETY: callers pass one valid owned SID; output uses LocalAlloc.
    unsafe { ConvertSidToStringSidW(sid, &raw mut text) }
        .map_err(|_| KeyAgentStorageError::Security)?;
    // SAFETY: successful conversion returns a NUL-terminated allocation.
    let result = unsafe { text.to_string() }.map_err(|_| KeyAgentStorageError::Security);
    // SAFETY: ConvertSidToStringSidW allocated this string with LocalAlloc.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(text.0.cast::<c_void>())));
    }
    result
}

fn wide_path(path: &Path) -> Result<Vec<u16>, KeyAgentStorageError> {
    let units = path.as_os_str().encode_wide();
    if units.clone().any(|unit| unit == 0) {
        return Err(KeyAgentStorageError::ProfileBinding);
    }
    let output: Vec<u16> = units.chain(core::iter::once(0)).collect();
    if output.len() > 32_767 {
        return Err(KeyAgentStorageError::ProfileBinding);
    }
    Ok(output)
}

fn wide_nul(value: &str) -> Result<Vec<u16>, KeyAgentStorageError> {
    if value.encode_utf16().any(|unit| unit == 0) {
        return Err(KeyAgentStorageError::Security);
    }
    Ok(value.encode_utf16().chain(core::iter::once(0)).collect())
}

#[cfg(test)]
pub(crate) unsafe fn create_unique_key_agent_storage_root_for_test(
    validated_ac_folder: &Path,
    fixed_profile_sid: PSID,
) -> Result<HeldKeyAgentStorageRoot, KeyAgentStorageError> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| KeyAgentStorageError::Creation)?;
    let mut leaf = String::from("YourWallet.KeyAgent.Storage.Test.");
    for byte in random {
        write!(&mut leaf, "{byte:02x}").map_err(|_| KeyAgentStorageError::Creation)?;
    }
    // SAFETY: identical to the public(crate) test seam contract; the generated
    // CSPRNG leaf is not caller selectable and uses the production constructor.
    unsafe { create_storage_root(validated_ac_folder, fixed_profile_sid, &leaf, true) }
}

#[cfg(test)]
mod tests {
    use super::{
        FixedKeyAgentGenerationStoreBindings, FixedKeyAgentGenerationStoreRole,
        HeldChildKeyAgentStorageRoot, HeldKeyAgentStorageRoot, KEY_AGENT_STORAGE_IDENTITY_BYTES,
        KEY_AGENT_STORAGE_ROOT_ACCESS, KeyAgentGenerationStoreBinding, KeyAgentStorageError,
        KeyAgentStorageRootIdentity, OwnedSid, SecurityDescriptor,
        inspect_handle_security_descriptor, is_exact_test_storage_root_leaf,
        reject_thread_impersonation, validate_child_profile_folder_shape,
    };
    use core::ffi::c_void;
    use core::mem::size_of;
    use core::ptr;
    use std::path::Path;
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::{
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetSecurityDescriptorSacl,
        ImpersonateSelf, PSID, RevertToSelf, SecurityImpersonation,
    };
    use windows::core::BOOL;

    const USER_SID: &str = "S-1-5-21-1-2-3-1001";
    const PROFILE_SID: &str = "S-1-15-2-1-2-3-4-5-6-7-8";
    const OTHER_PROFILE_SID: &str = "S-1-15-2-8-7-6-5-4-3-2-1";

    trait AmbiguousIfSend<Marker> {
        fn marker() {}
    }

    impl<T: ?Sized> AmbiguousIfSend<()> for T {}
    impl<T: ?Sized + Send> AmbiguousIfSend<u8> for T {}

    trait AmbiguousIfSync<Marker> {
        fn marker() {}
    }

    impl<T: ?Sized> AmbiguousIfSync<()> for T {}
    impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for T {}

    trait AmbiguousIfClone<Marker> {
        fn marker() {}
    }

    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    impl<T: Clone> AmbiguousIfClone<u8> for T {}

    trait AmbiguousIfCopy<Marker> {
        fn marker() {}
    }

    impl<T: ?Sized> AmbiguousIfCopy<()> for T {}
    impl<T: Copy> AmbiguousIfCopy<u8> for T {}

    struct StringSid(PSID);

    struct RevertImpersonation;

    impl Drop for RevertImpersonation {
        fn drop(&mut self) {
            // SAFETY: this guard is constructed only after ImpersonateSelf
            // succeeds in the same test thread.
            unsafe {
                let _ = RevertToSelf();
            }
        }
    }

    impl StringSid {
        fn parse(value: &str) -> Result<Self, KeyAgentStorageError> {
            let wide: Vec<u16> = value.encode_utf16().chain(core::iter::once(0)).collect();
            let mut sid = PSID::default();
            // SAFETY: input is NUL terminated; output is one LocalAlloc SID.
            unsafe {
                windows::Win32::Security::Authorization::ConvertStringSidToSidW(
                    windows::core::PCWSTR(wide.as_ptr()),
                    &raw mut sid,
                )
            }
            .map_err(|_| KeyAgentStorageError::Security)?;
            Ok(Self(sid))
        }

        fn owned(&self) -> Result<OwnedSid, KeyAgentStorageError> {
            // SAFETY: this wrapper owns one live SID for the complete copy.
            unsafe { OwnedSid::copy_from(self.0) }
        }
    }

    impl Drop for StringSid {
        fn drop(&mut self) {
            // SAFETY: ConvertStringSidToSidW allocated this one SID with LocalAlloc.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0.0)));
            }
        }
    }

    fn inspect_sddl(
        sddl: &str,
        expected_user: &OwnedSid,
        expected_profile: &OwnedSid,
    ) -> Result<(), KeyAgentStorageError> {
        let descriptor = SecurityDescriptor::from_sddl(sddl)?;
        let mut owner = PSID::default();
        let mut owner_defaulted = BOOL(0);
        let mut dacl_present = BOOL(0);
        let mut dacl_defaulted = BOOL(0);
        let mut dacl = ptr::null_mut();
        let mut sacl_present = BOOL(0);
        let mut sacl_defaulted = BOOL(0);
        let mut sacl = ptr::null_mut();
        // SAFETY: descriptor and all exact output locations remain live.
        unsafe {
            GetSecurityDescriptorOwner(descriptor.0, &raw mut owner, &raw mut owner_defaulted)
                .map_err(|_| KeyAgentStorageError::Security)?;
            GetSecurityDescriptorDacl(
                descriptor.0,
                &raw mut dacl_present,
                &raw mut dacl,
                &raw mut dacl_defaulted,
            )
            .map_err(|_| KeyAgentStorageError::Security)?;
            GetSecurityDescriptorSacl(
                descriptor.0,
                &raw mut sacl_present,
                &raw mut sacl,
                &raw mut sacl_defaulted,
            )
            .map_err(|_| KeyAgentStorageError::Security)?;
        }
        if owner_defaulted.as_bool()
            || !dacl_present.as_bool()
            || dacl_defaulted.as_bool()
            || !sacl_present.as_bool()
            || sacl_defaulted.as_bool()
        {
            return Err(KeyAgentStorageError::Security);
        }
        inspect_handle_security_descriptor(
            descriptor.0,
            owner,
            dacl,
            sacl,
            expected_user,
            expected_profile,
        )
    }

    fn principals() -> Result<(OwnedSid, OwnedSid), KeyAgentStorageError> {
        Ok((
            StringSid::parse(USER_SID)?.owned()?,
            StringSid::parse(PROFILE_SID)?.owned()?,
        ))
    }

    #[test]
    fn operation_union_excludes_acl_and_owner_mutation() {
        for forbidden in [
            super::DELETE.0,
            super::FILE_DELETE_CHILD.0,
            super::WRITE_DAC.0,
            super::WRITE_OWNER.0,
            super::ACCESS_SYSTEM_SECURITY,
        ] {
            assert_eq!(KEY_AGENT_STORAGE_ROOT_ACCESS & forbidden, 0);
        }
        assert_eq!(KEY_AGENT_STORAGE_ROOT_ACCESS, 0x0012_01b7);
    }

    #[test]
    fn fixed_generation_store_roles_are_closed_and_complete() {
        assert_eq!(
            [
                FixedKeyAgentGenerationStoreRole::Vault as u8,
                FixedKeyAgentGenerationStoreRole::NonceLedger as u8,
                FixedKeyAgentGenerationStoreRole::SignedCandidateJournal as u8,
                FixedKeyAgentGenerationStoreRole::LocalSettings as u8,
            ],
            [1, 2, 3, 4]
        );
    }

    #[test]
    fn generation_store_authorities_are_thread_bound_and_unique() {
        assert!(core::mem::needs_drop::<KeyAgentGenerationStoreBinding>());
        assert!(core::mem::needs_drop::<FixedKeyAgentGenerationStoreBindings>());
        let _ = <KeyAgentGenerationStoreBinding as AmbiguousIfSend<_>>::marker;
        let _ = <KeyAgentGenerationStoreBinding as AmbiguousIfSync<_>>::marker;
        let _ = <KeyAgentGenerationStoreBinding as AmbiguousIfClone<_>>::marker;
        let _ = <KeyAgentGenerationStoreBinding as AmbiguousIfCopy<_>>::marker;
        let _ = <FixedKeyAgentGenerationStoreBindings as AmbiguousIfSend<_>>::marker;
        let _ = <FixedKeyAgentGenerationStoreBindings as AmbiguousIfSync<_>>::marker;
        let _ = <FixedKeyAgentGenerationStoreBindings as AmbiguousIfClone<_>>::marker;
        let _ = <FixedKeyAgentGenerationStoreBindings as AmbiguousIfCopy<_>>::marker;
    }

    #[test]
    fn child_storage_identity_queries_reject_thread_impersonation() -> windows::core::Result<()> {
        {
            // SAFETY: the unwind-safe guard below restores the thread token.
            unsafe { ImpersonateSelf(SecurityImpersonation) }?;
            let _revert = RevertImpersonation;
            assert_eq!(
                reject_thread_impersonation(),
                Err(KeyAgentStorageError::Security)
            );
        }
        assert_eq!(reject_thread_impersonation(), Ok(()));
        Ok(())
    }

    #[test]
    fn identity_codec_is_exact_big_endian_and_round_trips() -> Result<(), KeyAgentStorageError> {
        let file_id = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ];
        let identity = KeyAgentStorageRootIdentity::from_parts(0x0102_0304_0506_0708, file_id)?;
        let encoded = identity.encode_be();
        assert_eq!(
            encoded,
            [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            ]
        );
        assert_eq!(KeyAgentStorageRootIdentity::decode_be(encoded)?, identity);
        Ok(())
    }

    #[test]
    fn identity_sentinels_fail_closed() {
        assert_eq!(
            KeyAgentStorageRootIdentity::from_parts(0, [1; 16]),
            Err(KeyAgentStorageError::Identity)
        );
        assert_eq!(
            KeyAgentStorageRootIdentity::from_parts(1, [0; 16]),
            Err(KeyAgentStorageError::Identity)
        );
        assert_eq!(
            KeyAgentStorageRootIdentity::from_parts(1, [u8::MAX; 16]),
            Err(KeyAgentStorageError::Identity)
        );
        assert!(KeyAgentStorageRootIdentity::from_parts(1, [2; 16]).is_ok());

        let mut zero_volume = [1_u8; 24];
        let (volume, _) = zero_volume.split_at_mut(size_of::<u64>());
        volume.fill(0);
        assert_eq!(
            KeyAgentStorageRootIdentity::decode_be(zero_volume),
            Err(KeyAgentStorageError::Identity)
        );

        let mut zero_file_id = [0_u8; 24];
        let (volume, _) = zero_file_id.split_at_mut(size_of::<u64>());
        volume.copy_from_slice(&1_u64.to_be_bytes());
        assert_eq!(
            KeyAgentStorageRootIdentity::decode_be(zero_file_id),
            Err(KeyAgentStorageError::Identity)
        );

        let mut maximum_file_id = [u8::MAX; 24];
        let (volume, _) = maximum_file_id.split_at_mut(size_of::<u64>());
        volume.copy_from_slice(&1_u64.to_be_bytes());
        assert_eq!(
            KeyAgentStorageRootIdentity::decode_be(maximum_file_id),
            Err(KeyAgentStorageError::Identity)
        );
    }

    #[test]
    fn identity_is_copy_value_evidence_with_fixed_redacted_debug()
    -> Result<(), KeyAgentStorageError> {
        fn require_copy<T: Copy>() {}

        require_copy::<KeyAgentStorageRootIdentity>();
        assert_eq!(KEY_AGENT_STORAGE_IDENTITY_BYTES, 24);
        assert!(core::mem::needs_drop::<HeldKeyAgentStorageRoot>());
        assert!(core::mem::needs_drop::<HeldChildKeyAgentStorageRoot>());
        let identity = KeyAgentStorageRootIdentity::from_parts(7, [8; 16])?;
        assert_eq!(
            format!("{identity:?}"),
            "KeyAgentStorageRootIdentity([REDACTED])"
        );
        Ok(())
    }

    #[test]
    fn test_child_leaf_accepts_only_existing_fixture_grammar() {
        assert!(is_exact_test_storage_root_leaf(
            "YourWallet.KeyAgent.Storage.Test.0123456789abcdef0123456789abcdef"
        ));
        for rejected in [
            "YourWallet.KeyAgent.Storage.v1",
            "YourWallet.KeyAgent.Storage.Test.",
            "YourWallet.KeyAgent.Storage.Test.0123456789abcdef0123456789abcde",
            "YourWallet.KeyAgent.Storage.Test.0123456789abcdef0123456789abcdef0",
            "YourWallet.KeyAgent.Storage.Test.0123456789ABCDEF0123456789ABCDEF",
            "YourWallet.KeyAgent.Storage.Test.0123456789abcdef0123456789abcdeg",
            "YourWallet.KeyAgent.Storage.Test.0123456789abcdef/123456789abcdef",
        ] {
            assert!(!is_exact_test_storage_root_leaf(rejected));
        }
    }

    #[test]
    fn child_profile_locator_accepts_only_fixed_drive_profile_ac_shape() {
        let accepted = Path::new(r"C:\Local\Packages\YourWallet.KeyAgent.LPAC.v1\AC");
        assert_eq!(validate_child_profile_folder_shape(accepted), Ok(()));

        for rejected in [
            r"Local\Packages\YourWallet.KeyAgent.LPAC.v1\AC",
            r"\\server\share\Packages\YourWallet.KeyAgent.LPAC.v1\AC",
            r"C:\Local\Other\YourWallet.KeyAgent.LPAC.v1\AC",
            r"C:\Local\Packages\YourWallet.KeyAgent.LPAC.v2\AC",
            r"C:\Local\Packages\YourWallet.KeyAgent.LPAC.v1\LocalCache",
            r"C:\Local\Parent\..\Packages\YourWallet.KeyAgent.LPAC.v1\AC",
            r"C:\Local\Packages\YourWallet.KeyAgent.LPAC.v1\AC\extra",
            "C:\\Local\\Packages\\YourWallet.KeyAgent.LPAC.v1\\A\0C",
        ] {
            assert_eq!(
                validate_child_profile_folder_shape(Path::new(rejected)),
                Err(KeyAgentStorageError::ProfileBinding)
            );
        }
    }

    #[test]
    fn exact_creation_descriptor_has_only_dual_principal_policy() -> Result<(), KeyAgentStorageError>
    {
        let (user, profile) = principals()?;
        let descriptor = SecurityDescriptor::for_key_agent_root(&user, &profile)?;
        descriptor.inspect_creation(&user, &profile)
    }

    #[test]
    fn exact_inherited_low_label_readback_is_accepted() -> Result<(), KeyAgentStorageError> {
        let (user, profile) = principals()?;
        let exact = format!(
            "O:{USER_SID}D:P(A;;FA;;;{USER_SID})(A;;0x{KEY_AGENT_STORAGE_ROOT_ACCESS:08x};;;{PROFILE_SID})S:(ML;OICIID;NW;;;LW)"
        );
        inspect_sddl(&exact, &user, &profile)
    }

    #[test]
    fn extra_or_wrong_profile_ace_is_rejected() -> Result<(), KeyAgentStorageError> {
        let (user, profile) = principals()?;
        let extra = format!(
            "O:{USER_SID}D:P(A;;FA;;;{USER_SID})(A;;0x{KEY_AGENT_STORAGE_ROOT_ACCESS:08x};;;{PROFILE_SID})(A;;FR;;;{OTHER_PROFILE_SID})S:(ML;OICIID;NW;;;LW)"
        );
        assert_eq!(
            inspect_sddl(&extra, &user, &profile),
            Err(KeyAgentStorageError::Security)
        );
        let wrong = format!(
            "O:{USER_SID}D:P(A;;FA;;;{USER_SID})(A;;0x{KEY_AGENT_STORAGE_ROOT_ACCESS:08x};;;{OTHER_PROFILE_SID})S:(ML;OICIID;NW;;;LW)"
        );
        assert_eq!(
            inspect_sddl(&wrong, &user, &profile),
            Err(KeyAgentStorageError::Security)
        );
        Ok(())
    }

    #[test]
    fn missing_or_non_low_mandatory_label_is_rejected() -> Result<(), KeyAgentStorageError> {
        let (user, profile) = principals()?;
        let missing = format!(
            "O:{USER_SID}D:P(A;;FA;;;{USER_SID})(A;;0x{KEY_AGENT_STORAGE_ROOT_ACCESS:08x};;;{PROFILE_SID})"
        );
        assert_eq!(
            inspect_sddl(&missing, &user, &profile),
            Err(KeyAgentStorageError::Security)
        );
        let medium = format!(
            "O:{USER_SID}D:P(A;;FA;;;{USER_SID})(A;;0x{KEY_AGENT_STORAGE_ROOT_ACCESS:08x};;;{PROFILE_SID})S:(ML;OICIID;NW;;;ME)"
        );
        assert_eq!(
            inspect_sddl(&medium, &user, &profile),
            Err(KeyAgentStorageError::Security)
        );
        let non_inherited = format!(
            "O:{USER_SID}D:P(A;;FA;;;{USER_SID})(A;;0x{KEY_AGENT_STORAGE_ROOT_ACCESS:08x};;;{PROFILE_SID})S:(ML;;NW;;;LW)"
        );
        assert_eq!(
            inspect_sddl(&non_inherited, &user, &profile),
            Err(KeyAgentStorageError::Security)
        );
        Ok(())
    }

    #[test]
    fn unprotected_or_deny_ace_descriptor_is_rejected() -> Result<(), KeyAgentStorageError> {
        let (user, profile) = principals()?;
        let unprotected = format!(
            "O:{USER_SID}D:(A;;FA;;;{USER_SID})(A;;0x{KEY_AGENT_STORAGE_ROOT_ACCESS:08x};;;{PROFILE_SID})S:(ML;OICIID;NW;;;LW)"
        );
        assert_eq!(
            inspect_sddl(&unprotected, &user, &profile),
            Err(KeyAgentStorageError::Security)
        );
        let deny = format!(
            "O:{USER_SID}D:P(A;;FA;;;{USER_SID})(D;;0x{KEY_AGENT_STORAGE_ROOT_ACCESS:08x};;;{PROFILE_SID})S:(ML;OICIID;NW;;;LW)"
        );
        assert_eq!(
            inspect_sddl(&deny, &user, &profile),
            Err(KeyAgentStorageError::Security)
        );
        Ok(())
    }

    #[test]
    fn debug_output_redacts_descriptor_and_sids() -> Result<(), KeyAgentStorageError> {
        let (user, profile) = principals()?;
        let descriptor = SecurityDescriptor::for_key_agent_root(&user, &profile)?;
        let rendered = format!("{descriptor:?} {user:?} {profile:?}");
        assert!(!rendered.contains(USER_SID));
        assert!(!rendered.contains(PROFILE_SID));
        assert!(rendered.contains("[REDACTED"));
        Ok(())
    }

    #[test]
    fn sid_wrapper_is_not_accidentally_ffi_exposed() {
        assert!(core::mem::align_of::<usize>() >= core::mem::align_of::<u32>());
        let _ = ptr::null_mut::<c_void>();
    }
}
