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
use core::mem::{offset_of, size_of, size_of_val};
use core::ptr;
use std::fs;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::fs::MetadataExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, RawHandle};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

use thiserror::Error;
use windows::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_SUCCESS, GENERIC_WRITE, HANDLE, HLOCAL, LocalFree,
};
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
    SE_SELF_RELATIVE, SECURITY_ATTRIBUTES, SYSTEM_MANDATORY_LABEL_ACE, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
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
use windows::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, FILE_PERSISTENT_ACLS, SYSTEM_MANDATORY_LABEL_ACE_TYPE,
    SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::System::WindowsProgramming::DRIVE_FIXED;
use windows::core::{BOOL, PCWSTR, PWSTR};

const KEY_AGENT_STORAGE_ROOT_LEAF: &str = "YourWallet.KeyAgent.Storage.v1";
const MIN_BINARY_SID_BYTES: usize = 8;
const MAX_BINARY_SID_BYTES: usize = 68;
const MAX_FINAL_PATH_UTF16: usize = 32_768;
const FILESYSTEM_NAME_UTF16: usize = 32;

// The directory access required by the existing generation-store backend:
// list/traverse, create files/subdirectories, perform its documented
// GENERIC_WRITE directory flush, and operate on exact child handles. It
// deliberately excludes DELETE_CHILD, WRITE_DAC,
// and WRITE_OWNER. FILE_ADD_SUBDIRECTORY, FILE_WRITE_EA, and
// FILE_WRITE_ATTRIBUTES are unavoidable members of FILE_GENERIC_WRITE, which
// the held directory handle requests for FlushFileBuffers.
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
    /// The supplied integration-only profile folder or SID was invalid.
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

#[derive(Eq, PartialEq)]
struct KeyAgentStorageRootIdentity {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

impl fmt::Debug for KeyAgentStorageRootIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyAgentStorageRootIdentity([REDACTED])")
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
    let wide = wide_path(path)?;
    // SAFETY: the freshly created absolute path is NUL terminated. Omitting
    // FILE_SHARE_DELETE pins this exact directory object against replacement.
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
    .map_err(|_| KeyAgentStorageError::Creation)?;
    // SAFETY: transfer the one successful owned Win32 handle to File exactly once.
    let handle = unsafe { std::fs::File::from_raw_handle(raw.0 as RawHandle) };
    verify_directory_object(&handle)?;
    verify_supported_local_ntfs(&handle)?;
    verify_handle_security(&handle, &stable_user_sid, &profile_sid)?;
    let identity = exact_file_identity(&handle)?;

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
    if information.VolumeSerialNumber == 0
        || information.FileId.Identifier == [0; 16]
        || information.FileId.Identifier == [u8::MAX; 16]
    {
        return Err(KeyAgentStorageError::Identity);
    }
    Ok(KeyAgentStorageRootIdentity {
        volume_serial_number: information.VolumeSerialNumber,
        file_id: information.FileId.Identifier,
    })
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
    let mut token = HANDLE::default();
    // SAFETY: query-only current process token output is valid.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) }
        .map_err(|_| KeyAgentStorageError::Security)?;
    let token = OwnedHandle(token);
    let mut needed = 0_u32;
    // SAFETY: first call intentionally queries the exact TokenUser length.
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &raw mut needed) };
    if needed < u32::try_from(size_of::<TOKEN_USER>()).unwrap_or(u32::MAX) {
        return Err(KeyAgentStorageError::Security);
    }
    let word_size = size_of::<usize>();
    let words = usize::try_from(needed)
        .map_err(|_| KeyAgentStorageError::Security)?
        .checked_add(word_size - 1)
        .and_then(|bytes| bytes.checked_div(word_size))
        .ok_or(KeyAgentStorageError::Security)?;
    let mut buffer = vec![0_usize; words];
    // SAFETY: aligned buffer is writable for the queried byte length.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            needed,
            &raw mut needed,
        )
    }
    .map_err(|_| KeyAgentStorageError::Security)?;
    // SAFETY: Windows initialized a complete TOKEN_USER in the aligned buffer.
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    // SAFETY: TokenUser owns a live SID until buffer drop; copy completes first.
    unsafe { OwnedSid::copy_from(sid) }.map_err(|_| KeyAgentStorageError::Security)
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
        KEY_AGENT_STORAGE_ROOT_ACCESS, KeyAgentStorageError, OwnedSid, SecurityDescriptor,
        inspect_handle_security_descriptor,
    };
    use core::ffi::c_void;
    use core::ptr;
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::{
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetSecurityDescriptorSacl, PSID,
    };
    use windows::core::BOOL;

    const USER_SID: &str = "S-1-5-21-1-2-3-1001";
    const PROFILE_SID: &str = "S-1-15-2-1-2-3-4-5-6-7-8";
    const OTHER_PROFILE_SID: &str = "S-1-15-2-8-7-6-5-4-3-2-1";

    struct StringSid(PSID);

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
        assert_eq!(KEY_AGENT_STORAGE_ROOT_ACCESS & 0x0004_0000, 0);
        assert_eq!(KEY_AGENT_STORAGE_ROOT_ACCESS & 0x0008_0000, 0);
        assert_eq!(KEY_AGENT_STORAGE_ROOT_ACCESS, 0x0012_01b7);
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
