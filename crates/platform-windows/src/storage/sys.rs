#![allow(unsafe_code)]

use core::ffi::c_void;
use core::mem::size_of;
use core::ptr;
use std::fs;
use std::io::{Read, Write};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
use std::path::{Component, Path, PathBuf, Prefix};

use windows::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS, GENERIC_READ,
    GENERIC_WRITE, HANDLE, HLOCAL, LocalFree,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, ACL_SIZE_INFORMATION, AclSizeInformation,
    DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetLengthSid,
    GetSecurityDescriptorControl, GetTokenInformation, IsValidAcl, IsValidSecurityDescriptor,
    IsValidSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_AUTO_INHERIT_REQ,
    SE_DACL_AUTO_INHERITED, SE_DACL_DEFAULTED, SE_DACL_PRESENT, SE_DACL_PROTECTED,
    SE_OWNER_DEFAULTED, SE_SELF_RELATIVE, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
#[cfg(test)]
use windows::Win32::Security::{
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, SECURITY_DESCRIPTOR_RELATIVE,
    SID_AND_ATTRIBUTES, TOKEN_GROUPS, TokenGroups,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE, FILE_ALL_ACCESS,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_REMOTE_PROTOCOL_INFO, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_WRITE_DATA, FileDispositionInfo, FileRemoteProtocolInfo,
    FlushFileBuffers, GetDriveTypeW, GetFileInformationByHandle, GetFileInformationByHandleEx,
    GetFinalPathNameByHandleW, GetVolumeInformationByHandleW, MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH, MoveFileExW, OPEN_ALWAYS, OPEN_EXISTING, READ_CONTROL,
    SetFileInformationByHandle, VOLUME_NAME_GUID,
};
#[cfg(test)]
use windows::Win32::System::SystemServices::SE_GROUP_LOGON_ID;
use windows::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, FILE_PERSISTENT_ACLS};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::System::WindowsProgramming::DRIVE_FIXED;
#[cfg(test)]
use windows::Win32::System::WindowsProgramming::{
    DRIVE_CDROM, DRIVE_NO_ROOT_DIR, DRIVE_RAMDISK, DRIVE_REMOTE, DRIVE_REMOVABLE, DRIVE_UNKNOWN,
};
use windows::core::{BOOL, PCWSTR, PWSTR};

use super::{DurableBackend, FaultControl, FaultPoint, FileRole, StoreConfig, StoreError, sha256};

const MIN_BINARY_SID_BYTES: usize = 8;
const MAX_FINAL_PATH_UTF16: usize = 32_768;
const FILESYSTEM_NAME_UTF16: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    volume_serial: u32,
    file_index: u64,
}

pub(super) struct WindowsBackend {
    root: PathBuf,
    root_handle: std::fs::File,
    root_identity: FileIdentity,
    lock_handle: std::fs::File,
    slot_paths: [PathBuf; 2],
    manifest_path: PathBuf,
    temp_paths: [PathBuf; 3],
    security_descriptor: SecurityDescriptor,
}

impl WindowsBackend {
    pub(super) fn open(config: &StoreConfig) -> Result<Self, StoreError> {
        validate_absolute_local_path(&config.root)?;
        reject_existing_reparse_ancestors(&config.root)?;
        let security_descriptor = SecurityDescriptor::current_user_only()?;
        create_root_if_missing(&config.root, &security_descriptor)?;
        reject_existing_reparse_ancestors(&config.root)?;

        let opened_root = open_directory(&config.root)?;
        verify_not_reparse(&opened_root)?;
        verify_stable_user_security(&opened_root, &security_descriptor.stable_user_sid)?;
        verify_supported_local_volume(&opened_root)?;
        let root_identity = file_identity(&opened_root)?;
        let canonical_root = fs::canonicalize(&config.root).map_err(|_| StoreError::UnsafePath)?;
        validate_absolute_local_path(&canonical_root)?;
        reject_existing_reparse_ancestors(&canonical_root)?;
        let root_handle = open_directory(&canonical_root)?;
        verify_not_reparse(&root_handle)?;
        verify_stable_user_security(&root_handle, &security_descriptor.stable_user_sid)?;
        verify_supported_local_volume(&root_handle)?;
        if file_identity(&root_handle)? != root_identity {
            return Err(StoreError::UnsafePath);
        }
        drop(opened_root);

        let lock_path = canonical_root.join(format!("{}.lock", config.namespace));
        let lock_handle = create_or_open_lock(&lock_path, &security_descriptor)?;

        let slot_paths = [
            canonical_root.join(format!("{}.slot0", config.namespace)),
            canonical_root.join(format!("{}.slot1", config.namespace)),
        ];
        let manifest_path = canonical_root.join(format!("{}.manifest", config.namespace));
        let temp_paths = [
            canonical_root.join(format!("{}.slot0.new", config.namespace)),
            canonical_root.join(format!("{}.slot1.new", config.namespace)),
            canonical_root.join(format!("{}.manifest.new", config.namespace)),
        ];

        let backend = Self {
            root: canonical_root,
            root_handle,
            root_identity,
            lock_handle,
            slot_paths,
            manifest_path,
            temp_paths,
            security_descriptor,
        };
        for temp in &backend.temp_paths {
            remove_stale_temp(temp, &backend.security_descriptor)?;
        }
        flush_directory(&backend.root_handle)?;
        Ok(backend)
    }

    fn path_for(&self, role: FileRole) -> &Path {
        match role {
            FileRole::Slot(slot) => &self.slot_paths[usize::from(slot)],
            FileRole::Manifest => &self.manifest_path,
        }
    }

    fn temp_path_for(&self, role: FileRole) -> &Path {
        match role {
            FileRole::Slot(slot) => &self.temp_paths[usize::from(slot)],
            FileRole::Manifest => &self.temp_paths[2],
        }
    }

    fn fault_points(role: FileRole) -> [FaultPoint; 5] {
        match role {
            FileRole::Slot(_) => [
                FaultPoint::SlotTempCreated,
                FaultPoint::SlotTempWritten,
                FaultPoint::SlotTempFlushed,
                FaultPoint::SlotReplaced,
                FaultPoint::SlotDirectoryFlushed,
            ],
            FileRole::Manifest => [
                FaultPoint::ManifestTempCreated,
                FaultPoint::ManifestTempWritten,
                FaultPoint::ManifestTempFlushed,
                FaultPoint::ManifestReplaced,
                FaultPoint::ManifestDirectoryFlushed,
            ],
        }
    }

    fn revalidate_held_root(&self) -> Result<(), StoreError> {
        verify_not_reparse(&self.root_handle)?;
        verify_stable_user_security(&self.root_handle, &self.security_descriptor.stable_user_sid)?;
        verify_supported_local_volume(&self.root_handle)?;
        if file_identity(&self.root_handle)? != self.root_identity {
            return Err(StoreError::UnsafePath);
        }
        let reopened = open_directory(&self.root)?;
        if file_identity(&reopened)? != self.root_identity {
            return Err(StoreError::UnsafePath);
        }
        Ok(())
    }
}

impl core::fmt::Debug for WindowsBackend {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("WindowsBackend")
            .field("root", &"[HELD SECURE DIRECTORY]")
            .field("root_identity", &self.root_identity)
            .field("lock_handle", &"[HELD EXCLUSIVE FILE]")
            .finish_non_exhaustive()
    }
}

impl DurableBackend for WindowsBackend {
    fn read(&self, role: FileRole, max_bytes: usize) -> Result<Option<Vec<u8>>, StoreError> {
        self.revalidate_held_root()?;
        let path = self.path_for(role);
        let file = match open_existing_file(path) {
            Ok(file) => file,
            Err(error) if is_not_found(&error) => return Ok(None),
            Err(_) => return Err(StoreError::DurabilityFailure),
        };
        verify_persistent_file(&file, &self.security_descriptor.stable_user_sid)?;
        let length = usize::try_from(
            file.metadata()
                .map_err(|_| StoreError::DurabilityFailure)?
                .len(),
        )
        .map_err(|_| StoreError::BoundsExceeded)?;
        if length > max_bytes {
            return Err(StoreError::BoundsExceeded);
        }
        let mut bytes = Vec::with_capacity(length);
        file.take(
            u64::try_from(max_bytes)
                .map_err(|_| StoreError::BoundsExceeded)?
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)
        .map_err(|_| StoreError::DurabilityFailure)?;
        if bytes.len() > max_bytes {
            return Err(StoreError::BoundsExceeded);
        }
        Ok(Some(bytes))
    }

    fn atomic_write(
        &mut self,
        role: FileRole,
        bytes: &[u8],
        fault: &mut dyn FaultControl,
    ) -> Result<(), StoreError> {
        self.revalidate_held_root()?;
        verify_persistent_file(&self.lock_handle, &self.security_descriptor.stable_user_sid)?;
        let target = self.path_for(role);
        let temp = self.temp_path_for(role);
        let points = Self::fault_points(role);

        let mut file = create_new_write_through(temp, &self.security_descriptor)?;
        let temp_identity = file_identity(&file)?;
        if temp_identity.volume_serial != self.root_identity.volume_serial {
            return Err(StoreError::UnsafePath);
        }
        fault.hit(points[0])?;
        file.write_all(bytes)
            .map_err(|_| StoreError::DurabilityFailure)?;
        fault.hit(points[1])?;
        flush_file(&file)?;
        verify_persistent_file(&file, &self.security_descriptor.stable_user_sid)?;
        if file_identity(&file)? != temp_identity {
            return Err(StoreError::UnsafePath);
        }
        fault.hit(points[2])?;
        drop(file);

        atomic_replace(temp, target)?;
        fault.hit(points[3])?;
        let installed = open_existing_file(target).map_err(|_| StoreError::DurabilityFailure)?;
        verify_installed_readback(
            &installed,
            temp_identity,
            self.root_identity.volume_serial,
            bytes,
            sha256(bytes),
            &self.security_descriptor.stable_user_sid,
        )?;
        let rebound = open_existing_file(target).map_err(|_| StoreError::DurabilityFailure)?;
        verify_persistent_file(&rebound, &self.security_descriptor.stable_user_sid)?;
        if file_identity(&rebound)? != temp_identity {
            return Err(StoreError::UnsafePath);
        }
        flush_directory(&self.root_handle)?;
        self.revalidate_held_root()?;
        fault.hit(points[4])?;
        Ok(())
    }
}

struct SecurityDescriptor {
    descriptor: PSECURITY_DESCRIPTOR,
    stable_user_sid: StableUserSid,
}

impl SecurityDescriptor {
    fn current_user_only() -> Result<Self, StoreError> {
        let stable_user_sid = current_stable_user_sid()?;
        Self::for_stable_user(stable_user_sid)
    }

    fn for_stable_user(stable_user_sid: StableUserSid) -> Result<Self, StoreError> {
        let sid_text = sid_to_string(stable_user_sid.as_psid())?;
        let sddl = format!(
            "O:{sid_text}D:P(A;;0x{:08x};;;{sid_text})",
            FILE_ALL_ACCESS.0
        );
        Self::from_sddl(stable_user_sid, &sddl)
    }

    fn from_sddl(stable_user_sid: StableUserSid, sddl: &str) -> Result<Self, StoreError> {
        let wide = wide_nul(sddl);
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `wide` is NUL terminated and the output allocation is owned by
        // this value until released with LocalFree.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &raw mut descriptor,
                None,
            )
            .map_err(|_| StoreError::DurabilityFailure)?;
            if !IsValidSecurityDescriptor(descriptor).as_bool() {
                let _ = LocalFree(Some(HLOCAL(descriptor.0)));
                return Err(StoreError::DurabilityFailure);
            }
        }
        Ok(Self {
            descriptor,
            stable_user_sid,
        })
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
            lpSecurityDescriptor: self.descriptor.0,
            bInheritHandle: BOOL(0),
        }
    }

    #[cfg(test)]
    fn inspect_for_test(&self, expected_sid: &StableUserSid) -> Result<(), StoreError> {
        let (owner, dacl) = self.parts_for_test()?;
        inspect_security_descriptor(self.descriptor, owner, dacl, expected_sid)
    }

    #[cfg(test)]
    fn parts_for_test(&self) -> Result<(PSID, *mut ACL), StoreError> {
        let mut owner = PSID::default();
        let mut owner_defaulted = BOOL(0);
        let mut dacl_present = BOOL(0);
        let mut dacl = ptr::null_mut::<ACL>();
        let mut dacl_defaulted = BOOL(0);
        // SAFETY: the allocated self-relative descriptor remains live and all
        // output pointers refer to initialized stack storage.
        unsafe {
            GetSecurityDescriptorOwner(self.descriptor, &raw mut owner, &raw mut owner_defaulted)
                .map_err(|_| StoreError::InsecurePermissions)?;
            GetSecurityDescriptorDacl(
                self.descriptor,
                &raw mut dacl_present,
                &raw mut dacl,
                &raw mut dacl_defaulted,
            )
            .map_err(|_| StoreError::InsecurePermissions)?;
        }
        if !dacl_present.as_bool()
            || dacl.is_null()
            || owner.0.is_null()
            || owner_defaulted.as_bool()
            || dacl_defaulted.as_bool()
        {
            return Err(StoreError::InsecurePermissions);
        }
        Ok((owner, dacl))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: the descriptor was allocated by LocalAlloc through the SDDL
        // conversion API and is released exactly once.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.descriptor.0)));
        }
    }
}

impl core::fmt::Debug for SecurityDescriptor {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SecurityDescriptor([STABLE TOKEN USER SID ONLY])")
    }
}

#[derive(Clone, Eq, PartialEq)]
struct StableUserSid(Vec<u8>);

impl StableUserSid {
    fn as_psid(&self) -> PSID {
        PSID(self.0.as_ptr().cast_mut().cast::<c_void>())
    }

    #[cfg(test)]
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for StableUserSid {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl core::fmt::Debug for StableUserSid {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("StableUserSid([REDACTED])")
    }
}

fn validate_absolute_local_path(path: &Path) -> Result<(), StoreError> {
    use std::os::windows::ffi::OsStrExt as _;

    if !path.is_absolute() {
        return Err(StoreError::UnsafePath);
    }
    if path.as_os_str().encode_wide().any(|unit| unit == 0) {
        return Err(StoreError::UnsafePath);
    }
    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err(StoreError::UnsafePath);
    };
    if !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        || !matches!(components.next(), Some(Component::RootDir))
        || components.any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(StoreError::UnsafePath);
    }
    Ok(())
}

fn verify_supported_local_volume(directory: &std::fs::File) -> Result<(), StoreError> {
    let drive_root = drive_root_for_held_handle(directory)?;
    // SAFETY: `drive_root` is a NUL-terminated volume-GUID root derived from
    // the final path of the live directory handle.
    let drive_type = unsafe { GetDriveTypeW(PCWSTR(drive_root.as_ptr())) };

    let mut remote_protocol = FILE_REMOTE_PROTOCOL_INFO::default();
    // A successful FileRemoteProtocolInfo query proves a redirector-backed
    // handle. Local handles normally reject this information class. Combined
    // with the fixed-drive and volume checks below, failure cannot turn an
    // unsupported remote store into an accepted one.
    // SAFETY: the live directory handle and exact output structure are valid
    // for the complete call.
    let remote_protocol_query_succeeded = unsafe {
        GetFileInformationByHandleEx(
            HANDLE(directory.as_raw_handle()),
            FileRemoteProtocolInfo,
            ptr::from_mut(&mut remote_protocol).cast::<c_void>(),
            u32::try_from(size_of::<FILE_REMOTE_PROTOCOL_INFO>()).unwrap_or(u32::MAX),
        )
    }
    .is_ok();

    let mut filesystem_flags = 0_u32;
    let mut filesystem_name = [0_u16; FILESYSTEM_NAME_UTF16];
    // SAFETY: outputs are fixed initialized storage and the held directory
    // handle remains live. This volume API is unsupported over SMB and failure
    // is therefore treated as an unsafe/unprovable storage location.
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
    .map_err(|_| StoreError::UnsafePath)?;
    validate_volume_characteristics(
        drive_type,
        remote_protocol_query_succeeded,
        filesystem_flags,
        &filesystem_name,
    )
}

fn validate_volume_characteristics(
    drive_type: u32,
    remote_protocol_query_succeeded: bool,
    filesystem_flags: u32,
    filesystem_name: &[u16],
) -> Result<(), StoreError> {
    if drive_type != DRIVE_FIXED
        || remote_protocol_query_succeeded
        || filesystem_flags & FILE_PERSISTENT_ACLS == 0
        || !is_allowed_filesystem_name(filesystem_name)
    {
        return Err(StoreError::UnsafePath);
    }
    Ok(())
}

fn drive_root_for_held_handle(directory: &std::fs::File) -> Result<Vec<u16>, StoreError> {
    let mut final_path = vec![0_u16; MAX_FINAL_PATH_UTF16];
    // SAFETY: the handle remains live and the initialized output slice is
    // writable for its complete declared length.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            HANDLE(directory.as_raw_handle()),
            &mut final_path,
            VOLUME_NAME_GUID,
        )
    };
    let length = usize::try_from(length).map_err(|_| StoreError::UnsafePath)?;
    if length == 0 || length >= final_path.len() {
        return Err(StoreError::UnsafePath);
    }
    volume_guid_root_from_final_path(&final_path[..length])
}

fn volume_guid_root_from_final_path(path: &[u16]) -> Result<Vec<u16>, StoreError> {
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
        return Err(StoreError::UnsafePath);
    }
    let closing_brace = path[prefix.len()..]
        .iter()
        .position(|unit| *unit == u16::from(b'}'))
        .and_then(|offset| prefix.len().checked_add(offset))
        .ok_or(StoreError::UnsafePath)?;
    if !is_canonical_volume_guid(&path[prefix.len()..closing_brace]) {
        return Err(StoreError::UnsafePath);
    }
    let root_end = closing_brace.checked_add(2).ok_or(StoreError::UnsafePath)?;
    if path.get(closing_brace + 1) != Some(&u16::from(b'\\')) {
        return Err(StoreError::UnsafePath);
    }
    let mut root = path.get(..root_end).ok_or(StoreError::UnsafePath)?.to_vec();
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

fn is_allowed_filesystem_name(buffer: &[u16]) -> bool {
    let Some(end) = buffer.iter().position(|unit| *unit == 0) else {
        return false;
    };
    if buffer[end..].iter().any(|unit| *unit != 0) {
        return false;
    }
    let name = &buffer[..end];
    // ReFS uses 128-bit file identifiers. The 64-bit identifier returned by
    // BY_HANDLE_FILE_INFORMATION is explicitly not guaranteed unique there, so
    // ReFS must remain denied until every identity check uses FILE_ID_INFO.
    ascii_utf16_eq_ignore_case(name, b"NTFS")
}

fn ascii_utf16_eq_ignore_case(value: &[u16], expected: &[u8]) -> bool {
    value.len() == expected.len()
        && value.iter().zip(expected).all(|(unit, expected)| {
            u8::try_from(*unit).is_ok_and(|unit| unit.eq_ignore_ascii_case(expected))
        })
}

fn reject_existing_reparse_ancestors(path: &Path) -> Result<(), StoreError> {
    for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 => {
                return Err(StoreError::UnsafePath);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(StoreError::UnsafePath),
        }
    }
    Ok(())
}

fn create_root_if_missing(root: &Path, descriptor: &SecurityDescriptor) -> Result<(), StoreError> {
    if root.exists() {
        return Ok(());
    }
    let parent = root.parent().ok_or(StoreError::UnsafePath)?;
    if !parent.is_dir() {
        return Err(StoreError::UnsafePath);
    }
    let path = wide_path(root);
    let attributes = descriptor.attributes();
    // SAFETY: the absolute path is NUL terminated and the security descriptor
    // remains live for the complete call.
    let result =
        unsafe { CreateDirectoryW(PCWSTR(path.as_ptr()), Some(ptr::from_ref(&attributes))) };
    if let Err(error) = result
        && error.code() != ERROR_ALREADY_EXISTS.to_hresult()
    {
        return Err(StoreError::DurabilityFailure);
    }
    Ok(())
}

fn open_directory(path: &Path) -> Result<std::fs::File, StoreError> {
    let wide = wide_path(path);
    // SAFETY: NUL-terminated path; requested handle has query/list access and no
    // delete sharing so ordinary replacement is held off while the store lives.
    let handle = unsafe {
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
    .map_err(|_| StoreError::UnsafePath)?;
    // SAFETY: CreateFileW returned one owned Win32 handle which is transferred
    // to `File` exactly once.
    Ok(unsafe { std::fs::File::from_raw_handle(handle.0 as RawHandle) })
}

fn open_existing_file(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
}

fn create_or_open_lock(
    path: &Path,
    descriptor: &SecurityDescriptor,
) -> Result<std::fs::File, StoreError> {
    let wide = wide_path(path);
    let attributes = descriptor.attributes();
    // SAFETY: validated same-directory path and live security attributes. A zero
    // share mode makes this an exclusive writer lease released on process crash.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0 | GENERIC_READ.0 | GENERIC_WRITE.0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_MODE(0),
            Some(ptr::from_ref(&attributes)),
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|_| StoreError::DurabilityFailure)?;
    // SAFETY: transfer exactly one successful owned handle to File.
    let file = unsafe { std::fs::File::from_raw_handle(handle.0 as RawHandle) };
    verify_persistent_file(&file, &descriptor.stable_user_sid)?;
    Ok(file)
}

fn remove_stale_temp(path: &Path, descriptor: &SecurityDescriptor) -> Result<(), StoreError> {
    let wide = wide_path(path);
    // SAFETY: exact fixed temp path is NUL terminated. OPEN_REPARSE_POINT prevents
    // following an attacker-created reparse object while obtaining delete access.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            DELETE.0 | FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    };
    let handle = match handle {
        Ok(handle) => handle,
        Err(error)
            if error.code() == ERROR_FILE_NOT_FOUND.to_hresult()
                || error.code() == ERROR_PATH_NOT_FOUND.to_hresult() =>
        {
            return Ok(());
        }
        Err(_) => return Err(StoreError::DurabilityFailure),
    };
    // SAFETY: transfer exactly one successful owned handle to File.
    let file = unsafe { std::fs::File::from_raw_handle(handle.0 as RawHandle) };
    verify_persistent_file(&file, &descriptor.stable_user_sid)?;
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: the live handle has DELETE access and the input buffer has the
    // exact FILE_DISPOSITION_INFO representation and length.
    unsafe {
        SetFileInformationByHandle(
            HANDLE(file.as_raw_handle()),
            FileDispositionInfo,
            ptr::from_ref(&disposition).cast::<c_void>(),
            u32::try_from(size_of::<FILE_DISPOSITION_INFO>()).unwrap_or(u32::MAX),
        )
    }
    .map_err(|_| StoreError::DurabilityFailure)?;
    drop(file);
    Ok(())
}

fn create_new_write_through(
    path: &Path,
    descriptor: &SecurityDescriptor,
) -> Result<std::fs::File, StoreError> {
    let wide = wide_path(path);
    let attributes = descriptor.attributes();
    // SAFETY: the NUL-terminated path and security attributes remain valid for
    // the call. CREATE_NEW prevents following or overwriting an attacker entry.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_WRITE_DATA.0 | FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0,
            FILE_SHARE_READ,
            Some(ptr::from_ref(&attributes)),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|_| StoreError::DurabilityFailure)?;
    // SAFETY: transfer exactly one successful owned handle to File.
    let file = unsafe { std::fs::File::from_raw_handle(handle.0 as RawHandle) };
    verify_persistent_file(&file, &descriptor.stable_user_sid)?;
    Ok(file)
}

fn atomic_replace(temp: &Path, target: &Path) -> Result<(), StoreError> {
    let temp_wide = wide_path(temp);
    let target_wide = wide_path(target);
    // Both paths are validated children of the same held local directory.
    // MOVEFILE_REPLACE_EXISTING handles both the first commit and replacement;
    // MOVEFILE_WRITE_THROUGH is the documented durability flag. ReplaceFileW's
    // similarly named REPLACEFILE_WRITE_THROUGH flag is explicitly unsupported.
    // SAFETY: both validated same-directory paths remain live for the call.
    unsafe {
        MoveFileExW(
            PCWSTR(temp_wide.as_ptr()),
            PCWSTR(target_wide.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(|_| StoreError::DurabilityFailure)
}

fn flush_file(file: &std::fs::File) -> Result<(), StoreError> {
    // SAFETY: the handle belongs to the live file and has write access.
    unsafe { FlushFileBuffers(HANDLE(file.as_raw_handle())) }
        .map_err(|_| StoreError::DurabilityFailure)
}

fn flush_directory(directory: &std::fs::File) -> Result<(), StoreError> {
    // Windows documents FlushFileBuffers primarily for file/volume handles. NTFS
    // accepts a directory handle opened with backup semantics; if a filesystem
    // rejects this proof, the store fails closed rather than claiming durability.
    // SAFETY: the handle belongs to the held directory.
    unsafe { FlushFileBuffers(HANDLE(directory.as_raw_handle())) }
        .map_err(|_| StoreError::DurabilityFailure)
}

fn verify_not_reparse(file: &std::fs::File) -> Result<(), StoreError> {
    let attributes = file
        .metadata()
        .map_err(|_| StoreError::UnsafePath)?
        .file_attributes();
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(StoreError::UnsafePath);
    }
    Ok(())
}

fn verify_persistent_file(
    file: &std::fs::File,
    expected_sid: &StableUserSid,
) -> Result<(), StoreError> {
    verify_not_reparse(file)?;
    let information = file_information(file)?;
    if information.nNumberOfLinks != 1 {
        return Err(StoreError::UnsafePath);
    }
    verify_stable_user_security(file, expected_sid)
}

fn verify_installed_readback(
    file: &std::fs::File,
    expected_identity: FileIdentity,
    expected_volume_serial: u32,
    expected_bytes: &[u8],
    expected_digest: [u8; 32],
    expected_sid: &StableUserSid,
) -> Result<(), StoreError> {
    verify_persistent_file(file, expected_sid)?;
    let actual_identity = file_identity(file)?;
    if actual_identity != expected_identity
        || actual_identity.volume_serial != expected_volume_serial
    {
        return Err(StoreError::UnsafePath);
    }
    let length = usize::try_from(
        file.metadata()
            .map_err(|_| StoreError::DurabilityFailure)?
            .len(),
    )
    .map_err(|_| StoreError::BoundsExceeded)?;
    if length != expected_bytes.len() {
        return Err(StoreError::DurabilityFailure);
    }
    let read_bound = expected_bytes
        .len()
        .checked_add(1)
        .ok_or(StoreError::BoundsExceeded)?;
    let mut actual = Vec::with_capacity(expected_bytes.len());
    file.take(u64::try_from(read_bound).map_err(|_| StoreError::BoundsExceeded)?)
        .read_to_end(&mut actual)
        .map_err(|_| StoreError::DurabilityFailure)?;
    if actual.len() != expected_bytes.len()
        || sha256(&actual) != expected_digest
        || actual.as_slice() != expected_bytes
    {
        return Err(StoreError::DurabilityFailure);
    }
    Ok(())
}

fn file_identity(file: &std::fs::File) -> Result<FileIdentity, StoreError> {
    let information = file_information(file)?;
    Ok(FileIdentity {
        volume_serial: information.dwVolumeSerialNumber,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
    })
}

fn file_information(file: &std::fs::File) -> Result<BY_HANDLE_FILE_INFORMATION, StoreError> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the file handle remains live; output has the exact API type.
    unsafe {
        GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &raw mut information)
            .map_err(|_| StoreError::UnsafePath)?;
    }
    Ok(information)
}

fn verify_stable_user_security(
    file: &std::fs::File,
    expected_sid: &StableUserSid,
) -> Result<(), StoreError> {
    let mut owner = PSID::default();
    let mut dacl = ptr::null_mut::<ACL>();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: output pointers are valid; GetSecurityInfo allocates descriptor
    // memory that is released below.
    let status = unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&raw mut owner),
            None,
            Some(&raw mut dacl),
            None,
            Some(&raw mut descriptor),
        )
    };
    if status != ERROR_SUCCESS || descriptor.0.is_null() || owner.0.is_null() || dacl.is_null() {
        return Err(StoreError::InsecurePermissions);
    }
    let result = inspect_security_descriptor(descriptor, owner, dacl, expected_sid);
    // SAFETY: GetSecurityInfo allocated this descriptor with LocalAlloc.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
    }
    result
}

fn inspect_security_descriptor(
    descriptor: PSECURITY_DESCRIPTOR,
    owner: PSID,
    dacl: *mut ACL,
    expected_sid: &StableUserSid,
) -> Result<(), StoreError> {
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: the descriptor was either returned by GetSecurityInfo or created
    // by the SDDL conversion API and remains live for this inspection.
    if !unsafe { IsValidSecurityDescriptor(descriptor) }.as_bool() {
        return Err(StoreError::InsecurePermissions);
    }
    // SAFETY: descriptor remains live; output fields are initialized stack values.
    unsafe {
        GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision)
            .map_err(|_| StoreError::InsecurePermissions)?;
    }
    let protected = u16::from_ne_bytes(SE_DACL_PROTECTED.0.to_ne_bytes());
    let present = u16::from_ne_bytes(SE_DACL_PRESENT.0.to_ne_bytes());
    let self_relative = u16::from_ne_bytes(SE_SELF_RELATIVE.0.to_ne_bytes());
    let dacl_defaulted = u16::from_ne_bytes(SE_DACL_DEFAULTED.0.to_ne_bytes());
    let owner_defaulted = u16::from_ne_bytes(SE_OWNER_DEFAULTED.0.to_ne_bytes());
    if control & protected == 0 {
        return Err(StoreError::UnprotectedDacl);
    }
    if control & (present | self_relative) != (present | self_relative) {
        return Err(StoreError::InsecurePermissions);
    }
    let forbidden_control = dacl_defaulted
        | owner_defaulted
        | u16::from_ne_bytes(SE_DACL_AUTO_INHERITED.0.to_ne_bytes())
        | u16::from_ne_bytes(SE_DACL_AUTO_INHERIT_REQ.0.to_ne_bytes());
    if control & forbidden_control != 0 {
        return Err(StoreError::InsecurePermissions);
    }

    // SAFETY: a non-null owner pointer returned inside the live descriptor may
    // be passed to the SID validator before any size-dependent access.
    if owner.0.is_null() || !unsafe { IsValidSid(owner) }.as_bool() {
        return Err(StoreError::InsecurePermissions);
    }
    // SAFETY: `owner` belongs to the live descriptor and the stable user SID is
    // a valid owned copy returned by TokenUser.
    unsafe { EqualSid(owner, expected_sid.as_psid()) }
        .map_err(|_| StoreError::WrongStoragePrincipal)?;

    inspect_exact_dacl(dacl, expected_sid)
}

fn inspect_exact_dacl(dacl: *mut ACL, expected_sid: &StableUserSid) -> Result<(), StoreError> {
    // IsValidSecurityDescriptor deliberately does not validate individual
    // ACL/ACE contents. Prove the ACL layout before GetAce returns a pointer
    // that this function will inspect.
    // SAFETY: `dacl` is non-null and belongs to the live descriptor.
    if !unsafe { IsValidAcl(dacl) }.as_bool() {
        return Err(StoreError::InsecurePermissions);
    }
    // SAFETY: `IsValidAcl` accepted the complete ACL header before any field is
    // read. Exact storage policy accepts only the canonical revision and zeroed
    // reserved fields emitted by this module's descriptor.
    let acl = unsafe { &*dacl };
    if u32::from(acl.AclRevision) != ACL_REVISION.0 || acl.Sbz1 != 0 || acl.Sbz2 != 0 {
        return Err(StoreError::UnexpectedAccessControlEntry);
    }
    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: `dacl` belongs to the live descriptor and output has exact size.
    unsafe {
        GetAclInformation(
            dacl,
            (&raw mut information).cast::<c_void>(),
            u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).unwrap_or(u32::MAX),
            AclSizeInformation,
        )
        .map_err(|_| StoreError::InsecurePermissions)?;
    }
    if information.AceCount != 1 {
        return Err(StoreError::UnexpectedAccessControlEntry);
    }
    let mut ace = ptr::null_mut::<c_void>();
    // SAFETY: the validated ACL reports one ACE at index zero.
    unsafe {
        GetAce(dacl, 0, &raw mut ace).map_err(|_| StoreError::InsecurePermissions)?;
    }
    if ace.is_null() {
        return Err(StoreError::UnexpectedAccessControlEntry);
    }
    inspect_exact_allow_ace(acl, &information, ace, expected_sid)
}

fn inspect_exact_allow_ace(
    acl: &ACL,
    information: &ACL_SIZE_INFORMATION,
    ace: *mut c_void,
    expected_sid: &StableUserSid,
) -> Result<(), StoreError> {
    // SAFETY: IsValidAcl and GetAce proved that the common fixed header is
    // contained in the ACL. Do not cast to a specific ACE layout until its type
    // and complete minimum size have been accepted.
    let header = unsafe { &*ace.cast::<ACE_HEADER>() };
    let (ace_type, ace_flags, ace_size) = (header.AceType, header.AceFlags, header.AceSize);
    let exact_acl_bytes = size_of::<ACL>()
        .checked_add(usize::from(ace_size))
        .ok_or(StoreError::UnexpectedAccessControlEntry)?;
    if usize::try_from(information.AclBytesInUse)
        .map_err(|_| StoreError::UnexpectedAccessControlEntry)?
        != exact_acl_bytes
        || information.AclBytesFree != 0
        || usize::from(acl.AclSize) != exact_acl_bytes
    {
        return Err(StoreError::UnexpectedAccessControlEntry);
    }
    let allowed_type = u8::try_from(ACCESS_ALLOWED_ACE_TYPE).unwrap_or(u8::MAX);
    let sid_offset = core::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    if ace_type != allowed_type
        || ace_flags != 0
        || usize::from(ace_size) < sid_offset.saturating_add(MIN_BINARY_SID_BYTES)
    {
        return Err(StoreError::UnexpectedAccessControlEntry);
    }
    // SAFETY: the accepted type and minimum size now prove that the standard
    // access-allowed ACE fixed fields are present.
    let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
    if allowed.Mask != FILE_ALL_ACCESS.0 {
        return Err(StoreError::UnexpectedAccessControlEntry);
    }
    // SAFETY: SidStart is the documented first byte of the variable SID within
    // ACCESS_ALLOWED_ACE; the ACE-size lower bound was verified above.
    let actual_sid_bytes = ptr::addr_of!(allowed.SidStart).cast::<u8>();
    let actual_sid = PSID(actual_sid_bytes.cast_mut().cast::<c_void>());
    let sid_bytes_available = usize::from(ace_size).saturating_sub(sid_offset);
    // The second byte is SubAuthorityCount. Reading it is bounded by the
    // complete fixed SID header proven above; calculate the exact declared SID
    // length ourselves before calling APIs that accept only a raw PSID.
    // SAFETY: MIN_BINARY_SID_BYTES includes the count byte.
    let sub_authority_count = usize::from(unsafe { *actual_sid_bytes.add(1) });
    let declared_sid_length = sub_authority_count
        .checked_mul(size_of::<u32>())
        .and_then(|length| length.checked_add(MIN_BINARY_SID_BYTES))
        .ok_or(StoreError::UnexpectedAccessControlEntry)?;
    if sid_bytes_available != declared_sid_length {
        return Err(StoreError::UnexpectedAccessControlEntry);
    }
    // SAFETY: the SID's self-declared complete length was proven to fit exactly
    // inside the already validated ACE.
    if !unsafe { IsValidSid(actual_sid) }.as_bool() {
        return Err(StoreError::UnexpectedAccessControlEntry);
    }
    // SAFETY: IsValidSid accepted a SID whose full buffer is contained in the
    // ACE. GetLengthSid therefore cannot read outside the descriptor.
    let actual_sid_length = usize::try_from(unsafe { GetLengthSid(actual_sid) })
        .map_err(|_| StoreError::UnexpectedAccessControlEntry)?;
    if actual_sid_length != declared_sid_length {
        return Err(StoreError::UnexpectedAccessControlEntry);
    }
    // SAFETY: both SIDs are valid and live for the comparison.
    unsafe { EqualSid(actual_sid, expected_sid.as_psid()) }
        .map_err(|_| StoreError::WrongStoragePrincipal)
}

fn current_stable_user_sid() -> Result<StableUserSid, StoreError> {
    let mut token = HANDLE::default();
    // SAFETY: query-only token handle output is valid.
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token)
            .map_err(|_| StoreError::DurabilityFailure)?;
    }
    let token = OwnedHandle(token);
    let mut needed = 0_u32;
    // SAFETY: the first call intentionally queries the required TokenUser size.
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &raw mut needed) };
    if needed < u32::try_from(size_of::<TOKEN_USER>()).unwrap_or(u32::MAX) {
        return Err(StoreError::DurabilityFailure);
    }
    let word_size = size_of::<usize>();
    let word_count = usize::try_from(needed)
        .map_err(|_| StoreError::DurabilityFailure)?
        .checked_add(word_size - 1)
        .and_then(|rounded| rounded.checked_div(word_size))
        .ok_or(StoreError::DurabilityFailure)?;
    let mut buffer = vec![0_usize; word_count];
    // SAFETY: the aligned output buffer is writable for exactly `needed` bytes.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            needed,
            &raw mut needed,
        )
        .map_err(|_| StoreError::DurabilityFailure)?;
    }
    let token_user = buffer.as_ptr().cast::<TOKEN_USER>();
    // SAFETY: Windows initialized the complete TOKEN_USER record in the buffer.
    let sid = unsafe { (*token_user).User.Sid };
    copy_sid(sid).map(StableUserSid)
}

#[cfg(test)]
fn current_logon_sid() -> Result<Vec<u8>, StoreError> {
    let mut token = HANDLE::default();
    // SAFETY: query-only token handle output is valid.
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token)
            .map_err(|_| StoreError::DurabilityFailure)?;
    }
    let token = OwnedHandle(token);
    let mut needed = 0_u32;
    // SAFETY: first call intentionally queries required size.
    let _ = unsafe { GetTokenInformation(token.0, TokenGroups, None, 0, &raw mut needed) };
    if needed < u32::try_from(size_of::<TOKEN_GROUPS>()).unwrap_or(u32::MAX) {
        return Err(StoreError::DurabilityFailure);
    }
    let word_size = size_of::<usize>();
    let word_count = usize::try_from(needed)
        .map_err(|_| StoreError::DurabilityFailure)?
        .checked_add(word_size - 1)
        .and_then(|rounded| rounded.checked_div(word_size))
        .ok_or(StoreError::DurabilityFailure)?;
    let mut buffer = vec![0_usize; word_count];
    // SAFETY: aligned output buffer is writable for `needed` bytes.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenGroups,
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            needed,
            &raw mut needed,
        )
        .map_err(|_| StoreError::DurabilityFailure)?;
    }
    let groups_ptr = buffer.as_ptr().cast::<TOKEN_GROUPS>();
    // SAFETY: Windows initialized the TOKEN_GROUPS header.
    let count = usize::try_from(unsafe { (*groups_ptr).GroupCount })
        .map_err(|_| StoreError::DurabilityFailure)?;
    let required = count
        .checked_mul(size_of::<SID_AND_ATTRIBUTES>())
        .and_then(|bytes| bytes.checked_add(core::mem::offset_of!(TOKEN_GROUPS, Groups)))
        .ok_or(StoreError::DurabilityFailure)?;
    if required > usize::try_from(needed).map_err(|_| StoreError::DurabilityFailure)? {
        return Err(StoreError::DurabilityFailure);
    }
    // SAFETY: count was bounded by the initialized output size.
    let groups = unsafe {
        core::slice::from_raw_parts(
            ptr::addr_of!((*groups_ptr).Groups).cast::<SID_AND_ATTRIBUTES>(),
            count,
        )
    };
    let logon_flag = u32::from_ne_bytes(SE_GROUP_LOGON_ID.to_ne_bytes());
    let sid = groups
        .iter()
        .find(|group| group.Attributes & logon_flag == logon_flag)
        .ok_or(StoreError::DurabilityFailure)?
        .Sid;
    copy_sid(sid)
}

fn copy_sid(sid: PSID) -> Result<Vec<u8>, StoreError> {
    // SAFETY: callers supply a non-owning SID pointer from a live token buffer.
    // Validation occurs before reading its declared length.
    if sid.0.is_null() || !unsafe { IsValidSid(sid) }.as_bool() {
        return Err(StoreError::DurabilityFailure);
    }
    // SAFETY: SID pointer remains owned by its token-info buffer for this call.
    let length =
        usize::try_from(unsafe { GetLengthSid(sid) }).map_err(|_| StoreError::DurabilityFailure)?;
    if length == 0 || length > 256 {
        return Err(StoreError::DurabilityFailure);
    }
    let mut copy = vec![0_u8; length];
    // SAFETY: Windows reported `length` bytes for this SID and destination owns
    // exactly that writable allocation.
    unsafe {
        ptr::copy_nonoverlapping(sid.0.cast::<u8>(), copy.as_mut_ptr(), length);
    }
    Ok(copy)
}

fn sid_to_string(sid: PSID) -> Result<String, StoreError> {
    let mut text = PWSTR::null();
    // SAFETY: the SID copy is valid; output is released with LocalFree.
    unsafe {
        ConvertSidToStringSidW(sid, &raw mut text).map_err(|_| StoreError::DurabilityFailure)?;
    }
    // SAFETY: success guarantees a NUL-terminated allocation.
    let result = unsafe { text.to_string() }.map_err(|_| StoreError::DurabilityFailure);
    // SAFETY: conversion allocated with LocalAlloc.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(text.0.cast::<c_void>())));
    }
    result
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: handle is owned exactly once by this wrapper.
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

fn is_not_found(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error().map(|code| u32::from_ne_bytes(code.to_ne_bytes())),
        Some(code) if code == ERROR_FILE_NOT_FOUND.0 || code == ERROR_PATH_NOT_FOUND.0
    )
}

fn wide_path(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    path.as_os_str()
        .encode_wide()
        .chain(core::iter::once(0))
        .collect()
}

fn wide_nul(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(core::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact_allow_ace(sid: &str) -> String {
        format!("(A;;0x{:08x};;;{sid})", FILE_ALL_ACCESS.0)
    }

    #[test]
    fn persistent_descriptor_uses_stable_token_user_not_logon_sid() -> Result<(), StoreError> {
        let stable_user = current_stable_user_sid()?;
        let logon_sid = StableUserSid(current_logon_sid()?);
        assert_ne!(stable_user.as_bytes(), logon_sid.as_bytes());

        let descriptor = SecurityDescriptor::for_stable_user(stable_user.clone())?;
        descriptor.inspect_for_test(&stable_user)?;
        assert_eq!(
            descriptor.inspect_for_test(&logon_sid),
            Err(StoreError::WrongStoragePrincipal)
        );
        Ok(())
    }

    #[test]
    fn persistent_descriptor_survives_simulated_logon_sid_change() -> Result<(), StoreError> {
        let stable_user = current_stable_user_sid()?;
        let first_logon = current_logon_sid()?;
        let mut second_logon = first_logon.clone();
        let final_byte = second_logon
            .last_mut()
            .ok_or(StoreError::DurabilityFailure)?;
        *final_byte ^= 1;
        assert_ne!(first_logon, second_logon);
        assert_ne!(stable_user.as_bytes(), first_logon);
        assert_ne!(stable_user.as_bytes(), second_logon);

        let descriptor = SecurityDescriptor::for_stable_user(stable_user.clone())?;
        for simulated_logon in [&first_logon, &second_logon] {
            assert_ne!(stable_user.as_bytes(), simulated_logon.as_slice());
            descriptor.inspect_for_test(&stable_user)?;
        }
        Ok(())
    }

    #[test]
    fn generated_descriptor_has_exact_owner_and_single_full_control_ace() -> Result<(), StoreError>
    {
        let stable_user = current_stable_user_sid()?;
        let descriptor = SecurityDescriptor::for_stable_user(stable_user.clone())?;
        descriptor.inspect_for_test(&stable_user)
    }

    #[test]
    fn descriptor_rejects_other_owner_or_access_principal() -> Result<(), StoreError> {
        let stable_user = current_stable_user_sid()?;
        let stable_text = sid_to_string(stable_user.as_psid())?;
        let expected_ace = exact_allow_ace(&stable_text);

        let wrong_owner =
            SecurityDescriptor::from_sddl(stable_user.clone(), &format!("O:SYD:P{expected_ace}"))?;
        assert_eq!(
            wrong_owner.inspect_for_test(&stable_user),
            Err(StoreError::WrongStoragePrincipal)
        );

        let wrong_access = SecurityDescriptor::from_sddl(
            stable_user.clone(),
            &format!("O:{stable_text}D:P{}", exact_allow_ace("WD")),
        )?;
        assert_eq!(
            wrong_access.inspect_for_test(&stable_user),
            Err(StoreError::WrongStoragePrincipal)
        );
        Ok(())
    }

    #[test]
    fn descriptor_rejects_any_extra_writable_or_noncanonical_ace() -> Result<(), StoreError> {
        let stable_user = current_stable_user_sid()?;
        let stable_text = sid_to_string(stable_user.as_psid())?;
        let expected_ace = exact_allow_ace(&stable_text);

        let writable_everyone = SecurityDescriptor::from_sddl(
            stable_user.clone(),
            &format!("O:{stable_text}D:P{expected_ace}(A;;GW;;;WD)"),
        )?;
        assert_eq!(
            writable_everyone.inspect_for_test(&stable_user),
            Err(StoreError::UnexpectedAccessControlEntry)
        );

        let deny_ace = SecurityDescriptor::from_sddl(
            stable_user.clone(),
            &format!(
                "O:{stable_text}D:P(D;;0x{:08x};;;{stable_text})",
                FILE_ALL_ACCESS.0
            ),
        )?;
        assert_eq!(
            deny_ace.inspect_for_test(&stable_user),
            Err(StoreError::UnexpectedAccessControlEntry)
        );

        let inherited_ace = SecurityDescriptor::from_sddl(
            stable_user.clone(),
            &format!(
                "O:{stable_text}D:P(A;ID;0x{:08x};;;{stable_text})",
                FILE_ALL_ACCESS.0
            ),
        )?;
        assert_eq!(
            inherited_ace.inspect_for_test(&stable_user),
            Err(StoreError::UnexpectedAccessControlEntry)
        );

        let inheritable_ace = SecurityDescriptor::from_sddl(
            stable_user.clone(),
            &format!(
                "O:{stable_text}D:P(A;CI;0x{:08x};;;{stable_text})",
                FILE_ALL_ACCESS.0
            ),
        )?;
        assert_eq!(
            inheritable_ace.inspect_for_test(&stable_user),
            Err(StoreError::UnexpectedAccessControlEntry)
        );

        let partial_rights = SecurityDescriptor::from_sddl(
            stable_user.clone(),
            &format!("O:{stable_text}D:P(A;;GR;;;{stable_text})"),
        )?;
        assert_eq!(
            partial_rights.inspect_for_test(&stable_user),
            Err(StoreError::UnexpectedAccessControlEntry)
        );

        let empty_dacl =
            SecurityDescriptor::from_sddl(stable_user.clone(), &format!("O:{stable_text}D:P"))?;
        assert_eq!(
            empty_dacl.inspect_for_test(&stable_user),
            Err(StoreError::UnexpectedAccessControlEntry)
        );

        let unprotected = SecurityDescriptor::from_sddl(
            stable_user.clone(),
            &format!("O:{stable_text}D:{expected_ace}"),
        )?;
        assert_eq!(
            unprotected.inspect_for_test(&stable_user),
            Err(StoreError::UnprotectedDacl)
        );
        Ok(())
    }

    #[test]
    fn descriptor_rejects_defaulted_control_bits_and_noncanonical_acl_layouts()
    -> Result<(), StoreError> {
        let stable_user = current_stable_user_sid()?;
        let forbidden_control_flags = [
            u16::from_ne_bytes(SE_DACL_DEFAULTED.0.to_ne_bytes()),
            u16::from_ne_bytes(SE_OWNER_DEFAULTED.0.to_ne_bytes()),
            u16::from_ne_bytes(SE_DACL_AUTO_INHERITED.0.to_ne_bytes()),
            u16::from_ne_bytes(SE_DACL_AUTO_INHERIT_REQ.0.to_ne_bytes()),
        ];
        for flag in forbidden_control_flags {
            let descriptor = SecurityDescriptor::for_stable_user(stable_user.clone())?;
            let (owner, dacl) = descriptor.parts_for_test()?;
            let relative = descriptor
                .descriptor
                .0
                .cast::<SECURITY_DESCRIPTOR_RELATIVE>();
            // SAFETY: SDDL conversion returned a live self-relative descriptor;
            // the test changes only its initialized control word.
            unsafe {
                (*relative).Control.0 |= flag;
            }
            assert_eq!(
                inspect_security_descriptor(descriptor.descriptor, owner, dacl, &stable_user),
                Err(StoreError::InsecurePermissions)
            );
        }

        let noncanonical_revision = SecurityDescriptor::for_stable_user(stable_user.clone())?;
        let (owner, dacl) = noncanonical_revision.parts_for_test()?;
        // SAFETY: `dacl` points into the live descriptor and its ACL header was
        // returned by the descriptor query above.
        unsafe {
            (*dacl).AclRevision = u8::try_from(ACL_REVISION.0.saturating_add(2)).unwrap_or(u8::MAX);
        }
        assert_eq!(
            inspect_security_descriptor(
                noncanonical_revision.descriptor,
                owner,
                dacl,
                &stable_user,
            ),
            Err(StoreError::UnexpectedAccessControlEntry)
        );

        let malformed_acl = SecurityDescriptor::for_stable_user(stable_user.clone())?;
        let (owner, dacl) = malformed_acl.parts_for_test()?;
        // SAFETY: `dacl` points into the live descriptor. Setting an impossible
        // revision makes `IsValidAcl` reject it before any ACE cast is reached.
        unsafe {
            (*dacl).AclRevision = 0;
        }
        assert_eq!(
            inspect_security_descriptor(malformed_acl.descriptor, owner, dacl, &stable_user),
            Err(StoreError::InsecurePermissions)
        );

        let malformed_sid_shape = SecurityDescriptor::for_stable_user(stable_user.clone())?;
        let (owner, dacl) = malformed_sid_shape.parts_for_test()?;
        let mut ace = ptr::null_mut::<c_void>();
        // SAFETY: the generated ACL is valid and contains exactly one ACE.
        unsafe {
            GetAce(dacl, 0, &raw mut ace).map_err(|_| StoreError::InsecurePermissions)?;
        }
        if ace.is_null() {
            return Err(StoreError::InsecurePermissions);
        }
        // SAFETY: the generated descriptor contains the standard access-allowed
        // ACE validated by earlier tests. The count byte is inside its SID.
        unsafe {
            let allowed = &mut *ace.cast::<ACCESS_ALLOWED_ACE>();
            let sid = ptr::addr_of_mut!(allowed.SidStart).cast::<u8>();
            *sid.add(1) = 0;
        }
        assert_eq!(
            inspect_security_descriptor(malformed_sid_shape.descriptor, owner, dacl, &stable_user,),
            Err(StoreError::UnexpectedAccessControlEntry)
        );
        Ok(())
    }

    #[test]
    fn descriptor_rejects_object_and_callback_ace_layouts() -> Result<(), StoreError> {
        let stable_user = current_stable_user_sid()?;
        let stable_text = sid_to_string(stable_user.as_psid())?;
        let object_ace = SecurityDescriptor::from_sddl(
            stable_user.clone(),
            &format!(
                "O:{stable_text}D:P(OA;;0x{:08x};00112233-4455-6677-8899-aabbccddeeff;;{stable_text})",
                FILE_ALL_ACCESS.0
            ),
        )?;
        assert_eq!(
            object_ace.inspect_for_test(&stable_user),
            Err(StoreError::UnexpectedAccessControlEntry)
        );

        let callback = SecurityDescriptor::from_sddl(
            stable_user.clone(),
            &format!(
                "O:{stable_text}D:P(XA;;0x{:08x};;;{stable_text};(@User.Title == \"wallet-test\"))",
                FILE_ALL_ACCESS.0
            ),
        )?;
        assert_eq!(
            callback.inspect_for_test(&stable_user),
            Err(StoreError::UnexpectedAccessControlEntry)
        );
        Ok(())
    }

    #[test]
    fn filesystem_allowlist_is_exact_ntfs_only_and_case_insensitive() {
        fn encoded(name: &str) -> Vec<u16> {
            name.encode_utf16().chain(core::iter::once(0)).collect()
        }

        for allowed in ["NTFS", "ntfs"] {
            assert!(is_allowed_filesystem_name(&encoded(allowed)));
        }
        for denied in [
            "ReFS", "refs", "FAT32", "exFAT", "CsvFS", "NTFS ", "ReFS2", "",
        ] {
            assert!(!is_allowed_filesystem_name(&encoded(denied)));
        }
        assert!(!is_allowed_filesystem_name(&[
            u16::from(b'N'),
            u16::from(b'T'),
            u16::from(b'F'),
            u16::from(b'S'),
        ]));
        assert!(!is_allowed_filesystem_name(&[
            u16::from(b'N'),
            u16::from(b'T'),
            u16::from(b'F'),
            u16::from(b'S'),
            0,
            u16::from(b'X'),
        ]));
    }

    #[test]
    fn volume_policy_rejects_every_nonfixed_remote_or_nonpersistent_shape() {
        fn encoded(name: &str) -> Vec<u16> {
            name.encode_utf16().chain(core::iter::once(0)).collect()
        }

        assert_eq!(
            validate_volume_characteristics(
                DRIVE_FIXED,
                false,
                FILE_PERSISTENT_ACLS,
                &encoded("NTFS"),
            ),
            Ok(())
        );
        for denied_drive in [
            DRIVE_UNKNOWN,
            DRIVE_NO_ROOT_DIR,
            DRIVE_REMOVABLE,
            DRIVE_REMOTE,
            DRIVE_CDROM,
            DRIVE_RAMDISK,
        ] {
            assert_eq!(
                validate_volume_characteristics(
                    denied_drive,
                    false,
                    FILE_PERSISTENT_ACLS,
                    &encoded("NTFS"),
                ),
                Err(StoreError::UnsafePath)
            );
        }
        assert_eq!(
            validate_volume_characteristics(
                DRIVE_FIXED,
                true,
                FILE_PERSISTENT_ACLS,
                &encoded("NTFS"),
            ),
            Err(StoreError::UnsafePath)
        );
        assert_eq!(
            validate_volume_characteristics(DRIVE_FIXED, false, 0, &encoded("NTFS")),
            Err(StoreError::UnsafePath)
        );
        for unsupported in ["ReFS", "FAT32", "exFAT", "CsvFS", "UDF", "unknown"] {
            assert_eq!(
                validate_volume_characteristics(
                    DRIVE_FIXED,
                    false,
                    FILE_PERSISTENT_ACLS,
                    &encoded(unsupported),
                ),
                Err(StoreError::UnsafePath)
            );
        }
    }

    #[test]
    fn local_path_policy_rejects_unc_device_relative_and_parent_traversal() {
        for allowed in [r"C:\wallet\vault", r"\\?\C:\wallet\vault"] {
            assert_eq!(validate_absolute_local_path(Path::new(allowed)), Ok(()));
        }
        for denied in [
            r"wallet\vault",
            r"\wallet\vault",
            r"C:wallet\vault",
            "C:\\wallet\0vault",
            r"C:\wallet\..\vault",
            r"\\server\share\wallet",
            r"\\?\UNC\server\share\wallet",
            r"\\.\C:\wallet",
        ] {
            assert_eq!(
                validate_absolute_local_path(Path::new(denied)),
                Err(StoreError::UnsafePath)
            );
        }
    }

    #[test]
    fn held_handle_volume_guid_parser_rejects_dos_unc_and_malformed_paths() {
        for malformed_guid in [
            r"\\?\Volume{00000000-0000-0000-0000-00000000000g}\wallet",
            r"\\?\Volume{000000000-000-0000-0000-000000000000}\wallet",
        ] {
            assert_eq!(
                volume_guid_root_from_final_path(
                    &malformed_guid.encode_utf16().collect::<Vec<_>>(),
                ),
                Err(StoreError::UnsafePath)
            );
        }

        let canonical = "\\\\?\\Volume{00112233-4455-6677-8899-aabbccddeeff}\\wallet\\vault"
            .encode_utf16()
            .collect::<Vec<_>>();
        assert_eq!(
            volume_guid_root_from_final_path(&canonical),
            Ok("\\\\?\\Volume{00112233-4455-6677-8899-aabbccddeeff}\\\0"
                .encode_utf16()
                .collect())
        );

        for denied in [
            r"\\?\D:\wallet\vault",
            r"\\server\share\wallet\vault",
            r"\\?\Volume{00112233-4455-6677-8899-aabbccddeeff}vault",
            r"\\?\Volume{00112233-4455-6677-8899-aabbccddeeff",
        ] {
            assert_eq!(
                volume_guid_root_from_final_path(&denied.encode_utf16().collect::<Vec<_>>()),
                Err(StoreError::UnsafePath)
            );
        }
    }

    #[test]
    fn held_file_readback_binds_bytes_digest_identity_and_acl()
    -> Result<(), Box<dyn std::error::Error>> {
        use core::fmt::Write as _;

        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_| StoreError::DurabilityFailure)?;
        let mut suffix = String::with_capacity(random.len() * 2);
        for byte in random {
            write!(&mut suffix, "{byte:02x}").map_err(|_| StoreError::DurabilityFailure)?;
        }
        let root = std::env::temp_dir().join(format!("your-wallet-readback-test-{suffix}"));
        let descriptor = SecurityDescriptor::current_user_only()?;
        create_root_if_missing(&root, &descriptor)?;
        let root_handle = open_directory(&root)?;
        verify_not_reparse(&root_handle)?;
        verify_stable_user_security(&root_handle, &descriptor.stable_user_sid)?;
        verify_supported_local_volume(&root_handle)?;
        let root_identity = file_identity(&root_handle)?;

        let path = root.join("candidate.new");
        let expected = b"authenticated readback bytes";
        let mut writer = create_new_write_through(&path, &descriptor)?;
        let expected_identity = file_identity(&writer)?;
        writer.write_all(expected)?;
        flush_file(&writer)?;
        drop(writer);

        let installed = open_existing_file(&path)?;
        verify_installed_readback(
            &installed,
            expected_identity,
            root_identity.volume_serial,
            expected,
            sha256(expected),
            &descriptor.stable_user_sid,
        )?;
        drop(installed);

        let wrong_bytes = b"authenticated readback byte!";
        let installed = open_existing_file(&path)?;
        assert_eq!(
            verify_installed_readback(
                &installed,
                expected_identity,
                root_identity.volume_serial,
                wrong_bytes,
                sha256(wrong_bytes),
                &descriptor.stable_user_sid,
            ),
            Err(StoreError::DurabilityFailure)
        );
        drop(installed);

        let installed = open_existing_file(&path)?;
        let mut wrong_digest = sha256(expected);
        wrong_digest[0] ^= 1;
        assert_eq!(
            verify_installed_readback(
                &installed,
                expected_identity,
                root_identity.volume_serial,
                expected,
                wrong_digest,
                &descriptor.stable_user_sid,
            ),
            Err(StoreError::DurabilityFailure)
        );
        drop(installed);

        let installed = open_existing_file(&path)?;
        let mut wrong_identity = expected_identity;
        wrong_identity.file_index ^= 1;
        assert_eq!(
            verify_installed_readback(
                &installed,
                wrong_identity,
                root_identity.volume_serial,
                expected,
                sha256(expected),
                &descriptor.stable_user_sid,
            ),
            Err(StoreError::UnsafePath)
        );
        drop(installed);
        drop(root_handle);

        let temporary_parent = std::env::temp_dir();
        let safe_name = root
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("your-wallet-readback-test-"));
        if !root.starts_with(&temporary_parent) || !safe_name {
            return Err(StoreError::UnsafePath.into());
        }
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
