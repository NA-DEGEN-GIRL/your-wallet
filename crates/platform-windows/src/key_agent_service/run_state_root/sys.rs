//! Windows kernel adapter for fixed, installer-created service run state.

#![allow(unsafe_code)]

use core::ffi::c_void;
use core::fmt;
use core::mem::{offset_of, size_of, size_of_val};
use core::ptr;
#[cfg(test)]
use std::cell::{Cell, RefCell};
use std::os::windows::ffi::OsStrExt as _;
use std::path::{Component, Path, PathBuf, Prefix};
use std::sync::atomic::{AtomicBool, Ordering};

use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Wdk::Storage::FileSystem::{
    FILE_ACCESS_INFORMATION, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
    FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, FileAccessInformation, NtCreateFile,
    NtQueryInformationFile,
};
#[cfg(test)]
use windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_LOCK_VIOLATION, ERROR_NO_TOKEN, ERROR_SUCCESS, GENERIC_READ,
    GetHandleInformation, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree, OBJ_CASE_INSENSITIVE,
    OBJ_DONT_REPARSE, STATUS_FILE_IS_A_DIRECTORY, STATUS_NOT_A_DIRECTORY,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND, STATUS_REPARSE_POINT_ENCOUNTERED,
    STATUS_SHARING_VIOLATION, STATUS_SUCCESS, UNICODE_STRING,
};
#[cfg(test)]
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE, ACE_HEADER, ACL, ACL_REVISION, ACL_SIZE_INFORMATION,
    AclSizeInformation, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
    GetLengthSid, GetSecurityDescriptorControl, IsValidAcl, IsValidSecurityDescriptor, IsValidSid,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_AUTO_INHERIT_REQ,
    SE_DACL_DEFAULTED, SE_DACL_PRESENT, SE_DACL_PROTECTED, SE_OWNER_DEFAULTED, SE_SELF_RELATIVE,
    TOKEN_QUERY, WinCreatorOwnerRightsSid, WinLocalSystemSid,
};
#[cfg(test)]
use windows::Win32::Security::{
    CopySid, CreateWellKnownSid, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    GetTokenInformation, ImpersonateSelf, RevertToSelf, SecurityImpersonation, TOKEN_USER,
    TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, DELETE, FILE_ACCESS_RIGHTS, FILE_ADD_FILE,
    FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_GENERIC_READ, FILE_ID_INFO, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES,
    FILE_REMOTE_PROTOCOL_INFO, FILE_SHARE_DELETE, FILE_SHARE_MODE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_TRAVERSE, FileIdInfo, FileRemoteProtocolInfo, GetDriveTypeW,
    GetFileInformationByHandle, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
    GetVolumeInformationByHandleW, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
    OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE, UnlockFileEx, VOLUME_NAME_GUID, WRITE_DAC,
    WRITE_OWNER,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::IO::{IO_STATUS_BLOCK, OVERLAPPED};
use windows::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, FILE_PERSISTENT_ACLS,
};
#[cfg(test)]
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
use windows::Win32::System::WindowsProgramming::{DRIVE_FIXED, FILE_OPENED};
use windows::Win32::UI::Shell::{FOLDERID_ProgramData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};
#[cfg(test)]
use windows::core::BOOL;
use windows::core::{PCWSTR, PWSTR};

use super::ServiceRunStateError;

const PRODUCT_LEAVES: [&str; 3] = ["YourWallet", "KeyAgent", "v1"];
const RUN_LOCK_LEAF: &str = "run.lock";
const STATE_LEAF: &str = "state";
const FILESYSTEM_NAME_UTF16: usize = 32;
const MAX_FINAL_PATH_UTF16: usize = 32_768;
const MIN_BINARY_SID_BYTES: usize = 8;
const MAX_BINARY_SID_BYTES: usize = 68;
#[cfg(test)]
const MAX_TEST_TOKEN_INFORMATION_BYTES: usize = 1_024;

const ROOT_ACCESS: u32 = READ_CONTROL.0
    | SYNCHRONIZE.0
    | FILE_LIST_DIRECTORY.0
    | FILE_TRAVERSE.0
    | FILE_READ_ATTRIBUTES.0;
const LOCK_OPEN_ACCESS: u32 = GENERIC_READ.0 | SYNCHRONIZE.0;
const LOCK_ACCESS: u32 = FILE_GENERIC_READ.0;
const STATE_ACCESS: u32 = ROOT_ACCESS | FILE_ADD_FILE.0;
const PARENT_ACCESS: u32 =
    SYNCHRONIZE.0 | FILE_LIST_DIRECTORY.0 | FILE_TRAVERSE.0 | FILE_READ_ATTRIBUTES.0;
const OWNER_RIGHTS_DENY: u32 = WRITE_DAC.0 | WRITE_OWNER.0 | DELETE.0 | FILE_DELETE_CHILD.0;

#[cfg(test)]
pub(super) const ROOT_ACCESS_FOR_TEST: u32 = ROOT_ACCESS;
#[cfg(test)]
pub(super) const LOCK_ACCESS_FOR_TEST: u32 = LOCK_ACCESS;
#[cfg(test)]
pub(super) const STATE_ACCESS_FOR_TEST: u32 = STATE_ACCESS;
#[cfg(test)]
pub(super) const OWNER_RIGHTS_DENY_FOR_TEST: u32 = OWNER_RIGHTS_DENY;

#[cfg(test)]
std::thread_local! {
    static TEST_OPEN_COUNT: Cell<usize> = const { Cell::new(0) };
    static TEST_RELEASE_TRACE: RefCell<Vec<TestReleaseStep>> = const { RefCell::new(Vec::new()) };
    static TEST_CLOSE_FAULT: Cell<Option<HandleRole>> = const { Cell::new(None) };
    static TEST_UNLOCK_FAULT: Cell<bool> = const { Cell::new(false) };
    static TEST_STATE_NATIVE_OPEN_COUNT: Cell<usize> = const { Cell::new(0) };
    static TEST_STATE_OPEN_IMPERSONATION_FAULT: Cell<Option<TestStateOpenImpersonationFault>> = const { Cell::new(None) };
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TestReleaseStep {
    WriterRevalidated,
    StateClosed,
    RangeUnlocked,
    LockClosed,
    RootRevalidatedAfterLock,
    RootClosed,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TestCloseFault {
    State,
    Lock,
    Root,
    RevalidationRoot,
    RevalidationState,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TestStateOpenImpersonationFault {
    BeforeNativeOpen,
    AfterNativeOpen,
}

/// Full, non-sentinel Windows file identity recorded by the installer.
#[derive(Clone, Copy, Eq, PartialEq)]
struct ObjectIdentity {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

impl ObjectIdentity {
    fn from_handle(handle: HANDLE) -> Result<Self, ServiceRunStateError> {
        let mut information = FILE_ID_INFO::default();
        // SAFETY: `handle` is held by the caller and the output has the exact
        // documented representation and writable length.
        unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileIdInfo,
                ptr::from_mut(&mut information).cast::<c_void>(),
                u32::try_from(size_of_val(&information))
                    .map_err(|_| ServiceRunStateError::Identity)?,
            )
        }
        .map_err(|_| ServiceRunStateError::Identity)?;
        if information.VolumeSerialNumber == 0
            || information.FileId.Identifier == [0; 16]
            || information.FileId.Identifier == [u8::MAX; 16]
        {
            return Err(ServiceRunStateError::Identity);
        }
        Ok(Self {
            volume_serial_number: information.VolumeSerialNumber,
            file_id: information.FileId.Identifier,
        })
    }
}

impl fmt::Debug for ObjectIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ObjectIdentity([REDACTED])")
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct TestObjectIdentity(ObjectIdentity);

#[cfg(test)]
impl fmt::Debug for TestObjectIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TestObjectIdentity([REDACTED])")
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TestSidMatch {
    OwnerRights,
    Service,
    System,
    Other,
    Invalid,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TestAceDiagnostic {
    pub(super) ace_type: u8,
    pub(super) flags: u8,
    pub(super) size: u16,
    pub(super) mask: u32,
    pub(super) sid_match: TestSidMatch,
}

#[cfg(test)]
#[derive(Debug, Eq, PartialEq)]
pub(super) struct TestSecurityDiagnostic {
    pub(super) control: u16,
    pub(super) descriptor_revision: u32,
    pub(super) owner_matches_service: bool,
    pub(super) acl_valid: bool,
    pub(super) acl_revision: u8,
    pub(super) acl_size: u16,
    pub(super) ace_count: u32,
    pub(super) bytes_in_use: u32,
    pub(super) bytes_free: u32,
    pub(super) aces: Vec<TestAceDiagnostic>,
}

/// Aligned, canonical copy of one expected SID.
struct OwnedSid {
    words: Box<[usize]>,
    byte_len: usize,
}

impl OwnedSid {
    fn as_psid(&self) -> PSID {
        PSID(self.words.as_ptr().cast_mut().cast::<c_void>())
    }

    fn validate(&self) -> Result<(), ServiceRunStateError> {
        if !(MIN_BINARY_SID_BYTES..=MAX_BINARY_SID_BYTES).contains(&self.byte_len)
            || self.byte_len > size_of_val(&*self.words)
        {
            return Err(ServiceRunStateError::Security);
        }
        let sid = self.as_psid();
        // SAFETY: construction owns native-aligned storage for `byte_len`.
        let valid = unsafe { IsValidSid(sid) }.as_bool();
        // SAFETY: a valid SID has a readable self-declared length.
        let byte_len = unsafe { GetLengthSid(sid) };
        if !valid
            || usize::try_from(byte_len).map_err(|_| ServiceRunStateError::Security)?
                != self.byte_len
        {
            return Err(ServiceRunStateError::Security);
        }
        Ok(())
    }

    #[cfg(test)]
    unsafe fn copy_from(sid: PSID) -> Result<Self, ServiceRunStateError> {
        // SAFETY: caller supplies a live readable SID for the duration of copy.
        if sid.0.is_null() || !unsafe { IsValidSid(sid) }.as_bool() {
            return Err(ServiceRunStateError::Security);
        }
        // SAFETY: IsValidSid accepted the complete input SID.
        let length = usize::try_from(unsafe { GetLengthSid(sid) })
            .map_err(|_| ServiceRunStateError::Security)?;
        if !(MIN_BINARY_SID_BYTES..=MAX_BINARY_SID_BYTES).contains(&length) {
            return Err(ServiceRunStateError::Security);
        }
        let word_size = size_of::<usize>();
        let words = length
            .checked_add(word_size - 1)
            .and_then(|value| value.checked_div(word_size))
            .ok_or(ServiceRunStateError::Security)?;
        let mut storage = vec![0_usize; words].into_boxed_slice();
        // SAFETY: the aligned destination owns at least `length` bytes and the
        // source was validated for exactly that many readable bytes.
        unsafe {
            CopySid(
                u32::try_from(length).map_err(|_| ServiceRunStateError::Security)?,
                PSID(storage.as_mut_ptr().cast::<c_void>()),
                sid,
            )
        }
        .map_err(|_| ServiceRunStateError::Security)?;
        Ok(Self {
            words: storage,
            byte_len: length,
        })
    }

    #[cfg(test)]
    fn well_known(
        kind: windows::Win32::Security::WELL_KNOWN_SID_TYPE,
    ) -> Result<Self, ServiceRunStateError> {
        let mut bytes =
            u32::try_from(MAX_BINARY_SID_BYTES).map_err(|_| ServiceRunStateError::Security)?;
        let words = MAX_BINARY_SID_BYTES
            .checked_add(size_of::<usize>() - 1)
            .and_then(|value| value.checked_div(size_of::<usize>()))
            .ok_or(ServiceRunStateError::Security)?;
        let mut storage = vec![0_usize; words].into_boxed_slice();
        // SAFETY: the aligned output owns the advertised writable capacity.
        unsafe {
            CreateWellKnownSid(
                kind,
                None,
                Some(PSID(storage.as_mut_ptr().cast::<c_void>())),
                &raw mut bytes,
            )
        }
        .map_err(|_| ServiceRunStateError::Security)?;
        let byte_len = usize::try_from(bytes).map_err(|_| ServiceRunStateError::Security)?;
        let sid = Self {
            words: storage,
            byte_len,
        };
        sid.validate()?;
        Ok(sid)
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

struct SecurityPolicy {
    service_sid: OwnedSid,
    system_sid: OwnedSid,
}

impl SecurityPolicy {
    fn validate(&self) -> Result<(), ServiceRunStateError> {
        self.service_sid.validate()?;
        self.system_sid.validate()?;
        // SAFETY: both SIDs are canonical and remain owned by `self`.
        let same_sid =
            unsafe { EqualSid(self.service_sid.as_psid(), self.system_sid.as_psid()) }.is_ok();
        // SAFETY: the owned canonical system SID remains readable.
        let system_is_local_system = unsafe {
            windows::Win32::Security::IsWellKnownSid(self.system_sid.as_psid(), WinLocalSystemSid)
        }
        .as_bool();
        // SAFETY: the owned canonical service SID remains readable.
        let service_is_owner_rights = unsafe {
            windows::Win32::Security::IsWellKnownSid(
                self.service_sid.as_psid(),
                WinCreatorOwnerRightsSid,
            )
        }
        .as_bool();
        if same_sid || !system_is_local_system || service_is_owner_rights {
            return Err(ServiceRunStateError::Security);
        }
        Ok(())
    }
}

impl fmt::Debug for SecurityPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecurityPolicy([REDACTED])")
    }
}

/// Opaque installer authority. There is intentionally no production mint.
pub(super) struct ExpectedObjects {
    root_identity: ObjectIdentity,
    lock_identity: ObjectIdentity,
    state_identity: ObjectIdentity,
    policy: SecurityPolicy,
}

impl fmt::Debug for ExpectedObjects {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExpectedObjects([REDACTED])")
    }
}

#[cfg(test)]
fn current_user_test_policy() -> Result<SecurityPolicy, ServiceRunStateError> {
    let service_sid = current_user_sid_for_test()?;
    let system_sid = OwnedSid::well_known(WinLocalSystemSid)?;
    let policy = SecurityPolicy {
        service_sid,
        system_sid,
    };
    policy.validate()?;
    Ok(policy)
}

#[cfg(test)]
pub(super) fn exact_sddl_for_test(service_mask: u32) -> Result<String, ServiceRunStateError> {
    let policy = current_user_test_policy()?;
    let service = sid_to_string_for_test(policy.service_sid.as_psid())?;
    Ok(format!(
        "O:{service}D:P(D;;0x{OWNER_RIGHTS_DENY:08x};;;OW)(A;;0x{service_mask:08x};;;{service})(A;;0x{:08x};;;SY)",
        FILE_ALL_ACCESS.0,
    ))
}

#[cfg(test)]
pub(super) fn current_service_sid_string_for_test() -> Result<String, ServiceRunStateError> {
    let policy = current_user_test_policy()?;
    sid_to_string_for_test(policy.service_sid.as_psid())
}

#[cfg(test)]
pub(super) fn expected_objects_for_test(
    root_identity: TestObjectIdentity,
    lock_identity: TestObjectIdentity,
    state_identity: TestObjectIdentity,
) -> Result<ExpectedObjects, ServiceRunStateError> {
    let policy = current_user_test_policy()?;
    Ok(ExpectedObjects {
        root_identity: root_identity.0,
        lock_identity: lock_identity.0,
        state_identity: state_identity.0,
        policy,
    })
}

#[cfg(test)]
pub(super) fn record_object_identity_for_test(
    path: &Path,
    directory: bool,
) -> Result<TestObjectIdentity, ServiceRunStateError> {
    let wide = wide_path(path)?;
    let flags = if directory {
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
    } else {
        FILE_FLAG_OPEN_REPARSE_POINT
    };
    // SAFETY: the test path is NUL-terminated and this opens only an existing
    // fixture object with non-inheritable default security attributes.
    let raw = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
    }
    .map_err(|_| ServiceRunStateError::Identity)?;
    let handle = OwnedHandle::new(raw).map_err(|_| ServiceRunStateError::Identity)?;
    ObjectIdentity::from_handle(handle.raw()).map(TestObjectIdentity)
}

#[cfg(test)]
pub(super) fn verify_object_security_for_test(
    path: &Path,
    directory: bool,
    service_mask: u32,
) -> Result<(), ServiceRunStateError> {
    let wide = wide_path(path)?;
    let flags = if directory {
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
    } else {
        FILE_FLAG_OPEN_REPARSE_POINT
    };
    // SAFETY: this opens only the exact existing test object for READ_CONTROL.
    let raw = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            READ_CONTROL.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
    }
    .map_err(|_| ServiceRunStateError::Security)?;
    let handle = OwnedHandle::new(raw).map_err(|_| ServiceRunStateError::Security)?;
    let policy = current_user_test_policy()?;
    verify_exact_security(handle.raw(), &policy, service_mask)
}

#[cfg(test)]
#[allow(clippy::too_many_lines)] // One path-free snapshot keeps the diagnostic internally consistent.
pub(super) fn diagnose_object_security_for_test(
    path: &Path,
    directory: bool,
) -> Result<TestSecurityDiagnostic, ServiceRunStateError> {
    let wide = wide_path(path)?;
    let flags = if directory {
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
    } else {
        FILE_FLAG_OPEN_REPARSE_POINT
    };
    // SAFETY: this opens only the exact existing fixture for READ_CONTROL.
    let raw = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            READ_CONTROL.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
    }
    .map_err(|_| ServiceRunStateError::Security)?;
    let handle = OwnedHandle::new(raw).map_err(|_| ServiceRunStateError::Security)?;
    let policy = current_user_test_policy()?;
    let mut owner = PSID::default();
    let mut dacl = ptr::null_mut::<ACL>();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: exact writable outputs remain live for this complete query.
    let status = unsafe {
        GetSecurityInfo(
            handle.raw(),
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
        free_descriptor(descriptor);
        return Err(ServiceRunStateError::Security);
    }
    let mut control = 0_u16;
    let mut descriptor_revision = 0_u32;
    // SAFETY: scalar outputs are exact for the live descriptor.
    unsafe {
        GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut descriptor_revision)
    }
    .map_err(|_| ServiceRunStateError::Security)?;
    // SAFETY: pointers lie in the still-live descriptor.
    let owner_matches_service = unsafe { EqualSid(owner, policy.service_sid.as_psid()) }.is_ok();
    // SAFETY: the pointer lies in the still-live descriptor.
    let acl_valid = unsafe { IsValidAcl(dacl) }.as_bool();
    // SAFETY: the fixed ACL header is readable after GetSecurityInfo.
    let acl = unsafe { &*dacl };
    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: output is exact and the ACL remains live.
    unsafe {
        GetAclInformation(
            dacl,
            ptr::from_mut(&mut information).cast::<c_void>(),
            u32::try_from(size_of::<ACL_SIZE_INFORMATION>())
                .map_err(|_| ServiceRunStateError::Security)?,
            AclSizeInformation,
        )
    }
    .map_err(|_| ServiceRunStateError::Security)?;
    let mut aces = Vec::new();
    for index in 0..information.AceCount.min(8) {
        let ace = ace_at(dacl, index)?;
        // SAFETY: GetAce proves the common header is readable.
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        let (mask, sid_bytes, sid_offset) =
            if header.AceType == u8::try_from(ACCESS_ALLOWED_ACE_TYPE).unwrap_or(u8::MAX) {
                // SAFETY: the reported type has the standard fixed allow layout.
                let value = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
                (
                    value.Mask,
                    ptr::addr_of!(value.SidStart).cast::<u8>(),
                    offset_of!(ACCESS_ALLOWED_ACE, SidStart),
                )
            } else if header.AceType == u8::try_from(ACCESS_DENIED_ACE_TYPE).unwrap_or(u8::MAX) {
                // SAFETY: the reported type has the standard fixed deny layout.
                let value = unsafe { &*ace.cast::<ACCESS_DENIED_ACE>() };
                (
                    value.Mask,
                    ptr::addr_of!(value.SidStart).cast::<u8>(),
                    offset_of!(ACCESS_DENIED_ACE, SidStart),
                )
            } else {
                (0, ptr::null(), 0)
            };
        let sid_match =
            sid_in_ace(sid_bytes, header, sid_offset).map_or(TestSidMatch::Invalid, |sid| {
                // SAFETY: sid_in_ace proved a complete canonical SID.
                if unsafe {
                    windows::Win32::Security::IsWellKnownSid(sid, WinCreatorOwnerRightsSid)
                }
                .as_bool()
                {
                    TestSidMatch::OwnerRights
                // SAFETY: both compared SIDs are canonical and live.
                } else if unsafe { EqualSid(sid, policy.service_sid.as_psid()) }.is_ok() {
                    TestSidMatch::Service
                // SAFETY: both compared SIDs are canonical and live.
                } else if unsafe { EqualSid(sid, policy.system_sid.as_psid()) }.is_ok() {
                    TestSidMatch::System
                } else {
                    TestSidMatch::Other
                }
            });
        aces.push(TestAceDiagnostic {
            ace_type: header.AceType,
            flags: header.AceFlags,
            size: header.AceSize,
            mask,
            sid_match,
        });
    }
    let diagnostic = TestSecurityDiagnostic {
        control,
        descriptor_revision,
        owner_matches_service,
        acl_valid,
        acl_revision: acl.AclRevision,
        acl_size: acl.AclSize,
        ace_count: information.AceCount,
        bytes_in_use: information.AclBytesInUse,
        bytes_free: information.AclBytesFree,
        aces,
    };
    free_descriptor(descriptor);
    Ok(diagnostic)
}

#[cfg(test)]
pub(super) fn verify_sddl_for_test(
    sddl: &str,
    service_mask: u32,
) -> Result<(), ServiceRunStateError> {
    let policy = current_user_test_policy()?;
    let wide = wide_nul_for_test(sddl)?;
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the SDDL is NUL-terminated and the output owns one LocalAlloc
    // descriptor until the end of this function.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wide.as_ptr()),
            SDDL_REVISION_1,
            &raw mut descriptor,
            None,
        )
    }
    .map_err(|_| ServiceRunStateError::Security)?;
    if descriptor.0.is_null() {
        return Err(ServiceRunStateError::Security);
    }
    let mut owner = PSID::default();
    let mut owner_defaulted = BOOL(0);
    let mut dacl = ptr::null_mut::<ACL>();
    let mut dacl_present = BOOL(0);
    let mut dacl_defaulted = BOOL(0);
    // SAFETY: all outputs are exact writable storage and the descriptor lives.
    let inspected = unsafe {
        GetSecurityDescriptorOwner(descriptor, &raw mut owner, &raw mut owner_defaulted).and_then(
            |()| {
                GetSecurityDescriptorDacl(
                    descriptor,
                    &raw mut dacl_present,
                    &raw mut dacl,
                    &raw mut dacl_defaulted,
                )
            },
        )
    };
    let result = if inspected.is_err()
        || owner_defaulted.as_bool()
        || !dacl_present.as_bool()
        || dacl_defaulted.as_bool()
        || dacl.is_null()
    {
        Err(ServiceRunStateError::Security)
    } else {
        inspect_security_descriptor(descriptor, owner, dacl, &policy, service_mask)
    };
    free_descriptor(descriptor);
    result
}

struct Location {
    base_path: PathBuf,
}

impl Location {
    fn fixed() -> Result<Self, ServiceRunStateError> {
        Ok(Self {
            base_path: fixed_program_data_path()?,
        })
    }

    #[cfg(test)]
    fn test(base_path: PathBuf) -> Self {
        Self { base_path }
    }
}

impl fmt::Debug for Location {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Location([REDACTED FIXED ROOT])")
    }
}

/// Held fixed root. Its root handle never grants delete sharing.
pub(super) struct HeldRoot {
    handle: OwnedHandle,
    expected: ExpectedObjects,
    location: Location,
    revalidation_close_ambiguous: AtomicBool,
}

impl HeldRoot {
    pub(super) fn open_fixed(expected: ExpectedObjects) -> Result<Self, ServiceRunStateError> {
        let location = impersonation_bookend(Location::fixed)?;
        Self::open_at(location, expected)
    }

    #[cfg(test)]
    pub(super) fn open_test(
        base: &Path,
        expected: ExpectedObjects,
    ) -> Result<Self, ServiceRunStateError> {
        Self::open_at(Location::test(base.to_path_buf()), expected)
    }

    fn open_at(
        location: Location,
        expected: ExpectedObjects,
    ) -> Result<Self, ServiceRunStateError> {
        impersonation_bookend(|| {
            expected.policy.validate()?;
            let handle = open_verified_root(&location, &expected)?;
            Ok(Self {
                handle,
                expected,
                location,
                revalidation_close_ambiguous: AtomicBool::new(false),
            })
        })
    }

    pub(super) fn revalidate(&self) -> Result<(), ServiceRunStateError> {
        impersonation_bookend(|| self.revalidate_inner())
    }

    fn revalidate_inner(&self) -> Result<(), ServiceRunStateError> {
        if self.revalidation_close_ambiguous.load(Ordering::Acquire) {
            return Err(ServiceRunStateError::Release);
        }
        self.expected.policy.validate()?;
        verify_root_handle(self.handle.raw(), &self.expected)?;
        let mut candidate = open_root_candidate(&self.location, &self.expected)?;
        candidate.handle.role = HandleRole::RevalidationRoot;
        if candidate.handle.close_checked().is_err() {
            self.revalidation_close_ambiguous
                .store(true, Ordering::Release);
            return Err(ServiceRunStateError::Release);
        }
        candidate.verification
    }

    #[allow(clippy::result_large_err)] // The error must retain both live move-only handles.
    pub(super) fn acquire_run_lock(self) -> Result<HeldWriter, AcquireFailure> {
        if let Err(cause) = self.revalidate() {
            return Err(AcquireFailure::BeforeLock(cause));
        }
        if let Err(cause) = reject_thread_impersonation() {
            return Err(AcquireFailure::BeforeLock(cause));
        }
        let opened = match open_relative(
            self.handle.raw(),
            RUN_LOCK_LEAF,
            LOCK_OPEN_ACCESS,
            FILE_SHARE_MODE(0),
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        ) {
            Ok(opened) => opened,
            Err(cause) => return Err(AcquireFailure::BeforeLock(cause)),
        };
        let mut lock = opened.handle;
        lock.role = HandleRole::Lock;
        let mut writer = HeldWriter {
            root: self,
            lock,
            state: None,
            range_lock_held: false,
        };
        let result = (|| {
            require_exact_open(opened.status_error, opened.information)?;
            verify_handle_flags_zero(writer.lock.raw())?;
            writer.acquire_exclusive_range()?;
            verify_lock_handle(
                writer.lock.raw(),
                &writer.root.expected,
                writer.root.expected.root_identity.volume_serial_number,
            )?;
            writer.root.revalidate_inner()?;
            #[cfg(test)]
            writer.open_state_with_test_fault()?;
            #[cfg(not(test))]
            writer.open_state()?;
            writer.root.revalidate_inner()?;
            reject_thread_impersonation()
        })();
        match result {
            Ok(()) => Ok(writer),
            Err(cause) => Err(AcquireFailure::WithLock {
                inner: writer,
                cause,
            }),
        }
    }

    fn close_checked(&mut self) -> Result<(), ServiceRunStateError> {
        let result = self.handle.close_checked();
        if self.revalidation_close_ambiguous.load(Ordering::Acquire) {
            Err(ServiceRunStateError::Release)
        } else {
            result
        }
    }

    #[cfg(test)]
    pub(super) fn handle_flags_are_zero_for_test(&self) -> bool {
        verify_handle_flags_zero(self.handle.raw()).is_ok()
    }

    #[cfg(test)]
    pub(super) fn byte_range_collision_probe_for_test(&self) -> Result<(), ServiceRunStateError> {
        probe_two_share_all_lock_handles(self.handle.raw(), &self.expected)
    }
}

impl fmt::Debug for HeldRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HeldRoot([REDACTED])")
    }
}

#[allow(clippy::large_enum_variant)] // Failure must retain authority without allocating.
pub(super) enum AcquireFailure {
    BeforeLock(ServiceRunStateError),
    WithLock {
        inner: HeldWriter,
        cause: ServiceRunStateError,
    },
}

pub(super) struct ReleaseFailure {
    pub(super) inner: HeldWriter,
    pub(super) cause: ServiceRunStateError,
}

/// Root and lock, plus any successfully opened state directory, remain held
/// until explicit verified release or retirement.
pub(super) struct HeldWriter {
    root: HeldRoot,
    lock: OwnedHandle,
    state: Option<OwnedHandle>,
    range_lock_held: bool,
}

impl HeldWriter {
    pub(super) fn revalidate(&self) -> Result<(), ServiceRunStateError> {
        impersonation_bookend(|| self.revalidate_inner())
    }

    fn revalidate_inner(&self) -> Result<(), ServiceRunStateError> {
        if !self.range_lock_held {
            return Err(ServiceRunStateError::Release);
        }
        let state = self.state.as_ref().ok_or(ServiceRunStateError::Release)?;
        self.root.revalidate_inner()?;
        verify_lock_handle(
            self.lock.raw(),
            &self.root.expected,
            self.root.expected.root_identity.volume_serial_number,
        )?;
        verify_state_handle(
            state.raw(),
            &self.root.expected,
            self.root.expected.root_identity.volume_serial_number,
        )?;
        self.revalidate_state_binding()
    }

    #[allow(clippy::result_large_err)] // Release failure intentionally retains writer authority.
    pub(super) fn release_verified(mut self) -> Result<(), ReleaseFailure> {
        if let Err(cause) = self.revalidate() {
            return Err(ReleaseFailure { inner: self, cause });
        }
        #[cfg(test)]
        record_release_step_for_test(TestReleaseStep::WriterRevalidated);
        if let Err(cause) = self.close_state_checked() {
            return Err(ReleaseFailure { inner: self, cause });
        }
        if let Err(cause) = self.unlock_exclusive_range() {
            return Err(ReleaseFailure { inner: self, cause });
        }
        if let Err(cause) = self.lock.close_checked() {
            return Err(ReleaseFailure { inner: self, cause });
        }
        if let Err(cause) = self.root.revalidate() {
            return Err(ReleaseFailure { inner: self, cause });
        }
        #[cfg(test)]
        record_release_step_for_test(TestReleaseStep::RootRevalidatedAfterLock);
        if let Err(cause) = self.root.close_checked() {
            return Err(ReleaseFailure { inner: self, cause });
        }
        Ok(())
    }

    pub(super) fn retire(mut self) -> Result<(), ServiceRunStateError> {
        let state_result = self.close_optional_state_checked();
        let unlock_result = if self.range_lock_held {
            self.unlock_exclusive_range()
        } else {
            Ok(())
        };
        let lock_result = self.lock.close_checked();
        if lock_result.is_ok() {
            self.range_lock_held = false;
        }
        let root_result = self.root.close_checked();
        state_result
            .and(unlock_result)
            .and(lock_result)
            .and(root_result)
    }

    fn open_state(&mut self) -> Result<(), ServiceRunStateError> {
        impersonation_bookend(|| self.open_state_inner())
    }

    #[cfg(test)]
    fn open_state_with_test_fault(&mut self) -> Result<(), ServiceRunStateError> {
        if take_state_open_impersonation_fault_for_test(
            TestStateOpenImpersonationFault::BeforeNativeOpen,
        ) {
            return run_impersonated_for_test(|| self.open_state());
        }
        self.open_state()
    }

    fn open_state_inner(&mut self) -> Result<(), ServiceRunStateError> {
        if !self.range_lock_held || self.state.is_some() {
            return Err(ServiceRunStateError::Release);
        }
        let opened = open_relative(
            self.root.handle.raw(),
            STATE_LEAF,
            STATE_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        )?;
        let mut state = opened.handle;
        state.role = HandleRole::State;
        self.state = Some(state);
        let state = self.state.as_ref().ok_or(ServiceRunStateError::Release)?;
        require_exact_open(opened.status_error, opened.information)?;
        verify_state_handle(
            state.raw(),
            &self.root.expected,
            self.root.expected.root_identity.volume_serial_number,
        )
    }

    fn revalidate_state_binding(&self) -> Result<(), ServiceRunStateError> {
        impersonation_bookend(|| self.revalidate_state_binding_inner())
    }

    fn revalidate_state_binding_inner(&self) -> Result<(), ServiceRunStateError> {
        if self
            .root
            .revalidation_close_ambiguous
            .load(Ordering::Acquire)
        {
            return Err(ServiceRunStateError::Release);
        }
        let opened = open_relative(
            self.root.handle.raw(),
            STATE_LEAF,
            STATE_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        )?;
        let mut candidate = opened.handle;
        candidate.role = HandleRole::RevalidationState;
        let verification = (|| {
            require_exact_open(opened.status_error, opened.information)?;
            verify_state_handle(
                candidate.raw(),
                &self.root.expected,
                self.root.expected.root_identity.volume_serial_number,
            )
        })();
        if candidate.close_checked().is_err() {
            self.root
                .revalidation_close_ambiguous
                .store(true, Ordering::Release);
            return Err(ServiceRunStateError::Release);
        }
        verification
    }

    fn close_state_checked(&mut self) -> Result<(), ServiceRunStateError> {
        let Some(mut state) = self.state.take() else {
            return Err(ServiceRunStateError::Release);
        };
        if let Err(cause) = state.close_checked() {
            self.state = Some(state);
            return Err(cause);
        }
        Ok(())
    }

    fn close_optional_state_checked(&mut self) -> Result<(), ServiceRunStateError> {
        let Some(mut state) = self.state.take() else {
            return Ok(());
        };
        if let Err(cause) = state.close_checked() {
            self.state = Some(state);
            return Err(cause);
        }
        Ok(())
    }

    fn acquire_exclusive_range(&mut self) -> Result<(), ServiceRunStateError> {
        let attempt = try_acquire_exclusive_writer_range(self.lock.raw());
        self.range_lock_held = attempt.acquired;
        attempt.result
    }

    fn unlock_exclusive_range(&mut self) -> Result<(), ServiceRunStateError> {
        if !self.range_lock_held {
            return Err(ServiceRunStateError::Release);
        }
        reject_thread_impersonation()?;
        #[cfg(test)]
        let injected_failure = take_unlock_fault_for_test();
        #[cfg(not(test))]
        let injected_failure = false;
        let mut overlapped = OVERLAPPED::default();
        let operation = if injected_failure {
            Err(ServiceRunStateError::Release)
        } else {
            // SAFETY: this is the same live handle and exact one-byte range
            // used by the successful exclusive LockFileEx acquisition.
            unsafe { UnlockFileEx(self.lock.raw(), None, 1, 0, &raw mut overlapped) }
                .map_err(|_| ServiceRunStateError::Release)
        };
        if operation.is_ok() {
            self.range_lock_held = false;
            #[cfg(test)]
            record_release_step_for_test(TestReleaseStep::RangeUnlocked);
        }
        let ending = reject_thread_impersonation();
        match (operation, ending) {
            (_, Err(error)) => Err(error),
            (result, Ok(())) => result,
        }
    }

    #[cfg(test)]
    pub(super) fn handle_flags_are_zero_for_test(&self) -> bool {
        verify_handle_flags_zero(self.root.handle.raw()).is_ok()
            && verify_handle_flags_zero(self.lock.raw()).is_ok()
            && self
                .state
                .as_ref()
                .is_some_and(|state| verify_handle_flags_zero(state.raw()).is_ok())
    }

    #[cfg(test)]
    pub(super) fn has_state_for_test(&self) -> bool {
        self.state.is_some()
    }

    #[cfg(test)]
    pub(super) fn directional_exclusivity_probe_for_test(
        &self,
    ) -> Result<(), ServiceRunStateError> {
        probe_share_all_lock_open(self.root.handle.raw(), self.lock.raw())
    }
}

impl fmt::Debug for HeldWriter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HeldWriter([REDACTED])")
    }
}

struct OpenedRelative {
    handle: OwnedHandle,
    status_error: Option<ServiceRunStateError>,
    information: usize,
}

struct RootCandidate {
    handle: OwnedHandle,
    verification: Result<(), ServiceRunStateError>,
}

fn open_verified_root(
    location: &Location,
    expected: &ExpectedObjects,
) -> Result<OwnedHandle, ServiceRunStateError> {
    let mut candidate = open_root_candidate(location, expected)?;
    match candidate.verification {
        Ok(()) => {
            candidate.handle.role = HandleRole::Root;
            Ok(candidate.handle)
        }
        Err(cause) => {
            if candidate.handle.close_checked().is_err() {
                Err(ServiceRunStateError::Release)
            } else {
                Err(cause)
            }
        }
    }
}

fn open_root_candidate(
    location: &Location,
    expected: &ExpectedObjects,
) -> Result<RootCandidate, ServiceRunStateError> {
    let (drive_root, base_components) = local_drive_path_parts(&location.base_path)?;
    let drive = open_drive_root(&drive_root)?;
    verify_directory_shape(drive.raw(), false)?;
    verify_handle_flags_zero(drive.raw())?;
    verify_supported_local_ntfs(drive.raw())?;
    let drive_identity = ObjectIdentity::from_handle(drive.raw())?;

    let mut parent = drive;
    for component in &base_components {
        let opened = open_relative(
            parent.raw(),
            component,
            PARENT_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        )?;
        require_exact_open(opened.status_error, opened.information)?;
        verify_handle_flags_zero(opened.handle.raw())?;
        verify_directory_shape(opened.handle.raw(), false)?;
        if ObjectIdentity::from_handle(opened.handle.raw())?.volume_serial_number
            != drive_identity.volume_serial_number
        {
            return Err(ServiceRunStateError::Volume);
        }
        parent = opened.handle;
    }
    for (index, leaf) in PRODUCT_LEAVES.iter().enumerate() {
        let is_root = index + 1 == PRODUCT_LEAVES.len();
        let desired = if is_root { ROOT_ACCESS } else { PARENT_ACCESS };
        let share = if is_root {
            FILE_SHARE_READ | FILE_SHARE_WRITE
        } else {
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        };
        let opened = open_relative(
            parent.raw(),
            leaf,
            desired,
            share,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        )?;
        if is_root {
            let verification = (|| {
                require_exact_open(opened.status_error, opened.information)?;
                verify_root_handle(opened.handle.raw(), expected)?;
                let identity = ObjectIdentity::from_handle(opened.handle.raw())?;
                if identity.volume_serial_number != drive_identity.volume_serial_number {
                    return Err(ServiceRunStateError::Volume);
                }
                Ok(())
            })();
            return Ok(RootCandidate {
                handle: opened.handle,
                verification,
            });
        }
        require_exact_open(opened.status_error, opened.information)?;
        verify_handle_flags_zero(opened.handle.raw())?;
        verify_directory_shape(opened.handle.raw(), false)?;
        let identity = ObjectIdentity::from_handle(opened.handle.raw())?;
        if identity.volume_serial_number != drive_identity.volume_serial_number {
            return Err(ServiceRunStateError::Volume);
        }
        parent = opened.handle;
    }
    Err(ServiceRunStateError::Location)
}

fn open_drive_root(path: &Path) -> Result<OwnedHandle, ServiceRunStateError> {
    let wide = wide_path(path)?;
    reject_thread_impersonation()?;
    // SAFETY: the validated absolute path is NUL-terminated; no inheritable
    // security attributes are supplied and only an existing directory opens.
    #[cfg(test)]
    record_open_for_test();
    // SAFETY: the validated absolute path and documented arguments above stay live.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            PARENT_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|_| ServiceRunStateError::Location)?;
    let handle = OwnedHandle::new(handle).map_err(|_| ServiceRunStateError::Location)?;
    reject_thread_impersonation()?;
    Ok(handle)
}

fn open_relative(
    parent: HANDLE,
    leaf: &str,
    desired_access: u32,
    share_access: FILE_SHARE_MODE,
    create_options: windows::Wdk::Storage::FileSystem::NTCREATEFILE_CREATE_OPTIONS,
) -> Result<OpenedRelative, ServiceRunStateError> {
    validate_leaf(leaf)?;
    reject_thread_impersonation()?;
    #[cfg(test)]
    if leaf == STATE_LEAF {
        TEST_STATE_NATIVE_OPEN_COUNT.with(|count| count.set(count.get().saturating_add(1)));
    }
    let mut name = leaf.encode_utf16().collect::<Vec<_>>();
    let byte_len = name
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|value| u16::try_from(value).ok())
        .ok_or(ServiceRunStateError::Location)?;
    let unicode = UNICODE_STRING {
        Length: byte_len,
        MaximumLength: byte_len,
        Buffer: PWSTR(name.as_mut_ptr()),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>())
            .map_err(|_| ServiceRunStateError::Open)?,
        RootDirectory: parent,
        ObjectName: &raw const unicode,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        SecurityDescriptor: ptr::null(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut io = IO_STATUS_BLOCK::default();
    let mut raw = HANDLE::default();
    // SAFETY: every structure and UTF-16 buffer remains live for the call;
    // `RootDirectory` is a held directory, disposition is strictly FILE_OPEN,
    // and no creation/repair buffer or inheritable attribute is supplied.
    #[cfg(test)]
    record_open_for_test();
    // SAFETY: all native structures, the parent, and UTF-16 leaf stay live.
    let status = unsafe {
        NtCreateFile(
            &raw mut raw,
            FILE_ACCESS_RIGHTS(desired_access),
            &raw const attributes,
            &raw mut io,
            None,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            share_access,
            FILE_OPEN,
            create_options,
            None,
            0,
        )
    };
    let mut status_error = if status == STATUS_SUCCESS {
        // SAFETY: NtCreateFile initialized IO_STATUS_BLOCK before returning a
        // usable handle, and Status is the active member for this operation.
        let io_status = unsafe { io.Anonymous.Status };
        (io_status != STATUS_SUCCESS).then_some(ServiceRunStateError::Open)
    } else {
        Some(map_open_status(status))
    };
    if raw.is_invalid() || raw == INVALID_HANDLE_VALUE {
        return Err(status_error.unwrap_or(ServiceRunStateError::Open));
    }
    let handle = OwnedHandle::new(raw)?;
    #[cfg(test)]
    let inject_post_open_impersonation = leaf == STATE_LEAF
        && take_state_open_impersonation_fault_for_test(
            TestStateOpenImpersonationFault::AfterNativeOpen,
        );
    #[cfg(test)]
    let impersonation_installed = if inject_post_open_impersonation {
        // SAFETY: this test-only fault is reverted on this same thread before
        // the opened handle is returned to the held failure typestate.
        unsafe { ImpersonateSelf(SecurityImpersonation) }.is_ok()
    } else {
        false
    };
    let ending = reject_thread_impersonation();
    #[cfg(test)]
    let ending = {
        let restored = if impersonation_installed {
            // SAFETY: the test fault installed impersonation on this thread.
            unsafe { RevertToSelf() }.map_err(|_| ServiceRunStateError::Impersonation)
        } else {
            Ok(())
        };
        if inject_post_open_impersonation && !impersonation_installed {
            Err(ServiceRunStateError::Impersonation)
        } else {
            ending.and(restored)
        }
    };
    if let Err(error) = ending {
        status_error = Some(error);
    }
    Ok(OpenedRelative {
        handle,
        status_error,
        information: io.Information,
    })
}

struct RangeLockAttempt {
    acquired: bool,
    result: Result<(), ServiceRunStateError>,
}

fn try_acquire_exclusive_writer_range(handle: HANDLE) -> RangeLockAttempt {
    if let Err(error) = reject_thread_impersonation() {
        return RangeLockAttempt {
            acquired: false,
            result: Err(error),
        };
    }
    let mut overlapped = OVERLAPPED::default();
    // SAFETY: the synchronous file handle has FILE_READ_DATA; the exact
    // one-byte range may extend beyond the empty file's end, and
    // FAIL_IMMEDIATELY prevents an unbounded wait.
    let operation = unsafe {
        LockFileEx(
            handle,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            None,
            1,
            0,
            &raw mut overlapped,
        )
    };
    let acquired = operation.is_ok();
    let result = match operation {
        Ok(()) => Ok(()),
        Err(error) if error.code() == ERROR_LOCK_VIOLATION.to_hresult() => {
            Err(ServiceRunStateError::Contended)
        }
        Err(_) => Err(ServiceRunStateError::Open),
    };
    let ending = reject_thread_impersonation();
    RangeLockAttempt {
        acquired,
        result: match (result, ending) {
            (_, Err(error)) => Err(error),
            (result, Ok(())) => result,
        },
    }
}

#[cfg(test)]
fn probe_share_all_lock_open(
    parent: HANDLE,
    held_lock: HANDLE,
) -> Result<(), ServiceRunStateError> {
    validate_leaf(RUN_LOCK_LEAF)?;
    reject_thread_impersonation()?;
    let mut name = RUN_LOCK_LEAF.encode_utf16().collect::<Vec<_>>();
    let byte_len = name
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|value| u16::try_from(value).ok())
        .ok_or(ServiceRunStateError::Location)?;
    let unicode = UNICODE_STRING {
        Length: byte_len,
        MaximumLength: byte_len,
        Buffer: PWSTR(name.as_mut_ptr()),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>())
            .map_err(|_| ServiceRunStateError::Open)?,
        RootDirectory: parent,
        ObjectName: &raw const unicode,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        SecurityDescriptor: ptr::null(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut io = IO_STATUS_BLOCK::default();
    let mut raw = HANDLE::default();
    record_open_for_test();
    // SAFETY: this is the production relative-open shape with the deliberate
    // test-only difference that the competing request offers all share modes.
    let status = unsafe {
        NtCreateFile(
            &raw mut raw,
            FILE_ACCESS_RIGHTS(LOCK_OPEN_ACCESS),
            &raw const attributes,
            &raw mut io,
            None,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            None,
            0,
        )
    };
    let impersonation_result = reject_thread_impersonation();
    let raw_valid = !raw.is_invalid() && raw != INVALID_HANDLE_VALUE;
    if status == STATUS_SHARING_VIOLATION {
        if raw_valid {
            let mut unexpected = OwnedHandle::new(raw)?;
            let close_result = unexpected.close_checked();
            impersonation_result?;
            close_result?;
            return Err(ServiceRunStateError::Open);
        }
        impersonation_result?;
        // SAFETY: NtCreateFile synchronously initialized the status member.
        let io_status = unsafe { io.Anonymous.Status };
        return if io_status == STATUS_SHARING_VIOLATION && io.Information == 0 {
            Ok(())
        } else {
            Err(ServiceRunStateError::Open)
        };
    }
    if status != STATUS_SUCCESS || !raw_valid {
        if raw_valid {
            let mut unexpected = OwnedHandle::new(raw)?;
            let close_result = unexpected.close_checked();
            impersonation_result?;
            close_result?;
        } else {
            impersonation_result?;
        }
        return Err(ServiceRunStateError::Open);
    }

    let mut unexpected = OwnedHandle::new(raw)?;
    let verification = (|| {
        // SAFETY: a successful synchronous NtCreateFile initialized Status.
        if unsafe { io.Anonymous.Status } != STATUS_SUCCESS
            || io.Information
                != usize::try_from(FILE_OPENED).map_err(|_| ServiceRunStateError::Open)?
        {
            return Err(ServiceRunStateError::Open);
        }
        verify_handle_flags_zero(unexpected.raw())?;
        verify_file_shape(unexpected.raw())?;
        if ObjectIdentity::from_handle(unexpected.raw())? != ObjectIdentity::from_handle(held_lock)?
        {
            return Err(ServiceRunStateError::Identity);
        }
        match try_acquire_exclusive_writer_range(unexpected.raw()).result {
            Err(ServiceRunStateError::Contended) => Ok(()),
            Ok(()) | Err(_) => Err(ServiceRunStateError::Open),
        }
    })();
    let close_result = unexpected.close_checked();
    impersonation_result?;
    verification?;
    close_result
}

#[cfg(test)]
fn probe_two_share_all_lock_handles(
    parent: HANDLE,
    expected: &ExpectedObjects,
) -> Result<(), ServiceRunStateError> {
    let share_all = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    let options = FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT;
    let first_open = open_relative(parent, RUN_LOCK_LEAF, LOCK_OPEN_ACCESS, share_all, options)?;
    let mut first = first_open.handle;
    let first_result = (|| {
        require_exact_open(first_open.status_error, first_open.information)?;
        verify_lock_handle(
            first.raw(),
            expected,
            expected.root_identity.volume_serial_number,
        )?;
        try_acquire_exclusive_writer_range(first.raw()).result
    })();
    if first_result.is_err() {
        let close_result = first.close_checked();
        return close_result.and(first_result);
    }

    let second_open =
        match open_relative(parent, RUN_LOCK_LEAF, LOCK_OPEN_ACCESS, share_all, options) {
            Ok(opened) => opened,
            Err(error) => {
                let close_result = first.close_checked();
                return close_result.and(Err(error));
            }
        };
    let mut second = second_open.handle;
    let collision_result = (|| {
        require_exact_open(second_open.status_error, second_open.information)?;
        verify_lock_handle(
            second.raw(),
            expected,
            expected.root_identity.volume_serial_number,
        )?;
        if ObjectIdentity::from_handle(first.raw())? != ObjectIdentity::from_handle(second.raw())? {
            return Err(ServiceRunStateError::Identity);
        }
        match try_acquire_exclusive_writer_range(second.raw()).result {
            Err(ServiceRunStateError::Contended) => Ok(()),
            Ok(()) | Err(_) => Err(ServiceRunStateError::Open),
        }
    })();
    let second_close = second.close_checked();
    let first_close = first.close_checked();
    second_close.and(first_close)?;
    collision_result
}

fn map_open_status(status: windows::Win32::Foundation::NTSTATUS) -> ServiceRunStateError {
    if status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND {
        ServiceRunStateError::Missing
    } else if status == STATUS_SHARING_VIOLATION {
        ServiceRunStateError::Contended
    } else if status == STATUS_REPARSE_POINT_ENCOUNTERED {
        ServiceRunStateError::Reparse
    } else if status == STATUS_FILE_IS_A_DIRECTORY || status == STATUS_NOT_A_DIRECTORY {
        ServiceRunStateError::Shape
    } else {
        ServiceRunStateError::Open
    }
}

fn require_exact_open(
    status_error: Option<ServiceRunStateError>,
    information: usize,
) -> Result<(), ServiceRunStateError> {
    if let Some(error) = status_error {
        return Err(error);
    }
    if information == usize::try_from(FILE_OPENED).map_err(|_| ServiceRunStateError::Open)? {
        Ok(())
    } else {
        Err(ServiceRunStateError::Open)
    }
}

fn verify_root_handle(
    handle: HANDLE,
    expected: &ExpectedObjects,
) -> Result<(), ServiceRunStateError> {
    verify_handle_flags_zero(handle)?;
    verify_directory_shape(handle, true)?;
    verify_supported_local_ntfs(handle)?;
    verify_exact_security(handle, &expected.policy, ROOT_ACCESS)?;
    if ObjectIdentity::from_handle(handle)? != expected.root_identity {
        return Err(ServiceRunStateError::Identity);
    }
    Ok(())
}

fn verify_lock_handle(
    handle: HANDLE,
    expected: &ExpectedObjects,
    root_volume: u64,
) -> Result<(), ServiceRunStateError> {
    verify_handle_flags_zero(handle)?;
    verify_exact_granted_access(handle, LOCK_ACCESS)?;
    verify_file_shape(handle)?;
    verify_supported_local_ntfs(handle)?;
    verify_exact_security(handle, &expected.policy, LOCK_ACCESS)?;
    let identity = ObjectIdentity::from_handle(handle)?;
    if identity != expected.lock_identity || identity.volume_serial_number != root_volume {
        return Err(ServiceRunStateError::Identity);
    }
    Ok(())
}

fn verify_state_handle(
    handle: HANDLE,
    expected: &ExpectedObjects,
    root_volume: u64,
) -> Result<(), ServiceRunStateError> {
    verify_handle_flags_zero(handle)?;
    verify_exact_granted_access(handle, STATE_ACCESS)?;
    verify_directory_shape(handle, true)?;
    verify_supported_local_ntfs(handle)?;
    verify_exact_security(handle, &expected.policy, STATE_ACCESS)?;
    let identity = ObjectIdentity::from_handle(handle)?;
    if identity != expected.state_identity || identity.volume_serial_number != root_volume {
        return Err(ServiceRunStateError::Identity);
    }
    Ok(())
}

fn basic_information(handle: HANDLE) -> Result<BY_HANDLE_FILE_INFORMATION, ServiceRunStateError> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the held handle remains live and the exact output is writable.
    unsafe { GetFileInformationByHandle(handle, &raw mut information) }
        .map_err(|_| ServiceRunStateError::Shape)?;
    Ok(information)
}

fn verify_directory_shape(
    handle: HANDLE,
    require_single_link: bool,
) -> Result<(), ServiceRunStateError> {
    let information = basic_information(handle)?;
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(ServiceRunStateError::Reparse);
    }
    if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0
        || (require_single_link && information.nNumberOfLinks != 1)
    {
        return Err(ServiceRunStateError::Shape);
    }
    Ok(())
}

fn verify_file_shape(handle: HANDLE) -> Result<(), ServiceRunStateError> {
    let information = basic_information(handle)?;
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(ServiceRunStateError::Reparse);
    }
    if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0
        || information.nNumberOfLinks != 1
        || information.nFileSizeHigh != 0
        || information.nFileSizeLow != 0
    {
        return Err(ServiceRunStateError::Shape);
    }
    Ok(())
}

fn verify_handle_flags_zero(handle: HANDLE) -> Result<(), ServiceRunStateError> {
    let mut flags = 0_u32;
    // SAFETY: `handle` is held and the scalar output is writable.
    unsafe { GetHandleInformation(handle, &raw mut flags) }
        .map_err(|_| ServiceRunStateError::Handle)?;
    if flags != 0 {
        return Err(ServiceRunStateError::Handle);
    }
    Ok(())
}

fn verify_exact_granted_access(handle: HANDLE, expected: u32) -> Result<(), ServiceRunStateError> {
    let mut io = IO_STATUS_BLOCK::default();
    let mut access = FILE_ACCESS_INFORMATION::default();
    let length = u32::try_from(size_of::<FILE_ACCESS_INFORMATION>())
        .map_err(|_| ServiceRunStateError::Security)?;
    // SAFETY: the held handle remains live and both native output structures
    // have their exact documented writable sizes.
    let status = unsafe {
        NtQueryInformationFile(
            handle,
            &raw mut io,
            ptr::from_mut(&mut access).cast::<c_void>(),
            length,
            FileAccessInformation,
        )
    };
    // SAFETY: a synchronous NtQueryInformationFile initialized Status.
    let io_status = unsafe { io.Anonymous.Status };
    if status != STATUS_SUCCESS
        || io_status != STATUS_SUCCESS
        || io.Information != size_of::<FILE_ACCESS_INFORMATION>()
        || access.AccessFlags != expected
    {
        return Err(ServiceRunStateError::Security);
    }
    Ok(())
}

fn verify_supported_local_ntfs(handle: HANDLE) -> Result<(), ServiceRunStateError> {
    let root = volume_guid_root_for_handle(handle)?;
    // SAFETY: `root` is a validated NUL-terminated volume GUID root.
    if unsafe { GetDriveTypeW(PCWSTR(root.as_ptr())) } != DRIVE_FIXED {
        return Err(ServiceRunStateError::Volume);
    }
    let mut remote = FILE_REMOTE_PROTOCOL_INFO::default();
    // A successful query proves redirector-backed storage.
    // SAFETY: the output is the exact documented writable representation.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileRemoteProtocolInfo,
            ptr::from_mut(&mut remote).cast::<c_void>(),
            u32::try_from(size_of_val(&remote)).map_err(|_| ServiceRunStateError::Volume)?,
        )
    }
    .is_ok()
    {
        return Err(ServiceRunStateError::Volume);
    }
    let mut flags = 0_u32;
    let mut filesystem = [0_u16; FILESYSTEM_NAME_UTF16];
    // SAFETY: all outputs are exact initialized storage and `handle` is live.
    unsafe {
        GetVolumeInformationByHandleW(
            handle,
            None,
            None,
            None,
            Some(&raw mut flags),
            Some(&mut filesystem),
        )
    }
    .map_err(|_| ServiceRunStateError::Volume)?;
    if flags & FILE_PERSISTENT_ACLS == 0 || !is_exact_ntfs_name(&filesystem) {
        return Err(ServiceRunStateError::Volume);
    }
    Ok(())
}

fn volume_guid_root_for_handle(handle: HANDLE) -> Result<Vec<u16>, ServiceRunStateError> {
    let mut path = vec![0_u16; MAX_FINAL_PATH_UTF16];
    // SAFETY: the held handle and complete writable buffer are valid.
    let length = unsafe { GetFinalPathNameByHandleW(handle, &mut path, VOLUME_NAME_GUID) };
    let length = usize::try_from(length).map_err(|_| ServiceRunStateError::Volume)?;
    if length == 0 || length >= path.len() {
        return Err(ServiceRunStateError::Volume);
    }
    volume_guid_root(&path[..length])
}

fn volume_guid_root(path: &[u16]) -> Result<Vec<u16>, ServiceRunStateError> {
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
        return Err(ServiceRunStateError::Volume);
    }
    let close = path[prefix.len()..]
        .iter()
        .position(|unit| *unit == u16::from(b'}'))
        .and_then(|offset| prefix.len().checked_add(offset))
        .ok_or(ServiceRunStateError::Volume)?;
    if !is_canonical_guid(&path[prefix.len()..close])
        || path.get(close + 1) != Some(&u16::from(b'\\'))
    {
        return Err(ServiceRunStateError::Volume);
    }
    let end = close.checked_add(2).ok_or(ServiceRunStateError::Volume)?;
    let mut root = path
        .get(..end)
        .ok_or(ServiceRunStateError::Volume)?
        .to_vec();
    root.push(0);
    Ok(root)
}

fn is_canonical_guid(value: &[u16]) -> bool {
    value.len() == 36
        && value.iter().enumerate().all(|(index, unit)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *unit == u16::from(b'-')
            } else {
                u8::try_from(*unit).is_ok_and(|byte| byte.is_ascii_hexdigit())
            }
        })
}

fn is_exact_ntfs_name(value: &[u16]) -> bool {
    let Some(end) = value.iter().position(|unit| *unit == 0) else {
        return false;
    };
    value[end..].iter().all(|unit| *unit == 0)
        && value[..end].len() == 4
        && value[..end].iter().zip(b"NTFS").all(|(unit, expected)| {
            u8::try_from(*unit).is_ok_and(|unit| unit.eq_ignore_ascii_case(expected))
        })
}

fn verify_exact_security(
    handle: HANDLE,
    policy: &SecurityPolicy,
    service_mask: u32,
) -> Result<(), ServiceRunStateError> {
    let mut owner = PSID::default();
    let mut dacl = ptr::null_mut::<ACL>();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // This scope proves owner and the protected DACL only. Audit SACL policy is
    // intentionally external because reading it requires additional privilege.
    // SAFETY: every output is initialized writable storage and the handle lives.
    let status = unsafe {
        GetSecurityInfo(
            handle,
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
        free_descriptor(descriptor);
        return Err(ServiceRunStateError::Security);
    }
    let result = inspect_security_descriptor(descriptor, owner, dacl, policy, service_mask);
    free_descriptor(descriptor);
    result
}

fn free_descriptor(descriptor: PSECURITY_DESCRIPTOR) {
    if !descriptor.0.is_null() {
        // SAFETY: GetSecurityInfo allocates this descriptor with LocalAlloc.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        }
    }
}

fn inspect_security_descriptor(
    descriptor: PSECURITY_DESCRIPTOR,
    owner: PSID,
    dacl: *mut ACL,
    policy: &SecurityPolicy,
    service_mask: u32,
) -> Result<(), ServiceRunStateError> {
    // SAFETY: the descriptor and interior pointers remain owned by the caller.
    let descriptor_valid = unsafe { IsValidSecurityDescriptor(descriptor) }.as_bool();
    // SAFETY: `owner` is an interior pointer of the same live descriptor.
    let owner_valid = unsafe { IsValidSid(owner) }.as_bool();
    // SAFETY: both complete SIDs remain readable for the comparison.
    let owner_matches = unsafe { EqualSid(owner, policy.service_sid.as_psid()) }.is_ok();
    if !descriptor_valid || !owner_valid || !owner_matches {
        return Err(ServiceRunStateError::Security);
    }
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: exact scalar outputs are writable for the live descriptor.
    unsafe {
        GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision)
            .map_err(|_| ServiceRunStateError::Security)?;
    }
    let required = control_flag(SE_SELF_RELATIVE)
        | control_flag(SE_DACL_PRESENT)
        | control_flag(SE_DACL_PROTECTED);
    let forbidden = control_flag(SE_OWNER_DEFAULTED)
        | control_flag(SE_DACL_DEFAULTED)
        | control_flag(SE_DACL_AUTO_INHERIT_REQ);
    if control & required != required || control & forbidden != 0 {
        return Err(ServiceRunStateError::Security);
    }
    inspect_exact_dacl(dacl, policy, service_mask)
}

fn control_flag(flag: windows::Win32::Security::SECURITY_DESCRIPTOR_CONTROL) -> u16 {
    u16::from_ne_bytes(flag.0.to_ne_bytes())
}

fn inspect_exact_dacl(
    dacl: *mut ACL,
    policy: &SecurityPolicy,
    service_mask: u32,
) -> Result<(), ServiceRunStateError> {
    let (acl_size, information) = inspect_acl_header(dacl, 3)?;
    let deny = ace_at(dacl, 0)?;
    let service = ace_at(dacl, 1)?;
    let system = ace_at(dacl, 2)?;
    let deny_size = inspect_owner_rights_deny(deny)?;
    let service_size = inspect_allow_ace(service, policy.service_sid.as_psid(), service_mask)?;
    let system_size = inspect_allow_ace(system, policy.system_sid.as_psid(), FILE_ALL_ACCESS.0)?;
    let exact = size_of::<ACL>()
        .checked_add(deny_size)
        .and_then(|value| value.checked_add(service_size))
        .and_then(|value| value.checked_add(system_size))
        .ok_or(ServiceRunStateError::Security)?;
    let used =
        usize::try_from(information.AclBytesInUse).map_err(|_| ServiceRunStateError::Security)?;
    let free =
        usize::try_from(information.AclBytesFree).map_err(|_| ServiceRunStateError::Security)?;
    let total = usize::from(acl_size);
    if used != exact || total < used || total.checked_sub(used) != Some(free) {
        return Err(ServiceRunStateError::Security);
    }
    Ok(())
}

fn inspect_acl_header(
    acl: *mut ACL,
    expected_aces: u32,
) -> Result<(u16, ACL_SIZE_INFORMATION), ServiceRunStateError> {
    // SAFETY: the pointer lies in the live descriptor returned by Windows.
    if acl.is_null() || !unsafe { IsValidAcl(acl) }.as_bool() {
        return Err(ServiceRunStateError::Security);
    }
    // SAFETY: IsValidAcl proves the fixed header is readable.
    let header = unsafe { &*acl };
    if u32::from(header.AclRevision) != ACL_REVISION.0 || header.Sbz1 != 0 || header.Sbz2 != 0 {
        return Err(ServiceRunStateError::Security);
    }
    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: output is exact and the ACL remains live.
    unsafe {
        GetAclInformation(
            acl,
            ptr::from_mut(&mut information).cast::<c_void>(),
            u32::try_from(size_of::<ACL_SIZE_INFORMATION>())
                .map_err(|_| ServiceRunStateError::Security)?,
            AclSizeInformation,
        )
    }
    .map_err(|_| ServiceRunStateError::Security)?;
    if information.AceCount != expected_aces {
        return Err(ServiceRunStateError::Security);
    }
    Ok((header.AclSize, information))
}

fn ace_at(acl: *mut ACL, index: u32) -> Result<*mut c_void, ServiceRunStateError> {
    let mut ace = ptr::null_mut::<c_void>();
    // SAFETY: the validated ACL's exact count is checked before fixed indexes.
    unsafe { GetAce(acl, index, &raw mut ace) }.map_err(|_| ServiceRunStateError::Security)?;
    if ace.is_null() {
        return Err(ServiceRunStateError::Security);
    }
    Ok(ace)
}

fn inspect_owner_rights_deny(ace: *mut c_void) -> Result<usize, ServiceRunStateError> {
    // SAFETY: GetAce proves the common header is readable.
    let header = unsafe { &*ace.cast::<ACE_HEADER>() };
    let sid_offset = offset_of!(ACCESS_DENIED_ACE, SidStart);
    if header.AceType != u8::try_from(ACCESS_DENIED_ACE_TYPE).unwrap_or(u8::MAX)
        || header.AceFlags != 0
        || usize::from(header.AceSize) < sid_offset.saturating_add(MIN_BINARY_SID_BYTES)
    {
        return Err(ServiceRunStateError::Security);
    }
    // SAFETY: type and size prove the fixed deny ACE fields.
    let denied = unsafe { &*ace.cast::<ACCESS_DENIED_ACE>() };
    if denied.Mask != OWNER_RIGHTS_DENY {
        return Err(ServiceRunStateError::Security);
    }
    let sid = sid_in_ace(
        ptr::addr_of!(denied.SidStart).cast::<u8>(),
        header,
        sid_offset,
    )?;
    // SAFETY: `sid_in_ace` proved one complete valid SID.
    if !unsafe { windows::Win32::Security::IsWellKnownSid(sid, WinCreatorOwnerRightsSid) }.as_bool()
    {
        return Err(ServiceRunStateError::Security);
    }
    Ok(usize::from(header.AceSize))
}

fn inspect_allow_ace(
    ace: *mut c_void,
    expected_sid: PSID,
    expected_mask: u32,
) -> Result<usize, ServiceRunStateError> {
    // SAFETY: GetAce proves the common header is readable.
    let header = unsafe { &*ace.cast::<ACE_HEADER>() };
    let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    if header.AceType != u8::try_from(ACCESS_ALLOWED_ACE_TYPE).unwrap_or(u8::MAX)
        || header.AceFlags != 0
        || usize::from(header.AceSize) < sid_offset.saturating_add(MIN_BINARY_SID_BYTES)
    {
        return Err(ServiceRunStateError::Security);
    }
    // SAFETY: type and size prove the fixed allow ACE fields.
    let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
    if allowed.Mask != expected_mask {
        return Err(ServiceRunStateError::Security);
    }
    let sid = sid_in_ace(
        ptr::addr_of!(allowed.SidStart).cast::<u8>(),
        header,
        sid_offset,
    )?;
    // SAFETY: both SIDs are complete and valid for this comparison.
    if unsafe { EqualSid(sid, expected_sid) }.is_err() {
        return Err(ServiceRunStateError::Security);
    }
    Ok(usize::from(header.AceSize))
}

fn sid_in_ace(
    bytes: *const u8,
    header: &ACE_HEADER,
    sid_offset: usize,
) -> Result<PSID, ServiceRunStateError> {
    let available = usize::from(header.AceSize).saturating_sub(sid_offset);
    if bytes.is_null() || available < MIN_BINARY_SID_BYTES {
        return Err(ServiceRunStateError::Security);
    }
    // SAFETY: the fixed SID header and sub-authority count fit `available`.
    let count = usize::from(unsafe { *bytes.add(1) });
    let declared = count
        .checked_mul(size_of::<u32>())
        .and_then(|value| value.checked_add(MIN_BINARY_SID_BYTES))
        .ok_or(ServiceRunStateError::Security)?;
    if declared != available || declared > MAX_BINARY_SID_BYTES {
        return Err(ServiceRunStateError::Security);
    }
    let sid = PSID(bytes.cast_mut().cast::<c_void>());
    // SAFETY: the self-declared SID range fits wholly within this ACE.
    let valid = unsafe { IsValidSid(sid) }.as_bool();
    // SAFETY: a valid in-ACE SID has a readable self-declared length.
    let byte_len = unsafe { GetLengthSid(sid) };
    if !valid || usize::try_from(byte_len).map_err(|_| ServiceRunStateError::Security)? != declared
    {
        return Err(ServiceRunStateError::Security);
    }
    Ok(sid)
}

#[cfg(test)]
fn current_user_sid_for_test() -> Result<OwnedSid, ServiceRunStateError> {
    let mut token = HANDLE::default();
    // SAFETY: query-only current-process token output is valid.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) }
        .map_err(|_| ServiceRunStateError::Security)?;
    let token = OwnedHandle::new(token).map_err(|_| ServiceRunStateError::Security)?;
    let mut needed = 0_u32;
    // SAFETY: the first call intentionally queries the exact buffer length.
    let size_query =
        unsafe { GetTokenInformation(token.raw(), TokenUser, None, 0, &raw mut needed) };
    let needed_bytes = usize::try_from(needed).map_err(|_| ServiceRunStateError::Security)?;
    if !matches!(size_query, Err(error) if error.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult())
        || needed_bytes < size_of::<TOKEN_USER>()
        || needed_bytes > MAX_TEST_TOKEN_INFORMATION_BYTES
    {
        return Err(ServiceRunStateError::Security);
    }
    let words = needed_bytes
        .checked_add(size_of::<usize>() - 1)
        .and_then(|value| value.checked_div(size_of::<usize>()))
        .ok_or(ServiceRunStateError::Security)?;
    let mut storage = vec![0_usize; words];
    let mut returned = 0_u32;
    // SAFETY: the native-aligned buffer is writable for the queried size.
    unsafe {
        GetTokenInformation(
            token.raw(),
            TokenUser,
            Some(storage.as_mut_ptr().cast::<c_void>()),
            needed,
            &raw mut returned,
        )
    }
    .map_err(|_| ServiceRunStateError::Security)?;
    if returned != needed {
        return Err(ServiceRunStateError::Security);
    }
    // SAFETY: Windows initialized a complete TOKEN_USER in aligned storage.
    let user = unsafe { ptr::read_unaligned(storage.as_ptr().cast::<TOKEN_USER>()) };
    // SAFETY: the returned buffer owns this live SID through the copy.
    unsafe { OwnedSid::copy_from(user.User.Sid) }
}

#[cfg(test)]
fn sid_to_string_for_test(sid: PSID) -> Result<String, ServiceRunStateError> {
    let mut text = PWSTR::null();
    // SAFETY: callers pass a canonical owned SID; output is LocalAlloc memory.
    unsafe { ConvertSidToStringSidW(sid, &raw mut text) }
        .map_err(|_| ServiceRunStateError::Security)?;
    if text.is_null() {
        return Err(ServiceRunStateError::Security);
    }
    // SAFETY: successful conversion returns a NUL-terminated allocation.
    let value = unsafe { text.to_string() }.map_err(|_| ServiceRunStateError::Security);
    // SAFETY: ConvertSidToStringSidW allocated this string with LocalAlloc.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(text.0.cast::<c_void>())));
    }
    value
}

#[cfg(test)]
fn wide_nul_for_test(value: &str) -> Result<Vec<u16>, ServiceRunStateError> {
    if value.encode_utf16().any(|unit| unit == 0) {
        return Err(ServiceRunStateError::Security);
    }
    let mut wide = value.encode_utf16().collect::<Vec<_>>();
    wide.push(0);
    Ok(wide)
}

fn reject_thread_impersonation() -> Result<(), ServiceRunStateError> {
    let mut token = HANDLE::default();
    // SAFETY: the pseudo-thread handle and query-only output are valid.
    match unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &raw mut token) } {
        Ok(()) if token.is_invalid() || token == INVALID_HANDLE_VALUE => {
            Err(ServiceRunStateError::Impersonation)
        }
        Ok(()) => {
            drop(OwnedHandle {
                state: HandleState::Open(token),
                role: HandleRole::Generic,
            });
            Err(ServiceRunStateError::Impersonation)
        }
        Err(error) if error.code() == ERROR_NO_TOKEN.to_hresult() => Ok(()),
        Err(_) => Err(ServiceRunStateError::Impersonation),
    }
}

fn impersonation_bookend<T>(
    operation: impl FnOnce() -> Result<T, ServiceRunStateError>,
) -> Result<T, ServiceRunStateError> {
    reject_thread_impersonation()?;
    let result = operation();
    let ending = reject_thread_impersonation();
    match (result, ending) {
        (_, Err(error)) => Err(error),
        (result, Ok(())) => result,
    }
}

fn fixed_program_data_path() -> Result<PathBuf, ServiceRunStateError> {
    // SAFETY: fixed known-folder GUID, default flags, and no token are valid.
    let raw = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, KF_FLAG_DEFAULT, None) }
        .map_err(|_| ServiceRunStateError::Location)?;
    if raw.is_null() {
        return Err(ServiceRunStateError::Location);
    }
    // SAFETY: success returns a NUL-terminated CoTaskMem allocation.
    let text = unsafe { raw.to_string() }.map_err(|_| ServiceRunStateError::Location);
    // SAFETY: SHGetKnownFolderPath allocated this one block with CoTaskMem.
    unsafe { CoTaskMemFree(Some(raw.0.cast::<c_void>())) };
    text.map(PathBuf::from)
}

fn local_drive_path_parts(path: &Path) -> Result<(PathBuf, Vec<String>), ServiceRunStateError> {
    let mut components = path.components();
    let disk = match (components.next(), components.next()) {
        (Some(Component::Prefix(prefix)), Some(Component::RootDir)) => match prefix.kind() {
            Prefix::Disk(letter) => letter,
            _ => return Err(ServiceRunStateError::Location),
        },
        _ => return Err(ServiceRunStateError::Location),
    };
    if path.as_os_str().encode_wide().any(|unit| unit == 0) {
        return Err(ServiceRunStateError::Location);
    }
    let mut names = Vec::new();
    for component in components {
        let Component::Normal(name) = component else {
            return Err(ServiceRunStateError::Location);
        };
        let name = name.to_str().ok_or(ServiceRunStateError::Location)?;
        validate_leaf(name)?;
        names.push(name.to_owned());
        if names.len() > 64 {
            return Err(ServiceRunStateError::Location);
        }
    }
    if names.is_empty() || !disk.is_ascii_alphabetic() {
        return Err(ServiceRunStateError::Location);
    }
    Ok((PathBuf::from(format!("{}:\\", char::from(disk))), names))
}

#[cfg(test)]
pub(super) fn validate_test_location_for_test(path: &Path) -> Result<(), ServiceRunStateError> {
    local_drive_path_parts(path).map(|_| ())
}

#[cfg(test)]
pub(super) fn validate_leaf_for_test(leaf: &str) -> Result<(), ServiceRunStateError> {
    validate_leaf(leaf)
}

fn validate_leaf(leaf: &str) -> Result<(), ServiceRunStateError> {
    if leaf.is_empty()
        || matches!(leaf, "." | "..")
        || leaf
            .encode_utf16()
            .any(|unit| matches!(unit, 0 | 47 | 58 | 92))
    {
        return Err(ServiceRunStateError::Location);
    }
    Ok(())
}

fn wide_path(path: &Path) -> Result<Vec<u16>, ServiceRunStateError> {
    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if wide.is_empty() || wide.contains(&0) {
        return Err(ServiceRunStateError::Location);
    }
    wide.push(0);
    Ok(wide)
}

struct OwnedHandle {
    state: HandleState,
    role: HandleRole,
}

enum HandleState {
    Open(HANDLE),
    Closed,
    CloseAmbiguous,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum HandleRole {
    Generic,
    Root,
    Lock,
    State,
    RevalidationRoot,
    RevalidationState,
}

impl OwnedHandle {
    fn new(raw: HANDLE) -> Result<Self, ServiceRunStateError> {
        if raw.is_invalid() || raw == INVALID_HANDLE_VALUE {
            return Err(ServiceRunStateError::Open);
        }
        Ok(Self {
            state: HandleState::Open(raw),
            role: HandleRole::Generic,
        })
    }

    fn raw(&self) -> HANDLE {
        match self.state {
            HandleState::Open(raw) => raw,
            HandleState::Closed | HandleState::CloseAmbiguous => HANDLE::default(),
        }
    }

    fn close_checked(&mut self) -> Result<(), ServiceRunStateError> {
        let state = core::mem::replace(&mut self.state, HandleState::CloseAmbiguous);
        let raw = match state {
            HandleState::Open(raw) => raw,
            HandleState::Closed => {
                self.state = HandleState::Closed;
                return Ok(());
            }
            HandleState::CloseAmbiguous => return Err(ServiceRunStateError::Release),
        };
        #[cfg(test)]
        let inject_ambiguous = take_close_fault_for_test(self.role);
        #[cfg(not(test))]
        let inject_ambiguous = false;
        // SAFETY: ownership is consumed exactly once even if Windows reports
        // ambiguous failure; neither retry nor Drop can double-close it.
        let result = unsafe { CloseHandle(raw) };
        if inject_ambiguous {
            return Err(ServiceRunStateError::Release);
        }
        match result {
            Ok(()) => {
                self.state = HandleState::Closed;
                #[cfg(test)]
                match self.role {
                    HandleRole::State => record_release_step_for_test(TestReleaseStep::StateClosed),
                    HandleRole::Lock => record_release_step_for_test(TestReleaseStep::LockClosed),
                    HandleRole::Root => record_release_step_for_test(TestReleaseStep::RootClosed),
                    HandleRole::Generic
                    | HandleRole::RevalidationRoot
                    | HandleRole::RevalidationState => {}
                }
                Ok(())
            }
            Err(_) => Err(ServiceRunStateError::Release),
        }
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        let state = core::mem::replace(&mut self.state, HandleState::Closed);
        if let HandleState::Open(raw) = state {
            // SAFETY: fallback Drop consumes the one still-owned handle and
            // intentionally cannot issue a checked release receipt.
            unsafe {
                let _ = CloseHandle(raw);
            }
        }
    }
}

impl fmt::Debug for OwnedHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OwnedHandle([REDACTED])")
    }
}

#[cfg(test)]
fn record_open_for_test() {
    TEST_OPEN_COUNT.with(|count| count.set(count.get().saturating_add(1)));
}

#[cfg(test)]
pub(super) fn reset_open_count_for_test() {
    TEST_OPEN_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(super) fn open_count_for_test() -> usize {
    TEST_OPEN_COUNT.with(Cell::get)
}

#[cfg(test)]
fn record_release_step_for_test(step: TestReleaseStep) {
    TEST_RELEASE_TRACE.with(|trace| trace.borrow_mut().push(step));
}

#[cfg(test)]
pub(super) fn take_release_trace_for_test() -> Vec<TestReleaseStep> {
    TEST_RELEASE_TRACE.with(|trace| core::mem::take(&mut *trace.borrow_mut()))
}

#[cfg(test)]
pub(super) fn inject_close_fault_for_test(fault: TestCloseFault) {
    let role = match fault {
        TestCloseFault::State => HandleRole::State,
        TestCloseFault::Lock => HandleRole::Lock,
        TestCloseFault::Root => HandleRole::Root,
        TestCloseFault::RevalidationRoot => HandleRole::RevalidationRoot,
        TestCloseFault::RevalidationState => HandleRole::RevalidationState,
    };
    TEST_CLOSE_FAULT.with(|slot| slot.set(Some(role)));
}

#[cfg(test)]
pub(super) fn inject_unlock_fault_for_test() {
    TEST_UNLOCK_FAULT.with(|slot| slot.set(true));
}

#[cfg(test)]
pub(super) fn inject_state_open_impersonation_fault_for_test(
    fault: TestStateOpenImpersonationFault,
) {
    TEST_STATE_OPEN_IMPERSONATION_FAULT.with(|slot| slot.set(Some(fault)));
}

#[cfg(test)]
pub(super) fn reset_state_native_open_count_for_test() {
    TEST_STATE_NATIVE_OPEN_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(super) fn state_native_open_count_for_test() -> usize {
    TEST_STATE_NATIVE_OPEN_COUNT.with(Cell::get)
}

#[cfg(test)]
fn take_state_open_impersonation_fault_for_test(expected: TestStateOpenImpersonationFault) -> bool {
    TEST_STATE_OPEN_IMPERSONATION_FAULT.with(|slot| {
        if slot.get() == Some(expected) {
            slot.set(None);
            true
        } else {
            false
        }
    })
}

#[cfg(test)]
fn run_impersonated_for_test<T>(
    operation: impl FnOnce() -> Result<T, ServiceRunStateError>,
) -> Result<T, ServiceRunStateError> {
    // SAFETY: this test-only token is reverted on the same thread before return.
    unsafe { ImpersonateSelf(SecurityImpersonation) }
        .map_err(|_| ServiceRunStateError::Impersonation)?;
    let result = operation();
    // SAFETY: ImpersonateSelf succeeded on this same test thread.
    let reverted = unsafe { RevertToSelf() }.map_err(|_| ServiceRunStateError::Impersonation);
    match (result, reverted) {
        (_, Err(error)) => Err(error),
        (result, Ok(())) => result,
    }
}

#[cfg(test)]
fn take_unlock_fault_for_test() -> bool {
    TEST_UNLOCK_FAULT.with(|slot| slot.replace(false))
}

#[cfg(test)]
fn take_close_fault_for_test(role: HandleRole) -> bool {
    TEST_CLOSE_FAULT.with(|slot| {
        if slot.get() == Some(role) {
            slot.set(None);
            true
        } else {
            false
        }
    })
}
