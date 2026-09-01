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
    FILE_ACCESS_INFORMATION, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_DISPOSITION_INFORMATION,
    FILE_MODE_INFORMATION, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
    FILE_RENAME_INFORMATION, FILE_RENAME_INFORMATION_0, FILE_STANDARD_INFORMATION,
    FILE_SYNCHRONOUS_IO_NONALERT, FILE_WRITE_THROUGH, FileAccessInformation,
    FileDispositionInformation, FileModeInformation, FileRenameInformation,
    FileStandardInformation, NtCreateFile, NtQueryInformationFile, NtSetInformationFile,
};
#[cfg(test)]
use windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_LOCK_VIOLATION, ERROR_NO_TOKEN, ERROR_SUCCESS, GENERIC_READ, GENERIC_WRITE,
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
    AclSizeInformation, AddAccessAllowedAceEx, AddAccessDeniedAceEx, CreateWellKnownSid,
    DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetLengthSid,
    GetSecurityDescriptorControl, InitializeAcl, InitializeSecurityDescriptor, IsValidAcl,
    IsValidSecurityDescriptor, IsValidSid, NO_INHERITANCE, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SE_DACL_AUTO_INHERIT_REQ, SE_DACL_DEFAULTED, SE_DACL_PRESENT,
    SE_DACL_PROTECTED, SE_OWNER_DEFAULTED, SE_SELF_RELATIVE, SECURITY_DESCRIPTOR,
    SetSecurityDescriptorControl, SetSecurityDescriptorDacl, SetSecurityDescriptorOwner,
    TOKEN_QUERY, WinCreatorOwnerRightsSid, WinLocalSystemSid,
};
#[cfg(test)]
use windows::Win32::Security::{
    CopySid, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetTokenInformation,
    ImpersonateSelf, RevertToSelf, SecurityImpersonation, TOKEN_USER, TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, DELETE, FILE_ACCESS_RIGHTS, FILE_ADD_FILE,
    FILE_ALL_ACCESS, FILE_ATTRIBUTE_COMPRESSED, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_ENCRYPTED,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_SPARSE_FILE, FILE_BEGIN, FILE_CASE_SENSITIVE_INFO, FILE_DELETE_CHILD,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_ID_INFO, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES,
    FILE_REMOTE_PROTOCOL_INFO, FILE_SHARE_DELETE, FILE_SHARE_MODE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_STREAM_INFO, FILE_TRAVERSE, FileCaseSensitiveInfo, FileIdInfo,
    FileRemoteProtocolInfo, FileStreamInfo, FlushFileBuffers, GetDriveTypeW,
    GetFileInformationByHandle, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
    GetVolumeInformationByHandleW, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
    OPEN_EXISTING, READ_CONTROL, ReadFile, SYNCHRONIZE, SetFilePointerEx, UnlockFileEx,
    VOLUME_NAME_GUID, WRITE_DAC, WRITE_OWNER, WriteFile,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::IO::{IO_STATUS_BLOCK, OVERLAPPED};
use windows::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, FILE_PERSISTENT_ACLS,
    SECURITY_DESCRIPTOR_REVISION,
};
#[cfg(test)]
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
use windows::Win32::System::WindowsProgramming::{DRIVE_FIXED, FILE_CREATED, FILE_OPENED};
use windows::Win32::UI::Shell::{FOLDERID_ProgramData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};
#[cfg(test)]
use windows::core::BOOL;
use windows::core::{PCWSTR, PWSTR};

use super::{
    ExactFixedRunStatePair, FIXED_RUN_STATE_RECORD_BYTES, FixedRunStatePairObservation,
    FixedRunStateRecordObservation, ServiceRunStateError,
};

const PRODUCT_LEAVES: [&str; 3] = ["YourWallet", "KeyAgent", "v1"];
const RUN_LOCK_LEAF: &str = "run.lock";
const STATE_LEAF: &str = "state";
const MARKER_FINAL_LEAF: &str = "marker.v1";
const MARKER_TEMP_LEAF: &str = "marker.tmp";
const CHECKPOINT_FINAL_LEAF: &str = "checkpt.v1";
const CHECKPOINT_TEMP_LEAF: &str = "checkpt.tmp";
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
const PAIR_CREATE_DESIRED_ACCESS: u32 = GENERIC_READ.0 | GENERIC_WRITE.0 | DELETE.0 | SYNCHRONIZE.0;
const PAIR_FINAL_OPEN_DESIRED_ACCESS: u32 = GENERIC_READ.0 | SYNCHRONIZE.0;
const PAIR_FINAL_GRANTED_ACCESS: u32 = FILE_GENERIC_READ.0;
const PAIR_TEMP_CLEANUP_DESIRED_ACCESS: u32 = GENERIC_READ.0 | DELETE.0 | SYNCHRONIZE.0;
const PAIR_TEMP_CLEANUP_GRANTED_ACCESS: u32 = FILE_GENERIC_READ.0 | DELETE.0;
const PAIR_FILE_ACCESS: u32 = FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | DELETE.0;
const PARENT_ACCESS: u32 =
    SYNCHRONIZE.0 | FILE_LIST_DIRECTORY.0 | FILE_TRAVERSE.0 | FILE_READ_ATTRIBUTES.0;
const OWNER_RIGHTS_DENY: u32 = WRITE_DAC.0 | WRITE_OWNER.0 | DELETE.0 | FILE_DELETE_CHILD.0;
const PAIR_OWNER_RIGHTS_DENY: u32 = WRITE_DAC.0 | WRITE_OWNER.0;
const PAIR_FILE_FORBIDDEN_SHAPE_ATTRIBUTES: u32 = FILE_ATTRIBUTE_DIRECTORY.0
    | FILE_ATTRIBUTE_READONLY.0
    | FILE_ATTRIBUTE_SPARSE_FILE.0
    | FILE_ATTRIBUTE_COMPRESSED.0
    | FILE_ATTRIBUTE_ENCRYPTED.0;

const fn pair_file_shape_attributes_are_supported(attributes: u32) -> bool {
    attributes & PAIR_FILE_FORBIDDEN_SHAPE_ATTRIBUTES == 0
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PairRecordKind {
    Marker,
    Checkpoint,
}

impl PairRecordKind {
    const fn final_leaf(self) -> &'static str {
        match self {
            Self::Marker => MARKER_FINAL_LEAF,
            Self::Checkpoint => CHECKPOINT_FINAL_LEAF,
        }
    }

    const fn temp_leaf(self) -> &'static str {
        match self {
            Self::Marker => MARKER_TEMP_LEAF,
            Self::Checkpoint => CHECKPOINT_TEMP_LEAF,
        }
    }

    const fn candidate(self, pair: &ExactFixedRunStatePair) -> &[u8; FIXED_RUN_STATE_RECORD_BYTES] {
        match self {
            Self::Marker => pair.marker(),
            Self::Checkpoint => pair.checkpoint(),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PairLeaf {
    MarkerFinal,
    MarkerTemp,
    CheckpointFinal,
    CheckpointTemp,
}

impl PairLeaf {
    const fn name(self) -> &'static str {
        match self {
            Self::MarkerFinal => MARKER_FINAL_LEAF,
            Self::MarkerTemp => MARKER_TEMP_LEAF,
            Self::CheckpointFinal => CHECKPOINT_FINAL_LEAF,
            Self::CheckpointTemp => CHECKPOINT_TEMP_LEAF,
        }
    }

    const fn for_record(record: PairRecordKind, temporary: bool) -> Self {
        match (record, temporary) {
            (PairRecordKind::Marker, false) => Self::MarkerFinal,
            (PairRecordKind::Marker, true) => Self::MarkerTemp,
            (PairRecordKind::Checkpoint, false) => Self::CheckpointFinal,
            (PairRecordKind::Checkpoint, true) => Self::CheckpointTemp,
        }
    }
}

#[cfg(test)]
pub(super) const ROOT_ACCESS_FOR_TEST: u32 = ROOT_ACCESS;
#[cfg(test)]
pub(super) const LOCK_ACCESS_FOR_TEST: u32 = LOCK_ACCESS;
#[cfg(test)]
pub(super) const STATE_ACCESS_FOR_TEST: u32 = STATE_ACCESS;
#[cfg(test)]
pub(super) const OWNER_RIGHTS_DENY_FOR_TEST: u32 = OWNER_RIGHTS_DENY;
#[cfg(test)]
pub(super) const PAIR_FILE_ACCESS_FOR_TEST: u32 = PAIR_FILE_ACCESS;
#[cfg(test)]
pub(super) const PAIR_CREATE_DESIRED_ACCESS_FOR_TEST: u32 = PAIR_CREATE_DESIRED_ACCESS;
#[cfg(test)]
pub(super) const PAIR_FINAL_OPEN_DESIRED_ACCESS_FOR_TEST: u32 = PAIR_FINAL_OPEN_DESIRED_ACCESS;
#[cfg(test)]
pub(super) const PAIR_FINAL_GRANTED_ACCESS_FOR_TEST: u32 = PAIR_FINAL_GRANTED_ACCESS;
#[cfg(test)]
pub(super) const PAIR_TEMP_CLEANUP_DESIRED_ACCESS_FOR_TEST: u32 = PAIR_TEMP_CLEANUP_DESIRED_ACCESS;
#[cfg(test)]
pub(super) const PAIR_TEMP_CLEANUP_GRANTED_ACCESS_FOR_TEST: u32 = PAIR_TEMP_CLEANUP_GRANTED_ACCESS;
#[cfg(test)]
pub(super) const PAIR_OWNER_RIGHTS_DENY_FOR_TEST: u32 = PAIR_OWNER_RIGHTS_DENY;

#[cfg(test)]
pub(super) const fn pair_leaf_names_for_test() -> [&'static str; 4] {
    [
        MARKER_FINAL_LEAF,
        MARKER_TEMP_LEAF,
        CHECKPOINT_FINAL_LEAF,
        CHECKPOINT_TEMP_LEAF,
    ]
}

#[cfg(test)]
pub(super) const fn pair_file_shape_attributes_are_supported_for_test(attributes: u32) -> bool {
    pair_file_shape_attributes_are_supported(attributes)
}

#[cfg(test)]
type TestPairProcessDeathHook = (TestPairProcessDeathCutpoint, Box<dyn FnOnce()>);

#[cfg(test)]
std::thread_local! {
    static TEST_OPEN_COUNT: Cell<usize> = const { Cell::new(0) };
    static TEST_RELEASE_TRACE: RefCell<Vec<TestReleaseStep>> = const { RefCell::new(Vec::new()) };
    static TEST_CLOSE_FAULT: Cell<Option<HandleRole>> = const { Cell::new(None) };
    static TEST_UNLOCK_FAULT: Cell<bool> = const { Cell::new(false) };
    static TEST_STATE_NATIVE_OPEN_COUNT: Cell<usize> = const { Cell::new(0) };
    static TEST_STATE_OPEN_IMPERSONATION_FAULT: Cell<Option<TestStateOpenImpersonationFault>> = const { Cell::new(None) };
    static TEST_PAIR_IMPERSONATION_FAULT: Cell<Option<TestPairImpersonationFault>> = const { Cell::new(None) };
    static TEST_PAIR_RENAME_COUNT: Cell<usize> = const { Cell::new(0) };
    static TEST_PAIR_INSPECT_COUNT: Cell<usize> = const { Cell::new(0) };
    static TEST_PAIR_BEFORE_SECOND_CAS: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    static TEST_PAIR_MARKER_ATTEMPT_FAILURE: Cell<bool> = const { Cell::new(false) };
    static TEST_PAIR_ARM_COMMITTED_REREAD_FAILURE: Cell<bool> = const { Cell::new(false) };
    static TEST_PAIR_RECORD_IO_FAULT: Cell<Option<TestPairRecordIoFault>> = const { Cell::new(None) };
    static TEST_PAIR_PROCESS_DEATH_CUTPOINT: RefCell<Option<TestPairProcessDeathHook>> = const { RefCell::new(None) };
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
    PairCheckpointClosed,
    PairMarkerClosed,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TestCloseFault {
    State,
    Lock,
    Root,
    RevalidationRoot,
    RevalidationState,
    PairMarkerTemp,
    PairCheckpointTemp,
    PairMarkerFinal,
    PairCheckpointFinal,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TestStateOpenImpersonationFault {
    BeforeNativeOpen,
    AfterNativeOpen,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TestPairImpersonationFault {
    BeforeInspect,
    AfterInspect,
    BeforeMarker,
    AfterMarker,
    BeforeCheckpoint,
    AfterCheckpoint,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TestPairRecordIoFault {
    MarkerShortWrite,
    MarkerFlush,
    CheckpointShortWrite,
    CheckpointFlush,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::enum_variant_names)] // Exact names mirror the two-record protocol.
pub(super) enum TestPairProcessDeathCutpoint {
    BeforeMarkerRename,
    AfterMarkerRename,
    AfterCheckpointRename,
}

#[cfg(test)]
#[derive(Debug, Eq, PartialEq)]
pub(super) struct TestPairRenamePacketSnapshot {
    pub(super) leaf: &'static str,
    pub(super) replace_if_exists: bool,
    pub(super) root_matches: bool,
    pub(super) anonymous_offset: usize,
    pub(super) root_directory_offset: usize,
    pub(super) file_name_length_offset: usize,
    pub(super) file_name_offset: usize,
    pub(super) struct_size: usize,
    pub(super) struct_alignment: usize,
    pub(super) file_name_length_bytes: u32,
    pub(super) packet_byte_count: u32,
    pub(super) backing_byte_count: usize,
    pub(super) file_name: Vec<u16>,
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

/// Absolute descriptor and ACL storage kept live across one from-birth create.
struct PairFileSecurityDescriptor {
    descriptor: SECURITY_DESCRIPTOR,
    _acl_words: Box<[usize]>,
    _owner_rights: OwnedSid,
}

impl PairFileSecurityDescriptor {
    fn new(policy: &SecurityPolicy) -> Result<Self, ServiceRunStateError> {
        policy.validate()?;
        let owner_rights = OwnedSid::well_known(WinCreatorOwnerRightsSid)?;
        let acl_bytes = exact_acl_bytes(&[
            owner_rights.as_psid(),
            policy.service_sid.as_psid(),
            policy.system_sid.as_psid(),
        ])?;
        let word_size = size_of::<usize>();
        let words = acl_bytes
            .checked_add(word_size - 1)
            .and_then(|value| value.checked_div(word_size))
            .ok_or(ServiceRunStateError::Security)?;
        let mut acl_words = vec![0_usize; words].into_boxed_slice();
        let acl = acl_words.as_mut_ptr().cast::<ACL>();
        // SAFETY: aligned zeroed storage owns exactly the ACL capacity passed
        // here, and all three complete SIDs outlive this builder and create.
        unsafe {
            InitializeAcl(
                acl,
                u32::try_from(acl_bytes).map_err(|_| ServiceRunStateError::Security)?,
                ACL_REVISION,
            )
            .map_err(|_| ServiceRunStateError::Security)?;
            AddAccessDeniedAceEx(
                acl,
                ACL_REVISION,
                NO_INHERITANCE,
                PAIR_OWNER_RIGHTS_DENY,
                owner_rights.as_psid(),
            )
            .map_err(|_| ServiceRunStateError::Security)?;
            AddAccessAllowedAceEx(
                acl,
                ACL_REVISION,
                NO_INHERITANCE,
                PAIR_FILE_ACCESS,
                policy.service_sid.as_psid(),
            )
            .map_err(|_| ServiceRunStateError::Security)?;
            AddAccessAllowedAceEx(
                acl,
                ACL_REVISION,
                NO_INHERITANCE,
                FILE_ALL_ACCESS.0,
                policy.system_sid.as_psid(),
            )
            .map_err(|_| ServiceRunStateError::Security)?;
        }
        let mut descriptor = SECURITY_DESCRIPTOR::default();
        // SAFETY: the absolute descriptor and ACL are writable and all
        // referenced SIDs remain live in `policy` or the returned wrapper.
        unsafe {
            InitializeSecurityDescriptor(
                PSECURITY_DESCRIPTOR(ptr::from_mut(&mut descriptor).cast::<c_void>()),
                SECURITY_DESCRIPTOR_REVISION,
            )
            .map_err(|_| ServiceRunStateError::Security)?;
            SetSecurityDescriptorOwner(
                PSECURITY_DESCRIPTOR(ptr::from_mut(&mut descriptor).cast::<c_void>()),
                Some(policy.service_sid.as_psid()),
                false,
            )
            .map_err(|_| ServiceRunStateError::Security)?;
            SetSecurityDescriptorDacl(
                PSECURITY_DESCRIPTOR(ptr::from_mut(&mut descriptor).cast::<c_void>()),
                true,
                Some(acl.cast_const()),
                false,
            )
            .map_err(|_| ServiceRunStateError::Security)?;
            SetSecurityDescriptorControl(
                PSECURITY_DESCRIPTOR(ptr::from_mut(&mut descriptor).cast::<c_void>()),
                SE_DACL_PROTECTED,
                SE_DACL_PROTECTED,
            )
            .map_err(|_| ServiceRunStateError::Security)?;
        }
        Ok(Self {
            descriptor,
            _acl_words: acl_words,
            _owner_rights: owner_rights,
        })
    }

    fn as_ptr(&self) -> *const SECURITY_DESCRIPTOR {
        ptr::from_ref(&self.descriptor)
    }
}

fn exact_acl_bytes(sids: &[PSID; 3]) -> Result<usize, ServiceRunStateError> {
    sids.iter().try_fold(size_of::<ACL>(), |total, sid| {
        // SAFETY: every caller supplies one validated owned SID.
        let sid_bytes = usize::try_from(unsafe { GetLengthSid(*sid) })
            .map_err(|_| ServiceRunStateError::Security)?;
        total
            .checked_add(offset_of!(ACCESS_ALLOWED_ACE, SidStart))
            .and_then(|value| value.checked_add(sid_bytes))
            .ok_or(ServiceRunStateError::Security)
    })
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
pub(super) fn exact_pair_file_sddl_for_test() -> Result<String, ServiceRunStateError> {
    let policy = current_user_test_policy()?;
    let service = sid_to_string_for_test(policy.service_sid.as_psid())?;
    Ok(format!(
        "O:{service}D:P(D;;0x{PAIR_OWNER_RIGHTS_DENY:08x};;;OW)(A;;0x{PAIR_FILE_ACCESS:08x};;;{service})(A;;0x{:08x};;;SY)",
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
    verify_exact_security(handle.raw(), &policy, OWNER_RIGHTS_DENY, service_mask)
}

#[cfg(test)]
pub(super) fn verify_pair_file_security_for_test(path: &Path) -> Result<(), ServiceRunStateError> {
    let wide = wide_path(path)?;
    // SAFETY: this opens only the exact existing fixed-record fixture.
    let raw = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            READ_CONTROL.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|_| ServiceRunStateError::Security)?;
    let handle = OwnedHandle::new(raw).map_err(|_| ServiceRunStateError::Security)?;
    let policy = current_user_test_policy()?;
    verify_exact_security(
        handle.raw(),
        &policy,
        PAIR_OWNER_RIGHTS_DENY,
        PAIR_FILE_ACCESS,
    )
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
        inspect_security_descriptor(
            descriptor,
            owner,
            dacl,
            &policy,
            OWNER_RIGHTS_DENY,
            service_mask,
        )
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
            pair_receipt_poisoned: false,
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
    pair_receipt_poisoned: bool,
}

impl HeldWriter {
    pub(super) fn revalidate(&self) -> Result<(), ServiceRunStateError> {
        impersonation_bookend(|| self.revalidate_inner())
    }

    fn revalidate_inner(&self) -> Result<(), ServiceRunStateError> {
        if !self.range_lock_held || self.pair_receipt_poisoned {
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
        let pair_receipt_poisoned = self.pair_receipt_poisoned;
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
        let result = state_result
            .and(unlock_result)
            .and(lock_result)
            .and(root_result);
        if pair_receipt_poisoned {
            Err(ServiceRunStateError::Release)
        } else {
            result
        }
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

#[derive(Clone, Copy, Eq, PartialEq)]
struct PairLeafSnapshot {
    observation: FixedRunStateRecordObservation,
    identity: Option<ObjectIdentity>,
    length: Option<usize>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct PairSnapshot {
    marker: PairLeafSnapshot,
    checkpoint: PairLeafSnapshot,
}

impl PairSnapshot {
    const fn observation(self) -> FixedRunStatePairObservation {
        FixedRunStatePairObservation::new(self.marker.observation, self.checkpoint.observation)
    }

    fn is_exact_candidate(&self, candidate: &ExactFixedRunStatePair) -> bool {
        self.marker.observation == FixedRunStateRecordObservation::Exact(*candidate.marker())
            && self.checkpoint.observation
                == FixedRunStateRecordObservation::Exact(*candidate.checkpoint())
    }

    fn is_committable(&self) -> bool {
        matches!(
            (self.marker.observation, self.checkpoint.observation),
            (
                FixedRunStateRecordObservation::Missing,
                FixedRunStateRecordObservation::Missing
            ) | (
                FixedRunStateRecordObservation::Exact(_),
                FixedRunStateRecordObservation::Exact(_)
            )
        )
    }

    fn is_exact_pair(&self) -> bool {
        pair_leaf_snapshot_is_exact(&self.marker) && pair_leaf_snapshot_is_exact(&self.checkpoint)
    }

    fn exact_pair(&self) -> Option<ExactFixedRunStatePair> {
        let FixedRunStateRecordObservation::Exact(marker) = self.marker.observation else {
            return None;
        };
        let FixedRunStateRecordObservation::Exact(checkpoint) = self.checkpoint.observation else {
            return None;
        };
        self.is_exact_pair()
            .then(|| ExactFixedRunStatePair::new(marker, checkpoint))
    }
}

fn pair_leaf_snapshot_is_exact(snapshot: &PairLeafSnapshot) -> bool {
    matches!(
        snapshot.observation,
        FixedRunStateRecordObservation::Exact(_)
    ) && snapshot.identity.is_some()
        && snapshot.length == Some(FIXED_RUN_STATE_RECORD_BYTES)
}

pub(super) struct PairFailure {
    pub(super) inner: HeldWriter,
    pub(super) cause: ServiceRunStateError,
}

#[allow(clippy::large_enum_variant)] // Inline terminal authority avoids fallible allocation.
pub(super) enum PairReleaseFailure {
    WriterRetained(PairReleaseWithWriter),
    WriterReleasedNoReceipt(ServiceRunStateError),
}

pub(super) struct PairReleaseWithWriter {
    inner: HeldWriter,
    handles: PairReleaseHandles,
    pub(super) cause: ServiceRunStateError,
}

impl PairReleaseWithWriter {
    pub(super) fn retire(self) -> Result<(), ServiceRunStateError> {
        let Self {
            inner,
            mut handles,
            cause: _,
        } = self;
        // The pair handles remain held while every remaining writer authority
        // is terminally retired. Both independent cleanup paths are attempted.
        let writer = inner.retire();
        let pair = handles.close_all_checked();
        writer.and(pair)
    }
}

pub(super) struct ObservedPairWriter {
    inner: HeldWriter,
    expected: PairSnapshot,
}

impl ObservedPairWriter {
    pub(super) const fn observation(&self) -> FixedRunStatePairObservation {
        self.expected.observation()
    }

    #[allow(clippy::large_types_passed_by_value)] // One-shot candidate ownership is intentional.
    pub(super) fn compare_and_replace(
        self,
        candidate: ExactFixedRunStatePair,
    ) -> PairCommitOutcome {
        commit_observed_pair(self.inner, self.expected, candidate)
    }

    #[allow(clippy::result_large_err)] // Failure retains writer and pair handles inline.
    pub(super) fn release_verified(self) -> Result<ExactFixedRunStatePair, PairReleaseFailure> {
        let Self { inner, expected } = self;
        release_snapshot_verified(inner, &expected)
    }

    pub(super) fn retire(self) -> Result<(), ServiceRunStateError> {
        self.inner.retire()
    }
}

#[allow(clippy::large_enum_variant)] // Inline move-only authority avoids fallible allocation.
pub(super) enum PairCommitOutcome {
    Committed(CommittedPairWriter),
    KnownNotCommitted(PairFailure),
    Ambiguous(AmbiguousPairWriter, ServiceRunStateError),
}

pub(super) struct CommittedPairWriter {
    inner: HeldWriter,
    candidate: ExactFixedRunStatePair,
}

impl CommittedPairWriter {
    pub(super) const fn candidate(&self) -> ExactFixedRunStatePair {
        self.candidate
    }

    #[allow(clippy::result_large_err)] // Ambiguity must retain the complete writer inline.
    pub(super) fn reread(
        self,
    ) -> Result<RereadPairWriter, (AmbiguousPairWriter, ServiceRunStateError)> {
        let Self {
            mut inner,
            candidate,
        } = self;
        let reread = (|| {
            inner.revalidate()?;
            observe_pair_snapshot_reopened(&mut inner)
        })();
        match reread {
            Ok(observed) if observed.is_exact_candidate(&candidate) => Ok(RereadPairWriter {
                inner,
                snapshot: observed,
            }),
            Ok(_) => Err((
                AmbiguousPairWriter::installed_pair(inner),
                ServiceRunStateError::Compare,
            )),
            Err(cause) => Err((AmbiguousPairWriter::installed_pair(inner), cause)),
        }
    }

    pub(super) fn retire(self) -> Result<(), ServiceRunStateError> {
        self.inner.retire()
    }
}

pub(super) struct RereadPairWriter {
    inner: HeldWriter,
    snapshot: PairSnapshot,
}

impl RereadPairWriter {
    pub(super) const fn observation(&self) -> FixedRunStatePairObservation {
        self.snapshot.observation()
    }

    pub(super) fn continue_observed(self) -> ObservedPairWriter {
        ObservedPairWriter {
            inner: self.inner,
            expected: self.snapshot,
        }
    }

    #[cfg(test)]
    pub(super) fn into_writer(self) -> HeldWriter {
        self.inner
    }

    pub(super) fn retire(self) -> Result<(), ServiceRunStateError> {
        self.inner.retire()
    }
}

pub(super) struct AmbiguousPairWriter {
    inner: HeldWriter,
    context: PairAmbiguityContext,
}

impl AmbiguousPairWriter {
    const fn marker_rename(
        inner: HeldWriter,
        marker_temp: ObjectIdentity,
        checkpoint_temp: ObjectIdentity,
    ) -> Self {
        Self {
            inner,
            context: PairAmbiguityContext::MarkerRename {
                marker_temp,
                checkpoint_temp,
            },
        }
    }

    const fn marker_installed(inner: HeldWriter, checkpoint_temp: ObjectIdentity) -> Self {
        Self {
            inner,
            context: PairAmbiguityContext::MarkerInstalled { checkpoint_temp },
        }
    }

    const fn checkpoint_rename(inner: HeldWriter, checkpoint_temp: ObjectIdentity) -> Self {
        Self {
            inner,
            context: PairAmbiguityContext::CheckpointRename { checkpoint_temp },
        }
    }

    const fn installed_pair(inner: HeldWriter) -> Self {
        Self {
            inner,
            context: PairAmbiguityContext::InstalledPair,
        }
    }

    #[allow(clippy::result_large_err)] // Failure must retain the complete writer inline.
    pub(super) fn reload(mut self) -> Result<ReloadedPairWriter, AmbiguousPairFailure> {
        let result = (|| {
            self.inner.revalidate()?;
            clear_ambiguity_bound_pair_temps(&mut self.inner, self.context)?;
            observe_pair_snapshot_reopened(&mut self.inner)
        })();
        match result {
            Ok(observed) => Ok(ReloadedPairWriter {
                inner: self.inner,
                snapshot: observed,
            }),
            Err(cause) => Err(AmbiguousPairFailure { inner: self, cause }),
        }
    }

    pub(super) fn retire(mut self) -> Result<(), ServiceRunStateError> {
        let cleanup = clear_ambiguity_bound_pair_temps(&mut self.inner, self.context);
        let retire = self.inner.retire();
        cleanup.and(retire)
    }
}

#[derive(Clone, Copy)]
enum PairAmbiguityContext {
    MarkerRename {
        marker_temp: ObjectIdentity,
        checkpoint_temp: ObjectIdentity,
    },
    MarkerInstalled {
        checkpoint_temp: ObjectIdentity,
    },
    CheckpointRename {
        checkpoint_temp: ObjectIdentity,
    },
    InstalledPair,
}

pub(super) struct AmbiguousPairFailure {
    pub(super) inner: AmbiguousPairWriter,
    pub(super) cause: ServiceRunStateError,
}

pub(super) struct ReloadedPairWriter {
    inner: HeldWriter,
    snapshot: PairSnapshot,
}

impl ReloadedPairWriter {
    pub(super) const fn observation(&self) -> FixedRunStatePairObservation {
        self.snapshot.observation()
    }

    pub(super) fn continue_observed(self) -> ObservedPairWriter {
        ObservedPairWriter {
            inner: self.inner,
            expected: self.snapshot,
        }
    }

    #[cfg(test)]
    pub(super) fn into_writer(self) -> HeldWriter {
        self.inner
    }

    pub(super) fn retire(self) -> Result<(), ServiceRunStateError> {
        self.inner.retire()
    }
}

impl HeldWriter {
    #[allow(clippy::result_large_err)] // Failure must retain the complete writer inline.
    pub(super) fn observe_fixed_pair(mut self) -> Result<ObservedPairWriter, PairFailure> {
        let result = (|| {
            self.revalidate()?;
            clear_stale_pair_temps(&mut self)?;
            observe_pair_snapshot_reopened(&mut self)
        })();
        match result {
            Ok(expected) => Ok(ObservedPairWriter {
                inner: self,
                expected,
            }),
            Err(cause) => Err(PairFailure { inner: self, cause }),
        }
    }

    fn state_handle(&self) -> Result<HANDLE, ServiceRunStateError> {
        self.state
            .as_ref()
            .map(OwnedHandle::raw)
            .filter(|handle| !handle.is_invalid() && *handle != INVALID_HANDLE_VALUE)
            .ok_or(ServiceRunStateError::Release)
    }

    fn poison_pair_receipt(&mut self) {
        self.pair_receipt_poisoned = true;
    }
}

impl fmt::Debug for ObservedPairWriter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ObservedPairWriter([REDACTED])")
    }
}

impl fmt::Debug for CommittedPairWriter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CommittedPairWriter([REDACTED])")
    }
}

impl fmt::Debug for AmbiguousPairWriter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AmbiguousPairWriter([REDACTED])")
    }
}

impl fmt::Debug for RereadPairWriter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RereadPairWriter([REDACTED])")
    }
}

impl fmt::Debug for ReloadedPairWriter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReloadedPairWriter([REDACTED])")
    }
}

impl fmt::Debug for PairReleaseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WriterRetained(failure) => formatter
                .debug_tuple("WriterRetained")
                .field(&failure.cause)
                .finish(),
            Self::WriterReleasedNoReceipt(cause) => formatter
                .debug_tuple("WriterReleasedNoReceipt")
                .field(cause)
                .finish(),
        }
    }
}

#[derive(Default)]
struct PairReleaseHandles {
    marker_final: Option<OwnedHandle>,
    checkpoint_final: Option<OwnedHandle>,
    marker_temp: Option<OwnedHandle>,
    checkpoint_temp: Option<OwnedHandle>,
}

impl PairReleaseHandles {
    fn slot_mut(&mut self, leaf: PairLeaf) -> &mut Option<OwnedHandle> {
        match leaf {
            PairLeaf::MarkerFinal => &mut self.marker_final,
            PairLeaf::MarkerTemp => &mut self.marker_temp,
            PairLeaf::CheckpointFinal => &mut self.checkpoint_final,
            PairLeaf::CheckpointTemp => &mut self.checkpoint_temp,
        }
    }

    fn close_all_checked(&mut self) -> Result<(), ServiceRunStateError> {
        let checkpoint_final = close_optional_pair_handle(&mut self.checkpoint_final);
        let marker_final = close_optional_pair_handle(&mut self.marker_final);
        let checkpoint_temp = close_optional_pair_handle(&mut self.checkpoint_temp);
        let marker_temp = close_optional_pair_handle(&mut self.marker_temp);
        checkpoint_final
            .and(marker_final)
            .and(checkpoint_temp)
            .and(marker_temp)
    }
}

fn close_optional_pair_handle(
    handle: &mut Option<OwnedHandle>,
) -> Result<(), ServiceRunStateError> {
    handle.as_mut().map_or(Ok(()), OwnedHandle::close_checked)
}

#[allow(clippy::result_large_err)] // Failure retains the writer and held pair handles inline.
fn release_snapshot_verified(
    writer: HeldWriter,
    expected: &PairSnapshot,
) -> Result<ExactFixedRunStatePair, PairReleaseFailure> {
    let mut handles = PairReleaseHandles::default();
    let Some(exact_pair) = expected.exact_pair() else {
        return Err(PairReleaseFailure::WriterRetained(PairReleaseWithWriter {
            inner: writer,
            handles,
            cause: ServiceRunStateError::Shape,
        }));
    };
    let verification = (|| {
        writer.revalidate()?;
        hold_exact_pair_final(
            &writer,
            &mut handles,
            PairLeaf::MarkerFinal,
            expected.marker,
        )?;
        hold_exact_pair_final(
            &writer,
            &mut handles,
            PairLeaf::CheckpointFinal,
            expected.checkpoint,
        )?;
        require_pair_temp_missing(&writer, &mut handles, PairLeaf::MarkerTemp)?;
        require_pair_temp_missing(&writer, &mut handles, PairLeaf::CheckpointTemp)
    })();
    if let Err(cause) = verification {
        return Err(PairReleaseFailure::WriterRetained(PairReleaseWithWriter {
            inner: writer,
            handles,
            cause,
        }));
    }

    match writer.release_verified() {
        Err(ReleaseFailure { inner, cause }) => {
            Err(PairReleaseFailure::WriterRetained(PairReleaseWithWriter {
                inner,
                handles,
                cause,
            }))
        }
        Ok(()) => match handles.close_all_checked() {
            Ok(()) => Ok(exact_pair),
            Err(cause) => Err(PairReleaseFailure::WriterReleasedNoReceipt(cause)),
        },
    }
}

fn hold_exact_pair_final(
    writer: &HeldWriter,
    handles: &mut PairReleaseHandles,
    leaf: PairLeaf,
    expected: PairLeafSnapshot,
) -> Result<(), ServiceRunStateError> {
    let opened = open_existing_pair_leaf(writer.state_handle()?, leaf)?;
    let PairLeafOpen::Opened(opened) = opened else {
        return Err(ServiceRunStateError::Missing);
    };
    let OpenedPairLeaf {
        handle,
        status_error,
        information,
    } = opened;
    *handles.slot_mut(leaf) = Some(handle);
    require_pair_open(status_error, information)?;
    let current = inspect_pair_file(
        handles
            .slot_mut(leaf)
            .as_ref()
            .ok_or(ServiceRunStateError::Release)?
            .raw(),
        &writer.root.expected.policy,
        writer.root.expected.root_identity.volume_serial_number,
        PAIR_FINAL_GRANTED_ACCESS,
    )?;
    if current.identity != expected.identity {
        return Err(ServiceRunStateError::Identity);
    }
    if current.length != expected.length {
        return Err(ServiceRunStateError::Shape);
    }
    if current.observation != expected.observation {
        return Err(ServiceRunStateError::Compare);
    }
    Ok(())
}

fn require_pair_temp_missing(
    writer: &HeldWriter,
    handles: &mut PairReleaseHandles,
    leaf: PairLeaf,
) -> Result<(), ServiceRunStateError> {
    let opened = open_existing_pair_leaf(writer.state_handle()?, leaf)?;
    let PairLeafOpen::Opened(opened) = opened else {
        return Ok(());
    };
    let OpenedPairLeaf {
        handle,
        status_error,
        information,
    } = opened;
    *handles.slot_mut(leaf) = Some(handle);
    require_pair_open(status_error, information)?;
    Err(ServiceRunStateError::Shape)
}

struct OpenedPairLeaf {
    handle: OwnedHandle,
    status_error: Option<ServiceRunStateError>,
    information: usize,
}

enum PairLeafOpen {
    Missing,
    Opened(OpenedPairLeaf),
}

fn open_existing_pair_leaf(
    parent: HANDLE,
    leaf: PairLeaf,
) -> Result<PairLeafOpen, ServiceRunStateError> {
    pair_leaf_native_open(
        parent,
        leaf,
        PAIR_FINAL_OPEN_DESIRED_ACCESS,
        FILE_OPEN,
        None,
    )
}

fn create_pair_temp(
    parent: HANDLE,
    record: PairRecordKind,
    policy: &SecurityPolicy,
) -> Result<OpenedPairLeaf, ServiceRunStateError> {
    let descriptor = PairFileSecurityDescriptor::new(policy)?;
    match pair_leaf_native_open(
        parent,
        PairLeaf::for_record(record, true),
        PAIR_CREATE_DESIRED_ACCESS,
        FILE_CREATE,
        Some(descriptor.as_ptr()),
    )? {
        PairLeafOpen::Opened(opened) => Ok(opened),
        PairLeafOpen::Missing => Err(ServiceRunStateError::Open),
    }
}

fn pair_leaf_native_open(
    parent: HANDLE,
    leaf: PairLeaf,
    desired_access: u32,
    disposition: windows::Wdk::Storage::FileSystem::NTCREATEFILE_CREATE_DISPOSITION,
    security_descriptor: Option<*const SECURITY_DESCRIPTOR>,
) -> Result<PairLeafOpen, ServiceRunStateError> {
    let leaf_name = leaf.name();
    validate_leaf(leaf_name)?;
    reject_thread_impersonation()?;
    let mut name = leaf_name.encode_utf16().collect::<Vec<_>>();
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
        SecurityDescriptor: security_descriptor.unwrap_or(ptr::null()),
        SecurityQualityOfService: ptr::null(),
    };
    let mut io = IO_STATUS_BLOCK::default();
    let mut raw = HANDLE::default();
    #[cfg(test)]
    record_open_for_test();
    // SAFETY: the held state directory, fixed UTF-16 leaf, optional live
    // descriptor, and exact native outputs remain valid for this call.
    let status = unsafe {
        NtCreateFile(
            &raw mut raw,
            FILE_ACCESS_RIGHTS(desired_access),
            &raw const attributes,
            &raw mut io,
            None,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_MODE(0),
            disposition,
            FILE_NON_DIRECTORY_FILE
                | FILE_OPEN_REPARSE_POINT
                | FILE_SYNCHRONOUS_IO_NONALERT
                | FILE_WRITE_THROUGH,
            None,
            0,
        )
    };
    let missing = disposition == FILE_OPEN
        && status == STATUS_OBJECT_NAME_NOT_FOUND
        && (raw.is_invalid() || raw == INVALID_HANDLE_VALUE);
    let mut status_error = if status == STATUS_SUCCESS {
        // SAFETY: the synchronous native call initialized Status.
        let io_status = unsafe { io.Anonymous.Status };
        (io_status != STATUS_SUCCESS).then_some(ServiceRunStateError::Open)
    } else {
        Some(map_open_status(status))
    };
    let ending = reject_thread_impersonation();
    if missing {
        ending?;
        return Ok(PairLeafOpen::Missing);
    }
    if raw.is_invalid() || raw == INVALID_HANDLE_VALUE {
        ending?;
        return Err(status_error.unwrap_or(ServiceRunStateError::Open));
    }
    let mut handle = OwnedHandle::new(raw)?;
    handle.role = HandleRole::from_pair_leaf(leaf);
    if let Err(error) = ending {
        status_error = Some(error);
    }
    Ok(PairLeafOpen::Opened(OpenedPairLeaf {
        handle,
        status_error,
        information: io.Information,
    }))
}

fn observe_pair_snapshot(writer: &mut HeldWriter) -> Result<PairSnapshot, ServiceRunStateError> {
    let marker = observe_pair_leaf(writer, PairLeaf::MarkerFinal)?;
    let checkpoint = observe_pair_leaf(writer, PairLeaf::CheckpointFinal)?;
    Ok(PairSnapshot { marker, checkpoint })
}

fn observe_pair_snapshot_reopened(
    writer: &mut HeldWriter,
) -> Result<PairSnapshot, ServiceRunStateError> {
    let first = observe_pair_snapshot(writer)?;
    let reopened = observe_pair_snapshot(writer)?;
    if first == reopened {
        Ok(reopened)
    } else {
        Err(ServiceRunStateError::Compare)
    }
}

fn observe_pair_leaf(
    writer: &mut HeldWriter,
    leaf: PairLeaf,
) -> Result<PairLeafSnapshot, ServiceRunStateError> {
    let parent = writer.state_handle()?;
    let opened = open_existing_pair_leaf(parent, leaf)?;
    let PairLeafOpen::Opened(mut opened) = opened else {
        return Ok(PairLeafSnapshot {
            observation: FixedRunStateRecordObservation::Missing,
            identity: None,
            length: None,
        });
    };
    let verification = (|| {
        require_pair_open(opened.status_error, opened.information)?;
        inspect_pair_file(
            opened.handle.raw(),
            &writer.root.expected.policy,
            writer.root.expected.root_identity.volume_serial_number,
            PAIR_FINAL_GRANTED_ACCESS,
        )
    })();
    if opened.handle.close_checked().is_err() {
        writer.poison_pair_receipt();
        return Err(ServiceRunStateError::Release);
    }
    verification
}

fn inspect_pair_file(
    handle: HANDLE,
    policy: &SecurityPolicy,
    root_volume: u64,
    expected_granted_access: u32,
) -> Result<PairLeafSnapshot, ServiceRunStateError> {
    #[cfg(test)]
    if take_pair_impersonation_fault_for_test(TestPairImpersonationFault::BeforeInspect) {
        return run_impersonated_for_test(|| {
            reject_thread_impersonation()?;
            Err(ServiceRunStateError::Impersonation)
        });
    }
    reject_thread_impersonation()?;
    #[cfg(test)]
    TEST_PAIR_INSPECT_COUNT.with(|count| count.set(count.get().saturating_add(1)));
    let operation = inspect_pair_file_inner(handle, policy, root_volume, expected_granted_access);
    #[cfg(test)]
    let inject_after =
        take_pair_impersonation_fault_for_test(TestPairImpersonationFault::AfterInspect);
    #[cfg(test)]
    let ending = if inject_after {
        run_impersonated_for_test(reject_thread_impersonation)
    } else {
        reject_thread_impersonation()
    };
    #[cfg(not(test))]
    let ending = reject_thread_impersonation();
    match (operation, ending) {
        (_, Err(cause)) => Err(cause),
        (result, Ok(())) => result,
    }
}

fn inspect_pair_file_inner(
    handle: HANDLE,
    policy: &SecurityPolicy,
    root_volume: u64,
    expected_granted_access: u32,
) -> Result<PairLeafSnapshot, ServiceRunStateError> {
    verify_handle_flags_zero(handle)?;
    verify_exact_granted_access(handle, expected_granted_access)?;
    verify_supported_local_ntfs(handle)?;
    verify_exact_security(handle, policy, PAIR_OWNER_RIGHTS_DENY, PAIR_FILE_ACCESS)?;
    let (identity, length) = pair_file_identity_and_length(handle)?;
    if identity.volume_serial_number != root_volume {
        return Err(ServiceRunStateError::Identity);
    }
    let observation = if length == FIXED_RUN_STATE_RECORD_BYTES {
        FixedRunStateRecordObservation::Exact(read_exact_pair_record(handle)?)
    } else {
        FixedRunStateRecordObservation::Malformed
    };
    Ok(PairLeafSnapshot {
        observation,
        identity: Some(identity),
        length: Some(length),
    })
}

fn require_pair_open(
    status_error: Option<ServiceRunStateError>,
    information: usize,
) -> Result<(), ServiceRunStateError> {
    if let Some(cause) = status_error {
        return Err(cause);
    }
    if information == usize::try_from(FILE_OPENED).map_err(|_| ServiceRunStateError::Open)? {
        Ok(())
    } else {
        Err(ServiceRunStateError::Open)
    }
}

fn require_pair_created(
    status_error: Option<ServiceRunStateError>,
    information: usize,
) -> Result<(), ServiceRunStateError> {
    if let Some(cause) = status_error {
        return Err(cause);
    }
    if information == usize::try_from(FILE_CREATED).map_err(|_| ServiceRunStateError::Open)? {
        Ok(())
    } else {
        Err(ServiceRunStateError::Open)
    }
}

fn pair_file_identity_and_length(
    handle: HANDLE,
) -> Result<(ObjectIdentity, usize), ServiceRunStateError> {
    impersonation_bookend(|| pair_file_identity_and_length_inner(handle))
}

fn pair_file_identity_and_length_inner(
    handle: HANDLE,
) -> Result<(ObjectIdentity, usize), ServiceRunStateError> {
    let basic = basic_information(handle)?;
    if basic.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(ServiceRunStateError::Reparse);
    }
    if !pair_file_shape_attributes_are_supported(basic.dwFileAttributes)
        || basic.nNumberOfLinks != 1
    {
        return Err(ServiceRunStateError::Shape);
    }
    let mut io = IO_STATUS_BLOCK::default();
    let mut standard = FILE_STANDARD_INFORMATION::default();
    let length = u32::try_from(size_of::<FILE_STANDARD_INFORMATION>())
        .map_err(|_| ServiceRunStateError::Shape)?;
    let query = impersonation_bookend(|| {
        // SAFETY: the held file and exact writable output remain live.
        let status = unsafe {
            NtQueryInformationFile(
                handle,
                &raw mut io,
                ptr::from_mut(&mut standard).cast::<c_void>(),
                length,
                FileStandardInformation,
            )
        };
        // SAFETY: the synchronous query initialized Status.
        let io_status = unsafe { io.Anonymous.Status };
        if status == STATUS_SUCCESS
            && io_status == STATUS_SUCCESS
            && io.Information == size_of::<FILE_STANDARD_INFORMATION>()
        {
            Ok(())
        } else {
            Err(ServiceRunStateError::Shape)
        }
    });
    query?;
    if standard.Directory || standard.DeletePending || standard.NumberOfLinks != 1 {
        return Err(ServiceRunStateError::Shape);
    }
    let length = usize::try_from(standard.EndOfFile).map_err(|_| ServiceRunStateError::Shape)?;
    verify_pair_default_stream(handle, length)?;
    Ok((ObjectIdentity::from_handle(handle)?, length))
}

#[repr(C, align(8))]
struct PairStreamInformationBuffer([u8; 512]);

fn verify_pair_default_stream(
    handle: HANDLE,
    expected_length: usize,
) -> Result<(), ServiceRunStateError> {
    const DEFAULT_STREAM_NAME: [u16; 7] = [
        b':' as u16,
        b':' as u16,
        b'$' as u16,
        b'D' as u16,
        b'A' as u16,
        b'T' as u16,
        b'A' as u16,
    ];
    let mut buffer = PairStreamInformationBuffer([0; 512]);
    impersonation_bookend(|| {
        // SAFETY: the aligned fixed buffer remains writable for the exact query.
        unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileStreamInfo,
                ptr::from_mut(&mut buffer).cast::<c_void>(),
                u32::try_from(buffer.0.len()).map_err(|_| ServiceRunStateError::Shape)?,
            )
        }
        .map_err(|_| ServiceRunStateError::Shape)
    })?;
    let information = ptr::from_ref(&buffer).cast::<FILE_STREAM_INFO>();
    // SAFETY: the successful query initialized at least the fixed header in
    // the suitably aligned buffer; all flexible-name bounds are checked below.
    let information = unsafe { &*information };
    let name_bytes =
        usize::try_from(information.StreamNameLength).map_err(|_| ServiceRunStateError::Shape)?;
    let name_offset = offset_of!(FILE_STREAM_INFO, StreamName);
    let name_end = name_offset
        .checked_add(name_bytes)
        .ok_or(ServiceRunStateError::Shape)?;
    if information.NextEntryOffset != 0
        || name_bytes % size_of::<u16>() != 0
        || name_end > buffer.0.len()
        || information.StreamSize
            != i64::try_from(expected_length).map_err(|_| ServiceRunStateError::Shape)?
        || information.StreamAllocationSize < 0
    {
        return Err(ServiceRunStateError::Shape);
    }
    // SAFETY: the checked byte length is even and wholly inside the live buffer.
    let name = unsafe {
        core::slice::from_raw_parts(
            ptr::addr_of!(information.StreamName).cast::<u16>(),
            name_bytes / size_of::<u16>(),
        )
    };
    if name != DEFAULT_STREAM_NAME {
        return Err(ServiceRunStateError::Shape);
    }
    Ok(())
}

fn verify_pair_create_mode(handle: HANDLE) -> Result<(), ServiceRunStateError> {
    let mut io = IO_STATUS_BLOCK::default();
    let mut mode = FILE_MODE_INFORMATION::default();
    let length = u32::try_from(size_of::<FILE_MODE_INFORMATION>())
        .map_err(|_| ServiceRunStateError::Shape)?;
    impersonation_bookend(|| {
        // SAFETY: the held file and exact writable output remain live.
        let status = unsafe {
            NtQueryInformationFile(
                handle,
                &raw mut io,
                ptr::from_mut(&mut mode).cast::<c_void>(),
                length,
                FileModeInformation,
            )
        };
        // SAFETY: the synchronous query initialized Status.
        let io_status = unsafe { io.Anonymous.Status };
        let required = FILE_WRITE_THROUGH.0 | FILE_SYNCHRONOUS_IO_NONALERT.0;
        if status == STATUS_SUCCESS
            && io_status == STATUS_SUCCESS
            && io.Information == size_of::<FILE_MODE_INFORMATION>()
            && mode.Mode & required == required
        {
            Ok(())
        } else {
            Err(ServiceRunStateError::Shape)
        }
    })
}

fn read_exact_pair_record(
    handle: HANDLE,
) -> Result<[u8; FIXED_RUN_STATE_RECORD_BYTES], ServiceRunStateError> {
    impersonation_bookend(|| {
        // SAFETY: this synchronous held file accepts an exact scalar seek.
        unsafe { SetFilePointerEx(handle, 0, None, FILE_BEGIN) }
            .map_err(|_| ServiceRunStateError::RecordIo)
    })?;
    let mut bytes = [0_u8; FIXED_RUN_STATE_RECORD_BYTES];
    let mut read = 0_u32;
    impersonation_bookend(|| {
        // SAFETY: the exact initialized output remains writable for the call.
        unsafe { ReadFile(handle, Some(&mut bytes), Some(&raw mut read), None) }
            .map_err(|_| ServiceRunStateError::RecordIo)
    })?;
    if usize::try_from(read).ok() != Some(FIXED_RUN_STATE_RECORD_BYTES) {
        return Err(ServiceRunStateError::RecordIo);
    }
    let mut eof = [0_u8; 1];
    let mut eof_read = u32::MAX;
    impersonation_bookend(|| {
        // SAFETY: the one-byte EOF probe is exact writable storage.
        unsafe { ReadFile(handle, Some(&mut eof), Some(&raw mut eof_read), None) }
            .map_err(|_| ServiceRunStateError::RecordIo)
    })?;
    if eof_read != 0 {
        return Err(ServiceRunStateError::Shape);
    }
    Ok(bytes)
}

fn write_flush_and_readback_pair_record(
    handle: HANDLE,
    record: PairRecordKind,
    candidate: &[u8; FIXED_RUN_STATE_RECORD_BYTES],
) -> Result<ObjectIdentity, ServiceRunStateError> {
    #[cfg(not(test))]
    let _ = record;
    let mut written = 0_u32;
    impersonation_bookend(|| {
        #[cfg(test)]
        let write_candidate: &[u8] = if take_pair_record_io_fault_for_test(match record {
            PairRecordKind::Marker => TestPairRecordIoFault::MarkerShortWrite,
            PairRecordKind::Checkpoint => TestPairRecordIoFault::CheckpointShortWrite,
        }) {
            &candidate[..FIXED_RUN_STATE_RECORD_BYTES - 1]
        } else {
            candidate
        };
        #[cfg(not(test))]
        let write_candidate: &[u8] = candidate;
        // SAFETY: the selected candidate slice remains readable for the synchronous call.
        unsafe { WriteFile(handle, Some(write_candidate), Some(&raw mut written), None) }
            .map_err(|_| ServiceRunStateError::RecordIo)
    })?;
    if usize::try_from(written).ok() != Some(FIXED_RUN_STATE_RECORD_BYTES) {
        return Err(ServiceRunStateError::RecordIo);
    }
    impersonation_bookend(|| {
        #[cfg(test)]
        if take_pair_record_io_fault_for_test(match record {
            PairRecordKind::Marker => TestPairRecordIoFault::MarkerFlush,
            PairRecordKind::Checkpoint => TestPairRecordIoFault::CheckpointFlush,
        }) {
            return Err(ServiceRunStateError::RecordIo);
        }
        // SAFETY: the same held write-through file remains valid.
        unsafe { FlushFileBuffers(handle) }.map_err(|_| ServiceRunStateError::RecordIo)
    })?;
    let readback = read_exact_pair_record(handle)?;
    if readback != *candidate {
        return Err(ServiceRunStateError::RecordIo);
    }
    let (identity, length) = pair_file_identity_and_length(handle)?;
    if length != FIXED_RUN_STATE_RECORD_BYTES {
        return Err(ServiceRunStateError::Shape);
    }
    Ok(identity)
}

fn clear_stale_pair_temps(writer: &mut HeldWriter) -> Result<(), ServiceRunStateError> {
    let marker = clear_one_stale_pair_temp(
        writer,
        PairLeaf::MarkerTemp,
        PairTempCleanupBinding::SafeStale,
    );
    let checkpoint = clear_one_stale_pair_temp(
        writer,
        PairLeaf::CheckpointTemp,
        PairTempCleanupBinding::SafeStale,
    );
    marker.and(checkpoint)
}

fn clear_ambiguity_bound_pair_temps(
    writer: &mut HeldWriter,
    context: PairAmbiguityContext,
) -> Result<(), ServiceRunStateError> {
    let (marker_binding, checkpoint_binding) = match context {
        PairAmbiguityContext::MarkerRename {
            marker_temp,
            checkpoint_temp,
        } => (
            PairTempCleanupBinding::ExactOrMissing(marker_temp),
            PairTempCleanupBinding::ExactOrMissing(checkpoint_temp),
        ),
        PairAmbiguityContext::MarkerInstalled { checkpoint_temp }
        | PairAmbiguityContext::CheckpointRename { checkpoint_temp } => (
            PairTempCleanupBinding::MustBeMissing,
            PairTempCleanupBinding::ExactOrMissing(checkpoint_temp),
        ),
        PairAmbiguityContext::InstalledPair => (
            PairTempCleanupBinding::MustBeMissing,
            PairTempCleanupBinding::MustBeMissing,
        ),
    };
    let marker = clear_one_stale_pair_temp(writer, PairLeaf::MarkerTemp, marker_binding);
    let checkpoint =
        clear_one_stale_pair_temp(writer, PairLeaf::CheckpointTemp, checkpoint_binding);
    marker.and(checkpoint)
}

#[derive(Clone, Copy)]
enum PairTempCleanupBinding {
    SafeStale,
    ExactOrMissing(ObjectIdentity),
    MustBeMissing,
}

fn clear_one_stale_pair_temp(
    writer: &mut HeldWriter,
    leaf: PairLeaf,
    binding: PairTempCleanupBinding,
) -> Result<(), ServiceRunStateError> {
    let parent = writer.state_handle()?;
    let mut observed = match open_existing_pair_leaf(parent, leaf) {
        Ok(PairLeafOpen::Missing) => return Ok(()),
        Ok(PairLeafOpen::Opened(opened)) => opened,
        Err(cause) => {
            writer.poison_pair_receipt();
            return Err(cause);
        }
    };
    let observation = (|| {
        require_pair_open(observed.status_error, observed.information)?;
        inspect_pair_file(
            observed.handle.raw(),
            &writer.root.expected.policy,
            writer.root.expected.root_identity.volume_serial_number,
            PAIR_FINAL_GRANTED_ACCESS,
        )
    })();
    if observed.handle.close_checked().is_err() {
        writer.poison_pair_receipt();
        return Err(ServiceRunStateError::Release);
    }
    if observation.is_err() {
        writer.poison_pair_receipt();
    }
    let observed_snapshot = observation?;
    let binding_result = match binding {
        PairTempCleanupBinding::SafeStale
            if observed_snapshot
                .length
                .is_some_and(|length| length <= FIXED_RUN_STATE_RECORD_BYTES) =>
        {
            Ok(())
        }
        PairTempCleanupBinding::SafeStale => Err(ServiceRunStateError::Shape),
        PairTempCleanupBinding::ExactOrMissing(expected)
            if observed_snapshot.identity == Some(expected)
                && observed_snapshot.length == Some(FIXED_RUN_STATE_RECORD_BYTES)
                && matches!(
                    observed_snapshot.observation,
                    FixedRunStateRecordObservation::Exact(_)
                ) =>
        {
            Ok(())
        }
        PairTempCleanupBinding::ExactOrMissing(_) | PairTempCleanupBinding::MustBeMissing => {
            Err(ServiceRunStateError::Identity)
        }
    };
    if let Err(cause) = binding_result {
        writer.poison_pair_receipt();
        return Err(cause);
    }

    let cleanup_open = pair_leaf_native_open(
        parent,
        leaf,
        PAIR_TEMP_CLEANUP_DESIRED_ACCESS,
        FILE_OPEN,
        None,
    );
    let mut cleanup = match cleanup_open {
        Ok(PairLeafOpen::Opened(opened)) => opened,
        Ok(PairLeafOpen::Missing) => {
            writer.poison_pair_receipt();
            return Err(ServiceRunStateError::Compare);
        }
        Err(cause) => {
            writer.poison_pair_receipt();
            return Err(cause);
        }
    };
    let cleanup_result = (|| {
        require_pair_open(cleanup.status_error, cleanup.information)?;
        let cleanup_snapshot = inspect_pair_file(
            cleanup.handle.raw(),
            &writer.root.expected.policy,
            writer.root.expected.root_identity.volume_serial_number,
            PAIR_TEMP_CLEANUP_GRANTED_ACCESS,
        )?;
        if cleanup_snapshot != observed_snapshot {
            return Err(ServiceRunStateError::Compare);
        }
        set_pair_delete_disposition(cleanup.handle.raw())
    })();
    let close = cleanup.handle.close_checked();
    if close.is_err() {
        writer.poison_pair_receipt();
        return Err(ServiceRunStateError::Release);
    }
    if cleanup_result.is_err() {
        writer.poison_pair_receipt();
    }
    cleanup_result
}

fn set_pair_delete_disposition(handle: HANDLE) -> Result<(), ServiceRunStateError> {
    let mut io = IO_STATUS_BLOCK::default();
    let disposition = FILE_DISPOSITION_INFORMATION { DeleteFile: true };
    let length = u32::try_from(size_of::<FILE_DISPOSITION_INFORMATION>())
        .map_err(|_| ServiceRunStateError::Cleanup)?;
    impersonation_bookend(|| {
        // SAFETY: the held file grants DELETE and the exact input remains live.
        let status = unsafe {
            NtSetInformationFile(
                handle,
                &raw mut io,
                ptr::from_ref(&disposition).cast::<c_void>(),
                length,
                FileDispositionInformation,
            )
        };
        // SAFETY: the synchronous call initialized Status.
        let io_status = unsafe { io.Anonymous.Status };
        if status == STATUS_SUCCESS && io_status == STATUS_SUCCESS {
            Ok(())
        } else {
            Err(ServiceRunStateError::Cleanup)
        }
    })
}

struct StagedPairFile {
    handle: OwnedHandle,
    identity: ObjectIdentity,
    record: PairRecordKind,
}

struct StagePairFailure {
    handle: Option<OwnedHandle>,
    cause: ServiceRunStateError,
}

fn stage_pair_record(
    writer: &HeldWriter,
    record: PairRecordKind,
    candidate: &[u8; FIXED_RUN_STATE_RECORD_BYTES],
) -> Result<StagedPairFile, StagePairFailure> {
    let parent = writer.state_handle().map_err(|cause| StagePairFailure {
        handle: None,
        cause,
    })?;
    let opened =
        create_pair_temp(parent, record, &writer.root.expected.policy).map_err(|cause| {
            StagePairFailure {
                handle: None,
                cause,
            }
        })?;
    let OpenedPairLeaf {
        handle,
        status_error,
        information,
    } = opened;
    let result = (|| {
        require_pair_created(status_error, information)?;
        #[cfg(test)]
        verify_pair_zero_share(parent, PairLeaf::for_record(record, true))?;
        verify_pair_create_mode(handle.raw())?;
        let before = inspect_pair_file(
            handle.raw(),
            &writer.root.expected.policy,
            writer.root.expected.root_identity.volume_serial_number,
            PAIR_FILE_ACCESS,
        )?;
        if before.observation != FixedRunStateRecordObservation::Malformed {
            return Err(ServiceRunStateError::Shape);
        }
        let identity = write_flush_and_readback_pair_record(handle.raw(), record, candidate)?;
        if before.identity != Some(identity) {
            return Err(ServiceRunStateError::Identity);
        }
        let after = inspect_pair_file(
            handle.raw(),
            &writer.root.expected.policy,
            writer.root.expected.root_identity.volume_serial_number,
            PAIR_FILE_ACCESS,
        )?;
        if after.identity != Some(identity)
            || after.observation != FixedRunStateRecordObservation::Exact(*candidate)
        {
            return Err(ServiceRunStateError::Identity);
        }
        Ok(identity)
    })();
    match result {
        Ok(identity) => Ok(StagedPairFile {
            handle,
            identity,
            record,
        }),
        Err(cause) => Err(StagePairFailure {
            handle: Some(handle),
            cause,
        }),
    }
}

#[cfg(test)]
fn verify_pair_zero_share(parent: HANDLE, leaf: PairLeaf) -> Result<(), ServiceRunStateError> {
    match open_existing_pair_leaf(parent, leaf) {
        Err(ServiceRunStateError::Contended) => Ok(()),
        Ok(PairLeafOpen::Opened(mut opened)) => {
            let _ = opened.handle.close_checked();
            Err(ServiceRunStateError::Security)
        }
        Ok(PairLeafOpen::Missing) | Err(_) => Err(ServiceRunStateError::Security),
    }
}

fn cleanup_staged_handle(
    writer: &mut HeldWriter,
    handle: Option<OwnedHandle>,
    delete: bool,
) -> Result<(), ServiceRunStateError> {
    let Some(mut handle) = handle else {
        return Ok(());
    };
    let delete_result = if delete {
        set_pair_delete_disposition(handle.raw())
    } else {
        Ok(())
    };
    let close_result = handle.close_checked();
    if delete_result.is_err() || close_result.is_err() {
        writer.poison_pair_receipt();
    }
    delete_result.and(close_result)
}

fn cleanup_staged_pair(
    writer: &mut HeldWriter,
    marker: Option<OwnedHandle>,
    delete_marker: bool,
    checkpoint: Option<OwnedHandle>,
    delete_checkpoint: bool,
) -> Result<(), ServiceRunStateError> {
    let marker_result = cleanup_staged_handle(writer, marker, delete_marker);
    let checkpoint_result = cleanup_staged_handle(writer, checkpoint, delete_checkpoint);
    marker_result.and(checkpoint_result)
}

struct RenamePairAttempt {
    attempted: bool,
    result: Result<(), ServiceRunStateError>,
}

fn rename_staged_pair_file(writer: &HeldWriter, staged: &StagedPairFile) -> RenamePairAttempt {
    let parent = match writer.state_handle() {
        Ok(parent) => parent,
        Err(cause) => {
            return RenamePairAttempt {
                attempted: false,
                result: Err(cause),
            };
        }
    };
    let (mut storage, bytes) = match pair_rename_packet(parent, staged.record.final_leaf()) {
        Ok(packet) => packet,
        Err(cause) => {
            return RenamePairAttempt {
                attempted: false,
                result: Err(cause),
            };
        }
    };
    #[cfg(test)]
    let inject_before = match staged.record {
        PairRecordKind::Marker => {
            take_pair_impersonation_fault_for_test(TestPairImpersonationFault::BeforeMarker)
        }
        PairRecordKind::Checkpoint => {
            take_pair_impersonation_fault_for_test(TestPairImpersonationFault::BeforeCheckpoint)
        }
    };
    #[cfg(test)]
    if inject_before {
        return RenamePairAttempt {
            attempted: false,
            result: run_impersonated_for_test(reject_thread_impersonation),
        };
    }
    if let Err(cause) = reject_thread_impersonation() {
        return RenamePairAttempt {
            attempted: false,
            result: Err(cause),
        };
    }
    let mut io = IO_STATUS_BLOCK::default();
    // From this exact point onward the source may already name the final leaf.
    #[cfg(test)]
    TEST_PAIR_RENAME_COUNT.with(|count| count.set(count.get().saturating_add(1)));
    #[cfg(test)]
    if staged.record == PairRecordKind::Marker && take_pair_marker_attempt_failure_for_test() {
        return RenamePairAttempt {
            attempted: true,
            result: Err(ServiceRunStateError::Rename),
        };
    }
    // SAFETY: the aligned packet, source handle, held root directory, and
    // output remain live for the complete synchronous native call.
    let status = unsafe {
        NtSetInformationFile(
            staged.handle.raw(),
            &raw mut io,
            storage.as_mut_ptr().cast::<c_void>(),
            bytes,
            FileRenameInformation,
        )
    };
    // SAFETY: the synchronous call initialized Status.
    let io_status = unsafe { io.Anonymous.Status };
    let operation = if status == STATUS_SUCCESS && io_status == STATUS_SUCCESS {
        Ok(())
    } else {
        Err(ServiceRunStateError::Rename)
    };
    #[cfg(test)]
    let inject_after = match staged.record {
        PairRecordKind::Marker => {
            take_pair_impersonation_fault_for_test(TestPairImpersonationFault::AfterMarker)
        }
        PairRecordKind::Checkpoint => {
            take_pair_impersonation_fault_for_test(TestPairImpersonationFault::AfterCheckpoint)
        }
    };
    #[cfg(test)]
    let ending = if inject_after {
        run_impersonated_for_test(reject_thread_impersonation)
    } else {
        reject_thread_impersonation()
    };
    #[cfg(not(test))]
    let ending = reject_thread_impersonation();
    RenamePairAttempt {
        attempted: true,
        result: match (operation, ending) {
            (_, Err(cause)) => Err(cause),
            (result, Ok(())) => result,
        },
    }
}

fn pair_rename_packet(
    parent: HANDLE,
    final_leaf: &'static str,
) -> Result<(Box<[usize]>, u32), ServiceRunStateError> {
    validate_leaf(final_leaf)?;
    let name = final_leaf.encode_utf16().collect::<Vec<_>>();
    let name_bytes = name
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or(ServiceRunStateError::Rename)?;
    let bytes = offset_of!(FILE_RENAME_INFORMATION, FileName)
        .checked_add(name_bytes)
        .ok_or(ServiceRunStateError::Rename)?;
    let word_size = size_of::<usize>();
    let words = bytes
        .checked_add(word_size - 1)
        .and_then(|value| value.checked_div(word_size))
        .ok_or(ServiceRunStateError::Rename)?;
    let mut storage = vec![0_usize; words].into_boxed_slice();
    let rename = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    // SAFETY: usize backing is suitably aligned and owns at least `bytes`;
    // the fixed UTF-16 destination is copied without a trailing NUL.
    unsafe {
        (*rename).Anonymous = FILE_RENAME_INFORMATION_0 {
            ReplaceIfExists: true,
        };
        (*rename).RootDirectory = parent;
        (*rename).FileNameLength =
            u32::try_from(name_bytes).map_err(|_| ServiceRunStateError::Rename)?;
        ptr::copy_nonoverlapping(
            name.as_ptr(),
            ptr::addr_of_mut!((*rename).FileName).cast::<u16>(),
            name.len(),
        );
    }
    Ok((
        storage,
        u32::try_from(bytes).map_err(|_| ServiceRunStateError::Rename)?,
    ))
}

#[cfg(test)]
pub(super) fn pair_rename_packet_snapshots_for_test()
-> Result<[TestPairRenamePacketSnapshot; 2], ServiceRunStateError> {
    // SAFETY: this parameter-free call returns the stable current-process
    // pseudo-handle; it remains process-owned and is never closed here.
    let parent = unsafe { GetCurrentProcess() };
    if parent == HANDLE::default() {
        return Err(ServiceRunStateError::Rename);
    }
    Ok([
        pair_rename_packet_snapshot_for_test(parent, MARKER_FINAL_LEAF)?,
        pair_rename_packet_snapshot_for_test(parent, CHECKPOINT_FINAL_LEAF)?,
    ])
}

#[cfg(test)]
fn pair_rename_packet_snapshot_for_test(
    parent: HANDLE,
    leaf: &'static str,
) -> Result<TestPairRenamePacketSnapshot, ServiceRunStateError> {
    let (storage, packet_byte_count) = pair_rename_packet(parent, leaf)?;
    let packet_byte_count_usize =
        usize::try_from(packet_byte_count).map_err(|_| ServiceRunStateError::Rename)?;
    let backing_byte_count = size_of_val(storage.as_ref());
    let anonymous_offset = offset_of!(FILE_RENAME_INFORMATION, Anonymous);
    let root_directory_offset = offset_of!(FILE_RENAME_INFORMATION, RootDirectory);
    let file_name_length_offset = offset_of!(FILE_RENAME_INFORMATION, FileNameLength);
    let file_name_offset = offset_of!(FILE_RENAME_INFORMATION, FileName);
    let struct_size = size_of::<FILE_RENAME_INFORMATION>();
    let struct_alignment = core::mem::align_of::<FILE_RENAME_INFORMATION>();
    let fixed_fields_end = file_name_length_offset
        .checked_add(size_of::<u32>())
        .ok_or(ServiceRunStateError::Rename)?;
    if storage.as_ptr().align_offset(struct_alignment) != 0
        || backing_byte_count < struct_size
        || packet_byte_count_usize > backing_byte_count
        || packet_byte_count_usize < struct_size
        || fixed_fields_end > packet_byte_count_usize
        || file_name_offset > packet_byte_count_usize
    {
        return Err(ServiceRunStateError::Rename);
    }

    let rename = storage.as_ptr().cast::<FILE_RENAME_INFORMATION>();
    // SAFETY: the production builder initialized the suitably aligned fixed
    // fields, and the fixed header is wholly inside the checked backing store.
    let (replace_if_exists, root_directory, file_name_length_bytes) = unsafe {
        (
            (*rename).Anonymous.ReplaceIfExists,
            (*rename).RootDirectory,
            (*rename).FileNameLength,
        )
    };
    let file_name_length =
        usize::try_from(file_name_length_bytes).map_err(|_| ServiceRunStateError::Rename)?;
    let file_name_end = file_name_offset
        .checked_add(file_name_length)
        .ok_or(ServiceRunStateError::Rename)?;
    if file_name_length % size_of::<u16>() != 0
        || file_name_end != packet_byte_count_usize
        || file_name_end > backing_byte_count
    {
        return Err(ServiceRunStateError::Rename);
    }
    // SAFETY: the even byte length and exact end were checked against the live
    // backing allocation before copying the flexible UTF-16 payload.
    let file_name = unsafe {
        core::slice::from_raw_parts(
            ptr::addr_of!((*rename).FileName).cast::<u16>(),
            file_name_length / size_of::<u16>(),
        )
    }
    .to_vec();
    Ok(TestPairRenamePacketSnapshot {
        leaf,
        replace_if_exists,
        root_matches: root_directory == parent,
        anonymous_offset,
        root_directory_offset,
        file_name_length_offset,
        file_name_offset,
        struct_size,
        struct_alignment,
        file_name_length_bytes,
        packet_byte_count,
        backing_byte_count,
        file_name,
    })
}

#[allow(clippy::too_many_lines)] // The ordered two-record state machine stays auditable inline.
#[allow(clippy::large_types_passed_by_value)] // Consumed tokens cannot outlive this one-shot call.
fn commit_observed_pair(
    mut writer: HeldWriter,
    expected: PairSnapshot,
    candidate: ExactFixedRunStatePair,
) -> PairCommitOutcome {
    let initial = (|| {
        writer.revalidate()?;
        let current = observe_pair_snapshot(&mut writer)?;
        if current != expected || !expected.is_committable() {
            return Err(ServiceRunStateError::Compare);
        }
        Ok(())
    })();
    if let Err(cause) = initial {
        return PairCommitOutcome::KnownNotCommitted(PairFailure {
            inner: writer,
            cause,
        });
    }

    let marker = match stage_pair_record(
        &writer,
        PairRecordKind::Marker,
        PairRecordKind::Marker.candidate(&candidate),
    ) {
        Ok(staged) => staged,
        Err(failure) => {
            let _ = cleanup_staged_pair(&mut writer, failure.handle, true, None, true);
            return PairCommitOutcome::KnownNotCommitted(PairFailure {
                inner: writer,
                cause: failure.cause,
            });
        }
    };
    let checkpoint = match stage_pair_record(
        &writer,
        PairRecordKind::Checkpoint,
        PairRecordKind::Checkpoint.candidate(&candidate),
    ) {
        Ok(staged) => staged,
        Err(failure) => {
            let _ =
                cleanup_staged_pair(&mut writer, Some(marker.handle), true, failure.handle, true);
            return PairCommitOutcome::KnownNotCommitted(PairFailure {
                inner: writer,
                cause: failure.cause,
            });
        }
    };

    let marker_identity = marker.identity;
    let checkpoint_identity = checkpoint.identity;
    if marker_identity == checkpoint_identity
        || expected.marker.identity == Some(marker_identity)
        || expected.marker.identity == Some(checkpoint_identity)
        || expected.checkpoint.identity == Some(marker_identity)
        || expected.checkpoint.identity == Some(checkpoint_identity)
    {
        let _ = cleanup_staged_pair(
            &mut writer,
            Some(marker.handle),
            true,
            Some(checkpoint.handle),
            true,
        );
        return PairCommitOutcome::KnownNotCommitted(PairFailure {
            inner: writer,
            cause: ServiceRunStateError::Identity,
        });
    }

    #[cfg(test)]
    run_pair_before_second_cas_hook_for_test();
    let second_cas = (|| {
        writer.revalidate()?;
        let current = observe_pair_snapshot(&mut writer)?;
        if current != expected {
            return Err(ServiceRunStateError::Compare);
        }
        Ok(())
    })();
    if let Err(cause) = second_cas {
        let _ = cleanup_staged_pair(
            &mut writer,
            Some(marker.handle),
            true,
            Some(checkpoint.handle),
            true,
        );
        return PairCommitOutcome::KnownNotCommitted(PairFailure {
            inner: writer,
            cause,
        });
    }

    #[cfg(test)]
    run_pair_process_death_cutpoint_for_test(TestPairProcessDeathCutpoint::BeforeMarkerRename);
    let marker_rename = rename_staged_pair_file(&writer, &marker);
    if let Err(cause) = marker_rename.result {
        let _ = cleanup_staged_pair(
            &mut writer,
            Some(marker.handle),
            !marker_rename.attempted,
            Some(checkpoint.handle),
            true,
        );
        return if marker_rename.attempted {
            PairCommitOutcome::Ambiguous(
                AmbiguousPairWriter::marker_rename(writer, marker_identity, checkpoint_identity),
                cause,
            )
        } else {
            PairCommitOutcome::KnownNotCommitted(PairFailure {
                inner: writer,
                cause,
            })
        };
    }
    #[cfg(test)]
    run_pair_process_death_cutpoint_for_test(TestPairProcessDeathCutpoint::AfterMarkerRename);
    if cleanup_staged_handle(&mut writer, Some(marker.handle), false).is_err() {
        let _ = cleanup_staged_handle(&mut writer, Some(checkpoint.handle), true);
        return PairCommitOutcome::Ambiguous(
            AmbiguousPairWriter::marker_installed(writer, checkpoint_identity),
            ServiceRunStateError::Release,
        );
    }
    let marker_confirmation = observe_pair_leaf(&mut writer, PairLeaf::MarkerFinal);
    if !matches!(
        marker_confirmation,
        Ok(snapshot)
            if snapshot.identity == Some(marker_identity)
                && snapshot.observation
                    == FixedRunStateRecordObservation::Exact(*candidate.marker())
    ) {
        let cause = marker_confirmation
            .err()
            .unwrap_or(ServiceRunStateError::Identity);
        let _ = cleanup_staged_handle(&mut writer, Some(checkpoint.handle), true);
        return PairCommitOutcome::Ambiguous(
            AmbiguousPairWriter::marker_installed(writer, checkpoint_identity),
            cause,
        );
    }

    let checkpoint_cas = observe_pair_leaf(&mut writer, PairLeaf::CheckpointFinal);
    if !matches!(checkpoint_cas, Ok(snapshot) if snapshot == expected.checkpoint) {
        let cause = checkpoint_cas
            .err()
            .unwrap_or(ServiceRunStateError::Compare);
        let _ = cleanup_staged_handle(&mut writer, Some(checkpoint.handle), true);
        return PairCommitOutcome::Ambiguous(
            AmbiguousPairWriter::marker_installed(writer, checkpoint_identity),
            cause,
        );
    }

    let checkpoint_rename = rename_staged_pair_file(&writer, &checkpoint);
    if let Err(cause) = checkpoint_rename.result {
        let _ = cleanup_staged_handle(
            &mut writer,
            Some(checkpoint.handle),
            !checkpoint_rename.attempted,
        );
        return PairCommitOutcome::Ambiguous(
            AmbiguousPairWriter::checkpoint_rename(writer, checkpoint_identity),
            cause,
        );
    }
    #[cfg(test)]
    run_pair_process_death_cutpoint_for_test(TestPairProcessDeathCutpoint::AfterCheckpointRename);
    if cleanup_staged_handle(&mut writer, Some(checkpoint.handle), false).is_err() {
        return PairCommitOutcome::Ambiguous(
            AmbiguousPairWriter::installed_pair(writer),
            ServiceRunStateError::Release,
        );
    }
    let checkpoint_confirmation = observe_pair_leaf(&mut writer, PairLeaf::CheckpointFinal);
    if !matches!(
        checkpoint_confirmation,
        Ok(snapshot)
            if snapshot.identity == Some(checkpoint_identity)
                && snapshot.observation
                    == FixedRunStateRecordObservation::Exact(*candidate.checkpoint())
    ) {
        let cause = checkpoint_confirmation
            .err()
            .unwrap_or(ServiceRunStateError::Identity);
        return PairCommitOutcome::Ambiguous(AmbiguousPairWriter::installed_pair(writer), cause);
    }

    let final_verification = (|| {
        let marker_temp = observe_pair_leaf(&mut writer, PairLeaf::MarkerTemp)?;
        let checkpoint_temp = observe_pair_leaf(&mut writer, PairLeaf::CheckpointTemp)?;
        if !matches!(
            marker_temp.observation,
            FixedRunStateRecordObservation::Missing
        ) || !matches!(
            checkpoint_temp.observation,
            FixedRunStateRecordObservation::Missing
        ) {
            return Err(ServiceRunStateError::Shape);
        }
        let final_pair = observe_pair_snapshot(&mut writer)?;
        if !final_pair.is_exact_candidate(&candidate)
            || final_pair.marker.identity != Some(marker_identity)
            || final_pair.checkpoint.identity != Some(checkpoint_identity)
        {
            return Err(ServiceRunStateError::Identity);
        }
        Ok(())
    })();
    match final_verification {
        Ok(()) => {
            #[cfg(test)]
            if take_pair_committed_reread_failure_for_test() {
                inject_close_fault_for_test(TestCloseFault::RevalidationState);
            }
            PairCommitOutcome::Committed(CommittedPairWriter {
                inner: writer,
                candidate,
            })
        }
        Err(cause) => {
            PairCommitOutcome::Ambiguous(AmbiguousPairWriter::installed_pair(writer), cause)
        }
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
    verify_exact_security(handle, &expected.policy, OWNER_RIGHTS_DENY, ROOT_ACCESS)?;
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
    verify_exact_security(handle, &expected.policy, OWNER_RIGHTS_DENY, LOCK_ACCESS)?;
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
    verify_case_insensitive_directory(handle)?;
    verify_supported_local_ntfs(handle)?;
    verify_exact_security(handle, &expected.policy, OWNER_RIGHTS_DENY, STATE_ACCESS)?;
    let identity = ObjectIdentity::from_handle(handle)?;
    if identity != expected.state_identity || identity.volume_serial_number != root_volume {
        return Err(ServiceRunStateError::Identity);
    }
    Ok(())
}

fn verify_case_insensitive_directory(handle: HANDLE) -> Result<(), ServiceRunStateError> {
    let mut information = FILE_CASE_SENSITIVE_INFO::default();
    impersonation_bookend(|| {
        // SAFETY: the held directory and exact scalar output remain live.
        unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileCaseSensitiveInfo,
                ptr::from_mut(&mut information).cast::<c_void>(),
                u32::try_from(size_of::<FILE_CASE_SENSITIVE_INFO>())
                    .map_err(|_| ServiceRunStateError::Shape)?,
            )
        }
        .map_err(|_| ServiceRunStateError::Shape)
    })?;
    if information.Flags == 0 {
        Ok(())
    } else {
        Err(ServiceRunStateError::Shape)
    }
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
    owner_rights_deny: u32,
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
    let result = inspect_security_descriptor(
        descriptor,
        owner,
        dacl,
        policy,
        owner_rights_deny,
        service_mask,
    );
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
    owner_rights_deny: u32,
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
    inspect_exact_dacl(dacl, policy, owner_rights_deny, service_mask)
}

fn control_flag(flag: windows::Win32::Security::SECURITY_DESCRIPTOR_CONTROL) -> u16 {
    u16::from_ne_bytes(flag.0.to_ne_bytes())
}

fn inspect_exact_dacl(
    dacl: *mut ACL,
    policy: &SecurityPolicy,
    owner_rights_deny: u32,
    service_mask: u32,
) -> Result<(), ServiceRunStateError> {
    let (acl_size, information) = inspect_acl_header(dacl, 3)?;
    let deny = ace_at(dacl, 0)?;
    let service = ace_at(dacl, 1)?;
    let system = ace_at(dacl, 2)?;
    let deny_size = inspect_owner_rights_deny(deny, owner_rights_deny)?;
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

fn inspect_owner_rights_deny(
    ace: *mut c_void,
    expected_mask: u32,
) -> Result<usize, ServiceRunStateError> {
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
    if denied.Mask != expected_mask {
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
    PairMarkerFinal,
    PairMarkerTemp,
    PairCheckpointFinal,
    PairCheckpointTemp,
}

impl HandleRole {
    const fn from_pair_leaf(leaf: PairLeaf) -> Self {
        match leaf {
            PairLeaf::MarkerFinal => Self::PairMarkerFinal,
            PairLeaf::MarkerTemp => Self::PairMarkerTemp,
            PairLeaf::CheckpointFinal => Self::PairCheckpointFinal,
            PairLeaf::CheckpointTemp => Self::PairCheckpointTemp,
        }
    }
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
                    HandleRole::PairCheckpointFinal => {
                        record_release_step_for_test(TestReleaseStep::PairCheckpointClosed);
                    }
                    HandleRole::PairMarkerFinal => {
                        record_release_step_for_test(TestReleaseStep::PairMarkerClosed);
                    }
                    HandleRole::Generic
                    | HandleRole::RevalidationRoot
                    | HandleRole::RevalidationState
                    | HandleRole::PairMarkerTemp
                    | HandleRole::PairCheckpointTemp => {}
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
        TestCloseFault::PairMarkerTemp => HandleRole::PairMarkerTemp,
        TestCloseFault::PairCheckpointTemp => HandleRole::PairCheckpointTemp,
        TestCloseFault::PairMarkerFinal => HandleRole::PairMarkerFinal,
        TestCloseFault::PairCheckpointFinal => HandleRole::PairCheckpointFinal,
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
pub(super) fn inject_pair_impersonation_fault_for_test(fault: TestPairImpersonationFault) {
    TEST_PAIR_IMPERSONATION_FAULT.with(|slot| slot.set(Some(fault)));
}

#[cfg(test)]
pub(super) fn inject_pair_record_io_fault_for_test(fault: TestPairRecordIoFault) {
    TEST_PAIR_RECORD_IO_FAULT.with(|slot| {
        assert!(
            slot.replace(Some(fault)).is_none(),
            "a pair-record I/O fault is already armed"
        );
    });
}

#[cfg(test)]
pub(super) fn pair_record_io_fault_is_armed_for_test() -> bool {
    TEST_PAIR_RECORD_IO_FAULT.with(|slot| slot.get().is_some())
}

#[cfg(test)]
fn take_pair_record_io_fault_for_test(expected: TestPairRecordIoFault) -> bool {
    TEST_PAIR_RECORD_IO_FAULT.with(|slot| {
        if slot.get() == Some(expected) {
            slot.set(None);
            true
        } else {
            false
        }
    })
}

#[cfg(test)]
pub(super) fn reset_pair_rename_count_for_test() {
    TEST_PAIR_RENAME_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(super) fn pair_rename_count_for_test() -> usize {
    TEST_PAIR_RENAME_COUNT.with(Cell::get)
}

#[cfg(test)]
pub(super) fn reset_pair_inspect_count_for_test() {
    TEST_PAIR_INSPECT_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(super) fn pair_inspect_count_for_test() -> usize {
    TEST_PAIR_INSPECT_COUNT.with(Cell::get)
}

#[cfg(test)]
pub(super) fn inject_pair_before_second_cas_for_test(operation: impl FnOnce() + 'static) {
    TEST_PAIR_BEFORE_SECOND_CAS.with(|slot| {
        assert!(slot.borrow_mut().replace(Box::new(operation)).is_none());
    });
}

#[cfg(test)]
pub(super) fn inject_pair_process_death_cutpoint_for_test(
    cutpoint: TestPairProcessDeathCutpoint,
    operation: impl FnOnce() + 'static,
) {
    TEST_PAIR_PROCESS_DEATH_CUTPOINT.with(|slot| {
        assert!(
            slot.borrow_mut()
                .replace((cutpoint, Box::new(operation)))
                .is_none(),
            "a pair process-death cutpoint is already armed"
        );
    });
}

#[cfg(test)]
pub(super) fn pair_process_death_cutpoint_is_armed_for_test() -> bool {
    TEST_PAIR_PROCESS_DEATH_CUTPOINT.with(|slot| slot.borrow().is_some())
}

#[cfg(test)]
pub(super) fn inject_pair_marker_attempt_failure_for_test() {
    TEST_PAIR_MARKER_ATTEMPT_FAILURE.with(|slot| slot.set(true));
}

#[cfg(test)]
fn take_pair_marker_attempt_failure_for_test() -> bool {
    TEST_PAIR_MARKER_ATTEMPT_FAILURE.with(|slot| slot.replace(false))
}

#[cfg(test)]
pub(super) fn inject_pair_committed_reread_failure_for_test() {
    TEST_PAIR_ARM_COMMITTED_REREAD_FAILURE.with(|slot| slot.set(true));
}

#[cfg(test)]
fn take_pair_committed_reread_failure_for_test() -> bool {
    TEST_PAIR_ARM_COMMITTED_REREAD_FAILURE.with(|slot| slot.replace(false))
}

#[cfg(test)]
fn run_pair_before_second_cas_hook_for_test() {
    let operation = TEST_PAIR_BEFORE_SECOND_CAS.with(|slot| slot.borrow_mut().take());
    if let Some(operation) = operation {
        operation();
    }
}

#[cfg(test)]
fn run_pair_process_death_cutpoint_for_test(actual: TestPairProcessDeathCutpoint) {
    let operation = TEST_PAIR_PROCESS_DEATH_CUTPOINT.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot
            .as_ref()
            .is_some_and(|(expected, _operation)| *expected == actual)
        {
            slot.take().map(|(_expected, operation)| operation)
        } else {
            None
        }
    });
    if let Some(operation) = operation {
        operation();
    }
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
fn take_pair_impersonation_fault_for_test(expected: TestPairImpersonationFault) -> bool {
    TEST_PAIR_IMPERSONATION_FAULT.with(|slot| {
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
