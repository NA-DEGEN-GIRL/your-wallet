#![allow(unsafe_code)]
//! Who is on the other end, and who may touch the data folder (spec/05 §8.1 H1, spec/04 §1.1,
//! §1.4-3).
//!
//! - Process identity: [`verify_process`] opens a process with
//!   `PROCESS_QUERY_LIMITED_INFORMATION` only, requires a token integrity level of at least
//!   Medium (`GetTokenInformation(TokenIntegrityLevel)`) and an image path
//!   (`QueryFullProcessImageNameW`) that is the same file as the expected one. yw-host uses it
//!   for the pipe server, yw-app for the window of the first instance: a Low-integrity process
//!   of the same user can create the predictable pipe name or a window of our class, but cannot
//!   pass this check.
//! - The private data folder: [`ensure_private_dir`] creates `%LOCALAPPDATA%\YourWallet`, `v3`
//!   and `logs` with a protected DACL (user, SYSTEM, Administrators: full, inherited by
//!   everything inside) and the mandatory label `S:(ML;OICI;NRNW;;;ME)` (a Low-integrity process
//!   can neither read nor write inside), and repairs an existing folder the user owns.

use core::ffi::c_void;
use core::fmt;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACE_HEADER, ACL, ACL_REVISION, ACL_SIZE_INFORMATION, AclSizeInformation,
    DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, GetSecurityDescriptorControl,
    GetSecurityDescriptorDacl, GetSecurityDescriptorSacl, GetSidSubAuthority,
    GetSidSubAuthorityCount, GetTokenInformation, InitializeAcl, LABEL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL,
    TOKEN_QUERY, TokenIntegrityLevel, UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_REPARSE_POINT,
};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
};

use crate::error::WinError;
use crate::pipe::SecurityDescriptor;
use crate::process::sid_to_string;
use crate::wide::{path_wide, to_wide};

/// `SECURITY_MANDATORY_MEDIUM_RID`: the lowest integrity level trusted as "this user".
pub const MEDIUM_INTEGRITY_RID: u32 = 0x2000;
/// `S-1-5-18` (Local System).
pub const SYSTEM_SID: &str = "S-1-5-18";
/// `S-1-5-32-544` (`BUILTIN\Administrators`).
pub const ADMINISTRATORS_SID: &str = "S-1-5-32-544";
/// `S-1-16-8192`: the Medium mandatory label.
const MEDIUM_LABEL_SID: &str = "S-1-16-8192";
/// `SYSTEM_MANDATORY_LABEL_ACE_TYPE`.
pub const MANDATORY_LABEL_ACE_TYPE: u8 = 0x11;
/// `SYSTEM_MANDATORY_LABEL_NO_WRITE_UP`.
pub const LABEL_NO_WRITE_UP: u32 = 0x1;
/// `SYSTEM_MANDATORY_LABEL_NO_READ_UP`.
pub const LABEL_NO_READ_UP: u32 = 0x2;
/// `OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE`.
const OBJECT_AND_CONTAINER_INHERIT: u8 = 0x1 | 0x2;
/// Allow-type ACEs: `ACCESS_ALLOWED`, `ACCESS_ALLOWED_OBJECT`, `ACCESS_ALLOWED_CALLBACK`,
/// `ACCESS_ALLOWED_CALLBACK_OBJECT`.
const ALLOW_ACE_TYPES: [u8; 4] = [0x0, 0x5, 0x9, 0xB];
/// Longest image path `QueryFullProcessImageNameW` may return.
const MAX_PATH_UNITS: usize = 32_768;

/// A kernel handle closed on drop.
struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: The handle was returned to us by the OS and is closed exactly once here.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// A `LocalAlloc` buffer from the OS (SID, security descriptor), freed on drop.
pub(crate) struct LocalMem(*mut c_void);

impl LocalMem {
    /// The pointer, valid while `self` lives.
    pub(crate) const fn raw(&self) -> *mut c_void {
        self.0
    }
}

impl Drop for LocalMem {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Allocated by the OS with LocalAlloc; freed exactly once here.
            unsafe { LocalFree(self.0) };
        }
    }
}

/// `ConvertStringSidToSidW`.
pub(crate) fn sid_from_string(sid: &str) -> Result<LocalMem, WinError> {
    const API: &str = "ConvertStringSidToSidW";
    let wide = to_wide(sid, API)?;
    let mut out: PSID = core::ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated and live; `out` is a writable out pointer.
    let ok = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &raw mut out) };
    if ok == 0 || out.is_null() {
        return Err(WinError::last(API));
    }
    Ok(LocalMem(out))
}

/// The SID string of the Medium mandatory label, as a binary SID.
pub(crate) fn medium_label_sid() -> Result<LocalMem, WinError> {
    sid_from_string(MEDIUM_LABEL_SID)
}

/// `GetTokenInformation(class)` into an 8-byte aligned buffer (≤ 4 KiB).
fn token_information(token: &Handle, class: TOKEN_INFORMATION_CLASS) -> Result<Vec<u64>, WinError> {
    const API: &str = "GetTokenInformation";
    let mut needed = 0_u32;
    // SAFETY: Size query: a null buffer of length 0 and a writable `needed`.
    unsafe { GetTokenInformation(token.0, class, core::ptr::null_mut(), 0, &raw mut needed) };
    let needed_bytes = usize::try_from(needed).map_err(|_| WinError::invalid_argument(API))?;
    if needed_bytes == 0 || needed_bytes > 4_096 {
        return Err(WinError::last(API));
    }
    let mut buffer = vec![0_u64; needed_bytes.div_ceil(8)];
    let capacity = u32::try_from(buffer.len().saturating_mul(8))
        .map_err(|_| WinError::invalid_argument(API))?;
    // SAFETY: `buffer` is writable for `capacity` bytes and 8-byte aligned; `needed` is writable.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            class,
            buffer.as_mut_ptr().cast(),
            capacity,
            &raw mut needed,
        )
    };
    if ok == 0 {
        return Err(WinError::last(API));
    }
    Ok(buffer)
}

/// The last sub-authority of a SID (the RID; for a mandatory label SID, the integrity level).
///
/// # Safety
///
/// `sid` must point to a valid SID that stays alive for the call.
unsafe fn last_sub_authority(sid: PSID) -> Result<u32, WinError> {
    const API: &str = "GetSidSubAuthority";
    // SAFETY: The caller guarantees `sid`.
    let count = unsafe { GetSidSubAuthorityCount(sid) };
    if count.is_null() {
        return Err(WinError::last("GetSidSubAuthorityCount"));
    }
    // SAFETY: `count` points at the sub-authority count inside the valid SID.
    let count = unsafe { count.read() };
    let index = u32::from(count)
        .checked_sub(1)
        .ok_or(WinError::invalid_argument(API))?;
    // SAFETY: `index` is below the SID's sub-authority count.
    let rid = unsafe { GetSidSubAuthority(sid, index) };
    if rid.is_null() {
        return Err(WinError::last(API));
    }
    // SAFETY: `rid` points at a sub-authority inside the valid SID.
    Ok(unsafe { rid.read_unaligned() })
}

fn open_process(pid: u32) -> Result<Handle, WinError> {
    // SAFETY: Plain values; the least access that allows the token and image queries.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(WinError::last("OpenProcess"));
    }
    Ok(Handle(process))
}

/// The integrity level RID of `pid`'s primary token (`0x2000` = Medium, `0x3000` = High).
///
/// # Errors
///
/// [`WinError`] from the failing call (e.g. the process is gone).
pub fn process_integrity_rid(pid: u32) -> Result<u32, WinError> {
    let process = open_process(pid)?;
    let mut raw: HANDLE = core::ptr::null_mut();
    // SAFETY: `process` is a live handle with PROCESS_QUERY_LIMITED_INFORMATION; `raw` is a
    // writable out pointer.
    let ok = unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &raw mut raw) };
    if ok == 0 {
        return Err(WinError::last("OpenProcessToken"));
    }
    let token = Handle(raw);
    let buffer = token_information(&token, TokenIntegrityLevel)?;
    if buffer.len().saturating_mul(8) < core::mem::size_of::<TOKEN_MANDATORY_LABEL>() {
        return Err(WinError::invalid_argument("GetTokenInformation"));
    }
    // SAFETY: On success the aligned buffer starts with an initialized TOKEN_MANDATORY_LABEL.
    let label = unsafe { buffer.as_ptr().cast::<TOKEN_MANDATORY_LABEL>().read() };
    // SAFETY: `label.Label.Sid` points into `buffer`, which outlives the call.
    unsafe { last_sub_authority(label.Label.Sid) }
}

/// `QueryFullProcessImageNameW(PROCESS_NAME_WIN32)` of `pid`.
///
/// # Errors
///
/// [`WinError`] from the failing call.
pub fn process_image_path(pid: u32) -> Result<PathBuf, WinError> {
    const API: &str = "QueryFullProcessImageNameW";
    let process = open_process(pid)?;
    let mut buffer = vec![0_u16; MAX_PATH_UNITS];
    let mut size = u32::try_from(buffer.len()).map_err(|_| WinError::invalid_argument(API))?;
    // SAFETY: `buffer` is writable for `size` units; `size` is writable.
    let ok = unsafe {
        QueryFullProcessImageNameW(
            process.0,
            PROCESS_NAME_WIN32,
            buffer.as_mut_ptr(),
            &raw mut size,
        )
    };
    if ok == 0 {
        return Err(WinError::last(API));
    }
    buffer.truncate(usize::try_from(size).map_err(|_| WinError::invalid_argument(API))?);
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}

/// Whether an integrity RID is trusted as the user's own (Medium or higher).
#[must_use]
pub const fn integrity_trusted(rid: u32) -> bool {
    rid >= MEDIUM_INTEGRITY_RID
}

/// Two canonical path strings name the same file: equal after Unicode upper-casing (NTFS file
/// names are case-insensitive).
#[must_use]
pub fn same_path_text(a: &str, b: &str) -> bool {
    !a.is_empty() && a.to_uppercase() == b.to_uppercase()
}

/// Whether two paths are the same existing file: both are canonicalized (`\\?\` form, long
/// names, links resolved) and compared case-insensitively. A path that cannot be resolved (or is
/// not valid Unicode) matches nothing.
#[must_use]
pub fn same_file_path(a: &Path, b: &Path) -> bool {
    let canonical = |path: &Path| {
        fs::canonicalize(path)
            .ok()
            .and_then(|path| path.to_str().map(str::to_owned))
    };
    matches!((canonical(a), canonical(b)), (Some(a), Some(b)) if same_path_text(&a, &b))
}

/// Why [`verify_process`] refused a process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessCheckError {
    /// The process could not be opened or queried (gone, or protected from this user).
    Query(WinError),
    /// Its integrity level is below Medium (the RID).
    LowIntegrity(u32),
    /// Its image is not the expected executable.
    OtherImage,
}

impl fmt::Display for ProcessCheckError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Query(error) => write!(formatter, "{error}"),
            Self::LowIntegrity(rid) => write!(formatter, "integrity 0x{rid:04X} below Medium"),
            Self::OtherImage => formatter.write_str("unexpected process image"),
        }
    }
}

impl std::error::Error for ProcessCheckError {}

/// Verifies that `pid` runs `expected_image` at Medium integrity or higher (spec/05 §8.1 H1,
/// spec/04 §1.1). A process that cannot be queried is refused.
///
/// # Errors
///
/// [`ProcessCheckError`].
pub fn verify_process(pid: u32, expected_image: &Path) -> Result<(), ProcessCheckError> {
    let rid = process_integrity_rid(pid).map_err(ProcessCheckError::Query)?;
    if !integrity_trusted(rid) {
        return Err(ProcessCheckError::LowIntegrity(rid));
    }
    let image = process_image_path(pid).map_err(ProcessCheckError::Query)?;
    if !same_file_path(&image, expected_image) {
        return Err(ProcessCheckError::OtherImage);
    }
    Ok(())
}

/// The Remote Desktop session of the current process (`ProcessIdToSessionId`).
///
/// # Errors
///
/// [`WinError`] from the call.
pub fn current_session_id() -> Result<u32, WinError> {
    let mut session = 0_u32;
    // SAFETY: Plain pid; `session` is writable.
    let ok = unsafe { ProcessIdToSessionId(std::process::id(), &raw mut session) };
    if ok == 0 {
        return Err(WinError::last("ProcessIdToSessionId"));
    }
    Ok(session)
}

/// One ACE of a [`PathSecurity`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathAce {
    /// `ACE_HEADER.AceType`.
    pub ace_type: u8,
    /// `ACE_HEADER.AceFlags` (`0x10` = inherited, `0x08` = inherit only, `0x1|0x2` = OI|CI).
    pub flags: u8,
    /// The access mask (for a mandatory label ACE: the policy, `NW = 1`, `NR = 2`).
    pub mask: u32,
    /// The trustee SID string; empty for ACE types without a plain SID.
    pub sid: String,
}

/// Owner, DACL and mandatory label of a file or folder (`GetNamedSecurityInfoW`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathSecurity {
    /// The owner SID string.
    pub owner: String,
    /// `false` for a NULL DACL (everyone has full access).
    pub dacl_present: bool,
    /// `SE_DACL_PROTECTED` (no inherited ACEs).
    pub dacl_protected: bool,
    /// The DACL entries in order.
    pub aces: Vec<PathAce>,
    /// The first mandatory label ACE of the SACL, if any.
    pub label: Option<PathAce>,
}

/// Reads owner, DACL and label of `path` (follows a reparse point; callers reject those first).
///
/// # Errors
///
/// [`WinError`] from the failing call.
pub fn path_security(path: &Path) -> Result<PathSecurity, WinError> {
    const API: &str = "GetNamedSecurityInfoW";
    let wide = path_wide(path, API)?;
    let mut owner: PSID = core::ptr::null_mut();
    let mut dacl: *mut ACL = core::ptr::null_mut();
    let mut sacl: *mut ACL = core::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = core::ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated and live; every requested out pointer is writable; the
    // group is not requested. Reading the label needs only READ_CONTROL.
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            &raw mut owner,
            core::ptr::null_mut(),
            &raw mut dacl,
            &raw mut sacl,
            &raw mut descriptor,
        )
    };
    if status != 0 {
        return Err(WinError::new(API, status));
    }
    let descriptor = LocalMem(descriptor);
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: `descriptor` is the live descriptor returned above; outputs are writable.
    let ok = unsafe {
        GetSecurityDescriptorControl(descriptor.raw(), &raw mut control, &raw mut revision)
    };
    if ok == 0 {
        return Err(WinError::last("GetSecurityDescriptorControl"));
    }
    let owner = if owner.is_null() {
        String::new()
    } else {
        // SAFETY: `owner` points into `descriptor`, which is alive.
        unsafe { sid_to_string(owner) }?
    };
    let aces = if dacl.is_null() {
        Vec::new()
    } else {
        // SAFETY: `dacl` points into `descriptor`, which is alive.
        unsafe { read_aces(dacl) }?
    };
    let label = if sacl.is_null() {
        None
    } else {
        // SAFETY: `sacl` points into `descriptor`, which is alive.
        unsafe { read_aces(sacl) }?
            .into_iter()
            .find(|ace| ace.ace_type == MANDATORY_LABEL_ACE_TYPE)
    };
    Ok(PathSecurity {
        owner,
        dacl_present: !dacl.is_null(),
        dacl_protected: control & SE_DACL_PROTECTED != 0,
        aces,
        label,
    })
}

/// The ACEs of `acl`.
///
/// # Safety
///
/// `acl` must point to a valid ACL that stays alive for the call.
unsafe fn read_aces(acl: *const ACL) -> Result<Vec<PathAce>, WinError> {
    let mut info = ACL_SIZE_INFORMATION::default();
    let size = u32::try_from(core::mem::size_of::<ACL_SIZE_INFORMATION>())
        .map_err(|_| WinError::invalid_argument("GetAclInformation"))?;
    // SAFETY: The caller guarantees `acl`; `info` is writable for `size` bytes.
    let ok = unsafe { GetAclInformation(acl, (&raw mut info).cast(), size, AclSizeInformation) };
    if ok == 0 {
        return Err(WinError::last("GetAclInformation"));
    }
    let header_len = core::mem::size_of::<ACE_HEADER>();
    let sid_offset = header_len.saturating_add(4);
    let mut aces = Vec::new();
    for index in 0..info.AceCount {
        let mut ace: *mut c_void = core::ptr::null_mut();
        // SAFETY: `index < AceCount` of the valid ACL; `ace` is a writable out pointer.
        let ok = unsafe { GetAce(acl, index, &raw mut ace) };
        if ok == 0 || ace.is_null() {
            return Err(WinError::last("GetAce"));
        }
        // SAFETY: `ace` points at an ACE inside the ACL; every ACE starts with an ACE_HEADER.
        let header = unsafe { ace.cast::<ACE_HEADER>().read_unaligned() };
        let ace_len = usize::from(header.AceSize);
        let mask = if ace_len >= sid_offset {
            // SAFETY: The ACE is at least header + 4 bytes; the mask follows the header.
            unsafe {
                ace.cast::<u8>()
                    .wrapping_add(header_len)
                    .cast::<u32>()
                    .read_unaligned()
            }
        } else {
            0
        };
        // Types 0–3 (allowed, denied, audit, alarm) and the mandatory label share the
        // {header, mask, SID} layout.
        let plain = header.AceType <= 3 || header.AceType == MANDATORY_LABEL_ACE_TYPE;
        let sid = if plain && ace_len > sid_offset {
            // SAFETY: For these ACE types a SID starts after the mask, inside the ACE.
            unsafe { sid_to_string(ace.cast::<u8>().wrapping_add(sid_offset).cast()) }?
        } else {
            String::new()
        };
        aces.push(PathAce {
            ace_type: header.AceType,
            flags: header.AceFlags,
            mask,
            sid,
        });
    }
    Ok(aces)
}

/// Whether `sid` is the user, SYSTEM or Administrators.
#[must_use]
pub fn trusted_sid(sid: &str, user_sid: &str) -> bool {
    !sid.is_empty() && (sid == user_sid || sid == SYSTEM_SID || sid == ADMINISTRATORS_SID)
}

/// Whether the DACL lets anyone but the user, SYSTEM and Administrators in: a NULL DACL, or an
/// allow-type ACE (inherited or not, inherit-only included) for any other trustee with a
/// non-zero mask. Deny ACEs never grant anything.
#[must_use]
pub fn grants_others(security: &PathSecurity, user_sid: &str) -> bool {
    !security.dacl_present
        || security.aces.iter().any(|ace| {
            ALLOW_ACE_TYPES.contains(&ace.ace_type)
                && ace.mask != 0
                && !trusted_sid(&ace.sid, user_sid)
        })
}

/// The state [`ensure_private_dir`] writes: protected DACL, the user with full access inherited
/// by files and folders inside, the Medium no-read-up/no-write-up label, a trusted owner and
/// nobody else.
#[must_use]
pub fn is_private_dir(security: &PathSecurity, user_sid: &str) -> bool {
    let user_inherits = security.aces.iter().any(|ace| {
        ace.ace_type == 0
            && ace.sid == user_sid
            && ace.flags & OBJECT_AND_CONTAINER_INHERIT == OBJECT_AND_CONTAINER_INHERIT
            && ace.mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS
    });
    let labeled = security.label.as_ref().is_some_and(|label| {
        sid_rid(&label.sid).is_some_and(integrity_trusted)
            && label.mask & (LABEL_NO_WRITE_UP | LABEL_NO_READ_UP)
                == (LABEL_NO_WRITE_UP | LABEL_NO_READ_UP)
            && label.flags & OBJECT_AND_CONTAINER_INHERIT == OBJECT_AND_CONTAINER_INHERIT
    });
    trusted_sid(&security.owner, user_sid)
        && security.dacl_present
        && security.dacl_protected
        && !grants_others(security, user_sid)
        && user_inherits
        && labeled
}

/// The integrity RID of a label SID string `S-1-16-<rid>`.
fn sid_rid(sid: &str) -> Option<u32> {
    sid.strip_prefix("S-1-16-")?.parse().ok()
}

/// What to do with an existing data folder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirDecision {
    /// Already private.
    Keep,
    /// Rewrite the DACL and label (extra grants, such as an inherited read ACE for another group,
    /// are dropped): the owner is the user, SYSTEM or Administrators.
    Repair,
    /// Owned by anyone else: that owner could rewrite the DACL at any time.
    Refuse,
}

/// spec/04 §1.4-3: the decision for an existing data folder.
#[must_use]
pub fn decide_dir(security: &PathSecurity, user_sid: &str) -> DirDecision {
    if !trusted_sid(&security.owner, user_sid) {
        DirDecision::Refuse
    } else if is_private_dir(security, user_sid) {
        DirDecision::Keep
    } else {
        DirDecision::Repair
    }
}

/// spec/04 §1.4-3: the decision for an entry inside the data folder (inherited ACEs come from
/// the private folder; only explicit extra grants and a foreign owner matter).
#[must_use]
pub fn decide_entry(security: &PathSecurity, user_sid: &str) -> DirDecision {
    if !trusted_sid(&security.owner, user_sid) {
        DirDecision::Refuse
    } else if grants_others(security, user_sid) {
        DirDecision::Repair
    } else {
        DirDecision::Keep
    }
}

/// The SDDL of the private data folder for `user_sid`.
#[must_use]
pub fn private_dir_sddl(user_sid: &str) -> String {
    format!(
        "O:{user_sid}D:PAI(A;OICI;FA;;;{user_sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)S:(ML;OICI;NRNW;;;ME)"
    )
}

/// What [`ensure_private_dir`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PrivateDir {
    /// The folder was created.
    pub created: bool,
    /// The folder's DACL and label were rewritten.
    pub repaired: bool,
    /// Entries directly inside whose extra grants were removed (they now inherit only).
    pub entries_repaired: u32,
}

/// [`ensure_private_dir`] failure. Carries no path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateDirError {
    /// The folder or an entry inside is owned by someone else, or grants access to others and
    /// cannot be repaired by this user.
    Untrusted,
    /// The folder is a reparse point or not a folder.
    NotPlainDir,
    /// A Win32 call failed.
    Os(WinError),
    /// A std I/O call failed.
    Io(io::ErrorKind),
}

impl fmt::Display for PrivateDirError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Untrusted => formatter.write_str("data folder owner or ACL untrusted"),
            Self::NotPlainDir => formatter.write_str("data folder is not a plain folder"),
            Self::Os(error) => write!(formatter, "{error}"),
            Self::Io(kind) => write!(formatter, "I/O error: {kind:?}"),
        }
    }
}

impl std::error::Error for PrivateDirError {}

impl From<io::Error> for PrivateDirError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

fn plain_dir(path: &Path) -> Result<bool, PrivateDirError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_dir()
            {
                Err(PrivateDirError::NotPlainDir)
            } else {
                Ok(true)
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// `CreateDirectoryW` with the private descriptor. `Ok(false)` when it already exists.
fn create_private(path: &Path, sddl: &str) -> Result<bool, PrivateDirError> {
    const API: &str = "CreateDirectoryW";
    let descriptor = SecurityDescriptor::from_sddl(sddl).map_err(PrivateDirError::Os)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(core::mem::size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| PrivateDirError::Os(WinError::invalid_argument(API)))?,
        lpSecurityDescriptor: descriptor.raw(),
        bInheritHandle: 0,
    };
    let wide = path_wide(path, API).map_err(PrivateDirError::Os)?;
    // SAFETY: `wide` is NUL-terminated; `attributes` points at a live descriptor; neither is
    // retained after the call.
    let ok = unsafe { CreateDirectoryW(wide.as_ptr(), &raw const attributes) };
    if ok == 0 {
        let error = WinError::last(API);
        if error.code == ERROR_ALREADY_EXISTS {
            return Ok(false);
        }
        return Err(match error.code {
            2 | 3 => PrivateDirError::Io(io::ErrorKind::NotFound),
            _ => PrivateDirError::Os(error),
        });
    }
    Ok(true)
}

fn set_security(
    path: &Path,
    info: u32,
    dacl: *const ACL,
    sacl: *const ACL,
) -> Result<(), WinError> {
    const API: &str = "SetNamedSecurityInfoW";
    let wide = path_wide(path, API)?;
    // SAFETY: `wide` is NUL-terminated; `dacl`/`sacl` are null or valid ACLs kept alive by the
    // caller; the name buffer is not modified; owner and group are not set.
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            info,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            dacl,
            sacl,
        )
    };
    if status != 0 {
        return Err(WinError::new(API, status));
    }
    Ok(())
}

/// Rewrites the DACL (protected) and the label of `path` from `sddl`. Inherited ACEs of the
/// entries inside are recomputed by `SetNamedSecurityInfoW`.
fn repair_dir(path: &Path, sddl: &str) -> Result<(), WinError> {
    let descriptor = SecurityDescriptor::from_sddl(sddl)?;
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl: *mut ACL = core::ptr::null_mut();
    // SAFETY: `descriptor` is live; outputs are writable.
    let ok = unsafe {
        GetSecurityDescriptorDacl(
            descriptor.raw(),
            &raw mut present,
            &raw mut dacl,
            &raw mut defaulted,
        )
    };
    if ok == 0 || present == 0 || dacl.is_null() {
        return Err(WinError::last("GetSecurityDescriptorDacl"));
    }
    let mut sacl: *mut ACL = core::ptr::null_mut();
    // SAFETY: `descriptor` is live; outputs are writable.
    let ok = unsafe {
        GetSecurityDescriptorSacl(
            descriptor.raw(),
            &raw mut present,
            &raw mut sacl,
            &raw mut defaulted,
        )
    };
    if ok == 0 || present == 0 || sacl.is_null() {
        return Err(WinError::last("GetSecurityDescriptorSacl"));
    }
    set_security(
        path,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        dacl,
        core::ptr::null(),
    )?;
    set_security(path, LABEL_SECURITY_INFORMATION, core::ptr::null(), sacl)
}

/// Replaces the explicit DACL of `path` with an empty, unprotected one: only the ACEs inherited
/// from the private folder remain.
fn reset_to_inherited(path: &Path) -> Result<(), WinError> {
    const API: &str = "InitializeAcl";
    // An empty ACL is just its 8-byte header; u32 storage keeps it aligned.
    let mut buffer = [0_u32; 4];
    let size = u32::try_from(core::mem::size_of_val(&buffer))
        .map_err(|_| WinError::invalid_argument(API))?;
    let acl: *mut ACL = buffer.as_mut_ptr().cast();
    // SAFETY: `acl` points at `size` writable, 4-byte aligned bytes owned by `buffer`.
    let ok = unsafe { InitializeAcl(acl, size, ACL_REVISION) };
    if ok == 0 {
        return Err(WinError::last(API));
    }
    set_security(
        path,
        DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
        acl,
        core::ptr::null(),
    )
}

/// Creates or checks one data folder (spec/04 §1.4-3; the parent must exist):
///
/// - missing → created with [`private_dir_sddl`] (protected DACL, inherited by everything
///   created inside, so `vault.ywv`, `apikeys.dpapi` and the logs get it too);
/// - existing → [`decide_dir`]: kept, repaired (owner user, SYSTEM or Administrators; extra
///   grants such as an inherited read ACE for another group are dropped) or refused
///   ([`PrivateDirError::Untrusted`]: another owner, or extra grants that could not be removed);
/// - then every entry directly inside → [`decide_entry`]: an entry with explicit extra grants
///   is reset to inherit only; an entry owned by someone else is refused. Reparse points inside
///   are skipped here: neither the link nor its target is ACL-checked or repaired. What keeps
///   them harmless is the file code: yw-app's `FileStorage` refuses to read or commit
///   `vault.ywv`, `meta.ywm`, `journal.ywj` or their `.prev` when it is a reparse point
///   ([`crate::file::read_limited_no_reparse`], [`crate::file::reject_reparse_point`]), and
///   [`crate::file::atomic_write`] refuses to replace one; `settings.json` and `apikeys.dpapi`
///   are read with the same no-follow read. Other files (e.g. the logs) are not checked
///   (review L8, S17).
///
/// # Errors
///
/// [`PrivateDirError`].
pub fn ensure_private_dir(path: &Path, user_sid: &str) -> Result<PrivateDir, PrivateDirError> {
    let sddl = private_dir_sddl(user_sid);
    let mut outcome = PrivateDir::default();
    if !plain_dir(path)? {
        outcome.created = create_private(path, &sddl)?;
        if !plain_dir(path)? {
            return Err(PrivateDirError::Io(io::ErrorKind::NotFound));
        }
    }
    if !outcome.created {
        let security = path_security(path).map_err(PrivateDirError::Os)?;
        match decide_dir(&security, user_sid) {
            DirDecision::Keep => {}
            DirDecision::Repair => match repair_dir(path, &sddl) {
                Ok(()) => outcome.repaired = true,
                // Nobody else has access: only the protection or the label is missing (e.g.
                // owned by Administrators without a grant for this user to change it).
                Err(_) if !grants_others(&security, user_sid) => {}
                Err(_) => return Err(PrivateDirError::Untrusted),
            },
            DirDecision::Refuse => return Err(PrivateDirError::Untrusted),
        }
        if outcome.repaired {
            let after = path_security(path).map_err(PrivateDirError::Os)?;
            if grants_others(&after, user_sid) {
                return Err(PrivateDirError::Untrusted);
            }
        }
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            continue;
        }
        let entry_path = entry.path();
        let security = path_security(&entry_path).map_err(PrivateDirError::Os)?;
        match decide_entry(&security, user_sid) {
            DirDecision::Keep => {}
            DirDecision::Repair => {
                reset_to_inherited(&entry_path).map_err(PrivateDirError::Os)?;
                let after = path_security(&entry_path).map_err(PrivateDirError::Os)?;
                if grants_others(&after, user_sid) {
                    return Err(PrivateDirError::Untrusted);
                }
                outcome.entries_repaired = outcome.entries_repaired.saturating_add(1);
            }
            DirDecision::Refuse => return Err(PrivateDirError::Untrusted),
        }
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::{
        DirDecision, PathAce, PathSecurity, decide_dir, decide_entry, grants_others,
        integrity_trusted, is_private_dir, same_path_text,
    };

    const USER: &str = "S-1-5-21-1-2-3-1001";
    const OTHER: &str = "S-1-5-21-1-2-3-1002";
    const SANDBOX_GROUP: &str = "S-1-5-21-1-2-3-1010";

    fn allow(sid: &str, flags: u8, mask: u32) -> PathAce {
        PathAce {
            ace_type: 0,
            flags,
            mask,
            sid: sid.to_owned(),
        }
    }

    fn private(owner: &str) -> PathSecurity {
        PathSecurity {
            owner: owner.to_owned(),
            dacl_present: true,
            dacl_protected: true,
            aces: vec![
                allow(USER, 0x3, 0x001F_01FF),
                allow("S-1-5-18", 0x3, 0x001F_01FF),
                allow("S-1-5-32-544", 0x3, 0x001F_01FF),
            ],
            label: Some(PathAce {
                ace_type: 0x11,
                flags: 0x3,
                mask: 0x3,
                sid: "S-1-16-8192".to_owned(),
            }),
        }
    }

    #[test]
    fn integrity_medium_and_above_is_trusted() {
        assert!(!integrity_trusted(0x1000), "Low");
        assert!(!integrity_trusted(0));
        assert!(integrity_trusted(0x2000), "Medium");
        assert!(integrity_trusted(0x2100), "Medium Plus");
        assert!(integrity_trusted(0x3000), "High");
    }

    #[test]
    fn image_paths_compare_case_insensitively() {
        assert!(same_path_text(
            r"\\?\C:\Apps\YourWallet\yw-app.exe",
            r"\\?\c:\apps\yourwallet\YW-APP.EXE"
        ));
        assert!(!same_path_text(
            r"\\?\C:\Apps\YourWallet\yw-app.exe",
            r"\\?\C:\Temp\yw-app.exe"
        ));
        assert!(!same_path_text("", ""));
    }

    #[test]
    fn the_written_state_is_kept() {
        let security = private(USER);
        assert!(is_private_dir(&security, USER));
        assert_eq!(decide_dir(&security, USER), DirDecision::Keep);
        assert_eq!(decide_entry(&security, USER), DirDecision::Keep);
    }

    #[test]
    fn an_inherited_read_grant_for_another_group_is_repaired_when_the_user_owns_it() {
        let mut security = private(USER);
        security.dacl_protected = false;
        security
            .aces
            .push(allow(SANDBOX_GROUP, 0x10 | 0x3, 0x0012_00A9));
        assert!(grants_others(&security, USER));
        assert_eq!(decide_dir(&security, USER), DirDecision::Repair);
        assert_eq!(decide_entry(&security, USER), DirDecision::Repair);
    }

    #[test]
    fn missing_protection_or_label_is_repaired() {
        let mut unprotected = private(USER);
        unprotected.dacl_protected = false;
        assert_eq!(decide_dir(&unprotected, USER), DirDecision::Repair);
        let mut unlabeled = private("S-1-5-32-544");
        unlabeled.label = None;
        assert_eq!(decide_dir(&unlabeled, USER), DirDecision::Repair);
        let mut low = private(USER);
        if let Some(label) = low.label.as_mut() {
            label.sid = "S-1-16-4096".to_owned();
        }
        assert_eq!(decide_dir(&low, USER), DirDecision::Repair);
        let mut not_inherited = private(USER);
        not_inherited.aces[0].flags = 0;
        assert_eq!(decide_dir(&not_inherited, USER), DirDecision::Repair);
    }

    #[test]
    fn a_foreign_owner_is_refused_and_trusted_owners_are_repaired() {
        let foreign = private(OTHER);
        assert_eq!(decide_dir(&foreign, USER), DirDecision::Refuse);
        assert_eq!(decide_entry(&foreign, USER), DirDecision::Refuse);
        let mut everyone_owner = private("S-1-1-0");
        everyone_owner.dacl_protected = false;
        assert_eq!(decide_dir(&everyone_owner, USER), DirDecision::Refuse);
        // Created by an elevated run (owner Administrators) on a host that adds a group.
        let mut admins_with_everyone = private("S-1-5-32-544");
        admins_with_everyone
            .aces
            .push(allow("S-1-1-0", 0x3, 0x0012_019F));
        assert_eq!(decide_dir(&admins_with_everyone, USER), DirDecision::Repair);
        let mut null_dacl = private("S-1-5-18");
        null_dacl.dacl_present = false;
        null_dacl.aces.clear();
        assert!(grants_others(&null_dacl, USER));
        assert_eq!(decide_dir(&null_dacl, USER), DirDecision::Repair);
    }

    #[test]
    fn deny_aces_and_empty_masks_grant_nothing() {
        let mut security = private(USER);
        security.aces.push(PathAce {
            ace_type: 1,
            flags: 0,
            mask: 0x001F_01FF,
            sid: "S-1-1-0".to_owned(),
        });
        security.aces.push(allow(OTHER, 0, 0));
        assert!(!grants_others(&security, USER));
        // An object or callback allow ACE has no plain SID: it counts as another trustee.
        security.aces.push(PathAce {
            ace_type: 0x9,
            flags: 0,
            mask: 1,
            sid: String::new(),
        });
        assert!(grants_others(&security, USER));
    }
}
