//! Narrow Windows adapter for current-service-token observations.

#![allow(unsafe_code)]

use core::ffi::c_void;
use core::fmt;
use core::mem::{offset_of, size_of};
use core::ptr;
use std::cell::Cell;
use std::marker::PhantomData;
use std::os::windows::io::BorrowedHandle;

use windows::Win32::Foundation::{
    CloseHandle, CompareObjectHandles, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_TOKEN,
    GetHandleInformation, HANDLE, INVALID_HANDLE_VALUE, LUID,
};
use windows::Win32::Security::{
    GetLengthSid, GetTokenInformation, IsValidSid, LookupAccountNameW, LookupPrivilegeValueW, PSID,
    SID_AND_ATTRIBUTES, SID_NAME_USE, SidTypeWellKnownGroup, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS,
    TOKEN_OWNER, TOKEN_PRIMARY_GROUP, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_TYPE,
    TOKEN_USER, TokenGroups, TokenHasRestrictions, TokenIsAppContainer, TokenOwner, TokenPrimary,
    TokenPrimaryGroup, TokenPrivileges, TokenRestrictedSids, TokenSessionId, TokenStatistics,
    TokenType, TokenUIAccess, TokenUser,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};
use windows::core::{PCWSTR, PWSTR};
use zeroize::Zeroize as _;

use super::{
    CapturedServiceToken, ExpectedPrivilege, FixturePrivilege, ForbiddenPrivilege,
    ForbiddenPrivilegeLuid, KEY_AGENT_SERVICE_FIXTURE_PRIVILEGES,
    KEY_AGENT_SERVICE_FORBIDDEN_PRIVILEGES, KEY_AGENT_VIRTUAL_SERVICE_ACCOUNT, LuidValue,
    PrivilegeCatalog, PrivilegeEntry, RecapturedServiceToken, ServiceTokenBaseline,
    ServiceTokenFixtureError, ServiceTokenObservation, SidBytes, SidEntry, TokenIdentityBaseline,
};

const MIN_BINARY_SID_BYTES: usize = 8;
const MAX_BINARY_SID_BYTES: usize = 68;
const MAX_TOKEN_INFORMATION_BYTES: usize = 64 * 1024;
const MAX_DOMAIN_NAME_UNITS: usize = 256;
const EXPECTED_DOMAIN_NAME: &[u16] = &[78, 84, 32, 83, 69, 82, 86, 73, 67, 69];
const CURRENT_SERVICE_TOKEN_ACCESS: windows::Win32::Security::TOKEN_ACCESS_MASK = TOKEN_QUERY;

pub(super) fn capture_current_service_token()
-> Result<CapturedServiceToken, ServiceTokenFixtureError> {
    reject_thread_impersonation()?;
    let (token, token_handle_flags) = open_current_process_token()?;
    let baseline = capture_service_token_baseline(token.raw(), token_handle_flags)?;
    reject_thread_impersonation()?;

    Ok(CapturedServiceToken { token, baseline })
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "debug-only Phase 1 service probe is gated out of ordinary builds"
    )
)]
pub(super) fn recapture_current_service_token(
    retained: &OwnedToken,
) -> Result<RecapturedServiceToken, ServiceTokenFixtureError> {
    reject_thread_impersonation()?;
    let retained_handle_flags = token_handle_flags(retained)?;
    let mut baseline = capture_service_token_baseline(retained.raw(), retained_handle_flags)?;
    let (token, fresh_handle_flags) = open_current_process_token()?;
    let same_token_object = same_kernel_object(retained.raw(), token.raw());
    let fresh_identity = token_identity_baseline(token.raw())?;
    if fresh_identity != baseline.observation.identity {
        return Err(ServiceTokenFixtureError::policy());
    }
    baseline.token_handle_flags = fresh_handle_flags;
    reject_thread_impersonation()?;

    Ok(RecapturedServiceToken {
        captured: CapturedServiceToken { token, baseline },
        retained_handle_flags,
        same_token_object,
    })
}

fn capture_service_token_baseline(
    token: HANDLE,
    token_handle_flags: u32,
) -> Result<ServiceTokenBaseline, ServiceTokenFixtureError> {
    let service_sid = resolve_fixed_service_sid()?;
    let catalog = resolve_privilege_catalog()?;

    let identity_before = token_identity_baseline(token)?;
    let token_is_primary = token_type(token)? == TokenPrimary;
    let session_id = token_u32(token, TokenSessionId)?;
    let app_container = exact_boolean(token_u32(token, TokenIsAppContainer)?)?;
    let ui_access = exact_boolean(token_u32(token, TokenUIAccess)?)?;
    let has_restrictions = token_has_restrictions(token)?;
    let user_sid = token_user_sid(token)?;
    if user_sid != service_sid {
        return Err(ServiceTokenFixtureError::policy());
    }
    let owner_sid = token_owner_sid(token)?;
    let primary_group_sid = token_primary_group_sid(token)?;
    let groups = token_sid_entries(token, TokenGroups)?;
    let restricted_sids = token_sid_entries(token, TokenRestrictedSids)?;
    let privileges = token_privileges(token)?;
    let identity = token_identity_baseline(token)?;
    if identity != identity_before {
        return Err(ServiceTokenFixtureError::policy());
    }

    Ok(ServiceTokenBaseline {
        token_handle_flags,
        observation: ServiceTokenObservation {
            identity,
            token_is_primary,
            session_id,
            app_container,
            ui_access,
            has_restrictions,
            user_sid,
            owner_sid,
            primary_group_sid,
            groups,
            restricted_sids,
            privileges,
        },
        catalog,
    })
}

pub(super) struct OwnedToken {
    handle: HANDLE,
    _not_sync: PhantomData<Cell<()>>,
}

// SAFETY: this owner contains one non-inheritable query-only token handle and
// no thread-affine impersonation state. Moving sole ownership does not alias or
// duplicate the handle; Drop still closes it exactly once.
unsafe impl Send for OwnedToken {}

impl OwnedToken {
    const fn new(handle: HANDLE) -> Self {
        Self {
            handle,
            _not_sync: PhantomData,
        }
    }

    const fn raw(&self) -> HANDLE {
        self.handle
    }

    pub(super) fn borrowed_handle(&self) -> BorrowedHandle<'_> {
        // SAFETY: this move-only owner keeps the exact live handle until the
        // returned borrow ends.
        unsafe { BorrowedHandle::borrow_raw(self.raw().0) }
    }

    #[cfg(test)]
    pub(super) fn invalid_for_test() -> Self {
        Self::new(HANDLE::default())
    }
}

impl fmt::Debug for OwnedToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OwnedToken([REDACTED])")
    }
}

impl Drop for OwnedToken {
    fn drop(&mut self) {
        if !invalid_handle(self.handle) {
            // SAFETY: every OwnedToken owns one successful OpenProcessToken result.
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

struct AlignedBuffer {
    words: Vec<usize>,
    returned_bytes: usize,
}

impl AlignedBuffer {
    fn as_ptr<T>(&self) -> *const T {
        self.words.as_ptr().cast::<T>()
    }

    fn as_mut_ptr<T>(&mut self) -> *mut T {
        self.words.as_mut_ptr().cast::<T>()
    }

    fn initialized_bytes(&self) -> &[u8] {
        // SAFETY: construction bounds returned_bytes by the initialized owner.
        unsafe {
            core::slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.returned_bytes)
        }
    }

    fn capacity_bytes(&self) -> Result<usize, ServiceTokenFixtureError> {
        self.words
            .len()
            .checked_mul(size_of::<usize>())
            .ok_or_else(ServiceTokenFixtureError::operating_system)
    }
}

impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        self.words.zeroize();
        self.returned_bytes.zeroize();
    }
}

struct ZeroizedWide(Vec<u16>);

impl Drop for ZeroizedWide {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn open_current_process_token() -> Result<(OwnedToken, u32), ServiceTokenFixtureError> {
    let mut token = HANDLE::default();
    // SAFETY: the process pseudo-handle is valid and output receives one fresh
    // query-only token handle.
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            CURRENT_SERVICE_TOKEN_ACCESS,
            &raw mut token,
        )
    }
    .map_err(|_| ServiceTokenFixtureError::operating_system())?;
    if invalid_handle(token) {
        return Err(ServiceTokenFixtureError::operating_system());
    }
    let owned = OwnedToken::new(token);
    let flags = token_handle_flags(&owned)?;
    Ok((owned, flags))
}

fn token_handle_flags(token: &OwnedToken) -> Result<u32, ServiceTokenFixtureError> {
    let mut flags = u32::MAX;
    // SAFETY: the owned token is live and flags is one initialized scalar.
    unsafe { GetHandleInformation(token.raw(), &raw mut flags) }
        .map_err(|_| ServiceTokenFixtureError::operating_system())?;
    Ok(flags)
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "debug-only Phase 1 service probe is gated out of ordinary builds"
    )
)]
fn same_kernel_object(first: HANDLE, second: HANDLE) -> bool {
    // SAFETY: callers retain both validated live handles for this observation.
    unsafe { CompareObjectHandles(first, second) }.as_bool()
}

fn reject_thread_impersonation() -> Result<(), ServiceTokenFixtureError> {
    let mut token = HANDLE::default();
    // SAFETY: the current thread pseudo-handle is valid. OpenAsSelf makes the
    // query independent of any present impersonation level.
    match unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &raw mut token) } {
        Err(error) if error.code() == ERROR_NO_TOKEN.to_hresult() => Ok(()),
        Ok(()) => {
            if !invalid_handle(token) {
                // SAFETY: unexpected success returned one fresh token handle.
                unsafe {
                    let _ = CloseHandle(token);
                }
            }
            Err(ServiceTokenFixtureError::policy())
        }
        Err(_) => Err(ServiceTokenFixtureError::operating_system()),
    }
}

fn resolve_fixed_service_sid() -> Result<SidBytes, ServiceTokenFixtureError> {
    let account: Vec<u16> = KEY_AGENT_VIRTUAL_SERVICE_ACCOUNT
        .encode_utf16()
        .chain(core::iter::once(0))
        .collect();
    let mut sid_bytes = 0_u32;
    let mut domain_units = 0_u32;
    let mut sid_use = SID_NAME_USE::default();
    // SAFETY: this first call supplies no output buffers and asks for exact sizes.
    let first = unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(account.as_ptr()),
            None,
            &raw mut sid_bytes,
            None,
            &raw mut domain_units,
            &raw mut sid_use,
        )
    };
    if !matches!(first, Err(ref error) if error.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult()) {
        return Err(ServiceTokenFixtureError::operating_system());
    }

    let sid_bytes_usize =
        usize::try_from(sid_bytes).map_err(|_| ServiceTokenFixtureError::operating_system())?;
    let domain_units_usize =
        usize::try_from(domain_units).map_err(|_| ServiceTokenFixtureError::operating_system())?;
    if !(MIN_BINARY_SID_BYTES..=MAX_BINARY_SID_BYTES).contains(&sid_bytes_usize)
        || domain_units_usize == 0
        || domain_units_usize > MAX_DOMAIN_NAME_UNITS
    {
        return Err(ServiceTokenFixtureError::operating_system());
    }

    let mut sid_owner = aligned_buffer(sid_bytes_usize)?;
    let mut domain = ZeroizedWide(vec![0_u16; domain_units_usize]);
    let mut returned_sid_bytes = sid_bytes;
    let mut returned_domain_units = domain_units;
    sid_use = SID_NAME_USE::default();
    // SAFETY: both zeroed output owners have the exact declared capacities and
    // the fixed account string is NUL terminated for the complete call.
    unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(account.as_ptr()),
            Some(PSID(sid_owner.as_mut_ptr::<c_void>())),
            &raw mut returned_sid_bytes,
            Some(PWSTR(domain.0.as_mut_ptr())),
            &raw mut returned_domain_units,
            &raw mut sid_use,
        )
    }
    .map_err(|_| ServiceTokenFixtureError::operating_system())?;

    let returned_sid_bytes = usize::try_from(returned_sid_bytes)
        .map_err(|_| ServiceTokenFixtureError::operating_system())?;
    if returned_sid_bytes != sid_bytes_usize
        || sid_use != SidTypeWellKnownGroup
        || !wide_domain_is_expected(&domain.0)
    {
        return Err(ServiceTokenFixtureError::policy());
    }
    sid_owner.returned_bytes = returned_sid_bytes;
    copy_bounded_sid(&sid_owner, PSID(sid_owner.as_ptr::<c_void>().cast_mut()))
}

fn wide_domain_is_expected(domain: &[u16]) -> bool {
    let Some(nul_index) = domain.iter().position(|unit| *unit == 0) else {
        return false;
    };
    domain[..nul_index] == *EXPECTED_DOMAIN_NAME
        && nul_index == EXPECTED_DOMAIN_NAME.len()
        && domain[nul_index..].iter().all(|unit| *unit == 0)
}

fn resolve_privilege_catalog() -> Result<PrivilegeCatalog, ServiceTokenFixtureError> {
    let expected = [
        ExpectedPrivilege {
            kind: FixturePrivilege::ChangeNotify,
            luid: lookup_privilege_luid(KEY_AGENT_SERVICE_FIXTURE_PRIVILEGES[0])?,
        },
        ExpectedPrivilege {
            kind: FixturePrivilege::Impersonate,
            luid: lookup_privilege_luid(KEY_AGENT_SERVICE_FIXTURE_PRIVILEGES[1])?,
        },
        ExpectedPrivilege {
            kind: FixturePrivilege::IncreaseQuota,
            luid: lookup_privilege_luid(KEY_AGENT_SERVICE_FIXTURE_PRIVILEGES[2])?,
        },
        ExpectedPrivilege {
            kind: FixturePrivilege::AssignPrimaryToken,
            luid: lookup_privilege_luid(KEY_AGENT_SERVICE_FIXTURE_PRIVILEGES[3])?,
        },
    ];
    let forbidden = [
        ForbiddenPrivilegeLuid {
            kind: ForbiddenPrivilege::TrustedComputingBase,
            luid: lookup_privilege_luid(KEY_AGENT_SERVICE_FORBIDDEN_PRIVILEGES[0])?,
        },
        ForbiddenPrivilegeLuid {
            kind: ForbiddenPrivilege::Debug,
            luid: lookup_privilege_luid(KEY_AGENT_SERVICE_FORBIDDEN_PRIVILEGES[1])?,
        },
        ForbiddenPrivilegeLuid {
            kind: ForbiddenPrivilege::TakeOwnership,
            luid: lookup_privilege_luid(KEY_AGENT_SERVICE_FORBIDDEN_PRIVILEGES[2])?,
        },
        ForbiddenPrivilegeLuid {
            kind: ForbiddenPrivilege::Restore,
            luid: lookup_privilege_luid(KEY_AGENT_SERVICE_FORBIDDEN_PRIVILEGES[3])?,
        },
    ];
    Ok(PrivilegeCatalog {
        expected,
        forbidden,
    })
}

fn lookup_privilege_luid(name: &str) -> Result<LuidValue, ServiceTokenFixtureError> {
    let name: Vec<u16> = name.encode_utf16().chain(core::iter::once(0)).collect();
    let mut luid = LUID::default();
    // SAFETY: the fixed privilege name is NUL terminated and output is one LUID.
    unsafe { LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(name.as_ptr()), &raw mut luid) }
        .map_err(|_| ServiceTokenFixtureError::operating_system())?;
    Ok(LuidValue {
        low_part: luid.LowPart,
        high_part: luid.HighPart,
    })
}

fn token_identity_baseline(
    token: HANDLE,
) -> Result<TokenIdentityBaseline, ServiceTokenFixtureError> {
    let information = token_information(token, TokenStatistics, size_of::<TOKEN_STATISTICS>())?;
    if information.returned_bytes != size_of::<TOKEN_STATISTICS>() {
        return Err(ServiceTokenFixtureError::operating_system());
    }
    // SAFETY: the exact initialized TOKEN_STATISTICS extent was checked above;
    // each read selects one fixed-size field without copying unrelated dynamic
    // allocator/accounting state out of the zeroized owner.
    let token_type = unsafe {
        ptr::read_unaligned(
            information
                .as_ptr::<u8>()
                .add(offset_of!(TOKEN_STATISTICS, TokenType))
                .cast::<TOKEN_TYPE>(),
        )
    };
    if token_type != TokenPrimary {
        return Err(ServiceTokenFixtureError::policy());
    }
    // SAFETY: the same exact initialized owner contains both complete LUID
    // fields at their generated structure offsets.
    let mut token_id = unsafe {
        ptr::read_unaligned(
            information
                .as_ptr::<u8>()
                .add(offset_of!(TOKEN_STATISTICS, TokenId))
                .cast::<LUID>(),
        )
    };
    // SAFETY: identical bounds reasoning applies to ModifiedId.
    let mut modified_id = unsafe {
        ptr::read_unaligned(
            information
                .as_ptr::<u8>()
                .add(offset_of!(TOKEN_STATISTICS, ModifiedId))
                .cast::<LUID>(),
        )
    };
    let baseline = TokenIdentityBaseline {
        token_id: LuidValue {
            low_part: token_id.LowPart,
            high_part: token_id.HighPart,
        },
        modified_id: LuidValue {
            low_part: modified_id.LowPart,
            high_part: modified_id.HighPart,
        },
    };
    token_id.LowPart.zeroize();
    token_id.HighPart.zeroize();
    modified_id.LowPart.zeroize();
    modified_id.HighPart.zeroize();
    Ok(baseline)
}

fn token_type(token: HANDLE) -> Result<TOKEN_TYPE, ServiceTokenFixtureError> {
    let information = token_information(token, TokenType, size_of::<TOKEN_TYPE>())?;
    read_fixed(&information)
}

fn token_u32(
    token: HANDLE,
    class: TOKEN_INFORMATION_CLASS,
) -> Result<u32, ServiceTokenFixtureError> {
    let information = token_information(token, class, size_of::<u32>())?;
    read_fixed(&information)
}

fn exact_boolean(value: u32) -> Result<bool, ServiceTokenFixtureError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ServiceTokenFixtureError::operating_system()),
    }
}

fn token_has_restrictions(token: HANDLE) -> Result<bool, ServiceTokenFixtureError> {
    let information = token_information(token, TokenHasRestrictions, 1)?;
    match information.initialized_bytes() {
        [value] => exact_boolean(u32::from(*value)),
        [first, second, third, fourth] => {
            exact_boolean(u32::from_ne_bytes([*first, *second, *third, *fourth]))
        }
        _ => Err(ServiceTokenFixtureError::operating_system()),
    }
}

fn token_user_sid(token: HANDLE) -> Result<SidBytes, ServiceTokenFixtureError> {
    let information = token_information(token, TokenUser, size_of::<TOKEN_USER>())?;
    // SAFETY: the aligned buffer contains a complete TOKEN_USER prefix.
    let user = unsafe { ptr::read_unaligned(information.as_ptr::<TOKEN_USER>()) };
    copy_bounded_sid(&information, user.User.Sid)
}

fn token_owner_sid(token: HANDLE) -> Result<SidBytes, ServiceTokenFixtureError> {
    let information = token_information(token, TokenOwner, size_of::<TOKEN_OWNER>())?;
    // SAFETY: the aligned buffer contains a complete TOKEN_OWNER prefix.
    let owner = unsafe { ptr::read_unaligned(information.as_ptr::<TOKEN_OWNER>()) };
    copy_bounded_sid(&information, owner.Owner)
}

fn token_primary_group_sid(token: HANDLE) -> Result<SidBytes, ServiceTokenFixtureError> {
    let information =
        token_information(token, TokenPrimaryGroup, size_of::<TOKEN_PRIMARY_GROUP>())?;
    // SAFETY: the aligned buffer contains a complete TOKEN_PRIMARY_GROUP prefix.
    let primary_group = unsafe { ptr::read_unaligned(information.as_ptr::<TOKEN_PRIMARY_GROUP>()) };
    copy_bounded_sid(&information, primary_group.PrimaryGroup)
}

fn token_sid_entries(
    token: HANDLE,
    class: TOKEN_INFORMATION_CLASS,
) -> Result<Vec<SidEntry>, ServiceTokenFixtureError> {
    let entries_offset = offset_of!(TOKEN_GROUPS, Groups);
    let information = token_information(token, class, entries_offset)?;
    // SAFETY: the initialized buffer contains the complete count prefix.
    let count = usize::try_from(unsafe {
        ptr::read_unaligned(information.as_ptr::<TOKEN_GROUPS>()).GroupCount
    })
    .map_err(|_| ServiceTokenFixtureError::operating_system())?;
    let entries_bytes = count
        .checked_mul(size_of::<SID_AND_ATTRIBUTES>())
        .and_then(|bytes| entries_offset.checked_add(bytes))
        .filter(|required| *required <= information.returned_bytes)
        .ok_or_else(ServiceTokenFixtureError::operating_system)?;
    let _ = entries_bytes;

    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let offset = index
            .checked_mul(size_of::<SID_AND_ATTRIBUTES>())
            .and_then(|bytes| entries_offset.checked_add(bytes))
            .ok_or_else(ServiceTokenFixtureError::operating_system)?;
        // SAFETY: the full flexible array was bounded above and this selects one entry.
        let entry = unsafe {
            ptr::read_unaligned(
                information
                    .as_ptr::<u8>()
                    .add(offset)
                    .cast::<SID_AND_ATTRIBUTES>(),
            )
        };
        entries.push(SidEntry {
            sid: copy_bounded_sid(&information, entry.Sid)?,
            attributes: entry.Attributes,
        });
    }
    Ok(entries)
}

fn token_privileges(token: HANDLE) -> Result<Vec<PrivilegeEntry>, ServiceTokenFixtureError> {
    let entries_offset = offset_of!(TOKEN_PRIVILEGES, Privileges);
    let information = token_information(token, TokenPrivileges, entries_offset)?;
    // SAFETY: the initialized buffer contains the complete count prefix.
    let count = usize::try_from(unsafe {
        ptr::read_unaligned(information.as_ptr::<TOKEN_PRIVILEGES>()).PrivilegeCount
    })
    .map_err(|_| ServiceTokenFixtureError::operating_system())?;
    let required = count
        .checked_mul(size_of::<windows::Win32::Security::LUID_AND_ATTRIBUTES>())
        .and_then(|bytes| entries_offset.checked_add(bytes))
        .ok_or_else(ServiceTokenFixtureError::operating_system)?;
    if required != information.returned_bytes {
        return Err(ServiceTokenFixtureError::operating_system());
    }

    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let offset = index
            .checked_mul(size_of::<windows::Win32::Security::LUID_AND_ATTRIBUTES>())
            .and_then(|bytes| entries_offset.checked_add(bytes))
            .ok_or_else(ServiceTokenFixtureError::operating_system)?;
        // SAFETY: the exact flexible-array extent was checked above.
        let entry = unsafe {
            ptr::read_unaligned(
                information
                    .as_ptr::<u8>()
                    .add(offset)
                    .cast::<windows::Win32::Security::LUID_AND_ATTRIBUTES>(),
            )
        };
        entries.push(PrivilegeEntry {
            luid: LuidValue {
                low_part: entry.Luid.LowPart,
                high_part: entry.Luid.HighPart,
            },
            attributes: entry.Attributes.0,
        });
    }
    Ok(entries)
}

fn read_fixed<T: Copy>(information: &AlignedBuffer) -> Result<T, ServiceTokenFixtureError> {
    if information.returned_bytes != size_of::<T>() {
        return Err(ServiceTokenFixtureError::operating_system());
    }
    // SAFETY: the exact initialized size and aligned owner were checked above.
    Ok(unsafe { ptr::read_unaligned(information.as_ptr::<T>()) })
}

fn token_information(
    token: HANDLE,
    class: TOKEN_INFORMATION_CLASS,
    minimum_bytes: usize,
) -> Result<AlignedBuffer, ServiceTokenFixtureError> {
    let mut needed = 0_u32;
    // SAFETY: this first call deliberately requests the exact required size.
    let first = unsafe { GetTokenInformation(token, class, None, 0, &raw mut needed) };
    if !matches!(first, Err(ref error) if error.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult()) {
        return Err(ServiceTokenFixtureError::operating_system());
    }
    let needed =
        usize::try_from(needed).map_err(|_| ServiceTokenFixtureError::operating_system())?;
    if needed < minimum_bytes || needed > MAX_TOKEN_INFORMATION_BYTES {
        return Err(ServiceTokenFixtureError::operating_system());
    }
    let mut owner = aligned_buffer(needed)?;
    let capacity = owner.capacity_bytes()?;
    let capacity_u32 =
        u32::try_from(capacity).map_err(|_| ServiceTokenFixtureError::operating_system())?;
    let mut returned = capacity_u32;
    // SAFETY: the aligned owner is writable for its complete declared capacity.
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some(owner.as_mut_ptr::<c_void>()),
            capacity_u32,
            &raw mut returned,
        )
    }
    .map_err(|_| ServiceTokenFixtureError::operating_system())?;
    let returned =
        usize::try_from(returned).map_err(|_| ServiceTokenFixtureError::operating_system())?;
    if returned < minimum_bytes || returned > capacity {
        return Err(ServiceTokenFixtureError::operating_system());
    }
    owner.returned_bytes = returned;
    Ok(owner)
}

fn aligned_buffer(bytes: usize) -> Result<AlignedBuffer, ServiceTokenFixtureError> {
    let word_bytes = size_of::<usize>();
    let words = bytes
        .checked_add(word_bytes.saturating_sub(1))
        .and_then(|rounded| rounded.checked_div(word_bytes))
        .filter(|count| *count != 0)
        .ok_or_else(ServiceTokenFixtureError::operating_system)?;
    Ok(AlignedBuffer {
        words: vec![0_usize; words],
        returned_bytes: 0,
    })
}

fn copy_bounded_sid(
    owner: &AlignedBuffer,
    sid: PSID,
) -> Result<SidBytes, ServiceTokenFixtureError> {
    if sid.0.is_null() {
        return Err(ServiceTokenFixtureError::operating_system());
    }
    let owner_start = owner.as_ptr::<u8>() as usize;
    let sid_start = sid.0 as usize;
    let sid_offset = sid_start
        .checked_sub(owner_start)
        .filter(|offset| *offset <= owner.returned_bytes)
        .ok_or_else(ServiceTokenFixtureError::operating_system)?;
    let sid_header_end = sid_offset
        .checked_add(MIN_BINARY_SID_BYTES)
        .filter(|end| *end <= owner.returned_bytes)
        .ok_or_else(ServiceTokenFixtureError::operating_system)?;
    let returned = owner.initialized_bytes();
    let sub_authority_count = usize::from(
        *returned
            .get(sid_offset + 1)
            .ok_or_else(ServiceTokenFixtureError::operating_system)?,
    );
    if sub_authority_count > 15 {
        return Err(ServiceTokenFixtureError::operating_system());
    }
    let sid_bytes = sub_authority_count
        .checked_mul(size_of::<u32>())
        .and_then(|sub_authorities| MIN_BINARY_SID_BYTES.checked_add(sub_authorities))
        .filter(|length| *length <= MAX_BINARY_SID_BYTES)
        .ok_or_else(ServiceTokenFixtureError::operating_system)?;
    let sid_end = sid_offset
        .checked_add(sid_bytes)
        .filter(|end| *end <= owner.returned_bytes && *end >= sid_header_end)
        .ok_or_else(ServiceTokenFixtureError::operating_system)?;

    // SAFETY: the SID range is wholly contained in the still-live initialized owner.
    let valid = unsafe { IsValidSid(sid) }.as_bool();
    // SAFETY: the same bounded SID remains live for the length query.
    let length = usize::try_from(unsafe { GetLengthSid(sid) })
        .map_err(|_| ServiceTokenFixtureError::operating_system())?;
    if !valid || length != sid_bytes {
        return Err(ServiceTokenFixtureError::operating_system());
    }
    Ok(SidBytes(returned[sid_offset..sid_end].to_vec()))
}

fn invalid_handle(handle: HANDLE) -> bool {
    handle.0.is_null() || handle == INVALID_HANDLE_VALUE || handle.is_invalid()
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::{HANDLE_FLAG_INHERIT, HANDLE_FLAGS, SetHandleInformation};

    trait AmbiguousIfSync<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfSync<()> for T {}
    impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for T {}

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

    fn assert_send<T: Send>() {}

    #[test]
    fn owned_query_token_is_move_only_send_not_sync_and_redacted() {
        assert_send::<OwnedToken>();
        let _ = <OwnedToken as AmbiguousIfSync<_>>::marker;
        let _ = <OwnedToken as AmbiguousIfClone<_>>::marker;
        let _ = <OwnedToken as AmbiguousIfCopy<_>>::marker;
        assert_eq!(CURRENT_SERVICE_TOKEN_ACCESS.0, TOKEN_QUERY.0);

        let token = OwnedToken::invalid_for_test();
        assert_eq!(format!("{token:?}"), "OwnedToken([REDACTED])");
    }

    #[test]
    fn current_query_tokens_are_same_non_inheritable_object_and_drop_closes()
    -> Result<(), ServiceTokenFixtureError> {
        let (first, first_flags) = open_current_process_token()?;
        let (second, second_flags) = open_current_process_token()?;
        assert_eq!(first_flags, 0);
        assert_eq!(second_flags, 0);
        assert!(same_kernel_object(first.raw(), second.raw()));

        let closed_raw = first.raw();
        drop(first);
        let mut flags = u32::MAX;
        // SAFETY: this is a negative observation of the just-closed value; no
        // ownership is reconstructed and no API may consume it.
        assert!(unsafe { GetHandleInformation(closed_raw, &raw mut flags) }.is_err());
        assert_eq!(token_handle_flags(&second)?, 0);
        Ok(())
    }

    #[test]
    fn handle_flag_drift_and_wrong_kernel_object_are_observed()
    -> Result<(), ServiceTokenFixtureError> {
        let (token, flags) = open_current_process_token()?;
        assert_eq!(flags, 0);
        // SAFETY: the process pseudo-handle is valid for this read-only object
        // comparison and carries no ownership.
        assert!(!same_kernel_object(token.raw(), unsafe {
            GetCurrentProcess()
        }));

        // SAFETY: the test owns this live token handle and changes only its
        // process-local inheritance bit for the bounded negative observation.
        unsafe { SetHandleInformation(token.raw(), HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT) }
            .map_err(|_| ServiceTokenFixtureError::operating_system())?;
        assert_eq!(token_handle_flags(&token)?, HANDLE_FLAG_INHERIT.0);
        // SAFETY: restore the same owned handle before the test releases it.
        unsafe { SetHandleInformation(token.raw(), HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)) }
            .map_err(|_| ServiceTokenFixtureError::operating_system())?;
        assert_eq!(token_handle_flags(&token)?, 0);
        Ok(())
    }
}
