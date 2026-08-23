//! Documented Win32 checks for the authenticated Approval runtime bootstrap.

#![allow(unsafe_code)]

use core::ffi::c_void;
use core::fmt;
use core::marker::PhantomData;
use core::mem::size_of;
use core::ptr;
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle, RawHandle};
use std::rc::Rc;

use approval_wire::{
    ApprovalChildHello, ApprovalParentHello, CHILD_HELLO_BYTES, MAX_PARENT_FINISH_BYTES,
    PARENT_FINISH_HEADER_BYTES, PARENT_HELLO_BYTES, decode_parent_finish, decode_parent_hello,
    encode_child_hello,
};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use windows::Win32::Foundation::{
    CloseHandle, CompareObjectHandles, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_NO_TOKEN,
    ERROR_SUCCESS, FILETIME, GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAGS, HWND,
    INVALID_HANDLE_VALUE, SetHandleInformation, WAIT_TIMEOUT,
};
use windows::Win32::Security::Isolation::DeriveAppContainerSidFromAppContainerName;
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_LIFETIME_SIGNING_FLAG,
    WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvSignerFromChain,
    WTHelperProvDataFromStateData, WinVerifyTrust,
};
use windows::Win32::Security::{
    EqualSid, FreeSid, GetTokenInformation, IsValidSid, PSID, TOKEN_APPCONTAINER_INFORMATION,
    TOKEN_QUERY, TokenAppContainerSid, TokenCapabilities, TokenIsAppContainer,
    TokenIsLessPrivilegedAppContainer,
};
use windows::Win32::Storage::FileSystem::{
    FILE_TYPE_PIPE, GETFINALPATHNAMEBYHANDLE_FLAGS, GetFileType, GetFileVersionInfoSizeW,
    GetFileVersionInfoW, GetFinalPathNameByHandleW, VS_FIXEDFILEINFO, VerQueryValueW,
};
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::JobObjects::{
    IsProcessInJob, JOB_OBJECT_LIMIT, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, QueryInformationJobObject,
};
use windows::Win32::System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeClientSessionId};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, GetProcessId, GetProcessTimes, OpenProcessToken,
    OpenThreadToken, PROCESS_NAME_WIN32, QueryFullProcessImageNameW, WaitForSingleObject,
};
use windows::core::{BOOL, PCWSTR, PWSTR};
use zeroize::{Zeroize as _, Zeroizing};

use super::AuthenticatedApprovalRequest;

const PROFILE_V1_NAME: &str = "YourWallet.ApprovalFrontend.LPAC.v1";
const MAX_TOKEN_INFORMATION_BYTES: usize = 64 * 1024;
const MAX_PATH_UNITS: usize = 32_768;
const VS_FIXEDFILEINFO_SIGNATURE: u32 = 0xFEEF_04BD;

/// Immutable evidence generated only by the reviewed release pipeline and then
/// covered by the Approval helper's own code signature.
#[derive(Clone, Copy)]
struct ParentTrustPolicy {
    executable_sha256: [u8; 32],
    signer_certificate_sha256: [u8; 32],
    version: [u16; 4],
}

// A release build may replace this only through the same reviewed generated
// source step as the platform release attestation. Keeping it absent prevents
// a test feature or arbitrary caller from turning the Approval surface on.
const COMPILED_PARENT_POLICY: Option<ParentTrustPolicy> = None;

#[must_use = "the Approval bootstrap must retain its sealed channel proof"]
struct Channels {
    stdio: SealedApprovalStdio,
    parent_process_id: u32,
    parent_session_id: u32,
}

#[must_use = "binary mode and request processing require the sealed Approval stdio proof"]
struct SealedApprovalStdio {
    input: HANDLE,
    output: HANDLE,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

pub(super) fn authenticate_request()
-> Result<AuthenticatedApprovalRequest, approval_ui::ApprovalError> {
    let sealed_stdio = seal_inherited_approval_stdio()?;
    let channels = verify_self_and_channels(sealed_stdio)?;
    let Some(policy) = COMPILED_PARENT_POLICY else {
        return Err(native_failure(()));
    };

    let input = std::io::stdin();
    let mut reader = input.lock();
    let mut encoded_parent = Zeroizing::new([0_u8; PARENT_HELLO_BYTES]);
    reader.read_exact(&mut *encoded_parent)?;
    let parent_hello = decode_parent_hello(&*encoded_parent)?;
    verify_parent_process_id(&parent_hello, channels.parent_process_id)?;
    let parent_handles = verify_parent_handles(
        &parent_hello,
        channels.parent_session_id,
        channels.stdio.input,
        channels.stdio.output,
        policy,
    )?;

    let mut child_nonce = [0_u8; 32];
    getrandom::fill(&mut child_nonce).map_err(native_failure)?;
    let child_hello = ApprovalChildHello::new(child_nonce)?;
    child_nonce.zeroize();
    let encoded_child = encode_child_hello(&parent_hello, &child_hello);
    debug_assert_eq!(encoded_child.len(), CHILD_HELLO_BYTES);
    let output = std::io::stdout();
    let mut writer = output.lock();
    writer.write_all(&encoded_child)?;
    writer.flush()?;

    let maximum_finish = PARENT_FINISH_HEADER_BYTES
        .checked_add(usize::try_from(approval_ui::MAX_REQUEST_BYTES).map_err(native_failure)?)
        .ok_or_else(|| native_failure(()))?;
    if maximum_finish != MAX_PARENT_FINISH_BYTES {
        return Err(native_failure(()));
    }
    let read_bound = u64::try_from(maximum_finish)
        .map_err(native_failure)?
        .checked_add(1)
        .ok_or_else(|| native_failure(()))?;
    let mut finish = Zeroizing::new(Vec::new());
    reader.take(read_bound).read_to_end(&mut finish)?;
    if finish.len() > maximum_finish {
        return Err(approval_ui::ApprovalError::Malformed);
    }
    let request = decode_parent_finish(&parent_hello, &child_hello, finish.as_slice())?;
    // Keep both proof kernel objects pinned until the exact nonce/hash-bound
    // request has arrived. They close before native UI code is entered.
    drop(parent_handles);
    Ok(AuthenticatedApprovalRequest::new(request))
}

fn verify_parent_process_id(
    hello: &ApprovalParentHello,
    expected_process_id: u32,
) -> Result<(), approval_ui::ApprovalError> {
    (hello.process_id() == expected_process_id)
        .then_some(())
        .ok_or_else(|| native_failure(()))
}

fn verify_self_and_channels(
    sealed: SealedApprovalStdio,
) -> Result<Channels, approval_ui::ApprovalError> {
    set_binary_stdio(&sealed)?;
    verify_lpac_token()?;
    verify_job()?;
    let input = sealed.input;
    let output = sealed.output;
    let (input_pid, input_session) = pipe_client(input)?;
    let (output_pid, output_session) = pipe_client(output)?;
    if input_pid == 0
        || input_pid != output_pid
        || input_session != output_session
        || input_session == u32::MAX
    {
        return Err(native_failure(()));
    }
    let mut parent_process_session = u32::MAX;
    // SAFETY: output points to one initialized DWORD.
    unsafe { ProcessIdToSessionId(input_pid, &raw mut parent_process_session) }
        .map_err(native_failure)?;
    let mut child_session = u32::MAX;
    // SAFETY: output points to one initialized DWORD and std::process::id is
    // the live current Approval child PID.
    unsafe { ProcessIdToSessionId(std::process::id(), &raw mut child_session) }
        .map_err(native_failure)?;
    if parent_process_session != input_session || child_session != input_session {
        return Err(native_failure(()));
    }
    Ok(Channels {
        stdio: sealed,
        parent_process_id: input_pid,
        parent_session_id: input_session,
    })
}

impl fmt::Debug for SealedApprovalStdio {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SealedApprovalStdio([REDACTED])")
    }
}

/// Seals the exact two unique inherited pipe objects before any other Windows,
/// CRT, protocol, or UI application operation. Stderr must be the same numeric
/// handle-table entry as stdout, matching the private launcher contract.
fn seal_inherited_approval_stdio() -> Result<SealedApprovalStdio, approval_ui::ApprovalError> {
    // SAFETY: these APIs return borrowed process standard handles. The process
    // retains ownership and the values are used only for this bootstrap proof.
    let input = unsafe { GetStdHandle(STD_INPUT_HANDLE) }.map_err(native_failure)?;
    // SAFETY: same borrowed standard-handle contract as input.
    let output = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) }.map_err(native_failure)?;
    // SAFETY: same borrowed standard-handle contract as input.
    let error = unsafe { GetStdHandle(STD_ERROR_HANDLE) }.map_err(native_failure)?;

    seal_exact_approval_stdio([input, output, error])?;
    Ok(SealedApprovalStdio {
        input,
        output,
        _not_send_or_sync: PhantomData,
    })
}

fn seal_exact_approval_stdio(handles: [HANDLE; 3]) -> Result<(), approval_ui::ApprovalError> {
    let [input, output, error] = handles;
    let unique = [input, output];
    if handles.iter().copied().any(invalid_handle)
        || input == output
        || output != error
        || same_object(input, output)
        || !same_object(output, error)
        // SAFETY: all candidates were proven live above and remain borrowed.
        || unsafe { GetFileType(input) } != FILE_TYPE_PIPE
        // SAFETY: same live borrowed-handle contract as input.
        || unsafe { GetFileType(output) } != FILE_TYPE_PIPE
        || unique.iter().any(|handle| {
            !matches!(handle_flags(*handle), Ok(flags) if flags == HANDLE_FLAG_INHERIT.0)
        })
    {
        return Err(native_failure(()));
    }

    // Clearing is intentionally non-atomic and has no rollback: attempt both
    // unique objects even when one call fails, then require exact zero flags on
    // both before issuing a proof.
    let mut clear_failed = false;
    for handle in unique {
        // SAFETY: both values are live borrowed standard handles. This changes
        // only the process-local inherit flag and never transfers ownership.
        if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)) }.is_err()
        {
            clear_failed = true;
        }
    }
    let exact_zero_flags = unique
        .iter()
        .all(|handle| matches!(handle_flags(*handle), Ok(0)));
    if clear_failed || !exact_zero_flags {
        return Err(native_failure(()));
    }
    Ok(())
}

fn set_binary_stdio(sealed: &SealedApprovalStdio) -> Result<(), approval_ui::ApprovalError> {
    const O_BINARY: i32 = 0x8000;

    unsafe extern "C" {
        fn _setmode(file_descriptor: i32, mode: i32) -> i32;
    }

    let input_still_sealed = matches!(handle_flags(sealed.input), Ok(0));
    let output_still_sealed = matches!(handle_flags(sealed.output), Ok(0));
    if !input_still_sealed || !output_still_sealed {
        return Err(native_failure(()));
    }
    // SAFETY: the stdio kernel objects were sealed above. File descriptors 0
    // and 1 remain live; `_setmode` changes only this process's CRT translation.
    let (input_mode, output_mode) = unsafe { (_setmode(0, O_BINARY), _setmode(1, O_BINARY)) };
    if input_mode == -1 || output_mode == -1 {
        return Err(std::io::Error::other("binary standard I/O unavailable").into());
    }
    Ok(())
}

fn invalid_handle(handle: HANDLE) -> bool {
    handle.is_invalid() || handle == INVALID_HANDLE_VALUE
}

fn same_object(first: HANDLE, second: HANDLE) -> bool {
    // SAFETY: callers reject invalid values before relying on this result and
    // all candidates remain live in the current process handle table.
    unsafe { CompareObjectHandles(first, second) }.as_bool()
}

fn handle_flags(handle: HANDLE) -> Result<u32, approval_ui::ApprovalError> {
    let mut flags = u32::MAX;
    // SAFETY: output points to one initialized flag word and the caller retains
    // the live borrowed or owned handle for this scalar query.
    unsafe { GetHandleInformation(handle, &raw mut flags) }.map_err(native_failure)?;
    Ok(flags)
}

fn exact_objects_are_pairwise_distinct(handles: &[HANDLE]) -> bool {
    handles.iter().enumerate().all(|(index, first)| {
        handles
            .iter()
            .skip(index + 1)
            .all(|second| !same_object(*first, *second))
    })
}

fn validate_parent_proof_handle_set(
    process: HANDLE,
    image: HANDLE,
    stdin: HANDLE,
    stdout: HANDLE,
) -> Result<(), approval_ui::ApprovalError> {
    let handles = [stdin, stdout, process, image];
    if handles.iter().copied().any(invalid_handle)
        || handles
            .iter()
            .any(|handle| !matches!(handle_flags(*handle), Ok(0)))
        || !exact_objects_are_pairwise_distinct(&handles)
    {
        return Err(native_failure(()));
    }
    Ok(())
}

fn pipe_client(handle: HANDLE) -> Result<(u32, u32), approval_ui::ApprovalError> {
    let mut process_id = 0_u32;
    let mut session_id = u32::MAX;
    // SAFETY: the sealed pipe is live for these non-owning queries and both
    // outputs are initialized exact-width values.
    unsafe {
        GetNamedPipeClientProcessId(handle, &raw mut process_id).map_err(native_failure)?;
        GetNamedPipeClientSessionId(handle, &raw mut session_id).map_err(native_failure)?;
    }
    Ok((process_id, session_id))
}

/// Owns one untrusted SID returned by the profile API until post-call checks,
/// SID validation, and exact comparison all complete.
struct UnvalidatedProfileApiSid {
    raw: Option<PSID>,
}

impl UnvalidatedProfileApiSid {
    const fn new(raw: PSID) -> Self {
        Self { raw: Some(raw) }
    }

    fn matches(&self, actual: PSID) -> Result<bool, approval_ui::ApprovalError> {
        let expected = self.raw.ok_or_else(|| native_failure(()))?;
        if actual.is_invalid() || expected.is_invalid() {
            return Err(native_failure(()));
        }
        // SAFETY: actual points into the still-live token buffer.
        let actual_is_valid = unsafe { IsValidSid(actual) }.as_bool();
        // SAFETY: expected remains owned by this wrapper.
        let expected_is_valid = unsafe { IsValidSid(expected) }.as_bool();
        if !actual_is_valid || !expected_is_valid {
            return Err(native_failure(()));
        }
        // SAFETY: both SIDs were validated and remain live.
        Ok(unsafe { EqualSid(actual, expected) }.is_ok())
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
        // SAFETY: a successful profile API call transferred this SID exactly
        // once to the wrapper, which releases it exactly once here.
        unsafe {
            let _ = FreeSid(sid);
        }
    }
}

fn reject_thread_impersonation() -> Result<(), approval_ui::ApprovalError> {
    let mut token = HANDLE::default();
    // SAFETY: the current pseudo-thread is valid for this query; OpenAsSelf
    // keeps the check independent from impersonation level.
    let result = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &raw mut token) };
    match result {
        Ok(()) if invalid_handle(token) => Err(native_failure(())),
        Ok(()) => {
            // SAFETY: successful OpenThreadToken returned one fresh handle.
            unsafe {
                let _ = CloseHandle(token);
            }
            Err(native_failure(()))
        }
        Err(error) if error.code() == ERROR_NO_TOKEN.to_hresult() => Ok(()),
        Err(_) => Err(native_failure(())),
    }
}

fn derive_expected_profile_sid(
    profile: &[u16],
) -> Result<UnvalidatedProfileApiSid, approval_ui::ApprovalError> {
    if profile.last().copied() != Some(0) {
        return Err(native_failure(()));
    }
    reject_thread_impersonation()?;
    // SAFETY: profile is a live NUL-terminated deterministic name.
    let expected = unsafe { DeriveAppContainerSidFromAppContainerName(PCWSTR(profile.as_ptr())) }
        .map(UnvalidatedProfileApiSid::new);
    reject_thread_impersonation()?;
    expected.map_err(native_failure)
}

fn verify_lpac_token() -> Result<(), approval_ui::ApprovalError> {
    let mut raw_token = HANDLE::default();
    // SAFETY: output receives one owned query handle for the current process.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut raw_token) }
        .map_err(native_failure)?;
    // SAFETY: successful OpenProcessToken returned unique ownership.
    let token = unsafe { owned_handle(raw_token.0 as usize as u64)? };
    if token_dword(&token, TokenIsAppContainer)? != 1
        || token_dword(&token, TokenIsLessPrivilegedAppContainer)? != 1
    {
        return Err(native_failure(()));
    }
    let capabilities = token_information(&token, TokenCapabilities)?;
    if capabilities.len().saturating_mul(size_of::<usize>()) < size_of::<u32>() {
        return Err(native_failure(()));
    }
    // SAFETY: aligned word storage contains at least the leading GroupCount.
    let count = unsafe { ptr::read_unaligned(capabilities.as_ptr().cast::<u32>()) };
    if count != 0 {
        return Err(native_failure(()));
    }
    let sid_buffer = token_information(&token, TokenAppContainerSid)?;
    if sid_buffer.len().saturating_mul(size_of::<usize>())
        < size_of::<TOKEN_APPCONTAINER_INFORMATION>()
    {
        return Err(native_failure(()));
    }
    // SAFETY: size and alignment were established; the interior SID remains
    // live while sid_buffer is retained.
    let container = unsafe {
        ptr::read_unaligned(sid_buffer.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>())
    };
    let profile = wide_nul(PROFILE_V1_NAME);
    let expected = derive_expected_profile_sid(&profile)?;
    expected
        .matches(container.TokenAppContainer)?
        .then_some(())
        .ok_or_else(|| native_failure(()))
}

fn verify_job() -> Result<(), approval_ui::ApprovalError> {
    let mut in_job = BOOL(0);
    // SAFETY: output is a live BOOL; None selects the current process job.
    unsafe { IsProcessInJob(GetCurrentProcess(), None, &raw mut in_job) }
        .map_err(native_failure)?;
    if !in_job.as_bool() {
        return Err(native_failure(()));
    }
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    // SAFETY: None selects the immediate current job and the output matches the
    // requested information class exactly.
    unsafe {
        QueryInformationJobObject(
            None,
            JobObjectExtendedLimitInformation,
            ptr::from_mut(&mut limits).cast::<c_void>(),
            u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                .map_err(native_failure)?,
            None,
        )
    }
    .map_err(native_failure)?;
    let basic = &limits.BasicLimitInformation;
    if basic.LimitFlags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS == JOB_OBJECT_LIMIT(0)
        || basic.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE == JOB_OBJECT_LIMIT(0)
        || basic.ActiveProcessLimit != 1
    {
        return Err(native_failure(()));
    }
    Ok(())
}

fn token_dword(
    token: &OwnedHandle,
    class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
) -> Result<u32, approval_ui::ApprovalError> {
    let mut value = 0_u32;
    let mut returned = 0_u32;
    // SAFETY: token is live and output points to an exact DWORD.
    unsafe {
        GetTokenInformation(
            raw(token),
            class,
            Some(ptr::from_mut(&mut value).cast::<c_void>()),
            u32::try_from(size_of::<u32>()).map_err(native_failure)?,
            &raw mut returned,
        )
    }
    .map_err(native_failure)?;
    if usize::try_from(returned).map_err(native_failure)? != size_of::<u32>() {
        return Err(native_failure(()));
    }
    Ok(value)
}

fn token_information(
    token: &OwnedHandle,
    class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
) -> Result<Vec<usize>, approval_ui::ApprovalError> {
    let mut required = 0_u32;
    // SAFETY: documented sizing call; the error is expected.
    let _ = unsafe { GetTokenInformation(raw(token), class, None, 0, &raw mut required) };
    let required = usize::try_from(required).map_err(native_failure)?;
    if required == 0 || required > MAX_TOKEN_INFORMATION_BYTES {
        return Err(native_failure(()));
    }
    let word_count = required
        .checked_add(size_of::<usize>() - 1)
        .and_then(|value| value.checked_div(size_of::<usize>()))
        .ok_or_else(|| native_failure(()))?;
    let mut buffer = vec![0_usize; word_count];
    let mut returned = 0_u32;
    // SAFETY: aligned storage has at least required writable bytes.
    unsafe {
        GetTokenInformation(
            raw(token),
            class,
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            u32::try_from(required).map_err(native_failure)?,
            &raw mut returned,
        )
    }
    .map_err(native_failure)?;
    let returned = usize::try_from(returned).map_err(native_failure)?;
    if returned == 0 || returned > required {
        return Err(native_failure(()));
    }
    Ok(buffer)
}

fn verify_parent_handles(
    hello: &ApprovalParentHello,
    expected_session: u32,
    stdin: HANDLE,
    stdout: HANDLE,
    policy: ParentTrustPolicy,
) -> Result<VerifiedParentHandles, approval_ui::ApprovalError> {
    let process_value = usize::try_from(hello.process_handle()).map_err(native_failure)?;
    let image_value = usize::try_from(hello.image_handle()).map_err(native_failure)?;
    let stdin_value = stdin.0 as usize;
    let stdout_value = stdout.0 as usize;
    if process_value == stdin_value
        || process_value == stdout_value
        || image_value == stdin_value
        || image_value == stdout_value
        || process_value == image_value
    {
        return Err(native_failure(()));
    }
    let process_candidate = HANDLE(process_value as RawHandle);
    let image_candidate = HANDLE(image_value as RawHandle);
    validate_parent_proof_handle_set(process_candidate, image_candidate, stdin, stdout)?;
    let process_copy = duplicate_untrusted_candidate(process_candidate)?;
    let image_copy = duplicate_untrusted_candidate(image_candidate)?;
    // SAFETY: process_copy is a live child-local duplicate of a kernel process handle.
    let process_id = unsafe { GetProcessId(raw(&process_copy)) };
    // SAFETY: a zero-timeout wait only queries the live process object's state.
    let process_wait = unsafe { WaitForSingleObject(raw(&process_copy), 0) };
    if process_id != hello.process_id() || process_wait != WAIT_TIMEOUT {
        return Err(native_failure(()));
    }
    let mut session = u32::MAX;
    // SAFETY: output points to an initialized DWORD.
    unsafe { ProcessIdToSessionId(hello.process_id(), &raw mut session) }
        .map_err(native_failure)?;
    if session != expected_session {
        return Err(native_failure(()));
    }
    require_parent_created_first(&process_copy)?;
    verify_parent_artifact(&process_copy, &image_copy, policy)?;
    if !same_object(process_candidate, raw(&process_copy))
        || !same_object(image_candidate, raw(&image_copy))
        || !matches!(handle_flags(process_candidate), Ok(0))
        || !matches!(handle_flags(image_candidate), Ok(0))
    {
        return Err(native_failure(()));
    }
    // SAFETY: each candidate was proven to be the exact non-inheritable object
    // validated through its retained duplicate. This single-threaded bootstrap
    // now transfers each original child-local handle into one owner exactly once.
    let process = unsafe { adopt_validated_handle(process_candidate) };
    // SAFETY: same final revalidation and unique transfer as process.
    let image = unsafe { adopt_validated_handle(image_candidate) };
    Ok(VerifiedParentHandles {
        _process: process,
        _image: image,
    })
}

struct VerifiedParentHandles {
    _process: OwnedHandle,
    _image: OwnedHandle,
}

fn require_parent_created_first(parent: &OwnedHandle) -> Result<(), approval_ui::ApprovalError> {
    let parent_creation = process_creation_time(raw(parent))?;
    // SAFETY: the pseudo handle is valid in the current process and is borrowed.
    let child_process = unsafe { GetCurrentProcess() };
    let child_creation = process_creation_time(child_process)?;
    (parent_creation <= child_creation)
        .then_some(())
        .ok_or_else(|| native_failure(()))
}

fn process_creation_time(process: HANDLE) -> Result<u64, approval_ui::ApprovalError> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: process is live and all four outputs are exact FILETIMEs.
    unsafe {
        GetProcessTimes(
            process,
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
    }
    .map_err(native_failure)?;
    Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

fn verify_parent_artifact(
    process: &OwnedHandle,
    image: &OwnedHandle,
    policy: ParentTrustPolicy,
) -> Result<(), approval_ui::ApprovalError> {
    if policy.executable_sha256 == [0; 32]
        || policy.signer_certificate_sha256 == [0; 32]
        || policy.version == [0; 4]
    {
        return Err(native_failure(()));
    }
    let process_path = process_image_path(process)?;
    let image_path = final_handle_path(image)?;
    let normalized_process = normalize_path(&process_path);
    let normalized_image = normalize_path(&image_path);
    if normalized_process != normalized_image
        || !normalized_image.ends_with("\\key-agent.exe")
        || file_version(&image_path)? != policy.version
    {
        return Err(native_failure(()));
    }
    verify_authenticode(image, &image_path, policy.signer_certificate_sha256)?;
    let mut file = File::from(image.try_clone().map_err(native_failure)?);
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut buffer = Zeroizing::new(vec![0_u8; 64 * 1024]);
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    let actual: [u8; 32] = hash.finalize().into();
    bool::from(actual.ct_eq(&policy.executable_sha256))
        .then_some(())
        .ok_or_else(|| native_failure(()))
}

fn process_image_path(process: &OwnedHandle) -> Result<String, approval_ui::ApprovalError> {
    let mut buffer = vec![0_u16; MAX_PATH_UNITS];
    let mut length = u32::try_from(buffer.len()).map_err(native_failure)?;
    // SAFETY: the process handle is live and the writable UTF-16 buffer has the
    // exact size communicated through length.
    unsafe {
        QueryFullProcessImageNameW(
            raw(process),
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &raw mut length,
        )
    }
    .map_err(native_failure)?;
    let length = usize::try_from(length).map_err(native_failure)?;
    if length == 0 || length >= buffer.len() {
        return Err(native_failure(()));
    }
    String::from_utf16(&buffer[..length]).map_err(native_failure)
}

fn final_handle_path(image: &OwnedHandle) -> Result<String, approval_ui::ApprovalError> {
    let mut buffer = vec![0_u16; MAX_PATH_UNITS];
    // SAFETY: image is a live file handle and buffer is writable.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            raw(image),
            &mut buffer,
            GETFINALPATHNAMEBYHANDLE_FLAGS::default(),
        )
    };
    let length = usize::try_from(length).map_err(native_failure)?;
    if length == 0 || length >= buffer.len() {
        return Err(native_failure(()));
    }
    String::from_utf16(&buffer[..length]).map_err(native_failure)
}

fn normalize_path(path: &str) -> String {
    path.strip_prefix(r"\\?\")
        .unwrap_or(path)
        .replace('/', "\\")
}

fn file_version(path: &str) -> Result<[u16; 4], approval_ui::ApprovalError> {
    let wide = wide_nul(path);
    // SAFETY: wide is a live NUL-terminated path.
    let length = unsafe { GetFileVersionInfoSizeW(PCWSTR(wide.as_ptr()), None) };
    if length == 0 {
        return Err(native_failure(()));
    }
    let mut data = vec![0_u8; usize::try_from(length).map_err(native_failure)?];
    // SAFETY: the output buffer has exactly length writable bytes.
    unsafe {
        GetFileVersionInfoW(
            PCWSTR(wide.as_ptr()),
            None,
            length,
            data.as_mut_ptr().cast::<c_void>(),
        )
    }
    .map_err(native_failure)?;
    let root = [u16::from(b'\\'), 0];
    let mut fixed = ptr::null_mut::<c_void>();
    let mut fixed_length = 0_u32;
    // SAFETY: version buffer stays live while the returned interior pointer is used.
    let found = unsafe {
        VerQueryValueW(
            data.as_ptr().cast::<c_void>(),
            PCWSTR(root.as_ptr()),
            &raw mut fixed,
            &raw mut fixed_length,
        )
    };
    if !found.as_bool()
        || fixed.is_null()
        || usize::try_from(fixed_length).map_err(native_failure)? < size_of::<VS_FIXEDFILEINFO>()
    {
        return Err(native_failure(()));
    }
    // SAFETY: VerQueryValue returned at least one fixed version structure.
    let fixed = unsafe { ptr::read_unaligned(fixed.cast::<VS_FIXEDFILEINFO>()) };
    decode_fixed_file_version(fixed)
}

fn decode_fixed_file_version(
    fixed: VS_FIXEDFILEINFO,
) -> Result<[u16; 4], approval_ui::ApprovalError> {
    if fixed.dwSignature != VS_FIXEDFILEINFO_SIGNATURE {
        return Err(native_failure(()));
    }
    Ok([
        u16::try_from(fixed.dwFileVersionMS >> 16).unwrap_or(u16::MAX),
        u16::try_from(fixed.dwFileVersionMS & 0xffff).unwrap_or(u16::MAX),
        u16::try_from(fixed.dwFileVersionLS >> 16).unwrap_or(u16::MAX),
        u16::try_from(fixed.dwFileVersionLS & 0xffff).unwrap_or(u16::MAX),
    ])
}

fn verify_authenticode(
    image: &OwnedHandle,
    path: &str,
    expected_signer: [u8; 32],
) -> Result<(), approval_ui::ApprovalError> {
    let wide = wide_nul(path);
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: u32::try_from(size_of::<WINTRUST_FILE_INFO>()).unwrap_or(u32::MAX),
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        hFile: raw(image),
        pgKnownSubject: ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: u32::try_from(size_of::<WINTRUST_DATA>()).unwrap_or(u32::MAX),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: ptr::from_mut(&mut file_info),
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL
            | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
            | WTD_LIFETIME_SIGNING_FLAG,
        ..WINTRUST_DATA::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: all WinTrust pointers remain live through verify and close.
    let status = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &raw mut action,
            ptr::from_mut(&mut data).cast::<c_void>(),
        )
    };
    let signer_matches = status == i32::try_from(ERROR_SUCCESS.0).unwrap_or(0)
        && signer_certificate_hash(data.hWVTStateData).is_some_and(|hash| hash == expected_signer);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: closes exactly the provider state from the preceding verify.
    let close = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &raw mut action,
            ptr::from_mut(&mut data).cast::<c_void>(),
        )
    };
    if !signer_matches || close != i32::try_from(ERROR_SUCCESS.0).unwrap_or(0) {
        return Err(native_failure(()));
    }
    Ok(())
}

fn signer_certificate_hash(state: HANDLE) -> Option<[u8; 32]> {
    // SAFETY: state is live WinTrust provider state until CLOSE.
    let provider = unsafe { WTHelperProvDataFromStateData(state) };
    if provider.is_null() {
        return None;
    }
    // SAFETY: index zero requests the primary signer.
    let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, false, 0) };
    if signer.is_null() {
        return None;
    }
    // SAFETY: signer belongs to live provider state.
    let signer = unsafe { &*signer };
    if signer.csCertChain == 0 || signer.pasCertChain.is_null() {
        return None;
    }
    // SAFETY: nonzero chain count makes element zero valid.
    let certificate = unsafe { &*signer.pasCertChain };
    if certificate.pCert.is_null() {
        return None;
    }
    // SAFETY: certificate context remains owned by provider state.
    let context = unsafe { &*certificate.pCert };
    let length = usize::try_from(context.cbCertEncoded).ok()?;
    if context.pbCertEncoded.is_null() || length == 0 || length > 1024 * 1024 {
        return None;
    }
    // SAFETY: CERT_CONTEXT exposes exactly cbCertEncoded bytes.
    let bytes = unsafe { core::slice::from_raw_parts(context.pbCertEncoded, length) };
    Some(Sha256::digest(bytes).into())
}

unsafe fn owned_handle(value: u64) -> Result<OwnedHandle, approval_ui::ApprovalError> {
    let value = usize::try_from(value).map_err(native_failure)?;
    if value == 0 || value == usize::MAX {
        return Err(native_failure(()));
    }
    // SAFETY: caller proves this is one fresh, valid, uniquely owned handle and
    // transfers ownership exactly once to this wrapper.
    Ok(unsafe { OwnedHandle::from_raw_handle(value as RawHandle) })
}

fn duplicate_untrusted_candidate(
    handle: HANDLE,
) -> Result<OwnedHandle, approval_ui::ApprovalError> {
    let mut duplicate = HANDLE::default();
    // SAFETY: the candidate has already passed live handle queries. Duplicating
    // it into this process with inherit=false creates independent ownership and
    // never closes or adopts the untrusted original on an error path.
    unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            GetCurrentProcess(),
            &raw mut duplicate,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
        .map_err(native_failure)?;
    }
    if invalid_handle(duplicate) {
        return Err(native_failure(()));
    }
    // SAFETY: successful DuplicateHandle returned one fresh current-process
    // handle, which transfers to this owner exactly once.
    Ok(unsafe { OwnedHandle::from_raw_handle(duplicate.0) })
}

unsafe fn adopt_validated_handle(handle: HANDLE) -> OwnedHandle {
    // SAFETY: caller proves this exact raw candidate completed final
    // revalidation and has not previously been adopted.
    unsafe { OwnedHandle::from_raw_handle(handle.0) }
}

fn raw(handle: &OwnedHandle) -> HANDLE {
    HANDLE(handle.as_raw_handle())
}

fn wide_nul(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(core::iter::once(0)).collect()
}

fn native_failure<T>(_error: T) -> approval_ui::ApprovalError {
    std::io::Error::other("Approval parent authentication failed").into()
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;
    use std::ffi::OsString;
    use std::fs::File;
    use std::io::{Read as _, Write as _};
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
    use std::sync::Mutex;

    use super::{
        COMPILED_PARENT_POLICY, Channels, PROFILE_V1_NAME, SealedApprovalStdio,
        UnvalidatedProfileApiSid, VS_FIXEDFILEINFO_SIGNATURE, decode_fixed_file_version,
        derive_expected_profile_sid, handle_flags, normalize_path, seal_exact_approval_stdio,
        seal_inherited_approval_stdio, set_binary_stdio, validate_parent_proof_handle_set,
        verify_parent_process_id, wide_nul,
    };
    use approval_ui::ApprovalError;
    use approval_wire::ApprovalParentHello;
    use windows::Win32::Foundation::{
        DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAGS,
        SetHandleInformation, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows::Win32::Security::PSID;
    use windows::Win32::Storage::FileSystem::VS_FIXEDFILEINFO;
    use windows::Win32::System::Pipes::CreatePipe;
    use windows::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CreateEventW, CreateProcessW, GetCurrentProcess,
        GetExitCodeProcess, PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOW,
        TerminateProcess, WaitForSingleObject,
    };
    use windows::core::{PCWSTR, PWSTR};

    const CHILD_FIXTURE: &str = "bootstrap::windows::tests::inherited_approval_stdio_child_fixture";
    const GRANDCHILD_FIXTURE: &str =
        "bootstrap::windows::tests::approval_deinheritance_grandchild_fixture";
    const CHALLENGE: &[u8] = b"approval-two-handle-challenge";
    const ACKNOWLEDGEMENT: &[u8] = b"approval-two-handles-sealed";
    const PROCESS_WAIT_MILLISECONDS: u32 = 25_000;
    static INHERITANCE_TEST_LOCK: Mutex<()> = Mutex::new(());

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
    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    impl<T: Clone> AmbiguousIfClone<u8> for T {}

    trait AmbiguousIfCopy<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfCopy<()> for T {}
    impl<T: Copy> AmbiguousIfCopy<u8> for T {}

    struct ReapedTestProcess {
        process: OwnedHandle,
    }

    impl ReapedTestProcess {
        fn is_alive(&self) -> bool {
            // SAFETY: the zero-timeout wait borrows the retained process handle.
            (unsafe { WaitForSingleObject(raw(&self.process), 0) }) == WAIT_TIMEOUT
        }

        fn wait_for_success(&self) -> Result<(), ApprovalError> {
            // SAFETY: the retained process handle remains live for this bounded
            // wait and the subsequent scalar exit-code query.
            let state =
                unsafe { WaitForSingleObject(raw(&self.process), PROCESS_WAIT_MILLISECONDS) };
            if state != WAIT_OBJECT_0 {
                return Err(test_failure());
            }
            let mut exit_code = u32::MAX;
            // SAFETY: output points to one initialized DWORD.
            unsafe { GetExitCodeProcess(raw(&self.process), &raw mut exit_code) }
                .map_err(super::native_failure)?;
            (exit_code == 0).then_some(()).ok_or_else(test_failure)
        }

        fn terminate_and_reap(&self) -> Result<(), ApprovalError> {
            let process = raw(&self.process);
            // SAFETY: this retained handle targets only an isolated test process.
            let state = unsafe { WaitForSingleObject(process, 0) };
            if state == WAIT_OBJECT_0 {
                return Ok(());
            }
            // SAFETY: every non-signaled result takes the conservative cleanup
            // path. Terminate and bounded wait target the exact retained test
            // process, which has no external work or persistent state. A race
            // where it already exited is accepted only after the wait observes it.
            unsafe {
                let _ = TerminateProcess(process, 1);
                if WaitForSingleObject(process, 5_000) != WAIT_OBJECT_0 {
                    return Err(test_failure());
                }
            }
            Ok(())
        }
    }

    impl Drop for ReapedTestProcess {
        fn drop(&mut self) {
            let _ = self.terminate_and_reap();
        }
    }

    struct BroadInheritanceGrandchild {
        child: ReapedTestProcess,
    }

    impl BroadInheritanceGrandchild {
        fn spawn(executable: &std::path::Path) -> Result<Self, ApprovalError> {
            let mut application = executable.as_os_str().encode_wide().collect::<Vec<_>>();
            application.push(0);
            let mut command = OsString::from("\"");
            command.push(executable.as_os_str());
            command.push("\" ");
            command.push(GRANDCHILD_FIXTURE);
            command.push(" --exact --ignored --test-threads=1");
            let mut command = command.encode_wide().collect::<Vec<_>>();
            command.push(0);
            let startup = STARTUPINFOW {
                cb: u32::try_from(size_of::<STARTUPINFOW>()).map_err(super::native_failure)?,
                ..Default::default()
            };
            let mut information = PROCESS_INFORMATION::default();
            // SAFETY: terminated UTF-16 buffers and initialized structures stay
            // live. TRUE inheritance intentionally has no HANDLE_LIST so the
            // positive-control sentinel must cross this boundary.
            unsafe {
                CreateProcessW(
                    PCWSTR(application.as_ptr()),
                    Some(PWSTR(command.as_mut_ptr())),
                    None,
                    None,
                    true,
                    CREATE_NO_WINDOW,
                    None,
                    PCWSTR::null(),
                    &raw const startup,
                    &raw mut information,
                )
            }
            .map_err(super::native_failure)?;
            let (process, thread) = owned_process_information(information)?;
            drop(thread);
            Ok(Self {
                child: ReapedTestProcess { process },
            })
        }

        fn names_same_object(
            &self,
            candidate: HANDLE,
            expected: HANDLE,
        ) -> Result<bool, ApprovalError> {
            let mut duplicate = HANDLE::default();
            // SAFETY: the retained grandchild process grants duplication rights.
            // Inherited handles preserve numeric values; exact-object comparison
            // below rejects coincidental reuse of the same numeric slot.
            let result = unsafe {
                DuplicateHandle(
                    raw(&self.child.process),
                    candidate,
                    GetCurrentProcess(),
                    &raw mut duplicate,
                    0,
                    false,
                    DUPLICATE_SAME_ACCESS,
                )
            };
            if result.is_err() {
                return Ok(false);
            }
            if super::invalid_handle(duplicate) {
                return Err(test_failure());
            }
            // SAFETY: successful DuplicateHandle returned one fresh owned handle.
            let duplicate = unsafe { OwnedHandle::from_raw_handle(duplicate.0) };
            Ok(super::same_object(raw(&duplicate), expected))
        }
    }

    struct TemporaryInheritFlags {
        handles: Vec<HANDLE>,
    }

    impl TemporaryInheritFlags {
        fn set(handles: impl IntoIterator<Item = HANDLE>) -> Result<Self, ApprovalError> {
            let mut changed = Vec::new();
            for handle in handles {
                if let Err(error) = set_inherit(handle, true) {
                    for previous in changed.iter().copied() {
                        let _ = set_inherit(previous, false);
                    }
                    return Err(error);
                }
                changed.push(handle);
            }
            Ok(Self { handles: changed })
        }
    }

    impl Drop for TemporaryInheritFlags {
        fn drop(&mut self) {
            for handle in self.handles.iter().copied() {
                let _ = set_inherit(handle, false);
            }
        }
    }

    fn owned_process_information(
        information: PROCESS_INFORMATION,
    ) -> Result<(OwnedHandle, OwnedHandle), ApprovalError> {
        if super::invalid_handle(information.hProcess) || super::invalid_handle(information.hThread)
        {
            if !super::invalid_handle(information.hProcess) {
                // SAFETY: CreateProcessW returned this fresh process handle. A
                // malformed companion result is terminated and reaped here.
                unsafe {
                    let _ = TerminateProcess(information.hProcess, 1);
                    let _ = WaitForSingleObject(information.hProcess, 5_000);
                    drop(OwnedHandle::from_raw_handle(information.hProcess.0));
                }
            }
            if !super::invalid_handle(information.hThread) {
                // SAFETY: CreateProcessW returned this fresh primary-thread handle.
                drop(unsafe { OwnedHandle::from_raw_handle(information.hThread.0) });
            }
            return Err(test_failure());
        }
        // SAFETY: successful CreateProcessW returned two fresh owned handles.
        let process = unsafe { OwnedHandle::from_raw_handle(information.hProcess.0) };
        // SAFETY: same unique ownership transfer for the primary thread.
        let thread = unsafe { OwnedHandle::from_raw_handle(information.hThread.0) };
        Ok((process, thread))
    }

    fn anonymous_pipe() -> Result<(OwnedHandle, OwnedHandle), ApprovalError> {
        let mut read = HANDLE::default();
        let mut write = HANDLE::default();
        // SAFETY: both output pointers are valid. Each successful raw handle is
        // transferred exactly once into an independent owner below.
        unsafe { CreatePipe(&raw mut read, &raw mut write, None, 0) }
            .map_err(super::native_failure)?;
        if super::invalid_handle(read) || super::invalid_handle(write) {
            return Err(test_failure());
        }
        // SAFETY: successful CreatePipe returned two fresh owned handles.
        let read = unsafe { OwnedHandle::from_raw_handle(read.0) };
        // SAFETY: same unique ownership transfer for the write end.
        let write = unsafe { OwnedHandle::from_raw_handle(write.0) };
        Ok((read, write))
    }

    fn duplicate_local(source: HANDLE, inheritable: bool) -> Result<OwnedHandle, ApprovalError> {
        let mut duplicate = HANDLE::default();
        // SAFETY: the source is retained by the caller and the success result is
        // one fresh current-process handle adopted exactly once below.
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                source,
                GetCurrentProcess(),
                &raw mut duplicate,
                0,
                inheritable,
                DUPLICATE_SAME_ACCESS,
            )
        }
        .map_err(super::native_failure)?;
        if super::invalid_handle(duplicate) {
            return Err(test_failure());
        }
        // SAFETY: successful DuplicateHandle returned one fresh owned handle.
        Ok(unsafe { OwnedHandle::from_raw_handle(duplicate.0) })
    }

    fn raw(handle: &OwnedHandle) -> HANDLE {
        HANDLE(handle.as_raw_handle())
    }

    fn set_inherit(handle: HANDLE, inherit: bool) -> Result<(), ApprovalError> {
        let flags = if inherit {
            HANDLE_FLAG_INHERIT
        } else {
            HANDLE_FLAGS(0)
        };
        // SAFETY: tests retain the exact owned handle and alter only its local
        // inherit attribute.
        unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, flags) }
            .map_err(super::native_failure)
    }

    fn test_failure() -> ApprovalError {
        super::native_failure(())
    }

    #[test]
    fn exact_approval_stdio_set_seals_two_unique_objects_without_closing_them()
    -> Result<(), ApprovalError> {
        let (input, _input_peer) = anonymous_pipe()?;
        let (_output_peer, output) = anonymous_pipe()?;
        let input = raw(&input);
        let output = raw(&output);
        set_inherit(input, true)?;
        set_inherit(output, true)?;

        seal_exact_approval_stdio([input, output, output])?;
        assert!(matches!(handle_flags(input), Ok(0)));
        assert!(matches!(handle_flags(output), Ok(0)));
        assert!(seal_exact_approval_stdio([input, output, output]).is_err());
        Ok(())
    }

    #[test]
    fn sealed_approval_stdio_is_thread_bound_non_clone_and_non_copy() {
        let _ = <SealedApprovalStdio as AmbiguousIfSend<_>>::marker;
        let _ = <SealedApprovalStdio as AmbiguousIfSync<_>>::marker;
        let _ = <SealedApprovalStdio as AmbiguousIfClone<_>>::marker;
        let _ = <SealedApprovalStdio as AmbiguousIfCopy<_>>::marker;
        let _ = <Channels as AmbiguousIfSend<_>>::marker;
        let _ = <Channels as AmbiguousIfSync<_>>::marker;
        let _ = <Channels as AmbiguousIfClone<_>>::marker;
        let _ = <Channels as AmbiguousIfCopy<_>>::marker;
    }

    #[test]
    fn invalid_alias_type_or_flags_are_rejected_before_mutation() -> Result<(), ApprovalError> {
        let (input, _input_peer) = anonymous_pipe()?;
        let (_output_peer, output) = anonymous_pipe()?;
        let (_error_peer, distinct_error) = anonymous_pipe()?;
        let input = raw(&input);
        let output = raw(&output);
        let distinct_error = raw(&distinct_error);
        for handle in [input, output, distinct_error] {
            set_inherit(handle, true)?;
        }

        assert!(seal_exact_approval_stdio([input, input, output]).is_err());
        assert!(seal_exact_approval_stdio([input, output, distinct_error]).is_err());
        assert!(seal_exact_approval_stdio([HANDLE::default(), output, output]).is_err());

        let output_alias = duplicate_local(output, true)?;
        assert!(seal_exact_approval_stdio([input, output, raw(&output_alias)]).is_err());
        let input_alias = duplicate_local(output, true)?;
        assert!(seal_exact_approval_stdio([raw(&input_alias), output, output]).is_err());

        // SAFETY: the event is a fresh non-pipe kernel object owned below.
        let event =
            unsafe { CreateEventW(None, true, false, None) }.map_err(super::native_failure)?;
        if super::invalid_handle(event) {
            return Err(test_failure());
        }
        // SAFETY: successful CreateEventW returned one fresh owned handle.
        let event = unsafe { OwnedHandle::from_raw_handle(event.0) };
        set_inherit(raw(&event), true)?;
        assert!(seal_exact_approval_stdio([raw(&event), output, output]).is_err());

        for handle in [
            input,
            output,
            distinct_error,
            raw(&output_alias),
            raw(&input_alias),
            raw(&event),
        ] {
            assert!(matches!(handle_flags(handle), Ok(flags) if flags == HANDLE_FLAG_INHERIT.0));
        }
        set_inherit(output, false)?;
        assert!(seal_exact_approval_stdio([input, output, output]).is_err());
        assert!(matches!(handle_flags(input), Ok(flags) if flags == HANDLE_FLAG_INHERIT.0));
        assert!(matches!(handle_flags(output), Ok(0)));

        for handle in [
            input,
            distinct_error,
            raw(&output_alias),
            raw(&input_alias),
            raw(&event),
        ] {
            assert!(matches!(handle_flags(handle), Ok(flags) if flags == HANDLE_FLAG_INHERIT.0));
            set_inherit(handle, false)?;
        }
        Ok(())
    }

    #[test]
    fn parent_proof_set_requires_four_distinct_exact_zero_handles() -> Result<(), ApprovalError> {
        let (stdin, _stdin_peer) = anonymous_pipe()?;
        let (stdout, _stdout_peer) = anonymous_pipe()?;
        let (process, _process_peer) = anonymous_pipe()?;
        let (image, _image_peer) = anonymous_pipe()?;
        let handles = [raw(&stdin), raw(&stdout), raw(&process), raw(&image)];
        validate_parent_proof_handle_set(handles[2], handles[3], handles[0], handles[1])?;
        assert!(
            validate_parent_proof_handle_set(handles[2], handles[2], handles[0], handles[1])
                .is_err()
        );
        assert!(
            validate_parent_proof_handle_set(handles[0], handles[3], handles[0], handles[1])
                .is_err()
        );
        set_inherit(handles[3], true)?;
        assert!(
            validate_parent_proof_handle_set(handles[2], handles[3], handles[0], handles[1])
                .is_err()
        );
        set_inherit(handles[3], false)?;
        Ok(())
    }

    #[test]
    fn parent_process_id_must_match_the_pipe_client() -> Result<(), ApprovalError> {
        let hello = ApprovalParentHello::new(42, 0x100, 0x104, [1; 32])?;
        verify_parent_process_id(&hello, 42)?;
        assert!(verify_parent_process_id(&hello, 43).is_err());
        assert!(verify_parent_process_id(&hello, 0).is_err());
        Ok(())
    }

    #[test]
    fn inherited_approval_stdio_is_sealed_before_descendant_creation() -> Result<(), ApprovalError>
    {
        let _inheritance_guard = INHERITANCE_TEST_LOCK
            .lock()
            .map_err(super::native_failure)?;
        let executable = std::env::current_exe().map_err(super::native_failure)?;
        let (child_input, parent_writer) = anonymous_pipe()?;
        let (parent_reader, child_output) = anonymous_pipe()?;
        let child_input_raw = raw(&child_input);
        let child_output_raw = raw(&child_output);
        let temporary_inherit = TemporaryInheritFlags::set([child_input_raw, child_output_raw])?;

        let mut application = executable.as_os_str().encode_wide().collect::<Vec<_>>();
        application.push(0);
        let mut command = OsString::from("\"");
        command.push(executable.as_os_str());
        command.push("\" ");
        command.push(CHILD_FIXTURE);
        command.push(" --exact --ignored --test-threads=1");
        let mut command = command.encode_wide().collect::<Vec<_>>();
        command.push(0);
        let startup = STARTUPINFOW {
            cb: u32::try_from(size_of::<STARTUPINFOW>()).map_err(super::native_failure)?,
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: child_input_raw,
            hStdOutput: child_output_raw,
            hStdError: child_output_raw,
            ..Default::default()
        };
        let mut information = PROCESS_INFORMATION::default();
        // SAFETY: buffers and structures remain live. TRUE inheritance passes
        // the two temporarily inheritable exact stdio objects to the suspended
        // isolated fixture process.
        unsafe {
            CreateProcessW(
                PCWSTR(application.as_ptr()),
                Some(PWSTR(command.as_mut_ptr())),
                None,
                None,
                true,
                CREATE_SUSPENDED | CREATE_NO_WINDOW,
                None,
                PCWSTR::null(),
                &raw const startup,
                &raw mut information,
            )
        }
        .map_err(super::native_failure)?;
        drop(temporary_inherit);
        let (process, thread) = owned_process_information(information)?;
        let child = ReapedTestProcess { process };
        assert!(matches!(handle_flags(child_input_raw), Ok(0)));
        assert!(matches!(handle_flags(child_output_raw), Ok(0)));
        drop(child_input);
        drop(child_output);

        let mut parent_writer = File::from(parent_writer);
        parent_writer.write_all(CHALLENGE)?;
        drop(parent_writer);

        // SAFETY: this is the exact still-suspended primary thread returned for
        // the guarded fixture child. A count other than one fails closed.
        let previous_suspend_count = unsafe { ResumeThread(raw(&thread)) };
        if previous_suspend_count != 1 {
            return Err(test_failure());
        }
        drop(thread);
        child.wait_for_success()?;

        let mut output = Vec::new();
        File::from(parent_reader).read_to_end(&mut output)?;
        assert!(
            output
                .windows(ACKNOWLEDGEMENT.len())
                .any(|window| window == ACKNOWLEDGEMENT)
        );
        Ok(())
    }

    #[test]
    #[ignore = "launched only by the isolated Approval handle driver"]
    fn inherited_approval_stdio_child_fixture() -> Result<(), ApprovalError> {
        let sealed = seal_inherited_approval_stdio()?;
        set_binary_stdio(&sealed)?;
        assert!(matches!(handle_flags(sealed.input), Ok(0)));
        assert!(matches!(handle_flags(sealed.output), Ok(0)));

        let mut request = Vec::new();
        std::io::stdin()
            .take(u64::try_from(CHALLENGE.len()).map_err(super::native_failure)? + 1)
            .read_to_end(&mut request)?;
        if request.as_slice() != CHALLENGE {
            return Err(test_failure());
        }

        // SAFETY: this unnamed event is initially non-inheritable and becomes a
        // positive control only for the immediately following broad launch.
        let sentinel =
            unsafe { CreateEventW(None, true, false, None) }.map_err(super::native_failure)?;
        if super::invalid_handle(sentinel) {
            return Err(test_failure());
        }
        // SAFETY: successful CreateEventW returned one fresh owned event handle.
        let sentinel = unsafe { OwnedHandle::from_raw_handle(sentinel.0) };
        let sentinel_raw = raw(&sentinel);
        let sentinel_inherit = TemporaryInheritFlags::set([sentinel_raw])?;

        let executable = std::env::current_exe().map_err(super::native_failure)?;
        let grandchild = BroadInheritanceGrandchild::spawn(&executable)?;
        drop(sentinel_inherit);
        assert!(matches!(handle_flags(sentinel_raw), Ok(0)));
        assert!(grandchild.child.is_alive());
        assert!(grandchild.names_same_object(sentinel_raw, sentinel_raw)?);
        assert!(!grandchild.names_same_object(sealed.input, sealed.input)?);
        assert!(!grandchild.names_same_object(sealed.output, sealed.output)?);
        grandchild.child.terminate_and_reap()?;

        std::io::stdout().write_all(ACKNOWLEDGEMENT)?;
        std::io::stdout().flush()?;
        drop(sealed);
        Ok(())
    }

    #[test]
    #[ignore = "launched only as the Approval deinheritance grandchild probe"]
    fn approval_deinheritance_grandchild_fixture() {
        std::thread::sleep(std::time::Duration::from_secs(15));
    }

    #[test]
    fn ordinary_build_has_no_parent_trust_policy() {
        assert!(COMPILED_PARENT_POLICY.is_none());
    }

    #[test]
    fn approval_profile_identity_is_revision_bound_and_stable() {
        assert_eq!(PROFILE_V1_NAME, "YourWallet.ApprovalFrontend.LPAC.v1");
    }

    #[test]
    fn fixed_file_version_requires_the_canonical_structure_signature() -> Result<(), ApprovalError>
    {
        let mut fixed = VS_FIXEDFILEINFO {
            dwSignature: VS_FIXEDFILEINFO_SIGNATURE,
            dwFileVersionMS: (1_u32 << 16) | 2,
            dwFileVersionLS: (3_u32 << 16) | 4,
            ..VS_FIXEDFILEINFO::default()
        };
        assert_eq!(decode_fixed_file_version(fixed)?, [1, 2, 3, 4]);
        fixed.dwSignature ^= 1;
        assert!(decode_fixed_file_version(fixed).is_err());
        Ok(())
    }

    #[test]
    fn path_normalization_removes_only_prefix_and_separator_aliases() {
        assert_eq!(
            normalize_path(r"\\?\C:/Program Files/YourWallet/KEY-AGENT.EXE"),
            r"C:\Program Files\YourWallet\KEY-AGENT.EXE"
        );
        assert_ne!(
            normalize_path(r"C:\Program Files\YourWallet\KEY-AGENT.EXE"),
            normalize_path(r"C:\Program Files\YourWallet\key-agent.exe")
        );
    }

    #[test]
    fn derived_profile_sid_rejects_invalid_inputs() {
        let sid = UnvalidatedProfileApiSid::new(PSID::default());
        assert!(matches!(
            sid.matches(PSID::default()),
            Err(ApprovalError::Io(_))
        ));
    }

    #[test]
    fn fixed_profile_derivation_is_valid_owned_and_deterministic() -> Result<(), ApprovalError> {
        let profile = wide_nul(PROFILE_V1_NAME);
        let first = derive_expected_profile_sid(&profile)?;
        let second = derive_expected_profile_sid(&profile)?;
        let second_raw = second.raw.ok_or_else(test_failure)?;

        assert!(first.matches(second_raw)?);
        Ok(())
    }
}
