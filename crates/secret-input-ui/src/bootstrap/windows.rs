//! Documented Win32 checks for the Secret Input bootstrap.

#![allow(unsafe_code)]

use core::ffi::c_void;
use core::mem::size_of;
use core::ptr;
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle, RawHandle};

use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_NO_TOKEN, ERROR_SUCCESS, FILETIME, HANDLE, HWND, INVALID_HANDLE_VALUE,
    WAIT_TIMEOUT,
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
    GETFINALPATHNAMEBYHANDLE_FLAGS, GetFileVersionInfoSizeW, GetFileVersionInfoW,
    GetFinalPathNameByHandleW, VS_FIXEDFILEINFO, VerQueryValueW,
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
use zeroize::Zeroizing;

use super::{
    AuthenticatedRecoverySession, AuthenticatedRequestSession, AuthenticatedSession, BootstrapKind,
    CHILD_HELLO_BYTES, NONCE_BYTES, PARENT_FINISH_HEADER_BYTES, PARENT_HELLO_BYTES,
    decode_parent_finish, decode_parent_hello, decode_recovery_parent_finish, encode_child_hello,
};
use crate::recovery::MAX_RECOVERY_REQUEST_BYTES;
use crate::{MAX_REQUEST_BYTES, SecretInputError};

const PROFILE_V1_NAME: &str = "YourWallet.SecretInputFrontend.LPAC.v1";
const MAX_TOKEN_INFORMATION_BYTES: usize = 64 * 1024;
const MAX_PATH_UNITS: usize = 32_768;

/// Immutable evidence generated only by the reviewed release pipeline and then
/// covered by the Secret Input helper's own code signature.
#[derive(Clone, Copy)]
struct ParentTrustPolicy {
    executable_sha256: [u8; 32],
    signer_certificate_sha256: [u8; 32],
    version: [u16; 4],
}

// A release build may replace this only through the same reviewed generated
// source step as the platform release attestation. Keeping it absent prevents
// a test feature or arbitrary caller from turning the UI on.
const COMPILED_PARENT_POLICY: Option<ParentTrustPolicy> = None;

#[derive(Clone, Copy)]
struct Channels {
    input: HANDLE,
    output: HANDLE,
    parent_process_id: u32,
    parent_session_id: u32,
}

pub(super) fn authenticate_request() -> Result<AuthenticatedRequestSession, SecretInputError> {
    let channels = verify_self_and_channels()?;
    let Some(policy) = COMPILED_PARENT_POLICY else {
        return Err(SecretInputError::NativeFailure);
    };

    let input = std::io::stdin();
    let mut reader = input.lock();
    let mut encoded_parent = Zeroizing::new(vec![0_u8; PARENT_HELLO_BYTES]);
    reader.read_exact(&mut encoded_parent)?;
    let (kind, parent_hello) = decode_parent_hello(&encoded_parent)?;
    if parent_hello.process_id != channels.parent_process_id {
        return Err(SecretInputError::NativeFailure);
    }
    let parent_handles = verify_parent_handles(
        &parent_hello,
        channels.parent_session_id,
        channels.input,
        channels.output,
        policy,
    )?;

    let mut child_nonce = Zeroizing::new([0_u8; NONCE_BYTES]);
    getrandom::fill(&mut *child_nonce).map_err(|_| SecretInputError::NativeFailure)?;
    if super::is_all_zero(&*child_nonce) {
        return Err(SecretInputError::NativeFailure);
    }
    let encoded_child = encode_child_hello(
        kind,
        &encoded_parent,
        &parent_hello.parent_nonce,
        &child_nonce,
    );
    debug_assert_eq!(encoded_child.len(), CHILD_HELLO_BYTES);
    let output = std::io::stdout();
    let mut writer = output.lock();
    writer.write_all(&encoded_child)?;
    writer.flush()?;

    let maximum_payload = usize::try_from(MAX_REQUEST_BYTES)
        .map_err(|_| SecretInputError::Malformed)?
        .max(MAX_RECOVERY_REQUEST_BYTES);
    let maximum_finish = PARENT_FINISH_HEADER_BYTES
        .checked_add(maximum_payload)
        .ok_or(SecretInputError::Malformed)?;
    let mut finish = Zeroizing::new(Vec::new());
    reader
        .take(u64::try_from(maximum_finish).map_err(|_| SecretInputError::Malformed)? + 1)
        .read_to_end(&mut finish)?;
    if finish.len() > maximum_finish {
        return Err(SecretInputError::Malformed);
    }
    let session = match kind {
        BootstrapKind::SecretInput => {
            let (prompt, prompt_hash) =
                decode_parent_finish(&finish, &parent_hello.parent_nonce, &child_nonce)?;
            AuthenticatedRequestSession::Secret(AuthenticatedSession {
                prompt,
                prompt_hash,
                parent_nonce: Zeroizing::new(parent_hello.parent_nonce),
                child_nonce,
            })
        }
        BootstrapKind::Recovery(recovery_kind) => {
            let (request, request_hash) = decode_recovery_parent_finish(
                finish,
                recovery_kind,
                &parent_hello.parent_nonce,
                &child_nonce,
            )?;
            AuthenticatedRequestSession::Recovery(AuthenticatedRecoverySession {
                request,
                request_hash,
                parent_nonce: Zeroizing::new(parent_hello.parent_nonce),
                child_nonce,
            })
        }
    };
    // Keep both proof kernel objects pinned until the exact nonce-bound prompt
    // has arrived. They are deliberately closed before native UI is entered.
    drop(parent_handles);
    Ok(session)
}

fn verify_self_and_channels() -> Result<Channels, SecretInputError> {
    verify_lpac_token()?;
    verify_job()?;
    // SAFETY: these APIs return borrowed process standard handles; ownership is
    // retained by the process and the handles are used only during bootstrap.
    let input =
        unsafe { GetStdHandle(STD_INPUT_HANDLE) }.map_err(|_| SecretInputError::NativeFailure)?;
    // SAFETY: same as above.
    let output =
        unsafe { GetStdHandle(STD_OUTPUT_HANDLE) }.map_err(|_| SecretInputError::NativeFailure)?;
    // SAFETY: same as above.
    let error =
        unsafe { GetStdHandle(STD_ERROR_HANDLE) }.map_err(|_| SecretInputError::NativeFailure)?;
    if input.is_invalid()
        || output.is_invalid()
        || error.is_invalid()
        || input == output
        || output != error
    {
        return Err(SecretInputError::NativeFailure);
    }
    let (input_pid, input_session) = pipe_client(input)?;
    let (output_pid, output_session) = pipe_client(output)?;
    if input_pid == 0
        || input_pid != output_pid
        || input_session != output_session
        || input_session == u32::MAX
    {
        return Err(SecretInputError::NativeFailure);
    }
    let mut process_session = u32::MAX;
    // SAFETY: output points to one initialized DWORD.
    unsafe { ProcessIdToSessionId(input_pid, &raw mut process_session) }
        .map_err(|_| SecretInputError::NativeFailure)?;
    if process_session != input_session {
        return Err(SecretInputError::NativeFailure);
    }
    Ok(Channels {
        input,
        output,
        parent_process_id: input_pid,
        parent_session_id: input_session,
    })
}

fn pipe_client(handle: HANDLE) -> Result<(u32, u32), SecretInputError> {
    let mut process_id = 0_u32;
    let mut session_id = u32::MAX;
    // SAFETY: the standard handle is live for these non-owning queries and all
    // output pointers refer to initialized exact-width stack values.
    unsafe {
        GetNamedPipeClientProcessId(handle, &raw mut process_id)
            .map_err(|_| SecretInputError::NativeFailure)?;
        GetNamedPipeClientSessionId(handle, &raw mut session_id)
            .map_err(|_| SecretInputError::NativeFailure)?;
    }
    Ok((process_id, session_id))
}

/// Owns one as-yet-untrusted SID returned by the child-side profile API call.
///
/// The allocation is captured before the post-call impersonation check and is
/// released even when that check, SID validation, or comparison fails.
struct UnvalidatedProfileApiSid {
    raw: Option<PSID>,
}

impl UnvalidatedProfileApiSid {
    const fn new(raw: PSID) -> Self {
        Self { raw: Some(raw) }
    }

    fn matches(&self, actual: PSID) -> Result<bool, SecretInputError> {
        let expected = self.raw.ok_or(SecretInputError::NativeFailure)?;
        if actual.is_invalid() || expected.is_invalid() {
            return Err(SecretInputError::NativeFailure);
        }
        // SAFETY: the non-null actual SID points into the caller's still-live
        // token-information buffer.
        let actual_is_valid = unsafe { IsValidSid(actual) }.as_bool();
        // SAFETY: the non-null expected SID remains owned by this wrapper.
        let expected_is_valid = unsafe { IsValidSid(expected) }.as_bool();
        if !actual_is_valid || !expected_is_valid {
            return Err(SecretInputError::NativeFailure);
        }
        // SAFETY: both SIDs were validated above and remain live for this call.
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
        // SAFETY: every non-null success result remains exclusively owned by
        // this wrapper and is released with FreeSid exactly once.
        unsafe {
            let _ = FreeSid(sid);
        }
    }
}

fn reject_thread_impersonation() -> Result<(), SecretInputError> {
    let mut token = HANDLE::default();
    // SAFETY: the current pseudo-thread handle is valid for this scalar query;
    // OpenAsSelf makes the query itself independent of impersonation level.
    let result = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &raw mut token) };
    match result {
        Ok(()) if token.is_invalid() || token == INVALID_HANDLE_VALUE => {
            Err(SecretInputError::NativeFailure)
        }
        Ok(()) => {
            // SAFETY: successful OpenThreadToken returned one fresh owned handle.
            unsafe {
                let _ = CloseHandle(token);
            }
            Err(SecretInputError::NativeFailure)
        }
        Err(error) if error.code() == ERROR_NO_TOKEN.to_hresult() => Ok(()),
        Err(_) => Err(SecretInputError::NativeFailure),
    }
}

fn derive_expected_profile_sid(
    profile: &[u16],
) -> Result<UnvalidatedProfileApiSid, SecretInputError> {
    if profile.last().copied() != Some(0) {
        return Err(SecretInputError::NativeFailure);
    }
    reject_thread_impersonation()?;
    // SAFETY: profile is a live NUL-terminated deterministic name.
    let expected = unsafe { DeriveAppContainerSidFromAppContainerName(PCWSTR(profile.as_ptr())) }
        .map(UnvalidatedProfileApiSid::new);
    reject_thread_impersonation()?;
    expected.map_err(|_| SecretInputError::NativeFailure)
}

fn verify_lpac_token() -> Result<(), SecretInputError> {
    let mut raw_token = HANDLE::default();
    // SAFETY: output receives one owned token handle for the current process.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut raw_token) }
        .map_err(|_| SecretInputError::NativeFailure)?;
    // SAFETY: successful OpenProcessToken returned exclusive ownership.
    let token = unsafe { owned_handle(raw_token.0 as usize as u64)? };
    if token_dword(&token, TokenIsAppContainer)? != 1
        || token_dword(&token, TokenIsLessPrivilegedAppContainer)? != 1
    {
        return Err(SecretInputError::NativeFailure);
    }
    let capabilities = token_information(&token, TokenCapabilities)?;
    if capabilities.len().saturating_mul(size_of::<usize>()) < size_of::<u32>() {
        return Err(SecretInputError::NativeFailure);
    }
    // SAFETY: aligned word storage contains at least the leading GroupCount.
    let count = unsafe { ptr::read_unaligned(capabilities.as_ptr().cast::<u32>()) };
    if count != 0 {
        return Err(SecretInputError::NativeFailure);
    }
    let sid_buffer = token_information(&token, TokenAppContainerSid)?;
    if sid_buffer.len().saturating_mul(size_of::<usize>())
        < size_of::<TOKEN_APPCONTAINER_INFORMATION>()
    {
        return Err(SecretInputError::NativeFailure);
    }
    // SAFETY: size/alignment were established and the interior SID remains live.
    let container = unsafe {
        ptr::read_unaligned(sid_buffer.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>())
    };
    let profile = wide_nul(PROFILE_V1_NAME);
    let expected = derive_expected_profile_sid(&profile)?;
    let matches = expected.matches(container.TokenAppContainer)?;
    matches.then_some(()).ok_or(SecretInputError::NativeFailure)
}

fn verify_job() -> Result<(), SecretInputError> {
    let mut in_job = BOOL(0);
    // SAFETY: output is a live BOOL; None selects the current process's job.
    unsafe { IsProcessInJob(GetCurrentProcess(), None, &raw mut in_job) }
        .map_err(|_| SecretInputError::NativeFailure)?;
    if !in_job.as_bool() {
        return Err(SecretInputError::NativeFailure);
    }
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    // SAFETY: None selects the immediate current job and the output structure
    // exactly matches JobObjectExtendedLimitInformation.
    unsafe {
        QueryInformationJobObject(
            None,
            JobObjectExtendedLimitInformation,
            ptr::from_mut(&mut limits).cast::<c_void>(),
            u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                .map_err(|_| SecretInputError::NativeFailure)?,
            None,
        )
    }
    .map_err(|_| SecretInputError::NativeFailure)?;
    let basic = &limits.BasicLimitInformation;
    let flags = basic.LimitFlags;
    let active_limit = basic.ActiveProcessLimit;
    if flags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS == JOB_OBJECT_LIMIT(0)
        || flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE == JOB_OBJECT_LIMIT(0)
        || active_limit != 1
    {
        return Err(SecretInputError::NativeFailure);
    }
    Ok(())
}

fn token_dword(
    token: &OwnedHandle,
    class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
) -> Result<u32, SecretInputError> {
    let mut value = 0_u32;
    let mut returned = 0_u32;
    // SAFETY: token is live and output points to an exact DWORD.
    unsafe {
        GetTokenInformation(
            raw(token),
            class,
            Some(ptr::from_mut(&mut value).cast::<c_void>()),
            u32::try_from(size_of::<u32>()).map_err(|_| SecretInputError::NativeFailure)?,
            &raw mut returned,
        )
    }
    .map_err(|_| SecretInputError::NativeFailure)?;
    if usize::try_from(returned).map_err(|_| SecretInputError::NativeFailure)? != size_of::<u32>() {
        return Err(SecretInputError::NativeFailure);
    }
    Ok(value)
}

fn token_information(
    token: &OwnedHandle,
    class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
) -> Result<Vec<usize>, SecretInputError> {
    let mut required = 0_u32;
    // SAFETY: documented sizing call; the error is expected.
    let _ = unsafe { GetTokenInformation(raw(token), class, None, 0, &raw mut required) };
    let required = usize::try_from(required).map_err(|_| SecretInputError::NativeFailure)?;
    if required == 0 || required > MAX_TOKEN_INFORMATION_BYTES {
        return Err(SecretInputError::NativeFailure);
    }
    let word_count = required
        .checked_add(size_of::<usize>() - 1)
        .and_then(|value| value.checked_div(size_of::<usize>()))
        .ok_or(SecretInputError::NativeFailure)?;
    let mut buffer = vec![0_usize; word_count];
    let mut returned = 0_u32;
    // SAFETY: aligned storage has at least required writable bytes.
    unsafe {
        GetTokenInformation(
            raw(token),
            class,
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            u32::try_from(required).map_err(|_| SecretInputError::NativeFailure)?,
            &raw mut returned,
        )
    }
    .map_err(|_| SecretInputError::NativeFailure)?;
    let returned = usize::try_from(returned).map_err(|_| SecretInputError::NativeFailure)?;
    if returned == 0 || returned > required {
        return Err(SecretInputError::NativeFailure);
    }
    Ok(buffer)
}

fn verify_parent_handles(
    hello: &super::ParentHello,
    expected_session: u32,
    stdin: HANDLE,
    stdout: HANDLE,
    policy: ParentTrustPolicy,
) -> Result<VerifiedParentHandles, SecretInputError> {
    let process_value =
        usize::try_from(hello.process_handle).map_err(|_| SecretInputError::NativeFailure)?;
    let image_value =
        usize::try_from(hello.image_handle).map_err(|_| SecretInputError::NativeFailure)?;
    let stdin_value = stdin.0 as usize;
    let stdout_value = stdout.0 as usize;
    if process_value == stdin_value
        || process_value == stdout_value
        || image_value == stdin_value
        || image_value == stdout_value
        || process_value == image_value
    {
        return Err(SecretInputError::NativeFailure);
    }
    // SAFETY: the values were delivered as explicit inherited handles. They are
    // distinct from stdio and from each other, and become owned exactly once.
    let process = unsafe { owned_handle(hello.process_handle)? };
    // SAFETY: same ownership argument as above.
    let image = unsafe { owned_handle(hello.image_handle)? };
    // SAFETY: process is a live inherited kernel process handle.
    let process_id = unsafe { GetProcessId(raw(&process)) };
    // SAFETY: a zero-timeout wait only queries the live process object's state.
    let process_wait = unsafe { WaitForSingleObject(raw(&process), 0) };
    if process_id != hello.process_id || process_wait != WAIT_TIMEOUT {
        return Err(SecretInputError::NativeFailure);
    }
    let mut session = u32::MAX;
    // SAFETY: output points to an initialized DWORD.
    unsafe { ProcessIdToSessionId(hello.process_id, &raw mut session) }
        .map_err(|_| SecretInputError::NativeFailure)?;
    if session != expected_session {
        return Err(SecretInputError::NativeFailure);
    }
    require_parent_created_first(&process)?;
    verify_parent_artifact(&process, &image, policy)?;
    Ok(VerifiedParentHandles {
        _process: process,
        _image: image,
    })
}

struct VerifiedParentHandles {
    _process: OwnedHandle,
    _image: OwnedHandle,
}

fn require_parent_created_first(parent: &OwnedHandle) -> Result<(), SecretInputError> {
    let parent_creation = process_creation_time(raw(parent))?;
    // SAFETY: the pseudo handle is valid in the current process and is borrowed.
    let child_process = unsafe { GetCurrentProcess() };
    let child_creation = process_creation_time(child_process)?;
    (parent_creation <= child_creation)
        .then_some(())
        .ok_or(SecretInputError::NativeFailure)
}

fn process_creation_time(process: HANDLE) -> Result<u64, SecretInputError> {
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
    .map_err(|_| SecretInputError::NativeFailure)?;
    Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

fn verify_parent_artifact(
    process: &OwnedHandle,
    image: &OwnedHandle,
    policy: ParentTrustPolicy,
) -> Result<(), SecretInputError> {
    if policy.executable_sha256 == [0; 32]
        || policy.signer_certificate_sha256 == [0; 32]
        || policy.version == [0; 4]
    {
        return Err(SecretInputError::NativeFailure);
    }
    let process_path = process_image_path(process)?;
    let image_path = final_handle_path(image)?;
    let normalized_process = normalize_path(&process_path);
    let normalized_image = normalize_path(&image_path);
    if normalized_process != normalized_image
        || !normalized_image.ends_with("\\key-agent.exe")
        || file_version(&image_path)? != policy.version
    {
        return Err(SecretInputError::NativeFailure);
    }
    verify_authenticode(image, &image_path, policy.signer_certificate_sha256)?;
    let mut file = File::from(
        image
            .try_clone()
            .map_err(|_| SecretInputError::NativeFailure)?,
    );
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
        .ok_or(SecretInputError::NativeFailure)
}

fn process_image_path(process: &OwnedHandle) -> Result<String, SecretInputError> {
    let mut buffer = vec![0_u16; MAX_PATH_UNITS];
    let mut length = u32::try_from(buffer.len()).map_err(|_| SecretInputError::NativeFailure)?;
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
    .map_err(|_| SecretInputError::NativeFailure)?;
    let length = usize::try_from(length).map_err(|_| SecretInputError::NativeFailure)?;
    if length == 0 || length >= buffer.len() {
        return Err(SecretInputError::NativeFailure);
    }
    String::from_utf16(&buffer[..length]).map_err(|_| SecretInputError::NativeFailure)
}

fn final_handle_path(image: &OwnedHandle) -> Result<String, SecretInputError> {
    let mut buffer = vec![0_u16; MAX_PATH_UNITS];
    // SAFETY: image is a live file handle and buffer is writable.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            raw(image),
            &mut buffer,
            GETFINALPATHNAMEBYHANDLE_FLAGS::default(),
        )
    };
    let length = usize::try_from(length).map_err(|_| SecretInputError::NativeFailure)?;
    if length == 0 || length >= buffer.len() {
        return Err(SecretInputError::NativeFailure);
    }
    String::from_utf16(&buffer[..length]).map_err(|_| SecretInputError::NativeFailure)
}

fn normalize_path(path: &str) -> String {
    path.strip_prefix(r"\\?\")
        .unwrap_or(path)
        .replace('/', "\\")
        .to_lowercase()
}

fn file_version(path: &str) -> Result<[u16; 4], SecretInputError> {
    let wide = wide_nul(path);
    // SAFETY: wide is a live NUL-terminated path.
    let length = unsafe { GetFileVersionInfoSizeW(PCWSTR(wide.as_ptr()), None) };
    if length == 0 {
        return Err(SecretInputError::NativeFailure);
    }
    let mut data =
        vec![0_u8; usize::try_from(length).map_err(|_| SecretInputError::NativeFailure)?];
    // SAFETY: the output buffer has exactly length writable bytes.
    unsafe {
        GetFileVersionInfoW(
            PCWSTR(wide.as_ptr()),
            None,
            length,
            data.as_mut_ptr().cast::<c_void>(),
        )
    }
    .map_err(|_| SecretInputError::NativeFailure)?;
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
        || usize::try_from(fixed_length).map_err(|_| SecretInputError::NativeFailure)?
            < size_of::<VS_FIXEDFILEINFO>()
    {
        return Err(SecretInputError::NativeFailure);
    }
    // SAFETY: VerQueryValue returned at least one fixed version structure.
    let fixed = unsafe { ptr::read_unaligned(fixed.cast::<VS_FIXEDFILEINFO>()) };
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
) -> Result<(), SecretInputError> {
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
        return Err(SecretInputError::NativeFailure);
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

unsafe fn owned_handle(value: u64) -> Result<OwnedHandle, SecretInputError> {
    let value = usize::try_from(value).map_err(|_| SecretInputError::NativeFailure)?;
    if value == 0 || value == usize::MAX {
        return Err(SecretInputError::NativeFailure);
    }
    // SAFETY: caller proves this is one distinct inherited handle and transfers
    // ownership exactly once to this wrapper.
    Ok(unsafe { OwnedHandle::from_raw_handle(value as RawHandle) })
}

fn raw(handle: &OwnedHandle) -> HANDLE {
    HANDLE(handle.as_raw_handle())
}

fn wide_nul(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(core::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::{
        COMPILED_PARENT_POLICY, PROFILE_V1_NAME, SecretInputError, UnvalidatedProfileApiSid,
        derive_expected_profile_sid, normalize_path, reject_thread_impersonation, wide_nul,
    };
    use windows::Win32::Security::{ImpersonateSelf, PSID, RevertToSelf, SecurityImpersonation};

    struct RevertImpersonation;

    impl Drop for RevertImpersonation {
        fn drop(&mut self) {
            // SAFETY: this guard exists only after ImpersonateSelf succeeded.
            unsafe {
                let _ = RevertToSelf();
            }
        }
    }

    #[test]
    fn ordinary_build_has_no_parent_trust_policy() {
        assert!(COMPILED_PARENT_POLICY.is_none());
    }

    #[test]
    fn secret_input_profile_identity_is_revision_bound_and_stable() {
        assert_eq!(PROFILE_V1_NAME, "YourWallet.SecretInputFrontend.LPAC.v1");
    }

    #[test]
    fn path_normalization_is_case_and_prefix_stable() {
        assert_eq!(
            normalize_path(r"\\?\C:\Program Files\YourWallet\KEY-AGENT.EXE"),
            r"c:\program files\yourwallet\key-agent.exe"
        );
    }

    #[test]
    fn derived_profile_sid_rejects_invalid_inputs() {
        let sid = UnvalidatedProfileApiSid::new(PSID::default());
        assert!(matches!(
            sid.matches(PSID::default()),
            Err(SecretInputError::NativeFailure)
        ));
    }

    #[test]
    fn fixed_profile_derivation_is_valid_owned_and_deterministic() -> Result<(), SecretInputError> {
        let profile = wide_nul(PROFILE_V1_NAME);
        let first = derive_expected_profile_sid(&profile)?;
        let second = derive_expected_profile_sid(&profile)?;
        let second_raw = second.raw.ok_or(SecretInputError::NativeFailure)?;

        assert!(first.matches(second_raw)?);
        Ok(())
    }

    #[test]
    fn profile_derivation_check_rejects_thread_impersonation() -> windows::core::Result<()> {
        assert!(reject_thread_impersonation().is_ok());

        // SAFETY: the test immediately installs an unwind-safe RevertToSelf guard.
        unsafe { ImpersonateSelf(SecurityImpersonation) }?;
        let revert = RevertImpersonation;

        assert!(matches!(
            reject_thread_impersonation(),
            Err(SecretInputError::NativeFailure)
        ));

        drop(revert);
        assert!(reject_thread_impersonation().is_ok());
        Ok(())
    }
}
